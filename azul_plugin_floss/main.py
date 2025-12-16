"""Extract obfuscated strings from Windows PE files using FLARE Obfuscated String Solver."""

import json
import signal
import subprocess  # noqa: S404 # nosec B404
import sys
import tempfile
from dataclasses import dataclass

import psutil
import pydantic
from azul_runner import FV, BinaryPlugin, Feature, FeatureType, Job, State, add_settings, cmdline_run

class FlossEmptyOutputException(Exception):
    """Custom exception for case where floss binary returns an empty string as output."""

    pass

@dataclass
class _FlossString:
    """Temp datastructure for floss_strings features."""

    string: str
    function: int
    offset: int

def kill_proc_tree(pid, sig=signal.SIGKILL):
    """Kill a process tree (including grandchildren) with signal KILL."""
    parent = psutil.Process(pid)
    children = parent.children(recursive=True)
    for p in children:
        try:
            p.send_signal(sig)
        except psutil.NoSuchProcess:
            pass

def _add_floss_feature(
    flossStrings: list[_FlossString], flossFunctions: dict[int, int], string: str, function: int, offset: int
):
    """Add string info and function count to data structures."""
    flossStrings.append(_FlossString(string, function, offset))
    if function in flossFunctions:
        flossFunctions[function] += 1
    else:
        flossFunctions[function] = 1

def _parse_floss_json(stdout: str) -> tuple[list[_FlossString], dict[int, int]]:
    """Parse floss json output into azul features."""
    j = json.loads(stdout)

    flossStrings: list[_FlossString] = []
    flossFunctions: dict[int, int] = {}

    startAddress = j["metadata"]["imagebase"]

    for stringData in j["strings"]["stack_strings"]:
        _add_floss_feature(
            flossStrings,
            flossFunctions,
            stringData["string"],
            int(stringData["function"]),
            int(stringData["function"]) + int(stringData["offset"]) - startAddress,
        )
    for stringData in j["strings"]["tight_strings"]:
        _add_floss_feature(
            flossStrings,
            flossFunctions,
            stringData["string"],
            int(stringData["function"]),
            int(stringData["function"]) + int(stringData["offset"]) - startAddress,
        )
    for stringData in j["strings"]["decoded_strings"]:
        _add_floss_feature(
            flossStrings,
            flossFunctions,
            stringData["string"],
            int(stringData["decoding_routine"]),
            int(stringData["decoded_at"]) - startAddress,
        )

    return flossStrings, flossFunctions

def _run_floss(fileDir: str, timeoutSeconds: int | None = None) -> str | State:
    """Run floss executable with flags set to output as json."""
    # run floss on file in directory
    cmdLineString = [sys.executable, "-m", "floss", "-j", "--no", "static", "--"] + [fileDir]

    # wait for binary to run - output is [stdout, stderr]
    # make sure this timeout is smaller than SETTINGS["run_timeout"]
    # using tempfile.TemporaryDirectory which will automatically clean up any
    # files or directories created during floss runtime

    with tempfile.TemporaryDirectory() as dir_name:
        # We use Popen in order to properly kill any child processes spawned
        # by floss immediately. subprocess.run does not allow us to get a pid
        # which we need in order to kill the child processes.
        flossProc = subprocess.Popen(  # noqa: S603 # nosec B603
            cmdLineString,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"TMPDIR": dir_name},
        )
        flossPid = flossProc.pid
        try:
            # wait for binary to run - output is [stdout, stderr]
            # make sure this timeout is smaller than SETTINGS["run_timeout"]
            output = flossProc.communicate(timeout=timeoutSeconds)
            stdout = output[0].decode()

        except subprocess.TimeoutExpired:
            # Kill all processes.
            kill_proc_tree(flossPid)
            flossProc.send_signal(9)
            raise
        if not stdout:
            error_text = output[1].decode()
            if "InvalidArchitecture" in error_text:
                return State(
                    State.Label.COMPLETED_WITH_ERRORS,
                    message="No strings could be extracted because the file Architecture"
                    + " is not supported by Floss",
                )
            if "UnicodeDecodeError" in error_text:
                return State(
                    State.Label.COMPLETED_WITH_ERRORS,
                    message="No strings could be extracted because a unicode decode error occurred"
                    + " and Floss can't process this file.",
                )
            raise FlossEmptyOutputException(error_text)
        return stdout

def _floss_data_to_features(strings: list[_FlossString], functions: dict[int, int]) -> dict[str, list[FV]]:
    """Convert floss data structures into feature values."""
    features: dict[str, list[FV]] = {"floss_strings": [], "floss_functions": []}
    for flossString in strings:
        features["floss_strings"].append(
            FV(value=flossString.string, label=f"function 0x{flossString.function:x}", offset=flossString.offset)
        )
    for flossFunction in functions:
        plural = "s" if functions[flossFunction] > 1 else ""
        features["floss_functions"].append(
            FV(value=f"0x{flossFunction:x}", label=f"{functions[flossFunction]} string{plural} found")
        )
    return features

class AzulPluginFloss(BinaryPlugin):
    """Extract obfuscated strings from Windows PE files using FLARE Obfuscated String Solver."""

    CONTACT = "ASD's ACSC"
    VERSION = "2025.03.18"
    SETTINGS = add_settings(
        # 16MB because floss is limited to 0x1000000 bytes (which is ~16MB)
        filter_max_content_size=(pydantic.ByteSize, "16MB"),
        filter_data_types={
            "content": [
                # Windows exe
                "executable/windows/pe",
                "executable/windows/pe32",
                "executable/windows/pe64",
                "executable/windows/dll",
                "executable/windows/dll32",
                "executable/windows/dll64",
                # Non windows exe
                "executable/dll32",
                "executable/pe32",
                # No ELF files because Floss only does static string extraction.
                # This can be acquired using `strings` which is much more efficient than Floss.
            ]
        },
        run_timeout=(int, 5 * 60),
        # run_timeout_difference here is a small difference to ensure the runtime of
        # the floss process is always less than the run time of the plugin to avoid
        # temporary files not being disposed of.
        run_timeout_difference=(int, 20),
    )
    FEATURES = [
        Feature(name="floss_strings", desc="Strings extracted from binary", type=FeatureType.String),
        Feature(name="floss_functions", desc="Functions strings are extracted from", type=FeatureType.String),
    ]

    def execute(self, job: Job) -> State:
        """Run FLOSS across data from any Windows PE file."""
        if job.event.entity.size > self.cfg.filter_max_content_size:
            self.logger.warning(
                "File size was too large for floss to process max filesize is "
                + self.cfg.filter_max_content_size.human_readable(True)
            )
            return State(State.Label.OPT_OUT)

        path = job.get_data().get_filepath()

        stdout = _run_floss(
            path,
            self.cfg.run_timeout - self.cfg.run_timeout_difference,
        )
        if isinstance(stdout, State):
            return stdout
        flossStrings, flossFunctions = _parse_floss_json(stdout)
        features = _floss_data_to_features(flossStrings, flossFunctions)
        self.add_many_feature_values(features)
        return State(State.Label.COMPLETED)


def main():
    """Run plugin via command-line."""
    cmdline_run(plugin=AzulPluginFloss)


if __name__ == "__main__":
    main()
