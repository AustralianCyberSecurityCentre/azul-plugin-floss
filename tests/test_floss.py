import os
import subprocess
from unittest import mock

from azul_runner import FV, Event, JobResult, State, TestPlugin

from azul_plugin_floss.main import AzulPluginFloss, _run_floss


class TestExecute(TestPlugin):
    PLUGIN_TO_TEST = AzulPluginFloss

    @staticmethod
    def current_directory():
        return os.path.split(os.path.realpath(__file__))[0]

    def test_base64(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "8bd74619b9c8fe6d5a586e54d10f45499fff70a4b4dfc47eef4c516646274676",
                        "Windows PE with base64 encoded strings.",
                    ),
                )
            ],
            config={"run_timeout": 5 * 60},
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="8bd74619b9c8fe6d5a586e54d10f45499fff70a4b4dfc47eef4c516646274676",
                        features={
                            "floss_strings": [
                                FV("hello world", label="function 0x4015d0", offset=5422),
                                FV("OP`A<(@", label="function 0x401f30", offset=8618),
                                FV("O0bA<(@", label="function 0x401f30", offset=8618),
                                FV("OpcA<(@", label="function 0x401f30", offset=8618),
                                FV("OPeA<(@", label="function 0x401f30", offset=8618),
                                FV("O0gA<(@", label="function 0x401f30", offset=8618),
                                FV("O0\\A C@", label="function 0x401ed0", offset=8930),
                                FV("OP`A<(@", label="function 0x401ed0", offset=8930),
                                FV("O0bA<(@", label="function 0x401ed0", offset=8930),
                                FV("OpcA<(@", label="function 0x401ed0", offset=8930),
                                FV("OPeA<(@", label="function 0x401ed0", offset=8930),
                                FV("O0gA<(@", label="function 0x401ed0", offset=8930),
                                FV("OphA<(@", label="function 0x401ed0", offset=8930),
                                FV("hello world", label="function 0x401500", offset=5086),
                            ],
                            "floss_functions": [
                                FV("0x4015d0", label="1 string found"),
                                FV("0x401f30", label="5 strings found"),
                                FV("0x401ed0", label="7 strings found"),
                                FV("0x401500", label="1 string found"),
                            ],
                        },
                    )
                ],
            ),
        )

    def test_xor(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "a1d6da411725de3d6be023311a7d0f26d35188e3548b1d0773916cf476b4aed8",
                        "Windows PE with strings that have a single byte xor.",
                    ),
                )
            ],
            config={"run_timeout": 5 * 60},
        )

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="a1d6da411725de3d6be023311a7d0f26d35188e3548b1d0773916cf476b4aed8",
                        features={
                            "floss_strings": [
                                FV("hello world", label="function 0x401500", offset=5712),
                                FV("hello world", label="function 0x4015b0", offset=5086),
                            ],
                            "floss_functions": [
                                FV("0x4015b0", label="1 string found"),
                                FV("0x401500", label="1 string found"),
                            ],
                        },
                    )
                ],
            ),
        )

    def test_stack(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "05563546888e49120be95040f618c8150a508cbf0ec9c719d6790d6fa078fb1b",
                        "PE that decodes strings to the stack.",
                    ),
                )
            ],
            config={"run_timeout": 5 * 60},
        )

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="05563546888e49120be95040f618c8150a508cbf0ec9c719d6790d6fa078fb1b",
                        features={
                            "floss_strings": [
                                FV("hello world", label="function 0x401500", offset=5712),
                                FV("hello world", label="function 0x4015b0", offset=5086),
                            ],
                            "floss_functions": [
                                FV("0x4015b0", label="1 string found"),
                                FV("0x401500", label="1 string found"),
                            ],
                        },
                    )
                ],
            ),
        )

    def test_tight(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "4afe728cc82089ade9d3dda4b0fa0dd8a1abe9b58fea6aa99fdd60330d8020b6",
                        "Malicious Windows 32EXE, with tight strings.",
                    ),
                )
            ],
            config={"run_timeout": 5 * 60},
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="4afe728cc82089ade9d3dda4b0fa0dd8a1abe9b58fea6aa99fdd60330d8020b6",
                        features={
                            "floss_strings": [
                                FV("goodbye world", label="function 0x401530", offset=4993),
                                FV("goodbye world", label="function 0x401530", offset=5453),
                                FV("hello world", label="function 0x401530", offset=4993),
                                FV("hello world", label="function 0x401530", offset=5467),
                            ],
                            "floss_functions": [FV("0x401530", label="4 strings found")],
                        },
                    )
                ],
            ),
        )

    def test_rust(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "e90bdaaf5f9ca900133b699f18e4062562148169b29cb4eb37a0577388c22527",
                        "Malicious Rust Windows 32EXE, malware family AGENDA.RUST.",
                    ),
                )
            ],
            config={"run_timeout": 10 * 60},
        )

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="e90bdaaf5f9ca900133b699f18e4062562148169b29cb4eb37a0577388c22527",
                        features={
                            "floss_strings": [
                                FV("0001", label="function 0x486d70", offset=552435),
                                FV("0258", label="function 0x41b1a0", offset=111072),
                                FV("3010", label="function 0x41af80", offset=110500),
                                FV("3010", label="function 0x4207c0", offset=133091),
                                FV("3010", label="function 0x434750", offset=214899),
                                FV("3010", label="function 0x4aa9e0", offset=698883),
                                FV("3010", label="function 0x4df190", offset=913843),
                                FV("65278", label="function 0x4167a0", offset=92068),
                                FV("65278", label="function 0x41ae90", offset=110287),
                                FV("71u0", label="function 0x4a52d0", offset=187240),
                                FV("78124286", label="function 0x401ec0", offset=7903),
                                FV("78124286", label="function 0x407ed0", offset=32495),
                                FV("78124286", label="function 0x410c30", offset=68687),
                                FV("78124286", label="function 0x41ac00", offset=109599),
                                FV("78124286", label="function 0x41b090", offset=110768),
                                FV("78124286", label="function 0x41c210", offset=115247),
                                FV("78124286", label="function 0x4205c0", offset=132575),
                                FV("78124286", label="function 0x434960", offset=215423),
                                FV("78124286", label="function 0x438930", offset=231759),
                                FV("78124286", label="function 0x44e420", offset=320575),
                                FV("78124286", label="function 0x454930", offset=346447),
                                FV("78124286", label="function 0x4726c0", offset=468703),
                                FV("78124286", label="function 0x4aa610", offset=697903),
                                FV("78124286", label="function 0x4df490", offset=914607),
                                FV("78124286", label="function 0x4eb7f0", offset=964623),
                                FV("78124286", label="function 0x4eb9f0", offset=965135),
                                FV("FEFE", label="function 0x402d10", offset=11660),
                                FV("FEFE", label="function 0x41a8b0", offset=108844),
                                FV("FEFE", label="function 0x471ee0", offset=466780),
                                FV("FEFEFEFE", label="function 0x41a9e0", offset=109144),
                                FV("FEFEFEFEm", label="function 0x401ec0", offset=7992),
                                FV("FEFEFEFEm", label="function 0x407ed0", offset=32584),
                                FV("FEFEFEFEm", label="function 0x410c30", offset=68776),
                                FV("FEFEFEFEm", label="function 0x41ac00", offset=109688),
                                FV("FEFEFEFEm", label="function 0x41c210", offset=115336),
                                FV("FEFEFEFEm", label="function 0x4205c0", offset=132664),
                                FV("FEFEFEFEm", label="function 0x4207c0", offset=133176),
                                FV("FEFEFEFEm", label="function 0x434750", offset=214984),
                                FV("FEFEFEFEm", label="function 0x434960", offset=215512),
                                FV("FEFEFEFEm", label="function 0x438930", offset=231848),
                                FV("FEFEFEFEm", label="function 0x44e420", offset=320664),
                                FV("FEFEFEFEm", label="function 0x454930", offset=346536),
                                FV("FEFEFEFEm", label="function 0x4726c0", offset=468792),
                                FV("FEFEFEFEm", label="function 0x4aa610", offset=697992),
                                FV("FEFEFEFEm", label="function 0x4aa9e0", offset=698968),
                                FV("FEFEFEFEm", label="function 0x4df190", offset=913928),
                                FV("FEFEFEFEm", label="function 0x4df490", offset=914696),
                                FV("FEFEFEFEm", label="function 0x4eb7f0", offset=964712),
                                FV("FEFEFEFEm", label="function 0x4eb9f0", offset=965224),
                                FV("TSUR", label="function 0x448ca0", offset=298144),
                                FV("fefe", label="function 0x402d10", offset=11660),
                                FV("fefe", label="function 0x41a820", offset=108700),
                                FV("fefe", label="function 0x471ee0", offset=466780),
                                FV("fefefefe", label="function 0x401ec0", offset=7992),
                                FV("fefefefe", label="function 0x407ed0", offset=32584),
                                FV("fefefefe", label="function 0x410c30", offset=68776),
                                FV("fefefefe", label="function 0x417bd0", offset=97396),
                                FV("fefefefe", label="function 0x41a940", offset=108984),
                                FV("fefefefe", label="function 0x41ac00", offset=109688),
                                FV("fefefefe", label="function 0x41c210", offset=115336),
                                FV("fefefefe", label="function 0x4204d0", offset=132468),
                                FV("fefefefe", label="function 0x4205c0", offset=132664),
                                FV("fefefefe", label="function 0x4207c0", offset=133176),
                                FV("fefefefe", label="function 0x434750", offset=214984),
                                FV("fefefefe", label="function 0x434960", offset=215512),
                                FV("fefefefe", label="function 0x438930", offset=231848),
                                FV("fefefefe", label="function 0x44e420", offset=320664),
                                FV("fefefefe", label="function 0x454930", offset=346536),
                                FV("fefefefe", label="function 0x4726c0", offset=468792),
                                FV("fefefefe", label="function 0x4aa610", offset=697992),
                                FV("fefefefe", label="function 0x4aa9e0", offset=698968),
                                FV("fefefefe", label="function 0x4ae460", offset=713988),
                                FV("fefefefe", label="function 0x4df190", offset=913928),
                                FV("fefefefe", label="function 0x4df3a0", offset=914500),
                                FV("fefefefe", label="function 0x4df490", offset=914696),
                                FV("fefefefe", label="function 0x4eb7f0", offset=964712),
                                FV("fefefefe", label="function 0x4eb9f0", offset=965224),
                                FV("uespemosarenegyl", label="function 0x432790", offset=206792),
                                FV("uespemosarenegyl", label="function 0x432790", offset=214154),
                                FV("uespemosarenegyl", label="function 0x458970", offset=362920),
                                FV("uespemosarenegyl", label="function 0x458970", offset=408826),
                                FV("uespemosarenegyl", label="function 0x458c40", offset=363640),
                            ],
                            "floss_functions": [
                                FV("0x401ec0", label="3 strings found"),
                                FV("0x402d10", label="2 strings found"),
                                FV("0x407ed0", label="3 strings found"),
                                FV("0x410c30", label="3 strings found"),
                                FV("0x4167a0", label="1 string found"),
                                FV("0x417bd0", label="1 string found"),
                                FV("0x41a820", label="1 string found"),
                                FV("0x41a8b0", label="1 string found"),
                                FV("0x41a940", label="1 string found"),
                                FV("0x41a9e0", label="1 string found"),
                                FV("0x41ac00", label="3 strings found"),
                                FV("0x41ae90", label="1 string found"),
                                FV("0x41af80", label="1 string found"),
                                FV("0x41b090", label="1 string found"),
                                FV("0x41b1a0", label="1 string found"),
                                FV("0x41c210", label="3 strings found"),
                                FV("0x4204d0", label="1 string found"),
                                FV("0x4205c0", label="3 strings found"),
                                FV("0x4207c0", label="3 strings found"),
                                FV("0x432790", label="2 strings found"),
                                FV("0x434750", label="3 strings found"),
                                FV("0x434960", label="3 strings found"),
                                FV("0x438930", label="3 strings found"),
                                FV("0x448ca0", label="1 string found"),
                                FV("0x44e420", label="3 strings found"),
                                FV("0x454930", label="3 strings found"),
                                FV("0x458970", label="2 strings found"),
                                FV("0x458c40", label="1 string found"),
                                FV("0x471ee0", label="2 strings found"),
                                FV("0x4726c0", label="3 strings found"),
                                FV("0x486d70", label="1 string found"),
                                FV("0x4a52d0", label="1 string found"),
                                FV("0x4aa610", label="3 strings found"),
                                FV("0x4aa9e0", label="3 strings found"),
                                FV("0x4ae460", label="1 string found"),
                                FV("0x4df190", label="3 strings found"),
                                FV("0x4df3a0", label="1 string found"),
                                FV("0x4df490", label="3 strings found"),
                                FV("0x4eb7f0", label="3 strings found"),
                                FV("0x4eb9f0", label="3 strings found"),
                            ],
                        },
                    )
                ],
            ),
        )

    def test_go(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "8d712c628ce31898f150a8e066ab3ca86a2bb075f1ec8cea8492eccb11f9e0b5",
                        "Malicious golang Windows 32EXE, spreader.",
                    ),
                )
            ],
            config={"run_timeout": 5 * 60},
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="8d712c628ce31898f150a8e066ab3ca86a2bb075f1ec8cea8492eccb11f9e0b5",
                        features={
                            "floss_strings": [
                                FV("0T0p", label="function 0x411019", offset=27790),
                                FV("AVA0", label="function 0x408db3", offset=36287),
                                FV("AVAO", label="function 0x4092c6", offset=37587),
                                FV("QxIZ", label="function 0x4107a0", offset=70000),
                                FV("e5Kv", label="function 0x4113f6", offset=70793),
                                FV("fLEB", label="function 0x4107a0", offset=67515),
                                FV("j:,4;87", label="function 0x40729f", offset=28327),
                                FV("j:,4;87", label="function 0x4113f6", offset=70374),
                                FV("lpHP", label="function 0x40f9d5", offset=63944),
                                FV("ntelineI", label="function 0x420816", offset=133182),
                                FV(
                                    "|}z{xyvwturspqnolmjkhifgdebc`a^_\]Z[XYVWTURSPQNOLMJKHIFGDEBC@A>?<=:;8967452301./,-*+()&'$%\"# !",
                                    label="function 0x410560",
                                    offset=28194,
                                ),
                            ],
                            "floss_functions": [
                                FV("0x40729f", label="1 string found"),
                                FV("0x408db3", label="1 string found"),
                                FV("0x4092c6", label="1 string found"),
                                FV("0x40f9d5", label="1 string found"),
                                FV("0x410560", label="1 string found"),
                                FV("0x4107a0", label="2 strings found"),
                                FV("0x411019", label="1 string found"),
                                FV("0x4113f6", label="2 strings found"),
                                FV("0x420816", label="1 string found"),
                            ],
                        },
                    )
                ],
            ),
        )

    @mock.patch("subprocess.Popen")
    @mock.patch("azul_plugin_floss.main.kill_proc_tree")
    def test_exception_in_floss(self, subprocess_mock, mock_kill_proc_tree):
        mock_process = mock.MagicMock()
        attrs = {"communicate.side_effect": subprocess.TimeoutExpired("", 1)}
        mock_process.configure_mock(**attrs)
        subprocess_mock.return_value = mock_process
        try:
            _run_floss("/a/randomFilePath", 1)
        except subprocess.TimeoutExpired:
            pass
        mock_kill_proc_tree.assert_called()

    def test_unicode_error(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "2a56863d78f5bd9fb371c3b58300bf03738e21a2b0940c405406396a596f4b4c",
                        "PE file with unicode encoding for some of it's strings.",
                    ),
                )
            ],
            config={"run_timeout": 5 * 60},
        )

        self.assertJobResult(
            result,
            JobResult(state=State(State.Label.COMPLETED_EMPTY)),
        )

    def test_unsupported_architecture(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "66f24fc6aace749c29afa233232fbf936f81076c9f401720007f940098dfa0fd",
                        "PE with unsupported architecture for Floss.",
                    ),
                )
            ],
            config={"run_timeout": 5 * 60},
        )

        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.COMPLETED_WITH_ERRORS,
                    message="No strings could be extracted because the file Architecture is not supported by Floss",
                )
            ),
        )

    def test_entity_larger_than16MB(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_cart(
                        "fa4610daeb93f4f22bbd39398a39345b244493cc2f1e56b6554c8b5f4e236d64.cart",
                        description="Benign PE file larger than 16MB create by Azul team.",
                    ),
                )
            ],
            config={"run_timeout": 5 * 60},
        )

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.OPT_OUT),
            ),
        )
