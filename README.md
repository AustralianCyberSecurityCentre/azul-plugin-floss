# Azul Plugin Floss

Extract obfuscated strings from Windows PE files using FLARE Obfuscated String Solver.

## Development Installation

To install azul-plugin-floss for development run the command
(from the root directory of this project):

```bash
pip install -e .
```

## Usage: azul-plugin-floss

This plug runs floss on a given PE file.

Usage on local files:

```
azul-plugin-floss path/to/file.exe
```

Example Output:

```
----- Floss results -----
OK

Output features:
    floss_functions: 3 strings found - 0x401BC0
                     1 strings found - 0x4022C0
                     1 strings found - 0x401500
    floss_strings: function 0x401530 - ADE@
                   function 0x401BC0 - ADE@
                   function 0x401BC0 - ADE@
                   function 0x4022C0 - csec
                   function 0x401500 - hello world

Feature key:
  floss_functions:  Functions strings are extracted from
  floss_strings:  Strings extracted from binary
```

Automated usage in system:

```
azul-plugin-floss --server http://azul-dispatcher.localnet/
```

## Python Package management

This python package is managed using a `pyproject.toml` file.

Standardisation of installing and testing the python package is handled through tox.
Tox commands include:

```bash
# Run all standard tox actions
tox
# Run linting only
tox -e style
# Run tests only
tox -e test
```

## Dependency management

Dependencies are managed in the pyproject.toml and debian.txt file.

Version pinning is achieved using the `uv.lock` file.

To add new dependencies it's recommended to use uv with the command `uv add <new-package>`
    or for a dev package `uv add --dev <new-dev-package>`

The tool used for linting and managing styling is `ruff` and it is configured via `pyproject.toml`

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.