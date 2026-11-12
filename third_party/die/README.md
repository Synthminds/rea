# Bring-your-own Detect It Easy

REA does not bundle, patch, install or download Detect It Easy (DiE). Operators
select one existing installation:

- `REA_DIE_PYTHON`: an absolute path to a Python executable whose environment
  contains elastic's `die-python` bindings.
- `REA_DIE_COMMAND`: an absolute path to the DiE console, `diec`. It is not
  admitted until a real `diec` lane passes; when set, it wins selection and is
  refused as an unverified backend.

Upstream references:

- DiE: https://github.com/horsicq/Detect-It-Easy and the build repository
  https://github.com/horsicq/DIE-engine, tag `3.09` (commit
  `13451cf4b406bb55de434bf8685c7142a7b45175`). License: MIT.
- die-python: https://github.com/elastic/die-python, PyPI `die-python` 0.5.0.
  Its LICENSE file is Apache-2.0. It reports DiE `3.09`, dielib `0.1.0` and
  dielib tag `09df9ccafe48a0531987ad1e605402ed79d4c3f6`.

## Admitted profile

`die-python` must report package `0.5.0` and DiE `3.09`. REA runs its own
`bridge/die/scan.py` with `python -I -B`; the bridge digests the loaded `_die`
native module, loads only `die.database_path`, digests that database's sorted
file records, and calls `die.scan_file` with `ScanFlags.RESULT_AS_JSON` and the
caller's flags.

## Pending diec profile

The source-derived `diec` contract stays in REA but is refused at selection.
`diec` must print a single-line `--version` banner ending in `3.09`. The scan
uses `diec -j` plus only the caller's `-d`, `-u`, `-r`, `-b` and `-a` choices and
the private snapshot path, and exactly one indented JSON document must appear
among plain message lines. These arguments, the nonzero exit status for an
unloadable database, and the output framing are derived from the DIE-engine
3.09 console source (`console_source/main_console.cpp`) and the matching
`Formats` serializer (`scanitemmodel.cpp`). They have not been verified against
a real `diec` binary. DiE's Qt QML engine sizes a `memfd` with `ftruncate`; under
REA's zero-byte file-size ceiling a native `diec` is expected to die from
`SIGXFSZ`, which die-python survives only because CPython ignores that signal.

Neither profile accepts a caller database, custom signature directory or script.
REA does not request DiE entropy, file-info or special methods.

## Verification

Real verification used Linux x64 (Ubuntu 24.04, Python 3.13.17) with the PyPI
wheel `die_python-0.5.0-cp313-abi3-manylinux_2_34_x86_64.whl`, SHA-256
`b68a8ce0ae4617ca242c69e29933b5086370b17ebbc4850b26bd29cc5c5ca1b6`, matching
the digest PyPI publishes for that file. PyPI reported no PEP 740 attestation for
it. This identifies that verification wheel, not arbitrary operator-supplied tools.
