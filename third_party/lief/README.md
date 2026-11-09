# Bring-your-own LIEF

REA does not bundle, patch, install or download LIEF or Python. Operators select
an existing interpreter that can import `lief` with `REA_LIEF_PYTHON`.

- Upstream: https://github.com/lief-project/LIEF
- Documentation and install instructions: https://lief.re/doc/latest/installation.html
  (`pip install lief`)
- Admitted release line: 1.0.x; verified release: 1.0.0 (PyPI `lief==1.0.0`,
  published July 12, 2026)
- Upstream license: Apache-2.0

`bridge/lief/inspect.py` is REA's own read-only helper. It imports `lief`,
calls only its parsers and accessors, and never calls LIEF's builder, writer or
patching APIs. The adapter admits the observed `lief.__version__` only when its
major and minor version match the admitted release line, and records that
version in Evidence. Version admission identifies the supported API profile; it
does not certify publisher authenticity. Operators remain responsible for the
provenance of the interpreter and package they configure.

Real verification on Linux x64 installed `lief==1.0.0`
(`lief-1.0.0-cp312-abi3-manylinux_2_28_x86_64.whl`, SHA-256
`41ff868f5328fc8e5237a9e1f4718590e0ee9180c1422b3e4948b7116ba4517c` per PyPI
metadata) into a throwaway virtual environment outside the repository.
