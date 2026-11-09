# Executable structure with LIEF

`inspect_with_lief` / `inspect-with-lief` answers what an explicit ELF, PE or
Mach-O file is built from: its format, architecture, entry point, sections and
segments with their flags, imports and exports, dependency libraries, PE data
directories, rich header and signature presence, and Mach-O load commands,
code-signature location and universal slices. It reads the file with a
caller-supplied [LIEF](https://lief.re/) installation. It needs no active
Hopper, Ghidra or IDA target and never executes the selected file.

## Bring your own LIEF

REA never installs Python or LIEF. Create an environment outside any target
directory, install the official `lief` package, and point
`REA_LIEF_PYTHON` at that interpreter:

```sh
python3 -m venv /absolute/lief-env
/absolute/lief-env/bin/pip install lief==1.0.0
export REA_LIEF_PYTHON=/absolute/lief-env/bin/python
```

The helper admits LIEF 1.0.x and records the observed `lief.__version__` in
Evidence. Other hosts report `unsupported_host` until they have their own
verification.

Real verification used LIEF 1.0.0 from PyPI on Linux x64 with compiled
fixtures (`npm run verify:lief`):

| Format | Verified with real LIEF                                                                                                  | Not verified                                                |
| ------ | ------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------- |
| ELF    | Executables and shared libraries: summary, interpreter, soname, `RUNPATH` and legacy `RPATH`, sections, imports, exports | Big-endian, 32-bit and relocatable objects                  |
| PE     | PE32+ EXE and DLL: imports, delay imports, exports, forwarded exports, data directories, a rich header                   | A signed file (`signatures.present: true`), PE32, ARM64     |
| Mach-O | arm64 and x86_64 slices in a universal file: slices, load commands, bound imports, exports, `LC_CODE_SIGNATURE` location | 32-bit slices, Apple-toolchain binaries, dyld shared caches |

Set the variable in the MCP server's launch environment and restart the
server; a shell export reaches only the next CLI call.

## Ask one question per call

| `operation`         | Returns                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `summary` (default) | Format, architecture, bitness, endianness, object type, entry point, image base, table counts and dependency libraries. ELF adds interpreter, soname, rpath and runpath. PE adds header and optional-header facts, data directories, rich header and signature presence. Mach-O adds header flags, load commands, dylib commands, code-signature location, UUID, build version and rpaths. |
| `sections`          | Section name, type, flags, virtual address and size, file offset and size, and the Mach-O segment name.                                                                                                                                                                                                                                                                                    |
| `segments`          | ELF program headers or Mach-O segments with permissions, ranges and contained section names. PE has no segment table and reports `applicable: false`.                                                                                                                                                                                                                                      |
| `imports`           | PE import and delay-import entries with library, name or ordinal, and IAT RVA; ELF undefined dynamic symbols with type, binding and version; Mach-O imported symbols with the bound library when LIEF reports one.                                                                                                                                                                         |
| `exports`           | PE export entries with ordinal, RVA or forwarder; ELF defined dynamic symbols; Mach-O exported symbols.                                                                                                                                                                                                                                                                                    |

List operations accept `offset` (default 0) and `limit` (default: every
remaining row). Each page reports `total`, `returned` and `next_offset`.
Every call parses the file again; compare `artifact.sha256` across pages.
For a universal Mach-O file, `summary` lists `macho.slices`; select another
slice with `macho_slice`.

```sh
rea inspect-with-lief ./application.exe --json
rea inspect-with-lief ./libexample.so exports --limit 200 --json
rea inspect-with-lief ./Application summary --macho-slice 1 --json
```

```json
{
  "name": "inspect_with_lief",
  "arguments": {
    "path": "/artifacts/libexample.so",
    "operation": "imports",
    "offset": 0,
    "limit": 200
  }
}
```

## What the result establishes

- REA reads the selected regular file once, records its SHA-256, and copies
  those bytes to a private read-only file. The helper receives only that copy,
  never the original path. After the helper exits, REA verifies the copy is
  unchanged and digests the original again (`artifact_after`). A changed copy
  fails the call. A changed original is reported as `changed: true`, and the
  results still describe `artifact.sha256`. Its `sha256` is null when the
  changed file grew past `max_file_bytes`, vanished, or changed during that
  digest; `changed` is null only when the file could not be read for another
  reason.
- Python runs isolated (`-I -B`) from the private directory, not from a target
  directory. The helper calls only LIEF parsers and accessors; it never calls
  LIEF's builder, writer or patching APIs. On Linux it lowers its soft limits to
  4 GiB of address space, a file-size limit just above the reply budget and no
  core files, keeping tighter inherited limits. The effective values are in
  `resource_limits`. The caller-supplied interpreter and LIEF installation are
  trusted code; this is not an OS sandbox.
- Rows, counts and absences are LIEF's parsed model. LIEF tolerates malformed
  structures and can skip entries it cannot parse. Its warnings and Python
  warnings are returned in `diagnostics.stderr`, and
  `coverage.parser_diagnostics` reports whether any were written. An empty
  table does not prove the file declares none.
- Addresses, offsets and sizes are hexadecimal strings. Virtual addresses are
  linked addresses, not runtime addresses. Type, flag and command names are
  LIEF's enumeration names.
- `entrypoint` is null when the header declares none. `imagebase` is the PE
  ImageBase, the lowest ELF `PT_LOAD` address (null without one) or the Mach-O
  `__TEXT` address. `libraries` are declared names, not resolved paths; the
  Mach-O list omits `LC_ID_DYLIB`, which names the image itself.
- PE `signatures` counts parsed Authenticode signatures; validity, chain trust
  and timestamps are not verified. Use `inspect_pe_certificates` for the
  certificate table itself. Mach-O `code_signature` locates the
  `LC_CODE_SIGNATURE` blob without parsing or verifying it.
- ELF imports have no per-library binding, so `library` is null. Mach-O
  offsets are relative to the selected slice; add its `fat_offset` for
  positions in the universal file.

## Limits and failures

`max_file_bytes` bounds the read (default 256 MiB, maximum 512 MiB).
`command_timeout_ms` bounds the helper process (default 120000 ms, range
1 to 2147483647) and applies on the next call. The 32 MiB reply and 4 MiB
diagnostics budgets have no runtime override; request a smaller page when a
reply is too large. One inspection runs at a time per REA process; a
concurrent call returns a retryable capacity error.

| Situation                                                 | Error                                                        |
| --------------------------------------------------------- | ------------------------------------------------------------ |
| `REA_LIEF_PYTHON` unset, relative, missing or not a file  | `capability_unavailable`, with the configuration remediation |
| The interpreter cannot import `lief`                      | `capability_unavailable`, with the import error              |
| LIEF outside 1.0.x                                        | `capability_unavailable`, with `observed_version`            |
| Not ELF, PE or Mach-O                                     | `unsupported_target`                                         |
| Unreadable ELF class or Mach-O header                     | `invalid_request` on `path`                                  |
| `macho_slice` out of range or used on ELF/PE              | `invalid_request` on `macho_slice`                           |
| File larger than `max_file_bytes`                         | `resource_constraint` (`file-size`)                          |
| Helper deadline                                           | `provider_timeout`, naming `command_timeout_ms`              |
| Reply or diagnostics over budget, or memory exhausted     | `resource_constraint`                                        |
| Helper crash, malformed reply, or a modified private copy | `unreadable_output`; no partial structure is reported        |

Cancellation stops the owned helper process and removes the private copy.
Cleanup that cannot complete is retained and retried before the next call.

## Cost of a call

Measured on Linux x64 with Node 22.22.0, Python 3.13.17 and LIEF 1.0.0, files
already in the OS cache. CPU is user plus system time; memory is the largest
single process in the command's process family.

| Call                                                     | Wall        | CPU          | Peak RSS     | Output           |
| -------------------------------------------------------- | ----------- | ------------ | ------------ | ---------------- |
| CLI `summary`, 390,848-byte ELF                          | 2.1 s       | 2.4 s        | 278 MiB      | 4,746 bytes      |
| CLI `summary`, 123,215,144-byte shared library           | 4.4 s       | 5.0 s        | 548 MiB      | 4,803 bytes      |
| CLI `exports --limit 100`, same library (50,455 exports) | 4.5 s       | 5.0 s        | 550 MiB      | 24,775 bytes     |
| Warm MCP `summary` or `exports` in a running server      | 0.45–0.54 s | not measured | not measured | about 9.5–9.8 KB |

Most of a warm call is Python start-up and `import lief`. The helper alone
peaked at 65 MiB for the small ELF and 250 MiB for the large library; the rest
is the Node process, which holds one copy of the selected bytes while staging
the private copy. Returning all 50,455 exports in one call produced 10.5 MB,
so page large tables. The `inspect_with_lief` tool definition adds 1,896 bytes
to `tools/list` without output schemas and 22,604 bytes with them. Token counts
were not measured; at roughly four bytes per token, a summary response is an
estimated 1,200 to 2,500 tokens. Cold disk reads were not measured.
