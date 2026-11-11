# Executable structure with LIEF

`inspect_with_lief` / `inspect-with-lief` answers what an explicit ELF, PE or
Mach-O file is built from: its format, architecture, entry point, sections and
segments with their flags, imports and exports, dependency libraries and
search paths, PE data directories, rich header and signature presence, and
Mach-O load commands, code-signature location and universal slices. It reads the file with a
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

| Format | Verified with real LIEF                                                                                                                                                                                                                                  | Not verified                                                |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| ELF    | Executables and shared libraries: summary, interpreter, soname, `RUNPATH` and legacy `RPATH`, sections, `.dynsym` imports and exports with exact counts against `readelf`, non-UTF-8 interpreter, `DT_NEEDED`, symbol and section names, 200,000 exports | Big-endian, 32-bit and relocatable objects                  |
| PE     | PE32+ EXE and DLL: imports, delay imports, exports, forwarded exports, data directories, a rich header, a non-UTF-8 section name                                                                                                                         | A signed file (`signatures.present: true`), PE32, ARM64     |
| Mach-O | arm64 and x86_64 slices in a universal file: slices, load commands, dylib commands, bound imports, exports, `LC_CODE_SIGNATURE` location                                                                                                                 | 32-bit slices, Apple-toolchain binaries, dyld shared caches |

Set the variable in the MCP server's launch environment and restart the
server; a shell export reaches only the next CLI call.

## Ask one question per call

| `operation`         | Returns                                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `summary` (default) | Format, architecture, bitness, endianness, object type, entry point, image base, a count for every table and up to 64 dependency libraries. ELF adds interpreter, soname, rpath and runpath. PE adds header and optional-header facts, data directories, rich header and signature presence. Mach-O adds header flags, load commands, `LC_ID_DYLIB`, code-signature location, UUID, build version and rpaths. |
| `sections`          | Section name, type, flags, virtual address and size, file offset and size, and the Mach-O segment name.                                                                                                                                                                                                                                                                                                       |
| `segments`          | ELF program headers or Mach-O segments with permissions, ranges and contained section names. PE has no segment table and reports `applicable: false`.                                                                                                                                                                                                                                                         |
| `imports`           | PE import and delay-import entries with library, name or ordinal, and IAT RVA; ELF undefined `GLOBAL` and `WEAK` symbols of `.dynsym` with type, binding and version; Mach-O imported symbols with the bound library when LIEF reports one.                                                                                                                                                                   |
| `exports`           | PE export entries with ordinal, RVA or forwarder; ELF defined `GLOBAL`, `WEAK` and `GNU_UNIQUE` symbols of `.dynsym` with default or protected visibility; Mach-O exported symbols.                                                                                                                                                                                                                           |
| `libraries`         | ELF `DT_NEEDED` entries, PE import and delay-import DLLs, or Mach-O dylib commands other than `LC_ID_DYLIB`, with `kind` and Mach-O versions.                                                                                                                                                                                                                                                                 |
| `rpaths`            | Every ELF `DT_RPATH` and `DT_RUNPATH` path, split on `:`, or Mach-O `LC_RPATH` paths. Not applicable to PE.                                                                                                                                                                                                                                                                                                   |
| `load_commands`     | Mach-O load commands with offset and size. Not applicable to ELF or PE.                                                                                                                                                                                                                                                                                                                                       |

List operations accept `offset` (default 0) and `limit` (default 64, the
same page size as `inspect_analysis_view`). Each page reports `total`,
`returned` and `next_offset`. Every call parses the file again; compare
`artifact.sha256` across pages. The summary keeps at most 64 rows per list;
`summary.truncated_lists` names each list it cut, its total and the operation
that pages the rest. For a universal Mach-O file, `summary` lists
`macho.slices`; select another slice with `macho_slice`.

```sh
rea inspect-with-lief ./application.exe --json
rea inspect-with-lief ./libexample.so exports --limit 200 --json
rea inspect-with-lief ./Application summary --macho-slice 1 --json
rea inspect-with-lief ./Application load_commands --macho-slice 1 --json
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

- REA digests the selected regular file, then streams it into a private
  read-only file and requires the copy to reproduce that digest. Neither pass
  holds the file in memory; a file that changes in between fails as
  `artifact_changed`. The helper receives only that copy, never the original
  path. After the helper exits, REA verifies the copy is unchanged and digests
  the original again (`artifact_after`). A changed copy
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
  trusted code; this is not an OS sandbox. `provider.python` is the resolved
  interpreter file REA launched and `provider.native_module` the loaded
  native LIEF module, each with its SHA-256. REA digests both before the run
  and again afterwards; a change fails the call as `unreadable_output`. Other
  Python and LIEF files are not digested.
- REA owns the helper's process group and its run token. Cleanup also stops
  descendants that left the group, for example through `setsid`.
- Rows, counts and absences are LIEF's parsed model. LIEF tolerates malformed
  structures and can skip entries it cannot parse. An empty table does not
  prove the file declares none. `coverage.parser_diagnostics` reports whether
  LIEF or Python wrote warnings. `diagnostics.stderr` gives their byte and
  line counts, the SHA-256 of the captured text and its distinct lines with
  repeat counts, up to 4 KiB. Warnings can echo file-controlled names, so the
  full text is returned only with `diagnostics: "complete"` (CLI
  `--diagnostics complete`).
- File strings that are valid UTF-8 are JSON strings. Any other name, path or
  interpreter is `{"text": null, "bytes_hex": "..."}` with its exact bytes.
  A summary field LIEF cannot read is null and listed in
  `summary.unread_fields`; the rest of the summary is still returned.
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
- ELF imports and exports come from `.dynsym` only; `.symtab` is a
  link-time table, so `main` or `_start` are not exports. ELF imports have no
  per-library binding, so `library` is null. Mach-O offsets are relative to
  the selected slice; add its `fat_offset` for positions in the universal
  file.

## Limits and failures

`max_file_bytes` bounds the read (default 256 MiB, maximum 512 MiB).
`command_timeout_ms` bounds the helper process (default 120000 ms, range
1 to 2147483647) and applies on the next call. The 32 MiB reply and 4 MiB
captured-diagnostics budgets have no runtime override; request a smaller page
when a reply is too large. A typed failure keeps the first and last 4 KiB of
each output stream with its full byte count, and a helper refusal message is
cut to 1 KiB with its full size. One inspection runs at a time per REA
process; a concurrent call returns a retryable capacity error.

| Situation                                                                                                                                                       | Error                                                               |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `REA_LIEF_PYTHON` unset, relative, missing or not a file                                                                                                        | `capability_unavailable`, with the configuration remediation        |
| The interpreter cannot import `lief`                                                                                                                            | `capability_unavailable`, with the import error                     |
| LIEF outside 1.0.x                                                                                                                                              | `capability_unavailable`, with `observed_version`                   |
| Not ELF, PE or Mach-O                                                                                                                                           | `unsupported_target`                                                |
| Unreadable ELF class or Mach-O header                                                                                                                           | `invalid_request` on `path`                                         |
| `macho_slice` out of range or used on ELF/PE                                                                                                                    | `invalid_request` on `macho_slice`                                  |
| File larger than `max_file_bytes`                                                                                                                               | `resource_constraint` (`file-size`)                                 |
| Helper deadline                                                                                                                                                 | `provider_timeout`, naming `command_timeout_ms`                     |
| Reply or diagnostics over budget, or memory exhausted while parsing or encoding the reply                                                                       | `resource_constraint`, with the effective limits the helper applied |
| Selected file changed between its digest and the private copy                                                                                                   | `artifact_changed`                                                  |
| Helper crash, nonzero exit, missing, oversized or symlinked reply, a modified private copy, or an interpreter or native LIEF module that changed during the run | `unreadable_output`; no partial structure is reported               |

Cancellation stops the owned helper process and removes the private copy.
Cleanup that cannot complete is retained and retried before the next call. If
the helper replied but its process group could not be confirmed stopped, the
call returns `cleanup_incomplete` with the completed result as
`partial_observation`. The same applies when a read REA makes after the helper
exits completes but its descriptor cannot be closed: the remaining checks
still run, and a result that passes them all is returned in one
`cleanup_incomplete` naming each held descriptor and the private copy kept
with it, until `close()` or the next call releases them. A failed check or a
cancellation, including one during that close, stays the primary error.

## Cost of a call

Measured on Linux x64 with Node 22.22.0, Python 3.13.17 and LIEF 1.0.0, files
already in the OS cache. CPU is user plus system time. Peak RSS is the largest
single process in the command's process family; the Node process is the
largest here.

| CLI call                                                | Wall   | CPU    | Peak RSS | Output      |
| ------------------------------------------------------- | ------ | ------ | -------- | ----------- |
| `summary`, 15,144-byte shared library                   | 2.33 s | 2.54 s | 294 MiB  | 6,132 bytes |
| `summary`, 34,551,120-byte `libclang-18.so.18`          | 2.36 s | 2.96 s | 310 MiB  | 5,977 bytes |
| `exports --limit 1`, same library                       | 2.29 s | 2.91 s | 310 MiB  | 5,718 bytes |
| `summary`, generated ELF with 200,000 `.dynsym` exports | 2.67 s | 2.89 s | 314 MiB  | 6,089 bytes |
| `exports --limit 1`, same ELF                           | 2.99 s | 3.28 s | 312 MiB  | 5,890 bytes |

Most of a call is Node and Python start-up and `import lief`; a warm stdio MCP
`exports` call took 0.62 s and returned about 12 KB. REA streams the selected
file into the private copy, so Node no longer holds it in memory; it held up
to three copies before (373 MiB for the same library). Digesting the
interpreter and the 10 MB native LIEF module adds about 25 MiB to Node's peak
for small files. Counting ELF symbols walks `.dynsym` once and builds only the
requested rows: the helper alone took 0.66 s for the 200,000-symbol summary
and 0.63 s for `exports --limit 1`, against 91 s and 93 s before, and peaked
at 127 MiB instead of 279 MiB. The inline diagnostics summary is bounded: for
a crafted ELF whose 30,000 distinct warnings filled 1.28 MB of stderr, it was
9.4 KB of JSON and the `sections --limit 1` response 14.6 KB, against 1.32 MB
with `diagnostics: "complete"`. Token counts were not measured; at roughly
four bytes per token, a summary response is an estimated 1,500 to 3,000
tokens. Cold disk reads were not measured.
