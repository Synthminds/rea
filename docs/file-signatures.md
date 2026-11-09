# Detect It Easy file signatures

`detect_file_signatures` / `detect-file-signatures` answers what Detect It Easy
(DiE) recognizes in one selected local file: its file type and the compiler,
linker, library, packer or protector signatures that match. It needs no active
Hopper, Ghidra or IDA target and never executes, unpacks or extracts the file.

```sh
REA_DIE_PYTHON=/absolute/die-env/bin/python \
  rea detect-file-signatures ./selected.exe --json
rea detect-file-signatures ./selected.exe --heuristic-scan --recursive-scan --json
```

```json
{
  "name": "detect_file_signatures",
  "arguments": { "path": "/artifacts/selected.exe", "recursive_scan": true }
}
```

## Bring your own DiE

The verified host is Linux x64. Select exactly one existing installation; REA
never installs, downloads or searches `PATH` for DiE:

- `REA_DIE_COMMAND`: absolute path to the DiE console `diec` 3.09.
- `REA_DIE_PYTHON`: absolute path to a Python executable whose environment
  contains elastic's [die-python](https://github.com/elastic/die-python) 0.5.0
  (DiE 3.09). For example, `python3.13 -m venv /opt/die && /opt/die/bin/pip install die-python==0.5.0`.

`REA_DIE_COMMAND` wins when both are set. Each command runs through util-linux
`prlimit` (`REA_DIE_PRLIMIT_COMMAND`, default `/usr/bin/prlimit`). Set these in
the shell for a CLI call, or in the MCP server launch environment and restart
that server. Upstream profiles are recorded in
[upstream provenance](https://github.com/morluto/rea/blob/main/third_party/die/README.md).

## Scope

This is static protection and toolchain **detection**. The workflow reports
DiE's own labels as leads. It does not unpack, deobfuscate or recover protected
code, and it does not suggest how to defeat a protection. It accepts no caller
signature database, custom signature directory or DiE script: `diec` uses its
installation's default databases and die-python uses its package-bundled
database. DiE entropy, file-info and special methods are not requested; use
[`inspect_byte_entropy`](binary-diagnostics.md#byte-entropy-triage) for entropy.

The scan options map to DiE's own options: `deep_scan` (`diec -d`),
`heuristic_scan` (`-u`), `recursive_scan` (`-r`), `verbose` (`-b`) and
`all_types` (`-a`). All default to false, as in `diec`.

## Interpreting results

- `artifact` identifies the original selected bytes by path, size and SHA-256.
  `artifact_after` reads the file again after the scan; `changed` is null when
  that read failed, with the reason in the limitations.
- DiE reads a read-only private snapshot that keeps the original file name.
  Signatures that read sibling files, such as companion DLL versions, see none.
- `file_parts` flattens DiE's tree in document order. `parent` names the
  containing part. `file_type` and `part` are DiE's labels (for example
  `PE64` / `Header`, or `ZIP` / `Overlay` under a recursive scan). `offset`
  and `size` are DiE-reported strings; a nested part can report values relative
  to its containing part. DiE 3.09 `diec` does not report them (null).
- Each detection keeps DiE's `type`, `name`, `version` and `info`. `heuristic`
  is true when DiE marked the match `(Heuristic)`, false for an ordinary match,
  and null when DiE's label did not follow its documented rendering; `label`
  then keeps that label verbatim.
- `Unknown: Unknown` is DiE's placeholder when no signature matched a part. It
  is not evidence that the part has no compiler, packer or protector.
- A detection is a signature match, not proof that a component is present or
  that the file is malicious or safe. A missing detection proves nothing, and an
  unrequested scan option leaves its detections unknown.
- `tool_profile` records the backend, configured and resolved executable paths
  with the executable's SHA-256, versions, the exact arguments after the
  limiter, the deadline, output budget and effective resource ceilings. For
  die-python, `database.sha256` digests the sorted (path, file SHA-256) records
  of `die.database_path`; `diec` database identity is not observed.
- `scan_messages` keeps lines DiE or its host printed outside the result
  document, including standard error.

## Limits and errors

`command_timeout_ms` (CLI `--command-timeout-ms`) is the deadline for each DiE
command, the `diec --version` probe and the scan; omitted means 120000 ms.
`max_file_bytes` (CLI `--max-file-bytes`) bounds the in-memory snapshot,
default 64 MiB and at most 512 MiB. The 16 MiB combined output budget, the
4 GiB address-space and 120 CPU-second ceilings, and the zero-byte file-size
ceiling have no runtime override; inherited tighter limits are kept.

Missing or relative configuration, a tool that is not an executable regular
file, an unadmitted `diec` banner, a Python without die-python 0.5.0, and a
`diec` that exits nonzero (DiE 3.09 does so when it cannot load its signature
database) return `capability_unavailable` with configuration guidance. A
directory, symbolic link or missing file is an input error; a file above
`max_file_bytes` is a file-size resource constraint. Deadlines, output overflow
and `SIGXCPU`/`SIGXFSZ` terminations return typed timeout or resource errors
with retained output. Another signal does not establish a memory cause. Owned
processes and the private snapshot are released before a result returns;
cleanup that cannot finish is reported with its resources for retry.

## Coverage

Real verification ran die-python 0.5.0 on Linux x64 through the provider,
CLI and stdio MCP. The `diec` arguments, exit status and output framing are
derived from the DIE-engine 3.09 console source and have not been run against a
real `diec`; treat that backend as unverified until it has.

A warm stdio MCP call on a 785 KB ELF with recursive and verbose scans took
about 250 ms on the verification host; a CLI call on a 390 KB ELF took about
1.8 s wall time including Node startup, with a sampled process-family peak of
333 MiB (mostly the REA CLI process). The complete Evidence for that CLI call
was 3.9 KB.
