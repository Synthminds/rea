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

The verified host is Linux x64. Select one existing installation; REA never
installs, downloads or searches `PATH` for DiE:

- `REA_DIE_PYTHON`: absolute path to a Python executable whose environment
  contains elastic's [die-python](https://github.com/elastic/die-python) 0.5.0
  (DiE 3.09). For example, `python3.13 -m venv /opt/die && /opt/die/bin/pip install die-python==0.5.0`.
- `REA_DIE_COMMAND` (the DiE console `diec`) is not admitted yet. Leave it
  unset: when it is set it wins selection and the call returns
  `capability_unavailable` naming an unverified backend, without running
  anything or falling back to `REA_DIE_PYTHON`. See
  [pending diec lane](#pending-diec-lane).

Each command runs through util-linux `prlimit` (`REA_DIE_PRLIMIT_COMMAND`,
default `/usr/bin/prlimit`). Set these in the shell for a CLI call, or in the
MCP server launch environment and restart that server. Upstream profiles are
recorded in
[upstream provenance](https://github.com/morluto/rea/blob/main/third_party/die/README.md).

## Scope

This is static protection and toolchain **detection**. The workflow reports
DiE's own labels as leads. It does not unpack, deobfuscate or recover protected
code, and it does not suggest how to defeat a protection. It accepts no caller
signature database, custom signature directory or DiE script: die-python uses
its package-bundled database. DiE entropy, file-info and special methods are not requested; use
[`inspect_byte_entropy`](binary-diagnostics.md#byte-entropy-triage) for entropy.

The scan options map to DiE's own scan flags (`diec` spells them `-d`, `-u`,
`-r`, `-b` and `-a`): `deep_scan`, `heuristic_scan`, `recursive_scan`,
`verbose` and `all_types`. All default to false, as in DiE.

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
  to its containing part. They are null when DiE omits them.
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
  limiter, the deadline, output budget and effective resource ceilings.
  `resource_limiter` records the configured and resolved `prlimit` paths, its
  SHA-256 and its arguments. `native_module` records the path and SHA-256 of
  die-python's loaded `_die` scanner module. The executable, limiter and module
  are digested again after the scan, and a changed file fails the call.
  `database.sha256` digests the sorted (path, file SHA-256) records of
  `die.database_path`. die-python's Python sources and bundled shared
  libraries are not digested.
- `scan_messages` keeps lines DiE or its host printed outside the result
  document, including standard error.

## Limits and errors

`command_timeout_ms` (CLI `--command-timeout-ms`) is the deadline for each DiE
command; omitted means 120000 ms. `max_file_bytes` (CLI `--max-file-bytes`)
bounds the snapshot, default 64 MiB and at most 512 MiB. The selected bytes are
held in memory only until the private snapshot is written; later checks stream
digests. The 16 MiB combined output budget, the 4 GiB address-space and 120
CPU-second ceilings, and the zero-byte file-size ceiling have no runtime
override; inherited tighter limits are kept.

Missing or relative configuration, a set `REA_DIE_COMMAND`, a tool that is not
an executable regular file and a Python without die-python 0.5.0 return
`capability_unavailable` with configuration guidance. An unreadable
`/proc/self/limits` returns `capability_unavailable` naming procfs, not DiE
configuration. A directory, symbolic link or missing file is an input error; a
file above `max_file_bytes` is a file-size resource constraint. Deadlines and
output overflow return typed timeout or resource errors. `SIGXCPU` and
`SIGXFSZ` return typed cpu or file-size resource errors. Linux sends `SIGKILL`,
not `SIGXCPU`, when the pinned 120 CPU-second ceiling is reached because its
soft and hard limits are equal; a `SIGKILL` REA did not send is reported as an
output error whose remediation names that ceiling, the OOM killer and other
senders without choosing among them. A snapshot that changed during the scan
is `artifact_changed`; a changed executable, limiter or scanner module is an
output error. Errors carry at most 4 KiB of each output stream with the
complete byte counts. Cancellation after DiE finishes returns typed
cancellation whose partial observation keeps DiE's parsed detections with
`artifact_after` unknown; its limitations name any snapshot, executable,
limiter or module check REA had not yet confirmed, and such detections are
unverified. Owned processes, run-token descendants that left the
process group, and the private snapshot are released before a result returns;
cleanup that cannot finish is reported with its resources for retry.

## Containment

DiE is trusted caller-supplied code; REA bounds it but does not sandbox it.
`prlimit` pins the address-space, CPU and file-size ceilings. The zero-byte
file-size ceiling stops file growth only: it does not prevent creating empty
files or directories, `mkdir`, `unlink`, `rename`, truncation or `chmod`. DiE
inherits REA's environment (plus `TMPDIR` set to the private runtime) and runs
without network isolation. These limits are shared with the WABT, tshark and
sigrok adapters.

DiE's embedded Qt QML engine sizes anonymous memory with `memfd_create` and
`ftruncate`. Under the zero-byte ceiling that `ftruncate` fails with `EFBIG`
and raises `SIGXFSZ`. CPython ignores `SIGXFSZ`, so die-python continues and
the real die-python lane passes.

## Pending diec lane

The `diec` parser and argument mapping remain in source, exercised only by
authored stand-ins, until a real `diec` 3.09 lane passes. A native Qt6 `diec`
keeps the default `SIGXFSZ` disposition, so the same `memfd_create` and
`ftruncate` path is expected to kill it with `SIGXFSZ` (exit status 153) under
the zero-byte ceiling; this was reproduced by restoring the default disposition
in die-python, not by running `diec`. Admitting `diec` needs a real lane on
Linux x64 and a file-size policy that accounts for that memfd. Its arguments,
exit status and output framing are derived from the DIE-engine 3.09 console
source.

## Coverage

Real verification ran die-python 0.5.0 on Linux x64 through the provider,
CLI and stdio MCP. Lifecycle and failure controls use authored stand-ins under
the real `prlimit`: output overflow, real `SIGXFSZ` and CPU-ceiling stops, an
authored `SIGXCPU`, nonzero exit, malformed bridge replies, snapshot tampering,
executable, limiter and module replacement during a scan, a `setsid`
descendant, cancellation during the scan, during each read after it and
during runtime removal, and runtime removal failure with retry. Stand-ins do not establish real DiE
behavior.

On a shared verification host, a warm stdio MCP call on a 785 KB ELF with
recursive and verbose scans took 300 to 490 ms, against 271 ms for the same
call before limiter and scanner-module digests and the run-token sweep were
added. A CLI call on a 390 KB ELF took 1.9 to 2.6 s wall time including Node
startup; the largest single process, the REA CLI, peaked at 294 MiB resident.
The complete Evidence for that CLI call was 5.0 KB, of which the limiter and
scanner-module identity add about 1.1 KB.
