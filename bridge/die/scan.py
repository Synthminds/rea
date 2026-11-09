"""Scan one private snapshot with caller-supplied die-python; print one JSON reply.

REA runs this file with `python -I` under util-linux prlimit and passes one JSON
request argument. Only the package-bundled signature database is loaded: the
request carries no database path, script or custom signature location. Native
DiE output is redirected to stderr so stdout carries only the reply line.
"""
import hashlib
import json
import os
import sys

# Upstream ScanFlags member for each REA request field.
SCAN_FLAGS = {
    "deep_scan": "DEEP_SCAN",
    "heuristic_scan": "HEURISTIC_SCAN",
    "recursive_scan": "RECURSIVE_SCAN",
    "verbose": "VERBOSE_FLAG",
    "all_types": "ALL_TYPES_SCAN",
}
DATABASE_MAX_FILES = 20000
DATABASE_MAX_BYTES = 256 * 1024 * 1024


class BridgeFailure(Exception):
    def __init__(self, reason, message, observed=None):
        super().__init__(message)
        self.reason = reason
        self.observed = observed


def database_identity(root):
    """Digest sorted (relative path, file SHA-256) records of the bundled database."""
    records = []
    total = 0
    for directory, subdirectories, files in os.walk(root):
        subdirectories.sort()
        for name in sorted(files):
            path = os.path.join(directory, name)
            relative = os.path.relpath(path, root).replace(os.sep, "/")
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    total += len(chunk)
                    if total > DATABASE_MAX_BYTES:
                        raise BridgeFailure("unavailable", "The bundled DiE database exceeds the 256 MiB identity budget.")
                    digest.update(chunk)
            records.append(relative + "\0" + digest.hexdigest() + "\n")
            if len(records) > DATABASE_MAX_FILES:
                raise BridgeFailure("unavailable", "The bundled DiE database exceeds the 20000-file identity budget.")
    if not records:
        raise BridgeFailure("unavailable", "The bundled DiE signature database is empty or missing: " + root)
    records.sort()
    return len(records), hashlib.sha256("".join(records).encode("utf-8")).hexdigest()


def scan(request):
    try:
        import die
    except ImportError as error:
        raise BridgeFailure("unavailable", "die-python is not importable from the selected Python: " + str(error))
    try:
        observed = {
            "package_version": str(die.__version__),
            "engine_version": str(die.die_version),
            "library_version": str(die.dielib_version),
            "library_tag": str(die.dielib_tag),
        }
    except AttributeError as error:
        raise BridgeFailure("unavailable", "The importable die module is not die-python: " + str(error))
    if (
        observed["package_version"] != request["package_version"]
        or observed["engine_version"] != request["engine_version"]
    ):
        raise BridgeFailure(
            "unsupported-version",
            "Selected die-python reports package "
            + observed["package_version"]
            + " with DiE "
            + observed["engine_version"]
            + "; this adapter admits die-python "
            + request["package_version"]
            + " with DiE "
            + request["engine_version"]
            + ".",
            observed,
        )
    database = str(die.database_path)
    files, digest = database_identity(database)
    if die.load_database(database) != 1:
        raise BridgeFailure("unavailable", "die-python could not load its bundled signature database: " + database)
    flags = die.ScanFlags.RESULT_AS_JSON
    for field, member in SCAN_FLAGS.items():
        if request["scan"][field] is True:
            flags |= getattr(die.ScanFlags, member)
    document = die.scan_file(request["path"], flags, database)
    return dict(observed, database={"files": files, "sha256": digest}, document=document)


def main():
    reply_stream = os.fdopen(os.dup(1), "w", encoding="ascii")
    # Library and DiE script messages must not corrupt the reply channel.
    os.dup2(2, 1)
    try:
        value = scan(json.loads(sys.argv[1]))
        reply = dict(value, ok=True)
    except BridgeFailure as error:
        reply = {"ok": False, "reason": error.reason, "message": str(error), "observed": error.observed}
    except MemoryError:
        reply = {"ok": False, "reason": "memory", "message": "die-python raised MemoryError under the effective resource limits; the exact allocation cause is unknown.", "observed": None}
    except Exception as error:
        reply = {"ok": False, "reason": "scanner", "message": type(error).__name__ + ": " + str(error), "observed": None}
    reply_stream.write(json.dumps(reply, ensure_ascii=True, allow_nan=False) + "\n")
    reply_stream.flush()


if __name__ == "__main__":
    main()
