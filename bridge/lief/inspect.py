"""Read-only LIEF structure reader for REA's inspect_with_lief workflow.

REA runs this file with a caller-supplied interpreter in isolated mode (-I -B)
from a private runtime directory. The request names a private read-only copy of
the selected artifact; this helper never receives the original path. It only
reads that copy through LIEF's parsers and writes one JSON reply into the
private directory. No LIEF builder, writer or patching API is called here.
"""
import json
import os
import re
import sys

MACHO_MAGICS = ("MAGIC", "MAGIC_64", "CIGAM", "CIGAM_64")


class Refusal(Exception):
    """A typed, expected failure reported to REA without partial results."""

    def __init__(self, reason, message, **details):
        super().__init__(message)
        self.reason = reason
        self.details = details


def lower_resource_limits(output_bytes, address_space_bytes):
    """Lower soft limits where the host supports them; never raise inherited limits."""
    try:
        import resource
    except ImportError:
        return {"address_space_bytes": None, "file_size_bytes": None, "core_file_bytes": None}
    limits = {}
    for name, kind, maximum in (
        ("address_space_bytes", getattr(resource, "RLIMIT_AS", None), address_space_bytes),
        ("file_size_bytes", getattr(resource, "RLIMIT_FSIZE", None), output_bytes + 1024 * 1024),
        ("core_file_bytes", getattr(resource, "RLIMIT_CORE", None), 0),
    ):
        if kind is None:
            limits[name] = None
            continue
        try:
            soft, hard = resource.getrlimit(kind)
            finite = [maximum] + [value for value in (soft, hard) if value != resource.RLIM_INFINITY]
            effective = min(finite)
            resource.setrlimit(kind, (effective, hard))
            limits[name] = effective
        except (ValueError, OSError):
            limits[name] = None
    return limits


def hexa(value):
    return hex(int(value))


def enum_name(value):
    # LIEF returns a bare int for a value outside its enumeration.
    name = getattr(value, "name", None)
    return name if isinstance(name, str) and name else str(int(value))


def names(values):
    return [enum_name(value) for value in values]


def text(value):
    """LIEF strings are already decoded; keep NUL-free, valid JSON text."""
    return str(value)


def admitted_version(admitted):
    import lief

    observed = str(getattr(lief, "__version__", ""))
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", observed)
    if match is None or f"{match.group(1)}.{match.group(2)}" != admitted:
        raise Refusal(
            "version",
            f"LIEF {observed or 'with an unknown version'} is not admitted; this REA release requires LIEF {admitted}.x.",
            observed_version=observed or None,
        )
    return lief, observed


def parse(lief, path, slice_index):
    """Detect and parse exactly one supported container, selecting one Mach-O slice."""
    if lief.is_elf(path):
        binary = lief.ELF.parse(path)
        if binary is None:
            raise Refusal("malformed", "LIEF recognized an ELF header but could not parse the image.")
        # LIEF still returns an image when it cannot read the ELF identity.
        if enum_name(binary.header.identity_class) not in ("ELF32", "ELF64"):
            raise Refusal("malformed", "LIEF could not read the ELF class from the identity header.")
        if slice_index is not None:
            raise Refusal("not-applicable", "macho_slice applies only to Mach-O inputs; the input is ELF.")
        return "elf", binary, None
    if lief.is_pe(path):
        binary = lief.PE.parse(path)
        if binary is None:
            raise Refusal("malformed", "LIEF recognized a PE header but could not parse the image.")
        if slice_index is not None:
            raise Refusal("not-applicable", "macho_slice applies only to Mach-O inputs; the input is PE.")
        return "pe", binary, None
    if lief.is_macho(path):
        fat = lief.MachO.parse(path)
        if fat is None or fat.size == 0:
            raise Refusal("malformed", "LIEF recognized a Mach-O header but could not parse any slice.")
        for index in range(fat.size):
            # LIEF still returns a slice when it cannot read the Mach-O header.
            if enum_name(fat.at(index).header.magic) not in MACHO_MAGICS:
                raise Refusal("malformed", f"LIEF could not read the Mach-O header of slice {index}.")
        selected = 0 if slice_index is None else slice_index
        if selected >= fat.size:
            raise Refusal(
                "invalid-slice",
                f"macho_slice {selected} is outside the {fat.size} parsed slice(s).",
                slice_count=fat.size,
            )
        slices = []
        for index in range(fat.size):
            item = fat.at(index)
            slices.append({
                "index": index,
                "cpu_type": enum_name(item.header.cpu_type),
                "cpu_subtype": int(item.header.cpu_subtype),
                "fat_offset": hexa(item.fat_offset),
                "size": hexa(item.original_size),
            })
        return "macho", fat.at(selected), {
            "universal": lief.MachO.is_fat(path),
            "slice_count": fat.size,
            "selected_index": selected,
            "slices": slices,
        }
    raise Refusal("unsupported-format", "LIEF does not recognize the input as ELF, PE or Mach-O.")


def common(binary):
    header = binary.abstract.header
    bits = 64 if header.is_64 else 32 if header.is_32 else None
    endianness = {"LITTLE": "little", "BIG": "big"}.get(enum_name(header.endianness))
    return {
        "architecture": enum_name(header.architecture),
        "bits": bits,
        "endianness": endianness,
        "object_type": enum_name(header.object_type),
    }


# ---- ELF -------------------------------------------------------------------

def elf_dynamic_strings(lief, binary, tag, attribute):
    entry = binary.get(tag)
    if entry is None:
        return None
    value = getattr(entry, attribute)
    return [text(item) for item in value] if isinstance(value, (list, tuple)) else text(value)


def elf_version(symbol):
    if not symbol.has_version:
        return None
    version = symbol.symbol_version
    if version.has_auxiliary_version:
        return text(version.symbol_version_auxiliary.name)
    return None


def elf_sections(binary):
    rows = []
    for index, section in enumerate(binary.sections):
        kind = enum_name(section.type)
        rows.append({
            "index": index,
            "name": text(section.name),
            "type": kind,
            "flags": names(section.flags_list),
            "virtual_address": hexa(section.virtual_address),
            "virtual_size": hexa(section.size),
            "file_offset": hexa(section.offset),
            "file_size": hexa(0 if kind == "NOBITS" else section.size),
            "segment": None,
        })
    return rows


def elf_segments(lief, binary):
    flags = lief.ELF.Segment.FLAGS
    rows = []
    for index, segment in enumerate(binary.segments):
        rows.append({
            "index": index,
            "name": None,
            "type": enum_name(segment.type),
            "flags": [name for name, flag in (("read", flags.R), ("write", flags.W), ("execute", flags.X)) if segment.has(flag)],
            "max_protection": None,
            "virtual_address": hexa(segment.virtual_address),
            "virtual_size": hexa(segment.virtual_size),
            "file_offset": hexa(segment.file_offset),
            "file_size": hexa(segment.physical_size),
            "sections": [text(section.name) for section in segment.sections],
        })
    return rows


def elf_symbol_row(symbol, address):
    return {
        "name": text(symbol.name),
        "library": None,
        "ordinal": None,
        "address": hexa(symbol.value) if address else None,
        "kind": enum_name(symbol.type),
        "binding": enum_name(symbol.binding),
        "version": elf_version(symbol),
        "forwarder": None,
    }


def elf_imports(binary):
    return [elf_symbol_row(symbol, False) for symbol in binary.imported_symbols]


def elf_exports(binary):
    return [elf_symbol_row(symbol, True) for symbol in binary.exported_symbols]


def elf_summary(lief, binary):
    header = binary.header
    tags = lief.ELF.DynamicEntry.TAG
    raw_entry = int(header.entrypoint)
    loads = [segment for segment in binary.segments if enum_name(segment.type) == "LOAD"]
    return {
        "entrypoint": None if raw_entry == 0 else hexa(raw_entry),
        # LIEF reports UINT64_MAX when no PT_LOAD exists; that is not an address.
        "imagebase": hexa(binary.imagebase) if loads else None,
        "libraries": [text(name) for name in binary.libraries],
        "elf": {
            "file_type": enum_name(header.file_type),
            "machine": enum_name(header.machine_type),
            "class": enum_name(header.identity_class),
            "data": enum_name(header.identity_data),
            "os_abi": enum_name(header.identity_os_abi),
            "header_entrypoint": hexa(raw_entry),
            "interpreter": text(binary.interpreter) if binary.has_interpreter else None,
            "soname": elf_dynamic_strings(lief, binary, tags.SONAME, "name"),
            "rpath": elf_dynamic_strings(lief, binary, tags.RPATH, "paths"),
            "runpath": elf_dynamic_strings(lief, binary, tags.RUNPATH, "paths"),
        },
        "pe": None,
        "macho": None,
    }


# ---- PE --------------------------------------------------------------------

def pe_sections(binary):
    return [{
        "index": index,
        "name": text(section.name),
        "type": None,
        "flags": names(section.characteristics_lists),
        "virtual_address": hexa(section.virtual_address),
        "virtual_size": hexa(section.virtual_size),
        "file_offset": hexa(section.offset),
        "file_size": hexa(section.size),
        "segment": None,
    } for index, section in enumerate(binary.sections)]


def pe_import_row(library, entry, kind, address):
    ordinal = int(entry.ordinal) if entry.is_ordinal else None
    return {
        "name": None if entry.is_ordinal else text(entry.name),
        "library": text(library),
        "ordinal": ordinal,
        "address": None if address is None else hexa(address),
        "kind": kind,
        "binding": None,
        "version": None,
        "forwarder": None,
    }


def pe_imports(binary):
    rows = []
    for library in binary.imports:
        for entry in library.entries:
            rows.append(pe_import_row(library.name, entry, "import", entry.iat_address))
    for library in binary.delay_imports:
        for entry in library.entries:
            rows.append(pe_import_row(library.name, entry, "delay-import", None))
    return rows


def pe_exports(binary):
    if not binary.has_exports:
        return []
    rows = []
    for entry in binary.get_export().entries:
        forwarded = bool(entry.is_forwarded)
        rows.append({
            "name": text(entry.name) if entry.name else None,
            "library": None,
            "ordinal": int(entry.ordinal),
            "address": None if forwarded else hexa(entry.address),
            "kind": "export",
            "binding": None,
            "version": None,
            "forwarder": text(entry.forward_information) if forwarded else None,
        })
    return rows


def pe_libraries(binary):
    return [text(library.name) for library in binary.imports] + [
        text(library.name) for library in binary.delay_imports
    ]


def pe_summary(binary):
    header = binary.header
    optional = binary.optional_header
    entry_rva = int(optional.addressof_entrypoint)
    directories = []
    for directory in binary.data_directories:
        if int(directory.rva) == 0 and int(directory.size) == 0:
            continue
        directories.append({
            "type": enum_name(directory.type),
            "rva": hexa(directory.rva),
            "size": hexa(directory.size),
            "section": text(directory.section.name) if directory.has_section else None,
        })
    rich = None
    if binary.has_rich_header:
        rich = {
            "key": hexa(binary.rich_header.key),
            "entries": [
                {"id": int(entry.id), "build_id": int(entry.build_id), "count": int(entry.count)}
                for entry in binary.rich_header.entries
            ],
        }
    signatures = list(binary.signatures)
    return {
        "entrypoint": None if entry_rva == 0 else hexa(int(optional.imagebase) + entry_rva),
        "imagebase": hexa(optional.imagebase),
        "libraries": pe_libraries(binary),
        "elf": None,
        "pe": {
            "machine": enum_name(header.machine),
            "timestamp": int(header.time_date_stamps),
            "characteristics": names(header.characteristics_list),
            "magic": enum_name(optional.magic),
            "subsystem": enum_name(optional.subsystem),
            "dll_characteristics": names(optional.dll_characteristics_lists),
            "address_of_entrypoint": hexa(entry_rva),
            "sizeof_image": hexa(optional.sizeof_image),
            "data_directory_count": len(binary.data_directories),
            "data_directories": directories,
            "rich_header": rich,
            "signatures": {"present": len(signatures) > 0, "count": len(signatures)},
            "export_name": text(binary.get_export().name) if binary.has_exports else None,
        },
        "macho": None,
    }


# ---- Mach-O ----------------------------------------------------------------

ZEROFILL_TYPES = {"ZEROFILL", "GB_ZEROFILL", "THREAD_LOCAL_ZEROFILL"}


def protection(value):
    value = int(value)
    return [name for name, bit in (("read", 1), ("write", 2), ("execute", 4)) if value & bit]


def macho_sections(binary):
    rows = []
    for index, section in enumerate(binary.sections):
        kind = enum_name(section.type)
        rows.append({
            "index": index,
            "name": text(section.name),
            "type": kind,
            "flags": names(section.flags_list),
            "virtual_address": hexa(section.virtual_address),
            "virtual_size": hexa(section.size),
            "file_offset": hexa(section.offset),
            "file_size": hexa(0 if kind in ZEROFILL_TYPES else section.size),
            "segment": text(section.segment_name),
        })
    return rows


def macho_segments(binary):
    return [{
        "index": index,
        "name": text(segment.name),
        "type": None,
        "flags": protection(segment.init_protection),
        "max_protection": protection(segment.max_protection),
        "virtual_address": hexa(segment.virtual_address),
        "virtual_size": hexa(segment.virtual_size),
        "file_offset": hexa(segment.file_offset),
        "file_size": hexa(segment.file_size),
        "sections": [text(section.name) for section in segment.sections],
    } for index, segment in enumerate(binary.segments)]


def macho_symbol_row(symbol, export):
    library = None
    if not export and symbol.has_binding_info and symbol.binding_info.has_library:
        library = text(symbol.binding_info.library.name)
    return {
        "name": text(symbol.name),
        "library": library,
        "ordinal": None,
        "address": hexa(symbol.value) if export else None,
        "kind": "symbol",
        "binding": None,
        "version": None,
        "forwarder": None,
    }


def macho_imports(binary):
    return [macho_symbol_row(symbol, False) for symbol in binary.imported_symbols]


def macho_exports(binary):
    return [macho_symbol_row(symbol, True) for symbol in binary.exported_symbols]


def version_text(value):
    return ".".join(str(int(part)) for part in value)


def macho_summary(binary):
    header = binary.header
    signature = None
    if binary.has_code_signature:
        signature = {
            "data_offset": hexa(binary.code_signature.data_offset),
            "data_size": hexa(binary.code_signature.data_size),
        }
    build = None
    if binary.has_build_version:
        build = {
            "platform": enum_name(binary.build_version.platform),
            "minos": version_text(binary.build_version.minos),
            "sdk": version_text(binary.build_version.sdk),
        }
    return {
        "entrypoint": hexa(binary.entrypoint) if binary.has_entrypoint else None,
        "imagebase": hexa(binary.imagebase),
        # LC_ID_DYLIB names this image itself; it is not a dependency.
        "libraries": [text(library.name) for library in binary.libraries if enum_name(library.command) != "ID_DYLIB"],
        "elf": None,
        "pe": None,
        "macho": {
            "magic": enum_name(header.magic),
            "cpu_type": enum_name(header.cpu_type),
            "cpu_subtype": int(header.cpu_subtype),
            "file_type": enum_name(header.file_type),
            "flags": names(header.flags_list),
            "load_commands": [
                {"index": index, "command": enum_name(command.command), "offset": hexa(command.command_offset), "size": hexa(command.size)}
                for index, command in enumerate(binary.commands)
            ],
            "libraries": [
                {
                    "name": text(library.name),
                    "command": enum_name(library.command),
                    "current_version": version_text(library.current_version),
                    "compatibility_version": version_text(library.compatibility_version),
                }
                for library in binary.libraries
            ],
            "code_signature": signature,
            "uuid": "".join(f"{int(byte):02x}" for byte in binary.uuid.uuid) if binary.has_uuid else None,
            "build_version": build,
            "rpaths": [text(rpath.path) for rpath in binary.rpaths],
        },
    }


# ---- Dispatch --------------------------------------------------------------

def tables(lief, kind, binary):
    if kind == "elf":
        return {
            "sections": lambda: elf_sections(binary),
            "segments": lambda: elf_segments(lief, binary),
            "imports": lambda: elf_imports(binary),
            "exports": lambda: elf_exports(binary),
        }
    if kind == "pe":
        return {
            "sections": lambda: pe_sections(binary),
            "segments": None,
            "imports": lambda: pe_imports(binary),
            "exports": lambda: pe_exports(binary),
        }
    return {
        "sections": lambda: macho_sections(binary),
        "segments": lambda: macho_segments(binary),
        "imports": lambda: macho_imports(binary),
        "exports": lambda: macho_exports(binary),
    }


def inspect(request):
    lief, version = admitted_version(request["admitted_release"])
    kind, binary, macho = parse(lief, request["snapshot_path"], request["macho_slice"])
    builders = tables(lief, kind, binary)
    operation = request["operation"]
    value = {
        "lief_version": version,
        "python_version": sys.version.split()[0],
        "format": kind,
        "macho": macho,
        "summary": None,
        "page": None,
    }
    if operation == "summary":
        detail = {"elf": lambda: elf_summary(lief, binary), "pe": lambda: pe_summary(binary), "macho": lambda: macho_summary(binary)}[kind]()
        counts = {name: (None if build is None else len(build())) for name, build in builders.items()}
        value["summary"] = {
            **common(binary),
            "entrypoint": detail["entrypoint"],
            "imagebase": detail["imagebase"],
            "counts": {**counts, "libraries": len(detail["libraries"])},
            "libraries": detail["libraries"],
            "elf": detail["elf"],
            "pe": detail["pe"],
            "macho": detail["macho"],
        }
        return value
    build = builders[operation]
    rows = [] if build is None else build()
    offset = request["offset"]
    limit = request["limit"]
    selected = rows[offset:] if limit is None else rows[offset:offset + limit]
    value["page"] = {
        "applicable": build is not None,
        "total": len(rows),
        "items": selected,
    }
    return value


def main(request_path):
    with open(request_path, "r", encoding="utf-8") as handle:
        request = json.load(handle)
    output_bytes = int(request["output_bytes"])
    limits = None
    # Release emergency headroom before reporting an allocation failure.
    reserve = bytearray(1024 * 1024)
    try:
        limits = lower_resource_limits(output_bytes, int(request["address_space_bytes"]))
        value = inspect(request)
        value["resource_limits"] = limits
        reply = {"ok": True, "value": value}
    except Refusal as error:
        reply = {"ok": False, "reason": error.reason, "message": str(error), **error.details}
    except ImportError as error:
        reply = {"ok": False, "reason": "unavailable", "message": f"The selected Python cannot import lief: {type(error).__name__}: {error}"}
    except MemoryError:
        reserve = None
        reply = {"ok": False, "reason": "resource-limit", "message": "LIEF memory allocation failed under the effective resource limits; the exact allocation is unknown.", "resource_limits": limits}
    except Exception as error:  # noqa: BLE001 - every other parser failure is reported, not partial success
        reply = {"ok": False, "reason": "decoder", "message": f"{type(error).__name__}: {error}"}
    del reserve
    encoded = json.dumps(reply, ensure_ascii=True, allow_nan=False).encode("utf-8")
    if len(encoded) > output_bytes:
        encoded = json.dumps({"ok": False, "reason": "output-limit", "message": f"The LIEF reply needs {len(encoded)} bytes, above the {output_bytes}-byte reply budget.", "reply_bytes": len(encoded)}).encode("utf-8")
    descriptor = os.open(request["reply_path"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encoded)


if __name__ == "__main__":
    main(sys.argv[1])
