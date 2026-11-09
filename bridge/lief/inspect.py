"""Read-only LIEF structure reader for REA's inspect_with_lief workflow.

REA runs this file with a caller-supplied interpreter in isolated mode (-I -B)
from a private runtime directory. The request names a private read-only copy of
the selected artifact; this helper never receives the original path. It only
reads that copy through LIEF's parsers and writes one JSON reply into the
private directory. No LIEF builder, writer or patching API is called here.
"""
import hashlib
import json
import os
import re
import sys

MACHO_MAGICS = ("MAGIC", "MAGIC_64", "CIGAM", "CIGAM_64")
# The loaded native module is digested so REA can re-check it after the run.
MODULE_MAX_BYTES = 256 * 1024 * 1024


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


def bounded(message, limit):
    """At most `limit` UTF-8 bytes of `message`, cut on a character boundary, and its full size."""
    encoded = message.encode("utf-8", "replace")
    if len(encoded) <= limit:
        return message, len(encoded)
    return encoded[:limit].decode("utf-8", "ignore"), len(encoded)


def hexa(value):
    return hex(int(value))


def enum_name(value):
    # LIEF returns a bare int for a value outside its enumeration.
    name = getattr(value, "name", None)
    return name if isinstance(name, str) and name else str(int(value))


def names(values):
    return [enum_name(value) for value in values]


# ---- Strings ---------------------------------------------------------------
# LIEF decodes file strings as strict UTF-8. Some accessors return bytes when
# that fails and others raise UnicodeDecodeError, whose `object` holds the exact
# source bytes. Valid UTF-8 stays a JSON string; any other byte string becomes
# {"text": null, "bytes_hex": ...} so identity is never replaced by a display form.

def raw_bytes(read):
    try:
        value = read()
    except UnicodeDecodeError as error:
        return bytes(error.object)
    if isinstance(value, str):
        return value.encode("utf-8", "surrogatepass")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"LIEF returned {type(value).__name__} where a string was expected")


def text_of(raw):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return {"text": None, "bytes_hex": raw.hex()}


def text(read):
    """Decode one LIEF string accessor at this boundary."""
    return text_of(raw_bytes(read))


class Fields:
    """Read optional summary fields so one unreadable field cannot abort the summary."""

    def __init__(self):
        self.unread = []

    def read(self, field, read):
        try:
            return read()
        except MemoryError:
            raise
        except Exception as error:  # noqa: BLE001 - recorded per field, not swallowed
            self.unread.append({"field": field, "error": bounded(f"{type(error).__name__}: {error}", 256)[0]})
            return None


class Listing:
    """The first `rows` items of a summary list, its total and a truncation marker."""

    def __init__(self, rows):
        self.rows = rows
        self.truncated = []

    def take(self, field, items, operation):
        """Keep at most `rows` items of a lazily built list; count the rest without building them."""
        kept = []
        total = 0
        for item in items:
            if total < self.rows:
                kept.append(item())
            total += 1
        if total > len(kept):
            self.truncated.append({"field": field, "total": total, "returned": len(kept), "operation": operation})
        return kept


def window(items, offset, limit):
    """Count a table and build only the rows inside [offset, offset + limit)."""
    end = None if limit is None else offset + limit
    total = 0
    rows = []
    for build in items:
        if total >= offset and (end is None or total < end):
            rows.append(build())
        total += 1
    return total, rows


def count(items):
    return sum(1 for _ in items)


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


def module_identity(lief):
    """Resolved path and SHA-256 of the loaded native LIEF module, before parsing."""
    native = sys.modules.get("lief._lief")
    location = getattr(native, "__file__", None)
    if not isinstance(location, str):
        raise Refusal("unavailable", "The imported lief package has no native _lief module file to identify.")
    path = os.path.realpath(location)
    digest = hashlib.sha256()
    total = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            total += len(chunk)
            if total > MODULE_MAX_BYTES:
                raise Refusal("unavailable", f"The native LIEF module exceeds the {MODULE_MAX_BYTES}-byte identity budget.")
            digest.update(chunk)
    return {"path": path, "sha256": digest.hexdigest()}


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

def elf_dynamic(lief, binary, *tags):
    return [entry for entry in binary.dynamic_entries if entry.tag in tags]


def elf_needed(lief, binary):
    for entry in elf_dynamic(lief, binary, lief.ELF.DynamicEntry.TAG.NEEDED):
        yield lambda entry=entry: {
            "name": text(lambda: entry.name),
            "kind": "NEEDED",
            "current_version": None,
            "compatibility_version": None,
        }


def elf_rpaths(lief, binary):
    """Every path of every DT_RPATH and DT_RUNPATH entry in dynamic-table order, split from raw bytes."""
    tags = lief.ELF.DynamicEntry.TAG
    for entry in elf_dynamic(lief, binary, tags.RPATH, tags.RUNPATH):
        attribute = "rpath" if entry.tag == tags.RPATH else "runpath"
        for path in raw_bytes(lambda entry=entry, attribute=attribute: getattr(entry, attribute)).split(b":"):
            yield lambda kind=enum_name(entry.tag), path=path: {"path": text_of(path), "kind": kind}


def elf_version(symbol):
    if not symbol.has_version:
        return None
    version = symbol.symbol_version
    if version.has_auxiliary_version:
        return text(lambda: version.symbol_version_auxiliary.name)
    return None


def elf_sections(binary):
    for index, section in enumerate(binary.sections):
        yield lambda index=index, section=section: elf_section_row(index, section)


def elf_section_row(index, section):
    kind = enum_name(section.type)
    return {
        "index": index,
        "name": text(lambda: section.name),
        "type": kind,
        "flags": names(section.flags_list),
        "virtual_address": hexa(section.virtual_address),
        "virtual_size": hexa(section.size),
        "file_offset": hexa(section.offset),
        "file_size": hexa(0 if kind == "NOBITS" else section.size),
        "segment": None,
    }


def elf_segments(lief, binary):
    flags = lief.ELF.Segment.FLAGS
    for index, segment in enumerate(binary.segments):
        yield lambda index=index, segment=segment: {
            "index": index,
            "name": None,
            "type": enum_name(segment.type),
            "flags": [name for name, flag in (("read", flags.R), ("write", flags.W), ("execute", flags.X)) if segment.has(flag)],
            "max_protection": None,
            "virtual_address": hexa(segment.virtual_address),
            "virtual_size": hexa(segment.virtual_size),
            "file_offset": hexa(segment.file_offset),
            "file_size": hexa(segment.physical_size),
            "sections": [text(lambda: section.name) for section in segment.sections],
        }


def elf_symbol_row(symbol, address):
    return {
        "name": text(lambda: symbol.name),
        "library": None,
        "ordinal": None,
        "address": hexa(symbol.value) if address else None,
        "kind": enum_name(symbol.type),
        "binding": enum_name(symbol.binding),
        "version": elf_version(symbol),
        "forwarder": None,
    }


def elf_dynamic_symbols(lief, binary, exported):
    """.dynsym only: imports are undefined GLOBAL/WEAK symbols; exports are defined
    GLOBAL/WEAK/GNU_UNIQUE symbols with default or protected visibility. .symtab is
    a link-time table and is never read as the dynamic interface."""
    binding = lief.ELF.Symbol.BINDING
    visibility = lief.ELF.Symbol.VISIBILITY
    imported_bindings = (binding.GLOBAL, binding.WEAK)
    exported_bindings = (binding.GLOBAL, binding.WEAK, binding.GNU_UNIQUE)
    visible = (visibility.DEFAULT, visibility.PROTECTED)
    for symbol in binary.dynamic_symbols:
        if symbol.shndx == 0:
            if not exported and symbol.binding in imported_bindings:
                yield lambda symbol=symbol: elf_symbol_row(symbol, False)
        elif exported and symbol.binding in exported_bindings and symbol.visibility in visible:
            yield lambda symbol=symbol: elf_symbol_row(symbol, True)


def elf_summary(lief, binary, fields, listing):
    header = binary.header
    tags = lief.ELF.DynamicEntry.TAG
    raw_entry = int(header.entrypoint)
    loads = [segment for segment in binary.segments if enum_name(segment.type) == "LOAD"]

    def soname():
        entries = elf_dynamic(lief, binary, tags.SONAME)
        return text(lambda: entries[0].name) if entries else None

    def search(tag, field):
        entries = elf_dynamic(lief, binary, tag)
        if not entries:
            return None
        attribute = "rpath" if tag == tags.RPATH else "runpath"
        paths = (path for entry in entries for path in raw_bytes(lambda entry=entry: getattr(entry, attribute)).split(b":"))
        return listing.take(field, ((lambda path=path: text_of(path)) for path in paths), "rpaths")

    def interpreter():
        if not binary.has_interpreter:
            return None
        return text(lambda: binary.interpreter)

    return {
        "entrypoint": None if raw_entry == 0 else hexa(raw_entry),
        # LIEF reports UINT64_MAX when no PT_LOAD exists; that is not an address.
        "imagebase": hexa(binary.imagebase) if loads else None,
        "elf": {
            "file_type": enum_name(header.file_type),
            "machine": enum_name(header.machine_type),
            "class": enum_name(header.identity_class),
            "data": enum_name(header.identity_data),
            "os_abi": enum_name(header.identity_os_abi),
            "header_entrypoint": hexa(raw_entry),
            "interpreter": fields.read("elf.interpreter", interpreter),
            "soname": fields.read("elf.soname", soname),
            "rpath": fields.read("elf.rpath", lambda: search(tags.RPATH, "elf.rpath")),
            "runpath": fields.read("elf.runpath", lambda: search(tags.RUNPATH, "elf.runpath")),
        },
        "pe": None,
        "macho": None,
    }


# ---- PE --------------------------------------------------------------------

def pe_sections(binary):
    for index, section in enumerate(binary.sections):
        yield lambda index=index, section=section: {
            "index": index,
            "name": text(lambda: section.name),
            "type": None,
            "flags": names(section.characteristics_lists),
            "virtual_address": hexa(section.virtual_address),
            "virtual_size": hexa(section.virtual_size),
            "file_offset": hexa(section.offset),
            "file_size": hexa(section.size),
            "segment": None,
        }


def pe_import_row(library, entry, kind, address):
    ordinal = int(entry.ordinal) if entry.is_ordinal else None
    return {
        "name": None if entry.is_ordinal else text(lambda: entry.name),
        "library": text(lambda: library.name),
        "ordinal": ordinal,
        "address": None if address is None else hexa(address),
        "kind": kind,
        "binding": None,
        "version": None,
        "forwarder": None,
    }


def pe_imports(binary):
    for library in binary.imports:
        for entry in library.entries:
            yield lambda library=library, entry=entry: pe_import_row(library, entry, "import", entry.iat_address)
    for library in binary.delay_imports:
        for entry in library.entries:
            yield lambda library=library, entry=entry: pe_import_row(library, entry, "delay-import", None)


def pe_forwarder(entry):
    information = entry.forward_information
    return text_of(raw_bytes(lambda: information.library) + b"." + raw_bytes(lambda: information.function))


def pe_export_row(entry):
    forwarded = bool(entry.is_forwarded)
    name = raw_bytes(lambda: entry.name)
    return {
        "name": text_of(name) if name else None,
        "library": None,
        "ordinal": int(entry.ordinal),
        "address": None if forwarded else hexa(entry.address),
        "kind": "export",
        "binding": None,
        "version": None,
        "forwarder": pe_forwarder(entry) if forwarded else None,
    }


def pe_exports(binary):
    if not binary.has_exports:
        return
    for entry in binary.get_export().entries:
        yield lambda entry=entry: pe_export_row(entry)


def pe_libraries(binary):
    for kind, libraries in (("import", binary.imports), ("delay-import", binary.delay_imports)):
        for library in libraries:
            yield lambda library=library, kind=kind: {
                "name": text(lambda: library.name),
                "kind": kind,
                "current_version": None,
                "compatibility_version": None,
            }


def pe_summary(binary, fields, listing):
    header = binary.header
    optional = binary.optional_header
    entry_rva = int(optional.addressof_entrypoint)
    directories = []
    for directory in binary.data_directories:
        if int(directory.rva) == 0 and int(directory.size) == 0:
            continue
        kind = enum_name(directory.type)
        directories.append({
            "type": kind,
            "rva": hexa(directory.rva),
            "size": hexa(directory.size),
            "section": fields.read(
                f"pe.data_directories.{kind}.section",
                lambda directory=directory: text(lambda: directory.section.name) if directory.has_section else None,
            ),
        })
    rich = None
    if binary.has_rich_header:
        rich = {
            "key": hexa(binary.rich_header.key),
            "entry_count": len(binary.rich_header.entries),
            "entries": listing.take(
                "pe.rich_header.entries",
                (
                    (lambda entry=entry: {"id": int(entry.id), "build_id": int(entry.build_id), "count": int(entry.count)})
                    for entry in binary.rich_header.entries
                ),
                None,
            ),
        }
    signatures = len(binary.signatures)
    return {
        "entrypoint": None if entry_rva == 0 else hexa(int(optional.imagebase) + entry_rva),
        "imagebase": hexa(optional.imagebase),
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
            "signatures": {"present": signatures > 0, "count": signatures},
            "export_name": fields.read(
                "pe.export_name",
                lambda: text(lambda: binary.get_export().name) if binary.has_exports else None,
            ),
        },
        "macho": None,
    }


# ---- Mach-O ----------------------------------------------------------------

ZEROFILL_TYPES = {"ZEROFILL", "GB_ZEROFILL", "THREAD_LOCAL_ZEROFILL"}


def protection(value):
    value = int(value)
    return [name for name, bit in (("read", 1), ("write", 2), ("execute", 4)) if value & bit]


def macho_sections(binary):
    for index, section in enumerate(binary.sections):
        yield lambda index=index, section=section: macho_section_row(index, section)


def macho_section_row(index, section):
    kind = enum_name(section.type)
    return {
        "index": index,
        "name": text(lambda: section.name),
        "type": kind,
        "flags": names(section.flags_list),
        "virtual_address": hexa(section.virtual_address),
        "virtual_size": hexa(section.size),
        "file_offset": hexa(section.offset),
        "file_size": hexa(0 if kind in ZEROFILL_TYPES else section.size),
        "segment": text(lambda: section.segment_name),
    }


def macho_segments(binary):
    for index, segment in enumerate(binary.segments):
        yield lambda index=index, segment=segment: {
            "index": index,
            "name": text(lambda: segment.name),
            "type": None,
            "flags": protection(segment.init_protection),
            "max_protection": protection(segment.max_protection),
            "virtual_address": hexa(segment.virtual_address),
            "virtual_size": hexa(segment.virtual_size),
            "file_offset": hexa(segment.file_offset),
            "file_size": hexa(segment.file_size),
            "sections": [text(lambda: section.name) for section in segment.sections],
        }


def macho_symbol_row(symbol, export):
    library = None
    if not export and symbol.has_binding_info and symbol.binding_info.has_library:
        library = text(lambda: symbol.binding_info.library.name)
    return {
        "name": text(lambda: symbol.name),
        "library": library,
        "ordinal": None,
        "address": hexa(symbol.value) if export else None,
        "kind": "symbol",
        "binding": None,
        "version": None,
        "forwarder": None,
    }


def macho_symbols(binary, exported):
    """LIEF's imported/exported predicates over one linear pass of the symbol table."""
    for symbol in binary.symbols:
        external = symbol.is_external
        exports = symbol.has_export_info
        if (exported and exports and not external) or (not exported and external and not exports):
            yield lambda symbol=symbol: macho_symbol_row(symbol, exported)


def version_text(value):
    return ".".join(str(int(part)) for part in value)


def macho_dylibs(lief, binary):
    for command in binary.commands:
        if isinstance(command, lief.MachO.DylibCommand):
            yield command


def macho_library_row(library):
    return {
        "name": text(lambda: library.name),
        "kind": enum_name(library.command),
        "current_version": version_text(library.current_version),
        "compatibility_version": version_text(library.compatibility_version),
    }


def macho_libraries(lief, binary):
    # LC_ID_DYLIB names this image itself; it is not a dependency.
    for library in macho_dylibs(lief, binary):
        if enum_name(library.command) != "ID_DYLIB":
            yield lambda library=library: macho_library_row(library)


def macho_rpaths(lief, binary):
    for command in binary.commands:
        if isinstance(command, lief.MachO.RPathCommand):
            yield lambda command=command: {"path": text(lambda: command.path), "kind": enum_name(command.command)}


def macho_load_commands(binary):
    for index, command in enumerate(binary.commands):
        yield lambda index=index, command=command: {
            "index": index,
            "command": enum_name(command.command),
            "offset": hexa(command.command_offset),
            "size": hexa(command.size),
        }


def macho_summary(lief, binary, fields, listing):
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

    def id_dylib():
        for library in macho_dylibs(lief, binary):
            if enum_name(library.command) == "ID_DYLIB":
                row = macho_library_row(library)
                return {key: row[key] for key in ("name", "current_version", "compatibility_version")}
        return None

    return {
        "entrypoint": hexa(binary.entrypoint) if binary.has_entrypoint else None,
        "imagebase": hexa(binary.imagebase),
        "elf": None,
        "pe": None,
        "macho": {
            "magic": enum_name(header.magic),
            "cpu_type": enum_name(header.cpu_type),
            "cpu_subtype": int(header.cpu_subtype),
            "file_type": enum_name(header.file_type),
            "flags": names(header.flags_list),
            "load_commands": listing.take("macho.load_commands", macho_load_commands(binary), "load_commands"),
            "id_dylib": fields.read("macho.id_dylib", id_dylib),
            "code_signature": signature,
            "uuid": "".join(f"{int(byte):02x}" for byte in binary.uuid.uuid) if binary.has_uuid else None,
            "build_version": build,
            "rpaths": fields.read(
                "macho.rpaths",
                lambda: listing.take("macho.rpaths", ((lambda build=build: build()["path"]) for build in macho_rpaths(lief, binary)), "rpaths"),
            ),
        },
    }


# ---- Dispatch --------------------------------------------------------------

def tables(lief, kind, binary):
    """Each list operation as a factory of lazy row builders, or None when not applicable."""
    if kind == "elf":
        return {
            "sections": lambda: elf_sections(binary),
            "segments": lambda: elf_segments(lief, binary),
            "imports": lambda: elf_dynamic_symbols(lief, binary, False),
            "exports": lambda: elf_dynamic_symbols(lief, binary, True),
            "libraries": lambda: elf_needed(lief, binary),
            "rpaths": lambda: elf_rpaths(lief, binary),
            "load_commands": None,
        }
    if kind == "pe":
        return {
            "sections": lambda: pe_sections(binary),
            "segments": None,
            "imports": lambda: pe_imports(binary),
            "exports": lambda: pe_exports(binary),
            "libraries": lambda: pe_libraries(binary),
            "rpaths": None,
            "load_commands": None,
        }
    return {
        "sections": lambda: macho_sections(binary),
        "segments": lambda: macho_segments(binary),
        "imports": lambda: macho_symbols(binary, False),
        "exports": lambda: macho_symbols(binary, True),
        "libraries": lambda: macho_libraries(lief, binary),
        "rpaths": lambda: macho_rpaths(lief, binary),
        "load_commands": lambda: macho_load_commands(binary),
    }


def summary(lief, kind, binary, builders, rows):
    fields = Fields()
    listing = Listing(rows)
    detail = {
        "elf": lambda: elf_summary(lief, binary, fields, listing),
        "pe": lambda: pe_summary(binary, fields, listing),
        "macho": lambda: macho_summary(lief, binary, fields, listing),
    }[kind]()
    libraries = fields.read(
        "libraries",
        lambda: listing.take("libraries", ((lambda build=build: build()["name"]) for build in builders["libraries"]()), "libraries"),
    )
    counts = {}
    for name, build in builders.items():
        # Counting walks each table once without building its rows.
        counts[name] = None if build is None else fields.read(f"counts.{name}", lambda build=build: count(build()))
    return {
        **common(binary),
        "entrypoint": detail["entrypoint"],
        "imagebase": detail["imagebase"],
        "counts": counts,
        "libraries": libraries,
        "elf": detail["elf"],
        "pe": detail["pe"],
        "macho": detail["macho"],
        "truncated_lists": listing.truncated,
        "unread_fields": fields.unread,
    }


def inspect(request):
    lief, version = admitted_version(request["admitted_release"])
    native_module = module_identity(lief)
    kind, binary, macho = parse(lief, request["snapshot_path"], request["macho_slice"])
    builders = tables(lief, kind, binary)
    operation = request["operation"]
    value = {
        "lief_version": version,
        "python_version": sys.version.split()[0],
        "native_module": native_module,
        "format": kind,
        "macho": macho,
        "summary": None,
        "page": None,
    }
    if operation == "summary":
        value["summary"] = summary(lief, kind, binary, builders, int(request["summary_rows"]))
        return value
    build = builders[operation]
    if build is None:
        value["page"] = {"applicable": False, "total": 0, "items": []}
        return value
    total, items = window(build(), int(request["offset"]), request["limit"])
    value["page"] = {"applicable": True, "total": total, "items": items}
    return value


def refusal(reason, message, limit, limits, **details):
    excerpt, size = bounded(message, limit)
    return {"ok": False, "reason": reason, "message": excerpt, "message_bytes": size, "resource_limits": limits, **details}


def encode(reply):
    return json.dumps(reply, ensure_ascii=True, allow_nan=False).encode("utf-8")


def main(request_path):
    with open(request_path, "r", encoding="utf-8") as handle:
        request = json.load(handle)
    output_bytes = int(request["output_bytes"])
    message_bytes = int(request["message_bytes"])
    limits = None
    # Released before reporting an allocation failure, so the refusal itself can be encoded.
    reserve = bytearray(1024 * 1024)
    try:
        limits = lower_resource_limits(output_bytes, int(request["address_space_bytes"]))
        value = inspect(request)
        value["resource_limits"] = limits
        # Encoding the reply can need as much memory as building it.
        encoded = encode({"ok": True, "value": value})
        value = None
    except Refusal as error:
        encoded = encode(refusal(error.reason, str(error), message_bytes, limits, **error.details))
    except ImportError as error:
        encoded = encode(refusal("unavailable", f"The selected Python cannot import lief: {type(error).__name__}: {error}", message_bytes, limits))
    except MemoryError:
        reserve = None
        value = None
        encoded = encode(refusal("resource-limit", "LIEF or reply encoding exhausted memory under the effective resource limits; the exact allocation is unknown.", message_bytes, limits))
    except Exception as error:  # noqa: BLE001 - every other parser failure is reported, not partial success
        encoded = encode(refusal("decoder", f"{type(error).__name__}: {error}", message_bytes, limits))
    del reserve
    if len(encoded) > output_bytes:
        encoded = encode(refusal(
            "output-limit",
            f"The LIEF reply needs {len(encoded)} bytes, above the {output_bytes}-byte reply budget.",
            message_bytes,
            limits,
            reply_bytes=len(encoded),
        ))
    descriptor = os.open(request["reply_path"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encoded)


if __name__ == "__main__":
    main(sys.argv[1])
