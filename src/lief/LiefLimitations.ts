import type { LiefInspection } from "../domain/lief/liefInspection.js";
import { LIEF_LIMITS } from "./LiefRelease.js";

type Facet = LiefInspection["operation"];
type Format = LiefInspection["format"];

/** Facet- and format-specific meaning that a reader could otherwise misread. */
const FACET_NOTES: Readonly<
  Partial<Record<Facet, Partial<Record<Format | "all", string>>>>
> = {
  summary: {
    all: "entrypoint is null when the header declares none (a zero ELF e_entry or PE AddressOfEntryPoint, or no Mach-O LC_MAIN/thread command). libraries are declared dependency names, not resolved runtime paths. imagebase is LIEF's linked base: PE ImageBase, the lowest ELF PT_LOAD address (null without PT_LOAD) or the Mach-O __TEXT address.",
    pe: "signatures counts parsed Authenticode signatures only; signature validity, chain trust and timestamps were not verified. data_directories lists entries with a nonzero RVA or size; the certificate table's rva is a file offset.",
    macho:
      "code_signature locates the LC_CODE_SIGNATURE blob only; the signature was neither parsed nor verified. The summary libraries list omits LC_ID_DYLIB, which names the image itself; macho.libraries keeps every dylib command.",
  },
  sections: {
    elf: "file_size is zero for SHT_NOBITS sections, which occupy no file bytes; virtual_size keeps the declared size.",
    macho:
      "file_size is zero for zero-fill sections, which occupy no file bytes; virtual_size keeps the declared size.",
  },
  segments: {
    pe: "PE images have no segment table; this facet is not applicable.",
  },
  imports: {
    elf: "ELF imports are undefined dynamic symbols. ELF does not bind a symbol to one DT_NEEDED library, so library is null; the runtime linker resolves it.",
    macho:
      "Mach-O import library comes from LIEF's bind information; it is null for flat-namespace or dynamic-lookup symbols.",
    pe: "PE import address is the IAT entry RVA; delay-load imports have no IAT address here. Bound-import timestamps are not reported.",
  },
};

const identityNotes = (report: LiefInspection): string[] => {
  const notes: string[] = [];
  if (report.coverage.parser_diagnostics === "reported")
    notes.push(
      "LIEF or Python wrote diagnostics to stderr (diagnostics.stderr); structures named there may be incomplete.",
    );
  if (report.artifact_after.changed === true)
    notes.push(
      "The selected file changed after REA copied it. Results describe the copied bytes (artifact.sha256), not the current file (artifact_after.sha256).",
    );
  else if (report.artifact_after.sha256 === null)
    notes.push(
      "The post-run digest of the selected file could not be read, so whether it changed after REA copied it is unknown.",
    );
  if (report.macho?.universal === true)
    notes.push(
      `Mach-O offsets are relative to the selected slice ${String(report.macho.selected_index)}; add macho.slices[${String(report.macho.selected_index)}].fat_offset for offsets in the universal file. Other slices were not read for this facet.`,
    );
  return notes;
};

/** State what the LIEF facet establishes and what it leaves unknown. */
export const liefLimitations = (report: LiefInspection): string[] => {
  const limits = report.resource_limits;
  const facet = FACET_NOTES[report.operation];
  return [
    "LIEF read a private read-only copy of the bytes identified by artifact.sha256. The helper never received the original path and REA verified the copy was unchanged afterwards. No target code was executed. The selected Python and LIEF installation are trusted caller-supplied code; this is not an OS sandbox.",
    "Rows, counts and absences reflect LIEF's parsed model. LIEF tolerates malformed structures and can skip entries it cannot parse, so an empty or short table does not prove the file declares none.",
    ...identityNotes(report),
    "Addresses, offsets and sizes are hexadecimal strings. Virtual addresses are linked addresses, not runtime addresses. Type, flag and command names are LIEF enumeration names.",
    ...[facet?.all, facet?.[report.format]].filter(
      (note): note is string => note !== undefined,
    ),
    ...(report.operation === "summary"
      ? []
      : [
          "Each page call parses the file again. Row order is stable for the same artifact.sha256 and LIEF version; continue from next_offset and compare artifact.sha256 across pages.",
        ]),
    `Python soft limits applied to the helper: address space ${String(limits.address_space_bytes ?? "not applied")}, file size ${String(limits.file_size_bytes ?? "not applied")}, core files ${String(limits.core_file_bytes ?? "not applied")} bytes; inherited tighter limits are kept. Fixed budgets: ${String(LIEF_LIMITS.replyBytes)}-byte reply and ${String(LIEF_LIMITS.diagnosticBytes)}-byte diagnostics, with no runtime override.`,
  ];
};
