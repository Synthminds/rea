import {
  inspectWithLiefInputSchema,
  liefInspectionSchema,
} from "../../domain/lief/liefInspection.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Optional caller-supplied LIEF capability with target-free CLI/MCP parity. */
export const INSPECT_WITH_LIEF_CONTRACT = {
  name: "inspect_with_lief",
  ...toolContractMetadata("inspect_with_lief"),
  kind: "artifact-provider",
  description:
    "Inspect one explicit local ELF, PE or Mach-O file's structure with caller-supplied LIEF 1.0.x, read-only and without executing the target. operation summary (default) returns format, architecture, entry point, image base, table counts and dependency libraries, plus ELF interpreter/soname/runpath, PE data directories, rich header and Authenticode signature presence, or Mach-O load commands, code-signature location, UUID, build version and universal slices. sections, segments, imports and exports return one page of that table with flags and hex addresses; use offset/limit and next_offset for large tables. macho_slice selects a universal slice. Returns artifact SHA-256 before and after, coverage, parser diagnostics and limitations inline as Evidence. Signatures are located, not verified; ELF imports have no per-library binding. Configure absolute REA_LIEF_PYTHON; REA never installs Python or LIEF. command_timeout_ms bounds the helper process (default 120000 ms); max_file_bytes bounds the read (default 256 MiB). Linux x64 hosts.",
  inputSchema: inspectWithLiefInputSchema,
  outputSchema: evidenceResultOf(liefInspectionSchema),
  examples: [
    {
      title: "Summarize an executable's structure",
      input: { path: "/artifacts/application.exe" },
    },
    {
      title: "Page through a library's exports",
      input: {
        path: "/artifacts/libexample.so",
        operation: "exports",
        offset: 0,
        limit: 200,
      },
    },
    {
      title: "Inspect the second slice of a universal Mach-O",
      input: {
        path: "/artifacts/Application",
        operation: "summary",
        macho_slice: 1,
      },
    },
  ],
} as const satisfies ToolContract;

export const LIEF_TOOL_CONTRACTS = [INSPECT_WITH_LIEF_CONTRACT] as const;
