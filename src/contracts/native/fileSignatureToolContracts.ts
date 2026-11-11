import {
  detectFileSignaturesInputSchema,
  fileSignaturesSchema,
} from "../../domain/native/fileSignatures.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Static protection and toolchain detection; never unpacking or bypass. */
export const FILE_SIGNATURE_TOOL_CONTRACTS = [
  {
    name: "detect_file_signatures",
    ...toolContractMetadata("detect_file_signatures"),
    kind: "native-provider",
    description:
      "Identify one explicit local file with caller-supplied Detect It Easy (DiE) without executing, unpacking or extracting it. Returns DiE's signature detections as leads: file type, compiler, linker, library, packer and protector names with versions, DiE's heuristic marker and the file parts (such as overlays) they belong to, plus before/after SHA-256 and the exact DiE tool profile. A detection is not proof that a component is present or that the file is malicious or safe, and a missing detection proves nothing. deep_scan, heuristic_scan, recursive_scan, verbose and all_types select DiE's own scan options. Linux x64: set absolute REA_DIE_PYTHON (Python with die-python 0.5.0) plus util-linux prlimit; REA_DIE_COMMAND (diec) is refused as unverified. Caller signature databases and scripts are not accepted. command_timeout_ms is each DiE command's deadline (omitted means 120000 ms); the 16 MiB output, 4 GiB address-space and 120 CPU-second ceilings have no runtime override.",
    inputSchema: detectFileSignaturesInputSchema,
    outputSchema: evidenceResultOf(fileSignaturesSchema),
    examples: [
      {
        title: "Identify a file's type, compiler and packer signatures",
        input: { path: "/artifacts/application.exe" },
      },
      {
        title: "Add DiE heuristic and overlay scans",
        input: {
          path: "/artifacts/application.exe",
          heuristic_scan: true,
          recursive_scan: true,
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
