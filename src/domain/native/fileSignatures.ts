import { z } from "zod";

import { digestSchema } from "../digests.js";
import { absoluteLocalPathStringSchema } from "../localPath.js";

/** Omitted `command_timeout_ms` for each DiE command, matching one-shot objdump/rizin. */
export const DEFAULT_FILE_SIGNATURE_COMMAND_TIMEOUT_MS = 120_000;
/** Node timer ceiling. Larger deadlines would be clamped instead of honored. */
export const MAX_FILE_SIGNATURE_COMMAND_TIMEOUT_MS = 2_147_483_647;
/** Omitted `max_file_bytes`: the stable snapshot is held in memory before the scan. */
export const DEFAULT_FILE_SIGNATURE_FILE_BYTES = 67_108_864;
/** Hard ceiling on the resident snapshot copy. */
export const MAX_FILE_SIGNATURE_FILE_BYTES = 536_870_912;

/** One explicit local file; every scan flag maps to one upstream DiE scan option. */
export const detectFileSignaturesInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute path of the local file to identify",
  ),
  deep_scan: z.boolean().default(false).describe("DiE deep scan (diec -d)"),
  heuristic_scan: z
    .boolean()
    .default(false)
    .describe(
      "Add DiE heuristic signatures (diec -u); matches report heuristic true",
    ),
  recursive_scan: z
    .boolean()
    .default(false)
    .describe(
      "Also scan file parts DiE finds inside the file, such as overlays (diec -r)",
    ),
  verbose: z
    .boolean()
    .default(false)
    .describe(
      "Include DiE verbose detections such as operating system (diec -b)",
    ),
  all_types: z
    .boolean()
    .default(false)
    .describe("Scan every file type DiE matches, not only one (diec -a)"),
  max_file_bytes: z
    .number()
    .int()
    .min(1)
    .max(MAX_FILE_SIGNATURE_FILE_BYTES)
    .default(DEFAULT_FILE_SIGNATURE_FILE_BYTES)
    .describe(
      "Maximum stable file bytes to snapshot (default 64 MiB); larger files fail without partial success",
    ),
  command_timeout_ms: z
    .number()
    .int()
    .min(1)
    .max(MAX_FILE_SIGNATURE_COMMAND_TIMEOUT_MS)
    .exactOptional()
    .describe(
      `Deadline in milliseconds for each DiE command, the version probe and the scan (default ${String(DEFAULT_FILE_SIGNATURE_COMMAND_TIMEOUT_MS)}). Applies on the next call; output and resource ceilings stay fixed.`,
    ),
});
export type DetectFileSignaturesInput = z.output<
  typeof detectFileSignaturesInputSchema
>;

/** Caller-supplied DiE distributions this adapter admits. */
export const FILE_SIGNATURE_BACKENDS = ["diec", "die-python"] as const;
export type FileSignatureBackend = (typeof FILE_SIGNATURE_BACKENDS)[number];

const artifact = z.strictObject({
  path: z.string().min(1),
  sha256: digestSchema,
  bytes: z.int().nonnegative(),
});

/**
 * One DiE file-part group. `file_type` and `part` are DiE's own labels; the
 * offset/size strings are reported verbatim because nested parts can report
 * values relative to their containing part.
 */
const filePartSchema = z.strictObject({
  id: z.int().nonnegative(),
  parent: z.int().nonnegative().nullable(),
  file_type: z.string(),
  part: z.string(),
  offset: z.string().nullable(),
  size: z.string().nullable(),
  info: z.string().nullable(),
});

/**
 * One DiE detection. `heuristic` is null when DiE's rendered label does not
 * match its documented rendering of these fields; `label` then retains it.
 */
const detectionSchema = z.strictObject({
  file_part: z.int().nonnegative().nullable(),
  type: z.string(),
  name: z.string(),
  version: z.string(),
  info: z.string(),
  heuristic: z.boolean().nullable(),
  label: z.string().exactOptional(),
});

const toolProfileSchema = z.strictObject({
  backend: z.enum(FILE_SIGNATURE_BACKENDS),
  configuration_key: z.enum(["REA_DIE_COMMAND", "REA_DIE_PYTHON"]),
  executable: z.strictObject({
    path: z.string().min(1),
    resolved_path: z.string().min(1),
    sha256: digestSchema,
  }),
  native_module: z
    .strictObject({ path: z.string().min(1), sha256: digestSchema })
    .nullable()
    .describe(
      "die-python's loaded native scanner module, digested before the scan and verified unchanged after it; null for diec",
    ),
  resource_limiter: z
    .strictObject({
      configured_path: z.string().min(1),
      path: z.string().min(1),
      sha256: digestSchema,
      arguments: z.array(z.string()),
    })
    .describe(
      "util-linux prlimit that ran each DiE command: configured and resolved paths, SHA-256 verified unchanged after the scan, and its arguments ending with the DiE executable",
    ),
  engine_version: z.string().min(1),
  version_banner: z.string().nullable(),
  package_version: z.string().nullable(),
  library_version: z.string().nullable(),
  library_tag: z.string().nullable(),
  database: z.strictObject({
    source: z.enum(["installation-default", "package-bundled"]),
    files: z.int().nonnegative().nullable(),
    sha256: digestSchema.nullable(),
  }),
  arguments: z.array(z.string()),
  timeout_ms: z.int().positive(),
  output_budget_bytes: z.int().positive(),
  resource_limits: z.strictObject({
    address_space_bytes: z.int().positive(),
    cpu_seconds: z.int().positive(),
    file_bytes: z.int().nonnegative(),
  }),
});

/**
 * Static DiE identification leads for one exact selected snapshot. Coverage
 * limitations travel once, on the enclosing Evidence.
 */
export const fileSignaturesSchema = z
  .strictObject({
    artifact,
    artifact_after: z.strictObject({
      sha256: digestSchema.nullable(),
      changed: z.boolean().nullable(),
    }),
    scan: z.strictObject({
      deep_scan: z.boolean(),
      heuristic_scan: z.boolean(),
      recursive_scan: z.boolean(),
      verbose: z.boolean(),
      all_types: z.boolean(),
    }),
    file_parts: z.array(filePartSchema),
    detections: z.array(detectionSchema),
    scan_messages: z.array(z.string()),
    tool_profile: toolProfileSchema,
    target_execution: z.literal("not-performed"),
  })
  .superRefine((value, context) => {
    for (const [index, part] of value.file_parts.entries()) {
      if (part.id !== index)
        context.addIssue({
          code: "custom",
          path: ["file_parts", index, "id"],
          message: "File parts must be numbered in document order.",
        });
      if (part.parent !== null && part.parent >= index)
        context.addIssue({
          code: "custom",
          path: ["file_parts", index, "parent"],
          message: "A file part must follow its containing part.",
        });
    }
    for (const [index, detection] of value.detections.entries())
      if (
        detection.file_part !== null &&
        detection.file_part >= value.file_parts.length
      )
        context.addIssue({
          code: "custom",
          path: ["detections", index, "file_part"],
          message: "Detection refers to an unknown file part.",
        });
    const { sha256, changed } = value.artifact_after;
    if ((sha256 === null) !== (changed === null))
      context.addIssue({
        code: "custom",
        path: ["artifact_after"],
        message: "Post-scan change state requires a post-scan digest.",
      });
    if (sha256 !== null && changed !== (sha256 !== value.artifact.sha256))
      context.addIssue({
        code: "custom",
        path: ["artifact_after", "changed"],
        message: "Post-scan change state contradicts the digests.",
      });
  });
export type FileSignatures = z.output<typeof fileSignaturesSchema>;
