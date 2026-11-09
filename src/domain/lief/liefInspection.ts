import { z } from "zod";

import { absoluteLocalPathStringSchema } from "../localPath.js";
import {
  DEFAULT_REVERSE_COMMAND_TIMEOUT_MS,
  MAX_REVERSE_COMMAND_TIMEOUT_MS,
} from "../reverseEngineering.js";

/** Facets one call can return; list facets page over LIEF's parsed tables. */
export const LIEF_OPERATIONS = [
  "summary",
  "sections",
  "segments",
  "imports",
  "exports",
] as const;
export type LiefOperation = (typeof LIEF_OPERATIONS)[number];
export type LiefListOperation = Exclude<LiefOperation, "summary">;

/** Omitted helper deadline; shares objdump/rizin `command_timeout_ms` semantics. */
export const DEFAULT_LIEF_COMMAND_TIMEOUT_MS =
  DEFAULT_REVERSE_COMMAND_TIMEOUT_MS;
/** Default stable-read budget for the selected artifact (256 MiB). */
export const DEFAULT_LIEF_MAX_FILE_BYTES = 268_435_456;
/**
 * REA holds the artifact once in memory and stages one private copy; LIEF then
 * loads that copy under a 4 GiB address-space reservation.
 */
export const MAX_LIEF_MAX_FILE_BYTES = 536_870_912;

/** One explicitly selected local ELF, PE or Mach-O file and one facet. */
export const inspectWithLiefInputSchema = z
  .strictObject({
    path: absoluteLocalPathStringSchema.describe(
      "Absolute path to a local ELF, PE or Mach-O file",
    ),
    operation: z
      .enum(LIEF_OPERATIONS)
      .default("summary")
      .describe(
        "summary (default): header, entry point, counts and libraries, plus PE data directories/rich header/signature presence or Mach-O load commands/code-signature presence/slices. sections, segments, imports, exports: one page of that table",
      ),
    offset: z
      .number()
      .int()
      .min(0)
      .max(Number.MAX_SAFE_INTEGER)
      .exactOptional()
      .describe("First row of a list operation (default 0)"),
    limit: z
      .number()
      .int()
      .min(1)
      .max(Number.MAX_SAFE_INTEGER)
      .exactOptional()
      .describe(
        "Maximum rows for a list operation; omit to return every row after offset",
      ),
    macho_slice: z
      .number()
      .int()
      .min(0)
      .max(0xffffffff)
      .exactOptional()
      .describe(
        "Mach-O slice index from summary macho.slices (default 0); Mach-O only",
      ),
    max_file_bytes: z
      .number()
      .int()
      .min(64)
      .max(MAX_LIEF_MAX_FILE_BYTES)
      .default(DEFAULT_LIEF_MAX_FILE_BYTES)
      .describe("Maximum stable artifact bytes to read (default 256 MiB)"),
    command_timeout_ms: z
      .number()
      .int()
      .min(1)
      .max(MAX_REVERSE_COMMAND_TIMEOUT_MS)
      .exactOptional()
      .describe(
        `Deadline in milliseconds for the LIEF helper process (default ${String(DEFAULT_LIEF_COMMAND_TIMEOUT_MS)}). Applies on the next call. Does not raise the file, reply or diagnostic byte budgets.`,
      ),
  })
  .superRefine((value, context) => {
    if (value.operation !== "summary") return;
    for (const field of ["offset", "limit"] as const)
      if (value[field] !== undefined)
        context.addIssue({
          code: "custom",
          path: [field],
          message: `${field} applies only to sections, segments, imports and exports`,
        });
  });
export type InspectWithLiefInput = z.output<typeof inspectWithLiefInputSchema>;

const hex = z.string().regex(/^0x[0-9a-f]+$/u);
const enumName = z.string().min(1);
const rowIndex = z.number().int().min(0);
const protection = z.array(z.enum(["read", "write", "execute"]));

const sectionRowSchema = z.strictObject({
  index: rowIndex,
  name: z.string(),
  type: enumName.nullable(),
  flags: z.array(enumName),
  virtual_address: hex,
  virtual_size: hex,
  file_offset: hex,
  file_size: hex,
  segment: z.string().nullable(),
});

const segmentRowSchema = z.strictObject({
  index: rowIndex,
  name: z.string().nullable(),
  type: enumName.nullable(),
  flags: protection,
  max_protection: protection.nullable(),
  virtual_address: hex,
  virtual_size: hex,
  file_offset: hex,
  file_size: hex,
  sections: z.array(z.string()),
});

const symbolRowSchema = z.strictObject({
  name: z.string().nullable(),
  library: z.string().nullable(),
  ordinal: z.number().int().min(0).nullable(),
  address: hex.nullable(),
  kind: enumName,
  binding: enumName.nullable(),
  version: z.string().nullable(),
  forwarder: z.string().nullable(),
});

const elfSummarySchema = z.strictObject({
  file_type: enumName,
  machine: enumName,
  class: enumName,
  data: enumName,
  os_abi: enumName,
  header_entrypoint: hex,
  interpreter: z.string().nullable(),
  soname: z.string().nullable(),
  rpath: z.array(z.string()).nullable(),
  runpath: z.array(z.string()).nullable(),
});

const peSummarySchema = z.strictObject({
  machine: enumName,
  timestamp: z.number().int().min(0).max(0xffffffff),
  characteristics: z.array(enumName),
  magic: enumName,
  subsystem: enumName,
  dll_characteristics: z.array(enumName),
  address_of_entrypoint: hex,
  sizeof_image: hex,
  data_directory_count: z.number().int().min(0),
  data_directories: z.array(
    z.strictObject({
      type: enumName,
      rva: hex,
      size: hex,
      section: z.string().nullable(),
    }),
  ),
  rich_header: z
    .strictObject({
      key: hex,
      entries: z.array(
        z.strictObject({
          id: z.number().int().min(0),
          build_id: z.number().int().min(0),
          count: z.number().int().min(0),
        }),
      ),
    })
    .nullable(),
  signatures: z.strictObject({
    present: z.boolean(),
    count: z.number().int().min(0),
  }),
  export_name: z.string().nullable(),
});

const machoSummarySchema = z.strictObject({
  magic: enumName,
  cpu_type: enumName,
  cpu_subtype: z.number().int().min(0),
  file_type: enumName,
  flags: z.array(enumName),
  load_commands: z.array(
    z.strictObject({
      index: rowIndex,
      command: enumName,
      offset: hex,
      size: hex,
    }),
  ),
  libraries: z.array(
    z.strictObject({
      name: z.string(),
      command: enumName,
      current_version: z.string(),
      compatibility_version: z.string(),
    }),
  ),
  code_signature: z
    .strictObject({ data_offset: hex, data_size: hex })
    .nullable(),
  uuid: z
    .string()
    .regex(/^[0-9a-f]{32}$/u)
    .nullable(),
  build_version: z
    .strictObject({
      platform: enumName,
      minos: z.string(),
      sdk: z.string(),
    })
    .nullable(),
  rpaths: z.array(z.string()),
});

const count = z.number().int().min(0);

const summarySchema = z.strictObject({
  architecture: enumName,
  bits: z.union([z.literal(32), z.literal(64)]).nullable(),
  endianness: z.enum(["little", "big"]).nullable(),
  object_type: enumName,
  entrypoint: hex.nullable(),
  imagebase: hex.nullable(),
  counts: z.strictObject({
    sections: count,
    segments: count.nullable(),
    imports: count,
    exports: count,
    libraries: count,
  }),
  libraries: z.array(z.string()),
  elf: elfSummarySchema.nullable(),
  pe: peSummarySchema.nullable(),
  macho: machoSummarySchema.nullable(),
});

const machoContainerSchema = z.strictObject({
  universal: z.boolean(),
  slice_count: z.number().int().min(1),
  selected_index: rowIndex,
  slices: z.array(
    z.strictObject({
      index: rowIndex,
      cpu_type: enumName,
      cpu_subtype: z.number().int().min(0),
      fat_offset: hex,
      size: hex,
    }),
  ),
});

const formatSchema = z.enum(["elf", "pe", "macho"]);

const resourceLimitsSchema = z.strictObject({
  address_space_bytes: z.number().int().min(0).nullable(),
  file_size_bytes: z.number().int().min(0).nullable(),
  core_file_bytes: z.number().int().min(0).nullable(),
});

/** The helper's successful reply, before REA binds artifact identity and pages. */
export const liefReplyValueSchema = z.strictObject({
  lief_version: z.string().min(1),
  python_version: z.string().min(1),
  format: formatSchema,
  macho: machoContainerSchema.nullable(),
  summary: summarySchema.nullable(),
  page: z
    .strictObject({
      applicable: z.boolean(),
      total: count,
      items: z.array(z.unknown()),
    })
    .nullable(),
  resource_limits: resourceLimitsSchema,
});
export type LiefReplyValue = z.output<typeof liefReplyValueSchema>;

const pageOf = <Row extends z.ZodType>(row: Row) =>
  z.strictObject({
    offset: count,
    limit: z.number().int().min(1).nullable(),
    total: count,
    returned: count,
    next_offset: count.nullable(),
    items: z.array(row),
  });

/** Row schemas owned by each list facet; providers validate items against these. */
export const LIEF_ROW_SCHEMAS = {
  sections: sectionRowSchema,
  segments: segmentRowSchema,
  imports: symbolRowSchema,
  exports: symbolRowSchema,
} as const;

const digest = z.string().regex(/^[0-9a-f]{64}$/u);

/** Complete public result for one facet of one selected file. */
export const liefInspectionSchema = z
  .strictObject({
    artifact: z.strictObject({
      path: z.string().min(1),
      sha256: digest,
      bytes: count,
    }),
    artifact_after: z.strictObject({
      sha256: digest.nullable(),
      changed: z.boolean().nullable(),
    }),
    provider: z.strictObject({
      lief_version: z.string().min(1),
      admitted_release: z.string().min(1),
      python_executable: z.string().min(1),
      python_version: z.string().min(1),
    }),
    operation: z.enum(LIEF_OPERATIONS),
    format: formatSchema,
    macho: machoContainerSchema.nullable(),
    summary: summarySchema.nullable(),
    sections: pageOf(sectionRowSchema).nullable(),
    segments: pageOf(segmentRowSchema).nullable(),
    imports: pageOf(symbolRowSchema).nullable(),
    exports: pageOf(symbolRowSchema).nullable(),
    coverage: z.strictObject({
      model: z.literal("lief-parsed"),
      applicable: z.boolean(),
      parser_diagnostics: z.enum(["none", "reported"]),
    }),
    resource_limits: resourceLimitsSchema,
    diagnostics: z.strictObject({
      stdout: z.string(),
      stderr: z.string(),
      truncated: z.boolean(),
    }),
    limitations: z.array(z.string()),
  })
  .superRefine((value, context) => {
    for (const facet of LIEF_OPERATIONS) {
      const present = value[facet] !== null;
      if (present !== (facet === value.operation))
        context.addIssue({
          code: "custom",
          path: [facet],
          message: `${facet} must be present exactly when it is the selected operation`,
        });
    }
    if ((value.macho !== null) !== (value.format === "macho"))
      context.addIssue({
        code: "custom",
        path: ["macho"],
        message: "Mach-O container facts are present exactly for Mach-O input",
      });
  });
export type LiefInspection = z.output<typeof liefInspectionSchema>;
