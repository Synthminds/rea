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
  "libraries",
  "rpaths",
  "load_commands",
] as const;
export type LiefOperation = (typeof LIEF_OPERATIONS)[number];
export type LiefListOperation = Exclude<LiefOperation, "summary">;

/** Omitted helper deadline; shares objdump/rizin `command_timeout_ms` semantics. */
export const DEFAULT_LIEF_COMMAND_TIMEOUT_MS =
  DEFAULT_REVERSE_COMMAND_TIMEOUT_MS;
/**
 * Rows in one list page when `limit` is omitted, and the rows each summary list
 * keeps before its truncation marker. Matches the analysis-view page default.
 */
export const DEFAULT_LIEF_PAGE_ROWS = 64;
/** Default stable-read budget for the selected artifact (256 MiB). */
export const DEFAULT_LIEF_MAX_FILE_BYTES = 268_435_456;
/**
 * REA streams the artifact into one private copy without holding it in memory;
 * LIEF then loads that copy under a 4 GiB address-space reservation.
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
        "summary (default): header, entry point, table counts and the first 64 libraries, plus ELF interpreter/soname/rpath/runpath, PE data directories/rich header/signature presence or Mach-O load commands/code-signature location/slices. sections, segments, imports, exports, libraries, rpaths, load_commands: one page of that table",
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
        `Maximum rows for a list operation (default ${String(DEFAULT_LIEF_PAGE_ROWS)}); continue from next_offset`,
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
    diagnostics: z
      .enum(["summary", "complete"])
      .default("summary")
      .describe(
        "summary (default): LIEF/Python stderr as counts, a SHA-256 and distinct lines up to 4 KiB. complete: also the full captured text",
      ),
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
          message: `${field} applies only to list operations, not summary`,
        });
  });
export type InspectWithLiefInput = z.output<typeof inspectWithLiefInputSchema>;

const hex = z.string().regex(/^0x[0-9a-f]+$/u);
const enumName = z.string().min(1);
/**
 * A string read from the file. Valid UTF-8 is a JSON string; other bytes keep
 * their exact value as hex with no text rendering.
 */
export const liefTextSchema = z.union([
  z.string(),
  z.strictObject({
    text: z.null(),
    bytes_hex: z.string().regex(/^(?:[0-9a-f]{2})+$/u),
  }),
]);
const fileText = liefTextSchema;
const rowIndex = z.number().int().min(0);
const protection = z.array(z.enum(["read", "write", "execute"]));

const sectionRowSchema = z.strictObject({
  index: rowIndex,
  name: fileText,
  type: enumName.nullable(),
  flags: z.array(enumName),
  virtual_address: hex,
  virtual_size: hex,
  file_offset: hex,
  file_size: hex,
  segment: fileText.nullable(),
});

const segmentRowSchema = z.strictObject({
  index: rowIndex,
  name: fileText.nullable(),
  type: enumName.nullable(),
  flags: protection,
  max_protection: protection.nullable(),
  virtual_address: hex,
  virtual_size: hex,
  file_offset: hex,
  file_size: hex,
  sections: z.array(fileText),
});

const symbolRowSchema = z.strictObject({
  name: fileText.nullable(),
  library: fileText.nullable(),
  ordinal: z.number().int().min(0).nullable(),
  address: hex.nullable(),
  kind: enumName,
  binding: enumName.nullable(),
  version: fileText.nullable(),
  forwarder: fileText.nullable(),
});

const libraryRowSchema = z.strictObject({
  name: fileText,
  kind: enumName,
  current_version: z.string().nullable(),
  compatibility_version: z.string().nullable(),
});

const rpathRowSchema = z.strictObject({
  path: fileText,
  kind: enumName,
});

const loadCommandRowSchema = z.strictObject({
  index: rowIndex,
  command: enumName,
  offset: hex,
  size: hex,
});

const elfSummarySchema = z.strictObject({
  file_type: enumName,
  machine: enumName,
  class: enumName,
  data: enumName,
  os_abi: enumName,
  header_entrypoint: hex,
  interpreter: fileText.nullable(),
  soname: fileText.nullable(),
  rpath: z.array(fileText).nullable(),
  runpath: z.array(fileText).nullable(),
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
      section: fileText.nullable(),
    }),
  ),
  rich_header: z
    .strictObject({
      key: hex,
      entry_count: z.number().int().min(0),
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
  export_name: fileText.nullable(),
});

const machoSummarySchema = z.strictObject({
  magic: enumName,
  cpu_type: enumName,
  cpu_subtype: z.number().int().min(0),
  file_type: enumName,
  flags: z.array(enumName),
  load_commands: z.array(loadCommandRowSchema),
  id_dylib: z
    .strictObject({
      name: fileText,
      current_version: z.string(),
      compatibility_version: z.string(),
    })
    .nullable(),
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
  rpaths: z.array(fileText).nullable(),
});

const count = z.number().int().min(0);

const summarySchema = z.strictObject({
  architecture: enumName,
  bits: z.union([z.literal(32), z.literal(64)]).nullable(),
  endianness: z.enum(["little", "big"]).nullable(),
  object_type: enumName,
  entrypoint: hex.nullable(),
  imagebase: hex.nullable(),
  /** null: not applicable to this format, or listed in unread_fields. */
  counts: z.strictObject({
    sections: count.nullable(),
    segments: count.nullable(),
    imports: count.nullable(),
    exports: count.nullable(),
    libraries: count.nullable(),
    rpaths: count.nullable(),
    load_commands: count.nullable(),
  }),
  libraries: z.array(fileText).nullable(),
  elf: elfSummarySchema.nullable(),
  pe: peSummarySchema.nullable(),
  macho: machoSummarySchema.nullable(),
  /** Summary lists cut at DEFAULT_LIEF_PAGE_ROWS; `operation` pages the rest. */
  truncated_lists: z.array(
    z.strictObject({
      field: z.string().min(1),
      total: count,
      returned: count,
      operation: z.enum(LIEF_OPERATIONS).nullable(),
    }),
  ),
  /** Fields LIEF could not read; their value is null, which here means unknown. */
  unread_fields: z.array(
    z.strictObject({ field: z.string().min(1), error: z.string() }),
  ),
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

const digest = z.string().regex(/^[0-9a-f]{64}$/u);

/** A file REA or the helper identified by resolved path and content digest. */
const fileIdentitySchema = z.strictObject({
  path: z.string().min(1),
  sha256: digest,
});

export const liefResourceLimitsSchema = z.strictObject({
  address_space_bytes: z.number().int().min(0).nullable(),
  file_size_bytes: z.number().int().min(0).nullable(),
  core_file_bytes: z.number().int().min(0).nullable(),
});

/** The helper's successful reply, before REA binds artifact identity and pages. */
export const liefReplyValueSchema = z.strictObject({
  lief_version: z.string().min(1),
  python_version: z.string().min(1),
  native_module: fileIdentitySchema,
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
  resource_limits: liefResourceLimitsSchema,
});
export type LiefReplyValue = z.output<typeof liefReplyValueSchema>;

const pageOf = <Row extends z.ZodType>(row: Row) =>
  z.strictObject({
    offset: count,
    limit: z.number().int().min(1),
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
  libraries: libraryRowSchema,
  rpaths: rpathRowSchema,
  load_commands: loadCommandRowSchema,
} as const;

/** One captured stream of the helper: counts, digest and distinct lines. */
const diagnosticStreamSchema = z.strictObject({
  bytes: count,
  lines: count,
  distinct_lines: count,
  sha256: digest,
  /** Distinct lines in first-seen order with repeat counts, up to 4 KiB of text. */
  excerpt: z.array(
    z.strictObject({
      line: z.string(),
      count: z.number().int().min(1),
      truncated: z.boolean(),
    }),
  ),
  excerpt_complete: z.boolean(),
  /** The complete captured text, only with diagnostics: "complete". */
  text: z.string().nullable(),
});

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
      /** The resolved interpreter file REA launched, digested before and after. */
      python: fileIdentitySchema,
      python_version: z.string().min(1),
      /** The native LIEF module the helper loaded, re-digested after the run. */
      native_module: fileIdentitySchema,
    }),
    operation: z.enum(LIEF_OPERATIONS),
    format: formatSchema,
    macho: machoContainerSchema.nullable(),
    summary: summarySchema.nullable(),
    sections: pageOf(sectionRowSchema).nullable(),
    segments: pageOf(segmentRowSchema).nullable(),
    imports: pageOf(symbolRowSchema).nullable(),
    exports: pageOf(symbolRowSchema).nullable(),
    libraries: pageOf(libraryRowSchema).nullable(),
    rpaths: pageOf(rpathRowSchema).nullable(),
    load_commands: pageOf(loadCommandRowSchema).nullable(),
    coverage: z.strictObject({
      model: z.literal("lief-parsed"),
      applicable: z.boolean(),
      parser_diagnostics: z.enum(["none", "reported"]),
    }),
    resource_limits: liefResourceLimitsSchema,
    diagnostics: z.strictObject({
      detail: z.enum(["summary", "complete"]),
      stderr: diagnosticStreamSchema,
      stdout: diagnosticStreamSchema,
      /** The supervisor stopped retaining output at its byte budget. */
      capture_truncated: z.boolean(),
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
