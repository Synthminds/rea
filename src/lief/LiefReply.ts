import { z } from "zod";

import type {
  AnalysisCapturedOutput,
  AnalysisError,
} from "../domain/analysisErrorBase.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import {
  LIEF_ROW_SCHEMAS,
  liefInspectionSchema,
  liefReplyValueSchema,
  type InspectWithLiefInput,
  type LiefInspection,
  type LiefListOperation,
  type LiefReplyValue,
} from "../domain/lief/liefInspection.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { liefLimitations } from "./LiefLimitations.js";
import {
  LIEF_ADMITTED_RELEASE,
  LIEF_CONFIGURATION_GUIDANCE,
  LIEF_LIMITS,
  LIEF_PROVIDER_IDENTITY,
} from "./LiefRelease.js";

const OPERATION = "inspect_with_lief";
export const LIEF_CONFIGURATION_KEY = "REA_LIEF_PYTHON";

const refusalSchema = z.strictObject({
  ok: z.literal(false),
  reason: z.enum([
    "version",
    "unavailable",
    "unsupported-format",
    "malformed",
    "invalid-slice",
    "not-applicable",
    "resource-limit",
    "output-limit",
    "decoder",
  ]),
  message: z.string(),
  observed_version: z.string().nullable().optional(),
  slice_count: z.number().int().min(1).optional(),
  reply_bytes: z.number().int().min(0).optional(),
  resource_limits: z.unknown().optional(),
});

/** The helper's complete reply protocol; any other shape is malformed output. */
export const liefReplySchema = z.discriminatedUnion("ok", [
  z.strictObject({ ok: z.literal(true), value: liefReplyValueSchema }),
  refusalSchema,
]);
type LiefRefusal = z.output<typeof refusalSchema>;

/** Facts REA observed itself, independent of the helper's reply. */
export interface LiefObservedRun {
  readonly input: InspectWithLiefInput;
  readonly python: string;
  readonly before: { readonly sha256: string; readonly bytes: number };
  /** `changed` is set only when the digest is unavailable but a change is proven. */
  readonly after: {
    readonly sha256: string | null;
    readonly changed: true | null | undefined;
  };
  readonly diagnostics: AnalysisCapturedOutput;
}

const page = (
  run: LiefObservedRun,
  operation: LiefListOperation,
  value: LiefReplyValue,
) => {
  const reply = value.page;
  if (reply === null)
    throw new AnalysisOutputError(
      OPERATION,
      `The LIEF helper returned no ${operation} page.`,
      { capturedOutput: run.diagnostics },
    );
  const offset = run.input.offset ?? 0;
  const items = z.array(LIEF_ROW_SCHEMAS[operation]).parse(reply.items);
  const end = offset + items.length;
  if (
    items.length > (run.input.limit ?? Number.MAX_SAFE_INTEGER) ||
    end > Math.max(reply.total, offset)
  )
    throw new AnalysisOutputError(
      OPERATION,
      "The LIEF helper returned a page inconsistent with the requested window.",
      { capturedOutput: run.diagnostics },
    );
  return {
    applicable: reply.applicable,
    facet: {
      offset,
      limit: run.input.limit ?? null,
      total: reply.total,
      returned: items.length,
      next_offset: end < reply.total ? end : null,
      items,
    },
  };
};

/** Bind the helper's facet to REA-observed identity, coverage and limitations. */
export const liefReport = (
  run: LiefObservedRun,
  value: LiefReplyValue,
): LiefInspection => {
  const operation = run.input.operation;
  const facets: Record<LiefListOperation, unknown> = {
    sections: null,
    segments: null,
    imports: null,
    exports: null,
  };
  let applicable = true;
  if (operation === "summary") {
    if (value.summary === null)
      throw new AnalysisOutputError(
        OPERATION,
        "The LIEF helper returned no summary.",
        { capturedOutput: run.diagnostics },
      );
  } else {
    const selected = page(run, operation, value);
    applicable = selected.applicable;
    facets[operation] = selected.facet;
  }
  const parsed = liefInspectionSchema.safeParse({
    artifact: {
      path: run.input.path,
      sha256: run.before.sha256,
      bytes: run.before.bytes,
    },
    artifact_after: {
      sha256: run.after.sha256,
      changed:
        run.after.sha256 === null
          ? (run.after.changed ?? null)
          : run.after.sha256 !== run.before.sha256,
    },
    provider: {
      lief_version: value.lief_version,
      admitted_release: LIEF_ADMITTED_RELEASE,
      python_executable: run.python,
      python_version: value.python_version,
    },
    operation,
    format: value.format,
    macho: value.macho,
    summary: operation === "summary" ? value.summary : null,
    ...facets,
    coverage: {
      model: "lief-parsed",
      applicable,
      parser_diagnostics:
        run.diagnostics.stderr.trim() === "" ? "none" : "reported",
    },
    resource_limits: value.resource_limits,
    diagnostics: {
      stdout: run.diagnostics.stdout,
      stderr: run.diagnostics.stderr,
      truncated: run.diagnostics.truncated,
    },
    limitations: [],
  });
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new AnalysisOutputError(
      OPERATION,
      `The LIEF helper reply does not match the inspect_with_lief contract: ${issue?.message ?? "schema mismatch"} at ${issue?.path.map(String).join(".") ?? "root"}`,
      { capturedOutput: run.diagnostics },
    );
  }
  return { ...parsed.data, limitations: liefLimitations(parsed.data) };
};

const configurationRefusal = (
  reply: LiefRefusal,
  python: string,
  capturedOutput: AnalysisCapturedOutput,
): AnalysisError =>
  new AnalysisCapabilityUnavailableError(
    LIEF_PROVIDER_IDENTITY.id,
    OPERATION,
    reply.message,
    {
      capturedOutput,
      diagnostics: {
        configuration_key: LIEF_CONFIGURATION_KEY,
        executable_path: python,
        admitted_release: LIEF_ADMITTED_RELEASE,
        observed_version: reply.observed_version ?? null,
      },
      userMessage: reply.message,
      remediationAction: `${LIEF_CONFIGURATION_GUIDANCE} Correct the configured interpreter or its LIEF package, not the selected file. Do not repeat the unchanged call.`,
    },
  );

const resourceRefusal = (
  reply: LiefRefusal,
  input: InspectWithLiefInput,
  capturedOutput: AnalysisCapturedOutput,
): AnalysisError =>
  reply.reason === "resource-limit"
    ? new AnalysisResourceConstraintError(
        OPERATION,
        "memory",
        reply.message,
        { address_space_bytes: LIEF_LIMITS.addressSpaceBytes },
        {
          capturedOutput,
          retryable: false,
          remediationAction: `The LIEF helper runs under at most ${String(LIEF_LIMITS.addressSpaceBytes)} bytes of address space and this release has no runtime override. Select a smaller artifact or slice; max_file_bytes and command_timeout_ms do not raise this limit.`,
        },
      )
    : new AnalysisResourceConstraintError(
        OPERATION,
        "memory",
        reply.message,
        {
          reply_bytes: LIEF_LIMITS.replyBytes,
          ...(reply.reply_bytes === undefined
            ? {}
            : { required_bytes: reply.reply_bytes }),
        },
        {
          capturedOutput,
          retryable: false,
          remediationAction:
            input.operation === "summary"
              ? `The ${String(LIEF_LIMITS.replyBytes)}-byte LIEF reply allowance has no runtime override. Request the sections, segments, imports or exports operation with limit instead.`
              : `The ${String(LIEF_LIMITS.replyBytes)}-byte LIEF reply allowance has no runtime override. Request a smaller page with limit and continue from next_offset.`,
        },
      );

/** Project one typed helper refusal; no refusal carries partial structure. */
export const liefRefusal = (
  reply: LiefRefusal,
  input: InspectWithLiefInput,
  python: string,
  capturedOutput: AnalysisCapturedOutput,
): AnalysisError => {
  switch (reply.reason) {
    case "version":
    case "unavailable":
      return configurationRefusal(reply, python, capturedOutput);
    case "unsupported-format":
      return new AnalysisUnsupportedTargetError(
        OPERATION,
        input.path,
        reply.message,
        {
          capturedOutput,
          remediationAction:
            "Select an ELF, PE or Mach-O file. inspect_byte_entropy or the artifact inventory tools can help identify other formats.",
        },
      );
    case "malformed":
      return new AnalysisInputError(OPERATION, { capturedOutput }, [
        { path: ["path"], reason: "invalid_format", message: reply.message },
      ]);
    case "invalid-slice":
      return new AnalysisInputError(OPERATION, { capturedOutput }, [
        {
          path: ["macho_slice"],
          reason: "out_of_range",
          message: reply.message,
          minimum: 0,
          ...(reply.slice_count === undefined
            ? {}
            : { maximum: reply.slice_count - 1 }),
        },
      ]);
    case "not-applicable":
      return new AnalysisInputError(OPERATION, { capturedOutput }, [
        {
          path: ["macho_slice"],
          reason: "invalid_value",
          message: reply.message,
        },
      ]);
    case "resource-limit":
    case "output-limit":
      return resourceRefusal(reply, input, capturedOutput);
    case "decoder":
      return new ProviderAdapterError(LIEF_PROVIDER_IDENTITY.id, OPERATION, {
        capturedOutput,
        diagnostics: { stage: "lief-parse", reason: reply.message },
        userMessage: `LIEF failed while reading ${input.path}: ${reply.message}`,
      });
  }
};
