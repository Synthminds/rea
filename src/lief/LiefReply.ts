import { createHash } from "node:crypto";

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
  DEFAULT_LIEF_PAGE_ROWS,
  LIEF_ROW_SCHEMAS,
  liefInspectionSchema,
  liefReplyValueSchema,
  liefResourceLimitsSchema,
  type InspectWithLiefInput,
  type LiefInspection,
  type LiefListOperation,
  type LiefReplyValue,
} from "../domain/lief/liefInspection.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { boundedUtf8Text } from "../process/boundedUtf8Text.js";
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
  /** The helper's excerpt; `message_bytes` is the full message size. */
  message: z.string(),
  message_bytes: z.number().int().min(0),
  /** Effective soft limits, or null when the helper had not applied them yet. */
  resource_limits: liefResourceLimitsSchema.nullable(),
  observed_version: z.string().nullable().optional(),
  slice_count: z.number().int().min(1).optional(),
  reply_bytes: z.number().int().min(0).optional(),
});

/** The helper's complete reply protocol; any other shape is malformed output. */
export const liefReplySchema = z.discriminatedUnion("ok", [
  z.strictObject({ ok: z.literal(true), value: liefReplyValueSchema }),
  refusalSchema,
]);
type LiefRefusal = z.output<typeof refusalSchema>;

/** One output stream retained by the owned helper process. */
export interface LiefOutputStream {
  readonly text: string;
  readonly bytes: number;
}

/** Complete retained output of one helper run. */
export interface LiefOutput {
  readonly stdout: LiefOutputStream;
  readonly stderr: LiefOutputStream;
  readonly truncated: boolean;
  readonly exitCode: number | null;
  readonly signal: string | null;
}

/** File identities REA observed for the interpreter it launched. */
export interface LiefInterpreter {
  readonly configured: string;
  readonly path: string;
  readonly sha256: string;
}

/** Facts REA observed itself, independent of the helper's reply. */
export interface LiefObservedRun {
  readonly input: InspectWithLiefInput;
  readonly python: LiefInterpreter;
  readonly before: { readonly sha256: string; readonly bytes: number };
  /** `changed` is set only when the digest is unavailable but a change is proven. */
  readonly after: {
    readonly sha256: string | null;
    readonly changed: true | null | undefined;
  };
  readonly output: LiefOutput;
}

/** Rows of one list page when the caller omits `limit`. */
export const liefPageLimit = (input: InspectWithLiefInput): number =>
  input.limit ?? DEFAULT_LIEF_PAGE_ROWS;

const tail = (text: string, maximumBytes: number): string => {
  const bytes = Buffer.from(text, "utf8");
  if (bytes.length <= maximumBytes) return text;
  let start = bytes.length - maximumBytes;
  // Begin on a code-point boundary.
  while (start < bytes.length && ((bytes[start] ?? 0) & 0xc0) === 0x80) start++;
  return bytes.subarray(start).toString("utf8");
};

/** Head and tail of one stream within the failure budget; the size stays exact. */
const failureText = (
  stream: LiefOutputStream,
): { readonly text: string; readonly truncated: boolean } => {
  const budget = LIEF_LIMITS.failureOutputBytes;
  const head = boundedUtf8Text(stream.text, budget);
  if (!head.truncated) return head;
  const end = tail(stream.text, budget);
  const omitted =
    Buffer.byteLength(stream.text, "utf8") -
    Buffer.byteLength(head.text, "utf8") -
    Buffer.byteLength(end, "utf8");
  return {
    text: `${head.text}\n[REA omitted ${String(omitted)} bytes of this stream]\n${end}`,
    truncated: true,
  };
};

/**
 * Bounded output for a typed failure: each stream's head and tail with its full
 * byte count. A Python traceback ends a stream, so its tail is kept.
 */
export const liefFailureOutput = (
  output: LiefOutput | undefined,
): AnalysisCapturedOutput | undefined => {
  if (output === undefined) return undefined;
  const stdout = failureText(output.stdout);
  const stderr = failureText(output.stderr);
  return {
    stdout: stdout.text,
    stderr: stderr.text,
    stdout_bytes: output.stdout.bytes,
    stderr_bytes: output.stderr.bytes,
    truncated: output.truncated || stdout.truncated || stderr.truncated,
    exit_code: output.exitCode,
    signal: output.signal,
  };
};

/** Counts, digest and distinct lines of one stream; text only when requested. */
const diagnosticStream = (stream: LiefOutputStream, complete: boolean) => {
  const lines =
    stream.text === "" ? [] : stream.text.replace(/\n$/u, "").split("\n");
  const counts = new Map<string, number>();
  for (const line of lines) counts.set(line, (counts.get(line) ?? 0) + 1);
  const excerpt: { line: string; count: number; truncated: boolean }[] = [];
  let used = 0;
  let excerptComplete = true;
  for (const [line, count] of counts) {
    const room = Math.min(
      LIEF_LIMITS.diagnosticExcerptBytes - used,
      LIEF_LIMITS.diagnosticLineBytes,
    );
    if (room <= 0) {
      excerptComplete = false;
      break;
    }
    const kept = boundedUtf8Text(line, room);
    excerpt.push({ line: kept.text, count, truncated: kept.truncated });
    used += Buffer.byteLength(kept.text, "utf8");
    if (kept.truncated) excerptComplete = false;
  }
  return {
    bytes: stream.bytes,
    lines: lines.length,
    distinct_lines: counts.size,
    sha256: createHash("sha256").update(stream.text, "utf8").digest("hex"),
    excerpt,
    excerpt_complete: excerptComplete,
    text: complete ? stream.text : null,
  };
};

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
      { capturedOutput: liefFailureOutput(run.output) },
    );
  const offset = run.input.offset ?? 0;
  const limit = liefPageLimit(run.input);
  const items = z.array(LIEF_ROW_SCHEMAS[operation]).parse(reply.items);
  const end = offset + items.length;
  if (
    items.length > limit ||
    end > Math.max(reply.total, offset) ||
    (end < reply.total && items.length < limit) ||
    (!reply.applicable && (reply.total !== 0 || items.length !== 0))
  )
    throw new AnalysisOutputError(
      OPERATION,
      "The LIEF helper returned a page inconsistent with the requested window.",
      { capturedOutput: liefFailureOutput(run.output) },
    );
  return {
    applicable: reply.applicable,
    facet: {
      offset,
      limit,
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
    libraries: null,
    rpaths: null,
    load_commands: null,
  };
  let applicable = true;
  if (operation === "summary") {
    if (value.summary === null)
      throw new AnalysisOutputError(
        OPERATION,
        "The LIEF helper returned no summary.",
        { capturedOutput: liefFailureOutput(run.output) },
      );
  } else {
    const selected = page(run, operation, value);
    applicable = selected.applicable;
    facets[operation] = selected.facet;
  }
  const complete = run.input.diagnostics === "complete";
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
      python_executable: run.python.configured,
      python: { path: run.python.path, sha256: run.python.sha256 },
      python_version: value.python_version,
      native_module: value.native_module,
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
        run.output.stderr.text.trim() === "" ? "none" : "reported",
    },
    resource_limits: value.resource_limits,
    diagnostics: {
      detail: run.input.diagnostics,
      stderr: diagnosticStream(run.output.stderr, complete),
      stdout: diagnosticStream(run.output.stdout, complete),
      capture_truncated: run.output.truncated,
    },
    limitations: [],
  });
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new AnalysisOutputError(
      OPERATION,
      `The LIEF helper reply does not match the inspect_with_lief contract: ${issue?.message ?? "schema mismatch"} at ${issue?.path.map(String).join(".") ?? "root"}`,
      { capturedOutput: liefFailureOutput(run.output) },
    );
  }
  return { ...parsed.data, limitations: liefLimitations(parsed.data) };
};

/** A bounded excerpt of the helper's message, naming its full size when cut. */
const refusalMessage = (reply: LiefRefusal): string => {
  const excerpt = boundedUtf8Text(reply.message, LIEF_LIMITS.messageBytes);
  return excerpt.truncated ||
    Buffer.byteLength(reply.message, "utf8") < reply.message_bytes
    ? `${excerpt.text} [excerpt of a ${String(reply.message_bytes)}-byte message]`
    : excerpt.text;
};

const configurationRefusal = (
  reply: LiefRefusal,
  message: string,
  python: string,
  capturedOutput: AnalysisCapturedOutput | undefined,
): AnalysisError =>
  new AnalysisCapabilityUnavailableError(
    LIEF_PROVIDER_IDENTITY.id,
    OPERATION,
    message,
    {
      capturedOutput,
      diagnostics: {
        configuration_key: LIEF_CONFIGURATION_KEY,
        executable_path: python,
        admitted_release: LIEF_ADMITTED_RELEASE,
        observed_version: reply.observed_version ?? null,
      },
      userMessage: message,
      remediationAction: `${LIEF_CONFIGURATION_GUIDANCE} Correct the configured interpreter or its LIEF package, not the selected file. Do not repeat the unchanged call.`,
    },
  );

const resourceRefusal = (
  reply: LiefRefusal,
  message: string,
  input: InspectWithLiefInput,
  capturedOutput: AnalysisCapturedOutput | undefined,
): AnalysisError => {
  const observed = reply.resource_limits;
  if (reply.reason === "resource-limit") {
    const effective = observed?.address_space_bytes ?? null;
    return new AnalysisResourceConstraintError(
      OPERATION,
      "memory",
      message,
      {
        address_space_bytes: effective,
        requested_address_space_bytes: LIEF_LIMITS.addressSpaceBytes,
        file_size_bytes: observed?.file_size_bytes ?? null,
      },
      {
        capturedOutput,
        retryable: false,
        remediationAction: `${effective === null ? `The helper could not apply its ${String(LIEF_LIMITS.addressSpaceBytes)}-byte address-space limit, so the effective limit is unknown.` : `The helper ran under an effective ${String(effective)}-byte address-space soft limit (REA requests at most ${String(LIEF_LIMITS.addressSpaceBytes)} and keeps tighter inherited limits).`} This release has no runtime override. Select a smaller artifact or slice; max_file_bytes and command_timeout_ms do not raise this limit.`,
      },
    );
  }
  const listRemedy =
    input.operation === "summary"
      ? `The summary keeps at most ${String(DEFAULT_LIEF_PAGE_ROWS)} rows per list; page the complete lists with the libraries, rpaths or load_commands operation and a smaller limit.`
      : "Request a smaller page with limit and continue from next_offset.";
  return new AnalysisResourceConstraintError(
    OPERATION,
    "memory",
    message,
    {
      reply_bytes: LIEF_LIMITS.replyBytes,
      ...(reply.reply_bytes === undefined
        ? {}
        : { required_bytes: reply.reply_bytes }),
      file_size_bytes: observed?.file_size_bytes ?? null,
    },
    {
      capturedOutput,
      retryable: false,
      remediationAction: `The ${String(LIEF_LIMITS.replyBytes)}-byte LIEF reply allowance has no runtime override. ${listRemedy}`,
    },
  );
};

/** Project one typed helper refusal; no refusal carries partial structure. */
export const liefRefusal = (
  reply: LiefRefusal,
  input: InspectWithLiefInput,
  python: string,
  output: LiefOutput,
): AnalysisError => {
  const message = refusalMessage(reply);
  const capturedOutput = liefFailureOutput(output);
  switch (reply.reason) {
    case "version":
    case "unavailable":
      return configurationRefusal(reply, message, python, capturedOutput);
    case "unsupported-format":
      return new AnalysisUnsupportedTargetError(
        OPERATION,
        input.path,
        message,
        {
          capturedOutput,
          remediationAction:
            "Select an ELF, PE or Mach-O file. inspect_byte_entropy or the artifact inventory tools can help identify other formats.",
        },
      );
    case "malformed":
      return new AnalysisInputError(OPERATION, { capturedOutput }, [
        { path: ["path"], reason: "invalid_format", message },
      ]);
    case "invalid-slice":
      return new AnalysisInputError(OPERATION, { capturedOutput }, [
        {
          path: ["macho_slice"],
          reason: "out_of_range",
          message,
          minimum: 0,
          ...(reply.slice_count === undefined
            ? {}
            : { maximum: reply.slice_count - 1 }),
        },
      ]);
    case "not-applicable":
      return new AnalysisInputError(OPERATION, { capturedOutput }, [
        { path: ["macho_slice"], reason: "invalid_value", message },
      ]);
    case "resource-limit":
    case "output-limit":
      return resourceRefusal(reply, message, input, capturedOutput);
    case "decoder":
      return new ProviderAdapterError(LIEF_PROVIDER_IDENTITY.id, OPERATION, {
        capturedOutput,
        diagnostics: {
          stage: "lief-parse",
          reason: message,
          message_bytes: reply.message_bytes,
          resource_limits:
            reply.resource_limits === null
              ? null
              : { ...reply.resource_limits },
        },
        userMessage: `LIEF failed while reading ${input.path}: ${message}`,
      });
  }
};
