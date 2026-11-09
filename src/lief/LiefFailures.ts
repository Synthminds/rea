import { z } from "zod";

import { artifactFileCancellationCause } from "../artifacts/ArtifactFileOperation.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import {
  AnalysisError,
  type AnalysisCapturedOutput,
} from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import {
  DEFAULT_LIEF_COMMAND_TIMEOUT_MS,
  MAX_LIEF_MAX_FILE_BYTES,
  type InspectWithLiefInput,
} from "../domain/lief/liefInspection.js";
import { MAX_REVERSE_COMMAND_TIMEOUT_MS } from "../domain/reverseEngineering.js";
import type { ArtifactAnalysisResources } from "../process/ArtifactAnalysisResources.js";
import { OwnedCommandFailure } from "../process/OwnedCommand.js";
import type { ProviderProcessSnapshot } from "../process/ProviderProcess.js";
import { privateWorkspaceFailure } from "../process/privateWorkspaceFailure.js";
import { LIEF_CONFIGURATION_KEY } from "./LiefReply.js";
import {
  LIEF_CONFIGURATION_GUIDANCE,
  LIEF_LIMITS,
  LIEF_PROVIDER_IDENTITY,
} from "./LiefRelease.js";

const OPERATION = "inspect_with_lief";

/** The owning stage when a failure was observed. */
export type LiefPhase =
  | "configuration"
  | "artifact"
  | "workspace"
  | "producer"
  | "integrity";

/** Configuration REA refused before acquiring the selected file. */
export class LiefConfigurationError extends Error {}

/** Everything one classification needs; owned by a single inspection. */
export interface LiefFailureContext {
  readonly phase: LiefPhase;
  readonly input: InspectWithLiefInput;
  readonly python: string;
  readonly timeoutMs: number;
  readonly workspacePath: string | null;
  readonly observedOutput: AnalysisCapturedOutput | undefined;
  readonly resources: ArtifactAnalysisResources;
  readonly signal: AbortSignal | undefined;
}

/** Bounded diagnostics of one owned helper run. */
export const outputOf = (
  snapshot: ProviderProcessSnapshot | null,
): AnalysisCapturedOutput | undefined =>
  snapshot === null
    ? undefined
    : {
        stdout: snapshot.stdout.text,
        stderr: snapshot.stderr.text,
        truncated: snapshot.diagnosticTruncated ?? false,
        exit_code: snapshot.exitCode ?? null,
        signal: snapshot.signal ?? null,
      };

const commandFailure = (
  cause: OwnedCommandFailure,
  context: LiefFailureContext,
): AnalysisError => {
  const capturedOutput = outputOf(cause.snapshot);
  const signal = cause.snapshot?.signal ?? null;
  if (cause.reason === "timeout")
    return new AnalysisTimeoutError(OPERATION, context.timeoutMs, {
      cause,
      ...(capturedOutput === undefined ? {} : { capturedOutput }),
      userMessage: `The LIEF helper reached its ${String(context.timeoutMs)} ms command_timeout_ms deadline before replying. This is REA's provider deadline, not an MCP client deadline.`,
      remediationAction:
        context.timeoutMs < MAX_REVERSE_COMMAND_TIMEOUT_MS
          ? `Increase command_timeout_ms above ${String(context.timeoutMs)} (integer milliseconds up to ${String(MAX_REVERSE_COMMAND_TIMEOUT_MS)}; omitted means ${String(DEFAULT_LIEF_COMMAND_TIMEOUT_MS)}), or use --command-timeout-ms on the CLI. It applies on the next call; no restart is required. Allow matching headroom in the MCP client deadline.`
          : `command_timeout_ms is already at its maximum of ${String(MAX_REVERSE_COMMAND_TIMEOUT_MS)} ms. Select a smaller artifact or slice.`,
    });
  // CPU and file-size signals keep the shared resource classification.
  if (
    cause.reason === "process" &&
    signal !== null &&
    signal !== "SIGXFSZ" &&
    signal !== "SIGXCPU"
  )
    return new AnalysisOutputError(
      OPERATION,
      `The LIEF helper terminated with ${signal} before replying; LIEF did not finish reading this input.`,
      {
        cause,
        ...(capturedOutput === undefined ? {} : { capturedOutput }),
        userMessage: `The LIEF helper terminated with ${signal} while reading ${context.input.path}. No partial structure is reported.`,
      },
    );
  return context.resources.commandFailure(
    cause,
    {
      command_timeout_ms: context.timeoutMs,
      output_bytes: LIEF_LIMITS.diagnosticBytes,
    },
    undefined,
  );
};

const configurationFailure = (
  cause: unknown,
  context: LiefFailureContext,
): AnalysisError => {
  const reason = cause instanceof Error ? cause.message : String(cause);
  const code =
    cause instanceof Error && "code" in cause ? String(cause.code) : null;
  return new AnalysisCapabilityUnavailableError(
    LIEF_PROVIDER_IDENTITY.id,
    OPERATION,
    reason,
    {
      cause,
      diagnostics: {
        configuration_key: LIEF_CONFIGURATION_KEY,
        executable_path: context.python,
        system_code: code,
      },
      userMessage:
        cause instanceof LiefConfigurationError
          ? reason
          : `${LIEF_CONFIGURATION_KEY} cannot be executed (${code ?? "unknown error"}): ${context.python}`,
      remediationAction: LIEF_CONFIGURATION_GUIDANCE,
    },
  );
};

const artifactFailure = (
  cause: unknown,
  { input }: LiefFailureContext,
): AnalysisError => {
  const reason = cause instanceof Error ? cause.message : String(cause);
  if (cause instanceof ArtifactReaderFailure && cause.reason === "limit")
    return new AnalysisResourceConstraintError(
      OPERATION,
      "file-size",
      reason,
      { max_file_bytes: input.max_file_bytes },
      {
        cause,
        retryable: false,
        remediationAction:
          input.max_file_bytes >= MAX_LIEF_MAX_FILE_BYTES
            ? `The file exceeds the ${String(MAX_LIEF_MAX_FILE_BYTES)}-byte ceiling this operation accepts. This release has no runtime override. Select a smaller artifact.`
            : `Raise max_file_bytes above ${String(input.max_file_bytes)} bytes (maximum ${String(MAX_LIEF_MAX_FILE_BYTES)}) or select a smaller artifact; the limit is the caller-selected input read budget.`,
      },
    );
  if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
    return new AnalysisArtifactChangedError(OPERATION, input.path, reason, {
      cause,
    });
  const code =
    cause instanceof Error && "code" in cause ? String(cause.code) : null;
  if (code === "EACCES" || code === "EPERM")
    return new AnalysisAccessDeniedError(OPERATION, input.path, code, {
      cause,
    });
  return new AnalysisInputError(OPERATION, { cause }, [
    {
      path: ["path"],
      reason: "invalid_value",
      message: `${reason}${code === null ? "" : ` (host error ${code})`}`,
    },
  ]);
};

/** Caller cancellation observed at a descriptor read or a private-copy write. */
const cancellationFailure = (
  cause: unknown,
  { signal, observedOutput }: LiefFailureContext,
): AnalysisError | undefined => {
  const output =
    observedOutput === undefined ? {} : { capturedOutput: observedOutput };
  if (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled")
    return new AnalysisCancelledError(OPERATION, {
      cause: artifactFileCancellationCause(cause),
      ...output,
    });
  // Node rejects an aborted private-copy write with its own envelope; the
  // caller's reason, not the workspace, explains it.
  if (
    signal?.aborted === true &&
    cause instanceof Error &&
    "code" in cause &&
    cause.code === "ABORT_ERR"
  )
    return new AnalysisCancelledError(OPERATION, {
      cause: signal.reason,
      ...output,
    });
  return undefined;
};

/** Classify one failure at its owning stage without discarding cleanup ownership. */
export const liefFailure = (
  cause: unknown,
  context: LiefFailureContext,
): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  const output =
    context.observedOutput === undefined
      ? {}
      : { capturedOutput: context.observedOutput };
  if (cause instanceof ArtifactReaderFailure && cause.cleanup !== undefined)
    return context.resources.cleanupFailure(
      cause,
      (primary) => liefFailure(primary, context),
      context.observedOutput,
    );
  const cancelled = cancellationFailure(cause, context);
  if (cancelled !== undefined) return cancelled;
  if (cause instanceof OwnedCommandFailure)
    return commandFailure(cause, context);
  if (context.phase === "configuration")
    return configurationFailure(cause, context);
  if (context.phase === "workspace")
    return privateWorkspaceFailure(
      LIEF_PROVIDER_IDENTITY.id,
      OPERATION,
      cause,
      context.workspacePath,
    );
  if (context.phase === "artifact") return artifactFailure(cause, context);
  const reason =
    cause instanceof z.ZodError
      ? `${cause.issues[0]?.message ?? "schema mismatch"} at ${cause.issues[0]?.path.map(String).join(".") ?? "root"}`
      : cause instanceof Error
        ? cause.message
        : String(cause);
  if (context.phase === "integrity")
    return new AnalysisOutputError(
      OPERATION,
      `Post-run verification of REA's private copy failed, so the helper's observations are not reported: ${reason}`,
      { cause, ...output },
    );
  return new AnalysisOutputError(
    OPERATION,
    `The LIEF helper reply could not be read: ${reason}`,
    { cause, ...output },
  );
};
