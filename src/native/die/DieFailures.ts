import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import {
  artifactFileCancellationCause,
  bindArtifactFileCleanup,
} from "../../artifacts/ArtifactFileOperation.js";
import { boundedUtf8Text } from "../../process/boundedUtf8Text.js";
import type { ProviderProcessSnapshot } from "../../process/ProviderProcess.js";
import {
  AnalysisError,
  type AnalysisCapturedOutput,
} from "../../domain/analysisErrorBase.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../../domain/analysisErrorCore.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { OwnedCommandFailure } from "../../process/OwnedCommand.js";
import {
  RuntimeControlUnavailableError,
  runtimeControlCapabilityError,
} from "../../process/RuntimeControlUnavailableError.js";
import {
  MAX_FILE_SIGNATURE_COMMAND_TIMEOUT_MS,
  MAX_FILE_SIGNATURE_FILE_BYTES,
} from "../../domain/native/fileSignatures.js";
import {
  DIE_ENGINE_VERSION,
  DIE_LIMITS,
  DIE_PROVIDER_IDENTITY,
  DIE_PYTHON_PACKAGE_VERSION,
} from "./DieRelease.js";

export const DETECT_FILE_SIGNATURES = "detect_file_signatures";
const EXCERPT_BYTES = 4096;

/** Which stage failed: tool selection, the selected file, or the DiE scan. */
export type DiePhase = "configuration" | "artifact" | "scanner";

/** Configuration is captured by the server; fixing files and changing its environment are distinct repairs. */
export const dieConfigurationRecoveryAction = (): string =>
  `Set absolute REA_DIE_COMMAND to a caller-supplied diec ${DIE_ENGINE_VERSION}, or absolute REA_DIE_PYTHON to a Python executable whose environment contains die-python ${DIE_PYTHON_PACKAGE_VERSION} (REA_DIE_COMMAND wins when both are set), plus util-linux prlimit (REA_DIE_PRLIMIT_COMMAND, default /usr/bin/prlimit). Set this in the shell for the next CLI call, or in the MCP server launch environment and restart that server. REA never installs DiE. Do not repeat the unchanged call.`;

/** A refused tool requirement that another input file cannot satisfy. */
export const dieUnavailable = (
  reason: string,
  options: {
    readonly cause?: unknown;
    readonly capturedOutput?: AnalysisCapturedOutput;
    readonly diagnostics?: Readonly<Record<string, string | null>>;
  } = {},
): AnalysisCapabilityUnavailableError =>
  new AnalysisCapabilityUnavailableError(
    DIE_PROVIDER_IDENTITY.id,
    DETECT_FILE_SIGNATURES,
    reason,
    {
      ...options,
      userMessage: reason,
      remediationAction: dieConfigurationRecoveryAction(),
    },
  );

/** Complete captured output of one finished DiE command. */
export const capturedDieOutput = (
  snapshot: ProviderProcessSnapshot,
): AnalysisCapturedOutput => ({
  stdout: snapshot.stdout.text,
  stderr: snapshot.stderr.text,
  stdout_bytes: snapshot.stdout.bytes,
  stderr_bytes: snapshot.stderr.bytes,
  exit_code: snapshot.exitCode ?? null,
  signal: snapshot.signal ?? null,
  truncated: snapshot.diagnosticTruncated === true,
});

/** Past the output budget, retained text is a prefix of an oversized stream. */
const excerpt = (
  snapshot: ProviderProcessSnapshot,
): AnalysisCapturedOutput => ({
  ...capturedDieOutput(snapshot),
  stdout: boundedUtf8Text(snapshot.stdout.text, EXCERPT_BYTES).text,
  stderr: boundedUtf8Text(snapshot.stderr.text, EXCERPT_BYTES).text,
  truncated: true,
});

/** A limiter signal names its ceiling; other signals do not establish a cause. */
const limiterSignal = (
  signal: string | null | undefined,
  timeoutMs: number,
  capturedOutput: AnalysisCapturedOutput | undefined,
): AnalysisError | undefined => {
  const ceiling =
    signal === "SIGXCPU"
      ? ({ resource: "cpu", name: "cpu_seconds" } as const)
      : signal === "SIGXFSZ"
        ? ({ resource: "file-size", name: "file_bytes" } as const)
        : undefined;
  if (ceiling === undefined) return undefined;
  return new AnalysisResourceConstraintError(
    DETECT_FILE_SIGNATURES,
    ceiling.resource,
    `DiE was stopped by ${signal ?? ""} at its ${ceiling.name} ceiling.`,
    {
      cpu_seconds: DIE_LIMITS.cpuSeconds,
      file_bytes: DIE_LIMITS.fileBytes,
      command_timeout_ms: timeoutMs,
    },
    {
      ...(capturedOutput === undefined ? {} : { capturedOutput }),
      retryable: false,
      remediationAction: `The DiE ${ceiling.name} ceiling is fixed (cpu_seconds ${String(DIE_LIMITS.cpuSeconds)}, file_bytes ${String(DIE_LIMITS.fileBytes)}); command_timeout_ms does not raise it. A scan that writes files or needs more CPU time is outside this adapter. Do not repeat the unchanged call.`,
    },
  );
};

/** Preserve lifecycle failures and diagnostic bytes instead of returning partial success. */
export const dieFailure = (
  cause: unknown,
  phase: DiePhase,
  path: string,
  timeoutMs: number,
): AnalysisError => {
  const failure = classify(cause, phase, path, timeoutMs);
  bindArtifactFileCleanup(cause, failure);
  return failure;
};

const classify = (
  cause: unknown,
  phase: DiePhase,
  path: string,
  timeoutMs: number,
): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  const cleanup =
    cause instanceof ArtifactReaderFailure ? cause.cleanup : undefined;
  const cleanupOptions = cleanup === undefined ? {} : { cleanup };
  const reason = cause instanceof Error ? cause.message : String(cause);
  if (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled")
    return new AnalysisCancelledError(DETECT_FILE_SIGNATURES, {
      cause: artifactFileCancellationCause(cause),
      ...cleanupOptions,
    });
  // Node's abortable file writes reject with an AbortError wrapping the reason.
  if (cause instanceof Error && cause.name === "AbortError")
    return new AnalysisCancelledError(DETECT_FILE_SIGNATURES, {
      cause: cause.cause ?? cause,
    });
  if (cause instanceof OwnedCommandFailure)
    return commandFailure(cause, phase, timeoutMs);
  if (cause instanceof RuntimeControlUnavailableError)
    return runtimeControlCapabilityError(
      DIE_PROVIDER_IDENTITY.id,
      DETECT_FILE_SIGNATURES,
      cause,
    );
  if (phase === "configuration")
    return dieUnavailable(`Configured DiE is unavailable: ${reason}`, {
      cause,
    });
  if (phase === "artifact" && cause instanceof ArtifactReaderFailure) {
    if (cause.reason === "limit" && cause.boundary === "file-size")
      return new AnalysisResourceConstraintError(
        DETECT_FILE_SIGNATURES,
        "file-size",
        reason,
        { maximum_file_bytes: MAX_FILE_SIGNATURE_FILE_BYTES },
        {
          cause,
          ...cleanupOptions,
          retryable: false,
          remediationAction: `Raise max_file_bytes (CLI --max-file-bytes) up to ${String(MAX_FILE_SIGNATURE_FILE_BYTES)} for a larger stable file; the snapshot is held in memory. Do not truncate the file; retrying the unchanged request fails again.`,
        },
      );
    if (cause.reason === "integrity")
      return new AnalysisArtifactChangedError(
        DETECT_FILE_SIGNATURES,
        path,
        reason,
        { cause, ...cleanupOptions },
      );
  }
  if (
    phase === "artifact" &&
    cause instanceof Error &&
    "code" in cause &&
    (cause.code === "EACCES" || cause.code === "EPERM")
  )
    return new AnalysisAccessDeniedError(
      DETECT_FILE_SIGNATURES,
      path,
      cause.code,
      { cause, ...cleanupOptions },
    );
  if (phase === "artifact")
    return new AnalysisInputError(
      DETECT_FILE_SIGNATURES,
      { cause, ...cleanupOptions },
      [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Select an existing regular file that is not a symbolic link: ${reason}`,
        },
      ],
    );
  return new AnalysisOutputError(DETECT_FILE_SIGNATURES, reason, {
    cause,
    ...cleanupOptions,
  });
};

const commandFailure = (
  cause: OwnedCommandFailure,
  phase: DiePhase,
  timeoutMs: number,
): AnalysisError => {
  const capturedOutput =
    cause.snapshot === null
      ? undefined
      : cause.reason === "output-limit"
        ? excerpt(cause.snapshot)
        : capturedDieOutput(cause.snapshot);
  const options = {
    cause,
    ...(capturedOutput === undefined ? {} : { capturedOutput }),
  };
  const timeout =
    cause.reason === "timeout"
      ? new AnalysisTimeoutError(DETECT_FILE_SIGNATURES, timeoutMs, {
          ...options,
          capturedOutput:
            cause.cleanupFailure === null ? capturedOutput : undefined,
          userMessage: `A DiE command reached its ${String(timeoutMs)} ms deadline (command_timeout_ms), not the MCP client deadline.`,
          remediationAction:
            timeoutMs < MAX_FILE_SIGNATURE_COMMAND_TIMEOUT_MS
              ? `Increase command_timeout_ms above ${String(timeoutMs)} (CLI --command-timeout-ms, maximum ${String(MAX_FILE_SIGNATURE_COMMAND_TIMEOUT_MS)}), or request fewer scan options. The fixed cpu_seconds ${String(DIE_LIMITS.cpuSeconds)} ceiling still applies. Resolve incomplete cleanup first; do not repeat the unchanged call.`
              : `command_timeout_ms is already at its maximum; request fewer scan options or select a smaller file. Do not repeat the unchanged call.`,
        })
      : undefined;
  if (cause.cleanupFailure !== null)
    return new ProviderCleanupError(
      DIE_PROVIDER_IDENTITY.id,
      cause.resources,
      {
        reason: cause.cleanupFailure,
        previous_error:
          timeout === undefined ? cause.message : projectAnalysisError(timeout),
        ...(capturedOutput === undefined
          ? {}
          : { captured_output: { ...capturedOutput } }),
      },
      { operation: DETECT_FILE_SIGNATURES, cause },
    );
  if (cause.reason === "cancelled")
    return new AnalysisCancelledError(DETECT_FILE_SIGNATURES, {
      ...options,
      cause: cause.cancellation?.reason ?? cause,
    });
  if (timeout !== undefined) return timeout;
  if (cause.reason === "output-limit")
    return new AnalysisResourceConstraintError(
      DETECT_FILE_SIGNATURES,
      "memory",
      `DiE output exceeded the ${String(DIE_LIMITS.outputBytes)}-byte output budget.`,
      { max_output_bytes: DIE_LIMITS.outputBytes },
      {
        ...options,
        retryable: false,
        remediationAction: `The ${String(DIE_LIMITS.outputBytes)}-byte DiE output budget has no runtime override. Request fewer scan options, such as recursive_scan false, or select a smaller file. Do not repeat the unchanged call.`,
      },
    );
  const signal = limiterSignal(
    cause.snapshot?.signal,
    timeoutMs,
    capturedOutput,
  );
  if (signal !== undefined) return signal;
  if (phase === "configuration")
    return dieUnavailable(`Configured DiE could not run: ${cause.message}`, {
      cause,
      ...(capturedOutput === undefined ? {} : { capturedOutput }),
    });
  return new AnalysisOutputError(DETECT_FILE_SIGNATURES, cause.message, {
    ...options,
    remediationAction:
      "Inspect the retained DiE output. A signal other than SIGXCPU or SIGXFSZ does not establish its cause, including memory exhaustion.",
  });
};
