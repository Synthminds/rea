import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { access, mkdir, realpath, stat, writeFile } from "node:fs/promises";
import { basename, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { ExecutionOptions } from "../../application/AnalysisProvider.js";
import { createAnalysisExecution } from "../../application/AnalysisProvider.js";
import type {
  FileSignaturesExecution,
  FileSignaturesPort,
} from "../../application/binaryDiagnostics/FileSignaturesPort.js";
import { AnalysisCleanupLeaseGroup } from "../../artifacts/AnalysisCleanupLease.js";
import {
  ArtifactFileCleanupFailure,
  bindArtifactFileCleanup,
} from "../../artifacts/ArtifactFileOperation.js";
import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import {
  ArtifactResourceRetryFailure,
  ArtifactResourceScope,
} from "../../artifacts/ArtifactResourceScope.js";
import {
  digestStableArtifact,
  readStableArtifact,
} from "../../artifacts/readStableArtifact.js";
import type {
  AnalysisCapturedOutput,
  AnalysisError,
} from "../../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupFailure } from "../../domain/analysisErrorCleanup.js";
import {
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
} from "../../domain/analysisErrorCore.js";
import { createAnalysisExecutionEvidence } from "../../domain/analysisObservation.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import {
  DEFAULT_FILE_SIGNATURE_COMMAND_TIMEOUT_MS,
  fileSignaturesSchema,
  type DetectFileSignaturesInput,
  type FileSignatureBackend,
} from "../../domain/native/fileSignatures.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  prlimitArgumentVector,
  readLinuxResourceLimits,
  type LinuxResourceLimits,
} from "../../process/LinuxResourceLimits.js";
import { boundedUtf8Text } from "../../process/boundedUtf8Text.js";
import { runOwnedCommand } from "../../process/OwnedCommand.js";
import { OwnedCommandRuntime } from "../../process/OwnedCommandRuntime.js";
import { PrivateRuntimeRoot } from "../../process/PrivateRuntimeRoot.js";
import type { ProviderProcessSnapshot } from "../../process/ProviderProcess.js";
import {
  DETECT_FILE_SIGNATURES as OPERATION,
  boundedDieOutput,
  dieFailure,
  dieUnavailable,
  type DiePhase,
} from "./DieFailures.js";
import {
  DIE_ENGINE_VERSION,
  DIE_LIMITS,
  DIE_PRLIMIT_COMMAND_DEFAULT,
  DIE_PROVIDER_IDENTITY,
  DIE_PYTHON_PACKAGE_VERSION,
  DIE_VERIFIED_BACKENDS,
  dieHostSupported,
} from "./DieRelease.js";
import {
  parseDieResultDocument,
  splitDiecOutput,
  type DieResultDocument,
} from "./DieResultDocument.js";

type Launcher = NonNullable<Parameters<typeof runOwnedCommand>[2]>["launcher"];
type Report = z.output<typeof fileSignaturesSchema>;
type ToolProfile = Report["tool_profile"];

const BRIDGE = new URL("../../../bridge/die/scan.py", import.meta.url);
const REPLY_MESSAGE_BYTES = 4096;
const HOST_REQUIREMENT =
  "Detect It Easy signature detection is verified on Linux x64 only.";

/** diec option for each requested DiE scan flag, from the DiE 3.09 console. */
const DIEC_FLAGS = {
  deep_scan: "-d",
  heuristic_scan: "-u",
  recursive_scan: "-r",
  verbose: "-b",
  all_types: "-a",
} as const;

const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/u);

/** One owned bridge reply; the DiE document stays opaque until its own parser. */
const bridgeReplySchema = z.discriminatedUnion("ok", [
  z.strictObject({
    ok: z.literal(true),
    package_version: z.string(),
    engine_version: z.string(),
    library_version: z.string(),
    library_tag: z.string(),
    native_module: z.strictObject({
      path: z.string().refine(isAbsolute, "native module path is not absolute"),
      sha256: sha256Schema,
    }),
    database: z.strictObject({
      files: z.int().nonnegative(),
      sha256: sha256Schema,
    }),
    document: z.string().nullable(),
  }),
  z.strictObject({
    ok: z.literal(false),
    reason: z.enum(["unavailable", "unsupported-version", "memory", "scanner"]),
    message: z.string(),
    observed: z.record(z.string(), z.string()).nullable(),
  }),
]);

interface SelectedTool {
  readonly backend: FileSignatureBackend;
  readonly configurationKey: ToolProfile["configuration_key"];
  readonly path: string;
  readonly resolvedPath: string;
  readonly sha256: string;
}

/** The limiter runs every DiE command; its resolved bytes are what executed. */
interface SelectedLimiter {
  readonly configuredPath: string;
  readonly path: string;
  readonly sha256: string;
}

/** A file that ran during the scan, with the digest recorded before it. */
interface ExecutedFile {
  readonly label: string;
  readonly path: string;
  readonly sha256: string;
}

/** The first read REA makes after DiE exits. */
const SNAPSHOT_READ = "private snapshot";

/** Lines DiE or its host printed outside the result document. */
const messageLines = (text: string): string[] =>
  text.split(/\r?\n/u).filter((line) => line.trim() !== "");

/** Run caller-supplied Detect It Easy against a private copy of exactly the selected bytes. */
export class DieSignatureProvider implements FileSignaturesPort {
  readonly #resources = new ArtifactResourceScope();

  constructor(
    readonly environment: Readonly<NodeJS.ProcessEnv> = process.env,
    readonly launcher?: Launcher,
    readonly createRuntime: () => Promise<
      Pick<PrivateRuntimeRoot, "path" | "close">
    > = () => PrivateRuntimeRoot.create({ prefix: "rea-die-" }),
    readonly readLimits: (
      configured: LinuxResourceLimits,
      resources: ArtifactResourceScope,
    ) => Promise<LinuxResourceLimits> = readLinuxResourceLimits,
    /** Selection refuses other backends; source-owned controls may admit diec. */
    readonly backends: readonly FileSignatureBackend[] = DIE_VERIFIED_BACKENDS,
  ) {}

  /** Retry retained cleanup without discarding roots or commands that still cannot be released. */
  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      throw resourceCleanupFailure(cause);
    }
  }

  async inspect(
    input: DetectFileSignaturesInput,
    options?: ExecutionOptions,
  ): Promise<Result<FileSignaturesExecution, AnalysisError>> {
    try {
      return await this.#resources.run(() => this.#inspect(input, options));
    } catch (cause: unknown) {
      if (cause instanceof ArtifactResourceRetryFailure)
        return err(resourceCleanupFailure(cause));
      if (
        cause instanceof ArtifactReaderFailure &&
        cause.reason === "unavailable" &&
        cause.cleanup === undefined
      )
        return err(
          new AnalysisCapabilityUnavailableError(
            DIE_PROVIDER_IDENTITY.id,
            OPERATION,
            "Provider is closing",
          ),
        );
      return err(
        dieFailure(
          cause,
          "artifact",
          input.path,
          input.command_timeout_ms ?? DEFAULT_FILE_SIGNATURE_COMMAND_TIMEOUT_MS,
        ),
      );
    }
  }

  /** Select exactly one caller-supplied backend; never search PATH or install DiE. */
  async #selectTool(
    signal?: AbortSignal,
  ): Promise<{ tool: SelectedTool; limiter: SelectedLimiter }> {
    const diec = this.environment.REA_DIE_COMMAND;
    const python = this.environment.REA_DIE_PYTHON;
    const selected =
      diec !== undefined && diec !== ""
        ? ({
            backend: "diec",
            configurationKey: "REA_DIE_COMMAND",
            path: diec,
          } as const)
        : python !== undefined && python !== ""
          ? ({
              backend: "die-python",
              configurationKey: "REA_DIE_PYTHON",
              path: python,
            } as const)
          : undefined;
    if (selected === undefined)
      throw dieUnavailable(
        "Detect It Easy is not configured: set REA_DIE_PYTHON.",
      );
    // Fail closed before touching the path: an explicit diec selection is
    // refused rather than silently replaced by REA_DIE_PYTHON.
    if (!this.backends.includes(selected.backend))
      throw dieUnavailable(
        `${selected.configurationKey} selects ${selected.backend}, an unverified DiE backend: no real ${selected.backend} lane has passed, and a Qt6 diec is expected to die from SIGXFSZ under the zero-byte file-size ceiling.`,
        {
          diagnostics: {
            configuration_key: selected.configurationKey,
            executable_path: selected.path,
            admitted_backends: this.backends.join(", "),
          },
        },
      );
    if (!isAbsolute(selected.path))
      throw dieUnavailable(
        `${selected.configurationKey} must be an absolute executable path.`,
      );
    const configuredLimiter =
      this.environment.REA_DIE_PRLIMIT_COMMAND ?? DIE_PRLIMIT_COMMAND_DEFAULT;
    if (!isAbsolute(configuredLimiter))
      throw dieUnavailable(
        "REA_DIE_PRLIMIT_COMMAND must be an absolute executable path.",
      );
    for (const [key, path] of [
      [selected.configurationKey, selected.path],
      ["REA_DIE_PRLIMIT_COMMAND", configuredLimiter],
    ] as const) {
      try {
        await access(path, constants.X_OK);
        if (!(await stat(path)).isFile())
          throw new TypeError("not a regular file");
      } catch (cause: unknown) {
        throw dieUnavailable(
          `${key} is not an executable regular file: ${path}: ${cause instanceof Error ? cause.message : String(cause)}`,
          { cause },
        );
      }
    }
    // Spawn the configured path so a virtual environment's interpreter keeps
    // its environment; the resolved file identifies the executed bytes.
    const resolvedPath = await realpath(selected.path);
    const executable = await this.#digest(
      resolvedPath,
      DIE_LIMITS.toolBytes,
      signal,
    );
    const limiterPath = await realpath(configuredLimiter);
    const limiter = await this.#digest(
      limiterPath,
      DIE_LIMITS.toolBytes,
      signal,
    );
    return {
      tool: { ...selected, resolvedPath, sha256: executable.sha256 },
      limiter: {
        configuredPath: configuredLimiter,
        path: limiterPath,
        sha256: limiter.sha256,
      },
    };
  }

  /** Stream one stable file's digest under this provider's descriptor ownership. */
  #digest(path: string, maximumBytes: number, signal?: AbortSignal) {
    return digestStableArtifact(
      path,
      maximumBytes,
      signal,
      undefined,
      this.#resources,
    );
  }

  /**
   * A post-scan read that completed keeps its digest when only its descriptor
   * close failed; `retained` collects that still-owned descriptor.
   */
  async #postScanDigest(
    path: string,
    maximumBytes: number,
    signal: AbortSignal | undefined,
    retained: ArtifactFileCleanupFailure[],
  ): Promise<{ readonly sha256: string; readonly bytes: number }> {
    try {
      return await this.#digest(path, maximumBytes, signal);
    } catch (cause: unknown) {
      const completed = completedDigest(cause);
      if (completed === undefined) throw cause;
      retained.push(completed.failure);
      return completed.digest;
    }
  }

  /**
   * Copy exactly the selected bytes into the private snapshot. The resident
   * copy lives only here, so it is released before the scan starts.
   */
  async #writeSnapshot(
    input: DetectFileSignaturesInput,
    snapshotPath: string,
    signal: AbortSignal | undefined,
  ): Promise<Report["artifact"]> {
    const selected = await readStableArtifact(
      input.path,
      input.max_file_bytes,
      signal,
      undefined,
      this.#resources,
    );
    await writeFile(snapshotPath, selected.bytes, {
      flag: "wx",
      mode: 0o400,
      ...(signal === undefined ? {} : { signal }),
    });
    return {
      path: input.path,
      sha256: selected.sha256,
      bytes: selected.bytes.length,
    };
  }

  /**
   * A changed or unreadable private snapshot means DiE may not have scanned
   * the selected bytes; cancellation and descriptor cleanup keep their own class.
   */
  async #verifySnapshot(
    snapshotPath: string,
    artifact: Report["artifact"],
    signal: AbortSignal | undefined,
    capturedOutput: AnalysisCapturedOutput,
    retained: ArtifactFileCleanupFailure[],
  ): Promise<void> {
    let reason: string | undefined;
    try {
      const after = await this.#postScanDigest(
        snapshotPath,
        artifact.bytes,
        signal,
        retained,
      );
      if (after.sha256 !== artifact.sha256)
        reason = "The private DiE snapshot changed during the scan.";
    } catch (cause: unknown) {
      if (
        signal?.aborted === true ||
        (cause instanceof ArtifactReaderFailure &&
          (cause.reason === "cancelled" || cause.cleanup !== undefined))
      )
        throw cause;
      reason = `The private DiE snapshot could not be read back unchanged after the scan: ${cause instanceof Error ? cause.message : String(cause)}`;
    }
    if (reason !== undefined)
      throw new AnalysisArtifactChangedError(OPERATION, artifact.path, reason, {
        capturedOutput,
      });
  }

  /** An executed file must still hold the bytes recorded before the scan. */
  async #verifyUnchanged(
    file: ExecutedFile,
    signal: AbortSignal | undefined,
    capturedOutput: AnalysisCapturedOutput,
    retained: ArtifactFileCleanupFailure[],
  ): Promise<void> {
    const after = await this.#postScanDigest(
      file.path,
      DIE_LIMITS.toolBytes,
      signal,
      retained,
    );
    if (after.sha256 !== file.sha256)
      throw new AnalysisOutputError(
        OPERATION,
        `The ${file.label} changed during the scan: ${file.path}`,
        {
          capturedOutput,
          remediationAction:
            "The bytes that produced this scan are unknown. Keep the DiE installation and limiter unchanged while REA runs, then repeat the call.",
        },
      );
  }

  async #inspect(
    input: DetectFileSignaturesInput,
    options?: ExecutionOptions,
  ): Promise<Result<FileSignaturesExecution, AnalysisError>> {
    const signal = options?.signal;
    const timeoutMs =
      input.command_timeout_ms ?? DEFAULT_FILE_SIGNATURE_COMMAND_TIMEOUT_MS;
    let phase: DiePhase = "configuration";
    let runtime: OwnedCommandRuntime | undefined;
    let capturedOutput: AnalysisCapturedOutput | undefined;
    // Once DiE's output is interpreted: what cancellation during REA's
    // post-scan reads keeps. A valid document keeps its detections, naming the
    // reads not yet confirmed; an invalid one keeps its known output error.
    let afterScan:
      | {
          readonly kind: "valid";
          readonly execution: () => FileSignaturesExecution | undefined;
        }
      | { readonly kind: "invalid"; readonly error: AnalysisError }
      | undefined;
    // Completed post-scan reads whose descriptor close failed.
    const retained: ArtifactFileCleanupFailure[] = [];
    let result: Result<FileSignaturesExecution, AnalysisError>;
    try {
      if (signal?.aborted)
        throw new AnalysisCancelledError(OPERATION, { cause: signal.reason });
      if (!dieHostSupported(process.platform, process.arch))
        throw dieUnavailable(HOST_REQUIREMENT);
      const { tool, limiter } = await this.#selectTool(signal);
      phase = "limits";
      const limits = await this.readLimits(
        {
          address_space_bytes: DIE_LIMITS.addressSpaceBytes,
          file_bytes: DIE_LIMITS.fileBytes,
          cpu_seconds: DIE_LIMITS.cpuSeconds,
        },
        this.#resources,
      );
      phase = "configuration";
      const root = await this.createRuntime();
      runtime = new OwnedCommandRuntime(root, "DiE", this.#resources);
      const limiterArguments = prlimitArgumentVector(limits, tool.path);
      const run = async (
        args: readonly string[],
        acceptNonZeroExit: boolean,
      ): Promise<ProviderProcessSnapshot> => {
        capturedOutput = undefined;
        const snapshot = await runOwnedCommand(
          {
            command: limiter.path,
            arguments: [...limiterArguments, ...args],
            expectedCommand: null,
            cwd: root.path,
            runId: `rea-die-${randomUUID()}`,
            hostEnvironment: this.environment,
            env: { TMPDIR: root.path },
            // A descendant that leaves the process group still carries the run token.
            sweepTokenOwnedProcesses: true,
          },
          {
            timeoutMs,
            diagnosticBytes: DIE_LIMITS.outputBytes,
            acceptNonZeroExit,
          },
          {
            ...(signal === undefined ? {} : { signal }),
            ...(this.launcher === undefined ? {} : { launcher: this.launcher }),
          },
        );
        capturedOutput = boundedDieOutput(snapshot);
        return snapshot;
      };
      let versionBanner: string | null = null;
      if (tool.backend === "diec") {
        const version = await run(["--version"], false);
        // Qt prints "<application> <version>" for --version.
        const banner = version.stdout.text.trim();
        if (
          banner.includes("\n") ||
          banner.split(/\s+/u).at(-1) !== DIE_ENGINE_VERSION ||
          version.stderr.text.trim() !== ""
        )
          throw dieUnavailable(
            `Unsupported diec version banner; this adapter admits DiE ${DIE_ENGINE_VERSION}.`,
            {
              capturedOutput: boundedDieOutput(version),
              diagnostics: {
                configuration_key: tool.configurationKey,
                executable_path: tool.path,
                expected_version: DIE_ENGINE_VERSION,
                observed_banner: boundedDieOutput(version).stdout.trim(),
              },
            },
          );
        versionBanner = version.stdout.text;
      }
      phase = "artifact";
      // DiE signatures may consult the file name; siblings stay unreachable.
      const directory = join(root.path, "target");
      await mkdir(directory, { mode: 0o700 });
      const snapshotPath = join(directory, basename(input.path));
      const artifact = await this.#writeSnapshot(input, snapshotPath, signal);
      phase = "scanner";
      const scanArguments =
        tool.backend === "diec"
          ? [
              "-j",
              ...Object.entries(DIEC_FLAGS)
                .filter(([field]) => input[field as keyof typeof DIEC_FLAGS])
                .map(([, flag]) => flag),
              snapshotPath,
            ]
          : [
              // Isolated mode, and no bytecode caches in the caller's environment.
              "-I",
              "-B",
              fileURLToPath(BRIDGE),
              JSON.stringify({
                path: snapshotPath,
                package_version: DIE_PYTHON_PACKAGE_VERSION,
                engine_version: DIE_ENGINE_VERSION,
                scan: scanOptions(input),
              }),
            ];
      const scan = await run(scanArguments, tool.backend === "diec");
      const scanOutput = boundedDieOutput(scan);
      // Interpret the finished scan before REA's post-scan reads so that a
      // cancellation during any of them still has its detections. Failures to
      // interpret it keep yielding to the integrity checks below.
      const produced =
        tool.backend === "diec"
          ? diecResult(scan, versionBanner)
          : diePythonResult(scan, tool);
      const reportOf = (
        output: ProducedResult,
        detected: DieResultDocument,
        afterSha256: string | null,
      ) => ({
        artifact,
        artifact_after: {
          sha256: afterSha256,
          changed:
            afterSha256 === null ? null : afterSha256 !== artifact.sha256,
        },
        scan: scanOptions(input),
        file_parts: detected.file_parts,
        detections: detected.detections,
        scan_messages: [...output.messages, ...messageLines(scan.stderr.text)],
        tool_profile: {
          backend: tool.backend,
          configuration_key: tool.configurationKey,
          executable: {
            path: tool.path,
            resolved_path: tool.resolvedPath,
            sha256: tool.sha256,
          },
          resource_limiter: {
            configured_path: limiter.configuredPath,
            path: limiter.path,
            sha256: limiter.sha256,
            arguments: limiterArguments,
          },
          ...output.profile,
          arguments: scanArguments,
          timeout_ms: timeoutMs,
          output_budget_bytes: DIE_LIMITS.outputBytes,
          resource_limits: {
            address_space_bytes: limits.address_space_bytes,
            cpu_seconds: limits.cpu_seconds,
            file_bytes: limits.file_bytes,
          },
        } satisfies ToolProfile,
        target_execution: "not-performed",
      });
      const executionOf = (
        report: Report,
        postScan: readonly string[],
      ): FileSignaturesExecution =>
        createAnalysisExecution(report, DIE_PROVIDER_IDENTITY, {
          subject: {
            path: input.path,
            format: "file",
            sha256: artifact.sha256,
          },
          locations: [{ kind: "artifact-path", path: input.path }],
          limitations: dieLimitations(report, postScan),
        });
      const executed: ExecutedFile[] = [
        {
          label: "configured DiE executable",
          path: tool.resolvedPath,
          sha256: tool.sha256,
        },
        {
          label: "configured resource limiter",
          path: limiter.path,
          sha256: limiter.sha256,
        },
        // Only a valid bridge reply names the module; an invalid one fails below.
        ...(produced.ok && produced.value.profile.native_module !== null
          ? [
              {
                label: "die-python native scanner module",
                ...produced.value.profile.native_module,
              },
            ]
          : []),
      ];
      const unconfirmed = new Set([
        SNAPSHOT_READ,
        ...executed.map(({ label }) => label),
      ]);
      const interpreted: Result<
        { output: ProducedResult; document: DieResultDocument },
        AnalysisError
      > = !produced.ok
        ? produced
        : produced.value.document.ok
          ? ok({
              output: produced.value,
              document: produced.value.document.value,
            })
          : err(
              new AnalysisOutputError(
                OPERATION,
                produced.value.document.error,
                { capturedOutput: scanOutput },
              ),
            );
      afterScan = interpreted.ok
        ? {
            kind: "valid",
            execution: () => {
              const report = fileSignaturesSchema.safeParse(
                reportOf(
                  interpreted.value.output,
                  interpreted.value.document,
                  null,
                ),
              );
              return report.success
                ? executionOf(report.data, cancelledPostScan([...unconfirmed]))
                : undefined;
            },
          }
        : { kind: "invalid", error: interpreted.error };
      await this.#verifySnapshot(
        snapshotPath,
        artifact,
        signal,
        scanOutput,
        retained,
      );
      unconfirmed.delete(SNAPSHOT_READ);
      for (const file of executed) {
        await this.#verifyUnchanged(file, signal, scanOutput, retained);
        unconfirmed.delete(file.label);
      }
      if (!interpreted.ok) throw interpreted.error;
      const after = await this.#digestAfter(input, signal, retained);
      result = ok(
        executionOf(
          fileSignaturesSchema.parse(
            reportOf(
              interpreted.value.output,
              interpreted.value.document,
              after.sha256,
            ),
          ),
          after.unknown === undefined ? [] : [after.unknown],
        ),
      );
    } catch (cause: unknown) {
      const failure = dieFailure(cause, phase, input.path, timeoutMs);
      runtime?.retainCommandFailure(cause, failure);
      // Cancellation during a post-scan read keeps what DiE's output established.
      if (failure instanceof AnalysisCancelledError) {
        if (afterScan?.kind === "invalid")
          failure.retainSecondaryFailure(afterScan.error, {
            scan_output_error: projectAnalysisError(afterScan.error),
          });
        const parsed =
          afterScan?.kind === "valid" ? afterScan.execution() : undefined;
        if (parsed !== undefined)
          failure.retainPartialObservation(
            createAnalysisExecutionEvidence(
              OPERATION,
              input,
              parsed,
              "observed",
            ),
          );
      }
      result = err(
        failure instanceof AnalysisOutputError &&
          failure.capturedOutput === undefined &&
          capturedOutput !== undefined
          ? new AnalysisOutputError(OPERATION, failure.reason, {
              cause: failure,
              capturedOutput,
              cleanup: failure.cleanup,
              ...(failure.remediationAction === undefined
                ? {}
                : { remediationAction: failure.remediationAction }),
            }).bindCleanupDependencies([failure])
          : failure,
      );
    }
    return runtime === undefined
      ? result
      : this.#releaseRuntime(runtime, result, retained, input, signal);
  }

  /** A post-scan read failure leaves the digest unknown rather than failing the scan. */
  async #digestAfter(
    input: DetectFileSignaturesInput,
    signal: AbortSignal | undefined,
    retained: ArtifactFileCleanupFailure[],
  ): Promise<{ sha256: string | null; unknown: string | undefined }> {
    try {
      const after = await this.#postScanDigest(
        input.path,
        input.max_file_bytes,
        signal,
        retained,
      );
      return { sha256: after.sha256, unknown: undefined };
    } catch (cause: unknown) {
      if (
        signal?.aborted === true ||
        (cause instanceof ArtifactReaderFailure &&
          (cause.reason === "cancelled" || cause.cleanup !== undefined))
      )
        throw cause;
      return {
        sha256: null,
        unknown: `The selected file could not be read again after the scan, so its post-scan digest is unknown: ${cause instanceof Error ? cause.message : String(cause)}`,
      };
    }
  }

  /**
   * Release the private runtime after every command. A completed result keeps
   * its Evidence when a post-scan descriptor close or root removal fails.
   */
  async #releaseRuntime(
    runtime: OwnedCommandRuntime,
    outcome: Result<FileSignaturesExecution, AnalysisError>,
    retained: readonly ArtifactFileCleanupFailure[],
    input: DetectFileSignaturesInput,
    signal: AbortSignal | undefined,
  ): Promise<Result<FileSignaturesExecution, AnalysisError>> {
    let result = outcome;
    // A descriptor still held inside the runtime keeps the runtime too.
    const cleanup = await this.#resources.release({
      kind: "lease",
      resource: runtime.path,
      lease: runtime.lease,
    });
    const incomplete = retained.length > 0 || cleanup.kind === "failed";
    const partialObservation =
      result.ok && (signal?.aborted === true || incomplete)
        ? createAnalysisExecutionEvidence(
            OPERATION,
            input,
            result.value,
            "observed",
          )
        : result.ok
          ? undefined
          : result.error.partialObservation;
    if (result.ok && signal?.aborted === true)
      result = err(
        new AnalysisCancelledError(OPERATION, {
          cause: signal.reason,
          ...(partialObservation === undefined ? {} : { partialObservation }),
        }),
      );
    if (!incomplete) return result;
    const causes = [
      ...retained,
      ...(cleanup.kind === "failed" ? [cleanup.cause] : []),
    ];
    const failure = new ProviderCleanupError(
      DIE_PROVIDER_IDENTITY.id,
      [
        ...new Set([
          ...retained.flatMap((read) => read.cleanup?.resources ?? []),
          ...(cleanup.kind === "failed" ? [runtime.path] : []),
        ]),
      ],
      {
        reason: [
          ...retained.map((read) => read.cleanup?.reason ?? read.message),
          ...(cleanup.kind === "failed"
            ? [
                cleanup.cause instanceof Error
                  ? cleanup.cause.message
                  : String(cleanup.cause),
              ]
            : []),
        ].join("; "),
        previous_error: result.ok ? null : projectAnalysisError(result.error),
      },
      {
        operation: OPERATION,
        cause:
          causes.length === 1
            ? causes[0]
            : new AggregateError(causes, "DiE cleanup remains incomplete"),
        ...(partialObservation === undefined ? {} : { partialObservation }),
      },
    );
    new AnalysisCleanupLeaseGroup(failure, [
      ...retained.map((read) => read.cleanupLease),
      ...(cleanup.kind === "failed" ? [runtime.lease] : []),
    ]);
    return err(
      result.ok
        ? failure
        : analysisErrorWithCleanupFailure(
            result.error,
            failure,
            OPERATION,
          ).bindCleanupDependencies([result.error, failure]),
    );
  }
}

const completedDigestSchema = z.strictObject({
  sha256: sha256Schema,
  bytes: z.int().nonnegative(),
});

/**
 * The digest a post-scan read completed before only its descriptor close
 * failed. readStableArtifact builds the result inside descriptor ownership.
 */
const completedDigest = (
  cause: unknown,
):
  | {
      readonly failure: ArtifactFileCleanupFailure;
      readonly digest: { readonly sha256: string; readonly bytes: number };
    }
  | undefined => {
  if (!(cause instanceof ArtifactFileCleanupFailure)) return undefined;
  const outcome = cause.fileCleanupFailure.outcome;
  if (outcome.kind !== "completed") return undefined;
  const digest = completedDigestSchema.safeParse(outcome.value);
  return digest.success ? { failure: cause, digest: digest.data } : undefined;
};

/** The requested upstream scan options, in a fixed order. */
const scanOptions = (input: DetectFileSignaturesInput): Report["scan"] => ({
  deep_scan: input.deep_scan,
  heuristic_scan: input.heuristic_scan,
  recursive_scan: input.recursive_scan,
  verbose: input.verbose,
  all_types: input.all_types,
});

/** One finished scan's output, interpreted once; integrity checks still follow. */
type ProducedResult = {
  readonly document: Result<DieResultDocument, string>;
  readonly messages: readonly string[];
  readonly profile: Pick<
    ToolProfile,
    | "engine_version"
    | "version_banner"
    | "package_version"
    | "library_version"
    | "library_tag"
    | "native_module"
    | "database"
  >;
};

/**
 * DiE 3.09 diec exits nonzero when it cannot load its signature database or
 * open the input, so the exit alone does not establish a configuration fault.
 */
const diecResult = (
  scan: ProviderProcessSnapshot,
  versionBanner: string | null,
): Result<ProducedResult, AnalysisError> => {
  if (scan.exitCode !== 0)
    return err(
      new AnalysisOutputError(
        OPERATION,
        `diec exited with status ${String(scan.exitCode ?? scan.signal)}.`,
        {
          capturedOutput: boundedDieOutput(scan),
          remediationAction: `Inspect the retained diec output. DiE ${DIE_ENGINE_VERSION} diec exits nonzero when it cannot load its installation's signature database or cannot open the private snapshot; repair the database for the former. Do not repeat the unchanged call.`,
        },
      ),
    );
  const split = splitDiecOutput(scan.stdout.text);
  if (!split.ok)
    return err(
      new AnalysisOutputError(OPERATION, split.error, {
        capturedOutput: boundedDieOutput(scan),
      }),
    );
  return ok({
    document: parseDieResultDocument(split.value.document),
    messages: split.value.messages,
    profile: {
      engine_version: DIE_ENGINE_VERSION,
      version_banner: versionBanner,
      package_version: null,
      library_version: null,
      library_tag: null,
      native_module: null,
      database: { source: "installation-default", files: null, sha256: null },
    },
  });
};

/** The owned bridge prints one reply line; native messages were redirected to stderr. */
const diePythonResult = (
  scan: ProviderProcessSnapshot,
  tool: SelectedTool,
): Result<ProducedResult, AnalysisError> => {
  const capturedOutput = boundedDieOutput(scan);
  let reply: z.output<typeof bridgeReplySchema>;
  try {
    reply = bridgeReplySchema.parse(JSON.parse(scan.stdout.text));
  } catch (cause: unknown) {
    return err(
      new AnalysisOutputError(
        OPERATION,
        `The die-python bridge reply is malformed: ${cause instanceof z.ZodError ? (cause.issues[0]?.message ?? "schema mismatch") : cause instanceof Error ? cause.message : String(cause)}`,
        { cause, capturedOutput },
      ),
    );
  }
  if (!reply.ok) {
    // The bridge message can carry producer text; keep it to an excerpt.
    const message = boundedUtf8Text(reply.message, REPLY_MESSAGE_BYTES).text;
    if (
      reply.reason === "unavailable" ||
      reply.reason === "unsupported-version"
    )
      return err(
        dieUnavailable(message, {
          capturedOutput,
          diagnostics: {
            configuration_key: tool.configurationKey,
            executable_path: tool.path,
            expected_version: `die-python ${DIE_PYTHON_PACKAGE_VERSION} with DiE ${DIE_ENGINE_VERSION}`,
            ...reply.observed,
          },
        }),
      );
    if (reply.reason === "memory")
      return err(
        new AnalysisResourceConstraintError(
          OPERATION,
          "memory",
          message,
          { address_space_bytes: DIE_LIMITS.addressSpaceBytes },
          {
            capturedOutput,
            retryable: false,
            remediationAction: `The ${String(DIE_LIMITS.addressSpaceBytes)}-byte DiE address-space ceiling has no runtime override; request fewer scan options or select a smaller file. Do not repeat the unchanged call.`,
          },
        ),
      );
    return err(new AnalysisOutputError(OPERATION, message, { capturedOutput }));
  }
  if (reply.document === null)
    return err(
      new AnalysisOutputError(
        OPERATION,
        "die-python returned no result document.",
        { capturedOutput },
      ),
    );
  return ok({
    document: parseDieResultDocument(reply.document),
    messages: [],
    profile: {
      engine_version: reply.engine_version,
      version_banner: null,
      package_version: reply.package_version,
      library_version: reply.library_version,
      library_tag: reply.library_tag,
      native_module: reply.native_module,
      database: {
        source: "package-bundled",
        files: reply.database.files,
        sha256: reply.database.sha256,
      },
    },
  });
};

/**
 * What cancellation during REA's post-scan reads leaves unknown: the reads it
 * had not confirmed, and the selected file's digest, which is read last.
 */
const cancelledPostScan = (unconfirmed: readonly string[]): string[] => [
  ...(unconfirmed.length === 0
    ? []
    : [
        `The call was cancelled after DiE finished, before REA confirmed that these still held the bytes recorded before the scan: ${unconfirmed.join(", ")}. These detections are unverified: they may not describe the selected bytes or come from the recorded tool.`,
      ]),
  "The call was cancelled before REA finished reading the selected file again after the scan, so its post-scan digest is unknown.",
];

/** Coverage statements for this exact report; unrequested scans stay unknown, not absent. */
const dieLimitations = (
  report: Report,
  postScan: readonly string[],
): string[] => {
  const unrequested = Object.entries(report.scan)
    .filter(([, requested]) => !requested)
    .map(([option]) => option);
  return [
    "Detections are Detect It Easy signature matches: leads about file type, compiler, linker, library, packer or protector, not proof of those components or of whether the file is malicious or safe. A missing detection does not establish that a component is absent.",
    "heuristic true marks DiE's own heuristic label; null means DiE's label did not match its documented rendering and is kept verbatim in label.",
    "DiE scanned a read-only private snapshot carrying the original file name. Signatures that read sibling files see none, so companion-file versions are not reported. No unpacking, script argument, caller signature database or target execution was used.",
    report.tool_profile.backend === "diec"
      ? "diec used its installation's default signature databases; REA passes no database path, and their identity is not observed."
      : "die-python used its package-bundled signature database at die.database_path; database.sha256 digests its sorted file records. Whether die-python also consults its bundled db_custom directory is not observed. native_module identifies the loaded scanner module; its Python sources and bundled shared libraries are not digested.",
    "file_parts offset and size are DiE-reported strings; a nested part can report values relative to its containing part.",
    "The DiE tool is trusted caller-supplied code. It ran under util-linux prlimit with the reported ceilings. The zero-byte file-size ceiling stops file growth, not creating empty files or directories, renaming, unlinking, truncation or permission changes. DiE inherited REA's environment and had no network isolation or other OS sandbox.",
    ...(report.detections.some(
      (detection) =>
        detection.type === "Unknown" && detection.name === "Unknown",
    )
      ? [
          "DiE reports Unknown: Unknown when no signature matched a file part; it is not evidence that the part has no compiler, packer or protector.",
        ]
      : []),
    ...(unrequested.length === 0
      ? []
      : [
          `Not requested: ${unrequested.join(", ")}. Detections those scans could add are not represented.`,
        ]),
    ...postScan,
  ];
};

/** Retry errors follow their exact retained leases, including partially released groups. */
const resourceCleanupFailure = (cause: unknown): ProviderCleanupError => {
  const cleanup =
    cause instanceof ArtifactReaderFailure ? cause.cleanup : undefined;
  const failure = new ProviderCleanupError(
    DIE_PROVIDER_IDENTITY.id,
    cleanup?.resources ?? ["artifact-resources"],
    {
      reason:
        cleanup?.reason ??
        (cause instanceof Error ? cause.message : String(cause)),
    },
    { operation: OPERATION, cause },
  );
  bindArtifactFileCleanup(cause, failure);
  return failure;
};
