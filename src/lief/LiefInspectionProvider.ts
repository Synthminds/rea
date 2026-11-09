import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { access, stat, writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { LiefInspectionPort } from "../application/lief/LiefInspectionPort.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import {
  AnalysisError,
  type AnalysisCapturedOutput,
} from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import { createEvidence } from "../domain/evidence.js";
import {
  DEFAULT_LIEF_COMMAND_TIMEOUT_MS,
  type InspectWithLiefInput,
  type LiefInspection,
} from "../domain/lief/liefInspection.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  ArtifactAnalysisResources,
  type ArtifactAnalysisRuntime,
} from "../process/ArtifactAnalysisResources.js";
import { readLinuxResourceLimits } from "../process/LinuxResourceLimits.js";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../process/OwnedCommand.js";
import { PrivateRuntimeRoot } from "../process/PrivateRuntimeRoot.js";
import {
  LiefConfigurationError,
  liefFailure,
  type LiefPhase,
} from "./LiefFailures.js";
import {
  LIEF_ADMITTED_RELEASE,
  LIEF_LIMITS,
  LIEF_PROVIDER_IDENTITY,
  liefHostSupported,
} from "./LiefRelease.js";
import {
  LIEF_CONFIGURATION_KEY,
  liefRefusal,
  liefReplySchema,
  liefReport,
} from "./LiefReply.js";

const OPERATION = "inspect_with_lief";
const PRIVATE_COPY_CHANGED =
  "The LIEF helper changed REA's private read-only copy of the selected bytes; its observations are not reported. The selected file itself was not given to the helper.";

type Launcher = NonNullable<Parameters<typeof runOwnedCommand>[2]>["launcher"];

/** Host and helper seams; production uses the running host and packaged bridge. */
export interface LiefProviderSeams {
  readonly launcher?: Launcher;
  readonly createRuntime?: () => Promise<ArtifactAnalysisRuntime>;
  readonly platform?: NodeJS.Platform;
  readonly arch?: string;
  readonly bridge?: URL;
}

/** Mutable facts of one inspection, read by failure classification. */
interface LiefRun {
  readonly python: string;
  readonly timeoutMs: number;
  phase: LiefPhase;
  root: ArtifactAnalysisRuntime | undefined;
  capturedOutput: AnalysisCapturedOutput | undefined;
}

/**
 * Run a caller-supplied LIEF installation against a private read-only copy of
 * exactly the selected bytes. The helper never receives the original path,
 * and REA verifies the copy is unchanged after the helper exits.
 */
export class LiefInspectionProvider implements LiefInspectionPort {
  readonly #resources: ArtifactAnalysisResources;
  readonly #seams: Required<Omit<LiefProviderSeams, "launcher">> &
    Pick<LiefProviderSeams, "launcher">;

  constructor(
    readonly environment: Readonly<NodeJS.ProcessEnv> = process.env,
    seams: LiefProviderSeams = {},
  ) {
    this.#seams = {
      ...(seams.launcher === undefined ? {} : { launcher: seams.launcher }),
      createRuntime:
        seams.createRuntime ??
        (() => PrivateRuntimeRoot.create({ prefix: "rea-lief-" })),
      platform: seams.platform ?? process.platform,
      arch: seams.arch ?? process.arch,
      bridge:
        seams.bridge ??
        new URL("../../bridge/lief/inspect.py", import.meta.url),
    };
    this.#resources = new ArtifactAnalysisResources(
      LIEF_PROVIDER_IDENTITY.id,
      OPERATION,
      readStableArtifact,
      readLinuxResourceLimits,
      {
        message:
          "A LIEF inspection is already running in this REA process; retry after it completes.",
        details: { max_concurrent_inspections: 1 },
      },
    );
  }

  inspect(
    input: InspectWithLiefInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    return this.#resources.run(
      () => this.#inspect(input, options?.signal),
      options?.signal,
    );
  }

  /** Retry retained helper processes and private copies before reporting release. */
  close(): Promise<void> {
    return this.#resources.close();
  }

  async #inspect(
    input: InspectWithLiefInput,
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const python = this.environment[LIEF_CONFIGURATION_KEY] ?? "";
    const timeoutMs =
      input.command_timeout_ms ?? DEFAULT_LIEF_COMMAND_TIMEOUT_MS;
    const run: LiefRun = {
      python,
      timeoutMs,
      phase: "configuration",
      root: undefined,
      capturedOutput: undefined,
    };
    let result: Result<AnalysisExecution, AnalysisError>;
    try {
      const report = await this.#observe(input, run, signal);
      result = ok(
        createAnalysisExecution(
          report,
          {
            ...LIEF_PROVIDER_IDENTITY,
            version: `lief@${report.provider.lief_version}`,
          },
          {
            subject: {
              path: input.path,
              sha256: report.artifact.sha256,
              format:
                report.format === "macho"
                  ? report.macho?.universal === true
                    ? "mach-o-universal"
                    : "mach-o"
                  : report.format,
            },
            locations: [{ kind: "artifact-path", path: input.path }],
            limitations: report.limitations,
          },
        ),
      );
    } catch (cause: unknown) {
      if (
        run.root !== undefined &&
        cause instanceof OwnedCommandFailure &&
        cause.cleanupOwner !== undefined
      )
        this.#resources.retain(run.root, cause.cleanupOwner);
      result = err(
        liefFailure(cause, {
          phase: run.phase,
          input,
          python,
          timeoutMs,
          workspacePath: run.root?.path ?? null,
          observedOutput: run.capturedOutput,
          resources: this.#resources,
        }),
      );
    }
    return this.#resources.finish(
      result,
      (execution) =>
        createEvidence(execution.subject ?? undefined, execution.provider, {
          operation: OPERATION,
          parameters: { ...input },
          result: execution.result,
          confidence: "observed",
          locations: execution.locations,
          limitations: execution.limitations,
        }),
      OPERATION,
      signal,
    );
  }

  async #configuredPython(python: string): Promise<void> {
    if (!liefHostSupported(this.#seams.platform, this.#seams.arch))
      throw new LiefConfigurationError(
        `LIEF inspection is real-verified only on Linux x64; this host is ${this.#seams.platform} ${this.#seams.arch}.`,
      );
    if (!isAbsolute(python))
      throw new LiefConfigurationError(
        `${LIEF_CONFIGURATION_KEY} must be an absolute path to a Python executable.`,
      );
    await access(python, constants.X_OK);
    if (!(await stat(python)).isFile())
      throw new LiefConfigurationError(
        `${LIEF_CONFIGURATION_KEY} must name a regular executable file, not a directory: ${python}`,
      );
  }

  async #observe(
    input: InspectWithLiefInput,
    run: LiefRun,
    signal: AbortSignal | undefined,
  ): Promise<LiefInspection> {
    const { python, timeoutMs } = run;
    if (signal?.aborted)
      throw new AnalysisCancelledError(OPERATION, { cause: signal.reason });
    await this.#resources.release();
    await this.#configuredPython(python);

    run.phase = "artifact";
    const selected = await this.#resources.read(
      input.path,
      input.max_file_bytes,
      signal,
    );
    const before = { sha256: selected.sha256, bytes: selected.bytes.length };

    run.phase = "workspace";
    const { root, paths } = await this.#stage(
      input,
      selected.bytes,
      run,
      signal,
    );

    run.phase = "producer";
    const output = await runOwnedCommand(
      {
        command: python,
        // Isolated mode ignores PYTHON* variables, user site-packages and the
        // script directory; -B keeps the caller's environment free of bytecode.
        arguments: [
          "-I",
          "-B",
          fileURLToPath(this.#seams.bridge),
          paths.request,
        ],
        cwd: root.path,
        // An interpreter shim may exec the real Python; keep group/run-token proof.
        expectedCommand: null,
        runId: `rea-lief-${randomUUID()}`,
        hostEnvironment: this.environment,
      },
      { timeoutMs, diagnosticBytes: LIEF_LIMITS.diagnosticBytes },
      {
        ...(signal === undefined ? {} : { signal }),
        ...(this.#seams.launcher === undefined
          ? {}
          : { launcher: this.#seams.launcher }),
      },
    );
    const diagnostics = {
      stdout: output.stdout.text,
      stderr: output.stderr.text,
      truncated: output.diagnosticTruncated ?? false,
      exit_code: output.exitCode ?? null,
      signal: output.signal ?? null,
    };
    run.capturedOutput = diagnostics;

    run.phase = "integrity";
    const copy = await this.#resources.digest(
      paths.snapshot,
      input.max_file_bytes,
      signal,
    );
    if (copy.sha256 !== before.sha256)
      throw new AnalysisOutputError(OPERATION, PRIVATE_COPY_CHANGED, {
        capturedOutput: diagnostics,
        userMessage: PRIVATE_COPY_CHANGED,
      });

    run.phase = "producer";
    const replyFile = await this.#resources.read(
      paths.reply,
      LIEF_LIMITS.replyBytes,
      signal,
    );
    const reply = liefReplySchema.parse(
      JSON.parse(replyFile.bytes.toString("utf8")),
    );
    if (!reply.ok) throw liefRefusal(reply, input, python, diagnostics);

    run.phase = "integrity";
    const after = await this.#digestAfter(input, signal);
    return liefReport(
      { input, python, before, after, diagnostics },
      reply.value,
    );
  }

  /** Stage a private read-only copy and request; the helper never sees input.path. */
  async #stage(
    input: InspectWithLiefInput,
    bytes: Buffer,
    run: LiefRun,
    signal: AbortSignal | undefined,
  ): Promise<{
    readonly root: ArtifactAnalysisRuntime;
    readonly paths: Readonly<Record<"snapshot" | "request" | "reply", string>>;
  }> {
    const root = await this.#seams.createRuntime();
    run.root = root;
    this.#resources.retain(root);
    const paths = {
      snapshot: join(root.path, "artifact"),
      request: join(root.path, "request.json"),
      reply: join(root.path, "reply.json"),
    };
    await writeFile(paths.snapshot, bytes, {
      flag: "wx",
      mode: 0o400,
      ...(signal === undefined ? {} : { signal }),
    });
    await writeFile(
      paths.request,
      JSON.stringify({
        snapshot_path: paths.snapshot,
        reply_path: paths.reply,
        operation: input.operation,
        offset: input.offset ?? 0,
        limit: input.limit ?? null,
        macho_slice: input.macho_slice ?? null,
        admitted_release: LIEF_ADMITTED_RELEASE,
        output_bytes: LIEF_LIMITS.replyBytes,
      }),
      { flag: "wx", mode: 0o600 },
    );
    return { root, paths };
  }

  /** Post-run digest of the original file; the helper never opened it. */
  async #digestAfter(
    input: InspectWithLiefInput,
    signal: AbortSignal | undefined,
  ): Promise<string | null> {
    try {
      return (
        await this.#resources.digest(input.path, input.max_file_bytes, signal)
      ).sha256;
    } catch (cause: unknown) {
      // Owned descriptor cleanup and cancellation keep their typed outcome.
      if (
        signal?.aborted === true ||
        cause instanceof AnalysisError ||
        (cause instanceof ArtifactReaderFailure &&
          (cause.cleanup !== undefined || cause.reason === "cancelled"))
      )
        throw cause;
      return null;
    }
  }
}
