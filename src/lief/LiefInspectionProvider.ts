import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { access, realpath, stat, writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { LiefInspectionPort } from "../application/lief/LiefInspectionPort.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import {
  digestStableArtifact,
  readStableArtifact,
} from "../artifacts/readStableArtifact.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import { createEvidence } from "../domain/evidence.js";
import {
  DEFAULT_LIEF_COMMAND_TIMEOUT_MS,
  DEFAULT_LIEF_PAGE_ROWS,
  type InspectWithLiefInput,
  type LiefInspection,
} from "../domain/lief/liefInspection.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  ArtifactAnalysisResources,
  type ArtifactAnalysisRuntime,
} from "../process/ArtifactAnalysisResources.js";
import { readLinuxResourceLimits } from "../process/LinuxResourceLimits.js";
import { runOwnedCommand } from "../process/OwnedCommand.js";
import { PrivateRuntimeRoot } from "../process/PrivateRuntimeRoot.js";
import {
  LiefConfigurationError,
  liefFailure,
  liefOutput,
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
  liefFailureOutput,
  liefPageLimit,
  liefRefusal,
  liefReplySchema,
  liefReport,
  type LiefInterpreter,
  type LiefObservedRun,
  type LiefOutput,
} from "./LiefReply.js";

const OPERATION = "inspect_with_lief";
const EMPTY_OUTPUT: LiefOutput = {
  stdout: { text: "", bytes: 0 },
  stderr: { text: "", bytes: 0 },
  truncated: false,
  exitCode: null,
  signal: null,
};
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
  /** Owned stable reads and digests, wrapped to place lifecycle interleavings. */
  readonly readArtifact?: typeof readStableArtifact;
  readonly digestArtifact?: typeof digestStableArtifact;
}

/** Mutable facts of one inspection, read by failure classification. */
interface LiefRun {
  readonly python: string;
  readonly timeoutMs: number;
  phase: LiefPhase;
  root: ArtifactAnalysisRuntime | undefined;
  output: LiefOutput | undefined;
}

/**
 * Run a caller-supplied LIEF installation against a private read-only copy of
 * exactly the selected bytes. The helper never receives the original path,
 * and REA verifies the copy is unchanged after the helper exits.
 */
export class LiefInspectionProvider implements LiefInspectionPort {
  readonly #resources: ArtifactAnalysisResources;
  readonly #seams: Required<
    Omit<LiefProviderSeams, "launcher" | "readArtifact" | "digestArtifact">
  > &
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
      seams.readArtifact ?? readStableArtifact,
      readLinuxResourceLimits,
      {
        message:
          "A LIEF inspection is already running in this REA process; retry after it completes.",
        details: { max_concurrent_inspections: 1 },
      },
      seams.digestArtifact ?? digestStableArtifact,
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
      output: undefined,
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
      result = err(
        liefFailure(cause, {
          phase: run.phase,
          input,
          python,
          timeoutMs,
          workspacePath: run.root?.path ?? null,
          observedOutput: run.output,
          resources: this.#resources,
          signal,
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

  /** Resolve and digest the interpreter REA launches, so a mid-run change is detected. */
  async #interpreter(
    python: string,
    signal: AbortSignal | undefined,
  ): Promise<LiefInterpreter> {
    const path = await realpath(python);
    try {
      const { sha256 } = await this.#resources.digest(
        path,
        LIEF_LIMITS.toolBytes,
        signal,
      );
      return { configured: python, path, sha256 };
    } catch (cause: unknown) {
      // Cancellation and descriptor cleanup keep their typed outcome.
      if (
        signal?.aborted === true ||
        (cause instanceof ArtifactReaderFailure &&
          (cause.cleanup !== undefined || cause.reason === "cancelled"))
      )
        throw cause;
      throw new LiefConfigurationError(
        `${LIEF_CONFIGURATION_KEY} resolves to ${path}, which REA could not digest to identify the interpreter: ${cause instanceof Error ? cause.message : String(cause)}`,
        { cause },
      );
    }
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
    const interpreter = await this.#interpreter(python, signal);

    run.phase = "artifact";
    // A streamed digest fixes the selected bytes; the copy must reproduce it,
    // so REA never holds the artifact in memory.
    const before = await this.#resources.digest(
      input.path,
      input.max_file_bytes,
      signal,
    );

    run.phase = "workspace";
    const { root, paths } = await this.#stage(input, run);

    run.phase = "copy";
    await this.#resources.copy(input.path, paths.snapshot, before, signal);

    run.phase = "producer";
    const snapshot = await runOwnedCommand(
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
        // A virtual environment's python is a symlink and a shim may exec
        // another file, so the command path proves nothing; ownership is the
        // process group plus the run token, which also reaches descendants
        // that leave the group (setsid).
        expectedCommand: null,
        runId: `rea-lief-${randomUUID()}`,
        hostEnvironment: this.environment,
        sweepTokenOwnedProcesses: true,
      },
      { timeoutMs, diagnosticBytes: LIEF_LIMITS.diagnosticBytes },
      {
        ...(signal === undefined ? {} : { signal }),
        ...(this.#seams.launcher === undefined
          ? {}
          : { launcher: this.#seams.launcher }),
        // Unconfirmed process cleanup after a completed run keeps the reply;
        // the root retains the supervisor and finish() reports cleanup_incomplete.
        retainCleanup: (owner) => this.#resources.retain(root, owner),
      },
    );
    const output = liefOutput(snapshot) ?? EMPTY_OUTPUT;
    run.output = output;

    run.phase = "integrity";
    const copy = await this.#resources.digest(
      paths.snapshot,
      input.max_file_bytes,
      signal,
    );
    if (copy.sha256 !== before.sha256)
      throw new AnalysisOutputError(OPERATION, PRIVATE_COPY_CHANGED, {
        capturedOutput: liefFailureOutput(output),
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
    if (!reply.ok) throw liefRefusal(reply, input, python, output);

    run.phase = "integrity";
    await this.#unchanged(
      [
        {
          label: "configured Python interpreter",
          path: interpreter.path,
          sha256: interpreter.sha256,
        },
        { label: "native LIEF module", ...reply.value.native_module },
      ],
      output,
      signal,
    );
    const after = await this.#digestAfter(input, signal);
    return liefReport(
      { input, python: interpreter, before, after, output },
      reply.value,
    );
  }

  /** The code that produced the reply must be the code identified before the run. */
  async #unchanged(
    files: readonly {
      readonly label: string;
      readonly path: string;
      readonly sha256: string;
    }[],
    output: LiefOutput,
    signal: AbortSignal | undefined,
  ): Promise<void> {
    for (const file of files) {
      const changed = (detail: string) => {
        const message = `The ${file.label} changed during the LIEF run, so the code that produced this reply is unknown: ${file.path} (${detail}).`;
        return new AnalysisOutputError(OPERATION, message, {
          capturedOutput: liefFailureOutput(output),
          userMessage: message,
          remediationAction:
            "Keep the configured Python and its LIEF installation unchanged while REA runs, then repeat the call.",
        });
      };
      if (!isAbsolute(file.path)) throw changed("the path is not absolute");
      let sha256: string;
      try {
        ({ sha256 } = await this.#resources.digest(
          file.path,
          LIEF_LIMITS.toolBytes,
          signal,
        ));
      } catch (cause: unknown) {
        if (
          signal?.aborted === true ||
          (cause instanceof ArtifactReaderFailure &&
            (cause.cleanup !== undefined || cause.reason === "cancelled"))
        )
          throw cause;
        throw changed(cause instanceof Error ? cause.message : String(cause));
      }
      if (sha256 !== file.sha256) throw changed(`SHA-256 is now ${sha256}`);
    }
  }

  /** Create the private root and request; the helper never sees input.path. */
  async #stage(
    input: InspectWithLiefInput,
    run: LiefRun,
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
    await writeFile(
      paths.request,
      JSON.stringify({
        snapshot_path: paths.snapshot,
        reply_path: paths.reply,
        operation: input.operation,
        offset: input.offset ?? 0,
        limit: input.operation === "summary" ? null : liefPageLimit(input),
        macho_slice: input.macho_slice ?? null,
        admitted_release: LIEF_ADMITTED_RELEASE,
        output_bytes: LIEF_LIMITS.replyBytes,
        address_space_bytes: LIEF_LIMITS.addressSpaceBytes,
        summary_rows: DEFAULT_LIEF_PAGE_ROWS,
        message_bytes: LIEF_LIMITS.messageBytes,
      }),
      { flag: "wx", mode: 0o600 },
    );
    return { root, paths };
  }

  /**
   * Post-run digest of the original file; the helper never opened it. A file
   * that grew past the admitted size, changed during this read, or vanished
   * has provably changed even though no digest is available.
   */
  async #digestAfter(
    input: InspectWithLiefInput,
    signal: AbortSignal | undefined,
  ): Promise<LiefObservedRun["after"]> {
    try {
      const { sha256 } = await this.#resources.digest(
        input.path,
        input.max_file_bytes,
        signal,
      );
      return { sha256, changed: undefined };
    } catch (cause: unknown) {
      // Owned descriptor cleanup and cancellation keep their typed outcome.
      if (
        signal?.aborted === true ||
        cause instanceof AnalysisError ||
        (cause instanceof ArtifactReaderFailure &&
          (cause.cleanup !== undefined || cause.reason === "cancelled"))
      )
        throw cause;
      const code =
        cause instanceof Error && "code" in cause ? String(cause.code) : null;
      const changed =
        (cause instanceof ArtifactReaderFailure &&
          ["limit", "integrity", "path"].includes(cause.reason)) ||
        code === "ENOENT";
      return { sha256: null, changed: changed ? true : null };
    }
  }
}
