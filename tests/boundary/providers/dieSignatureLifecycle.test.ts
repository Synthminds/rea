import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import {
  access,
  chmod,
  copyFile,
  readFile,
  readdir,
  realpath,
  rename,
  writeFile,
  type FileHandle,
} from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { beforeEach, describe, expect, it, onTestFinished, vi } from "vitest";

/**
 * Descriptor faults for one of REA's own stable reads. Inert until a test arms
 * `matches`; earlier opens of the armed path (`skip`) and every other open pass
 * through unchanged.
 */
const fault = vi.hoisted(() => ({
  matches: undefined as ((path: string) => boolean) | undefined,
  skip: 0,
  onStat: undefined as (() => void) | undefined,
  denyFirstClose: false,
  handles: [] as FileHandle[],
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const original = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...original,
    open: async (...arguments_: Parameters<typeof original.open>) => {
      const handle = await original.open(...arguments_);
      if (fault.matches?.(String(arguments_[0])) !== true) return handle;
      if (fault.skip > 0) {
        fault.skip -= 1;
        return handle;
      }
      fault.matches = undefined;
      fault.handles.push(handle);
      const { onStat, denyFirstClose } = fault;
      if (onStat !== undefined) {
        const stat = handle.stat.bind(handle) as (
          options?: object,
        ) => Promise<unknown>;
        handle.stat = (async (options?: object) => {
          onStat();
          return stat(options);
        }) as typeof handle.stat;
      }
      if (denyFirstClose) {
        const close = handle.close.bind(handle);
        let denied = false;
        handle.close = async () => {
          if (!denied) {
            denied = true;
            throw new Error("authored descriptor close denial");
          }
          await close();
        };
      }
      return handle;
    },
  };
});

import { FileSignaturesService } from "../../../src/application/binaryDiagnostics/FileSignaturesService.js";
import type { AnalysisError } from "../../../src/domain/analysisErrorBase.js";
import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";
import {
  fileSignaturesSchema,
  type FileSignatureBackend,
} from "../../../src/domain/native/fileSignatures.js";
import { DIE_LIMITS } from "../../../src/native/die/DieRelease.js";
import { DieSignatureProvider } from "../../../src/native/die/DieSignatureProvider.js";
import { readLinuxResourceLimits } from "../../../src/process/LinuxResourceLimits.js";
import { PrivateRuntimeRoot } from "../../../src/process/PrivateRuntimeRoot.js";
import { spawnOwnedProviderProcess } from "../../../src/process/ProviderProcess.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

/**
 * Source-owned lifecycle controls for the DiE adapter. Each stand-in is an
 * authored bash script selected as REA_DIE_PYTHON (or, through the
 * source-owned backend seam, REA_DIE_COMMAND); none is recorded DiE output.
 * Commands still run through the real util-linux prlimit and owned process
 * supervision, so SIGXFSZ, the CPU ceiling and the token sweep are real kernel
 * and process behavior. Descriptor faults on REA's own post-scan reads go
 * through the `node:fs/promises` open seam above. Simulated tools do not
 * establish real DiE behavior.
 */
const supported =
  process.platform === "linux" &&
  process.arch === "x64" &&
  existsSync("/usr/bin/prlimit");

beforeEach(() => {
  fault.matches = undefined;
  fault.skip = 0;
  fault.onStat = undefined;
  fault.denyFirstClose = false;
  fault.handles = [];
});

const sha256 = (bytes: Buffer | string) =>
  createHash("sha256").update(bytes).digest("hex");

const DOCUMENT = JSON.stringify({
  detects: [
    {
      filetype: "PE32",
      parentfilepart: "Header",
      info: "",
      offset: "0",
      size: "202",
      values: [
        {
          type: "Packer",
          name: "UPX",
          version: "3.96",
          info: "",
          string: "(Heuristic)Packer: UPX(3.96)",
        },
      ],
    },
  ],
});

type Launcher = NonNullable<
  ConstructorParameters<typeof DieSignatureProvider>[1]
>;

interface Fixture {
  readonly root: string;
  readonly target: string;
  readonly targetBytes: Buffer;
  readonly module: string;
  readonly reply: string;
  readonly tool: (body: string, name?: string) => Promise<string>;
}

const createFixture = async (): Promise<Fixture> => {
  const root = await createTestTempDirectory("rea-die-lifecycle-");
  const target = join(root, "sample.bin");
  const targetBytes = Buffer.from("MZ" + "A".repeat(200));
  await writeFile(target, targetBytes);
  const module = join(root, "_die.cpython-313-x86_64-linux-gnu.so");
  const moduleBytes = Buffer.from("authored native module stand-in");
  await writeFile(module, moduleBytes);
  const reply = JSON.stringify({
    ok: true,
    package_version: "0.5.0",
    engine_version: "3.09",
    library_version: "0.1.0",
    library_tag: "tag",
    native_module: { path: module, sha256: sha256(moduleBytes) },
    database: { files: 1, sha256: "c".repeat(64) },
    document: DOCUMENT,
  });
  return {
    root,
    target,
    targetBytes,
    module,
    reply,
    tool: async (body, name = "python") => {
      const path = join(root, name);
      await writeFile(path, `#!/bin/bash\n${body}\n`, { mode: 0o755 });
      return path;
    },
  };
};

/** Print the authored bridge reply as the scan's only stdout line. */
const printReply = (fixture: Fixture) =>
  `cat <<'REPLY'\n${fixture.reply}\nREPLY`;

interface Run {
  readonly provider: DieSignatureProvider;
  readonly service: FileSignaturesService;
  readonly runtimePaths: string[];
}

const createRun = (
  environment: NodeJS.ProcessEnv,
  options: {
    readonly launcher?: Launcher;
    readonly closeRuntime?: (close: () => Promise<void>) => Promise<void>;
    readonly readLimits?: ConstructorParameters<typeof DieSignatureProvider>[3];
    readonly backends?: readonly FileSignatureBackend[];
  } = {},
): Run => {
  const runtimePaths: string[] = [];
  const provider = new DieSignatureProvider(
    { PATH: process.env.PATH, ...environment },
    options.launcher,
    async () => {
      const root = await PrivateRuntimeRoot.create({
        prefix: "rea-die-lifecycle-root-",
      });
      runtimePaths.push(root.path);
      return {
        path: root.path,
        close: () =>
          options.closeRuntime === undefined
            ? root.close()
            : options.closeRuntime(() => root.close()),
      };
    },
    options.readLimits,
    options.backends,
  );
  const service = new FileSignaturesService(provider);
  onTestFinished(() => provider.close());
  return { provider, service, runtimePaths };
};

const expectReleased = async (run: Run): Promise<void> => {
  expect(run.runtimePaths).toHaveLength(1);
  await expect(access(run.runtimePaths[0] ?? "")).rejects.toMatchObject({
    code: "ENOENT",
  });
};

const failureOf = (
  result: Awaited<ReturnType<FileSignaturesService["inspect"]>>,
): AnalysisError => {
  if (result.ok) throw new Error("Expected a typed DiE failure.");
  return result.error;
};

/** Replace a file by rename so an executable is never written in place. */
const replace = async (
  path: string,
  content: string | Buffer,
): Promise<void> => {
  const next = `${path}.next`;
  await writeFile(next, content, { mode: 0o755 });
  await rename(next, path);
};

/**
 * Act after selection recorded its digests and immediately before the scan
 * process starts. Acting after spawn would let a fast stand-in exit before
 * its supervisor attaches, which the launcher contract does not allow.
 */
const launchAfter =
  (action: () => Promise<void>): Launcher =>
  async (input) => {
    await action();
    return spawnOwnedProviderProcess(input);
  };

type Projection = ReturnType<typeof projectAnalysisError>;

/** Authored stand-in bodies and the typed outcome each must map to. */
const STAND_IN_OUTCOMES = [
  {
    name: "output beyond the 16 MiB budget",
    body: `head -c ${String(DIE_LIMITS.outputBytes + 4096)} /dev/zero | tr '\\0' a`,
    tag: "AnalysisResourceConstraintError",
    check: (projected: Projection) => {
      expect(projected).toMatchObject({
        code: "resource_constraint",
        details: {
          captured_output: { stdout: "a".repeat(4096), truncated: true },
        },
      });
    },
  },
  {
    name: "a real SIGXFSZ from file growth under the zero-byte ceiling",
    body: 'echo data > "$TMPDIR/grown"',
    tag: "AnalysisResourceConstraintError",
    check: (projected: Projection) => {
      expect(projected).toMatchObject({
        code: "resource_constraint",
        details: { captured_output: { signal: "SIGXFSZ" } },
      });
      expect(projected.remediation.action).toContain("memfd_create");
      expect(projected.remediation.action).not.toContain("REA_DIE_COMMAND to");
    },
  },
  {
    name: "an authored SIGXCPU",
    body: "kill -XCPU $$",
    tag: "AnalysisResourceConstraintError",
    check: (projected: Projection) => {
      expect(projected).toMatchObject({
        code: "resource_constraint",
        details: { captured_output: { signal: "SIGXCPU" } },
      });
      expect(projected.remediation.action).toContain("cpu_seconds");
    },
  },
  {
    name: "a nonzero exit",
    body: "echo 'Traceback: authored failure' >&2; exit 3",
    tag: "AnalysisOutputError",
    check: (projected: Projection) => {
      expect(projected.details?.captured_output).toMatchObject({
        stderr: "Traceback: authored failure\n",
        exit_code: 3,
        truncated: false,
      });
    },
  },
  {
    name: "a malformed bridge reply",
    body: `echo 'not a reply'; head -c 10000 /dev/zero | tr '\\0' b`,
    tag: "AnalysisOutputError",
    check: (projected: Projection) => {
      expect(projected.details?.reason).toContain("bridge reply is malformed");
      expect(projected.details?.captured_output).toMatchObject({
        stdout: "not a reply\n" + "b".repeat(4096 - 12),
        stdout_bytes: 10012,
        truncated: true,
      });
    },
  },
];

describe.skipIf(!supported)("DiE stand-in outcomes", () => {
  it("records the limiter, native module and released runtime on success", async () => {
    const fixture = await createFixture();
    const python = await fixture.tool(printReply(fixture));
    const run = createRun({ REA_DIE_PYTHON: python });
    const result = await run.service.inspect({ path: fixture.target });
    if (!result.ok) throw result.error;
    const report = fileSignaturesSchema.parse(result.value.normalized_result);
    const limiter = await realpath("/usr/bin/prlimit");
    expect(report.tool_profile).toMatchObject({
      native_module: {
        path: fixture.module,
        sha256: sha256(await readFile(fixture.module)),
      },
      resource_limiter: {
        configured_path: "/usr/bin/prlimit",
        path: limiter,
        sha256: sha256(await readFile(limiter)),
      },
    });
    expect(report.tool_profile.resource_limiter.arguments).toEqual([
      `--as=${String(report.tool_profile.resource_limits.address_space_bytes)}:${String(report.tool_profile.resource_limits.address_space_bytes)}`,
      "--fsize=0:0",
      `--cpu=${String(report.tool_profile.resource_limits.cpu_seconds)}:${String(report.tool_profile.resource_limits.cpu_seconds)}`,
      "--core=0:0",
      "--",
      python,
    ]);
    expect(report.detections).toEqual([
      expect.objectContaining({ name: "UPX", heuristic: true }),
    ]);
    expect(report.artifact).toEqual({
      path: fixture.target,
      sha256: sha256(fixture.targetBytes),
      bytes: fixture.targetBytes.length,
    });
    expect(result.value.limitations.join(" ")).toContain(
      "not creating empty files or directories",
    );
    await expectReleased(run);
  });

  it.each(STAND_IN_OUTCOMES)("maps $name", async ({ body, tag, check }) => {
    const fixture = await createFixture();
    const run = createRun({ REA_DIE_PYTHON: await fixture.tool(body) });
    const error = failureOf(
      await run.service.inspect({ path: fixture.target }),
    );
    expect(error._tag).toBe(tag);
    check(projectAnalysisError(error));
    await expectReleased(run);
    expect(await readFile(fixture.target)).toEqual(fixture.targetBytes);
  });

  it("reports a real CPU-ceiling SIGKILL without inventing its cause", async () => {
    const fixture = await createFixture();
    const run = createRun(
      { REA_DIE_PYTHON: await fixture.tool("while :; do :; done") },
      {
        readLimits: async (configured, resources) => ({
          ...(await readLinuxResourceLimits(configured, resources)),
          cpu_seconds: 1,
        }),
      },
    );
    const error = failureOf(
      await run.service.inspect({ path: fixture.target }),
    );
    const projected = projectAnalysisError(error);
    // Linux sends SIGKILL, not SIGXCPU, when soft and hard CPU limits are equal.
    expect(projected).toMatchObject({
      code: "unreadable_output",
      details: { captured_output: { signal: "SIGKILL" } },
    });
    expect(projected.remediation.action).toContain("CPU-second ceiling");
    expect(projected.remediation.action).toContain("not established");
    await expectReleased(run);
  });
});

describe.skipIf(!supported)("DiE integrity and process ownership", () => {
  it("refuses a snapshot the tool truncated as a changed artifact", async () => {
    const fixture = await createFixture();
    const python = await fixture.tool(
      `f="$TMPDIR/target/sample.bin"; chmod u+w "$f"; : > "$f"\n${printReply(fixture)}`,
    );
    const run = createRun({ REA_DIE_PYTHON: python });
    const error = failureOf(
      await run.service.inspect({ path: fixture.target }),
    );
    expect(error).toMatchObject({
      _tag: "AnalysisArtifactChangedError",
      path: fixture.target,
      reason: expect.stringContaining("snapshot changed"),
    });
    expect(await readFile(fixture.target)).toEqual(fixture.targetBytes);
    await expectReleased(run);
  });

  it.each(["executable", "limiter", "native module"] as const)(
    "refuses a scan whose %s changed while it ran",
    async (changed) => {
      const fixture = await createFixture();
      const python = await fixture.tool(printReply(fixture));
      const limiter = join(fixture.root, "prlimit");
      await copyFile("/usr/bin/prlimit", limiter);
      await chmod(limiter, 0o755);
      const path =
        changed === "executable"
          ? python
          : changed === "limiter"
            ? limiter
            : fixture.module;
      const run = createRun(
        { REA_DIE_PYTHON: python, REA_DIE_PRLIMIT_COMMAND: limiter },
        {
          // Each replacement still completes the scan, so only identity fails.
          launcher: launchAfter(async () =>
            replace(
              path,
              changed === "executable"
                ? `#!/bin/bash\n# authored replacement\n${printReply(fixture)}`
                : changed === "limiter"
                  ? Buffer.concat([await readFile(limiter), Buffer.of(0)])
                  : "authored replacement module",
            ),
          ),
        },
      );
      const error = failureOf(
        await run.service.inspect({ path: fixture.target }),
      );
      expect(error).toMatchObject({
        _tag: "AnalysisOutputError",
        reason: expect.stringContaining(`changed during the scan: ${path}`),
        capturedOutput: { stdout: `${fixture.reply}\n`, exit_code: 0 },
      });
      await expectReleased(run);
    },
  );

  it("refuses unreadable inherited limits without blaming DiE configuration", async () => {
    const fixture = await createFixture();
    const run = createRun(
      { REA_DIE_PYTHON: await fixture.tool(printReply(fixture)) },
      {
        readLimits: () =>
          Promise.reject(
            Object.assign(new Error("authored procfs denial"), {
              code: "EACCES",
            }),
          ),
      },
    );
    const error = failureOf(
      await run.service.inspect({ path: fixture.target }),
    );
    const projected = projectAnalysisError(error);
    expect(projected).toMatchObject({ code: "capability_unavailable" });
    expect(projected.message).toContain("/proc/self/limits");
    expect(projected.remediation.action).toContain("procfs");
    expect(projected.remediation.action).not.toContain("REA_DIE_PYTHON");
    expect(run.runtimePaths).toEqual([]);
  });

  it("sweeps a setsid descendant that outlives the scan", async () => {
    const fixture = await createFixture();
    const markers = join(fixture.root, "markers");
    const python = await fixture.tool(
      [
        `mkdir -p '${markers}'`,
        // The zero-byte file ceiling still allows an empty marker file.
        `setsid bash -c 'touch "${markers}/$$"; exec sleep 60' </dev/null >/dev/null 2>&1 &`,
        `until [ -n "$(ls '${markers}')" ]; do sleep 0.02; done`,
        printReply(fixture),
      ].join("\n"),
    );
    const run = createRun({ REA_DIE_PYTHON: python });
    const result = await run.service.inspect({ path: fixture.target });
    if (!result.ok) throw result.error;
    const [marker] = await readdir(markers);
    const pid = Number(marker);
    expect(Number.isSafeInteger(pid) && pid > 1).toBe(true);
    let alive = true;
    const deadline = Date.now() + 2_000;
    while (alive && Date.now() < deadline) {
      try {
        process.kill(pid, 0);
        await delay(25);
      } catch {
        alive = false;
      }
    }
    if (alive) process.kill(pid, "SIGKILL");
    expect(alive).toBe(false);
    await expectReleased(run);
  });

  it("returns typed cancellation with the caller's reason during a scan", async () => {
    const fixture = await createFixture();
    const controller = new AbortController();
    const reason = { authored: "cancel during scan" };
    const run = createRun(
      { REA_DIE_PYTHON: await fixture.tool("sleep 30") },
      {
        launcher: launchAfter(async () => {
          setTimeout(() => controller.abort(reason), 50);
        }),
      },
    );
    const error = failureOf(
      await run.service.inspect(
        { path: fixture.target },
        { signal: controller.signal },
      ),
    );
    expect(error._tag).toBe("AnalysisCancelledError");
    expect(error.cause).toBe(reason);
    await expectReleased(run);
  });
});

/**
 * REA's reads after the stand-in exits, in order, with the opens of the same
 * path that tool selection or snapshot staging made before the scan.
 */
const POST_SCAN_READS = [
  { read: "private snapshot", earlier: 0 },
  { read: "configured DiE executable", earlier: 1 },
  { read: "resource limiter", earlier: 1 },
  { read: "die-python native scanner module", earlier: 0 },
  { read: "selected file", earlier: 1 },
] as const;

/**
 * Arm the fault for the post-scan open of one read and return its exact path.
 * The snapshot path exists only once the provider created its runtime root.
 */
const armPostScanRead = async (
  fixture: Fixture,
  run: Run,
  { read, earlier }: (typeof POST_SCAN_READS)[number],
): Promise<() => string> => {
  const known =
    read === "configured DiE executable"
      ? await realpath(join(fixture.root, "python"))
      : read === "resource limiter"
        ? await realpath("/usr/bin/prlimit")
        : read === "die-python native scanner module"
          ? fixture.module
          : read === "selected file"
            ? fixture.target
            : undefined;
  const path = () =>
    known ?? join(run.runtimePaths[0] ?? "", "target", "sample.bin");
  fault.skip = earlier;
  fault.matches = (opened) => opened === path();
  return path;
};

describe.skipIf(!supported)("DiE post-scan result reads", () => {
  it.each(POST_SCAN_READS)(
    "returns typed cancellation when the caller aborts while REA reads the $read",
    async (entry) => {
      const fixture = await createFixture();
      const controller = new AbortController();
      const reason = { authored: `cancel during ${entry.read} read` };
      let launches = 0;
      let launchesAtFault: number | undefined;
      const run = createRun(
        { REA_DIE_PYTHON: await fixture.tool(printReply(fixture)) },
        {
          launcher: launchAfter(async () => {
            launches += 1;
          }),
        },
      );
      await armPostScanRead(fixture, run, entry);
      fault.onStat = () => {
        launchesAtFault = launches;
        controller.abort(reason);
      };
      const error = failureOf(
        await run.service.inspect(
          { path: fixture.target },
          { signal: controller.signal },
        ),
      );
      // The only command is the scan, so the abort landed after it ran.
      expect(launchesAtFault).toBe(1);
      expect(fault.handles).toHaveLength(1);
      expect(error).toMatchObject({
        _tag: "AnalysisCancelledError",
        cleanupIncomplete: false,
      });
      expect(error.cause).toBe(reason);
      expect(fault.handles.every((handle) => handle.fd === -1)).toBe(true);
      await expectReleased(run);
    },
  );

  it.each(POST_SCAN_READS)(
    "retains the $read descriptor whose post-scan close failed, then releases it on close",
    async (entry) => {
      const fixture = await createFixture();
      let launches = 0;
      let launchesAtFault: number | undefined;
      const run = createRun(
        { REA_DIE_PYTHON: await fixture.tool(printReply(fixture)) },
        {
          launcher: launchAfter(async () => {
            launches += 1;
          }),
        },
      );
      const path = await armPostScanRead(fixture, run, entry);
      fault.onStat = () => {
        launchesAtFault = launches;
      };
      fault.denyFirstClose = true;
      const error = failureOf(
        await run.service.inspect({ path: fixture.target }),
      );
      expect(launchesAtFault).toBe(1);
      expect(fault.handles).toHaveLength(1);
      expect(error).toMatchObject({
        cleanupIncomplete: true,
        cleanupResources: [path()],
      });
      expect(projectAnalysisError(error)).toMatchObject({
        code: "cleanup_incomplete",
      });
      expect(fault.handles[0]?.fd).not.toBe(-1);
      await expectReleased(run);
      await run.service.close();
      expect(fault.handles[0]?.fd).toBe(-1);
      expect(error).toMatchObject({
        cleanupIncomplete: false,
        cleanupResources: [],
      });
    },
  );
});

describe.skipIf(!supported)("DiE runtime-root finalization", () => {
  it("retains completed detections when root removal fails, then releases it on close", async () => {
    const fixture = await createFixture();
    let attempts = 0;
    const run = createRun(
      { REA_DIE_PYTHON: await fixture.tool(printReply(fixture)) },
      {
        closeRuntime: async (close) => {
          attempts += 1;
          if (attempts === 1) throw new Error("authored root removal denial");
          await close();
        },
      },
    );
    const error = failureOf(
      await run.service.inspect({ path: fixture.target }),
    );
    const runtimePath = run.runtimePaths[0] ?? "";
    expect(error).toMatchObject({
      _tag: "ProviderAdapterError",
      cleanupIncomplete: true,
      cleanupResources: [runtimePath],
      partialObservation: {
        normalized_result: {
          detections: [expect.objectContaining({ name: "UPX" })],
        },
      },
    });
    await expect(access(runtimePath)).resolves.toBeUndefined();
    await run.service.close();
    expect(attempts).toBe(2);
    await expectReleased(run);
    expect(error).toMatchObject({
      cleanupIncomplete: false,
      cleanupResources: [],
    });
  });

  it("returns typed cancellation with detections when cancelled during root removal", async () => {
    const fixture = await createFixture();
    const controller = new AbortController();
    const reason = { authored: "abort during final cleanup" };
    const run = createRun(
      { REA_DIE_PYTHON: await fixture.tool(printReply(fixture)) },
      {
        closeRuntime: async (close) => {
          controller.abort(reason);
          await close();
        },
      },
    );
    const error = failureOf(
      await run.service.inspect(
        { path: fixture.target },
        { signal: controller.signal },
      ),
    );
    expect(error).toMatchObject({
      _tag: "AnalysisCancelledError",
      cleanupIncomplete: false,
      partialObservation: {
        normalized_result: {
          detections: [expect.objectContaining({ name: "UPX" })],
        },
      },
    });
    expect(error.cause).toBe(reason);
    await expectReleased(run);
  });

  it("keeps the cancellation primary when root removal also fails, then retries", async () => {
    const fixture = await createFixture();
    const controller = new AbortController();
    const reason = { authored: "abort before failed removal" };
    let attempts = 0;
    const run = createRun(
      { REA_DIE_PYTHON: await fixture.tool(printReply(fixture)) },
      {
        closeRuntime: async (close) => {
          controller.abort(reason);
          attempts += 1;
          if (attempts === 1) throw new Error("authored root removal denial");
          await close();
        },
      },
    );
    const error = failureOf(
      await run.service.inspect(
        { path: fixture.target },
        { signal: controller.signal },
      ),
    );
    const runtimePath = run.runtimePaths[0] ?? "";
    expect(error).toMatchObject({
      cleanupIncomplete: true,
      cleanupResources: [runtimePath],
      partialObservation: {
        normalized_result: {
          detections: [expect.objectContaining({ name: "UPX" })],
        },
      },
    });
    expect(projectAnalysisError(error)).toMatchObject({
      code: "cleanup_incomplete",
    });
    expect(error.cleanupPrimary?.cause).toBe(reason);
    await run.service.close();
    expect(attempts).toBe(2);
    await expectReleased(run);
    expect(error.cleanupIncomplete).toBe(false);
  });
});

describe.skipIf(!supported)(
  "unverified diec through the source-owned seam",
  () => {
    const banner =
      'if [ "$1" = "--version" ]; then echo "diec 3.09"; exit 0; fi';

    it("maps a nonzero diec exit to retained output, not configuration", async () => {
      const fixture = await createFixture();
      const diec = await fixture.tool(
        `${banner}\necho "Cannot open file"; exit 2`,
        "diec",
      );
      const run = createRun(
        { REA_DIE_COMMAND: diec },
        { backends: ["diec", "die-python"] },
      );
      const error = failureOf(
        await run.service.inspect({ path: fixture.target }),
      );
      const projected = projectAnalysisError(error);
      expect(projected).toMatchObject({
        code: "unreadable_output",
        details: {
          reason: "diec exited with status 2.",
          captured_output: { stdout: "Cannot open file\n", exit_code: 2 },
        },
      });
      expect(projected.remediation.action).toContain("signature database");
      expect(projected.remediation.action).not.toContain("REA_DIE_COMMAND");
      await expectReleased(run);
    });

    it("refuses a leading bare document instead of returning zero detections", async () => {
      const fixture = await createFixture();
      const indented = JSON.stringify(JSON.parse(DOCUMENT), null, 4);
      const diec = await fixture.tool(
        `${banner}\nprintf '{\\n"detects": []\\n}\\n'\ncat <<'DOC'\n${indented}\nDOC`,
        "diec",
      );
      const run = createRun(
        { REA_DIE_COMMAND: diec },
        { backends: ["diec", "die-python"] },
      );
      const error = failureOf(
        await run.service.inspect({ path: fixture.target }),
      );
      expect(error).toMatchObject({
        _tag: "AnalysisOutputError",
        reason: expect.stringContaining("exactly one indented JSON result"),
      });
      await expectReleased(run);
    });
  },
);
