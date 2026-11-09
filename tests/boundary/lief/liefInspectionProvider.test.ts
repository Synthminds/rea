import { createHash } from "node:crypto";
import {
  access,
  lstat,
  open,
  readFile,
  rename,
  symlink,
  writeFile,
  type FileHandle,
} from "node:fs/promises";
import { basename, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { expect, it } from "vitest";

import { LiefInspectionService } from "../../../src/application/lief/LiefInspectionService.js";
import {
  digestStableArtifact,
  readStableArtifact,
  type StableArtifactFileSystem,
} from "../../../src/artifacts/readStableArtifact.js";
import type { AnalysisError } from "../../../src/domain/analysisErrorBase.js";
import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { liefInspectionSchema } from "../../../src/domain/lief/liefInspection.js";
import { LiefInspectionProvider } from "../../../src/lief/LiefInspectionProvider.js";
import { LIEF_LIMITS } from "../../../src/lief/LiefRelease.js";
import { cleanupOwnedProcessGroup } from "../../../src/process/ProcessOwnership.js";
import { PrivateRuntimeRoot } from "../../../src/process/PrivateRuntimeRoot.js";
import { spawnOwnedProviderProcess } from "../../../src/process/ProviderProcess.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const ELF = Buffer.from("7f454c4602010100", "hex");
const sha256 = (bytes: Buffer | string) =>
  createHash("sha256").update(bytes).digest("hex");

const summary = {
  architecture: "X86_64",
  bits: 64,
  endianness: "little",
  object_type: "EXECUTABLE",
  entrypoint: "0x1040",
  imagebase: "0x0",
  counts: {
    sections: 3,
    segments: 2,
    imports: 1,
    exports: 0,
    libraries: 1,
    rpaths: 0,
    load_commands: null,
  },
  libraries: ["libc.so.6"],
  elf: {
    file_type: "DYN",
    machine: "X86_64",
    class: "ELF64",
    data: "LSB",
    os_abi: "SYSTEMV",
    header_entrypoint: "0x1040",
    interpreter: "/lib64/ld-linux-x86-64.so.2",
    soname: null,
    rpath: null,
    runpath: null,
  },
  pe: null,
  macho: null,
  truncated_lists: [],
  unread_fields: [],
};

const LIMITS = {
  address_space_bytes: 4294967296,
  file_size_bytes: 34603008,
  core_file_bytes: 0,
};

/** A successful helper value; the producer adds the authored native module identity. */
const value = (overrides: Record<string, unknown> = {}) => ({
  lief_version: "1.0.0-test",
  python_version: "3.13.0",
  format: "elf",
  macho: null,
  summary,
  page: null,
  resource_limits: LIMITS,
  ...overrides,
});

const refusal = (fields: Record<string, unknown>) => ({
  ok: false,
  message_bytes: Buffer.byteLength(String(fields.message ?? "")),
  resource_limits: LIMITS,
  ...fields,
});

const row = (index: number) => ({
  name: `symbol_${String(index)}`,
  library: null,
  ordinal: null,
  address: null,
  kind: "FUNC",
  binding: "GLOBAL",
  version: "GLIBC_2.2.5",
  forwarder: null,
});

/**
 * A producer speaking the helper's reply protocol in place of Python+LIEF.
 * `body` runs with `request` (the parsed request), `selected` (the original
 * path, which the real helper never receives), `python` (the authored
 * interpreter file REA digests), `native` (the authored native-module
 * identity) and `reply(value)` in scope.
 */
const producer = (body: string): string => `
const fs = require("node:fs");
const request = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const selected = process.argv[2];
const native = { path: process.argv[3], sha256: process.argv[4] };
const python = process.argv[5];
const reply = (value) => {
  if (value.ok === true && value.value.native_module === undefined) value.value.native_module = native;
  fs.writeFileSync(request.reply_path, JSON.stringify(value), { flag: "wx" });
};
${body}
`;

type RuntimeRoot = Awaited<ReturnType<typeof PrivateRuntimeRoot.create>>;
type Spawned = Awaited<ReturnType<typeof spawnOwnedProviderProcess>>;

const harness = async (
  body: string,
  options: {
    readonly platform?: NodeJS.Platform;
    /** Wrap the owned private root, for example to control its removal. */
    readonly runtime?: (
      root: RuntimeRoot,
    ) => Pick<RuntimeRoot, "path" | "close">;
    readonly onSpawn?: (process: { readonly pid?: number | undefined }) => void;
    /** Wrap the spawned process, for example to deny its group cleanup. */
    readonly spawned?: (spawned: Spawned) => Spawned;
    readonly readArtifact?: (
      real: typeof readStableArtifact,
    ) => typeof readStableArtifact;
    readonly digestArtifact?: (
      real: typeof digestStableArtifact,
    ) => typeof digestStableArtifact;
  } = {},
) => {
  const directory = await createTestTempDirectory("rea-lief-provider-");
  const path = join(directory, "selected.elf");
  const bytes = Buffer.concat([ELF, Buffer.alloc(56, 1)]);
  await writeFile(path, bytes);
  // Authored stand-ins REA digests: the configured interpreter and the native module.
  const python = join(directory, "python");
  await writeFile(python, "#!/bin/sh\nexit 97\n", { mode: 0o755 });
  const native = join(directory, "_lief.so");
  const nativeBytes = Buffer.from("authored native LIEF module stand-in");
  await writeFile(native, nativeBytes);
  const observed: {
    cwd: string | undefined;
    arguments: readonly string[] | undefined;
    sweep: boolean | undefined;
    roots: string[];
  } = { cwd: undefined, arguments: undefined, sweep: undefined, roots: [] };
  const provider = new LiefInspectionProvider(
    { REA_LIEF_PYTHON: python },
    {
      platform: options.platform ?? "linux",
      arch: "x64",
      createRuntime: async () => {
        const root = await PrivateRuntimeRoot.create({
          prefix: "rea-lief-test-",
        });
        observed.roots.push(root.path);
        return options.runtime?.(root) ?? root;
      },
      launcher: async (spawn) => {
        observed.cwd = spawn.cwd;
        observed.arguments = spawn.arguments;
        observed.sweep = spawn.sweepTokenOwnedProcesses;
        const spawned = await spawnOwnedProviderProcess({
          ...spawn,
          command: process.execPath,
          arguments: [
            "-e",
            producer(body),
            spawn.arguments.at(-1) ?? "",
            path,
            native,
            sha256(nativeBytes),
            python,
          ],
        });
        options.onSpawn?.(spawned.process);
        return options.spawned?.(spawned) ?? spawned;
      },
      ...(options.readArtifact === undefined
        ? {}
        : { readArtifact: options.readArtifact(readStableArtifact) }),
      ...(options.digestArtifact === undefined
        ? {}
        : { digestArtifact: options.digestArtifact(digestStableArtifact) }),
    },
  );
  const service = new LiefInspectionService(provider);
  const exists = async (candidate: string) => {
    try {
      await access(candidate);
      return true;
    } catch {
      return false;
    }
  };
  return {
    directory,
    path,
    python,
    native,
    sha256: sha256(bytes),
    observed,
    service,
    provider,
    exists,
    async rootRemoved() {
      for (const root of observed.roots) if (await exists(root)) return false;
      return true;
    },
  };
};

const failure = async (
  result: Awaited<ReturnType<LiefInspectionService["inspect"]>>,
) => {
  if (result.ok) throw new Error("Expected a typed failure");
  return projectAnalysisError(result.error);
};

const reportOf = (
  result: Awaited<ReturnType<LiefInspectionService["inspect"]>>,
) => {
  if (!result.ok) throw result.error;
  return liefInspectionSchema.parse(
    parseEvidence(result.value).normalized_result,
  );
};

/** Group cleanup denied while `gate.deny` holds, then the real owned-group cleanup. */
const deniedCleanup =
  (gate: { deny: boolean }) =>
  (spawned: Spawned): Spawned => ({
    ...spawned,
    cleanup: async () =>
      gate.deny
        ? { cleaned: false, reason: "authored group cleanup denial" }
        : cleanupOwnedProcessGroup(spawned.ownership),
  });

// The controlled producer relies on POSIX process groups and file modes.
const posix = it.runIf(process.platform !== "win32");

posix(
  "binds a summary to the private copy, interpreter and native module identities and removes the copy",
  async () => {
    const fixture = await harness(
      `process.stderr.write("LIEF warning\\n"); reply({ ok: true, value: ${JSON.stringify(value())} });`,
    );
    const result = await fixture.service.inspect({ path: fixture.path });
    if (!result.ok) throw result.error;
    const evidence = parseEvidence(result.value);
    const report = liefInspectionSchema.parse(evidence.normalized_result);
    expect(evidence.subject).toMatchObject({
      format: "elf",
      digest: { sha256: fixture.sha256 },
    });
    expect(evidence.provider.version).toBe("lief@1.0.0-test");
    expect(report).toMatchObject({
      artifact: { path: fixture.path, sha256: fixture.sha256, bytes: 64 },
      artifact_after: { sha256: fixture.sha256, changed: false },
      operation: "summary",
      coverage: { applicable: true, parser_diagnostics: "reported" },
      diagnostics: {
        detail: "summary",
        stderr: {
          bytes: 13,
          lines: 1,
          distinct_lines: 1,
          sha256: sha256("LIEF warning\n"),
          excerpt: [{ line: "LIEF warning", count: 1, truncated: false }],
          excerpt_complete: true,
          text: null,
        },
        capture_truncated: false,
      },
      provider: {
        admitted_release: "1.0",
        python_executable: fixture.python,
        python: {
          path: fixture.python,
          sha256: sha256(await readFile(fixture.python)),
        },
        native_module: {
          path: fixture.native,
          sha256: sha256(await readFile(fixture.native)),
        },
      },
    });
    expect(report.limitations.join("\n")).toContain(
      "never received the original path",
    );
    expect(report.limitations.join("\n")).toContain("diagnostics: complete");
    // Isolated interpreter, packaged helper, a request inside the private root,
    // and a token sweep for descendants that leave the process group.
    expect(fixture.observed.arguments?.slice(0, 2)).toEqual(["-I", "-B"]);
    expect(fixture.observed.arguments?.[2]).toMatch(
      /bridge[\\/]lief[\\/]inspect\.py$/u,
    );
    expect(fixture.observed.arguments?.[3]).toBe(
      join(fixture.observed.cwd ?? "", "request.json"),
    );
    expect(fixture.observed.sweep).toBe(true);
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix(
  "summarizes repeated diagnostics within the excerpt budget and returns the complete text on request",
  async () => {
    // 3000 repeats of one warning plus 200 distinct, file-controlled lines.
    const fixture = await harness(`
      let text = "";
      for (let index = 0; index < 3000; index++) text += "LIEF: repeated warning\\n";
      for (let index = 0; index < 200; index++) text += "LIEF: section " + "x".repeat(40) + index + " is malformed\\n";
      process.stderr.write(text, () => reply({ ok: true, value: { ...${JSON.stringify(value({ summary: null }))}, page: { applicable: true, total: 0, items: [] } } }));
    `);
    const summarized = reportOf(
      await fixture.service.inspect({
        path: fixture.path,
        operation: "sections",
        limit: 1,
      }),
    );
    const stderr = summarized.diagnostics.stderr;
    expect(stderr).toMatchObject({
      lines: 3200,
      distinct_lines: 201,
      excerpt_complete: false,
      text: null,
    });
    expect(stderr.excerpt[0]).toEqual({
      line: "LIEF: repeated warning",
      count: 3000,
      truncated: false,
    });
    expect(
      stderr.excerpt.reduce(
        (total, entry) => total + Buffer.byteLength(entry.line),
        0,
      ),
    ).toBeLessThanOrEqual(LIEF_LIMITS.diagnosticExcerptBytes);
    // The whole report stays small although stderr was about 80 KB.
    expect(stderr.bytes).toBeGreaterThan(80_000);
    expect(JSON.stringify(summarized).length).toBeLessThan(12_000);
    const complete = reportOf(
      await fixture.service.inspect({
        path: fixture.path,
        operation: "sections",
        limit: 1,
        diagnostics: "complete",
      }),
    );
    expect(complete.diagnostics.stderr.text).toHaveLength(stderr.bytes);
    expect(sha256(complete.diagnostics.stderr.text ?? "")).toBe(stderr.sha256);
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix(
  "pages list facets with a default limit of 64 and rejects inconsistent pages",
  async () => {
    const fixture = await harness(`
      const items = Array.from({ length: 100 }, (_, index) => (${row.toString()})(index + 1));
      const window = request.limit === 9 ? items : items.slice(request.offset, request.offset + request.limit);
      reply({ ok: true, value: { ...${JSON.stringify(value({ summary: null }))}, page: { applicable: true, total: items.length, items: window } } });
    `);
    const page = reportOf(
      await fixture.service.inspect({
        path: fixture.path,
        operation: "imports",
        offset: 1,
        limit: 2,
      }),
    );
    expect(page.imports).toMatchObject({
      offset: 1,
      limit: 2,
      total: 100,
      returned: 2,
      next_offset: 3,
      items: [{ name: "symbol_2" }, { name: "symbol_3" }],
    });
    const defaulted = reportOf(
      await fixture.service.inspect({
        path: fixture.path,
        operation: "imports",
      }),
    );
    expect(defaulted.imports).toMatchObject({
      offset: 0,
      limit: 64,
      returned: 64,
      next_offset: 64,
    });
    // A producer that ignores the window must not be reported as a page.
    expect(
      await failure(
        await fixture.service.inspect({
          path: fixture.path,
          operation: "imports",
          offset: 4,
          limit: 9,
        }),
      ),
    ).toMatchObject({ code: "unreadable_output" });
  },
);

posix(
  "returns non-UTF-8 names as exact bytes and pages the new library, rpath and load-command facets",
  async () => {
    const fixture = await harness(`
      const rows = {
        libraries: [{ name: { text: null, bytes_hex: "ff696273" }, kind: "NEEDED", current_version: null, compatibility_version: null }],
        rpaths: [{ path: "$ORIGIN", kind: "RUNPATH" }],
        load_commands: [],
      }[request.operation];
      reply({ ok: true, value: { ...${JSON.stringify(value({ summary: null }))}, page: { applicable: request.operation !== "load_commands", total: rows.length, items: rows } } });
    `);
    const libraries = reportOf(
      await fixture.service.inspect({
        path: fixture.path,
        operation: "libraries",
      }),
    );
    expect(libraries.libraries?.items).toEqual([
      {
        name: { text: null, bytes_hex: "ff696273" },
        kind: "NEEDED",
        current_version: null,
        compatibility_version: null,
      },
    ]);
    expect(libraries.limitations.join("\n")).toContain("bytes_hex");
    expect(
      reportOf(
        await fixture.service.inspect({
          path: fixture.path,
          operation: "rpaths",
        }),
      ).rpaths?.items,
    ).toEqual([{ path: "$ORIGIN", kind: "RUNPATH" }]);
    const commands = reportOf(
      await fixture.service.inspect({
        path: fixture.path,
        operation: "load_commands",
      }),
    );
    expect(commands.coverage.applicable).toBe(false);
    expect(commands.limitations.join("\n")).toContain("not applicable to ELF");
  },
);

posix.each([
  [
    {
      reason: "version",
      message: "LIEF 0.17.6 is not admitted",
      observed_version: "0.17.6",
    },
    {
      code: "capability_unavailable",
      details: {
        diagnostics: {
          observed_version: "0.17.6",
          configuration_key: "REA_LIEF_PYTHON",
        },
      },
    },
  ],
  [
    { reason: "unsupported-format", message: "not ELF, PE or Mach-O" },
    { code: "unsupported_target" },
  ],
  [
    { reason: "invalid-slice", message: "outside", slice_count: 2 },
    {
      code: "invalid_request",
      details: {
        issues: [{ path: ["macho_slice"], reason: "out_of_range", maximum: 1 }],
      },
    },
  ],
  [
    { reason: "output-limit", message: "too large", reply_bytes: 40000000 },
    {
      code: "resource_constraint",
      retryable: false,
      details: {
        reported_limits: {
          required_bytes: 40000000,
          file_size_bytes: 34603008,
        },
      },
    },
  ],
  [
    {
      reason: "resource-limit",
      message: "memory",
      resource_limits: { ...LIMITS, address_space_bytes: 1073741824 },
    },
    {
      code: "resource_constraint",
      details: {
        reported_limits: {
          address_space_bytes: 1073741824,
          requested_address_space_bytes: 4294967296,
        },
      },
    },
  ],
  [
    { reason: "malformed", message: "unreadable ELF class" },
    {
      code: "invalid_request",
      details: { issues: [{ path: ["path"], reason: "invalid_format" }] },
    },
  ],
  [
    { reason: "not-applicable", message: "Mach-O only" },
    {
      code: "invalid_request",
      details: { issues: [{ path: ["macho_slice"], reason: "invalid_value" }] },
    },
  ],
  [
    { reason: "decoder", message: "AttributeError: no such field" },
    {
      code: "execution_failure",
      details: {
        diagnostics: {
          stage: "lief-parse",
          reason: "AttributeError: no such field",
          resource_limits: LIMITS,
        },
      },
    },
  ],
])(
  "projects the %o refusal without partial structure",
  async (fields, expected) => {
    const fixture = await harness(`reply(${JSON.stringify(refusal(fields))});`);
    const projected = await failure(
      await fixture.service.inspect({ path: fixture.path }),
    );
    expect(projected).toMatchObject(expected);
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix(
  "bounds a long refusal message to an excerpt that names its full size",
  async () => {
    const message = `ValueError: ${"é".repeat(30_000)}`;
    const fixture = await harness(
      `reply(${JSON.stringify(refusal({ reason: "decoder", message }))});`,
    );
    const projected = await failure(
      await fixture.service.inspect({ path: fixture.path }),
    );
    const reason = String(
      (projected.details as { diagnostics: { reason: string } }).diagnostics
        .reason,
    );
    expect(Buffer.byteLength(reason)).toBeLessThan(
      LIEF_LIMITS.messageBytes + 100,
    );
    expect(reason).toContain(
      `excerpt of a ${String(Buffer.byteLength(message))}-byte message`,
    );
    expect(projected.message.length).toBeLessThan(2_000);
  },
);

posix(
  "rejects observations when the helper changes its private copy",
  async () => {
    const fixture = await harness(`
      fs.chmodSync(request.snapshot_path, 0o600);
      fs.appendFileSync(request.snapshot_path, "patched");
      reply({ ok: true, value: ${JSON.stringify(value())} });
    `);
    const projected = await failure(
      await fixture.service.inspect({ path: fixture.path }),
    );
    expect(projected.code).toBe("unreadable_output");
    expect(projected.message).toContain("private read-only copy");
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix.each([
  [
    "configured Python interpreter",
    `fs.appendFileSync(python, "# changed\\n");`,
  ],
  ["native LIEF module", `fs.appendFileSync(native.path, "changed");`],
])(
  "rejects a reply when the %s changes during the run",
  async (label, change) => {
    const fixture = await harness(
      `${change} reply({ ok: true, value: ${JSON.stringify(value())} });`,
    );
    const projected = await failure(
      await fixture.service.inspect({ path: fixture.path }),
    );
    expect(projected.code).toBe("unreadable_output");
    expect(projected.message).toContain(`The ${label} changed during`);
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix(
  "reports a helper deadline with command_timeout_ms recovery and stops the owned process",
  async () => {
    const fixture = await harness("setInterval(() => {}, 1000);");
    const projected = await failure(
      await fixture.service.inspect({
        path: fixture.path,
        command_timeout_ms: 300,
      }),
    );
    expect(projected).toMatchObject({ code: "provider_timeout" });
    expect(projected.remediation.action).toContain(
      "Increase command_timeout_ms above 300",
    );
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix.each([
  ["a signal", `process.kill(process.pid, "SIGSEGV");`, "SIGSEGV"],
  [
    "a malformed reply",
    `fs.writeFileSync(request.reply_path, "{");`,
    "reply could not be read",
  ],
  [
    "a nonzero exit without a signal",
    `process.stderr.write("Traceback: authored failure\\n"); process.exit(3);`,
    "Traceback: authored failure",
  ],
  ["exit 0 without a reply", `process.exit(0);`, "reply could not be read"],
  [
    "an oversized reply",
    `fs.writeFileSync(request.reply_path, ""); fs.truncateSync(request.reply_path, ${String(LIEF_LIMITS.replyBytes + 1)});`,
    "reply could not be read",
  ],
  [
    "a symlinked reply",
    `fs.writeFileSync(request.reply_path + ".real", JSON.stringify({ ok: true, value: ${JSON.stringify(value())} })); fs.symlinkSync(request.reply_path + ".real", request.reply_path);`,
    "reply could not be read",
  ],
])(
  "fails without partial success when the helper ends with %s",
  async (_case, body, message) => {
    const fixture = await harness(body);
    const projected = await failure(
      await fixture.service.inspect({ path: fixture.path }),
    );
    expect(projected.code).toBe("unreadable_output");
    expect(JSON.stringify(projected)).toContain(message);
    expect(projected.details).not.toHaveProperty("partial_observation");
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix(
  "refuses diagnostics past the 4 MiB budget with a bounded excerpt and the stream's size",
  async () => {
    const fixture = await harness(`
      const line = "LIEF warning: " + "w".repeat(1000) + "\\n";
      let written = 0;
      const pump = () => {
        while (written < ${String(LIEF_LIMITS.diagnosticBytes + 1024 * 1024)}) {
          written += line.length;
          if (!process.stderr.write(line)) return process.stderr.once("drain", pump);
        }
        reply({ ok: true, value: ${JSON.stringify(value())} });
      };
      pump();
    `);
    const projected = await failure(
      await fixture.service.inspect({ path: fixture.path }),
    );
    expect(projected.code).toBe("resource_constraint");
    const captured = (
      projected.details as {
        captured_output: { stderr: string; truncated: boolean };
      }
    ).captured_output;
    expect(captured.truncated).toBe(true);
    expect(Buffer.byteLength(captured.stderr)).toBeLessThan(
      2 * LIEF_LIMITS.failureOutputBytes + 200,
    );
    expect(captured.stderr).toContain("REA omitted");
    expect(JSON.stringify(projected).length).toBeLessThan(20_000);
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix(
  "returns typed cancellation once the helper is running and stops its process",
  async () => {
    const controller = new AbortController();
    const reason = new Error("caller stopped");
    let pid: number | undefined;
    const fixture = await harness("setInterval(() => {}, 1000);", {
      // Abort only after the owned helper exists, so the run phase is covered.
      onSpawn: (child) => {
        pid = child.pid;
        controller.abort(reason);
      },
    });
    const result = await fixture.service.inspect(
      { path: fixture.path },
      { signal: controller.signal },
    );
    if (result.ok) throw new Error("Expected cancellation");
    expect(result.error._tag).toBe("AnalysisCancelledError");
    expect(result.error.cause).toBe(reason);
    expect(pid).toBeTypeOf("number");
    expect(() => process.kill(pid ?? 0, 0)).toThrow(
      expect.objectContaining({ code: "ESRCH" }),
    );
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix(
  "returns typed cancellation when the caller aborts while REA reads the completed reply",
  async () => {
    const controller = new AbortController();
    const reason = { authored: "cancel during result read" };
    const fixture = await harness(
      `process.stderr.write("LIEF warning\\n"); reply({ ok: true, value: ${JSON.stringify(value())} });`,
      {
        readArtifact:
          (real) =>
          (path, ...rest) => {
            if (path.endsWith("reply.json")) controller.abort(reason);
            return real(path, ...rest);
          },
      },
    );
    const result = await fixture.service.inspect(
      { path: fixture.path },
      { signal: controller.signal },
    );
    if (result.ok) throw new Error("Expected cancellation");
    expect(result.error._tag).toBe("AnalysisCancelledError");
    expect(result.error.cause).toBe(reason);
    // The completed helper's output is retained on the typed cancellation.
    expect(result.error.capturedOutput?.stderr).toBe("LIEF warning\n");
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix(
  "returns typed cancellation when the caller aborts while REA stages the private copy",
  async () => {
    const controller = new AbortController();
    const fixture = await harness("process.exit(9);", {
      runtime: (root) => {
        controller.abort(new Error("caller stopped"));
        return root;
      },
    });
    const projected = await failure(
      await fixture.service.inspect(
        { path: fixture.path },
        { signal: controller.signal },
      ),
    );
    expect(projected).toMatchObject({ code: "cancelled" });
    expect(fixture.observed.cwd).toBeUndefined();
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix(
  "returns typed cancellation with the caller's reason when the selected-file digest is cancelled",
  async () => {
    const controller = new AbortController();
    const reason = { authored: "cancel during digest" };
    const fixture = await harness("process.exit(9);", {
      digestArtifact:
        (real) =>
        (path, ...rest) => {
          if (path.endsWith("selected.elf")) controller.abort(reason);
          return real(path, ...rest);
        },
    });
    const result = await fixture.service.inspect(
      { path: fixture.path },
      { signal: controller.signal },
    );
    if (result.ok) throw new Error("Expected cancellation");
    expect(result.error._tag).toBe("AnalysisCancelledError");
    expect(result.error.cause).toBe(reason);
    expect(fixture.observed.cwd).toBeUndefined();
    expect(fixture.observed.roots).toEqual([]);
  },
);

posix.each([
  [
    "replaced with other bytes",
    async (path: string) => {
      await writeFile(`${path}.next`, Buffer.alloc(64, 7));
      await rename(`${path}.next`, path);
    },
  ],
  [
    "replaced with a symlink to identical bytes",
    async (path: string) => {
      await writeFile(`${path}.target`, await readFile(path));
      await rename(path, `${path}.moved`);
      await symlink(`${path}.target`, path);
    },
  ],
])(
  "refuses a selected file %s between its digest and the private copy",
  async (_case, replace) => {
    let replaced = false;
    const fixture = await harness("process.exit(9);", {
      digestArtifact:
        (real) =>
        async (path, ...rest) => {
          const digest = await real(path, ...rest);
          if (path.endsWith("selected.elf") && !replaced) {
            replaced = true;
            await replace(path);
          }
          return digest;
        },
    });
    const projected = await failure(
      await fixture.service.inspect({ path: fixture.path }),
    );
    expect(projected.code).toBe("artifact_changed");
    expect(fixture.observed.cwd).toBeUndefined();
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix(
  "keeps a completed observation when the caller aborts during private-copy removal",
  async () => {
    const controller = new AbortController();
    const fixture = await harness(
      `reply({ ok: true, value: ${JSON.stringify(value())} });`,
      {
        runtime: (root) => ({
          path: root.path,
          close: async () => {
            controller.abort(new Error("caller stopped late"));
            await root.close();
          },
        }),
      },
    );
    const projected = await failure(
      await fixture.service.inspect(
        { path: fixture.path },
        { signal: controller.signal },
      ),
    );
    expect(projected).toMatchObject({
      code: "cancelled",
      details: {
        partial_observation: {
          operation: "inspect_with_lief",
          normalized_result: { artifact: { sha256: fixture.sha256 } },
        },
      },
    });
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix(
  "retains a private copy whose removal fails and releases it before the next call",
  async () => {
    let deny = true;
    const fixture = await harness(
      `reply({ ok: true, value: ${JSON.stringify(value())} });`,
      {
        runtime: (root) => ({
          path: root.path,
          close: async () => {
            if (deny) {
              deny = false;
              throw new Error("authored cleanup denial");
            }
            await root.close();
          },
        }),
      },
    );
    const first = await failure(
      await fixture.service.inspect({ path: fixture.path }),
    );
    const [retained] = fixture.observed.roots;
    expect(first).toMatchObject({
      code: "cleanup_incomplete",
      details: {
        cleanup: "incomplete",
        resources: expect.arrayContaining([retained]),
        partial_observation: {
          normalized_result: { artifact: { sha256: fixture.sha256 } },
        },
      },
    });
    expect(await fixture.exists(retained ?? "")).toBe(true);
    const second = await fixture.service.inspect({ path: fixture.path });
    if (!second.ok) throw second.error;
    expect(await fixture.rootRemoved()).toBe(true);
    await fixture.provider.close();
  },
);

posix(
  "keeps the completed reply with cleanup_incomplete when process-group cleanup fails after exit 0",
  async () => {
    const gate = { deny: true };
    const fixture = await harness(
      `reply({ ok: true, value: ${JSON.stringify(value())} });`,
      // Denied after the run and again on the finalization retry.
      { spawned: deniedCleanup(gate) },
    );
    const first = await failure(
      await fixture.service.inspect({ path: fixture.path }),
    );
    const [retained] = fixture.observed.roots;
    expect(first).toMatchObject({
      code: "cleanup_incomplete",
      details: {
        cleanup: "incomplete",
        resources: expect.arrayContaining([retained]),
        partial_observation: {
          normalized_result: {
            operation: "summary",
            artifact: { sha256: fixture.sha256 },
          },
        },
      },
    });
    expect(JSON.stringify(first)).toContain("authored group cleanup denial");
    expect(await fixture.exists(retained ?? "")).toBe(true);
    // The retained owner is retried before the next call is admitted.
    gate.deny = false;
    reportOf(await fixture.service.inspect({ path: fixture.path }));
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix(
  "keeps the primary failure and retains the process group when its cleanup fails after a failed run",
  async () => {
    const gate = { deny: true };
    const fixture = await harness(
      `process.stderr.write("Traceback: authored primary\\n"); process.exit(3);`,
      { spawned: deniedCleanup(gate) },
    );
    const first = await failure(
      await fixture.service.inspect({ path: fixture.path }),
    );
    const [retained] = fixture.observed.roots;
    // The primary unreadable-output failure and its diagnostics stay primary.
    expect(first).toMatchObject({
      code: "cleanup_incomplete",
      message: expect.stringContaining("unreadable result"),
      details: {
        cleanup: "incomplete",
        resources: expect.arrayContaining([retained]),
        captured_output: {
          stderr: "Traceback: authored primary\n",
          exit_code: 3,
        },
      },
    });
    expect(await fixture.exists(retained ?? "")).toBe(true);
    gate.deny = false;
    await fixture.provider.close();
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

/**
 * Stable-read filesystem whose descriptors deny their first close, then close
 * for real; `onDenied` runs inside the denied close.
 */
const closeDenied = (
  handles: FileHandle[],
  onDenied?: () => void,
): StableArtifactFileSystem => ({
  lstat: (path) => lstat(path, { bigint: true }),
  open: async (path, flags) => {
    const handle = await open(path, flags);
    handles.push(handle);
    const close = handle.close.bind(handle);
    let denied = false;
    handle.close = async () => {
      if (!denied) {
        denied = true;
        onDenied?.();
        throw new Error("authored descriptor close denial");
      }
      await close();
    };
    return handle;
  },
});

type Fixture = Awaited<ReturnType<typeof harness>>;

/** REA's reads after the helper exits, in order; `earlier` reads of the same file precede the run. */
const POST_RUN_READS = [
  {
    read: "private copy",
    file: "artifact",
    earlier: 0,
    path: (_fixture: Fixture, root: string) => join(root, "artifact"),
  },
  {
    read: "reply",
    file: "reply.json",
    earlier: 0,
    path: (_fixture: Fixture, root: string) => join(root, "reply.json"),
  },
  {
    read: "configured Python interpreter",
    file: "python",
    earlier: 1,
    path: (fixture: Fixture) => fixture.python,
  },
  {
    read: "native LIEF module",
    file: "_lief.so",
    earlier: 0,
    path: (fixture: Fixture) => fixture.native,
  },
  {
    read: "selected file",
    file: "selected.elf",
    earlier: 1,
    path: (fixture: Fixture) => fixture.path,
  },
] as const;
type PostRunRead = (typeof POST_RUN_READS)[number];

/** Deny the first close of each listed post-run read's descriptor; every other read passes through. */
const denyPostRunCloses = (
  reads: readonly PostRunRead[],
  handles: FileHandle[],
  onDenied?: () => void,
) => {
  const seen = new Map<PostRunRead, number>();
  const fileSystem = (path: string, real?: StableArtifactFileSystem) => {
    const entry = reads.find((read) => read.file === basename(path));
    if (entry === undefined) return real;
    const count = seen.get(entry) ?? 0;
    seen.set(entry, count + 1);
    return count === entry.earlier ? closeDenied(handles, onDenied) : real;
  };
  return {
    readArtifact:
      (real: typeof readStableArtifact): typeof readStableArtifact =>
      (path, bytes, signal, files, scope) =>
        real(path, bytes, signal, fileSystem(path, files), scope),
    digestArtifact:
      (real: typeof digestStableArtifact): typeof digestStableArtifact =>
      (path, bytes, signal, files, scope) =>
        real(path, bytes, signal, fileSystem(path, files), scope),
  };
};

const SUCCESS = `process.stderr.write("LIEF warning\\n"); reply({ ok: true, value: ${JSON.stringify(value())} });`;

/** The complete, verified result a retained descriptor must not discard. */
const completedResult = async (fixture: Fixture) => ({
  operation: "inspect_with_lief",
  confidence: "observed",
  normalized_result: {
    artifact: { sha256: fixture.sha256 },
    artifact_after: { sha256: fixture.sha256, changed: false },
    provider: {
      python: { sha256: sha256(await readFile(fixture.python)) },
      native_module: { sha256: sha256(await readFile(fixture.native)) },
    },
    summary: { architecture: "X86_64" },
    diagnostics: { stderr: { bytes: 13 } },
  },
});

posix.each(POST_RUN_READS)(
  "keeps the completed result when the $read descriptor cannot be closed after its read",
  async (entry) => {
    const handles: FileHandle[] = [];
    const fixture = await harness(SUCCESS, denyPostRunCloses([entry], handles));
    const result = await fixture.service.inspect({ path: fixture.path });
    if (result.ok) throw new Error("Expected cleanup_incomplete");
    expect(handles).toHaveLength(1);
    const root = fixture.observed.roots[0] ?? "";
    const descriptor = entry.path(fixture, root);
    const projected = projectAnalysisError(result.error);
    expect(projected).toMatchObject({
      code: "cleanup_incomplete",
      retryable: false,
      details: {
        cleanup: "incomplete",
        execution_failure: "execution_failure",
        // The shared helper keeps the private root while any descriptor is held.
        resources: [descriptor, root],
        diagnostics: {
          reason: expect.stringContaining("authored descriptor close denial"),
        },
        partial_observation: await completedResult(fixture),
      },
    });
    // One cleanup failure carries the complete result once, without a nested copy.
    expect(projected.details).not.toHaveProperty("captured_output");
    expect(projected.details?.diagnostics).not.toHaveProperty("primary_error");
    expect(handles[0]?.fd).not.toBe(-1);
    expect(await fixture.exists(root)).toBe(true);
    await fixture.provider.close();
    expect(handles[0]?.fd).toBe(-1);
    expect(result.error.cleanupIncomplete).toBe(false);
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix(
  "names every retained descriptor when several post-run closes fail and releases them before the next call",
  async () => {
    const handles: FileHandle[] = [];
    const [copy, , , native] = POST_RUN_READS;
    const fixture = await harness(
      SUCCESS,
      denyPostRunCloses([copy, native], handles),
    );
    const result = await fixture.service.inspect({ path: fixture.path });
    if (result.ok) throw new Error("Expected cleanup_incomplete");
    expect(handles).toHaveLength(2);
    const root = fixture.observed.roots[0] ?? "";
    const projected = projectAnalysisError(result.error);
    expect(projected).toMatchObject({
      code: "cleanup_incomplete",
      details: {
        resources: [join(root, "artifact"), fixture.native, root],
        partial_observation: await completedResult(fixture),
      },
    });
    expect(
      String(
        (projected.details?.diagnostics as { reason: string }).reason,
      ).match(/authored descriptor close denial/gu),
    ).toHaveLength(2);
    // The next call retries both closes and the kept root before it runs.
    reportOf(await fixture.service.inspect({ path: fixture.path }));
    expect(handles.map((handle) => handle.fd)).toEqual([-1, -1]);
    expect(result.error.cleanupIncomplete).toBe(false);
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix(
  "runs the remaining integrity reads after a retained descriptor and keeps their failure primary",
  async () => {
    const handles: FileHandle[] = [];
    const fixture = await harness(
      `fs.appendFileSync(native.path, "changed"); reply({ ok: true, value: ${JSON.stringify(value())} });`,
      denyPostRunCloses([POST_RUN_READS[0]], handles),
    );
    const result = await fixture.service.inspect({ path: fixture.path });
    if (result.ok) throw new Error("Expected a failure");
    const root = fixture.observed.roots[0] ?? "";
    const projected = projectAnalysisError(result.error);
    expect(projected).toMatchObject({
      code: "cleanup_incomplete",
      message: expect.stringContaining(
        "The native LIEF module changed during the LIEF run",
      ),
      details: {
        execution_failure: "execution_failure",
        resources: [join(root, "artifact"), root],
        diagnostics: {
          primary_error: { code: "unreadable_output" },
          cleanup_error: {
            details: {
              diagnostics: {
                reason: expect.stringContaining(
                  "authored descriptor close denial",
                ),
              },
            },
          },
        },
      },
    });
    expect(projected.details).not.toHaveProperty("partial_observation");
    await fixture.provider.close();
    expect(handles[0]?.fd).toBe(-1);
    expect(result.error.cleanupIncomplete).toBe(false);
    expect(projectAnalysisError(result.error).code).toBe("unreadable_output");
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix(
  "keeps cancellation primary when the caller aborts after a retained descriptor",
  async () => {
    const handles: FileHandle[] = [];
    const controller = new AbortController();
    const reason = { authored: "cancel after a retained descriptor" };
    const fixture = await harness(SUCCESS, {
      digestArtifact: denyPostRunCloses([POST_RUN_READS[0]], handles)
        .digestArtifact,
      readArtifact:
        (real) =>
        (path, ...rest) => {
          if (path.endsWith("reply.json")) controller.abort(reason);
          return real(path, ...rest);
        },
    });
    const result = await fixture.service.inspect(
      { path: fixture.path },
      { signal: controller.signal },
    );
    if (result.ok) throw new Error("Expected cancellation");
    const root = fixture.observed.roots[0] ?? "";
    expect(projectAnalysisError(result.error)).toMatchObject({
      code: "cleanup_incomplete",
      details: {
        resources: [join(root, "artifact"), root],
        diagnostics: { primary_error: { code: "cancelled" } },
      },
    });
    expect(result.error.cleanupPrimary).toMatchObject({
      _tag: "AnalysisCancelledError",
      cause: reason,
    });
    await fixture.provider.close();
    expect(handles[0]?.fd).toBe(-1);
    expect(projectAnalysisError(result.error).code).toBe("cancelled");
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

/** The innermost primary below every cleanup composition. */
const primaryOf = (error: AnalysisError): AnalysisError =>
  error.cleanupPrimary === undefined ? error : primaryOf(error.cleanupPrimary);

posix.each([
  ["a valid reply", POST_RUN_READS[1], SUCCESS],
  [
    "an invalid reply",
    POST_RUN_READS[1],
    `fs.writeFileSync(request.reply_path, "{");`,
  ],
  [
    "a modified private copy",
    POST_RUN_READS[0],
    `fs.chmodSync(request.snapshot_path, 0o600); fs.appendFileSync(request.snapshot_path, "patched"); reply({ ok: true, value: ${JSON.stringify(value())} });`,
  ],
] as const)(
  "returns typed cancellation when the caller aborts inside a denied post-run close after %s",
  async (_case, entry, body) => {
    const handles: FileHandle[] = [];
    const controller = new AbortController();
    const reason = { authored: "cancel inside a denied close" };
    const fixture = await harness(
      body,
      denyPostRunCloses([entry], handles, () => controller.abort(reason)),
    );
    const result = await fixture.service.inspect(
      { path: fixture.path },
      { signal: controller.signal },
    );
    if (result.ok) throw new Error("Expected cancellation");
    expect(handles).toHaveLength(1);
    const root = fixture.observed.roots[0] ?? "";
    // The completed read does not outrank the abort observed while closing it.
    expect(primaryOf(result.error)).toMatchObject({
      _tag: "AnalysisCancelledError",
      cause: reason,
    });
    const projected = projectAnalysisError(result.error);
    expect(projected).toMatchObject({
      code: "cleanup_incomplete",
      details: { resources: [entry.path(fixture, root), root] },
    });
    expect(projected.details).not.toHaveProperty("partial_observation");
    await fixture.provider.close();
    expect(handles[0]?.fd).toBe(-1);
    expect(projectAnalysisError(result.error).code).toBe("cancelled");
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix("sweeps a setsid descendant that outlives a successful run", async () => {
  const fixture = await harness(`
      const { spawn } = require("node:child_process");
      // detached starts a new session and process group; the run token stays in its environment.
      const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { detached: true, stdio: "ignore" });
      fs.writeFileSync(selected + ".pid", String(child.pid));
      child.unref();
      reply({ ok: true, value: ${JSON.stringify(value())} });
    `);
  reportOf(await fixture.service.inspect({ path: fixture.path }));
  const pid = Number(await readFile(`${fixture.path}.pid`, "utf8"));
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
  expect(await fixture.rootRemoved()).toBe(true);
});

posix.each([
  [
    "grows past max_file_bytes",
    "fs.appendFileSync(selected, 'x');",
    (digest: string | null) => expect(digest).toBeNull(),
  ],
  [
    "is rewritten in place",
    "const bytes = fs.readFileSync(selected); bytes[9] ^= 0xff; fs.writeFileSync(selected, bytes);",
    (digest: string | null) => expect(digest).toMatch(/^[0-9a-f]{64}$/u),
  ],
])(
  "reports a selected file that %s after the copy as changed",
  async (_case, change, checkDigest) => {
    const fixture = await harness(
      `${change} reply({ ok: true, value: ${JSON.stringify(value())} });`,
    );
    const report = reportOf(
      await fixture.service.inspect({
        path: fixture.path,
        max_file_bytes: 64,
      }),
    );
    expect(report.artifact.sha256).toBe(fixture.sha256);
    expect(report.artifact_after.changed).toBe(true);
    expect(report.artifact_after.sha256).not.toBe(fixture.sha256);
    checkDigest(report.artifact_after.sha256);
    expect(report.limitations.join("\n")).toContain(
      "changed after REA copied it",
    );
  },
);

posix.each([
  ["an unsupported host", { platform: "darwin" as const }, {}],
  ["missing configuration", {}, { REA_LIEF_PYTHON: undefined }],
])(
  "refuses %s before reading the selected file",
  async (_case, host, environment) => {
    const fixture = await harness("process.exit(9);", host);
    const service =
      "REA_LIEF_PYTHON" in environment
        ? new LiefInspectionService(new LiefInspectionProvider({}))
        : fixture.service;
    const projected = await failure(
      await service.inspect({ path: fixture.path }),
    );
    expect(projected).toMatchObject({ code: "capability_unavailable" });
    expect(projected.remediation.action).toContain("REA_LIEF_PYTHON");
    expect(fixture.observed.cwd).toBeUndefined();
  },
);

posix(
  "rejects paging fields for summary and unknown fields before acquisition",
  async () => {
    const fixture = await harness("process.exit(9);");
    for (const input of [
      { path: fixture.path, offset: 1 },
      { path: fixture.path, operation: "imports", approval: true },
      { path: fixture.path, diagnostics: "everything" },
      { path: "relative.elf" },
    ])
      expect(
        await failure(await fixture.service.inspect(input)),
        JSON.stringify(input),
      ).toMatchObject({ code: "invalid_request" });
    expect(fixture.observed.cwd).toBeUndefined();
  },
);
