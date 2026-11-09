import { createHash } from "node:crypto";
import { access, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it } from "vitest";

import { LiefInspectionService } from "../../../src/application/lief/LiefInspectionService.js";
import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { liefInspectionSchema } from "../../../src/domain/lief/liefInspection.js";
import { LiefInspectionProvider } from "../../../src/lief/LiefInspectionProvider.js";
import { PrivateRuntimeRoot } from "../../../src/process/PrivateRuntimeRoot.js";
import { spawnOwnedProviderProcess } from "../../../src/process/ProviderProcess.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const ELF = Buffer.from("7f454c4602010100", "hex");

const summary = {
  architecture: "X86_64",
  bits: 64,
  endianness: "little",
  object_type: "EXECUTABLE",
  entrypoint: "0x1040",
  imagebase: "0x0",
  counts: { sections: 3, segments: 2, imports: 1, exports: 0, libraries: 1 },
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
};

const value = (overrides: Record<string, unknown> = {}) => ({
  lief_version: "1.0.0-test",
  python_version: "3.13.0",
  format: "elf",
  macho: null,
  summary,
  page: null,
  resource_limits: {
    address_space_bytes: 4294967296,
    file_size_bytes: 34603008,
    core_file_bytes: 0,
  },
  ...overrides,
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
 * path, which the real helper never receives) and `reply(value)` in scope.
 */
const producer = (body: string): string => `
const fs = require("node:fs");
const request = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const selected = process.argv[2];
const reply = (value) => fs.writeFileSync(request.reply_path, JSON.stringify(value), { flag: "wx" });
${body}
`;

type RuntimeRoot = Awaited<ReturnType<typeof PrivateRuntimeRoot.create>>;

const harness = async (
  body: string,
  options: {
    readonly platform?: NodeJS.Platform;
    /** Wrap the owned private root, for example to control its removal. */
    readonly runtime?: (
      root: RuntimeRoot,
    ) => Pick<RuntimeRoot, "path" | "close">;
    readonly onSpawn?: (process: { readonly pid?: number | undefined }) => void;
  } = {},
) => {
  const directory = await createTestTempDirectory("rea-lief-provider-");
  const path = join(directory, "selected.elf");
  const bytes = Buffer.concat([ELF, Buffer.alloc(56, 1)]);
  await writeFile(path, bytes);
  const observed: {
    cwd: string | undefined;
    arguments: readonly string[] | undefined;
    roots: string[];
  } = { cwd: undefined, arguments: undefined, roots: [] };
  const provider = new LiefInspectionProvider(
    { REA_LIEF_PYTHON: process.execPath },
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
        const spawned = await spawnOwnedProviderProcess({
          ...spawn,
          command: process.execPath,
          arguments: ["-e", producer(body), spawn.arguments.at(-1) ?? "", path],
        });
        options.onSpawn?.(spawned.process);
        return spawned;
      },
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
    path,
    sha256: createHash("sha256").update(bytes).digest("hex"),
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

// The controlled producer relies on POSIX process groups and file modes.
const posix = it.runIf(process.platform !== "win32");

posix(
  "binds a summary to the private copy's identity and removes the copy",
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
      diagnostics: { stderr: "LIEF warning\n" },
      provider: {
        admitted_release: "1.0",
        python_executable: process.execPath,
      },
    });
    expect(report.limitations.join("\n")).toContain(
      "never received the original path",
    );
    expect(report.limitations.join("\n")).toContain("diagnostics.stderr");
    // Isolated interpreter, packaged helper, and a request inside the private root.
    expect(fixture.observed.arguments?.slice(0, 2)).toEqual(["-I", "-B"]);
    expect(fixture.observed.arguments?.[2]).toMatch(
      /bridge[\\/]lief[\\/]inspect\.py$/u,
    );
    expect(fixture.observed.arguments?.[3]).toBe(
      join(fixture.observed.cwd ?? "", "request.json"),
    );
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix(
  "pages list facets from the reported total and rejects inconsistent pages",
  async () => {
    const fixture = await harness(`
      const items = [1, 2, 3, 4, 5].map((index) => (${row.toString()})(index));
      const window = request.limit === 9 ? items : items.slice(request.offset, request.offset + request.limit);
      reply({ ok: true, value: { ...${JSON.stringify(value({ summary: null }))}, page: { applicable: true, total: items.length, items: window } } });
    `);
    const page = await fixture.service.inspect({
      path: fixture.path,
      operation: "imports",
      offset: 1,
      limit: 2,
    });
    if (!page.ok) throw page.error;
    expect(
      liefInspectionSchema.parse(parseEvidence(page.value).normalized_result)
        .imports,
    ).toMatchObject({
      offset: 1,
      limit: 2,
      total: 5,
      returned: 2,
      next_offset: 3,
      items: [{ name: "symbol_2" }, { name: "symbol_3" }],
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
    { code: "resource_constraint", retryable: false },
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
        },
      },
    },
  ],
])(
  "projects the %o refusal without partial structure",
  async (refusal, expected) => {
    const fixture = await harness(
      `reply(${JSON.stringify({ ok: false, ...refusal })});`,
    );
    expect(
      await failure(await fixture.service.inspect({ path: fixture.path })),
    ).toMatchObject(expected);
    expect(await fixture.rootRemoved()).toBe(true);
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
])(
  "fails without partial success when the helper ends with %s",
  async (_case, body, message) => {
    const fixture = await harness(body);
    const projected = await failure(
      await fixture.service.inspect({ path: fixture.path }),
    );
    expect(projected.code).toBe("unreadable_output");
    expect(JSON.stringify(projected)).toContain(message);
    expect(await fixture.rootRemoved()).toBe(true);
  },
);

posix(
  "returns typed cancellation once the helper is running and stops its process",
  async () => {
    const controller = new AbortController();
    let pid: number | undefined;
    const fixture = await harness("setInterval(() => {}, 1000);", {
      // Abort only after the owned helper exists, so the run phase is covered.
      onSpawn: (child) => {
        pid = child.pid;
        controller.abort(new Error("caller stopped"));
      },
    });
    expect(
      await failure(
        await fixture.service.inspect(
          { path: fixture.path },
          { signal: controller.signal },
        ),
      ),
    ).toMatchObject({ code: "cancelled" });
    expect(pid).toBeTypeOf("number");
    expect(() => process.kill(pid ?? 0, 0)).toThrow(
      expect.objectContaining({ code: "ESRCH" }),
    );
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

posix.each([
  [
    "grows past max_file_bytes",
    "fs.appendFileSync(selected, 'x');",
    (sha256: string | null) => expect(sha256).toBeNull(),
  ],
  [
    "is rewritten in place",
    "const bytes = fs.readFileSync(selected); bytes[9] ^= 0xff; fs.writeFileSync(selected, bytes);",
    (sha256: string | null) => expect(sha256).toMatch(/^[0-9a-f]{64}$/u),
  ],
])(
  "reports a selected file that %s after the copy as changed",
  async (_case, change, checkDigest) => {
    const fixture = await harness(
      `${change} reply({ ok: true, value: ${JSON.stringify(value())} });`,
    );
    const result = await fixture.service.inspect({
      path: fixture.path,
      max_file_bytes: 64,
    });
    if (!result.ok) throw result.error;
    const report = liefInspectionSchema.parse(
      parseEvidence(result.value).normalized_result,
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
      { path: "relative.elf" },
    ])
      expect(
        await failure(await fixture.service.inspect(input)),
        JSON.stringify(input),
      ).toMatchObject({ code: "invalid_request" });
    expect(fixture.observed.cwd).toBeUndefined();
  },
);
