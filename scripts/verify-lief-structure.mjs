#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { PrivateRuntimeRoot } from "../dist/process/PrivateRuntimeRoot.js";

const python = process.env.REA_LIEF_PYTHON;
if (
  process.platform !== "linux" ||
  process.arch !== "x64" ||
  !isAbsolute(python ?? "")
)
  throw new Error(
    "verify:lief requires Linux x64 and absolute REA_LIEF_PYTHON for a Python that imports LIEF 1.0.x. cc builds the ELF fixtures; clang with lld and llvm-lipo build the PE and Mach-O fixtures. No target is executed.",
  );
const execute = promisify(execFile);
const entrypoint =
  process.argv[2] ?? fileURLToPath(new URL("./rea.mjs", import.meta.url));
const available = async (command, args = ["--version"]) => {
  try {
    await execute(command, args, { timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
};
const lipo = (await available("llvm-lipo"))
  ? "llvm-lipo"
  : (await available("llvm-lipo-18"))
    ? "llvm-lipo-18"
    : undefined;
const formats = { elf: await available("cc"), pe: false, macho: false };
const skipped = {};
if (!formats.elf) throw new Error("verify:lief requires cc for ELF fixtures.");

const RICH_KEY = 0x5eed1e1f;
const root = await PrivateRuntimeRoot.create({ prefix: "rea-lief-verifier-" });
const fixtures = join(root.path, "fixtures");
const temporary = join(root.path, "tmp");
await mkdir(fixtures);
await mkdir(temporary);
// Children allocate private roots under this TMPDIR; it must end empty.
const environment = {
  ...Object.fromEntries(
    Object.entries(process.env).filter(
      ([, value]) => typeof value === "string",
    ),
  ),
  TMPDIR: temporary,
};
const sha256 = async (path) =>
  createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
const build = async (command, args) =>
  execute(command, args, { cwd: fixtures, timeout: 120_000 });
const source = async (name, text) => writeFile(join(fixtures, name), text);

await source(
  "demo.c",
  "int demo_add(int a, int b) { return a + b; }\nint demo_mul(int a, int b) { return a * b; }\n",
);
await source(
  "app.c",
  "extern int demo_add(int, int);\nint main(void) { return demo_add(1, 2); }\n",
);
await build("cc", [
  "-shared",
  "-fPIC",
  "-Wl,-soname,libdemo.so",
  "-o",
  "libdemo.so",
  "demo.c",
]);
await build("cc", [
  "-o",
  "app.elf",
  "app.c",
  "-L.",
  "-ldemo",
  "-Wl,-rpath,$ORIGIN",
]);
// Legacy DT_RPATH instead of DT_RUNPATH.
await build("cc", [
  "-o",
  "app.rpath",
  "app.c",
  "-L.",
  "-ldemo",
  "-Wl,--disable-new-dtags,-rpath,/opt/demo",
]);
// Optional formats are reported as unverified when their toolchain is absent.
try {
  await source(
    "demo_pe.c",
    "__declspec(dllexport) int demo_add(int a, int b) { return a + b; }\n__declspec(dllexport) int demo_mul(int a, int b) { return a * b; }\n",
  );
  await source(
    "app_pe.c",
    "__declspec(dllimport) int demo_add(int, int);\nint mainCRTStartup(void) { return demo_add(1, 2); }\n",
  );
  const pe = ["--target=x86_64-pc-windows-msvc", "-fuse-ld=lld", "-nostdlib"];
  await build("clang", [
    ...pe,
    "-shared",
    "-Wl,/noentry",
    "-o",
    "demo.dll",
    "demo_pe.c",
  ]);
  await build("clang", [
    ...pe,
    "-Wl,/subsystem:console",
    "-o",
    "app.exe",
    "app_pe.c",
    "demo.lib",
  ]);
  // A delay-loaded import. The helper symbol is never called; nothing runs.
  await source(
    "app_delay.c",
    "__declspec(dllimport) int demo_add(int, int);\nvoid *__delayLoadHelper2(void *a, void *b) { return 0; }\nint mainCRTStartup(void) { return demo_add(1, 2); }\n",
  );
  await build("clang", [
    ...pe,
    "-Wl,/subsystem:console",
    "-Wl,/delayload:demo.dll",
    "-o",
    "app_delay.exe",
    "app_delay.c",
    "demo.lib",
  ]);
  // A forwarded export.
  await source("forward.c", "int forward_local(void) { return 1; }\n");
  await build("clang", [
    ...pe,
    "-shared",
    "-Wl,/noentry",
    "-Wl,/export:forward_add=demo.demo_add",
    "-o",
    "forward.dll",
    "forward.c",
  ]);
  // lld writes no rich header; place a known one in the DOS stub before e_lfanew.
  const image = await readFile(join(fixtures, "demo.dll"));
  const rich = [
    0x536e6144,
    0,
    0,
    0,
    (0x0104 << 16) | 30148,
    3,
    (0x0102 << 16) | 30148,
    1,
  ];
  const header = Buffer.alloc(rich.length * 4 + 8);
  rich.forEach((word, index) =>
    header.writeUInt32LE((word ^ RICH_KEY) >>> 0, index * 4),
  );
  header.write("Rich", rich.length * 4, "latin1");
  header.writeUInt32LE(RICH_KEY, rich.length * 4 + 4);
  assert.ok(0x40 + header.length <= image.readUInt32LE(0x3c));
  header.copy(image, 0x40);
  await writeFile(join(fixtures, "rich.dll"), image);
  formats.pe = true;
} catch (cause) {
  skipped.pe = `PE fixture build failed (clang with lld-link): ${cause.message.split("\n")[0]}`;
}
try {
  if (lipo === undefined) throw new Error("llvm-lipo is unavailable");
  const macho = (arch) => [
    `--target=${arch}-apple-macos12`,
    "-fuse-ld=lld",
    "-nostdlib",
  ];
  await build("clang", [
    ...macho("arm64"),
    "-shared",
    "-Wl,-install_name,@rpath/libdemo.dylib",
    "-o",
    "libdemo.dylib",
    "demo.c",
  ]);
  await build("clang", [
    ...macho("arm64"),
    "-Wl,-e,_main",
    "-Wl,-fixup_chains",
    "-o",
    "app.arm64",
    "app.c",
    "libdemo.dylib",
  ]);
  await build("clang", [
    ...macho("x86_64"),
    "-Wl,-e,_main",
    "-Wl,-fixup_chains",
    "-Wl,-undefined,dynamic_lookup",
    "-o",
    "app.x86_64",
    "app.c",
  ]);
  await build(lipo, [
    "-create",
    "app.x86_64",
    "app.arm64",
    "-output",
    "app.universal",
  ]);
  formats.macho = true;
} catch (cause) {
  skipped.macho = `Mach-O fixture build failed (clang with ld64.lld and llvm-lipo): ${cause.message.split("\n")[0]}`;
}
await source("notes.txt", "not an executable\n");
const fixtureFiles = (await readdir(fixtures)).sort();
const digests = new Map();
for (const name of fixtureFiles)
  digests.set(name, await sha256(join(fixtures, name)));

const cli = async (...args) => {
  const started = performance.now();
  let stdout;
  try {
    ({ stdout } = await execute(
      process.execPath,
      [entrypoint, "inspect-with-lief", ...args, "--json"],
      { env: environment, maxBuffer: 64 * 1024 * 1024, timeout: 300_000 },
    ));
  } catch (cause) {
    stdout = cause.stdout;
  }
  return { value: JSON.parse(stdout), ms: performance.now() - started };
};
const result = (evidence) => {
  assert.equal(
    evidence.operation,
    "inspect_with_lief",
    JSON.stringify(evidence),
  );
  const value = evidence.normalized_result;
  assert.equal(value.artifact_after.changed, false);
  return value;
};
const report = { formats: {}, mcp: {}, timings_ms: {} };
const path = (name) => join(fixtures, name);

// ELF: dependency, runpath, soname, exports and unbound imports.
{
  const app = await cli(path("app.elf"));
  report.timings_ms.elf_cli_summary = Math.round(app.ms);
  const summary = result(app.value).summary;
  assert.equal(result(app.value).format, "elf");
  assert.ok(summary.libraries.includes("libdemo.so"));
  assert.deepEqual(summary.elf.runpath, ["$ORIGIN"]);
  const legacy = result((await cli(path("app.rpath"))).value).summary.elf;
  assert.deepEqual(legacy.rpath, ["/opt/demo"]);
  assert.equal(legacy.runpath, null);
  assert.ok(summary.elf.interpreter !== null && summary.entrypoint !== null);
  const library = result((await cli(path("libdemo.so"))).value).summary;
  assert.equal(library.elf.soname, "libdemo.so");
  const exports = result(
    (await cli(path("libdemo.so"), "exports")).value,
  ).exports;
  assert.ok(
    exports.items.some((row) => row.name === "demo_add" && row.kind === "FUNC"),
  );
  const imports = result((await cli(path("app.elf"), "imports")).value).imports;
  assert.ok(
    imports.items.some(
      (row) => row.name === "demo_add" && row.library === null,
    ),
  );
  const page = result(
    (await cli(path("app.elf"), "sections", "--offset", "1", "--limit", "2"))
      .value,
  ).sections;
  assert.equal(page.returned, 2);
  assert.equal(page.next_offset, 3);
  report.formats.elf = {
    verified: true,
    sections: page.total,
    exports: exports.total,
  };
}

// PE: imports bound to their DLL, exports with ordinals, no segment table.
if (formats.pe) {
  const summary = result((await cli(path("app.exe"))).value).summary;
  assert.deepEqual(summary.libraries, ["demo.dll"]);
  assert.ok(
    summary.pe.data_directories.some((entry) => entry.type === "IMPORT_TABLE"),
  );
  assert.deepEqual(summary.pe.signatures, { present: false, count: 0 });
  const imports = result((await cli(path("app.exe"), "imports")).value).imports;
  assert.ok(
    imports.items.some(
      (row) =>
        row.name === "demo_add" &&
        row.library === "demo.dll" &&
        row.address !== null,
    ),
  );
  const exports = result(
    (await cli(path("demo.dll"), "exports")).value,
  ).exports;
  assert.ok(
    exports.items.some(
      (row) => row.name === "demo_add" && row.ordinal !== null,
    ),
  );
  const segments = result((await cli(path("app.exe"), "segments")).value);
  assert.equal(segments.coverage.applicable, false);
  const delayed = result(
    (await cli(path("app_delay.exe"), "imports")).value,
  ).imports;
  assert.ok(
    delayed.items.some(
      (row) =>
        row.name === "demo_add" &&
        row.library === "demo.dll" &&
        row.kind === "delay-import" &&
        row.address === null,
    ),
  );
  const forwarded = result(
    (await cli(path("forward.dll"), "exports")).value,
  ).exports;
  assert.ok(
    forwarded.items.some(
      (row) =>
        row.name === "forward_add" &&
        row.forwarder === "demo.demo_add" &&
        row.address === null,
    ),
  );
  const richHeader = result((await cli(path("rich.dll"))).value).summary.pe
    .rich_header;
  assert.equal(richHeader.key, `0x${RICH_KEY.toString(16)}`);
  assert.deepEqual(
    richHeader.entries
      .map((entry) => `${entry.id}:${entry.build_id}:${entry.count}`)
      .sort(),
    ["258:30148:1", "260:30148:3"],
  );
  report.formats.pe = { verified: true, exports: exports.total };
} else
  report.formats.pe = {
    verified: false,
    reason: "clang with lld-link unavailable",
  };

// Mach-O: universal slices, slice selection, bound imports, code-signature location.
if (formats.macho) {
  const universal = result((await cli(path("app.universal"))).value);
  assert.equal(universal.macho.universal, true);
  assert.equal(universal.macho.slice_count, 2);
  const arm = universal.macho.slices.findIndex(
    (slice) => slice.cpu_type === "ARM64",
  );
  const selected = result(
    (await cli(path("app.universal"), "summary", "--macho-slice", String(arm)))
      .value,
  );
  assert.equal(selected.summary.architecture, "ARM64");
  assert.ok(selected.summary.macho.code_signature !== null);
  assert.ok(
    selected.summary.macho.load_commands.some(
      (command) => command.command === "CODE_SIGNATURE",
    ),
  );
  const imports = result(
    (await cli(path("app.universal"), "imports", "--macho-slice", String(arm)))
      .value,
  ).imports;
  assert.ok(
    imports.items.some(
      (row) =>
        row.name === "_demo_add" && row.library === "@rpath/libdemo.dylib",
    ),
  );
  const exports = result(
    (await cli(path("libdemo.dylib"), "exports")).value,
  ).exports;
  assert.ok(exports.items.some((row) => row.name === "_demo_add"));
  const outOfRange = (await cli(path("app.universal"), "--macho-slice", "9"))
    .value;
  assert.equal(outOfRange.code, "invalid_request");
  report.formats.macho = {
    verified: true,
    slices: universal.macho.slice_count,
  };
} else
  report.formats.macho = {
    verified: false,
    reason: "clang, ld64.lld or llvm-lipo unavailable",
  };

assert.equal((await cli(path("notes.txt"))).value.code, "unsupported_target");

// One stdio MCP session must produce the same Evidence as the CLI.
const client = new Client({ name: "lief-verifier", version: "1" });
await client.connect(
  new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "mcp"],
    env: environment,
    stderr: "pipe",
  }),
);
try {
  const tools = (await client.listTools()).tools;
  assert.ok(tools.some((tool) => tool.name === "inspect_with_lief"));
  for (const [name, args] of [
    ["elf_summary", { path: path("app.elf") }],
    ["elf_exports", { path: path("libdemo.so"), operation: "exports" }],
  ]) {
    const started = performance.now();
    const response = await client.callTool({
      name: "inspect_with_lief",
      arguments: args,
    });
    report.timings_ms[`mcp_${name}`] = Math.round(performance.now() - started);
    assert.notEqual(response.isError, true, JSON.stringify(response.content));
    const evidence = response.structuredContent;
    const cliArgs = [
      args.path,
      ...(args.operation === undefined ? [] : [args.operation]),
    ];
    const cliEvidence = (await cli(...cliArgs)).value;
    assert.equal(evidence.evidence_id, cliEvidence.evidence_id);
    report.mcp[name] = {
      evidence_id: evidence.evidence_id,
      response_bytes: Buffer.byteLength(JSON.stringify(response)),
    };
  }
} finally {
  await client.close();
}

// The helper read only private copies: fixtures are unchanged and no roots remain.
assert.deepEqual((await readdir(fixtures)).sort(), fixtureFiles);
for (const [name, digest] of digests)
  assert.equal(await sha256(join(fixtures, name)), digest, name);
assert.deepEqual(await readdir(temporary), []);
report.lief_version = result(
  (await cli(path("app.elf"))).value,
).provider.lief_version;
await root.close();
console.log(JSON.stringify({ status: "passed", ...report }, null, 2));
