#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  readFile,
  readdir,
  realpath,
  writeFile,
} from "node:fs/promises";
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
if (!(await available("readelf")))
  throw new Error(
    "verify:lief requires binutils readelf as the ELF symbol oracle.",
  );

const RICH_KEY = 0x5eed1e1f;
let badPeSectionName;
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
const hex = (bytes) => Buffer.from(bytes).toString("hex");

/** ELF64 section headers by name; enough to patch fixture strings in place. */
const elfSections = (image) => {
  const offset = Number(image.readBigUInt64LE(0x28));
  const size = image.readUInt16LE(0x3a);
  const count = image.readUInt16LE(0x3c);
  const strings = image.readUInt16LE(0x3e);
  const header = (index) => ({
    name: image.readUInt32LE(offset + index * size),
    offset: Number(image.readBigUInt64LE(offset + index * size + 0x18)),
    size: Number(image.readBigUInt64LE(offset + index * size + 0x20)),
  });
  const table = header(strings);
  const sections = new Map();
  for (let index = 0; index < count; index++) {
    const entry = header(index);
    const start = table.offset + entry.name;
    const name = image.toString("latin1", start, image.indexOf(0, start));
    sections.set(name, entry);
  }
  return sections;
};

/** Replace the first byte of `text` inside one section with 0xff; returns the patched string's bytes. */
const corrupt = (image, section, text) => {
  const { offset, size } = elfSections(image).get(section);
  const at = image.indexOf(Buffer.from(`${text}\0`, "latin1"), offset);
  assert.ok(at >= offset && at < offset + size, `${text} in ${section}`);
  image[at] = 0xff;
  return image.subarray(at, at + text.length);
};

/**
 * ELF64 x86-64 shared object with `exported` defined GLOBAL FUNC and
 * `imported` undefined GLOBAL symbols in .dynsym, a DT_HASH table and a .symtab
 * mirror. Never executed; it measures linear table reads.
 */
const dynamicSymbolElf = (exported, imported) => {
  const names = [
    ...Array.from({ length: imported }, (_, index) => `imp${String(index)}`),
    ...Array.from({ length: exported }, (_, index) => `exp${String(index)}`),
  ];
  const strings = [Buffer.from([0])];
  let used = 1;
  const offsets = names.map((name) => {
    const at = used;
    strings.push(Buffer.from(`${name}\0`, "latin1"));
    used += name.length + 1;
    return at;
  });
  const needed = used;
  strings.push(Buffer.from("libc.so.6\0", "latin1"));
  const dynstr = Buffer.concat(strings);
  const symbols = Buffer.alloc(24 * (names.length + 1));
  names.forEach((_, index) => {
    const base = 24 * (index + 1);
    const defined = index >= imported;
    symbols.writeUInt32LE(offsets[index], base);
    symbols[base + 4] = 0x12;
    symbols.writeUInt16LE(defined ? 1 : 0, base + 6);
    symbols.writeBigUInt64LE(
      defined ? BigInt(0x1000 + (index % 16)) : 0n,
      base + 8,
    );
    symbols.writeBigUInt64LE(1n, base + 16);
  });
  const shstr = Buffer.from(
    "\0.text\0.dynsym\0.dynstr\0.dynamic\0.symtab\0.shstrtab\0",
    "latin1",
  );
  const align = (value, to) => Math.ceil(value / to) * to;
  const textAt = align(64 + 56 * 2, 16);
  const dynsymAt = align(textAt + 16, 8);
  const dynstrAt = dynsymAt + symbols.length;
  const hashAt = align(dynstrAt + dynstr.length, 8);
  const hash = Buffer.alloc(12 + 4 * (names.length + 1));
  hash.writeUInt32LE(1, 0);
  hash.writeUInt32LE(names.length + 1, 4);
  const dynamicAt = align(hashAt + hash.length, 8);
  const dynamic = Buffer.alloc(16 * 7);
  [
    [1, needed],
    [4, hashAt],
    [6, dynsymAt],
    [5, dynstrAt],
    [10, dynstr.length],
    [11, 24],
    [0, 0],
  ].forEach(([tag, value], index) => {
    dynamic.writeBigInt64LE(BigInt(tag), index * 16);
    dynamic.writeBigUInt64LE(BigInt(value), index * 16 + 8);
  });
  const symtabAt = dynamicAt + dynamic.length;
  const shstrAt = symtabAt + symbols.length;
  const sectionsAt = align(shstrAt + shstr.length, 8);
  const end = sectionsAt + 64 * 7;
  const image = Buffer.alloc(end);
  image.write("\x7fELF", 0, "latin1");
  image.set([2, 1, 1], 4);
  image.writeUInt16LE(3, 16);
  image.writeUInt16LE(62, 18);
  image.writeUInt32LE(1, 20);
  image.writeBigUInt64LE(BigInt(textAt), 24);
  image.writeBigUInt64LE(64n, 32);
  image.writeBigUInt64LE(BigInt(sectionsAt), 40);
  image.writeUInt16LE(64, 52);
  image.writeUInt16LE(56, 54);
  image.writeUInt16LE(2, 56);
  image.writeUInt16LE(64, 58);
  image.writeUInt16LE(7, 60);
  image.writeUInt16LE(6, 62);
  const program = (index, type, flags, offset, size) => {
    const base = 64 + index * 56;
    image.writeUInt32LE(type, base);
    image.writeUInt32LE(flags, base + 4);
    for (const [field, value] of [
      [8, offset],
      [16, offset],
      [24, offset],
      [32, size],
      [40, size],
    ])
      image.writeBigUInt64LE(BigInt(value), base + field);
  };
  program(0, 1, 5, 0, end);
  program(1, 2, 6, dynamicAt, dynamic.length);
  image.fill(0xc3, textAt, textAt + 16);
  symbols.copy(image, dynsymAt);
  dynstr.copy(image, dynstrAt);
  hash.copy(image, hashAt);
  dynamic.copy(image, dynamicAt);
  symbols.copy(image, symtabAt);
  shstr.copy(image, shstrAt);
  const section = (
    index,
    name,
    type,
    flags,
    offset,
    size,
    link,
    info,
    entry,
  ) => {
    const base = sectionsAt + index * 64;
    image.writeUInt32LE(name === "" ? 0 : shstr.indexOf(`${name}\0`), base);
    image.writeUInt32LE(type, base + 4);
    image.writeBigUInt64LE(BigInt(flags), base + 8);
    image.writeBigUInt64LE(BigInt(flags === 0 ? 0 : offset), base + 16);
    image.writeBigUInt64LE(BigInt(offset), base + 24);
    image.writeBigUInt64LE(BigInt(size), base + 32);
    image.writeUInt32LE(link, base + 40);
    image.writeUInt32LE(info, base + 44);
    image.writeBigUInt64LE(8n, base + 48);
    image.writeBigUInt64LE(BigInt(entry), base + 56);
  };
  section(1, ".text", 1, 6, textAt, 16, 0, 0, 0);
  section(2, ".dynsym", 11, 2, dynsymAt, symbols.length, 3, 1, 24);
  section(3, ".dynstr", 3, 2, dynstrAt, dynstr.length, 0, 0, 0);
  section(4, ".dynamic", 6, 3, dynamicAt, dynamic.length, 3, 0, 16);
  section(5, ".symtab", 2, 0, symtabAt, symbols.length, 3, 1, 24);
  section(6, ".shstrtab", 3, 0, shstrAt, shstr.length, 0, 0, 0);
  return image;
};

/** binutils readelf as an independent oracle for the dynamic symbol interface. */
const readelfDynamic = async (file) => {
  const { stdout } = await execute("readelf", ["--dyn-syms", "-W", file], {
    maxBuffer: 64 * 1024 * 1024,
  });
  const imports = [];
  const exports = [];
  for (const line of stdout.split("\n")) {
    const fields = line.trim().split(/\s+/u);
    if (!/^\d+:$/u.test(fields[0] ?? "") || fields.length < 8) continue;
    const [, , , , binding, visibility, index, name] = fields;
    const symbol = (name ?? "").replace(/@.*$/u, "");
    if (index === "UND" && ["GLOBAL", "WEAK"].includes(binding))
      imports.push(symbol);
    else if (
      index !== "UND" &&
      ["GLOBAL", "WEAK", "UNIQUE"].includes(binding) &&
      ["DEFAULT", "PROTECTED"].includes(visibility)
    )
      exports.push(symbol);
  }
  return { imports: imports.sort(), exports: exports.sort() };
};
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
// Non-UTF-8 strings patched into copies of the compiled executable; never run.
{
  const original = await readFile(join(fixtures, "app.elf"));
  for (const [name, section, text] of [
    ["bad-interp.elf", ".interp", "/lib64/ld-linux-x86-64.so.2"],
    ["bad-needed.elf", ".dynstr", "libdemo.so"],
    ["bad-dynstr.elf", ".dynstr", "demo_add"],
    ["bad-secname.elf", ".shstrtab", ".text"],
  ]) {
    const image = Buffer.from(original);
    corrupt(image, section, text);
    await writeFile(join(fixtures, name), image);
  }
  // A truncated header makes LIEF print parser warnings.
  await writeFile(join(fixtures, "truncated.elf"), original.subarray(0, 64));
  await writeFile(
    join(fixtures, "dynsym-200k.so"),
    dynamicSymbolElf(200_000, 3),
  );
}
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
  // A section name that is not valid UTF-8, patched into a copy of the DLL.
  const badName = Buffer.from(await readFile(join(fixtures, "demo.dll")));
  const sectionTable =
    badName.readUInt32LE(0x3c) +
    24 +
    badName.readUInt16LE(badName.readUInt32LE(0x3c) + 20);
  badName[sectionTable + 1] = 0xff;
  const nameEnd = badName.indexOf(0, sectionTable);
  badPeSectionName = hex(
    badName.subarray(sectionTable, Math.min(nameEnd, sectionTable + 8)),
  );
  await writeFile(join(fixtures, "bad-secname.dll"), badName);
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

// ELF: dependency, runpath, soname, exact .dynsym imports and exports.
{
  const app = await cli(path("app.elf"));
  report.timings_ms.elf_cli_summary = Math.round(app.ms);
  const elf = result(app.value);
  const summary = elf.summary;
  assert.equal(elf.format, "elf");
  assert.ok(summary.libraries.includes("libdemo.so"));
  assert.deepEqual(summary.elf.runpath, ["$ORIGIN"]);
  assert.deepEqual(summary.truncated_lists, []);
  assert.deepEqual(summary.unread_fields, []);
  // The interpreter and native module REA digested before and after the run.
  const interpreter = await realpath(python);
  assert.equal(elf.provider.python.path, interpreter);
  assert.equal(elf.provider.python.sha256, await sha256(interpreter));
  assert.equal(
    elf.provider.native_module.sha256,
    await sha256(elf.provider.native_module.path),
  );
  const legacy = result((await cli(path("app.rpath"))).value).summary.elf;
  assert.deepEqual(legacy.rpath, ["/opt/demo"]);
  assert.equal(legacy.runpath, null);
  assert.ok(summary.elf.interpreter !== null && summary.entrypoint !== null);
  const library = result((await cli(path("libdemo.so"))).value).summary;
  assert.equal(library.elf.soname, "libdemo.so");
  // Exact counts against readelf: .dynsym only, weak undefined references
  // included, no duplicate rows, no .symtab-only globals.
  const counts = {};
  for (const name of ["libdemo.so", "app.elf"]) {
    const oracle = await readelfDynamic(path(name));
    const imports = result(
      (await cli(path(name), "imports", "--limit", "1000")).value,
    ).imports;
    const exports = result(
      (await cli(path(name), "exports", "--limit", "1000")).value,
    ).exports;
    const summarized = result((await cli(path(name))).value).summary.counts;
    assert.deepEqual(
      imports.items.map((row) => row.name).sort(),
      oracle.imports,
      name,
    );
    assert.deepEqual(
      exports.items.map((row) => row.name).sort(),
      oracle.exports,
      name,
    );
    assert.equal(imports.total, oracle.imports.length, name);
    assert.equal(exports.total, oracle.exports.length, name);
    assert.equal(summarized.imports, oracle.imports.length, name);
    assert.equal(summarized.exports, oracle.exports.length, name);
    counts[name] = { imports: imports.total, exports: exports.total };
  }
  assert.equal(counts["libdemo.so"].exports, 2);
  assert.ok(
    (await readelfDynamic(path("libdemo.so"))).imports.includes(
      "__gmon_start__",
    ),
  );
  const appExports = result(
    (await cli(path("app.elf"), "exports", "--limit", "1000")).value,
  ).exports.items.map((row) => row.name);
  for (const symtabOnly of ["main", "_start", "_init", "_fini"])
    assert.ok(!appExports.includes(symtabOnly), symtabOnly);
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
  // Dependencies and search paths page like any other table.
  const needed = result(
    (await cli(path("app.elf"), "libraries")).value,
  ).libraries;
  assert.deepEqual(
    needed.items.map((row) => [row.name, row.kind]),
    summary.libraries.map((name) => [name, "NEEDED"]),
  );
  assert.deepEqual(
    result((await cli(path("app.elf"), "rpaths")).value).rpaths.items,
    [{ path: "$ORIGIN", kind: "RUNPATH" }],
  );
  assert.deepEqual(
    result((await cli(path("app.rpath"), "rpaths")).value).rpaths.items,
    [{ path: "/opt/demo", kind: "RPATH" }],
  );
  assert.equal(
    result((await cli(path("app.elf"), "load_commands")).value).coverage
      .applicable,
    false,
  );
  // Non-UTF-8 file strings keep their exact bytes and do not abort the summary.
  const raw = (text) => ({
    text: null,
    bytes_hex: `ff${hex(Buffer.from(text, "latin1").subarray(1))}`,
  });
  const badInterp = result((await cli(path("bad-interp.elf"))).value).summary;
  assert.deepEqual(
    badInterp.elf.interpreter,
    raw("/lib64/ld-linux-x86-64.so.2"),
  );
  assert.deepEqual(badInterp.unread_fields, []);
  const badNeeded = result((await cli(path("bad-needed.elf"))).value).summary;
  assert.ok(
    badNeeded.libraries.some(
      (name) => JSON.stringify(name) === JSON.stringify(raw("libdemo.so")),
    ),
  );
  const badSymbol = result(
    (await cli(path("bad-dynstr.elf"), "imports", "--limit", "1000")).value,
  ).imports;
  assert.ok(
    badSymbol.items.some(
      (row) => JSON.stringify(row.name) === JSON.stringify(raw("demo_add")),
    ),
  );
  const badSection = result(
    (await cli(path("bad-secname.elf"), "sections", "--limit", "1000")).value,
  ).sections;
  assert.ok(
    badSection.items.some(
      (row) => JSON.stringify(row.name) === JSON.stringify(raw(".text")),
    ),
  );
  // Parser warnings are summarized inline; the complete text is opt-in.
  const truncated = result((await cli(path("truncated.elf"))).value);
  assert.equal(truncated.coverage.parser_diagnostics, "reported");
  assert.equal(truncated.diagnostics.stderr.text, null);
  assert.ok(truncated.diagnostics.stderr.excerpt.length > 0);
  const complete = result(
    (await cli(path("truncated.elf"), "--diagnostics", "complete")).value,
  );
  assert.equal(
    createHash("sha256")
      .update(complete.diagnostics.stderr.text ?? "")
      .digest("hex"),
    truncated.diagnostics.stderr.sha256,
  );
  // 200,000 exported .dynsym symbols: linear counts and a one-row page.
  const large = await cli(path("dynsym-200k.so"));
  report.timings_ms.dynsym_200k_cli_summary = Math.round(large.ms);
  const largeSummary = result(large.value).summary;
  assert.equal(largeSummary.counts.exports, 200_000);
  assert.equal(largeSummary.counts.imports, 3);
  const last = await cli(
    path("dynsym-200k.so"),
    "exports",
    "--offset",
    "199999",
    "--limit",
    "1",
  );
  report.timings_ms.dynsym_200k_cli_last_export = Math.round(last.ms);
  assert.deepEqual(
    result(last.value).exports.items.map((row) => row.name),
    ["exp199999"],
  );
  report.formats.elf = {
    verified: true,
    sections: page.total,
    exact_dynamic_symbols: counts,
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
  assert.deepEqual(
    result(
      (await cli(path("app_delay.exe"), "libraries")).value,
    ).libraries.items.map((row) => [row.name, row.kind]),
    [["demo.dll", "delay-import"]],
  );
  const peSections = result(
    (await cli(path("bad-secname.dll"), "sections")).value,
  ).sections;
  assert.deepEqual(peSections.items[0].name, {
    text: null,
    bytes_hex: badPeSectionName,
  });
  const richHeader = result((await cli(path("rich.dll"))).value).summary.pe
    .rich_header;
  assert.equal(richHeader.key, `0x${RICH_KEY.toString(16)}`);
  assert.equal(richHeader.entry_count, 2);
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
  const commands = result(
    (
      await cli(
        path("app.universal"),
        "load_commands",
        "--macho-slice",
        String(arm),
      )
    ).value,
  ).load_commands;
  assert.equal(commands.total, selected.summary.counts.load_commands);
  assert.deepEqual(
    commands.items.map((row) => row.command),
    selected.summary.macho.load_commands.map((row) => row.command),
  );
  assert.deepEqual(
    result(
      (
        await cli(
          path("app.universal"),
          "libraries",
          "--macho-slice",
          String(arm),
        )
      ).value,
    ).libraries.items.map((row) => [row.name, row.kind]),
    [["@rpath/libdemo.dylib", "LOAD_DYLIB"]],
  );
  const dylib = result((await cli(path("libdemo.dylib"))).value).summary;
  assert.equal(dylib.macho.id_dylib.name, "@rpath/libdemo.dylib");
  assert.deepEqual(dylib.libraries, []);
  const exports = result(
    (await cli(path("libdemo.dylib"), "exports")).value,
  ).exports;
  assert.deepEqual(exports.items.map((row) => row.name).sort(), [
    "_demo_add",
    "_demo_mul",
  ]);
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
