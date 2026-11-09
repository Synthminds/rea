import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { chmod, copyFile, mkdir, readdir, writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { describe, expect, it } from "vitest";

import { FileSignaturesService } from "../../../src/application/binaryDiagnostics/FileSignaturesService.js";
import type { AnalysisError } from "../../../src/domain/analysisErrorBase.js";
import { fileSignaturesSchema } from "../../../src/domain/native/fileSignatures.js";
import { DieSignatureProvider } from "../../../src/native/die/DieSignatureProvider.js";
import { peExportImage } from "../../fixtures/binaryDiagnostics/nativeExports.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { createSingleEntryZip } from "../../fixtures/zipNames.js";

/**
 * Real-provider lane: REA_VERIFY_DIE_PYTHON names a Python executable whose
 * environment contains die-python 0.5.0. Without it these cases skip by name;
 * the configuration and failure controls below run everywhere on Linux x64.
 */
const realPython = process.env.REA_VERIFY_DIE_PYTHON ?? "";
const verifiedHost = process.platform === "linux" && process.arch === "x64";
const realDie = verifiedHost && isAbsolute(realPython);

const service = (environment: NodeJS.ProcessEnv) =>
  new FileSignaturesService(new DieSignatureProvider(environment));

const failure = async (
  environment: NodeJS.ProcessEnv,
  input: Record<string, unknown>,
): Promise<AnalysisError> => {
  const inspector = service(environment);
  try {
    const result = await inspector.inspect(input);
    if (result.ok) throw new Error("Expected a typed DiE failure.");
    return result.error;
  } finally {
    await inspector.close();
  }
};

const identify = async (
  environment: NodeJS.ProcessEnv,
  input: Record<string, unknown>,
) => {
  const inspector = service(environment);
  try {
    const result = await inspector.inspect(input);
    if (!result.ok) throw result.error;
    return {
      evidence: result.value,
      report: fileSignaturesSchema.parse(result.value.normalized_result),
    };
  } finally {
    await inspector.close();
  }
};

const sha256 = (bytes: Buffer) =>
  createHash("sha256").update(bytes).digest("hex");

describe.skipIf(!realDie)("real die-python 0.5.0", () => {
  const environment = { ...process.env, REA_DIE_PYTHON: realPython };

  it("identifies a host ELF executable from a private snapshot", async () => {
    const root = await createTestTempDirectory("rea-die-elf-");
    const path = join(root, "true");
    await copyFile("/bin/true", path);
    const { evidence, report } = await identify(environment, { path });
    expect(report.tool_profile).toMatchObject({
      backend: "die-python",
      configuration_key: "REA_DIE_PYTHON",
      package_version: "0.5.0",
      engine_version: "3.09",
      database: { source: "package-bundled" },
      resource_limits: { file_bytes: 0 },
    });
    expect(report.tool_profile.database.sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(report.file_parts[0]).toMatchObject({
      parent: null,
      file_type: "ELF64",
      part: "Header",
    });
    expect(report.detections.length).toBeGreaterThan(0);
    expect(report.artifact_after).toEqual({
      sha256: report.artifact.sha256,
      changed: false,
    });
    expect(evidence.subject).toMatchObject({
      local_path: path,
      format: "file",
      digest: { sha256: report.artifact.sha256 },
    });
    expect(evidence.limitations.join(" ")).toContain("not proof");
    // The private runtime, including the snapshot, is released.
    expect(await readdir(root)).toEqual(["true"]);
  });

  it("reports a generated PE image and its recursive overlay part", async () => {
    const root = await createTestTempDirectory("rea-die-pe-");
    const image = peExportImage({ bits: 64 });
    const path = join(root, "fixture.dll");
    const bytes = Buffer.concat([
      image,
      await createSingleEntryZip("member.txt"),
    ]);
    await writeFile(path, bytes);
    const plain = await identify(environment, { path });
    expect(plain.report.artifact).toEqual({
      path,
      sha256: sha256(bytes),
      bytes: bytes.length,
    });
    expect(plain.report.file_parts.map((part) => part.file_type)).toEqual([
      "PE64",
    ]);
    const recursive = await identify(environment, {
      path,
      recursive_scan: true,
    });
    expect(recursive.report.scan.recursive_scan).toBe(true);
    expect(recursive.report.tool_profile.arguments.at(-1)).toContain(
      '"recursive_scan":true',
    );
    expect(
      recursive.report.file_parts.map(({ parent, file_type, part }) => ({
        parent,
        file_type,
        part,
      })),
    ).toEqual([
      { parent: null, file_type: "PE64", part: "Header" },
      { parent: 0, file_type: "ZIP", part: "Overlay" },
    ]);
    expect(recursive.evidence.limitations.join(" ")).not.toContain(
      "recursive_scan",
    );
  });

  it("returns a typed timeout from the owned command deadline", async () => {
    const root = await createTestTempDirectory("rea-die-timeout-");
    const path = join(root, "true");
    await copyFile("/bin/true", path);
    const error = await failure(environment, { path, command_timeout_ms: 1 });
    expect(error._tag).toBe("AnalysisTimeoutError");
  });

  it.skipIf(!existsSync("/usr/bin/python3"))(
    "rejects a Python without die-python as an unavailable capability",
    async () => {
      const root = await createTestTempDirectory("rea-die-python-");
      const path = join(root, "true");
      await copyFile("/bin/true", path);
      const error = await failure(
        { ...process.env, REA_DIE_PYTHON: "/usr/bin/python3" },
        { path },
      );
      expect(error._tag).toBe("AnalysisCapabilityUnavailableError");
      expect(error.message).toContain("die-python");
    },
  );
});

describe.skipIf(!verifiedHost)("DiE configuration and file admission", () => {
  it("names the missing configuration without launching anything", async () => {
    const error = await failure(
      { PATH: process.env.PATH },
      { path: "/bin/true" },
    );
    expect(error._tag).toBe("AnalysisCapabilityUnavailableError");
    expect(error.message).toContain("REA_DIE_COMMAND or REA_DIE_PYTHON");
  });

  it("requires absolute tool paths", async () => {
    const error = await failure(
      { REA_DIE_COMMAND: "diec" },
      { path: "/bin/true" },
    );
    expect(error.message).toContain("REA_DIE_COMMAND must be an absolute");
  });

  it("refuses an unadmitted diec version banner", async () => {
    // Authored stand-in for a different diec release; not recorded diec output.
    const root = await createTestTempDirectory("rea-die-version-");
    const tools = join(root, "tools");
    await mkdir(tools);
    const diec = join(tools, "diec");
    await writeFile(diec, "#!/bin/sh\necho 'die 3.10'\n");
    await chmod(diec, 0o755);
    const error = await failure(
      { PATH: process.env.PATH, REA_DIE_COMMAND: diec },
      { path: "/bin/true" },
    );
    expect(error._tag).toBe("AnalysisCapabilityUnavailableError");
    expect(error.message).toContain("Unsupported diec version banner");
    expect(error.diagnostics).toMatchObject({ observed_banner: "die 3.10" });
  });

  it.skipIf(!realDie)(
    "reports directories and oversized files as typed input failures",
    async () => {
      const environment = { ...process.env, REA_DIE_PYTHON: realPython };
      const root = await createTestTempDirectory("rea-die-input-");
      const directory = await failure(environment, { path: root });
      expect(directory._tag).toBe("AnalysisInputError");
      const path = join(root, "large.bin");
      await writeFile(path, Buffer.alloc(4096));
      const large = await failure(environment, { path, max_file_bytes: 1024 });
      expect(large).toMatchObject({
        _tag: "AnalysisResourceConstraintError",
        resource: "file-size",
      });
    },
  );
});
