import { copyFile, writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { expect } from "vitest";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { expandToolAvailability } from "../../../src/contracts/toolOutputSchemaPrimitives.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { mcpTest, type TestMcp } from "../../support/mcp/mcpFixture.js";

const realPython = process.env.REA_VERIFY_DIE_PYTHON ?? "";
const realDie =
  process.platform === "linux" &&
  process.arch === "x64" &&
  isAbsolute(realPython);

const connect = async (mcp: TestMcp, environment: NodeJS.ProcessEnv) => {
  const session = createTestBinarySession(() => {
    throw new Error("DiE identification must not start a deep provider");
  });
  const client = await mcp.connect(
    createServer({ kind: "session", session }, { environment }),
  );
  return { client, session };
};

mcpTest(
  "advertises detect_file_signatures and names missing DiE configuration",
  async ({ mcp }) => {
    const { client, session } = await connect(mcp, { PATH: process.env.PATH });
    try {
      const advertised = (await client.listTools()).tools.find(
        (tool) => tool.name === "detect_file_signatures",
      );
      expect(advertised?.annotations).toMatchObject({
        readOnlyHint: false,
        destructiveHint: false,
      });
      const response = await client.callTool({
        name: "detect_file_signatures",
        arguments: { path: "/bin/true" },
      });
      expect(response.isError).toBe(true);
      expect(parseMcpToolError(response).error).toMatchObject({
        code: "capability_unavailable",
      });
      const relative = await client.callTool({
        name: "detect_file_signatures",
        arguments: { path: "true", database: "/tmp/db" },
      });
      expect(parseMcpToolError(relative).error).toMatchObject({
        code: "invalid_request",
      });
    } finally {
      await session.close();
    }
  },
);

const fileSignaturesAvailability = async (
  client: Awaited<ReturnType<typeof connect>>["client"],
) =>
  expandToolAvailability(
    toolContract("binary_session").outputSchema.parse(
      (await client.callTool({ name: "binary_session", arguments: {} }))
        .structuredContent,
    ).result.tool_availability,
  ).find((tool) => tool.name === "detect_file_signatures");

mcpTest.skipIf(process.platform !== "linux" || process.arch !== "x64")(
  "reports REA_DIE_COMMAND as unavailable and refuses it as an unverified backend",
  async ({ mcp }) => {
    const root = await createTestTempDirectory("rea-die-mcp-diec-");
    const python = join(root, "python");
    // Authored executable: discovery and refusal must not run it.
    await writeFile(python, "#!/bin/sh\nexit 99\n", { mode: 0o755 });
    const available = await connect(mcp, {
      PATH: process.env.PATH,
      REA_DIE_PYTHON: python,
    });
    try {
      expect(await fileSignaturesAvailability(available.client)).toMatchObject({
        available: true,
      });
    } finally {
      await available.session.close();
    }
    const { client, session } = await connect(mcp, {
      PATH: process.env.PATH,
      REA_DIE_COMMAND: join(root, "diec"),
      REA_DIE_PYTHON: python,
    });
    try {
      expect(await fileSignaturesAvailability(client)).toMatchObject({
        available: false,
        reason: "provider_missing",
        remediation: expect.stringContaining("leave REA_DIE_COMMAND unset"),
      });
      const response = await client.callTool({
        name: "detect_file_signatures",
        arguments: { path: python },
      });
      expect(response.isError).toBe(true);
      const { error } = parseMcpToolError(response);
      expect(error).toMatchObject({
        code: "capability_unavailable",
        details: {
          diagnostics: {
            configuration_key: "REA_DIE_COMMAND",
            admitted_backends: "die-python",
          },
        },
      });
      expect(error.message).toContain("unverified DiE backend");
    } finally {
      await session.close();
    }
  },
);

mcpTest.skipIf(!realDie)(
  "identifies an ELF with real die-python and validates the advertised output",
  async ({ mcp }) => {
    const { client, session } = await connect(mcp, {
      ...process.env,
      REA_DIE_PYTHON: realPython,
    });
    try {
      const root = await createTestTempDirectory("rea-die-mcp-");
      const path = join(root, "true");
      await copyFile("/bin/true", path);
      const response = await client.callTool({
        name: "detect_file_signatures",
        arguments: { path, verbose: true },
      });
      expect(response.isError, JSON.stringify(response.content)).not.toBe(true);
      const evidence = toolContract(
        "detect_file_signatures",
      ).outputSchema.parse(response.structuredContent);
      expect(evidence.normalized_result.file_parts[0]?.file_type).toBe("ELF64");
      expect(evidence.normalized_result.scan.verbose).toBe(true);
      expect(evidence.normalized_result.tool_profile.backend).toBe(
        "die-python",
      );
    } finally {
      await session.close();
    }
  },
);
