import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it, onTestFinished } from "vitest";

import { createAnalysisExecution } from "../../../src/application/AnalysisProvider.js";
import { LiefInspectionService } from "../../../src/application/lief/LiefInspectionService.js";
import { TOOL_EFFECTS } from "../../../src/contracts/toolEffects.js";
import {
  liefInspectionSchema,
  type InspectWithLiefInput,
} from "../../../src/domain/lief/liefInspection.js";
import { ok } from "../../../src/domain/result.js";
import { createServer } from "../../../src/server/createServer.js";
import {
  advertisedMcpToolSchemas,
  assertRecordedMcpEvidence,
} from "../../fixtures/advertisedMcpTool.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";

const PATH = "/artifacts/application.exe";
const SHA256 = "a".repeat(64);

const report = liefInspectionSchema.parse({
  artifact: { path: PATH, sha256: SHA256, bytes: 2560 },
  artifact_after: { sha256: SHA256, changed: false },
  provider: {
    lief_version: "1.0.0-test",
    admitted_release: "1.0",
    python_executable: "/opt/lief/bin/python",
    python_version: "3.13.0",
  },
  operation: "summary",
  format: "pe",
  macho: null,
  summary: {
    architecture: "X86_64",
    bits: 64,
    endianness: "little",
    object_type: "EXECUTABLE",
    entrypoint: "0x140001000",
    imagebase: "0x140000000",
    counts: {
      sections: 3,
      segments: null,
      imports: 2,
      exports: 0,
      libraries: 1,
    },
    libraries: ["example.dll"],
    elf: null,
    pe: {
      machine: "AMD64",
      timestamp: 0,
      characteristics: ["EXECUTABLE_IMAGE"],
      magic: "PE32_PLUS",
      subsystem: "WINDOWS_CUI",
      dll_characteristics: ["NX_COMPAT"],
      address_of_entrypoint: "0x1000",
      sizeof_image: "0x4000",
      data_directory_count: 16,
      data_directories: [
        {
          type: "IMPORT_TABLE",
          rva: "0x2000",
          size: "0x28",
          section: ".rdata",
        },
      ],
      rich_header: null,
      signatures: { present: false, count: 0 },
      export_name: null,
    },
    macho: null,
  },
  sections: null,
  segments: null,
  imports: null,
  exports: null,
  coverage: {
    model: "lief-parsed",
    applicable: true,
    parser_diagnostics: "none",
  },
  resource_limits: {
    address_space_bytes: 4294967296,
    file_size_bytes: 34603008,
    core_file_bytes: 0,
  },
  diagnostics: { stdout: "", stderr: "", truncated: false },
  limitations: ["Test provider limitation."],
});

it("advertises a closed read-only contract and records inline LIEF Evidence without a binary target", async () => {
  const received: InspectWithLiefInput[] = [];
  let closed = false;
  const service = new LiefInspectionService({
    inspect: (input) => {
      received.push(input);
      return Promise.resolve(
        ok(
          createAnalysisExecution(
            report,
            {
              id: "lief",
              name: "REA LIEF adapter",
              version: "lief@1.0.0-test",
            },
            {
              subject: { path: PATH, sha256: SHA256, format: "pe" },
              locations: [{ kind: "artifact-path", path: PATH }],
              limitations: report.limitations,
            },
          ),
        ),
      );
    },
    close: async () => {
      closed = true;
    },
  });
  const session = createTestBinarySession(() => {
    throw new Error("deep provider must not start");
  });
  const server = createServer(
    { kind: "session", session },
    { liefInspection: service },
  );
  const client = new Client({ name: "lief-contract", version: "1" });
  onTestFinished(async () => {
    await client.close();
    await server.close();
    expect(closed).toBe(true);
    await session.close();
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  const schemas = await advertisedMcpToolSchemas(client, "inspect_with_lief");
  const { ajv, inputSchema } = schemas;
  expect(ajv.validate(inputSchema, { path: PATH })).toBe(true);
  expect(
    ajv.validate(inputSchema, { path: PATH, operation: "exports", limit: 50 }),
  ).toBe(true);
  expect(ajv.validate(inputSchema, { path: "relative.exe" })).toBe(false);
  expect(ajv.validate(inputSchema, { path: PATH, operation: "patch" })).toBe(
    false,
  );
  expect(ajv.validate(inputSchema, { path: PATH, write: true })).toBe(false);
  expect(schemas.toolDefinition.annotations).toMatchObject({
    destructiveHint: false,
  });
  expect(TOOL_EFFECTS.inspect_with_lief).toMatchObject({
    mutatesTarget: false,
    executesForeignCode: false,
    launchesProcess: true,
  });

  assertRecordedMcpEvidence(
    await client.callTool({
      name: "inspect_with_lief",
      arguments: { path: PATH },
    }),
    "inspect_with_lief",
    schemas,
    session,
    report,
    "observed",
  );
  expect(received).toEqual([
    { path: PATH, operation: "summary", max_file_bytes: 268435456 },
  ]);

  const refused = await client.callTool({
    name: "inspect_with_lief",
    arguments: { path: PATH, offset: 2 },
  });
  expect(refused.isError).toBe(true);
  expect(JSON.stringify(refused.content)).toContain(
    "offset applies only to sections, segments, imports and exports",
  );
  expect(received).toHaveLength(1);
});
