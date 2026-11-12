import { expect, it } from "vitest";

import { createAnalysisExecution } from "../AnalysisProvider.js";
import type { FileSignaturesPort } from "./FileSignaturesPort.js";
import { FileSignaturesService } from "./FileSignaturesService.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type { FileSignatures } from "../../domain/native/fileSignatures.js";
import { ok } from "../../domain/result.js";

const path = "/artifacts/application.exe";
const sha256 = "a".repeat(64);
const report: FileSignatures = {
  artifact: { path, sha256, bytes: 2048 },
  artifact_after: { sha256, changed: false },
  scan: {
    deep_scan: false,
    heuristic_scan: true,
    recursive_scan: false,
    verbose: false,
    all_types: false,
  },
  file_parts: [
    {
      id: 0,
      parent: null,
      file_type: "PE64",
      part: "Header",
      offset: "0",
      size: "2048",
      info: "",
    },
  ],
  detections: [
    {
      file_part: 0,
      type: "Unknown",
      name: "Unknown",
      version: "",
      info: "",
      heuristic: false,
    },
  ],
  scan_messages: [],
  tool_profile: {
    backend: "die-python",
    configuration_key: "REA_DIE_PYTHON",
    executable: {
      path: "/opt/die/bin/python",
      resolved_path: "/usr/bin/python3.13",
      sha256: "b".repeat(64),
    },
    native_module: {
      path: "/opt/die/lib/python3.13/site-packages/die/_die.so",
      sha256: "d".repeat(64),
    },
    resource_limiter: {
      configured_path: "/usr/bin/prlimit",
      path: "/usr/bin/prlimit",
      sha256: "e".repeat(64),
      arguments: ["--fsize=0:0", "--", "/opt/die/bin/python"],
    },
    engine_version: "3.09",
    version_banner: null,
    package_version: "0.5.0",
    library_version: "0.1.0",
    library_tag: "tag",
    database: { source: "package-bundled", files: 1, sha256: "c".repeat(64) },
    arguments: [],
    timeout_ms: 120000,
    output_budget_bytes: 16777216,
    resource_limits: {
      address_space_bytes: 1,
      cpu_seconds: 1,
      file_bytes: 0,
    },
  },
  target_execution: "not-performed",
};

const port = (
  result: FileSignatures,
  onInspect: () => void = () => undefined,
): FileSignaturesPort & { calls: number } => {
  const recording = {
    calls: 0,
    close: () => Promise.resolve(),
    inspect: () => {
      recording.calls += 1;
      onInspect();
      return Promise.resolve(
        ok(
          createAnalysisExecution(
            result,
            { id: "detect-it-easy", name: "DiE", version: null },
            {
              subject: {
                path: result.artifact.path,
                format: "file",
                sha256: result.artifact.sha256,
              },
              limitations: ["Detections are leads."],
            },
          ),
        ),
      );
    },
  };
  return recording;
};

it("rejects relative paths and unknown options before the provider runs", async () => {
  const recording = port(report);
  const service = new FileSignaturesService(recording);
  for (const input of [
    { path: "application.exe" },
    { path, script: "/tmp/custom.sg" },
    { path, database: "/tmp/db" },
  ]) {
    const result = await service.inspect(input);
    expect(result.ok ? undefined : result.error).toBeInstanceOf(
      AnalysisInputError,
    );
  }
  expect(recording.calls).toBe(0);
});

it("publishes observed Evidence bound to the selected file and scan options", async () => {
  const result = await new FileSignaturesService(port(report)).inspect({
    path,
    heuristic_scan: true,
  });
  if (!result.ok) throw result.error;
  expect(result.value).toMatchObject({
    confidence: "observed",
    parameters: { path, heuristic_scan: true, deep_scan: false },
    normalized_result: report,
    limitations: ["Detections are leads."],
  });
});

it("rejects a report for other scan options or another file", async () => {
  for (const [input, value] of [
    [{ path }, report],
    [
      { path, heuristic_scan: true },
      { ...report, artifact: { ...report.artifact, path: "/other" } },
    ],
    [{ path, heuristic_scan: true, command_timeout_ms: 5 }, report],
  ] as const) {
    const result = await new FileSignaturesService(port(value)).inspect(input);
    expect(result.ok ? undefined : result.error).toBeInstanceOf(
      AnalysisOutputError,
    );
  }
});

it("discards an observation when the caller cancels as the provider completes", async () => {
  const controller = new AbortController();
  const result = await new FileSignaturesService(
    port(report, () => controller.abort()),
  ).inspect({ path, heuristic_scan: true }, { signal: controller.signal });
  expect(result.ok ? undefined : result.error).toBeInstanceOf(
    AnalysisCancelledError,
  );
});
