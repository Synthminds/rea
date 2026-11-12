import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { FileSignaturesPort } from "./FileSignaturesPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createAnalysisExecutionEvidence } from "../../domain/analysisObservation.js";
import type { Evidence } from "../../domain/evidence.js";
import {
  DEFAULT_FILE_SIGNATURE_COMMAND_TIMEOUT_MS,
  detectFileSignaturesInputSchema,
  fileSignaturesSchema,
} from "../../domain/native/fileSignatures.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";

const OPERATION = "detect_file_signatures";

/** Shared CLI/MCP validation and Evidence composition for static file identification. */
export class FileSignaturesService {
  constructor(readonly provider: FileSignaturesPort) {}

  /** Join provider cleanup during shutdown or an explicit retry. */
  close(): Promise<void> {
    return this.provider.close();
  }

  /** Bind the provider report to the caller-selected file and scan choices before publishing Evidence. */
  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(OPERATION, {
          cause: options.signal.reason,
        }),
      );
    const input = detectFileSignaturesInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    const inspected = await this.provider.inspect(input.data, options);
    if (!inspected.ok) return inspected;
    const execution = inspected.value;
    const report = fileSignaturesSchema.safeParse(execution.result);
    const { path, command_timeout_ms: timeoutMs, ...selected } = input.data;
    if (
      !report.success ||
      report.data.artifact.path !== path ||
      execution.subject.path !== path ||
      execution.subject.sha256 !== report.data.artifact.sha256 ||
      report.data.tool_profile.timeout_ms !==
        (timeoutMs ?? DEFAULT_FILE_SIGNATURE_COMMAND_TIMEOUT_MS) ||
      report.data.scan.deep_scan !== selected.deep_scan ||
      report.data.scan.heuristic_scan !== selected.heuristic_scan ||
      report.data.scan.recursive_scan !== selected.recursive_scan ||
      report.data.scan.verbose !== selected.verbose ||
      report.data.scan.all_types !== selected.all_types
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "DiE adapter returned malformed data or changed the selected file or scan options.",
        ),
      );
    return completeProviderEvidence(
      createAnalysisExecutionEvidence(
        OPERATION,
        input.data,
        { ...execution, result: report.data },
        "observed",
      ),
      options?.signal,
    );
  }
}
