import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { LiefInspectionPort } from "./LiefInspectionPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createAnalysisExecutionEvidence } from "../../domain/analysisObservation.js";
import type { Evidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import {
  inspectWithLiefInputSchema,
  liefInspectionSchema,
} from "../../domain/lief/liefInspection.js";
import { err, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";

const OPERATION = "inspect_with_lief";

/** Shared CLI/MCP validation and Evidence composition for LIEF structure reads. */
export class LiefInspectionService {
  constructor(readonly provider: LiefInspectionPort) {}

  close(): Promise<void> {
    return this.provider.close();
  }

  async inspect(
    raw: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(OPERATION, { cause: options.signal.reason }),
      );
    const input = inspectWithLiefInputSchema.safeParse(raw);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, raw, {
          cause: input.error,
        }),
      );
    const inspected = await this.provider.inspect(input.data, options);
    if (!inspected.ok) return inspected;
    const execution = inspected.value;
    const report = liefInspectionSchema.safeParse(execution.result);
    if (
      !report.success ||
      report.data.artifact.path !== input.data.path ||
      report.data.operation !== input.data.operation ||
      execution.subject?.path !== input.data.path ||
      execution.subject.sha256 !== report.data.artifact.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "LIEF provider returned malformed evidence or changed the selected artifact identity or operation.",
          report.success
            ? { capturedOutput: report.data.diagnostics }
            : undefined,
        ),
      );
    return completeProviderEvidence(
      createAnalysisExecutionEvidence(
        OPERATION,
        input.data,
        execution,
        "observed",
      ),
      options?.signal,
      report.data.diagnostics,
    );
  }
}
