import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectWithLiefInput } from "../../domain/lief/liefInspection.js";
import type { Result } from "../../domain/result.js";

/** Replaceable LIEF adapter; owns its helper process, private copy and reply parsing. */
export interface LiefInspectionPort {
  /** Release per-call resources before returning, or retain failed cleanup for close/retry. */
  inspect(
    input: InspectWithLiefInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
  close(): Promise<void>;
}
