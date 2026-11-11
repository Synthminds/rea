import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { EvidenceSubjectTarget } from "../../domain/evidence.js";
import type { DetectFileSignaturesInput } from "../../domain/native/fileSignatures.js";
import type { Result } from "../../domain/result.js";

/** Successful identification must name the selected local file. */
export type FileSignaturesExecution = Omit<AnalysisExecution, "subject"> & {
  readonly subject: EvidenceSubjectTarget & { readonly format: "file" };
};

/** Replaceable static file-identification engine; it never executes the selected file. */
export interface FileSignaturesPort {
  /** Retry removal of retained workspaces and commands; failures keep ownership. */
  close(): Promise<void>;
  inspect(
    input: DetectFileSignaturesInput,
    options?: ExecutionOptions,
  ): Promise<Result<FileSignaturesExecution, AnalysisError>>;
}
