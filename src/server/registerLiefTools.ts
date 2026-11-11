import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { LiefInspectionService } from "../application/lief/LiefInspectionService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { liefInspectionModule } from "../composition/lief.js";
import type { Logger } from "pino";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { applicationToolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Bind the named LIEF contract to shared validation and session Evidence recording. */
export const registerLiefTools = (
  server: EvidenceMcpServer,
  service: Pick<LiefInspectionService, "inspect">,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const contract = liefInspectionModule.contract;
  const handler = createEvidenceToolHandler(
    server,
    (input, options) => service.inspect(input, options),
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  server.registerTool(
    contract.name,
    applicationToolRegistrationOptions(contract),
    handler(contract),
  );
};
