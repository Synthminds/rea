import { LiefInspectionService } from "../application/lief/LiefInspectionService.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { INSPECT_WITH_LIEF_CONTRACT } from "../contracts/lief/liefToolContracts.js";
import { LiefInspectionProvider } from "../lief/LiefInspectionProvider.js";
import { liefHostSupported } from "../lief/LiefRelease.js";

export { liefHostSupported };

/** Compose the caller-supplied LIEF adapter without import-time I/O or acquisition. */
export const createLiefInspectionService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): LiefInspectionService =>
  new LiefInspectionService(new LiefInspectionProvider(environment));

/**
 * Static descriptor for the named LIEF operation and its lifetime. CLI/MCP
 * share this binding; the service keeps failed resource ownership so close can
 * be retried. Construction performs no acquisition or target I/O.
 */
export const liefInspectionModule = {
  contract: INSPECT_WITH_LIEF_CONTRACT,
  cliCommand: CLI_COMMANDS.inspectWithLief,
  create(
    environment: Readonly<NodeJS.ProcessEnv>,
    injected?: LiefInspectionService,
  ): Pick<LiefInspectionService, "inspect" | "close"> {
    const service = injected ?? createLiefInspectionService(environment);
    return {
      inspect: service.inspect.bind(service),
      close: service.close.bind(service),
    };
  },
} as const;
