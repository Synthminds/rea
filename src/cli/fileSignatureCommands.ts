import { z } from "incur";
import type { Logger } from "pino";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { createFileSignaturesService } from "../composition/binaryDiagnostics.js";
import { detectFileSignaturesInputSchema } from "../domain/native/fileSignatures.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import type { CliInstance } from "./types.js";

const flags = detectFileSignaturesInputSchema.shape;

/** Identify an operator-selected file through the same DiE workflow as MCP. */
export const registerFileSignatureCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv>,
): void => {
  cli.command(CLI_COMMANDS.detectFileSignatures, {
    description:
      "Identify file type, compiler, linker, library and packer signatures with Detect It Easy",
    args: z.object({ path: z.string().describe("Local file") }),
    options: z.object({
      deepScan: flags.deep_scan,
      heuristicScan: flags.heuristic_scan,
      recursiveScan: flags.recursive_scan,
      verbose: flags.verbose,
      allTypes: flags.all_types,
      maxFileBytes: flags.max_file_bytes,
      commandTimeoutMs: flags.command_timeout_ms,
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) => {
        const service = createFileSignaturesService(environment);
        return await logCliCommand(
          logger,
          CLI_COMMANDS.detectFileSignatures,
          async () =>
            finishAnalysisCommand(
              () =>
                service.inspect(
                  {
                    path: absoluteCallerPath(args.path),
                    deep_scan: options.deepScan,
                    heuristic_scan: options.heuristicScan,
                    recursive_scan: options.recursiveScan,
                    verbose: options.verbose,
                    all_types: options.allTypes,
                    max_file_bytes: options.maxFileBytes,
                    ...(options.commandTimeoutMs === undefined
                      ? {}
                      : { command_timeout_ms: options.commandTimeoutMs }),
                  },
                  { signal },
                ),
              service,
              "detect-it-easy",
              "detect_file_signatures",
              signal,
            ),
        );
      }),
  });
};
