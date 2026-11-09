import { z } from "incur";
import type { Logger } from "pino";

import { logCliCommand } from "../cliLogging.js";
import { liefInspectionModule } from "../composition/lief.js";
import {
  LIEF_OPERATIONS,
  inspectWithLiefInputSchema,
} from "../domain/lief/liefInspection.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import type { CliInstance } from "./types.js";

/** Inspect one operator-selected file through the same shared workflow as MCP. */
export const registerLiefCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv>,
): void => {
  const fields = inspectWithLiefInputSchema.shape;
  cli.command(liefInspectionModule.cliCommand, {
    description:
      "Inspect ELF, PE or Mach-O structure with caller-supplied LIEF, read-only",
    args: z.object({
      path: z.string().describe("Local ELF, PE or Mach-O file"),
      operation: z
        .enum(LIEF_OPERATIONS)
        .optional()
        .describe("summary (default), sections, segments, imports or exports"),
    }),
    options: z.object({
      offset: fields.offset,
      limit: fields.limit,
      machoSlice: fields.macho_slice,
      maxFileBytes: fields.max_file_bytes,
      commandTimeoutMs: fields.command_timeout_ms,
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) => {
        const service = liefInspectionModule.create(environment);
        return logCliCommand(logger, liefInspectionModule.cliCommand, () =>
          finishAnalysisCommand(
            () =>
              service.inspect(
                {
                  path: absoluteCallerPath(args.path),
                  ...(args.operation === undefined
                    ? {}
                    : { operation: args.operation }),
                  ...(options.offset === undefined
                    ? {}
                    : { offset: options.offset }),
                  ...(options.limit === undefined
                    ? {}
                    : { limit: options.limit }),
                  ...(options.machoSlice === undefined
                    ? {}
                    : { macho_slice: options.machoSlice }),
                  max_file_bytes: options.maxFileBytes,
                  ...(options.commandTimeoutMs === undefined
                    ? {}
                    : { command_timeout_ms: options.commandTimeoutMs }),
                },
                { signal },
              ),
            service,
            "lief",
            "inspect_with_lief",
            signal,
          ),
        );
      }),
  });
};
