import { createHash } from "node:crypto";
import { open } from "node:fs/promises";

import { NonRegularFileReadError } from "../filesystem/RegularFile.js";
import { sameRegularFileState } from "../filesystem/RegularFile.js";
import {
  assertArtifactReadActive,
  mapArtifactFileFailure,
  withArtifactFileHandle,
  withArtifactRegularFile,
} from "./ArtifactFileOperation.js";
import { ArtifactReaderFailure } from "./ArtifactReader.js";
import type { ArtifactResourceScope } from "./ArtifactResourceScope.js";
import { readArtifactFileChunks } from "./readArtifactFileChunks.js";

/** The destination of a stable copy could not be written; the source was not at fault. */
export class StableCopyDestinationFailure extends Error {
  constructor(
    readonly destination: string,
    options: ErrorOptions,
  ) {
    super(`Private copy could not be written: ${destination}`, options);
  }
}

/**
 * Stream one regular file, without following a symlink, into a new read-only
 * file and require exactly the bytes of an earlier stable digest. Neither file
 * is held in memory. A changed, replaced or non-regular source fails as an
 * `integrity` read failure; both descriptors are owned by `resources`.
 */
export const copyStableArtifact = async (
  source: string,
  destination: string,
  expected: { readonly sha256: string; readonly bytes: number },
  signal: AbortSignal | undefined,
  resources: ArtifactResourceScope,
): Promise<void> => {
  try {
    await withArtifactRegularFile(
      source,
      resources,
      signal,
      async (input) => {
        const initial = await input.stat({ bigint: true });
        if (initial.size !== BigInt(expected.bytes))
          throw new ArtifactReaderFailure(
            "integrity",
            `Artifact changed before REA copied it: ${source}`,
          );
        assertArtifactReadActive(signal);
        let output;
        try {
          output = await open(destination, "wx", 0o600);
        } catch (cause: unknown) {
          throw new StableCopyDestinationFailure(destination, { cause });
        }
        await withArtifactFileHandle(
          destination,
          output,
          resources,
          signal,
          async (file) => {
            const hash = createHash("sha256");
            const chunks = readArtifactFileChunks(input, {
              end: initial.size,
              ...(signal === undefined ? {} : { signal }),
            });
            for await (const chunk of chunks) {
              assertArtifactReadActive(signal);
              try {
                // writeFile completes the whole chunk at the descriptor offset.
                await file.writeFile(chunk);
              } catch (cause: unknown) {
                throw new StableCopyDestinationFailure(destination, { cause });
              }
              hash.update(chunk);
            }
            const coverage = chunks.readCoverage();
            const after = await input.stat({ bigint: true });
            if (
              coverage.kind !== "complete" ||
              coverage.bytes !== initial.size ||
              !sameRegularFileState(initial, after) ||
              hash.digest("hex") !== expected.sha256
            )
              throw new ArtifactReaderFailure(
                "integrity",
                `Artifact changed while REA copied it: ${source}`,
              );
            await file.chmod(0o400);
            assertArtifactReadActive(signal);
          },
        );
      },
      "reject",
    );
  } catch (cause: unknown) {
    throw mapArtifactFileFailure(cause, classifySource(source));
  }
};

/** A source that is no longer the admitted regular file has changed. */
const classifySource =
  (source: string) =>
  (cause: unknown): unknown => {
    if (cause instanceof NonRegularFileReadError)
      return new ArtifactReaderFailure(
        "integrity",
        `Artifact is no longer a regular file: ${source}`,
        { cause },
      );
    if (
      cause instanceof Error &&
      "code" in cause &&
      ["ENOENT", "ENOTDIR", "ELOOP"].includes(String(cause.code))
    )
      return new ArtifactReaderFailure(
        "integrity",
        `Artifact changed before REA copied it: ${source}`,
        { cause },
      );
    return cause;
  };
