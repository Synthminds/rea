import { createHash } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import { lstat, open, type FileHandle } from "node:fs/promises";
import { ArtifactReaderFailure } from "./ArtifactReader.js";
import type { ArtifactResourceScope } from "./ArtifactResourceScope.js";
import {
  withArtifactFileHandle,
  assertArtifactReadActive,
} from "./ArtifactFileOperation.js";

/** Exact physical read completed before descriptor finalization. */
export interface StableArtifactSnapshot {
  readonly bytes: Buffer;
  readonly sha256: string;
}

/** Filesystem boundary for stable reads, including deterministic replacement probes. */
export interface StableArtifactFileSystem {
  lstat(path: string): Promise<BigIntStats>;
  open(path: string, flags: number): Promise<FileHandle>;
}

const FILE_SYSTEM: StableArtifactFileSystem = {
  lstat: (path) => lstat(path, { bigint: true }),
  open,
};

const afterValidation = async <T>(
  path: string,
  stage: string,
  read: () => Promise<T>,
): Promise<T> => {
  try {
    return await read();
  } catch (cause) {
    if (
      cause instanceof Error &&
      "code" in cause &&
      ["ENOENT", "ENOTDIR", "ELOOP"].includes(String(cause.code))
    )
      throw new ArtifactReaderFailure(
        "integrity",
        `Artifact changed ${stage}: ${path}`,
        { cause },
      );
    throw cause;
  }
};

/**
 * Stream one bounded regular file to `sink`, rejecting replacement or in-place
 * changes. `complete` runs inside descriptor ownership so a failed close still
 * retains the completed result.
 */
const readStableChunks = async <Result>(
  path: string,
  maximumBytes: number,
  signal: AbortSignal | undefined,
  fileSystem: StableArtifactFileSystem,
  resourceScope: ArtifactResourceScope | undefined,
  sink: {
    readonly accept: (bytes: Buffer) => void;
    readonly complete: (count: number) => Result;
  },
): Promise<Result> => {
  assertArtifactReadActive(signal);
  const before = await fileSystem.lstat(path);
  if (!before.isFile() || before.isSymbolicLink())
    throw new ArtifactReaderFailure(
      "path",
      `Expected a regular file without a symlink: ${path}`,
    );
  if (before.size > BigInt(maximumBytes))
    throw new ArtifactReaderFailure(
      "limit",
      `Selected artifact exceeds ${String(maximumBytes)} bytes: ${path}`,
      { boundary: "file-size" },
    );
  const file = await afterValidation(path, "before open", () =>
    fileSystem.open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    ),
  );
  return withArtifactFileHandle(
    path,
    file,
    resourceScope,
    signal,
    async (file) => {
      const initial = await file.stat({ bigint: true });
      if (
        !initial.isFile() ||
        initial.dev !== before.dev ||
        initial.ino !== before.ino
      )
        throw new ArtifactReaderFailure(
          "integrity",
          `Artifact changed before open: ${path}`,
        );
      let count = 0;
      for await (const chunk of file.createReadStream({
        autoClose: false,
        highWaterMark: 65536,
      })) {
        assertArtifactReadActive(signal);
        const value: unknown = chunk;
        if (!Buffer.isBuffer(value))
          throw new ArtifactReaderFailure(
            "format",
            `Artifact stream did not return bytes: ${path}`,
          );
        const bytes = value;
        count += bytes.length;
        if (count > maximumBytes)
          throw new ArtifactReaderFailure(
            "limit",
            `Selected artifact grew beyond its byte limit: ${path}`,
            { boundary: "file-size" },
          );
        sink.accept(bytes);
      }
      const after = await file.stat({ bigint: true });
      const current = await afterValidation(path, "during read", () =>
        fileSystem.lstat(path),
      );
      if (
        [after, current].some(
          (stat) =>
            !stat.isFile() ||
            stat.dev !== initial.dev ||
            stat.ino !== initial.ino ||
            stat.size !== initial.size ||
            stat.mtimeNs !== initial.mtimeNs ||
            stat.ctimeNs !== initial.ctimeNs,
        ) ||
        BigInt(count) !== initial.size
      )
        throw new ArtifactReaderFailure(
          "integrity",
          `Artifact changed during read: ${path}`,
        );
      assertArtifactReadActive(signal);
      return sink.complete(count);
    },
  );
};

/** Read one bounded regular file and reject replacement or in-place changes. */
export const readStableArtifact = async (
  path: string,
  maximumBytes: number,
  signal?: AbortSignal,
  fileSystem: StableArtifactFileSystem = FILE_SYSTEM,
  resourceScope?: ArtifactResourceScope,
): Promise<StableArtifactSnapshot> => {
  const chunks: Buffer[] = [];
  return readStableChunks(
    path,
    maximumBytes,
    signal,
    fileSystem,
    resourceScope,
    {
      accept: (bytes) => chunks.push(bytes),
      complete: (count) => {
        const bytes = Buffer.concat(chunks, count);
        return {
          bytes,
          sha256: createHash("sha256").update(bytes).digest("hex"),
        };
      },
    },
  );
};

/** Digest one bounded regular file under the same checks without retaining its bytes. */
export const digestStableArtifact = async (
  path: string,
  maximumBytes: number,
  signal?: AbortSignal,
  fileSystem: StableArtifactFileSystem = FILE_SYSTEM,
  resourceScope?: ArtifactResourceScope,
): Promise<{ readonly sha256: string; readonly bytes: number }> => {
  const hash = createHash("sha256");
  return readStableChunks(
    path,
    maximumBytes,
    signal,
    fileSystem,
    resourceScope,
    {
      accept: (chunk) => hash.update(chunk),
      complete: (bytes) => ({ sha256: hash.digest("hex"), bytes }),
    },
  );
};
