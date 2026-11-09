import { z } from "zod";

import { err, ok, type Result } from "../../domain/result.js";
import type { FileSignatures } from "../../domain/native/fileSignatures.js";
import { DIE_LIMITS } from "./DieRelease.js";

type FilePart = FileSignatures["file_parts"][number];
type Detection = FileSignatures["detections"][number];

/** DiE's file-part tree flattened in document order. */
export interface DieResultDocument {
  readonly file_parts: readonly FilePart[];
  readonly detections: readonly Detection[];
}

/** Leaf record written by DiE's ScanItemModel JSON serializer. */
const leafSchema = z.strictObject({
  type: z.string(),
  name: z.string(),
  version: z.string(),
  info: z.string(),
  string: z.string(),
});

/**
 * File-part record. DiE 3.09's console writes `filetype`, `parentfilepart`
 * and `values`; die-python 0.5.0 also writes `info`, `offset` and `size`.
 */
const groupSchema = z.strictObject({
  filetype: z.string(),
  parentfilepart: z.string(),
  info: z.string().optional(),
  offset: z.string().optional(),
  size: z.string().optional(),
  values: z.array(z.unknown()),
});

const rootSchema = z.strictObject({ detects: z.array(z.unknown()) });

const HEURISTIC_PREFIX = "(Heuristic)";

/** DiE's createResultString2 rendering of one record, without the heuristic prefix. */
const renderedLabel = (leaf: z.output<typeof leafSchema>): string =>
  `${leaf.type}: ${leaf.name}` +
  (leaf.version === "" ? "" : `(${leaf.version})`) +
  (leaf.info === "" ? "" : `[${leaf.info}]`);

/**
 * Parse one complete DiE JSON result document. The heuristic marker exists
 * only in DiE's rendered label, so it is derived here once; a label that does
 * not match the documented rendering is retained verbatim with unknown status.
 */
export const parseDieResultDocument = (
  text: string,
): Result<DieResultDocument, string> => {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (cause: unknown) {
    return err(
      `DiE result is not JSON: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
  const root = rootSchema.safeParse(value);
  if (!root.success) return err("DiE result does not contain a detects array.");
  const fileParts: FilePart[] = [];
  const detections: Detection[] = [];
  const visit = (
    items: readonly unknown[],
    parent: number | null,
    path: string,
    depth: number,
  ): string | undefined => {
    if (depth > DIE_LIMITS.maxDepth)
      return `DiE file parts are nested deeper than ${String(DIE_LIMITS.maxDepth)} levels at ${path}.`;
    for (const [index, item] of items.entries()) {
      const location = `${path}[${String(index)}]`;
      const group = groupSchema.safeParse(item);
      if (group.success) {
        if (fileParts.length >= DIE_LIMITS.maxFileParts)
          return `DiE reported more than ${String(DIE_LIMITS.maxFileParts)} file parts.`;
        const id = fileParts.length;
        fileParts.push({
          id,
          parent,
          file_type: group.data.filetype,
          part: group.data.parentfilepart,
          offset: group.data.offset ?? null,
          size: group.data.size ?? null,
          info: group.data.info ?? null,
        });
        const nested = visit(
          group.data.values,
          id,
          `${location}.values`,
          depth + 1,
        );
        if (nested !== undefined) return nested;
        continue;
      }
      const leaf = leafSchema.safeParse(item);
      if (!leaf.success)
        return `DiE record at ${location} is neither a file part nor a detection.`;
      if (detections.length >= DIE_LIMITS.maxDetections)
        return `DiE reported more than ${String(DIE_LIMITS.maxDetections)} detections.`;
      const rendered = renderedLabel(leaf.data);
      const heuristic =
        leaf.data.string === rendered
          ? false
          : leaf.data.string === HEURISTIC_PREFIX + rendered
            ? true
            : null;
      detections.push({
        file_part: parent,
        type: leaf.data.type,
        name: leaf.data.name,
        version: leaf.data.version,
        info: leaf.data.info,
        heuristic,
        ...(heuristic === null ? { label: leaf.data.string } : {}),
      });
    }
    return undefined;
  };
  const failure = visit(root.data.detects, null, "detects", 0);
  return failure === undefined
    ? ok({ file_parts: fileParts, detections })
    : err(failure);
};

/**
 * Split diec stdout into its indented JSON document and surrounding DiE
 * messages. DiE 3.09 prints script errors and info messages as plain lines
 * around the document; Qt's indented writer starts and ends the top-level
 * object on unindented `{` and `}` lines, and JSON strings cannot contain a
 * raw line break.
 */
export const splitDiecOutput = (
  stdout: string,
): Result<{ document: string; messages: string[] }, string> => {
  const lines = stdout.split(/\r?\n/u);
  const start = lines.indexOf("{");
  if (start === -1) return err("diec printed no JSON result document.");
  const end = lines.indexOf("}", start + 1);
  if (end === -1)
    return err("diec printed an incomplete JSON result document.");
  const messages = [...lines.slice(0, start), ...lines.slice(end + 1)].filter(
    (line) => line.trim() !== "",
  );
  return ok({
    document: lines.slice(start, end + 1).join("\n"),
    messages,
  });
};
