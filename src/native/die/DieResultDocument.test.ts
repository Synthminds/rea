import { expect, it } from "vitest";

import {
  parseDieResultDocument,
  splitDiecOutput,
} from "./DieResultDocument.js";

const parsed = (text: string) => {
  const result = parseDieResultDocument(text);
  if (!result.ok) throw new Error(result.error);
  return result.value;
};

// Recorded die-python 0.5.0 (DiE 3.09, dielib 0.1.0) output for /bin/true on
// Ubuntu 24.04 x86-64 with no scan flags.
const RECORDED_ELF = `{
    "detects": [
        {
            "filetype": "ELF64",
            "info": "",
            "offset": "0",
            "parentfilepart": "Header",
            "size": "26936",
            "values": [
                {
                    "info": "DYN AMD64-64",
                    "name": "GLIBC",
                    "string": "Library: GLIBC(2.4)[DYN AMD64-64]",
                    "type": "Library",
                    "version": "2.4"
                }
            ]
        }
    ]
}`;

// Recorded die-python 0.5.0 output with recursive scan for a generated PE64
// image followed by a one-file ZIP overlay.
const RECORDED_OVERLAY = `{
    "detects": [
        {
            "filetype": "PE64",
            "info": "",
            "offset": "0",
            "parentfilepart": "Header",
            "size": "2230",
            "values": [
                {
                    "info": "100.0%,1 file",
                    "name": "Zip",
                    "string": "Archive: Zip(1.0)[100.0%,1 file]",
                    "type": "Archive",
                    "version": "1.0"
                },
                {
                    "filetype": "ZIP",
                    "info": "",
                    "offset": "0",
                    "parentfilepart": "Overlay",
                    "size": "182",
                    "values": [
                        {
                            "info": "",
                            "name": "Unknown",
                            "string": "Unknown: Unknown",
                            "type": "Unknown",
                            "version": ""
                        }
                    ]
                }
            ]
        }
    ]
}`;

it("flattens recorded die-python file parts and derives the heuristic marker", () => {
  expect(parsed(RECORDED_ELF)).toEqual({
    file_parts: [
      {
        id: 0,
        parent: null,
        file_type: "ELF64",
        part: "Header",
        offset: "0",
        size: "26936",
        info: "",
      },
    ],
    detections: [
      {
        file_part: 0,
        type: "Library",
        name: "GLIBC",
        version: "2.4",
        info: "DYN AMD64-64",
        heuristic: false,
      },
    ],
  });
});

it("keeps nested overlay parts and their own detections in document order", () => {
  const document = parsed(RECORDED_OVERLAY);
  expect(
    document.file_parts.map(({ id, parent, file_type, part }) => ({
      id,
      parent,
      file_type,
      part,
    })),
  ).toEqual([
    { id: 0, parent: null, file_type: "PE64", part: "Header" },
    { id: 1, parent: 0, file_type: "ZIP", part: "Overlay" },
  ]);
  expect(
    document.detections.map(({ file_part, type, name }) => ({
      file_part,
      type,
      name,
    })),
  ).toEqual([
    { file_part: 0, type: "Archive", name: "Zip" },
    { file_part: 1, type: "Unknown", name: "Unknown" },
  ]);
});

it("marks DiE's heuristic rendering and retains an unrecognized label verbatim", () => {
  // Authored records following DiE 3.09 createResultString2; not recorded output.
  const leaf = (string: string) => ({
    type: "Packer",
    name: "UPX",
    version: "4.24",
    info: "NRV,brute",
    string,
  });
  const document = parsed(
    JSON.stringify({
      detects: [
        {
          filetype: "PE32",
          parentfilepart: "Header",
          values: [
            leaf("(Heuristic)Packer: UPX(4.24)[NRV,brute]"),
            leaf("Packer: UPX 4.24"),
          ],
        },
      ],
    }),
  );
  expect(document.file_parts[0]).toMatchObject({
    offset: null,
    size: null,
    info: null,
  });
  expect(document.detections).toEqual([
    expect.objectContaining({ heuristic: true }),
    expect.objectContaining({ heuristic: null, label: "Packer: UPX 4.24" }),
  ]);
  expect(document.detections[0]).not.toHaveProperty("label");
});

it("rejects documents that are not DiE detection trees", () => {
  for (const [text, reason] of [
    ["not json", "not JSON"],
    ['{"values": []}', "detects array"],
    ['{"detects": [{"filetype": "PE32"}]}', "neither a file part"],
    [
      '{"detects": [{"type": "A", "name": "B", "version": "", "info": "", "string": "A: B", "extra": 1}]}',
      "neither a file part",
    ],
  ] as const) {
    const result = parseDieResultDocument(text);
    expect(result.ok ? undefined : result.error).toContain(reason);
  }
});

it("bounds file-part nesting before walking deeper", () => {
  let value: unknown = {
    type: "Format",
    name: "x",
    version: "",
    info: "",
    string: "Format: x",
  };
  for (let depth = 0; depth < 70; depth += 1)
    value = { filetype: "Binary", parentfilepart: "Region", values: [value] };
  const result = parseDieResultDocument(JSON.stringify({ detects: [value] }));
  expect(result.ok ? undefined : result.error).toContain("deeper than 64");
});

it("separates diec messages from its indented JSON document", () => {
  // Authored framing controls for DiE 3.09 console printing; not recorded diec output.
  const split = splitDiecOutput(
    `info line\n{\n    "detects": [\n    ]\n}\n\nscript error\n`,
  );
  expect(split).toEqual({
    ok: true,
    value: {
      document: '{\n    "detects": [\n    ]\n}',
      messages: ["info line", "script error"],
    },
  });
  expect(splitDiecOutput("Cannot find: /x\n")).toMatchObject({ ok: false });
  expect(splitDiecOutput('{\n  "detects": []\n')).toMatchObject({
    ok: false,
  });
});

it.each([
  [
    "a bare document before the real one",
    '{\n"detects":[]\n}\n{\n    "detects": [\n        {"type":"P","name":"U","version":"","info":"","string":"P: U"}\n    ]\n}\n',
  ],
  ["an unindented nested object", '{\n"detects":[\n{\n}\n]\n}\n'],
  [
    "a bare brace message after the document",
    '{\n    "detects": [\n    ]\n}\n}\n',
  ],
  ["a closing brace before the document", '}\n{\n    "detects": []\n}\n'],
])("refuses diec output with %s", (_case, stdout) => {
  // Authored framing controls; a real diec prints one indented document.
  const split = splitDiecOutput(stdout);
  expect(split.ok).toBe(false);
  expect(split.ok ? undefined : split.error).toMatch(
    /exactly one indented JSON result document|incomplete JSON result document/u,
  );
});
