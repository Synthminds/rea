import { expect, it, vi } from "vitest";

import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { DestinationRefusedError } from "../../browser/network/PublicNetwork.js";
import {
  DEFAULT_STATE_INTAKE,
  fetchStateDocument,
  partDocument,
  STATE_FETCH_TIMEOUT_MS,
} from "./stateIntake.js";

const vetted = vi.hoisted(() => ({ calls: [] as unknown[][] }));

// Record the default fetcher's request options while keeping the real vetting.
vi.mock("../../browser/network/PublicNetwork.js", async (importOriginal) => {
  const actual =
    await importOriginal<
      typeof import("../../browser/network/PublicNetwork.js")
    >();
  return {
    ...actual,
    vettedFetch: (...args: Parameters<typeof actual.vettedFetch>) => {
      vetted.calls.push(args);
      return actual.vettedFetch(...args);
    },
  };
});

it("downloads through the vetted fetch with redirects refused and the 30 s timeout by default", async () => {
  // The default fetcher vets the host and connects only to the vetted
  // address; it never reaches the ambient global fetch.
  const fetched = vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValue(new Response("{}"));
  try {
    expect(DEFAULT_STATE_INTAKE).toEqual({
      fetchState: fetchStateDocument,
      timeoutMs: 30_000,
    });
    const url = new URL("https://127.0.0.1/state.json");
    const signal = AbortSignal.timeout(STATE_FETCH_TIMEOUT_MS);
    await expect(fetchStateDocument(url, signal)).rejects.toBeInstanceOf(
      DestinationRefusedError,
    );
    expect(vetted.calls.at(-1)).toEqual([url, { signal, redirect: "error" }]);
    expect(fetched).not.toHaveBeenCalled();
  } finally {
    fetched.mockRestore();
  }
});

it.each([
  ["https://127.0.0.1/state.json", "loopback"],
  ["https://169.254.169.254/latest/meta-data/", "link-local"],
  ["https://[::ffff:7f00:1]/state.json", "ipv4-mapped"],
  ["https://[fd00::1]/state.json", "unique-local"],
  ["https://0x0a000001/state.json", "private"],
  ["https://localhost/state.json", "localhost-name"],
])(
  "refuses %s as non-public-address without echoing the uri",
  async (uri, addressClass) => {
    const result = await partDocument(
      { kind: "file", file: { uri, mimeType: "application/json" } },
      DEFAULT_STATE_INTAKE,
      new AbortController().signal,
      new ArtifactResourceScope(),
    );
    expect(result).toEqual({
      ok: false,
      error: {
        code: -32000,
        message: `the state document was not downloaded: its host is not a public address (${addressClass})`,
        data: { reason: "non-public-address" },
      },
    });
  },
);
