import { vettedFetch } from "../browser/network/PublicNetwork.js";

/** Maximum admitted vendor response bytes, shared by Hopper setup adapters. */
export const HOPPER_DOWNLOAD_BYTES = 100_000_000;

/** Bound observed response bytes before retaining them, including chunked bodies. */
export const downloadHopperPackage = async (
  url: string,
  options: {
    readonly signal?: AbortSignal;
    readonly maxBytes?: number;
    readonly timeoutMs?: number;
  } = {},
): Promise<{ readonly ok: boolean; readonly bytes: Uint8Array }> => {
  const timeoutMs = options.timeoutMs ?? 120_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000)
    throw new RangeError("Invalid Hopper response time budget");
  const deadline = AbortSignal.timeout(timeoutMs);
  const maxBytes = options.maxBytes ?? HOPPER_DOWNLOAD_BYTES;
  if (
    !Number.isSafeInteger(maxBytes) ||
    maxBytes < 1 ||
    maxBytes > HOPPER_DOWNLOAD_BYTES
  )
    throw new RangeError("Invalid Hopper response byte budget");
  // Callers pass only the vendor's fixed URLs or feed filenames validated to
  // the https://www.hopperapp.com origin, TLS authenticates that host, and the
  // package is signature- and hash-verified before use. The vendor still
  // chooses redirects, so the private-network policy
  // (src/domain/networkDestination.ts) vets the first hop and every redirect
  // hop: a 30x to a private or metadata address is refused, never requested.
  const response = await vettedFetch(url, {
    redirect: "follow",
    headers: { accept: "application/json", "user-agent": "rea-installer" },
    signal:
      options.signal === undefined
        ? deadline
        : AbortSignal.any([options.signal, deadline]),
  });
  const refused = { ok: false, bytes: new Uint8Array() };
  if (
    !response.ok ||
    Number(response.headers.get("content-length")) > maxBytes
  ) {
    await response.body?.cancel();
    return refused;
  }
  if (response.body === null) return { ok: true, bytes: new Uint8Array() };
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) return { ok: true, bytes: Buffer.concat(chunks, bytes) };
      if (chunk.value.byteLength > maxBytes - bytes) {
        await reader.cancel();
        return refused;
      }
      chunks.push(chunk.value);
      bytes += chunk.value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
};
