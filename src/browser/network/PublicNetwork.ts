import { lookup } from "node:dns/promises";
import {
  request as httpRequest,
  type IncomingMessage,
  type RequestOptions,
} from "node:http";
import { request as httpsRequest } from "node:https";
import type { LookupFunction } from "node:net";
import { pipeline, Readable, type Transform } from "node:stream";
import { createBrotliDecompress, createGunzip, createInflate } from "node:zlib";

import {
  allowedPrivateDestinations,
  destinationLabel,
  isUnresolved,
  refusalSentence,
  urlPort,
  vetDestination,
  type DestinationPolicy,
  type DestinationRefusal,
  type DestinationResolver,
  type VettedDestination,
} from "../../domain/networkDestination.js";

/** Every address the host resolver currently gives for a name, in resolver order. */
export const systemResolver: DestinationResolver = (hostname) =>
  lookup(hostname, { all: true, verbatim: true });

/** Public addresses only, plus the exact origins a caller explicitly allowed. */
export const destinationPolicy = (
  allowedPrivateOrigins: readonly string[] = [],
  resolve: DestinationResolver = systemResolver,
): DestinationPolicy => ({
  allowedPrivate: allowedPrivateDestinations(allowedPrivateOrigins),
  resolve,
});

/** A request REA refused because its destination is not a public internet address. */
export class DestinationRefusedError extends Error {
  override readonly name = "DestinationRefusedError";

  constructor(readonly refusal: DestinationRefusal) {
    super(refusalSentence(refusal));
  }
}

/**
 * Vet a URL's host and port. A non-public destination throws
 * `DestinationRefusedError`; a name with no vettable address throws the
 * TypeError fetch throws for a failed lookup, so callers keep reporting it as
 * a network failure.
 */
export const vetUrlDestination = async (
  url: URL,
  policy: DestinationPolicy,
): Promise<VettedDestination> => {
  const vetted = await vetDestination(url.hostname, urlPort(url), policy);
  if (vetted.ok) return vetted.value;
  const { host, port, reason } = vetted.error;
  if (isUnresolved(vetted.error))
    throw new TypeError("fetch failed", {
      cause: new Error(`${destinationLabel(host, port)}: ${reason}`),
    });
  throw new DestinationRefusedError(vetted.error);
};

/**
 * Answer the socket's lookup with the addresses vetted before the request
 * started, never a fresh resolution, so DNS rebinding cannot swap them.
 */
const pinnedLookup =
  (vetted: VettedDestination): LookupFunction =>
  (_hostname, options, callback) => {
    const family = typeof options.family === "number" ? options.family : 0;
    const candidates = vetted.addresses.filter(
      (address) => family === 0 || address.family === family,
    );
    const first = candidates[0];
    if (first === undefined) {
      callback(
        Object.assign(new Error("no vetted address for this family"), {
          code: "ENOTFOUND",
        }),
        "",
        0,
      );
      return;
    }
    if (options.all === true)
      (callback as (error: null, addresses: typeof candidates) => void)(
        null,
        candidates,
      );
    else callback(null, first.address, first.family);
  };

/** Fetch's redirect statuses; other 3xx answers carry their own meaning. */
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const NULL_BODY_STATUSES = new Set([101, 103, 204, 205, 304]);
const MAX_REDIRECTS = 20;

/** Decode the content codings fetch decodes; `pipeline` carries a socket failure into the decoder. */
const decoded = (message: IncomingMessage): Readable => {
  const encoding = message.headers["content-encoding"]?.trim().toLowerCase();
  let decoder: Transform | undefined;
  if (encoding === "gzip" || encoding === "x-gzip") decoder = createGunzip();
  else if (encoding === "deflate") decoder = createInflate();
  else if (encoding === "br") decoder = createBrotliDecompress();
  return decoder === undefined
    ? message
    : pipeline(message, decoder, () => undefined);
};

const webResponse = (message: IncomingMessage): Response => {
  const headers = new Headers();
  try {
    for (let index = 0; index + 1 < message.rawHeaders.length; index += 2)
      headers.append(
        message.rawHeaders[index] ?? "",
        message.rawHeaders[index + 1] ?? "",
      );
    const status = message.statusCode ?? 0;
    const body = NULL_BODY_STATUSES.has(status)
      ? null
      : (Readable.toWeb(decoded(message)) as ReadableStream<Uint8Array>);
    if (body === null) message.resume();
    return new Response(body, {
      status,
      statusText: message.statusMessage ?? "",
      headers,
    });
  } catch (cause: unknown) {
    message.destroy();
    throw new TypeError("the server answered with an invalid response", {
      cause,
    });
  }
};

/**
 * Settle with the caller's abort reason as soon as the signal aborts. A name
 * lookup cannot be cancelled, so a vetting still in flight is abandoned, not
 * awaited: the download's deadline also bounds a stalled resolver.
 */
const untilAborted = <T>(
  work: Promise<T>,
  signal: AbortSignal | undefined,
): Promise<T> => {
  if (signal === undefined) return work;
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(signal.reason);
    if (signal.aborted) onAbort();
    else signal.addEventListener("abort", onAbort, { once: true });
    work
      .then(resolve, reject)
      .finally(() => signal.removeEventListener("abort", onAbort));
  });
};

const requestOnce = async (
  url: URL,
  headers: Headers,
  signal: AbortSignal | undefined,
  policy: DestinationPolicy,
): Promise<Response> => {
  if (url.protocol !== "http:" && url.protocol !== "https:")
    throw new TypeError(`unsupported URL scheme ${url.protocol}`);
  const vetted = await untilAborted(vetUrlDestination(url, policy), signal);
  const options: RequestOptions = {
    method: "GET",
    headers: Object.fromEntries(headers),
    lookup: pinnedLookup(vetted),
    // A fresh connection per request: a pooled socket must never outlive the vetting that admitted it.
    agent: false,
    ...(signal === undefined ? {} : { signal }),
  };
  const message = await new Promise<IncomingMessage>((resolve, reject) => {
    const request = (url.protocol === "https:" ? httpsRequest : httpRequest)(
      url,
      options,
      resolve,
    );
    // Later errors (an abort while the body streams) reach the body stream; keep a listener so none is unhandled.
    request.on("error", reject);
    request.end();
  });
  return webResponse(message);
};

/** How `vettedFetch` treats redirect answers, as fetch's `redirect` option does. */
export type VettedRedirect = "manual" | "error" | "follow";

/** The subset of fetch REA's own downloads use. */
export interface VettedFetchInit {
  readonly redirect: VettedRedirect;
  readonly headers?: RequestInit["headers"];
  readonly signal?: AbortSignal | null;
  readonly policy?: DestinationPolicy;
}

/**
 * GET one http(s) URL after vetting its destination, connecting only to the
 * vetted addresses. Every followed redirect hop is vetted again. A refused
 * destination throws `DestinationRefusedError`; network failures throw as
 * fetch does. Connections are direct; proxy environment variables are not used.
 */
export const vettedFetch = async (
  input: string | URL,
  init: VettedFetchInit,
): Promise<Response> => {
  const policy = init.policy ?? destinationPolicy();
  const headers = new Headers(init.headers);
  const signal = init.signal ?? undefined;
  let url = new URL(input);
  for (let hop = 0; ; hop += 1) {
    const response = await requestOnce(url, headers, signal, policy);
    const location = REDIRECT_STATUSES.has(response.status)
      ? response.headers.get("location")
      : null;
    if (init.redirect === "manual" || location === null) return response;
    await response.body?.cancel().catch(() => undefined);
    if (init.redirect === "error")
      throw new TypeError(
        "the server answered with a redirect, which is refused",
      );
    if (hop >= MAX_REDIRECTS)
      throw new TypeError(`more than ${String(MAX_REDIRECTS)} redirects`);
    url = new URL(location, url);
  }
};
