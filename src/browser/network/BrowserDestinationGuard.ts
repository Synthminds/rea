import type { CDPSession } from "playwright-core";

import { BrowserObservationError } from "../../domain/browserObservationError.js";
import type { BrowserObservationOperation } from "../../domain/browserObservationErrors.js";
import {
  canonicalHost,
  isUnresolved,
  refuseWithoutLookup,
  refusalSentence,
  urlPort,
  vetDestination,
  type DestinationPolicy,
  type DestinationRefusal,
  type VettedDestination,
} from "../../domain/networkDestination.js";
import type { Result } from "../../domain/result.js";
import {
  startDestinationGuardProxy,
  type DestinationDialer,
  type DestinationGuardProxy,
} from "./DestinationGuardProxy.js";

const MAX_RETAINED_DESTINATIONS = 32;
const NETWORK_SCHEMES = new Set(["http:", "https:", "ws:", "wss:"]);
/** Chromium's errors for a connection the guard proxy or the interception refused. */
const REFUSED_NETWORK_ERROR =
  /net::ERR_(?:SOCKS_CONNECTION_FAILED|PROXY_CONNECTION_FAILED|TUNNEL_CONNECTION_FAILED|BLOCKED_BY_CLIENT)\b/u;

/** How to allow a local dev server; every other non-public destination stays refused. */
export const ALLOW_PRIVATE_ORIGIN_REMEDIATION =
  "To capture a local dev server, add its exact origin to allow_private_origins; every other private, loopback, link-local or otherwise non-public destination stays refused.";

interface RefusedDestination {
  readonly refusal: DestinationRefusal;
  count: number;
}

/**
 * One scenario's private-network policy: it vets navigation targets, guards
 * every connection a launched browser makes, intercepts requests of an
 * attached page, and keeps a bounded record of what it refused.
 */
export class BrowserDestinationGuard {
  readonly #refused = new Map<string, RefusedDestination>();
  #omitted = 0;
  /** Counts every refusal, so a navigation can tell which ones happened during it. */
  #sequence = 0;
  #latest: DestinationRefusal | undefined;
  /** Concurrent requests to one host and port share a single vetting. */
  readonly #vetting = new Map<
    string,
    Promise<Result<VettedDestination, DestinationRefusal>>
  >();
  #proxy: DestinationGuardProxy | undefined;

  constructor(
    private readonly policy: DestinationPolicy,
    private readonly dial?: DestinationDialer,
  ) {}

  /** Record one refusal, once per destination and address class. */
  record(refusal: DestinationRefusal): void {
    this.#sequence += 1;
    this.#latest = refusal;
    const key = `${canonicalHost(refusal.host)}:${String(refusal.port)}:${refusal.addressClass}`;
    const known = this.#refused.get(key);
    if (known !== undefined) known.count += 1;
    else if (this.#refused.size < MAX_RETAINED_DESTINATIONS)
      this.#refused.set(key, { refusal, count: 1 });
    else this.#omitted += 1;
  }

  /** A mark taken before a navigation; `explain` considers only later refusals. */
  mark(): number {
    return this.#sequence;
  }

  /**
   * Refuse a navigation to a non-public literal or a localhost name before the
   * browser starts it, naming the address class. A name is vetted where its
   * connection is made: by the guard proxy in launch mode and by request
   * interception in connect mode.
   */
  assertNavigable(url: string, operation: BrowserObservationOperation): void {
    const parsed = new URL(url);
    if (!NETWORK_SCHEMES.has(parsed.protocol)) return;
    const refused = refuseWithoutLookup(
      parsed.hostname,
      urlPort(parsed),
      this.policy.allowedPrivate,
    );
    if (refused === undefined) return;
    this.record(refused);
    throw this.refusalError(operation, refused);
  }

  /** The error for a navigation the policy refused, before or during the request. */
  refusalError(
    operation: BrowserObservationOperation,
    refusal: DestinationRefusal,
    cause?: unknown,
  ): BrowserObservationError {
    return new BrowserObservationError(operation, "target_not_allowed", {
      ...(cause === undefined ? {} : { cause }),
      detail: refusalSentence(refusal),
      remediationAction: ALLOW_PRIVATE_ORIGIN_REMEDIATION,
    });
  }

  /**
   * Name the refused destination when a navigation failed with a refused
   * connection and the guard refused a destination since `since`; any other
   * failure is returned unchanged. A navigation whose redirect was refused is
   * named by that redirect's destination.
   */
  explain(
    operation: BrowserObservationOperation,
    cause: unknown,
    since: number,
  ): unknown {
    const refusal = this.#latest;
    return refusal !== undefined &&
      this.#sequence > since &&
      cause instanceof Error &&
      !(cause instanceof BrowserObservationError) &&
      REFUSED_NETWORK_ERROR.test(cause.message)
      ? this.refusalError(operation, refusal, cause)
      : cause;
  }

  /**
   * Launch options that route every browser connection through the guard.
   * `<-loopback>` removes Chromium's implicit loopback and link-local bypass;
   * Playwright makes the browser leave name resolution to the SOCKS5 guard.
   */
  async launchOptions(): Promise<{
    readonly proxy: { readonly server: string; readonly bypass: string };
    readonly args: readonly string[];
  }> {
    this.#proxy ??= await startDestinationGuardProxy({
      policy: this.policy,
      onRefusal: (refusal) => this.record(refusal),
      ...(this.dial === undefined ? {} : { dial: this.dial }),
    });
    return {
      proxy: { server: this.#proxy.server, bypass: "<-loopback>" },
      args: [
        "--disable-quic",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
      ],
    };
  }

  /**
   * Intercept every request of an attached page, including each redirect hop,
   * and fail those whose destination is not allowed. The attached browser
   * resolves names itself, so this vets but cannot pin a name's address.
   * The returned disposer disables interception before it stops listening, so
   * no paused request is left without an answer.
   */
  async intercept(session: CDPSession): Promise<() => Promise<void>> {
    const onPaused = (event: {
      readonly requestId: string;
      readonly request: { readonly url: string };
    }): void => {
      void this.#decide(session, event.requestId, event.request.url).catch(
        () => undefined,
      );
    };
    session.on("Fetch.requestPaused", onPaused);
    try {
      await session.send("Fetch.enable", {
        patterns: [{ urlPattern: "*", requestStage: "Request" }],
      });
    } catch (cause: unknown) {
      session.off("Fetch.requestPaused", onPaused);
      throw cause;
    }
    return async () => {
      try {
        await session.send("Fetch.disable");
      } finally {
        session.off("Fetch.requestPaused", onPaused);
      }
    };
  }

  #vet(url: URL): Promise<Result<VettedDestination, DestinationRefusal>> {
    const port = urlPort(url);
    const key = `${url.hostname}:${String(port)}`;
    const pending = this.#vetting.get(key);
    if (pending !== undefined) return pending;
    const vetting = vetDestination(url.hostname, port, this.policy).finally(
      () => this.#vetting.delete(key),
    );
    this.#vetting.set(key, vetting);
    return vetting;
  }

  async #decide(
    session: CDPSession,
    requestId: string,
    url: string,
  ): Promise<void> {
    const parsed = URL.parse(url);
    if (parsed !== null && NETWORK_SCHEMES.has(parsed.protocol)) {
      const vetted = await this.#vet(parsed);
      if (!vetted.ok) {
        // A name REA cannot resolve cannot be vetted; it fails as unresolved,
        // not as a policy refusal.
        const unresolved = isUnresolved(vetted.error);
        if (!unresolved) this.record(vetted.error);
        await session.send("Fetch.failRequest", {
          requestId,
          errorReason: unresolved ? "NameNotResolved" : "BlockedByClient",
        });
        return;
      }
    }
    await session.send("Fetch.continueRequest", { requestId });
  }

  /** Evidence lines for each refused destination; empty when nothing was refused. */
  limitations(): readonly string[] {
    if (this.#refused.size === 0) return [];
    return [
      ...[...this.#refused.values()].map(
        ({ refusal, count }) =>
          `Private-network policy refused ${canonicalHost(refusal.host)}:${String(refusal.port)}${count > 1 ? ` (${String(count)} connections)` : ""}: ${refusal.reason}.`,
      ),
      ...(this.#omitted === 0
        ? []
        : [
            `Private-network policy refused ${String(this.#omitted)} more connections to destinations beyond the ${String(MAX_RETAINED_DESTINATIONS)} listed.`,
          ]),
      ALLOW_PRIVATE_ORIGIN_REMEDIATION,
    ];
  }

  /** Stop the launch-mode guard; tunnels still open are closed. */
  async close(): Promise<void> {
    const proxy = this.#proxy;
    this.#proxy = undefined;
    await proxy?.close();
  }
}
