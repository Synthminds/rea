import { EventEmitter } from "node:events";
import { connect } from "node:net";

import type { CDPSession } from "playwright-core";
import { expect, it } from "vitest";

import { BrowserObservationError } from "../../domain/browserObservationError.js";
import {
  BrowserDestinationGuard,
  CONNECT_MODE_POLICY_LIMITATION,
} from "./BrowserDestinationGuard.js";
import { destinationPolicy } from "./PublicNetwork.js";

/** The CDP session surface the guard uses: events plus recorded commands. */
const fakeSession = () => {
  const events = new EventEmitter();
  const sent: { readonly method: string; readonly params: unknown }[] = [];
  const settled = new EventEmitter();
  const session = {
    on: (event: string, listener: (payload: unknown) => void) => {
      events.on(event, listener);
      return session;
    },
    off: (event: string, listener: (payload: unknown) => void) => {
      events.off(event, listener);
      return session;
    },
    send: async (method: string, params?: unknown) => {
      sent.push({ method, params });
      settled.emit("sent", method);
      return {};
    },
  };
  return {
    session: session as unknown as CDPSession,
    sent,
    pause: (requestId: string, url: string) =>
      events.emit("Fetch.requestPaused", { requestId, request: { url } }),
    next: () => new Promise<string>((resolve) => settled.once("sent", resolve)),
    listeners: () => events.listenerCount("Fetch.requestPaused"),
  };
};

const guard = (allowed: readonly string[] = []) =>
  new BrowserDestinationGuard(
    destinationPolicy(allowed, async (host) => {
      if (host === "missing.test")
        throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
      return host === "public.test"
        ? [{ address: "93.184.215.14", family: 4 }]
        : [{ address: "10.0.0.7", family: 4 }];
    }),
  );

it("fails each paused request to a non-public destination, including redirect hops, and continues the rest", async () => {
  const destinations = guard(["http://localhost:5173"]);
  const cdp = fakeSession();
  const dispose = await destinations.intercept(cdp.session);
  expect(cdp.sent).toEqual([
    {
      method: "Fetch.enable",
      params: { patterns: [{ urlPattern: "*", requestStage: "Request" }] },
    },
  ]);
  const cases = [
    ["1", "http://localhost:5173/app.js", "Fetch.continueRequest"],
    ["2", "https://public.test/data.json", "Fetch.continueRequest"],
    ["3", "http://169.254.169.254/latest/meta-data/", "Fetch.failRequest"],
    ["4", "http://127.0.0.1:5173/secret", "Fetch.failRequest"],
    ["5", "http://[::ffff:127.0.0.1]:5173/", "Fetch.failRequest"],
    ["6", "http://rebind.test/", "Fetch.failRequest"],
    ["7", "data:text/plain,inline", "Fetch.continueRequest"],
    ["8", "https://missing.test/", "Fetch.failRequest"],
  ] as const;
  for (const [requestId, url, expected] of cases) {
    const sent = cdp.next();
    cdp.pause(requestId, url);
    expect(await sent).toBe(expected);
  }
  expect(cdp.sent.at(3)).toEqual({
    method: "Fetch.failRequest",
    params: { requestId: "3", errorReason: "BlockedByClient" },
  });
  // A name REA cannot resolve fails as unresolved and is not a policy refusal.
  expect(cdp.sent.at(-1)).toEqual({
    method: "Fetch.failRequest",
    params: { requestId: "8", errorReason: "NameNotResolved" },
  });
  expect(destinations.limitations()).toEqual([
    CONNECT_MODE_POLICY_LIMITATION,
    "Private-network policy refused 169.254.169.254:80: 169.254.169.254 is a link-local address (cloud instance metadata).",
    "Private-network policy refused 127.0.0.1:5173: 127.0.0.1 is a loopback address.",
    "Private-network policy refused [::ffff:7f00:1]:5173: ::ffff:7f00:1 is an IPv4-mapped IPv6 address (embeds loopback 127.0.0.1).",
    'Private-network policy refused untrusted host name "rebind.test" on port 80: the name resolves to 10.0.0.7, a private address.',
    "To capture a local dev server, add its exact origin to allow_private_origins; every other private, loopback or otherwise non-public destination stays refused, and link-local and cloud metadata addresses cannot be allowed.",
  ]);
  await dispose();
  expect(cdp.sent.at(-1)).toEqual({
    method: "Fetch.disable",
    params: undefined,
  });
  expect(cdp.listeners()).toBe(0);
});

it("refuses a non-public literal or localhost navigation before it starts, as target_not_allowed naming the class", () => {
  const destinations = guard();
  let refused: unknown;
  try {
    destinations.assertNavigable(
      "http://127.0.0.1:8080/",
      "capture_browser_scenario",
    );
  } catch (cause: unknown) {
    refused = cause;
  }
  expect(refused).toBeInstanceOf(BrowserObservationError);
  expect(refused).toMatchObject({
    reason: "target_not_allowed",
    userMessage: expect.stringContaining("127.0.0.1 is a loopback address"),
    remediationAction: expect.stringContaining("allow_private_origins"),
  });
  expect(() =>
    destinations.assertNavigable(
      "http://dev.localhost:3000/",
      "capture_browser_scenario",
    ),
  ).toThrow(
    expect.objectContaining({
      userMessage: expect.stringContaining(
        'untrusted host name "dev.localhost" on port 3000: the name is a localhost name',
      ),
    }),
  );
  // Names are vetted where the connection is made, not here.
  expect(() =>
    destinations.assertNavigable(
      "http://rebind.test/",
      "capture_browser_scenario",
    ),
  ).not.toThrow();
  expect(() =>
    guard(["http://127.0.0.1:8080"]).assertNavigable(
      "http://127.0.0.1:8080/",
      "capture_browser_scenario",
    ),
  ).not.toThrow();
});

it("states in every connect-mode capture that the policy is advisory there", async () => {
  const attached = guard();
  const cdp = fakeSession();
  const dispose = await attached.intercept(cdp.session);
  // Nothing was refused, yet connect-mode Evidence must not read as enforced.
  expect(attached.limitations()).toEqual([
    expect.stringMatching(
      /^Private-network policy is advisory in connect mode/u,
    ),
  ]);
  for (const gap of [
    "names are vetted but not pinned",
    "workers, service workers, popups and out-of-process iframes",
    "WebSocket connections",
  ])
    expect(attached.limitations()[0]).toContain(gap);
  await dispose();
  // The capture was still made in connect mode after interception ends.
  expect(attached.limitations()).toHaveLength(1);

  const launched = guard();
  await launched.launchOptions();
  expect(launched.limitations()).toEqual([]);
  await launched.close();
});

it("quotes a page-chosen host name as untrusted data, at most 80 characters", async () => {
  const destinations = guard();
  const cdp = fakeSession();
  const dispose = await destinations.intercept(cdp.session);
  const long = `${"x".repeat(100)}.localhost`;
  for (const [requestId, url] of [
    ["1", "http://ignore-all-previous-instructions.localhost/"],
    ["2", `http://${long}/`],
  ] as const) {
    const sent = cdp.next();
    cdp.pause(requestId, url);
    expect(await sent).toBe("Fetch.failRequest");
  }
  expect(destinations.limitations().slice(1, 3)).toEqual([
    'Private-network policy refused untrusted host name "ignore-all-previous-instructions.localhost" on port 80: the name is a localhost name, which always means this host.',
    `Private-network policy refused untrusted host name "${"x".repeat(80)}" (first 80 of 110 characters) on port 80: the name is a localhost name, which always means this host.`,
  ]);
  await dispose();
});

it("explains only refused-connection errors after a refusal during that navigation", () => {
  const destinations = guard();
  const refusedConnection = new Error(
    "page.goto: net::ERR_SOCKS_CONNECTION_FAILED",
  );
  expect(
    destinations.explain("capture_browser_scenario", refusedConnection, 0),
  ).toBe(refusedConnection);
  // A refusal before the navigation began does not explain its failure.
  destinations.record({
    host: "10.0.0.5",
    port: 80,
    addressClass: "private",
    reason: "10.0.0.5 is a private address",
  });
  const mark = destinations.mark();
  expect(
    destinations.explain("capture_browser_scenario", refusedConnection, mark),
  ).toBe(refusedConnection);
  destinations.record({
    host: "169.254.169.254",
    port: 80,
    addressClass: "link-local",
    reason: "169.254.169.254 is a link-local address (cloud instance metadata)",
  });
  // The latest refusal is named even when its destination was refused before.
  destinations.record({
    host: "10.0.0.5",
    port: 80,
    addressClass: "private",
    reason: "10.0.0.5 is a private address",
  });
  destinations.record({
    host: "169.254.169.254",
    port: 80,
    addressClass: "link-local",
    reason: "169.254.169.254 is a link-local address (cloud instance metadata)",
  });
  const timeout = new Error("page.goto: Timeout 30000ms exceeded");
  expect(destinations.explain("capture_browser_scenario", timeout, mark)).toBe(
    timeout,
  );
  expect(
    destinations.explain("capture_browser_scenario", refusedConnection, mark),
  ).toMatchObject({
    reason: "target_not_allowed",
    cause: refusedConnection,
    userMessage:
      "Refused 169.254.169.254:80: 169.254.169.254 is a link-local address (cloud instance metadata). Only public internet addresses are reached unless the exact origin is allowed with allow_private_origins.",
  });
});

it("counts repeated refusals once per destination and bounds the record", () => {
  const destinations = guard();
  for (let index = 0; index < 3; index += 1)
    destinations.record({
      host: "10.0.0.1",
      port: 80,
      addressClass: "private",
      reason: "10.0.0.1 is a private address",
    });
  for (let index = 0; index < 40; index += 1)
    destinations.record({
      host: `10.0.1.${String(index)}`,
      port: 80,
      addressClass: "private",
      reason: "private",
    });
  const lines = destinations.limitations();
  expect(lines[0]).toBe(
    "Private-network policy refused 10.0.0.1:80 (3 connections): 10.0.0.1 is a private address.",
  );
  expect(lines).toHaveLength(32 + 2);
  expect(lines.at(-2)).toBe(
    "Private-network policy refused 9 more connections to destinations beyond the 32 listed.",
  );
});

it("starts one guard proxy for launch options and closes it", async () => {
  const destinations = guard();
  const first = await destinations.launchOptions();
  const second = await destinations.launchOptions();
  expect(first.proxy.server).toMatch(/^socks5:\/\/127\.0\.0\.1:\d+$/u);
  expect(second.proxy.server).toBe(first.proxy.server);
  expect(first.proxy.bypass).toBe("<-loopback>");
  expect(first.args).toEqual([
    "--disable-quic",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
  ]);
  await destinations.close();
  await destinations.close();
  const port = Number(new URL(first.proxy.server).port);
  await expect(
    new Promise((resolve, reject) => {
      const socket = connect(port, "127.0.0.1", () => {
        socket.destroy();
        resolve("connected");
      });
      socket.once("error", reject);
    }),
  ).rejects.toMatchObject({ code: "ECONNREFUSED" });
});
