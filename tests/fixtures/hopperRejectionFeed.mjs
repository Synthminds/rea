/** Deterministic feed boundary for the package verifier's deliberately foreign launcher.
 * This fixture never authorizes a Hopper build or simulates successful cryptography.
 *
 * Hopper downloads use vettedFetch, which resolves the host through
 * node:dns/promises and connects through node:https. Only the release feed
 * URL is answered here; every other lookup and request reaches the real modules.
 */
import { EventEmitter } from "node:events";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { Readable } from "node:stream";

import { HOPPER_RELEASES_URL } from "../../dist/application/HopperReleaseFeed.js";

const require = createRequire(import.meta.url);
const dnsPromises = require("node:dns/promises");
const https = require("node:https");

const feedUrl = new URL(HOPPER_RELEASES_URL);
const feedHost = feedUrl.hostname;
const row = (suffix) => ({
  version: "fixture-current",
  filename: `https://www.hopperapp.com:443/downloader/public/Hopper-fixture-current-Linux-demo.${suffix}`,
  file_length: "1",
  file_hash: "0".repeat(40),
  main_exe_hash: "0".repeat(64),
  signature: "AQ==",
  public: "1",
  beta: "0",
});
const feed = JSON.stringify({
  "Ubuntu / Mint": row("deb"),
  Fedora: row("rpm"),
  Arch: row("pkg.tar.xz"),
});

// The private-network policy vets the feed host before any request. A public
// answer lets it pass without real DNS; the request below never connects.
const feedAddress = { address: "93.184.215.14", family: 4 };
const systemLookup = dnsPromises.lookup;
dnsPromises.lookup = (hostname, options) =>
  hostname === feedHost
    ? Promise.resolve(options?.all === true ? [feedAddress] : feedAddress)
    : systemLookup(hostname, options);

const systemRequest = https.request;
https.request = (...request) => {
  const [url, options, onResponse] = request;
  const target = url instanceof URL ? url : URL.parse(String(url));
  if (target?.hostname === feedHost && target.href !== feedUrl.href) {
    // The answer above serves only the feed; another vendor URL resolves and
    // connects for real, as it would without this fixture.
    const { lookup: _feedLookup, ...real } = options ?? {};
    return systemRequest(url, real, onResponse);
  }
  if (target?.href !== feedUrl.href) return systemRequest(...request);
  const pending = new EventEmitter();
  pending.end = () => {
    queueMicrotask(() => {
      if (options?.signal?.aborted === true) {
        pending.emit("error", options.signal.reason);
        return;
      }
      onResponse(
        Object.assign(Readable.from([Buffer.from(feed)]), {
          statusCode: 200,
          statusMessage: "OK",
          headers: { "content-type": "application/json" },
          rawHeaders: ["content-type", "application/json"],
        }),
      );
    });
    return pending;
  };
  return pending;
};

// Rebind the ES module exports REA imports to the replacements above.
syncBuiltinESMExports();
