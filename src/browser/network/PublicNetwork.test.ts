import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { gzipSync } from "node:zlib";

import { afterEach, beforeEach, expect, it, vi } from "vitest";

import type { DestinationResolver } from "../../domain/networkDestination.js";
import {
  DestinationRefusedError,
  destinationPolicy,
  vettedFetch,
} from "./PublicNetwork.js";

let server: Server;
let port: number;
let hits: string[];

beforeEach(async () => {
  hits = [];
  server = createServer((request, response) => {
    hits.push(request.url ?? "");
    if (request.url === "/metadata") {
      response.writeHead(302, {
        location: "http://169.254.169.254/latest/meta-data/",
      });
      response.end();
    } else if (request.url === "/same-host") {
      response.writeHead(302, { location: "/document" });
      response.end();
    } else if (request.url === "/no-location") {
      response.writeHead(302);
      response.end("no location");
    } else if (request.url === "/gzip") {
      response.writeHead(200, { "content-encoding": "gzip" });
      response.end(gzipSync('{"compressed":true}'));
    } else {
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"ok":true}');
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = (server.address() as AddressInfo).port;
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

it("refuses a loopback literal by default before connecting, naming the address class", async () => {
  const failure = vettedFetch(`http://127.0.0.1:${String(port)}/document`, {
    redirect: "manual",
  });
  await expect(failure).rejects.toBeInstanceOf(DestinationRefusedError);
  await expect(failure).rejects.toMatchObject({
    refusal: { addressClass: "loopback", port },
    message: expect.stringContaining("127.0.0.1 is a loopback address"),
  });
  expect(hits).toEqual([]);
});

it("reaches an exactly allowed local dev server", async () => {
  const origin = `http://127.0.0.1:${String(port)}`;
  const response = await vettedFetch(`${origin}/document`, {
    redirect: "manual",
    policy: destinationPolicy([origin]),
  });
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({ ok: true });
});

it("connects only to the vetted address, never re-resolving the name", async () => {
  // The system resolver has no answer for this name, so reaching the server
  // proves the socket used the address the policy vetted.
  const resolve = vi.fn<DestinationResolver>(async () => [
    { address: "127.0.0.1", family: 4 },
  ]);
  const response = await vettedFetch(
    `http://pinned.invalid:${String(port)}/document`,
    {
      redirect: "manual",
      policy: destinationPolicy(
        [`http://pinned.invalid:${String(port)}`],
        resolve,
      ),
    },
  );
  expect(await response.json()).toEqual({ ok: true });
  expect(resolve).toHaveBeenCalledExactlyOnceWith("pinned.invalid");
});

it("vets every followed redirect hop and refuses the metadata address", async () => {
  const origin = `http://127.0.0.1:${String(port)}`;
  await expect(
    vettedFetch(`${origin}/metadata`, {
      redirect: "follow",
      policy: destinationPolicy([origin]),
    }),
  ).rejects.toMatchObject({
    refusal: { host: "169.254.169.254", addressClass: "link-local" },
    message: expect.stringContaining("cloud instance metadata"),
  });
  expect(hits).toEqual(["/metadata"]);
});

it("follows an allowed redirect, returns manual redirects and refuses them in error mode", async () => {
  const origin = `http://127.0.0.1:${String(port)}`;
  const policy = destinationPolicy([origin]);
  const followed = await vettedFetch(`${origin}/same-host`, {
    redirect: "follow",
    policy,
  });
  expect(await followed.json()).toEqual({ ok: true });
  const manual = await vettedFetch(`${origin}/metadata`, {
    redirect: "manual",
    policy,
  });
  expect(manual.status).toBe(302);
  expect(manual.headers.get("location")).toBe(
    "http://169.254.169.254/latest/meta-data/",
  );
  await manual.body?.cancel();
  await expect(
    vettedFetch(`${origin}/metadata`, { redirect: "error", policy }),
  ).rejects.toThrow("redirect");
});

it("decodes a gzip body as fetch does", async () => {
  const origin = `http://127.0.0.1:${String(port)}`;
  const response = await vettedFetch(`${origin}/gzip`, {
    redirect: "manual",
    policy: destinationPolicy([origin]),
  });
  expect(await response.json()).toEqual({ compressed: true });
});

it("refuses a name that resolves to a private address", async () => {
  await expect(
    vettedFetch("https://internal.test/state.json", {
      redirect: "error",
      policy: destinationPolicy([], async () => [
        { address: "10.1.2.3", family: 4 },
      ]),
    }),
  ).rejects.toMatchObject({
    refusal: { addressClass: "private", host: "internal.test", port: 443 },
  });
});

it("returns a redirect status without Location unchanged, as fetch does", async () => {
  const origin = `http://127.0.0.1:${String(port)}`;
  const response = await vettedFetch(`${origin}/no-location`, {
    redirect: "error",
    policy: destinationPolicy([origin]),
  });
  expect(response.status).toBe(302);
  expect(await response.text()).toBe("no location");
});

it("reports a name with no address as fetch's network failure, not a refusal", async () => {
  const failure = vettedFetch("https://missing.test/state.json", {
    redirect: "error",
    policy: destinationPolicy([], async () => {
      throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
    }),
  });
  await expect(failure).rejects.toBeInstanceOf(TypeError);
  await expect(failure).rejects.not.toBeInstanceOf(DestinationRefusedError);
  await expect(failure).rejects.toMatchObject({
    message: "fetch failed",
    cause: {
      message:
        'untrusted host name "missing.test" on port 443: the name could not be resolved (ENOTFOUND)',
    },
  });
});

it("ends a download whose name lookup stalls when the caller's signal aborts", async () => {
  const controller = new AbortController();
  const reason = new Error("download deadline");
  const stalled = vettedFetch("https://stalled.test/state.json", {
    redirect: "error",
    signal: controller.signal,
    policy: destinationPolicy([], () => new Promise(() => undefined)),
  });
  setTimeout(() => controller.abort(reason), 10);
  await expect(stalled).rejects.toBe(reason);
});

it("rejects with the caller's abort reason", async () => {
  const origin = `http://127.0.0.1:${String(port)}`;
  const controller = new AbortController();
  const reason = new Error("caller cancelled");
  controller.abort(reason);
  await expect(
    vettedFetch(`${origin}/document`, {
      redirect: "manual",
      signal: controller.signal,
      policy: destinationPolicy([origin]),
    }),
  ).rejects.toBe(reason);
});
