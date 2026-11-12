import {
  connect,
  createConnection,
  createServer,
  type Server,
  Socket,
} from "node:net";

import { afterEach, beforeEach, expect, it, vi } from "vitest";

import type {
  DestinationRefusal,
  DestinationResolver,
} from "../../domain/networkDestination.js";
import { destinationPolicy } from "./PublicNetwork.js";
import {
  startDestinationGuardProxy,
  type DestinationDialer,
  type DestinationGuardProxy,
} from "./DestinationGuardProxy.js";

let echo: Server;
let echoPort: number;
let guard: DestinationGuardProxy | undefined;

beforeEach(async () => {
  echo = createServer((socket) => socket.pipe(socket));
  await new Promise<void>((resolve) => echo.listen(0, "127.0.0.1", resolve));
  const address = echo.address();
  if (address === null || typeof address === "string")
    throw new Error("no port");
  echoPort = address.port;
});

afterEach(async () => {
  await guard?.close();
  guard = undefined;
  await new Promise<void>((resolve) => echo.close(() => resolve()));
});

const proxyPort = (proxy: DestinationGuardProxy): number =>
  Number(new URL(proxy.server).port);

/** Speak SOCKS5 as a browser does and return the CONNECT reply code. */
const socksConnect = async (
  proxy: DestinationGuardProxy,
  destination: Buffer,
  port: number,
): Promise<{ readonly code: number; readonly socket: Socket }> => {
  const socket = connect(proxyPort(proxy), "127.0.0.1");
  await new Promise<void>((resolve) => socket.once("connect", resolve));
  const chunks: Buffer[] = [];
  const reply = new Promise<number>((resolve, reject) => {
    socket.on("data", (chunk: Buffer) => {
      chunks.push(chunk);
      const all = Buffer.concat(chunks);
      if (all.length >= 12) resolve(all[3] ?? -1);
    });
    socket.once("error", reject);
    socket.once("close", () => resolve(Buffer.concat(chunks)[3] ?? -1));
  });
  const portBytes = Buffer.alloc(2);
  portBytes.writeUInt16BE(port);
  socket.write(
    Buffer.concat([
      Buffer.from([5, 1, 0]),
      Buffer.from([5, 1, 0]),
      destination,
      portBytes,
    ]),
  );
  return { code: await reply, socket };
};

const domain = (name: string): Buffer =>
  Buffer.concat([Buffer.from([3, name.length]), Buffer.from(name, "latin1")]);
const ipv4 = (address: string): Buffer =>
  Buffer.from([1, ...address.split(".").map(Number)]);
const ipv6 = (groups: readonly number[]): Buffer => {
  const bytes = Buffer.alloc(17);
  bytes[0] = 4;
  groups.forEach((group, index) => bytes.writeUInt16BE(group, 1 + index * 2));
  return bytes;
};

it("refuses a name that resolves to the metadata address and records why", async () => {
  const refusals: DestinationRefusal[] = [];
  guard = await startDestinationGuardProxy({
    policy: destinationPolicy([], async () => [
      { address: "169.254.169.254", family: 4 },
    ]),
    onRefusal: (refusal) => refusals.push(refusal),
  });
  const { code, socket } = await socksConnect(guard, domain("evil.test"), 80);
  socket.destroy();
  expect(code).toBe(2);
  expect(refusals).toEqual([
    {
      host: "evil.test",
      port: 80,
      addressClass: "link-local",
      reason:
        "the name resolves to 169.254.169.254, a link-local address (cloud instance metadata)",
      alwaysRefused: true,
    },
  ]);
});

it.each([
  ["IPv4 loopback", ipv4("127.0.0.1"), "loopback"],
  [
    "IPv4-mapped loopback",
    ipv6([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1]),
    "ipv4-mapped",
  ],
  [
    "unique-local IPv6",
    ipv6([0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254]),
    "unique-local",
  ],
  ["the localhost name", domain("localhost"), "localhost-name"],
] as const)("refuses %s", async (_label, destination, addressClass) => {
  const refusals: DestinationRefusal[] = [];
  guard = await startDestinationGuardProxy({
    policy: destinationPolicy([], () => {
      throw new Error("literals must not be resolved");
    }),
    onRefusal: (refusal) => refusals.push(refusal),
  });
  const { code, socket } = await socksConnect(guard, destination, echoPort);
  socket.destroy();
  expect(code).toBe(2);
  expect(refusals).toMatchObject([{ addressClass }]);
});

it("tunnels an allowed private origin to the address it vetted", async () => {
  guard = await startDestinationGuardProxy({
    policy: destinationPolicy([`http://127.0.0.1:${String(echoPort)}`]),
    onRefusal: () => {
      throw new Error("Unexpected refusal");
    },
  });
  const { code, socket } = await socksConnect(
    guard,
    ipv4("127.0.0.1"),
    echoPort,
  );
  expect(code).toBe(0);
  const echoed = new Promise<string>((resolve) =>
    socket.once("data", (chunk: Buffer) => resolve(chunk.toString())),
  );
  socket.write("ping");
  expect(await echoed).toBe("ping");
  socket.destroy();
});

it("dials the vetted public answer of a rebinding name and never resolves it again", async () => {
  let calls = 0;
  const rebinding: DestinationResolver = async () => {
    calls += 1;
    return [
      calls === 1
        ? { address: "93.184.215.14", family: 4 }
        : { address: "127.0.0.1", family: 4 },
    ];
  };
  // The fake dialer records the vetted address and routes it to the local echo server.
  const dial = vi.fn<DestinationDialer>(() =>
    createConnection({ host: "127.0.0.1", port: echoPort }),
  );
  guard = await startDestinationGuardProxy({
    policy: destinationPolicy([], rebinding),
    onRefusal: () => {
      throw new Error("Unexpected refusal");
    },
    dial,
  });
  const { code, socket } = await socksConnect(guard, domain("rebind.test"), 80);
  expect(code).toBe(0);
  const echoed = new Promise<string>((resolve) =>
    socket.once("data", (chunk: Buffer) => resolve(chunk.toString())),
  );
  socket.write("bytes");
  expect(await echoed).toBe("bytes");
  socket.destroy();
  expect(calls).toBe(1);
  expect(dial).toHaveBeenCalledExactlyOnceWith(
    { address: "93.184.215.14", family: 4 },
    80,
  );
});

it("answers a name with no address as unreachable without recording a refusal", async () => {
  const refusals: DestinationRefusal[] = [];
  guard = await startDestinationGuardProxy({
    policy: destinationPolicy([], async () => {
      throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
    }),
    onRefusal: (refusal) => refusals.push(refusal),
  });
  const { code, socket } = await socksConnect(
    guard,
    domain("missing.test"),
    80,
  );
  socket.destroy();
  expect(code).toBe(4);
  expect(refusals).toEqual([]);
});

it("closes a dial still in progress when the guard closes", async () => {
  let pending: Socket | undefined;
  guard = await startDestinationGuardProxy({
    policy: destinationPolicy([], async () => [
      { address: "93.184.215.14", family: 4 },
    ]),
    onRefusal: () => undefined,
    // A socket that never connects stands in for an address that drops SYNs.
    dial: () => {
      pending = new Socket();
      return pending;
    },
  });
  const client = connect(proxyPort(guard), "127.0.0.1");
  await new Promise<void>((resolve) => client.once("connect", resolve));
  client.write(
    Buffer.concat([
      Buffer.from([5, 1, 0, 5, 1, 0]),
      domain("slow.test"),
      Buffer.from([0, 80]),
    ]),
  );
  for (let attempt = 0; attempt < 100 && pending === undefined; attempt += 1)
    await new Promise((resolve) => setTimeout(resolve, 5));
  expect(pending?.destroyed).toBe(false);
  await guard.close();
  guard = undefined;
  expect(pending?.destroyed).toBe(true);
  client.destroy();
});

it("answers unsupported commands and authentication without tunnelling", async () => {
  guard = await startDestinationGuardProxy({
    policy: destinationPolicy(),
    onRefusal: () => undefined,
  });
  const socket = connect(proxyPort(guard), "127.0.0.1");
  const reply = new Promise<Buffer>((resolve) => {
    const chunks: Buffer[] = [];
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.once("close", () => resolve(Buffer.concat(chunks)));
  });
  // Username/password authentication only: no acceptable method.
  socket.write(Buffer.from([5, 1, 2]));
  expect([...(await reply)]).toEqual([5, 0xff]);
});
