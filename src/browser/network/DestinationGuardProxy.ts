import { createConnection, createServer, type Socket } from "node:net";

import {
  isUnresolved,
  vetDestination,
  type DestinationPolicy,
  type DestinationRefusal,
  type ResolvedAddress,
} from "../../domain/networkDestination.js";

/**
 * A SOCKS5 proxy on 127.0.0.1 that a launched browser sends every connection
 * through. Chromium hands it the destination name, so the guard resolves it
 * once, refuses any non-public answer, and dials only the address it vetted:
 * redirects, subresources, workers and WebSockets are each a new connection
 * through this check, and DNS rebinding cannot swap the vetted address.
 */
export interface DestinationGuardProxy {
  /** The value for a browser's proxy server setting. */
  readonly server: string;
  close(): Promise<void>;
}

/** Opens one TCP connection to a vetted address. */
export type DestinationDialer = (
  address: ResolvedAddress,
  port: number,
) => Socket;

const directDial: DestinationDialer = ({ address }, port) =>
  createConnection({ host: address, port });

const HANDSHAKE_TIMEOUT_MS = 10_000;
// A vetted address that drops SYNs must not hold a socket for the OS TCP timeout.
const DIAL_TIMEOUT_MS = 30_000;
// Greeting (2 + 255 methods) and a CONNECT with a 255-byte name fit well within this.
const MAX_HANDSHAKE_BYTES = 1_024;

const SOCKS_VERSION = 5;
const NO_AUTHENTICATION = 0;
const NO_ACCEPTABLE_METHOD = 0xff;
const CONNECT = 1;
const REPLY = {
  succeeded: 0,
  generalFailure: 1,
  notAllowed: 2,
  hostUnreachable: 4,
  connectionRefused: 5,
  commandNotSupported: 7,
  addressTypeNotSupported: 8,
} as const;

const reply = (code: number): Buffer =>
  Buffer.from([SOCKS_VERSION, code, 0, 1, 0, 0, 0, 0, 0, 0]);

interface ConnectRequest {
  readonly host: string;
  readonly port: number;
  readonly consumed: number;
}

type Parsed<T> = T | "incomplete" | { readonly reply: number };

const parseGreeting = (buffer: Buffer): Parsed<number> => {
  if (buffer.length < 2) return "incomplete";
  if (buffer[0] !== SOCKS_VERSION) return { reply: NO_ACCEPTABLE_METHOD };
  const length = 2 + (buffer[1] ?? 0);
  if (buffer.length < length) return "incomplete";
  return buffer.subarray(2, length).includes(NO_AUTHENTICATION)
    ? length
    : { reply: NO_ACCEPTABLE_METHOD };
};

const ipv6Text = (bytes: Buffer): string => {
  const groups: string[] = [];
  for (let index = 0; index < 16; index += 2)
    groups.push(bytes.readUInt16BE(index).toString(16));
  return groups.join(":");
};

const parseConnect = (buffer: Buffer): Parsed<ConnectRequest> => {
  if (buffer.length < 5) return "incomplete";
  if (buffer[0] !== SOCKS_VERSION) return { reply: REPLY.generalFailure };
  if (buffer[1] !== CONNECT) return { reply: REPLY.commandNotSupported };
  const type = buffer[3];
  let host: string;
  let offset: number;
  if (type === 1) {
    if (buffer.length < 10) return "incomplete";
    host = [...buffer.subarray(4, 8)].join(".");
    offset = 8;
  } else if (type === 3) {
    const length = buffer[4] ?? 0;
    if (buffer.length < 7 + length) return "incomplete";
    host = buffer.subarray(5, 5 + length).toString("latin1");
    offset = 5 + length;
  } else if (type === 4) {
    if (buffer.length < 22) return "incomplete";
    host = ipv6Text(buffer.subarray(4, 20));
    offset = 20;
  } else return { reply: REPLY.addressTypeNotSupported };
  return { host, port: buffer.readUInt16BE(offset), consumed: offset + 2 };
};

interface GuardOptions {
  readonly policy: DestinationPolicy;
  readonly onRefusal: (refusal: DestinationRefusal) => void;
  readonly dial?: DestinationDialer;
}

/** Every socket the guard opened, so `close` also ends dials still in progress. */
type SocketRegistry = (socket: Socket) => Socket;

/** Dial the vetted addresses in resolver order until one connects. */
const dialVetted = (
  addresses: readonly ResolvedAddress[],
  port: number,
  dial: DestinationDialer,
  register: SocketRegistry,
): Promise<Socket> =>
  new Promise((resolve, reject) => {
    const attempt = (index: number, lastError?: unknown): void => {
      const address = addresses[index];
      if (address === undefined) {
        reject(lastError ?? new Error("no vetted address"));
        return;
      }
      const upstream = register(dial(address, port));
      upstream.setTimeout(DIAL_TIMEOUT_MS, () =>
        upstream.destroy(
          Object.assign(new Error("dial timed out"), { code: "ETIMEDOUT" }),
        ),
      );
      // Exactly one outcome per attempt: a failure tries the next address; a
      // close without an error (the guard closing) ends the dial.
      let settled = false;
      upstream.on("error", (cause: unknown) => {
        if (settled) return;
        settled = true;
        upstream.destroy();
        attempt(index + 1, cause);
      });
      upstream.once("close", () => {
        if (settled) return;
        settled = true;
        reject(new Error("the dial was closed"));
      });
      upstream.once("connect", () => {
        if (settled) return;
        settled = true;
        upstream.setTimeout(0);
        resolve(upstream);
      });
    };
    attempt(0);
  });

const tunnel = async (
  client: Socket,
  request: ConnectRequest,
  rest: Buffer,
  options: GuardOptions & { readonly register: SocketRegistry },
): Promise<void> => {
  const vetted = await vetDestination(
    request.host,
    request.port,
    options.policy,
  );
  if (client.destroyed) return;
  if (!vetted.ok) {
    // A name with no vettable address is unreachable, not a policy refusal.
    if (isUnresolved(vetted.error)) {
      client.end(reply(REPLY.hostUnreachable));
      return;
    }
    options.onRefusal(vetted.error);
    client.end(reply(REPLY.notAllowed));
    return;
  }
  let upstream: Socket;
  try {
    upstream = await dialVetted(
      vetted.value.addresses,
      request.port,
      options.dial ?? directDial,
      options.register,
    );
  } catch (cause: unknown) {
    const code =
      cause instanceof Error && "code" in cause ? String(cause.code) : "";
    client.end(
      reply(
        code === "ECONNREFUSED"
          ? REPLY.connectionRefused
          : REPLY.hostUnreachable,
      ),
    );
    return;
  }
  if (client.destroyed) {
    upstream.destroy();
    return;
  }
  client.write(reply(REPLY.succeeded));
  if (rest.length > 0) upstream.write(rest);
  client.pipe(upstream).pipe(client);
  const closeBoth = (): void => {
    client.destroy();
    upstream.destroy();
  };
  client.once("error", closeBoth).once("close", closeBoth);
  upstream.once("error", closeBoth).once("close", closeBoth);
};

const handleClient = (
  client: Socket,
  options: GuardOptions & { readonly register: SocketRegistry },
): void => {
  let buffer = Buffer.alloc(0);
  let greeted = false;
  client.setTimeout(HANDSHAKE_TIMEOUT_MS, () => client.destroy());
  client.on("error", () => client.destroy());
  const onData = (chunk: Buffer): void => {
    buffer = Buffer.concat([buffer, chunk]);
    if (buffer.length > MAX_HANDSHAKE_BYTES) {
      client.destroy();
      return;
    }
    if (!greeted) {
      const greeting = parseGreeting(buffer);
      if (greeting === "incomplete") return;
      if (typeof greeting !== "number") {
        client.end(Buffer.from([SOCKS_VERSION, greeting.reply]));
        return;
      }
      greeted = true;
      buffer = buffer.subarray(greeting);
      client.write(Buffer.from([SOCKS_VERSION, NO_AUTHENTICATION]));
    }
    const request = parseConnect(buffer);
    if (request === "incomplete") return;
    client.off("data", onData);
    client.setTimeout(0);
    if ("reply" in request) {
      client.end(reply(request.reply));
      return;
    }
    client.pause();
    void tunnel(client, request, buffer.subarray(request.consumed), options)
      .catch(() => client.destroy())
      .finally(() => client.resume());
  };
  client.on("data", onData);
};

/** Start the guard on an ephemeral loopback port; `close` ends every tunnel it holds. */
export const startDestinationGuardProxy = async (
  options: GuardOptions,
): Promise<DestinationGuardProxy> => {
  const sockets = new Set<Socket>();
  const register: SocketRegistry = (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    return socket;
  };
  const server = createServer((client) => {
    handleClient(register(client), { ...options, register });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 0 }, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    server.close();
    throw new Error("the destination guard has no TCP address");
  }
  // Open tunnels keep the process alive; an idle listener alone never does.
  server.unref();
  return {
    server: `socks5://127.0.0.1:${String(address.port)}`,
    close: () =>
      new Promise<void>((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolve());
      }),
  };
};
