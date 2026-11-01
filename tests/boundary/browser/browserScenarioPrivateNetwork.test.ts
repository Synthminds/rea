import { existsSync } from "node:fs";
import { once } from "node:events";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { expect, it } from "vitest";

import { createBrowserScenarioProvider } from "../../../src/composition/browserScenario.js";
import { browserScenarioSchema } from "../../../src/domain/browserScenario.js";

const chromeExecutable = [
  process.env.REA_BROWSER_EXECUTABLE,
  "/usr/bin/google-chrome-stable",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
].find(
  (candidate): candidate is string =>
    typeof candidate === "string" &&
    candidate.length > 0 &&
    existsSync(candidate),
);

const KINDS = ["img", "fetch", "websocket", "worker", "iframe"] as const;

const listen = async (server: Server): Promise<number> => {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return (server.address() as AddressInfo).port;
};

/** One private service per request kind, so each refusal is named separately. */
const privateService = async () => {
  const connections: string[] = [];
  const server = createServer((_request, response) => response.end("secret"));
  server.on("connection", (socket) => {
    connections.push(String(socket.remotePort));
    socket.destroy();
  });
  return { server, connections, port: await listen(server) };
};

/** The page names every request kind; `#done` appears once all have settled. */
const scenarioPage = (
  ports: Readonly<Record<(typeof KINDS)[number], number>>,
) => {
  const target = (kind: (typeof KINDS)[number]) =>
    `127.0.0.1:${String(ports[kind])}`;
  return `<!doctype html><title>private network</title><body><script>
const settled = new Set();
const finish = (kind) => {
  settled.add(kind);
  if (settled.size === ${String(KINDS.length)} || kind === "timeout") {
    const done = document.createElement("p");
    done.id = "done";
    done.textContent = [...settled].sort().join(",");
    document.body.append(done);
  }
};
setTimeout(() => finish("timeout"), 20000);
const image = new Image();
image.onload = image.onerror = () => finish("img");
image.src = "http://${target("img")}/pixel.png";
document.body.append(image);
fetch("http://${target("fetch")}/data", { mode: "no-cors" }).then(
  () => finish("fetch"),
  () => finish("fetch"),
);
const socket = new WebSocket("ws://${target("websocket")}/socket");
socket.onerror = socket.onclose = () => finish("websocket");
const worker = new Worker("/worker.js");
worker.onmessage = () => finish("worker");
const frame = document.createElement("iframe");
frame.onload = () => finish("iframe");
frame.src = "http://${target("iframe")}/frame";
document.body.append(frame);
</script></body>`;
};

it.skipIf(chromeExecutable === undefined)(
  "refuses a launched page's image, fetch, WebSocket, worker and iframe requests to loopback",
  { timeout: 120_000 },
  async () => {
    const services = Object.fromEntries(
      await Promise.all(
        KINDS.map(async (kind) => [kind, await privateService()] as const),
      ),
    ) as Record<
      (typeof KINDS)[number],
      Awaited<ReturnType<typeof privateService>>
    >;
    const ports = Object.fromEntries(
      KINDS.map((kind) => [kind, services[kind].port]),
    ) as Record<(typeof KINDS)[number], number>;
    const page = scenarioPage(ports);
    const worker = `fetch("http://127.0.0.1:${String(ports.worker)}/from-worker", { mode: "no-cors" }).then(() => postMessage("settled"), () => postMessage("settled"));`;
    // The scenario's own dev server is the one allowed private origin.
    const app = createServer((request, response) => {
      if (request.url === "/worker.js") {
        response.writeHead(200, { "content-type": "text/javascript" });
        response.end(worker);
        return;
      }
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end(page);
    });
    const origin = `http://127.0.0.1:${String(await listen(app))}`;
    const provider = createBrowserScenarioProvider(process.env);
    try {
      const capture = await provider.captureScenario(
        browserScenarioSchema.parse({
          browser: {
            mode: "launch",
            executable_path: chromeExecutable,
            headless: true,
          },
          start_url: { url: `${origin}/` },
          actions: [
            {
              step_id: "settled",
              action: "wait_for",
              locator: { kind: "css", selector: "#done" },
              state: "attached",
              timeout_ms: 30_000,
            },
          ],
          allow_private_origins: [origin],
        }),
      );
      if (!capture.ok) throw capture.error;
      for (const kind of KINDS)
        expect(capture.value.limitations).toContainEqual(
          expect.stringMatching(
            new RegExp(
              `^Private-network policy refused 127\\.0\\.0\\.1:${String(ports[kind])}( \\(\\d+ connections\\))?: 127\\.0\\.0\\.1 is a loopback address\\.$`,
              "u",
            ),
          ),
        );
      // The guard refused before dialing: no private service saw a connection.
      for (const kind of KINDS) expect(services[kind].connections).toEqual([]);
    } finally {
      await provider.close?.();
      app.close();
      for (const kind of KINDS) services[kind].server.close();
    }
  },
);
