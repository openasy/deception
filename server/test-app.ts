// Starts the app on a random port for tests.
import { createServer, type RequestListener, type Server } from "node:http";
import { createAuth } from "@openasy/auth";
import type { AddressInfo } from "node:net";
import { createApp, type AppOptions } from "./app.ts";
import { createDeception, type DeceptionOptions } from "./deception.ts";
import { openDb } from "./db.ts";
import { sealer } from "./seal.ts";

export const INGEST_TOKEN = "test-ingest-token";
export const ADMIN_TOKEN = "test-admin-token";
export const KEY_ID = "AKIAIOSFODNN7EXAMPLE";
export const KEY_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

export async function startApp(opts: Partial<AppOptions> & { version: string; deceptionOptions?: Partial<DeceptionOptions> }) {
  const db = openDb(":memory:");
  const { deceptionOptions, ...appOptions } = opts;
  const deception = createDeception(db, {
    sealer: sealer(Buffer.alloc(32, 7)),
    canaryUrl: "https://cdn.example.com",
    dnsZone: "canary.example.com",
    ...deceptionOptions,
  });
  // The origin is known once the port is, so the handler is set after listening.
  let handler: RequestListener = (_req, res) => res.writeHead(503).end();
  const server: Server = createServer((req, res) => handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const auth = createAuth({ db, product: "deception", productName: "OpenAsy Deception", origin: base });
  handler = createApp({ db, deception, auth, ingestToken: INGEST_TOKEN, adminToken: ADMIN_TOKEN, ...appOptions });
  const as =
    (token: string) =>
    (path: string, init: RequestInit = {}) =>
      fetch(base + path, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...init.headers } });
  const admin = as(ADMIN_TOKEN);
  const ingest = as(INGEST_TOKEN);
  const get = async (path: string) => (await (await admin(path)).json()) as any;
  const post = async (path: string, body: unknown) => (await admin(path, { method: "POST", body: JSON.stringify(body) })).json() as Promise<any>;
  /** Makes a canary and returns it with its bait. */
  const make = (body: Record<string, unknown>) => post("/api/v1/canaries", body) as Promise<{ canary: any; bait: { file: string; content: string } }>;
  /** The token in a canary's address. */
  const token = (canary: { kind: string; address: string }) =>
    canary.kind === "url" ? canary.address.split("/c/")[1]! : canary.kind === "dns" ? canary.address.split(".")[0]! : canary.address;
  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return { db, deception, auth, base, admin, ingest, get, post, make, token, close };
}
