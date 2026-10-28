import { timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { extname, join, normalize } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { createGunzip } from "node:zlib";
import { AuthError, identityOrigin, mergeOpenApi, sendProblem, type Auth, type Role } from "@openasy/auth";
import { parseTrail } from "./cloudtrail.ts";
import { DeceptionError, parseLimit, type Deception, type ProblemCode } from "./deception.ts";
import { log } from "./log.ts";
import { countRequest, renderMetrics } from "./metrics.ts";
import type { ProductLink } from "./products.ts";

export interface AppOptions {
  db: DatabaseSync;
  deception: Deception;
  version: string;
  /** Sign-in, sessions, members and API tokens (ADR 0002, 0003). */
  auth: Auth;
  /** Token a pipeline sends CloudTrail events with. It can send events and nothing else (ADR 0003). */
  ingestToken?: string;
  /** For tests and local scripts: one shared token with the admin role. main.ts never sets it. */
  adminToken?: string;
  /** How many proxies in front of deception add X-Forwarded-For, so a trigger's source is the caller, not the proxy. */
  proxyHops?: number;
  /** Built web UI; omit to run headless (ADR 0018). */
  webDir?: string;
  /** Built API reference (Swagger UI), served at /api/docs. */
  docsDir?: string;
  /** The OpenAPI description, served at /api/openapi.json with this release's version. */
  openapi?: Record<string, unknown>;
  /** false when /metrics is served on its own port instead (ADR 0026). */
  serveMetrics?: boolean;
  /** The install's OpenAsy products and their addresses, from OPENASY_PRODUCTS, for the product switcher. */
  products?: ProductLink[];
}

function metricsText(deception: Deception, version: string) {
  return renderMetrics(version, deception.gauges());
}

/** Serves only /metrics, for a port that is not exposed with the rest (DECEPTION_METRICS_PORT). */
export function createMetricsHandler(deception: Deception, version: string) {
  return (req: IncomingMessage, res: ServerResponse) => {
    if (new URL(req.url ?? "/", "http://localhost").pathname !== "/metrics") return problem(res, 404, "not-found");
    send(res, 200, metricsText(deception, version), "text/plain; version=0.0.4");
  };
}

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".json": "application/json",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

// Identity keeps people's theme and language when they sign in through it; the pages read them there (ADR 0033).
const IDENTITY = identityOrigin(process.env);

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "content-security-policy": `default-src 'self'; connect-src 'self'${IDENTITY ? ` ${IDENTITY}` : ""}; img-src 'self' data:; style-src 'self' 'unsafe-inline'`,
};

/** Largest body of CloudTrail events accepted, after decompression: a log file from S3 is far smaller. */
const TRAIL_LIMIT = 32 * 1024 * 1024;

function send(res: ServerResponse, status: number, body: string | Buffer, type = "application/json", headers: Record<string, string> = {}) {
  res.writeHead(status, { ...SECURITY_HEADERS, ...headers, "content-type": type, "content-length": Buffer.byteLength(body) });
  res.end(body);
}

const json = (res: ServerResponse, status: number, data: unknown, headers?: Record<string, string>) =>
  send(res, status, JSON.stringify(data), "application/json", headers);

const TITLES: Record<ProblemCode, string> = {
  "invalid-token": "Invalid token",
  "invalid-json": "Invalid JSON",
  "invalid-body": "Invalid request body",
  "not-found": "Not found",
  conflict: "Conflict",
  "not-configured": "Not configured",
  "payload-too-large": "Payload too large",
  "internal-error": "Internal error",
};

/** RFC 9457 Problem Details (ADR 0024). `code` is the stable part clients match on. */
function problem(res: ServerResponse, status: number, code: ProblemCode, detail?: string) {
  const body = { type: `https://openasy.github.io/problems/${code}`, title: TITLES[code], status, code, ...(detail && { detail }) };
  send(res, status, JSON.stringify(body), "application/problem+json");
}

/** Serves a file from dir, or returns false when the path is outside it or missing. */
async function serveFile(res: ServerResponse, dir: string, relative: string): Promise<boolean> {
  const file = normalize(join(dir, relative));
  if (!file.startsWith(normalize(dir)) || !extname(file)) return false;
  try {
    send(res, 200, await readFile(file), TYPES[extname(file)] ?? "application/octet-stream");
    return true;
  } catch {
    return false;
  }
}

/** Reads the whole body, gunzipping it when sent with `Content-Encoding: gzip`, up to limit bytes. */
async function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
  const encoding = req.headers["content-encoding"];
  if (encoding && encoding !== "gzip" && encoding !== "identity") throw new DeceptionError(400, "invalid-body", "Content-Encoding must be gzip or absent.");
  const source = encoding === "gzip" ? req.pipe(createGunzip()) : req;
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of source as AsyncIterable<Buffer>) {
      size += chunk.length;
      if (size > limit) throw new DeceptionError(413, "payload-too-large", `The body must be at most ${Math.round(limit / 1024 / 1024)} MiB.`);
      chunks.push(chunk);
    }
  } catch (err) {
    if (err instanceof DeceptionError) throw err;
    throw new DeceptionError(400, "invalid-body", "The gzip body could not be read.");
  }
  return Buffer.concat(chunks);
}

async function readJson(req: IncomingMessage, limit = 64 * 1024): Promise<Record<string, unknown>> {
  const raw = await readBody(req, limit).catch((err: unknown) => {
    if (err instanceof DeceptionError && err.code === "payload-too-large")
      throw new DeceptionError(400, "invalid-json", `The body must be JSON, at most ${Math.round(limit / 1024)} KiB.`);
    throw err;
  });
  try {
    const body = JSON.parse(raw.toString("utf8")) as unknown;
    if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error("not an object");
    return body as Record<string, unknown>;
  } catch {
    throw new DeceptionError(400, "invalid-json", "The body must be a JSON object.");
  }
}

function tokenMatches(header: string | undefined, expected: string | undefined): boolean {
  if (!expected || !header?.startsWith("Bearer ")) return false;
  const a = Buffer.from(header.slice(7));
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Who called: the socket's address, or with proxies in front, the address the outermost of them saw. Only the last
 * `hops` entries of X-Forwarded-For are trusted; anything before them could be written by the caller.
 */
export function sourceOf(req: IncomingMessage, hops = 0): string {
  const plain = (ip: string) => ip.replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/, "");
  const remote = req.socket.remoteAddress ?? "unknown";
  if (!hops) return plain(remote);
  const header = req.headers["x-forwarded-for"];
  const chain = [
    ...(Array.isArray(header) ? header.join(",") : (header ?? ""))
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    remote,
  ];
  return plain(chain[Math.max(0, chain.length - 1 - hops)]!);
}

/** A transparent 1×1 GIF: what a canary URL answers, so a document or page that loads it shows nothing. */
const PIXEL = Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "base64");

/**
 * Answers a canary URL: /c/<token>, with anything after it, as a kubeconfig's server is called. Every path answers
 * the same, known token or not, so nothing tells a caller whether it found a canary.
 */
export function createCanaryHandler(deception: Deception, proxyHops = 0) {
  return (req: IncomingMessage, res: ServerResponse): boolean => {
    const raw = req.url ?? "/";
    const path = raw.split("?")[0]!;
    const m = /^\/c\/([a-z0-9]{8,64})(?:\/|$)/.exec(path);
    if (!m) return false;
    try {
      const used = deception.touch({
        token: m[1]!,
        channel: "http",
        source: sourceOf(req, proxyHops),
        userAgent: String(req.headers["user-agent"] ?? ""),
        detail: `${req.method ?? "GET"} ${raw.slice(0, 300)}`,
      });
      if (used?.created) log("warn", "canary used", { trigger: used.trigger, channel: "http" });
    } catch (err) {
      log("error", "a canary use could not be kept", { error: String(err) });
    }
    res.writeHead(200, { "content-type": "image/gif", "content-length": PIXEL.length, "cache-control": "no-store" });
    res.end(req.method === "HEAD" ? undefined : PIXEL);
    if (!req.complete) req.resume();
    return true;
  };
}

/** The role a route needs (ADR 0003), or "ingest" for events sent from a pipeline. */
type Access = "none" | "ingest" | Role;
interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  params: string[];
  body: () => Promise<Record<string, unknown>>;
  /** Who made the request, for the record of a decision. */
  actor: () => string;
}
interface Route {
  method: string;
  /** Path pattern; each `:name` matches one segment. */
  path: string;
  auth: Access;
  handle: (ctx: Ctx) => unknown;
}

export function createApp({
  db,
  deception,
  version,
  auth,
  adminToken,
  ingestToken,
  proxyHops = 0,
  webDir,
  docsDir,
  openapi,
  serveMetrics = true,
  products = [],
}: AppOptions) {
  // The served description includes /api/v1/auth from @openasy/auth, so the API reference documents sign-in too.
  const spec = openapi && JSON.stringify({ ...mergeOpenApi(openapi), info: { ...(openapi.info as object), version } });
  const canary = createCanaryHandler(deception, proxyHops);
  const noContent = (res: ServerResponse) => {
    res.writeHead(204, SECURITY_HEADERS).end();
  };
  const cursor = (url: URL) => url.searchParams.get("cursor") ?? undefined;
  const limit = (url: URL) => parseLimit(url.searchParams.get("limit"));
  const page = <K extends string, T>(key: K, p: { items: T[]; nextCursor?: string }) =>
    ({ [key]: p.items, ...(p.nextCursor && { nextCursor: p.nextCursor }) }) as Record<K, T[]> & { nextCursor?: string };

  const routes: Route[] = [
    { method: "GET", path: "/api/v1/version", auth: "none", handle: () => ({ product: "deception", version }) },
    { method: "GET", path: "/api/v1/products", auth: "viewer", handle: () => ({ products }) },
    { method: "GET", path: "/api/v1/summary", auth: "viewer", handle: () => deception.summary() },

    // Canaries and their bait.
    {
      method: "GET",
      path: "/api/v1/canaries",
      auth: "viewer",
      handle: ({ url }) => ({
        canaries: deception.canaries({ kind: url.searchParams.get("kind"), state: url.searchParams.get("state"), q: url.searchParams.get("q")?.slice(0, 200) }),
      }),
    },
    {
      method: "POST",
      path: "/api/v1/canaries",
      auth: "editor",
      handle: async ({ res, body, actor }) => json(res, 201, deception.createCanary(await body(), actor())),
    },
    { method: "GET", path: "/api/v1/canaries/:id", auth: "viewer", handle: ({ params }) => deception.canary(params[0]!) },
    { method: "PATCH", path: "/api/v1/canaries/:id", auth: "editor", handle: async ({ params, body }) => deception.updateCanary(params[0]!, await body()) },
    { method: "DELETE", path: "/api/v1/canaries/:id", auth: "admin", handle: ({ res, params }) => (deception.deleteCanary(params[0]!), noContent(res)) },
    // The bait holds the secret of an AWS key canary, so it is for those who plant canaries.
    { method: "GET", path: "/api/v1/canaries/:id/bait", auth: "editor", handle: ({ params }) => deception.bait(params[0]!) },

    // Each use of a canary, and what a person says it was.
    {
      method: "GET",
      path: "/api/v1/triggers",
      auth: "viewer",
      handle: ({ url }) =>
        page("triggers", deception.triggers({ status: url.searchParams.get("status"), canary: url.searchParams.get("canary") }, cursor(url), limit(url))),
    },
    { method: "GET", path: "/api/v1/triggers/:id", auth: "viewer", handle: ({ params }) => deception.trigger(params[0]!) },
    {
      method: "PUT",
      path: "/api/v1/triggers/:id",
      auth: "editor",
      handle: async ({ params, body, actor }) => deception.decide(params[0]!, await body(), actor()),
    },

    // AWS key canaries are found in CloudTrail events a pipeline sends.
    {
      method: "POST",
      path: "/api/v1/cloudtrail",
      auth: "ingest",
      handle: async ({ req }) => {
        let body: unknown;
        try {
          body = JSON.parse((await readBody(req, TRAIL_LIMIT)).toString("utf8"));
        } catch (err) {
          if (err instanceof DeceptionError) throw err;
          throw new DeceptionError(400, "invalid-json", "The body must be JSON: a CloudTrail log file, lookup-events' answer or EventBridge events.");
        }
        const events = parseTrail(body);
        let matched = 0;
        let created = 0;
        for (const e of events) {
          const used = deception.touch({
            token: e.accessKeyId,
            channel: "aws",
            source: e.source,
            userAgent: e.userAgent,
            detail: e.detail,
            at: e.at,
            ref: e.id,
          });
          if (!used) continue;
          matched++;
          if (used.created) (created++, log("warn", "canary used", { trigger: used.trigger, channel: "aws" }));
        }
        return { events: events.length, matched, triggers: created };
      },
    },
  ];

  const compiled = routes.map((r) => ({ ...r, re: new RegExp(`^${r.path.replace(/:[A-Za-z]+/g, "([^/]+)")}$`) }));

  /** Returns who is calling, or null for the ingest token. */
  function authorize(req: IncomingMessage, access: Access): string | null {
    if (access === "none") return null;
    if (access === "ingest" && tokenMatches(req.headers.authorization, ingestToken)) return null;
    if (tokenMatches(req.headers.authorization, adminToken)) return "admin token";
    if (access === "ingest") {
      // An API token with the editor role can send events too, for a pipeline set up from Settings.
      if (!ingestToken && !req.headers.authorization?.startsWith("Bearer oa_"))
        throw new DeceptionError(503, "not-configured", "Set DECEPTION_INGEST_TOKEN on deception, or send an API token with the editor role.");
      if (!req.headers.authorization?.startsWith("Bearer oa_"))
        throw new DeceptionError(401, "invalid-token", "Send DECEPTION_INGEST_TOKEN or an API token as a bearer token.");
    }
    const p = auth.authorize(req, access === "ingest" ? "editor" : access);
    return p.kind === "session" ? p.user.name : `API token ${p.name}`;
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<string> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;

    if (path.startsWith("/c/") && canary(req, res)) return "/c/*";

    if (path === "/healthz") return (json(res, 200, { status: "ok" }), "/healthz");

    if (path === "/readyz") {
      // Ready to keep triggers as long as the database answers.
      try {
        db.prepare("SELECT 1").get();
        json(res, 200, { status: "ready" });
      } catch {
        json(res, 503, { status: "database unavailable" });
      }
      return "/readyz";
    }

    if (path === "/metrics") {
      // Not even the web UI's fallback answers here when metrics have their own port.
      if (serveMetrics) send(res, 200, metricsText(deception, version), "text/plain; version=0.0.4");
      else problem(res, 404, "not-found");
      return "/metrics";
    }

    if (path === "/api/openapi.json" && spec) return (send(res, 200, spec), "/api/openapi.json");

    if (docsDir && (path === "/api/docs" || path.startsWith("/api/docs/"))) {
      if (path === "/api/docs") {
        res.writeHead(301, { ...SECURITY_HEADERS, location: "/api/docs/" }).end();
        return "/api/docs";
      }
      const relative = path.slice("/api/docs/".length) || "index.html";
      if (!(await serveFile(res, docsDir, relative))) problem(res, 404, "not-found");
      return "/api/docs";
    }

    if (await auth.handle(req, res)) return auth.routeName(req) ?? "/api/v1/auth/*";

    for (const r of compiled) {
      const m = path.match(r.re);
      if (!m || r.method !== req.method) continue;
      try {
        const who = authorize(req, r.auth);
        const params = m.slice(1).map(decodeURIComponent);
        const result = await r.handle({ req, res, url, params, body: () => readJson(req), actor: () => who ?? "unknown" });
        if (!res.headersSent && result !== undefined) json(res, 200, result);
      } catch (err) {
        if (err instanceof AuthError) {
          sendProblem(res, err);
          if (!req.complete) req.resume();
          return r.path;
        }
        if (!(err instanceof DeceptionError)) throw err;
        problem(res, err.status, err.code, err.message);
        // Unread request bodies would otherwise hold the connection.
        if (!req.complete) req.resume();
      }
      return r.path;
    }

    if (path.startsWith("/api/")) return (problem(res, 404, "not-found"), "/api/*");

    if (webDir && (req.method === "GET" || req.method === "HEAD")) {
      // Unknown paths fall back to the single-page app.
      if (!(await serveFile(res, webDir, path === "/" ? "index.html" : path))) send(res, 200, await readFile(join(webDir, "index.html")), TYPES[".html"]);
      return "/web";
    }

    problem(res, 404, "not-found");
    return "unmatched";
  }

  return async (req: IncomingMessage, res: ServerResponse) => {
    const started = performance.now();
    let routeName = "error";
    try {
      routeName = await route(req, res);
    } catch (err) {
      log("error", "request failed", { error: String(err), path: req.url });
      if (!res.headersSent) problem(res, 500, "internal-error");
    }
    countRequest(req.method ?? "GET", routeName, res.statusCode);
    // Canary URLs are logged by the trigger they make, not as requests: their tokens stay out of the logs.
    if (routeName !== "/healthz" && routeName !== "/metrics" && routeName !== "/c/*") {
      log("info", "request", { method: req.method, path: url(req), status: res.statusCode, ms: Math.round(performance.now() - started) });
    }
  };
}

/** The path without the query string. */
const url = (req: IncomingMessage) => (req.url ?? "/").split("?")[0];
