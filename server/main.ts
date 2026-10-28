import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createAuth, oidcFromEnv, readSecretsKey } from "@openasy/auth";
import { createApp, createCanaryHandler, createMetricsHandler } from "./app.ts";
import { openDb } from "./db.ts";
import { createDeception } from "./deception.ts";
import { startDns } from "./dns.ts";
import { createIncidentsLink, type Severity } from "./incidents.ts";
import { log } from "./log.ts";
import { parseProducts } from "./products.ts";
import { sealer } from "./seal.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const port = Number(process.env.PORT ?? 8080);
const dbPath = process.env.DECEPTION_DB ?? "/data/deception.db";
const retentionDays = Number(process.env.DECEPTION_RETENTION_DAYS ?? 365);
const webDir = new URL("../dist/web", import.meta.url).pathname;
const docsDir = new URL("../dist/docs", import.meta.url).pathname;
const openapi = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Record<string, unknown>;
const headless = process.env.DECEPTION_HEADLESS === "true";
// Set it to keep /metrics off the port that is published or behind an ingress (ADR 0026).
const metricsPort = process.env.DECEPTION_METRICS_PORT ? Number(process.env.DECEPTION_METRICS_PORT) : undefined;
// A port that answers canary URLs and nothing else, to publish where the UI should not be (ADR 0057).
const canaryPort = process.env.DECEPTION_CANARY_PORT ? Number(process.env.DECEPTION_CANARY_PORT) : undefined;
const proxyHops = Number(process.env.DECEPTION_PROXY_HOPS ?? 0);
const dnsZone = process.env.DECEPTION_DNS_ZONE?.trim().toLowerCase().replace(/\.$/, "") || undefined;
const dnsPort = Number(process.env.DECEPTION_DNS_PORT ?? 5353);

if (!Number.isFinite(retentionDays) || retentionDays < 1) throw new Error("DECEPTION_RETENTION_DAYS must be a number of days, 1 or more");
if (!Number.isInteger(proxyHops) || proxyHops < 0 || proxyHops > 5) throw new Error("DECEPTION_PROXY_HOPS must be 0 to 5: the proxies in front of deception");
if (dnsZone && !/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(dnsZone))
  throw new Error("DECEPTION_DNS_ZONE must be a DNS name, such as canary.example.com");

const db = openDb(dbPath);
// The address people open deception at, behind the TLS proxy (ADR 0026). Cookies, passkeys and OIDC redirects use it.
const publicUrl = (process.env.DECEPTION_PUBLIC_URL ?? `http://localhost:${port}`).replace(/\/$/, "");
// Where URL canaries call. Another name than the UI's keeps the word "deception" out of every bait.
const canaryUrl = (process.env.DECEPTION_CANARY_URL ?? publicUrl).replace(/\/$/, "");
if (!URL.canParse(canaryUrl) || !/^https?:$/.test(new URL(canaryUrl).protocol)) throw new Error("DECEPTION_CANARY_URL must be an http(s) address");
const secretsKeyFile = process.env.DECEPTION_SECRETS_KEY_FILE ?? "/run/secrets/openasy-kek";
const secretsKey = readSecretsKey(secretsKeyFile);
const auth = createAuth({
  db,
  product: "deception",
  productName: "OpenAsy Deception",
  origin: publicUrl,
  // Locally the same deception is often opened as 127.0.0.1 too.
  trustedOrigins: publicUrl.startsWith("http://localhost:") ? [publicUrl.replace("localhost", "127.0.0.1")] : [],
  passwords: process.env.DECEPTION_PASSWORD_SIGN_IN !== "false",
  oidc: oidcFromEnv(process.env, "DECEPTION_"),
  secretsKey,
  // Audit log (ADR 0013): every sign-in, failure and change to members and tokens.
  onEvent: (event) => log(event.type === "sign-in-failed" ? "warn" : "info", "auth", { event }),
});
const products = parseProducts(process.env.OPENASY_PRODUCTS);
if (products.invalid.length) log("warn", "OPENASY_PRODUCTS: left out entries that are not id=https://address", { entries: products.invalid });

// Incidents is called at DECEPTION_INCIDENTS_URL, or where OPENASY_PRODUCTS says people open it.
const incidentsPage = products.products.find((p) => p.id === "incidents")?.url;
const incidentsUrl = process.env.DECEPTION_INCIDENTS_URL ?? incidentsPage;
const incidentSeverity = (process.env.DECEPTION_INCIDENTS_SEVERITY ?? "critical") as Severity;
if (!["critical", "high", "medium", "low"].includes(incidentSeverity)) throw new Error("DECEPTION_INCIDENTS_SEVERITY must be critical, high, medium or low");
if (process.env.DECEPTION_INCIDENTS_TOKEN && !incidentsUrl)
  log("warn", "DECEPTION_INCIDENTS_TOKEN is set but no address: set DECEPTION_INCIDENTS_URL, or incidents in OPENASY_PRODUCTS");
const incidents =
  process.env.DECEPTION_INCIDENTS_TOKEN && incidentsUrl
    ? {
        link: createIncidentsLink({ url: incidentsUrl, token: process.env.DECEPTION_INCIDENTS_TOKEN, publicUrl: incidentsPage, product: "deception" }),
        severity: incidentSeverity,
        triggerUrl: (id: string) => `${publicUrl}/triggers/${encodeURIComponent(id)}`,
      }
    : undefined;

const deception = createDeception(db, { retentionDays, sealer: sealer(secretsKey), canaryUrl, dnsZone, incidents });
const server = createServer(
  createApp({
    db,
    deception,
    version,
    auth,
    ingestToken: process.env.DECEPTION_INGEST_TOKEN,
    proxyHops,
    webDir: !headless && existsSync(webDir) ? webDir : undefined,
    docsDir: existsSync(docsDir) ? docsDir : undefined,
    openapi,
    serveMetrics: metricsPort === undefined,
    products: products.products,
  }),
);
const metricsServer = metricsPort !== undefined ? createServer(createMetricsHandler(deception, version)) : undefined;
metricsServer?.listen(metricsPort, () => log("info", "metrics on their own port", { port: metricsPort }));
const canaryHandler = createCanaryHandler(deception, proxyHops);
const canaryServer =
  canaryPort !== undefined
    ? createServer((req, res) => {
        if (!canaryHandler(req, res)) res.writeHead(404, { "content-type": "text/plain" }).end("Not found\n");
      })
    : undefined;
canaryServer?.listen(canaryPort, () => log("info", "canary URLs on their own port", { port: canaryPort }));

const dns = dnsZone
  ? await startDns({
      port: dnsPort,
      zone: dnsZone,
      answer: process.env.DECEPTION_DNS_ANSWER || undefined,
      onLookup: ({ token, name, type, source }) => {
        const used = deception.touch({ token, channel: "dns", source, detail: `${type} lookup of ${name}` });
        if (used?.created) log("warn", "canary used", { trigger: used.trigger, channel: "dns" });
      },
      onError: (err) => log("error", "DNS", { error: String(err) }),
    })
  : undefined;
if (dns) log("info", "DNS canaries answered", { zone: dnsZone, port: dnsPort });

server.listen(port, () =>
  log("info", "deception started", {
    version,
    port,
    db: dbPath,
    headless,
    retentionDays,
    canaryUrl,
    dnsZone: dnsZone ?? "off",
    incidents: incidents ? incidentsUrl : "off",
  }),
);
if (!process.env.DECEPTION_INGEST_TOKEN)
  log("warn", "DECEPTION_INGEST_TOKEN is not set; a CloudTrail pipeline needs an API token with the editor role (Settings, API tokens)");
if (!publicUrl.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1)(:|$)/.test(publicUrl)) {
  log("warn", "DECEPTION_PUBLIC_URL is not https: browsers will not keep secure cookies or allow passkeys. Put deception behind TLS (ADR 0026)", {
    url: publicUrl,
  });
}
if (!secretsKey)
  log("warn", "no secrets key: TOTP secrets and the secrets of AWS key canaries are stored unencrypted. Mount a 32-byte key (openssl rand -hex 32)", {
    file: secretsKeyFile,
  });
const setup = auth.setupLink();
// No default password (ADR 0013): the first person to open this link becomes the owner.
if (setup) log("info", "no owner yet: open this link once to create the owner account", { url: setup });

deception.purge();
// One turn at a time: a slow Incidents must not have two turns open the same incident.
let sending = false;
const sendIncidents = () => {
  if (sending) return;
  sending = true;
  void deception
    .sendIncidents()
    .catch((err: unknown) => log("error", "incidents", { error: String(err) }))
    .finally(() => (sending = false));
};
const timers: NodeJS.Timeout[] = [
  setInterval(() => auth.purge(), 5 * 60_000),
  setInterval(() => deception.purge(), 24 * 3_600_000),
  // A trigger reaches Incidents within seconds; one that fails is tried again on the next turn.
  setInterval(sendIncidents, 5_000),
];

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  for (const t of timers) clearInterval(t);
  metricsServer?.close();
  canaryServer?.close();
  dns?.close();
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
