import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ADMIN_TOKEN, INGEST_TOKEN, KEY_ID, KEY_SECRET, startApp } from "./test-app.ts";

// Contract tests (ADR 0024): every response the API sends must match openapi.json.

type Spec = {
  info: { version: string };
  paths: Record<string, Record<string, { responses: Record<string, { $ref?: string; content?: Record<string, { schema: object }> }> }>>;
  components: { responses: Record<string, { content: Record<string, { schema: object }> }> };
};

const spec = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Spec;
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(spec, "openapi");

const docsDir = mkdtempSync(join(tmpdir(), "deception-docs-"));
writeFileSync(join(docsDir, "index.html"), "<!doctype html><title>API</title>");

let app: Awaited<ReturnType<typeof startApp>>;
let base: string;
const covered = new Set<string>();

beforeAll(async () => {
  app = await startApp({ version, openapi: spec, docsDir });
  base = app.base;
});

afterAll(() => app.close());

/** Calls the API and checks status, content type and body against the description. */
async function call(method: string, path: string, init: RequestInit = {}, concrete = path) {
  const res = await fetch(base + concrete, { ...init, method });
  const operation = spec.paths[path]?.[method.toLowerCase()];
  expect(operation, `${method} ${path} is not in openapi.json`).toBeDefined();
  covered.add(`${method} ${path}`);

  const declared = operation!.responses[String(res.status)];
  expect(declared, `${method} ${concrete} answered ${res.status}, which openapi.json does not list`).toBeDefined();
  // A response is either inline or a $ref to components/responses; build the JSON pointer to its schema either way.
  const shared = declared!.$ref?.split("/").pop();
  const response = shared ? spec.components.responses[shared]! : declared!;
  const at = shared
    ? `openapi#/components/responses/${shared}`
    : `openapi#/paths/${path.replaceAll("/", "~1")}/${method.toLowerCase()}/responses/${res.status}`;

  if (!response.content) {
    expect(res.headers.get("content-length") ?? "0", `${method} ${path} ${res.status} should have no body`).toBe("0");
    return { res, body: undefined };
  }
  const type = res.headers.get("content-type")!.split(";")[0]!;
  expect(response.content?.[type], `${method} ${path} ${res.status} sent ${type}, which openapi.json does not list`).toBeDefined();

  const body = type.endsWith("json") ? await res.json() : await res.text();
  const schema = `${at}/content/${type.replace("/", "~1")}/schema`;
  const validate = ajv.getSchema(schema)!;
  expect(validate(body), JSON.stringify(validate.errors)).toBe(true);
  return { res, body };
}

const auth = (token: string, body?: string, type = "application/json") => ({
  headers: { authorization: `Bearer ${token}`, "content-type": type },
  ...(body !== undefined && { body }),
});
const admin = (body?: unknown) => auth(ADMIN_TOKEN, body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body));

describe("openapi.json", () => {
  it("has the version of this release", () => {
    expect(spec.info.version).toBe(version);
  });

  it("is served with the running version", async () => {
    const served = (await (await fetch(`${base}/api/openapi.json`)).json()) as Spec;
    expect(served.info.version).toBe(version);
    // deception's own operations, then sign-in from @openasy/auth (tested against its description in that package).
    expect(Object.keys(served.paths).filter((p) => !p.startsWith("/api/v1/auth/"))).toEqual(Object.keys(spec.paths));
    expect(served.paths["/api/v1/auth/login"]).toBeDefined();
  });

  it("serves the API reference at /api/docs/", async () => {
    expect((await fetch(`${base}/api/docs`, { redirect: "manual" })).headers.get("location")).toBe("/api/docs/");
    const res = await fetch(`${base}/api/docs/`);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect((await fetch(`${base}/api/docs/../../package.json`)).status).not.toBe(200);
  });
});

describe("responses match openapi.json", () => {
  let canary = "";
  let trigger = "";
  const event = {
    eventID: "e1",
    eventTime: "2026-10-28T13:58:12Z",
    eventSource: "sts.amazonaws.com",
    eventName: "GetCallerIdentity",
    userIdentity: { accessKeyId: KEY_ID },
  };
  const send = (body: string, token = INGEST_TOKEN) => auth(token, body);

  it("product and health", async () => {
    await call("GET", "/api/v1/version");
    await call("GET", "/api/v1/products", admin());
    await call("GET", "/api/v1/products", {});
    await call("GET", "/healthz");
    await call("GET", "/readyz");
    await call("GET", "/metrics");
  });

  it("canaries", async () => {
    canary = ((await call("POST", "/api/v1/canaries", admin({ name: "Wiki", template: "link", location: "wiki" }))).body as { canary: { id: string } }).canary
      .id;
    await call("POST", "/api/v1/canaries", admin({ name: "Key", template: "aws-credentials", accessKeyId: KEY_ID, secretAccessKey: KEY_SECRET }));
    await call("POST", "/api/v1/canaries", admin({ name: "Key again", template: "aws-credentials", accessKeyId: KEY_ID, secretAccessKey: KEY_SECRET }));
    await call("POST", "/api/v1/canaries", admin({ name: "Bad", template: "pdf" }));
    await call("POST", "/api/v1/canaries", admin("nope"));
    await call("POST", "/api/v1/canaries", { method: "POST" });
    await call("GET", "/api/v1/canaries", admin());
    await call("GET", "/api/v1/canaries", admin(), "/api/v1/canaries?kind=url&state=armed&q=wi");
    await call("GET", "/api/v1/canaries", admin(), "/api/v1/canaries?kind=pdf");
    await call("GET", "/api/v1/canaries", {});
    await call("GET", "/api/v1/canaries/{id}", admin(), `/api/v1/canaries/${canary}`);
    await call("GET", "/api/v1/canaries/{id}", admin(), "/api/v1/canaries/missing");
    await call("GET", "/api/v1/canaries/{id}", {}, `/api/v1/canaries/${canary}`);
    await call("PATCH", "/api/v1/canaries/{id}", admin({ host: "fs01" }), `/api/v1/canaries/${canary}`);
    await call("PATCH", "/api/v1/canaries/{id}", admin({}), `/api/v1/canaries/${canary}`);
    await call("PATCH", "/api/v1/canaries/{id}", admin("nope"), `/api/v1/canaries/${canary}`);
    await call("PATCH", "/api/v1/canaries/{id}", admin({ name: "x" }), "/api/v1/canaries/missing");
    await call("PATCH", "/api/v1/canaries/{id}", { method: "PATCH" }, `/api/v1/canaries/${canary}`);
    await call("GET", "/api/v1/canaries/{id}/bait", admin(), `/api/v1/canaries/${canary}/bait`);
    await call("GET", "/api/v1/canaries/{id}/bait", admin(), "/api/v1/canaries/missing/bait");
    await call("GET", "/api/v1/canaries/{id}/bait", {}, `/api/v1/canaries/${canary}/bait`);
  });

  it("a DNS canary without a zone", async () => {
    const bare = await startApp({ version, openapi: spec, deceptionOptions: { dnsZone: undefined } });
    const res = await fetch(`${bare.base}/api/v1/canaries`, { method: "POST", ...admin({ name: "SSH", template: "ssh-config" }) });
    expect(res.status).toBe(409);
    const declared = spec.paths["/api/v1/canaries"]!.post!.responses["409"];
    expect(declared).toBeDefined();
    const id = ((await res.json()) as { code: string }).code;
    expect(id).toBe("not-configured");
    // The bait of a DNS canary made before the zone went away cannot be shown.
    bare.db
      .prepare("INSERT INTO canaries (id, name, kind, template, token, created_at, created_by) VALUES ('cn_dns', 'n', 'dns', 'hostname', 'abc', 'now', 'me')")
      .run();
    const bait = await fetch(`${bare.base}/api/v1/canaries/cn_dns/bait`, admin());
    expect(bait.status).toBe(409);
    expect(spec.paths["/api/v1/canaries/{id}/bait"]!.get!.responses["409"]).toBeDefined();
    await bare.close();
  });

  it("CloudTrail", async () => {
    await call("POST", "/api/v1/cloudtrail", send(JSON.stringify({ Records: [event] })));
    await call("POST", "/api/v1/cloudtrail", send("{nope"));
    await call("POST", "/api/v1/cloudtrail", send("{}", "wrong"));
    await call("POST", "/api/v1/cloudtrail", { method: "POST" });
  });

  it("triggers", async () => {
    const list = (await call("GET", "/api/v1/triggers", admin())).body as { triggers: Array<{ id: string }> };
    trigger = list.triggers[0]!.id;
    await call("GET", "/api/v1/triggers", admin(), `/api/v1/triggers?status=open&canary=${canary}&limit=1`);
    await call("GET", "/api/v1/triggers", admin(), "/api/v1/triggers?status=old");
    await call("GET", "/api/v1/triggers", admin(), "/api/v1/triggers?cursor=junk");
    await call("GET", "/api/v1/triggers", {});
    await call("GET", "/api/v1/triggers/{id}", admin(), `/api/v1/triggers/${trigger}`);
    await call("GET", "/api/v1/triggers/{id}", admin(), "/api/v1/triggers/missing");
    await call("GET", "/api/v1/triggers/{id}", {}, `/api/v1/triggers/${trigger}`);
    await call("PUT", "/api/v1/triggers/{id}", admin({ status: "test", reason: "Drill" }), `/api/v1/triggers/${trigger}`);
    await call("PUT", "/api/v1/triggers/{id}", admin({ status: "test" }), `/api/v1/triggers/${trigger}`);
    await call("PUT", "/api/v1/triggers/{id}", admin("nope"), `/api/v1/triggers/${trigger}`);
    await call("PUT", "/api/v1/triggers/{id}", admin({ status: "open" }), "/api/v1/triggers/missing");
    await call("PUT", "/api/v1/triggers/{id}", { method: "PUT" }, `/api/v1/triggers/${trigger}`);
    await call("GET", "/api/v1/summary", admin());
    await call("GET", "/api/v1/summary", {});
  });

  it("deletes a canary", async () => {
    await call("DELETE", "/api/v1/canaries/{id}", admin(), `/api/v1/canaries/${canary}`);
    await call("DELETE", "/api/v1/canaries/{id}", admin(), `/api/v1/canaries/${canary}`);
    await call("DELETE", "/api/v1/canaries/{id}", { method: "DELETE" }, "/api/v1/canaries/x");
  });

  it("covers every operation in openapi.json", () => {
    const all = Object.entries(spec.paths).flatMap(([path, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${path}`));
    expect([...covered].sort()).toEqual(all.sort());
  });
});
