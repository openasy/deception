import { request } from "node:http";
import { gzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { sourceOf } from "./app.ts";
import { INGEST_TOKEN, KEY_ID, KEY_SECRET, startApp } from "./test-app.ts";

let app: Awaited<ReturnType<typeof startApp>>;

beforeAll(async () => {
  app = await startApp({ version: "0.1.0" });
});
afterAll(() => app.close());

describe("canary URLs", () => {
  it("answer a pixel for every path, known or not, and keep a trigger for a known one", async () => {
    const { canary } = await app.make({ name: "Kubeconfig", template: "kubeconfig", location: "worker-prod-04:/root/.kube/config" });
    const path = `/c/${app.token(canary)}`;
    const known = await fetch(`${app.base}${path}/api?timeout=32s`, { headers: { "user-agent": "kubectl/v1.31.0" } });
    const unknown = await fetch(`${app.base}/c/aaaaaaaaaaaaaaaaaaaaaaaa`);
    for (const res of [known, unknown]) {
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toBe("image/gif");
      expect(res.headers.get("cache-control")).toBe("no-store");
    }
    expect(Buffer.from(await known.arrayBuffer())).toEqual(Buffer.from(await unknown.arrayBuffer()));

    const { triggers } = await app.get(`/api/v1/triggers?canary=${canary.id}`);
    expect(triggers).toHaveLength(1);
    expect(triggers[0].source).toMatch(/^(127\.0\.0\.1|::1)$/);
    expect(triggers[0]).toMatchObject({ channel: "http", userAgent: "kubectl/v1.31.0", detail: `GET ${path}/api?timeout=32s` });
    expect((await app.get(`/api/v1/triggers?canary=other`)).triggers).toEqual([]);
  });

  it("take the caller from X-Forwarded-For only as far as the proxies go", () => {
    const req = (xff: string | undefined, remote = "10.0.0.2") => ({ headers: { "x-forwarded-for": xff }, socket: { remoteAddress: remote } }) as never;
    expect(sourceOf(req("198.51.100.7"))).toBe("10.0.0.2");
    expect(sourceOf(req("198.51.100.7", "::ffff:10.0.0.2"))).toBe("10.0.0.2");
    expect(sourceOf(req("6.6.6.6, 198.51.100.7"), 1)).toBe("198.51.100.7");
    expect(sourceOf(req("6.6.6.6, 198.51.100.7, 10.0.0.1"), 2)).toBe("198.51.100.7");
    expect(sourceOf(req(undefined), 1)).toBe("10.0.0.2");
  });
});

describe("canaries over the API", () => {
  it("are made by editors, and their bait shown again only to editors", async () => {
    const res = await app.admin("/api/v1/canaries", {
      method: "POST",
      body: JSON.stringify({ name: "Deploy key", template: "aws-credentials", accessKeyId: KEY_ID, secretAccessKey: KEY_SECRET, host: "api-prod-01" }),
    });
    expect(res.status).toBe(201);
    const { canary, bait } = (await res.json()) as any;
    expect(bait.content).toContain(KEY_SECRET);
    expect((await app.get(`/api/v1/canaries/${canary.id}/bait`)).content).toBe(bait.content);
    expect((await app.ingest(`/api/v1/canaries/${canary.id}/bait`)).status).toBe(401);
    expect((await fetch(`${app.base}/api/v1/canaries`)).status).toBe(401);
  });

  it("are listed, changed and deleted", async () => {
    const { canary } = await app.make({ name: "Old wiki link", template: "link" });
    expect((await app.get("/api/v1/canaries?q=wiki")).canaries.map((c: any) => c.name)).toEqual(["Old wiki link"]);
    expect((await app.admin("/api/v1/canaries?kind=pdf")).status).toBe(422);
    const patched = await app.admin(`/api/v1/canaries/${canary.id}`, { method: "PATCH", body: JSON.stringify({ enabled: false }) });
    expect(((await patched.json()) as any).state).toBe("disabled");
    expect((await app.admin(`/api/v1/canaries/${canary.id}`, { method: "DELETE" })).status).toBe(204);
    expect((await app.admin(`/api/v1/canaries/${canary.id}`)).status).toBe(404);
  });

  it("refuses a DNS canary while there is no zone", async () => {
    const bare = await startApp({ version: "0.1.0", deceptionOptions: { dnsZone: undefined } });
    const res = await bare.admin("/api/v1/canaries", { method: "POST", body: JSON.stringify({ name: "SSH", template: "ssh-config" }) });
    expect(res.status).toBe(409);
    expect(((await res.json()) as any).code).toBe("not-configured");
    await bare.close();
  });
});

describe("CloudTrail", () => {
  const event = (id: string, name = "GetCallerIdentity") => ({
    eventID: id,
    eventTime: "2026-10-28T13:58:12Z",
    eventSource: "sts.amazonaws.com",
    eventName: name,
    awsRegion: "us-east-1",
    sourceIPAddress: "198.51.100.201",
    userAgent: "aws-cli/2.17.4",
    userIdentity: { accessKeyId: KEY_ID },
  });
  const send = (body: unknown, headers: Record<string, string> = {}, token = INGEST_TOKEN) =>
    fetch(`${app.base}/api/v1/cloudtrail`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...headers },
      body: typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body),
    });

  it("finds AWS key canaries in the events, once per event", async () => {
    const other = { ...event("x"), userIdentity: { accessKeyId: "AKIAZZZZZZZZZZZZZZZZ" } };
    const res = await send({ Records: [event("e1"), event("e2", "ListBuckets"), other] });
    expect(await res.json()).toEqual({ events: 3, matched: 2, triggers: 1 });
    expect(await (await send(gzipSync(JSON.stringify({ Records: [event("e1")] })), { "content-encoding": "gzip" })).json()).toEqual({
      events: 1,
      matched: 0,
      triggers: 0,
    });
    const { triggers } = await app.get("/api/v1/triggers");
    const aws = triggers.find((t: any) => t.channel === "aws");
    expect(aws).toMatchObject({ source: "198.51.100.201", hits: 2, detail: "sts:GetCallerIdentity in us-east-1", canary: { name: "Deploy key" } });
    expect((await app.get(`/api/v1/triggers/${aws.id}`)).timeline).toHaveLength(2);
  });

  it("refuses what is not JSON, and callers without the token", async () => {
    expect((await send("{nope")).status).toBe(400);
    expect((await send({}, {}, "wrong")).status).toBe(401);
  });
});

describe("triggers over the API", () => {
  it("are decided by editors", async () => {
    const { triggers } = await app.get("/api/v1/triggers?status=open&limit=1");
    const res = await app.admin(`/api/v1/triggers/${triggers[0].id}`, { method: "PUT", body: JSON.stringify({ status: "confirmed" }) });
    expect(((await res.json()) as any).decidedBy).toBe("admin token");
    expect((await app.admin("/api/v1/triggers/missing", { method: "PUT", body: JSON.stringify({ status: "open" }) })).status).toBe(404);
  });
});

describe("the product", () => {
  it("names itself, and has metrics for Prometheus", async () => {
    expect(await (await fetch(`${app.base}/api/v1/version`)).json()).toEqual({ product: "deception", version: "0.1.0" });
    const metrics = await (await fetch(`${app.base}/metrics`)).text();
    expect(metrics).toContain('openasy_build_info{product="deception",version="0.1.0"} 1');
    expect(metrics).toMatch(/openasy_deception_triggers_open \d+/);
    expect(metrics).toMatch(/openasy_deception_canaries\{kind="url"\} \d+/);
  });

  it("keeps canary tokens out of the request log", async () => {
    const lines: string[] = [];
    const write = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk: string) => (lines.push(chunk), true)) as typeof process.stdout.write;
    try {
      await fetch(`${app.base}/c/secrettokenvalue1234`);
    } finally {
      process.stdout.write = write;
    }
    expect(lines.join("")).not.toContain("secrettokenvalue1234");
  });

  it("answers a HEAD on a canary without a body", async () => {
    const res = await new Promise<{ status: number; body: string }>((resolve) =>
      request(`${app.base}/c/aaaaaaaaaaaa`, { method: "HEAD" }, (r) => {
        let body = "";
        r.on("data", (c: Buffer) => (body += c));
        r.on("end", () => resolve({ status: r.statusCode!, body }));
      }).end(),
    );
    expect(res).toEqual({ status: 200, body: "" });
  });
});
