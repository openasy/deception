import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { openDb } from "./db.ts";
import { createDeception } from "./deception.ts";
import { createIncidentsLink } from "./incidents.ts";
import { sealer } from "./seal.ts";

const TOKEN = "oa_incidents_editor";

/** Incidents as deception sees it: one incident per external id, notes on its timeline. */
function fakeIncidents() {
  const incidents: Array<{ id: string; key: string; body: Record<string, any>; evidence: any[]; notes: string[] }> = [];
  let down = false;
  const server: Server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {};
    const send = (status: number, b: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(b));
    if (down) return send(503, { detail: "Starting." });
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return send(401, {});
    if (req.method === "POST" && req.url === "/api/v1/incidents") {
      const same = incidents.find((i) => i.body.external.reference === body.external.reference);
      if (same) return send(200, { id: same.id, key: same.key });
      const i = { id: `id-${incidents.length + 1}`, key: `INC-${incidents.length + 1}`, body, evidence: [], notes: [] };
      incidents.push(i);
      return send(201, { id: i.id, key: i.key });
    }
    const m = /^\/api\/v1\/incidents\/([^/]+)\/(evidence|timeline)$/.exec(req.url!);
    const i = m && incidents.find((x) => x.id === m[1]);
    if (req.method === "POST" && i) {
      if (m![2] === "evidence") i.evidence.push(body);
      else i.notes.push(body.text);
      return send(201, {});
    }
    send(404, {});
  });
  return { server, incidents, setDown: (v: boolean) => (down = v) };
}

const fake = fakeIncidents();
beforeAll(() => new Promise<void>((r) => fake.server.listen(0, "127.0.0.1", r)));
afterAll(() => new Promise<void>((r) => fake.server.close(() => r())));

function setup() {
  let now = Date.parse("2026-10-28T12:00:00Z");
  const d = createDeception(openDb(":memory:"), {
    sealer: sealer(undefined),
    canaryUrl: "https://cdn.example.com",
    clock: () => now,
    incidents: {
      link: createIncidentsLink({
        url: `http://127.0.0.1:${(fake.server.address() as AddressInfo).port}`,
        token: TOKEN,
        publicUrl: "https://incidents.example.com",
        product: "deception",
      }),
      severity: "critical",
      triggerUrl: (id) => `https://deception.example.com/triggers/${id}`,
    },
  });
  const { canary } = d.createCanary({ name: "Payroll export", template: "html", location: "//fs01/finance/passwords.html", host: "fs01" }, "Ada");
  const use = (source: string) => d.touch({ token: canary.address!.split("/c/")[1]!, channel: "http", source, detail: "GET /c/…" })!.trigger;
  return { d, use, later: (ms: number) => (now += ms) };
}

describe("incidents", () => {
  it("opens one critical incident per trigger, with a link back", async () => {
    const { d, use } = setup();
    const trigger = use("198.51.100.7");
    await d.sendIncidents();
    await d.sendIncidents();
    const i = fake.incidents.at(-1)!;
    expect(i.body).toMatchObject({
      title: "Canary used: Payroll export",
      severity: "critical",
      products: ["deception"],
      external: { source: "deception", reference: `trigger:${trigger}` },
    });
    expect(i.body.summary).toContain("planted at //fs01/finance/passwords.html on fs01 was used from 198.51.100.7");
    expect(i.evidence).toEqual([{ title: "Deception trigger: Payroll export", url: `https://deception.example.com/triggers/${trigger}`, source: "deception" }]);
    expect(d.trigger(trigger).incident).toEqual({ state: "opened", key: i.key, url: `https://incidents.example.com/incidents/${i.key}`, error: null });
    expect(fake.incidents.filter((x) => x.body.external.reference === `trigger:${trigger}`)).toHaveLength(1);
  });

  it("notes on the incident when the trigger was a test", async () => {
    const { d, use } = setup();
    const trigger = use("192.0.2.44");
    await d.sendIncidents();
    d.decide(trigger, { status: "test", reason: "Quarterly drill" }, "Emily");
    await d.sendIncidents();
    expect(fake.incidents.at(-1)!.notes).toEqual(["Deception: the trigger was marked as a test by Emily: Quarterly drill"]);
  });

  it("tries again while Incidents is down, for a day, and opens none for a test", async () => {
    const { d, use, later } = setup();
    const before = fake.incidents.length;
    fake.setDown(true);
    const trigger = use("203.0.113.9");
    const test = use("203.0.113.10");
    await d.sendIncidents();
    expect(d.trigger(trigger).incident).toMatchObject({ state: "pending", error: "Incidents answered 503: Starting." });
    expect(d.summary().incidents).toEqual({ on: true, failing: 2 });
    d.decide(test, { status: "test", reason: "drill" }, "Ada");
    later(25 * 3_600_000);
    await d.sendIncidents();
    expect(d.trigger(trigger).incident?.state).toBe("failed");
    expect(d.trigger(test).incident).toBeNull();
    fake.setDown(false);
    await d.sendIncidents();
    expect(fake.incidents.length).toBe(before);
  });
});
