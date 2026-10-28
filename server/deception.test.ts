import { describe, expect, it } from "vitest";
import { openDb } from "./db.ts";
import { createDeception, SAME_TRIGGER_MS, type DeceptionOptions } from "./deception.ts";
import { sealer } from "./seal.ts";
import { KEY_ID, KEY_SECRET } from "./test-app.ts";

const T0 = Date.parse("2026-10-28T12:00:00Z");

function setup(opts: Partial<DeceptionOptions> = {}) {
  let now = T0;
  const db = openDb(":memory:");
  const d = createDeception(db, {
    sealer: sealer(Buffer.alloc(32, 3)),
    canaryUrl: "https://cdn.example.com",
    dnsZone: "canary.example.com",
    clock: () => now,
    ...opts,
  });
  const url = (name = "Wiki link") => d.createCanary({ name, template: "link", location: "wiki: Ops/Passwords" }, "Ada");
  const tokenOf = (address: string | null) => address!.split("/c/")[1]!;
  return { db, d, url, tokenOf, at: (ms: number) => (now = T0 + ms) };
}

describe("canaries", () => {
  it("makes each with its own token, and names the copy in its bait", () => {
    const { d, url, tokenOf } = setup();
    const a = url("A");
    const b = url("B");
    expect(a.canary).toMatchObject({ name: "A", kind: "url", template: "link", state: "armed", triggers: 0, createdBy: "Ada" });
    expect(tokenOf(a.canary.address)).toMatch(/^[a-z0-9]{24}$/);
    expect(a.canary.address).not.toBe(b.canary.address);
    expect(a.bait.content).toBe(a.canary.address);
    expect(d.bait(a.canary.id).content).toBe(a.canary.address);
  });

  it("keeps an AWS key's secret sealed, and gives it back in the bait", () => {
    const { db, d } = setup();
    const { canary, bait } = d.createCanary({ name: "Deploy key", template: "aws-credentials", accessKeyId: KEY_ID, secretAccessKey: KEY_SECRET }, "Ada");
    expect(canary).toMatchObject({ kind: "aws-key", address: KEY_ID });
    expect(bait.content).toContain(KEY_SECRET);
    expect(JSON.stringify(db.prepare("SELECT secret FROM canaries").get())).not.toContain("wJalr");
    expect(() => d.createCanary({ name: "Again", template: "aws-credentials", accessKeyId: KEY_ID, secretAccessKey: KEY_SECRET }, "Ada")).toThrow(/exists/);
    expect(() => d.createCanary({ name: "Bad", template: "aws-credentials", accessKeyId: "AKIA123", secretAccessKey: KEY_SECRET }, "Ada")).toThrow(/AKIA/);
  });

  it("refuses what it cannot make", () => {
    const { d } = setup({ dnsZone: undefined });
    expect(() => d.createCanary({ name: "x", template: "pdf" }, "Ada")).toThrow(/template is one of/);
    expect(() => d.createCanary({ name: "", template: "link" }, "Ada")).toThrow(/name is required/);
    expect(() => d.createCanary({ name: "x", template: "link", kind: "dns" }, "Ada")).toThrow(/makes a url canary/);
    expect(() => d.createCanary({ name: "x", template: "hostname" }, "Ada")).toThrow(/DECEPTION_DNS_ZONE/);
  });

  it("changes where it is and turns it off, with the same token", () => {
    const { d, url } = setup();
    const { canary } = url();
    const changed = d.updateCanary(canary.id, { location: "fs01:/finance", host: "fs01", enabled: false });
    expect(changed).toMatchObject({ location: "fs01:/finance", host: "fs01", enabled: false, state: "disabled", address: canary.address });
    expect(() => d.updateCanary(canary.id, {})).toThrow(/at least one/);
    expect(() => d.updateCanary(canary.id, { enabled: "no" })).toThrow(/true or false/);
    expect(() => d.updateCanary("missing", { name: "x" })).toThrow(/does not exist/);
  });

  it("finds them by name, place or host, kind and state", () => {
    const { d, url } = setup();
    url("Wiki link");
    d.createCanary({ name: "Bastion", template: "ssh-config", host: "worker-prod-04" }, "Ada");
    expect(d.canaries({ q: "prod-04" }).map((c) => c.name)).toEqual(["Bastion"]);
    expect(d.canaries({ q: "Ops/" }).map((c) => c.name)).toEqual(["Wiki link"]);
    expect(d.canaries({ q: "%" })).toEqual([]);
    expect(d.canaries({ kind: "dns" }).map((c) => c.name)).toEqual(["Bastion"]);
    expect(d.canaries({ state: "armed" })).toHaveLength(2);
    expect(() => d.canaries({ kind: "pdf" })).toThrow();
  });
});

describe("triggers", () => {
  it("are one per source, with later uses as hits", () => {
    const { d, url, tokenOf, at } = setup();
    const { canary } = url();
    const token = tokenOf(canary.address);
    const use = (source: string, detail = "GET /c/x") => d.touch({ token, channel: "http", source, userAgent: "curl/8.7", detail });
    const first = use("198.51.100.7")!;
    expect(first.created).toBe(true);
    at(5 * 60_000);
    expect(use("198.51.100.7", "GET /c/x/again")).toEqual({ trigger: first.trigger, created: false });
    expect(use("203.0.113.9")!.created).toBe(true);
    at(5 * 60_000 + SAME_TRIGGER_MS + 1);
    expect(use("198.51.100.7")!.created).toBe(true);

    const t = d.trigger(first.trigger);
    expect(t).toMatchObject({ channel: "http", source: "198.51.100.7", userAgent: "curl/8.7", hits: 2, status: "open", detail: "GET /c/x", incident: null });
    expect(t.canary).toMatchObject({ id: canary.id, name: "Wiki link", location: "wiki: Ops/Passwords" });
    expect(t.timeline.map((h) => h.detail)).toEqual(["GET /c/x", "GET /c/x/again"]);
    expect(d.canary(canary.id)).toMatchObject({ state: "triggered", triggers: 3, openTriggers: 3 });
  });

  it("are not made by unknown tokens, a turned-off canary, or the wrong channel", () => {
    const { d, url, tokenOf } = setup();
    const { canary } = url();
    expect(d.touch({ token: "nothing", channel: "http", source: "x", detail: "" })).toBeUndefined();
    expect(d.touch({ token: tokenOf(canary.address), channel: "dns", source: "x", detail: "" })).toBeUndefined();
    d.updateCanary(canary.id, { enabled: false });
    expect(d.touch({ token: tokenOf(canary.address), channel: "http", source: "x", detail: "" })).toBeUndefined();
  });

  it("keep an event sent twice once", () => {
    const { d } = setup();
    d.createCanary({ name: "Key", template: "aws-credentials", accessKeyId: KEY_ID, secretAccessKey: KEY_SECRET }, "Ada");
    const use = {
      token: KEY_ID,
      channel: "aws" as const,
      source: "198.51.100.201",
      detail: "sts:GetCallerIdentity",
      at: "2026-10-28T11:58:00.000Z",
      ref: "e1",
    };
    expect(d.touch(use)!.created).toBe(true);
    expect(d.touch(use)).toBeUndefined();
    expect(d.triggers({}, undefined, 10).items[0]).toMatchObject({ hits: 1, firstAt: "2026-10-28T11:58:00.000Z" });
  });

  it("are decided by a person, and a test needs a reason", () => {
    const { d, url, tokenOf } = setup();
    const { canary } = url();
    const { trigger } = d.touch({ token: tokenOf(canary.address), channel: "http", source: "192.0.2.44", detail: "GET" })!;
    expect(() => d.decide(trigger, { status: "test" }, "Ada")).toThrow(/why/);
    expect(() => d.decide(trigger, { status: "fine" }, "Ada")).toThrow(/open, confirmed or test/);
    expect(d.decide(trigger, { status: "test", reason: "Quarterly test by Emily" }, "Ada")).toMatchObject({
      status: "test",
      reason: "Quarterly test by Emily",
      decidedBy: "Ada",
    });
    expect(d.canary(canary.id)).toMatchObject({ state: "armed", openTriggers: 0 });
    expect(d.decide(trigger, { status: "open" }, "Ada")).toMatchObject({ status: "open", reason: null, decidedBy: null });
    expect(d.decide(trigger, { status: "confirmed" }, "Ada")).toMatchObject({ status: "confirmed", decidedBy: "Ada" });
  });

  it("page newest first", () => {
    const { d, url, tokenOf, at } = setup();
    const { canary } = url();
    for (let i = 0; i < 3; i++) (at(i * SAME_TRIGGER_MS * 2), d.touch({ token: tokenOf(canary.address), channel: "http", source: "x", detail: `use ${i}` }));
    const first = d.triggers({}, undefined, 2);
    expect(first.items.map((t) => t.detail)).toEqual(["use 2", "use 1"]);
    expect(d.triggers({}, first.nextCursor, 2).items.map((t) => t.detail)).toEqual(["use 0"]);
    expect(d.triggers({ status: "confirmed" }, undefined, 2).items).toEqual([]);
    expect(() => d.triggers({}, "junk", 2)).toThrow(/cursor/);
  });

  it("are deleted after the retention, with the canary kept", () => {
    const { d, url, tokenOf, at } = setup({ retentionDays: 30 });
    const { canary } = url();
    d.touch({ token: tokenOf(canary.address), channel: "http", source: "x", detail: "GET" });
    at(31 * 86_400_000);
    expect(d.purge()).toBe(1);
    expect(d.canary(canary.id).triggers).toBe(0);
  });
});

describe("summary", () => {
  it("counts canaries by state and kind, and triggers by day", () => {
    const { d, url, tokenOf, at } = setup();
    const a = url("A").canary;
    url("B");
    d.createCanary({ name: "C", template: "hostname" }, "Ada");
    at(2 * 86_400_000);
    const { trigger } = d.touch({ token: tokenOf(a.address), channel: "http", source: "x", detail: "GET" })!;
    const s = d.summary();
    expect(s.canaries).toEqual({ total: 3, armed: 2, triggered: 1, disabled: 0, byKind: { url: 2, dns: 1, "aws-key": 0 } });
    expect(s.triggers).toMatchObject({ last30Days: 1, open: 1, confirmed: 0, tests: 0, lastAt: "2026-10-30T12:00:00.000Z" });
    expect(s.triggers.perDay).toHaveLength(30);
    expect(s.triggers.perDay.at(-1)).toEqual({ date: "2026-10-30", triggers: 1 });
    expect(s.latest.map((t) => t.id)).toEqual([trigger]);
    expect(s.setup).toEqual({ canaryUrl: "https://cdn.example.com", dnsZone: "canary.example.com" });
    expect(s.incidents).toEqual({ on: false, failing: 0 });
    d.decide(trigger, { status: "test", reason: "drill" }, "Ada");
    expect(d.summary().triggers).toMatchObject({ last30Days: 0, open: 0, tests: 1, lastAt: null });
  });
});
