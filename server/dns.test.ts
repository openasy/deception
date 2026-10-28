import { createSocket } from "node:dgram";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseQuery, respond, startDns, tokenOf } from "./dns.ts";

/** A query as a resolver sends it, with RD set. */
function query(name: string, type = 1, id = 0x1234): Buffer {
  const header = Buffer.from([id >> 8, id & 0xff, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
  const labels = name.split(".").map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]));
  return Buffer.concat([header, ...labels, Buffer.from([0, type >> 8, type & 0xff, 0, 1])]);
}

describe("DNS", () => {
  it("reads the question", () => {
    const q = parseQuery(query("ABC.Canary.Example.com", 28))!;
    expect(q).toMatchObject({ id: 0x1234, name: "abc.canary.example.com", type: 28 });
    expect(parseQuery(Buffer.from([1, 2, 3]))).toBeUndefined();
    const response = query("a.example.com");
    response[2] = 0x81;
    expect(parseQuery(response)).toBeUndefined();
  });

  it("finds the token right in front of the zone", () => {
    expect(tokenOf("k3v9q2.canary.example.com", "canary.example.com")).toBe("k3v9q2");
    expect(tokenOf("data.more.k3v9q2.canary.example.com", "canary.example.com")).toBe("k3v9q2");
    expect(tokenOf("canary.example.com", "canary.example.com")).toBeUndefined();
    expect(tokenOf("k3v9q2.example.org", "canary.example.com")).toBeUndefined();
    expect(tokenOf("xcanary.example.com", "canary.example.com")).toBeUndefined();
  });

  it("answers in the zone with the address, and refuses the rest", () => {
    const a = respond(parseQuery(query("k3v9q2.canary.example.com"))!, "canary.example.com", "192.0.2.10");
    expect(a.readUInt16BE(2)).toBe(0x8500); // QR, AA, RD, NOERROR
    expect(a.readUInt16BE(6)).toBe(1);
    expect([...a.subarray(-4)]).toEqual([192, 0, 2, 10]);
    const nodata = respond(parseQuery(query("k3v9q2.canary.example.com", 16))!, "canary.example.com", "192.0.2.10");
    expect(nodata.readUInt16BE(6)).toBe(0);
    const refused = respond(parseQuery(query("example.org"))!, "canary.example.com");
    expect(refused.readUInt16BE(2) & 0xf).toBe(5);
    expect(refused.readUInt16BE(2) & 0x0400).toBe(0);
  });

  describe("over UDP", () => {
    const lookups: Array<{ token: string; type: string; source: string }> = [];
    let dns: Awaited<ReturnType<typeof startDns>>;
    beforeAll(async () => {
      dns = await startDns({ port: 0, zone: "Canary.Example.com.", answer: "192.0.2.10", onLookup: (l) => lookups.push(l) });
    });
    afterAll(() => dns.close());

    const ask = (msg: Buffer) =>
      new Promise<Buffer>((resolve) => {
        const s = createSocket("udp4");
        s.once("message", (m) => (s.close(), resolve(m)));
        s.send(msg, (dns.address() as AddressInfo).port, "127.0.0.1");
      });

    it("tells of each lookup of a token and answers it", async () => {
      const answer = await ask(query("x1.k3v9q2.canary.example.com", 1, 7));
      expect(answer.readUInt16BE(0)).toBe(7);
      expect(lookups).toEqual([{ token: "k3v9q2", name: "x1.k3v9q2.canary.example.com", type: "A", source: "127.0.0.1" }]);
      await ask(query("www.example.org"));
      expect(lookups).toHaveLength(1);
    });

    it("will not start with an answer that is not an IPv4 address", () => {
      expect(() => startDns({ port: 0, zone: "canary.example.com", answer: "::1", onLookup: () => {} })).toThrow(/IPv4/);
    });
  });
});
