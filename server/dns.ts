// A small authoritative DNS server for the canary zone (ADR 0057). The zone is delegated to it, so a lookup of
// <token>.<zone> anywhere reaches it through the resolvers in between: the source it sees is the last resolver, not
// the person, but a lookup still happens only when someone uses the bait. It answers over UDP only, for names in the
// zone, and refuses the rest, so it cannot be used as an open resolver.
import { createSocket, type Socket } from "node:dgram";
import { isIPv4 } from "node:net";

const TYPES: Record<number, string> = { 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY" };

export interface Query {
  id: number;
  flags: number;
  /** Lowercase, without the trailing dot. */
  name: string;
  type: number;
  /** The question as it was sent, to echo in the answer. */
  question: Buffer;
}

export const typeName = (type: number) => TYPES[type] ?? `TYPE${type}`;

/** The first question of a query, or undefined for anything that is not a well-formed standard query. */
export function parseQuery(msg: Buffer): Query | undefined {
  if (msg.length < 17) return undefined;
  const flags = msg.readUInt16BE(2);
  // A response, or not a standard query (opcode 0).
  if (flags & 0x8000 || (flags >> 11) & 0xf) return undefined;
  if (msg.readUInt16BE(4) < 1) return undefined;
  const labels: string[] = [];
  let at = 12;
  for (;;) {
    const len = msg[at];
    if (len === undefined || len > 63) return undefined; // compression pointers have no place in a question
    at += 1;
    if (len === 0) break;
    if (at + len > msg.length) return undefined;
    labels.push(msg.toString("latin1", at, at + len).toLowerCase());
    at += len;
    if (at > 12 + 255) return undefined;
  }
  if (at + 4 > msg.length) return undefined;
  return { id: msg.readUInt16BE(0), flags, name: labels.join("."), type: msg.readUInt16BE(at), question: msg.subarray(12, at + 4) };
}

/** The label right in front of the zone, which is the token, or undefined for a name outside the zone or the zone itself. */
export function tokenOf(name: string, zone: string): string | undefined {
  if (!name.endsWith(`.${zone}`)) return undefined;
  return (
    name
      .slice(0, -zone.length - 1)
      .split(".")
      .pop() || undefined
  );
}

export const inZone = (name: string, zone: string) => name === zone || name.endsWith(`.${zone}`);

/** The answer: NOERROR with an A record when one is set and asked for, NODATA otherwise, REFUSED outside the zone. */
export function respond(q: Query, zone: string, answerIp?: string): Buffer {
  const header = Buffer.alloc(12);
  const refused = !inZone(q.name, zone);
  const withA = !refused && answerIp !== undefined && (q.type === 1 || q.type === 255) && q.name !== zone;
  header.writeUInt16BE(q.id, 0);
  // QR, authoritative unless refused, RD as asked, RCODE 0 or 5.
  header.writeUInt16BE(0x8000 | (refused ? 0 : 0x0400) | (q.flags & 0x0100) | (refused ? 5 : 0), 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(withA ? 1 : 0, 6);
  if (!withA) return Buffer.concat([header, q.question]);
  const record = Buffer.alloc(16);
  record.writeUInt16BE(0xc00c, 0); // the name in the question
  record.writeUInt16BE(1, 2); // A
  record.writeUInt16BE(1, 4); // IN
  record.writeUInt32BE(0, 6); // TTL 0, so the next use is looked up again
  record.writeUInt16BE(4, 10);
  answerIp.split(".").forEach((b, i) => record.writeUInt8(Number(b), 12 + i));
  return Buffer.concat([header, q.question, record]);
}

export interface DnsOptions {
  port: number;
  zone: string;
  /** An IPv4 address to answer A lookups with; without it, names have no address. */
  answer?: string;
  /** Called for each lookup of a name with a token in it, before the answer is sent. */
  onLookup: (lookup: { token: string; name: string; type: string; source: string }) => void;
  onError?: (err: Error) => void;
}

export function startDns({ port, zone, answer, onLookup, onError }: DnsOptions): Promise<Socket> {
  if (answer !== undefined && !isIPv4(answer)) throw new Error("The DNS answer must be an IPv4 address.");
  const z = zone.toLowerCase().replace(/\.$/, "");
  const socket = createSocket("udp4");
  socket.on("message", (msg, from) => {
    const q = parseQuery(msg);
    if (!q) return;
    const token = tokenOf(q.name, z);
    if (token) {
      try {
        onLookup({ token, name: q.name, type: typeName(q.type), source: from.address });
      } catch (err) {
        onError?.(err as Error);
      }
    }
    socket.send(respond(q, z, answer), from.port, from.address);
  });
  if (onError) socket.on("error", onError);
  return new Promise((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(port, () => (socket.off("error", reject), resolve(socket)));
  });
}
