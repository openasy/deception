import { randomBytes } from "node:crypto";
import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import { bait, canaryName, canaryUrl, isTemplate, KINDS, TEMPLATES, type Bait, type Kind, type Template } from "./baits.ts";
import type { IncidentsLink, Severity } from "./incidents.ts";
import type { Sealer } from "./seal.ts";

export type ProblemCode =
  "invalid-token" | "invalid-json" | "invalid-body" | "not-found" | "conflict" | "not-configured" | "payload-too-large" | "internal-error";

export class DeceptionError extends Error {
  readonly status: number;
  readonly code: ProblemCode;
  constructor(status: number, code: ProblemCode, detail: string) {
    super(detail);
    this.status = status;
    this.code = code;
  }
}

const bad = (detail: string) => new DeceptionError(422, "invalid-body", detail);
const notFound = (what: string) => new DeceptionError(404, "not-found", `${what} does not exist.`);

const MINUTE = 60_000;
const DAY_MS = 86_400_000;
/** Uses from the same source within this time are hits of one trigger, not new triggers. */
export const SAME_TRIGGER_MS = 15 * MINUTE;
/** A trigger keeps the first uses for its timeline; later ones are counted. */
const HITS_KEPT = 100;

export type Channel = "http" | "dns" | "aws";
export type TriggerStatus = "open" | "confirmed" | "test";
const STATUSES: readonly TriggerStatus[] = ["open", "confirmed", "test"];
const CHANNEL_OF: Record<Kind, Channel> = { url: "http", dns: "dns", "aws-key": "aws" };

export interface Page<T> {
  items: T[];
  /** Opaque; pass it back as `cursor` for the next page. Absent on the last page (ADR 0024). */
  nextCursor?: string;
}

const encodeCursor = (offset: number) => Buffer.from(JSON.stringify({ o: offset })).toString("base64url");
function decodeCursor(cursor: string | undefined): number {
  if (!cursor) return 0;
  try {
    const o = (JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as { o?: unknown }).o;
    if (typeof o === "number" && Number.isSafeInteger(o) && o >= 0) return o;
  } catch {
    // fall through
  }
  throw bad("cursor is not one this API returned.");
}

export function parseLimit(value: string | null, max = 500, fallback = 100): number {
  if (value === null) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > max) throw bad(`limit must be between 1 and ${max}.`);
  return n;
}

/** Lowercase letters and digits, which fit a URL path and a DNS label alike, and are not in any dictionary. */
const ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";
function randomToken(length: number): string {
  let out = "";
  // 252 is the largest multiple of 36 below 256, so every character is as likely as the others.
  while (out.length < length) for (const b of randomBytes(length * 2)) if (b < 252 && out.length < length) out += ALPHABET[b % 36];
  return out;
}

const AWS_KEY_ID = /^AKIA[A-Z2-7]{16}$/;
const AWS_SECRET = /^[A-Za-z0-9/+]{40}$/;

// ------------------------------------------------------------------ shapes

export type CanaryState = "armed" | "triggered" | "disabled";

export interface Canary {
  id: string;
  name: string;
  kind: Kind;
  template: Template;
  /** What the bait carries: its URL, its DNS name, or its access key ID. Null for a DNS canary while no zone is set. */
  address: string | null;
  location: string;
  host: string;
  note: string;
  enabled: boolean;
  state: CanaryState;
  triggers: number;
  openTriggers: number;
  lastTriggeredAt: string | null;
  createdAt: string;
  createdBy: string;
}

export interface Hit {
  at: string;
  detail: string;
}

export interface Trigger {
  id: string;
  canary: { id: string; name: string; kind: Kind; location: string; host: string } | null;
  channel: Channel;
  source: string;
  userAgent: string;
  /** What the first use was, such as GET /c/… or sts:GetCallerIdentity in us-east-1. */
  detail: string;
  firstAt: string;
  lastAt: string;
  hits: number;
  status: TriggerStatus;
  reason: string | null;
  decidedBy: string | null;
  decidedAt: string | null;
  incident: { state: "pending" | "opened" | "failed"; key: string | null; url: string | null; error: string | null } | null;
}

export interface Use {
  /** The URL's last part, the DNS label, or the AWS access key ID. */
  token: string;
  channel: Channel;
  source: string;
  userAgent?: string;
  detail: string;
  /** When it happened; now unless the event says. */
  at?: string;
  /** The event's own id, so the same event sent twice counts once. */
  ref?: string;
}

export interface DeceptionOptions {
  retentionDays?: number;
  clock?: () => number;
  /** Seals the secret of AWS key canaries. */
  sealer: Sealer;
  /** The address URL canaries call, which may be another name than the one people open. */
  canaryUrl: string;
  /** The delegated DNS zone; DNS canaries need it. */
  dnsZone?: string;
  /** Opens an incident in OpenAsy Incidents for each trigger (ADR 0041). */
  incidents?: {
    link: IncidentsLink;
    severity: Severity;
    /** The trigger's page in deception, linked from the incident. */
    triggerUrl: (id: string) => string;
  };
}

type Row = Record<string, SQLInputValue>;

const KIND_LABEL: Record<Kind, string> = { url: "URL", dns: "DNS", "aws-key": "AWS key" };

export function createDeception(db: DatabaseSync, { retentionDays = 365, clock = Date.now, sealer, canaryUrl: base, dnsZone, incidents }: DeceptionOptions) {
  const iso = (ms = clock()) => new Date(ms).toISOString();
  const zone = dnsZone?.toLowerCase().replace(/\.$/, "");

  const address = (kind: Kind, token: string) => (kind === "url" ? canaryUrl(base, token) : kind === "dns" ? (zone ? canaryName(zone, token) : null) : token);

  const CANARY_SELECT = `SELECT c.*,
      (SELECT COUNT(*) FROM triggers t WHERE t.canary_id = c.id) AS n_triggers,
      (SELECT COUNT(*) FROM triggers t WHERE t.canary_id = c.id AND t.status = 'open') AS n_open,
      (SELECT COUNT(*) FROM triggers t WHERE t.canary_id = c.id AND t.status != 'test') AS n_real,
      (SELECT MAX(last_at) FROM triggers t WHERE t.canary_id = c.id) AS last_triggered_at
    FROM canaries c`;

  function toCanary(r: Row): Canary {
    const kind = r.kind as Kind;
    const enabled = r.enabled === 1;
    return {
      id: r.id as string,
      name: r.name as string,
      kind,
      template: r.template as Template,
      address: address(kind, r.token as string),
      location: r.location as string,
      host: r.host as string,
      note: r.note as string,
      enabled,
      state: !enabled ? "disabled" : Number(r.n_real) > 0 ? "triggered" : "armed",
      triggers: Number(r.n_triggers),
      openTriggers: Number(r.n_open),
      lastTriggeredAt: (r.last_triggered_at as string | null) ?? null,
      createdAt: r.created_at as string,
      createdBy: r.created_by as string,
    };
  }

  function toTrigger(r: Row): Trigger {
    return {
      id: r.id as string,
      canary: r.c_name
        ? { id: r.canary_id as string, name: r.c_name as string, kind: r.c_kind as Kind, location: r.c_location as string, host: r.c_host as string }
        : null,
      channel: r.channel as Channel,
      source: r.source as string,
      userAgent: r.user_agent as string,
      detail: (r.first_detail as string | null) ?? "",
      firstAt: r.first_at as string,
      lastAt: r.last_at as string,
      hits: Number(r.hits),
      status: r.status as TriggerStatus,
      reason: (r.reason as string | null) ?? null,
      decidedBy: (r.decided_by as string | null) ?? null,
      decidedAt: (r.decided_at as string | null) ?? null,
      incident: r.incident_state
        ? {
            state: r.incident_state as "pending" | "opened" | "failed",
            key: (r.incident_key as string | null) ?? null,
            url: (r.incident_url as string | null) ?? null,
            error: (r.incident_error as string | null) ?? null,
          }
        : null,
    };
  }

  const TRIGGER_SELECT = `SELECT t.*, c.name AS c_name, c.kind AS c_kind, c.location AS c_location, c.host AS c_host,
      (SELECT detail FROM hits h WHERE h.trigger_id = t.id ORDER BY h.at, h.id LIMIT 1) AS first_detail
    FROM triggers t LEFT JOIN canaries c ON c.id = t.canary_id`;

  const getCanaryRow = (id: string) => db.prepare(`${CANARY_SELECT} WHERE c.id = ?`).get(id) as Row | undefined;
  const getTriggerRow = (id: string) => db.prepare(`${TRIGGER_SELECT} WHERE t.id = ?`).get(id) as Row | undefined;

  function text(body: Record<string, unknown>, name: string, max: number, required = false): string | undefined {
    const v = body[name];
    if (v === undefined || v === null) {
      if (required) throw bad(`${name} is required.`);
      return undefined;
    }
    if (typeof v !== "string") throw bad(`${name} must be text.`);
    const t = v.trim();
    if (required && !t) throw bad(`${name} is required.`);
    if (t.length > max) throw bad(`${name} is at most ${max} characters.`);
    return t;
  }

  function baitOf(r: Row): Bait {
    const secret = r.secret ? sealer.open(r.secret as string) : undefined;
    return bait({ template: r.template as Template, token: r.token as string, secret, canaryUrl: base, dnsZone: zone });
  }

  return {
    // ---------------------------------------------------------------- canaries

    canaries(filter: { kind?: string | null; state?: string | null; q?: string | null } = {}): Canary[] {
      if (filter.kind && !(KINDS as readonly string[]).includes(filter.kind)) throw bad(`kind is one of ${KINDS.join(", ")}.`);
      if (filter.state && !["armed", "triggered", "disabled"].includes(filter.state)) throw bad("state is armed, triggered or disabled.");
      const where: string[] = [];
      const args: SQLInputValue[] = [];
      if (filter.kind) (where.push("c.kind = ?"), args.push(filter.kind));
      if (filter.q) {
        where.push("(c.name LIKE ? ESCAPE '\\' OR c.location LIKE ? ESCAPE '\\' OR c.host LIKE ? ESCAPE '\\')");
        const like = `%${filter.q.replace(/[\\%_]/g, (m) => `\\${m}`)}%`;
        args.push(like, like, like);
      }
      const rows = db.prepare(`${CANARY_SELECT}${where.length ? ` WHERE ${where.join(" AND ")}` : ""} ORDER BY c.created_at DESC, c.id`).all(...args) as Row[];
      const all = rows.map(toCanary);
      return filter.state ? all.filter((c) => c.state === filter.state) : all;
    },

    canary(id: string): Canary {
      const r = getCanaryRow(id);
      if (!r) throw notFound("The canary");
      return toCanary(r);
    },

    /** Makes a canary and its bait. The token is new for each, so a trigger names the one copy that was used. */
    createCanary(body: Record<string, unknown>, actor: string): { canary: Canary; bait: Bait } {
      const name = text(body, "name", 120, true)!;
      const template = body.template;
      if (!isTemplate(template)) throw bad(`template is one of ${Object.keys(TEMPLATES).join(", ")}.`);
      const kind = TEMPLATES[template].kind;
      if (body.kind !== undefined && body.kind !== kind) throw bad(`The ${template} template makes a ${kind} canary.`);
      if (kind === "dns" && !zone)
        throw new DeceptionError(409, "not-configured", "DNS canaries need a zone: set DECEPTION_DNS_ZONE and delegate the zone to deception.");
      let token: string;
      let secret: string | null = null;
      if (kind === "aws-key") {
        const keyId = text(body, "accessKeyId", 20, true)!;
        const keySecret = text(body, "secretAccessKey", 40, true)!;
        if (!AWS_KEY_ID.test(keyId)) throw bad("accessKeyId is an AWS access key ID: AKIA and 16 more letters and digits.");
        if (!AWS_SECRET.test(keySecret)) throw bad("secretAccessKey is the 40 characters AWS gave with the key.");
        token = keyId;
        secret = sealer.seal(keySecret);
      } else token = randomToken(kind === "dns" ? 16 : 24);
      const id = `cn_${randomToken(10)}`;
      try {
        db.prepare(
          "INSERT INTO canaries (id, name, kind, template, token, secret, location, host, note, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ).run(
          id,
          name,
          kind,
          template,
          token,
          secret,
          text(body, "location", 500) ?? "",
          text(body, "host", 200) ?? "",
          text(body, "note", 1000) ?? "",
          iso(),
          actor,
        );
      } catch (err) {
        if (/UNIQUE/.test(String(err))) throw new DeceptionError(409, "conflict", "A canary with this access key ID exists.");
        throw err;
      }
      const r = getCanaryRow(id)!;
      return { canary: toCanary(r), bait: baitOf(r) };
    },

    bait(id: string): Bait {
      const r = getCanaryRow(id);
      if (!r) throw notFound("The canary");
      if (r.kind === "dns" && !zone) throw new DeceptionError(409, "not-configured", "DNS canaries need a zone: set DECEPTION_DNS_ZONE.");
      return baitOf(r);
    },

    /** Changes where it is planted, its name and note, or turns it off. The token and bait never change. */
    updateCanary(id: string, body: Record<string, unknown>): Canary {
      if (!getCanaryRow(id)) throw notFound("The canary");
      const sets: string[] = [];
      const args: SQLInputValue[] = [];
      const fields = [
        ["name", 120, true],
        ["location", 500, false],
        ["host", 200, false],
        ["note", 1000, false],
      ] as const;
      for (const [field, max, required] of fields) {
        if (body[field] === undefined) continue;
        const v = text(body, field, max, required);
        sets.push(`${field} = ?`);
        args.push(v ?? "");
      }
      if (body.enabled !== undefined) {
        if (typeof body.enabled !== "boolean") throw bad("enabled must be true or false.");
        sets.push("enabled = ?");
        args.push(body.enabled ? 1 : 0);
      }
      if (!sets.length) throw bad("Send at least one of name, location, host, note and enabled.");
      db.prepare(`UPDATE canaries SET ${sets.join(", ")} WHERE id = ?`).run(...args, id);
      return toCanary(getCanaryRow(id)!);
    },

    deleteCanary(id: string): void {
      if (!db.prepare("DELETE FROM canaries WHERE id = ?").run(id).changes) throw notFound("The canary");
    },

    // ---------------------------------------------------------------- uses and triggers

    /**
     * Records a use of a canary: a new trigger, or one more hit of the trigger from the same source in the last 15
     * minutes. Returns undefined when no enabled canary has the token, so a guessed token leaves nothing behind.
     */
    touch(use: Use): { trigger: string; created: boolean } | undefined {
      const canary = db.prepare("SELECT id, kind FROM canaries WHERE token = ? AND enabled = 1").get(use.token) as Row | undefined;
      if (!canary || CHANNEL_OF[canary.kind as Kind] !== use.channel) return undefined;
      if (use.ref && db.prepare("SELECT 1 FROM hits WHERE ref = ?").get(use.ref)) return undefined;
      const at = use.at ?? iso();
      const source = use.source.slice(0, 64);
      db.exec("BEGIN IMMEDIATE");
      try {
        const same = db
          .prepare("SELECT id, last_at FROM triggers WHERE canary_id = ? AND source = ? AND last_at >= ? ORDER BY last_at DESC LIMIT 1")
          .get(canary.id as string, source, new Date(Date.parse(at) - SAME_TRIGGER_MS).toISOString()) as Row | undefined;
        let trigger: string;
        if (same) {
          trigger = same.id as string;
          db.prepare("UPDATE triggers SET hits = hits + 1, last_at = MAX(last_at, ?) WHERE id = ?").run(at, trigger);
        } else {
          trigger = `tr_${randomToken(12)}`;
          db.prepare(
            "INSERT INTO triggers (id, canary_id, channel, source, user_agent, first_at, last_at, incident_state) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
          ).run(trigger, canary.id as string, use.channel, source, (use.userAgent ?? "").slice(0, 512), at, at, incidents ? "pending" : null);
        }
        const kept = (db.prepare("SELECT COUNT(*) AS n FROM hits WHERE trigger_id = ?").get(trigger) as { n: number }).n;
        if (kept < HITS_KEPT || use.ref)
          db.prepare("INSERT INTO hits (trigger_id, at, detail, ref) VALUES (?, ?, ?, ?)").run(trigger, at, use.detail.slice(0, 512), use.ref ?? null);
        db.exec("COMMIT");
        return { trigger, created: !same };
      } catch (err) {
        db.exec("ROLLBACK");
        throw err;
      }
    },

    triggers(filter: { status?: string | null; canary?: string | null }, cursor: string | undefined, limit: number): Page<Trigger> {
      if (filter.status && !(STATUSES as readonly string[]).includes(filter.status)) throw bad("status is open, confirmed or test.");
      const where: string[] = [];
      const args: SQLInputValue[] = [];
      if (filter.status) (where.push("t.status = ?"), args.push(filter.status));
      if (filter.canary) (where.push("t.canary_id = ?"), args.push(filter.canary));
      const offset = decodeCursor(cursor);
      const rows = db
        .prepare(`${TRIGGER_SELECT}${where.length ? ` WHERE ${where.join(" AND ")}` : ""} ORDER BY t.first_at DESC, t.id LIMIT ? OFFSET ?`)
        .all(...args, limit + 1, offset) as Row[];
      return { items: rows.slice(0, limit).map(toTrigger), ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }) };
    },

    trigger(id: string): Trigger & { timeline: Hit[] } {
      const r = getTriggerRow(id);
      if (!r) throw notFound("The trigger");
      const timeline = db.prepare("SELECT at, detail FROM hits WHERE trigger_id = ? ORDER BY at, id").all(id) as unknown as Hit[];
      return { ...toTrigger(r), timeline };
    },

    /** A person says what a trigger was: a breach (confirmed), a test, or back to open. */
    decide(id: string, body: Record<string, unknown>, actor: string): Trigger {
      const r = getTriggerRow(id);
      if (!r) throw notFound("The trigger");
      const status = body.status;
      if (typeof status !== "string" || !(STATUSES as readonly string[]).includes(status)) throw bad("status is open, confirmed or test.");
      const reason = text(body, "reason", 500) || null;
      if (status === "test" && !reason) throw bad("Say why it was a test, such as who ran it.");
      const open = status === "open";
      db.prepare(
        "UPDATE triggers SET status = ?, reason = ?, decided_by = ?, decided_at = ?, incident_note = CASE WHEN ? AND incident_state IN ('pending', 'opened') THEN 'pending' ELSE incident_note END WHERE id = ?",
      ).run(status, open ? null : reason, open ? null : actor, open ? null : iso(), status === "test" ? 1 : 0, id);
      return toTrigger(getTriggerRow(id)!);
    },

    /**
     * Opens the incidents of triggers waiting for one, then notes on those marked as a test. What fails stays waiting,
     * with why, and is tried again at the next turn, for a day; Incidents keeps one incident per trigger, so a retry
     * never opens a second.
     */
    async sendIncidents(): Promise<void> {
      if (!incidents) return;
      // A test that never reached Incidents needs no incident.
      db.prepare(
        "UPDATE triggers SET incident_state = NULL, incident_note = NULL, incident_error = NULL WHERE incident_state IN ('pending', 'failed') AND status = 'test'",
      ).run();
      db.prepare(
        "UPDATE triggers SET incident_state = 'failed', incident_error = COALESCE(incident_error, 'Incidents was not reached for a day.') WHERE incident_state = 'pending' AND first_at < ?",
      ).run(iso(clock() - DAY_MS));
      const waiting = db.prepare(`${TRIGGER_SELECT} WHERE t.incident_state = 'pending' AND t.status != 'test' ORDER BY t.first_at LIMIT 50`).all() as Row[];
      for (const r of waiting) {
        const t = toTrigger(r);
        const c = t.canary;
        try {
          const opened = await incidents.link.open({
            reference: `trigger:${t.id}`,
            title: `Canary used: ${c?.name ?? "a deleted canary"}`,
            severity: incidents.severity,
            summary: [
              `The ${c ? KIND_LABEL[c.kind] : ""} canary "${c?.name ?? ""}"${c?.location ? ` planted at ${c.location}` : ""}${c?.host ? ` on ${c.host}` : ""} was used from ${t.source} at ${t.firstAt}: ${t.detail}.`,
              "Nobody has a reason to use it, so treat this as a breach until shown otherwise.",
              t.channel === "dns" ? "The source of a DNS canary is the last resolver that asked, not the person." : "",
            ]
              .filter(Boolean)
              .join(" "),
            evidence: { title: `Deception trigger: ${c?.name ?? t.id}`, url: incidents.triggerUrl(t.id) },
          });
          db.prepare(
            "UPDATE triggers SET incident_state = 'opened', incident_id = ?, incident_key = ?, incident_url = ?, incident_error = NULL WHERE id = ?",
          ).run(opened.id, opened.key, opened.url, t.id);
        } catch (err) {
          db.prepare("UPDATE triggers SET incident_error = ? WHERE id = ?").run((err as Error).message.slice(0, 300), t.id);
        }
      }
      const notes = db.prepare("SELECT * FROM triggers WHERE incident_state = 'opened' AND incident_note = 'pending' LIMIT 50").all() as Row[];
      for (const r of notes) {
        try {
          await incidents.link.note(r.incident_id as string, `Deception: the trigger was marked as a test by ${r.decided_by as string}: ${r.reason as string}`);
          db.prepare("UPDATE triggers SET incident_note = 'sent', incident_error = NULL WHERE id = ?").run(r.id as string);
        } catch (err) {
          db.prepare("UPDATE triggers SET incident_error = ? WHERE id = ?").run((err as Error).message.slice(0, 300), r.id as string);
        }
      }
    },

    // ---------------------------------------------------------------- overview

    summary() {
      const now = clock();
      const canaries = this.canaries();
      const since = iso(now - 30 * DAY_MS);
      const count = (sql: string, ...args: SQLInputValue[]) => (db.prepare(sql).get(...args) as { n: number }).n;
      const byDay = new Map(
        (db.prepare("SELECT substr(first_at, 1, 10) AS day, COUNT(*) AS n FROM triggers WHERE first_at >= ? GROUP BY day").all(since) as Row[]).map((r) => [
          r.day as string,
          Number(r.n),
        ]),
      );
      const today = Date.parse(iso(now).slice(0, 10));
      const perDay = Array.from({ length: 30 }, (_, i) => {
        const date = new Date(today - (29 - i) * DAY_MS).toISOString().slice(0, 10);
        return { date, triggers: byDay.get(date) ?? 0 };
      });
      const last = db.prepare("SELECT MAX(first_at) AS at FROM triggers WHERE status != 'test'").get() as { at: string | null };
      return {
        canaries: {
          total: canaries.length,
          armed: canaries.filter((c) => c.state === "armed").length,
          triggered: canaries.filter((c) => c.state === "triggered").length,
          disabled: canaries.filter((c) => c.state === "disabled").length,
          byKind: Object.fromEntries(KINDS.map((k) => [k, canaries.filter((c) => c.kind === k).length])) as Record<Kind, number>,
        },
        triggers: {
          last30Days: count("SELECT COUNT(*) AS n FROM triggers WHERE first_at >= ? AND status != 'test'", since),
          open: count("SELECT COUNT(*) AS n FROM triggers WHERE status = 'open'"),
          confirmed: count("SELECT COUNT(*) AS n FROM triggers WHERE status = 'confirmed' AND first_at >= ?", since),
          tests: count("SELECT COUNT(*) AS n FROM triggers WHERE status = 'test' AND first_at >= ?", since),
          lastAt: last.at,
          perDay,
        },
        latest: (db.prepare(`${TRIGGER_SELECT} ORDER BY t.first_at DESC LIMIT 5`).all() as Row[]).map(toTrigger),
        incidents: incidents
          ? {
              on: true,
              failing: count(
                "SELECT COUNT(*) AS n FROM triggers WHERE incident_state = 'failed' OR (incident_state = 'pending' AND incident_error IS NOT NULL)",
              ),
            }
          : { on: false, failing: 0 },
        setup: { canaryUrl: base.replace(/\/$/, ""), dnsZone: zone ?? null },
      };
    },

    gauges() {
      const rows = db.prepare("SELECT kind, enabled, COUNT(*) AS n FROM canaries GROUP BY kind, enabled").all() as Row[];
      return {
        canaries: rows.filter((r) => r.enabled === 1).map((r) => ({ kind: r.kind as string, n: Number(r.n) })),
        triggersTotal: (db.prepare("SELECT COUNT(*) AS n FROM triggers WHERE status != 'test'").get() as { n: number }).n,
        triggersOpen: (db.prepare("SELECT COUNT(*) AS n FROM triggers WHERE status = 'open'").get() as { n: number }).n,
      };
    },

    /** Triggers older than the retention are deleted with their hits; canaries stay until someone deletes them. */
    purge(): number {
      return Number(db.prepare("DELETE FROM triggers WHERE last_at < ?").run(iso(clock() - retentionDays * DAY_MS)).changes);
    },
  };
}

export type Deception = ReturnType<typeof createDeception>;
