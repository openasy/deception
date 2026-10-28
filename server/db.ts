import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Forward-only migrations (ADR 0010): append new entries, never edit or remove old ones.
const MIGRATIONS = [
  `-- A canary: something only an attacker would use. The token is what its bait carries: the last part of a URL, the
   -- label of a DNS name, or an AWS access key ID (ADR 0057).
   CREATE TABLE canaries (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL,
     kind TEXT NOT NULL CHECK (kind IN ('url', 'dns', 'aws-key')),
     template TEXT NOT NULL,
     token TEXT NOT NULL UNIQUE,
     -- The AWS secret access key, sealed with the secrets key, so the bait can be shown again.
     secret TEXT,
     location TEXT NOT NULL DEFAULT '',
     host TEXT NOT NULL DEFAULT '',
     note TEXT NOT NULL DEFAULT '',
     enabled INTEGER NOT NULL DEFAULT 1,
     created_at TEXT NOT NULL,
     created_by TEXT NOT NULL
   );
   -- One use of a canary from one source. Uses from the same source soon after are hits of the same trigger.
   CREATE TABLE triggers (
     id TEXT PRIMARY KEY,
     canary_id TEXT NOT NULL REFERENCES canaries (id) ON DELETE CASCADE,
     channel TEXT NOT NULL CHECK (channel IN ('http', 'dns', 'aws')),
     source TEXT NOT NULL,
     user_agent TEXT NOT NULL DEFAULT '',
     first_at TEXT NOT NULL,
     last_at TEXT NOT NULL,
     hits INTEGER NOT NULL DEFAULT 1,
     status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'confirmed', 'test')),
     reason TEXT,
     decided_by TEXT,
     decided_at TEXT,
     incident_state TEXT CHECK (incident_state IN ('pending', 'opened', 'failed')),
     incident_id TEXT,
     incident_key TEXT,
     incident_url TEXT,
     incident_error TEXT,
     incident_note TEXT CHECK (incident_note IN ('pending', 'sent'))
   );
   CREATE INDEX triggers_canary ON triggers (canary_id, source, last_at);
   CREATE INDEX triggers_first ON triggers (first_at);
   -- What each use was, for the trigger's timeline. ref is the event's own id where it has one, such as CloudTrail's
   -- eventID, so an event sent twice is kept once.
   CREATE TABLE hits (
     id INTEGER PRIMARY KEY,
     trigger_id TEXT NOT NULL REFERENCES triggers (id) ON DELETE CASCADE,
     at TEXT NOT NULL,
     detail TEXT NOT NULL,
     ref TEXT UNIQUE
   );
   CREATE INDEX hits_trigger ON hits (trigger_id, at)`,
];

/** Opens the product's single SQLite file in WAL mode (ADR 0011) and migrates it forward. */
export function openDb(path: string): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
  const row = db.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").get() as { v: number };
  for (let v = row.v; v < MIGRATIONS.length; v++) {
    db.exec("BEGIN");
    try {
      db.exec(MIGRATIONS[v]!);
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(v + 1, new Date().toISOString());
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }
  return db;
}
