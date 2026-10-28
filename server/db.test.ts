import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { openDb } from "./db.ts";

describe("openDb", () => {
  it("uses WAL and migrates once", () => {
    const path = join(mkdtempSync(join(tmpdir(), "deception-")), "nested", "deception.db");
    const first = openDb(path);
    expect(first.prepare("PRAGMA journal_mode").get()).toEqual({ journal_mode: "wal" });
    first.close();

    const second = openDb(path);
    expect(second.prepare("SELECT COUNT(*) AS n FROM schema_migrations").get()).toEqual({ n: 1 });
    second.close();
  });

  it("keeps a token for one canary only, and its triggers go with it", () => {
    const db = openDb(":memory:");
    const insert = (id: string) =>
      db.prepare("INSERT INTO canaries (id, name, kind, template, token, created_at, created_by) VALUES (?, 'n', 'url', 'link', 'same', 'now', 'me')").run(id);
    insert("a");
    expect(() => insert("b")).toThrow(/UNIQUE/);
    db.prepare("INSERT INTO triggers (id, canary_id, channel, source, first_at, last_at) VALUES ('t', 'a', 'http', '192.0.2.1', 'now', 'now')").run();
    db.prepare("DELETE FROM canaries WHERE id = 'a'").run();
    expect(db.prepare("SELECT COUNT(*) AS n FROM triggers").get()).toEqual({ n: 0 });
  });
});
