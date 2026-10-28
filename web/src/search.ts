// What the search window (Cmd+K) finds in Deception: canaries by name, where they are planted or their host. The
// API filters them.
import type { SearchFn, SearchResult } from "@openasy/ui";
import { Bird } from "lucide-react";
import type { Canary } from "./api.ts";
import type { T } from "./i18n.ts";

type Call = <R>(path: string, init?: RequestInit) => Promise<R>;

export function search(call: Call, t: T): SearchFn {
  return async (q, signal) => {
    const found = await call<{ canaries: Canary[] }>(`/api/v1/canaries?q=${encodeURIComponent(q)}`, { signal });
    return found.canaries.slice(0, 8).map((c): SearchResult => ({
      id: `canary:${c.id}`,
      label: c.name,
      detail: [c.location, c.host].filter(Boolean).join(" · ") || t(`kinds.${c.kind}`),
      kind: t("search.canary"),
      icon: Bird,
      severity: c.state === "triggered" ? "critical" : undefined,
      href: `/canaries?open=${encodeURIComponent(c.id)}`,
    }));
  };
}
