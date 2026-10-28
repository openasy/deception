// Prometheus text exposition, written by hand: a few lines, no client library needed.
const requests = new Map<string, number>();

export function countRequest(method: string, route: string, status: number) {
  const key = `method="${method}",route="${route}",status="${status}"`;
  requests.set(key, (requests.get(key) ?? 0) + 1);
}

export interface Gauges {
  /** Enabled canaries by kind. */
  canaries: Array<{ kind: string; n: number }>;
  /** Triggers kept, leaving out those marked as a test. */
  triggersTotal: number;
  triggersOpen: number;
}

export function renderMetrics(version: string, g: Gauges): string {
  const lines = [
    "# HELP openasy_build_info Build information.",
    "# TYPE openasy_build_info gauge",
    `openasy_build_info{product="deception",version="${version}"} 1`,
    "# HELP openasy_http_requests_total HTTP requests handled.",
    "# TYPE openasy_http_requests_total counter",
    ...[...requests].map(([labels, n]) => `openasy_http_requests_total{${labels}} ${n}`),
    "# HELP openasy_deception_canaries Enabled canaries by kind.",
    "# TYPE openasy_deception_canaries gauge",
    ...g.canaries.map((c) => `openasy_deception_canaries{kind="${c.kind}"} ${c.n}`),
    "# HELP openasy_deception_triggers Triggers kept, leaving out those marked as a test.",
    "# TYPE openasy_deception_triggers gauge",
    `openasy_deception_triggers ${g.triggersTotal}`,
    "# HELP openasy_deception_triggers_open Triggers nobody has looked at. Above 0 means someone may be inside.",
    "# TYPE openasy_deception_triggers_open gauge",
    `openasy_deception_triggers_open ${g.triggersOpen}`,
    "# HELP process_uptime_seconds Seconds since the process started.",
    "# TYPE process_uptime_seconds gauge",
    `process_uptime_seconds ${process.uptime().toFixed(0)}`,
  ];
  return lines.join("\n") + "\n";
}
