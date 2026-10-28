// The UI is an ordinary client of the public API (ADR 0014, 0018). Types follow openapi.json.

export type Kind = "url" | "dns" | "aws-key";
export type Template = "link" | "kubeconfig" | "env" | "html" | "hostname" | "ssh-config" | "aws-credentials";
export type CanaryState = "armed" | "triggered" | "disabled";
export type TriggerStatus = "open" | "confirmed" | "test";
export type Channel = "http" | "dns" | "aws";

/** The templates and the kind of canary each makes, in the order the form offers them. */
export const TEMPLATES: Array<{ id: Template; kind: Kind }> = [
  { id: "link", kind: "url" },
  { id: "kubeconfig", kind: "url" },
  { id: "env", kind: "url" },
  { id: "html", kind: "url" },
  { id: "hostname", kind: "dns" },
  { id: "ssh-config", kind: "dns" },
  { id: "aws-credentials", kind: "aws-key" },
];

/** Another OpenAsy product of this install, from OPENASY_PRODUCTS. */
export interface ProductLink {
  id: string;
  url: string;
}

export interface Canary {
  id: string;
  name: string;
  kind: Kind;
  template: Template;
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

export interface Bait {
  file: string;
  content: string;
}

export interface Trigger {
  id: string;
  canary: { id: string; name: string; kind: Kind; location: string; host: string } | null;
  channel: Channel;
  source: string;
  userAgent: string;
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

export interface TriggerDetail extends Trigger {
  timeline: Array<{ at: string; detail: string }>;
}

export interface Summary {
  canaries: { total: number; armed: number; triggered: number; disabled: number; byKind: Record<Kind, number> };
  triggers: {
    last30Days: number;
    open: number;
    confirmed: number;
    tests: number;
    lastAt: string | null;
    perDay: Array<{ date: string; triggers: number }>;
  };
  latest: Trigger[];
  incidents: { on: boolean; failing: number };
  setup: { canaryUrl: string; dnsZone: string | null };
}

export class Unauthorized extends Error {}
/** The signed-in owner or admin has no second factor yet; the sign-in gate asks for one. */
export class MfaSetupRequired extends Error {}
export class ApiError extends Error {}

// The session is an HttpOnly cookie set by sign-in (@openasy/auth); the browser sends it, nothing is stored here.
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...init.headers },
  });
  if (!res.ok) {
    const problem = (await res.json().catch(() => ({}))) as { code?: string; detail?: string };
    if (res.status === 401) throw new Unauthorized(problem.detail);
    if (problem.code === "mfa-setup-required") throw new MfaSetupRequired(problem.detail);
    throw new ApiError(problem.detail ?? `${path}: ${res.status}`);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}
