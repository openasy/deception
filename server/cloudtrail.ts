// Reads AWS CloudTrail events in the shapes they come in, and keeps what a trigger needs. AWS key canaries are found
// by their access key ID in these events (ADR 0057):
//   - a CloudTrail log file from S3: { "Records": [ ... ] }
//   - aws cloudtrail lookup-events: { "Events": [ { "CloudTrailEvent": "<the event as a JSON string>" } ] }
//   - an EventBridge event: { "detail": { ... } }, or an array of them
//   - one event, or an array of events

export interface TrailEvent {
  /** The event's own id, so an event sent twice is kept once. */
  id?: string;
  accessKeyId: string;
  at: string;
  source: string;
  userAgent: string;
  /** Such as "sts:GetCallerIdentity in us-east-1, AccessDenied". */
  detail: string;
}

const str = (v: unknown) => (typeof v === "string" ? v : undefined);

function event(raw: unknown): TrailEvent | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const e = raw as Record<string, unknown>;
  const identity = e.userIdentity as Record<string, unknown> | undefined;
  const accessKeyId = str(identity?.accessKeyId);
  const name = str(e.eventName);
  if (!accessKeyId || !name) return undefined;
  const service = (str(e.eventSource) ?? "").replace(/\.amazonaws\.com$/, "");
  const time = Date.parse(str(e.eventTime) ?? "");
  const error = str(e.errorCode);
  return {
    id: str(e.eventID),
    accessKeyId,
    at: Number.isFinite(time) ? new Date(time).toISOString() : new Date().toISOString(),
    source: str(e.sourceIPAddress) ?? "unknown",
    userAgent: (str(e.userAgent) ?? "").slice(0, 512),
    detail: `${service ? `${service}:` : ""}${name}${str(e.awsRegion) ? ` in ${str(e.awsRegion)}` : ""}${error ? `, ${error}` : ""}`.slice(0, 512),
  };
}

/** The events in a body, in any of the shapes above. Anything that is not an event with an access key is left out. */
export function parseTrail(body: unknown): TrailEvent[] {
  const items: unknown[] = [];
  const add = (v: unknown) => {
    if (Array.isArray(v)) for (const x of v) add(x);
    else if (v && typeof v === "object") {
      const o = v as Record<string, unknown>;
      if (Array.isArray(o.Records)) add(o.Records);
      else if (Array.isArray(o.Events)) add(o.Events);
      else if (typeof o.CloudTrailEvent === "string") {
        try {
          items.push(JSON.parse(o.CloudTrailEvent));
        } catch {
          // Not JSON: not an event.
        }
      } else if (o.detail && typeof o.detail === "object") items.push(o.detail);
      else items.push(o);
    }
  };
  add(body);
  return items.map(event).filter((e): e is TrailEvent => e !== undefined);
}
