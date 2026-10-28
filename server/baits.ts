// The bait for each template: the file or text a person plants. Each canary has its own token, so a trigger names the
// one copy that was read. The extra values in a bait (a token, a key) are random and lead nowhere.
import { randomBytes } from "node:crypto";

export const KINDS = ["url", "dns", "aws-key"] as const;
export type Kind = (typeof KINDS)[number];

export const TEMPLATES = {
  link: { kind: "url", file: "" },
  kubeconfig: { kind: "url", file: "config" },
  env: { kind: "url", file: ".env" },
  html: { kind: "url", file: "passwords.html" },
  hostname: { kind: "dns", file: "" },
  "ssh-config": { kind: "dns", file: "config" },
  "aws-credentials": { kind: "aws-key", file: "credentials" },
} as const satisfies Record<string, { kind: Kind; file: string }>;
export type Template = keyof typeof TEMPLATES;

export const isTemplate = (t: unknown): t is Template => typeof t === "string" && Object.hasOwn(TEMPLATES, t);

export interface BaitInput {
  template: Template;
  token: string;
  /** For aws-key canaries. */
  secret?: string;
  /** Where URL canaries call, such as https://cdn.example.com. */
  canaryUrl: string;
  /** The zone DNS canaries are names in, such as canary.example.com; undefined when DNS is not set up. */
  dnsZone?: string;
}

export interface Bait {
  /** A file name to save it as, or empty when it is a value to paste. */
  file: string;
  content: string;
}

/** Random filler that looks like a credential: lowercase hex, or base64url when asked. */
const filler = (bytes: number, base64 = false) => randomBytes(bytes).toString(base64 ? "base64url" : "hex");

export const canaryUrl = (base: string, token: string) => `${base.replace(/\/$/, "")}/c/${token}`;
export const canaryName = (zone: string, token: string) => `${token}.${zone}`;

export function bait({ template, token, secret, canaryUrl: base, dnsZone }: BaitInput): Bait {
  const file = TEMPLATES[template].file;
  const url = canaryUrl(base, token);
  const name = dnsZone ? canaryName(dnsZone, token) : "";
  switch (template) {
    case "link":
      return { file, content: url };
    case "kubeconfig":
      return {
        file,
        content: `apiVersion: v1
kind: Config
clusters:
  - name: prod
    cluster:
      server: ${url}
contexts:
  - name: prod-admin
    context:
      cluster: prod
      user: admin
current-context: prod-admin
users:
  - name: admin
    user:
      token: ${filler(32, true)}
`,
      };
    case "env":
      return {
        file,
        content: `# Internal admin API, used by the nightly export
ADMIN_API_URL=${url}
ADMIN_API_KEY=${filler(24)}
`,
      };
    case "html":
      return {
        file,
        content: `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Server passwords</title>
  </head>
  <body>
    <h1>Server passwords</h1>
    <p>Moved to the vault. The old list is below until everyone has access.</p>
    <img src="${url}" alt="" width="1" height="1" />
  </body>
</html>
`,
      };
    case "hostname":
      return { file, content: name };
    case "ssh-config":
      return {
        file,
        content: `Host bastion
  HostName ${name}
  User root
  IdentityFile ~/.ssh/id_bastion
`,
      };
    case "aws-credentials":
      return {
        file,
        content: `[default]
aws_access_key_id = ${token}
aws_secret_access_key = ${secret ?? ""}
region = us-east-1
`,
      };
  }
}
