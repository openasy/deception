# deception

[![CI](https://github.com/openasy/deception/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/deception/actions/workflows/ci.yml)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) Deception product: **tripwires that only an attacker would touch, so an alert
means a breach** (ADR 0057). A canary is a fake kubeconfig, a `.env` file, an SSH config or an AWS key that nobody has
a reason to use. When one is used, deception keeps a trigger with where it came from, and opens an incident in
Incidents.

```
kubeconfig, .env, passwords.html, link ──GET /c/<token>──────────▶
ssh config, host name ──────────────────DNS lookup of <token>.zone──▶  deception  ──▶  a trigger, and an incident
AWS credentials file ───CloudTrail ──POST /api/v1/cloudtrail───────▶
```

## Canaries

Each canary has its own token, so a trigger names the one copy that was used. Make one from a template, then plant its
bait:

| Template | Kind | The bait |
| --- | --- | --- |
| `link` | URL | The canary URL, to paste in a wiki page, a ticket or a bookmark |
| `kubeconfig` | URL | A kubeconfig whose cluster is the canary URL: any `kubectl` with it calls it |
| `env` | URL | A `.env` with an admin API address and key |
| `html` | URL | `passwords.html` with an invisible image: opening it in a browser calls the URL |
| `hostname` | DNS | `<token>.<zone>`, for a config where a host name belongs |
| `ssh-config` | DNS | An SSH config whose bastion is the canary: `ssh bastion` looks it up |
| `aws-credentials` | AWS key | `~/.aws/credentials` with the key of an IAM user that may do nothing |

Random values in a bait (a token, a key) are new each time and lead nowhere.

- **URL canaries** call `/c/<token>`, with anything after it. Every path answers the same transparent GIF, known token
  or not, so nothing tells the caller it found a canary, and canary URLs are not written to the request log. Set
  `DECEPTION_CANARY_URL` to another name on the same proxy, such as `https://cdn.example.com`, to keep the word
  "deception" out of every bait. `DECEPTION_CANARY_PORT` serves canary URLs alone on a port of their own.
- **DNS canaries** need a zone delegated to deception: set `DECEPTION_DNS_ZONE`, publish UDP 53 to the container's
  5353, and add an `NS` record for the zone in its parent. deception answers names in the zone and refuses the rest, so
  it is not an open resolver. A lookup reaches it through resolvers: the source of a DNS trigger is the last resolver,
  not the person.
- **AWS key canaries** are a key of an IAM user with a deny-all policy. deception holds no AWS credentials; it finds
  the key's use in CloudTrail events a pipeline sends. The secret is kept sealed with `openasy-kek`.

```bash
aws iam create-user --user-name backup-svc
aws iam put-user-policy --user-name backup-svc --policy-name deny-all \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
aws iam create-access-key --user-name backup-svc   # make the canary with this key

# every 5 minutes, from cron or a scheduled job
aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA... \
  --start-time "$(date -u -d '-15 min' +%FT%TZ)" \
  | curl -sf -X POST -H "Authorization: Bearer $DECEPTION_INGEST_TOKEN" -H 'content-type: application/json' \
    --data-binary @- https://deception.example.com/api/v1/cloudtrail
```

`/api/v1/cloudtrail` also takes a CloudTrail log file from S3 (`{ "Records": [...] }`) and EventBridge events, gzipped
or not. An event sent again is kept once, by its `eventID`.

## Triggers

A trigger is the use of a canary from one address. Uses from the same address within 15 minutes are hits of the same
trigger, with the first 100 kept for its timeline. There is no threshold: every trigger is worth a look.

A person says what it was: **a breach**, or **a test**, which needs a reason such as who ran it. With
`DECEPTION_INCIDENTS_TOKEN`, an API token of Incidents with the editor role, each trigger opens a critical incident
(`DECEPTION_INCIDENTS_SEVERITY` to change it) with a link back, and a test is noted on it. When Incidents cannot be
reached, deception tries again for a day.

## Run

```bash
openssl rand -hex 32 > openasy-kek
docker compose up -d
docker compose logs deception | grep 'no owner yet'
```

Open the link from the log once to create the owner account; there is no default password (ADR 0013). The UI and API
are on http://localhost:8080, the API reference at http://localhost:8080/api/docs/.

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port: UI, API and canary URLs |
| `DECEPTION_PUBLIC_URL` | `http://localhost:8080` | The address people open, with `https://` behind your TLS proxy |
| `DECEPTION_CANARY_URL` | the public URL | Where URL canaries call; another name keeps the product's name out of the bait |
| `DECEPTION_CANARY_PORT` | | Serve canary URLs, and nothing else, on this port too |
| `DECEPTION_PROXY_HOPS` | `0` | Proxies in front that add `X-Forwarded-For`; only that many entries are trusted |
| `DECEPTION_DNS_ZONE` | | The zone delegated to deception; DNS canaries need it |
| `DECEPTION_DNS_PORT` | `5353` | UDP port of the zone's name server |
| `DECEPTION_DNS_ANSWER` | | An IPv4 address to answer lookups with; without it, names have no address |
| `DECEPTION_INGEST_TOKEN` | | Lets a pipeline send CloudTrail events and nothing else. An API token with the editor role works too |
| `DECEPTION_INCIDENTS_URL` | `incidents` in `OPENASY_PRODUCTS` | Where deception calls Incidents |
| `DECEPTION_INCIDENTS_TOKEN` | | An Incidents API token with the editor role; each trigger opens an incident |
| `DECEPTION_INCIDENTS_SEVERITY` | `critical` | The severity of those incidents |
| `OPENASY_PRODUCTS` | | The install's other OpenAsy products, for the product switcher |
| `DECEPTION_SECRETS_KEY_FILE` | `/run/secrets/openasy-kek` | 32-byte key-encryption key |
| `DECEPTION_DB` | `/data/deception.db` | SQLite file (WAL), on the `/data` volume |
| `DECEPTION_RETENTION_DAYS` | `365` | Triggers older than this are deleted; canaries stay |
| `DECEPTION_METRICS_PORT` | | Serve `/metrics` on this port only (ADR 0026) |
| `DECEPTION_HEADLESS` | `false` | `true` serves only the API and canary URLs |
| `DECEPTION_PASSWORD_SIGN_IN`, `OPENASY_OIDC_*` | | Sign-in, as in every OpenAsy product ([@openasy/auth](https://github.com/openasy/auth)) |

`/metrics` has `openasy_deception_canaries{kind}`, `openasy_deception_triggers` and
`openasy_deception_triggers_open`: alert on the last one above 0 in your own Prometheus.

The container runs as non-root with a read-only root filesystem, no capabilities and `no-new-privileges`.

## Roles

Viewers see everything but the bait; editors also make canaries, see their bait and decide on triggers; admins also
delete canaries, and manage members and API tokens (ADR 0003).

## Not yet

Decoy hosts that answer like real services, decoy database users and Windows accounts, and documents that call home
when opened outside a browser are planned. A canary tells you someone is inside, not how they got in, and it only works
where an attacker would find it.

## Develop

```bash
npm install
npm test        # tokens, baits, DNS, CloudTrail, triggers, Incidents, and every API response against openapi.json
npm run dev     # the UI, with the API on :8080
```

## Licence

AGPL-3.0 (ADR 0008).
