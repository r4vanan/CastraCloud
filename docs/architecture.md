# How it works

CastraCloud is a **CSPM** (Cloud Security Posture Management) platform: it discovers cloud assets, evaluates misconfiguration rules, and surfaces findings in a multi-tenant console.

## Architecture

```
                       ┌──────────────────────────────┐
                       │        Console (Next.js)      │
                       │   Dashboard, findings, AI,     │
                       │   settings, exports           │
                       └───────────────┬──────────────┘
                                       │ REST (JWT)
                       ┌───────────────▼──────────────┐
   CSPM Collector ────►│        Control Plane API      │◄─── OIDC IdP
   (cmd/cspm)          │   auth, RBAC, findings,       │
                       │   connectors, alerts, AI      │
                       └───────────────┬──────────────┘
                                       │
                       ┌───────────────▼──────────────┐
                       │          PostgreSQL          │
                       │  tenants, users, assets,      │
                       │  findings, alerts, audit      │
                       └──────────────────────────────┘
```

- **Go** — API and collectors (single binary, high concurrency).
- **PostgreSQL** — system of record (tenants, users, assets, findings, alerts, audit).
- **Next.js/TypeScript** — operator console.
- **Connector SDK** — pluggable cloud-provider adapters (`aws`, `gcp`, `azure`).

## Directory layout

```
cmd/
  api/            control-plane API server
  cspm/           standalone CSPM collector
internal/
  ai/             BYOK LLM client (OpenAI-compatible + Anthropic)
  api/            HTTP handlers, middleware, router
  attack/         attack-path graph analysis
  auth/           JWT, bcrypt, RBAC, MFA, OIDC
  compliance/     framework/control mapping
  connector/      connector SDK + aws/gcp/azure implementations
  crypto/         AES-256-GCM credential encryption
  cspm/           baseline rule registry
  logging/        structured slog logger
  notify/         alert/SIEM dispatch
  risk/           severity → risk-score mapping
  store/          PostgreSQL persistence layer
  vuln/           curated CVE database
migrations/       versioned SQL schema
web/              Next.js console
```

## Key concepts

### Multi-tenancy
Every row is scoped to a `tenant`. A user belongs to a primary tenant (`users.tenant_id`) and, optionally, many tenants via `user_tenants` (MSSP model). Every API call is scoped by the tenant resolved from the JWT.

### Authentication & authorization
- **Local auth** — bcrypt password hashing + JWT issuance. Passwords must be 12+ chars with upper/lower/digit.
- **MFA** — TOTP (authenticator app) with one-time recovery codes. Login returns an `mfa_required` challenge token when enabled.
- **SSO/OIDC** — authorization code + PKCE; auto-provisions users into a configured tenant.
- **Password reset** — single-use, 1-hour tokens.
- **RBAC** — four roles: `owner`, `admin`, `analyst`, `viewer`. See the [permission matrix](./configuration.md#roles-and-permissions).

### Scanning pipeline

1. A **connector** is created with read-only cloud credentials (encrypted at rest).
2. A scan is triggered on-demand ("Run Scan Now") or by the **scheduler** (`SCAN_INTERVAL`).
3. The connector discovers resources (S3 buckets, IAM users, security groups, GCS buckets, firewalls, NSGs, storage accounts…) and evaluates the **baseline rule set**.
4. Each violation becomes a `finding` with a severity (`critical`/`high`/`medium`/`low`/`info`) and a risk score (0–100).
5. Discovered resources are upserted as `assets`; findings are linked to their asset.
6. **De-duplication** prevents the same open finding from being created twice on re-scan.
7. New findings are dispatched to configured **alert channels** (Slack, Teams, webhook, email, Syslog/Wazuh).

### Posture score
The dashboard computes a 0–100 posture score from open findings:

```
score = 100 - (critical*10 + high*5 + medium*2 + low*1)
```

### Attack paths
`internal/attack` builds a graph of assets → exposure and computes shortest paths from the internet to risky assets, surfacing exploitable chains (e.g., public S3 → data exfiltration).

### Vulnerability scanning
`internal/vuln` maps workload packages (`name@version`) against a curated CVE database and emits findings with remediation guidance.

### Compliance
`internal/compliance` maps detection rules to controls in CIS AWS, NIST CSF, and ISO 27001 frameworks.

### AI assistant
A **bring-your-own-key** (BYOK) assistant with a chat interface and per-finding "AI Analyze":

- Supports OpenAI-compatible providers (OpenAI, **Groq**, **DeepSeek**, OpenRouter, Mistral, Google Gemini, Ollama) and **Anthropic's** native Messages API.
- Provider keys are stored only in the browser (`localStorage`) and sent per-request; the server never persists them.
- The chat receives the tenant's live open findings as context, so it can triage results directly.
- A server-side key (`AI_API_KEY`) can be set to enable the assistant without per-user keys.

### Scheduled scanning
The API runs a background loop that re-scans all connectors on an interval (`SCAN_INTERVAL`, default `24h`).

### Data flow summary

```
Cloud (AWS/GCP/Azure) ── connector SDK ──► rules ──► findings/assets ──► Postgres
                                                                          │
                                                          ┌───────────────┴───────────────┐
                                                          ▼                               ▼
                                                   Console (dashboard,            Alert channels
                                                   charts, tables)                 (Slack/Teams/…)
```

## Reporting & exports

- **CSV** — `GET /v1/export/findings.csv` streams every finding.
- **PDF** — `GET /v1/export/report.pdf` renders a formatted security posture report (summary, metric cards, severity distribution, findings table).
