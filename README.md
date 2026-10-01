# CastraCloud

A cloud security platform combining **CSPM** (Cloud Security Posture Management, Wiz-style), built as a Go monorepo with a Next.js console.

## Documentation

- [Installation](docs/installation.md) — prerequisites, Docker & local setup, cloud credentials
- [How it works](docs/architecture.md) — architecture, scanning pipeline, RBAC, AI, scheduling
- [Administration](docs/administration.md) — users, connectors, scans, alerts, MFA, exports
- [Configuration](docs/configuration.md) — environment variables and the role/permission matrix

## Components

| Component | Path | Purpose |
|-----------|------|---------|
| CSPM Collector | `cmd/cspm` | Discovers cloud assets and evaluates misconfiguration rules via the connector SDK |
| Connector SDK | `internal/connector` | Pluggable interface for cloud providers; `aws`, `gcp`, and `azure` connectors register themselves |
| Control Plane API | `cmd/api` | REST API for auth, findings, and cloud integrations (Postgres-backed, multi-tenant, RBAC) |
| Auth / RBAC | `internal/auth` | bcrypt password hashing, JWT issuance, role-based permissions (`owner`/`admin`/`analyst`/`viewer`) |
| AI Assistant | `internal/ai` | BYOK LLM client (OpenAI-compatible + Anthropic) powering a security chat, threat analysis, and summaries |
| Console | `web/` | Next.js dashboard for findings and cloud integrations |

## Architecture

```
   CSPM Collector (Go) ──► API (Go) ◄── Console (Next.js)
              │                │
        Connector SDK      PostgreSQL
        (AWS, GCP, Azure)
```

- **Go** for the API and collectors (single binary, high concurrency).
- **PostgreSQL** as system-of-record (tenants, users, assets, findings, and compliance).
- **Next.js/TypeScript** for the operator console.
- **Connector SDK** lets new cloud providers be added without touching core code.

## Quick start

```bash
# 1. Configure secrets
cp .env.example .env
# Set JWT_SECRET and CREDENTIAL_ENCRYPTION_KEY (openssl rand -base64 32).

# 2. Start everything (Postgres, API, collector, console)
docker compose up -d --build

# 3. Register the first user (auto-promoted to owner of the tenant)
curl -X POST localhost:8080/v1/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"admin@castra.io","password":"changeme","full_name":"Admin","tenant":"acme"}'

# 4. Log in to get a JWT
TOKEN=$(curl -s -X POST localhost:8080/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"admin@castra.io","password":"changeme"}' | jq -r .access_token)

# 5. Run a CSPM scan (requires AWS credentials)
docker compose --profile scan run --rm cspm
```

To run outside Docker, start Postgres (`docker compose up -d postgres`), then:

```bash
psql -d postgres -c "CREATE ROLE castracloud LOGIN PASSWORD 'castracloud' CREATEDB;"
psql -d postgres -c "CREATE DATABASE castracloud OWNER castracloud;"
go run ./cmd/api    # :8080 (applies migrations on startup)
AWS_REGION=us-east-1 go run ./cmd/cspm
cd web && npm install && npm run dev   # :3000
```

## API examples

```bash
curl localhost:8080/healthz

# Auth (JWT-secured when JWT_SECRET is set; passwords must be 12+ chars with upper/lower/digit)
curl -X POST localhost:8080/v1/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"a@b.c","password":"CorrectHorse9!","tenant":"acme"}'
curl -X POST localhost:8080/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"a@b.c","password":"CorrectHorse9!"}'
curl localhost:8080/v1/auth/me -H "Authorization: Bearer $TOKEN"

# Password reset
curl -X POST localhost:8080/v1/auth/password/reset -H 'Content-Type: application/json' \
  -d '{"email":"a@b.c"}'    # -> reset_token
curl -X POST localhost:8080/v1/auth/password/reset/confirm -H 'Content-Type: application/json' \
  -d '{"token":"...","password":"NewPassword9!"}'

# Users (owner only)
curl localhost:8080/v1/users -H "Authorization: Bearer $TOKEN"
curl -X POST localhost:8080/v1/users -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"email":"analyst@b.c","role":"analyst"}'

# Findings
curl localhost:8080/v1/findings?severity=critical -H "Authorization: Bearer $TOKEN"
curl -X POST localhost:8080/v1/findings/ingest -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"provider":"aws","findings":[{"rule_id":"X","title":"y","severity":"high"}]}'

# Attack path analysis
curl localhost:8080/v1/attack-path -H "Authorization: Bearer $TOKEN"

# Vulnerability scanning
curl -X POST localhost:8080/v1/vulns/scan -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"resource_type":"container","resource_id":"web-1","packages":[{"name":"log4j-core","version":"2.14.1"}]}'

# Alert channels
curl -X POST localhost:8080/v1/alerts -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"sec-ops","type":"syslog","config":{"host":"10.0.0.5","port":514}}'

# SSO (when OIDC_ISSUER is configured)
curl -i localhost:8080/v1/auth/oidc/start   # 302 -> IdP

# MFA (two-factor authentication)
curl localhost:8080/v1/auth/mfa/status -H "Authorization: Bearer $TOKEN"
curl -X POST localhost:8080/v1/auth/mfa/enroll -H "Authorization: Bearer $TOKEN" \
  # -> {"secret":"...","otpauth_uri":"otpauth://..."} scan with authenticator app
curl -X POST localhost:8080/v1/auth/mfa/verify -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"code":"123456"}'   # -> recovery codes
curl -X POST localhost:8080/v1/auth/mfa/disable -H "Authorization: Bearer $TOKEN"

# When MFA is enabled, login returns an mfa_required challenge; complete it with:
curl -X POST localhost:8080/v1/auth/mfa/verify-login -H 'Content-Type: application/json' \
  -d '{"mfa_token":"...","code":"123456"}'

# AI assistant (bring your own key; OpenAI, Groq, DeepSeek, Anthropic, OpenRouter, Ollama…)
curl -X POST localhost:8080/v1/ai/analyze -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"description":"S3 bucket with production data is publicly readable"}'
curl -X POST localhost:8080/v1/ai/chat -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"triage my findings"}]}'

# Export
curl -OJ localhost:8080/v1/export/findings.csv -H "Authorization: Bearer $TOKEN"
curl -OJ localhost:8080/v1/export/report.pdf -H "Authorization: Bearer $TOKEN"
```

The CSPM collector reports to the API via `CSPM_API_URL` and `CSPM_API_TOKEN` (a JWT for a user with `findings:write`).

## Testing

```bash
make test     # go test ./...
make vet      # go vet ./...
make build    # builds api and cspm into bin/
```

## Configuration

All services are configured via environment variables. See `.env.example` for the full list.

## Roadmap

- [x] Attack path analysis (graph model of assets → exposure)
- [x] Vulnerability scanning (curated CVE database for workload packages)
- [x] Compliance frameworks (CIS AWS, NIST CSF, ISO 27001) mapping with controls
- [x] GCP + Azure connectors (connector SDK is ready)
- [x] Alerting / SIEM forwarding (Slack, Teams, webhook, email, Wazuh-compatible syslog/JSON)
- [x] SSO / OIDC (authorization code + PKCE; per-tenant role assignment via `user_tenants` is in place)
- [x] Two-factor authentication (TOTP enrollment, recovery codes, MFA login challenge)
- [x] Password reset (single-use tokens)
- [x] User management (owner-managed roles, activation, deactivation)
- [x] Continuous / scheduled scanning (`SCAN_INTERVAL`)
- [x] Findings de-duplication on re-scan
- [x] PDF report + CSV export
