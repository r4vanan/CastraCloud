# CastraCloud

A cloud security platform combining **CSPM** (Cloud Security Posture Management, Wiz-style), a **WAF** (Web Application Firewall), and a **Domain Manager**, built as a Go monorepo with a Next.js console.

## Components

| Component | Path | Purpose |
|-----------|------|---------|
| WAF Gateway | `cmd/waf` | Reverse proxy with a rule engine (SQLi/XSS/traversal/cmd-injection), Redis rate limiting, and dynamic IP blocklisting |
| CSPM Collector | `cmd/cspm` | Discovers cloud assets and evaluates misconfiguration rules via the connector SDK |
| Connector SDK | `internal/connector` | Pluggable interface for cloud providers; `aws`, `gcp`, and `azure` connectors register themselves |
| Control Plane API | `cmd/api` | REST API for auth, findings, WAF rules, and domains (Postgres-backed, multi-tenant, RBAC) |
| Auth / RBAC | `internal/auth` | bcrypt password hashing, JWT issuance, role-based permissions (`owner`/`admin`/`analyst`/`viewer`) |
| Console | `web/` | Next.js dashboard for findings, WAF rules, and domains |

## Architecture

```
Internet → WAF Gateway (Go) → reverse proxy → Origin
                  │
        Redis (rate limit / blocklist)
                  │
   CSPM Collector (Go) ──► API (Go) ◄── Console (Next.js)
              │                │
        Connector SDK      PostgreSQL
        (AWS, +GCP/Azure)
```

- **Go** for the edge and collectors (single binary, high concurrency).
- **PostgreSQL** as system-of-record (tenants, users, assets, findings, WAF rules, domains, compliance).
- **Redis** for hot counters (rate limiting, dynamic blocklist).
- **Next.js/TypeScript** for the operator console.
- **Connector SDK** lets new cloud providers be added without touching core code.

## Quick start

```bash
# 1. Configure secrets
cp .env.example .env
# Set JWT_SECRET and CREDENTIAL_ENCRYPTION_KEY (openssl rand -base64 32).

# 2. Start everything (Postgres, Redis, API, WAF, console)
docker compose up -d --build

# 3. Register the first user (auto-promoted to owner of the tenant)
curl -X POST localhost:8080/v1/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"changeme","full_name":"Admin","tenant":"acme"}'

# 4. Log in to get a JWT
TOKEN=$(curl -s -X POST localhost:8080/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"changeme"}' | jq -r .access_token)

# 5. Run a CSPM scan (requires AWS credentials)
docker compose --profile scan run --rm cspm
```

To run outside Docker, start Postgres + Redis (`docker compose up -d postgres redis`), then:

```bash
psql -d postgres -c "CREATE ROLE castracloud LOGIN PASSWORD 'castracloud' CREATEDB;"
psql -d postgres -c "CREATE DATABASE castracloud OWNER castracloud;"
go run ./cmd/api    # :8080 (applies migrations on startup)
go run ./cmd/waf    # :8000
AWS_REGION=us-east-1 go run ./cmd/cspm
cd web && npm install && npm run dev   # :3000
```

## API examples

```bash
curl localhost:8080/healthz

# Auth (JWT-secured when JWT_SECRET is set)
curl -X POST localhost:8080/v1/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"a@b.c","password":"pw","tenant":"acme"}'
curl -X POST localhost:8080/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"a@b.c","password":"pw"}'
curl localhost:8080/v1/auth/me -H "Authorization: Bearer $TOKEN"

# Findings
curl localhost:8080/v1/findings?severity=critical -H "Authorization: Bearer $TOKEN"
curl -X POST localhost:8080/v1/findings/ingest -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"provider":"aws","findings":[{"rule_id":"X","title":"y","severity":"high"}]}'

# Domains
curl -X POST localhost:8080/v1/domains -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"example.com","provider":"route53"}'
curl -X POST localhost:8080/v1/domains/$DOMAIN_ID/enumerate -H "Authorization: Bearer $TOKEN"
curl -X POST localhost:8080/v1/domains/$DOMAIN_ID/scan -H "Authorization: Bearer $TOKEN"

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
```

The CSPM collector reports to the API via `CSPM_API_URL` and `CSPM_API_TOKEN` (a JWT for a user with `findings:write`).

## Testing

```bash
make test     # go test ./...
make vet      # go vet ./...
make build    # builds api, waf, cspm into bin/
```

## Configuration

All services are configured via environment variables. See `.env.example` for the full list.

## Roadmap

- [x] Attack path analysis (graph model of assets → exposure)
- [x] Vulnerability scanning (curated CVE database for workload packages)
- [x] Compliance frameworks (CIS AWS, NIST CSF, ISO 27001) mapping with controls
- [x] GCP + Azure connectors (connector SDK is ready)
- [x] Alerting / SIEM forwarding (Slack, Teams, webhook, email, Wazuh-compatible syslog/JSON)
- [x] WAF TLS termination + OWASP ModSecurity CRS import
- [x] SSO / OIDC (authorization code + PKCE; per-tenant role assignment via `user_tenants` is in place)
