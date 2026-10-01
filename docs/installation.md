# Installation

This guide covers installing and running CastraCloud locally and in production.

## Requirements

| Dependency | Version | Notes |
|------------|---------|-------|
| Go | 1.27+ | Builds the API and CSPM collector |
| Node.js | 20+ | Builds the Next.js console |
| PostgreSQL | 13+ | System-of-record (multi-tenant data) |
| Docker + Compose | recent | Optional — recommended for the simplest setup |

## Option A — Docker Compose (recommended)

```bash
# 1. Clone
git clone https://github.com/<you>/CastraCloud.git
cd CastraCloud

# 2. Configure secrets
cp .env.example .env
```

Edit `.env` and set two required secrets (generate with `openssl rand -base64 32`):

```bash
openssl rand -base64 32   # -> JWT_SECRET
openssl rand -base64 32   # -> CREDENTIAL_ENCRYPTION_KEY
```

```dotenv
JWT_SECRET=<32-byte base64>
CREDENTIAL_ENCRYPTION_KEY=<32-byte base64>
```

```bash
# 3. Start everything (Postgres + API + console)
docker compose up -d --build
```

> The collector is a one-shot job. Run it manually:
> `docker compose --profile scan run --rm cspm`

### Register the first user

The first registered user becomes the **owner** of their tenant.

```bash
curl -X POST localhost:8080/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@castra.io","password":"<strong-password>","full_name":"Admin","tenant":"acme"}'
```

Then open the console at **http://localhost:3000** and sign in.

## Option B — Run locally (no Docker)

1. Install Go, Node.js, and PostgreSQL.

2. Create the database:

```bash
psql -d postgres -c "CREATE ROLE castracloud LOGIN PASSWORD 'castracloud' CREATEDB;"
psql -d postgres -c "CREATE DATABASE castracloud OWNER castracloud;"
```

3. Configure environment (same `.env` as above).

4. Run the API (applies migrations on startup):

```bash
export JWT_SECRET="$(openssl rand -base64 32)"
export CREDENTIAL_ENCRYPTION_KEY="$(openssl rand -base64 32)"
go run ./cmd/api            # :8080
```

5. Run the console:

```bash
cd web
npm install
npm run dev                 # :3000 (dev)
# or production:
npm run build && npm start
```

## Cloud credentials

To run real scans you need **read-only** credentials for each cloud you connect.

| Provider | Credential JSON (paste in the console) | Without credentials |
|----------|----------------------------------------|---------------------|
| AWS | `{"access_key_id":"…","secret_access_key":"…","session_token":"…"}` | falls back to the default credential chain (`~/.aws/credentials`, IAM role, env) |
| GCP | full service-account key JSON (with `project_id`) | Application Default Credentials (`GOOGLE_APPLICATION_CREDENTIALS`) |
| Azure | `{"subscription_id":"…","tenant_id":"…","client_id":"…","client_secret":"…"}` | `DefaultAzureCredential` (managed identity) + `AZURE_SUBSCRIPTION_ID` |

Credentials are encrypted at rest with `CREDENTIAL_ENCRYPTION_KEY` (AES-256-GCM).

### CLI collector (headless)

The `cmd/cspm` binary scans a single provider and reports findings to the API:

```bash
AWS_REGION=us-east-1 \
CSPM_API_URL=http://localhost:8080 \
CSPM_API_TOKEN=<jwt> \
go run ./cmd/cspm
```

`CSPM_API_TOKEN` must be a JWT for a user with `findings:write`.

## Verifying the install

```bash
curl localhost:8080/healthz
# {"status":"ok","service":"castracloud-api"}
```

## Production considerations

- Store `JWT_SECRET` and `CREDENTIAL_ENCRYPTION_KEY` in a secret manager (Vault, SOPS, cloud KMS), not a plain `.env`.
- Run the console with `npm run build && npm start` (not `next dev`).
- Put the API behind TLS (reverse proxy) and a load balancer.
- Enable OIDC SSO for enterprise sign-on (see [configuration](./configuration.md)).
- Back up PostgreSQL regularly (`pg_dump`).
