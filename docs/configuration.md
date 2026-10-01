# Configuration

All services are configured via environment variables. Copy `.env.example` to `.env` and adjust.

## Environment variables

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `API_PORT` | `8080` | API listen port |
| `JWT_SECRET` | — (required) | Signs auth tokens. `openssl rand -base64 32` |
| `JWT_TTL` | `1h` | Access-token lifetime |
| `MIGRATIONS_DIR` | `migrations` | Path to SQL migrations |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |

### Secrets at rest

| Variable | Default | Description |
|----------|---------|-------------|
| `CREDENTIAL_ENCRYPTION_KEY` | — (required) | AES-256-GCM key (base64) for connector credentials & MFA secrets |

### Database

| Variable | Default |
|----------|---------|
| `DB_USER` | `castracloud` |
| `DB_PASS` | `castracloud` |
| `DB_HOST` | `localhost` |
| `DB_PORT` | `5432` |
| `DB_NAME` | `castracloud` |
| `DB_SSLMODE` | `disable` |

### CSPM / scanning

| Variable | Default | Description |
|----------|---------|-------------|
| `CSPM_PROVIDER` | `aws` | `aws` / `gcp` / `azure` (for the CLI collector) |
| `AWS_REGION` | `us-east-1` | Scan region |
| `SCAN_INTERVAL` | `24h` | Background re-scan interval |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` | — | AWS CLI-collector credentials |
| `GCP_PROJECT` | — | GCP project (falls back to ADC) |
| `GOOGLE_APPLICATION_CREDENTIALS` | — | GCP service-account key file |
| `AZURE_SUBSCRIPTION_ID` / `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` | — | Azure CLI-collector credentials |
| `CSPM_TENANT_ID` | — | Target tenant for CLI ingest |
| `CSPM_API_URL` | `http://localhost:8080` | API for CLI ingest |
| `CSPM_API_TOKEN` | — | JWT with `findings:write` |

### SSO / OIDC (optional)

| Variable | Description |
|----------|-------------|
| `OIDC_ISSUER` | IdP issuer URL (enables SSO when set) |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | IdP client credentials |
| `OIDC_REDIRECT_URL` | Must point at the API callback (`…/v1/auth/oidc/callback`) |
| `OIDC_TENANT_SLUG` | `default` — tenant for auto-provisioned users |
| `OIDC_REDIRECT_AFTER` | `http://localhost:3000/` — post-login destination |

### Console

| Variable | Default | Description |
|----------|---------|-------------|
| `NEXT_PUBLIC_API_URL` | `http://localhost:8080` | API base URL (baked in at build time) |
| `NEXT_PUBLIC_OIDC_ENABLED` | `false` | Show the "Continue with SSO" button |

### AI assistant (server-side key, optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_API_KEY` | — | Server-side LLM key (enables assistant without per-user keys) |
| `AI_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible base URL |
| `AI_MODEL` | `gpt-4o-mini` | Model name |

The console also supports per-user **BYOK** keys (OpenAI, Groq, DeepSeek, Anthropic, OpenRouter, Mistral, Gemini, Ollama) configured in the browser.

## Roles & permissions

| Permission | owner | admin | analyst | viewer |
|------------|:-----:|:-----:|:-------:|:------:|
| `findings:read` | ✓ | ✓ | ✓ | ✓ |
| `findings:write` | ✓ | ✓ | ✓ | — |
| `assets:read` | ✓ | ✓ | ✓ | ✓ |
| `connectors:read` | ✓ | ✓ | — | — |
| `connectors:write` | ✓ | ✓ | — | — |
| `scans:run` | ✓ | ✓ | ✓ | — |
| `users:manage` | ✓ | — | — | — |
| `audit:read` | ✓ | ✓ | — | ✓ |
| `compliance:read` | ✓ | ✓ | ✓ | ✓ |
| `alerts:read` | ✓ | ✓ | ✓ | ✓ |
| `alerts:write` | ✓ | ✓ | — | — |
| `ai:use` | ✓ | ✓ | ✓ | — |
