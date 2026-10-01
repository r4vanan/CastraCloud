# Administration

This guide covers day-to-day operation of CastraCloud from the console.

## Signing in

Open the console (`http://localhost:3000`), enter your email and password. If MFA is enabled, you'll be prompted for a six-digit code. If SSO is configured, use the "Continue with SSO" link.

## Roles

| Role | Purpose |
|------|---------|
| **owner** | Full access including user management |
| **admin** | Full access except user management |
| **analyst** | Triage findings, run scans, use AI |
| **viewer** | Read-only (findings, assets, compliance, alerts) |

See the [permission matrix](./configuration.md#roles-and-permissions) for details.

## Managing users (owner)

Go to **Platform Settings → Users**.

- **Add user** — enter name, email, role, and optionally a password. If left blank, a temporary password is generated and shown once.
- **Change role** — use the role dropdown on a user row.
- **Deactivate / Activate** — soft-disable a user without deleting their history.
- **Remove** — deactivates the account.

You cannot modify your own account (prevents lock-out).

## Connecting cloud accounts

Go to **Cloud Integrations**, click the form:

1. **Account name** — e.g. `AWS Production`.
2. **Provider** — AWS, GCP, or Azure.
3. **Region** — e.g. `us-east-1`.
4. **Credential JSON** — paste read-only credentials (format below), or leave empty to use the default credential chain / workload identity.

```jsonc
// AWS
{"access_key_id":"…","secret_access_key":"…","session_token":"…"}
// GCP — full service-account key
{"type":"service_account","project_id":"…","client_email":"…","private_key":"…"}
// Azure
{"subscription_id":"…","tenant_id":"…","client_id":"…","client_secret":"…"}
```

Credentials are encrypted at rest with `CREDENTIAL_ENCRYPTION_KEY`.

## Running scans

- **Manual** — click **Run Scan Now** on a connector row.
- **Scheduled** — the API re-scans all connectors every `SCAN_INTERVAL` (default 24h).

Results appear under **Findings**, **Dashboard**, and **Attack Paths**.

> Findings are de-duplicated: re-scanning the same misconfiguration won't create duplicate open findings.

## Triaging findings

On the **Findings** page you can:

- Filter by severity and status.
- **Resolve** / **Suppress** / **Reopen** a finding.
- **AI Analyze** — get an AI explanation/remediation for a single finding (uses your BYOK key).

## Alerts & SIEM forwarding

Go to **Alerts** to add a channel. Supported types:

| Type | Config example |
|------|----------------|
| Slack | `{"url":"https://hooks.slack.com/services/…"}` |
| Teams | `{"url":"https://outlook.office.com/webhook/…"}` |
| Webhook | `{"url":"https://example.com/hook"}` |
| Email | `{"host":"smtp.example.com","port":587,"from":"a@b.c","to":["x@y.z"]}` |
| Syslog / Wazuh | `{"host":"10.0.0.5","port":514}` |

New findings are dispatched to all enabled channels.

## Security settings

### Two-factor authentication
**Platform Settings → Account Security**:

1. Click **Set up MFA**.
2. Scan the QR code / enter the secret in your authenticator app.
3. Enter the six-digit code to verify.
4. Save the recovery codes (each is single-use).

You can regenerate recovery codes or disable MFA at any time.

### Password reset
On the login page, click **Forgot password?** → enter your email → a reset token is shown (in production this would be emailed) → set a new password.

### SSO / OIDC
Set `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, and `OIDC_REDIRECT_URL` to enable enterprise sign-on. Users signing in via SSO are auto-provisioned into the configured tenant.

## AI assistant

**AI Security Assistant** in the sidebar:

1. Click **Configure AI**.
2. Pick a provider (OpenAI, Groq, DeepSeek, Anthropic, OpenRouter, Mistral, Gemini, Ollama).
3. Enter your API key, base URL, and model.
4. Chat, or use **AI Analyze** on individual findings.

Keys are stored in your browser only. Alternatively, set `AI_API_KEY` server-side to enable the assistant for all users.

## Exports

On the **Findings** page:

- **Export CSV** — download all findings as CSV.
- **Download PDF report** — download a formatted security posture report.

## Backups & recovery

Back up PostgreSQL:

```bash
pg_dump "postgres://castracloud:castracloud@localhost:5432/castracloud" > backup.sql
```

Restore:

```bash
psql "postgres://castracloud:castracloud@localhost:5432/castracloud" < backup.sql
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `healthz` not responding | API not running | `go run ./cmd/api` / `docker compose up -d api` |
| Login fails "Invalid email or password" | wrong password / inactive user | reset password, or re-activate the user |
| Scan fails with 500 | bad credentials / missing `CREDENTIAL_ENCRYPTION_KEY` | check credential JSON and `.env` |
| "no API key configured" in AI | no BYOK key / `AI_API_KEY` | configure the key in the AI settings |
| 401 on API | expired/invalid JWT | sign in again |
| Console shows old data | stale cache | hard-refresh / rebuild the web bundle |
