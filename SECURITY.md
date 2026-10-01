# Security Policy

## Reporting a vulnerability

Please do **not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities privately to the maintainers. Include:

- A description of the issue and its impact
- Steps to reproduce (or a proof of concept)
- Affected versions / components

We will acknowledge receipt, confirm the issue, and coordinate a fix and disclosure.

## Security notes

- `JWT_SECRET` and `CREDENTIAL_ENCRYPTION_KEY` are required at runtime and must never be committed. Use `openssl rand -base64 32` to generate them and store them in a secret manager in production.
- Cloud-connector credentials and TOTP secrets are encrypted at rest with `CREDENTIAL_ENCRYPTION_KEY` (AES-256-GCM).
- The BYOK AI assistant stores provider API keys in the browser's `localStorage` only; they are never persisted server-side.
