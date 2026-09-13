-- RBAC, cloud connectors, scan jobs, compliance mapping, risk scoring.

-- User profile + account state (role lives in users.role for the primary tenant).
ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- MSSP multi-tenancy: a user may belong to many tenants with a per-tenant role.
-- users.tenant_id remains the user's primary tenant; this table is the source of
-- truth for cross-tenant membership and role assignment.
CREATE TABLE IF NOT EXISTS user_tenants (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'viewer',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, tenant_id)
);

-- Cloud connectors. Credentials are read-only IAM roles / service accounts and
-- are encrypted at rest (AES-256-GCM via CREDENTIAL_ENCRYPTION_KEY).
CREATE TABLE IF NOT EXISTS cloud_accounts (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider             TEXT NOT NULL,              -- aws | gcp | azure | oci | m365 | google_workspace
    name                 TEXT NOT NULL,
    account_id           TEXT NOT NULL DEFAULT '',   -- provider account / subscription id
    region               TEXT NOT NULL DEFAULT '',
    credentials_encrypted BYTEA NOT NULL,
    status               TEXT NOT NULL DEFAULT 'pending', -- pending | active | error
    last_sync_at         TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, provider, name)
);

-- Async scan jobs, processed by a worker queue (Redis/RabbitMQ).
CREATE TABLE IF NOT EXISTS scan_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    cloud_account_id UUID REFERENCES cloud_accounts(id) ON DELETE SET NULL,
    provider        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'queued', -- queued | running | completed | failed
    error           TEXT NOT NULL DEFAULT '',
    summary         JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_tenant ON scan_jobs (tenant_id, status);

-- Compliance frameworks (CIS, NIST CSF, ISO 27001, SOC2, PCI).
CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    version    TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name, version)
);

CREATE TABLE IF NOT EXISTS compliance_controls (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id UUID NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    control_id   TEXT NOT NULL,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT ''
);

-- Map detection rules to compliance controls (many-to-many). rule_id references
-- the rule identifiers emitted by connectors (e.g. CASTRA-S3-001).
CREATE TABLE IF NOT EXISTS rule_controls (
    rule_id    TEXT NOT NULL,
    control_id UUID NOT NULL REFERENCES compliance_controls(id) ON DELETE CASCADE,
    PRIMARY KEY (rule_id, control_id)
);

-- Risk scoring per asset and per finding (0-100, higher = riskier).
ALTER TABLE assets   ADD COLUMN IF NOT EXISTS risk_score INT NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_score INT NOT NULL DEFAULT 0;

-- Certificate expiry tracking for the Domain Manager.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS cert_expires_at TIMESTAMPTZ;
