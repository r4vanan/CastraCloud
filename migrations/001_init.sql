-- CastraCloud initial schema.

CREATE TABLE IF NOT EXISTS tenants (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email       TEXT NOT NULL UNIQUE,
    role        TEXT NOT NULL DEFAULT 'viewer',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS assets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider    TEXT NOT NULL,
    asset_type  TEXT NOT NULL,
    external_id TEXT NOT NULL,
    region      TEXT NOT NULL DEFAULT '',
    name        TEXT NOT NULL DEFAULT '',
    properties  JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, provider, asset_type, external_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id    UUID REFERENCES assets(id) ON DELETE SET NULL,
    source      TEXT NOT NULL DEFAULT 'cspm',
    rule_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'medium',
    status      TEXT NOT NULL DEFAULT 'open',
    description TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_findings_tenant ON findings (tenant_id, status, severity);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings (rule_id);

CREATE TABLE IF NOT EXISTS domains (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL UNIQUE,
    provider    TEXT NOT NULL DEFAULT 'route53',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dns_records (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id   UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,
    name        TEXT NOT NULL,
    value       TEXT NOT NULL,
    ttl         INT NOT NULL DEFAULT 300,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID REFERENCES tenants(id) ON DELETE SET NULL,
    actor       TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    resource    TEXT NOT NULL DEFAULT '',
    metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
