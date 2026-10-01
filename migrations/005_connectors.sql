-- CastraCloud Cloud Connectors schema.

CREATE TABLE IF NOT EXISTS cloud_connectors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    provider        TEXT NOT NULL, -- aws | gcp | azure
    region          TEXT NOT NULL DEFAULT 'us-east-1',
    credentials_encrypted BYTEA NOT NULL DEFAULT ''::bytea,
    status          TEXT NOT NULL DEFAULT 'connected',
    last_scanned_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_connectors_tenant ON cloud_connectors (tenant_id, provider);
