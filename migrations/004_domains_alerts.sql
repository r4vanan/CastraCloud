-- Domain Manager (subdomains) and alert channels.

CREATE TABLE IF NOT EXISTS subdomains (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain_id  UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    source     TEXT NOT NULL DEFAULT 'crt.sh',   -- crt.sh | dns | manual
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (domain_id, name)
);

CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains (domain_id);

-- Unique constraint so compliance controls can be upserted.
CREATE UNIQUE INDEX IF NOT EXISTS idx_controls_framework ON compliance_controls (framework_id, control_id);

-- Alert/notification channels (Slack, Teams, email, webhook, SIEM/syslog).
CREATE TABLE IF NOT EXISTS alert_channels (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL,               -- slack | teams | email | webhook | syslog
    config     JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
