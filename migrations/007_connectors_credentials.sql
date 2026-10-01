-- Reconcile cloud_connectors with the current credential-at-rest schema.
-- Earlier dev builds created the table with a plaintext `credentials` JSONB
-- column; the code now stores encrypted BYTEA credentials.

ALTER TABLE cloud_connectors ADD COLUMN IF NOT EXISTS credentials_encrypted BYTEA NOT NULL DEFAULT ''::bytea;
ALTER TABLE cloud_connectors DROP COLUMN IF EXISTS credentials;
