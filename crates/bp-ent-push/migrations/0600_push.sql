-- Backplane Enterprise account-based mobile push registry (0600-0699).
-- Every table carries `tenant_id uuid NOT NULL`, ENABLE+FORCE ROW LEVEL SECURITY,
-- and policies bound to `bp_tenant()`. All tenant-to-tenant FKs are composite.
--
-- Device tokens are strictly bound to `(tenant_id, user_id)` and stored only
-- envelope-encrypted (`token_enc`) plus a SHA-256 lookup digest (`token_hash`).

CREATE TABLE push_devices (
  id           uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id      uuid NOT NULL,
  token_hash   bytea NOT NULL CHECK (octet_length(token_hash) = 32),
  token_enc    bytea NOT NULL,
  handle       text NOT NULL CHECK (length(handle) = 12),
  platform     text NOT NULL CHECK (platform IN ('ios', 'android')),
  bundle       text NOT NULL CHECK (length(bundle) BETWEEN 1 AND 255),
  env          text NOT NULL DEFAULT 'production' CHECK (env IN ('sandbox', 'production')),
  kind         text NOT NULL DEFAULT 'alert' CHECK (kind IN ('alert', 'activity', 'start')),
  device_name  text NOT NULL DEFAULT '' CHECK (length(device_name) <= 120),
  muted        boolean NOT NULL DEFAULT false,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, token_hash),
  FOREIGN KEY (tenant_id, user_id)
    REFERENCES users (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX push_devices_user ON push_devices (tenant_id, user_id);
ALTER TABLE push_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE push_devices FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON push_devices
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON push_devices TO bp_app;
