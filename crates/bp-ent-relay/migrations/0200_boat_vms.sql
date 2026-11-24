-- Backplane Enterprise Boat VM & Zero-Tailscale Relay schema (0200-0299).
-- Every table carries `tenant_id uuid NOT NULL`, ENABLE+FORCE ROW LEVEL SECURITY,
-- and policies bound to `bp_tenant()`. All tenant-to-tenant FKs are composite.

-- ---------------------------------------------------------------- boat_vms
CREATE TABLE boat_vms (
  id                uuid PRIMARY KEY,
  tenant_id         uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name              text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  assigned_user_id  uuid,
  region            text NOT NULL DEFAULT 'us-east-1',
  kicad_version     text NOT NULL DEFAULT '10.99.0-bp.13.5',
  state             text NOT NULL DEFAULT 'stopped'
                      CHECK (state IN ('provisioning', 'running', 'stopping', 'stopped', 'terminated')),
  last_active_at    timestamptz NOT NULL DEFAULT now(),
  started_at        timestamptz,
  stopped_at        timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, assigned_user_id)
    REFERENCES users (tenant_id, id) ON DELETE SET NULL (assigned_user_id)
);
CREATE INDEX boat_vms_tenant_user ON boat_vms (tenant_id, assigned_user_id);
ALTER TABLE boat_vms ENABLE ROW LEVEL SECURITY;
ALTER TABLE boat_vms FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON boat_vms
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON boat_vms TO bp_app;

-- ------------------------------------------------------- boat_device_certs
-- Short-lived (<= 24h) X.509 mTLS certificates issued by BoatCa.
CREATE TABLE boat_device_certs (
  serial_hex  text PRIMARY KEY CHECK (length(serial_hex) BETWEEN 8 AND 64),
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  vm_id       uuid NOT NULL,
  spiffe_uri  text NOT NULL CHECK (spiffe_uri LIKE 'spiffe://backplane.enterprise/tenant/%/vm/%'),
  issued_at   timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  revoked_at  timestamptz,
  CHECK (expires_at > issued_at),
  CHECK (expires_at <= issued_at + interval '24 hours'),
  FOREIGN KEY (tenant_id, vm_id)
    REFERENCES boat_vms (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX boat_device_certs_vm ON boat_device_certs (tenant_id, vm_id);
ALTER TABLE boat_device_certs ENABLE ROW LEVEL SECURITY;
ALTER TABLE boat_device_certs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON boat_device_certs
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON boat_device_certs TO bp_app;

-- --------------------------------------------------- boat_vm_usage_records
-- Compute-hour metering intervals emitted on VM stop/reap for Stripe billing.
CREATE TABLE boat_vm_usage_records (
  id                uuid PRIMARY KEY,
  tenant_id         uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  vm_id             uuid NOT NULL,
  started_at        timestamptz NOT NULL,
  stopped_at        timestamptz NOT NULL,
  duration_seconds  bigint NOT NULL CHECK (duration_seconds >= 0),
  idempotency_key   text NOT NULL,
  synced_to_stripe  boolean NOT NULL DEFAULT false,
  created_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, idempotency_key),
  CHECK (stopped_at >= started_at),
  FOREIGN KEY (tenant_id, vm_id)
    REFERENCES boat_vms (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX boat_vm_usage_tenant ON boat_vm_usage_records (tenant_id, created_at DESC);
ALTER TABLE boat_vm_usage_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE boat_vm_usage_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON boat_vm_usage_records
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON boat_vm_usage_records TO bp_app;

-- ----------------------------------------------------- boat_relay_sessions
CREATE TABLE boat_relay_sessions (
  id              uuid PRIMARY KEY,
  tenant_id       uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  vm_id           uuid NOT NULL,
  user_id         uuid NOT NULL,
  client_kind     text NOT NULL CHECK (client_kind IN ('desktop', 'web')),
  connected_at    timestamptz NOT NULL DEFAULT now(),
  disconnected_at timestamptz,
  FOREIGN KEY (tenant_id, vm_id)
    REFERENCES boat_vms (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, user_id)
    REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX boat_relay_sessions_vm ON boat_relay_sessions (tenant_id, vm_id);
ALTER TABLE boat_relay_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE boat_relay_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON boat_relay_sessions
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON boat_relay_sessions TO bp_app;

-- -------------------------------------------------- boat_enrollment_tokens
-- Single-use short-lived bootstrap tokens allowing a new Boat VM to exchange
-- a locally generated CSR for its initial <=24h mTLS device certificate.
CREATE TABLE boat_enrollment_tokens (
  token_hash  bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  vm_id       uuid NOT NULL,
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, vm_id)
    REFERENCES boat_vms (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX boat_enrollment_tokens_vm ON boat_enrollment_tokens (tenant_id, vm_id);
ALTER TABLE boat_enrollment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE boat_enrollment_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON boat_enrollment_tokens
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON boat_enrollment_tokens TO bp_app;
