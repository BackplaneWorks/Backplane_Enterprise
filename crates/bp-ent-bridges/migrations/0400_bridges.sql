-- External Bridges & Comms (bp-ent-bridges).
-- Runs as the schema owner after 0001_core.sql. Every table carries
-- tenant_id NOT NULL, ENABLE + FORCE ROW LEVEL SECURITY with bp_tenant(),
-- composite (tenant_id, id) foreign keys, and DML-only grants to bp_app.

-- ------------------------------------------------------------------ bridges
CREATE TABLE bridges (
  id                     uuid PRIMARY KEY,
  tenant_id              uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name                   text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  kind                   text NOT NULL CHECK (kind IN ('webhook', 'slack', 'teams', 'discord', 'a2a')),
  enabled                boolean NOT NULL DEFAULT true,
  direction              text NOT NULL DEFAULT 'bidirectional' CHECK (direction IN ('inbound', 'outbound', 'bidirectional')),
  target_url             text CHECK (target_url IS NULL OR length(target_url) <= 2048),
  subscribed_events      text[] NOT NULL DEFAULT '{}',
  -- Envelope-encrypted secrets and adapter configuration (BPE1).
  inbound_secret_sealed  bytea NOT NULL,
  outbound_secret_sealed bytea,
  adapter_config_sealed  bytea NOT NULL,
  secret_hint            text NOT NULL DEFAULT '' CHECK (length(secret_hint) <= 32),
  rate_limit_rpm         integer NOT NULL DEFAULT 60 CHECK (rate_limit_rpm BETWEEN 1 AND 600),
  peer_enabled           boolean NOT NULL DEFAULT false,
  peer_scopes            text[] NOT NULL DEFAULT '{}' CHECK (peer_scopes <@ ARRAY['boards:read', 'boards:comment']::text[]),
  created_by             uuid NOT NULL,
  created_at             timestamptz NOT NULL DEFAULT now(),
  updated_at             timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, created_by) REFERENCES users (tenant_id, id)
);
CREATE INDEX bridges_by_tenant ON bridges (tenant_id, enabled, kind);
ALTER TABLE bridges ENABLE ROW LEVEL SECURITY;
ALTER TABLE bridges FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON bridges
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON bridges TO bp_app;

-- ------------------------------------------------------- bridge_deliveries
-- Inbound replay guard + outbound delivery ledger.
CREATE TABLE bridge_deliveries (
  id              uuid PRIMARY KEY,
  tenant_id       uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  bridge_id       uuid NOT NULL,
  direction       text NOT NULL CHECK (direction IN ('inbound', 'outbound')),
  delivery_id     text NOT NULL CHECK (length(delivery_id) BETWEEN 1 AND 255),
  event_type      text NOT NULL CHECK (length(event_type) BETWEEN 1 AND 120),
  status          text NOT NULL CHECK (status IN ('accepted', 'delivered', 'rejected', 'failed', 'pending_approval')),
  http_status     smallint,
  payload_sealed  bytea NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, bridge_id, direction, delivery_id),
  FOREIGN KEY (tenant_id, bridge_id) REFERENCES bridges (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX bridge_deliveries_recent ON bridge_deliveries (tenant_id, bridge_id, created_at DESC);
ALTER TABLE bridge_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE bridge_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON bridge_deliveries
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE ON bridge_deliveries TO bp_app;

-- -------------------------------------------------------- bridge_messages
-- Quarantined untrusted external messages & comments from inbound webhooks
-- and scoped external agent peers. Never treated as privileged instructions.
CREATE TABLE bridge_messages (
  id                   uuid PRIMARY KEY,
  tenant_id            uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  bridge_id            uuid NOT NULL,
  delivery_id          uuid NOT NULL,
  external_actor       text NOT NULL CHECK (length(external_actor) <= 200),
  channel_ref          text NOT NULL DEFAULT '' CHECK (length(channel_ref) <= 200),
  event_type           text NOT NULL CHECK (length(event_type) <= 120),
  trust_level          text NOT NULL DEFAULT 'untrusted_external' CHECK (trust_level = 'untrusted_external'),
  approval_request_id  uuid,
  body_sealed          bytea NOT NULL,
  created_at           timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, bridge_id) REFERENCES bridges (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, delivery_id) REFERENCES bridge_deliveries (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX bridge_messages_by_bridge ON bridge_messages (tenant_id, bridge_id, created_at DESC);
ALTER TABLE bridge_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE bridge_messages FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON bridge_messages
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT ON bridge_messages TO bp_app;
