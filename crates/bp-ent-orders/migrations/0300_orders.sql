-- Encrypted ordering, order mail ledger and Stripe billing (bp-ent-orders).
-- Runs as the schema owner after 0001_core.sql. Conventions follow core:
-- every table carries tenant_id, ENABLE + FORCE row-level security, one
-- tenant_isolation policy on bp_tenant(), composite (tenant_id, x) foreign
-- keys so a row can never point into another tenant, and bp_app gets only
-- the verbs it needs.
--
-- Columns named `sealed` / `*_sealed` hold bp_ent_core envelope ciphertext
-- (AES-256-GCM under the tenant DEK). Their AAD binds table, row id and
-- column, so a ciphertext copied to another row, column or tenant will not
-- open. What stays in the clear is only what the database must filter or
-- join on: ids, status, timestamps, the random order reference and the
-- vendor's mail domain.

-- ------------------------------------------------------------------ orders
CREATE TABLE orders (
  id                    uuid PRIMARY KEY,
  tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  -- Random public reference (BP-XXXXXXXXXX) quoted in mail subjects.
  order_ref             text NOT NULL CHECK (order_ref ~ '^BP-[0-9A-HJKMNP-TV-Z]{10}$'),
  status                text NOT NULL DEFAULT 'draft' CHECK (status IN (
                          'draft', 'quote_requested', 'pending_approval', 'ordered',
                          'in_fabrication', 'shipped', 'delivered', 'on_hold', 'cancelled')),
  -- The status an on_hold order resumes to.
  held_from             text CHECK (held_from IN (
                          'draft', 'quote_requested', 'pending_approval', 'ordered',
                          'in_fabrication', 'shipped')),
  -- Lower-case mail domain of the vendor; inbound mail must come from it.
  vendor_domain         text CHECK (vendor_domain = lower(vendor_domain) AND length(vendor_domain) <= 253),
  -- Title, board, quantity, line items, amounts, quote, shipping address,
  -- customer contact, vendor reference, tracking.
  sealed                bytea NOT NULL,
  payment_state         text NOT NULL DEFAULT 'none' CHECK (payment_state IN ('none', 'pending', 'paid')),
  stripe_session_id     text,
  -- SHA-256 over the amount and currency the payment session was opened for.
  payment_binding       bytea,
  created_by            uuid NOT NULL,
  approved_by           uuid,
  approved_at           timestamptz,
  approval_request_id   uuid,
  -- Optimistic concurrency: every update bumps it.
  version               integer NOT NULL DEFAULT 1,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, order_ref),
  FOREIGN KEY (tenant_id, created_by) REFERENCES users (tenant_id, id),
  FOREIGN KEY (tenant_id, approved_by) REFERENCES users (tenant_id, id),
  CHECK ((status = 'on_hold') = (held_from IS NOT NULL))
);
CREATE INDEX orders_by_status ON orders (tenant_id, status, updated_at DESC);
CREATE UNIQUE INDEX orders_stripe_session ON orders (tenant_id, stripe_session_id) WHERE stripe_session_id IS NOT NULL;
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON orders
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE ON orders TO bp_app;

-- Status ledger: one row per transition. Append-only for the app role.
CREATE TABLE order_events (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  order_id      uuid NOT NULL,
  from_status   text,
  to_status     text NOT NULL,
  source        text NOT NULL CHECK (source IN ('user', 'approver', 'payment', 'mail')),
  actor         uuid,
  mail_message  uuid,
  -- Optional free-text note (reason for hold, etc.).
  note_sealed   bytea,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, order_id) REFERENCES orders (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, actor) REFERENCES users (tenant_id, id)
);
CREATE INDEX order_events_by_order ON order_events (tenant_id, order_id, created_at);
ALTER TABLE order_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE order_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON order_events
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT ON order_events TO bp_app;

-- Quotes, PO documents, invoices. Content is sealed before it gets here.
CREATE TABLE order_documents (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  order_id      uuid NOT NULL,
  kind          text NOT NULL CHECK (kind IN ('quote', 'purchase_order', 'invoice', 'other')),
  -- File name and media type.
  meta_sealed   bytea NOT NULL,
  content_sealed bytea NOT NULL CHECK (octet_length(content_sealed) <= 6 * 1024 * 1024),
  created_by    uuid NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, order_id) REFERENCES orders (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, created_by) REFERENCES users (tenant_id, id)
);
CREATE INDEX order_documents_by_order ON order_documents (tenant_id, order_id);
ALTER TABLE order_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE order_documents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON order_documents
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, DELETE ON order_documents TO bp_app;

-- Purchasing BOM: one row per line of a board's bill of materials.
CREATE TABLE bom_lines (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  -- Opaque board key (the co-dev board id or name); not a foreign key so
  -- purchasing can keep a BOM for a board that lives outside the portal.
  board_key     text NOT NULL CHECK (length(board_key) BETWEEN 1 AND 200),
  position      integer NOT NULL DEFAULT 0,
  -- Refdes, quantity, MPN, manufacturer, description, lifecycle, price,
  -- stock, alternates.
  sealed        bytea NOT NULL,
  updated_by    uuid NOT NULL,
  updated_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, updated_by) REFERENCES users (tenant_id, id)
);
CREATE INDEX bom_lines_by_board ON bom_lines (tenant_id, board_key, position);
ALTER TABLE bom_lines ENABLE ROW LEVEL SECURITY;
ALTER TABLE bom_lines FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON bom_lines
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON bom_lines TO bp_app;

-- -------------------------------------------------------------------- mail
-- A connected Google or Microsoft 365 mailbox.
CREATE TABLE mail_connections (
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  provider            text NOT NULL CHECK (provider IN ('google', 'microsoft')),
  address             text NOT NULL CHECK (address = lower(address) AND length(address) <= 320),
  -- OAuth refresh token, sealed. Never returned by any route.
  refresh_token_sealed bytea NOT NULL,
  scopes              text NOT NULL DEFAULT '',
  status              text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'error')),
  -- Only mail received after this instant is fetched.
  sync_cursor         timestamptz NOT NULL DEFAULT now(),
  last_sync_at        timestamptz,
  -- A fixed error code, never provider text.
  last_error          text CHECK (length(last_error) <= 64),
  connected_by        uuid NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, provider, address),
  FOREIGN KEY (tenant_id, connected_by) REFERENCES users (tenant_id, id)
);
ALTER TABLE mail_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE mail_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mail_connections
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON mail_connections TO bp_app;

-- One-time OAuth state for connecting a mailbox (10 minute life).
CREATE TABLE mail_oauth_states (
  id              uuid PRIMARY KEY,
  tenant_id       uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id         uuid NOT NULL,
  provider        text NOT NULL CHECK (provider IN ('google', 'microsoft')),
  -- SHA-256 of the state parameter; the value itself is never stored.
  state_hash      bytea NOT NULL,
  -- PKCE code verifier, sealed.
  verifier_sealed bytea NOT NULL,
  expires_at      timestamptz NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, state_hash),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
ALTER TABLE mail_oauth_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE mail_oauth_states FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mail_oauth_states
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, DELETE ON mail_oauth_states TO bp_app;

-- The order mail ledger: every vendor/customer message we ingested or sent.
CREATE TABLE mail_messages (
  id                uuid PRIMARY KEY,
  tenant_id         uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  connection_id     uuid,
  -- Provider message id (opaque); with the connection it makes ingestion idempotent.
  provider_message  text NOT NULL CHECK (length(provider_message) <= 512),
  direction         text NOT NULL CHECK (direction IN ('inbound', 'outbound')),
  order_id          uuid,
  received_at       timestamptz NOT NULL,
  -- From-domain matched the order's vendor AND the mailbox provider reported DMARC pass.
  sender_verified   boolean NOT NULL DEFAULT false,
  kind              text NOT NULL DEFAULT 'other' CHECK (kind IN (
                      'quote', 'confirmation', 'in_fabrication', 'shipping', 'delivery', 'other', 'notification')),
  -- What the parser proposed. A proposal only: see order_events for what happened.
  proposed_status   text CHECK (proposed_status IN ('in_fabrication', 'shipped', 'delivered')),
  confidence        smallint NOT NULL DEFAULT 0 CHECK (confidence BETWEEN 0 AND 2),
  applied           boolean NOT NULL DEFAULT false,
  -- Sender, recipients, subject, sanitised text, tracking, attachment names.
  sealed            bytea NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES mail_connections (tenant_id, id) ON DELETE SET NULL (connection_id),
  FOREIGN KEY (tenant_id, order_id) REFERENCES orders (tenant_id, id) ON DELETE SET NULL (order_id)
);
CREATE UNIQUE INDEX mail_messages_dedupe ON mail_messages (tenant_id, connection_id, provider_message);
CREATE INDEX mail_messages_by_order ON mail_messages (tenant_id, order_id, received_at DESC);
CREATE INDEX mail_messages_recent ON mail_messages (tenant_id, received_at DESC);
ALTER TABLE mail_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE mail_messages FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mail_messages
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE ON mail_messages TO bp_app;

ALTER TABLE order_events
  ADD FOREIGN KEY (tenant_id, mail_message) REFERENCES mail_messages (tenant_id, id);

-- ----------------------------------------------------------------- billing
-- One Stripe customer / subscription per tenant.
CREATE TABLE billing_accounts (
  tenant_id               uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  stripe_customer_id      text,
  stripe_subscription_id  text,
  subscription_status     text NOT NULL DEFAULT 'none' CHECK (subscription_status IN (
                            'none', 'incomplete', 'trialing', 'active', 'past_due', 'unpaid', 'canceled', 'paused')),
  seats                   integer NOT NULL DEFAULT 0 CHECK (seats >= 0),
  current_period_end      timestamptz,
  updated_at              timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE billing_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON billing_accounts
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE ON billing_accounts TO bp_app;

-- Replay guard: a Stripe event id is processed at most once. The tenant is
-- taken from the signed event's metadata, so the table stays tenant-scoped.
CREATE TABLE stripe_events (
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  event_id      text NOT NULL CHECK (length(event_id) <= 255),
  event_type    text NOT NULL CHECK (length(event_type) <= 255),
  received_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, event_id)
);
ALTER TABLE stripe_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE stripe_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON stripe_events
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT ON stripe_events TO bp_app;

-- Boat VM compute usage waiting to be (or already) reported to Stripe as
-- meter events. `idempotency_key` is supplied by the relay per VM run, and is
-- also the Stripe meter event identifier, so a retry never bills twice.
CREATE TABLE usage_meter_events (
  tenant_id         uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  idempotency_key   text NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 100),
  vm_id             uuid NOT NULL,
  started_at        timestamptz NOT NULL,
  stopped_at        timestamptz NOT NULL,
  seconds           bigint NOT NULL CHECK (seconds >= 0 AND seconds <= 366 * 86400),
  reported_at       timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, idempotency_key),
  CHECK (stopped_at >= started_at)
);
CREATE INDEX usage_meter_unreported ON usage_meter_events (tenant_id, created_at) WHERE reported_at IS NULL;
ALTER TABLE usage_meter_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_meter_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON usage_meter_events
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE ON usage_meter_events TO bp_app;
