-- Backplane Enterprise core schema.
-- Runs as the schema owner (DATABASE_ADMIN_URL). Services connect as `bp_app`,
-- which is NOBYPASSRLS and owns nothing, so every statement it runs is subject
-- to the tenant_isolation policies below.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'bp_app') THEN
    -- No password here: infra sets it out of band (`bp-ent-api migrate` reads
    -- BP_APP_DB_PASSWORD, or the operator runs ALTER ROLE).
    CREATE ROLE bp_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
END $$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM bp_app;
GRANT USAGE ON SCHEMA public TO bp_app;

-- The tenant every policy compares against. NULL (unset or '') matches no row.
CREATE FUNCTION bp_tenant() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE
  SET search_path = pg_catalog
  AS $$ SELECT nullif(current_setting('app.tenant_id', true), '')::uuid $$;
GRANT EXECUTE ON FUNCTION bp_tenant() TO bp_app;

-- ---------------------------------------------------------------- tenants
CREATE TABLE tenants (
  id          uuid PRIMARY KEY,
  name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  slug        text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenants
  USING (id = bp_tenant()) WITH CHECK (id = bp_tenant());
GRANT SELECT, INSERT, UPDATE ON tenants TO bp_app;

-- Login routing only: org slug / operator-verified e-mail domain -> tenant id.
-- Readable before a tenant is known (it holds nothing else); writes are
-- tenant-checked, and only the operator (schema owner) can add a domain, so a
-- tenant cannot squat on another company's domain.
CREATE TABLE tenant_directory (
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  kind        text NOT NULL CHECK (kind IN ('slug', 'domain')),
  value       text NOT NULL CHECK (value = lower(value) AND length(value) BETWEEN 2 AND 253),
  PRIMARY KEY (kind, value)
);
ALTER TABLE tenant_directory ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_directory FORCE ROW LEVEL SECURITY;
CREATE POLICY directory_read ON tenant_directory FOR SELECT USING (true);
CREATE POLICY directory_insert ON tenant_directory FOR INSERT
  WITH CHECK (tenant_id = bp_tenant() AND kind = 'slug');
CREATE POLICY directory_delete ON tenant_directory FOR DELETE
  USING (tenant_id = bp_tenant() AND kind = 'slug');
GRANT SELECT, INSERT, DELETE ON tenant_directory TO bp_app;

-- ------------------------------------------------------------------ users
CREATE TABLE users (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email         text NOT NULL CHECK (email = lower(email) AND length(email) <= 320),
  name          text NOT NULL DEFAULT '',
  role          text NOT NULL CHECK (role IN ('org_admin', 'engineer', 'librarian', 'purchasing', 'external_reviewer')),
  status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'invited')),
  idp_id        uuid,
  idp_subject   text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz,
  UNIQUE (tenant_id, email),
  UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX users_idp_subject ON users (tenant_id, idp_id, idp_subject) WHERE idp_subject IS NOT NULL;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON users
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON users TO bp_app;

-- ----------------------------------------------------- identity providers
CREATE TABLE identity_providers (
  id                uuid PRIMARY KEY,
  tenant_id         uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  kind              text NOT NULL CHECK (kind IN ('google', 'microsoft', 'oidc', 'saml')),
  display_name      text NOT NULL,
  enabled           boolean NOT NULL DEFAULT true,
  -- OIDC family
  issuer            text,
  client_id         text,
  client_secret_enc bytea,           -- envelope-encrypted (BPE1)
  -- Google `hd` / Microsoft `tid` pin, and the e-mail domains allowed to sign in
  directory_id      text,
  allowed_domains   text[] NOT NULL DEFAULT '{}',
  -- generic OIDC only: accept tokens without `email_verified` (for IdPs that
  -- never send it and only issue addresses the org controls)
  trust_email       boolean NOT NULL DEFAULT false,
  -- SAML 2.0
  saml_entity_id    text,
  saml_sso_url      text,
  saml_cert_pem     text,
  -- provisioning
  auto_provision    boolean NOT NULL DEFAULT false,
  default_role      text NOT NULL DEFAULT 'engineer' CHECK (default_role IN ('engineer', 'librarian', 'purchasing', 'external_reviewer')),
  created_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id)
);
ALTER TABLE identity_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_providers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON identity_providers
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON identity_providers TO bp_app;

-- In-flight SSO logins (state + PKCE + nonce), single use, short lived.
CREATE TABLE login_states (
  tenant_id         uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  state_hash        bytea PRIMARY KEY,
  idp_id            uuid NOT NULL,
  pkce_verifier_enc bytea NOT NULL,
  nonce             text NOT NULL,
  return_to         text,
  -- desktop sign-in (loopback redirect + PKCE-style challenge)
  desktop_redirect  text,
  desktop_challenge text,
  expires_at        timestamptz NOT NULL
);
ALTER TABLE login_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE login_states FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON login_states
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, DELETE ON login_states TO bp_app;

-- One-time codes handed to the desktop app's loopback listener.
CREATE TABLE desktop_codes (
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  code_hash   bytea PRIMARY KEY,
  user_id     uuid NOT NULL,
  challenge   text NOT NULL,
  expires_at  timestamptz NOT NULL,
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
ALTER TABLE desktop_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE desktop_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON desktop_codes
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, DELETE ON desktop_codes TO bp_app;

-- Sessions ('s'), user API tokens ('u') and device tokens ('d'). Only the
-- SHA-256 of a token is ever stored.
CREATE TABLE auth_tokens (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id       uuid NOT NULL,
  kind          text NOT NULL CHECK (kind IN ('s', 'u', 'd')),
  name          text NOT NULL DEFAULT '',
  token_hash    bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  scopes        text[] NOT NULL DEFAULT '{*}',
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  last_used_at  timestamptz,
  revoked_at    timestamptz,
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX auth_tokens_user ON auth_tokens (tenant_id, user_id);
ALTER TABLE auth_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON auth_tokens
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON auth_tokens TO bp_app;

-- ------------------------------------------------------- envelope keys
-- One data-encryption key per tenant and version, stored only wrapped by the
-- KEK (AWS KMS or the self-host master key).
CREATE TABLE tenant_keys (
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  version      integer NOT NULL CHECK (version > 0),
  kek_id       text NOT NULL,
  wrapped_dek  bytea NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, version)
);
ALTER TABLE tenant_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_keys
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
-- No DELETE: losing a DEK version loses the data sealed under it.
GRANT SELECT, INSERT, UPDATE ON tenant_keys TO bp_app;

-- ------------------------------------------------- governance settings
CREATE TABLE tenant_settings (
  tenant_id       uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  llm_policy      jsonb NOT NULL,
  approval_gates  jsonb NOT NULL,
  updated_at      timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE tenant_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_settings
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE ON tenant_settings TO bp_app;

CREATE TABLE approval_requests (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  gate          text NOT NULL,
  subject       text NOT NULL,          -- stable id of the thing, e.g. 'order:<uuid>'
  payload_hash  bytea NOT NULL,         -- binds the approval to exactly what was shown
  summary       jsonb NOT NULL,
  status        text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'consumed', 'expired')),
  requested_by  uuid NOT NULL,
  requested_via text NOT NULL,
  decided_by    uuid,
  decided_at    timestamptz,
  reason        text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL
);
CREATE INDEX approval_requests_lookup ON approval_requests (tenant_id, gate, subject, status);
ALTER TABLE approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON approval_requests
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE ON approval_requests TO bp_app;

-- ------------------------------------------------------------ audit log
-- Append-only, per-tenant hash chain: hash = SHA-256(prev_hash, fields).
CREATE TABLE audit_log (
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  seq         bigint NOT NULL CHECK (seq > 0),
  at_us       bigint NOT NULL,          -- unix microseconds (hashed exactly)
  actor_kind  text NOT NULL,            -- 'user' | 'token' | 'device' | 'system'
  actor       text NOT NULL,            -- user id, or the system component name
  action      text NOT NULL,
  target      text NOT NULL,
  details     text NOT NULL,            -- JSON text, hashed byte for byte
  prev_hash   bytea NOT NULL,
  hash        bytea NOT NULL,
  PRIMARY KEY (tenant_id, seq)
);
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_log
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
REVOKE ALL ON audit_log FROM bp_app;
GRANT SELECT, INSERT ON audit_log TO bp_app;

CREATE FUNCTION audit_log_immutable() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog
  AS $$ BEGIN RAISE EXCEPTION 'audit_log is append-only'; END $$;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();
