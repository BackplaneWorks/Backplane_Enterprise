-- Backplane Enterprise Private KiCad HTTP Library & Web Librarian schema (0100-0199).
-- Every table is strictly tenant-isolated with FORCE ROW LEVEL SECURITY and
-- composite tenant foreign keys so cross-tenant references are impossible.

CREATE TABLE library_categories (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  description text NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name)
);
ALTER TABLE library_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE library_categories FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON library_categories
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON library_categories TO bp_app;

CREATE TABLE library_parts (
  id                 uuid PRIMARY KEY,
  tenant_id          uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  category_id        uuid NOT NULL,
  part_number        text NOT NULL CHECK (length(part_number) BETWEEN 1 AND 120),
  mpn                text NOT NULL CHECK (length(mpn) BETWEEN 1 AND 200),
  manufacturer       text NOT NULL CHECK (length(manufacturer) BETWEEN 1 AND 200),
  value              text NOT NULL DEFAULT '',
  package_name       text NOT NULL DEFAULT '',
  description        text NOT NULL DEFAULT '',
  lifecycle          text NOT NULL DEFAULT 'Draft'
    CHECK (lifecycle IN ('Draft', 'In Review', 'Released', 'Obsolete')),
  symbol_ref         text NOT NULL DEFAULT '',
  footprint_ref      text NOT NULL DEFAULT '',
  model_3d_key       text,
  datasheet_url      text NOT NULL DEFAULT '',
  preferred_by_fab   boolean NOT NULL DEFAULT false,
  fab_stock_qty      integer NOT NULL DEFAULT 0 CHECK (fab_stock_qty >= 0),
  unit_price_cents   bigint NOT NULL DEFAULT 0 CHECK (unit_price_cents >= 0),
  attributes         jsonb NOT NULL DEFAULT '{}'::jsonb,
  ipc_spec           jsonb,
  exclude_from_bom   boolean NOT NULL DEFAULT false,
  exclude_from_board boolean NOT NULL DEFAULT false,
  created_by         uuid NOT NULL,
  updated_by         uuid NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, part_number),
  FOREIGN KEY (tenant_id, category_id) REFERENCES library_categories (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, created_by) REFERENCES users (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, updated_by) REFERENCES users (tenant_id, id) ON DELETE RESTRICT
);
CREATE INDEX library_parts_category_idx ON library_parts (tenant_id, category_id);
CREATE INDEX library_parts_lifecycle_idx ON library_parts (tenant_id, lifecycle);
CREATE INDEX library_parts_mpn_idx ON library_parts (tenant_id, lower(mpn));
ALTER TABLE library_parts ENABLE ROW LEVEL SECURITY;
ALTER TABLE library_parts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON library_parts
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON library_parts TO bp_app;

CREATE TABLE library_part_artifacts (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  part_id     uuid NOT NULL,
  kind        text NOT NULL
    CHECK (kind IN ('symbol_kicad', 'footprint_kicad', 'symbol_svg', 'footprint_svg', 'model_3d_ref')),
  name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  content     text,
  s3_key      text,
  sha256_hex  text NOT NULL CHECK (length(sha256_hex) = 64),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, part_id, kind),
  FOREIGN KEY (tenant_id, part_id) REFERENCES library_parts (tenant_id, id) ON DELETE CASCADE
);
ALTER TABLE library_part_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE library_part_artifacts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON library_part_artifacts
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON library_part_artifacts TO bp_app;

CREATE TABLE part_where_used (
  id           uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  part_id      uuid NOT NULL,
  board_id     text NOT NULL CHECK (length(board_id) BETWEEN 1 AND 128),
  board_name   text NOT NULL CHECK (length(board_name) BETWEEN 1 AND 200),
  revision_tag text NOT NULL CHECK (length(revision_tag) BETWEEN 1 AND 120),
  refdes_list  text[] NOT NULL DEFAULT '{}',
  updated_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, part_id, board_id, revision_tag),
  FOREIGN KEY (tenant_id, part_id) REFERENCES library_parts (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX part_where_used_part_idx ON part_where_used (tenant_id, part_id);
ALTER TABLE part_where_used ENABLE ROW LEVEL SECURITY;
ALTER TABLE part_where_used FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON part_where_used
  USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON part_where_used TO bp_app;
