-- Board co-development: projects, immutable revisions with BOM and placement
-- data, sealed snapshot artifacts, pinned review comments, ECOs.

CREATE TABLE boards (
  id              uuid PRIMARY KEY,
  tenant_id       uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  slug            text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
  description     text NOT NULL DEFAULT '' CHECK (length(description) <= 4000),
  width_mm        double precision NOT NULL DEFAULT 0 CHECK (width_mm >= 0 AND width_mm <= 5000),
  height_mm       double precision NOT NULL DEFAULT 0 CHECK (height_mm >= 0 AND height_mm <= 5000),
  layer_count     integer NOT NULL DEFAULT 2 CHECK (layer_count BETWEEN 1 AND 64),
  -- visible to the external_reviewer role (contract manufacturers, outside reviewers)
  external_access boolean NOT NULL DEFAULT false,
  created_by      uuid NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, slug),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, created_by) REFERENCES users (tenant_id, id)
);
ALTER TABLE boards ENABLE ROW LEVEL SECURITY;
ALTER TABLE boards FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON boards USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON boards TO bp_app;

CREATE TABLE board_revisions (
  id           uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  board_id     uuid NOT NULL,
  seq          integer NOT NULL,
  tag          text NOT NULL CHECK (length(tag) BETWEEN 1 AND 100),
  commit_sha   text NOT NULL DEFAULT '' CHECK (commit_sha ~ '^[0-9a-f]{0,64}$'),
  summary      text NOT NULL DEFAULT '' CHECK (length(summary) <= 4000),
  status       text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'released')),
  -- placement data for the web viewer: [{refdes, mpn, xMm, yMm, widthMm, heightMm, layer, packageName}]
  components   jsonb NOT NULL DEFAULT '[]',
  created_by   uuid NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  released_by  uuid,
  released_at  timestamptz,
  UNIQUE (tenant_id, board_id, seq),
  UNIQUE (tenant_id, board_id, tag),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, board_id) REFERENCES boards (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, created_by) REFERENCES users (tenant_id, id)
);
ALTER TABLE board_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE board_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON board_revisions USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON board_revisions TO bp_app;

CREATE TABLE board_bom_lines (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  revision_id   uuid NOT NULL,
  mpn           text NOT NULL CHECK (length(mpn) BETWEEN 1 AND 200),
  manufacturer  text NOT NULL DEFAULT '' CHECK (length(manufacturer) <= 200),
  value         text NOT NULL DEFAULT '' CHECK (length(value) <= 200),
  footprint     text NOT NULL DEFAULT '' CHECK (length(footprint) <= 200),
  quantity      integer NOT NULL CHECK (quantity > 0 AND quantity <= 1000000),
  refdes        text[] NOT NULL DEFAULT '{}',
  FOREIGN KEY (tenant_id, revision_id) REFERENCES board_revisions (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX board_bom_lines_rev ON board_bom_lines (tenant_id, revision_id);
CREATE INDEX board_bom_lines_mpn ON board_bom_lines (tenant_id, mpn);
ALTER TABLE board_bom_lines ENABLE ROW LEVEL SECURITY;
ALTER TABLE board_bom_lines FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON board_bom_lines USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, DELETE ON board_bom_lines TO bp_app;

-- Snapshots (layer SVGs, schematic SVG, 3D model, fabrication outputs).
-- `data` is envelope-encrypted with the tenant's key (BPE1 blob).
CREATE TABLE board_artifacts (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  revision_id   uuid NOT NULL,
  kind          text NOT NULL CHECK (kind IN ('pcb_svg', 'schematic_svg', 'model_glb', 'model_step', 'gerbers_zip', 'bom_csv', 'kicad_pcb', 'kicad_sch', 'pdf')),
  name          text NOT NULL DEFAULT '' CHECK (name ~ '^[A-Za-z0-9._-]{0,80}$'),
  size_bytes    bigint NOT NULL CHECK (size_bytes >= 0),
  sha256        bytea NOT NULL CHECK (octet_length(sha256) = 32),
  data          bytea NOT NULL,
  uploaded_by   uuid NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, revision_id, kind, name),
  FOREIGN KEY (tenant_id, revision_id) REFERENCES board_revisions (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, uploaded_by) REFERENCES users (tenant_id, id)
);
ALTER TABLE board_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE board_artifacts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON board_artifacts USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON board_artifacts TO bp_app;

-- Review comments pinned to a point on a layer and/or a component.
CREATE TABLE board_comments (
  id           uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  board_id     uuid NOT NULL,
  revision_id  uuid NOT NULL,
  layer        text NOT NULL CHECK (layer ~ '^[A-Za-z0-9._-]{1,40}$'),
  x_mm         double precision NOT NULL CHECK (x_mm BETWEEN -10000 AND 10000),
  y_mm         double precision NOT NULL CHECK (y_mm BETWEEN -10000 AND 10000),
  refdes       text CHECK (refdes ~ '^[A-Za-z0-9_#.+-]{1,32}$'),
  body         text NOT NULL CHECK (length(body) BETWEEN 1 AND 8000),
  author_id    uuid NOT NULL,
  resolved     boolean NOT NULL DEFAULT false,
  resolved_by  uuid,
  resolved_at  timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, board_id) REFERENCES boards (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, revision_id) REFERENCES board_revisions (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, author_id) REFERENCES users (tenant_id, id)
);
CREATE INDEX board_comments_board ON board_comments (tenant_id, board_id, created_at);
ALTER TABLE board_comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE board_comments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON board_comments USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON board_comments TO bp_app;

-- Engineering change orders.
CREATE TABLE board_ecos (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  board_id      uuid NOT NULL,
  number        integer NOT NULL,
  title         text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
  rationale     text NOT NULL DEFAULT '' CHECK (length(rationale) <= 8000),
  status        text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'in_review', 'approved', 'implemented', 'rejected')),
  revision_id   uuid,
  created_by    uuid NOT NULL,
  decided_by    uuid,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, number),
  FOREIGN KEY (tenant_id, board_id) REFERENCES boards (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, revision_id) REFERENCES board_revisions (tenant_id, id) ON DELETE SET NULL (revision_id),
  FOREIGN KEY (tenant_id, created_by) REFERENCES users (tenant_id, id)
);
ALTER TABLE board_ecos ENABLE ROW LEVEL SECURITY;
ALTER TABLE board_ecos FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON board_ecos USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON board_ecos TO bp_app;
