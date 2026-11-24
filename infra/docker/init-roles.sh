#!/usr/bin/env bash
set -euo pipefail

# Provisions the unprivileged runtime role (bp_app) with NOBYPASSRLS and no
# schema creation rights. Password comes strictly from BP_APP_DB_PASSWORD
# (never embedded in SQL migrations).

APP_USER="${BP_APP_DB_USER:-bp_app}"
APP_PASS="${BP_APP_DB_PASSWORD:?BP_APP_DB_PASSWORD must be set}"

psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname "${POSTGRES_DB}" \
  -v app_user="${APP_USER}" \
  -v app_pass="${APP_PASS}" <<'EOSQL'
SELECT format(
  'DO $$ BEGIN
     IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %L) THEN
       CREATE ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L;
     ELSE
       ALTER ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L;
     END IF;
   END $$;',
  :'app_user', :'app_user', :'app_pass', :'app_user', :'app_pass'
) \gexec

REVOKE ALL ON SCHEMA public FROM PUBLIC;
SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'app_user') \gexec
EOSQL
