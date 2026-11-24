# Backplane Enterprise — Docker Compose (Self-Hosted)

Single-command self-hosted deployment of the unified Backplane Enterprise binary (`bp-ent-api serve`):

- `postgres` (PostgreSQL 16, internal network only; runs `init-roles.sh` to create unprivileged `bp_app` with `NOBYPASSRLS`)
- `minio` + `minio-init` (S3-compatible object store with private bucket ACL and a bucket-scoped `bp_app_s3` service account for `app`)
- `boat-ca-init` (creates a persistent Boat mTLS CA keypair in the `boat_ca` volume if not already present)
- `migrate` (one-shot job — the **only** container given `DATABASE_ADMIN_URL` and `BP_APP_DB_PASSWORD`)
- `app` (`bp-ent-api serve` with embedded `/app/web` SPA, connecting exclusively via `DATABASE_URL` as `bp_app`; serves HTTP API + portal + desktop WSS on `:8080` and Boat mTLS on `:8443`)

> **Production TLS Note:** By default, Compose listens on plain HTTP (`http://localhost:8080`) with `BP_INSECURE_COOKIES=1` for local evaluation. In production self-hosted deployments, terminate TLS 1.3 in front of `app:8080` (Caddy/Traefik/ALB), set `BP_PUBLIC_ORIGIN=https://<your-domain>`, `BP_INSECURE_COOKIES=0`, and `BP_TRUSTED_PROXY_HOPS=1`.

## Quick Start

```bash
cp infra/docker/.env.example infra/docker/.env
# Generate BP_KEK: echo "v1:$(openssl rand -base64 32)"
# Edit infra/docker/.env with strong passwords
docker compose -f infra/docker/docker-compose.yml --env-file infra/docker/.env up -d --build
```
