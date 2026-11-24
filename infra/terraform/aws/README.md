# Backplane Enterprise — Lean AWS Terraform Deployment

Modular, cost-disciplined AWS infrastructure engineered for **$10–$20/month/seat** SaaS pricing (**<$1–$2/user/month COGS** at scale) without sacrificing multi-tenant security isolation:

## Architecture Choices (Cost + Security)

- **Zero EKS ($0 vs $73/mo)** & **Zero NAT Gateways ($0 vs $65/mo):** Single unified ARM64 Graviton ECS Fargate container (`bp-ent-api serve` with embedded `/app/web`, serving HTTP API/Portal/WSS on `8080` and Boat mTLS on `8443`) runs in public subnets with `assign_public_ip = true` and a strict security group allowing inbound **only** from the ALB SG (`8080`) and VPC NLB ENIs (`8443`). RDS stays in isolated private subnets (`publicly_accessible = false`, zero IGW route, ingress only from ECS task SG).
- **1 Shared Multi-Tenant RDS Postgres (`db.t4g.micro`/`small`):** Enforces strict PostgreSQL Row-Level Security (`FORCE ROW LEVEL SECURITY` + `bp_tenant()`) and split Secrets Manager credentials (`database-admin-url` readable **only** by the one-shot `migrate` task; `database-app-url` for `bp_app` `NOBYPASSRLS`).
- **1 Shared AWS KMS CMK ($1/mo flat):** Wraps random per-tenant DEKs with `EncryptionContext={tenant_id}` + `tenant_id` in AES-256-GCM AAD — preserving full per-tenant crypto-shredding and independent DEK rotation without paying $1/tenant/month.
- **S3 Gateway Endpoint ($0)** + **SSE-KMS with S3 Bucket Keys**.
- **WAFv2 Rate Limit (~$6/mo):** Single per-IP rate-limit rule in front of the TLS 1.3 ALB.
- **On-Demand Boat VMs:** Optional metered compute add-on with aggressive 15-minute (`900s`) idle auto-stop and optional NLB `:8443` toggle (`enable_boat_mtls_nlb`).

## Monthly AWS Cost Estimate (`us-east-1`, Control Plane)

| AWS Component | 10 Seats (Starter) | 100 Seats (Growth) | 1,000 Seats (Scale) | Notes |
| --- | ---: | ---: | ---: | --- |
| **ECS Fargate ARM64** (`api+relay+web`) | $8.70 | $17.40 | $69.60 | 1× `0.25 vCPU/0.5 GB` → 2× `0.25/0.5` → 4× `0.5/1.0` |
| **RDS PostgreSQL Graviton** (`gp3 20–50 GB`) | $13.50 | $27.00 | $62.00 | `db.t4g.micro` (10) → `db.t4g.small` (100) → `db.t4g.medium` Multi-AZ (1k) |
| **ALB + WAFv2** (`1 rate-limit rule`) | $23.00 | $25.00 | $35.00 | ALB $16.20 + WAF $6.00 + LCU/requests |
| **Shared KMS CMK + Secrets (2)** | $1.80 | $1.80 | $1.80 | 1 CMK ($1.00) + 2 secrets ($0.80); in-memory DEK TTL cache |
| **S3 + CloudWatch Logs + SES** | $1.50 | $4.00 | $18.00 | Free S3 Gateway endpoint; Bucket Keys reduce KMS API calls ~99% |
| **NLB :8443 (optional Boat mTLS)** | $0.00–$16.20 | $16.20 | $16.20 | Disabled when Boat VMs unused; amortized across Boat seats |
| **Total Monthly AWS Base** | **$48.50** *(no NLB)* | **$91.40** | **$202.60** | Zero EKS, zero NAT Gateways, zero per-tenant KMS keys |
| **COGS per Seat / Month** | **$4.85** *(seed)* | **$0.91** | **$0.20** | **< $1/user/mo from ~90 seats upward** |

> **Boat VM Add-On & Stripe Metering:** On-demand Graviton EC2 (`c7g.large`/`xlarge` Spot or on-demand) with `900s` auto-stop costs ~$0.03–$0.07/active-hour, passed through via Stripe metered `UsageRecord`s. In Stripe, `STRIPE_VM_PRICE_ID` must be a metered price attached to a meter matching `STRIPE_VM_METER_EVENT` (`boat_vm_minutes`), with `transform_quantity[divide_by]=60` if you price per hour (since `bp-ent-orders` reports whole minutes, rounded up per run).

> **Required Encrypted State Backend:** Terraform state contains generated RDS credentials (`random_password`) and the Boat CA private key (`tls_private_key`). You MUST configure an encrypted remote backend (`backend "s3"` with `encrypt = true`, `kms_key_id`, and `use_lockfile = true` — template in `versions.tf`) before running `terraform apply`.
