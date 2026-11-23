# Backplane Enterprise — Architecture, Product & Security Specification (v1.0)

**Backplane Enterprise** is an open-source (MIT), self-hostable and AWS-managed enterprise control plane for hardware and firmware engineering teams using [Backplane](https://github.com/BackplaneWorks/Backplane).

---

## 1. Core Design Principles

1. **Zero-VPN / Zero-Tailscale Customer Experience:** Customers never install Tailscale or open inbound firewall ports. Managed Boat VMs dial outbound mTLS to the Enterprise Relay, and local Backplane desktop clients connect automatically over HTTPS/WSS (TLS 1.3) authenticated with org OAuth/SSO.
2. **Strict Multi-Tenant Isolation by Construction:** PostgreSQL Row-Level Security (`tenant_id` enforced on every table), per-tenant S3 prefixes, per-tenant KMS envelope encryption keys (DEK wrapped by AWS KMS or local master key for self-host), and strictly tenant-scoped HTTP Library caching so zero customer parts, schematics, or BOMs can ever leak across tenants.
3. **Self-Hostable & AWS-Native:** Identical Rust + TypeScript/Vite containers deployable via Terraform/OpenTofu on AWS (ECS Fargate / RDS Postgres / S3 / KMS / SES / ALB+WAF) or via Docker Compose / Helm on-prem or in a customer's own VPC.
4. **Role-First Web Experience:** Engineers, Librarians, Purchasing/Supply-Chain, Org Admins, and External CMs/Reviewers each get purpose-built web workflows without requiring KiCad installed locally.
5. **MIT Licensed:** Frictionless enterprise legal adoption, full security auditability, and self-host freedom.

---

## 2. Technology Stack

- **Backend & Control Plane:** Rust workspace (`crates/`):
  - `bp-ent-core`: domain models, RBAC/policy engine, KMS envelope crypto (`aes-256-gcm` + AWS KMS / local KEK provider), audit log hash-chain.
  - `bp-ent-api`: Axum HTTP/WebSocket API server, SQLx PostgreSQL migrations & RLS middleware, OAuth/OIDC/SAML auth, Stripe webhooks.
  - `bp-ent-relay`: Zero-Tailscale mTLS/WSS relay connecting local Backplane clients to upstream managed Boat VMs (preloaded with Backplane + `Backplane_KiCad`).
  - `bp-ent-httplib`: Private per-tenant KiCad HTTP Library (`kicad_httplib` v1 API) + Librarian service (symbol/footprint generation via KiCad headless/IPC + parametric lifecycle + where-used).
  - `bp-ent-orders`: Encrypted ordering & status ledger, Google (Gmail API) & Microsoft 365 (Graph API) email ingestion/dispatch, status parser, and Stripe billing integration.
- **Web Portal (`web/`):** TypeScript + Vite + clean modular SPA:
  - Co-Development & Board/Schematic/3D Review portal (pin-drop comments, git revisions, ECOs)
  - Purchasing & BOM workspace (live stock/pricing, alternates, RFQ export, order approvals & tracking)
  - Web Librarian (part table, parametric editor, lifecycle transitions, symbol/footprint preview, 1-click "Open in KiCad")
  - Admin Console (SSO/RBAC, Boat VM fleet, LLM provider/model allowlists & optional ZDR toggle, approval gates, audit logs, Stripe billing)
- **Infrastructure (`infra/`):**
  - `infra/terraform/aws/`: Modular AWS deployment (VPC, ECS Fargate, RDS Postgres + KMS, S3 + KMS, Secrets Manager, SES, ALB + WAF, CloudWatch).
  - `infra/docker/`: Turnkey `docker-compose.yml` + local KMS dev key + Postgres + MinIO for 1-command self-hosting.
  - `infra/helm/`: Kubernetes Helm chart for enterprise VPC / on-prem deployments.
  - `infra/boat/`: Boat VM image/provisioning spec preloaded with latest `backplane-hub`, `Backplane_KiCad`, and outbound relay agent.

---

## 3. Feature Specifications

### 3.1 AWS & Self-Hosted Infrastructure
- Single-command local/self-host boot via `docker compose up` (Postgres 16, Rust API/Relay/HTTP-Lib, Vite web bundle, MinIO S3-compatible object store).
- Production AWS Terraform modules with private subnets, KMS CMK option, automated encrypted RDS snapshots, WAF rate-limiting, and zero public DB/VM ports.

### 3.2 Managed Boat VMs & Zero-Tailscale Remote Control
- Control plane manages per-org / per-seat Boat VMs preloaded with latest Backplane hub + pinned `Backplane_KiCad`.
- **Automatic tunnel (no Tailscale):** Each Boat VM maintains an outbound mTLS WebSocket/HTTP2 tunnel to `bp-ent-relay` using a short-lived signed device certificate.
- Local Backplane desktop app signs in via org OAuth/SSO and automatically discovers & controls the user's assigned Boat VM (chat, file sync, remote KiCad IPC, builds) over TLS 1.3 through the relay.
- Idle auto-stop and automatic wake-on-connect with VM-hour metering fed to Stripe.

### 3.3 Altium 365 Parity — Private HTTP Library, Web Librarian & Co-Development
- **Private KiCad HTTP Library (`GET /v1/httplib/{tenant}/...`):**
  - Implements KiCad's `kicad_httplib` JSON protocol (`/categories.json`, `/parts/category/{id}.json`, `/parts/{id}.json`) plus signed, tenant-scoped symbol/footprint/3D-model fetches.
  - Authenticated via per-user/per-device scoped bearer tokens (or mTLS client certs); strictly tenant-isolated (zero shared cache across tenants).
  - Auto-generates ready-to-import `<org>.kicad_httplib` config files from the Web UI or Backplane desktop app.
- **Web Librarian:**
  - Create, clone, and edit parts in the browser: MPN, manufacturer, parametric attributes, datasheet link, preferred/approved/EOL lifecycle states (`Draft → In Review → Released → Obsolete`), and **Where-Used** impact lookup across all org boards.
  - Symbol & footprint generation/editing outside KiCad (parametric IPC-7351 footprint & symbol generator + SVG/2D preview) with **1-click "Open in KiCad"** (deep-linking to local KiCad or the user's Boat VM).
- **Web Co-Development & Purchasing Portal (OAuth/SSO):**
  - **Board Co-Dev:** View board/schematic/3D snapshots in browser, pin spatial review comments to `(layer, x, y)` or component refdes, inspect BOM/schematic/PCB diffs across revisions, and manage ECOs.
  - **Purchasing View:** Dedicated non-engineer role view showing live BOM, part lifecycle/EOL flags, supplier pricing/stock/alternates, RFQ export, and 1-click PO approval & order tracking.

### 3.4 Admin Governance & Production Controls
- **Identity & Access:** Google Workspace OAuth, Microsoft Entra ID / Outlook OAuth, generic OIDC/SAML 2.0, and RBAC roles (`org_admin`, `engineer`, `librarian`, `purchasing`, `external_reviewer`).
- **LLM Policy Engine:**
  - Org admins configure allowed providers/models (Anthropic, OpenAI, Google, AWS Bedrock, Azure OpenAI, self-hosted).
  - **Optional ZDR (Zero-Data-Retention) policy:** Toggleable per org based on the customer's own LLM account/contract.
  - **Approval gates:** Configurable mandatory human/admin approval before agents execute high-impact actions (placing orders, modifying released boards/parts, enabling external MCP servers, spending above budget thresholds).
  - **Immutable Audit Log:** Append-only, hash-chained audit trail of auth events, part releases, board changes, LLM policy changes, VM launches, and orders.

### 3.5 Google Workspace & Microsoft 365 (Outlook) Integration
- OAuth 2.0 connectors for **Google (Gmail API)** and **Microsoft 365 (Graph API)** with encrypted refresh-token storage (KMS envelope encrypted).
- Syncs customer & vendor order emails (quotes, fab confirmations, shipping/tracking notices) into the order pipeline and sends branded order status updates from the org's connected mailbox or AWS SES.

### 3.6 Encrypted Ordering, Status Tracking & Stripe Billing
- **Order Lifecycle:** `draft → quote_requested → pending_approval → ordered → in_fabrication → shipped → delivered` (plus `on_hold` / `cancelled`).
- **Encryption at Rest:** Sensitive order payloads (quotes, PO documents, vendor/customer email bodies, shipping addresses, tracking metadata) are **envelope-encrypted per tenant** (`AES-256-GCM` with per-tenant DEKs wrapped by AWS KMS or self-host KEK) before hitting PostgreSQL or S3.
- **Stripe Billing:** Subscription seat billing, Boat VM compute-hour metered usage, and order payment processing via Stripe Checkout / Billing Portal / signed webhooks.

### 3.7 Cybersecurity Infrastructure Review (`docs/SECURITY.md`)
- Full STRIDE threat model covering:
  1. Multi-tenant HTTP Library & S3 artifact isolation (preventing cross-tenant part/IP leakage)
  2. Zero-Tailscale Boat VM Relay (mTLS cert pinning, SSRF prevention, session isolation)
  3. OAuth/SAML/SSO & RBAC privilege boundaries
  4. Inbound email ingestion & parser hardening (HTML sanitization, attachment sandboxing, prompt-injection isolation)
  5. Encryption at rest (KMS envelope design, key rotation, zero plaintext secrets in logs)
  6. Supply-chain & CI security (Cargo audit/deny, npm audit, SBOM, strict CSP/HSTS/CORS headers, SOC 2 Type II control mapping).
