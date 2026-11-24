# Backplane Enterprise — Cybersecurity Review & Threat Model

Scope: the whole repository at v1.0 (`crates/*`, `web/`, `infra/`), reviewed against `docs/SPEC.md` §3.7.
Method: STRIDE per trust boundary, source review of every security-relevant module, and an automated attack suite (`crates/bp-ent-sectest`) that runs against a real PostgreSQL as the unprivileged service role.

This document separates three things, and the difference matters:

- **Verified by test**: an automated test in this repository attacks the control and fails if it regresses.
- **Verified by review**: the code was read and the control is present; no automated test pins it yet.
- **Open**: a finding that is not fixed. See the [findings register](#9-findings-register).

To report a vulnerability, see [§11](#11-reporting-a-vulnerability).

---

## 1. System and trust boundaries

```
 Browser (portal SPA) ──HTTPS──┐
 Backplane desktop app ─HTTPS/WSS──┤            ┌──────────── PostgreSQL (RLS, role bp_app)
 KiCad (HTTP library) ──HTTPS──┼─► edge (ALB/nginx + WAF) ─► bp-ent-api ─┤
                               │                              bp-ent-httplib │──── S3 / MinIO (tenants/<id>/…)
 Boat VM ──outbound mTLS (8443)────────────────► bp-ent-relay ─┘            └──── KMS / local KEK
                                                     │
 Stripe ──signed webhook──► /v1/webhooks/stripe      └─► Gmail API · Microsoft Graph · Stripe API · IdPs (outbound)
 Chat platforms ──signed webhook──► /v1/bridges/{id}/inbound
```

| # | Boundary | Who is on the far side | What they are trusted for |
|---|----------|------------------------|---------------------------|
| B1 | Internet → edge | Anyone | Nothing |
| B2 | Authenticated user → API | A member of one tenant | Only their tenant, only their role's permissions |
| B3 | Tenant ↔ tenant | Another paying customer | Nothing. This is the boundary the product must never fail |
| B4 | Boat VM → relay | A VM running customer-directed agents and builds | Only its own `(tenant, vm)` identity |
| B5 | Service → database | Our own code, possibly buggy or injected | Only what role `bp_app` may do under RLS |
| B6 | Third-party content → service | E-mail senders, chat users, Stripe, IdPs, LLM output | Nothing; it is data, never instructions |
| B7 | Operator / cloud account | Whoever runs the deployment | Everything except undetected audit tampering |

**Assets**, most valuable first: customer design IP (part libraries, schematics, BOMs, board files); order data (quotes, POs, addresses, vendor mail); credentials (mailbox refresh tokens, IdP client secrets, sessions, device tokens, the Boat CA key, the KEK); the audit trail; billing integrity; availability.

**Out of scope for this review:** the Backplane desktop app and `Backplane_KiCad` themselves, the security of what agents do *inside* a Boat VM once commands reach it, and the customer's own IdP, mailbox and LLM provider accounts.

---

## 2. How tenant isolation is built

Isolation does not depend on every query remembering a `WHERE tenant_id = …`. It is enforced four times over, so one mistake is not a leak:

1. **The tenant comes only from the verified credential.** `Principal.tenant_id` is set by `bp_ent_core::auth` and nowhere else. No handler reads a tenant from a path, query or body; where a tenant appears in a URL (`/v1/httplib/{tenant}/…`) it is only compared with the principal's and a mismatch is a 404.
2. **The database refuses cross-tenant rows.** Every table has `tenant_id uuid NOT NULL`, `ENABLE` + `FORCE ROW LEVEL SECURITY`, and a policy `USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant())`. `bp_tenant()` reads the transaction-local setting `app.tenant_id`; unset or empty means NULL, which matches no row (fail closed). Services connect as `bp_app`, which is not the owner, has `NOBYPASSRLS`, cannot create objects, and cannot `TRUNCATE`. `Db::connect` refuses to start as a role that could bypass RLS. The only way to get a connection is `Db::tenant_tx(tenant)`, which opens a transaction and sets the tenant with `set_config(…, true)` so it cannot outlive the transaction on a pooled connection.
3. **Foreign keys cannot cross tenants.** Foreign-key checks bypass RLS, so references between tenant tables are composite: `(tenant_id, x) REFERENCES t (tenant_id, id)`.
4. **Ciphertext is bound to its tenant.** Sensitive payloads are sealed with a per-tenant key and the tenant id is in the authenticated data, so a row copied into another tenant does not decrypt ([§6](#6-encryption-at-rest-and-key-management)).

Object storage keys are built by `TenantId::s3_key`, which prefixes `tenants/<tenant_id>/` and rejects `..`, absolute paths, backslashes and NUL.

Pre-authentication lookups never search across tenants: tokens are `bpe_<kind>_<tenant-hex>_<secret>`; the tenant in the token only selects *which* tenant's RLS scope the hash lookup runs in, so a forged tenant finds nothing. The single table readable without a tenant is `tenant_directory` (login slug / verified domain → tenant id), which holds no customer data.

**Verified by test** (`bp-ent-sectest`, run over every `crates/*/migrations/*.sql` in global order, so new tables are covered without writing a test):

| Test | What it proves |
|------|----------------|
| `rls_catalog::every_table_has_forced_row_level_security` | No table without ENABLE + FORCE + a policy |
| `rls_catalog::every_table_carries_a_not_null_tenant_id` | No table without `tenant_id uuid NOT NULL` (allowlist: `tenants`) |
| `rls_catalog::every_policy_is_bound_to_the_current_tenant` | Every USING / WITH CHECK references the current tenant (allowlist: `tenant_directory.directory_read`, read-only) |
| `rls_catalog::app_role_is_unprivileged_and_owns_nothing` | `bp_app` is not superuser/bypassrls/owner, cannot CREATE, holds no TRUNCATE/TRIGGER/REFERENCES; nothing granted to PUBLIC |
| `rls_catalog::no_security_definer_functions` | No function that would run as the owner and skip RLS |
| `rls_catalog::foreign_keys_between_tenant_tables_include_tenant_id` | No foreign key that can point at another tenant's row |
| `rls_behavior::no_tenant_set_sees_no_rows_in_any_table` | Unset and empty tenant both see zero rows in every table |
| `rls_behavior::tenant_cannot_read_update_or_delete_another_tenants_rows` | SELECT / UPDATE / DELETE across tenants affect nothing |
| `rls_behavior::tenant_cannot_insert_or_move_rows_into_another_tenant` | INSERT with a foreign tenant id and UPDATE of `tenant_id` are rejected |
| `rls_behavior::tenant_scope_does_not_survive_the_transaction` | After commit or rollback the same connection sees nothing |
| `rls_behavior::app_role_cannot_disable_or_bypass_rls` | `bp_app` cannot disable RLS, drop/add policies, truncate, set `row_security=off`, shadow `bp_tenant()`, or grant itself BYPASSRLS |
| `rls_behavior::audit_log_is_append_only_for_the_app_role` | No UPDATE / DELETE / TRUNCATE on the audit log, even for the owner |

`db::run_migrations` repeats the structural checks at deploy time and fails the migration if a table is not isolated.

The same suite attacks the code above the database:

| Test | Attack it tries |
|------|-----------------|
| `core_boundaries::token_cannot_be_replayed_into_another_tenant` | Valid token with the tenant claim swapped, presented as another kind, one character flipped; revoked token; raw token in the database |
| `core_boundaries::suspended_user_or_tenant_loses_access_at_once` | Keep using a credential after suspension |
| `core_boundaries::session_cookies_and_api_tokens_are_not_interchangeable_and_csrf_is_enforced` | Session value as API key and the reverse; cross-site writes with missing, foreign or look-alike `Origin`; cross-site WebSocket |
| `core_boundaries::sealed_data_and_wrapped_keys_cannot_be_moved_between_tenants` | Sealed blob moved to another tenant, row or column; another tenant's wrapped key row planted as this tenant's next key |
| `core_boundaries::key_rows_are_tenant_scoped` | Read or delete another tenant's key rows as the service role |
| `core_boundaries::role_matrix_is_pinned` | Any change to what a role may do |
| `core_boundaries::token_scopes_narrow_and_never_widen_the_role` | Narrow token used for anything else; scope the role lacks; unknown scope strings; over-long lifetime |
| `core_boundaries::outbound_http_refuses_internal_destinations` | 22 SSRF URLs: metadata services, loopback, private ranges, IPv4-mapped / NAT64 / decimal / hex forms, credentials in URL, non-https schemes |
| `core_boundaries::audit_chain_detects_edits_and_deletions` | Superuser disables the triggers, edits an entry, then deletes one |
| `core_boundaries::secrets_and_emails_are_redacted_from_debug_output` | Secrets and e-mail addresses through `{:?}` |
| `feature_boundaries::untrusted_sources_cannot_place_cancel_or_rewind_an_order` | Mail or a payment event moving an order, across all 81 state pairs |
| `feature_boundaries::inbound_mail_is_reduced_to_visible_plain_text` | Script, hidden prompt-injection text, comments, invisible and right-to-left characters, header injection, oversized mail |
| `feature_boundaries::stripe_webhook_rejects_forged_replayed_and_downgraded_events` | Tampered body, attacker's key, replay, re-stamped timestamp, `v0` downgrade, unconfigured secret |
| `feature_boundaries::boat_vm_identity_comes_only_from_what_the_ca_signed` | Over-long or expired certificate, the CA certificate as an identity, nine malformed SPIFFE identities |
| `feature_boundaries::relay_frames_cannot_name_a_destination` | Frames naming a host or port; oversized frames |

At review time the whole workspace ran 235 tests (27 in this suite, the rest in the crates) with no failures against PostgreSQL 16.

---

## 3. STRIDE threat model

Legend for **Status**: T = verified by test, R = verified by review, F-n = open finding n in [§9](#9-findings-register).

### 3.1 Multi-tenant HTTP library and artifact isolation (SPEC §3.7 item 1)

| STRIDE | Threat | Control | Status |
|--------|--------|---------|--------|
| S | Tenant A's KiCad token used against tenant B's library URL | Tenant from token only; `{tenant}` path compared inside the RLS transaction; mismatch → 404 | R (`httplib/store.rs` `resolve_and_verify_tenant_path`), T (token replay: `core_boundaries::token_cannot_be_replayed_into_another_tenant`) |
| S | Stolen `.kicad_httplib` token used for anything but reading parts | Device tokens are scoped `parts:read`; scopes intersect with the role; device tokens cannot mint tokens | T (`token_scopes_narrow_and_never_widen_the_role`) |
| T | Tenant A writes or re-parents a part into B | RLS WITH CHECK; composite FKs | T |
| R | Part released or obsoleted with no record | `audit::append` in the same transaction as the change | R |
| I | Shared cache returns A's parts to B | In-process cache keyed `(tenant_id, namespace, item)`; every lookup takes a `TenantId`; tenant path and permission are checked *before* the cache; writes invalidate the tenant | R (`httplib/cache.rs`, unit test in crate) |
| I | CDN / proxy caches a private response | `Cache-Control: private, no-store`, `Vary: Authorization`, `nosniff` on every library and order response | R |
| I | Part id from another tenant used as an existence oracle | Not found and other-tenant are the same 404 (`Error::NotFound`) | R |
| I | Unreleased or obsolete parts served to KiCad | Only `Released` parts by default; drafts only on request with `parts:write` and never to a device token | R (F-6 fixed) |
| I | SVG preview or uploaded document runs script in the portal origin | Generated SVG is XML-escaped and served with `CSP: default-src 'none'; sandbox`; order documents are always `application/octet-stream` + `attachment` + sandbox CSP | R |
| I | S3 object of another tenant fetched by key manipulation | `TenantId::s3_key` prefix + traversal rejection; bucket has public access blocked | R |
| D | Wildcard search forcing table scans | LIKE escaping + length cap; `LIMIT 500` | R (F-7 fixed) |
| E | External reviewer reads the private library | `external_reviewer` has no `PartsRead` | T (`role_matrix_is_pinned`) |

### 3.2 Zero-Tailscale Boat VM relay (SPEC §3.7 item 2)

| STRIDE | Threat | Control | Status |
|--------|--------|---------|--------|
| S | A VM claims another tenant's or VM's identity | Identity is taken only from the verified client certificate's single SPIFFE URI SAN `spiffe://backplane.enterprise/tenant/<uuid>/vm/<uuid>`; headers are ignored; CA-signed leaf required | R + crate test `mtls_server_extracts_identity_from_cert_and_ignores_forged_headers` |
| S | A rogue relay impersonates ours to a VM (cert pinning) | The VM trusts only the Boat CA, not the public web PKI | R (`infra/boat/agent`) |
| S | Long-lived stolen device certificate | Lifetime ≤ 24 h enforced at issue, at verify, and by a DB CHECK; serial recorded; revocation checked at connect | R (re-checked every minute on live tunnels) |
| S | Relay runs with an unintended, throwaway CA | Startup fails unless a CA is configured (ephemeral only with an explicit dev flag) | R |
| T | Desktop user drives a VM that is not theirs | Same tenant (RLS) **and** `assigned_user_id == user` or `VmManage`; otherwise 404 | R |
| T | Cross-site page opens the relay WebSocket with the user's cookie | Cookie-authenticated upgrades require `Origin` = portal origin | T (`session_cookies…csrf_is_enforced`) |
| R | VM started, stopped, certificate issued or revoked with no record | Audit entries for each | R |
| I | Frames for one session delivered to another client | Registry keyed `(tenant, vm)`; one client stream per VM | R (second client refused) |
| I | Relay used to reach internal hosts (SSRF) | Protocol is a closed enum of logical channels; there is no host, address or port field anywhere | R + crate test (unknown channel rejected) |
| I | Downgrade below TLS 1.3 on the VM listener | TLS 1.3 only | R + crate test |
| D | Oversized frames or half-open TLS handshakes exhaust the relay | 1 MiB frame cap; 2 MiB message cap; 10 s handshake timeout; connection cap | R |
| D | Idle VMs burn compute | Idle reaper stops VMs and emits usage | R |
| E | VM renews or mints certificates beyond its own identity | CSR renewal over mTLS; every field of the CSR is overwritten with the presenting certificate's `(tenant, vm)`; first boot uses a single-use, hashed, tenant-scoped enrolment token | R + crate test (forged SAN in CSR), T (`feature_boundaries::boat_vm_identity…`) |
| — | Customer overbilled for stopped time | Usage interval = one start → one stop | R + crate DB test |

### 3.3 OAuth / OIDC / SAML, sessions and RBAC (SPEC §3.7 item 3)

| STRIDE | Threat | Control | Status |
|--------|--------|---------|--------|
| S | Token guessed or forged | 256-bit random secret; only SHA-256 stored; constant-time compare | T |
| S | Token replayed into another tenant, or as another kind | Lookup inside the claimed tenant's RLS scope; kind checked | T |
| S | Stolen session cookie used as an API key (or the reverse) | Session tokens are cookie-only; API tokens are header-only | T |
| S | Login CSRF / code injection in the SSO callback | State (tenant-prefixed, stored hashed, single use, 10 min) + PKCE + nonce; the callback must come from the browser that started the flow (`__Host-` login cookie compared in constant time) | R (`api/routes/sso.rs`) |
| S | Sign-in from the wrong Google Workspace / Entra tenant | Google: `email_verified` and the pinned `hd`; Entra: the pinned `tid` is mandatory; allowed e-mail domains; an account bound to an IdP subject is never re-linked by e-mail | R + crate tests. Generic OIDC also requires `email_verified` unless the admin marks the IdP as issuing only verified addresses |
| S | Forged or algorithm-confused ID token; IdP mix-up | Asymmetric algorithms only (no `none`, no HMAC); signature against the issuer's published keys; `iss`, `aud`, `exp`, `nonce`; discovery document must name the issuer that was asked | R (`api/oidc.rs`) |
| S | SAML assertion forgery (signature wrapping, comment truncation, entity expansion) | IdP certificate pinned (in-document `KeyInfo` ignored); RSA-SHA256, exclusive C14N and SHA-256 only; the signature must be a direct child of, and reference by a document-unique ID, the element that is read (the single `Assertion`, or the `Response` directly containing it); no DTD; `EncryptedAssertion` refused; nesting depth capped before parsing; `Issuer`, `Audience`, `Recipient`, validity window and `InResponseTo` bound to the single-use, browser-bound login state | R + crate tests (canonicalisation checked against libxml2, signatures against OpenSSL vectors, five wrapping variants) |
| T | Open redirect after login; desktop code sent off-machine | `return_to` must be a portal path; desktop redirect must be `http://` loopback with a port; one-time code is useless without the app's verifier | R + crate tests |
| E | Agent holding an admin's API token changes users, SSO, policy or keys | Admin writes need a browser session (`require_interactive`); the last active org admin cannot be demoted, suspended or deleted | R (`api/routes/admin.rs`) |
| S | Tenant squats another company's e-mail domain | Only the operator can add a `domain` directory row (policy allows tenants `slug` only) | R (policy text), T (catalog) |
| T | Cross-site request changes state with the user's cookie | Non-GET cookie requests need `Origin` = portal **and** `X-BP-CSRF`; cookie is `__Host-`, `HttpOnly`, `Secure`, `SameSite=Lax` | T |
| R | Admin changes roles, SSO, LLM policy with no trail | Hash-chained audit log | T (tamper detection) |
| I | E-mail addresses or secrets in logs | `Principal` Debug omits e-mail; `Secret<T>` prints `[redacted]`, is not `Serialize`, zeroes on drop | T |
| I | Errors leak internals | `Error` → JSON `{code,message}`; 500s return no cause | R |
| D | Credential stuffing / token spraying | WAF rate rule at the edge; no password login exists (SSO only) | R (terraform) |
| E | Anyone on the internet creates an organisation or its first admin | No HTTP route creates tenants. `bp-ent-api tenant create` is an operator CLI; e-mail domains are added by the operator (`tenant add-domain`) with the schema-owner credential | R (`api/main.rs`) |
| E | Role does more than intended | One table (`Role::permissions`), every handler calls `Principal::require`; matrix pinned by test | T |
| E | Narrow token widened, or scope grants what the role lacks | Effective permission = role ∧ scope; unknown scopes grant nothing | T |
| E | Agent with a token approves its own high-impact action | Approvals need a browser session, an approver role, and a different person (unless the org enables self-approval); bound to a hash of what was shown; single use | R (`core/policy.rs`, core tests) |
| E | Suspended user keeps working | User and tenant status checked on every request; `revoke_user_tokens` | T |

### 3.4 Inbound e-mail, webhooks and prompt injection (SPEC §3.7 item 4)

Inbound mail, chat messages and webhook bodies are hostile input written by strangers. The design rule is: **they are data; they can never become instructions, markup, or a state change on their own.**

| STRIDE | Threat | Control | Status |
|--------|--------|---------|--------|
| S | Forged Stripe webhook | HMAC-SHA256 over the raw bytes, constant-time, `v1` only (no `v0` downgrade), ±300 s, body cap, nothing parsed before it verifies | T (`feature_boundaries::stripe_webhook…`) |
| S | Replayed Stripe event | `stripe_events (tenant_id, event_id)` dedupe | R |
| S | Event for tenant A applied to tenant B | Tenant only from metadata we set on the Stripe object; customer id must match the one on file | R |
| S | Forged chat-platform webhook | Per-platform scheme: HMAC (generic), Slack v0, Discord Ed25519, Teams JWT; timestamp + replay dedupe | R (`bridges/signatures.rs`) |
| T | "Your order has shipped" phishing mail moves an order | The parser only *proposes* a status; a person with `OrdersWrite` applies it, and the state machine must allow the step | R (`orders/mailbox.rs` `apply_event`), T (`feature_boundaries::untrusted_sources_cannot_place_cancel_or_rewind_an_order`, all 81 state pairs) |
| T | Paid-for-less: checkout completed for a smaller amount | Payment bound to `(order, amount, currency)` + our own session id; order must be approved | R |
| T | HTML mail carries script, trackers, or hidden text | HTML is reduced to bounded plain text: tags, scripts, styles, comments, hidden elements, control and bidi/zero-width characters removed; 1 MB in, 64 KB out | T (`feature_boundaries::inbound_mail_is_reduced_to_visible_plain_text`) |
| T | Header injection through a subject or address reused outbound | `clean_header` forces a single bounded line | R + crate test |
| I | Prompt injection: mail or chat text steers an LLM agent | Text is stored sealed and shown as text; it is not placed in an instruction channel; anything an agent does that is high-impact (orders, released parts, external MCP servers, spend) goes through the approval gate, which a token cannot satisfy | R |
| I | Attachment executes or is rendered | Attachment names recorded only; uploaded documents download as opaque bytes with a sandbox CSP | R |
| I | Mailbox token leak | Refresh tokens sealed with row-bound AAD; never returned by any route; held in `Secret` | R |
| D | Mail bomb / huge body | Input and output caps; sync cursor | R |
| E | External agent peer (MCP / A2A bridge) reaches parts, VMs or admin | Dedicated deny-by-default principal: only `boards:read` / `boards:comment` can be granted; mapped to the guest role and a non-interactive credential; proposals only enter the approval queue | R + crate tests |

### 3.5 Encryption at rest and key management (SPEC §3.7 item 5)

See [§6](#6-encryption-at-rest-and-key-management) for the design.

| STRIDE | Threat | Control | Status |
|--------|--------|---------|--------|
| T | Ciphertext moved to another tenant, row or column | AAD = `tenant_id ‖ key_version ‖ table\|row\|field` | T |
| T | Wrapped key row moved to another tenant or version | Wrap AAD / KMS encryption context = tenant + version | T |
| T | Bit flip in a blob or key row | AES-256-GCM tag | T (core tests) |
| I | Database dump or backup read by an attacker | Order payloads, mail bodies, addresses, tracking, mailbox tokens, IdP client secrets, PKCE verifiers are sealed; the KEK is not in the database | R |
| I | Nonce reuse | 96-bit random nonce from the OS RNG per seal; rotate the DEK yearly or before ~2³² seals (§6) | T (core test) |
| I | Key material in logs or dumps | `KeyBytes` zeroes on drop and has no Debug/Clone/Serialize | R |
| I | Database writer redirects unwrap to another KMS key | Only key ids from configuration are used, never the id stored in the row | R (F-12 fixed) |
| D | Losing a key version loses data | `bp_app` has no DELETE on `tenant_keys` | T |
| E | Service role reads another tenant's wrapped keys | RLS on `tenant_keys` | T |

### 3.6 Supply chain, CI and web hardening (SPEC §3.7 item 6)

| Threat | Control | Status |
|--------|---------|--------|
| Vulnerable or yanked crate | `cargo deny check` (advisories, yanked) + `cargo audit`, on every push and daily (`.github/workflows/security.yml`) | R (workflow not yet run on GitHub) |
| Copyleft or unknown-license dependency | `deny.toml` license allowlist | R |
| Second TLS stack / system OpenSSL | `deny.toml` bans `openssl`, `native-tls`; everything uses rustls | R |
| Dependency from an unknown registry or git URL | `deny.toml` `[sources]` | R |
| Build ignores the lockfile | `--locked` / `npm ci --ignore-scripts` only | Web: fixed. Backend image: F-14 |
| Vulnerable npm package | `npm audit --omit=dev --audit-level=high` in CI; 0 production vulnerabilities at review time | R |
| No inventory of what shipped | CycloneDX SBOMs for Rust and web as CI artifacts | R |
| Secret committed to the repo | gitleaks in CI; `.env` and state files git-ignored | R |
| Misconfigured IaC | trivy config scan of `infra/` in CI | R |
| XSS in the portal | No `innerHTML`/`eval`/web storage anywhere in `web/src`; React escaping; CSP `default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'` | R |
| Clickjacking, MIME sniffing, referrer leaks | `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Permissions-Policy` | R (`infra/docker/nginx.conf`) |
| Downgrade to HTTP | HSTS (1 year, subdomains); ALB policy `TLS13-1-2-2021-06` | R |
| CORS abuse | Same-origin by default (no CORS headers at all); otherwise exactly the portal origin with credentials, never a wildcard | R (`api/lib.rs`) |
| CSV formula injection in RFQ exports | Cells starting `= + - @ \t \r` are prefixed with `'` | R + web test |
| Server-side request forgery | `SafeHttp`: https only, checks the resolved address inside the resolver (no rebinding gap), blocks private, link-local, metadata, NAT64/6to4-embedded ranges, no redirects, no proxy, size and time caps | T |

---

## 4. Identity, sessions and roles

| Credential | Where it lives | Lifetime | Notes |
|------------|----------------|----------|-------|
| Session (`bpe_s_…`) | `__Host-bpe_session` cookie: `HttpOnly; Secure; SameSite=Lax; Path=/` | `BP_SESSION_TTL_HOURS` (12 h) | Cookie only. CSRF rules apply. The only kind that counts as "a person" for approvals |
| User token (`bpe_u_…`) | Desktop app, scripts, agents | ≤ 366 days | `Authorization: Bearer` only. Optional scopes |
| Device token (`bpe_d_…`) | `.kicad_httplib` file | 90 days | `parts:read` only; cannot mint tokens |
| Boat device certificate | VM disk | ≤ 24 h | mTLS to the relay only |

Role matrix (source of truth: `crates/bp-ent-core/src/rbac.rs`; pinned by `core_boundaries::role_matrix_is_pinned`):

| Permission | org_admin | engineer | librarian | purchasing | external_reviewer |
|------------|:-:|:-:|:-:|:-:|:-:|
| parts:read | ✓ | ✓ | ✓ | ✓ | |
| parts:write | ✓ | ✓ | ✓ | | |
| parts:release | ✓ | | ✓ | | |
| boards:read | ✓ | ✓ | ✓ | ✓ | ✓ |
| boards:comment | ✓ | ✓ | ✓ | ✓ | ✓ |
| boards:write | ✓ | ✓ | | | |
| orders:read | ✓ | ✓ | | ✓ | |
| orders:write | ✓ | ✓ | | ✓ | |
| orders:approve | ✓ | | | ✓ | |
| mail:manage | ✓ | | | ✓ | |
| billing:manage | ✓ | | | | |
| vm:use | ✓ | ✓ | ✓ | | |
| vm:manage | ✓ | | | | |
| llm:use | ✓ | ✓ | ✓ | | |
| admin:manage | ✓ | | | | |
| audit:read | ✓ | | | | |

The portal's copy of this table is for showing and hiding navigation only; the server decides.

### Sign-in methods and their limits

- **OIDC** (Google Workspace, Microsoft Entra ID, any standards-compliant issuer): authorization code + PKCE + nonce.
- **SAML 2.0**: SP-initiated Web Browser SSO (Redirect request, POST response). Limits in v1.0: RSA signing certificates only (2048 bits or more; no ECDSA); no single logout; no encrypted assertions; requires https (the short-lived login-binding cookie must be `SameSite=None` to survive the IdP's cross-site POST; the session cookie stays `Lax`). The IdP must send a **persistent or e-mail NameID**: accounts are bound to the NameID at first login, so a transient NameID locks the user out the second time.
- The XML canonicalisation and signature verification for SAML are implemented in this repository (`crates/bp-ent-api/src/saml.rs`) rather than by a library. It is tested against libxml2 and OpenSSL reference output and no bypass was found in review, but it is the code in this repository most deserving of an independent review and fuzzing before SAML is relied on in production.
- There is no password login and no self-service organisation sign-up. Organisations and their first admin are created by the operator (`bp-ent-api tenant create`).

---

## 5. LLM governance and ZDR

- Org admins choose allowed providers and models. `LlmPolicy::evaluate` denies anything not listed.
- **ZDR is an optional per-org switch.** When on, only providers the admin has marked as covered by their own zero-data-retention agreement are allowed. The product cannot verify a customer's contract with their LLM vendor; the switch enforces routing, and the audit log records who set it.
- Approval gates are **on by default** for placing orders, modifying released parts or boards, enabling external MCP servers, and spend above a threshold. A request is bound to a hash of exactly what the approver saw, expires, is single-use, and cannot be approved by any token. It cannot be approved by its own requester either, unless an org admin turns on `allow_self_approval` (off by default; small teams with one approver need it, and turning it on is itself an audited policy change).
- Untrusted text (mail, chat, part descriptions, datasheet content) must be passed to models as quoted data, never concatenated into system or developer instructions. Model output is treated like user input: it goes through the same permission checks and gates as the principal it runs for.

---

## 6. Encryption at rest and key management

```
 KEK  (AWS KMS key, or self-host BP_KEK)        never in the database; wraps ↓
 DEK  (random 256-bit, one per tenant per version)  stored wrapped in tenant_keys; AAD/context = tenant ‖ version
 Data blob = "BPE1" ‖ key_version(u32) ‖ nonce(12, random) ‖ AES-256-GCM(ciphertext ‖ tag)
            GCM AAD = "bpe-env1" ‖ tenant_id ‖ key_version ‖ caller AAD ("table|row_id|field")
```

- **One shared KMS key, per-tenant data keys.** A single CMK (about $1/month in total) wraps a separate random DEK for each tenant. Tenants are still cryptographically separated: each DEK is random, its wrap is bound to the tenant by the KMS encryption context (or the local wrap's AAD), and every data blob authenticates the tenant id. Per-tenant CMKs would add a per-tenant CloudTrail and key-policy boundary but not confidentiality, at $1 per tenant per month; they are not needed for the isolation claims in this document.
- **What is sealed:** order payloads (quotes, PO documents, shipping addresses, tracking), uploaded order documents (stored sealed in PostgreSQL in v1.0, not in object storage), mail bodies, mailbox refresh tokens, IdP client secrets, in-flight PKCE verifiers, bridge secrets. **What is not:** identifiers, status, timestamps and amounts needed for queries; part library data (protected by RLS and storage encryption, not sealed).
- **Underneath:** RDS storage encryption, S3 SSE-KMS with bucket keys, Secrets Manager; TLS to the database (`rds.force_ssl`, `sslmode=require`).

### Rotation runbook

| Key | When | How | Effect |
|-----|------|-----|--------|
| Tenant DEK | Yearly, on suspected exposure, or before ~2³² seals under one version | `EnvelopeCipher::rotate_dek(tenant)` (admin route `/v1/admin/keys`) | New seals use the new version; old versions stay readable. Re-seal old rows in the background using `blob_key_version` to find them |
| AWS KMS key | Automatic yearly rotation is enabled | Nothing to do: KMS keeps old backing keys | Transparent |
| Self-host KEK | Yearly or on exposure | Set new `BP_KEK=<id>:<base64>`, move the old one to `BP_KEK_RETIRED`, deploy, run `rewrap` for every tenant, then drop the retired key | DEKs re-wrapped; data blobs untouched |
| Boat CA | Yearly or on exposure | Issue a new CA, trust both during overlap, re-issue device certs (they turn over within 24 h), remove the old CA | VMs reconnect |
| Sessions / tokens | On offboarding, role change, suspected theft | `revoke_user_tokens`; suspend user | Immediate |
| Mailbox / IdP / Stripe secrets | On staff change or exposure | Reconnect the mailbox; rotate at the provider; Stripe supports overlapping webhook secrets (any `v1` signature may match) | — |

**Crypto-shredding a tenant:** deleting the tenant's rows in `tenant_keys` (owner role) makes every sealed blob for that tenant unreadable, including in backups. Running processes keep an unwrapped key for up to 10 minutes; call `EnvelopeCipher::forget(tenant)` or restart to drop it at once.

**Secrets in logs:** secrets are carried in `Secret<T>` (redacted Debug/Display, not serialisable, zeroed on drop); key bytes have no Debug at all; upstream URLs are stripped from HTTP errors; the audit API tells callers never to put plaintext in `details`.

---

## 7. Audit log

Per-tenant, append-only hash chain: `hash = SHA-256(prev_hash, seq, time, actor, action, target, details)`. `bp_app` has only SELECT and INSERT; UPDATE, DELETE and TRUNCATE raise an error by trigger even for the owner. Entries are written in the same transaction as the change they describe, so a change cannot commit without its entry.

A database superuser can still disable the triggers. The chain makes that **detectable, not impossible**: `audit::verify_chain` recomputes it and reports the first break (`core_boundaries::audit_chain_detects_edits_and_deletions` edits and deletes rows as superuser and checks both are caught). What the chain alone cannot detect is truncation of the *tail*. For that, export the chain head (`audit::head`) on a schedule to storage the database administrator cannot write (S3 Object Lock, or a SIEM); this is listed as operator work in [§10](#10-soc-2-type-ii-control-matrix).

---

## 8. Deployment hardening

**One process.** To meet the cost ceiling the product owner set, v1.0 deploys a single `bp-ent-api serve` process that mounts every crate's routes, serves the portal bundle, and runs the Boat mTLS listener on a second port. The trade-off is blast radius: the Boat CA key, the KMS/KEK access, the Stripe key and the mail client secrets are all in one process, so a remote-code-execution bug anywhere reaches all of them. The crates remain separable (`bp-ent-relay` and `bp-ent-httplib` still build as their own binaries) for operators who prefer to split the relay and its CA key into a separate task later. Tenant isolation does not depend on the split: it is enforced in the database and by the per-tenant keys.

AWS (`infra/terraform/aws`), built to the cost ceiling the product owner set (no NAT gateway, no EKS, one shared CMK):

- Fargate tasks sit in public subnets **only because there is no NAT**; their security group accepts traffic solely from the load balancer's security group (and the NLB for Boat mTLS). There is no direct inbound path.
- RDS is in subnets with no internet route, `publicly_accessible = false`, encrypted, TLS forced, deletion-protected, 7-day backups.
- The schema-owner database URL is readable only by the one-shot migrate task's role; running services get only the `bp_app` URL.
- WAF rate-based rule on the ALB; ALB TLS policy `TLS13-1-2-2021-06`.
- S3: all public access blocked, versioned, SSE-KMS.

Self-host (`infra/docker`, `infra/helm`): Postgres and MinIO are not published; containers run as non-root with read-only root filesystems and all capabilities dropped (Helm); the default compose stack listens on plain HTTP and **must** be put behind TLS for anything but local evaluation.

Deployment findings F-3 and F-14 to F-18 are fixed; what remains open is listed in §9.

---

## 9. Findings register

Severity: **High** = can cause cross-user harm, financial harm, or loss of a stated security property; **Medium** = weakens a control or needs another flaw to exploit; **Low** = hardening.

No finding in this review breaks tenant isolation. No cross-tenant read or write path was found in any crate.

**Still open at v1.0** (all Low unless noted):

- Desktop sign-in completes without a confirmation page; the login rate limiter is per process (F-23).
- Container base images are pinned by tag, not digest (F-14).
- The idle reaper ignores traffic on long sessions; the VM provisioner is a mock and nothing in this repository starts a real VM yet (F-19).
- Organisation slugs that imitate another customer's name are not detected (reserved words are refused) (F-21).
- The SAML verifier is hand-written and has had no independent review or fuzzing (§4).
- Not exercised end to end against live or mocked third parties: mailbox OAuth connect, Microsoft Graph, SES send, the Stripe billing portal. `terraform validate` and `helm template` were not run (the tools were not installed where this review ran); `cargo deny`, `cargo audit` and the CI workflow have not run yet.
- Operator work the software cannot do: exporting the audit chain head to storage the database administrator cannot write, an encrypted remote Terraform state backend, TLS in front of the Docker Compose stack, and the organisational SOC 2 controls in §10.

| ID | Sev | Component | Finding | Status |
|----|-----|-----------|---------|--------|
| F-1 | High | relay | `started_at` is never cleared on stop, so each later stop bills from the first-ever start (customers overcharged) | Fixed, verified by review: interval starts on each start and is cleared on stop, reap and terminate |
| F-2 | High | relay | Certificate revocation/expiry and user suspension are checked only when a tunnel or desktop socket opens; live connections outlive them | Fixed, verified by review: both socket types re-check on a timer; boat sockets close at certificate expiry; revoke and delete drop the live tunnel |
| F-3 | High | relay, infra | Relay silently generates a throwaway CA when none is configured, and no deployment configures one | Fixed, verified by review: startup fails without a configured CA unless `BP_BOAT_CA_EPHEMERAL=1`; compose, Helm and Terraform supply one |
| F-4 | Med | relay | A second authorised client attaching to a VM takes over the reply stream of the first | Fixed, verified by review: a second client is refused with 409 |
| F-5 | Med | relay | mTLS listener accepts TLS 1.2; spec requires 1.3 | Fixed, verified by review: TLS 1.3 only (crate test performs the handshake) |
| F-6 | Med | httplib | KiCad endpoints served Draft / In Review / Obsolete parts, bypassing the release gate | Fixed, verified by review: Released only; `?include=draft` needs `parts:write` and a non-device token; Obsolete is always 404 |
| F-7 | Low | httplib | Unescaped LIKE wildcards in part search; 60 s per-process cache staleness; no token list/revoke route | Fixed, verified by review: wildcards escaped and query capped at 100 characters; cache TTL 5 s; token list and revoke routes added |
| F-8 | Low | relay | No WebSocket message-size limit before decode, no TLS handshake timeout or connection cap, 7-day server cert never re-issued, byte payloads as JSON arrays | Fixed, verified by review: 2 MiB message cap, 10 s handshake timeout, connection cap, base64 payloads |
| F-9 | High | relay, boat | No working certificate renewal: the agent calls an admin-only route and reads the wrong field names; the server generates VM private keys. Needs a CSR-based renewal on the mTLS listener and a one-time enrolment token | Fixed, verified by review: single-use enrolment token + CSR on first boot; CSR renewal over mTLS with the identity overwritten from the presenting certificate; private keys stay on the VM |
| F-10 | Med | api | SAML 2.0 was a placeholder returning 404 | Fixed, verified by review. SP-initiated SSO with a pinned RSA certificate; see the limits in §4 |
| F-23 | Low | api | Generic OIDC accepted a token with no `email_verified` claim; desktop sign-in has no confirmation page; login rate limiter is per process | `email_verified` now required unless the admin sets `trustEmail`: fixed. Confirmation page and shared limiter: Open |
| F-24 | — | codev | `bp-ent-codev` (board co-development backend) landed late | Reviewed, no findings: external reviewers only reach boards explicitly shared with them; snapshots are sealed; uploaded SVG is served under a sandbox CSP |
| F-11 | Med | bridges | Rate limit and an audit entry were spent on requests *before* the signature was checked, so anyone who knew a bridge's public id could exhaust its quota and grow the tenant's audit chain without a secret | Fixed, verified by review: signature first; failures use a separate bucket and at most one audit entry per bridge per minute (crate DB test) |
| F-22 | Low | bridges | Replayed deliveries answered 409 (senders retry on non-2xx); rate limiter was per process | Fixed, verified by review: replays answer 200 `duplicate`; limit also counted in PostgreSQL |
| F-12 | Low | core | AWS KMS unwrap took the key id from the database row instead of configuration | Fixed, verified by review: only configured key ids are used |
| F-13 | Low | core | Unwrapped DEKs were cached with no expiry (crypto-shred needed a restart) | Fixed, verified by review: 10-minute cache and `EnvelopeCipher::forget` (core test). Rotation cadence is documented in §6 |
| F-14 | Med | infra | Backend image falls back to an unlocked `cargo build`; base images not pinned by digest | Fixed (`--locked` only), verified by review. Base images still pinned by tag, not digest: Open (Low) |
| F-15 | High | infra | Environment variable names in compose, Helm and Terraform do not match what the services read (`BP_PUBLIC_ORIGIN`, `BP_INSECURE_COOKIES`, `BP_KEK=<id>:<b64>`, `BP_KMS_PROVIDER`/`BP_KMS_KEY_ID`), and the image is not built with the `aws-kms` feature. Fails closed, but nothing starts | Fixed, verified by review |
| F-16 | High | infra | Nothing sets the `bp_app` login password on RDS | Fixed, verified by review: `BP_APP_DB_PASSWORD` goes to the migrate task only |
| F-17 | Med | infra | Compose gives the API MinIO root credentials; Helm NetworkPolicy allow-rules have no `from`; task role KMS/S3 permissions are unconditional | Fixed, verified by review |
| F-18 | Low | infra | Edge forwards the client-supplied `X-Forwarded-For`; Terraform state holds DB passwords (needs an encrypted remote backend) | Edge now sets `X-Forwarded-For` itself: fixed. Remote encrypted state backend is an operator step (documented) |
| F-19 | Low | relay | A stopped VM that dials in is flipped back to `running`; idle reaper ignores traffic on long sessions; mock provisioner and no-op meter are the defaults | Tunnel refused unless the VM is provisioning or running: fixed. Mock provisioner and no-op meter remain the defaults until bp-ent-api wires real ones: Open |
| F-20 | Low | orders | Outbound client for fixed provider hosts was not `https_only` | Fixed, verified by review: `https_only` in production; plain http only for a configured loopback test base (crate test) |
| F-21 | Low | core | Tenants could register look-alike or reserved slugs | Reserved slugs (`admin`, `api`, `login`, …) are refused: fixed, verified by review. Look-alikes of another customer's name are not detected |
| W-1 | Med | web | CSP allowed connections to any HTTPS host; two diverging nginx configs | Fixed, verified |
| W-2 | Med | web | Demo "sandbox" with invented encrypted orders and audit entries shipped in production builds | Fixed, verified (off unless `VITE_ENABLE_SANDBOX=1`, permanent banner) |
| W-3 | Low | web | Image build fell back to `npm install`; dev-dependency advisories; client URL check blocked private IdPs | Fixed (lockfile-only build verified; dependency bump not re-audited) |
| W-4 | Low | web | Portal's role table differed from the server's (display only) | Fixed, verified by review: fallback table matches `rbac.rs`; `/v1/me` permissions take precedence |

---

## 10. SOC 2 Type II control matrix

What the software provides, where the evidence is, and what the operator still has to do. SOC 2 is an audit of an *organisation over time*; code can supply controls and evidence, not the report.

| TSC | Criterion (short) | Control in this repository | Evidence | Operator must add |
|-----|-------------------|----------------------------|----------|-------------------|
| CC1–CC5 | Governance, risk, monitoring of controls | This threat model and findings register | `docs/SECURITY.md`, CI history | Policies, risk register, management review, staff training |
| CC6.1 | Logical access to information assets | SSO only; role matrix; scopes; RLS; deny by default | `rbac.rs`, `0001_core.sql`, `bp-ent-sectest` results | Access policy |
| CC6.1 | Encryption of data at rest | Envelope encryption; RDS/S3/Secrets encryption | `crypto.rs`, Terraform | Key ceremony record for self-host KEK |
| CC6.2 | Provisioning of users | IdP-driven; auto-provision off by default; default role never admin | `identity_providers` schema, audit entries | Joiner process in the IdP |
| CC6.3 | Role changes and removal | Suspend → immediate loss of access; token revocation; audit entry | `core_boundaries::suspended_user…`, audit log | Quarterly access review using `/v1/admin/users` + audit export |
| CC6.6 | Protection against threats from outside the boundary | TLS 1.3 edge; WAF rate rule; no public DB/VM ports; mTLS for VMs; CSRF, CSP, HSTS | Terraform, `nginx.conf`, tests | Pen test; WAF tuning |
| CC6.7 | Data in transit and movement | TLS everywhere; `rds.force_ssl`; `SafeHttp` for outbound; `no-store` on tenant data | Terraform, `safehttp.rs` | DLP for exports if required |
| CC6.8 | Prevention of malicious software | Uploaded documents never rendered; mail reduced to text; attachments not executed | `orders/routes.rs`, `mail/sanitize.rs` | Malware scan of stored documents if required |
| CC7.1 | Vulnerability detection | `cargo deny`, `cargo audit`, `npm audit`, trivy, gitleaks, daily schedule | `.github/workflows/security.yml` | Triage SLA; patch records |
| CC7.2 | Monitoring for anomalies | Structured JSON logs with request ids; audit log; CloudWatch | Logs | Alerting rules; SIEM; on-call |
| CC7.3–7.5 | Incident evaluation, response, recovery | Tamper-evident audit trail; token and certificate revocation; crypto-shred; key rotation runbook | §6, §7 | Incident response plan; tabletop exercises; breach notification process |
| CC8.1 | Change management | Migrations fail if a table is not isolated; isolation suite in CI; lockfile builds; SBOM per build | `db::verify_isolation`, CI | Branch protection, required reviews, deploy approvals |
| CC9.2 | Vendor risk | Outbound vendors are few and explicit (AWS, Stripe, Google, Microsoft, the customer's LLM vendor); least-privilege OAuth scopes | `mail/oauth.rs`, §5 | Vendor reviews; DPAs |
| A1.1–A1.3 | Availability, backup, recovery | RDS backups (7 d) + deletion protection; S3 versioning; stateless services; idle VM stop | Terraform | Restore test at least yearly; RTO/RPO; multi-AZ if required |
| C1.1 | Identify and protect confidential information | Tenant isolation (§2); sealing of order and mail data; private caching rules | §2, §6, tests | Data classification policy |
| C1.2 | Disposal of confidential information | Tenant delete cascades; crypto-shred by deleting DEKs; token purge | Schema `ON DELETE CASCADE`, §6 | Retention schedule; backup expiry |
| PI1 | Processing integrity | Order state machine; approvals bound to what was shown; payment bound to order and amount; idempotent metering; webhook dedupe | `orders/status.rs`, `billing.rs`, `policy.rs` | Reconciliation of Stripe to the order ledger (and fix F-1 first) |
| P1–P8 | Privacy | Minimal personal data (name, e-mail); e-mail kept out of logs; mail content sealed; ZDR switch for LLM routing | `rbac.rs` Debug, §5 | Privacy notice, DSAR process, DPA, sub-processor list |

Evidence an auditor can pull directly from a running system: the audit log and its chain verification; `tenant_keys` (key versions and KEK ids, no key material); CI runs of the isolation suite; SBOM artifacts; Terraform plan/state for the infrastructure controls.

---

## 11. Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting on this repository (Security → Report a vulnerability) if the maintainers have enabled it; otherwise contact the maintainers privately first. Include the affected version or commit, steps to reproduce, and the impact you believe it has. Cross-tenant data exposure, authentication bypass, and key or token disclosure are treated as critical.

---

## 12. Running the security suite

```sh
# any throwaway PostgreSQL 16 with a superuser URL
docker run -d --name bpe-sectest-pg -e POSTGRES_PASSWORD=sectest -p 127.0.0.1:55433:5432 postgres:16-alpine
export BP_TEST_ADMIN_DATABASE_URL=postgres://postgres:sectest@127.0.0.1:55433/postgres
export BP_TEST_REQUIRE_DB=1        # fail instead of skipping when the database is missing
cargo test -p bp-ent-sectest
```

The suite creates and drops its own databases. It applies every crate's migrations, then acts as `bp_app`. Add a table and it is audited; add a role or permission and `role_matrix_is_pinned` must be updated on purpose.
