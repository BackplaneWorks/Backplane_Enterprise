# bp-ent-orders

Encrypted ordering, order mail and Stripe billing for Backplane Enterprise.

## What it does

- **Order ledger.** `draft → quote_requested → pending_approval → ordered → in_fabrication → shipped → delivered`, plus `on_hold` and `cancelled`. One state machine (`src/status.rs`) decides every change; who is asking decides which steps are open.
- **Encryption at rest.** Titles, line items, amounts, quotes, addresses, customer contacts, tracking, mail content, documents and OAuth refresh tokens are sealed with the tenant's key (`bp_ent_core` envelope encryption) before they reach PostgreSQL. Each blob is bound to its tenant, table, row and column.
- **Mail.** Gmail API and Microsoft Graph connectors (OAuth code + PKCE). Inbound mail is reduced to bounded plain text and parsed by fixed rules into a status *proposal*.
- **Stripe.** Seat subscription checkout, billing portal, order payment checkout, Boat VM usage meter events, and a signature-verified webhook.

## Routes

Mounted by `bp-ent-api` through `bp_ent_orders::router(ctx)`. JSON is camelCase.

| Route | Permission |
|---|---|
| `GET/POST /v1/orders`, `GET/PATCH /v1/orders/{id}` | `orders:read` / `orders:write` |
| `POST /v1/orders/{id}/transition` `{state, note?}` | `orders:write`; `→ ordered` needs `orders:approve` and the `place_order` gate. `202` = waiting for an approver or for payment |
| `GET /v1/orders/{id}/events`, `/mail`, `/documents`; `POST /documents`; `GET /documents/{doc}` | `orders:read` / `orders:write` |
| `GET/PUT /v1/orders/bom/{board}`, `POST /v1/orders/bom/lines/{line}/swap` `{mpn}` | `orders:read` / `orders:write` |
| `GET /v1/mail/connectors`, `DELETE /v1/mail/connectors/{id}`, `POST …/{id}/sync` | `mail:manage` |
| `POST /v1/mail/connect/{google\|microsoft}` → `{authorizeUrl}`; `GET /v1/mail/callback/{provider}` | `mail:manage`, browser session |
| `GET /v1/mail/events`, `POST /v1/mail/events/{id}/apply` | `mail:manage` / `orders:write` |
| `POST /v1/mail/orders/{id}/notify` `{message?}` | `orders:write` |
| `GET /v1/billing/summary`, `POST /v1/billing/checkout` `{seats}`, `POST /v1/billing/portal`, `POST /v1/billing/usage/flush` | `billing:manage` |
| `POST /v1/billing/orders/{id}/checkout` → `{checkoutUrl}` | `orders:approve`, browser session |
| `POST /v1/webhooks/stripe` | Stripe signature |

## Background jobs

The API's scheduler should call these on a timer:

- `mailbox::sync_all(&svc)`: pull new order mail for every connected mailbox.
- `billing::flush_all_usage(&svc)`: report unreported VM usage to Stripe.

Each finished VM run is recorded with `billing::record_vm_usage(&mut tx, tenant, &VmUsage { .. })`, or `billing::record_vm_usage_for(&svc, tenant, &usage)` outside a transaction. The API adapts the relay's `UsageMeterSink` to the latter.

## Configuration

All optional; a feature without its settings answers "not configured".

| Variable | Purpose |
|---|---|
| `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` | Stripe API key and webhook endpoint secret |
| `STRIPE_SEAT_PRICE_ID`, `STRIPE_VM_PRICE_ID` | Seat price and metered VM price |
| `STRIPE_VM_METER_EVENT` | Meter event name (default `boat_vm_minutes`; the value is whole minutes, rounded up per run) |
| `BP_SEAT_PRICE_CENTS`, `BP_VM_HOUR_PRICE_CENTS`, `BP_PLAN_NAME` | Display-only figures for the billing summary |
| `GOOGLE_MAIL_CLIENT_ID`, `GOOGLE_MAIL_CLIENT_SECRET` | Gmail connector OAuth client |
| `MICROSOFT_MAIL_CLIENT_ID`, `MICROSOFT_MAIL_CLIENT_SECRET`, `MICROSOFT_MAIL_TENANT` | Microsoft 365 connector OAuth client |
| `BP_SES_REGION`, `BP_SES_FROM` | AWS SES sender used when no mailbox is connected |

OAuth redirect URI to register with Google and Microsoft: `<BP_API_BASE_URL>/v1/mail/callback/google` and `…/microsoft`. Stripe webhook events to enable: `checkout.session.completed`, `checkout.session.async_payment_succeeded`, `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`.

## Security rules this crate holds to

- The tenant comes from the verified `Principal`, or for the webhook from metadata this server put on the Stripe object. Never from a path, query or body.
- Inbound mail is untrusted. It is never rendered, executed or given to an LLM. Only mail naming one of the tenant's own order references is stored. It moves an order automatically only if it comes from the order's vendor domain with DMARC pass reported by the mailbox provider, and then only forward along fulfilment of an already placed order. Mail can never approve, place, hold or cancel.
- A payment places an order only if the order was approved and the Stripe session id, amount and currency match what was stored when checkout was opened. Each event id is processed once.
- Attachment bytes are not downloaded. Uploaded documents are served only as opaque downloads.
- Outbound calls go to fixed vendor hosts over https, without redirects, with size caps. Errors and logs carry no tokens, URLs or message content.

## Tests

```
cargo test -p bp-ent-orders
BP_TEST_ADMIN_DATABASE_URL=postgres://postgres:<pw>@127.0.0.1:<port>/postgres cargo test -p bp-ent-orders
```

The second form also runs the live-PostgreSQL tests (as the `bp_app` role, under row-level security). Without the variable they skip; `BP_TEST_REQUIRE_DB=1` makes that a failure.
