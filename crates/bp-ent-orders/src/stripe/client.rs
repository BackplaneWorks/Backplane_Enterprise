//! Minimal Stripe REST client (form-encoded, `reqwest` + rustls).
//!
//! Only the handful of calls this crate needs: Checkout Sessions, Billing
//! Portal sessions, customers and billing meter events. The host is fixed
//! (`api.stripe.com`); nothing a tenant supplies ever becomes part of the
//! URL host or path. Redirects are refused, every mutating call carries an
//! `Idempotency-Key`, and the API key never appears in errors or logs.

use bp_ent_core::Secret;
use serde::Deserialize;
use std::time::Duration;

pub const STRIPE_API_BASE: &str = "https://api.stripe.com";
const STRIPE_VERSION: &str = "2025-03-31.basil";

#[derive(Debug, thiserror::Error)]
pub enum StripeError {
    #[error("stripe is not configured")]
    NotConfigured,
    #[error("stripe request failed")]
    Transport,
    /// Stripe answered with an error. Only the machine-readable code is kept.
    #[error("stripe rejected the request ({status}{})", code.as_deref().map(|c| format!(", {c}")).unwrap_or_default())]
    Api { status: u16, code: Option<String> },
    #[error("unexpected stripe response")]
    Decode,
}

#[derive(Clone)]
pub struct StripeClient {
    http: reqwest::Client,
    base: String,
    key: Secret<String>,
}

#[derive(Debug, Deserialize)]
pub struct CheckoutSession {
    pub id: String,
    pub url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PortalSession {
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct Customer {
    pub id: String,
}

/// What a Checkout Session is for.
pub enum Checkout<'a> {
    /// Seat subscription, optionally with the metered Boat VM-hour price.
    Subscription {
        seat_price: &'a str,
        seats: u32,
        vm_hour_price: Option<&'a str>,
    },
    /// One-off payment of an approved order.
    OrderPayment {
        amount_cents: i64,
        currency: &'a str,
        order_ref: &'a str,
        order_id: uuid::Uuid,
    },
}

pub struct CheckoutParams<'a> {
    pub tenant_id: uuid::Uuid,
    pub customer: &'a str,
    pub success_url: &'a str,
    pub cancel_url: &'a str,
    pub idempotency_key: &'a str,
    pub what: Checkout<'a>,
}

impl StripeClient {
    pub fn new(key: Secret<String>) -> Result<Self, StripeError> {
        Self::with_base(key, STRIPE_API_BASE)
    }

    /// `base` is configuration, not request data. Anything but https is
    /// refused unless it is a loopback address (tests, stripe-mock).
    pub fn with_base(key: Secret<String>, base: &str) -> Result<Self, StripeError> {
        let url = url::Url::parse(base).map_err(|_| StripeError::NotConfigured)?;
        let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
        if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
            return Err(StripeError::NotConfigured);
        }
        if key.expose().is_empty() {
            return Err(StripeError::NotConfigured);
        }
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .connect_timeout(Duration::from_secs(5))
            .https_only(!loopback)
            .user_agent("backplane-enterprise")
            .build()
            .map_err(|_| StripeError::Transport)?;
        Ok(Self { http, base: base.trim_end_matches('/').to_string(), key })
    }

    async fn post<T: for<'de> Deserialize<'de>>(
        &self,
        path: &'static str,
        form: &[(String, String)],
        idempotency_key: &str,
    ) -> Result<T, StripeError> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        let resp = self
            .http
            .post(format!("{}{}", self.base, path))
            .bearer_auth(self.key.expose())
            .header("Stripe-Version", STRIPE_VERSION)
            .header("Idempotency-Key", idempotency_key)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            // reqwest errors can embed the URL; drop them entirely.
            .map_err(|_| StripeError::Transport)?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|_| StripeError::Transport)?;
        if !status.is_success() {
            #[derive(Deserialize)]
            struct Env {
                error: Option<Inner>,
            }
            #[derive(Deserialize)]
            struct Inner {
                code: Option<String>,
                r#type: Option<String>,
            }
            let code = serde_json::from_slice::<Env>(&bytes)
                .ok()
                .and_then(|e| e.error)
                .and_then(|e| e.code.or(e.r#type))
                .filter(|c| c.len() <= 64 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
            return Err(StripeError::Api { status: status.as_u16(), code });
        }
        serde_json::from_slice(&bytes).map_err(|_| StripeError::Decode)
    }

    /// Create the Stripe customer for a tenant. The tenant id goes into the
    /// customer metadata; no e-mail or name is sent unless given.
    pub async fn create_customer(
        &self,
        tenant_id: uuid::Uuid,
        name: Option<&str>,
        email: Option<&str>,
    ) -> Result<Customer, StripeError> {
        let mut form = vec![("metadata[tenant_id]".to_string(), tenant_id.to_string())];
        if let Some(n) = name {
            form.push(("name".into(), n.to_string()));
        }
        if let Some(e) = email {
            form.push(("email".into(), e.to_string()));
        }
        self.post("/v1/customers", &form, &format!("bpe-cust-{tenant_id}")).await
    }

    pub async fn create_checkout(&self, p: CheckoutParams<'_>) -> Result<CheckoutSession, StripeError> {
        let form = checkout_form(&p);
        self.post("/v1/checkout/sessions", &form, p.idempotency_key).await
    }

    pub async fn create_portal_session(
        &self,
        customer: &str,
        return_url: &str,
        idempotency_key: &str,
    ) -> Result<PortalSession, StripeError> {
        let form = vec![
            ("customer".to_string(), customer.to_string()),
            ("return_url".to_string(), return_url.to_string()),
        ];
        self.post("/v1/billing_portal/sessions", &form, idempotency_key).await
    }

    /// Report metered usage. `identifier` makes the event idempotent on
    /// Stripe's side (a repeat within 24 h is rejected as a duplicate, which
    /// we treat as success).
    pub async fn meter_event(
        &self,
        event_name: &str,
        customer: &str,
        value: u64,
        identifier: &str,
        timestamp: i64,
    ) -> Result<(), StripeError> {
        let form = vec![
            ("event_name".to_string(), event_name.to_string()),
            ("payload[stripe_customer_id]".to_string(), customer.to_string()),
            ("payload[value]".to_string(), value.to_string()),
            ("identifier".to_string(), identifier.to_string()),
            ("timestamp".to_string(), timestamp.to_string()),
        ];
        match self
            .post::<serde_json::Value>("/v1/billing/meter_events", &form, &format!("bpe-meter-{identifier}"))
            .await
        {
            Ok(_) => Ok(()),
            Err(StripeError::Api { status: 400, code: Some(c) }) if c.contains("duplicate") || c == "resource_already_exists" => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Form fields for a Checkout Session. Separate from the HTTP call so the
/// exact parameters are unit-tested.
pub fn checkout_form(p: &CheckoutParams<'_>) -> Vec<(String, String)> {
    let tenant = p.tenant_id.to_string();
    let mut f: Vec<(String, String)> = vec![
        ("customer".into(), p.customer.into()),
        ("success_url".into(), p.success_url.into()),
        ("cancel_url".into(), p.cancel_url.into()),
        ("client_reference_id".into(), tenant.clone()),
        // The webhook finds the tenant here: it is part of the signed event.
        ("metadata[tenant_id]".into(), tenant.clone()),
    ];
    match &p.what {
        Checkout::Subscription { seat_price, seats, vm_hour_price } => {
            f.push(("mode".into(), "subscription".into()));
            f.push(("metadata[purpose]".into(), "seats".into()));
            f.push(("line_items[0][price]".into(), (*seat_price).into()));
            f.push(("line_items[0][quantity]".into(), seats.to_string()));
            if let Some(vm) = vm_hour_price {
                // Metered prices take no quantity.
                f.push(("line_items[1][price]".into(), (*vm).into()));
            }
            f.push(("subscription_data[metadata][tenant_id]".into(), tenant));
        }
        Checkout::OrderPayment { amount_cents, currency, order_ref, order_id } => {
            f.push(("mode".into(), "payment".into()));
            f.push(("metadata[purpose]".into(), "order".into()));
            f.push(("metadata[order_id]".into(), order_id.to_string()));
            f.push(("line_items[0][quantity]".into(), "1".into()));
            f.push(("line_items[0][price_data][currency]".into(), currency.to_ascii_lowercase()));
            f.push(("line_items[0][price_data][unit_amount]".into(), amount_cents.to_string()));
            // Only the random reference goes to Stripe: no board name, no line items.
            f.push(("line_items[0][price_data][product_data][name]".into(), format!("Order {order_ref}")));
            f.push(("payment_intent_data[metadata][tenant_id]".into(), tenant));
            f.push(("payment_intent_data[metadata][order_id]".into(), order_id.to_string()));
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get<'a>(f: &'a [(String, String)], k: &str) -> Option<&'a str> {
        f.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str())
    }

    #[test]
    fn order_checkout_binds_tenant_and_order_and_leaks_no_detail() {
        let tenant = uuid::Uuid::new_v4();
        let order = uuid::Uuid::new_v4();
        let f = checkout_form(&CheckoutParams {
            tenant_id: tenant,
            customer: "cus_1",
            success_url: "https://portal.example.com/orders",
            cancel_url: "https://portal.example.com/orders",
            idempotency_key: "k",
            what: Checkout::OrderPayment { amount_cents: 12_345, currency: "USD", order_ref: "BP-0123456789", order_id: order },
        });
        assert_eq!(get(&f, "mode"), Some("payment"));
        assert_eq!(get(&f, "metadata[tenant_id]"), Some(tenant.to_string().as_str()));
        assert_eq!(get(&f, "metadata[order_id]"), Some(order.to_string().as_str()));
        assert_eq!(get(&f, "payment_intent_data[metadata][tenant_id]"), Some(tenant.to_string().as_str()));
        assert_eq!(get(&f, "line_items[0][price_data][unit_amount]"), Some("12345"));
        assert_eq!(get(&f, "line_items[0][price_data][currency]"), Some("usd"));
        assert_eq!(get(&f, "line_items[0][price_data][product_data][name]"), Some("Order BP-0123456789"));
    }

    #[test]
    fn subscription_checkout_has_seats_and_metered_price() {
        let tenant = uuid::Uuid::new_v4();
        let f = checkout_form(&CheckoutParams {
            tenant_id: tenant,
            customer: "cus_1",
            success_url: "https://p/x",
            cancel_url: "https://p/x",
            idempotency_key: "k",
            what: Checkout::Subscription { seat_price: "price_seat", seats: 7, vm_hour_price: Some("price_vm") },
        });
        assert_eq!(get(&f, "mode"), Some("subscription"));
        assert_eq!(get(&f, "line_items[0][quantity]"), Some("7"));
        assert_eq!(get(&f, "line_items[1][price]"), Some("price_vm"));
        assert_eq!(get(&f, "line_items[1][quantity]"), None);
        assert_eq!(get(&f, "subscription_data[metadata][tenant_id]"), Some(tenant.to_string().as_str()));
    }

    #[test]
    fn refuses_plain_http_and_empty_key() {
        let key = || Secret::new("sk_test_x".to_string());
        assert!(StripeClient::with_base(key(), "http://api.stripe.com").is_err());
        assert!(StripeClient::with_base(key(), "http://169.254.169.254").is_err());
        assert!(StripeClient::with_base(key(), "ftp://x").is_err());
        assert!(StripeClient::with_base(Secret::new(String::new()), STRIPE_API_BASE).is_err());
        assert!(StripeClient::with_base(key(), "http://127.0.0.1:12111").is_ok());
        assert!(StripeClient::new(key()).is_ok());
    }

    #[test]
    fn errors_do_not_carry_the_key() {
        let e = StripeError::Api { status: 402, code: Some("card_declined".into()) };
        assert_eq!(e.to_string(), "stripe rejected the request (402, card_declined)");
    }
}
