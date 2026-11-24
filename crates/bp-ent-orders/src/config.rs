//! Configuration for ordering, mail and billing. All optional: a feature
//! whose settings are missing answers "not configured" instead of failing
//! the whole service.

use bp_ent_core::Secret;

pub struct OrdersConfig {
    /// Stripe secret API key (`sk_...`).
    pub stripe_secret_key: Option<Secret<String>>,
    /// Stripe webhook endpoint secret (`whsec_...`).
    pub stripe_webhook_secret: Option<Secret<String>>,
    /// Override for tests / stripe-mock. Defaults to `https://api.stripe.com`.
    pub stripe_api_base: Option<String>,
    /// Price id of the per-seat subscription.
    pub stripe_seat_price: Option<String>,
    /// Price id of the metered Boat VM usage price.
    pub stripe_vm_price: Option<String>,
    /// Billing meter event name for Boat VM minutes.
    pub stripe_vm_meter_event: String,
    /// Display-only prices for the billing summary estimate.
    pub seat_price_cents: i64,
    pub vm_hour_price_cents: i64,
    pub plan_name: String,

    pub google_client_id: Option<String>,
    pub google_client_secret: Option<Secret<String>>,
    pub microsoft_client_id: Option<String>,
    pub microsoft_client_secret: Option<Secret<String>>,
    /// Entra tenant segment (`common`, `organizations` or a directory id).
    pub microsoft_tenant: String,
    /// Overrides for tests.
    pub gmail_api_base: Option<String>,
    pub graph_api_base: Option<String>,
    pub google_token_base: Option<String>,
    pub microsoft_token_base: Option<String>,

    /// SES fallback sender.
    pub ses_region: Option<String>,
    pub ses_from: Option<String>,
}

fn opt(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn secret(name: &str) -> Option<Secret<String>> {
    opt(name).map(Secret::new)
}

impl Default for OrdersConfig {
    fn default() -> Self {
        Self {
            stripe_secret_key: None,
            stripe_webhook_secret: None,
            stripe_api_base: None,
            stripe_seat_price: None,
            stripe_vm_price: None,
            stripe_vm_meter_event: "boat_vm_minutes".into(),
            seat_price_cents: 0,
            vm_hour_price_cents: 0,
            plan_name: "Backplane Enterprise".into(),
            google_client_id: None,
            google_client_secret: None,
            microsoft_client_id: None,
            microsoft_client_secret: None,
            microsoft_tenant: "common".into(),
            gmail_api_base: None,
            graph_api_base: None,
            google_token_base: None,
            microsoft_token_base: None,
            ses_region: None,
            ses_from: None,
        }
    }
}

impl OrdersConfig {
    /// Environment:
    /// - `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_SEAT_PRICE_ID`,
    ///   `STRIPE_VM_PRICE_ID`, `STRIPE_VM_METER_EVENT` (default `boat_vm_minutes`)
    /// - `BP_SEAT_PRICE_CENTS`, `BP_VM_HOUR_PRICE_CENTS`, `BP_PLAN_NAME` (display only)
    /// - `GOOGLE_MAIL_CLIENT_ID`, `GOOGLE_MAIL_CLIENT_SECRET`
    /// - `MICROSOFT_MAIL_CLIENT_ID`, `MICROSOFT_MAIL_CLIENT_SECRET`, `MICROSOFT_MAIL_TENANT`
    /// - `BP_SES_REGION`, `BP_SES_FROM`
    pub fn from_env() -> Self {
        let d = Self::default();
        Self {
            stripe_secret_key: secret("STRIPE_SECRET_KEY"),
            stripe_webhook_secret: secret("STRIPE_WEBHOOK_SECRET"),
            stripe_api_base: opt("STRIPE_API_BASE"),
            stripe_seat_price: opt("STRIPE_SEAT_PRICE_ID"),
            stripe_vm_price: opt("STRIPE_VM_PRICE_ID"),
            stripe_vm_meter_event: opt("STRIPE_VM_METER_EVENT").unwrap_or(d.stripe_vm_meter_event),
            seat_price_cents: opt("BP_SEAT_PRICE_CENTS").and_then(|v| v.parse().ok()).unwrap_or(0),
            vm_hour_price_cents: opt("BP_VM_HOUR_PRICE_CENTS").and_then(|v| v.parse().ok()).unwrap_or(0),
            plan_name: opt("BP_PLAN_NAME").unwrap_or(d.plan_name),
            google_client_id: opt("GOOGLE_MAIL_CLIENT_ID"),
            google_client_secret: secret("GOOGLE_MAIL_CLIENT_SECRET"),
            microsoft_client_id: opt("MICROSOFT_MAIL_CLIENT_ID"),
            microsoft_client_secret: secret("MICROSOFT_MAIL_CLIENT_SECRET"),
            microsoft_tenant: opt("MICROSOFT_MAIL_TENANT").unwrap_or(d.microsoft_tenant),
            gmail_api_base: None,
            graph_api_base: None,
            google_token_base: None,
            microsoft_token_base: None,
            ses_region: opt("BP_SES_REGION"),
            ses_from: opt("BP_SES_FROM"),
        }
    }
}
