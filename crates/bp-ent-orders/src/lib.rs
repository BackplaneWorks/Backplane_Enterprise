//! Backplane Enterprise encrypted ordering, order mail and billing.
//!
//! - [`status`]: the order state machine.
//! - [`orders`], [`documents`], [`bom`]: the envelope-encrypted ledger.
//! - [`mail`]: Gmail / Microsoft Graph connectors, sanitiser, status parser.
//! - [`mailbox`]: connecting mailboxes, syncing order mail, notifications.
//! - [`stripe`], [`billing`]: checkout, billing portal, metering, webhooks.
//! - [`routes`]: the Axum routes mounted by `bp-ent-api`.

#![forbid(unsafe_code)]

pub mod billing;
pub mod bom;
pub mod config;
pub mod documents;
pub mod mail;
pub mod mailbox;
pub mod model;
pub mod net;
pub mod orders;
pub mod routes;
pub mod sealed;
pub mod status;
pub mod stripe;

use bp_ent_core::AppCtx;
use std::sync::Arc;

pub use config::OrdersConfig;

/// Service state shared by every handler and background job in this crate.
#[derive(Clone)]
pub struct Svc {
    pub ctx: AppCtx,
    pub cfg: Arc<OrdersConfig>,
    /// Client for the fixed vendor APIs (see [`net`]).
    pub http: reqwest::Client,
    pub stripe: Option<stripe::client::StripeClient>,
}

impl Svc {
    pub fn new(ctx: AppCtx, cfg: OrdersConfig) -> Self {
        let stripe = cfg.stripe_secret_key.clone().and_then(|key| {
            let base = cfg.stripe_api_base.as_deref().unwrap_or(stripe::client::STRIPE_API_BASE);
            match stripe::client::StripeClient::with_base(key, base) {
                Ok(c) => Some(c),
                Err(_) => {
                    tracing::error!("Stripe is configured with an invalid API base; billing is disabled");
                    None
                }
            }
        });
        // Base overrides exist for tests against a loopback mock; without
        // them the client refuses anything that is not https.
        let overridden = [&cfg.gmail_api_base, &cfg.graph_api_base, &cfg.google_token_base, &cfg.microsoft_token_base]
            .iter()
            .any(|b| b.is_some());
        Self { ctx, cfg: Arc::new(cfg), http: net::client(!overridden), stripe }
    }
}

/// Routes for `/v1/orders`, `/v1/mail`, `/v1/billing` (authenticated) and
/// `/v1/webhooks/stripe` (signature-verified), configured from the
/// environment.
pub fn router(ctx: AppCtx) -> axum::Router {
    routes::router(Svc::new(ctx, OrdersConfig::from_env()))
}

/// This crate's migrations (0300-0399). Run after core's.
pub fn migrator() -> sqlx::migrate::Migrator {
    sqlx::migrate!("./migrations")
}
