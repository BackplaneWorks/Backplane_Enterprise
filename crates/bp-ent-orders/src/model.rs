//! Request / response shapes and the sealed payloads.
//!
//! JSON is camelCase to match the web portal (`web/src/types/domain.ts`).

use crate::mail::parser::Tracking;
use crate::status::OrderStatus;
use bp_ent_core::{Error, Result};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

pub const MAX_LINE_ITEMS: usize = 500;
pub const MAX_AMOUNT_CENTS: i64 = 1_000_000_000_000;
pub const MAX_DOCUMENT_BYTES: usize = 5 * 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LineItem {
    pub description: String,
    #[serde(default)]
    pub mpn: String,
    pub quantity: u32,
    pub unit_cents: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Address {
    pub name: String,
    #[serde(default)]
    pub company: String,
    pub line1: String,
    #[serde(default)]
    pub line2: String,
    pub city: String,
    #[serde(default)]
    pub region: String,
    pub postal_code: String,
    /// ISO 3166-1 alpha-2.
    pub country: String,
    #[serde(default)]
    pub phone: String,
}

/// Everything sensitive about an order. Stored only as envelope ciphertext
/// in `orders.sealed`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OrderPayload {
    pub title: String,
    pub board_name: String,
    pub quantity: u32,
    pub currency: String,
    pub total_cents: i64,
    pub line_items: Vec<LineItem>,
    pub vendor_name: String,
    /// The vendor's own order / quote number.
    pub vendor_reference: String,
    pub quote_notes: String,
    pub shipping_address: Option<Address>,
    /// Where status updates go, if the customer wants them.
    pub customer_email: Option<String>,
    pub tracking: Option<Tracking>,
    /// Collect payment through Stripe Checkout before the order is placed.
    pub payment_required: bool,
}

/// Fields a caller may set when creating or editing an order.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrderInput {
    pub title: Option<String>,
    pub board_name: Option<String>,
    pub quantity: Option<u32>,
    pub currency: Option<String>,
    pub total_cents: Option<i64>,
    pub line_items: Option<Vec<LineItem>>,
    pub vendor_name: Option<String>,
    pub vendor_domain: Option<String>,
    pub fab_reference: Option<String>,
    pub quote_notes: Option<String>,
    pub shipping_address: Option<Address>,
    pub customer_email: Option<String>,
    pub tracking_number: Option<String>,
    pub payment_required: Option<bool>,
    /// For edits: the version the caller last read.
    pub version: Option<i32>,
}

fn text(v: &str, max: usize, what: &str) -> Result<String> {
    let t = v.trim();
    if t.len() > max || t.chars().any(|c| c.is_control() && c != '\n') {
        return Err(Error::invalid(format!("{what} is too long or has control characters")));
    }
    Ok(t.to_string())
}

impl Address {
    fn validated(&self) -> Result<Address> {
        let country = self.country.trim().to_ascii_uppercase();
        if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(Error::invalid("country must be a two-letter code"));
        }
        Ok(Address {
            name: text(&self.name, 200, "name")?,
            company: text(&self.company, 200, "company")?,
            line1: text(&self.line1, 200, "address line")?,
            line2: text(&self.line2, 200, "address line")?,
            city: text(&self.city, 100, "city")?,
            region: text(&self.region, 100, "region")?,
            postal_code: text(&self.postal_code, 20, "postal code")?,
            country,
            phone: text(&self.phone, 40, "phone")?,
        })
    }
}

impl OrderPayload {
    /// Apply validated input on top of the current payload. Returns the new
    /// vendor domain if the input set one (`Some(None)` clears it).
    pub fn apply(&mut self, i: &OrderInput) -> Result<Option<Option<String>>> {
        if let Some(v) = &i.title {
            self.title = text(v, 200, "title")?;
        }
        if let Some(v) = &i.board_name {
            self.board_name = text(v, 200, "board name")?;
        }
        if let Some(q) = i.quantity {
            if !(1..=10_000_000).contains(&q) {
                return Err(Error::invalid("quantity must be between 1 and 10,000,000"));
            }
            self.quantity = q;
        }
        if let Some(c) = &i.currency {
            let c = c.trim().to_ascii_uppercase();
            if c.len() != 3 || !c.bytes().all(|b| b.is_ascii_uppercase()) {
                return Err(Error::invalid("currency must be a three-letter code"));
            }
            self.currency = c;
        }
        if let Some(items) = &i.line_items {
            if items.len() > MAX_LINE_ITEMS {
                return Err(Error::invalid("too many line items"));
            }
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                if !(0..=MAX_AMOUNT_CENTS).contains(&it.unit_cents) || it.quantity == 0 {
                    return Err(Error::invalid("line item quantity or price is out of range"));
                }
                out.push(LineItem {
                    description: text(&it.description, 500, "line description")?,
                    mpn: text(&it.mpn, 120, "MPN")?,
                    quantity: it.quantity,
                    unit_cents: it.unit_cents,
                });
            }
            self.line_items = out;
        }
        if let Some(t) = i.total_cents {
            self.total_cents = t;
        } else if i.line_items.is_some() && !self.line_items.is_empty() {
            self.total_cents = self
                .line_items
                .iter()
                .try_fold(0i64, |acc, it| acc.checked_add(it.unit_cents.checked_mul(i64::from(it.quantity))?))
                .ok_or_else(|| Error::invalid("order total is out of range"))?;
        }
        if !(0..=MAX_AMOUNT_CENTS).contains(&self.total_cents) {
            return Err(Error::invalid("order total is out of range"));
        }
        if let Some(v) = &i.vendor_name {
            self.vendor_name = text(v, 200, "vendor name")?;
        }
        if let Some(v) = &i.fab_reference {
            self.vendor_reference = text(v, 120, "vendor reference")?;
        }
        if let Some(v) = &i.quote_notes {
            self.quote_notes = text(v, 8000, "notes")?;
        }
        if let Some(a) = &i.shipping_address {
            self.shipping_address = Some(a.validated()?);
        }
        if let Some(e) = &i.customer_email {
            self.customer_email = if e.trim().is_empty() {
                None
            } else {
                Some(crate::mail::validate_address(e).ok_or_else(|| Error::invalid("customer e-mail is not a valid address"))?)
            };
        }
        if let Some(t) = &i.tracking_number {
            let n: String = t.trim().to_ascii_uppercase();
            self.tracking = if n.is_empty() {
                None
            } else if n.len() <= 40 && n.bytes().all(|b| b.is_ascii_alphanumeric()) {
                Some(Tracking { carrier: self.tracking.as_ref().and_then(|t| t.carrier), number: n })
            } else {
                return Err(Error::invalid("tracking number may only contain letters and digits"));
            };
        }
        if let Some(p) = i.payment_required {
            self.payment_required = p;
        }
        let domain = match &i.vendor_domain {
            None => None,
            Some(d) if d.trim().is_empty() => Some(None),
            Some(d) => {
                let d = d.trim().trim_start_matches('@');
                Some(Some(
                    crate::mail::parser::sender_domain(&format!("x@{d}"))
                        .ok_or_else(|| Error::invalid("vendor domain is not a valid domain"))?,
                ))
            }
        };
        Ok(domain)
    }
}

/// What the API returns for an order. A superset of the portal's `OrderRecord`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderView {
    pub id: Uuid,
    pub order_number: String,
    pub title: String,
    pub board_name: String,
    pub quantity: u32,
    pub currency: String,
    pub total_cents: i64,
    pub state: OrderStatus,
    pub fab_reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracking_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracking_url: Option<String>,
    pub envelope_key_version: u32,
    pub aad_binding: String,
    pub approval_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<Uuid>,
    pub payment_required: bool,
    pub payment_state: String,
    pub vendor_name: String,
    pub vendor_domain: Option<String>,
    pub line_items: Vec<LineItem>,
    pub quote_notes: String,
    pub shipping_address: Option<Address>,
    pub customer_email: Option<String>,
    pub created_by: Uuid,
    pub approved_by: Option<Uuid>,
    pub version: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderEventView {
    pub id: Uuid,
    pub from_state: Option<OrderStatus>,
    pub to_state: OrderStatus,
    pub source: String,
    pub actor: Option<Uuid>,
    pub note: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitionInput {
    pub state: OrderStatus,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckoutResponse {
    pub checkout_url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totals_from_line_items_and_bounds() {
        let mut p = OrderPayload::default();
        let input: OrderInput = serde_json::from_value(serde_json::json!({
            "title": " Rev C ", "quantity": 10, "currency": "usd",
            "lineItems": [{"description": "PCB", "quantity": 10, "unitCents": 1250}, {"description": "Stencil", "quantity": 1, "unitCents": 900}],
            "vendorDomain": "@PCBFab.com", "customerEmail": "Buyer@Example.com"
        }))
        .unwrap();
        let domain = p.apply(&input).unwrap();
        assert_eq!(domain, Some(Some("pcbfab.com".into())));
        assert_eq!((p.title.as_str(), p.currency.as_str(), p.total_cents), ("Rev C", "USD", 13_400));
        assert_eq!(p.customer_email.as_deref(), Some("Buyer@example.com"));

        let overflow: OrderInput = serde_json::from_value(serde_json::json!({
            "lineItems": [{"description": "x", "quantity": 4000000000u32, "unitCents": 1000000000000i64}]
        }))
        .unwrap();
        assert!(p.clone().apply(&overflow).is_err());
        for bad in [
            serde_json::json!({"totalCents": -1}),
            serde_json::json!({"quantity": 0}),
            serde_json::json!({"currency": "dollars"}),
            serde_json::json!({"vendorDomain": "not a domain"}),
            serde_json::json!({"customerEmail": "a@b.com\r\nBcc: x@y.com"}),
            serde_json::json!({"trackingNumber": "1Z<script>"}),
            serde_json::json!({"title": "a\u{0000}b"}),
        ] {
            let i: OrderInput = serde_json::from_value(bad.clone()).unwrap();
            assert!(p.clone().apply(&i).is_err(), "{bad}");
        }
    }

    #[test]
    fn unknown_fields_are_rejected() {
        // A caller cannot set status, tenant or approval through the input.
        for bad in ["state", "status", "tenantId", "approvedBy", "paymentState"] {
            let v = serde_json::json!({ bad: "x" });
            assert!(serde_json::from_value::<OrderInput>(v).is_err(), "{bad}");
        }
    }
}
