//! Outbound order status notifications.
//!
//! Plain text only. Every value that came from a person or from an e-mail is
//! passed through the sanitiser and capped before it is placed in the
//! message; tracking links are built from the carrier and number, never
//! copied from inbound mail.

use super::parser::Tracking;
use super::sanitize::{clean_header, clean_text};
use super::OutboundMessage;
use crate::status::OrderStatus;

pub const MAX_NOTE_LEN: usize = 2000;

pub struct StatusNotice<'a> {
    pub to: &'a str,
    /// Organisation name shown as the sender ("Acme Hardware").
    pub org_name: &'a str,
    pub order_ref: &'a str,
    pub title: &'a str,
    pub status: OrderStatus,
    pub tracking: Option<&'a Tracking>,
    /// Optional note written by the person sending the update.
    pub note: Option<&'a str>,
}

fn headline(s: OrderStatus) -> &'static str {
    match s {
        OrderStatus::Draft => "is being prepared",
        OrderStatus::QuoteRequested => "is out for quotation",
        OrderStatus::PendingApproval => "is awaiting approval",
        OrderStatus::Ordered => "has been placed",
        OrderStatus::InFabrication => "is in fabrication",
        OrderStatus::Shipped => "has shipped",
        OrderStatus::Delivered => "has been delivered",
        OrderStatus::OnHold => "is on hold",
        OrderStatus::Cancelled => "has been cancelled",
    }
}

pub fn status_notice(n: &StatusNotice<'_>) -> OutboundMessage {
    let org = clean_header(n.org_name);
    let title = clean_header(n.title);
    let head = headline(n.status);
    let mut text = format!("Hello,\n\nYour order {} ", n.order_ref);
    if !title.is_empty() {
        text.push_str(&format!("({title}) "));
    }
    text.push_str(head);
    text.push_str(".\n");
    if let Some(t) = n.tracking {
        let number: String = t.number.chars().filter(char::is_ascii_alphanumeric).take(40).collect();
        if !number.is_empty() {
            text.push_str(&format!("\nTracking number: {number}\n"));
            if let Some(c) = t.carrier {
                text.push_str(&format!("Track it: {}\n", c.tracking_url(&number)));
            }
        }
    }
    if let Some(note) = n.note.map(|s| clean_text(s, MAX_NOTE_LEN)).filter(|s| !s.is_empty()) {
        text.push_str(&format!("\n{note}\n"));
    }
    text.push_str(&format!("\n{}\n", if org.is_empty() { "Backplane" } else { &org }));
    OutboundMessage {
        to: n.to.to_string(),
        subject: format!("Order {} {}", n.order_ref, head),
        text,
    }
}

#[cfg(test)]
mod tests {
    use super::super::parser::Carrier;
    use super::*;

    #[test]
    fn shipped_notice_with_tracking() {
        let t = Tracking { carrier: Some(Carrier::Ups), number: "1Z999AA10123456784".into() };
        let m = status_notice(&StatusNotice {
            to: "buyer@example.com",
            org_name: "Acme Hardware",
            order_ref: "BP-7K2M9QX4TZ",
            title: "Rev C panels",
            status: OrderStatus::Shipped,
            tracking: Some(&t),
            note: Some("Arriving Friday."),
        });
        assert_eq!(m.subject, "Order BP-7K2M9QX4TZ has shipped");
        assert!(m.text.contains("Your order BP-7K2M9QX4TZ (Rev C panels) has shipped."));
        assert!(m.text.contains("https://www.ups.com/track?tracknum=1Z999AA10123456784"));
        assert!(m.text.contains("Arriving Friday."));
        assert!(m.text.trim_end().ends_with("Acme Hardware"));
    }

    #[test]
    fn hostile_values_are_neutralised() {
        let t = Tracking { carrier: Some(Carrier::Dhl), number: "123\r\nhttp://evil.example/x".into() };
        let m = status_notice(&StatusNotice {
            to: "buyer@example.com",
            org_name: "Acme\r\nBcc: evil@x.com",
            order_ref: "BP-7K2M9QX4TZ",
            title: "T\u{202E}itle\nSubject: x",
            status: OrderStatus::Delivered,
            tracking: Some(&t),
            note: Some(&"n".repeat(10_000)),
        });
        assert!(!m.subject.contains('\n') && !m.subject.contains('\r'));
        assert!(!m.text.contains('\r') && !m.text.contains('\u{202E}'));
        assert!(!m.text.contains("http://evil.example"));
        assert!(m.text.len() < MAX_NOTE_LEN + 600);
    }
}
