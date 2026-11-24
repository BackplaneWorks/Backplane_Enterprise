//! Order lifecycle state machine (SPEC 3.6).
//!
//! `draft → quote_requested → pending_approval → ordered → in_fabrication →
//! shipped → delivered`, plus `on_hold` / `cancelled`.
//!
//! Every status change in the crate goes through [`check_transition`]. The
//! table is deliberately small and explicit: who is asking ([`Source`]) decides
//! which edges are open, so an inbound e-mail or a webhook can never do what
//! only a person with the right permission may do.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Draft,
    QuoteRequested,
    PendingApproval,
    Ordered,
    InFabrication,
    Shipped,
    Delivered,
    OnHold,
    Cancelled,
}

impl OrderStatus {
    pub const ALL: [OrderStatus; 9] = [
        Self::Draft,
        Self::QuoteRequested,
        Self::PendingApproval,
        Self::Ordered,
        Self::InFabrication,
        Self::Shipped,
        Self::Delivered,
        Self::OnHold,
        Self::Cancelled,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::QuoteRequested => "quote_requested",
            Self::PendingApproval => "pending_approval",
            Self::Ordered => "ordered",
            Self::InFabrication => "in_fabrication",
            Self::Shipped => "shipped",
            Self::Delivered => "delivered",
            Self::OnHold => "on_hold",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }

    /// Position on the forward path; `None` for the side states.
    fn rank(self) -> Option<u8> {
        Some(match self {
            Self::Draft => 0,
            Self::QuoteRequested => 1,
            Self::PendingApproval => 2,
            Self::Ordered => 3,
            Self::InFabrication => 4,
            Self::Shipped => 5,
            Self::Delivered => 6,
            Self::OnHold | Self::Cancelled => return None,
        })
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Delivered | Self::Cancelled)
    }

    /// Money has been committed once the order is placed.
    pub fn is_placed(self) -> bool {
        matches!(self.rank(), Some(r) if r >= 3)
    }
}

/// Who is asking for the transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// A signed-in person holding `OrdersWrite`.
    User,
    /// A signed-in person holding `OrdersApprove`, after the approval gate passed.
    Approver,
    /// A verified Stripe webhook confirming payment of this order.
    Payment,
    /// The inbound e-mail parser. Untrusted input: fulfilment progress only.
    Mail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransitionError {
    #[error("order is already {0:?}")]
    NoChange(OrderStatus),
    #[error("order is {0:?} and cannot change any more")]
    Terminal(OrderStatus),
    #[error("{from:?} → {to:?} is not a valid step")]
    NotAllowed { from: OrderStatus, to: OrderStatus },
    #[error("{from:?} → {to:?} is not open to this source")]
    Forbidden { from: OrderStatus, to: OrderStatus },
    #[error("an order on hold resumes to the status it was held from")]
    BadResume,
}

/// Decide whether `from → to` is allowed for `source`.
///
/// `held_from` is the status the order had before it went on hold (stored on
/// the row); it is only consulted when `from == OnHold`.
pub fn check_transition(
    from: OrderStatus,
    to: OrderStatus,
    source: Source,
    held_from: Option<OrderStatus>,
) -> Result<(), TransitionError> {
    use OrderStatus::*;
    if from == to {
        return Err(TransitionError::NoChange(from));
    }
    if from.is_terminal() {
        return Err(TransitionError::Terminal(from));
    }
    let deny = TransitionError::NotAllowed { from, to };
    let forbid = TransitionError::Forbidden { from, to };

    // Placing the order is the one high-impact edge. It opens only to an
    // approver (gate passed) or to a verified payment of an approved order.
    if to == Ordered {
        return match (from, source) {
            (PendingApproval, Source::Approver | Source::Payment) => Ok(()),
            (OnHold, Source::Approver) if held_from == Some(Ordered) => Ok(()),
            (OnHold, _) if held_from != Some(Ordered) => Err(TransitionError::BadResume),
            (PendingApproval | OnHold, _) => Err(forbid),
            _ => Err(deny),
        };
    }

    match source {
        // Mail may only move a placed order forward along fulfilment, and may
        // skip a step (a "shipped" notice with no "in fabrication" before it).
        Source::Mail => match (from.rank(), to.rank()) {
            (Some(f), Some(t)) if f >= 3 && t > f => Ok(()),
            _ => Err(forbid),
        },
        // Payment confirms placement and nothing else (handled above).
        Source::Payment => Err(forbid),
        Source::User | Source::Approver => match (from, to) {
            (OnHold, Cancelled) => Ok(()),
            (OnHold, t) => {
                if held_from == Some(t) {
                    Ok(())
                } else {
                    Err(TransitionError::BadResume)
                }
            }
            (_, OnHold) | (_, Cancelled) => Ok(()),
            // Sending an order back for rework before it is placed.
            (QuoteRequested | PendingApproval, Draft) => Ok(()),
            (PendingApproval, QuoteRequested) => Ok(()),
            (f, t) => match (f.rank(), t.rank()) {
                // Before placement: one step at a time, or draft straight to
                // approval when the quote is already in hand.
                (Some(0), Some(2)) => Ok(()),
                (Some(a), Some(b)) if b == a + 1 => Ok(()),
                // After placement a person may also record a skipped step.
                (Some(a), Some(b)) if a >= 3 && b > a => Ok(()),
                _ => Err(deny),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::OrderStatus::*;
    use super::*;

    #[test]
    fn round_trips_names() {
        for s in OrderStatus::ALL {
            assert_eq!(OrderStatus::parse(s.as_str()), Some(s));
            assert_eq!(
                serde_json::to_string(&s).unwrap(),
                format!("\"{}\"", s.as_str())
            );
        }
        assert_eq!(OrderStatus::parse("ORDERED"), None);
    }

    #[test]
    fn happy_path() {
        let path = [
            (Draft, QuoteRequested, Source::User),
            (QuoteRequested, PendingApproval, Source::User),
            (PendingApproval, Ordered, Source::Approver),
            (Ordered, InFabrication, Source::Mail),
            (InFabrication, Shipped, Source::Mail),
            (Shipped, Delivered, Source::Mail),
        ];
        for (f, t, s) in path {
            assert_eq!(check_transition(f, t, s, None), Ok(()), "{f:?}→{t:?}");
        }
    }

    #[test]
    fn only_approver_or_payment_places_an_order() {
        for from in OrderStatus::ALL {
            for source in [Source::User, Source::Mail] {
                assert!(
                    check_transition(from, Ordered, source, Some(Ordered)).is_err(),
                    "{from:?} by {source:?}"
                );
            }
        }
        assert!(check_transition(PendingApproval, Ordered, Source::Payment, None).is_ok());
        // Nothing but pending_approval (or a held placed order) reaches ordered.
        for from in [Draft, QuoteRequested, InFabrication, Shipped] {
            assert!(check_transition(from, Ordered, Source::Approver, None).is_err());
        }
    }

    #[test]
    fn mail_cannot_touch_anything_before_placement_or_go_sideways() {
        for from in OrderStatus::ALL {
            for to in OrderStatus::ALL {
                let ok = check_transition(from, to, Source::Mail, None).is_ok();
                let expected = matches!(
                    (from, to),
                    (Ordered, InFabrication | Shipped | Delivered)
                        | (InFabrication, Shipped | Delivered)
                        | (Shipped, Delivered)
                );
                assert_eq!(ok, expected, "{from:?}→{to:?}");
            }
        }
    }

    #[test]
    fn payment_can_only_place() {
        for from in OrderStatus::ALL {
            for to in OrderStatus::ALL {
                let ok = check_transition(from, to, Source::Payment, Some(Ordered)).is_ok();
                assert_eq!(ok, (from, to) == (PendingApproval, Ordered), "{from:?}→{to:?}");
            }
        }
    }

    #[test]
    fn terminal_states_are_final() {
        for from in [Delivered, Cancelled] {
            for to in OrderStatus::ALL {
                for s in [Source::User, Source::Approver, Source::Payment, Source::Mail] {
                    assert!(check_transition(from, to, s, None).is_err());
                }
            }
        }
    }

    #[test]
    fn hold_resumes_only_where_it_came_from() {
        assert!(check_transition(InFabrication, OnHold, Source::User, None).is_ok());
        assert!(check_transition(OnHold, InFabrication, Source::User, Some(InFabrication)).is_ok());
        assert_eq!(
            check_transition(OnHold, Shipped, Source::User, Some(InFabrication)),
            Err(TransitionError::BadResume)
        );
        // Hold cannot be used to jump past approval.
        assert!(check_transition(OnHold, Ordered, Source::User, Some(PendingApproval)).is_err());
        assert!(check_transition(OnHold, Ordered, Source::Approver, Some(PendingApproval)).is_err());
        assert!(check_transition(OnHold, Ordered, Source::Approver, Some(Ordered)).is_ok());
        assert!(check_transition(OnHold, Cancelled, Source::User, Some(Draft)).is_ok());
    }

    #[test]
    fn no_skipping_approval() {
        assert!(check_transition(Draft, PendingApproval, Source::User, None).is_ok());
        for to in [InFabrication, Shipped, Delivered] {
            for from in [Draft, QuoteRequested, PendingApproval] {
                assert!(check_transition(from, to, Source::User, None).is_err());
                assert!(check_transition(from, to, Source::Approver, None).is_err());
            }
        }
    }
}
