//! Stripe webhook signature verification.
//!
//! Verifies the `Stripe-Signature` header (`t=<unix>,v1=<hex hmac>[,v1=...]`)
//! over the **raw request bytes**: `HMAC-SHA256(secret, "<t>.<body>")`,
//! compared in constant time, with a timestamp tolerance against replay.
//! Nothing in the body is parsed, logged or trusted before this passes.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Stripe's recommended tolerance.
pub const DEFAULT_TOLERANCE_SECS: i64 = 300;
/// Stripe events are small; anything larger is refused before hashing.
pub const MAX_WEBHOOK_BODY: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    #[error("missing or malformed signature header")]
    Malformed,
    #[error("timestamp outside tolerance")]
    Stale,
    #[error("signature mismatch")]
    Mismatch,
    #[error("body too large")]
    TooLarge,
}

/// Verify `header` against `body` with `secret` (the `whsec_...` endpoint
/// secret). `now` is unix seconds. Accepts if any `v1` signature matches,
/// which is what lets Stripe roll secrets.
pub fn verify_signature(
    secret: &[u8],
    header: &str,
    body: &[u8],
    now: i64,
    tolerance_secs: i64,
) -> Result<(), SignatureError> {
    if body.len() > MAX_WEBHOOK_BODY {
        return Err(SignatureError::TooLarge);
    }
    if secret.is_empty() || header.len() > 2048 {
        return Err(SignatureError::Malformed);
    }
    let mut timestamp: Option<&str> = None;
    let mut candidates: Vec<Vec<u8>> = Vec::new();
    for part in header.split(',') {
        let Some((k, v)) = part.trim().split_once('=') else {
            return Err(SignatureError::Malformed);
        };
        match k {
            "t" => {
                if timestamp.replace(v).is_some() {
                    return Err(SignatureError::Malformed);
                }
            }
            // Only the v1 scheme is accepted; `v0` (test) is ignored so it
            // cannot be used as a downgrade.
            "v1" => {
                if let Ok(raw) = hex::decode(v) {
                    if raw.len() == 32 && candidates.len() < 8 {
                        candidates.push(raw);
                    }
                }
            }
            _ => {}
        }
    }
    let t_str = timestamp.ok_or(SignatureError::Malformed)?;
    if t_str.is_empty() || t_str.len() > 12 || !t_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SignatureError::Malformed);
    }
    let t: i64 = t_str.parse().map_err(|_| SignatureError::Malformed)?;
    if candidates.is_empty() {
        return Err(SignatureError::Malformed);
    }

    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| SignatureError::Malformed)?;
    mac.update(t_str.as_bytes());
    mac.update(b".");
    mac.update(body);
    let expected = mac.finalize().into_bytes();

    // Check every candidate without short-circuiting.
    let mut ok = 0u8;
    for c in &candidates {
        ok |= c.as_slice().ct_eq(expected.as_slice()).unwrap_u8();
    }
    if ok != 1 {
        return Err(SignatureError::Mismatch);
    }
    // Checked after the MAC so an attacker learns nothing about timing from
    // an unsigned request.
    if (now - t).abs() > tolerance_secs {
        return Err(SignatureError::Stale);
    }
    Ok(())
}

/// Build a valid header for `body`. Used by tests (here and in other crates).
pub fn sign_for_test(secret: &[u8], body: &[u8], t: i64) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(t.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!("t={t},v1={}", hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"whsec_test_secret";
    const BODY: &[u8] = br#"{"id":"evt_1","type":"checkout.session.completed"}"#;

    #[test]
    fn accepts_valid() {
        let h = sign_for_test(SECRET, BODY, 1_000);
        assert_eq!(verify_signature(SECRET, &h, BODY, 1_100, 300), Ok(()));
    }

    #[test]
    fn accepts_any_matching_v1_during_secret_roll() {
        let good = sign_for_test(SECRET, BODY, 1_000);
        let sig = good.split("v1=").nth(1).unwrap();
        let h = format!("t=1000,v1={},v1={sig}", "00".repeat(32));
        assert_eq!(verify_signature(SECRET, &h, BODY, 1_000, 300), Ok(()));
    }

    #[test]
    fn rejects_tampered_body_wrong_secret_and_shifted_timestamp() {
        let h = sign_for_test(SECRET, BODY, 1_000);
        let mut body = BODY.to_vec();
        body[10] ^= 1;
        assert_eq!(
            verify_signature(SECRET, &h, &body, 1_000, 300),
            Err(SignatureError::Mismatch)
        );
        assert_eq!(
            verify_signature(b"other", &h, BODY, 1_000, 300),
            Err(SignatureError::Mismatch)
        );
        // Re-stamping an old signature with a fresh timestamp breaks the MAC.
        let restamped = h.replace("t=1000", "t=9000");
        assert_eq!(
            verify_signature(SECRET, &restamped, BODY, 9_000, 300),
            Err(SignatureError::Mismatch)
        );
    }

    #[test]
    fn rejects_replay_outside_tolerance() {
        let h = sign_for_test(SECRET, BODY, 1_000);
        assert_eq!(
            verify_signature(SECRET, &h, BODY, 1_301, 300),
            Err(SignatureError::Stale)
        );
        assert_eq!(
            verify_signature(SECRET, &h, BODY, 600, 300),
            Err(SignatureError::Stale)
        );
    }

    #[test]
    fn rejects_malformed_and_downgrade() {
        for h in [
            "",
            "garbage",
            "t=1000",
            "v1=abcd",
            "t=,v1=00",
            "t=-5,v1=00",
            "t=1000,t=1000,v1=00",
            "t=1000,v1=zz",
        ] {
            assert_eq!(
                verify_signature(SECRET, h, BODY, 1_000, 300),
                Err(SignatureError::Malformed),
                "{h}"
            );
        }
        // A correct MAC presented under the v0 scheme is not accepted.
        let v0 = sign_for_test(SECRET, BODY, 1_000).replace("v1=", "v0=");
        assert_eq!(
            verify_signature(SECRET, &v0, BODY, 1_000, 300),
            Err(SignatureError::Malformed)
        );
        assert_eq!(
            verify_signature(b"", "t=1,v1=00", BODY, 1, 300),
            Err(SignatureError::Malformed)
        );
    }

    #[test]
    fn rejects_oversized_body() {
        let big = vec![b'a'; MAX_WEBHOOK_BODY + 1];
        let h = sign_for_test(SECRET, &big, 1);
        assert_eq!(
            verify_signature(SECRET, &h, &big, 1, 300),
            Err(SignatureError::TooLarge)
        );
    }
}
