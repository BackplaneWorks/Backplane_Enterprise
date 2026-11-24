//! Append-only, hash-chained audit log (one chain per tenant).
//!
//! Each entry stores `hash = SHA-256(prev_hash ‖ fields)`. Changing or
//! removing any earlier entry breaks every hash after it, which
//! [`verify_chain`] detects. The database additionally refuses UPDATE, DELETE
//! and TRUNCATE on the table. Removing entries from the *end* is only
//! detectable against an anchor kept elsewhere: export [`head`] periodically
//! (the API exposes it; ship it to your SIEM / an S3 Object Lock bucket).

use crate::{Principal, Result, TenantId, Tx};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::Row;

const GENESIS: [u8; 32] = [0u8; 32];

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Entry {
    pub seq: i64,
    /// Unix microseconds.
    pub at_us: i64,
    pub actor_kind: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    /// JSON text exactly as hashed.
    pub details: String,
    #[serde(with = "hex_bytes")]
    pub prev_hash: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub hash: Vec<u8>,
}

mod hex_bytes {
    pub fn serialize<S: serde::Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
}

/// The hash of one entry. Every field is length-prefixed so that no two
/// different entries serialise to the same bytes.
#[allow(clippy::too_many_arguments)]
pub fn entry_hash(
    tenant: TenantId,
    seq: i64,
    at_us: i64,
    actor_kind: &str,
    actor: &str,
    action: &str,
    target: &str,
    details: &str,
    prev_hash: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"bpe-audit-v1");
    h.update(prev_hash);
    h.update(tenant.0.as_bytes());
    h.update(seq.to_be_bytes());
    h.update(at_us.to_be_bytes());
    for field in [actor_kind, actor, action, target, details] {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field.as_bytes());
    }
    h.finalize().into()
}

/// Record an action by an authenticated caller, inside the caller's
/// transaction: the entry commits or rolls back with the change it describes.
///
/// `action` is a dotted verb (`order.approved`, `part.released`); `target` is
/// `kind:id`. Never put secrets or encrypted-payload plaintext in `details`.
pub async fn append(
    tx: &mut Tx,
    principal: &Principal,
    action: &str,
    target: &str,
    details: serde_json::Value,
) -> Result<i64> {
    append_raw(
        tx,
        principal.tenant_id,
        principal.auth.as_str(),
        &principal.user_id.to_string(),
        action,
        target,
        details,
    )
    .await
}

/// Record an action by a system component (webhook, mail sync, reaper).
pub async fn append_system(
    tx: &mut Tx,
    tenant: TenantId,
    component: &str,
    action: &str,
    target: &str,
    details: serde_json::Value,
) -> Result<i64> {
    append_raw(tx, tenant, "system", component, action, target, details).await
}

async fn append_raw(
    tx: &mut Tx,
    tenant: TenantId,
    actor_kind: &str,
    actor: &str,
    action: &str,
    target: &str,
    details: serde_json::Value,
) -> Result<i64> {
    // One writer per tenant chain at a time; released at commit/rollback.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('bpe-audit:' || $1, 0))")
        .bind(tenant.0.to_string())
        .execute(&mut **tx)
        .await?;
    let last = sqlx::query(
        "SELECT seq, hash FROM audit_log WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1",
    )
    .bind(tenant.0)
    .fetch_optional(&mut **tx)
    .await?;
    let (seq, prev): (i64, Vec<u8>) = match last {
        Some(r) => (r.get::<i64, _>("seq") + 1, r.get("hash")),
        None => (1, GENESIS.to_vec()),
    };
    let at_us = (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000) as i64;
    let details = details.to_string();
    let hash = entry_hash(tenant, seq, at_us, actor_kind, actor, action, target, &details, &prev);
    sqlx::query(
        "INSERT INTO audit_log (tenant_id, seq, at_us, actor_kind, actor, action, target, details, prev_hash, hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(tenant.0)
    .bind(seq)
    .bind(at_us)
    .bind(actor_kind)
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(&details)
    .bind(&prev)
    .bind(hash.as_slice())
    .execute(&mut **tx)
    .await?;
    Ok(seq)
}

fn entry_from_row(r: &sqlx::postgres::PgRow) -> Entry {
    Entry {
        seq: r.get("seq"),
        at_us: r.get("at_us"),
        actor_kind: r.get("actor_kind"),
        actor: r.get("actor"),
        action: r.get("action"),
        target: r.get("target"),
        details: r.get("details"),
        prev_hash: r.get("prev_hash"),
        hash: r.get("hash"),
    }
}

const COLS: &str = "seq, at_us, actor_kind, actor, action, target, details, prev_hash, hash";

/// Newest first, entries with `seq < before` (pagination cursor).
pub async fn list(tx: &mut Tx, tenant: TenantId, before: Option<i64>, limit: i64) -> Result<Vec<Entry>> {
    let rows = sqlx::query(&format!(
        "SELECT {COLS} FROM audit_log WHERE tenant_id = $1 AND seq < $2 ORDER BY seq DESC LIMIT $3"
    ))
    .bind(tenant.0)
    .bind(before.unwrap_or(i64::MAX))
    .bind(limit.clamp(1, 500))
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows.iter().map(entry_from_row).collect())
}

/// The latest `(seq, hash)` of the tenant's chain: the value to anchor externally.
pub async fn head(tx: &mut Tx, tenant: TenantId) -> Result<Option<(i64, Vec<u8>)>> {
    let r = sqlx::query("SELECT seq, hash FROM audit_log WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1")
        .bind(tenant.0)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(r.map(|r| (r.get("seq"), r.get("hash"))))
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChainError {
    #[error("audit chain broken at seq {0}: entry does not match its hash")]
    BadHash(i64),
    #[error("audit chain broken at seq {0}: does not link to the previous entry")]
    BadLink(i64),
    #[error("audit chain broken: expected seq {expected}, found {found}")]
    Gap { expected: i64, found: i64 },
}

/// Check a sequence of entries (oldest first, starting at seq 1).
#[allow(clippy::explicit_counter_loop)]
pub fn verify_entries(tenant: TenantId, entries: &[Entry]) -> std::result::Result<u64, ChainError> {
    let mut prev = GENESIS.to_vec();
    let mut expected = 1i64;
    for e in entries {
        if e.seq != expected {
            return Err(ChainError::Gap { expected, found: e.seq });
        }
        if e.prev_hash != prev {
            return Err(ChainError::BadLink(e.seq));
        }
        let h = entry_hash(tenant, e.seq, e.at_us, &e.actor_kind, &e.actor, &e.action, &e.target, &e.details, &e.prev_hash);
        if h.as_slice() != e.hash.as_slice() {
            return Err(ChainError::BadHash(e.seq));
        }
        prev = e.hash.clone();
        expected += 1;
    }
    Ok(entries.len() as u64)
}

/// Recompute the whole chain of the transaction's tenant. Returns the number
/// of entries, or `Error::Conflict` describing the first break.
pub async fn verify_chain(tx: &mut Tx, tenant: TenantId) -> Result<u64> {
    let mut prev = GENESIS.to_vec();
    let mut next = 1i64;
    loop {
        let rows = sqlx::query(&format!(
            "SELECT {COLS} FROM audit_log WHERE tenant_id = $1 AND seq >= $2 ORDER BY seq LIMIT 1000"
        ))
        .bind(tenant.0)
        .bind(next)
        .fetch_all(&mut **tx)
        .await?;
        if rows.is_empty() {
            return Ok((next - 1) as u64);
        }
        for r in &rows {
            let e = entry_from_row(r);
            let res = if e.seq != next {
                Err(ChainError::Gap { expected: next, found: e.seq })
            } else if e.prev_hash != prev {
                Err(ChainError::BadLink(e.seq))
            } else if entry_hash(tenant, e.seq, e.at_us, &e.actor_kind, &e.actor, &e.action, &e.target, &e.details, &e.prev_hash).as_slice() != e.hash.as_slice() {
                Err(ChainError::BadHash(e.seq))
            } else {
                Ok(())
            };
            res.map_err(|c| crate::Error::Conflict(c.to_string()))?;
            prev = e.hash;
            next += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(tenant: TenantId, n: i64) -> Vec<Entry> {
        let mut prev = GENESIS.to_vec();
        (1..=n)
            .map(|seq| {
                let details = format!("{{\"n\":{seq}}}");
                let hash = entry_hash(tenant, seq, 1000 + seq, "user", "u", "part.released", "part:1", &details, &prev);
                let e = Entry {
                    seq,
                    at_us: 1000 + seq,
                    actor_kind: "user".into(),
                    actor: "u".into(),
                    action: "part.released".into(),
                    target: "part:1".into(),
                    details,
                    prev_hash: prev.clone(),
                    hash: hash.to_vec(),
                };
                prev = hash.to_vec();
                e
            })
            .collect()
    }

    #[test]
    fn intact_chain_verifies() {
        let t = TenantId::new();
        assert_eq!(verify_entries(t, &chain(t, 5)), Ok(5));
        assert_eq!(verify_entries(t, &[]), Ok(0));
    }

    #[test]
    fn edited_entry_is_detected() {
        let t = TenantId::new();
        let mut c = chain(t, 5);
        c[2].action = "part.deleted".into();
        assert_eq!(verify_entries(t, &c), Err(ChainError::BadHash(3)));
    }

    #[test]
    fn removed_entry_is_detected() {
        let t = TenantId::new();
        let mut c = chain(t, 5);
        c.remove(1);
        assert_eq!(verify_entries(t, &c), Err(ChainError::Gap { expected: 2, found: 3 }));
    }

    #[test]
    fn recomputed_hash_without_relinking_is_detected() {
        let t = TenantId::new();
        let mut c = chain(t, 3);
        c[0].details = "{}".into();
        c[0].hash = entry_hash(t, 1, c[0].at_us, "user", "u", "part.released", "part:1", "{}", &c[0].prev_hash).to_vec();
        assert_eq!(verify_entries(t, &c), Err(ChainError::BadLink(2)));
    }

    #[test]
    fn chain_is_bound_to_its_tenant() {
        let t = TenantId::new();
        assert_eq!(verify_entries(TenantId::new(), &chain(t, 2)), Err(ChainError::BadHash(1)));
    }

    #[test]
    fn field_boundaries_are_unambiguous() {
        let t = TenantId::new();
        let a = entry_hash(t, 1, 0, "user", "ab", "c", "", "", &GENESIS);
        let b = entry_hash(t, 1, 0, "user", "a", "bc", "", "", &GENESIS);
        assert_ne!(a, b);
    }
}
