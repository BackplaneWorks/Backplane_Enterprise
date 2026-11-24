//! Per-bridge rate limiting and pre-auth rejection audit throttling.
//!
//! Note on multi-replica behavior:
//! - In-memory buckets here are per-process (fast-path protection for verified
//!   handshakes and pre-auth rejection throttling).
//! - For verified inbound event deliveries and A2A RPC calls, `routes.rs` ALSO
//!   counts recent accepted rows in PostgreSQL (`bridge_deliveries`) over the
//!   last 60 seconds so `rate_limit_rpm` holds globally across N replicas.

use bp_ent_core::{Error, Result, TenantId};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use uuid::Uuid;

/// Cap on unauthenticated signature failures per bridge per minute before
/// shedding load with 429 (separate from the verified delivery quota).
const PRE_AUTH_FAILURE_RPM: usize = 30;

#[derive(Default)]
pub struct BridgeRateLimiter {
    verified: Mutex<HashMap<(TenantId, Uuid), VecDeque<i64>>>,
    pre_auth_failures: Mutex<HashMap<(TenantId, Uuid), VecDeque<i64>>>,
    last_rejection_audit: Mutex<HashMap<(TenantId, Uuid), i64>>,
}

impl BridgeRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    fn consume_from(
        map: &Mutex<HashMap<(TenantId, Uuid), VecDeque<i64>>>,
        tenant: TenantId,
        bridge_id: Uuid,
        limit: usize,
        now: i64,
    ) -> Result<()> {
        let cutoff = now - 60;
        let mut guard = map.lock().unwrap();
        if guard.len() > 2048 {
            guard.retain(|_, q| q.back().is_some_and(|&ts| ts > cutoff));
        }
        let q = guard.entry((tenant, bridge_id)).or_default();
        while q.front().is_some_and(|&ts| ts <= cutoff) {
            q.pop_front();
        }
        if q.len() >= limit {
            return Err(Error::TooManyRequests);
        }
        q.push_back(now);
        Ok(())
    }

    /// Consume one verified delivery slot for `(tenant, bridge_id)` at `now`.
    /// Must ONLY be called AFTER cryptographic signature verification succeeds.
    pub fn check_and_consume_verified(
        &self,
        tenant: TenantId,
        bridge_id: Uuid,
        rpm: i32,
        now: i64,
    ) -> Result<()> {
        let limit = rpm.clamp(1, 600) as usize;
        Self::consume_from(&self.verified, tenant, bridge_id, limit, now)
    }

    /// Separate small pre-auth failure bucket so unauthenticated floods cannot
    /// exhaust the bridge's verified delivery quota.
    pub fn check_pre_auth_failure_bucket(
        &self,
        tenant: TenantId,
        bridge_id: Uuid,
        now: i64,
    ) -> Result<()> {
        Self::consume_from(
            &self.pre_auth_failures,
            tenant,
            bridge_id,
            PRE_AUTH_FAILURE_RPM,
            now,
        )
    }

    /// Returns `true` at most once per 60 seconds per bridge so unauthenticated
    /// invalid signatures cannot grow the append-only audit chain without bound.
    pub fn should_audit_rejection(&self, tenant: TenantId, bridge_id: Uuid, now: i64) -> bool {
        let mut guard = self.last_rejection_audit.lock().unwrap();
        if guard.len() > 2048 {
            let cutoff = now - 60;
            guard.retain(|_, &mut ts| ts > cutoff);
        }
        match guard.get(&(tenant, bridge_id)) {
            Some(&last) if now - last < 60 => false,
            _ => {
                guard.insert((tenant, bridge_id), now);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_rpm_and_isolates_bridges_and_buckets() {
        let rl = BridgeRateLimiter::new();
        let t1 = TenantId::new();
        let t2 = TenantId::new();
        let b1 = Uuid::new_v4();
        let b2 = Uuid::new_v4();

        // Exhausting pre-auth failure bucket never affects the verified bucket.
        for _ in 0..PRE_AUTH_FAILURE_RPM {
            assert!(rl.check_pre_auth_failure_bucket(t1, b1, 1_000).is_ok());
        }
        assert!(matches!(
            rl.check_pre_auth_failure_bucket(t1, b1, 1_000),
            Err(Error::TooManyRequests)
        ));

        for _ in 0..3 {
            assert!(rl.check_and_consume_verified(t1, b1, 3, 1_000).is_ok());
        }
        assert!(matches!(
            rl.check_and_consume_verified(t1, b1, 3, 1_000),
            Err(Error::TooManyRequests)
        ));

        // Different bridge or tenant is unaffected.
        assert!(rl.check_and_consume_verified(t1, b2, 3, 1_000).is_ok());
        assert!(rl.check_and_consume_verified(t2, b1, 3, 1_000).is_ok());

        // Window expires after 60s.
        assert!(rl.check_and_consume_verified(t1, b1, 3, 1_061).is_ok());
    }

    #[test]
    fn throttles_rejection_audits_to_once_per_minute() {
        let rl = BridgeRateLimiter::new();
        let t = TenantId::new();
        let b = Uuid::new_v4();

        assert!(rl.should_audit_rejection(t, b, 1_000));
        assert!(!rl.should_audit_rejection(t, b, 1_005));
        assert!(!rl.should_audit_rejection(t, b, 1_059));
        assert!(rl.should_audit_rejection(t, b, 1_060));
    }
}
