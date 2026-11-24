//! Strictly tenant-scoped in-memory response cache for `kicad_httplib`.
//!
//! By construction, there is no way to query or insert into the cache without a
//! [`TenantId`], and every physical key starts with `<tenant_uuid>:`.

use bp_ent_core::TenantId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Short 5-second per-process TTL to bound multi-replica staleness when parts
/// are obsoleted, updated, or deleted on another instance.
const DEFAULT_TTL: Duration = Duration::from_secs(5);
const MAX_ENTRIES_PER_TENANT: usize = 512;

/// A cache key whose string representation is guaranteed to start with `<tenant_id>:`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TenantCacheKey {
    tenant_id: TenantId,
    formatted: String,
}

impl TenantCacheKey {
    pub fn new(tenant_id: TenantId, namespace: &'static str, item: impl AsRef<str>) -> Self {
        let formatted = format!("{}:{}:{}", tenant_id.0, namespace, item.as_ref());
        Self { tenant_id, formatted }
    }

    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub fn formatted_key(&self) -> &str {
        &self.formatted
    }
}

#[derive(Clone)]
struct CachedEntry {
    tenant_id: TenantId,
    payload: String,
    expires_at: Instant,
}

struct CacheInner {
    ttl: Duration,
    max_per_tenant: usize,
    entries: HashMap<String, CachedEntry>,
}

#[derive(Clone)]
pub struct TenantScopedCache {
    inner: Arc<RwLock<CacheInner>>,
}

impl Default for TenantScopedCache {
    fn default() -> Self {
        Self::new(DEFAULT_TTL, MAX_ENTRIES_PER_TENANT)
    }
}

impl TenantScopedCache {
    pub fn new(ttl: Duration, max_per_tenant: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(CacheInner {
                ttl,
                max_per_tenant: max_per_tenant.max(1),
                entries: HashMap::new(),
            })),
        }
    }

    pub fn get(&self, tenant_id: TenantId, namespace: &'static str, item: &str) -> Option<String> {
        let key = TenantCacheKey::new(tenant_id, namespace, item);
        let now = Instant::now();
        {
            let guard = self.inner.read().ok()?;
            let entry = guard.entries.get(key.formatted_key())?;
            if entry.tenant_id == tenant_id && entry.expires_at > now {
                return Some(entry.payload.clone());
            }
        }
        // Expired entry: prune under write lock.
        if let Ok(mut guard) = self.inner.write() {
            if let Some(entry) = guard.entries.get(key.formatted_key()) {
                if entry.expires_at <= now {
                    guard.entries.remove(key.formatted_key());
                }
            }
        }
        None
    }

    pub fn put(
        &self,
        tenant_id: TenantId,
        namespace: &'static str,
        item: impl AsRef<str>,
        payload: String,
    ) {
        let key = TenantCacheKey::new(tenant_id, namespace, item);
        let now = Instant::now();
        if let Ok(mut guard) = self.inner.write() {
            guard.entries.retain(|_, v| v.expires_at > now);
            let tenant_count = guard
                .entries
                .values()
                .filter(|v| v.tenant_id == tenant_id)
                .count();
            if tenant_count >= guard.max_per_tenant {
                // Evict oldest-expiring entry for this tenant only.
                if let Some(oldest_key) = guard
                    .entries
                    .iter()
                    .filter(|(_, v)| v.tenant_id == tenant_id)
                    .min_by_key(|(_, v)| v.expires_at)
                    .map(|(k, _)| k.clone())
                {
                    guard.entries.remove(&oldest_key);
                }
            }
            let expires_at = now + guard.ttl;
            guard.entries.insert(
                key.formatted,
                CachedEntry {
                    tenant_id,
                    payload,
                    expires_at,
                },
            );
        }
    }

    pub fn invalidate_tenant(&self, tenant_id: TenantId) {
        if let Ok(mut guard) = self.inner.write() {
            guard.entries.retain(|_, v| v.tenant_id != tenant_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn cache_keys_always_prefix_with_tenant_id_and_never_collide() {
        let tenant_a = TenantId(Uuid::new_v4());
        let tenant_b = TenantId(Uuid::new_v4());

        let key_a = TenantCacheKey::new(tenant_a, "part", "same-part-id");
        let key_b = TenantCacheKey::new(tenant_b, "part", "same-part-id");
        assert!(key_a.formatted_key().starts_with(&format!("{}:", tenant_a.0)));
        assert!(key_b.formatted_key().starts_with(&format!("{}:", tenant_b.0)));
        assert_ne!(key_a.formatted_key(), key_b.formatted_key());

        let cache = TenantScopedCache::default();
        cache.put(tenant_a, "categories", "all", r#"[{"id":"1","name":"SecretA"}]"#.into());
        cache.put(tenant_b, "categories", "all", r#"[{"id":"1","name":"SecretB"}]"#.into());

        assert!(cache
            .get(tenant_a, "categories", "all")
            .unwrap()
            .contains("SecretA"));
        assert!(cache
            .get(tenant_b, "categories", "all")
            .unwrap()
            .contains("SecretB"));

        cache.invalidate_tenant(tenant_a);
        assert!(cache.get(tenant_a, "categories", "all").is_none());
        assert!(cache.get(tenant_b, "categories", "all").is_some());
    }
}
