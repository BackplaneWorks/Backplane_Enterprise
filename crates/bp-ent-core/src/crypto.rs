//! Per-tenant envelope encryption.
//!
//! Each tenant has its own 256-bit data-encryption key (DEK), versioned for
//! rotation. A DEK exists in plaintext only in process memory; at rest it is
//! wrapped by a key-encryption key that lives in AWS KMS or, for self-host, in
//! a local master key ([`LocalKek`]).
//!
//! Sealed blob layout:
//!
//! ```text
//! "BPE1" | key_version: u32 BE | nonce: 12 random bytes | AES-256-GCM ciphertext+tag
//! ```
//!
//! The GCM associated data is `tenant_id | key_version | caller AAD`, so a blob
//! copied to another tenant, another key version, or (with the recommended
//! caller AAD `table|row_id|field`) another row or column fails to open.
//!
//! Nonces are random 96-bit values, which is safe for about 2^32 seals under
//! one key. Rotate a tenant's DEK ([`EnvelopeCipher::rotate_dek`]) at least
//! yearly, and sooner for a tenant that seals billions of payloads.

use crate::{Db, Error, Result, TenantId};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use async_trait::async_trait;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAGIC: &[u8; 4] = b"BPE1";
const HEADER_LEN: usize = 4 + 4 + 12;
const TAG_LEN: usize = 16;
/// How long a process keeps using a cached "current version" before
/// re-reading it, i.e. how long a rotation takes to reach every instance.
const CURRENT_TTL: Duration = Duration::from_secs(60);
/// How long an unwrapped DEK stays in memory. Bounds how long a deleted
/// (crypto-shredded) tenant key remains usable by a running process, and
/// keeps KMS calls to a handful per tenant per hour.
const DEK_TTL: Duration = Duration::from_secs(600);

/// 256-bit key material. Zeroed on drop; deliberately not `Debug`, `Clone` or `Serialize`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyBytes([u8; 32]);

impl KeyBytes {
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        Self(k)
    }

    pub fn from_slice(b: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = b.try_into().map_err(|_| Error::internal(anyhow::anyhow!("key must be 32 bytes")))?;
        Ok(Self(arr))
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new_from_slice(&self.0).expect("32-byte key")
    }
}

fn random_nonce() -> [u8; 12] {
    let mut n = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut n);
    n
}

// ------------------------------------------------------------ key provider

/// Wraps and unwraps DEKs with a key-encryption key that never leaves the provider.
#[async_trait]
pub trait KeyProvider: Send + Sync + 'static {
    /// Identifier of the KEK that `wrap` currently uses (stored beside the wrapped DEK).
    fn current_kek_id(&self) -> String;
    async fn wrap(&self, tenant: TenantId, version: u32, dek: &KeyBytes) -> Result<Vec<u8>>;
    async fn unwrap(&self, tenant: TenantId, version: u32, kek_id: &str, wrapped: &[u8]) -> Result<KeyBytes>;
}

fn wrap_aad(tenant: TenantId, version: u32) -> Vec<u8> {
    let mut aad = b"bpe-dek-wrap-v1".to_vec();
    aad.extend_from_slice(tenant.0.as_bytes());
    aad.extend_from_slice(&version.to_be_bytes());
    aad
}

/// Self-host master key: AES-256-GCM key wrapping with keys from the
/// environment / a mounted secret. Holds the current KEK plus any retired
/// ones still needed to unwrap older DEKs.
pub struct LocalKek {
    current: String,
    keys: HashMap<String, KeyBytes>,
}

impl LocalKek {
    pub fn new(current_id: impl Into<String>, key: KeyBytes) -> Self {
        let current = current_id.into();
        let mut keys = HashMap::new();
        keys.insert(current.clone(), key);
        Self { current, keys }
    }

    /// Keep a retired KEK available for unwrapping (KEK rotation).
    pub fn with_retired(mut self, id: impl Into<String>, key: KeyBytes) -> Self {
        self.keys.insert(id.into(), key);
        self
    }

    /// `BP_KEK` = `<id>:<base64 of 32 bytes>` (current), optional `BP_KEK_RETIRED`
    /// = comma-separated list in the same form. Either may instead be given
    /// as a file path in `BP_KEK_FILE` / `BP_KEK_RETIRED_FILE`.
    pub fn from_env() -> anyhow::Result<Self> {
        let cur = read_env_or_file("BP_KEK")?
            .ok_or_else(|| anyhow::anyhow!("BP_KEK (or BP_KEK_FILE) is not set"))?;
        let (id, key) = parse_kek(cur.trim())?;
        let mut me = Self::new(id, key);
        if let Some(mut retired) = read_env_or_file("BP_KEK_RETIRED")? {
            for item in retired.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let (id, key) = parse_kek(item)?;
                me = me.with_retired(id, key);
            }
            retired.zeroize();
        }
        Ok(me)
    }
}

fn read_env_or_file(name: &str) -> anyhow::Result<Option<String>> {
    if let Ok(v) = std::env::var(name) {
        if !v.is_empty() {
            return Ok(Some(v));
        }
    }
    if let Ok(path) = std::env::var(format!("{name}_FILE")) {
        if !path.is_empty() {
            return Ok(Some(std::fs::read_to_string(&path).map_err(|e| anyhow::anyhow!("cannot read {name}_FILE: {e}"))?));
        }
    }
    Ok(None)
}

fn parse_kek(s: &str) -> anyhow::Result<(String, KeyBytes)> {
    use base64::Engine;
    let (id, b64) = s.split_once(':').ok_or_else(|| anyhow::anyhow!("KEK must be <id>:<base64>"))?;
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        anyhow::bail!("KEK id must be letters, digits, '-' or '_'");
    }
    let mut raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| anyhow::anyhow!("KEK is not valid base64"))?;
    let key = KeyBytes::from_slice(&raw).map_err(|_| anyhow::anyhow!("KEK must decode to exactly 32 bytes"));
    raw.zeroize();
    Ok((format!("local:{id}"), key?))
}

#[async_trait]
impl KeyProvider for LocalKek {
    fn current_kek_id(&self) -> String {
        self.current.clone()
    }

    async fn wrap(&self, tenant: TenantId, version: u32, dek: &KeyBytes) -> Result<Vec<u8>> {
        let kek = &self.keys[&self.current];
        let nonce = random_nonce();
        let ct = kek
            .cipher()
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &dek.0, aad: &wrap_aad(tenant, version) })
            .map_err(|_| Error::internal(anyhow::anyhow!("DEK wrap failed")))?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }

    async fn unwrap(&self, tenant: TenantId, version: u32, kek_id: &str, wrapped: &[u8]) -> Result<KeyBytes> {
        let kek = self
            .keys
            .get(kek_id)
            .ok_or_else(|| Error::internal(anyhow::anyhow!("KEK {kek_id} is not configured")))?;
        if wrapped.len() != 12 + 32 + TAG_LEN {
            return Err(Error::internal(anyhow::anyhow!("wrapped DEK has the wrong length")));
        }
        let (nonce, ct) = wrapped.split_at(12);
        let mut pt = kek
            .cipher()
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &wrap_aad(tenant, version) })
            .map_err(|_| Error::internal(anyhow::anyhow!("DEK unwrap failed (wrong KEK or tampered key row)")))?;
        let key = KeyBytes::from_slice(&pt);
        pt.zeroize();
        key
    }
}

/// AWS KMS key provider. The encryption context binds every wrapped DEK to
/// its tenant and version, and shows up in CloudTrail for each use.
#[cfg(feature = "aws-kms")]
pub struct AwsKms {
    client: aws_sdk_kms::Client,
    key_id: String,
    /// Earlier keys that may still wrap old DEKs (until `rewrap` has run).
    retired: Vec<String>,
}

#[cfg(feature = "aws-kms")]
impl AwsKms {
    /// `BP_KMS_KEY_ID`: key id, ARN or alias of a symmetric KMS key (one
    /// shared key for all tenants; isolation comes from the per-tenant DEKs
    /// and the encryption context). `BP_KMS_KEY_ID_RETIRED`: comma-separated
    /// earlier keys still allowed for unwrapping.
    pub async fn from_env() -> anyhow::Result<Self> {
        let key_id = std::env::var("BP_KMS_KEY_ID").map_err(|_| anyhow::anyhow!("BP_KMS_KEY_ID is not set"))?;
        let retired = std::env::var("BP_KMS_KEY_ID_RETIRED")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        let conf = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Ok(Self { client: aws_sdk_kms::Client::new(&conf), key_id, retired })
    }
}

#[cfg(feature = "aws-kms")]
#[async_trait]
impl KeyProvider for AwsKms {
    fn current_kek_id(&self) -> String {
        format!("aws-kms:{}", self.key_id)
    }

    async fn wrap(&self, tenant: TenantId, version: u32, dek: &KeyBytes) -> Result<Vec<u8>> {
        let out = self
            .client
            .encrypt()
            .key_id(&self.key_id)
            .plaintext(aws_sdk_kms::primitives::Blob::new(dek.0.to_vec()))
            .encryption_context("bpe:tenant_id", tenant.to_string())
            .encryption_context("bpe:key_version", version.to_string())
            .send()
            .await
            .map_err(|e| Error::upstream(anyhow::anyhow!("KMS Encrypt failed: {}", aws_sdk_kms::error::DisplayErrorContext(&e))))?;
        Ok(out.ciphertext_blob.map(|b| b.into_inner()).unwrap_or_default())
    }

    async fn unwrap(&self, tenant: TenantId, version: u32, kek_id: &str, wrapped: &[u8]) -> Result<KeyBytes> {
        // The key id comes from a database row: only ever use a key this
        // deployment was configured with, never whatever the row names.
        let named = kek_id.strip_prefix("aws-kms:").unwrap_or(kek_id);
        let key_id = if named == self.key_id {
            &self.key_id
        } else {
            self.retired
                .iter()
                .find(|k| k.as_str() == named)
                .ok_or_else(|| Error::internal(anyhow::anyhow!("KMS key {named} is not configured")))?
        };
        let out = self
            .client
            .decrypt()
            .key_id(key_id)
            .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(wrapped.to_vec()))
            .encryption_context("bpe:tenant_id", tenant.to_string())
            .encryption_context("bpe:key_version", version.to_string())
            .send()
            .await
            .map_err(|e| Error::upstream(anyhow::anyhow!("KMS Decrypt failed: {}", aws_sdk_kms::error::DisplayErrorContext(&e))))?;
        let mut pt = out.plaintext.map(|b| b.into_inner()).unwrap_or_default();
        let key = KeyBytes::from_slice(&pt);
        pt.zeroize();
        key
    }
}

/// Pick the provider from `BP_KMS_PROVIDER` (`local` (default) or `aws`).
pub async fn provider_from_env() -> anyhow::Result<Arc<dyn KeyProvider>> {
    match std::env::var("BP_KMS_PROVIDER").as_deref().unwrap_or("local") {
        "local" | "" => Ok(Arc::new(LocalKek::from_env()?)),
        #[cfg(feature = "aws-kms")]
        "aws" => Ok(Arc::new(AwsKms::from_env().await?)),
        #[cfg(not(feature = "aws-kms"))]
        "aws" => anyhow::bail!("BP_KMS_PROVIDER=aws needs a build with the `aws-kms` feature"),
        other => anyhow::bail!("unknown BP_KMS_PROVIDER {other:?} (use local or aws)"),
    }
}

// --------------------------------------------------------------- DEK store

/// A wrapped DEK row.
#[derive(Clone)]
pub struct WrappedDek {
    pub version: u32,
    pub kek_id: String,
    pub wrapped: Vec<u8>,
}

/// Where wrapped DEKs are kept (`tenant_keys` in Postgres; memory in tests).
#[async_trait]
pub trait DekStore: Send + Sync + 'static {
    async fn latest(&self, tenant: TenantId) -> Result<Option<WrappedDek>>;
    async fn get(&self, tenant: TenantId, version: u32) -> Result<Option<WrappedDek>>;
    async fn all(&self, tenant: TenantId) -> Result<Vec<WrappedDek>>;
    /// Insert a new version. Returns false if that version already exists
    /// (another instance won the race).
    async fn insert(&self, tenant: TenantId, dek: &WrappedDek) -> Result<bool>;
    /// Replace the wrapping of an existing version (KEK rotation).
    async fn rewrap(&self, tenant: TenantId, dek: &WrappedDek) -> Result<()>;
}

pub struct PgDekStore {
    db: Db,
}

impl PgDekStore {
    pub fn new(db: Db) -> Self {
        Self { db }
    }
}

fn dek_row(r: sqlx::postgres::PgRow) -> WrappedDek {
    use sqlx::Row;
    WrappedDek { version: r.get::<i32, _>("version") as u32, kek_id: r.get("kek_id"), wrapped: r.get("wrapped_dek") }
}

#[async_trait]
impl DekStore for PgDekStore {
    async fn latest(&self, tenant: TenantId) -> Result<Option<WrappedDek>> {
        let mut tx = self.db.tenant_tx(tenant).await?;
        let r = sqlx::query("SELECT version, kek_id, wrapped_dek FROM tenant_keys WHERE tenant_id = $1 ORDER BY version DESC LIMIT 1")
            .bind(tenant.0)
            .fetch_optional(&mut *tx)
            .await?;
        Ok(r.map(dek_row))
    }

    async fn get(&self, tenant: TenantId, version: u32) -> Result<Option<WrappedDek>> {
        let mut tx = self.db.tenant_tx(tenant).await?;
        let r = sqlx::query("SELECT version, kek_id, wrapped_dek FROM tenant_keys WHERE tenant_id = $1 AND version = $2")
            .bind(tenant.0)
            .bind(version as i32)
            .fetch_optional(&mut *tx)
            .await?;
        Ok(r.map(dek_row))
    }

    async fn all(&self, tenant: TenantId) -> Result<Vec<WrappedDek>> {
        let mut tx = self.db.tenant_tx(tenant).await?;
        let rows = sqlx::query("SELECT version, kek_id, wrapped_dek FROM tenant_keys WHERE tenant_id = $1 ORDER BY version")
            .bind(tenant.0)
            .fetch_all(&mut *tx)
            .await?;
        Ok(rows.into_iter().map(dek_row).collect())
    }

    async fn insert(&self, tenant: TenantId, dek: &WrappedDek) -> Result<bool> {
        let mut tx = self.db.tenant_tx(tenant).await?;
        let n = sqlx::query(
            "INSERT INTO tenant_keys (tenant_id, version, kek_id, wrapped_dek) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (tenant_id, version) DO NOTHING",
        )
        .bind(tenant.0)
        .bind(dek.version as i32)
        .bind(&dek.kek_id)
        .bind(&dek.wrapped)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        Ok(n == 1)
    }

    async fn rewrap(&self, tenant: TenantId, dek: &WrappedDek) -> Result<()> {
        let mut tx = self.db.tenant_tx(tenant).await?;
        sqlx::query("UPDATE tenant_keys SET kek_id = $3, wrapped_dek = $4 WHERE tenant_id = $1 AND version = $2")
            .bind(tenant.0)
            .bind(dek.version as i32)
            .bind(&dek.kek_id)
            .bind(&dek.wrapped)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

/// In-memory store for tests and tools.
#[derive(Default)]
pub struct MemDekStore {
    rows: Mutex<HashMap<(TenantId, u32), WrappedDek>>,
}

#[async_trait]
impl DekStore for MemDekStore {
    async fn latest(&self, tenant: TenantId) -> Result<Option<WrappedDek>> {
        let rows = self.rows.lock().unwrap();
        Ok(rows.iter().filter(|((t, _), _)| *t == tenant).max_by_key(|((_, v), _)| *v).map(|(_, d)| d.clone()))
    }
    async fn get(&self, tenant: TenantId, version: u32) -> Result<Option<WrappedDek>> {
        Ok(self.rows.lock().unwrap().get(&(tenant, version)).cloned())
    }
    async fn all(&self, tenant: TenantId) -> Result<Vec<WrappedDek>> {
        let rows = self.rows.lock().unwrap();
        let mut v: Vec<_> = rows.iter().filter(|((t, _), _)| *t == tenant).map(|(_, d)| d.clone()).collect();
        v.sort_by_key(|d| d.version);
        Ok(v)
    }
    async fn insert(&self, tenant: TenantId, dek: &WrappedDek) -> Result<bool> {
        let mut rows = self.rows.lock().unwrap();
        if rows.contains_key(&(tenant, dek.version)) {
            return Ok(false);
        }
        rows.insert((tenant, dek.version), dek.clone());
        Ok(true)
    }
    async fn rewrap(&self, tenant: TenantId, dek: &WrappedDek) -> Result<()> {
        self.rows.lock().unwrap().insert((tenant, dek.version), dek.clone());
        Ok(())
    }
}

// --------------------------------------------------------- envelope cipher

type DekCache = HashMap<(TenantId, u32), (Arc<KeyBytes>, Instant)>;

struct Inner {
    provider: Arc<dyn KeyProvider>,
    store: Arc<dyn DekStore>,
    /// Unwrapped DEKs, keyed by tenant AND version: a lookup for one tenant
    /// can never return another tenant's key.
    deks: Mutex<DekCache>,
    current: Mutex<HashMap<TenantId, (u32, Instant)>>,
}

/// Seals and opens payloads with the calling tenant's DEK.
#[derive(Clone)]
pub struct EnvelopeCipher {
    inner: Arc<Inner>,
}

/// Public facts about one DEK version (never the key).
#[derive(Clone, Debug, serde::Serialize)]
pub struct KeyInfo {
    pub version: u32,
    pub kek_id: String,
    pub current: bool,
}

impl EnvelopeCipher {
    pub fn new(provider: Arc<dyn KeyProvider>, store: Arc<dyn DekStore>) -> Self {
        Self {
            inner: Arc::new(Inner {
                provider,
                store,
                deks: Mutex::new(HashMap::new()),
                current: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Encrypt `plaintext` for `tenant`. Pass an `aad` that names where the
    /// blob will live (`table|row_id|field`) and pass the same to [`Self::open`].
    pub async fn seal(&self, tenant: TenantId, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let (version, dek) = self.current_dek(tenant).await?;
        let nonce = random_nonce();
        let ct = dek
            .cipher()
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &full_aad(tenant, version, aad) })
            .map_err(|_| Error::internal(anyhow::anyhow!("encryption failed")))?;
        let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt a blob sealed for `tenant` with the same `aad`. Any mismatch
    /// (tenant, aad, key version, a flipped bit) is one indistinguishable error.
    pub async fn open(&self, tenant: TenantId, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
        let fail = || Error::internal(anyhow::anyhow!("decryption failed"));
        if blob.len() < HEADER_LEN + TAG_LEN || &blob[..4] != MAGIC {
            return Err(fail());
        }
        let version = u32::from_be_bytes(blob[4..8].try_into().unwrap());
        let nonce = &blob[8..HEADER_LEN];
        let dek = self.dek(tenant, version).await?.ok_or_else(fail)?;
        dek.cipher()
            .decrypt(Nonce::from_slice(nonce), Payload { msg: &blob[HEADER_LEN..], aad: &full_aad(tenant, version, aad) })
            .map_err(|_| fail())
    }

    pub async fn seal_str(&self, tenant: TenantId, aad: &[u8], plaintext: &str) -> Result<Vec<u8>> {
        self.seal(tenant, aad, plaintext.as_bytes()).await
    }

    pub async fn open_str(&self, tenant: TenantId, aad: &[u8], blob: &[u8]) -> Result<String> {
        String::from_utf8(self.open(tenant, aad, blob).await?)
            .map_err(|_| Error::internal(anyhow::anyhow!("decrypted payload is not UTF-8")))
    }

    /// The key version a blob was sealed under (to find rows to re-seal after a rotation).
    pub fn blob_key_version(blob: &[u8]) -> Option<u32> {
        (blob.len() >= HEADER_LEN + TAG_LEN && &blob[..4] == MAGIC)
            .then(|| u32::from_be_bytes(blob[4..8].try_into().unwrap()))
    }

    /// Start a new DEK version for the tenant. New seals use it; older
    /// versions stay available for opening until their data is re-sealed.
    pub async fn rotate_dek(&self, tenant: TenantId) -> Result<u32> {
        loop {
            let next = self.inner.store.latest(tenant).await?.map(|d| d.version + 1).unwrap_or(1);
            if self.create_version(tenant, next).await? {
                self.inner.current.lock().unwrap().insert(tenant, (next, Instant::now()));
                return Ok(next);
            }
        }
    }

    /// Re-wrap every DEK version of the tenant under the provider's current
    /// KEK (after rotating the master key). Returns how many were re-wrapped.
    pub async fn rewrap(&self, tenant: TenantId) -> Result<u32> {
        let target = self.inner.provider.current_kek_id();
        let mut n = 0;
        for row in self.inner.store.all(tenant).await? {
            if row.kek_id == target {
                continue;
            }
            let dek = self.inner.provider.unwrap(tenant, row.version, &row.kek_id, &row.wrapped).await?;
            let wrapped = self.inner.provider.wrap(tenant, row.version, &dek).await?;
            self.inner
                .store
                .rewrap(tenant, &WrappedDek { version: row.version, kek_id: target.clone(), wrapped })
                .await?;
            n += 1;
        }
        Ok(n)
    }

    /// Drop every cached key of a tenant from this process (after deleting
    /// its key rows to crypto-shred it; other processes follow within
    /// `DEK_TTL`).
    pub fn forget(&self, tenant: TenantId) {
        self.inner.deks.lock().unwrap().retain(|(t, _), _| *t != tenant);
        self.inner.current.lock().unwrap().remove(&tenant);
    }

    pub async fn key_info(&self, tenant: TenantId) -> Result<Vec<KeyInfo>> {
        let rows = self.inner.store.all(tenant).await?;
        let latest = rows.iter().map(|r| r.version).max();
        Ok(rows
            .into_iter()
            .map(|r| KeyInfo { current: Some(r.version) == latest, version: r.version, kek_id: r.kek_id })
            .collect())
    }

    async fn create_version(&self, tenant: TenantId, version: u32) -> Result<bool> {
        let dek = KeyBytes::generate();
        let wrapped = self.inner.provider.wrap(tenant, version, &dek).await?;
        let row = WrappedDek { version, kek_id: self.inner.provider.current_kek_id(), wrapped };
        if !self.inner.store.insert(tenant, &row).await? {
            return Ok(false);
        }
        self.inner.deks.lock().unwrap().insert((tenant, version), (Arc::new(dek), Instant::now()));
        Ok(true)
    }

    async fn current_dek(&self, tenant: TenantId) -> Result<(u32, Arc<KeyBytes>)> {
        let cached = self.inner.current.lock().unwrap().get(&tenant).copied();
        let version = match cached {
            Some((v, at)) if at.elapsed() < CURRENT_TTL => v,
            _ => {
                let v = match self.inner.store.latest(tenant).await? {
                    Some(d) => d.version,
                    None => {
                        // First use: create version 1. If another instance got
                        // there first, use theirs.
                        self.create_version(tenant, 1).await?;
                        1
                    }
                };
                self.inner.current.lock().unwrap().insert(tenant, (v, Instant::now()));
                v
            }
        };
        let dek = self
            .dek(tenant, version)
            .await?
            .ok_or_else(|| Error::internal(anyhow::anyhow!("current DEK version is missing")))?;
        Ok((version, dek))
    }

    async fn dek(&self, tenant: TenantId, version: u32) -> Result<Option<Arc<KeyBytes>>> {
        {
            let mut deks = self.inner.deks.lock().unwrap();
            match deks.get(&(tenant, version)) {
                Some((k, at)) if at.elapsed() < DEK_TTL => return Ok(Some(k.clone())),
                Some(_) => {
                    deks.remove(&(tenant, version));
                }
                None => {}
            }
        }
        let Some(row) = self.inner.store.get(tenant, version).await? else {
            return Ok(None);
        };
        let key = Arc::new(self.inner.provider.unwrap(tenant, version, &row.kek_id, &row.wrapped).await?);
        self.inner.deks.lock().unwrap().insert((tenant, version), (key.clone(), Instant::now()));
        Ok(Some(key))
    }
}

fn full_aad(tenant: TenantId, version: u32, aad: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + 16 + 4 + aad.len());
    v.extend_from_slice(b"bpe-env1");
    v.extend_from_slice(tenant.0.as_bytes());
    v.extend_from_slice(&version.to_be_bytes());
    v.extend_from_slice(aad);
    v
}

/// SHA-256, for token and state hashes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}

/// Constant-time equality for secrets and hashes.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// `n` random bytes, URL-safe base64 without padding.
pub fn random_token(n: usize) -> String {
    use base64::Engine;
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher_with(store: Arc<MemDekStore>, kek: LocalKek) -> EnvelopeCipher {
        EnvelopeCipher::new(Arc::new(kek), store)
    }

    fn kek(id: &str, byte: u8) -> LocalKek {
        LocalKek::new(format!("local:{id}"), KeyBytes([byte; 32]))
    }

    fn cipher() -> EnvelopeCipher {
        cipher_with(Arc::new(MemDekStore::default()), kek("k1", 7))
    }

    #[tokio::test]
    async fn round_trip() {
        let c = cipher();
        let t = TenantId::new();
        let blob = c.seal(t, b"orders|1|quote", b"PO 4411, 250 boards").await.unwrap();
        assert_eq!(&blob[..4], b"BPE1");
        assert_eq!(EnvelopeCipher::blob_key_version(&blob), Some(1));
        assert!(!blob.windows(7).any(|w| w == b"PO 4411"));
        assert_eq!(c.open(t, b"orders|1|quote", &blob).await.unwrap(), b"PO 4411, 250 boards");
    }

    #[tokio::test]
    async fn nonces_are_fresh() {
        let c = cipher();
        let t = TenantId::new();
        let a = c.seal(t, b"x", b"same").await.unwrap();
        let b = c.seal(t, b"x", b"same").await.unwrap();
        assert_ne!(a, b);
        assert_ne!(a[8..20], b[8..20]);
    }

    #[tokio::test]
    async fn another_tenant_cannot_open() {
        let c = cipher();
        let (a, b) = (TenantId::new(), TenantId::new());
        let blob = c.seal(a, b"x", b"secret").await.unwrap();
        // b has its own DEK (created on first use) and a different AAD.
        c.seal(b, b"x", b"warm up").await.unwrap();
        assert!(c.open(b, b"x", &blob).await.is_err());
    }

    #[tokio::test]
    async fn tenants_get_different_deks() {
        let store = Arc::new(MemDekStore::default());
        let c = cipher_with(store.clone(), kek("k1", 7));
        let (a, b) = (TenantId::new(), TenantId::new());
        c.seal(a, b"", b"1").await.unwrap();
        c.seal(b, b"", b"1").await.unwrap();
        let ka = c.dek(a, 1).await.unwrap().unwrap();
        let kb = c.dek(b, 1).await.unwrap().unwrap();
        assert_ne!(ka.0, kb.0);
        // A wrapped DEK row copied to another tenant does not unwrap there.
        let row = store.get(a, 1).await.unwrap().unwrap();
        let p = kek("k1", 7);
        assert!(p.unwrap(b, 1, &row.kek_id, &row.wrapped).await.is_err());
        assert!(p.unwrap(a, 2, &row.kek_id, &row.wrapped).await.is_err());
        assert!(p.unwrap(a, 1, &row.kek_id, &row.wrapped).await.is_ok());
    }

    #[tokio::test]
    async fn wrong_aad_or_tampering_fails() {
        let c = cipher();
        let t = TenantId::new();
        let blob = c.seal(t, b"orders|1|quote", b"secret").await.unwrap();
        assert!(c.open(t, b"orders|2|quote", &blob).await.is_err());
        for i in [0, 5, 10, 22, blob.len() - 1] {
            let mut bad = blob.clone();
            bad[i] ^= 1;
            assert!(c.open(t, b"orders|1|quote", &bad).await.is_err(), "byte {i}");
        }
        assert!(c.open(t, b"orders|1|quote", &blob[..10]).await.is_err());
        assert!(c.open(t, b"orders|1|quote", b"").await.is_err());
    }

    #[tokio::test]
    async fn rotation_keeps_old_blobs_readable() {
        let c = cipher();
        let t = TenantId::new();
        let old = c.seal(t, b"a", b"before").await.unwrap();
        assert_eq!(c.rotate_dek(t).await.unwrap(), 2);
        let new = c.seal(t, b"a", b"after").await.unwrap();
        assert_eq!(EnvelopeCipher::blob_key_version(&new), Some(2));
        assert_eq!(c.open(t, b"a", &old).await.unwrap(), b"before");
        assert_eq!(c.open(t, b"a", &new).await.unwrap(), b"after");
        let info = c.key_info(t).await.unwrap();
        assert_eq!(info.len(), 2);
        assert!(info[1].current && !info[0].current);
    }

    #[tokio::test]
    async fn kek_rotation_rewraps_and_old_kek_can_be_retired() {
        let store = Arc::new(MemDekStore::default());
        let t = TenantId::new();
        let blob = cipher_with(store.clone(), kek("k1", 7)).seal(t, b"a", b"data").await.unwrap();

        // New KEK current, old one still available: rewrap.
        let c2 = cipher_with(store.clone(), kek("k2", 9).with_retired("local:k1", KeyBytes([7; 32])));
        assert_eq!(c2.rewrap(t).await.unwrap(), 1);
        assert_eq!(c2.rewrap(t).await.unwrap(), 0);
        assert_eq!(store.get(t, 1).await.unwrap().unwrap().kek_id, "local:k2");

        // A process that only has the new KEK reads everything.
        let c3 = cipher_with(store.clone(), kek("k2", 9));
        assert_eq!(c3.open(t, b"a", &blob).await.unwrap(), b"data");
        // And one with only the old KEK no longer can.
        let c4 = cipher_with(store, kek("k1", 7));
        assert!(c4.open(t, b"a", &blob).await.is_err());
    }

    #[tokio::test]
    async fn forgetting_a_shredded_tenant_makes_its_data_unreadable() {
        let store = Arc::new(MemDekStore::default());
        let c = cipher_with(store.clone(), kek("k1", 7));
        let t = TenantId::new();
        let blob = c.seal(t, b"", b"x").await.unwrap();
        store.rows.lock().unwrap().clear(); // key rows deleted
        assert!(c.open(t, b"", &blob).await.is_ok(), "still cached");
        c.forget(t);
        assert!(c.open(t, b"", &blob).await.is_err());
    }

    #[tokio::test]
    async fn two_instances_share_one_dek() {
        let store = Arc::new(MemDekStore::default());
        let t = TenantId::new();
        let a = cipher_with(store.clone(), kek("k1", 7));
        let b = cipher_with(store.clone(), kek("k1", 7));
        let blob = a.seal(t, b"", b"x").await.unwrap();
        assert_eq!(b.open(t, b"", &blob).await.unwrap(), b"x");
        assert_eq!(store.all(t).await.unwrap().len(), 1);
    }

    #[test]
    fn kek_parsing() {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        let (id, _) = parse_kek(&format!("prod-1:{b64}")).unwrap();
        assert_eq!(id, "local:prod-1");
        assert!(parse_kek(&b64).is_err());
        assert!(parse_kek("k:AAAA").is_err());
        assert!(parse_kek(&format!("bad id:{b64}")).is_err());
    }

    #[test]
    fn helpers() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert_ne!(random_token(32), random_token(32));
        assert_eq!(random_token(32).len(), 43);
    }
}
