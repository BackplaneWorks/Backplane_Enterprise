//! Boat VM Device Certificate Authority & strict mTLS identity verifier.
//!
//! Every Boat VM authenticates to `bp-ent-relay` using a short-lived
//! (<= 24h) X.509 client certificate signed by `BoatCa`. The certificate carries
//! a single SPIFFE URI Subject Alternative Name:
//!
//!   `spiffe://backplane.enterprise/tenant/<tenant_uuid>/vm/<vm_uuid>`
//!
//! `bp-ent-relay` extracts `(tenant_id, vm_id)` exclusively from this verified
//! peer certificate and ignores any client-supplied headers.

use bp_ent_core::{Error, Result, Secret, TenantId};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
    SerialNumber,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fmt;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

/// Hard security cap from the specification: device certs may never exceed 24h.
pub const MAX_DEVICE_CERT_TTL_SECS: u64 = 24 * 60 * 60;
pub const SPIFFE_PREFIX: &str = "spiffe://backplane.enterprise/tenant/";

/// Verified identity derived solely from the mTLS peer leaf certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBoatIdentity {
    pub tenant_id: TenantId,
    pub vm_id: Uuid,
    pub serial_hex: String,
    pub spiffe_uri: String,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

/// Issued short-lived Boat device certificate bundle (admin-triggered provisioning).
#[derive(Clone)]
pub struct IssuedDeviceCert {
    pub serial_hex: String,
    pub spiffe_uri: String,
    pub cert_pem: String,
    pub key_pem: Secret<String>,
    pub ca_cert_pem: String,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for IssuedDeviceCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedDeviceCert")
            .field("serial_hex", &self.serial_hex)
            .field("spiffe_uri", &self.spiffe_uri)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Signed certificate returned to a VM that generated its own keypair + CSR
/// (the private key never leaves the Boat VM).
#[derive(Clone, Debug)]
pub struct SignedDeviceCert {
    pub serial_hex: String,
    pub spiffe_uri: String,
    pub cert_pem: String,
    pub ca_cert_pem: String,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// Certificate Authority that signs and verifies Boat VM mTLS certificates.
/// Private key material is held in `Secret<String>` (zeroized on drop, never logged).
#[derive(Clone)]
pub struct BoatCa {
    ca_cert_pem: String,
    ca_cert_der: Vec<u8>,
    ca_key_pem: Secret<String>,
}

impl fmt::Debug for BoatCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoatCa")
            .field("ca_cert_der_len", &self.ca_cert_der.len())
            .finish_non_exhaustive()
    }
}

impl BoatCa {
    /// Generate an ephemeral in-memory Boat CA (only for explicit dev/test use).
    pub fn generate_ephemeral(common_name: &str) -> Result<Self> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, "Backplane Enterprise");
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;

        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::days(365);

        let key = KeyPair::generate().map_err(|e| Error::internal(anyhow::anyhow!("{e}")))?;
        let cert = params
            .self_signed(&key)
            .map_err(|e| Error::internal(anyhow::anyhow!("{e}")))?;

        Ok(Self {
            ca_cert_pem: cert.pem(),
            ca_cert_der: cert.der().to_vec(),
            ca_key_pem: Secret::new(key.serialize_pem()),
        })
    }

    /// Construct from existing PEM-encoded CA certificate and private key.
    pub fn from_pem(ca_cert_pem: String, ca_key_pem: Secret<String>) -> Result<Self> {
        let mut reader = std::io::Cursor::new(ca_cert_pem.as_bytes());
        let cert = rustls_pemfile::certs(&mut reader)
            .next()
            .transpose()
            .map_err(|e| Error::invalid(format!("invalid CA cert PEM: {e}")))?
            .ok_or_else(|| Error::invalid("empty CA cert PEM"))?;
        KeyPair::from_pem(ca_key_pem.expose())
            .map_err(|e| Error::invalid(format!("invalid CA key PEM: {e}")))?;

        Ok(Self {
            ca_cert_pem,
            ca_cert_der: cert.to_vec(),
            ca_key_pem,
        })
    }

    /// Fail-closed CA loader:
    /// 1. `BP_BOAT_CA_CERT_FILE` + `BP_BOAT_CA_KEY_FILE` (preferred in production)
    /// 2. `BP_BOAT_CA_CERT_PEM` + `BP_BOAT_CA_KEY_PEM` (e.g. Secrets Manager injection)
    /// 3. Ephemeral CA ONLY if `BP_BOAT_CA_EPHEMERAL=1` is explicitly set (dev/compose).
    pub fn from_env() -> anyhow::Result<Self> {
        if let (Ok(cert_path), Ok(key_path)) = (
            std::env::var("BP_BOAT_CA_CERT_FILE"),
            std::env::var("BP_BOAT_CA_KEY_FILE"),
        ) {
            if !cert_path.trim().is_empty() && !key_path.trim().is_empty() {
                let cert_pem = std::fs::read_to_string(&cert_path)
                    .map_err(|e| anyhow::anyhow!("failed reading BP_BOAT_CA_CERT_FILE: {e}"))?;
                let key_pem = std::fs::read_to_string(&key_path)
                    .map_err(|e| anyhow::anyhow!("failed reading BP_BOAT_CA_KEY_FILE: {e}"))?;
                return Self::from_pem(cert_pem, Secret::new(key_pem))
                    .map_err(|e| anyhow::anyhow!("invalid Boat CA PEM files: {e}"));
            }
        }

        if let (Ok(cert), Ok(key)) = (
            std::env::var("BP_BOAT_CA_CERT_PEM"),
            std::env::var("BP_BOAT_CA_KEY_PEM"),
        ) {
            if !cert.trim().is_empty() && !key.trim().is_empty() {
                return Self::from_pem(cert, Secret::new(key))
                    .map_err(|e| anyhow::anyhow!("invalid Boat CA env PEMs: {e}"));
            }
        }

        if bp_ent_core::config::env_flag("BP_BOAT_CA_EPHEMERAL") {
            tracing::warn!("BP_BOAT_CA_EPHEMERAL=1 active — generating in-memory Boat CA (dev only)");
            return Self::generate_ephemeral("Backplane Enterprise Ephemeral Boat CA")
                .map_err(|e| anyhow::anyhow!("{e}"));
        }

        anyhow::bail!(
            "Boat CA not configured: set BP_BOAT_CA_CERT_FILE/BP_BOAT_CA_KEY_FILE \
             (or BP_BOAT_CA_CERT_PEM/BP_BOAT_CA_KEY_PEM, or BP_BOAT_CA_EPHEMERAL=1 for dev)"
        );
    }

    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    pub fn ca_cert_der(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.ca_cert_der.clone())
    }

    /// Sign a short-lived server certificate for `MtlsRelayServer`.
    pub fn issue_server_cert(
        &self,
        dns_names: &[&str],
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let ca_key = KeyPair::from_pem(self.ca_key_pem.expose())
            .map_err(|e| Error::internal(anyhow::anyhow!("CA key parse failed: {e}")))?;
        let ca_cert = self.reconstruct_ca_cert(&ca_key)?;

        let mut params = CertificateParams::new(
            dns_names.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
        )
        .map_err(|e| Error::invalid(format!("invalid server SANs: {e}")))?;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(1);
        params.not_after = now + time::Duration::days(7);

        let key = KeyPair::generate().map_err(|e| Error::internal(anyhow::anyhow!("{e}")))?;
        let cert = params
            .signed_by(&key, &ca_cert, &ca_key)
            .map_err(|e| Error::internal(anyhow::anyhow!("sign server cert: {e}")))?;

        let key_der = PrivateKeyDer::try_from(key.serialize_der())
            .map_err(|e| Error::internal(anyhow::anyhow!("server key der: {e}")))?;

        Ok((vec![CertificateDer::from(cert.der().to_vec())], key_der))
    }

    /// Sign a VM-generated CSR into a `<= 24h` mTLS client certificate.
    /// Security: ALL certificate params (SAN, IsCa=NoCa, ClientAuth EKU, DN,
    /// serial, validity) are overwritten by the CA for `(tenant_id, vm_id)` —
    /// any extensions or SANs requested in the CSR are ignored/stripped.
    pub fn sign_device_csr(
        &self,
        csr_pem: &str,
        tenant_id: TenantId,
        vm_id: Uuid,
        ttl: Duration,
    ) -> Result<SignedDeviceCert> {
        let (params, serial_hex, spiffe_uri, issued_at, expires_at) =
            build_device_cert_params(tenant_id, vm_id, ttl)?;

        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|_| Error::invalid("invalid PEM certificate signing request"))?;
        // Overwrite every field — never honor CSR-supplied SANs, CA flags, or validity.
        csr.params = params;

        let ca_key = KeyPair::from_pem(self.ca_key_pem.expose())
            .map_err(|e| Error::internal(anyhow::anyhow!("CA key parse failed: {e}")))?;
        let ca_cert = self.reconstruct_ca_cert(&ca_key)?;
        let leaf_cert = csr
            .signed_by(&ca_cert, &ca_key)
            .map_err(|e| Error::internal(anyhow::anyhow!("sign device CSR: {e}")))?;

        Ok(SignedDeviceCert {
            serial_hex,
            spiffe_uri,
            cert_pem: leaf_cert.pem(),
            ca_cert_pem: self.ca_cert_pem.clone(),
            issued_at,
            expires_at,
        })
    }

    /// Issue a device client certificate bound strictly to `(tenant_id, vm_id)`
    /// with TTL strictly capped at `<= 24h` (`MAX_DEVICE_CERT_TTL_SECS`).
    pub fn issue_device_cert(
        &self,
        tenant_id: TenantId,
        vm_id: Uuid,
        ttl: Duration,
    ) -> Result<IssuedDeviceCert> {
        let (params, serial_hex, spiffe_uri, issued_at, expires_at) =
            build_device_cert_params(tenant_id, vm_id, ttl)?;

        let ca_key = KeyPair::from_pem(self.ca_key_pem.expose())
            .map_err(|e| Error::internal(anyhow::anyhow!("CA key parse failed: {e}")))?;
        let ca_cert = self.reconstruct_ca_cert(&ca_key)?;

        let leaf_key = KeyPair::generate().map_err(|e| Error::internal(anyhow::anyhow!("{e}")))?;
        let leaf_cert = params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .map_err(|e| Error::internal(anyhow::anyhow!("sign device cert: {e}")))?;

        Ok(IssuedDeviceCert {
            serial_hex,
            spiffe_uri,
            cert_pem: leaf_cert.pem(),
            key_pem: Secret::new(leaf_key.serialize_pem()),
            ca_cert_pem: self.ca_cert_pem.clone(),
            issued_at,
            expires_at,
        })
    }

    fn reconstruct_ca_cert(&self, ca_key: &KeyPair) -> Result<Certificate> {
        let mut params = CertificateParams::from_ca_cert_pem(&self.ca_cert_pem)
            .map_err(|e| Error::internal(anyhow::anyhow!("parse CA params: {e}")))?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .self_signed(ca_key)
            .map_err(|e| Error::internal(anyhow::anyhow!("reconstruct CA cert: {e}")))
    }
}

fn build_device_cert_params(
    tenant_id: TenantId,
    vm_id: Uuid,
    ttl: Duration,
) -> Result<(CertificateParams, String, String, OffsetDateTime, OffsetDateTime)> {
    if ttl.is_zero() || ttl.as_secs() > MAX_DEVICE_CERT_TTL_SECS {
        return Err(Error::invalid(format!(
            "device certificate TTL must be between 1s and {MAX_DEVICE_CERT_TTL_SECS}s (24h)"
        )));
    }

    let spiffe_uri = format_spiffe_uri(tenant_id, vm_id);
    let mut serial_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut serial_bytes);
    serial_bytes[0] &= 0x7f; // positive ASN.1 integer
    serial_bytes[0] |= 0x01; // non-zero leading byte
    let serial_hex = hex::encode(serial_bytes);

    let now = OffsetDateTime::now_utc();
    let expires_at = now + time::Duration::seconds(ttl.as_secs() as i64);

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::NoCa;
    params.serial_number = Some(SerialNumber::from_slice(&serial_bytes));
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.not_before = now;
    params.not_after = expires_at;
    params.subject_alt_names = vec![SanType::URI(
        spiffe_uri
            .clone()
            .try_into()
            .map_err(|e| Error::internal(anyhow::anyhow!("invalid SPIFFE URI: {e}")))?,
    )];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("boat-{vm_id}"));
    dn.push(DnType::OrganizationName, tenant_id.to_string());
    params.distinguished_name = dn;

    Ok((params, serial_hex, spiffe_uri, now, expires_at))
}

pub fn format_spiffe_uri(tenant_id: TenantId, vm_id: Uuid) -> String {
    format!("{SPIFFE_PREFIX}{tenant_id}/vm/{vm_id}")
}

pub fn parse_spiffe_uri(uri: &str) -> Result<(TenantId, Uuid)> {
    let rest = uri
        .strip_prefix(SPIFFE_PREFIX)
        .ok_or(Error::Unauthorized)?;
    let (tenant_str, vm_part) = rest.split_once("/vm/").ok_or(Error::Unauthorized)?;
    if vm_part.contains('/') {
        return Err(Error::Unauthorized);
    }
    let tenant_id = tenant_str
        .parse::<TenantId>()
        .map_err(|_| Error::Unauthorized)?;
    let vm_id = vm_part.parse::<Uuid>().map_err(|_| Error::Unauthorized)?;
    Ok((tenant_id, vm_id))
}

/// Inspect a verified peer X.509 leaf certificate (already cryptographically
/// verified against `BoatCa` by rustls `WebPkiClientVerifier`) and enforce:
/// - non-CA leaf certificate
/// - validity window `not_before <= now <= not_after`
/// - maximum lifetime `not_after - not_before <= 24h`
/// - exactly one URI SAN matching `spiffe://backplane.enterprise/tenant/<uuid>/vm/<uuid>`
pub fn verify_client_cert_der(cert_der: &[u8], now: OffsetDateTime) -> Result<VerifiedBoatIdentity> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|_| Error::Unauthorized)?;

    if cert.is_ca() {
        return Err(Error::Unauthorized);
    }

    let not_before = OffsetDateTime::from_unix_timestamp(cert.validity().not_before.timestamp())
        .map_err(|_| Error::Unauthorized)?;
    let not_after = OffsetDateTime::from_unix_timestamp(cert.validity().not_after.timestamp())
        .map_err(|_| Error::Unauthorized)?;

    if now < not_before || now > not_after {
        return Err(Error::Unauthorized);
    }

    let lifetime = not_after - not_before;
    if lifetime.is_negative() || lifetime.whole_seconds() > MAX_DEVICE_CERT_TTL_SECS as i64 {
        return Err(Error::Unauthorized);
    }

    let mut spiffe_uris: Vec<String> = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            if let GeneralName::URI(uri) = name {
                spiffe_uris.push((*uri).to_string());
            }
        }
    }

    if spiffe_uris.len() != 1 {
        return Err(Error::Unauthorized);
    }

    let spiffe_uri = spiffe_uris.remove(0);
    let (tenant_id, vm_id) = parse_spiffe_uri(&spiffe_uri)?;
    let serial_hex = hex::encode(cert.raw_serial());

    Ok(VerifiedBoatIdentity {
        tenant_id,
        vm_id,
        serial_hex,
        spiffe_uri,
        not_before,
        not_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_verify_device_cert_within_24h() {
        let ca = BoatCa::generate_ephemeral("Test CA").unwrap();
        let tenant = TenantId::new();
        let vm_id = Uuid::new_v4();

        let issued = ca
            .issue_device_cert(tenant, vm_id, Duration::from_secs(MAX_DEVICE_CERT_TTL_SECS))
            .unwrap();
        assert!(!format!("{issued:?}").contains("BEGIN PRIVATE KEY"));

        let mut cur = std::io::Cursor::new(issued.cert_pem.as_bytes());
        let der = rustls_pemfile::certs(&mut cur).next().unwrap().unwrap();
        let verified = verify_client_cert_der(&der, OffsetDateTime::now_utc()).unwrap();
        assert_eq!(verified.tenant_id, tenant);
        assert_eq!(verified.vm_id, vm_id);
        assert_eq!(verified.spiffe_uri, format_spiffe_uri(tenant, vm_id));
    }

    #[test]
    fn sign_csr_overwrites_forged_san_with_verified_tenant_and_vm() {
        let ca = BoatCa::generate_ephemeral("Test CA").unwrap();
        let real_tenant = TenantId::new();
        let real_vm = Uuid::new_v4();
        let forged_tenant = TenantId::new();
        let forged_vm = Uuid::new_v4();

        let vm_key = KeyPair::generate().unwrap();
        let mut req_params = CertificateParams::default();
        req_params.subject_alt_names = vec![SanType::URI(
            format_spiffe_uri(forged_tenant, forged_vm)
                .try_into()
                .unwrap(),
        )];
        let csr = req_params.serialize_request(&vm_key).unwrap();
        let csr_pem = csr.pem().unwrap();

        let signed = ca
            .sign_device_csr(&csr_pem, real_tenant, real_vm, Duration::from_secs(3600))
            .unwrap();
        let mut cur = std::io::Cursor::new(signed.cert_pem.as_bytes());
        let der = rustls_pemfile::certs(&mut cur).next().unwrap().unwrap();
        let verified = verify_client_cert_der(&der, OffsetDateTime::now_utc()).unwrap();
        assert_eq!(verified.tenant_id, real_tenant);
        assert_eq!(verified.vm_id, real_vm);
    }

    #[test]
    fn rejects_ttl_exceeding_24h_or_zero() {
        let ca = BoatCa::generate_ephemeral("Test CA").unwrap();
        let tenant = TenantId::new();
        let vm_id = Uuid::new_v4();

        assert!(ca
            .issue_device_cert(tenant, vm_id, Duration::from_secs(0))
            .is_err());
        assert!(ca
            .issue_device_cert(tenant, vm_id, Duration::from_secs(MAX_DEVICE_CERT_TTL_SECS + 1))
            .is_err());
    }

    #[test]
    fn rejects_ca_cert_and_long_lived_leaf_cert() {
        let ca = BoatCa::generate_ephemeral("Test CA").unwrap();
        assert!(verify_client_cert_der(ca.ca_cert_der().as_ref(), OffsetDateTime::now_utc()).is_err());

        let ca_key = KeyPair::from_pem(ca.ca_key_pem.expose()).unwrap();
        let ca_cert = ca.reconstruct_ca_cert(&ca_key).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        let now = OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::hours(48);
        params.subject_alt_names = vec![SanType::URI(
            format_spiffe_uri(TenantId::new(), Uuid::new_v4())
                .try_into()
                .unwrap(),
        )];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
        assert!(verify_client_cert_der(leaf.der(), now).is_err());
    }

    #[test]
    fn rejects_expired_or_bad_san_cert() {
        let ca = BoatCa::generate_ephemeral("Test CA").unwrap();
        let issued = ca
            .issue_device_cert(TenantId::new(), Uuid::new_v4(), Duration::from_secs(60))
            .unwrap();
        let mut cur = std::io::Cursor::new(issued.cert_pem.as_bytes());
        let der = rustls_pemfile::certs(&mut cur).next().unwrap().unwrap();

        let future = OffsetDateTime::now_utc() + time::Duration::hours(2);
        assert!(verify_client_cert_der(&der, future).is_err());

        assert!(parse_spiffe_uri("spiffe://other.domain/tenant/x/vm/y").is_err());
        assert!(parse_spiffe_uri("spiffe://backplane.enterprise/tenant/not-a-uuid/vm/not-a-uuid").is_err());
    }
}
