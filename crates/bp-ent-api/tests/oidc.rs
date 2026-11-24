//! ID token verification against a locally generated RSA key.

use base64::Engine;
use bp_ent_api::oidc::{verify_id_token, VerifyError};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;

const KEY: &str = include_str!("fixtures/test_idp_key.pem");
const ISS: &str = "https://idp.example";
const AUD: &str = "client-123";

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// The JWKS for the fixture key, built from the public key's DER.
fn jwks() -> JwkSet {
    use x509_parser::prelude::FromDer;
    let pem = include_str!("fixtures/test_idp_pub.pem");
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(body).unwrap();
    let (_, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(&der).unwrap();
    let x509_parser::public_key::PublicKey::RSA(rsa) = spki.parsed().unwrap() else { panic!("not RSA") };
    let strip = |b: &[u8]| b.iter().skip_while(|x| **x == 0).copied().collect::<Vec<u8>>();
    serde_json::from_value(json!({ "keys": [{ "kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": b64(&strip(rsa.modulus)), "e": b64(&strip(rsa.exponent)) }] })).unwrap()
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn sign(claims: serde_json::Value, kid: Option<&str>) -> String {
    let mut h = Header::new(Algorithm::RS256);
    h.kid = kid.map(String::from);
    jsonwebtoken::encode(&h, &claims, &EncodingKey::from_rsa_pem(KEY.as_bytes()).unwrap()).unwrap()
}

fn good() -> serde_json::Value {
    json!({ "iss": ISS, "aud": AUD, "sub": "user-1", "exp": now() + 300, "nonce": "n-1", "email": "a@acme.test", "email_verified": true })
}

#[test]
fn accepts_a_valid_token() {
    let c = verify_id_token(&sign(good(), Some("k1")), &jwks(), ISS, AUD, "n-1").unwrap();
    assert_eq!(c.sub, "user-1");
    assert_eq!(c.email.as_deref(), Some("a@acme.test"));
}

#[test]
fn rejects_wrong_issuer_audience_nonce_and_expiry() {
    let ks = jwks();
    let with = |k: &str, v: serde_json::Value| {
        let mut c = good();
        c[k] = v;
        sign(c, Some("k1"))
    };
    assert_eq!(verify_id_token(&with("iss", json!("https://evil.example")), &ks, ISS, AUD, "n-1").unwrap_err(), VerifyError::Invalid);
    assert_eq!(verify_id_token(&with("aud", json!("someone-else")), &ks, ISS, AUD, "n-1").unwrap_err(), VerifyError::Invalid);
    assert_eq!(verify_id_token(&with("exp", json!(now() - 3600)), &ks, ISS, AUD, "n-1").unwrap_err(), VerifyError::Invalid);
    assert_eq!(verify_id_token(&with("sub", json!("")), &ks, ISS, AUD, "n-1").unwrap_err(), VerifyError::Invalid);
    // A token replayed into a different login (nonce mismatch) or without a nonce.
    assert_eq!(verify_id_token(&sign(good(), Some("k1")), &ks, ISS, AUD, "other").unwrap_err(), VerifyError::Invalid);
    let mut no_nonce = good();
    no_nonce.as_object_mut().unwrap().remove("nonce");
    assert_eq!(verify_id_token(&sign(no_nonce, Some("k1")), &ks, ISS, AUD, "n-1").unwrap_err(), VerifyError::Invalid);
}

#[test]
fn rejects_forged_signatures_and_weak_algorithms() {
    let ks = jwks();
    let token = sign(good(), Some("k1"));
    let parts: Vec<&str> = token.split('.').collect();

    // Payload swapped under the original signature.
    let mut evil = good();
    evil["sub"] = json!("admin");
    let forged = format!("{}.{}.{}", parts[0], b64(evil.to_string().as_bytes()), parts[2]);
    assert_eq!(verify_id_token(&forged, &ks, ISS, AUD, "n-1").unwrap_err(), VerifyError::Invalid);

    // alg=none.
    let none = format!("{}.{}.", b64(br#"{"alg":"none","typ":"JWT","kid":"k1"}"#), parts[1]);
    assert_eq!(verify_id_token(&none, &ks, ISS, AUD, "n-1").unwrap_err(), VerifyError::Invalid);

    // HS256 "signed" with the public modulus as the secret (key confusion).
    let n = ks.keys[0].common.key_id.clone().unwrap();
    let hs = jsonwebtoken::encode(&{ let mut h = Header::new(Algorithm::HS256); h.kid = Some("k1".into()); h }, &good(), &EncodingKey::from_secret(n.as_bytes())).unwrap();
    assert_eq!(verify_id_token(&hs, &ks, ISS, AUD, "n-1").unwrap_err(), VerifyError::Invalid);

    // Unknown key id: reported distinctly so the caller can refresh the JWKS once.
    assert_eq!(verify_id_token(&sign(good(), Some("rotated")), &ks, ISS, AUD, "n-1").unwrap_err(), VerifyError::UnknownKey);
    assert_eq!(verify_id_token("not.a.jwt", &ks, ISS, AUD, "n-1").unwrap_err(), VerifyError::Invalid);
}
