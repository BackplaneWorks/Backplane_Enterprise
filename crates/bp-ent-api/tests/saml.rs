//! SAML verification against vectors produced by an independent
//! implementation (libxml2 canonicalization + OpenSSL signatures; see
//! `fixtures/saml/gen.py`), plus the classic attacks.

use bp_ent_api::saml::{canonicalize, parse_certificate, verify_response, Expect};
use bp_ent_core::Error;

const SP: &str = "https://portal.test/v1/auth/saml/11111111-1111-1111-1111-111111111111/metadata";
const ACS: &str = "https://portal.test/v1/auth/saml/acs";
const IDP: &str = "https://idp.example/saml";

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{}/tests/fixtures/saml/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn key() -> Vec<u8> {
    parse_certificate(&fixture("idp_cert.pem")).unwrap()
}

fn at(ts: &str) -> time::OffsetDateTime {
    time::OffsetDateTime::parse(ts, &time::format_description::well_known::Rfc3339).unwrap()
}

fn expect() -> Expect<'static> {
    Expect { idp_entity_id: IDP, sp_entity_id: SP, acs_url: ACS, request_id: "_request123", now: at("2026-01-01T00:01:00Z") }
}

fn verify(xml: &str) -> Result<bp_ent_api::routes::sso::Identity, Error> {
    verify_response(xml, &key(), &expect())
}

#[test]
fn canonicalization_matches_libxml2() {
    let cases: serde_json::Value = serde_json::from_str(&fixture("c14n_cases.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let xml = case["xml"].as_str().unwrap();
        let doc = roxmltree::Document::parse(xml).unwrap();
        let node = doc.descendants().find(|n| n.attribute("ID") == case["id"].as_str()).unwrap();
        let inclusive: Vec<String> = case["inclusive"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
        let got = canonicalize(xml, node, None, &inclusive).unwrap();
        assert_eq!(got, case["expected"].as_str().unwrap(), "input: {xml}");
    }
}

#[test]
fn accepts_responses_signed_by_the_pinned_idp() {
    let who = verify(&fixture("signed_assertion.xml")).unwrap();
    assert_eq!((who.subject.as_str(), who.email.as_str(), who.name.as_str()), ("ann@acme.test", "ann@acme.test", "Ann & Co <R&D>"));
    // Signature on the Response instead of the Assertion.
    assert_eq!(verify(&fixture("signed_response.xml")).unwrap().email, "ann@acme.test");
    // InclusiveNamespaces PrefixList, xsi:type values, opaque NameID + mail attribute.
    let who = verify(&fixture("inclusive_ns.xml")).unwrap();
    assert_eq!((who.subject.as_str(), who.email.as_str()), ("opaque-id-7731", "ann@acme.test"));
    // Default namespaces, reordered attributes, whitespace, CDATA, character references.
    let who = verify(&fixture("default_ns.xml")).unwrap();
    assert_eq!(who.email, "ann@acme.test");
    assert!(who.name.contains("<cdata> & more"));
}

#[test]
fn rejects_another_signer_and_any_modification() {
    assert!(verify(&fixture("wrong_key.xml")).is_err());
    // The same document verifies under its own certificate, so the failure
    // above is the key pin and nothing else.
    let other = parse_certificate(&fixture("other_cert.pem")).unwrap();
    assert!(verify_response(&fixture("wrong_key.xml"), &other, &expect()).is_ok());
    assert!(verify_response(&fixture("signed_assertion.xml"), &other, &expect()).is_err());

    let good = fixture("signed_assertion.xml");
    for (from, to) in [
        ("ann@acme.test</saml:NameID>", "admin@acme.test</saml:NameID>"),
        ("ann@acme.test</saml:AttributeValue>", "ceo@acme.test</saml:AttributeValue>"),
        ("NotOnOrAfter=\"2026-01-01T00:05:00Z\"", "NotOnOrAfter=\"2036-01-01T00:05:00Z\""),
        (SP, "https://portal.test/v1/auth/saml/22222222-2222-2222-2222-222222222222/metadata"),
        ("<saml:Issuer>https://idp.example/saml</saml:Issuer><ds:Signature", "<saml:Issuer>https://evil.example/saml</saml:Issuer><ds:Signature"),
    ] {
        assert!(good.contains(from), "fixture changed: {from}");
        assert!(verify(&good.replacen(from, to, 1)).is_err(), "accepted after changing {from}");
    }
    let good = fixture("signed_response.xml");
    assert!(verify(&good.replace("ann@acme.test</saml:NameID>", "admin@acme.test</saml:NameID>")).is_err());
}

#[test]
fn rejects_unsigned_and_stripped_signatures() {
    let good = fixture("signed_assertion.xml");
    let start = good.find("<ds:Signature").unwrap();
    let end = good.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
    let stripped = format!("{}{}", &good[..start], &good[end..]);
    assert!(verify(&stripped).is_err());
    // Stripped and re-labelled with a weaker algorithm name.
    assert!(verify(&good.replace("rsa-sha256", "rsa-sha1")).is_err());
    assert!(verify(&good.replace("xmlenc#sha256", "xmldsig#sha1")).is_err());
}

#[test]
fn rejects_signature_wrapping() {
    let good = fixture("signed_assertion.xml");
    let a_start = good.find("<saml:Assertion").unwrap();
    let a_end = good.find("</saml:Assertion>").unwrap() + "</saml:Assertion>".len();
    let signed = &good[a_start..a_end];
    let sig_start = signed.find("<ds:Signature").unwrap();
    let sig_end = signed.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
    let unsigned_evil = format!("{}{}", &signed[..sig_start], &signed[sig_end..]).replace("ann@acme.test", "admin@acme.test").replace("_assertion1", "_evil");

    // 1. Evil assertion first, the genuine signed one after it.
    let v1 = format!("{}{}{}{}", &good[..a_start], unsigned_evil, signed, &good[a_end..]);
    assert!(verify(&v1).is_err());
    // 2. Genuine one first, evil second.
    let v2 = format!("{}{}{}{}", &good[..a_start], signed, unsigned_evil, &good[a_end..]);
    assert!(verify(&v2).is_err());
    // 3. Genuine assertion tucked into a wrapper; evil one takes its place.
    let v3 = format!("{}<samlp:Extensions>{}</samlp:Extensions>{}{}", &good[..a_start], signed, unsigned_evil, &good[a_end..]);
    assert!(verify(&v3).is_err());
    // 4. Evil assertion re-uses the signed ID and carries the genuine signature,
    //    with the genuine assertion hidden inside it.
    let evil_same_id = unsigned_evil.replace("_evil", "_assertion1");
    let nested = evil_same_id.replacen("<saml:Subject>", &format!("{}<saml:Subject>", &signed[sig_start..sig_end]), 1).replacen("</saml:Assertion>", &format!("<saml:Advice>{signed}</saml:Advice></saml:Assertion>"), 1);
    let v4 = format!("{}{}{}", &good[..a_start], nested, &good[a_end..]);
    assert!(verify(&v4).is_err());
    // 5. The signature moved to an evil Response-level position referencing the assertion.
    let v5 = format!("{}{}{}{}", &good[..a_start], &signed[sig_start..sig_end], unsigned_evil, &good[a_end..]);
    assert!(verify(&v5).is_err());
}

#[test]
fn comments_cannot_truncate_the_signed_value() {
    // Signed NameID is `ann@acme.test<!-- x -->.evil.example`. A verifier
    // that reads only the first text node would log in ann@acme.test.
    let who = verify(&fixture("comment_in_nameid.xml")).unwrap();
    assert_eq!(who.email, "ann@acme.test.evil.example");
    assert_eq!(who.subject, "ann@acme.test.evil.example");
    // And inserting a comment after signing does not change who that is.
    let good = fixture("signed_assertion.xml");
    let with_comment = good.replacen("ann@acme.test</saml:NameID>", "ann@acme<!---->.test</saml:NameID>", 1);
    assert_eq!(verify(&with_comment).unwrap().email, "ann@acme.test");
}

#[test]
fn rejects_wrong_audience_recipient_request_and_time() {
    let xml = fixture("signed_assertion.xml");
    let k = key();
    let with = |f: &dyn Fn(&mut Expect)| {
        let mut e = expect();
        f(&mut e);
        verify_response(&xml, &k, &e)
    };
    assert!(with(&|_| {}).is_ok());
    assert!(with(&|e| e.sp_entity_id = "https://other-sp.example/metadata").is_err(), "assertion issued for another service provider");
    assert!(with(&|e| e.acs_url = "https://portal.test/other").is_err());
    assert!(with(&|e| e.request_id = "_some_other_login").is_err(), "assertion answering a different login");
    assert!(with(&|e| e.idp_entity_id = "https://another-idp.example").is_err());
    assert!(with(&|e| e.now = at("2026-01-01T00:10:00Z")).is_err(), "expired");
    assert!(with(&|e| e.now = at("2025-12-31T23:00:00Z")).is_err(), "not yet valid");
    // Within the allowed clock skew.
    assert!(with(&|e| e.now = at("2026-01-01T00:06:00Z")).is_ok());
}

#[test]
fn rejects_dtd_entities_encrypted_assertions_and_failed_status() {
    let good = fixture("signed_assertion.xml");
    let dtd = format!("<!DOCTYPE r [<!ENTITY x \"boom\">]>{good}");
    assert!(verify(&dtd).is_err());
    let enc = good.replacen("<saml:Assertion", "<saml:EncryptedAssertion/><saml:Assertion", 1);
    assert!(verify(&enc).is_err());
    let failed = good.replace("status:Success", "status:Responder");
    assert!(verify(&failed).is_err());
    assert!(verify("<not-saml/>").is_err());
    assert!(verify("").is_err());
}

#[test]
fn deeply_nested_documents_are_refused_before_parsing() {
    use bp_ent_api::saml::max_depth;
    assert_eq!(max_depth("<a><b/><c><d>x</d></c></a>"), Some(3));
    assert_eq!(max_depth("<a x=\"/>\"><b y='>'><c/></b></a>"), Some(3));
    assert_eq!(max_depth("<a><!-- <b><c> --><![CDATA[<d><e>]]></a>"), Some(1));
    assert_eq!(max_depth("<a"), None);
    assert!(max_depth(&fixture("signed_assertion.xml")).unwrap() < 12);

    // Each of these used to be able to exhaust the stack.
    let n = 200_000;
    assert!(verify(&"<a>".repeat(n)).is_err());
    assert!(verify(&format!("{}{}", "<a>".repeat(n), "</a>".repeat(n))).is_err());
    // Attribute values that look like self-closing tags do not hide depth.
    assert!(verify(&format!("{}{}", "<a x=\"/>\">".repeat(n), "</a>".repeat(n))).is_err());
    assert!(verify(&format!("{}{}", "<a x='/>'>".repeat(n), "</a>".repeat(n))).is_err());
}

#[test]
fn certificate_parsing_is_strict() {
    assert!(parse_certificate(&fixture("idp_cert.pem")).is_ok());
    assert!(parse_certificate("not a certificate").is_err());
    assert!(parse_certificate("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----").is_err());
    // A bare public key is not a certificate.
    assert!(parse_certificate(include_str!("fixtures/test_idp_pub.pem")).is_err());
}
