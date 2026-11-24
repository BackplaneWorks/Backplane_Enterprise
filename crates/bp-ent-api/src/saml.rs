//! SAML 2.0 service provider: SP-initiated Web Browser SSO
//! (HTTP-Redirect request, HTTP-POST response).
//!
//! What is verified before an assertion is believed:
//! - the document has no DTD (so no entities) and no `EncryptedAssertion`;
//! - an XML signature (RSA-SHA256, exclusive C14N, SHA-256 digest) made by
//!   the IdP certificate pinned in the provider settings. `KeyInfo` inside
//!   the document is ignored;
//! - the signature covers the very element the claims are read from: either
//!   the single `Assertion` itself or the `Response` that directly contains
//!   it, referenced by an ID that is unique in the document (signature
//!   wrapping defence);
//! - `Issuer`, `Audience` (this SP), `Recipient`/`Destination` (our ACS
//!   URL), the validity window, and `InResponseTo` == the request we sent for
//!   this login state. The login state is single-use, so an assertion cannot
//!   be replayed.

use crate::routes::sso::{self, Identity, Idp};
use crate::state::ApiState;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::Form;
use base64::Engine;
use bp_ent_core::{AppCtx, Error, Result};
use roxmltree::{Document, Node};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const NS_SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const NS_SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const ALG_EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ALG_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const ALG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const ALG_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const CLOCK_SKEW_SECS: i64 = 120;

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

// ============================================================ certificate

/// Parse the IdP signing certificate (PEM) and return its RSA public key in
/// the form the verifier needs. Rejects anything that is not an RSA key of
/// at least 2048 bits.
pub fn parse_certificate(pem: &str) -> Result<Vec<u8>> {
    let bad = || Error::invalid("samlCertPem must be a PEM X.509 certificate with an RSA key (2048 bits or more)");
    let body: String = pem.lines().map(str::trim).filter(|l| !l.starts_with("-----") && !l.is_empty()).collect();
    let der = b64().decode(body).map_err(|_| bad())?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).map_err(|_| bad())?;
    let spki = cert.public_key();
    match spki.parsed().map_err(|_| bad())? {
        x509_parser::public_key::PublicKey::RSA(rsa) if rsa.key_size() >= 2048 => Ok(spki.subject_public_key.data.to_vec()),
        _ => Err(bad()),
    }
}

// ================================================= exclusive canonical XML

fn escape_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn escape_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

/// The element's name exactly as written (`prefix:local`), from the source text.
fn source_qname<'a>(src: &'a str, node: Node) -> Result<&'a str> {
    let start = node.range().start;
    let rest = src.get(start + 1..).ok_or(Error::Unauthorized)?;
    let end = rest.find(|c: char| c.is_whitespace() || c == '>' || c == '/').ok_or(Error::Unauthorized)?;
    Ok(&rest[..end])
}

fn split_prefix(qname: &str) -> (&str, &str) {
    qname.split_once(':').unwrap_or(("", qname))
}

/// Exclusive XML Canonicalization 1.0 (without comments) of `node`'s subtree,
/// leaving out the subtree rooted at `skip` (the enveloped signature).
/// `inclusive` lists prefixes to treat inclusively (`InclusiveNamespaces`).
pub fn canonicalize(src: &str, node: Node, skip: Option<Node>, inclusive: &[String]) -> Result<String> {
    let mut out = String::new();
    c14n_element(src, node, skip, inclusive, &BTreeMap::new(), &mut out)?;
    Ok(out)
}

fn c14n_element(src: &str, node: Node, skip: Option<Node>, inclusive: &[String], rendered: &BTreeMap<String, String>, out: &mut String) -> Result<()> {
    let qname = source_qname(src, node)?;
    let (prefix, _) = split_prefix(qname);

    // Attributes with their written names.
    let mut attrs: Vec<(&str, &str, &str, &str)> = Vec::new(); // (ns uri, local, qname, value)
    for a in node.attributes() {
        let aq = src.get(a.range_qname()).ok_or(Error::Unauthorized)?;
        attrs.push((a.namespace().unwrap_or(""), a.name(), aq, a.value()));
    }
    attrs.sort_by(|x, y| (x.0, x.1).cmp(&(y.0, y.1)));

    // Namespace prefixes this element visibly uses.
    let mut used: Vec<String> = vec![prefix.to_string()];
    for (_, _, aq, _) in &attrs {
        let (ap, _) = split_prefix(aq);
        if !ap.is_empty() && ap != "xml" {
            used.push(ap.to_string());
        }
    }
    for p in inclusive {
        let p = if p == "#default" { "" } else { p.as_str() };
        let in_scope = if p.is_empty() { node.lookup_namespace_uri(None).is_some() } else { node.lookup_namespace_uri(Some(p)).is_some() };
        if in_scope {
            used.push(p.to_string());
        }
    }
    used.sort();
    used.dedup();

    let mut now = rendered.clone();
    let mut decls: Vec<(String, String)> = Vec::new();
    for p in used {
        let uri = if p.is_empty() { node.lookup_namespace_uri(None).unwrap_or("") } else { node.lookup_namespace_uri(Some(&p)).ok_or(Error::Unauthorized)? };
        let already = rendered.get(&p).map(String::as_str);
        let needed = match already {
            Some(prev) => prev != uri,
            // xmlns="" is only ever written to undo a rendered default.
            None => !(p.is_empty() && uri.is_empty()),
        };
        if needed {
            decls.push((p.clone(), uri.to_string()));
            now.insert(p, uri.to_string());
        }
    }

    out.push('<');
    out.push_str(qname);
    for (p, uri) in &decls {
        if p.is_empty() {
            out.push_str(" xmlns=\"");
        } else {
            out.push_str(" xmlns:");
            out.push_str(p);
            out.push_str("=\"");
        }
        escape_attr(uri, out);
        out.push('"');
    }
    for (_, _, aq, value) in &attrs {
        out.push(' ');
        out.push_str(aq);
        out.push_str("=\"");
        escape_attr(value, out);
        out.push('"');
    }
    out.push('>');
    for child in node.children() {
        if Some(child) == skip {
            continue;
        }
        if child.is_element() {
            c14n_element(src, child, skip, inclusive, &now, out)?;
        } else if child.is_text() {
            escape_text(child.text().unwrap_or(""), out);
        } else if child.is_pi() {
            // Processing instructions are part of canonical XML; SAML has no
            // use for them, so refuse rather than risk a mismatch.
            return Err(Error::Unauthorized);
        }
        // Comments are dropped (canonicalization without comments).
    }
    out.push_str("</");
    out.push_str(qname);
    out.push('>');
    Ok(())
}

// ============================================================== signature

fn child<'a, 'i>(node: Node<'a, 'i>, ns: &str, name: &str) -> Option<Node<'a, 'i>> {
    node.children().find(|c| c.is_element() && c.tag_name().name() == name && c.tag_name().namespace() == Some(ns))
}

fn children<'a, 'i>(node: Node<'a, 'i>, ns: &'a str, name: &'a str) -> impl Iterator<Item = Node<'a, 'i>> {
    node.children().filter(move |c| c.is_element() && c.tag_name().name() == name && c.tag_name().namespace() == Some(ns))
}

/// All text directly inside an element. Comments split text into several
/// nodes; joining them is what the signature covers (a first-text-node read
/// is the classic `user@org<!---->.evil` truncation bug).
fn text_of(node: Node) -> Result<String> {
    if node.children().any(|c| c.is_element()) {
        return Err(Error::Unauthorized);
    }
    Ok(node.children().filter(|c| c.is_text()).filter_map(|c| c.text()).collect::<String>().trim().to_string())
}

fn inclusive_prefixes(node: Node) -> Vec<String> {
    node.children()
        .find(|c| c.is_element() && c.tag_name().name() == "InclusiveNamespaces" && c.tag_name().namespace() == Some(ALG_EXC_C14N))
        .and_then(|c| c.attribute("PrefixList"))
        .map(|l| l.split_whitespace().map(String::from).collect())
        .unwrap_or_default()
}

/// Verify the enveloped signature that is a direct child of `signed`, with
/// the pinned RSA key. On success the caller may trust `signed`'s subtree
/// (minus the Signature element) and nothing else.
fn verify_enveloped_signature(src: &str, doc: &Document, signed: Node, rsa_public_key: &[u8]) -> Result<()> {
    let no = || Error::Unauthorized;
    let sig = child(signed, NS_DS, "Signature").ok_or_else(no)?;
    if children(signed, NS_DS, "Signature").count() != 1 {
        return Err(no());
    }
    let id = signed.attribute("ID").filter(|s| !s.is_empty()).ok_or_else(no)?;
    // The ID must name exactly one element in the whole document.
    if doc.descendants().filter(|n| n.is_element() && n.attribute("ID") == Some(id)).count() != 1 {
        return Err(no());
    }

    let info = child(sig, NS_DS, "SignedInfo").ok_or_else(no)?;
    let c14n_method = child(info, NS_DS, "CanonicalizationMethod").ok_or_else(no)?;
    if c14n_method.attribute("Algorithm") != Some(ALG_EXC_C14N) {
        return Err(no());
    }
    if child(info, NS_DS, "SignatureMethod").and_then(|n| n.attribute("Algorithm")) != Some(ALG_RSA_SHA256) {
        return Err(no());
    }
    let mut refs = children(info, NS_DS, "Reference");
    let reference = refs.next().ok_or_else(no)?;
    if refs.next().is_some() {
        return Err(no());
    }
    if reference.attribute("URI") != Some(format!("#{id}").as_str()) {
        return Err(no());
    }
    let mut ref_inclusive = Vec::new();
    if let Some(transforms) = child(reference, NS_DS, "Transforms") {
        for t in children(transforms, NS_DS, "Transform") {
            match t.attribute("Algorithm") {
                Some(ALG_ENVELOPED) => {}
                Some(ALG_EXC_C14N) => ref_inclusive = inclusive_prefixes(t),
                _ => return Err(no()),
            }
        }
    }
    if child(reference, NS_DS, "DigestMethod").and_then(|n| n.attribute("Algorithm")) != Some(ALG_SHA256) {
        return Err(no());
    }

    // 1. The digest of the signed element (without its signature).
    let canonical = canonicalize(src, signed, Some(sig), &ref_inclusive)?;
    let want: String = text_of(child(reference, NS_DS, "DigestValue").ok_or_else(no)?)?.split_whitespace().collect();
    let want = b64().decode(want).map_err(|_| no())?;
    if !bp_ent_core::crypto::ct_eq(&Sha256::digest(canonical.as_bytes()), &want) {
        return Err(no());
    }

    // 2. The signature over SignedInfo (which contains that digest).
    let signed_info = canonicalize(src, info, None, &inclusive_prefixes(c14n_method))?;
    let sig_value: String = text_of(child(sig, NS_DS, "SignatureValue").ok_or_else(no)?)?.split_whitespace().collect();
    let sig_value = b64().decode(sig_value).map_err(|_| no())?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::RSA_PKCS1_2048_8192_SHA256, rsa_public_key)
        .verify(signed_info.as_bytes(), &sig_value)
        .map_err(|_| no())
}

// =============================================================== response

/// What we expect a response to be bound to.
pub struct Expect<'a> {
    pub idp_entity_id: &'a str,
    pub sp_entity_id: &'a str,
    pub acs_url: &'a str,
    pub request_id: &'a str,
    pub now: time::OffsetDateTime,
}

fn parse_time(s: &str) -> Result<time::OffsetDateTime> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).map_err(|_| Error::Unauthorized)
}

const EMAIL_ATTRS: [&str; 6] = [
    "email",
    "mail",
    "emailaddress",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "urn:oid:0.9.2342.19200300.100.1.3",
    "user.email",
];
const NAME_ATTRS: [&str; 5] = [
    "displayname",
    "name",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    "http://schemas.microsoft.com/identity/claims/displayname",
    "urn:oid:2.16.840.1.113730.3.1.241",
];

/// Element nesting depth of a document, by a flat scan (no recursion), or
/// `None` if a tag is malformed. Run before parsing: deeply nested input
/// must be refused before any recursive code sees it.
pub fn max_depth(xml: &str) -> Option<usize> {
    let b = xml.as_bytes();
    let (mut i, mut depth, mut max) = (0usize, 0usize, 0usize);
    while i < b.len() {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        if b[i..].starts_with(b"<!--") {
            i += xml[i..].find("-->")? + 3;
        } else if b[i..].starts_with(b"<![CDATA[") {
            i += xml[i..].find("]]>")? + 3;
        } else if b[i..].starts_with(b"<?") {
            i += xml[i..].find("?>")? + 2;
        } else if b[i..].starts_with(b"<!") {
            // DOCTYPE and friends: rejected by the parser anyway.
            return None;
        } else {
            let closing = b.get(i + 1) == Some(&b'/');
            // Find the end of the tag, honouring quoted attribute values
            // (which may contain `>` and `/>`).
            let mut j = i + 1;
            let mut quote = 0u8;
            loop {
                let c = *b.get(j)?;
                if quote != 0 {
                    if c == quote {
                        quote = 0;
                    }
                } else if c == b'"' || c == b'\'' {
                    quote = c;
                } else if c == b'>' {
                    break;
                }
                j += 1;
            }
            let self_closing = b[j - 1] == b'/';
            if closing {
                depth = depth.checked_sub(1)?;
            } else if !self_closing {
                depth += 1;
                max = max.max(depth);
            } else {
                max = max.max(depth + 1);
            }
            i = j + 1;
        }
    }
    Some(max)
}

const MAX_DEPTH: usize = 64;

/// Verify a decoded SAML `Response` and extract the identity it asserts.
pub fn verify_response(xml: &str, rsa_public_key: &[u8], ex: &Expect) -> Result<Identity> {
    let no = || Error::Unauthorized;
    if xml.len() > MAX_RESPONSE_BYTES {
        return Err(no());
    }
    if !matches!(max_depth(xml), Some(d) if d <= MAX_DEPTH) {
        return Err(no());
    }
    // Default options: a DTD is a parse error, so there are no entities to expand.
    let opts = roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: 20_000 };
    let doc = Document::parse_with_options(xml, opts).map_err(|_| no())?;
    let root = doc.root_element();
    if root.tag_name().name() != "Response" || root.tag_name().namespace() != Some(NS_SAMLP) {
        return Err(no());
    }
    if doc.descendants().any(|n| n.is_element() && n.tag_name().name() == "EncryptedAssertion") {
        return Err(no());
    }
    let status = child(root, NS_SAMLP, "Status").and_then(|s| child(s, NS_SAMLP, "StatusCode")).and_then(|c| c.attribute("Value"));
    if status != Some(STATUS_SUCCESS) {
        return Err(Error::Forbidden);
    }
    if matches!(root.attribute("Destination"), Some(d) if d != ex.acs_url) {
        return Err(no());
    }
    if matches!(root.attribute("InResponseTo"), Some(r) if r != ex.request_id) {
        return Err(no());
    }

    // Exactly one assertion in the whole document, directly under the Response.
    let mut direct = children(root, NS_SAML, "Assertion");
    let assertion = direct.next().ok_or_else(no)?;
    if direct.next().is_some() || doc.descendants().filter(|n| n.is_element() && n.tag_name().name() == "Assertion").count() != 1 {
        return Err(no());
    }

    // The signature must cover the assertion we are about to read: its own
    // enveloped signature, or the signature of the Response that contains it.
    if child(assertion, NS_DS, "Signature").is_some() {
        verify_enveloped_signature(xml, &doc, assertion, rsa_public_key)?;
    } else if child(root, NS_DS, "Signature").is_some() {
        verify_enveloped_signature(xml, &doc, root, rsa_public_key)?;
    } else {
        return Err(no());
    }

    // From here on, read only from `assertion`.
    let issuer = text_of(child(assertion, NS_SAML, "Issuer").ok_or_else(no)?)?;
    if issuer != ex.idp_entity_id {
        return Err(no());
    }
    let skew = time::Duration::seconds(CLOCK_SKEW_SECS);

    let conditions = child(assertion, NS_SAML, "Conditions").ok_or_else(no)?;
    if let Some(nb) = conditions.attribute("NotBefore") {
        if ex.now + skew < parse_time(nb)? {
            return Err(no());
        }
    }
    let not_after = parse_time(conditions.attribute("NotOnOrAfter").ok_or_else(no)?)?;
    if ex.now - skew >= not_after {
        return Err(no());
    }
    let mut audience_ok = false;
    for restriction in children(conditions, NS_SAML, "AudienceRestriction") {
        // Every restriction must include us.
        let mut any = false;
        for a in children(restriction, NS_SAML, "Audience") {
            any |= text_of(a)? == ex.sp_entity_id;
        }
        if !any {
            return Err(no());
        }
        audience_ok = true;
    }
    if !audience_ok {
        return Err(no());
    }

    let subject = child(assertion, NS_SAML, "Subject").ok_or_else(no)?;
    let name_id_node = child(subject, NS_SAML, "NameID").ok_or_else(no)?;
    let name_id = text_of(name_id_node)?;
    if name_id.is_empty() || name_id.len() > 255 {
        return Err(no());
    }
    let mut confirmed = false;
    for sc in children(subject, NS_SAML, "SubjectConfirmation") {
        if sc.attribute("Method") != Some("urn:oasis:names:tc:SAML:2.0:cm:bearer") {
            continue;
        }
        let Some(data) = child(sc, NS_SAML, "SubjectConfirmationData") else { continue };
        let recipient_ok = data.attribute("Recipient") == Some(ex.acs_url);
        let in_response_ok = data.attribute("InResponseTo") == Some(ex.request_id);
        let fresh = match data.attribute("NotOnOrAfter") {
            Some(t) => ex.now - skew < parse_time(t)?,
            None => false,
        };
        confirmed |= recipient_ok && in_response_ok && fresh;
    }
    if !confirmed {
        return Err(no());
    }

    // Attributes.
    let (mut email, mut name) = (None, None);
    for stmt in children(assertion, NS_SAML, "AttributeStatement") {
        for attr in children(stmt, NS_SAML, "Attribute") {
            let key = attr.attribute("Name").unwrap_or_default().to_ascii_lowercase();
            let Some(value) = child(attr, NS_SAML, "AttributeValue") else { continue };
            let value = text_of(value)?;
            if email.is_none() && EMAIL_ATTRS.contains(&key.as_str()) {
                email = Some(value);
            } else if name.is_none() && NAME_ATTRS.contains(&key.as_str()) {
                name = Some(value);
            }
        }
    }
    let email = match email {
        Some(e) => e,
        // Without an e-mail attribute, the NameID must itself be the address.
        None if name_id.contains('@') => name_id.clone(),
        None => return Err(Error::Forbidden),
    };
    let email = sso::normalize_email(&email)?;
    Ok(Identity { subject: name_id, email, name: name.unwrap_or_default().chars().take(200).collect() })
}

// ============================================================ HTTP surface

pub fn sp_entity_id(ctx: &AppCtx, idp_id: uuid::Uuid) -> String {
    format!("{}/v1/auth/saml/{idp_id}/metadata", ctx.config.api_base_url)
}

pub fn acs_url(ctx: &AppCtx) -> String {
    format!("{}/v1/auth/saml/acs", ctx.config.api_base_url)
}

/// The AuthnRequest ID for a login state. Derived from the state, so the
/// response's `InResponseTo` can be checked without storing anything more.
pub fn request_id_for(state: &str) -> String {
    let h = Sha256::digest(format!("bpe-saml-request|{state}").as_bytes());
    format!("_{}", h[..20].iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn xml_attr(s: &str) -> String {
    let mut out = String::new();
    escape_attr(s, &mut out);
    out
}

/// The IdP URL to send the browser to (HTTP-Redirect binding: the request is
/// deflated and base64-encoded into the query).
pub fn authn_request_url(ctx: &AppCtx, idp: &Idp, state: &str) -> Result<String> {
    use std::io::Write;
    let sso_url = idp.saml_sso_url.as_deref().ok_or(Error::NotFound)?;
    let now = time::OffsetDateTime::now_utc().replace_nanosecond(0).map_err(Error::internal)?;
    let issue_instant = now.format(&time::format_description::well_known::Rfc3339).map_err(Error::internal)?;
    let xml = format!(
        "<samlp:AuthnRequest xmlns:samlp=\"{NS_SAMLP}\" xmlns:saml=\"{NS_SAML}\" ID=\"{id}\" Version=\"2.0\" IssueInstant=\"{issue_instant}\" \
         Destination=\"{dest}\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"{acs}\">\
         <saml:Issuer>{issuer}</saml:Issuer>\
         <samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\" AllowCreate=\"true\"/>\
         </samlp:AuthnRequest>",
        id = request_id_for(state),
        dest = xml_attr(sso_url),
        acs = xml_attr(&acs_url(ctx)),
        issuer = xml_attr(&sp_entity_id(ctx, idp.id)),
    );
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(xml.as_bytes()).map_err(Error::internal)?;
    let deflated = enc.finish().map_err(Error::internal)?;
    let mut url = ctx.http.check_url(sso_url)?;
    url.query_pairs_mut().append_pair("SAMLRequest", &b64().encode(deflated)).append_pair("RelayState", state);
    Ok(url.into())
}

#[derive(Deserialize)]
pub struct AcsForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
    #[serde(rename = "RelayState")]
    relay_state: String,
}

/// Assertion Consumer Service: the IdP posts the signed response here.
pub async fn acs(State(st): State<ApiState>, headers: HeaderMap, Form(form): Form<AcsForm>) -> Response {
    let ctx = &st.ctx;
    let run = async {
        if form.saml_response.len() > MAX_RESPONSE_BYTES * 2 {
            return Err(Error::Unauthorized);
        }
        // Single-use state, bound to the browser that started the login.
        let pending = sso::take_pending_login(ctx, &headers, &form.relay_state).await?;
        let mut tx = ctx.db.tenant_tx(pending.tenant).await?;
        let idp = sso::load_idp(&mut tx, pending.tenant, pending.idp_id).await?;
        tx.commit().await?;
        if idp.kind != "saml" {
            return Err(Error::Unauthorized);
        }
        let key = parse_certificate(idp.saml_cert_pem.as_deref().ok_or(Error::Unauthorized)?).map_err(|_| Error::Unauthorized)?;
        let compact: String = form.saml_response.split_whitespace().collect();
        let xml = String::from_utf8(b64().decode(compact).map_err(|_| Error::Unauthorized)?).map_err(|_| Error::Unauthorized)?;
        let who = verify_response(
            &xml,
            &key,
            &Expect {
                idp_entity_id: idp.saml_entity_id.as_deref().ok_or(Error::Unauthorized)?,
                sp_entity_id: &sp_entity_id(ctx, idp.id),
                acs_url: &acs_url(ctx),
                request_id: &request_id_for(&form.relay_state),
                now: time::OffsetDateTime::now_utc(),
            },
        )?;
        sso::check_domain(&idp, &who.email)?;
        sso::complete_login(ctx, &pending, &idp, &who).await
    };
    match run.await {
        Ok(r) => r,
        Err(e) => sso::login_failed(ctx, &e),
    }
}

/// SP metadata to give to the identity provider's administrator. Public:
/// it holds only our entity id and ACS URL.
pub async fn metadata(State(st): State<ApiState>, Path(idp_id): Path<uuid::Uuid>) -> Response {
    let xml = format!(
        "<?xml version=\"1.0\"?>\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"{entity}\">\
         <md:SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"{NS_SAMLP}\">\
         <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>\
         <md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"{acs}\" index=\"0\" isDefault=\"true\"/>\
         </md:SPSSODescriptor></md:EntityDescriptor>\n",
        entity = xml_attr(&sp_entity_id(&st.ctx, idp_id)),
        acs = xml_attr(&acs_url(&st.ctx)),
    );
    ([(header::CONTENT_TYPE, "application/samlmetadata+xml")], xml).into_response()
}
