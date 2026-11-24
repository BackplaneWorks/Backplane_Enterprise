#!/usr/bin/env python3
"""Generate the SAML test vectors with an independent implementation.

Canonicalization is done by libxml2 (via lxml) and signing by OpenSSL (via
`cryptography`), so the Rust verifier is checked against other people's code,
not against itself. Re-run to regenerate: python3 gen.py
"""
import base64, copy, datetime, hashlib, json, os
from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
DS = "http://www.w3.org/2000/09/xmldsig#"
IDP = "https://idp.example/saml"
SP = "https://portal.test/v1/auth/saml/11111111-1111-1111-1111-111111111111/metadata"
ACS = "https://portal.test/v1/auth/saml/acs"
REQ = "_request123"


def make_key(cn):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2025, 1, 1)).not_valid_after(datetime.datetime(2045, 1, 1))
            .sign(key, hashes.SHA256()))
    return key, cert.public_bytes(serialization.Encoding.PEM).decode()


def sig_template(ref_id, prefix_list):
    inc = f'<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="{prefix_list}"/>' if prefix_list else ""
    return (f'<ds:Signature xmlns:ds="{DS}"><ds:SignedInfo>'
            f'<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            f'<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
            f'<ds:Reference URI="#{ref_id}"><ds:Transforms>'
            f'<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
            f'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">{inc}</ds:Transform>'
            f'</ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            f'<ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo>'
            f'<ds:SignatureValue></ds:SignatureValue>'
            f'<ds:KeyInfo><ds:KeyName>ignored-by-the-verifier</ds:KeyName></ds:KeyInfo></ds:Signature>')


def c14n(el, prefixes):
    return etree.tostring(el, method="c14n", exclusive=True, with_comments=False, inclusive_ns_prefixes=prefixes or None)


def without_signature(root, ref_id):
    """A copy of the document with the referenced element's own Signature removed."""
    dup = copy.deepcopy(root)
    target = dup.xpath(f'//*[@ID="{ref_id}"]')[0]
    sig = target.find(f"{{{DS}}}Signature")
    tail = sig.tail or ""
    prev = sig.getprevious()
    if prev is not None:
        prev.tail = (prev.tail or "") + tail
    else:
        target.text = (target.text or "") + tail
    target.remove(sig)
    return target


def sign(xml, ref_id, key, prefix_list=""):
    xml = xml.replace("<!--SIG-->", sig_template(ref_id, prefix_list))
    root = etree.fromstring(xml.encode())
    prefixes = prefix_list.split() if prefix_list else []
    digest = hashlib.sha256(c14n(without_signature(root, ref_id), prefixes)).digest()
    target = root.xpath(f'//*[@ID="{ref_id}"]')[0]
    sig = target.find(f"{{{DS}}}Signature")
    sig.find(f".//{{{DS}}}DigestValue").text = base64.b64encode(digest).decode()
    signed_info = c14n(sig.find(f"{{{DS}}}SignedInfo"), [])
    value = key.sign(signed_info, padding.PKCS1v15(), hashes.SHA256())
    sig.find(f"{{{DS}}}SignatureValue").text = base64.b64encode(value).decode()
    return etree.tostring(root).decode()


def assertion(body_extra="", name_id="ann@acme.test", sig="<!--SIG-->", aid="_assertion1", attrs=True):
    attr_stmt = ('<saml:AttributeStatement>'
                 '<saml:Attribute Name="email"><saml:AttributeValue>ann@acme.test</saml:AttributeValue></saml:Attribute>'
                 '<saml:Attribute Name="displayName"><saml:AttributeValue>Ann &amp; Co &lt;R&amp;D&gt;</saml:AttributeValue></saml:Attribute>'
                 '</saml:AttributeStatement>') if attrs else ""
    return (f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{aid}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">'
            f'<saml:Issuer>{IDP}</saml:Issuer>{sig}'
            f'<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>'
            f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            f'<saml:SubjectConfirmationData InResponseTo="{REQ}" NotOnOrAfter="2026-01-01T00:05:00Z" Recipient="{ACS}"/>'
            f'</saml:SubjectConfirmation></saml:Subject>'
            f'<saml:Conditions NotBefore="2025-12-31T23:55:00Z" NotOnOrAfter="2026-01-01T00:05:00Z">'
            f'<saml:AudienceRestriction><saml:Audience>{SP}</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
            f'<saml:AuthnStatement AuthnInstant="2026-01-01T00:00:00Z"><saml:AuthnContext>'
            f'<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>'
            f'</saml:AuthnContext></saml:AuthnStatement>{attr_stmt}{body_extra}</saml:Assertion>')


def response(inner, sig="", rid="_response1"):
    return (f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            f'ID="{rid}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="{ACS}" InResponseTo="{REQ}">'
            f'<saml:Issuer>{IDP}</saml:Issuer>{sig}'
            f'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            f'{inner}</samlp:Response>')


def write(name, text):
    with open(os.path.join(HERE, name), "w", newline="") as f:
        f.write(text)


def main():
    key, cert = make_key("Test IdP")
    other_key, other_cert = make_key("Some Other IdP")
    write("idp_cert.pem", cert)
    write("other_cert.pem", other_cert)

    # 1. The common shape: signed assertion inside an unsigned response.
    write("signed_assertion.xml", sign(response(assertion()), "_assertion1", key))
    # 2. Signed response, unsigned assertion (ADFS-style).
    write("signed_response.xml", sign(response(assertion(sig=""), sig="<!--SIG-->"), "_response1", key))
    # 3. InclusiveNamespaces + xsi:type values that need the xs prefix kept.
    typed = ('<saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
             '<saml:Attribute Name="mail"><saml:AttributeValue xsi:type="xs:string">ann@acme.test</saml:AttributeValue></saml:Attribute>'
             '</saml:AttributeStatement>')
    write("inclusive_ns.xml", sign(response(assertion(body_extra=typed, attrs=False, name_id="opaque-id-7731")), "_assertion1", key, "xs saml"))
    # 4. Default namespaces instead of prefixes, pretty-printed with odd whitespace.
    default_ns = f'''<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="{ACS}" InResponseTo="{REQ}">
  <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">{IDP}</Issuer>
  <Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>
  <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
             Version="2.0"   ID="_assertion1"
             IssueInstant="2026-01-01T00:00:00Z">
    <Issuer>{IDP}</Issuer><!--SIG-->
    <Subject>
      <NameID>ann@acme.test</NameID>
      <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <SubjectConfirmationData Recipient="{ACS}" NotOnOrAfter="2026-01-01T00:05:00Z" InResponseTo="{REQ}"/>
      </SubjectConfirmation>
    </Subject>
    <Conditions NotOnOrAfter="2026-01-01T00:05:00Z" NotBefore="2025-12-31T23:55:00Z">
      <AudienceRestriction><Audience>{SP}</Audience></AudienceRestriction>
    </Conditions>
    <AttributeStatement>
      <Attribute Name="displayName" NameFormat="a&amp;b &quot;q&quot;"><AttributeValue>Tab&#9;CR&#13;LF&#10;end <![CDATA[<cdata> & more]]></AttributeValue></Attribute>
    </AttributeStatement>
  </Assertion>
</Response>'''
    write("default_ns.xml", sign(default_ns, "_assertion1", key))
    # 5. A comment inside the NameID: the signed value is the joined text.
    write("comment_in_nameid.xml", sign(response(assertion(name_id="ann@acme.test<!-- x -->.evil.example", attrs=False)), "_assertion1", key))
    # 6. Signed by a different (untrusted) key.
    write("wrong_key.xml", sign(response(assertion()), "_assertion1", other_key))

    # Canonicalization vectors: (document, element ID, drop its Signature?, inclusive prefixes) -> libxml2 output.
    cases = []
    docs = [
        ('<a:root xmlns:a="urn:a" xmlns:b="urn:b" xmlns:unused="urn:u"><b:x ID="t" b:attr="1" z="2" a:attr="3" xml:lang="en">  text &amp; &lt;more&gt; <a:y/><c xmlns="urn:d"><d xmlns=""/></c></b:x></a:root>', "t", []),
        ('<root xmlns="urn:def" xmlns:p="urn:p"><x ID="t" p:b="2" a="1"><y xmlns=""><z xmlns="urn:def"/></y><!-- c --><p:q/>tail</x></root>', "t", []),
        ('<r xmlns:xs="urn:xs" xmlns:xsi="urn:xsi" xmlns:n="urn:n"><n:e ID="t"><n:v xsi:type="xs:string">v</n:v></n:e></r>', "t", ["xs"]),
        ('<r xmlns:n="urn:n" xmlns:m="urn:n"><n:e ID="t"><m:f n:a="1" m:b="2"/></n:e></r>', "t", []),
        ('<r><e ID="t" a="x&#10;y&#9;z &quot;q&quot; &lt; &amp;">line1&#13;\nline2 &gt; ]]&gt;</e></r>', "t", []),
        ('<r xmlns="urn:def"><e ID="t" xmlns:k="urn:k"><k:c xmlns:k="urn:k2"><k:d/></k:c><k:c/></e></r>', "t", ["k"]),
    ]
    for xml, tid, prefixes in docs:
        root = etree.fromstring(xml.encode())
        el = root.xpath(f'//*[@ID="{tid}"]')[0]
        cases.append({"xml": xml, "id": tid, "inclusive": prefixes, "expected": c14n(el, prefixes).decode()})
    write("c14n_cases.json", json.dumps(cases, indent=1))
    print("ok")


main()
