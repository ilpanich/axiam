#!/usr/bin/env bash
# =============================================================================
# SAML Test Fixture Generator
# =============================================================================
#
# Regenerates the pre-signed SAML XML test fixtures from scratch.
#
# Prerequisites:
#   - openssl (any modern version)
#   - xmlsec1 1.3+ (Arch Linux) or xmlsec1 1.2+ (Debian Bookworm)
#
# Usage:
#   cd crates/axiam-federation/tests/fixtures/saml
#   bash generate.sh
#
# This script is NOT run during `cargo test`. The generated fixtures are
# committed to the repository. Run this script only when you need to
# regenerate fixtures (e.g., after key rotation or format changes).
#
# Cross-reference: plan 04-06 Task 2 (`saml_rejects_tampered_response`)
# reuses these fixtures.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Generating test RSA keypair ==="
openssl genrsa -out /tmp/saml_gen_key.pem 2048
openssl req -new -x509 \
  -key /tmp/saml_gen_key.pem \
  -out signing_cert.pem \
  -days 3650 \
  -subj "/CN=AXIAM Test IdP/O=AXIAM Test/C=US"
echo "Certificate generated: signing_cert.pem"

echo "=== Building well_signed_response.xml template ==="
cat > /tmp/saml_well_tmpl.xml << 'ENDXML'
<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                ID="_response-id-well-signed-1"
                Version="2.0"
                IssueInstant="2099-01-01T00:00:00Z">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  ID="well-signed-1"
                  Version="2.0"
                  IssueInstant="2099-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#well-signed-1">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue></ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue></ds:SignatureValue>
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate></ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">user@example.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T01:00:00Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2099-01-01T00:00:00Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>user@example.com</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
ENDXML

echo "=== Signing well_signed_response.xml ==="
xmlsec1 --sign \
  --privkey-pem /tmp/saml_gen_key.pem,signing_cert.pem \
  --lax-key-search \
  --id-attr:ID "urn:oasis:names:tc:SAML:2.0:assertion:Assertion" \
  --output well_signed_response.xml \
  /tmp/saml_well_tmpl.xml

echo "=== Verifying well_signed_response.xml ==="
xmlsec1 --verify \
  --trusted-pem signing_cert.pem \
  --lax-key-search \
  --id-attr:ID "urn:oasis:names:tc:SAML:2.0:assertion:Assertion" \
  well_signed_response.xml

echo "=== Creating tampered_response.xml (one byte flipped in AttributeValue) ==="
sed 's|<saml:AttributeValue>user@example.com</saml:AttributeValue>|<saml:AttributeValue>xser@example.com</saml:AttributeValue>|' \
  well_signed_response.xml > tampered_response.xml

echo "=== Creating replay template (assertion ID = replay-victim-1) ==="
sed 's|ID="well-signed-1"|ID="replay-victim-1"|;s|URI="#well-signed-1"|URI="#replay-victim-1"|' \
  /tmp/saml_well_tmpl.xml > /tmp/saml_replay_tmpl.xml

echo "=== Signing replayed_response.xml ==="
xmlsec1 --sign \
  --privkey-pem /tmp/saml_gen_key.pem,signing_cert.pem \
  --lax-key-search \
  --id-attr:ID "urn:oasis:names:tc:SAML:2.0:assertion:Assertion" \
  --output replayed_response.xml \
  /tmp/saml_replay_tmpl.xml

echo "=== Cleanup ==="
rm -f /tmp/saml_gen_key.pem /tmp/saml_well_tmpl.xml /tmp/saml_replay_tmpl.xml

echo ""
echo "Done. Generated files:"
ls -la *.xml *.pem 2>/dev/null
