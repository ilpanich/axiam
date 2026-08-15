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
# IMPORTANT: every fixture is signed with ONE ephemeral keypair whose public
# half is written to `signing_cert.pem`. The private key is deleted at the end,
# so a fixture can never be re-signed in isolation — adding or changing any
# signed content means re-running this script and regenerating the WHOLE set
# (including `signing_cert.pem`). Consumers must always read the certificate
# from `signing_cert.pem`, never hard-code it.
#
# Cross-reference: plan 04-06 Task 2 (`saml_rejects_tampered_response`)
# reuses these fixtures. R1.5/SEC-005 added the `scd_*` SubjectConfirmationData
# vectors and the bearer <SubjectConfirmation> block now present in every
# fixture.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

KEY=/tmp/saml_gen_key.pem

# `--lax-key-search` only exists in xmlsec1 1.3+. On 1.2.x (Debian Bookworm,
# and the CI image) the flag is rejected outright, so probe for it once.
if xmlsec1 --help-sign 2>&1 | grep -q -- '--lax-key-search'; then
  LAX_KEY_SEARCH=(--lax-key-search)
else
  LAX_KEY_SEARCH=()
fi

# The SP's real Assertion Consumer Service URL. This is the value the ACS
# handler passes as `expected_destination` (crates/axiam-api-rest/src/handlers/
# federation.rs, `saml_acs`), and therefore the value that
# SubjectConfirmationData/@Recipient must equal (SEC-005, Web-Browser-SSO
# profile §4.1.4.3). Kept in sync with the `acs_url` used by
# crates/axiam-server/tests/req5_saml_e2e.rs.
ACS_URL="https://sp.example.com/api/v1/federation/saml/acs"

echo "=== Generating test RSA keypair ==="
openssl genrsa -out "$KEY" 2048
openssl req -new -x509 \
  -key "$KEY" \
  -out signing_cert.pem \
  -days 3650 \
  -subj "/CN=AXIAM Test IdP/O=AXIAM Test/C=US"
echo "Certificate generated: signing_cert.pem"

# -----------------------------------------------------------------------------
# emit_template <outfile> <assertion_id> <response_extra_attrs> <scd_attrs> \
#               <conditions_not_on_or_after>
#
# Writes an unsigned SAML Response template.
#   response_extra_attrs — extra attributes for the <samlp:Response> start tag
#                          (e.g. InResponseTo/Destination). Emitted BEFORE
#                          IssueInstant so that `IssueInstant="..."` stays the
#                          last attribute of the start tag — req5_saml_e2e.rs's
#                          `inject_response_attrs` splices on that exact text.
#   scd_attrs            — attributes for <saml:SubjectConfirmationData>.
# -----------------------------------------------------------------------------
emit_template() {
  local out="$1" aid="$2" resp_attrs="$3" scd_attrs="$4" cond_noa="$5"
  cat > "$out" << ENDXML
<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                ID="_response-id-${aid}"
                Version="2.0"
                ${resp_attrs}IssueInstant="2099-01-01T00:00:00Z">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  ID="${aid}"
                  Version="2.0"
                  IssueInstant="2099-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#${aid}">
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
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData ${scd_attrs}/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-01-01T00:00:00Z" NotOnOrAfter="${cond_noa}">
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
}

sign_template() {
  local tmpl="$1" out="$2"
  xmlsec1 --sign \
    --privkey-pem "$KEY,signing_cert.pem" \
    ${LAX_KEY_SEARCH+"${LAX_KEY_SEARCH[@]}"} \
    --id-attr:ID "urn:oasis:names:tc:SAML:2.0:assertion:Assertion" \
    --output "$out" \
    "$tmpl"
  xmlsec1 --verify \
    --trusted-pem signing_cert.pem \
    ${LAX_KEY_SEARCH+"${LAX_KEY_SEARCH[@]}"} \
    --id-attr:ID "urn:oasis:names:tc:SAML:2.0:assertion:Assertion" \
    "$out"
}

# -----------------------------------------------------------------------------
# 1. well_signed_response.xml — the baseline happy-path fixture.
#
# Shaped as an UNSOLICITED response: no Response/@InResponseTo and no
# Response/@Destination, so the existing "missing InResponseTo" and "missing
# Destination" negative tests keep working. Its bearer SubjectConfirmationData
# therefore carries no @InResponseTo either (§4.1.4.2: InResponseTo is present
# only when the assertion answers an AuthnRequest).
# -----------------------------------------------------------------------------
echo "=== well_signed_response.xml ==="
emit_template /tmp/saml_well_tmpl.xml \
  "well-signed-1" \
  "" \
  "NotOnOrAfter=\"2099-01-01T01:00:00Z\" Recipient=\"$ACS_URL\"" \
  "2099-01-01T01:00:00Z"
sign_template /tmp/saml_well_tmpl.xml well_signed_response.xml

echo "=== tampered_response.xml (one byte flipped in AttributeValue) ==="
sed 's|<saml:AttributeValue>user@example.com</saml:AttributeValue>|<saml:AttributeValue>xser@example.com</saml:AttributeValue>|' \
  well_signed_response.xml > tampered_response.xml

echo "=== replayed_response.xml (assertion ID = replay-victim-1) ==="
emit_template /tmp/saml_replay_tmpl.xml \
  "replay-victim-1" \
  "" \
  "NotOnOrAfter=\"2099-01-01T01:00:00Z\" Recipient=\"$ACS_URL\"" \
  "2099-01-01T01:00:00Z"
sign_template /tmp/saml_replay_tmpl.xml replayed_response.xml

# -----------------------------------------------------------------------------
# 2. SEC-005 / R1.5 — SubjectConfirmationData vectors.
#
# All four are shaped like a real SP-initiated Web-Browser-SSO response landing
# on the AUTHENTICATED ACS path: Response/@Destination and Response/@InResponseTo
# are set to the SP's own values. Those two attributes live on the UNSIGNED
# <samlp:Response> root (the signature covers only the child <saml:Assertion>),
# so an attacker relaying someone else's assertion can freely rewrite them —
# which is exactly why the SIGNED SubjectConfirmationData must be checked too.
#
# Every negative differs from `scd_valid_response.xml` in exactly ONE signed
# SubjectConfirmationData attribute; everything an earlier check looks at
# (signature, Destination, Response/@InResponseTo, Conditions, Audience) stays
# valid, so the only control that can reject them is the new SCD validation.
# -----------------------------------------------------------------------------
SCD_RESP_ATTRS="InResponseTo=\"_axiam-req-1\" Destination=\"$ACS_URL\" "

echo "=== scd_valid_response.xml (positive vector) ==="
emit_template /tmp/saml_scd_valid_tmpl.xml \
  "scd-valid-1" \
  "$SCD_RESP_ATTRS" \
  "NotOnOrAfter=\"2099-01-01T01:00:00Z\" Recipient=\"$ACS_URL\" InResponseTo=\"_axiam-req-1\"" \
  "2099-01-01T01:00:00Z"
sign_template /tmp/saml_scd_valid_tmpl.xml scd_valid_response.xml

echo "=== scd_wrong_recipient_response.xml (assertion minted for another SP) ==="
emit_template /tmp/saml_scd_recipient_tmpl.xml \
  "scd-wrong-recipient-1" \
  "$SCD_RESP_ATTRS" \
  "NotOnOrAfter=\"2099-01-01T01:00:00Z\" Recipient=\"https://other-sp.example.com/api/v1/federation/saml/acs\" InResponseTo=\"_axiam-req-1\"" \
  "2099-01-01T01:00:00Z"
sign_template /tmp/saml_scd_recipient_tmpl.xml scd_wrong_recipient_response.xml

echo "=== scd_expired_response.xml (SCD NotOnOrAfter passed, Conditions still valid) ==="
emit_template /tmp/saml_scd_expired_tmpl.xml \
  "scd-expired-1" \
  "$SCD_RESP_ATTRS" \
  "NotOnOrAfter=\"2020-01-01T00:00:00Z\" Recipient=\"$ACS_URL\" InResponseTo=\"_axiam-req-1\"" \
  "2099-01-01T01:00:00Z"
sign_template /tmp/saml_scd_expired_tmpl.xml scd_expired_response.xml

echo "=== scd_foreign_in_response_to_response.xml (SCD answers a different request) ==="
emit_template /tmp/saml_scd_irt_tmpl.xml \
  "scd-foreign-irt-1" \
  "$SCD_RESP_ATTRS" \
  "NotOnOrAfter=\"2099-01-01T01:00:00Z\" Recipient=\"$ACS_URL\" InResponseTo=\"_attacker-req-9\"" \
  "2099-01-01T01:00:00Z"
sign_template /tmp/saml_scd_irt_tmpl.xml scd_foreign_in_response_to_response.xml

echo "=== scd_missing_confirmation_response.xml (no <SubjectConfirmation> at all) ==="
# Fail-closed vector: strip the whole bearer <SubjectConfirmation> block from the
# valid template and RE-SIGN, so the assertion is authentic but profile-invalid.
sed '/<saml:SubjectConfirmation /,/<\/saml:SubjectConfirmation>/d' \
  /tmp/saml_scd_valid_tmpl.xml \
  | sed 's|ID="scd-valid-1"|ID="scd-missing-confirmation-1"|; s|URI="#scd-valid-1"|URI="#scd-missing-confirmation-1"|; s|ID="_response-id-scd-valid-1"|ID="_response-id-scd-missing-confirmation-1"|' \
  > /tmp/saml_scd_missing_tmpl.xml
sign_template /tmp/saml_scd_missing_tmpl.xml scd_missing_confirmation_response.xml

echo "=== Cleanup ==="
rm -f "$KEY" /tmp/saml_well_tmpl.xml /tmp/saml_replay_tmpl.xml \
  /tmp/saml_scd_valid_tmpl.xml /tmp/saml_scd_recipient_tmpl.xml \
  /tmp/saml_scd_expired_tmpl.xml /tmp/saml_scd_irt_tmpl.xml \
  /tmp/saml_scd_missing_tmpl.xml

echo ""
echo "Done. Generated files:"
ls -la *.xml *.pem 2>/dev/null
