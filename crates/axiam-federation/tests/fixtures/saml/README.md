# SAML Test Fixtures

Pre-signed SAML XML test vectors for signature verification tests (plan 04-03), the
SubjectConfirmationData validation tests (R1.5 / SEC-005 residual) and integration tests
(plan 04-06 Task 2 — `saml_rejects_tampered_response`).

## Files

| File | Purpose |
|------|---------|
| `well_signed_response.xml` | Complete SAML Response with a valid assertion-level `<ds:Signature>`. Assertion `ID="well-signed-1"`, `NotOnOrAfter="2099-01-01T01:00:00Z"`. Deliberately shaped as an **unsolicited** response: no `Response/@InResponseTo`, no `Response/@Destination` (the "missing InResponseTo" / "missing Destination" negative tests rely on that), and consequently no `@InResponseTo` on its bearer `<SubjectConfirmationData>`. |
| `tampered_response.xml` | Copy of `well_signed_response.xml` with one byte flipped inside `<saml:AttributeValue>` (not inside the signature element). Signature digest check MUST fail. |
| `replayed_response.xml` | Like `well_signed_response.xml` but assertion `ID="replay-victim-1"`. Used to exercise the UNIQUE replay-detection path: insert once → Ok, insert again → `ReplayDetected`. |
| `scd_valid_response.xml` | **R1.5 positive vector.** SP-initiated shape for the authenticated ACS path: `Response/@Destination` and `Response/@InResponseTo="_axiam-req-1"` set, and a bearer `<SubjectConfirmationData>` whose `@Recipient` is the SP ACS URL, `@NotOnOrAfter` is 2099 and `@InResponseTo` is `_axiam-req-1`. Assertion `ID="scd-valid-1"`. |
| `scd_wrong_recipient_response.xml` | **R1.5 negative.** Identical to the positive vector except the signed `@Recipient` names a *different* SP (`https://other-sp.example.com/...`) — the Web-Browser-SSO §4.1.4.3 cross-SP relay. Assertion `ID="scd-wrong-recipient-1"`. |
| `scd_expired_response.xml` | **R1.5 negative.** Signed `SubjectConfirmationData/@NotOnOrAfter="2020-01-01T00:00:00Z"` (long past) while `<Conditions>` is still valid until 2099, so only the SCD clock check can reject it. Assertion `ID="scd-expired-1"`. |
| `scd_foreign_in_response_to_response.xml` | **R1.5 negative.** `Response/@InResponseTo="_axiam-req-1"` (attacker-rewritable, unsigned) but the signed `SubjectConfirmationData/@InResponseTo="_attacker-req-9"`. Assertion `ID="scd-foreign-irt-1"`. |
| `scd_missing_confirmation_response.xml` | **R1.5 fail-closed vector.** Authentic, correctly signed assertion with **no** `<SubjectConfirmation>` at all — bearer confirmation is REQUIRED by the profile, so this must be rejected rather than silently accepted. Assertion `ID="scd-missing-confirmation-1"`. |
| `signing_cert.pem` | The PEM certificate loaded as `idp_signing_cert_pem` in the test `FederationConfig`. Read it from this file — never hard-code it; `generate.sh` rotates it on every run. |
| `generate.sh` | Reproducibility script — regenerates all files from scratch. Run when the key needs rotation or format changes. |

Every fixture carries a bearer
`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` block inside
`<saml:Subject>` (except `scd_missing_confirmation_response.xml`, which exists precisely to
prove the absence is rejected). The SP ACS URL used throughout is
`https://sp.example.com/api/v1/federation/saml/acs`.

### Why the negatives keep everything else valid

`Response/@Destination` and `Response/@InResponseTo` live on the **unsigned** `<samlp:Response>`
root — the enveloped signature covers only the child `<saml:Assertion>`. An attacker relaying
an assertion issued for another SP can therefore rewrite both at will. Each `scd_*` negative
keeps the signature, `Destination`, `Response/@InResponseTo`, `<Conditions>` and the
`<AudienceRestriction>` fully valid, and differs from `scd_valid_response.xml` in exactly one
**signed** `SubjectConfirmationData` attribute. That isolation is what makes them meaningful:
before the R1.5 fix all three were accepted.

## Regenerating

```bash
cd crates/axiam-federation/tests/fixtures/saml
bash generate.sh
```

Requires: `openssl` + `xmlsec1` (1.2+ or 1.3+; the script probes for the 1.3-only
`--lax-key-search` flag). The script does NOT run during `cargo test`.

The signing private key is generated fresh and deleted at the end of every run, so individual
fixtures can never be re-signed in isolation — any change to signed content means re-running
the script and regenerating the **whole** set, `signing_cert.pem` included.

## Cross-references

- **Plan 04-03 Task 3** — `verify_rejects_tampered_body` and `verify_accepts_well_signed_response` unit tests in `saml.rs` use `tampered_response.xml` and `well_signed_response.xml`.
- **Plan 04-06 Task 2** — `saml_rejects_tampered_response` integration test reuses `tampered_response.xml`.
- **Plan 04-03 Task 3** — `acs_rejects_replayed_assertion` uses `replayed_response.xml`.
- **Remediation R1.5 (SEC-005 residual)** — the `scd_*` vectors back the
  `handle_saml_response_*subject_confirmation*` / `*recipient*` / `*scd*` tests in
  `crates/axiam-federation/src/saml.rs`.
- `crates/axiam-server/tests/req5_saml_e2e.rs` consumes the same directory over a relative path.
