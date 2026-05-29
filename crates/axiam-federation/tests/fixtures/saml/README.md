# SAML Test Fixtures

Pre-signed SAML XML test vectors for signature verification tests (plan 04-03) and
integration tests (plan 04-06 Task 2 — `saml_rejects_tampered_response`).

## Files

| File | Purpose |
|------|---------|
| `well_signed_response.xml` | Complete SAML Response with a valid assertion-level `<ds:Signature>`. Assertion `ID="well-signed-1"`, `NotOnOrAfter="2099-01-01T01:00:00Z"`. |
| `tampered_response.xml` | Copy of `well_signed_response.xml` with one byte flipped inside `<saml:AttributeValue>` (not inside the signature element). Signature digest check MUST fail. |
| `replayed_response.xml` | Like `well_signed_response.xml` but assertion `ID="replay-victim-1"`. Used to exercise the UNIQUE replay-detection path: insert once → Ok, insert again → `ReplayDetected`. |
| `signing_cert.pem` | The PEM certificate loaded as `idp_signing_cert_pem` in the test `FederationConfig`. |
| `generate.sh` | Reproducibility script — regenerates all files from scratch. Run when the key needs rotation or format changes. |

## Regenerating

```bash
cd crates/axiam-federation/tests/fixtures/saml
bash generate.sh
```

Requires: `openssl` + `xmlsec1` (1.2+ or 1.3+). The script does NOT run during `cargo test`.

## Cross-references

- **Plan 04-03 Task 3** — `verify_rejects_tampered_body` and `verify_accepts_well_signed_response` unit tests in `saml.rs` use `tampered_response.xml` and `well_signed_response.xml`.
- **Plan 04-06 Task 2** — `saml_rejects_tampered_response` integration test reuses `tampered_response.xml`.
- **Plan 04-03 Task 3** — `acs_rejects_replayed_assertion` uses `replayed_response.xml`.
