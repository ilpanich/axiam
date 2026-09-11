# fapi2-security-profile-final-test-plan

- **Plan id**: `oHt7JzQ0L8Hn6`
- **Modules**: 37
- **Passed**: 26/37

**11 module(s) did not pass.** A submission built on this run would be a submission with 11 open question(s).

## Verdict summary

| Verdict | Count | What it means |
|---|---:|---|
| `WARNING` | 1 | a non-fatal deviation; permitted, but worth understanding before submitting |
| `REVIEW` | 10 | the suite cannot decide automatically — a human must read the log and judge |
| `PASSED` | 26 | the module's assertions all held |

## Modules that did not pass

| Module | Verdict | Suite log |
|---|---|---|
| `fapi2-security-profile-final-test-claims-parameter-identity-claims` | `WARNING` | `fyqHvQo1i6AIEzu` |
| `fapi2-security-profile-final-ensure-different-nonce-inside-and-outside-request-object` | `REVIEW` | `VEAOkif94hmqt3b` |
| `fapi2-security-profile-final-ensure-different-state-inside-and-outside-request-object` | `REVIEW` | `W1JvE2hDP7jG7D5` |
| `fapi2-security-profile-final-ensure-authorization-request-with-long-nonce` | `REVIEW` | `VXyvRncdMDycPI3` |
| `fapi2-security-profile-final-ensure-authorization-request-with-long-state` | `REVIEW` | `6Sxeb5XsM8O5bCR` |
| `fapi2-security-profile-final-state-only-outside-request-object-not-used` | `REVIEW` | `QrPYbmFyOIwiTJV` |
| `fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails` | `REVIEW` | `Qk2aUSDlEgggNiI` |
| `fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` | `REVIEW` | `ApnWq6hWiBi9Adt` |
| `fapi2-security-profile-final-par-attempt-reuse-request_uri` | `REVIEW` | `clhF9BmPTWZjvSP` |
| `fapi2-security-profile-final-par-attempt-to-use-expired-request_uri` | `REVIEW` | `FonPxCdCry5ovTW` |
| `fapi2-security-profile-final-par-attempt-to-use-request_uri-for-different-client` | `REVIEW` | `FapeKBo2hegQNNR` |

Open a suite log with `<SUITE_BASE_URL>/log-detail.html?log=<id>`. See [`claude_dev/fapi-conformance-runbook.md`](../../claude_dev/fapi-conformance-runbook.md) for how to read one and how to re-run a single module.

<details><summary>Modules that passed</summary>

- `fapi2-security-profile-final-discovery-end-point-verification`
- `fapi2-security-profile-final-happy-flow`
- `fapi2-security-profile-final-user-rejects-authentication`
- `fapi2-security-profile-final-ensure-authorization-request-without-state-success`
- `fapi2-security-profile-final-ensure-authorization-request-without-nonce-success`
- `fapi2-security-profile-final-ensure-authorization-request-with-64-char-nonce-success`
- `fapi2-security-profile-final-ensure-other-scope-order-succeeds`
- `fapi2-security-profile-final-access-token-type-header-case-sensitivity`
- `fapi2-security-profile-final-ensure-request-object-without-redirect-uri-fails`
- `fapi2-security-profile-final-plain-fapi-tolerate-unregistered-redirect-uri`
- `fapi2-security-profile-final-ensure-redirect-uri-in-authorization-request`
- `fapi2-security-profile-final-ensure-response-type-code-idtoken-fails`
- `fapi2-security-profile-final-ensure-response-type-token-fails`
- `fapi2-security-profile-final-ensure-client-id-in-token-endpoint`
- `fapi2-security-profile-final-ensure-holder-of-key-required`
- `fapi2-security-profile-final-ensure-authorization-code-is-bound-to-client`
- `fapi2-security-profile-final-attempt-reuse-authorization-code-after-one-second`
- `fapi2-security-profile-final-ensure-token-endpoint-fails-with-expired-auth-code`
- `fapi2-security-profile-final-refresh-token`
- `fapi2-security-profile-final-par-authorization-request-containing-request_uri-form-param`
- `fapi2-security-profile-final-par-attempt-invalid-http-method`
- `fapi2-security-profile-final-par-ensure-pkce-required`
- `fapi2-security-profile-final-ensure-pkce-code-verifier-required`
- `fapi2-security-profile-final-incorrect-pkce-code-verifier-rejected`
- `fapi2-security-profile-final-par-plain-pkce-rejected`
- `fapi2-security-profile-final-par-without-duplicate-parameters`

</details>
