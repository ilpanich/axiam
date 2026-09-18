# fapi2-security-profile-final-test-plan

- **Plan id**: `E4S6TlfTUbhOZ`
- **Modules**: 56
- **Passed**: 52/56

**3 module(s) did not pass.** A submission built on this run would be a submission with 3 open question(s).

## Verdict summary

| Verdict | Count | What it means |
|---|---:|---|
| `WARNING` | 1 | a non-fatal deviation; permitted, but worth understanding before submitting |
| `REVIEW` | 2 | the suite cannot decide automatically — a human must read the log and judge |
| `SKIPPED` | 1 | not applicable to this variant |
| `PASSED` | 52 | the module's assertions all held |

## Modules that did not pass

| Module | Verdict | Suite log |
|---|---|---|
| `fapi2-security-profile-final-test-claims-parameter-identity-claims` | `WARNING` | `EMmhf9XeyOic64Q` |
| `fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails` | `REVIEW` | `UH4GQS6Rdt0Mija` |
| `fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` | `REVIEW` | `VzMZCXOEWuy1PDr` |

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
- `fapi2-security-profile-final-check-dpop-proof-nbf-exp`
- `fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-before-succeeds`
- `fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-after-succeeds`
- `fapi2-security-profile-final-ensure-mismatched-dpop-jkt-fails`
- `fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt`
- `fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-jkt`
- `fapi2-security-profile-final-ensure-dpopproof-at-par-endpoint-binding-success`
- `fapi2-security-profile-final-ensure-dpop-auth-code-binding-success`
- `fapi2-security-profile-final-ensure-different-nonce-inside-and-outside-request-object`
- `fapi2-security-profile-final-ensure-different-state-inside-and-outside-request-object`
- `fapi2-security-profile-final-ensure-authorization-request-with-long-nonce`
- `fapi2-security-profile-final-ensure-authorization-request-with-long-state`
- `fapi2-security-profile-final-state-only-outside-request-object-not-used`
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
- `fapi2-security-profile-final-ensure-client-assertion-in-token-endpoint`
- `fapi2-security-profile-final-ensure-client-assertion-with-exp-is-5-minutes-in-past-fails`
- `fapi2-security-profile-final-ensure-client-assertion-with-wrong-aud-fails`
- `fapi2-security-profile-final-ensure-client-assertion-with-no-sub-fails`
- `fapi2-security-profile-final-dpop-negative-tests`
- `fapi2-security-profile-final-refresh-token`
- `fapi2-security-profile-final-par-attempt-reuse-request_uri`
- `fapi2-security-profile-final-par-attempt-to-use-expired-request_uri`
- `fapi2-security-profile-final-par-ensure-jwt-client-assertions-nbf-8-seconds-in-the-future-is-accepted`
- `fapi2-security-profile-final-par-ensure-jwt-client-assertions-nbf-over-60-seconds-in-the-future-fails`
- `fapi2-security-profile-final-par-attempt-to-use-request_uri-for-different-client`
- `fapi2-security-profile-final-par-authorization-request-containing-request_uri-form-param`
- `fapi2-security-profile-final-par-attempt-invalid-http-method`
- `fapi2-security-profile-final-par-ensure-pkce-required`
- `fapi2-security-profile-final-ensure-pkce-code-verifier-required`
- `fapi2-security-profile-final-incorrect-pkce-code-verifier-rejected`
- `fapi2-security-profile-final-par-plain-pkce-rejected`
- `fapi2-security-profile-final-par-without-duplicate-parameters`
- `fapi2-security-profile-final-par-test-array-as-audience-fails`
- `fapi2-security-profile-final-par-test-par-endpoint-url-as-audience-fails`
- `fapi2-security-profile-final-par-test-token-endpoint-url-as-audience-fails`

</details>
