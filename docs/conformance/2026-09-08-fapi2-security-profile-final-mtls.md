# fapi2-security-profile-final-test-plan

- **Plan id**: `fTAVsUFPFChO3`
- **Modules**: 37
- **Passed**: 2/37

**34 module(s) did not pass.** A submission built on this run would be a submission with 34 open question(s).

## Verdict summary

| Verdict | Count | What it means |
|---|---:|---|
| `FAILED` | 31 | an assertion did not hold. This is a real finding. |
| `WAITING` | 1 | the module is waiting for a browser to complete an authorization. NOT a pass and NOT a failure — no assertion has been evaluated yet |
| `WARNING` | 2 | a non-fatal deviation; permitted, but worth understanding before submitting |
| `SKIPPED` | 1 | not applicable to this variant |
| `PASSED` | 2 | the module's assertions all held |

## Modules that did not pass

| Module | Verdict | Suite log |
|---|---|---|
| `fapi2-security-profile-final-happy-flow` | `FAILED` | `V3KJVtvAC3mwdaE` |
| `fapi2-security-profile-final-user-rejects-authentication` | `FAILED` | `JXza8mmudRzym6h` |
| `fapi2-security-profile-final-ensure-authorization-request-without-state-success` | `FAILED` | `FGpFmLI7NBdrYM3` |
| `fapi2-security-profile-final-ensure-authorization-request-without-nonce-success` | `FAILED` | `M9wATWzxKZBdzfX` |
| `fapi2-security-profile-final-ensure-authorization-request-with-64-char-nonce-success` | `FAILED` | `6uXfMXjjJZIZusH` |
| `fapi2-security-profile-final-ensure-other-scope-order-succeeds` | `FAILED` | `TAmP1ef7uT7eHN2` |
| `fapi2-security-profile-final-access-token-type-header-case-sensitivity` | `FAILED` | `0z8iBwqMFHZu9EB` |
| `fapi2-security-profile-final-ensure-different-nonce-inside-and-outside-request-object` | `FAILED` | `PLC6cYAtsrIvBiJ` |
| `fapi2-security-profile-final-ensure-different-state-inside-and-outside-request-object` | `FAILED` | `1qYRatxn8s3qmzZ` |
| `fapi2-security-profile-final-ensure-authorization-request-with-long-nonce` | `FAILED` | `9lYdkdEINuGeyKj` |
| `fapi2-security-profile-final-ensure-authorization-request-with-long-state` | `FAILED` | `yc07HIXijDLNiT7` |
| `fapi2-security-profile-final-state-only-outside-request-object-not-used` | `FAILED` | `WYPzCCmajjkzNbo` |
| `fapi2-security-profile-final-ensure-request-object-without-redirect-uri-fails` | `FAILED` | `9qgdjBYvfixG2IX` |
| `fapi2-security-profile-final-plain-fapi-tolerate-unregistered-redirect-uri` | `FAILED` | `SEGmcOM7T21PygS` |
| `fapi2-security-profile-final-ensure-redirect-uri-in-authorization-request` | `FAILED` | `qYMczFEDwWSkJn6` |
| `fapi2-security-profile-final-ensure-client-id-in-token-endpoint` | `FAILED` | `ycqjzRbYcWTieb4` |
| `fapi2-security-profile-final-ensure-holder-of-key-required` | `FAILED` | `c7auZ3SCi2jjgio` |
| `fapi2-security-profile-final-ensure-authorization-code-is-bound-to-client` | `FAILED` | `pcEtHhRFxyFWkq3` |
| `fapi2-security-profile-final-attempt-reuse-authorization-code-after-one-second` | `FAILED` | `UjDlWl6fzknJ1iI` |
| `fapi2-security-profile-final-ensure-token-endpoint-fails-with-expired-auth-code` | `FAILED` | `X0HfOvd39Cumjco` |
| `fapi2-security-profile-final-refresh-token` | `FAILED` | `NPl5UJoYeEeknlW` |
| `fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` | `FAILED` | `ma8rzBSeC5yLx9K` |
| `fapi2-security-profile-final-par-attempt-reuse-request_uri` | `FAILED` | `McdSNaZnO9F8Car` |
| `fapi2-security-profile-final-par-attempt-to-use-expired-request_uri` | `FAILED` | `2sWUX5Xfg7isU2I` |
| `fapi2-security-profile-final-par-attempt-to-use-request_uri-for-different-client` | `FAILED` | `Vbsf9LwAV7wWilb` |
| `fapi2-security-profile-final-par-authorization-request-containing-request_uri-form-param` | `FAILED` | `mE387EgSyQqflFg` |
| `fapi2-security-profile-final-par-ensure-pkce-required` | `FAILED` | `mZQ0Bd5mUmolzRN` |
| `fapi2-security-profile-final-ensure-pkce-code-verifier-required` | `FAILED` | `C0Nem0lAcazMYXb` |
| `fapi2-security-profile-final-incorrect-pkce-code-verifier-rejected` | `FAILED` | `Pn3a5l9zmr403M8` |
| `fapi2-security-profile-final-par-plain-pkce-rejected` | `FAILED` | `y4F3iE1Nz7CaH3l` |
| `fapi2-security-profile-final-par-without-duplicate-parameters` | `FAILED` | `pxfgGEDqJM7ZT5W` |
| `fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails` | `WAITING` | `mpsinx4AbHYPHr4` |
| `fapi2-security-profile-final-ensure-response-type-code-idtoken-fails` | `WARNING` | `aH4eGPvXCBwqNWx` |
| `fapi2-security-profile-final-ensure-response-type-token-fails` | `WARNING` | `GcfyBoFHfdyk5yX` |

Open a suite log with `<SUITE_BASE_URL>/log-detail.html?log=<id>`. See [`claude_dev/fapi-conformance-runbook.md`](../../claude_dev/fapi-conformance-runbook.md) for how to read one and how to re-run a single module.

<details><summary>Modules that passed</summary>

- `fapi2-security-profile-final-discovery-end-point-verification`
- `fapi2-security-profile-final-par-attempt-invalid-http-method`

</details>
