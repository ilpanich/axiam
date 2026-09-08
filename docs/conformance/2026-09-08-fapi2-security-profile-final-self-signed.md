# fapi2-security-profile-final-test-plan

- **Plan id**: `FMAheek9k0Vi2`
- **Modules**: 37
- **Passed**: 1/37

**35 module(s) did not pass.** A submission built on this run would be a submission with 35 open question(s).

## Verdict summary

| Verdict | Count | What it means |
|---|---:|---|
| `FAILED` | 34 | an assertion did not hold. This is a real finding. |
| `WAITING` | 1 | the module is waiting for a browser to complete an authorization. NOT a pass and NOT a failure — no assertion has been evaluated yet |
| `SKIPPED` | 1 | not applicable to this variant |
| `PASSED` | 1 | the module's assertions all held |

## Modules that did not pass

| Module | Verdict | Suite log |
|---|---|---|
| `fapi2-security-profile-final-happy-flow` | `FAILED` | `li03kJl95w5FUrM` |
| `fapi2-security-profile-final-user-rejects-authentication` | `FAILED` | `V12M6ONU1ohIa0R` |
| `fapi2-security-profile-final-ensure-authorization-request-without-state-success` | `FAILED` | `OtEGpN2WgbUaQxr` |
| `fapi2-security-profile-final-ensure-authorization-request-without-nonce-success` | `FAILED` | `3KTzFZPrzwA1o4K` |
| `fapi2-security-profile-final-ensure-authorization-request-with-64-char-nonce-success` | `FAILED` | `bwEN0runkAdFvxz` |
| `fapi2-security-profile-final-ensure-other-scope-order-succeeds` | `FAILED` | `a47wD30jKpUZ3kC` |
| `fapi2-security-profile-final-access-token-type-header-case-sensitivity` | `FAILED` | `JwAjq1wFgdQnTbd` |
| `fapi2-security-profile-final-ensure-different-nonce-inside-and-outside-request-object` | `FAILED` | `h5SJRwruJQQyfiu` |
| `fapi2-security-profile-final-ensure-different-state-inside-and-outside-request-object` | `FAILED` | `L7KSCmOWx7ofrkZ` |
| `fapi2-security-profile-final-ensure-authorization-request-with-long-nonce` | `FAILED` | `EYMXwrjkgPUvzMu` |
| `fapi2-security-profile-final-ensure-authorization-request-with-long-state` | `FAILED` | `FOUnJk6oq1Ffzeu` |
| `fapi2-security-profile-final-state-only-outside-request-object-not-used` | `FAILED` | `89VOJlKO1CjarHH` |
| `fapi2-security-profile-final-ensure-request-object-without-redirect-uri-fails` | `FAILED` | `qPXmVhksex6UI8l` |
| `fapi2-security-profile-final-plain-fapi-tolerate-unregistered-redirect-uri` | `FAILED` | `7Tnv68bJChJyRPp` |
| `fapi2-security-profile-final-ensure-redirect-uri-in-authorization-request` | `FAILED` | `72eMVg5KWH1FQJ1` |
| `fapi2-security-profile-final-ensure-response-type-code-idtoken-fails` | `FAILED` | `rnWXkYo4K2rt0re` |
| `fapi2-security-profile-final-ensure-response-type-token-fails` | `FAILED` | `QeWCjNwO7tJlaFs` |
| `fapi2-security-profile-final-ensure-client-id-in-token-endpoint` | `FAILED` | `4lbSNPN0oDKxP63` |
| `fapi2-security-profile-final-ensure-holder-of-key-required` | `FAILED` | `cixjNuNertGjMUr` |
| `fapi2-security-profile-final-ensure-authorization-code-is-bound-to-client` | `FAILED` | `zlcTDRjTSod8l2l` |
| `fapi2-security-profile-final-attempt-reuse-authorization-code-after-one-second` | `FAILED` | `o9ZIMWFJzoNRwis` |
| `fapi2-security-profile-final-ensure-token-endpoint-fails-with-expired-auth-code` | `FAILED` | `GVLgM4tmLkJQTrd` |
| `fapi2-security-profile-final-refresh-token` | `FAILED` | `57CxywyaJBtpbOz` |
| `fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` | `FAILED` | `F39NMFLZLxhLdi5` |
| `fapi2-security-profile-final-par-attempt-reuse-request_uri` | `FAILED` | `q0xGx2GK9oyqiVK` |
| `fapi2-security-profile-final-par-attempt-to-use-expired-request_uri` | `FAILED` | `WKNhf1tSLszYS5o` |
| `fapi2-security-profile-final-par-attempt-to-use-request_uri-for-different-client` | `FAILED` | `Sv6d6p3rAR8bSK3` |
| `fapi2-security-profile-final-par-authorization-request-containing-request_uri-form-param` | `FAILED` | `seX7KzzhybRPYKy` |
| `fapi2-security-profile-final-par-attempt-invalid-http-method` | `FAILED` | `tEQ1sHd4vFMAfWf` |
| `fapi2-security-profile-final-par-ensure-pkce-required` | `FAILED` | `lkeF3qyrV3xWYqL` |
| `fapi2-security-profile-final-ensure-pkce-code-verifier-required` | `FAILED` | `87ElGTvsnSczhnB` |
| `fapi2-security-profile-final-incorrect-pkce-code-verifier-rejected` | `FAILED` | `fudF1avNOGZgNQV` |
| `fapi2-security-profile-final-par-plain-pkce-rejected` | `FAILED` | `pm9nUo0lX3iqjiO` |
| `fapi2-security-profile-final-par-without-duplicate-parameters` | `FAILED` | `6nbSxZYawvP9hfV` |
| `fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails` | `WAITING` | `47RYsD0wS6uJcvr` |

Open a suite log with `<SUITE_BASE_URL>/log-detail.html?log=<id>`. See [`claude_dev/fapi-conformance-runbook.md`](../../claude_dev/fapi-conformance-runbook.md) for how to read one and how to re-run a single module.

<details><summary>Modules that passed</summary>

- `fapi2-security-profile-final-discovery-end-point-verification`

</details>
