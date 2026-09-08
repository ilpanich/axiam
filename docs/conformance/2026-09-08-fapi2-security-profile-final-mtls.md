# fapi2-security-profile-final-test-plan

- **Plan id**: `BsK9tbLZB0GvA`
- **Modules**: 31
- **Passed**: 0/31

**31 module(s) did not pass.** A submission built on this run would be a submission with 31 open question(s).

## Verdict summary

| Verdict | Count | What it means |
|---|---:|---|
| `FAILED` | 31 | an assertion did not hold. This is a real finding. |

## Modules that did not pass

| Module | Verdict | Suite log |
|---|---|---|
| `fapi2-security-profile-final-discovery-end-point-verification` | `FAILED` | `WPdB8dGvDlXx3xo` |
| `fapi2-security-profile-final-happy-flow` | `FAILED` | `TI49gXXqFcBBDgb` |
| `fapi2-security-profile-final-user-rejects-authentication` | `FAILED` | `a3xqIscK5uhI7aB` |
| `fapi2-security-profile-final-ensure-authorization-request-without-state-success` | `FAILED` | `xQWNM64xwr9U1jV` |
| `fapi2-security-profile-final-access-token-type-header-case-sensitivity` | `FAILED` | `bkfqKYQSUhOanzK` |
| `fapi2-security-profile-final-ensure-different-state-inside-and-outside-request-object` | `FAILED` | `D3qf1EEEeO2GeR9` |
| `fapi2-security-profile-final-ensure-authorization-request-with-long-state` | `FAILED` | `Tth8fWnmz7413Pn` |
| `fapi2-security-profile-final-state-only-outside-request-object-not-used` | `FAILED` | `euM3ieANFWQH3nf` |
| `fapi2-security-profile-final-ensure-request-object-without-redirect-uri-fails` | `FAILED` | `OZ7XlF8tNJIRF0U` |
| `fapi2-security-profile-final-plain-fapi-tolerate-unregistered-redirect-uri` | `FAILED` | `18bU28oeG2qCsIh` |
| `fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails` | `FAILED` | `wPBaKaBDIbWXMOX` |
| `fapi2-security-profile-final-ensure-redirect-uri-in-authorization-request` | `FAILED` | `763uwFUKkULg5RH` |
| `fapi2-security-profile-final-ensure-response-type-code-idtoken-fails` | `FAILED` | `1LpEu4oSgWPsmWc` |
| `fapi2-security-profile-final-ensure-response-type-token-fails` | `FAILED` | `5O0QuF86PiuBGkq` |
| `fapi2-security-profile-final-ensure-client-id-in-token-endpoint` | `FAILED` | `aFvtEzFAgkA0vG4` |
| `fapi2-security-profile-final-ensure-holder-of-key-required` | `FAILED` | `umepTuMN4CzbggA` |
| `fapi2-security-profile-final-ensure-authorization-code-is-bound-to-client` | `FAILED` | `TGYPkpQKYcGGY7B` |
| `fapi2-security-profile-final-attempt-reuse-authorization-code-after-one-second` | `FAILED` | `xFQFvOvCJ1t9Az0` |
| `fapi2-security-profile-final-ensure-token-endpoint-fails-with-expired-auth-code` | `FAILED` | `foBiyChUf5tqhBQ` |
| `fapi2-security-profile-final-refresh-token` | `FAILED` | `fg6Ba2oBoQm09bz` |
| `fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` | `FAILED` | `2XjJxI0fzaeaFY2` |
| `fapi2-security-profile-final-par-attempt-reuse-request_uri` | `FAILED` | `3hoynptyhmqdUnD` |
| `fapi2-security-profile-final-par-attempt-to-use-expired-request_uri` | `FAILED` | `jC4DMA4xUXRw7kW` |
| `fapi2-security-profile-final-par-attempt-to-use-request_uri-for-different-client` | `FAILED` | `1YrYljtDNLxfNh9` |
| `fapi2-security-profile-final-par-authorization-request-containing-request_uri-form-param` | `FAILED` | `35wkuDdnghA9bc8` |
| `fapi2-security-profile-final-par-attempt-invalid-http-method` | `FAILED` | `AV5HAsKqvQUBB4D` |
| `fapi2-security-profile-final-par-ensure-pkce-required` | `FAILED` | `ryEtbQAV7PfCHOC` |
| `fapi2-security-profile-final-ensure-pkce-code-verifier-required` | `FAILED` | `XlUzXWzxJhtavJ5` |
| `fapi2-security-profile-final-incorrect-pkce-code-verifier-rejected` | `FAILED` | `kkYtIVQWZP4TeNQ` |
| `fapi2-security-profile-final-par-plain-pkce-rejected` | `FAILED` | `Otb6BG7BNFsqSB2` |
| `fapi2-security-profile-final-par-without-duplicate-parameters` | `FAILED` | `p5pQeUoZ5DY7Xs8` |

Open a suite log with `<SUITE_BASE_URL>/log-detail.html?log=<id>`. See [`claude_dev/fapi-conformance-runbook.md`](../../claude_dev/fapi-conformance-runbook.md) for how to read one and how to re-run a single module.
