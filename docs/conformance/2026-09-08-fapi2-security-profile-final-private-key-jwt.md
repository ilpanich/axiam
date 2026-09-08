# fapi2-security-profile-final-test-plan

- **Plan id**: `dklOtBRsS52Uq`
- **Modules**: 56
- **Passed**: 6/56

**48 module(s) did not pass.** A submission built on this run would be a submission with 48 open question(s).

## Verdict summary

| Verdict | Count | What it means |
|---|---:|---|
| `FAILED` | 44 | an assertion did not hold. This is a real finding. |
| `WAITING` | 1 | the module is waiting for a browser to complete an authorization. NOT a pass and NOT a failure — no assertion has been evaluated yet |
| `WARNING` | 3 | a non-fatal deviation; permitted, but worth understanding before submitting |
| `SKIPPED` | 2 | not applicable to this variant |
| `PASSED` | 6 | the module's assertions all held |

## Modules that did not pass

| Module | Verdict | Suite log |
|---|---|---|
| `fapi2-security-profile-final-happy-flow` | `FAILED` | `mNYmn6V1CebypEy` |
| `fapi2-security-profile-final-user-rejects-authentication` | `FAILED` | `IzDku6JSVHWeKfP` |
| `fapi2-security-profile-final-ensure-authorization-request-without-state-success` | `FAILED` | `u67FeIHmgHSHbgb` |
| `fapi2-security-profile-final-ensure-authorization-request-without-nonce-success` | `FAILED` | `flJWqL9ZQQtOdo1` |
| `fapi2-security-profile-final-ensure-authorization-request-with-64-char-nonce-success` | `FAILED` | `SY9unaQ6TEMoP18` |
| `fapi2-security-profile-final-ensure-other-scope-order-succeeds` | `FAILED` | `0eB8JbOdQCnjXhf` |
| `fapi2-security-profile-final-access-token-type-header-case-sensitivity` | `FAILED` | `vN8UijzA1uxR8Aq` |
| `fapi2-security-profile-final-check-dpop-proof-nbf-exp` | `FAILED` | `lpDcn2FV0BzIg25` |
| `fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-before-succeeds` | `FAILED` | `Fgq8DEoxbgr9gri` |
| `fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-after-succeeds` | `FAILED` | `GauA6ScW8trhOy5` |
| `fapi2-security-profile-final-ensure-mismatched-dpop-jkt-fails` | `FAILED` | `IDgOUY05acS3dur` |
| `fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt` | `FAILED` | `gDapxEgfkJxE4ta` |
| `fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-jkt` | `FAILED` | `pcrsqyVZgLAVhtt` |
| `fapi2-security-profile-final-ensure-dpopproof-at-par-endpoint-binding-success` | `FAILED` | `w8cnZcvlaIqyXK9` |
| `fapi2-security-profile-final-ensure-dpop-auth-code-binding-success` | `FAILED` | `Dn7kZnsOGWtunkV` |
| `fapi2-security-profile-final-ensure-different-nonce-inside-and-outside-request-object` | `FAILED` | `pei4fMU9BbL0vN1` |
| `fapi2-security-profile-final-ensure-different-state-inside-and-outside-request-object` | `FAILED` | `Ye6uE7G5clhWVZz` |
| `fapi2-security-profile-final-ensure-authorization-request-with-long-nonce` | `FAILED` | `Wr1hFM3JqUtuZ8d` |
| `fapi2-security-profile-final-ensure-authorization-request-with-long-state` | `FAILED` | `J0aTOyE2WbB7mz2` |
| `fapi2-security-profile-final-state-only-outside-request-object-not-used` | `FAILED` | `Kcp6omXX6Olvjgj` |
| `fapi2-security-profile-final-ensure-request-object-without-redirect-uri-fails` | `FAILED` | `R2x4Ccc5hI9GbS7` |
| `fapi2-security-profile-final-plain-fapi-tolerate-unregistered-redirect-uri` | `FAILED` | `Sp0WjXcqGVns82V` |
| `fapi2-security-profile-final-ensure-redirect-uri-in-authorization-request` | `FAILED` | `1QnZ7LpgehmsG1x` |
| `fapi2-security-profile-final-ensure-client-id-in-token-endpoint` | `FAILED` | `1TzEnX3wyIWPGYB` |
| `fapi2-security-profile-final-ensure-holder-of-key-required` | `FAILED` | `RvU0DKpcHmM6Bdx` |
| `fapi2-security-profile-final-ensure-authorization-code-is-bound-to-client` | `FAILED` | `VFUCtfOTuEKoM1a` |
| `fapi2-security-profile-final-attempt-reuse-authorization-code-after-one-second` | `FAILED` | `5bKhZndcOpJUY7e` |
| `fapi2-security-profile-final-ensure-token-endpoint-fails-with-expired-auth-code` | `FAILED` | `KMpL5DtVhwPdrNk` |
| `fapi2-security-profile-final-ensure-client-assertion-in-token-endpoint` | `FAILED` | `0ZZo6zWLnrOWIGg` |
| `fapi2-security-profile-final-ensure-client-assertion-with-exp-is-5-minutes-in-past-fails` | `FAILED` | `FLtWANkc5hPmAK0` |
| `fapi2-security-profile-final-ensure-client-assertion-with-wrong-aud-fails` | `FAILED` | `uPaT1fSTi97l3AZ` |
| `fapi2-security-profile-final-ensure-client-assertion-with-no-sub-fails` | `FAILED` | `IvvfcdCLcSXGatE` |
| `fapi2-security-profile-final-dpop-negative-tests` | `FAILED` | `dlWuKtDyBntZjDH` |
| `fapi2-security-profile-final-refresh-token` | `FAILED` | `4kkbb4zCPKHI5Bo` |
| `fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` | `FAILED` | `CSDe3u6bHeKnDij` |
| `fapi2-security-profile-final-par-attempt-reuse-request_uri` | `FAILED` | `oxsDyAXZ2GXpNfR` |
| `fapi2-security-profile-final-par-attempt-to-use-expired-request_uri` | `FAILED` | `ZXRESTvTdtrJf6R` |
| `fapi2-security-profile-final-par-attempt-to-use-request_uri-for-different-client` | `FAILED` | `fZgfhKim8DbmlOs` |
| `fapi2-security-profile-final-par-authorization-request-containing-request_uri-form-param` | `FAILED` | `bNhpwe5m96JQAam` |
| `fapi2-security-profile-final-par-ensure-pkce-required` | `FAILED` | `WtP6Corj4odWf7y` |
| `fapi2-security-profile-final-ensure-pkce-code-verifier-required` | `FAILED` | `UxpZXp7JjdlAdMw` |
| `fapi2-security-profile-final-incorrect-pkce-code-verifier-rejected` | `FAILED` | `luxNeMHH494kF1Q` |
| `fapi2-security-profile-final-par-plain-pkce-rejected` | `FAILED` | `tcHW9CrAxzro5IQ` |
| `fapi2-security-profile-final-par-without-duplicate-parameters` | `FAILED` | `cItAb1ABCgYRaOC` |
| `fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails` | `WAITING` | `erhnT6nl5IxsTkt` |
| `fapi2-security-profile-final-ensure-response-type-code-idtoken-fails` | `WARNING` | `YMqD3ks79yRpcHo` |
| `fapi2-security-profile-final-ensure-response-type-token-fails` | `WARNING` | `17LVucoxDBEyBch` |
| `fapi2-security-profile-final-par-ensure-jwt-client-assertions-nbf-8-seconds-in-the-future-is-accepted` | `WARNING` | `NteVSublQtW4JTd` |

Open a suite log with `<SUITE_BASE_URL>/log-detail.html?log=<id>`. See [`claude_dev/fapi-conformance-runbook.md`](../../claude_dev/fapi-conformance-runbook.md) for how to read one and how to re-run a single module.

<details><summary>Modules that passed</summary>

- `fapi2-security-profile-final-discovery-end-point-verification`
- `fapi2-security-profile-final-par-ensure-jwt-client-assertions-nbf-over-60-seconds-in-the-future-fails`
- `fapi2-security-profile-final-par-attempt-invalid-http-method`
- `fapi2-security-profile-final-par-test-array-as-audience-fails`
- `fapi2-security-profile-final-par-test-par-endpoint-url-as-audience-fails`
- `fapi2-security-profile-final-par-test-token-endpoint-url-as-audience-fails`

</details>
