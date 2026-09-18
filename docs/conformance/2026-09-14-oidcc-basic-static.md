# oidcc-basic-certification-test-plan

- **Plan id**: `3VpW8I5ho7Suo`
- **Modules**: 35
- **Passed**: 29/35

**5 module(s) did not pass.** A submission built on this run would be a submission with 5 open question(s).

## Verdict summary

| Verdict | Count | What it means |
|---|---:|---|
| `REVIEW` | 5 | the suite cannot decide automatically — a human must read the log and judge |
| `SKIPPED` | 1 | not applicable to this variant |
| `PASSED` | 29 | the module's assertions all held |

## Modules that did not pass

| Module | Verdict | Suite log |
|---|---|---|
| `oidcc-response-type-missing` | `REVIEW` | `dvxm4SQ68NVYD7Y` |
| `oidcc-prompt-login` | `REVIEW` | `Hs95VQwMAF0MLG7` |
| `oidcc-max-age-1` | `REVIEW` | `2r0TbyoI8XWdzaY` |
| `oidcc-ensure-registered-redirect-uri` | `REVIEW` | `cv76nYakHKATiIP` |
| `oidcc-ensure-request-object-with-redirect-uri` | `REVIEW` | `yucPsfL0E27CITu` |

Open a suite log with `<SUITE_BASE_URL>/log-detail.html?log=<id>`. See [`claude_dev/fapi-conformance-runbook.md`](../../claude_dev/fapi-conformance-runbook.md) for how to read one and how to re-run a single module.

<details><summary>Modules that passed</summary>

- `oidcc-server`
- `oidcc-userinfo-get`
- `oidcc-userinfo-post-header`
- `oidcc-userinfo-post-body`
- `oidcc-ensure-request-without-nonce-succeeds-for-code-flow`
- `oidcc-scope-profile`
- `oidcc-scope-email`
- `oidcc-scope-address`
- `oidcc-scope-phone`
- `oidcc-scope-all`
- `oidcc-alternate-happy-flow`
- `oidcc-display-page`
- `oidcc-display-popup`
- `oidcc-prompt-none-not-logged-in`
- `oidcc-prompt-none-logged-in`
- `oidcc-max-age-10000`
- `oidcc-ensure-request-with-unknown-parameter-succeeds`
- `oidcc-id-token-hint`
- `oidcc-login-hint`
- `oidcc-ui-locales`
- `oidcc-claims-locales`
- `oidcc-ensure-request-with-acr-values-succeeds`
- `oidcc-codereuse`
- `oidcc-codereuse-30seconds`
- `oidcc-ensure-post-request-succeeds`
- `oidcc-server-client-secret-post`
- `oidcc-claims-essential`
- `oidcc-refresh-token`
- `oidcc-ensure-request-with-valid-pkce-succeeds`

</details>
