# oidcc-basic-certification-test-plan

- **Plan id**: `2rXitnIR6cEug`
- **Modules**: 35
- **Passed**: 30/35

**4 module(s) did not pass.** A submission built on this run would be a submission with 4 open question(s).

## Verdict summary

| Verdict | Count | What it means |
|---|---:|---|
| `REVIEW` | 4 | the suite cannot decide automatically — a human must read the log and judge |
| `SKIPPED` | 1 | not applicable to this variant |
| `PASSED` | 30 | the module's assertions all held |

## Modules that did not pass

| Module | Verdict | Suite log |
|---|---|---|
| `oidcc-prompt-login` | `REVIEW` | `NzTkhxhgIcOnymK` |
| `oidcc-max-age-1` | `REVIEW` | `KW1GJh03tS2k0Db` |
| `oidcc-ensure-registered-redirect-uri` | `REVIEW` | `SIqVqn22QkzYxg3` |
| `oidcc-ensure-request-object-with-redirect-uri` | `REVIEW` | `9b3TPXckjNdzyzD` |

Open a suite log with `<SUITE_BASE_URL>/log-detail.html?log=<id>`. See [`claude_dev/fapi-conformance-runbook.md`](../../claude_dev/fapi-conformance-runbook.md) for how to read one and how to re-run a single module.

<details><summary>Modules that passed</summary>

- `oidcc-server`
- `oidcc-response-type-missing`
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
