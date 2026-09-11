# oidcc-basic-certification-test-plan

- **Plan id**: `VSWejcydXoQZv`
- **Modules**: 35
- **Passed**: 16/35

**18 module(s) did not pass.** A submission built on this run would be a submission with 18 open question(s).

## Verdict summary

| Verdict | Count | What it means |
|---|---:|---|
| `FAILED` | 5 | an assertion did not hold. This is a real finding. |
| `WAITING` | 5 | the module is waiting for a browser to complete an authorization. NOT a pass and NOT a failure — no assertion has been evaluated yet |
| `WARNING` | 8 | a non-fatal deviation; permitted, but worth understanding before submitting |
| `SKIPPED` | 1 | not applicable to this variant |
| `PASSED` | 16 | the module's assertions all held |

## Modules that did not pass

| Module | Verdict | Suite log |
|---|---|---|
| `oidcc-prompt-none-logged-in` | `FAILED` | `XfJO21X9wYe1naY` |
| `oidcc-max-age-10000` | `FAILED` | `ttoJId8AFOYQBTB` |
| `oidcc-id-token-hint` | `FAILED` | `ctRTHsXDdaI0rmr` |
| `oidcc-server-client-secret-post` | `FAILED` | `roPUxxELptgJKRj` |
| `oidcc-refresh-token` | `FAILED` | `mW64QMgPaWmYcN5` |
| `oidcc-scope-email` | `WAITING` | `f763TILzDVKCrdy` |
| `oidcc-prompt-login` | `WAITING` | `IxxlnX6TUvYNUJV` |
| `oidcc-max-age-1` | `WAITING` | `JouIPJBlWaV04Be` |
| `oidcc-ensure-registered-redirect-uri` | `WAITING` | `46JT45SUJvKeXbK` |
| `oidcc-ensure-request-object-with-redirect-uri` | `WAITING` | `8ByYr46ms2A0zK4` |
| `oidcc-server` | `WARNING` | `TSJzsApHuDgu0V3` |
| `oidcc-scope-profile` | `WARNING` | `XcANPBgKfyy0ZcY` |
| `oidcc-scope-address` | `WARNING` | `z9Px6k3cfoAhAbq` |
| `oidcc-scope-phone` | `WARNING` | `qRUhfCzLR77Mvxb` |
| `oidcc-scope-all` | `WARNING` | `fRgsLU6bwWc7cax` |
| `oidcc-alternate-happy-flow` | `WARNING` | `tNCdxJY2yYqEaDj` |
| `oidcc-codereuse-30seconds` | `WARNING` | `FvdHILiAxX7Q2lz` |
| `oidcc-claims-essential` | `WARNING` | `ECjAg9txkGe1c8Y` |

Open a suite log with `<SUITE_BASE_URL>/log-detail.html?log=<id>`. See [`claude_dev/fapi-conformance-runbook.md`](../../claude_dev/fapi-conformance-runbook.md) for how to read one and how to re-run a single module.

<details><summary>Modules that passed</summary>

- `oidcc-response-type-missing`
- `oidcc-userinfo-get`
- `oidcc-userinfo-post-header`
- `oidcc-userinfo-post-body`
- `oidcc-ensure-request-without-nonce-succeeds-for-code-flow`
- `oidcc-display-page`
- `oidcc-display-popup`
- `oidcc-prompt-none-not-logged-in`
- `oidcc-ensure-request-with-unknown-parameter-succeeds`
- `oidcc-login-hint`
- `oidcc-ui-locales`
- `oidcc-claims-locales`
- `oidcc-ensure-request-with-acr-values-succeeds`
- `oidcc-codereuse`
- `oidcc-ensure-post-request-succeeds`
- `oidcc-ensure-request-with-valid-pkce-succeeds`

</details>
