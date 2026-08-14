# FAPI 2.0 conformance runbook (X5.2)

How to run the OpenID Foundation conformance suite against AXIAM, how to read
what it tells you, and how to re-run one failing test without re-running forty.

Read the **Known gaps** section before you treat any green run as
submission-ready. It is the shortest section and the one that decides whether a
result means what you want it to mean.

---

## What this harness is for

FAPI 2.0 Security Profile (Final) certification is a *self-certification*: you
run the Foundation's own open-source test suite against your deployment, and you
submit the results. The suite is therefore both the gate and the evidence.

Two consequences shape everything below.

1. **Reproducibility is the product.** A result somebody else cannot regenerate
   is not evidence. That is why the suite version is pinned
   (`conformance/suite.env`), why the plan configurations are committed as
   templates, and why §X5.3 requires the final run to target a digest-pinned
   release image rather than a working tree.
2. **The red runs get published too.** AXIAM publishes complete benchmark
   results including its own regressions and failing tables. Conformance is
   handled the same way: `just conformance-report` writes the failures first and
   `docs/conformance/` keeps them. A report that quietly said "42 modules" and
   omitted which four were red would be the exact artifact this project exists
   not to produce.

---

## Prerequisites

- `docker` + `docker compose`, `python3`, `jq`, `curl`, `openssl`.
- **A running AXIAM with an mTLS listener.** FAPI 2.0 requires mutual-TLS client
  authentication and certificate-bound tokens, so a plain-TLS deployment cannot
  pass the plan — it will fail at client authentication in every module, which
  reads like forty failures and is one configuration problem. The benchmark
  harness's `p3-mtls` profile is the quickest way to get one:
  `cd benchmarks && just target=axiam profile=p3-mtls bench-up`.
- **The listener must trust the conformance CA.** `just conformance-certs`
  writes `conformance/certs/ca.crt`; point
  `AXIAM__SERVER__TLS__CLIENT_CA_PATH` at it (or add it to the bundle already
  configured) and restart. Without this the `tls_client_auth` client's
  certificate is rejected during the TLS handshake, *before* AXIAM sees a
  request — so AXIAM's own logs show nothing and the suite reports a transport
  error.
- An admin bearer token for the tenant under test, in `AXIAM_ADMIN_TOKEN`.

---

## First run, in order

```bash
just conformance-certs          # two client certs: CA-issued and self-signed
# ... configure AXIAM's client-CA bundle to include conformance/certs/ca.crt,
#     set AXIAM_ISSUER and AXIAM_TENANT_ID in conformance/suite.env, restart ...
just conformance-up             # pinned suite, ~60s to ready
export AXIAM_ADMIN_TOKEN=...
just conformance-register       # creates both fapi2 clients, fills suite.env
just conformance-run            # drives both plans
just conformance-report         # docs/conformance/*.md
```

`conformance-register` creates both clients with `profile: "fapi2"`. That single
field is what makes them FAPI-shaped: AXIAM refuses the registration unless it
also carries `require_par`, an mTLS `token_endpoint_auth_method`, and
`tls_client_certificate_bound_access_tokens`. If registration succeeds, the
clients satisfy the profile's structural requirements by construction — you
cannot have forgotten one.

### The two variants

X5.2 calls for both client-authentication variants, and the harness runs both:

| Plan config | Method | Credential AXIAM matches |
|---|---|---|
| `…-mtls.json` | `tls_client_auth` (RFC 8705 §2.1) | the registered subject DN or SAN |
| `…-self-signed.json` | `self_signed_tls_client_auth` (RFC 8705 §2.2) | the registered `x5t#S256` thumbprint |

Both are mutual-TLS methods. See **Known gaps** for why that is not the same as
covering both of FAPI's client-authentication families.

---

## Reading a result

`just conformance-report` writes one Markdown file per plan under
`docs/conformance/`, with the modules that did not pass listed first, by
severity. The suite's verdicts mean:

| Verdict | Meaning | Blocks submission? |
|---|---|---|
| `PASSED` | every assertion held | no |
| `SKIPPED` | not applicable to this variant | no |
| `WARNING` | a permitted deviation the suite wants you to notice | usually not — but understand it |
| `REVIEW` | the suite cannot decide automatically; a human reads the log | **you must actually read it** |
| `INTERRUPTED` / `TIMEOUT` | the module did not finish — very often an interactive step nobody completed | yes, until resolved |
| `FAILED` | an assertion did not hold | **yes** |
| `COULD_NOT_START` | the suite refused to start it — a configuration problem, not a result | yes |

**`REVIEW` is not a pass.** It is the suite saying it cannot judge this one
mechanically. Treating a wall of `REVIEW` as green is the most common way a
first submission comes back rejected.

### Interactive modules

Several FAPI 2.0 modules require a browser to complete an authorization —
that is inherent to testing an authorization-code flow, not a gap in the
harness. `run-plan.sh` starts them, waits `CONFORMANCE_MODULE_TIMEOUT`
(default 180 s), and records what it found. Finish them in the suite UI at
`<SUITE_BASE_URL>/plan-detail.html?plan=<id>`, then re-run the report.

### Opening a log

Every non-passing module in the report carries its test id. Open it at:

```
<SUITE_BASE_URL>/log-detail.html?log=<testId>
```

Read from the **bottom**. The suite logs each condition it evaluated; the last
red entry is the assertion that actually failed, and everything above it is
context that succeeded.

### Re-running one module

Re-running a whole plan to retest one module wastes twenty minutes. From the
suite UI, use the plan detail page's per-module re-run. From the API:

```bash
set -a; . conformance/suite.env; set +a
curl -sSk -X POST "$SUITE_BASE_URL/api/runner?test=<moduleName>&plan=<planId>" \
  -H 'Content-Type: application/json'
```

The plan id is in the report and in `conformance/.run/results/*.results.json`.

---

## Failures you should expect to hit first

These are configuration, not conformance. Recognising them saves the evening.

| Symptom | Cause |
|---|---|
| Every module fails at the authorization step | The suite's redirect URI is not registered. `conformance-register` derives it from `SUITE_BASE_URL`; if you changed that afterwards, re-register. |
| Every module fails at the token endpoint with `invalid_client` | The listener is not requesting client certificates, or does not trust `conformance/certs/ca.crt`. AXIAM answers `invalid_client` for *every* mTLS authentication failure by design (SEC-086), so the wire response cannot tell you which — check the server log, which names the specific reason. |
| The suite cannot reach the issuer | `AXIAM_ISSUER` names `localhost`, which inside the suite's container is the suite. Use `host.docker.internal` (the compose file maps it on Linux too). |
| Discovery fails | AXIAM's discovery document is tenant-scoped; `AXIAM_TENANT_ID` must be set in `suite.env`. |
| `COULD_NOT_START` on everything | The plan name changed upstream. Override with `CONFORMANCE_PLAN_NAME=…`, and update `justfile`'s default. |

---

## Known gaps — read this before submitting

**`private_key_jwt` is not implemented.** FAPI 2.0 §5.3.1.1 permits two
families of client authentication: `private_key_jwt` (RFC 7523) and mutual TLS
(RFC 8705). AXIAM implements the mutual-TLS family, both of its methods. It does
**not** implement `private_key_jwt`.

X5.1's plan lists `private_key_jwt` as the second half of that row, and this
pass deliberately landed the first half only — mTLS is AXIAM's differentiator
and the infrastructure for it already existed. The consequence for
certification is concrete and should not be discovered late:

- The two plans here cover **both RFC 8705 mTLS methods**, not both FAPI
  client-authentication families.
- A submission that claims coverage of `private_key_jwt` cannot be built on
  these runs.
- Whether the Foundation requires both families for a given certification is a
  question for the certification team; the fee-waiver letter (§X5.4) already
  says the submission will cover "both `private_key_jwt` and mutual-TLS client
  authentication variants", **and that sentence is currently ahead of the
  implementation.** Either implement `private_key_jwt` before sending, or amend
  that sentence. Do not send it as drafted.

**DPoP is not implemented.** FAPI 2.0 accepts either mTLS certificate binding or
DPoP for sender-constraining. AXIAM implements the mTLS half, which satisfies
the requirement — but a client that cannot do mTLS has no route to a
sender-constrained token here. This is a coverage limitation, not a conformance
failure.

**No run has been performed yet.** As of this document's addition, the harness
exists and has not been executed against a live deployment — there is no docker
daemon in the environment it was written in. `docs/conformance/` is therefore
empty. The first person to run it should expect to find harness bugs, and
should fix them here rather than working around them locally.

---

## What is already enforced, and needs no new work

X5.1's audit-list items — verified in the tree, covered by tests, and pinned by
`crates/axiam-oauth2/src/fapi.rs`'s module table so a later convenience change
cannot quietly undo one:

- **Authorization code single-use.** Guaranteed, not merely intended: since X6
  (#316) and #318 all four single-use consume paths run a guarded `UPDATE`
  inside an explicit transaction with a post-commit nonce read-back, on an
  attested persistent engine.
- **Strict `redirect_uri` equality.** `redirect_uris.contains()`. No prefix
  matching, no wildcards, anywhere.
- **`response_type=code` only.** No other value is accepted for any client, and
  no token ever appears in a URL because no implicit-style response exists.
- **Algorithms.** `EdDSA` is hard-coded at both encode and decode. `none` is
  not reachable.
- **PKCE.** `S256` only, for every client; mandatory for public clients
  (SEC-025) and, under the `fapi2` profile, for confidential ones too.

---

## Moving the suite pin

Change `SUITE_VERSION` in `conformance/suite.env`, `just conformance-up`, re-run.
Commit the new reports **alongside** the old ones rather than over them: a
version bump that changes a verdict is itself a finding, and the diff is the
only place it is visible.
