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

`conformance-register` creates all three clients with `profile: "fapi2"`. That
single field is what makes them FAPI-shaped: AXIAM refuses the registration
unless it also carries `require_par`, a **strong** `token_endpoint_auth_method`
(either mTLS method or `private_key_jwt`), and **some** sender-constraining
(`tls_client_certificate_bound_access_tokens` or `dpop_bound_access_tokens`). If
registration succeeds, the clients satisfy the profile's structural requirements
by construction — you cannot have forgotten one.

The gate accepts all four pairings of the two families; it does not require the
authentication family and the binding mechanism to match. What it refuses is a
client with strong authentication and sender-constraining from *neither*, which
is the shape a half-finished migration produces.

### The three variants

X5.2 calls for both client-authentication *families*, and since contract 1.16
the harness runs all three methods across both:

| Plan config | Family | Method | Credential AXIAM matches |
|---|---|---|---|
| `…-mtls.json` | mutual TLS | `tls_client_auth` (RFC 8705 §2.1) | the registered subject DN or SAN |
| `…-self-signed.json` | mutual TLS | `self_signed_tls_client_auth` (RFC 8705 §2.2) | the registered `x5t#S256` thumbprint |
| `…-private-key-jwt.json` | asymmetric JWT | `private_key_jwt` (RFC 7523 §2.2) | a signature under the client's registered `jwks` / `jwks_uri` |

The third variant is the one that needs no mTLS listener at all — which is both
its point and a useful diagnostic. If the first two plans fail at client
authentication and the third passes, the problem is your listener's client-CA
bundle, not AXIAM.

Its client is registered with `dpop_bound_access_tokens` rather than
`tls_client_certificate_bound_access_tokens`, so the plan also exercises the
DPoP half of sender-constraining end to end. The suite generates the proof key;
nothing in `conformance/certs/` is involved.

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

#### The manual same-tab trick, and what W3 changes about it

Those modules are finished by hand in a browser tab that already holds an admin
UI session, because `axiam_access` is `SameSite=Strict` and would not otherwise
survive the suite's cross-site redirect. That trick still works and is still
what these runs use.

Since **W3** (`claude_dev/basic-op-gap-plan.md` §4.0) there is an alternative:
register the harness's clients with `"browser_sso": true` and add
`tenant_id=$AXIAM_TENANT_ID` to the authorization request, and the suite's own
redirect reaches a sign-in page instead of a `401`. That is what the plan's W9
Basic OP harness is designed around, and it is the reason `browser_sso` is
permitted on `fapi2` clients (§11, D2).

Do **not** flip it on the existing FAPI clients before run #3. Plan §8's
promise is that runs #1 and #2 equal the W0 baseline, and a comparison is only
worth making if the client registrations did not move underneath it. See
[`docs/admin/browser-login-hop.md`](../docs/admin/browser-login-hop.md) for the
cookie, the `SameSite=Lax` iframe limitation, and the 60-second PAR window that
bounds how long a hop may take.

### Opening a log

Every non-passing module in the report carries its test id. Open it at:

```
<SUITE_BASE_URL>/log-detail.html?log=<testId>
```

Read from the **bottom**. The suite logs each condition it evaluated; the last
red entry is the assertion that actually failed, and everything above it is
context that succeeded.

### Running a handful of modules

`conformance/scripts/run-some.sh` creates one plan and starts only the modules
you name in it. A whole-plan sweep is the wrong tool while iterating on two
modules — it is dozens of authorizations, several of which deliberately sleep
out a 60-second window.

```bash
just conformance-drive &          # the browser driver, as for a full sweep
conformance/scripts/run-some.sh \
  conformance/plans/fapi2-security-profile-final-mtls.json \
  fapi2-security-profile-final-test-plan \
  fapi2-security-profile-final-happy-flow \
  fapi2-security-profile-final-par-attempt-reuse-request_uri
```

It prints `status / result` per module and writes each module's **full** log to
`conformance/.run/some/`. Read the file rather than the UI: the UI truncates a
condition's text, and for a `REVIEW` the truncated part is usually the half that
says what evidence it wants.

**Reading the evidence, and the one way to get it backwards.** On a log entry a
filled screenshot slot appears as `img`, and the suite sets `upload` to **null**
once it is filled. So `img` present means evidence exists; `upload` present means
it is still missing. Reading it the other way round makes a run with complete
evidence look like one with none.

### One browser driver, ever

Two deliver two callbacks for one URL and the suite throws
`runInBackground called after runFinalisationTaskInBackground()`. Check with
`pgrep -a -f drive-browser.mjs` and **read the rows** — `pgrep -c` matches its
own command line and always over-counts. Kill by PID; a `pkill -f` whose pattern
appears in your own command line kills the shell that ran it (exit 144).

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
| Every module fails at the token endpoint with `invalid_client` | The listener is not requesting client certificates, or does not trust `conformance/certs/ca.crt`. AXIAM answers `invalid_client` for *every* client-authentication failure by design (SEC-086), so the wire response cannot tell you which — check the server log, which names the specific reason. |
| Only the `private-key-jwt` plan fails at the token endpoint | AXIAM could not obtain the client's keys. If the plan registered a `jwks_uri`, AXIAM fetches it through the SSRF-guarded JWKS cache, which **refuses private and loopback addresses** — a suite running on `host.docker.internal` publishes its JWKS somewhere AXIAM will not fetch from. Register the suite's key set inline (`jwks`) instead; `conformance-register` does this by default for exactly this reason. (Since SEC-107 there is also `AXIAM__PKI__SSRF_ALLOWED_HOSTS`, but inline `jwks` remains the right answer here — the allowlist exists for a production IdP an operator vouches for, not to loosen the guard for a test harness.) |
| The `private-key-jwt` plan fails only on repeated runs | The `jti` replay guard is doing its job. The suite reuses assertion identifiers across a re-run of the *same* module in some versions; each assertion is single-use, permanently. Re-run the whole plan rather than one module, or wait out `oauth2_proof_replay`'s cleanup. |
| A DPoP module fails with `use_dpop_nonce` and does not recover | ~~The client was registered with `dpop_require_nonce: true`.~~ **No longer reachable (SEC-097).** That flag was persisted and API-visible but never read by any code path, so it could not have produced this symptom in the first place; `POST`/`PUT /api/v1/oauth2-clients` now refuse `dpop_require_nonce: true` with 400 rather than storing a switch that does nothing. If a DPoP module still fails this way, the cause is elsewhere — read the server log rather than the client registration. |
| The suite cannot reach the issuer | `AXIAM_ISSUER` names `localhost`, which inside the suite's container is the suite. Use `host.docker.internal` (the compose file maps it on Linux too). |
| Discovery fails | AXIAM's discovery document is tenant-scoped; `AXIAM_TENANT_ID` must be set in `suite.env`. |
| `COULD_NOT_START` on everything | The plan name changed upstream. Override with `CONFORMANCE_PLAN_NAME=…`, and update `justfile`'s default. |
| `POST /api/v1/admin/bootstrap` answers `403` on a fresh deployment | The bootstrap gate is not open. It is satisfied either by starting the server with `AXIAM_BOOTSTRAP_ADMIN_EMAIL` set to the administrator you are about to create, or by the one-time setup token the server mints and logs on its first boot. It is a property of the **server process**, not of the request, so no amount of re-sending the body will change the answer. |
| `register-clients.sh basic` exits with `sensitive_scopes_enabled did not stick` | Fixed 2026-09-14; this row is kept because the symptom named the wrong field for a month. `GET /organizations/{id}/settings` answers a **grouped** document and `PUT` is a **flat full replacement**, so echoing the GET back fails with `missing field min_length` — and the script sent that response to `/dev/null`. The registrar now flattens every object-valued group before the PUT, the way `benchmarks/runner/seed.sh` has since 2026-08-30. |
| Every module fails at discovery with a PKIX / "unable to find valid certification path" error | The suite's JVM truststore does not carry `conformance/certs/ca.crt`. `conformance-up` imports it and restarts the suite container; before 2026-09-14 `suite.env` said it did and it did not. The JVM reads its truststore at boot, so importing without the restart changes nothing. |

---

## Known gaps — read this before submitting

Two of the three entries this section carried have been closed. They are
rewritten rather than deleted, because *why* a gap existed is the part a reader
six months from now cannot reconstruct.

**`private_key_jwt` is implemented (closed 2026-08-14).** FAPI 2.0 §5.3.1.1
permits two families of client authentication: `private_key_jwt` (RFC 7523) and
mutual TLS (RFC 8705). AXIAM now implements **both**, and the harness covers
both.

The earlier revision of this section said `private_key_jwt` was absent and drew
the consequence out at length: that the two plans covered both RFC 8705 *methods*
but only one FAPI *family*, and that §X5.4's fee-waiver letter — which promises a
submission "covering both `private_key_jwt` and mutual-TLS client authentication
variants" — was ahead of the implementation, so it must be amended or the
implementation finished before sending. **The implementation was finished.** That
was option B in
[`fapi-certification-submission.md`](fapi-certification-submission.md)'s A/B/C
decision, and taking it means:

- The plans here now cover **both FAPI client-authentication families**, across
  three methods (`tls_client_auth`, `self_signed_tls_client_auth`,
  `private_key_jwt`).
- A submission claiming coverage of `private_key_jwt` **can** be built on these
  runs.
- **§X5.4's letter needs no amendment.** Its scope sentence is now accurate as
  originally drafted. Do not edit it; the reason the earlier revision said not to
  send it as written no longer applies.

Why the first half landed alone in the first pass: mTLS is AXIAM's
differentiator and the listener infrastructure already existed, so the mTLS half
was nearly free while `private_key_jwt` needed key resolution, an SSRF-guarded
`jwks_uri` fetch, and a single-use `jti` store. Splitting the row was the right
call; leaving it split would not have been.

**DPoP is implemented (closed 2026-08-14).** FAPI 2.0 accepts either mTLS
certificate binding or DPoP for sender-constraining. AXIAM previously
implemented only the mTLS half, which satisfied the requirement — but a client
that cannot present a certificate to AXIAM directly (anything behind a
TLS-terminating load balancer it does not control) had **no route to a
sender-constrained token here at all.** That was a coverage limitation rather
than a conformance failure, and it is now closed: `cnf.jkt`, proof verification
at the token endpoint and at resource-server validation, the `DPoP` token type,
and the `DPoP-Nonce` challenge path all exist.

What the closure costs, stated plainly because the alternative is discovering it
under load: **DPoP pays an asymmetric signature verification per request**,
where mTLS binding pays one SHA-256 amortised over a connection. The two are in
different cost classes. §X5.1's "What sender-constraining actually costs"
subsection carries the measured figures and is explicit about which of them are
criterion micro-benchmarks rather than end-to-end measurements. A client that can
do mTLS should.

**The harness had never been executed, and it did not work (closed 2026-09-08,
W9).** This entry used to say no run had been performed, because the
environments X5.1 and X5.2 were written in had no docker daemon. It has now been
run. The prediction it made — "the first person to run it should expect to find
harness bugs, and should fix them here rather than working around them locally"
— was correct, and understated: **fourteen** defects stood between the committed
harness and a single executed module, and the three FAPI plan templates could
not create a plan at all.

The full list, with what each one looked like when it bit, is in
[`docs/conformance/README.md`](../docs/conformance/README.md). The four worth
knowing before you touch this harness again:

- **The suite image reference was wrong and the pin was unobtainable.**
  `SUITE_IMAGE` named `ghcr.io/openid/conformance-suite`, which does not exist —
  the pull fails with `denied`, which reads like a credentials problem and is
  not one. The suite is published to `registry.gitlab.com`, exactly as
  `suite.env`'s own comment always said. And the pinned tag `release-v5.1.34`
  had been **reaped**: that registry retains only its most recent releases. This
  file argued at length that pinning is what makes a result reproducible; a
  *tag* pin is precisely what a retention policy can delete. The pin is now a
  **digest**, with the tag kept as a human-readable label.
- **The compose file could not start the suite.** It set `MONGODB_URI`, which
  the image does not read; it left `OIDC_GITLAB_CLIENTID` unset, which the
  entrypoint turns into an *empty* property that makes Spring refuse to boot;
  and — the structural one — it had deliberately trimmed upstream's nginx
  sidecar as "an httpd fronting a hosted deployment". That sidecar is where the
  suite's TLS comes from. The application serves plain HTTP on 8080 and
  **refuses any request that did not arrive over TLS**, so the trimmed compose
  produced a suite that could not answer anything, on a port nothing published.
- **The FAPI plans had never been runnable.** All three templates carried
  `fapi_client_type`, a FAPI 1.0 variant the suite rejects outright, and
  `fapi_request_method`/`fapi_response_mode`, which are module-level variants
  the plan sets itself and refuses to accept from a user. Every one of the three
  failed at *plan creation*, before a module existed to fail.
- **`suite.env` is tracked, and the registrars rewrite it in place.** The FAPI
  lane only ever wrote client ids so this stayed survivable; the Basic OP lane
  writes client **secrets**. Configuration is now split — `suite.env` keeps the
  reviewable shape, and the gitignored `suite.local.env` takes the values.

**Baseline run #0 happened, and W9 absorbed it.** The plan's §8 asks for the
FAPI plans to be run on `main` before anything else, and this is that run —
performed first, from this branch's corrected harness, because the uncorrected
one could not run at all. What that means for the comparison §8 wanted is
honest but limited: **runs #1 and #2 still do not exist**, and cannot be
reconstructed, because the harness that would have produced them was broken for
the whole period they were supposed to cover. The argument that W1–W3 changed
nothing on the FAPI lane therefore continues to rest where it always rested —
on §8's construction (every addition is per-client opt-in or a refusal, and the
FAPI plans run `openid: plain_oauth`, so they exercise no OpenID Connect
authentication-request parameter at all) plus the unit and integration pins in
`docs/compliance/oidc-conformance.md`. Run #0's real value is different and
larger: it is the first evidence of what the FAPI lane actually does, and it
found three genuine discovery-document gaps that no unit test had.

**A conformance run needs a deployment that serves the admin SPA (open).** The
W3 login hop redirects to `LOGIN_PATH`, a same-origin `/login`
(`crates/axiam-oauth2/src/login_hop.rs`) — same-origin deliberately, since that
is what keeps `return_to` path-only. The `axiam-server` binary alone does not
serve that route, so `just conformance-serve` is sufficient for the metadata
half of a plan (discovery, JWKS, token, userinfo) and **cannot complete a single
authorization module**. Every one of the Basic OP plan's 35 modules needs an
authorization, and all 35 sat in `WAITING`. Until a conformance target serves
both the SPA and the API on one origin — which the production nginx image does —
the interactive modules must be finished by hand, and `browser_sso` buys nothing
in an unattended run. This is the entry now blocking a submission.

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
- **Algorithms.** `EdDSA` is hard-coded at both encode and decode for AXIAM's own
  tokens. For the signatures AXIAM *verifies* rather than mints — client
  assertions and DPoP proofs — `crates/axiam-oauth2/src/jose.rs` permits exactly
  `PS256`, `ES256` and `EdDSA`, takes the algorithm from the **registered or
  embedded key rather than the JWS header**, and refuses `RS256` explicitly.
  `none` is unreachable twice over: `jsonwebtoken::Algorithm` has no such
  variant, and the permitted list would not contain it if it did.
- **PKCE.** `S256` only, for every client; mandatory for public clients
  (SEC-025) and, under the `fapi2` profile, for confidential ones too.

---

## Maintainer run checklist (before the release tag)

Decision of 2026-10-03: the maintainer runs the OpenID conformance suites —
Basic OP and the FAPI 2.0 variants — **personally, before the release tag**.
Nothing in an agent session produces a final run, and nothing below is a result;
it is what to do and what to compare. The submission itself (§X5.3, next section)
is sent by the maintainer only.

The FAPI items were completed by T23.1.7 together with the judgements
(`docs/conformance/REVIEW-JUDGEMENTS.md`) and the submission package
([`fapi-certification-submission.md`](fapi-certification-submission.md)); the Basic
OP items are T23.1.6's. Nothing here is a run result. The 2026-09-25 baseline was
run on a build that **predates the Phase 23 W1 gates**, so the maintainer's run is
the first against them: a change from the baseline is a finding to read, not
necessarily a regression.

### 1. Before the run

- [ ] The suite pin is the one the reports record: `SUITE_VERSION` and
      `SUITE_DIGEST` in `conformance/suite.env` against the digest in
      `docs/conformance/README.md` (`release-v5.2.4`,
      `sha256:3a2615ed95a7f3bb92d545b4c65c0268f82a3893d6cd97fd98fd8e44eb15d81f`
      for the baseline). A moved pin is a finding of its own; say so in the report.
- [ ] Bring the rig up as "Reproducing a run" in `docs/conformance/README.md`
      lists it: `conformance-certs`, `conformance-frontend`, `conformance-up`,
      `conformance-serve`, `conformance-register`, `conformance-register-basic`, a
      restart of `conformance-serve` once after the first registration, then
      `conformance-drive` in a second terminal. Check that `pgrep -a -f
      drive-browser.mjs` shows **one** driver.
- [ ] Use the **bare issuer** (`AXIAM_ISSUER`), not a `/t/{tenant}/` one: the
      2026-09-25 baseline and the registered clients are on it, and a different
      issuer is a different submission. (Browser SSO on a per-tenant issuer path
      works since T23.1.8, D-11: each sign-in also sets the OP cookie at
      `Path=/t/{tenant}/oauth2/authorize`. It is not what this run certifies.)
- [ ] Move the previous `conformance/.run/results/*.results.json` aside before the
      sweep. `just conformance-report` renders every file in that directory under
      the new date, so a stale file would be published as part of the new run.
- [ ] The AXIAM build under test, and its image digest if the run is against a
      release image; `fapi-certification-submission.md` Steps 1–2 cover the release
      image. Note that `fapi-conformance.yml` cannot drive a browser, so the
      interactive modules (both FAPI `REVIEW` modules among them) are finished on the
      local rig above; the workflow's artifact is a smoke test unless `axiam_image`
      is a digest. Open: the Basic lane has no image path. `serve-axiam.sh` runs `AXIAM_BIN` (default
      `target/debug/axiam-server`), and `fapi-conformance.yml` runs only the FAPI
      plans. Whether the Basic run must be against the digest-pinned release
      image, and how to serve it, is not documented anywhere in the repository.

### 2. Which plans and variants

There are **three** FAPI 2.0 variants, one plan file each, and one Basic OP plan.
The competitor-gap plan's "four FAPI variants" counts the Basic OP plan with the
three; there is no fourth FAPI variant and none is to be invented.

| Plan file in `conformance/plans/` | Suite plan name | Baseline report (2026-09-25) |
|---|---|---|
| `oidcc-basic-static.json` | `oidcc-basic-certification-test-plan` | `2026-09-25-oidcc-basic-static.md`, 35 modules |
| `fapi2-security-profile-final-mtls.json` | `fapi2-security-profile-final-test-plan` | `2026-09-25-fapi2-security-profile-final-mtls.md`, 37 modules |
| `fapi2-security-profile-final-self-signed.json` | `fapi2-security-profile-final-test-plan` | `2026-09-25-fapi2-security-profile-final-self-signed.md`, 37 modules |
| `fapi2-security-profile-final-private-key-jwt.json` | `fapi2-security-profile-final-test-plan` | `2026-09-25-fapi2-security-profile-final-private-key-jwt.md`, 56 modules |

```bash
just conformance-run-basic     # renders the Basic plan, then run-plan.sh on it
just conformance-run           # the three FAPI plans, one after another
```

Per plan, the two commands underneath those recipes are:

```bash
bash conformance/scripts/render-plan.sh conformance/plans/<plan>.json
bash conformance/scripts/run-plan.sh conformance/.run/<plan>.json <suite plan name>
```

### 3. What to compare with the baseline, and how

Render the reports with a date, then compare each with its 2026-09-25 baseline:

```bash
CONFORMANCE_DATE=<YYYY-MM-DD> just conformance-report
strip() { grep -E '^- `|^\| `' "$1" | sed -E 's/\| `[A-Za-z0-9]{15}` \|$/|/'; }
diff <(strip docs/conformance/2026-09-25-<plan>.md) <(strip docs/conformance/<YYYY-MM-DD>-<plan>.md)
```

`strip` drops the suite log id, which differs on every run, and keeps the
verdict-count rows, the not-passing rows and the passed list. An empty diff means
the same shape and the same modules. (It was checked on the 2026-09-18 and
2026-09-25 Basic OP reports, which it reports as identical.) The new
`## Modules skipped` section lists the `SKIPPED` modules by name (T23.1.6); the
2026-09-25 reports do not, so the baseline's skipped modules can be named only
from a retained `conformance/.run/results/*.results.json` of that run, or from the
suite's own logs. Read each skipped module's reason in its log.

- **Basic OP.** Baseline: 30 `PASSED`, 4 `REVIEW`, 1 `SKIPPED` (30/35). The
  plan's target is every module `PASSED` or a documented `SKIPPED`. Two things to
  know before reading the diff. First, a module that asks for an uploaded
  screenshot ends `REVIEW` by the suite's design
  (`docs/conformance/evidence/2026-09-25/README.md`: "`REVIEW` is therefore a
  terminal verdict, **not** a failure"); the four here are closed by
  `docs/conformance/REVIEW-JUDGEMENTS.md`, not by a changed verdict, so the
  expected shape of a good run is the baseline's with a judgement per `REVIEW`.
  Open for the maintainer: whether the target is meant literally. Second,
  anything that moves the other way (`FAILED`, `WAITING`, `INTERRUPTED`,
  `TIMEOUT`, a new `WARNING`) is a finding.
- **FAPI 2.0, every variant.** Every module equals its baseline except three:
  `…-ensure-unsigned-authorization-request-without-using-par-fails` (`REVIEW`),
  `…-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` (`REVIEW`)
  and `…-test-claims-parameter-identity-claims` (`WARNING`). Those three may stay
  as they are, each with its entry in `REVIEW-JUDGEMENTS.md` (T23.1.7), or change;
  any change is to be read in the log. Baseline logs: `mtls` plan `A6nvEhaNVt4hQ`,
  `self-signed` `9xDkyLVW61B39`, `private-key-jwt` `IKxIaLZ4ZWC1z`; the three
  modules' log ids are in the judgements file's index. The three 2026-09-25 reports
  record the `WARNING` on **all three** variants (logs `E3LMGPfxxRnrBff`,
  `Ifh31qq9b0lDMpw`, `v440VDWfwxP7kKo`), not on `private-key-jwt` alone as the
  plan's table says. `private-key-jwt` has 56 modules against the other two's 37,
  so its diff is against its own baseline.
- **F4 item (g) — the `claims` parameter on `fapi2`.** Confirm that
  `fapi2-security-profile-final-test-claims-parameter-identity-claims` keeps its
  verdict now that `claims.id_token.acr` is refused on `fapi2` (W1 T23.1.1) and,
  from this wave, an essential `claims.id_token.auth_time` too (D-12, T23.1.4).
  Run the one module on one variant:

  ```bash
  conformance/scripts/run-some.sh \
    conformance/plans/fapi2-security-profile-final-private-key-jwt.json \
    fapi2-security-profile-final-test-plan \
    fapi2-security-profile-final-test-claims-parameter-identity-claims
  ```

  then open the full log it saved under `conformance/.run/some/`, find the entry
  that records the authorization request, URL-decode its `claims` parameter and
  look for `"acr"` and `"auth_time"` under `id_token`. If the module now fails,
  that is a finding to be judged before submission, not a harness bug. Source:
  `claude_dev/security-review-phase23-w1-2026-10-03.md` §8 (g). Also note which
  condition raised the warning: the claims entry in `REVIEW-JUDGEMENTS.md` cannot be
  closed without it, and says what is open for the maintainer if the cause is the
  `id_token` member being ignored. If the D-12 change (T23.1.4) has landed, the
  entry's description of it is then checked against the code.

### 4. The REVIEW modules

- [ ] Export the screenshots: `CONFORMANCE_DATE=<YYYY-MM-DD> just
      conformance-evidence` (`conformance/scripts/export-evidence.py`). It writes
      `docs/conformance/evidence/<date>/` with a `manifest.json` in the shape of
      the earlier ones, and refuses a directory that already has one. It was
      exercised against a local mock of the suite's API only; if it misbehaves
      against the real one, the recipe in `evidence/2026-09-25/README.md` ("How
      this was produced") is the fallback.
- [ ] **View every distinct image**; do not classify by size or hash. Compare each
      with the condition in the manifest.
- [ ] `oidcc-prompt-login` and `oidcc-max-age-1`: the image must carry the notice
      **"Please sign in again to continue."**. It is the only thing that tells the
      second sign-in from the first; an image without it is the first visit's and
      the module is not evidenced. Then read each module's log for what a
      screenshot cannot show: the first sign-in completed, the second request
      carried `prompt=login` / `max_age=1`, and (for `max-age-1`) a delay longer
      than the bound preceded it. Keep the log with the image if the submission
      package needs both; the suite log is the record.
- [ ] `oidcc-ensure-request-object-with-redirect-uri`: read the log for which
      `redirect_uri` the module put in the query and which in the request object,
      as `REVIEW-JUDGEMENTS.md` says. The page "redirect_uri not registered" can
      come only from the query value; if the log shows otherwise the entry must be
      rewritten before the submission relies on it.
- [ ] `…-ensure-unsigned-authorization-request-without-using-par-fails`, each of
      the three variants: the image must be an error page carrying `invalid_request`
      (the 2026-09-25 one says "this client must use pushed authorization requests").
      Read the log for the request the module sent (no `request_uri`) and for
      whether a sign-in page came before the refusal; the judgement records both as
      open until read.
- [ ] `…-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds`, each of
      the three variants: the image must be the sign-in page, with no notice. Read
      the log for which visit it is, that the second visit completed, and that the
      second request came within 60 seconds of the push.
- [ ] `…-test-claims-parameter-identity-claims`: no image; the item is §3's F4 item
      (g) above. Do not close the entry until the log's `claims` value and the
      raising condition are written into it.

### 5. Where the results go

- [ ] New dated reports under `docs/conformance/`, **alongside** the earlier ones,
      never over them (`docs/conformance/README.md`). The regenerated `index.md`
      lists the new run and, beneath it, the earlier dated reports.
- [ ] `docs/conformance/README.md`: the suite image digest, and the AXIAM image
      digest if the run was against one, beside the date. It is hand-maintained;
      the generator never writes it.
- [ ] Evidence under `docs/conformance/evidence/<date>/`, with a short README of
      what each image shows, in the style of `evidence/2026-09-25/README.md`.
- [ ] `docs/conformance/REVIEW-JUDGEMENTS.md`: add the new log ids to each entry
      **alongside** the 2026-09-25 ones, edit any sentence the log contradicts,
      and fill the sign-off table (plan id, image digest, date). Leave an entry
      that the log does not support marked open rather than smoothing it over.
- [ ] `docs/compliance/oidc-conformance.md`: the X7.9 rows say the final runs are
      pending; update them to the run's date and result.
- [ ] The submission package: fill every `<…>` placeholder in
      `fapi-certification-submission.md` ("The X5.3 package") from the run, and work
      its pre-send checklist. The website wording in it stays unpublished until the
      mark is granted.
- [ ] Issue #513 (G-1): the run's date, plan ids, digests and the verdicts that
      differ from the baseline.
- [ ] The submission (§X5.3) is sent by the maintainer only. No agent sends it.

---

## Submitting (§X5.3)

When the run is green and you are ready to make it official (the checklist above
comes first), follow
[`fapi-certification-submission.md`](fapi-certification-submission.md) — the
digest-pinned release run and the OIDF submission, with its package (what is
submitted, what is attached, the pre-send checklist, and the website wording for
the mark). The §X5.4 letter amendment
that document used to require is no longer needed: `private_key_jwt` landed, so
the letter's scope sentence is accurate as drafted.

---

## Moving the suite pin

Change `SUITE_VERSION` in `conformance/suite.env`, `just conformance-up`, re-run.
Commit the new reports **alongside** the old ones rather than over them: a
version bump that changes a verdict is itself a finding, and the diff is the
only place it is visible.
