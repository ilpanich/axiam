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
| Every module fails at the token endpoint with `invalid_client` | The listener is not requesting client certificates, or does not trust `conformance/certs/ca.crt`. AXIAM answers `invalid_client` for *every* client-authentication failure by design (SEC-086), so the wire response cannot tell you which — check the server log, which names the specific reason. |
| Only the `private-key-jwt` plan fails at the token endpoint | AXIAM could not obtain the client's keys. If the plan registered a `jwks_uri`, AXIAM fetches it through the SSRF-guarded JWKS cache, which **refuses private and loopback addresses** — a suite running on `host.docker.internal` publishes its JWKS somewhere AXIAM will not fetch from. Register the suite's key set inline (`jwks`) instead; `conformance-register` does this by default for exactly this reason. |
| The `private-key-jwt` plan fails only on repeated runs | The `jti` replay guard is doing its job. The suite reuses assertion identifiers across a re-run of the *same* module in some versions; each assertion is single-use, permanently. Re-run the whole plan rather than one module, or wait out `oauth2_proof_replay`'s cleanup. |
| A DPoP module fails with `use_dpop_nonce` and does not recover | The client was registered with `dpop_require_nonce: true`. The suite handles the challenge, but only once per module — check the suite log for a second challenge, which means AXIAM rotated the nonce mid-plan. |
| The suite cannot reach the issuer | `AXIAM_ISSUER` names `localhost`, which inside the suite's container is the suite. Use `host.docker.internal` (the compose file maps it on Linux too). |
| Discovery fails | AXIAM's discovery document is tenant-scoped; `AXIAM_TENANT_ID` must be set in `suite.env`. |
| `COULD_NOT_START` on everything | The plan name changed upstream. Override with `CONFORMANCE_PLAN_NAME=…`, and update `justfile`'s default. |

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

**No run has been performed yet.** As of this document's most recent revision the
harness exists and has still not been executed against a live deployment — there
is no docker daemon in the environment X5.1 was implemented in, either half.
`docs/conformance/` is therefore empty. The first person to run it should expect
to find harness bugs, and should fix them here rather than working around them
locally. This entry has not moved and is now the only one blocking submission.

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

## Submitting (§X5.3)

When the run is green and you are ready to make it official, follow
[`fapi-certification-submission.md`](fapi-certification-submission.md) — the
digest-pinned release run and the OIDF submission. The §X5.4 letter amendment
that document used to require is no longer needed: `private_key_jwt` landed, so
the letter's scope sentence is accurate as drafted.

---

## Moving the suite pin

Change `SUITE_VERSION` in `conformance/suite.env`, `just conformance-up`, re-run.
Commit the new reports **alongside** the old ones rather than over them: a
version bump that changes a verdict is itself a finding, and the diff is the
only place it is visible.
