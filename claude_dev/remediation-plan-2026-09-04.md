# Remediation plan — the residuals the beta08…beta11 threat-model wave left open

> **EXECUTED — R-4, R-5, R-6, R-7, 2026-09-04.** The "small hardenings" PR §1
> item 4 asks for. No threat changes status; T-216 stays **Open** on purpose,
> because R-7 adds a check and not a seal.
>
> **R-4.** Both key extractors now emit one `WARN` per process on the first
> discarded `X-Forwarded-For` — naming the hop count seen, the `trusted_hops` in
> force and the rule — and increment
> `axiam_rate_limit_xff_discarded_total{protocol="rest"|"grpc"}` on every one.
> The fallback itself is untouched (SECHRD-03). A request with **no** header is
> deliberately not counted, so the fault signal is the counter tracking request
> volume rather than merely being non-zero. `main.rs` logs the value and the
> derivation rule next to the rate-limit posture line. The counters follow the
> house convention (`axiam_db::metrics`, `axiam_amqp::reactor::metrics`):
> process-wide relaxed atomics with the Prometheus name documented beside them,
> since this workspace has no metrics facade — the `protocol` label is two
> counters an exporter joins, because the two crates are siblings and neither
> may depend on the other. Tests on both extractors: header discarded → peer key
> **and** the counter up by one; header trusted → counter unchanged; no header →
> counter unchanged; plus the once-per-process latch.
>
> **R-5.** `"axiam.v1.ReactorAdminService" => Self::Admin`, the one-line fix the
> plan prefers. The catch-all arm and its comment are unchanged. Family tables
> updated in Pi runbook §14.1, `docs/deployment/rate-limit-sizing.md` §3.1,
> `docs/deployment/README.md` and `docs/api/grpc.md`. Note for the CHANGELOG
> reader, which is in it: an operator driving reactor CRUD over gRPC above 10/s
> per IP is now throttled and should pin `AXIAM__GRPC__GRPC_ADMIN_PER_SEC`.
>
> **R-6.** `crate::health::jobs` added to `paths(…)`, `JobsHealthResponse` and
> `JobStatus` to `components(schemas(…))`, `sdks/openapi.json` regenerated from
> `--dump-openapi` on the SAML-off build the drift gate uses. Two tests assert
> the path, its `GET`, both schemas and the `health` tag — the existing parity
> tests could not have caught this, since Test A walks
> `ROUTE_PERMISSION_MAP` (which an unauthenticated probe is not in) and Test B
> only checks the other direction.
>
> One thing the plan did not anticipate: the §27 registry gate demands every
> documented route be claimed by a namespace or excluded **with a reason**, and
> `/health` and `/ready` are already `platform` operations. Adding `/health/jobs`
> beside them would have grown the SDK surface, which §7 explicitly says must not
> happen. It is therefore in `EXCLUDED_OPERATIONS`, and the reason is recorded
> where the next person will read it: the two siblings answer a fixed one-word
> liveness contract, this returns a variable inventory of a deployment's
> background jobs — `public-backend-tls-design.md` §6's "free map of what a
> deployment runs and what is currently broken in it" — and an SDK talks to the
> edge none of the three is routed at. `operation_count` is unchanged at 155, so
> **no SDK surface regenerates**, exactly as §7 says.
>
> **R-7.** `seal_findings` / `seal_is_production_ready` in
> `vault_status_report.py`, `print_seal` in `vault-status.py`, and a
> `--seal-status FILE` flag the `just vault-status` recipe fills from the
> **unauthenticated** `sys/seal-status` — so it answers even when the token is
> wrong and even when the Vault is sealed. Every auto-unseal type reads `OK`;
> `shamir` reads `SHAMIR` with `t`/`n` quoted; an unrecognised type and a failed
> request both read `unknown`, never `OK`; `sealed: true` is a separate line that
> does not change the verdict. `--strict` fails on an unconfirmed auto-unseal;
> `just vault-status` still does not pass it, so the dev stack's deliberate
> root-token-on-Shamir does not turn every local run red. Ten new cases in
> `scripts/test_vault_status.py`, which CI already runs through
> `unittest discover`. Documented in `docs/deployment/vault.md` §5.3 (with the
> `--strict` note) and Pi runbook §7.4.
>
> Threat model: T-212 and T-233 gain the R-4 clause, T-233 also has its
> `ReactorAdminService` follow-up replaced by what landed, T-213 gains the R-6
> clause, T-216 gains the R-7 clause and **stays Open**, and T-235's "Residual,
> in the SDK repositories" sentence is replaced by the R-2 gate — in
> `Axiam.json`, `threat-model-stride.md` and `threat-modeling-and-security.md`.
> The website was **not** regenerated (§9 step 3).

> **Who this is for.** A fresh Claude session (Opus 5) implementing the fixes
> below. It is the entry point: read this, then §1 for the order, then one item
> at a time. Each item names the threat it closes or narrows, the files, the
> shape of the fix, the tests that prove it, and what to update in the threat
> model afterwards. When an item lands, record it in the **EXECUTED** blockquote
> this file should gain at the top, in the style of the older remediation plans
> in this directory.
>
> **Where it came from.** The 2026-09-04 threat-model pass
> ([`threat-modeling-and-security.md`](threat-modeling-and-security.md) handoff
> block, [`threat-model-stride.md`](threat-model-stride.md) §5.8 and §5.9) added
> T-212…T-236. Most are mitigated; the wave also wrote down, in the model's own
> words, what it could *not* close. This plan is those residuals, plus three
> small hardenings the same review found, ranked by what they buy.

**Repositories affected.**

| Item | Repository | Crate / path |
|---|---|---|
| R-1 gRPC listener: reloadable certificate, TLS 1.3 only | `ilpanich/axiam` | `crates/axiam-api-grpc`, `crates/axiam-server` |
| R-2 §27 drift-check gates the release | all eleven `ilpanich/axiam-<lang>-sdk` | `.github/workflows/sdk-ci-<lang>.yml` |
| R-3 handoff-origin rule on every federation start path | `ilpanich/axiam` | `crates/axiam-api-rest` |
| R-4 an observable `TRUSTED_HOPS` misconfiguration | `ilpanich/axiam` | `crates/axiam-api-rest`, `crates/axiam-api-grpc` |
| R-5 `ReactorAdminService` out of the authz rate-limit family | `ilpanich/axiam` | `crates/axiam-api-grpc` |
| R-6 `/health/jobs` in the OpenAPI document | `ilpanich/axiam` | `crates/axiam-api-rest` |
| R-7 `just vault-status` reports the seal type | `ilpanich/axiam` | `scripts/` |

Nothing here touches the admin UI, the website, or the SDKs' library code.

---

## 1. Order, and how to cut the work

1. **R-1** first — it is the only *open* threat in the set (T-234), it is the
   one that fails at day 90 in production, and it is the largest. One PR.
2. **R-2** in parallel if two sessions are available — eleven small, mechanical
   PRs, one per SDK repository, independent of everything in `axiam`.
3. **R-3** on its own PR: it changes behaviour for one class of deployment and
   needs its own CHANGELOG entry.
4. **R-4, R-5, R-6, R-7** together in one "small hardenings" PR; each is
   a few dozen lines with a test.

Every `axiam` PR: feature branch from `main`, `just check` (or the narrow
`cargo fmt -p … -- --check`, `cargo clippy -p … --all-targets -- -D warnings`,
`cargo test -p …` per `CLAUDE.md`'s disk-hygiene rules; `cargo clean` between
crates), CHANGELOG entry under `[Unreleased]`, and the threat-model update in
§9 in the **same PR** — a fix the model does not know about is a fix the
website will not show. PRs must reference the issues they address and be opened
by the agent on behalf of the developer, per `CLAUDE.md`.

---

## 2. R-1 — gRPC listener: hot-reloadable certificate and TLS 1.3 only

**Closes** T-234 (open, Medium). **Narrows** the TLS-version caveat T-233
records and `public-backend-tls-design.md` §13.4 names as "the right eventual
answer".

**The defect.** `crates/axiam-api-grpc/src/server.rs` reads
`AXIAM__GRPC_TLS_CERT_PATH` / `_KEY_PATH` once (lines ~313–330), builds
`Identity::from_pem` → `ServerTlsConfig`, and hands it to tonic. tonic 0.14's
`ServerTlsConfig` accepts neither a `rustls::ServerConfig` nor a certificate
resolver, so the leaf is bound for the process's life (the failure T-214 fixed
for REST) and the protocol versions are the crate default (TLS 1.2 negotiable —
the module docs at lines ~23–27 record both limits). The runbook bridges it by
restarting the container from the certbot deploy hook.

**The shape of the fix.** Stop asking tonic to do TLS. Accept the TCP stream,
do the handshake with `tokio-rustls`, and hand tonic the already-encrypted
stream through `Server::serve_with_incoming`:

- `axiam-api-grpc` (layer 6) **cannot** depend on `axiam-server` (layer 8),
  where `ReloadableCertResolver` lives (`crates/axiam-server/src/tls.rs`
  ~line 431). So the lower crate takes the TLS configuration as a value:
  `start_grpc_server` gains a parameter of the form
  `tls: Option<Arc<rustls::ServerConfig>>` (or a small `GrpcTls` enum:
  `Plaintext | Rustls(Arc<ServerConfig>)`). The composition root builds the
  `ServerConfig` and passes it in. This respects
  `scripts/check-crate-layering.py`, which will fail the PR otherwise.
- In `axiam-server`, build that `ServerConfig` **with the same
  `ReloadableCertResolver` instance the REST listener uses** when both listeners
  serve the same leaf (the documented topology: "There is no second certificate
  and there must not be", Pi runbook §14.4), so one `SIGHUP` or one hourly poll
  renews both. `build_rustls_server_config` (`tls.rs` ~line 867) already does
  `.with_protocol_versions(&[&rustls::version::TLS13])` and installs the
  resolver; reuse it rather than writing a second builder. If the gRPC paths
  differ from the REST paths (both env pairs set to different files), build a
  second resolver over the gRPC pair and register it with the same reloader
  (`spawn_leaf_reloader`, `reload_leaf_certificate`) so it is reloaded on the
  same triggers — do not leave a second, unreloaded path behind.
- Inside `axiam-api-grpc`: `TcpListener::bind` → for each accepted stream,
  `tokio_rustls::TlsAcceptor::from(config).accept(stream)` → yield
  `tokio_rustls::server::TlsStream<TcpStream>` into a `Stream` for
  `serve_with_incoming`. A failed handshake logs at `debug` and drops that
  connection only; it must never take the accept loop down. Bound the number of
  concurrent in-flight handshakes (a semaphore, a few hundred) so a flood of
  half-open TLS clients cannot starve the accept loop — this is the one new
  denial-of-service surface the change introduces, and the test in §"Tests"
  covers it.
- **Peer address plumbing.** `GrpcTrustedHopsKeyExtractor` reads
  `TcpConnectInfo` / `TlsConnectInfo<TcpConnectInfo>` from request extensions
  (`middleware/rate_limit.rs` ~line 165). tonic populates those through its
  `Connected` trait on the incoming stream type; `tokio_rustls::server::TlsStream<T>`
  implements it under tonic's `tls-*` features. Verify this against the pinned
  tonic before writing anything, because if `remote_addr()` comes back `None`
  every gRPC request keys on "no address", the extractor returns
  `UnableToExtractKey`, and the limiter fails closed for everyone. The existing
  test around `rate_limit.rs` ~line 905 (XFF + peer) must keep passing against
  the new listener, and a new test asserts a TLS connection's peer is recovered.
- Keep the flat env names `AXIAM__GRPC_TLS_CERT_PATH` / `_KEY_PATH` and the
  panic-on-unreadable behaviour (T-233 relies on "a typo is a failed boot"); the
  Pi runbook §14.4 documents them. Keep the `INFO`/`WARN` lines the runbook
  greps for (`gRPC server TLS enabled`, `gRPC TLS is DISABLED`).
- The `tls-ring` tonic feature and the test-only `rustls` dev-dependency in
  `crates/axiam-api-grpc/Cargo.toml` (lines ~14, ~61–67) exist to install a
  `CryptoProvider` for `ServerTlsConfig`; revisit them once tonic no longer does
  the handshake — `crates/axiam-server/tests/grpc_tls_crypto_provider.rs` is the
  test that will tell you.

**Tests** (in `crates/axiam-api-grpc/tests/grpc_server_test.rs` and
`crates/axiam-server/src/tls.rs`'s test module, mirroring what T-214 did for
REST):

1. Two real handshakes against one running listener; the resolver is swapped
   between them; the client is presented the renewed leaf on the second, with no
   dropped connection.
2. A TLS 1.2-only client is refused (`with_protocol_versions(&[&TLS12])` on the
   client side; expect a handshake failure, not a downgrade).
3. Peer address: a TLS-connected client's `remote_addr` reaches the extractor
   (assert the rate-limit key is the client's IP, not `UnableToExtractKey`).
4. Handshake flood: N connections that open TCP and never complete TLS do not
   stop a well-behaved client from being served.
5. Plaintext mode unchanged: `tls: None` behaves exactly as today (the E2E
   suite and the benches rely on it).

**Docs.** `public-backend-tls-design.md` §13.4: replace "not done here" with
what landed. Pi runbook §14.4 (the "One honest caveat" paragraph goes) and
§14.5 (the restart step 4 becomes unnecessary — say so, and say the `SIGHUP`
now covers both listeners). `docs/deployment/README.md` if it repeats the
caveat. `CHANGELOG.md`.

**Threat model.** T-234 → `Mitigated`, mitigation rewritten to name the accept
loop, the shared resolver, the TLS 1.3 pin and the tests. T-233: drop the
"TLS 1.2-negotiable" row. T-214: replace the gRPC clause with a pointer to the
closed T-234. Open count 17 → 16; deployment diagram 6 → 5 open.

---

## 3. R-2 — the §27 drift-check gates the release, in every SDK

**Closes** the residual T-235 records: `scripts/mass-tag.sh` now regenerates the
§27 management surface at release, but the repository-side gate that would catch
a stale surface reaching a tag by any other route runs only on `pull_request`
in eight of eleven repositories — and in the three where it does run on tags,
the release job does not depend on it.

**Verified 2026-09-04.** `axiam-rust-sdk`: the `§27 management surface is
regenerated` step lives inside the `test` job, which is
`if: github.event_name == 'pull_request'`. `axiam-python-sdk`: a dedicated
`management-drift-check` job, also `pull_request`-only; its `publish` job
re-runs the *gRPC stub* drift-check on the tagged commit but not the §27 one.
`axiam-swift-sdk`: `management-drift-check` runs on tags, but `release` has
`needs: [build-test, tls-bypass-gate, secret-scan-gate, verify-tag-on-main]` —
the drift-check is not in the list, so a red check does not stop the tag being
the release. Expect the other eight to follow one of these three patterns; read
each file rather than assuming.

**The fix, per repository** (`.github/workflows/sdk-ci-<lang>.yml`):

1. The §27 check runs on both triggers: either drop the `pull_request`
   condition from the job that carries it, or split it into its own job with no
   `if:` (the Python/Swift shape), so the whole heavy test matrix does not have
   to run on tags where it does not today.
2. The publish/release job lists that job in `needs:`. In the repositories
   where publishing is irreversible (crates.io, npm, PyPI, NuGet, Maven
   Central, Packagist, Go proxy, CocoaPods trunk) this is the point of the
   change: a stale surface must fail *before* a version number is spent.
3. Keep `verify-tag-on-main` and the attestation steps exactly as they are;
   this change adds a dependency, it moves nothing else.
4. Where the check needs a toolchain (Go and TypeScript generators are written
   in their own languages; Swift's needs only `python3`), install it in that job
   — the same steps the PR-path job already uses.

**Tests.** There is no unit test for a workflow; the verification is the run
itself. Open the PR, confirm the job appears in the PR run; after merge,
`git tag`-push a pre-release tag on a throwaway branch is **not** an option
(tags publish). Instead, in the PR, temporarily revert one generated file and
confirm the check goes red on the PR run, then restore it; note that in the PR
description. Confirm `needs:` resolves by reading the workflow graph in the PR's
checks tab.

**Threat model.** T-235: remove the "Residual, in the SDK repositories" sentence
and name the gate. No status change (already Mitigated).

---

## 4. R-3 — the handoff-origin rule on every federation start path

**Narrows** T-219 and retires `TODO(T19.14)`.

**The gap.** `validate_redirect_uri` (`crates/axiam-api-rest/src/handlers/federation.rs`
~line 1647) accepts any absolute `https://` URL (loopback `http://` excepted).
Beta08 added `require_deployment_spa_origin` (`federation_login.rs` ~line 448)
— origin of `effective_issuer()` plus `AXIAM__AUTH__SSO_SPA_ORIGINS` — and
applied it to the two cross-site flows (SAML, Apple form-post), where the
identity provider never sees the SPA URI. On the OIDC and OAuth2 start paths
(`federation.rs` ~lines 1820 and 2023; `federation_login.rs` ~line 704) the
same scheme-only check is still the only server-side rule, and the argument for
leaving it was that the provider's registered-redirect check backstops it. That
backstop is only as strict as each provider's registration hygiene — several
providers accept wildcard or prefix registrations — and it is a control AXIAM
does not own. The rule the server *does* own should be uniform across the four
flows.

**The fix.** Call `require_deployment_spa_origin` on the OIDC and OAuth2 start
paths and at their mints, exactly as the SAML and Apple paths do (after
workspace and config resolution, so an unknown slug still answers the uniform
`401`; a `400` naming the knob otherwise). Delete the `TODO(T19.14)` comment
and the "deferred" sentence above it; `validate_redirect_uri` stays as the
first, cheap check. Do **not** add a per-config allowlist column — the
deployment-origin rule already says where a code may go, and a second list to
keep in sync is a second place to get wrong.

**Compatibility.** A deployment whose SPA is hosted on an origin other than the
issuer's, signing in through OIDC or OAuth2 providers, has worked without
`AXIAM__AUTH__SSO_SPA_ORIGINS` until now and will get a `400` after this change
until it sets the variable. That is the same requirement the SAML and Apple
flows already impose, and the shipped same-origin topology needs nothing. State
it in `CHANGELOG.md` under a **Changed** heading with the variable named, and in
`docs/` wherever `SSO_SPA_ORIGINS` is described. CONTRACT §12.1 rule 12a
currently scopes the rule to the SAML and Apple flows; extend the rule's text to
all four start operations (contract 1.39, additive and restrictive server-side
only, as 12a was).

**Tests.** For each of the two start handlers: an off-origin `redirect_uri` is
refused with `400` and the knob's name; the issuer origin passes; an origin
listed in `SSO_SPA_ORIGINS` passes; a same-host different-port URL is refused
(origin comparison, not host comparison); an unknown organization slug still
answers `401` regardless of the URI.

**Threat model.** T-219 mitigation: the sentence "the OIDC and OAuth2 flows …
backstopped by the provider" becomes "enforced on all four start paths, and on
the OIDC and OAuth2 flows the provider's registered-redirect check is a second,
independent layer". Add the contract amendment to T-147's list if it keeps one.

---

## 5. R-4 — make a `TRUSTED_HOPS` misconfiguration observable

**Narrows** T-212 and T-233. Both key extractors —
`XForwardedForKeyExtractor::extract` (`crates/axiam-api-rest/src/extractors/rate_limit.rs`
~line 101) and `GrpcTrustedHopsKeyExtractor::extract`
(`crates/axiam-api-grpc/src/middleware/rate_limit.rs` ~line 134) — fall through
to the peer address **silently** when `trusted_hops >= hops.len()`. That
silence is exactly how the off-by-one T-212 describes went unnoticed: every
client keyed to the proxy's address, one global bucket, and nothing in any log
said so. The fallback itself is correct and must stay (SECHRD-03).

**The fix.** In both extractors, when an `X-Forwarded-For` header is present
but the configured `trusted_hops` discards it, emit a **rate-limited** `WARN`
(once per process is enough; a `std::sync::Once` or an `AtomicBool` — never one
line per request) stating the hop count seen, the `trusted_hops` in force, and
the rule ("proxies − 1"), and increment a Prometheus counter
`axiam_rate_limit_xff_discarded_total{protocol="rest"|"grpc"}` so a dashboard
can show that every request is keying on the peer. Log the same derivation once
at startup next to the existing rate-limit posture line in
`crates/axiam-server/src/main.rs` (~line 1212), so an operator reading boot logs
sees the number and the rule together.

**Tests.** Unit tests on both extractors: header present with fewer hops than
`trusted_hops + 1` → key is the peer **and** the counter incremented; header
present with enough hops → counter unchanged; no header → counter unchanged
(a client with no proxy is not a misconfiguration).

**Threat model.** T-212 and T-233: one clause each — "a discarded header is
counted and warned about, so the one-bucket failure is visible in metrics
rather than only in an incident".

---

## 6. R-5 — `ReactorAdminService` out of the authz rate-limit family

**Closes** the follow-up T-233 names. `GrpcMethodFamily::classify`
(`crates/axiam-api-grpc/src/middleware/rate_limit.rs` ~line 244) maps
`UserInfoService`/`TokenService` → `IdentityRead`, `UserService` → `Admin`,
and *everything else* → `AuthzCheck` — deliberately, so an unknown service is
throttled rather than unlimited. `ReactorAdminService` (reactor CRUD,
`ListReactorEvents`) is administrative traffic sized like the hot path
(100/s per IP by default, raised by the `gateway`/`mesh` profiles).

**The fix.** Add `"axiam.v1.ReactorAdminService" => Self::Admin` to the match.
The `Admin` family's ceiling is the absolute `ADMIN_PER_SEC_DEFAULT` (10/s)
that no profile raises (SEC-079) — sized for `ValidateCredentials`'s Argon2
cost, which reactor CRUD does not have, but administrative surfaces should not
scale with authorization throughput either, and 10/s per IP is generous for
reactor administration. If that is judged too tight for `ListReactorEvents`,
the alternative is a fifth family with its own knob; prefer the one-line fix
unless a benchmark says otherwise. Keep the catch-all arm and its comment.

**Tests.** `classify("/axiam.v1.ReactorAdminService/ListReactorEvents") ==
Admin`, and the existing unknown-path → `AuthzCheck` test unchanged. Update the
family table in the Pi runbook §14.1 and `docs/` where the families are listed.

**Threat model.** T-233: remove the "reclassifying … is a named follow-up" row
and state the family.

---

## 7. R-6 — `/health/jobs` in the OpenAPI document

**Closes** an omission the beta06 website plan recorded and T-213 relies on
being documented. `crates/axiam-api-rest/src/health.rs` annotates `jobs` with
`#[utoipa::path]` (~line 123), and `server.rs` routes it (~line 107), but
`crates/axiam-api-rest/src/openapi.rs` lists only `health::health` and
`health::ready` in `paths(…)` (~line 21) — the same class of omission contract
1.36 recorded for `/auth/me`, `/auth/password/change` and `/admin/bootstrap`.

**The fix.** Add `crate::health::jobs` to `paths(…)` and `JobsHealthResponse`
(and `JobStatus`) to `components(schemas(…))`. Regenerate `sdks/openapi.json`
with `axiam-server --dump-openapi` (the drift gate compares the two), and note
that the eleven SDKs re-vendor it at the next release; it is not a §27
management operation, so no SDK surface regenerates from it. Tag it under the
existing `health` tag.

**Tests.** The OpenAPI drift gate is the test; also assert in
`crates/axiam-api-rest/tests/` (wherever the spec is loaded) that
`paths["/health/jobs"]` exists.

**Threat model.** T-213: one clause — the endpoint is documented, and the
document is where "not routed at the edge" is stated for it.

---

## 8. R-7 — `just vault-status` reports the seal type

**Narrows** T-216 (open, High) the way H-4 narrowed T-180: AXIAM cannot
configure auto-unseal, but it can make its absence **checkable**. Today
`scripts/vault-status.py` / `scripts/vault_status_report.py` query
`sys/capabilities-self` and the KV path and report token scope and secret
presence; nothing reports whether the Vault will come back sealed after a
restart.

**The fix.** Query `sys/seal-status` (unauthenticated; returns `type` —
`shamir`, `awskms`, `gcpckms`, `azurekeyvault`, `transit`, `pkcs11`… — plus
`sealed`, `recovery_seal`, `initialized`). Add a **Seal** section to the
report: the type; `OK` for any auto-unseal type; a clearly worded
`SHAMIR — no auto-unseal; every restart needs <threshold> key shares, not
production` for `shamir`, quoting `t`/`n` from the response; and a distinct
line for `sealed: true` (which is a state, not a policy problem — say so, as
the CA-key 403 message already does for its case). Exit non-zero only if
`--strict` is passed, so the dev stack's Shamir Vault does not turn every
local run red. Add the same line to the Pi runbook §7 and
`docs/deployment/vault.md` §5.3 where auto-unseal is discussed.

**Tests.** `scripts/test_vault_status.py` already drives the report over stub
responses; add cases for each seal type, for `sealed: true`, and for a
`seal-status` request that fails (report `unknown`, never `OK`).

**Threat model.** T-216: append "checkable since …: `just vault-status` names
the seal type and flags Shamir as not production". Status stays Open — the
control is a check, not a seal.

---

## 9. After each item: keep the model honest

The Threat Dragon JSON is the source of truth and the website renders it. In
the same PR as the code:

1. Edit the threat in `ThreatDragonModels/Axiam/Axiam.json` (status,
   mitigation) — find it by its `number`. Do not renumber anything; do not
   raise `threatTop` unless you add a threat.
2. Mirror the change into `claude_dev/threat-model-stride.md` (the table row
   and the detail block for that threat; the section's count line and §6/§7
   if a status changed) and into the handoff block and the relevant per-layer
   bullet of `claude_dev/threat-modeling-and-security.md`.
3. Run `cd website && npm run gen:threat-model` and commit the regenerated
   `src/threatModel.ts` / `src/threatModelSummary.ts` **only if** the website
   plan ([`website-security-beta11-update-plan.md`](website-security-beta11-update-plan.md))
   has already been executed; otherwise leave the website to that plan and say
   so in the PR. Two passes regenerating from different model versions is fine;
   two passes both hand-editing `security.ts` is not.
4. Update `CHANGELOG.md` under `[Unreleased]`.

---

## 10. Out of scope, deliberately

- **Auto-unseal itself** (T-216): every Vault OSS seal needs a cloud KMS or a
  second Vault; `pkcs11` is Enterprise-only. R-7 makes the gap visible; nothing
  in this repository can close it.
- **A per-config redirect allowlist** (the original T19.14 wording): superseded
  by the deployment-origin rule R-3 generalises.
- **Backups, cluster RBAC, per-service broker credentials, SDK package-name
  reservation** (T-18, T-124, T-133, T-134, T-135, T-146): deployment and
  registry responsibilities, unchanged.
- **The website Security section**: its own plan, above.

---

## Appendix — the prompt for the session that executes this plan

> Read `claude_dev/remediation-plan-2026-09-04.md` in the `ilpanich/axiam`
> repository and implement it in the order §1 gives: R-1 on its own PR first,
> then R-3 on its own PR, then R-4, R-5, R-6 and R-7 together in one PR — each
> on a feature branch from `main`, with the tests the plan names, a CHANGELOG
> entry, and the threat-model update from §9 in the same PR. R-2 is eleven
> mechanical PRs, one per `ilpanich/axiam-<lang>-sdk` repository: read each
> `sdk-ci-<lang>.yml` before editing, make the §27 drift-check run on tag
> pushes and make the publish/release job depend on it, and change nothing
> else. Respect the crate-layering gate (`scripts/check-crate-layering.py`):
> `axiam-api-grpc` must take its TLS configuration as a value from
> `axiam-server`, never depend on it. Verify the tonic `Connected`
> implementation for `tokio_rustls::server::TlsStream` before writing R-1,
> because the rate limiter's peer-address lookup depends on it. Follow
> `CLAUDE.md`'s build and disk-hygiene rules (narrow cargo commands,
> `cargo clean` between crates, the swagger-ui placeholder after any
> `target/` wipe). Open each PR referencing this plan and the issues it
> addresses, and record what landed in an EXECUTED blockquote at the top of
> the plan.
