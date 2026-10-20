# Security review — release 1.1.1, wave W2 (F4)

**Date:** 2026-10-19.
**Against:** `claude/release-1.1.1-w2`, the whole wave diff
`origin/main..ac3effd10` (merge base `6b15aa36a`; 10 commits, 42 files, 2 564
lines added and 418 removed). Every commit carries a signature (`gpgsig` header
in 10 of 10; the sandbox has no `gpg.ssh.allowedSignersFile`, so `%G?` cannot
verify them here).
**Scope:** every W2 task of the release-1.1.1 plan (§3): W2.1 #711/#686
(`TRUSTED_PROXIES`, `d1c97b6ee`), W2.2 #673 (the governor sweep, `b846942f4`),
W2.3 #718 (the administrative presets skip the cold-entry seed, `be74f6231`,
repaired by `2b24f3787`), W2.4 #685 (the public-client bucket removed,
`d3448c2f4`), W2.5 #670 (the DPoP scheme in the audit middleware, `7f1f9cb9a`),
W2.6 #671 (the ten authenticated crypto acquires bounded, `a8a65617b`), W2.7
#672 (the bucket-name scan widened, `6211b4286`), W2.8 #682 (the audit action
grammar, `5f17ff98c`), W2.9 #674 (text and pins, `ac3effd10`).
**Method:** the method and severity scale of the 1.1.0 wave reviews
([`security-review-release-1.1.0-w2-2026-10-15.md`](security-review-release-1.1.0-w2-2026-10-15.md)):
adversarial reading of the diff and of every sibling path it implies, against
[`threat-model-stride.md`](threat-model-stride.md) and `Axiam.json` (model
2.42.0, 487 threats), the plan's §10, §1.2 and §1.3 rules, the ten issues and
their comments, and the OWASP ASVS 5.0 areas the diff touches (V2
anti-automation, V7/V9 token handling, V13 configuration, V16 logging). Every
commit message was read in full and its claims checked against the code (§2 …
§10). Every test binary of every crate the wave touched was run, crate by crate
(§12). This review fixes nothing. IDs: `R111W2-nn`.

---

## 0. Summary

**No finding is Medium or higher. One Low and five Informational**, all filed on
milestone `1.1.x` (#731 … #735, #741).

The wave does what its ten issues ask. The keying rule for `X-Forwarded-For` is
one function below both listeners and both call it; a list that does not parse
stops the boot; every in-process governor of both listeners is swept and none is
kept alive or dropped by the registry; the 25 administrative wirings skip the
seed and nothing else does; the removed public-client bucket refused nothing the
route had not refused first, in every key mode; the DPoP-scheme identity is
cached only for readers that enforce the sender constraint; the ten crypto
acquires are bounded with the issue's answers; the audit ingestion refuses
lookalikes before the namespace test and no in-tree or contract producer is
outside the grammar. What the review adds:

| ID | Finding | Severity | Surface / threat | Origin | Disposition |
|---|---|---|---|---|---|
| **R111W2-01** | The empty-list boot `WARN` is decided on `AXIAM__SERVER__TLS__ENABLED` only. The gRPC listener has its own native TLS (with client certificates, the device topology, whose TLS ends at AXIAM) and reads the same list, but gets no `WARN`. The `WARN` text ("Both listeners read the list") and T-212's amendment ("stated at boot where the operator has not") overstate it. | **Low** | `boot.rs:1592-1606`; `forwarded_for.rs` (`boot_warning`); `tls.rs:1711` → T-212, T-233 | wave (W2.1) | #731 |
| R111W2-02 | `TrustedProxies::from_env` folds `VarError::NotUnicode` into "unset": a non-UTF-8 value boots with the empty list (every header read) instead of stopping the boot. The boot refusal itself has no test. | Informational | `forwarded_for.rs` (`from_env`); `boot.rs:1592` → T-212 | wave (W2.1) | #732 |
| R111W2-03 | (a) `audit_wraps_routes` pins a textual order actix-web gives no meaning (an `App::wrap` covers every route wherever it is written), and a plain `find` would be satisfied by a comment; T-477 repeats the premise. (b) The four gRPC sweep registrations have no test. | Informational | `axiam-server/tests/audit_wraps_routes.rs`; `axiam-api-grpc` `build_grpc_governor_layer` → T-474, T-477, T-212 | wave (W2.9, W2.2) | #733 |
| R111W2-04 | T-212's W2.1 amendment and T-428 still name the public-client bucket W2.4 removed. | Informational | STRIDE / `Axiam.json` T-212, T-428 | wave (W2.1 × W2.4) | #734 |
| R111W2-05 | The bucket-name scan does not read the CIBA hint cap's `increment_by` keys (W2.7's recorded residual). No collision is possible today. | Informational | `axiam-oauth2/src/ciba.rs:994`; `rate_limit_bucket_names_test.rs` → T-474 | wave (W2.7) | #735 |
| R111W2-06 | An AMQP-ingested audit row carries no provenance: a tenant's signed producer can persist rows that read like the server's security-change records (`network_segment.*`, `network_policy.*`, `network_role.*_refused` today; W4's `network_role.assigned` … and `certificate_binding.*` next). The reserved set is, by design, only the records the server reads back; none of these is read back. | Informational | `models/audit.rs` (`RESERVED_ACTION_NAMESPACES`); `audit_consumer.rs` → T-118 | pre-existing (raised against W4) | #741 |

**Verdict on merge.** Nothing blocks. R111W2-01 is a missing signal on the
listener W2.1 did not consider, not a change in keying; it is a two-line fix and
may be taken in-wave or in the next patch.

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| Proxy list, keying | W2.1 | `axiam-core/src/forwarded_for.rs`, `ip_class.rs` (`IpNetwork::contains`, `canonical`), REST `extractors/rate_limit.rs`, `middleware/rate_limit_shared.rs`, `server.rs`, gRPC `middleware/rate_limit.rs`, `boot.rs` (the parse and the `WARN`, listener binding order), `main.rs` (panic propagation), `tls.rs` (`grpc_tls_from_env`), `k8s/server/configmap.yml`, the deployment guide, `website/src/docs/configuration.ts` | read in full; every `X-Forwarded-For` reader and every `KeyExtractor` impl in the workspace enumerated |
| Sweep | W2.2 | `axiam-core/src/limiter_sweep.rs`, `axiam-server/src/limiter_sweep.rs`, `server.rs` (`governor_swept`), gRPC `build_grpc_governor_layer` and its four callers, `boot.rs:2776` | read in full; every `Governor::new` / `GovernorLayer::new` in the workspace enumerated |
| Cold-entry seed | W2.3 + repair | `rate_limit_shared.rs` (`admin_preset`), `axiam-db/src/rate_limit_counter.rs`, all 25 wirings in `server.rs`, `rate-limit-sizing.md` | read; wirings counted |
| Public-client bucket | W2.4 | `handlers/oauth2.rs` (`token_inner`), `bucket_key_part` in every key mode, `device_flow_test.rs` | read in full |
| DPoP attribution | W2.5 | `axiam-audit/src/middleware.rs`, every reader of `CachedUserIdentity` (`extractors/auth.rs::cached_identity`, `extractors/rate_limit.rs::verified_principal`) | read in full |
| Crypto acquires | W2.6 | `axiam-pki/src/{permit,ca,cert,pgp}.rs`, `saml_idp.rs`, `saml_idp_slo.rs`, every `CaService`/`CertService`/`PgpService` construction, every `acquire()` in `crates/*/src`, the PKI handlers' utoipa annotations and `sdks/openapi.json` | read in full |
| Bucket-name scan | W2.7 | `rate_limit_bucket_names_test.rs`; every `check_at*` and `increment_by` writer | read; 19 tests run |
| Action grammar | W2.8 | `axiam-core/src/models/audit.rs`, `axiam-amqp/src/audit_consumer.rs`, `asyncapi.yml`, `sdks/CONTRACT.md` §8, the v2 reference vectors | read in full |
| Text and pins | W2.9 | `saml_idp.rs` (`request_status`, the body cap), `saml_idp_slo.rs`, `audit_wraps_routes.rs`, `boot.rs` App composition | read in full |
| Threat model, docs | all | the nine 2026-10-19 amendments in both copies; `docs/deployment/README.md`, `rate-limit-sizing.md`, `docs/admin/public-clients.md` | compared byte for byte (§9) |

Not run: a multi-replica deployment, a live gRPC TLS listener, the frontend. No
probe was needed: every question below was settled by reading and the wave's
own tests.

---

## 2. W2.1 — `TRUSTED_PROXIES` (orchestrator point 1)

### 2.1 The default-open choice

**Confirmed, against #711, #686, D-2, T-212 and T-486.** The orchestrator note
calls the empty-list behaviour a deviation from the plan; it is not one, and the
commit body says so correctly. Plan §3's W2.1 row says "With the list empty,
today's behaviour, plus one `WARN` at boot when native TLS is on", and #711's
own **Fix** paragraph says the same words. Only #711's **Test** sentence ("with
`TRUSTED_PROXIES` empty, two `/auth/login` requests … share a bucket") contradicts
its Fix; the executor followed the Fix and tested the defect with an *unlisted
peer under a non-empty list*, which is the only shape in which "share a bucket"
can hold without breaking the shipped topology. The tree decides it:
`k8s/server/configmap.yml:52` sets `AXIAM__SERVER__TLS__ENABLED: "true"` behind
ingress-nginx, which re-encrypts to the native listener; keying an unlisted
native-TLS peer on itself by default would collapse every client of a Kubernetes
deployment into the ingress's bucket on upgrade — T-212's collapse, which the
entry exists to prevent. D-2 is #718's decision and does not bear on this.
T-486's per-caller bucket on the decision route is unaffected either way (it is
keyed on the authenticated caller).

The residual is real and stated: with the list empty, a direct caller still
chooses its bucket (R110-01 remains open by default, closed by configuration).
T-212's amendment says so ("mitigated where the operator lists the proxies, and
stated at boot where the operator has not"), and the deployment guide says it at
the "Direct, no proxy" row and its paragraph. The "stated at boot" half holds for
the REST listener only — R111W2-01.

### 2.2 One rule for both listeners

**Confirmed.** `axiam_core::forwarded_for::TrustedProxies::honours_forwarded_for`
is the one predicate. REST: `select_rate_limit_ip` returns `(peer, None)` before
reading the header when it is false; every REST address key comes from
`XForwardedForKeyExtractor::configured()` — `build_governor`,
`build_client_aware_governor` (hence the principal governor's address fallback,
the federation backstop, the network-decide backstop), the SCIM mount (which
calls `build_governor`) and the shared counter (`rate_limit_shared.rs:343`).
gRPC: `GrpcTrustedHopsKeyExtractor::extract` gates the header on the same call,
built by `configured()` for the four family governors and from the layer's own
`TrustedProxies::configured()` in `GrpcSharedRateLimitService`. There is no other
`KeyExtractor` impl and no other reader of `X-Forwarded-For` for a rate-limit key
in `crates/*/src` (`realip_remote_addr` is read only for audit and tracing
values, SEC-087). The hop selection after the gate is still written twice, once
per crate, as before the wave (pre-existing; the two agree on every shape the
unit tests pin).

`IpNetwork::contains` canonicalises an IPv4-mapped IPv6 peer
(`::ffff:10.42.7.1` is inside `10.42.0.0/16`), so a dual-stack socket cannot
step outside a v4 list; the unit test pins it. A request with no known peer is
never honoured under a list.

### 2.3 An unparsable value stops the boot

**Confirmed by reading, with one hole.** `boot.rs:1592` calls
`TrustedProxies::from_env()` and `panic!`s on an error. `serve` is awaited
directly from `#[tokio::main]` (`main.rs:672`), so the panic ends the process,
and it runs before either listener binds (`bind_rustls_0_23` / `bind` at
`boot.rs:3240-3245`; the gRPC server later still). The parse refuses a host
name, host bits below the prefix (`10.0.0.1/8`) and an out-of-range prefix. The
hole: `from_env` maps every `VarError` to the empty list, so a value that is not
UTF-8 boots with the header read from every peer (R111W2-02). Nothing tests the
boot refusal itself; the parse is unit-tested.

### 2.4 The `WARN`

Emitted when `config.server.tls.enabled` and the list is empty; otherwise, with
a list, one `INFO` naming it. The gRPC listener's native TLS is a separate
setting (`grpc_tls_from_env`, `boot.rs:2641`) and is not consulted — R111W2-01.
The FreeRADIUS sentence W5.8 wrote on the W5 branch — "Left empty, every peer's
header is still read and a server with native TLS on logs one `WARN` at boot" —
**matches W2.1's code** for the listener FreeRADIUS reaches (the REST listener,
`AXIAM__SERVER__TLS__ENABLED`). No merge finding; if R111W2-01 is fixed, the
sentence stays true.

### 2.5 Plan vs tree

The row names `config/rate_limit.rs` and `scripts/check-config-key-coverage.py`;
the tree reads the variable in `axiam-core` (below both listeners, as the
layering requires) and the coverage script needed no exemption because
`website/src/docs/configuration.ts` documents the key. The #686 correction is
posted (comment 6274230681, 2026-10-19) and matches the code.

---

## 3. W2.2 — the sweep (orchestrator point 7)

**Confirmed.** The registry holds closures over `Weak<RateLimiter>`:

* **It never keeps a governor alive.** The only strong reference it takes is the
  `upgrade()` inside one sweep, dropped when the closure returns; between sweeps
  the map lives exactly as long as the `Governor`/`GovernorLayer` holding the
  config's `Arc`. `governor_sweep_test.rs` shows a dropped app leaves 0
  registered limiters.
* **It never drops a live one, nor a live cell.** A sweeper is forgotten only
  when `upgrade()` fails. `retain_recent` removes only cells indistinguishable
  from a fresh one (fully replenished), so a caller in the middle of its burst
  keeps its state; the sweep cannot hand anyone a fresh allowance.
* **Coverage.** Every `Governor::new` in `crates/*/src` is now inside
  `governor_swept` (`server.rs:80`); the gRPC side registers each of the four
  family layers in `build_grpc_governor_layer`, called only from
  `build_grpc_method_scoped_governor_layer`, which the gRPC server holds for its
  lifetime (`axiam-api-grpc/src/server.rs:314`). `register_api_v1_routes_with`
  runs once per actix worker, so each worker's maps are registered once, at
  start; no governor is built per request.
* **The task** (`boot.rs:2776`) sweeps every 60 s and stops on the cleanup
  task's shutdown signal.

The gRPC registration has no test of its own (R111W2-03 (b)). The executor's
"T-474 has no such text" is confirmed; only T-212 said the maps were unswept.

---

## 4. W2.3 and its repair (orchestrator point 2)

**Confirmed.** `admin_preset` is `new` with `human: true`; all 25
`*_admin_per_min` wirings in `server.rs` use it (directory 4, SAML 7, SSF 3, SCIM
targets 4, network 7) and no other bucket changed. The sliding-window carry
still applies (`check_at_human` skips only the seed), so a spent minute is not
re-spent at once; the routes are authenticated and authorised. The new counter
test shows a key first seen at second 57 keeps all 30 while the machine path
with the same limit is still seeded.

W2.3 broke `rate_limit_bucket_names_test` (its scan refused the unknown
constructor). `2b24f3787` adds `admin_preset` to `CONSTRUCTORS`;
`an_admin_preset_registration_is_read` and `an_unknown_constructor_is_refused`
pin both halves. After W2.7 the file has **19** tests and still reads
`admin_preset` (in `CONSTRUCTORS`, in the defining-file test) and
`check_at_human` (in `COUNTER_CALLS`; `ciba_approval_list` is found through it).
All 19 pass (§12).

---

## 5. W2.4 — the public-client bucket

**Confirmed.** The commit's claim that the bucket "could only refuse a request
the route had already admitted" holds in every key mode: the removed key was
`(tenant, client_id, address)` at `token_per_min`; the route's key at the same
limit is `address` (`ip`), `client_id` (`client_id`) or `(address, client_id)`
(`ip_client_id`) — each a coarsening of it — so the route bucket empties no
later. With the bucket gone a credential-less flood meets `429
rate_limit_exceeded`; the device grant's `slow_down` (a `400` to a poll inside
its interval) is unchanged and tested. `rate_limit_client_ip` had no other
caller. The text left behind is R111W2-04.

---

## 6. W2.5 — the DPoP scheme in the audit middleware

**Confirmed.** The middleware now caches the identity of a `DPoP <jwt>` request,
case-insensitively, without checking the proof. That is safe because the cache
has exactly two readers: `cached_identity` (`extractors/auth.rs:950`), which runs
`enforce_sender_constraint` against the request's own proof before admitting
anything, and `verified_principal` (`extractors/rate_limit.rs:360`), which marks
a `cnf` token `sender_constrained` so `bucket_key_part` keys it on `(address,
principal)` — a copy replayed from another address spends its own bucket. A
proofless request is still `401`. The spelling is local because `axiam-oauth2`
is above `axiam-audit` in the layering (the layering check passes). The
request-audit row of a refused request carrying a stolen bound token now names
the token's user; that was already true under the `Bearer` scheme and is
correct attribution of what was presented.

---

## 7. W2.6 — the bounded acquires (orchestrator point 3)

**Confirmed.** All ten sites take a bounded permit: the eight PKI sites through
`permit::bounded_permit` (`ServiceUnavailable` → `503` after the wait; closed →
`Internal`, as before), assertion signing through `CryptoGate::acquire` (busy →
the retry page, `503` + `Retry-After: 5`, nothing written; closed → `Responder`),
SLO signing → `Err("signing")`, a partial hop. A sweep of `acquire()` /
`acquire_owned()` in `crates/*/src` finds no unbounded acquirer of the shared
semaphore left. Both production constructions take the deployment's wait
(`boot.rs:1053-1076`; the SAML IdP credential service gets `cert_service.clone()`,
`boot.rs:1460`); the second `CertService::new` in `state/mod.rs:694` is the test
harness's. `sign_audit_batch` has one caller, an authenticated REST handler, so
a `503` there is retried by the administrator and loses nothing.

**The undocumented `503`: a W7.1/W8.2 note, not a finding.** The PKI routes'
utoipa annotations, and therefore `sdks/openapi.json`, do not list `503`
(`POST /api/v1/certificates` lists 201/400/404). The spec's own precedent is the
same: `POST /api/v1/auth/login`, gated on the same semaphore since 1.0, lists no
`503` either, and CONTRACT §2 maps every `5xx` to `NetworkError`, so no SDK
mis-handles it. Annotating the gate's `503` consistently (login, register,
password, the PKI routes, the SAML pages) is a spec-completeness task for W7.1's
regeneration or W8.2, not a defect of this wave.

---

## 8. W2.7 (orchestrator point 4), W2.8 (point 6), W2.9 (point 5)

### 8.1 `ciba_hint_cap`

**No collision is possible today**: the prefix appears only at
`axiam-oauth2/src/ciba.rs:994` and in tests, and its keys
(`ciba_hint_cap:{tenant}:{64 hex}`) cannot equal any middleware key unless a
future bucket is named `ciba_hint_cap`, which the scan would then accept. Filed
as Informational (R111W2-05).

### 8.2 The action grammar and its producers

**Confirmed.** The check runs after the HMAC, `key_version` and freshness gates
and before the reserved-namespace test and the nonce, as the commit says; a
refused message's nonce is not recorded, which costs nothing because the refusal
is deterministic (a replay is refused again). The only ingestion of a
producer-written action is the AMQP consumer (`is_valid_audit_action` and
`reserved_action_namespace` have no other caller; no gRPC or REST route accepts
an external audit action). The server's own writers, `METHOD /path` included,
append directly and never pass the consumer. CONTRACT §8's audit vector uses
`user.login`; the v2 reference vectors use `user.login`; both are inside the
grammar. The SDK repositories are outside this session's scope; their producers
emit what CONTRACT shows. The grammar bounds the alphabet, not ASCII homoglyphs
(`tenants,audit_exported`); T-118's residual says so.

**Note for W7.1:** CONTRACT §8 "Actions the audit ingestion refuses" ends "No
other action name is reserved", which is no longer the whole rule: an action
outside printable ASCII with one inner space is now refused the same way.
Contract 1.63 should state the grammar (W2 may not edit CONTRACT, §10).

### 8.3 T-477 and the `413`

**Confirmed against the code; the note that the `413` could not be located is
rejected.** `saml_idp.rs:214-221` (`request_status`) answers `413` for
`RequestError::TooLarge`, raised when the POST body passes `MAX_POST_BODY_BYTES`
(192 KiB, `saml_idp.rs:117,585`; the SLO receiver at `saml_idp_slo.rs:289`). The
SLO receiver's `403`s are `sp_disabled` (`:386`) and `idp_logout_cross_site`
(`:1022`). T-477's amended text is accurate.

### 8.4 The audit-wrap scan

See R111W2-03 (a): an `App::wrap` is app-wide in actix-web, so the scan's
assertion (and T-477's sentence describing it) pins an order with no runtime
meaning; it does catch the removal of the only `.wrap(audit_middleware`.

### 8.5 Server-written security-change actions at the ingestion (orchestrator follow-up)

The orchestrator asked whether W4's new server-written actions
(`network_role.assigned` / `.unassigned` / `.granted` / `.revoked` /
`.permission_revoked_by_reconcile`, `certificate_binding.bound`, and the refusal
rows `network_role.*_refused`, `certificate_binding.refused`) belong in
`RESERVED_ACTION_NAMESPACES`. On W2's tree after W2.8 the reserved set is still
`["tenants.", "gdpr."]` and the grammar reserves nothing more, so an
HMAC-authenticated producer of a tenant can persist any of them. But the
property is **pre-existing and wider than W4**: W2's own tree already writes
`network_segment.created`/`.deleted`, `network_policy.raised`/`.lowered`,
`network_role.assign_refused`/`.grant_refused`/`.write_refused`,
`network_decision.*` and `user.certificates_revoked`, all equally open, as is
every other server action. The reserved set's purpose (`models/audit.rs`,
R101W3-03, T-118, T-472) is the records the server **reads back to decide**: the
export receipt that authorises a deletion, the deletion and purge records, the
GDPR records. Nothing reads a `network_role.*` or `certificate_binding.*` row
back on W4's tree either (no reader of the constants but the writers; the only
`action = $action` query is the administrator's list filter). The forger needs
the tenant's own signing subkey and writes only into that tenant's log; CONTRACT
§8 says no other name is reserved. **Informational (R111W2-06, #741)**, not
Medium: a provenance gap in a log for humans, not a control bypass. Adding the
two prefixes would treat one family and leave the rest; the issue proposes a
server-stamped provenance mark on every ingested row instead, with reservation of
every server namespace (enforced by a test over the action constants) as the
alternative.

---

## 9. The §10 rules and the threat model

| Rule | Held? | Evidence |
|---|---|---|
| Every fix carries the test its row names | yes | each commit's tests located and run (§12); W2.1's row test realised with an unlisted peer (§2.1) |
| Every document the row names moved in the same commit | yes | per commit `--stat`; W2.6's README row, W2.8's `asyncapi.yml`, W2.1's guide and `configuration.ts` |
| Threat-model entries amended in both copies, dated, no version bump | yes | the nine 2026-10-19 paragraphs are byte-identical in `threat-model-stride.md` and `Axiam.json` (scripted comparison of each full paragraph); `version` still `2.42.0` |
| Nobody edited `sdks/CONTRACT.md` | yes | not in the diff |
| No migration | yes | `schema.rs` not in the diff |
| No new crate | yes | no `Cargo.toml` in the diff; layering check passes (19 crates) |
| Signed commits | yes | 10 of 10 |

Threat-model text against code: T-212 (W2.1) — accurate except "and the
public-client bucket" (R111W2-04) and "stated at boot" for gRPC (R111W2-01);
T-212 (W2.2) — accurate; T-289 (W2.4) — accurate; T-474 (W2.5, W2.7) — accurate;
T-102 and T-477 (W2.6, W2.9) — accurate except the audit-wrap scan's premise
(R111W2-03); T-118 (W2.8) — accurate. T-428 still names the removed bucket
(R111W2-04). T-212's pointer to `docs/pki/freeradius.md` section 5 for "expose
the native listener only to the clients that must reach it" is W5.8's text on
the W5 branch; it resolves once both waves are merged.

Observation, not a finding: nine of the ten commits carry a model name in their
`Co-Authored-By` trailer; the kickoff asks executors not to put one in a commit.

---

## 10. Executors' follow-ups, confirmed or rejected

| Executor note | Verdict |
|---|---|
| W2.1: the row and the orchestrator note disagree; the tree (k8s native TLS behind ingress) decides for the row | **confirmed** (§2.1) |
| W2.2: only T-212, not T-474, said the maps were unswept; a `Weak` closure instead of a handle | **confirmed** (§3) |
| W2.3: the mechanism is the existing `check_at_human` flag, not a constant; neither threat-model copy states the seed per family | **confirmed** |
| W2.4: `rate_limit_bucket_names_test` failed before and after (W2.3's constructor) | **confirmed**; repaired by `2b24f3787` (§4) |
| W2.5: the extractor-side enforcement is in the tree as the 1.1.0 review argued | **confirmed** (§6) |
| W2.6: stale line numbers; the remote-issuance leg has no in-memory test; no annotation changed, so no spec regeneration | **confirmed**; the `503` is a W7.1/W8.2 note (§7) |
| W2.7: seven handler prefixes, not eight (`oauth2_token_public` removed); `ciba_hint_cap` not read | **confirmed**; filed as R111W2-05 |
| W2.8: no in-tree action through the ingestion falls outside the grammar | **confirmed** (§8.2) |
| W2.9: (d) and (g) already done by W2.5/W2.6; the `413` (orchestrator: "could not locate") | (d), (g) **confirmed**; the `413` exists (§8.3) — the note is **rejected** |

---

## 11. Issue bodies

Filed on `ilpanich/axiam`, milestone `1.1.x`:

* **#731** — R111W2-01 (Low): the empty-`TRUSTED_PROXIES` boot `WARN` ignores the
  gRPC listener's native TLS. Fix: decide the `WARN` on
  `config.server.tls.enabled || grpc_tls.is_some()` and name the listener;
  amend T-212. Test: the decision with REST TLS off and gRPC TLS on warns.
* **#732** — R111W2-02 (Informational): a non-UTF-8 `TRUSTED_PROXIES` is read as
  the empty list, and the boot refusal has no test. Fix: `NotUnicode` is an
  error; a lookup-closure twin of `from_env`. Test: the twin refuses a non-UTF-8
  value and an unparsable entry.
* **#733** — R111W2-03 (Informational): the audit-wrap scan pins an order actix
  does not have and matches comments; the gRPC sweep registration is untested.
  Fix: assert the wrap on the `App::new()` chain with comments stripped (or a
  behavioural test); correct the doc comment and T-477; a gRPC sweep unit test.
* **#734** — R111W2-04 (Informational): T-212 and T-428 still name the removed
  public-client bucket. Fix: dated correction in both copies.
* **#735** — R111W2-05 (Informational): the bucket-name scan does not read the CIBA
  hint cap's `increment_by` keys. Fix: read repository writers' key prefixes into
  the uniqueness check. Test: a synthetic colliding `increment_by` prefix is
  flagged.
* **#741** — R111W2-06 (Informational): an AMQP-ingested audit row is
  indistinguishable from a server-written security-change row. Fix: a
  provenance mark the consumer stamps and the producer cannot override (or
  reservation of every server namespace, pinned by a test over the action
  constants, with CONTRACT and T-118 amended). Test: an ingested
  `network_segment.created` is persisted marked; a producer-supplied mark is
  overwritten.

---

## 12. Checks run

Every command's own exit code (redirected to a log, `$?` read; never a
pipeline's). Environment: `CARGO_INCREMENTAL=0`, the swagger placeholder,
`protoc` and `libxml2-dev`/`libxmlsec1-dev` installed; `cargo clean` between
crates. Counts are passed / failed / ignored, the doc-test binary included.

| Command | Exit | Counts |
|---|---|---|
| `cargo test -p axiam-core --lib` | 0 | 531 / 0 / 0 |
| `cargo test -p axiam-amqp` (15 binaries) | 0 | 283 / 0 / 11 — `audit_consumer_test` 14/0/0; the 11 ignored are `#[ignore]` broker/container tests (`amqp_recovery_test`, `reactor_containerized_test`) |
| `cargo test -p axiam-audit` (5) | 0 | 75 / 0 / 1 — `service_and_middleware` 32/0/0 |
| `cargo test -p axiam-pki` (19) | 0 | 374 / 0 / 2 — `permit_bound_test` 8/0/0 |
| `cargo test -p axiam-federation` (4) | 0 | 363 / 0 / 0 |
| `cargo test -p axiam-db --lib` | 0 | 317 / 0 / 0 (the counter's #718 test included) |
| `cargo test -p axiam-api-grpc` (6) | 0 | 113 / 0 / 2 — `rate_limit_shared_store_test` 5/0/0, lib 48/0/0 |
| `cargo test -p axiam-api-rest --no-default-features --lib`, then each of the 112 test binaries with `--test <name>` | 0 for 112 of 113 | 1 938 / 15 / 3. The one non-zero is `federation_test` (exit 101, 69/15/0): its 15 failing tests are SAML routes answering `404` because SAML is compiled out; they carry no `cfg(feature = "saml")`, the wave does not touch the file, and CI runs this binary with SAML on only (its SAML-off job runs two conformance binaries). With SAML on it passes (below). Wave binaries: `rate_limit_keying_test`, `governor_sweep_test`, `device_flow_test`, `rate_limit_principal_test`, `rate_limit_bucket_names_test` (19/0/0) all exit 0 |
| `cargo test -p axiam-api-rest --lib`, then the 10 SAML-dependent binaries (SAML on) | 0 for 11 of 11 | 576 / 0 / 6 — `federation_test` 87/0/0, `saml_idp_sso_test` 22/0/0, `saml_idp_slo_test` 28/0/0, `rate_limit_bucket_names_test` 19/0/0, `rate_limit_principal_test` 13/0/0; the 6 ignored are `saml_idp_keycloak_roundtrip_test` (needs Keycloak) |
| `cargo test -p axiam-server --no-default-features --lib`, then each of the 26 test binaries | 0 for 27 of 27 | 319 / 0 / 0 — `audit_wraps_routes` 1/0/0, `radius_e2e` 2/0/0 |
| `cargo fmt -p <crate> -- --check` for the eight touched crates | 0 ×8 | |
| `python3 scripts/check-remediation-evidence.py` (after `git fetch --unshallow`) | 0 | 5 verified, 0 failed, 32 skipped (SDK repositories unreachable from this sandbox, HTTP 403) |
| `bash scripts/check-doc-links.sh` | 0 | 533 links across 78 files |
| `python3 scripts/check-config-key-coverage.py` | 0 | |
| `python3 scripts/check-crate-layering.py` | 0 | 19 crates, 62 edges |
| `python3 scripts/check-spec-digest.py` | 0 | the spec is unchanged by the wave |

A first attempt to run the REST suite as one `cargo test` invocation ran out of
the sandbox's disk quota while linking (`ld … Bus error`, `No space left on
device`), so no binary ran; it was rerun one binary at a time as above. Not run:
clippy (the executors' gates record it per commit; CI runs it).

---

## 13. Invariants

* `X-Forwarded-For` decides a rate-limit key only through
  `TrustedProxies::honours_forwarded_for`, on both listeners.
* No in-process rate-limiter map outlives one minute of inactivity per key; the
  sweep registry never owns a limiter.
* No waiter on the shared crypto semaphore waits without a bound.
* No audit action outside printable ASCII (one inner space) is persisted from
  the AMQP ingestion.
