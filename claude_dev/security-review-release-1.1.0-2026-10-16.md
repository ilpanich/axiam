# Security review — release 1.1.0, the combined plan branch (F4)

**Date:** 2026-10-16.
**Against:** `claude/release-1.1.0` at `f922935a0`, the whole release diff
`3d011573e..f922935a0` (97 commits — 91 plus the six wave merges —, 246 files,
56 654 lines added and 5 919 removed; `3d011573e` is the `main` the six wave
branches were cut from, plan §13.0). Every commit of the range carries a `gpgsig`
header (97 of 97; the sandbox has no `gpg.ssh.allowedSignersFile`, so `%G?` prints
`N` and cannot verify them here).
**Scope:** what no single review could see. Each wave was reviewed on its own
branch — [W1](security-review-release-1.1.0-w1-2026-10-14.md),
[W2](security-review-release-1.1.0-w2-2026-10-15.md),
[W3](security-review-release-1.1.0-w3-2026-10-15.md),
[W4](security-review-release-1.1.0-w4-2026-10-15.md),
[W5](security-review-release-1.1.0-w5-2026-10-15.md),
[W6](security-review-release-1.1.0-w6-2026-10-16.md) — and contract 1.62 with the
eleven SDK ports by [`sdk-contract-1.62-conformance-review.md`](sdk-contract-1.62-conformance-review.md).
Their findings are not repeated here (the Low and Informational ones are
ilpanich/axiam#664 … #709 and the SDK repositories' issues, plan §13). This
review covers, as plan §9 (W8.2) and the orchestrator's brief ask:

1. the **cross-wave interactions and the six merges** (§13.7's table), above all
   the code the merges had to write: W1's orphan claim (#622) inside W4's
   two-phase purge (#655); W2's, W3's and W6's limiter and bucket changes
   together; W1's v99 beside W6's v100; W3's device-grant client authentication
   beside W6's certificate-bound decision caller; W1's random serials beside W6's
   serial-keyed fingerprint stash; `error.rs`'s `reason_code: None` on W3's `422`;
2. the **commits no wave review read**: `6e7a0015d` (#675, the boot warning, on
   the W3 branch after its review); every W6 commit after its review `dacca3318`
   (`21ab64fbc`, `22fcc5098`, `9dff2aa97`, `f15f67434`, `b3a035413`, `122b9ea92`);
   the W7 contract commits `5c012d741`, `d76c5a80b`, `d25413506` read as
   normative security text; `89e488e3e` (version 1.1.0); `f922935a0` (rustls);
3. the **residuals carried forward** (the 23 Open threats, among them T-450,
   T-462, T-481, T-483, T-484, T-486) and whether 1.1.0 as merged still has the
   substance the model claims (W8.3 reconciles the text);
4. the **release as a whole**: the authentication and authorization boundary of
   the new routes and of the decision route; the deny-override engine under the
   H1–H6 gate; tenant isolation; audit completeness; rate limiting end to end;
   secrets in logs; the supply chain at `f922935a0`.

**Method:** the method and severity scale of the 1.0.1 combined review
([`security-review-release-1.0.1-2026-10-14.md`](security-review-release-1.0.1-2026-10-14.md)).
Adversarial reading of the merges' combined diffs (`git show --cc`), of every file
two waves touched, of each commit in item 2 in full, and of the code each claim
rests on at `f922935a0` (not the commit messages). Where a behaviour depends on
another program, its source was read: FreeRADIUS 3.2.8's `src/main/tls.c`
(`cbtls_verify`), for when the D4 fingerprint hook runs. One claim was settled by
a probe (§3): a temporary test file in `crates/axiam-db/tests/`, run and deleted
before this commit. The supply-chain gates were run exactly as CI runs them
(§11). Threat model: `Axiam.json` and `threat-model-stride.md` at 487 entries —
454 Mitigated, 23 Open, 10 Not applicable; ids 1 … 487 unique, `threatTop` 487,
every STRIDE status equal to the JSON's (verified by script). IDs: `R110-NN`.
This review fixes nothing. **Nothing is Medium or higher**, so nothing is
dispatched before the release PR; the two Low and three Informational findings have
issue bodies (§10) for milestone `1.1.x` (#23).

---

## 0. Summary

**No finding is Medium or higher.** The merges are sound where they had to write
code, the commits nobody had read do what their messages say, and the release's new
surfaces hold their boundaries on the merged tree. Two findings are Low. One comes
from two waves meeting: the deployment D4 (W6) requires meets a limiter caveat
(T-212, #686) that no wave owned. The other is in a commit no review had read
(#675's boot count, R110-02).

* **R110-01 (Low, cross-wave: W6.5 × T-212/#686).** The D4 recipe requires mutual
  TLS that ends at **AXIAM's own listener** ("a layer-4 proxy that passes the TLS
  connection through untouched is fine", `docs/pki/freeradius.md:521-533`). AXIAM has
  one listener (`boot.rs:3199`), so that is the listener every route is served on.
  With no appending proxy in front, every address-keyed limiter reads the
  **rightmost `X-Forwarded-For` entry the caller wrote** (`select_rate_limit_ip`,
  `extractors/rate_limit.rs:131-157`, `trusted_hops = 0`, the default and the only
  correct value for the shipped topologies). A caller who reaches that listener
  chooses its own bucket on every request: `/auth/login`'s per-address limiter, the
  device login FreeRADIUS uses, the decision route's per-address backstop, the token
  endpoint in its default key mode, every other per-address route. It also grows
  every in-process governor map by one entry per request, maps nothing ever sweeps
  (#673). The deployment guide says the direct case reads `peer_addr()` because the
  header is "*(absent)*" (`docs/deployment/README.md:927`), which holds only for a
  caller that sends none. #686 recorded the defect for a non-zero `TRUSTED_HOPS`
  and says the default is safe. It is not: the default reads the header too, and
  1.1.0's D4 is the first documented topology that asks for this exposure. The
  primary controls are not touched: per-account lockout, Argon2id behind the crypto
  gate, and the decision route's per-caller bucket, which is keyed on the
  authenticated `sub`.

**Findings index.**

| ID | Finding | Severity | Surface / threat | Origin | Disposition |
|---|---|---|---|---|---|
| R110-01 | D4 requires AXIAM's own listener to be reachable with no appending proxy; there every per-address limiter keys on a caller-written `X-Forwarded-For` (rotatable buckets, unswept governor maps). The guide is silent, and #686's body says the default is safe. | Low | `extractors/rate_limit.rs:131-157`; `boot.rs:3199`; `freeradius.md:521-533`; `docs/deployment/README.md:927` → T-212, T-468, T-486, #673, #686 | cross-wave (W6.5 × pre-existing T-212) | Issue (§10) |
| R110-02 | #675's boot count re-evaluates the live-tenant subquery for every matching client row (the shape R110W1-01 removed from the retention sweep), while its comment says the tenant table is read once. At about 3 000 device clients in 300 tenants it outlives its 5 s deadline by a factor of ten (probe: 55.7 s against 0.245 s hoisted, §3), so the warning becomes "timed out" with no count, and the query keeps running in the datastore at every replica's boot. | Low | `oauth2_client.rs:1145-1180`; `device_grant_scan.rs:35,43-56` → R110W3-02 (#675) | commit no review read (`6e7a0015d`) | Issue |
| R110-03 | `radius-e2e.yml`'s path filter names the decision route and the gate, but not what the decision's answer rests on: `axiam-pki/src/mtls.rs` (`authenticate_der`, run twice per decision), `extractors/cert_auth.rs`, `handlers/auth.rs` (the device login), `axiam-db/src/repository/network.rs`, `handlers/network.rs`, `axiam-authz/src/engine.rs` (deny-override, which quarantine is). | Informational | `.github/workflows/radius-e2e.yml:39-61` → T-462, T-468, #697 | cross-wave (W6.5 × W5.3's filter) | Issue (extends #697) |
| R110-04 | An orphan purge's claim marker is created before the unit holds its `PurgeClaim`. A teardown cut in `begin_orphan_purge` (between the marker's `CREATE` and `has_purgeable_rows`'s answer) leaves the marker claimed with no guard to release it. The id then waits out the one-hour lease. For a stale scan whose id another replica already purged, the tombstoned-tenant sweep later purges the empty marker and writes a **second** `tenants.purged` for that id. | Informational | `tenant.rs:570-605`; `cleanup.rs:602-622` → T-444, T-472 | merge (W1 #622 × W4 #655) | Issue |
| R110-05 | Text the merged tree contradicts: (a) `RadiusServiceType`'s schema description says the administrative values are refused with `400`, whereas the code and contract §36.3 rule 5 (as corrected) say `403`; (b) the deployment guide's "Direct, no proxy" row (R110-01); (c) #686's body; (d) T-481 calls the segment, profile and cap writes "the exception", but their transactions re-check the row, not the writer's rights; (e) the network-gate enumeration test exempts every function named `prepare` in `cleanup.rs`, not W4's erasure step alone. | Informational | §5 | cross-wave text | Issue ((a) also on #700; (d) W8.3) |

The cross-wave points that are **not** findings (§6, §7, §8, §9):

* **The purge merge (`7292eaf56`) is correct.** W1's marker sits inside W4's two
  phases, and W4's `PurgeClaim` releases it at every exit but a removed marker. A
  marker given up at the stop is therefore taken over by the tombstoned-tenant sweep
  as the orphan it is, and recorded once with `orphan: true`.
* **The limiters merged as a union.** Each route keeps its own bucket and backstop.
  The rate-limit bucket sweep's retention derivation covers the decision route's
  bucket, and both new settings are validated `≥ 1`.
* **The migrations run in order.** v99 and v100 apply 98 → 99 → 100, both
  additive, with the newest-version assertion at 100.
* **No device-grant token reaches the decision route**, whatever its `cnf`. The
  route takes only a service-account `sub_kind`, bound to a certificate on this
  connection that `authenticate_der` re-resolves on every request.
* **The serial-keyed stash cannot be poisoned.** FreeRADIUS runs the hook only
  after OpenSSL accepted the chain (`tls.c` returns at `if (!my_ok)` before the
  depth-0 block). With one issuer in `ca_file`, the serial names one certificate.
* **`reason_code: None` on the `422` is right.** The member is
  `skip_serializing_if`, so the body is unchanged.
* **The six commits after W6's review hold under re-reading.** H6 now covers every
  §5.3 door, the placement re-check is in the write transactions, and a
  certificate cannot be moved off the writer (one binding per certificate
  (`idx_cert_bound_unique`), and no unbind route).
* **Supply chain.** `cargo deny --all-features check -D advisory-not-detected` and
  `cargo audit` with CI's ignore list both exit 0 at `f922935a0`, with rustls
  0.23.46 in all three Rust lockfiles that carry it.

---

## 1. What was reviewed, and how

| Surface | Waves | Files | Depth |
|---|---|---|---|
| Tenant and orphan purge (merge `7292eaf56`) | W1.8 (#622), W4.2 (#655), W3.3 (#637) | `axiam-db` `tenant.rs:195-660` (claim, release, `purge_tombstoned{,_rows}`, `remove_purged_tenant`, `claim_orphan_purge`, `begin_orphan_purge`, `purge_orphan{,_rows}`), `tenant_purge.rs` (`has_purgeable_rows`, `orphaned_tenant_ids`, `TENANT_PURGE_ORDER`); `axiam-server` `cleanup.rs:380-770` (`sweep_tenant_purge`, both units, `PurgeClaim`) | **read in full**; `--cc` of the W3 and W4 merges; every exit of both units traced against the claim's state |
| Limiters and buckets (merges `45243b94d`, `09350bd2f`) | W2.3, R110W2-01, W3.1, R110W3-01, W3.4, W3.5, W6.3, W6.4 | `server.rs:20-150, 1800-1935`; `extractors/rate_limit.rs`; `config/rate_limit.rs` (`validate`, presets); `network_decide_guard.rs`; `cleanup.rs:240-345` (`RATE_LIMIT_BUCKET_*`) | **read**; the decision route's spend order checked against its extractors |
| Schema v99 + v100 | W1.9, W6.1 | `schema.rs:500-525, 4835-4990`, the scope tests, the assertion at `:6661` | read |
| The decision route as merged | W6.4, W3.1, W1.9, W5.4 | `handlers/network_decide.rs` (in full), `permissions.rs:440-476`, `handlers/auth.rs:919-967` (`device_auth`), `axiam-pki/src/mtls.rs:63-230`; `docker/radius/raddb/d4/*`; FreeRADIUS 3.2.8 `tls.c` `cbtls_verify` | **read in full** |
| The network gate after the review | W6.7's fixes | `axiam-authz/src/network_gate.rs:960-2140` (every rule); `axiam-db/src/repository/network.rs` (the three transactions); `handlers/certificates.rs:680-790` (bind) | **read in full** |
| `6e7a0015d` (#675) | W3 after its review | `oauth2_client.rs` `count_confidential_with_grant`, `device_grant_scan.rs`, `boot.rs:1189` | read; **probe** (§3) |
| Contract 1.62 as security text | W7.1, W7.1b, W7.1c | `CONTRACT.md` §14 (`:2867-3060`), §36.3, §36.11 (`:13786-13870`), the §34.6 record; checked against `token_device.rs`, `network_decide.rs` | read; the order of each refusal checked in the code |
| `89e488e3e`, `f922935a0` | W8.4a, W8.1a | `Cargo.lock`, the two example lockfiles, `k8s/*/deployment.yml` | read; deny and audit run |
| Workflows | W4.5, W5.3, W6.5 | `ci.yml`, `fapi-conformance.yml`, `radius-e2e.yml` diffs | read |
| Console | W6.8 | `frontend/src` diff (26 files) | scanned for DOM sinks: none |
| Threat model | all | `Axiam.json`, STRIDE; T-212, T-444, T-457, T-462, T-468, T-481, T-483, T-484, T-486 | script + reading |

Not done: a Rust build of anything but `axiam-db`'s test binaries. W8.1 ran the
whole regression gate on `310203c98`, and `f922935a0` re-ran 81 binaries after
changing only lockfiles. The SurrealDB container, a live AMQP broker and the
eleven SDK repositories were not touched. The `radius-e2e` was not re-run; W8.1 ran
it on the merged tree (2 passed, 425 s).

---

## 2. R110-01 — D4's listener meets a caller-written `X-Forwarded-For`

**The two facts, each from a different wave.**

* W6.5 (the D4 recipe) requires the decision route's TLS to end at AXIAM:
  "**FreeRADIUS must reach AXIAM over a TLS connection that AXIAM itself ends.** …
  A proxy, load balancer, ingress or service-mesh sidecar that terminates TLS …
  cannot stand in … A layer-4 proxy that passes the TLS connection through untouched
  is fine." (`docs/pki/freeradius.md:521-533`; T-468, T-486). The token request
  `POST /api/v1/auth/device` needs the same connection.
* AXIAM's native TLS is **one listener** for the whole API:
  `http_server.bind_rustls_0_23(&bind_addr, rustls_config)` (`crates/axiam-server/src/boot.rs:3199`).
  Every per-address limiter keys on `select_rate_limit_ip(headers, peer,
  trusted_hops)` (`crates/axiam-api-rest/src/extractors/rate_limit.rs:131-157`). It
  takes `hops[len - 1 - trusted_hops]` of `X-Forwarded-For` whenever the header has
  more entries than `trusted_hops`, and the peer address only when there is no
  header.

**What happens on that listener.** With no appending proxy in front (direct, or an
L4 pass-through without the PROXY protocol, which actix does not read), nothing
appends to the header: the rightmost entry is whatever the caller wrote. With
`TRUSTED_HOPS = 0`, the default and the value both shipped topologies set, the
caller's entry is the key. The function's own doc comment says so ("A server
exposed with no proxy at all reads whatever the caller wrote — the deployment
guide's T-212 caveat"). The guide, though, says the direct topology sees the header
"*(absent)* → `peer_addr()`" (`docs/deployment/README.md:927`). That holds only
for a caller that sends none.

So a caller who can open a TLS connection to that listener picks a fresh bucket on
every request, on every route that keys on the address:

* `/auth/login`'s per-address limiter, there so that guessing does not scale with
  requests;
* `device_login_per_min` on `/auth/device`, the route FreeRADIUS itself uses;
* the decision route's per-address backstop (`server.rs:1923-1934`,
  `NETWORK_DECIDE_BACKSTOP_FACTOR`), whose stated job is to stop "a burst of calls
  with a token that does not authenticate";
* `/oauth2/token`, `/oauth2/device_authorization` and the public-client bucket
  (R110W3-01's fix reads the same function);
* every other per-address route.

Each fresh key is also one more entry in the route's in-process governor map, and
nothing ever sweeps those maps (#673, R110W2-05). On this listener their growth is
the caller's to choose.

**Why it is a 1.1.0 interaction and not only #686.**

* #686 (filed from W3) records the defect only for "`TRUSTED_HOPS` at a value
  ≥ 1 (verify the default)". The default is `0`, and `0` reads the header too.
* No shipped topology exposes the listener without a proxy. The D4 guide is the
  first document that asks for that exposure, and it says nothing about the
  limiters.
* Two routes D4 depends on are among those affected: the device login and the
  decision route's backstop.

**Why Low.**

* The per-account controls are untouched: lockout, Argon2id behind the bounded
  crypto gate, and the per-client and per-principal buckets.
* The decision route's real limit, `network_decide_per_min`, is keyed on the
  authenticated caller's `sub` and is not affected.
* An operator can confine the native listener to the FreeRADIUS hosts and keep the
  appending proxy for everything else. Both reach the same listener: the proxy's
  path then keys correctly, and only the FreeRADIUS path reads a caller's header.
  Nothing tells the operator to do that, however, and a deployment that switches its
  ingress to L4 pass-through for D4 exposes every route this way.

**Fix (1.1.x).**

1. **Code — #686's remedy, made explicit.** Add a setting that names the proxies
   whose `X-Forwarded-For` is honoured: `AXIAM__RATE_LIMIT__TRUSTED_PROXIES`, a list
   of CIDRs. Honour the header only when the transport peer is in that list,
   otherwise key on the peer. With the list empty, keep today's behaviour (the
   shipped topologies) and log one `WARN` at boot when native TLS is on. A
   connection that arrives on the native listener and is not in the list is keyed
   on its peer.
2. **Docs.** `docs/pki/freeradius.md` §5 "The connection" gains one paragraph: the
   native listener is every route's listener; expose it only to the FreeRADIUS
   servers (a firewall or network policy); keep the HTTP ingress for everything
   else; and why. `docs/deployment/README.md:927` says what a direct server sees
   when the caller writes the header. T-212 gains a dated amendment (or a new
   entry) for the spoofed direction; today T-212 covers only the collapse.
3. **#686's body** is corrected: the default reads the header too.

**Test.** In `crates/axiam-api-rest/tests/rate_limit_keying_test.rs`, two cases:
with `TRUSTED_PROXIES` empty and native TLS on, two requests from one peer whose
`X-Forwarded-For` differ share a bucket on `/auth/login`; with the peer in
`TRUSTED_PROXIES`, they do not.

---

## 3. R110-02 — #675's count reads the tenant table once per matching row

`6e7a0015d` added `OAuth2ClientRepository::count_confidential_with_grant`
(`crates/axiam-db/src/repository/oauth2_client.rs:1145-1180`), whose doc comment
says "The live-tenant subquery reads the `tenant` table once, not once per client
row". The statement is
`… WHERE grant_types CONTAINSANY $grants AND (… != 'none') AND tenant_id IN (SELECT VALUE meta::id(id) FROM tenant WHERE deleted_at = NONE)`,
twice (the client count and the tenant count). That is the inline-subquery shape
R110W1-01 measured and removed from the certificate retention sweep (`b24e34a1`,
`LET $live`): the datastore evaluates it again for every row that reaches it. Here
those are the rows that pass the first two conditions, the confidential device
clients.

**Probe** (`crates/axiam-db/tests/zz_probe_r110_count.rs`, in-memory engine, run
and deleted): 300 live tenants with 10 confidential device clients each (3 000 rows): the shipped statement answered `(3000, 300)` in **55.7 s**; the same count with the live tenants read once into `$live` answered `3000` in **0.245 s**, a factor of about 230.

The function runs once per process at boot, on its own task, under
`SCAN_TIMEOUT = 5 s` (`crates/axiam-server/src/device_grant_scan.rs:35`). So in the
deployments with the most clients to warn about, the warning is replaced by "timed
out", and the warning was the whole point of #675. On a remote datastore,
`tokio::time::timeout` drops the client's future, not the server's query. Every
replica then runs this query at every boot: a rolling restart of three replicas puts
three of these full-table loops on the production datastore at once. It does not
fail closed or open, and nothing is decided on it. It is **Low** rather than
Informational for two reasons. The cost is measured, it recurs and it lands on the
shared datastore. And it defeats the one purpose of the commit, which no review had
read (R110W1-01, the same shape every tick, was Medium).

**Fix:** `LET $live = (SELECT VALUE meta::id(id) FROM tenant WHERE deleted_at = NONE);`,
then `tenant_id IN $live` in both statements (result indices move by one), and
correct the comment.
**Test:** `oauth2_client_confidential_grant_test.rs`: 201 live tenants, one
confidential device client in one of them, and 2 000 confidential device clients
of a tombstoned tenant, which reach the subquery and must not be counted. The answer
is `(1, 1)` within 5 s. It fails on the current statement: about 2 000 × 202
evaluations, the scale the probe measured at 56 s.

---

## 4. R110-03 and R110-04

**R110-03 — the e2e filter does not follow the decision.**
`.github/workflows/radius-e2e.yml` runs the D4 test when the route, the gate, the
two models or the recipe change (`:39-61`). The decision's answer also rests on the
following, and a change to any of them runs no RADIUS end-to-end:

* `axiam-pki/src/mtls.rs` — `authenticate_der`, run for the caller and for the
  device on every decision;
* `axiam-api-rest/src/extractors/cert_auth.rs` — the certificate on the connection;
* `axiam-api-rest/src/handlers/auth.rs` — `device_auth`, the token FreeRADIUS
  presents;
* `axiam-db/src/repository/network.rs` — `list_site`, `list_stored`;
* `axiam-api-rest/src/handlers/network.rs`;
* `axiam-authz/src/engine.rs` — deny-override, which is what quarantine is.

#697 (R110W5-09) lists the D3 gaps; this extends it. The fix is the six globs; no
test.

**R110-04 — the orphan claim's unguarded window (merge `7292eaf56`).**

1. `purge_orphan_unit` calls `begin_orphan_purge` (`cleanup.rs:612`) and only then
   builds its `PurgeClaim`.
2. `begin_orphan_purge` (`tenant.rs:570-605`) first `CREATE`s the marker, a
   tombstoned tenant row with `purge_claimed_at = now`. It then reads
   `has_purgeable_rows`, one `LIMIT 1` per tenant-scoped table, and drops the marker
   when nothing is left: a scan that predates another replica's finished purge.
3. The unit runs under `AuditedWork`, which the teardown's join aborts at its bound.
   An abort inside that read drops a future that holds no guard, so the marker stays
   claimed.
4. `claim_purge` skips it until `TENANT_PURGE_LEASE` (one hour, `cleanup.rs:237`)
   runs out, and then `purge_tombstoned_unit` takes it over.

That is a one-hour delay, no worse than R110W4-01. For a **stale** scan there is
one more effect: the marker it leaves names an id that is already purged and
recorded. The takeover purges nothing, removes the marker, and writes a second
`tenants.purged` (`orphan: true`, zero counts) for that id to the append-only log.
That contradicts R101W1-09 (a)'s "recorded once", which T-472 and the module doc
repeat. The window is the time `has_purgeable_rows` takes, at a stop, on a replica
whose orphan scan is stale. Informational.

**Fix:** move the guard to the marker's creation. Either `begin_orphan_purge`
returns a value the unit wraps at once, with `claim_orphan_purge` called by the unit
itself; or the stale-scan check runs before the `CREATE`, a read that predicts and
a re-check under the claim as today. The latter narrows the window without closing
it. Alternatively, make the tombstoned takeover of a marker record nothing when its
report removed nothing and `orphan` is true.
**Test:** `cleanup_task.rs`, using the step hook W4 added: hold a unit inside
`has_purgeable_rows` across a stop and abort it. The next start's tombstoned sweep
purges the marker at once (no lease wait), and `tenants.purged` exists once for
the id.

---

## 5. R110-05 — text the merged tree contradicts

* **(a)** The schema description of `RadiusServiceType`
  (`crates/axiam-core/src/models/radius_reply.rs:250-253`, and so
  `sdks/openapi.json`) says "the administrative values are refused with a 400". The
  code answers `403 authorization_denied` naming `network:grant_admin` (H4 before the
  repository's validation; R110W6-02). Contract §36.3 rule 5, as corrected in 1.62,
  says `403` and points to #700 for answering `400` instead. W7.1 recorded the
  disagreement "for W8.2". The spec contradicts the contract the SDKs vendor; #700
  decides which changes.
* **(b)** `docs/deployment/README.md:927`, "Direct, no proxy | *(absent)* →
  `peer_addr()`" — see R110-01.
* **(c)** ilpanich/axiam#686's body says the defect needs `TRUSTED_HOPS ≥ 1`; at the
  default `0` the caller's header is read as well (R110-01).
* **(d)** T-481 says "Segment, profile and cap writes are the exception: each is
  conditional on the versions the caller read, inside the write's transaction."
  Since `9dff2aa97` and `122b9ea92` the transactions also re-read whether the
  segment has a profile. What they re-check is the row, though, not the writer's
  rights: a `network:grant` withdrawn between the gate and the commit is the same
  one-request window as T-481's other writes. W8.3: one sentence.
* **(e)** `crates/axiam-api-rest/tests/network_gate_enumeration_test.rs:124-128`
  exempts `("crates/axiam-server/src/cleanup.rs", "prepare")`, the function name
  the W6 merge gave W4's erasure step. It exempts every function of that name in the
  file, so a future `prepare` that writes an assignment passes the scan unread
  (T-480's name-matching residual). Name the impl (`ErasureUnit::prepare`) in the
  scan, or pin the exempt function's body by a substring.

---

## 6. The merges and the cross-wave invariants — verified

* **W1 #622 × W4 #655 (`7292eaf56`).** The stages run as follows.
  * **The tombstoned path.** `purge_tombstoned_unit` claims the tenant and builds
    its `PurgeClaim` at once. It runs `purge_tombstoned_rows` under
    `until_stopped`. For a row that is an orphan marker (`metadata.orphan_purge`,
    `tenant.rs:350-366`) that is the `Orphan` scope (audit trail kept,
    `report.orphan = true`). The unit then re-checks `stopping()`. Only then does it
    call `remove_purged_tenant`, the point of no return (`DELETE … RETURN BEFORE`,
    `true` only for the call that removed the row), and it records only on its own
    `Ok`.
  * **Every other exit releases.** The awaited `release()` handles the stop, a
    failure, and a removal that failed for any reason but `NotFound`. A cut drops
    the guard, and the drop spawns the release (R110W4-01's runtime caveat filed,
    #687).
  * **The orphan path.** `purge_orphan_unit` is the same after
    `begin_orphan_purge` (R110-04 is the window before its guard). Two differences:
    a failed rows step drops the marker inside the repository and the unit
    `settle()`s, because the next scan finds the id again; and a marker released at
    the stop is a tombstoned, unclaimed row that the next tick's tombstoned sweep
    claims immediately (`purge_claimed_at = NONE` matches `claim_purge`).
  * **The record.** `record_tenant_purged` writes `orphan || report.orphan`, so a
    taken-over marker is recorded as the orphan it is.
  * **The table lists.** The orphan scan and `has_purgeable_rows` read the same
    `TENANT_PURGE_ORDER` with the same `purgeable()` filter. W6's three tables are
    in it (`tenant_purge.rs:457-459`), so a network row neither hides an orphan nor
    survives a purge.
  * **Readers that skip the marker.** It is out of `certificate_retention` (W1.4,
    live tenants only) and out of #675's count (`deleted_at = NONE`).
* **Limiters (`45243b94d`, `09350bd2f`).**
  * **Backstops.** Both factors are kept, each in-process and per replica:
    `FEDERATION_FLOW_BACKSTOP_FACTOR` for W2's five principal-keyed routes and
    `NETWORK_DECIDE_BACKSTOP_FACTOR` for the decision route, beside
    `CIBA_LIST_BACKSTOP_FACTOR`.
  * **Network write buckets.** The seven `network_*` write buckets are distinct and
    pass W2.2's name test (run at the merge). The reads are unlimited, as every
    admin read in `server.rs` is.
  * **The decision route's spend order.**
    1. `CertificateBoundServiceAccount` (the token is verified and bound to the
       certificate on this connection) is extracted before the body, so a
       wrong-kind or unbound caller is `401` before anything is read.
    2. The handler spends `network_decide:{tenant}:{sub}` (`admit`), then
       `certificate_bound_caller`, then the body's reads.
    3. A malformed body is a `400` from the JSON extractor without a spend.
  * **Bucket retention.** The decision bucket is written by the REST shared counter
    (`check_at`, `DEFAULT_WINDOW_SECS`), which W3.4's derivation of
    `RATE_LIMIT_BUCKET_LONGEST_WINDOW_SECS` already covers (`cleanup.rs:247-265`).
  * **Validation.** `network_admin_per_min` and `network_decide_per_min` are
    validated `≥ 1` (`config/rate_limit.rs:1189-1194`), so no governor is built at
    zero.
  * **In-process maps.** The decision route's per-caller map holds authenticated
    callers only. Its defect window map is pruned on every insert
    (`network_decide_guard.rs:87`).
* **Migrations.** The order is 98, 99, 100 (`schema.rs:506-523`).
  * v99: `serial` plus two `UNIQUE (issuer, serial)` indexes. Legacy rows are
    `NONE`, which the probe test `v99_applies_over_rows_that_already_share_a_serial`
    covers.
  * v100: three new tables, nothing else.
  * Both are `IF NOT EXISTS` only, each with a scope test forbidding
    `UPDATE`/`REMOVE`/`DELETE`/`OVERWRITE`, and the newest-version assertion is 100.
  * R110W6-07 (a datastore that recorded v100 without v99) concerns an unreleased
    branch build only; filed (#704).
* **W3.1 × W6.4.** Device-grant tokens are user tokens carrying `client_id`; for a
  DPoP or mTLS client they are `cnf`-bound. The decision route refuses every
  `sub_kind` but `ServiceAccount` (`network_decide.rs:270-320`), and a DPoP-only
  binding. An SA token bound to a certificate (from `/auth/device`, or the `sa_`
  client-credentials path) is then re-resolved: `authenticate_der(caller.der)` must
  answer this tenant and this `sub`, and the account must be `Active`. A token bound
  to a self-signed `self_signed_tls_client_auth` certificate therefore fails there.
  Tenant deletion revokes the tenant's certificates (`tenants.rs:760-775`), so a
  deleted tenant's FreeRADIUS stops at its next decision.
* **W1.9 × W6.5 (the stash).** FreeRADIUS 3.2.8's `cbtls_verify` returns at
  `if (!my_ok) { … return my_ok; }` (`tls.c:3196-3206`) before the depth-0 block
  that runs `verify { client = … }` (`:3470-3519`). That block in turn requires the
  issuer check, the CN check and OCSP to have passed. So the hook writes
  `$DIR/<serial>` only for a certificate that chains to `ca_file`, passes the CRL and
  is not revoked. An attacker's self-signed certificate carrying a victim's serial
  never reaches it. With one issuer in `ca_file` (`freeradius.md:130-147`) and
  v99's per-issuer uniqueness, a serial names one certificate. Legacy certificates
  from 1.0.x share a serial only when they share a key, and so a holder. The TLS
  session cache is off (`raddb/eap`), so a resumed session cannot meet a missing
  stash.
* **`error.rs` (`09350bd2f`).** `unprocessable_entity()` sets `reason_code: None`.
  The member is `skip_serializing_if = "Option::is_none"` (`error.rs:43-49`), so
  W3.2's `422` body is byte-for-byte what W3 shipped. The unit test
  `a_reason_code_is_one_member_added_and_absent_otherwise` pins the absence.
* **W5 × W1 (`a6c6340fa`).** The guide's Ed25519 bullet is W1's (#651), and the
  re-encoding recipe has gone. That was text only.

---

## 7. The commits no review read

* **`6e7a0015d` (#675).**
  * **Counts only.** One `warn!` with two integers and fixed text; no id, name or
    tenant. The query returns aggregates only.
  * **Never in the way of boot.** It runs on its own task under a deadline, behind
    a process-wide `AtomicBool`. An error or a timeout is one `warn!`.
  * **The four mock repositories** gained `unimplemented!()`, as their neighbours
    have; that is test code.
  * **Finding:** R110-02.
* **`21ab64fbc` (R110W6-01).** H6 is now compared at every §5.3 door that widens
  the writer's own placement:
  * `role_assign` refuses a join allow when the edge reaches the writer, directly
    or through a group (`edge_reaches_writer`);
  * `role_unassign` refuses releasing a deny on the writer;
  * `role_delete` refuses a deny role the writer holds;
  * `permission_grant` refuses a join allow to a role the writer holds;
  * `permission_revoke` refuses a deny from a role the writer holds.

  Narrowing stays allowed: taking a deny, or giving up an allow. The rule is
  subject-agnostic. The one remaining way for a machine to place a key it holds
  through *another* account is to issue a new certificate and bind it there. That
  needs `certificates:generate`, `certificates:bind` and `network:grant` at that
  account's joins: the enrolment delegation itself, which no H6 can tell apart from
  enrolment. Moving the writer's **own** certificate is impossible
  (`idx_cert_bound_unique`, `schema.rs:929`; no unbind route).
* **`9dff2aa97` (R110W6-03).** A segment replace that moves `vlan_id`, `rank` or
  `enabled` on a profiled segment asks `H2:placement`, plus `H5:placement` on a
  quarantine segment, then H6.
  * A replace cleared without the grant carries `freeze_profiled_placement`. Its
    transaction re-reads the profile and the row at the expected version, and
    `THROW`s `PLACEMENT_RACED` (`409 stale_version`) for any move on a profiled row
    (`network.rs:399-414`).
  * The profile writer bumps `profile_epoch` on the same segment row, so the two
    writes cannot both commit.
  * A request naming a future `expected_version` is compared against that future
    row. It still cannot move a profiled placement without the grant.
* **`122b9ea92` (delete gate).** Deleting a profiled segment or a profile asks the
  same placing right, then H6. The delete transaction re-reads the profile under
  the frozen clearance (`network.rs:460-470`). The profile delete is conditional on
  the profile's version; it narrows, and it now needs the grant.
* **`f15f67434` (`reason_code`).** The sub-code is chosen from a closed enum, and
  the message the client sees is the one it saw before. That the code is derived by
  matching message text is #708.
* **`22fcc5098`, `b3a035413`.** The coverage matrix and the rule 6 text. Nothing
  executable.
* **Contract `5c012d741`, `d76c5a80b`, `d25413506`, as security text.** Each claim
  was checked against the code.
  * §14.1: a public client sends no credential and is refused if it sends one; a
    confidential client sends its credential at both endpoints, in the form body
    (never `Authorization: Basic`, §12.1 rule 3).
  * §14.1 rule 4: `unauthorized_client` is answered only **after** client
    authentication (`token_device.rs:118-121`), so it is no client-existence oracle.
  * §14.2 rule 8: proof or certificate on every poll for a bound client.
  * §36.11: the caller rules, "spent before anything is read for the caller", the
    closed body, and "no reason" — each matches `network_decide.rs` as read in §6.
  * §36.11 rule 5 now states R110W6-09's cross-tenant timing signal as a residual,
    rather than claiming "the same reads".
  * §36.3 rule 5 says `403` for the administrative values; the spec text disagrees
    (R110-05 (a)).
  * Q1 (no session or adopted credential on `/oauth2/*`) can only narrow what an
    SDK sends. The server-side half is #710.

  No new contradiction beyond R110-05 (a). No contract question arises from this
  review.
* **`89e488e3e` (version).**
  * Version strings, image tags, `info.version` and the registry's digest; no
    behaviour.
  * `k8s/*/deployment.yml` keep the `OWNER` placeholder and a fixed tag
    (no `latest`).
  * Its `Co-Authored-By` trailer names another model than the rules' verbatim line
    (process, not security; recorded for the maintainer in the report).
* **`f922935a0` (rustls).**
  * `Cargo.lock`, `examples/b3-mesh-delegation-grpc/Cargo.lock` and
    `tools/surreal-race-probe/Cargo.lock` all resolve `rustls 0.23.46`;
    `crates/axiam-opaque-wasm/Cargo.lock` has no rustls.
  * `yoke-derive` 0.8.3 (yanked) is now 0.8.4.
  * `tempfile` now resolves `getrandom 0.3.4`, which was already in the lock.
  * The four advisories (RUSTSEC-2026-0346 … -0349) are all closed by ≥ 0.23.46;
    -0346 (a `Debug` impl printing secrets) has no `Debug` formatting of a rustls
    connection in AXIAM's code to reach.
  * Verified by running both tools (§11).

---

## 8. Residuals carried forward — does 1.1.0 still match the model?

| Entry | Status | Substance on the merged tree |
|---|---|---|
| T-481 (gate read vs write) | Open, Low | Holds. `check_at_write_time` is the engine's uncached evaluation (`network_gate.rs:120-147`), so the window is one request's. The segment and profile transactions now re-check the row's placement (§7). R110-05 (d) is a one-sentence text change. |
| T-483 (org super-admin) | Open, Low | Holds as written. The seeder grants `SEEDED_SUPER_ADMIN_NETWORK_ACTIONS` to the organization scope's super-admin too, and `network:decide` is of no use to it (§36.11 rule 1). |
| T-484 (no success row) | Open, Low | Holds: §5.3 writes still leave only the request row and the edge. |
| T-462 (port kept until re-authentication) | Open, Medium | Holds. The decision is uncached per request (two `authenticate_der`, one `check_access_batch`). What remains is the stated residual, `Session-Timeout` without CoA, plus the decision cache's TTL on other replicas. |
| T-486 (AXIAM down, or TLS ended by a proxy) | Open, Medium | Holds (fail closed, e2e). R110-01 adds what the entry's "operator carries" list should say about exposing the native listener. |
| T-450 (MD5 attribute hiding) | Open, High | Unchanged by 1.1.0, and correctly so: D4 changes nothing on the RADIUS wire. RadSec remains the guide's answer (R110W5-05 / #693 says the guide's RadSec block does not start, which bears on this entry's mitigation advice). |
| T-457, T-468 (oracle; caller) | Mitigated | Hold, with §36.11 rule 5's residuals. The tests named exist and passed at W8.1. |
| T-482 (self-placement) | Mitigated | Holds after `21ab64fbc` (§7). |
| T-444, T-472 | Mitigated | Substance holds after the purge merge (§6). The text is stale (an orphan purge now has a point of no return; "#655 not fixed"); it is W8.3's (R110W4-06, §13.7). R110-04 qualifies "recorded once". |
| T-212 | Mitigated | Holds for what it states (the collapse direction). R110-01 is the other direction, which no entry states. |
| The other Open entries (T-9, T-18, T-94, T-123, T-124, T-133, T-134, T-135, T-146, T-148, T-161, T-180, T-216, T-306, T-380, T-405, T-445) | Open | None was touched by the release diff, and none was made worse by it. |

---

## 9. The release as a whole

* **Authentication boundary of the new routes.**
  * **The management routes** (seven writes, five reads) take the tenant from the
    token. They are in `ROUTE_PERMISSION_MAP` and are human-only (`network` in
    `HUMAN_ONLY_FAMILIES`).
  * **The decision route** is that family's one named machine exception
    (`CERTIFICATE_BOUND_MACHINE_ROUTES`, pinned against the route map by
    `m2m_management_test`).
  * **No other route was added.** The registry is 202 operations in 29 namespaces,
    the decision route excluded by name; `gen-management-registry.py --check` and
    `check-spec-digest.py` both exit 0.
* **Authorization.**
  * **The engine** compares actions exactly; there are no wildcard actions
    (`engine.rs:213-215`).
  * **The gate refuses** scoped network grants, global network roles, network roles
    on groups, and network denies with `inherit: false`. No resource id can be
    chosen by a caller, so the deterministic v5 ids of the `/network` nodes cannot
    be squatted. A generic resource can be neither created under nor moved into the
    reserved subtree.
  * **Quarantine is a deny.** Under deny-override it beats any allow at or below
    its node. H6 keeps the quarantined credential from removing it (§7).
* **Tenant isolation.**
  * The decision resolves the presented certificate globally, then refuses another
    tenant's with the unknown certificate's reason, and the audit row carries the
    fingerprint alone.
  * Every network table and every reserved node is tenant-keyed, and all three
    tables are in the purge order.
  * The marker row carries the nil organization and no `has_tenant` edge.
* **Audit completeness.**
  * Segment, profile and cap writes, and every gate refusal, write their own rows
    with before and after values.
  * Each decision writes one row (`allowed`, `denied` or `refused`), and a
    defective profile one per hour.
  * The §5.3 successes are T-484.
  * No new action falls in the reserved `tenants.`/`gdpr.` namespaces, and no
    server reader of a new action exists that a tenant's AMQP producer could feed.
* **Rate limiting end to end.** Every new write route has its own bucket, and the
  decision route has its per-caller bucket plus a per-address backstop. Gaps:
  R110-01 (the native listener) and the known #673 and #686.
* **Secrets in logs.** No log line added in the range prints a token, secret, key
  or certificate. Scanned: every added `tracing::` macro with its arguments. Hits:
  #675's fixed text and a CA id. The recipe keeps the token in FreeRADIUS's memory
  and strips `REST-HTTP-Body` from the reply.
* **Supply chain.** §11. The SDK repositories' own supply chain is the conformance
  review's (C162-01 … -03 fixed in W7.14).

---

## 10. Issue bodies

All for milestone **`1.1.x`** (#23).

### R110-01 (Low) — the D4 listener keys every per-address limiter on a caller-written `X-Forwarded-For`

**Where:** `crates/axiam-api-rest/src/extractors/rate_limit.rs:131-157`
(`select_rate_limit_ip`); `crates/axiam-server/src/boot.rs:3199` (the one native
listener); `docs/pki/freeradius.md:521-533`; `docs/deployment/README.md:927`;
`crates/axiam-api-rest/src/server.rs:1923-1934`. Threats: T-212 (the other
direction), T-468, T-486. Related: #686, #673. From the 1.1.0 combined F4 review
(`claude_dev/security-review-release-1.1.0-2026-10-16.md` §2).

D4 requires FreeRADIUS's mTLS to end at AXIAM's own listener, directly or through
an L4 pass-through. That listener serves every route, and with no appending proxy in
front the rate limiters take the rightmost `X-Forwarded-For` entry, which the caller
writes, also at the default `TRUSTED_HOPS = 0`. A caller who reaches the listener
picks a fresh bucket per request on `/auth/login`, `/auth/device`, the decision
route's backstop, `/oauth2/token` and every other per-address route, and grows the
unswept governor maps (#673). Per-account lockout, the crypto gate and the
decision's per-caller bucket are unaffected.

**Fix:** `AXIAM__RATE_LIMIT__TRUSTED_PROXIES` (CIDRs). Honour `X-Forwarded-For` only
from those peers and key everything else on the peer; with the list empty, keep
today's behaviour and log one `WARN` at boot when native TLS is on. Add to
`freeradius.md` §5: expose the native listener to the FreeRADIUS servers only, and
keep the HTTP ingress for everything else. Correct the guide's "Direct, no proxy"
row, amend T-212 (dated), and correct #686's body (the default reads the header
too).

**Test:** `rate_limit_keying_test.rs`: with `TRUSTED_PROXIES` empty, two `/auth/login`
requests from one peer with different `X-Forwarded-For` share a bucket; with the
peer listed, they do not.

### R110-02 (Low) — #675's boot count reads the tenant table once per matching client

**Where:** `crates/axiam-db/src/repository/oauth2_client.rs:1145-1180`
(`count_confidential_with_grant`); `crates/axiam-server/src/device_grant_scan.rs:35`.
From `6e7a0015d`. Related: #675, R110W1-01 (`b24e34a1`).

Both statements filter `tenant_id IN (SELECT VALUE meta::id(id) FROM tenant WHERE
deleted_at = NONE)` inline. The datastore re-evaluates that subquery for every
confidential device client, though the comment says it reads the table once. Probe
(review §3): 3 000 confidential device clients in 300 live tenants took 55.7 s as shipped and 0.245 s with the subquery hoisted. Past the 5 s `SCAN_TIMEOUT`, the boot warning
#675 added becomes "timed out" with no count, in the deployments with the most
clients to warn about, and the query keeps running in a remote datastore, on every
replica's boot.

**Fix:** `LET $live = (…);` then `tenant_id IN $live` in both statements; correct the
comment.
**Test:** `oauth2_client_confidential_grant_test.rs`: 201 live tenants, one
confidential device client in one of them, and 2 000 confidential device clients of
a tombstoned tenant. The count is `(1, 1)` within 5 s.

### R110-03 (Informational) — the RADIUS e2e filter misses what the decision rests on

**Where:** `.github/workflows/radius-e2e.yml:39-61`. Extends #697 (R110W5-09).

Add `crates/axiam-pki/src/mtls.rs`, `crates/axiam-api-rest/src/extractors/cert_auth.rs`,
`crates/axiam-api-rest/src/handlers/auth.rs`, `crates/axiam-db/src/repository/network.rs`,
`crates/axiam-api-rest/src/handlers/network.rs` and `crates/axiam-authz/src/engine.rs`.
Each is on the path of every D4 decision: `authenticate_der` for the caller and the
device, the device login, the site's segments and profiles, and deny-override, which
is what quarantine is. A change to any of them runs no RADIUS end-to-end today.

### R110-04 (Informational) — an orphan purge cut before its guard holds the id for an hour, or records it twice

**Where:** `crates/axiam-db/src/repository/tenant.rs:570-605` (`begin_orphan_purge`);
`crates/axiam-server/src/cleanup.rs:602-622` (`purge_orphan_unit`), `:237`
(`TENANT_PURGE_LEASE`). From the W1 × W4 merge `7292eaf56`. Threats: T-444, T-472.

The marker is `CREATE`d inside `begin_orphan_purge`, before the unit builds its
`PurgeClaim`. A teardown abort while `has_purgeable_rows` runs leaves the marker
claimed with no guard, so the id waits out the one-hour lease. If the scan was
stale (another replica had already purged and recorded the id), the
tombstoned-tenant sweep later purges the empty marker and writes a second
`tenants.purged` (`orphan: true`, zero counts) to the append-only log, against
R101W1-09 (a)'s "recorded once".

**Fix:** let the unit hold the guard from the `CREATE` (the unit calls
`claim_orphan_purge` and wraps it at once), or record nothing when a taken-over
marker's report removed nothing.
**Test:** `cleanup_task.rs`: hold a unit inside `has_purgeable_rows` across a stop
and abort it. The next start's sweep takes the marker at once, and `tenants.purged`
exists once for the id.

### R110-05 (Informational) — text the merged tree contradicts

**Where:** as listed.

* (a) `crates/axiam-core/src/models/radius_reply.rs:250-253` (and
  `sdks/openapi.json`): "the administrative values are refused with a 400". The code
  answers `403` naming `network:grant_admin`, as contract §36.3 rule 5 now says.
  Align with whatever #700 decides; until then the description should say `403`.
* (b) `docs/deployment/README.md:927`: the "Direct, no proxy" row holds only for a
  caller that sends no `X-Forwarded-For` (R110-01).
* (c) #686's body: the default `TRUSTED_HOPS = 0` reads the caller's header too.
* (d) T-481: the segment, profile and cap transactions re-check the row, not the
  writer's rights (W8.3).
* (e) `crates/axiam-api-rest/tests/network_gate_enumeration_test.rs:124-128` exempts
  every `fn prepare` in `cleanup.rs`. Narrow it to `ErasureUnit::prepare`, or pin
  the function's body.

---

## 11. Evidence

| What | Command | Result |
|---|---|---|
| Release head | `git pull --ff-only`; `git log -1` | `f922935a0`, up to date |
| Range | `git log --oneline 3d011573e..HEAD \| wc -l`; `--no-merges`; `--merges`; `git diff --stat` | 97 / 91 / 6; 246 files, +56 654 −5 919 |
| Signatures | `git cat-file -p <c> \| grep ^gpgsig` over the range | 97 of 97 carry `gpgsig` |
| Trailers | `git log --format='%(trailers:key=Co-Authored-By,valueonly)'` | one deviation: `89e488e3e` |
| Threat model integrity | Python over `Axiam.json` and the STRIDE tables | 487 entries, ids unique, `threatTop` 487; 454 / 23 / 10; STRIDE statuses = JSON |
| Remediation evidence | `python3 scripts/check-remediation-evidence.py` | exit 0 (37 verified) |
| Spec and registry | `python3 scripts/check-spec-digest.py`; `python3 scripts/gen-management-registry.py --check` | exit 0; exit 0 |
| Layering, config keys, coverage matrix, audit ignores, conflict markers, RADIUS vendors-nothing | `python3 scripts/check-{crate-layering,config-key-coverage,frontend-coverage,audit-ignore-sync,conflict-markers,radius-vendors-nothing}.py` | all exit 0 |
| Doc links | `bash scripts/check-doc-links.sh` | exit 0 (also after this file) |
| cargo-deny | `cargo-deny deny --all-features check -D advisory-not-detected` (0.20.2, as CI's action) | exit 0: advisories, bans, licenses, sources ok (duplicate-version warnings only) |
| cargo-audit | `cargo-audit audit --ignore` CI's six IDs (0.22.2; 1 329 advisories) | exit 0; 879 crates; 4 yank lookups answered `503` by the registry (cargo-deny's yank check passed) |
| rustls pins | `grep` the four lockfiles | 0.23.46 in three; none in `axiam-opaque-wasm` |
| FreeRADIUS hook order | `tls.c` at `release_3_2_8`, `cbtls_verify` | early `return my_ok` at `:3196-3206` before the depth-0 `verify client` block `:3470-3519` |
| Probe R110-02 | `cargo test -p axiam-db --test zz_probe_r110_count -- --nocapture` (temporary file, deleted) | exit 0; 3 000 clients / 300 tenants: 55.7 s as shipped, 0.245 s hoisted, same count |
| Purge merge, cross-wave | `cargo test -p axiam-db --test tenant_purge_test` | exit 0, 11 passed |
| #675 count test | `cargo test -p axiam-db --test oauth2_client_confidential_grant_test` | exit 0, 1 passed |

All cargo commands ran with `CARGO_INCREMENTAL=0`,
`CARGO_PROFILE_{DEV,TEST}_DEBUG=line-tables-only` and `RUSTFLAGS=-Dwarnings`; exit
codes are the tools', read from logs. `cargo clean` afterwards.

---

## 12. Invariants

* **Append-only audit.** Nothing in the range updates an audit row. R110-04 is the
  one way it can gain a redundant `tenants.purged`, never lose one.
* **Fail closed where it matters.**
  * The decision route answers `allow: false` on every failure, and the recipe
    rejects on everything but a well-formed allow.
  * The network write transactions refuse a placement move or a delete that raced a
    profile.
  * A tenant purge never removes its tenant row once stopping.
* **Default-deny with deny-override.** The engine is unchanged by the release. The
  network gate adds refusals and never an allow, and the clearance token makes a
  segment, profile or cap write without the gate a compile error.
* **Additive schema.** v99 and v100, with no backfill; the newest-version assertion
  is 100.
* **Contract.** 1.62 is consistent with the server except R110-05 (a). The
  registry is 202 / 29, and the spec and registry digests agree.
* **Threat model.** 487 entries (454 / 23 / 10), version 2.41.0 until W8.3 takes it
  to 2.42.0. R110-01 (T-212, T-486), R110-04 (T-472) and R110-05 (d) (T-481) are
  W8.3's text.
