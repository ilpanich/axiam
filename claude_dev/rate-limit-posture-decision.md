# Rate-limit posture — decision record (G7)

**Date:** 2026-07-26
**Task:** G7 of [`improvement-after-serious-benchmark.md`](improvement-after-serious-benchmark.md)
**Scope:** shipped rate-limit defaults, deployment presets, sizing docs, startup posture log
**Status:** implemented; **no shipped default changed**. One item needs
maintainer sign-off (§7.1) and one needs a laptop re-measurement (§7.2).

---

## 1. Decision, in one paragraph

**No shipped default was moved.** `RateLimitConfig::default()` and
`GrpcConfig::default()` are byte-for-byte what they were before this task.
Instead, the M2M/NAT'd-fleet sizing ships as an **opt-in deployment posture
preset** selected by a single environment variable,
`AXIAM__RATE_LIMIT__PROFILE` = `internet` (default) | `gateway` | `mesh`,
which moves the whole machine-traffic family — bucket-key mode, token,
introspect, revoke, REST authz, and the gRPC authz ceiling — coherently.
Human endpoints (`login`, `register`, `password_reset`, `mfa`) are excluded
**by construction**: the preset struct has no field for them, so no profile
can raise them, now or later. The default posture is a *no-op by
construction* (`RateLimitProfile::Internet::preset()` returns `None`), so
the internet-facing posture cannot drift as the presets evolve.

This is the safer of the two routes the spec offered, and it is the one the
evidence supports (§4 below produced a finding that argues *against* making
per-client keying the default at all).

---

## 2. Evidence

From benchmark run 3 (2026-07-25/26, `1.0.0-alpha19`, median-of-3;
[`benchmarks/PRIVATE_BENCH_ANALYSIS.md`](../benchmarks/PRIVATE_BENCH_ANALYSIS.md)
§3.7 and §5.3, [`benchmarks/PUBLIC_BENCH_ANALYSIS.md`](../benchmarks/PUBLIC_BENCH_ANALYSIS.md) §6):

| Observation | Number |
|---|---|
| Shipped defaults vs a 50-VU **single-source-IP** load | every limited endpoint flattened to ~0–14 req/s at ~100% `429` (client-credentials 0.9/s, introspection 0.4/s) |
| Unlimited paths in the same pass | unaffected — JWKS 27 700/s, userinfo 5 994/s |
| Same 2-core server, unthrottled | ~1 800 token issuances/s; ~740/s authz checks cache-off, ~2 300/s cache-on; ~2 200/s introspection; ~603/s gRPC authz; ~69 logins/s (Argon2id) |
| Shipped default caps a *client* at | 20 token req/min = 0.33/s |

Both facts hold simultaneously. The defaults are a **working anti-abuse
control** on a small internet-facing deployment and are **wrong for an
M2M/NAT'd fleet**, where dozens-to-thousands of distinct OAuth2 clients
share one egress IP and therefore one bucket. The maintainer confirmed the
latter reading (private §3.7, §5.3).

All numbers above are **laptop-class** (Docker containers pinned to
2 cores / 1 GiB, developer machine) and explicitly temporary. Nothing in
this task invented a number: every preset value is derived from that table
and the derivation is written next to the constant in
`crates/axiam-api-rest/src/config/rate_limit.rs` and in
[`docs/deployment/rate-limit-sizing.md`](../docs/deployment/rate-limit-sizing.md) §3.

---

## 3. Options considered

### Option A — move the raw defaults (token → `client_id` keying at ~600/min, etc.)

The spec's own proposal-to-assess. **Rejected.**

- It changes the security posture of *every existing deployment* on
  upgrade, silently, including the small internet-facing ones the current
  defaults were designed for. That inverts the safe direction of a default
  change.
- Its central mechanism — keying on `client_id` — is **not an anti-abuse
  control** (§4.1). Making it the default would replace a control that
  demonstrably stops a flood with one that an attacker bypasses by
  incrementing a string.
- It cannot be justified from the measurements: the run-3 posture pass
  measured that the defaults *work*. There is no evidence of a default that
  is too strict for the deployment it was designed for — only evidence of a
  default applied to a topology it was not designed for. That is a
  configuration problem, and configuration problems are solved with
  configuration.

### Option B — documented opt-in posture preset (**chosen**)

- Zero behaviour change on upgrade; the change is visible, deliberate, and
  logged at boot.
- One env var sets the family coherently, so an operator cannot fix REST
  token limits and leave gRPC authz at 100/s/IP — the exact trap that makes
  hand-tuning fail.
- The per-client keying caveat can be stated *at the point of choosing it*,
  which is where it will actually be read.
- Cost: an operator who does not read the docs stays throttled. Mitigated
  by the startup log line (§5.3), the deployment-guide pointer, and public
  §6 already recommending the M2M values.

### Option C — docs only, no preset

Rejected: public §6's advice is a list of six independent knobs. Applying
it by hand is error-prone in precisely the coherence dimension that matters
(key mode without the matching per-client ceilings is worse than either
alone — it splits the bucket *and* keeps the small number).

---

## 4. Abuse-vector analysis

### 4.1 `client_id` keying is a fairness control, not an abuse control

The `client_id` used for bucket derivation is parsed from the
**unauthenticated** form body (`client_secret_post`, RFC 6749 §2.3.1) by
`extractors::rate_limit::extract_form_client_id`, **before** any credential
is verified (`axiam_oauth2::token` verifies the secret later, in the
handler). Therefore:

- Under `key=client_id` or `ip_client_id`, an attacker who rotates the
  `client_id` string gets a **fresh bucket per value** and is effectively
  unlimited on `/oauth2/token`, `/oauth2/revoke`, `/oauth2/introspect`.
- This is a property of the **D8 key modes as shipped**, independent of this
  task. The presets do not create it; they make it the active posture — which
  is the decisive reason they are opt-in, logged, and documented with the
  caveat in the operator's face
  ([sizing doc §5.1](../docs/deployment/rate-limit-sizing.md)).
- Residual protection under those modes: the client lookup fails fast
  (secret comparison is a cheap constant-time hash compare, not Argon2), so
  the marginal cost of a rejected request is ~one DB lookup — survivable at
  the measured envelope, but it is DB load, not free. The real control moves
  to the edge (WAF / API gateway / mTLS / IP allow-list), which is what a
  `gateway`/`mesh` deployment has by definition.

**Consequence for the default:** keeping `key=ip` as the shipped default is
not conservatism, it is correctness. The IP-keyed bucket is the only one of
the three modes an attacker cannot mint at will.

### 4.2 Bucket-keyspace growth

A rotating `client_id` also grows the key space of both limiter layers: the
per-replica in-memory `Governor` map and the shared `rate_limit_bucket`
SurrealDB table. Neither is unbounded in practice (fixed 60 s windows
expire; the cleanup task sweeps), but a sustained rotation flood is a
resource-consumption vector on top of the bypass. Documented in sizing §5.2.
**Not fixed here** — a proper fix (only key on `client_id`s that resolve to
a real client, or a bounded keyspace with an IP-keyed overflow bucket) is a
design change to D8 and is listed for the maintainer in §7.3.

### 4.3 No-`client_id` requests fall back to the IP key

`ClientAwareKeyExtractor` falls back to the IP key when no `client_id` is
parseable — fail-safe (limiting is never disabled), but under a preset that
fallback is metered at the *preset's larger number* (e.g. 600/min instead of
20/min per IP). An anonymous/malformed token flood therefore gets 30× more
budget under `gateway` than under the defaults. Acceptable for the intended
topology (edge-protected), documented in sizing §5.4, and another reason not
to make it the default.

### 4.4 The gRPC limiter cannot key per client at all

`AXIAM__GRPC__KEY` is reserved and a no-op: the rate-limit `tower::Layer` is
`Server::builder()`-wide and runs before tonic resolves per-RPC claims, so
there is no client identity at the keying point. Behind a shared ingress IP,
`AXIAM__GRPC__GRPC_AUTHZ_PER_SEC` is a **fleet-wide** ceiling. The presets
raise it (1 000 / 5 000 per sec) precisely because a per-IP ceiling under
NAT is a fleet ceiling — but this means the gRPC authz surface has *no*
per-client fairness in any posture. Documented (sizing §5.3); the fix is the
future per-RPC identity-aware interceptor already anticipated in
`GrpcRateLimitKeyMode`'s doc comment.

### 4.5 Human endpoints — why they are non-negotiable

`login`/`register`/`password_reset`/`mfa` gate password guessing, OTP
guessing, account enumeration and (for login) an Argon2id CPU cost of
~1/69th of a 2-core server per request. None of those economics change
because the deployment is a service mesh, and none of those endpoints has an
OAuth2 client identity to key on (structural — see `RateLimitKeyMode` docs).
They are absent from `MachineLimitPreset` entirely, and
`no_profile_touches_human_endpoints` is a unit test, so a future preset
cannot regress this by accident.

### 4.6 What the preset values still stop

Under `gateway` (token 600/min/client = 10/s):

- A single compromised client credential is capped at ~0.55% of the measured
  1 800/s server ceiling — ~180 distinct credentials running flat out would
  be needed to saturate the server, so one leaked secret is not a DoS engine
  and its abuse is visibly rate-shaped in audit logs.
- Introspection at 6 000/min still bounds token-probing to a rate where the
  opaque-token search space is untouchable, while covering a resource server
  that introspects once per request.
- `authz_check` at 6 000/min/client sits an order of magnitude below the
  measured ~44 400/min whole-server cache-off ceiling.

Under `mesh`, the authz ceiling (60 000/min = 1 000/s) is **above** the
measured 740/s cache-off whole-server ceiling. Stated honestly in the docs:
on that hardware it is a runaway-retry-loop guard, not an abuse control. It
is an appropriate value only for a deployment with no internet exposure on
the machine endpoints, which is exactly what `mesh` names.

---

## 5. What was implemented

### 5.1 Config (`crates/axiam-api-rest/src/config/rate_limit.rs`)

- `RateLimitProfile { Internet (default), Gateway, Mesh }` +
  `MachineLimitPreset` (the preset's field set — machine endpoints only).
- `RateLimitConfig::profile` (`AXIAM__RATE_LIMIT__PROFILE`).
- `apply_profile(is_set)` / `apply_profile_from_env()` — applies the preset
  to every field the operator did **not** pin with an explicit
  `AXIAM__RATE_LIMIT__*` env var, and returns a `RateLimitPosture`
  (profile, whether a preset was applied, the list of overriding env var
  names, and the gRPC ceiling to hand to the gRPC config).
  **Precedence: explicit env var > preset > shipped default.**
- `RateLimitKeyMode::as_str()` / `RateLimitProfile::as_str()` for logging.

Preset values (per bucket), with derivations recorded next to the constants:

| | `internet` (shipped) | `gateway` | `mesh` |
|---|---|---|---|
| `KEY` | `ip` | `client_id` | `client_id` |
| `TOKEN_PER_MIN` | 20 | 600 | 6 000 |
| `INTROSPECT_PER_MIN` | 10 | 6 000 | 60 000 |
| `REVOKE_PER_MIN` | 10 | 600 | 6 000 |
| `AUTHZ_CHECK_PER_MIN` | 300 | 6 000 | 60 000 |
| `GRPC__GRPC_AUTHZ_PER_SEC` | 100 | 1 000 | 5 000 |
| login / register / reset / MFA | 10 / 5 / 3 / 5 | **unchanged** | **unchanged** |

### 5.2 gRPC (`crates/axiam-api-grpc/src/config.rs`)

`GrpcConfig::apply_rate_limit_preset[_from_env]()` — applies the ceiling the
REST-side preset table specifies, unless `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC`
is pinned. The **numbers are not duplicated here**: the gRPC crate does not
depend on the REST crate, so the composition root passes the value. This
keeps one source of truth and one operator-facing env var for the whole
family.

### 5.3 Startup posture log (`crates/axiam-server/src/main.rs`)

One `tracing::info!` line — the existing structured-JSON idiom, `info`
level, alongside the other boot lines — emitted after the posture is
resolved and validated, before the listeners bind:

```
"Rate-limit posture active"
  profile, preset_applied, key_mode,
  login_per_min, register_per_min, password_reset_per_min, mfa_per_min,
  token_per_min, introspect_per_min, revoke_per_min, authz_check_per_min,
  grpc_authz_per_sec, operator_overrides
```

Every field is configuration; no secrets. `operator_overrides` lists the env
var **names** that beat the preset (or `none`), so an operator seeing a value
that disagrees with the profile immediately knows why.

### 5.4 Docs

- **New:** [`docs/deployment/rate-limit-sizing.md`](../docs/deployment/rate-limit-sizing.md)
  — the "sizing your limits" page: which posture you are in, the measured
  envelope (labelled laptop-class and temporary), the preset table with
  derivations, how to size by hand, the six security caveats from §4, and
  how to read the startup log.
- `docs/deployment/README.md` — `AXIAM__RATE_LIMIT__PROFILE` row + a pointer
  to the sizing page from the rate-limiting section.
- `docs/README.md` — index entry.

### 5.5 Single-source-of-truth check (pragmatic, not a build-time include)

The sizing page's posture table is delimited by
`<!-- rate-limit-posture-table:begin/end -->` and parsed by unit tests that
run in the existing CI test job (`cargo test --workspace`):

- `axiam-api-rest`: `documented_defaults_match_shipped_config` (doc vs
  `RateLimitConfig::default()`), `documented_presets_match_applied_profiles`
  (doc vs what `apply_profile` actually produces, including the gRPC column
  and the human-endpoint columns), and
  `public_benchmark_doc_shipped_defaults_match_code` — which also diffs the
  **"Shipped default" column of `benchmarks/PUBLIC_BENCH_ANALYSIS.md` §6**
  against the code. That file is owned by the benchmark harness, so a
  *missing* file is skipped; a *wrong* value fails.
- `axiam-api-grpc`: `documented_grpc_default_matches_shipped_config`
  (doc vs `GrpcConfig::default()` — each crate checks its own half).

Plus behavioural tests: `internet_profile_is_a_no_op`,
`explicit_env_vars_win_over_the_preset`,
`no_profile_touches_human_endpoints`,
`presets_stay_below_the_measured_server_ceiling`,
`profile_deserializes_from_documented_env_values`,
`rate_limit_preset_applies_only_when_env_unset`.

### 5.6 Known limitation (documented, not fixed)

"Explicitly set" is detected as *an `AXIAM__…` env var is present*. A value
coming from the optional `config/default.toml` file source looks unset to
the preset and will be overwritten. The repo ships no such file and the
container/K8s deployment path is env-var-only, so this is a documentation
matter (sizing §5.5), not a defect in the shipped deployment model.

---

## 6. Verification actually run

```
cargo test  -p axiam-api-rest --lib --no-default-features config::   → 23 passed, 0 failed
cargo test  -p axiam-api-grpc --lib config::                         → 4 passed, 0 failed
cargo check -p axiam-server   --no-default-features                  → Finished (clean)
cargo clippy -p axiam-api-rest --lib --no-default-features --tests -- -D warnings → clean
cargo clippy -p axiam-api-grpc --lib --tests -- -D warnings          → clean
cargo fmt   -p axiam-api-rest -p axiam-api-grpc -- --check           → clean
cargo fmt   -p axiam-server -- --check                               → no diffs in main.rs
bash scripts/check-doc-links.sh                                      → all links resolve
```

`--no-default-features` is used for the REST/server crates because this
sandbox has no `libxml2` for the `saml` feature (same flag CI's
"Build (SAML off)" job uses). The rate-limit code is not feature-gated.

**Not run:** the startup log line has not been observed on a live boot — it
requires SurrealDB + RabbitMQ, which this sandbox does not have. It is
straight-line `tracing::info!` with no fallible call, and the crate compiles,
but a maintainer smoke-boot is the honest confirmation (§7.2).

---

## 7. What remains for the maintainer

### 7.1 Sign-off items

1. **Preset values.** No shipped default moved, so nothing regresses on
   upgrade — but the `gateway`/`mesh` numbers are a judgement call anchored
   to laptop-class measurements. Confirm 600 / 6 000 / 600 / 6 000 (gateway)
   and 6 000 / 60 000 / 6 000 / 60 000 (mesh) match the fleet sizes you
   intend to support. They are one table in one file.
2. **`mesh` authz = 60 000/min is above the measured whole-server
   ceiling** — deliberately a runaway-loop guard rather than an abuse
   control, and labelled as such in the docs. Confirm you are comfortable
   shipping a documented not-really-a-limit under that profile name, or drop
   it to 30 000.
3. **§4.1 is a live finding about D8 as shipped**, not about this change:
   the `client_id` key modes are attacker-mintable. Confirm the
   documentation-plus-opt-in treatment is sufficient for v1.0-beta, or open
   an issue for the bounded-keyspace fix (§7.3).

### 7.2 Needs a laptop run

1. **Boot smoke test** — start the stack and confirm the
   `Rate-limit posture active` line appears once at `info` with the expected
   fields, under both no profile and `AXIAM__RATE_LIMIT__PROFILE=gateway`.
2. **Re-measure the posture pass under `gateway`** in run 4: the run-3
   `rl=prod` pass measured the defaults; there is no measured cell for the
   preset. Expected result — the single-IP generator is no longer flattened
   *if* the harness sends distinct `client_id`s, and is still flattened if it
   sends one. Both outcomes are informative; the second would empirically
   confirm §4.3.
3. **Refresh the envelope numbers** in
   `docs/deployment/rate-limit-sizing.md` §2 after run 4 — they are copied
   from public §6 and labelled temporary. The doc-vs-code test does not
   cover that prose table (it covers the posture table), so it is a manual
   sync at run-4 time.

### 7.3 Follow-ups deliberately not done here

1. **Bounded bucket keyspace for `client_id` modes** (§4.2) — key only on
   `client_id`s that resolve to a known client, or cap distinct keys per IP
   with an overflow bucket. Design change to D8; needs its own issue.
2. **Per-RPC client-identity-aware gRPC rate limiting** (§4.4) — the
   interceptor reordering already anticipated in `GrpcRateLimitKeyMode`'s
   doc comment. Until then, gRPC authz has no per-client fairness.
3. **`benchmarks/PUBLIC_BENCH_ANALYSIS.md` §6 does not yet mention
   `AXIAM__RATE_LIMIT__PROFILE`.** That file is outside this task's file
   ownership (owned by the benchmark/reporting agent), and its *shipped
   default* column is already correct and now CI-guarded against drift
   (§5.5). Someone should add a `PROFILE` row and point the M2M column at
   the preset when the public doc is next revised (E4 / fourth draft).
