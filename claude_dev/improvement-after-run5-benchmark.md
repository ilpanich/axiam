# Post-Run-5 Improvement Plan — Fixes, Competitor Feature Gaps, Frontend & SDK Completion

> Prepared 2026-08-06 from `benchmarks/PRIVATE_BENCH_ANALYSIS.md` and
> `benchmarks/PUBLIC_BENCH_ANALYSIS.md` (run 5, release image
> `1.0.0-alpha24`). Companion to `claude_dev/roadmap.md`; supersedes the
> run-4 plan (`improvement-after-run4-benchmark.md`) for open items.
>
> Scope: (A) server fixes ranked by run-5 evidence, (B) competitor
> feature-gap closure (Keycloak-style RBAC deny, Zitadel-class protocol
> surface), (C) frontend parity with shipped server features (WebAuthn
> passkeys/security keys first), (D) SDK fixes + new SDK features, (E)
> benchmark-harness fixes, (F) cross-cutting tests/docs/examples.
> Every task carries **detailed instructions**, **required tests, docs and
> examples**, **acceptance criteria**, and a **model recommendation**
> (cheapest of Opus 5 / Sonnet 5 that safely meets the task's difficulty).
>
> Guiding constraints (unchanged): high security (OWASP ASVS, additive
> hardening only — no regression of Argon2id/EdDSA/rotation posture),
> high performance (no fix may regress a run-5 headline cell by >2%
> without an explicit accepted trade), low resource consumption (server
> RSS envelope stays ≤ ~130 MiB average under the bench matrix).

## Model-choice policy used below

- **Opus 5** — open-ended root-cause diagnosis (unknown-cause perf
  regressions), security-critical protocol/semantics design (deny
  precedence, token exchange, impersonation), and anything whose failure
  mode is a silent security or correctness hole.
- **Sonnet 5** — well-specified implementation against an existing spec,
  contract, or RFC; CRUD/UI work; harness and tooling fixes; per-SDK
  fan-out where the contract already pins the semantics; docs and
  examples.
- Split tasks where the design and the implementation deserve different
  models: Opus designs and reviews, Sonnet executes the pinned design.

---

# Track A — Server fixes (evidence-ranked from run 5)

## A1 — Rate limiter fails its own enforcement assertions, both directions (J1, J1c) — **P0**

**Evidence.** `rl-prod-summary.md`: gRPC families admit **1/20–1/33** of
the configured ceiling under a single-IP 50-VU flood (authz: 181/min
admitted vs 6 000 configured); REST machine endpoints **over-admit**
(+12% token, +48% introspect, +50% authz check) against the ±10% bar.
Login passes exactly. Three limiter families (revoke, gRPC admin, gRPC
infra) have **no test scenario at all**. This blocks advertising any
gRPC prod-posture number.

**Instructions.**

1. **Verify the two-layer window-mismatch hypothesis** before changing
   code. The gRPC path stacks a shared write-behind pre-check (60 s
   window, enforced via `crates/axiam-db/src/rate_limit_counter.rs` /
   `crates/axiam-db/src/repository/rate_limit.rs`) in front of the
   in-memory governor (`crates/axiam-api-grpc/src/middleware/rate_limit.rs`,
   per-second quota + small burst). Hypothesis: under flood the 60 s
   pre-check admits its whole window allowance in the first instants of
   each window; the per-second governor then only passes
   `burst + rate×t` of that front-loaded spike, so effective admission ≈
   governor burst per 60 s. Reproduce locally with a small tokio test
   that drives both layers at ≥10× the configured rate and counts
   admissions per window; assert the starvation shape before and the fix
   after.
2. **Fix by aligning windows or dropping a layer for gRPC.** Preferred:
   make the write-behind pre-check window match the governor granularity
   (per-second buckets with the same burst semantics), OR demote the
   pre-check to a pure telemetry/distributed-abuse counter for gRPC and
   let the governor be the sole admission decision. Choose whichever
   keeps multi-instance fairness (the pre-check exists for
   cross-instance state); document the choice in the code and in
   `docs/` rate-limit posture docs.
3. **REST over-admission — product decision, then code.** The +48–50%
   shape is token-bucket burst allowance bleeding into the sustained
   window. Decide: (a) model burst explicitly in the assertion (admitted
   ≤ configured + burst, ±10%) and document "sustained rate converges to
   configured after the first window", or (b) tighten the bucket so a
   60 s sustained flood admits ≤1.1× configured. Recommendation: (b) for
   `introspect`/`authz check` (48–50% over is too loose for an abuse
   posture), (a) for `token` (+12% is burst working as designed —
   document it). Either way the shipped posture and the assertion script
   must agree.
4. **J1c — add the three missing flood scenarios** to
   `benchmarks/scenarios/`: `oauth2_revoke` (REST, 60/min bucket), gRPC
   admin family (SEC-079 absolute ceiling 10/s), gRPC infra family
   (fixed 100/s). Wire them into `rl_prod_check.py` so the verdict table
   covers all eight families.
5. Re-run the full `rl-prod` pass; the public doc's §7 table must flip
   to PASS on every measured row (or carry a documented burst label per
   3a).

**Tests.** Unit tests for each limiter layer at window boundaries;
integration test driving sustained flood ≥60 s asserting admitted-rate
within bar; regression test pinning the gRPC starvation reproduction
(fails on the old code). CI job running the limiter unit suite.

**Docs.** Update rate-limit posture doc: exact burst semantics per
endpoint family, the two-layer architecture and which layer decides,
`internet`/`gateway`/`mesh` tables regenerated.

**Model: Opus 5** for steps 1–3 (concurrency diagnosis + posture
decision with security implications). **Sonnet 5** for step 4 (scenario
authoring follows the existing k6 scenario pattern).

## A2 — token_refresh −35% regression (J2) — **P0**

**Evidence.** 839 → 545/s, p50 47.5 → 88.8 ms, tight medians both runs,
no harness change. Whole distribution shifted right ⇒ added serialized
per-request work. Suspects: the 53-commit post-run-4 security series
(session validation/rotation bookkeeping, audit emission on rotate,
OBS-1 keyed hashing) vs SurrealDB v3 digest drift.

**Instructions.**

1. **Instrument first, bisect second.** Add (or activate) `axiam::perf`
   stage timings in the refresh path: handler
   (`crates/axiam-api-rest/src/handlers/auth.rs` refresh endpoint) and
   service (`crates/axiam-auth/src/service.rs` /
   `crates/axiam-auth/src/token.rs` rotate logic). Stages to time:
   CSRF/double-submit validation, session read, token verify, rotation
   write (old-token invalidate + new-token insert), audit emit, response
   serialization. Requires A5/E1 (`RUST_LOG` reaching the container) for
   in-container measurement; local `just dev-up` measurement is fine for
   the bisect itself.
2. Compare stage profile at alpha24 vs the run-4 image commit. If one
   stage owns the +40 ms, `git bisect` the security series on that stage
   only (build + targeted k6 refresh scenario, 30 s cells are enough for
   a −35% signal).
3. Rule SurrealDB drift in/out with one A/B: alpha24 binary against the
   run-4-pinned SurrealDB digest.
4. Fix candidates, in order of likely cheapness: batch the
   rotation bookkeeping writes into one SurrealDB transaction; make
   audit emission on refresh async (AMQP fire-and-forget is the
   existing pattern — audit must not add serialized DB latency); cache
   the per-tenant session-policy read if the series added one. **Do not
   weaken security semantics** (single-use rotation, CSRF, audit
   completeness) — only restructure when/where the work happens.
5. If the cost is irreducible security work, accept and document: update
   the public doc §6 with the explanation and close the item honestly.

**Tests.** A criterion/bench or k6 smoke pinned in CI (`refresh ≥ 700/s
on the reference envelope` guard, or a stage-time budget test asserting
rotate-path DB round-trips ≤ N). Unit tests for any restructured
rotation transaction (single-use invariant, replay rejection).

**Docs.** Post-mortem section in the next public draft; performance
report update.

**Model: Opus 5** (unknown-cause regression across a 53-commit surface;
the fix touches token-rotation correctness).

## A3 — DB concurrency ceiling: CP-3 pass + read-replica design (J11) — **P1**

**Evidence.** Cache-off checks: capped 1 010–1 032/s, uncapped (4 DB
cores) +75–79% — the remaining authz ceiling is DB *concurrency*, not
per-query cost. Read-replica work now outranks further query tuning.

**Instructions.**

1. **CP-3 measured pass (cheap, do first):** one benchmark pass sweeping
   SurrealDB container/runtime tuning (worker threads, connection-pool
   size from `claude_dev/db-pool-design.md`, memory limits) on the authz
   scenarios, 2c and 4c DB. Publish the knob→throughput table in
   `claude_dev/surrealdb-tuning-report.md` (append run-5 section).
2. **Read-replica design doc** (`claude_dev/read-replica-design.md`):
   route hot authz/identity *reads* to SurrealDB replicas while all
   writes and revocation-sensitive reads stay on primary. Must state:
   the staleness contract (mirror the decision-cache contract — event
   path invalidation vs TTL bound; a replica-lag allow is the same class
   of stale allow), which queries are replica-eligible (authz check
   reads, userinfo, JWKS — never session-revocation reads unless the
   documented posture accepts the lag bound), config surface, failure
   modes (replica down ⇒ fall back to primary, never fail closed on
   reads), and the bench plan to prove it (re-run §12.6 with 1 replica).
3. Implementation behind a feature flag in `crates/axiam-db` repository
   layer: a `ReadPreference` on repository methods, plumbed from a
   per-query-class config. No API changes.

**Tests.** Repository tests for routing (replica-eligible vs pinned);
integration test with a simulated lagging replica asserting the
staleness bound and the primary-pinned queries never route to replica.

**Docs.** Deployment guide section (k8s manifests for a replica
StatefulSet in `k8s/`), staleness contract in operator docs.

**Model: Opus 5** for the design doc (staleness semantics are a
security contract), **Sonnet 5** for the CP-3 measured pass and the
flagged implementation once the design is approved.

## A4 — gRPC strict-revocation opt-in mode + posture docs (J10) — **P1**

**Evidence.** gRPC's speed advantage partly *is* skipping the
per-request session-revocation read
(`crates/axiam-api-grpc/src/middleware/auth.rs:42` validates the token
and stops); revocation bound = token expiry (15 min). Run 5 measured the
cache revocation contract (262 ms event-path deny; TTL-bounded
out-of-band) so the guidance can ship.

**Instructions.**

1. **Docs first (unblocked now):** document the gRPC posture choice
   explicitly — "gRPC data plane trusts JWT lifetime; REST re-checks
   session revocation" — plus the session-cache guidance with the
   measured contract numbers (262 ms / TTL+slack). Add to the security
   docs and the gRPC API docs; state it in `sdks/CONTRACT.md` §10 notes
   so SDK middleware docs inherit it.
2. **Opt-in strict mode:** config flag (per-tenant or server-wide;
   recommend server-wide first) `grpc_strict_revocation = true` that
   adds the session/token-revocation read to the gRPC auth interceptor,
   reusing the session-validation cache (TTL 5 s default when cache
   enabled) so the cost is one cache hit, not one DB read, on the hot
   path. Expected cost: gRPC check throughput approaches REST's
   revocation-checked profile — measure and publish it (add one labeled
   bench cell).
3. Wire the same invalidation hooks that serve the REST cache so
   event-path revocation is immediate in strict mode too.

**Tests.** Interceptor unit tests (strict off = today's behavior; strict
on = revoked session denied within cache TTL; event-path invalidation
denies immediately). Bench cell for strict-mode overhead.

**Docs.** Security posture page, config reference, CHANGELOG.

**Model: Sonnet 5** (mechanism and cache already exist on the REST path;
this is a guarded port with pinned semantics). Opus 5 review pass on the
interceptor diff is cheap insurance — fold into F4.

## A5 — Refresh-under-prod harness re-login budget (J4) and remaining bench-harness carryovers — **P2**

**Evidence.** rl-prod refresh: 516/s at 4.4% errors (worse than run 4's
2.4%) — the harness burns re-logins against the 10/min login bucket.

**Instructions.** In the rl-prod refresh scenario, pre-mint a pool of
sessions during setup sized for the full measurement window (VUs ×
duration / rotations-per-session), or budget re-logins inside the login
bucket. Keep the product-docs coupling note: short-session deployments'
refresh capacity is gated by the login limit. Also close J3: freeze the
Keycloak login story at "51/s, p2, 2 GiB, 2/3 valid" unless a single
KC-heap-knob sweep (KC's own `JAVA_OPTS_KC_HEAP`, not the container cap)
is cheap to run alongside the next matrix.

**Tests.** Harness self-check: scenario setup asserts the session pool
outlasts the window.

**Model: Sonnet 5.**

## A6 — AMQP transport encryption (`amqps://` TLS support) — **P1**

**Evidence / current state.** Broker traffic is **plaintext everywhere**:
`AmqpConfig` (`crates/axiam-amqp/src/config.rs`) has no TLS options and
defaults to `amqp://localhost:5672`; `docker/docker-compose.prod.yml`
and `k8s/server/configmap.yml` both wire `amqp://…:5672`; the RabbitMQ
statefulset/service and the network policies expose only 5672 — no TLS
listener (5671) exists in any deployment artifact. The AMQP layer's
HMAC-SHA256 signing + replay protection (contract §8) provides
**authenticity/integrity only, not confidentiality** — authz requests,
audit events, and outbound mail payloads cross the wire in cleartext.
This contradicts the project standard "TLS 1.3 minimum for all external
communication": six SDKs (Rust, TypeScript, Go, Python, Java, PHP)
consume AMQP directly, so broker traffic crosses service boundaries.
Mitigating fact: lapin 4.10 already compiles in a rustls backend
(`tcp-stream` → `rustls-connector` + `p12-keystore` in `Cargo.lock`), so
`amqps://` capability is in the shipped binary — the missing pieces are
the config surface, deployment wiring, tests, docs, and the SDK
contract clause.

**Instructions.**

1. **Config surface** (`crates/axiam-amqp/src/config.rs`): accept
   `amqps://` URLs (port 5671) and add an optional `tls` block —
   `ca_cert_path` (custom CA bundle; system roots when unset),
   `client_cert_path`/`client_key_path` (optional mutual TLS toward the
   broker, PEM; PKCS#12 acceptable via the already-present
   `p12-keystore`), and nothing else. **No `verify_peer: false` /
   insecure-skip option in release builds** — dev convenience, if
   wanted, is debug-build-only, mirroring the existing
   `DEV_DEFAULT_SIGNING_KEY` pattern in the same file. Enforce TLS 1.3
   minimum in the rustls client config per the project standard.
2. **Connection path** (`crates/axiam-amqp/src/connection.rs`): build a
   lapin `OwnedTLSConfig` from the config block and connect via
   `Connection::connect_with_config` when the scheme is `amqps`;
   plaintext `amqp://` keeps working (dev/e2e). Fail closed with a
   clear, actionable error on CA/cert misconfiguration (bad path,
   expired cert, hostname mismatch) — no silent plaintext fallback.
   Reconnect logic must preserve the TLS config across retries.
3. **Release-build posture flag:** add
   `AXIAM__AMQP__ALLOW_PLAINTEXT` (default `false` in release builds):
   a release binary refuses an `amqp://` URL unless the operator
   explicitly sets the flag — same fail-closed philosophy as the
   signing key. Log a prominent warning when plaintext is explicitly
   allowed.
4. **Deployment wiring:**
   - `docker/docker-compose.prod.yml`: RabbitMQ TLS listener
     (`listeners.ssl.default = 5671`, cert/key/CA mounts,
     `ssl_options.versions.1 = tlsv1.3`), server URL switched to
     `amqps://…:5671`; a documented cert-provisioning helper script
     (or reuse `axiam-pki`'s CA tooling — an AXIAM org CA signing its
     own broker cert is good dogfooding; document both this and
     bring-your-own-cert).
   - `k8s/`: statefulset + service gain 5671; network policies
     (`allow-ingress-to-rabbitmq.yml`, `server-egress.yml`) updated to
     5671; configmap URL → `amqps`; document cert-manager as the
     recommended issuer path, with secret mounts.
   - Dev compose stays plaintext (documented as dev-only).
5. **SDK contract**: add a transport-security clause to §8 (or a new
   §8b): SDKs that consume AMQP MUST support `amqps://`, custom CA
   bundles, and SHOULD support client certificates; MUST NOT offer
   verification-skip in production builds; HMAC signing remains
   mandatory regardless of transport (defense in depth — TLS is
   confidentiality, HMAC is end-to-end authenticity across broker hops).
   Fan out via D6.
6. **Perf sanity cell (optional, with E4):** one labeled bench cell for
   the AMQP async-authz path over TLS vs plaintext — expected ~nil
   steady-state cost (long-lived connections amortize the handshake),
   but measure rather than assert, per project culture.

**Tests.** Unit tests for config parsing/validation (scheme/tls-block
combinations, release-build plaintext refusal via the flag, missing-CA
error text); integration test in the e2e compose variant with a
TLS-enabled RabbitMQ (self-signed CA generated in setup): connect,
publish/consume round-trip, wrong-CA rejection, plaintext-URL-refused
assertion. Reconnect-with-TLS test (restart broker container
mid-consume).

**Docs.** Deployment guide "Securing the broker" section (compose + k8s
walkthroughs, cert rotation note); security posture page updated to
state the layering explicitly (TLS = confidentiality in transit, HMAC =
authenticity + replay protection, both required in production);
CHANGELOG; threat-model update (closes the cleartext-broker-traffic
exposure).

**Acceptance.** Prod compose and k8s templates run `amqps` end to end;
release binary refuses unflagged plaintext; e2e TLS suite green; no
measurable regression on the AMQP authz bench cell.

**Model: Sonnet 5** (the TLS backend is already compiled in; semantics
are pinned above — config plumbing, deployment wiring, tests). Include
the diff in the **F4 Opus 5 security review** alongside the other
security surfaces.

---

# Track B — Competitor feature-gap closure

Priority rationale: deny-override RBAC is the single most-cited
Keycloak/Zitadel comparison gap and is called out in our own public doc
(§10 cons). Device Authorization Grant serves the IoT positioning
directly. Token Exchange serves the service-mesh positioning. SCIM
serves enterprise provisioning (Zitadel has it; Keycloak only via
extensions — a chance to leapfrog).

## B1 — RBAC deny-override (explicit deny, Keycloak-parity) — **P0 of Track B**

**Current state.** Engine is additive-only, allow-wins, default-deny
(SEC-040; deny-override deferred post-v1.0-beta — that time is now).
`crates/axiam-authz` evaluates tenant-scoped roles, resource hierarchy,
scopes; decision + session caches with event-path invalidation; hot
queries CI-guarded against table scans.

**Instructions.**

1. **Design doc first** (`claude_dev/deny-override-design.md`), pinning:
   - **Semantics:** default-deny → explicit allow → **explicit deny wins
     over any allow** (Keycloak "negative permission" / policy-deny
     parity). Deny is attachable at the same grant points as allow:
     permission-in-role (a role can carry `effect: deny` entries), and
     role-assignment on resource nodes.
   - **Hierarchy cascade:** a deny on a parent resource cascades to
     children exactly like allows cascade today; a child-level allow
     must NOT override an inherited deny (deny-override, not
     most-specific-wins — state this explicitly with a worked example
     table; most-specific-wins is a footgun for security reviews).
   - **Scope interaction:** deny at resource level masks all scopes;
     deny at scope level masks only that scope.
   - **Evaluation order & short-circuit:** collect applicable denies
     first (or evaluate in one pass tracking a deny flag); a matched
     deny short-circuits to `Deny` immediately — this keeps the hot
     path's incremental cost at ~zero when no denies exist (the common
     case must stay one indexed query; add the deny check as a second
     indexed query only for tenants that have ≥1 deny rule — a cheap
     per-tenant `has_denies` flag in the tenant config/cache gates it).
   - **Cache correctness:** decision-cache entries must key identically
     for allow and deny outcomes; every deny-rule create/update/delete
     fires the existing invalidation hooks (same 262 ms event-path
     contract). Session cache unaffected.
   - **API surface:** `effect: "allow" | "deny"` (default `"allow"`,
     backward compatible) on permission and role-assignment
     create/update DTOs (REST + gRPC + AMQP authz messages), OpenAPI
     and proto updates.
   - **Migration:** existing data all-allow; no migration needed beyond
     schema default.
2. **Implementation order:** core types (`axiam-core`) → repository +
   indexed deny query with `EXPLAIN` CI guard (`axiam-db`) → engine
   (`axiam-authz`) → REST/gRPC/AMQP DTOs → OpenAPI/proto export →
   `sdks/CONTRACT.md` §11 helper-vocabulary update (declarative helpers
   must surface deny distinctly, e.g. decision reason `denied_by_rule`
   vs `no_grant`) → SDK re-sync (see D6) → frontend (C4).
3. **Performance gate:** re-run authz_check/batch cells; the
   no-denies-present path must be within noise (±2%) of run-5 numbers;
   publish the with-denies cost honestly as a new labeled cell.
4. Update SEC-040 status in threat model and CLAUDE.md/architecture
   docs.

**Tests.** Exhaustive engine table tests: (allow only, deny only,
allow+deny same node, allow child + deny parent, deny child + allow
parent, deny at scope vs resource, deny via group-inherited role, deny
in global vs resource-specific role, cache-hit deny, invalidation on
deny-rule delete). Property test: adding any deny rule can never widen
access. `EXPLAIN` guard for the deny query. Bench guard per step 3.

**Docs.** Authorization concepts page (worked examples + the precedence
table), API reference, migration note "additive-only → deny-override",
SDK contract §11 changes.

**Examples.** One end-to-end example per flagship SDK (rust, typescript,
python, go, java): "grant admin on /fleet, deny on /fleet/decommissioned".

**Model: Opus 5** for the design doc + engine/evaluation-order
implementation and the property tests (authorization semantics — silent
failure = privilege escalation). **Sonnet 5** for DTO/OpenAPI/proto
plumbing, docs, and examples after the engine lands.

## B2 — OAuth2 Device Authorization Grant (RFC 8628) — **P1**

**Why.** Keycloak and Zitadel both ship it; it is *the* grant for
input-constrained IoT devices — squarely AXIAM's target market. Current
grants: authorization_code(+PKCE), client_credentials, refresh_token
(`crates/axiam-oauth2/src/token.rs`; no device flow today).

**Instructions.**

1. New endpoints in `axiam-oauth2`: `POST /oauth2/device_authorization`
   (issues `device_code` + short `user_code` + `verification_uri`),
   token endpoint support for
   `urn:ietf:params:oauth:grant-type:device_code` with `authorization_pending`,
   `slow_down`, `expired_token`, `access_denied` responses per RFC 8628 §3.5.
2. Storage: device-grant record in SurrealDB (tenant-scoped, TTL'd,
   single-use user_code, status machine `pending → approved|denied →
   redeemed`), user_code generated from an unambiguous charset
   (BCDFGHJKLMNPQRSTVWXZ, 8 chars, rate-limit verification attempts —
   OWASP: brute-force window `charset^len / (rate × lifetime)` must
   exceed 10^6).
3. Verification UI: minimal server-rendered or frontend page
   `/device` (enter code → authenticate → consent → approve). Frontend
   part lands with C4.
4. Rate limiting: device_authorization and the polling token requests
   get their own buckets (polling interval enforcement via `slow_down`
   — do not let the generic token bucket absorb polling floods); add a
   flood scenario to the A1/J1c family.
5. Discovery: advertise in OIDC discovery metadata
   (`device_authorization_endpoint`, grant type).
6. SDK support is D6's device-flow helper (poll loop with backoff,
   contract §14 addition).

**Tests.** Full state-machine unit tests; integration test of the
polling flow incl. slow_down and expiry; brute-force test asserting the
verification endpoint rate limit; k6 scenario (bench-optional).

**Docs.** OAuth2 guide section + IoT quickstart example (device flow on
a headless device with mTLS provisioning as the follow-on).

**Model: Sonnet 5** (tightly specified RFC; the security invariants
above are pinned in the instructions). Opus 5 review in F4.

## B3 — OAuth2 Token Exchange (RFC 8693) — **P1**

**Why.** Service-mesh delegation/impersonation — Keycloak (now standard)
and Zitadel both ship it; it complements AXIAM's gRPC data-plane story
(a mesh service exchanging an inbound user token for a scoped-down
service token at 12 k reads/s is the demo).

**Instructions.**

1. **Design doc first** (`claude_dev/token-exchange-design.md`):
   supported subject/actor token types (start: our own access tokens
   only — no external-IdP subject tokens in v1), delegation
   (`actor_token` present, `act` claim chain) vs impersonation (policy
   decides who may impersonate — default OFF, per-client grant
   `may_impersonate` with audit), scope narrowing rule (requested scopes
   must be ⊆ subject token scopes ∩ client allowed scopes — never
   widen), audience restriction (`resource`/`audience` → `aud` claim),
   token lifetime (min(subject remaining, configured max)).
2. Implement as `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
   in the token endpoint; every exchange audited (subject, actor,
   client, granted scopes).
3. Rate-limit bucket + flood scenario (A1 family).
4. Discovery metadata; contract §15 + SDK helper in D6.

**Tests.** Scope-narrowing property test (result scopes ⊆ inputs, all
paths); impersonation-disabled default test; `act` chain correctness;
audit-record test; expiry inheritance.

**Docs.** Mesh delegation guide with a gRPC end-to-end example.

**Model: Opus 5** for design + scope/impersonation policy code (silent
failure = privilege escalation), **Sonnet 5** for endpoint plumbing,
docs, examples.

## B4 — SCIM 2.0 provisioning endpoint (RFC 7643/7644) — **P2**

**Why.** Zitadel ships SCIM; Keycloak needs a third-party extension.
Enterprise IdP-driven user/group provisioning (Okta/Entra as clients) is
a standard checkbox that costs us deals to lack and is mostly CRUD.

**Instructions.** New crate `axiam-scim` (REST, mounted under
`/scim/v2`, tenant-scoped via bearer token with a dedicated
`scim:provision` permission): `Users` and `Groups` resources (CRUD +
PATCH per RFC 7644 §3.5.2 — implement the PATCH op subset Okta/Entra
actually send: add/replace/remove on the standard attribute paths),
filtering subset (`userName eq`, `externalId eq`, paging), `/Schemas`,
`/ServiceProviderConfig`, `/ResourceTypes`. Map to existing user/group
repositories; emit the same webhooks/audit events as native CRUD. ETag
optional-v2. Explicitly out: bulk ops, complex filters.

**Tests.** Contract tests against recorded Okta and Entra provisioning
request fixtures; PATCH-op unit matrix; tenant-isolation tests (SCIM
token from tenant A cannot touch tenant B).

**Docs.** Provisioning guide (Okta + Entra setup walkthroughs).

**Model: Sonnet 5** (large but well-specified CRUD; fixtures pin
compatibility).

## B5 — OIDC session/logout completion: RP-Initiated, Back-Channel Logout, PAR — **P2**

**Why.** Keycloak/Zitadel both ship the logout triad; federation
deployments expect it. PAR (RFC 9126) is cheap and increasingly required
by security profiles (FAPI).

**Instructions.**

1. RP-initiated logout (`end_session_endpoint`, `id_token_hint`,
   `post_logout_redirect_uri` allow-list per client).
2. Back-channel logout (RFC 8471-family: OIDC Back-Channel Logout 1.0):
   logout tokens (JWT, `events` claim) POSTed to registered client
   `backchannel_logout_uri`s on session termination — reuse the webhook
   delivery machinery (retry, HMAC is replaced by the signed logout JWT).
3. PAR: `POST /oauth2/par` returning `request_uri`, authorize endpoint
   accepting it; config flag `require_par` per client.
4. Discovery metadata for all three. SDK RP helpers already exist
   (contract §12) — extend with logout verification helper (D6).

**Tests.** Logout-token validation vectors; redirect allow-list tests;
PAR expiry/one-time-use tests.

**Docs + examples.** Federation guide updates; one RP example app update.

**Model: Sonnet 5** (specs are precise; reuses existing OIDC/webhook
infrastructure). Opus 5 review in F4.

## B6 — Formerly deferred items — now scheduled as X1–X5

Zitadel Actions-style scripting (→ **Reactors**, AMQP-native external
actors), UMA 2.0 permission tickets, WebAuthn attestation policy
enforcement (FIDO MDS3), external-IdP token exchange, FAPI 2.0
certification run (incl. the OIDF fee-waiver letter). Activated per
operator decision of 2026-08-07 — detailed instructions, sequencing and
model recommendations in
[`extra-B-track-features.md`](extra-B-track-features.md).

---

# Track C — Frontend: expose shipped server features

**Current state.** Server ships full WebAuthn (registration +
authentication ceremonies via `crates/axiam-api-rest/src/handlers/webauthn.rs`,
credential model supports `Totp | Passkey | SecurityKey`), but the
frontend (`frontend/src/`) has **zero** WebAuthn references —
`MfaManagementPage.tsx` and `MfaSetupPage.tsx` are TOTP-only and
`LoginPage.tsx` cannot exercise passkey login. The design-system audit
(`claude_dev/AXIAM-frontend-audit.md`) also lists P1/P2 accessibility
gaps.

## C1 — Passkey & security-key management UI — **P0 of Track C**

**Instructions.**

1. `frontend/src/services/`: add a `webauthn.ts` API client for the four
   REST endpoints (`start_registration`, `finish_registration`,
   `start_authentication`, `finish_authentication`) + credential
   list/rename/delete from the MFA-methods API
   (`handlers/mfa_methods.rs` already returns the unified
   `MfaMethod { method_type: Totp|Passkey|SecurityKey, name,
   last_used_at }` view).
2. Use the native `navigator.credentials` API via the small
   `@simplewebauthn/browser` helper (base64url plumbing, feature
   detection) — no heavyweight dependency.
3. `MfaManagementPage`: list all methods with type badges (reuse
   `StatusBadge`), per-credential rename + delete (with
   `ConfirmDialog`), "Add passkey" and "Add security key" flows —
   both call the same registration ceremony; pass
   `authenticatorAttachment` hint (`platform` for passkey, `cross-platform`
   for hardware key) and the server-chosen residentKey/userVerification
   options untouched.
4. Error UX: user-cancelled ceremony, unsupported browser
   (`window.PublicKeyCredential` feature check → hide buttons with an
   explanatory note), timeout, duplicate credential
   (`InvalidStateError`).
5. Do not weaken server options client-side; the challenge/verification
   logic is entirely server-side already.

**Tests.** Vitest component tests with a mocked
`navigator.credentials` (all four ceremony outcomes + error paths),
service-layer tests against recorded server fixtures. Follows the
existing `*.test.tsx` pattern.

**Docs.** User guide page "Passkeys & security keys" with screenshots;
CHANGELOG.

**Model: Sonnet 5.**

## C2 — Passkey login on `LoginPage` — **P0 of Track C**

**Instructions.** Add "Sign in with a passkey" to `LoginPage.tsx`:
discoverable-credential flow (empty `allowCredentials` from the server's
`start_authentication`), plus **conditional UI** (passkey autofill:
`mediation: "conditional"` + `autocomplete="username webauthn"` on the
username field, gated on
`PublicKeyCredential.isConditionalMediationAvailable()`). On ceremony
success the existing session-cookie flow continues unchanged (CSRF
double-submit as today). Also surface WebAuthn as a second-factor step
when the server's login response demands MFA and the user has a
registered credential (today the page only offers TOTP). Fallback
ordering: passkey → TOTP → recovery path.

**Tests.** Component tests for both mediation modes, MFA-step
selection logic, and graceful degradation when the API says WebAuthn but
the browser lacks support.

**Docs.** Same user-guide page as C1; admin note on RP-ID/origin config.

**Model: Sonnet 5.**

## C3 — Design-system accessibility fixes (audit P1 + P2) — **P1**

**Instructions.** Implement `claude_dev/AXIAM-frontend-audit.md` items
1–7 exactly as specced there: global `prefers-reduced-motion` guard;
`Input`/`Textarea` `error`/`aria-invalid` + `aria-describedby` wiring and
a `FormDialog` error slot; dialog focus-restore + body scroll-lock via a
shared `useModalA11y` hook; one standardized `focus-visible` token;
`backdrop-filter` fallback; structural-border contrast tokens
(`--border-strong`); `ToggleField` target size. Then the P3 polish items
(8–10) in the same pass if trivial.

**Tests.** Component tests for error-state announcement and
focus-restore; axe-core smoke run over the main pages added to the CI
frontend job.

**Model: Sonnet 5.**

## C4 — Frontend coverage audit + new-feature pages — **P1, rolling**

**Instructions.** One systematic pass diffing REST handler surface
(`crates/axiam-api-rest/src/handlers/*.rs`, 28 modules) against
`frontend/src/pages/` and produce
`claude_dev/frontend-coverage-matrix.md` (endpoint → page/component →
covered? gap severity). Known/expected gaps to confirm and then close in
this task's follow-on waves: GDPR tooling (export/erasure requests —
`gdpr.rs`), email config test-send UI (`email_config.rs`), scopes CRUD
(`scopes.rs`, if not already inside the permissions pages), plus the new
surfaces this plan creates: **deny-override effect selector** on
role/permission editors with an explicit visual treatment (red "DENY"
badge + inheritance preview on the `ResourceTree`) (B1), **device-flow
verification page** `/device` (B2), SCIM token management (B4), session
logout settings (B5). The deny-override UI must include an "effective
access" preview panel (calls the check endpoint as a chosen
user/resource pair) so admins can see deny cascade results before
saving.

**Tests.** Component tests per new page (existing pattern); the coverage
matrix itself gets a CI check that fails when a new handler module has
no matrix row (cheap grep-based script).

**Model: Sonnet 5** (audit + CRUD pages). The deny-preview panel UX
copy should be reviewed alongside B1's docs (Opus reviews semantics
wording in F4).

---

# Track D — SDKs (11 repos: rust, typescript, python, java, kotlin, csharp, go, php, swift, c, cpp)

## D1 — Python performance residual (J5) — **P1**

**Evidence.** Async rewrite didn't close the gap: check p50 40.2 ms /
p95 116.8 ms / 311 rps vs go/java/rust ~10 ms/60 ms/835–869 rps at the
same 16-way concurrency; +60 ms p95 over wire; client CPU 40 s (worst).
The harness is now clean — the residual is in the SDK or asyncio usage.

**Instructions.** Profile the bench loop (`py-spy record` +
`asyncio` debug mode) against a local server: suspects in order —
(1) per-request session/connector churn (ensure one shared
`aiohttp.ClientSession`/httpx `AsyncClient` with keep-alive and a
connection pool ≥ concurrency); (2) event-loop starvation from
sync-in-async (JSON parsing, HMAC, logging on the hot path — move to
`loop.run_in_executor` only if profiling proves it, else pure-C json);
(3) uvloop absent (add `uvloop` as an optional extra, document the
speedup); (4) per-call object churn (pydantic validation on the hot
check path — allow a fast path that skips model construction for
`check()` bool results). Fix what profiling indicts, re-run the SDK
bench (median-of-3), publish before/after. Target: check p50 ≤ 20 ms,
p95 overhead ≤ +15 ms vs wire (honest target — CPython won't match Go).

**Tests.** Existing conformance suite must stay green; add a regression
bench threshold to the SDK repo CI (soft warning, not hard fail —
laptop-dependent).

**Model: Opus 5** (open-ended profiling; easy to "fix" the wrong thing).

## D2 — C++ reconnect tail (J6) — **P1**

**Evidence.** check p50 3.2 ms / p95 280 ms, identical signature across
runs 4→5 despite the connection-age fix; own acceptance bar (p95 ≤ 3×
p50) fails. Live hypotheses are now **server-side**: idle/keep-alive
timeout closing pooled connections, or a `Connection: close` on some
response path.

**Instructions.** Capture with `SSLKEYLOGFILE`/plaintext tcpdump during
a bench run: count TCP handshakes per 1 000 requests for cpp vs go on
the same server. If reconnects correlate with a fixed idle gap, check
Actix keep-alive config (`keep_alive`, `client_request_timeout`) vs the
C++ pool's idle-eviction and set the pool's max-idle *below* the server
keep-alive (plus jitter). If `Connection: close` appears, find the
emitting handler/middleware path and fix server-side. Also verify the
C++ pool actually applies `SDK_BENCH_CONCURRENCY` (run-5 notes flagged
the C SDK ignoring it for refresh; check cpp's plumbing too). Fix, then
re-bench: acceptance p95 ≤ 3× p50.

**Model: Opus 5** for the diagnosis (cross-component, packet-level);
the eventual fix is likely small (Sonnet 5 executes if the diagnosis
hands over a pinned cause).

## D3 — TypeScript wire-baseline audit (J7) + C# pass merge (J8) + Rust CPU telemetry (J8b) — **P2**

**Instructions.**

- **TS:** a client cannot beat the k6 wire baseline (−23 ms p95) doing
  the same work. Audit comparability: k6's connection model
  (per-VU connections, `noConnectionReuse`?) vs undici/fetch pooling +
  pipelining; confirm response-validation parity (is the TS bench
  skipping JSON parse or status assertions?); confirm identical payloads
  and concurrency accounting (in-flight vs VU semantics). Either fix the
  baseline (make k6 reuse match) or annotate the methodology; do not
  publish TS-vs-wire until the audit closes.
- **C#:** find why one of three passes drops (harness log, likely
  timeout or port clash) and why refresh throughput reads 20 rps vs ~55
  (suspect a serialized `await` in the refresh loop or the single-flight
  guard serializing the bench's forced-expiry pattern); fix harness or
  SDK accordingly.
- **Rust:** 23.4 s client CPU (7× Go) contradicts its latency profile —
  check whether the harness CPU counter includes `cargo` build/spawn
  time and whether the bench loop busy-polls (e.g. `try_recv` spin);
  fix the measurement first, only then suspect the SDK.

**Tests.** Harness assertions: wire baseline records its connection
model in metadata; per-SDK pass-merge requires 3/3 or logs the drop
reason.

**Model: Sonnet 5** (bounded audits with clear hypotheses).

## D4 — SDK contract additions for new server features — **P1, gated on B1/B2/B3/B5**

**Instructions.** Extend `sdks/CONTRACT.md` in this repo first, then
fan out (D6):

- **§11 update (deny-override, after B1):** check/batch responses gain a
  decision reason (`allowed`, `no_grant`, `denied_by_rule`); declarative
  helpers must not collapse deny into a generic false without exposing
  the reason; middleware behavior unchanged (deny = 403 same as today).
- **§14 Device flow (after B2):** `oauth2_device_authorize()` +
  `oauth2_device_poll()` helper implementing the RFC 8628 poll loop
  (interval + slow_down backoff, expiry, cancellation token), naming per
  the §1 per-language map conventions.
- **§15 Token exchange (after B3):** `oauth2_token_exchange(subject,
  actor?, scopes?, audience?)` with `Sensitive<T>` on all token params
  (§7 applies).
- **§12 logout additions (after B5):** back-channel logout-token
  verification helper (validate signature/`events`/`sid`, hand the
  session id to the app), RP-initiated logout URL builder.
- Bump the contract version, update the Breaking Changes Log, re-export
  `sdks/openapi.json` and `proto/`.

**Tests.** Contract conformance checklists updated (§ Conformance
Statement) with per-feature required test names.

**Model: Opus 5** for the contract text of §14/§15 semantics (it is the
normative security spec 11 repos implement); **Sonnet 5** for openapi/
proto regeneration.

## D5 — SDK quality-of-life features (independent of server work) — **P2**

**Instructions.** Add to the contract, then implement per-SDK:

1. **Standard retry policy** (idempotent GETs + token refresh only):
   capped exponential backoff + full jitter, `Retry-After` honored,
   default off for non-idempotent calls — one normative table in the
   contract so all SDKs match.
2. **Client-side decision memo (opt-in):** tiny TTL cache (default off,
   max TTL 5 s — mirror the server session-cache contract and its
   documented staleness bound verbatim) for `check()` results, keyed
   (subject, resource, action, scope), with an explicit
   "reads-your-own-writes not guaranteed" doc note. Never cache deny…
   actually: cache deny and allow identically (asymmetric caching leaks
   timing signal and surprises); keep it simple and documented.
3. **`close()`/context-manager audit:** every SDK exposes deterministic
   connection shutdown (the C++ tail work in D2 showed lifecycle gaps);
   add conformance test.
4. **Telemetry hooks:** optional callback interface (request start/end,
   retry, refresh) so users can wire metrics without us shipping an
   OTel dependency; OTel adapter as a separate example per flagship SDK.

**Tests.** Per-SDK conformance additions; jitter/backoff unit tests with
a fake clock.

**Model: Sonnet 5** (contract-driven fan-out); Opus 5 only for the
contract wording of the retry + memo semantics (fold into D4's contract
pass).

## D6 — Contract/spec re-sync fan-out to all 11 SDK repos — **P1, recurring gate**

**Instructions.** After each of B1/B2/B3/B5/D4/D5 lands here: re-vendor
`sdks/CONTRACT.md`, `sdks/openapi.json`, `proto/` into every
`axiam-<lang>-sdk` repo; implement the new contract sections; each SDK
adds the required conformance tests + one runnable example per new
feature (`examples/` dir convention); README feature-matrix row flips.
Swift/C/C++ no longer have a §12 deferral to work around: contract 1.11
lifted it and ported §12 + §12.7 to all three, so they implement §14/§15
on the same §12 discovery cache and token endpoint as everyone else
(C still leaves device-flow *UI* polling cadence to the app and ships the
raw endpoints plus the composed helper).
Per-repo PRs on the designated branch, one repo at a time, kept small.

**Model: Sonnet 5** per repo (mechanical against a pinned contract);
flag any contract ambiguity found back to an Opus 5 contract errata
pass rather than improvising per-language.

---

# Track E — Benchmark harness & observability fixes

## E1 — `RUST_LOG` never reaches the container (J9) — **P1** (blocks A2 in-container stage timing)

**Instructions.** Add `RUST_LOG` to the compose env allow-list used by
the bench profiles (`benchmarks/profiles/`, `docker/` compose files);
add a preflight `docker inspect` assertion to the runner (fail the cell
if a runbook-required env var is absent from the container config);
record `axiam_env` completeness in cell metadata.

**Model: Sonnet 5.**

## E2 — `bench-pack` drops all non-k6 artifacts (J13) — **P1**

**Instructions.** Fix the include patterns to add `**/*.md`, `**/*.log`,
`nsenter.log`, `rl-prod-summary.md` etc. under `results/`; add a
self-test that packs a fixture tree and asserts the investigation
artifacts survive; document the manifest in `benchmarks/README.md`.

**Model: Sonnet 5.**

## E3 — Bulk-seed tooling for the 10× seed-size cell (J12) — **P2**

**Instructions.** Extend the seeder to generate N× tenants/users/roles/
resources with realistic hierarchy depth via batched SurrealDB inserts
(single transaction per 1 000 records; target: 10× seed in <5 min on
the G-box); parameterize scenarios to select seed scale; add the
seed-size sensitivity cell to the next-run runbook.

**Model: Sonnet 5.**

## E4 — New-feature scenarios join the matrix — **P2, gated on B-track**

Device-flow polling, token-exchange, strict-revocation gRPC, and
deny-present authz cells (the B1 perf gate) get k6 scenarios and runbook
entries so the next public draft measures the new surface honestly.

**Model: Sonnet 5.**

---

# Track F — Cross-cutting quality gates

## F1 — Test coverage for every task above

Every task lands with: unit tests in the touched crate(s) (narrow
`cargo test -p <crate>` scope per CLAUDE.md disk-hygiene rules),
integration tests where a protocol boundary is crossed, and — for
authz/oauth2 changes — property/table tests as specified per-task.
End-of-track regression gate: full workspace `just check` once per
track, `cargo clean` between tracks (sandbox disk quota).

## F2 — Documentation set

Per-feature docs listed in each task, plus one umbrella update:
architecture doc (deny-override, token exchange, device flow, replica
reads), security posture page (gRPC revocation modes, limiter
semantics), comparison page refresh (the §10 cons list shrinks —
deny-override and device flow move from "cons" to "features"; keep the
same honesty: new features ship with their measured cost).

## F3 — Examples

`examples/` additions named in B1/B2/B3/D5/D6; each example is CI-smoke
run (compile/run against a compose stack) so they can't rot.

## F4 — Security review pass — **required before any B-track merge**

One consolidated Opus 5 review of: deny-override engine diff (B1),
device-flow brute-force surface (B2), token-exchange scope narrowing
(B3), SCIM tenant isolation (B4), logout-token validation (B5), strict
revocation interceptor (A4), AMQP TLS config + fail-closed plaintext
posture (A6). Follow the existing
`claude_dev/security-review*.md` format; findings block merge.

**Model: Opus 5.**

---

# Sequencing & waves

| Wave | Tasks (parallelizable within wave) | Gate to next wave |
|---|---|---|
| 1 | A1 (limiter), A2 (refresh regression), E1, E2, C1, C2 | limiter assertions PASS locally; refresh cause identified |
| 2 | B1 design+engine, A3 design + CP-3 pass, A6 (AMQP TLS), C3, D1, D2, D3, A5 | B1 engine tests green + perf gate |
| 3 | B1 plumbing/docs, B2, B3, A4, C4 (audit + deny UI), E3 | F4 security review of B1–B3/A4 |
| 4 | D4 (contract), B5, B4, E4 | contract merged in axiam repo |
| 5 | D6 fan-out (11 SDK repos), D5, C4 remaining pages, F2/F3 umbrella | conformance suites green per SDK |
| 6 | Bench re-run (next public draft: limiter table PASS, refresh explained, new-feature cells) | — |

Dependencies: A2 in-container stage timing needs E1 (local timing does
not). D4/D6 strictly follow their server features. C4's deny UI follows
B1's API. F4 blocks all B-track merges.

# Model recommendation summary

| Task | Model | One-line rationale |
|---|---|---|
| A1 diagnose/fix limiter | **Opus 5** | Concurrency root-cause + abuse-posture decision |
| A1c flood scenarios | Sonnet 5 | Pattern-following k6 authoring |
| A2 refresh regression | **Opus 5** | Unknown cause across 53 commits; touches rotation correctness |
| A3 replica design | **Opus 5** / Sonnet 5 impl | Staleness contract is a security semantic |
| A4 strict-revocation gRPC | Sonnet 5 (+F4 review) | Ports existing REST mechanism with pinned semantics |
| A5 harness re-login budget | Sonnet 5 | Bounded harness fix |
| A6 AMQP TLS (`amqps`) | Sonnet 5 (+F4 review) | rustls backend already compiled in; semantics pinned in-task |
| B1 deny-override design+engine | **Opus 5** | Authorization semantics; silent failure = privilege escalation |
| B1 DTO/docs/examples | Sonnet 5 | Plumbing after pinned design |
| B2 device flow | Sonnet 5 (+F4 review) | Tight RFC with invariants pinned in-task |
| B3 token exchange design+policy | **Opus 5** / Sonnet 5 plumbing | Scope-narrowing/impersonation policy |
| B4 SCIM | Sonnet 5 | Spec-pinned CRUD with fixtures |
| B5 logout triad + PAR | Sonnet 5 (+F4 review) | Precise specs, reuses infra |
| C1/C2 WebAuthn UI + login | Sonnet 5 | Server does the crypto; browser plumbing well-trodden |
| C3 a11y fixes | Sonnet 5 | Audit already contains the fixes |
| C4 coverage audit + pages | Sonnet 5 | CRUD/UI fan-out |
| D1 Python residual | **Opus 5** | Open-ended profiling |
| D2 C++ tail | **Opus 5** diagnose / Sonnet 5 fix | Packet-level cross-component diagnosis |
| D3 TS/C#/Rust harness audits | Sonnet 5 | Bounded, hypothesis-driven |
| D4 contract §14/§15 | **Opus 5** text / Sonnet 5 regen | Normative spec for 11 implementations |
| D5 SDK QoL features | Sonnet 5 | Contract-driven fan-out |
| D6 SDK re-sync ×11 | Sonnet 5 | Mechanical against pinned contract |
| E1–E4 harness | Sonnet 5 | Tooling |
| F4 security review | **Opus 5** | The backstop for every Sonnet-implemented security surface |

Rule of thumb applied: **Opus 5 where a wrong-but-plausible answer is
expensive** (authz semantics, token issuance policy, unknown-cause perf
regressions, the consolidated security review); **Sonnet 5 everywhere
the spec, contract, or audit already pins the answer** — which this
document tries hard to do, precisely so most of the execution can run on
the cheaper model.
