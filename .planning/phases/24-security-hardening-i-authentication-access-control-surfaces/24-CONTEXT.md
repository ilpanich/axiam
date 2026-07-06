# Phase 24: Security Hardening I — Authentication & Access-Control Surfaces - Context

**Gathered:** 2026-07-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Harden the authentication and access-control front door against replay, IP-spoofing, race, path-smuggling, and timing attacks. Scope is exactly SECHRD-01, SECHRD-03, SECHRD-04, SECHRD-11, SECHRD-12 — each fix fails **closed** and ships with a **negative test** that proves the attack is now rejected (the phase's defining success signal). No other findings, no refactors beyond what a given fix strictly requires.

- **SECHRD-01 / SEC-008** — TOTP atomic replay protection: DB compare-and-set on the step, skew-boundary + enrollment-confirm windows closed.
- **SECHRD-03 / SEC-048+060** — rate-limit client-IP keying: kill the XFF leftmost-hop fallback (use `peer_addr()` when `trusted_hops >= hops.len()`), correct the `trusted_hops` nginx guidance, and implement a **multi-replica shared rate-limit store**.
- **SECHRD-04 / SEC-049** — bootstrap atomicity (single-super-admin invariant, no TOCTOU) + mandatory first-run gate (unset gate ⇒ refuse, never unconditional bootstrap).
- **SECHRD-11 / T19.25** — public-path allowlist hardening: segment-boundary wildcard matching + path normalization before the exclusion check.
- **SECHRD-12 / T19.23+24+27+SEC-028** — auth crypto/recovery side-channels: constant-time reset, peppered-buffer zeroize, durable GDPR audit dead-letter, block current-password reuse on the unauthenticated reset path + seed initial password into history.

**Out of scope (tracked elsewhere in v1.2):** SSRF address-pinning + mTLS CA validity + GDPR erasure durability/ledger + federation nonce + AMQP + egress (SECHRD-02/05/06/07/08/09/10 → Phase 25); gRPC governor **throughput semantics** (CORR-01 → Phase 26 — see coordination note under D-01c below); Playwright-in-CI body assertions (CORR-04 → Phase 26).
</domain>

<decisions>
## Implementation Decisions

> Captured interactively during discuss-phase (2026-07-03). The user selected the more robust option on three of four gray areas. The rest of the mechanics (below, "Claude's Discretion") flow straight from the SECHRD acceptance criteria.

### Rate-limit topology & keying (SECHRD-03)
- **D-01a — Shared store, not documented-multiplier.** Implement a **SurrealDB-backed shared rate-limit store** (reuse the existing SurrealDB — no new infra dependency like Redis) so buckets are shared across replicas under HPA. This closes the multi-replica gap rather than only documenting the per-replica multiplier.
- **D-01b — Fail open with per-replica in-memory fallback.** When the shared store is unreachable (DB blip), the limiter falls back to the existing per-replica in-memory governor and logs/alarms. A counter-store outage must never hard-block all auth traffic. (Availability-first posture standard for rate limiters; brute-force protection degrades gracefully to per-pod, never off.)
- **D-01c — Coverage: REST + gRPC both this phase.** Move both the REST governor endpoints (login, `/auth/mfa/*`, `/oauth2/introspect|revoke`, etc.) **and** the gRPC limiter onto the shared store now.
  - ⚠ **Coordination note for planner/executor:** CORR-01 (Phase 26) reworks the gRPC governor's *throughput/quota semantics* (`rate_limit.rs:40-47`, `per_millisecond(1000/authz_per_sec)`). This phase's shared-store swap on the gRPC limiter MUST NOT re-introduce the inverted `per_second` bug and MUST leave the quota math in a state CORR-01 can build on (or align with it). Treat the gRPC change as store/key-extractor only; do not "fix" throughput here.
- **D-01d — Keying bug (the core AC):** when `trusted_hops >= hops.len()`, ignore XFF entirely and use `peer_addr()` (do NOT return `hops[0]`). Correct the `trusted_hops` docs for nginx `proxy_add_x_forwarded_for` (rightmost entry = real client). Negative test: rotating `X-Forwarded-For` per request no longer yields a fresh bucket.

### GDPR audit-write durability (SECHRD-12 / T19.27)
- **D-02 — Both file + syslog.** When the erasure audit DB-write fails, dead-letter to **both** an append-only local file (on a mounted volume, matching AXIAM's append-only audit posture) **and** structured audit syslog. Most robust — the record survives a DB failure even if one sink is absent; a SIEM can ingest either.

### Bootstrap gate (SECHRD-04)
- **D-03a — Gate: env var OR one-time setup token.** Accept **either** `AXIAM_BOOTSTRAP_ADMIN_EMAIL` **or** a one-time setup token as the mandatory first-run gate. Both unset ⇒ **refuse bootstrap** (fail closed). An unset gate never allows arbitrary bootstrap.
- **D-03b — Setup token: server-generated, logged once at first boot.** The server mints the setup token on first run and logs it exactly once for the operator to copy; it is consumed once (persist a consumed-once record so it cannot be replayed). No pre-provisioning required.
- **D-03c — Atomicity (the core AC):** first-super-admin creation is a single conditional/transactional operation keyed on a uniqueness invariant — two concurrent first-run requests ⇒ at most one super-admin. Concurrency test proves the single-admin invariant.

### Constant-time reset (SECHRD-12 / T19.23)
- **D-04 — Mirror the real Argon2 cost.** On the ineligible/unknown/federated reset branch, perform a **dummy Argon2 hash (same params) + the same async wait** as the valid branch, so timing self-calibrates and stays indistinguishable. Consistent with the existing dummy-Argon2-on-user-not-found login pattern already in the codebase. Do NOT pad to a hand-tuned fixed duration (drifts if Argon2 params change).

### Claude's Discretion
These are prescriptive enough in the acceptance criteria that the researcher/planner should nail them directly — no user decision needed:

- **SECHRD-01 mechanics:** turn `update_totp_step` (`repository/user.rs:483-497`) into a **conditional CAS** — `UPDATE … SET totp_last_used_step = $step WHERE tenant_id = $tenant_id AND (totp_last_used_step = NONE OR totp_last_used_step < $step)` — and have the handler treat a **no-op update (no row affected)** as replay-rejected. Record the **actual matched step** (incl. the −1 skew step, not always `current_step`) in `verify_code_with_replay_check` so a skew-accepted code can't be replayed in a later wall-clock step. Seed `totp_last_used_step` at enrollment-confirm time. Concurrency test: N parallel submissions of one valid code ⇒ exactly one success.
- **SECHRD-11 mechanics:** in `is_public_path` (`middleware/authz.rs:38-45`), require a **path-segment boundary** on `*` prefix entries (so `/api/v1/auth/*` does not match `/api/v1/authz/...`), and **normalize the path** (collapse `//`, resolve/**reject** `..` traversal) before the allowlist check. Negative test: a non-canonical route cannot slip past the allowlist.
- **SECHRD-12 residual mechanics:** wrap the peppered-password buffer with `zeroize` and the pepper with `secrecy`, wiped before return (T19.24); block reuse of the **current** password on the unauthenticated reset path and seed the initial password into history (SEC-028 residual).
- **Test placement:** Rust negative/concurrency tests in the owning crate's `tests/` (`axiam-auth`, `axiam-db`, `axiam-api-rest`, `axiam-api-grpc`); per-crate `cargo check/test -p <crate>` only.
- **Per-PLAN `<threat_model>`:** the security capability is active — each PLAN.md carries an ASVS-aligned threat-model block for the control it touches.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Authoritative finding descriptions
- `claude_dev/security-review-postremediation.md` — SEC-008 (TOTP), SEC-048/060 (rate-limit keying), SEC-049 (bootstrap), SEC-028 residual (reset history) — exact issue + suggested fix per finding.
- `claude_dev/code-review-postremediation.md` — cross-references for the touched surfaces.
- `claude_dev/roadmap.md` — original T19.23 / T19.24 / T19.25 / T19.27 descriptions (constant-time reset, zeroize, public-path allowlist, GDPR audit DLQ).

### Requirements & roadmap
- `.planning/REQUIREMENTS.md` §SECHRD-01, SECHRD-03, SECHRD-04, SECHRD-11, SECHRD-12 — full acceptance criteria + verification baseline (lines 666-830).
- `.planning/ROADMAP.md` §"Phase 24" — goal + 5 success criteria (each includes a negative test).
- `CLAUDE.md` — security standards: Argon2id (OWASP params), EdDSA/Ed25519 JWT, AES-256-GCM at rest, additive-only RBAC (allow-wins), fail-closed default, append-only audit, per-crate build discipline.

### Prior-phase carry-forward
- `.planning/phases/23-security-regressions-high-findings/23-CONTEXT.md` — Phase 23 posture (fail-closed default; negative-test-per-fix bar; D-05 explicitly deferred deeper constant-time reset + zeroize + GDPR-audit DLQ to SECHRD-12/this phase).

### Code surfaces (verify current file:line before editing — may have drifted)
- **SECHRD-01:** `crates/axiam-auth/src/totp.rs:85-125` (`verify_code_with_replay_check`), `crates/axiam-db/src/repository/user.rs:483-497` (`update_totp_step`), `crates/axiam-core/src/models/user.rs:32,71` (`totp_last_used_step`), `crates/axiam-api-rest/src/handlers/auth.rs` (MFA verify handler), enrollment-confirm path. Existing test: `crates/axiam-auth/tests/req14_totp_replay_test.rs`.
- **SECHRD-03:** `crates/axiam-api-rest/src/extractors/rate_limit.rs` (`XForwardedForKeyExtractor`, lines 55-72), `crates/axiam-api-rest/src/server.rs:24-38` (`build_governor`, `trusted_hops` env), `crates/axiam-api-grpc/src/middleware/rate_limit.rs` (gRPC governor — coordinate with CORR-01), `crates/axiam-api-rest/src/extractors/client_info.rs`.
- **SECHRD-04:** `crates/axiam-api-rest/src/handlers/bootstrap.rs`, `crates/axiam-db/src/seeder.rs`, `crates/axiam-api-rest/src/middleware/authz.rs` (bootstrap path is public), `crates/axiam-server/src/main.rs`. Existing test: `crates/axiam-api-rest/tests/bootstrap_test.rs`.
- **SECHRD-11:** `crates/axiam-api-rest/src/middleware/authz.rs:32-45,106` (`is_public_path` + call site), tests at `:145-175`.
- **SECHRD-12:** `crates/axiam-auth/src/password_reset.rs:83-235` (`initiate_reset` returns `Ok(None)` on unknown/federated — the timing leak; `confirm_reset`), `crates/axiam-auth/src/password.rs` (`hash_password`, pepper), `crates/axiam-auth/src/crypto.rs`, `crates/axiam-core/src/models/password_history.rs`, `crates/axiam-db/src/repository/password_history.rs`, `crates/axiam-server/src/cleanup.rs` (GDPR erasure audit-write), `crates/axiam-api-rest/src/handlers/gdpr.rs:119-126`. Existing test: `crates/axiam-api-rest/tests/req14_pepper_test.rs`.

### Codebase maps (context)
- `.planning/codebase/ARCHITECTURE.md`, `CONVENTIONS.md`, `TESTING.md`, `CONCERNS.md` — trait-in-core / impl-in-db / thin-handler layering, per-crate build discipline, existing test bias.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`verify_code_with_replay_check` (`totp.rs:85`)** already returns `(valid, current_step)` and documents that the caller MUST persist the step — the CAS is the missing atomicity. The matched-step (skew) recording is the correctness gap to close.
- **`XForwardedForKeyExtractor` (`extractors/rate_limit.rs`)** already skips `trusted_hops` from the right and falls through to `peer_addr()` — the fix tightens the `>= hops.len()` branch and swaps the in-memory governor store for a shared one.
- **In-memory `Governor` per endpoint (`server.rs:build_governor`)** — becomes the **fail-open fallback** (D-01b) when the shared store is unreachable; keep it as the degraded path, don't delete it.
- **Existing dummy-Argon2-on-user-not-found login path** (SEC-032/PROJECT.md) — the exact pattern to mirror for the constant-time reset branch (D-04).
- **`is_public_path` prefix-strip matcher (`authz.rs:38`)** — a small, well-tested function; add segment-boundary + normalization without changing its call contract.
- **AES-256-GCM at-rest + `#[serde(skip_serializing)]` conventions** — reuse for any secret-adjacent handling; secrets never serialized/logged/defaulted.

### Established Patterns
- Trait-in-core / impl-in-db / thin-handler; per-crate `cargo check/test -p <crate>` (never full workspace); `cargo fmt` + `clippy -D warnings` before commit.
- Fail-closed is the default for auth/authz/crypto controls — **except** the rate-limit store, which is deliberately fail-**open** with a per-replica fallback (D-01b) so a counter blip can't take down auth.
- Append-only audit; DB errors mapped to typed variants (e.g. Phase 23 added `AxiamError::ServiceUnavailable`→503 for a missing key — a similar operator-actionable variant may fit the bootstrap-gate-unset refusal).
- Every fix ships a regression test that fails-before/passes-after; security fixes additionally ship a negative/concurrency test proving the attack/race is rejected.

### Integration Points
- **gRPC limiter shared-store swap (D-01c)** overlaps CORR-01 (Phase 26) — store/key-extractor change only, preserve quota semantics for CORR-01 to fix.
- **GDPR audit dead-letter (D-02)** touches `cleanup.rs` — the same file SECHRD-06 (Phase 25) hardens for erasure durability/ledger; keep the DLQ change additive so Phase 25 can build on it without conflict.
- **Bootstrap gate (D-03)** builds on the earlier "transactional+gated bootstrap" (Phase 11) — this phase makes the gate **mandatory/unconditional** and closes the initialized-check TOCTOU; the setup-token path is new.
- Constant-time reset (D-04) must not regress the enumeration-safety Phase 23 (D-05) established on the reset/resend flows.

</code_context>

<specifics>
## Specific Ideas

- Every one of the 5 fixes ships a **negative or concurrency test** demonstrating the attack/race is now rejected — this is the phase's defining success signal, not optional. Concretely: N-parallel-TOTP → exactly one success (SECHRD-01); rotating-XFF → same bucket (SECHRD-03); two concurrent bootstraps → one super-admin + unset-gate refusal (SECHRD-04); non-canonical route → not public (SECHRD-11); ineligible-email reset → time-indistinguishable + current-password-reuse blocked (SECHRD-12).
- No new `unwrap()`/`expect()`/constant-key fallbacks on security paths. Secrets (pepper, setup token) never serialized, logged in cleartext (the setup-token single log line at first boot is the one deliberate exception, per D-03b), or defaulted.
- Reuse the existing SurrealDB and AES-256-GCM/serde-skip conventions — no new infra (no Redis) and no new crates beyond `zeroize`/`secrecy` (already implied by SECHRD-12 ACs).

</specifics>

<deferred>
## Deferred Ideas

- **gRPC governor throughput-semantics fix** — CORR-01, Phase 26 (this phase only swaps the gRPC limiter store; it does not touch the inverted-quota bug).
- **SSRF address-pinning, mTLS CA validity, GDPR erasure durability/ledger, federation nonce, AMQP signing, egress/k8s secrets** — SECHRD-02/05/06/07/08/09/10, Phase 25 (parallel-capable with this phase after Phase 23).
- **Playwright-in-CI with request-body assertions** — CORR-04, Phase 26 (what actually gates the reset/enumeration behavior in CI).
- A **hand-tuned fixed-duration** constant-time reset — rejected in favor of mirroring real Argon2 cost (D-04); revisit only if the dummy-hash approach proves insufficient under profiling.

None of these expand Phase 24 scope — they are the correct home for adjacent work.

</deferred>

---

*Phase: 24-security-hardening-i-authentication-access-control-surfaces*
*Context gathered: 2026-07-03*
