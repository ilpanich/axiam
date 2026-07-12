# Phase 24: Security Hardening I — Authentication & Access-Control Surfaces - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-03
**Phase:** 24-security-hardening-i-authentication-access-control-surfaces
**Areas discussed:** Rate-limit topology, GDPR audit durability, Bootstrap gate credential, Constant-time reset budget

---

## Rate-limit topology (SECHRD-03)

| Option | Description | Selected |
|--------|-------------|----------|
| Document multiplier | Keep in-memory governor; fix keying; document effective limit ≈ configured × replica_count; no new infra | |
| SurrealDB-backed shared store | Distributed counter on existing SurrealDB (no new dependency); shared across replicas | ✓ |
| Redis shared store | Add Redis as distributed store; standard but new infra dependency | |

**User's choice:** SurrealDB-backed shared store
**Notes:** User opted to actually close the multi-replica gap rather than only documenting it, while avoiding a new infra dependency (Redis) by reusing SurrealDB.

### Follow-up: store failure mode

| Option | Description | Selected |
|--------|-------------|----------|
| Fail open w/ in-memory fallback | On store error, fall back to per-replica in-memory governor + log/alarm; auth stays available | ✓ |
| Fail closed | Reject on store error; strongest brute-force posture but a DB blip hard-blocks auth | |

**User's choice:** Fail open with per-replica in-memory fallback

### Follow-up: store coverage

| Option | Description | Selected |
|--------|-------------|----------|
| REST governor endpoints only | Swap store+keying for REST governors; leave gRPC per-replica (CORR-01 reworks it in Phase 26) | |
| REST + gRPC both now | Move both REST and gRPC limiters onto the shared store this phase | ✓ |

**User's choice:** REST + gRPC both now
**Notes:** Recorded a coordination note in CONTEXT (D-01c): the gRPC change is store/key-extractor only and must not collide with CORR-01's Phase 26 throughput-semantics rework.

---

## GDPR audit durability (SECHRD-12 / T19.27)

| Option | Description | Selected |
|--------|-------------|----------|
| Persistent local file | Append-only dead-letter file on a mounted volume; simple, durable | |
| Audit syslog | Structured syslog for SIEM ingestion; loss if no sink configured | |
| Both file + syslog | Write file AND emit syslog; most robust | ✓ |

**User's choice:** Both file + syslog
**Notes:** Maximum durability — the record survives a DB failure even if one sink is absent.

---

## Bootstrap gate credential (SECHRD-04)

| Option | Description | Selected |
|--------|-------------|----------|
| Mandatory env var only | Require AXIAM_BOOTSTRAP_ADMIN_EMAIL unconditionally; refuse when unset; minimal | |
| Env var OR one-time setup token | Also accept a one-time setup token as an alternative gate | ✓ |

**User's choice:** Env var OR one-time setup token

### Follow-up: setup-token mechanism

| Option | Description | Selected |
|--------|-------------|----------|
| AXIAM_BOOTSTRAP_SETUP_TOKEN env var | Symmetric with the email var; neither set ⇒ fail closed | |
| Server-generated, logged once at first boot | Server mints token on first run, logs once, consumed-once record | ✓ |

**User's choice:** Server-generated, logged once at first boot
**Notes:** No pre-provisioning; the single first-boot log line is the one deliberate exception to "secrets never logged". Requires a consumed-once record to prevent replay.

---

## Constant-time reset budget (SECHRD-12 / T19.23)

| Option | Description | Selected |
|--------|-------------|----------|
| Mirror real Argon2 cost | Dummy Argon2 hash (same params) + same async wait on reject branch; self-calibrating | ✓ |
| Pad to fixed target duration | Sleep reject branch to a constant deadline; simpler but must be tuned above worst-case Argon2 | |

**User's choice:** Mirror real Argon2 cost
**Notes:** Consistent with the existing dummy-Argon2-on-user-not-found login pattern already in the codebase; avoids drift if Argon2 params change.

---

## Claude's Discretion

Deferred to researcher/planner (prescriptive in the SECHRD acceptance criteria):
- SECHRD-01 TOTP CAS mechanics + skew-matched-step recording + enrollment-confirm seeding.
- SECHRD-11 segment-boundary matching + path normalization (reject `..`, collapse `//`).
- SECHRD-12 residual: `zeroize`/`secrecy` for the peppered buffer; block current-password reuse on the unauthenticated reset path + seed initial password into history.
- Test placement (per-crate `tests/`) and per-PLAN ASVS threat-model blocks.

## Deferred Ideas

- gRPC governor throughput-semantics fix — CORR-01, Phase 26.
- SECHRD-02/05/06/07/08/09/10 (SSRF pinning, mTLS CA validity, GDPR erasure ledger, federation nonce, AMQP, egress/k8s) — Phase 25.
- Playwright-in-CI request-body assertions — CORR-04, Phase 26.
- Hand-tuned fixed-duration constant-time reset — rejected in favor of mirroring real Argon2 cost.
