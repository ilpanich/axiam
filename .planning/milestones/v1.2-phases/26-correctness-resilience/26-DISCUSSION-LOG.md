# Phase 26: Correctness & Resilience - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-04
**Phase:** 26-correctness-resilience
**Areas discussed:** DB resilience strategy (CORR-02), Webhook retry & queue design (CORR-03), CI e2e gating (CORR-04), MFA-setup landing & tenant restore UX (CORR-05), Webhook HMAC signature format (CORR-03), New config knobs & defaults, CORR-06 specifics, CORR-01 governor burst sizing

---

## DB recovery strategy (CORR-02)

| Option | Description | Selected |
|--------|-------------|----------|
| Both (proactive + reactive) | Background re-signin inside TTL + on-auth-error reconnect path | ✓ |
| Proactive re-signin only | Periodic timer only; missed tick strands client until PERF-04 | |
| Reactive reconnect-on-auth-error only | Re-signin on detected auth-expiry; first request eats the failure | |

**User's choice:** Both (belt-and-suspenders).
**Notes:** Reactive path also serves as the hook PERF-04 (Phase 27) builds on.

## Refresh interval & health (CORR-02)

| Option | Description | Selected |
|--------|-------------|----------|
| Fraction of TTL (~50–75%), config-overridable; health=Unhealthy on expiry | Derived from TTL, self-adjusts if TTL changes | ✓ |
| Fixed config interval (e.g. daily), health=Unhealthy | Simpler but drifts if TTL changes | |
| Let me specify exact numbers | User-supplied cadence/threshold | |

**User's choice:** Fraction of TTL (~50–75%, e.g. ~0.6), overridable; `health_check` Unhealthy on auth-expiry.

---

## Webhook retry policy (CORR-03)

| Option | Description | Selected |
|--------|-------------|----------|
| Bounded exp-backoff + dead-letter on exhaustion | Retry ~5 with backoff to ceiling; DLQ + terminal failed audit | ✓ |
| Bounded exp-backoff, drop + audit on exhaustion | Same backoff, no DLQ (not replayable) | |
| Let me specify attempts/delays | User-supplied numbers | |

**User's choice:** Bounded exponential backoff + dead-letter queue on exhaustion.

## Webhook queue topology (CORR-03)

| Option | Description | Selected |
|--------|-------------|----------|
| Dedicated exchange + per-attempt delay via TTL/DLX, final DLQ | Native RabbitMQ delayed retry, survives restart | ✓ |
| Dedicated queue + in-process backoff | Consumer sleeps backoff; ties up slots | |
| Reuse existing AMQP infra/conventions | Match current audit/mail consumer convention | |

**User's choice:** Dedicated exchange + per-message TTL/DLX delayed retry (attempt count in headers) + real DLQ.
**Notes:** Still reuse `axiam-amqp` connection/publisher infra and mirror the mail-consumer backoff conventions (25-08) for consistency.

## Webhook audit granularity (CORR-03)

| Option | Description | Selected |
|--------|-------------|----------|
| Per-attempt + terminal outcome | Audit each attempt + terminal success/exhausted-failure | ✓ |
| Terminal outcome only | One record on final success/DLQ | |
| You decide | Match existing audit-event model | |

**User's choice:** Per-attempt + terminal outcome.

## Webhook HMAC signature format (CORR-03)

| Option | Description | Selected |
|--------|-------------|----------|
| Keep existing format as-is | `X-Axiam-Signature` = hex HMAC(body); delivery-id header for idempotency | |
| Add signed timestamp (Stripe-style t=,v1=) | `X-Axiam-Timestamp` + sign timestamp+body; stronger replay resistance | ✓ |
| You decide | Based on any documented receiver/SDK contract | |

**User's choice:** Stripe-style signed timestamp (`t=<unix>,v1=<hex HMAC(timestamp.body)>`).
**Notes:** ⚠ SDK/doc webhook-verification helpers must be updated to the new scheme — flagged for researcher/planner. Existing `X-Axiam-Event`/`X-Axiam-Delivery` headers retained.

---

## CI wiring (CORR-04)

| Option | Description | Selected |
|--------|-------------|----------|
| Same e2e job: vitest step + playwright step, both blocking | Reuse seeded backend; minimal infra change | ✓ |
| Separate jobs (unit vs e2e-playwright), both required | Cleaner split but duplicates setup | |
| Playwright non-blocking at first | Soft-fail to shake out flakes; leaves build ungated | |

**User's choice:** Same e2e job, distinct blocking vitest + playwright steps.

## Which specs gate (CORR-04)

| Option | Description | Selected |
|--------|-------------|----------|
| All 12 must pass (fix/skip any that fail) | Whole suite required; skip-with-note unfinished specs | ✓ |
| AC-named critical subset gates; rest non-blocking | auth/login/contract required only | |
| You decide after a trial run | Choose gating set from what's green | |

**User's choice:** All 12 specs gate; fix or `test.skip`-with-note any failing spec ("green means green").

---

## MFA landing (CORR-05)

| Option | Description | Selected |
|--------|-------------|----------|
| Dedicated setup route carrying the setup_token | Bookmark/refresh-safe; mirrors reset-password page | ✓ |
| Inline modal using token in state | Fewer routes; refresh loses token (dead-end risk) | |
| Reuse existing MFA enrollment component | Route mandated user into existing settings enroll flow | |

**User's choice:** Dedicated MFA-setup route carrying the `setup_token`.

## Tenant restore fallback (CORR-05)

| Option | Description | Selected |
|--------|-------------|----------|
| Fall back to prior behavior; degrade gracefully, no crash | Slugs are enhancement, not hard dependency | ✓ |
| Treat missing slugs as an error state | Stricter; risks lockout during rollout window | |
| You decide from current Topbar code | Match existing fallback | |

**User's choice:** Degrade gracefully when slugs missing/unresolvable; never crash.

---

## New config knobs & defaults

| Option | Description | Selected |
|--------|-------------|----------|
| New nested sections + safe defaults, all overridable | `AXIAM__DB__TOKEN_REFRESH_FRACTION`, `AXIAM__WEBHOOK__MAX_ATTEMPTS`, backoff base/ceiling | ✓ |
| Hardcode sensible constants, no new env knobs | Fewer surfaces; not tunable without rebuild | |
| Let me specify names/defaults | User-supplied keys/values | |

**User's choice:** New nested `AXIAM__SECTION__KEY` knobs with safe defaults, all overridable.

---

## CORR-06 org-settings dirtiness (CQ-F38)

| Option | Description | Selected |
|--------|-------------|----------|
| Guard init + preserve edits on refocus (minimal, matches AC) | Dirtiness tracking + init guard | |
| Also warn-on-navigate-away when dirty | Adds unsaved-changes router blocker | ✓ |
| You decide | Match other forms | |

**User's choice:** Minimal fix **plus** warn-on-navigate-away when dirty (router blocker wiring).

---

## CORR-01 governor burst sizing

| Option | Description | Selected |
|--------|-------------|----------|
| Burst = configured rate (1s worth), test asserts sustained ≈ rate | Absorbs spikes; simple default | ✓ |
| Separate configurable burst knob (`AXIAM__GRPC__AUTHZ_BURST`) | More tunable; extra config surface | |
| You decide | Idiomatic tower-governor default, test target = rate | |

**User's choice:** Burst = one second's worth of tokens (= `grpc_authz_per_sec`); throughput test asserts sustained ≈ configured rate.

---

## Claude's Discretion

- Dashboard distinct query-key exact shape (CORR-06 / CQ-F37).
- Exact retry attempt/backoff numeric defaults within the agreed ranges (validate against `axiam-amqp` mail-consumer backoff, 25-08).
- Whether new webhook config lives under a fresh `[webhook]` section vs an existing one — follow the config module structure.
- CORR-01 quota mechanic (`per_millisecond` vs `Quota::per_second`) — either acceptable.

## Deferred Ideas

- PERF-04 (Phase 27): full-jitter reconnect backoff, `max_backoff` ceiling, bounded retry, poisoned-connection eviction in `connection.rs`.
- Receiver/SDK-side replay-window tolerance policy for `X-Axiam-Timestamp` (sender emits it now).
- Independent gRPC burst config knob (`AXIAM__GRPC__AUTHZ_BURST`) — not added now.
