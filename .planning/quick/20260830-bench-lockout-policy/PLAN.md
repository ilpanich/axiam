---
slug: bench-lockout-policy
created: 2026-08-30
status: in-progress
---

# Benchmark dry-run: five FAIL cells from an ineffective lockout neutralization

## Problem

`just targets=axiam profiles=p2-tls13 bench-dry-run` reported 5 FAIL out of 27:

| Scenario | k6 exit | Symptom |
|---|---|---|
| `oauth2_password_login` | 99 | 1460/1460 checks failed, ~8ms per request |
| `token_refresh` | 107 | `setup()` aborted: "refresh session pool: minted 0/2 sessions" |
| `uma_ticket_grant` | 107 | `setup()` aborted: `auth.loginSession: login failed (status 401)` |
| `userinfo` | 99 | 11072/11072 failed, `bench_fallback=1` |
| `userinfo_grpc` | 99 | 13105/13105 failed, `bench_grpc_status` pinned at 3 |

The runner's verdict text ("the k6 client could not reach the target") is
misleading — the client reached the target fine.

## Root cause (one bug, five symptoms)

The seeded bench user gets **locked out mid-sweep**.

`targets/axiam/docker-compose.yml` sets
`AXIAM__AUTH__MAX_FAILED_LOGIN_ATTEMPTS=1000000` and its comment block claims
this neutralizes D-06 accrual. It no longer does. The lockout threshold became a
per-organization / per-tenant **policy** resolved through
`axiam_core::models::settings::effective_settings`; both credential paths take a
`LockoutPolicy`, not an `AuthConfig` (`crates/axiam-auth/src/lockout.rs`). The
deployment-wide config value is only the fallback for a check that cannot
resolve a tenant. The bench org's settings row still carried the shipped
default:

    "lockout": { "max_failed_login_attempts": 5, "lockout_duration_secs": 300,
                 "lockout_backoff_multiplier": 2.0, "max_lockout_duration_secs": 3600 }

Scenarios run alphabetically. `grpc_admin_validate` (8th) drives
`ValidateCredentials` with a deliberately wrong password thousands of times, so
the account locks ~5 iterations in. Every later cell that logs in as the user
(`loginSession` / `mintUserToken`) then 401s. Cells before it pass, which is why
this read as five unrelated failures.

Proven live against the running bench stack: 5 wrong passwords, then the correct
one → `401 invalid credentials` in **3ms** (the lockout short-circuit, ahead of
Argon2id).

Second, quieter cost: once locked, `grpc_admin_validate` reported **green** while
measuring the short-circuit instead of Argon2id — p95 4ms against a real ~38ms.

## Fix (benchmarks only — no server or frontend code)

1. `runner/seed.sh` — after bootstrap, GET `/api/v1/organizations/{ORG_ID}/settings`,
   flatten the grouped `SecuritySettings` response into the flat `SetOrgSettings`
   body (PUT is a full replacement), set `max_failed_login_attempts`, PUT it back,
   assert the readback. Overridable via `BENCH_MAX_FAILED_LOGIN_ATTEMPTS`.
   Placed before the existing `POST /users/{id}/unlock` step, which must stay
   after it.
2. `targets/axiam/docker-compose.yml` — correct the D-06 comment: the env var is
   the deployment-wide backstop, not the neutralization.

## Verification

Re-run `BENCH_TLS_PORT=18443 just targets=axiam profiles=p2-tls13 bench-dry-run`
and require 0 FAIL, plus `grpc_admin_validate` / `oauth2_password_login` p95 in
the tens of ms (proof Argon2id is actually being measured).
