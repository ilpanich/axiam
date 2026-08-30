---
slug: bench-lockout-policy
status: complete
completed: 2026-08-30
---

# Summary — bench lockout neutralization moved to the org policy

Five FAIL cells in the beta06 `p2-tls13` dry run were one bug: the bench user
locked out mid-sweep because `AXIAM__AUTH__MAX_FAILED_LOGIN_ATTEMPTS` stopped
being the value the login path reads. The threshold is now a per-org/per-tenant
policy (`effective_settings` → `LockoutPolicy`); the compose env var is only the
no-tenant fallback, so the bench org kept the shipped default of 5.

## Changes

- `benchmarks/runner/seed.sh` — new step after bootstrap: read the org security
  settings, flatten the grouped GET shape into the flat `SetOrgSettings` PUT body
  (preserving `opaque_mode` and everything else), set
  `max_failed_login_attempts` (default 1000000, `BENCH_MAX_FAILED_LOGIN_ATTEMPTS`
  to override), PUT, assert the readback. The existing user `unlock` step now
  documents that it must stay ordered after this one.
- `benchmarks/targets/axiam/docker-compose.yml` — the D-06 comment no longer
  claims the env var neutralizes anything on its own.

## Verification — `BENCH_TLS_PORT=18443 just targets=axiam profiles=p2-tls13 bench-dry-run`

Before: 17 PASS / 5 SKIP / **5 FAIL**. After: **22 PASS / 5 SKIP / 0 FAIL** (3m 39s).

The two cells that were silently mis-measuring now show real Argon2id cost:

| Scenario | before | after |
|---|---|---|
| `grpc_admin_validate` | p95 4ms (lockout short-circuit, reported green) | p95 **38ms** |
| `oauth2_password_login` | 100% fail, ~8ms | ok=348, p95 **42ms** |
| `token_refresh` | setup abort | ok=665, p95 19ms |
| `uma_ticket_grant` | setup abort (401) | ok=324, p95 37ms |
| `userinfo` | 11072/11072 fail | ok=10663, p95 1ms |
| `userinfo_grpc` | 13105/13105 fail | ok=31547, p95 1ms |

## Note for a follow-up (not done here)

The runner grades a k6 `setup()` exception (exit 107) as "the k6 client could not
reach the target or every response was rejected". The k6 `GoError`/`Error` line is
already in the `.dryrun.log`; surfacing it in the verdict would have named the
401 immediately instead of pointing at connectivity.
