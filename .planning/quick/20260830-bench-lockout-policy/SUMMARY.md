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

## Follow-up, done in the same task

The runner graded a k6 `setup()` exception (exit 107) as "the k6 client could not
reach the target or every response was rejected" — the one thing it was not: the
client reached the target and got a clean 401. The `GoError`/`Error` line was
already sitting in the `.dryrun.log` this run tees. `dry_verdict()` now lifts it:

    FAIL  uma_ticket_grant  no operation completed at all (exit 107, 0 failed)
                            — k6: Error: auth.loginSession: login failed
                              (status 401) — check seeding + profile

Applies to both dead-cell branches (summary present with `ok == 0`, and k6 dying
before it wrote a summary). A `thresholds ... have been crossed` line is skipped
as noise — it says only that a threshold failed, which the verdict already knows,
so those cells keep the accurate generic wording. The message is flattened and
`|`-escaped before it reaches `record_dry`, which writes TSV that the justfile
renders as a markdown table.

Verified live, not just unit-tested: a cell run against a deliberately wrong
`BENCH_PASSWORD` produced the verdict above from a real k6 exit 107, and
`jwks_fetch` still graded `PASS — ok=42873, p95=0ms`.
