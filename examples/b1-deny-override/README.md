# B1 — RBAC deny-override walkthrough

**What this demonstrates.** The canonical deny-override scenario: grant
`fleet:admin` on `/fleet`, deny it on `/fleet/decommissioned`, and show that
the deny wins — both at the node it's attached to and cascaded two levels
down to `/fleet/decommissioned/unit-7`. This is worked table rows 1 and 3 of
[`claude_dev/deny-override-design.md`](../../claude_dev/deny-override-design.md#22-hierarchy-cascade--worked-table),
run against a live server instead of read off a table.

This is the **stable, canonical version** of the scenario. AXIAM's five
flagship SDKs (Rust, TypeScript, Python, Go, Java) each ship their own
language-idiomatic deny-override example in their own repository; all of them
link back to this page rather than duplicating the wire-level walkthrough.
If you are looking at this from one of those repos: the calls below are
exactly what your SDK's declarative-helper call (`can()` / `check()` /
equivalent — see `sdks/CONTRACT.md` §11) does under the hood.

**What it requires.**

- A running AXIAM instance, already bootstrapped (an organization, a tenant,
  and an admin user — see [`scripts/e2e-bootstrap.sh`](../../scripts/e2e-bootstrap.sh),
  or your own deployment's equivalent). This example creates its own
  resources, permission, roles and a disposable test user on top of that —
  it does not need anything else pre-seeded.
- `curl` and `jq` on `PATH`. Nothing else — this is plain REST, no SDK
  dependency, so it can never drift from what the wire actually does.

**What it does NOT cover.** Scope-level denies (§2.3 of the design doc —
a deny scoped to `scope_ids: ["pii"]` masking only that scope rather than the
whole action) and cache-hit-vs-miss behavior are exercised by the engine's
own test suite (`crates/axiam-authz/src/engine.rs`, `crates/axiam-authz/tests/authz_engine_test.rs`),
not repeated here — this example is scoped to the one scenario every other
description of the feature quotes.

## Run it

```bash
# Against docker/docker-compose.e2e.yml, from the repo root:
docker compose -f docker/docker-compose.e2e.yml up -d --wait
./scripts/e2e-bootstrap.sh
AXIAM_URL=http://localhost:8090 ./examples/b1-deny-override/walkthrough.sh
```

Or point `AXIAM_URL` (and, if you didn't use the e2e-bootstrap.sh defaults,
`E2E_ORG_SLUG` / `E2E_TENANT_SLUG` / `E2E_ADMIN_EMAIL` / `E2E_ADMIN_PASSWORD`)
at any already-bootstrapped AXIAM deployment.

## What the script does

1. Logs in as the tenant admin (cookie session; captures the `X-CSRF-Token`
   response header per `sdks/CONTRACT.md` §3's non-browser pattern).
2. Creates the resource hierarchy `/fleet` → `/fleet/decommissioned` →
   `/fleet/decommissioned/unit-7`.
3. Creates one permission (`fleet:admin`) and **two roles**: `fleet-operator`
   carrying an `effect: "allow"` grant, and `fleet-decommission-lockout`
   carrying an `effect: "deny"` grant on the same permission. Two roles,
   not one — a role's grants apply everywhere the role is *assigned*, so the
   allow and the deny need independent assignment points to reproduce the
   scenario (assigning one role carrying both grants to both resources would
   just deny everywhere, which is a different — and correct, but less
   interesting — outcome).
4. Creates a disposable test user and assigns `fleet-operator` at `/fleet`,
   `fleet-decommission-lockout` at `/fleet/decommissioned`.
5. Logs in as that user and calls `POST /api/v1/authz/check` three times,
   asserting:
   - `/fleet` → `allowed: true`, `reason_code: "allowed"`
   - `/fleet/decommissioned` → `allowed: false`, `reason_code: "denied_by_rule"`
   - `/fleet/decommissioned/unit-7` → `allowed: false`, `reason_code: "denied_by_rule"`
     (proving the deny cascades through a resource it was never directly
     attached to)

The script exits non-zero if any assertion fails, which is what
`.github/workflows/examples-smoke.yml` relies on to keep this example honest.

## Why deny wins, in one sentence

Default-deny → explicit allow → **explicit deny beats every allow, at any
depth and at equal specificity** — never most-specific-wins. See
[`claude_dev/deny-override-design.md` §2.1](../../claude_dev/deny-override-design.md#21-why-deny-override-and-not-most-specific-wins)
for why that trade was made deliberately.

## Verification status

`bash -n` and `shellcheck` are both clean. Its request/response shapes
(`CreateResourceRequest`, `GrantPermissionRequest`'s `effect` field,
`CheckAccessResponse`'s `reason_code`) are read directly from
`crates/axiam-api-rest/src/handlers/{resources,permissions,authz_check}.rs`,
not guessed. **It has not been run against a live server** — no docker
daemon in the environment this was authored in (see the repo root
`examples/README.md`).
