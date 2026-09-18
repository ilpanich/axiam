---
task: SCIM answers a contended write with 500 instead of the documented 503 + Retry-After
found: 2026-09-13
found-at: main @ 8e4ffc6e9 (1.0.0-beta14, contract 1.45)
severity: contract violation (not a regression from PR #447)
---

# Fix: `axiam-scim` never got a `WriteContention` arm

Paste everything below into a fresh cloud session. It is self-contained.

---

## What is wrong

`3ccef6a30` (*feat(api): a contended write answers 503 with Retry-After — R-4, T-262*)
introduced `AxiamError::WriteContention`. Its doc comment at
`crates/axiam-core/src/error.rs:112` states the contract:

> Maps to `503 Service Unavailable` with `Retry-After: 1`, and to gRPC `UNAVAILABLE`.

That was wired into **two of the three** API surfaces:

| Surface | Mapping | Status |
|---|---|---|
| `crates/axiam-api-rest/src/error.rs:60,104,130,165` | 503 + `Retry-After` | ✅ |
| `crates/axiam-api-grpc/src/services/user.rs:114`, `reactor.rs:190` | `Status::unavailable` | ✅ |
| `crates/axiam-scim/src/error.rs` | **missing** | ❌ **500** |

`axiam-scim` has its own `From<AxiamError> for ScimError` with explicit arms for
`NotFound`, `AlreadyExists`, `AuthenticationFailed`, `AuthorizationDenied`,
`Validation`, `PasswordPolicy`, `TenantContext`, `RateLimited` and
`ServiceUnavailable` (line 162) — but none for `WriteContention`. It therefore
falls through to the catch-all at line 168:

```rust
_ => Self::new(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
```

So a SCIM caller that loses an optimistic-concurrency race is told the server
broke, rather than being told to retry. A provisioning IdP has no way to know
the request is safe to repeat.

### Reproduced

`PATCH /scim/v2/Users/{id}` under concurrency logs, ~3–4% of the time:

```json
{"level":"ERROR","target":"axiam_scim::error","fields":{
  "message":"SCIM internal error","status":"500 Internal Server Error",
  "detail":"the datastore is busy; retry this request"}}
```

That `detail` is `AxiamError::WriteContention`'s own `#[error(...)]` string, which
confirms the variant reached the mapper and was swallowed by the catch-all.

The write itself is correct: the SCIM user update goes through
`retry_on_write_conflict` (`crates/axiam-db/src/repository/user.rs:491` and `:864`),
which spends `MAX_WRITE_ATTEMPTS = 4` attempts with 2/4/8 ms backoff
(`crates/axiam-db/src/helpers.rs:241-253`). Surfacing after four attempts is
**deliberate** — the constant's doc says past that, retrying "is no longer masking
a race but hiding sustained contention that should surface." Do **not** raise
`MAX_WRITE_ATTEMPTS`; the defect is the status code, not the retry budget.

---

## Change 1 — map `WriteContention` in `axiam-scim` (the actual bug)

`crates/axiam-scim/src/error.rs`.

Three parts, because a naïve arm alone still violates the contract:

1. **Add the arm**, beside the existing `ServiceUnavailable` arm at line 162:
   `AxiamError::WriteContention` → `503 Service Unavailable`.

2. **Do not redact its detail.** `ResponseError::error_response()` (line 115)
   currently redacts *every* 5xx body to `"An internal error occurred"` under
   SEC-011/CQ-B33, because 5xx details can carry DB strings. `WriteContention`'s
   message is a fixed, non-sensitive constant, and redacting it turns an
   actionable "retry this" into a dead end. Carve out this one case — keep the
   blanket redaction for every other 5xx, and keep logging.

3. **Set `Retry-After: 1`** on that response. The current builder sets no
   headers at all, so the header must be added explicitly. This is the half of
   the documented contract that makes the status code useful.

Match the shape `axiam-api-rest/src/error.rs:165` already uses so the two
surfaces agree.

### Tests (`crates/axiam-scim/src/error.rs` test module)

The existing table-driven test around line 243 already pairs `AxiamError`
variants with expected statuses — extend it, plus:

- `WriteContention` maps to `503`, **not** `500`.
- The 503 response carries `Retry-After: 1`.
- Its body detail is **not** the redacted string.
- **Control (do not skip):** `AxiamError::Database("host=db-1 user=axiam")` still
  redacts to `"An internal error occurred"` — there is already a test at line 309
  asserting this; it must keep passing. The carve-out must not widen.

---

## Change 2 — the benchmark scenario predates R-4

`benchmarks/scenarios/scim_provisioning.js` asserts `expect: 200` (line ~121) on a
scenario that is *deliberately* a single-row PATCH storm: one SCIM user is created
in `setup()`, then a ramping-VU flood PATCHes **that one row**. Its header comment
says it exists to reproduce the pre-`2d371ad4b` conflict bug.

Post-R-4 that scenario **must** produce some 503s by design, so the cell as written
can never pass. Update it to treat `503` as an acceptable outcome (ideally
asserting `Retry-After` is present), while keeping `200` the expected happy path.
Any other status stays a failure.

Note `benchmarks/runner/run-benchmark.sh:1160` is `if failed or fails: out("FAIL", …)`
— the dry-run cell verdict fires on **any** non-expected response, independently of
k6's `rate>0.99` threshold, because a dry run grades the client contract rather than
performance. So the scenario's `expect` set is the only thing that decides this cell.

---

## Explicitly out of scope

- **No SDK fan-out.** `sdks/CONTRACT.md` §16 already carries T-262 retry semantics
  as of contract 1.44. Making SCIM comply with the documented behaviour changes no
  SDK-visible surface, and the contract version does **not** need bumping.
- **Do not touch** `MAX_WRITE_ATTEMPTS`, the backoff schedule, or
  `retry_on_write_conflict`.
- **Do not touch** `axiam-api-rest` or `axiam-api-grpc` — both already correct.

---

## Verifying — read this before benchmarking, it is how the bug hid

`bench-up` defaults to `build=0` and derives `BENCH_AXIAM_IMAGE` from the workspace
version (`ghcr.io/ilpanich/axiam/server:$(grep ^version Cargo.toml)`). At a commit
whose version already has a published image, it will **silently benchmark that
stale image instead of your source**. That is exactly how this defect went
unnoticed: the published `1.0.0-beta13` image predates `3ccef6a30`, so runs against
it show 0% failures.

**Always pass `build=1`, and verify provenance before trusting a number.** The
cheap fingerprint is the startup migration count — it must match the highest
`version:` in `crates/axiam-db/src/schema.rs` (currently **62**):

```bash
docker logs bench-axiam-server 2>&1 | grep -c 'Applying migration'   # must be 62
docker inspect bench-axiam-server --format '{{.Config.Image}}'
```

A 59 there means you are measuring a pre-R-4 binary and your result is meaningless.

### Repro / verification recipe

```bash
cd benchmarks
export BENCH_TLS_PORT=18443            # 8443 is sage-gui
export BENCH_ALLOW_UNMERGED_BUILD_REF=1  # needed for a local, unpushed commit
just target=axiam profile=p2-tls13 build=1 bench-up
just target=axiam profile=p2-tls13 bench-seed
just target=axiam profile=p2-tls13 scenario=scim_provisioning dry=1 bench-run
just target=axiam bench-down           # uses `down -v`; each run starts on a fresh DB
```

Expected after the fix: the cell **PASSES**, and any contended writes appear as
`503` with `Retry-After`, not `500`. Confirm no `"SCIM internal error"` lines
remain in `docker logs bench-axiam-server`.

Because the failure is probabilistic (~3–4%), run the scenario **at least 3 times**
before concluding. A single clean run proves nothing.

---

## Build constraints on this repo

- `--no-default-features` where system libxml2 is unavailable (the `saml` feature
  pulls `libxml`); this is what CI's "Build (SAML off)" job does.
- If `target/` was wiped, `utoipa-swagger-ui` needs the egress workaround:
  `export SWAGGER_UI_DOWNLOAD_URL="file://$(scripts/make-swagger-ui-placeholder.sh)"`
- Scope cargo commands narrowly — `cargo test -p axiam-scim`, not a workspace build.
  Disk is quota-limited; `cargo clean` between steps, never during a run.
- `cargo fmt` and `cargo clippy -D warnings` on every changed crate before commit
  (`rustfmt.toml` sets `max_width = 100`).
- Crate layering is CI-enforced (`scripts/check-crate-layering.py`); this change
  stays inside `axiam-scim`, so it cannot violate it — but do not add a dependency
  to make it work.

## Commit / PR

- Signed commits, feature branch, PR referencing the issue.
- Suggested subject: `fix(scim): a contended write answers 503 with Retry-After, not 500`
- The PR body should state that this completes `3ccef6a30` (R-4, T-262), which wired
  `WriteContention` into REST and gRPC but not SCIM.
