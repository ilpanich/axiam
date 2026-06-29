# Phase 15: SDK Foundation - Context

**Gathered:** 2026-06-29
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 15 delivers the **shared, language-agnostic plumbing** that every per-language SDK (Phases 16–22) depends on. Nothing language-specific is built here.

In scope (FND-01..05):
- `--dump-openapi` flag on `axiam-server` (prints `ApiDoc` JSON, no DB/AMQP) + committed `sdks/openapi.json` + drift gate (FND-01)
- `buf`-driven gRPC codegen pipeline over `proto/axiam/v1/` with `lint`/`breaking` gates (FND-02)
- `sdks/CONTRACT.md` cross-language behavioral contract (FND-03)
- `POST /api/v1/authz/check` (+ batch) REST endpoint reusing the gRPC `AuthorizationEngine` (FND-04)
- `sdks/{rust,typescript,python,java,csharp,php,go}/` scaffold with per-SDK path-filtered CI + Apache-2.0 LICENSE (FND-05)

Out of scope: any actual SDK client logic (auth flows, refresh guards, middleware) — those are Phases 16–22. Phase 16 (Rust) is the reference implementation that **consumes** this contract.

</domain>

<decisions>
## Implementation Decisions

### Proto Codegen Delivery (FND-02)
- **D-01:** **Generate-on-build** — no buf-generated gRPC stubs are committed to git for any of the 6 buf-managed languages (Rust/TS/Go/Python/Java). Each SDK build + CI runs buf to emit stubs into a gitignored directory. C# remains the documented exception (`Grpc.Tools` MSBuild at build time).
- **D-02:** Because registry consumers (npm/PyPI/Maven/crates) cannot run buf, the **release/packaging step must regenerate-and-bundle** stubs into the published artifact. FND-02's "single documented command" for reproducible generation therefore doubles as the publish-time codegen step. Reproducibility is asserted by running that command from a clean checkout in CI.

### Drift-Gate CI Cadence (FND-01, FND-02)
- **D-03:** **Path-filtered per-PR gates** (not release-tag only). OpenAPI drift gate runs on PRs touching `crates/axiam-api-rest/**`; `buf lint` + `buf breaking` run on PRs touching `proto/**`. Catches drift at the PR that introduces it.
- **D-04:** The **release-tag re-export remains** as a final belt-and-suspenders confirm (satisfies the literal success criterion) but is no longer the first line of defense.

### REST Authz-Check Surface (FND-04)
- **D-05:** Ship **both** `POST /api/v1/authz/check` (single) **and** `POST /api/v1/authz/check/batch` (ordered list of `{action, resource_id, scope?}` → ordered results), mirroring gRPC `CheckAccess` / `BatchCheckAccess`. Batch is foundational so the browser TS `can()` (Phase 17) can render a page without N round-trips, and every later SDK inherits it uniformly.
- **D-06:** **Subject = caller by default, with admin subject-override now.** Request may carry an optional `subject_id`; when present it requires an admin-level permission and the cross-subject query is written to the audit log. Default (no `subject_id`) checks the authenticated session's own identity.
- **D-07:** **Dedicated higher rate-limit tier** for the authz-check routes (separate bucket, higher ceiling than auth/mutation endpoints), reusing the Phase-2 rate-limit middleware. Read-only permission checks are high-frequency/low-cost and must not trip the standard limiter on normal UI use.
- **D-08:** Decision logic computed via the **same `AuthorizationEngine::check_access`** as gRPC — no divergent authz path. `reason` semantics follow the existing additive-only / allow-wins / default-deny model.

### Cross-Language Contract (FND-03)
- **D-09:** `sdks/CONTRACT.md` is **normative/binding**. "Conforms to CONTRACT.md §X" becomes a verification checklist item in each downstream SDK phase (16–22).
- **D-10:** The **canonical vocabulary is locked NOW** in Phase 15, not deferred to the Rust reference: the method-name map (`login` / `verify_mfa` / `refresh` / `logout` / `check_access`+`can` / batch-check) per-language idiom, and the error taxonomy (`AuthError` / `AuthzError` / `NetworkError`) with HTTP/gRPC status mapping. Rust (Phase 16) *implements* this contract; it does not define it.

### Package / Publish Identities (FND-05 + downstream)
- **D-11:** **GitHub org / namespace base = `axiam`.** Derived identities: Maven groupId `io.axiam`, Packagist vendor `axiam/`, NuGet root `Axiam.*`, GitHub org `github.com/axiam`. Ratifies the names already written into the roadmap success criteria. (Availability/reservation of the `axiam` org + registry names is a Phase-15 ops/research verification item.)
- **D-12:** Canonical per-registry package names (ratified): Rust crate `axiam-sdk`, npm `axiam-sdk`, PyPI `axiam-sdk`, Maven `io.axiam:axiam-sdk`, NuGet `Axiam.Sdk`, Packagist `axiam/axiam-sdk`.
- **D-13:** **Go = monorepo subdir, not a split repo.** Go SDK lives at `sdks/go/` with module path **`github.com/axiam/axiam/sdks/go`**, released via tag **`sdks/go/vX.Y.Z`**. This preserves the single-monorepo model FND-05 establishes. **Roadmap fixup required:** Phase 18's `go get github.com/axiam/axiam-go-sdk` and `sdk/go/vX.Y.Z` strings must be corrected to match this reality.

### Claude's Discretion
- Exact internal structure of the `--dump-openapi` code path (subcommand vs early-return branch in `axiam-server/src/main.rs`) — implementation detail for the planner.
- gitignored output directory naming for generated stubs.
- The specific permission name that gates the admin subject-override (D-06) — to be identified by research against the existing permission registry (see canonical refs); must be an existing or newly-registered admin-scoped permission, granted on bootstrap.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase definition & requirements
- `.planning/ROADMAP.md` — Phase 15 goal, success criteria, and the v1.1 SDK milestone framing (SDKs are stateful auth clients, not codegen wrappers). **Also contains the Phase 18 Go strings that D-13 flags for fixup.**
- `.planning/REQUIREMENTS.md` — FND-01..05 acceptance criteria (the authoritative "what")

### SDK domain research (Phase 17 commit)
- `.planning/research/ARCHITECTURE.md` — codegen source-of-truth model, monorepo layout + path-filtered CI rationale (origin of FND-01/02/05)
- `.planning/research/STACK.md` — buf toolchain choice and plugin set for codegen
- `.planning/research/PITFALLS.md` — cross-language divergence trap (origin of FND-03 binding contract) and proto-codegen pitfalls relevant to D-01/D-02
- `.planning/research/FEATURES.md` — per-SDK feature matrix
- `.planning/research/SUMMARY.md` — consolidated research synthesis

### Code these requirements build on (reuse, do not reinvent)
- `crates/axiam-api-rest/src/openapi.rs` — `ApiDoc` (utoipa `#[derive(OpenApi)]`) the `--dump-openapi` flag must serialize; note `SamlApiDoc` is feature-gated (export must behave under `--no-default-features`)
- `crates/axiam-api-rest/src/tests/route_openapi_parity_test.rs` — Phase-6 route↔OpenAPI parity gate to EXTEND for the new `/authz/check` routes (FND-04 AC)
- `crates/axiam-authz/src/engine.rs:63` — `AuthorizationEngine::check_access`, the single decision path FND-04 must reuse (D-08)
- `crates/axiam-api-grpc/src/services/authorization.rs` — gRPC `check_access` / `batch_check_access` semantics the REST endpoints (D-05) mirror
- `proto/axiam/v1/authorization.proto`, `user.proto`, `token.proto` — proto surface the buf pipeline (FND-02) covers; **no `buf.yaml`/`buf.gen.yaml` exists yet**
- `crates/axiam-server/src/main.rs:103` — server entry / arg handling where `--dump-openapi` hooks in

### Project-wide constraints carried forward
- License is **Apache-2.0** repo-wide (each `sdks/<lang>/` LICENSE must match; do not trust the stale `Cargo.toml` license field) — see project memory `project_license_apache.md`
- Phase-2 rate-limit middleware is the basis for the new authz-check tier (D-07)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `ApiDoc` (utoipa) — already aggregates REST paths/schemas; `--dump-openapi` is `api_doc().to_pretty_json()` + early exit before DB/AMQP init.
- `AuthorizationEngine::check_access` — the exact engine gRPC uses; FND-04 wraps it in an Actix handler, guaranteeing no divergent authz logic.
- gRPC `check_access` / `batch_check_access` handlers — reference for request/response shape and the `AccessDecision::{Allow, Deny(reason)}` → `{allowed, reason?}` mapping.
- Phase-6 `route_openapi_parity_test.rs` — extend rather than recreate to satisfy FND-04's parity-test AC.
- Phase-2 rate-limit middleware — basis for the dedicated authz-check tier (D-07).

### Established Patterns
- utoipa `#[utoipa::path(...)]` annotations on every handler (see `handlers/groups.rs`, `handlers/tenants.rs`) — the new `/authz/check` handlers follow the same annotation pattern so they flow into the OpenAPI export automatically (FND-01 ↔ FND-04 linkage).
- SAML is feature-gated (`SamlApiDoc` merged only with `saml` feature); the `--dump-openapi` output must be deterministic regardless of feature flags (or document which feature set produces the committed `sdks/openapi.json`).
- Additive-only / allow-wins / default-deny RBAC — constrains `/authz/check` `reason` semantics.

### Integration Points
- New `sdks/` top-level directory (does not exist yet) — monorepo root for all SDK packages + shared `openapi.json`, `buf.yaml`, `buf.gen.yaml`, `CONTRACT.md`.
- New `/api/v1/authz/check` + `/api/v1/authz/check/batch` routes registered in the REST router and parity test.
- New per-SDK GitHub Actions workflows under `.github/workflows/` with `paths:` filters.

</code_context>

<specifics>
## Specific Ideas

- Browser `can()` should be cheap to call per-render — the batch endpoint (D-05) and dedicated rate-limit tier (D-07) exist specifically to support button-level permission gating in the admin UI without tripping limits.
- The C# `Grpc.Tools` build-time exception is intentional and must be documented as the one deviation from the repo-wide buf pipeline.

</specifics>

<deferred>
## Deferred Ideas

- **Conformance test harness** that mechanically verifies each SDK against CONTRACT.md — the contract is binding now (D-09), but an automated cross-language conformance suite is a future enhancement, not Phase 15. Each SDK phase verifies conformance via its own checklist for now.
- **Go vanity import path** (e.g. `go.axiam.dev/sdk`) — considered for D-13 but deferred in favor of the plain monorepo subdir path; revisit only if a cleaner public import path is wanted later (would require hosting a redirect endpoint).
- **Split-out per-SDK repos** — considered and rejected for Go (D-13); the monorepo model stands. Revisit only if monorepo CI/release friction proves untenable.

</deferred>

---

*Phase: 15-sdk-foundation*
*Context gathered: 2026-06-29*
