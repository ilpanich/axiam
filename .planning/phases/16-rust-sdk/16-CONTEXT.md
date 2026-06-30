# Phase 16: Rust SDK - Context

**Gathered:** 2026-06-30
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 16 delivers `sdks/rust/` — the **publishable `axiam-sdk` crate** and the **reference implementation** for all 7 language SDKs. It implements the full client capability baseline against the frozen v1.0 APIs:

- **REST** (reqwest 0.12) — auth flow (`login` → `verify_mfa`), `refresh`, `logout`, `check_access`/`can`, `batch_check`
- **gRPC** (tonic 0.14) — `CheckAccess`, `BatchCheckAccess`
- **AMQP** (lapin 4) — event consumer with HMAC-SHA256 verification

It conforms to `sdks/CONTRACT.md` §1–§10 in full, and its structural choices (`Sensitive<T>`, gRPC-channel/interceptor pattern, error idiom, feature layout, publish pipeline) are the **reference patterns Phases 17–22 inherit**.

**In scope (RUST-01):** the SDK crate + all three transports + Actix-Web middleware/extractor + examples + crates.io publish CI, with token-safety and single-flight concurrency proven by test.

**Out of scope:** any change to the AXIAM server itself (the v1.0 APIs are frozen — the SDK is a pure external client and MUST NOT depend on server workspace crates); the other 6 language SDKs (Phases 17–22).

</domain>

<decisions>
## Implementation Decisions

> **Note:** The bulk of the SDK's *behavioral* surface is already locked by the binding `sdks/CONTRACT.md` §1–§10 (method names, error taxonomy, CSRF, cookie jar, tenant context, TLS policy, `Sensitive<T>`, AMQP HMAC protocol, single-flight refresh, middleware interface) and by `RUST-01` (pinned crate versions). The decisions below are the **open HOW choices** resolved in this discussion. They do not restate the contract — downstream agents MUST read CONTRACT.md.

### Async Model & API Surface
- **D-01:** **Async-only (tokio).** No blocking facade. gRPC (tonic) and AMQP (lapin) are inherently async and the locked single-flight guard uses tokio primitives; a blocking wrapper would double the surface across 6 SDKs for uneven (REST-only) coverage. Users needing sync wrap with their own runtime. Sets the async-first precedent (Python's explicit sync+async in Phase 19 is the documented exception, not the norm).

### Transport Packaging (Cargo Features)
- **D-02:** **All transports on by default, each behind its own Cargo feature.** `default = ["rest", "grpc", "amqp"]` so `cargo add axiam-sdk` yields full coverage (satisfies RUST-01), but a REST-only consumer can set `default-features = false, features = ["rest"]` to drop the tonic + lapin dependency/compile cost. This modularity pattern is the analog the TypeScript persona-split (Phase 17) mirrors.

### Token Validation & Cross-Transport Auth
- **D-03:** **Local JWKS verification (EdDSA / Ed25519).** The SDK fetches + caches the server's JWKS and verifies access-token signatures and `exp` locally. This enables (a) **proactive pre-expiry refresh** on the client and (b) the §10 Actix extractor to validate sessions **without a per-request server round-trip**. Matches the JWKS libraries every other SDK pulls in (jose / PyJWT / nimbus-jose-jwt / jwx). The locked single-flight 401/`UNAUTHENTICATED` handling remains the fallback path.
- **D-04:** **gRPC auth = shared channel + interceptor.** One lazily-connected `tonic::Channel` is reused across calls. A tonic/tower interceptor reads the access token (wrapped in `Sensitive<T>`), injects `authorization` + `x-tenant-id` metadata on every RPC, and triggers the shared single-flight refresh on `UNAUTHENTICATED`. This is the "gRPC-channel pattern reused by all later SDKs" called out in RUST-01.
- **D-05:** **Token source = research-confirmed, jar-read preferred.** Tokens are delivered via httpOnly cookies (§4), but the SDK needs the raw value for JWKS verification (D-03) and gRPC metadata (D-04). Preferred path: read the access-token cookie from the `reqwest::cookie::Jar` by name. **Open research item:** confirm against the server's auth response whether SDK clients can read tokens from the jar, or whether `login`/`refresh` also return tokens in the JSON body — design the extraction accordingly. Either way, the raw token is immediately wrapped in `Sensitive<T>`.

### Error Idiom
- **D-06:** **Single `AxiamError` enum** (`thiserror`-derived) with `Auth` / `Authz` / `Network` variants (plus idiomatic sub-detail fields per §2 construction rules). One `?`-friendly return type that maps cleanly to the contract's three categories. Languages with exceptions (Java/C#/PHP) render the same three as exception classes; Rust idiom prefers the enum.

### AMQP Consumer API
- **D-07:** **Closure-handler consumer.** API shape `consume(queue, |event| async { ... })`. The SDK owns the ack/nack loop, performs §8 HMAC-SHA256 verification *before* invoking the handler, and on signature failure nacks-without-requeue + emits a security event — the handler never sees an unverified message. Ergonomic and hard to misuse for the security-sensitive nack contract (chosen over exposing a raw `Stream` that pushes ack correctness onto the user).

### Examples
- **D-08:** **Full per-capability example set** under `examples/`: one runnable example each for login+MFA, REST `check_access` (+ `batch_check` / `can`), gRPC `CheckAccess` + `BatchCheckAccess`, the AMQP consumer, and an Actix-Web route guarded by the §10 extractor. Doubles as the CONTRACT.md §1–§10 conformance demonstration that later SDKs copy.

### Publish / CI
- **D-09:** **Path-tag publish with bundle-on-publish.** `cargo publish --dry-run` gate on PRs touching `sdks/rust/**`; real publish triggered by tag `sdks/rust/vX.Y.Z` (consistent with the D-13 monorepo tag convention from Phase 15). The publish job **regenerates-and-bundles** the buf gRPC stubs (Phase 15 D-02) so crates.io consumers — who cannot run buf — get a self-contained artifact.

### MSRV
- **D-10:** **Derive MSRV from dependency floors, CI-enforced.** Set `rust-version` in Cargo.toml to the highest minimum among tonic 0.14 / reqwest 0.12 / lapin 4 / tokio, document it in the README, and add a CI job that builds on that pinned toolchain. Honest, testable floor for enterprise adopters on pinned toolchains.

### JWKS Endpoint & Cache
- **D-11:** **OIDC discovery + cache with rotation.** Fetch keys from the standard OIDC `/.well-known/jwks.json` (exact path confirmed in research against the chosen OAuth2/OIDC crate), cache with a TTL, and refetch on an unknown `kid` to handle key rotation. Matches the behavior of the other SDKs' JWKS libraries.

### Retry / Backoff
- **D-12:** **Bounded backoff, idempotent operations only.** Auto-retry only idempotent ops (GET / read-only authz checks) for transient `NetworkError` (timeouts, gRPC `UNAVAILABLE`), honoring `Retry-After` on 429, with exponential backoff + jitter and a small max attempt cap (~2–3). State-changing requests never auto-retry (no double-submit). Caller-tunable via the builder. Contract bars on auth retries (no retry on 5xx-auth, no refresh-failure loop) remain in force.

### Observability / Tracing
- **D-13:** **`tracing` spans, feature-gated OFF by default.** Instrument the request lifecycle, refresh, gRPC calls, and AMQP verify with `tracing` spans/events behind an `observability` (or similar) feature, off by default for a leaner baseline build. Instrumentation MUST be redaction-aware — never emit token values (respect `Sensitive<T>`). *(User chose off-by-default; differs from the on-by-default suggestion.)*

### Timeouts & Config Defaults
- **D-14:** **Sane defaults, builder-overridable.** Ship reasonable connect/request timeouts (e.g. ~10s connect / ~30s request — exact values planner/research), lapin auto-reconnect with backoff, `base_url` required, all overridable via the client builder. Concrete construction defaults the other SDKs mirror.

### Claude's Discretion
- Exact module/file layout of the crate (e.g. `rest`/`grpc`/`amqp`/`auth`/`middleware` submodules), naming of the `Sensitive<T>` accessor, and internal organization of the single-flight guard implementation — planner's call within the locked contract.
- Specific numeric timeout/backoff values and max-attempt counts (D-12, D-14) — research/planner picks within the stated shape.
- Whether the `tracing` feature is named `observability`, `tracing`, or `tower-tracing` (D-13).
- Choice of OAuth2/OIDC + JWKS crate for D-03/D-11 — research selects (must support Ed25519/EdDSA JWKS verification).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Binding contract & phase definition (read FIRST)
- `sdks/CONTRACT.md` §1–§10 — **normative/binding** cross-language behavioral contract. The Rust SDK *implements* this; it does not redefine it. §1 method map, §2 error taxonomy + status mapping, §3 CSRF, §4 cookie jar, §5 tenant context, §6 TLS policy, §7 `Sensitive<T>`, §8 AMQP HMAC protocol, §9 single-flight refresh, §10 middleware interface.
- `.planning/ROADMAP.md` — Phase 16 goal + 5 success criteria; v1.1 SDK milestone framing ("SDKs are stateful auth clients, not codegen wrappers"); the D-13 monorepo tag convention this phase's publish CI follows.
- `.planning/REQUIREMENTS.md` §RUST-01 — acceptance criteria + pinned crate versions (reqwest 0.12 / tonic 0.14 / lapin 4, pinned to server workspace).

### Prior-phase decisions this phase inherits
- `.planning/phases/15-sdk-foundation/15-CONTEXT.md` — D-01/D-02 (generate-on-build buf codegen; regenerate-and-bundle stubs at publish, basis for D-09), D-09/D-10 (binding contract + locked vocabulary), D-11/D-12/D-13 (package identities: crate `axiam-sdk`, monorepo tag scheme).

### SDK domain research (Phase 17 commit — read for rationale)
- `.planning/research/ARCHITECTURE.md` — codegen source-of-truth, monorepo + path-filtered CI rationale.
- `.planning/research/STACK.md` — buf toolchain + plugin set for gRPC codegen.
- `.planning/research/PITFALLS.md` — cross-language divergence trap + proto-codegen pitfalls (relevant to D-09 bundling).
- `.planning/research/FEATURES.md` — per-SDK feature matrix.
- `.planning/research/SUMMARY.md` — consolidated research synthesis.

### Server code the SDK consumes / mirrors (reuse semantics, do NOT depend on these crates)
- `crates/axiam-amqp/src/messages.rs` — **AMQP HMAC reference impl** (§8): `sign_payload`, `verify_payload` (constant-time via `hmac` crate `verify_slice`), `hmac_signature` field on `AuthzRequest` / `AuditEventMessage`. The SDK's verify (D-07) must match this canonical JSON + HMAC-SHA256 protocol exactly.
- `proto/axiam/v1/authorization.proto`, `user.proto`, `token.proto` — proto surface the buf gRPC codegen covers (D-09); `CheckAccess`/`BatchCheckAccess` request/response shapes for D-04.
- `crates/axiam-api-grpc/src/services/authorization.rs` — gRPC `check_access`/`batch_check_access` semantics the SDK's gRPC client targets.
- REST `POST /api/v1/authz/check` + `/api/v1/authz/check/batch` (Phase 15 FND-04) — the endpoints `check_access`/`can`/`batch_check` call.
- OIDC `/.well-known/jwks.json` (path to confirm) — JWKS source for D-03/D-11 local verification.

### Project-wide constraints
- License is **Apache-2.0** repo-wide — `sdks/rust/LICENSE` must match (do not trust the stale workspace `Cargo.toml` license field); see project memory `project_license_apache.md`.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/axiam-amqp/src/messages.rs` — HMAC sign/verify reference (`verify_payload` constant-time). The SDK reimplements *verification* client-side (it cannot depend on the server crate), but the canonical-JSON + hex-HMAC-SHA256 protocol must be byte-identical (§8 / D-07).
- The buf gRPC codegen pipeline + `proto/axiam/v1/*.proto` (Phase 15) — the SDK runs `buf generate` into a gitignored dir at build time and bundles stubs at publish (D-09).
- `sdks/rust/` scaffold already exists (`Cargo.toml` with metadata, `src/lib.rs` doc-only placeholder, Apache-2.0 LICENSE, README stating "conforms to CONTRACT.md §1–§10") — Phase 16 fills it in.

### Established Patterns
- **CONTRACT.md is binding (Phase 15 D-09):** "CONTRACT.md §1–§10 conformance verified" is a required acceptance checklist item for this phase.
- **`reqwest::cookie::Jar`** per-client cookie persistence (§4) is the session mechanism; D-05 reads tokens from it.
- **Additive-only / allow-wins / default-deny RBAC** constrains how the SDK surfaces authz `reason` semantics (mirrors gRPC).
- **Monorepo tag release** (`sdks/<lang>/vX.Y.Z`, Phase 15 D-13) — D-09 follows it.

### Integration Points
- New `sdks/rust/` source tree (crate body, `examples/`, transport submodules).
- New per-SDK GitHub Actions workflow under `.github/workflows/` with `paths: sdks/rust/**` filter (dry-run gate + tag-triggered publish, D-09).
- gRPC stubs generated from `proto/axiam/v1/` via buf into a gitignored dir.

</code_context>

<specifics>
## Specific Ideas

- The Rust SDK is explicitly the **reference**: every structural decision here (D-01..D-14) is chosen for *reusability across the other 6 SDKs*, not just Rust ergonomics. When a choice is Rust-idiomatic-only, note the cross-language analog (e.g. single `AxiamError` enum → exception classes elsewhere).
- Success-criterion proof points to preserve as concrete tests: (#2) 5 concurrent requests on an expired token ⇒ exactly 1 refresh call (single-flight); (#3) `grep -r 'eyJ' target/debug/` returns empty in CI (`Sensitive<T>` redaction); (#4) AMQP nacks-without-requeue on HMAC mismatch; (#5) `cargo publish --dry-run` succeeds.

</specifics>

<deferred>
## Deferred Ideas

- **Blocking/sync facade** for the Rust SDK — considered (D-01) and rejected for the reference; revisit only if user demand for a non-async REST surface emerges. (Python ships sync+async by design in Phase 19; that's the documented exception.)
- **On-by-default tracing** — considered for D-13 but user chose feature-gated-off; revisit if diagnostics-by-default becomes a cross-SDK expectation.
- **Async `Stream`-based AMQP consumer** — considered (D-07) for composability; deferred in favor of the safer closure-handler. Revisit if advanced users need stream composition.
- **Automated cross-language conformance harness** — inherited from Phase 15 deferred list; Phase 16 verifies conformance via its own §1–§10 checklist, not a mechanical suite.

</deferred>

---

*Phase: 16-rust-sdk*
*Context gathered: 2026-06-30*
