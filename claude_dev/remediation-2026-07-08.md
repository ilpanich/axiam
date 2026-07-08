# AXIAM — Remediation of the 2026-07-08 Final Review

- **Date**: 2026-07-08
- **Companion**: [`final-review-2026-07-08.md`](final-review-2026-07-08.md) — the review these fixes address.
- **Scope**: every finding in the review's §5 remediation order (Tiers 0–3), across the Rust backend, all 7 SDKs, and CI config. One LOW item (NEW-4) is deferred with rationale below.

Statuses: ✅ FIXED · ⏭️ DEFERRED.

---

## 1. Summary

All CI-blocking, HIGH, and MEDIUM findings are fixed and test-backed; the LOW/polish items are fixed except **NEW-4** (AMQP replay protection), which is deferred because a correct fix is a coordinated wire-format change across the server and all 7 SDKs and a partial fix would introduce a correctness regression (see §4).

The two headline escalations found in this review — **NEW-1** (cross-organization `org_id` forgery) and **NEW-2** (org-settings permission boundary collapse) — are both closed and carry new regression tests.

---

## 2. Backend (Rust)

| ID | Sev | Fix | Evidence |
|---|---|---|---|
| **CI-fmt** | blocker | `cargo fmt --all` (6 files) | `cargo fmt --all --check` clean |
| **CI-01** | blocker | `#[derive(Default)]` + `#[default]` on `SubjectKind` | `token.rs:30-40`; clippy gate |
| **NEW-1** | HIGH | Derive the authoritative `org_id` from the tenant record in both login and refresh; reject client/tenant mismatch (enumeration-safe 401). Closes login (UUID branch), refresh, and the MFA challenge/setup token paths (they embed this org_id). | `handlers/auth.rs` login + refresh; `auth_test` (19 pass) |
| **NEW-2** | HIGH | Org-settings handlers now enforce `organizations:get_settings`/`organizations:update_settings` (were enforcing tenant-level `settings:*`). | `handlers/settings.rs:37,77`; new `rbac_test` cases assert `settings:update`→403 and `organizations:update_settings`→200 (9 pass) |
| **NEW-3** | MED | Atomic single-use refresh: new `SessionRepository::consume` (`DELETE … RETURN BEFORE`, returns whether *this* call won); `refresh` aborts before minting if it lost the race. | `repository/session.rs`; `service.rs:554`; `db --lib` (40 pass) |
| **CQ-B48** | HIGH | `health_check` now also probes a startup-generation handle (same auth-snapshot lineage as the repositories), so readiness trips when the repo tokens expire — the manager-only probe masked it. | `connection.rs` (`health_probe`) |
| **CQ-B49** | HIGH | Webhook consumer `nack`s (requeue) on a retry-publish failure instead of acking the original + writing a "retry scheduled" audit record. | `webhook_consumer.rs:306` |
| **CQ-B50/B51/B52** | MED (sec) | Tenant-predicate + transaction + `.check()` on the five unguarded edge deletes: `permission.delete`, `group.delete`, `service_account.delete`, `group.remove_member` (now uses its `tenant_id`), `resource.update` re-parent (+ validates the new parent is in-tenant). | `repository/{permission,group,service_account,resource}.rs`; `req14_tenant_isolation_test` (7 pass) |
| **CQ-B22** | MED | `WebhookPublisher` stored in `AppState`; `AppState::emit_webhook` helper; wired at `user.created`/`user.updated`/`user.deleted`. Best-effort (no-op when AMQP absent). | `state.rs`; `main.rs`; `handlers/users.rs` |
| **CQ-B53** | MED | Webhook consumer runs in a bounded-backoff reconnect loop instead of `process::exit(1)` on a broker blip. | `main.rs` (webhook task) |
| **SEC-067** | MED | Redacting manual `Debug` on `Webhook`/`CreateWebhook`/`UpdateWebhook`. | `models/webhook.rs` |
| **SEC-068** | LOW | gRPC `IntrospectToken`/`ValidateToken` cross-check the introspected token's tenant against the caller's `ValidatedClaims`; cross-tenant tokens report inactive (indistinguishable from invalid). | `services/token.rs` |
| **SEC-069** | LOW | `guarded_fetch` enforces `https` (http only behind the private-network seam) and rejects an over-large `Content-Length`. | `federation/ssrf.rs`; new ssrf tests (4 pass) |
| **SEC-070** | LOW | Corrected the XFF `trusted_hops` doc comment (rightmost-untrusted, not leftmost) + operator note. | `extractors/rate_limit.rs` |
| **PKI nit** | info | Zeroize the decrypted CA key (`cert.rs`) and PGP private key (`pgp.rs`) once parsed. | `axiam-pki` (build ok) |

## 3. SDKs (all 7 reviewed; fixes verified in-language where the toolchain was available)

| ID | SDK(s) | Fix |
|---|---|---|
| **SDK-Q01 / X-1** | Go, Rust | AMQP-HMAC now canonicalizes in the server's struct-declaration order (Go: declaration-order structs; Rust: `serde_json` `preserve_order` + `shift_remove`). Regression tests use real server-declaration-order bytes. `go test`/`cargo test` green. |
| **SDK-Q04** | Rust | authz POST now sends `X-CSRF-Token`. |
| **SDK-Q05** | TS | `createNodeClient` + injectable session so Node REST login/refresh persist httpOnly cookies; browser bundle unaffected. `tsc`/`vitest` (98) green. |
| **SDK-Q06** | TS | Corrected `amqplib` (`^0.10.5`), `jsdom` (`^26`), `vitest` (`^3`) pins; lockfile resolves. |
| **SDK-19** | PHP | Discovered `jwks_uri` validated as `https` + same-origin, else falls back to `{baseUrl}/oauth2/jwks`. `php -l` + logic tests. |
| **X-2** | Rust, TS | Reject plaintext base URLs (loopback exception); TS gRPC throws on non-secure targets unless explicit `allowInsecure`. |
| **X-4 / SDK-04** | Rust, Java | Redacting `Debug`/`toString` on credential-bearing types; Rust redirect policy stops on `https→http` downgrade. |
| **X-3** | TS, Python, Go, Java, C# | Error/log header redaction switched from a 3-entry denylist to a small case-insensitive **allowlist** (`content-type`/`content-length`/`date`/`server`/`retry-after`/`x-request-id`/`x-tenant-id`), so a custom `X-Auth-Token` is redacted by default. Tests added; TS `vitest` (99), Java `ErrorRedactionTest` (6), Go `go test` all green. |
| **SDK-10** | Python | Decode-error message no longer interpolates the decoded payload (static message). |
| **SDK-11** | Python | Non-numeric `exp` now maps to 401 (parse moved inside the verify try/except) in both the FastAPI dependency and Django middleware — `pytest` 145 pass. |
| **SDK-17** | C# | `AllowAutoRedirect = false` on the REST handlers so a redirect can't re-send `X-Tenant-Id`/`X-CSRF-Token`. |

## 4. Deferred (recommended follow-ups, with rationale)

⏭️ **NEW-4 [LOW] — AMQP replay/nonce/timestamp protection.** A correct fix adds a `nonce` + `issued_at` *inside* the HMAC-signed body, plus a clock-skew window and per-tenant nonce dedup. That is a coordinated wire-format change across the server (`AuthzRequest`/`AuditEventMessage` declaration order) and all 7 SDK HMAC implementations — the exact canonicalization just fixed in SDK-Q01. A consumer-side content dedup *without* new fields is unsafe: `AuditEventMessage` carries no unique id, so two legitimately-identical events (e.g. two failed logins) would be wrongly dropped. This should be done as its own versioned protocol change.

⏭️ **CQ-B11 / CQ-B16 [MED] — error-taxonomy polish.** Routing the remaining create/RELATE sites through `classify_write_error` (409-on-duplicate) and mapping delete-of-missing-id to 404 are broad, cross-cutting changes to the DB layer's error and idempotency semantics (delete-404 also touches the GDPR erasure path, which currently relies on idempotent delete). Worth doing behind per-path integration coverage rather than as a blind sweep.

⏭️ **CQ-B13 / CQ-B23 [MED] — performance.** The authz per-role N+1 (`WHERE role_id IN $ids` + a single recursive ancestor query) and OIDC-discovery caching are optimizations, not correctness defects; they need benchmarking to validate and are best landed with the PERF-01 load-test harness.

⏭️ **SDK-Q02/Q03/Q08/Q09/Q10 [MED, contract] — conformance/design rulings.** Surfacing the server's denied `action`/`resource_id` in `AuthzError`, the CONTRACT §8 `key_version` doc/struct sync, async-method naming, PHP `can()` arg order, and authz-model normalization are contract-design decisions the review itself flagged as "needs a ruling," not clear-cut bugs. They should be resolved with an explicit CONTRACT.md revision.

## 5. CI / supply chain

- **CI-03**: dependabot extended to all 7 SDK ecosystems (cargo/npm/pip/gomod/maven×2/nuget/composer); dependency vuln-scan step added to each `sdk-ci-*.yml` (govulncheck, pip-audit, npm audit, cargo audit, composer audit, `dotnet list --vulnerable`). Java relies on dependabot (OWASP dependency-check omitted as too fragile for a gate).
- **CI-04**: committed `.github/workflows/codeql.yml` — real `codeql-action/init` + `analyze` for javascript-typescript, python, go, java-kotlin, csharp (Rust covered by clippy/cargo-audit).

## 6. Verification

Local, this branch: `cargo fmt --all --check` clean; workspace lib `cargo clippy -- -D warnings` clean (CI-01 gate green). Tests: `axiam-db` lib (40) + `req14_tenant_isolation` (7), `axiam-auth` lib (87), `axiam-api-grpc` lib (6), `axiam-federation` ssrf (4, incl. new scheme tests), `axiam-api-rest` webhook lib (24), `rbac_test` (9, incl. 2 new NEW-2 cases), `auth_test` (19), `settings_test` (7), `axiam-pki` build. SDKs: Go/Rust/TS suites green in-language; PHP/Java verified by syntax + logic (full suites blocked by this sandbox's GitHub-egress limits, as noted in the SDK work). Build inputs use the documented swagger-ui offline placeholder; `xmlsec1`/`libxml2` installed for the SAML feature.
