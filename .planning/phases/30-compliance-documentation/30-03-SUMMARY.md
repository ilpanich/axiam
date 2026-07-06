---
phase: 30-compliance-documentation
plan: 03
subsystem: api
tags: [asyncapi, openapi, grpc, amqp, rabbitmq, tonic, protobuf, docs]

# Dependency graph
requires:
  - phase: 30-compliance-documentation (30-01, 30-02)
    provides: security-audit.md master doc + GDPR compliance doc conventions (v1.2/beta version-stamp pattern, citation-over-duplication style)
provides:
  - "docs/api/asyncapi.yml — hand-authored AsyncAPI 2.6 spec covering all 11 AMQP queues (incl. 4 DLQs + the webhook TTL-retry queue) and all 6 message types from crates/axiam-amqp/src/messages.rs"
  - "docs/api/openapi.json — symlink to sdks/openapi.json (single source of truth, zero duplication)"
  - "docs/api/grpc.md — usage guide for the 3 gRPC services (AuthorizationService/TokenService/UserService)"
  - "docs/api/README.md — landing page for REST/gRPC/AMQP with view instructions"
  - "sdks/openapi.json refreshed — was stale (missing federation-sso OIDC start/callback + org/tenant email-config endpoints and several schema updates)"
affects: [30-04-deployment-admin-pki-guides, 30-05-docs-readme-link-check, 30-06-docs-ci]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "AsyncAPI 2.6 channel-per-queue with bindings.amqp queue metadata + $ref'd components.messages/schemas, mirroring the utoipa OpenAPI aggregator's title/description/version info-block convention"
    - "Symlinked docs artifact (docs/api/openapi.json -> ../../sdks/openapi.json) as the D-09 'single source of truth, link-out, no duplication' pattern applied to a binary/generated artifact rather than prose"

key-files:
  created:
    - docs/api/asyncapi.yml
    - docs/api/openapi.json (symlink)
    - docs/api/grpc.md
    - docs/api/README.md
  modified:
    - sdks/openapi.json

key-decisions:
  - "Regenerated sdks/openapi.json rather than leaving the symlink pointing at a stale spec — the committed spec had drifted (missing federation-sso OIDC endpoints, org/tenant email-config endpoints, and several schema field changes) since it was last updated 2026-07-03; a fresh --dump-openapi (--no-default-features, matching the drift gate's exact feature set) replaced it byte-for-byte so the new docs/api/openapi.json symlink is accurate"
  - "Modeled the DLQ queues (axiam.authz.request.dlq / axiam.audit.events.dlq / axiam.mail.outbound.dlq / axiam.webhook.dlq) as AsyncAPI channels with a publish operation reusing the same message schema as their primary queue, with a description noting they are not consumed by the running application in normal operation — this documents the fail-closed dead-letter chain (T-30-07 mitigation) without inventing a separate schema"
  - "Modeled axiam.webhook.retry as a publish-only channel (AXIAM publishes with a per-message TTL; no application ever subscribes) per the RESEARCH.md direction table, documenting the RabbitMQ-native delayed-retry mechanism in the channel description since AsyncAPI 2.6 has no first-class TTL/delay concept"

requirements-completed: [DOCS-01]

coverage:
  - id: D1
    description: "docs/api/asyncapi.yml — valid AsyncAPI 2.6 YAML transcribing every AMQP queue/message from messages.rs + connection.rs field-for-field, with HMAC/fail-closed convention documented"
    requirement: DOCS-01
    verification:
      - kind: other
        ref: "python3 -c \"import yaml; yaml.safe_load(open('docs/api/asyncapi.yml'))\" && grep -Eq '^asyncapi: *\"?2\\.6' docs/api/asyncapi.yml && grep -q 'axiam.authz.request' docs/api/asyncapi.yml && grep -q 'axiam.webhook.retry' docs/api/asyncapi.yml && grep -q 'AuthzRequest' docs/api/asyncapi.yml && grep -q 'hmac_signature' docs/api/asyncapi.yml"
        status: pass
    human_judgment: false
  - id: D2
    description: "docs/api/openapi.json published as a valid-JSON symlink to the drift-gated sdks/openapi.json, refreshed to be current"
    requirement: DOCS-01
    verification:
      - kind: other
        ref: "jq empty docs/api/openapi.json && test -L docs/api/openapi.json"
        status: pass
      - kind: other
        ref: "cargo build -p axiam-server --no-default-features && ./target/debug/axiam-server --dump-openapi | diff sdks/openapi.json -"
        status: pass
    human_judgment: false
  - id: D3
    description: "docs/api/grpc.md references all 3 proto files with a usage guide; docs/api/README.md overviews REST/gRPC/AMQP with view instructions, notes the AsyncAPI manual-snapshot caveat, both stamped v1.2"
    requirement: DOCS-01
    verification:
      - kind: other
        ref: "test -f docs/api/grpc.md && test -f docs/api/README.md && grep -q 'authorization.proto' docs/api/grpc.md && grep -q 'asyncapi.yml' docs/api/README.md && grep -q 'openapi.json' docs/api/README.md && grep -Eq 'v1\\.2' docs/api/README.md"
        status: pass
    human_judgment: false

duration: 30min
completed: 2026-07-06
status: complete
---

# Phase 30 Plan 03: API Contract Docs Consolidation Summary

**Consolidated REST/gRPC/AMQP API contracts under `docs/api/`: hand-authored a full AsyncAPI 2.6 spec for the AMQP surface, published the REST OpenAPI spec as a drift-gated symlink (refreshing it after finding it was stale), and wrote a gRPC usage guide + overview README — no new in-app Swagger UI.**

## Performance

- **Duration:** ~30 min (includes a ~4 min scoped `cargo build -p axiam-server --no-default-features`)
- **Completed:** 2026-07-06
- **Tasks:** 3
- **Files modified:** 5 (4 created, 1 refreshed)

## Accomplishments
- `docs/api/asyncapi.yml`: a self-contained, offline-validatable AsyncAPI 2.6.0 document covering all 11 real AMQP queues (`axiam.authz.request(+.dlq)`, `axiam.authz.response`, `axiam.audit.events(+.dlq)`, `axiam.notifications`, `axiam.mail.outbound(+.dlq)`, `axiam.webhook`, `axiam.webhook.retry`, `axiam.webhook.dlq`) and all 6 message types (`AuthzRequest`, `AuthzResponse`, `AuditEventMessage`, `NotificationEvent`, `OutboundMailMessage`, `WebhookMessage`), transcribed field-for-field from `crates/axiam-amqp/src/messages.rs` + `crates/axiam-core/src/models/mail.rs`, with the HMAC-SHA256 fail-closed signing convention and the webhook DLQ/retry chain documented in message/channel descriptions.
- `docs/api/openapi.json`: published as a relative symlink to `../../sdks/openapi.json` (D-09/D-10 — zero duplication, existing `sdk-openapi-drift.yml` remains the single drift gate). Discovered during verification that the committed `sdks/openapi.json` had drifted from the live API (missing the federation-sso OIDC start/callback endpoints and org/tenant email-config endpoints added since it was last regenerated); regenerated it via a scoped `--no-default-features` build + `--dump-openapi`, matching the CI drift gate's exact mechanism, so the new symlink target is accurate.
- `docs/api/grpc.md`: usage guide naming all three `.proto` files (`authorization.proto` / `token.proto` / `user.proto`), summarizing `AuthorizationService`/`TokenService`/`UserService`, the default gRPC bind address/port, and how SDKs consume pre-generated stubs via `buf generate` (Rust/TypeScript/Go) or language-specific codegen (Python/Java/PHP).
- `docs/api/README.md`: docs/api landing page overviewing all three protocols with concrete "how to view" instructions (external Swagger/Redoc for REST, AsyncAPI Studio/CLI for AMQP, proto reference for gRPC), explicitly flagging `asyncapi.yml` as a hand-authored snapshot requiring manual re-verification on `messages.rs` changes (Pitfall 3), stamped v1.2 Beta / last-verified 2026-07-06.

## Task Commits

Each task was committed atomically:

1. **Task 1: Hand-author docs/api/asyncapi.yml** - `d2d96ec` (docs)
2. **Task 2: Publish docs/api/openapi.json as symlink + refresh sdks/openapi.json** - `297c258` (docs)
3. **Task 3: Author docs/api/grpc.md + docs/api/README.md** - `6ccb7d5` (docs)

**Plan metadata:** pending (this commit)

## Files Created/Modified
- `docs/api/asyncapi.yml` - net-new AsyncAPI 2.6 spec for the AMQP surface
- `docs/api/openapi.json` - new symlink -> `../../sdks/openapi.json`
- `sdks/openapi.json` - refreshed via fresh `--dump-openapi` (was stale)
- `docs/api/grpc.md` - new gRPC usage guide
- `docs/api/README.md` - new docs/api landing page

## Decisions Made
- Regenerated `sdks/openapi.json` in-place rather than leaving the new symlink pointing at a spec that no longer matched the live API — this was explicitly anticipated by the plan's Task 2 action ("if it drifts, regenerate ... so the symlink target is accurate") and used the drift gate's exact build command (`cargo build -p axiam-server --no-default-features`) to stay CI-consistent.
- DLQ queues and the webhook retry queue were modeled as `publish`-only AsyncAPI channels (the application enqueues/dead-letters into them; nothing in AXIAM actively consumes them in normal operation) with a description noting they exist for operator inspection/replay — this keeps the spec accurate to the real consumer topology in `connection.rs` rather than implying a live subscriber on every queue.
- `docs/api/README.md` and `docs/api/grpc.md` forward-reference `docs/deployment/README.md` and `docs/README.md`, which don't exist yet at this point in the phase — confirmed both are created by later plans in this same phase (30-04 and 30-05 respectively, per their `files_modified` frontmatter) before phase-level link-checking (30-05's `check-doc-links.sh`, 30-06's `docs-ci.yml`) runs, so the links will resolve by the time they're validated.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Regenerated stale `sdks/openapi.json`**
- **Found during:** Task 2 (publish `docs/api/openapi.json` symlink)
- **Issue:** The plan's own acceptance criteria required confirming `sdks/openapi.json` is current via a fresh `--dump-openapi` diff. A fresh build (scoped `--no-default-features`, matching the CI drift gate exactly) diffed non-clean against the committed spec — missing the federation-sso OIDC start/callback endpoints, org/tenant email-config endpoints, and several schema field changes (e.g. `ResetPasswordRequest` slug fields, `WebhookMessage`-adjacent `SmtpConfig`/`SsoLoginSuccessResponse` schemas) that had landed in prior phases without a corresponding `sdks/openapi.json` regeneration.
- **Fix:** Overwrote `sdks/openapi.json` with the fresh `--dump-openapi` output; re-diffed to confirm byte-identical match. This is exactly the "regenerate sdks/openapi.json ... so the symlink target is accurate" branch the plan's Task 2 action already called for — not an out-of-scope change.
- **Files modified:** `sdks/openapi.json`
- **Verification:** `diff sdks/openapi.json <(./target/debug/axiam-server --dump-openapi)` — clean.
- **Committed in:** `297c258` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1, explicitly anticipated by the plan's own task instructions)
**Impact on plan:** No scope creep — the fix keeps the newly-published `docs/api/openapi.json` symlink accurate, which is the entire point of Task 2. `sdks/openapi.json`'s existing CI drift gate (`sdk-openapi-drift.yml`) will now pass again on the next PR touching REST/server crates instead of already failing on drift accumulated before this plan ran.

## Issues Encountered
None beyond the drift documented above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- `docs/api/` is complete and self-consistent (REST/gRPC/AMQP), ready to be linked from `docs/README.md` (30-05) and validated by `docs-ci.yml` (30-06, spec-validate + link-check).
- No blockers for 30-04 (deployment/admin/PKI guides), which is independent of this plan's artifacts.

---
*Phase: 30-compliance-documentation*
*Completed: 2026-07-06*

## Self-Check: PASSED

All created files verified present on disk (`docs/api/asyncapi.yml`, `docs/api/openapi.json`, `docs/api/grpc.md`, `docs/api/README.md`, this SUMMARY). All task commits (`d2d96ec`, `297c258`, `6ccb7d5`, `000b857`) verified present in `git log`.
