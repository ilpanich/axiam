# Phase 30: Compliance & Documentation - Pattern Map

**Mapped:** 2026-07-06
**Files analyzed:** 11 net-new/modified artifacts (predominantly docs, one AsyncAPI spec, one CI workflow, one script)
**Analogs found:** 10 / 11 (1 genuinely net-new format: AsyncAPI — analog is structural, not codebase-native)

This is a **verify + document** phase, not a build phase. There is effectively
no new Rust/product code to pattern-match against controller/service/model
conventions — the "files" here are markdown docs, one YAML spec, one CI
workflow, and one shell/script. Patterns below are about **document
structure, tone, version-stamping, and CI/workflow conventions**, not code
architecture.

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `claude_dev/security-audit.md` | doc (compliance master) | transform (citation/aggregation) | `docs/compliance/asvs-l2-checklist.md` + `claude_dev/security-review-postremediation.md` | role-match (structure + tone) |
| `docs/api/asyncapi.yml` | config/spec (API contract) | transform (hand-authored from Rust structs) | `crates/axiam-amqp/src/messages.rs` (source of truth for schema); `sdks/openapi.json` (sibling spec-file convention) | partial-match (format itself is net-new to repo) |
| `docs/api/openapi.json` | config (generated artifact, symlink or republish) | batch (regenerate via existing dump mechanism) | `sdks/openapi.json` + `.github/workflows/sdk-openapi-drift.yml` | exact (same artifact, same mechanism) |
| `docs/api/README.md` | doc (index/landing, section) | transform | `sdks/rust/README.md` (heading/tone convention) + this phase's own `docs/README.md` | role-match |
| `docs/api/grpc.md` | doc (reference guide) | transform | `proto/axiam/v1/*.proto` (source), `docs/api/README.md` (sibling style) | role-match |
| `docs/README.md` | doc (top-level index) | transform (link-out aggregator) | 7 `sdks/*/README.md` headers (heading/tone convention); no existing top-level docs index to copy structure from directly | partial-match |
| `docs/deployment/README.md` | doc (operator guide) | transform | `k8s/network-policy/*.yml`, `k8s/server/secret.yml`, `docker/docker-compose.prod.yml` (source data); no existing deployment-guide doc as prose analog | partial-match |
| `docs/admin/README.md` | doc (operator/task guide) | transform | `crates/axiam-api-rest/src/handlers/organizations.rs` / bootstrap flow (source); no existing prose admin guide | partial-match |
| `docs/pki/README.md` | doc (operator/task guide) | transform | `crates/axiam-api-rest/src/handlers/{certificates,ca_certificates}.rs` (source); `crates/axiam-pki/` (source) | partial-match |
| `scripts/check-doc-links.py` (or `.sh`) | utility (CI link-checker) | batch/transform | `scripts/e2e-bootstrap.sh` (existing scripts/ convention: standalone, invoked by CI/just) | role-match |
| `.github/workflows/docs-ci.yml` | config (CI workflow) | event-driven (path-filtered trigger) | `.github/workflows/sdk-openapi-drift.yml` (near-identical shape: path-filtered PR+push trigger, SHA-pinned actions, single validation job) | exact |

## Pattern Assignments

### `claude_dev/security-audit.md` (doc, transform/citation)

**Analogs:** `docs/compliance/asvs-l2-checklist.md`, `docs/compliance/FINDINGS.md`, `claude_dev/security-review-postremediation.md`

**Header/version-stamp pattern** (`docs/compliance/asvs-l2-checklist.md` lines 1-16):
```markdown
# OWASP ASVS Level 2 Checklist — AXIAM IAM

**Standard:** OWASP Application Security Verification Standard v4.0.3, Level 2

**Scope (D-02):** V2 (Authentication), V3 (Session Management), V4 (Access Control),
V6 (Stored Cryptography), V7 (Error Handling / Logging), V8 (Data Protection),
V9 (Communications), V10 (Malicious Code), V14 (Configuration).

**Out of scope:** V1 (Architecture), V5 (Validation), V11 (Business Logic), V12 (Files),
V13 (API), V15 (Build).

**Status values:** Pass / N/A / Deferred (see FINDINGS.md #N)

**Compliance assertion:** All in-scope controls below have an explicit status.
**Every control is Pass, N/A, or Deferred — zero controls lack a status.** No High-severity Deferred row.
```
→ Copy this "Standard / Scope / Out-of-scope / Status-values / Compliance-assertion" preamble shape for `security-audit.md`'s own header, adapted to cite ASVS+ISO27001+CyberSecurity Act as three cited standards rather than one authored one (per D-01/D-02, `security-audit.md` is the aggregator, this file is what it points into).

**Findings-register row pattern** (`docs/compliance/FINDINGS.md` lines 1-12):
```markdown
**Schema:** Each row is one finding. Status is either Fixed (with commit) or Deferred
(with rationale and tracking issue).

| # | Finding | Severity | ASVS / RFC Ref | Status | Disposition |
|---|---------|----------|---------------|--------|-------------|
| F-01 | WWW-Authenticate header absent on 401 ... | Low | RFC 6749 §5.2 | **Fixed** | Inline fix (D-04) in `build_oauth2_error_response`... |
```
→ Use this exact row shape for `security-audit.md` §7 "Open Items / Deferred Findings", cross-referencing `FINDINGS.md` rows by `#` and adding a v1.2 REQ-ID column per D-01/D-03.

**Provenance/versioning + status-glyph pattern** (`claude_dev/security-review-postremediation.md` lines 1-9):
```markdown
- **Date**: 2026-07-01
- **Commit reviewed**: `ea85872` (HEAD of `claude/post-remediation-review-994pto`)
- **Baseline**: the previous review at `d69323b` ([`security-review.md`](security-review.md))...
- **Method**: per-finding re-verification of every active `SEC-*` finding against current code with file:line evidence...
Statuses: ✅ FIXED (verified), 🔶 PARTIAL (core improved, residual risk), ❌ OPEN.
```
→ Adopt the "Date / Commit reviewed / Baseline / Method" metadata block convention (D-12's "last verified" stamp) and the ✅/🔶/❌ glyph convention for pass/partial/fail rows if `security-audit.md` wants visual scannability beyond the plain-table style of `asvs-l2-checklist.md`. Either table style is acceptable — pick one and be consistent.

**Citation-not-duplication anti-pattern reminder:** every row in the new doc must be a one-line summary + link (e.g. `| A.8.24 Cryptography | Pass | See docs/compliance/asvs-l2-checklist.md#v6-v8-rows |`), never a re-transcription of checklist prose — see RESEARCH.md `## security-audit.md Master-Doc Structure` and `Pitfall 2`.

---

### `docs/api/asyncapi.yml` (spec, transform — hand-authored)

**Source of truth (schema fields):** `crates/axiam-amqp/src/messages.rs`

Confirmed struct shapes to transcribe field-for-field into AsyncAPI `payload` schemas:
```rust
// messages.rs lines 125-146 — AuthzRequest
pub struct AuthzRequest {
    pub correlation_id: Uuid,
    pub tenant_id: Uuid,
    pub subject_id: Uuid,
    pub action: String,
    pub resource_id: Uuid,
    pub scope: Option<String>,       // #[serde(default, skip_serializing_if...)]
    pub key_version: u8,             // #[serde(default = "default_key_version")]
    // + hmac_signature: String (HMAC-SHA256 hex, mandatory, fail-closed)
}

// lines 148-153 — AuthzResponse
pub struct AuthzResponse {
    pub correlation_id: Uuid,
    pub allowed: bool,
    pub reason: Option<String>,
}

// lines 159-174 — AuditEventMessage
pub struct AuditEventMessage {
    pub tenant_id: Uuid,
    pub actor_id: Uuid,
    pub actor_type: String,
    pub action: String,
    pub resource_id: Option<Uuid>,
    pub outcome: String,
    pub ip_address: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub key_version: u8,
    // + hmac_signature
}

// lines 187-196 — NotificationEvent
pub struct NotificationEvent {
    pub event_type: String,
    pub tenant_id: Uuid,
    pub actor_id: Uuid,
    pub resource_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
    pub data: Option<serde_json::Value>,
}

// lines 214-221 — WebhookMessage
pub struct WebhookMessage {
    pub webhook_id: Uuid,
    pub delivery_id: Uuid,
    pub tenant_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub attempt: u32,
}
```

**Queue name constants** (`crates/axiam-amqp/src/connection.rs` lines 12-46, `pub mod queues`):
```rust
pub const AUTHZ_REQUEST: &str = "axiam.authz.request";
pub const AUTHZ_RESPONSE: &str = "axiam.authz.response";
pub const AUTHZ_REQUEST_DLQ: &str = "axiam.authz.request.dlq";
pub const AUDIT_EVENTS: &str = "axiam.audit.events";
pub const AUDIT_EVENTS_DLQ: &str = "axiam.audit.events.dlq";
pub const NOTIFICATIONS: &str = "axiam.notifications";
pub const MAIL_OUTBOUND: &str = "axiam.mail.outbound";
pub const MAIL_OUTBOUND_DLQ: &str = "axiam.mail.outbound.dlq";
pub const WEBHOOK: &str = "axiam.webhook";
pub const WEBHOOK_RETRY: &str = "axiam.webhook.retry";
pub const WEBHOOK_DLQ: &str = "axiam.webhook.dlq";
```
Note: `OutboundMailMessage`/`MailType` live in `axiam_core::models::mail`, re-exported by `messages.rs` (see its module doc comment, lines 1-13) — read that source file for the mail message shape when authoring the `axiam.mail.outbound` channel.

**Format/version-stamp analog** (sibling spec-file, `sdks/openapi.json`/`crates/axiam-api-rest/src/openapi.rs` lines 1-14):
```rust
#[derive(OpenApi)]
#[openapi(
    info(
        title = "AXIAM API",
        description = "Access eXtended Identity and Authorization Management — REST API",
        version = "0.1.0",
        license(name = "Apache-2.0"),
    ),
    paths( ... )
)]
```
→ Mirror the `title`/`description`/`version` convention (version = `"0.1.0"` matching the REST spec, per D-12 stamp with v1.2/beta note in the `description` prose) in the AsyncAPI `info` block. RESEARCH.md's proposed skeleton (see RESEARCH.md `## AsyncAPI 2.x Spec Skeleton`, includes full `channels`/`components.messages` YAML template) is the concrete starting point — use it directly, transcribing the struct fields above.

---

### `docs/api/openapi.json` (config, batch/regenerate)

**Analog:** `sdks/openapi.json` + `.github/workflows/sdk-openapi-drift.yml`

**Existing dump mechanism to reuse** (`crates/axiam-server/src/main.rs` lines 130-144):
```rust
let args: Vec<String> = std::env::args().collect();
if args.get(1).map(String::as_str) == Some("--dump-openapi") {
    let json = serde_json::to_string_pretty(&axiam_api_rest::openapi::api_doc())
        .expect("OpenAPI serialization failed");
    println!("{json}");
    std::process::exit(0);
}
```
**Existing drift-gate CI job to imitate or extend** (`.github/workflows/sdk-openapi-drift.yml`, full file read — see excerpt below under Shared Patterns / CI). Recommendation (per RESEARCH.md `## OpenAPI Publishing Mechanism`): symlink `docs/api/openapi.json -> ../../sdks/openapi.json` — zero duplication, existing drift gate remains sole source of truth; document the regenerate command in `docs/api/README.md`.

---

### `docs/README.md`, `docs/api/README.md`, `docs/deployment/README.md`, `docs/admin/README.md`, `docs/pki/README.md` (doc, transform/index)

**Analog:** `sdks/rust/README.md` heading/tone convention (lines 1-14):
```markdown
# axiam-sdk (Rust)

Official Rust client SDK for [AXIAM](https://github.com/ilpanich/axiam) — ...

## Package identity

- **Crate:** `axiam-sdk`
- **Registry:** [crates.io/crates/axiam-sdk](...) _(reserved, not yet published)_
- **License:** Apache-2.0
- **MSRV:** Rust 1.88 (...)

## Contract conformance

This SDK conforms to CONTRACT.md §1-§10.
```
→ Use this "H1 title, one-line description, H2 sections with bold-label bullet lists, explicit cross-references (`§` anchors / relative links)" convention for all new `docs/**/README.md` files. No existing top-level `docs/README.md` or prose deployment/admin/PKI guide exists in the repo to copy structure from directly (confirmed: `docs/` today only contains `dev-environment.md` + `compliance/`) — these are the genuinely net-new prose docs (D-08, D-09). Follow RESEARCH.md's `## Recommended docs/ Structure` tree exactly for file layout, and pull concrete content from:
- Deployment: `k8s/network-policy/*.yml` (6 files: default-deny, allow-dns-egress, allow-ingress-to-{frontend,rabbitmq,server,surrealdb}, server-egress), `k8s/server/secret.yml` (canonical `AXIAM__*` env-var list), `docker/docker-compose.prod.yml`
- Admin: `AXIAM_BOOTSTRAP_ADMIN_EMAIL` bootstrap pattern (ROADMAP.md Phase 3), `crates/axiam-api-rest/src/handlers/organizations.rs` for org/tenant/user mgmt walkthrough content
- PKI: `crates/axiam-api-rest/src/handlers/certificates.rs` (`generate`/`list`/`get`/`revoke`/`bind`), `crates/axiam-api-rest/src/handlers/ca_certificates.rs` (`generate`/`list`/`get`/`revoke`), `crates/axiam-pki/`

Every landing doc must **link out** (D-09) rather than duplicate: `docs/README.md` links to `docs/api/`, `docs/deployment/`, `docs/admin/`, `docs/pki/`, `docs/compliance/`, all 7 `sdks/{rust,typescript,python,java,csharp,php,go}/README.md`, and `claude_dev/security-audit.md`.

---

### `docs/api/grpc.md` (doc, transform/reference)

**Source:** `proto/axiam/v1/authorization.proto`, `token.proto`, `user.proto` (already exist, unchanged). No prose gRPC guide exists yet — short usage guide only, referencing the `.proto` files by path, matching the same H1/H2 README convention above.

---

### `scripts/check-doc-links.py` (utility, batch)

**Analog:** `scripts/e2e-bootstrap.sh` — existing `scripts/` convention: standalone script (bash or Python), invoked directly or via `just`, no external framework. Confirmed sibling scripts: `bootstrap-dev-tools.sh`, `e2e-bootstrap.sh`, `provision-agent-tooling.sh`, `session-start-tooling.sh` — all shell. Per RESEARCH.md's recommendation (`## Light Docs CI`), prefer a small stdlib-only script (Python 3 or bash/awk) that greps `docs/**/*.md` + `claude_dev/security-audit.md` for relative markdown links `[text](path)` and asserts each resolves to an existing file — no new npm dependency (avoids `markdown-link-check`, flagged `[SUS]` in RESEARCH.md's Package Legitimacy Audit). Verify bash-vs-Python preference against the existing `scripts/` convention at plan time (all four existing scripts are `.sh` — a bash script keeps full consistency with sibling files unless the link-check logic is materially easier in Python).

---

### `.github/workflows/docs-ci.yml` (CI workflow, event-driven)

**Analog:** `.github/workflows/sdk-openapi-drift.yml` (full file, read in entirety — 40 lines):
```yaml
name: SDK OpenAPI Drift Gate

on:
  pull_request:
    branches: [main]
    paths:
      - 'crates/axiam-api-rest/**'
      - 'crates/axiam-server/**'
  push:
    branches: [main]
    paths:
      - 'crates/axiam-api-rest/**'
      - 'crates/axiam-server/**'
    tags:
      - 'v*'

permissions:
  contents: read

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-Dwarnings"

jobs:
  openapi-drift:
    name: OpenAPI Drift Gate (SAML off)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
      - uses: dtolnay/rust-toolchain@3c5f7ea28cd621ae0bf5283f0e981fb97b8a7af9  # stable (2026-03-27)
        with:
          toolchain: stable
      - uses: Swatinem/rust-cache@9d47c6ad4b02e050fd481d890b2ea34778fd09d6  # v2.7.8
      - run: sudo apt-get update && sudo apt-get install -y protobuf-compiler
      - name: Build axiam-server (SAML off / --no-default-features)
        run: cargo build -p axiam-server --no-default-features
      - name: Export fresh OpenAPI spec
        run: ./target/debug/axiam-server --dump-openapi > /tmp/openapi-fresh.json
      - name: Check drift against committed sdks/openapi.json
        run: diff sdks/openapi.json /tmp/openapi-fresh.json
```
→ Copy this exact shape for `docs-ci.yml`: `name:` header, `on.pull_request`/`on.push` both with `branches: [main]` + a `paths:` filter (use `['docs/**', 'claude_dev/security-audit.md', 'crates/axiam-amqp/**', 'crates/axiam-api-rest/src/openapi.rs']` per RESEARCH.md), `permissions: contents: read` at workflow level, SHA-pinned `actions/checkout` at the same commit (`11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2`), single job with descriptive `name:`. Steps to add per RESEARCH.md `## Light Docs CI`: (1) OpenAPI parse check reusing the `--dump-openapi` + `jq empty`/`json.tool` pattern, (2) `npx @asyncapi/cli validate docs/api/asyncapi.yml` (flag with `checkpoint:human-verify` per Package Legitimacy Audit — `[SUS]` verdict, sandbox download-count lookup limitation, not a real trust concern), (3) the new `scripts/check-doc-links.py`/`.sh` script.

---

## Shared Patterns

### Version-stamp / "last verified" convention (D-12)
**Source:** `docs/compliance/asvs-l2-checklist.md` header (lines 1-9) + `claude_dev/security-review-postremediation.md` header (lines 1-9)
**Apply to:** every new doc under `docs/**` and `claude_dev/security-audit.md`
```markdown
**Standard:** ...
**Scope:** ...
- **Date**: 2026-07-06
- **Milestone:** v1.2 (Beta)
```
Combine both conventions: a `Standard/Scope` preamble (asvs style) plus a `Date`/`Milestone` metadata line (post-remediation-review style) at the top of every doc, honoring D-12's "milestone + last-verified date" requirement.

### Citation-over-duplication (D-01, D-09, D-10)
**Source:** the entire `docs/compliance/` set's existing relationship to `claude_dev/security-review-postremediation.md` (which cites `security-review.md` and `remediation-plan.md` by link, e.g. `[`security-review.md`](security-review.md)`)
**Apply to:** `security-audit.md` → `docs/compliance/*`; `docs/README.md` → all section READMEs + SDK READMEs; `docs/api/openapi.json` → `sdks/openapi.json` (symlink, not copy)
```markdown
**Baseline**: the previous review at `d69323b` ([`security-review.md`](security-review.md))
```
→ Use relative markdown links with this exact `[`label`](relative/path.md)` syntax throughout — it is also what the link-check script (D-11) will validate.

### CI workflow conventions (all `.github/workflows/*.yml`)
**Source:** `.github/workflows/sdk-openapi-drift.yml` (see full excerpt above)
**Apply to:** `.github/workflows/docs-ci.yml`
- Actions pinned by commit SHA with version comment: `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2`
- `permissions: contents: read` at workflow level
- Path-filtered triggers on both `pull_request` and `push: branches: [main]`
- Job/step `name:` fields are human-readable purpose descriptions, not generic

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `docs/api/asyncapi.yml` | spec | transform | No AsyncAPI (or any AMQP contract doc) exists anywhere in the repo — genuinely net-new format (D-07 explicitly chooses hand-authoring, no existing analog to copy the AsyncAPI shape from; use RESEARCH.md's proposed skeleton + `messages.rs`/`connection.rs` as the only sources) |
| `docs/README.md`, `docs/deployment/README.md`, `docs/admin/README.md`, `docs/pki/README.md` | doc | transform | No top-level docs index or operator/admin/PKI prose guide currently exists under `docs/` (only `dev-environment.md` + `compliance/` exist today) — structural analog is the SDK README heading convention, not a same-role sibling doc |

## Metadata

**Analog search scope:** `docs/`, `claude_dev/`, `sdks/`, `.github/workflows/`, `scripts/`, `crates/axiam-amqp/src/`, `crates/axiam-api-rest/src/openapi.rs`, `crates/axiam-server/src/main.rs`
**Files scanned:** ~20 (targeted reads/greps, no full-repo sweep needed given RESEARCH.md's exhaustive existing-file enumeration)
**Pattern extraction date:** 2026-07-06
