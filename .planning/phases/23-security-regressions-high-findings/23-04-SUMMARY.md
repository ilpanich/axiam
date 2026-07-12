---
phase: 23-security-regressions-high-findings
plan: 04
subsystem: federation
tags: [saml, xsw, xml-signature, federation, samael, libxml, security]

# Dependency graph
requires:
  - phase: 04-federation-verification-session-security
    provides: "handle_saml_response signature verification + Conditions/replay checks (04-03), expected_request_id/expected_destination params (10-05)"
provides:
  - "bind_signature_to_assertion: libxml raw-XML XSW binding check (exactly-one-Assertion + verified Reference URI resolves to consumed assertion ID)"
  - "handle_saml_response require_in_response_to: bool param — unsolicited-response defense when no stored expected_request_id is available"
  - "SamlAcsRequest.acs_url — authenticated saml_acs now validates Destination against the real ACS URL"
affects: []

# Tech tracking
tech-stack:
  added:
    - "libxml 0.3.3 — promoted from transitive (via samael 0.0.19's xmlsec feature) to a direct axiam-federation dependency, pinned to the exact Cargo.lock-resolved version; no new crate enters the dependency graph"
  patterns:
    - "Raw-XML XPath introspection (libxml::xpath::Context + local-name()-based, namespace-agnostic XPath) to supplement — never replace — a library's XML-DSig verification, closing the 'signature exists somewhere' vs 'signature covers THIS data' gap (XSW defense)"
    - "require_presence-decoupled-from-equality boolean param pattern for protocol-binding checks that have no stored comparison value on one call path (authenticated ACS) but still need a floor guarantee"

key-files:
  created: []
  modified:
    - Cargo.toml
    - crates/axiam-federation/Cargo.toml
    - Cargo.lock
    - crates/axiam-federation/src/saml.rs
    - crates/axiam-api-rest/src/handlers/federation.rs
    - crates/axiam-server/tests/req5_saml_e2e.rs
    - .planning/REQUIREMENTS.md

key-decisions:
  - "libxml pinned via the workspace dependency table (Cargo.toml [workspace.dependencies]) rather than a bare crate-local version string, matching the existing samael convention — keeps a single source of truth for the pinned version and makes the Cargo.lock diff a single dependency-edge addition (no duplicate FFI binding)."
  - "SamlAcsRequest gained a required acs_url field. The plan assumed this field already existed at federation.rs:762 (research/plan drift) — it did not; adding it was necessary to satisfy the plan's own literal acceptance criteria (pass Some(&req.acs_url) instead of None)."
  - "bind_signature_to_assertion implemented as a private free function (not a SamlFederationService method) — it needs only raw XML bytes and the consumed assertion's ID, no repository/service state, matching the style of the existing extract_assertion_claims/apply_attribute_map helpers."
  - "Recipient/SubjectConfirmationData validation beyond XSW+Destination+InResponseTo is a recorded SEC-005 residual (see below), per 23-CONTEXT.md <deferred> and 23-RESEARCH.md 'Deferred Ideas' — explicitly out of scope for this plan, not silently dropped."

requirements-completed: [SECFIX-04]

coverage:
  - id: D1
    description: "A SAML response with a wrapped/duplicated Assertion is rejected on the authenticated ACS path (the defining SECFIX-04 negative signal, ROADMAP SC#4)"
    requirement: SECFIX-04
    verification:
      - kind: integration
        ref: "crates/axiam-server/tests/req5_saml_e2e.rs#saml_rejects_xsw_wrapped_assertion"
        status: pass
    human_judgment: false
  - id: D2
    description: "Authenticated ACS path rejects a response whose Destination does not match the real ACS URL"
    requirement: SECFIX-04
    verification:
      - kind: integration
        ref: "crates/axiam-server/tests/req5_saml_e2e.rs#saml_rejects_wrong_destination_on_authenticated_path"
        status: pass
    human_judgment: false
  - id: D3
    description: "Authenticated ACS path rejects an unsolicited response with no InResponseTo, even with no stored expected_request_id to compare against"
    requirement: SECFIX-04
    verification:
      - kind: integration
        ref: "crates/axiam-server/tests/req5_saml_e2e.rs#saml_rejects_missing_in_response_to_on_authenticated_path"
        status: pass
    human_judgment: false
  - id: D4
    description: "libxml promoted to a direct dependency introduces no new crate and no duplicate FFI binding; samael stays pinned at 0.0.19"
    requirement: SECFIX-04
    verification:
      - kind: other
        ref: "git diff Cargo.lock (Task 1 commit 0d850c5): single dependency-edge addition (\"libxml\" added to axiam-federation's deps list); grep confirms exactly one `name = \"libxml\"` entry"
        status: pass
    human_judgment: false
  - id: D5
    description: "Existing SAML unit/integration test suites stay green after the binding check and new params land"
    requirement: SECFIX-04
    verification:
      - kind: unit
        ref: "cargo test -p axiam-federation --features saml — 19/19 pass"
        status: pass
      - kind: integration
        ref: "cargo test -p axiam-server --test req5_saml_e2e --features saml — 9/9 pass (6 pre-existing + 3 new)"
        status: pass
    human_judgment: false

duration: 27min
completed: 2026-07-03
status: complete
---

# Phase 23 Plan 04: SAML Signature-to-Assertion Binding (XSW) Summary

**Closed the SEC-005 XML Signature Wrapping gap with a hand-written libxml raw-XML binding check between samael's signature verification and claims extraction, plus Destination/InResponseTo enforcement on the authenticated ACS path — samael stays at 0.0.19, unchanged.**

## Performance

- **Duration:** ~27 min (first commit 19:51 UTC → last commit 20:18 UTC)
- **Completed:** 2026-07-03
- **Tasks:** 3 completed
- **Files modified:** 6 (+ REQUIREMENTS.md)

## Libxml API Decision (Task 1 SPIKE)

Confirmed the exact call shape against the vendored crate source at `~/.cargo/registry/src/*/libxml-0.3.3/src/{parser.rs,xpath.rs,tree/node.rs}` (docs.rs returned 403 during 23-RESEARCH.md's session — Assumption A2). **No fallback needed** — the ergonomic XPath API Pattern 5 assumed is exactly what the vendored source exposes:

- `libxml::parser::Parser::default().parse_string(bytes: impl AsRef<[u8]>) -> Result<Document, XmlParseError>`
- `libxml::xpath::Context::new(&doc) -> Result<Context, ()>`
- `context.findnodes(xpath: &str, node_opt: Option<&Node>) -> Result<Vec<Node>, ()>` — **`Context` must be `mut`**, `findnodes` takes `&mut self` (this one detail was not spelled out in Pattern 5's sketch)
- `Node::get_content() -> String` — works correctly on attribute-result nodes from an `@URI`-style XPath (libxml2 attribute nodes return their value from `xmlNodeGetContent`)

libxml 0.3.3 (the exact version already resolved transitively by samael 0.0.19's `xmlsec` feature) was pinned as a direct `axiam-federation` dependency via the workspace dependency table (`Cargo.toml [workspace.dependencies] libxml = "=0.3.3"`, referenced as `{ workspace = true, optional = true }` in `crates/axiam-federation/Cargo.toml`, gated behind the existing `saml` feature alongside `samael`). `git diff Cargo.lock` for this change is a single line — `"libxml"` added to axiam-federation's dependency list — confirming no new crate entered the graph and no duplicate FFI binding was created.

## Accomplishments

- **`bind_signature_to_assertion`** (new private helper in `saml.rs`): re-parses the raw SAML response XML independently of samael's typed `Response` struct, and (1) rejects unless exactly one `<Assertion>` element (namespace-agnostic `local-name()`) exists anywhere in the document, and (2) rejects unless at least one `<Signature>`'s `<Reference URI="#...">` resolves to the consumed assertion's ID (empty/absent/non-matching references also rejected). No regex/string XML matching anywhere — real XPath only, per 23-RESEARCH.md's Anti-Patterns.
- Wired into `handle_saml_response` immediately after the consumed assertion is read (`response.assertion`) and before Conditions validation / `extract_assertion_claims` — i.e. exactly between the "verify_signature succeeded" point and the "claims are trusted" point that 23-RESEARCH.md's Pitfall 2 identified as the actual gap. `verify_signature` itself (still calling `samael::crypto::verify_signed_xml`) is byte-for-byte unchanged.
- `handle_saml_response` gained a `require_in_response_to: bool` parameter: when there is no stored `expected_request_id` (the authenticated ACS path's situation — it has no `FederationLoginState` row), the caller can still require `InResponseTo` presence to reject unsolicited responses. Has zero effect when `expected_request_id` is `Some` (the public path's existing presence-and-equality check is untouched).
- Authenticated `saml_acs` handler (`federation.rs`) now validates `req.acs_url` is non-empty (mirroring the sibling `build_authn_request` handler) and passes `Some(&req.acs_url)` as `expected_destination` (was `None`) plus `require_in_response_to: true`. `saml_acs_public` is unchanged in behavior (still passes its own stored `expected_request_id`, which already enforces presence-and-equality); only updated for the new parameter shape.
- Three new negative tests in `req5_saml_e2e.rs`, all exercised through the authenticated-path parameter shape (`expected_request_id=None, expected_destination=Some(acs_url), require_in_response_to=true`):
  - `saml_rejects_xsw_wrapped_assertion` — the defining SECFIX-04 signal (ROADMAP SC#4).
  - `saml_rejects_wrong_destination_on_authenticated_path`.
  - `saml_rejects_missing_in_response_to_on_authenticated_path`.

## XSW Fail-Before / Pass-After Proof

The first fixture design attempted (two direct `<saml:Assertion>` siblings under `<samlp:Response>`) turned out to be a **dead end**: samael 0.0.19's `Response` struct declares `assertion: Option<Assertion>` (a scalar field), and quick_xml's derived deserializer hard-errors on two direct siblings with `"duplicate field \`Assertion\`"` at the `xml.parse()` step — before `verify_signature` or the binding check ever run. The rejection would have come from the unrelated parser, not from Task 2's fix, so this shape does not prove anything about SECFIX-04.

The working payload instead moves the legitimately-signed `<saml:Assertion ID="well-signed-1">` (Signature intact) into a `<samlp:Extensions>` wrapper — a field samael's `Response` struct does not know about, so quick_xml's struct deserializer silently skips the whole subtree without erroring — and inserts a **new forged, unsigned** `<saml:Assertion ID="forged-xsw-1">` at the position `response.assertion` now binds to. `samael::crypto::verify_signed_xml` operates on the raw XML bytes via its own (non-serde) libxmlsec1 tree walk, so it still finds and successfully verifies the original `<ds:Signature>` wherever it now sits in the document (the referenced `#well-signed-1` content is byte-for-byte unmodified) — the "some signature exists" check passes.

I proved this both ways by temporarily commenting out the `bind_signature_to_assertion(...)?` call in `saml.rs`, rerunning the test, and restoring it (the shipped diff contains no reversion — the temporary edit was made and undone in the same working session before Task 3's commit):

- **Before** (binding check absent): `handle_saml_response` returns `Ok(...)` and **provisions a brand-new local user for `attacker@evil.com`** from the forged assertion's claims — the XSW exploit fully succeeds.
- **After** (binding check active): rejected with `SamlResponseFailed("expected exactly 1 Assertion element in SAML Response, found 2 (possible XML Signature Wrapping attack)")`.

## SEC-005 Residual (recorded, not dropped)

Full `Recipient` / `SubjectConfirmationData` validation (beyond the XSW-binding + Destination + InResponseTo minimum implemented here) is **explicitly out of scope** for this plan, per `23-CONTEXT.md <deferred>` and `23-RESEARCH.md` "Deferred Ideas". `.planning/REQUIREMENTS.md`'s SECFIX-04 acceptance criteria list this item unchecked with an explicit deferral note, and the traceability table status reads "Complete (residual: Recipient/SubjectConfirmationData deferred)" rather than a bare "Complete", so this gap remains visible for a future phase rather than silently closed.

## Task Commits

Each task was committed atomically:

1. **Task 1: SPIKE — verify libxml XPath/tree API; pin libxml as direct axiam-federation dep** - `0d850c5` (feat)
2. **Task 2: XSW binding (libxml) + authenticated-ACS Destination + InResponseTo** - `126612e` (fix)
3. **Task 3: Negative tests — XSW wrapped-assertion, wrong-Destination, missing-InResponseTo** - `aa6419b` (test)

**Plan metadata:** (this commit, docs)

## Files Created/Modified

- `Cargo.toml` - `libxml = "=0.3.3"` added to `[workspace.dependencies]`, pinned to the exact Cargo.lock-resolved version (SAML section, alongside `samael`)
- `crates/axiam-federation/Cargo.toml` - `libxml = { workspace = true, optional = true }`; `saml` feature now also enables `dep:libxml`
- `Cargo.lock` - single dependency-edge addition (`"libxml"` under axiam-federation's deps); no new crate, no duplicate version
- `crates/axiam-federation/src/saml.rs` - new `bind_signature_to_assertion` helper; `handle_saml_response` gains `require_in_response_to: bool` and calls the binding helper between assertion-read and Conditions validation; InResponseTo check gains a presence-only branch for when `expected_request_id` is `None`
- `crates/axiam-api-rest/src/handlers/federation.rs` - `SamlAcsRequest` gains required `acs_url: String`; authenticated `saml_acs` validates it non-empty and passes `Some(&req.acs_url)` + `require_in_response_to: true`; `saml_acs_public` call site updated for the new parameter (`false`), behavior unchanged
- `crates/axiam-server/tests/req5_saml_e2e.rs` - existing 6 call sites updated for the new parameter; 3 new negative tests + `inject_response_attrs`/`build_xsw_wrapped_response` test helpers
- `.planning/REQUIREMENTS.md` - SECFIX-04 acceptance criteria checked (4/5) with the Recipient/SubjectConfirmationData item explicitly marked deferred; traceability row updated

## Decisions Made

- libxml pinned via the workspace dependency table rather than a bare version string local to `axiam-federation/Cargo.toml`, matching the existing `samael` convention in the same workspace `Cargo.toml` SAML section — single source of truth, minimal Cargo.lock diff.
- `SamlAcsRequest.acs_url` added as a new required field. 23-RESEARCH.md/23-04-PLAN.md both stated this field "already exists at federation.rs:762" — on inspection, line 762 was actually inside the unrelated `SamlMetadataQuery` struct; `SamlAcsRequest` had no `acs_url` field at all. This is Rule 2 (missing critical functionality directly required by the plan's own acceptance criteria) — added the field, validated non-empty like the sibling `build_authn_request` handler, and wired it through.
- `bind_signature_to_assertion` is a free function, not a `SamlFederationService` method — it only needs raw XML bytes + an assertion ID, consistent with the crate's existing `extract_assertion_claims`/`apply_attribute_map` helper style.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing critical functionality] Added `SamlAcsRequest.acs_url` field**
- **Found during:** Task 2
- **Issue:** The plan's `<read_first>` and acceptance criteria assumed `SamlAcsRequest.acs_url` already existed (citing `federation.rs:762`) and was merely unused. On inspection, `SamlAcsRequest` (lines 745-752) had only `config_id`, `saml_response`, `relay_state` — no `acs_url`. Line 762 was inside the unrelated `SamlMetadataQuery` struct. Without this field, the authenticated `saml_acs` handler would have no real ACS URL to pass as `expected_destination`, making the plan's own literal acceptance criterion ("passes `Some(&req.acs_url)` instead of `None`") impossible to satisfy as written.
- **Fix:** Added `pub acs_url: String` to `SamlAcsRequest`; added a non-empty validation check mirroring the sibling `build_authn_request` handler's existing `acs_url` validation pattern (`federation.rs:797-798`).
- **Files modified:** `crates/axiam-api-rest/src/handlers/federation.rs`
- **Verification:** `cargo build -p axiam-api-rest --features saml` succeeds; `saml_acs` now compiles and passes the URL through
- **Committed in:** `126612e` (Task 2 commit)

**2. [Rule 1 - Bug in own test design] Discarded the first XSW fixture shape (two direct Assertion siblings)**
- **Found during:** Task 3, while proving the fail-before observation
- **Issue:** The initial XSW test fixture (two `<saml:Assertion>` elements as direct siblings under `<samlp:Response>`) was rejected even with the binding check temporarily removed — but for the wrong reason: `samael`'s quick-xml-derived `Response` struct hard-errors on duplicate `Assertion` fields at parse time (`"duplicate field \`Assertion\`"`), before `verify_signature` or the binding check run. This would have made the test pass without actually proving Task 2's fix does anything.
- **Fix:** Redesigned the payload to move the original signed assertion into a `<samlp:Extensions>` wrapper (invisible to samael's typed struct deserializer, but still visible to `verify_signed_xml`'s raw libxmlsec1 tree walk and to the raw-XML XPath scan) and insert the forged assertion at the position `response.assertion` binds to. Re-ran the fail-before/pass-after proof against this corrected shape (see "XSW Fail-Before / Pass-After Proof" above) — confirmed the exploit genuinely succeeds without the binding check (a new user is provisioned for `attacker@evil.com`) and is genuinely rejected with it.
- **Files modified:** `crates/axiam-server/tests/req5_saml_e2e.rs`
- **Verification:** Manual fail-before/pass-after run (binding check commented out, then restored) plus `cargo test -p axiam-server --test req5_saml_e2e --features saml`
- **Committed in:** `aa6419b` (Task 3 commit; the temporary revert used to prove fail-before was never itself committed)

---

**Total deviations:** 2 auto-fixed (1 Rule 2 - missing DTO field required by the plan's own acceptance criteria; 1 Rule 1 - test-design bug caught during the mandated fail-before proof)
**Impact on plan:** Both were necessary to satisfy the plan's literal, stated acceptance criteria and the mandated fail-before/pass-after proof. No scope creep — no other endpoints, crates, or unrelated behavior touched.

## Issues Encountered

- **Sandbox environment build prerequisite (pre-existing, unrelated to this plan's code):** `utoipa-swagger-ui`'s build script needs to download a Swagger UI zip from GitHub, which this sandbox's session cannot reach (`"GitHub access to this repository is not enabled for this session"`) — the same documented limitation noted in `23-03-SUMMARY.md`. Worked around locally by pointing `SWAGGER_UI_DOWNLOAD_URL` at a minimal placeholder zip built in the scratchpad directory (`file://` protocol) for every `axiam-api-rest`/`axiam-server` build and test invocation in this session. This is a local build-only environment variable, not a code or config change, and does not affect the committed diff.
- No issues in the actual SAML/XSW logic itself once the correct XSW fixture shape was found (see Deviation 2 above) — the design in 23-RESEARCH.md Pattern 5 held exactly as specified once the vendored libxml API was confirmed (Task 1).

## User Setup Required

None — no external service configuration required. Operators deploying with SAML enabled should ensure the frontend/SP integration sends the real `acs_url` in the authenticated `POST /api/v1/federation/saml/acs` request body (new required field); the public SSO flow (`saml_acs_public`) is unaffected.

## Next Phase Readiness

- SECFIX-04 is closed for its stated scope: XSW binding, authenticated-path Destination validation, and authenticated-path InResponseTo presence are all implemented and proven by green negative tests (fail-before/pass-after demonstrated for the XSW case specifically).
- The Recipient/SubjectConfirmationData residual is explicitly recorded (REQUIREMENTS.md + this SUMMARY) for a future phase — not a blocker for the rest of Phase 23.
- No blockers for the remaining Phase 23 plans (SECFIX-05 logout, SECFIX-06 reset/resend).

---
*Phase: 23-security-regressions-high-findings*
*Completed: 2026-07-03*

## Self-Check: PASSED

- All 6 modified source files verified present on disk (`Cargo.toml`, `crates/axiam-federation/Cargo.toml`, `Cargo.lock`, `crates/axiam-federation/src/saml.rs`, `crates/axiam-api-rest/src/handlers/federation.rs`, `crates/axiam-server/tests/req5_saml_e2e.rs`).
- All 3 task commits (`0d850c5`, `126612e`, `aa6419b`) verified present in `git log`.
