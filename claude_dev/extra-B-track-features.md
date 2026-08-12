# Extra B-Track Features — X1–X5 (formerly "deferred" B6 items, now scheduled)

> Prepared 2026-08-07. Extends
> [`improvement-after-run5-benchmark.md`](improvement-after-run5-benchmark.md):
> the five items its §B6 recorded as deferred are hereby activated as
> tasks X1–X5, per operator decision. Same conventions as the parent
> plan: every task carries detailed instructions, required tests / docs
> / examples, acceptance criteria, and the cheapest-adequate model
> recommendation (Opus 5 vs Sonnet 5). The parent plan's guiding
> constraints (security ≥ current posture, performance within ±2% on
> untouched hot paths, low resource footprint) apply verbatim.
>
> Operator-pinned requirements honored below:
> - **X1** (Actions-style scripting) is built as **AMQP-wired external
>   actors** implementable in any SDK language, with SDK runtime
>   support + code + examples + docs across the SDK fleet, and a DB
>   configuration section. Feature name chosen here: **Reactors**.
> - **X5** (FAPI) prepares for the certification tests **and** includes
>   the ready-to-send **fee-waiver letter to the OpenID Foundation**
>   (§X5.4).

Cross-plan dependencies (why the waves at the end look the way they do):

| Needs first | From parent plan |
|---|---|
| X1 production guidance | A6 (AMQP TLS) — actors talk to the broker across trust boundaries |
| X2 policy evaluation | B1 (deny-override) — UMA decisions must respect deny rules |
| X4 | B3 (token exchange core) — X4 extends its grant |
| X5 certification run | B5 (PAR, logout triad) — FAPI 2.0 requires PAR |

---

## X1 — **Reactors**: AMQP-native extension actors (Zitadel-Actions parity, done the AXIAM way)

**Positioning.** Zitadel Actions embed user JavaScript in the IAM
process; Keycloak SPIs load user JARs into the JVM. Both put third-party
code inside the security kernel. AXIAM's variant keeps the kernel
closed: a **Reactor** is an external process, written in **any SDK
language**, that subscribes to well-defined hook events on the AMQP bus
and answers back (veto / mutate / observe) under a signed,
timeout-bounded, field-allow-listed protocol. This is both the safer
design and the one AXIAM's stack is already shaped for (RabbitMQ is in
every deployment; contract §8 HMAC + replay protection already secures
the bus; A6 adds transport TLS).

**Name.** `Reactors` (an actor that *reacts* to bus events). Wire
prefix `axiam.reactor.*`, DB table `reactor`, SDK helper family
`reactor_*`. Consistent, grep-able, not overloaded by Zitadel
("Actions") or Keycloak ("SPI", "Authenticators").

### X1.1 Event model

Two hook classes, declared per event in one server-side registry
(`crates/axiam-amqp/src/reactor/events.rs`, single source of truth
exported into docs and the SDK contract):

1. **Interceptors** (synchronous request/response; can veto or mutate
   within an allow-list). v1 set — deliberately small:
   - `token.pre_issue` — enrich/veto token issuance. Mutable fields:
     **custom claims under the `ext.` namespace only**; standard claims
     (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, scopes) are
     immutable to reactors. Veto ⇒ `invalid_grant` with audited reason.
   - `login.post_auth` — after credentials verify, before session
     issuance: veto (fraud/geo checks) or require step-up
     (`require_mfa`). Cannot mutate identity fields.
   - `user.pre_create`, `user.pre_update` — validate/normalize
     profile fields (mutable: profile attributes only, never
     credentials, tenant, or role fields).
   - `grant.pre_assign` — veto role/permission assignments (four-eyes
     workflows). Veto-only, no mutation.
   - **Explicitly NOT hookable in v1:** `authz.check` and every other
     hot-path decision (the 1 000–12 000 req/s paths from the
     benchmark matrix). A reactor round-trip is milliseconds; the
     check path budget is microseconds. Recorded in docs as a design
     decision with the benchmark numbers as rationale.
2. **Listeners** (async, fire-and-forget observation): every event the
   webhook system emits is also publishable to the reactor exchange
   (`mode: listen`). Listeners never block, never reply, and exist so
   an actor can maintain state without polling. (Webhooks remain the
   HTTP-push alternative; docs get a "webhook vs listener reactor"
   table.)

### X1.2 Wire protocol (contract §16, normative)

- **Topology:** topic exchange `axiam.reactor.events`; routing key
  `<tenant_id>.<event>` (e.g. `t_123.token.pre_issue`). Each reactor
  registration materializes a server-declared, durable, per-reactor
  queue `axiam.reactor.q.<tenant_id>.<reactor_id>` bound to its
  subscribed patterns — actors consume, they never declare topology.
  Replies go to a direct reply queue named in `reply_to`, correlated by
  `correlation_id` (standard AMQP RPC), consumed by the server.
- **Message security:** contract §8 v2 HMAC applies **in both
  directions** — the server signs events with the tenant signing key;
  the reactor signs replies with the same key; nonce + `issued_at`
  replay protection verbatim. An unsigned or stale reply is discarded
  as if timed out. A6's TLS requirement applies to actor connections in
  production.
- **Reply schema (interceptors):**
  `{ decision: "allow" | "deny" | "mutate", reason?, patch?, require_mfa? }`
  where `patch` is a flat map validated against the **per-event mutable
  field allow-list** (unknown or forbidden field ⇒ the entire reply is
  rejected and the failure policy applies — no partial application).
- **Timeouts & failure policy:** per-registration `timeout_ms`
  (default 500, hard max 5 000) and `failure_policy`:
  `fail_closed` (deny the underlying operation) or `fail_open`
  (proceed as if `allow`). **Defaults pinned by hook class:**
  veto-capable security hooks (`login.post_auth`, `grant.pre_assign`)
  default `fail_closed`; enrichment hooks (`token.pre_issue` claim
  additions) default `fail_open` *for the mutation* but a configured
  veto reactor on the same event stays `fail_closed`. Every timeout is
  audited and surfaced as a metric.
- **Ordering / multiplicity:** multiple interceptor reactors on one
  event run **sequentially in registration priority order**, each
  seeing the prior patch (documented, deterministic); total event
  budget = min(sum of timeouts, 5 000 ms). Deny short-circuits.

### X1.3 DB configuration (SurrealDB)

New tenant-scoped table `reactor` via `axiam-core` model +
`axiam-db` repository (indexed on `(tenant, enabled)` with the standing
`EXPLAIN` CI guard):

```
reactor {
  id, tenant, name, description,
  events: [string],           // patterns from the registry only (validated)
  mode: "intercept" | "listen",
  priority: int,              // interceptor ordering
  timeout_ms: int,            // ≤ 5000
  failure_policy: "fail_open" | "fail_closed",
  enabled: bool,
  created_at, updated_at, last_seen_at,  // last consumed heartbeat
}
```

REST CRUD under `/api/v1/reactors` (new handler module, OpenAPI'd,
admin-permission-gated), gRPC admin service addition, and a frontend
page (folds into parent-plan C4: list + editor + per-reactor health
showing `last_seen_at`, recent timeouts/vetoes from audit). Reactor
create/update/delete fires the existing cache-invalidation hooks so the
server's in-memory routing table refreshes within the measured 262 ms
event-path contract.

### X1.4 Server-side dispatch

New module `crates/axiam-amqp/src/reactor/` (dispatcher + reply
correlator on the existing `AmqpManager` connection, reusing the
publisher-confirm and DLQ conventions; interceptor calls exposed to
`axiam-auth`/`axiam-oauth2` via a small `ReactorGate` trait in
`axiam-core` so those crates stay broker-agnostic). Per-tenant
concurrency cap on in-flight interceptions (default 64) so a slow actor
cannot exhaust the token path; breach ⇒ failure policy applies
immediately (documented as back-pressure semantics).

### X1.5 SDK support (all 11 repos; contract §16)

- **Full reactor runtime** — the eight managed-runtime SDKs (rust,
  typescript, python, java, kotlin, csharp, go, php): a
  `reactor_serve(config, handlers)` helper (per-language naming per
  contract §1 conventions) that connects (TLS per A6, §6 policy),
  consumes the reactor queue, verifies §8 HMAC + replay, decodes the
  event, dispatches to a user-supplied handler
  (`fn(event) -> Allow | Deny(reason) | Mutate(patch)`), signs and
  publishes the reply, and handles reconnect/heartbeat
  (`last_seen_at`). Graceful shutdown drains in-flight events.
- **Deferred runtimes** (swift, c, cpp — a §8 AMQP carve-out of their own;
  the §12.6 deferral this once rode alongside was lifted in contract 1.11):
  no bundled runtime in v1 (no maintained AMQP client we
  are willing to vendor on embedded targets); they get the **normative
  wire-protocol chapter** so integrators can hand-roll, plus a C++
  example against a commonly-used AMQP library as a non-normative
  sample. Revisit after demand.
- **Examples (each runtime SDK, in `examples/reactor/`):** the same
  canonical scenario everywhere so docs can cross-link: *"enrich
  `token.pre_issue` with a `ext.department` claim fetched from an HR
  lookup, and veto logins from embargoed regions on
  `login.post_auth`."* CI-smoke-run against the compose stack like all
  parent-plan F3 examples.
- **Docs per SDK:** a "Writing a Reactor" page (runtime setup, handler
  contract, failure-policy implications, idempotency note for
  listeners).

### X1.6 Tests, bench, acceptance

- Server: dispatcher unit tests (timeout, malformed/unsigned/stale
  reply, forbidden patch field, priority chaining, deny short-circuit,
  concurrency-cap breach, DLQ on listener poison); integration test
  with a real containerized reactor (rust example) through RabbitMQ;
  invalidation test (registry update visible ≤ TTL).
- Contract: §16 conformance checklist (verify-sign round-trip vectors
  added next to the §8 fixtures in
  `crates/axiam-amqp/tests/fixtures/`).
- Bench: one labeled cell — `oauth2_client_credentials` with a no-op
  `token.pre_issue` interceptor attached — published honestly as "the
  cost of hooking token issuance" (expected: + one AMQP RTT ≈ 1–3 ms
  p50 on the bench box). Hot-path cells must show **zero** delta with
  reactors configured on other events (routing is a hash lookup).
- Acceptance: example reactor runs from all eight runtime SDKs against
  the e2e stack; failure-policy matrix behaves as pinned; audit trail
  complete.

**Model: Opus 5** for §X1.1–X1.4 (event registry semantics, wire
protocol + contract §16 text, dispatcher — third-party code influencing
token contents is the most security-sensitive surface in this document)
· **Sonnet 5** for the eight-SDK runtime fan-out, CRUD/UI, examples,
docs (contract §16 pins everything). F4 security review mandatory.

---

## X2 — UMA 2.0 permission tickets (Keycloak authorization-services parity)

**Scope decision (mine).** Implement the **UMA 2.0 Grant** and the
**Federated Authorization** resource/permission APIs on top of the
existing RBAC engine; **defer interactive claims-gathering** (the
`request_submitted` / redirect dance) to v2 — it is rarely exercised by
API-to-API consumers and Keycloak deployments overwhelmingly use the
non-interactive path. Party-to-party sharing UIs are likewise deferred.

**Instructions.**

1. **Endpoints** (new module in `axiam-oauth2`, discovery at
   `/.well-known/uma2-configuration`):
   - **Resource registration API** (`/uma2/rreg/resource_set`,
     PAT-protected — a Protection API Token is an ordinary AXIAM access
     token carrying the new `uma_protection` scope): CRUD mapping 1:1
     onto the existing `resources` table + `resource_scopes` from the
     scopes model; the UMA `_id` is the AXIAM resource id — **no
     parallel resource store**.
   - **Permission API** (`/uma2/perm`): resource-server posts the
     (resource, scopes) tuples it requires → server mints a
     **permission ticket**: tenant-scoped SurrealDB record, single-use,
     TTL 60 s (config), opaque 256-bit handle. Indexed, `EXPLAIN`-guarded.
   - **Token endpoint**: `grant_type=urn:ietf:params:oauth:grant-type:uma-ticket`
     with `ticket` (+ optional `claim_token` restricted to **AXIAM
     access tokens only** in v1). Evaluation: resolve the requesting
     party from the presented token, run the tickets' (resource, scope)
     pairs through **the existing authz engine** (deny-override aware
     once B1 lands — a deny rule must veto an RPT exactly as it vetoes
     a live check), and on success issue an **RPT**: a standard AXIAM
     access token carrying a `permissions` claim
     (`[{resource_id, resource_scopes, exp}]`). Partial grants:
     follow the spec — deny the ticket, return `need_info`-less
     `access_denied` in v1 (no claims gathering).
   - **RPT introspection**: extend the existing RFC 7662 endpoint to
     include the `permissions` array for RPTs (Keycloak-compatible
     shape, eases migration).
2. **Semantics to pin in code comments + docs:** RPT lifetime =
   min(subject token remaining, configured max, 300 s default);
   tickets are single-use and bound to the requesting resource-server
   client_id; RPTs are **not** refresh-tokenable in v1 (re-run the
   grant); revocation via the normal token paths + decision-cache
   invalidation contract.
3. **Rate limiting:** `/uma2/perm` and the uma-ticket grant join the
   machine-endpoint family (A1's fixed buckets) with their own flood
   scenario (parent E4).
4. **SDK support** (contract §17, fan-out via parent D6): resource
   registration + permission-ticket helpers for the resource-server
   side (`uma_register_resource`, `uma_request_ticket`,
   `uma_exchange_ticket`), and middleware sugar: on 403, emit the
   `WWW-Authenticate: UMA` challenge with a fresh ticket (spec §3.2),
   client-side helper consumes it. Examples: one resource-server +
   client pair per flagship SDK (rust, typescript, python, java, go).
5. **Frontend:** none beyond existing resource/scope pages (UMA reuses
   them); add a read-only "UMA" badge on resources registered via the
   Protection API (provenance field).

**Tests.** Grant-flow integration tests (happy path, expired ticket,
reused ticket, wrong client, deny-rule veto, scope subset/superset);
introspection shape test against a recorded Keycloak RPT introspection
fixture (compat check); property test: an RPT can never carry a
(resource, scope) pair the live engine would deny at mint time.

**Docs.** "UMA 2.0 in AXIAM" concept page (what maps onto what — one
table), resource-server how-to, Keycloak-migration notes.

**Acceptance.** The five-SDK example pair runs e2e; conformance against
the UMA 2.0 Grant + FedAuthz spec sections listed in the design header;
deny-override veto test green (post-B1).

**Model: Opus 5** for the grant/ticket semantics + engine integration
(step 1 token-endpoint logic and step 2 pinning — authorization
issuance again) · **Sonnet 5** for rreg CRUD, introspection extension,
SDK helpers, docs, examples.

---

## X3 — WebAuthn attestation policy enforcement (FIDO Metadata Service)

**Current state.** `axiam-auth` uses `webauthn-rs` 0.5; registration
accepts authenticators without attestation-metadata policy (the code
notes attestation metadata as future work). Enterprises need "only
FIDO-certified / non-revoked / explicitly-allowed authenticators may
register".

**Instructions.**

1. **MDS3 ingestion** (new module in `axiam-pki` — it is a
   trust-anchor/certificate concern, and the crate already owns CA
   handling): fetch the FIDO Alliance MDS3 BLOB (JWT), verify its
   signature chain against the **vendored FIDO root certificate**
   (pinned in-repo with an update procedure documented — never fetched
   dynamically), parse via the `fido-mds` crate (same author/ecosystem
   as webauthn-rs; evaluate once — if unmaintained, parse the JWT
   payload directly, schema is stable), store parsed entries in a
   server-global (not tenant) SurrealDB table keyed by AAGUID with the
   BLOB `no.` (serial) and `nextUpdate`. Refresh: weekly background
   job + admin-triggered endpoint; **offline deployments** ship the
   vendored BLOB snapshot from the release image and log staleness
   past `nextUpdate` (never hard-fail on staleness — policy decides).
   All outbound fetch goes through the existing SSRF guard patterns
   (`axiam-federation/src/ssrf.rs` — lift the helper to a shared crate
   or duplicate the checks; do not skip them).
2. **Per-tenant policy** (extends tenant WebAuthn config in
   `axiam-auth/src/config.rs` + tenant settings storage):
   ```
   webauthn_attestation_policy {
     mode: "none" | "indirect" | "direct_required",
     require_fido_certified: bool,          // any certification level
     min_certification: option<enum>,       // L1 | L1+ | L2 | L3
     allowed_aaguids: [uuid] | null,        // null = all except blocked
     blocked_aaguids: [uuid],
     block_revoked_status: bool (default true),  // MDS status REVOKED /
                                                 // USER_KEY_*_COMPROMISE
     unknown_aaguid: "allow" | "deny" (default allow when mode=none,
                                       deny when direct_required)
   }
   ```
3. **Enforcement at `finish_registration`:** request attestation
   conveyance per `mode`; resolve AAGUID → MDS entry; apply the policy
   table above; verify the attestation chain against the MDS-provided
   attestation roots via webauthn-rs's attestation-CA-list support.
   Denials return a distinct, user-actionable error ("this security key
   model is not permitted by your organization") and are audited with
   AAGUID + reason. **Existing credentials are never auto-revoked** on
   policy change: ship an admin **compliance report** endpoint + UI
   panel (list credentials violating current policy, with per-credential
   admin revoke) — policy is enforced at registration time; retroactive
   enforcement is a human decision.
4. **Frontend (with parent C1/C4):** policy editor in tenant security
   settings (mode, toggles, AAGUID pickers with MDS-sourced friendly
   names); credential lists gain authenticator model names/icons from
   MDS metadata (nice UX win for free); compliance report panel.
5. **Passkey caveat, documented prominently:** consumer passkey
   providers (iCloud Keychain, Google Password Manager) return
   `none`-attestation by design; `direct_required` policies will block
   them. The docs must present the trade ("hardware-key-only
   enterprise posture" vs "passkey-friendly consumer posture") and the
   default stays `mode: none` — current behavior unchanged unless
   opted in.

**Tests.** BLOB verification vectors (valid chain, broken chain, stale
`nextUpdate`); policy matrix unit tests (every field × allow/deny
outcome, incl. unknown AAGUID and revoked status); registration
integration tests with recorded attestation objects (YubiKey direct
attestation fixture, packed/none formats); compliance-report test.

**Docs.** Admin guide "Authenticator policies" (incl. the passkey
caveat + MDS refresh/air-gap operations); threat-model update.

**Acceptance.** A `direct_required + require_fido_certified` tenant
rejects a none-attestation registration and accepts the YubiKey
fixture; default-config tenants behave exactly as today (regression
suite green untouched).

**Model: Sonnet 5** (webauthn-rs and the MDS ecosystem do the
cryptographic heavy lifting; policy semantics are pinned above) — with
the BLOB-chain verification and enforcement diff included in the **F4
Opus 5 security review**.

### X3 implementation notes (established 2026-08-08, before starting)

Two questions decide how expensive this task is. Both are now answered
against the pinned dependency tree rather than assumed, so the
implementation does not have to discover them halfway through an auth
migration.

**1. There is no credential-storage migration. This was the big risk.**

`finish_attested_passkey_registration` returns `AttestedPasskey`, not
`Passkey`, which reads like a change of stored shape for every existing
credential. It is not. In `webauthn-rs` 0.5.5 (`src/interface.rs`) both
types are newtypes over the *same* inner `Credential`:

```rust
pub struct Passkey         { pub(crate) cred: Credential }
pub struct AttestedPasskey { pub(crate) cred: Credential }
```

Both derive `Serialize`/`Deserialize` with no container attributes, so
they serialize to identical JSON (`{"cred": …}`), and the crate ships
`impl From<AttestedPasskey> for Passkey`. So:

- the attested path converts its result to `Passkey` and writes the
  existing encrypted `passkey_json` column unchanged;
- `start_authentication` / `finish_authentication` keep using the
  `Passkey` API for attested and non-attested credentials alike;
- **no schema migration, no dual-format read path, and no window in
  which some credentials are unreadable.**

Attestation therefore changes only the *registration* ceremony, which is
exactly what the policy is about. Note the one behavioural difference the
crate documents: attested keys always enforce user verification.

The `attestation` feature this needs is in `webauthn-rs`'s **default**
feature set and the workspace does not set `default-features = false`, so
`start_attested_passkey_registration` is already compiled in — same
situation as A6's rustls backend. `webauthn-attestation-ca` is already in
`Cargo.lock` transitively.

**2. The vendored trust anchor is GlobalSign Root CA – R3, and its
fingerprint is verifiable.**

The MDS3 BLOB's signing chain roots in GlobalSign Root CA – R3. Fetched
from `https://secure.globalsign.com/cacert/root-r3.crt`, it presents:

```
subject = OU = GlobalSign Root CA - R3, O = GlobalSign, CN = GlobalSign
SHA-256 = CB:B5:22:D7:B7:F1:27:AD:6A:01:13:86:5B:DF:1C:D4:
          10:2E:7D:07:59:AF:63:5A:7C:F4:72:0D:C9:63:C5:3B
```

which matches the long-published fingerprint for that root. Vendoring it
is therefore defensible on evidence rather than on a single unverified
download, and **the documented update procedure must pin that SHA-256**:
re-fetching the file is not the check, matching the digest is. This
matters more than usual here — the vendored certificate is the root of
trust for every attestation decision the policy makes, so a swapped
anchor silently converts "only FIDO-certified authenticators" into "any
authenticator whose attestation an attacker can mint".

**3. What is genuinely blocked in a sandbox.** The registration
integration tests need *recorded attestation objects* — the plan names a
YubiKey direct-attestation fixture plus packed/none formats. Those must
come from real hardware or a vendor-published test vector; they cannot be
synthesized, and a test that fabricates them would assert the code
against its own assumptions. Either capture them from a device or lift
them from `webauthn-rs`'s own test corpus, and say in the test which.

---

## X4 — External-IdP token exchange (RFC 8693, cross-domain)

**Positioning.** Parent-plan B3 ships token exchange for **AXIAM-issued**
subject tokens. X4 extends the same grant to accept subject tokens from
**trusted external IdPs** — the "accept a partner's Entra/Okta/Keycloak
token at the mesh edge, emit a scoped AXIAM token" enterprise pattern.
Strictly gated on B3.

**Instructions.**

1. **Trust configuration, per federation provider** (extends the
   existing `axiam-federation` OIDC provider records — reuse
   `discovery_cache`/`jwks_cache`/`ssrf` infra, no new fetch paths):
   `token_exchange { enabled: false (default), accepted_audiences:
   [string] (non-empty required), subject_mapping: "linked_only" |
   "jit_provision" (default linked_only), scope_map: { external claim/
   scope → AXIAM scopes } (deny-by-default: unmapped ⇒ dropped),
   max_token_age_secs }`.
2. **Validation pipeline** for `subject_token_type=…:jwt` with an
   external `iss`: issuer must exactly match an enabled provider;
   signature via cached JWKS (existing kid-retry rollover behavior);
   `exp`/`iat`/`nbf` with bounded skew; `aud` ∩ `accepted_audiences`
   non-empty; token age ≤ `max_token_age_secs`. Subject resolution via
   the existing federated-identity link (`iss`+`sub` → AXIAM user);
   unlinked ⇒ reject (or JIT-provision when explicitly configured —
   reuses the federation JIT path, audited as such).
3. **Security invariants (pinned, tested):**
   - **No transitive exchange:** tokens minted by any exchange carry a
     provenance claim (`ext_exchange: {iss}` alongside B3's `act`);
     the grant rejects subject tokens bearing it — an exchanged token
     can never be re-exchanged, ours or theirs.
   - **Never widen:** requested scopes ⊆ scope_map output ⊆ the
     resolved user's actual permissions at mint time (the engine is
     consulted; deny-override applies post-B1).
   - External **refresh/ID tokens are rejected** as subject tokens
     (access tokens / assertion-style JWTs only, by `typ`/claims
     shape); `actor_token` from external issuers unsupported in v1.
   - Lifetime = min(subject remaining, provider max, B3 configured
     max). Every exchange audited with full provenance.
4. **Ops surface:** provider config CRUD already exists — extend DTOs +
   frontend federation pages (parent C4) with the `token_exchange`
   block; discovery metadata unchanged (grant already advertised by
   B3).
5. **SDK:** B3's `oauth2_token_exchange` helper already carries the
   parameters; contract gains a short §15 addendum (external subject
   tokens: what to pass, which errors mean "issuer not trusted") — no
   new per-SDK surface. One example (typescript + go): partner-token →
   AXIAM-token at an API gateway.

**Tests.** Validation-pipeline matrix (each invariant violated in
isolation ⇒ specific error); JWKS rollover mid-flight; JIT on/off;
transitive-exchange rejection both directions; scope-map property test
(output scopes ⊆ map range ∩ user permissions); fixtures with tokens
minted by a real Keycloak container in the e2e suite (cross-vendor
proof).

**Docs.** "Federated token exchange" guide (trust-config walkthrough,
threat notes: why deny-by-default scope maps, why no transitivity);
threat-model update.

**Model: Opus 5** for steps 2–3 (a cross-domain trust boundary; a
plausible-but-wrong validation order here is a cross-tenant/cross-org
privilege escalation) · **Sonnet 5** for config CRUD/DTOs, frontend,
example, docs. F4 review mandatory.

---

## X5 — FAPI 2.0 certification: readiness, conformance harness, and the OIDF fee-waiver letter

**Target.** **FAPI 2.0 Security Profile (Final)** certification for
AXIAM as an OpenID Provider (the current certifiable FAPI profile;
FAPI 1.0 Advanced remains available but new certifications should
target 2.0). Message Signing (JARM etc.) is a separate optional
certification — explicitly out of scope for this pass.

### X5.1 Gap analysis (grounded in the current tree)

Verified present: authorization code + PKCE, refresh rotation, EdDSA
JWTs, TLS 1.3 stack, mTLS listener (p3 profile), PAR planned in
parent-plan B5. Verified **absent** (grep of `axiam-oauth2`/
`axiam-auth`): `private_key_jwt` client auth, mTLS **client** auth for
the token endpoint (`tls_client_auth`/`self_signed_tls_client_auth`),
sender-constrained access tokens (no `cnf` claim anywhere), DPoP, RFC
9207 `iss` authorization-response parameter. FAPI 2.0 requires, beyond
what B5 delivers:

| Requirement | Status | Work |
|---|---|---|
| PAR, mandatory for FAPI clients | B5 (parent) | gate `require_par` on the FAPI client profile |
| Client auth: `private_key_jwt` **or** mTLS | absent | implement **both**; mTLS first (AXIAM's differentiator — the p3 infra exists), `private_key_jwt` second (RFC 7523 assertion validation, per-client registered JWKS/jwks_uri) |
| Sender-constrained tokens: mTLS certificate binding (`cnf.x5t#S256`, RFC 8705) **or** DPoP | absent | implement **mTLS binding first** (natural fit: cert already verified in-process at ~1% cost — this becomes a headline: *certificate-bound tokens at IoT prices*); DPoP (RFC 9449) second for non-mTLS clients |
| Resource servers verify the binding | absent | introspection + local-validation additions: `cnf` exposed via introspection; SDK middleware (§10) verifies `x5t#S256` against the presented client cert / DPoP proof |
| RFC 9207 `iss` in authz responses | absent | small; always emit |
| Authorization code single-use, strict redirect_uri equality, `response_type=code` only, no token in any URL | partially verified | audit + tests; enforce strictly under the FAPI profile |
| ID token / JWT algs: PS256/ES256/EdDSA only, no `none`, keys ≥ 2048 | EdDSA already | conformance-tightening pass + tests |
| Refresh-token & code lifetimes, `exp` bounds per profile | mostly | profile-driven config bundle |

Implementation vehicle: a per-client **`profile: "fapi2"` flag** that
bundles the constraints (require PAR + PKCE S256, require
private_key_jwt or mTLS auth, require sender-constraining, forbid the
relaxed behaviors) so ordinary clients are untouched and the FAPI
posture is one switch — same philosophy as the rate-limit postures.

### X5.2 Conformance harness

Run the **OpenID Foundation conformance suite** (open source,
`gitlab.com/openid/conformance-suite`, ships a docker-compose) locally
against a dev AXIAM: add `benchmarks/`-style tooling —
`just conformance-up / conformance-run / conformance-report` targets, a
pinned suite version, an AXIAM test-plan config file
(`fapi2-security-profile-final` OP test plan, both client-auth
variants), and a runbook doc (`claude_dev/fapi-conformance-runbook.md`)
recording how to run, read failures, and re-run single tests. Iterate
to green **before** any formal submission; keep the final HTML report
artifacts in-repo under `docs/conformance/` (they are the evidence for
the certification submission and good marketing in the benchmark
tradition of publishing the receipts).

### X5.3 Certification submission (after green)

Formal self-certification flow: run the certified test plan on the
release image (digest-pinned, matching the benchmark provenance
culture), submit results + certification request to OIDF, publish the
certification mark on the website. Fees at time of writing:
non-member per-profile fees (hundreds to low-thousands USD; member
rates lower) — hence §X5.4. Do not pay before the waiver answer
arrives.

### X5.4 Fee-waiver letter (deliverable, ready to adapt and send)

> To: certification@oidf.org
> Cc: director@oidf.org
> Subject: Fee waiver request — FAPI 2.0 OP certification for AXIAM (open-source IAM)
>
> Dear OpenID Foundation Certification Team,
>
> I am writing to request a certification fee waiver (or, failing
> that, guidance on reduced-fee options) for **AXIAM**, an open-source
> identity and access management server, ahead of our planned **FAPI
> 2.0 Security Profile (Final)** OpenID Provider certification.
>
> **About the project.** AXIAM (Access eXtended Identity and
> Authorization Management, https://github.com/ilpanich/axiam) is an
> Apache-2.0-licensed IAM platform written in Rust, targeting
> microservices and IoT deployments. It implements OAuth 2.0, OpenID
> Connect, native mutual TLS, and hierarchical RBAC, and is developed
> fully in the open — including our benchmark methodology: we publish
> complete, reproducible performance comparisons against incumbent
> products, *including our own regressions and failing test tables*,
> as a matter of project culture. We intend to treat conformance the
> same way: our OpenID conformance-suite results will be published in
> full alongside the certification, green and red alike.
>
> **Why a waiver.** AXIAM is an independent community project with no
> corporate sponsor and no commercial revenue. The certification fee,
> while modest for a vendor, is material for us — and certification is
> precisely the kind of ecosystem signal an open-source security
> project should lead with rather than defer. A waiver would directly
> convert into engineering time spent meeting the profile rather than
> funding gates around it.
>
> **What the Foundation gains.** A certified, freely auditable,
> memory-safe FAPI 2.0 implementation lowers the barrier for smaller
> financial-grade deployments and gives implementers a reference they
> can read to the last line. We commit to: (1) completing the full
> conformance test plan on a tagged, digest-pinned release before
> submission; (2) maintaining certification across future releases per
> the Foundation's re-certification policy; (3) publicly documenting
> our conformance process so other open-source implementers can follow
> it; and (4) prominently and accurately using the certification mark
> per the Foundation's guidelines.
>
> We have reviewed the self-certification process and expect to submit
> results for the FAPI 2.0 Security Profile (Final) OP test plan,
> covering both `private_key_jwt` and mutual-TLS client
> authentication variants. If the Foundation has a standing policy or
> precedent for open-source/non-commercial fee relief, we would be
> glad to provide any supporting information required — project
> governance, licensing, or finances.
>
> Thank you for the work the Foundation and the certification program
> do for the ecosystem; the openly available conformance suite has
> already made our implementation better before any formal submission.
>
> Kind regards,
> [Full name]
> Maintainer, AXIAM — https://github.com/ilpanich/axiam
> [Contact email]

*(Operator action: fill the two placeholders, optionally attach the
conformance-suite green report from §X5.2 — a completed test plan
attached to the request materially strengthens it. Recommended send
order: finish §X5.2 first, then send with the report; the letter's
commitment list assumes that ordering.)*

### X5.5 Tests, docs, acceptance

**Tests.** Per-gap unit/integration tests as listed in the X5.1 table
(binding verification matrix: right cert, wrong cert, no cert, DPoP
proof replay/nonce, private_key_jwt assertion vectors incl. rejected
algs); the conformance suite itself is the integration gate — its
pinned test-plan run wired into a manually-triggered CI workflow (too
slow for every PR).

**Docs.** "FAPI 2.0 profile" operator guide (enabling `profile: fapi2`,
client onboarding for both auth methods, sender-constraining with mTLS
— cross-linked to the IoT mTLS docs); SDK contract §10.1 addendum
(middleware must verify token binding when `cnf` present — fan-out via
D6); conformance runbook (§X5.2).

**Acceptance.** Conformance suite green on both client-auth variants
against a digest-pinned release image; no regression on non-FAPI
clients (full matrix cells within ±2%); letter sent (operator);
submission prepared.

**Model: Opus 5** for X5.1's protocol work (client auth, token
binding, DPoP — every one is a token-security mechanism where subtle
mistakes are CVEs) · **Sonnet 5** for the conformance harness/justfile
tooling, iteration on suite findings of the mechanical kind, docs. The
letter is delivered above (no further model spend).

---

## Sequencing (extends the parent plan's wave table; X-waves start after parent wave 3)

| Wave | Tasks | Gate |
|---|---|---|
| X-a | X1 design + protocol + dispatcher (Opus), X3 (full), X5.1 protocol work (Opus) | contract §16 merged; F4 review of X1/X3/X5.1 |
| X-b | X1 SDK fan-out ×8 + examples, X2 (needs B1 merged), X5.2 conformance harness + iteration | X1 e2e green; conformance first full run |
| X-c | X4 (needs B3 merged), X2 SDK helpers, X5.2 iterate-to-green | F4 review of X2/X4 |
| X-d | X5.3 submission prep + §X5.4 letter sent (operator), bench cells (X1 hook cost, binding overhead), docs/examples sweep | conformance green on release image |

## Model recommendation summary

| Task | Model | One-line rationale |
|---|---|---|
| X1 Reactors — events/protocol/dispatcher/§16 | **Opus 5** | External code influencing token contents; protocol is normative for 8 SDKs |
| X1 Reactors — SDK runtimes, CRUD, UI, examples | Sonnet 5 | Contract-pinned fan-out |
| X2 UMA — grant semantics + engine integration | **Opus 5** | Authorization issuance semantics |
| X2 UMA — rreg CRUD, introspection, SDK helpers, docs | Sonnet 5 | Spec-pinned plumbing |
| X3 WebAuthn attestation policy (all) | Sonnet 5 (+F4 review) | webauthn-rs/MDS do the crypto; policy matrix pinned in-task |
| X4 external-IdP exchange — validation/invariants | **Opus 5** | Cross-domain trust boundary |
| X4 — config/UI/example/docs | Sonnet 5 | Extends existing federation surface |
| X5 — client auth, mTLS/DPoP token binding | **Opus 5** | Token-security mechanisms; mistakes are CVEs |
| X5 — conformance harness, iteration, docs | Sonnet 5 | Tooling + suite-driven fixes |
| X5 — fee-waiver letter | — | Delivered in §X5.4 |

Same division of labor as the parent plan: Opus 5 owns every place
where a plausible-but-wrong answer mints a token it shouldn't; Sonnet 5
executes everything the contracts, specs, and this document have
already pinned.
