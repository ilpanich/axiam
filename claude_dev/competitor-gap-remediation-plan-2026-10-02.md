# Competitor gap remediation plan — 2026-10-02

> **Status: PROPOSED.** Written against AXIAM `1.0.0-beta17` from the three
> comparisons in this directory:
> [`competitor-comparison-keycloak.md`](competitor-comparison-keycloak.md)
> (Keycloak 26.8.0),
> [`competitor-comparison-zitadel.md`](competitor-comparison-zitadel.md)
> (Zitadel v4.19.4) and
> [`competitor-comparison-authentik.md`](competitor-comparison-authentik.md)
> (authentik 2026.8.3). Each item below is grounded in the current tree; where a
> comparison's claim about AXIAM was checked against the code, the finding is
> recorded under *Today*. As items land, each section gets an `EXECUTED` block
> at its head, in the form [`remediation-plan-2026-09-12.md`](remediation-plan-2026-09-12.md)
> uses.

The three comparisons agree on one thesis: AXIAM wins on **authorization depth,
high-assurance OAuth, PKI, efficiency and safe defaults**, and loses on
**enterprise integration** (SAML issuance, directories), **certification** and
a handful of newer protocol surfaces. This plan turns the three gap lists into
one ranked list, drops what the comparisons themselves say not to chase, and
proposes a phase of work with dependencies, acceptance criteria and the
bookkeeping each item owes (contract, threat model, website, SDKs).

---

## 1. Method

Each gap named by at least one comparison was scored on three questions:

1. **Breadth.** How many of the three competitors have it, and at what
   maturity (GA, preview, experimental, enterprise-only)?
2. **Positioning.** Does the gap block AXIAM's own niche (machine and IoT
   first, strict multi-tenancy, enterprise-grade), or would closing it turn
   AXIAM into a product it does not want to be (an application portal)?
3. **Leverage.** How much of the work is already in the tree, and does the
   gap sit on top of something AXIAM is uniquely good at (the integrated CA,
   the revocation feed, the AMQP event spine)?

Consolidated priority follows the comparisons' own three tiers. Where the
three documents disagree, the stricter reading was kept and the reason is
noted. The comparisons' *P3 — watch, do not chase* items are kept as explicit
decisions rather than dropped silently: a gap nobody wrote down is a gap the
next reviewer rediscovers.

---

## 2. Consolidated gap matrix

Legend for the competitor columns: **GA** generally available, **Pv** preview,
**Ex** experimental, **Ent** enterprise licence only, **—** absent, **?**
not documented.

| # | Gap | Keycloak | Zitadel | authentik | Priority in comparisons | **Consolidated** | Today in AXIAM |
|---|---|---|---|---|---|---|---|
| G-1 | OpenID / FAPI 2.0 certification | GA (FAPI 2.0 passed) | not reachable (no PAR/DPoP/mTLS) | GA (OP + logout, 2026.8) | K P1, A P1 | **P1** | Suites run on demand (`fapi-conformance.yml` is `workflow_dispatch` only); 2026-09-25: Basic OP 30/35 (4 `REVIEW`), FAPI 2.0 34/37 and 52/56 (2 `REVIEW`, 1 `WARNING`). X7 is planned with no code yet; X5 submission not sent |
| G-2 | SAML 2.0 identity provider | GA | GA | GA (+ WS-Fed Ent) | K P1, Z P1, A P1 | **P1** | SP only (`crates/axiam-federation/src/saml.rs`, 3 527 lines, behind the `saml` feature) |
| G-3 | LDAP / Active Directory as a user source | GA (+ Kerberos) | GA (external IdP) | GA (+ Kerberos, nested groups) | K P1, Z P1, A P1 | **P1** | Nothing: no crate, no model, no mention in the design document |
| G-4 | RFC 7592 client configuration endpoint | GA | GA (v4.17) | — | Z P2 | **P2** | RFC 7591 only; `dcr.rs` returns no `registration_access_token` and records 7592 as deferred |
| G-5 | Shared Signals Framework transmitter (CAEP / RISC) | Ex | — | Ent | K P2, A P2 | **P2** | Revocation feed `GET /oauth2/revocations` (R-6), webhooks, Reactors — the ingredients, not the protocol |
| G-6 | Outbound SCIM provisioning | — | — | GA | A P2 | **P2** | Inbound SCIM server only (`crates/axiam-scim`) |
| G-7 | CIBA (OpenID client-initiated backchannel authentication) | GA | — | — | K P2 | **P2** | Nothing |
| G-8 | Whole-stack resting footprint; AMQP mandatory | n/a | wins this cell | not measured | Z P2 | **P2** | Broker is a hard dependency: the server refuses to boot without an AMQP signing key (`main.rs:962`); no AMQP-less profile is documented |
| G-9 | Verifiable credentials (OID4VCI / OID4VP) | Pv / Ex | — | — | K P2 | **P2 (design only)** | Nothing |
| G-10 | Benchmark currency: Keycloak 26.8 memory claim; authentik never measured | — | — | — | K §4.1, A §4 | **P2** | `benchmarks/targets/` has `axiam`, `keycloak`, `zitadel`; run 5 measured Keycloak 26.7.0 |
| G-11 | RADIUS interface | — | — | GA (EAP-TLS Ent) | A P2 | **P3 (spike)** | Nothing |
| G-12 | Front-channel logout | GA | ? | GA | K P3, A P3 | **P3 (decline, recorded)** | RP-initiated and back-channel logout shipped (B5) |
| G-13 | Social-provider presets | large catalogue | GitLab, Azure AD, Zitadel | large catalogue | K P3 | **P3 (on demand)** | Google, GitHub, Microsoft, Apple, generic OIDC/OAuth2 |
| G-14 | Hosted offering, admin-console breadth, flow designer, outposts (proxy, RAC), governance workflows | varies | cloud | GA / Ent | K P3, Z P2, A P3 | **Watch, do not chase** | Out of the API-first scope by the comparisons' own argument |
| G-15 | Agent identity positioning (`zitadel/nextgen`, authentik "agent accounts") | — | Pv | Ent | Z P3, A table | **Watch + documentation** | Service accounts, RFC 8693 delegation with `act`, MCP profile end to end |

**Closed, not gaps.** Deny-override, device grant, token exchange (internal and
external), SCIM inbound, the logout and PAR triad, UMA 2.0, WebAuthn
attestation policy, DPoP, mTLS client auth, CIMD, RFC 8707, RFC 7591 and the
MCP profile all appear as parity or advantage in the three tables. Nothing in
this plan reopens them.

---

## 3. Ranking rationale

**Why G-1, G-2 and G-3 are the only P1s.** All three comparisons name the same
three items in their P1 tier, and each one blocks a *procurement* step rather
than a technical one. Certification is the checkbox buyers tick before any
evaluation. SAML issuance is the integration that enterprise SaaS still
demands, and AXIAM is the only one of the four products that cannot do it.
Directory federation is the brownfield door: without it AXIAM can replace a
greenfield IAM but cannot sit in front of an existing one. Their order matters
too: G-1 is nearly free (the work is reading four `REVIEW` logs and sending a
submission), G-2 reuses a 3 500-line SAML stack that already parses, verifies
and signs, and G-3 is the only P1 that starts from nothing.

**Why G-4 ranks above the other P2s.** It is small, it extends a surface AXIAM
markets (MCP clients register dynamically and increasingly expect to update or
delete their registration), and `dcr.rs` already names it as deferred.

**Why G-5 and G-6 are kept together.** Both are *outbound* identity signals.
SSF pushes session and credential events to relying parties; outbound SCIM
pushes lifecycle events to applications. They share a delivery engine (the
webhook dispatcher's retry, backoff and signing) and the same source of truth
(the audit and revocation feeds). Designing them apart would build two
dispatchers.

**Why G-8 is in the plan at all.** The Zitadel comparison is honest that the
whole-stack memory cell is the one efficiency figure AXIAM loses. An AMQP-less
profile also removes the single largest operational objection a small
deployment raises ("why do I need a broker for an IAM?"). It is a deployment
profile, not a product change.

**Why G-9 is design only.** OID4VCI is preview and OID4VP experimental in
Keycloak; the EUDI wallet reference framework is still moving. Writing the
design now, and implementing when the specifications settle, is cheaper than
chasing a moving target.

**Why G-12 is declined rather than deferred.** Front-channel logout depends on
third-party iframes and cookies, which browsers are removing. Back-channel
logout, which AXIAM ships, is the robust variant. Recording the decision stops
the item from reappearing in every future comparison.

---

## 4. Remediation items

Each item has the form: *Target · Today · Design · Acceptance · Bookkeeping ·
Size · Model*. Size is in single-session units as the roadmap uses them
(S ≤ 1, M 2–3, L 4–6, XL > 6). The model column follows the repository's
convention: Opus 5 where a mistake is a CVE or a normative contract change,
Sonnet 5 for pinned plumbing and fan-out.

### G-1 — Certification: Basic OP and FAPI 2.0 submissions — **P1**

**Target.** Two certificates: OpenID Connect *Basic OP* and *FAPI 2.0 Security
Profile (Final)*, as OpenID Provider, with the results published under
`docs/conformance/` green and red alike, as X5.4's fee-waiver letter promises.

**Today.** The 2026-09-25 runs leave seven modules open, none of them a
`FAILED`:

| Plan | Module | Verdict |
|---|---|---|
| Basic OP | `oidcc-prompt-login` | `REVIEW` |
| Basic OP | `oidcc-max-age-1` | `REVIEW` |
| Basic OP | `oidcc-ensure-registered-redirect-uri` | `REVIEW` |
| Basic OP | `oidcc-ensure-request-object-with-redirect-uri` | `REVIEW` |
| FAPI 2.0 (all three variants) | `…-ensure-unsigned-authorization-request-without-using-par-fails` | `REVIEW` |
| FAPI 2.0 (all three variants) | `…-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` | `REVIEW` |
| FAPI 2.0 (private_key_jwt) | `…-test-claims-parameter-identity-claims` | `WARNING` |

The two Basic OP `prompt`/`max_age` modules are exactly the ones
[`basic-op-gap-plan.md`](basic-op-gap-plan.md) says are unreachable until the
browser-SSO login hop and the `SameSite=Lax` OP-session cookie exist (X7.2,
X7.3). The plan is complete and the maintainer answered its two escalations on
2026-09-07; no crate source has changed since.

**Design.** No new design: execute X7.1 through X7.9 as planned, then X5.3.
Two additions:

1. A `REVIEW` module is closed by a human reading the suite log and writing
   the judgement down. Add `docs/conformance/REVIEW-JUDGEMENTS.md`, one entry
   per module: the log id, what the suite could not decide, what AXIAM does,
   and why that is conformant. A certification submission is this file plus
   the green run.
2. The `WARNING` on the `claims` parameter asks whether AXIAM honours
   requested identity claims on the FAPI lane. R-2 (requested claims survive a
   refresh) already touched this path; verify the warning is the "claims
   parameter not supported" deviation that FAPI permits and record it in the
   same judgement file, or support it on the honour lane only.

**Acceptance.** Both plans run `PASSED` on every module except documented
`SKIPPED` ones; the four FAPI variants are identical to the 2026-09-25
baseline except for the three modules above; the submission is sent and the
mark published on the website once granted.

**Bookkeeping.** `docs/conformance/`, the website's security section
(`website/src/docs/`), the threat model entries X7 names (profile-confusion
matrix M1–M9), `CHANGELOG.md`. No contract change: X7.0 decision A needs no
SDK code change.

**Size.** L (X7 is nine waves, several of them small). **Model.** Opus 5 for
X7.1 to X7.3 (authorization-request gating and the OP cookie are
security-bearing); Sonnet 5 for the harness, judgements and submission.

### G-2 — SAML 2.0 identity provider — **P1**

**Target.** AXIAM issues SAML 2.0 assertions to registered service providers,
per tenant: IdP metadata, Web Browser SSO profile with HTTP-Redirect and
HTTP-POST bindings, SP-initiated and IdP-initiated flows, signed assertions
(and optionally signed responses), attribute mapping from AXIAM claims, and
single logout wired into the existing session-revocation path.

**Today.** `crates/axiam-federation/src/saml.rs` implements the SP side on
`samael` with `xmlsec`: it builds `AuthnRequest`s, verifies signed responses
and assertions and maps claims. Everything an IdP needs to *verify* is there;
everything it needs to *issue* (assertion construction, signing with a tenant
key, SP registry, SLO) is not. The whole SAML stack is behind the `saml`
feature because `libxml` needs system libxml2 headers.

**Design.**

- **Placement.** A new module `saml_idp` in `axiam-federation` (layer 3) for
  the protocol, and a new `SamlServiceProvider` model in `axiam-core` with a
  repository in `axiam-db`. Routes live in `axiam-api-rest` under
  `/saml/v2/{tenant}/metadata`, `/sso`, `/slo`, mirroring the per-tenant
  path issuers T21.6 introduced for OIDC. No new crate: the layering table
  stays as it is.
- **Signing key.** The IdP signing certificate is issued by the tenant's
  signing CA through `axiam-pki`, with a new `CertificateType::SamlSigning`
  that reuses T22.14's per-type KU/EKU profile (digitalSignature only, no
  SANs). The private key is stored encrypted at rest exactly as signing-CA
  keys are (AES-256-GCM, `ca_key_store.rs`). This is the one place AXIAM is
  structurally ahead: Keycloak, Zitadel and authentik all require an
  externally produced certificate.
- **SP registry.** `SamlServiceProvider { tenant_id, entity_id, acs_urls,
  slo_url, name_id_format, sign_assertions, sign_responses, encrypt_assertions,
  sp_signing_cert, attribute_mappings, allowed_groups }`. Metadata import
  (upload an SP metadata XML) and manual entry. The ACS URL list is an
  allow-list checked the way redirect URIs are (exact match, no globs).
- **Authentication.** The SSO endpoint reuses X7.3's browser login hop and
  OP-session cookie: a SAML `AuthnRequest` is an authorization request with a
  different wire format. `ForceAuthn` maps to `prompt=login`; `IsPassive` to
  `prompt=none`. MFA enforcement, OPAQUE and passkeys apply unchanged because
  the session is the same session.
- **Assertion contents.** `NameID` from a per-SP policy (persistent pairwise
  identifier by default, email on request), `AuthnContextClassRef` from the
  session's `amr`, attributes from a mapping table over user fields, groups
  and roles. `SessionIndex` is the AXIAM session id, so SLO and the
  revocation feed revoke the same thing.
- **Security rules.** Assertions are signed always; responses signed by
  policy; `NotOnOrAfter` five minutes; `InResponseTo` must match an
  outstanding request stored with the same single-use guarantee X6 built for
  authorization codes; `Destination` must equal the ACS URL used; encryption
  with the SP's certificate optional and off by default. XML parsing stays in
  `samael`/`libxml` with external entities disabled, which the SP side
  already enforces.
- **Feature flag.** Same `saml` feature as the SP. The admin console gains an
  *SAML Service Providers* page per tenant.

**Acceptance.** An end-to-end test with a reference SP (the `samael`
test SP, plus an exported metadata round trip against Keycloak's SAML client
in the e2e harness); SP-initiated and IdP-initiated login; SLO revokes the
session and the revocation feed shows it; a replayed `InResponseTo` is
refused; an ACS URL outside the registry is refused; a tenant without the
feature returns 404 on all three endpoints.

**Bookkeeping.** Contract: a new §29 *SAML service provider registration*
for the eleven SDKs (management CRUD only; no SDK runs the browser flow).
OpenAPI regenerated. Threat model: new elements for the SSO and SLO endpoints
and the SP registry; threats for assertion replay, ACS redirection, signing
key exposure, XML external entities. Website: *Integrate* section. Design
document: the federation chapter.

**Size.** XL. **Model.** Opus 5 for assertion issuance, signing and the SP
allow-list; Sonnet 5 for the SP CRUD, metadata import, console page and SDK
fan-out.

### G-3 — LDAP / Active Directory identity source — **P1**

**Target.** A tenant can federate an existing LDAP or Active Directory
directory: users authenticate with their directory password, are provisioned
just in time, and their directory groups map onto AXIAM groups, so roles and
permissions keep working. Read-only against the directory. Kerberos is out of
scope for this item (see *Decisions*).

**Today.** Nothing in the tree. The design document does not mention
directories. The closest ancestors are the federation configuration model
(per-tenant external IdP with encrypted secrets, T19.8) and SCIM inbound
provisioning (user and group reconciliation with external ids).

**Design.**

- **Placement.** A new crate `axiam-directory` at **layer 3** next to
  `axiam-federation` (it is a federation protocol, with the same dependency
  shape), added to the layering table in `scripts/check-crate-layering.py`
  and to [`crate-layering.md`](crate-layering.md) in the same commit. It is a
  new crate, so it opts into `missing_docs` from its first commit. Dependency:
  the `ldap3` crate over `rustls` (no OpenSSL; the workspace is
  `rustls`-only).
- **Model.** `DirectoryConfig { tenant_id, url (ldaps:// or ldap:// +
  StartTLS, plaintext refused), bind_dn, bind_secret (secret provider, R-5
  pattern), base_dn, user_filter, user_attribute_map, group_base_dn,
  group_filter, group_member_attribute, sync_interval, jit_provisioning,
  trust_anchors }`. One directory per tenant in the first cut.
- **Authentication.** A new credential path in `axiam-auth`: resolve the
  user's DN by filter, bind as the user with the presented password, never
  store the password or a hash. The directory decides; AXIAM's brute-force
  counters, rate limits and lockout still apply in front of it, since the
  directory's own lockout policy may be absent. On success, upsert the local
  user with `source = directory`, `external_id = entryUUID | objectGUID`.
  MFA, passkeys and session issuance then proceed as for any user.
  Password change, reset and OPAQUE are refused for directory users with a
  clear error.
- **Group mapping.** `memberOf` (AD) or reverse `member` lookup (OpenLDAP),
  nested groups resolved to a configurable depth; mapped to AXIAM groups by
  DN or by a mapping table, so role inheritance through groups is unchanged.
- **Sync.** A background job on the server's existing cleanup-interval
  scheduler, per tenant: incremental by `modifyTimestamp` /
  `uSNChanged`, full reconciliation nightly, soft-delete on disappearance
  (never hard delete; GDPR erasure stays an explicit admin action).
- **Security rules.** Filters built with RFC 4515 escaping only, never by
  string formatting; referrals not followed; TLS verification mandatory with
  per-tenant trust anchors (the org CA can be one); bind secret via the
  secret provider; the bind DN gets read-only directory rights and the docs
  say so; connection pool bounded per tenant.

**Acceptance.** Integration tests against containerised OpenLDAP and Samba AD
in the e2e harness (`docker/` gains both): login, JIT provisioning, group
mapping into an existing role assignment, nested group, disabled directory
account refused, filter injection attempt refused, plaintext URL refused at
config time, sync removes a vanished user as soft-delete.

**Bookkeeping.** Contract: no SDK change for login (the SDK calls the same
login endpoint); a §30 management CRUD for the directory config. OpenAPI,
console page (*Directory* per tenant), website *Integrate* section, design
document chapter, threat model elements for the directory connector and the
sync job.

**Size.** XL. **Model.** Opus 5 for the bind path, filter construction and
trust handling; Sonnet 5 for sync, mapping, CRUD, console and docs.

### G-4 — RFC 7592 client configuration endpoint — **P2**

**Target.** A dynamically registered client can read, update and delete its own
registration with the `registration_access_token` RFC 7591 lets the server
return.

**Today.** `dcr.rs` issues registrations and deliberately omits
`registration_access_token` and `registration_client_uri`, recording RFC 7592
as deferred. The `oauth2_registration_token` model holds *initial access*
tokens for gated registration, not per-client management tokens.

**Design.** On `POST /oauth2/register`, mint a per-client management token
(32 random bytes, hash stored on the client row, plaintext returned once) and
return `registration_client_uri = {issuer}/oauth2/register/{client_id}`.
Mount `GET`, `PUT`, `DELETE` on that URI, authenticated by the management
token only (never by a user or service-account token), tenant-scoped through
the issuer path. `PUT` re-validates through the same `validate` as
registration, keeps the tenant's policy limits, and rotates the management
token. `DELETE` revokes the client's tokens and sessions through the existing
revocation path. Rate limit the three routes with the registration limiter.

**Acceptance.** Round trip register → read → update redirect URIs → delete;
a token from another client is `401`; a `PUT` widening scopes beyond tenant
policy is `400`; the MCP e2e harness (T21.8) exercises read and delete.

**Bookkeeping.** Contract §28 (MCP helpers) gains the three operations;
OpenAPI; threat model entry on the management token; website *OAuth2*
section.

**Size.** S. **Model.** Opus 5 (an unauthenticated-by-user write surface on
the authorization server, the same class as T-272 to T-280).

### G-5 — Shared Signals Framework transmitter — **P2**

**Target.** AXIAM transmits CAEP `session-revoked`,
`credential-change`, `assurance-level-change` and RISC `account-disabled`,
`account-enabled`, `account-purged` events as Security Event Tokens (RFC
8417) to registered receivers, over push (RFC 8935) and poll (RFC 8936), with
the SSF stream management API and discovery at
`/.well-known/ssf-configuration`.

**Today.** The ingredients exist and the protocol does not. The revocation
feed (`GET /oauth2/revocations`, R-6) already publishes session and token
revocations; webhooks deliver HMAC-signed JSON with retry; Reactors emit the
same events onto AMQP; the audit log records credential changes.

**Design.** A `ssf` module in `axiam-oauth2` (layer 4): a `SsfStream` model
per tenant and receiver (audience, delivery method, endpoint, requested
events, status), SETs signed with the tenant's EdDSA issuer key and published
on the existing JWKS, a subject identifier policy (`iss_sub` by default,
`email` on request). Event sources: the revocation feed for sessions and
tokens, the audit log for credential and account state changes. Delivery
reuses the webhook dispatcher's queue, retry and backoff; poll delivery is a
per-stream bounded buffer with acknowledgement. Receiver registration is an
admin operation; the stream management API is receiver-authenticated by an
OAuth2 client credential with a dedicated scope.

**Acceptance.** A test receiver in the e2e harness receives a SET within one
second of a session revocation and verifies it against the JWKS; poll with
acknowledgement drains the buffer; a disabled stream delivers nothing;
discovery lists the supported events.

**Bookkeeping.** Contract: a receiver helper is optional (`SHOULD`) in the
seven full-surface SDKs. Threat model: new element and threats for receiver
impersonation and event flooding. Website *Integrate* section.

**Size.** L. **Model.** Opus 5 for SET issuance and stream authentication;
Sonnet 5 for delivery plumbing and docs.

### G-6 — Outbound SCIM provisioning — **P2**

**Target.** A tenant can register downstream SCIM 2.0 service providers and
AXIAM pushes user and group lifecycle changes to them, with reconciliation.

**Today.** `axiam-scim` is a server only. User and group mutations already
produce audit events and webhook deliveries.

**Design.** A SCIM client in `axiam-scim` (layer 7 already; the client needs
nothing from the REST layer, so it can move to layer 3 if the layering check
prefers, in the same commit that adds the code). `ScimTarget { tenant_id,
base_url, auth (bearer via secret provider | OAuth2 client credentials),
mapping, filter (groups whose members are provisioned) }`. Lifecycle events
from the same source as G-5 are translated to `POST /Users`, `PATCH`, and
`DELETE` (or `active=false` by policy), with `externalId = AXIAM id` and the
downstream id stored on a link row. Delivery through the shared dispatcher
(G-5). A nightly reconciliation lists the downstream and repairs drift.

**Acceptance.** A test SCIM server in the harness; create, rename, group
membership change, disable and erase propagate; a downstream 5xx retries with
backoff and a 4xx dead-letters with an admin notification; GDPR erasure
(T18.2) propagates as `DELETE`.

**Bookkeeping.** Contract §31 management CRUD; OpenAPI; console page; threat
model (credential storage for targets, over-provisioning); website.

**Size.** M. **Model.** Sonnet 5, with the dispatcher shared with G-5 built
first under Opus 5.

### G-7 — CIBA — **P2**

**Target.** OpenID Connect Client-Initiated Backchannel Authentication, poll
and ping modes, as the FAPI-CIBA profile requires.

**Today.** Nothing. The device grant (B2) is the nearest relative: a pending
authorization that a user completes elsewhere.

**Design.** `POST /oauth2/bc-authorize` issues an `auth_req_id` bound to a
`login_hint` or `id_token_hint`, with `binding_message` and a user code; the
user is notified through the email service (and later push) and approves on
the user identity pages (T15.7) after full authentication including MFA; the
token endpoint accepts `grant_type=urn:openid:params:grant-type:ciba` with
the same single-use redemption X6 guarantees. Ping mode reuses the webhook
dispatcher. Brute-force protection on `auth_req_id` polling: interval
back-off, as the device grant does, and the rate-limit preset.

**Acceptance.** Poll and ping end to end in the e2e harness; expired and
already-redeemed requests refused; the Keycloak CVE class (brute-force
lockout not applying to CIBA, 26.7.x) covered by a test that the limiter
counts CIBA attempts.

**Bookkeeping.** Contract §32 (the seven full-surface SDKs gain a CIBA
initiation helper); OpenAPI; threat model; website.

**Size.** L. **Model.** Opus 5.

### G-8 — AMQP-less deployment profile and whole-stack footprint — **P2**

**Target.** A documented *minimal* profile in which AXIAM runs with SurrealDB
only, and a re-measured whole-stack resting footprint.

**Today.** The broker is mandatory: `axiam-server` fails closed at boot
without an AMQP signing key (SECHRD-08), and async authz, audit ingestion,
mail delivery, Reactors, event notifications and the cross-replica
cache-invalidation publisher all ride AMQP.

**Design.** `AXIAM__AMQP__ENABLED=false` (default `true`): the AMQP consumers
and producers are not started; audit events are written directly by the audit
service (which already has the repository); the mail consumer runs in-process
on a bounded channel; webhooks already deliver from the REST process;
Reactors and async authz are reported as unavailable in `/health` and their
admin routes return `409` with a message naming the profile. Cross-replica
cache invalidation has no transport without the broker, so the minimal
profile is **single-replica by definition**: boot refuses `amqp.enabled=false`
together with a replica count above one, and the docs say so first. The compose
file gains `docker-compose.minimal.yml`. The benchmark's §5 resource table
gains a *minimal* row.

**Acceptance.** The full REST and gRPC suites pass with the flag off, minus
the Reactor and AMQP tests, which are skipped by profile and listed; boot
refuses a configuration that enables Reactors with AMQP off; the resting RSS
of server plus SurrealDB is measured and published.

**Bookkeeping.** Deployment docs, website *Operate*, `CHANGELOG`, benchmark
analysis. No contract change.

**Size.** M. **Model.** Sonnet 5, with an Opus 5 review of the audit-write
path (audit durability, T19.27, must not regress).

### G-9 — Verifiable credentials: design only — **P2**

**Target.** `claude_dev/verifiable-credentials-design.md`: how AXIAM would act
as an OID4VCI issuer and an OID4VP verifier for the EUDI wallet architecture,
which credential formats (SD-JWT VC first, mdoc evaluated), how the tenant
signing keys and the integrated CA map onto issuer trust, what the data model
and endpoints are, and what the implementation would cost. No code.

**Acceptance.** The design names the specification versions it targets, the
Rust crates evaluated, the threat model elements it would add, and a go/no-go
criterion (specification stability, one concrete adopter).

**Size.** S. **Model.** Opus 5.

### G-10 — Benchmark currency — **P2**

**Target.** Re-measure Keycloak at 26.8 (which reports reduced memory) and
Zitadel at v4.19, and add authentik 2026.8 as a fourth benchmark target, so
that the authentik comparison can make a performance statement.

**Design.** A `benchmarks/targets/authentik/` profile in the same shape as
`keycloak/` and `zitadel/` (container, seed, k6 scenarios for the shared
endpoints: client credentials, introspection, JWKS, userinfo, password
login); run 6 on the same G-box with the run-5 caps.

**Acceptance.** `PUBLIC_BENCH_ANALYSIS.md` seventh draft with four targets;
the three comparison documents' performance rows updated and their change
logs dated.

**Size.** M. **Model.** Sonnet 5.

### G-11 — RADIUS: spike — **P3**

**Target.** A one-session spike answering whether a RADIUS front end with
EAP-TLS over the integrated CA is a fit for AXIAM's network-device audience,
and what it would cost. authentik gates EAP-TLS behind its enterprise licence;
AXIAM could ship it open source. Outcome: a decision record, not code.

**Size.** S. **Model.** Sonnet 5.

### G-12 — Front-channel logout: decline — **P3**

**Decision.** Not implemented. Rationale: it depends on third-party iframes
and cookies that browsers are removing; back-channel logout (shipped) is the
robust variant and the one FAPI and the OpenID logout certification profile
for back-channel require. Record in the design document's logout chapter and
in the three comparisons' change logs so the item stops recurring. Revisit
only on a concrete adopter request.

**Size.** S (documentation).

### G-13 — Social-provider presets: on demand — **P3**

**Decision.** Generic OIDC and OAuth2 cover the catalogue. Add a named preset
only when a user asks, one preset per PR, GitLab first if any. No scheduled
work.

### G-14 — Portal features: watch, do not chase

Hosted offering, admin-console breadth, visual flow designer, forward-auth
and remote-access outposts, privileged-access and offboarding workflows.
All three comparisons place these outside AXIAM's scope. No work. The
competitor change logs track them.

### G-15 — Agent identity: documentation

**Target.** AXIAM already has what authentik sells as "agent accounts" and
what `zitadel/nextgen` previews: service accounts, RFC 8693 delegation with
`act` and depth-capped chains, CIMD, RFC 8707, loopback public clients and
the MCP profile. The gap is a named story. Add a website page and a
`docs/` guide, *Identity for agents*, that walks an agent through
registration, delegated acting on behalf of a user, resource indicators and
revocation, with SDK snippets from the §28 helpers. Watch `zitadel/nextgen`
in the Zitadel change log.

**Size.** S. **Model.** Sonnet 5.

---

## 5. Sequencing

Dependencies, then waves. G-1 goes first because it is cheap and because G-2
reuses its browser-SSO login hop. G-5 and G-6 share a dispatcher, so the
dispatcher lands once, under G-5. G-8 is independent and can fill gaps.

```
G-1 (X7 waves, X5 submission) ──► G-2 (SAML IdP reuses the login hop)
G-3 (directory)                   independent, starts in parallel with G-1
G-4 (RFC 7592)                    independent, small
G-5 (SSF) ──► G-6 (outbound SCIM shares the dispatcher)
G-7 (CIBA)                        after G-1 (FAPI baseline must be green first)
G-8 (AMQP-less)                   independent
G-9, G-10, G-11, G-12, G-15       independent, documentation and measurement
```

| Wave | Items | Why together |
|---|---|---|
| W1 | G-1 (X7.1–X7.3), G-4, G-12, G-15, G-9 | The P1 that is nearly free, three small items, and the two decision documents |
| W2 | G-1 (X7.4–X7.9, X5.3 submission), G-3 (crate, model, bind path) | Certification closes; the directory crate's security core lands under Opus 5 |
| W3 | G-2 (SP registry, signing key, SSO), G-3 (sync, mapping, console) | SAML IdP on top of the login hop; directory completes |
| W4 | G-2 (SLO, console, contract §29), G-5 (dispatcher, SETs, streams) | SAML completes; the outbound signal spine lands |
| W5 | G-6, G-7, G-8 | Outbound SCIM on the dispatcher; CIBA on a green FAPI baseline; the minimal profile |
| W6 | G-10 (run 6 with four targets), G-11 spike, comparison documents refreshed | Measure after the product changed |

Every wave ends with the F4 security review before merge, as Track B
required, and with `cargo clean` between plan steps as `CLAUDE.md` requires.

Proposed roadmap entry: **Phase 23 — Competitor gap closure**, tasks T23.1
through T23.15 mapping one-to-one onto G-1 through G-15, in wave order. This
plan does not edit `roadmap.md`; the phase is added when the maintainer
accepts the plan.

---

## 6. Model recommendation summary

| Item | Model | Why |
|---|---|---|
| G-1 X7.1–X7.3 | **Opus 5** | Authorization-request gating and the OP cookie; a profile-confusion mistake weakens FAPI clients |
| G-1 harness, judgements, submission | Sonnet 5 | Suite-driven, pinned by the plan |
| G-2 assertion issuance, signing, ACS allow-list | **Opus 5** | Assertion forgery or redirection is an account takeover at every SP |
| G-2 SP CRUD, metadata import, console, SDK fan-out | Sonnet 5 | Contract-pinned plumbing |
| G-3 bind path, filter escaping, TLS trust | **Opus 5** | Directory injection or a plaintext bind leaks every corporate password |
| G-3 sync, mapping, CRUD, console | Sonnet 5 | Reconciliation plumbing |
| G-4 | **Opus 5** | A new write surface authenticated by a bearer the server mints |
| G-5 SET issuance, stream auth | **Opus 5** | Forged signals revoke sessions at relying parties |
| G-5 delivery, G-6 | Sonnet 5 | Dispatcher reuse |
| G-7 | **Opus 5** | A new grant with single-use redemption; the Keycloak 26.7 CVE class |
| G-8 | Sonnet 5, Opus 5 review | Audit durability must not regress |
| G-9, G-11 | Opus 5 / Sonnet 5 | Design judgement / spike |
| G-10, G-12, G-13, G-15 | Sonnet 5 | Measurement and documentation |

---

## 7. Cross-cutting rules every item owes

1. **Contract before SDK.** A server change that an SDK can see ships with its
   `sdks/CONTRACT.md` section and `sdks/openapi.json` regeneration in the same
   PR; SDK ports follow from the merge commit, never from a draft (the
   fan-out rules in [`remediation-plan-2026-09-12.md`](remediation-plan-2026-09-12.md) §13).
2. **Threat model in the same commit.** New elements and threats enter
   [`threat-model-stride.md`](threat-model-stride.md) and `Axiam.json` with the
   code, not after. G-2, G-3, G-5 and G-7 each add a trust boundary.
3. **Layering.** `axiam-directory` is placed in the layering table in the
   commit that creates it; any move of the SCIM client is justified in
   [`crate-layering.md`](crate-layering.md).
4. **Documentation lint.** New crates opt into `missing_docs` from their
   first commit; existing crates are not opted in by these items.
5. **Features.** Everything SAML stays behind the `saml` feature; CI's
   *Build (SAML off)* job must stay green. The directory crate has no
   feature flag (pure Rust, `rustls`).
6. **Safe defaults.** Every new inbound surface (SAML SSO, `bc-authorize`,
   RFC 7592 routes, SSF stream API) is covered by the rate-limit presets
   before merge; a limiter that forgets a route is the Keycloak 26.7 lesson.
7. **Website and comparisons.** Each landed item updates the relevant
   `website/src/docs/` module and flips its row in the three comparison
   tables, with a dated change-log line.

---

## 8. Decisions requested from the maintainer

| # | Question | Recommendation |
|---|---|---|
| D-1 | Kerberos (SPNEGO) in G-3? | **No** in this phase. It needs a browser-facing negotiate handshake and a keytab on the server; LDAP bind covers the directory case. Revisit on request |
| D-2 | SAML assertion encryption in the first cut of G-2? | **Optional and off by default.** Signed assertions over TLS are what the three competitors default to; encryption adds key management for SPs that rarely use it |
| D-3 | SAML IdP-initiated SSO? | **Yes, per SP opt-in**, default off. It is the flow most enterprise SaaS onboarding guides still describe; unsolicited responses are the replay risk, hence the opt-in |
| D-4 | SSF receiver (consume signals from upstream IdPs) alongside the transmitter? | **Later.** Transmitting is what relying parties ask an IAM for; receiving matters once AXIAM federates to an upstream that transmits |
| D-5 | CIBA now (W5) or after a first adopter? | **W5**, because FAPI-CIBA is the natural next certification after FAPI 2.0 and the device grant already paid for the pending-authorization machinery |
| D-6 | Front-channel logout | **Decline**, record (G-12) |
| D-7 | authentik as a benchmark target | **Yes** (G-10); the authentik comparison makes no performance claim today and says why |
| D-8 | Phase 23 in `roadmap.md` | **Yes**, on acceptance of this plan |

---

## 9. What this plan does not do

- It does not reopen any item the comparisons list as closed (§2, *Closed,
  not gaps*).
- It does not propose a hosted offering, a flow designer, outposts or
  governance workflows (G-14).
- It does not change AXIAM's licence, database or broker; G-8 makes the
  broker optional, not absent.
- It does not implement verifiable credentials (G-9 is design only) or
  RADIUS (G-11 is a spike).
- It does not edit `roadmap.md`, `design-document.md` or the three comparison
  documents; each landed item does that in its own PR.
