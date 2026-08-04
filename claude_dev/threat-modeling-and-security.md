# Threat Modeling & Security

> **Website section source.** This document is written to become a new, dedicated
> **Security** section on the AXIAM website (a top-level nav entry alongside Docs,
> SDKs and Benchmarks). It is public-facing: it explains how AXIAM is designed to
> be secure, what it defends against, and where responsibility passes to whoever
> deploys it. The internal, code-level evidence lives in
> [`security-analysis-2026-08-02.md`](security-analysis-2026-08-02.md), the
> [`threat-model-stride.md`](threat-model-stride.md) STRIDE model, and the
> [`security-audit.md`](security-audit.md) compliance index — this page is the
> readable summary those documents hang from.
>
> ---
>
> ## Handoff — read this first if you are building the website section
>
> **Status: ready to publish.** Every factual claim below was verified against
> the code at `3ede4d19` (2026-08-04) and is current. The security review series
> that backs it is **closed with no open findings** — see §24 of the analysis.
> You do not need to re-verify anything to build the page; if you want to check a
> specific claim, the evidence is cited by file and line in the analysis document.
>
> **What to build.** A new top-level **Security** nav entry, alongside Docs, SDKs,
> Benchmarks and Roadmap. Concretely, in `website/`:
>
> 1. `src/types.ts` — add `"security"` to the `Page` union.
> 2. `src/components/Header.tsx` — add a `NAV_ITEM` (`{ label: "Security", page: "security", active: (p) => p === "security" }`).
> 3. `src/App.tsx` — add the `{page === "security" && <Security />}` branch.
> 4. `src/pages/Security.tsx` — the page itself, or extend `src/docs.ts` if you
>    prefer it inside the existing docs shell with a sidebar.
>
> **Content mapping.** The structure here maps onto the existing `DocBlock` model
> in `src/docs.ts`: `##`→`h`, paragraphs→`p`, bullet lists→`list`, tables→`table`,
> and the blockquote marked **Caution**→`warn`. The eight subsections under
> *"How AXIAM defends each layer"* are the natural sidebar entries.
>
> **Three things not to change when adapting the prose:**
>
> - **Do not upgrade the hedges.** "No open Critical or High finding *in AXIAM's
>   own request path*", "self-assessment, not a certified audit", and the alpha
>   caution are all load-bearing and deliberately scoped. Removing a qualifier
>   turns an accurate statement into a false one.
> - **Do not add claims.** Everything here is backed by verified code. A plausible
>   extra bullet is the one thing on the page that would not be.
> - **Keep the shared-responsibility section.** It is the part that makes the rest
>   credible, and it is where a real deployment gets its hardening checklist.
>
> **One open TODO:** the closing line asks for a security contact. There is no
> `SECURITY.md` in the repository yet — either add one and link it, or drop the
> parenthetical and give an email. Do not ship the placeholder as written.

---

## Security at a glance

AXIAM is an identity and access-management platform, so it is itself a piece of
security infrastructure: a weakness here is a weakness in every application that
trusts it. The project treats that seriously. Security is not a feature bolted on
at the end — it is designed in, verified continuously, and documented honestly,
including the risks AXIAM cannot close on its own.

Three principles run through the whole system:

- **Secure by default.** The safe configuration is the one you get out of the box.
  Authorization is default-deny, TLS 1.3 is the floor for external traffic, tokens
  live in `HttpOnly` cookies, secrets are encrypted at rest, and a missing
  encryption key fails startup rather than silently substituting a weak one.
- **Defense in depth.** No single control is load-bearing. Tenant isolation is
  enforced at the handler, the query and the graph-traversal layers; a stolen
  token is short-lived, signature-pinned and revocable; a forged message must pass
  transport, signature and freshness checks before it is acted on.
- **Honest about the boundary.** A threat AXIAM cannot close from inside the
  application — backup encryption, cluster RBAC, per-service broker credentials —
  is written down as an open item with guidance, not quietly assumed away.

The system is verified against a **STRIDE threat model of 149 threats** and a
compliance self-assessment covering **OWASP ASVS Level 2, ISO/IEC 27001:2022,
the EU Cyber Resilience Act and GDPR**, with its OAuth2/OIDC surface checked
against the relevant RFC and OpenID conformance matrices.

---

## The threat model

AXIAM maintains a formal threat model in **[OWASP Threat Dragon](https://www.threatdragon.com)**
format, built with the **STRIDE** methodology (Spoofing, Tampering, Repudiation,
Information disclosure, Denial of service, Elevation of privilege). It is a
design-level model: it reasons about the system's data flows and trust boundaries,
and records the specific control that answers each threat — or marks the threat
open and says why.

| | |
|---|---|
| Methodology | STRIDE, per-element |
| Tool | OWASP Threat Dragon (model schema v2) |
| Diagrams | 9 |
| Threats identified | 149 |
| Mitigated / Open | 128 / 21 |

Every threat is examined against the STRIDE categories that apply to its element
type (actor, process, data store or data flow). A threat is marked **mitigated**
only where a control exists in the codebase and can be pointed at; where the
residual risk is accepted, deferred, or belongs to whoever deploys AXIAM, it stays
**open** and explains itself. An honest open item is more useful than an
optimistic closed one.

### Coverage by area

| Area | Threats | Open |
|---|---|---|
| System context | 26 | 3 |
| Authentication & session management | 22 | 1 |
| OAuth2 / OIDC authorization server | 14 | 0 |
| Federation (SAML SP & OIDC RP) | 15 | 0 |
| Authorization engine (RBAC, hierarchy, scopes) | 15 | 1 |
| PKI, certificates & IoT device identity | 13 | 1 |
| Audit, webhooks, email & notifications | 18 | 4 |
| Deployment & platform (Kubernetes) | 11 | 7 |
| Client SDKs & admin-UI integration surface | 15 | 4 |

The concentration of open items in *Deployment* and *Client SDKs* is deliberate
and expected: those are the two areas where security is a shared responsibility
between AXIAM and the people who run and integrate it. AXIAM's own request path —
authentication, authorization, tokens, PKI, federation — carries **no open
Critical or High finding**.

---

## Trust boundaries

Five trust boundaries recur across the system. A data flow that crosses one is a
place where authentication, authorization, validation and transport protection all
have to be re-established — nothing is assumed across a boundary.

| Boundary | Separates | What must hold on every crossing |
|---|---|---|
| **Public Internet ↔ AXIAM** | Browsers, SDK callers, IoT devices, external IdPs | TLS 1.3, authentication, rate limiting, CSRF on cookie requests, input validation |
| **AXIAM ↔ data tier** | Application pods ↔ SurrealDB, RabbitMQ, Secrets | Private network, credentialed connections, parameterised queries, tenant scoping at the repository layer |
| **Tenant ↔ tenant** | Every tenant's data from every other's | Tenant context derived from the verified session or JWT — never from request input — and enforced on every query and graph traversal |
| **AXIAM ↔ third parties** | Outbound to IdPs, email providers, webhook receivers | SSRF guard with resolve-and-pin, HTTPS enforcement, response-size caps, HMAC signatures on deliveries |
| **Server ↔ SDK / admin UI** | The server contract from its client implementations | One cross-language contract — TLS policy, secret redaction, CSRF, AMQP HMAC — enforced by CI drift and protobuf gates |

### The assets worth protecting

| Asset | Protection | Compromise would mean |
|---|---|---|
| JWT signing key (Ed25519) | Kubernetes Secret, never in the image | Any identity in any tenant forged |
| Organization CA private key | AES-256-GCM encrypted at rest | Any user/service/device certificate minted |
| Password hashes | Argon2id, per-user salt, pepper | Offline cracking of credentials |
| MFA secrets | AES-256-GCM encrypted at rest | Second factor defeated |
| Refresh tokens & sessions | Stored hashed, single-use rotation | Sustained impersonation |
| Client & webhook secrets | Hashed / encrypted, redacted from logs | Service-account impersonation; forged events |
| Authorization graph | Private data tier, API-only mutation, audited | Silent privilege escalation |
| Audit log | Append-only, OpenPGP-signed | Loss of accountability |

---

## How AXIAM defends each layer

### Authentication & sessions

- **Passwords** are hashed with **Argon2id** at OWASP-recommended parameters
  (~19 MiB memory cost, per-user salt, server-side pepper). Plaintext passwords are
  never stored or logged.
- **Login is enumeration-safe and brute-force-resistant**: unknown-user and
  bad-password return the same uniform failure, password verification runs on a
  dummy hash when the user does not exist so timing does not distinguish the two,
  and failed attempts drive an atomic, exponential-backoff lockout that is shared
  by every credential-checking path (REST and gRPC alike).
- **Rate limits are sized by what an operation costs, not by one global number.**
  A password verification is thousands of times more expensive than a permission
  check, so it gets its own much tighter ceiling — and that ceiling is deliberately
  *not* derived from the throughput knobs, so tuning a cluster for authorization
  volume cannot widen credential guessing as a side effect. The internet-facing
  human endpoints (login, registration, password reset, MFA) keep strict per-IP
  limits under every deployment profile, enforced structurally: the tuning presets
  are prevented from touching them at all. Every request path is bounded, including
  infrastructure endpoints like health and reflection — there is no unmetered route.
- **MFA** is built in — TOTP today, WebAuthn/passkeys for phishing-resistant,
  origin-bound second factors. TOTP codes are single-use within their window
  (replay is rejected with an atomic compare-and-set), and the MFA challenge is a
  distinct, single-use, no-authority token so the second factor can never be
  skipped by replaying it.
- **Tokens**: access tokens are **EdDSA (Ed25519) JWTs**, 15 minutes long. The
  verifier pins the algorithm and never reads it from the token header, so
  `alg:none` and HMAC-key-confusion attacks are rejected outright. Refresh tokens
  are opaque, server-stored and **single-use with rotation**, consumed through an
  atomic delete-gate so a race cannot fork the session or hide a stolen-token
  reuse. In the browser, tokens live only in `Secure` / `HttpOnly` /
  `SameSite=Strict` cookies — never in `localStorage`, never in a URL.
- **Password reset** uses CSPRNG-generated, single-use, short-lived tokens
  (never time-ordered UUIDs), delivered over an authenticated POST, and consuming a
  reset invalidates every existing session. An optional **Have I Been Pwned**
  k-anonymity check (only a five-character hash prefix leaves the server, behind a
  circuit breaker) blocks known-breached passwords.

### Authorization & tenant isolation

Tenant isolation is the core guarantee of a multi-tenant IAM, so it is enforced
redundantly rather than at one chokepoint:

- **Tenant context comes from the verified session or JWT, never from request
  input.** A caller cannot name a tenant it does not belong to. The organization
  claim in a token is derived server-side from the tenant record on both login and
  refresh — it is never accepted from the client.
- **Repository queries are tenant-scoped and parameterised.** Every SurrealQL
  statement uses bind parameters — no query is assembled by string concatenation of
  user input — and carries a `tenant_id` predicate. Cross-tenant graph edges are
  stripped during permission resolution rather than followed. The isolation is
  enforced twice over: an edge that would cross tenants cannot be *written* in the
  first place, and every traversal that reads one — including group membership,
  the indirect path by which roles are inherited — re-checks the tenant at read
  time rather than trusting the write-time guard.
- **The authorization engine is RBAC, additive, allow-wins with default-deny.**
  A route with no declared permission is refused, not allowed. Roles cascade down a
  resource hierarchy with bounded, cycle-safe traversal.
- **The performance caches are off by default and never change an answer.** AXIAM
  offers two optional caches — one for authorization decisions, one for session
  validation. Both ship disabled, both are keyed per tenant, and both are invalidated
  by the mutations that could change their answer, so revoking a role or a session
  takes effect immediately on the replica that handled it. Enabling one is an
  explicit, logged decision that trades a few seconds of worst-case staleness for
  throughput — never correctness.
- **Revocation propagates across replicas, and a cache that cannot hear it switches
  itself off.** The decision cache can broadcast invalidations to every replica over
  the message broker. Those messages are signed with the same per-tenant authenticated
  envelope as the rest of AXIAM's messaging — nonce, timestamp and constant-time
  verification — so a party with broker access but no signing key cannot forge one,
  and a forged message could in any case only *drop* cache entries, never grant
  access. The design fails safe in both directions: a replica starts out not trusting
  its cache and only begins using it once it is successfully subscribed, and if a
  privilege-narrowing change cannot be broadcast, the change itself fails rather than
  leaving other replicas stale.
- **Three protocols, one engine.** REST middleware, gRPC `CheckAccess` and the
  async AMQP path all evaluate the same policy. The gRPC interceptor authenticates
  the caller and derives the tenant from its verified identity, so a service account
  cannot ask about a subject outside its own tenant.

### OAuth2 & OpenID Connect

AXIAM is a full OAuth2 authorization server and OIDC provider, checked against the
RFC 6749 / 7636 / 7009 / 7662 MUST matrices and OIDC Core/Discovery conformance:

- **Authorization Code with PKCE (S256 only)** — the `plain` method is rejected;
  public clients prove possession with the verifier rather than a secret. The
  implicit grant is not offered.
- **Exact `redirect_uri` matching** — no wildcards, no prefix matching, no
  normalisation that could widen the match, closing the open-redirect class.
- **Single-use authorization codes** bound to client and redirect URI; **refresh
  rotation** that can only narrow scope, never widen it; `state` and `nonce`
  required and verified.
- **Introspection and revocation require client authentication** and are scoped
  to the caller's own tenant; unknown tokens return the uniform inactive response.
- **userinfo is scope-filtered**; JWKS publishes the active key plus a bounded
  rotation-overlap window.
- **Machine tokens and user tokens are not interchangeable.** Every machine
  credential — a service account's client secret, or an IoT device's client
  certificate — yields a token with a machine audience, while a human login
  yields a user audience; each is rejected where the other is expected, in both
  directions. Without that split, one device certificate would silently unlock
  every endpoint built for people. It is enforced at the request-extraction
  layer rather than left to individual handlers, so a new route inherits it by
  default, and the endpoints machines legitimately need — authorization checks —
  accept either principal while still recording which kind it was, so a device
  is never written into the audit trail as a person.

### Federation (SAML & OIDC)

Inbound federation is a deliberate delegation of trust to an external IdP, hardened
against the classic federation attacks:

- **SAML** verifies the signature over the *exact* element it then consumes (XML
  Signature Wrapping defence), rejects unsigned or multiply-signed responses, checks
  `Conditions`, `NotBefore`/`NotOnOrAfter`, `Audience`, `Destination` and
  `InResponseTo`, and refuses replayed assertion IDs.
- **OIDC federation** requires `state` and `nonce` from server-side flow state
  (never from the request body), binds the federation-config id into `state` to stop
  IdP mix-up, and validates the issuer.
- **Every outbound IdP fetch** — discovery, token exchange, JWKS, SAML metadata —
  goes through one **SSRF guard** that resolves DNS fresh, rejects private,
  loopback, link-local and ULA addresses, **pins the validated IP for the actual
  connection** (closing the DNS-rebind window), enforces HTTPS on every hop
  including redirects, and caps the response body.
- **Attribute-to-role mapping is an explicit, tenant-scoped allow-list** set by an
  AXIAM administrator; unmapped IdP attributes are discarded, so an IdP cannot
  self-assign privileged roles.

### PKI, certificates & device identity

- Certificates are **per-tenant, signed by the organization CA**, using RSA-4096 or
  Ed25519 from the platform CSPRNG. **Private keys are never stored server-side** —
  they are returned exactly once at issuance and delivered only over TLS 1.3.
- **CA signing keys are AES-256-GCM encrypted at rest** in a separate,
  access-controlled table, with the key held outside the datastore.
- **mTLS device authentication verifies the full chain** to the tenant/org CA after
  the fingerprint lookup, checks the issuing CA is active and within its validity
  window, and enforces the certificate's own validity period and live revocation
  status on every connection — a fingerprint match alone is never enough.
- **OpenPGP keys** sign the audit trail and encrypt GDPR data exports, so both are
  independently verifiable and confidential.

### Audit & accountability

- The audit log is **append-only** — no UPDATE or DELETE paths — and batches are
  **OpenPGP-signed**, making tampering or selective deletion detectable rather than
  merely difficult.
- Every state-changing and authorization action is recorded with actor, actor type,
  IP, outcome and timestamp; **both allow and deny decisions** are captured, so
  probing shows up in the trail. Records are structured fields, not formatted
  strings, so log-injection cannot forge a synthetic entry.

### Webhooks, email & messaging

- **Webhook deliveries are signed with a Stripe-style signed-timestamp HMAC** —
  HMAC-SHA256 over `<timestamp>.<body>`, so a stale or body-only forgery cannot be
  produced — and use the same resolve-and-pin SSRF guard as federation, so a webhook
  URL cannot be used to scan internal services.
- **AMQP messages** (async authz, audit ingestion, mail) carry an **HMAC-SHA256
  signature over the canonical body with a per-tenant HKDF-derived subkey**,
  verified in constant time before processing; a bad signature is rejected without
  requeue. The v2 message format binds a **per-message nonce and timestamp** so a
  captured, validly-signed message cannot be replayed. Signing is mandatory in
  production builds.
- **Email** is built through a typed API that rejects header injection, renders
  templates with user values as escaped data (never as template source), and
  encrypts provider credentials at rest.

### Transport, secrets & the SDKs

- **TLS 1.3 is the minimum** for all external communication; HSTS is emitted; the
  optional in-process TLS listener is TLS 1.3-only and fails fast rather than
  falling back to plaintext.
- **Secrets at rest** — MFA seeds, CA keys, federation and webhook and email
  secrets — are AES-256-GCM encrypted; passwords are Argon2id-hashed and client
  secrets are hashed under a **server-held key**, so a database disclosure alone does
  not yield an offline-crackable corpus. Secret-bearing types carry redacting
  `Debug`/`toString` implementations so a credential never reaches a log line. A
  **missing encryption key or pepper fails startup**; no code path substitutes an
  all-zero, constant or unkeyed fallback.
- **The eleven client SDKs conform to one cross-language contract.** Strict TLS
  verification is unconditional and TLS-bypass APIs are prohibited (CI greps for
  them); a plaintext `http://` base URL is refused at construction, with a
  loopback-only development exception matched on literal hostnames rather than
  resolved DNS; secrets are wrapped in redacting types; the browser flow keeps tokens
  in cookies with single-flight refresh; JWKS relying-party helpers pin the key set to
  the configured issuer's origin. The server is the single source of truth: a CI drift
  gate fails the build if an SDK's vendored OpenAPI/protobuf copy diverges.
- **Local token verification in the SDK route guards is strict by default, and the
  standard is written down.** A guard that only checked a signature would accept an
  expired token, and — because the JWKS is organization-wide — one minted for a
  different tenant. The SDK contract therefore defines a **normative minimum
  verification set** that every guard must enforce: algorithm pinned before key
  lookup, expiry required (not merely checked when present), not-before honoured,
  tenant asserted against the configured tenant and failing closed when there is
  nothing to compare against, issuer and audience checked when configured, and a
  named, bounded clock skew. Stating it once rather than leaving each language to
  infer it is deliberate — auditing eleven implementations against the written set
  found real gaps that per-SDK review had missed. Where a raw signature-only
  primitive still exists it is named to make accidental use hard.
- **A guard decides on the caller's credential and no other.** The rules above ask
  *"is this token good?"*; one more asks *"is this the token the decision is
  about?"* — because a guard can satisfy every claim rule and still be a bypass if a
  failed verification quietly routes into a second, successful one. So a guard must
  reject when the presented credential fails: never retry, never refresh, and never
  fall back to the application's own session, which would admit the caller under a
  service account's identity. Where an SDK offers a refresh-on-failure helper for its
  own outbound calls, that helper is a separate method that guards do not use.
- **Every SDK ships a webhook-signature verifier** (contract §13). Receivers no longer
  hand-roll the check: `verify_webhook(...)` implements one canonical spec across all
  eleven languages — HMAC-SHA256 over `<timestamp>.<raw_body>`, constant-time
  comparison on decoded signature bytes, a signature header with no `v1` value always
  failing rather than silently passing, multiple `v1` values accepted so secrets can be
  rotated without downtime, and a two-sided freshness window (default 300 seconds) that
  rejects future-dated timestamps as firmly as stale ones.

---

## Compliance posture

AXIAM keeps an internal compliance self-assessment mapping its controls to
recognised frameworks. This is a control-family self-assessment appropriate to a
beta-stage product — **not** a certified ISO 27001 ISMS audit or a formal Cyber
Resilience Act conformity assessment, and it says so plainly.

| Framework | Scope | Status |
|---|---|---|
| **OWASP ASVS v4.0.3 Level 2** | 103 controls across authentication, session, access control, cryptography, error handling, data protection, communications, malicious code, configuration | 94 Pass, 4 N/A, 5 Deferred — **no Deferred item is High or Critical** |
| **ISO/IEC 27001:2022 Annex A** | Access control, secure authentication, cryptography, logging, network security, secure development | Interpretive control-family mapping; code-level themes Pass |
| **EU Cyber Resilience Act (Annex I)** | Secure-by-design, no known exploitable vulnerabilities, confidentiality, data minimisation, access control, vulnerability handling, security updates | Themes Pass; SBOM deferred |
| **GDPR** | Data-subject export (Art. 15) and erasure (Art. 17), pseudonymisation, data minimisation | Export excludes secrets; erasure is durable and re-selectable on failure; audit actor identities are pseudonymised |
| **OAuth2 / OIDC** | RFC 6749 / 7636 / 7009 / 7662 + OIDC Core/Discovery MUST matrices | All tracked MUSTs pass; dedicated conformance suites |

Dependency and supply-chain security is gated in CI — `cargo audit`, `cargo deny`,
Trivy filesystem/config scans and `npm audit` at a high threshold, with Dependabot
across the workspace's ecosystems and each SDK repository, SHA-pinned GitHub
Actions, and signed release provenance.

---

## Shared responsibility

Some risks cannot be closed from inside the application. AXIAM records them openly
and tells you what to do about them. Treat the following as a deployment hardening
checklist — most of the threat model's open items live here.

**Platform & operations**

- Put a NetworkPolicy in front of the pods so nothing reaches the service around the
  ingress; keep the data tier off any public route.
- Give RabbitMQ **per-service credentials with vhost separation** — AXIAM verifies
  message signatures, but broker access control is yours.
- Supply secrets as **mounted Secret files, not `AXIAM_*` environment variables**,
  and enable etcd encryption at rest. A signing key in a ConfigMap or plain env var
  is effectively public within the namespace.
- **Encrypt backups and volume snapshots** with a key separate from the cluster,
  restrict snapshot IAM, and include backup media in the same access review as the
  live data tier — a snapshot carries the same data under weaker controls.
- Restrict `kubectl exec` and Secret-read RBAC and enable Kubernetes audit logging;
  **cluster-admin is equivalent to full AXIAM compromise** and is outside the
  application's audit trail.
- Add edge protection (WAF, connection limits, autoscaling) for volumetric floods,
  and a **liveness alert on scheduled-job completion** so a missed GDPR-erasure or
  certificate-expiry run is noticed.

**Integration & SDKs**

- **Call the webhook verifier.** Every SDK now ships `verify_webhook(...)`, so the
  hard part is done — but a helper you never invoke protects nothing, and an
  unverified receiver acts on any POST that reaches its URL. Verify before you act on
  a delivery, and deduplicate on the delivery id. The same applies to AMQP: the
  contract requires HMAC verification on every consumed message.
- **Configure the tenant on any SDK route guard.** The guards bind each token to your
  configured tenant, which means they need to know it — a guard given no tenant to
  compare against fails closed and rejects every token, by design.
- Prefer **mTLS or short-lived workload identity** over static client secrets;
  rotate secrets through the rotation endpoint and enable secret scanning on your
  own repositories.
- Install SDKs under their **canonical package names**, commit lockfiles, and keep
  dependency scanning on — eleven public registries are eleven chances for a
  typosquat or a hijacked release.

**Accepted, documented trade-offs**

- **Access tokens survive revocation for up to 15 minutes** — the price of stateless
  verification. Where immediate revocation matters, verify through the gRPC
  introspection path instead of locally.
- **The RBAC engine is additive with no deny-override** in the current release; model
  exclusions by granting lower in the resource hierarchy rather than granting high
  and excluding. Deny-override is on the roadmap.
- **Audit records cannot be erased** — append-only by design, which is in tension
  with GDPR Art. 17; erasure anonymises the subject instead. Set a retention period
  consistent with your lawful basis.

> **Caution — this is alpha software.** AXIAM is in active development and has not
> reached a stable release. It has not undergone an independent third-party
> penetration test or security certification. Do not use it to protect production
> systems until it reaches a stable, audited release. The controls described here
> are real and verified in the codebase, but a beta is a starting point for
> evaluation, not a guarantee.

---

## How security is maintained

- **Continuous review.** AXIAM has been through repeated full security-review rounds
  — an initial audit, targeted remediation waves, and independent re-verification
  passes — each re-checking every prior finding against current code with
  file-and-line evidence, not trusting a checklist. Findings carry stable IDs so a
  fix can be traced back to the review that raised it.
- **A fix is not trusted until someone else checks it.** Remediation and verification
  are deliberately separated: after a round of fixes lands, an independent pass
  re-derives every claim from source. That discipline earns its keep — the most recent
  pass confirmed the fixes but also caught one that was only half complete, and found
  that a *performance* change had quietly raised a brute-force ceiling. Both are
  recorded as new findings rather than absorbed silently.
- **The threat model is living.** It is revisited when a new API surface, protocol
  or integration lands, when a trust boundary moves, when a review raises something
  with no corresponding threat, or when a deferred item ships. The Threat Dragon
  JSON is the source of truth and this section is generated from it.
- **Gates, not vibes.** Every commit runs formatting, lints (`-D warnings`), the
  test suite against real SurrealDB and RabbitMQ, dependency and container scans, and
  cross-language SDK contract-drift checks. Security-relevant fixes land with a
  regression or negative test.

**Reporting a vulnerability.** If you find a security issue, please report it
privately to the maintainers rather than opening a public issue, and give us a
reasonable window to remediate before disclosure. *(Publish a security contact /
`SECURITY.md` policy link here when the section goes live.)*

---

*References — [STRIDE threat model](threat-model-stride.md) · [security analysis](security-analysis-2026-08-02.md) · [compliance audit](security-audit.md) · [`sdks/CONTRACT.md`](../sdks/CONTRACT.md) · [`docs/compliance/`](../docs/compliance/) · [OWASP Threat Dragon](https://www.threatdragon.com)*
