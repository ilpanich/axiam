# AXIAM — STRIDE Threat Model

Threat model for AXIAM (Access eXtended Identity and Authorization Management), produced with the **STRIDE** methodology and maintained in **[OWASP Threat Dragon](https://www.threatdragon.com)** format.

| | |
|---|---|
| **Model file** | [`ThreatDragonModels/Axiam/Axiam.json`](../ThreatDragonModels/Axiam/Axiam.json) |
| **Methodology** | STRIDE (per-element) |
| **Tool** | OWASP Threat Dragon, model schema v2 |
| **Diagrams** | 9 |
| **Threats identified** | 280 |
| **Mitigated / Open** | 258 / 13 |
| **Owner** | ilpanich |

---

## 1. Scope and purpose

This model covers the AXIAM server (this repository), the components it depends on at runtime — SurrealDB, RabbitMQ, HashiCorp Vault (the default secret provider in the production stacks), the Kubernetes platform, email providers — and the client-facing integration surface: the React admin UI and the eleven client SDKs that live in the `ilpanich/axiam-<lang>-sdk` repositories.

It is a **design-level** threat model. It reasons about the data flows and trust boundaries described in [`design-document.md`](design-document.md), and records the control that answers each threat where one exists in the codebase. It does not replace the code-level security reviews in this directory ([`security-audit.md`](security-audit.md), [`final-security-review.md`](final-security-review.md)) — it gives them a structure to hang from, and the two should be read together.

**In scope**

- The `axiam-server` binary and every crate it composes — including the OPAQUE (RFC 9807) engine and the shared `axiam-opaque` client core it ships to every SDK, and the SCIM 2.0 provisioning endpoint with its long-lived provisioning tokens
- REST (Actix-Web), gRPC (Tonic) and AMQP (Lapin) API surfaces — the AMQP transport is TLS-only (`amqps://` is the only accepted scheme)
- SurrealDB as the system of record, RabbitMQ as the async transport, and HashiCorp Vault as the secret provider the production stacks default to
- The React admin UI and the eleven client SDKs
- The documented Kubernetes deployment topology
- Federated identity providers and email providers as external trust dependencies

**Out of scope**

- The internal security of third-party IdPs and email providers beyond the trust AXIAM places in them
- Physical security of IoT devices (recorded as an accepted risk, not analysed)
- Kubernetes control-plane and cloud-provider security, except where the shipped manifests make a choice
- Per-SDK implementation conformance, which is verified in each SDK's own repository against `sdks/CONTRACT.md`

## 2. Method

Each element in each data-flow diagram is examined against the STRIDE categories that apply to its type. Threat Dragon enforces this per-element mapping, and so does the model:

| Element | S | T | R | I | D | E |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| External entity (actor) | ● | | ● | | | |
| Process | ● | ● | ● | ● | ● | ● |
| Data store | | ● | ● | ● | ● | |
| Data flow | | ● | | ● | ● | |

A threat is marked **Mitigated** only where a control exists in this repository or in the SDK contract and can be pointed at. Where the residual risk is accepted, deferred, or falls to whoever deploys AXIAM, the threat stays **Open** and says so — an honest open item is more useful than an optimistic closed one. Section 6 lists every open item in one place.

Identifiers such as `SEC-040`, `SECHRD-03`, `D-01c` and `X-1` refer to findings from the security reviews in this directory; the mitigation text carries them so a threat can be traced back to the review that raised it.

## 3. Working with the model

The Threat Dragon JSON is the source of truth. This document is generated from it, so edit the model — not the tables below.

**Open it**

1. Go to [threatdragon.com](https://www.threatdragon.com) (or run the desktop application, or `docker run -p 8080:3000 owasp/threat-dragon`).
2. Choose *Open an existing threat model from your local file system*.
3. Select `ThreatDragonModels/Axiam/Axiam.json`.

**Export diagrams for the website** — open a diagram and use *Export diagram as PNG/SVG*, or produce the full HTML/PDF report from the model page. The report includes every threat with its mitigation, which is the form most useful to reviewers and auditors.

**Validate after editing**

```sh
npx ajv validate --allow-union-types \
  -s threat-dragon-v2.schema.json \
  -d ThreatDragonModels/Axiam/Axiam.json
```

The schema lives at `td.vue/src/assets/schema/threat-dragon-v2.schema.json` in the [OWASP/threat-dragon](https://github.com/OWASP/threat-dragon) repository. Note that it marks `strokeDasharray` with OpenAPI's `nullable` keyword, which strict JSON Schema validators do not honour; a `null` there is correct and Threat Dragon's own reference models contain it too.

## 4. Decomposition and trust boundaries

Five trust boundaries recur across the diagrams. A flow that crosses one is where authentication, authorization, validation and transport protection have to be re-established — nothing may be assumed across a boundary.

| Boundary | Separates | What must hold on every crossing |
|---|---|---|
| **Public Internet ↔ AXIAM** | Browsers, SDK callers, IoT devices, external IdPs | TLS 1.3, authentication, rate limiting, CSRF on cookie-borne requests, input validation |
| **AXIAM ↔ data tier** | Application pods ↔ SurrealDB, RabbitMQ, Vault / Secrets | Private network, credentialed connections, TLS-only AMQP, parameterised queries, tenant scoping at the repository layer |
| **Tenant ↔ tenant** | Every tenant's data from every other tenant's | Tenant context derived from the verified session or JWT — never from request input — and enforced on every query and graph traversal; cross-tenant reach exists only as an explicit organization-scope claim (`SubjectScope`), a role assignment may additionally confine an organization-level principal to named tenants (`tenant_scope`), and the `X-Axiam-Tenant` header is verified to stay inside the caller's organization and the caller's reach |
| **AXIAM ↔ third parties** | Outbound to IdPs, email providers, webhook receivers | SSRF guard with resolve-and-pin, https enforcement, response size caps, HMAC signatures on webhook deliveries |
| **Server ↔ SDK / admin UI** | The server contract from its client implementations | `sdks/CONTRACT.md` clauses — TLS policy, secret redaction, CSRF, AMQP HMAC — enforced by CI drift and buf gates |

### Principal assets

| Asset | Where | Compromise means |
|---|---|---|
| JWT signing key (Ed25519) | Secret provider — Vault in production, Kubernetes Secrets otherwise | Any identity in any tenant can be forged |
| Organization CA private key | `ca_certificate` row (AES-256-GCM) or Vault — custody recorded per CA | Any user, service or device certificate can be minted |
| Tenant signing CA private key | Same per-CA custody; path-length-zero intermediate | One tenant's certificates can be minted; revocation is scoped to that tenant |
| Password hashes (Argon2id) | `user` | Offline cracking of every credential |
| OPAQUE setup key + per-tenant OPRF seeds | Secret provider; `opaque_server_setup`, AES-256-GCM encrypted | Stolen OPAQUE records become dictionary-attackable at KSF cost |
| MFA secrets | `mfa` records, AES-256-GCM encrypted | Second factor defeated indefinitely |
| Refresh tokens and sessions | `session`, hashed | Sustained impersonation |
| Client and webhook secrets | hashed / encrypted | Service-account impersonation; forged events |
| Authorization graph | `role`, `permission`, `resource` edges | Silent privilege grant across the estate |
| Audit log | `audit_log`, append-only, PGP-signed | Loss of accountability and non-repudiation |

## 5. Diagrams and threats

Each subsection corresponds to one diagram in the Threat Dragon model. Threat numbers match the model, so `T-42` here is threat 42 there.

### 5.1 System diagram

Level-0 context data-flow diagram: external actors, the three AXIAM API surfaces, the shared middleware pipeline, the core service layer and the private data tier. Trust boundaries separate the public Internet, the Kubernetes runtime and the data tier. 1.0.0-beta13 adds two findings from the OpenID Connect work that belong to the system rather than to any one protocol surface: the explicit column lists behind erasure and export (T-261) and the datastore's own write-conflict phrasing going unrecognised (T-262).

*31 threats — 3 critical, 15 high, 13 medium; 2 open.*

| # | Element | STRIDE | Threat | Severity | Status |
|---|---|:-:|---|---|---|
| T-1 | Admin / End user (browser, React UI) <br/>*Actor* | S | Session cookie theft leads to account takeover | High | Mitigated |
| T-2 | Admin / End user (browser, React UI) <br/>*Actor* | R | Administrator denies having made a privileged change | Medium | Mitigated |
| T-3 | Client application / service account (SDKs) <br/>*Actor* | S | Leaked client_secret impersonates a service account | High | Mitigated |
| T-4 | IoT device (mTLS client cert) <br/>*Actor* | S | Cloned device certificate | High | Mitigated |
| T-5 | External IdP (SAML / OIDC) <br/>*Actor* | S | Malicious or compromised IdP asserts arbitrary identities | High | Mitigated |
| T-6 | Email provider (SMTP / SendGrid / …) <br/>*Actor* | S | Provider compromise exposes reset and verification links | Medium | Mitigated |
| T-7 | Webhook receiver (tenant endpoint) <br/>*Actor* | S | Forged webhook delivery to a tenant endpoint | Medium | Mitigated |
| T-8 | Ingress / TLS 1.3 termination <br/>*Process* | T | TLS downgrade or termination-point interception | High | Mitigated |
| T-9 | Ingress / TLS 1.3 termination <br/>*Process* | D | Connection flood exhausts ingress capacity | Medium | Open |
| T-10 | REST API (Actix-Web) <br/>*Process* | D | Argon2id memory flood on unauthenticated login | High | Mitigated |
| T-11 | REST API (Actix-Web) <br/>*Process* | E | Missing tenant scoping exposes another tenant's data | Critical | Mitigated |
| T-12 | gRPC API (Tonic) <br/>*Process* | I | Cross-tenant token introspection | Medium | Mitigated |
| T-13 | AMQP consumer (Lapin) <br/>*Process* | S | Forged authorization request on the broker | High | Mitigated |
| T-14 | Security middleware (authn, CSRF, rate limit, CORS, audit) <br/>*Process* | D | Rate limits multiplied by replica count | Medium | Mitigated |
| T-15 | Security middleware (authn, CSRF, rate limit, CORS, audit) <br/>*Process* | S | X-Forwarded-For spoofing bypasses per-IP limits | Medium | Mitigated |
| T-16 | Core service layer (AuthN, AuthZ, User, PKI, Federation) <br/>*Process* | E | No deny-override in the RBAC cascade | Medium | Mitigated |
| T-17 | SurrealDB cluster (all tenant data) <br/>*Store* | I | Direct datastore access bypasses every application control | Critical | Mitigated |
| T-18 | SurrealDB cluster (all tenant data) <br/>*Store* | I | Backup or snapshot exfiltration | High | Open |
| T-19 | Audit log (append-only, PGP signed) <br/>*Store* | T | Audit record tampering or selective deletion | High | Mitigated |
| T-20 | RabbitMQ (authz, audit, mail, notification queues) <br/>*Store* | D | Queue flooding delays authorization decisions | Medium | Mitigated |
| T-21 | Secret store (Vault / Kubernetes Secrets) <br/>*Store* | I | Signing-key disclosure allows arbitrary token minting | Critical | Mitigated |
| T-22 | Admin UI + auth endpoints <br/>*Flow* | I | Credentials or tokens sent over plaintext HTTP | High | Mitigated |
| T-23 | SDK REST + gRPC traffic <br/>*Flow* | I | SDK transport downgraded or TLS verification disabled | High | Mitigated |
| T-24 | Domain reads and writes <br/>*Flow* | T | Query injection into SurrealQL | High | Mitigated |
| T-25 | Discovery, JWKS, token exchange <br/>*Flow* | I | SSRF via admin-supplied IdP metadata URL | High | Mitigated |
| T-26 | Event delivery <br/>*Flow* | I | Webhook registration used to probe internal services | Medium | Mitigated |
| T-181 | REST API (Actix-Web) <br/>*Process* | S | Leaked SCIM provisioning token replayed as the IdP | High | Mitigated |
| T-187 | REST API (Actix-Web) <br/>*Process* | I | Deleted user's tombstone retains personal data and discloses the account existed | Medium | Mitigated |
| T-200 | Security middleware (authn, CSRF, rate limit, CORS, audit) <br/>*Process* | S | CSRF exemption for machine callers forged by pairing a bearer header with a session cookie | Medium | Mitigated |
| T-261 | REST API (Actix-Web) <br/>*Process* | I | A personal-data column added to `user` survives erasure and never reaches the Art. 15 export, and a SCIM patch that erases it is read as a no-op | High | Mitigated |
| T-262 | SurrealDB cluster (all tenant data) <br/>*Store* | D | A contended write surfaces as a migration failure, and the single-use guard cannot recognise the engine's own conflict message | Medium | Mitigated |

<details>
<summary>Threat detail and mitigations</summary>

**T-1 — Session cookie theft leads to account takeover**  
`Admin / End user (browser, React UI)` (Actor) · Spoofing · High · Mitigated

An attacker who obtains the axiam_access / axiam_refresh cookie (XSS, malware, shared device) can impersonate the user for the lifetime of the token.

> Cookies are Secure + HttpOnly + SameSite; access tokens are EdDSA-signed and expire in 15 min; refresh tokens are opaque, server-stored and single-use with rotation, so a stolen refresh token is detectable on reuse. CSP headers are set by the security_headers middleware.

**T-2 — Administrator denies having made a privileged change**  
`Admin / End user (browser, React UI)` (Actor) · Repudiation · Medium · Mitigated

A tenant or org administrator disputes a role assignment, certificate revocation or settings change attributed to them.

> Every state-changing request is written to the append-only audit_log with actor id, actor type, IP, outcome and timestamp; audit batches are signed with the tenant OpenPGP key.

**T-3 — Leaked client_secret impersonates a service account**  
`Client application / service account (SDKs)` (Actor) · Spoofing · High · Mitigated

Service-account and OAuth2 client secrets embedded in SDK configuration, CI variables or container images let an attacker mint tokens with the service account's roles.

> Client secrets are stored HMAC-SHA256 hashed, never in plaintext; secrets are redacted from Debug output; rotation is supported. Deployments should prefer mTLS or short-lived workload identity over static secrets.

**T-4 — Cloned device certificate**  
`IoT device (mTLS client cert)` (Actor) · Spoofing · High · Mitigated

A private key extracted from a physical device lets an attacker clone that device's identity and act with its bound roles.

> SEC-024: mTLS auth verifies the full chain to the tenant/org CA after the fingerprint lookup and fails closed when no active CA exists. Revocation invalidates the device immediately. Devices should hold keys in a secure element where available.

**T-5 — Malicious or compromised IdP asserts arbitrary identities**  
`External IdP (SAML / OIDC)` (Actor) · Spoofing · High · Mitigated

A federated IdP — or an attacker who controls its metadata URL — can assert any subject and any attribute set, including attributes mapped onto privileged AXIAM roles.

> Assertions are signature-verified against pinned IdP keys; JWKS and discovery documents are fetched only through the SSRF-guarded resolve-and-pin helper; attribute-to-role mapping is explicit and tenant-scoped. Federation is a deliberate trust delegation — the tenant owner accepts the IdP as an authority.

**T-6 — Provider compromise exposes reset and verification links**  
`Email provider (SMTP / SendGrid / …)` (Actor) · Spoofing · Medium · Mitigated

Password-reset and email-verification tokens transit a third-party provider; a compromised provider account can read or replay them.

> Tokens are CSPRNG-generated, single-use and short-lived; reset confirms only over an authenticated POST; provider API keys are encrypted at rest and TLS is required on every provider hop.

**T-7 — Forged webhook delivery to a tenant endpoint**  
`Webhook receiver (tenant endpoint)` (Actor) · Spoofing · Medium · Mitigated

An attacker posts fabricated AXIAM events to a known tenant webhook URL to trigger downstream provisioning or de-provisioning.

> Every delivery carries an HMAC-SHA256 signature computed with the per-endpoint shared secret; receivers must verify it before acting.

**T-8 — TLS downgrade or termination-point interception**  
`Ingress / TLS 1.3 termination` (Process) · Tampering · High · Mitigated

An on-path attacker forces a weaker protocol version or cipher, or reaches the plaintext hop behind the terminator.

> TLS 1.3 is the configured minimum for all external communication; HSTS is emitted by the security-headers middleware; in-cluster hops run on the cluster's own network policy and, where deployed, a service mesh.

**T-9 — Connection flood exhausts ingress capacity**  
`Ingress / TLS 1.3 termination` (Process) · Denial of service · Medium · Open

Unauthenticated TLS handshake or slow-loris floods consume ingress worker capacity before any AXIAM control applies.

> Partly outside the application boundary: AXIAM enforces per-IP and per-user rate limits and Argon2 backpressure, but edge-level protection (WAF, connection limits, autoscaling) is a deployment responsibility and is not shipped with AXIAM.

**T-10 — Argon2id memory flood on unauthenticated login**  
`REST API (Actix-Web)` (Process) · Denial of service · High · Mitigated

Each Argon2id verification allocates a ~19 MiB arena; an unauthenticated login flood turns password hashing into a memory-exhaustion vector (~970 MiB RSS observed at ~50 concurrent hashes against a 1024 MiB cap).

> crypto_gate bounds concurrent Argon2id operations with a process-wide semaphore and fails fast with 503 backpressure once the acquire timeout elapses, instead of queueing unboundedly. Both credential-verifying surfaces pass through the same gate: the REST login path and gRPC ValidateCredentials (B1) — an ungated path in either protocol would reopen the flood through the other.

**T-11 — Missing tenant scoping exposes another tenant's data**  
`REST API (Actix-Web)` (Process) · Elevation of privilege · Critical · Mitigated

A handler that trusts a caller-supplied tenant_id, or a repository query that omits the tenant filter, breaks the isolation guarantee that is the core of the product.

> Tenant context is derived from the interceptor-verified session or JWT, never from request-body input; tenant filtering is enforced at the repository layer and cross-tenant graph edges are stripped on traversal.

**T-12 — Cross-tenant token introspection**  
`gRPC API (Tonic)` (Process) · Information disclosure · Medium · Mitigated

A service account in tenant A introspects a token issued to tenant B and learns its subject, scopes and validity.

> SEC-068: the caller's tenant is taken from the interceptor-verified JWT and introspection refuses any token belonging to a different tenant.

**T-13 — Forged authorization request on the broker**  
`AMQP consumer (Lapin)` (Process) · Spoofing · High · Mitigated

Anyone able to publish to axiam.authz.request can request decisions for arbitrary subjects, and anyone able to publish to axiam.audit.events can inject fabricated audit records.

> SEC-022 / SEC-055: messages carry an HMAC-SHA256 signature over the canonical JSON body, verified with constant-time comparison before the message is processed; a failed check is nacked without requeue and logged as a security event. SDK CONTRACT §8 makes this mandatory for every SDK that consumes AXIAM queues.

**T-14 — Rate limits multiplied by replica count**  
`Security middleware (authn, CSRF, rate limit, CORS, audit)` (Process) · Denial of service · Medium · Mitigated

Per-replica in-memory token buckets mean an HPA-scaled deployment enforces N times the intended rate, so brute-force and enumeration budgets scale with the cluster.

> SECHRD-03: a shared write-behind counter backed by the datastore pre-checks the limit across replicas, with the per-replica governor retained as a fail-open fallback and no synchronous datastore write on the request path.

**T-15 — X-Forwarded-For spoofing bypasses per-IP limits**  
`Security middleware (authn, CSRF, rate limit, CORS, audit)` (Process) · Spoofing · Medium · Mitigated

A caller that can set XFF freely attributes every request to a different source address and defeats per-IP rate limiting and lockout.

> SEC-070: only a configured number of rightmost XFF hops (trusted_hops) is trusted, shared by the REST and gRPC extractors; untrusted hops fall back to the socket peer address.

**T-16 — No deny-override in the RBAC cascade**  
`Core service layer (AuthN, AuthZ, User, PKI, Federation)` (Process) · Elevation of privilege · Medium · Mitigated

The authorization engine is additive-only (allow-wins, default deny). A role granted high in the resource hierarchy cannot be revoked on a single child resource — the only way to remove access to a subtree is to restructure the grant.

> SEC-040 — **CLOSED (B1).** The engine now supports explicit deny. A grant
> carries `effect: "allow" | "deny"`, and a deny **overrides every allow**, at
> any depth of the resource hierarchy and at equal specificity (deny-override,
> not most-specific-wins). Exclusions no longer have to be modelled by narrowing
> the grant. See `claude_dev/deny-override-design.md` for the precedence table,
> the scope-interaction rules, and the argument for deny-override over
> most-specific-wins — the property it buys is that adding a deny rule can never
> widen access and can never be undone by adding allows, which is asserted by an
> exhaustive property test.
>
> **Amended 2026-09-22 (T22.11, DF-021).** An assignment can now also be made
> **non-inheritable** — `inherit: false` on the `has_role` edge — so a role
> granted high in the hierarchy can be stopped at its node instead of cascading
> to every child ("here and no further"), for allows and denies alike.
> Precedence is unchanged: the flag decides which assignments are *applicable*
> at a resource, never how deny-override weighs them (§2.2 rows 9–11 of the
> design document). The flag's own hazards are T-285.

**T-17 — Direct datastore access bypasses every application control**  
`SurrealDB cluster (all tenant data)` (Store) · Information disclosure · Critical · Mitigated

SurrealDB holds Argon2id password hashes, encrypted MFA secrets, hashed client secrets and the entire authorization graph. Direct access bypasses tenant scoping, RBAC and audit entirely.

> The data tier sits on a private network with no ingress; credentials come from Kubernetes Secrets; connections are authenticated and namespaced. Secrets stored in the database are themselves hashed (passwords, client secrets) or AES-256-GCM encrypted (MFA secrets, CA keys, federation secrets).

**T-18 — Backup or snapshot exfiltration**  
`SurrealDB cluster (all tenant data)` (Store) · Information disclosure · High · Open

A database backup, volume snapshot or debug dump carries the same data as the live store but usually far weaker access control.

> Not addressed by AXIAM itself. Deployment guidance: encrypt backups at rest, restrict snapshot IAM, and treat backup media as in-scope for the same access review as the live cluster.

**T-19 — Audit record tampering or selective deletion**  
`Audit log (append-only, PGP signed)` (Store) · Tampering · High · Mitigated

An attacker with datastore access edits or removes the records describing their own activity, destroying the forensic trail.

> The audit_log table grants no UPDATE or DELETE at the SurrealDB permission level, and batches are signed with the tenant OpenPGP key so removal or edit is detectable. Ship audit records to an external WORM sink for defence in depth.

**T-20 — Queue flooding delays authorization decisions**  
`RabbitMQ (authz, audit, mail, notification queues)` (Store) · Denial of service · Medium · Mitigated

A producer that floods axiam.authz.request starves legitimate async decisions and backs up audit ingestion.

> Consumer prefetch is bounded by configuration and broker credentials are per-service so a single misbehaving producer can be revoked. Async authz is a deferred path; synchronous gRPC checks are unaffected.

**T-21 — Signing-key disclosure allows arbitrary token minting**  
`Secret store (Vault / Kubernetes Secrets)` (Store) · Information disclosure · Critical · Mitigated

The Ed25519 JWT signing key lets an attacker mint access tokens for any subject in any tenant, defeating authentication entirely.

> The signing key is fetched through the pluggable secret provider — HashiCorp Vault by default in the production stacks (`AXIAM__AUTH__SECRET_PROVIDER=vault`), Kubernetes Secrets otherwise — and never lives in the image or a ConfigMap; CA private keys are additionally AES-256-GCM encrypted at rest. Rotate signing keys on a schedule — JWKS publishes multiple key ids so rotation is non-breaking — and where Kubernetes Secrets are the source, enable envelope encryption for etcd.

**T-22 — Credentials or tokens sent over plaintext HTTP**  
`Admin UI + auth endpoints` (Flow) · Information disclosure · High · Mitigated

A downgraded or misconfigured deployment sends passwords, MFA codes and bearer tokens in the clear.

> TLS 1.3 minimum; HSTS emitted by the security-headers middleware; auth cookies carry the Secure attribute so they are never sent over plaintext.

**T-23 — SDK transport downgraded or TLS verification disabled**  
`SDK REST + gRPC traffic` (Flow) · Information disclosure · High · Mitigated

An SDK that accepts a plaintext base URL, or that offers an insecure() / skip-verify escape hatch, sends bearer tokens and credentials to an attacker-controlled or observable endpoint (finding X-2).

> SDK CONTRACT §6 makes strict TLS verification unconditional and absolutely prohibits any bypass API (no skip_tls_verification, insecure, allow_insecure, verify_peer(false)); the only escape hatch is with_custom_ca(pem) for development CAs. CI lint gates in each SDK repository grep for bypass patterns such as InsecureSkipVerify.

**T-24 — Query injection into SurrealQL**  
`Domain reads and writes` (Flow) · Tampering · High · Mitigated

String-built queries would let attacker-controlled identifiers or filters alter the statement and cross tenant boundaries.

> Parameterised queries only — SurrealDB bind parameters are used throughout axiam-db; no query is assembled by string concatenation of user input.

**T-25 — SSRF via admin-supplied IdP metadata URL**  
`Discovery, JWKS, token exchange` (Flow) · Information disclosure · High · Mitigated

A tenant admin who can set metadata_url or jwks_uri makes the server fetch internal addresses — cloud metadata endpoints, in-cluster services — and observe the response.

> SEC-069 / D-01: guarded_fetch resolves A and AAAA fresh, rejects loopback, private, link-local, ULA and unspecified addresses, pins the validated IP for the connect (closing the DNS-rebind TOCTOU window), enforces https on every hop including redirects, and caps the advertised body size. SEC-107 adds a deliberate, bounded bypass for same-network IdPs: `AXIAM__PKI__SSRF_ALLOWED_HOSTS` is default-empty, set only at the composition root, matches exact hosts (no wildcards, no CIDRs), applies to the first hop only with redirects always strict, and logs every use — and cloud metadata endpoints stay blocked even for an allowlisted host, with IPv4-mapped canonicalisation running before that check so the allowlist cannot re-open SEC-094.

**T-26 — Webhook registration used to probe internal services**  
`Event delivery` (Flow) · Information disclosure · Medium · Mitigated

A tenant admin registers a webhook pointing at an internal address and uses delivery success or timing as an internal port scanner.

> Webhook delivery uses the same guarded_fetch resolve-and-pin guard as federation: private and loopback destinations are rejected before connect.

**T-181 — Leaked SCIM provisioning token replayed as the IdP**  
`REST API (Actix-Web)` (Process) · Spoofing · High · Mitigated

SCIM provisioning tokens exist because Okta and Entra can present only one static bearer string, so the credential is deliberately long-lived — pasted once into the IdP and forgotten. Whoever obtains it can drive user provisioning and deprovisioning for the tenant for as long as it lives.

> Containment is the design (#330): a provisioning token is accepted on `/scim/v2/*` and nowhere else — not `/api/v1/*`, not `/oauth2/*`, not gRPC — and carries no permissions of its own: it resolves to an existing tenant user whose RBAC must still pass the same `require_scim_provision` check as a session would. It is stored SHA-256-hashed with the plaintext returned exactly once, carries an expiry, is revocable independently of every other credential, stamps `last_used_at` on use, and minting and revocation are audited. SCIM has its own rate-limit bucket (R5.2), and deprovisioning a user through SCIM revokes their live sessions and refresh tokens (SEC-098).

**T-187 — Deleted user's tombstone retains personal data and discloses the account existed**  
`REST API (Actix-Web)` (Process) · Information disclosure · Medium · Mitigated

Administrator deletion tombstoned the user row but kept username, email and metadata on it indefinitely — retention with the UI hidden, not erasure. Because the per-tenant uniqueness indexes are enforced by the database, the retained identifiers also blocked the person from ever registering again, and the duplicate-account refusal itself disclosed that the deleted account had existed.

> Fixed in 1.0.0-beta01: deletion overwrites username, email and metadata with values derived from the row's own id and erases what lives outside the row — WebAuthn credentials, federation identity links, password history — the same residue the GDPR Art. 17 purge clears, so an administrator's Delete and a data subject's erasure request do not leave different residue. The freed identifiers make a later registration a genuinely new account (pinned by a delete-then-recreate test). The row survives holding only its id, because append-only audit entries name their actor by id; only the Art. 17 pipeline additionally pseudonymises audit references and produces an erasure proof — a distinction docs/compliance/gdpr-compliance.md now states.

**T-200 — CSRF exemption for machine callers forged by pairing a bearer header with a session cookie**  
`Security middleware (authn, CSRF, rate limit, CORS, audit)` (Process) · Spoofing · Medium · Mitigated

The CSRF middleware required an axiam_csrf cookie matching the X-CSRF-Token header on every state-changing request, which a bearer-authenticated machine caller has no way to satisfy — POST /api/v1/authz/check under a client-credentials token answered 403 “CSRF validation failed”, so the machine-facing REST surface was unreachable by a machine (B-05). Exempting bearer requests naively would open the opposite hole: a cross-site page can attach a fabricated Authorization header while the browser attaches the victim’s session cookie — precisely the shape an attacker would craft to escape the exemption.

> Fixed in 1.0.0-beta05: is_bearer_only(authorization, has_session_cookie) is a pure function so the condition can be pinned by unit tests. A bearer token with no session cookie is exempt — CSRF is an attack on credentials the browser attaches by itself, and a cross-site page cannot set an Authorization header on a victim’s behalf. A bearer header alongside a session cookie is deliberately not exempt (the load-bearing case), and no bearer means no exemption whatever the cookies say. Scheme matching is case-insensitive and leading-whitespace tolerant, and the machine principal extractor accepts the axiam:m2m audience.

**T-261 — A personal-data column added to `user` survives erasure and never reaches the Art. 15 export, and a SCIM patch that erases it is read as a no-op**  
`REST API (Actix-Web)` (Process) · Information disclosure · High · Mitigated

Both erasure statements — the Art. 17 pipeline's `anonymize_user` and the administrator's tombstone behind `DELETE /api/v1/users/{id}` (T-187) — and the export job's `profile` section write **explicit column lists**. A column none of them names survives erasure and never appears in an export. Latent rather than live: the columns it would have stranded, `phone_number` and `address`, are added by the same release, and the plan assumed user-row fields were erased "for free"; an erased subject would have held a telephone number and a postal address indefinitely, with the account hidden from the UI — what the tombstone's own documentation calls retention with the UI hidden, not erasure. Beside it, `user_patch_is_noop` had never been taught the two columns, so a SCIM PATCH that set or *removed* only those answered `200` with the unchanged resource and wrote nothing — an erasure that silently does not happen.

> All three paths name the columns, and the tests erase a subject who has both and read the row back rather than inspecting the SQL, so a fourth erasure path cannot pass by sharing a statement. The no-op list is destructured from `UpdateUser`, so a field added to that struct fails to compile here instead of silently becoming unwritable, and each of its seven fields is asserted on its own rather than in one lump — a lump assertion still passes with a field missing, which is precisely how this was missed the first time. The three-way distinction is asserted too: `None` means the PATCH did not mention the attribute, `Some(None)` means write NULL — the erasure a data subject asked for — and confusing the two is an erasure that does not happen; `remove` and an empty array both erase, because RFC 7644 §3.5.2.3 spells "replace with nothing" that way, and `phoneNumbers` and `addresses` are removable unlike `emails`, deliberately, since a provisioning client sending `remove` is a subject asking for a number or an address to stop being held. **The three hand-maintained lists are gone (R-1, 2026-09-12).** `axiam_core::personal_data::USER_COLUMNS` is one declaration with a row per `user` column, recording for each whether erasure clears it, which key the Art. 15 `profile` section shows it under, and — where either answer is “neither” — why; the two questions are separate fields because a single “is personal data” flag gets `password_hash` (erased, never exported — D-10) and `created_at` (exported, never erased) both wrong. Both erasure statements render their shared `SET` fragment from it, so a declared personal-data column is erased by both paths by construction; each keeps its own path-specific clauses, and the asymmetries between them (`email_verified_at` and `totp_last_used_step` on the tombstone, `deletion_pending` and `scheduled_purge_at` on the Art. 17 path) are recorded on the columns they belong to rather than harmonised, because harmonising them would be a behaviour change and this is a gate. Three checks close the loop: `user_schema_matches_the_declared_inventory` runs `INFO FOR TABLE user` against a live datastore after migrations and compares the field set with the inventory **in both directions** — a column added to the schema and classified nowhere fails naming itself, and so does a classification for a column that no longer exists; `the_profile_section_shows_exactly_the_declared_export_keys` does the same for the export literal, which stays hand-written because two of its entries are not column reads (`id`, and the derived `phone_number_verified`); and `every_unerased_or_unexported_column_says_why` keeps “nobody classified this” and “classified as neither” different states. The erase-then-read-back tests are untouched on purpose — reading the row back is the one assertion a fourth path sharing a bad statement cannot satisfy, and rewriting them against the new machinery would throw exactly that away. `docs/compliance/gdpr-compliance.md` §1 and §2 now describe the gate rather than warning the reader to remember.

**T-262 — A contended write surfaces as a migration failure, and the single-use guard cannot recognise the engine's own conflict message**  
`SurrealDB cluster (all tenant data)` (Store) · Denial of service · Medium · Mitigated

The first run of the `scim_provisioning` benchmark cell failed 20 of 907 operations, every one a concurrent `PATCH /scim/v2/Users/{id}` that lost a SurrealDB optimistic-concurrency race and reached the client as `500` carrying the engine's own words — "Transaction write conflict. This transaction can be retried". Nothing retried it: the `retry_on_write_conflict` helper the marker documentation linked to had never been written, so the one method that had surfaced the bug got a hand-rolled loop and every other contended write got nothing, and an IdP driving Okta- or Entra-shaped provisioning reads those as failed syncs and re-sends the whole record. Worse for T-163 and T-164: `is_transaction_conflict` — the single-use consume guard on `device_grant`, `permission_ticket`, `pushed_auth_request` and `oauth2_auth_code` — matched only the two pre-v3 phrasings, so on the deployed engine its "someone else got there first" branch could not fire and a correctly refused replay surfaced as a `500` rather than as "no row consumed". Fail-closed, so a robustness defect and not a hole: no token is minted either way.

> 2d371ad. `retry_on_write_conflict` now exists; `update` — which every administrative and SCIM write goes through — and `increment_failed_logins` use it, and replay is safe because a conflicted transaction commits *nothing*, which is also why the non-idempotent `failed_login_attempts += 1` can be retried at all. `classify_write_error` gains a conflict branch feeding `DbError::Conflict`, ordered after the UNIQUE check so a constraint violation — a statement about the request, which retrying only reproduces — still wins, and a contended write is no longer reported as a schema-migration failure that sends operators hunting a broken migration; the HTTP status stayed `5xx` pending a separate decision, which was taken on 2026-09-12 (R-4, decision A): a contended write now answers **`503 Service Unavailable` with `Retry-After: 1`** over REST and `UNAVAILABLE` over gRPC, through one new payload-free `AxiamError::WriteContention` and one mapping. `503` because the answer is a statement about the *server* — come back in a moment — which is what an IdP driving SCIM provisioning (Okta, Entra) treats as transient and retries; `409` in SCIM means "your request conflicts with the resource's state" (RFC 7644 §3.12), a statement about the request that changing the request is the response to, and `500` tells a client to stop when the correct advice is the opposite. The variant carries no payload, so the engine's own words stay on `DbError::Conflict` for the log and can never reach a body; the `Retry-After: 1` is a convention rather than a measurement, and CONTRACT §16.1 makes every SDK honour it as a floor so a client's own backoff still governs the wait. The UNIQUE-before-conflict ordering is what keeps a constraint violation on `409`, and it is pinned by its own I4 twin. No SDK behaviour needed to change — §16.3 already retries `5xx` on an eligible operation — and each SDK gains one test pinning that. Both legacy literals now live in `WRITE_CONFLICT_MARKERS` beside the v3 phrasing and the helper delegates, so the two sets can never again disagree about what a conflict looks like — the drift D-09 and `scripts/check-conflict-markers.py` exist to prevent, and which survived because these were never one set. Seven tests, one pinning the verbatim message captured from the failing run. **Corrected 2026-09-13 (f7d5ab8).** The sentence above claimed `503` *over REST*, and for a day it was true of every REST surface but the one the defect was found on: `axiam-scim`'s own error type maps `AxiamError` itself, its 5xx branch redacted every body to "An internal error occurred", and `WriteContention` fell through its catch-all as `500` — the exact answer an IdP reads as a failed sync. It now maps to `ScimError::retry_later`: `503`, `Retry-After: 1`, no `scimType` (RFC 7644 §3.12 defines none for a 5xx), the header and the body's exemption from redaction set from one field so they cannot drift apart, and the echoed `detail` a fixed, payload-free sentence — the engine's own words stay on `DbError::Conflict`, in the log, and a control test asserts that an ordinary `500` still redacts and advertises no retry. Four handler-level tests over the wire, one row on the mapping table. A control wired on two of three surfaces had been recorded here as whole; it is recorded now as it was.

</details>

### 5.2 Authentication & session management

Password and OPAQUE (RFC 9807) login, MFA (TOTP and WebAuthn, including usernameless passkey sign-in), lockout and rate limiting, JWT and refresh-token issuance, password reset and email verification, and the credential stores behind them. Since 1.0.0-beta09 user verification on a WebAuthn ceremony is a tightening-only security setting rather than a library constant (T-229, T-230); 1.0.0-beta13 adds the credential-in-log class CodeQL raised three times on the browser login hop (T-260). 1.0.0-beta14 closes the diagram's last open item, T-39: the optional revocation feed the server began publishing on 2026-09-12 gained a poller in all eleven SDKs the next day, so a revoked session can be refused within one poll interval rather than one token lifetime.

*35 threats — 3 critical, 16 high, 14 medium, 2 low; 0 open.*

| # | Element | STRIDE | Threat | Severity | Status |
|---|---|:-:|---|---|---|
| T-27 | End user (browser or SDK) <br/>*Actor* | S | Credential stuffing with breached password lists | High | Mitigated |
| T-28 | End user (browser or SDK) <br/>*Actor* | S | Phishing harvests password and TOTP code | High | Mitigated |
| T-29 | Email provider <br/>*Actor* | S | Reset link intercepted in transit or at rest in a mailbox | Medium | Mitigated |
| T-30 | Login endpoints /auth/login + /auth/opaque/* <br/>*Process* | I | Username enumeration via differential responses | Medium | Mitigated |
| T-31 | Login endpoints /auth/login + /auth/opaque/* <br/>*Process* | E | Unmetered credential-check path outside the lockout counter | High | Mitigated |
| T-32 | MFA verification TOTP / WebAuthn <br/>*Process* | E | MFA step skipped by replaying the challenge token | Critical | Mitigated |
| T-33 | MFA verification TOTP / WebAuthn <br/>*Process* | S | TOTP code replay inside its validity window | Medium | Mitigated |
| T-34 | MFA verification TOTP / WebAuthn <br/>*Process* | E | Admin MFA reset abused as a takeover path | High | Mitigated |
| T-35 | Lockout & rate limiting <br/>*Process* | D | Lockout weaponised to deny service to a known user | Medium | Mitigated |
| T-36 | Lockout & rate limiting <br/>*Process* | T | Failed-attempt counter race under concurrency | Medium | Mitigated |
| T-37 | Token service EdDSA JWT + refresh rotation <br/>*Process* | S | Refresh-token theft and reuse | High | Mitigated |
| T-38 | Token service EdDSA JWT + refresh rotation <br/>*Process* | S | Algorithm confusion or unsigned-token acceptance | Critical | Mitigated |
| T-39 | Token service EdDSA JWT + refresh rotation <br/>*Process* | E | Access token still valid after entitlement revocation | Medium | Mitigated |
| T-40 | Password reset & email verification <br/>*Process* | S | Reset token guessing | High | Mitigated |
| T-41 | Password reset & email verification <br/>*Process* | D | Verification email resend used for mail flooding | Low | Mitigated |
| T-42 | Password policy + HIBP check <br/>*Process* | I | Password exposed to the breach-check service | Low | Mitigated |
| T-43 | user credentials (Argon2id hashes, OPAQUE records) <br/>*Store* | I | Offline cracking of exfiltrated password hashes | High | Mitigated |
| T-44 | session / refresh token store <br/>*Store* | I | Stored session tokens usable directly from the datastore | High | Mitigated |
| T-45 | MFA secrets (AES-256-GCM) <br/>*Store* | I | TOTP seed disclosure allows permanent code generation | High | Mitigated |
| T-46 | rate-limit counters (shared, write-behind) <br/>*Store* | D | Counter store unavailability disables the shared limit | Medium | Mitigated |
| T-47 | JWT signing keys (Ed25519) <br/>*Store* | I | Signing-key compromise forges any identity | Critical | Mitigated |
| T-48 | access + refresh cookies <br/>*Flow* | I | Tokens leaked through URLs, logs or Referer headers | Medium | Mitigated |
| T-176 | Login endpoints /auth/login + /auth/opaque/* <br/>*Process* | I | Account existence probed through the OPAQUE login flow | Medium | Mitigated |
| T-177 | Login endpoints /auth/login + /auth/opaque/* <br/>*Process* | D | Unauthenticated OPAQUE exchanges consume server state and OPRF budget | Medium | Mitigated |
| T-178 | Lockout & rate limiting <br/>*Process* | E | OPAQUE login path sits outside the lockout counter | High | Mitigated |
| T-179 | user credentials (Argon2id hashes, OPAQUE records) <br/>*Store* | I | Stolen OPAQUE records opened offline with the tenant OPRF seed | High | Mitigated |
| T-182 | MFA verification TOTP / WebAuthn <br/>*Process* | E | Usernameless passkey sign-in skips the gates of the ordinary login path | High | Mitigated |
| T-188 | Lockout & rate limiting <br/>*Process* | S | Brute force metered against the deployment default, not the configured threshold | Medium | Mitigated |
| T-189 | access + refresh cookies <br/>*Flow* | T | Logout's removal cookies were weaker than the cookies they cleared | Medium | Mitigated |
| T-201 | MFA verification TOTP / WebAuthn <br/>*Process* | E | Enrolling a passkey never turns the second-factor requirement on | High | Mitigated |
| T-229 | MFA verification TOTP / WebAuthn <br/>*Process* | S | A possession-only security key is accepted where possession alone must not be a complete login | High | Mitigated |
| T-230 | MFA verification TOTP / WebAuthn <br/>*Process* | T | A relaxed user-verification policy silently weakens credentials enrolled under a stricter one | Medium | Mitigated |
| T-260 | Login endpoints /auth/login + /auth/opaque/* <br/>*Process* | I | A bearer credential reaches stderr or the CI log through a derived `Debug` or a failing test's panic message | Medium | Mitigated |
| T-267 | MFA verification TOTP / WebAuthn <br/>*Process* | E | A user lowers their own account below the tenant's MFA floor through self-service reset | High | Mitigated |
| T-269 | MFA verification TOTP / WebAuthn <br/>*Process* | E | A setup token enrols a passkey on an account that already has a factor, or one the tenant's authenticator policy forbids | High | Mitigated |

<details>
<summary>Threat detail and mitigations</summary>

**T-27 — Credential stuffing with breached password lists**  
`End user (browser or SDK)` (Actor) · Spoofing · High · Mitigated

Automated login attempts using credentials leaked from unrelated services succeed against users who reuse passwords.

> Per-IP and per-user rate limiting, exponential-backoff lockout after N failures, optional HIBP k-anonymity breach check on password set, and org/tenant-enforceable MFA.

**T-28 — Phishing harvests password and TOTP code**  
`End user (browser or SDK)` (Actor) · Spoofing · High · Mitigated

A proxy phishing page relays the user's password and live TOTP code to the real endpoint in real time — TOTP does not bind to the origin.

> WebAuthn/FIDO2 passkeys and hardware keys are supported and are origin-bound, so they resist real-time proxy phishing. Tenants requiring phishing resistance should mandate WebAuthn rather than TOTP.

**T-29 — Reset link intercepted in transit or at rest in a mailbox**  
`Email provider` (Actor) · Spoofing · Medium · Mitigated

Password-reset links are bearer credentials; a compromised mailbox or provider grants account takeover.

> Reset tokens are CSPRNG-generated (never UUIDv7 — see the design-document note on id generation), single-use and expire quickly; consuming a reset invalidates existing sessions.

**T-30 — Username enumeration via differential responses**  
`Login endpoints /auth/login + /auth/opaque/*` (Process) · Information disclosure · Medium · Mitigated

Different status codes, error bodies or response times for existing versus non-existent accounts let an attacker enumerate valid usernames and email addresses.

> Login returns a uniform failure for unknown-user and bad-password alike, and password verification runs on a dummy hash when the user does not exist so timing does not distinguish the cases.

**T-31 — Unmetered credential-check path outside the lockout counter**  
`Login endpoints /auth/login + /auth/opaque/*` (Process) · Elevation of privilege · High · Mitigated

If any code path verifies a password without incrementing the failed-attempt counter, brute force is unbounded through that path even though the main login endpoint is protected.

> SEC-026b / D-06: the REST login path and the gRPC UserService::validate_credentials path both call the single shared lockout helper, which is the sole source of truth for failed-attempt accrual.

**T-32 — MFA step skipped by replaying the challenge token**  
`MFA verification TOTP / WebAuthn` (Process) · Elevation of privilege · Critical · Mitigated

If the intermediate MFA challenge token is accepted as a full session, or can be exchanged more than once, the second factor is bypassed.

> The challenge token is a distinct, short-lived credential that only authorises the MFA verification call and carries no API authority. **Corrected and extended 2026-09-13 (M-5, not taken).** "Consumed on use" was the wrong word for what the code does and is worth stating precisely, because the imprecision is what a reader would rely on. What is consumed is the **TOTP step**: `verify_mfa` records `totp_last_used_step` under a compare-and-swap and refuses a code from a step already spent, so a captured challenge token cannot be replayed *with the same code*. The token itself carries no `jti` and nothing records that it was presented, so within its window it could be re-presented with a fresh code — which requires the authenticator, and therefore adds nothing an attacker holding the authenticator does not already have. The property T-32 is about holds; the mechanism is a step store, not a token store.
>
> **R-E, recorded as a known residual rather than closed.** The *setup* token (`purpose: "mfa_setup"`) is stateless in the same way and has no second factor behind it, because there is not one yet. Within its 300-second window a captured token lets a second party call `setup/enroll` — which replaces the pending secret — and then `confirm`, completing the login as the user; the WebAuthn twins added by M-3 have the same shape. The window is short, the token travels only under TLS and is delivered in a `403` body to the caller who authenticated, and after the legitimate completion the token is inert (`enroll` refuses a configured account, `confirm` needs the stored secret, and `setup/register/start` refuses an account with a factor). Severity is therefore low.
>
> M-5 would have added a `jti` and consumed it on the call that *chooses* the factor. It was assessed and **not taken**: there is no existing consumption store to reuse — T-32's is a step store, not a token store — so it needs a repository trait method, a SurrealDB implementation, a fifth repository on `AuthService` (already generic over four), and the enrol→confirm binding on both the TOTP and the WebAuthn pairs with their tests. That is more than the day the plan budgeted for it, for a low-severity window, and spending it here would have come out of C-3 or the SDK wave. It stays open as a follow-up, and the admin UI's comment describing the token as single-use has been corrected to say what is actually true.

**T-33 — TOTP code replay inside its validity window**  
`MFA verification TOTP / WebAuthn` (Process) · Spoofing · Medium · Mitigated

A code observed by a proxy or shoulder-surfer stays valid for the remainder of its 30-second step plus drift tolerance.

> Verified TOTP codes are recorded and refused on reuse within the acceptance window; the drift window is kept to the minimum RFC 6238 recommends.

**T-34 — Admin MFA reset abused as a takeover path**  
`MFA verification TOTP / WebAuthn` (Process) · Elevation of privilege · High · Mitigated

MFA enrolment reset must exist for lost devices, but an attacker who reaches an admin account can use it to strip the second factor from any user.

> Only org/tenant admins can reset MFA state; the reset is audited and raises an admin notification. Enrolment must be redone on next login before any resource is reachable. **Amended 2026-09-13 (M-1):** the reset now evicts **every** factor — the WebAuthn credentials as well as the TOTP secret — in the same call that clears `mfa_enabled` and revokes the sessions (`MfaMethodService::reset_mfa`, which is where it moved to so that it could). Until then it cleared the challenge and not the factor: the credential rows survived, the forced TOTP setup at the next login turned `mfa_enabled` back on, and `available_method_types` offered `webauthn` again off a count that had never reached zero — so an authenticator an administrator reset the account *because of* became a live second factor once more, with nobody having re-registered it. Covered by `reset_mfa_then_totp_setup_does_not_resurrect_the_old_passkey`.

**T-267 — A user lowers their own account below the tenant's MFA floor through self-service reset**  
`MFA verification TOTP / WebAuthn` (Process) · Elevation of privilege · High · Mitigated

`POST /api/v1/users/{id}/reset-mfa` is self-service as well as administrative: a signed-in user could reset their own MFA with no fresh authentication, no password and no policy check. Under a tenant that enforces MFA this was the one path by which a user took their own account below the floor their administrator set — sessions are revoked, but the next password login hands out a setup token and whoever holds the password enrols a factor of their choosing. The per-method delete already refused to remove the last factor (`MfaCannotRemoveLastMethod`); the reset, which removes all of them at once, did not.

> **M-2 (2026-09-13).** The self-service branch reads the caller's **own** tenant's effective settings — the tenant they live in, never the one they are acting on, the same rule `start_registration` applies for the same reason — and refuses with `403` and the error code `mfa_enforced` where `MfaPolicy::mfa_enforced` is true. Its own code rather than `authorization_denied`, because the caller holds every permission the action needs and only an administrator can act against the policy; the message names the administrator, and the admin UI renders it verbatim. The `users:admin` branch is unaffected — unlocking a user who lost their only factor is what the endpoint exists for, and an enforcing tenant is where it matters most. Where the tenant does not enforce MFA the self-service reset stays allowed: such a user was free to run at one factor anyway, so refusing them protects nothing (D-1). The settings read is propagated rather than defaulted to not-enforced, so a datastore failure is not the way the floor is escaped. Tests: `self_reset_is_refused_under_an_enforcing_tenant` (403, the code, and the factor still listed afterwards), `self_reset_still_works_where_mfa_is_optional`, `admin_reset_ignores_the_enforcement_flag`.
>
> **Residual, recorded rather than absorbed:** this refuses the reset, it does not require a *fresh* authentication for the self-service MFA changes that remain allowed (the per-method delete, and the reset itself under a non-enforcing tenant). That is D-1's rejected alternative and it is a separate piece of work — OPAQUE tenants have no password AXIAM can re-verify, and a recency requirement is the `max_age` machinery. It is listed as a follow-up in the plan's §8, not as an open entry here, because the property this threat is about — the tenant's floor cannot be lowered by the user it binds — now holds.

**T-269 — A setup token enrols a passkey on an account that already has a factor, or one the tenant's authenticator policy forbids**  
`MFA verification TOTP / WebAuthn` (Process) · Elevation of privilege · High · Mitigated

Forced first-login enrolment offered **TOTP only**, so a tenant whose authenticator policy is built around security keys still had to hand every new user a TOTP app for their first login — the gap roadmap T14.1 and design §8c.1 both describe as "choose TOTP, passkey, or hardware key". Opening the WebAuthn registration ceremony to a setup token creates two ways to get it wrong. The token could add a factor to an account that already has one, so a captured token becomes a way to register an attacker's own authenticator onto an account whose owner has just finished enrolling. And the session-less ceremony could skip the attestation and user-verification policies the profile-page ceremony applies — the one path that runs before the user has a session would be the one path the policy does not reach.

> **M-3 (2026-09-13).** `POST /auth/webauthn/setup/register/start` and `/finish` both decode the token with the same purpose-checked decoder the TOTP twins use: a `mfa_challenge`-purpose token, an expired one, and a session bearer are all `401`. Both then ask whether the account already has **any** factor and refuse with `400` — the same answer `setup/enroll` gives, because it is the same rule. The question is asked of `MfaMethodService`, not `AuthService`: it spans the TOTP secret *and* the WebAuthn credential rows, and a check that read only the TOTP half would let a captured token add a second passkey.
>
> Nothing about *what may register* differs from the profile-page ceremony. The attestation policy and the user-verification policy are read from the token's `tenant_id` — which for a setup token is the principal tenant, there being no session and so no selected tenant to confuse it with — and handed to the same `start_registration_for_policy`; `finish` runs the same `enforce_mds_freshness` and `finish_registration_for_policy`. T-229/T-230 hold here unchanged, and by construction rather than by a second implementation agreeing.
>
> The completion shares **one** session-issuance tail with the TOTP path, `complete_setup_token_login`, rather than a second copy: `basic-op-gap-plan.md` §4 lists every path that funnels through `create_session_and_tokens`, and that list is what makes "the OP session cookie is minted on every browser login" checkable. The evidence recorded matches what the WebAuthn *authentication* path records for the same credential kind — `pwd` for the password that earned the token, `hwk` or `swk` for the credential, `mfa` for the two distinct factors, and `user` **only** under a `Required` user-verification policy, the one setting that rejects a ceremony whose `UV` bit is clear. Under the default `Preferred` a PIN-less security key enrols perfectly well and proves presence only, and claiming verification for it would overstate the session to a relying party asking for it; `finish_authentication` declines it for exactly this reason. The session lands in `urn:axiam:acr:mfa` either way, through `mfa`, which `acr_for` accepts alone.
>
> One deliberate asymmetry with the profile-page `finish`: there, a failure to mark MFA required is logged and swallowed, because the credential exists and the page's own refresh corrects it. Here it **fails the request**. There is no profile page to correct it from — the user is mid-login — and handing them a session while the account still reads "no second factor" would send them through forced enrolment again at the next sign-in, with a credential already registered that `setup/register/start` would then refuse as a second factor.
>
> Both routes are CSRF-exempt and public, on the same grounds as `/mfa/setup/enroll` and `/setup/confirm` and for the opposite reason the profile-page registration pair is neither: their caller has no session and no `axiam_csrf` cookie to echo, and the only credential the endpoints accept travels in the request body. A site that could forge one of these would already have to hold the token, and a caller holding the token needs no forgery.
>
> **Residual, stated because it is a gap in the evidence and not in the control:** the ceremony cannot be completed in-process — it needs a real authenticator, which is why every pre-existing WebAuthn handler test stops at `finish` — so the AMR and ACR claims above are pinned by unit tests on the evidence function together with `acr_for`, and the refusals by HTTP tests, rather than by an end-to-end sign-in. The e2e suite mocks the ceremony, as it did before.

**T-35 — Lockout weaponised to deny service to a known user**  
`Lockout & rate limiting` (Process) · Denial of service · Medium · Mitigated

An attacker who knows a username deliberately fails logins to keep the victim locked out.

> Lockout uses exponential backoff rather than a permanent lock, and a successful password reset clears the counter, giving the legitimate user a self-service path back in.

**T-36 — Failed-attempt counter race under concurrency**  
`Lockout & rate limiting` (Process) · Tampering · Medium · Mitigated

Read-then-write increments lose updates under parallel attempts, letting an attacker exceed the configured threshold.

> SEC-032: the increment is a single atomic SurrealQL UPDATE, removing the TOCTOU window.

**T-37 — Refresh-token theft and reuse**  
`Token service EdDSA JWT + refresh rotation` (Process) · Spoofing · High · Mitigated

A stolen refresh token grants indefinite re-authentication if it can be redeemed repeatedly.

> Refresh tokens are opaque, server-stored and single-use with rotation; redeeming a token that has already been rotated is detectable and invalidates the family. **Amended at 1.0.0-beta13 and re-amended by the T-254 decision (2026-09-12):** rotation *supersedes* rather than revokes for a client registered `profile: fapi2` only — there the previous token stays redeemable for a 60-second grace (FAPI 2.0 §5.3.2.1-9) before its brought-forward expiry retires it, and every token on that profile is sender-constrained, so redeeming one inside the window needs the client's private key as well. For every other client the predecessor is revoked at rotation and a second presentation is refused, which is what this entry has always recorded. "Detectable" now holds on both lanes: rotation stamps `rotated_at`, so a presentation after rotation is recorded on the session and audited as `oauth2.refresh_token_replayed` whether it was accepted under the grace or refused (T-254).

**T-38 — Algorithm confusion or unsigned-token acceptance**  
`Token service EdDSA JWT + refresh rotation` (Process) · Spoofing · Critical · Mitigated

A verifier that honours the token's own alg header can be tricked into accepting alg=none or an HMAC token signed with the public key.

> The verifier pins EdDSA (Ed25519) and rejects any other algorithm; the expected algorithm is never read from the token header.

**T-39 — Access token still valid after entitlement revocation**  
`Token service EdDSA JWT + refresh rotation` (Process) · Elevation of privilege · Medium · Mitigated

Access tokens are self-contained and valid for up to 15 minutes, so a role removal or account disable does not take effect on already-issued tokens until they expire.

> Accepted trade-off for stateless verification. The 15-minute lifetime bounds the window; sessions are invalidated on password change; deployments needing immediate revocation can use the gRPC introspection path rather than local JWT verification. **Narrowed server-side on 2026-09-12 (R-6, decision C) and Mitigated on 2026-09-13, when the SDK half landed in all eleven repositories.** `GET /oauth2/revocations` — off by default (`AXIAM__AUTH__REVOCATION_FEED_ENABLED`), and with it off the route is not mounted, no row is written and the deployment is byte-identical to one built before it existed — publishes the base64url SHA-256 of each session id revoked within the last access-token lifetime. Five properties make it safe to serve unauthenticated: entries are **hashes, never identifiers** (a `sid` is a session id and not a subject, so the document discloses neither who was revoked nor how many users are behind it; the argument is non-enumerability of a UUIDv4 preimage space, not that a hash is magic); it is **bounded** by the revocation rate over one token lifetime rather than by history, filtered on read as well as swept so a late sweep makes the table large and never the document untruthful; it is cacheable with an `ETag` over the entry list only; a guard **never fails closed on it**, which is what stops a network blip becoming an outage; and the token format is unchanged. Three deliberate revocation paths publish — logout, a password or MFA reset, and "sign out everywhere else", which does not publish the session it keeps — while the two single-use redemption paths deliberately do not, because a handoff being exchanged is not a session being withdrawn and publishing it would reject a caller whose grant is proceeding normally. Contract 1.44 §10.4 makes polling a **SHOULD** for a guard and scopes §10.2's MUST NOT to per-request polling, which is what it always said. Schema v62; conformance rows 165–169. **Closed on 2026-09-13, by the SDK half.** The entry stayed Open for a day on purpose — a feed nobody polls narrows nothing, the same shape of gap T-266 records for `mtls_endpoint_aliases` — and it flips now because every one of the eleven SDKs implements contract §10.4 (PRs rust #104, typescript #103, python #80, java #92, kotlin #62, csharp #87, php #67, go #77, swift #60, c #59, cplusplus #60, each merged and released at that SDK's 1.0.0-beta14), and §10.4.1 records the attachment point per SDK with no row that `declines`. Each poller was checked against the four rules that make the feature safe rather than merely present: default off, never on the request path, never fail closed (an unreachable feed, a non-`200`, an unparseable body or an unknown `alg` behaves as no feed at all — and specifically not as an empty list), and reject-only. The residual, stated plainly: the window is one poll interval (30–60 s recommended, 15 s floor) rather than zero, and it is opt-in on **both** sides — a deployment that leaves the feed off, or an integration that attaches no poller, keeps the fifteen-minute window and the introspection answer. The trade is narrowed, not removed, which is why the register's accepted-trade-off bullet keeps it.

**T-40 — Reset token guessing**  
`Password reset & email verification` (Process) · Spoofing · High · Mitigated

A predictable or low-entropy reset token is brute-forceable within its validity window.

> Reset, verification, export-download and deletion-cancel tokens are CSPRNG-generated. The design document explicitly forbids UUIDv7 for secrets because its 48-bit timestamp prefix leaves same-millisecond values sharing a long common prefix.

**T-41 — Verification email resend used for mail flooding**  
`Password reset & email verification` (Process) · Denial of service · Low · Mitigated

Repeated resend requests turn AXIAM into an email flooder against an arbitrary address and burn provider quota.

> Resend is capped (max 2 per day per account) and the endpoint is rate limited.

**T-42 — Password exposed to the breach-check service**  
`Password policy + HIBP check` (Process) · Information disclosure · Low · Mitigated

Sending a password or its full hash to a third-party breach API discloses the credential to that service.

> HIBP is queried with the k-anonymity model: only the first five characters of the SHA-1 hash leave the server. A circuit breaker prevents the optional check from becoming an availability dependency.

**T-43 — Offline cracking of exfiltrated password hashes**  
`user credentials (Argon2id hashes, OPAQUE records)` (Store) · Information disclosure · High · Mitigated

A database disclosure exposes every password hash to offline attack at attacker-chosen cost.

> Argon2id with OWASP-recommended parameters (m=19 MiB, t=2, p=1) and per-user salts makes bulk cracking expensive; policy enforces a 12-character minimum by default. The `argon2` crate moved to 0.6 in 1.0.0-beta08: the PHC string format is unchanged, the crate now draws the 16-byte salt from the OS RNG itself, and hashes written under 0.5 were verified to still verify.

**T-44 — Stored session tokens usable directly from the datastore**  
`session / refresh token store` (Store) · Information disclosure · High · Mitigated

If session tokens were stored in plaintext, datastore read access would be equivalent to holding every live session.

> Sessions store a token hash, not the token; the bearer value never rests in the database in usable form.

**T-45 — TOTP seed disclosure allows permanent code generation**  
`MFA secrets (AES-256-GCM)` (Store) · Information disclosure · High · Mitigated

A TOTP shared secret is a long-lived credential: whoever holds it can generate valid codes indefinitely.

> Seeds are AES-256-GCM encrypted at rest with a key held outside the datastore, so a database-only compromise does not yield usable seeds.

**T-46 — Counter store unavailability disables the shared limit**  
`rate-limit counters (shared, write-behind)` (Store) · Denial of service · Medium · Mitigated

If the shared counter cannot be read, the cross-replica limit cannot be evaluated.

> The shared pre-check fails open onto the per-replica in-memory governor, which is retained unchanged as the fallback — degraded but never absent protection.

**T-47 — Signing-key compromise forges any identity**  
`JWT signing keys (Ed25519)` (Store) · Information disclosure · Critical · Mitigated

The Ed25519 private key mints tokens for any subject in any tenant and cannot be detected by any downstream verifier.

> Keys are loaded from Kubernetes Secrets, never from the image; JWKS publishes multiple key ids so rotation is non-breaking; rotate on a schedule and immediately on suspicion.

**T-48 — Tokens leaked through URLs, logs or Referer headers**  
`access + refresh cookies` (Flow) · Information disclosure · Medium · Mitigated

Bearer values placed in query strings end up in access logs, browser history and Referer headers sent to third parties.

> Tokens are delivered in the response body and in Secure/HttpOnly cookies, never as URL parameters; secret-bearing types carry manual Debug implementations that redact them from logs (SEC-067 / SECHRD-09).

**T-176 — Account existence probed through the OPAQUE login flow**  
`Login endpoints /auth/login + /auth/opaque/*` (Process) · Information disclosure · Medium · Mitigated

POST /auth/opaque/login/start is unauthenticated and must answer for any identity; a response that differs for unknown accounts — in shape, stability or KSF parameters — is a username-enumeration oracle equivalent to a differential /auth/login error.

> RFC 9807 designs the case in: for an unknown identity the server runs the AKE with no password file and returns a well-formed KE2 derived from the setup's dummy public key. AXIAM adds the stability half — the decoy credential identifier is `HMAC(decoy_key, tenant_id || lowercased identity)`, so probing the same non-existent name twice gets the same answer; a random identifier would announce non-existence as loudly as a 404. Stated residual: a decoy carries the tenant's *current* KSF parameters while a real user carries those they enrolled under, so an attacker who knows the tenant's policy history can tell an account still on the old cost exists; the window closes as passwords rotate.

**T-177 — Unauthenticated OPAQUE exchanges consume server state and OPRF budget**  
`Login endpoints /auth/login + /auth/opaque/*` (Process) · Denial of service · Medium · Mitigated

login/start and register/start are unauthenticated by necessity; each costs the server an OPRF evaluation and in-flight exchange state, so a flood turns the PAKE handshake into a resource-exhaustion vector — the OPAQUE analogue of the Argon2id memory flood (T-10).

> Under OPAQUE the expensive KSF runs on the client, so the server-side cost per attempt is a bounded elliptic-curve OPRF evaluation, not a ~19 MiB Argon2id arena. The endpoints sit under the strict internet-facing per-IP rate limits the tuning presets are prevented from widening; register/start has its own benchmark scenario and budget (`opaque_register_start` — new in kind, since SRP enrolment cost the server nothing); and in-flight exchange state is sealed for 120 seconds under the cheap-to-rotate `opaque_session_key` rather than accumulating unbounded server-side sessions. OPAQUE is additionally off by default (`opaque_mode: disabled`) until an organization or tenant enables it.

**T-178 — OPAQUE login path sits outside the lockout counter**  
`Lockout & rate limiting` (Process) · Elevation of privilege · High · Mitigated

A failed OPAQUE authentication is a wrong password, but it surfaces as a failed KE3 inside the AKE rather than a failed hash verify. A path that did not accrue toward lockout would mean enabling OPAQUE silently removed brute-force protection from every account that adopted it — the same unmetered-path defect SEC-026b closed for gRPC (T-31), reopened by a new protocol.

> A failed KE3 accrues toward the shared exponential-backoff lockout exactly as a failed Argon2id verify does. `OpaqueRejection` deliberately has two variants rather than one so the caller can attribute an attempt before accruing it: a malformed client message (`AuthError::OpaqueMalformed`, 400) is distinguished from a wrong password, and only the latter counts against the account — and from corrupt stored state (500), so junk from a client is never read as a server fault.

**T-179 — Stolen OPAQUE records opened offline with the tenant OPRF seed**  
`user credentials (Argon2id hashes, OPAQUE records)` (Store) · Information disclosure · High · Mitigated

opaque_credential rows are the OPAQUE analogue of password hashes. Unlike an Argon2id or SRP-verifier corpus they are not offline-attackable at KDF cost alone — but only while the per-tenant OPRF seed stays secret. A dump that includes a usable seed reduces OPAQUE to the SRP posture: a dictionary attack priced at the KSF.

> Each tenant's OPRF seed and AKE keypair (`opaque_server_setup`, schema v42) are AES-256-GCM encrypted at rest under `opaque_setup_key`, which is held outside the datastore in the secret provider (Vault in production), so a database-only disclosure yields no dictionary attack to mount at any cost. The trade-off is stated in `docs/deployment/vault.md`: losing `opaque_setup_key` means a password reset for every user in every tenant — which is why the Vault seeder never regenerates an existing key, and why the setup key is split from the cheap-to-rotate `opaque_session_key`.

**T-182 — Usernameless passkey sign-in skips the gates of the ordinary login path**  
`MFA verification TOTP / WebAuthn` (Process) · Elevation of privilege · High · Mitigated

authenticate/discoverable/{start,finish} is a one-round-trip, first-class sign-in: there is no preceding password step for the account-status check, the operator's login veto or lockout to have run in. A path added without re-establishing those gates would verify a discoverable credential for an account that is locked, deactivated or anonymised — or make "click the passkey button" a bypass of an operator's login veto (SEC-095's shape, on a new door).

> Each gate is re-established on the new path. The `login.post_auth` reactor interception fires on the discoverable finish, reusing `intercept_federated_login_post_auth` because a one-round-trip sign-in has no branch to route `require_mfa` into. `ensure_can_sign_in` stands in for the missing first step — lockout first, then account status — refusing as `InvalidCredentials` so which of the two reasons applies is not disclosed. And start touches no storage: no "does this workspace have passkey users?" pre-check, because the caller is anonymous and that answer is a tenant-enumeration oracle (pinned by unit tests whose repository double panics on every method); an unknown credential fails at finish with the same error as any other bad assertion. Registration now requests a discoverable credential (`residentKey` required, replacing webauthn-rs's `discouraged` default); passkeys enrolled before that are not retroactively discoverable and keep password sign-in with the passkey second factor. Since 1.0.0-alpha38 the two authenticate/\*/finish handlers also emit the same Set-Cookie triple (`axiam_access`, `axiam_refresh`, `axiam_csrf`) and `X-CSRF-Token` header as the password path's cookie builder: a completed browser passkey ceremony lands in the same HttpOnly-cookie, CSRF-protected session posture as a password login, instead of leaving the token pair only in the JSON body. The body keeps its tokens for non-browser clients, which adopt them directly per CONTRACT §24.
>
> One gate was missed on the first pass and is worth recording as such, because it
> is this threat's own shape rather than a separate finding: **rate limiting**.
> `/auth/login` carries `login_per_min`; all six `/auth/webauthn/*` routes carried
> no limiter at all, and no `webauthn_per_min` existed to configure one with — so
> the discoverable pair, an unauthenticated first-class sign-in, was the one
> authentication surface with no throttle while the password path it parallels was
> held to ten attempts a minute per IP. T-182 enumerated the gates it re-established
> and this was not among them. Closed by `webauthn_per_min`, sized at
> `login_per_min` and asserted equal to it, so the two sign-in paths cannot drift
> apart silently.
>
> Note what did *not* find this: `rl_prod_check.py` verifies every configured
> rate-limit family against a measured admitted rate, and could not have reported
> it, because a family that does not exist cannot be extracted or compared. An
> endpoint with no limiter is invisible to the check that audits limiters. Finding
> the next one means reading the route table against `RateLimitConfig` — which
> nothing does today.

**T-188 — Brute force metered against the deployment default, not the configured threshold**  
`Lockout & rate limiting` (Process) · Spoofing · Medium · Mitigated

Every credential path accrued failed attempts against the process-wide AuthConfig defaults. A tenant or organization that lowered max_failed_login_attempts saw the setting stored, merged and returned by the settings API — and never read by the code that locks accounts, so the configured threshold was decoration and an attacker was metered against the more permissive deployment number on every transport.

> Fixed in 1.0.0-beta01: the REST login handler, OPAQUE login-finish and gRPC ValidateCredentials all resolve the org→tenant effective LockoutPolicy before accruing, so an account locks after the same number of failures whichever transport the attacker uses. record_failed_login now takes a LockoutPolicy rather than an AuthConfig — there is no longer a type that fits the parameter and carries the wrong numbers. A settings-resolution failure falls back to the deployment default rather than to no threshold, so a settings outage cannot open a brute-force window.

**T-189 — Logout's removal cookies were weaker than the cookies they cleared**  
`access + refresh cookies` (Flow) · Tampering · Medium · Mitigated

A removal is a Set-Cookie in its own right: the browser parses it and keeps the empty-valued cookie it describes until it expires. The logout paths emitted removals carrying only Path, dropping the HttpOnly, Secure and SameSite=Strict the matching setters emit — a replacement that was JS-readable, cross-site-sendable and cleartext-transmissible, and whose effectiveness rested on transport the setters explicitly do not trust, since a browser refuses to let a non-Secure cookie from an insecure origin overwrite a Secure one (“Leave Secure Cookies Alone”).

> Fixed in 1.0.0-beta03 (CodeQL rust/insecure-cookie): each removal cookie is built by calling the cookie's own setter and expiring the result, so HttpOnly, Secure, SameSite and Path are mirrored by construction rather than by repetition — there is exactly one place per cookie where those attributes are written, the deliberately JS-readable CSRF cookie included (D-07). Tests assert the attributes on the wire for all three cookies, across both logout paths and both cookie_secure values.

**T-201 — Enrolling a passkey never turns the second-factor requirement on**  
`MFA verification TOTP / WebAuthn` (Process) · Elevation of privilege · High · Mitigated

Adding a TOTP authenticator made the next sign-in demand a second factor; adding a passkey or security key did not (W5-01). The mfa_enabled flag began life meaning “a confirmed TOTP secret exists” and was reused to mean “challenge this account” — two readings that agree only while TOTP is the sole factor. A WebAuthn-only account listed its credential on the profile page while a password alone still let the account straight in, and the disable-on-last-removal branch was unreachable because nothing had ever turned the flag on for such an account.

> Fixed in 1.0.0-beta05: MfaMethodService::enable_after_enrollment runs when a WebAuthn registration completes, so a passkey is a factor from the moment it exists. The trap the fix had to avoid is pinned: every downstream reader tests mfa_enabled together with a stored TOTP secret, so setting the flag could have promoted an abandoned, unconfirmed TOTP enrollment into a live second factor — the pending secret is dropped rather than adopted, and an unconfirmed TOTP secret is never offered at sign-in. Removing the last passkey turns the requirement back off. Stated residual: if the flag write fails, the handler logs and continues, because the credential is already persisted and reporting the registration as failed would invite the user to register a second one. The user-verification policy those ceremonies run under became a tightening-only security setting in 1.0.0-beta09 (T-229, T-230). **Amended 2026-09-13 (M-3):** `enable_after_enrollment` now also runs on the setup-token registration path, where the stated residual above is deliberately *not* taken — a failure there fails the request, because the user is mid-login and there is no profile page to correct the flag from. See T-269.

**T-229 — A possession-only security key is accepted where possession alone must not be a complete login**  
`MFA verification TOTP / WebAuthn` (Process) · Spoofing · High · Mitigated

`webauthn-rs` hard-codes `UserVerificationPolicy::Required` on both passkey ceremonies, so a security key with no PIN — which can prove user *presence* but never user *verification* — was refused at the finish step against a policy that existed nowhere an operator could see or change, and the refusal read as a hardware fault because a PIN-protected key on the same account worked. Making user verification configurable is the right answer, and it opens the hazard this threat records: a relaxed policy applied indiscriminately would let a PIN-less key satisfy the usernameless sign-in path, where the credential is the only factor and mere possession of the token would then be a complete login; and a policy the browser is not told about leaves a browser that does not prompt facing a server that rejects the answer, or the reverse.

> Fixed in 1.0.0-beta09. `webauthn_user_verification` is a security setting in the same hierarchical model as the OPAQUE and privacy settings: an organization baseline every tenant inherits and may only make stricter, ordered `required > preferred > discouraged` — it can join that model, unlike the attestation policy, because it is totally ordered, which is exactly what the tighten-only override check needs. The default is `preferred`, not `required`, because nobody chose `required`: it was a library constant, and backfilling it would have preserved the bug rather than an intent; `preferred` accepts a security key whether or not it has a PIN and records which happened, so tightening later is a policy change rather than a re-enrolment. Two ceremonies deliberately do not follow the setting: **usernameless sign-in keeps `required`**, so a PIN-less key is a working second factor and never a passwordless one, and attested registration keeps the `required` that `webauthn-rs` imposes, on a path that already excludes synchronised authenticators and hybrid flows. The policy is applied in both places it has to be — the challenge, which decides whether the browser prompts for a PIN, and the ceremony state, which decides what the server accepts — and because the state's policy field is private with no builder, it is re-stamped in the serialization this crate already performs on the way into the state-token JWT, failing loudly rather than silently if upstream's shape changes, with a test that pins that shape against the real library so a patch release cannot turn the re-stamp into a no-op. The organization and tenant settings requests carry the field in `openapi.json` and in the eleven SDKs' §27 management surfaces (T-235). **Amended 2026-09-13 (M-3):** forced first-login enrolment can now register a passkey or a security key, and it reads both this policy and the attestation policy from the same places the profile-page ceremony does and hands them to the same functions — so the session-less path is governed by exactly the same settings rather than by a second implementation that agrees with them. See T-269.

**T-230 — A relaxed user-verification policy silently weakens credentials enrolled under a stricter one**  
`MFA verification TOTP / WebAuthn` (Process) · Tampering · Medium · Mitigated

A policy that governed how a credential is *used* rather than how it was *enrolled* would let an administrator downgrade every existing passkey at a stroke. The settings write that could do it is a `PUT` that replaces the whole row, so a client that simply omitted the new field would relax an organization that had set `required` without anyone choosing to — the quiet path by which a stricter posture is lost.

> Fixed in 1.0.0-beta09. No existing credential is weakened: `webauthn-rs` records the policy a credential was registered under and demands user verification at authentication whenever *either* that or the current policy says `required`, so every credential enrolled before this change carries the old hard-coded `required` for the rest of its life and the setting governs new enrolments only. Schema v53 adds the column with `DEFAULT 'preferred'` and backfills rows that predate it. The admin UI sends the field explicitly on the organization settings `PUT`, and it is a required field in the request type on purpose — a test fixture that has to be updated is exactly the friction that buys. `docs/admin/authenticator-policies.md` states the ordering, the two ceremonies that ignore the setting, and the per-credential rule. **Amended 2026-09-13 (M-3):** the forced first-login ceremony follows the setting, like the profile-page one and unlike those two; it is also the one place AXIAM reads the setting to decide what to *claim* rather than what to accept — `user` is recorded in the session's `amr` only under `required`, the one value that guarantees verification happened (T-269).

**T-260 — A bearer credential reaches stderr or the CI log through a derived `Debug` or a failing test's panic message**  
`Login endpoints /auth/login + /auth/opaque/*` (Process) · Information disclosure · Medium · Mitigated

Three CodeQL high-severity alerts on this wave, one class. `LoginOutput` gained a browser session token, and its derived `Debug` would have printed three credentials; a test panic formatted a whole `LoginResult`, whose non-`Success` variants carry a live MFA challenge token and a setup token; two assertions printed a full `Set-Cookie` header, token included, to explain a failed attribute check, and an `assert_ne!` on two cookie values prints both credentials when it fires. A panic message reaches stderr and a CI log that outlives the run, so a test is not exempt — the values are fixtures, but the sink is real and the next author's would not be.

> SECHRD-09 applied to every new sink rather than to the one CodeQL named. `LoginOutput`, `BasicCredentials` (T-253) and `UserInfoPostForm` (T-243) hand-write redacting `Debug` impls; the tests name the variant or the cookie that was set, never the value — compare, then assert. The TRACE-capture tests grep for the secret, its encoding and the header value rather than trusting the absence of a `{:?}`. `axiam-core`'s three redacting certificate `Debug` impls, which reach `{:?}` in handler-level tracing spans where `#[serde(skip_serializing)]` cannot help, are now asserted — `Option`-aware on purpose, since a `vault_pki` CA has no key and printing `[REDACTED]` would claim one was withheld. One adjacent hygiene fix on 2026-09-13 (fcc976d): the two redaction tests R-5 added for `DbConfig` and `AmqpConfig` wrote a literal fake password into the source, which a secret scanner (GitGuardian, on the PR) cannot tell from a real one and neither can a reader six months later. They now mint the value through `axiam_test_support::test_password`, so the assertion holds for whatever the helper produces rather than for one string, and the seeder derives its credential field-name list from the environment table rather than repeating it. No scanner exemption was added: `.gitguardian.yaml` is for published RFC test vectors, and silencing a detector over a value one can simply stop writing is how an exemption list stops meaning anything.

</details>

### 5.3 OAuth2 / OIDC authorization server

Authorization Code with PKCE, client credentials and refresh grants; consent, introspection, revocation, userinfo, JWKS and discovery; client registration and the code and token stores.

Since 1.0.0-beta13 this also covers the OpenID Connect **Basic OP** surface the W1–W9 waves of [`basic-op-gap-plan.md`](basic-op-gap-plan.md) added — the per-client browser login hop and its OP session cookie, the honour lane for the authentication-request parameters, the consent-gated `address` and `phone` scopes, `client_secret_basic`, `POST /oauth2/userinfo` and tenant-scoped discovery (T-237…T-245, T-255…T-259) — and what the OpenID Foundation conformance suite found when it was first run against a live AXIAM (T-246…T-252). Three of those findings had no honest home on the diagram, because they are about what the server does with a token it did not just mint, so the model gains a tenth element here: **resource-endpoint token validation**, the extractors every protected route runs. One of them, T-254, was recorded **open** at beta13 — the refresh-rotation grace window FAPI 2.0 requires, which AXIAM applied to every profile — and was closed by the maintainer's decision of 2026-09-12: the window is now a `fapi2` behaviour, and a rotated token presented again is marked and audited whatever the window.

The 2026-09-14 pass, between 1.0.0-beta14 and the next release, moved two refusals to the point where the request is already known to be unusable, so nobody is asked to sign in for a request that cannot succeed and the relying party is told over the protocol rather than through a browser: a `request_uri` that is already spent, expired or another client's is refused before the login hop by a read that does not spend it, and reported as `invalid_request_uri` to a registered `redirect_uri` (T-270); and a `fapi2` client's `state` and `nonce` are bounded at push (T-271). Eight OpenID Foundation modules moved from `REVIEW` to `PASSED` per module; no full plan has been re-swept.

The 2026-09-17 pass adds Phase 21's MCP authorization surfaces ([`mcp-authorization-server-plan.md`](mcp-authorization-server-plan.md)), which are the first thing in this model to put an **unauthenticated write endpoint** and an **outbound fetch whose target an unauthenticated caller chooses** on the authorization server itself, and the first to let a token be minted for an audience that is not AXIAM. Four new elements carry them: `/oauth2/register` (RFC 7591), the client ID metadata document fetch, the externally registered client rows those two mechanisms create, and the per-tenant path issuers that give an MCP client an issuer it can turn into a discovery URL. T-277 through T-279 are the three places the phase could have broken an existing guarantee and does not; T-272, T-275, T-276 and T-280 are recorded **open** from [`security-review-mcp-2026-09-17.md`](security-review-mcp-2026-09-17.md), which is the first entry in this model's history where a review's findings arrive already filed rather than already fixed — three of the four need a settings field or a migration to close, and the fourth is a six-call-site change in a handler its own task did not touch.

*58 threats — 5 critical, 25 high, 24 medium, 4 low; 4 open.*

| # | Element | STRIDE | Threat | Severity | Status |
|---|---|:-:|---|---|---|
| T-49 | OAuth2 client app (confidential / public) <br/>*Actor* | S | Public client cannot keep a secret | High | Mitigated |
| T-50 | Resource server (protected API) <br/>*Actor* | S | Token substitution across audiences | High | Mitigated |
| T-51 | End user (resource owner) <br/>*Actor* | S | Consent screen spoofing / clickjacking | Medium | Mitigated |
| T-52 | /oauth2/authorize (+ consent) <br/>*Process* | E | Open redirect via a loosely matched redirect_uri | Critical | Mitigated |
| T-53 | /oauth2/authorize (+ consent) <br/>*Process* | T | Login CSRF via a missing state parameter | Medium | Mitigated |
| T-54 | /oauth2/token (code, refresh, client credentials) <br/>*Process* | S | Authorization code replay | High | Mitigated |
| T-55 | /oauth2/token (code, refresh, client credentials) <br/>*Process* | E | Scope escalation at token exchange | High | Mitigated |
| T-56 | PKCE verification (S256) <br/>*Process* | T | PKCE downgrade to the plain method | High | Mitigated |
| T-57 | /oauth2/introspect /revoke <br/>*Process* | I | Unauthenticated introspection leaks token metadata | Medium | Mitigated |
| T-58 | OIDC /userinfo, /jwks, discovery <br/>*Process* | I | userinfo returns claims beyond the granted scope | Medium | Mitigated |
| T-59 | Client registration & secret rotation <br/>*Process* | I | Client secrets recoverable from storage or logs | High | Mitigated |
| T-60 | authorization codes (single-use) <br/>*Store* | T | Codes outlive their intended window | Medium | Mitigated |
| T-61 | OIDC signing keys (JWKS) <br/>*Store* | I | Stale key served in JWKS after rotation | Low | Mitigated |
| T-62 | redirect with code <br/>*Flow* | I | Code leaked through the Referer header or browser history | Medium | Mitigated |
| T-163 | single-use credentials (UMA tickets, device codes, PAR request_uris) <br/>*Store* | T | Concurrent redemption spends one credential twice | High | Mitigated |
| T-271 | single-use credentials (UMA tickets, device codes, PAR request_uris) <br/>*Store* | T | An unbounded `state` or `nonce` makes a pushed request a payload channel: kilobytes stored under a 60-second handle and reflected out of the client's `redirect_uri` | Low | Mitigated |
| T-164 | authorization codes (single-use) <br/>*Store* | T | Two concurrent redemptions of one authorization code | High | Mitigated |
| T-166 | /oauth2/token (code, refresh, client credentials) <br/>*Process* | S | Stolen client credential replayed from anywhere on the network | High | Mitigated |
| T-168 | redirect with code <br/>*Flow* | S | Authorization-server mix-up delivers an honest server's code to an attacker's token endpoint | High | Mitigated |
| T-169 | /oauth2/token (code, refresh, client credentials) <br/>*Process* | S | Client assertion replay (private_key_jwt) | High | Mitigated |
| T-170 | /oauth2/token (code, refresh, client credentials) <br/>*Process* | S | Client assertion minted for another authorization server | High | Mitigated |
| T-171 | /oauth2/token (code, refresh, client credentials) <br/>*Process* | S | Algorithm confusion on a client assertion or DPoP proof | Critical | Mitigated |
| T-172 | /oauth2/token (code, refresh, client credentials) <br/>*Process* | S | DPoP proof replay | High | Mitigated |
| T-173 | Client registration & secret rotation <br/>*Process* | I | SSRF via a registered jwks_uri | High | Mitigated |
| T-174 | Client registration & secret rotation <br/>*Process* | D | Availability coupling to a client's JWKS endpoint | Medium | Mitigated |
| T-259 | End user (resource owner) <br/>*Actor* | R | The end user cannot refuse an authorization request, so the relying party cannot tell a refusal from a crash | Low | Mitigated |
| T-237 | /oauth2/authorize (+ consent) <br/>*Process* | S | The OP session cookie travels where a Strict cookie would not, so its attributes carry the whole risk | High | Mitigated |
| T-238 | /oauth2/authorize (+ consent) <br/>*Process* | E | `/login?return_to=` becomes an open redirect, or the login hop a redirect loop | High | Mitigated |
| T-239 | /oauth2/authorize (+ consent) <br/>*Process* | T | A relying party is told it received a freshness or assurance guarantee it did not get | High | Mitigated |
| T-255 | /oauth2/authorize (+ consent) <br/>*Process* | T | An authorization error is delivered to the wrong place: redirected to an unregistered target, rendered as JSON to a person, or echoing attacker-chosen parameters on AXIAM's origin | Medium | Mitigated |
| T-256 | /oauth2/authorize (+ consent) <br/>*Process* | T | Inline parameters beside a PAR `request_uri` are read, or a pushed `request_uri` is accepted | Medium | Mitigated |
| T-257 | /oauth2/authorize (+ consent) <br/>*Process* | I | `login_hint` becomes an account-existence oracle, or `ui_locales` / `display` an injection into the sign-in page | Medium | Mitigated |
| T-270 | /oauth2/authorize (+ consent) <br/>*Process* | T | A dead `request_uri` is discovered only after a sign-in, or the early read that prevents it spends the handle, authorizes from it, or reports the refusal somewhere the client never registered | High | Mitigated |
| T-240 | /oauth2/token (code, refresh, client credentials) <br/>*Process* | T | A refresh or a replayed upstream SSO session is dated as a fresh authentication | Medium | Mitigated |
| T-251 | /oauth2/token (code, refresh, client credentials) <br/>*Process* | S | An authorization code is redeemed by a DPoP key other than the one it was pinned to | High | Mitigated |
| T-252 | /oauth2/token (code, refresh, client credentials) <br/>*Process* | S | The strong client-authentication methods were registrable and unusable, inviting a fall-back to a shared secret | High | Mitigated |
| T-253 | /oauth2/token (code, refresh, client credentials) <br/>*Process* | S | `client_secret_basic`: the header reaches a log, the RFC 6749 §2.3.1 decoding is wrong, or a client gets two ways in | Medium | Mitigated |
| T-254 | /oauth2/token (code, refresh, client credentials) <br/>*Process* | S | A leaked refresh token replayed inside the rotation grace window forks the session undetected | Medium | Mitigated |
| T-241 | OIDC /userinfo, /jwks, discovery <br/>*Process* | I | A postal address or telephone number is released by naming the claim, from a token issued before consent was withdrawn, or inside an ID token | High | Mitigated |
| T-242 | OIDC /userinfo, /jwks, discovery <br/>*Process* | I | The ID token carries identifiers nobody asked for, and travels further than the relying party | Medium | Mitigated |
| T-243 | OIDC /userinfo, /jwks, discovery <br/>*Process* | I | A UserInfo POST authenticated by a cookie answers a cross-site form, or logs the token it carried | Medium | Mitigated |
| T-244 | OIDC /userinfo, /jwks, discovery <br/>*Process* | I | Tenant-scoped discovery becomes a tenant-enumeration oracle, or a default tenant becomes a handler fallback | Medium | Mitigated |
| T-245 | OIDC /userinfo, /jwks, discovery <br/>*Process* | T | A misconfigured mTLS alias routes clients to the wrong host, or the front channel is aliased | Medium | Mitigated |
| T-258 | Client registration & secret rotation <br/>*Process* | T | A registration is edited into a weaker posture: a `fapi2` row set to honour, a sensitive scope on a `fapi2` client, or a scope-only patch that skips the merged validation | Medium | Mitigated |
| T-250 | authorization codes (single-use) <br/>*Store* | T | A replayed authorization code is refused, but the tokens it already minted keep working | High | Mitigated |
| T-246 | Resource-endpoint token validation (cnf, DPoP jti, sid) <br/>*Process* | S | A sender-constrained token is laundered into a bearer token through the identity cache | Critical | Mitigated |
| T-247 | Resource-endpoint token validation (cnf, DPoP jti, sid) <br/>*Process* | S | A DPoP proof captured at a resource endpoint is replayed within its freshness window | High | Mitigated |
| T-248 | Resource-endpoint token validation (cnf, DPoP jti, sid) <br/>*Process* | D | Replay protection recorded before verification becomes a denial-of-service primitive against the key it protects | Medium | Mitigated |
| T-249 | Resource-endpoint token validation (cnf, DPoP jti, sid) <br/>*Process* | E | An OAuth2 access token names no session, so a password or MFA reset cannot revoke it — or UserInfo refuses every token | Medium | Mitigated |
| T-273 | /oauth2/register (RFC 7591, unauthenticated) <br/>*Process* | S | A stranger registers a client whose `redirect_uris` name a host the tenant did not mean to admit, or whose posture it did not mean to grant | High | Mitigated |
| T-272 | /oauth2/register (RFC 7591, unauthenticated) <br/>*Process* | D | A stranger fills the tenant's registration quota and denies registration to legitimate clients until the sweeper runs | Medium | **Closed** — `c4d9ea2` |
| T-274 | Client ID metadata document fetch <br/>*Process* | I | An unauthenticated `client_id` turns the authorization server into a request-forgery engine against its own network | High | Mitigated |
| T-276 | Client ID metadata document fetch <br/>*Process* | I | The trusted-publisher list that bounds the fetch admits a value meaning "every host" | Medium | **Closed** — `0a273ec` |
| T-275 | externally registered clients (dcr, cimd) <br/>*Store* | D | Shadow client rows accumulate without a quota and are reclaimed by nothing | Medium | **Closed** — `0b216c6` |
| T-277 | Resource-endpoint token validation (cnf, DPoP jti, sid) <br/>*Process* | E | A resource indicator names AXIAM's own token audience, so a grant mints a credential for AXIAM while claiming to mint one for somebody else | Medium | Mitigated |
| T-278 | /oauth2/authorize (+ consent) <br/>*Process* | E | RFC 8252's loopback port allowance widens a redirect registration by more than a port | Critical | Mitigated |
| T-280 | /oauth2/authorize (+ consent) <br/>*Process* | D | A desktop client on an ephemeral loopback port is never told its authorization failed | Low | **Closed** — `b8bc508` |
| T-279 | per-tenant path issuers (/t/{tenant_id}) <br/>*Process* | E | One key set signs every tenant, so a token minted for tenant A verifies on tenant B's path | Critical | Mitigated |

<details>
<summary>Threat detail and mitigations</summary>

**T-49 — Public client cannot keep a secret**  
`OAuth2 client app (confidential / public)` (Actor) · Spoofing · High · Mitigated

SPAs and mobile apps ship their client_secret to the user, so secret-based client authentication is meaningless for them.

> Authorization Code with PKCE is the supported flow for public clients; the code_verifier replaces the secret as proof of possession. The implicit grant is not offered.

**T-50 — Token substitution across audiences**  
`Resource server (protected API)` (Actor) · Spoofing · High · Mitigated

A resource server that does not check the audience accepts a token minted for a different client or API, letting a malicious RP replay a token it legitimately received.

> Tokens carry issuer, audience and tenant claims; SDK verifiers check iss and aud against configuration, and the discovery document publishes the expected issuer.

**T-51 — Consent screen spoofing / clickjacking**  
`End user (resource owner)` (Actor) · Spoofing · Medium · Mitigated

Framing the consent screen and overlaying it tricks a user into approving a grant they cannot see.

> The security-headers middleware sets frame-ancestors in the CSP and X-Frame-Options, so the authorization endpoint cannot be framed by a third-party origin.

**T-52 — Open redirect via a loosely matched redirect_uri**  
`/oauth2/authorize (+ consent)` (Process) · Elevation of privilege · Critical · Mitigated

Prefix or wildcard matching on redirect_uri lets an attacker append a path or subdomain and receive the authorization code at a URL they control.

> redirect_uri is matched by exact string comparison against the registered set; no wildcards, no prefix matching, no normalisation that could widen the match.

**T-53 — Login CSRF via a missing state parameter**  
`/oauth2/authorize (+ consent)` (Process) · Tampering · Medium · Mitigated

Without a state value bound to the user's session, an attacker can complete an authorization in the victim's browser and link the victim's session to an attacker-controlled identity.

> state is required and echoed unchanged; the browser-facing flow additionally runs behind the double-submit CSRF cookie middleware with constant-time comparison.

**T-54 — Authorization code replay**  
`/oauth2/token (code, refresh, client credentials)` (Process) · Spoofing · High · Mitigated

A code observed in a redirect, a proxy log or browser history is exchanged a second time for a fresh token pair.

> Codes are single-use, short-lived, and bound to the issuing client and redirect_uri; a second redemption both fails and is audited.

**T-55 — Scope escalation at token exchange**  
`/oauth2/token (code, refresh, client credentials)` (Process) · Elevation of privilege · High · Mitigated

A client requests broader scopes at the token endpoint than the user consented to at the authorize endpoint.

> Granted scope is fixed at authorization time and stored with the code; the token endpoint can only narrow it, never widen it, and refresh never re-expands scope.

**T-56 — PKCE downgrade to the plain method**  
`PKCE verification (S256)` (Process) · Tampering · High · Mitigated

Accepting code_challenge_method=plain lets an attacker who intercepts the authorization request read the verifier directly, defeating the protection.

> S256 is required; the plain method is rejected, and a code issued with a challenge cannot be redeemed without a matching verifier.

**T-57 — Unauthenticated introspection leaks token metadata**  
`/oauth2/introspect /revoke` (Process) · Information disclosure · Medium · Mitigated

An open introspection endpoint becomes a token oracle: an attacker can test captured values and learn subject, scope and expiry.

> Introspection requires client authentication and is scoped to the caller's own tenant (SEC-068); unknown tokens return the uniform inactive response with no distinguishing detail.

**T-58 — userinfo returns claims beyond the granted scope**  
`OIDC /userinfo, /jwks, discovery` (Process) · Information disclosure · Medium · Mitigated

Returning the full profile regardless of scope discloses email, groups or metadata the user never consented to share.

> Claims are filtered by the token's granted scopes; profile, email and groups claims each require their corresponding scope. Since 1.0.0-beta13 the `profile` scope releases the full OIDC Core §5.1 claim set — SCIM attributes first, `metadata.oidc` as the fallback for every claim, `updated_at` from the row's own column as a NumericDate — and §5.5's `claims` parameter is honoured for its `userinfo` member, parsed and filtered at the authorization endpoint, stored on the code and carried in the token as `axiam_requested_claims`. Neither can unlock `phone_number`, `phone_number_verified` or `address`, which sit behind the consent gates of T-241 (`claims_request::RELEASABLE`).

**T-59 — Client secrets recoverable from storage or logs**  
`Client registration & secret rotation` (Process) · Information disclosure · High · Mitigated

Plaintext client secrets in the database — or in a Debug or trace line — are directly reusable credentials.

> Secrets are stored HMAC-SHA256 hashed and returned once at creation; secret-bearing structs carry manual Debug impls that redact them (SEC-067 / SECHRD-09).

**T-60 — Codes outlive their intended window**  
`authorization codes (single-use)` (Store) · Tampering · Medium · Mitigated

Codes that are not expired or purged remain redeemable long after the flow completes, widening the replay window.

> Codes carry a short expiry, are deleted on redemption, and expired entries are swept.

**T-61 — Stale key served in JWKS after rotation**  
`OIDC signing keys (JWKS)` (Store) · Information disclosure · Low · Mitigated

Removing a key from JWKS before its last token expires breaks verification; leaving a retired key indefinitely widens the window in which a compromised key is still trusted.

> JWKS publishes the active key plus a bounded overlap window matching the maximum token lifetime, then drops the retired kid.

**T-62 — Code leaked through the Referer header or browser history**  
`redirect with code` (Flow) · Information disclosure · Medium · Mitigated

The authorization code travels in a URL, so it can leak to any third-party resource loaded by the redirect target.

> PKCE makes a leaked code unusable without the verifier; codes are single-use and short-lived; Referrer-Policy is set by the security-headers middleware.

**T-163 — Concurrent redemption spends one credential twice**  
`single-use credentials (UMA tickets, device codes, PAR request_uris)` (Store) · Tampering · High · Mitigated

Two redemptions of the same credential arriving together can both observe it unspent and both succeed, yielding two RPTs from one authorization decision, two token sets from one user approval, or a replayable authorization request. RFC 8628 makes this the normal shape of the device flow rather than an exotic case: the device polls on a short interval, so a poll is usually already in flight when the user approves.

> Two independent layers, so a double redemption needs both to fail (ilpanich/axiam#302). The guarded UPDATE runs inside an explicit transaction, making two concurrent redemptions a write-write conflict the storage engine aborts the loser of; and a per-attempt nonce is read back in a separate query after that transaction commits, so a conflict the engine silently missed is still caught. The read-back stays outside the transaction deliberately — inside one, snapshot isolation shows every racer its own write. Measured with tools/surreal-race-probe: zero double redemptions in 40 000 contended attempts on surrealkv and 9 600 on rocksdb. Layer one is a property of the storage engine, so the guarantee is conditional on running a persistent one — see T-165. authorization_code.consume carries the same two layers as of schema v37 (T-164). At 1.0.0-beta13 the conflict recogniser behind this branch was found not to match SurrealDB v3's own phrasing — fail-closed, so a refused replay surfaced as a `500` rather than as "no row consumed" — and the three phrasings now live in one marker set (T-262). 2026-09-14: `find_unconsumed` is a second reader of this store — `consume`'s guard clause with the write removed, spelled out rather than shared so the two stay identical in what they consider spendable — and it is a read only: `ParService::peek` refuses a dead handle before the login hop and never spends a live one, so nothing here changes which statement decides single use (T-270).

**T-271 — An unbounded `state` or `nonce` makes a pushed request a payload channel: kilobytes stored under a 60-second handle and reflected out of the client's `redirect_uri`**  
`single-use credentials (UMA tickets, device codes, PAR request_uris)` (Store) · Tampering · Low · Mitigated

`state` and `nonce` are opaque values the client chooses and the server only echoes, so length carries no meaning: 32 bytes of entropy is 43 characters base64url. What an unbounded value buys is a way to push kilobytes of chosen text through `/oauth2/par`, keep it in the `pushed_auth_request` row until the handle expires, and have it reflected into the authorization response — and into whatever the relying party does with `state`. The OpenID Foundation's FAPI 2.0 suite probes this boundary directly, with a 1000-character `state` and a 384-character `nonce`, and requires both to be refused (`ensure-authorization-request-with-long-state`, `-with-long-nonce`); AXIAM accepted both.

> 2026-09-14 (ad1cb67). `ParService::push` refuses a `state` or `nonce` longer than `MAX_FAPI_OPAQUE_PARAM_CHARS` — 256 characters, counted as characters rather than bytes so the bound does not depend on how many non-ASCII code points an opaque value happens to contain — with `invalid_request`, checked at push, where the client is authenticated and the refusal is attributable and reaches it as a protocol error, rather than at `/oauth2/authorize`, where it would surface in a browser after a sign-in nobody should have been asked for. Gated on `ClientProfile::Fapi2` deliberately: a cap is a breaking change for a `standard` client that packs data into `state` — a bad practice, a widespread one, and one a deployment upgrading AXIAM has not agreed to — while the FAPI profile is where the stricter bundle was agreed and where the suite requires the refusal. A `const` block pins the cap against the suite's own probes and against what a conformant client sends (`86 <= cap < 384`), so relaxing it past either fails to compile rather than surfacing as a failed certification. The residual on the `standard` profile is stated rather than hidden, and is small: the pusher is an authenticated client reflecting text into its *own* registered `redirect_uri`, the row lives 60 seconds on a route under the per-IP rate limit, and the whole form is bounded by actix's default 16 KiB body cap on `/oauth2/par`. Four FAPI 2.0 modules moved from `REVIEW` to `PASSED` per module (`-with-long-state`, `-with-long-nonce`, `-different-nonce-inside-and-outside-request-object`, `-different-state-inside-and-outside-request-object`), and a `standard` client still accepts a 1000-character `state`, asserted.

**T-164 — Two concurrent redemptions of one authorization code**  
`authorization codes (single-use)` (Store) · Tampering · High · Mitigated

A code observed in a redirect or a proxy log and replayed at the same moment as the legitimate exchange could, if the two are not serialised, let both callers mint a token pair from one authorization. T-54 covers the sequential replay; this is the concurrent one, which the single-use flag alone does not decide.

> Two independent layers, the same pair the three credentials in T-163 carry (schema v37). The guarded UPDATE — used = false, with client_id and redirect_uri matched in the same statement so a wrong-client attempt cannot burn the code — runs inside an explicit transaction, so two concurrent redemptions conflict on one key and the engine aborts the loser; and a per-attempt redemption nonce is read back in a separate query after that transaction commits, catching a conflict the engine silently missed. Before v37 this path had the first layer implicitly (a lone statement runs in the engine's own transaction) and the second not at all, which left it resting on T-165 with nothing behind it. Guarded by authorization_code_consume_serialises over 50 rounds of 8 racers, and by an_authorization_code_redemption_stamps_its_nonce, which asserts the second layer directly — a race test cannot distinguish a two-layer mechanism from a one-layer one when the engine arbitrates either way. At 1.0.0-beta13 the conflict recogniser behind this branch was found not to match SurrealDB v3's own phrasing — fail-closed, so a refused replay surfaced as a `500` rather than as "no row consumed" — and the three phrasings now live in one marker set (T-262).

**T-166 — Stolen client credential replayed from anywhere on the network**  
`/oauth2/token (code, refresh, client credentials)` (Process) · Spoofing · High · Mitigated

A confidential client's `client_secret` leaks — through a log, a CI variable, a config repository or an operator's shell history — and an attacker presents it from an arbitrary host to mint tokens as that client. A shared secret carries no evidence of *where* it is being used from, so the authorization server cannot distinguish the legitimate client from the thief.

> X5.1 adds RFC 8705 mutual-TLS client authentication. A client registered `tls_client_auth` or `self_signed_tls_client_auth` authenticates by presenting a certificate rustls verified during the TLS 1.3 handshake, matched against the registration's subject DN / SAN or its `x5t#S256` thumbprint. The private key never leaves the client, so the credential cannot be copied out of a log. Three details do the load-bearing work: the **registration** selects which credential authenticates and never the request, so the two methods can never become an OR an attacker may pick from; the `X-Client-Certificate` proxy header that the device-auth path accepts is deliberately not a source here, because a client credential must not be assertable by anything that can set a header; and every failure returns one uniform `invalid_client` description, so SEC-086's property — client existence stays undecidable to an unauthenticated caller — survives the new method. Certificate binding (T-167) then addresses the *tokens* the same way this addresses the credential. Since 1.0.0-beta13 the listener can also admit RFC 8705 §2.2 self-signed certificates under a fourth, opt-in policy, and `tls_client_auth` then *requires* the certificate to have chained (T-263); the registered subject DN is compared, still exactly, against both correct renderings derived from the certificate, because the documented `-nameopt rfc2253` form never matched before (T-252).

**T-168 — Authorization-server mix-up delivers an honest server's code to an attacker's token endpoint**  
`redirect with code` (Flow) · Spoofing · High · Mitigated

A client configured against more than one authorization server receives an authorization response on a redirect URI shared between them. A bare `code`+`state` response names no sender, so an attacker controlling one of those servers can arrange for a code minted by an honest server to be redeemed at the attacker's token endpoint, or the reverse. The client's own `state` check does not help: the state is the client's, and it matches.

> X5.1 implements RFC 9207 — every AXIAM authorization response carries an `iss` parameter naming the issuer, and discovery advertises `authorization_response_iss_parameter_supported: true`. It is emitted for **every** client regardless of profile, and on the **error** redirect as well as the success one: mix-up is the attack a client does not know it is under, so gating it on a setting would mean protection only where somebody remembered; and one variant of the attack works by injecting an error response, so a client that validates `iss` on success and skips it on failure has left ajar the door it just closed. Contract 1.15 §21.4 requires SDKs implementing the §12 relying-party flow to compare it against the issuer the flow began with. **Residual risk sits with the relying party**: a client that ignores the parameter gains nothing from it, which is why §21.4 is written as a SHOULD that any SDK talking to more than one issuer should treat as a MUST.

**T-169 — Client assertion replay (private_key_jwt)**  
`/oauth2/token (code, refresh, client credentials)` (Process) · Spoofing · High · Mitigated

A `private_key_jwt` client assertion (RFC 7523 §2.2) is a bearer credential for whoever holds it until it expires. Anything that observes one — a logging proxy, an APM trace that captures request bodies, a mis-scoped debug dump — can present it again and authenticate as that client. Freshness alone does not stop this: `exp` only bounds how long the captured assertion stays interesting.

> `jti` is single-use and permanently so. Recording is a `CREATE` against `oauth2_proof_replay`, whose `UNIQUE` index over `(tenant_id, kind, scope, jti)` **is** the "already seen" answer — there is no read-then-write, so two concurrent copies of one assertion cannot both pass the race #316/#318 closed for authorization codes. Assertion lifetime is additionally capped at 3600 s whether or not the client sent `iat`, so omitting an optional claim cannot buy an unbounded credential. A replay guard that cannot record refuses the authentication rather than failing open.

**T-170 — Client assertion minted for another authorization server**  
`/oauth2/token (code, refresh, client credentials)` (Process) · Spoofing · High · Mitigated

A client that authenticates to several authorization servers signs an assertion for each. An assertion captured at (or by) one server is a valid signature by that client, and a server that does not check `aud` would accept it — letting a malicious or compromised peer AS authenticate as the client here.

> RFC 7523 §3: `aud` must name this server (its issuer or its token-endpoint URL; both are accepted because OIDC Core §9 and RFC 7523 disagree about which, and refusing either is an interop failure with no security content). `iss` and `sub` must both equal the `client_id` per OIDC Core §9, so one registered client cannot mint an assertion authenticating as another.

**T-171 — Algorithm confusion on a client assertion or DPoP proof**  
`/oauth2/token (code, refresh, client credentials)` (Process) · Spoofing · Critical · Mitigated

Both mechanisms verify a JWS the server did not mint. The classic forgeries are `alg: none` and RSA-public-key-as-HMAC-secret, and both are the same bug: the token told the verifier how to check the token. A verifier that reads `alg` from the JWS header lets an attacker choose the verification path.

> `axiam_oauth2::jose` derives the algorithm from the **key material** — the registered JWK for an assertion, the embedded JWK for a proof — and then requires the header to agree with what the key already decided. A key declaring an `alg` inconsistent with its material is refused rather than reinterpreted. Only `PS256`, `ES256` and `EdDSA` are permitted; `RS256` and symmetric keys are refused explicitly. `none` is unreachable twice over: `jsonwebtoken::Algorithm` has no such variant, and the permitted list would not contain it if it did.

**T-172 — DPoP proof replay**  
`/oauth2/token (code, refresh, client credentials)` (Process) · Spoofing · High · Mitigated

A DPoP proof (RFC 9449) travels in a request header on every request, so it is observed by strictly more infrastructure than a client assertion is. A captured proof replayed within its freshness window would let the captor obtain or use a sender-constrained token without holding the private key — which is the entire property DPoP exists to provide.

> Layered, because no single layer is sufficient. (1) `iat` must be within 60 s in both directions. (2) `htm`/`htu` bind the proof to one method and one URI, compared with query and fragment stripped and nothing else normalised. (3) `ath` binds it to one access token, so a proof cannot be re-aimed at another token held by the same key. (4) `jti` is recorded single-use at the token endpoint through the same `UNIQUE`-index guard the client assertion uses, with the row expiring exactly at the end of the freshness window. (5) `dpop_require_nonce` optionally makes a proof unusable before the server has spoken. **Known residual:** the resource-server path in `axiam-api-rest`'s extractor is synchronous and does **not** record `jti`, so within the 60 s window a proof for that exact method, URI and token could be presented twice there. Documented in the extractor and in contract §21.7.2; closing it means moving the check into middleware that can await. **Residual closed at 1.0.0-beta13:** the resource-endpoint extractors now record `jti` in their async tail through the same replay repository the token endpoint writes (T-247, T-248), and `htu` is compared after RFC 3986 syntax- and scheme-based normalisation as §4.3 asks — `:443`, host case and a `..` segment no longer produce false negatives, an unparseable `htu` is compared raw on both sides, and a URI naming a different resource is still refused.

**T-173 — SSRF via a registered jwks_uri**  
`Client registration & secret rotation` (Process) · Information disclosure · High · Mitigated

A `private_key_jwt` client may register a `jwks_uri` that AXIAM fetches on demand to obtain the keys that authenticate it. That is an operator- or client-supplied URL the server will retrieve: pointed at a link-local metadata endpoint, an internal admin service or a loopback port, it turns client registration into a request-forgery primitive against the server's own network. A DNS name that resolves publicly at registration and privately at fetch time (rebinding) defeats a naive validate-then-fetch check.

> The fetch goes through `axiam_federation::jwks_cache::JwksCache`, the **same** guarded path a federated IdP's JWKS uses — not a bare `reqwest::get`. That guard (`ssrf::guarded_fetch`, SEC-054/SECHRD-02) resolves the host, rejects private, loopback and link-local addresses, and **pins the validated IP into the connection**, which is what closes the rebinding TOCTOU. A 512 KiB body cap bounds the response. Registration additionally refuses a `jwks_uri` that is not absolute `https`, so the operator hears about the mistake while onboarding. Reusing one guard rather than writing a second is deliberate: two guards are two chances for one to miss a fix.

**T-174 — Availability coupling to a client's JWKS endpoint**  
`Client registration & secret rotation` (Process) · Denial of service · Medium · Mitigated

A client registered with `jwks_uri` cannot authenticate if AXIAM cannot fetch its key set. Naively that makes every token request depend on a third party's uptime, and makes the token endpoint's latency a function of somebody else's TLS handshake.

> The shared JWKS cache serves keys for a 1-hour TTL without any HTTP, and serves **stale** keys for a further 24 hours when the client's endpoint is unreachable rather than failing the authentication. An operator who wants no outbound dependency at all registers the key set inline as `jwks`; the operator guide says which to choose and why.

**T-259 — The end user cannot refuse an authorization request, so the relying party cannot tell a refusal from a crash**  
`End user (resource owner)` (Actor) · Repudiation · Low · Mitigated

RFC 6749 §4.1.2.1 and OIDC Core §3.1.2.6 both require `access_denied` when the end user declines. The consent screen has a decline button, but it renders only for a sensitive scope; a request for `openid profile` reached a sign-in page whose only outcomes were "authenticate" and "close the tab". Closing the tab is not a protocol answer: the relying party waits on a response that never arrives, cannot tell a refusal from a crash, and the refusal is recorded nowhere.

> 065f37c: the sign-in page gains a Cancel control, shown only when a pending authorization is being decided, which returns through `axiam_user_declined`. The refusal is delivered on the same terms as every other authorization error — only to a `redirect_uri` this client registered, compared exactly, with the request's own `state`, and for a pushed request both come from the pushed copy (T-256); consuming the `request_uri` there is correct, since it is single-use and the request has just been answered terminally. A sensitive-scope consent decision is recorded either way: the `consent` row is live state and `gdpr.oidc_scope_consent_*` in the append-only audit log is the history (Art. 7(1)).

**T-237 — The OP session cookie travels where a Strict cookie would not, so its attributes carry the whole risk**  
`/oauth2/authorize (+ consent)` (Process) · Spoofing · High · Mitigated

Wave W3 added `axiam_op_session`, the only `SameSite=Lax` cookie AXIAM sets. It has to be Lax: a relying party's redirect is a cross-site top-level navigation, and the `SameSite=Strict` API cookie never travels on one — which is why `/oauth2/authorize` could not answer an anonymous browser at all, and why `prompt`, `max_age` and `id_token_hint` were unreachable rather than merely unimplemented. A cookie that travels further is exposed to more: a plaintext hop on a request the user never typed, a hidden cross-site iframe probing whether a session exists, and a client that never opted into browser sign-on whose authorization request now arrives with a session attached.

> `HttpOnly; Secure; SameSite=Lax; Path=/oauth2/authorize`, `Max-Age` equal to the session's; minted at `create_session_and_tokens`, the choke point every browser sign-in funnels through, and only its SHA-256 is stored (256 CSPRNG bits; the schema-v56 index is deliberately not UNIQUE because the column is unset on almost every row, and the ambiguity a unique index would have caught is refused in `get_by_browser_token_hash`, which returns no principal rather than the first of two rows). `Secure` is **unconditional** — unlike the three Strict cookies this one does not follow `AuthConfig::cookie_secure` (D-18), because RFC 6749 §3.1 requires TLS at the authorization endpoint regardless and browsers treat loopback origins as trustworthy, so the local-development case costs nothing; a plaintext login hop to a non-loopback host fails into `login_required`, whose description names the cause (CodeQL 557). `Lax` is load-bearing and not a candidate for fixing: it is sent on a top-level navigation and not inside a frame, so the relying-party redirect works and hidden-iframe probing fails closed — cross-site silent renew is the plan's §9 recorded decision. The cookie is read only for a client registered `browser_sso: true`, and the client is loaded *before* the cookie is read, because the registration decides whether the cookie is consulted; with the default `false` the anonymous answer is the same `401` object it always was, pinned byte for byte with and without every new parameter and with a live cookie attached (`t0_1`, `t0_5`). Logout and `end_session` clear it, `clear_op_session_cookie` is built from the setter so the removal is `Secure` too, and refresh copies the digest rather than restamping it. `docs/admin/browser-login-hop.md`; conformance rows 47–59.

**T-238 — `/login?return_to=` becomes an open redirect, or the login hop a redirect loop**  
`/oauth2/authorize (+ consent)` (Process) · Elevation of privilege · High · Mitigated

The login hop sends an anonymous browser to `/login?return_to=…` and back to the authorization endpoint. A `return_to` that accepts a foreign origin is an open redirect on the sign-in page — the page on which a phishing target types a password, on AXIAM's own origin — and a hop that can be re-entered is a loop a misconfiguration or an attacker can drive indefinitely.

> `return_to` is exactly `/oauth2/authorize?` plus a query, and it is validated three times: by the builder, by the deployment-origin resolution (`require_deployment_spa_origin`, the same rule the SSO handoff uses rather than a second one), and by the SPA before it navigates. A foreign origin, a scheme-relative `//evil.example`, its backslash spellings, path traversal and any other same-origin path are each refused. Every login redirect carries `axiam_login_hop=1` inside its `return_to`, and a request that *arrives* with the marker is never redirected again — it is answered `login_required` — so a chain is at most two authorization requests and one sign-in page whatever goes wrong in between. A browser presenting an OP cookie that resolves to no live session gets `reauth` mode, with the stale cookie cleared on the way out. A PAR `request_uri` that expired during the hop answers `invalid_request_uri` with a description saying so, and only on a return leg, so an ordinary request with a dead handle keeps today's `invalid_request`. The consent screen (W7) carries its own `axiam_consent_hop` marker, because a request carrying both `prompt=consent` and `address` came back from the sign-in page with the login marker, which the consent rule read as "asked and declined" — `access_denied` for somebody never shown the question (row 129; a test walks all three legs). **Amended 2026-09-14.** The clause above — an ordinary request with a dead handle keeps `invalid_request` — no longer describes the endpoint. A handle that is already unusable is now refused *before* the hop, by a read that does not spend it, and the refusal reaches the relying party as `invalid_request_uri` whenever the request named a registered `redirect_uri` — on the return leg exactly as before it (T-270).

**T-239 — A relying party is told it received a freshness or assurance guarantee it did not get**  
`/oauth2/authorize (+ consent)` (Process) · Tampering · High · Mitigated

OpenID Connect Core §3.1.2.1 lets a relying party ask for five things that change what a token *means*: `prompt=none`, `prompt=login`, `max_age`, `acr_values` / `claims.id_token.acr` and `id_token_hint`. Until W4 AXIAM accepted all five and acted on none. That is a conformant answer to nothing: a relying party that sent `max_age=60` and received a code minted from a week-old login had been told a freshness guarantee it did not get, and could not tell. On the assurance side the classic deception is to copy `acr_values[0]` into the `acr` claim, which no reviewer reliably notices.

> A per-client `authn_request_params: ignore | honour`, default `ignore` (schema v54; pre-v54 rows decode to `ignore`, an unknown stored value fails closed the way `decode_profile` does). On the honour lane a relying party gets the property it asked for or is told it cannot have it — never a token that quietly does not have it. The ACR echo is designed out at the type level: `acr::acr_for(amr: &[Amr]) -> Acr` takes the session's evidence and nothing else, so there is no parameter through which the request could reach it, and `report_acr` can only return a requested value the achieved class already satisfies — the strongest thing a relying party achieves by asking is to select among true statements; the vocabulary is the two AXIAM URNs and is not operator-configurable, because an operator who could configure the string could configure it to say `mfa` for a password login. `max_age` is `elapsed >= max_age` with no leeway in the relying party's disfavour, and `max_age=0` always demands a reauthentication whose return leg answers `login_required`. `prompt=none` from an anonymous browser is refused, and on a return leg it is refused however good the session is, so silent authentication over PAR sees `invalid_request_uri` or `login_required` and never a token minted behind an interaction it forbade. `prompt=consent` was treated as `login` until W7 gave it a consent screen — ignoring it is the silent downgrade the lane exists to prevent. A `fapi2` client is refused the five security-bearing parameters at registration and at request time (W1 rules 1–3), and a `fapi2` row edited to `honour` is refused with `tracing::error!`; `claims` left that list once §5.5 was implemented, because the list is the parameters AXIAM *drops*, and dropping is what made it dangerous. Request objects are rejected rather than implemented — `request` answers `request_not_supported`, a `request_uri` that is not a PAR handle `request_uri_not_supported`, both redirected only to a registered `redirect_uri` (G12; plan §9 says why nobody should "helpfully" implement them later). Invariant 4 — no client registered today changes behaviour — is proved by the `P1`/`P2` twins and by an I4 twin on every negative test. `docs/admin/oidc-authn-parameters.md`; conformance rows 23–39 and 60–80.

**T-255 — An authorization error is delivered to the wrong place: redirected to an unregistered target, rendered as JSON to a person, or echoing attacker-chosen parameters on AXIAM's origin**  
`/oauth2/authorize (+ consent)` (Process) · Tampering · Medium · Mitigated

RFC 6749 §4.1.2.1 draws the line at whether the server can trust where it would be sending the browser. It MUST NOT redirect when the `redirect_uri` is missing or does not match a registered one — the open-redirect case, where a direct answer is right — and it MUST deliver the error by redirect, with `state`, when `client_id` names a real client and the `redirect_uri` is one it registered, or the relying party waits on a response that never comes (the suite stalled its whole plan at module 2 of 35 on `oidcc-response-type-missing`). AXIAM answered the second case with a JSON body in the browser window, and answered the first with JSON too — informing a developer, and not the resource owner §4.1.2.1 says SHOULD be informed. An HTML page on AXIAM's own origin is then a reflected-content sink for `state`, `redirect_uri` and `request_uri`, and an `error_description` carrying `§` or an em dash violates §5.2's `NQSCHAR` grammar.

> 0853e20: a known client with a registered `redirect_uri` receives the error by redirect with `state` echoed. The lookup uses `user.tenant_id`, never the query's `tenant_id` — a lookup that decides where a browser is sent is the worst place to reintroduce a tenant-crossing primitive — and the description stops naming `redirect_uri`, which was misleading in exactly the case that matters. dfcef2d and 13050d9: the direct-answer arms — all seven, including the three inside `resolve_authorize_principal` that build their own responses and were found by probing the live endpoint as a browser after the integration test had passed by authenticating first — render a page only on an explicit `Accept: text/html`; a missing header, `*/*` and `application/json` keep the JSON byte for byte, asserted directly, because content negotiation is only safe if the un-negotiated answer is untouched. The page renders the same `error` and `error_description` the JSON carries, escaped, and nothing else: no `state`, no `redirect_uri`, no `request_uri`, the rule `logged_out_page` already states applied to the endpoint that actually receives attacker-chosen parameters. The `build_error_redirect` branches beside them are untouched. 52ded73: `OAuth2Error::error_description()` — the one renderer every OAuth2 error passes through, and `dpop_error_response` routed through it — transliterates to `NQSCHAR` rather than stripping (`§` to "section ", an em dash to a hyphen, anything else to a visible `?`), because a silently deleted character is an invisible change of meaning; enforced in one place rather than at hundreds of call sites written in a house style that cites specifications with `§`. The character-set test walks U+0000..U+00FF in both directions. The token, PAR and introspection endpoints are API endpoints and keep one JSON renderer. 2026-09-14: the same delivery rule now covers the two refusals that used to be decided only after a sign-in — a missing or unsupported `response_type` on a request without a `request_uri`, and a `request_uri` that is unknown, expired, spent or another client's — so `oidcc-response-type-missing` no longer stalls a plan at a sign-in page: redirected only to a registered `redirect_uri`, compared exactly, rendered in place otherwise, and the page still echoes nothing (T-270).

**T-256 — Inline parameters beside a PAR `request_uri` are read, or a pushed `request_uri` is accepted**  
`/oauth2/authorize (+ consent)` (Process) · Tampering · Medium · Mitigated

RFC 9101 §5 lets a client duplicate the pushed parameters in the query string "for backward compatibility", and §6.3 says the server MUST only use the parameters in the request object even when the same parameter is provided in the query. AXIAM refused the combination — citing RFC 9126 §4, which says nothing of the sort — and failed every FAPI 2.0 authorization module. The security argument the refusal rested on, that merging is exactly where parameter confusion lives, is sound; but confusion needs the inline value to be *read*, and ignoring it satisfies the argument as well as refusing does. Beside it, PAR accepted a pushed `request_uri` (RFC 9126 §2.1-2) because the parameter was not modelled and serde dropped it, answering `201` to a request the specification says must be rejected.

> Every field comes from the pushed copy and nothing reads the inline value — `state` and `nonce` always did, and the nine OIDC authentication-request parameters, `dpop_jkt` (T-251) and the user's own refusal (T-259) follow the same rule, because a FAPI client sends `client_id` and `request_uri` and may send nothing else. `has_inline_params` is deleted rather than left unused, with a tombstone saying why the rule it encoded was not the one the specifications state, and the test that asserted the defect is inverted rather than supplemented, so the suite cannot claim both behaviours. A pushed `request_uri` is refused before client authentication: the refusal names a parameter the caller sent rather than anything about the client, so it is not an oracle. PAR errors are JSON at the route (RFC 9126 §2.3 makes the PAR error response the token endpoint's), since actix's form-deserialisation error fired before the handler was reached and a client cannot act on prose. Conformance rows 141–154. 2026-09-14, one clause: an inline `redirect_uri` beside a `request_uri` is still never read for authorization. It is read for exactly one thing — deciding where a *refusal* of that handle may be delivered — and only after the client's registration has vouched for it, which is RFC 6749 §4.1.2.1's own rule and the same one the `prompt=none` arm applies (T-270).

**T-257 — `login_hint` becomes an account-existence oracle, or `ui_locales` / `display` an injection into the sign-in page**  
`/oauth2/authorize (+ consent)` (Process) · Information disclosure · Medium · Mitigated

Wave W5 lets four cosmetic parameters reach the sign-in page. A `login_hint` that is looked up answers differently for an existing and a non-existing account, on an unauthenticated endpoint; a locale or display value forwarded raw is attacker-chosen text rendered on AXIAM's own origin; and `claims_locales` sits one parameter name away from `ui_locales`, which is how two adjacent names get confused.

> `login_hint` is carried verbatim and **nothing looks it up, on any path** — uniformity with respect to whether the hinted account exists is a property of there being no branch, not of two branches kept equal (T5.1 asserts whole-response equality for an existing and a non-existing hint). `ui_locales` is matched on the server by RFC 4647 §3.4 lookup, per requested tag in the relying party's order, against the five locales AXIAM ships, so the raw value never crosses into the SPA and T6.2 is true by construction rather than by escaping; `display` is allow-listed to the four OIDC Core values and anything else is dropped; `claims_locales` is accepted and ignored, and `Cosmetic::from_params` — the single call site of `select_ui_locale` — takes no `claims_locales` argument at all, which is the guard against the two being confused. The four decide no `Outcome` and never enter the honour evaluation; they are never *refused* on a `fapi2` row, since relying-party libraries send `login_hint` by reflex, but no `/login?login_hint=` is ever built for one. A CI gate fails when the server's allow-list and the SPA's locale bundles drift, and the SPA's typed catalogue makes a missing translation a compile error rather than a runtime fallback. `default_locale` at the settings API is refused for a tag this build does not ship. Conformance rows 81–89.

**T-270 — A dead `request_uri` is discovered only after a sign-in, or the early read that prevents it spends the handle, authorizes from it, or reports the refusal somewhere the client never registered**  
`/oauth2/authorize (+ consent)` (Process) · Tampering · High · Mitigated

`/oauth2/authorize` could not look at a pushed request while answering an anonymous browser: the handle is single-use and is spent in the handler, after a principal exists. So a browser presenting a `request_uri` that had already been used, had expired, or had been issued to a different client was sent to `/login`, the person typed a password, and the request was refused on the return leg — which the OpenID Foundation suite reports as a screenshot of a sign-in page where an error about an invalid `request_uri` was expected (`fapi2-security-profile-final-par-attempt-reuse-request_uri`, `-attempt-to-use-expired-request_uri`, `-attempt-to-use-request_uri-for-different-client`). The same shape held for a request with no `request_uri` and a missing or unsupported `response_type` (`oidcc-response-type-missing`). Refusing earlier creates its own ways to get it wrong. An early check that *consumed* the handle would spend it on a refusal path and break the case the specification requires — the same `request_uri` presented twice before the first authorization completes must still reach the sign-in page — and one that returned the pushed parameters would let a caller authorize from a handle it never consumed, which is the single-use guarantee T-163 exists for. And a refusal delivered by redirect is an open redirect unless the target was registered: the pushed copy's own `redirect_uri` is exactly what could not be read.

> 2026-09-14 (616b731, ad1cb67). `ParService::peek` answers the three questions `consume` answers — is this a PAR handle at all, does an unexpired, unconsumed row exist for it, does it belong to this client — with the same refusals in the same order, and returns `()`: nothing is cached, marked or carried forward, and the authoritative single-use decision stays in `consume`, in the handler, in one statement. `PushedAuthRequestRepository::find_unconsumed` is `consume`'s `WHERE` clause with the write removed — no transaction, because there is nothing to serialise, and a read that raced a concurrent redemption is answered by that redemption failing. The endpoint runs it for an anonymous browser only after the client has been resolved and found to opt into the login hop, and only for a genuine PAR handle: a request object by value or by reference keeps the OIDC Core §3.1.2.6 code `classify_request_object` owns. `response_type` is decided first, without touching the datastore, and only when no `request_uri` is present, because with PAR the pushed value is authoritative (RFC 9126 §4). Both refusals are delivered exactly as the `prompt=none` arm of T-255 delivers its own: by redirect only to a `redirect_uri` this client registered, compared exactly, with the request's own `state`, and answered in place otherwise — as `error=invalid_request_uri` (OIDC Core §3.1.2.6), the code a relying party can act on by pushing again, while a handle issued to a *different* client keeps `invalid_request`, because a client spending someone else's handle is not a handle that is gone, and an audit trail that cannot tell the two apart is worth less. The post-login return leg was brought to the same rule (`refuse_request_uri_to_client`: one registration read, on a refusal path only, keyed by `user.tenant_id` and never the query's). What the peek costs, stated: one indexed datastore read per anonymous authorization request that carries a `request_uri`, on a route under the per-IP rate limit, keyed by a 256-bit CSPRNG handle that cannot be guessed — so the wrong-client refusal, distinguishable by design, is not an oracle anyone can drive. Tests: `peek` is proved never to call `consume` and never to touch the client registration (doubles that panic if it does); seven handler tests walk a spent, an expired and a wrong-client handle before the hop, a live handle presented twice, a request object by reference, and a dead handle with and without a registered target; two repository tests pin `find_unconsumed` reading without spending and ignoring an expired row. Measured per module with `run-some.sh` against the OpenID Foundation suite, the three PAR modules and `oidcc-response-type-missing` moved from `REVIEW` to `PASSED`; no full plan has been re-swept, so the published receipts remain the 2026-09-11 ones. Contract 1.46 §26.2 rule 3 records both forms of the refusal; no SDK changes, since rule 2's authorization URL carries no `redirect_uri` and never reaches the redirected form.

**T-240 — A refresh or a replayed upstream SSO session is dated as a fresh authentication**  
`/oauth2/token (code, refresh, client credentials)` (Process) · Tampering · Medium · Mitigated

`auth_time` says when the end user authenticated, and `amr` how. `session.created_at` cannot stand in for it because refresh rotation writes a new session row on every refresh, and a code's evidence cannot be looked up at redemption because by then the session it came from may be gone. A federated login dated by AXIAM's clock records a provider session established hours ago as having just happened; a refreshed ID token that restamps `auth_time` violates OIDC Core §12.2; and an evidence record whose absence reads as *stronger* would upgrade every pre-migration session.

> Wave W2 (schema v55): `session.authenticated_at` and `session.amr` — a closed RFC 8176 enum rather than a free string, so a typo at one of the five login call sites is found by the compiler rather than by a relying party, and unknown stored values decode to nothing. The authentication event is recorded at the one choke point, `create_session_and_tokens`, whose callers pass what they actually verified: `pwd`, `pwd otp mfa`, `pwd hwk mfa`, `hwk user` (usernameless passkey, which requires user verification unconditionally) or `fed`. Federated logins are dated by the upstream provider — OIDC `auth_time`, SAML `AuthnInstant`, carried across the 60-second handoff hop on the handoff row — and fall back to the moment AXIAM verified the assertion only when the provider asserted no instant. Refresh rotation **copies** the evidence rather than restamping it; the authorization code snapshots it at issuance (a snapshot, not a join, because rotation replaces the row). Every column is optional with no backfill, and the decode path leans strict: an absent `authenticated_at` reads as `created_at`, an absent `amr` as the empty list, so a pre-migration row can be judged staler and weaker than it was, never fresher and stronger. The claims are emitted only for a client on the honour lane (`fapi::honours_authn_params`) and for nobody else — pinned for every `ignore` client and every `fapi2` row at either setting — and a refreshed ID token reports the class the session proves. `session_evidence_rotation_test` (two rotations, the event never moves); conformance rows 40–46.

**T-251 — An authorization code is redeemed by a DPoP key other than the one it was pinned to**  
`/oauth2/token (code, refresh, client credentials)` (Process) · Spoofing · High · Mitigated

RFC 9449 §10 lets the authorization request bind the grant to a key (`dpop_jkt`), so a code observed in transit cannot be redeemed by a thief presenting a proof from a key of their own. AXIAM never recorded which key an authorization was pinned to, so there was nothing for the token endpoint to compare a proof against: the happy-path FAPI modules passed by accident, and `ensure-mismatched-dpop-jkt-fails` received a `201` from a PAR endpoint dropping both carriers on the floor.

> 246c163. §10.1 requires an authorization server supporting both PAR and DPoP to accept two carriers — `dpop_jkt` in the PAR body or on a plain request, and a `DPoP` header on the PAR request, whose key thumbprint the server "MUST further behave as if" had been sent as `dpop_jkt` — and the PAR endpoint resolves them into one binding under client authentication, refusing a contradiction with `invalid_dpop_proof`. The value rides the pushed parameters to the authorization endpoint, read from the pushed copy and never a query-string copy for the same reason `state` and `nonce` are (T-256), and is snapshotted onto the code (schema v58, one optional column, no backfill). At redemption a code whose bound key the request has not proven possession of is refused `invalid_grant`, not `invalid_dpop_proof`: the proof is perfectly valid — signature, `htm`, `htu` and freshness all check out — and what fails is the grant, bound to a key this caller cannot demonstrate; the other code would send an honest client debugging its proof generation over a code it should simply push again. The check sits beside PKCE, *before* the code is consumed, on PKCE's own argument: a caller who cannot satisfy it must not be able to burn a valid code by failing it deliberately. `verify_dpop_header` is extracted so PAR runs the §4.3 proof check from one copy. Four of the nine tests state the non-regression claim directly: a code that carries no binding, and a push that used neither carrier, are answered exactly as before — the property that matters for every client registered today, none of which sends the parameter.

**T-252 — The strong client-authentication methods were registrable and unusable, inviting a fall-back to a shared secret**  
`/oauth2/token (code, refresh, client credentials)` (Process) · Spoofing · High · Mitigated

Three defects, each a strong method that no conformant request could use. `tls_client_auth` compared the registered `tls_client_auth_subject_dn` only against `x509_parser`'s rendering of the subject, and the operator guide's `openssl x509 -nameopt rfc2253` form never equals it — RFC 2253 emits the RDNs in reverse of their encoded order, and the separators differ — so every client onboarded as documented authenticated nothing (89 FAPI module failures, all at PAR). `private_key_jwt` was implemented and wired to nothing: `JwksAssertionVerifier` was constructed nowhere, so no client in any deployment could use one of FAPI 2.0's two client-authentication families (all 56 modules of that lane). And a request carrying only a `client_assertion` was refused "client_id is required", though RFC 7521 §4.2 makes it optional and OIDC Core §9 makes the assertion's `sub` the identifier. A strong method that cannot work is pressure toward the shared secret that can — and a test that compared the server against its own rendering passed throughout.

> The DN exact match is kept — the comment that "a normalising comparison is exactly where DN-matching CVEs live" stands, so nothing normalises the registered value. Instead the server derives **both** correct renderings of the name from the certificate, and the registered string must equal one of them exactly: no case folding, no whitespace stripping, no structural comparison. The RFC 2253 form is built by rendering each RDN individually and joining the reversed list on `,` — reversing the formatted full string would have split a value containing an escaped comma, the very failure the comment warns about — and the new test uses a two-RDN certificate, because a single-RDN name renders identically both ways and cannot observe an ordering difference at all. The assertion verifier is wired with the **federation** JWKS cache, deliberately and not one of its own: a client's `jwks_uri` is the same SEC-054 SSRF surface whichever feature asked for it, and a second cache would be a second place for a guard to go missing (T-173). Wiring alone would have made three passing modules fail, because FAPI 2.0 §5.3.2.1 narrows RFC 7523's audience rule to the issuer identifier, as a string, only; `verify_client_assertion` takes an `AudiencePolicy` — `IssuerStringOnly` for a `fapi2` client, refusing an array even when it *contains* the issuer, `AnyOf` (issuer or token-endpoint URL, string or array) for everyone else, since RFC 7523 §3 and OIDC Core §9 disagree and refusing either is an interop failure with no security content. `client_id` is optional beside an assertion, and `unverified_client_id` reads `sub` from a JWT nobody has checked for the one thing that is safe: the row it names is loaded and the assertion is then verified against *that* row's registered key, so naming somebody else only picks the key the forgery will be checked against — a routing hint, never a credential; the pre-lookup credential guard three grants copied now lives in one place, `TokenRequestContext::carries_no_client_credential`. A missing DPoP proof is `invalid_dpop_proof` with `400` (RFC 9449 §5), not `invalid_client` with `401`: the client authenticated, what was missing was the proof; the certificate branch keeps `invalid_client`. Every test pins the operator-facing contract rather than the server's own rendering.

**T-253 — `client_secret_basic`: the header reaches a log, the RFC 6749 §2.3.1 decoding is wrong, or a client gets two ways in**  
`/oauth2/token (code, refresh, client credentials)` (Process) · Spoofing · Medium · Mitigated

Wave W8 (G9) adds HTTP Basic client authentication as a fifth registrable `token_endpoint_auth_method` — escalated as decision A of the Basic OP plan and decided yes by the maintainer on 2026-09-07, because 37 of the 38 modules of the OpenID Foundation's Basic OP plan use it and there is no badge without it. Three failure modes travel with it: the classic omission of the form-urlencode step in §2.3.1's encoding, invisible against server-generated secrets; an `Authorization` header, which is the channel intermediaries routinely log; and a second channel carrying the same credential, which is an OR an attacker may pick from (SEC-093).

> The decoding is base64, split on the **first** `:`, then `application/x-www-form-urlencoded`-decode each half, with the fixture secret `p%a+s:s` so the last step cannot be skipped unnoticed; it is hand-written in `axiam-oauth2::client_secret_basic` rather than routed through `url::form_urlencoded::parse`, which also splits on `&` and `=`. `Authorization` reaches no log: asserted at TRACE over a successful request, a rejected one and one refused at the edge, grepping for the secret, its encoding, the base64 blob and the header value; `BasicCredentials` hand-writes a redacting `Debug`, and a second test pins that the request-logging layer is `TracingLogger::default()`, which has no header allow-list to add the header to. The registration decides which channel carries the credential, never the request: a body `client_secret` on a `client_secret_basic` client is `invalid_request`, ordered *after* the header credential verifies so that SEC-086's undecidability of client existence survives; an `Authorization: Basic` header on a `client_secret_post` client is ignored and logged at `warn`, never a second way in. `client_id` may arrive in the header alone, and a disagreeing pair is refused before the client lookup so no existence oracle is created; the RFC 6749 §5.2 challenge is applied by wrapping the four handlers rather than at their ~35 error sites. The FAPI gate needed no new code — `validate_registration` and `enforce_token_request` ask `is_strong()` rather than enumerating variants — so a `fapi2` client is refused it exactly as it is refused `client_secret_post`. **No SDK sends it**: `sdks/CONTRACT.md` §5 rule 3 keeps its MUST NOT verbatim (contract 1.41, T-266). Residual, and where it lands: the header is protected from AXIAM's own logs and nothing in front of AXIAM — `docs/admin/fapi2-profile.md` says to audit what the ingress logs before enabling it, and the broader class of a long-lived secret in the wrong place is T-146.

**T-254 — A leaked refresh token replayed inside the rotation grace window forks the session undetected**  
`/oauth2/token (code, refresh, client credentials)` (Process) · Spoofing · Medium · Mitigated

FAPI 2.0 Security Profile §5.3.2.1-9 requires an authorization server that rotates refresh tokens to keep accepting the previous one for a period after issuing its successor — the only recovery a client has from a rotation response lost in transit, since under immediate revocation it holds a token the server has destroyed and has not been given the replacement. Commit 065f37c implemented that as a **supersede** — the old token's `expires_at` brought forward to a 60-second grace instant — and applied it to every client on every profile. Inside that window a second presentation was answered `200` and rotated again, so a refresh token leaked at the moment of a legitimate rotation yielded a second live chain, and nothing distinguished the thief's use from the honest retry. The profile that requires the window sender-constrains every token; the `standard` profile, which does not, had been given the same window.

> Mitigated by the maintainer's decision of 2026-09-12, which is two things and needed both. **The window is now a `fapi2` behaviour.** `axiam_oauth2::fapi::refresh_rotation_grace_secs` is the gate — the same registration-decides mechanism as `auth_code_lifetime_secs`, not a second one — and `TokenService::refresh` picks a retirement lane from it: `supersede` for a `fapi2` client, `revoke_rotated` for every other, which is the pre-065f37c behaviour (`invalid_grant`, "already consumed", on a second presentation). What remains on `fapi2` is a 60-second window in which the previous token is redeemable by a client that also holds the private key every token on that profile is bound to. **And a replay is now marked whatever the window.** Both lanes stamp `rotated_at` in the same statement that retires the row (schema v60, additive, backfilling nothing), so a presentation of a rotated token is distinguishable from an ordinary stale credential — `find_rotated` answers `None` for one revoked at logout. Every such presentation, accepted under the grace or refused, increments a per-outcome counter on the session the token names and appends an `oauth2.refresh_token_replayed` audit row naming the client, its profile, the session and the disposition, never the token or its digest; `GET /api/v1/users/{user_id}/sessions` serves the derived verdict and the admin UI renders "FAPI grace retry" and "Replay refused" as two visibly different badges. The single-use race is untouched: both lanes keep `revoked = false AND expires_at > time::now()` in the WHERE, so the loser of two concurrent rotations still gets `NotFound`. A password or MFA reset still revokes the whole family through `revoke_all_for_user`, and T-249's `sid` extends that to the access tokens in flight. Pinned by the `t254_*` tests in `axiam-oauth2/tests/token_service.rs` and `fapi.rs`, by `refresh_token_rotation_retires_old_on_a_standard_client` and `a_refused_refresh_replay_is_audited` in `oauth2_flow_test.rs`, and by the invariant-4 twin each of them carries.

**T-241 — A postal address or telephone number is released by naming the claim, from a token issued before consent was withdrawn, or inside an ID token**  
`OIDC /userinfo, /jwks, discovery` (Process) · Information disclosure · High · Mitigated

OIDC Core §5.4's `address` and `phone` scopes release data AXIAM holds for no purpose of its own — nothing authenticates against them, nothing is sent to them — so they exist only to be released to a relying party the end user has agreed to. Three ways past a consent ceremony: §5.5's `claims` parameter naming the claim directly; a release decision taken once at authorization that outlives a withdrawal for the access token's fifteen minutes and the refresh's thirty days; and the ID token, a long-lived artefact relying parties log and cache. A fourth is a client on a profile that collects no consent record at all.

> X7 G8 / wave W7: four gates, each closed by a different party — the **organization** enabled `sensitive_scopes_enabled` (off by default, and the settings model's only *disable*-only field: a tenant may refuse a release its organization allows and never authorise one it forbade); the **operator** registered the scope on the client, checked on create and on the merged update path because a gate that only runs on create is a gate with a PATCH around it; the **end user** consented, per client and per exact scope set; and the client is not on the `fapi2` profile, refused at registration, at the authorization endpoint (M8) and at UserInfo (M10) — even against a hand-written consent record the API would have refused to create. All four are re-asked **at every UserInfo call**, so withdrawal is effective on the relying party's next request with the token it already holds (T8.4 uses the byte-identical token before and after). Claims are returned from UserInfo only and never in the ID token (T8.3 decodes the ID token a relying party actually receives). `claims_request::RELEASABLE` cannot unlock `phone_number`, `phone_number_verified` or `address` for anybody, FAPI or not: the filter runs at the authorization endpoint and is asserted again at UserInfo against a token minted as though it had been bypassed, because that endpoint is the one that would leak. A release is audited by claim **name** and never by value, since the audit log is append-only and is itself exported under Art. 15 (T8.6). The Art. 7 self-service surface is new — `GET /api/v1/account/consents`, `POST`/`DELETE …/oidc-scopes` — withdrawal is one call with no confirmation and no grace, and it is namespaced `oidc_scope_release:` so it can never reach a `terms_of_service` row. A token naming no relying party — every token issued before this wave — releases nothing, and nothing registered earlier changes behaviour, structurally: the scopes were unregistrable. The requested claims now ride the refresh token too (R-2, schema v61): the code exchange writes the list onto the refresh token it issues, rotation copies it onto each successor exactly as it copies `session_id`, and the refreshed access token asserts the same `axiam_requested_claims` the code-exchanged one did — so a refreshing client no longer loses consented claims fifteen minutes after the consent was given, which it had to start a whole new authorization to recover from. This carries a **request**, never a release decision: `claims_request::RELEASABLE` still runs only at the authorization endpoint, the refresh path copies and never widens (asserted against a hand-built row naming `phone_number` and `address`, which the endpoint above still refuses), and all four gates are re-asked at every UserInfo call as before. Additive with no backfill: a refresh token issued before v61 decodes to no claims and mints exactly the token it minted before. `docs/compliance/gdpr-compliance.md` §3.1; conformance rows 104–129.

**T-242 — The ID token carries identifiers nobody asked for, and travels further than the relying party**  
`OIDC /userinfo, /jwks, discovery` (Process) · Information disclosure · Medium · Mitigated

The ID token carried `tenant_id`, `org_id` and — under `scope=email` — `email`. The OpenID Foundation suite objects by name in both lanes and states the consequence rather than the rule (OIDC Core §5.4): an ID token is often forwarded as proof of an authentication event, so anything in it travels further than the relying party that asked for it. The reverse defect sat beside it — UserInfo withheld `email_verified`, `name`, `given_name` and `family_name`, which AXIAM held all along.

> The three claims left the ID token (065f37c). `sdks/CONTRACT.md` binds both identifiers to two other places that do not move — an SDK resolves them from the access-token claims returned by login, and `UserInfo { sub, tenant_id, org_id, … }` still carries both — so the ID token was a third copy nothing was specified to read; `preferred_username` deliberately stays, which §5.4 permits. The member list is pinned exactly (`an_id_token_with_no_evidence_has_exactly_todays_claim_set`, `t2_6_…`), so `auth_time`, `acr` or `amr` appearing for an `ignore` client still fails. UserInfo now emits what the OP can assert and omits what it cannot rather than inventing it (§5.3.2): `email_verified` from `email_verified_at`, the SCIM-provisioned names, and since c4bdefd the full §5.1 `profile` set read SCIM-first with `metadata.oidc` as the fallback (T-58).

**T-243 — A UserInfo POST authenticated by a cookie answers a cross-site form, or logs the token it carried**  
`OIDC /userinfo, /jwks, discovery` (Process) · Information disclosure · Medium · Mitigated

OIDC Core §5.3 requires UserInfo to accept POST, and RFC 6750 §2.2 lets the access token travel in the form body. `/oauth2` carries no CSRF middleware and the cookie is read before the header, so a route that accepted a cookie-authenticated cross-site form POST would return personal data to any page that submitted one; a form field is a place a token gets logged; and a token accepted from the query string is a credential read out of a URL.

> Wave W6 (G10): `/oauth2/userinfo` is one resource with two routes, deliberately without the scope's rate-limit wraps — every wrapped endpoint there is unauthenticated and allocates or terminates state, UserInfo does neither, and a limiter would change what GET does under load. The token is accepted from the `Authorization` header or, on POST only, from an `access_token` form field; a request carrying more than one credential is refused `400 invalid_request` and the refusal reads neither of them; an `access_token` query parameter is never read on either method (RFC 6750 §2.3 — refusing it would mean reading a credential out of a URL first). A cross-site cookie POST fails closed because `axiam_access` is `SameSite=Strict`, and since that is a property of the cookie the test pins the attribute and then asserts that a same-site cookie POST *does* authenticate, so the pin cannot pass against a route that stopped reading the cookie. `UserInfoPostForm` hand-writes a redacting `Debug`, and a TRACE capture over a successful and a failed POST asserts that neither the token nor its signature segment appears. GET is unchanged as a property of the routing table — the POST handler resolves the carrier and delegates to the body GET calls, `AuthenticatedUser`'s extractor is untouched, and whole-response equality between the two is asserted. DPoP needs no method-specific branch: `htm` is built from the request method, so a proof minted for GET is refused on POST; a certificate-bound token presented without a certificate is refused on POST identically to GET. `POST /oauth2/authorize` (G11) is declined and the reason recorded with a revisit condition. Conformance rows 90–103.

**T-244 — Tenant-scoped discovery becomes a tenant-enumeration oracle, or a default tenant becomes a handler fallback**  
`OIDC /userinfo, /jwks, discovery` (Process) · Information disclosure · Medium · Mitigated

The discovery document advertised endpoints that could not be used at the URLs it advertised: every endpoint that authenticates a client takes a required `?tenant_id=`, `/oauth2/authorize` needs one for any browser arriving from a relying party, and the document published all of them bare — so no third-party discovery-driven client could complete a flow against AXIAM, which is the problem discovery exists to solve. Each of the two fixes opens a door of its own: a document that varies by tenant can be probed for which tenants exist, and a "default tenant" applied at the endpoint would silently give an unparameterised request a tenant on a multi-tenant authorization server where the tenant *is* the isolation boundary.

> Discovery takes an optional `tenant_id`. A caller that omits it receives exactly the document it received before; an unknown tenant is answered identically to a known one except for the single caller-supplied value the document now echoes — asserted by normalising that one value away and requiring the two documents to match exactly, so a leak anywhere else still fails — and the sensitive scopes and their claims are advertised only for a tenant that has them enabled. The endpoint URLs carry the tenant they describe (RFC 6749 §3.1 and §3.2 allow a query component and require clients to retain it), from the caller's `tenant_id`, else from `AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID`. That default **states a fact in a document; it is not a fallback in a handler**: no endpoint's behaviour changed, a request arriving without `tenant_id` is refused exactly as before, and a deployment that sets nothing serves the document it served before, with no endpoint gaining a query string (`a_document_that_names_no_tenant_carries_no_query_string`). `userinfo_endpoint`, `jwks_uri` and `issuer` stay bare — UserInfo resolves its tenant from the token, the JWKS is deployment-wide, and an `issuer` carrying a query would stop matching every token's `iss`. An unparseable default is treated as unset, deliberately the opposite of the mTLS alias's fail-closed refusal (T-245): a missing tenant only fails to help a client, while a bad alias actively misdirects one. That choice stands and the silence around it does not (R-3, 2026-09-12): one `WARN` at boot, beside the other posture lines, names the variable and says what will happen — the document served is the one served with the variable unset, and no endpoint URL carries a tenant. It describes the value's **shape**, its length and whether its characters could belong to a UUID at all, and never the value, because a variable this code cannot prove holds a tenant id is one it cannot prove is safe to print; and it is never logged on the request path, where the accessor runs per discovery request and a warning would be a log flood any anonymous caller could drive. The document is unchanged in every configuration, asserted byte for byte over the whole serialisation against the unconfigured case (`an_unparseable_default_tenant_serves_the_unconfigured_document`). The same first conformance run found two RFC 8414 members missing that described behaviour AXIAM already had — `code_challenge_methods_supported` and `token_endpoint_auth_signing_alg_values_supported` — and RFC 8414 defines no default for either, so silence read as "unsupported"; the second is derived from `jose::permitted_algorithm_names()` through an exhaustive match, so widening the verifier's list stops compiling until the wire name is spelled (contract 1.42 §21.5).

**T-245 — A misconfigured mTLS alias routes clients to the wrong host, or the front channel is aliased**  
`OIDC /userinfo, /jwks, discovery` (Process) · Tampering · Medium · Mitigated

RFC 8705 §5 `mtls_endpoint_aliases` instructs a conforming client to switch hosts. AXIAM implemented both halves of RFC 8705 and published no §5 metadata, so a deployment terminating mTLS on a separate host — the only shape one TLS listener allows, since it decides whether to request a certificate before it has seen a byte of HTTP — had to pass client configuration out of band. Publishing the member wrongly misdirects every mTLS client; dropping it silently on a bad value routes them to the conventional endpoints, the one outcome the setting exists to prevent, indistinguishably from a deployment that has no mTLS host; and aliasing the front channel makes a browser raise a certificate-chooser dialog most users cannot answer.

> `AXIAM__AUTH__OAUTH2_MTLS_BASE_URL` adds aliases for the six back-channel endpoints — token, userinfo, revocation, introspection, device authorization and PAR — each the top-level endpoint of the same name re-based on the mTLS host through one macro, so the two cannot drift. `authorization_endpoint`, `end_session_endpoint` and `jwks_uri` are deliberately not aliased (the first two authenticate the user and never the client; the third is public key material), and the `issuer` does not move because OIDC Core §2 requires it to equal every token's `iss`, including one minted at an alias. The member is absent by default and absence is correct — a present member instructs a client to switch hosts, so a single-listener deployment must emit none, including one running `client_auth = optional` — and it is omitted rather than serialised as `null`. A configured-but-unusable value, or one carrying a query or fragment, fails the discovery request with `500` rather than quietly dropping the aliases. Since b9232f3 the aliases carry the tenant (T-244): an alias tells an mTLS client it *must* use that URL, so one that omitted the tenant would be strictly worse than no alias. The conformance rig runs exactly this split — an nginx sidecar on the issuer for the front channel, the server's own rustls listener for the back channel — because `axiam_oauth2::mtls` refuses the `X-Client-Certificate` proxy header for OAuth2 client authentication by construction. Contract 1.40 §21.3 rule 2 is the SDK half (T-266).

**T-258 — A registration is edited into a weaker posture: a `fapi2` row set to honour, a sensitive scope on a `fapi2` client, or a scope-only patch that skips the merged validation**  
`Client registration & secret rotation` (Process) · Tampering · Medium · Mitigated

Three per-client switches now share one registration — `profile`, `authn_request_params`, `browser_sso` — plus the sensitive scopes, and a client's posture is what its row says. A `fapi2` row edited to `honour`, a `fapi2` client registered for `address` or `phone`, or a scope-only PATCH validated against the *stored* scope list rather than the one about to be written, would each move a client onto a lane a test proves refused, without any request having been made.

> Wave W1's gates, in `fapi.rs`'s existing two-layer pattern: `FapiRegistrationError::{AuthnParamsOnFapiClient, SensitiveScopesOnFapiClient}` enforced on create **and** on update, at both handler call sites; `touches_security_profile` now covers `scopes`, so a scope-only patch costs the merged read it previously skipped instead of validating against the wrong list; a `fapi2` row somehow on `honour` is refused again at request time with `tracing::error!`. `reject_sensitive_scopes_when_disabled` is the tenant-switch gate, found missing while writing W7's tests — `validate_registration` is a pure function four layers below the settings row — and it runs on create and on the merged update, because a gate that only runs on create is a gate with a PATCH around it. `browser_sso` is permitted on a `fapi2` client by decision (plan §11 D2), and `m7_…` asserts the flag changes nothing about what a request may contain on either profile. The admin API echoes both new fields so an operator can audit the posture from the endpoint; pre-v54 rows decode to today's behaviour; and the `WeakClientAuth` gate asks `is_strong()` rather than enumerating variants, so the fifth authentication method needed no new refusal code to be refused.

**T-250 — A replayed authorization code is refused, but the tokens it already minted keep working**  
`authorization codes (single-use)` (Store) · Tampering · High · Mitigated

RFC 6749 §10.5 asks two things of a code used twice: deny it, and revoke, when possible, every token previously issued on it. The denial half was thorough — single-use across two layers with a redemption nonce (T-54, T-164). The revocation half was absent: `revoke_after_code_replay` ran only when `consume` failed, but `get_by_hash` requires `used = false`, so a replayed code was refused one step earlier and the revocation fired for a race and for nothing else. An access token minted from a replayed code kept working, and the server logged nothing at all across a whole conformance run; both `oidcc-codereuse-30seconds` and FAPI's `attempt-reuse-authorization-code-after-one-second` proved it by presenting the first access token afterwards. FAPI 2.0 §5.3.2.1 additionally caps a code at 60 seconds, and AXIAM issued 600.

> a76161b and 065f37c: `AuthorizationCodeRepository::replayed_session` returns the session for a code that exists and is spent — `used = true` is what makes it a replay rather than a lookup, `client_id` and `redirect_uri` are matched so a caller presenting the wrong pair cannot revoke somebody else's session, and expiry is deliberately *not* filtered, because a replayed code that has since expired still minted tokens. Revocation reaches the session: an AXIAM access token is a stateless JWT, so what can be revoked is the session its `sid` names (T-249), which every resource request already checks. Two costs are stated in the code rather than glossed — the session is the browser session, so revoking it signs the user out of everything it reaches, admin UI included; and a legitimate client retrying after a lost `200` replays a code exactly as an attacker does. The server cannot tell them apart, which is precisely why §10.5's answer is to revoke rather than to guess. Not an oracle: both paths return the same `invalid_grant`, and a hash naming nothing revokes nothing; a replay costs one extra read and one write, distinguishable by timing only to an attacker who already holds a real code. The FAPI lifetime is a per-client cap taken as the minimum of the profile's 60 seconds and the operator's own setting — never a lower global default, which would shorten the window for every existing client to satisfy a profile none of them is on, and never a longer one, because a security profile must not make a deployment less strict.

**T-246 — A sender-constrained token is laundered into a bearer token through the identity cache**  
`Resource-endpoint token validation (cnf, DPoP jti, sid)` (Process) · Spoofing · Critical · Mitigated

The audit middleware validates a JWT's signature and expiry and caches the result as `CachedUserIdentity`. `extract_user` and `extract_principal` then took those claims and returned — never reaching `validate_presented_token`, the only place `enforce_sender_constraint` lives. So on every route behind `AuthenticatedUser`, a certificate-bound or DPoP-bound access token was accepted over a connection that presented no certificate and carried no proof: the binding T-167 and T-175 require every relying party to honour was decorative on AXIAM's own API. It survived because the test that asserts the property could not exhibit the defect — the test app installs no audit middleware, so the cache was always absent and the slow path always taken.

> Found by the OpenID Foundation suite and closed in 065f37c, "one of them a hole". Signature and expiry are facts about the **token** and are worth caching; RFC 8705 §3 and RFC 9449 §7.1 are facts about **this request** — which certificate the connection presented, which proof accompanied it — and no cached answer can stand in for them. Both extractors now go through one `cached_identity` helper that enforces the constraint every time the cache is used, and `CachedUserIdentity` carries the encoded token so the DPoP `ath` binding can still be checked. The new test installs the cache, uses the same token and the same assertion, and keeps an **unbound** token as a control so it cannot pass by having broken the cached path outright. `authenticate_presented_token` (W6) does not consult the cache at all. Recorded Critical rather than High because the whole value of sender constraint rests on the resource server, and here the resource server is AXIAM.

**T-247 — A DPoP proof captured at a resource endpoint is replayed within its freshness window**  
`Resource-endpoint token validation (cnf, DPoP jti, sid)` (Process) · Spoofing · High · Mitigated

T-172's known residual. The token endpoint has recorded proof `jti`s since X5.1; the resource endpoints did not, and `enforce_sender_constraint` documented the gap rather than hiding it — actix extractors are synchronous and the replay store is not — so within the 60-second freshness window a captured proof for that exact method, URI and token would be accepted a second time. The OIDF `dpop-negative-tests` module measured it: "Second use of the same jti" expected 400 or 401 and got 200 (RFC 9449 §11.1).

> The remedy the comment proposed — middleware that can await — was more than needed: the three extractors that matter already return a boxed future, only the helpers were synchronous. So the check splits along the line that was already there: verification stays synchronous, where every caller already is, and leaves the verified proof on the request as a `PendingDpopProof`; recording — the part that is a write — happens in the extractor's async tail through a `DpopReplayGuard`, the same object-safe boxed-future seam `SessionValidator` uses. The guard is a clone of the token endpoint's own `proof_replay_repo` by construction rather than by convention: a proof is single-use, not single-use *per endpoint*, and two stores would let one proof be spent once at each; the `UNIQUE` index decides, with no read-then-write. `AuthenticatedServiceAccount` was wholly synchronous and is now async like the others, because a machine token carries `cnf` exactly as a user token can and leaving it alone would have left every m2m route as the replayable way in. Requests presenting no proof pay nothing. Two tests: one proof sent twice answers 200 then 401, with the good first request there so the test cannot pass against a server that refuses every proof; three fresh proofs from the same key are all served, because "single-use" means that proof, not that key. `htu` is now compared in canonical form as §4.3 asks (T-172).

**T-248 — Replay protection recorded before verification becomes a denial-of-service primitive against the key it protects**  
`Resource-endpoint token validation (cnf, DPoP jti, sid)` (Process) · Denial of service · Medium · Mitigated

Recording a proof's `(jkt, jti)` is a write keyed by the client's public key. Done *before* the signature is verified, anyone could burn arbitrary pairs against a victim's key by sending forged proofs carrying that victim's `jwk` — turning replay protection into a denial-of-service aimed at its beneficiary. And a guard that fails open when the store is unreachable turns a database blip into an unlimited replay window.

> The order is load-bearing and stated in the code: verify first, record after, and only a proof that verified is ever recorded. A proof that verified but whose `jti` cannot be recorded is **refused**, including when no `DpopReplayGuard` is registered at all — the token endpoint's rule ("failing open would turn a database blip into an unlimited replay window") applied at the other end of the same mechanism, at no cost to a deployment that wires the guard and with a `tracing::error!` for one that forgot. The replay row expires exactly at the end of the 60-second freshness window, so the table is bounded by the proof rate rather than growing without limit, and a client is never locked out by its own last request, since the tuple is per proof and not per key.

**T-249 — An OAuth2 access token names no session, so a password or MFA reset cannot revoke it — or UserInfo refuses every token**  
`Resource-endpoint token validation (cnf, DPoP jti, sid)` (Process) · Elevation of privilege · Medium · Mitigated

`check_user_aud_and_parse_jti` derived the session id from the token's `jti`. Every login path honours the contract that a user-flow token's `jti` equals the issuing `session.id`; the OAuth2 paths cannot, because a `jti` must be unique per token (RFC 7519 §4.1.7) and one session issues many, so they minted a random one. `is_session_active` then looked up a session that had never existed and refused, seconds after issuance — UserInfo did not work for any OIDC client at all. The obvious repair, dropping the session check at UserInfo, would have given up the property the check exists for: a password or MFA reset revoking in-flight OAuth2 access tokens.

> 49916b4: the session travels in its own `sid` claim — the name OIDC Core §2 already uses on the ID token — on the authorization-code and refresh paths, and the reader prefers `sid`, falling back to `jti`. The fallback is what makes this need no migration and no flag day: every login-issued token resolves to exactly the session it always did, and not one login path changed. The refresh path carries it too, because a rotated token that dropped `sid` would stop working at UserInfo the moment it replaced the one that had it — a session ending mid-flow fifteen minutes after sign-in. `None` for a token with no session behind it (client credentials, an RPT, a token exchange), which are not weakened by the absence since there is no session to revoke. The access token's `sid` equals the ID token's, and RFC 6749 §10.5's code-replay revocation (T-250) is built on the same claim.


**T-273 — A stranger registers a client whose `redirect_uris` name a host the tenant did not mean to admit, or whose posture it did not mean to grant**  
`/oauth2/register (RFC 7591, unauthenticated)` (Process) · Spoofing · High · Mitigated

`POST /oauth2/register` is the first endpoint in AXIAM that writes for a caller holding no credential. What a caller can write is what decides whether it is a registration endpoint or a way to mint an authorization target of one's own choosing: a `redirect_uris` entry pointing at attacker infrastructure makes every subsequent authorization a code delivered to the attacker, and a self-granted `client_credentials` or token-exchange grant would be a client acting with no user at all.

> Off by default: `dynamic_registration` is `disabled` and the path answers a `403` shaped like every other refusal, so the feature does not leak from the route's existence. When it is on, the request is narrowed on every axis a caller can influence. `redirect_uris` go through the same `validate_redirect_uris` the admin API uses — one answer to "what is a usable redirect URI" in this server — and then through the tenant's `dcr_allowed_redirect_hosts`, a glob whose grammar is deliberately tiny: a literal host, `*` as the **whole** leftmost label, or `*` alone, with the match anchored on a label boundary so `evil-example.com` cannot match a pattern meant for `example.com`, and a `*` anywhere else matching nothing at all. The loopback three are always admitted, because they are what the desktop clients this exists for actually use. `grant_types` is narrowed to `{authorization_code, refresh_token}`, so a self-registered client can never reach `client_credentials` or an exchange grant; `scope` is narrowed to `dcr_allowed_scopes`, which the settings layer refuses to let contain `address` or `phone`; the profile is forced to `standard` and `managed_by` to `dcr`, so I5 holds and `fapi.rs` refuses a FAPI posture on the row twice over; `allowed_resources` is forced to the tenant's own list rather than taken from the request (D3), so an unrelated party cannot name its own audiences; and `software_statement` is refused explicitly rather than ignored. Every registration is audited, and D4 forces the consent hop on the first authorization whatever scopes were asked for, so an end user is always shown a client an administrator did not create. Asserted end to end by `mcp_authorization_test`, whose loopback probes drive seven host spellings against the live authorization endpoint (2026-09-17 review, V1).

**T-272 — A stranger fills the tenant's registration quota and denies registration to legitimate clients until the sweeper runs**  
`/oauth2/register (RFC 7591, unauthenticated)` (Process) · Denial of service · Medium · **Closed** — `c4d9ea2`

`dcr_max_clients` bounds the rows a tenant's self-registration can create, which is the right control for storage and is also, unavoidably, the tenant's availability budget for the feature. In `anonymous` mode an unauthenticated caller can spend all of it: the default ceiling is 20 and the default per-IP limit is 5 a minute, so about four minutes from one address fills it, and a handful of addresses removes the four minutes. The rows then sit until the sweeper reclaims them, which for a client that was never authorized is `created_at + dcr_unused_client_ttl_days` — 30 days by default — because the same TTL serves both "registered and abandoned" and "used once and gone quiet", which are different clocks.

> Bounded, not closed. `initial_access_token` mode is unaffected: a caller holding no handle is refused before the quota is consulted, which is a real reason to prefer that mode and one the operator page does not currently give. `anonymous` mode is opt-in, refused while `external_client_allowed_resources` is empty, and every attempt is rate-limited and audited, so the denial is noisy and attributable to whatever addresses it came from. **Closed** (`c4d9ea2`), filed as MCP-05 ([#471](https://github.com/ilpanich/axiam/issues/471)) against T21.4a. The window is shortened where the exposure is: a `managed_by: dcr` row with no `last_authorized_at`, in a tenant whose effective mode is `anonymous`, is swept an hour after `created_at` rather than after `dcr_unused_client_ttl_days`. One TTL was serving two situations with nothing in common — the 30-day default is sized for "a client somebody uses monthly", and a registration nobody authorized is not that client, which the sweeper could already tell from `last_authorized_at: None`. The second clock does not make the flood more expensive; it turns a month of denial into an hour, at no cost to any client that completes a flow. It does not apply in `initial_access_token` or `disabled` mode, does not touch a row that has been authorized once, and is not switched off by `dcr_unused_client_ttl_days: 0`. The hour is a constant rather than a tenant setting: the fix plan recommended the field and its own cost table was wrong about the price — `OidcPolicy`'s scalars are columns on a `SCHEMAFULL` table, so a fifth DCR number is a migration v66, which the remediation's constraints excluded. The plan's §4 carries the evidence and the promotion checklist; the field remains the right answer and is the maintainer's call.
>
> Two residuals stay recorded. A **per-IP or per-subnet share** of the quota is not done: it needs a ledger per (tenant, address) that no store holds, it is defeated by a handful of source addresses, and the mode it would protect is the one the documentation now says is for tenants that accept this exposure. The condition that would change that: a deployment reporting quota exhaustion from distributed sources in `anonymous` mode *with* the second clock in place — and even then the answer is more likely `initial_access_token` than a subnet ledger. And the quota check and the write are still separated by an `await`, so concurrent registrations can overshoot the ceiling by the number in flight; the second clock makes such a burst cheap to recover from rather than cheap to cause.

**T-274 — An unauthenticated `client_id` turns the authorization server into a request-forgery engine against its own network**  
`Client ID metadata document fetch` (Process) · Information disclosure · High · Mitigated

A client ID metadata document is fetched because an unauthenticated request named its URL. That is the whole mechanism and it is also the whole exposure: without a guard it is a `GET` to any address the caller chooses, issued from inside the deployment's network, with the response parsed and its contents stored. SEC-094 is the reason this entry is not merely theoretical — the shared SSRF guard once failed to canonicalise IPv4-mapped IPv6, so an `AAAA` record of `::ffff:169.254.169.254` passed the address check and was then *pinned* into the connection, guaranteeing the attacker's address was the one dialled.

> The fetch goes through `axiam_pki::ssrf::guarded_fetch` over the existing `axiam-oauth2 → axiam-federation` edge, so it inherits the guard every other outbound fetch in AXIAM uses rather than carrying its own. Re-verified on this path at the 2026-09-17 review (V3): both IPv4-in-IPv6 embeddings are folded before classification — `::ffff:0:0/96` canonicalised to the v4 address it denotes, `::/96` rejected outright because `to_canonical` does not fold it — and **every** resolved address is classified rather than only the one dialled, so an `A`/`AAAA` pair with one bad answer is refused. Rebinding between check and connect is closed by pinning the validated address into a client built fresh per fetch, with no pooling. Redirects are never followed automatically: each hop is re-resolved, re-classified and re-issued, and the `allow_private` test seam is honoured on the first hop only, so `cimd.allow_http` cannot be turned into a redirect to a metadata endpoint. The bounds are each enforced and each tested — `https` unless the tenant opts into `http`, a 10-second timeout, a `Content-Length` gate plus a *streaming* cap at `max_metadata_bytes`, and a JSON content-type check. Ordering is the part most easily got wrong and is right here: `cimd::resolve` runs the trusted-publisher check **before** `get_or_fetch`, so an untrusted host is never contacted at all.

**T-276 — The trusted-publisher list that bounds the fetch admits a value meaning "every host"**  
`Client ID metadata document fetch` (Process) · Information disclosure · Medium · **Closed** — `0a273ec`

T-274's address guard keeps the fetch out of the private network; it does nothing about the public one, and nothing else does either. `cimd.trusted_client_id_domains` is the control that stops the mechanism being a general-purpose outbound-request primitive, and T21.5 added an interlock refusing to enable CIMD while that list is empty, on exactly that reasoning. The interlock refuses the empty list and accepts `*` — which `host_glob_matches` documents as "a tenant that wants no host restriction" — so the posture the interlock exists to prevent is reachable by one character, and the validator's own error message names `*` as a valid entry.

> Not a default: CIMD is off by default and the field ships empty, so no deployment has this posture without an operator writing it. The address guard still holds, so the residual is an outbound `GET` to public URLs a caller chooses, with AXIAM's source address and no attribution — not an internal-network primitive. **Closed** (`0a273ec`), filed as MCP-03 ([#469](https://github.com/ilpanich/axiam/issues/469)) against T21.5. `*` is refused in `trusted_client_id_domains`, and so is a wildcard over a whole top-level domain (`*.com`), which is the same posture spelled longer; it stays admissible in `trusted_redirect_domains`, where an empty list is a working posture and the entries are not fetch targets. The argument is the one T21.5's amendment 2 made for refusing the empty list: an unrestricted trusted-publisher list is a request-forgery primitive offered to strangers **and no second control does that job**, so a control with a one-character bypass is not the control. Enforced at both settings doors by one condition, since `validate_cimd_policy` runs on the merged policy too, and the validator's entry-shape message no longer offers `*` for this field. It is a floor and not a public-suffix check: `*.github.io` still passes, because trusting shared hosting is a decision an operator may reasonably make, and what bounds it is T-275's quota. Validation runs on write, so a stored `*` survives until that row is next saved — and no released deployment can hold one, CIMD being unreleased.

**T-275 — Shadow client rows accumulate without a quota and are reclaimed by nothing**  
`externally registered clients (dcr, cimd)` (Store) · Denial of service · Medium · **Closed** — `0b216c6`

Both external mechanisms write client rows for parties nobody vetted, and the two are bounded differently. A `dcr` row counts against `dcr_max_clients` and is swept on a TTL. A `cimd` row counts against nothing — the quota query asks for `ManagedBy::Dcr` — and is swept by nothing, because `sweep_unused_dcr_clients` excludes `cimd` deliberately, reasoning that a shadow row is a cache of a document the client publishes and deleting it would only be re-materialised on the next request. That argument is correct about TTL semantics and does not carry to storage: a cache that is never evicted is not a cache.

> The bound is the number of distinct URLs that both match `trusted_client_id_domains` and serve a valid document, which for the profile the documentation recommends — a named publisher, `*.vendor.example` — is small, and the entry would be theoretical. It stops being theoretical the moment a tenant trusts shared hosting, which is a natural thing to do because shared hosting is where a small tool publishes a JSON file; any third party who can publish under that domain then mints unbounded rows at one unauthenticated request each. It compounds with T-276, where `*` makes every domain shared hosting. **Closed** (`0b216c6`), filed as MCP-04 ([#470](https://github.com/ilpanich/axiam/issues/470)) against T21.5, in three parts and with no migration. `dcr_max_clients` now caps `cimd` rows as a separate count against the same number — which is what the repository's own comment on `count_by_managed_by` asked for — and the count is checked **before** the fetch, so a tenant at its ceiling is not an outbound amplifier either; the refusal is audited in T21.4a's shape and carries no caller-supplied string. `dcr_unused_client_ttl_days` now sweeps `cimd` rows on their own `/health/jobs` counter and their own clock, `max(updated_at, last_authorized_at, created_at)`: no column was added because `updated_at` is *already* "last presented", every resolve upserting the row whether or not a fetch happened. And the in-memory document cache evicts entries past their TTL and stale window on the insert path. Eviction on last-seen is *coherent* with T21.4's cache argument rather than against it — a row deleted while its document is still published is re-materialised on the next request, which is what a cache should do; what the old argument said nothing about is storage, and a cache that is never evicted is not a cache. T-276's closure did not lower this one: `*` was the one-character path to shared hosting and is gone, but naming `*.github.io` is one settings line, is a reasonable operator decision, and is the path this entry was filed about. The accepted residual is the ordering overshoot T-272 records, which applies here identically.

**T-277 — A resource indicator names AXIAM's own token audience, so a grant mints a credential for AXIAM while claiming to mint one for somebody else**  
`Resource-endpoint token validation (cnf, DPoP jti, sid)` (Process) · Elevation of privilege · Medium · Mitigated

I3 is enforced by pinning `aud` to AXIAM's two built-in audiences in `decode_access_token`, so a token minted for an MCP server is refused at AXIAM's own doors. RFC 8707 resource indicators are validated as absolute URIs without a fragment, and the parser deliberately admits any scheme, because `urn:` resources are legitimate and a loopback `http` MCP server is a resource like any other. AXIAM's audiences are spelled `axiam:user` and `axiam:m2m`, and a scheme followed by a path is all an absolute URI needs — so they parsed, carried no fragment, and were resource indicators like any other. Naming one did not defeat the audience pin; it satisfied it, and the boundary stopped being a boundary. The sharpest case is `client_credentials`, which mints `axiam:m2m` when no resource is named: naming `axiam:user` made the *same* grant mint a token carrying the user audience, from a grant with no end user in it — a shape no other path in the server can produce. `external_client_allowed_resources` is what made it more than untidy, because D3 has DCR and CIMD clients inherit that list wholesale.

> 2026-09-17 (MCP-02, `013903d`). `axiam_oauth2::resource::normalise` reserves the whole `axiam` scheme rather than the two literals, so an audience added later is covered without anybody having to remember the rule exists. It is checked after parsing, against the scheme `url` resolved, so `AXIAM:user` cannot slip past a byte comparison on the input, and every door answers `invalid_target`: registration refuses the entry, and the token endpoint refuses the parameter even for a row that somehow holds one, because `is_allowed` normalises both sides. Fail-closed and reachable by no existing deployment — `allowed_resources` ships in the same unreleased version, so no stored row can contain one. Asserted at the parser and at both endpoints.

**T-278 — RFC 8252's loopback port allowance widens a redirect registration by more than a port**  
`/oauth2/authorize (+ consent)` (Process) · Elevation of privilege · Critical · Mitigated

T-52 is Critical because a loosely matched `redirect_uri` hands the authorization code to an attacker's origin, and until T21.2 the match was byte-for-byte everywhere, which is exactly right and unimplementable for a desktop client listening on a port the operating system chose at run time. RFC 8252 §7.3 requires the port to be free; the risk is that the relaxation is written once and relaxes something else with it — a host, a path, a userinfo segment — at the one comparison standing between an authorization code and an attacker's server.

> The allowance is applied only when the **registered** URI is `http` on `127.0.0.1`, `[::1]` or `localhost`; every `https` registration keeps exact matching (I6), because an `https` registration means the operator wrote a TLS endpoint down and a port is part of which endpoint that is. Everything but the port must still be identical — scheme, host, path, query, fragment, **username and password** — and the three loopback hosts each match only themselves, so a registration is never widened to a host the operator did not write. The non-loopback path compares the *strings*, byte for byte, so nothing existing changed. The doubled guard is what makes the classic attack uninteresting: `http://127.0.0.1@evil.example.com/callback` fails on the host and again on the userinfo. One function serves the authorization endpoint, PAR and code redemption, so the rule cannot be applied at one and forgotten at another, and the authorization code stores the **presented** URI so the token request's comparison stays exact against what was actually used. Driven against the live endpoint at the 2026-09-17 review (V1) with seven host, path, encoding and scheme spellings, including the two the review was asked to try.

**T-280 — A desktop client on an ephemeral loopback port is never told its authorization failed**  
`/oauth2/authorize (+ consent)` (Process) · Denial of service · Low · **Closed** — `b8bc508`

T-255 established that an authorization error must be delivered where the relying party can read it. T-278's matcher answers "is this a registered redirect URI?" for the success path and for refusals raised after it runs; six sites in `handlers/oauth2.rs` still ask with an exact comparison, and decide whether an error may be reported by redirecting. For a client that registered `http://127.0.0.1/callback` and is listening on an ephemeral port, the answer is no, and the error is rendered into the browser instead — so the client's loopback listener waits for a callback that never arrives while the user reads an error page the client cannot see.

> Fail-closed in the direction that matters: no error is ever redirected to a URI that was not registered, so this was never an open-redirect finding and the exact comparison was the safe error to make. What it cost was interoperability, on exactly the client family Phase 21 exists to serve. Confined to refusals raised *before* the matcher runs — `response_type` absent entirely, and the `request_uri` refusals — which the 2026-09-17 review established by driving both the negative and the positive case after its first, wider, framing of the finding was contradicted by the harness. **Closed** (`b8bc508`), filed as MCP-01 ([#472](https://github.com/ilpanich/axiam/issues/472)) against T21.2a: all six sites now call `any_redirect_uri_matches`, which is where the rule already lived precisely so that it could not be applied at one endpoint and forgotten at another. Ungated, and it needs no flag: the matcher short-circuits on string equality and takes the port allowance only when the *registered* URI is `http` on a loopback host, so the answer changes for one shape of registration and no other, and nothing that was refused becomes redirectable. `mcp01_an_error_is_not_redirected_to_an_ephemeral_loopback_port` was written to be inverted and was, to `mcp01_an_error_is_redirected_to_an_ephemeral_loopback_port`; a second case pins `refuse_request_uri_to_client`, the site furthest from the first.
>
> One thing found while closing it, recorded because it was the last inconsistency in the same story rather than a new threat: `http://[::1]/…` could not be *registered* at all. `validate_redirect_uris` compared the parsed host against the bare `::1` while a URL parser returns the bracketed literal, so the matcher's tested `[::1]` arm was live code nothing could reach. Fixed in `7ab890d`, in its own commit because it is the one change in the group that makes a refused request succeed: the widening admits one host, reachable only from the machine the user is sitting at, and a routable IPv6 literal over `http` is still refused. A validator that refuses what its own error message says it allows is a defect, not a decision.

**T-279 — One key set signs every tenant, so a token minted for tenant A verifies on tenant B's path**  
`per-tenant path issuers (/t/{tenant_id})` (Process) · Elevation of privilege · Critical · Mitigated

RFC 8414 §2 forbids a query component in an issuer, so AXIAM's `?tenant_id=` convention cannot be published as one tenant's issuer and an MCP client deriving discovery from a protected-resource document always landed on the deployment's default tenant. T21.6's opt-in `{root}/t/{tenant_id}` fixes that and introduces the risk, which T21.6's own second amendment found rather than inherited: the JWKS is shared — one key set, many issuers, which RFC 8414 permits — and the extractors must accept both the root issuer and any tenant issuer, so **the signature no longer distinguishes tenant A's token from tenant B's**. Left there, a path-shaped tenant selector would be a selector the caller and the token could disagree about, which on a multi-tenant authorization server is the whole ball game.

> Two checks, and the 2026-09-17 review (V2) confirmed both against live routes rather than against the functions. `enforce_issuer` refuses a token whose `iss` names a tenant its `tenant_id` claim does not, so a token can never be internally ambiguous; it is a no-op with the flag off, where `jsonwebtoken`'s pinned-issuer check is kept verbatim, so I1 holds by construction. `enforce_tenant_path_binding` refuses a principal whose tenant is not the tenant the path named, and sits in `extract_user` — the funnel **both** extractor arms pass through — so a route mounted under the scope later inherits it rather than having to remember it; it is placed after the decode because the scope middleware cannot decode a token. The refusal is the same `401` an uncredentialed request gets, so the holder of a tenant-A token is not told tenant B exists. A `tenant_id` query parameter on a tenant path is refused outright with `invalid_request`, so the two selectors can never both be present. Introspection is tenant-scoped independently — the token's `tenant_id` is compared with the request's and a mismatch answers `active: false` — so the shared key set does not make introspection a cross-tenant read either. One note for whoever widens the scope: only the OAuth2 endpoints are mounted under `/t/{tenant_id}` today, and the binding is checked against the principal's *home* tenant, which the organization-level tenant header can move afterwards; that does not meet a path selector on any route as things stand.

</details>

### 5.4 Federation — SAML SP & OIDC relying party

Inbound federation from external identity providers: OIDC discovery and code exchange, SAML assertion consumption, the shared SSRF guard on every outbound IdP fetch, and attribute-to-role mapping with JIT provisioning. Since 1.0.0-beta08 this also covers the *public* login surface — the unauthenticated providers listing a login page renders its buttons from, the single-use handoff codes that let a cross-site SAML or Apple return issue a `SameSite=Strict` session, the plain-OAuth2 variant that authenticates by a userinfo call rather than a signed ID token, and organization→tenant inheritance of a federation config.

*31 threats — 4 critical, 12 high, 13 medium, 2 low; 1 open.*

| # | Element | STRIDE | Threat | Severity | Status |
|---|---|:-:|---|---|---|
| T-63 | External IdP (Entra, Okta, Keycloak…) <br/>*Actor* | S | IdP key substitution via a hijacked jwks_uri | High | Mitigated |
| T-64 | Federated user <br/>*Actor* | S | Account takeover through unverified email linking | High | Mitigated |
| T-65 | OIDC RP (discovery, code exchange) <br/>*Process* | S | IdP mix-up attack | Medium | Mitigated |
| T-66 | OIDC RP (discovery, code exchange) <br/>*Process* | T | Nonce or state omitted on callback | High | Mitigated |
| T-67 | SAML SP (assertion consumer) <br/>*Process* | T | XML signature wrapping | Critical | Mitigated |
| T-68 | SAML SP (assertion consumer) <br/>*Process* | S | Assertion replay | High | Mitigated |
| T-69 | SAML SP (assertion consumer) <br/>*Process* | T | Unsigned or partially signed assertion accepted | Critical | Mitigated |
| T-70 | SSRF guard resolve-and-pin (guarded_fetch) <br/>*Process* | E | DNS rebinding between validation and connect | High | Mitigated |
| T-71 | SSRF guard resolve-and-pin (guarded_fetch) <br/>*Process* | D | Oversized IdP response exhausts memory | Medium | Mitigated |
| T-72 | Attribute mapping & JIT provisioning <br/>*Process* | E | Role injection through attribute mapping | Critical | Mitigated |
| T-73 | Attribute mapping & JIT provisioning <br/>*Process* | D | JIT provisioning inflates the user population | Low | Mitigated |
| T-74 | federation_config (encrypted secrets) <br/>*Store* | I | Federation client secret disclosed via logs or Debug | Medium | Mitigated |
| T-75 | JWKS / discovery cache <br/>*Store* | T | Cache poisoning extends a compromised key's lifetime | Medium | Mitigated |
| T-76 | IdP signing certificates <br/>*Store* | T | Expired or revoked IdP certificate still trusted | Medium | Mitigated |
| T-77 | SAML response (POST binding) <br/>*Flow* | I | Assertion readable in transit or in browser history | Medium | Mitigated |
| T-155 | OIDC RP (discovery, code exchange) <br/>*Process* | E | A partner's token is accepted as an AXIAM credential (X4) | Critical | Mitigated |
| T-156 | OIDC RP (discovery, code exchange) <br/>*Process* | S | A token not addressed to AXIAM is replayed at the exchange (X4) | High | Mitigated |
| T-157 | OIDC RP (discovery, code exchange) <br/>*Process* | E | Trust composes transitively across three domains (X4) | High | Mitigated |
| T-158 | OIDC RP (discovery, code exchange) <br/>*Process* | E | A long-lived partner token becomes a long replay window (X4) | Medium | Mitigated |
| T-159 | OIDC RP (discovery, code exchange) <br/>*Process* | S | An ID token or refresh token is presented as a subject token (X4) | Medium | Mitigated |
| T-160 | Attribute mapping & JIT provisioning <br/>*Process* | E | A suspended user is revived through the exchange path (X4) | Medium | Mitigated |
| T-161 | Attribute mapping & JIT provisioning <br/>*Process* | D | A partner's IdP silently populates the AXIAM user table (X4) | Low | Open |
| T-162 | federation_config (encrypted secrets) <br/>*Store* | T | A malformed trust block is enabled without review (X4) | Medium | Mitigated |
| T-218 | Public providers listing <br/>*Process* | I | The login-page provider list enumerates organizations and tenants | Medium | Mitigated |
| T-219 | SSO handoff code <br/>*Flow* | S | A handoff code is captured from a URL and redeemed first | Medium | Mitigated |
| T-220 | OAuth2 RP (userinfo variant) <br/>*Process* | S | Authentication rests on a userinfo call with no verifiable assertion | High | Mitigated |
| T-221 | OAuth2 RP (userinfo variant) <br/>*Process* | T | A substituted userinfo endpoint is an authentication bypass | High | Mitigated |
| T-222 | OAuth2 RP (userinfo variant) <br/>*Process* | S | A provider asserts an email nobody has proved they control | High | Mitigated |
| T-223 | OIDC RP (discovery, code exchange) <br/>*Process* | S | A templated issuer accepts every tenant of the provider | High | Mitigated |
| T-224 | Federation config inheritance <br/>*Process* | E | An inherited organization provider signs users into the wrong tenant | High | Mitigated |
| T-225 | federation_config (encrypted secrets) <br/>*Store* | T | A custom button icon is stored content served to every login-page visitor | Medium | Mitigated |

<details>
<summary>Threat detail and mitigations</summary>

**T-63 — IdP key substitution via a hijacked jwks_uri**  
`External IdP (Entra, Okta, Keycloak…)` (Actor) · Spoofing · High · Mitigated

If jwks_uri can be redirected — DNS takeover, an unvalidated discovery document, or a stale cache — the attacker supplies their own signing key and every assertion validates.

> jwks_uri is validated and fetched only through guarded_fetch with https enforcement and IP pinning; the discovery document itself is fetched the same way. (The equivalent PHP SDK gap, SDK-19, is tracked in that SDK's own repository.)

**T-64 — Account takeover through unverified email linking**  
`Federated user` (Actor) · Spoofing · High · Mitigated

Linking a federated identity to a local account purely on a matching email lets an IdP that does not verify email addresses claim any local account.

> Linking requires the IdP to assert email_verified, or an explicit administrator-configured linking policy per federation config; unverified matches create a distinct identity rather than merging.

**T-65 — IdP mix-up attack**  
`OIDC RP (discovery, code exchange)` (Process) · Spoofing · Medium · Mitigated

With multiple IdPs configured, an attacker starts a flow at IdP A and delivers the response to the callback expecting IdP B, so a code from a weak IdP is redeemed against a trusted one.

> The federation config id is bound into the state value and checked on callback, and the issuer in the returned id_token must match the configuration that started the flow.

**T-66 — Nonce or state omitted on callback**  
`OIDC RP (discovery, code exchange)` (Process) · Tampering · High · Mitigated

Without nonce binding, an id_token obtained elsewhere can be injected into a victim's session.

> state and nonce are both required, generated with a CSPRNG, stored server-side against the pending flow, and verified before any identity is established.

**T-67 — XML signature wrapping**  
`SAML SP (assertion consumer)` (Process) · Tampering · Critical · Mitigated

A classic SAML attack: the attacker keeps a legitimately signed assertion but wraps it so the parser reads attacker-controlled content while the verifier checks the original signature.

> The signature is verified over the exact element that is then consumed — the same reference is used for validation and for attribute extraction — and multiple assertions or unreferenced elements are rejected outright.

**T-68 — Assertion replay**  
`SAML SP (assertion consumer)` (Process) · Spoofing · High · Mitigated

A captured assertion is replayed within its validity window to establish a second session as the victim.

> Assertion IDs are recorded and refused on reuse; NotBefore and NotOnOrAfter are enforced with a small clock skew; the Recipient and Destination must match this SP.

**T-69 — Unsigned or partially signed assertion accepted**  
`SAML SP (assertion consumer)` (Process) · Tampering · Critical · Mitigated

Accepting a response whose assertion is unsigned — or trusting a signed response wrapper without checking the assertion — makes every claim attacker-controlled.

> The SP fails closed: an assertion without a valid signature from the configured IdP certificate is rejected, and signature presence is not inferred from the response envelope.

**T-70 — DNS rebinding between validation and connect**  
`SSRF guard resolve-and-pin (guarded_fetch)` (Process) · Elevation of privilege · High · Mitigated

Validating the resolved address and then letting the HTTP client re-resolve at send time leaves a TOCTOU window in which the name flips to an internal address.

> D-01c: the guard resolves A and AAAA fresh, rejects private, loopback, link-local, ULA and unspecified results, and pins the validated IP for the actual connection so no second resolution happens.

**T-71 — Oversized IdP response exhausts memory**  
`SSRF guard resolve-and-pin (guarded_fetch)` (Process) · Denial of service · Medium · Mitigated

A hostile or compromised IdP returns a multi-gigabyte discovery or JWKS document and the fetch buffers it.

> SEC-069: the advertised Content-Length is checked against a maximum before the body is read, and the fetch is refused when it exceeds the cap.

**T-72 — Role injection through attribute mapping**  
`Attribute mapping & JIT provisioning` (Process) · Elevation of privilege · Critical · Mitigated

If IdP-supplied group or role attributes are mapped straight onto AXIAM roles, anyone who controls their own IdP attributes — or an IdP admin — can self-assign administrative roles.

> Mapping is an explicit, tenant-scoped allow-list configured by an AXIAM administrator; unmapped attributes are discarded, and mapped roles are constrained to the tenant of the federation config. Grant no privileged role through mapping unless the IdP is administratively equivalent to AXIAM.

**T-73 — JIT provisioning inflates the user population**  
`Attribute mapping & JIT provisioning` (Process) · Denial of service · Low · Mitigated

Unbounded just-in-time user creation from a federated IdP lets a hostile IdP create arbitrarily many tenant users.

> JIT provisioning is opt-in per federation config and the created users hold no roles beyond those the mapping allow-list grants.

**T-74 — Federation client secret disclosed via logs or Debug**  
`federation_config (encrypted secrets)` (Store) · Information disclosure · Medium · Mitigated

The OIDC client secret configured for an IdP is a credential against that IdP; leaking it in a trace line is a real third-party compromise.

> SECHRD-09: the federation secret type carries a manual Debug impl that redacts the value, and the secret is encrypted at rest. The same treatment was applied to webhook secrets under SEC-067.

**T-75 — Cache poisoning extends a compromised key's lifetime**  
`JWKS / discovery cache` (Store) · Tampering · Medium · Mitigated

A JWKS entry fetched during a window of IdP compromise stays trusted for the whole cache lifetime even after the IdP rotates.

> Cache entries are bounded by a short TTL and are re-fetched through the same guarded path; an unknown kid forces an immediate refresh rather than a silent failure.

**T-76 — Expired or revoked IdP certificate still trusted**  
`IdP signing certificates` (Store) · Tampering · Medium · Mitigated

A SAML IdP certificate left in place after rotation or revocation keeps validating assertions signed by a key the IdP no longer controls.

> Certificate validity is checked at assertion-verification time, not only at configuration time, and expiry raises an admin notification through the compliance notification category.

**T-77 — Assertion readable in transit or in browser history**  
`SAML response (POST binding)` (Flow) · Information disclosure · Medium · Mitigated

SAML assertions carry identity attributes and travel through the user's browser.

> HTTP-POST binding keeps the assertion out of the URL; TLS 1.3 protects it in transit; assertion encryption is supported where the IdP offers it.

**T-155 — A partner's token is accepted as an AXIAM credential (X4)**  
`OIDC RP (discovery, code exchange)` (Process) · Elevation of privilege · Critical · Mitigated

External-IdP token exchange (RFC 8693, X4) lets a client present a token minted by a partner's IdP and receive an AXIAM token. If the partner's assertions were trusted as authorization, the partner's administrator would be able to name AXIAM scopes and grant their own users authority in this tenant.

> An external subject token is treated as evidence of authentication only. The issued token's scopes are the intersection of an AXIAM-admin-authored deny-by-default scope_map, the exchanging client's registration, and the RBAC engine's answer for the resolved user at mint time (deny-override applied at its broadest reading). Trust is off by default per provider, and enabling it requires a non-empty accepted_audiences list.

**T-156 — A token not addressed to AXIAM is replayed at the exchange (X4)**  
`OIDC RP (discovery, code exchange)` (Process) · Spoofing · High · Mitigated

A token the partner minted for a third party — or for their own internal service — is captured and presented to AXIAM's token endpoint. Without an audience check, any token from the partner's estate becomes an AXIAM credential.

> accepted_audiences is required and non-empty whenever token exchange is enabled; there is deliberately no accept-all value. Matching is exact string equality in both directions (no trailing-slash forgiveness, no case folding), and aud may be a string or an array, of which at least one member must match.

**T-157 — Trust composes transitively across three domains (X4)**  
`OIDC RP (discovery, code exchange)` (Process) · Elevation of privilege · High · Mitigated

AXIAM trusts partner B; B trusts partner C. Without a barrier, a token C minted can be exchanged at B and the result exchanged at AXIAM, giving C authority nobody configured and neither configuration reveals.

> Every token minted from an external subject token carries an ext_exchange provenance claim naming the foreign issuer, and BOTH exchange paths refuse a subject token that carries it. An exchanged token can never be re-exchanged, ours or theirs.

**T-158 — A long-lived partner token becomes a long replay window (X4)**  
`OIDC RP (discovery, code exchange)` (Process) · Elevation of privilege · Medium · Mitigated

A partner IdP that issues 24-hour access tokens would, without an independent bound, hand a captured token a 24-hour window in which it can be turned into AXIAM credentials.

> max_token_age_secs bounds the token's age independently of its own exp (default 300 s, hard ceiling 3600 s), and an iat in the future beyond 60 s of skew is refused. The issued token's lifetime is the minimum of the partner token's remaining life, the per-provider ceiling, and the server-wide exchange maximum.

**T-159 — An ID token or refresh token is presented as a subject token (X4)**  
`OIDC RP (discovery, code exchange)` (Process) · Spoofing · Medium · Mitigated

An ID token is an assertion to a client about a login, which an OIDC deployment distributes more widely and gives a longer life than an access token; a refresh token is a re-authentication credential. Either accepted as a subject token would let an artefact the partner considers low-risk buy an AXIAM credential.

> Both are refused by name at the subject_token_type check, and — since a caller can mislabel a token — again by shape: the ID-token-only claims nonce, at_hash, c_hash and s_hash, and typ headers or claims naming an ID or refresh token, are rejected even when the signature verifies.

**T-160 — A suspended user is revived through the exchange path (X4)**  
`Attribute mapping & JIT provisioning` (Process) · Elevation of privilege · Medium · Mitigated

An AXIAM user who has been locked, deactivated or anonymized would, if the exchange path skipped the status gate, still be able to obtain tokens for as long as their partner IdP kept authenticating them.

> The resolved user's status is checked after subject resolution and before any token is minted; Locked, Inactive and Anonymized are refused. PendingVerification is allowed deliberately: federation provisioning never moves a federated user off it, so requiring Active would refuse the whole population the feature serves while stopping nobody.

**T-161 — A partner's IdP silently populates the AXIAM user table (X4)**  
`Attribute mapping & JIT provisioning` (Process) · Denial of service · Low · Open

With subject_mapping set to jit_provision, every previously-unseen subject the partner vouches for creates an AXIAM user row. A partner with a large or hostile user population can grow the table without an AXIAM administrator acting.

> Off by default (linked_only refuses unknown subjects). Every JIT provision is audited with the provider and the external subject, and a provisioned user holds no roles, so the exchange that created them still yields no token. Residual risk accepted: the same exposure the browser SSO JIT path already carries, bounded by the same per-client exchange rate limit.

**T-162 — A malformed trust block is enabled without review (X4)**  
`federation_config (encrypted secrets)` (Store) · Tampering · Medium · Mitigated

A scope_map entry mapping to no scopes, an out-of-range token age, or an unknown subject_mapping value stored while token exchange is disabled becomes live the moment an administrator ticks the enable box — which is not where they expect to be told their configuration was wrong.

> The trust block is validated at the API edge on every write, whether or not it is enabled (only the non-empty-audience rule is conditional). On read, every hydration failure resolves towards the default, and enabled is read from its own column so a corrupt neighbouring column can never switch exchange on. A provider whose stored trust block fails validation is skipped at resolution time with a warning rather than being used.

**T-218 — The login-page provider list enumerates organizations and tenants**  
`Public providers listing` (Process) · Information disclosure · Medium · Mitigated

`GET /api/v1/auth/federation/providers` has to be unauthenticated — its caller is a person at a login page — and it takes an organization slug. If it answered differently for a slug that exists and one that does not, it would be an organization-slug oracle, and knowing which organizations a deployment hosts is reconnaissance for every other attack on it.

> An unknown organization or tenant and a known one with nothing configured return the **same** answer: `200` with an empty list. That is deliberately different from `oidc_start_public`, which answers `401` for a slug miss: there every failure is a `401`, so the answer carries nothing, whereas a *list* endpoint answering `401` for unknown and `200 []` for known-but-empty would be two-valued. The rate is bounded by the same `login_per_min` budget the sign-in endpoints use, through both the per-process governor and the shared limiter. The response body is a dedicated struct carrying only what a button needs — config id, provider kind, display name, protocol, and the operator's icon — rather than a narrowed admin response, so a field added to the admin surface cannot reach it by inheritance; an integration test asserts the body contains no client id, secret, metadata URL or endpoint.

**T-219 — A handoff code is captured from a URL and redeemed first**  
`SSO handoff code` (Flow) · Spoofing · Medium · Mitigated

AXIAM's session cookies are `SameSite=Strict`. SAML and Apple's `response_mode=form_post` both return **cross-site**, so cookies set on that response would not be sent on the navigation that follows. The mechanism that bridges it — a code in a redirect URL, exchanged same-origin — puts a session-bearing credential somewhere URLs go: browser history, and a `Referer` header.

> The code is 256 bits from the same CSPRNG as `state`; only its SHA-256 hash is stored, so a database read yields nothing usable; it lives **60 seconds**, not the ten minutes a login state row gets, because it exists to survive exactly one redirect; and it is consumed atomically by the same `SELECT`+`DELETE` transaction pattern as `consume_by_state`, so a replay is refused with the same answer as an unknown code. It carries no token material at all — the session is minted from `user_id`/`tenant_id` at redemption, so a code that is never redeemed leaves no session behind. The redirect response sets `Cache-Control: no-store` and `Referrer-Policy: no-referrer`, and the SPA strips the parameter with `history.replaceState` before doing anything else.
>
> **Where the code may be delivered is the load-bearing part, and it is not the caller's choice.** `redirect_uri` reaches AXIAM on an *unauthenticated* start endpoint, and `validate_redirect_uri` checks its scheme only — every `https://` host on the internet passes it. The two cross-site flows have no provider-side backstop **by construction**: a SAML IdP is pointed at AXIAM's own ACS and Apple at AXIAM's own form-callback, so the provider never sees the SPA URI and never validates it — AXIAM alone decides where the browser goes next, carrying a credential the handoff endpoint will exchange for session cookies for whoever presents it. Without a check, anyone could start a login with `redirect_uri = https://attacker.example/`, lure a victim through the victim's own real IdP, and read a working session out of their access log; the 60-second TTL, the single use and the hash-only storage are all irrelevant when the attacker *is* the destination. `require_deployment_spa_origin` therefore confines the target to the **origin of** `AuthConfig::effective_issuer()` — the same value the ACS and form-callback URLs are built from, so it cannot be wrong where these flows work at all — plus anything an operator names in `AXIAM__AUTH__SSO_SPA_ORIGINS` for a separately hosted SPA. Compared as origins via `Url::origin`, so a userinfo prefix, a path, a port or a scheme cannot smuggle a second host past it. It is enforced at login start (a `400` naming the knob), again at the mint (so a state row written by an older binary is not honoured), and on the error redirect. It runs *after* workspace and config resolution, so an unknown slug still answers the uniform `401`. This is the rule T-52 already states for the OAuth2 authorization server's own `redirect_uri`. **Enforced on all four start paths since 1.0.0-beta12 (R-3), not only the cross-site two.** The OIDC and plain-OAuth2 paths were left on the scheme-only check because the identity provider *is* handed the same `redirect_uri` and *does* compare it against its registered set. That backstop is real and it stays — but it is only as strict as each provider's registration hygiene, and several providers accept wildcard or prefix registrations; more to the point it is a control AXIAM neither owns nor can inspect. The rule the server owns is therefore uniform across the four flows, and on the OIDC and OAuth2 flows the provider's registered-redirect check is now a second, independent layer rather than the only one. The `TODO(T19.14)` that proposed a per-`FederationConfig` registered-redirect allowlist is retired rather than carried: the deployment-origin rule already answers where a code may go, and a second list to keep in sync is a second place to get wrong. `sdks/CONTRACT.md` §12.1 rule 12a widened to match (contract 1.39), additive and restrictive server-side only. One class of deployment must act: an SPA on an origin other than the issuer's, signing in through OIDC or OAuth2, needs `AXIAM__AUTH__SSO_SPA_ORIGINS` set — the requirement SAML and Apple have imposed since beta08, and the `400` names the variable.
>
> Weakening the session cookies to `SameSite=Lax` would have removed the need for any of this, and re-opened the CSRF surface `Strict` closes across every endpoint, permanently, to serve two flows. Residual risk accepted: an attacker who reads the URL inside 60 seconds *and* redeems before the legitimate SPA gets a session — and the legitimate user gets a visible failure, because the code is gone. That is the same trade the OAuth authorization code itself makes.

**T-220 — Authentication rests on a userinfo call with no verifiable assertion**  
`OAuth2 RP (userinfo variant)` (Process) · Spoofing · High · Mitigated

`FederationProtocol::OAuth2` exists because GitHub publishes no discovery document and issues no ID token, and Facebook's web flow returns only an access token to a confidential client. On that path there is no signature, no `nonce` and no `aud` — the whole assurance is "the access token we just received works against the userinfo endpoint we configured". That is a genuine downgrade from the OIDC path, and a downgrade nobody writes down is a downgrade nobody notices.

> Stated explicitly in the module documentation, in the design doc (§3), in the admin UI (the protocol carries its own warning and its own badge colour), and here. Enforced rather than merely documented: `validate_protocol_for_kind` **refuses** this protocol for `google`, `microsoft`, `apple` and `generic_oidc`, so it cannot be selected for a provider that supports OIDC properly, and the refusal says why. PKCE (`S256`) is mandatory on this path rather than optional — it is the only replay protection left once `nonce` is gone — with the verifier generated server-side, stored in `federation_login_state`, and never returned to the client. `state` stays 256-bit, server-side and single-use. The token exchange is server-side with the encrypted client secret; nothing about it happens in the browser. Honest caveat, recorded in `crate::pkce`: a provider that *ignores* `code_challenge` gives us nothing for it, and no relying party can make a remote server verify something — GitHub has supported S256 since July 2025, and where a provider does not, the residual protection is the single-use state plus the confidential-client secret.

**T-221 — A substituted userinfo endpoint is an authentication bypass**  
`OAuth2 RP (userinfo variant)` (Process) · Tampering · High · Mitigated

With no signature to check, whoever answers the userinfo request decides who signed in. An endpoint redirected to an attacker — by a plaintext URL, a redirect, a rebound DNS name, or a value derived at runtime from something the IdP said — is a complete authentication bypass with nothing to catch it.

> The three OAuth2 endpoints are **explicit per config**, never derived from a discovery document or from anything the provider sends at runtime, and each is validated as absolute HTTPS (loopback excepted, for tests) at write time, by the same rule `validate_metadata_url` applies to the OIDC discovery URL. Every fetch goes through the shared `guarded_fetch` SSRF guard: HTTPS on every hop, resolve-and-pin against DNS rebinding, bounded redirects, and a 256 KiB response cap read as a running byte count. A `200` carrying `{"error": …}` is treated as the failure it is, rather than handed onward as an empty bearer token.

**T-222 — A provider asserts an email nobody has proved they control**  
`OAuth2 RP (userinfo variant)` (Process) · Spoofing · High · Mitigated

AXIAM keys account recovery, email verification and administrative notification on the address. An unverified address adopted as an identity is account takeover by whoever typed it into the provider first — and `GET https://api.github.com/user` returns `email: null` or an unverified address for a large share of accounts.

> An address the provider does not affirmatively mark verified is **never** adopted on this path: `email_verified` must be truthy or the login is refused with `UnverifiedExternalEmail`, and absent, `null` and falsey all read as false. For GitHub the primary *verified* address comes from a second, mandatory call to the `/emails` resource — derived from the configured `userinfo_endpoint`, so GitHub Enterprise Server works too — and only a `primary && verified` entry is taken, because a verified non-primary address is somebody else's choice of which mailbox represents them. Where a provider offers no verification signal at all (Facebook's Graph API), the decision is the operator's and is written down where it can be audited: an `attribute_map` literal, `"email_verified": "@true"`. Refusing rather than provisioning without an address is deliberate — an account that cannot recover itself is not a better outcome than a clear failure. See design doc §5.3.

**T-223 — A templated issuer accepts every tenant of the provider**  
`OIDC RP (discovery, code exchange)` (Process) · Spoofing · High · Mitigated

Verified live: Entra ID's `common` authority publishes `issuer` as `https://login.microsoftonline.com/{tenantid}/v2.0` — the placeholder literally. Strict `iss` matching rejects every token, so supporting it at all means substituting the token's `tid`. Microsoft signs every tenant's tokens at `common` with the same keys, so "accept whatever `tid` says" means *every Microsoft account on earth may sign in here*.

> Templated issuers are supported, and a config with one and an **empty** `allowed_issuer_tenants` is refused at create and update time — the message names both ways out (a tenant-specific authority, or a list of accepted tenants), because that configuration is occasionally intended and never intended by accident. The refusal is repeated at sign-in time, so a row written before the check existed cannot fall through to "accept anyone". The `tid` is read from the *unverified* payload solely to select which of a closed, operator-written set of issuer strings to require: it must parse as a UUID (otherwise a crafted value could substitute path segments), it must appear in the allow-list, and the signature check and the verified `iss` comparison both still run afterwards. It can never widen the accepted set.

**T-224 — An inherited organization provider signs users into the wrong tenant**  
`Federation config inheritance` (Process) · Elevation of privilege · High · Mitigated

A federation config may now live in the organization-scope tenant and be used by the organization's tenants. The config's tenant and the tenant being signed into are therefore different, and every place that previously said "the tenant" now has two candidates. Provisioning into the config's tenant would put every tenant's federated users in one shared tenant — an isolation failure with a benign-looking cause.

> Visibility and provisioning are decided in one place each and are deliberately different: `effective_providers` decides which configs a tenant may use, and `provision_or_link_identity` is documented and tested to create the user and the link in the **requesting** tenant. A login resolves its config through the same `effective_providers` the buttons were rendered from, so a config that is disabled, not inheritable, or shadowed by a tenant override cannot be reached by posting its id. `FederationLink`'s `(tenant_id, federation_config_id, external_subject)` uniqueness still means one link per external identity per tenant — verified, not assumed — so one Google account signing into two tenants through one inherited config gets two AXIAM users, which is what tenant isolation requires. A tenant's own config of the same kind always shadows the inherited one, **including a disabled one**, so "disable" cannot come to mean "re-enable the organization's". The SAML assertion-consumer path is the one place where the two tenants both do real work and differently: `handle_saml_response_for` records the assertion-replay row under the **config's** tenant — a no-op for a config the requesting tenant owns, and strictly stronger for an inherited one, since an assertion spent in one tenant cannot then be spent in a sibling — while the user and the link are created in the **requesting** tenant like every other protocol. Both ACS entry points resolve the config through `effective_providers` first, exactly as the OIDC and OAuth2 callbacks do; loading it with a `get_by_id` scoped to the requesting tenant, as the ACS originally did, could not find an inherited config at all.

**T-225 — A custom button icon is stored content served to every login-page visitor**  
`federation_config (encrypted secrets)` (Store) · Tampering · Medium · Mitigated

A generic provider may carry an operator-uploaded icon, and that image is returned by the unauthenticated providers endpoint on every render of a login page. An SVG would be a document with its own parser in that position; an unbounded one would make every visitor download whatever an operator pasted.

> Raster only — `image/png`, `image/jpeg`, `image/webp` — with `image/svg+xml` refused by name and the refusal saying why. Bounded to 16 KiB decoded, checked on the data URL's length first (so a multi-megabyte paste is rejected before anything walks it) and then on the decoded size; the admin UI crops to 64×64 in the browser, so what is uploaded is a few kilobytes and the source file never reaches the server. The value is only ever rendered as an `<img src>` under the SPA's `default-src 'self'; img-src 'self' data:` CSP. It is refused outright for the branded kinds, whose published sign-in-button rules require their own mark.

</details>

### 5.5 Authorization engine — RBAC, hierarchy & scopes

The three authorization entry points (REST middleware, gRPC CheckAccess, AMQP async), the default-deny RBAC engine with explicit deny-override and resource-hierarchy traversal, the decision cache, and the graph and audit stores behind them. Organization-level principals are evaluated under an explicit SubjectScope claim: only global grants carry across a tenant boundary, and an ordinary tenant principal cannot express cross-tenant reach at all. Since 1.0.0-beta05 a role assignment can additionally name the tenants it reaches (`tenant_scope`), confining an organization-level account to particular tenants, and organization-level actions require an organization-scoped principal, not merely the permission. 1.0.0-beta09 corrected three defects in how a grant's reach is computed — an assignment naming no resource is tenant-wide rather than inert, scoped grants inherit down the resource lineage without widening sideways, and the authorization-check endpoints resolve the acting tenant through the same reach check as every other route (T-226…T-228).

*27 threats — 6 critical, 14 high, 7 medium; 0 open.*

| # | Element | STRIDE | Threat | Severity | Status |
|---|---|:-:|---|---|---|
| T-78 | Microservice / PEP <br/>*Actor* | S | Caller asserts a subject_id it does not own | Critical | Mitigated |
| T-79 | AMQP producer (deferred authz) <br/>*Actor* | S | Replay of a previously valid signed authz message | High | Mitigated |
| T-80 | Tenant administrator <br/>*Actor* | R | Privileged grant made without attribution | Medium | Mitigated |
| T-81 | REST authz middleware <br/>*Process* | E | Endpoint reachable without an authorization check | Critical | Mitigated |
| T-82 | gRPC CheckAccess / BatchCheckAccess <br/>*Process* | I | Batch check used as an entitlement oracle | Medium | Mitigated |
| T-83 | gRPC CheckAccess / BatchCheckAccess <br/>*Process* | D | Batch amplification as a denial-of-service vector | Medium | Mitigated |
| T-84 | AMQP async authz consumer <br/>*Process* | I | Decision response delivered to the wrong reply queue | Medium | Mitigated |
| T-85 | RBAC engine (graph traversal, hierarchy, scopes) <br/>*Process* | E | Cross-tenant graph edge traversed during resolution | Critical | Mitigated |
| T-86 | RBAC engine (graph traversal, hierarchy, scopes) <br/>*Process* | D | Deep or cyclic resource hierarchy stalls resolution | Medium | Mitigated |
| T-87 | RBAC engine (graph traversal, hierarchy, scopes) <br/>*Process* | E | No deny-override in the additive cascade | Medium | Mitigated |
| T-88 | Decision cache <br/>*Process* | E | Stale allow served after revocation | High | Mitigated |
| T-89 | Decision cache <br/>*Process* | I | Cache key collision leaks a decision across subjects | High | Mitigated |
| T-90 | role / permission / resource graph <br/>*Store* | T | Direct edge insertion grants privilege silently | Critical | Mitigated |
| T-91 | audit_log (decisions & changes) <br/>*Store* | R | Denied decisions not recorded | Medium | Mitigated |
| T-92 | authz.request <br/>*Flow* | T | Request tampered in flight on the broker | High | Mitigated |
| T-190 | RBAC engine (graph traversal, hierarchy, scopes) <br/>*Process* | E | Cross-tenant reach granted by inference rather than by claim | Critical | Mitigated |
| T-191 | RBAC engine (graph traversal, hierarchy, scopes) <br/>*Process* | E | Organization-scoped resource grant honoured against a look-alike resource in another tenant | High | Mitigated |
| T-192 | Decision cache <br/>*Process* | E | Revoked organization-level role survives in other tenants' decision caches | High | Mitigated |
| T-193 | REST authz middleware <br/>*Process* | E | Active-tenant header reaches across organization boundaries | High | Mitigated |
| T-202 | REST authz middleware <br/>*Process* | E | Organization-level action authorized by permission alone, from the wrong scope within the organization | Critical | Mitigated |
| T-203 | role / permission / resource graph <br/>*Store* | T | Seeded tenant roles carry organization-level actions the guard has to refuse | High | Mitigated |
| T-204 | RBAC engine (graph traversal, hierarchy, scopes) <br/>*Process* | E | A tenant-scoped role assignment enforced on some paths and not others | High | Mitigated |
| T-205 | REST authz middleware <br/>*Process* | I | Deployment-wide rosters answer a principal whose reach is one tenant | High | Mitigated |
| T-226 | RBAC engine (graph traversal, hierarchy, scopes) <br/>*Process* | E | An upgrade turns dormant unscoped role assignments into live tenant-wide grants | High | Mitigated |
| T-227 | RBAC engine (graph traversal, hierarchy, scopes) <br/>*Process* | E | Scope inheritance down the hierarchy widens a grant to sibling or unrelated resources | High | Mitigated |
| T-228 | REST authz middleware <br/>*Process* | E | Two request extractors resolve the acting tenant separately, and one of them skips the reach check | High | Mitigated |
| T-285 | RBAC engine (graph traversal, hierarchy, scopes) <br/>*Process* | E | A non-inheritable role assignment reaches further, or less far, than it reads | High | Mitigated |

<details>
<summary>Threat detail and mitigations</summary>

**T-78 — Caller asserts a subject_id it does not own**  
`Microservice / PEP` (Actor) · Spoofing · Critical · Mitigated

CheckAccess takes subject_id as a parameter. A service account that can name any subject becomes a confused deputy and can enumerate or exercise anyone's entitlements.

> The gRPC interceptor authenticates the caller and derives the tenant from the verified JWT; a check for a subject outside the caller's tenant is refused. Grant the authz-check permission only to service accounts that are trusted policy enforcement points.

**T-79 — Replay of a previously valid signed authz message**  
`AMQP producer (deferred authz)` (Actor) · Spoofing · High · Mitigated

An HMAC alone proves origin and integrity but not freshness: a captured, correctly signed authz request or audit event can be republished indefinitely.

> CONTRACT §8 v2 (key_version = 2) binds a per-message nonce and an issued_at timestamp into the signed body. The server records (tenant_id, nonce) durably and rejects a duplicate within the freshness window, a stale or future issued_at, or any key_version below 2 — nack without requeue, no grace window.

**T-80 — Privileged grant made without attribution**  
`Tenant administrator` (Actor) · Repudiation · Medium · Mitigated

An administrator assigns a powerful role and later disputes it, or the change cannot be reconstructed during an incident.

> role.assigned and role.unassigned are audited with actor, target and resource, emitted as webhook events, and can raise an admin notification under the Access category.

**T-81 — Endpoint reachable without an authorization check**  
`REST authz middleware` (Process) · Elevation of privilege · Critical · Mitigated

A handler registered outside the guarded scope — or a new route added without its permission annotation — is reachable by any authenticated caller.

> Required permissions are declared centrally in the REST permissions table rather than ad hoc per handler, and the middleware default is deny; a route with no declared permission is refused rather than allowed.

**T-82 — Batch check used as an entitlement oracle**  
`gRPC CheckAccess / BatchCheckAccess` (Process) · Information disclosure · Medium · Mitigated

BatchCheckAccess answers many questions per call, so a caller can map another subject's complete entitlement surface cheaply.

> Batch size is bounded, the caller is authenticated and tenant-scoped, and gRPC rate limiting applies per caller.

**T-83 — Batch amplification as a denial-of-service vector**  
`gRPC CheckAccess / BatchCheckAccess` (Process) · Denial of service · Medium · Mitigated

One request expanding into thousands of graph traversals amplifies a modest request rate into heavy datastore load.

> Batch size limits, per-caller rate limiting and the decision cache bound the work a single caller can induce.

**T-84 — Decision response delivered to the wrong reply queue**  
`AMQP async authz consumer` (Process) · Information disclosure · Medium · Mitigated

If the reply-to address is taken from the message without checks, a producer can direct another tenant's decision to a queue it controls.

> Responses are correlated by the signed correlation id and published to the configured response queue; the decision is tenant-scoped to the verified producer identity.

**T-85 — Cross-tenant graph edge traversed during resolution**  
`RBAC engine (graph traversal, hierarchy, scopes)` (Process) · Elevation of privilege · Critical · Mitigated

Permission resolution walks has_role, member_of, grants, on_resource and child_of edges. An edge that crosses tenants — however it was created — would grant access across the isolation boundary.

> Traversal results are filtered to the caller's tenant and cross-tenant edges are stripped rather than followed (CQ-B07 / CQ-B50 / CQ-B52).

**T-86 — Deep or cyclic resource hierarchy stalls resolution**  
`RBAC engine (graph traversal, hierarchy, scopes)` (Process) · Denial of service · Medium · Mitigated

Ancestor walking on a deliberately deep — or cyclic — resource tree turns a single check into an expensive traversal.

> Traversal depth is bounded and visited nodes are tracked so a cycle terminates; the decision cache absorbs repeated checks on the same subject/resource pair.

**T-87 — No deny-override in the additive cascade**  
`RBAC engine (graph traversal, hierarchy, scopes)` (Process) · Elevation of privilege · Medium · Mitigated

The engine is allow-wins with default deny and no explicit deny. A role granted on a parent resource cascades to every child and cannot be revoked on one child alone.

> SEC-040 — **CLOSED (B1).** Explicit deny is implemented; a deny grant
> overrides every allow at any depth. Modelling exclusions by granting lower in
> the hierarchy is still valid, but it is no longer the only option. See
> `claude_dev/deny-override-design.md`.
>
> **Amended 2026-09-22 (T22.11, DF-021).** "Cannot be revoked on one child
> alone" no longer holds in the other direction either: an assignment made with
> `inherit: false` applies at its resource and at no descendant, so a parent
> grant need not cascade at all. It stops allows and denies alike and changes
> applicability, not precedence — a non-inheritable allow below an inheritable
> deny is still denied. See T-285.

**T-88 — Stale allow served after revocation**  
`Decision cache` (Process) · Elevation of privilege · High · Mitigated

A cached allow decision keeps granting access after the role or group membership behind it has been removed.

> Cache entries carry a short TTL and are invalidated on the mutations that can change a decision (role assignment, group membership, resource re-parenting). The residual exposure is bounded by the TTL and is documented in the decision-cache design note.

**T-89 — Cache key collision leaks a decision across subjects**  
`Decision cache` (Process) · Information disclosure · High · Mitigated

A key that omits tenant, subject, action, resource or scope would return one subject's decision to another.

> The cache key includes every input to the decision — tenant, subject, action, resource and scopes — so distinct questions cannot collide.

**T-90 — Direct edge insertion grants privilege silently**  
`role / permission / resource graph` (Store) · Tampering · Critical · Mitigated

Writing a has_role or grants edge straight into the datastore confers privilege without passing any API authorization check and without an audit record.

> Datastore access is restricted to the service credentials on the private data tier; all supported mutation paths go through the API and are audited. Datastore-level access must be treated as equivalent to full administrative compromise.

**T-91 — Denied decisions not recorded**  
`audit_log (decisions & changes)` (Store) · Repudiation · Medium · Mitigated

Without a record of denials there is no signal for probing or privilege-escalation attempts during an investigation.

> Authorization outcomes are written with an explicit outcome field covering both allow and deny, so denial patterns are queryable and can drive the security notification category.

**T-92 — Request tampered in flight on the broker**  
`authz.request` (Flow) · Tampering · High · Mitigated

A party with broker access modifies subject, action or resource between publish and consume.

> Messages carry an HMAC signature over the payload that the consumer verifies before evaluating; the broker connection is TLS-only — `AXIAM__AMQP__URL` must be `amqps://` and every other scheme is refused before a socket is opened, in a debug build exactly as in a release one, with the `AXIAM__AMQP__ALLOW_PLAINTEXT` escape hatch removed.

**T-190 — Cross-tenant reach granted by inference rather than by claim**  
`RBAC engine (graph traversal, hierarchy, scopes)` (Process) · Elevation of privilege · Critical · Mitigated

AccessRequest carried subject_tenant_id: Option<Uuid>, and the engine treated two tenant ids differing as authority to read a subject's grants across the tenant boundary. Any caller that built a request for a subject in tenant A about tenant B got cross-tenant reach for free, so an ordinary global admin role applied in every tenant of the deployment — the exact opposite of what a tenant is.

> Fixed in 1.0.0-beta02: SubjectScope names the claim. Tenant is every ordinary principal and pins the assignment tenant to the target, so a tenant principal cannot express cross-tenant reach at all, whatever tenant it names. Organization is a statement a caller has to make deliberately — no combination of ordinary values produces it — and its sole production producer is the REST extractor, which resolves the tenant record and checks it is the organization's reserved scope before setting the flag. organization_scope_test asserts both properties directly, plus the case the fix must not break: an organization-level principal acting on the organization tenant still gets resource-scoped evaluation there.

**T-191 — Organization-scoped resource grant honoured against a look-alike resource in another tenant**  
`RBAC engine (graph traversal, hierarchy, scopes)` (Process) · Elevation of privilege · High · Mitigated

An organization-level principal's resource-scoped assignment names a resource in the organization's reserved tenant. A same-named resource in a member tenant is a different thing, and honouring the assignment against it would be a silent escalation between isolated tenants.

> One rule, stated once in AuthorizationEngine::evaluate (1.0.0-beta02): when a subject's grants are read across a tenant boundary, only global grants carry. check_access_batch applies the identical rule through the same helper, so a batched decision stays byte-identical to a per-item one. Deny override, scope narrowing and group inheritance are unchanged. Access is derived at check time rather than fanned out at tenant creation, so a tenant created later is governed by the same rule with no backfill, and revoking the organization role revokes everywhere because there is only one copy.

**T-192 — Revoked organization-level role survives in other tenants' decision caches**  
`Decision cache` (Process) · Elevation of privilege · High · Mitigated

The decision cache shards by the tenant a decision was about, while an organization-level principal's roles live in exactly one tenant. Invalidating only the shard of the tenant the mutation happened in would leave a freshly revoked administrator holding cached allows in every other tenant until the TTL expired.

> invalidate_subject sweeps every shard (1.0.0-beta02); a subject id is unique across the deployment, so the sweep removes exactly that subject's entries and nothing else. SubKey carries subject_tenant_id, so cache-key correctness does not depend on a subject's home tenant being fixed.

**T-193 — Active-tenant header reaches across organization boundaries**  
`REST authz middleware` (Process) · Elevation of privilege · High · Mitigated

An organization-level principal selects the tenant it is acting in with the X-Axiam-Tenant header. Accepted unverified, that header would let organization scope cross organization boundaries too — which is the one isolation an organization is.

> The header is verified to name a tenant inside the caller's own organization before any scope is derived, and the check fails closed: no tenant resolver registered means the header is refused (1.0.0-beta02). For an ordinary tenant principal the same header change is a 403 — CONTRACT §5.2 states the SDK-visible half: organization_level is derived server-side and response-only, and a tenant-switch helper may exist only where it is true. Since 1.0.0-beta09 the same resolution serves the `AuthenticatedPrincipal` extractor the authorization-check endpoints bind, through one implementation rather than a second copy (T-228).

**T-202 — Organization-level action authorized by permission alone, from the wrong scope within the organization**  
`REST authz middleware` (Process) · Elevation of privilege · Critical · Mitigated

Organization-level handlers checked the permission and that the target organization was the caller’s own — a bar every principal in the organization clears — and a tenant’s seeded super-admin holds the entire permission registry. Signed in as an ordinary tenant administrator, creating organizations, creating tenants, generating CAs and — the serious one — flipping a CA’s mTLS trust-anchor flag all succeeded (B-04). The tenant administrator holds that CA’s private key, so it could mint certificates authenticating as principals in sibling tenants: the isolation boundary the product is built on, crossed from inside. The same shape recurred on POST /api/v1/mds/refresh (B-08), where a tenant administrator could rewrite the server-global FIDO attestation trust picture, and on /auth/me, which prefixed the * wildcard for any principal holding a role merely named super-admin (B-09), so the admin UI offered controls the server would refuse.

> Fixed in 1.0.0-beta05: require_organization_principal guards all sixteen organization-level handlers plus MDS refresh, keyed on where the caller’s record lives — principal_tenant_id resolving to the organization’s reserved scope — rather than on what its roles carry, deliberately not on AuthenticatedUser::organization_level, which is false for exactly the calls that needed guarding; it fails closed when the home tenant cannot be resolved. Reads are untouched. /auth/me emits the wildcard only when the same predicate resolves the caller into the organization scope, and drops it when the tenant cannot be resolved — a control hidden from someone who could use it is the cheaper mistake than one offered to someone the server refuses. Pinned by paired tests in both directions and by the E2E permission matrix run against the production image.

**T-203 — Seeded tenant roles carry organization-level actions the guard has to refuse**  
`role / permission / resource graph` (Store) · Tampering · High · Mitigated

After B-04’s scope guard landed, every tenant’s seeded super-admin still held ca_certificates:manage, organizations:create, tenants:delete and the rest — the grant data and the guard disagreed, and only one of them was saying no. Grants the API must never honour sitting in the graph are a standing hazard: any future handler registered without the scope guard, or any consumer trusting the stored edges, re-opens B-04 from the data side.

> Fixed in 1.0.0-beta05: ORGANIZATION_LEVEL_ACTIONS in axiam-core is the single nine-action, exact-match list both layers read. The seeder withholds those actions from an ordinary tenant’s super-admin and admin roles, and the reconciler learned to revoke — deliberately narrow: only the three seeded default roles, only the listed actions, only outside the organization scope, with a WARN naming each tenant it touches, so an operator’s own custom grants are never swept. The invariant — an action can be withheld only if every handler requiring it is scope-guarded — is enforced by a consistency test that reads the handler sources and fails in both directions; email_config:write is deliberately excluded because it also guards a tenant’s own mail configuration. Operational note: on the first boot after upgrade the revocation removes grants the scope guard was already refusing, so no working call stops working.

**T-204 — A tenant-scoped role assignment enforced on some paths and not others**  
`RBAC engine (graph traversal, hierarchy, scopes)` (Process) · Elevation of privilege · High · Mitigated

1.0.0-beta05 adds tenant_scope to role assignments (schema 51 — additive, no backfill, every existing assignment stays unrestricted): an organization-level account can be confined to particular tenants of its organization. A restriction is only as strong as its weakest enforcement point — a path that forgot the filter (the batch engine, an organization-level endpoint that names no tenant, the X-Axiam-Tenant switch, the tenant roster) would leave a confined administrator estate-wide reach through that one door. Two subtleties invited exactly that: the batch path shares one cached assignment vector across items naming different tenants, and the filter must compare against the tenant being acted on rather than the tenant the grants live in — which for this principal is the organization tenant every time, making every restriction vacuous.

> tenant_scope_reaches is written once in axiam-core and read by every consumer, so the engine, /auth/me and the tenant listing cannot drift apart on the rule. Enforced at four sites: the engine’s single and batch paths (the batch filter applied per item against each request’s tenant), require_organization_principal (an action naming no tenant is refused to a restricted account, with a reason naming the restriction), require_organization_principal_for_tenant for organization actions that name one tenant, and the header resolver refusing X-Axiam-Tenant for any tenant outside the account’s reach. Holding no roles is Unrestricted rather than confined-to-nothing, so the permission check refuses for the right reason; one unrestricted assignment makes the whole set unrestricted; an empty scope cannot be created; accepted scopes are deduplicated and sorted so equal grants store identically. /auth/me reports reachable_tenant_ids and withholds the * wildcard from a restricted principal (CONTRACT §5.2.3, contract 1.35). Pinned by engine property tests, a 14-case REST suite and a dedicated E2E matrix principal.

**T-205 — Deployment-wide rosters answer a principal whose reach is one tenant**  
`REST authz middleware` (Process) · Information disclosure · High · Mitigated

GET /api/v1/organizations returned every organization in the deployment to any principal holding a super-admin role — a role seeded per tenant — so one customer’s tenant administrator could enumerate the name and slug of every other customer in the same installation. Inside one organization, GET /organizations/{id}/tenants showed the whole tenant roster to every holder of tenants:list (W5-03): names, slugs and creation dates of sibling workspaces that the isolation boundary exists to hide from a confined administrator.

> Fixed in 1.0.0-beta05: the organization listing returns the caller’s own organization and nothing else — the rule the by-id endpoint already applied. The tenant roster is filtered to the caller’s reach: a tenant administrator sees its own tenant, a restricted organization principal the tenants its assignments name (dangling ids silently dropped), an unrestricted one the whole roster — the reserved organization scope included, because an organization administrator acts on it and filtering it out server-side would put it beyond the API; the admin console drops it where offering it would be wrong. The permission question is asked in a tenant the caller actually reaches, so a confined account can read the one list that says which tenants it administers, and the cross-organization refusal is answered before the reach check so the error names the right reason instead of describing an organization that is not the caller’s.

**T-226 — An upgrade turns dormant unscoped role assignments into live tenant-wide grants**  
`RBAC engine (graph traversal, hierarchy, scopes)` (Process) · Elevation of privilege · High · Mitigated

Before 1.0.0-beta09, assigning a role to a user or group without naming a resource granted nothing, anywhere, unless the role also carried `is_global`: the write succeeded, the assignment listed back correctly, and every check against it answered "no applicable roles for this resource" — which reads as though the resource were at fault rather than the assignment being inert. That contradicted the meaning the model gives the field in three places: `AssignmentScope::global()` is named for it, and both `AssignmentScope::resource_id` and `RoleAssignment::resource_id` document `None` as "every resource in reach". Two hazards follow. An operator who scoped a grant, saw no access, and removed the scope to widen it got the same refusal with nothing anywhere to say why — the pressure that produces global roles and over-broad grants. And once the engine honours the field, every assignment written into the inert state becomes a live tenant-wide grant at the moment of upgrade, with nobody having decided that.

> Fixed in 1.0.0-beta09. `applicable_role_ids` now treats an assignment naming no resource as tenant-wide, which is what the field has always been documented to mean; `is_global` keeps its own, independent meaning as a property of the role, so a global role still applies even when the assignment does name a resource — two ways to say "everywhere", both honoured. Tenant-wide, not organization-wide: `global_role_ids`, the path an organization-level principal takes across a tenant boundary, is deliberately unchanged, so an unscoped assignment in an organization's own tenant does not reach every tenant of that organization, and the organization-scope tests pin that boundary. Two regression tests reproduce the report that found this, one per half; the scoped half already passed and is kept because it proves groups, hierarchy cascade and scoped grants were never the problem. The upgrade hazard is handled as an upgrade note in `docs/admin/README.md`: what changes, and how to find assignments sitting in the inert state so an administrator reviews them before the upgrade makes them live. The effective-access preview in the admin UI now lists the tenant's own permissions rather than a hard-coded read/write/delete/admin vocabulary, and says so when the action typed matches none of them, so an administrator debugging a grant is no longer offered an action that does not exist.

**T-227 — Scope inheritance down the hierarchy widens a grant to sibling or unrelated resources**  
`RBAC engine (graph traversal, hierarchy, scopes)` (Process) · Elevation of privilege · High · Mitigated

A `Scope` belongs to exactly one resource and scope names are unique per resource — the auto-seeded name embeds the resource id precisely so two levels do not collide — so a parent's `billing` scope and a child's are always different records. Before 1.0.0-beta09 both halves of the engine compared them by id: `grant_applies` required the requested scope id to appear in the grant's `scope_ids`, so a grant written on a parent's scope matched nothing below it (reported as "no permission grants action", as though the permission were missing), and `resolve_scope` looked a name up only on the target resource, so asking about a scope the resource inherits was refused as malformed. Making scopes inherit down the lineage is the correct semantics, and it carries the hazard the fix has to avoid: reading "the requested scope is not one of my scopes" as "therefore unconstrained" would turn every scoped grant in the tenant into a wildcard on every other resource, and inheriting sideways would let a grant on `billing` reach `payroll` beside it. An authorization answer that depended on the order ancestors happen to be returned in would be a second, quieter defect.

> Fixed in 1.0.0-beta09. A grant naming a scope constrains the resource that scope lives on, and below it the grant is inherited whole — every scope of every descendant — until a deny says otherwise; denies inherit by the same rule, which is what makes a scoped deny on a parent a way to carve a subtree out of a broad grant. Two things deliberately do not widen, each pinned by a test: on the scope's own resource the constraint still bites (a grant on `billing` does not reach `payroll`), and a scope on an unrelated resource still grants nothing. Name resolution is nearest-first over the lineage — the resource's own scope beats an ancestor's of the same name, a nearer ancestor beats a further one — and the batch path keeps that order alongside the id set it already had, because an authorization answer that depends on row order is not an answer. `ScopeRepository::list_by_resources` reads the whole lineage in one bound-array `IN` query, the same shape as the `has_role` and `grants` reads, and `lineage_scope_lookup_is_index_satisfied` pins that `idx_scope_resource_name` serves it, so the correct semantics did not buy an unindexed scan on the hot path. The coalesced batch path mirrors all of it, and `batched_decisions_match_per_item_decisions_across_scopes` holds the two paths to the same answers.

**T-228 — Two request extractors resolve the acting tenant separately, and one of them skips the reach check**  
`REST authz middleware` (Process) · Elevation of privilege · High · Mitigated

The authorization-check endpoints are the only ones that bind `AuthenticatedPrincipal` rather than `AuthenticatedUser`, and the two extractors had a field of the same name meaning different things: `AuthenticatedUser::tenant_id` is the tenant being acted upon, resolved from the `X-Axiam-Tenant` header through the organization-reach check (T-193, T-204), while `AuthenticatedPrincipal::tenant_id` was the raw claim — the caller's own tenant. The visible symptom was fail-closed: every effective-access preview an organization-level administrator ran was evaluated in the organization's own tenant, where the subject being asked about has no assignments, and answered `no roles assigned` against a correct rule set. The structural hazard is worse than the symptom. The reach check is the only thing standing between "acting on another tenant" and "asserting another tenant's grants", and a second copy of it — or, as here, a second extractor with none — is exactly how the guard drifts on one path and not the others. The handler also hard-coded `SubjectScope::Tenant`, which is right for a checked-as subject (an ordinary member of the tenant being acted upon) and wrong for an organization principal asking about its own access, whose roles live in its own tenant.

> Fixed in 1.0.0-beta09. `AuthenticatedPrincipal` resolves the acting tenant exactly as `AuthenticatedUser` does — same header, same tenant lookup, same reach check, same refusal when the caller's own tenant is not the organization scope — through one implementation, `resolve_active_tenant_for`, keyed on the home tenant id, so there is one copy of the check and both extractors run it. The session-revocation check keeps reading the principal's own tenant and still runs before the header is applied, which is where the session row lives. Both call sites pick the subject scope rather than hard-coding it, and the `authz:check_as` guard reads the caller's grants through `subject_scope()` for the same reason — with the fixed scope it looked for the permission in the wrong tenant and would refuse a caller that holds it. Only `authz_check.rs` binds this extractor, so the blast radius was the two check endpoints; a regression test pins the tenant a check is evaluated in.

**T-285 — A non-inheritable role assignment reaches further, or less far, than it reads**  
`RBAC engine (graph traversal, hierarchy, scopes)` (Process) · Elevation of privilege · High · Mitigated

DF-021 asked for a role assignment that applies at its resource and not below it. `inherit: false` on the `has_role` edge does that, and it can go wrong three ways. **It can be honoured on one path and not another.** The engine decides through `evaluate` and, for batches, `evaluate_batch`, and an assignment reaches a subject through two different SELECTs — direct and group-inherited — so a flag read on one of them leaves a non-inheritable allow cascading to every descendant on the other; `deny-override-design.md` §5.1 records that exactly this class of regression in `applicable_role_ids` leaves every evaluator unit test green. **It can be stored where the engine ignores it** — an assignment naming no resource, or one of an `is_global` role — so an operator believes access stops at a node when it does not. **And it moves access in both directions:** `false` on an allow narrows, but `false` on a deny re-opens every descendant the deny covered, so a silent in-place toggle, or one a decision cache does not see, would widen access with nobody reviewing it.

> **T22.11 (2026-09-22).** One clause in `applicable_role_ids` — the assignment's own resource always applies, an ancestor's only when `inherit` is true — shared by `evaluate` and `evaluate_batch`. The repository reads the field in both the direct and the group-inherited SELECT and in every assignment listing. Schema v66 adds it as `option<bool>` with no backfill, and absent reads as `true`, so every existing assignment and every client that does not send the field keeps its meaning.
>
> The three assign routes (user, group, service account) refuse `inherit: false` with **400** when no `resource_id` is named and when the role is global, each with an I4 twin that the same request without the field, or with `true`, is accepted. There is no update: `has_role` is `UNIQUE(in, out)`, so changing the flag is an unassign and an assign, each of which invalidates the subject's cached decisions (the tenant's, for a group), and the `grant.pre_assign` four-eyes hook payload carries `inherit`.
>
> Property tests over every rule set of a three-node chain: adding a deny never widens access whatever its flag; `false` on an allow never widens; `false` on a deny can, with row 10 as the asserted witness. Rows 9–11 are proved end to end through both `evaluate` and `evaluate_batch`, for a group-inherited assignment, and over gRPC `CheckAccess` and `BatchCheckAccess`. The clause was broken on purpose — the `inherit` guard alone, then the whole ancestor term — and the new tests went red both times.
>
> Residual, documented in `docs/admin/README.md`: making a role global *after* assigning it non-inheritably widens that assignment to everywhere, as it widens every assignment of the role; and the admin console does not yet offer the flag, so it is set through the API.

</details>

### 5.6 PKI, certificates & IoT device identity

Organization and tenant CA lifecycle with per-CA key custody (sealed database row or Vault), tenant signing CAs beneath the organization CA, tenant certificate issuance with policy enforcement, mTLS device and workload authentication with full chain verification against hot-reloadable trust anchors, revocation and CRL, and the OpenPGP key service used for audit signing and GDPR export encryption. Extended for X3 with FIDO MDS3 metadata ingestion (BLOB trust-chain verification, rollback protection, staleness posture) feeding the WebAuthn attestation policy engine. 1.0.0-beta13 lets the listener admit RFC 8705 §2.2 self-signed client certificates under an opt-in policy, with the trust level a certificate earned carried to every consumer so that device authentication can refuse it (T-263).

*29 threats — 7 critical, 17 high, 5 medium; 1 open.*

| # | Element | STRIDE | Threat | Severity | Status |
|---|---|:-:|---|---|---|
| T-93 | Organization administrator <br/>*Actor* | S | CA generation or import without effective authorization | Critical | Mitigated |
| T-94 | IoT device <br/>*Actor* | S | Key extracted from device firmware or flash | High | Open |
| T-95 | CA management (generate / upload / rotate) <br/>*Process* | I | CA private key exfiltration | Critical | Mitigated |
| T-96 | CA management (generate / upload / rotate) <br/>*Process* | T | Weak key material from poor entropy | High | Mitigated |
| T-97 | Certificate issuance (rcgen, policy enforcement) <br/>*Process* | E | Certificate issued beyond the tenant's validity policy | Medium | Mitigated |
| T-98 | Certificate issuance (rcgen, policy enforcement) <br/>*Process* | E | Certificate issued for another tenant's subject | Critical | Mitigated |
| T-99 | Certificate issuance (rcgen, policy enforcement) <br/>*Process* | I | Returned private key persisted in logs or audit records | High | Mitigated |
| T-100 | mTLS device auth (fingerprint + chain verify) <br/>*Process* | S | Fingerprint match accepted without chain verification | Critical | Mitigated |
| T-101 | mTLS device auth (fingerprint + chain verify) <br/>*Process* | S | Expired certificate still accepted | Medium | Mitigated |
| T-102 | Revocation & CRL <br/>*Process* | S | Revoked certificate honoured until the CRL refreshes | High | Mitigated |
| T-103 | OpenPGP key service (audit signing, GDPR export) <br/>*Process* | T | Substituted PGP key invalidates audit tamper-evidence | High | Mitigated |
| T-104 | certificate (public certs, fingerprints) <br/>*Store* | T | Certificate status flipped back to active | High | Mitigated |
| T-105 | certificate + private key (once) <br/>*Flow* | I | Private key intercepted on its single delivery | Critical | Mitigated |
| T-150 | FIDO MDS3 ingestion (BLOB verify, X3) <br/>*Process* | S | Public-CA root proves "a GlobalSign EV customer", not "FIDO Alliance" | High | Mitigated |
| T-151 | FIDO MDS3 ingestion (BLOB verify, X3) <br/>*Process* | T | Vendored trust anchor silently swapped for an attacker-controlled root | Critical | Mitigated |
| T-152 | FIDO MDS3 ingestion (BLOB verify, X3) <br/>*Process* | T | Older MDS BLOB replayed to reintroduce a since-revoked authenticator | High | Mitigated |
| T-153 | FIDO MDS3 ingestion (BLOB verify, X3) <br/>*Process* | E | Stale MDS metadata leaves a newly-revoked authenticator treated as compliant | Medium | Mitigated |
| T-154 | mds_entry / mds_blob_meta (global, X3) <br/>*Store* | T | MDS entry status edited directly in the datastore to hide a revocation | High | Mitigated |
| T-194 | CA management (generate / upload / rotate) <br/>*Process* | E | Tenant CSR signed into an unconstrained CA, or onto a key the requester does not hold | High | Mitigated |
| T-195 | Certificate issuance (rcgen, policy enforcement) <br/>*Process* | E | One tenant's compromised issuance burns the organization trust anchor | High | Mitigated |
| T-196 | ca_certificate (sealed row or Vault custody) <br/>*Store* | I | Vault configured, CA keys silently sealed into database rows | High | Mitigated |
| T-197 | CA management (generate / upload / rotate) <br/>*Process* | D | Custody migration destroys the only copy of a CA signing key | High | Mitigated |
| T-198 | mTLS device auth (fingerprint + chain verify) <br/>*Process* | S | Revoked or unflagged CA lingers in the mTLS trust-anchor bundle | Medium | Mitigated |
| T-206 | mTLS device auth (fingerprint + chain verify) <br/>*Process* | S | Certificate chaining to a CA never enabled as a trust anchor authenticates on the proxy path | High | Mitigated |
| T-263 | mTLS device auth (fingerprint + chain verify) <br/>*Process* | E | Accepting an unchained certificate for RFC 8705 §2.2 lets a self-minted certificate authenticate as a device or as a `tls_client_auth` client | Critical | Mitigated |
| T-268 | Certificate issuance (rcgen, policy enforcement) <br/>*Process* | E | Leaf CSR signed with the requester's extensions, a weak key, or onto a key the requester does not hold | High | Mitigated |
| T-281 | Certificate issuance (rcgen, policy enforcement) <br/>*Process* | E | A tenant administrator issues a leaf under another tenant's signing CA, or directly under the organization anchor | High | Mitigated |
| T-282 | mTLS device auth (fingerprint + chain verify) <br/>*Process* | D | The one auth endpoint that performs a client-certificate handshake has no rate limiter | Medium | Mitigated |
| T-283 | mTLS device auth (fingerprint + chain verify) <br/>*Process* | S | A device's access token is a bearer credential, so stealing it is as good as stealing the key | High | Mitigated |

<details>
<summary>Threat detail and mitigations</summary>

**T-93 — CA generation or import without effective authorization**  
`Organization administrator` (Actor) · Spoofing · Critical · Mitigated

Whoever can create or import an organization CA controls the root of trust for every tenant beneath it and can mint identities at will.

> CA operations are organization-scoped and require an organization-level administrative permission; every operation is audited and raises an admin notification.

**T-94 — Key extracted from device firmware or flash**  
`IoT device` (Actor) · Spoofing · High · Open

A physically accessible device may yield its private key from unprotected flash, allowing an indefinite clone until the certificate is revoked.

> Outside AXIAM's control: private keys are generated for the device and returned once, never stored server-side, but hardware protection is the integrator's responsibility. AXIAM limits the blast radius with per-device certificates, a maximum validity policy and immediate revocation.

**T-95 — CA private key exfiltration**  
`CA management (generate / upload / rotate)` (Process) · Information disclosure · Critical · Mitigated

The signing CA key allows forging any tenant, user, service or device identity in the organization.

> User-generated CAs are returned once and never stored. Only signing CAs whose key AXIAM must hold are persisted, and those are AES-256-GCM encrypted at rest in a separate, access-controlled table with the key held outside the datastore. Since 1.0.0-beta01 custody is recorded per CA and may instead be Vault — vault holds the sealed key, vault_pki has Vault hold a key it never hands over — the configured Vault is inherited for new keys, and an explicit database choice beside a working Vault is a startup warning naming the exposure (see T-196, T-197).

**T-96 — Weak key material from poor entropy**  
`CA management (generate / upload / rotate)` (Process) · Tampering · High · Mitigated

A CA or leaf key generated from a weak source is factorable or predictable, silently invalidating the whole hierarchy.

> Key generation uses the platform CSPRNG — Ed25519 through rcgen/ring, RSA-4096 through the rsa crate's OS-seeded generator handed to rcgen as PKCS#8, since ring deliberately implements no RSA key generation (1.0.0-beta01). No custom or seeded RNG is used anywhere in the PKI path. **Extended 2026-09-13 (C-1):** a key AXIAM did not generate now reaches the PKI path, through `POST /api/v1/certificates/sign-csr`, where entropy is the caller's problem and *size* is AXIAM's. The CSR's modulus is measured and an RSA key below 4096 bits is refused, rather than mapped onto `KeyAlgorithm::Rsa4096` by the any-RSA-OID rule `parse_ca_certificate` applies to imported CAs — which would have signed a 2048-bit key and written 4096 on the row. See T-268.

**T-97 — Certificate issued beyond the tenant's validity policy**  
`Certificate issuance (rcgen, policy enforcement)` (Process) · Elevation of privilege · Medium · Mitigated

An over-long certificate outlives the review cycle and cannot be retired without an explicit revocation.

> max_certificate_validity_days is an org/tenant setting, and the hierarchical settings rule means a tenant can only make it stricter, never longer, than the organization baseline. Since 1.0.0-beta01 issuance also refuses a validity that would outlive the issuing CA and quotes the achievable number, rather than silently truncating to the issuer's notAfter — a truncation that left renewal calendars built on a date the certificate does not carry.

**T-98 — Certificate issued for another tenant's subject**  
`Certificate issuance (rcgen, policy enforcement)` (Process) · Elevation of privilege · Critical · Mitigated

Issuing under a subject belonging to a different tenant would produce a credential that authenticates across the isolation boundary.

> Issuance is tenant-scoped from the authenticated context, and the signing CA is resolved from the requesting tenant's organization — a cross-tenant subject cannot be signed. Tenant signing CAs (1.0.0-alpha44) narrow the blast radius further: issuance for a tenant is anchored at that tenant's path-length-zero intermediate, so a compromised or misused issuer is revocable without touching any other tenant.
>
> **Corrected 2026-09-22 (S-1).** The second sentence described what tenant signing CAs made *possible*, and read as though it were enforced. It was not: the issuing CA was resolved from the requesting tenant's **organization** and nothing compared it against the tenant, so a tenant administrator could anchor its issuance at any tenant's intermediate, or at the organization CA above them all. The subject half of this entry held throughout — `tenant_id` has come from the authenticated context since T-98 was written — but a leaf's authority comes from its chain and not from the row, so the half that failed is the half that mattered. **T-281** carries the defect, the fix and its tests; this entry is left as the record of a claim the code did not keep, which is the more useful thing for it to be.

**T-99 — Returned private key persisted in logs or audit records**  
`Certificate issuance (rcgen, policy enforcement)` (Process) · Information disclosure · High · Mitigated

The generated private key is returned once in the API response; if it reaches a log line or an audit payload it becomes durably stored in the clear.

> Key material is excluded from audit payloads, and secret-bearing types carry manual Debug implementations so they cannot reach a trace or error line (SEC-067 / SECHRD-09).

**T-100 — Fingerprint match accepted without chain verification**  
`mTLS device auth (fingerprint + chain verify)` (Process) · Spoofing · Critical · Mitigated

Authenticating on a stored SHA-256 fingerprint alone lets any certificate whose fingerprint was registered — by any means — authenticate as that device.

> SEC-024: after the fingerprint lookup the client certificate is cryptographically verified against the CA returned by the CA repository, and the call fails closed when no active CA exists.

**T-101 — Expired certificate still accepted**  
`mTLS device auth (fingerprint + chain verify)` (Process) · Spoofing · Medium · Mitigated

Skipping validity-period checks lets a retired device certificate keep working indefinitely.

> not_before and not_after are enforced at authentication time against the current clock, in addition to the stored status.

**T-102 — Revoked certificate honoured until the CRL refreshes**  
`Revocation & CRL` (Process) · Spoofing · High · Mitigated

If relying parties depend only on a periodically published CRL, a revoked device keeps authenticating for the refresh interval.

> AXIAM checks certificate status in its own store on every mTLS authentication, so revocation takes effect immediately for AXIAM-terminated connections. External relying parties consuming the CRL remain bound by its publication interval.

**T-103 — Substituted PGP key invalidates audit tamper-evidence**  
`OpenPGP key service (audit signing, GDPR export)` (Process) · Tampering · High · Mitigated

If the audit-signing key can be replaced, an attacker can rewrite audit batches and re-sign them so verification still passes.

> PGP key management is tenant-scoped and administratively audited, key rotation is itself an audited event, and verification pins the key fingerprint recorded with the batch.

**T-104 — Certificate status flipped back to active**  
`certificate (public certs, fingerprints)` (Store) · Tampering · High · Mitigated

Editing a revoked certificate's status directly in the datastore silently restores a credential that was withdrawn.

> Status transitions go through the audited API path; direct datastore write access is restricted to the service credentials on the private data tier and is treated as full administrative compromise.

**T-105 — Private key intercepted on its single delivery**  
`certificate + private key (once)` (Flow) · Information disclosure · Critical · Mitigated

The generated private key crosses the network exactly once, in the issuance response; interception yields a complete, indefinitely usable identity.

> Delivery is over TLS 1.3 only, the key is never persisted server-side and is never repeated in any later response, and the issuance is audited so an unexpected issuance is visible.

**T-150 — Public-CA root proves "a GlobalSign EV customer", not "FIDO Alliance"**  
`FIDO MDS3 ingestion (BLOB verify, X3)` (Process) · Spoofing · High · Mitigated

GlobalSign Root CA – R3 is a public CA root sitting above the entire public web, not just the FIDO Alliance. Chain-verifying `x5c` up to that root alone is satisfied by any genuine end-entity certificate an attacker can obtain under the same public root, spliced beneath a self-minted leaf carrying whatever SAN the attacker chose.

> The leaf must additionally carry the pinned hostname (`mds.fidoalliance.org`) as a SAN DNS entry (CN fallback only when no SAN extension exists), and every issuing position in the chain must be a real CA (`basicConstraints` `CA=true`, and `keyCertSign` when `keyUsage` is present) with `pathLenConstraint` enforced — closing the ordinary-end-entity-certificate splice that signature verification alone would miss (`axiam-pki::mds::blob::assert_is_issuer`).

**T-151 — Vendored trust anchor silently swapped for an attacker-controlled root**  
`FIDO MDS3 ingestion (BLOB verify, X3)` (Process) · Tampering · Critical · Mitigated

The vendored root certificate is the root of trust for every attestation decision the policy engine makes; a swapped file would convert "only FIDO-certified authenticators may register" into "any authenticator an attacker can mint an attestation chain for" — a security regression that produces no test failure and no error, only a bad key.

> The loader recomputes the SHA-256 of the vendored PEM's DER bytes against a pinned hex constant (`FIDO_MDS_ROOT_SHA256_HEX`) on every use and fails closed on any mismatch. Matching the digest is the check; the anchor is never re-fetched from anywhere at runtime. The documented update procedure requires updating the file and the pinned digest in the same reviewed commit.

**T-152 — Older MDS BLOB replayed to reintroduce a since-revoked authenticator**  
`FIDO MDS3 ingestion (BLOB verify, X3)` (Process) · Tampering · High · Mitigated

A validly-signed but older BLOB (a captured earlier serial, or a compromised/rolled-back distribution point) could overwrite newer entries and quietly re-admit an authenticator model FIDO has since revoked or decertified.

> Ingestion compares the freshly-verified BLOB's serial (`no`) against the stored serial before replacing entries: a lower serial is rejected outright as a rollback, an equal serial only bumps `last_refreshed_at`, and only a strictly higher serial replaces stored entries (`axiam_pki::mds::decide_ingest_outcome`, applied by the `axiam-db` ingestion orchestrator).

**T-153 — Stale MDS metadata leaves a newly-revoked authenticator treated as compliant**  
`FIDO MDS3 ingestion (BLOB verify, X3)` (Process) · Elevation of privilege · Medium · Mitigated

A BLOB past its own `nextUpdate` date is deliberately not treated as a hard failure — ingestion still succeeds so a transient FIDO Alliance outage cannot brick registration — but this means an authenticator model FIDO has revoked or decertified since the last successful refresh keeps passing `block_revoked_status` / `require_fido_certified` / `min_certification` until the next successful refresh. Air-gapped deployments on `AXIAM__PKI__MDS_BLOB_PATH` have no automatic refresh path at all.

> **CLOSED (T-153), opt-in.** `AXIAM__PKI__MDS_MAX_STALE_DAYS` bounds the
> window: past that many days beyond `nextUpdate`, an attested registration
> is refused with `AttestationDenyReason::MetadataStale` before the ceremony
> is finished, so nothing is written and then rejected.
>
> Default `0` (disabled) keeps the documented fail-open behaviour, and that
> is the point rather than a hedge: the right bound is a property of the
> deployment. A high-assurance tenant may want days; an air-gapped one on
> `MDS_BLOB_PATH`, with no automatic refresh path at all, would be taken
> offline by anything short of months. A defaulted value would have made
> that decision for both of them.
>
> Scoped to attested ceremonies only. Under `AttestationMode::None` no
> metadata is consulted, so stale metadata cannot have misled the decision
> and refusing would deny a registration for a reason that does not apply to
> it. Never-ingested is likewise left alone — that is the policy's
> `unknown_aaguid` setting's job, and treating it as stale would silently
> disable WebAuthn on deployments that never enabled MDS.
>
> A new deny reason rather than reusing an existing one: every other reason
> is a statement about the authenticator, and this one is a statement about
> our own data being too old to make such a statement. Staleness still never
> hard-fails *ingestion*, and air-gapped operators must still re-supply the
> BLOB themselves.

**T-154 — MDS entry status edited directly in the datastore to hide a revocation**  
`mds_entry / mds_blob_meta (global, X3)` (Store) · Tampering · High · Mitigated

Flipping a stored entry's status reports directly in the datastore would let an authenticator model FIDO has revoked keep passing `block_revoked_status` / `require_fido_certified` indefinitely, bypassing the policy engine entirely.

> Same posture as the certificate store (T-104): these tables are written only by the verified ingestion path (weekly refresh job or the admin-triggered refresh endpoint), which always re-derives entries from a BLOB that passed the full digest-pinned trust-chain verification. Direct datastore write access is restricted to the service credentials on the private data tier and is treated as full administrative compromise.

**T-194 — Tenant CSR signed into an unconstrained CA, or onto a key the requester does not hold**  
`CA management (generate / upload / rotate)` (Process) · Elevation of privilege · High · Mitigated

The tenant signing-CA endpoint signs a PKCS#10 request whose key was generated elsewhere. Honouring the request's own extensions would let a caller mint an unconstrained CA; skipping verification of the request's self-signature would mint a CA certificate for somebody else's public key.

> The CSR's subject is honoured; its requested extensions are not — AXIAM states CA:TRUE, path length zero and keyCertSign/cRLSign itself, so a request that asked to be an unconstrained CA does not become one (1.0.0-alpha44). from_pem verifies the request's self-signature as proof of possession. **T-268 is the leaf twin of this entry** (2026-09-13), and the two now share one parse and one possession check in `ca::inspect_csr`; the leaf path refuses the extensions it cannot guarantee are dropped on every custodian, rather than stripping them as this one does — a CA has no SANs and a caller cannot have meant them here, while a leaf caller can and did. The parent must be unexpired, unrevoked, key-holding and not itself tenant-scoped — refused up front rather than downstream — the intermediate's validity is capped to the parent's expiry, and the row records custody External because AXIAM never held the key.

**T-195 — One tenant's compromised issuance burns the organization trust anchor**  
`Certificate issuance (rcgen, policy enforcement)` (Process) · Elevation of privilege · High · Mitigated

When every tenant's user, service and device certificates issue straight from the organization CA, a compromised issuance path in one tenant is the whole estate's problem: the anchor is long-lived, widely distributed and painful to replace, and rotating it is a coordinated change at every relying party.

> Tenant signing CAs (1.0.0-alpha44): an intermediate created beneath the organization CA, constrained to a path length of zero, named as issuer_ca_id when issuing for that tenant, its key held by the configured custodian — Vault where configured, even when the parent's key predates Vault adoption. Revoking it revokes exactly one tenant's issuance. Under vault_pki the signing chain deliberately reaches past the path-length-zero issuing intermediate to the root, because signing from the issuing intermediate would produce certificates Vault accepts and every chain validator rejects.

**T-268 — Leaf CSR signed with the requester's extensions, a weak key, or onto a key the requester does not hold**  
`Certificate issuance (rcgen, policy enforcement)` (Process) · Elevation of privilege · High · Mitigated

`POST /api/v1/certificates/sign-csr` issues an end-entity certificate over a public key supplied by the caller — the point being a private key AXIAM never sees. Three things a naive implementation gets wrong. It signs a request whose signature it never checked, minting a certificate over somebody else's public key. It honours the extensions the request asks for, so a CSR saying `CA:TRUE` and `keyCertSign` becomes a CA that can sign anything under the tenant's trust anchor — the leaf twin of T-194. And it records the key algorithm the caller states rather than the one the key is, so an RSA-2048 key is signed and written down as `Rsa4096` (T-96, on the leaf path).

> **C-1 (2026-09-13).** `ca::inspect_csr` parses the request **once**, verifies its self-signature before anything else — the only proof the sender holds the matching private key — and reports the subject, the key and the requested extensions from that single parse. Three functions each doing their own parse would have verified possession up to three times on the way to three answers, and would have let a future caller reach one fact without having verified anything.
>
> The key must be Ed25519, or RSA with a **measured** modulus of at least 4096 bits. `KeyAlgorithm::Rsa4096` is a label and not a measurement — `parse_ca_certificate` maps any RSA OID onto it deliberately, so an imported root of another size stays usable — and reusing that mapping here is exactly how T-96 would reappear.
>
> A CSR requesting `subjectAltName`, `keyUsage` or `extendedKeyUsage` is refused **by name** rather than silently stripped; every other requested extension is discarded when rcgen's parameter set is overwritten with the shared `leaf_params`, the same function `CertService::generate` builds a generated leaf from — so "a CSR-signed leaf is the same shape as a generated one" is true because one function says what the shape is, not because two agree. `basicConstraints` needs no rule: the in-process path overwrites it and Vault ignores it outright, so a CSR asking to be a CA comes back a leaf on both.
>
> **The `keyUsage` refusal is load-bearing under `vault_pki`, and this is the finding that shaped the design.** The plan expected to state `key_usage`/`ext_key_usage` in the Vault request body and get parity that way. Vault's own API documentation is explicit that `sign-verbatim` **discards** those parameters whenever the CSR carries the matching extensions, and issues what the CSR asked for. So the parameters alone guarantee nothing, and a silent strip would have been a promise AXIAM keeps on a database-custody deployment and breaks on a Vault one, for the same CSR. Refusing in the shared inspection makes one rule that holds on every custodian. Having refused them, the Vault body *also* states both as empty, so the shape is AXIAM's decision rather than whichever default the Vault version in front of it carries (`DigitalSignature`, `KeyAgreement`, `KeyEncipherment`) — neither half is sufficient alone.
>
> The issuer, the tenant scope and the validity come from the same `prepare_leaf_issuance` the generate path uses, so a revoked CA, an expired one, one in another organization (T-98) and a certificate that would outlive its issuer are refused identically on both. The permission is `certificates:generate`, following `signing-cas/sign-csr`'s reuse of `ca_certificates:generate`: a caller allowed to mint a certificate under a CA is allowed to mint one for a key they already hold, and this path is the less powerful of the two. No private key exists here, so the response type has no field for one (T-99, T-105 hold by construction).
>
> Tests: twenty in `crates/axiam-pki/tests/sign_csr_test.rs`, one per rule; three against the Vault mock in `vault_pki_test.rs`, including one asserting the exact request body AXIAM sends and one proving a `keyUsage`-requesting CSR never reaches Vault at all; four at the HTTP layer in `certificate_test.rs`; and `a_csr_signed_certificate_binds_and_authenticates_like_a_generated_one` in `mtls_test.rs`, which is the property the feature exists for.
>
> **Residual.** What Vault does with the body is documented rather than observed: the tests here run against a mock, and a real Vault was not available. The security property does not rest on that — it rests on the refusal, which is enforced before any custodian is chosen — but the cosmetic parity of the key-usage extension under `vault_pki` is the part taken on the documentation's word.

**T-281 — A tenant administrator issues a leaf under another tenant's signing CA, or directly under the organization anchor**  
`Certificate issuance (rcgen, policy enforcement)` (Process) · Elevation of privilege · High · Mitigated

Both leaf paths resolve the issuing CA through `prepare_leaf_issuance`, which fetched it with `ca_repo.get_by_id(org_id, issuer_ca_id)` — a query whose only scope is `WHERE organization_id = $org_id` — and never read `ca_certificate.tenant_id`, the column that exists to record which tenant a signing CA signs for. Every CA of the organization was therefore reachable by every principal of the organization holding `certificates:generate`: a sibling tenant's signing CA, and the organization-level CA that anchors the whole estate. The leaf came back written with the caller's own `tenant_id` and the other tenant's `issuer_ca_id`, chaining to the root every relying party in the organization trusts — so a certificate minted in tenant A authenticated as a principal of tenant B against anything that verified the chain rather than the row, which is what mTLS verifies. No bug in the caller was needed: the API accepted the CA id and answered `201`. `axiam-domo-demo` reproduced it at runtime and rode the certificate to a full MQTT session (DF-017, DF-025).

> **S-1 (2026-09-22).** `prepare_leaf_issuance` takes the tenant being acted on and an `IssuingScope`, and matches the CA against both **immediately after the lookup** — ahead of the status and validity-window checks. The ordering is the disclosure control: a caller outside the tenant must not be able to tell a CA that does not exist from one that is revoked by watching which refusal comes back, and `a_foreign_ca_is_not_found_even_when_it_is_revoked` pins it.
>
> A tenant signing CA is usable only by a caller acting on that tenant. An organization-level CA is usable only by a principal whose own record lives in the organization's reserved scope — resolved by the residence test `require_organization_principal` already uses, and deliberately **not** `AuthenticatedUser::organization_level`, which is set only when a request names another tenant through `X-Axiam-Tenant` and is therefore `false` for exactly the calls this governs. Reading that flag instead would have refused the organization administrator its own anchor, which is the one issuance path that had to stay byte for byte as it was.
>
> The refusal is `NotFound`, following `a_ca_in_another_organization_is_not_found`: a CA the caller may not use is a CA the caller cannot see. One site covers both custodians, because the check precedes custodian resolution — the Vault path never reaches a `sign-verbatim` it should not have made.
>
> Tests: five in `sign_csr_test.rs` (another tenant's CA, the organization CA, the tenant's own CA, the ordering probe, and the I4 twin that an organization principal still issues under the anchor), four `generate` twins in `cert_test.rs`, and the end-to-end refusal in `axiam-api-rest`'s `certificate_test.rs` beside the cross-organization one.
>
> **Residual — operator action, deliberately not automated.** Leaves already issued across the boundary are not revoked on upgrade. AXIAM will not revoke on an operator's behalf: revocation takes effect against whatever is presenting those certificates right now, and a deployment that discovers a cross-tenant leaf has to decide when it can afford to. `docs/pki/README.md` carries the reach table, how to find them, and what a tenant needs before it can issue again.

**T-282 — The one auth endpoint that performs a client-certificate handshake has no rate limiter**  
`mTLS device auth (fingerprint + chain verify)` (Process) · Denial of service · Medium · Mitigated

`POST /api/v1/auth/device` was a bare route in `server.rs` — no `build_governor`, no `RateLimitShared` — while every neighbouring auth resource carried both layers: `/auth/login`, the three OPAQUE routes, the six WebAuthn ceremony routes, the federation sign-in routes. It is in `PUBLIC_PATHS` and CSRF-exempt, both of which it must be, because a device holds no session and no cookie. So the single endpoint whose happy path makes the server complete a TLS handshake with a client certificate — asymmetric verification plus a chain walk against the trust anchors, the most expensive work an unauthenticated caller can ask of it — was the one an unauthenticated caller could drive at line rate. Every other shape of the same attack was already bounded, and nothing in the code said why this one was not, which is the signature of an omission rather than a decision. Filed by `axiam-domo-demo`'s reading as the suggested DF-028.

> **S-2 (2026-09-22).** `AXIAM__RATE_LIMIT__DEVICE_LOGIN_PER_MIN`, default **60** per minute per IP, through both layers exactly as `/auth/login`: `build_governor` for the per-process ceiling and `RateLimitShared("device_login")` so the limit holds across replicas rather than multiplying by their count.
>
> Per-IP unconditionally. The identity on this path is a certificate presented in the handshake; there is no OAuth2 `client_id` in the request to key a bucket on, and the `RateLimitKeyMode` that would offer one governs three OAuth2 endpoints and not this.
>
> **In the machine family, not the human one.** G7 rules that no preset may move a human-endpoint default, and this is not a human endpoint: the caller is a device and the traffic shape is a fleet's re-login interval. `gateway` and `mesh` take it to 300 and 3 000 — the same 5x and 50x `token_per_min` takes, so the family scales coherently — and that, rather than a higher shipped default for everyone, is the answer for a fleet behind one NAT.
>
> **Sized from the honest traffic, not from capacity.** A device re-authenticates once per access-token lifetime, 900 s by default. Sixty per minute per address therefore holds nine hundred devices with the whole allowance to spare, and no deployment on the shipped posture sees a 429 it did not see before — which is the I1.
>
> Tests: six in `device_login_rate_limit_test.rs`, driving the real `register_api_v1_routes` wiring so that a regression to a bare route fails the suite rather than passing quietly. They pin the 429 and its `Retry-After`, the per-IP isolation (one noisy device must not lock out a fleet), the I4 twin that `login_per_min` is neither changed nor charged, the shipped-default arithmetic, the preset multipliers, and that an operator's pinned value still beats the preset.

**T-283 — A device's access token is a bearer credential, so stealing it is as good as stealing the key**  
`mTLS device auth (fingerprint + chain verify)` (Process) · Spoofing · High · Mitigated

`POST /api/v1/auth/device` authenticates a device by a TLS handshake with a client certificate — the strongest thing a device can prove — and then called `issue_service_account_token`, which had no `cnf` parameter at all. The token that came back was a plain bearer credential: whoever holds it may use it. So the proof of possession bought nothing past the handshake that produced it, and a token read off the device's flash, recovered from a log line, captured at a misconfigured egress proxy, or taken from a compromised Twin authenticated *as that device* for its whole lifetime, with no certificate and no key required. What makes this the sharpest entry in this diagram is that the machinery to close it already existed and was already in use: `CnfClaim`, `x5t#S256` per RFC 8705 §3.1, and `verify_token_binding`'s decision table were all built for OAuth2 mTLS client credentials, which mint the claim. The device path was the one mint site that did not — the weakest credential AXIAM issues, from the strongest authentication it performs (DF-014).

> **S-3 (2026-09-22).** `issue_service_account_token` takes a `cnf`, and `device_auth` builds one from the thumbprint of the certificate rustls verified for this connection, so the token names the key the device proved it holds.
>
> **No enforcement code changed, and that is the finding rather than a shortcut.** Both surfaces already refuse a `cnf`-bearing token whose evidence does not match: `axiam-api-rest`'s `enforce_sender_constraint` runs inside `validate_presented_token`, which *every* extractor reaches — the service-account one included — and `axiam-api-grpc`'s interceptor reads `peer_certs()` and runs the same `verify_token_binding`. The plan expected to write REST enforcement and found it already generic. The claim was the only missing half.
>
> **The thumbprint is recorded only where rustls verified the certificate on this connection.** The trusted-proxy `X-Client-Certificate` path mints no `cnf`, deliberately: there the certificate is present at login and absent from every later request, so a bound token would be one AXIAM itself refuses on first use. The asymmetry is stated in `CertificateAuthenticated::certificate_thumbprint`'s own documentation and in `docs/pki/README.md`, rather than left to be discovered — and the remedy named there is a deployment change (terminate mTLS at AXIAM), because no claim can substitute for evidence that never arrives.
>
> **Over gRPC** the evidence is `peer_certs()`, which is empty until the listener asks for a client certificate — `with_no_client_auth()` today, which S-8 changes. A device token presented there is therefore refused for want of evidence. That is the fail-closed direction and it is why a fleet talks to the REST surface; it is also the ordering argument for taking S-8 before anything routes device traffic through the mesh.
>
> **I1.** A token minted before this change carries no `cnf` and takes row one of the decision table, which returns `Ok` without reading anything. The migration lasts one access-token lifetime.
>
> Tests: three in `axiam-auth` — the stamp round-trips the thumbprint into the decoded claim, the bound token is refused with no certificate and with a different one and accepted with the right one, and an unbound one demands nothing.

**T-196 — Vault configured, CA keys silently sealed into database rows**  
`ca_certificate (sealed row or Vault custody)` (Store) · Information disclosure · High · Mitigated

CA key custody read its own PKI-specific Vault variable pair. A deployment that configured the secret provider's pair saw 'secret provider ready provider=vault' at startup and reasonably concluded its CA signing keys were in Vault — while custody fell through to database, sealing every organization and tenant CA private key into a ca_certificate row. A database dump plus one process's AXIAM__PKI__ENCRYPTION_KEY then yields every CA private key in the deployment, and nothing records the read.

> Fixed in 1.0.0-beta02: no PKI-specific pair now means the Vault the deployment already configured, not no Vault at all, and the startup custody line carries vault_inherited so an operator who never set a PKI variable can read why their keys are in Vault. The PKI pair still wins outright when set. Database custody beside a working Vault is reachable only by writing AXIAM__PKI__CA_KEY_STORE=database explicitly, and is reported at startup as a warning naming what is at stake. Custody is recorded per CA, and the migrate-custody endpoint moves existing keys into Vault without re-issuing anything.

**T-197 — Custody migration destroys the only copy of a CA signing key**  
`CA management (generate / upload / rotate)` (Process) · Denial of service · High · Mitigated

Migrating a CA's key from Vault into database custody wrote custody = database beside an emptied key column, then released the Vault copy — and returned Ok. The CA row claimed to hold a key it did not have, the key it named was gone, and no backup of the row helps, because the row never contained the key. That CA could no longer sign anything.

> Fixed in 1.0.0-beta02: the repository writes the ciphertext it is given in the same single statement that records the custodian, so the Vault→database direction carries the key and the database→Vault direction still clears the column — clearing is now the caller's decision, not the repository's assumption. The operation orders copy, record, then release, so a failure before the record leaves the CA exactly as it was. Five integration tests drive the real Vault key store against a mock HTTP server, including that a migrated-back key still decrypts and equals the one Vault handed over.

**T-198 — Revoked or unflagged CA lingers in the mTLS trust-anchor bundle**  
`mTLS device auth (fingerprint + chain verify)` (Process) · Spoofing · Medium · Mitigated

Flagging an organization CA as an mTLS trust anchor exports its public certificate into the bundle rustls verifies client certificates against. A bundle that is not rewritten when a CA is unflagged or revoked leaves an anchor on disk that the live verifier — and every later restart — would still trust, so certificates chaining to a withdrawn CA keep authenticating.

> The trust-anchor reload rewrites the entire flagged set every time (1.0.0-beta01/beta02): unflagging removes an anchor, emptying the set empties the bundle rather than leaving stale anchors a reboot would trust, and the hot reload swaps the live verifier without a restart. Only public certificates are exported — the signing key is never copied. Client verification stays optional, so flagging a CA cannot lock every browser out of the admin UI, and an operator's own CLIENT_AUTH / CLIENT_CA_PATH configuration is never overridden by the convenience.

**T-206 — Certificate chaining to a CA never enabled as a trust anchor authenticates on the proxy path**  
`mTLS device auth (fingerprint + chain verify)` (Process) · Spoofing · High · Mitigated

A certificate issued under an organization CA that was never flagged as an mTLS trust anchor authenticated successfully at POST /api/v1/auth/device (B-06). On the native-mTLS listener rustls enforces the flag, because the client-CA bundle is built from exactly the flagged anchors — but on the proxy-terminated path, the one docker-compose.prod.yml and the Kubernetes manifests actually use, nothing consulted mtls_trust_anchor: every Active CA in the organization was as good as every other, and un-flagging a CA — the documented way to stop trusting it — changed nothing. The “flat hierarchy” assumption this rested on had been stale since tenant signing CAs made intermediates real.

> Fixed in 1.0.0-beta05: require_trust_anchor runs on every device authentication, before the service-account binding. It walks up parent_ca_id until it reaches a CA flagged as an anchor — a walk, not a test of the immediate issuer, because a tenant signing CA is deliberately an unflagged intermediate — requires every CA on the way to be Active and inside its validity window (an anchor reached through a revoked intermediate is not reached), and bounds the walk at depth 8, because parent_ca_id is data and data can describe a cycle. Each refusal names its reason distinctly. The decisive test presents a bound, otherwise-valid certificate from an unflagged CA, so the refusal can only be about trust — the first draft presented an unbound one and passed for the wrong reason, which is recorded so the next assertion is written with one reason to succeed.

**T-263 — Accepting an unchained certificate for RFC 8705 §2.2 lets a self-minted certificate authenticate as a device or as a `tls_client_auth` client**  
`mTLS device auth (fingerprint + chain verify)` (Process) · Elevation of privilege · Critical · Mitigated

A `self_signed_tls_client_auth` client could never open a connection: `ReloadableClientCertVerifier` delegated to webpki, whose job is chain-building, and an RFC 8705 §2.2 certificate is self-signed by design — it chains to nothing, because the method identifies a client by the `x5t#S256` an administrator registered rather than by an issuer — so rustls sent `bad_certificate` before AXIAM saw a request (34 of 37 FAPI modules `INTERRUPTED` with no HTTP status). RFC 8705 puts two trust models under one transport: §2.1 is PKI, the identity a name a CA vouched for; §2.2 has no PKI in it, the certificate *is* the credential, and adding an issuer to the bundle cannot answer it. The hazard is in the fix: once the listener admits an unchained certificate, device and IoT authentication — whose entire model is chaining to a CA an administrator flagged as a trust anchor, the native-listener twin of B-06 — must not accept one, and a `tls_client_auth` DN match without a chain requirement makes `openssl req -subj "/CN=<whatever was registered>"` the entire attack.

> 2d4cb59, four layers, and the third and fourth are where the safety is. (1) `ClientAuth::OptionalSelfSigned`, spelled `optional_self_signed`, a fourth policy: `off`, `optional` and `required` are byte-for-byte unchanged, every new branch is gated on `accepts_self_asserted()`, which only this variant answers true to, and the new behaviour is reachable only through a value no deployment sets today — which is what makes it non-regressive rather than merely tested. (2) The verifier tries webpki and, under the new policy only, accepts on failure, with an explicit `not_before`/`not_after` check on that branch because webpki performs the validity check as part of chain building and the path that skips chain building would silently lose it, for exactly the clients nobody else vouches for; the self-signature is deliberately not verified, since under §2.2 the identity is the SHA-256 of the DER and possession is proven by TLS 1.3's `CertificateVerify`, which rustls checks whether or not a chain was built. (3) `CertTrust::{ChainedToAnchor, SelfAsserted}` travels from the handshake to every consumer, on `VerifiedClientCert` and `PresentedCertificate` — an enum rather than a bool, **required** rather than defaulted, because a default would have handed the privileged value to any future call site that said nothing; it lives in `axiam-core` because the layering gate refuses the outward edge, and it is re-derived in the `on_connect` hook via `tls::peer_certificate_trust` because rustls's `ClientCertVerified` is an opaque token with no payload and the verifier is handed no connection handle to key a side channel on. (4) Only the one method specified to work this way may consume the weaker level: device/IoT certificate auth **refuses** `SelfAsserted` outright — rather than by falling through to the header branch, whose error text would advise setting `TRUST_FORWARDED_CLIENT_CERT`, advice that would widen a different trust boundary while chasing this one; `tls_client_auth` (§2.1) now **requires** `ChainedToAnchor`, a no-op until this commit and a real guard now that the invariant is configurable; `self_signed_tls_client_auth` (§2.2) accepts either, since the thumbprint comparison is the authentication and is no weaker for the certificate having also chained. Net effect: an unchained certificate can do exactly one thing — authenticate as a client whose exact SHA-256 an administrator registered — and every other path treats it as though the handshake had carried no certificate at all. A second listener for §2.2 was rejected: the per-client decision happens at the application layer either way, so an extra port buys only another listener to operate. The tests pin the operator-facing contract: a DN that *matches* is refused unchained with the chained case as a control on the same certificate; the §2.2 acceptance test computes the thumbprint the way an administrator does rather than reading it back off the value under test; the four documented policy strings are hard-coded; a real rustls TLS 1.3 handshake through `build_rustls_server_config` rejects the certificate under `optional` and accepts it under `optional_self_signed`; expired, not-yet-valid and non-certificate bytes are each refused.

</details>

### 5.7 Audit, webhooks, email & notifications

The append-only audit trail and its OpenPGP batch signing, webhook delivery with HMAC signatures and the SSRF guard, the pluggable email service and templates, and admin notification rules.

*18 threats — 2 high, 14 medium, 2 low; 1 open.*

| # | Element | STRIDE | Threat | Severity | Status |
|---|---|:-:|---|---|---|
| T-106 | Webhook receiver (tenant endpoint) <br/>*Actor* | S | Receiver accepts unverified deliveries | Medium | Mitigated |
| T-107 | Email provider <br/>*Actor* | S | Provider API key reused to send mail as the tenant | Medium | Mitigated |
| T-108 | Audit middleware & service <br/>*Process* | R | Action succeeds while its audit write fails | High | Mitigated |
| T-109 | Audit middleware & service <br/>*Process* | T | Log injection through attacker-controlled fields | Medium | Mitigated |
| T-110 | Audit middleware & service <br/>*Process* | I | Personal data over-collected into an immutable log | Medium | Mitigated |
| T-111 | Audit batch PGP signing <br/>*Process* | T | Signing gap leaves a batch unattested | Medium | Mitigated |
| T-112 | Webhook delivery (HMAC + guarded_fetch + retry) <br/>*Process* | I | Webhook URL used to reach internal services | High | Mitigated |
| T-113 | Webhook delivery (HMAC + guarded_fetch + retry) <br/>*Process* | T | Delivery replay by a party who captured one request | Medium | Mitigated |
| T-114 | Webhook delivery (HMAC + guarded_fetch + retry) <br/>*Process* | D | Retry storm against a slow endpoint | Low | Mitigated |
| T-115 | Email service (SMTP / provider API, templates) <br/>*Process* | E | Template injection through user-controlled placeholders | Medium | Mitigated |
| T-116 | Email service (SMTP / provider API, templates) <br/>*Process* | T | Header injection producing extra recipients | Medium | Mitigated |
| T-117 | Notification rules (admin alerts) <br/>*Process* | D | Alert flooding buries a real incident | Medium | Mitigated |
| T-118 | audit_log (append-only, signed) <br/>*Store* | T | Audit trail deleted along with the tenant | Medium | Mitigated |
| T-119 | audit_log (append-only, signed) <br/>*Store* | D | Unbounded audit growth degrades the datastore | Low | Mitigated |
| T-120 | webhook (HMAC secrets) <br/>*Store* | I | Webhook secret leaked through derived Debug output | Medium | Mitigated |
| T-121 | outbound mail queue (RabbitMQ) <br/>*Store* | I | Queued messages readable on the broker | Medium | Mitigated |
| T-122 | event delivery <br/>*Flow* | I | Event payload discloses more than the receiver needs | Medium | Mitigated |
| T-123 | deliver mail <br/>*Flow* | I | Final mail hop is not confidential | Medium | Open |

<details>
<summary>Threat detail and mitigations</summary>

**T-106 — Receiver accepts unverified deliveries**  
`Webhook receiver (tenant endpoint)` (Actor) · Spoofing · Medium · Mitigated

A receiver that does not check the HMAC signature acts on any POST that reaches its URL, so knowledge of the URL alone is enough to drive downstream provisioning.

> Every delivery carries an HMAC-SHA256 signature over the payload with the per-endpoint secret; the SDK contract documents verification as mandatory on the receiving side.

**T-107 — Provider API key reused to send mail as the tenant**  
`Email provider` (Actor) · Spoofing · Medium · Mitigated

A leaked SendGrid/Postmark/Resend/Brevo key lets an attacker send mail from the tenant's verified domain — ideal for phishing that passes SPF and DKIM.

> Provider credentials are encrypted at rest and redacted from Debug output; configuration changes are audited. Rotate keys on any suspicion and scope them to send-only.

**T-108 — Action succeeds while its audit write fails**  
`Audit middleware & service` (Process) · Repudiation · High · Mitigated

If audit writes are best-effort, an attacker who can make the audit path fail — by exhausting the datastore or triggering a specific error — performs actions that leave no trace.

> Audit writes share the transactional path with the action they record where the datastore allows it, and audit failures are surfaced as errors and raise a compliance notification rather than being swallowed.

**T-109 — Log injection through attacker-controlled fields**  
`Audit middleware & service` (Process) · Tampering · Medium · Mitigated

Newlines or control characters in a username or resource name let an attacker forge additional log lines and mislead an investigation.

> Audit records are structured values persisted as fields, not formatted strings, so injected control characters cannot create a synthetic record.

**T-110 — Personal data over-collected into an immutable log**  
`Audit middleware & service` (Process) · Information disclosure · Medium · Mitigated

The audit log is append-only by design, so any personal data written into it cannot later be erased — which is in direct tension with the GDPR Art. 17 erasure path AXIAM also offers.

> Both halves are now bounded. **Retention** (T-119): a default 730-day sweep through the table's only deletion path — deployment-wide, reachable from no HTTP handler, `0` to disable, both states logged at startup. **Collection** (R-7, 2026-09-12): `AXIAM__AUDIT__MINIMISE`, default `false`, applied in `SurrealAuditLogRepository::append` — the only code every audit row passes through, since the request middleware is one producer among eighteen and the rest call `append` directly. With it on, `ip_address` is truncated to its `/24` or `/48` prefix and a `user_agent` in `metadata` is reduced to a coarse family, immediately before the write because the table is append-only and there is no second chance by construction; an address that does not parse is **dropped** rather than written through, since a value that cannot be parsed cannot be shown to have been minimised. Three limits, each deliberate: the structured metadata producers write is never touched — the client and disposition on a refresh-token replay (T-254), the names of released claims (T-241), a federated subject (T-161) are accountability evidence other mitigations depend on, and dropping them would weaken three controls to narrow one; the switch is **deployment-wide and not per tenant**, because audit is a control the deployment relies on *including against a tenant administrator* and a tenant-level switch would let a tenant weaken the evidence used to investigate that tenant; and it is off by default, because reducing forensic precision is a lawful-basis judgement to make deliberately. Both states are logged at startup exactly as retention is. Erasure and export are unaffected and are asserted so rather than assumed: `pseudonymize_actor` clears `ip_address` outright so a truncated value is erased by the same statement as a whole one, and the Art. 15 export's `audit_entries` section reads `action`, `outcome`, `timestamp` and `resource_id` and never the address (`minimisation_leaves_every_field_the_art_15_export_reads`). The request-audit middleware's own metadata key set is pinned exactly — `http_status` and `authenticated`, nothing else — so “no request metadata” cannot regress into an append-only table with a 730-day window. Residual, accepted: the deployment still chooses, and one that leaves the switch off collects what it collects today. `docs/compliance/gdpr-compliance.md` §2a; `docs/deployment/README.md`.

**T-111 — Signing gap leaves a batch unattested**  
`Audit batch PGP signing` (Process) · Tampering · Medium · Mitigated

If a batch can be written and left unsigned without notice, tamper-evidence has a hole exactly where an attacker would want one.

> Signing failures raise a compliance admin notification rather than failing silently, so an unsigned batch is visible.

**T-112 — Webhook URL used to reach internal services**  
`Webhook delivery (HMAC + guarded_fetch + retry)` (Process) · Information disclosure · High · Mitigated

A tenant administrator points a webhook at an internal or cloud metadata address and uses delivery success, latency or error detail as an internal scanner.

> Delivery uses the same resolve-and-pin guarded_fetch as federation: private, loopback, link-local, ULA and unspecified destinations are rejected before connect, https is enforced on every hop, and the response size is capped.

**T-113 — Delivery replay by a party who captured one request**  
`Webhook delivery (HMAC + guarded_fetch + retry)` (Process) · Tampering · Medium · Mitigated

An HMAC over the body alone proves origin but not freshness, so a captured delivery could be replayed against the receiver indefinitely.

> D-10 / T-26-03-01: deliveries use the Stripe-style signed-timestamp scheme — HMAC-SHA256 over `<timestamp>.<body>` emitted as `X-Axiam-Signature: t=<unix>,v1=<hex>` alongside `X-Axiam-Timestamp`, so a forged or stale signature cannot be produced from the body alone. Receivers must enforce a freshness window on t and deduplicate on X-Axiam-Delivery.

**T-114 — Retry storm against a slow endpoint**  
`Webhook delivery (HMAC + guarded_fetch + retry)` (Process) · Denial of service · Low · Mitigated

Aggressive retries against an unhealthy receiver amplify load on both AXIAM and the receiver.

> Retries use exponential backoff with a per-webhook configurable policy, concurrent deliveries are bounded, and each attempt is logged to the audit trail.

**T-115 — Template injection through user-controlled placeholders**  
`Email service (SMTP / provider API, templates)` (Process) · Elevation of privilege · Medium · Mitigated

Templates interpolate {{username}} and {{tenant_name}}. If a user-supplied value is treated as template source rather than data, it can execute template expressions during rendering.

> Values are passed as rendering context, never concatenated into the template body, and the template engine autoescapes output for the HTML variant.

**T-116 — Header injection producing extra recipients**  
`Email service (SMTP / provider API, templates)` (Process) · Tampering · Medium · Mitigated

CR/LF in an address or subject field can inject additional SMTP headers and add hidden recipients.

> Addresses and headers are constructed through the typed lettre API, which rejects embedded control characters, rather than by string assembly.

**T-117 — Alert flooding buries a real incident**  
`Notification rules (admin alerts)` (Process) · Denial of service · Medium · Mitigated

An attacker triggers thousands of notifiable events so the genuine signal is lost among them, and burns the mail quota along the way.

> Notifications are delivered in configurable batches through the mail queue, and rules are per-category so a noisy category can be tuned without disabling the rest.

**T-118 — Audit trail deleted along with the tenant**  
`audit_log (append-only, signed)` (Store) · Tampering · Medium · Mitigated

Deleting a tenant removes its data; if audit records go with it, the evidence of what happened disappears exactly when it matters most.

> **CLOSED (T-118).** Deleting a tenant is now a two-step act. `POST /api/v1/organizations/{org_id}/tenants/{tenant_id}/audit-export` streams the tenant's whole audit trail as newline-delimited JSON — paged from the datastore, so a large trail is bounded in memory rather than truncated — and, only after the last row has been written, appends a receipt to that tenant's own audit log. The export's final line is a manifest carrying the record count, a SHA-256 over the entry lines before it, and the receipt id, so an archived file can be re-hashed and matched to the deletion it authorised. `DELETE .../tenants/{tenant_id}` then answers `409` unless such a receipt exists and is under **six hours** old; an export that dies half way writes no receipt and unblocks nothing. The window is a constant, not a setting — a configurable freshness bound is one an operator can widen until it means nothing — and there is no override parameter. Because the tenant's own entries (the receipt included) go with it, the deletion is recorded in the **system** audit log, naming the actor, the tenant slug and the receipt that authorised it; that record is what outlives the tenant. Residual, stated rather than hidden: this proves an identified principal was handed the trail minutes before the deletion, not that they kept the bytes — custody of a file the server gave away is not something the server can attest. GDPR Art. 17 is unaffected: erasure is delayed by the length of one export, never refused.

**T-119 — Unbounded audit growth degrades the datastore**  
`audit_log (append-only, signed)` (Store) · Denial of service · Low · Mitigated

An append-only table with no retention policy grows without limit, eventually affecting query latency across the datastore.

> **CLOSED (T-119).** AXIAM now prunes audit records on a clock, defaulting to a 730-day retention window. `AuditLogRepository::prune_older_than` is the table's first deletion path and is deliberately narrow: reachable only from the background sweep, never from any HTTP handler — retention is a deployment-wide policy, not an operation an administrator can aim at a time range of their choosing, which is what stops "prune old records" becoming "delete the evidence" — and deployment-wide rather than per-tenant, so one tenant's settings cannot decide how long another tenant's records survive on shared storage. `0` disables pruning and restores the old behaviour, and both states are logged at startup so the window in force is visible rather than inferable from config. Archival to an external WORM sink before the window expires remains the operator's choice; the separate question of what happens to a trail when its *tenant* is deleted is closed by T-118.

**T-120 — Webhook secret leaked through derived Debug output**  
`webhook (HMAC secrets)` (Store) · Information disclosure · Medium · Mitigated

A derived Debug implementation on the webhook type prints the HMAC secret into any trace or error line that formats it.

> SEC-067: Webhook, CreateWebhook and the secret-rotation type all carry manual Debug implementations that redact the secret, mirroring the treatment already applied to federation secrets under SECHRD-09.

**T-121 — Queued messages readable on the broker**  
`outbound mail queue (RabbitMQ)` (Store) · Information disclosure · Medium · Mitigated

Outbound mail messages carry reset links and verification tokens; anyone able to read the queue can use them.

> Broker access is credentialed per service on the private network, and the transport is always TLS — the server refuses any non-`amqps://` broker URL in every build profile; tokens are single-use and short-lived so a stale queued message has limited value.

**T-122 — Event payload discloses more than the receiver needs**  
`event delivery` (Flow) · Information disclosure · Medium · Mitigated

Webhook payloads carry tenant context and event data across an organizational boundary to a customer-controlled endpoint.

> Payloads carry the event type, timestamp, tenant context and event-specific data only — never credentials, password hashes, MFA secrets or private keys.

**T-123 — Final mail hop is not confidential**  
`deliver mail` (Flow) · Information disclosure · Medium · Open

AXIAM enforces TLS to the provider, but the provider-to-recipient hop is outside its control and may be opportunistic or plaintext.

> Inherent to email. Bounded by making the tokens carried in mail single-use and short-lived, so interception has a narrow window. Deploy MTA-STS and DANE on the sending domain to harden the onward hops.

</details>

### 5.8 Deployment & platform (Kubernetes)

Runtime and platform view: the edge (ingress or reverse proxy), replicated AXIAM pods, scheduled jobs, monitoring, and the stateful tier — SurrealDB, RabbitMQ, Vault/Secrets and backups. Threats here are largely deployment responsibilities rather than application code.

T-212…T-217 record the 1.0.0-beta08 topology change (`claude_dev/public-backend-tls-design.md`): the edge now routes **by path** — the SPA at `/`, and `/api`, `/oauth2` and `/.well-known` to the server over TLS the server terminates itself. That removes a proxy hop and a cleartext leg, and moves four things across a trust boundary that were previously behind one. T-231…T-234 and T-236 record the beta09…beta11 follow-through on the same topology: the Vault seeder and the server's Vault policy, gRPC published through the same edge and the certificate-renewal gap that opened with it — closed at 1.0.0-beta12 by R-1, which moved the gRPC handshake off tonic and onto the same reloadable, TLS 1.3-only resolver the REST listener uses — and the CI gates that must measure the artifact rather than the worktree. 1.0.0-beta13 adds the Vault CA bundle that could parse to nothing and silently fall back to the public trust store (T-264), and narrows T-236's Trivy scan to what AXIAM ships.

*28 threats — 2 critical, 17 high, 9 medium; 5 open.*

| # | Element | STRIDE | Threat | Severity | Status |
|---|---|:-:|---|---|---|
| T-124 | Cluster operator / SRE <br/>*Actor* | S | Operator credentials grant unaudited data access | High | Open |
| T-125 | Ingress controller (TLS 1.3) <br/>*Process* | E | Traffic reaches pods bypassing the ingress | High | Mitigated |
| T-126 | AXIAM deployment (N replicas, HPA) <br/>*Process* | E | Container escape from an over-privileged pod | High | Mitigated |
| T-127 | AXIAM deployment (N replicas, HPA) <br/>*Process* | T | Vulnerable dependency reaches production | High | Mitigated |
| T-128 | Prometheus / Grafana <br/>*Process* | I | Metrics or traces disclose tenant identifiers | Medium | Mitigated |
| T-129 | Scheduled jobs (cert expiry, GDPR erasure, sweeps) <br/>*Process* | R | Erasure or expiry job silently stops running | Medium | Mitigated |
| T-130 | SurrealDB StatefulSet (cluster) <br/>*Store* | I | Datastore reachable without authentication | Critical | Mitigated |
| T-131 | RabbitMQ StatefulSet (cluster) <br/>*Store* | I | Default or shared broker credentials | High | Mitigated |
| T-132 | Secrets (Vault / K8s Secrets / ConfigMap) <br/>*Store* | I | Secret material placed in a ConfigMap or plain env var | High | Mitigated |
| T-133 | Backups / volume snapshots <br/>*Store* | I | Backup media accessible outside the cluster | High | Open |
| T-134 | scheduled backup <br/>*Flow* | I | Backup stream unencrypted in transit | Medium | Open |
| T-165 | SurrealDB StatefulSet (cluster) <br/>*Store* | T | A non-persistent storage engine removes single-use arbitration | High | Mitigated |
| T-180 | Secrets (Vault / K8s Secrets / ConfigMap) <br/>*Store* | I | Vault concentrates every long-lived secret behind one credential | High | Open |
| T-207 | AXIAM deployment (N replicas, HPA) <br/>*Process* | D | A rolling deployment logs every not-yet-replaced replica out of the datastore | High | Mitigated |
| T-208 | Ingress controller (TLS 1.3) <br/>*Process* | T | The shipped proxy config diverges from the proxy CI tests | Medium | Mitigated |
| T-212 | Ingress controller (TLS 1.3) <br/>*Process* | T | An unaccounted proxy hop collapses every per-IP rate limit into one bucket | High | Mitigated |
| T-213 | AXIAM deployment (N replicas, HPA) <br/>*Process* | I | Path-routing at the edge makes the health endpoints internet-reachable | Medium | Mitigated |
| T-214 | AXIAM deployment (N replicas, HPA) <br/>*Process* | D | The TLS leaf expires because rustls binds it for the process's life | High | Mitigated |
| T-215 | IoT device / service account <br/>*Actor* | S | A forwarded client certificate authenticates whoever can set the header | Critical | Mitigated |
| T-216 | Secrets (Vault / K8s Secrets / ConfigMap) <br/>*Store* | E | The unseal key sits on the same disk as the sealed data | High | Open |
| T-217 | proxy → axiam-server <br/>*Flow* | I | Credentials cross the internal network in cleartext | High | Mitigated |
| T-231 | Secrets (Vault / K8s Secrets / ConfigMap) <br/>*Store* | T | A refused Vault read is indistinguishable from an empty Vault, and the seeder overwrites every live secret | High | Mitigated |
| T-232 | Secrets (Vault / K8s Secrets / ConfigMap) <br/>*Store* | E | The server's Vault policy is quoted in several places, and none of them is checked against what the server does | Medium | Mitigated |
| T-233 | AXIAM deployment (N replicas, HPA) <br/>*Process* | S | A gRPC listener published by port-forward keys every rate limit on a header the client writes | High | Mitigated |
| T-234 | AXIAM deployment (N replicas, HPA) <br/>*Process* | D | The gRPC TLS leaf expires because tonic reads it once at startup | Medium | Mitigated |
| T-236 | AXIAM deployment (N replicas, HPA) <br/>*Process* | T | A registry outage or a stale suppression turns the dependency-audit gate into a rubber stamp | Medium | Mitigated |
| T-264 | Secrets (Vault / K8s Secrets / ConfigMap) <br/>*Store* | T | A Vault CA bundle that parses to nothing silently replaces the operator's pin with the public trust store | Medium | Mitigated |
| T-284 | AXIAM deployment (N replicas, HPA) <br/>*Process* | E | A re-minted bootstrap setup token is a second way to create the first administrator | High | Mitigated |

<details>
<summary>Threat detail and mitigations</summary>

**T-124 — Operator credentials grant unaudited data access**  
`Cluster operator / SRE` (Actor) · Spoofing · High · Open

Anyone with kubectl exec or Secret-read rights in the namespace can read signing keys and datastore credentials, bypassing every application control without appearing in the AXIAM audit log.

> Outside the application boundary. Restrict RBAC on Secrets and exec, enable Kubernetes audit logging, and treat cluster-admin as equivalent to full AXIAM compromise in your threat register.

**T-125 — Traffic reaches pods bypassing the ingress**  
`Ingress controller (TLS 1.3)` (Process) · Elevation of privilege · High · Mitigated

Without a NetworkPolicy, any workload in the cluster can call the AXIAM Service directly and skip the ingress, along with any edge protections applied there.

> **CLOSED (SEC-053).** AXIAM's own authn/authz still applies on every request,
> so this was always defence-in-depth rather than a bypass of access control —
> but the depth is now actually shipped. `k8s/network-policy/` carries a
> namespace-wide `default-deny-all` (ingress *and* egress, `podSelector: {}`)
> plus the minimum set of allows that a working deployment needs: DNS egress,
> `server-egress` scoped to SurrealDB:8000, RabbitMQ:5671, public HTTPS with
> RFC1918/CGN and the cluster CIDRs excluded, and a fail-closed SMTP relay
> range; and receiver-side ingress policies for the server, frontend, SurrealDB
> and RabbitMQ pods.
>
> The receiver-side halves matter as much as the sender-side ones, and for a
> reason worth stating: NetworkPolicy is evaluated at *both* ends of a
> connection. `server-egress` permitting server → surrealdb:8000 counts for
> nothing while `default-deny-all` still denies ingress on the SurrealDB pod.
> The SurrealDB and RabbitMQ ingress policies existed as files but were absent
> from `kustomization.yml`, so they were never applied — which did not merely
> leave the model weaker than it read, it broke the deployment outright. They
> are now listed, and `kubectl kustomize k8s/` is the check that they stay
> listed.
>
> Two values in `server-egress` are deliberately placeholders the operator must
> replace: the cluster pod/service CIDRs in the HTTPS `except` list (defaults
> match kubeadm/flannel and are almost certainly wrong for a given cluster), and
> the SMTP relay range, which ships as RFC 5737 TEST-NET-1 so mail egress is
> denied until it is configured rather than open by default.

**T-126 — Container escape from an over-privileged pod**  
`AXIAM deployment (N replicas, HPA)` (Process) · Elevation of privilege · High · Mitigated

A pod running as root with a writable filesystem turns a process-level bug into a node-level compromise.

> The image runs as a non-root user with a read-only root filesystem and no additional capabilities. Apply a restricted PodSecurity standard to the namespace to enforce this at admission.

**T-127 — Vulnerable dependency reaches production**  
`AXIAM deployment (N replicas, HPA)` (Process) · Tampering · High · Mitigated

A transitive Rust or npm dependency with a known advisory ships in the image without anyone noticing.

> CI runs cargo-audit, cargo-deny (advisories, licences, bans, sources) and npm audit at a high threshold, uploads SARIF, and Dependabot covers cargo, the frontend npm tree and GitHub Actions. Residual: the eleven SDK repositories are scanned separately and are not covered by this repository's CI (CI-03). Since 1.0.0-beta11 the gate also fails on a stale suppression and tells a registry outage apart from a clean audit (T-236). Exercised on 2026-09-14 (f6dfb6a): RUSTSEC-2026-0285 — rustls 0.23.43 accepting TLS 1.3 handshake messages across encryption-level boundaries, CVSS 5.3, fixed in 0.23.45 — was published, the Security Scan went red the same day on a branch that had not touched TLS, and the lock was moved with `cargo update --precise` (rustls, `rustls-webpki`, and the `aws-lc-rs` / `aws-lc-sys` native crypto underneath every listener) and verified by re-running the OIDF FAPI 2.0 mTLS plan against the rebuilt binary rather than by reading a lockfile diff. Stated plainly: the `1.0.0-beta14` release artefacts of 2026-09-13 carry 0.23.43, and the fix ships with the next release; until then the advisory's own severity and scope are a deployment's exposure.

**T-128 — Metrics or traces disclose tenant identifiers**  
`Prometheus / Grafana` (Process) · Information disclosure · Medium · Mitigated

High-cardinality labels carrying usernames, tenant slugs or resource names turn a monitoring endpoint into a directory of the deployment.

> Metric labels are bounded to low-cardinality dimensions and carry no user or tenant identifiers; the metrics endpoint is not exposed through the ingress.

**T-129 — Erasure or expiry job silently stops running**  
`Scheduled jobs (cert expiry, GDPR erasure, sweeps)` (Process) · Repudiation · Medium · Mitigated

The 30-day GDPR erasure grace period and certificate-expiry warnings depend on scheduled work. A job that fails quietly produces a compliance gap that nobody sees.

> **CLOSED (T-129).** `GET /health/jobs` reports every background sweep:
> when it last succeeded, when it last failed, the error text, the
> consecutive-failure count, and a computed `stalled` flag. Alert on
> `status == "degraded"`, or on a named job's `stalled`.
>
> The distinction that made this worth building: a job that *errors* was
> already visible in the log, but a job that stops running produces no log
> line at all, and GDPR erasure failing that way is silent until a regulator
> asks. `stalled` is therefore measured from the last SUCCESS (falling back
> to process start, so a sweep that never ran once is still caught), not
> from the last error — a job failing every time is a different condition,
> reported separately by `consecutive_failures`.
>
> Returns 200 even when degraded, deliberately: this is not a readiness
> gate. A stuck sweep must not pull a serving pod from the load balancer and
> shift its traffic to replicas running the identical stuck code. Tolerates
> three missed intervals before flagging, because a sweep that overruns its
> interval under load is normal and an alert that fires on that gets muted.

**T-130 — Datastore reachable without authentication**  
`SurrealDB StatefulSet (cluster)` (Store) · Information disclosure · Critical · Mitigated

SurrealDB exposed on a Service without credentials, or with default credentials, hands over every tenant's data.

> The datastore runs on the private tier with no ingress and credentialed, namespaced connections sourced from Kubernetes Secrets. Verify no LoadBalancer or NodePort Service is created for it in your environment.

**T-131 — Default or shared broker credentials**  
`RabbitMQ StatefulSet (cluster)` (Store) · Information disclosure · High · Mitigated

A broker left on guest/guest, or with one credential shared by every service, lets any workload read authz decisions and audit events and publish forged ones.

> **CLOSED (T-131).** The shipped manifests never carried guest/guest — the
> broker's credentials come from the `rabbitmq-credentials` Secret, supplied
> at deploy time. What was genuinely missing is now added:
> `RABBITMQ_DEFAULT_VHOST: axiam`, so AXIAM gets its own authorization
> boundary rather than sharing the default `/` with anything else on a
> broker it does not have to itself.
>
> Fixing this exposed a defect that mattered more than the threat. The
> server's `AXIAM__AMQP__URL` lived in the **ConfigMap** as
> `amqps://rabbitmq:5671` — no credentials at all. `AmqpConfig` has only a
> `url` field, so there was nowhere else for them to go, and lapin falls back
> to guest/guest, which this broker rejects and RabbitMQ restricts to
> loopback regardless. The shipped manifests could not have connected to
> their own broker. The URL now lives in `axiam-secrets` (it embeds a
> password, so it was never ConfigMap material — T-132) with the `/axiam`
> vhost suffix.
>
> The compose stack deliberately stays on the default vhost, documented in
> place: nothing else shares that broker, and `RABBITMQ_DEFAULT_VHOST` is
> honoured only on the first boot of an empty volume, so adopting it there
> would require full data loss to gain a boundary with nothing behind it.
>
> Two controls this threat previously leaned on are unchanged and still
> apply: AXIAM verifies HMAC signatures on consumed messages, and the
> transport is not configurable — the server refuses any non-`amqps://`
> broker URL in every build profile, so a broker credential never travels in
> the clear.

**T-132 — Secret material placed in a ConfigMap or plain env var**  
`Secrets (Vault / K8s Secrets / ConfigMap)` (Store) · Information disclosure · High · Mitigated

ConfigMaps are not secret and environment variables appear in pod specs, crash dumps and debug output — a signing key or datastore password there is effectively public within the namespace.

> **CLOSED (T-132).** Two providers now keep key material out of the
> container spec, and the manifests use one of them by default rather than
> leaving it to the operator.
>
> The production stacks default to `AXIAM__AUTH__SECRET_PROVIDER=vault`,
> which keeps every long-lived secret behind Vault — at the cost of
> concentrating them behind one credential, which is T-180 and stays open.
>
> For deployments not running Vault, the `file` provider already existed and
> the manifests simply were not using it. `axiam-key-material` now mounts all
> eleven cryptographic secrets as files at `/etc/axiam/secrets`, one per
> logical name (`axiam_core::secrets::ALL_KEYS` + `ALL_SECRETS`), with
> `AXIAM__AUTH__SECRET_PROVIDER=file`. Mode `0440` plus `fsGroup: 65532` —
> both, because Kubernetes gives secret files to root:root and 0440 alone
> would lock the non-root container out of its own keys.
>
> Three of those keys (`opaque_session_key`, `opaque_setup_key`,
> `amqp_signing_key`) were absent from the old env-var Secret entirely, so
> those features could not be configured through the shipped manifests at
> all.
>
> **The residual is closed (R-5, 2026-09-12).** `AXIAM__DB__USERNAME`,
> `AXIAM__DB__PASSWORD` and `AXIAM__AMQP__URL` were read by the layered
> configuration before any secret provider existed, so a deployment that put
> every key in Vault still had its datastore password in the pod spec — the
> exact sentence this entry was closed on, one secret class short. They are now
> three more text secrets on the port (`db_username`, `db_password`,
> `amqp_url`), fetched in the same round trip as the other eleven, so **the
> Vault token — or the `file` provider's mount — is the only credential the
> container spec has to carry**. It stays, unavoidably: something must
> bootstrap the trust chain.
>
> The fix needed no `_FILE` convention, which is what the old text predicted.
> What it needed was for the two checks that forced the old shape —
> `load_config`'s assertions on the JWT keys — to run **after** the provider has
> been consulted. They did not move because they were wrong; they moved because
> they ran at the one point where they could see only one of the two sources,
> and that is why a `vault` deployment had to keep setting the very variable the
> provider exists to replace.
>
> The environment variables **stay permanently** (decision B of
> `remediation-plan-2026-09-12.md`): `env` is a supported provider kind, not a
> legacy path — the dev compose file, the E2E stack and any single-node
> deployment use it deliberately — so deprecating the variables would deprecate
> the provider that reads them. The `WARN` is scoped to the one case where the
> operator believes something untrue: a *non-`env`* provider configured, and the
> value arriving from the environment anyway.
>
> The seeder carries them and never **mints** them, and that difference is the
> design. A 256-bit key is meaningful only to AXIAM, so inventing one for an
> empty slot is what seeding is for; a datastore password has to match what
> SurrealDB was configured with, and inventing one gives a Vault that looks
> configured and a server that cannot connect. An existing value always wins
> over a supplied one, so re-running the seeder with a stale variable in the
> shell cannot silently undo a rotation (T-231).
>
> `docker/vault/axiam-policy.hcl` needed **no change** — it grants `read` on
> `secret/data/axiam` and the three fields live in that KV entry; the policy is
> path-based, not field-based. Worth recording, because "add the new secrets to
> the policy" is the reasonable first assumption and following it would mean
> editing a file that did not need editing.
>
> `DbConfig` and `AmqpConfig` gained hand-written redacting `Debug` impls. The
> broker URL embeds its credential inline by the AMQP URI's own design, so a
> derived `Debug` there is a password in every log line, panic message or error
> chain that renders a configuration — the shape of the three CodeQL findings
> T-260 closed, in the struct that most invites it. The redaction shows scheme,
> host and path and drops the userinfo, because a connection failure asks
> "which broker" and never "which password"; a value that does not parse as a
> URL is not echoed at all, since that is the value most likely to be a
> credential pasted into the wrong variable.
>
> All three secrets now sit behind the one Vault credential, which is T-180 and
> stays open. Enable etcd encryption at rest either way; see
> docs/deployment/vault.md.

**T-133 — Backup media accessible outside the cluster**  
`Backups / volume snapshots` (Store) · Information disclosure · High · Open

Backups contain everything the live datastore does, usually under weaker access control and longer retention.

> Not addressed by AXIAM. Encrypt backups at rest with a key separate from the cluster, restrict snapshot IAM, and include backup media in the same access review as the live data tier.

**T-134 — Backup stream unencrypted in transit**  
`scheduled backup` (Flow) · Information disclosure · Medium · Open

A backup written across the network without encryption exposes the entire datastore to anyone who can observe that path.

> Deployment responsibility: use an encrypted transport and server-side encryption on the backup target.

**T-165 — A non-persistent storage engine removes single-use arbitration**  
`SurrealDB StatefulSet (cluster)` (Store) · Tampering · High · Mitigated

SurrealDB's in-memory datastore does not reliably arbitrate the write-write conflict that decides a contended single-use redemption. It is not failing to arbitrate — it aborts contended attempts at the same ~54% rate the persistent engines do, then occasionally misses, silently, with both callers receiving the pre-transition row. An operator who points AXIAM at `surreal start memory` gets a server that boots cleanly and admits a second redemption in roughly 1% of contended rounds, defeating the first layer of T-163 and T-164 from below. Both retain their redemption-nonce layer, which asks the engine for nothing, so this weakens the guarantee rather than removing it — but the nonce alone was measured leaking on that engine too (3 rounds in 1200), so it is not a substitute.

> The shipped deployments pin a persistent engine — all three compose files and k8s/surrealdb/statefulset.yml pass surrealkv: — and docs/deployment/README.md carries it as a MUST-level operator requirement. axiam-server attests the engine at startup and refuses a memory datastore unless AXIAM__DB__ALLOW_MEMORY_ENGINE=true; because SurrealDB 3.2.4 publishes no datastore identity over the wire, that attestation currently logs a WARN, and a unit test fails on the version bump that makes the name available. A CI gate re-runs tools/surreal-race-probe whenever Cargo.lock moves surrealdb, surrealdb-core or surrealkv, so a bump cannot remove the arbitration silently.

**T-180 — Vault concentrates every long-lived secret behind one credential**  
`Secrets (Vault / K8s Secrets / ConfigMap)` (Store) · Information disclosure · High · Open

With `AXIAM__AUTH__SECRET_PROVIDER=vault` the production default, all ten long-lived secrets — the JWT signing key, `opaque_setup_key`, the PKI, MFA, federation and email encryption keys, the password pepper, the GDPR pseudonym pepper and the AMQP signing key — sit behind one KV path. A Vault token with read on that path, or the unseal or root material, is equivalent to every one of them at once; a dev-mode Vault left in production holds them unsealed in memory.

> Deployment responsibility, stated in `docs/deployment/vault.md` rather than enforceable in-product: run a production-mode Vault with TLS (the shipped prod stack does — TLS material, init, unseal, then seed), scope AXIAM's token to read-only on its own KV path with the documented policy, keep unseal keys and the root token offline, and enable Vault's audit device so secret reads are attributable. The tooling is shaped to help, and since **H-4 it checks rather than merely advises**: `just vault-status` queries `sys/capabilities-self` and reports the capabilities the token in hand actually holds on AXIAM's KV path, marking anything beyond `read` as `OVER-SCOPED` and naming a root token as what it is; `--strict` turns that into a non-zero exit for a deployment smoke test. It still reports secret presence only, never a value, and the seeder never rewrites a secret that already exists. Since 1.0.0-beta10 the token is no longer strictly read-only: it holds `read` on the startup path and `create`/`update` on `secret/data/axiam/ca-keys/*`, from the one policy file `docker/vault/axiam-policy.hcl`, and `just vault-status` reports missing capabilities as well as excess ones (T-232). Since 2026-09-12 (R-5) three more secrets sit behind that one credential — the datastore username and password and the broker URL, moved off the container spec to close T-132's follow-up — which widens exactly the concentration this entry records rather than narrowing it, and is the honest trade: a credential in a pod spec is readable by anyone with `get pod`, while a credential behind Vault is readable by whoever holds the token and revocable after the fact. The policy needed no change, because it grants `read` on the path rather than on fields.

**T-207 — A rolling deployment logs every not-yet-replaced replica out of the datastore**  
`AXIAM deployment (N replicas, HPA)` (Process) · Denial of service · High · Mitigated

Starting a second AXIAM process against the same SurrealDB took the first from healthy to 401 on every query within five seconds — permanently: still 401 after a 350-second window, and after the second process was removed (B-07). A rolling deployment does exactly this to every pod it has not replaced yet. Two independent causes: boot ran DEFINE USER OVERWRITE … PASSWORD on every start, and PASSWORD re-hashes with a fresh salt while SurrealDB signs root tokens against that hash, so each boot invalidated every token already issued; and the health check recognised only the WebSocket engine’s statement-level auth error while AXIAM runs the HTTP engine, whose transport-level 401 arrived looking like an ordinary query failure — so the reconnect loop never ran.

> Fixed in 1.0.0-beta05: boot reads the current token TTL from INFO FOR ROOT and skips the redefine when it already meets the configured value, with every unreadable case falling through to the redefine — wrong that way costs a redefine, wrong the other way would leave the TTL at the ~1h default while the re-signin task waits weeks. Health classification maps the HTTP engine’s 401/403 — matched narrowly on the status phrase, so a timeout or refused connection still gets ordinary retry rather than a pool rebuild on a blip — to Unhealthy, and reconnection swaps the pooled handles without a restart. Verified against the live stack: a second replica leaves login at 200 throughout, and a provoked credential invalidation recovers in tens of milliseconds with no caller-visible error.

**T-208 — The shipped proxy config diverges from the proxy CI tests**  
`Ingress controller (TLS 1.3)` (Process) · Tampering · Medium · Mitigated

The nginx config in the shipped admin-UI image used location /oauth2 — a prefix match that captured the SPA’s own /oauth2-clients route and answered a bare 404 before React was ever reached (F-02), so ProtectedRoute never ran and there was nothing to render or refuse. The vite preview proxy had the same shape, with /auth/mfa swallowing /auth/mfa-setup. The deeper defect: the fix had been made in the dev and preview proxies and never mirrored into the nginx config the image ships — and CI ran the E2E suite against vite preview, so the suite was green while the shipped artifact was broken. A route the proxy captures never reaches the permission layer, and no downstream permission assertion can tell “correctly refused” from “unreachable”.

> Fixed in 1.0.0-beta05: the nginx rule is narrowed to location /oauth2/ — all nine backend OAuth2 endpoints live under the slash-terminated prefix — and the preview regex gained the same boundary. The generalising guard is the spa-routing E2E matrix spec, which asserts every registered SPA route answers 200 text/html unauthenticated: a server-level check, run against the production image rather than the preview proxy, so the artifact being measured is the artifact being shipped.

**T-212 — An unaccounted proxy hop collapses every per-IP rate limit into one bucket**  
`Ingress controller (TLS 1.3)` (Process) · Tampering · High · Mitigated

`XForwardedForKeyExtractor` selects `hops[len - 1 - trusted_hops]` and falls back to `peer_addr()` when `trusted_hops >= len`. Both the extractor's own doc comment and three documentation sites told operators to set `AXIAM__RATE_LIMIT__TRUSTED_HOPS` to the *number of trusted proxy hops* — "1 behind a single ingress/nginx". That is off by one: a proxy appends the address it received **from**, not its own, so the nearest proxy is the socket peer and never appears in the header. Following the advice behind one proxy makes `trusted_hops >= hops.len()`, the header is discarded, and every client on the internet keys to the proxy's address. The documented Compose topology hit the same failure from the other direction — it had **two** appending proxies with the default `0`, so the extractor selected the inner proxy's address for every request. Either way the effect is one global bucket, including on `/auth/login`, which is deliberately keyed per-IP and never per-principal precisely so an attacker cannot lock a victim out. Collapsed, it does exactly that: one attacker's flood exhausts the allowance every legitimate user shares.

> Fixed in 1.0.0-beta08. The rule is stated as `trusted_hops = proxies − 1` with a derivation and a per-topology table in `crates/axiam-api-rest/src/extractors/rate_limit.rs`, `docs/deployment/README.md` and the docs site. Five tests in `rate_limit_keying_test.rs` pin the table, including a regression witness asserting that the old advice really does collapse two different clients onto one key. Structurally, the topology change removes the second hop, so both shipped deployments now have exactly one proxy and the default `0` is correct — and both set it **explicitly** anyway, with the derivation in a comment, because a value that is right by accident is one nobody re-derives when they add a load balancer. The gRPC listener shares the same variable and the same derivation, which is why publishing gRPC is sound only through the same proxy (T-233). Made **observable** in 1.0.0-beta12 (R-4), which is what the rest of this mitigation was missing: the fallback was correct and silent, and silence is how this off-by-one went unnoticed in the first place — every client keyed on the proxy, one bucket for the whole deployment, and the symptom reads as "the rate limit is mysteriously strict", which an operator fixes by raising the limit. Both extractors now emit one `WARN` per process on the first discard, naming the hop count seen, the `trusted_hops` in force and the rule, and increment `axiam_rate_limit_xff_discarded_total{protocol="rest"|"grpc"}` on every one; the boot log states the value and the rule together next to the rate-limit posture line. A request with no header is deliberately not counted — a client with no proxy is not a misconfiguration, and counting it would bury the signal — so the fault condition is the counter tracking total request volume, which a dashboard can show.

**T-213 — Path-routing at the edge makes the health endpoints internet-reachable**  
`AXIAM deployment (N replicas, HPA)` (Process) · Information disclosure · Medium · Mitigated

`/health`, `/ready` and `/health/jobs` are served at the **server root**, not under `/api/v1`. While the edge forwarded everything to the frontend's nginx — which proxies only `/api`, `/oauth2` and `/.well-known` — they were unreachable from outside by accident rather than by decision. Routing by path forces the decision, and the wrong answer is expensive: `/health/jobs` reports per-job scheduler state (names, last-run timestamps, consecutive-failure counts), which is a free map of what a deployment runs and what is currently broken in it, and `/ready` answers "can this instance reach its datastore", a cheap oracle for whether an attack on the datastore is working. Neither is rate-limited the way `/api` is, because neither was ever internet-facing.

> Deliberately **not routed** at the edge. The Caddyfile in `claude_dev/rpi5-prod-google-federation-guide.md` §4.3 claims `/api`, `/oauth2` and `/.well-known` and nothing else, so `/health` falls through to the SPA route and returns `index.html` rather than the health payload. The probes that need them — the Docker healthcheck and the Kubernetes liveness/readiness probes — reach the server on the container or pod network, which is where a health probe belongs. The guide shows the loopback probe for an operator checking by hand. Documented since 1.0.0-beta12 (R-6): `/health/jobs` carried a `#[utoipa::path]` annotation and a route from the day it was written and was listed in `paths(…)` by nothing, so it existed in the server and in no generated document — which also meant this decision had nowhere canonical to be stated for it. It is in `sdks/openapi.json` now, under the `health` tag with its response schemas, and deliberately excluded from the §27 SDK surface with the reason recorded in `gen-management-registry.py`: unlike `/health` and `/ready`, which answer a fixed one-word contract, it returns a variable inventory of a deployment's background jobs, and an SDK talks to the edge this endpoint is not routed at.

**T-214 — The TLS leaf expires because rustls binds it for the process's life**  
`AXIAM deployment (N replicas, HPA)` (Process) · Denial of service · High · Mitigated

rustls resolves the server certificate per handshake but reads nothing from disk: `with_single_cert` installed an immutable `SingleCertAndKey`, and actix binds the resulting config for the process's life. The certificate a server booted with was the certificate it served forever. Harmless for a leaf installed by hand once a year; a scheduled outage once an ACME client is involved, since Let's Encrypt issues for 90 days and clients renew at 60 — the renewed certificate lands on disk and changes nothing, and the listener starts failing every handshake on day 90. The only remedy was restarting an identity provider every couple of months, which drops in-flight requests and re-reads every secret out of Vault on a schedule.

> Fixed in 1.0.0-beta08. `ReloadableCertResolver` holds the certificate in an `ArcSwap` that rustls consults per handshake, so a renewal takes effect on the next connection with no restart and no dropped request — the same mechanism `ReloadableClientCertVerifier` already used for trust anchors, rather than a second one. Two triggers, because they fail differently: `SIGHUP` (immediate, what an ACME deploy hook sends, and a signal actix-server does not claim) and an hourly `stat` poll (`AXIAM__SERVER__TLS__RELOAD_INTERVAL_SECS`) for the case that actually happens — a hook nobody wired up, or a runtime that does not forward signals. The swap is validated before it happens: a reload that finds an unreadable or mismatched pair leaves the previous certificate serving and retries, which is what makes a renewal observed mid-write (certbot writes the chain and the key as two operations) a logged warning instead of a dead listener. A test drives two real TLS 1.3 handshakes against one `ServerConfig` and asserts the client is presented the renewed leaf on the second. The mechanism covers both listeners since 1.0.0-beta12: the gRPC listener resolves its leaf through the same `ReloadableCertResolver` instance whenever both are pointed at the same pair, so one trigger renews both — see T-234, closed by R-1.

**T-215 — A forwarded client certificate authenticates whoever can set the header**  
`IoT device / service account` (Actor) · Spoofing · Critical · Mitigated

`CertificateAuthenticated::extract` prefers the rustls-verified peer certificate and falls back to an `X-Client-Certificate` header when the connection carries none. `DeviceAuthService::authenticate` then checks the fingerprint, the status, the expiry, and the chain to the tenant or organization CA — every one of which a **copy** of an enrolled device's certificate also satisfies. A certificate is public data: it is handed out at enrollment, it appears in every handshake, and the certificates API returns it to anyone who may read it. Nothing on that path proves possession of the private key, and nothing can — possession is proven by a handshake, and on that path there was none. The fallback was sound only while the header could not originate with the client, i.e. while a trusted proxy terminated mTLS and overwrote it. It stops being sound the moment anything else can reach the listener, which is what exposing the backend does — and Caddy forwards client headers verbatim unless told otherwise.

> Fixed in 1.0.0-beta08. `AXIAM__AUTH__TRUST_FORWARDED_CLIENT_CERT` gates the fallback and defaults to **false**, so the header is consulted only where an operator asserts that a proxy they run performs the mTLS handshake and overwrites the header on every request. Native mTLS is unaffected and always preferred: a certificate rustls verified on the connection is authoritative and the setting is never consulted. Defence in depth rather than a single gate — the edge Caddyfile and `docker/nginx.conf.template` both strip `X-Client-Certificate` from inbound requests, so neither half has to be the only one. The FAPI2 client-credential path never accepted the header at all and still does not (`claude_dev/threat-model-stride.md` §5.3, X5.1): a client credential must not be assertable by anything that can set a header, and this brings the device path to the same standard. Devices that need real mTLS get a route the edge does not terminate — a second hostname or a TCP-passthrough Service — where rustls verifies the certificate itself.

**T-216 — The unseal key sits on the same disk as the sealed data**  
`Secrets (Vault / K8s Secrets / ConfigMap)` (Store) · Elevation of privilege · High · Open

`just prod-up` initialises Vault with a single Shamir share and writes it, with the root token, to `docker/.secrets/vault-init.json` — the same disk as the sealed data. That is not Shamir's scheme with the shares stored badly; it is no seal at all, and anyone who can read the disk can unseal and then read every long-lived secret AXIAM has (the set enumerated in T-180). The stack also handed the server that **root token**, so a credential visible in `docker inspect` could read, write and delete every secret, revoke tokens and mount engines — for a process that reads one path once at boot and never writes. Both were acceptable while `docker-compose.prod.yml` was only ever a laptop stack; they stopped being acceptable when a deployment guide pointed a real domain at it.

> Narrowed, not closed. `prod-up` now writes the read-only `axiam` policy from `docs/deployment/vault.md` §5.4 and issues a **scoped, periodic token** for the server, refusing to fall back to root if that fails; seeding keeps its own short-lived credential, because the seeding token and the serving token were never the same thing. Both the Compose stack and `k8s/vault/statefulset.yml` move from the `file` backend to **Raft**, which has a consistent backup story (`vault operator raft snapshot save`) and a migration path to three nodes that does not require a re-seed — a re-seed changes the OPAQUE setup key, i.e. a password reset for every user in every tenant. What remains **open** is auto-unseal, which cannot be closed from inside AXIAM: every Vault OSS seal type needs a cloud KMS or a second Vault elsewhere, and `pkcs11` is Enterprise-only, so a TPM is not an option whatever the hardware. `docs/deployment/vault.md` §5.3 and the Pi runbook §7.1 give the honest option table — GCP Cloud KMS at roughly $0.06 per key per month is the cheapest real answer — and state plainly that a deployment which configures none of them needs a human with three shares after every restart and is not production. A script that unseals from shares kept on the machine is explicitly **not** offered as an alternative: it removes the seal rather than automating it, and is strictly worse than Shamir because the shares are now in the one place an attacker already has. Two amendments since: the server's token is no longer strictly read-only — it holds `create`/`update` on the CA-key prefix, from the one policy file (T-232) — and the seeder that runs after unseal can no longer mistake a refused read for an empty Vault and mint fresh keys over the live ones (T-231). Vault itself runs unprivileged: the prod Compose stack chowns the Raft volume in a one-shot init container rather than running the process that holds every secret as root. Made **checkable** in 1.0.0-beta12 (R-7), the way H-4 made T-180's token scope checkable. `just vault-status` gains a Seal section from the unauthenticated `sys/seal-status` — so it answers even when the token is wrong and even when the Vault is sealed: it names the seal type, reads `OK` for any auto-unseal type, and for `shamir` says "no auto-unseal; every restart needs t of n key shares, not production" with the quorum quoted from the response. A Vault sealed at that instant gets its own line, because that is a state somebody is about to fix rather than a statement about the configured seal, and conflating the two would train an operator to ignore both; a request that fails reports `unknown`, never `OK`. `--strict` fails on an unconfirmed auto-unseal, and `just vault-status` still does not pass it so the dev stack's deliberate root-token-on-Shamir does not turn every local run red. **Status stays Open**: the control is a check, not a seal — nothing in this repository can configure auto-unseal, and R-7 does not pretend otherwise.

**T-217 — Credentials cross the internal network in cleartext**  
`proxy → axiam-server` (Flow) · Information disclosure · High · Mitigated

`docker/nginx.conf` proxied to `http://axiam-server:8090`. Every password on its way to `/api/v1/auth/login`, every bearer token, every session cookie and every OAuth2 client secret crossed the container network in the clear, readable by anything that could join that bridge or read the host's network namespace — which on a single host also running an operator's other containers is not hypothetical. The project's own standard ("TLS 1.3 minimum for all external communication") was satisfied only by treating the container network as not external, which is exactly the assumption CONTRACT §8b already refused to make for AMQP, where `AXIAM__AMQP__ALLOW_PLAINTEXT` was **removed** rather than left as an escape hatch. The REST leg was held to a weaker standard than the message bus for no recorded reason.

> Fixed in 1.0.0-beta08. `docker/nginx.conf` becomes a template whose upstream is rendered from `AXIAM_BACKEND_ORIGIN` / `AXIAM_BACKEND_SNI` / `AXIAM_BACKEND_CA`, and the documented topology points the edge at `https://` with the server terminating TLS 1.3 itself. Certificate verification is unconditional in every rendering: there is no `proxy_ssl_verify off` anywhere in the change and no documented setting that produces one, because a backend certificate that does not verify is a misconfiguration to fix and an escape hatch here is the first thing reached for at 3am. Defaults are unchanged, so the dev stack and the E2E suite keep the plaintext behaviour they rely on and reaching the frontend container directly keeps working.

**T-231 — A refused Vault read is indistinguishable from an empty Vault, and the seeder overwrites every live secret**  
`Secrets (Vault / K8s Secrets / ConfigMap)` (Store) · Tampering · High · Mitigated

The seeder's one invariant — a secret already present is never regenerated — was enforced by `vault_seed_payload.build()`, a pure function that has always been correct and unit-tested, behind a shell line that was not: `curl --fail … || echo '{}'` turned every failed read into "the Vault is empty", and `build()` cannot tell the two apart. `just prod-up` supplied the failure on a plate: Vault with Raft storage returns from `sys/unseal` while the node is still a standby contending for leadership, every request in that window is refused, and the recipe seeded immediately after unsealing — so a restart-driven run aimed the read straight at it. A revoked or write-only token reached the same end deterministically. The outcome was a full set of freshly minted keys written over the live ones, a `→ Seeded` line and exit 0; from then on every login answered `500` with `AES-GCM decrypt: aead::Error`, because `opaque_setup_key` no longer opened the OPAQUE records the datastore held (`mfa_encryption_key` fails the same way at the TOTP step). That is a password reset for every user in every tenant, caused by a restart. Reproduced against a fake Vault answering `500` to the read.

> Fixed in 1.0.0-beta11, in layers that each hold alone. `scripts/vault-seed.sh` waits for an **active** node — `sys/health` answering `200` — not merely a listening or unsealed one. The read's HTTP status reaches the payload builder: only `200` or `404` are statements about the contents of the path, `interpret_read` raises on everything else and the script exits non-zero with nothing written. The write is pinned with KV v2's `cas` to the version that was read — `0` to create, `N` to update — so even a stale-but-trusted read cannot clobber. `assert_preserved` refuses any payload that would replace a stored secret, with a carve-out only for the JWT pair's two documented replacement paths. `just prod-up` waits for `sys/health` to answer `200` after unsealing, before it seeds. `scripts/test_vault_seed_shell.py` drives the real script over real HTTP against a Vault answering `500`, `503`, `403` and `404` and asserts on what was written rather than on an exit code — eight of its twelve cases fail against the previous script — and both seeder test files now run in CI, which they never did: a well-tested pure function behind an untested boundary is exactly as safe as the boundary. Recovery for a deployment already hit: KV v2 keeps ten versions, and `docs/deployment/vault.md` §8.1 has the `vault kv patch` restore, which costs no password resets.

**T-232 — The server's Vault policy is quoted in several places, and none of them is checked against what the server does**  
`Secrets (Vault / K8s Secrets / ConfigMap)` (Store) · Elevation of privilege · Medium · Mitigated

The policy `just prod-up` wrote — and the one the production ceremony documented — granted `read` on `secret/data/axiam` and nothing on `secret/data/axiam/ca-keys/*`, where CA key custody writes one secret per CA. Because custody inherits `AXIAM__AUTH__VAULT_ADDR` / `_TOKEN` when no `AXIAM__PKI__VAULT_*` pair is set, every such stack booted cleanly, served every request, and refused its first organization CA with a `403`. A policy that is too narrow fails late and looks like a product bug, and the reflex fix — handing the server a broader token, or the root token — is precisely the failure T-180 and T-216 exist to prevent. A policy quoted in three documents and a recipe is one nobody re-derives, in either direction.

> Fixed in 1.0.0-beta10. The policy lives in one file, `docker/vault/axiam-policy.hcl`: `read` on the startup path — the server reads it once at boot and never writes it — plus `create`, `read` and `update` confined to the CA-key prefix, and `delete` on that prefix's metadata so a custody migration can release a key. `scripts/vault-policy.sh` applies it, the docs quote it, and the status reporter's tests assert against it. One glob covers both CA tiers, because `CaKeyStore::store` is keyed by `(organization_id, ca_id)` with no tenant segment, so tenant intermediates land beside the organization root; `vault_pki` custody is deliberately not covered and now says so. `just vault-policy` applies it to a running deployment — Vault evaluates policies per request, so nothing is restarted, re-initialised or re-seeded and nothing already stored is lost. `just vault-status` reports **missing** capabilities as well as excess ones, so the misconfiguration is visible before it becomes a `403`, and a `403` from CA key custody prints the missing stanza as HCL addressed to the mount and prefix that deployment configured. The token is therefore no longer read-only, and T-180 and T-216 say so rather than repeating the older claim.

**T-233 — A gRPC listener published by port-forward keys every rate limit on a header the client writes**  
`AXIAM deployment (N replicas, HPA)` (Process) · Spoofing · High · Mitigated

The gRPC listener is loopback-bound in Compose and ClusterIP-only in Kubernetes, a rule filed as SEC-003 when `UserService` and `TokenService` had no authentication at all. That is no longer true — every service is built with `with_interceptor(AuthInterceptor)`, derives tenant and subject from verified claims rather than the request body, `ValidateCredentials` accrues lockout, and neither reflection nor the health service is registered — so publishing the surface became a defensible choice, and the obvious cheap way to do it is unsound for a reason that has nothing to do with TLS. `GrpcTrustedHopsKeyExtractor` reads `X-Forwarded-For` before the verified connection peer, exactly as the REST extractor does (T-212); with no proxy appending the real peer, a client that sends one entry is keyed on a value it chose, and a value it varies per call mints a fresh bucket per call, so every ceiling becomes decorative. No value of `TRUSTED_HOPS` repairs it — for `n`, `n+1` client-written entries select the leftmost and fewer fall back to the peer — and both protocols read the one `AXIAM__RATE_LIMIT__TRUSTED_HOPS`, so they cannot be given different values. Publishing the whole `axiam.v1` package would also put `ValidateCredentials`, a real Argon2id password check, and `ReactorAdminService`, an administrative surface rate-limited like the hot path, on the internet by default.

> Recorded at 1.0.0-beta11. The bind stays loopback by default, and the blanket rule becomes a default rather than a prohibition: gRPC is published **through the edge on 443, path-matched, or not at all**. Caddy speaks HTTP/2 to the client, re-encrypts to the backend's own gRPC listener and appends the real peer, so the hop count is one on both protocols and the shared `TRUSTED_HOPS` stays correct for both. The documented route is an **allowlist** of services — `AuthorizationService`, `UserInfoService`, `TokenService` — so `UserService` and `ReactorAdminService` stay off the public edge unless an operator names them, with what each costs written beside the line that would add it; anything under `/axiam.v1.*` not listed falls through to the SPA handler and gets HTML back, a confusing refusal but a safe one. The site-wide stripping of `X-Client-Certificate` and `X-Real-IP` applies to the route. The listener's own TLS is enabled only when both `AXIAM__GRPC_TLS_CERT_PATH` and `_KEY_PATH` are set, and the server panics at startup if either names a file it cannot read — a typo is a failed boot, never a listener that quietly came up in cleartext. The runbook sets `AXIAM__GRPC__STRICT_REVOCATION=true` for a public listener so a revoked session does not keep passing for up to fifteen minutes, and states the per-IP-is-not-per-client sizing behind NAT. `claude_dev/public-backend-tls-design.md` §13 and the Pi runbook §14 carry the argument; `ReactorAdminService` left the authz rate-limit family in 1.0.0-beta12 (R-5): it fell through `GrpcMethodFamily::classify`'s catch-all, which puts an unrecognised path in the strictest *limited* family so a new service is throttled rather than unlimited — safe as a default, wrong as an outcome for an administrative surface, which was therefore sized like the hot path at 100/s per IP and raised by the `gateway` and `mesh` profiles. It now maps to `Admin`, whose ceiling is the absolute `ADMIN_PER_SEC_DEFAULT` (10/s) that no profile raises; the catch-all arm is unchanged. The listener's TLS was 1.3-capable but 1.2-negotiable when this was recorded, because tonic's `ServerTlsConfig` exposed no protocol-version knob; R-1 removed that limit and both listeners are TLS 1.3-only (T-234).

**T-234 — The gRPC TLS leaf expires because tonic reads it once at startup**  
`AXIAM deployment (N replicas, HPA)` (Process) · Denial of service · Medium · Mitigated

T-214 made the REST listener's certificate hot-reloadable so that an ACME renewal would never need a restart. That work covered the actix listener only: `axiam-api-grpc`'s `start_grpc_server` read `AXIAM__GRPC_TLS_CERT_PATH` / `_KEY_PATH` once, handed the PEM to tonic's `ServerTlsConfig`, and the crate contained no reload path and no poll. A gRPC listener that is public was therefore a listener whose certificate expires at day 90 while REST keeps working — the failure mode T-214 exists to prevent, reintroduced on the other protocol, and the worst version of it because it presents as a gRPC bug. The same API limit kept that leg TLS 1.2-negotiable where the REST listener is 1.3-only.

> Fixed in 1.0.0-beta12 (R-1). The gRPC listener no longer asks tonic to terminate TLS. `start_grpc_server` takes the rustls configuration as a value (`GrpcTls::Plaintext | Rustls(Arc<ServerConfig>)`), binds its own `TcpListener`, completes each handshake with `tokio-rustls`, and hands tonic an already-encrypted stream through `serve_with_incoming` — the hand-rolled accept loop this threat named as the structural fix, and it closes the reload gap and the TLS-version gap in the one change, as anticipated. The configuration is built by the composition root (`axiam_server::tls::build_grpc_rustls_server_config`), not by `axiam-api-grpc`: `ReloadableCertResolver` lives in `axiam-server` at layer 8 and the gRPC crate is layer 6, and `scripts/check-crate-layering.py` fails any edge pointing the other way. That builder resolves the leaf through `shared_resolver`, which returns the **same** resolver instance when both listeners name the same certificate and key — the documented topology, where there is no second certificate — so one `SIGHUP` or one hourly poll renews both; a deployment that really does point them at different files gets a second registered leaf reloaded on the same triggers, replacing the single-slot `OnceLock` that would have silently kept only the first. The configuration pins `with_protocol_versions(&[&rustls::version::TLS13])` and advertises ALPN `h2` alone, so the leg is TLS 1.3-**exclusive** rather than merely 1.3-capable. The flat env-var names and the panic-on-unreadable behaviour moved with the read and are unchanged: a typo is still a failed boot. Terminating the handshake here introduces one new denial-of-service surface — a client that opens TCP and never speaks — bounded by 512 concurrent handshakes taken with a non-blocking `try_acquire_owned` (so the accept loop is never starved, however many half-open clients are outstanding) and a 10-second handshake timeout that releases every permit; a failed or timed-out handshake logs at `debug` and drops that connection only, never the accept loop. Five tests carry it: a resolver swapped between two real handshakes against one running listener, with the connection established before the swap still usable after it; a TLS 1.2-only client refused rather than downgraded; a real TLS connection's peer address carried through `Connected::connect_info()` into the request extension and out of `GrpcTrustedHopsKeyExtractor` as the client's IP (verified against the pinned tonic before the code was written — had it come back `None` the limiter would have failed closed for everyone); sixty-four half-open connections not stopping a well-behaved client; and plaintext mode unchanged. On the server side, one reload covering every registered leaf, the shared-resolver identity asserted by pointer, and the boot panic for each half of an unreadable pair. The certbot deploy hook's container restart (Pi runbook §14.5) is now redundant rather than required.

**T-236 — A registry outage or a stale suppression turns the dependency-audit gate into a rubber stamp**  
`AXIAM deployment (N replicas, HPA)` (Process) · Tampering · Medium · Mitigated

The gate T-127 relies on failed in both directions at once. `npm audit` got `503` from the registry's audit endpoint, retried internally for seven minutes and exited `1` seconds after `npm ci` had reported zero vulnerabilities — a red job with no vulnerability anywhere in the tree, the kind of failure that teaches a team to re-run until green, and one that buried the line that explained it under four SARIF upload errors from producers that never ran. And four advisory suppressions had gone stale, emitting `advisory-not-detected` on every run: two for advisories already fixed upstream, two for crates no longer in the resolved feature graph at all. An ignore is keyed by advisory ID, not by version or crate, so one left behind after its crate leaves the graph silently re-suppresses that advisory if the crate ever comes back — a gate that has been quietly told what to ignore.

> Fixed in 1.0.0-beta11. The npm audit step retries with backoff and tells "found advisories" apart from "could not reach the endpoint" by the shape of the output rather than the exit code — npm exits `1` for both, but only a completed audit parses as JSON without an `error` key. A real HIGH/CRITICAL finding still fails the job; anything parseable that is not an error object counts as a real report, so an unfamiliar schema fails rather than being waved through; and a sustained outage ends in a `::warning::` that says explicitly it is not a clean bill of health. `cargo-deny` now runs with `-D advisory-not-detected`, so the next stale entry fails CI instead of scrolling past, and the two ignore-lists are allowed to differ legitimately — cargo-deny resolves the feature graph while cargo-audit reads `Cargo.lock` — under a containment check that demands an explicit `# audit-only: <ID> — <reason>` declaration and rejects one that is missing, unreasoned, contradictory or stale, with seven self-test cases. The yanked `chacha20 0.10.1` was bumped, and the four SARIF uploads are guarded on the file existing so a failed producer stops adding its own errors on top of the one that matters. `scripts/check-docker-context.py` closes the neighbouring class of the same shape — a gate that reads the worktree while the artifact is built from a filtered context, which is how the beta08 release lost both frontend image legs — by asking, for every `COPY`/`ADD` in every Dockerfile, whether at least one tracked file both exists and survives `.dockerignore`, cross-checked file by file against BuildKit's real context export. Narrowed deliberately at 1.0.0-beta13, and stated rather than folded into another change: the Trivy filesystem scan is scoped to what AXIAM ships — `crates/`, `frontend/`, `website/`, `examples/` and the root lockfile — and excludes the `benchmarks/` and `conformance/` harnesses, whose transitive CVEs (a netty CRITICAL under the Java bench) nothing in this repository can remediate and which were turning the gate red on every unrelated PR, which is how a red security check stops being read. The same wave removed 209 files of unbuilt design-system tooling that had entered the scan and the lint by accident.

**T-264 — A Vault CA bundle that parses to nothing silently replaces the operator's pin with the public trust store**  
`Secrets (Vault / K8s Secrets / ConfigMap)` (Store) · Tampering · Medium · Mitigated

`reqwest::Certificate::from_pem_bundle` errors on malformed PEM but answers `Ok` with an **empty** list for a file containing no PEM blocks at all — empty, truncated, DER rather than PEM, or a path that points at something else. The loop then added no roots and startup carried on, which is exactly the fallback the branch exists to prevent: continuing falls back to the default trust store, the check the operator asked for. Behind a publicly-trusted certificate the pinning is silently lost and everything appears to work; behind a private CA the connection fails with "error sending request", which reads as a network fault and sends the operator to the wrong place — and that is the likelier deployment, since `AXIAM__AUTH__VAULT_CA_CERT_PATH` exists precisely for it.

> c38879a: refused at the bundle, naming the file. Two tests under `tests/` so no fixture is instrumented — an unreadable path and a bundle that parses to nothing — and the empty-bundle case asserts the message is *not* a downstream "error sending request", because failing later, against Vault, was the original symptom. Found while writing tests for `SecretProviderKind::build`, the one place in that change where the code did not do what its comment said. The neighbouring invariant is now asserted too: `SettingsLockoutPolicy` falls back to the deployment default when a tenant is unresolvable or the settings store is unreachable, so brute force is still metered while the store is down — failure must not mean "no lockout" (T-178's rule).

**T-284 — A re-minted bootstrap setup token is a second way to create the first administrator**  
`AXIAM deployment (N replicas, HPA)` (Process) · Elevation of privilege · High · Mitigated

Only the SHA-256 hash of the one-time bootstrap setup token is stored, and `mint_bootstrap_setup_token_if_needed` is a no-op once a token row exists — so an operator who lost the token from the first-boot log had exactly one documented recovery, which was to wipe the volume (DF-019). Closing that cliff means adding a second credential path to `POST /api/v1/admin/bootstrap`, the endpoint that creates the first super-admin. Ungated, it would work on a deployment that already has administrators: an account takeover available to anyone who can run a command in the pod, with no authentication in front of it and nothing in the audit trail naming a principal.

> **S-6c (2026-09-22).** `axiam-server setup-token --remint` refuses — exit code **2**, and no write at all — unless the deployment has **no `user` row AND no redeemed setup token**.
>
> **The gate is the whole security argument, and it is a statement about time rather than about authorization.** Before bootstrap there is no administrator to take over and no credential to reset; that is precisely the state the operator who lost the token is stuck in. After bootstrap the deployment has an authenticated way to create accounts and a password-reset flow, so re-minting is never the answer, and the command says so rather than doing it.
>
> **Both gates are evaluated before the existing hash is deleted**, so a refused call leaves the current token working. The two are separate checks rather than one: a datastore can carry a consumed token and no `user` row — a restore, a purge, a rolled-back bootstrap — so neither implies the other.
>
> The token is printed to **stdout only**, never through `tracing`, so it does not reach the container log a second time; first-boot minting already makes that exception once, deliberately, and twice is a habit. There is no `--print`: the plaintext is not stored, and storing it so that it could be printed would be the wrong fix.
>
> The argv parse moved into `axiam_server::cli`, a unit-tested pure function, for one branch in particular: `setup-token` with the flag missing or mistyped must exit 2 rather than fall through to `Serve` and quietly start a second server against the production datastore.
>
> Tests: `remint_replaces_the_previous_hash` (one row before, one row after, a different hash — not two valid tokens), `remint_refuses_once_a_user_exists` and `remint_refuses_once_a_token_was_consumed`, the last two asserting the stored hash is **unchanged** after the refusal; five over the argv table, including the I4 twin that an unrecognised argument still serves.

</details>

### 5.9 Client SDKs & admin UI integration surface

The React admin UI and the eleven client SDKs (Rust, TypeScript, Python, Java, Kotlin, C#, PHP, Go, Swift, C, C++), which live in separate repositories and vendor CONTRACT.md, openapi.json and proto/ from here. Covers SDK transport and credential handling, token verification, the WebAuthn relying-party layer, account lifecycle and PAR operations (contract 1.28, §24–§26), AMQP HMAC consumption and the reactor protocol core, webhook verification and package-distribution supply chain — and, since 1.0.0-beta11, the release step that regenerates each SDK's §27 management surface from the spec it vendors (T-235). 1.0.0-beta13 adds the admin UI's redaction of secrets a gateway echoes back (T-265) and the contract's mTLS-alias and Basic-authentication rules (T-266). 1.0.0-beta14 is the SDK half of both of the previous day's contract additions, landed in all eleven repositories on 2026-09-13: the §10.4 revocation-feed poller, which closes T-143, and the §21.3 rule 2 alias handling with the §21.3.1 vectors, which retires the residual T-266 carried.

*28 threats — 2 critical, 14 high, 12 medium; 3 open.*

| # | Element | STRIDE | Threat | Severity | Status |
|---|---|:-:|---|---|---|
| T-135 | Integrator / developer <br/>*Actor* | S | Dependency-confusion or typosquatted SDK package | High | Open |
| T-136 | Browser user (admin UI) <br/>*Actor* | S | Stored XSS in the admin UI escalates to full tenant compromise | High | Mitigated |
| T-137 | React admin UI (Vite SPA) <br/>*Process* | T | State-changing request forged from another origin | High | Mitigated |
| T-138 | React admin UI (Vite SPA) <br/>*Process* | I | Tokens placed in localStorage instead of cookies | High | Mitigated |
| T-139 | SDK HTTP core (11 languages) <br/>*Process* | I | Credentials or tokens printed by default formatting | High | Mitigated |
| T-140 | SDK HTTP core (11 languages) <br/>*Process* | D | Concurrent refresh storms invalidate the token family | Medium | Mitigated |
| T-141 | SDK HTTP core (11 languages) <br/>*Process* | T | Contract drift between server and SDKs | Medium | Mitigated |
| T-142 | SDK token verification (JWKS cache, iss/aud) <br/>*Process* | S | JWKS URI taken from discovery without validation | High | Mitigated |
| T-143 | SDK token verification (JWKS cache, iss/aud) <br/>*Process* | E | Local JWT verification misses a revoked entitlement | Medium | Mitigated |
| T-167 | SDK token verification (JWKS cache, iss/aud) <br/>*Process* | E | Certificate-bound access token accepted as a bearer token by a resource server that ignores `cnf` | High | Mitigated |
| T-144 | SDK AMQP consumer (HMAC verify, nonce) <br/>*Process* | S | HMAC verification present but inoperative | Critical | Mitigated |
| T-145 | Webhook receiver helper (§13) <br/>*Process* | T | Receiver acts on an unverified webhook delivery | Medium | Mitigated |
| T-146 | SDK configuration (client secrets, CA bundles) <br/>*Store* | I | Long-lived client secret committed to a repository | High | Open |
| T-147 | sdks/CONTRACT.md, openapi.json, proto/ <br/>*Store* | T | Contract weakened without review | Medium | Mitigated |
| T-148 | Public package registries <br/>*Store* | T | Compromised release pipeline publishes a backdoored SDK | Critical | Open |
| T-149 | install SDK package <br/>*Flow* | T | Unpinned SDK dependency pulls a malicious transitive update | High | Mitigated |
| T-175 | SDK token verification (JWKS cache, iss/aud) <br/>*Process* | E | Sender-constrained token downgraded to a bearer token by a validator that cannot check `cnf` | High | Mitigated |
| T-183 | SDK HTTP core (11 languages) <br/>*Process* | T | SDK reshapes the WebAuthn ceremony the server configured | High | Mitigated |
| T-184 | SDK HTTP core (11 languages) <br/>*Process* | I | TOTP secret or setup token leaks through account-lifecycle serialization | High | Mitigated |
| T-185 | SDK HTTP core (11 languages) <br/>*Process* | I | Lifecycle helpers turned into an account-enumeration oracle | Medium | Mitigated |
| T-186 | SDK AMQP consumer (HMAC verify, nonce) <br/>*Process* | I | Caller-supplied reactor transport connects without TLS | High | Mitigated |
| T-199 | sdks/CONTRACT.md, openapi.json, proto/ <br/>*Store* | T | Two OpenAPI exports cannot be told apart, so vendored spec drift goes unseen | Medium | Mitigated |
| T-209 | React admin UI (Vite SPA) <br/>*Process* | I | The admin UI keeps rendering the previous tenant’s data after a switch | High | Mitigated |
| T-210 | sdks/CONTRACT.md, openapi.json, proto/ <br/>*Store* | T | The contract documents an acting-tenant header the server never reads | Medium | Mitigated |
| T-211 | React admin UI (Vite SPA) <br/>*Process* | E | The assignment dialog offers the widest possible grant as its only option | Medium | Mitigated |
| T-235 | sdks/CONTRACT.md, openapi.json, proto/ <br/>*Store* | T | A release tags an SDK whose generated management surface disagrees with the spec it vendors | Medium | Mitigated |
| T-265 | React admin UI (Vite SPA) <br/>*Process* | I | A gateway echoes a rejected request body and the UI renders a prefixed secret unredacted, or an Axios error path skips redaction | Medium | Mitigated |
| T-266 | SDK HTTP core (11 languages) <br/>*Process* | S | An SDK on a two-listener deployment authenticates at the front-channel host, or sends the secret over the header channel that intermediaries log | Medium | Mitigated |

<details>
<summary>Threat detail and mitigations</summary>

**T-135 — Dependency-confusion or typosquatted SDK package**  
`Integrator / developer` (Actor) · Spoofing · High · Open

The SDKs are published across the public registries — crates.io, npm, PyPI, Maven Central, NuGet, Packagist, the Go module proxy, Swift Package Index / CocoaPods, and GitHub Releases for C and C++. A typosquatted or hijacked package name delivers an attacker's code straight into an integrator's authentication path.

> Not fully controllable from this repository. Publish under reserved names, enable 2FA and trusted publishing on every registry, sign releases, and document the exact canonical package names in the SDK contract so integrators can verify what they installed.

**T-136 — Stored XSS in the admin UI escalates to full tenant compromise**  
`Browser user (admin UI)` (Actor) · Spoofing · High · Mitigated

Script injected through a user-controlled field (username, resource name, metadata) executes in an administrator's session and can drive every privileged action the admin can perform.

> React escapes interpolated output by default, the security-headers middleware sets a Content-Security-Policy, and auth cookies are HttpOnly so injected script cannot read them directly. Avoid dangerouslySetInnerHTML anywhere in the admin UI.

**T-137 — State-changing request forged from another origin**  
`React admin UI (Vite SPA)` (Process) · Tampering · High · Mitigated

Cookie-based sessions mean a cross-origin form or fetch can drive privileged endpoints in the victim's browser.

> D-01: the CSRF middleware requires an X-CSRF-Token header matching the axiam_csrf cookie on every state-changing method, compared in constant time; cookies are SameSite; CORS allowed origins are explicit with strict defaults. CONTRACT §3 mirrors the same behaviour in the SDKs.

**T-138 — Tokens placed in localStorage instead of cookies**  
`React admin UI (Vite SPA)` (Process) · Information disclosure · High · Mitigated

Tokens in localStorage are readable by any script on the origin, so a single XSS becomes a durable credential theft.

> The browser flow uses the Secure/HttpOnly axiam_access and axiam_refresh cookies (D-05..D-09); the SPA never handles the raw token, and CONTRACT §4 requires SDKs in cookie mode to use a cookie jar rather than application-readable storage.

**T-139 — Credentials or tokens printed by default formatting**  
`SDK HTTP core (11 languages)` (Process) · Information disclosure · High · Mitigated

A derived Debug/toString/repr on a client or config type prints the client secret or bearer token into the integrator's logs, where it is durably stored and widely readable.

> CONTRACT §7 mandates a Sensitive<T> wrapper for every secret field in every SDK, so the default formatting of a credential-bearing type is redacted — the same discipline applied server-side under SEC-067 / SECHRD-09.

**T-140 — Concurrent refresh storms invalidate the token family**  
`SDK HTTP core (11 languages)` (Process) · Denial of service · Medium · Mitigated

Refresh tokens are single-use with rotation. Parallel requests that each notice expiry and refresh independently race, and all but one redeem a rotated token — which reads as theft and can invalidate the family.

> CONTRACT §9 requires a single-flight refresh guard: concurrent callers await one in-flight refresh rather than each issuing their own.

**T-141 — Contract drift between server and SDKs**  
`SDK HTTP core (11 languages)` (Process) · Tampering · Medium · Mitigated

The SDKs vendor copies of CONTRACT.md, openapi.json and proto/. If the server changes and the copies do not, an SDK can silently stop enforcing a control it believes it implements.

> CI enforces this repository as the single source of truth: the SDK OpenAPI Drift Gate rebuilds the server, exports a fresh spec and fails on any difference from sdks/openapi.json, and the buf gates lint the protos and block breaking changes.

**T-142 — JWKS URI taken from discovery without validation**  
`SDK token verification (JWKS cache, iss/aud)` (Process) · Spoofing · High · Mitigated

An SDK that follows jwks_uri straight out of an OIDC discovery document lets whoever controls that document substitute the signing key — or point the fetch at an internal address (finding SDK-19, first seen in the PHP SDK).

> CONTRACT §12 requires the relying-party helpers to validate the discovery document and constrain jwks_uri to the configured issuer's origin before fetching, mirroring the server-side guarded_fetch discipline. Per-SDK conformance is verified in each SDK repository.

**T-143 — Local JWT verification misses a revoked entitlement**  
`SDK token verification (JWKS cache, iss/aud)` (Process) · Elevation of privilege · Medium · Mitigated

An SDK that verifies the access token locally cannot see a role removal or account disable until the token expires — the client-side face of the stateless-verification trade-off recorded on the token service.

> Bounded by the 15-minute access-token lifetime. CONTRACT §10 and §11 expose route-guard and declarative-authorization helpers; integrations needing immediate revocation can call gRPC introspection or CheckAccess rather than verifying locally. **The server half of the cheaper answer landed on 2026-09-12 (R-6, decision C); the client half landed in all eleven SDKs on 2026-09-13, and this entry is Mitigated from that date.** Contract 1.44 §10.4 defines an optional poller for `GET /oauth2/revocations` (see T-39 for what the server publishes and why it is safe to serve unauthenticated): default off, poll interval and cached set both bounded, never on the request path, and **never fail closed** — a guard that cannot fetch the document, gets a non-`200`, cannot parse it or sees an unknown `alg` behaves exactly as it does with the feature off, and specifically must not read any of those as an empty list, which would be a guard silently honouring no revocations while appearing to honour them. The feed can only ever turn an accept into a reject; every §10.1 rule still runs first and still decides. A token with no `sid` is never matched against it. §10.4.1 records, per SDK, whether it polls — and as in §21.9, an unrecorded row is not a supported answer. **As of 2026-09-13 every row says `yes`**: `RevocationFeed` (or the C ABI's `axiam_client_enable_revocation_feed`) attached to the JWKS verifier in each language, off unless the caller attaches it, with a test suite per SDK pinning the fail-open rule — the unreachable, non-`200`, unparseable and unknown-`alg` cases each asserted to verify exactly as with no feed, and never as an empty set — and the bounded interval and cache (§10.4 rule 2; the Rust poller, for one, drops the *whole* set on overflow rather than truncating it, because a truncated set admits some revoked sessions while reporting none). The eleven PRs are rust #104, typescript #103, python #80, java #92, kotlin #62, csharp #87, php #67, go #77, swift #60, c #59, cplusplus #60, merged and released at each SDK's 1.0.0-beta14. The residual is the poll interval itself, and that both sides are opt-in: an integration that attaches no poller is exactly where it was, which is the documented fifteen-minute trade and the gRPC introspection answer.

**T-167 — Certificate-bound access token accepted as a bearer token by a resource server that ignores `cnf`**  
`SDK token verification (JWKS cache, iss/aud)` (Process) · Elevation of privilege · High · Mitigated

An operator turns on certificate-bound access tokens (RFC 8705 §3) and the server duly stamps `cnf.x5t#S256` into every token it issues for that client. A resource server whose middleware does not understand the claim accepts the token anyway: the binding is decorative, a leaked token works exactly as it did before, and the operator believes otherwise. A subtler form of the same failure: a validator looks for `x5t#S256`, does not find it because the `cnf` names some *other* confirmation method, and concludes the token is unconstrained — downgrading a sender-constrained token to a bearer token precisely when a newer authorization server begins issuing a constraint that validator predates.

Note where this threat lives. Issuing the claim is the easy half and the server does it; the mechanism's entire security value depends on the **relying party**, which is why this is filed against SDK token verification rather than against the token service.

> Contract 1.15 makes the check normative for all eleven SDKs (§10.1 rule 9): a token carrying `cnf` is not a bearer token and MUST NOT be accepted as one. The rule is written as a four-row table whose last row is exactly the subtle failure above — a `cnf` naming an unimplemented method MUST be refused, never read as unconstrained — and the presented thumbprint MUST come from the transport, never from a caller-supplied header, or the mechanism is decorative for a different reason. Server-side, `axiam_auth::token::verify_certificate_binding` implements that table and is the reference; introspection exposes `cnf` (RFC 8705 §3.3) so an introspecting resource server cannot disagree with a locally-validating one. The contract additionally requires a *positive* regression test — an **unbound** token is still accepted with or without a certificate — because the likeliest wrong implementation of this rule is one that starts demanding certificates from every caller and breaks every existing deployment. Per-SDK conformance is verified in each SDK repository. **T-175 is the generalisation of this threat once a second confirmation method exists**, and is where the widened rule lives.

**T-175 — Sender-constrained token downgraded to a bearer token by a validator that cannot check `cnf`**  
`SDK token verification (JWKS cache, iss/aud)` (Process) · Elevation of privilege · High · Mitigated

T-167 anticipated this in its second paragraph, as a hypothetical: a validator meeting a `cnf` naming some *other* confirmation method. With DPoP landed there are now two methods in circulation, so it is no longer hypothetical — an SDK built against contract 1.15 will meet a `jkt` the first time an operator turns DPoP on. The natural-looking implementation ("no `x5t#S256` field, therefore unbound") silently converts a sender-constrained token back into a bearer token at exactly that moment. The same failure appears in a second guise on a token that names **both** confirmations: "check whichever one we can" honours the token under weaker terms than it was issued under.

> `axiam_auth::token::verify_token_binding` refuses a `cnf` naming no method it can check — **including an empty object**, because an absent claim means "never bound" while an empty one means "bound by something that did not survive the trip" — and treats two confirmations as a **conjunction** rather than a disjunction. The narrower `verify_certificate_binding` is deliberately retained for validators that genuinely cannot verify a proof, and it **refuses** a `jkt`-bound token rather than passing it; that refusal is the reason for keeping the narrower entry point rather than widening every caller to the new one. Contract 1.16 §10.1 rule 9 makes the same behaviour normative for all eleven SDKs, widening the four-row table to ten and adding a supported "we decline to verify proofs" posture (§21.7.3) whose only requirement is that declining means *rejecting*, never accepting as bearer. The positive regression test is widened too: an **unbound** token must still be accepted with no certificate and no proof, because demanding a proof from every caller remains the most likely way to implement this wrongly.

**T-144 — HMAC verification present but inoperative**  
`SDK AMQP consumer (HMAC verify, nonce)` (Process) · Spoofing · Critical · Mitigated

Finding X-1: AMQP HMAC verification was implemented but did not actually reject bad signatures in the Go and Rust SDKs — a security control that appears present and enforces nothing is worse than an absent one, because it is trusted.

> CONTRACT §8 specifies the protocol precisely — strip hmac_signature, canonicalise, HMAC-SHA256, constant-time compare, nack-without-requeue on mismatch, strict mode by default — and §8 v2 adds the mandatory nonce and issued_at replay fields. Conformance tests belong in each SDK repository.

**T-145 — Receiver acts on an unverified webhook delivery**  
`Webhook receiver helper (§13)` (Process) · Tampering · Medium · Mitigated

The server signs deliveries with the Stripe-style signed-timestamp scheme, but a receiver that does not verify the signature acts on any POST reaching its URL. Previously no SDK shipped a verify_webhook helper, so every integrator hand-rolled the check or skipped it.

> T-145 closed: CONTRACT.md §13 is now normative and all eleven SDKs (Rust, TypeScript, Python, Java, C#, PHP, Go, Kotlin, Swift, C, C++) ship a webhook-signature verifier against one canonical spec — HMAC-SHA256 over `<timestamp>.<raw_body>`, constant-time comparison on decoded MAC bytes, a header carrying no `v1` always fails, multiple `v1` values accepted for secret rotation, and a two-sided freshness window (default 300 s) so future-dated timestamps are rejected like stale ones. Verified present and conformant in all eleven repositories. Integrators must still call it.

**T-146 — Long-lived client secret committed to a repository**  
`SDK configuration (client secrets, CA bundles)` (Store) · Information disclosure · High · Open

Static client secrets in a config file, CI variable or container image are the most common way service-account credentials escape.

> Outside AXIAM's control. Mitigate by preferring mTLS or short-lived workload identity over static secrets, rotating regularly through the client-rotation endpoint, and enabling secret scanning on integrator repositories.

**T-147 — Contract weakened without review**  
`sdks/CONTRACT.md, openapi.json, proto/` (Store) · Tampering · Medium · Mitigated

The contract is where SDK security behaviour is actually specified — TLS policy, secret redaction, AMQP HMAC, CSRF. Relaxing a clause silently relaxes it across eleven implementations at once.

> The contract lives in this repository under normal review, and the drift and buf gates make any change to the generated artifacts visible in CI rather than in a downstream repository.

**T-148 — Compromised release pipeline publishes a backdoored SDK**  
`Public package registries` (Store) · Tampering · Critical · Open

A stolen registry token or a compromised release workflow publishes an SDK version that exfiltrates credentials from every integrator who upgrades.

> Partially enacted, and narrowed at beta03. Nine of the eleven pipelines carry no long-lived registry credential: Rust, TypeScript, Python and C# and the shared `axiam-opaque` core publish via Trusted Publishing (OIDC); PHP through Packagist's webhook; Go, Swift, C and C++ from git tags. Every release workflow in the fleet now pins its actions by commit digest, and every published artifact — the server's binary tarballs and CycloneDX SBOMs, the container images, and each SDK's release artifacts — carries a GitHub build-provenance attestation, so an integrator can verify build origin with `gh attestation verify`. Maven Central (Java, Kotlin) still requires a stored Portal user token: Central has no trusted-publishing equivalent, and its two OIDC surfaces are account sign-in and Sigstore *signing*, neither of which authorises an upload — the research is in [`maven-central-publishing-decision.md`](maven-central-publishing-decision.md). Those two are bounded by compensating controls instead: the credential is an environment secret behind a required-reviewer GitHub environment restricted to `v*` tags, every published file carries a Sigstore bundle (`.sigstore.json`) alongside its PGP signature — keyless, signed against the release workflow's GitHub OIDC identity and validated by the Central Publisher Portal, so the artifact set Central itself serves carries a statement of build origin the Portal token cannot forge — and the token rotates quarterly. A pull-request gate in each of those two repositories performs a real keyless signing run of the real artifact set on every change, so a release-path misconfiguration surfaces on a pull request rather than at a tag. Open because a stored bearer credential still exists for two of eleven registries.

**T-149 — Unpinned SDK dependency pulls a malicious transitive update**  
`install SDK package` (Flow) · Tampering · High · Mitigated

An SDK's own dependency tree is part of the integrator's authentication path; an unscanned transitive update reaches production silently.

> Finding CI-03 flagged that SDK dependencies were unscanned. This repository runs cargo-audit, cargo-deny and npm audit with SARIF upload and Dependabot on cargo, frontend npm and GitHub Actions; each SDK repository must carry the equivalent for its own ecosystem, and integrators should commit lockfiles.

**T-183 — SDK reshapes the WebAuthn ceremony the server configured**  
`SDK HTTP core (11 languages)` (Process) · Tampering · High · Mitigated

Contract 1.28 (§24) gives every SDK the relying-party half of the WebAuthn ceremony — four JSON round trips against the server. Every field in the server's `PublicKeyCredentialCreationOptions` is a security parameter, every one looks locally adjustable, and an SDK that "fixes" one — relaxing `userVerification` because a CI authenticator kept prompting, supplying a timeout the server omitted, re-encoding base64url "to be safe" — has weakened or broken a ceremony the server believes it configured. The server cannot catch a relaxation: an assertion produced under weaker options is still a valid assertion.

> CONTRACT §24.0 makes the pass-through rules normative for every SDK claiming §24: the server does all of the crypto and all of the policy; the SDK hands the server's options to the authenticator unchanged (no defaulting, no filling in, no normalizing), may not refuse options it parsed — a client-side algorithm allow-list is a second policy engine, and the tenant's is the only one that counts — and posts the authenticator's response back verbatim. The only permitted addition is the `authenticatorAttachment` hint, which selects which authenticator is prompted for, not what the server accepts. §24.8's required tests pin byte-identical pass-through, and §24.4 rule 1 does not license dumping a raw response body into an error an integrator would then log.

**T-184 — TOTP secret or setup token leaks through account-lifecycle serialization**  
`SDK HTTP core (11 languages)` (Process) · Information disclosure · High · Mitigated

Contract 1.28 (§25) brings MFA enrolment, email verification and password reset into every SDK, and with them a new crop of credential-bearing fields: `secret_base32`, the `otpauth://` URI that *contains* it, the forced-enrolment `setup_token` that completes a login, and the single-use reset and verification tokens. `totp_uri` is the field an implementer skips: wrapping the secret while leaving the URI bare wraps nothing, because the URI is what the caller passes to a QR renderer — and therefore the field that actually gets logged.

> CONTRACT §25.3 wraps every one of these fields in `Sensitive<T>`, names `totp_uri` in its own row precisely because it embeds the secret, and requires each SDK's §25 test to scan serialized output for the secret **value** itself rather than for the field name — which catches the URI case automatically. Single-use tokens are wrapped too: single-use is not the same as harmless, and a token is a credential right up until it is spent.

**T-185 — Lifecycle helpers turned into an account-enumeration oracle**  
`SDK HTTP core (11 languages)` (Process) · Information disclosure · Medium · Mitigated

Six of §25's nine operations are deliberately unauthenticated — a user who cannot log in is the entire audience for a password reset. Each is an enumeration oracle in waiting: an SDK that surfaces a "no such user" state on `request_password_reset` (even inferred from timing), distinguishes unknown from expired from already-consumed on a reset token, or displays the account a token belongs to beside the form re-creates exactly the oracle the server's uniform responses exist to prevent.

> CONTRACT §25.4 forbids all three, normatively: `request_password_reset` answers `200` whether or not the address exists and an SDK may not improve on it; `404` on the reset context means unknown, expired or already-consumed and the SDK's presentation may not distinguish them either; and the context response discloses no identity — contract 1.26 removed the username when OPAQUE made it unnecessary, and an SDK must not reintroduce one by inferring the account from elsewhere.

**T-186 — Caller-supplied reactor transport connects without TLS**  
`SDK AMQP consumer (HMAC verify, nonce)` (Process) · Information disclosure · High · Mitigated

Contract 1.28 (§22.11) brings the reactor protocol core — v2 HMAC over the canonical serialization, freshness in both directions, nonce and correlation binding, the §22.5 allow-lists — to Swift, C and C++ over a transport the caller supplies, because no vendorable AMQP client exists for those targets. The runtime never sees a broker URL, so it cannot enforce §8b itself: the integrator's transport is where a plaintext `amqp://` connection or a verification-skip flag would slip in, carrying signed-but-cleartext events and replies. Before 1.28 these three shipped nothing from §22 at all, and the sharper risk was integrators re-implementing the signing protocol from prose — which is how a signing bug ships.

> §8b rule 7's second clause is the whole of their obligation and it is discharged in code, not documentation: each of the three ships the rule 1–5 guard as a public, tested function (`amqpsEndpoint`, `axiam_amqps_endpoint`, `axiam::amqps_endpoint`) — scheme refusal with no loopback exception, no plaintext fallback, no verification-skip switch, fail-closed on an unparseable URL — and calls it in its own example transport before anything opens a socket. The transport seam is deliberately no wider than deliver-inbound and publish-reply, so it cannot hand the integrator the topology tools §22.1 forbids; the protocol core itself is now library code, ending the hand-rolled-HMAC divergence. HMAC signing (§8/§22.2) remains mandatory on every message regardless of transport.

**T-199 — Two OpenAPI exports cannot be told apart, so vendored spec drift goes unseen**  
`sdks/CONTRACT.md, openapi.json, proto/` (Store) · Tampering · Medium · Mitigated

Eleven SDK repositories vendor openapi.json and the §27 management registry, and generate client surface from them. Without a content identity, a stale or altered copy is indistinguishable from a faithful one — and the failure mode is real: 1.0.0-beta02 itself shipped a spec whose digest described beta01, because the release flow rewrote info.version under an assumption the digest field had deliberately inverted.

> Every OpenAPI export carries info.x-axiam-spec-digest, a SHA-256 over the document with that field absent, so two exports can be told apart and a vendored copy can be checked against the spec it claims to be (1.0.0-beta02). check-spec-digest.py recomputes the digest on every commit with no toolchain and no build, the SDK drift gate watches sdks/openapi.json itself, and the release script re-stamps the digest and regenerates the registry immediately after its version substitution — verified by replaying the release that broke (1.0.0-beta03). The digest tells an operator that the vendored spec moved; since 1.0.0-beta11 the release script also regenerates what each SDK derives from it (T-235).

**T-209 — The admin UI keeps rendering the previous tenant’s data after a switch**  
`React admin UI (Vite SPA)` (Process) · Information disclosure · High · Mitigated

Switching the acting tenant called queryClient.clear(), which removes and destroys cached queries — but a mounted observer keeps its reference to the orphaned query and goes on rendering the data it already had, with no refetch: the page the operator was looking at kept showing the previous tenant’s rows under the new tenant’s name. Two riders: pages rendered before /auth/me answered gated on the old tenant’s permission set, and page-local state survived the switch. Separately, the self-service endpoints scoped the caller’s own record to the acting tenant instead of principal_tenant_id, so an organization administrator with a tenant selected could not open their own profile, saw no MFA factors and could not enrol one — with nothing on screen changed but the tenant switcher.

> Fixed in 1.0.0-beta06: the query cache is namespaced by the acting tenant via queryKeyHashFn, so cross-tenant bleed is structurally impossible rather than procedurally avoided; the switch swaps the routed subtree for a spinner until /auth/me has answered, and the subtree is keyed by the acting tenant so page-local state resets. Server-side, user_scope_tenant states the self-vs-others rule once: a caller’s own resources resolve in principal_tenant_id, anybody else’s follow the acting-tenant header — written into CONTRACT §5.2.2 rule 4 (contract 1.36) so no SDK “fixes” the old 404 by stripping the header, which would break the administrative form of the same endpoints. Guards were added for the classes, not the instances: every /api/v1 literal in the app is checked against openapi.json, and an invalidation-coverage test fails on any cached root nothing can invalidate.

**T-210 — The contract documents an acting-tenant header the server never reads**  
`sdks/CONTRACT.md, openapi.json, proto/` (Store) · Tampering · Medium · Mitigated

CONTRACT §5.2, §5.2.2 and §5.2.3 told SDKs to switch the acting tenant by sending X-Tenant-ID — a header the server has never read (the extractor’s constant is X-Axiam-Tenant) — in eighteen places. The failure mode is silence, not a 4xx: an SDK following the contract to the letter sends a header nothing looks at, the request quietly acts on the principal’s own tenant, and the caller gets a successful response describing the wrong tenant’s data. §5.2.3’s rule that naming a tenant outside reachable_tenant_ids is refused could not be true as written, because nothing was read to refuse.

> Fixed in 1.0.0-beta06 (contract 1.36, closing #395): the three sections name X-Axiam-Tenant. §5 rule 2’s unconditional X-Tenant-ID is deliberately not renamed — folding a constructor-tenant header into the acting-tenant header would override the acting tenant on every request an organization-level principal made after switching, reintroducing the bug through its fix. It now carries a note that it exists for proxies, gateways and an SDK’s own §10 resource-server middleware, that AXIAM does not read it, and that it must not be renamed. The eleven contract-1.35 SDK fan-out PRs already implement the real header, so the correction lets them re-sync against a contract that agrees with them.

**T-211 — The assignment dialog offers the widest possible grant as its only option**  
`React admin UI (Vite SPA)` (Process) · Elevation of privilege · Medium · Mitigated

tenant_scope was reachable from exactly one of the places roles are assigned — the role page’s dialogs, and only while administering an organization scope, with both restrictions invisible. The user page’s Assign Role dialog posted a bare user id: no resource scope, no tenant scope, no sign either existed — and at organization scope an unscoped grant reaches every tenant of the organization, so the page offered the widest possible assignment as its only assignment, silently. A group — where “these people administer these tenants” is most naturally written down — could not be granted a role from its own page at all.

> Fixed in 1.0.0-beta06: one shared AssignRoleDialog serves the user and group pages with the same ResourceScopePicker and TenantScopePicker as the role page, in the same order — shared rather than written twice, because drift between two phrasings of one question is exactly what produced the defect. The scope picker distinguishes a principal that could switch to the organization scope (and is pointed at the selector) from one for whom that door does not exist, using the same predicate as the sidebar and the server’s own guard. Stated residual: has_role is created and deleted but never updated, so re-scoping an existing grant remains a revoke plus a fresh assignment — the transient under- or over-grant during the swap is the operator’s to sequence (docs/admin/organization-scope.md).

**T-235 — A release tags an SDK whose generated management surface disagrees with the spec it vendors**  
`sdks/CONTRACT.md, openapi.json, proto/` (Store) · Tampering · Medium · Mitigated

`scripts/mass-tag.sh` copies `CONTRACT.md`, `openapi.json` and `management-registry.json` into every SDK clone as part of a release, so a tagged SDK ships the spec its server was tagged from (T-199). It did not re-run the generator that turns those documents into each SDK's CONTRACT §27 management surface, so a release carrying schema changes tagged eleven trees whose committed code disagreed with the artifacts sitting beside it. v1.0.0-beta09 was the worked example: it re-vendored a spec carrying the WebAuthn user-verification policy (T-229) and regenerated nothing. Only the Swift, C and C++ SDKs said so, because they are the only three whose `§27 management surface drift-check` runs on a tag push; the other eight gate that job — or, in the Rust and TypeScript SDKs, the whole test job — to `pull_request`, and published a surface missing the new policy with no signal at all. A pure version bump then carried the broken trees forward through beta10.

> Fixed in 1.0.0-beta11. `mass-tag.sh` runs each SDK's generator immediately after the re-vendor and stages exactly what it wrote: the dirty set is recorded as path-plus-checksum before and after the call and compared as a symmetric difference, so an operator's unrelated local edit is never staged and a file that was stale before and correct after is recognised as repaired rather than missed. The generator table names all eleven repositories even where the answer is the common one, so a missing repository is a visible hole; a missing generator or interpreter is fatal rather than a skip, because tagging a tree the repository's own CI rejects is the failure this closes. The regeneration is unconditional — a surface can also be stale from a merge that moved the artifacts without regenerating, which is how beta09 went out — and prints "already current" in the common case. Verified against the live clones with a deliberately reverted surface in the C SDK, which was detected and exactly its six files staged. The repository-side gate closed in 1.0.0-beta12 (R-2), in all eleven SDK repositories: the §27 drift-check runs on tag pushes as well as pull requests, and the publish/release job lists it in `needs:`, so a stale surface fails *before* a version number is spent. Three shapes were found and fixed in place — six repositories had a dedicated job carrying `if: github.event_name == 'pull_request'` (dropped); Rust and TypeScript had the check as a step inside a `pull_request`-only test job (split into its own job, with the toolchain each generator needs); C, C++ and Swift already ran it on tags but their release job did not depend on it (one entry added to one list). Every generator was verified to detect drift locally — clean, perturbed, restored — rather than by pushing a deliberately red commit to eleven pull requests. Nothing else in any workflow changed.

**T-265 — A gateway echoes a rejected request body and the UI renders a prefixed secret unredacted, or an Axios error path skips redaction**  
`React admin UI (Vite SPA)` (Process) · Information disclosure · Medium · Mitigated

`redactSecrets` exists because the error body is not always written by AXIAM at all — a reverse proxy, a load balancer or a gateway can answer instead, and those echo requests routinely. Its key match used `\b(password|api_key|…)\b`; underscore is a word character, so `\bpassword\b` does not match inside `smtp_password`, and `smtp_password=hunter2`, `smtpPassword=…` and `provider_api_key=…` passed straight through — the key shape a gateway actually emits. Separately, four `onError` handlers in the email-configuration panel — the one panel in the application that handles SMTP passwords and provider API keys — rendered `err.message`, so a real `400` showed as "Request failed with status code 400" and never reached `redactSecrets()` at all.

> 2646add: the key is now word characters *ending* in a named secret, still followed by `\s*[:=]`, so widening the key does not widen what counts as a match — "password too short: minimum 12" and the SCIM "does not hold scim:provision" message stay intact, both already pinned — and a secret word counts only when it ends the key, so `password_policy` is not mistaken for a credential and configuration errors are not mangled, the failure mode that makes people stop trusting the UI and read the network tab instead. Checked for catastrophic backtracking at 2000-character runs, near-miss prefixes and 300 keys in one message. 0ac3d46: all four handlers go through `getApiErrorMessage`, the existing test that asserted the broken generic fallback now asserts the server's sentence, and a new test pins that a server-echoed password is redacted rather than rendered. Frontend line coverage moved from 92.6% to 96.6% with the threshold ratcheted to the achieved number, which is what found both.

**T-266 — An SDK on a two-listener deployment authenticates at the front-channel host, or sends the secret over the header channel that intermediaries log**  
`SDK HTTP core (11 languages)` (Process) · Spoofing · Medium · Mitigated

Once discovery can name a separate mTLS host (T-245), an SDK that ignores `mtls_endpoint_aliases` presents its certificate to a listener that never asked for one and authenticates nothing; one that reads an absent member as "unsupported" breaks against every single-listener deployment; one that synthesises an alias for the front channel raises a certificate-chooser dialog in the user's browser. And a server that accepts `client_secret_basic` (T-253) invites an SDK to send a long-lived credential in the one channel routinely logged by intermediaries.

> Contract 1.40 adds §21.3 rule 2, normative for the §21 client role only: an SDK making a call over mTLS must prefer an alias over the top-level entry, must read an absent member as "no separate host" rather than "unsupported", must not synthesise aliases for the three excluded endpoints, and must keep validating `iss` against the unchanged issuer; the guard role (§10.1 rule 9) is untouched, and the change is additive and server-side — every existing SDK keeps working unchanged against every existing deployment, because none publishes the member until an operator configures it. Contract 1.41 keeps §5 rule 3's MUST NOT on Basic authentication verbatim and changes only its rationale, from "the server documents no alternative" to the reason that was always the better one: the two methods carry the identical credential and only the header channel is routinely logged. Contract 1.42 records the two RFC 8414 discovery members as informative; SDK decoders ignore unknown members, as they did for `dpop_signing_alg_values_supported` and `mtls_endpoint_aliases`. **The SDK half landed on 2026-09-12 (R-8, contract 1.43).** Rule 2 had been normative since 1.40 and was implemented by nobody, which is the residual this closes: the server published the member and every SDK ignored it. Three things were added here first. The clause that was implicit — **an alias's query component is preserved, not appended to**: AXIAM's aliases carry the tenant as a query component, so an SDK that appends its own `?tenant_id=` produces a duplicated parameter the server cannot resolve to one tenant, and one that rebuilds the URL from host and path strips whatever else the deployment put there. Displacing the `tenant_id` value with the caller's own is correct and is explicitly not what the clause forbids — the multi-tenant document names no tenant and the client supplies its own. Reading the Rust SDK, which had implemented rule 2 since contract 1.40, is what produced that distinction: a first draft of the clause said "verbatim" and would have forbidden the one behaviour a multi-tenant deployment requires. Either way the failure is one that shows up *only* on a two-listener deployment, which is the deployment the rule exists for. The **§21.3.1 test vectors** — present, absent, malformed — published inside `CONTRACT.md` itself rather than as a fourth vendored artifact, so eleven repositories pin the same bytes and the existing drift gate already covers them; vector C must be **refused** rather than fallen back from, because quietly presenting a certificate to the front-channel host authenticates nothing while appearing to work; its two defects are a non-absolute URL and a scheme **weaker than the top-level endpoint it replaces** — comparing like with like, because an alias substitutes for exactly one endpoint. Neither "must be `https`" nor "weaker than the `issuer`" survives contact with an implementation: the server accepts an `http` alias for local development, every SDK suite runs against a mock server speaking plain HTTP, and a test fixture (or a deployment behind a TLS-terminating proxy) routinely pairs a realistic `issuer` string with loopback endpoints. Both wordings were tried against the Rust SDK and both failed tests that were correct. The refusal sits at the point of use, so a client with no certificate never reads the member and a malformed alias cannot break the clients that never use it. And the **§21.10 per-SDK table**, in the §21.9 style, where an unrecorded row is not a supported answer and `declines` with a reason is. Server side, two tests pin what SDKs pin: the alias object has exactly the six meaningful endpoints and never the three front-channel ones, and an unusable base (relative, non-`https`, or carrying a query or fragment) fails discovery rather than being published — so no conformant deployment can serve vector C and an SDK's refusal is defence in depth. Conformance rows 161–164. **The eleven implementations landed on 2026-09-13** (the same PRs as the §10.4 poller: rust #104, typescript #103, python #80, java #92, kotlin #62, csharp #87, php #67, go #77, swift #60, c #59, cplusplus #60, each released at that SDK's 1.0.0-beta14): §21.10 now has `yes` in both columns for every SDK, none `declines`, and each carries the three §21.3.1 vectors as tests — vector C refused at the point of use, so a client with no certificate never reads the member and a malformed alias cannot break the clients that never use it. Three of the eleven were first reported as unreachable for toolchain reasons and two of those reports were wrong (the .NET SDK is in Ubuntu's apt repository and NuGet was reachable; PHPUnit installs from apt); the Swift SDK alone was verified by CI rather than locally, and its commit says so. The residual this entry carried — a normative rule implemented by nobody — is closed; what remains is the ordinary one, that an integrator has to be on an SDK release that carries it.

</details>

## 6. Open risk register

13 of 285 threats remain open, and **none of them is an unhandled defect in AXIAM's own request path**: they are accepted design trade-offs, responsibilities that land on whoever deploys AXIAM, or gaps on the SDK and distribution side. For two revisions of this document that sentence carried a qualification, and it is worth recording why it is gone rather than simply deleting it. Phase 21 brought four entries from [`security-review-mcp-2026-09-17.md`](security-review-mcp-2026-09-17.md) that **did** sit on the request path — T-272, T-275, T-276 and T-280: filed defects with named fixes rather than trade-offs, open because each needed a settings field, a migration, a sweep or a change to a handler its own task did not touch. All four closed on 2026-09-17 and are recorded below. The qualification retires with them, which is what the previous revision said would happen, because its whole point was that the group existed. The thirteen that remain are the ones that were always here.


| # | Severity | Threat | Element | Why it is open |
|---|---|---|---|---|
| T-148 | Critical | Compromised release pipeline publishes a backdoored SDK | Public package registries <br/>*Client SDKs & admin UI integration surface* | Narrowed at beta03: nine of eleven pipelines publish credential-free, every release workflow pins actions by digest and every artifact carries a build-provenance attestation. Open because Maven Central (Java, Kotlin) has no trusted-publishing equivalent, so two stored Portal tokens remain — behind a required-reviewer environment, with keyless Sigstore bundles on every published file and quarterly rotation… |
| T-18 | High | Backup or snapshot exfiltration | SurrealDB cluster (all tenant data) <br/>*System diagram* | Not addressed by AXIAM itself. Deployment guidance: encrypt backups at rest, restrict snapshot IAM, and treat backup media as in-scope for the same access review as the live… |
| T-94 | High | Key extracted from device firmware or flash | IoT device <br/>*PKI, certificates & IoT device identity* | Outside AXIAM's control: private keys are generated for the device and returned once, never stored server-side, but hardware protection is the integrator's responsibility. AXIAM… |
| T-124 | High | Operator credentials grant unaudited data access | Cluster operator / SRE <br/>*Deployment & platform (Kubernetes)* | Outside the application boundary. Restrict RBAC on Secrets and exec, enable Kubernetes audit logging, and treat cluster-admin as equivalent to full AXIAM compromise in your threat… |
| T-133 | High | Backup media accessible outside the cluster | Backups / volume snapshots <br/>*Deployment & platform (Kubernetes)* | Not addressed by AXIAM. Encrypt backups at rest with a key separate from the cluster, restrict snapshot IAM, and include backup media in the same access review as the live data… |
| T-135 | High | Dependency-confusion or typosquatted SDK package | Integrator / developer <br/>*Client SDKs & admin UI integration surface* | Not fully controllable from this repository. Publish under reserved names, enable 2FA and trusted publishing on every registry, sign releases, and document the exact canonical… |
| T-146 | High | Long-lived client secret committed to a repository | SDK configuration (client secrets, CA bundles) <br/>*Client SDKs & admin UI integration surface* | Outside AXIAM's control. Mitigate by preferring mTLS or short-lived workload identity over static secrets, rotating regularly through the client-rotation endpoint, and enabling… |
| T-216 | High | The unseal key sits on the same disk as the sealed data | Secrets (Vault / K8s Secrets / ConfigMap) <br/>*Deployment & platform (Kubernetes)* | Narrowed at beta08: the server now holds a read-only token scoped to one path rather than root, seeding uses its own short-lived credential, and both Vault deployments moved to Raft. Open because **auto-unseal cannot be closed from inside AXIAM** — every Vault OSS seal type needs a cloud KMS or a second Vault elsewhere, and `pkcs11` is Enterprise-only, so a TPM is not an option. A deployment that configures none of them needs a human with three shares after every restart… |
| T-180 | High | Vault concentrates every long-lived secret behind one credential | Secrets (Vault / K8s Secrets / ConfigMap) <br/>*Deployment & platform (Kubernetes)* | Deployment responsibility — a token AXIAM is handed is a token AXIAM must use. Narrowed by H-4: `just vault-status` now reports the token's actual capabilities and flags anything beyond `read`, so the documented read-only policy is checkable rather than merely stated… |
| T-9 | Medium | Connection flood exhausts ingress capacity | Ingress / TLS 1.3 termination <br/>*System diagram* | Partly outside the application boundary: AXIAM enforces per-IP and per-user rate limits and Argon2 backpressure, but edge-level protection (WAF, connection limits, autoscaling) is… |
| T-123 | Medium | Final mail hop is not confidential | deliver mail <br/>*Audit, webhooks, email & notifications* | Inherent to email. Bounded by making the tokens carried in mail single-use and short-lived, so interception has a narrow window. Deploy MTA-STS and DANE on the sending domain to… |
| T-134 | Medium | Backup stream unencrypted in transit | scheduled backup <br/>*Deployment & platform (Kubernetes)* | Deployment responsibility: use an encrypted transport and server-side encryption on the backup target. |
| T-161 | Low | A partner's IdP silently populates the AXIAM user table (X4) | Attribute mapping & JIT provisioning <br/>*Federation — SAML SP & OIDC relying party* | Off by default (`linked_only` refuses unknown subjects). Every JIT provision is audited with the provider and the external subject, and a provisioned user holds no roles, so the exchange that created them still yields no token. Residual risk accepted: the same exposure the browser SSO JIT path already carries, bounded by the same per-client exchange rate limit. |

### Grouping

**Accepted design trade-offs** — deliberate, documented, and bounded.

- **~~No deny-override in the RBAC cascade~~ (SEC-040, T-16/T-87) — closed.** The engine now supports explicit deny: a grant carries `effect: "allow" | "deny"`, and a deny overrides every allow, at any depth of the resource hierarchy and at equal specificity. Recorded here as closed rather than deleted so the history stays legible; see `claude_dev/deny-override-design.md`.
- **Access tokens survive revocation for up to 15 minutes — or one poll interval.** The price of stateless verification. Use gRPC introspection where immediate revocation matters — or turn on the revocation feed (`AXIAM__AUTH__REVOCATION_FEED_ENABLED`, server side since 2026-09-12) and attach the poller every SDK ships since 1.0.0-beta14, which narrows the window to one poll interval for the cost of one cacheable fetch per interval rather than a round trip per request. Off by default on both sides, never fail-closed, and it narrows the trade rather than removing it, which is why the bullet stays although T-39 and T-143 are now Mitigated.
- **Audit records cannot be erased, only aged out.** Append-only by design, which is in tension with GDPR Art. 17; erasure anonymises the subject instead. Both sides are now bounded: retention defaults to a 730-day pruning window (T-119) applied by the background sweep, and collection can be minimised deployment-wide with `AXIAM__AUDIT__MINIMISE` (T-110, off by default) — a client address truncated to `/24` or `/48` and a user-agent reduced to its family, before the append, with the structured accountability metadata other mitigations depend on left alone. Tune both to match your lawful basis; there is still no on-demand deletion path, and the deployment still chooses — one that leaves minimisation off collects what it collected before.
- **A stale FIDO MDS3 BLOB is never a hard failure at ingestion (X3),** though `AXIAM__PKI__MDS_MAX_STALE_DAYS` now lets an operator bound how stale metadata may get before attested *registration* is refused (T-153).
- **~~A rotated refresh token stays redeemable for 60 seconds~~ (T-254) — closed.** Recorded here as closed rather than deleted so the history stays legible. Between 065f37c and 2026-09-12 the FAPI 2.0 §5.3.2.1-9 grace window applied to every profile, which on `standard` handed a bearer refresh token a replay window the server could not tell from an honest retry. The maintainer's decision confines the window to `fapi2`, where every token is sender-constrained and a replay inside it needs the client's private key — every other client is back to the predecessor being revoked at rotation — and makes a rotated token presented again visible whatever the window: a per-outcome counter on the session and an `oauth2.refresh_token_replayed` audit row. See [`t254-refresh-grace-decision.md`](t254-refresh-grace-decision.md).

**Deployment responsibilities** — AXIAM cannot close these from inside the application; they belong in a hardening checklist.

- Network policy so pods are not reachable around the ingress
- **Per-service** RabbitMQ credentials. Vhost separation is no longer on this list — the manifests now ship `RABBITMQ_DEFAULT_VHOST: axiam` (T-131) — but splitting one credential per service still belongs to whoever deploys. The transport itself is always TLS: the server refuses any non-`amqps://` broker URL
- Running Vault itself in production mode — TLS, a read-only token scoped to AXIAM's KV path, unseal and root material kept offline, audit device on (T-180). Every long-lived secret sits behind one credential, so the Vault posture is the secret posture
- etcd encryption at rest. Which secrets reach the container is no longer an operator choice (T-132): the manifests default to the Vault provider, and the `file` provider mounts key material for deployments without Vault. Since 2026-09-12 that covers the datastore and broker credentials too, so the Vault token (or the `file` mount) is the only credential the container spec has to carry; `AXIAM__DB__USERNAME`, `AXIAM__DB__PASSWORD` and `AXIAM__AMQP__URL` remain as a permanent fallback, and a deployment on a non-`env` provider that still uses them is told so at boot
- Backup encryption, restricted snapshot IAM, and backups included in access review
- Edge protection (WAF, connection limits) in front of the ingress
- **Auto-unseal on Vault** (T-216). The one production step AXIAM cannot take for you, and the one most often deferred: without it every restart leaves Vault sealed and the server crash-looping until a human with three shares arrives. A cloud KMS seal is the cheap answer (GCP Cloud KMS is roughly $0.06 per key per month); a transit seal against a Vault you already run elsewhere is the other. A script that unseals from shares kept on the machine is not auto-unseal
- **Deriving `AXIAM__RATE_LIMIT__TRUSTED_HOPS` for your own topology** (T-212). It is the number of proxies in front of the server **minus one**, and both too high and too low collapse every client into one bucket. The shipped values are right for the shipped topologies and stop being right the moment you add a load balancer or a CDN
- **Stripping `X-Forwarded-For` and `X-Client-Certificate` at the edge**, and at the firewall for any route that reaches the server without a proxy (T-215). A directly-reachable listener with `trusted_hops = 0` will honour an `X-Forwarded-For` the client invented, which is a fresh rate-limit bucket per request
- Kubernetes audit logging, since cluster-admin bypasses the AXIAM audit trail entirely
- Running SurrealDB on a **persistent** storage engine (`surrealkv:` or `rocksdb:`, never `memory:`). This is a correctness control, not a durability preference: the first layer deciding a contended single-use redemption is the engine aborting the loser of a write-write conflict, which the in-memory datastore does not do reliably (T-163, T-164, T-165). The shipped compose files and k8s StatefulSet already pin it, and the server cannot verify it for you — SurrealDB exposes no datastore identity over the wire, so `axiam-server` logs a WARN that the engine could not be attested
- Re-supplying the local FIDO MDS3 BLOB file on air-gapped deployments (`AXIAM__PKI__MDS_BLOB_PATH`) — there is no automatic refresh path off the public network, so an operator who never updates the file never gets the newer BLOB's revocations either

**Genuine gaps worth scheduling**

- **~~No SDK ships a webhook-signature verifier~~ (T-145) — closed.** The server signs deliveries with the Stripe-style signed-timestamp scheme, and as of the 2026-08-02 remediation every one of the eleven SDKs ships a conformant `verify_webhook(...)` helper against a canonical spec, with `CONTRACT.md` §13 made normative. What remains is integrator discipline, not a missing control: the helper still has to be called. Recorded here as closed rather than deleted so the history stays legible.
- **SDK package distribution.** Eleven SDKs across the public registries are that many opportunities for typosquatting or a hijacked release. The Rust, TypeScript, Python and C# pipelines and the shared `axiam-opaque` core now publish via Trusted Publishing (OIDC) with no long-lived registry token; Maven Central (Java, Kotlin) still needs stored credentials. Reserve names, keep 2FA on, and publish provenance attestations.
- **Static client secrets in integrator configuration.** Outside AXIAM's control, but the most common way service-account credentials escape. Prefer mTLS or short-lived workload identity.

**Closed at the 2026-09-17 T21.8 remediation** — recorded rather than deleted, as with T-145. **All four** of Phase 21's filed defects, decided and costed in [`issues-469-472-fix-plan.md`](issues-469-472-fix-plan.md) and fixed across two pull requests: [#475](https://github.com/ilpanich/axiam/pull/475) for T-280, which shares no file with the others and merged first, and [#476](https://github.com/ilpanich/axiam/pull/476) for the three that share `settings.rs`, `cleanup.rs` and both operator pages.

- **~~The trusted-publisher list that bounds the CIMD fetch admits a value meaning "every host"~~ (T-276) — closed (`0a273ec`, #469).** `cimd.trusted_client_id_domains` refused the empty list and admitted `*`, which means the same thing, so the interlock T21.5 added to remove the "a stranger chooses the fetch target" class had a one-character bypass — and the validator's own entry-shape message recommended the spelling that produced it. `*` and a wildcard over a whole top-level domain are now refused, at both settings doors, by one condition. A floor rather than a public-suffix check: `*.github.io` still passes, and what bounds shared hosting is T-275's quota.
- **~~Shadow client rows accumulate without a quota and are reclaimed by nothing~~ (T-275) — closed (`0b216c6`, #470).** `dcr_max_clients` now caps `managed_by: cimd` rows as a separate count against the same number, checked *before* the fetch so a tenant at its ceiling is not an outbound amplifier either; `dcr_unused_client_ttl_days` sweeps them on their own `/health/jobs` counter and their own clock; and the in-memory document cache evicts what it can no longer serve. No migration and no new column: `updated_at` was already "last presented", because every resolve upserts the row whether or not a fetch happened.
- **~~A stranger fills the tenant's registration quota and denies registration to legitimate clients~~ (T-272) — closed (`c4d9ea2`, #471).** A never-authorized `managed_by: dcr` row in `anonymous` mode is now swept an hour after registration rather than after 30 days, so filling the quota buys an hour of denial instead of a month. The per-IP share of the quota and the count-then-write overshoot stay as accepted residuals, with the conditions that would reopen them in T-272's detail block in §5.3.

- **~~A desktop client on an ephemeral loopback port is never told its authorization failed~~ (T-280) — closed (`b8bc508`, #472).** Six refusal paths in the authorization and PAR handlers compared the presented `redirect_uri` with `==` while the success path had applied RFC 8252 §7.3's port allowance since T21.2a, so a client that registered `http://127.0.0.1/callback` got its codes redirected to the port it was listening on and its errors rendered as a page its listener could not read. All six now call `any_redirect_uri_matches`. Fail-closed before and after — no error is redirected to a URI that was not registered — and byte-for-byte unchanged for every registration that is not an `http` loopback URI. The `http://[::1]/…` registration gap found alongside it closed in `7ab890d`, and MCP-06's accepted refusal is now pinned by a harness case so that a change to the query extractor cannot turn an accepted informational into an open Medium silently.

**Closed at 1.0.0-beta14 (2026-09-13)** — recorded rather than deleted, as with T-145.

- **~~Access token still valid after entitlement revocation~~ (T-39) and ~~Local JWT verification misses a revoked entitlement~~ (T-143) — closed.** Two faces of one trade, open since the first version of this model. The server half — an optional, off-by-default `GET /oauth2/revocations` publishing the base64url SHA-256 of each session id revoked within the last token lifetime, and nothing else — landed on 2026-09-12 and the entries were deliberately kept Open for a day, because a feed nobody polls narrows nothing. The client half landed on 2026-09-13 in all eleven SDKs (rust #104, typescript #103, python #80, java #92, kotlin #62, csharp #87, php #67, go #77, swift #60, c #59, cplusplus #60, each released at that SDK's 1.0.0-beta14): a poller attached to the JWKS verifier, opt-in, never on the request path, never fail-closed and reject-only, with contract §10.4.1 recording the attachment point per SDK and no row that `declines`. What remains is one poll interval rather than zero, on a feature both sides must turn on — kept above as an accepted trade-off.

**Closed at the 2026-08-21 review** — recorded rather than deleted, as with T-145.

- **~~Secret material in a ConfigMap or plain env var~~ (T-132) — closed.** The `file` secret provider already existed and the manifests were not using it; eleven cryptographic secrets are now mounted as files. The follow-up this entry named — datastore and broker credentials still env-supplied — was itself closed on 2026-09-12 (R-5): three more text secrets on the same port, fetched in the same round trip, with the environment kept as a permanent fallback that warns when a non-`env` provider is configured. The bootstrap credential is now the only one a container spec must carry.
- **~~Default or shared broker credentials~~ (T-131) — closed.** A dedicated `axiam` vhost. The larger find was that the shipped manifests carried a credential-free AMQP URL in the ConfigMap and could never have authenticated at all.
- **~~Erasure or expiry job silently stops running~~ (T-129) — closed.** `GET /health/jobs` reports every sweep's last success, failure and a computed `stalled` flag, measured from the last *success* rather than the last error.
- **~~Stale MDS metadata~~ (T-153) — closed, opt-in.** `AXIAM__PKI__MDS_MAX_STALE_DAYS` bounds how far past `nextUpdate` metadata may drift before attested registration is refused. Default `0` keeps fail-open, deliberately.
- **~~Unbounded audit growth~~ (T-119) — closed.** A default 730-day retention window, pruned by the background sweep through the table's first (and only) deletion path — deployment-wide, never reachable from any HTTP handler, `0` to disable, and both states logged at startup.

- **~~No deny-override in the RBAC cascade~~ (T-16, T-87) — closed (SEC-040 / B1).** These were carried as open long after the control shipped: their own detail blocks already read "SEC-040 — CLOSED (B1)" while the status column still said `Open`. The engine takes `effect: "allow" | "deny"` and a deny overrides every allow at any depth of the hierarchy and at equal specificity, verified by the precedence-table tests in `crates/axiam-authz/src/engine.rs` — including the property that motivates the choice, `adding_a_deny_can_never_widen_access`. A stale `Open` is not a harmless bookkeeping error: it argues for spending effort on a control that already exists, and it understates the product to anyone reading the model as a security statement.
- **~~Traffic reaches pods bypassing the ingress~~ (T-125) — closed (SEC-053).** The entry claimed "the shipped k8s manifests do not include NetworkPolicies"; they ship seven, including a namespace-wide default-deny on both ingress and egress. The genuine defect this review found was narrower and worse: the SurrealDB and RabbitMQ ingress policies were present as files but missing from `kustomization.yml`, so they were never applied — and because NetworkPolicy is enforced at both ends, that left the server unable to reach its own datastore or broker. Both are now listed; `kubectl kustomize k8s/` is the check.

## 7. Coverage

**By STRIDE category**

| Category | Threats |
|---|---|
| Spoofing | 68 |
| Tampering | 59 |
| Repudiation | 6 |
| Information disclosure | 67 |
| Denial of service | 28 |
| Elevation of privilege | 57 |

**By severity**

| Severity | Total | Open |
|---|---|---|
| Critical | 32 | 1 |
| High | 132 | 8 |
| Medium | 111 | 6 |
| Low | 10 | 2 |

**By diagram**

| Diagram | Threats | Open |
|---|---|---|
| System diagram | 31 | 2 |
| Authentication & session management | 35 | 0 |
| OAuth2 / OIDC authorization server | 58 | 4 |
| Federation — SAML SP & OIDC relying party | 31 | 1 |
| Authorization engine — RBAC, hierarchy & scopes | 27 | 0 |
| PKI, certificates & IoT device identity | 29 | 1 |
| Audit, webhooks, email & notifications | 18 | 1 |
| Deployment & platform (Kubernetes) | 28 | 5 |
| Client SDKs & admin UI integration surface | 28 | 3 |

## 8. Assumptions

The analysis holds only while these hold. If one stops being true, revisit the diagrams it touches.

1. TLS 1.3 terminates at the edge. The hop from the edge to the pods stays inside the cluster or host network **and is itself TLS 1.3** wherever the deployment carries a certificate for it — which the documented topology does (T-217). A deployment that leaves that leg plaintext is relying on the network being trustworthy, and should say so deliberately rather than inherit it from this assumption.
2. The data tier has no route from the public Internet.
3. The configured secret provider — Vault in the production stacks, Kubernetes Secrets otherwise — is the only source of key material, and CA signing-key custody is recorded per CA on its own row; nothing sensitive is baked into an image.
4. Cluster-admin is equivalent to full AXIAM compromise and is governed outside this model.
5. A federated IdP is trusted by the tenant that configures it — federation delegates authentication deliberately.
6. Integrators verify webhook signatures and AMQP HMACs as `sdks/CONTRACT.md` requires.
7. Tenant administrators are trusted within their own tenant and only there. Organization-level principals are trusted across their organization's tenants — and only their organization's; the reserved organization scope is a tenant, so every tenant-isolation control applies to it too.

## 9. Maintaining this model

Revisit the model when any of the following happens, and re-run the generator so this document tracks the JSON:

- A new API surface, protocol or external integration is added (the OPAQUE endpoints, the SCIM provisioning tokens and the Vault secret provider are the 2026-08 examples — each added or changed threats here; the OpenID Connect Basic OP surface of 1.0.0-beta13 — the browser login hop, the honour lane, the sensitive scopes, `client_secret_basic`, `POST /oauth2/userinfo` — is the 2026-09 one, T-237…T-245 and T-255…T-259, and it also added an element to the OAuth2 diagram, because three findings were about what the server does with a token it did not just mint and had no honest home on the diagram as drawn)
- A trust boundary moves — a new component, a change in deployment topology (organization-level principals moved the tenant ↔ tenant boundary in 1.0.0-beta02, and tenant signing CAs with per-CA Vault custody re-shaped the PKI diagram — T-187…T-199 record the 1.0.0-beta01…beta03 wave; tenant-scoped role assignments and the organization-principal guard narrowed the same boundary again in 1.0.0-beta05…beta06 — T-200…T-211 record that wave, most of it found by the E2E permission matrix run against the production image; and exposing the backend at `/api` on the public origin with its own TLS moved the edge ↔ server boundary in 1.0.0-beta08 — T-212…T-217 record that wave; the public login-provider surface of the same release is T-218…T-225, and publishing gRPC through that edge in 1.0.0-beta11 is T-233 and T-234)
- A security review raises a finding with no corresponding threat here — or an external run does: the OpenID Foundation conformance suite's first executions against a live AXIAM found the identity-cache hole (T-246), the resource-endpoint DPoP replay (T-247), the unreachable code-replay revocation (T-250) and three strong client-authentication methods no conformant request could use (T-252), none of which any internal review had, and each entered the model with the module that found it
- A deferred item lands (SEC-040 deny-override did, closing T-16/T-87) — and, for a control with a server half and a client half, when the *second* half lands: the revocation feed of 2026-09-12 left T-39 and T-143 Open on purpose until every SDK polled it the next day, because a feed nobody reads narrows nothing, and a model that closed them on the server commit alone would have described a control that did not yet exist for any integrator. The same pass corrected one element whose `hasOpenThreats` flag had gone stale (the deployment process carried `true` with every threat on it Mitigated); the flag is derived from the threats' statuses and the generator counts statuses rather than flags, so the website was never wrong, but the JSON should agree with itself
- The SDK contract gains or relaxes a security clause (contract 1.28's WebAuthn, account-lifecycle and PAR sections and the Swift/C/C++ reactor protocol core are the 2026-08-22 examples — T-183…T-186 record them; contract 1.37 and 1.38 added the login-provider operations and the handoff-origin rule — T-218…T-225)
- A conformance module moves from `REVIEW` to `PASSED` because the code changed, not because the evidence was re-read — the 2026-09-14 early-refusal pass is the example: a dead `request_uri` refused before the login hop and a `fapi2` client's `state` and `nonce` bounded at push entered as T-270 and T-271, and four existing entries (T-163, T-238, T-255, T-256) gained the clause that says what moved. And the reverse discipline, which the same week supplied: a fix that names a status *over REST* is not whole until every crate that renders a status carries it — T-262 was recorded Mitigated with `503` on two of three surfaces while `axiam-scim`'s own error type still answered `500`, and the entry now says so rather than absorbing the correction
- A fix changes what a grant, a policy or a credential *means* even when no surface moves (the beta09 authorization-reach fixes T-226…T-228 and the WebAuthn user-verification policy T-229…T-230 are the examples: nothing new was exposed, but what existing data authorises changed) — and the reverse case, a fix that *weakens* a property the model records, which is written down as an open item rather than absorbed: the beta13 refresh-rotation grace window amended T-37 and opened T-254 — and was then closed by a decision rather than by a further fix, which is the other half of the same discipline

Threat numbers are stable: add new threats with new numbers and raise `threatTop` rather than renumbering, so review comments and issues keep pointing at the right thing. Allocate them from `threatTop`, never from the last number in a section — the login-provider threats were first published as T-163…T-170, continuing §5.4's own sequence, and collided with numbers the model already held for §5.3's single-use credentials and §5.9's `cnf` threats. They were renumbered T-218…T-225 when they entered the model at 2.11.0 (they had lived only in this document until then, so nothing on the website pointed at them), and the four code comments that cite them moved with them.

---

**References** — [`design-document.md`](design-document.md) · [`security-audit.md`](security-audit.md) · [`final-security-review.md`](final-security-review.md) · [`../sdks/CONTRACT.md`](../sdks/CONTRACT.md) · [`../docs/compliance/`](../docs/compliance/) · [OWASP Threat Dragon](https://www.threatdragon.com)
