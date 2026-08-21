# AXIAM — STRIDE Threat Model

Threat model for AXIAM (Access eXtended Identity and Authorization Management), produced with the **STRIDE** methodology and maintained in **[OWASP Threat Dragon](https://www.threatdragon.com)** format.

| | |
|---|---|
| **Model file** | [`ThreatDragonModels/Axiam/Axiam.json`](../ThreatDragonModels/Axiam/Axiam.json) |
| **Methodology** | STRIDE (per-element) |
| **Tool** | OWASP Threat Dragon, model schema v2 |
| **Diagrams** | 9 |
| **Threats identified** | 181 |
| **Mitigated / Open** | 159 / 22 |
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
| **Tenant ↔ tenant** | Every tenant's data from every other tenant's | Tenant context derived from the verified session or JWT — never from request input — and enforced on every query and graph traversal |
| **AXIAM ↔ third parties** | Outbound to IdPs, email providers, webhook receivers | SSRF guard with resolve-and-pin, https enforcement, response size caps, HMAC signatures on webhook deliveries |
| **Server ↔ SDK / admin UI** | The server contract from its client implementations | `sdks/CONTRACT.md` clauses — TLS policy, secret redaction, CSRF, AMQP HMAC — enforced by CI drift and buf gates |

### Principal assets

| Asset | Where | Compromise means |
|---|---|---|
| JWT signing key (Ed25519) | Secret provider — Vault in production, Kubernetes Secrets otherwise | Any identity in any tenant can be forged |
| Organization CA private key | `ca_certificate`, AES-256-GCM encrypted | Any user, service or device certificate can be minted |
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

Level-0 context data-flow diagram: external actors, the three AXIAM API surfaces, the shared middleware pipeline, the core service layer and the private data tier. Trust boundaries separate the public Internet, the Kubernetes runtime and the data tier.

*27 threats — 3 critical, 14 high, 10 medium; 2 open.*

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

</details>

### 5.2 Authentication & session management

Password and OPAQUE (RFC 9807) login, MFA (TOTP and WebAuthn), lockout and rate limiting, JWT and refresh-token issuance, password reset and email verification, and the credential stores behind them.

*26 threats — 3 critical, 11 high, 10 medium, 2 low; 1 open.*

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
| T-39 | Token service EdDSA JWT + refresh rotation <br/>*Process* | E | Access token still valid after entitlement revocation | Medium | Open |
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

> The challenge token is a distinct, short-lived, single-use credential that only authorises the MFA verification call; it carries no API authority and is consumed on use.

**T-33 — TOTP code replay inside its validity window**  
`MFA verification TOTP / WebAuthn` (Process) · Spoofing · Medium · Mitigated

A code observed by a proxy or shoulder-surfer stays valid for the remainder of its 30-second step plus drift tolerance.

> Verified TOTP codes are recorded and refused on reuse within the acceptance window; the drift window is kept to the minimum RFC 6238 recommends.

**T-34 — Admin MFA reset abused as a takeover path**  
`MFA verification TOTP / WebAuthn` (Process) · Elevation of privilege · High · Mitigated

MFA enrolment reset must exist for lost devices, but an attacker who reaches an admin account can use it to strip the second factor from any user.

> Only org/tenant admins can reset MFA state; the reset is audited and raises an admin notification. Enrolment must be redone on next login before any resource is reachable.

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

> Refresh tokens are opaque, server-stored and single-use with rotation; redeeming a token that has already been rotated is detectable and invalidates the family.

**T-38 — Algorithm confusion or unsigned-token acceptance**  
`Token service EdDSA JWT + refresh rotation` (Process) · Spoofing · Critical · Mitigated

A verifier that honours the token's own alg header can be tricked into accepting alg=none or an HMAC token signed with the public key.

> The verifier pins EdDSA (Ed25519) and rejects any other algorithm; the expected algorithm is never read from the token header.

**T-39 — Access token still valid after entitlement revocation**  
`Token service EdDSA JWT + refresh rotation` (Process) · Elevation of privilege · Medium · Open

Access tokens are self-contained and valid for up to 15 minutes, so a role removal or account disable does not take effect on already-issued tokens until they expire.

> Accepted trade-off for stateless verification. The 15-minute lifetime bounds the window; sessions are invalidated on password change; deployments needing immediate revocation should use the gRPC introspection path rather than local JWT verification.

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

> Argon2id with OWASP-recommended parameters (m=19 MiB, t=2, p=1) and per-user salts makes bulk cracking expensive; policy enforces a 12-character minimum by default.

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

</details>

### 5.3 OAuth2 / OIDC authorization server

Authorization Code with PKCE, client credentials and refresh grants; consent, introspection, revocation, userinfo, JWKS and discovery; client registration and the code and token stores.

*24 threats — 2 critical, 14 high, 7 medium, 1 low; 0 open.*

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
| T-164 | authorization codes (single-use) <br/>*Store* | T | Two concurrent redemptions of one authorization code | High | Mitigated |
| T-166 | /oauth2/token (code, refresh, client credentials) <br/>*Process* | S | Stolen client credential replayed from anywhere on the network | High | Mitigated |
| T-168 | redirect with code <br/>*Flow* | S | Authorization-server mix-up delivers an honest server's code to an attacker's token endpoint | High | Mitigated |
| T-169 | /oauth2/token (code, refresh, client credentials) <br/>*Process* | S | Client assertion replay (private_key_jwt) | High | Mitigated |
| T-170 | /oauth2/token (code, refresh, client credentials) <br/>*Process* | S | Client assertion minted for another authorization server | High | Mitigated |
| T-171 | /oauth2/token (code, refresh, client credentials) <br/>*Process* | S | Algorithm confusion on a client assertion or DPoP proof | Critical | Mitigated |
| T-172 | /oauth2/token (code, refresh, client credentials) <br/>*Process* | S | DPoP proof replay | High | Mitigated |
| T-173 | Client registration & secret rotation <br/>*Process* | I | SSRF via a registered jwks_uri | High | Mitigated |
| T-174 | Client registration & secret rotation <br/>*Process* | D | Availability coupling to a client's JWKS endpoint | Medium | Mitigated |

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

> Claims are filtered by the token's granted scopes; profile, email and groups claims each require their corresponding scope.

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

> Two independent layers, so a double redemption needs both to fail (ilpanich/axiam#302). The guarded UPDATE runs inside an explicit transaction, making two concurrent redemptions a write-write conflict the storage engine aborts the loser of; and a per-attempt nonce is read back in a separate query after that transaction commits, so a conflict the engine silently missed is still caught. The read-back stays outside the transaction deliberately — inside one, snapshot isolation shows every racer its own write. Measured with tools/surreal-race-probe: zero double redemptions in 40 000 contended attempts on surrealkv and 9 600 on rocksdb. Layer one is a property of the storage engine, so the guarantee is conditional on running a persistent one — see T-165. authorization_code.consume carries the same two layers as of schema v37 (T-164).

**T-164 — Two concurrent redemptions of one authorization code**  
`authorization codes (single-use)` (Store) · Tampering · High · Mitigated

A code observed in a redirect or a proxy log and replayed at the same moment as the legitimate exchange could, if the two are not serialised, let both callers mint a token pair from one authorization. T-54 covers the sequential replay; this is the concurrent one, which the single-use flag alone does not decide.

> Two independent layers, the same pair the three credentials in T-163 carry (schema v37). The guarded UPDATE — used = false, with client_id and redirect_uri matched in the same statement so a wrong-client attempt cannot burn the code — runs inside an explicit transaction, so two concurrent redemptions conflict on one key and the engine aborts the loser; and a per-attempt redemption nonce is read back in a separate query after that transaction commits, catching a conflict the engine silently missed. Before v37 this path had the first layer implicitly (a lone statement runs in the engine's own transaction) and the second not at all, which left it resting on T-165 with nothing behind it. Guarded by authorization_code_consume_serialises over 50 rounds of 8 racers, and by an_authorization_code_redemption_stamps_its_nonce, which asserts the second layer directly — a race test cannot distinguish a two-layer mechanism from a one-layer one when the engine arbitrates either way.

**T-166 — Stolen client credential replayed from anywhere on the network**  
`/oauth2/token (code, refresh, client credentials)` (Process) · Spoofing · High · Mitigated

A confidential client's `client_secret` leaks — through a log, a CI variable, a config repository or an operator's shell history — and an attacker presents it from an arbitrary host to mint tokens as that client. A shared secret carries no evidence of *where* it is being used from, so the authorization server cannot distinguish the legitimate client from the thief.

> X5.1 adds RFC 8705 mutual-TLS client authentication. A client registered `tls_client_auth` or `self_signed_tls_client_auth` authenticates by presenting a certificate rustls verified during the TLS 1.3 handshake, matched against the registration's subject DN / SAN or its `x5t#S256` thumbprint. The private key never leaves the client, so the credential cannot be copied out of a log. Three details do the load-bearing work: the **registration** selects which credential authenticates and never the request, so the two methods can never become an OR an attacker may pick from; the `X-Client-Certificate` proxy header that the device-auth path accepts is deliberately not a source here, because a client credential must not be assertable by anything that can set a header; and every failure returns one uniform `invalid_client` description, so SEC-086's property — client existence stays undecidable to an unauthenticated caller — survives the new method. Certificate binding (T-167) then addresses the *tokens* the same way this addresses the credential.

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

> Layered, because no single layer is sufficient. (1) `iat` must be within 60 s in both directions. (2) `htm`/`htu` bind the proof to one method and one URI, compared with query and fragment stripped and nothing else normalised. (3) `ath` binds it to one access token, so a proof cannot be re-aimed at another token held by the same key. (4) `jti` is recorded single-use at the token endpoint through the same `UNIQUE`-index guard the client assertion uses, with the row expiring exactly at the end of the freshness window. (5) `dpop_require_nonce` optionally makes a proof unusable before the server has spoken. **Known residual:** the resource-server path in `axiam-api-rest`'s extractor is synchronous and does **not** record `jti`, so within the 60 s window a proof for that exact method, URI and token could be presented twice there. Documented in the extractor and in contract §21.7.2; closing it means moving the check into middleware that can await.

**T-173 — SSRF via a registered jwks_uri**  
`Client registration & secret rotation` (Process) · Information disclosure · High · Mitigated

A `private_key_jwt` client may register a `jwks_uri` that AXIAM fetches on demand to obtain the keys that authenticate it. That is an operator- or client-supplied URL the server will retrieve: pointed at a link-local metadata endpoint, an internal admin service or a loopback port, it turns client registration into a request-forgery primitive against the server's own network. A DNS name that resolves publicly at registration and privately at fetch time (rebinding) defeats a naive validate-then-fetch check.

> The fetch goes through `axiam_federation::jwks_cache::JwksCache`, the **same** guarded path a federated IdP's JWKS uses — not a bare `reqwest::get`. That guard (`ssrf::guarded_fetch`, SEC-054/SECHRD-02) resolves the host, rejects private, loopback and link-local addresses, and **pins the validated IP into the connection**, which is what closes the rebinding TOCTOU. A 512 KiB body cap bounds the response. Registration additionally refuses a `jwks_uri` that is not absolute `https`, so the operator hears about the mistake while onboarding. Reusing one guard rather than writing a second is deliberate: two guards are two chances for one to miss a fix.

**T-174 — Availability coupling to a client's JWKS endpoint**  
`Client registration & secret rotation` (Process) · Denial of service · Medium · Mitigated

A client registered with `jwks_uri` cannot authenticate if AXIAM cannot fetch its key set. Naively that makes every token request depend on a third party's uptime, and makes the token endpoint's latency a function of somebody else's TLS handshake.

> The shared JWKS cache serves keys for a 1-hour TTL without any HTTP, and serves **stale** keys for a further 24 hours when the client's endpoint is unreachable rather than failing the authentication. An operator who wants no outbound dependency at all registers the key set inline as `jwks`; the operator guide says which to choose and why.

</details>

### 5.4 Federation — SAML SP & OIDC relying party

Inbound federation from external identity providers: OIDC discovery and code exchange, SAML assertion consumption, the shared SSRF guard on every outbound IdP fetch, and attribute-to-role mapping with JIT provisioning.

*23 threats — 4 critical, 7 high, 10 medium, 2 low; 1 open.*

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

</details>

### 5.5 Authorization engine — RBAC, hierarchy & scopes

The three authorization entry points (REST middleware, gRPC CheckAccess, AMQP async), the default-deny RBAC engine with explicit deny-override and resource-hierarchy traversal, the decision cache, and the graph and audit stores behind them.

*15 threats — 4 critical, 4 high, 7 medium; 0 open.*

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

</details>

### 5.6 PKI, certificates & IoT device identity

Organization CA lifecycle, tenant certificate issuance with policy enforcement, mTLS device and workload authentication with full chain verification, revocation and CRL, and the OpenPGP key service used for audit signing and GDPR export encryption. Extended for X3 with FIDO MDS3 metadata ingestion (BLOB trust-chain verification, rollback protection, staleness posture) feeding the WebAuthn attestation policy engine.

*18 threats — 6 critical, 9 high, 3 medium; 2 open.*

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

> User-generated CAs are returned once and never stored. Only signing CAs whose key AXIAM must hold are persisted, and those are AES-256-GCM encrypted at rest in a separate, access-controlled table with the key held outside the datastore.

**T-96 — Weak key material from poor entropy**  
`CA management (generate / upload / rotate)` (Process) · Tampering · High · Mitigated

A CA or leaf key generated from a weak source is factorable or predictable, silently invalidating the whole hierarchy.

> Key generation uses the platform CSPRNG through rcgen with RSA-4096 or Ed25519; no custom or seeded RNG is used anywhere in the PKI path.

**T-97 — Certificate issued beyond the tenant's validity policy**  
`Certificate issuance (rcgen, policy enforcement)` (Process) · Elevation of privilege · Medium · Mitigated

An over-long certificate outlives the review cycle and cannot be retired without an explicit revocation.

> max_certificate_validity_days is an org/tenant setting, and the hierarchical settings rule means a tenant can only make it stricter, never longer, than the organization baseline.

**T-98 — Certificate issued for another tenant's subject**  
`Certificate issuance (rcgen, policy enforcement)` (Process) · Elevation of privilege · Critical · Mitigated

Issuing under a subject belonging to a different tenant would produce a credential that authenticates across the isolation boundary.

> Issuance is tenant-scoped from the authenticated context, and the signing CA is resolved from the requesting tenant's organization — a cross-tenant subject cannot be signed.

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

</details>

### 5.7 Audit, webhooks, email & notifications

The append-only audit trail and its OpenPGP batch signing, webhook delivery with HMAC signatures and the SSRF guard, the pluggable email service and templates, and admin notification rules.

*18 threats — 2 high, 14 medium, 2 low; 4 open.*

| # | Element | STRIDE | Threat | Severity | Status |
|---|---|:-:|---|---|---|
| T-106 | Webhook receiver (tenant endpoint) <br/>*Actor* | S | Receiver accepts unverified deliveries | Medium | Mitigated |
| T-107 | Email provider <br/>*Actor* | S | Provider API key reused to send mail as the tenant | Medium | Mitigated |
| T-108 | Audit middleware & service <br/>*Process* | R | Action succeeds while its audit write fails | High | Mitigated |
| T-109 | Audit middleware & service <br/>*Process* | T | Log injection through attacker-controlled fields | Medium | Mitigated |
| T-110 | Audit middleware & service <br/>*Process* | I | Personal data over-collected into an immutable log | Medium | Open |
| T-111 | Audit batch PGP signing <br/>*Process* | T | Signing gap leaves a batch unattested | Medium | Mitigated |
| T-112 | Webhook delivery (HMAC + guarded_fetch + retry) <br/>*Process* | I | Webhook URL used to reach internal services | High | Mitigated |
| T-113 | Webhook delivery (HMAC + guarded_fetch + retry) <br/>*Process* | T | Delivery replay by a party who captured one request | Medium | Mitigated |
| T-114 | Webhook delivery (HMAC + guarded_fetch + retry) <br/>*Process* | D | Retry storm against a slow endpoint | Low | Mitigated |
| T-115 | Email service (SMTP / provider API, templates) <br/>*Process* | E | Template injection through user-controlled placeholders | Medium | Mitigated |
| T-116 | Email service (SMTP / provider API, templates) <br/>*Process* | T | Header injection producing extra recipients | Medium | Mitigated |
| T-117 | Notification rules (admin alerts) <br/>*Process* | D | Alert flooding buries a real incident | Medium | Mitigated |
| T-118 | audit_log (append-only, signed) <br/>*Store* | T | Audit trail deleted along with the tenant | Medium | Open |
| T-119 | audit_log (append-only, signed) <br/>*Store* | D | Unbounded audit growth degrades the datastore | Low | Open |
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
`Audit middleware & service` (Process) · Information disclosure · Medium · Open

The audit log is append-only by design, so any personal data written into it cannot later be erased — which is in direct tension with the GDPR Art. 17 erasure path AXIAM also offers.

> Partially addressed: audit metadata is deliberately minimised and erasure anonymises the subject rather than deleting audit records. Deployments must set an audit retention period consistent with their lawful basis; AXIAM does not enforce one today.

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
`audit_log (append-only, signed)` (Store) · Tampering · Medium · Open

Deleting a tenant removes its data; if audit records go with it, the evidence of what happened disappears exactly when it matters most.

> Not resolved in-product: retention of audit records past tenant deletion is a deployment decision that conflicts with GDPR erasure. Export audit records to an external WORM sink before deletion if your retention obligations require it.

**T-119 — Unbounded audit growth degrades the datastore**  
`audit_log (append-only, signed)` (Store) · Denial of service · Low · Open

An append-only table with no retention policy grows without limit, eventually affecting query latency across the datastore.

> No retention or archival policy is enforced by AXIAM today. Operators should archive and prune on a schedule consistent with their compliance requirements.

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

Runtime and platform view: ingress, replicated AXIAM pods, scheduled jobs, monitoring, and the stateful tier — SurrealDB, RabbitMQ, Vault/Secrets and backups. Threats here are largely deployment responsibilities rather than application code.

*13 threats — 1 critical, 9 high, 3 medium; 8 open.*

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

> CI runs cargo-audit, cargo-deny (advisories, licences, bans, sources) and npm audit at a high threshold, uploads SARIF, and Dependabot covers cargo, the frontend npm tree and GitHub Actions. Residual: the eleven SDK repositories are scanned separately and are not covered by this repository's CI (CI-03).

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
> **One residual, worth stating plainly:** `AXIAM__DB__USERNAME`,
> `AXIAM__DB__PASSWORD` and `AXIAM__AMQP__URL` remain environment variables.
> They are read by the layered configuration before any secret provider
> exists, so moving them needs the config layer to learn a `_FILE`
> convention — a real follow-up, not done here. The Vault token stays too,
> and unavoidably: something must bootstrap the trust chain. Enable etcd
> encryption at rest either way; see docs/deployment/vault.md.

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

> Deployment responsibility, stated in `docs/deployment/vault.md` rather than enforceable in-product: run a production-mode Vault with TLS (the shipped prod stack does — TLS material, init, unseal, then seed), scope AXIAM's token to read-only on its own KV path with the documented policy, keep unseal keys and the root token offline, and enable Vault's audit device so secret reads are attributable. The tooling is shaped to help: `just vault-status` reports presence only, never values, and the seeder never rewrites a secret that already exists.

</details>

### 5.9 Client SDKs & admin UI integration surface

The React admin UI and the eleven client SDKs (Rust, TypeScript, Python, Java, Kotlin, C#, PHP, Go, Swift, C, C++), which live in separate repositories and vendor CONTRACT.md, openapi.json and proto/ from here. Covers SDK transport and credential handling, token verification, AMQP HMAC consumption, webhook verification and package-distribution supply chain.

*17 threats — 2 critical, 10 high, 5 medium; 4 open.*

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
| T-143 | SDK token verification (JWKS cache, iss/aud) <br/>*Process* | E | Local JWT verification misses a revoked entitlement | Medium | Open |
| T-167 | SDK token verification (JWKS cache, iss/aud) <br/>*Process* | E | Certificate-bound access token accepted as a bearer token by a resource server that ignores `cnf` | High | Mitigated |
| T-144 | SDK AMQP consumer (HMAC verify, nonce) <br/>*Process* | S | HMAC verification present but inoperative | Critical | Mitigated |
| T-145 | Webhook receiver helper (§13) <br/>*Process* | T | Receiver acts on an unverified webhook delivery | Medium | Mitigated |
| T-146 | SDK configuration (client secrets, CA bundles) <br/>*Store* | I | Long-lived client secret committed to a repository | High | Open |
| T-147 | sdks/CONTRACT.md, openapi.json, proto/ <br/>*Store* | T | Contract weakened without review | Medium | Mitigated |
| T-148 | Public package registries <br/>*Store* | T | Compromised release pipeline publishes a backdoored SDK | Critical | Open |
| T-149 | install SDK package <br/>*Flow* | T | Unpinned SDK dependency pulls a malicious transitive update | High | Mitigated |
| T-175 | SDK token verification (JWKS cache, iss/aud) <br/>*Process* | E | Sender-constrained token downgraded to a bearer token by a validator that cannot check `cnf` | High | Mitigated |

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
`SDK token verification (JWKS cache, iss/aud)` (Process) · Elevation of privilege · Medium · Open

An SDK that verifies the access token locally cannot see a role removal or account disable until the token expires — the client-side face of the stateless-verification trade-off recorded on the token service.

> Bounded by the 15-minute access-token lifetime. CONTRACT §10 and §11 expose route-guard and declarative-authorization helpers; integrations needing immediate revocation should call gRPC introspection or CheckAccess rather than verifying locally.

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

> Partially enacted: the Rust, TypeScript, Python and C# SDKs and the shared axiam-opaque core publish via Trusted Publishing (OIDC), so no long-lived registry token exists to steal for them; PHP publishes through Packagist's webhook and Go, Swift, C and C++ from git tags. Maven Central (Java, Kotlin) still requires stored credentials, and a compromised release workflow remains a live risk everywhere — pin and review workflow actions by digest as this repository's CI already does, and publish provenance attestations so integrators can verify build origin.

**T-149 — Unpinned SDK dependency pulls a malicious transitive update**  
`install SDK package` (Flow) · Tampering · High · Mitigated

An SDK's own dependency tree is part of the integrator's authentication path; an unscanned transitive update reaches production silently.

> Finding CI-03 flagged that SDK dependencies were unscanned. This repository runs cargo-audit, cargo-deny and npm audit with SARIF upload and Dependabot on cargo, frontend npm and GitHub Actions; each SDK repository must carry the equivalent for its own ecosystem, and integrators should commit lockfiles.

</details>

## 6. Open risk register

17 of 181 threats remain open. None of them is an unhandled defect in AXIAM's own request path: they are accepted design trade-offs, responsibilities that land on whoever deploys AXIAM, or gaps on the SDK and distribution side. They are listed most severe first.

| # | Severity | Threat | Element | Why it is open |
|---|---|---|---|---|
| T-148 | Critical | Compromised release pipeline publishes a backdoored SDK | Public package registries <br/>*Client SDKs & admin UI integration surface* | Enable 2FA and trusted/OIDC publishing on every registry, pin and review release workflow actions by digest as this repository's CI already does, and publish provenance… |
| T-18 | High | Backup or snapshot exfiltration | SurrealDB cluster (all tenant data) <br/>*System diagram* | Not addressed by AXIAM itself. Deployment guidance: encrypt backups at rest, restrict snapshot IAM, and treat backup media as in-scope for the same access review as the live… |
| T-94 | High | Key extracted from device firmware or flash | IoT device <br/>*PKI, certificates & IoT device identity* | Outside AXIAM's control: private keys are generated for the device and returned once, never stored server-side, but hardware protection is the integrator's responsibility. AXIAM… |
| T-124 | High | Operator credentials grant unaudited data access | Cluster operator / SRE <br/>*Deployment & platform (Kubernetes)* | Outside the application boundary. Restrict RBAC on Secrets and exec, enable Kubernetes audit logging, and treat cluster-admin as equivalent to full AXIAM compromise in your threat… |
| T-133 | High | Backup media accessible outside the cluster | Backups / volume snapshots <br/>*Deployment & platform (Kubernetes)* | Not addressed by AXIAM. Encrypt backups at rest with a key separate from the cluster, restrict snapshot IAM, and include backup media in the same access review as the live data… |
| T-135 | High | Dependency-confusion or typosquatted SDK package | Integrator / developer <br/>*Client SDKs & admin UI integration surface* | Not fully controllable from this repository. Publish under reserved names, enable 2FA and trusted publishing on every registry, sign releases, and document the exact canonical… |
| T-146 | High | Long-lived client secret committed to a repository | SDK configuration (client secrets, CA bundles) <br/>*Client SDKs & admin UI integration surface* | Outside AXIAM's control. Mitigate by preferring mTLS or short-lived workload identity over static secrets, rotating regularly through the client-rotation endpoint, and enabling… |
| T-180 | High | Vault concentrates every long-lived secret behind one credential | Secrets (Vault / K8s Secrets / ConfigMap) <br/>*Deployment & platform (Kubernetes)* | Deployment responsibility, stated in `docs/deployment/vault.md` rather than enforceable in-product: run a production-mode Vault with TLS, scope AXIAM's token to read-only on its… |
| T-9 | Medium | Connection flood exhausts ingress capacity | Ingress / TLS 1.3 termination <br/>*System diagram* | Partly outside the application boundary: AXIAM enforces per-IP and per-user rate limits and Argon2 backpressure, but edge-level protection (WAF, connection limits, autoscaling) is… |
| T-39 | Medium | Access token still valid after entitlement revocation | Token service EdDSA JWT + refresh rotation <br/>*Authentication & session management* | Accepted trade-off for stateless verification. The 15-minute lifetime bounds the window; sessions are invalidated on password change; deployments needing immediate revocation… |
| T-110 | Medium | Personal data over-collected into an immutable log | Audit middleware & service <br/>*Audit, webhooks, email & notifications* | Partially addressed: audit metadata is deliberately minimised and erasure anonymises the subject rather than deleting audit records. Deployments must set an audit retention period… |
| T-118 | Medium | Audit trail deleted along with the tenant | audit_log (append-only, signed) <br/>*Audit, webhooks, email & notifications* | Not resolved in-product: retention of audit records past tenant deletion is a deployment decision that conflicts with GDPR erasure. Export audit records to an external WORM sink… |
| T-123 | Medium | Final mail hop is not confidential | deliver mail <br/>*Audit, webhooks, email & notifications* | Inherent to email. Bounded by making the tokens carried in mail single-use and short-lived, so interception has a narrow window. Deploy MTA-STS and DANE on the sending domain to… |
| T-134 | Medium | Backup stream unencrypted in transit | scheduled backup <br/>*Deployment & platform (Kubernetes)* | Deployment responsibility: use an encrypted transport and server-side encryption on the backup target. |
| T-143 | Medium | Local JWT verification misses a revoked entitlement | SDK token verification (JWKS cache, iss/aud) <br/>*Client SDKs & admin UI integration surface* | Bounded by the 15-minute access-token lifetime. CONTRACT §10 and §11 expose route-guard and declarative-authorization helpers; integrations needing immediate revocation should… |
| T-119 | Low | Unbounded audit growth degrades the datastore | audit_log (append-only, signed) <br/>*Audit, webhooks, email & notifications* | No retention or archival policy is enforced by AXIAM today. Operators should archive and prune on a schedule consistent with their compliance requirements. |
| T-161 | Low | A partner's IdP silently populates the AXIAM user table (X4) | Attribute mapping & JIT provisioning <br/>*Federation — SAML SP & OIDC relying party* | Off by default (`linked_only` refuses unknown subjects). Every JIT provision is audited with the provider and the external subject, and a provisioned user holds no roles, so the exchange that created them still yields no token. Residual risk accepted: the same exposure the browser SSO JIT path already carries, bounded by the same per-client exchange rate limit. |

### Grouping

**Accepted design trade-offs** — deliberate, documented, and bounded.

- **~~No deny-override in the RBAC cascade~~ (SEC-040, T-16/T-87) — closed.** The engine now supports explicit deny: a grant carries `effect: "allow" | "deny"`, and a deny overrides every allow, at any depth of the resource hierarchy and at equal specificity. Recorded here as closed rather than deleted so the history stays legible; see `claude_dev/deny-override-design.md`.
- **Access tokens survive revocation for up to 15 minutes.** The price of stateless verification. Use gRPC introspection where immediate revocation matters.
- **Audit records cannot be erased.** Append-only by design, which is in tension with GDPR Art. 17; erasure anonymises the subject instead. Set a retention period consistent with your lawful basis.
- **A stale FIDO MDS3 BLOB is never a hard failure at ingestion (X3),** though `AXIAM__PKI__MDS_MAX_STALE_DAYS` now lets an operator bound how stale metadata may get before attested *registration* is refused (T-153).

**Deployment responsibilities** — AXIAM cannot close these from inside the application; they belong in a hardening checklist.

- Network policy so pods are not reachable around the ingress
- **Per-service** RabbitMQ credentials. Vhost separation is no longer on this list — the manifests now ship `RABBITMQ_DEFAULT_VHOST: axiam` (T-131) — but splitting one credential per service still belongs to whoever deploys. The transport itself is always TLS: the server refuses any non-`amqps://` broker URL
- Running Vault itself in production mode — TLS, a read-only token scoped to AXIAM's KV path, unseal and root material kept offline, audit device on (T-180). Every long-lived secret sits behind one credential, so the Vault posture is the secret posture
- etcd encryption at rest. Which secrets reach the container is no longer an operator choice (T-132): the manifests default to the Vault provider, and the `file` provider mounts key material for deployments without Vault. `AXIAM__DB__USERNAME`, `AXIAM__DB__PASSWORD` and `AXIAM__AMQP__URL` are the remaining environment variables, read before any provider exists
- Backup encryption, restricted snapshot IAM, and backups included in access review
- Edge protection (WAF, connection limits) in front of the ingress
- Kubernetes audit logging, since cluster-admin bypasses the AXIAM audit trail entirely
- Running SurrealDB on a **persistent** storage engine (`surrealkv:` or `rocksdb:`, never `memory:`). This is a correctness control, not a durability preference: the first layer deciding a contended single-use redemption is the engine aborting the loser of a write-write conflict, which the in-memory datastore does not do reliably (T-163, T-164, T-165). The shipped compose files and k8s StatefulSet already pin it, and the server cannot verify it for you — SurrealDB exposes no datastore identity over the wire, so `axiam-server` logs a WARN that the engine could not be attested
- Re-supplying the local FIDO MDS3 BLOB file on air-gapped deployments (`AXIAM__PKI__MDS_BLOB_PATH`) — there is no automatic refresh path off the public network, so an operator who never updates the file never gets the newer BLOB's revocations either

**Genuine gaps worth scheduling**

- **~~No SDK ships a webhook-signature verifier~~ (T-145) — closed.** The server signs deliveries with the Stripe-style signed-timestamp scheme, and as of the 2026-08-02 remediation every one of the eleven SDKs ships a conformant `verify_webhook(...)` helper against a canonical spec, with `CONTRACT.md` §13 made normative. What remains is integrator discipline, not a missing control: the helper still has to be called. Recorded here as closed rather than deleted so the history stays legible.
- **SDK package distribution.** Eleven SDKs across the public registries are that many opportunities for typosquatting or a hijacked release. The Rust, TypeScript, Python and C# pipelines and the shared `axiam-opaque` core now publish via Trusted Publishing (OIDC) with no long-lived registry token; Maven Central (Java, Kotlin) still needs stored credentials. Reserve names, keep 2FA on, and publish provenance attestations.
- **Static client secrets in integrator configuration.** Outside AXIAM's control, but the most common way service-account credentials escape. Prefer mTLS or short-lived workload identity.

**Closed at the 2026-08-21 review** — recorded rather than deleted, as with T-145.

- **~~Secret material in a ConfigMap or plain env var~~ (T-132) — closed.** The `file` secret provider already existed and the manifests were not using it; eleven cryptographic secrets are now mounted as files. Datastore and broker credentials remain env-supplied — see the entry for why, and treat it as the open follow-up.
- **~~Default or shared broker credentials~~ (T-131) — closed.** A dedicated `axiam` vhost. The larger find was that the shipped manifests carried a credential-free AMQP URL in the ConfigMap and could never have authenticated at all.
- **~~Erasure or expiry job silently stops running~~ (T-129) — closed.** `GET /health/jobs` reports every sweep's last success, failure and a computed `stalled` flag, measured from the last *success* rather than the last error.
- **~~Stale MDS metadata~~ (T-153) — closed, opt-in.** `AXIAM__PKI__MDS_MAX_STALE_DAYS` bounds how far past `nextUpdate` metadata may drift before attested registration is refused. Default `0` keeps fail-open, deliberately.

- **~~No deny-override in the RBAC cascade~~ (T-16, T-87) — closed (SEC-040 / B1).** These were carried as open long after the control shipped: their own detail blocks already read "SEC-040 — CLOSED (B1)" while the status column still said `Open`. The engine takes `effect: "allow" | "deny"` and a deny overrides every allow at any depth of the hierarchy and at equal specificity, verified by the precedence-table tests in `crates/axiam-authz/src/engine.rs` — including the property that motivates the choice, `adding_a_deny_can_never_widen_access`. A stale `Open` is not a harmless bookkeeping error: it argues for spending effort on a control that already exists, and it understates the product to anyone reading the model as a security statement.
- **~~Traffic reaches pods bypassing the ingress~~ (T-125) — closed (SEC-053).** The entry claimed "the shipped k8s manifests do not include NetworkPolicies"; they ship seven, including a namespace-wide default-deny on both ingress and egress. The genuine defect this review found was narrower and worse: the SurrealDB and RabbitMQ ingress policies were present as files but missing from `kustomization.yml`, so they were never applied — and because NetworkPolicy is enforced at both ends, that left the server unable to reach its own datastore or broker. Both are now listed; `kubectl kustomize k8s/` is the check.

## 7. Coverage

**By STRIDE category**

| Category | Threats |
|---|---|
| Spoofing | 47 |
| Tampering | 36 |
| Repudiation | 5 |
| Information disclosure | 47 |
| Denial of service | 18 |
| Elevation of privilege | 28 |

**By severity**

| Severity | Total | Open |
|---|---|---|
| Critical | 25 | 1 |
| High | 80 | 7 |
| Medium | 69 | 7 |
| Low | 7 | 2 |

**By diagram**

| Diagram | Threats | Open |
|---|---|---|
| System diagram | 27 | 2 |
| Authentication & session management | 26 | 1 |
| OAuth2 / OIDC authorization server | 24 | 0 |
| Federation — SAML SP & OIDC relying party | 23 | 1 |
| Authorization engine — RBAC, hierarchy & scopes | 15 | 0 |
| PKI, certificates & IoT device identity | 18 | 1 |
| Audit, webhooks, email & notifications | 18 | 4 |
| Deployment & platform (Kubernetes) | 13 | 4 |
| Client SDKs & admin UI integration surface | 17 | 4 |

## 8. Assumptions

The analysis holds only while these hold. If one stops being true, revisit the diagrams it touches.

1. TLS 1.3 terminates at the ingress and the hop to the pods stays inside the cluster network.
2. The data tier has no route from the public Internet.
3. Kubernetes Secrets are the only source of key material; nothing sensitive is baked into an image.
4. Cluster-admin is equivalent to full AXIAM compromise and is governed outside this model.
5. A federated IdP is trusted by the tenant that configures it — federation delegates authentication deliberately.
6. Integrators verify webhook signatures and AMQP HMACs as `sdks/CONTRACT.md` requires.
7. Tenant administrators are trusted within their own tenant and only there.

## 9. Maintaining this model

Revisit the model when any of the following happens, and re-run the generator so this document tracks the JSON:

- A new API surface, protocol or external integration is added (the OPAQUE endpoints, the SCIM provisioning tokens and the Vault secret provider are the 2026-08 examples — each added or changed threats here)
- A trust boundary moves — a new component, a change in deployment topology
- A security review raises a finding with no corresponding threat here
- A deferred item lands (SEC-040 deny-override did, closing T-16/T-87)
- The SDK contract gains or relaxes a security clause

Threat numbers are stable: add new threats with new numbers and raise `threatTop` rather than renumbering, so review comments and issues keep pointing at the right thing.

---

**References** — [`design-document.md`](design-document.md) · [`security-audit.md`](security-audit.md) · [`final-security-review.md`](final-security-review.md) · [`../sdks/CONTRACT.md`](../sdks/CONTRACT.md) · [`../docs/compliance/`](../docs/compliance/) · [OWASP Threat Dragon](https://www.threatdragon.com)
