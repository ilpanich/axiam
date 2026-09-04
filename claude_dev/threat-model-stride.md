# AXIAM — STRIDE Threat Model

Threat model for AXIAM (Access eXtended Identity and Authorization Management), produced with the **STRIDE** methodology and maintained in **[OWASP Threat Dragon](https://www.threatdragon.com)** format.

| | |
|---|---|
| **Model file** | [`ThreatDragonModels/Axiam/Axiam.json`](../ThreatDragonModels/Axiam/Axiam.json) |
| **Methodology** | STRIDE (per-element) |
| **Tool** | OWASP Threat Dragon, model schema v2 |
| **Diagrams** | 9 |
| **Threats identified** | 236 |
| **Mitigated / Open** | 219 / 17 |
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

Level-0 context data-flow diagram: external actors, the three AXIAM API surfaces, the shared middleware pipeline, the core service layer and the private data tier. Trust boundaries separate the public Internet, the Kubernetes runtime and the data tier.

*29 threats — 3 critical, 14 high, 12 medium; 2 open.*

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

**T-187 — Deleted user's tombstone retains personal data and discloses the account existed**  
`REST API (Actix-Web)` (Process) · Information disclosure · Medium · Mitigated

Administrator deletion tombstoned the user row but kept username, email and metadata on it indefinitely — retention with the UI hidden, not erasure. Because the per-tenant uniqueness indexes are enforced by the database, the retained identifiers also blocked the person from ever registering again, and the duplicate-account refusal itself disclosed that the deleted account had existed.

> Fixed in 1.0.0-beta01: deletion overwrites username, email and metadata with values derived from the row's own id and erases what lives outside the row — WebAuthn credentials, federation identity links, password history — the same residue the GDPR Art. 17 purge clears, so an administrator's Delete and a data subject's erasure request do not leave different residue. The freed identifiers make a later registration a genuinely new account (pinned by a delete-then-recreate test). The row survives holding only its id, because append-only audit entries name their actor by id; only the Art. 17 pipeline additionally pseudonymises audit references and produces an erasure proof — a distinction docs/compliance/gdpr-compliance.md now states.

**T-200 — CSRF exemption for machine callers forged by pairing a bearer header with a session cookie**  
`Security middleware (authn, CSRF, rate limit, CORS, audit)` (Process) · Spoofing · Medium · Mitigated

The CSRF middleware required an axiam_csrf cookie matching the X-CSRF-Token header on every state-changing request, which a bearer-authenticated machine caller has no way to satisfy — POST /api/v1/authz/check under a client-credentials token answered 403 “CSRF validation failed”, so the machine-facing REST surface was unreachable by a machine (B-05). Exempting bearer requests naively would open the opposite hole: a cross-site page can attach a fabricated Authorization header while the browser attaches the victim’s session cookie — precisely the shape an attacker would craft to escape the exemption.

> Fixed in 1.0.0-beta05: is_bearer_only(authorization, has_session_cookie) is a pure function so the condition can be pinned by unit tests. A bearer token with no session cookie is exempt — CSRF is an attack on credentials the browser attaches by itself, and a cross-site page cannot set an Authorization header on a victim’s behalf. A bearer header alongside a session cookie is deliberately not exempt (the load-bearing case), and no bearer means no exemption whatever the cookies say. Scheme matching is case-insensitive and leading-whitespace tolerant, and the machine principal extractor accepts the axiam:m2m audience.

</details>

### 5.2 Authentication & session management

Password and OPAQUE (RFC 9807) login, MFA (TOTP and WebAuthn, including usernameless passkey sign-in), lockout and rate limiting, JWT and refresh-token issuance, password reset and email verification, and the credential stores behind them. Since 1.0.0-beta09 user verification on a WebAuthn ceremony is a tightening-only security setting rather than a library constant (T-229, T-230).

*32 threats — 3 critical, 14 high, 13 medium, 2 low; 1 open.*

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
| T-182 | MFA verification TOTP / WebAuthn <br/>*Process* | E | Usernameless passkey sign-in skips the gates of the ordinary login path | High | Mitigated |
| T-188 | Lockout & rate limiting <br/>*Process* | S | Brute force metered against the deployment default, not the configured threshold | Medium | Mitigated |
| T-189 | access + refresh cookies <br/>*Flow* | T | Logout's removal cookies were weaker than the cookies they cleared | Medium | Mitigated |
| T-201 | MFA verification TOTP / WebAuthn <br/>*Process* | E | Enrolling a passkey never turns the second-factor requirement on | High | Mitigated |
| T-229 | MFA verification TOTP / WebAuthn <br/>*Process* | S | A possession-only security key is accepted where possession alone must not be a complete login | High | Mitigated |
| T-230 | MFA verification TOTP / WebAuthn <br/>*Process* | T | A relaxed user-verification policy silently weakens credentials enrolled under a stricter one | Medium | Mitigated |

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

> Fixed in 1.0.0-beta05: MfaMethodService::enable_after_enrollment runs when a WebAuthn registration completes, so a passkey is a factor from the moment it exists. The trap the fix had to avoid is pinned: every downstream reader tests mfa_enabled together with a stored TOTP secret, so setting the flag could have promoted an abandoned, unconfirmed TOTP enrollment into a live second factor — the pending secret is dropped rather than adopted, and an unconfirmed TOTP secret is never offered at sign-in. Removing the last passkey turns the requirement back off. Stated residual: if the flag write fails, the handler logs and continues, because the credential is already persisted and reporting the registration as failed would invite the user to register a second one. The user-verification policy those ceremonies run under became a tightening-only security setting in 1.0.0-beta09 (T-229, T-230).

**T-229 — A possession-only security key is accepted where possession alone must not be a complete login**  
`MFA verification TOTP / WebAuthn` (Process) · Spoofing · High · Mitigated

`webauthn-rs` hard-codes `UserVerificationPolicy::Required` on both passkey ceremonies, so a security key with no PIN — which can prove user *presence* but never user *verification* — was refused at the finish step against a policy that existed nowhere an operator could see or change, and the refusal read as a hardware fault because a PIN-protected key on the same account worked. Making user verification configurable is the right answer, and it opens the hazard this threat records: a relaxed policy applied indiscriminately would let a PIN-less key satisfy the usernameless sign-in path, where the credential is the only factor and mere possession of the token would then be a complete login; and a policy the browser is not told about leaves a browser that does not prompt facing a server that rejects the answer, or the reverse.

> Fixed in 1.0.0-beta09. `webauthn_user_verification` is a security setting in the same hierarchical model as the OPAQUE and privacy settings: an organization baseline every tenant inherits and may only make stricter, ordered `required > preferred > discouraged` — it can join that model, unlike the attestation policy, because it is totally ordered, which is exactly what the tighten-only override check needs. The default is `preferred`, not `required`, because nobody chose `required`: it was a library constant, and backfilling it would have preserved the bug rather than an intent; `preferred` accepts a security key whether or not it has a PIN and records which happened, so tightening later is a policy change rather than a re-enrolment. Two ceremonies deliberately do not follow the setting: **usernameless sign-in keeps `required`**, so a PIN-less key is a working second factor and never a passwordless one, and attested registration keeps the `required` that `webauthn-rs` imposes, on a path that already excludes synchronised authenticators and hybrid flows. The policy is applied in both places it has to be — the challenge, which decides whether the browser prompts for a PIN, and the ceremony state, which decides what the server accepts — and because the state's policy field is private with no builder, it is re-stamped in the serialization this crate already performs on the way into the state-token JWT, failing loudly rather than silently if upstream's shape changes, with a test that pins that shape against the real library so a patch release cannot turn the re-stamp into a no-op. The organization and tenant settings requests carry the field in `openapi.json` and in the eleven SDKs' §27 management surfaces (T-235).

**T-230 — A relaxed user-verification policy silently weakens credentials enrolled under a stricter one**  
`MFA verification TOTP / WebAuthn` (Process) · Tampering · Medium · Mitigated

A policy that governed how a credential is *used* rather than how it was *enrolled* would let an administrator downgrade every existing passkey at a stroke. The settings write that could do it is a `PUT` that replaces the whole row, so a client that simply omitted the new field would relax an organization that had set `required` without anyone choosing to — the quiet path by which a stricter posture is lost.

> Fixed in 1.0.0-beta09. No existing credential is weakened: `webauthn-rs` records the policy a credential was registered under and demands user verification at authentication whenever *either* that or the current policy says `required`, so every credential enrolled before this change carries the old hard-coded `required` for the rest of its life and the setting governs new enrolments only. Schema v53 adds the column with `DEFAULT 'preferred'` and backfills rows that predate it. The admin UI sends the field explicitly on the organization settings `PUT`, and it is a required field in the request type on purpose — a test fixture that has to be updated is exactly the friction that buys. `docs/admin/authenticator-policies.md` states the ordering, the two ceremonies that ignore the setting, and the per-credential rule.

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
> **Where the code may be delivered is the load-bearing part, and it is not the caller's choice.** `redirect_uri` reaches AXIAM on an *unauthenticated* start endpoint, and `validate_redirect_uri` checks its scheme only — every `https://` host on the internet passes it (`TODO(T19.14)`). On the OIDC and OAuth2 flows that is backstopped by the provider, which is handed the same URI and compares it against its registered set. The two cross-site flows have no such backstop **by construction**: a SAML IdP is pointed at AXIAM's own ACS and Apple at AXIAM's own form-callback, so the provider never sees the SPA URI and never validates it — AXIAM alone decides where the browser goes next, carrying a credential the handoff endpoint will exchange for session cookies for whoever presents it. Without a check, anyone could start a login with `redirect_uri = https://attacker.example/`, lure a victim through the victim's own real IdP, and read a working session out of their access log; the 60-second TTL, the single use and the hash-only storage are all irrelevant when the attacker *is* the destination. `require_deployment_spa_origin` therefore confines the target to the **origin of** `AuthConfig::effective_issuer()` — the same value the ACS and form-callback URLs are built from, so it cannot be wrong where these flows work at all — plus anything an operator names in `AXIAM__AUTH__SSO_SPA_ORIGINS` for a separately hosted SPA. Compared as origins via `Url::origin`, so a userinfo prefix, a path, a port or a scheme cannot smuggle a second host past it. It is enforced at login start (a `400` naming the knob), again at the mint (so a state row written by an older binary is not honoured), and on the error redirect. It runs *after* workspace and config resolution, so an unknown slug still answers the uniform `401`. This is the rule T-52 already states for the OAuth2 authorization server's own `redirect_uri`.
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

*26 threats — 6 critical, 13 high, 7 medium; 0 open.*

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

</details>

### 5.6 PKI, certificates & IoT device identity

Organization and tenant CA lifecycle with per-CA key custody (sealed database row or Vault), tenant signing CAs beneath the organization CA, tenant certificate issuance with policy enforcement, mTLS device and workload authentication with full chain verification against hot-reloadable trust anchors, revocation and CRL, and the OpenPGP key service used for audit signing and GDPR export encryption. Extended for X3 with FIDO MDS3 metadata ingestion (BLOB trust-chain verification, rollback protection, staleness posture) feeding the WebAuthn attestation policy engine.

*24 threats — 6 critical, 14 high, 4 medium; 1 open.*

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

> Key generation uses the platform CSPRNG — Ed25519 through rcgen/ring, RSA-4096 through the rsa crate's OS-seeded generator handed to rcgen as PKCS#8, since ring deliberately implements no RSA key generation (1.0.0-beta01). No custom or seeded RNG is used anywhere in the PKI path.

**T-97 — Certificate issued beyond the tenant's validity policy**  
`Certificate issuance (rcgen, policy enforcement)` (Process) · Elevation of privilege · Medium · Mitigated

An over-long certificate outlives the review cycle and cannot be retired without an explicit revocation.

> max_certificate_validity_days is an org/tenant setting, and the hierarchical settings rule means a tenant can only make it stricter, never longer, than the organization baseline. Since 1.0.0-beta01 issuance also refuses a validity that would outlive the issuing CA and quotes the achievable number, rather than silently truncating to the issuer's notAfter — a truncation that left renewal calendars built on a date the certificate does not carry.

**T-98 — Certificate issued for another tenant's subject**  
`Certificate issuance (rcgen, policy enforcement)` (Process) · Elevation of privilege · Critical · Mitigated

Issuing under a subject belonging to a different tenant would produce a credential that authenticates across the isolation boundary.

> Issuance is tenant-scoped from the authenticated context, and the signing CA is resolved from the requesting tenant's organization — a cross-tenant subject cannot be signed. Tenant signing CAs (1.0.0-alpha44) narrow the blast radius further: issuance for a tenant is anchored at that tenant's path-length-zero intermediate, so a compromised or misused issuer is revocable without touching any other tenant.

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

> The CSR's subject is honoured; its requested extensions are not — AXIAM states CA:TRUE, path length zero and keyCertSign/cRLSign itself, so a request that asked to be an unconstrained CA does not become one (1.0.0-alpha44). from_pem verifies the request's self-signature as proof of possession. The parent must be unexpired, unrevoked, key-holding and not itself tenant-scoped — refused up front rather than downstream — the intermediate's validity is capped to the parent's expiry, and the row records custody External because AXIAM never held the key.

**T-195 — One tenant's compromised issuance burns the organization trust anchor**  
`Certificate issuance (rcgen, policy enforcement)` (Process) · Elevation of privilege · High · Mitigated

When every tenant's user, service and device certificates issue straight from the organization CA, a compromised issuance path in one tenant is the whole estate's problem: the anchor is long-lived, widely distributed and painful to replace, and rotating it is a coordinated change at every relying party.

> Tenant signing CAs (1.0.0-alpha44): an intermediate created beneath the organization CA, constrained to a path length of zero, named as issuer_ca_id when issuing for that tenant, its key held by the configured custodian — Vault where configured, even when the parent's key predates Vault adoption. Revoking it revokes exactly one tenant's issuance. Under vault_pki the signing chain deliberately reaches past the path-length-zero issuing intermediate to the root, because signing from the issuing intermediate would produce certificates Vault accepts and every chain validator rejects.

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

</details>

### 5.7 Audit, webhooks, email & notifications

The append-only audit trail and its OpenPGP batch signing, webhook delivery with HMAC signatures and the SSRF guard, the pluggable email service and templates, and admin notification rules.

*18 threats — 2 high, 14 medium, 2 low; 2 open.*

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
`Audit middleware & service` (Process) · Information disclosure · Medium · Open

The audit log is append-only by design, so any personal data written into it cannot later be erased — which is in direct tension with the GDPR Art. 17 erasure path AXIAM also offers.

> Partially addressed: audit metadata is deliberately minimised, erasure anonymises the subject rather than deleting audit records, and a default retention sweep bounds the log at 730 days — the table's only deletion path, configurable and disableable with 0 (T-119). What remains open is the collection side: nothing prevents a deployment from writing personal data into fields the sweep will hold for the full window, so the retention period must still be set consistent with the deployment's lawful basis.

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

T-212…T-217 record the 1.0.0-beta08 topology change (`claude_dev/public-backend-tls-design.md`): the edge now routes **by path** — the SPA at `/`, and `/api`, `/oauth2` and `/.well-known` to the server over TLS the server terminates itself. That removes a proxy hop and a cleartext leg, and moves four things across a trust boundary that were previously behind one. T-231…T-234 and T-236 record the beta09…beta11 follow-through on the same topology: the Vault seeder and the server's Vault policy, gRPC published through the same edge and the certificate-renewal gap that opens, and the CI gates that must measure the artifact rather than the worktree.

*26 threats — 2 critical, 16 high, 8 medium; 6 open.*

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
| T-234 | AXIAM deployment (N replicas, HPA) <br/>*Process* | D | The gRPC TLS leaf expires because tonic reads it once at startup | Medium | Open |
| T-236 | AXIAM deployment (N replicas, HPA) <br/>*Process* | T | A registry outage or a stale suppression turns the dependency-audit gate into a rubber stamp | Medium | Mitigated |

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

> CI runs cargo-audit, cargo-deny (advisories, licences, bans, sources) and npm audit at a high threshold, uploads SARIF, and Dependabot covers cargo, the frontend npm tree and GitHub Actions. Residual: the eleven SDK repositories are scanned separately and are not covered by this repository's CI (CI-03). Since 1.0.0-beta11 the gate also fails on a stale suppression and tells a registry outage apart from a clean audit (T-236).

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

> Deployment responsibility, stated in `docs/deployment/vault.md` rather than enforceable in-product: run a production-mode Vault with TLS (the shipped prod stack does — TLS material, init, unseal, then seed), scope AXIAM's token to read-only on its own KV path with the documented policy, keep unseal keys and the root token offline, and enable Vault's audit device so secret reads are attributable. The tooling is shaped to help, and since **H-4 it checks rather than merely advises**: `just vault-status` queries `sys/capabilities-self` and reports the capabilities the token in hand actually holds on AXIAM's KV path, marking anything beyond `read` as `OVER-SCOPED` and naming a root token as what it is; `--strict` turns that into a non-zero exit for a deployment smoke test. It still reports secret presence only, never a value, and the seeder never rewrites a secret that already exists. Since 1.0.0-beta10 the token is no longer strictly read-only: it holds `read` on the startup path and `create`/`update` on `secret/data/axiam/ca-keys/*`, from the one policy file `docker/vault/axiam-policy.hcl`, and `just vault-status` reports missing capabilities as well as excess ones (T-232).

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

> Fixed in 1.0.0-beta08. `ReloadableCertResolver` holds the certificate in an `ArcSwap` that rustls consults per handshake, so a renewal takes effect on the next connection with no restart and no dropped request — the same mechanism `ReloadableClientCertVerifier` already used for trust anchors, rather than a second one. Two triggers, because they fail differently: `SIGHUP` (immediate, what an ACME deploy hook sends, and a signal actix-server does not claim) and an hourly `stat` poll (`AXIAM__SERVER__TLS__RELOAD_INTERVAL_SECS`) for the case that actually happens — a hook nobody wired up, or a runtime that does not forward signals. The swap is validated before it happens: a reload that finds an unreadable or mismatched pair leaves the previous certificate serving and retries, which is what makes a renewal observed mid-write (certbot writes the chain and the key as two operations) a logged warning instead of a dead listener. A test drives two real TLS 1.3 handshakes against one `ServerConfig` and asserts the client is presented the renewed leaf on the second. The mechanism covers the actix (REST) listener only; the gRPC listener still reads its PEM once at startup — T-234 records that gap and the restart the runbook uses to bridge it.

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

> Recorded at 1.0.0-beta11. The bind stays loopback by default, and the blanket rule becomes a default rather than a prohibition: gRPC is published **through the edge on 443, path-matched, or not at all**. Caddy speaks HTTP/2 to the client, re-encrypts to the backend's own gRPC listener and appends the real peer, so the hop count is one on both protocols and the shared `TRUSTED_HOPS` stays correct for both. The documented route is an **allowlist** of services — `AuthorizationService`, `UserInfoService`, `TokenService` — so `UserService` and `ReactorAdminService` stay off the public edge unless an operator names them, with what each costs written beside the line that would add it; anything under `/axiam.v1.*` not listed falls through to the SPA handler and gets HTML back, a confusing refusal but a safe one. The site-wide stripping of `X-Client-Certificate` and `X-Real-IP` applies to the route. The listener's own TLS is enabled only when both `AXIAM__GRPC_TLS_CERT_PATH` and `_KEY_PATH` are set, and the server panics at startup if either names a file it cannot read — a typo is a failed boot, never a listener that quietly came up in cleartext. The runbook sets `AXIAM__GRPC__STRICT_REVOCATION=true` for a public listener so a revoked session does not keep passing for up to fifteen minutes, and states the per-IP-is-not-per-client sizing behind NAT. `claude_dev/public-backend-tls-design.md` §13 and the Pi runbook §14 carry the argument; `ReactorAdminService` left the authz rate-limit family in 1.0.0-beta12 (R-5): it fell through `GrpcMethodFamily::classify`'s catch-all, which puts an unrecognised path in the strictest *limited* family so a new service is throttled rather than unlimited — safe as a default, wrong as an outcome for an administrative surface, which was therefore sized like the hot path at 100/s per IP and raised by the `gateway` and `mesh` profiles. It now maps to `Admin`, whose ceiling is the absolute `ADMIN_PER_SEC_DEFAULT` (10/s) that no profile raises; the catch-all arm is unchanged.

**T-234 — The gRPC TLS leaf expires because tonic reads it once at startup**  
`AXIAM deployment (N replicas, HPA)` (Process) · Denial of service · Medium · Open

T-214 made the REST listener's certificate hot-reloadable so that an ACME renewal would never need a restart. That work covers the actix listener only: `axiam-api-grpc`'s `start_grpc_server` reads `AXIAM__GRPC_TLS_CERT_PATH` / `_KEY_PATH` once, hands the PEM to tonic's `ServerTlsConfig`, and the crate contains no reload path and no poll. A gRPC listener that is public is therefore a listener whose certificate expires at day 90 while REST keeps working — the failure mode T-214 exists to prevent, reintroduced on the other protocol, and the worst version of it because it presents as a gRPC bug. The same API limit keeps that leg TLS 1.2-negotiable where the REST listener is 1.3-only.

> Open, with the residual bounded operationally. tonic 0.14's `ServerTlsConfig` does not accept a rustls `ServerConfig`, so the existing `ReloadableCertResolver` cannot be installed behind it; the structural fix is a hand-rolled accept loop over `tokio-rustls` using that resolver, which would close the reload gap and the TLS-version gap in one change and needs its own tests. Until it exists the runbook states the workaround rather than leaving it to be discovered at day 90: when gRPC TLS is on, the certbot deploy hook restarts the container — roughly fifteen seconds every sixty days, at a moment the operator controls — while keeping the REST listener's `SIGHUP` reload, so removing the restart later leaves a correct hook rather than a broken one. The exposure is opt-in twice over: the listener is loopback-bound unless published (T-233), and its TLS is off unless both paths are set. On the documented topology the only client of that leg is Caddy on loopback, which negotiates TLS 1.3, and the public half can be pinned with `protocols tls1.3`.

**T-236 — A registry outage or a stale suppression turns the dependency-audit gate into a rubber stamp**  
`AXIAM deployment (N replicas, HPA)` (Process) · Tampering · Medium · Mitigated

The gate T-127 relies on failed in both directions at once. `npm audit` got `503` from the registry's audit endpoint, retried internally for seven minutes and exited `1` seconds after `npm ci` had reported zero vulnerabilities — a red job with no vulnerability anywhere in the tree, the kind of failure that teaches a team to re-run until green, and one that buried the line that explained it under four SARIF upload errors from producers that never ran. And four advisory suppressions had gone stale, emitting `advisory-not-detected` on every run: two for advisories already fixed upstream, two for crates no longer in the resolved feature graph at all. An ignore is keyed by advisory ID, not by version or crate, so one left behind after its crate leaves the graph silently re-suppresses that advisory if the crate ever comes back — a gate that has been quietly told what to ignore.

> Fixed in 1.0.0-beta11. The npm audit step retries with backoff and tells "found advisories" apart from "could not reach the endpoint" by the shape of the output rather than the exit code — npm exits `1` for both, but only a completed audit parses as JSON without an `error` key. A real HIGH/CRITICAL finding still fails the job; anything parseable that is not an error object counts as a real report, so an unfamiliar schema fails rather than being waved through; and a sustained outage ends in a `::warning::` that says explicitly it is not a clean bill of health. `cargo-deny` now runs with `-D advisory-not-detected`, so the next stale entry fails CI instead of scrolling past, and the two ignore-lists are allowed to differ legitimately — cargo-deny resolves the feature graph while cargo-audit reads `Cargo.lock` — under a containment check that demands an explicit `# audit-only: <ID> — <reason>` declaration and rejects one that is missing, unreasoned, contradictory or stale, with seven self-test cases. The yanked `chacha20 0.10.1` was bumped, and the four SARIF uploads are guarded on the file existing so a failed producer stops adding its own errors on top of the one that matters. `scripts/check-docker-context.py` closes the neighbouring class of the same shape — a gate that reads the worktree while the artifact is built from a filtered context, which is how the beta08 release lost both frontend image legs — by asking, for every `COPY`/`ADD` in every Dockerfile, whether at least one tracked file both exists and survives `.dockerignore`, cross-checked file by file against BuildKit's real context export.

</details>

### 5.9 Client SDKs & admin UI integration surface

The React admin UI and the eleven client SDKs (Rust, TypeScript, Python, Java, Kotlin, C#, PHP, Go, Swift, C, C++), which live in separate repositories and vendor CONTRACT.md, openapi.json and proto/ from here. Covers SDK transport and credential handling, token verification, the WebAuthn relying-party layer, account lifecycle and PAR operations (contract 1.28, §24–§26), AMQP HMAC consumption and the reactor protocol core, webhook verification and package-distribution supply chain — and, since 1.0.0-beta11, the release step that regenerates each SDK's §27 management surface from the spec it vendors (T-235).

*26 threats — 2 critical, 14 high, 10 medium; 4 open.*

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
| T-183 | SDK HTTP core (11 languages) <br/>*Process* | T | SDK reshapes the WebAuthn ceremony the server configured | High | Mitigated |
| T-184 | SDK HTTP core (11 languages) <br/>*Process* | I | TOTP secret or setup token leaks through account-lifecycle serialization | High | Mitigated |
| T-185 | SDK HTTP core (11 languages) <br/>*Process* | I | Lifecycle helpers turned into an account-enumeration oracle | Medium | Mitigated |
| T-186 | SDK AMQP consumer (HMAC verify, nonce) <br/>*Process* | I | Caller-supplied reactor transport connects without TLS | High | Mitigated |
| T-199 | sdks/CONTRACT.md, openapi.json, proto/ <br/>*Store* | T | Two OpenAPI exports cannot be told apart, so vendored spec drift goes unseen | Medium | Mitigated |
| T-209 | React admin UI (Vite SPA) <br/>*Process* | I | The admin UI keeps rendering the previous tenant’s data after a switch | High | Mitigated |
| T-210 | sdks/CONTRACT.md, openapi.json, proto/ <br/>*Store* | T | The contract documents an acting-tenant header the server never reads | Medium | Mitigated |
| T-211 | React admin UI (Vite SPA) <br/>*Process* | E | The assignment dialog offers the widest possible grant as its only option | Medium | Mitigated |
| T-235 | sdks/CONTRACT.md, openapi.json, proto/ <br/>*Store* | T | A release tags an SDK whose generated management surface disagrees with the spec it vendors | Medium | Mitigated |

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

</details>

## 6. Open risk register

17 of 236 threats remain open. None of them is an unhandled defect in AXIAM's own request path: they are accepted design trade-offs, responsibilities that land on whoever deploys AXIAM, or gaps on the SDK and distribution side. They are listed most severe first.

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
| T-39 | Medium | Access token still valid after entitlement revocation | Token service EdDSA JWT + refresh rotation <br/>*Authentication & session management* | Accepted trade-off for stateless verification. The 15-minute lifetime bounds the window; sessions are invalidated on password change; deployments needing immediate revocation… |
| T-110 | Medium | Personal data over-collected into an immutable log | Audit middleware & service <br/>*Audit, webhooks, email & notifications* | Partially addressed: audit metadata is deliberately minimised, erasure anonymises the subject, and a default 730-day retention sweep bounds the log (T-119). What remains open is the collection side… |
| T-123 | Medium | Final mail hop is not confidential | deliver mail <br/>*Audit, webhooks, email & notifications* | Inherent to email. Bounded by making the tokens carried in mail single-use and short-lived, so interception has a narrow window. Deploy MTA-STS and DANE on the sending domain to… |
| T-134 | Medium | Backup stream unencrypted in transit | scheduled backup <br/>*Deployment & platform (Kubernetes)* | Deployment responsibility: use an encrypted transport and server-side encryption on the backup target. |
| T-234 | Medium | The gRPC TLS leaf expires because tonic reads it once at startup | AXIAM deployment (N replicas, HPA) <br/>*Deployment & platform (Kubernetes)* | Open, with the residual bounded operationally. tonic 0.14's `ServerTlsConfig` does not accept a rustls `ServerConfig`, so the existing `ReloadableCertResolver` cannot be installed behind it; the structural fix is a hand-rolled accept loop over `tokio-rustls` using that resolver, which would close the reload gap and the TLS-version gap in one change and needs its own tests. Until it exists the runbook states the workaround rather than leaving it to be discovered at day 90: when gRPC TLS is on, the certbot deploy hook restarts the container — roughly fifteen seconds every sixty days, at a moment the operator controls — while keeping the REST listener's `SIGHUP` reload, so removing the restart later leaves a correct hook rather than a broken one. The exposure is opt-in twice over: the listener is loopback-bound unless published (T-233), and its TLS is off unless both paths are set.… |
| T-143 | Medium | Local JWT verification misses a revoked entitlement | SDK token verification (JWKS cache, iss/aud) <br/>*Client SDKs & admin UI integration surface* | Bounded by the 15-minute access-token lifetime. CONTRACT §10 and §11 expose route-guard and declarative-authorization helpers; integrations needing immediate revocation should… |
| T-161 | Low | A partner's IdP silently populates the AXIAM user table (X4) | Attribute mapping & JIT provisioning <br/>*Federation — SAML SP & OIDC relying party* | Off by default (`linked_only` refuses unknown subjects). Every JIT provision is audited with the provider and the external subject, and a provisioned user holds no roles, so the exchange that created them still yields no token. Residual risk accepted: the same exposure the browser SSO JIT path already carries, bounded by the same per-client exchange rate limit. |

### Grouping

**Accepted design trade-offs** — deliberate, documented, and bounded.

- **~~No deny-override in the RBAC cascade~~ (SEC-040, T-16/T-87) — closed.** The engine now supports explicit deny: a grant carries `effect: "allow" | "deny"`, and a deny overrides every allow, at any depth of the resource hierarchy and at equal specificity. Recorded here as closed rather than deleted so the history stays legible; see `claude_dev/deny-override-design.md`.
- **Access tokens survive revocation for up to 15 minutes.** The price of stateless verification. Use gRPC introspection where immediate revocation matters.
- **Audit records cannot be erased, only aged out.** Append-only by design, which is in tension with GDPR Art. 17; erasure anonymises the subject instead. Retention now defaults to a 730-day pruning window (T-119) applied by the background sweep — tune it (or disable with `0`) to match your lawful basis; there is still no on-demand deletion path.
- **A stale FIDO MDS3 BLOB is never a hard failure at ingestion (X3),** though `AXIAM__PKI__MDS_MAX_STALE_DAYS` now lets an operator bound how stale metadata may get before attested *registration* is refused (T-153).

**Deployment responsibilities** — AXIAM cannot close these from inside the application; they belong in a hardening checklist.

- Network policy so pods are not reachable around the ingress
- **Per-service** RabbitMQ credentials. Vhost separation is no longer on this list — the manifests now ship `RABBITMQ_DEFAULT_VHOST: axiam` (T-131) — but splitting one credential per service still belongs to whoever deploys. The transport itself is always TLS: the server refuses any non-`amqps://` broker URL
- Running Vault itself in production mode — TLS, a read-only token scoped to AXIAM's KV path, unseal and root material kept offline, audit device on (T-180). Every long-lived secret sits behind one credential, so the Vault posture is the secret posture
- etcd encryption at rest. Which secrets reach the container is no longer an operator choice (T-132): the manifests default to the Vault provider, and the `file` provider mounts key material for deployments without Vault. `AXIAM__DB__USERNAME`, `AXIAM__DB__PASSWORD` and `AXIAM__AMQP__URL` are the remaining environment variables, read before any provider exists
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

**Closed at the 2026-08-21 review** — recorded rather than deleted, as with T-145.

- **~~Secret material in a ConfigMap or plain env var~~ (T-132) — closed.** The `file` secret provider already existed and the manifests were not using it; eleven cryptographic secrets are now mounted as files. Datastore and broker credentials remain env-supplied — see the entry for why, and treat it as the open follow-up.
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
| Spoofing | 58 |
| Tampering | 49 |
| Repudiation | 5 |
| Information disclosure | 57 |
| Denial of service | 22 |
| Elevation of privilege | 45 |

**By severity**

| Severity | Total | Open |
|---|---|---|
| Critical | 28 | 1 |
| High | 113 | 8 |
| Medium | 88 | 7 |
| Low | 7 | 1 |

**By diagram**

| Diagram | Threats | Open |
|---|---|---|
| System diagram | 29 | 2 |
| Authentication & session management | 32 | 1 |
| OAuth2 / OIDC authorization server | 24 | 0 |
| Federation — SAML SP & OIDC relying party | 31 | 1 |
| Authorization engine — RBAC, hierarchy & scopes | 26 | 0 |
| PKI, certificates & IoT device identity | 24 | 1 |
| Audit, webhooks, email & notifications | 18 | 2 |
| Deployment & platform (Kubernetes) | 26 | 6 |
| Client SDKs & admin UI integration surface | 26 | 4 |

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

- A new API surface, protocol or external integration is added (the OPAQUE endpoints, the SCIM provisioning tokens and the Vault secret provider are the 2026-08 examples — each added or changed threats here)
- A trust boundary moves — a new component, a change in deployment topology (organization-level principals moved the tenant ↔ tenant boundary in 1.0.0-beta02, and tenant signing CAs with per-CA Vault custody re-shaped the PKI diagram — T-187…T-199 record the 1.0.0-beta01…beta03 wave; tenant-scoped role assignments and the organization-principal guard narrowed the same boundary again in 1.0.0-beta05…beta06 — T-200…T-211 record that wave, most of it found by the E2E permission matrix run against the production image; and exposing the backend at `/api` on the public origin with its own TLS moved the edge ↔ server boundary in 1.0.0-beta08 — T-212…T-217 record that wave; the public login-provider surface of the same release is T-218…T-225, and publishing gRPC through that edge in 1.0.0-beta11 is T-233 and T-234)
- A security review raises a finding with no corresponding threat here
- A deferred item lands (SEC-040 deny-override did, closing T-16/T-87)
- The SDK contract gains or relaxes a security clause (contract 1.28's WebAuthn, account-lifecycle and PAR sections and the Swift/C/C++ reactor protocol core are the 2026-08-22 examples — T-183…T-186 record them; contract 1.37 and 1.38 added the login-provider operations and the handoff-origin rule — T-218…T-225)
- A fix changes what a grant, a policy or a credential *means* even when no surface moves (the beta09 authorization-reach fixes T-226…T-228 and the WebAuthn user-verification policy T-229…T-230 are the examples: nothing new was exposed, but what existing data authorises changed)

Threat numbers are stable: add new threats with new numbers and raise `threatTop` rather than renumbering, so review comments and issues keep pointing at the right thing. Allocate them from `threatTop`, never from the last number in a section — the login-provider threats were first published as T-163…T-170, continuing §5.4's own sequence, and collided with numbers the model already held for §5.3's single-use credentials and §5.9's `cnf` threats. They were renumbered T-218…T-225 when they entered the model at 2.11.0 (they had lived only in this document until then, so nothing on the website pointed at them), and the four code comments that cite them moved with them.

---

**References** — [`design-document.md`](design-document.md) · [`security-audit.md`](security-audit.md) · [`final-security-review.md`](final-security-review.md) · [`../sdks/CONTRACT.md`](../sdks/CONTRACT.md) · [`../docs/compliance/`](../docs/compliance/) · [OWASP Threat Dragon](https://www.threatdragon.com)
