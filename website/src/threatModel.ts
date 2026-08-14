// AUTO-GENERATED — do not edit by hand.
//
// Produced by `npm run gen:threat-model` from the OWASP Threat Dragon model at
// `ThreatDragonModels/Axiam/Axiam.json`, which is the source of truth for the
// Security section. Re-run the generator whenever the model changes.

import type {
  ThreatModel,
  TmDiagram,
} from "./threatModelTypes";

export type { ThreatModel, TmDiagram };

export const THREAT_MODEL: ThreatModel = {
 "title": "Axiam",
 "owner": "ilpanich",
 "description": "Complete IAM SW written in Rust using SurrealDB to store data and relationships. STRIDE threat model covering the system context, authentication and session management, the OAuth2/OIDC provider, inbound federation, the RBAC authorization engine, PKI and IoT device identity, audit/webhooks/email, and the Kubernetes deployment.",
 "version": "2.7.0",
 "diagramCount": 9,
 "total": 168,
 "open": 23,
 "mitigated": 145,
 "diagrams": [
  {
   "id": 0,
   "title": "System diagram",
   "description": "Level-0 context data-flow diagram: external actors, the three AXIAM API surfaces, the shared middleware pipeline, the core service layer and the private data tier. Trust boundaries separate the public Internet, the Kubernetes runtime and the data tier.",
   "width": 1588,
   "height": 968,
   "boundaries": [
    {
     "id": "a8609307-08fe-5109-9781-9e4ffbd01c13",
     "x": 24,
     "y": 24,
     "w": 290,
     "h": 480,
     "label": "Untrusted network — client devices"
    },
    {
     "id": "24023898-50ca-5139-a76d-178bce63b6fc",
     "x": 364,
     "y": 24,
     "w": 800,
     "h": 620,
     "label": "AXIAM runtime — Kubernetes cluster trust zone"
    },
    {
     "id": "50715fdf-59f5-5b3d-a3b7-349dc15d5ef1",
     "x": 1214,
     "y": 44,
     "w": 350,
     "h": 520,
     "label": "Data tier — private network, no ingress"
    },
    {
     "id": "b049af10-7389-5b21-8649-49670b4f3355",
     "x": 1214,
     "y": 604,
     "w": 350,
     "h": 340,
     "label": "Third-party services — outbound only"
    }
   ],
   "nodes": [
    {
     "id": "97990f2c-7004-578b-aece-7d8d4c6c3576",
     "kind": "actor",
     "x": 59,
     "y": 64,
     "w": 150,
     "h": 80,
     "name": "Admin / End user (browser, React UI)",
     "lines": [
      "Admin / End user",
      "(browser, React UI)"
     ],
     "description": "Human operator or end user reaching the React admin UI and the public auth endpoints over HTTPS.",
     "outOfScope": false,
     "threats": [
      {
       "number": 1,
       "title": "Session cookie theft leads to account takeover",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "An attacker who obtains the axiam_access / axiam_refresh cookie (XSS, malware, shared device) can impersonate the user for the lifetime of the token.",
       "mitigation": "Cookies are Secure + HttpOnly + SameSite; access tokens are EdDSA-signed and expire in 15 min; refresh tokens are opaque, server-stored and single-use with rotation, so a stolen refresh token is detectable on reuse. CSP headers are set by the security_headers middleware."
      },
      {
       "number": 2,
       "title": "Administrator denies having made a privileged change",
       "type": "Repudiation",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A tenant or org administrator disputes a role assignment, certificate revocation or settings change attributed to them.",
       "mitigation": "Every state-changing request is written to the append-only audit_log with actor id, actor type, IP, outcome and timestamp; audit batches are signed with the tenant OpenPGP key."
      }
     ],
     "open": 0
    },
    {
     "id": "2f920e4f-a713-5e0e-9185-033f9d45c36e",
     "kind": "actor",
     "x": 59,
     "y": 214,
     "w": 150,
     "h": 80,
     "name": "Client application / service account (SDKs)",
     "lines": [
      "Client application /",
      "service account",
      "(SDKs)"
     ],
     "description": "Machine-to-machine callers using the seven AXIAM SDKs over REST or gRPC.",
     "outOfScope": false,
     "threats": [
      {
       "number": 3,
       "title": "Leaked client_secret impersonates a service account",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "Service-account and OAuth2 client secrets embedded in SDK configuration, CI variables or container images let an attacker mint tokens with the service account's roles.",
       "mitigation": "Client secrets are stored HMAC-SHA256 hashed, never in plaintext; secrets are redacted from Debug output; rotation is supported. Deployments should prefer mTLS or short-lived workload identity over static secrets."
      }
     ],
     "open": 0
    },
    {
     "id": "dcbee205-bc5b-5a53-95de-ff3f301d7014",
     "kind": "actor",
     "x": 59,
     "y": 364,
     "w": 150,
     "h": 80,
     "name": "IoT device (mTLS client cert)",
     "lines": [
      "IoT device",
      "(mTLS client cert)"
     ],
     "description": "Constrained device authenticating with an X.509 certificate signed by the tenant CA.",
     "outOfScope": false,
     "threats": [
      {
       "number": 4,
       "title": "Cloned device certificate",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "A private key extracted from a physical device lets an attacker clone that device's identity and act with its bound roles.",
       "mitigation": "SEC-024: mTLS auth verifies the full chain to the tenant/org CA after the fingerprint lookup and fails closed when no active CA exists. Revocation invalidates the device immediately. Devices should hold keys in a secure element where available."
      }
     ],
     "open": 0
    },
    {
     "id": "62dc12c6-8941-5127-b674-5001c783ba60",
     "kind": "actor",
     "x": 1279,
     "y": 654,
     "w": 150,
     "h": 80,
     "name": "External IdP (SAML / OIDC)",
     "lines": [
      "External IdP",
      "(SAML / OIDC)"
     ],
     "description": "Third-party identity provider federated into a tenant.",
     "outOfScope": false,
     "threats": [
      {
       "number": 5,
       "title": "Malicious or compromised IdP asserts arbitrary identities",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "A federated IdP — or an attacker who controls its metadata URL — can assert any subject and any attribute set, including attributes mapped onto privileged AXIAM roles.",
       "mitigation": "Assertions are signature-verified against pinned IdP keys; JWKS and discovery documents are fetched only through the SSRF-guarded resolve-and-pin helper; attribute-to-role mapping is explicit and tenant-scoped. Federation is a deliberate trust delegation — the tenant owner accepts the IdP as an authority."
      }
     ],
     "open": 0
    },
    {
     "id": "df34f1a4-ec9f-557f-8120-7b151eb06d54",
     "kind": "actor",
     "x": 1279,
     "y": 759,
     "w": 150,
     "h": 80,
     "name": "Email provider (SMTP / SendGrid / …)",
     "lines": [
      "Email provider",
      "(SMTP / SendGrid /",
      "…)"
     ],
     "description": "Outbound transactional email for verification, reset and admin alerts.",
     "outOfScope": false,
     "threats": [
      {
       "number": 6,
       "title": "Provider compromise exposes reset and verification links",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Password-reset and email-verification tokens transit a third-party provider; a compromised provider account can read or replay them.",
       "mitigation": "Tokens are CSPRNG-generated, single-use and short-lived; reset confirms only over an authenticated POST; provider API keys are encrypted at rest and TLS is required on every provider hop."
      }
     ],
     "open": 0
    },
    {
     "id": "1121595d-5951-5a6f-9335-898c5dd0d41b",
     "kind": "actor",
     "x": 1279,
     "y": 859,
     "w": 150,
     "h": 80,
     "name": "Webhook receiver (tenant endpoint)",
     "lines": [
      "Webhook receiver",
      "(tenant endpoint)"
     ],
     "description": "Customer-controlled HTTPS endpoint receiving AXIAM event notifications.",
     "outOfScope": false,
     "threats": [
      {
       "number": 7,
       "title": "Forged webhook delivery to a tenant endpoint",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "An attacker posts fabricated AXIAM events to a known tenant webhook URL to trigger downstream provisioning or de-provisioning.",
       "mitigation": "Every delivery carries an HMAC-SHA256 signature computed with the per-endpoint shared secret; receivers must verify it before acting."
      }
     ],
     "open": 0
    },
    {
     "id": "6b97cb3c-b213-5c17-acc3-209252e7e436",
     "kind": "process",
     "x": 404,
     "y": 94,
     "w": 140,
     "h": 140,
     "name": "Ingress / TLS 1.3 termination",
     "lines": [
      "Ingress /",
      "TLS 1.3",
      "termination"
     ],
     "description": "Kubernetes ingress terminating TLS for REST and gRPC.",
     "outOfScope": false,
     "threats": [
      {
       "number": 8,
       "title": "TLS downgrade or termination-point interception",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "An on-path attacker forces a weaker protocol version or cipher, or reaches the plaintext hop behind the terminator.",
       "mitigation": "TLS 1.3 is the configured minimum for all external communication; HSTS is emitted by the security-headers middleware; in-cluster hops run on the cluster's own network policy and, where deployed, a service mesh."
      },
      {
       "number": 9,
       "title": "Connection flood exhausts ingress capacity",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Open",
       "description": "Unauthenticated TLS handshake or slow-loris floods consume ingress worker capacity before any AXIAM control applies.",
       "mitigation": "Partly outside the application boundary: AXIAM enforces per-IP and per-user rate limits and Argon2 backpressure, but edge-level protection (WAF, connection limits, autoscaling) is a deployment responsibility and is not shipped with AXIAM."
      }
     ],
     "open": 1
    },
    {
     "id": "cb51a43e-b63a-5602-8eb7-fc0fcfa02750",
     "kind": "process",
     "x": 614,
     "y": 64,
     "w": 140,
     "h": 140,
     "name": "REST API (Actix-Web)",
     "lines": [
      "REST API",
      "(Actix-Web)"
     ],
     "description": "Public REST surface: auth, OAuth2/OIDC, admin CRUD, GDPR endpoints.",
     "outOfScope": false,
     "threats": [
      {
       "number": 10,
       "title": "Argon2id memory flood on unauthenticated login",
       "type": "Denial of service",
       "severity": "High",
       "status": "Mitigated",
       "description": "Each Argon2id verification allocates a ~19 MiB arena; an unauthenticated login flood turns password hashing into a memory-exhaustion vector (~970 MiB RSS observed at ~50 concurrent hashes against a 1024 MiB cap).",
       "mitigation": "crypto_gate bounds concurrent Argon2id operations with a process-wide semaphore and fails fast with 503 backpressure once the acquire timeout elapses, instead of queueing unboundedly."
      },
      {
       "number": 11,
       "title": "Missing tenant scoping exposes another tenant's data",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "A handler that trusts a caller-supplied tenant_id, or a repository query that omits the tenant filter, breaks the isolation guarantee that is the core of the product.",
       "mitigation": "Tenant context is derived from the interceptor-verified session or JWT, never from request-body input; tenant filtering is enforced at the repository layer and cross-tenant graph edges are stripped on traversal."
      }
     ],
     "open": 0
    },
    {
     "id": "c840f79b-58af-5760-bed5-695977fed95e",
     "kind": "process",
     "x": 614,
     "y": 254,
     "w": 140,
     "h": 140,
     "name": "gRPC API (Tonic)",
     "lines": [
      "gRPC API",
      "(Tonic)"
     ],
     "description": "Low-latency authz checks, token introspection and user lookups for the service mesh.",
     "outOfScope": false,
     "threats": [
      {
       "number": 12,
       "title": "Cross-tenant token introspection",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A service account in tenant A introspects a token issued to tenant B and learns its subject, scopes and validity.",
       "mitigation": "SEC-068: the caller's tenant is taken from the interceptor-verified JWT and introspection refuses any token belonging to a different tenant."
      }
     ],
     "open": 0
    },
    {
     "id": "f1483c57-3f03-5760-9437-ed84f813a320",
     "kind": "process",
     "x": 614,
     "y": 444,
     "w": 140,
     "h": 140,
     "name": "AMQP consumer (Lapin)",
     "lines": [
      "AMQP",
      "consumer",
      "(Lapin)"
     ],
     "description": "Async authorization requests and audit-event ingestion from RabbitMQ.",
     "outOfScope": false,
     "threats": [
      {
       "number": 13,
       "title": "Forged authorization request on the broker",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "Anyone able to publish to axiam.authz.request can request decisions for arbitrary subjects, and anyone able to publish to axiam.audit.events can inject fabricated audit records.",
       "mitigation": "SEC-022 / SEC-055: messages carry an HMAC-SHA256 signature over the canonical JSON body, verified with constant-time comparison before the message is processed; a failed check is nacked without requeue and logged as a security event. SDK CONTRACT §8 makes this mandatory for every SDK that consumes AXIAM queues."
      }
     ],
     "open": 0
    },
    {
     "id": "6e37431c-2faf-5dbe-a94a-a425b4edd17f",
     "kind": "process",
     "x": 814,
     "y": 159,
     "w": 140,
     "h": 140,
     "name": "Security middleware (authn, CSRF, rate limit, CORS, audit)",
     "lines": [
      "Security",
      "middleware",
      "(authn,",
      "CSRF, rate",
      "limit,",
      "CORS,",
      "audit)"
     ],
     "description": "Shared request pipeline in front of every REST and gRPC handler.",
     "outOfScope": false,
     "threats": [
      {
       "number": 14,
       "title": "Rate limits multiplied by replica count",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Per-replica in-memory token buckets mean an HPA-scaled deployment enforces N times the intended rate, so brute-force and enumeration budgets scale with the cluster.",
       "mitigation": "SECHRD-03: a shared write-behind counter backed by the datastore pre-checks the limit across replicas, with the per-replica governor retained as a fail-open fallback and no synchronous datastore write on the request path."
      },
      {
       "number": 15,
       "title": "X-Forwarded-For spoofing bypasses per-IP limits",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A caller that can set XFF freely attributes every request to a different source address and defeats per-IP rate limiting and lockout.",
       "mitigation": "SEC-070: only a configured number of rightmost XFF hops (trusted_hops) is trusted, shared by the REST and gRPC extractors; untrusted hops fall back to the socket peer address."
      }
     ],
     "open": 0
    },
    {
     "id": "76d7e689-0541-59d7-ad98-0c2f633e96f2",
     "kind": "process",
     "x": 1014,
     "y": 159,
     "w": 140,
     "h": 140,
     "name": "Core service layer (AuthN, AuthZ, User, PKI, Federation)",
     "lines": [
      "Core",
      "service",
      "layer",
      "(AuthN,",
      "AuthZ,",
      "User,",
      "PKI,",
      "Federation)"
     ],
     "description": "Domain services composed by axiam-server; the only component that talks to the data tier.",
     "outOfScope": false,
     "threats": [
      {
       "number": 16,
       "title": "No deny-override in the RBAC cascade",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Open",
       "description": "The authorization engine is additive-only (allow-wins, default deny). A role granted high in the resource hierarchy cannot be revoked on a single child resource — the only way to remove access to a subtree is to restructure the grant.",
       "mitigation": "SEC-040, accepted for v1.0-beta and documented in the design document and the roadmap. Deny-override cascade is deferred to post-v1.0-beta. Operators must model exclusions by narrowing the grant rather than by adding a deny."
      }
     ],
     "open": 1
    },
    {
     "id": "b0953520-e5ca-5c39-8233-e8a9a3b7446b",
     "kind": "store",
     "x": 1269,
     "y": 94,
     "w": 170,
     "h": 80,
     "name": "SurrealDB cluster (all tenant data)",
     "lines": [
      "SurrealDB cluster",
      "(all tenant data)"
     ],
     "description": "Users, roles, resources, sessions, OAuth2 clients, certificates.",
     "outOfScope": false,
     "threats": [
      {
       "number": 17,
       "title": "Direct datastore access bypasses every application control",
       "type": "Information disclosure",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "SurrealDB holds Argon2id password hashes, encrypted MFA secrets, hashed client secrets and the entire authorization graph. Direct access bypasses tenant scoping, RBAC and audit entirely.",
       "mitigation": "The data tier sits on a private network with no ingress; credentials come from Kubernetes Secrets; connections are authenticated and namespaced. Secrets stored in the database are themselves hashed (passwords, client secrets) or AES-256-GCM encrypted (MFA secrets, CA keys, federation secrets)."
      },
      {
       "number": 18,
       "title": "Backup or snapshot exfiltration",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Open",
       "description": "A database backup, volume snapshot or debug dump carries the same data as the live store but usually far weaker access control.",
       "mitigation": "Not addressed by AXIAM itself. Deployment guidance: encrypt backups at rest, restrict snapshot IAM, and treat backup media as in-scope for the same access review as the live cluster."
      }
     ],
     "open": 1
    },
    {
     "id": "729c29f1-a3e5-5c09-9304-ccb838d250ff",
     "kind": "store",
     "x": 1269,
     "y": 204,
     "w": 170,
     "h": 80,
     "name": "Audit log (append-only, PGP signed)",
     "lines": [
      "Audit log",
      "(append-only, PGP",
      "signed)"
     ],
     "description": "Immutable audit trail; no UPDATE or DELETE permission.",
     "outOfScope": false,
     "threats": [
      {
       "number": 19,
       "title": "Audit record tampering or selective deletion",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "An attacker with datastore access edits or removes the records describing their own activity, destroying the forensic trail.",
       "mitigation": "The audit_log table grants no UPDATE or DELETE at the SurrealDB permission level, and batches are signed with the tenant OpenPGP key so removal or edit is detectable. Ship audit records to an external WORM sink for defence in depth."
      }
     ],
     "open": 0
    },
    {
     "id": "d52c38c4-1341-5d1f-8517-836feb9cfadb",
     "kind": "store",
     "x": 1269,
     "y": 314,
     "w": 170,
     "h": 80,
     "name": "RabbitMQ (authz, audit, mail, notification queues)",
     "lines": [
      "RabbitMQ",
      "(authz, audit, mail,",
      "notification queues)"
     ],
     "description": "Async transport for authz requests, audit ingestion and outbound mail.",
     "outOfScope": false,
     "threats": [
      {
       "number": 20,
       "title": "Queue flooding delays authorization decisions",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A producer that floods axiam.authz.request starves legitimate async decisions and backs up audit ingestion.",
       "mitigation": "Consumer prefetch is bounded by configuration and broker credentials are per-service so a single misbehaving producer can be revoked. Async authz is a deferred path; synchronous gRPC checks are unaffected."
      }
     ],
     "open": 0
    },
    {
     "id": "bcca5e76-1845-552a-9430-1d8d3a20e3ae",
     "kind": "store",
     "x": 1269,
     "y": 424,
     "w": 170,
     "h": 80,
     "name": "Kubernetes Secrets / ConfigMap",
     "lines": [
      "Kubernetes Secrets",
      "/ ConfigMap"
     ],
     "description": "JWT signing keys, datastore credentials, CA key encryption key, provider API keys.",
     "outOfScope": false,
     "threats": [
      {
       "number": 21,
       "title": "Signing-key disclosure allows arbitrary token minting",
       "type": "Information disclosure",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "The Ed25519 JWT signing key lets an attacker mint access tokens for any subject in any tenant, defeating authentication entirely.",
       "mitigation": "Keys live in Kubernetes Secrets, not in the image or ConfigMap; CA private keys are additionally AES-256-GCM encrypted at rest. Enable envelope encryption for etcd and rotate signing keys on a schedule — JWKS publishes multiple keys so rotation is non-breaking."
      }
     ],
     "open": 0
    }
   ],
   "edges": [
    {
     "id": "87b83a6c-1371-558e-bbb7-554b58dd0227",
     "path": "M209,117.2 L405.1,151.8",
     "name": "Admin UI + auth endpoints",
     "description": "React admin UI and public authentication endpoints.",
     "label": "Admin UI + auth endpoints (HTTPS)",
     "labelLines": [
      "Admin UI + auth endpoints (HTTPS)"
     ],
     "lx": 307,
     "ly": 134.5,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [
      {
       "number": 22,
       "title": "Credentials or tokens sent over plaintext HTTP",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "A downgraded or misconfigured deployment sends passwords, MFA codes and bearer tokens in the clear.",
       "mitigation": "TLS 1.3 minimum; HSTS emitted by the security-headers middleware; auth cookies carry the Secure attribute so they are never sent over plaintext."
      }
     ],
     "open": 0
    },
    {
     "id": "e1c3fab6-33e4-5f72-8d50-6ce012cdfa39",
     "path": "M209,234.1 L406.3,181.9",
     "name": "SDK REST + gRPC traffic",
     "description": "",
     "label": "SDK REST + gRPC traffic (HTTPS / gRPC-TLS)",
     "labelLines": [
      "SDK REST + gRPC traffic (HTTPS /",
      "gRPC-TLS)"
     ],
     "lx": 307.7,
     "ly": 208,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS / gRPC-TLS",
     "threats": [
      {
       "number": 23,
       "title": "SDK transport downgraded or TLS verification disabled",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "An SDK that accepts a plaintext base URL, or that offers an insecure() / skip-verify escape hatch, sends bearer tokens and credentials to an attacker-controlled or observable endpoint (finding X-2).",
       "mitigation": "SDK CONTRACT §6 makes strict TLS verification unconditional and absolutely prohibits any bypass API (no skip_tls_verification, insecure, allow_insecure, verify_peer(false)); the only escape hatch is with_custom_ca(pem) for development CAs. CI lint gates in each SDK repository grep for bypass patterns such as InsecureSkipVerify."
      }
     ],
     "open": 0
    },
    {
     "id": "d6507045-ba09-5901-9d86-da1fb27d443a",
     "path": "M190.7,364 L416.8,204.4",
     "name": "Device authentication",
     "description": "",
     "label": "Device authentication (mTLS)",
     "labelLines": [
      "Device authentication (mTLS)"
     ],
     "lx": 303.7,
     "ly": 284.2,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "mTLS",
     "threats": [],
     "open": 0
    },
    {
     "id": "92e26258-1a86-54c7-9fc8-990e014020f2",
     "path": "M543.3,154.1 L614.7,143.9",
     "name": "Proxied REST requests",
     "description": "",
     "label": "Proxied REST requests (HTTP/2)",
     "labelLines": [
      "Proxied REST requests (HTTP/2)"
     ],
     "lx": 579,
     "ly": 149,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "HTTP/2",
     "threats": [],
     "open": 0
    },
    {
     "id": "6b70ad3d-16a6-51ec-a18a-8d19a065e3c0",
     "path": "M529.7,206.4 L628.3,281.6",
     "name": "Proxied gRPC calls",
     "description": "",
     "label": "Proxied gRPC calls (gRPC/HTTP2)",
     "labelLines": [
      "Proxied gRPC calls (gRPC/HTTP2)"
     ],
     "lx": 579,
     "ly": 244,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "gRPC/HTTP2",
     "threats": [],
     "open": 0
    },
    {
     "id": "ecc39267-ad38-50ad-b761-29328c662a83",
     "path": "M747.2,164 L820.8,199",
     "name": "Request pipeline",
     "description": "",
     "label": "Request pipeline (in-process)",
     "labelLines": [
      "Request pipeline (in-process)"
     ],
     "lx": 784,
     "ly": 181.5,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "436d50ed-17d6-5352-a5b1-ca761479c87c",
     "path": "M747.2,294 L820.8,259",
     "name": "Interceptor pipeline",
     "description": "",
     "label": "Interceptor pipeline (in-process)",
     "labelLines": [
      "Interceptor pipeline (in-process)"
     ],
     "lx": 784,
     "ly": 276.5,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "448ca573-9d04-5851-b041-bf1518676601",
     "path": "M954,229 L1014,229",
     "name": "Authenticated, tenant-scoped call",
     "description": "",
     "label": "Authenticated, tenant-scoped call (in-process)",
     "labelLines": [
      "Authenticated, tenant-scoped call",
      "(in-process)"
     ],
     "lx": 984,
     "ly": 229,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "3f35443c-4a63-58df-9d48-619b7c795989",
     "path": "M741,473.4 L1027,269.6",
     "name": "Async authz / audit dispatch",
     "description": "",
     "label": "Async authz / audit dispatch (in-process)",
     "labelLines": [
      "Async authz / audit dispatch",
      "(in-process)"
     ],
     "lx": 884,
     "ly": 371.5,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "84874875-b0fc-5d01-9e46-7e5b070e1611",
     "path": "M1150,205.8 L1269,163.9",
     "name": "Domain reads and writes",
     "description": "",
     "label": "Domain reads and writes (SurrealQL/WSS)",
     "labelLines": [
      "Domain reads and writes",
      "(SurrealQL/WSS)"
     ],
     "lx": 1209.5,
     "ly": 184.8,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL/WSS",
     "threats": [
      {
       "number": 24,
       "title": "Query injection into SurrealQL",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "String-built queries would let attacker-controlled identifiers or filters alter the statement and cross tenant boundaries.",
       "mitigation": "Parameterised queries only — SurrealDB bind parameters are used throughout axiam-db; no query is assembled by string concatenation of user input."
      }
     ],
     "open": 0
    },
    {
     "id": "a537610b-f08b-593a-908b-7aab0a292fad",
     "path": "M1153.9,232.9 L1269,239.3",
     "name": "Append-only audit writes",
     "description": "",
     "label": "Append-only audit writes (SurrealQL/WSS)",
     "labelLines": [
      "Append-only audit writes",
      "(SurrealQL/WSS)"
     ],
     "lx": 1211.4,
     "ly": 236.1,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL/WSS",
     "threats": [],
     "open": 0
    },
    {
     "id": "ef3facab-deb6-57a7-93a0-b7c49bdd5991",
     "path": "M1147.5,258.4 L1269,314.6",
     "name": "Publish events / consume queues",
     "description": "",
     "label": "Publish events / consume queues (AMQPS)",
     "labelLines": [
      "Publish events / consume queues",
      "(AMQPS)"
     ],
     "lx": 1208.3,
     "ly": 286.5,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "AMQPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "a8a236be-cf02-5339-bc5f-dbec6bb1caf7",
     "path": "M1269,374.3 L752.1,497.7",
     "name": "Deliver authz + audit messages",
     "description": "",
     "label": "Deliver authz + audit messages (AMQPS)",
     "labelLines": [
      "Deliver authz + audit messages",
      "(AMQPS)"
     ],
     "lx": 1010.5,
     "ly": 436,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "AMQPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "ce605a4f-1539-5038-b600-290b738469c5",
     "path": "M1136.8,275 L1308,424",
     "name": "Read keys and credentials",
     "description": "",
     "label": "Read keys and credentials (K8s API / file)",
     "labelLines": [
      "Read keys and credentials (K8s API /",
      "file)"
     ],
     "lx": 1222.4,
     "ly": 349.5,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "K8s API / file",
     "threats": [],
     "open": 0
    },
    {
     "id": "2feed68f-7d68-59be-b820-8ecc432a3a37",
     "path": "M1119.1,289.5 L1330.8,654",
     "name": "Discovery, JWKS, token exchange",
     "description": "All outbound IdP fetches go through the SSRF-guarded resolve-and-pin helper.",
     "label": "Discovery, JWKS, token exchange (HTTPS)",
     "labelLines": [
      "Discovery, JWKS, token exchange",
      "(HTTPS)"
     ],
     "lx": 1225,
     "ly": 471.8,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [
      {
       "number": 25,
       "title": "SSRF via admin-supplied IdP metadata URL",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "A tenant admin who can set metadata_url or jwks_uri makes the server fetch internal addresses — cloud metadata endpoints, in-cluster services — and observe the response.",
       "mitigation": "SEC-069 / D-01: guarded_fetch resolves A and AAAA fresh, rejects loopback, private, link-local, ULA and unspecified addresses, pins the validated IP for the connect (closing the DNS-rebind TOCTOU window), enforces https on every hop including redirects, and caps the advertised body size."
      }
     ],
     "open": 0
    },
    {
     "id": "0a71dad5-4d7f-51ff-bde4-a79e4e0898f1",
     "path": "M1114,292.3 L1335.1,759",
     "name": "Transactional email",
     "description": "",
     "label": "Transactional email (SMTP-TLS / HTTPS)",
     "labelLines": [
      "Transactional email (SMTP-TLS /",
      "HTTPS)"
     ],
     "lx": 1224.5,
     "ly": 525.6,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "SMTP-TLS / HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "2ad94690-1f56-5241-ac1b-a7d47b2cd04d",
     "path": "M1110.2,293.9 L1337.9,859",
     "name": "Event delivery",
     "description": "",
     "label": "Event delivery (HTTPS + HMAC-SHA256)",
     "labelLines": [
      "Event delivery (HTTPS + HMAC-SHA256)"
     ],
     "lx": 1224,
     "ly": 576.5,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS + HMAC-SHA256",
     "threats": [
      {
       "number": 26,
       "title": "Webhook registration used to probe internal services",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A tenant admin registers a webhook pointing at an internal address and uses delivery success or timing as an internal port scanner.",
       "mitigation": "Webhook delivery uses the same guarded_fetch resolve-and-pin guard as federation: private and loopback destinations are rejected before connect."
      }
     ],
     "open": 0
    }
   ],
   "total": 26,
   "open": 3,
   "bySeverity": {
    "High": 13,
    "Medium": 10,
    "Critical": 3
   }
  },
  {
   "id": 1,
   "title": "Authentication & session management",
   "description": "Password login, MFA (TOTP and WebAuthn), lockout and rate limiting, JWT and refresh-token issuance, password reset and email verification, and the credential stores behind them.",
   "width": 1448,
   "height": 908,
   "boundaries": [
    {
     "id": "af233983-3fc1-59bb-999e-fb9da2ae19e7",
     "x": 24,
     "y": 24,
     "w": 250,
     "h": 700,
     "label": "Untrusted network"
    },
    {
     "id": "0dfb1c65-0426-5d6b-be8f-42c0a5a23b2f",
     "x": 314,
     "y": 24,
     "w": 660,
     "h": 860,
     "label": "AXIAM authentication services"
    },
    {
     "id": "6da5f7e4-cb1d-5abf-aa06-f9204b98fa4d",
     "x": 1024,
     "y": 64,
     "w": 400,
     "h": 800,
     "label": "Data tier"
    }
   ],
   "nodes": [
    {
     "id": "c3a28398-2e1a-506b-96e7-e7349fd96628",
     "kind": "actor",
     "x": 49,
     "y": 94,
     "w": 150,
     "h": 80,
     "name": "End user (browser or SDK)",
     "lines": [
      "End user",
      "(browser or SDK)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 27,
       "title": "Credential stuffing with breached password lists",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "Automated login attempts using credentials leaked from unrelated services succeed against users who reuse passwords.",
       "mitigation": "Per-IP and per-user rate limiting, exponential-backoff lockout after N failures, optional HIBP k-anonymity breach check on password set, and org/tenant-enforceable MFA."
      },
      {
       "number": 28,
       "title": "Phishing harvests password and TOTP code",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "A proxy phishing page relays the user's password and live TOTP code to the real endpoint in real time — TOTP does not bind to the origin.",
       "mitigation": "WebAuthn/FIDO2 passkeys and hardware keys are supported and are origin-bound, so they resist real-time proxy phishing. Tenants requiring phishing resistance should mandate WebAuthn rather than TOTP."
      }
     ],
     "open": 0
    },
    {
     "id": "c0035bef-d326-5b96-960a-2106baccf92d",
     "kind": "actor",
     "x": 49,
     "y": 484,
     "w": 150,
     "h": 80,
     "name": "Email provider",
     "lines": [
      "Email provider"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 29,
       "title": "Reset link intercepted in transit or at rest in a mailbox",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Password-reset links are bearer credentials; a compromised mailbox or provider grants account takeover.",
       "mitigation": "Reset tokens are CSPRNG-generated (never UUIDv7 — see the design-document note on id generation), single-use and expire quickly; consuming a reset invalidates existing sessions."
      }
     ],
     "open": 0
    },
    {
     "id": "6800fc4b-a3b4-581c-b613-969b5a6e9d2d",
     "kind": "process",
     "x": 364,
     "y": 74,
     "w": 140,
     "h": 140,
     "name": "Login endpoint POST /auth/login",
     "lines": [
      "Login",
      "endpoint",
      "POST",
      "/auth/login"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 30,
       "title": "Username enumeration via differential responses",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Different status codes, error bodies or response times for existing versus non-existent accounts let an attacker enumerate valid usernames and email addresses.",
       "mitigation": "Login returns a uniform failure for unknown-user and bad-password alike, and password verification runs on a dummy hash when the user does not exist so timing does not distinguish the cases."
      },
      {
       "number": 31,
       "title": "Unmetered credential-check path outside the lockout counter",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "If any code path verifies a password without incrementing the failed-attempt counter, brute force is unbounded through that path even though the main login endpoint is protected.",
       "mitigation": "SEC-026b / D-06: the REST login path and the gRPC UserService::validate_credentials path both call the single shared lockout helper, which is the sole source of truth for failed-attempt accrual."
      }
     ],
     "open": 0
    },
    {
     "id": "cfb2181e-2bde-5024-81d2-ee89349748f7",
     "kind": "process",
     "x": 364,
     "y": 254,
     "w": 140,
     "h": 140,
     "name": "MFA verification TOTP / WebAuthn",
     "lines": [
      "MFA",
      "verification",
      "TOTP /",
      "WebAuthn"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 32,
       "title": "MFA step skipped by replaying the challenge token",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "If the intermediate MFA challenge token is accepted as a full session, or can be exchanged more than once, the second factor is bypassed.",
       "mitigation": "The challenge token is a distinct, short-lived, single-use credential that only authorises the MFA verification call; it carries no API authority and is consumed on use."
      },
      {
       "number": 33,
       "title": "TOTP code replay inside its validity window",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A code observed by a proxy or shoulder-surfer stays valid for the remainder of its 30-second step plus drift tolerance.",
       "mitigation": "Verified TOTP codes are recorded and refused on reuse within the acceptance window; the drift window is kept to the minimum RFC 6238 recommends."
      },
      {
       "number": 34,
       "title": "Admin MFA reset abused as a takeover path",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "MFA enrolment reset must exist for lost devices, but an attacker who reaches an admin account can use it to strip the second factor from any user.",
       "mitigation": "Only org/tenant admins can reset MFA state; the reset is audited and raises an admin notification. Enrolment must be redone on next login before any resource is reachable."
      }
     ],
     "open": 0
    },
    {
     "id": "bf8d511e-1da8-59ad-909b-a4ad6a647b85",
     "kind": "process",
     "x": 364,
     "y": 434,
     "w": 140,
     "h": 140,
     "name": "Lockout & rate limiting",
     "lines": [
      "Lockout &",
      "rate",
      "limiting"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 35,
       "title": "Lockout weaponised to deny service to a known user",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "An attacker who knows a username deliberately fails logins to keep the victim locked out.",
       "mitigation": "Lockout uses exponential backoff rather than a permanent lock, and a successful password reset clears the counter, giving the legitimate user a self-service path back in."
      },
      {
       "number": 36,
       "title": "Failed-attempt counter race under concurrency",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Read-then-write increments lose updates under parallel attempts, letting an attacker exceed the configured threshold.",
       "mitigation": "SEC-032: the increment is a single atomic SurrealQL UPDATE, removing the TOCTOU window."
      }
     ],
     "open": 0
    },
    {
     "id": "fcccaa5a-620f-5695-afdb-bae022846c05",
     "kind": "process",
     "x": 594,
     "y": 74,
     "w": 140,
     "h": 140,
     "name": "Token service EdDSA JWT + refresh rotation",
     "lines": [
      "Token",
      "service",
      "EdDSA JWT +",
      "refresh",
      "rotation"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 37,
       "title": "Refresh-token theft and reuse",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "A stolen refresh token grants indefinite re-authentication if it can be redeemed repeatedly.",
       "mitigation": "Refresh tokens are opaque, server-stored and single-use with rotation; redeeming a token that has already been rotated is detectable and invalidates the family."
      },
      {
       "number": 38,
       "title": "Algorithm confusion or unsigned-token acceptance",
       "type": "Spoofing",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "A verifier that honours the token's own alg header can be tricked into accepting alg=none or an HMAC token signed with the public key.",
       "mitigation": "The verifier pins EdDSA (Ed25519) and rejects any other algorithm; the expected algorithm is never read from the token header."
      },
      {
       "number": 39,
       "title": "Access token still valid after entitlement revocation",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Open",
       "description": "Access tokens are self-contained and valid for up to 15 minutes, so a role removal or account disable does not take effect on already-issued tokens until they expire.",
       "mitigation": "Accepted trade-off for stateless verification. The 15-minute lifetime bounds the window; sessions are invalidated on password change; deployments needing immediate revocation should use the gRPC introspection path rather than local JWT verification."
      }
     ],
     "open": 1
    },
    {
     "id": "0a06a341-40e5-5a4a-a53e-e095a5c62ca7",
     "kind": "process",
     "x": 594,
     "y": 434,
     "w": 140,
     "h": 140,
     "name": "Password reset & email verification",
     "lines": [
      "Password",
      "reset &",
      "email",
      "verification"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 40,
       "title": "Reset token guessing",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "A predictable or low-entropy reset token is brute-forceable within its validity window.",
       "mitigation": "Reset, verification, export-download and deletion-cancel tokens are CSPRNG-generated. The design document explicitly forbids UUIDv7 for secrets because its 48-bit timestamp prefix leaves same-millisecond values sharing a long common prefix."
      },
      {
       "number": 41,
       "title": "Verification email resend used for mail flooding",
       "type": "Denial of service",
       "severity": "Low",
       "status": "Mitigated",
       "description": "Repeated resend requests turn AXIAM into an email flooder against an arbitrary address and burn provider quota.",
       "mitigation": "Resend is capped (max 2 per day per account) and the endpoint is rate limited."
      }
     ],
     "open": 0
    },
    {
     "id": "4239d8ce-a5f5-5908-86c6-a68436c8e359",
     "kind": "process",
     "x": 594,
     "y": 624,
     "w": 140,
     "h": 140,
     "name": "Password policy + HIBP check",
     "lines": [
      "Password",
      "policy",
      "+ HIBP",
      "check"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 42,
       "title": "Password exposed to the breach-check service",
       "type": "Information disclosure",
       "severity": "Low",
       "status": "Mitigated",
       "description": "Sending a password or its full hash to a third-party breach API discloses the credential to that service.",
       "mitigation": "HIBP is queried with the k-anonymity model: only the first five characters of the SHA-1 hash leave the server. A circuit breaker prevents the optional check from becoming an availability dependency."
      }
     ],
     "open": 0
    },
    {
     "id": "723bd2e1-0555-5a1b-9fca-915b84a37849",
     "kind": "store",
     "x": 1074,
     "y": 104,
     "w": 170,
     "h": 80,
     "name": "user (Argon2id hashes)",
     "lines": [
      "user",
      "(Argon2id hashes)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 43,
       "title": "Offline cracking of exfiltrated password hashes",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "A database disclosure exposes every password hash to offline attack at attacker-chosen cost.",
       "mitigation": "Argon2id with OWASP-recommended parameters (m=19 MiB, t=2, p=1) and per-user salts makes bulk cracking expensive; policy enforces a 12-character minimum by default."
      }
     ],
     "open": 0
    },
    {
     "id": "e27104a1-bf6c-5076-ae53-119e529fc25b",
     "kind": "store",
     "x": 1074,
     "y": 264,
     "w": 170,
     "h": 80,
     "name": "session / refresh token store",
     "lines": [
      "session /",
      "refresh token store"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 44,
       "title": "Stored session tokens usable directly from the datastore",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "If session tokens were stored in plaintext, datastore read access would be equivalent to holding every live session.",
       "mitigation": "Sessions store a token hash, not the token; the bearer value never rests in the database in usable form."
      }
     ],
     "open": 0
    },
    {
     "id": "56326314-a524-54b8-b713-02a5f29b0a0b",
     "kind": "store",
     "x": 1074,
     "y": 424,
     "w": 170,
     "h": 80,
     "name": "MFA secrets (AES-256-GCM)",
     "lines": [
      "MFA secrets",
      "(AES-256-GCM)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 45,
       "title": "TOTP seed disclosure allows permanent code generation",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "A TOTP shared secret is a long-lived credential: whoever holds it can generate valid codes indefinitely.",
       "mitigation": "Seeds are AES-256-GCM encrypted at rest with a key held outside the datastore, so a database-only compromise does not yield usable seeds."
      }
     ],
     "open": 0
    },
    {
     "id": "e2df752c-693a-54e1-952e-5df6f22f80b6",
     "kind": "store",
     "x": 1074,
     "y": 584,
     "w": 170,
     "h": 80,
     "name": "rate-limit counters (shared, write-behind)",
     "lines": [
      "rate-limit counters",
      "(shared, write-behind)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 46,
       "title": "Counter store unavailability disables the shared limit",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "If the shared counter cannot be read, the cross-replica limit cannot be evaluated.",
       "mitigation": "The shared pre-check fails open onto the per-replica in-memory governor, which is retained unchanged as the fallback — degraded but never absent protection."
      }
     ],
     "open": 0
    },
    {
     "id": "a555ee1a-48e7-50f5-a8d1-b431b33657c0",
     "kind": "store",
     "x": 1074,
     "y": 724,
     "w": 170,
     "h": 80,
     "name": "JWT signing keys (Ed25519)",
     "lines": [
      "JWT signing keys",
      "(Ed25519)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 47,
       "title": "Signing-key compromise forges any identity",
       "type": "Information disclosure",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "The Ed25519 private key mints tokens for any subject in any tenant and cannot be detected by any downstream verifier.",
       "mitigation": "Keys are loaded from Kubernetes Secrets, never from the image; JWKS publishes multiple key ids so rotation is non-breaking; rotate on a schedule and immediately on suspicion."
      }
     ],
     "open": 0
    }
   ],
   "edges": [
    {
     "id": "b82b483a-1cc4-5fce-8024-47a1ded0765c",
     "path": "M199,136.4 L364,141.7",
     "name": "username + password",
     "description": "",
     "label": "username + password (HTTPS)",
     "labelLines": [
      "username + password (HTTPS)"
     ],
     "lx": 281.5,
     "ly": 139.1,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "bc6e4e36-9b83-5308-b703-cd93807ad7ce",
     "path": "M434,214 L434,434",
     "name": "record attempt",
     "description": "",
     "label": "record attempt (in-process)",
     "labelLines": [
      "record attempt (in-process)"
     ],
     "lx": 434,
     "ly": 324,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "cb9e18e2-9aa5-520f-8421-d72fb83af566",
     "path": "M434,214 L434,254",
     "name": "MFA challenge token",
     "description": "",
     "label": "MFA challenge token (in-process)",
     "labelLines": [
      "MFA challenge token (in-process)"
     ],
     "lx": 434,
     "ly": 234,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "3fbe78c5-695d-5a49-9c82-cdc50d8c0449",
     "path": "M189.3,174 L374.3,287.4",
     "name": "TOTP code / WebAuthn assertion",
     "description": "",
     "label": "TOTP code / WebAuthn assertion (HTTPS)",
     "labelLines": [
      "TOTP code / WebAuthn assertion",
      "(HTTPS)"
     ],
     "lx": 281.8,
     "ly": 230.7,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "faf43688-3d52-56d9-8b50-da376e04ea80",
     "path": "M489.1,280.9 L608.9,187.1",
     "name": "verified factor",
     "description": "",
     "label": "verified factor (in-process)",
     "labelLines": [
      "verified factor (in-process)"
     ],
     "lx": 549,
     "ly": 234,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "98fdc3ac-e829-5af2-8e87-6763ce5b6dab",
     "path": "M504,144 L594,144",
     "name": "issue session",
     "description": "",
     "label": "issue session (in-process)",
     "labelLines": [
      "issue session (in-process)"
     ],
     "lx": 549,
     "ly": 144,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "2ab836c5-adfd-5688-a818-cb732cdd34fb",
     "path": "M594,142.7 L199,135.4",
     "name": "access + refresh cookies",
     "description": "",
     "label": "access + refresh cookies (HTTPS)",
     "labelLines": [
      "access + refresh cookies (HTTPS)"
     ],
     "lx": 396.5,
     "ly": 139,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [
      {
       "number": 48,
       "title": "Tokens leaked through URLs, logs or Referer headers",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Bearer values placed in query strings end up in access logs, browser history and Referer headers sent to third parties.",
       "mitigation": "Tokens are delivered in the response body and in Secure/HttpOnly cookies, never as URL parameters; secret-bearing types carry manual Debug implementations that redact them from logs (SEC-067 / SECHRD-09)."
      }
     ],
     "open": 0
    },
    {
     "id": "4a77cae1-0cbc-5d8e-b492-ca5be800a0b1",
     "path": "M504,144 L1074,144",
     "name": "fetch user + verify hash",
     "description": "",
     "label": "fetch user + verify hash (SurrealQL)",
     "labelLines": [
      "fetch user + verify hash (SurrealQL)"
     ],
     "lx": 789,
     "ly": 144,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "78349ccf-99d8-5c4e-8c20-da10651453db",
     "path": "M730.6,165.5 L1074,276.5",
     "name": "store hashed session",
     "description": "",
     "label": "store hashed session (SurrealQL)",
     "labelLines": [
      "store hashed session (SurrealQL)"
     ],
     "lx": 902.3,
     "ly": 221,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "047c2b7d-cf6b-56c9-a4ed-26b167c896ee",
     "path": "M502.7,337.3 L1074,447.6",
     "name": "read encrypted seed",
     "description": "",
     "label": "read encrypted seed (SurrealQL)",
     "labelLines": [
      "read encrypted seed (SurrealQL)"
     ],
     "lx": 788.4,
     "ly": 392.4,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "cc949af1-5a7d-5a77-ade2-d29a0755bf2c",
     "path": "M503.1,515.4 L1074,609.9",
     "name": "atomic increment",
     "description": "",
     "label": "atomic increment (SurrealQL)",
     "labelLines": [
      "atomic increment (SurrealQL)"
     ],
     "lx": 788.5,
     "ly": 562.7,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "78a00103-7d6e-5909-b092-5361fdcc7f0d",
     "path": "M707.7,198.7 L1127.1,724",
     "name": "sign assertion",
     "description": "",
     "label": "sign assertion (in-process)",
     "labelLines": [
      "sign assertion (in-process)"
     ],
     "lx": 917.4,
     "ly": 461.4,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "9874896f-1579-5692-b9b2-dabc038fcdea",
     "path": "M594,506.6 L199,521.2",
     "name": "reset / verification mail",
     "description": "",
     "label": "reset / verification mail (SMTP-TLS / HTTPS)",
     "labelLines": [
      "reset / verification mail (SMTP-TLS",
      "/ HTTPS)"
     ],
     "lx": 396.5,
     "ly": 513.9,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "SMTP-TLS / HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "f68e80a7-7555-5514-b62f-e0e95d1426a1",
     "path": "M182.4,174 L606.3,464.4",
     "name": "reset request + confirm",
     "description": "",
     "label": "reset request + confirm (HTTPS)",
     "labelLines": [
      "reset request + confirm (HTTPS)"
     ],
     "lx": 394.3,
     "ly": 319.2,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "a03f46f1-5e49-54b5-a6d8-26c34a48b286",
     "path": "M664,574 L664,624",
     "name": "validate new password",
     "description": "",
     "label": "validate new password (in-process)",
     "labelLines": [
      "validate new password (in-process)"
     ],
     "lx": 664,
     "ly": 599,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "169093ba-c8b9-5edb-b1a3-76043f13a2de",
     "path": "M710.8,642 L1123,184",
     "name": "write new hash + history",
     "description": "",
     "label": "write new hash + history (SurrealQL)",
     "labelLines": [
      "write new hash + history (SurrealQL)"
     ],
     "lx": 916.9,
     "ly": 413,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    }
   ],
   "total": 22,
   "open": 1,
   "bySeverity": {
    "High": 9,
    "Medium": 8,
    "Critical": 3,
    "Low": 2
   }
  },
  {
   "id": 2,
   "title": "OAuth2 / OIDC authorization server",
   "description": "Authorization Code with PKCE, client credentials and refresh grants; consent, introspection, revocation, userinfo, JWKS and discovery; client registration and the code and token stores.",
   "width": 1438,
   "height": 868,
   "boundaries": [
    {
     "id": "62545360-5217-533c-8fe0-9d3096b4e555",
     "x": 24,
     "y": 24,
     "w": 260,
     "h": 720,
     "label": "Relying parties / public Internet"
    },
    {
     "id": "41f5d0f6-5f9d-5f68-be10-2c4e8ea0d5e1",
     "x": 324,
     "y": 24,
     "w": 660,
     "h": 800,
     "label": "AXIAM OAuth2 / OIDC provider"
    },
    {
     "id": "7b061546-11a6-5063-a60a-18fc28c2d119",
     "x": 1034,
     "y": 64,
     "w": 380,
     "h": 780,
     "label": "Data tier"
    }
   ],
   "nodes": [
    {
     "id": "942f79a1-21ea-5fce-a043-dedc03b9dd69",
     "kind": "actor",
     "x": 49,
     "y": 94,
     "w": 150,
     "h": 80,
     "name": "OAuth2 client app (confidential / public)",
     "lines": [
      "OAuth2 client app",
      "(confidential /",
      "public)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 49,
       "title": "Public client cannot keep a secret",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "SPAs and mobile apps ship their client_secret to the user, so secret-based client authentication is meaningless for them.",
       "mitigation": "Authorization Code with PKCE is the supported flow for public clients; the code_verifier replaces the secret as proof of possession. The implicit grant is not offered."
      }
     ],
     "open": 0
    },
    {
     "id": "f87eea4c-e8b9-54be-b890-88743fe08b84",
     "kind": "actor",
     "x": 49,
     "y": 264,
     "w": 150,
     "h": 80,
     "name": "Resource server (protected API)",
     "lines": [
      "Resource server",
      "(protected API)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 50,
       "title": "Token substitution across audiences",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "A resource server that does not check the audience accepts a token minted for a different client or API, letting a malicious RP replay a token it legitimately received.",
       "mitigation": "Tokens carry issuer, audience and tenant claims; SDK verifiers check iss and aud against configuration, and the discovery document publishes the expected issuer."
      }
     ],
     "open": 0
    },
    {
     "id": "02c75ad6-34a0-5a3d-86d0-0f684e0c5ae1",
     "kind": "actor",
     "x": 49,
     "y": 434,
     "w": 150,
     "h": 80,
     "name": "End user (resource owner)",
     "lines": [
      "End user",
      "(resource owner)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 51,
       "title": "Consent screen spoofing / clickjacking",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Framing the consent screen and overlaying it tricks a user into approving a grant they cannot see.",
       "mitigation": "The security-headers middleware sets frame-ancestors in the CSP and X-Frame-Options, so the authorization endpoint cannot be framed by a third-party origin."
      }
     ],
     "open": 0
    },
    {
     "id": "0df1ba0d-316d-5394-91be-646cb231fc84",
     "kind": "process",
     "x": 374,
     "y": 74,
     "w": 140,
     "h": 140,
     "name": "/oauth2/authorize (+ consent)",
     "lines": [
      "/oauth2/authorize",
      "(+ consent)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 52,
       "title": "Open redirect via a loosely matched redirect_uri",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "Prefix or wildcard matching on redirect_uri lets an attacker append a path or subdomain and receive the authorization code at a URL they control.",
       "mitigation": "redirect_uri is matched by exact string comparison against the registered set; no wildcards, no prefix matching, no normalisation that could widen the match."
      },
      {
       "number": 53,
       "title": "Login CSRF via a missing state parameter",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Without a state value bound to the user's session, an attacker can complete an authorization in the victim's browser and link the victim's session to an attacker-controlled identity.",
       "mitigation": "state is required and echoed unchanged; the browser-facing flow additionally runs behind the double-submit CSRF cookie middleware with constant-time comparison."
      }
     ],
     "open": 0
    },
    {
     "id": "85a0d330-603a-516c-b60a-8e989081343d",
     "kind": "process",
     "x": 374,
     "y": 264,
     "w": 140,
     "h": 140,
     "name": "/oauth2/token (code, refresh, client credentials)",
     "lines": [
      "/oauth2/token",
      "(code,",
      "refresh,",
      "client",
      "credentials)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 54,
       "title": "Authorization code replay",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "A code observed in a redirect, a proxy log or browser history is exchanged a second time for a fresh token pair.",
       "mitigation": "Codes are single-use, short-lived, and bound to the issuing client and redirect_uri; a second redemption both fails and is audited."
      },
      {
       "number": 55,
       "title": "Scope escalation at token exchange",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "A client requests broader scopes at the token endpoint than the user consented to at the authorize endpoint.",
       "mitigation": "Granted scope is fixed at authorization time and stored with the code; the token endpoint can only narrow it, never widen it, and refresh never re-expands scope."
      },
      {
       "number": 166,
       "title": "Stolen client credential replayed from anywhere on the network",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "A confidential client's client_secret leaks — through a log, a CI variable, a config repository or an operator's shell history — and an attacker presents it from an arbitrary host to mint tokens as that client. A shared secret carries no evidence of where it is being used from, so the authorization server cannot distinguish the legitimate client from the thief.",
       "mitigation": "X5.1 adds RFC 8705 mutual-TLS client authentication: a client registered tls_client_auth or self_signed_tls_client_auth authenticates by presenting a certificate rustls verifies during the TLS 1.3 handshake, matched against the registration's subject DN / SAN or its x5t#S256 thumbprint. The private key never leaves the client, so the credential cannot be copied out of a log. The REGISTRATION selects which credential authenticates, never the request, so the two methods can never become an OR an attacker may pick from; and the X-Client-Certificate proxy header the device-auth path accepts is deliberately not a source here, because a client credential must not be assertable by anything that can set a header. Every failure returns one uniform invalid_client description (SEC-086), so client existence stays undecidable to an unauthenticated caller."
      }
     ],
     "open": 0
    },
    {
     "id": "12ef7ba0-6262-5ee5-bd0c-53e29bf97e30",
     "kind": "process",
     "x": 374,
     "y": 464,
     "w": 140,
     "h": 140,
     "name": "PKCE verification (S256)",
     "lines": [
      "PKCE",
      "verification",
      "(S256)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 56,
       "title": "PKCE downgrade to the plain method",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "Accepting code_challenge_method=plain lets an attacker who intercepts the authorization request read the verifier directly, defeating the protection.",
       "mitigation": "S256 is required; the plain method is rejected, and a code issued with a challenge cannot be redeemed without a matching verifier."
      }
     ],
     "open": 0
    },
    {
     "id": "fc37d424-69f0-57e0-88af-7392afd9c8af",
     "kind": "process",
     "x": 624,
     "y": 74,
     "w": 140,
     "h": 140,
     "name": "/oauth2/introspect /revoke",
     "lines": [
      "/oauth2/introspect",
      "/revoke"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 57,
       "title": "Unauthenticated introspection leaks token metadata",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "An open introspection endpoint becomes a token oracle: an attacker can test captured values and learn subject, scope and expiry.",
       "mitigation": "Introspection requires client authentication and is scoped to the caller's own tenant (SEC-068); unknown tokens return the uniform inactive response with no distinguishing detail."
      }
     ],
     "open": 0
    },
    {
     "id": "0e4c6d78-5d60-5e5c-8155-001a2aa194a3",
     "kind": "process",
     "x": 624,
     "y": 264,
     "w": 140,
     "h": 140,
     "name": "OIDC /userinfo, /jwks, discovery",
     "lines": [
      "OIDC",
      "/userinfo,",
      "/jwks,",
      "discovery"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 58,
       "title": "userinfo returns claims beyond the granted scope",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Returning the full profile regardless of scope discloses email, groups or metadata the user never consented to share.",
       "mitigation": "Claims are filtered by the token's granted scopes; profile, email and groups claims each require their corresponding scope."
      }
     ],
     "open": 0
    },
    {
     "id": "ac473925-1f97-55be-aafc-97c12a7fe1d6",
     "kind": "process",
     "x": 624,
     "y": 464,
     "w": 140,
     "h": 140,
     "name": "Client registration & secret rotation",
     "lines": [
      "Client",
      "registration",
      "& secret",
      "rotation"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 59,
       "title": "Client secrets recoverable from storage or logs",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "Plaintext client secrets in the database — or in a Debug or trace line — are directly reusable credentials.",
       "mitigation": "Secrets are stored HMAC-SHA256 hashed and returned once at creation; secret-bearing structs carry manual Debug impls that redact them (SEC-067 / SECHRD-09)."
      }
     ],
     "open": 0
    },
    {
     "id": "f8c49d07-806e-5df3-9676-9bf67219bb9e",
     "kind": "store",
     "x": 1079,
     "y": 114,
     "w": 170,
     "h": 80,
     "name": "oauth2_client (hashed secrets)",
     "lines": [
      "oauth2_client",
      "(hashed secrets)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [],
     "open": 0
    },
    {
     "id": "ea2fab0b-2102-5d72-b336-747899b41383",
     "kind": "store",
     "x": 1079,
     "y": 274,
     "w": 170,
     "h": 80,
     "name": "authorization codes (single-use)",
     "lines": [
      "authorization codes",
      "(single-use)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 60,
       "title": "Codes outlive their intended window",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Codes that are not expired or purged remain redeemable long after the flow completes, widening the replay window.",
       "mitigation": "Codes carry a short expiry, are deleted on redemption, and expired entries are swept."
      },
      {
       "number": 164,
       "title": "Two concurrent redemptions of one authorization code",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "A code observed in a redirect or a proxy log and replayed at the same moment as the legitimate exchange could, if the two are not serialised, let both callers mint a token pair from one authorization. T-54 covers the sequential replay; this is the concurrent one, which the single-use flag alone does not decide.",
       "mitigation": "Two independent layers, the same pair the three credentials in T-163 carry (schema v37). The guarded UPDATE — used = false, with client_id and redirect_uri matched in the same statement so a wrong-client attempt cannot burn the code — runs inside an explicit transaction, so two concurrent redemptions conflict on one key and the engine aborts the loser; and a per-attempt redemption nonce is read back in a separate query after that transaction commits, catching a conflict the engine silently missed. Before v37 this path had the first layer implicitly (a lone statement runs in the engine's own transaction) and the second not at all, which left it resting on T-165 with nothing behind it. Guarded by authorization_code_consume_serialises over 50 rounds of 8 racers, and by an_authorization_code_redemption_stamps_its_nonce, which asserts the second layer directly — a race test cannot distinguish a two-layer mechanism from a one-layer one when the engine arbitrates either way."
      }
     ],
     "open": 0
    },
    {
     "id": "80616398-b151-54a9-8b63-8ddda79c7552",
     "kind": "store",
     "x": 1079,
     "y": 434,
     "w": 170,
     "h": 80,
     "name": "access / refresh token store",
     "lines": [
      "access / refresh",
      "token store"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [],
     "open": 0
    },
    {
     "id": "443fa9af-3c1e-571b-8b1e-e97fd5e13e83",
     "kind": "store",
     "x": 1079,
     "y": 594,
     "w": 170,
     "h": 80,
     "name": "OIDC signing keys (JWKS)",
     "lines": [
      "OIDC signing keys",
      "(JWKS)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 61,
       "title": "Stale key served in JWKS after rotation",
       "type": "Information disclosure",
       "severity": "Low",
       "status": "Mitigated",
       "description": "Removing a key from JWKS before its last token expires breaks verification; leaving a retired key indefinitely widens the window in which a compromised key is still trusted.",
       "mitigation": "JWKS publishes the active key plus a bounded overlap window matching the maximum token lifetime, then drops the retired kid."
      }
     ],
     "open": 0
    },
    {
     "id": "c237826a-f4f2-5097-ac9a-591ed35d79f6",
     "kind": "store",
     "x": 1079,
     "y": 754,
     "w": 170,
     "h": 80,
     "name": "single-use credentials (UMA tickets, device codes, PAR request_uris)",
     "lines": [
      "single-use credentials",
      "(UMA tickets, device",
      "codes, PAR",
      "request_uris)"
     ],
     "description": "permission_ticket, device_grant and pushed_auth_request rows. Each is redeemable exactly once: a UMA ticket mints one RPT, a device code mints one token set, a PAR request_uri authorises one authorization request.",
     "outOfScope": false,
     "threats": [
      {
       "number": 163,
       "title": "Concurrent redemption spends one credential twice",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "Two redemptions of the same credential arriving together can both observe it unspent and both succeed, yielding two RPTs from one authorization decision, two token sets from one user approval, or a replayable authorization request. RFC 8628 makes this the normal shape of the device flow rather than an exotic case: the device polls on a short interval, so a poll is usually already in flight when the user approves.",
       "mitigation": "Two independent layers, so a double redemption needs both to fail (ilpanich/axiam#302). The guarded UPDATE runs inside an explicit transaction, making two concurrent redemptions a write-write conflict the storage engine aborts the loser of; and a per-attempt nonce is read back in a separate query after that transaction commits, so a conflict the engine silently missed is still caught. The read-back stays outside the transaction deliberately — inside one, snapshot isolation shows every racer its own write. Measured with tools/surreal-race-probe: zero double redemptions in 40 000 contended attempts on surrealkv and 9 600 on rocksdb. Layer one is a property of the storage engine, so the guarantee is conditional on running a persistent one — see T-165. authorization_code.consume carries the same two layers as of schema v37 (T-164)."
      }
     ],
     "open": 0
    }
   ],
   "edges": [
    {
     "id": "985aff7b-0108-5462-b063-87c1af4b8f7f",
     "path": "M162.8,434 L395.3,194.3",
     "name": "authorize + consent",
     "description": "",
     "label": "authorize + consent (HTTPS)",
     "labelLines": [
      "authorize + consent (HTTPS)"
     ],
     "lx": 279,
     "ly": 314.1,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "ab8fabac-ca3c-59c1-8e47-4b4ff03ef429",
     "path": "M199,136.3 L374,141.8",
     "name": "authorization request",
     "description": "",
     "label": "authorization request (HTTPS)",
     "labelLines": [
      "authorization request (HTTPS)"
     ],
     "lx": 286.5,
     "ly": 139.1,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "7847cec2-07c0-5923-b9a6-35a1410b69de",
     "path": "M374,141.8 L199,136.3",
     "name": "redirect with code",
     "description": "",
     "label": "redirect with code (HTTPS)",
     "labelLines": [
      "redirect with code (HTTPS)"
     ],
     "lx": 286.5,
     "ly": 139.1,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [
      {
       "number": 62,
       "title": "Code leaked through the Referer header or browser history",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The authorization code travels in a URL, so it can leak to any third-party resource loaded by the redirect target.",
       "mitigation": "PKCE makes a leaked code unusable without the verifier; codes are single-use and short-lived; Referrer-Policy is set by the security-headers middleware."
      },
      {
       "number": 168,
       "title": "Authorization-server mix-up delivers an honest server's code to an attacker's token endpoint",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "A client configured against more than one authorization server receives an authorization response on a redirect URI shared between them. A bare code+state response names no sender, so an attacker controlling one of those servers can arrange for a code minted by an honest server to be redeemed at the attacker's token endpoint, or the reverse. The client's own state check does not help: the state is the client's, and it matches.",
       "mitigation": "X5.1 implements RFC 9207: every AXIAM authorization response carries an iss parameter naming the issuer, and discovery advertises authorization_response_iss_parameter_supported: true. Emitted for EVERY client regardless of profile and on the ERROR redirect as well as the success one — unconditionally, because mix-up is the attack a client does not know it is under, and because one variant works by injecting an error response, so a client validating iss on success and skipping it on failure has left ajar the door it just closed. Contract 1.15 §21.4 requires SDKs implementing the §12 relying-party flow to compare it against the issuer the flow began with. Residual risk sits with the relying party: a client that ignores the parameter gains nothing, which is why §21.4 is a SHOULD any SDK talking to multiple issuers should treat as a MUST."
      }
     ],
     "open": 0
    },
    {
     "id": "bb992b31-a584-539e-a48c-e7cbb26b33f5",
     "path": "M188,174 L384.6,296.9",
     "name": "code + verifier / client auth",
     "description": "",
     "label": "code + verifier / client auth (HTTPS)",
     "labelLines": [
      "code + verifier / client auth",
      "(HTTPS)"
     ],
     "lx": 286.3,
     "ly": 235.5,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "fa20de0f-8500-5d55-a768-70b1cfb2987a",
     "path": "M444,404 L444,464",
     "name": "verify challenge",
     "description": "",
     "label": "verify challenge (in-process)",
     "labelLines": [
      "verify challenge (in-process)"
     ],
     "lx": 444,
     "ly": 434,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "232715ea-ee5d-57b5-8c1e-bfaabae39c4a",
     "path": "M384.6,296.9 L188,174",
     "name": "access + id + refresh token",
     "description": "",
     "label": "access + id + refresh token (HTTPS)",
     "labelLines": [
      "access + id + refresh token (HTTPS)"
     ],
     "lx": 286.3,
     "ly": 235.5,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "1a62f5d9-a0d4-50c2-a610-db0dc2e62706",
     "path": "M124,174 L124,264",
     "name": "API call with bearer token",
     "description": "",
     "label": "API call with bearer token (HTTPS)",
     "labelLines": [
      "API call with bearer token (HTTPS)"
     ],
     "lx": 124,
     "ly": 219,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "62e50b82-a954-58e8-b662-e2b50c15a5c0",
     "path": "M199,307.9 L624.1,330.3",
     "name": "fetch JWKS / verify",
     "description": "",
     "label": "fetch JWKS / verify (HTTPS)",
     "labelLines": [
      "fetch JWKS / verify (HTTPS)"
     ],
     "lx": 411.5,
     "ly": 319.1,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "1fbe6fdf-fc66-538c-8304-b2133feec620",
     "path": "M199,282.9 L626.6,162.9",
     "name": "token introspection",
     "description": "",
     "label": "token introspection (HTTPS)",
     "labelLines": [
      "token introspection (HTTPS)"
     ],
     "lx": 412.8,
     "ly": 222.9,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "8c33029d-e874-5112-a604-a29d67a52fa7",
     "path": "M512.1,160.1 L1079,293.9",
     "name": "persist code + challenge",
     "description": "",
     "label": "persist code + challenge (SurrealQL)",
     "labelLines": [
      "persist code + challenge (SurrealQL)"
     ],
     "lx": 795.6,
     "ly": 227,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "90f05dc7-d368-5a66-bcfc-506dbe503b21",
     "path": "M514,332.1 L1079,316.4",
     "name": "redeem + delete code",
     "description": "",
     "label": "redeem + delete code (SurrealQL)",
     "labelLines": [
      "redeem + delete code (SurrealQL)"
     ],
     "lx": 796.5,
     "ly": 324.2,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "04c4bf40-9894-57ea-90bf-1a687467e58d",
     "path": "M512.7,347.4 L1079,457.5",
     "name": "store refresh token",
     "description": "",
     "label": "store refresh token (SurrealQL)",
     "labelLines": [
      "store refresh token (SurrealQL)"
     ],
     "lx": 795.9,
     "ly": 402.4,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "93dcf70e-d837-5cfa-b68d-86fddb92d85a",
     "path": "M511.9,317 L1079,175.3",
     "name": "verify client secret",
     "description": "",
     "label": "verify client secret (SurrealQL)",
     "labelLines": [
      "verify client secret (SurrealQL)"
     ],
     "lx": 795.5,
     "ly": 246.1,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "a7cd4b40-6136-5fc2-bcac-86f9dc87f4e8",
     "path": "M748.4,490 L1114.5,194",
     "name": "register / rotate",
     "description": "",
     "label": "register / rotate (SurrealQL)",
     "labelLines": [
      "register / rotate (SurrealQL)"
     ],
     "lx": 931.5,
     "ly": 342,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "7d7cfd30-662e-5161-8ad2-3473fc705b20",
     "path": "M753,371.7 L1101.3,594",
     "name": "read signing keys",
     "description": "",
     "label": "read signing keys (SurrealQL)",
     "labelLines": [
      "read signing keys (SurrealQL)"
     ],
     "lx": 927.2,
     "ly": 482.8,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "38d4ddc5-e88e-5e58-ab7a-05d4e8b6526e",
     "path": "M751.3,184.2 L1107,434",
     "name": "lookup token state",
     "description": "",
     "label": "lookup token state (SurrealQL)",
     "labelLines": [
      "lookup token state (SurrealQL)"
     ],
     "lx": 929.2,
     "ly": 309.1,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "73b64273-1551-5046-a08b-7b734c165fd3",
     "path": "M503,371.7 L1101.4,754",
     "name": "redeem ticket / device code",
     "description": "",
     "label": "redeem ticket / device code (SurrealQL)",
     "labelLines": [
      "redeem ticket / device code",
      "(SurrealQL)"
     ],
     "lx": 802.2,
     "ly": 562.8,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "a59b2622-0df1-5dd6-b209-92cd9dbdd180",
     "path": "M496,190.9 L1119.7,754",
     "name": "consume request_uri",
     "description": "",
     "label": "consume request_uri (SurrealQL)",
     "labelLines": [
      "consume request_uri (SurrealQL)"
     ],
     "lx": 807.8,
     "ly": 472.5,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    }
   ],
   "total": 18,
   "open": 0,
   "bySeverity": {
    "High": 10,
    "Medium": 6,
    "Critical": 1,
    "Low": 1
   }
  },
  {
   "id": 3,
   "title": "Federation — SAML SP & OIDC relying party",
   "description": "Inbound federation from external identity providers: OIDC discovery and code exchange, SAML assertion consumption, the shared SSRF guard on every outbound IdP fetch, and attribute-to-role mapping with JIT provisioning.",
   "width": 1438,
   "height": 808,
   "boundaries": [
    {
     "id": "a89fe874-1c88-526f-9ef4-378f7d6958a8",
     "x": 24,
     "y": 24,
     "w": 260,
     "h": 560,
     "label": "External identity providers"
    },
    {
     "id": "e0dd7f91-5669-50da-adf4-31576eadeead",
     "x": 324,
     "y": 24,
     "w": 660,
     "h": 760,
     "label": "AXIAM federation services"
    },
    {
     "id": "4915d4de-0462-5843-a09e-77c433fcf2ac",
     "x": 1034,
     "y": 84,
     "w": 380,
     "h": 620,
     "label": "Data tier"
    }
   ],
   "nodes": [
    {
     "id": "a9f8492b-162e-59a1-a0c2-4a20bc494f8e",
     "kind": "actor",
     "x": 49,
     "y": 94,
     "w": 150,
     "h": 80,
     "name": "External IdP (Entra, Okta, Keycloak…)",
     "lines": [
      "External IdP",
      "(Entra, Okta,",
      "Keycloak…)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 63,
       "title": "IdP key substitution via a hijacked jwks_uri",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "If jwks_uri can be redirected — DNS takeover, an unvalidated discovery document, or a stale cache — the attacker supplies their own signing key and every assertion validates.",
       "mitigation": "jwks_uri is validated and fetched only through guarded_fetch with https enforcement and IP pinning; the discovery document itself is fetched the same way. (The equivalent PHP SDK gap, SDK-19, is tracked in that SDK's own repository.)"
      }
     ],
     "open": 0
    },
    {
     "id": "31b120a0-2b7e-5174-a1a1-d2f04c2a6038",
     "kind": "actor",
     "x": 49,
     "y": 304,
     "w": 150,
     "h": 80,
     "name": "Federated user",
     "lines": [
      "Federated user"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 64,
       "title": "Account takeover through unverified email linking",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "Linking a federated identity to a local account purely on a matching email lets an IdP that does not verify email addresses claim any local account.",
       "mitigation": "Linking requires the IdP to assert email_verified, or an explicit administrator-configured linking policy per federation config; unverified matches create a distinct identity rather than merging."
      }
     ],
     "open": 0
    },
    {
     "id": "2d094b8d-06ff-58ab-8ed6-30c4beb86f98",
     "kind": "process",
     "x": 374,
     "y": 74,
     "w": 140,
     "h": 140,
     "name": "OIDC RP (discovery, code exchange)",
     "lines": [
      "OIDC RP",
      "(discovery,",
      "code",
      "exchange)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 65,
       "title": "IdP mix-up attack",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "With multiple IdPs configured, an attacker starts a flow at IdP A and delivers the response to the callback expecting IdP B, so a code from a weak IdP is redeemed against a trusted one.",
       "mitigation": "The federation config id is bound into the state value and checked on callback, and the issuer in the returned id_token must match the configuration that started the flow."
      },
      {
       "number": 66,
       "title": "Nonce or state omitted on callback",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "Without nonce binding, an id_token obtained elsewhere can be injected into a victim's session.",
       "mitigation": "state and nonce are both required, generated with a CSPRNG, stored server-side against the pending flow, and verified before any identity is established."
      },
      {
       "number": 155,
       "title": "A partner's token is accepted as an AXIAM credential (X4)",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "External-IdP token exchange (RFC 8693, X4) lets a client present a token minted by a partner's IdP and receive an AXIAM token. If the partner's assertions were trusted as authorization, the partner's administrator would be able to name AXIAM scopes and grant their own users authority in this tenant.",
       "mitigation": "An external subject token is treated as evidence of authentication only. The issued token's scopes are the intersection of an AXIAM-admin-authored deny-by-default scope_map, the exchanging client's registration, and the RBAC engine's answer for the resolved user at mint time (deny-override applied at its broadest reading). Trust is off by default per provider, and enabling it requires a non-empty accepted_audiences list."
      },
      {
       "number": 156,
       "title": "A token not addressed to AXIAM is replayed at the exchange (X4)",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "A token the partner minted for a third party — or for their own internal service — is captured and presented to AXIAM's token endpoint. Without an audience check, any token from the partner's estate becomes an AXIAM credential.",
       "mitigation": "accepted_audiences is required and non-empty whenever token exchange is enabled; there is deliberately no accept-all value. Matching is exact string equality in both directions (no trailing-slash forgiveness, no case folding), and aud may be a string or an array, of which at least one member must match."
      },
      {
       "number": 157,
       "title": "Trust composes transitively across three domains (X4)",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "AXIAM trusts partner B; B trusts partner C. Without a barrier, a token C minted can be exchanged at B and the result exchanged at AXIAM, giving C authority nobody configured and neither configuration reveals.",
       "mitigation": "Every token minted from an external subject token carries an ext_exchange provenance claim naming the foreign issuer, and BOTH exchange paths refuse a subject token that carries it. An exchanged token can never be re-exchanged, ours or theirs."
      },
      {
       "number": 158,
       "title": "A long-lived partner token becomes a long replay window (X4)",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A partner IdP that issues 24-hour access tokens would, without an independent bound, hand a captured token a 24-hour window in which it can be turned into AXIAM credentials.",
       "mitigation": "max_token_age_secs bounds the token's age independently of its own exp (default 300 s, hard ceiling 3600 s), and an iat in the future beyond 60 s of skew is refused. The issued token's lifetime is the minimum of the partner token's remaining life, the per-provider ceiling, and the server-wide exchange maximum."
      },
      {
       "number": 159,
       "title": "An ID token or refresh token is presented as a subject token (X4)",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "An ID token is an assertion to a client about a login, which an OIDC deployment distributes more widely and gives a longer life than an access token; a refresh token is a re-authentication credential. Either accepted as a subject token would let an artefact the partner considers low-risk buy an AXIAM credential.",
       "mitigation": "Both are refused by name at the subject_token_type check, and — since a caller can mislabel a token — again by shape: the ID-token-only claims nonce, at_hash, c_hash and s_hash, and typ headers or claims naming an ID or refresh token, are rejected even when the signature verifies."
      }
     ],
     "open": 0
    },
    {
     "id": "37936176-ed8c-5749-9a8d-fba8d8d8d736",
     "kind": "process",
     "x": 374,
     "y": 284,
     "w": 140,
     "h": 140,
     "name": "SAML SP (assertion consumer)",
     "lines": [
      "SAML SP",
      "(assertion",
      "consumer)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 67,
       "title": "XML signature wrapping",
       "type": "Tampering",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "A classic SAML attack: the attacker keeps a legitimately signed assertion but wraps it so the parser reads attacker-controlled content while the verifier checks the original signature.",
       "mitigation": "The signature is verified over the exact element that is then consumed — the same reference is used for validation and for attribute extraction — and multiple assertions or unreferenced elements are rejected outright."
      },
      {
       "number": 68,
       "title": "Assertion replay",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "A captured assertion is replayed within its validity window to establish a second session as the victim.",
       "mitigation": "Assertion IDs are recorded and refused on reuse; NotBefore and NotOnOrAfter are enforced with a small clock skew; the Recipient and Destination must match this SP."
      },
      {
       "number": 69,
       "title": "Unsigned or partially signed assertion accepted",
       "type": "Tampering",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "Accepting a response whose assertion is unsigned — or trusting a signed response wrapper without checking the assertion — makes every claim attacker-controlled.",
       "mitigation": "The SP fails closed: an assertion without a valid signature from the configured IdP certificate is rejected, and signature presence is not inferred from the response envelope."
      }
     ],
     "open": 0
    },
    {
     "id": "ec39c350-7067-521d-a682-8283e1487344",
     "kind": "process",
     "x": 374,
     "y": 514,
     "w": 140,
     "h": 140,
     "name": "SSRF guard resolve-and-pin (guarded_fetch)",
     "lines": [
      "SSRF guard",
      "resolve-and-pin",
      "(guarded_fetch)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 70,
       "title": "DNS rebinding between validation and connect",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "Validating the resolved address and then letting the HTTP client re-resolve at send time leaves a TOCTOU window in which the name flips to an internal address.",
       "mitigation": "D-01c: the guard resolves A and AAAA fresh, rejects private, loopback, link-local, ULA and unspecified results, and pins the validated IP for the actual connection so no second resolution happens."
      },
      {
       "number": 71,
       "title": "Oversized IdP response exhausts memory",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A hostile or compromised IdP returns a multi-gigabyte discovery or JWKS document and the fetch buffers it.",
       "mitigation": "SEC-069: the advertised Content-Length is checked against a maximum before the body is read, and the fetch is refused when it exceeds the cap."
      }
     ],
     "open": 0
    },
    {
     "id": "f4c8c207-b57d-5538-8320-11af50a2d6a6",
     "kind": "process",
     "x": 624,
     "y": 284,
     "w": 140,
     "h": 140,
     "name": "Attribute mapping & JIT provisioning",
     "lines": [
      "Attribute",
      "mapping",
      "& JIT",
      "provisioning"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 72,
       "title": "Role injection through attribute mapping",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "If IdP-supplied group or role attributes are mapped straight onto AXIAM roles, anyone who controls their own IdP attributes — or an IdP admin — can self-assign administrative roles.",
       "mitigation": "Mapping is an explicit, tenant-scoped allow-list configured by an AXIAM administrator; unmapped attributes are discarded, and mapped roles are constrained to the tenant of the federation config. Grant no privileged role through mapping unless the IdP is administratively equivalent to AXIAM."
      },
      {
       "number": 73,
       "title": "JIT provisioning inflates the user population",
       "type": "Denial of service",
       "severity": "Low",
       "status": "Mitigated",
       "description": "Unbounded just-in-time user creation from a federated IdP lets a hostile IdP create arbitrarily many tenant users.",
       "mitigation": "JIT provisioning is opt-in per federation config and the created users hold no roles beyond those the mapping allow-list grants."
      },
      {
       "number": 160,
       "title": "A suspended user is revived through the exchange path (X4)",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "An AXIAM user who has been locked, deactivated or anonymized would, if the exchange path skipped the status gate, still be able to obtain tokens for as long as their partner IdP kept authenticating them.",
       "mitigation": "The resolved user's status is checked after subject resolution and before any token is minted; Locked, Inactive and Anonymized are refused. PendingVerification is allowed deliberately: federation provisioning never moves a federated user off it, so requiring Active would refuse the whole population the feature serves while stopping nobody."
      },
      {
       "number": 161,
       "title": "A partner's IdP silently populates the AXIAM user table (X4)",
       "type": "Denial of service",
       "severity": "Low",
       "status": "Open",
       "description": "With subject_mapping set to jit_provision, every previously-unseen subject the partner vouches for creates an AXIAM user row. A partner with a large or hostile user population can grow the table without an AXIAM administrator acting.",
       "mitigation": "Off by default (linked_only refuses unknown subjects). Every JIT provision is audited with the provider and the external subject, and a provisioned user holds no roles, so the exchange that created them still yields no token. Residual risk accepted: the same exposure the browser SSO JIT path already carries, bounded by the same per-client exchange rate limit."
      }
     ],
     "open": 1
    },
    {
     "id": "24bff414-a751-52a6-bb4e-b0b187da2873",
     "kind": "store",
     "x": 1079,
     "y": 144,
     "w": 170,
     "h": 80,
     "name": "federation_config (encrypted secrets)",
     "lines": [
      "federation_config",
      "(encrypted secrets)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 74,
       "title": "Federation client secret disclosed via logs or Debug",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The OIDC client secret configured for an IdP is a credential against that IdP; leaking it in a trace line is a real third-party compromise.",
       "mitigation": "SECHRD-09: the federation secret type carries a manual Debug impl that redacts the value, and the secret is encrypted at rest. The same treatment was applied to webhook secrets under SEC-067."
      },
      {
       "number": 162,
       "title": "A malformed trust block is enabled without review (X4)",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A scope_map entry mapping to no scopes, an out-of-range token age, or an unknown subject_mapping value stored while token exchange is disabled becomes live the moment an administrator ticks the enable box — which is not where they expect to be told their configuration was wrong.",
       "mitigation": "The trust block is validated at the API edge on every write, whether or not it is enabled (only the non-empty-audience rule is conditional). On read, every hydration failure resolves towards the default, and enabled is read from its own column so a corrupt neighbouring column can never switch exchange on. A provider whose stored trust block fails validation is skipped at resolution time with a warning rather than being used."
      }
     ],
     "open": 0
    },
    {
     "id": "2e5acb1c-d395-5736-8d76-92e0d99b06de",
     "kind": "store",
     "x": 1079,
     "y": 324,
     "w": 170,
     "h": 80,
     "name": "JWKS / discovery cache",
     "lines": [
      "JWKS / discovery",
      "cache"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 75,
       "title": "Cache poisoning extends a compromised key's lifetime",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A JWKS entry fetched during a window of IdP compromise stays trusted for the whole cache lifetime even after the IdP rotates.",
       "mitigation": "Cache entries are bounded by a short TTL and are re-fetched through the same guarded path; an unknown kid forces an immediate refresh rather than a silent failure."
      }
     ],
     "open": 0
    },
    {
     "id": "26b9def1-178d-5611-b43a-75ec800c46ee",
     "kind": "store",
     "x": 1079,
     "y": 484,
     "w": 170,
     "h": 80,
     "name": "IdP signing certificates",
     "lines": [
      "IdP signing",
      "certificates"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 76,
       "title": "Expired or revoked IdP certificate still trusted",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A SAML IdP certificate left in place after rotation or revocation keeps validating assertions signed by a key the IdP no longer controls.",
       "mitigation": "Certificate validity is checked at assertion-verification time, not only at configuration time, and expiry raises an admin notification through the compliance notification category."
      }
     ],
     "open": 0
    }
   ],
   "edges": [
    {
     "id": "637d09aa-44ef-58f0-ae1f-1052d7521ce1",
     "path": "M188,304 L384.6,181.1",
     "name": "start federated login",
     "description": "",
     "label": "start federated login (HTTPS)",
     "labelLines": [
      "start federated login (HTTPS)"
     ],
     "lx": 286.3,
     "ly": 242.5,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "7e9584c7-4b8e-5c93-9835-c8a7ec6af35b",
     "path": "M374,141.8 L199,136.3",
     "name": "authorization request",
     "description": "",
     "label": "authorization request (HTTPS)",
     "labelLines": [
      "authorization request (HTTPS)"
     ],
     "lx": 286.5,
     "ly": 139.1,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "9e03e6e6-b9d0-5824-88e3-c725f288b339",
     "path": "M199,136.3 L374,141.8",
     "name": "code / id_token callback",
     "description": "",
     "label": "code / id_token callback (HTTPS)",
     "labelLines": [
      "code / id_token callback (HTTPS)"
     ],
     "lx": 286.5,
     "ly": 139.1,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "02f48d17-7444-5ab1-bff1-98ac686a404e",
     "path": "M182.2,174 L386.3,314.3",
     "name": "SAML response (POST binding)",
     "description": "",
     "label": "SAML response (POST binding) (HTTPS)",
     "labelLines": [
      "SAML response (POST binding) (HTTPS)"
     ],
     "lx": 284.2,
     "ly": 244.2,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [
      {
       "number": 77,
       "title": "Assertion readable in transit or in browser history",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "SAML assertions carry identity attributes and travel through the user's browser.",
       "mitigation": "HTTP-POST binding keeps the assertion out of the URL; TLS 1.3 protects it in transit; assertion encryption is supported where the IdP offers it."
      }
     ],
     "open": 0
    },
    {
     "id": "a2b6640b-3f26-5aa4-ba7e-fac7b9079c17",
     "path": "M444,214 L444,514",
     "name": "discovery / JWKS / token fetch",
     "description": "",
     "label": "discovery / JWKS / token fetch (in-process)",
     "labelLines": [
      "discovery / JWKS / token fetch",
      "(in-process)"
     ],
     "lx": 444,
     "ly": 364,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "db23722f-f9bb-5d54-97f2-ab42353cafa6",
     "path": "M444,424 L444,514",
     "name": "metadata fetch",
     "description": "",
     "label": "metadata fetch (in-process)",
     "labelLines": [
      "metadata fetch (in-process)"
     ],
     "lx": 444,
     "ly": 469,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "9a0e03b2-45b7-5021-984f-fb05cc62fa5a",
     "path": "M403.4,527 L152.4,174",
     "name": "guarded outbound fetch",
     "description": "",
     "label": "guarded outbound fetch (HTTPS (pinned IP))",
     "labelLines": [
      "guarded outbound fetch (HTTPS",
      "(pinned IP))"
     ],
     "lx": 277.9,
     "ly": 350.5,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS (pinned IP)",
     "threats": [],
     "open": 0
    },
    {
     "id": "aea86934-e8ce-57de-a373-fbe64e6486a8",
     "path": "M510.9,563.5 L1079,390",
     "name": "cache keys + discovery",
     "description": "",
     "label": "cache keys + discovery (in-process)",
     "labelLines": [
      "cache keys + discovery (in-process)"
     ],
     "lx": 795,
     "ly": 476.8,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "ac6ff234-22e1-5da9-89dc-c41b3595fc49",
     "path": "M497.6,189 L640.4,309",
     "name": "verified claims",
     "description": "",
     "label": "verified claims (in-process)",
     "labelLines": [
      "verified claims (in-process)"
     ],
     "lx": 569,
     "ly": 249,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "93a2fe06-54a3-5df7-aaae-9c38551267bf",
     "path": "M514,354 L624,354",
     "name": "verified attributes",
     "description": "",
     "label": "verified attributes (in-process)",
     "labelLines": [
      "verified attributes (in-process)"
     ],
     "lx": 569,
     "ly": 354,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "f457b6d9-d424-5ede-be01-de924ac41936",
     "path": "M759.8,330.2 L1079,214.7",
     "name": "read mapping allow-list",
     "description": "",
     "label": "read mapping allow-list (SurrealQL)",
     "labelLines": [
      "read mapping allow-list (SurrealQL)"
     ],
     "lx": 919.4,
     "ly": 272.5,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "5990d5fc-2789-5ed8-bf06-0429e0e58555",
     "path": "M512.1,370.1 L1079,503.9",
     "name": "read IdP certificate",
     "description": "",
     "label": "read IdP certificate (SurrealQL)",
     "labelLines": [
      "read IdP certificate (SurrealQL)"
     ],
     "lx": 795.6,
     "ly": 437,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    }
   ],
   "total": 23,
   "open": 1,
   "bySeverity": {
    "High": 7,
    "Medium": 10,
    "Critical": 4,
    "Low": 2
   }
  },
  {
   "id": 4,
   "title": "Authorization engine — RBAC, hierarchy & scopes",
   "description": "The three authorization entry points (REST middleware, gRPC CheckAccess, AMQP async), the additive allow-wins RBAC engine with resource-hierarchy traversal, the decision cache, and the graph and audit stores behind them.",
   "width": 1438,
   "height": 808,
   "boundaries": [
    {
     "id": "f4f92a7b-73a6-5c9f-adf8-1dc1b660cadd",
     "x": 24,
     "y": 24,
     "w": 260,
     "h": 620,
     "label": "Service mesh / calling workloads"
    },
    {
     "id": "91f9917b-5f48-57ac-8b12-f09adaf933ff",
     "x": 324,
     "y": 24,
     "w": 640,
     "h": 760,
     "label": "AXIAM authorization engine"
    },
    {
     "id": "03759639-f7eb-5085-8513-ce490ec59f2d",
     "x": 1014,
     "y": 84,
     "w": 400,
     "h": 620,
     "label": "Data tier"
    }
   ],
   "nodes": [
    {
     "id": "cc3bb1e7-e519-59be-8662-9b777137085b",
     "kind": "actor",
     "x": 49,
     "y": 94,
     "w": 150,
     "h": 80,
     "name": "Microservice / PEP",
     "lines": [
      "Microservice /",
      "PEP"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 78,
       "title": "Caller asserts a subject_id it does not own",
       "type": "Spoofing",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "CheckAccess takes subject_id as a parameter. A service account that can name any subject becomes a confused deputy and can enumerate or exercise anyone's entitlements.",
       "mitigation": "The gRPC interceptor authenticates the caller and derives the tenant from the verified JWT; a check for a subject outside the caller's tenant is refused. Grant the authz-check permission only to service accounts that are trusted policy enforcement points."
      }
     ],
     "open": 0
    },
    {
     "id": "e79cc991-c755-5476-a130-2a8c32a86e64",
     "kind": "actor",
     "x": 49,
     "y": 304,
     "w": 150,
     "h": 80,
     "name": "AMQP producer (deferred authz)",
     "lines": [
      "AMQP producer",
      "(deferred authz)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 79,
       "title": "Replay of a previously valid signed authz message",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "An HMAC alone proves origin and integrity but not freshness: a captured, correctly signed authz request or audit event can be republished indefinitely.",
       "mitigation": "CONTRACT §8 v2 (key_version = 2) binds a per-message nonce and an issued_at timestamp into the signed body. The server records (tenant_id, nonce) durably and rejects a duplicate within the freshness window, a stale or future issued_at, or any key_version below 2 — nack without requeue, no grace window."
      }
     ],
     "open": 0
    },
    {
     "id": "20764854-1aa7-566c-80f7-3df5d1770633",
     "kind": "actor",
     "x": 49,
     "y": 474,
     "w": 150,
     "h": 80,
     "name": "Tenant administrator",
     "lines": [
      "Tenant administrator"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 80,
       "title": "Privileged grant made without attribution",
       "type": "Repudiation",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "An administrator assigns a powerful role and later disputes it, or the change cannot be reconstructed during an incident.",
       "mitigation": "role.assigned and role.unassigned are audited with actor, target and resource, emitted as webhook events, and can raise an admin notification under the Access category."
      }
     ],
     "open": 0
    },
    {
     "id": "0d81f06f-8403-5b1c-a67d-0dd0e43a6750",
     "kind": "process",
     "x": 374,
     "y": 74,
     "w": 140,
     "h": 140,
     "name": "REST authz middleware",
     "lines": [
      "REST authz",
      "middleware"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 81,
       "title": "Endpoint reachable without an authorization check",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "A handler registered outside the guarded scope — or a new route added without its permission annotation — is reachable by any authenticated caller.",
       "mitigation": "Required permissions are declared centrally in the REST permissions table rather than ad hoc per handler, and the middleware default is deny; a route with no declared permission is refused rather than allowed."
      }
     ],
     "open": 0
    },
    {
     "id": "31ac62b4-23bd-5e5e-bb0a-c15534a3ee67",
     "kind": "process",
     "x": 374,
     "y": 264,
     "w": 140,
     "h": 140,
     "name": "gRPC CheckAccess / BatchCheckAccess",
     "lines": [
      "gRPC",
      "CheckAccess",
      "/",
      "BatchCheckAccess"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 82,
       "title": "Batch check used as an entitlement oracle",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "BatchCheckAccess answers many questions per call, so a caller can map another subject's complete entitlement surface cheaply.",
       "mitigation": "Batch size is bounded, the caller is authenticated and tenant-scoped, and gRPC rate limiting applies per caller."
      },
      {
       "number": 83,
       "title": "Batch amplification as a denial-of-service vector",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "One request expanding into thousands of graph traversals amplifies a modest request rate into heavy datastore load.",
       "mitigation": "Batch size limits, per-caller rate limiting and the decision cache bound the work a single caller can induce."
      }
     ],
     "open": 0
    },
    {
     "id": "ef218dd1-6a4f-5171-af2d-010a9bf7ebcc",
     "kind": "process",
     "x": 374,
     "y": 454,
     "w": 140,
     "h": 140,
     "name": "AMQP async authz consumer",
     "lines": [
      "AMQP async",
      "authz",
      "consumer"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 84,
       "title": "Decision response delivered to the wrong reply queue",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "If the reply-to address is taken from the message without checks, a producer can direct another tenant's decision to a queue it controls.",
       "mitigation": "Responses are correlated by the signed correlation id and published to the configured response queue; the decision is tenant-scoped to the verified producer identity."
      }
     ],
     "open": 0
    },
    {
     "id": "4d799b4c-16c2-598d-9e74-a9e7758e6f93",
     "kind": "process",
     "x": 624,
     "y": 264,
     "w": 140,
     "h": 140,
     "name": "RBAC engine (graph traversal, hierarchy, scopes)",
     "lines": [
      "RBAC engine",
      "(graph",
      "traversal,",
      "hierarchy,",
      "scopes)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 85,
       "title": "Cross-tenant graph edge traversed during resolution",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "Permission resolution walks has_role, member_of, grants, on_resource and child_of edges. An edge that crosses tenants — however it was created — would grant access across the isolation boundary.",
       "mitigation": "Traversal results are filtered to the caller's tenant and cross-tenant edges are stripped rather than followed (CQ-B07 / CQ-B50 / CQ-B52)."
      },
      {
       "number": 86,
       "title": "Deep or cyclic resource hierarchy stalls resolution",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Ancestor walking on a deliberately deep — or cyclic — resource tree turns a single check into an expensive traversal.",
       "mitigation": "Traversal depth is bounded and visited nodes are tracked so a cycle terminates; the decision cache absorbs repeated checks on the same subject/resource pair."
      },
      {
       "number": 87,
       "title": "No deny-override in the additive cascade",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Open",
       "description": "The engine is allow-wins with default deny and no explicit deny. A role granted on a parent resource cascades to every child and cannot be revoked on one child alone.",
       "mitigation": "SEC-040, accepted for v1.0-beta and documented in the design document. Deny-override cascade is deferred to post-v1.0-beta. Model exclusions by granting lower in the hierarchy instead of granting high and excluding."
      }
     ],
     "open": 1
    },
    {
     "id": "cb90bd7e-3fb9-5083-b48b-28b85d9208fa",
     "kind": "process",
     "x": 624,
     "y": 484,
     "w": 140,
     "h": 140,
     "name": "Decision cache",
     "lines": [
      "Decision",
      "cache"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 88,
       "title": "Stale allow served after revocation",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "A cached allow decision keeps granting access after the role or group membership behind it has been removed.",
       "mitigation": "Cache entries carry a short TTL and are invalidated on the mutations that can change a decision (role assignment, group membership, resource re-parenting). The residual exposure is bounded by the TTL and is documented in the decision-cache design note."
      },
      {
       "number": 89,
       "title": "Cache key collision leaks a decision across subjects",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "A key that omits tenant, subject, action, resource or scope would return one subject's decision to another.",
       "mitigation": "The cache key includes every input to the decision — tenant, subject, action, resource and scopes — so distinct questions cannot collide."
      }
     ],
     "open": 0
    },
    {
     "id": "a2cfad41-880d-59f4-838a-a6616c8ecd30",
     "kind": "store",
     "x": 1059,
     "y": 144,
     "w": 170,
     "h": 80,
     "name": "role / permission / resource graph",
     "lines": [
      "role / permission /",
      "resource graph"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 90,
       "title": "Direct edge insertion grants privilege silently",
       "type": "Tampering",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "Writing a has_role or grants edge straight into the datastore confers privilege without passing any API authorization check and without an audit record.",
       "mitigation": "Datastore access is restricted to the service credentials on the private data tier; all supported mutation paths go through the API and are audited. Datastore-level access must be treated as equivalent to full administrative compromise."
      }
     ],
     "open": 0
    },
    {
     "id": "44f386cf-7043-5b1c-b947-6b6a7540772a",
     "kind": "store",
     "x": 1059,
     "y": 324,
     "w": 170,
     "h": 80,
     "name": "session / token state",
     "lines": [
      "session / token",
      "state"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [],
     "open": 0
    },
    {
     "id": "cb57e62c-3f96-5aa3-b50c-3bd2c828b118",
     "kind": "store",
     "x": 1059,
     "y": 484,
     "w": 170,
     "h": 80,
     "name": "audit_log (decisions & changes)",
     "lines": [
      "audit_log",
      "(decisions & changes)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 91,
       "title": "Denied decisions not recorded",
       "type": "Repudiation",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Without a record of denials there is no signal for probing or privilege-escalation attempts during an investigation.",
       "mitigation": "Authorization outcomes are written with an explicit outcome field covering both allow and deny, so denial patterns are queryable and can drive the security notification category."
      }
     ],
     "open": 0
    }
   ],
   "edges": [
    {
     "id": "29d9e5a8-6c55-5c88-8f8a-caed25b7073d",
     "path": "M188,174 L384.6,296.9",
     "name": "CheckAccess",
     "description": "",
     "label": "CheckAccess (gRPC/TLS)",
     "labelLines": [
      "CheckAccess (gRPC/TLS)"
     ],
     "lx": 286.3,
     "ly": 235.5,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "gRPC/TLS",
     "threats": [],
     "open": 0
    },
    {
     "id": "53cc3c52-75f1-559a-a713-8b97d5ea9332",
     "path": "M195.1,384 L383,489.7",
     "name": "authz.request",
     "description": "",
     "label": "authz.request (AMQPS)",
     "labelLines": [
      "authz.request (AMQPS)"
     ],
     "lx": 289.1,
     "ly": 436.8,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "AMQPS",
     "threats": [
      {
       "number": 92,
       "title": "Request tampered in flight on the broker",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "A party with broker access modifies subject, action or resource between publish and consume.",
       "mitigation": "Messages carry an HMAC signature over the payload that the consumer verifies before evaluating; AMQPS protects the transport."
      }
     ],
     "open": 0
    },
    {
     "id": "a2d81dca-d3f3-53bb-b696-e51d0a92ac14",
     "path": "M158.6,474 L398.2,196.9",
     "name": "role / resource administration",
     "description": "",
     "label": "role / resource administration (HTTPS)",
     "labelLines": [
      "role / resource administration",
      "(HTTPS)"
     ],
     "lx": 278.4,
     "ly": 335.5,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "fc5d73bb-d929-5905-96ba-9a777aefe5c1",
     "path": "M499.7,186.4 L638.3,291.6",
     "name": "permission check",
     "description": "",
     "label": "permission check (in-process)",
     "labelLines": [
      "permission check (in-process)"
     ],
     "lx": 569,
     "ly": 239,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "292fc454-d584-5526-bbb1-7f2d77cd0d06",
     "path": "M514,334 L624,334",
     "name": "permission check",
     "description": "",
     "label": "permission check (in-process)",
     "labelLines": [
      "permission check (in-process)"
     ],
     "lx": 569,
     "ly": 334,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "c532668f-3e45-5825-8b43-046479f6df36",
     "path": "M499.7,481.6 L638.3,376.4",
     "name": "permission check",
     "description": "",
     "label": "permission check (in-process)",
     "labelLines": [
      "permission check (in-process)"
     ],
     "lx": 569,
     "ly": 429,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "60d1b5b0-9381-5b9d-a279-370c8a37411a",
     "path": "M694,404 L694,484",
     "name": "lookup / populate",
     "description": "",
     "label": "lookup / populate (in-process)",
     "labelLines": [
      "lookup / populate (in-process)"
     ],
     "lx": 694,
     "ly": 444,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "b6241bb8-e374-585f-957f-d16fc9460758",
     "path": "M760.4,311.9 L1059,212.3",
     "name": "graph traversal",
     "description": "",
     "label": "graph traversal (SurrealQL)",
     "labelLines": [
      "graph traversal (SurrealQL)"
     ],
     "lx": 909.7,
     "ly": 262.1,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "4e2428c7-82ec-5cfb-ac98-c9f4bb393d7e",
     "path": "M510.8,165 L1059,337.3",
     "name": "validate session",
     "description": "",
     "label": "validate session (SurrealQL)",
     "labelLines": [
      "validate session (SurrealQL)"
     ],
     "lx": 784.9,
     "ly": 251.1,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "359cbb76-fafc-5a7c-95a9-2bff25b576a2",
     "path": "M758.5,361.2 L1059,488.1",
     "name": "record decision",
     "description": "",
     "label": "record decision (SurrealQL)",
     "labelLines": [
      "record decision (SurrealQL)"
     ],
     "lx": 908.7,
     "ly": 424.7,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "71648efe-c997-5933-bcc3-31d76d7ca466",
     "path": "M383,489.7 L195.1,384",
     "name": "authz.response",
     "description": "",
     "label": "authz.response (AMQPS)",
     "labelLines": [
      "authz.response (AMQPS)"
     ],
     "lx": 289.1,
     "ly": 436.8,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "AMQPS",
     "threats": [],
     "open": 0
    }
   ],
   "total": 15,
   "open": 1,
   "bySeverity": {
    "Critical": 4,
    "High": 4,
    "Medium": 7
   }
  },
  {
   "id": 5,
   "title": "PKI, certificates & IoT device identity",
   "description": "Organization CA lifecycle, tenant certificate issuance with policy enforcement, mTLS device and workload authentication with full chain verification, revocation and CRL, and the OpenPGP key service used for audit signing and GDPR export encryption. Extended for X3 with FIDO MDS3 metadata ingestion (BLOB trust-chain verification, rollback protection, staleness posture) feeding the WebAuthn attestation policy engine.",
   "width": 1438,
   "height": 828,
   "boundaries": [
    {
     "id": "247fb050-0c6a-578e-a10f-536ea7baf860",
     "x": 24,
     "y": 24,
     "w": 260,
     "h": 620,
     "label": "Devices & administrators"
    },
    {
     "id": "5809e0c5-8d28-5b67-94c2-ef1f6e9ccd14",
     "x": 324,
     "y": 24,
     "w": 640,
     "h": 760,
     "label": "AXIAM PKI services"
    },
    {
     "id": "2102c103-ecc0-542b-865d-24a4254e24d8",
     "x": 1014,
     "y": 84,
     "w": 400,
     "h": 620,
     "label": "Data tier"
    }
   ],
   "nodes": [
    {
     "id": "9d0977bf-a651-5f95-9dfa-26ebfdf1e590",
     "kind": "actor",
     "x": 49,
     "y": 94,
     "w": 150,
     "h": 80,
     "name": "Organization administrator",
     "lines": [
      "Organization",
      "administrator"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 93,
       "title": "CA generation or import without effective authorization",
       "type": "Spoofing",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "Whoever can create or import an organization CA controls the root of trust for every tenant beneath it and can mint identities at will.",
       "mitigation": "CA operations are organization-scoped and require an organization-level administrative permission; every operation is audited and raises an admin notification."
      }
     ],
     "open": 0
    },
    {
     "id": "81a1ec38-73fb-580b-980b-5f7376093125",
     "kind": "actor",
     "x": 49,
     "y": 284,
     "w": 150,
     "h": 80,
     "name": "IoT device",
     "lines": [
      "IoT device"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 94,
       "title": "Key extracted from device firmware or flash",
       "type": "Spoofing",
       "severity": "High",
       "status": "Open",
       "description": "A physically accessible device may yield its private key from unprotected flash, allowing an indefinite clone until the certificate is revoked.",
       "mitigation": "Outside AXIAM's control: private keys are generated for the device and returned once, never stored server-side, but hardware protection is the integrator's responsibility. AXIAM limits the blast radius with per-device certificates, a maximum validity policy and immediate revocation."
      }
     ],
     "open": 1
    },
    {
     "id": "1014a143-dacc-51c3-ba15-48d93d55c6ba",
     "kind": "actor",
     "x": 49,
     "y": 464,
     "w": 150,
     "h": 80,
     "name": "Service / workload (mTLS client)",
     "lines": [
      "Service / workload",
      "(mTLS client)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [],
     "open": 0
    },
    {
     "id": "0c72c6c7-3a13-591f-b51f-c7db336ebbc0",
     "kind": "process",
     "x": 374,
     "y": 74,
     "w": 140,
     "h": 140,
     "name": "CA management (generate / upload / rotate)",
     "lines": [
      "CA",
      "management",
      "(generate /",
      "upload /",
      "rotate)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 95,
       "title": "CA private key exfiltration",
       "type": "Information disclosure",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "The signing CA key allows forging any tenant, user, service or device identity in the organization.",
       "mitigation": "User-generated CAs are returned once and never stored. Only signing CAs whose key AXIAM must hold are persisted, and those are AES-256-GCM encrypted at rest in a separate, access-controlled table with the key held outside the datastore."
      },
      {
       "number": 96,
       "title": "Weak key material from poor entropy",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "A CA or leaf key generated from a weak source is factorable or predictable, silently invalidating the whole hierarchy.",
       "mitigation": "Key generation uses the platform CSPRNG through rcgen with RSA-4096 or Ed25519; no custom or seeded RNG is used anywhere in the PKI path."
      }
     ],
     "open": 0
    },
    {
     "id": "eb80874d-646f-5abc-ac17-db54f759c1e3",
     "kind": "process",
     "x": 374,
     "y": 284,
     "w": 140,
     "h": 140,
     "name": "Certificate issuance (rcgen, policy enforcement)",
     "lines": [
      "Certificate",
      "issuance",
      "(rcgen,",
      "policy",
      "enforcement)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 97,
       "title": "Certificate issued beyond the tenant's validity policy",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "An over-long certificate outlives the review cycle and cannot be retired without an explicit revocation.",
       "mitigation": "max_certificate_validity_days is an org/tenant setting, and the hierarchical settings rule means a tenant can only make it stricter, never longer, than the organization baseline."
      },
      {
       "number": 98,
       "title": "Certificate issued for another tenant's subject",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "Issuing under a subject belonging to a different tenant would produce a credential that authenticates across the isolation boundary.",
       "mitigation": "Issuance is tenant-scoped from the authenticated context, and the signing CA is resolved from the requesting tenant's organization — a cross-tenant subject cannot be signed."
      },
      {
       "number": 99,
       "title": "Returned private key persisted in logs or audit records",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "The generated private key is returned once in the API response; if it reaches a log line or an audit payload it becomes durably stored in the clear.",
       "mitigation": "Key material is excluded from audit payloads, and secret-bearing types carry manual Debug implementations so they cannot reach a trace or error line (SEC-067 / SECHRD-09)."
      }
     ],
     "open": 0
    },
    {
     "id": "54f0ec8e-f431-57a9-934c-f48ff965061b",
     "kind": "process",
     "x": 374,
     "y": 504,
     "w": 140,
     "h": 140,
     "name": "mTLS device auth (fingerprint + chain verify)",
     "lines": [
      "mTLS device",
      "auth",
      "(fingerprint",
      "+",
      "chain",
      "verify)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 100,
       "title": "Fingerprint match accepted without chain verification",
       "type": "Spoofing",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "Authenticating on a stored SHA-256 fingerprint alone lets any certificate whose fingerprint was registered — by any means — authenticate as that device.",
       "mitigation": "SEC-024: after the fingerprint lookup the client certificate is cryptographically verified against the CA returned by the CA repository, and the call fails closed when no active CA exists."
      },
      {
       "number": 101,
       "title": "Expired certificate still accepted",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Skipping validity-period checks lets a retired device certificate keep working indefinitely.",
       "mitigation": "not_before and not_after are enforced at authentication time against the current clock, in addition to the stored status."
      }
     ],
     "open": 0
    },
    {
     "id": "9a80f354-ab85-50c6-8405-8a91a50e9681",
     "kind": "process",
     "x": 624,
     "y": 284,
     "w": 140,
     "h": 140,
     "name": "Revocation & CRL",
     "lines": [
      "Revocation",
      "& CRL"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 102,
       "title": "Revoked certificate honoured until the CRL refreshes",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "If relying parties depend only on a periodically published CRL, a revoked device keeps authenticating for the refresh interval.",
       "mitigation": "AXIAM checks certificate status in its own store on every mTLS authentication, so revocation takes effect immediately for AXIAM-terminated connections. External relying parties consuming the CRL remain bound by its publication interval."
      }
     ],
     "open": 0
    },
    {
     "id": "522c5d92-8100-5357-8571-396a2b44ff19",
     "kind": "process",
     "x": 624,
     "y": 504,
     "w": 140,
     "h": 140,
     "name": "OpenPGP key service (audit signing, GDPR export)",
     "lines": [
      "OpenPGP key",
      "service",
      "(audit",
      "signing,",
      "GDPR",
      "export)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 103,
       "title": "Substituted PGP key invalidates audit tamper-evidence",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "If the audit-signing key can be replaced, an attacker can rewrite audit batches and re-sign them so verification still passes.",
       "mitigation": "PGP key management is tenant-scoped and administratively audited, key rotation is itself an audited event, and verification pins the key fingerprint recorded with the batch."
      }
     ],
     "open": 0
    },
    {
     "id": "e006e495-addb-55a7-bbdf-44b2df1c1882",
     "kind": "store",
     "x": 1059,
     "y": 144,
     "w": 170,
     "h": 80,
     "name": "ca_certificate (AES-256-GCM key)",
     "lines": [
      "ca_certificate",
      "(AES-256-GCM key)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [],
     "open": 0
    },
    {
     "id": "d96b65b5-6a1e-5f22-b54b-357e84d4dd27",
     "kind": "store",
     "x": 1059,
     "y": 324,
     "w": 170,
     "h": 80,
     "name": "certificate (public certs, fingerprints)",
     "lines": [
      "certificate",
      "(public certs,",
      "fingerprints)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 104,
       "title": "Certificate status flipped back to active",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "Editing a revoked certificate's status directly in the datastore silently restores a credential that was withdrawn.",
       "mitigation": "Status transitions go through the audited API path; direct datastore write access is restricted to the service credentials on the private data tier and is treated as full administrative compromise."
      }
     ],
     "open": 0
    },
    {
     "id": "94966cac-9ba7-5d7d-97e4-2e2890a69c29",
     "kind": "store",
     "x": 1059,
     "y": 484,
     "w": 170,
     "h": 80,
     "name": "PGP keys (public; private returned once)",
     "lines": [
      "PGP keys",
      "(public; private",
      "returned once)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [],
     "open": 0
    },
    {
     "id": "18ed2d20-aec6-5ddb-91e2-d348cb5405a2",
     "kind": "process",
     "x": 374,
     "y": 664,
     "w": 140,
     "h": 140,
     "name": "FIDO MDS3 ingestion (BLOB verify, X3)",
     "lines": [
      "FIDO MDS3",
      "ingestion",
      "(BLOB",
      "verify, X3)"
     ],
     "description": "Fetches (or loads, air-gapped) the FIDO Alliance MDS3 BLOB, verifies its RS256 JWT signature chain against a digest-pinned vendored trust anchor, pins the leaf's SAN DNS identity, rejects a rollback to an older serial, and marks the result stale (never hard-fails) past nextUpdate.",
     "outOfScope": false,
     "threats": [
      {
       "number": 150,
       "title": "Public-CA root proves \"a GlobalSign EV customer\", not \"FIDO Alliance\"",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "GlobalSign Root CA - R3 is a public CA root sitting above the entire public web, not just the FIDO Alliance. Chain-verifying x5c up to that root alone is satisfied by any genuine end-entity certificate an attacker can obtain under the same public root, spliced beneath a self-minted leaf.",
       "mitigation": "The leaf must additionally carry the pinned hostname (mds.fidoalliance.org) as a SAN DNS entry (CN fallback only when no SAN extension exists), and every issuing position in the chain must be a real CA (basicConstraints CA=true, and keyCertSign when keyUsage is present) with pathLenConstraint enforced - closing the ordinary-end-entity-certificate splice that signature verification alone would miss (axiam-pki::mds::blob::assert_is_issuer)."
      },
      {
       "number": 151,
       "title": "Vendored trust anchor silently swapped for an attacker-controlled root",
       "type": "Tampering",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "The vendored root certificate is the root of trust for every attestation decision the policy engine makes; a swapped file would convert \"only FIDO-certified authenticators may register\" into \"any authenticator an attacker can mint an attestation chain for\", with no test failure and no error - just a bad key.",
       "mitigation": "The loader recomputes the SHA-256 of the vendored PEM's DER bytes against a pinned hex constant (FIDO_MDS_ROOT_SHA256_HEX) on every use and fails closed on any mismatch. Matching the digest is the check; the anchor is never re-fetched from anywhere at runtime. The documented update procedure requires updating the file and the pinned digest in the same reviewed commit."
      },
      {
       "number": 152,
       "title": "Older MDS BLOB replayed to reintroduce a since-revoked authenticator",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "A validly-signed but older BLOB (a captured earlier serial, or a compromised/rolled-back distribution point) could overwrite newer entries and quietly re-admit an authenticator model FIDO has since revoked or decertified.",
       "mitigation": "Ingestion compares the freshly-verified BLOB's serial (no) against the stored serial before replacing entries: a lower serial is rejected outright as a rollback, an equal serial only bumps last_refreshed_at, and only a strictly higher serial replaces stored entries (axiam_pki::mds::decide_ingest_outcome, applied by the axiam-db ingestion orchestrator)."
      },
      {
       "number": 153,
       "title": "Stale MDS metadata leaves a newly-revoked authenticator treated as compliant",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Open",
       "description": "A BLOB past its own nextUpdate date is deliberately not treated as a hard failure - ingestion still succeeds so a transient FIDO Alliance outage cannot brick registration - but this means an authenticator model FIDO has revoked or decertified since the last successful refresh keeps passing block_revoked_status / require_fido_certified / min_certification until the next successful refresh. Air-gapped deployments on AXIAM__PKI__MDS_BLOB_PATH have no automatic refresh path at all.",
       "mitigation": "Staleness is logged at WARN with the nextUpdate/now delta and surfaced on GET /api/v1/mds/status (stale: true); the weekly background job and the admin-triggered POST /api/v1/mds/refresh both re-attempt ingestion. No automated alert on sustained staleness ships yet, and air-gapped operators must re-supply the local BLOB file themselves - accepted as an operational responsibility rather than closed in-product; monitor stale and the refresh audit actions (mds.refreshed / mds.refresh_failed)."
      }
     ],
     "open": 1
    },
    {
     "id": "65a3b482-ded2-5ac6-9daf-0f2a8cdf3b51",
     "kind": "store",
     "x": 1059,
     "y": 584,
     "w": 170,
     "h": 80,
     "name": "mds_entry / mds_blob_meta (global, X3)",
     "lines": [
      "mds_entry /",
      "mds_blob_meta",
      "(global, X3)"
     ],
     "description": "Server-global (not tenant-scoped) tables holding parsed FIDO MDS3 entries keyed by AAGUID and the last-ingested BLOB's serial/nextUpdate/staleness - written only by the verified ingestion path, never directly.",
     "outOfScope": false,
     "threats": [
      {
       "number": 154,
       "title": "MDS entry status edited directly in the datastore to hide a revocation",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "Flipping a stored entry's status reports directly in the datastore would let an authenticator model FIDO has revoked keep passing block_revoked_status / require_fido_certified indefinitely, bypassing the policy engine entirely.",
       "mitigation": "Same posture as the certificate store (T-104): these tables are written only by the verified ingestion path (weekly refresh job or the admin-triggered refresh endpoint), which always re-derives entries from a BLOB that passed the full digest-pinned trust-chain verification. Direct datastore write access is restricted to the service credentials on the private data tier and is treated as full administrative compromise."
      }
     ],
     "open": 0
    }
   ],
   "edges": [
    {
     "id": "b4e1db45-9790-585c-b29b-9e315978e634",
     "path": "M199,136.3 L374,141.8",
     "name": "CA lifecycle operations",
     "description": "",
     "label": "CA lifecycle operations (HTTPS)",
     "labelLines": [
      "CA lifecycle operations (HTTPS)"
     ],
     "lx": 286.5,
     "ly": 139.1,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "fe2654d6-f234-534e-bc78-9fd1f942a090",
     "path": "M182.2,174 L386.3,314.3",
     "name": "request certificate",
     "description": "",
     "label": "request certificate (HTTPS)",
     "labelLines": [
      "request certificate (HTTPS)"
     ],
     "lx": 284.2,
     "ly": 244.2,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "074052f6-5d7b-5ed0-af33-7ae9cbb36dd5",
     "path": "M386.3,314.3 L182.2,174",
     "name": "certificate + private key (once)",
     "description": "",
     "label": "certificate + private key (once) (HTTPS)",
     "labelLines": [
      "certificate + private key (once)",
      "(HTTPS)"
     ],
     "lx": 284.2,
     "ly": 244.2,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [
      {
       "number": 105,
       "title": "Private key intercepted on its single delivery",
       "type": "Information disclosure",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "The generated private key crosses the network exactly once, in the issuance response; interception yields a complete, indefinitely usable identity.",
       "mitigation": "Delivery is over TLS 1.3 only, the key is never persisted server-side and is never repeated in any later response, and the issuance is audited so an unexpected issuance is visible."
      }
     ],
     "open": 0
    },
    {
     "id": "4e73667e-2731-541d-9997-73d7b8604655",
     "path": "M175.2,364 L388.8,530.9",
     "name": "client certificate handshake",
     "description": "",
     "label": "client certificate handshake (mTLS)",
     "labelLines": [
      "client certificate handshake (mTLS)"
     ],
     "lx": 282,
     "ly": 447.5,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "mTLS",
     "threats": [],
     "open": 0
    },
    {
     "id": "46138ad1-3469-549d-b5dc-f6261f66b945",
     "path": "M199,520.4 L375.6,559",
     "name": "workload certificate handshake",
     "description": "",
     "label": "workload certificate handshake (mTLS)",
     "labelLines": [
      "workload certificate handshake",
      "(mTLS)"
     ],
     "lx": 287.3,
     "ly": 539.7,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "mTLS",
     "threats": [],
     "open": 0
    },
    {
     "id": "3e5d300c-c3ee-594e-94e9-cbda2d6f43c1",
     "path": "M513.9,148 L1059,179.1",
     "name": "store encrypted CA key",
     "description": "",
     "label": "store encrypted CA key (SurrealQL)",
     "labelLines": [
      "store encrypted CA key (SurrealQL)"
     ],
     "lx": 786.4,
     "ly": 163.6,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "21fc4e9f-d560-5c66-99db-d0b31b9ef68c",
     "path": "M512,337.5 L1059,204.6",
     "name": "read signing CA",
     "description": "",
     "label": "read signing CA (SurrealQL)",
     "labelLines": [
      "read signing CA (SurrealQL)"
     ],
     "lx": 785.5,
     "ly": 271.1,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "6c597229-9ad6-5f68-af39-26c6475d902b",
     "path": "M514,355 L1059,362.8",
     "name": "persist public cert + fingerprint",
     "description": "",
     "label": "persist public cert + fingerprint (SurrealQL)",
     "labelLines": [
      "persist public cert + fingerprint",
      "(SurrealQL)"
     ],
     "lx": 786.5,
     "ly": 358.9,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "8b505f19-c48a-5847-83f0-3d7d581a06da",
     "path": "M511,553.9 L1059,389.5",
     "name": "fingerprint lookup + status",
     "description": "",
     "label": "fingerprint lookup + status (SurrealQL)",
     "labelLines": [
      "fingerprint lookup + status",
      "(SurrealQL)"
     ],
     "lx": 785,
     "ly": 471.7,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "47f7efa8-043f-5ccd-9f38-efd13cc7d374",
     "path": "M505.1,539.9 L1072.2,224",
     "name": "chain verification",
     "description": "",
     "label": "chain verification (SurrealQL)",
     "labelLines": [
      "chain verification (SurrealQL)"
     ],
     "lx": 788.7,
     "ly": 382,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "9586ec55-bcbd-57d9-8d6c-890721b9cee2",
     "path": "M764,355.6 L1059,362.1",
     "name": "mark revoked",
     "description": "",
     "label": "mark revoked (SurrealQL)",
     "labelLines": [
      "mark revoked (SurrealQL)"
     ],
     "lx": 911.5,
     "ly": 358.8,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "3780b9c2-45ab-5d9f-93c5-b7d4bc54d730",
     "path": "M763.6,566.3 L1059,533.4",
     "name": "read / write keys",
     "description": "",
     "label": "read / write keys (SurrealQL)",
     "labelLines": [
      "read / write keys (SurrealQL)"
     ],
     "lx": 911.3,
     "ly": 549.9,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "9c1d31a8-b76b-59b4-b344-92247caee2ab",
     "path": "M199,162.9 L628.7,328.8",
     "name": "revoke / rotate",
     "description": "",
     "label": "revoke / rotate (HTTPS)",
     "labelLines": [
      "revoke / rotate (HTTPS)"
     ],
     "lx": 413.8,
     "ly": 245.9,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "e86be81e-0435-5173-8f0c-c4dab7566d7d",
     "path": "M513.2,723.1 L1059,637.4",
     "name": "replace verified entries",
     "description": "",
     "label": "replace verified entries (SurrealQL)",
     "labelLines": [
      "replace verified entries (SurrealQL)"
     ],
     "lx": 786.1,
     "ly": 680.2,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    }
   ],
   "total": 18,
   "open": 2,
   "bySeverity": {
    "Critical": 6,
    "High": 9,
    "Medium": 3
   }
  },
  {
   "id": 6,
   "title": "Audit, webhooks, email & notifications",
   "description": "The append-only audit trail and its OpenPGP batch signing, webhook delivery with HMAC signatures and the SSRF guard, the pluggable email service and templates, and admin notification rules.",
   "width": 1438,
   "height": 848,
   "boundaries": [
    {
     "id": "c0d71a54-aac0-5a7f-84bf-d3ac20259104",
     "x": 324,
     "y": 24,
     "w": 660,
     "h": 800,
     "label": "AXIAM eventing & audit services"
    },
    {
     "id": "f95ee7e5-32b1-5775-a417-9b60c4d61955",
     "x": 24,
     "y": 24,
     "w": 260,
     "h": 700,
     "label": "External recipients"
    },
    {
     "id": "dd6f7815-56b0-5943-a6a5-eabc67e0b662",
     "x": 1034,
     "y": 84,
     "w": 380,
     "h": 660,
     "label": "Data tier"
    }
   ],
   "nodes": [
    {
     "id": "9e9d7e39-1cf5-5822-8506-0e1a5b5d780c",
     "kind": "actor",
     "x": 49,
     "y": 94,
     "w": 150,
     "h": 80,
     "name": "Webhook receiver (tenant endpoint)",
     "lines": [
      "Webhook receiver",
      "(tenant endpoint)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 106,
       "title": "Receiver accepts unverified deliveries",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A receiver that does not check the HMAC signature acts on any POST that reaches its URL, so knowledge of the URL alone is enough to drive downstream provisioning.",
       "mitigation": "Every delivery carries an HMAC-SHA256 signature over the payload with the per-endpoint secret; the SDK contract documents verification as mandatory on the receiving side."
      }
     ],
     "open": 0
    },
    {
     "id": "1baadc97-d0c0-5bd6-8dc9-29fee7fe5f3a",
     "kind": "actor",
     "x": 49,
     "y": 274,
     "w": 150,
     "h": 80,
     "name": "Mail recipient",
     "lines": [
      "Mail recipient"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [],
     "open": 0
    },
    {
     "id": "67f064a7-b520-5fcc-92a1-71dff9459724",
     "kind": "actor",
     "x": 49,
     "y": 444,
     "w": 150,
     "h": 80,
     "name": "Email provider",
     "lines": [
      "Email provider"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 107,
       "title": "Provider API key reused to send mail as the tenant",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A leaked SendGrid/Postmark/Resend/Brevo key lets an attacker send mail from the tenant's verified domain — ideal for phishing that passes SPF and DKIM.",
       "mitigation": "Provider credentials are encrypted at rest and redacted from Debug output; configuration changes are audited. Rotate keys on any suspicion and scope them to send-only."
      }
     ],
     "open": 0
    },
    {
     "id": "176a8db0-29b3-5da5-8dbf-101539a77419",
     "kind": "actor",
     "x": 49,
     "y": 604,
     "w": 150,
     "h": 80,
     "name": "Security administrator (notification subscriber)",
     "lines": [
      "Security",
      "administrator",
      "(notification",
      "subscriber)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [],
     "open": 0
    },
    {
     "id": "5c5402bf-0738-5484-b624-590047e0e6d3",
     "kind": "process",
     "x": 374,
     "y": 74,
     "w": 140,
     "h": 140,
     "name": "Audit middleware & service",
     "lines": [
      "Audit",
      "middleware",
      "& service"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 108,
       "title": "Action succeeds while its audit write fails",
       "type": "Repudiation",
       "severity": "High",
       "status": "Mitigated",
       "description": "If audit writes are best-effort, an attacker who can make the audit path fail — by exhausting the datastore or triggering a specific error — performs actions that leave no trace.",
       "mitigation": "Audit writes share the transactional path with the action they record where the datastore allows it, and audit failures are surfaced as errors and raise a compliance notification rather than being swallowed."
      },
      {
       "number": 109,
       "title": "Log injection through attacker-controlled fields",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Newlines or control characters in a username or resource name let an attacker forge additional log lines and mislead an investigation.",
       "mitigation": "Audit records are structured values persisted as fields, not formatted strings, so injected control characters cannot create a synthetic record."
      },
      {
       "number": 110,
       "title": "Personal data over-collected into an immutable log",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Open",
       "description": "The audit log is append-only by design, so any personal data written into it cannot later be erased — which is in direct tension with the GDPR Art. 17 erasure path AXIAM also offers.",
       "mitigation": "Partially addressed: audit metadata is deliberately minimised and erasure anonymises the subject rather than deleting audit records. Deployments must set an audit retention period consistent with their lawful basis; AXIAM does not enforce one today."
      }
     ],
     "open": 1
    },
    {
     "id": "564e10a1-ee60-5981-91af-b9a8d05a75fa",
     "kind": "process",
     "x": 374,
     "y": 294,
     "w": 140,
     "h": 140,
     "name": "Audit batch PGP signing",
     "lines": [
      "Audit batch",
      "PGP signing"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 111,
       "title": "Signing gap leaves a batch unattested",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "If a batch can be written and left unsigned without notice, tamper-evidence has a hole exactly where an attacker would want one.",
       "mitigation": "Signing failures raise a compliance admin notification rather than failing silently, so an unsigned batch is visible."
      }
     ],
     "open": 0
    },
    {
     "id": "1e6088d7-61e3-57c2-b772-39df74574e10",
     "kind": "process",
     "x": 374,
     "y": 504,
     "w": 140,
     "h": 140,
     "name": "Webhook delivery (HMAC + guarded_fetch + retry)",
     "lines": [
      "Webhook",
      "delivery",
      "(HMAC +",
      "guarded_fetch",
      "+ retry)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 112,
       "title": "Webhook URL used to reach internal services",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "A tenant administrator points a webhook at an internal or cloud metadata address and uses delivery success, latency or error detail as an internal scanner.",
       "mitigation": "Delivery uses the same resolve-and-pin guarded_fetch as federation: private, loopback, link-local, ULA and unspecified destinations are rejected before connect, https is enforced on every hop, and the response size is capped."
      },
      {
       "number": 113,
       "title": "Delivery replay by a party who captured one request",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "An HMAC over the body alone proves origin but not freshness, so a captured delivery could be replayed against the receiver indefinitely.",
       "mitigation": "D-10 / T-26-03-01: deliveries use the Stripe-style signed-timestamp scheme — HMAC-SHA256 over `<timestamp>.<body>` emitted as `X-Axiam-Signature: t=<unix>,v1=<hex>` alongside `X-Axiam-Timestamp`, so a forged or stale signature cannot be produced from the body alone. Receivers must enforce a freshness window on t and deduplicate on X-Axiam-Delivery."
      },
      {
       "number": 114,
       "title": "Retry storm against a slow endpoint",
       "type": "Denial of service",
       "severity": "Low",
       "status": "Mitigated",
       "description": "Aggressive retries against an unhealthy receiver amplify load on both AXIAM and the receiver.",
       "mitigation": "Retries use exponential backoff with a per-webhook configurable policy, concurrent deliveries are bounded, and each attempt is logged to the audit trail."
      }
     ],
     "open": 0
    },
    {
     "id": "da53123e-3f19-52d0-b83a-bf3515d6f6e1",
     "kind": "process",
     "x": 624,
     "y": 294,
     "w": 140,
     "h": 140,
     "name": "Email service (SMTP / provider API, templates)",
     "lines": [
      "Email",
      "service",
      "(SMTP /",
      "provider",
      "API,",
      "templates)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 115,
       "title": "Template injection through user-controlled placeholders",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Templates interpolate {{username}} and {{tenant_name}}. If a user-supplied value is treated as template source rather than data, it can execute template expressions during rendering.",
       "mitigation": "Values are passed as rendering context, never concatenated into the template body, and the template engine autoescapes output for the HTML variant."
      },
      {
       "number": 116,
       "title": "Header injection producing extra recipients",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "CR/LF in an address or subject field can inject additional SMTP headers and add hidden recipients.",
       "mitigation": "Addresses and headers are constructed through the typed lettre API, which rejects embedded control characters, rather than by string assembly."
      }
     ],
     "open": 0
    },
    {
     "id": "42999a33-a324-5b3c-baef-e2176cd7a52c",
     "kind": "process",
     "x": 624,
     "y": 504,
     "w": 140,
     "h": 140,
     "name": "Notification rules (admin alerts)",
     "lines": [
      "Notification",
      "rules",
      "(admin",
      "alerts)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 117,
       "title": "Alert flooding buries a real incident",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "An attacker triggers thousands of notifiable events so the genuine signal is lost among them, and burns the mail quota along the way.",
       "mitigation": "Notifications are delivered in configurable batches through the mail queue, and rules are per-category so a noisy category can be tuned without disabling the rest."
      }
     ],
     "open": 0
    },
    {
     "id": "54f8e397-5ae5-5288-b810-bc75e2af389d",
     "kind": "store",
     "x": 1079,
     "y": 144,
     "w": 170,
     "h": 80,
     "name": "audit_log (append-only, signed)",
     "lines": [
      "audit_log",
      "(append-only, signed)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 118,
       "title": "Audit trail deleted along with the tenant",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Open",
       "description": "Deleting a tenant removes its data; if audit records go with it, the evidence of what happened disappears exactly when it matters most.",
       "mitigation": "Not resolved in-product: retention of audit records past tenant deletion is a deployment decision that conflicts with GDPR erasure. Export audit records to an external WORM sink before deletion if your retention obligations require it."
      },
      {
       "number": 119,
       "title": "Unbounded audit growth degrades the datastore",
       "type": "Denial of service",
       "severity": "Low",
       "status": "Open",
       "description": "An append-only table with no retention policy grows without limit, eventually affecting query latency across the datastore.",
       "mitigation": "No retention or archival policy is enforced by AXIAM today. Operators should archive and prune on a schedule consistent with their compliance requirements."
      }
     ],
     "open": 2
    },
    {
     "id": "9883f81e-42c5-5275-81eb-22eeaa0782b9",
     "kind": "store",
     "x": 1079,
     "y": 324,
     "w": 170,
     "h": 80,
     "name": "webhook (HMAC secrets)",
     "lines": [
      "webhook",
      "(HMAC secrets)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 120,
       "title": "Webhook secret leaked through derived Debug output",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A derived Debug implementation on the webhook type prints the HMAC secret into any trace or error line that formats it.",
       "mitigation": "SEC-067: Webhook, CreateWebhook and the secret-rotation type all carry manual Debug implementations that redact the secret, mirroring the treatment already applied to federation secrets under SECHRD-09."
      }
     ],
     "open": 0
    },
    {
     "id": "b2654591-5a21-5db9-bfb5-75953efc9909",
     "kind": "store",
     "x": 1079,
     "y": 484,
     "w": 170,
     "h": 80,
     "name": "outbound mail queue (RabbitMQ)",
     "lines": [
      "outbound mail queue",
      "(RabbitMQ)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 121,
       "title": "Queued messages readable on the broker",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Outbound mail messages carry reset links and verification tokens; anyone able to read the queue can use them.",
       "mitigation": "Broker access is credentialed per service on the private network and AMQPS protects the transport; tokens are single-use and short-lived so a stale queued message has limited value."
      }
     ],
     "open": 0
    }
   ],
   "edges": [
    {
     "id": "c576baa2-cae2-5cfe-96f9-8ee2fedad7ec",
     "path": "M513.9,147.9 L1079,179.3",
     "name": "append audit record",
     "description": "",
     "label": "append audit record (SurrealQL)",
     "labelLines": [
      "append audit record (SurrealQL)"
     ],
     "lx": 796.4,
     "ly": 163.6,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "e671d12f-58a9-5a28-95ef-5ee1ddb25fcb",
     "path": "M444,214 L444,294",
     "name": "batch for signing",
     "description": "",
     "label": "batch for signing (in-process)",
     "labelLines": [
      "batch for signing (in-process)"
     ],
     "lx": 444,
     "ly": 254,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "e46b372a-dcb2-51bb-a440-992a3f5aca99",
     "path": "M511.9,347 L1079,205.3",
     "name": "store signature",
     "description": "",
     "label": "store signature (SurrealQL)",
     "labelLines": [
      "store signature (SurrealQL)"
     ],
     "lx": 795.5,
     "ly": 276.1,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "abc77d7a-19e3-5032-a223-94c60718fcf3",
     "path": "M479.2,204.5 L658.8,513.5",
     "name": "notifiable event",
     "description": "",
     "label": "notifiable event (in-process)",
     "labelLines": [
      "notifiable event (in-process)"
     ],
     "lx": 569,
     "ly": 359,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "fe72441b-2d67-5f36-b917-4dfac9a65d52",
     "path": "M511.2,554.4 L1079,388.8",
     "name": "read endpoint + secret",
     "description": "",
     "label": "read endpoint + secret (SurrealQL)",
     "labelLines": [
      "read endpoint + secret (SurrealQL)"
     ],
     "lx": 795.1,
     "ly": 471.6,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0
    },
    {
     "id": "8274ff45-69b2-5ca2-a5be-62e206704c39",
     "path": "M402.8,517.4 L153.1,174",
     "name": "event delivery",
     "description": "",
     "label": "event delivery (HTTPS + HMAC-SHA256)",
     "labelLines": [
      "event delivery (HTTPS + HMAC-SHA256)"
     ],
     "lx": 278,
     "ly": 345.7,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS + HMAC-SHA256",
     "threats": [
      {
       "number": 122,
       "title": "Event payload discloses more than the receiver needs",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Webhook payloads carry tenant context and event data across an organizational boundary to a customer-controlled endpoint.",
       "mitigation": "Payloads carry the event type, timestamp, tenant context and event-specific data only — never credentials, password hashes, MFA secrets or private keys."
      }
     ],
     "open": 0
    },
    {
     "id": "9fc1bed4-7a84-53e7-b32f-0cc37039913c",
     "path": "M763.6,566.6 L1079,533",
     "name": "enqueue notification",
     "description": "",
     "label": "enqueue notification (AMQPS)",
     "labelLines": [
      "enqueue notification (AMQPS)"
     ],
     "lx": 921.3,
     "ly": 549.8,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "AMQPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "39ea5288-689d-5b8d-a3e6-be87388164e4",
     "path": "M760.3,386.6 L1079,495.1",
     "name": "consume outbound mail",
     "description": "",
     "label": "consume outbound mail (AMQPS)",
     "labelLines": [
      "consume outbound mail (AMQPS)"
     ],
     "lx": 919.6,
     "ly": 440.8,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "AMQPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "a8792892-1209-587a-adb1-12de73bab6a2",
     "path": "M625.5,378.4 L199,468.2",
     "name": "send message",
     "description": "",
     "label": "send message (SMTP-TLS / HTTPS)",
     "labelLines": [
      "send message (SMTP-TLS / HTTPS)"
     ],
     "lx": 412.3,
     "ly": 423.3,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "SMTP-TLS / HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "1044da13-065c-5f8c-a94c-f2c2ccc5956d",
     "path": "M124,444 L124,354",
     "name": "deliver mail",
     "description": "",
     "label": "deliver mail (SMTP)",
     "labelLines": [
      "deliver mail (SMTP)"
     ],
     "lx": 124,
     "ly": 399,
     "bidirectional": false,
     "encrypted": false,
     "publicNetwork": true,
     "protocol": "SMTP",
     "threats": [
      {
       "number": 123,
       "title": "Final mail hop is not confidential",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Open",
       "description": "AXIAM enforces TLS to the provider, but the provider-to-recipient hop is outside its control and may be opportunistic or plaintext.",
       "mitigation": "Inherent to email. Bounded by making the tokens carried in mail single-use and short-lived, so interception has a narrow window. Deploy MTA-STS and DANE on the sending domain to harden the onward hops."
      }
     ],
     "open": 1
    },
    {
     "id": "e955fc76-7cef-5e3c-af0c-ac91b633f76a",
     "path": "M624.5,582.5 L199,634.8",
     "name": "security / compliance alert",
     "description": "",
     "label": "security / compliance alert (email)",
     "labelLines": [
      "security / compliance alert (email)"
     ],
     "lx": 411.8,
     "ly": 608.7,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "email",
     "threats": [],
     "open": 0
    }
   ],
   "total": 18,
   "open": 4,
   "bySeverity": {
    "Medium": 14,
    "High": 2,
    "Low": 2
   }
  },
  {
   "id": 7,
   "title": "Deployment & platform (Kubernetes)",
   "description": "Runtime and platform view: ingress, replicated AXIAM pods, scheduled jobs, monitoring, and the stateful tier — SurrealDB, RabbitMQ, Secrets and backups. Threats here are largely deployment responsibilities rather than application code.",
   "width": 1448,
   "height": 848,
   "boundaries": [
    {
     "id": "7ae3e87b-7c02-5ca4-b148-2ca6b13816b0",
     "x": 24,
     "y": 24,
     "w": 250,
     "h": 420,
     "label": "Public Internet"
    },
    {
     "id": "5f1e9c40-73cd-510b-9400-78f996c122fd",
     "x": 314,
     "y": 24,
     "w": 680,
     "h": 800,
     "label": "Kubernetes cluster"
    },
    {
     "id": "f6f220ca-3586-539e-8b7f-f3ba20e113cb",
     "x": 1044,
     "y": 64,
     "w": 380,
     "h": 720,
     "label": "Stateful tier (private network)"
    }
   ],
   "nodes": [
    {
     "id": "92f0ef3c-13e0-55a0-9167-e30bac958de9",
     "kind": "actor",
     "x": 49,
     "y": 94,
     "w": 150,
     "h": 80,
     "name": "Internet clients",
     "lines": [
      "Internet clients"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [],
     "open": 0
    },
    {
     "id": "4f10242a-8405-59a8-bb6a-366deb737eb3",
     "kind": "actor",
     "x": 49,
     "y": 264,
     "w": 150,
     "h": 80,
     "name": "Cluster operator / SRE",
     "lines": [
      "Cluster operator /",
      "SRE"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 124,
       "title": "Operator credentials grant unaudited data access",
       "type": "Spoofing",
       "severity": "High",
       "status": "Open",
       "description": "Anyone with kubectl exec or Secret-read rights in the namespace can read signing keys and datastore credentials, bypassing every application control without appearing in the AXIAM audit log.",
       "mitigation": "Outside the application boundary. Restrict RBAC on Secrets and exec, enable Kubernetes audit logging, and treat cluster-admin as equivalent to full AXIAM compromise in your threat register."
      }
     ],
     "open": 1
    },
    {
     "id": "fe65f1aa-1900-57d3-abb9-27b1b23182ba",
     "kind": "process",
     "x": 364,
     "y": 94,
     "w": 140,
     "h": 140,
     "name": "Ingress controller (TLS 1.3)",
     "lines": [
      "Ingress",
      "controller",
      "(TLS 1.3)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 125,
       "title": "Traffic reaches pods bypassing the ingress",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Open",
       "description": "Without a NetworkPolicy, any workload in the cluster can call the AXIAM Service directly and skip the ingress, along with any edge protections applied there.",
       "mitigation": "AXIAM's own authn/authz still applies on every request, so this is defence-in-depth rather than a bypass of access control. The shipped k8s manifests do not include NetworkPolicies; add default-deny ingress and egress policies for the namespace."
      }
     ],
     "open": 1
    },
    {
     "id": "76ca990a-d1c4-56fb-b323-38c6185a8aa0",
     "kind": "process",
     "x": 364,
     "y": 304,
     "w": 140,
     "h": 140,
     "name": "AXIAM deployment (N replicas, HPA)",
     "lines": [
      "AXIAM",
      "deployment",
      "(N",
      "replicas,",
      "HPA)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 126,
       "title": "Container escape from an over-privileged pod",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "A pod running as root with a writable filesystem turns a process-level bug into a node-level compromise.",
       "mitigation": "The image runs as a non-root user with a read-only root filesystem and no additional capabilities. Apply a restricted PodSecurity standard to the namespace to enforce this at admission."
      },
      {
       "number": 127,
       "title": "Vulnerable dependency reaches production",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "A transitive Rust or npm dependency with a known advisory ships in the image without anyone noticing.",
       "mitigation": "CI runs cargo-audit, cargo-deny (advisories, licences, bans, sources) and npm audit at a high threshold, uploads SARIF, and Dependabot covers cargo, the frontend npm tree and GitHub Actions. Residual: the seven SDK repositories are scanned separately and are not covered by this repository's CI (CI-03)."
      }
     ],
     "open": 0
    },
    {
     "id": "d6917d9a-710b-50eb-82ff-1cb71c7fb7b4",
     "kind": "process",
     "x": 624,
     "y": 304,
     "w": 140,
     "h": 140,
     "name": "Prometheus / Grafana",
     "lines": [
      "Prometheus",
      "/",
      "Grafana"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 128,
       "title": "Metrics or traces disclose tenant identifiers",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "High-cardinality labels carrying usernames, tenant slugs or resource names turn a monitoring endpoint into a directory of the deployment.",
       "mitigation": "Metric labels are bounded to low-cardinality dimensions and carry no user or tenant identifiers; the metrics endpoint is not exposed through the ingress."
      }
     ],
     "open": 0
    },
    {
     "id": "c2101ddc-09ed-58e9-b978-160bf020d5f4",
     "kind": "process",
     "x": 624,
     "y": 94,
     "w": 140,
     "h": 140,
     "name": "Scheduled jobs (cert expiry, GDPR erasure, sweeps)",
     "lines": [
      "Scheduled",
      "jobs",
      "(cert",
      "expiry,",
      "GDPR",
      "erasure,",
      "sweeps)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 129,
       "title": "Erasure or expiry job silently stops running",
       "type": "Repudiation",
       "severity": "Medium",
       "status": "Open",
       "description": "The 30-day GDPR erasure grace period and certificate-expiry warnings depend on scheduled work. A job that fails quietly produces a compliance gap that nobody sees.",
       "mitigation": "Job failures are logged but AXIAM does not ship an alert on missed runs. Add a liveness alert on job completion in your monitoring stack."
      }
     ],
     "open": 1
    },
    {
     "id": "a57f6400-7f09-5560-8e08-3df64d296d56",
     "kind": "store",
     "x": 1089,
     "y": 124,
     "w": 170,
     "h": 80,
     "name": "SurrealDB StatefulSet (cluster)",
     "lines": [
      "SurrealDB StatefulSet",
      "(cluster)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 130,
       "title": "Datastore reachable without authentication",
       "type": "Information disclosure",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "SurrealDB exposed on a Service without credentials, or with default credentials, hands over every tenant's data.",
       "mitigation": "The datastore runs on the private tier with no ingress and credentialed, namespaced connections sourced from Kubernetes Secrets. Verify no LoadBalancer or NodePort Service is created for it in your environment."
      },
      {
       "number": 165,
       "title": "A non-persistent storage engine removes single-use arbitration",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "SurrealDB's in-memory datastore does not reliably arbitrate the write-write conflict that decides a contended single-use redemption. It is not failing to arbitrate — it aborts contended attempts at the same ~54% rate the persistent engines do, then occasionally misses, silently, with both callers receiving the pre-transition row. An operator who points AXIAM at `surreal start memory` gets a server that boots cleanly and admits a second redemption in roughly 1% of contended rounds, defeating the first layer of T-163 and T-164 from below. Both retain their redemption-nonce layer, which asks the engine for nothing, so this weakens the guarantee rather than removing it — but the nonce alone was measured leaking on that engine too (3 rounds in 1200), so it is not a substitute.",
       "mitigation": "The shipped deployments pin a persistent engine — all three compose files and k8s/surrealdb/statefulset.yml pass surrealkv: — and docs/deployment/README.md carries it as a MUST-level operator requirement. axiam-server attests the engine at startup and refuses a memory datastore unless AXIAM__DB__ALLOW_MEMORY_ENGINE=true; because SurrealDB 3.2.4 publishes no datastore identity over the wire, that attestation currently logs a WARN, and a unit test fails on the version bump that makes the name available. A CI gate re-runs tools/surreal-race-probe whenever Cargo.lock moves surrealdb, surrealdb-core or surrealkv, so a bump cannot remove the arbitration silently."
      }
     ],
     "open": 0
    },
    {
     "id": "289ece31-a7b9-5486-aec2-a84146f15695",
     "kind": "store",
     "x": 1089,
     "y": 304,
     "w": 170,
     "h": 80,
     "name": "RabbitMQ StatefulSet (cluster)",
     "lines": [
      "RabbitMQ StatefulSet",
      "(cluster)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 131,
       "title": "Default or shared broker credentials",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Open",
       "description": "A broker left on guest/guest, or with one credential shared by every service, lets any workload read authz decisions and audit events and publish forged ones.",
       "mitigation": "AXIAM verifies HMAC signatures on consumed messages, which limits forgery, but per-service broker credentials and vhost separation are a deployment responsibility and are not enforced by the shipped manifests."
      }
     ],
     "open": 1
    },
    {
     "id": "8fbbc2a9-a70f-513d-a1e0-ea9fdce2783b",
     "kind": "store",
     "x": 1089,
     "y": 484,
     "w": 170,
     "h": 80,
     "name": "Secrets / ConfigMap",
     "lines": [
      "Secrets / ConfigMap"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 132,
       "title": "Secret material placed in a ConfigMap or plain env var",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Open",
       "description": "ConfigMaps are not secret and environment variables appear in pod specs, crash dumps and debug output — a signing key or datastore password there is effectively public within the namespace.",
       "mitigation": "The layered configuration model reads secrets from Secrets rather than ConfigMaps, but nothing prevents an operator from supplying them as AXIAM_* environment variables. Prefer mounted Secret files, and enable etcd encryption at rest."
      }
     ],
     "open": 1
    },
    {
     "id": "78160ffe-cb3f-5dbb-8852-1142ff0d92aa",
     "kind": "store",
     "x": 1089,
     "y": 644,
     "w": 170,
     "h": 80,
     "name": "Backups / volume snapshots",
     "lines": [
      "Backups / volume",
      "snapshots"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 133,
       "title": "Backup media accessible outside the cluster",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Open",
       "description": "Backups contain everything the live datastore does, usually under weaker access control and longer retention.",
       "mitigation": "Not addressed by AXIAM. Encrypt backups at rest with a key separate from the cluster, restrict snapshot IAM, and include backup media in the same access review as the live data tier."
      }
     ],
     "open": 1
    }
   ],
   "edges": [
    {
     "id": "d03e0c11-6565-59aa-a3dc-61a961d15968",
     "path": "M199,141.3 L364.3,157.3",
     "name": "public traffic",
     "description": "",
     "label": "public traffic (HTTPS / gRPC-TLS)",
     "labelLines": [
      "public traffic (HTTPS / gRPC-TLS)"
     ],
     "lx": 281.7,
     "ly": 149.3,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS / gRPC-TLS",
     "threats": [],
     "open": 0
    },
    {
     "id": "39e44fbf-616d-5d6a-bef4-f851466a7e63",
     "path": "M434,234 L434,304",
     "name": "proxied requests",
     "description": "",
     "label": "proxied requests (HTTP/2)",
     "labelLines": [
      "proxied requests (HTTP/2)"
     ],
     "lx": 434,
     "ly": 269,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "HTTP/2",
     "threats": [],
     "open": 0
    },
    {
     "id": "ebc32a13-8d62-5858-91fb-c43a47ac2323",
     "path": "M199,320.9 L365.7,358.6",
     "name": "kubectl / cluster administration",
     "description": "",
     "label": "kubectl / cluster administration (K8s API (mTLS))",
     "labelLines": [
      "kubectl / cluster administration",
      "(K8s API (mTLS))"
     ],
     "lx": 282.4,
     "ly": 339.8,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "K8s API (mTLS)",
     "threats": [],
     "open": 0
    },
    {
     "id": "2b5937c4-d87f-513d-b6a3-1d9e9039a463",
     "path": "M501.3,354.9 L1089,188.1",
     "name": "datastore connections",
     "description": "",
     "label": "datastore connections (WSS)",
     "labelLines": [
      "datastore connections (WSS)"
     ],
     "lx": 795.2,
     "ly": 271.5,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "WSS",
     "threats": [],
     "open": 0
    },
    {
     "id": "87f2c267-f787-585a-a667-f9c6b09c1455",
     "path": "M503.9,371.2 L1089,347.4",
     "name": "publish / consume",
     "description": "",
     "label": "publish / consume (AMQPS)",
     "labelLines": [
      "publish / consume (AMQPS)"
     ],
     "lx": 796.5,
     "ly": 359.3,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "AMQPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "7e70d2f8-a563-5998-be7f-a3ca300d887f",
     "path": "M502.6,387.9 L1089,506.8",
     "name": "read configuration + keys",
     "description": "",
     "label": "read configuration + keys (K8s API / mounted files)",
     "labelLines": [
      "read configuration + keys (K8s API /",
      "mounted files)"
     ],
     "lx": 795.8,
     "ly": 447.3,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "K8s API / mounted files",
     "threats": [],
     "open": 0
    },
    {
     "id": "c04e31c5-a5d8-5fae-81a6-ea13b7828f92",
     "path": "M1174,204 L1174,644",
     "name": "scheduled backup",
     "description": "",
     "label": "scheduled backup (internal)",
     "labelLines": [
      "scheduled backup (internal)"
     ],
     "lx": 1174,
     "ly": 424,
     "bidirectional": false,
     "encrypted": false,
     "publicNetwork": false,
     "protocol": "internal",
     "threats": [
      {
       "number": 134,
       "title": "Backup stream unencrypted in transit",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Open",
       "description": "A backup written across the network without encryption exposes the entire datastore to anyone who can observe that path.",
       "mitigation": "Deployment responsibility: use an encrypted transport and server-side encryption on the backup target."
      }
     ],
     "open": 1
    },
    {
     "id": "71aed01c-8609-5e16-b6f2-0b9951854344",
     "path": "M504,374 L624,374",
     "name": "scrape metrics",
     "description": "",
     "label": "scrape metrics (HTTP (in-cluster))",
     "labelLines": [
      "scrape metrics (HTTP (in-cluster))"
     ],
     "lx": 564,
     "ly": 374,
     "bidirectional": false,
     "encrypted": false,
     "publicNetwork": false,
     "protocol": "HTTP (in-cluster)",
     "threats": [],
     "open": 0
    },
    {
     "id": "ec2f05ec-874a-5212-a811-524bafe15ee5",
     "path": "M764,164 L1089,164",
     "name": "sweeps and expiry processing",
     "description": "",
     "label": "sweeps and expiry processing (WSS)",
     "labelLines": [
      "sweeps and expiry processing (WSS)"
     ],
     "lx": 926.5,
     "ly": 164,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "WSS",
     "threats": [],
     "open": 0
    }
   ],
   "total": 12,
   "open": 7,
   "bySeverity": {
    "High": 8,
    "Medium": 3,
    "Critical": 1
   }
  },
  {
   "id": 8,
   "title": "Client SDKs & admin UI integration surface",
   "description": "The React admin UI and the seven client SDKs (Rust, TypeScript, Python, Java, C#, PHP, Go), which live in separate repositories and vendor CONTRACT.md, openapi.json and proto/ from here. Covers SDK transport and credential handling, token verification, AMQP HMAC consumption, webhook verification and package-distribution supply chain.",
   "width": 1448,
   "height": 798,
   "boundaries": [
    {
     "id": "6c158fa6-3e60-519f-b4de-8c9e906fce82",
     "x": 24,
     "y": 24,
     "w": 300,
     "h": 150,
     "label": "Public package registries"
    },
    {
     "id": "7459a3fc-6747-5457-beb9-ef66c6002ff9",
     "x": 24,
     "y": 214,
     "w": 300,
     "h": 560,
     "label": "Integrator-controlled environment"
    },
    {
     "id": "106280d9-0398-5633-8c99-dc47dcfa2ec8",
     "x": 374,
     "y": 24,
     "w": 620,
     "h": 750,
     "label": "AXIAM client libraries (separate repositories)"
    },
    {
     "id": "a21c7c02-f792-58c3-a294-6b581b85ce9a",
     "x": 1044,
     "y": 124,
     "w": 380,
     "h": 520,
     "label": "AXIAM server (this repository)"
    }
   ],
   "nodes": [
    {
     "id": "bec12df3-b228-5306-99ab-e35e703e9e01",
     "kind": "actor",
     "x": 59,
     "y": 264,
     "w": 150,
     "h": 80,
     "name": "Integrator / developer",
     "lines": [
      "Integrator /",
      "developer"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 135,
       "title": "Dependency-confusion or typosquatted SDK package",
       "type": "Spoofing",
       "severity": "High",
       "status": "Open",
       "description": "The SDKs are published to seven public registries (crates.io, npm, PyPI, Maven Central, NuGet, Packagist, Go modules). A typosquatted or hijacked package name delivers an attacker's code straight into an integrator's authentication path.",
       "mitigation": "Not fully controllable from this repository. Publish under reserved names, enable 2FA and trusted publishing on every registry, sign releases, and document the exact canonical package names in the SDK contract so integrators can verify what they installed."
      }
     ],
     "open": 1
    },
    {
     "id": "3a571b9d-2c58-5c8d-9ef9-dc00d6dc0c0b",
     "kind": "actor",
     "x": 59,
     "y": 424,
     "w": 150,
     "h": 80,
     "name": "Browser user (admin UI)",
     "lines": [
      "Browser user",
      "(admin UI)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 136,
       "title": "Stored XSS in the admin UI escalates to full tenant compromise",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "Script injected through a user-controlled field (username, resource name, metadata) executes in an administrator's session and can drive every privileged action the admin can perform.",
       "mitigation": "React escapes interpolated output by default, the security-headers middleware sets a Content-Security-Policy, and auth cookies are HttpOnly so injected script cannot read them directly. Avoid dangerouslySetInnerHTML anywhere in the admin UI."
      }
     ],
     "open": 0
    },
    {
     "id": "57fbe487-02b7-5a57-89aa-c1d59c0508a6",
     "kind": "process",
     "x": 414,
     "y": 64,
     "w": 140,
     "h": 140,
     "name": "React admin UI (Vite SPA)",
     "lines": [
      "React admin",
      "UI",
      "(Vite SPA)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 137,
       "title": "State-changing request forged from another origin",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "Cookie-based sessions mean a cross-origin form or fetch can drive privileged endpoints in the victim's browser.",
       "mitigation": "D-01: the CSRF middleware requires an X-CSRF-Token header matching the axiam_csrf cookie on every state-changing method, compared in constant time; cookies are SameSite; CORS allowed origins are explicit with strict defaults. CONTRACT §3 mirrors the same behaviour in the SDKs."
      },
      {
       "number": 138,
       "title": "Tokens placed in localStorage instead of cookies",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "Tokens in localStorage are readable by any script on the origin, so a single XSS becomes a durable credential theft.",
       "mitigation": "The browser flow uses the Secure/HttpOnly axiam_access and axiam_refresh cookies (D-05..D-09); the SPA never handles the raw token, and CONTRACT §4 requires SDKs in cookie mode to use a cookie jar rather than application-readable storage."
      }
     ],
     "open": 0
    },
    {
     "id": "478f32d2-ac93-5350-ade6-1f0a28f6401a",
     "kind": "process",
     "x": 414,
     "y": 294,
     "w": 140,
     "h": 140,
     "name": "SDK HTTP core (7 languages: rs/ts/py/java/cs/php/go)",
     "lines": [
      "SDK HTTP",
      "core",
      "(7",
      "languages:",
      "rs/ts/py/java/cs/php/go)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 139,
       "title": "Credentials or tokens printed by default formatting",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "A derived Debug/toString/repr on a client or config type prints the client secret or bearer token into the integrator's logs, where it is durably stored and widely readable.",
       "mitigation": "CONTRACT §7 mandates a Sensitive<T> wrapper for every secret field in every SDK, so the default formatting of a credential-bearing type is redacted — the same discipline applied server-side under SEC-067 / SECHRD-09."
      },
      {
       "number": 140,
       "title": "Concurrent refresh storms invalidate the token family",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Refresh tokens are single-use with rotation. Parallel requests that each notice expiry and refresh independently race, and all but one redeem a rotated token — which reads as theft and can invalidate the family.",
       "mitigation": "CONTRACT §9 requires a single-flight refresh guard: concurrent callers await one in-flight refresh rather than each issuing their own."
      },
      {
       "number": 141,
       "title": "Contract drift between server and SDKs",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The SDKs vendor copies of CONTRACT.md, openapi.json and proto/. If the server changes and the copies do not, an SDK can silently stop enforcing a control it believes it implements.",
       "mitigation": "CI enforces this repository as the single source of truth: the SDK OpenAPI Drift Gate rebuilds the server, exports a fresh spec and fails on any difference from sdks/openapi.json, and the buf gates lint the protos and block breaking changes."
      }
     ],
     "open": 0
    },
    {
     "id": "9df9cb23-1a5d-5fdf-9697-7e276681aa52",
     "kind": "process",
     "x": 414,
     "y": 524,
     "w": 140,
     "h": 140,
     "name": "SDK token verification (JWKS cache, iss/aud)",
     "lines": [
      "SDK token",
      "verification",
      "(JWKS",
      "cache,",
      "iss/aud)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 142,
       "title": "JWKS URI taken from discovery without validation",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "An SDK that follows jwks_uri straight out of an OIDC discovery document lets whoever controls that document substitute the signing key — or point the fetch at an internal address (finding SDK-19, first seen in the PHP SDK).",
       "mitigation": "CONTRACT §12 requires the relying-party helpers to validate the discovery document and constrain jwks_uri to the configured issuer's origin before fetching, mirroring the server-side guarded_fetch discipline. Per-SDK conformance is verified in each SDK repository."
      },
      {
       "number": 143,
       "title": "Local JWT verification misses a revoked entitlement",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Open",
       "description": "An SDK that verifies the access token locally cannot see a role removal or account disable until the token expires — the client-side face of the stateless-verification trade-off recorded on the token service.",
       "mitigation": "Bounded by the 15-minute access-token lifetime. CONTRACT §10 and §11 expose route-guard and declarative-authorization helpers; integrations needing immediate revocation should call gRPC introspection or CheckAccess rather than verifying locally."
      },
      {
       "number": 167,
       "title": "Certificate-bound access token accepted as a bearer token by a resource server that ignores cnf",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "An operator turns on certificate-bound access tokens (RFC 8705 §3) and the server duly stamps cnf.x5t#S256 into every token for that client. A resource server whose middleware does not understand the claim accepts the token anyway: the binding is decorative, a leaked token works exactly as before, and the operator believes otherwise. A subtler form: a validator looks for x5t#S256, does not find it because the cnf names another confirmation method, and concludes the token is unconstrained — downgrading a sender-constrained token to a bearer token precisely when a newer authorization server begins issuing a constraint that validator predates.",
       "mitigation": "Contract 1.15 makes the check normative for all eleven SDKs (§10.1 rule 9): a token carrying cnf is not a bearer token and MUST NOT be accepted as one. The rule is a four-row table whose last row is the failure above — a cnf naming an unimplemented method MUST be refused, never read as unconstrained — and the thumbprint MUST come from the transport, never from a caller-supplied header. Server-side, axiam_auth::token::verify_certificate_binding implements exactly that table. Introspection exposes cnf (RFC 8705 §3.3) so an introspecting resource server cannot disagree with a locally-validating one. The contract also requires a positive regression test — an UNBOUND token is still accepted with or without a certificate — because the likeliest wrong implementation is one that starts demanding certificates from every caller."
      }
     ],
     "open": 1
    },
    {
     "id": "333133bc-1236-5f14-a917-732d86fea87f",
     "kind": "process",
     "x": 724,
     "y": 294,
     "w": 140,
     "h": 140,
     "name": "SDK AMQP consumer (HMAC verify, nonce)",
     "lines": [
      "SDK AMQP",
      "consumer",
      "(HMAC",
      "verify,",
      "nonce)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 144,
       "title": "HMAC verification present but inoperative",
       "type": "Spoofing",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "Finding X-1: AMQP HMAC verification was implemented but did not actually reject bad signatures in the Go and Rust SDKs — a security control that appears present and enforces nothing is worse than an absent one, because it is trusted.",
       "mitigation": "CONTRACT §8 specifies the protocol precisely — strip hmac_signature, canonicalise, HMAC-SHA256, constant-time compare, nack-without-requeue on mismatch, strict mode by default — and §8 v2 adds the mandatory nonce and issued_at replay fields. Conformance tests belong in each SDK repository."
      }
     ],
     "open": 0
    },
    {
     "id": "32f40e4d-ad24-5e7a-ac23-1a63051e704d",
     "kind": "process",
     "x": 724,
     "y": 524,
     "w": 140,
     "h": 140,
     "name": "Webhook receiver helper (§13)",
     "lines": [
      "Webhook",
      "receiver",
      "helper",
      "(§13)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 145,
       "title": "Receiver acts on an unverified webhook delivery",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The server signs deliveries with the Stripe-style signed-timestamp scheme, but a receiver that does not verify the signature acts on any POST reaching its URL. Previously no SDK shipped a verify_webhook helper, so every integrator hand-rolled the check or skipped it.",
       "mitigation": "T-145 closed: CONTRACT.md §13 is now normative and all eleven SDKs (Rust, TypeScript, Python, Java, C#, PHP, Go, Kotlin, Swift, C, C++) ship a webhook-signature verifier against one canonical spec — HMAC-SHA256 over <timestamp>.<raw_body>, constant-time comparison on decoded MAC bytes, a header carrying no v1 always fails, multiple v1 values accepted for secret rotation, and a two-sided freshness window (default 300 s) so future-dated timestamps are rejected like stale ones. Integrators must still call it."
      }
     ],
     "open": 0
    },
    {
     "id": "77bfaf8e-ccce-5d24-8ced-7452f475d5c0",
     "kind": "store",
     "x": 59,
     "y": 594,
     "w": 170,
     "h": 80,
     "name": "SDK configuration (client secrets, CA bundles)",
     "lines": [
      "SDK configuration",
      "(client secrets,",
      "CA bundles)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 146,
       "title": "Long-lived client secret committed to a repository",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Open",
       "description": "Static client secrets in a config file, CI variable or container image are the most common way service-account credentials escape.",
       "mitigation": "Outside AXIAM's control. Mitigate by preferring mTLS or short-lived workload identity over static secrets, rotating regularly through the client-rotation endpoint, and enabling secret scanning on integrator repositories."
      }
     ],
     "open": 1
    },
    {
     "id": "1369048e-72ee-5425-b6ea-a8dd53cfbd32",
     "kind": "store",
     "x": 1089,
     "y": 184,
     "w": 170,
     "h": 80,
     "name": "sdks/CONTRACT.md, openapi.json, proto/",
     "lines": [
      "sdks/CONTRACT.md,",
      "openapi.json, proto/"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 147,
       "title": "Contract weakened without review",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The contract is where SDK security behaviour is actually specified — TLS policy, secret redaction, AMQP HMAC, CSRF. Relaxing a clause silently relaxes it across seven implementations at once.",
       "mitigation": "The contract lives in this repository under normal review, and the drift and buf gates make any change to the generated artifacts visible in CI rather than in a downstream repository."
      }
     ],
     "open": 0
    },
    {
     "id": "4b405aae-8b0a-5fbd-a672-12ff80ee1b03",
     "kind": "store",
     "x": 59,
     "y": 59,
     "w": 170,
     "h": 80,
     "name": "Public package registries",
     "lines": [
      "Public package",
      "registries"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 148,
       "title": "Compromised release pipeline publishes a backdoored SDK",
       "type": "Tampering",
       "severity": "Critical",
       "status": "Open",
       "description": "A stolen registry token or a compromised release workflow publishes an SDK version that exfiltrates credentials from every integrator who upgrades.",
       "mitigation": "Enable 2FA and trusted/OIDC publishing on every registry, pin and review release workflow actions by digest as this repository's CI already does, and publish provenance attestations so integrators can verify build origin."
      }
     ],
     "open": 1
    },
    {
     "id": "a9eff9ae-2e28-5e50-8efa-1e5915231a5c",
     "kind": "process",
     "x": 1154,
     "y": 384,
     "w": 140,
     "h": 140,
     "name": "AXIAM REST / gRPC / AMQP surface",
     "lines": [
      "AXIAM REST",
      "/",
      "gRPC / AMQP",
      "surface"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [],
     "open": 0
    }
   ],
   "edges": [
    {
     "id": "3264cd39-a753-56da-8c38-d7f98bed5f83",
     "path": "M176.4,424 L433.1,182",
     "name": "admin UI session",
     "description": "",
     "label": "admin UI session (HTTPS)",
     "labelLines": [
      "admin UI session (HTTPS)"
     ],
     "lx": 304.7,
     "ly": 303,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "8624ff2b-3e3c-56e6-b2cb-d54835051035",
     "path": "M209,316.9 L415,352.2",
     "name": "application calls",
     "description": "",
     "label": "application calls (in-process)",
     "labelLines": [
      "application calls (in-process)"
     ],
     "lx": 312,
     "ly": 334.5,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "b3b13cfe-f8c2-50b3-ad67-b4983ce58fab",
     "path": "M135.2,344 L142.8,594",
     "name": "supply credentials",
     "description": "",
     "label": "supply credentials (config)",
     "labelLines": [
      "supply credentials (config)"
     ],
     "lx": 139,
     "ly": 469,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "config",
     "threats": [],
     "open": 0
    },
    {
     "id": "a3a5d8b3-630d-5aa4-b743-5025c1ee1e88",
     "path": "M429.2,407.5 L194.4,594",
     "name": "read secrets + CA",
     "description": "",
     "label": "read secrets + CA (in-process)",
     "labelLines": [
      "read secrets + CA (in-process)"
     ],
     "lx": 311.8,
     "ly": 500.8,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "b2338c28-aa31-5741-b838-03b3a078b0fd",
     "path": "M548.2,161.8 L1159.8,426.2",
     "name": "REST + CSRF token",
     "description": "",
     "label": "REST + CSRF token (HTTPS)",
     "labelLines": [
      "REST + CSRF token (HTTPS)"
     ],
     "lx": 854,
     "ly": 294,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "e36b5993-ab12-575b-91e4-5b81a518f961",
     "path": "M553.5,372.5 L1154.5,445.5",
     "name": "REST / gRPC calls",
     "description": "",
     "label": "REST / gRPC calls (HTTPS / gRPC-TLS)",
     "labelLines": [
      "REST / gRPC calls (HTTPS / gRPC-TLS)"
     ],
     "lx": 854,
     "ly": 409,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS / gRPC-TLS",
     "threats": [],
     "open": 0
    },
    {
     "id": "c6e828c4-3493-5cf9-9a21-a55e52d6a4f6",
     "path": "M484,434 L484,524",
     "name": "verify received token",
     "description": "",
     "label": "verify received token (in-process)",
     "labelLines": [
      "verify received token (in-process)"
     ],
     "lx": 484,
     "ly": 479,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0
    },
    {
     "id": "122b8796-fd82-5674-b53b-c5a492450ae6",
     "path": "M552.8,581 L1155.2,467",
     "name": "fetch JWKS / discovery",
     "description": "",
     "label": "fetch JWKS / discovery (HTTPS)",
     "labelLines": [
      "fetch JWKS / discovery (HTTPS)"
     ],
     "lx": 854,
     "ly": 524,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "861bc2db-6c49-5f80-91e3-3d57c46b3b4e",
     "path": "M862.5,378.3 L1155.5,439.7",
     "name": "consume signed messages",
     "description": "",
     "label": "consume signed messages (AMQPS)",
     "labelLines": [
      "consume signed messages (AMQPS)"
     ],
     "lx": 1009,
     "ly": 409,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "AMQPS",
     "threats": [],
     "open": 0
    },
    {
     "id": "3f13a939-e45b-5880-a042-e9dfe430affc",
     "path": "M1157.4,475.7 L860.6,572.3",
     "name": "signed webhook delivery",
     "description": "",
     "label": "signed webhook delivery (HTTPS + HMAC-SHA256)",
     "labelLines": [
      "signed webhook delivery (HTTPS +",
      "HMAC-SHA256)"
     ],
     "lx": 1009,
     "ly": 524,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS + HMAC-SHA256",
     "threats": [],
     "open": 0
    },
    {
     "id": "b3937415-41d5-541f-a233-21c8e92aa387",
     "path": "M1089,241.2 L552.6,350.1",
     "name": "generated + vendored artifacts",
     "description": "",
     "label": "generated + vendored artifacts (CI sync)",
     "labelLines": [
      "generated + vendored artifacts (CI",
      "sync)"
     ],
     "lx": 820.8,
     "ly": 295.7,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "CI sync",
     "threats": [],
     "open": 0
    },
    {
     "id": "1b945bb0-820e-5d08-83e4-88a78c6f8132",
     "path": "M142,139 L136,264",
     "name": "install SDK package",
     "description": "",
     "label": "install SDK package (HTTPS)",
     "labelLines": [
      "install SDK package (HTTPS)"
     ],
     "lx": 139,
     "ly": 201.5,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [
      {
       "number": 149,
       "title": "Unpinned SDK dependency pulls a malicious transitive update",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "An SDK's own dependency tree is part of the integrator's authentication path; an unscanned transitive update reaches production silently.",
       "mitigation": "Finding CI-03 flagged that SDK dependencies were unscanned. This repository runs cargo-audit, cargo-deny and npm audit with SARIF upload and Dependabot on cargo, frontend npm and GitHub Actions; each SDK repository must carry the equivalent for its own ecosystem, and integrators should commit lockfiles."
      }
     ],
     "open": 0
    }
   ],
   "total": 16,
   "open": 4,
   "bySeverity": {
    "High": 9,
    "Medium": 5,
    "Critical": 2
   }
  }
 ]
};
