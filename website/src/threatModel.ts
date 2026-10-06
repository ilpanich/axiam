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
 "description": "Complete IAM SW written in Rust using SurrealDB to store data and relationships. STRIDE threat model covering the system context, authentication and session management, the OAuth2/OIDC provider, inbound federation, the RBAC authorization engine, PKI and IoT device identity, audit/webhooks/email, and the Kubernetes deployment, and — as a design-only diagram whose entries are recorded Not applicable — a RADIUS front end that is not built.",
 "version": "2.36.1",
 "diagramCount": 10,
 "total": 469,
 "open": 23,
 "mitigated": 425,
 "notApplicable": 21,
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 1,
     "notApplicable": 0
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
       "mitigation": "crypto_gate bounds concurrent Argon2id operations with a process-wide semaphore and fails fast with 503 backpressure once the acquire timeout elapses, instead of queueing unboundedly. Both credential-verifying surfaces pass through the same gate: the REST login path and gRPC ValidateCredentials (B1) — an ungated path in either protocol would reopen the flood through the other."
      },
      {
       "number": 11,
       "title": "Missing tenant scoping exposes another tenant's data",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "A handler that trusts a caller-supplied tenant_id, or a repository query that omits the tenant filter, breaks the isolation guarantee that is the core of the product.",
       "mitigation": "Tenant context is derived from the interceptor-verified session or JWT, never from request-body input; tenant filtering is enforced at the repository layer and cross-tenant graph edges are stripped on traversal."
      },
      {
       "number": 181,
       "title": "Leaked SCIM provisioning token replayed as the IdP",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "SCIM provisioning tokens exist because Okta and Entra can present only one static bearer string, so the credential is deliberately long-lived — pasted once into the IdP and forgotten. Whoever obtains it can drive user provisioning and deprovisioning for the tenant for as long as it lives.",
       "mitigation": "Containment is the design (#330): a provisioning token is accepted on /scim/v2/* and nowhere else — not /api/v1/*, not /oauth2/*, not gRPC — and carries no permissions of its own: it resolves to an existing tenant user whose RBAC must still pass the same require_scim_provision check as a session would. It is stored SHA-256-hashed with the plaintext returned exactly once, carries an expiry, is revocable independently of every other credential, stamps last_used_at on use, and minting and revocation are audited. SCIM has its own rate-limit bucket (R5.2), and deprovisioning a user through SCIM revokes their live sessions and refresh tokens (SEC-098)."
      },
      {
       "number": 187,
       "title": "Deleted user's tombstone retains personal data and discloses the account existed",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Administrator deletion tombstoned the user row but kept username, email and metadata on it indefinitely — retention with the UI hidden, not erasure. Because the per-tenant uniqueness indexes are enforced by the database, the retained identifiers also blocked the person from ever registering again, and the duplicate-account refusal itself disclosed that the deleted account had existed.",
       "mitigation": "Fixed in 1.0.0-beta01: deletion overwrites username, email and metadata with values derived from the row's own id and erases what lives outside the row — WebAuthn credentials, federation identity links, password history — the same residue the GDPR Art. 17 purge clears, so an administrator's Delete and a data subject's erasure request do not leave different residue. The freed identifiers make a later registration a genuinely new account (pinned by a delete-then-recreate test). The row survives holding only its id, because append-only audit entries name their actor by id; only the Art. 17 pipeline additionally pseudonymises audit references and produces an erasure proof — a distinction docs/compliance/gdpr-compliance.md now states."
      },
      {
       "number": 261,
       "title": "A personal-data column added to `user` survives erasure and never reaches the Art. 15 export, and a SCIM patch that erases it is read as a no-op",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "Both erasure statements — the Art. 17 pipeline's `anonymize_user` and the administrator's tombstone behind `DELETE /api/v1/users/{id}` (T-187) — and the export job's `profile` section write **explicit column lists**. A column none of them names survives erasure and never appears in an export. Latent rather than live: the columns it would have stranded, `phone_number` and `address`, are added by the same release, and the plan assumed user-row fields were erased \"for free\"; an erased subject would have held a telephone number and a postal address indefinitely, with the account hidden from the UI — what the tombstone's own documentation calls retention with the UI hidden, not erasure. Beside it, `user_patch_is_noop` had never been taught the two columns, so a SCIM PATCH that set or *removed* only those answered `200` with the unchanged resource and wrote nothing — an erasure that silently does not happen.",
       "mitigation": "All three paths name the columns, and the tests erase a subject who has both and read the row back rather than inspecting the SQL, so a fourth erasure path cannot pass by sharing a statement. The no-op list is destructured from `UpdateUser`, so a field added to that struct fails to compile here instead of silently becoming unwritable, and each of its seven fields is asserted on its own rather than in one lump — a lump assertion still passes with a field missing, which is precisely how this was missed the first time. The three-way distinction is asserted too: `None` means the PATCH did not mention the attribute, `Some(None)` means write NULL — the erasure a data subject asked for — and confusing the two is an erasure that does not happen; `remove` and an empty array both erase, because RFC 7644 §3.5.2.3 spells \"replace with nothing\" that way, and `phoneNumbers` and `addresses` are removable unlike `emails`, deliberately, since a provisioning client sending `remove` is a subject asking for a number or an address to stop being held. **The three hand-maintained lists are gone (R-1, 2026-09-12).** `axiam_core::personal_data::USER_COLUMNS` is one declaration with a row per `user` column, recording for each whether erasure clears it, which key the Art. 15 `profile` section shows it under, and — where either answer is “neither” — why; the two questions are separate fields because a single “is personal data” flag gets `password_hash` (erased, never exported — D-10) and `created_at` (exported, never erased) both wrong. Both erasure statements render their shared `SET` fragment from it, so a declared personal-data column is erased by both paths by construction; each keeps its own path-specific clauses, and the asymmetries between them (`email_verified_at` and `totp_last_used_step` on the tombstone, `deletion_pending` and `scheduled_purge_at` on the Art. 17 path) are recorded on the columns they belong to rather than harmonised, because harmonising them would be a behaviour change and this is a gate. Three checks close the loop: `user_schema_matches_the_declared_inventory` runs `INFO FOR TABLE user` against a live datastore after migrations and compares the field set with the inventory **in both directions** — a column added to the schema and classified nowhere fails naming itself, and so does a classification for a column that no longer exists; `the_profile_section_shows_exactly_the_declared_export_keys` does the same for the export literal, which stays hand-written because two of its entries are not column reads (`id`, and the derived `phone_number_verified`); and `every_unerased_or_unexported_column_says_why` keeps “nobody classified this” and “classified as neither” different states. The erase-then-read-back tests are untouched on purpose — reading the row back is the one assertion a fourth path sharing a bad statement cannot satisfy, and rewriting them against the new machinery would throw exactly that away. `docs/compliance/gdpr-compliance.md` §1 and §2 now describe the gate rather than warning the reader to remember."
      },
      {
       "number": 287,
       "title": "Automation holds a human administrator's credentials because no management route accepts a service-account token",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "Every REST management handler took AuthenticatedUser, which refuses aud = axiam:m2m, so a service account could authenticate and then reach two routes: POST /authz/check and its batch form (DF-013). Automation that has to create resources, roles and groups, assign roles, issue and bind device certificates or register webhooks — a tenant's provisioning job, the demo's domo-bootstrap — was therefore given a person's credential instead: a password or a refresh token sitting in a CI secret or a container environment. That credential carries every role the person holds rather than the few the job needs, cannot be narrowed without narrowing the person, and is revoked only by locking the person out; its session looks interactive, and every change the job makes is audited as that person, so the trail cannot separate an administrator's act from a script's. The plumbing to do better already existed and was unused: AuthenticatedPrincipal, RBAC applied identically to both principal kinds, and role assignments on service accounts.",
       "mitigation": "T22.13 (S-9, 2026-09-23). Decision D-5 admits a service-account token on eight permission families — resources, scopes, permissions, roles (assignments included), groups, service accounts, certificates (generate, sign-csr, bind, list, get, revoke) and webhooks — whose 66 handlers now take AuthenticatedPrincipal; every other guarded route keeps AuthenticatedUser and still answers a machine token with 401. The boundary is two constants in permissions.rs checked against PERMISSION_REGISTRY, and a sweep drives every route of ROUTE_PERMISSION_MAP, plus every other non-public /api/v1 operation in the OpenAPI document, with real service-account tokens: admitted exactly on those families, refused everywhere else, and an account with no role reaches none of them (403 authorization_denied — RBAC is default-deny). Reaching a route is not being allowed on it; each is authorized by the roles assigned to the account. Widening the surface made four latent properties of AuthenticatedPrincipal matter, and all four are closed. (1) A machine-audience token is admitted only with sub_kind = service_account, because an RFC 8693 exchange can narrow a user's token to axiam:m2m and the machine branch skips the session check — such a token would have acted as that user with no session behind it. (2) Its user branch is now AuthenticatedUser's own code, not a copy; the copy read the session id from jti where the original reads sid first, so an OAuth2-issued user token would have been refused on every converted route; a differential test compares both extractors case by case. (3) The T21.6 tenant-path binding applies to both kinds. (4) X-Axiam-Tenant is resolved for a service account through the same function as for a user, so only an organization-level account may name another tenant of its organization, within its tenant_scope; and no service account is an organization principal for issuance, so the organization CA stays human-only (S-1's gate). A certificate-bound device token is refused on the new surface without its certificate, since enforce_sender_constraint runs on every extraction path. The audit middleware records the actor type from the signed sub_kind claim, so a service account's write reads service_account rather than user, and grant.pre_assign payloads carry actor_type for four-eyes rules. The CSRF exemption for bearer-only callers (T-200) is unchanged and does not cover a request that also carries a session cookie. Residual: a service account holding roles:assign can grant itself any role of its tenant, exactly as a user with that permission can — RBAC is the control, and granting it is the operator's decision; a machine token has no session to revoke, so disabling an account stops new tokens and the last one lives out its access-token lifetime (15 minutes by default); families outside D-5 still require a person, each to be argued on its own."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
      },
      {
       "number": 286,
       "title": "The gRPC listener cannot verify client certificates, so every call rests on a bearer token alone",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "build_grpc_rustls_server_config built the listener's rustls configuration with with_no_client_auth(), and no setting could change it; its own doc comment recorded client-certificate policy as a deployment decision deferred from T-234 (DF-005). That was defensible while the listener answered CheckAccess. It stopped being so as the surface grew: ReactorAdminService — create, update and delete of the reactors a tenant's policy decisions call out to — sits on the same listener, UserService/ValidateCredentials is a password check behind a rate limit, and gRPC skips session revocation by default (AXIAM__GRPC__STRICT_REVOCATION), so a revoked session keeps passing there until its token expires. A bearer token was all any caller needed, and a mesh that already issues client certificates had no network-level gate it could turn on. The other half is S-3's (T-283): device tokens carry cnf.x5t#S256, and the interceptor matches it against Request::peer_certs() — which was always empty, so a certificate-bound token was refused on every gRPC call. Fail-closed, but the property the binding exists for could only be had by keeping devices on REST.",
       "mitigation": "T22.12 (S-8, 2026-09-23). Two flat variables beside the certificate pair: AXIAM__GRPC_TLS_CLIENT_AUTH (off default | optional | required) and AXIAM__GRPC_TLS_CLIENT_CA_PATH. The verifying modes install a ReloadableClientCertVerifier — the REST listener's mechanism, as a second instance, because the policy is fixed per verifier and the two listeners may be configured differently — registered with reload_trust_anchors, which re-reads each gRPC listener's own bundle so it never trusts a set its next boot would not read. Pointed at the REST bundle, flagging a CA reaches both listeners without a restart, and only then is the reload reported as applied. required is enforced by rustls in the handshake, ahead of every RPC. The verified certificate reaches the interceptor through tonic's TlsConnectInfo, which the custom accept loop already produced — confirmed against tonic 0.14.6 and end to end rather than assumed — so a device token is now accepted over gRPC with its own certificate and refused with another device's or with none. Boot is refused, not warned about, on an unknown mode, on optional_self_signed, on a verifying mode without a bundle, on a bundle under off, on an empty or unreadable bundle, and on either variable set while the listener is plaintext. A reload that finds the bundle empty or unreadable keeps the previous anchors. off keeps with_no_client_auth(); the I1 compares handshakes, not structs, across four client shapes against the pre-change configuration, including a client holding a certificate, which is neither asked for it nor has it reach the server. Residual, by design: the default is off, so a deployment that sets nothing keeps a bearer-only gRPC listener; and the certificate is proof of possession and a gate, never an identity."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
      },
      {
       "number": 200,
       "title": "CSRF exemption for machine callers forged by pairing a bearer header with a session cookie",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The CSRF middleware required an axiam_csrf cookie matching the X-CSRF-Token header on every state-changing request, which a bearer-authenticated machine caller has no way to satisfy — POST /api/v1/authz/check under a client-credentials token answered 403 “CSRF validation failed”, so the machine-facing REST surface was unreachable by a machine (B-05). Exempting bearer requests naively would open the opposite hole: a cross-site page can attach a fabricated Authorization header while the browser attaches the victim’s session cookie — precisely the shape an attacker would craft to escape the exemption.",
       "mitigation": "Fixed in 1.0.0-beta05: is_bearer_only(authorization, has_session_cookie) is a pure function so the condition can be pinned by unit tests. A bearer token with no session cookie is exempt — CSRF is an attack on credentials the browser attaches by itself, and a cross-site page cannot set an Authorization header on a victim’s behalf. A bearer header alongside a session cookie is deliberately not exempt (the load-bearing case), and no bearer means no exemption whatever the cookies say. Scheme matching is case-insensitive and leading-whitespace tolerant, and the machine principal extractor accepts the axiam:m2m audience."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
       "status": "Mitigated",
       "description": "The authorization engine is additive-only (allow-wins, default deny). A role granted high in the resource hierarchy cannot be revoked on a single child resource — the only way to remove access to a subtree is to restructure the grant.",
       "mitigation": "SEC-040 — closed (B1). The engine now supports explicit deny: a grant carries effect: \"allow\" | \"deny\", and a deny overrides every allow, at any depth of the resource hierarchy and at equal specificity (deny-override, not most-specific-wins). Adding a deny rule can never widen access and can never be undone by adding allows — asserted by an exhaustive property test. Modelling exclusions by granting lower in the hierarchy remains valid but is no longer the only option. See claude_dev/deny-override-design.md for the precedence table and the scope-interaction rules. Amended 2026-09-22 (T22.11, DF-021): an assignment can also be made non-inheritable — inherit: false on the has_role edge — so a role granted high in the hierarchy can be stopped at its node instead of cascading to every child (\"here and no further\"), for allows and denies alike. Precedence is unchanged: the flag decides which assignments are applicable at a resource, never how deny-override weighs them (deny-override-design.md §2.2 rows 9–11). The flag's own hazards are T-285."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
      },
      {
       "number": 262,
       "title": "A contended write surfaces as a migration failure, and the single-use guard cannot recognise the engine's own conflict message",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The first run of the `scim_provisioning` benchmark cell failed 20 of 907 operations, every one a concurrent `PATCH /scim/v2/Users/{id}` that lost a SurrealDB optimistic-concurrency race and reached the client as `500` carrying the engine's own words — \"Transaction write conflict. This transaction can be retried\". Nothing retried it: the `retry_on_write_conflict` helper the marker documentation linked to had never been written, so the one method that had surfaced the bug got a hand-rolled loop and every other contended write got nothing, and an IdP driving Okta- or Entra-shaped provisioning reads those as failed syncs and re-sends the whole record. Worse for T-163 and T-164: `is_transaction_conflict` — the single-use consume guard on `device_grant`, `permission_ticket`, `pushed_auth_request` and `oauth2_auth_code` — matched only the two pre-v3 phrasings, so on the deployed engine its \"someone else got there first\" branch could not fire and a correctly refused replay surfaced as a `500` rather than as \"no row consumed\". Fail-closed, so a robustness defect and not a hole: no token is minted either way.",
       "mitigation": "2d371ad. `retry_on_write_conflict` now exists; `update` — which every administrative and SCIM write goes through — and `increment_failed_logins` use it, and replay is safe because a conflicted transaction commits *nothing*, which is also why the non-idempotent `failed_login_attempts += 1` can be retried at all. `classify_write_error` gains a conflict branch feeding `DbError::Conflict`, ordered after the UNIQUE check so a constraint violation — a statement about the request, which retrying only reproduces — still wins, and a contended write is no longer reported as a schema-migration failure that sends operators hunting a broken migration; the HTTP status stayed `5xx` pending a separate decision, which was taken on 2026-09-12 (R-4, decision A): a contended write now answers **`503 Service Unavailable` with `Retry-After: 1`** over REST and `UNAVAILABLE` over gRPC, through one new payload-free `AxiamError::WriteContention` and one mapping. `503` because the answer is a statement about the *server* — come back in a moment — which is what an IdP driving SCIM provisioning (Okta, Entra) treats as transient and retries; `409` in SCIM means \"your request conflicts with the resource's state\" (RFC 7644 §3.12), a statement about the request that changing the request is the response to, and `500` tells a client to stop when the correct advice is the opposite. The variant carries no payload, so the engine's own words stay on `DbError::Conflict` for the log and can never reach a body; the `Retry-After: 1` is a convention rather than a measurement, and CONTRACT §16.1 makes every SDK honour it as a floor so a client's own backoff still governs the wait. The UNIQUE-before-conflict ordering is what keeps a constraint violation on `409`, and it is pinned by its own I4 twin. No SDK behaviour needed to change — §16.3 already retries `5xx` on an eligible operation — and each SDK gains one test pinning that. Both legacy literals now live in `WRITE_CONFLICT_MARKERS` beside the v3 phrasing and the helper delegates, so the two sets can never again disagree about what a conflict looks like — the drift D-09 and `scripts/check-conflict-markers.py` exist to prevent, and which survived because these were never one set. Seven tests, one pinning the verbatim message captured from the failing run. **Corrected 2026-09-13 (f7d5ab8).** The sentence above claimed `503` *over REST*, and for a day it was true of every REST surface but the one the defect was found on: `axiam-scim`'s own error type maps `AxiamError` itself, its 5xx branch redacted every body to \"An internal error occurred\", and `WriteContention` fell through its catch-all as `500` — the exact answer an IdP reads as a failed sync. It now maps to `ScimError::retry_later`: `503`, `Retry-After: 1`, no `scimType` (RFC 7644 §3.12 defines none for a 5xx), the header and the body's exemption from redaction set from one field so they cannot drift apart, and the echoed `detail` a fixed, payload-free sentence — the engine's own words stay on `DbError::Conflict`, in the log, and a control test asserts that an ordinary `500` still redacts and advertises no retry. Four handler-level tests over the wire, one row on the mapping table. A control wired on two of three surfaces had been recorded here as whole; it is recorded now as it was."
      }
     ],
     "open": 1,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "bcca5e76-1845-552a-9430-1d8d3a20e3ae",
     "kind": "store",
     "x": 1269,
     "y": 424,
     "w": 170,
     "h": 80,
     "name": "Secret store (Vault / Kubernetes Secrets)",
     "lines": [
      "Secret store (Vault /",
      "Kubernetes Secrets)"
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
       "mitigation": "The signing key is fetched through the pluggable secret provider — HashiCorp Vault by default in the production stacks (AXIAM__AUTH__SECRET_PROVIDER=vault), Kubernetes Secrets otherwise — and never lives in the image or a ConfigMap; CA private keys are additionally AES-256-GCM encrypted at rest. Rotate signing keys on a schedule — JWKS publishes multiple key ids so rotation is non-breaking — and where Kubernetes Secrets are the source, enable envelope encryption for etcd."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
       "mitigation": "SEC-069 / D-01: guarded_fetch resolves A and AAAA fresh, rejects loopback, private, link-local, ULA and unspecified addresses, pins the validated IP for the connect (closing the DNS-rebind TOCTOU window), enforces https on every hop including redirects, and caps the advertised body size. SEC-107 adds a deliberate, bounded bypass for same-network IdPs: AXIAM__PKI__SSRF_ALLOWED_HOSTS is default-empty, set only at the composition root, matches exact hosts (no wildcards, no CIDRs), applies to the first hop only with redirects always strict, and logs every use — and cloud metadata endpoints stay blocked even for an allowlisted host, with IPv4-mapped canonicalisation running before that check so the allowlist cannot re-open SEC-094."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
    }
   ],
   "total": 33,
   "open": 2,
   "notApplicable": 0,
   "bySeverity": {
    "High": 17,
    "Medium": 13,
    "Critical": 3
   }
  },
  {
   "id": 1,
   "title": "Authentication & session management",
   "description": "Password and OPAQUE (RFC 9807) login, MFA (TOTP and WebAuthn), lockout and rate limiting, JWT and refresh-token issuance, password reset and email verification, and the credential stores behind them.",
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "6800fc4b-a3b4-581c-b613-969b5a6e9d2d",
     "kind": "process",
     "x": 364,
     "y": 74,
     "w": 140,
     "h": 140,
     "name": "Login endpoints /auth/login + /auth/opaque/*",
     "lines": [
      "Login",
      "endpoints",
      "/auth/login",
      "+",
      "/auth/opaque/*"
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
       "mitigation": "Login returns a uniform failure for unknown-user and bad-password alike, and password verification runs on a dummy hash when the user does not exist so timing does not distinguish the cases. Residual (W6 F4 review, model 2.36.1): the temporary-lockout branch answers without the dummy verify, and gRPC `ValidateCredentials` runs none on any refusal; recorded open as T-469."
      },
      {
       "number": 31,
       "title": "Unmetered credential-check path outside the lockout counter",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "If any code path verifies a password without incrementing the failed-attempt counter, brute force is unbounded through that path even though the main login endpoint is protected.",
       "mitigation": "SEC-026b / D-06: the REST login path and the gRPC UserService::validate_credentials path both call the single shared lockout helper, which is the sole source of truth for failed-attempt accrual."
      },
      {
       "number": 176,
       "title": "Account existence probed through the OPAQUE login flow",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "POST /auth/opaque/login/start is unauthenticated and must answer for any identity; a response that differs for unknown accounts — in shape, stability or KSF parameters — is a username-enumeration oracle equivalent to a differential /auth/login error.",
       "mitigation": "RFC 9807 designs the case in: for an unknown identity the server runs the AKE with no password file and returns a well-formed KE2 derived from the setup's dummy public key. AXIAM adds the stability half — the decoy credential identifier is HMAC(decoy_key, tenant_id || lowercased identity), so probing the same non-existent name twice gets the same answer; a random identifier would announce non-existence as loudly as a 404. Stated residual: a decoy carries the tenant's current KSF parameters while a real user carries those they enrolled under, so an attacker who knows the tenant's policy history can tell an account still on the old cost exists; the window closes as passwords rotate."
      },
      {
       "number": 177,
       "title": "Unauthenticated OPAQUE exchanges consume server state and OPRF budget",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "login/start and register/start are unauthenticated by necessity; each costs the server an OPRF evaluation and in-flight exchange state, so a flood turns the PAKE handshake into a resource-exhaustion vector — the OPAQUE analogue of the Argon2id memory flood (T-10).",
       "mitigation": "Under OPAQUE the expensive KSF runs on the client, so the server-side cost per attempt is a bounded elliptic-curve OPRF evaluation, not a ~19 MiB Argon2id arena. The endpoints sit under the strict internet-facing per-IP rate limits the tuning presets are prevented from widening; register/start has its own benchmark scenario and budget (opaque_register_start — new in kind, since SRP enrolment cost the server nothing); and in-flight exchange state is sealed for 120 seconds under the cheap-to-rotate opaque_session_key rather than accumulating unbounded server-side sessions. OPAQUE is additionally off by default (opaque_mode: disabled) until an organization or tenant enables it."
      },
      {
       "number": 260,
       "title": "A bearer credential reaches stderr or the CI log through a derived `Debug` or a failing test's panic message",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Three CodeQL high-severity alerts on this wave, one class. `LoginOutput` gained a browser session token, and its derived `Debug` would have printed three credentials; a test panic formatted a whole `LoginResult`, whose non-`Success` variants carry a live MFA challenge token and a setup token; two assertions printed a full `Set-Cookie` header, token included, to explain a failed attribute check, and an `assert_ne!` on two cookie values prints both credentials when it fires. A panic message reaches stderr and a CI log that outlives the run, so a test is not exempt — the values are fixtures, but the sink is real and the next author's would not be.",
       "mitigation": "SECHRD-09 applied to every new sink rather than to the one CodeQL named. `LoginOutput`, `BasicCredentials` (T-253) and `UserInfoPostForm` (T-243) hand-write redacting `Debug` impls; the tests name the variant or the cookie that was set, never the value — compare, then assert. The TRACE-capture tests grep for the secret, its encoding and the header value rather than trusting the absence of a `{:?}`. `axiam-core`'s three redacting certificate `Debug` impls, which reach `{:?}` in handler-level tracing spans where `#[serde(skip_serializing)]` cannot help, are now asserted — `Option`-aware on purpose, since a `vault_pki` CA has no key and printing `[REDACTED]` would claim one was withheld. One adjacent hygiene fix on 2026-09-13 (fcc976d): the two redaction tests R-5 added for `DbConfig` and `AmqpConfig` wrote a literal fake password into the source, which a secret scanner (GitGuardian, on the PR) cannot tell from a real one and neither can a reader six months later. They now mint the value through `axiam_test_support::test_password`, so the assertion holds for whatever the helper produces rather than for one string, and the seeder derives its credential field-name list from the environment table rather than repeating it. No scanner exemption was added: `.gitguardian.yaml` is for published RFC test vectors, and silencing a detector over a value one can simply stop writing is how an exemption list stops meaning anything."
      },
      {
       "number": 469,
       "title": "A locked account is refused without the equalising password verify, so its cost, or its status under load, tells it apart",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Open",
       "description": "`AuthService::login` refuses an account serving a temporary lockout, local or directory, before it asks for a hash permit or runs any Argon2id verify (`crates/axiam-auth/src/service.rs`, step 2), while an unknown name and a wrong password each cost one verify (SEC-026, T-30). Lockout is set by the attacker's own failures, so a name that answers fast after N wrong passwords exists and one that keeps costing a verify does not: an enumeration oracle at N + 1 requests per name, which also locks the real user out (T-35). Under hash-permit saturation the difference is in the status itself: the locked account answers 401 while every branch that verifies answers 503. gRPC `UserService/ValidateCredentials` answers an unknown name, and a locked, non-active or directory account, `valid: false` with no verify at all, an oracle for any caller holding a validated token of the tenant.",
       "mitigation": "Open (W6 F4 review, 2026-10-06, model 2.36.1; found by the T23.11.1 RADIUS spike, whose T-457 requires the same of any RADIUS build). Fix: run the equalising dummy verify, under the same bounded permit, on the lockout branch (still before the directory is contacted, T-302, and without verifying the real hash, so a correct password during a lockout neither succeeds nor shows) and on every refusal of `ValidateCredentials`. A timing-free test pins it: with no hash permit available, a locked account must answer the 503 an unknown name answers; today it answers 401 (ilpanich/axiam#564). Bounded meanwhile by the per-IP login limiter and by the lockout's exponential backoff, which makes every probe cost N failed attempts against a real user."
      }
     ],
     "open": 1,
     "notApplicable": 0
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
       "mitigation": "The challenge token is a distinct, short-lived credential that only authorises the MFA verification call and carries no API authority. Corrected 2026-09-13: what is consumed is the TOTP step, not the token — verify_mfa records totp_last_used_step under a compare-and-swap and refuses a code from a step already spent, so a captured challenge token cannot be replayed with the same code, and re-presenting it requires the authenticator. Known residual R-E: the setup token (purpose mfa_setup) is stateless in the same way and has no second factor behind it, so within its 300-second window a captured token lets a second party enrol a factor and complete the login. Low: the window is short, the token travels only under TLS in a 403 body to the caller who authenticated, and it is inert once the legitimate completion has run. The single-use hardening (M-5) was assessed and not taken — there is no consumption store to reuse and it needs a new repository on a service already generic over four — and remains a follow-up."
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
       "mitigation": "Only org/tenant admins can reset MFA state; the reset is audited and raises an admin notification. Enrolment must be redone on next login before any resource is reachable. Amended 2026-09-13 (M-1): the reset evicts every factor — the WebAuthn credentials as well as the TOTP secret — in the same call that clears mfa_enabled and revokes the sessions. Until then it cleared the challenge and not the factor: the credential rows survived, the forced TOTP setup at the next login turned mfa_enabled back on, and available_method_types offered webauthn again off a count that had never reached zero."
      },
      {
       "number": 182,
       "title": "Usernameless passkey sign-in skips the gates of the ordinary login path",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "authenticate/discoverable/{start,finish} is a one-round-trip, first-class sign-in: there is no preceding password step for the account-status check, the operator's login veto or lockout to have run in. A path added without re-establishing those gates would verify a discoverable credential for an account that is locked, deactivated or anonymised — or make \"click the passkey button\" a bypass of an operator's login veto (SEC-095's shape, on a new door).",
       "mitigation": "Each gate is re-established on the new path. The login.post_auth reactor interception fires on the discoverable finish, reusing intercept_federated_login_post_auth because a one-round-trip sign-in has no branch to route require_mfa into. ensure_can_sign_in stands in for the missing first step — lockout first, then account status — refusing as InvalidCredentials so which of the two reasons applies is not disclosed. And start touches no storage: no \"does this workspace have passkey users?\" pre-check, because the caller is anonymous and that answer is a tenant-enumeration oracle (pinned by unit tests whose repository double panics on every method); an unknown credential fails at finish with the same error as any other bad assertion. Registration now requests a discoverable credential (residentKey required, replacing webauthn-rs's discouraged default); passkeys enrolled before that are not retroactively discoverable and keep password sign-in with the passkey second factor. Since 1.0.0-alpha38 the two authenticate/*/finish handlers also emit the same Set-Cookie triple (axiam_access, axiam_refresh, axiam_csrf) and X-CSRF-Token header as the password path's cookie builder: a completed browser passkey ceremony lands in the same HttpOnly-cookie, CSRF-protected session posture as a password login, instead of leaving the token pair only in the JSON body. The body keeps its tokens for non-browser clients, which adopt them directly per CONTRACT §24. One gate was missed on the first pass and is worth recording as such, because it is this threat's own shape rather than a separate finding: rate limiting. /auth/login carries login_per_min; all six /auth/webauthn/* routes carried no limiter at all, and no webauthn_per_min existed to configure one with — so the discoverable pair, an unauthenticated first-class sign-in, was the one authentication surface with no throttle while the password path it parallels was held to ten attempts a minute per IP. Closed by webauthn_per_min, sized at login_per_min and asserted equal to it, so the two sign-in paths cannot drift apart silently."
      },
      {
       "number": 201,
       "title": "Enrolling a passkey never turns the second-factor requirement on",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "Adding a TOTP authenticator made the next sign-in demand a second factor; adding a passkey or security key did not (W5-01). The mfa_enabled flag began life meaning “a confirmed TOTP secret exists” and was reused to mean “challenge this account” — two readings that agree only while TOTP is the sole factor. A WebAuthn-only account listed its credential on the profile page while a password alone still let the account straight in, and the disable-on-last-removal branch was unreachable because nothing had ever turned the flag on for such an account.",
       "mitigation": "Fixed in 1.0.0-beta05: MfaMethodService::enable_after_enrollment runs when a WebAuthn registration completes, so a passkey is a factor from the moment it exists. The trap the fix had to avoid is pinned: every downstream reader tests mfa_enabled together with a stored TOTP secret, so setting the flag could have promoted an abandoned, unconfirmed TOTP enrollment into a live second factor — the pending secret is dropped rather than adopted, and an unconfirmed TOTP secret is never offered at sign-in. Removing the last passkey turns the requirement back off. Stated residual: if the flag write fails, the handler logs and continues, because the credential is already persisted and reporting the registration as failed would invite the user to register a second one. The user-verification policy those ceremonies run under became a tightening-only security setting in 1.0.0-beta09 (T-229, T-230)."
      },
      {
       "number": 229,
       "title": "A possession-only security key is accepted where possession alone must not be a complete login",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "`webauthn-rs` hard-codes `UserVerificationPolicy::Required` on both passkey ceremonies, so a security key with no PIN — which can prove user *presence* but never user *verification* — was refused at the finish step against a policy that existed nowhere an operator could see or change, and the refusal read as a hardware fault because a PIN-protected key on the same account worked. Making user verification configurable is the right answer, and it opens the hazard this threat records: a relaxed policy applied indiscriminately would let a PIN-less key satisfy the usernameless sign-in path, where the credential is the only factor and mere possession of the token would then be a complete login; and a policy the browser is not told about leaves a browser that does not prompt facing a server that rejects the answer, or the reverse.",
       "mitigation": "Fixed in 1.0.0-beta09. `webauthn_user_verification` is a security setting in the same hierarchical model as the OPAQUE and privacy settings: an organization baseline every tenant inherits and may only make stricter, ordered `required > preferred > discouraged` — it can join that model, unlike the attestation policy, because it is totally ordered, which is exactly what the tighten-only override check needs. The default is `preferred`, not `required`, because nobody chose `required`: it was a library constant, and backfilling it would have preserved the bug rather than an intent; `preferred` accepts a security key whether or not it has a PIN and records which happened, so tightening later is a policy change rather than a re-enrolment. Two ceremonies deliberately do not follow the setting: **usernameless sign-in keeps `required`**, so a PIN-less key is a working second factor and never a passwordless one, and attested registration keeps the `required` that `webauthn-rs` imposes, on a path that already excludes synchronised authenticators and hybrid flows. The policy is applied in both places it has to be — the challenge, which decides whether the browser prompts for a PIN, and the ceremony state, which decides what the server accepts — and because the state's policy field is private with no builder, it is re-stamped in the serialization this crate already performs on the way into the state-token JWT, failing loudly rather than silently if upstream's shape changes, with a test that pins that shape against the real library so a patch release cannot turn the re-stamp into a no-op. The organization and tenant settings requests carry the field in `openapi.json` and in the eleven SDKs' §27 management surfaces (T-235)."
      },
      {
       "number": 230,
       "title": "A relaxed user-verification policy silently weakens credentials enrolled under a stricter one",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A policy that governed how a credential is *used* rather than how it was *enrolled* would let an administrator downgrade every existing passkey at a stroke. The settings write that could do it is a `PUT` that replaces the whole row, so a client that simply omitted the new field would relax an organization that had set `required` without anyone choosing to — the quiet path by which a stricter posture is lost.",
       "mitigation": "Fixed in 1.0.0-beta09. No existing credential is weakened: `webauthn-rs` records the policy a credential was registered under and demands user verification at authentication whenever *either* that or the current policy says `required`, so every credential enrolled before this change carries the old hard-coded `required` for the rest of its life and the setting governs new enrolments only. Schema v53 adds the column with `DEFAULT 'preferred'` and backfills rows that predate it. The admin UI sends the field explicitly on the organization settings `PUT`, and it is a required field in the request type on purpose — a test fixture that has to be updated is exactly the friction that buys. `docs/admin/authenticator-policies.md` states the ordering, the two ceremonies that ignore the setting, and the per-credential rule."
      },
      {
       "number": 267,
       "title": "A user lowers their own account below the tenant's MFA floor through self-service reset",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "POST /api/v1/users/{id}/reset-mfa is self-service as well as administrative: a signed-in user could reset their own MFA with no fresh authentication, no password and no policy check. Under a tenant that enforces MFA this was the one path by which a user took their own account below the floor their administrator set — sessions are revoked, but the next password login hands out a setup token and whoever holds the password enrols a factor of their choosing. The per-method delete already refused to remove the last factor; the reset, which removes all of them at once, did not.",
       "mitigation": "M-2 (2026-09-13): the self-service branch reads the caller's own tenant's effective settings and refuses with 403 and the error code mfa_enforced where MfaPolicy::mfa_enforced is true. Its own code rather than authorization_denied, because the caller holds every permission the action needs and only an administrator can act against the policy; the message names the administrator. The users:admin branch is unaffected — unlocking a user who lost their only factor is what the endpoint exists for, and an enforcing tenant is where it matters most. Where the tenant does not enforce MFA the self-service reset is still allowed: such a user was free to run at one factor anyway, so refusing them protects nothing (D-1). The settings read is propagated rather than defaulted to not-enforced, so a datastore failure is not the way the floor is escaped."
      },
      {
       "number": 269,
       "title": "A setup token enrols a passkey on an account that already has a factor, or one the tenant's authenticator policy forbids",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "Forced first-login enrolment offered TOTP only, so a tenant whose authenticator policy is built around security keys still had to hand every new user a TOTP app. Opening the WebAuthn registration ceremony to a setup token creates two ways to get it wrong. The token could be used to add a factor to an account that already has one — a captured token would then be a way to register an attacker's own authenticator onto an account whose owner had just finished enrolling. And the session-less ceremony could skip the attestation and user-verification policies the profile-page ceremony applies, so an authenticator the tenant forbids would enrol through the one path that runs before the user has a session.",
       "mitigation": "M-3 (2026-09-13): POST /auth/webauthn/setup/register/start and /finish both decode the token with the same purpose-checked decoder the TOTP twins use — a challenge token, an expired token or a session bearer are all 401 — and both then ask MfaMethodService whether the account already has any factor, refusing with 400, the same answer setup/enroll gives. The question is asked of MfaMethodService and not AuthService because it spans the TOTP secret and the WebAuthn credential rows, and a check that read only the TOTP half would let a captured token add a second passkey. Nothing about what may register differs from the profile-page ceremony: the attestation policy and the user-verification policy are read from the token's tenant — which for a setup token is the principal tenant — and passed to the same start_registration_for_policy, and finish runs the same enforce_mds_freshness and finish_registration_for_policy (T-229/T-230 hold unchanged). The completion shares one session-issuance tail with the TOTP path, complete_setup_token_login, rather than a second copy: basic-op-gap-plan.md §4 lists every path funnelling through create_session_and_tokens and this adds no unlisted one. The evidence recorded matches what the WebAuthn authentication path records for the same credential kind — pwd for the password that earned the token, hwk or swk for the credential, mfa for the two factors, and user only under a Required user-verification policy, the one setting that rejects a ceremony whose UV bit is clear — so the session lands in urn:axiam:acr:mfa. Unlike the profile-page finish, a failure to mark MFA required fails the request: there is no profile page to correct it from and a session issued while the account still reads no-second-factor would send the user through forced enrolment again with a credential already registered. Both routes are CSRF-exempt and public for the same reason the TOTP twins are — the caller has no session and no cookie to echo, and the only credential is a body token, so there is no ambient credential for a cross-site request to ride."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
      },
      {
       "number": 178,
       "title": "OPAQUE login path sits outside the lockout counter",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "A failed OPAQUE authentication is a wrong password, but it surfaces as a failed KE3 inside the AKE rather than a failed hash verify. A path that did not accrue toward lockout would mean enabling OPAQUE silently removed brute-force protection from every account that adopted it — the same unmetered-path defect SEC-026b closed for gRPC (T-31), reopened by a new protocol.",
       "mitigation": "A failed KE3 accrues toward the shared exponential-backoff lockout exactly as a failed Argon2id verify does. OpaqueRejection deliberately has two variants rather than one so the caller can attribute an attempt before accruing it: a malformed client message (AuthError::OpaqueMalformed, 400) is distinguished from a wrong password, and only the latter counts against the account — and from corrupt stored state (500), so junk from a client is never read as a server fault."
      },
      {
       "number": 188,
       "title": "Brute force metered against the deployment default, not the configured threshold",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Every credential path accrued failed attempts against the process-wide AuthConfig defaults. A tenant or organization that lowered max_failed_login_attempts saw the setting stored, merged and returned by the settings API — and never read by the code that locks accounts, so the configured threshold was decoration and an attacker was metered against the more permissive deployment number on every transport.",
       "mitigation": "Fixed in 1.0.0-beta01: the REST login handler, OPAQUE login-finish and gRPC ValidateCredentials all resolve the org→tenant effective LockoutPolicy before accruing, so an account locks after the same number of failures whichever transport the attacker uses. record_failed_login now takes a LockoutPolicy rather than an AuthConfig — there is no longer a type that fits the parameter and carries the wrong numbers. A settings-resolution failure falls back to the deployment default rather than to no threshold, so a settings outage cannot open a brute-force window."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
       "mitigation": "Refresh tokens are opaque, server-stored and single-use with rotation; redeeming a token that has already been rotated is detectable and invalidates the family. **Amended at 1.0.0-beta13 and re-amended by the T-254 decision (2026-09-12):** rotation *supersedes* rather than revokes for a client registered `profile: fapi2` only — there the previous token stays redeemable for a 60-second grace (FAPI 2.0 §5.3.2.1-9) before its brought-forward expiry retires it, and every token on that profile is sender-constrained, so redeeming one inside the window needs the client's private key as well. For every other client the predecessor is revoked at rotation and a second presentation is refused, which is what this entry has always recorded. \"Detectable\" now holds on both lanes: rotation stamps `rotated_at`, so a presentation after rotation is recorded on the session and audited as `oauth2.refresh_token_replayed` whether it was accepted under the grace or refused (T-254)."
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
       "status": "Mitigated",
       "description": "Access tokens are self-contained and valid for up to 15 minutes, so a role removal or account disable does not take effect on already-issued tokens until they expire.",
       "mitigation": "Accepted trade-off for stateless verification. The 15-minute lifetime bounds the window; sessions are invalidated on password change; deployments needing immediate revocation can use the gRPC introspection path rather than local JWT verification. **Narrowed server-side on 2026-09-12 (R-6, decision C) and Mitigated on 2026-09-13, when the SDK half landed in all eleven repositories.** `GET /oauth2/revocations` — off by default (`AXIAM__AUTH__REVOCATION_FEED_ENABLED`), and with it off the route is not mounted, no row is written and the deployment is byte-identical to one built before it existed — publishes the base64url SHA-256 of each session id revoked within the last access-token lifetime. Five properties make it safe to serve unauthenticated: entries are **hashes, never identifiers** (a `sid` is a session id and not a subject, so the document discloses neither who was revoked nor how many users are behind it; the argument is non-enumerability of a UUIDv4 preimage space, not that a hash is magic); it is **bounded** by the revocation rate over one token lifetime rather than by history, filtered on read as well as swept so a late sweep makes the table large and never the document untruthful; it is cacheable with an `ETag` over the entry list only; a guard **never fails closed on it**, which is what stops a network blip becoming an outage; and the token format is unchanged. Three deliberate revocation paths publish — logout, a password or MFA reset, and \"sign out everywhere else\", which does not publish the session it keeps — while the two single-use redemption paths deliberately do not, because a handoff being exchanged is not a session being withdrawn and publishing it would reject a caller whose grant is proceeding normally. Contract 1.44 §10.4 makes polling a **SHOULD** for a guard and scopes §10.2's MUST NOT to per-request polling, which is what it always said. Schema v62; conformance rows 165–169. **Closed on 2026-09-13, by the SDK half.** The entry stayed Open for a day on purpose — a feed nobody polls narrows nothing, the same shape of gap T-266 records for `mtls_endpoint_aliases` — and it flips now because every one of the eleven SDKs implements contract §10.4 (PRs rust #104, typescript #103, python #80, java #92, kotlin #62, csharp #87, php #67, go #77, swift #60, c #59, cplusplus #60, each merged and released at that SDK's 1.0.0-beta14), and §10.4.1 records the attachment point per SDK with no row that `declines`. Each poller was checked against the four rules that make the feature safe rather than merely present: default off, never on the request path, never fail closed (an unreachable feed, a non-`200`, an unparseable body or an unknown `alg` behaves as no feed at all — and specifically not as an empty list), and reject-only. The residual, stated plainly: the window is one poll interval (30–60 s recommended, 15 s floor) rather than zero, and it is opt-in on **both** sides — a deployment that leaves the feed off, or an integration that attaches no poller, keeps the fifteen-minute window and the introspection answer. The trade is narrowed, not removed, which is why the register's accepted-trade-off bullet keeps it.\n\n**Amended 2026-10-03 (F4 P23W1-01).** “The 15-minute lifetime bounds the window” was not true of an account disable. Locking or deactivating a user through `PUT /api/v1/users/{id}` revokes no credential (deletion, SCIM deprovisioning and a credential reset do), and the OAuth2 `refresh_token` grant did not re-read the account. Each rotation stamps a fresh `expires_at`, so a relying party holding a suspended user's grant kept minting access and ID tokens for as long as it kept refreshing: unbounded, not fifteen minutes. T23.1.3 closed the same gap for the OP cookie at `/oauth2/authorize` and recorded that endpoint as the one place a session became a principal without the read; it was not. The `authorization_code` and `refresh_token` grants now re-read the account and refuse a suspended one (`Locked`, `Inactive`, `Anonymized`, `Deleted`, or no account) through the function `/oauth2/authorize` uses (`axiam_auth::service::account_may_act`); `PendingVerification` is not refused, whatever its grace period, because every federated account holds it for life (P23W1-03). A refused account is `invalid_grant`; nothing is minted or rotated, and nothing is revoked, so reactivation restores the grant as it restores the session. The code grant is covered too because the bearer and `axiam_access` path at `/oauth2/authorize` does not re-read the account, and redeeming its code is what turned a 15-minute credential into a long-lived one. What remains is the window this entry always described: an access token already issued lives to its `exp`, and introspection and UserInfo answer it until then. Tests: `token_service.rs::p23w1_01_*` (three refused statuses and a removed account, on both grants; the active, no-user and pending twins) and `oauth2_flow_test.rs::p23w1_01_a_suspended_accounts_refresh_token_mints_nothing_until_reactivated`, each failing before the fix."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "723bd2e1-0555-5a1b-9fca-915b84a37849",
     "kind": "store",
     "x": 1074,
     "y": 104,
     "w": 170,
     "h": 80,
     "name": "user credentials (Argon2id hashes, OPAQUE records)",
     "lines": [
      "user credentials",
      "(Argon2id",
      "hashes, OPAQUE records)"
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
       "mitigation": "Argon2id with OWASP-recommended parameters (m=19 MiB, t=2, p=1) and per-user salts makes bulk cracking expensive; policy enforces a 12-character minimum by default. The `argon2` crate moved to 0.6 in 1.0.0-beta08: the PHC string format is unchanged, the crate now draws the 16-byte salt from the OS RNG itself, and hashes written under 0.5 were verified to still verify."
      },
      {
       "number": 179,
       "title": "Stolen OPAQUE records opened offline with the tenant OPRF seed",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "opaque_credential rows are the OPAQUE analogue of password hashes. Unlike an Argon2id or SRP-verifier corpus they are not offline-attackable at KDF cost alone — but only while the per-tenant OPRF seed stays secret. A dump that includes a usable seed reduces OPAQUE to the SRP posture: a dictionary attack priced at the KSF.",
       "mitigation": "Each tenant's OPRF seed and AKE keypair (opaque_server_setup, schema v42) are AES-256-GCM encrypted at rest under opaque_setup_key, which is held outside the datastore in the secret provider (Vault in production), so a database-only disclosure yields no dictionary attack to mount at any cost. The trade-off is stated in docs/deployment/vault.md: losing opaque_setup_key means a password reset for every user in every tenant — which is why the Vault seeder never regenerates an existing key, and why the setup key is split from the cheap-to-rotate opaque_session_key."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
      },
      {
       "number": 189,
       "title": "Logout's removal cookies were weaker than the cookies they cleared",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A removal is a Set-Cookie in its own right: the browser parses it and keeps the empty-valued cookie it describes until it expires. The logout paths emitted removals carrying only Path, dropping the HttpOnly, Secure and SameSite=Strict the matching setters emit — a replacement that was JS-readable, cross-site-sendable and cleartext-transmissible, and whose effectiveness rested on transport the setters explicitly do not trust, since a browser refuses to let a non-Secure cookie from an insecure origin overwrite a Secure one (“Leave Secure Cookies Alone”).",
       "mitigation": "Fixed in 1.0.0-beta03 (CodeQL rust/insecure-cookie): each removal cookie is built by calling the cookie's own setter and expiring the result, so HttpOnly, Secure, SameSite and Path are mirrored by construction rather than by repetition — there is exactly one place per cookie where those attributes are written, the deliberately JS-readable CSRF cookie included (D-07). Tests assert the attributes on the wire for all three cookies, across both logout paths and both cookie_secure values."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
    }
   ],
   "total": 36,
   "open": 1,
   "notApplicable": 0,
   "bySeverity": {
    "High": 16,
    "Medium": 15,
    "Critical": 3,
    "Low": 2
   }
  },
  {
   "id": 2,
   "title": "OAuth2 / OIDC authorization server",
   "description": "Authorization Code with PKCE, client credentials and refresh grants; consent, introspection, revocation, userinfo, JWKS and discovery; client registration and the code and token stores. Since 1.0.0-beta13 this also covers the OpenID Connect Basic OP surface the W1–W9 waves added — the per-client browser login hop and its OP session cookie, the honour lane for the authentication-request parameters, the consent-gated address and phone scopes, client_secret_basic, POST /oauth2/userinfo and tenant-scoped discovery — and the resource-endpoint token validation the OpenID Foundation conformance runs found wanting (T-237…T-259). Since Phase 23 (G-7, T23.7.1, model 2.33.0) it also covers CIBA — Client-Initiated Backchannel Authentication: the backchannel authentication endpoint and the approval service the identity pages call, the pending-request store, and the CIBA client in a boundary of its own, the consumption device (T-421…T-439). At model 2.33.1 (D-61 amended, T23.7.1 continued) the endpoint verifies signed authentication requests (CIBA Core 7.1.1) and serves the fapi2 CIBA client as FAPI-CIBA requires (T-440 ... T-443; T-421 and T-434 amended).",
   "width": 1438,
   "height": 1028,
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
     "h": 940,
     "label": "Data tier"
    },
    {
     "id": "349c0354-dfae-5c05-ab28-e1c8cfb006cd",
     "x": 24,
     "y": 784,
     "w": 260,
     "h": 200,
     "label": "CIBA consumption device"
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
      },
      {
       "number": 259,
       "title": "The end user cannot refuse an authorization request, so the relying party cannot tell a refusal from a crash",
       "type": "Repudiation",
       "severity": "Low",
       "status": "Mitigated",
       "description": "RFC 6749 §4.1.2.1 and OIDC Core §3.1.2.6 both require `access_denied` when the end user declines. The consent screen has a decline button, but it renders only for a sensitive scope; a request for `openid profile` reached a sign-in page whose only outcomes were \"authenticate\" and \"close the tab\". Closing the tab is not a protocol answer: the relying party waits on a response that never arrives, cannot tell a refusal from a crash, and the refusal is recorded nowhere.",
       "mitigation": "065f37c: the sign-in page gains a Cancel control, shown only when a pending authorization is being decided, which returns through `axiam_user_declined`. The refusal is delivered on the same terms as every other authorization error — only to a `redirect_uri` this client registered, compared exactly, with the request's own `state`, and for a pushed request both come from the pushed copy (T-256); consuming the `request_uri` there is correct, since it is single-use and the request has just been answered terminally. A sensitive-scope consent decision is recorded either way: the `consent` row is live state and `gdpr.oidc_scope_consent_*` in the append-only audit log is the history (Art. 7(1))."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
      },
      {
       "number": 237,
       "title": "The OP session cookie travels where a Strict cookie would not, so its attributes carry the whole risk",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "Wave W3 added `axiam_op_session`, the only `SameSite=Lax` cookie AXIAM sets. It has to be Lax: a relying party's redirect is a cross-site top-level navigation, and the `SameSite=Strict` API cookie never travels on one — which is why `/oauth2/authorize` could not answer an anonymous browser at all, and why `prompt`, `max_age` and `id_token_hint` were unreachable rather than merely unimplemented. A cookie that travels further is exposed to more: a plaintext hop on a request the user never typed, a hidden cross-site iframe probing whether a session exists, and a client that never opted into browser sign-on whose authorization request now arrives with a session attached.",
       "mitigation": "`HttpOnly; Secure; SameSite=Lax; Path=/oauth2/authorize`, `Max-Age` equal to the session's; minted at `create_session_and_tokens`, the choke point every browser sign-in funnels through, and only its SHA-256 is stored (256 CSPRNG bits; the schema-v56 index is deliberately not UNIQUE because the column is unset on almost every row, and the ambiguity a unique index would have caught is refused in `get_by_browser_token_hash`, which returns no principal rather than the first of two rows). `Secure` is **unconditional** — unlike the three Strict cookies this one does not follow `AuthConfig::cookie_secure` (D-18), because RFC 6749 §3.1 requires TLS at the authorization endpoint regardless and browsers treat loopback origins as trustworthy, so the local-development case costs nothing; a plaintext login hop to a non-loopback host fails into `login_required`, whose description names the cause (CodeQL 557). `Lax` is load-bearing and not a candidate for fixing: it is sent on a top-level navigation and not inside a frame, so the relying-party redirect works and hidden-iframe probing fails closed — cross-site silent renew is the plan's §9 recorded decision. The cookie is read only for a client registered `browser_sso: true`, and the client is loaded *before* the cookie is read, because the registration decides whether the cookie is consulted; with the default `false` the anonymous answer is the same `401` object it always was, pinned byte for byte with and without every new parameter and with a live cookie attached (`t0_1`, `t0_5`). Logout and `end_session` clear it, `clear_op_session_cookie` is built from the setter so the removal is `Secure` too, and refresh copies the digest rather than restamping it. `docs/admin/browser-login-hop.md`; conformance rows 47–59. **Amended 2026-10-02 (T23.1.3).** An independent audit of the shipped X7.3 found the cookie outliving the account it acts for. The cookie names a session row, and an account status change — an administrator setting `status` to `locked` or `inactive` through `PUT /api/v1/users/{id}`, or a `PendingVerification` account's grace period running out — revokes no session: the refresh path re-reads `check_user_status` instead, and `/oauth2/authorize` was the one place a session became a principal without that read. A suspended user's browser therefore kept buying authorization codes, and with them access, ID and refresh tokens, at every `browser_sso` relying party for the rest of the session's lifetime (`refresh_token_lifetime_secs`). `resolve_authorize_principal` now re-reads the account behind a resolved session and applies the sign-in rule through `AuthService::check_session_holder`, which is the refresh path's `check_user_status` with the same grace period. An account that fails it is treated exactly as a revoked session (`reauth`, cookie cleared, `login_required` on the return leg), and a failed read is anonymous, never a principal. The bearer and `axiam_access` path is unchanged: its 15-minute token is the residual it always was. The same audit pinned over HTTP five properties this entry asserted without a test. A sign-in mints a new value and never adopts a presented one (session fixation). A password step that still owes a second factor sets no cookie. A cookie from one tenant never authorizes in another. An access token beside the cookie decides the subject, and the two never cross users. `POST /oauth2/authorize` is not routed, and the cookie is no API credential. Tests: `oauth2_login_hop_test.rs::an_op_session_stops_authorizing_once_its_account_is_suspended_or_removed` (failed before the fix), `::an_op_session_follows_the_email_verification_grace_period`, `::a_sign_in_never_adopts_an_op_cookie_the_browser_already_holds`, `::a_password_step_that_still_owes_a_second_factor_sets_no_op_session`, `::an_op_cookie_minted_in_one_tenant_never_authorizes_in_another`, `::an_access_token_wins_over_the_op_cookie_and_the_two_never_cross_users` and `::the_op_session_reaches_no_endpoint_but_get_authorize`. Two limits are recorded rather than changed. First, the name carries no `__Host-` prefix and cannot, because `__Host-` requires `Path=/`. A browser therefore does not refuse a same-named cookie tossed from an attacker-controlled sibling subdomain. A planted value is never adopted, so it either names nothing and fails closed, or names the planter's own session, which signs the victim in to the planter's account at the relying party: login CSRF, which the relying party's `state` does not bound because the victim's browser started the request. Second, on a T21.6 per-tenant path the cookie is not sent at all, because `/oauth2/authorize` is not a path-prefix of `/t/{tenant_id}/oauth2/authorize`. The hop there fails closed into `login_required`. This is an open design question, not a fix. **Corrected 2026-10-03 (F4 P23W1-01).** `/oauth2/authorize` was not the one place: the OAuth2 `authorization_code` and `refresh_token` grants also turned a long-lived credential into tokens without re-reading the account, and now apply the same rule (T-39). **Corrected 2026-10-03 (F4 P23W1-03).** Holding the cookie to the password sign-in rule *including the grace period* refused every federated account a day after it was provisioned: `UserRepository::create` writes `PendingVerification` and federation provisioning never moves a federated user off it, so browser sign-on ended for the whole federated population, the hop looping them to `login_required`. The rule is now `axiam_auth::service::account_may_act`: `Locked`, `Inactive`, `Anonymized` and `Deleted` are refused and `PendingVerification` is not, which is the rule T-160 already applies to token exchange. `…::an_op_session_follows_the_email_verification_grace_period` became `…::p23w1_03_an_op_session_survives_a_pending_verification_status`, which failed before the change. **Amended 2026-10-03 (T23.1.8, D-11).** The second limit above is closed by the maintainer's D-11 (issue #516, option 1). A sign-in now mints the cookie at every path in one list, `csrf::op_session_cookie_paths`: the bare `/oauth2/authorize` always, and `/t/{tenant_id}/oauth2/authorize` for **the session's own tenant** only, where `AXIAM__AUTH__TENANT_ISSUER_PATHS` is on. The copies share name, value, `HttpOnly`, `Secure`, `SameSite=Lax` and `Max-Age`, and differ in `Path` alone. Every completed sign-in mints both: password, OPAQUE, MFA verify, forced enrolment, both WebAuthn ceremonies and the federation handoff. A password step that still owes a factor mints neither. One name, because the paths are pairwise disjoint under RFC 6265 path-match, so no request carries two copies and the one resolver serves every route. One value, so every copy names the same row through the stored digest, with no schema change. What keeps a copy out of another tenant is not its path, a browser courtesy, but the tenant-keyed lookup. A tenant-A value presented at `/t/B/oauth2/authorize` names nothing there, even though the same digest names a live row in A. Every remover is built from the same list, so a minted path cannot go uncleared. Logout, `end_session` (bare and per-tenant) and its `/logout` hop clear every copy for the tenant (T-290). A stale copy is cleared at the path it arrived on. Another browser's session revoked server-side cannot have its cookies cleared from here; its copies resolve to nothing once the row is gone. Clearing found one defect, failed first. `POST /api/v1/auth/logout` revoked the session in the **acted-upon** tenant, but an organization-level principal that had switched tenant sends `X-Axiam-Tenant` on every request, logout included. The tenant-scoped `DELETE` then matched no row, the answer was `204`, and the session stayed live with every copy naming it. Logout now revokes and clears in the principal's own tenant. The T23.1.3 audit list was re-run on the tenant path, in `oauth2_tenant_path_sso_test.rs`: a code from the tenant copy alone; fixation; cross-user and cross-tenant use in both directions; no copy from an owed factor; `POST` unrouted; nothing reflected; the decline arm; M7; the account re-read, including `PendingVerification`; non-`browser_sso` and `fapi2` opt-outs reading nothing; and the honour lane. Further tests: `d11_logout_clears_both_copies_and_the_tenant_value_then_resolves_to_nothing`, `d11_logout_by_an_org_level_principal_acting_on_a_child_tenant_ends_its_session` (failed before the fix), `d11_end_session_on_the_bare_and_the_tenant_path_clears_both_copies` and `d11_a_revoked_sessions_tenant_cookie_resolves_to_nothing`. Unit tests in `csrf.rs` pin the list, the attribute identity, the disjoint paths and the mirrored removals. The `__Host-` limit above is unchanged and applies to every copy alike."
      },
      {
       "number": 238,
       "title": "`/login?return_to=` becomes an open redirect, or the login hop a redirect loop",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "The login hop sends an anonymous browser to `/login?return_to=…` and back to the authorization endpoint. A `return_to` that accepts a foreign origin is an open redirect on the sign-in page — the page on which a phishing target types a password, on AXIAM's own origin — and a hop that can be re-entered is a loop a misconfiguration or an attacker can drive indefinitely.",
       "mitigation": "`return_to` is exactly `/oauth2/authorize?` plus a query, and it is validated three times: by the builder, by the deployment-origin resolution (`require_deployment_spa_origin`, the same rule the SSO handoff uses rather than a second one), and by the SPA before it navigates. A foreign origin, a scheme-relative `//evil.example`, its backslash spellings, path traversal and any other same-origin path are each refused. Every login redirect carries `axiam_login_hop=1` inside its `return_to`, and a request that *arrives* with the marker is never redirected again — it is answered `login_required` — so a chain is at most two authorization requests and one sign-in page whatever goes wrong in between. A browser presenting an OP cookie that resolves to no live session gets `reauth` mode, with the stale cookie cleared on the way out. A PAR `request_uri` that expired during the hop answers `invalid_request_uri` with a description saying so, and only on a return leg, so an ordinary request with a dead handle keeps today's `invalid_request`. The consent screen (W7) carries its own `axiam_consent_hop` marker, because a request carrying both `prompt=consent` and `address` came back from the sign-in page with the login marker, which the consent rule read as \"asked and declined\" — `access_denied` for somebody never shown the question (row 129; a test walks all three legs). **Amended 2026-09-14.** The clause above — an ordinary request with a dead handle keeps `invalid_request` — no longer describes the endpoint. A handle that is already unusable is now refused *before* the hop, by a read that does not spend it, and the refusal reaches the relying party as `invalid_request_uri` whenever the request named a registered `redirect_uri` — on the return leg exactly as before it (T-270). **Amended 2026-10-02 (T23.1.3).** An independent audit of this entry against the shipped code found no accepted redirect target, and closed the gap the plan's §6 named: the suite did not test the redirect validator member by member. One 56-candidate list is now refused on both sides, row for row: `login_hop.rs::the_audit_list_is_refused_on_the_server_too` and `returnTo.test.ts` (\"the T23.1.3 audit list\"). It covers absolute, scheme-relative and triple-slash forms; every backslash spelling; encoded and double-encoded slashes and traversal, which are never decoded and so never become the path; `javascript:`, `data:` and `vbscript:` in mixed case; leading, trailing and embedded whitespace, CR, LF, NUL, DEL, C1, U+2028, NBSP and BOM; dot segments, a trailing slash, another case and other endpoints; `@` userinfo tricks; and full-width, division and fraction solidi, a Cyrillic look-alike and a zero-width space. Two further tests pin the inclusive 4096 bound on both sides and that the builder never lets the query choose the path. On the page, a repeated `return_to` is validated whichever value is read, Cancel returns only to the validated value plus `axiam_user_declined=1`, and `resumeLoginHop` re-validates at the moment it navigates (`LoginPage.test.tsx`). Over HTTP, the hop's `302` carries no body and its HTML refusal echoes nothing (`the_login_hop_reflects_no_request_parameter_into_a_body`). The `user_declined` arm had no HTTP test, and now delivers only to a registered `redirect_uri` with or without a live cookie (`a_declined_sign_in_is_reported_only_to_a_registered_redirect_uri`). A `return_to` carried on the authorization request is never a redirect target (`an_anonymous_refusal_never_redirects_to_a_return_to_the_request_carried`; T-255). Plan row M7's end-to-end half, which `fapi.rs` cited and nothing implemented, now exists: a `fapi2` + `browser_sso` + `require_par` return leg with inline parameters is `ParRequired`, and its pushed request without `code_challenge` gets the FAPI PKCE refusal while the same handle with one is authorized (`m7_*`). The marker is still unbound, by design: a forged `axiam_login_hop` skips a `prompt=login` interaction only for its own author, and `auth_time` still reports the old authentication (`oauth2_honour_lane_test.rs::a_forged_return_leg_marker_cannot_make_an_old_session_look_reauthenticated`); it cannot satisfy `max_age` with an old session (`::a_forged_return_leg_marker_cannot_satisfy_max_age_with_an_old_session`). **Amended 2026-10-03 (T23.1.8).** On a per-tenant path the hop never came back. `TenantPathScope` appends `tenant_id` to the query it hands the handlers, and the login and interaction hops built `return_to` from that rewritten query. Every return leg on `/t/{tenant_id}/oauth2/authorize` therefore carried a second tenant selector, and was refused `invalid_request` by the very middleware that had added it. The cookie's path (T-237) had hidden the defect. `TenantPathBinding` now records the client's own query, `client_query`, and both hops echo that, so the `return_to` is the tenant authorization path plus exactly what the client sent. The return leg is validated against that one path, as before. The test failed first: `oauth2_tenant_path_sso_test.rs::d11_the_login_hop_on_the_tenant_path_completes_end_to_end`, with `::d11_an_interaction_hop_on_the_tenant_path_returns_to_the_tenant_path` beside it. The 56-candidate audit list is now also refused re-based under a tenant path, on the server (`login_hop.rs::t23_1_8_the_audit_list_is_refused_against_the_tenant_path_too`) and in the SPA (`returnTo.test.ts`, \"re-based under a tenant path\"). Over HTTP, a hostile `return_to` on a tenant-path request is never promoted (`::d11_the_return_to_from_the_tenant_path_is_the_servers_own_and_validated`). A stale copy presented on the tenant path is cleared at that path, where a bare-path removal would not have matched it (`::d11_a_stale_tenant_cookie_is_cleared_at_the_tenant_path`)."
      },
      {
       "number": 239,
       "title": "A relying party is told it received a freshness or assurance guarantee it did not get",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "OpenID Connect Core §3.1.2.1 lets a relying party ask for five things that change what a token *means*: `prompt=none`, `prompt=login`, `max_age`, `acr_values` / `claims.id_token.acr` and `id_token_hint`. Until W4 AXIAM accepted all five and acted on none. That is a conformant answer to nothing: a relying party that sent `max_age=60` and received a code minted from a week-old login had been told a freshness guarantee it did not get, and could not tell. On the assurance side the classic deception is to copy `acr_values[0]` into the `acr` claim, which no reviewer reliably notices.",
       "mitigation": "A per-client `authn_request_params: ignore | honour`, default `ignore` (schema v54; pre-v54 rows decode to `ignore`, an unknown stored value fails closed the way `decode_profile` does). On the honour lane a relying party gets the property it asked for or is told it cannot have it — never a token that quietly does not have it. The ACR echo is designed out at the type level: `acr::acr_for(amr: &[Amr]) -> Acr` takes the session's evidence and nothing else, so there is no parameter through which the request could reach it, and `report_acr` can only return a requested value the achieved class already satisfies — the strongest thing a relying party achieves by asking is to select among true statements; the vocabulary is the two AXIAM URNs and is not operator-configurable, because an operator who could configure the string could configure it to say `mfa` for a password login. `max_age` is `elapsed >= max_age` with no leeway in the relying party's disfavour, and `max_age=0` is handled as `prompt=login` (always a reauthentication; its return leg is answered with a code, D-14). `prompt=none` from an anonymous browser is refused, and on a return leg it is refused however good the session is, so silent authentication over PAR sees `invalid_request_uri` or `login_required` and never a token minted behind an interaction it forbade. `prompt=consent` was treated as `login` until W7 gave it a consent screen — ignoring it is the silent downgrade the lane exists to prevent. A `fapi2` client is refused the five security-bearing parameters at registration and at request time (W1 rules 1–3), and a `fapi2` row edited to `honour` is refused with `tracing::error!`; `claims` left that list once §5.5 was implemented, because the list is the parameters AXIAM *drops*, and dropping is what made it dangerous. Request objects are rejected rather than implemented — `request` answers `request_not_supported`, a `request_uri` that is not a PAR handle `request_uri_not_supported`, both redirected only to a registered `redirect_uri` (G12; plan §9 says why nobody should \"helpfully\" implement them later). Invariant 4 — no client registered today changes behaviour — is proved by the `P1`/`P2` twins and by an I4 twin on every negative test. `docs/admin/oidc-authn-parameters.md`; conformance rows 23–39 and 60–80. **Amended 2026-10-02 (T23.1.1).** Two clauses above overstated the gate, and an independent audit of the plan's §7 matrix found both. (1) \"`claims` left that list once §5.5 was implemented, because the list is the parameters AXIAM *drops*\" was true of the `userinfo` member only: `id_token.acr` is read by `honour::evaluate`, which runs on the honour lane, which a `fapi2` client can never be on — so a `fapi2` client asking for an **essential** `urn:axiam:acr:mfa` was served a token minted from whatever the session was, with no `acr` and no error, the downgrade OIDC Core §5.5.1.1 says to treat as a failed authentication, and plan row M3 verbatim. `AuthnRequestParams::security_bearing_present` now reports `claims` exactly when it asks for `id_token.acr` or cannot be read well enough to rule that out, so the `fapi2` gate answers `invalid_request` naming it; a `claims` asking only for `userinfo` members is still served, which keeps the FAPI suite's `test-claims-parameter-identity-claims` request shape unrefused. (2) \"`request` answers `request_not_supported`\" held at `/oauth2/authorize` and not at `/oauth2/par`, whose body had no `request` member: serde dropped it and the push answered `201`, so security-bearing parameters a client put inside a request object — which RFC 9101 §6.3 tells it is the only copy the server uses — reached neither the `fapi2` gate nor the honour lane. PAR now refuses a non-blank `request` with `request_not_supported` through the same `classify_request_object` the authorization endpoint uses, before client authentication. Tests: `fapi.rs::a_fapi2_client_may_send_claims_for_userinfo_but_not_for_id_token_acr` and the restored M3 rows; `par_test.rs::a_fapi2_client_is_refused_what_it_pushed_exactly_as_what_it_sent_inline` (the gate on the pushed carrier over HTTP, with its I4, `userinfo`-only and P2 twins), `::a_request_object_pushed_to_par_is_refused_with_request_not_supported`, `::a_fapi2_row_edited_to_honour_in_the_database_is_refused_at_authorize` and `::a_repeated_authentication_parameter_is_refused_on_both_carriers`. Nothing changes for a `standard` client on either lane. **Amended 2026-10-03 (T23.1.4, D-12).** One more `claims` member was dropped on `fapi2` and is now refused. OIDC Core §2 makes `auth_time` REQUIRED in the ID token when it is requested as an **essential** claim, and a `fapi2` ID token has never carried it (`fapi::emits_session_evidence` is the honour lane only) — so a `fapi2` client sending `claims={\"id_token\":{\"auth_time\":{\"essential\":true}}}` was served a token without the claim it said it could not do without, and no error: the `id_token.acr` downgrade again, in the same parameter. `AuthnRequestParams::security_bearing_present` now reports `claims` also when `id_token.auth_time` is requested essential, or in a form that cannot be shown to be voluntary (neither `null` nor an object, or an `essential` that is not a boolean), so the `fapi2` gate answers `invalid_request` naming it, exactly as for `id_token.acr`. A *voluntary* `auth_time` request (`null`, or `essential: false`) is not refused: an OP may decline it (§5.5.1), so it is answered truthfully by omission, and `auth_time` under `userinfo` is not an ID-token request at all. The flag is not a parse error, so the honour lane (which emits `auth_time` for every session) honours an essential request as before and no honour-lane client starts being refused. Tests: `authn_params.rs::an_essential_auth_time_request_is_security_bearing` (with `::a_voluntary_auth_time_request_is_not_security_bearing` and `::an_essential_auth_time_request_is_never_a_parse_error`), `fapi.rs::a_fapi2_client_is_refused_an_essential_auth_time_and_only_that` and `::an_essential_auth_time_is_not_refused_off_the_fapi_profile`, the service-level gate in `oauth2_flow_test.rs::a_fapi_client_is_refused_the_security_bearing_parameters`, the pushed carrier in `par_test.rs::a_fapi2_client_is_refused_an_essential_auth_time_it_pushed`, and the honour-lane and ignore-lane twins `oauth2_honour_lane_test.rs::d12_an_essential_auth_time_is_honoured_on_the_honour_lane` and `::d12_i1_twin_an_essential_auth_time_is_still_ignored_on_the_ignore_lane`. No other client's behaviour changes. The same audit pinned, over HTTP, the honour-lane rows the suite had only at unit level: `id_token_hint` must be signed by this deployment and name this user and this client (an expired-but-signed one is accepted), `prompt=select_account`, and the ignore-lane twin for an essential `claims.id_token.acr`. **Amended 2026-10-03 (T23.1.4, D-14).** The clause \"`max_age=0` always demands a reauthentication whose return leg answers `login_required`\" was a design error, not a mitigation: `elapsed >= max_age` applied to `0` made the reauthentication the hop produces itself \"too old\" (`0 >= 0`), so a relying party sending `max_age=0` could never sign in, where OIDC Core §3.1.2.1 (errata set 2) re-authenticates only when the elapsed time is *greater than* `max_age` and says `max_age=0` is equivalent to `prompt=login`. `honour::evaluate` now takes `max_age=0` down exactly the `prompt=login` path and no path of its own: the outbound leg always interacts (`reauth=1`, no factor demanded), the return leg proceeds to a code whose ID token carries the new `auth_time`, a forged return-leg marker on an old session behaves exactly as it does for `prompt=login` (the interaction is skipped, which only the request's author could ask for, and `auth_time` still reports the old authentication truthfully; the accepted residual P23W1-08, unchanged), and `prompt=none` with `max_age=0` is `login_required`. Positive values keep `>=`, so an unmet positive `max_age` on the return leg is still `login_required` and `oidcc-max-age-1` is unaffected. Tests: `honour.rs::t2_1_max_age_zero_interacts_and_then_proceeds_exactly_as_prompt_login_does`, `::max_age_zero_and_prompt_login_cannot_drift_apart`, `::max_age_zero_under_prompt_none_is_login_required`, `::a_positive_max_age_that_the_sign_in_did_not_meet_is_still_login_required`; `oauth2_honour_lane_test.rs::t2_1_max_age_zero_reauthenticates_and_the_return_leg_yields_a_fresh_code`, `::d14_a_forged_marker_on_max_age_zero_cannot_make_an_old_session_look_reauthenticated`, `::d14_prompt_none_with_max_age_zero_is_login_required`, with the unchanged ignore-lane twin `::t2_1_i4_twin_max_age_zero_is_dropped_on_the_ignore_lane` and the `fapi2` refusal of `max_age`."
      },
      {
       "number": 255,
       "title": "An authorization error is delivered to the wrong place: redirected to an unregistered target, rendered as JSON to a person, or echoing attacker-chosen parameters on AXIAM's origin",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "RFC 6749 §4.1.2.1 draws the line at whether the server can trust where it would be sending the browser. It MUST NOT redirect when the `redirect_uri` is missing or does not match a registered one — the open-redirect case, where a direct answer is right — and it MUST deliver the error by redirect, with `state`, when `client_id` names a real client and the `redirect_uri` is one it registered, or the relying party waits on a response that never comes (the suite stalled its whole plan at module 2 of 35 on `oidcc-response-type-missing`). AXIAM answered the second case with a JSON body in the browser window, and answered the first with JSON too — informing a developer, and not the resource owner §4.1.2.1 says SHOULD be informed. An HTML page on AXIAM's own origin is then a reflected-content sink for `state`, `redirect_uri` and `request_uri`, and an `error_description` carrying `§` or an em dash violates §5.2's `NQSCHAR` grammar.",
       "mitigation": "0853e20: a known client with a registered `redirect_uri` receives the error by redirect with `state` echoed. The lookup uses `user.tenant_id`, never the query's `tenant_id` — a lookup that decides where a browser is sent is the worst place to reintroduce a tenant-crossing primitive — and the description stops naming `redirect_uri`, which was misleading in exactly the case that matters. dfcef2d and 13050d9: the direct-answer arms — all seven, including the three inside `resolve_authorize_principal` that build their own responses and were found by probing the live endpoint as a browser after the integration test had passed by authenticating first — render a page only on an explicit `Accept: text/html`; a missing header, `*/*` and `application/json` keep the JSON byte for byte, asserted directly, because content negotiation is only safe if the un-negotiated answer is untouched. The page renders the same `error` and `error_description` the JSON carries, escaped, and nothing else: no `state`, no `redirect_uri`, no `request_uri`, the rule `logged_out_page` already states applied to the endpoint that actually receives attacker-chosen parameters. The `build_error_redirect` branches beside them are untouched. 52ded73: `OAuth2Error::error_description()` — the one renderer every OAuth2 error passes through, and `dpop_error_response` routed through it — transliterates to `NQSCHAR` rather than stripping (`§` to \"section \", an em dash to a hyphen, anything else to a visible `?`), because a silently deleted character is an invisible change of meaning; enforced in one place rather than at hundreds of call sites written in a house style that cites specifications with `§`. The character-set test walks U+0000..U+00FF in both directions. The token, PAR and introspection endpoints are API endpoints and keep one JSON renderer. 2026-09-14: the same delivery rule now covers the two refusals that used to be decided only after a sign-in — a missing or unsupported `response_type` on a request without a `request_uri`, and a `request_uri` that is unknown, expired, spent or another client's — so `oidcc-response-type-missing` no longer stalls a plan at a sign-in page: redirected only to a registered `redirect_uri`, compared exactly, rendered in place otherwise, and the page still echoes nothing (T-270)."
      },
      {
       "number": 256,
       "title": "Inline parameters beside a PAR `request_uri` are read, or a pushed `request_uri` is accepted",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "RFC 9101 §5 lets a client duplicate the pushed parameters in the query string \"for backward compatibility\", and §6.3 says the server MUST only use the parameters in the request object even when the same parameter is provided in the query. AXIAM refused the combination — citing RFC 9126 §4, which says nothing of the sort — and failed every FAPI 2.0 authorization module. The security argument the refusal rested on, that merging is exactly where parameter confusion lives, is sound; but confusion needs the inline value to be *read*, and ignoring it satisfies the argument as well as refusing does. Beside it, PAR accepted a pushed `request_uri` (RFC 9126 §2.1-2) because the parameter was not modelled and serde dropped it, answering `201` to a request the specification says must be rejected.",
       "mitigation": "Every field comes from the pushed copy and nothing reads the inline value — `state` and `nonce` always did, and the nine OIDC authentication-request parameters, `dpop_jkt` (T-251) and the user's own refusal (T-259) follow the same rule, because a FAPI client sends `client_id` and `request_uri` and may send nothing else. `has_inline_params` is deleted rather than left unused, with a tombstone saying why the rule it encoded was not the one the specifications state, and the test that asserted the defect is inverted rather than supplemented, so the suite cannot claim both behaviours. A pushed `request_uri` is refused before client authentication: the refusal names a parameter the caller sent rather than anything about the client, so it is not an oracle. PAR errors are JSON at the route (RFC 9126 §2.3 makes the PAR error response the token endpoint's), since actix's form-deserialisation error fired before the handler was reached and a client cannot act on prose. Conformance rows 141–154. 2026-09-14, one clause: an inline `redirect_uri` beside a `request_uri` is still never read for authorization. It is read for exactly one thing — deciding where a *refusal* of that handle may be delivered — and only after the client's registration has vouched for it, which is RFC 6749 §4.1.2.1's own rule and the same one the `prompt=none` arm applies (T-270)."
      },
      {
       "number": 257,
       "title": "`login_hint` becomes an account-existence oracle, or `ui_locales` / `display` an injection into the sign-in page",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Wave W5 lets four cosmetic parameters reach the sign-in page. A `login_hint` that is looked up answers differently for an existing and a non-existing account, on an unauthenticated endpoint; a locale or display value forwarded raw is attacker-chosen text rendered on AXIAM's own origin; and `claims_locales` sits one parameter name away from `ui_locales`, which is how two adjacent names get confused.",
       "mitigation": "`login_hint` is carried verbatim and **nothing looks it up, on any path** — uniformity with respect to whether the hinted account exists is a property of there being no branch, not of two branches kept equal (T5.1 asserts whole-response equality for an existing and a non-existing hint). `ui_locales` is matched on the server by RFC 4647 §3.4 lookup, per requested tag in the relying party's order, against the five locales AXIAM ships, so the raw value never crosses into the SPA and T6.2 is true by construction rather than by escaping; `display` is allow-listed to the four OIDC Core values and anything else is dropped; `claims_locales` is accepted and ignored, and `Cosmetic::from_params` — the single call site of `select_ui_locale` — takes no `claims_locales` argument at all, which is the guard against the two being confused. The four decide no `Outcome` and never enter the honour evaluation; they are never *refused* on a `fapi2` row, since relying-party libraries send `login_hint` by reflex, but no `/login?login_hint=` is ever built for one. A CI gate fails when the server's allow-list and the SPA's locale bundles drift, and the SPA's typed catalogue makes a missing translation a compile error rather than a runtime fallback. `default_locale` at the settings API is refused for a tag this build does not ship. Conformance rows 81–89."
      },
      {
       "number": 270,
       "title": "A dead `request_uri` is discovered only after a sign-in, or the early read that prevents it spends the handle, authorizes from it, or reports the refusal somewhere the client never registered",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "`/oauth2/authorize` could not look at a pushed request while answering an anonymous browser: the handle is single-use and is spent in the handler, after a principal exists. So a browser presenting a `request_uri` that had already been used, had expired, or had been issued to a different client was sent to `/login`, the person typed a password, and the request was refused on the return leg — which the OpenID Foundation suite reports as a screenshot of a sign-in page where an error about an invalid `request_uri` was expected (`fapi2-security-profile-final-par-attempt-reuse-request_uri`, `-attempt-to-use-expired-request_uri`, `-attempt-to-use-request_uri-for-different-client`). The same shape held for a request with no `request_uri` and a missing or unsupported `response_type` (`oidcc-response-type-missing`). Refusing earlier creates its own ways to get it wrong. An early check that *consumed* the handle would spend it on a refusal path and break the case the specification requires — the same `request_uri` presented twice before the first authorization completes must still reach the sign-in page — and one that returned the pushed parameters would let a caller authorize from a handle it never consumed, which is the single-use guarantee T-163 exists for. And a refusal delivered by redirect is an open redirect unless the target was registered: the pushed copy's own `redirect_uri` is exactly what could not be read.",
       "mitigation": "2026-09-14 (616b731, ad1cb67). `ParService::peek` answers the three questions `consume` answers — is this a PAR handle at all, does an unexpired, unconsumed row exist for it, does it belong to this client — with the same refusals in the same order, and returns `()`: nothing is cached, marked or carried forward, and the authoritative single-use decision stays in `consume`, in the handler, in one statement. `PushedAuthRequestRepository::find_unconsumed` is `consume`'s `WHERE` clause with the write removed — no transaction, because there is nothing to serialise, and a read that raced a concurrent redemption is answered by that redemption failing. The endpoint runs it for an anonymous browser only after the client has been resolved and found to opt into the login hop, and only for a genuine PAR handle: a request object by value or by reference keeps the OIDC Core §3.1.2.6 code `classify_request_object` owns. `response_type` is decided first, without touching the datastore, and only when no `request_uri` is present, because with PAR the pushed value is authoritative (RFC 9126 §4). Both refusals are delivered exactly as the `prompt=none` arm of T-255 delivers its own: by redirect only to a `redirect_uri` this client registered, compared exactly, with the request's own `state`, and answered in place otherwise — as `error=invalid_request_uri` (OIDC Core §3.1.2.6), the code a relying party can act on by pushing again, while a handle issued to a *different* client keeps `invalid_request`, because a client spending someone else's handle is not a handle that is gone, and an audit trail that cannot tell the two apart is worth less. The post-login return leg was brought to the same rule (`refuse_request_uri_to_client`: one registration read, on a refusal path only, keyed by `user.tenant_id` and never the query's). What the peek costs, stated: one indexed datastore read per anonymous authorization request that carries a `request_uri`, on a route under the per-IP rate limit, keyed by a 256-bit CSPRNG handle that cannot be guessed — so the wrong-client refusal, distinguishable by design, is not an oracle anyone can drive. Tests: `peek` is proved never to call `consume` and never to touch the client registration (doubles that panic if it does); seven handler tests walk a spent, an expired and a wrong-client handle before the hop, a live handle presented twice, a request object by reference, and a dead handle with and without a registered target; two repository tests pin `find_unconsumed` reading without spending and ignoring an expired row. Measured per module with `run-some.sh` against the OpenID Foundation suite, the three PAR modules and `oidcc-response-type-missing` moved from `REVIEW` to `PASSED`; no full plan has been re-swept, so the published receipts remain the 2026-09-11 ones. Contract 1.46 §26.2 rule 3 records both forms of the refusal; no SDK changes, since rule 2's authorization URL carries no `redirect_uri` and never reaches the redirected form."
      },
      {
       "number": 278,
       "title": "RFC 8252's loopback port allowance widens a redirect registration by more than a port",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "T-52 is Critical because a loosely matched `redirect_uri` hands the authorization code to an attacker's origin, and until T21.2 the match was byte-for-byte everywhere, which is exactly right and unimplementable for a desktop client listening on a port the operating system chose at run time. RFC 8252 §7.3 requires the port to be free; the risk is that the relaxation is written once and relaxes something else with it — a host, a path, a userinfo segment — at the one comparison standing between an authorization code and an attacker's server.",
       "mitigation": "The allowance is applied only when the **registered** URI is `http` on `127.0.0.1`, `[::1]` or `localhost`; every `https` registration keeps exact matching (I6), because an `https` registration means the operator wrote a TLS endpoint down and a port is part of which endpoint that is. Everything but the port must still be identical — scheme, host, path, query, fragment, **username and password** — and the three loopback hosts each match only themselves, so a registration is never widened to a host the operator did not write. The non-loopback path compares the *strings*, byte for byte, so nothing existing changed. The doubled guard is what makes the classic attack uninteresting: `http://127.0.0.1@evil.example.com/callback` fails on the host and again on the userinfo. One function serves the authorization endpoint, PAR and code redemption, so the rule cannot be applied at one and forgotten at another, and the authorization code stores the **presented** URI so the token request's comparison stays exact against what was actually used. Driven against the live endpoint at the 2026-09-17 review (V1) with seven host, path, encoding and scheme spellings, including the two the review was asked to try."
      },
      {
       "number": 280,
       "title": "A desktop client on an ephemeral loopback port is never told its authorization failed",
       "type": "Denial of service",
       "severity": "Low",
       "status": "Mitigated",
       "description": "T-255 established that an authorization error must be delivered where the relying party can read it. T-278's matcher answers \"is this a registered redirect URI?\" for the success path and for refusals raised after it runs; six sites in `handlers/oauth2.rs` still ask with an exact comparison, and decide whether an error may be reported by redirecting. For a client that registered `http://127.0.0.1/callback` and is listening on an ephemeral port, the answer is no, and the error is rendered into the browser instead — so the client's loopback listener waits for a callback that never arrives while the user reads an error page the client cannot see.",
       "mitigation": "Closed in `b8bc508` (MCP-01, #472): Fail-closed in the direction that matters: no error is ever redirected to a URI that was not registered, so this was never an open-redirect finding and the exact comparison was the safe error to make. What it cost was interoperability, on exactly the client family Phase 21 exists to serve. Confined to refusals raised *before* the matcher runs — `response_type` absent entirely, and the `request_uri` refusals — which the 2026-09-17 review established by driving both the negative and the positive case after its first, wider, framing of the finding was contradicted by the harness. **Closed** (`b8bc508`), filed as MCP-01 (#472) against T21.2a: all six sites now call `any_redirect_uri_matches`, which is where the rule already lived precisely so that it could not be applied at one endpoint and forgotten at another. Ungated, and it needs no flag: the matcher short-circuits on string equality and takes the port allowance only when the *registered* URI is `http` on a loopback host, so the answer changes for one shape of registration and no other, and nothing that was refused becomes redirectable. `mcp01_an_error_is_not_redirected_to_an_ephemeral_loopback_port` was written to be inverted and was, to `mcp01_an_error_is_redirected_to_an_ephemeral_loopback_port`; a second case pins `refuse_request_uri_to_client`, the site furthest from the first.\n\nOne thing found while closing it, recorded because it was the last inconsistency in the same story rather than a new threat: `http://[::1]/…` could not be *registered* at all. `validate_redirect_uris` compared the parsed host against the bare `::1` while a URL parser returns the bracketed literal, so the matcher's tested `[::1]` arm was live code nothing could reach. Fixed in `7ab890d`, in its own commit because it is the one change in the group that makes a refused request succeed: the widening admits one host, reachable only from the machine the user is sitting at, and a routable IPv6 literal over `http` is still refused. A validator that refuses what its own error message says it allows is a defect, not a decision."
      },
      {
       "number": 290,
       "title": "A logout without a signed hint cannot end the session the browser's OP cookie names — or the route that can becomes an open redirect, a cross-tenant revocation or a wider logout CSRF",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The OP-session cookie is scoped to the authorization endpoint — `Path=/oauth2/authorize`, and since D-11 its per-tenant twin `Path=/t/{tenant_id}/oauth2/authorize` — so it never reaches `/oauth2/end_session`. An RP-initiated logout without an `id_token_hint` `sid` could therefore clear the cookie but not end the session row it named (F4 residual P23W1-10): the row stayed live for the rest of its lifetime, and a copy of the value taken before the logout — malware in the profile, a synced or exported cookie jar, a shared machine — kept buying authorization codes at every `browser_sso` relying party. Ending that row needs a route the cookie reaches, and such a route is a surface of its own: unauthenticated, reachable by any site's top-level navigation, it reads a credential, ends a session and then redirects.",
       "mitigation": "Mitigated in T23.1.8. **The hop.** `end_session` answers a request with no verified hint `sid` with a `302` to the `/logout` sub-path of the authorization endpoint it came through — `/oauth2/authorize/logout?tenant_id=…` on the deployment-wide path, `/t/{tenant_id}/oauth2/authorize/logout` on a per-tenant one — which RFC 6265 §5.1.4 path-match sends the copy scoped there, and which is the only place a logout is handled that the cookie reaches. The bounce sets no cookie, because a removal on it would be applied before the browser follows it. `end_session_at_cookie_path` looks the digest up **in the tenant the request names** (a tenant-A copy at B's hop names no session), revokes that one row, clears every OP copy for the tenant and the three API cookies, and continues exactly as `end_session`. A cross-site form `POST` to `end_session` is covered too: the `302` turns it into a top-level `GET`, on which a `Lax` cookie travels. **The continuation.** Only what `end_session` would itself have used — `post_logout_redirect_uri`, `state`, the effective `client_id` and, on the deployment-wide path, `tenant_id` — and never the hint. It is validated as there: the redirect only by exact match on the identified client's `post_logout_redirect_uris`, a client from another tenant naming no allow-list, `state` echoed only on a redirect that happens, nothing reflected into AXIAM's page; and a `tenant_id` parameter on the tenant hop is refused by the scope, as on every tenant path. **Safe defaults.** `GET` only; public in `PUBLIC_PATHS` on the ground `end_session` is (a logout must work for a session that is already gone); rate-limited with the `end_session` preset under its own `oauth2_end_session_cookie` bucket, shared by both mounts so alternating paths buys nothing; in OpenAPI. **Logout CSRF, unchanged.** AXIAM shows no confirmation prompt (RP-Initiated Logout §2 permits one; the B5 decision stands). A forged navigation to `end_session` already cleared every cookie the browser holds; the hop adds only the revocation of the row those cookies named, which nobody but that browser can observe — OAuth2 refresh grants do not depend on the row since schema v68. It therefore does **not** fan out back-channel logout: telling every relying party stays reserved for a request that names its session with a signed hint. **Residual.** A hinted logout ends the hinted session; if the browser's cookie names a different session (a second sign-in in the same browser), that row keeps its pre-T23.1.8 shape — cookies cleared, row orphaned and reachable only by a copy taken earlier. Tests: `oauth2_tenant_path_sso_test.rs::p23w1_10_end_session_without_a_hint_revokes_the_session_the_op_cookie_names` (bare and tenant), `::p23w1_10_the_cookie_hop_never_ends_another_tenants_session`, `::p23w1_10_the_cookie_hop_validates_its_continuation_as_end_session_does`, `::p23w1_10_the_cookie_hop_is_get_only_public_and_rate_limited`; `end_session_test.rs` follows the bounce in every no-hint case."
      },
      {
       "number": 447,
       "title": "A user access token minted for an OAuth2 client approves a device or CIBA request in its user's name",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Open",
       "description": "The routes on which a person approves a pending grant — the device grant's `POST /api/v1/device/decide` and CIBA's `POST /api/v1/ciba/requests/{id}/approve` and `/deny` — authenticate an `AuthenticatedUser`, which admits any `axiam:user` access token whose session is live: a console sign-in's, and equally one AXIAM minted for any OAuth2 client of the tenant through the code, refresh or CIBA grant. CSRF does not apply to a bearer token. A relying party holding such a token — even one granted only `openid` — can therefore approve on its user's behalf: a device authorization it started itself, since it chose the `user_code`, which mints for its device client that client's registered scopes and a refresh token without the user; and a CIBA request whose record id it knows.",
       "mitigation": "Narrowed by the W5 F4 review (P23W5-04 closed it for CIBA; P23W5-06 reports the device grant, where it is pre-existing since B2). CIBA: the approval routes refuse a token that carries a `client_id` — only a console sign-in decides (contract 1.58 §33 amended in place); test `crates/axiam-api-rest/tests/ciba_approval_test.rs` `a_token_minted_for_a_client_cannot_decide_a_request` (a CIBA client's own token, from an earlier redemption, opened and approved the next request before the fix); the record id travels only in the mail to the user, and every decision is audited with its session (T-435). The device grant: `/api/v1/device/verify` and `/decide` still admit it; bounded by the token itself (a live session of a user of the tenant) and by the device client's registered scopes. Closes when `/api/v1/device/*` applies the same rule (issue body in the W5 F4 review, §14)."
      }
     ],
     "open": 1,
     "notApplicable": 0
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
       "mitigation": "X5.1 adds RFC 8705 mutual-TLS client authentication: a client registered tls_client_auth or self_signed_tls_client_auth authenticates by presenting a certificate rustls verifies during the TLS 1.3 handshake, matched against the registration's subject DN / SAN or its x5t#S256 thumbprint. The private key never leaves the client, so the credential cannot be copied out of a log. The REGISTRATION selects which credential authenticates, never the request, so the two methods can never become an OR an attacker may pick from; and the X-Client-Certificate proxy header the device-auth path accepts is deliberately not a source here, because a client credential must not be assertable by anything that can set a header. Every failure returns one uniform invalid_client description (SEC-086), so client existence stays undecidable to an unauthenticated caller. Since 1.0.0-beta13 the listener can also admit RFC 8705 §2.2 self-signed certificates under a fourth, opt-in policy, and `tls_client_auth` then *requires* the certificate to have chained (T-263); the registered subject DN is compared, still exactly, against both correct renderings derived from the certificate, because the documented `-nameopt rfc2253` form never matched before (T-252)."
      },
      {
       "number": 169,
       "title": "Client assertion replay (private_key_jwt)",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "A private_key_jwt client assertion (RFC 7523 §2.2) is a bearer credential for whoever holds it until it expires. Anything that observes one -- a logging proxy, an APM trace that captures request bodies, a mis-scoped debug dump -- can present it again and authenticate as that client. Freshness alone does not stop this: `exp` only bounds how long the captured assertion stays interesting.",
       "mitigation": "`jti` is single-use and permanently so. Recording is a CREATE against `oauth2_proof_replay`, whose UNIQUE index over (tenant_id, kind, scope, jti) IS the 'already seen' answer -- there is no read-then-write, so two concurrent copies of one assertion cannot both pass the race #316/#318 closed for authorization codes. Assertion lifetime is additionally capped at 3600 s whether or not the client sent `iat`, so omitting an optional claim cannot buy an unbounded credential. A replay guard that cannot record refuses the authentication rather than failing open."
      },
      {
       "number": 170,
       "title": "Client assertion minted for another authorization server",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "A client that authenticates to several authorization servers signs an assertion for each. An assertion captured at (or by) one server is a valid signature by that client, and a server that does not check `aud` would accept it -- letting a malicious or compromised peer AS authenticate as the client here.",
       "mitigation": "RFC 7523 §3: `aud` must name this server (its issuer or its token-endpoint URL; both are accepted because OIDC Core §9 and RFC 7523 disagree about which, and refusing either is an interop failure with no security content). `iss` and `sub` must both equal the client_id per OIDC Core §9, so one registered client cannot mint an assertion authenticating as another."
      },
      {
       "number": 171,
       "title": "Algorithm confusion on a client assertion or DPoP proof",
       "type": "Spoofing",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "Both mechanisms verify a JWS the server did not mint. The classic forgeries are `alg: none` and RSA-public-key-as-HMAC-secret, and both are the same bug: the token told the verifier how to check the token. A verifier that reads `alg` from the JWS header lets an attacker choose the verification path.",
       "mitigation": "`axiam_oauth2::jose` derives the algorithm from the KEY MATERIAL -- the registered JWK for an assertion, the embedded JWK for a proof -- and then requires the header to agree with what the key already decided. A key declaring an `alg` inconsistent with its material is refused rather than reinterpreted. Only PS256, ES256 and EdDSA are permitted; RS256 and symmetric keys are refused explicitly. `none` is unreachable twice over: jsonwebtoken::Algorithm has no such variant, and the permitted list would not contain it if it did."
      },
      {
       "number": 172,
       "title": "DPoP proof replay",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "A DPoP proof (RFC 9449) travels in a request header on every request, so it is observed by strictly more infrastructure than a client assertion is. A captured proof replayed within its freshness window would let the captor obtain or use a sender-constrained token without holding the private key -- which is the entire property DPoP exists to provide.",
       "mitigation": "Layered, because no single layer is sufficient. (1) `iat` must be within 60 s in both directions. (2) `htm`/`htu` bind the proof to one method and one URI, compared with query and fragment stripped and nothing else normalised. (3) `ath` binds it to one access token, so a proof cannot be re-aimed at another token held by the same key. (4) `jti` is recorded single-use at the token endpoint through the same UNIQUE-index guard the client assertion uses, with the row expiring exactly at the end of the freshness window. (5) `dpop_require_nonce` optionally makes a proof unusable before the server has spoken. KNOWN RESIDUAL: the resource-server path in `axiam-api-rest`'s extractor is synchronous and does NOT record `jti`, so within the 60 s window a proof for that exact method, URI and token could be presented twice there. Documented in the extractor and in contract §21.7.2; closing it means moving the check into middleware that can await. **Residual closed at 1.0.0-beta13:** the resource-endpoint extractors now record `jti` in their async tail through the same replay repository the token endpoint writes (T-247, T-248), and `htu` is compared after RFC 3986 syntax- and scheme-based normalisation as §4.3 asks — `:443`, host case and a `..` segment no longer produce false negatives, an unparseable `htu` is compared raw on both sides, and a URI naming a different resource is still refused."
      },
      {
       "number": 240,
       "title": "A refresh or a replayed upstream SSO session is dated as a fresh authentication",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "`auth_time` says when the end user authenticated, and `amr` how. `session.created_at` cannot stand in for it because refresh rotation writes a new session row on every refresh, and a code's evidence cannot be looked up at redemption because by then the session it came from may be gone. A federated login dated by AXIAM's clock records a provider session established hours ago as having just happened; a refreshed ID token that restamps `auth_time` violates OIDC Core §12.2; and an evidence record whose absence reads as *stronger* would upgrade every pre-migration session.",
       "mitigation": "Wave W2 (schema v55): `session.authenticated_at` and `session.amr` — a closed RFC 8176 enum rather than a free string, so a typo at one of the five login call sites is found by the compiler rather than by a relying party, and unknown stored values decode to nothing. The authentication event is recorded at the one choke point, `create_session_and_tokens`, whose callers pass what they actually verified: `pwd`, `pwd otp mfa`, `pwd hwk mfa`, `hwk user` (usernameless passkey, which requires user verification unconditionally) or `fed`. Federated logins are dated by the upstream provider — OIDC `auth_time`, SAML `AuthnInstant`, carried across the 60-second handoff hop on the handoff row — and fall back to the moment AXIAM verified the assertion only when the provider asserted no instant. Refresh rotation **copies** the evidence rather than restamping it; the authorization code snapshots it at issuance (a snapshot, not a join, because rotation replaces the row). Every column is optional with no backfill, and the decode path leans strict: an absent `authenticated_at` reads as `created_at`, an absent `amr` as the empty list, so a pre-migration row can be judged staler and weaker than it was, never fresher and stronger. The claims are emitted only for a client on the honour lane (`fapi::honours_authn_params`) and for nobody else — pinned for every `ignore` client and every `fapi2` row at either setting — and a refreshed ID token reports the class the session proves. `session_evidence_rotation_test` (two rotations, the event never moves); conformance rows 40–46. **Amended 2026-10-02 (T23.1.2, D-9).** A refreshed ID token no longer \"reports the class the session proves\": that read the session row the code was issued under, and `AuthService::refresh` deletes that row at every browser-session rotation, so after the first one an honour-lane client's refreshed token lost `auth_time`, `acr` and `amr` altogether (OIDC Core §12.2 wants the original). The evidence is now snapshotted on the OAuth2 refresh token (schema v68, three optional columns, no backfill), written at code exchange from the **code's** snapshot and copied verbatim at every OAuth2 rotation, so a refreshed token attests the original authentication whatever happened to the session; a grant issued before v68 falls back to the old live-session lookup and is no worse off. Emission is gated exactly as before (honour lane only; `fapi2` and `ignore` clients receive nothing). Covered by `d9_a_refreshed_id_token_keeps_the_original_evidence_after_the_session_rotated_away` and the `d9_*` tests in `token_service`. **Amended 2026-10-02 (T23.1.2, D-10).** \"Dated by the upstream provider\" had no upper bound: an IdP whose clock ran ahead of AXIAM's, or one replaying a crafted `auth_time`/`AuthnInstant` in the future, produced a session whose `authenticated_at` post-dated the moment AXIAM verified the assertion. `max_age` would then be satisfied by an authentication that had not yet happened by AXIAM's clock, and the emitted `auth_time` would post-date its own `iat`. The recorded instant is now `min(upstream instant, verification instant)`: `AuthenticationEvidence::upstream` takes the verification instant as an explicit argument, and the SSO callbacks bound the instant at the moment the assertion is verified — before it is carried across the 60-second handoff hop — so the evidence is never later than the moment AXIAM checked the assertion. A past instant is kept as asserted; an instant within the federation path's existing clock-skew allowance (`CLOCK_SKEW_LEEWAY_SECS`, 60 s) is clamped silently; one further ahead is clamped and logged at `warn` naming the identity provider. No new configuration. Covered by `a_far_future_upstream_instant_records_the_verification_instant`, `an_upstream_instant_inside_the_skew_allowance_is_clamped` (`axiam-core`), the `bound_upstream_auth_time` tests in `handlers/federation.rs` and `d10_a_far_future_upstream_instant_is_stored_as_the_verification_instant`."
      },
      {
       "number": 251,
       "title": "An authorization code is redeemed by a DPoP key other than the one it was pinned to",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "RFC 9449 §10 lets the authorization request bind the grant to a key (`dpop_jkt`), so a code observed in transit cannot be redeemed by a thief presenting a proof from a key of their own. AXIAM never recorded which key an authorization was pinned to, so there was nothing for the token endpoint to compare a proof against: the happy-path FAPI modules passed by accident, and `ensure-mismatched-dpop-jkt-fails` received a `201` from a PAR endpoint dropping both carriers on the floor.",
       "mitigation": "246c163. §10.1 requires an authorization server supporting both PAR and DPoP to accept two carriers — `dpop_jkt` in the PAR body or on a plain request, and a `DPoP` header on the PAR request, whose key thumbprint the server \"MUST further behave as if\" had been sent as `dpop_jkt` — and the PAR endpoint resolves them into one binding under client authentication, refusing a contradiction with `invalid_dpop_proof`. The value rides the pushed parameters to the authorization endpoint, read from the pushed copy and never a query-string copy for the same reason `state` and `nonce` are (T-256), and is snapshotted onto the code (schema v58, one optional column, no backfill). At redemption a code whose bound key the request has not proven possession of is refused `invalid_grant`, not `invalid_dpop_proof`: the proof is perfectly valid — signature, `htm`, `htu` and freshness all check out — and what fails is the grant, bound to a key this caller cannot demonstrate; the other code would send an honest client debugging its proof generation over a code it should simply push again. The check sits beside PKCE, *before* the code is consumed, on PKCE's own argument: a caller who cannot satisfy it must not be able to burn a valid code by failing it deliberately. `verify_dpop_header` is extracted so PAR runs the §4.3 proof check from one copy. Four of the nine tests state the non-regression claim directly: a code that carries no binding, and a push that used neither carrier, are answered exactly as before — the property that matters for every client registered today, none of which sends the parameter."
      },
      {
       "number": 252,
       "title": "The strong client-authentication methods were registrable and unusable, inviting a fall-back to a shared secret",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "Three defects, each a strong method that no conformant request could use. `tls_client_auth` compared the registered `tls_client_auth_subject_dn` only against `x509_parser`'s rendering of the subject, and the operator guide's `openssl x509 -nameopt rfc2253` form never equals it — RFC 2253 emits the RDNs in reverse of their encoded order, and the separators differ — so every client onboarded as documented authenticated nothing (89 FAPI module failures, all at PAR). `private_key_jwt` was implemented and wired to nothing: `JwksAssertionVerifier` was constructed nowhere, so no client in any deployment could use one of FAPI 2.0's two client-authentication families (all 56 modules of that lane). And a request carrying only a `client_assertion` was refused \"client_id is required\", though RFC 7521 §4.2 makes it optional and OIDC Core §9 makes the assertion's `sub` the identifier. A strong method that cannot work is pressure toward the shared secret that can — and a test that compared the server against its own rendering passed throughout.",
       "mitigation": "The DN exact match is kept — the comment that \"a normalising comparison is exactly where DN-matching CVEs live\" stands, so nothing normalises the registered value. Instead the server derives **both** correct renderings of the name from the certificate, and the registered string must equal one of them exactly: no case folding, no whitespace stripping, no structural comparison. The RFC 2253 form is built by rendering each RDN individually and joining the reversed list on `,` — reversing the formatted full string would have split a value containing an escaped comma, the very failure the comment warns about — and the new test uses a two-RDN certificate, because a single-RDN name renders identically both ways and cannot observe an ordering difference at all. The assertion verifier is wired with the **federation** JWKS cache, deliberately and not one of its own: a client's `jwks_uri` is the same SEC-054 SSRF surface whichever feature asked for it, and a second cache would be a second place for a guard to go missing (T-173). Wiring alone would have made three passing modules fail, because FAPI 2.0 §5.3.2.1 narrows RFC 7523's audience rule to the issuer identifier, as a string, only; `verify_client_assertion` takes an `AudiencePolicy` — `IssuerStringOnly` for a `fapi2` client, refusing an array even when it *contains* the issuer, `AnyOf` (issuer or token-endpoint URL, string or array) for everyone else, since RFC 7523 §3 and OIDC Core §9 disagree and refusing either is an interop failure with no security content. `client_id` is optional beside an assertion, and `unverified_client_id` reads `sub` from a JWT nobody has checked for the one thing that is safe: the row it names is loaded and the assertion is then verified against *that* row's registered key, so naming somebody else only picks the key the forgery will be checked against — a routing hint, never a credential; the pre-lookup credential guard three grants copied now lives in one place, `TokenRequestContext::carries_no_client_credential`. A missing DPoP proof is `invalid_dpop_proof` with `400` (RFC 9449 §5), not `invalid_client` with `401`: the client authenticated, what was missing was the proof; the certificate branch keeps `invalid_client`. Every test pins the operator-facing contract rather than the server's own rendering."
      },
      {
       "number": 253,
       "title": "`client_secret_basic`: the header reaches a log, the RFC 6749 §2.3.1 decoding is wrong, or a client gets two ways in",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Wave W8 (G9) adds HTTP Basic client authentication as a fifth registrable `token_endpoint_auth_method` — escalated as decision A of the Basic OP plan and decided yes by the maintainer on 2026-09-07, because 37 of the 38 modules of the OpenID Foundation's Basic OP plan use it and there is no badge without it. Three failure modes travel with it: the classic omission of the form-urlencode step in §2.3.1's encoding, invisible against server-generated secrets; an `Authorization` header, which is the channel intermediaries routinely log; and a second channel carrying the same credential, which is an OR an attacker may pick from (SEC-093).",
       "mitigation": "The decoding is base64, split on the **first** `:`, then `application/x-www-form-urlencoded`-decode each half, with the fixture secret `p%a+s:s` so the last step cannot be skipped unnoticed; it is hand-written in `axiam-oauth2::client_secret_basic` rather than routed through `url::form_urlencoded::parse`, which also splits on `&` and `=`. `Authorization` reaches no log: asserted at TRACE over a successful request, a rejected one and one refused at the edge, grepping for the secret, its encoding, the base64 blob and the header value; `BasicCredentials` hand-writes a redacting `Debug`, and a second test pins that the request-logging layer is `TracingLogger::default()`, which has no header allow-list to add the header to. The registration decides which channel carries the credential, never the request: a body `client_secret` on a `client_secret_basic` client is `invalid_request`, ordered *after* the header credential verifies so that SEC-086's undecidability of client existence survives; an `Authorization: Basic` header on a `client_secret_post` client is ignored and logged at `warn`, never a second way in. `client_id` may arrive in the header alone, and a disagreeing pair is refused before the client lookup so no existence oracle is created; the RFC 6749 §5.2 challenge is applied by wrapping the four handlers rather than at their ~35 error sites. The FAPI gate needed no new code — `validate_registration` and `enforce_token_request` ask `is_strong()` rather than enumerating variants — so a `fapi2` client is refused it exactly as it is refused `client_secret_post`. **No SDK sends it**: `sdks/CONTRACT.md` §5 rule 3 keeps its MUST NOT verbatim (contract 1.41, T-266). Residual, and where it lands: the header is protected from AXIAM's own logs and nothing in front of AXIAM — `docs/admin/fapi2-profile.md` says to audit what the ingress logs before enabling it, and the broader class of a long-lived secret in the wrong place is T-146. **Amended 2026-10-03 (T23.1.5).** An independent audit of this entry against the shipped code found one clause untrue. “a second channel carrying the same credential” was closed for authentication and not for **throttling**. The rate-limit layer in front of `/oauth2/token`, `/oauth2/revoke` and `/oauth2/introspect` derived the bucket's client identity from the form body alone, and RFC 6749 §2.3.1 lets a `client_secret_basic` client name itself in the header alone, which 37 of the Basic OP suite's 38 modules do. Under `AXIAM__RATE_LIMIT__KEY=client_id` or `ip_client_id` such a request fell back to the per-address key, so a Basic client had no per-client bucket and its secret could be guessed from as many addresses as the guesser held, where the same client registered for `client_secret_post` was throttled as one. The default key mode, `ip`, was never affected. The layer now takes the form's `client_id` and, when there is none, the `client_id` the Basic header decodes to, through `axiam_oauth2::client_secret_basic` itself so that the throttle and the handlers cannot disagree about what a header names. The secret half is never read for this purpose and nothing is logged. The form wins when both are present, and a pair that disagrees is refused by `resolve_client_id` before any secret is compared, so the disagreement cannot be used to guess under a bucket the caller is not charged to. Test failed first: `t23_1_5_a_basic_clients_wrong_secrets_share_the_same_bucket` saw four `401`s where its control, `t23_1_5_control_a_post_clients_wrong_secrets_share_one_bucket_across_addresses`, sees three and a `429`. The audit also pinned, with no code change: the §2.3.1 decoding at its edges (`%3A` in the id, `%2B`, `%2b` and a raw `+`, `&` and `=`, non-ASCII raw and encoded, a colon in the secret, an empty half, unpadded and URL-safe base64, the scheme's case, extra spaces, and two `Authorization` headers refused rather than resolved by position); the registered method deciding at the three ordinary token grants as well as at the five endpoints SEC-093 named; and the `fapi2` refusal at registration through the admin API's create and merged-update paths. **Residual closed by D-17 (2026-10-03).** The request-time `is_strong()` gate ran at the token endpoint and at its token-exchange and uma-ticket grants, and not at PAR, introspection or revocation, so a `fapi2` row edited in the database to a shared-secret method still authenticated at those three, for `client_secret_basic` exactly as for `client_secret_post`, with registration validation as the only line. The rule is now `fapi::enforce_client_authentication`, extracted from `enforce_token_request` so that there is one copy, and it runs at `/oauth2/par`, `/oauth2/introspect` and `/oauth2/revoke` after client authentication succeeds and before anything is pushed, revealed or revoked, with the token endpoint's `invalid_client` and `error!`. It is only that rule, not the whole of `enforce_token_request`, because the rest asks for a DPoP proof those endpoints do not verify before authentication and would refuse a legitimate DPoP-bound client. The refusal comes after authentication, so it tells a caller without the credential nothing (`d17_a_wrong_secret_learns_nothing_from_the_gate`); RFC 7009 §2.2's “an invalid token is a 200” and a strong `fapi2` client are untouched (`d17_a_strong_fapi2_client_still_revokes_and_introspects`). Tests, failed first (PAR answered `201`, introspection and revocation `200`, and the service reached `revoke` on the tampered row): `d17_a_tampered_fapi2_row_is_refused_at_par_introspection_and_revocation` in both channels with a standard-profile control, and `d17_revoke_and_introspect_refuse_a_tampered_fapi2_row_after_it_authenticates`. No new threat id."
      },
      {
       "number": 254,
       "title": "A leaked refresh token replayed inside the rotation grace window forks the session undetected",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "FAPI 2.0 Security Profile §5.3.2.1-9 requires an authorization server that rotates refresh tokens to keep accepting the previous one for a period after issuing its successor — the only recovery a client has from a rotation response lost in transit, since under immediate revocation it holds a token the server has destroyed and has not been given the replacement. Commit 065f37c implemented that as a **supersede** — the old token's `expires_at` brought forward to a 60-second grace instant — and applied it to every client on every profile. Inside that window a second presentation was answered `200` and rotated again, so a refresh token leaked at the moment of a legitimate rotation yielded a second live chain, and nothing distinguished the thief's use from the honest retry. The profile that requires the window sender-constrains every token; the `standard` profile, which does not, had been given the same window.",
       "mitigation": "Mitigated by the maintainer's decision of 2026-09-12, which is two things and needed both. **The window is now a `fapi2` behaviour.** `axiam_oauth2::fapi::refresh_rotation_grace_secs` is the gate — the same registration-decides mechanism as `auth_code_lifetime_secs`, not a second one — and `TokenService::refresh` picks a retirement lane from it: `supersede` for a `fapi2` client, `revoke_rotated` for every other, which is the pre-065f37c behaviour (`invalid_grant`, \"already consumed\", on a second presentation). What remains on `fapi2` is a 60-second window in which the previous token is redeemable by a client that also holds the private key every token on that profile is bound to. **And a replay is now marked whatever the window.** Both lanes stamp `rotated_at` in the same statement that retires the row (schema v60, additive, backfilling nothing), so a presentation of a rotated token is distinguishable from an ordinary stale credential — `find_rotated` answers `None` for one revoked at logout. Every such presentation, accepted under the grace or refused, increments a per-outcome counter on the session the token names and appends an `oauth2.refresh_token_replayed` audit row naming the client, its profile, the session and the disposition, never the token or its digest; `GET /api/v1/users/{user_id}/sessions` serves the derived verdict and the admin UI renders \"FAPI grace retry\" and \"Replay refused\" as two visibly different badges. The single-use race is untouched: both lanes keep `revoked = false AND expires_at > time::now()` in the WHERE, so the loser of two concurrent rotations still gets `NotFound`. A password or MFA reset still revokes the whole family through `revoke_all_for_user`, and T-249's `sid` extends that to the access tokens in flight. Pinned by the `t254_*` tests in `axiam-oauth2/tests/token_service.rs` and `fapi.rs`, by `refresh_token_rotation_retires_old_on_a_standard_client` and `a_refused_refresh_replay_is_audited` in `oauth2_flow_test.rs`, and by the invariant-4 twin each of them carries."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
       "mitigation": "Claims are filtered by the token's granted scopes; profile, email and groups claims each require their corresponding scope. Since 1.0.0-beta13 the `profile` scope releases the full OIDC Core §5.1 claim set — SCIM attributes first, `metadata.oidc` as the fallback for every claim, `updated_at` from the row's own column as a NumericDate — and §5.5's `claims` parameter is honoured for its `userinfo` member, parsed and filtered at the authorization endpoint, stored on the code and carried in the token as `axiam_requested_claims`. Neither can unlock `phone_number`, `phone_number_verified` or `address`, which sit behind the consent gates of T-241 (`claims_request::RELEASABLE`)."
      },
      {
       "number": 241,
       "title": "A postal address or telephone number is released by naming the claim, from a token issued before consent was withdrawn, or inside an ID token",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "OIDC Core §5.4's `address` and `phone` scopes release data AXIAM holds for no purpose of its own — nothing authenticates against them, nothing is sent to them — so they exist only to be released to a relying party the end user has agreed to. Three ways past a consent ceremony: §5.5's `claims` parameter naming the claim directly; a release decision taken once at authorization that outlives a withdrawal for the access token's fifteen minutes and the refresh's thirty days; and the ID token, a long-lived artefact relying parties log and cache. A fourth is a client on a profile that collects no consent record at all.",
       "mitigation": "X7 G8 / wave W7: four gates, each closed by a different party — the **organization** enabled `sensitive_scopes_enabled` (off by default, and the settings model's only *disable*-only field: a tenant may refuse a release its organization allows and never authorise one it forbade); the **operator** registered the scope on the client, checked on create and on the merged update path because a gate that only runs on create is a gate with a PATCH around it; the **end user** consented, per client and per exact scope set; and the client is not on the `fapi2` profile, refused at registration, at the authorization endpoint (M8) and at UserInfo (M10) — even against a hand-written consent record the API would have refused to create. All four are re-asked **at every UserInfo call**, so withdrawal is effective on the relying party's next request with the token it already holds (T8.4 uses the byte-identical token before and after). Claims are returned from UserInfo only and never in the ID token (T8.3 decodes the ID token a relying party actually receives). `claims_request::RELEASABLE` cannot unlock `phone_number`, `phone_number_verified` or `address` for anybody, FAPI or not: the filter runs at the authorization endpoint and is asserted again at UserInfo against a token minted as though it had been bypassed, because that endpoint is the one that would leak. A release is audited by claim **name** and never by value, since the audit log is append-only and is itself exported under Art. 15 (T8.6). The Art. 7 self-service surface is new — `GET /api/v1/account/consents`, `POST`/`DELETE …/oidc-scopes` — withdrawal is one call with no confirmation and no grace, and it is namespaced `oidc_scope_release:` so it can never reach a `terms_of_service` row. A token naming no relying party — every token issued before this wave — releases nothing, and nothing registered earlier changes behaviour, structurally: the scopes were unregistrable. The requested claims now ride the refresh token too (R-2, schema v61): the code exchange writes the list onto the refresh token it issues, rotation copies it onto each successor exactly as it copies `session_id`, and the refreshed access token asserts the same `axiam_requested_claims` the code-exchanged one did — so a refreshing client no longer loses consented claims fifteen minutes after the consent was given, which it had to start a whole new authorization to recover from. This carries a **request**, never a release decision: `claims_request::RELEASABLE` still runs only at the authorization endpoint, the refresh path copies and never widens (asserted against a hand-built row naming `phone_number` and `address`, which the endpoint above still refuses), and all four gates are re-asked at every UserInfo call as before. Additive with no backfill: a refresh token issued before v61 decodes to no claims and mints exactly the token it minted before. `docs/compliance/gdpr-compliance.md` §3.1; conformance rows 104–129."
      },
      {
       "number": 242,
       "title": "The ID token carries identifiers nobody asked for, and travels further than the relying party",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The ID token carried `tenant_id`, `org_id` and — under `scope=email` — `email`. The OpenID Foundation suite objects by name in both lanes and states the consequence rather than the rule (OIDC Core §5.4): an ID token is often forwarded as proof of an authentication event, so anything in it travels further than the relying party that asked for it. The reverse defect sat beside it — UserInfo withheld `email_verified`, `name`, `given_name` and `family_name`, which AXIAM held all along.",
       "mitigation": "The three claims left the ID token (065f37c). `sdks/CONTRACT.md` binds both identifiers to two other places that do not move — an SDK resolves them from the access-token claims returned by login, and `UserInfo { sub, tenant_id, org_id, … }` still carries both — so the ID token was a third copy nothing was specified to read; `preferred_username` deliberately stays, which §5.4 permits. The member list is pinned exactly (`an_id_token_with_no_evidence_has_exactly_todays_claim_set`, `t2_6_…`), so `auth_time`, `acr` or `amr` appearing for an `ignore` client still fails. UserInfo now emits what the OP can assert and omits what it cannot rather than inventing it (§5.3.2): `email_verified` from `email_verified_at`, the SCIM-provisioned names, and since c4bdefd the full §5.1 `profile` set read SCIM-first with `metadata.oidc` as the fallback (T-58)."
      },
      {
       "number": 243,
       "title": "A UserInfo POST authenticated by a cookie answers a cross-site form, or logs the token it carried",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "OIDC Core §5.3 requires UserInfo to accept POST, and RFC 6750 §2.2 lets the access token travel in the form body. `/oauth2` carries no CSRF middleware and the cookie is read before the header, so a route that accepted a cookie-authenticated cross-site form POST would return personal data to any page that submitted one; a form field is a place a token gets logged; and a token accepted from the query string is a credential read out of a URL.",
       "mitigation": "Wave W6 (G10): `/oauth2/userinfo` is one resource with two routes, deliberately without the scope's rate-limit wraps — every wrapped endpoint there is unauthenticated and allocates or terminates state, UserInfo does neither, and a limiter would change what GET does under load. The token is accepted from the `Authorization` header or, on POST only, from an `access_token` form field; a request carrying more than one credential is refused `400 invalid_request` and the refusal reads neither of them; an `access_token` query parameter is never read on either method (RFC 6750 §2.3 — refusing it would mean reading a credential out of a URL first). A cross-site cookie POST fails closed because `axiam_access` is `SameSite=Strict`, and since that is a property of the cookie the test pins the attribute and then asserts that a same-site cookie POST *does* authenticate, so the pin cannot pass against a route that stopped reading the cookie. `UserInfoPostForm` hand-writes a redacting `Debug`, and a TRACE capture over a successful and a failed POST asserts that neither the token nor its signature segment appears. GET is unchanged as a property of the routing table — the POST handler resolves the carrier and delegates to the body GET calls, `AuthenticatedUser`'s extractor is untouched, and whole-response equality between the two is asserted. DPoP needs no method-specific branch: `htm` is built from the request method, so a proof minted for GET is refused on POST; a certificate-bound token presented without a certificate is refused on POST identically to GET. `POST /oauth2/authorize` (G11) is declined and the reason recorded with a revisit condition. Conformance rows 90–103."
      },
      {
       "number": 244,
       "title": "Tenant-scoped discovery becomes a tenant-enumeration oracle, or a default tenant becomes a handler fallback",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The discovery document advertised endpoints that could not be used at the URLs it advertised: every endpoint that authenticates a client takes a required `?tenant_id=`, `/oauth2/authorize` needs one for any browser arriving from a relying party, and the document published all of them bare — so no third-party discovery-driven client could complete a flow against AXIAM, which is the problem discovery exists to solve. Each of the two fixes opens a door of its own: a document that varies by tenant can be probed for which tenants exist, and a \"default tenant\" applied at the endpoint would silently give an unparameterised request a tenant on a multi-tenant authorization server where the tenant *is* the isolation boundary.",
       "mitigation": "Discovery takes an optional `tenant_id`. A caller that omits it receives exactly the document it received before; an unknown tenant is answered identically to a known one except for the single caller-supplied value the document now echoes — asserted by normalising that one value away and requiring the two documents to match exactly, so a leak anywhere else still fails — and the sensitive scopes and their claims are advertised only for a tenant that has them enabled. The endpoint URLs carry the tenant they describe (RFC 6749 §3.1 and §3.2 allow a query component and require clients to retain it), from the caller's `tenant_id`, else from `AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID`. That default **states a fact in a document; it is not a fallback in a handler**: no endpoint's behaviour changed, a request arriving without `tenant_id` is refused exactly as before, and a deployment that sets nothing serves the document it served before, with no endpoint gaining a query string (`a_document_that_names_no_tenant_carries_no_query_string`). `userinfo_endpoint`, `jwks_uri` and `issuer` stay bare — UserInfo resolves its tenant from the token, the JWKS is deployment-wide, and an `issuer` carrying a query would stop matching every token's `iss`. An unparseable default is treated as unset, deliberately the opposite of the mTLS alias's fail-closed refusal (T-245): a missing tenant only fails to help a client, while a bad alias actively misdirects one. That choice stands and the silence around it does not (R-3, 2026-09-12): one `WARN` at boot, beside the other posture lines, names the variable and says what will happen — the document served is the one served with the variable unset, and no endpoint URL carries a tenant. It describes the value's **shape**, its length and whether its characters could belong to a UUID at all, and never the value, because a variable this code cannot prove holds a tenant id is one it cannot prove is safe to print; and it is never logged on the request path, where the accessor runs per discovery request and a warning would be a log flood any anonymous caller could drive. The document is unchanged in every configuration, asserted byte for byte over the whole serialisation against the unconfigured case (`an_unparseable_default_tenant_serves_the_unconfigured_document`). The same first conformance run found two RFC 8414 members missing that described behaviour AXIAM already had — `code_challenge_methods_supported` and `token_endpoint_auth_signing_alg_values_supported` — and RFC 8414 defines no default for either, so silence read as \"unsupported\"; the second is derived from `jose::permitted_algorithm_names()` through an exhaustive match, so widening the verifier's list stops compiling until the wire name is spelled (contract 1.42 §21.5)."
      },
      {
       "number": 245,
       "title": "A misconfigured mTLS alias routes clients to the wrong host, or the front channel is aliased",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "RFC 8705 §5 `mtls_endpoint_aliases` instructs a conforming client to switch hosts. AXIAM implemented both halves of RFC 8705 and published no §5 metadata, so a deployment terminating mTLS on a separate host — the only shape one TLS listener allows, since it decides whether to request a certificate before it has seen a byte of HTTP — had to pass client configuration out of band. Publishing the member wrongly misdirects every mTLS client; dropping it silently on a bad value routes them to the conventional endpoints, the one outcome the setting exists to prevent, indistinguishably from a deployment that has no mTLS host; and aliasing the front channel makes a browser raise a certificate-chooser dialog most users cannot answer.",
       "mitigation": "`AXIAM__AUTH__OAUTH2_MTLS_BASE_URL` adds aliases for the six back-channel endpoints — token, userinfo, revocation, introspection, device authorization and PAR — each the top-level endpoint of the same name re-based on the mTLS host through one macro, so the two cannot drift. `authorization_endpoint`, `end_session_endpoint` and `jwks_uri` are deliberately not aliased (the first two authenticate the user and never the client; the third is public key material), and the `issuer` does not move because OIDC Core §2 requires it to equal every token's `iss`, including one minted at an alias. The member is absent by default and absence is correct — a present member instructs a client to switch hosts, so a single-listener deployment must emit none, including one running `client_auth = optional` — and it is omitted rather than serialised as `null`. A configured-but-unusable value, or one carrying a query or fragment, fails the discovery request with `500` rather than quietly dropping the aliases. Since b9232f3 the aliases carry the tenant (T-244): an alias tells an mTLS client it *must* use that URL, so one that omitted the tenant would be strictly worse than no alias. The conformance rig runs exactly this split — an nginx sidecar on the issuer for the front channel, the server's own rustls listener for the back channel — because `axiam_oauth2::mtls` refuses the `X-Client-Certificate` proxy header for OAuth2 client authentication by construction. Contract 1.40 §21.3 rule 2 is the SDK half (T-266)."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
      },
      {
       "number": 173,
       "title": "SSRF via a registered jwks_uri",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "A `private_key_jwt` client may register a `jwks_uri` that AXIAM fetches on demand to obtain the keys that authenticate it. That is an operator- or client-supplied URL the server will retrieve: pointed at a link-local metadata endpoint, an internal admin service or a loopback port, it turns client registration into a request forgery primitive against the server's own network. A DNS name that resolves publicly at registration and privately at fetch time (rebinding) defeats a naive validate-then-fetch check.",
       "mitigation": "The fetch goes through `axiam_federation::jwks_cache::JwksCache`, the SAME guarded path a federated IdP's JWKS uses -- not a bare reqwest::get. That guard (`ssrf::guarded_fetch`, SEC-054/SECHRD-02) resolves the host, rejects private, loopback and link-local addresses, and PINS the validated IP into the connection, which is what closes the rebinding TOCTOU. A 512 KiB body cap bounds the response. Registration additionally refuses a jwks_uri that is not absolute https, so the operator hears about the mistake while onboarding. Reusing one guard rather than writing a second is deliberate: two guards are two chances for one to miss a fix."
      },
      {
       "number": 174,
       "title": "Availability coupling to a client's JWKS endpoint",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A client registered with `jwks_uri` cannot authenticate if AXIAM cannot fetch its key set. Naively that makes every token request depend on a third party's uptime, and makes the token endpoint's latency a function of somebody else's TLS handshake.",
       "mitigation": "The shared JWKS cache serves keys for a 1-hour TTL without any HTTP, and serves STALE keys for a further 24 hours when the client's endpoint is unreachable rather than failing the authentication. An operator who wants no outbound dependency at all registers the key set inline as `jwks`; the operator guide says which to choose and why."
      },
      {
       "number": 258,
       "title": "A registration is edited into a weaker posture: a `fapi2` row set to honour, a sensitive scope on a `fapi2` client, or a scope-only patch that skips the merged validation",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Three per-client switches now share one registration — `profile`, `authn_request_params`, `browser_sso` — plus the sensitive scopes, and a client's posture is what its row says. A `fapi2` row edited to `honour`, a `fapi2` client registered for `address` or `phone`, or a scope-only PATCH validated against the *stored* scope list rather than the one about to be written, would each move a client onto a lane a test proves refused, without any request having been made.",
       "mitigation": "Wave W1's gates, in `fapi.rs`'s existing two-layer pattern: `FapiRegistrationError::{AuthnParamsOnFapiClient, SensitiveScopesOnFapiClient}` enforced on create **and** on update, at both handler call sites; `touches_security_profile` now covers `scopes`, so a scope-only patch costs the merged read it previously skipped instead of validating against the wrong list; a `fapi2` row somehow on `honour` is refused again at request time with `tracing::error!`. `reject_sensitive_scopes_when_disabled` is the tenant-switch gate, found missing while writing W7's tests — `validate_registration` is a pure function four layers below the settings row — and it runs on create and on the merged update, because a gate that only runs on create is a gate with a PATCH around it. `browser_sso` is permitted on a `fapi2` client by decision (plan §11 D2), and `m7_…` asserts the flag changes nothing about what a request may contain on either profile. The admin API echoes both new fields so an operator can audit the posture from the endpoint; pre-v54 rows decode to today's behaviour; and the `WeakClientAuth` gate asks `is_strong()` rather than enumerating variants, so the fifth authentication method needed no new refusal code to be refused."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
       "mitigation": "Two independent layers, the same pair the three credentials in T-163 carry (schema v37). The guarded UPDATE — used = false, with client_id and redirect_uri matched in the same statement so a wrong-client attempt cannot burn the code — runs inside an explicit transaction, so two concurrent redemptions conflict on one key and the engine aborts the loser; and a per-attempt redemption nonce is read back in a separate query after that transaction commits, catching a conflict the engine silently missed. Before v37 this path had the first layer implicitly (a lone statement runs in the engine's own transaction) and the second not at all, which left it resting on T-165 with nothing behind it. Guarded by authorization_code_consume_serialises over 50 rounds of 8 racers, and by an_authorization_code_redemption_stamps_its_nonce, which asserts the second layer directly — a race test cannot distinguish a two-layer mechanism from a one-layer one when the engine arbitrates either way. At 1.0.0-beta13 the conflict recogniser behind this branch was found not to match SurrealDB v3's own phrasing — fail-closed, so a refused replay surfaced as a `500` rather than as \"no row consumed\" — and the three phrasings now live in one marker set (T-262)."
      },
      {
       "number": 250,
       "title": "A replayed authorization code is refused, but the tokens it already minted keep working",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "RFC 6749 §10.5 asks two things of a code used twice: deny it, and revoke, when possible, every token previously issued on it. The denial half was thorough — single-use across two layers with a redemption nonce (T-54, T-164). The revocation half was absent: `revoke_after_code_replay` ran only when `consume` failed, but `get_by_hash` requires `used = false`, so a replayed code was refused one step earlier and the revocation fired for a race and for nothing else. An access token minted from a replayed code kept working, and the server logged nothing at all across a whole conformance run; both `oidcc-codereuse-30seconds` and FAPI's `attempt-reuse-authorization-code-after-one-second` proved it by presenting the first access token afterwards. FAPI 2.0 §5.3.2.1 additionally caps a code at 60 seconds, and AXIAM issued 600.",
       "mitigation": "a76161b and 065f37c: `AuthorizationCodeRepository::replayed_session` returns the session for a code that exists and is spent — `used = true` is what makes it a replay rather than a lookup, `client_id` and `redirect_uri` are matched so a caller presenting the wrong pair cannot revoke somebody else's session, and expiry is deliberately *not* filtered, because a replayed code that has since expired still minted tokens. Revocation reaches the session: an AXIAM access token is a stateless JWT, so what can be revoked is the session its `sid` names (T-249), which every resource request already checks. Two costs are stated in the code rather than glossed — the session is the browser session, so revoking it signs the user out of everything it reaches, admin UI included; and a legitimate client retrying after a lost `200` replays a code exactly as an attacker does. The server cannot tell them apart, which is precisely why §10.5's answer is to revoke rather than to guess. Not an oracle: both paths return the same `invalid_grant`, and a hash naming nothing revokes nothing; a replay costs one extra read and one write, distinguishable by timing only to an attacker who already holds a real code. The FAPI lifetime is a per-client cap taken as the minimum of the profile's 60 seconds and the operator's own setting — never a lower global default, which would shorten the window for every existing client to satisfy a profile none of them is on, and never a longer one, because a security profile must not make a deployment less strict."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
       "mitigation": "Two independent layers, so a double redemption needs both to fail (ilpanich/axiam#302). The guarded UPDATE runs inside an explicit transaction, making two concurrent redemptions a write-write conflict the storage engine aborts the loser of; and a per-attempt nonce is read back in a separate query after that transaction commits, so a conflict the engine silently missed is still caught. The read-back stays outside the transaction deliberately — inside one, snapshot isolation shows every racer its own write. Measured with tools/surreal-race-probe: zero double redemptions in 40 000 contended attempts on surrealkv and 9 600 on rocksdb. Layer one is a property of the storage engine, so the guarantee is conditional on running a persistent one — see T-165. authorization_code.consume carries the same two layers as of schema v37 (T-164). At 1.0.0-beta13 the conflict recogniser behind this branch was found not to match SurrealDB v3's own phrasing — fail-closed, so a refused replay surfaced as a `500` rather than as \"no row consumed\" — and the three phrasings now live in one marker set (T-262). 2026-09-14: `find_unconsumed` is a second reader of this store — `consume`'s guard clause with the write removed, spelled out rather than shared so the two stay identical in what they consider spendable — and it is a read only: `ParService::peek` refuses a dead handle before the login hop and never spends a live one, so nothing here changes which statement decides single use (T-270)."
      },
      {
       "number": 271,
       "title": "An unbounded `state` or `nonce` makes a pushed request a payload channel: kilobytes stored under a 60-second handle and reflected out of the client's `redirect_uri`",
       "type": "Tampering",
       "severity": "Low",
       "status": "Mitigated",
       "description": "`state` and `nonce` are opaque values the client chooses and the server only echoes, so length carries no meaning: 32 bytes of entropy is 43 characters base64url. What an unbounded value buys is a way to push kilobytes of chosen text through `/oauth2/par`, keep it in the `pushed_auth_request` row until the handle expires, and have it reflected into the authorization response — and into whatever the relying party does with `state`. The OpenID Foundation's FAPI 2.0 suite probes this boundary directly, with a 1000-character `state` and a 384-character `nonce`, and requires both to be refused (`ensure-authorization-request-with-long-state`, `-with-long-nonce`); AXIAM accepted both.",
       "mitigation": "2026-09-14 (ad1cb67). `ParService::push` refuses a `state` or `nonce` longer than `MAX_FAPI_OPAQUE_PARAM_CHARS` — 256 characters, counted as characters rather than bytes so the bound does not depend on how many non-ASCII code points an opaque value happens to contain — with `invalid_request`, checked at push, where the client is authenticated and the refusal is attributable and reaches it as a protocol error, rather than at `/oauth2/authorize`, where it would surface in a browser after a sign-in nobody should have been asked for. Gated on `ClientProfile::Fapi2` deliberately: a cap is a breaking change for a `standard` client that packs data into `state` — a bad practice, a widespread one, and one a deployment upgrading AXIAM has not agreed to — while the FAPI profile is where the stricter bundle was agreed and where the suite requires the refusal. A `const` block pins the cap against the suite's own probes and against what a conformant client sends (`86 <= cap < 384`), so relaxing it past either fails to compile rather than surfacing as a failed certification. The residual on the `standard` profile is stated rather than hidden, and is small: the pusher is an authenticated client reflecting text into its *own* registered `redirect_uri`, the row lives 60 seconds on a route under the per-IP rate limit, and the whole form is bounded by actix's default 16 KiB body cap on `/oauth2/par`. Four FAPI 2.0 modules moved from `REVIEW` to `PASSED` per module (`-with-long-state`, `-with-long-nonce`, `-different-nonce-inside-and-outside-request-object`, `-different-state-inside-and-outside-request-object`), and a `standard` client still accepts a 1000-character `state`, asserted."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "7a5c9644-3db1-4d22-ad8d-fdd39b62946a",
     "kind": "process",
     "x": 374,
     "y": 644,
     "w": 140,
     "h": 140,
     "name": "Resource-endpoint token validation (cnf, DPoP jti, sid)",
     "lines": [
      "Resource-endpoint",
      "token",
      "validation",
      "(cnf, DPoP",
      "jti, sid)"
     ],
     "description": "The extractors every protected REST route runs before a handler: JWT signature and expiry, the session named by `sid`, and the sender constraint — certificate thumbprint or DPoP proof, now single-use — a bound token demands of this request.",
     "outOfScope": false,
     "threats": [
      {
       "number": 246,
       "title": "A sender-constrained token is laundered into a bearer token through the identity cache",
       "type": "Spoofing",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "The audit middleware validates a JWT's signature and expiry and caches the result as `CachedUserIdentity`. `extract_user` and `extract_principal` then took those claims and returned — never reaching `validate_presented_token`, the only place `enforce_sender_constraint` lives. So on every route behind `AuthenticatedUser`, a certificate-bound or DPoP-bound access token was accepted over a connection that presented no certificate and carried no proof: the binding T-167 and T-175 require every relying party to honour was decorative on AXIAM's own API. It survived because the test that asserts the property could not exhibit the defect — the test app installs no audit middleware, so the cache was always absent and the slow path always taken.",
       "mitigation": "Found by the OpenID Foundation suite and closed in 065f37c, \"one of them a hole\". Signature and expiry are facts about the **token** and are worth caching; RFC 8705 §3 and RFC 9449 §7.1 are facts about **this request** — which certificate the connection presented, which proof accompanied it — and no cached answer can stand in for them. Both extractors now go through one `cached_identity` helper that enforces the constraint every time the cache is used, and `CachedUserIdentity` carries the encoded token so the DPoP `ath` binding can still be checked. The new test installs the cache, uses the same token and the same assertion, and keeps an **unbound** token as a control so it cannot pass by having broken the cached path outright. `authenticate_presented_token` (W6) does not consult the cache at all. Recorded Critical rather than High because the whole value of sender constraint rests on the resource server, and here the resource server is AXIAM."
      },
      {
       "number": 247,
       "title": "A DPoP proof captured at a resource endpoint is replayed within its freshness window",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "T-172's known residual. The token endpoint has recorded proof `jti`s since X5.1; the resource endpoints did not, and `enforce_sender_constraint` documented the gap rather than hiding it — actix extractors are synchronous and the replay store is not — so within the 60-second freshness window a captured proof for that exact method, URI and token would be accepted a second time. The OIDF `dpop-negative-tests` module measured it: \"Second use of the same jti\" expected 400 or 401 and got 200 (RFC 9449 §11.1).",
       "mitigation": "The remedy the comment proposed — middleware that can await — was more than needed: the three extractors that matter already return a boxed future, only the helpers were synchronous. So the check splits along the line that was already there: verification stays synchronous, where every caller already is, and leaves the verified proof on the request as a `PendingDpopProof`; recording — the part that is a write — happens in the extractor's async tail through a `DpopReplayGuard`, the same object-safe boxed-future seam `SessionValidator` uses. The guard is a clone of the token endpoint's own `proof_replay_repo` by construction rather than by convention: a proof is single-use, not single-use *per endpoint*, and two stores would let one proof be spent once at each; the `UNIQUE` index decides, with no read-then-write. `AuthenticatedServiceAccount` was wholly synchronous and is now async like the others, because a machine token carries `cnf` exactly as a user token can and leaving it alone would have left every m2m route as the replayable way in. Requests presenting no proof pay nothing. Two tests: one proof sent twice answers 200 then 401, with the good first request there so the test cannot pass against a server that refuses every proof; three fresh proofs from the same key are all served, because \"single-use\" means that proof, not that key. `htu` is now compared in canonical form as §4.3 asks (T-172)."
      },
      {
       "number": 248,
       "title": "Replay protection recorded before verification becomes a denial-of-service primitive against the key it protects",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Recording a proof's `(jkt, jti)` is a write keyed by the client's public key. Done *before* the signature is verified, anyone could burn arbitrary pairs against a victim's key by sending forged proofs carrying that victim's `jwk` — turning replay protection into a denial-of-service aimed at its beneficiary. And a guard that fails open when the store is unreachable turns a database blip into an unlimited replay window.",
       "mitigation": "The order is load-bearing and stated in the code: verify first, record after, and only a proof that verified is ever recorded. A proof that verified but whose `jti` cannot be recorded is **refused**, including when no `DpopReplayGuard` is registered at all — the token endpoint's rule (\"failing open would turn a database blip into an unlimited replay window\") applied at the other end of the same mechanism, at no cost to a deployment that wires the guard and with a `tracing::error!` for one that forgot. The replay row expires exactly at the end of the 60-second freshness window, so the table is bounded by the proof rate rather than growing without limit, and a client is never locked out by its own last request, since the tuple is per proof and not per key."
      },
      {
       "number": 249,
       "title": "An OAuth2 access token names no session, so a password or MFA reset cannot revoke it — or UserInfo refuses every token",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "`check_user_aud_and_parse_jti` derived the session id from the token's `jti`. Every login path honours the contract that a user-flow token's `jti` equals the issuing `session.id`; the OAuth2 paths cannot, because a `jti` must be unique per token (RFC 7519 §4.1.7) and one session issues many, so they minted a random one. `is_session_active` then looked up a session that had never existed and refused, seconds after issuance — UserInfo did not work for any OIDC client at all. The obvious repair, dropping the session check at UserInfo, would have given up the property the check exists for: a password or MFA reset revoking in-flight OAuth2 access tokens.",
       "mitigation": "49916b4: the session travels in its own `sid` claim — the name OIDC Core §2 already uses on the ID token — on the authorization-code and refresh paths, and the reader prefers `sid`, falling back to `jti`. The fallback is what makes this need no migration and no flag day: every login-issued token resolves to exactly the session it always did, and not one login path changed. The refresh path carries it too, because a rotated token that dropped `sid` would stop working at UserInfo the moment it replaced the one that had it — a session ending mid-flow fifteen minutes after sign-in. `None` for a token with no session behind it (client credentials, an RPT, a token exchange), which are not weakened by the absence since there is no session to revoke. The access token's `sid` equals the ID token's, and RFC 6749 §10.5's code-replay revocation (T-250) is built on the same claim."
      },
      {
       "number": 277,
       "title": "A resource indicator names AXIAM's own token audience, so a grant mints a credential for AXIAM while claiming to mint one for somebody else",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "I3 is enforced by pinning `aud` to AXIAM's two built-in audiences in `decode_access_token`, so a token minted for an MCP server is refused at AXIAM's own doors. RFC 8707 resource indicators are validated as absolute URIs without a fragment, and the parser deliberately admits any scheme, because `urn:` resources are legitimate and a loopback `http` MCP server is a resource like any other. AXIAM's audiences are spelled `axiam:user` and `axiam:m2m`, and a scheme followed by a path is all an absolute URI needs — so they parsed, carried no fragment, and were resource indicators like any other. Naming one did not defeat the audience pin; it satisfied it, and the boundary stopped being a boundary. The sharpest case is `client_credentials`, which mints `axiam:m2m` when no resource is named: naming `axiam:user` made the *same* grant mint a token carrying the user audience, from a grant with no end user in it — a shape no other path in the server can produce. `external_client_allowed_resources` is what made it more than untidy, because D3 has DCR and CIMD clients inherit that list wholesale.",
       "mitigation": "2026-09-17 (MCP-02, `013903d`). `axiam_oauth2::resource::normalise` reserves the whole `axiam` scheme rather than the two literals, so an audience added later is covered without anybody having to remember the rule exists. It is checked after parsing, against the scheme `url` resolved, so `AXIAM:user` cannot slip past a byte comparison on the input, and every door answers `invalid_target`: registration refuses the entry, and the token endpoint refuses the parameter even for a row that somehow holds one, because `is_allowed` normalises both sides. Fail-closed and reachable by no existing deployment — `allowed_resources` ships in the same unreleased version, so no stored row can contain one. Asserted at the parser and at both endpoints."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "02a44c35-6670-495e-900c-92c24dfaa00c",
     "kind": "process",
     "x": 814,
     "y": 464,
     "w": 140,
     "h": 140,
     "name": "/oauth2/register (RFC 7591, unauthenticated)",
     "lines": [
      "/oauth2/register",
      "(RFC 7591,",
      "unauthenticated)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 273,
       "title": "A stranger registers a client whose `redirect_uris` name a host the tenant did not mean to admit, or whose posture it did not mean to grant",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "`POST /oauth2/register` is the first endpoint in AXIAM that writes for a caller holding no credential. What a caller can write is what decides whether it is a registration endpoint or a way to mint an authorization target of one's own choosing: a `redirect_uris` entry pointing at attacker infrastructure makes every subsequent authorization a code delivered to the attacker, and a self-granted `client_credentials` or token-exchange grant would be a client acting with no user at all.",
       "mitigation": "Off by default: `dynamic_registration` is `disabled` and the path answers a `403` shaped like every other refusal, so the feature does not leak from the route's existence. When it is on, the request is narrowed on every axis a caller can influence. `redirect_uris` go through the same `validate_redirect_uris` the admin API uses — one answer to \"what is a usable redirect URI\" in this server — and then through the tenant's `dcr_allowed_redirect_hosts`, a glob whose grammar is deliberately tiny: a literal host, `*` as the **whole** leftmost label, or `*` alone, with the match anchored on a label boundary so `evil-example.com` cannot match a pattern meant for `example.com`, and a `*` anywhere else matching nothing at all. The loopback three are always admitted, because they are what the desktop clients this exists for actually use. `grant_types` is narrowed to `{authorization_code, refresh_token}`, so a self-registered client can never reach `client_credentials` or an exchange grant; `scope` is narrowed to `dcr_allowed_scopes`, which the settings layer refuses to let contain `address` or `phone`; the profile is forced to `standard` and `managed_by` to `dcr`, so I5 holds and `fapi.rs` refuses a FAPI posture on the row twice over; `allowed_resources` is forced to the tenant's own list rather than taken from the request (D3), so an unrelated party cannot name its own audiences; and `software_statement` is refused explicitly rather than ignored. Every registration is audited, and D4 forces the consent hop on the first authorization whatever scopes were asked for, so an end user is always shown a client an administrator did not create. Asserted end to end by `mcp_authorization_test`, whose loopback probes drive seven host spellings against the live authorization endpoint (2026-09-17 review, V1)."
      },
      {
       "number": 272,
       "title": "A stranger fills the tenant's registration quota and denies registration to legitimate clients until the sweeper runs",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "`dcr_max_clients` bounds the rows a tenant's self-registration can create, which is the right control for storage and is also, unavoidably, the tenant's availability budget for the feature. In `anonymous` mode an unauthenticated caller can spend all of it: the default ceiling is 20 and the default per-IP limit is 5 a minute, so about four minutes from one address fills it, and a handful of addresses removes the four minutes. The rows then sit until the sweeper reclaims them, which for a client that was never authorized is `created_at + dcr_unused_client_ttl_days` — 30 days by default — because the same TTL serves both \"registered and abandoned\" and \"used once and gone quiet\", which are different clocks.",
       "mitigation": "Closed in `c4d9ea2` (MCP-05, #471): Bounded, not closed. `initial_access_token` mode is unaffected: a caller holding no handle is refused before the quota is consulted, which is a real reason to prefer that mode and one the operator page does not currently give. `anonymous` mode is opt-in, refused while `external_client_allowed_resources` is empty, and every attempt is rate-limited and audited, so the denial is noisy and attributable to whatever addresses it came from. **Closed** (`c4d9ea2`), filed as MCP-05 (#471) against T21.4a. The window is shortened where the exposure is: a `managed_by: dcr` row with no `last_authorized_at`, in a tenant whose effective mode is `anonymous`, is swept an hour after `created_at` rather than after `dcr_unused_client_ttl_days`. One TTL was serving two situations with nothing in common — the 30-day default is sized for \"a client somebody uses monthly\", and a registration nobody authorized is not that client, which the sweeper could already tell from `last_authorized_at: None`. The second clock does not make the flood more expensive; it turns a month of denial into an hour, at no cost to any client that completes a flow. It does not apply in `initial_access_token` or `disabled` mode, does not touch a row that has been authorized once, and is not switched off by `dcr_unused_client_ttl_days: 0`. The hour is a constant rather than a tenant setting: the fix plan recommended the field and its own cost table was wrong about the price — `OidcPolicy`'s scalars are columns on a `SCHEMAFULL` table, so a fifth DCR number is a migration v66, which the remediation's constraints excluded. The plan's §4 carries the evidence and the promotion checklist; the field remains the right answer and is the maintainer's call.\n\nTwo residuals stay recorded. A **per-IP or per-subnet share** of the quota is not done: it needs a ledger per (tenant, address) that no store holds, it is defeated by a handful of source addresses, and the mode it would protect is the one the documentation now says is for tenants that accept this exposure. The condition that would change that: a deployment reporting quota exhaustion from distributed sources in `anonymous` mode *with* the second clock in place — and even then the answer is more likely `initial_access_token` than a subnet ledger. And the quota check and the write are still separated by an `await`, so concurrent registrations can overshoot the ceiling by the number in flight; the second clock makes such a burst cheap to recover from rather than cheap to cause."
      },
      {
       "number": 289,
       "title": "The RFC 7592 registration access token opens a write surface on the authorization server: stolen or replayed, used across clients or tenants, outliving its client, written to a log, or used to widen the registration it manages",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "`GET`, `PUT` and `DELETE /oauth2/register/{client_id}` (T23.4.1) let a dynamically registered client read, replace and delete its own registration, authenticated by a bearer the server minted at registration rather than by a user or a service account — the same class as T-272…T-280: an unauthenticated-by-user write path on the authorization server. Whoever holds the token can repoint the client's `redirect_uris`, rename it on the consent screen its users see, or delete it. The ways that goes wrong: the token is stolen from the MCP client's configuration or from a log and replayed; a token minted for one client, or in one tenant, is accepted for another; a user's or a service account's access token, or the client secret, is accepted in its place; a token survives the deletion of its client or a rotation; a `PUT` is a second, weaker registration that keeps a scope, a grant, a host or an audience the tenant has withdrawn, or reaches a column a registration cannot set (the profile, the X7 flags, the provenance); two racing `PUT`s both succeed and leave two live tokens; the token reaches an audit row, a log line or a URL; or the three routes become an unmetered way to burn server work.",
       "mitigation": "Mitigated in T23.4.1. **Minting and storage.** 32 CSPRNG bytes, base64url, returned once in the registration's `201` (and the rotated value once in a `PUT`'s `200`); only its SHA-256 is stored, on the client row (schema v69, optional, no backfill). **Who has one.** Only a `managed_by: dcr` client registered after v69; an administrator's client, a CIMD shadow row and an older `dcr` row hold none. **Authentication.** `Authorization: Bearer` only; a token in the query string is refused `400` even beside a good header, and no form body is read. The digest is compared in the datastore in one `WHERE` with the tenant the request resolved (query or T21.6 path), the path's `client_id` and `managed_by = 'dcr'` — a digest looked up by index, the pattern refresh and initial access tokens use — so a token names exactly one row in one tenant, and a user token, a service-account token, a client secret or another client's token hashes to something that row does not hold. Unknown client, wrong token, other tenant and no-token client are one `401 invalid_token` with an RFC 6750 challenge (RFC 7592 §2.1: existence is not revealed); `404` is never used. **Replacement.** A `PUT` is a full replacement held to the same `dcr::validate` as a registration under the tenant's **current** policy (grants within `{authorization_code, refresh_token}`, scopes within `dcr_allowed_scopes`, hosts within the glob plus loopback, audiences forced to `external_client_allowed_resources`); widening is `400 invalid_client_metadata`; the four server-stated members and a foreign `client_id` are `400 invalid_request`; the authentication method cannot change; and the repository type it writes through has no field for the profile, the X7 flags, the provenance or the tenant. Refused under `disabled`. **Rotation** is one compare-and-swap on the presented digest with X6's two layers (transaction, then a read-back of the new digest as the nonce), so of racing `PUT`s one wins and the rest get `401`. **Deletion** is conditional on the digest; the token dies with the row, a second `DELETE` is `401`, the client's refresh tokens are revoked through `revoke_all_for_client`, and the `dcr_max_clients` slot is released. **Redaction and audit.** Every request, served or refused, writes an `oauth2.client_configuration_*` audit row carrying the operation, the error code and the `client_id` only when it has the minted `oa_` shape — never the token or its digest; asserted under a `TRACE` subscriber and against the audit API. Marked **Sensitive** in CONTRACT §28.12 and given its own OpenAPI security scheme. **DoS.** The three routes share one per-IP bucket at the registration preset (`dcr_per_min`, 5/min), separate from `POST /oauth2/register`'s, with a 16 KiB body limit. **Residuals.** A stolen token is good until the client next updates (no expiry, as RFC 7592 permits) — the holder can repoint redirects only within the tenant's glob and loopback, and every use is audited. Access tokens already issued to a deleted client stay valid for their remaining lifetime (≤ the access-token TTL), as for any client an administrator deletes. Consent records keyed by the deleted `client_id` are left to their users, since the identifier is never reissued."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "50084f15-5206-4550-ae51-f0ff7e0e6bc5",
     "kind": "process",
     "x": 814,
     "y": 644,
     "w": 140,
     "h": 140,
     "name": "Client ID metadata document fetch",
     "lines": [
      "Client ID",
      "metadata",
      "document",
      "fetch"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 274,
       "title": "An unauthenticated `client_id` turns the authorization server into a request-forgery engine against its own network",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "A client ID metadata document is fetched because an unauthenticated request named its URL. That is the whole mechanism and it is also the whole exposure: without a guard it is a `GET` to any address the caller chooses, issued from inside the deployment's network, with the response parsed and its contents stored. SEC-094 is the reason this entry is not merely theoretical — the shared SSRF guard once failed to canonicalise IPv4-mapped IPv6, so an `AAAA` record of `::ffff:169.254.169.254` passed the address check and was then *pinned* into the connection, guaranteeing the attacker's address was the one dialled.",
       "mitigation": "The fetch goes through `axiam_pki::ssrf::guarded_fetch` over the existing `axiam-oauth2 → axiam-federation` edge, so it inherits the guard every other outbound fetch in AXIAM uses rather than carrying its own. Re-verified on this path at the 2026-09-17 review (V3): both IPv4-in-IPv6 embeddings are folded before classification — `::ffff:0:0/96` canonicalised to the v4 address it denotes, `::/96` rejected outright because `to_canonical` does not fold it — and **every** resolved address is classified rather than only the one dialled, so an `A`/`AAAA` pair with one bad answer is refused. Rebinding between check and connect is closed by pinning the validated address into a client built fresh per fetch, with no pooling. Redirects are never followed automatically: each hop is re-resolved, re-classified and re-issued, and the `allow_private` test seam is honoured on the first hop only, so `cimd.allow_http` cannot be turned into a redirect to a metadata endpoint. The bounds are each enforced and each tested — `https` unless the tenant opts into `http`, a 10-second timeout, a `Content-Length` gate plus a *streaming* cap at `max_metadata_bytes`, and a JSON content-type check. Ordering is the part most easily got wrong and is right here: `cimd::resolve` runs the trusted-publisher check **before** `get_or_fetch`, so an untrusted host is never contacted at all."
      },
      {
       "number": 276,
       "title": "The trusted-publisher list that bounds the fetch admits a value meaning \"every host\"",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "T-274's address guard keeps the fetch out of the private network; it does nothing about the public one, and nothing else does either. `cimd.trusted_client_id_domains` is the control that stops the mechanism being a general-purpose outbound-request primitive, and T21.5 added an interlock refusing to enable CIMD while that list is empty, on exactly that reasoning. The interlock refuses the empty list and accepts `*` — which `host_glob_matches` documents as \"a tenant that wants no host restriction\" — so the posture the interlock exists to prevent is reachable by one character, and the validator's own error message names `*` as a valid entry.",
       "mitigation": "Closed in `0a273ec` (MCP-03, #469): Not a default: CIMD is off by default and the field ships empty, so no deployment has this posture without an operator writing it. The address guard still holds, so the residual is an outbound `GET` to public URLs a caller chooses, with AXIAM's source address and no attribution — not an internal-network primitive. **Closed** (`0a273ec`), filed as MCP-03 (#469) against T21.5. `*` is refused in `trusted_client_id_domains`, and so is a wildcard over a whole top-level domain (`*.com`), which is the same posture spelled longer; it stays admissible in `trusted_redirect_domains`, where an empty list is a working posture and the entries are not fetch targets. The argument is the one T21.5's amendment 2 made for refusing the empty list: an unrestricted trusted-publisher list is a request-forgery primitive offered to strangers **and no second control does that job**, so a control with a one-character bypass is not the control. Enforced at both settings doors by one condition, since `validate_cimd_policy` runs on the merged policy too, and the validator's entry-shape message no longer offers `*` for this field. It is a floor and not a public-suffix check: `*.github.io` still passes, because trusting shared hosting is a decision an operator may reasonably make, and what bounds it is T-275's quota. Validation runs on write, so a stored `*` survives until that row is next saved — and no released deployment can hold one, CIMD being unreleased."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "bcb5139c-1607-43dd-badd-6256ff7b2b31",
     "kind": "process",
     "x": 814,
     "y": 264,
     "w": 140,
     "h": 140,
     "name": "per-tenant path issuers (/t/{tenant_id})",
     "lines": [
      "per-tenant",
      "path",
      "issuers",
      "(/t/{tenant_id})"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 279,
       "title": "One key set signs every tenant, so a token minted for tenant A verifies on tenant B's path",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "RFC 8414 §2 forbids a query component in an issuer, so AXIAM's `?tenant_id=` convention cannot be published as one tenant's issuer and an MCP client deriving discovery from a protected-resource document always landed on the deployment's default tenant. T21.6's opt-in `{root}/t/{tenant_id}` fixes that and introduces the risk, which T21.6's own second amendment found rather than inherited: the JWKS is shared — one key set, many issuers, which RFC 8414 permits — and the extractors must accept both the root issuer and any tenant issuer, so **the signature no longer distinguishes tenant A's token from tenant B's**. Left there, a path-shaped tenant selector would be a selector the caller and the token could disagree about, which on a multi-tenant authorization server is the whole ball game.",
       "mitigation": "Two checks, and the 2026-09-17 review (V2) confirmed both against live routes rather than against the functions. `enforce_issuer` refuses a token whose `iss` names a tenant its `tenant_id` claim does not, so a token can never be internally ambiguous; it is a no-op with the flag off, where `jsonwebtoken`'s pinned-issuer check is kept verbatim, so I1 holds by construction. `enforce_tenant_path_binding` refuses a principal whose tenant is not the tenant the path named, and sits in `extract_user` — the funnel **both** extractor arms pass through — so a route mounted under the scope later inherits it rather than having to remember it; it is placed after the decode because the scope middleware cannot decode a token. The refusal is the same `401` an uncredentialed request gets, so the holder of a tenant-A token is not told tenant B exists. A `tenant_id` query parameter on a tenant path is refused outright with `invalid_request`, so the two selectors can never both be present. Introspection is tenant-scoped independently — the token's `tenant_id` is compared with the request's and a mismatch answers `active: false` — so the shared key set does not make introspection a cross-tenant read either. One note for whoever widens the scope: only the OAuth2 endpoints are mounted under `/t/{tenant_id}` today, and the binding is checked against the principal's *home* tenant, which the organization-level tenant header can move afterwards; that does not meet a path selector on any route as things stand."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "89558645-355b-40c7-952c-081d58a6656b",
     "kind": "store",
     "x": 1079,
     "y": 914,
     "w": 170,
     "h": 80,
     "name": "externally registered clients (dcr, cimd)",
     "lines": [
      "externally registered",
      "clients (dcr, cimd)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 275,
       "title": "Shadow client rows accumulate without a quota and are reclaimed by nothing",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Both external mechanisms write client rows for parties nobody vetted, and the two are bounded differently. A `dcr` row counts against `dcr_max_clients` and is swept on a TTL. A `cimd` row counts against nothing — the quota query asks for `ManagedBy::Dcr` — and is swept by nothing, because `sweep_unused_dcr_clients` excludes `cimd` deliberately, reasoning that a shadow row is a cache of a document the client publishes and deleting it would only be re-materialised on the next request. That argument is correct about TTL semantics and does not carry to storage: a cache that is never evicted is not a cache.",
       "mitigation": "Closed in `0b216c6` (MCP-04, #470): The bound is the number of distinct URLs that both match `trusted_client_id_domains` and serve a valid document, which for the profile the documentation recommends — a named publisher, `*.vendor.example` — is small, and the entry would be theoretical. It stops being theoretical the moment a tenant trusts shared hosting, which is a natural thing to do because shared hosting is where a small tool publishes a JSON file; any third party who can publish under that domain then mints unbounded rows at one unauthenticated request each. It compounds with T-276, where `*` makes every domain shared hosting. **Closed** (`0b216c6`), filed as MCP-04 (#470) against T21.5, in three parts and with no migration. `dcr_max_clients` now caps `cimd` rows as a separate count against the same number — which is what the repository's own comment on `count_by_managed_by` asked for — and the count is checked **before** the fetch, so a tenant at its ceiling is not an outbound amplifier either; the refusal is audited in T21.4a's shape and carries no caller-supplied string. `dcr_unused_client_ttl_days` now sweeps `cimd` rows on their own `/health/jobs` counter and their own clock, `max(updated_at, last_authorized_at, created_at)`: no column was added because `updated_at` is *already* \"last presented\", every resolve upserting the row whether or not a fetch happened. And the in-memory document cache evicts entries past their TTL and stale window on the insert path. Eviction on last-seen is *coherent* with T21.4's cache argument rather than against it — a row deleted while its document is still published is re-materialised on the next request, which is what a cache should do; what the old argument said nothing about is storage, and a cache that is never evicted is not a cache. T-276's closure did not lower this one: `*` was the one-character path to shared hosting and is gone, but naming `*.github.io` is one settings line, is a reasonable operator decision, and is the path this entry was filed about. The accepted residual is the ordering overshoot T-272 records, which applies here identically."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "85b33ce6-dea8-545c-8ee5-840c358057ab",
     "kind": "actor",
     "x": 49,
     "y": 854,
     "w": 150,
     "h": 80,
     "name": "CIBA client (consumption device)",
     "lines": [
      "CIBA client",
      "(consumption device)"
     ],
     "description": "A confidential client registered for urn:openid:params:grant-type:ciba (poll or ping): a call centre, a point of sale, a back office acting for a customer. It knows whom it wants authenticated and holds none of their credentials (G-7).",
     "outOfScope": false,
     "threats": [
      {
       "number": 434,
       "title": "A `fapi2` client is served CIBA weaker than the FAPI-CIBA profile requires",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The FAPI-CIBA profile requires signed authentication requests, strong client authentication (`tls_client_auth`, `self_signed_tls_client_auth` or `private_key_jwt`), sender-constrained tokens, a unique authorization context or binding message, and no push mode. A `fapi2` client served the CIBA grant without any one of them would be a client registered under a profile that promises FAPI running a flow that does not meet it, while its operator believes it does — and a client that registered a signing algorithm but whose unsigned requests were accepted anyway would hold a security switch that does nothing (the SEC-097 shape).",
       "mitigation": "Built (T23.7.1, D-61). A `fapi2` client may hold the CIBA grant only with `backchannel_authentication_request_signing_alg` registered (refused otherwise at the admin API; a self-registered client is never `fapi2`, I5), and the `fapi2` profile's own rules — strong client authentication and sender-constrained tokens — run on the same registration through `fapi::validate_registration`. At `bc-authorize`, every request from a client that registered an algorithm must be a signed `request` JWT under exactly it (T-440 … T-442), and a `fapi2` row edited to drop the algorithm is `unauthorized_client`; D-17 refuses one edited to a shared secret. A `fapi2` request must carry a `binding_message` (`invalid_request` otherwise), and a `fapi2` ping client's `client_notification_token` must be at least 22 characters (128 bits in base64url — the floor an authorization server can enforce on entropy it cannot measure). Push is not offered to anyone. The token endpoint applies `fapi::enforce_token_request` to the CIBA grant as to every other: no certificate or DPoP proof the registration requires, no token. Tests: `crates/axiam-oauth2/src/ciba.rs` `a_fapi2_client_holds_the_grant_only_with_signed_requests`; `crates/axiam-api-rest/tests/ciba_test.rs` `admin_registration_validates_signed_requests_and_the_fapi2_ciba_client` (no signing algorithm, a shared secret, no sender-constraining — each `400`; the complete client `201`), `a_fapi2_ciba_client_signs_authenticates_strongly_and_is_sender_constrained` (signed and `private_key_jwt`-authenticated: `200`; unsigned or without a binding message: `invalid_request`; redeemed without the DPoP proof: `invalid_dpop_proof`; a row edited to drop the algorithm: `unauthorized_client`), `a_fapi2_ping_client_needs_a_notification_token_of_128_bits`, `a_row_edited_to_public_or_fapi2_is_refused_at_bc_authorize`. Residual: FAPI-CIBA certification itself is a run of the OpenID Foundation suite, not a property a unit test can show."
      },
      {
       "number": 438,
       "title": "A self-registered client obtains the CIBA grant and targets the tenant's users",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Dynamic registration lets a stranger create a client (T-273). The CIBA grant lets a client send sign-in requests to any user of the tenant by naming them. A stranger who could register a CIBA client would gain exactly that — a notification channel to every user, and the T-424 attack, from a client nobody vetted.",
       "mitigation": "Built (T23.7.1, D-62). RFC 7591 accepts the CIBA grant **only in `initial_access_token` mode** — the registration an administrator authorised by minting a single-use token — and refuses it in `anonymous` mode with `invalid_client_metadata`; the CIBA metadata is validated by the same rules as the admin API's, and a CIBA-only registration needs no redirect URI. Tests: `crates/axiam-oauth2/src/dcr.rs` `an_anonymous_registration_cannot_name_the_ciba_grant`, `an_initial_access_token_registration_may_name_it_without_redirect_uris`, `the_ciba_metadata_rules_apply_to_a_registration`; `crates/axiam-api-rest/tests/ciba_test.rs` `an_anonymous_registration_cannot_obtain_the_ciba_grant`."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "3c33fdd2-685b-5587-8571-836183810548",
     "kind": "process",
     "x": 624,
     "y": 644,
     "w": 140,
     "h": 140,
     "name": "CIBA: /oauth2/bc-authorize + approval service",
     "lines": [
      "CIBA:",
      "/oauth2/bc-authorize",
      "+ approval",
      "service"
     ],
     "description": "POST /oauth2/bc-authorize (and under /t/{tenant_id}) and axiam_oauth2::ciba::CibaService (T23.7.1; D-61, D-62, D-63): client authentication as at the token endpoint, verification of a signed authentication request (CIBA Core 7.1.1, D-61: the registered algorithm and keys, aud/iss/exp/nbf/iat, a single-use jti in oauth2_proof_replay), hint resolution, validation and storage of the request, the user-notification port, and the approval service API (lookup_for_approval, approve, deny) the identity pages call (T23.7.2). The CIBA grant itself is redeemed at /oauth2/token.",
     "outOfScope": false,
     "threats": [
      {
       "number": 421,
       "title": "A caller starts a backchannel authentication without authenticating as the client its registration names",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "`POST /oauth2/bc-authorize` asks AXIAM to push a sign-in request at a user on another device. If a caller could reach it unauthenticated, as a public client, with a credential the registration does not name (SEC-093's shape), or — for a `fapi2` row edited in the datastore — with a shared secret, anybody who learned a client id could send the tenant's users sign-in prompts in that client's name, and the request would be attributed to a client that never made it.",
       "mitigation": "Built (T23.7.1). The endpoint authenticates exactly as the token endpoint does: the same request context (the `Authorization: Basic` header, the client certificate rustls verified, a client assertion) and the same `TokenService::authenticate_client`, so the **registration** decides the method; the D-17 request-time rule (`fapi::enforce_client_authentication`) runs next. A CIBA client must be confidential — the grant is refused at registration (admin API and RFC 7591) and at request time to a `none` client — and must hold the grant (`unauthorized_client` otherwise). A failure is the uniform `401 invalid_client` and is recorded as the token endpoint's `oauth2.client_auth_failed` audit row, detached from the response and attributed by the SEC-087 rules. A `tls_client_auth` client — the FAPI-CIBA shape — reaches the endpoint on the mTLS host: since D-61 `backchannel_authentication_endpoint` is one of the RFC 8705 §5 `mtls_endpoint_aliases`, so a two-listener deployment does not leave it with no way to present its certificate. Tests: `crates/axiam-api-rest/tests/ciba_test.rs` `bc_authorize_refuses_each_malformed_request_with_its_section_13_code` (a wrong secret is `401`, a client without the grant `unauthorized_client`, nothing stored), `ciba_client_authentication_failures_meet_the_same_lockout` (the audit rows name the CIBA grant and the client), `admin_registration_accepts_and_validates_the_ciba_metadata` (a public client is refused the grant), `a_row_edited_to_public_or_fapi2_is_refused_at_bc_authorize` (a row edited in the datastore to `none` is `invalid_client`, one edited to `fapi2` on a shared secret is refused by D-17), `a_fapi2_ciba_client_signs_authenticates_strongly_and_is_sender_constrained` (`private_key_jwt` at the endpoint); `crates/axiam-oauth2/src/ciba.rs` `stray_metadata_public_clients_and_unimplemented_members_are_refused`; `crates/axiam-oauth2/src/oidc.rs` `the_alias_object_has_exactly_the_seven_members_the_contract_names`; `crates/axiam-api-rest/tests/oidc_conformance.rs` `discovery_publishes_mtls_aliases_when_a_host_is_configured`."
      },
      {
       "number": 422,
       "title": "`bc-authorize` becomes a user-enumeration oracle",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A CIBA request names its user by a hint — a username, an e-mail address or an ID token. CIBA Core §13 defines `unknown_user_id` for a hint that names nobody; answering it, or answering a locked or inactive account differently, or taking measurably longer for a real user (to send them a notification), would let every registered CIBA client test the tenant's usernames and addresses at the endpoint's rate limit.",
       "mitigation": "Built (T23.7.1, D-63). A hint naming nobody, a user who may not sign in, or a user under brute-force lockout is **answered exactly like a real one**: the request is stored with no subject and the response carries the same members and values (`auth_req_id`, `expires_in`, `interval`); nothing can approve it, the client polls `authorization_pending` and then `expired_token`. `unknown_user_id` is never sent. The hint is resolved only after every other parameter has been validated, so a malformed request is refused identically whoever it names, and the user notification is handed to the port **detached** from the response, so its cost is not on the response path. Tests: `crates/axiam-api-rest/tests/ciba_test.rs` `bc_authorize_is_not_a_user_oracle` (a real and an unknown hint get the same shape, the unknown one has no subject and answers `authorization_pending`, a locked user is nobody, only the real unlocked user is notified)."
      },
      {
       "number": 423,
       "title": "An `id_token_hint` names a user of another tenant or another client's relying party",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "The key that signs ID tokens is the deployment's, shared by every tenant and every issuer form (T-279). An `id_token_hint` that were only signature-checked could carry a subject from another tenant, or an ID token issued to a different relying party, and make AXIAM push a sign-in request to a user the requesting client never authenticated — the CIBA form of token confusion.",
       "mitigation": "Built (T23.7.1). The hint must verify under the deployment's EdDSA key **and** carry `aud` equal to the authenticated client **and** an `iss` this request may name (the deployment's root issuer or this tenant's path issuer); anything else is `invalid_request`, with one message whatever failed. The subject is then looked up in the request's tenant only (and the row's tenant re-checked), so a subject from another tenant resolves to nobody (T-422). Expiry is not required: the hint authenticates nothing, it only names the user to ask. Tests: `crates/axiam-api-rest/tests/ciba_test.rs` `an_id_token_hint_must_be_one_this_server_issued_to_this_client` (issued to this client: resolved; to another client: refused; signed by another key: refused); `bc_authorize_refuses_each_malformed_request_with_its_section_13_code` (an ID token this server never issued)."
      },
      {
       "number": 429,
       "title": "Brute-force lockout does not apply to CIBA (the Keycloak 26.7.x class)",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "A user's brute-force lockout (`locked_until`) is read on the password path, and `account_may_act` — what the other grants check — reads the account's status but not that lockout. A backchannel grant that skipped it would mint tokens for an account the lockout was protecting; and client-authentication failures at a new endpoint that skipped the token endpoint's machinery would be a second, unaudited guessing surface.",
       "mitigation": "Built (T23.7.1). A user may be the subject of a CIBA grant only while the account may act **and** is not under lockout (`ciba::user_may_be_subject`), checked three times: at `bc-authorize` (a locked user resolves to nobody and is not notified, T-422), at approval, and at redemption — after the approval is spent, so a lockout between approval and redemption burns it (`invalid_grant`). Client-authentication failures at `bc-authorize` and for the CIBA grant meet the token endpoint's machinery: the uniform `invalid_client`, the `oauth2.client_auth_failed` audit row, and buckets that end in `429` whatever the credential. Tests: `crates/axiam-api-rest/tests/ciba_test.rs` `bc_authorize_is_not_a_user_oracle` (the locked user), `a_lockout_after_approval_refuses_the_redemption`, `ciba_client_authentication_failures_meet_the_same_lockout`."
      },
      {
       "number": 430,
       "title": "A request is approved by someone other than its user, with weaker authentication than it asked for, or after it was decided or expired — and the tokens claim the approval",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "The approval is the only act of the person in the whole flow. An approval API that accepted any signed-in user, a version or status it did not check, an expired request, or an `acr` stated by its caller would let one user approve another's request, an MFA request be satisfied by a password, or tokens carry `auth_time`, `acr` and `amr` that no authentication produced.",
       "mitigation": "Built (T23.7.1) in the service API the identity pages call (`CibaService::lookup_for_approval`, `approve`, `deny`). A request is shown and decidable only for **its own user**, while pending and unexpired, and the decision is conditional on the version the page read (T-427); the account must still be allowed to act and not be locked out. The `acr` recorded is **derived from the approving session's `amr`** (`acr_for`), never taken from the caller; a request whose `acr_values` named a class the session did not achieve is not approved — the page is told which class to step up to. The minted ID token carries the approval's `auth_time`, the reported `acr` and the `amr`, the access token names the approving session in `sid` (ending it ends them), and the refresh token keeps the same snapshot (D-9). Tests: `crates/axiam-api-rest/tests/ciba_test.rs` `pending_then_slow_down_then_tokens_with_the_approvals_evidence` (a password-only session cannot approve an MFA request; the tokens carry the approval's evidence and session), `denied_is_access_denied_and_expired_is_expired_token` (another user cannot deny; an expired request cannot be approved); `crates/axiam-db/tests/ciba_request_repository_test.rs` `approval_is_conditional_on_version_user_status_and_expiry`."
      },
      {
       "number": 435,
       "title": "CIBA requests and decisions are not attributable",
       "type": "Repudiation",
       "severity": "Low",
       "status": "Mitigated",
       "description": "A sign-in request pushed at a user, and that user's approval or refusal, are security decisions. Without a record, a stream of prompts a user reports, or an approval they dispute, could not be traced to the client that asked or to the session that decided.",
       "mitigation": "Built (T23.7.1, T23.7.2; completed by the W5 F4 review). Every stored request is `oauth2.ciba_initiated` (the client, the request, the delivery mode and the expiry — never the hint or the binding message) and every client-authentication failure `oauth2.client_auth_failed`; each approval and refusal is `ciba.approved` / `ciba.denied`, the user as actor and the request as resource, with the client, the delivery mode, the `acr` of an approval and — since the W5 F4 review — the **session that decided**, which the request row cannot keep (it is swept ten minutes after expiry, and a refusal stores no session on it). Never the binding message. Tests: `crates/axiam-api-rest/tests/ciba_approval_test.rs` `both_decisions_are_audited_without_the_binding_message` (its session assertion failed before the review's change); `crates/axiam-api-rest/tests/ciba_test.rs` `bc_authorize_validates_stores_and_notifies`, `ciba_client_authentication_failures_meet_the_same_lockout`."
      },
      {
       "number": 440,
       "title": "A signed authentication request is forged, altered, or verified under an algorithm or key the client did not register",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "A signed CIBA request (§7.1.1) is only worth its signature if the signature binds it to the client's own key under the algorithm the client registered. A verifier that took the algorithm from the JWS header (`alg: none`, RS256-public-key-as-HMAC-secret), accepted a key the request carries, accepted any supported algorithm rather than the registered one, or checked `iss` loosely, would let anybody who learned a client id — or a man in the middle of a TLS-terminating proxy log — mint or edit a request in that client's name: a different `login_hint`, a wider `scope`, a binding message the user is meant to trust.",
       "mitigation": "Built (T23.7.1, D-61). `crates/axiam-oauth2/src/ciba_signed_request.rs` `verify_signed_request` refuses a header `alg` other than the client's registered `backchannel_authentication_request_signing_alg`, then verifies only under keys the client **registered** (inline `jwks`, or `jwks_uri` through the SSRF-guarded federation JWKS cache via `private_key_jwt::resolve_registered_keys`, the one path every client-signed JWT's keys come through) whose own key material is of that algorithm (`jose`: the key decides, the header only confirms; a `kid` narrows, never widens). Only PS256, ES256 and EdDSA can be registered — refused otherwise at the admin API and RFC 7591 — and an inline `jwks` must hold a key of the registered algorithm. `iss` (and a `client_id` claim, if present) must equal the authenticated client. Every refusal is `invalid_request` naming what failed, to the client that already authenticated, and nothing is stored. Tests: `crates/axiam-oauth2/src/ciba_signed_request.rs` `a_signature_by_an_unregistered_key_is_refused` (a stranger's key and a tampered payload), `only_the_registered_algorithm_is_accepted` (an ES256 signature by the client's own P-256 key when EdDSA is registered, an HS256 token keyed with public bytes), `a_kid_selects_among_registered_keys_and_an_unknown_one_is_refused`, `iss_and_a_client_id_claim_must_be_this_client`, `the_advertised_registered_and_verified_sets_agree`; `crates/axiam-oauth2/src/ciba.rs` `a_signing_algorithm_is_verified_keyed_and_stored`; `crates/axiam-api-rest/tests/ciba_test.rs` `signed_request_refusals_are_invalid_request_and_store_nothing` (bad signature, wrong algorithm, another client's `iss`), `admin_registration_validates_signed_requests_and_the_fapi2_ciba_client`."
      },
      {
       "number": 442,
       "title": "Parameters outside a signed request supplement or override it, or a signing client is served an unsigned request",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "If `bc-authorize` merged form parameters with a signed request's claims, an intermediary could add what the signature does not cover — a `login_hint` the JWT omitted, a longer `requested_expiry` — and the server and the client would read one request two ways. If a client that registered a signing algorithm could still send plain requests (or `request_uri`, which would have AXIAM fetch a URL the caller chose), the signature would protect nothing, because an attacker would simply not sign.",
       "mitigation": "Built (T23.7.1, D-61). A `request` beside **any** authentication-request parameter is refused before client authentication, naming them (§7.1.1: they \"MUST NOT be present outside of the JWT\"); only the client-authentication members may accompany it. The verified request's parameters come from its claims alone, and the parameters AXIAM does not implement (`login_hint_token`, `user_code`) are refused inside it as outside it; a nested `request` or `request_uri` claim is malformed. A client that registered an algorithm sending a plain request, and a client that registered none sending a signed one, are both `invalid_request`; a `fapi2` row edited to drop the algorithm is `unauthorized_client`. `request_uri` is not part of CIBA and is refused before authentication — AXIAM never fetches a request. Tests: `crates/axiam-oauth2/src/ciba.rs` `unsupported_parameters_are_refused_before_anything_else` (the outside parameters are named; the client-authentication members are not counted); `crates/axiam-oauth2/src/ciba_signed_request.rs` `parameters_of_the_wrong_type_or_nested_requests_are_malformed`; `crates/axiam-api-rest/tests/ciba_test.rs` `signed_request_refusals_are_invalid_request_and_store_nothing` (a parameter outside the JWT, `request_uri`, an unsigned request from a signing client, a signed request from a non-signing client, `login_hint_token` inside the JWT), `a_signed_request_is_verified_and_its_claims_are_the_request` (the stored request and the user's notification carry the JWT's scope and binding message)."
      },
      {
       "number": 443,
       "title": "Signed requests make `bc-authorize` expensive to serve",
       "type": "Denial of service",
       "severity": "Low",
       "status": "Mitigated",
       "description": "Verifying a signed request costs a signature verification (PS256 is the dearest of the three) and, for a client with a `jwks_uri`, possibly a key-set fetch. An authenticated client sending large or many signed requests, or one whose `jwks_uri` is slow, could make the endpoint costly for everyone.",
       "mitigation": "Built (T23.7.1, D-61). A `request` over 16 KiB is refused before it is parsed, and a `jti` over 256 bytes before it is recorded; only candidate keys of the registered algorithm are tried, and the `jti` is recorded only after the signature verified, so garbage cannot fill the replay table. Key sets come through the shared federation JWKS cache (TTL, stale-while-revalidate, SEC-054 guard) keyed per client, so verification does not fetch per request. The route's governor, the shared `bc_authorize_per_min` counter and the per-client bucket after authentication (T-428) all count signed requests like any other. Tests: `crates/axiam-oauth2/src/ciba_signed_request.rs` `an_oversized_or_non_jws_request_is_malformed`, `a_blank_or_oversized_jti_is_unusable`; `crates/axiam-api-rest/tests/ciba_test.rs` `the_limiter_counts_bc_authorize`."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "fdbd0326-30ee-5184-abdd-7ecdd22a271a",
     "kind": "store",
     "x": 1254,
     "y": 754,
     "w": 150,
     "h": 80,
     "name": "ciba_request (pending CIBA requests)",
     "lines": [
      "ciba_request",
      "(pending CIBA",
      "requests)"
     ],
     "description": "ciba_request (schema v80): one row per bc-authorize — tenant, client, SHA-256 of the auth_req_id (unique), the resolved user or none, scopes, binding message, acr_values, resource, delivery mode, status, version, interval, last poll, expiry and the approval's evidence; a ping-mode request's auth_req_id and client_notification_token sealed under pki_encryption_key. Swept by the ciba_request job; removed with its user and its tenant.",
     "outOfScope": false,
     "threats": [
      {
       "number": 425,
       "title": "An `auth_req_id` is guessed, stolen from storage or redeemed by a client that did not start it",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "Once a user approves, the `auth_req_id` is what turns the approval into tokens. A short or predictable identifier could be guessed; one stored in clear could be read from the datastore or a backup; and one honoured for any authenticated client would let a client that learned another's identifier — from a log, a shared proxy, its own tenant's data — collect tokens for a user who approved somebody else.",
       "mitigation": "Built (T23.7.1). 256 bits of CSPRNG, base64url (CIBA Core asks for 128); only its SHA-256 is stored, under a unique index; the raw value is returned once and never logged. Redemption is conditional on the **client that started the request** in the datastore's own `WHERE` (and on the tenant), and the token endpoint matches the row to the authenticated client before it writes anything: another client's or tenant's identifier is `invalid_grant`, exactly like an unknown one, and leaves the row untouched. A ping-mode request's recoverable copy is sealed (T-432). Tests: `crates/axiam-oauth2/src/ciba.rs` `auth_req_ids_are_high_entropy_and_hashed`; `crates/axiam-db/tests/ciba_request_repository_test.rs` `redemption_needs_approval_the_starting_client_and_happens_once`, `the_hash_is_unique`, `a_request_round_trips_every_column`; `crates/axiam-api-rest/tests/ciba_test.rs` `another_clients_or_tenants_auth_req_id_is_invalid_grant` (no write for the foreign client; the owner still redeems), `bc_authorize_validates_stores_and_notifies` (only the digest is stored)."
      },
      {
       "number": 426,
       "title": "Two concurrent token requests redeem one approval twice",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "A CIBA client polls on an interval and retries; the moment a user approves there is likely a request in flight. A read-then-write redemption would let two requests both see `approved` and both mint a token set from one approval — T-163's class, on a new credential.",
       "mitigation": "Built (T23.7.1). Redemption is the **X6 two-layer arbiter** the device grant uses: a guarded `UPDATE … WHERE status = 'approved' AND client_id = … AND expires_at > now RETURN BEFORE` inside an explicit transaction (the engine aborts a conflicting loser), then a per-attempt nonce read back after the commit in a query of its own, so only the caller whose nonce survived mints tokens; a lost race is `invalid_grant`, never a `5xx`. Single use is conditional on an attested persistent engine, as for every X6 path. Tests: `crates/axiam-db/tests/ciba_request_repository_test.rs` `concurrent_redemptions_yield_exactly_one_winner` (50 rounds of 8 racers on `surrealkv`); `crates/axiam-api-rest/tests/ciba_test.rs` `concurrent_redemptions_yield_exactly_one_token_set` (two concurrent token requests over HTTP on `surrealkv`, six rounds: one `200`, the other refused), `pending_then_slow_down_then_tokens_with_the_approvals_evidence` (a second redemption is `invalid_grant`)."
      },
      {
       "number": 427,
       "title": "The user deciding and the client polling overwrite each other, or a request moves on a marker before it is validated",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Two parties write the same row without coordinating: the user approving or denying, and the client whose every token request records a poll. Read-modify-write between them (T-406's class) could put back a status the other changed, let a stale approval page approve a request that was denied in another tab, or let a poll stamp a request it does not own; and a transition driven by a marker rather than by a validated request (T-404's lesson) could move a request no authenticated party asked to move.",
       "mitigation": "Built (T23.7.1). Every transition is one statement carrying its precondition: approval and denial on `status = 'pending'`, the `version` the page read, the request's own user and an unexpired request; expiry on `status IN [pending, approved]`, the version and a past expiry; redemption as T-426. A poll is a compare-and-set on the `last_polled_at` the token endpoint read, and does **not** move `version`, so a client polling every five seconds cannot make an approval page's read stale; a lost compare-and-set is answered `slow_down`. Nothing is written for a request before the client is authenticated and matched to it. Tests: `crates/axiam-db/tests/ciba_request_repository_test.rs` `approval_is_conditional_on_version_user_status_and_expiry`, `denial_is_conditional_and_final`, `polls_compare_and_set_without_moving_the_version`; `crates/axiam-api-rest/tests/ciba_test.rs` `another_clients_or_tenants_auth_req_id_is_invalid_grant` (a foreign client writes nothing), `denied_is_access_denied_and_expired_is_expired_token` (another user cannot deny)."
      },
      {
       "number": 432,
       "title": "A ping-mode request's notification credential and identifier are readable at rest",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Ping mode needs two values in clear at delivery: the `auth_req_id` (the notification's body) and the `client_notification_token` the client supplied (the bearer AXIAM presents to the client's endpoint). Stored in clear, a datastore or backup reader could forge notifications to the client and learn a live identifier.",
       "mitigation": "Built (T23.7.1). Both are sealed together with AES-256-GCM under `pki_encryption_key` (the key webhook secrets, SSF push headers and SCIM target credentials use), nonce in its own column; no read of the table projects either column except `CibaRequestRepository::ping_credentials`, for the deliverer; the type's `Debug` redacts both. With no key configured a ping-mode request is refused, never stored in clear; a poll-mode request holds neither. Tests: `crates/axiam-db/tests/ciba_request_repository_test.rs` `ping_credentials_are_sealed_and_need_the_key` (refused without the key; neither value appears in the stored row; opens to what was stored); `crates/axiam-core/src/models/ciba.rs` `ping_credentials_never_print`."
      },
      {
       "number": 436,
       "title": "Pending requests keep a person's identity, binding message and approval after they are needed, or after erasure",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A request row names a user, carries the client's binding message (often a transaction description) and, once approved, the session and authentication methods of the approval. Kept indefinitely, or surviving the user's erasure or the tenant's deletion, it is personal data held without purpose.",
       "mitigation": "Built (T23.7.1). A request lives at most ten minutes (`requested_expiry` 30–600 s); the cleanup loop's `ciba_request` job — listed in `/health/jobs` from boot — marks every pending or approved request past its expiry `expired`, and deletes any request ten minutes after it expired (long enough to answer a late poll `expired_token`). The row carries `user_id`, so both erasure paths delete the user's requests, and the tenant-delete transaction deletes the tenant's. Tests: `crates/axiam-db/tests/ciba_request_repository_test.rs` `expiry_is_marked_conditionally_and_the_sweep_marks_then_deletes`, `erasure_and_tenant_deletion_remove_the_requests`; `crates/axiam-server/src/job_health.rs` `the_slo_sweeps_are_recorded_by_the_cleanup_loop_and_registered` (the `ciba_request` sweep is recorded by the loop and registered); `crates/axiam-db/src/schema.rs` `v80_defines_the_ciba_request_store_additively`."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "cfb25907-2444-4138-9d15-1ad1e919c642",
     "path": "M155.2,344 L400.9,658.8",
     "name": "validate presented token",
     "description": "",
     "label": "validate presented token (cnf, DPoP, sid)",
     "labelLines": [
      "validate presented token (cnf, DPoP,",
      "sid)"
     ],
     "lx": 278.1,
     "ly": 501.4,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "13fde7ec-9950-4ffd-8d7e-0af440e9cb5f",
     "path": "M510.4,691.9 L1079,502.3",
     "name": "check session, record proof jti",
     "description": "",
     "label": "check session / record proof jti",
     "labelLines": [
      "check session / record proof jti"
     ],
     "lx": 794.7,
     "ly": 597.1,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "a5448b82-8370-45f9-95ee-d6a202fd9bc2",
     "path": "M199,173.5 L822.1,501.4",
     "name": "register (RFC 7591)",
     "description": "",
     "label": "register (RFC 7591)",
     "labelLines": [
      "register (RFC 7591)"
     ],
     "lx": 510.5,
     "ly": 337.4,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "0cf3d510-ec6f-458d-945e-183f5b8f9f1f",
     "path": "M922.8,592.2 L1137.3,914",
     "name": "create dcr row",
     "description": "",
     "label": "create dcr row",
     "labelLines": [
      "create dcr row"
     ],
     "lx": 1030.1,
     "ly": 753.1,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "62fb1252-a30d-4166-9e04-d421ac131bcb",
     "path": "M486.8,199.4 L841.2,658.6",
     "name": "resolve client_id URL",
     "description": "",
     "label": "resolve client_id URL",
     "labelLines": [
      "resolve client_id URL"
     ],
     "lx": 664,
     "ly": 429,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "6fb9306e-7335-48ce-b065-6329211e21b3",
     "path": "M937.1,759.6 L1117.3,914",
     "name": "cache cimd shadow row",
     "description": "",
     "label": "cache cimd shadow row",
     "labelLines": [
      "cache cimd shadow row"
     ],
     "lx": 1027.2,
     "ly": 836.8,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "611cd2a9-3f9e-4bd1-8bf7-b7118ed7fd1b",
     "path": "M814,334 L764,334",
     "name": "discovery at /t/{tenant_id}",
     "description": "",
     "label": "discovery at /t/{tenant_id}",
     "labelLines": [
      "discovery at /t/{tenant_id}"
     ],
     "lx": 789,
     "ly": 334,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "e3cef156-70ea-5f39-9b1b-534441c8012b",
     "path": "M142.2,434 L217.4,268.6 Q224,254 238.3,246.8 L381.4,175.3",
     "name": "OP-session cookie + /logout hop",
     "description": "The browser presents axiam_op_session (HttpOnly; Secure; SameSite=Lax) on a top-level navigation to the authorization endpoint: the copy at Path=/oauth2/authorize, or, on a T21.6 per-tenant issuer, the copy at Path=/t/{tenant_id}/oauth2/authorize minted for the session's own tenant (D-11). The same copies reach the /logout sub-path of each, which end_session bounces to when no id_token_hint names a session, and which reads the cookie only to revoke the row it names (T-237, T-290).",
     "label": "OP-session cookie + /logout hop",
     "labelLines": [
      "OP-session cookie + /logout hop"
     ],
     "lx": 219.5,
     "ly": 263.9,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "b9a496a9-5911-5bd3-864d-6ab46243807c",
     "path": "M199,870.3 L627.2,735.1",
     "name": "backchannel authentication request",
     "description": "",
     "label": "backchannel authentication request (HTTPS, client auth)",
     "labelLines": [
      "backchannel authentication request",
      "(HTTPS, client auth)"
     ],
     "lx": 413.1,
     "ly": 802.7,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [
      {
       "number": 437,
       "title": "A `binding_message` misleads the user: overlong, multi-line or direction-reversed text",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The binding message is the only text the client's device and the user's approval page both show, and the user compares them to know they are approving the request in front of them. Text with control characters, line breaks or bidirectional overrides could make the two screens disagree or hide what is being approved; an unbounded one could carry a payload into a notification.",
       "mitigation": "Built (T23.7.1). At most 64 characters, not blank, no control character and no bidirectional embedding or override (`invalid_binding_message`, CIBA Core §13); stored trimmed and passed to the notification port as validated. Tests: `crates/axiam-oauth2/src/ciba.rs` `binding_messages_are_bounded_and_printable`; `crates/axiam-api-rest/tests/ciba_test.rs` `bc_authorize_refuses_each_malformed_request_with_its_section_13_code` (too long, a line break)."
      },
      {
       "number": 441,
       "title": "A captured signed authentication request is replayed, or reused at another authorization server",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A signed request is a bearer artefact: whoever holds a copy can present it. Replayed at `bc-authorize` it would push the same user a fresh sign-in prompt in the client's name for as long as it verifies; minted for another authorization server that trusts the same client key, it would be accepted here too.",
       "mitigation": "Built (T23.7.1, D-61). `aud` must name this authorization server's issuer identifier — the deployment's or the tenant path's, as a string or inside an array; the endpoint URL is not an issuer. `exp`, `nbf`, `iat` and `jti` are all required (§7.1.1); `exp` must be in the future, `nbf` and `iat` not, `exp - nbf` at most sixty minutes and `nbf` no older than sixty minutes (FAPI-CIBA §5.2.2), with sixty seconds' skew, for every client. The `jti` is **single-use**: recorded after verification in `oauth2_proof_replay` (kind `ciba_request_object`, scope the client id, schema v81) by `CREATE` against the UNIQUE `(tenant_id, kind, scope, jti)` index — the arbiter client assertions and DPoP proofs already use, with no read in the path — and a guard that cannot record refuses rather than accepting. Tests: `crates/axiam-oauth2/src/ciba_signed_request.rs` `both_issuer_forms_are_an_audience_as_a_string_or_in_an_array`, `every_claim_section_7_1_1_requires_is_required`, `the_fapi_ciba_lifetime_bounds_hold`, `a_blank_or_oversized_jti_is_unusable`; `crates/axiam-api-rest/tests/ciba_test.rs` `signed_request_refusals_are_invalid_request_and_store_nothing` (missing `jti`, expired, over sixty minutes, a foreign `aud`, the endpoint as `aud`; the same request twice is `invalid_request` the second time and stores one row; another client may use the same `jti` value), `a_signed_request_is_verified_and_its_claims_are_the_request` (both issuer forms and an array); `crates/axiam-db/src/schema.rs` `v81_admits_the_signing_alg_and_the_request_object_replay_kind`."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "1e71bc5c-8cee-5772-985c-022d90f5f6ad",
     "path": "M763.5,722.7 L1254,784.6",
     "name": "store pending request",
     "description": "",
     "label": "store pending request (hashed auth_req_id)",
     "labelLines": [
      "store pending request (hashed",
      "auth_req_id)"
     ],
     "lx": 1008.7,
     "ly": 753.7,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "b852cced-d3c4-589b-b3bc-e8d06d418183",
     "path": "M629.5,686.8 L199,505.6",
     "name": "sign-in request notification",
     "description": "",
     "label": "sign-in request notification (port, T23.7.2)",
     "labelLines": [
      "sign-in request notification (port,",
      "T23.7.2)"
     ],
     "lx": 414.2,
     "ly": 596.2,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "e-mail / push",
     "threats": [
      {
       "number": 424,
       "title": "A flood of sign-in prompts wears a user down until one is approved by mistake",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Every CIBA request may notify its user. A client — or several — sending request after request for one person turns the notification channel into the *MFA fatigue* attack: prompts arrive until the user approves one to make them stop, or approves the wrong one. The prompt is also the only place the user can tell a legitimate request from a hostile one.",
       "mitigation": "Built (T23.7.1, T23.7.2; verified by the W5 F4 review). A notification approves nothing: the mail carries the client's name, its binding message and a link, and approval is one deliberate act on AXIAM's own page after a full sign-in — a console session of the request's own user, stepped up to the class the request asked for — under CSRF, showing the client and the binding message to compare with the client's device (T-431). One user is sent at most **three** notifications a minute whatever the clients asking (a fixed shared bucket no preset moves); a request past it is still stored and answered as usual, so the throttle reveals nothing (T-422); every client has its own `bc-authorize` bucket after authentication besides the route's; the `binding_message` is bounded and printable (T-437); a request expires in at most ten minutes; and only an address something vouches for is mailed (T-446, D-74). Tests: `crates/axiam-api-rest/tests/ciba_approval_test.rs` `a_flood_of_requests_for_one_user_sends_at_most_three_mails_a_minute`, `a_request_for_nobody_sends_no_mail`, `a_request_for_mfa_needs_a_step_up_and_then_approves`; `crates/axiam-api-rest/tests/ciba_test.rs` `bc_authorize_validates_stores_and_notifies`, `the_limiter_counts_bc_authorize`; `frontend/src/pages/ciba/CibaApprovalPage.test.tsx` `renders the binding message as text, never as markup`. Residual: three a minute is still up to 180 prompts an hour to one person from any number of clients; what makes a flood ineffective is that none can be approved without signing in on AXIAM's page."
      },
      {
       "number": 446,
       "title": "The approval mail goes to an address nobody proved, making AXIAM a phishing relay",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A CIBA request mails its user. An account can carry an address its holder never proved — a self-registration inside its grace period, or one whose verification never completed — and the subject rule admits a `PendingVerification` account whatever its age (`account_may_act`). A client able to call `bc-authorize` (registered by an administrator or with an initial access token, D-62) that names such an account would have AXIAM mail the address's real owner — a stranger to the account, who cannot approve anything — up to three times a minute, from the tenant's own sender, quoting a binding message the client wrote.",
       "mitigation": "Built (the W5 F4 review, P23W5-03, D-74). The notifier mails only an address something vouches for — D-25's rule, the one the SAML IdP applies to an email `NameID` and SSF to an email subject: `email_verified_at` is set, or the account is `Active`, a state only the verification flow, an administrator, SCIM or the directory path put an account in. Anything else is the same quiet no-op as an account that may not sign in: the request is stored and answered as usual (T-422) and waits on the approval page. Test: `crates/axiam-oauth2/tests/ciba_notifier_test.rs` `an_address_nothing_vouches_for_is_not_mailed` (it failed before the fix). Residual: a federated account stays `PendingVerification` for life (T-160) and has no vouched address unless one was verified, so it is sent no approval mail."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "5638e544-e852-5b31-92d2-a9330fce072b",
     "path": "M199,505.6 L629.5,686.8",
     "name": "approve / deny (identity pages)",
     "description": "",
     "label": "approve / deny (identity pages) (T23.7.2)",
     "labelLines": [
      "approve / deny (identity pages)",
      "(T23.7.2)"
     ],
     "lx": 414.2,
     "ly": 596.2,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [
      {
       "number": 431,
       "title": "The approval page approves without a full sign-in, or is driven cross-site",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "The approval is a state-changing act a user performs in a browser, on a request a third party started. A page that approved on a weak or stale session, that a hostile page could submit cross-site or frame, or that hid which client asked and what binding message it showed, would turn CIBA into a way to obtain a user's approval without their informed consent.",
       "mitigation": "Built (T23.7.2; verified and tightened by the W5 F4 review). The page is the console's `/ciba/approve` over `GET /api/v1/ciba/requests/{id}`, `POST …/approve` and `…/deny`: only a **console sign-in** of the request's own user decides — a token with no live session row behind it is `403`, and so, since the W5 F4 review (T-447), is a token AXIAM minted for an OAuth2 client, which names the user and a session too; `/api/v1`'s CSRF double-submit guards both decisions; the console serves `frame-ancestors 'none'` and `X-Frame-Options: DENY`. The page shows the client's name, the scopes and the binding message as text and passes back the version it read, so a request decided, expired or changed since is the one indistinguishable `404` (T-430). A request asking for a class the session has not achieved is `403 step_up_required`, and the page sends the user through the login hop's re-authentication, consuming nothing on the way back (T-404's lesson). Each decision is audited with its session (T-435). Tests: `crates/axiam-api-rest/tests/ciba_approval_test.rs` `the_routes_need_a_session_and_a_csrf_token`, `a_token_minted_for_a_client_cannot_decide_a_request`, `another_users_request_is_a_404_identical_to_an_unknown_id`, `a_request_for_mfa_needs_a_step_up_and_then_approves`, `a_decision_on_a_stale_version_is_refused`, `an_expired_request_is_refused_on_the_page_and_on_both_decisions`; `frontend/src/pages/ciba/CibaApprovalPage.test.tsx` `renders the binding message as text, never as markup`, `offers the step-up up front when the session has not achieved the class`; `frontend/e2e/ciba.spec.ts` (a real browser approval; an MFA request a password session cannot approve)."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "befc0d61-587e-5c27-b0bd-76337daf35e1",
     "path": "M146.9,854 L409.3,394.8",
     "name": "token request with auth_req_id",
     "description": "",
     "label": "token request with auth_req_id (HTTPS, client auth)",
     "labelLines": [
      "token request with auth_req_id",
      "(HTTPS, client auth)"
     ],
     "lx": 278.1,
     "ly": 624.4,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [
      {
       "number": 428,
       "title": "A limiter forgets the CIBA endpoint or grant, so initiation and polling are unmetered",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The Keycloak 26.7 lesson: a rate limit that covers every grant but one is a rate limit an attacker routes around through that one. `bc-authorize` allocates a row per request and may notify a person; the CIBA grant is polled in a loop by design. Either left out of the limiter, or polled without a per-request interval, becomes a storage, notification and CPU sink.",
       "mitigation": "Built (T23.7.1). `bc-authorize` has **its own bucket and preset** (`AXIAM__RATE_LIMIT__BC_AUTHORIZE_PER_MIN`, default 60; gateway 600, mesh 6000; a docs-parity row in `docs/deployment/rate-limit-sizing.md`), counted on the route by the per-key governor and the shared counter (keyed like `/oauth2/token`) and again per authenticated client in the handler. The CIBA grant is dispatched **inside** the token endpoint after its route limiters, its public-client bucket and its DPoP check, so `TOKEN_PER_MIN` counts it like every grant; and each request carries its own interval: a token request inside it is `slow_down` and raises the interval by 5 s, to 60 s. Tests: `crates/axiam-api-rest/tests/ciba_test.rs` `the_limiter_counts_bc_authorize` (429 after the budget), `the_limiter_counts_the_ciba_grant` (429 after the budget), `pending_then_slow_down_then_tokens_with_the_approvals_evidence` (the interval grows 5 → 10 → 15); `crates/axiam-oauth2/src/ciba.rs` `polling_inside_the_interval_slows_down_and_the_interval_grows_to_a_cap`; `crates/axiam-api-rest/src/config/rate_limit.rs` `documented_defaults_match_shipped_config`, `documented_presets_match_applied_profiles`."
      },
      {
       "number": 439,
       "title": "Tokens from a CIBA grant reach beyond what the request asked for and the user approved",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The user approves a request the client made: a set of scopes, for a resource, under the client's registration. A redemption that could add scopes, name a different `resource`, or mint for a client other than the one that asked would hand out a token wider than the approval.",
       "mitigation": "Built (T23.7.1). `scope` must include `openid` and name only scopes the client is registered for (`invalid_scope` otherwise); the RFC 8707 `resource` is validated against the client's `allowed_resources` at `bc-authorize` and **bound**: a token request may repeat it, never change it (`invalid_target`); tokens are minted for the redeeming client, which must be the starting client (T-425), with the request's scopes and the approval's evidence (T-430). Tests: `crates/axiam-oauth2/src/ciba.rs` `scope_must_carry_openid_and_stay_registered`; `crates/axiam-api-rest/tests/ciba_test.rs` `bc_authorize_refuses_each_malformed_request_with_its_section_13_code` (`invalid_scope`, `invalid_target`), `pending_then_slow_down_then_tokens_with_the_approvals_evidence` (the scope and client of the minted tokens)."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "568bd2f3-589f-5dfa-aac6-cd31ef264941",
     "path": "M506.1,366.3 L1254,755",
     "name": "redeem CIBA request",
     "description": "",
     "label": "redeem CIBA request (X6 arbiter)",
     "labelLines": [
      "redeem CIBA request (X6 arbiter)"
     ],
     "lx": 880.1,
     "ly": 560.7,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "a052c53c-af43-5c92-bb5b-74ff87dff55c",
     "path": "M627.2,735.1 L199,870.3",
     "name": "ping notification",
     "description": "",
     "label": "ping notification (T23.7.2)",
     "labelLines": [
      "ping notification (T23.7.2)"
     ],
     "lx": 413.1,
     "ly": 802.7,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [
      {
       "number": 433,
       "title": "The ping notification endpoint is used to reach internal services",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "A ping-mode client registers `backchannel_client_notification_endpoint`, and AXIAM will POST to it from inside the deployment with a bearer token attached. Pointed at a metadata service, a loopback admin port or a private address — or at a public name that resolves to one, or that redirects — the deliverer becomes a request forger (T-112 and T-392's class).",
       "mitigation": "Built (T23.7.1 at write time, T23.7.2 at delivery; verified by the W5 F4 review). Write time: the endpoint is required in ping mode, refused in poll mode, and held to the webhook outbound address policy (`validate_push_endpoint`) at the admin API and RFC 7591/7592. Delivery: the `CibaPing` deliverer's one way out is `guarded_fetch_no_redirect` with `allow_private = false` — the name resolved fresh, every address globally routable, the validated address pinned, `https` required, a `3xx` a retry and never followed — and the client is read again after the sealed credentials are opened, the ping leaving only if it is the version whose endpoint was read (W4 F4 §15). Only the record id travels on the queue. Reasons are a fixed vocabulary, never the endpoint, a header or a body. Tests: `crates/axiam-oauth2/tests/ciba_ping_test.rs` `the_address_guard_refuses_an_internal_endpoint_at_delivery`, `a_redirect_is_not_followed`, `no_reason_carries_a_credential_or_the_endpoint`, `the_clients_current_registration_decides`, `a_decision_queues_a_message_with_nothing_secret_in_it`; `crates/axiam-oauth2/src/ciba.rs` `a_ping_registration_needs_a_public_https_endpoint`; `crates/axiam-api-rest/tests/ciba_test.rs` `admin_registration_accepts_and_validates_the_ciba_metadata`; `crates/axiam-api-rest/tests/ciba_ping_flow_test.rs` `an_approval_pings_the_client_which_then_redeems_once`."
      }
     ],
     "open": 0,
     "notApplicable": 0
    }
   ],
   "total": 85,
   "open": 1,
   "notApplicable": 0,
   "bySeverity": {
    "High": 35,
    "Medium": 39,
    "Low": 6,
    "Critical": 5
   }
  },
  {
   "id": 3,
   "title": "Federation — SAML SP & OIDC relying party",
   "description": "Inbound federation from external identity providers: OIDC discovery and code exchange, SAML assertion consumption, the shared SSRF guard on every outbound IdP fetch, and attribute-to-role mapping with JIT provisioning. Since 1.0.0-beta08 this also covers the public login surface — the unauthenticated providers listing a login page renders its buttons from, the single-use handoff codes that let a cross-site SAML or Apple return issue a SameSite=Strict session, the plain-OAuth2 variant that authenticates by a userinfo call rather than a signed ID token, and organization→tenant inheritance of a federation config. Since Phase 23 (G-2) it also covers AXIAM as a SAML identity provider: the assertion issuer (`axiam_federation::saml_idp`, T23.2.2), the tenant's sealed signing credential (`saml_idp_credential`, D-21) and the trust boundary to the service providers it issues to. T23.2.3 adds the SSO endpoint (`/saml/v2/{tenant}/sso`, both bindings, IdP-initiated, the continue leg) and the `saml_authn_request` store that holds a request across the login hop. T23.2.8 (model 2.25.0) specifies the rest of the IdP ahead of its code: the SP registry store (`saml_service_provider`) and its management routes (contract §29, with SP metadata import as an SSRF and XXE surface), the IdP metadata endpoint, and the SLO endpoint with the per-SP `saml_sp_session` and `saml_logout_run` stores it needs (D-37 … D-42); its threats are Open until T23.2.5 and T23.2.4 build the controls they name.",
   "width": 1478,
   "height": 1298,
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
     "h": 1240,
     "label": "AXIAM federation services"
    },
    {
     "id": "4915d4de-0462-5843-a09e-77c433fcf2ac",
     "x": 1034,
     "y": 84,
     "w": 420,
     "h": 1180,
     "label": "Data tier"
    },
    {
     "id": "c9b4a41a-83fd-5622-a753-c56538cb279a",
     "x": 24,
     "y": 624,
     "w": 260,
     "h": 190,
     "label": "Tenant directory (LDAP / AD)"
    },
    {
     "id": "ba2d3e30-eb5c-53ec-b467-783b02929021",
     "x": 24,
     "y": 854,
     "w": 260,
     "h": 190,
     "label": "SAML service providers"
    },
    {
     "id": "cbed75da-f7cb-52ab-bf3c-dd9a6e542bde",
     "x": 24,
     "y": 1084,
     "w": 260,
     "h": 190,
     "label": "Tenant administrators"
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
      },
      {
       "number": 223,
       "title": "A templated issuer accepts every tenant of the provider",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "Verified live: Entra ID's `common` authority publishes `issuer` as `https://login.microsoftonline.com/{tenantid}/v2.0` — the placeholder literally. Strict `iss` matching rejects every token, so supporting it at all means substituting the token's `tid`. Microsoft signs every tenant's tokens at `common` with the same keys, so \"accept whatever `tid` says\" means *every Microsoft account on earth may sign in here*.",
       "mitigation": "Templated issuers are supported, and a config with one and an **empty** `allowed_issuer_tenants` is refused at create and update time — the message names both ways out (a tenant-specific authority, or a list of accepted tenants), because that configuration is occasionally intended and never intended by accident. The refusal is repeated at sign-in time, so a row written before the check existed cannot fall through to \"accept anyone\". The `tid` is read from the *unverified* payload solely to select which of a closed, operator-written set of issuer strings to require: it must parse as a UUID (otherwise a crafted value could substitute path segments), it must appear in the allow-list, and the signature check and the verified `iss` comparison both still run afterwards. It can never widen the accepted set."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
       "mitigation": "The signature is verified over the exact element that is then consumed — the same reference is used for validation and for attribute extraction — and multiple assertions or unreferenced elements are rejected outright. **Amended 2026-10-03 (T23.2.2, D-23): every signature is verified, and only two places may hold one.** The verifier called `verify_signed_xml`, which verifies only the *first* `ds:Signature` in document order, and the binding check accepted *any* `Reference` naming the assertion, verified or not; so a document the IdP signed for another purpose and carrying no assertion (a signed `LogoutRequest` or `LogoutResponse`, a signed error response), placed ahead of a forged assertion with a dummy signature naming it, passed both and provisioned an arbitrary user — an authentication bypass, found while building AXIAM's own SAML IdP. Now a `ds:Signature` is accepted only as the enveloped child of the `Response` root or of the `Assertion` that is its child, at most one per parent, each with one `Reference` to its parent's `ID`; any other `Signature` element anywhere refuses the document. Every accepted signature is verified on its own node by xmlsec (`reduce_xml_to_signed`), IDs must be unique, and the consumed assertion must carry its own enveloped signature referencing it. Tests: `saml_idp::tests::a_signed_assertion_free_document_cannot_vouch_for_a_forged_assertion`, `no_signed_gadget_vouches_for_a_forged_assertion_wherever_it_is_placed` (three gadgets — signed LogoutRequest, LogoutResponse and error response — in `Extensions`, beside the assertion and in its `Advice`, with the dummy signature enveloped, at the root or in `Extensions`; all three failed before the fix), `a_valid_response_with_an_extra_unsigned_signature_is_refused`, and the existing XSW and fixture suites."
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
       "mitigation": "The resolved user's status is checked after subject resolution and before any token is minted; Locked, Inactive and Anonymized are refused. PendingVerification is allowed deliberately: federation provisioning never moves a federated user off it, so requiring Active would refuse the whole population the feature serves while stopping nobody.\n\n**Amended 2026-10-03 (F4 P23W1-04).** The exchange path was gated and the browser sign-in path was not. Every federated callback (OIDC, SAML, plain OAuth2 “Sign in with …”, and the handoff they mint) loaded the linked user and issued a full session without reading its status, so locking or deactivating an account in AXIAM — by hand, or through SCIM `active: false` — was undone by the user's next federated sign-in, for as long as the identity provider kept authenticating them; the threat this entry names, on the path most users take. `sso_login_post_auth`, which every federated sign-in passes through before a session or a handoff code exists, now applies `axiam_auth::service::account_may_act` first: `Locked`, `Inactive`, `Anonymized` and `Deleted` are refused with the sign-in error a password login gets, and `PendingVerification` is allowed for the reason above. It is the same function `/oauth2/authorize` and the OAuth2 grants use (T-237, T-39). Test: `sec095_federated_login_gate_test.rs::p23w1_04_a_suspended_account_is_not_signed_back_in_by_its_identity_provider` (four refused statuses, no session written; the active and pending twins sign in), which failed before the fix."
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
     "open": 1,
     "notApplicable": 0
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
      },
      {
       "number": 225,
       "title": "A custom button icon is stored content served to every login-page visitor",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A generic provider may carry an operator-uploaded icon, and that image is returned by the unauthenticated providers endpoint on every render of a login page. An SVG would be a document with its own parser in that position; an unbounded one would make every visitor download whatever an operator pasted.",
       "mitigation": "Raster only — `image/png`, `image/jpeg`, `image/webp` — with `image/svg+xml` refused by name and the refusal saying why. Bounded to 16 KiB decoded, checked on the data URL's length first (so a multi-megabyte paste is rejected before anything walks it) and then on the decoded size; the admin UI crops to 64×64 in the browser, so what is uploaded is a few kilobytes and the source file never reaches the server. The value is only ever rendered as an `<img src>` under the SPA's `default-src 'self'; img-src 'self' data:` CSP. It is refused outright for the branded kinds, whose published sign-in-button rules require their own mark."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "e4028335-ec1c-5586-8b2b-49dc66c2cb6a",
     "kind": "process",
     "x": 624,
     "y": 74,
     "w": 140,
     "h": 140,
     "name": "Public providers listing",
     "lines": [
      "Public",
      "providers",
      "listing"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 218,
       "title": "The login-page provider list enumerates organizations and tenants",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "`GET /api/v1/auth/federation/providers` has to be unauthenticated — its caller is a person at a login page — and it takes an organization slug. If it answered differently for a slug that exists and one that does not, it would be an organization-slug oracle, and knowing which organizations a deployment hosts is reconnaissance for every other attack on it.",
       "mitigation": "An unknown organization or tenant and a known one with nothing configured return the **same** answer: `200` with an empty list. That is deliberately different from `oidc_start_public`, which answers `401` for a slug miss: there every failure is a `401`, so the answer carries nothing, whereas a *list* endpoint answering `401` for unknown and `200 []` for known-but-empty would be two-valued. The rate is bounded by the same `login_per_min` budget the sign-in endpoints use, through both the per-process governor and the shared limiter. The response body is a dedicated struct carrying only what a button needs — config id, provider kind, display name, protocol, and the operator's icon — rather than a narrowed admin response, so a field added to the admin surface cannot reach it by inheritance; an integration test asserts the body contains no client id, secret, metadata URL or endpoint."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "a0a5052d-6eca-5b6c-9ddd-2b3b6c284f89",
     "kind": "process",
     "x": 824,
     "y": 74,
     "w": 140,
     "h": 140,
     "name": "OAuth2 RP (userinfo variant)",
     "lines": [
      "OAuth2 RP",
      "(userinfo",
      "variant)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 220,
       "title": "Authentication rests on a userinfo call with no verifiable assertion",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "`FederationProtocol::OAuth2` exists because GitHub publishes no discovery document and issues no ID token, and Facebook's web flow returns only an access token to a confidential client. On that path there is no signature, no `nonce` and no `aud` — the whole assurance is \"the access token we just received works against the userinfo endpoint we configured\". That is a genuine downgrade from the OIDC path, and a downgrade nobody writes down is a downgrade nobody notices.",
       "mitigation": "Stated explicitly in the module documentation, in the design doc (§3), in the admin UI (the protocol carries its own warning and its own badge colour), and here. Enforced rather than merely documented: `validate_protocol_for_kind` **refuses** this protocol for `google`, `microsoft`, `apple` and `generic_oidc`, so it cannot be selected for a provider that supports OIDC properly, and the refusal says why. PKCE (`S256`) is mandatory on this path rather than optional — it is the only replay protection left once `nonce` is gone — with the verifier generated server-side, stored in `federation_login_state`, and never returned to the client. `state` stays 256-bit, server-side and single-use. The token exchange is server-side with the encrypted client secret; nothing about it happens in the browser. Honest caveat, recorded in `crate::pkce`: a provider that *ignores* `code_challenge` gives us nothing for it, and no relying party can make a remote server verify something — GitHub has supported S256 since July 2025, and where a provider does not, the residual protection is the single-use state plus the confidential-client secret."
      },
      {
       "number": 221,
       "title": "A substituted userinfo endpoint is an authentication bypass",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "With no signature to check, whoever answers the userinfo request decides who signed in. An endpoint redirected to an attacker — by a plaintext URL, a redirect, a rebound DNS name, or a value derived at runtime from something the IdP said — is a complete authentication bypass with nothing to catch it.",
       "mitigation": "The three OAuth2 endpoints are **explicit per config**, never derived from a discovery document or from anything the provider sends at runtime, and each is validated as absolute HTTPS (loopback excepted, for tests) at write time, by the same rule `validate_metadata_url` applies to the OIDC discovery URL. Every fetch goes through the shared `guarded_fetch` SSRF guard: HTTPS on every hop, resolve-and-pin against DNS rebinding, bounded redirects, and a 256 KiB response cap read as a running byte count. A `200` carrying `{\"error\": …}` is treated as the failure it is, rather than handed onward as an empty bearer token."
      },
      {
       "number": 222,
       "title": "A provider asserts an email nobody has proved they control",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "AXIAM keys account recovery, email verification and administrative notification on the address. An unverified address adopted as an identity is account takeover by whoever typed it into the provider first — and `GET https://api.github.com/user` returns `email: null` or an unverified address for a large share of accounts.",
       "mitigation": "An address the provider does not affirmatively mark verified is **never** adopted on this path: `email_verified` must be truthy or the login is refused with `UnverifiedExternalEmail`, and absent, `null` and falsey all read as false. For GitHub the primary *verified* address comes from a second, mandatory call to the `/emails` resource — derived from the configured `userinfo_endpoint`, so GitHub Enterprise Server works too — and only a `primary && verified` entry is taken, because a verified non-primary address is somebody else's choice of which mailbox represents them. Where a provider offers no verification signal at all (Facebook's Graph API), the decision is the operator's and is written down where it can be audited: an `attribute_map` literal, `\"email_verified\": \"@true\"`. Refusing rather than provisioning without an address is deliberate — an account that cannot recover itself is not a better outcome than a clear failure. See design doc §5.3."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "3cb98d5d-ccdd-57f7-9c34-e5cb08d5b33a",
     "kind": "process",
     "x": 824,
     "y": 284,
     "w": 140,
     "h": 140,
     "name": "Federation config inheritance",
     "lines": [
      "Federation",
      "config",
      "inheritance"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 224,
       "title": "An inherited organization provider signs users into the wrong tenant",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "A federation config may now live in the organization-scope tenant and be used by the organization's tenants. The config's tenant and the tenant being signed into are therefore different, and every place that previously said \"the tenant\" now has two candidates. Provisioning into the config's tenant would put every tenant's federated users in one shared tenant — an isolation failure with a benign-looking cause.",
       "mitigation": "Visibility and provisioning are decided in one place each and are deliberately different: `effective_providers` decides which configs a tenant may use, and `provision_or_link_identity` is documented and tested to create the user and the link in the **requesting** tenant. A login resolves its config through the same `effective_providers` the buttons were rendered from, so a config that is disabled, not inheritable, or shadowed by a tenant override cannot be reached by posting its id. `FederationLink`'s `(tenant_id, federation_config_id, external_subject)` uniqueness still means one link per external identity per tenant — verified, not assumed — so one Google account signing into two tenants through one inherited config gets two AXIAM users, which is what tenant isolation requires. A tenant's own config of the same kind always shadows the inherited one, **including a disabled one**, so \"disable\" cannot come to mean \"re-enable the organization's\". The SAML assertion-consumer path is the one place where the two tenants both do real work and differently: `handle_saml_response_for` records the assertion-replay row under the **config's** tenant — a no-op for a config the requesting tenant owns, and strictly stronger for an inherited one, since an assertion spent in one tenant cannot then be spent in a sibling — while the user and the link are created in the **requesting** tenant like every other protocol. Both ACS entry points resolve the config through `effective_providers` first, exactly as the OIDC and OAuth2 callbacks do; loading it with a `get_by_id` scoped to the requesting tenant, as the ACS originally did, could not find an inherited config at all."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "252914d7-795a-5c03-bbf0-52017e519ff4",
     "kind": "actor",
     "x": 49,
     "y": 684,
     "w": 150,
     "h": 80,
     "name": "Tenant directory (LDAP / Active Directory)",
     "lines": [
      "Tenant directory",
      "(LDAP / Active",
      "Directory)"
     ],
     "description": "The tenant's own directory server (OpenLDAP, Active Directory). Read-only to AXIAM: a service bind to search, a bind as the user to check the password.",
     "outOfScope": false,
     "threats": [
      {
       "number": 293,
       "title": "An impersonated directory collects passwords and answers binds (man in the middle)",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "Whoever can answer for the directory's address (a DNS answer, an on-path network, a lookalike host) receives every password a sign-in sends, and can answer every bind with success: anyone signs in as anyone.",
       "mitigation": "TLS verification is mandatory with per-tenant anchors. The tenant's `trust_anchors_pem` (CA certificates only, checked at save time; the organization's own CA can be one) is the whole trust store for its directory; only an empty list selects the public `webpki-roots` bundle the rest of the workspace trusts, and the two are never combined. The name verified is the URL's host, by rustls' WebPKI verifier, under the `ring` provider named explicitly. No code path disables verification. A failed handshake is `Unavailable` and is never retried in a weaker form. Tests: `a_certificate_outside_the_tenant_anchors_is_refused_before_any_bind`, `a_server_name_mismatch_is_refused_before_any_bind`, `the_public_bundle_does_not_trust_a_private_ca`. An IPv6-literal URL fails closed: `ldap3` cannot derive a server name from a bracketed host, so such a directory is unusable rather than unverified."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "54acf578-5395-5fed-addc-172837ec6c9b",
     "kind": "process",
     "x": 624,
     "y": 514,
     "w": 140,
     "h": 140,
     "name": "Directory sign-in (bind-as-user, bounded pool)",
     "lines": [
      "Directory",
      "sign-in",
      "(bind-as-user,",
      "bounded",
      "pool)"
     ],
     "description": "axiam-directory's LDAP client (ldap3 over rustls) and its injection into the login path through the DirectoryAuthenticator port (T23.3.2); just-in-time provisioning and explicit linking (T23.3.3, D-28); group mapping through the explicit table (T23.3.4, D-30). Every connection passes the address guard and is pinned to the vetted address, and every message from the directory passes the frame guard (T23.3.7, D-19).",
     "outOfScope": false,
     "threats": [
      {
       "number": 291,
       "title": "LDAP filter injection through the login name widens the user search",
       "type": "Tampering",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "The login name a caller types is placed into the tenant's user filter. Built by string formatting, `*)(uid=*` or `*)(|(objectClass=*` turns a lookup of one entry into a match on many, or on whichever entry the attacker steers the bind to; a distinguished name built the same way could be redirected.",
       "mitigation": "One function puts a value into a filter: `axiam_directory::escape::user_filter_for` substitutes `escape_filter_value(login_name)` into the template's single `{username}` placeholder, which `config::validate` guarantees sits in value position. The escaping covers RFC 4515's five octets (`*`, `(`, `)`, `\\`, NUL) and every byte outside printable ASCII, so the output cannot contain filter syntax; it agrees with `ldap3::ldap_escape` on everything the RFC requires and only escapes more. Login names are capped at 256 bytes and refused before any I/O beyond it. No DN is ever constructed: the user binds as the DN the directory returned, so RFC 4514 escaping is never needed. Exactly one match is required (zero and two are the same generic failure) under a server-side size limit of 2, and the client stops reading after the second entry whatever the server's limit says. Pinned against the in-process test directory, which evaluates `(attr=*)` and substrings so a widened filter would really match: `filter_injection_reaches_the_server_as_a_literal_value` asserts the server parsed each hostile name (`*`, `)(uid=*`, `*)(|(objectClass=*`, `admin)(&`, `\\`, `al*`) as one equality assertion with the literal value, and none reached a user bind; unit tests pin the escaped form of the same list, long input and UTF-8."
      },
      {
       "number": 294,
       "title": "An empty password is accepted as an RFC 4513 unauthenticated bind",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "A simple bind with a DN and an empty password is an \"unauthenticated\" bind (RFC 4513 §5.1.2), and many servers answer it with success. A client that forwards an empty password signs the named user in with no password at all; a service account with an empty secret does the same for the search.",
       "mitigation": "Refused before any network I/O: the authenticator and the client both answer an empty password with `InvalidCredentials` without opening a connection, and the client refuses an empty stored bind secret as `Misconfigured` (validation refuses one at save time). `an_empty_password_is_refused_with_zero_packets` runs against a test server that would accept the unauthenticated bind and asserts that no connection was opened; `an_empty_password_is_refused_before_the_configuration_is_read` pins the authenticator."
      },
      {
       "number": 295,
       "title": "A slow or hostile directory pins AXIAM's tasks, sockets and memory",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The directory is an external server a tenant administrator chooses. One that accepts and never answers, stalls on every bind, or streams entries without end could hold a task and a socket per sign-in attempt, and an attacker hammering one tenant's login could exhaust AXIAM's file descriptors for every tenant.",
       "mitigation": "A bounded pool: at most 8 connections in use per tenant (`MAX_CONNECTIONS_PER_TENANT`) and 256 across tenants, each permit acquired within 2 s or answered `Unavailable` at once, so the overflow is refused rather than queued; at most 4 idle connections per tenant, closed after 60 s idle or 300 s of age. A permit is held until its socket is actually closed, so the bound counts real sockets. Connecting (TCP, StartTLS and the handshake together) is bounded at 5 s, each operation at 5 s, and the whole authentication at 15 s; the user search reads at most two entries. Tests: `the_pool_bounds_concurrent_connections_per_tenant` (a burst against a slow server never exceeds the per-tenant bound plus the idle cap in open sockets, and the overflow fails fast), `pools_are_partitioned_by_tenant`, `a_silent_directory_times_out_at_connect`, `a_stalling_directory_times_out_per_operation`, `the_authentication_deadline_bounds_the_whole_flow`. **Amended 2026-10-04 (T23.3.7, P23W2-10): the frame cap.** That residual is closed. AXIAM now performs StartTLS and the TLS handshake itself and hands `ldap3` one end of a private Unix socket pair; a relay task forwards the directory's messages only after `axiam_directory::frame` has read each one whole — and the declared length is checked against the cap (default 2 MiB, `AXIAM__DIRECTORY__MAX_MESSAGE_BYTES`, clamped to 64 KiB … 16 MiB) from the header alone, before a byte of content is reserved; within the cap the buffer grows only as bytes arrive. A longer declaration ends the connection at once instead of after the operation timeout. Memory is now bounded by the cap twice (the relay's message and `ldap3`'s buffer) per connection, times the pool bounds. Tests: `an_over_long_declared_length_aborts_the_connection_without_waiting_for_it`, `the_cap_is_configurable_and_ordinary_traffic_passes_under_the_default` (`connector_guard_test.rs`), and the unit test `a_declared_length_over_the_cap_is_refused_from_the_header_alone`, which feeds the reader the six header octets only and gets the refusal, not a wait for content."
      },
      {
       "number": 296,
       "title": "A referral or search reference steers the bind to an attacker's host",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "LDAP lets a server answer \"ask over there\": a referral result, or search result references beside the entries. A client that chases them sends the service bind, and possibly the user's password, to a host the configuration never named; one that counts a reference as an entry can be made to match.",
       "mitigation": "Referrals are never followed. Search result references and intermediate responses are skipped and never counted as entries; a search or bind that ends in a `referral` result is `Misconfigured`. The tests stand up a second live server as the referred host and assert it saw no connection: `search_references_are_neither_followed_nor_matched`, `a_referral_result_is_not_followed`."
      },
      {
       "number": 297,
       "title": "One tenant's sign-in is answered by another tenant's directory or connection",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "Directory configurations, decrypted secrets, trust stores and pooled connections are all per tenant, and one process holds them all. A lookup keyed by anything but the tenant being signed in to, or a pooled connection reused across tenants or across a configuration change, authenticates a user against the wrong directory, or searches with another tenant's bind account.",
       "mitigation": "The authenticator reads the configuration and decrypts the secret for the tenant the login path resolved, on every sign-in. The pool is keyed by tenant id with a semaphore per tenant; a pooled connection carries its configuration's generation (row id and `updated_at`) and is closed rather than reused when that differs, so a new URL, bind DN, secret or trust store applies at the next sign-in. The TLS cache is keyed the same way. A connection bound as a user is never pooled, so no search runs with a previous user's rights. Tests: `one_tenant_is_never_answered_by_another_tenants_directory`, `pools_are_partitioned_by_tenant`, `the_pool_reuses_service_connections_and_never_user_bound_ones`. **Entry binding (login path).** A successful bind is accepted only when the identifier the directory returns equals the account's `directory_external_id` (case-insensitively), so a login name that resolves to a different entry — a renamed account, a colliding `uid`, a second person given the same login name — cannot sign in as this account even with that entry's correct password; the refusal is counted. Test: `an_answer_from_another_entry_is_refused_and_counted`."
      },
      {
       "number": 300,
       "title": "A tenant-configured directory URL turns sign-in into a probe of AXIAM's own network",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The directory host and port are whatever a tenant administrator saves. Pointed at an internal address, each directory sign-in makes AXIAM open a TCP connection and begin a TLS handshake there, and how long the failure takes distinguishes an open port from a closed one.",
       "mitigation": "**Closed 2026-10-04 (T23.3.7, D-19, D-32): the address guard.** `axiam_directory::address::guard` resolves the directory host once and judges every address it resolves to with the classifier `guarded_fetch` uses (`axiam_core::ip_class`, moved below both so they cannot disagree): loopback, unspecified, link-local (`169.254.169.254`, `fe80::/10`), multicast and special-purpose addresses are always refused; IPv4-mapped forms are judged as the IPv4 address they carry; a metadata endpoint inside a private range (`fd00:ec2::254`, `100.100.100.200`) is refused whatever the configuration says; an address of this host on AXIAM's REST or gRPC port is refused; and a private address (RFC 1918, CGNAT, ULA) is admitted only inside a network the operator listed in `AXIAM__DIRECTORY__ALLOWED_PRIVATE_NETWORKS` — deployment configuration, unset admits none. An IPv6-literal URL is refused. `DirectoryClient::connect` runs the guard at **every** connection — the pool, the user bind, group lookup, the sync job — and opens its TCP socket to a vetted `SocketAddr`, so nothing resolves the name a second time; the TLS server name stays the URL's host. The management routes (T23.3.8) call the same guard before a configuration is saved, and answer every resolution-dependent refusal of a host name with one message (T-356). Tests (`connector_guard_test.rs`): `each_refused_class_is_refused_at_guard_and_at_connect_with_no_connection`, `a_hostname_that_resolves_to_loopback_is_refused`, `an_own_listener_port_is_refused_and_another_port_is_not`, `a_private_address_is_refused_without_the_allow_list_and_admitted_with_it`, `dns_rebinding_between_check_and_connect_never_reaches_loopback`, `the_connection_uses_the_pinned_address_and_resolves_once_per_connection`, `the_tls_name_checked_is_the_hostname_over_a_pinned_address`, plus the classifier's table test in `axiam-core`. Residual, stated: inside the networks the operator lists, any tenant administrator can aim the connector at any host and port, and what that buys is a TCP connect and a TLS ClientHello (after a 31-byte StartTLS request on `ldap://`) toward a host that must present a certificate chaining to that tenant's anchors before anything else is sent, answered to the user as the generic failure. The listener rule recognises this host's own addresses only — not another replica's pod address, nor a Service that forwards back to AXIAM — so the operator note says not to list AXIAM's own networks."
      },
      {
       "number": 301,
       "title": "Sign-in latency tells directory accounts apart from local and unknown ones",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A directory account's password is checked by a network bind; a local one's by an Argon2id verify; an unknown name's by a dummy verify. If those take different time, or answer differently, the login endpoint tells an attacker which names exist and which are directory accounts — and whether the directory is up.",
       "mitigation": "The response is the same in every case: `InvalidCredentials`, the answer an unknown name and a wrong local password already get, for a wrong directory password, an entry that is not the account's, an unreachable, misconfigured or disabled directory, a restricted account, an empty password and a deployment without an authenticator alike. The work is equalised the way SEC-026 equalises unknown names: every directory branch runs the same dummy Argon2id verify, under the same hash permit and the same `503` backpressure rule — on the bind path concurrently with the bind, holding a permit acquired before the directory is contacted, so saturation answers `503` exactly where the local path would. The residual, stated plainly: a directory sign-in costs `max(Argon2id verify, bind)`, and a bind (two TLS handshakes and three round trips) usually costs more than one verify, so a directory account answers measurably later than a local or unknown name. The login endpoint's per-IP rate limit and the per-account lockout bound how fast that can be sampled. The same shape as T-30's lockout branch, which also answers without a verify. Tests: `a_locked_account_is_refused_before_the_directory_is_called`, `there_is_no_fallback_to_a_local_hash`, `an_unknown_name_is_answered_as_today_without_the_directory` (`axiam-auth/tests/directory_account_test.rs`)."
      },
      {
       "number": 302,
       "title": "AXIAM is used to lock users out of the corporate directory",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Active Directory and many OpenLDAP deployments lock an account after a number of failed binds. An attacker who sprays passwords at AXIAM's login endpoint could make AXIAM perform those failed binds, locking real users out of their corporate accounts — mail, VPN, workstation — not just out of AXIAM; and the directory's own lockout may be absent altogether, leaving AXIAM's as the only brake.",
       "mitigation": "AXIAM's brute-force controls sit in front of the directory. The temporary lockout is checked before the directory branch, so a locked account is refused without a bind; an inactive, suspended or deleted account and an empty password are refused without one too. A failed bind increments the same counter a wrong local password does, with the tenant's lockout policy, so AXIAM locks the account after the tenant's threshold and stops binding; a success resets it. Configure the tenant threshold below the directory's own so AXIAM's lockout always engages first; the per-IP login rate limits apply unchanged. An unusable directory does not count against the account. Tests: `a_locked_account_is_refused_before_the_directory_is_called`, `failed_binds_count_and_lock_and_then_stop_reaching_the_directory`, `an_inactive_directory_account_is_refused_before_the_directory`, `an_empty_password_never_reaches_the_directory`. **Widened 2026-10-04 (T23.3.7): names AXIAM holds no account for.** With `jit_provisioning` on, an unknown login name reaches the directory too (T23.3.3), and there is no AXIAM account whose counter could stop it; that case is T-332, closed by the W3 F4 review with a failure counter for names AXIAM holds no account for."
      },
      {
       "number": 303,
       "title": "A directory account is taken over through a local password path",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "A directory account's password belongs to the directory, where the customer's own policy, rotation and offboarding apply. A local credential beside it — a reset link mailed to the account's address, a self-service change, an administrator's or a SCIM provisioner's password write, an OPAQUE record, or simply the local hash it was created with — is a second way in that the directory never sees: disabling the person in Active Directory would leave it working, and whoever controls the mailbox or the provisioning token owns the account.",
       "mitigation": "Every local door is refused, and the account holds nothing a door could open. **The hash.** `mark_directory_account`, the marker's only writer, replaces `password_hash` with an Argon2id hash of 32 random bytes nobody holds and deletes any OPAQUE record, in the same transaction; and no sign-in path verifies a directory account's hash at all (`AuthService::login` binds to the directory, gRPC `ValidateCredentials` answers `valid: false`). **Change.** `AuthService::change_password` refuses before verifying or writing anything (`400 validation_error`, an existing code). **Reset.** The request answers a directory account exactly as an unknown address — the same `200`, the same dummy Argon2id verify, no token — so it reveals no more than existence does today; a confirm with a token that predates the marking spends it and writes nothing. **Administrators.** The native admin API has no password write; SCIM `PATCH` refuses `password` for a directory account with RFC 7644's `mutability`. **OPAQUE.** `login/start` serves a directory account the decoy whatever the table holds, `login/finish` refuses one with the generic `401`, and `store_credential` — the one place a record is written — refuses one too. **The marker itself** cannot be set or cleared by the admin API or SCIM (neither `CreateUser` nor `UpdateUser` carries it). Tests: `directory_account_test.rs` in `axiam-auth` (change, reset request, reset confirm), in `axiam-api-rest` (the change, reset and confirm routes, both OPAQUE doors, the admin API), in `axiam-scim` (password write, marker), `grpc_units.rs::validate_credentials_refuses_a_directory_account`, and `user_directory_marker_test.rs` (the transaction). Residual: a passkey enrolled by the account keeps working until the account is disabled in AXIAM (the sync job, T23.3.5, carries directory disablement over)."
      },
      {
       "number": 331,
       "title": "A hostile directory's malformed message crashes or panics the connector every tenant shares",
       "type": "Denial of service",
       "severity": "High",
       "status": "Mitigated",
       "description": "`ldap3 0.12` hands every message to `lber`, whose parser recurses once per nested constructed element with no bound: a few tens of kilobytes of nesting overflow a worker's stack, and a stack overflow aborts the process — every tenant's sign-ins with it. Its envelope decoder `expect`s a message id and an operation, so a short message panics the connection's task. The directory is a tenant administrator's choice.",
       "mitigation": "The frame guard beneath `ldap3` (`axiam_directory::frame`, through the crate's relay): AXIAM performs StartTLS and the TLS handshake itself and gives `ldap3` one end of a private Unix socket pair; a relay task reads each message from the decrypted stream and forwards it only after checking it whole — an outer `SEQUENCE`, definite lengths of at most four octets, single-octet tags, every element inside its parent, constructed nesting at most 16 deep (walked iteratively, so the check cannot itself be driven into the stack it protects), and an envelope of a one-to-four-octet message id followed by an operation. The first message refused closes both sockets, the operation in flight fails as `Unavailable`, and the reason is logged at `warn`. On a platform without Unix sockets the connector refuses to connect rather than run without the guard. Tests: `nesting_past_any_stack_is_refused_and_the_process_survives` (20 000 levels), `an_envelope_ldap3_would_panic_on_is_refused`, and the unit tests `nesting_is_bounded_without_recursion` (100 000 levels), `envelopes_ldap3_would_panic_on_are_refused`, `an_element_that_overruns_its_parent_is_malformed`. Residual: what `ldap3` does with a well-formed operation is still `ldap3`'s code; a panic there unwinds that connection's task only (the release profile keeps `panic = \"unwind\"`), and search entries are read by AXIAM's own fallible parser (T23.3.2), never `SearchEntry::construct`."
      },
      {
       "number": 332,
       "title": "With just-in-time provisioning on, an unknown name costs a directory bind that no AXIAM lockout counts",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "T-302's brake is the per-account counter, and an unknown name has no account. With `jit_provisioning` on, every sign-in for a name AXIAM does not hold is a directory search and, when the directory knows the name, a bind with the presented password: AXIAM can be used to spray passwords at directory accounts that have never signed in to AXIAM — guessing them, or tripping the directory's own lockout for them — at whatever rate the login endpoint admits.",
       "mitigation": "**Closed 2026-10-04 (W3 F4 review, P23W3-02).** A failure counter for names AXIAM holds no account for: `axiam_auth::unknown_name_lockout`, keyed by tenant and the login name as typed, trimmed and lower-cased (directories compare names without regard to case), applying the tenant's own lockout policy — after `max_failed_login_attempts` failures the directory decided (a wrong password or no such entry; an unusable directory counts against nobody, as for accounts) the name is locked for `lockout_duration_secs`, growing by the backoff to `max_lockout_duration_secs`. A locked name is answered as an unknown user, dummy verify included, **without asking the directory**, even with the right password; a successful sign-in clears it. The provisioning gate, the hash permit taken first, the per-IP login limits and the unknown-user answer (T-333) still stand in front of it. Tests (`axiam-auth/tests/directory_provisioning_test.rs`): `p23w3_02_guessing_at_an_unknown_name_stops_reaching_the_directory`, `p23w3_02_failures_below_the_threshold_still_provision`, the counter's unit tests (`unknown_name_lockout::tests`), and the three that pinned the bounds before: `every_refusal_is_the_unknown_user_answer_and_pays_the_dummy_verify`, `saturation_answers_the_same_503_before_the_directory_is_contacted`, `a_tenant_without_a_directory_observes_nothing_new`. Residual: the counter lives in each process's memory, so with N replicas a name gets at most N times the policy's attempts per lockout window (the bound the in-memory rate-limit governor has) and a restart forgets it; at most 50 000 names are tracked per process, and a full table makes room from the least recently failed name that is not locked, so a spray of other names cannot free a locked one; whoever guesses at a name can lock it out of its first sign-in for the lockout window — the account lockout's own trade-off."
      },
      {
       "number": 333,
       "title": "Just-in-time provisioning tells an outsider which names the directory holds",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "If a name the directory knows answered differently, or later, than one it does not — or a refused provisioning looked unlike a wrong password — the login endpoint would enumerate the corporate directory for anyone, and the account's creation would itself be a signal.",
       "mitigation": "Every non-success branch of `AuthService::login_unknown_user` — no directory, provisioning off, no entry, a wrong password, an ambiguous entry, an unusable attribute, a collision (T-334), a directory that cannot be reached — is the unknown-user `InvalidCredentials`, and the dummy Argon2id verify runs beside the directory call under a hash permit taken first, so each costs at least what an unknown name costs. Success creates the account only after the bind succeeded; administrators and the audit log see it, the caller sees an ordinary sign-in. Residual, as for T-301: a bind usually costs more than a verify, so a name the directory knows can answer measurably later; the per-IP login limits bound the sampling. Tests: `every_refusal_is_the_unknown_user_answer_and_pays_the_dummy_verify` (each branch timed against the unknown-user cost), `a_first_login_creates_an_active_marked_account_and_signs_in`."
      },
      {
       "number": 334,
       "title": "A directory administrator takes over a local AXIAM account by creating an entry with its name or address",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "Whoever administers the tenant's directory can create an entry called `admin`, or one carrying a local administrator's email address. Linking by name — at sign-in or in the sync job — would make that entry's password the local account's.",
       "mitigation": "D-28: just-in-time provisioning never links, and the sync job never creates or links; both act only on accounts already carrying `directory_external_id`, whose only writers are on the directory path (D-18, D-29). Before creating, a collision probe compares the entry's username and email, lowercased, with both columns of every account of the tenant — every status, tombstones included — and the v71 unique indexes decide a concurrent race; a collision is the generic failure plus a `directory.jit_refused` audit row naming the collision, never the password. Linking an existing account is an explicit administrator act (T-336, T-337). Tests: `an_entry_that_collides_with_a_local_account_is_refused_and_audited` (five collision variants), `two_concurrent_first_logins_yield_exactly_one_account`, `a_local_account_is_never_touched` (sync). Residual: the comparison is Unicode lowercasing, not compatibility normalisation or confusable detection, so a fullwidth or look-alike spelling of `admin` is a distinct account — a phishing aid in a list of users, not a takeover."
      },
      {
       "number": 335,
       "title": "Directory-supplied attributes inject control characters, bidirectional overrides or oversize values into AXIAM's records",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A provisioned account's username, email and display name are whatever the directory says. Control characters, `U+202E`-style overrides or a megabyte of display name would reach every log line, administrator list, token claim and email that renders them.",
       "mitigation": "One set of cleaners, `axiam_core::models::directory_profile`, used by provisioning and by the sync job: a username or email holding a control, whitespace or bidirectional-control character, or longer than its bound, is refused rather than repaired (the sign-in fails with the generic answer and an `unusable_attributes` audit row, and an entry without a plausible email is refused too, D-29); a display name loses its overrides and controls, has its whitespace collapsed and its length capped. The client drops any attribute value over 1 024 bytes rather than truncating it — a truncated address is another address. Tests: `directory_supplied_attributes_are_cleaned_before_they_are_stored`, `an_entry_without_a_usable_address_is_refused_and_audited`, `a_value_that_cannot_be_cleaned_leaves_the_account_alone` (sync), and the cleaners' unit tests."
      },
      {
       "number": 336,
       "title": "A linked account keeps a credential that signs in without the directory deciding",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "Linking turns a local account into a directory account. Marking it retires the local password and the OPAQUE record (D-18), but its sessions, refresh tokens, passkeys, federation links and certificates were issued on the old basis; any one left alive is a way in that disabling the person in the directory does not close.",
       "mitigation": "`AuthService::link_local_account_to_directory` (D-28) marks the account, then deletes its WebAuthn credentials and its federation links, revokes its still-active `User`-type certificates, and revokes its sessions and OAuth2 refresh tokens last — through the repositories, so the session validation cache and the revocation feed see it. TOTP is kept: it is a second factor behind the directory password. A link interrupted part-way is completed by calling it again. **Amended 2026-10-04 (W3 F4 review, P23W3-01):** federation links were missing from the set — an upstream OIDC or SAML identity bound to the account resolved its link and opened a session without the directory deciding, exactly as a passkey does; linking now deletes every link the account holds and counts them in the audit row (`federation_links_deleted`), and a deleted link is not re-made, because federated provisioning never links by name or address. Tests: `linking_marks_the_account_and_retires_what_the_directory_does_not_decide`, `p23w3_01_linking_removes_the_accounts_federation_links`, `an_interrupted_link_is_retryable_and_the_retry_completes_it`. Residual (D-29): no certificate carries a user binding, so certificates are found by convention — `metadata.user_id`, or a subject CN equal to the username or email, ignoring case — with over-matching the accepted side, and a real binding is a filed follow-up; a certificate authenticates only as the service account it is bound to, which limits what a missed one could do."
      },
      {
       "number": 337,
       "title": "An administrator links a colleague's account to a directory entry they control",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Linking hands an account's password to the directory. A tenant administrator who can also create directory entries could create one with a colleague's username, link the colleague's account, and sign in with a password of their own choosing.",
       "mitigation": "Linking resolves the entry by the account's own username through the tenant's directory — never an identifier the caller supplies — refuses an entry already linked to another account and an account linked to a different entry, stays inside the path's tenant, revokes everything the account held (T-336), which its owner notices as being signed out everywhere, and writes a `directory.account_linked` row with the actor and the counts. Contract §30 puts the route behind a permission of its own, `directory:link`, apart from `directory:write`. It adds no capability a tenant administrator lacks: `users:update` already changes an account's email, and with it where the reset mail goes. Tests: `an_entry_already_linked_elsewhere_is_refused_and_nothing_is_revoked`, `an_account_linked_to_a_different_entry_is_refused`, `a_deleted_account_cannot_be_linked`, `an_entry_that_cannot_be_resolved_refuses_the_link_and_revokes_nothing`."
      },
      {
       "number": 338,
       "title": "A directory administrator grants AXIAM roles by naming or nesting a group",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "Group mapping turns directory membership into AXIAM group membership, and so into roles. Matching by name or DN prefix, or creating AXIAM groups from directory ones, would let whoever administers the directory create `admins` — or nest any group inside a mapped one — and grant themselves privileges no tenant administrator assigned.",
       "mitigation": "D-30: an explicit table only. `DirectoryConfig.group_mappings` maps a directory group DN, compared after RFC 4514 normalisation (`axiam_directory::dn`), to an AXIAM group of the same tenant; at most 500 rows, written only through the configuration; no match by name, no prefix or wildcard, and no AXIAM group is ever created. Nesting is followed to the configured depth, and only groups the table names count. Tests: `unmapped_directory_groups_grant_nothing_including_one_named_like_an_axiam_group`, `a_mapping_matches_whatever_the_spelling_of_the_dn`, `a_role_through_a_mapped_group_is_effective_and_gone_after_removal`, `the_table_holds_at_most_five_hundred_rows`."
      },
      {
       "number": 339,
       "title": "A deep, cyclic or enormous group graph exhausts the connector during sign-in",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Nested groups are resolved on the sign-in path. A directory whose groups nest without end, loop, or number in the tens of thousands could make one sign-in issue unbounded searches and hold a pooled connection while it does.",
       "mitigation": "Resolution follows at most `group_nesting_depth` levels (0–10, default 5), terminates cycles on the normalised DN, and refuses — rather than truncates — at the 1 001st group; a ranged `memberOf` (Active Directory's answer past 1 500 values) counts as the cap. Every search runs under the per-operation deadline on the pooled service connection, inside the per-tenant bounds, and every message passes the frame cap (T-295). A refused resolution refuses the sign-in (T-340). Tests: `nesting_is_followed_to_depth_n_and_n_plus_one_is_not_asked`, `a_cycle_terminates`, `the_hard_cap_of_one_thousand_groups_refuses`, `member_of_beyond_the_cap_or_in_ranged_form_refuses`, `a_slow_directory_is_unavailable_within_the_deadline`."
      },
      {
       "number": 340,
       "title": "Memberships the directory revoked survive while the directory cannot be asked",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A user removed from a mapped group in the directory should lose the AXIAM group. A sign-in that kept the old memberships whenever the directory could not answer — an outage, a timeout, the cap — would keep access the directory had taken away.",
       "mitigation": "Fail closed (D-30): the mapping runs on every successful directory sign-in before any session or MFA challenge, and a lookup that fails or hits a cap refuses the sign-in with the generic answer, changes nothing and does not count against the account; a provisioned account whose lookup fails holds no memberships. The sync job applies the same mapping on every run, and a failed run changes nothing. Tests: `a_failed_group_lookup_refuses_the_sign_in_and_changes_nothing`, `a_provisioned_account_whose_group_lookup_fails_is_refused_and_holds_nothing`, `the_group_mapping_follows_the_directory_on_every_run`. Residual: a session already open keeps the memberships until the next sign-in or the next successful sync run applies the removal (the decision cache is then flushed, T-343); deactivation, not mapping, revokes sessions."
      },
      {
       "number": 342,
       "title": "A mapping row or a mapped edge places a user in another tenant's group",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "The mapping table names AXIAM groups by id, and one process serves every tenant. A row naming another tenant's group, or an edge written without the tenant, would grant one tenant's directory users another tenant's roles.",
       "mitigation": "Every `group_id` in the table is checked, at write and before anything is written, to be a group of the configuration's own tenant; membership writes and removals are scoped by tenant; a row whose group has since been deleted is skipped, never re-pointed. Tests: `a_mapping_naming_another_tenants_group_is_refused_and_writes_nothing`, `a_mapping_naming_no_group_at_all_is_refused`, `directory_memberships_are_tenant_scoped`, `a_mapping_row_whose_group_was_deleted_is_skipped`."
      },
      {
       "number": 343,
       "title": "A cached authorization decision outlives the directory's removal of a membership",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Authorization decisions are cached. A membership the mapping removes but whose cached allow survives keeps granting the role until the entry expires — on every replica.",
       "mitigation": "Mapping writes go through `RepositoryGroupMapper`, whose `MembershipChangeHook` (installed by `axiam-server`) flushes the decision cache for the user, locally and by broadcast, whenever a membership changes — as the group-membership routes do. Tests: `a_membership_change_flushes_the_decision_cache_through_the_hook`, `a_role_through_a_mapped_group_is_effective_and_gone_after_removal`. Residual: a broadcast that fails is logged, and the other replicas' entries then live out the cache TTL."
      },
      {
       "number": 356,
       "title": "The directory management routes' address-guard answers map the deployment's internal DNS",
       "type": "Information disclosure",
       "severity": "Low",
       "status": "Mitigated",
       "description": "A tenant administrator saving a directory URL with a host name learned from the `400` whether the name did not resolve, resolved into a private range outside the allow-list, to loopback, to the metadata service or to one of AXIAM's own listeners — so the write route answered, thirty times a minute, which names exist in the deployment's DNS and into which range they point: reconnaissance of an operator's network that a tenant in a multi-tenant deployment has no business seeing.",
       "mitigation": "Decided in the W3 F4 review (P23W3-04, 2026-10-04): for a host **name**, every refusal that depends on what the name resolved to — it did not resolve, it resolved to too many addresses, to loopback, link-local or the metadata service, unspecified, multicast or special-purpose space, an own listener, or a private range outside the allow-list — is one `400` message and one audit rule, `address_guard.not_permitted`; the specific rule goes to the operator's log only. An IP literal, an IPv6 literal and an unparseable URL keep their specific answers, which reveal nothing the administrator did not type. The writes stay on the `directory_admin` bucket (30 a minute) and every refusal is audited. Tests: `p23w3_04_a_refused_host_name_gets_one_answer_whatever_it_resolves_to`, `the_address_guard_refuses_each_class_as_a_400_naming_the_rule`. Residual: a write that succeeds still tells the administrator that the name resolved into a permitted range — inherent in saving it, and confined to networks the operator listed for directories."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "5ecdb607-7d05-50ee-867f-13653e64219b",
     "kind": "store",
     "x": 1079,
     "y": 604,
     "w": 170,
     "h": 80,
     "name": "directory_config (encrypted bind secret)",
     "lines": [
      "directory_config",
      "(encrypted bind secret)"
     ],
     "description": "One row per tenant (schema v70); the bind secret AES-256-GCM encrypted under directory_encryption_key (D-15).",
     "outOfScope": false,
     "threats": [
      {
       "number": 298,
       "title": "The directory bind secret is disclosed from the database, an API response, a log or a Debug line",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "The bind account can read the customer's directory: every user, every group. Its secret in plaintext in the database, returned by a read, or printed in a log line is a breach of the customer's directory, not only of AXIAM.",
       "mitigation": "Decision D-15: AES-256-GCM in the row with a fresh nonce per write, under the optional provider key `directory_encryption_key`, through the existing `axiam_auth::crypto` helpers. No read returns it; only `decrypt_bind_secret` produces the plaintext, as a `Zeroizing<String>`. `NewDirectoryConfig`'s `Debug` redacts it, and the client never logs it or carries it in an error. Residual, stated as it is for the per-tenant SMTP password: no associated data binds a ciphertext to its tenant's row, so a party able to write the database could move one tenant's ciphertext into another's row. That party already holds the data tier, which this model treats as full compromise. The bind account should hold read-only rights, and the operator note in `docs/deployment/README.md` says so. **Amended 2026-10-03 (F4 P23W2-01): a kept secret keeps its connection.** The repository's `update` kept the stored ciphertext whenever no new secret came with the request, whatever else changed — and `an_update_without_a_secret_keeps_the_stored_one` pinned a URL change doing exactly that. So whoever may edit the configuration (no route yet; T23.3.8 adds one for tenant administrators) could repoint the URL at a host they control, name their own CA as the trust anchor, and receive the write-only secret in the next service bind: disclosure by redirection, which no read path would ever have allowed. `SurrealDirectoryConfigRepository::update` now refuses, with `Validation` and no change at all, an update without a secret whose `url`, `start_tls`, `bind_dn` or `trust_anchors_pem` differs from the stored value; the comparison is in the `UPDATE`'s `WHERE`, so it cannot race the write. Re-entering the secret makes the same change an ordinary update. Test: `directory_config_repository_test.rs::p23w2_01_moving_the_connection_requires_the_secret_again` (failed before the fix). **Amended 2026-10-03 (F4 P23W2-02): the cascade's failure is reported.** The tenant delete removes the tenant's directory row in the same transaction as the tenant (T23.3.1), so a failure removes neither; but the repository did not check the response, and a cancelled transaction answered `Ok` — the handler then answered `204` and wrote a \"tenant deleted\" record for a tenant that still existed with its ciphertext. `SurrealTenantRepository::delete` now checks it. Test: `p23w2_02_a_tenant_delete_that_fails_is_reported_and_removes_nothing` (failed before the fix). That the delete cascades to nothing else — users, sessions, OAuth2 clients and refresh tokens, the SMTP ciphertext — is pre-existing and reported separately (P23W2-04)."
      },
      {
       "number": 299,
       "title": "An absent encryption key makes directory sign-in insecure, or keeps the server from starting",
       "type": "Denial of service",
       "severity": "Low",
       "status": "Mitigated",
       "description": "The directory key is optional. A missing key must not mean a plaintext secret, a default key, or a server that refuses to boot over a feature most deployments do not use.",
       "mitigation": "Unavailable rather than insecure. Without the key a save is refused with an error naming it, `decrypt_bind_secret` answers `ServiceUnavailable`, and the authenticator turns that into `Unavailable` before any connection is opened. Boot logs the key's absence at INFO and continues. Test: `a_missing_encryption_key_is_unavailable_with_no_connection`."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "0650fae0-6076-575a-82ea-efbb5f39ab39",
     "kind": "actor",
     "x": 49,
     "y": 914,
     "w": 150,
     "h": 80,
     "name": "SAML service provider (registered per tenant)",
     "lines": [
      "SAML service",
      "provider",
      "(registered per",
      "tenant)"
     ],
     "description": "A relying application (SaaS or internal) registered in the tenant's SP registry (T23.2.1): entity id, ACS allow-list, NameID policy, attribute mapping. External: AXIAM controls what it signs for the SP, not what the SP does with it.",
     "outOfScope": false,
     "threats": [
      {
       "number": 306,
       "title": "A leaked signing key keeps forging assertions after the credential is retired",
       "type": "Spoofing",
       "severity": "Critical",
       "status": "Open",
       "description": "Service providers pin the IdP certificate from metadata and cache metadata for hours or days, and SAML has no revocation channel SPs consult. Once a tenant's signing key has leaked, every SP that trusts the tenant accepts assertions forged for any user until its own administrator removes the certificate.",
       "mitigation": "Partly mitigated. Retiring the credential destroys its key and takes its certificate out of the tenant's metadata (D-21; the metadata endpoint is T23.2.5), and a credential is valid for at most two years (`MAX_SAML_IDP_CREDENTIAL_VALIDITY_DAYS`), after which AXIAM's own signer refuses it (T-308) and SPs that check validity do too. Open because nothing AXIAM does reaches an SP's pinned trust: recovering from a leak means telling every SP administrator, which is a procedure, not a control. T-304 and T-305 are what keep the key from leaking."
      }
     ],
     "open": 1,
     "notApplicable": 0
    },
    {
     "id": "d311d7ba-fb5e-54ed-aab1-9d7aed357c69",
     "kind": "process",
     "x": 824,
     "y": 514,
     "w": 140,
     "h": 140,
     "name": "SAML assertion issuer (saml_idp)",
     "lines": [
      "SAML",
      "assertion",
      "issuer",
      "(saml_idp)"
     ],
     "description": "axiam_federation::saml_idp (T23.2.2, behind the `saml` feature): builds the assertion (pairwise or email NameID, bearer confirmation, five-minute conditions, AuthnStatement from the session, attribute mapping), signs it with the tenant's credential (enveloped XML-DSig, rsa-sha256), optionally signs the response, checks its own output and returns the HTTP-POST binding value. Pure library; the SSO endpoint (T23.2.3) calls it.",
     "outOfScope": false,
     "threats": [
      {
       "number": 305,
       "title": "The SAML signing key leaks from memory, a log line, a Debug print or an error",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "The signing key is opened on every sign-on. A copy left in a freed buffer, printed by a derived `Debug`, interpolated into a log line or carried in an error string reaches crash dumps, log pipelines and support tickets, and from there anyone can sign as the tenant.",
       "mitigation": "The plaintext exists only as `SamlIdpSigningKey::private_key_pem`, a `Zeroizing<String>` whose `Debug` prints `[REDACTED]` (T23.2.1). The issuer (`axiam_federation::saml_idp`) decodes it to DER itself, into `Zeroizing` buffers, rather than through the `pem` crate, whose parser keeps intermediate copies of the base64 text it does not wipe; the DER is dropped as soon as the last signature is made. `SamlIdpError` is a closed set of fixed strings with no fields, so no refusal can carry key material, and the signing path logs only xmlsec's own error text. The pairwise-identifier key (D-22) is held the same way (`PairwiseKey`: zeroizing, `Debug` redacted). Tests: `no_debug_output_carries_key_material`, `a_pkcs1_key_signs_too_and_a_key_that_does_not_match_the_certificate_is_refused`. Residual: libxmlsec1 and OpenSSL hold their own copy of the key for the duration of a signature and release it under their own discipline (OpenSSL clears an RSA key's private components when it frees them)."
      },
      {
       "number": 307,
       "title": "An assertion is signed with one tenant's key, or under one tenant's Issuer, for another tenant's user or SP",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "Credentials, SP registrations, users and sessions of every tenant sit in one process. An issuer that took its tenant from the SP row, the session or the credential rather than from the request could sign tenant B's user into tenant A's SP, or put tenant A's `Issuer` on tenant B's assertion; an SP trusting tenant A would then admit a user tenant A never authenticated.",
       "mitigation": "The tenant is an explicit input taken from the request path (`SsoIssuance::tenant_id`), and the `Issuer` and `NameQualifier` are `idp_entity_id(public_base_url, tenant_id)` — one function, never a stored value; T23.2.5's metadata `entityID` uses the same one. `SamlIdpIssuer::issue` refuses with `TenantMismatch` (answered `Responder`) unless the SP row, the user, the session, every group and role passed for the attribute statement, and the signing credential all carry that tenant; the session must also be the user's and unexpired. Tests: `every_input_from_another_tenant_is_refused`, `a_credential_outside_its_validity_window_or_not_active_refuses_to_sign` (another tenant's credential), `the_session_must_be_the_users_and_live_and_the_account_may_act`, `the_idp_entity_id_is_one_function_of_the_base_url_and_the_path_tenant`."
      },
      {
       "number": 308,
       "title": "An expired, not-yet-valid or retired credential signs assertions",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "`SamlIdpCredentialService::get_active_signing_key` returns the tenant's active row whatever its dates (T23.2.1 left the decision to the signer). A signer that used it anyway would issue under a certificate its SPs may already distrust, or keep a credential in service past the date an administrator relied on.",
       "mitigation": "The signer refuses before any key is decoded: the credential must be `active` and `not_before ≤ now < not_after`, otherwise `CredentialNotActive` or `CredentialNotValid`, both answered `Responder` with no status message. Tests: `a_credential_outside_its_validity_window_or_not_active_refuses_to_sign` (one second past `not_after`, exactly at it, one second before `not_before`, `next`, `retired`)."
      },
      {
       "number": 310,
       "title": "The SAML signing certificate is accepted as a TLS or client-authentication credential",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The leaf is signed by a CA of the tenant's organization, which other verifiers — mTLS, device login — trust. A SAML signing certificate those verifiers accepted would make the IdP key a client credential, and an application-layer use of one key a cross-protocol one.",
       "mitigation": "D-21's `SamlSigning` profile: keyUsage `digitalSignature` only (no `keyEncipherment`, even on RSA), extendedKeyUsage `id-kp-documentSigning` (RFC 9336) only, no SANs, so no TLS verifier accepts it for server or client authentication. The type is internal (`serde`-skipped and absent from the OpenAPI enum) and is refused by certificate generation, CSR signing, the bind endpoint, device login and mTLS; the leaf is never a `certificate` row. Tests (T23.2.1): `saml_idp_credential_test.rs::the_generic_issuance_paths_and_the_certificate_store_refuse_saml_signing`, `mtls_test.rs::a_saml_signing_certificate_cannot_log_in_as_a_device`, `device_auth_test.rs::a_saml_signing_certificate_cannot_be_bound`."
      },
      {
       "number": 311,
       "title": "The signer emits a wrapped, mis-referenced or markup-injected document under the tenant's signature",
       "type": "Tampering",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "Signature-wrapping attacks need a signed element and a second, unsigned one an SP reads instead. An issuer that signed the wrong element, emitted two assertions, reused an `ID`, referenced something other than the element its signature sits in, or let a user-controlled value — a display name, a group name, an attribute name, an `AuthnRequest` id — close an element and open another, would hand an attacker a document signed by the tenant whose meaning the attacker chose.",
       "mitigation": "The assertion is written as text through one escaping function for element text and attribute values alike (`&`, `<`, `>` and quotes as entities; tab, line feed and carriage return as character references; a character XML 1.0 cannot carry becomes U+FFFD). `InResponseTo` is echoed only when it is an ASCII `NCName` of at most 256 bytes. `ID`s are `_` followed by 160 CSPRNG bits. Signing is enveloped XML-DSig, `rsa-sha256` over `sha256` with exclusive canonicalization, the reference naming the signed element's `ID` and the certificate in `KeyInfo`; the assertion is signed on its own, embedded, and the response signed after it when the SP's `sign_responses` is set, so that signature covers the signed assertion. Before anything is returned the issuer re-parses its output and requires exactly one `Assertion`, the root's child; exactly the intended `ds:Signature`s, each referencing its parent's `ID`; two distinct `ID`s; and every signature verifying against the credential's certificate with the xmlsec verifier the SP side uses. Anything else is `SigningFailed`. Tests: `the_output_has_one_assertion_unique_ids_and_matching_references`, `values_are_escaped_and_round_trip_as_text_not_markup`, `a_single_changed_byte_in_any_signed_element_fails_verification`, `with_response_signing_on_both_signatures_verify_and_the_response_signature_covers_the_signed_assertion`, `xsw1_and_xsw2_wrapped_copies_of_a_signed_response_are_refused_by_the_sp`, `assertion_level_wrapping_of_the_builder_output_is_refused_by_the_sp`, `a_pkcs1_key_signs_too_and_a_key_that_does_not_match_the_certificate_is_refused` (a signature the certificate does not verify never leaves)."
      },
      {
       "number": 312,
       "title": "Service providers link a user across SPs, or back to the AXIAM account",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A `NameID` that is the same at every SP, or derivable from the user id, lets SPs that compare notes — or an attacker who breaches two of them — follow a person across services the person kept apart, and hands every SP an AXIAM internal identifier.",
       "mitigation": "Decision D-22: the default persistent `NameID` is HMAC-SHA256 under the dedicated deployment key `saml_pairwise_key` over a versioned label, the tenant id, the user id and the length-prefixed SP entity id, hex-encoded: different per SP and per tenant, not reversible without the key, and independent of the signing credential so a rotation changes nothing. Tests: `the_pairwise_name_id_differs_across_sps_tenants_users_and_keys`, `the_pairwise_name_id_is_stable_across_calls_and_across_a_credential_rotation`, `the_pairwise_name_id_contains_neither_the_user_id_nor_the_tenant_id`. An `emailAddress` `NameID`, and email, username, group and role attributes, are linkable by design and are released only to an SP an administrator configured them for. **Built (T23.2.4, 2026-10-04).** D-37: a per-SP random `SessionIndex` (32 CSPRNG bytes, base64url) recorded in `saml_sp_session` before signing and mapped back by the SLO endpoint by (tenant, SP, index) and then `NameID`, so SLO and the revocation feed still revoke the same session; the session id no longer reaches the XML. Tests (T23.2.4): `saml_idp_sso_test.rs::the_assertion_carries_a_per_sp_index_that_is_not_the_session_id` (one session, two SPs: two indexes, neither the session id, the session id nowhere in either assertion; a second sign-on to one SP reuses its index), `saml_idp::tests::the_authn_statement_carries_the_per_sp_index_instant_and_class` and, in `axiam-db`, `saml_slo_test.rs::an_index_resolves_for_its_own_sp_and_tenant_only`. Residual: `AuthnInstant` is the session's authentication time at every SP, which colluding SPs can compare (T-314 forbids misstating it)."
      },
      {
       "number": 313,
       "title": "An email NameID vouches for an address AXIAM never verified",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "An SP that keys accounts on email trusts the IdP to say who owns the address. In a tenant that allows self-registration, someone can create an account under a victim's address and, within the email-verification grace period (or as one of the accounts that stay pending for life, T-160), sign on to such an SP and land in the victim's existing account there.",
       "mitigation": "Decided in T23.2.3 (D-25): an email `NameID` is issued only for an address something vouches for — `email_verified_at` is set, or the account is `Active`, which only the verification flow, an administrator, SCIM or the directory path make it, each of which proved or wrote the address. A `PendingVerification` account with an unverified address — a self-registration inside its grace period, or an account provisioned pending and never activated — is answered `InvalidNameIDPolicy` (`NameIdUnverified`) at an email-keyed SP, never with a weaker identifier, and the `email` attribute is omitted for it, since an SP may key accounts on that just as well. Such an account still signs on wherever the `NameID` is the pairwise default. An account with no address is refused (`NameIdUnavailable`). Tests: `t_313_an_unverified_pending_address_is_never_asserted`, `an_email_name_id_is_the_address_and_a_missing_address_is_a_refusal`."
      },
      {
       "number": 314,
       "title": "The authentication context overstates how the user authenticated",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "SPs that require a second factor read `AuthnContextClassRef`. Copied from the SP's `RequestedAuthnContext`, or from an upstream IdP's claim, it says multi-factor for a password login, and the SP releases what it meant to protect.",
       "mitigation": "`authn_context_class_ref` takes the session's `amr` and nothing else; there is no request parameter to echo, the rule `acr_for` follows for OIDC (W4). Multi-factor evidence (`mfa`, or `hwk`/`swk` with `user`) is the REFEDS MFA profile; `x509` is `X509`; `pwd` is `PasswordProtectedTransport`; a federated login (`fed`), a presence-only key and no evidence are `unspecified`. Tests: `the_authn_context_mapping_table_is_pinned`, `the_authn_statement_carries_the_session_id_instant_and_class`."
      },
      {
       "number": 315,
       "title": "An SP registered for encrypted assertions receives them in plaintext",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "An administrator who set `encrypt_assertions` expects the attributes to be readable by the SP alone — not by a TLS-terminating proxy in front of it, nor from browser history. A silent downgrade would release them in the clear while the console says otherwise.",
       "mitigation": "Assertion encryption (D-2) is not implemented: `samael` has no encryption API and nothing in the tree could verify an AES-256-GCM `EncryptedAssertion`. The issuer refuses such an SP outright (`EncryptionUnsupported`, answered `Responder`) and never emits the plaintext. Residual: the registry still accepts the flag, so the refusal surfaces at sign-on rather than at save; the write path (T23.2.5/T23.2.6) should refuse it until encryption ships. Test: `request_shaped_refusals`."
      },
      {
       "number": 316,
       "title": "A document signed by the tenant's key is harvested as a signature-wrapping gadget",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "Some SP verifiers check only the first signature in a document, or treat a signature as covering an assertion because a reference names it. Against them, any document the tenant's key signed that carries no assertion — an error response echoing a request id an attacker chose, for instance — can be placed ahead of a forged assertion and vouch for it. Anyone who can send an `AuthnRequest` could collect one.",
       "mitigation": "The tenant's key signs one shape of document only: a response carrying exactly one assertion (T-311). Failure responses (`Requester`, `Responder`, `NoPassive`, `AuthnFailed`, `RequestDenied`, `InvalidNameIDPolicy`) carry no assertion and are never signed, which SAML Profiles §4.1.3.5 permits, and they have no status message or detail. Tests: `failure_responses_are_status_only_unsigned_and_echo_what_can_be_echoed`, `axiam_own_sp_refuses_a_failure_response`. Constraint for T23.2.4: a signed `LogoutRequest` or `LogoutResponse` is exactly such a document, so SLO signing needs its own decision rather than reusing this key by default. Decided for SLO (T23.2.8, 2026-10-04, D-38): AXIAM signs a logout message only for a session holder or in reply to a verified SP request, detached over the query on HTTP-Redirect so no XML signature exists to harvest; recorded as T-373."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "2a2a1983-07c2-5847-a3d0-7de61be737f2",
     "kind": "store",
     "x": 1079,
     "y": 719,
     "w": 170,
     "h": 80,
     "name": "saml_idp_credential (sealed signing key)",
     "lines": [
      "saml_idp_credential",
      "(sealed signing key)"
     ],
     "description": "One active and at most one next credential per tenant (schema v72, D-21): the RSA-4096 SamlSigning leaf and its private key sealed AES-256-GCM under pki_encryption_key by the database custodian.",
     "outOfScope": false,
     "threats": [
      {
       "number": 304,
       "title": "The tenant's SAML signing key is disclosed from the database or a backup",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "Whoever holds a tenant's SAML signing key can sign an assertion for any user of the tenant, to every service provider that trusts the tenant's metadata: account takeover at every SP, with no AXIAM sign-in at all. The key lives in the tenant's `saml_idp_credential` row.",
       "mitigation": "Decision D-21: the key is sealed with AES-256-GCM under `pki_encryption_key` through `DatabaseCaKeyStore` — the database custodian, chosen explicitly whatever the deployment's CA custody — with the custody recorded on the row. A database dump or backup alone yields ciphertext; it takes the dump and the provider-held `pki_encryption_key` together. Only `SamlIdpCredentialRepository::get_active_sealed` selects the ciphertext (every list and get returns `SamlIdpCredential`, a type with no key field); the leaf is never a `certificate` row, so no certificate API can return it; `retire` clears the sealed key in the same write that takes the row out of its slot; and both SAML tables go with their tenant in the tenant-delete transaction. Tests: `saml_idp_credential_test.rs::an_issued_credential_has_the_saml_profile_chains_to_its_ca_and_seals_its_key` (T23.2.1). Residual: no audit record is written when the key is unsealed — it is unsealed on every sign-on, so a record per read would be one per assertion — and a compromised application process can unseal it exactly as the signer does."
      },
      {
       "number": 309,
       "title": "Sign-on stops when the active credential expires or is retired before a successor is in place",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Because the signer refuses an expired credential (T-308), a tenant whose credential reaches `not_after` stops issuing assertions to every SP, and so does one whose administrator retires the active credential. SPs pin the certificate, so a successor must be published in metadata before it signs, or every SP rejects its first assertion.",
       "mitigation": "**Built (T23.2.5, 2026-10-04).** Contract §29 and D-42: an `issue_idp_credential` into the `next` slot and a `promote_idp_credential` that, in one transaction, retires the old `active` and activates `next`, refused unless the id is the current `next` and inside its validity window; D-40 makes the metadata endpoint publish `active` and then `next`, so an SP has the successor before it signs, with `Cache-Control: max-age=3600`; §29 `get_idp` and `list_idp_credentials` show `not_after` so an administrator sees expiry coming. Tests (T23.2.5): `saml_admin_test.rs::promote_swaps_the_slots_in_one_transaction_and_destroys_the_old_key`, `::a_promotion_that_cannot_happen_is_a_409_or_404_and_changes_nothing`, `::a_promotion_repeated_with_a_stale_page_is_a_409`, `::metadata::the_document_parses_back_with_samael_active_before_next_and_never_a_retired_key` and `::metadata::a_promotion_changes_what_is_published`; in `axiam-db`, `saml_idp_credential_test.rs::of_concurrent_promotions_exactly_one_wins`. Residual: a tenant that never rotates stops at `not_after`, and retiring the active credential without a successor stops sign-on at once — deliberate, as the incident response to T-306. The failure is closed: the signer never falls back to another credential, a weaker one, or an unsigned assertion."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "7443c8b5-68b4-5ac9-bd3d-f39cdb1d21be",
     "kind": "process",
     "x": 624,
     "y": 794,
     "w": 140,
     "h": 140,
     "name": "SAML SSO endpoint (/saml/v2/{tenant}/sso)",
     "lines": [
      "SAML SSO",
      "endpoint",
      "(/saml/v2/{tenant}/sso)"
     ],
     "description": "axiam-api-rest `handlers::saml_idp` (T23.2.3, behind `saml`): GET/POST `/saml/v2/{tenant}/sso` (HTTP-Redirect and HTTP-POST bindings), `/sso/idp-initiated` and `/sso/continue`. The first leg decodes, parses and checks the AuthnRequest (DTDs refused, signature, Destination, ACS allow-list, binding, RelayState, request-id replay) and holds it under an opaque handle bound to the browser; the second resolves the OP session through the tenant-keyed lookup, runs the login hop, and consumes the handle before calling the issuer. Answers 404 when the tenant's saml_idp_enabled is off (D-20).",
     "outOfScope": false,
     "threats": [
      {
       "number": 317,
       "title": "An AuthnRequest that does not come from the registered SP obtains an assertion for it",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "Anyone can send an `AuthnRequest` naming any SP's entity id as its `Issuer`. If the SSO endpoint believed the request's own claims — its ACS URL, its binding, its requested identifier — a forged request could decide where and in what form an assertion for that SP is delivered.",
       "mitigation": "The SP is found by `Issuer` within the tenant of the request path only, and nothing the request names is used until it has passed every check that needs no principal (D-24): for an SP that registered a signing certificate, any signature present must verify — on HTTP-Redirect over the exact query octets received (SAML Bindings §3.4.4.1), on HTTP-POST as the single enveloped signature of the root (D-23's placement rule on the receiving side), SHA-1 refused — and an SP with `want_authn_requests_signed` gets nothing unsigned. A signed request must carry `Destination`, which must be the tenant's own SSO URL. Even an unsigned request can only steer delivery to an ACS URL the SP registered (T-318), so a forged one at most signs the user in to that SP as themselves (T-322). Tests: `a_signing_sp_s_missing_bad_or_wrong_key_signature_is_refused_on_both_bindings`, `an_acs_outside_the_registry_or_a_destination_mismatch_is_refused_before_the_hop`, `saml_idp::request::tests` (placement gadgets, exact-octet verification, SHA-1)."
      },
      {
       "number": 318,
       "title": "ACS redirection: the signed assertion is posted to a URL the SP never registered",
       "type": "Tampering",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "An `AuthnRequest` names the URL the response is posted to. Honouring an attacker's URL turns the IdP into a machine that hands a victim's signed assertion to the attacker, who presents it to the real SP as the victim.",
       "mitigation": "The ACS URL is resolved against the SP's registration only: an `AssertionConsumerServiceURL` must equal a registered endpoint byte for byte, an index must name one, neither means the SP's default, both is malformed, and the endpoint must use HTTP-POST. Checked before the login hop, again by `SamlIdpIssuer::failure` and `issue`, and an unregistered URL is answered with an error page that posts nowhere — not even a failure response. The response's `Destination` and `Recipient` are the URL used; the auto-post page's `Content-Security-Policy` allows `form-action` to that URL's origin and nothing else. Tests: `an_acs_outside_the_registry_or_a_destination_mismatch_is_refused_before_the_hop` (unregistered, near-miss, unknown index, URL and index together), `redirect_binding_end_to_end_through_the_login_hop` (the CSP)."
      },
      {
       "number": 319,
       "title": "A replayed AuthnRequest or pending handle yields a second assertion",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "A captured `AuthnRequest`, or the handle of one held across the login hop, presented again — from the same browser or another — obtains a second response answering the same request, which an SP that tracks outstanding requests poorly will accept.",
       "mitigation": "The request `ID` is single-use per SP: the pending row is created under a unique index on `(tenant_id, sp_id:request_id)` and is kept, consumed, until it expires ten minutes later — longer than the `IssueInstant` window (five minutes back, the 60 s skew forward), so a replay from outside the window fails on freshness and one inside it on the index (schema v73). The handle is consumed on the X6 two-layer arbiter immediately before issuing, so of any number of concurrent continues one issues. Assertions live five minutes and carry `InResponseTo` (T23.2.2). Tests: `a_replayed_request_id_is_refused_before_the_hop` (both bindings), `a_handle_is_single_use_and_bound_to_the_browser_that_started_it`, `saml_authn_request_test::concurrent_consumes_yield_exactly_one_winner` (100 rounds of 8 racers on surrealkv), `a_request_id_is_single_use_per_service_provider_even_after_consumption`."
      },
      {
       "number": 320,
       "title": "XML external entities or entity expansion in an AuthnRequest",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "An `AuthnRequest` is attacker-supplied XML parsed before anything is known about its sender. A DTD can declare an external entity (a local file or an internal URL, read into a field AXIAM echoes or fetched on parse) or a nest of entities that expands to gigabytes (billion laughs).",
       "mitigation": "Any markup declaration — `<!DOCTYPE`, `<!ENTITY`, `<!ELEMENT`, `<!ATTLIST`, `<!NOTATION` — is refused on the document's bytes before libxml sees it, so there is no entity to resolve or expand; a NUL byte (how UTF-16 would hide a `<!DOCTYPE` from that scan) and a declared encoding other than UTF-8 are refused too. libxml then runs without recovery and without network access, and the document is capped at 64 KiB. All of it happens before the SP lookup. Tests: `xxe_billion_laughs_and_a_decompression_bomb_are_refused_before_any_lookup` (both bindings), `saml_idp::request::tests::an_external_entity_request_is_refused_before_parsing`, `a_billion_laughs_request_is_refused_before_parsing`, `a_document_in_another_encoding_is_refused`."
      },
      {
       "number": 321,
       "title": "A decompression bomb, an oversized body or a request flood exhausts the SSO endpoint",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The HTTP-Redirect binding carries raw DEFLATE, which compresses a few kilobytes into gigabytes; the HTTP-POST binding is a body of the sender's choosing; and every accepted request writes a row and costs XML parsing and possibly an RSA verification.",
       "mitigation": "Inflation stops one byte past 64 KiB, so a bomb costs at most that; the encoded value and the POST body (192 KiB, read only after the tenant check) are capped. The three SSO routes carry a per-route governor and shared buckets of their own (`saml_idp_sso`, `saml_idp_sso_continue`, `saml_idp_sso_idp_initiated`) at the browser-endpoint preset `end_session_per_min` (§7 rule 6). Pending rows expire in ten minutes and are swept. RSA-4096 signing runs off the async workers under the shared CPU gate. Tests: `the_sso_routes_are_rate_limited`, `xxe_billion_laughs_and_a_decompression_bomb_are_refused_before_any_lookup`, `saml_idp::request::tests::a_decompression_bomb_is_refused_at_the_inflated_bound`."
      },
      {
       "number": 322,
       "title": "Login CSRF or session swapping across the pending handle",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The browser leaves the SSO endpoint with an opaque handle in a URL and comes back with it after signing in. A handle that leaks (a referrer, a log, a shared link) or is planted in a victim's browser could pair one person's request with another person's session — the assertion going to the SP in the wrong browser, for the wrong user.",
       "mitigation": "The handle is bound to the browser that started the request: the first leg sets an `HttpOnly; Secure; SameSite=Lax` cookie scoped to the tenant's SSO path, named per handle so concurrent sign-ons do not collide, and the continue leg requires the SHA-256 of its value to match the row (constant-time) before it reads a session or consumes anything. The assertion is always for the session whose OP cookie arrives, resolved through the tenant-keyed digest lookup, and is posted to the SP's registered ACS in that same browser, so neither party to a swap can receive the other's assertion. The redirects carry `Referrer-Policy: no-referrer` and `no-store`. Residual: anyone can make a victim's browser start an `AuthnRequest` of their own making and so sign the victim in to a registered SP as the victim — inherent to SAML Web Browser SSO and bounded by the SP's own `InResponseTo` tracking. Tests: `a_handle_is_single_use_and_bound_to_the_browser_that_started_it` (another browser, signed in, refused; the same browser without its binding cookie refused, nothing burned)."
      },
      {
       "number": 323,
       "title": "ForceAuthn is skipped by forging the login-hop marker",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "`ForceAuthn` asks the IdP to authenticate the user afresh. If the continue leg decided \"fresh\" from the login hop's return marker — as `/oauth2/authorize` does for `prompt=login` (P23W1-08) — anyone at an unlocked browser could append the marker and receive an assertion from the existing session.",
       "mitigation": "Bound to the request rather than to the marker: the pending row records the instant the first leg accepted the request, and the continue leg treats a session as satisfying `ForceAuthn` only if its `authenticated_at` is strictly later. A session that is not is sent to sign in with `reauth=1`; on a return leg it is answered `AuthnFailed` with no assertion. The marker decides only whether to hop again or answer. `IsPassive` never shows the sign-in page (`NoPassive` without a session). Tests: `force_authn_requires_a_sign_in_after_the_request_and_a_forged_marker_skips_nothing`, `is_passive_never_shows_the_sign_in_page`."
      },
      {
       "number": 324,
       "title": "Unsolicited (IdP-initiated) responses are triggered for an SP or from a page that did not ask",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "An IdP-initiated response answers no request, so the SP cannot bind it to anything it started; and a trigger any web page can link to lets a third party sign a visitor in to an SP with a `RelayState` of its choosing.",
       "mitigation": "Per-SP opt-in, off by default (D-3): `GET /saml/v2/{tenant}/sso/idp-initiated?sp=…` refuses an SP that has not set `allow_idp_initiated` — and a disabled SP, an SP asking for encryption, an unusable default ACS or an over-long `RelayState` — with an error page before the login hop (D-26). A request carrying `Sec-Fetch-Site: cross-site` is refused: the trigger is for AXIAM's own pages and bookmarks. The response carries no `InResponseTo` and goes to the SP's default registered ACS. Residual: a browser that sends no `Sec-Fetch-Site` header is not refused. Test: `idp_initiated_is_served_for_an_sp_that_opted_in_and_refused_otherwise`."
      },
      {
       "number": 326,
       "title": "The SSO routes reveal whether a tenant exists or serves SAML",
       "type": "Information disclosure",
       "severity": "Low",
       "status": "Mitigated",
       "description": "D-20 makes the SAML IdP a per-tenant setting. An endpoint that answered a disabled tenant differently from a nonexistent one, or from a build without SAML, would enumerate tenants and their configuration.",
       "mitigation": "Every route answers the empty `404` an unmounted path answers when the tenant does not exist, its path segment is not the canonical UUID spelling, or its effective `saml_idp_enabled` is off — decided before the body is read — and every other method and sub-path under the scope answers the same, so no `405` distinguishes a build with SAML from one without (D-20, D-27). Residual: the routes are rate-limited in a build with SAML and not in one without, so a flood tells the two builds apart (not tenants). Test: `every_sso_route_answers_an_indistinguishable_404_when_saml_is_off` (status and every header compared with an unmounted path, four tenant spellings, seven method/path pairs)."
      },
      {
       "number": 327,
       "title": "An issued assertion cannot be traced to the user, the SP and the sign-on",
       "type": "Repudiation",
       "severity": "Low",
       "status": "Mitigated",
       "description": "Without a record, a tenant administrator cannot answer which user signed in to which SP when, or see that an SP is being refused.",
       "mitigation": "Every assertion issued and every SAML failure response sent writes an audit row: `saml_idp.sso.issued` with the user, the SP's record id and the response id, or `saml_idp.sso.refused` with the SAML status. Refusals answered with an error page (a request that never proved it came from an SP) are logged with a fixed reason, not audited per tenant. The rows carry no `NameID`, `RelayState` or response. The `SessionIndex` in the assertion is the AXIAM session id (T23.2.2), tying it to the session record."
      },
      {
       "number": 328,
       "title": "A suspended account's OP session still obtains SAML assertions",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "An account-status change revokes no session. A locked, deactivated or deleted user whose browser still holds the OP cookie would keep signing in to every SAML SP for the session's lifetime — the defect T23.1.3 found at `/oauth2/authorize`.",
       "mitigation": "The continue leg re-reads the account behind the resolved session and applies `account_may_act` through `AuthService::check_session_holder` — `Locked`, `Inactive`, `Anonymized` and `Deleted` refused, `PendingVerification` served (T-160, P23W1-03) — and treats a refused account as no session (`reauth`, then `AuthnFailed`); `SamlIdpIssuer::issue` applies the rule again. `allowed_groups` is read from the user's current groups. Tests: `a_suspended_account_is_not_served_and_a_pending_one_is`, `allowed_groups_decide_who_may_use_the_sp`."
      },
      {
       "number": 329,
       "title": "Script injection through the auto-post page",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "The HTTP-POST binding page echoes the SP's `RelayState` verbatim and the ACS URL into a form; it is the one HTML page the API serves with values from a request in it.",
       "mitigation": "Every value is HTML-escaped (`&`, `<`, `>`, `\"`, `'`). The page carries its own `Content-Security-Policy` — `default-src 'none'`, the one inline `submit()` under a per-response nonce, `form-action` the ACS origin only, `frame-ancestors 'none'`, `base-uri 'none'` — stricter than the global policy in every directive; the security-headers middleware writes the global policy only when a handler set none (D-27). `Cache-Control: no-store`. Tests: `post_binding_signed_end_to_end_verified_by_axiam_own_sp` (a `RelayState` of `relay&<x>` arrives escaped and round-trips), `security_headers::tests::the_global_policy_is_written_unless_the_handler_set_its_own`."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "00b1c269-bd14-572b-a277-4946eed1f557",
     "kind": "store",
     "x": 1079,
     "y": 834,
     "w": 170,
     "h": 80,
     "name": "saml_authn_request (pending requests)",
     "lines": [
      "saml_authn_request",
      "(pending requests)"
     ],
     "description": "Schema v73: AuthnRequests between the SSO endpoint's two legs — SP, resolved ACS URL, RelayState, ForceAuthn/IsPassive and the outbound instant — under SHA-256 digests of the handle and of the browser-binding value. Ten-minute rows, kept after consumption as the request-id replay guard; unique (tenant_id, replay_key) and handle_hash.",
     "outOfScope": false,
     "threats": [
      {
       "number": 330,
       "title": "A database read yields a usable sign-on handle",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Pending rows name a user's SP, ACS URL and `RelayState` for ten minutes. If they stored the handle or the binding value, anyone who could read the table could complete another person's sign-on.",
       "mitigation": "Only SHA-256 digests of the handle and of the binding value are stored, as `sso_handoff_code` stores its codes; a digest cannot be presented. Rows are tenant-scoped on every query, removed with their tenant in the tenant-delete transaction, and swept when expired (`saml_authn_request` on `/health/jobs`). Tests: `saml_authn_request_test` (cross-tenant read and consume refused, expiry and sweep, the tenant cascade); `v73_defines_the_pending_authn_request_table_additively` (no raw column)."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "53ad9895-e646-51e4-88b4-fc1e675e7cbc",
     "kind": "process",
     "x": 374,
     "y": 794,
     "w": 140,
     "h": 140,
     "name": "Directory sync job (full / incremental, safety valve)",
     "lines": [
      "Directory",
      "sync job",
      "(full /",
      "incremental,",
      "safety",
      "valve)"
     ],
     "description": "axiam-directory's sync job (T23.3.5, D-31), last in each cleanup tick: incremental runs by modifyTimestamp / uSNChanged, a full reconciliation every 24 h, Inactive as the soft-delete, the safety valve. Reads the directory through the same pool, address guard and frame guard as sign-in; never creates, links, re-enables or deletes an account.",
     "outOfScope": false,
     "threats": [
      {
       "number": 344,
       "title": "A directory that empties or disables at once deactivates the whole tenant",
       "type": "Denial of service",
       "severity": "High",
       "status": "Mitigated",
       "description": "The sync job sets `Inactive` every account whose entry vanished or was disabled. A wrong `base_dn`, an outage that answers empty, a bind account stripped of rights, or a hostile directory administrator could make every entry look gone in one run.",
       "mitigation": "D-31: a full run reads every answer before it writes anything, and the safety valve refuses to apply a run that would deactivate more than 10 % of the tenant's directory accounts and at least 5 of them — nothing is applied, `directory.sync_safety_valve` is audited once, and the job shows as failed in `GET /health/jobs` until the directory is fixed or the accounts really gone are deactivated by hand. A deactivated account keeps its row, marker and audit trail, and an administrator can re-enable it. Tests: `the_valve_trips_and_applies_nothing`, `the_valve_does_not_trip_under_its_floor`, `the_valve_does_not_trip_at_or_under_its_percentage`, `an_empty_directory_does_not_disable_the_tenant`, `a_failure_part_way_through_the_reads_applies_nothing`. Residual (D-31): incremental runs have no valve, so a directory that disables many accounts through changes the incremental search sees deactivates them run by run — the directory is the authority for those accounts' standing, and every deactivation is audited and reversible. The valve has no override in this cut; contract §30 says why."
      },
      {
       "number": 345,
       "title": "An incomplete or access-filtered answer is read as an entry having vanished",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "Absence is an inference. A search that hit a size or time limit, was referred elsewhere, failed part-way or matched two entries — or was answered by a bind account that can no longer read part of the tree — looks, to a careless reader, like \"not there\".",
       "mitigation": "Only a completed full run concludes \"vanished\", and only from an exactly-one lookup by the account's immutable identifier under `base_dn` that the directory answered with success and no entry; an error, a referral, a bound, an ambiguous answer or an identifier that cannot be asked for skips that account and owes a full run, and an incremental run never concludes it at all. Tests: `an_incremental_run_never_concludes_that_an_entry_vanished`, `a_service_account_without_read_rights_is_a_failure_not_a_vanishing`, `an_ambiguous_identifier_skips_the_account_and_is_not_a_vanishing`, `an_identifier_that_cannot_be_asked_for_is_skipped_not_vanished`, `an_unreachable_directory_changes_nothing_and_is_a_reported_failure`. Residual: an access-control change that hides entries from the bind account answers \"no such entry\" exactly as a deletion does; the valve catches it at scale (T-344), and below the valve those accounts are deactivated, audited, and re-enabled by an administrator."
      },
      {
       "number": 346,
       "title": "The sync job creates, links or re-enables accounts on the directory's say",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "A job that acted on whatever the directory reports could revive an account an administrator disabled, create accounts nobody signed in with, or link a local account by name (T-334).",
       "mitigation": "No such code path exists (D-31). The job reads only accounts already carrying `directory_external_id`, writes `Inactive` by compare-and-set from a live status and nothing else, never writes `Deleted` and never removes a row. An account the directory re-enables, or whose entry reappears, stays `Inactive`, and one `directory.account_reappeared` row says an administrator must act (deduplicated in the state row). Tests: `a_reappearing_entry_leaves_the_account_inactive_and_says_so_once`, `an_account_an_administrator_made_inactive_is_reported_never_reactivated`, `a_local_account_is_never_touched`, `no_row_is_removed_and_no_account_is_deleted`, `deactivating_sets_inactive_and_only_inactive`."
      },
      {
       "number": 347,
       "title": "A stored identifier or watermark carries filter syntax into the sync job's searches",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "The sync job builds filters from values AXIAM stored — an account's directory identifier, the watermark — that first came from the directory. Formatted raw, a crafted `entryUUID` or watermark would widen a lookup into a match on many entries.",
       "mitigation": "Values enter a filter only through the escape module: an `entryUUID` through RFC 4515 escaping, an `objectGUID` as its little-endian octets through the binary escaper (every byte `\\xx`), and a watermark only when it parses as a generalized time or a decimal USN — `changed_since_filter` refuses anything else and the run falls back to full; attribute names are fixed by the directory kind. Tests: `an_object_guid_lookup_reaches_the_server_as_little_endian_octets` (asserted on the filter the server parsed), `an_identifier_that_cannot_be_asked_for_is_skipped_not_vanished`, and the escape module's unit tests."
      },
      {
       "number": 348,
       "title": "A stale or foreign watermark makes incremental runs miss changes",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Active Directory's `uSNChanged` counts per domain controller, so a watermark taken from one server means nothing on another, and a load-balanced URL can reach a different one each time. A missed change is a disable that never arrives.",
       "mitigation": "On Active Directory the watermark is `highestCommittedUSN` read from the rootDSE of the same connection and stored with its `dsServiceName`; a different server, a missing watermark or an unreadable rootDSE falls back to a full run. A full run happens every 24 hours regardless, and after any skipped account, bound hit or untrusted watermark. Tests: `the_active_directory_watermark_is_the_root_dse_usn_of_the_same_server`, `a_different_directory_server_falls_back_to_a_full_run`, `a_root_dse_without_a_usn_falls_back_to_a_full_run_and_keeps_doing_so`, `an_unreadable_root_dse_falls_back_to_a_full_run`, `an_incremental_run_over_the_bound_applies_the_prefix_and_owes_a_full_run`."
      },
      {
       "number": 349,
       "title": "The sync job exhausts the connector or the database, and every replica runs it",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A background job that walks every directory account of every tenant can crowd out sign-ins for the shared connector, and a deployment of several replicas runs every sweep once per replica.",
       "mitigation": "The job runs last in each cleanup tick, one tenant at a time, only for tenants with an enabled directory that are due, on the same bounded pool, deadlines, address guard and frame cap as sign-in, with incremental searches bounded; an error ends that tenant's run and the others still run. Tests: `a_tenant_without_a_directory_or_with_it_disabled_is_skipped_without_a_connection`, `a_tenant_that_is_not_yet_due_is_left_alone`, `an_incremental_run_over_the_bound_applies_the_prefix_and_owes_a_full_run`. Residual: no sweep in the tree has a multi-replica guard, so every replica runs the job; its writes are idempotent or compare-and-set, but directory reads and attribute-refresh audit rows multiply by the replica count."
      },
      {
       "number": 350,
       "title": "A deactivation stopped part-way leaves the account able to act",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Deactivating is several writes: sessions, refresh tokens, memberships, the status. Done in the wrong order, a crash between them leaves an account marked `Inactive` that still holds a live session, or memberships that still grant roles.",
       "mitigation": "Deactivation revokes sessions and refresh tokens first, through the repositories (so the validation cache and the revocation feed see it), then removes the directory's memberships with the decision-cache flush, then sets `Inactive`; `account_may_act` refuses `Inactive` on every path, passkeys and the OP cookie included. Stopped part-way, the account holds less than before, and the next run repeats what remains. Tests: `a_vanished_entry_deactivates_the_account_and_takes_back_what_the_directory_gave`, `a_second_run_changes_and_audits_nothing_more`."
      },
      {
       "number": 351,
       "title": "The sync job overwrites a decision an administrator made during the run",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A run reads first and writes later. An administrator who suspends, deactivates or erases an account in between could have that decision overwritten by a write based on the earlier read.",
       "mitigation": "The status write is a compare-and-set from a live status to `Inactive`: an account an administrator changed in the meantime to a status that is not live is left as the administrator left it, an erased account is never touched, and nothing the job does re-enables. Tests: `deactivating_does_not_overwrite_a_deleted_account`, `pending_and_locked_accounts_are_deactivated_when_their_entry_vanishes`, `an_account_an_administrator_made_inactive_is_reported_never_reactivated`."
      },
      {
       "number": 352,
       "title": "A directory rename takes over another account's username or email",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "The job keeps a directory account's username and email in step with its entry. A directory administrator who renames an entry to a colleague's name or address would, applied blindly, collide with — or capture the reset mail of — another account.",
       "mitigation": "Changes pass the same cleaners as provisioning (T-335) and the same lowercased collision probe over both columns of every other account of the tenant, tombstones included; a colliding change is skipped and audited (`directory.sync_attribute_skipped`) while the rest is applied, and a case-only change to the account's own name is allowed. Tests: `a_colliding_change_is_skipped_and_audited_and_the_rest_is_applied`, `a_case_only_change_to_ones_own_name_is_applied`, `the_collision_probe_can_leave_one_account_out`. Residual: a name no account holds is free, so the directory can rename an account to any unused name — as it could have named the entry in the first place."
      },
      {
       "number": 353,
       "title": "An outsider's failed binds become a permanent deactivation through the sync job",
       "type": "Denial of service",
       "severity": "High",
       "status": "Mitigated",
       "description": "OpenLDAP's `ppolicy` writes `pwdAccountLockedTime` when failed binds pass its threshold — something anyone guessing at the directory can provoke. Read as \"disabled\", that turns a temporary lockout into a permanent `Inactive`, because sync never re-enables (T-346): a denial of service on any account an outsider can name.",
       "mitigation": "D-31 as amended after T23.3.5: on OpenLDAP only ppolicy's permanent-lock value `000001010000Z` is a disable, and any other value is a temporary lockout that leaves the account alone; on Active Directory only `userAccountControl` bit `0x2` is a disable, and `lockoutTime` is not read. An unreadable value never deactivates. Tests: `a_temporary_lockout_leaves_the_account_active_in_a_full_run`, `a_temporary_lockout_leaves_the_account_active_in_an_incremental_run`, `an_open_ldap_locked_time_deactivates_the_account_the_same_way`, `an_active_directory_account_with_the_disabled_bit_is_deactivated`, `an_unreadable_disabled_attribute_never_deactivates`."
      },
      {
       "number": 355,
       "title": "A deactivation cannot be traced to the run and the reason that caused it",
       "type": "Repudiation",
       "severity": "Low",
       "status": "Mitigated",
       "description": "An account that stops working because a background job decided so needs an answer to \"why, and when\" that does not depend on the directory still showing what it showed then.",
       "mitigation": "Every change the job makes is a row on the append-only audit log carrying identifiers and reasons, never names or values: `directory.account_deactivated` (`reason` vanished or disabled, `run` full or incremental), `directory.account_updated` (the fields, not their values), `directory.sync_attribute_skipped`, `directory.sync_user_skipped`, `directory.groups_mapped`, `directory.sync_safety_valve`, and one `directory.sync_run` row of counts per full run; job health records each run. Tests: `a_full_run_writes_one_summary_row_of_counts`, `a_vanished_entry_deactivates_the_account_and_takes_back_what_the_directory_gave`."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "2994dd70-ce2c-50ac-b49f-72d1f7dfd235",
     "kind": "store",
     "x": 1269,
     "y": 604,
     "w": 170,
     "h": 80,
     "name": "directory_sync_state (watermark, last run)",
     "lines": [
      "directory_sync_state",
      "(watermark, last run)"
     ],
     "description": "Schema v75, one row per tenant, deleted with the tenant: the watermark and the server it belongs to, the last full run and attempt, the last result, and the account ids already reported as reappeared. No personal data.",
     "outOfScope": false,
     "threats": [
      {
       "number": 354,
       "title": "The sync state row exposes personal data or another tenant's directory",
       "type": "Information disclosure",
       "severity": "Low",
       "status": "Mitigated",
       "description": "The job keeps state between runs. A row that held names, addresses or DNs of people, or that one tenant's reads could reach, would be a second copy of directory data with its own exposure.",
       "mitigation": "One row per tenant (schema v75) holding a watermark, the identity of the server it belongs to, timestamps, the last result and account ids — no name, address or person's DN; read and written by tenant id only, and deleted in the tenant's delete transaction. Tests: `tenants_cannot_read_each_others_state`, `a_tenants_state_goes_with_the_tenant`, `the_reported_list_is_trimmed_to_its_cap_keeping_the_newest`."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "6c7796cb-edff-5c81-aa70-06e97fe3ee19",
     "kind": "store",
     "x": 1269,
     "y": 719,
     "w": 170,
     "h": 80,
     "name": "user accounts & member_of (source)",
     "lines": [
      "user accounts &",
      "member_of (source)"
     ],
     "description": "The user rows the directory path writes — a just-in-time account created marked (D-29), the linking marker (D-18), the sync job's Inactive status and refreshed attributes — and member_of edges, where source = directory marks the memberships the group mapping owns (schema v74).",
     "outOfScope": false,
     "threats": [
      {
       "number": 341,
       "title": "A manual membership is removed by the directory, or a directory one is mistaken for manual",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Administrators add members by hand and the mapping adds them from the directory, on the same edges. A mapping that removed whatever it no longer saw would delete hand-made memberships; one that could not tell the two apart would sweep a manual edge, or let a directory edge outlive the directory's say.",
       "mitigation": "Every edge the mapping writes carries `member_of.source = directory` (schema v74; the datastore admits no other owner value, and an edge without the field reads as manual). The mapping removes only directory-sourced edges the directory no longer backs, never touches or duplicates a manual edge, and leaves a manual edge of the same pair as it is; removals run before additions, so a stop part-way leaves less access. Tests: `a_manual_membership_is_untouched_by_every_application`, `a_manual_membership_of_the_same_pair_is_left_alone_and_never_removed`, `removing_a_directory_membership_removes_only_that_edge`, `the_datastore_admits_no_owner_but_directory`, `apply_backed_groups_reports_what_it_did_and_leaves_manual_edges`. Residual: an administrator's `add_member` on a pair the directory already owns is a conflict, not a promotion to manual, so that membership leaves with the directory — the safe direction (`add_member_on_a_directory_edge_is_still_a_conflict`)."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "2c859601-e642-5294-8142-a9ed10a36135",
     "kind": "actor",
     "x": 49,
     "y": 1144,
     "w": 150,
     "h": 80,
     "name": "Tenant administrator (console / SDK, §29)",
     "lines": [
      "Tenant administrator",
      "(console / SDK, §29)"
     ],
     "description": "A human administrator of one tenant holding `saml_sp:read`, `saml_sp:write` or `saml_idp:credential`. Service-account tokens are refused on the `saml` namespace in this revision (D-42).",
     "outOfScope": false,
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "de15bf38-6ec2-5998-a6c9-a20a44ae1780",
     "kind": "process",
     "x": 374,
     "y": 1044,
     "w": 140,
     "h": 140,
     "name": "SAML registry management (/api/v1/tenants/{t}/saml)",
     "lines": [
      "SAML",
      "registry",
      "management",
      "(/api/v1/tenants/{t}/saml)"
     ],
     "description": "Contract §29 (T23.2.8, built by T23.2.5): the eleven `saml` management routes — the SP registry (CRUD, `update` a replacement), `parse_sp_metadata` (upload or URL through `guarded_fetch`, a draft only) and the IdP credential lifecycle (`issue`, `promote` in one transaction, `retire`) plus `get_idp`. Compiled in every build and independent of `saml_idp_enabled` (D-42); every SP write through `validate_saml_service_provider` and §29.3's refusals.",
     "outOfScope": false,
     "threats": [
      {
       "number": 357,
       "title": "A principal registers, edits or deletes service providers it should not, or another tenant's",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "The SP registry decides where a tenant's signed assertions may be delivered and which users each SP receives. A caller who could write it for a tenant it does not administer, or with a weaker permission than registration deserves, could register an SP of its own and receive assertions for the tenant's users, or delete a production SP.",
       "mitigation": "**Built (T23.2.5, 2026-10-04).** Contract §29.3 rule 9 and D-42: the routes live under `/api/v1/tenants/{tenant_id}/saml` and the path tenant must be the caller's (another tenant's id is `403`); reads need `saml_sp:read`, SP writes and `parse_sp_metadata` `saml_sp:write`, the credential writes `saml_idp:credential`; service-account tokens are refused on the whole namespace in this revision, so registering where assertions go stays a human administrator's act; every repository call is tenant-keyed. Tests (T23.2.5): `saml_admin_test.rs::another_tenants_id_is_403_on_all_eleven`, `::each_operation_needs_its_own_permission_and_no_other`, `::a_service_account_token_is_refused_on_all_eleven` (the extractor's `401`, as on every human-only route)."
      },
      {
       "number": 358,
       "title": "A registration admits a delivery target, certificate or option the IdP cannot hold to its rules",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "Every later SSO and SLO decision trusts the registry. A write path that skipped the validator, accepted an ACS or SLO URL that is a glob, plaintext or fragment-bearing, stored a certificate the SSO endpoint cannot use, or accepted `encrypt_assertions` while encryption is unimplemented would turn into ACS redirection (T-318), a signing SP whose requests can never verify, or an SP refused at every sign-on.",
       "mitigation": "**Built (T23.2.5, 2026-10-04).** Contract §29.3 rules 1–3 and D-42: every create and update runs `validate_saml_service_provider` (the redirect-URI rule shared with OAuth2 clients, no `*`, unique URLs and indexes, one default, exactly one `CERTIFICATE` block that parses, a private key refused by name) and then four refusals of its own — `encrypt_assertions: true` (D-2), an `sp_signing_cert_pem` the SSO endpoint's decoder (`pem_cert_to_der`) refuses or whose key is not RSA ≥ 2048 or ECDSA P-256/384/521, an `allowed_groups` entry outside the tenant, and a changed `entity_id` (the pairwise `NameID` is keyed on it, D-22). The SSO endpoint still re-checks the ACS on every use (`check_acs_url`). Tests (T23.2.5): `saml_admin_test.rs::every_validator_refusal_is_a_400_validation_error_naming_the_rule` (each validator rule, on create and on update), `::each_d42_refusal_is_a_400_on_create_and_on_update`, `::the_certificates_the_endpoint_can_use_are_accepted_expired_ones_included`; in `axiam-federation`, `saml_sp::write_refusal_tests` (RSA, ECDSA on P-256, P-384 and P-521, Ed25519, secp256k1 and garbage)."
      },
      {
       "number": 359,
       "title": "SP metadata import makes the server fetch an internal or metadata-service address",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "`parse_sp_metadata` accepts a URL chosen by an administrator, or by whoever holds an administrator's token. Fetched naively, it would reach cloud-metadata credentials, internal admin interfaces or AXIAM itself from the server's network position, and an error that echoed the response would read them back.",
       "mitigation": "**Built (T23.2.5, 2026-10-04).** D-41: `https` only, fetched only through `axiam_pki::ssrf::guarded_fetch` with `allow_private = false` — the name resolved once and the connection pinned to the vetted address, loopback, private, link-local and metadata addresses refused, every redirect hop re-validated, the transport cap and timeout — then the 512 KiB document cap; one fetch per call, no credentials sent, and no periodic refresh. A failure answers one of three generic messages and never the body, status line or resolved address (T-356's lesson), so the route cannot read an internal response; refusals are audited by category. Permission `saml_sp:write` and the `SAML_ADMIN_PER_MIN` bucket bound who and how often. Tests (T23.2.5): `saml_admin_test.rs::parse::a_url_is_refused_by_the_guard_with_a_message_that_names_no_address` (`http`, loopback, private, link-local, IPv6 and credentialed URLs); in `axiam-federation`, `saml_idp::sp_metadata::fetch_tests::without_the_seam_every_loopback_private_and_plain_http_url_is_refused`, `::a_success_is_the_body_and_a_failure_is_a_category_never_the_body` (an error body is never echoed) and `::the_response_is_capped_and_a_redirect_is_re_validated_strictly` (a redirect hop is held to the production rule); in `axiam-pki`, `ssrf::tests::ssrf_rejects_redirect_to_internal`."
      },
      {
       "number": 360,
       "title": "XML external entities, entity expansion or a parser differential in imported SP metadata",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "An SP metadata document is attacker-influenced XML (an upload, or whatever a URL serves). A DTD with external entities reads local files or makes requests; nested internal entities exhaust memory; a non-UTF-8 encoding can hide a declaration from a byte-level check.",
       "mitigation": "**Built (T23.2.5, 2026-10-04).** D-41: the receiver's rule, unchanged — `refuse_markup_declarations` (any `<!` other than a comment or CDATA) and `refuse_other_encodings` (a NUL, or a declared encoding other than UTF-8) on the bytes before any parser sees them, so there is no entity to expand; a 512 KiB cap; then `samael`'s metadata types, which open no network. Exactly one `EntityDescriptor` with one SAML 2.0 `SPSSODescriptor` is accepted; an aggregate is refused. Tests (T23.2.5): `saml_admin_test.rs::parse::dtd_xxe_encoding_aggregate_and_oversize_documents_are_refused_with_one_generic_message` (`<!DOCTYPE>`, `<!ENTITY>`, an entity bomb, a declared UTF-16 encoding, an `EntitiesDescriptor`, an oversized document); in `axiam-federation`, `saml_idp::sp_metadata::tests::a_dtd_an_entity_and_a_declared_foreign_encoding_are_refused_on_the_bytes` (UTF-16 on the wire included), `::an_aggregate_a_wrong_root_two_sp_descriptors_and_a_non_saml2_one_are_refused` and `::an_oversize_document_and_a_deeply_nested_one_are_refused`."
      },
      {
       "number": 361,
       "title": "Unsigned SP metadata decides what the IdP trusts",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "SP metadata is usually unsigned and fetched over a path the administrator does not control. If its ACS endpoints and certificates were stored as fetched — or refreshed from the URL later — whoever could alter the document in transit or on the SP's host would redirect assertions or substitute the key AXIAM verifies the SP's requests with.",
       "mitigation": "**Built (T23.2.5, 2026-10-04).** D-41: import is a parse to a draft, never a write; nothing is stored until an administrator submits the draft through `create_service_provider` or `update_service_provider`, where the validator and §29's refusals apply as to a manual entry. The document's own signature is not evaluated (there is no anchor, and its own certificate would be circular) and the draft warns so; the certificates' SHA-256 fingerprints are returned for out-of-band comparison; `validUntil` and `cacheDuration` are ignored; `encrypt_assertions` is never set; and AXIAM never re-reads an SP's metadata on its own. Tests (T23.2.5): `saml_admin_test.rs::parse::good_metadata_becomes_a_draft_that_create_accepts_unchanged_and_nothing_is_stored` (a parse stores nothing, `encrypt_assertions` is never set, the fingerprints come back) and `::parse::a_document_signature_is_reported_as_not_verified`."
      },
      {
       "number": 362,
       "title": "Registry and credential changes cannot be traced to an administrator",
       "type": "Repudiation",
       "severity": "Low",
       "status": "Mitigated",
       "description": "A changed ACS list, a new SP certificate or a promoted, retired or newly issued signing credential changes who receives assertions and which key SPs must trust. Without a record, a malicious or mistaken change cannot be attributed or reconstructed.",
       "mitigation": "**Built (T23.2.5, 2026-10-04).** Contract §29.3 rule 11 and D-42: `saml_sp.created`, `saml_sp.updated` (the names of the changed fields, `acs_changed`, `certificate_changed`), `saml_sp.deleted`, `saml_sp.metadata_parsed` (source, URL host, outcome), `saml_idp.credential_issued`, `saml_idp.credential_promoted` and `saml_idp.credential_retired` (ids, slot, fingerprint), each with the actor, on the append-only audit trail; never a certificate's or a document's content. Tests (T23.2.5): `saml_admin_test.rs::every_sp_write_leaves_an_audit_row_with_names_and_no_certificate` (`saml_sp.created`, `.updated`, `.deleted`), `::parse::good_metadata_becomes_a_draft_that_create_accepts_unchanged_and_nothing_is_stored` and `::parse::a_url_is_refused_by_the_guard_with_a_message_that_names_no_address` (`saml_sp.metadata_parsed`, success and refusal), `::issuing_fills_an_empty_slot_with_a_keyless_answer_and_a_sealed_key` (`saml_idp.credential_issued`), `::promote_swaps_the_slots_in_one_transaction_and_destroys_the_old_key` (`saml_idp.credential_promoted`) and `::retire_works_on_next_and_active_and_is_idempotent` (`saml_idp.credential_retired`)."
      },
      {
       "number": 363,
       "title": "The management routes are used to burn CPU or to amplify outbound requests",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "`issue_idp_credential` generates an RSA-4096 key (seconds of CPU) and `parse_sp_metadata` makes an outbound request per call. A loop with a stolen administrator token could exhaust the shared process or use AXIAM to hammer an external host.",
       "mitigation": "**Built (T23.2.5, 2026-10-04).** D-42: every write has a per-IP bucket of its own (`AXIAM__RATE_LIMIT__SAML_ADMIN_PER_MIN`, default 30 per route); issuance checks the slot before generating a key, so an occupied slot costs no key generation (T23.2.1), and a free slot can only be refilled by retiring — which is audited and destroys a key; a metadata fetch is one request with `guarded_fetch`'s timeout and caps and no retry. Tests (T23.2.5): `saml_admin_test.rs::the_seven_writes_have_a_bucket_each_pinned_at_30_and_reads_have_none` and `::an_occupied_slot_is_409_before_any_key_is_generated`."
      },
      {
       "number": 364,
       "title": "A credential write races, half-applies or is made by a principal who may only edit SPs",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Rotation is two moves — the old active out, the next in. Done as two calls it leaves a moment with no signer (every sign-on fails) or, done in the other order, a database that briefly holds two active keys; a stale console could promote a credential other than the one its operator saw; and a permission shared with ordinary SP edits would let whoever may rename an SP stop sign-on at every SP of the tenant.",
       "mitigation": "**Built (T23.2.5, 2026-10-04).** D-42: `promote_idp_credential/{credential_id}` requires that the id is the tenant's current `next` and inside its validity window (`409` otherwise) and retires the old `active` (destroying its key) and activates `next` in one transaction, a repository method of its own; the slots stay enforced by the UNIQUE index (D-21); issue writes only into an empty slot; the three credential writes need `saml_idp:credential`, separate from `saml_sp:write`. Retiring the active credential without a successor is allowed on purpose (the incident response to T-306) and the console must warn. Tests (T23.2.5): `saml_admin_test.rs::a_promotion_that_cannot_happen_is_a_409_or_404_and_changes_nothing` (a non-`next` id, an expired and a not-yet-valid `next`), `::promote_swaps_the_slots_in_one_transaction_and_destroys_the_old_key`, `::a_promotion_repeated_with_a_stale_page_is_a_409`, `::of_two_concurrent_promotions_exactly_one_wins` (on `surrealkv`) and `::each_operation_needs_its_own_permission_and_no_other` (the permission split); in `axiam-db`, `saml_idp_credential_test.rs::of_concurrent_promotions_exactly_one_wins` and `::a_promotion_that_cannot_happen_changes_nothing`."
      },
      {
       "number": 365,
       "title": "A management response or error carries the IdP signing key or its sealed form",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "The credential routes are the first API to expose the `saml_idp_credential` table. A response type derived from the stored row, or an error that formatted it, could hand the tenant's signing key — or its ciphertext and custody — to anyone with read access, and with it the ability to sign as the tenant at every SP.",
       "mitigation": "**Built (T23.2.5, 2026-10-04).** Contract §29.2 and D-42: `SamlIdpCredential` on the wire is a response type of its own with the public facts only (certificate, serial, fingerprint, dates, status, issuer CA) — no key, no ciphertext, no custody — built from `SamlIdpCredential`, which carries no key field, and never from `SealedSamlIdpCredential`; only the signer calls `get_active_sealed`. The core type derives no `Serialize`, so a route cannot expose the row by accident. SDKs must drop an undeclared key member (§29.5). Tests (T23.2.5): `saml_admin_test.rs::the_credential_list_is_a_bare_array_newest_first_and_carries_no_key`, `::issuing_fills_an_empty_slot_with_a_keyless_answer_and_a_sealed_key`, `::promote_swaps_the_slots_in_one_transaction_and_destroys_the_old_key`, `::retire_works_on_next_and_active_and_is_idempotent`, `::a_promotion_that_cannot_happen_is_a_409_or_404_and_changes_nothing` (the error bodies) and `::the_spec_has_the_eleven_operations_and_a_credential_with_no_key_member` — each asserts that no answer contains `PRIVATE KEY`, a key column name or the sealed bytes."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "2d150b0e-0535-5769-8bdc-0c75f7669c8e",
     "kind": "store",
     "x": 1269,
     "y": 834,
     "w": 170,
     "h": 80,
     "name": "saml_service_provider (SP registry)",
     "lines": [
      "saml_service_provider",
      "(SP registry)"
     ],
     "description": "Schema v72 (T23.2.1): one row per registered SP — entity id (unique per tenant), ACS allow-list, SLO endpoint, NameID policy, response signing, certificates (public), attribute mappings, allowed groups. No secret. Written only by the §29 routes after validation; read by the SSO and SLO endpoints, which re-check what they use.",
     "outOfScope": false,
     "threats": [
      {
       "number": 366,
       "title": "A registry row is read or written across tenants, or outlives the SP it described",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The `saml_service_provider` table holds every tenant's SP registrations side by side. A query that lost its tenant key would let one tenant's SSO request match another tenant's SP; a delete that left the SP's session records behind would let a stale participation drive a logout.",
       "mitigation": "**Built (T23.2.4, 2026-10-04).** Every repository method is tenant-keyed and `entity_id` is unique per tenant (T23.2.1, Mitigated at the repository); rows go with their tenant in the tenant-delete transaction. D-37 and §29.3 rule 5: deleting an SP deletes its pending `AuthnRequest`s and its `saml_sp_session` rows in the same transaction (`SP_DELETE_CASCADE`), so a stale participation can never drive a logout or keep a `NameID` for an SP that no longer exists; the registry holds no secret (certificates are public). Tests (T23.2.4): in `axiam-db`, `saml_service_provider_test.rs::deleting_an_sp_removes_what_the_datastore_holds_for_it` (the pending requests and the participant rows of the deleted SP are gone, another SP's stay, a refused delete cascades nothing), `saml_slo_test.rs::deleting_an_sp_removes_its_participant_rows_and_only_its_own` and `::deleting_a_tenant_removes_both_tables_rows_and_only_its_own`; over HTTP, `saml_admin_test.rs::deleting_an_sp_over_http_removes_its_pending_requests_and_only_its_own`; the repository tenant-isolation tests of T23.2.1 in `saml_service_provider_test.rs`."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "e7c6d16d-b27f-5884-b98a-d3b974004b47",
     "kind": "process",
     "x": 624,
     "y": 1044,
     "w": 140,
     "h": 140,
     "name": "SAML IdP metadata (/saml/v2/{tenant}/metadata)",
     "lines": [
      "SAML IdP",
      "metadata",
      "(/saml/v2/{tenant}/metadata)"
     ],
     "description": "D-40 (built by T23.2.5, behind `saml`): GET/HEAD, unauthenticated; one EntityDescriptor from fixed templates — signing keys of the `active` and `next` credentials, SSO (and, from T23.2.4, SLO) locations from the one URL function per tenant; unsigned; the D-20 404 when SAML is unavailable, off or without a publishable credential; cached for an hour with an ETag.",
     "outOfScope": false,
     "threats": [
      {
       "number": 367,
       "title": "An SP pins a key or endpoints that are not the tenant's",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "SPs trust whatever certificate the IdP metadata carries. A document built from request input, served for the wrong tenant, or with stale or extra keys would make an SP trust an attacker's key or send users somewhere else.",
       "mitigation": "**Built (T23.2.5, 2026-10-04).** D-40: one fixed template, every value escaped; `entityID` and every location from `idp_entity_id`/`idp_sso_url`/`idp_slo_url` of the path tenant only (T-307); one `KeyDescriptor use=\"signing\"` per publishable credential — `active`, then `next` — read through the keyless `list`; no encryption key; `SingleLogoutService` only once the route exists. Unsigned by decision: signing with the published key anchors nothing and would mint another signed document (T-316); trust comes from TLS to the deployment's origin and the fingerprint §29 shows. Residual: an SP that fetches metadata over a path an attacker controls is outside AXIAM's reach. Tests (T23.2.5): `saml_admin_test.rs::metadata::the_document_parses_back_with_samael_active_before_next_and_never_a_retired_key` (both keys, `active` first, no retired one, no encryption key, no `SingleLogoutService`), `::metadata::each_tenant_publishes_its_own_urls_and_keys` and `::metadata::a_promotion_changes_what_is_published`; in `axiam-federation`, `saml_idp::idp_metadata::tests` (the template carries what D-40 names and nothing else, every value escaped)."
      },
      {
       "number": 368,
       "title": "The metadata endpoint reveals whether a tenant exists, serves SAML or has a credential",
       "type": "Information disclosure",
       "severity": "Low",
       "status": "Mitigated",
       "description": "The metadata route is unauthenticated. Different answers for an unknown tenant, a tenant with SAML off, a build without SAML and a tenant without a credential would let anyone enumerate tenants and their SAML posture.",
       "mitigation": "**Built (T23.2.5, 2026-10-04).** D-40 with D-20/D-27: the same empty `404` for every one of those cases and for a non-canonical tenant id, decided before anything is read, on every method and sub-path (`default_service`); no `503` for a missing credential. Readiness is visible only to the tenant's administrator through §29 `get_idp`. Residual as T-326: a flood tells a build with SAML from one without (429 against 404). Tests (T23.2.5): `saml_admin_test.rs::metadata::the_three_d20_404s_are_indistinguishable_from_each_other_and_from_an_unmounted_path` (an unknown tenant, a non-canonical id, the setting off, only a retired credential, no credential, sub-paths and every other method)."
      },
      {
       "number": 369,
       "title": "A metadata request flood loads the database and the process",
       "type": "Denial of service",
       "severity": "Low",
       "status": "Mitigated",
       "description": "Every metadata request reads the tenant's settings and credentials and renders XML, unauthenticated.",
       "mitigation": "**Built (T23.2.5, 2026-10-04).** D-40: a per-route governor with the `end_session_per_min` preset and the shared bucket `saml_idp_metadata`; at most two certificates per document; `Cache-Control: public, max-age=3600` and a strong `ETag` so SPs and caches revalidate cheaply (`304`). Tests (T23.2.5): `saml_admin_test.rs::metadata::the_metadata_route_is_rate_limited_with_a_bucket_of_its_own` and `::metadata::the_etag_revalidates_with_304_and_head_answers_like_get`."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "98615ed3-7338-5a0e-a46a-c202a2371450",
     "kind": "process",
     "x": 824,
     "y": 794,
     "w": 140,
     "h": 140,
     "name": "SAML SLO endpoint (/saml/v2/{tenant}/slo)",
     "lines": [
      "SAML SLO",
      "endpoint",
      "(/saml/v2/{tenant}/slo)"
     ],
     "description": "D-38/D-39 (built by T23.2.4, behind `saml`): GET/POST `/slo` for SP LogoutRequests and LogoutResponses on both bindings, and the IdP-initiated trigger `/sso/logout`. Receives with T23.2.3's receiver, requires every SP message signed (per node, SHA-2, never verify_signed_xml), resolves sessions through `saml_sp_session`, revokes them (back-channel to OIDC clients, invalidate → revocation feed) before propagating a signed LogoutRequest to each other SP through the browser, clears the OP cookies, and answers the initiating SP.",
     "outOfScope": false,
     "threats": [
      {
       "number": 370,
       "title": "A forged LogoutRequest ends another user's sessions",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Whoever can make a browser deliver a `LogoutRequest` naming a user's `NameID` and `SessionIndex` could sign that user out everywhere; done across a tenant, it is a mass sign-out.",
       "mitigation": "**Built (T23.2.4, 2026-10-04).** D-38: every `LogoutRequest` must be signed by the issuing SP's registered certificate — HTTP-Redirect over the exact octets received, RSA-SHA-2 only (`SigAlg` must name RSA-SHA-256, -384 or -512, else the request is refused as an algorithm not accepted; `SigAlg` is itself among the signed octets, and a `SigAlg` that names another algorithm than the one the signature was made with fails as an invalid signature — there is no separate comparison; wording made exact in the W4 F4 review); HTTP-POST as the one enveloped signature of the root, verified on that node by xmlsec with SHA-1 refused; `verify_signed_xml` is never used — and an SP without a certificate cannot start a logout; `Destination` must be present and byte-equal to the tenant's SLO URL, `IssueInstant` fresh, `NotOnOrAfter` unexpired. A disabled SP's key ends nothing. D-37: the request resolves only sessions recorded for that SP whose `NameID` matches. Anything refused gets an error page that posts nowhere, sets no cookie and signs nothing. Tests (T23.2.4), over HTTP in `saml_idp_slo_test.rs`: `unsigned_wrong_key_tampered_and_sha1_requests_are_refused_on_both_bindings`, `a_misplaced_or_wrong_binding_signature_is_refused` (inside `Extensions`, inside the `NameID`, beside a second signature, a half signature, an enveloped signature on the Redirect binding), `field_level_refusals_hold_on_both_bindings` (wrong and missing `Destination`, stale and future `IssueInstant`, expired `NotOnOrAfter`, `EncryptedID`, `BaseID`, 33 `SessionIndex` values, an empty `NameID`) and `an_sp_without_a_certificate_a_disabled_sp_and_an_unknown_issuer_cannot_initiate`; in `axiam-federation`, `saml_idp::logout::tests::a_signature_anywhere_but_the_roots_own_child_is_refused` and `::a_redirect_query_carries_one_message_and_is_signed_over_that_parameter`. Every refusal test asserts the session, the participant row and the run table are untouched."
      },
      {
       "number": 371,
       "title": "A captured logout message is replayed",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Logout messages travel through the browser and can be captured. A replayed `LogoutRequest` could end a session created after it; a replayed `LogoutResponse` could advance or confuse a logout chain.",
       "mitigation": "**Built (T23.2.4, 2026-10-04).** D-38: a `LogoutRequest` `ID` is single-use per SP — `replay_key` `{sp_id}:{ID}`, UNIQUE per tenant in `saml_logout_run`, claimed before anything is resolved or revoked and kept after the run finishes, for the row's ten minutes, longer than the five-minute `IssueInstant` window; D-39: each outbound request `ID` is 256 random bits, stored as a digest and consumed once on the X6 two-layer arbiter when its response arrives, from the SP it was sent to. Tests (T23.2.4): `saml_idp_slo_test.rs::a_replayed_request_id_is_refused_and_ends_no_later_session` (both bindings; the replay of a request naming no index does not end a session created after it) and `::a_replayed_or_foreign_in_response_to_is_refused` (a response from the wrong SP, an unknown id, a replay after the chain moved on and after it ended); in `axiam-db`, `saml_slo_test.rs::a_request_id_is_single_use_per_sp_even_after_the_run_finished`, `::an_outbound_request_is_consumed_once_by_the_sp_it_went_to` and `::concurrent_responses_yield_exactly_one_winner` (100 rounds of 8 racers on surrealkv)."
      },
      {
       "number": 372,
       "title": "XML external entities, entity expansion or a decompression bomb in a logout message",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "The SLO endpoint parses SP-supplied XML, DEFLATE-compressed on the Redirect binding, before it knows who sent it.",
       "mitigation": "**Built (T23.2.4, 2026-10-04).** D-38: T23.2.3's receiver, unchanged — 96 KiB encoded and 64 KiB decoded caps, inflating stopped one byte past the cap, any markup declaration and any non-UTF-8 encoding refused on the bytes, libxml without recovery or network — before any lookup; the tenant check and the D-20 `404` run before the body is read. Tests (T23.2.4): `saml_idp_slo_test.rs::xxe_and_a_decompression_bomb_are_refused_before_any_lookup` (an external entity on both bindings and a 16 MiB bomb on the Redirect binding, each refused with no run claimed and nothing touched); in `axiam-federation`, `saml_idp::logout::tests::a_dtd_or_entity_is_refused_before_parsing`, plus the receiver's own refusal tests (`saml_idp::request::tests`)."
      },
      {
       "number": 373,
       "title": "A logout message signed by the tenant's key is harvested as a signature-wrapping gadget",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "T-316's constraint: an SP verifier that checks only the first signature, or binds a reference by name, can be fed any document the tenant's key signed, placed ahead of a forged assertion. Signed logout messages are such documents, and SLO exists to produce them.",
       "mitigation": "**Built (T23.2.4, 2026-10-04).** D-38: AXIAM signs a `LogoutRequest` only for a session its holder ended or a verified SP request ended, and a `LogoutResponse` only in reply to a verified request — never for an unauthenticated party, so obtaining one needs a session (whose holder can already obtain signed responses for their own account) or an SP's key. On HTTP-Redirect the signature is the detached query signature, so no XML signature exists to harvest; on HTTP-POST it is enveloped like the assertion's (root child, one reference to the root `ID`) and re-verified before sending. AXIAM's own SP verifier refuses misplaced signatures (D-23). Tests (T23.2.4): `saml_idp_slo_test.rs::the_other_sps_receive_signed_logout_requests_in_sequence_and_a_partial_run_ends_in_partial_logout` (every Redirect-bound message is verified against the tenant credential's certificate and carries no `Signature` in its document; every POST-bound one carries exactly one enveloped signature that verifies) and `::a_full_run_ends_in_success_to_the_initiator`; the refusal tests of T-370 and `::an_sp_without_a_certificate_a_disabled_sp_and_an_unknown_issuer_cannot_initiate`, whose `assert_refused` checks that an unverified message gets no redirect, no form, no cookie and so nothing signed; in `axiam-federation`, `saml_idp::logout::tests::a_redirect_logout_request_has_a_detached_signature_and_no_xml_signature`, `::a_post_logout_request_is_enveloped_and_verifies_under_the_roots_own_signature`, `::a_logout_response_is_signed_on_both_bindings_and_reports_success_or_partial` and `::nothing_is_signed_for_an_input_that_is_not_in_order`."
      },
      {
       "number": 374,
       "title": "A flood or an endless chain exhausts the SLO endpoint",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "`/slo` and the logout trigger are unauthenticated, parse XML and verify signatures; a logout chain could be driven through many SPs.",
       "mitigation": "**Built (T23.2.4, 2026-10-04).** D-38/D-39: the tenant check and D-20 `404` before the body is read; per-route governors with the `end_session_per_min` preset and the buckets `saml_idp_slo` and `saml_idp_sso_logout`; the receiver's size caps; at most 32 `SessionIndex` elements per request and 32 SPs per chain, then `PartialLogout`; runs expire after ten minutes and are swept. Tests (T23.2.4): `saml_idp_slo_test.rs::the_slo_route_is_rate_limited` and `::the_logout_trigger_is_rate_limited_in_a_bucket_of_its_own` (each bucket at a limit of 1, and `/slo` keeps its own allowance), `::a_run_is_capped_at_32_service_providers_and_is_partial_past_it` (33 participants: 32 taken, the run partial from the start), `::field_level_refusals_hold_on_both_bindings` (33 `SessionIndex` values refused, 32 served) and `::slo_and_the_logout_trigger_answer_an_indistinguishable_404_when_saml_is_off`; in `axiam-federation`, `saml_idp::logout::tests::at_most_32_session_indexes_are_read`; in `axiam-db`, `saml_slo_test.rs::expired_runs_are_swept_and_a_runs_user_rows_are_erased`."
      },
      {
       "number": 375,
       "title": "The SLO endpoint delivers messages or the browser to a location an SP never registered",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A logout endpoint that took its destination from a message — a response location, a `RelayState`, a post-logout parameter — would be an open redirector and could post signed logout messages to an attacker.",
       "mitigation": "**Built (T23.2.4, 2026-10-04).** D-38/D-39: outbound messages go only to the SP's registered `slo_url` on its registered `slo_binding`, the final response only to the initiating SP's registered `slo_url`; an SP's `RelayState` (≤ 80 bytes) is echoed to that SP only; the IdP-initiated trigger ends on AXIAM's own page with no redirect parameter; the POST binding renders through the D-27 auto-post page (`form-action` = the `slo_url` origin), so no second setter of a content-security policy appears. Tests (T23.2.4): `saml_idp_slo_test.rs::a_message_naming_another_location_is_answered_at_the_registered_one` (hostile extensions and a URL as `RelayState`, both bindings, the form's policy naming only the registered origin) and `::the_trigger_reads_no_destination_from_its_query`, and the destination assertions of the propagation tests; in `axiam-api-rest`, `middleware::security_headers::tests::exactly_one_handler_sets_its_own_policy` (still exactly one) and `handlers::saml_idp::tests::the_auto_post_policy_is_narrower_than_the_global_one`."
      },
      {
       "number": 376,
       "title": "A logout cannot be traced to the SP, the sessions and the outcome",
       "type": "Repudiation",
       "severity": "Low",
       "status": "Mitigated",
       "description": "A user disputing that they were signed out, or an administrator investigating a mass sign-out, needs to know which SP asked, which sessions ended and which SPs were told.",
       "mitigation": "**Built (T23.2.4, 2026-10-04).** D-39: an audit row `saml_idp.logout` per logout phase — `sessions_ended` when the sessions are revoked (initiator, SP, sessions ended, SPs queued) and `completed` when the chain ends (SPs told, partial, outcome) — never a `NameID`, a `SessionIndex` or a session id; session revocation itself is recorded as every logout is. Tests (T23.2.4): `saml_idp_slo_test.rs::the_other_sps_receive_signed_logout_requests_in_sequence_and_a_partial_run_ends_in_partial_logout` (both rows, their phases and counts, and none of the principals' `NameID`s or indexes in either), `::a_full_run_ends_in_success_to_the_initiator` (outcome `success`) and `::the_idp_initiated_trigger_revokes_clears_the_cookies_and_propagates` (initiator `idp`)."
      },
      {
       "number": 378,
       "title": "A third-party page signs the visitor out of AXIAM and every SP",
       "type": "Spoofing",
       "severity": "Low",
       "status": "Mitigated",
       "description": "The IdP-initiated trigger acts on the browser's own OP cookie; a cross-site page that could navigate a visitor to it would end the visitor's session and their SP sessions — a nuisance, at scale a denial of service.",
       "mitigation": "**Built (T23.2.4, 2026-10-04).** D-39: `GET /saml/v2/{t}/sso/logout` is refused with `403` for `Sec-Fetch-Site: cross-site` (D-26's rule) and acts only on the session the browser's own OP cookie names, resolved through the tenant-keyed lookup; `/slo` itself acts only on signed SP requests and never reads the cookie. Residual as D-26: a browser that sends no fetch metadata is admitted. Tests (T23.2.4): `saml_idp_slo_test.rs::the_trigger_refuses_cross_site_and_resolves_the_cookie_in_its_own_tenant_only` (the cross-site trigger is refused with nothing ended and nothing cleared; with no cookie only the page is shown; another tenant's cookie names nothing here), `::the_idp_initiated_trigger_revokes_clears_the_cookies_and_propagates` and `::slo_never_reads_the_op_cookie`."
      },
      {
       "number": 379,
       "title": "An SP's logout reaches sessions it never took part in, or another tenant's",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "SLO ends whole sessions. If an SP could name any session — by a guessed index, by another SP's index, by a `NameID` alone or across tenants — one compromised SP could sign anyone out of everything.",
       "mitigation": "**Built (T23.2.4, 2026-10-04).** D-37/D-39: sessions are resolved by (path tenant, the verified issuer's SP, `SessionIndex`) in `saml_sp_session`, and the row's `NameID` value and format must equal the request's; with no index, only the sessions recorded for that SP and that `NameID`. Indexes are 256-bit random per SP. Tests (T23.2.4): `saml_idp_slo_test.rs::only_the_sessions_the_sp_participates_in_end_and_only_for_the_right_name_id` (another SP's index, a mismatched `NameID` value, a mismatched and an absent format, an unknown principal — each answered `Success`, each ending nothing; then the right request ends only its own session), `::a_request_without_an_index_ends_every_session_the_sp_holds_for_that_name_id` and `::another_tenants_path_ends_nothing` (an SP unknown to the other tenant is refused; one registered there with the same entity id and certificate finds no row under that tenant); in `axiam-db`, `saml_slo_test.rs::an_index_resolves_for_its_own_sp_and_tenant_only` and `::list_for_sp_name_id_is_scoped_to_the_sp_and_the_name_id`."
      },
      {
       "number": 380,
       "title": "SP sessions outlive the AXIAM session they came from",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Open",
       "description": "An SP keeps its own session after the assertion. When the AXIAM session ends by anything but a SAML logout chain — an administrator's revocation, a password reset, an account disable, `/oauth2/end_session`, expiry — or a chain stops at an SP that never answers, the remaining SPs are not told and the user stays signed in there.",
       "mitigation": "Accepted design trade-off (D-38, D-39). SAML has no back channel through the browser; the SOAP binding that would provide one is not implemented. What bounds it: SLO revokes the AXIAM session first, so a broken chain never keeps an AXIAM session alive; assertions are valid for five minutes and single-use; a revoked session or a suspended account obtains no new assertion (T-328), so the SP session cannot be renewed through AXIAM; and the SP's own session lifetime is the SP administrator's to set. A later decision may add SOAP back-channel logout or drive a chain from `end_session`."
      }
     ],
     "open": 1,
     "notApplicable": 0
    },
    {
     "id": "a2a0c721-f0d1-5524-a648-bf8002e851f5",
     "kind": "store",
     "x": 1079,
     "y": 964,
     "w": 170,
     "h": 80,
     "name": "saml_sp_session (per-SP SessionIndex)",
     "lines": [
      "saml_sp_session",
      "(per-SP SessionIndex)"
     ],
     "description": "D-37 (T23.2.4, next schema version): one row per (tenant, session, SP) — user, SP entity id, the asserted NameID and format, the per-SP random SessionIndex, expiry. Written by the SSO continue leg before signing; read by SLO to map an index back to a session and to find the SPs to tell.",
     "outOfScope": false,
     "threats": [
      {
       "number": 381,
       "title": "The participant table links a person's sessions to the SPs they use",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "`saml_sp_session` records, per live session, which SPs the user signed in to and the `NameID` each received — an email address at an `emailAddress` SP. A dump, or rows kept after the session or the person is gone, would disclose that history.",
       "mitigation": "**Built (T23.2.4, 2026-10-04).** D-37: rows are tenant-scoped, deleted when the logout chain that revoked their session ends, swept once the session has expired or is gone (a logout that just ended it keeps them for one run lifetime), deleted with their SP and their tenant, and removed by both erasure paths by `user_id`; they hold no credential (a `SessionIndex` alone ends nothing, since a logout request must be signed). Tests (T23.2.4), in `axiam-db`: `saml_slo_test.rs::the_sweeper_removes_expired_rows_and_rows_of_sessions_that_are_gone`, `::deleting_a_tenant_removes_both_tables_rows_and_only_its_own`, `::deleting_an_sp_removes_its_participant_rows_and_only_its_own`, `::both_erasure_paths_remove_the_persons_rows` (the administrator's `delete` and the Art. 17 `anonymize_user`), `::rows_are_deleted_by_session_and_by_user_and_only_in_their_tenant` and the schema test `v76_stores_digests_and_record_ids_only_where_it_must` (no credential column); over HTTP, `saml_idp_slo_test.rs::an_sp_initiated_logout_on_the_redirect_binding_revokes_the_session_and_the_feed_shows_it` (no row left when the chain ends)."
      },
      {
       "number": 382,
       "title": "An assertion is issued whose session SLO cannot find",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "If the SSO leg signed before recording which SP got which `SessionIndex`, a failed or lost write would leave an SP holding a session no logout can reach.",
       "mitigation": "**Built (T23.2.4, 2026-10-04).** D-37: the continue leg writes (or reads back) the participant row after consuming the handle and before signing; the issuer takes its `SessionIndex` from the row and the endpoint compares what was issued with what was recorded; a failed write answers `Responder` and issues nothing. Tests (T23.2.4): `saml_idp_sso_test.rs::a_failed_participant_write_yields_no_assertion` (the datastore refuses every participant write: a failure response with no assertion and no row) and `::the_assertion_carries_a_per_sp_index_that_is_not_the_session_id`; in `axiam-federation`, `saml_idp::tests::the_authn_statement_carries_the_per_sp_index_instant_and_class`."
      },
      {
       "number": 384,
       "title": "Participant and logout-chain rows accumulate without bound",
       "type": "Denial of service",
       "severity": "Low",
       "status": "Mitigated",
       "description": "Every sign-on to an SP writes a row and every logout a run; without expiry the tables grow with traffic.",
       "mitigation": "**Built (T23.2.4, 2026-10-04).** D-37/D-39: one participant row per (session, SP), refreshed rather than duplicated; runs expire after ten minutes; both tables are swept by the cleanup scheduler and reported on `/health/jobs` as `saml_sp_session` and `saml_logout_run`. Tests (T23.2.4): in `axiam-db`, `saml_slo_test.rs::the_sweeper_removes_expired_rows_and_rows_of_sessions_that_are_gone`, `::expired_runs_are_swept_and_a_runs_user_rows_are_erased`, `::a_second_sign_on_to_one_sp_in_one_session_keeps_the_first_index` and `::concurrent_records_for_one_session_and_sp_agree_on_one_index`; over HTTP, `saml_idp_sso_test.rs::the_assertion_carries_a_per_sp_index_that_is_not_the_session_id` (a second sign-on adds no row); in `axiam-server`, `job_health::tests::the_slo_sweeps_are_recorded_by_the_cleanup_loop_and_registered`."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "ba9784ec-399d-526d-8530-f9541a09249a",
     "kind": "store",
     "x": 1269,
     "y": 964,
     "w": 170,
     "h": 80,
     "name": "saml_logout_run (logout chains)",
     "lines": [
      "saml_logout_run",
      "(logout chains)"
     ],
     "description": "D-38/D-39 (T23.2.4): a logout in progress — initiator, the queue of participant rows still to tell, the digest of the current outbound request ID, the partial flag and the inbound LogoutRequest replay key; ten-minute rows, consumed on the X6 arbiter.",
     "outOfScope": false,
     "threats": [
      {
       "number": 383,
       "title": "A database read yields a usable logout-chain identifier",
       "type": "Information disclosure",
       "severity": "Low",
       "status": "Mitigated",
       "description": "A logout run names the next SP's outbound request. If the store kept the raw request `ID`, someone who could read it could forge the matching `LogoutResponse` and steer the chain.",
       "mitigation": "**Built (T23.2.4, 2026-10-04).** D-39: the outbound request `ID` is stored as its SHA-256 digest, consumed once, and accepted only from the SP it was sent to (with its signature when it registered a certificate); runs are tenant-scoped, expire after ten minutes and go with their tenant. A forged response could at most continue a logout already under way. Tests (T23.2.4): in `axiam-db`, `saml_slo_test.rs::the_run_holds_a_digest_of_the_outbound_id_and_no_name_id` and the schema test `v76_stores_digests_and_record_ids_only_where_it_must`; over HTTP in `saml_idp_slo_test.rs`, `the_other_sps_receive_signed_logout_requests_in_sequence_and_a_partial_run_ends_in_partial_logout` (the stored run holds the digest and the serialised table never contains the `ID`), `::a_replayed_or_foreign_in_response_to_is_refused` (only the SP the request went to can consume it) and `::non_success_answers_make_the_run_partial_and_unverified_ones_are_refused_unconsumed` (an unsigned or wrong-key answer from an SP with a certificate is refused and consumes nothing)."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "84aeaa23-2930-5ea3-8269-d1e7fd183781",
     "kind": "store",
     "x": 1079,
     "y": 1094,
     "w": 170,
     "h": 80,
     "name": "session / revoked_session (feed)",
     "lines": [
      "session /",
      "revoked_session (feed)"
     ],
     "description": "The AXIAM session rows and, when the feed is on, the revocation feed's `revoked_session` entries (shown in full on the authentication diagram). SLO revokes through `SessionRepository::invalidate`, which publishes the revoked session's hash.",
     "outOfScope": false,
     "threats": [],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "be826e94-7b03-5922-a02b-b3f09f0b03ff",
     "path": "M199,317.7 L627.9,167.2",
     "name": "list login providers",
     "description": "",
     "label": "list login providers (HTTPS, unauthenticated)",
     "labelLines": [
      "list login providers (HTTPS,",
      "unauthenticated)"
     ],
     "lx": 413.5,
     "ly": 242.4,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "a8e4a89b-05d8-5e08-94c5-70e7fc2932e1",
     "path": "M199,135 L824,143.1",
     "name": "userinfo response",
     "description": "",
     "label": "userinfo response (HTTPS)",
     "labelLines": [
      "userinfo response (HTTPS)"
     ],
     "lx": 511.5,
     "ly": 139,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "aaf682f3-9e81-5764-83d7-a9a53e798847",
     "path": "M843.9,192.9 L494.1,535.1",
     "name": "userinfo fetch",
     "description": "",
     "label": "userinfo fetch (via guarded_fetch)",
     "labelLines": [
      "userinfo fetch (via guarded_fetch)"
     ],
     "lx": 669,
     "ly": 364,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "44226f03-37d0-500d-84b8-a594f933aee7",
     "path": "M953.2,316.7 L1100.5,224",
     "name": "resolve effective providers",
     "description": "",
     "label": "resolve effective providers",
     "labelLines": [
      "resolve effective providers"
     ],
     "lx": 1026.9,
     "ly": 270.4,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB (TLS)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "b0cf1693-6f8f-567b-b49e-4f2a5466e7d8",
     "path": "M374,351.8 L199,346.3",
     "name": "SSO handoff code",
     "description": "",
     "label": "SSO handoff code (redirect, 60 s, single use)",
     "labelLines": [
      "SSO handoff code (redirect, 60 s,",
      "single use)"
     ],
     "lx": 286.5,
     "ly": 349.1,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [
      {
       "number": 219,
       "title": "A handoff code is captured from a URL and redeemed first",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "AXIAM's session cookies are `SameSite=Strict`. SAML and Apple's `response_mode=form_post` both return **cross-site**, so cookies set on that response would not be sent on the navigation that follows. The mechanism that bridges it — a code in a redirect URL, exchanged same-origin — puts a session-bearing credential somewhere URLs go: browser history, and a `Referer` header.",
       "mitigation": "The code is 256 bits from the same CSPRNG as `state`; only its SHA-256 hash is stored, so a database read yields nothing usable; it lives **60 seconds**, not the ten minutes a login state row gets, because it exists to survive exactly one redirect; and it is consumed atomically by the same `SELECT`+`DELETE` transaction pattern as `consume_by_state`, so a replay is refused with the same answer as an unknown code. It carries no token material at all — the session is minted from `user_id`/`tenant_id` at redemption, so a code that is never redeemed leaves no session behind. The redirect response sets `Cache-Control: no-store` and `Referrer-Policy: no-referrer`, and the SPA strips the parameter with `history.replaceState` before doing anything else.\n\n**Where the code may be delivered is the load-bearing part, and it is not the caller's choice.** `redirect_uri` reaches AXIAM on an *unauthenticated* start endpoint, and `validate_redirect_uri` checks its scheme only — every `https://` host on the internet passes it. The two cross-site flows have no provider-side backstop **by construction**: a SAML IdP is pointed at AXIAM's own ACS and Apple at AXIAM's own form-callback, so the provider never sees the SPA URI and never validates it — AXIAM alone decides where the browser goes next, carrying a credential the handoff endpoint will exchange for session cookies for whoever presents it. Without a check, anyone could start a login with `redirect_uri = https://attacker.example/`, lure a victim through the victim's own real IdP, and read a working session out of their access log; the 60-second TTL, the single use and the hash-only storage are all irrelevant when the attacker *is* the destination. `require_deployment_spa_origin` therefore confines the target to the **origin of** `AuthConfig::effective_issuer()` — the same value the ACS and form-callback URLs are built from, so it cannot be wrong where these flows work at all — plus anything an operator names in `AXIAM__AUTH__SSO_SPA_ORIGINS` for a separately hosted SPA. Compared as origins via `Url::origin`, so a userinfo prefix, a path, a port or a scheme cannot smuggle a second host past it. It is enforced at login start (a `400` naming the knob), again at the mint (so a state row written by an older binary is not honoured), and on the error redirect. It runs *after* workspace and config resolution, so an unknown slug still answers the uniform `401`. This is the rule T-52 already states for the OAuth2 authorization server's own `redirect_uri`.\n\n**Enforced on all four start paths since 1.0.0-beta12 (R-3), not only the cross-site two.** The OIDC and plain-OAuth2 paths were left on the scheme-only check because the identity provider *is* handed the same `redirect_uri` and *does* compare it against its registered set. That backstop is real and it stays — but it is only as strict as each provider's registration hygiene, and several providers accept wildcard or prefix registrations; more to the point it is a control AXIAM neither owns nor can inspect, so nothing on this side can tell whether a given tenant's provider was registered tightly. The rule the server owns is therefore uniform across the four flows, and on the OIDC and OAuth2 flows the provider's registered-redirect check is now a second, independent layer rather than the only one. The `TODO(T19.14)` that proposed a per-`FederationConfig` registered-redirect allowlist is retired rather than carried: the deployment-origin rule already answers where a code may go, and a second list to keep in sync is a second place to get wrong. `sdks/CONTRACT.md` §12.1 rule 12a widened to match (contract 1.39), additive and restrictive server-side only. One class of deployment must act: an SPA on an origin other than the issuer's, signing in through OIDC or OAuth2, needs `AXIAM__AUTH__SSO_SPA_ORIGINS` set — the requirement SAML and Apple have imposed since beta08, and the `400` names the variable.\n\nWeakening the session cookies to `SameSite=Lax` would have removed the need for any of this, and re-opened the CSRF surface `Strict` closes across every endpoint, permanently, to serve two flows. Residual risk accepted: an attacker who reads the URL inside 60 seconds *and* redeems before the legitimate SPA gets a session — and the legitimate user gets a visible failure, because the code is gone. That is the same trade the OAuth authorization code itself makes."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "f2c61652-ff60-5339-805e-609b8a94c3ff",
     "path": "M199,375.6 L629.5,556.8",
     "name": "directory sign-in (password)",
     "description": "",
     "label": "directory sign-in (POST /auth/login, HTTPS)",
     "labelLines": [
      "directory sign-in (POST /auth/login,",
      "HTTPS)"
     ],
     "lx": 414.2,
     "ly": 466.2,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "5459bc1e-deb2-5bec-ab7b-b862818ac7fe",
     "path": "M626,600.7 L199,705.6",
     "name": "service bind + user search",
     "description": "",
     "label": "service bind + user search (LDAPS / StartTLS)",
     "labelLines": [
      "service bind + user search (LDAPS /",
      "StartTLS)"
     ],
     "lx": 412.5,
     "ly": 653.1,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "LDAP over TLS",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "1b53155b-1339-575b-b5e3-6aaf45a3c8ef",
     "path": "M626,600.7 L199,705.6",
     "name": "user bind (presented password)",
     "description": "",
     "label": "user bind with the presented password (LDAPS / StartTLS)",
     "labelLines": [
      "user bind with the presented",
      "password (LDAPS / StartTLS)"
     ],
     "lx": 412.5,
     "ly": 653.1,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "LDAP over TLS",
     "threats": [
      {
       "number": 292,
       "title": "A directory password crosses the network in the clear: a plaintext URL, or StartTLS stripped",
       "type": "Information disclosure",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "A simple bind carries the user's corporate password, which is the password for everything else the directory gates. A plaintext `ldap://` URL, a client that carries on after a server (or an on-path attacker) refuses StartTLS, or a bind sent before the upgrade completes hands it to anyone on the path.",
       "mitigation": "Plaintext is refused at three points: `config::validate` at save time (`ldap://` only with `start_tls`, `ldaps://` only without, every other scheme refused); the authenticator against the stored row; and `DirectoryClient::connect`, the only place a socket is opened. With StartTLS, `ldap3` sends the extended operation first and fails the connection when it is refused; AXIAM binds only after the connection call returns, which is after the handshake. `ldap3`'s `no_tls_verify` is never set. Tests: `a_refused_starttls_fails_closed_with_no_bind_in_the_clear` (the server would accept a clear-text bind, and receives none), `bind_as_user_succeeds_over_starttls_and_nothing_precedes_the_upgrade`, `a_plaintext_target_is_refused_with_zero_connections`, `a_stored_plaintext_url_is_refused_before_any_connection`. TLS 1.2 is the floor toward a directory rather than 1.3 because Active Directory on Windows Server 2019 and earlier, and many OpenLDAP builds, stop at 1.2; rustls restricts 1.2 to forward-secret AEAD suites."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "58b75628-0c13-55c4-a1ee-00739c3c753b",
     "path": "M199,705.6 L626,600.7",
     "name": "search entry / bind result",
     "description": "",
     "label": "search entry / bind result",
     "labelLines": [
      "search entry / bind result"
     ],
     "lx": 412.5,
     "ly": 653.1,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "LDAP over TLS",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "5b264422-f2c5-536d-9358-ba838a281afd",
     "path": "M763.4,592.9 L1079,633.1",
     "name": "read config + decrypt bind secret",
     "description": "",
     "label": "read config + decrypt bind secret",
     "labelLines": [
      "read config + decrypt bind secret"
     ],
     "lx": 921.2,
     "ly": 613,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB (private network)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "7d696844-4832-50fc-875a-20131322325c",
     "path": "M952.7,622.1 L1102.3,719",
     "name": "unseal active signing key",
     "description": "SamlIdpCredentialService::get_active_signing_key: the one read that selects the ciphertext; the key is opened into a Zeroizing buffer for one issuance.",
     "label": "unseal active signing key",
     "labelLines": [
      "unseal active signing key"
     ],
     "lx": 1027.5,
     "ly": 670.5,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB (private network)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "f92614c0-f205-5e5f-9730-1b48f5a720cb",
     "path": "M830.9,614.3 L199,918",
     "name": "signed SAML response (HTTP-POST)",
     "description": "Base64 of the samlp:Response, auto-posted by the user's browser to the registered ACS URL, with RelayState echoed verbatim (at most 80 bytes).",
     "label": "signed SAML response (HTTP-POST via the browser)",
     "labelLines": [
      "signed SAML response (HTTP-POST via",
      "the browser)"
     ],
     "lx": 515,
     "ly": 766.1,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS (SAML HTTP-POST binding)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "86f8777a-f3dc-5554-8c11-a5915843dd41",
     "path": "M199,942.2 L624.9,874.9",
     "name": "AuthnRequest (HTTP-Redirect / HTTP-POST, via the browser)",
     "description": "The SP's AuthnRequest, carried by the user's browser: a DEFLATEd query parameter (Redirect, optionally signed over the query) or a form post (POST, optionally signed enveloped), with RelayState. Crosses the AXIAM ↔ SAML service provider boundary.",
     "label": "AuthnRequest (HTTP-Redirect / HTTP-POST, via the browser)",
     "labelLines": [
      "AuthnRequest (HTTP-Redirect /",
      "HTTP-POST, via the browser)"
     ],
     "lx": 411.9,
     "ly": 908.5,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS (SAML bindings)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "55ea167f-3347-575f-8690-1f8ca464a0b9",
     "path": "M167.8,384 L642.3,816.8",
     "name": "continue leg: OP cookie + binding cookie",
     "description": "GET /saml/v2/{tenant}/sso/continue?handle=…: a top-level navigation carrying the SameSite=Lax OP-session cookie (minted at /saml/v2/{tenant}/sso since T23.2.3) and the per-handle binding cookie; the return leg of the login hop.",
     "label": "continue leg: OP cookie + binding cookie",
     "labelLines": [
      "continue leg: OP cookie + binding",
      "cookie"
     ],
     "lx": 405.1,
     "ly": 600.4,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [
      {
       "number": 325,
       "title": "RelayState and the pending handle are recorded in request logs",
       "type": "Information disclosure",
       "severity": "Low",
       "status": "Mitigated",
       "description": "The HTTP-Redirect binding carries `RelayState` (and `SAMLRequest`) in the query string, and the continue leg carries the pending handle there. The request-tracing middleware records the request target, query included, as it does for every route.",
       "mitigation": "**Closed 2026-10-04 (W3 F4 review, P23W3-03).** `axiam-server` wraps the application in `TracingLogger::<RedactingRootSpanBuilder>` (`axiam_api_rest::middleware::request_span`): the default builder's field set, span name and target, with `http.target` recorded as the path and every query **value** replaced by `[redacted]` unless its parameter is on a short allow-list of structural ones (tenant, organization and client ids, protocol switches, pagination), and a `{token}` path segment redacted too; parameter names stay. An allow-list rather than a deny-list, so a parameter added later is redacted until someone decides otherwise. The same change takes `/oauth2/authorize`'s `state` and `login_hint`, `end_session`'s `id_token_hint`, password-reset, GDPR-cancellation and export tokens and administrators' search terms out of the request log, which the default builder recorded on every route (with the shipped `axiam=info` filter the root span is recorded only where an operator enables `tracing_actix_web`). Unchanged: the SSO handlers never log `SAMLRequest`, `SAMLResponse`, `RelayState`, the handle, the binding value or the OP cookie, the audit middleware records paths only, and a handle is useless without the browser's binding cookie (T-322) and single-use. Tests: `request_span::tests` (each sensitive parameter redacted and each structural one kept, the export token redacted from the path, and a request through `TracingLogger` whose recorded span carries the redacted target and never the handle) and `t9_4_the_request_logging_layer_records_no_headers_at_all` (the server installs this builder, and the builder reads no header but `User-Agent`)."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "0cb2b6b5-fab7-5f04-bac9-6abe03099111",
     "path": "M764,865.5 L1079,872.2",
     "name": "hold / consume pending request (X6)",
     "description": "CREATE under the replay index on the first leg; a read on the second; the guarded UPDATE plus nonce read-back that consumes the handle exactly once before issuing.",
     "label": "hold / consume pending request (X6)",
     "labelLines": [
      "hold / consume pending request (X6)"
     ],
     "lx": 921.5,
     "ly": 868.8,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB (private network)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "371da1a7-3637-565b-8c77-5b7b69034023",
     "path": "M734.7,807 L853.3,641",
     "name": "checked request + resolved session",
     "description": "The SP row, the resolved ACS URL, InResponseTo, RelayState, the session, the account (account_may_act), groups and roles, and the unsealed credential, handed to SamlIdpIssuer::issue in a blocking task.",
     "label": "checked request + resolved session",
     "labelLines": [
      "checked request + resolved session"
     ],
     "lx": 794,
     "ly": 724,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "fc29364c-ec65-5863-ba0e-8bdb23ac0f36",
     "path": "M379.9,835.9 L199,756.8",
     "name": "sync searches",
     "description": "",
     "label": "sync searches: by identifier, by watermark, rootDSE (LDAPS / StartTLS)",
     "labelLines": [
      "sync searches: by identifier, by",
      "watermark, rootDSE (LDAPS /",
      "StartTLS)"
     ],
     "lx": 289.4,
     "ly": 796.4,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "LDAP over TLS",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "3cab2c3b-a0e3-527b-8d9c-f6c4702469e0",
     "path": "M199,756.8 L379.9,835.9",
     "name": "sync entries + watermark",
     "description": "",
     "label": "entries + watermark",
     "labelLines": [
      "entries + watermark"
     ],
     "lx": 289.4,
     "ly": 796.4,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "LDAP over TLS",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "7ad160e9-27fe-5fe7-973a-d9bb6ed74961",
     "path": "M510.9,843.5 L1079,670",
     "name": "sync: read config + decrypt bind secret",
     "description": "",
     "label": "read config + decrypt bind secret",
     "labelLines": [
      "read config + decrypt bind secret"
     ],
     "lx": 795,
     "ly": 756.8,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB (private network)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "61f7d0d2-6d12-56e2-a2c0-484166cfd156",
     "path": "M512,847.6 L1269,664.5",
     "name": "sync: read / write run state",
     "description": "",
     "label": "read / write run state",
     "labelLines": [
      "read / write run state"
     ],
     "lx": 890.5,
     "ly": 756.1,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB (private network)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "7e78b413-27fd-5738-b8b9-ffc1bd9485be",
     "path": "M513.5,856 L1269,768.8",
     "name": "sync: deactivate, revoke, unmap, refresh",
     "description": "",
     "label": "deactivate (compare-and-set), revoke, unmap, refresh attributes",
     "labelLines": [
      "deactivate (compare-and-set),",
      "revoke, unmap, refresh attributes"
     ],
     "lx": 891.3,
     "ly": 812.4,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB (private network)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "7d593dc0-6b7f-53bd-82bb-0dd4a569a55d",
     "path": "M761.7,601.9 L1269,736.5",
     "name": "sign-in: provision, link, map groups",
     "description": "",
     "label": "JIT create, link, apply group mapping",
     "labelLines": [
      "JIT create, link, apply group",
      "mapping"
     ],
     "lx": 1015.3,
     "ly": 669.2,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB (private network)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "838d668f-79a3-5423-9b67-3a6cab44d25b",
     "path": "M199,1167.6 L375.6,1129",
     "name": "§29 management calls (bearer)",
     "description": "Authenticated administrator calls to the `saml` namespace: SP CRUD, metadata parse, credential lifecycle.",
     "label": "§29 management calls (bearer)",
     "labelLines": [
      "§29 management calls (bearer)"
     ],
     "lx": 287.3,
     "ly": 1148.3,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS (REST)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "7a016eb8-b689-5611-8e99-4c70624d8222",
     "path": "M511.7,1096.1 L1269,896.4",
     "name": "validated SP write / read",
     "description": "Create, replace, delete and read SP rows after `validate_saml_service_provider` and §29.3's refusals; delete cascades to the SP's participant rows.",
     "label": "validated SP write / read",
     "labelLines": [
      "validated SP write / read"
     ],
     "lx": 890.3,
     "ly": 996.3,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB (private network)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "da053c41-980b-5812-930d-c75174de5ed2",
     "path": "M506.8,1083 L1082.9,799",
     "name": "issue / promote / retire (one transaction)",
     "description": "Key generation and sealing on issue; promote retires the old active and activates next in one transaction; retire destroys the key. No key ever returned.",
     "label": "issue / promote / retire (one transaction)",
     "labelLines": [
      "issue / promote / retire (one",
      "transaction)"
     ],
     "lx": 794.8,
     "ly": 941,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB (private network)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "aecc212e-9e49-5c1a-87f9-aedc40961889",
     "path": "M444,1044 L444,654",
     "name": "SP metadata_url fetch request",
     "description": "parse_sp_metadata with a URL: handed to guarded_fetch only (https, resolve once and pin, private/loopback/link-local refused, redirects re-validated, capped).",
     "label": "SP metadata_url fetch request",
     "labelLines": [
      "SP metadata_url fetch request"
     ],
     "lx": 444,
     "ly": 849,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "b2044a54-8193-5743-bbd3-5e8ea2c42a5e",
     "path": "M398.2,636.9 L158.6,914",
     "name": "SP metadata fetch (guarded)",
     "description": "The single outbound GET for an SP's metadata, to the address the guard vetted.",
     "label": "SP metadata fetch (guarded)",
     "labelLines": [
      "SP metadata fetch (guarded)"
     ],
     "lx": 278.4,
     "ly": 775.5,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "fe16fedf-59bb-5766-bb45-b05c50734f1b",
     "path": "M199,975.1 L626.6,1095.1",
     "name": "IdP metadata fetch (unauthenticated)",
     "description": "An SP (or its administrator) reads the tenant's IdP metadata to pin the signing certificates and locations.",
     "label": "IdP metadata fetch (unauthenticated)",
     "labelLines": [
      "IdP metadata fetch (unauthenticated)"
     ],
     "lx": 412.8,
     "ly": 1035.1,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "3e31b42d-3cf5-5187-af38-eb02cf56ae4c",
     "path": "M749.9,1071.8 L1111,799",
     "name": "read active + next certificates (no key)",
     "description": "SamlIdpCredentialRepository::list — public facts only; never get_active_sealed.",
     "label": "read active + next certificates (no key)",
     "labelLines": [
      "read active + next certificates (no",
      "key)"
     ],
     "lx": 930.4,
     "ly": 935.4,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB (private network)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "4673f45b-efb4-5d72-893b-47935b6e0e14",
     "path": "M199,945.2 L824.5,872.1",
     "name": "LogoutRequest / LogoutResponse (Redirect / POST, via the browser)",
     "description": "An SP's signed logout request, or its answer to AXIAM's, delivered by the user's browser on either binding.",
     "label": "LogoutRequest / LogoutResponse (Redirect / POST, via the browser)",
     "labelLines": [
      "LogoutRequest / LogoutResponse",
      "(Redirect / POST, via the browser)"
     ],
     "lx": 511.7,
     "ly": 908.7,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS (front channel)",
     "threats": [
      {
       "number": 377,
       "title": "Logout messages, NameIDs and RelayState are recorded in request logs",
       "type": "Information disclosure",
       "severity": "Low",
       "status": "Mitigated",
       "description": "On the HTTP-Redirect binding a `LogoutRequest` — with its `NameID`, possibly an email address — and `RelayState` travel in the query string, which request tracing records.",
       "mitigation": "**Built (T23.2.4, 2026-10-04).** The W3 F4 request tracer (`RedactingRootSpanBuilder`) redacts every query value not on `KEPT_QUERY_PARAMETERS`; D-38 adds no SLO parameter to that list (`SigAlg`, an algorithm URI, was already a kept structural parameter: its value is recorded as received, which reveals nothing, and what it must be is T-370's rule, not this one's), and the handlers log no message, `NameID`, `RelayState` or cookie. Tests (T23.2.4): `saml_idp_slo_test.rs::the_request_log_records_no_message_parameter_of_slo` (the real `/slo` route through the tracer: `SAMLRequest`, `SAMLResponse`, `RelayState` and `Signature` are recorded as `[redacted]` and no value reaches the log) and, in `axiam-api-rest`, `middleware::request_span::tests::the_single_logout_parameters_are_redacted_and_none_was_added_to_the_kept_list`."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "4eb779bc-f741-50dc-898c-4cd860b2cab4",
     "path": "M824.5,872.1 L199,945.2",
     "name": "signed LogoutRequest / LogoutResponse (SP's slo_binding)",
     "description": "AXIAM's logout messages to each SP of the session, and the final response to the initiating SP — only to registered slo_url values; detached signature on Redirect, enveloped on POST.",
     "label": "signed LogoutRequest / LogoutResponse (SP's slo_binding)",
     "labelLines": [
      "signed LogoutRequest /",
      "LogoutResponse (SP's slo_binding)"
     ],
     "lx": 511.7,
     "ly": 908.7,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS (front channel)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "8d529853-83b0-5696-9f8a-d0872c14e3a8",
     "path": "M183.2,384 L836,824.8",
     "name": "IdP-initiated logout (/sso/logout, OP cookie)",
     "description": "The browser's own sign-out at AXIAM: same-site only, acting on the session its OP cookie names.",
     "label": "IdP-initiated logout (/sso/logout, OP cookie)",
     "labelLines": [
      "IdP-initiated logout (/sso/logout,",
      "OP cookie)"
     ],
     "lx": 509.6,
     "ly": 604.4,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "10587f12-ae62-5b32-aa7c-bb4acb8c4d4a",
     "path": "M956.1,896.2 L1086.9,964",
     "name": "resolve sessions by (SP, SessionIndex, NameID)",
     "description": "Map a verified request back to sessions; list the other SPs of those sessions; delete the rows when the run ends.",
     "label": "resolve sessions by (SP, SessionIndex, NameID)",
     "labelLines": [
      "resolve sessions by (SP,",
      "SessionIndex, NameID)"
     ],
     "lx": 1021.5,
     "ly": 930.1,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB (private network)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "3dc774a1-2785-5cb6-afe9-73808f2fd5a0",
     "path": "M961,884.4 L1269,978.1",
     "name": "hold / consume logout chain (X6)",
     "description": "Create the run with the request's replay key; consume each outbound request ID once when its response arrives.",
     "label": "hold / consume logout chain (X6)",
     "labelLines": [
      "hold / consume logout chain (X6)"
     ],
     "lx": 1115,
     "ly": 931.3,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB (private network)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "b77f0d5a-cdda-595a-9403-4517d88a7573",
     "path": "M943.5,913.5 L1124,1094",
     "name": "invalidate session + publish to revocation feed",
     "description": "AuthService::logout → SessionRepository::invalidate, after OIDC back-channel logout; the feed entry is written when the feed is enabled.",
     "label": "invalidate session + publish to revocation feed",
     "labelLines": [
      "invalidate session + publish to",
      "revocation feed"
     ],
     "lx": 1033.7,
     "ly": 1003.7,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB (private network)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "7919cd3f-7265-50a2-a0e3-85f4f52f24f1",
     "path": "M959.2,838.6 L1079,792.1",
     "name": "unseal active key (logout signing)",
     "description": "get_active_sealed for the two signing cases D-38 allows; the key decrypted into a zeroizing buffer only.",
     "label": "unseal active key (logout signing)",
     "labelLines": [
      "unseal active key (logout signing)"
     ],
     "lx": 1019.1,
     "ly": 815.3,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB (private network)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "b8fa4fa2-ba50-57fa-a281-9aeaca24d89c",
     "path": "M964,865.5 L1269,872.2",
     "name": "read SP (certificate, slo_url)",
     "description": "The verified issuer's registration: the certificate to verify with and the registered slo_url/slo_binding to send to.",
     "label": "read SP (certificate, slo_url)",
     "labelLines": [
      "read SP (certificate, slo_url)"
     ],
     "lx": 1116.5,
     "ly": 868.8,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB (private network)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "edf438c0-318e-5508-8865-782c1cecda5e",
     "path": "M761.1,884 L1079,978.7",
     "name": "record participant + per-SP SessionIndex",
     "description": "Written after the handle is consumed and before the assertion is signed (D-37); a failure issues nothing.",
     "label": "record participant + per-SP SessionIndex",
     "labelLines": [
      "record participant + per-SP",
      "SessionIndex"
     ],
     "lx": 920,
     "ly": 931.3,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB (private network)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "5dad8923-1903-5abd-afa5-748f475447bc",
     "path": "M764,865.1 L1269,872.7",
     "name": "read SP registration",
     "description": "Find the SP by Issuer within the path tenant; ACS allow-list, certificate and policy.",
     "label": "read SP registration",
     "labelLines": [
      "read SP registration"
     ],
     "lx": 1016.5,
     "ly": 868.9,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB (private network)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    }
   ],
   "total": 125,
   "open": 3,
   "notApplicable": 0,
   "bySeverity": {
    "High": 44,
    "Medium": 51,
    "Critical": 13,
    "Low": 17
   }
  },
  {
   "id": 4,
   "title": "Authorization engine — RBAC, hierarchy & scopes",
   "description": "The three authorization entry points (REST middleware, gRPC CheckAccess, AMQP async), the default-deny RBAC engine with explicit deny-override with resource-hierarchy traversal, the decision cache, and the graph and audit stores behind them. Organization-level principals are evaluated under an explicit SubjectScope claim: only global grants carry across a tenant boundary, and an ordinary tenant principal cannot express cross-tenant reach at all. Since 1.0.0-beta05 a role assignment can additionally name the tenants it reaches (tenant_scope), confining an organization-level account to particular tenants, and organization-level actions require an organization-scoped principal, not merely the permission.",
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
      },
      {
       "number": 193,
       "title": "Active-tenant header reaches across organization boundaries",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "An organization-level principal selects the tenant it is acting in with the X-Axiam-Tenant header. Accepted unverified, that header would let organization scope cross organization boundaries too — which is the one isolation an organization is.",
       "mitigation": "The header is verified to name a tenant inside the caller's own organization before any scope is derived, and the check fails closed: no tenant resolver registered means the header is refused (1.0.0-beta02). For an ordinary tenant principal the same header change is a 403 — CONTRACT §5.2 states the SDK-visible half: organization_level is derived server-side and response-only, and a tenant-switch helper may exist only where it is true. Since 1.0.0-beta09 the same resolution serves the `AuthenticatedPrincipal` extractor the authorization-check endpoints bind, through one implementation rather than a second copy (T-228)."
      },
      {
       "number": 202,
       "title": "Organization-level action authorized by permission alone, from the wrong scope within the organization",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "Organization-level handlers checked the permission and that the target organization was the caller’s own — a bar every principal in the organization clears — and a tenant’s seeded super-admin holds the entire permission registry. Signed in as an ordinary tenant administrator, creating organizations, creating tenants, generating CAs and — the serious one — flipping a CA’s mTLS trust-anchor flag all succeeded (B-04). The tenant administrator holds that CA’s private key, so it could mint certificates authenticating as principals in sibling tenants: the isolation boundary the product is built on, crossed from inside. The same shape recurred on POST /api/v1/mds/refresh (B-08), where a tenant administrator could rewrite the server-global FIDO attestation trust picture, and on /auth/me, which prefixed the * wildcard for any principal holding a role merely named super-admin (B-09), so the admin UI offered controls the server would refuse.",
       "mitigation": "Fixed in 1.0.0-beta05: require_organization_principal guards all sixteen organization-level handlers plus MDS refresh, keyed on where the caller’s record lives — principal_tenant_id resolving to the organization’s reserved scope — rather than on what its roles carry, deliberately not on AuthenticatedUser::organization_level, which is false for exactly the calls that needed guarding; it fails closed when the home tenant cannot be resolved. Reads are untouched. /auth/me emits the wildcard only when the same predicate resolves the caller into the organization scope, and drops it when the tenant cannot be resolved — a control hidden from someone who could use it is the cheaper mistake than one offered to someone the server refuses. Pinned by paired tests in both directions and by the E2E permission matrix run against the production image."
      },
      {
       "number": 205,
       "title": "Deployment-wide rosters answer a principal whose reach is one tenant",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "GET /api/v1/organizations returned every organization in the deployment to any principal holding a super-admin role — a role seeded per tenant — so one customer’s tenant administrator could enumerate the name and slug of every other customer in the same installation. Inside one organization, GET /organizations/{id}/tenants showed the whole tenant roster to every holder of tenants:list (W5-03): names, slugs and creation dates of sibling workspaces that the isolation boundary exists to hide from a confined administrator.",
       "mitigation": "Fixed in 1.0.0-beta05: the organization listing returns the caller’s own organization and nothing else — the rule the by-id endpoint already applied. The tenant roster is filtered to the caller’s reach: a tenant administrator sees its own tenant, a restricted organization principal the tenants its assignments name (dangling ids silently dropped), an unrestricted one the whole roster — the reserved organization scope included, because an organization administrator acts on it and filtering it out server-side would put it beyond the API; the admin console drops it where offering it would be wrong. The permission question is asked in a tenant the caller actually reaches, so a confined account can read the one list that says which tenants it administers, and the cross-organization refusal is answered before the reach check so the error names the right reason instead of describing an organization that is not the caller’s."
      },
      {
       "number": 228,
       "title": "Two request extractors resolve the acting tenant separately, and one of them skips the reach check",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "The authorization-check endpoints are the only ones that bind `AuthenticatedPrincipal` rather than `AuthenticatedUser`, and the two extractors had a field of the same name meaning different things: `AuthenticatedUser::tenant_id` is the tenant being acted upon, resolved from the `X-Axiam-Tenant` header through the organization-reach check (T-193, T-204), while `AuthenticatedPrincipal::tenant_id` was the raw claim — the caller's own tenant. The visible symptom was fail-closed: every effective-access preview an organization-level administrator ran was evaluated in the organization's own tenant, where the subject being asked about has no assignments, and answered `no roles assigned` against a correct rule set. The structural hazard is worse than the symptom. The reach check is the only thing standing between \"acting on another tenant\" and \"asserting another tenant's grants\", and a second copy of it — or, as here, a second extractor with none — is exactly how the guard drifts on one path and not the others. The handler also hard-coded `SubjectScope::Tenant`, which is right for a checked-as subject (an ordinary member of the tenant being acted upon) and wrong for an organization principal asking about its own access, whose roles live in its own tenant.",
       "mitigation": "Fixed in 1.0.0-beta09. `AuthenticatedPrincipal` resolves the acting tenant exactly as `AuthenticatedUser` does — same header, same tenant lookup, same reach check, same refusal when the caller's own tenant is not the organization scope — through one implementation, `resolve_active_tenant_for`, keyed on the home tenant id, so there is one copy of the check and both extractors run it. The session-revocation check keeps reading the principal's own tenant and still runs before the header is applied, which is where the session row lives. Both call sites pick the subject scope rather than hard-coding it, and the `authz:check_as` guard reads the caller's grants through `subject_scope()` for the same reason — with the fixed scope it looked for the permission in the wrong tenant and would refuse a caller that holds it. Only `authz_check.rs` binds this extractor, so the blast radius was the two check endpoints; a regression test pins the tenant a check is evaluated in."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
       "status": "Mitigated",
       "description": "The engine is allow-wins with default deny and no explicit deny. A role granted on a parent resource cascades to every child and cannot be revoked on one child alone.",
       "mitigation": "SEC-040 — closed (B1). The engine now supports explicit deny: a grant carries effect: \"allow\" | \"deny\", and a deny overrides every allow, at any depth of the resource hierarchy and at equal specificity (deny-override, not most-specific-wins). Adding a deny rule can never widen access and can never be undone by adding allows — asserted by an exhaustive property test. Modelling exclusions by granting lower in the hierarchy remains valid but is no longer the only option. See claude_dev/deny-override-design.md for the precedence table and the scope-interaction rules. Amended 2026-09-22 (T22.11, DF-021): an assignment can also be made non-inheritable — inherit: false on the has_role edge — so a role granted high in the hierarchy can be stopped at its node instead of cascading to every child (\"here and no further\"), for allows and denies alike. Precedence is unchanged: the flag decides which assignments are applicable at a resource, never how deny-override weighs them (deny-override-design.md §2.2 rows 9–11). The flag's own hazards are T-285."
      },
      {
       "number": 190,
       "title": "Cross-tenant reach granted by inference rather than by claim",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "AccessRequest carried subject_tenant_id: Option<Uuid>, and the engine treated two tenant ids differing as authority to read a subject's grants across the tenant boundary. Any caller that built a request for a subject in tenant A about tenant B got cross-tenant reach for free, so an ordinary global admin role applied in every tenant of the deployment — the exact opposite of what a tenant is.",
       "mitigation": "Fixed in 1.0.0-beta02: SubjectScope names the claim. Tenant is every ordinary principal and pins the assignment tenant to the target, so a tenant principal cannot express cross-tenant reach at all, whatever tenant it names. Organization is a statement a caller has to make deliberately — no combination of ordinary values produces it — and its sole production producer is the REST extractor, which resolves the tenant record and checks it is the organization's reserved scope before setting the flag. organization_scope_test asserts both properties directly, plus the case the fix must not break: an organization-level principal acting on the organization tenant still gets resource-scoped evaluation there."
      },
      {
       "number": 191,
       "title": "Organization-scoped resource grant honoured against a look-alike resource in another tenant",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "An organization-level principal's resource-scoped assignment names a resource in the organization's reserved tenant. A same-named resource in a member tenant is a different thing, and honouring the assignment against it would be a silent escalation between isolated tenants.",
       "mitigation": "One rule, stated once in AuthorizationEngine::evaluate (1.0.0-beta02): when a subject's grants are read across a tenant boundary, only global grants carry. check_access_batch applies the identical rule through the same helper, so a batched decision stays byte-identical to a per-item one. Deny override, scope narrowing and group inheritance are unchanged. Access is derived at check time rather than fanned out at tenant creation, so a tenant created later is governed by the same rule with no backfill, and revoking the organization role revokes everywhere because there is only one copy."
      },
      {
       "number": 204,
       "title": "A tenant-scoped role assignment enforced on some paths and not others",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "1.0.0-beta05 adds tenant_scope to role assignments (schema 51 — additive, no backfill, every existing assignment stays unrestricted): an organization-level account can be confined to particular tenants of its organization. A restriction is only as strong as its weakest enforcement point — a path that forgot the filter (the batch engine, an organization-level endpoint that names no tenant, the X-Axiam-Tenant switch, the tenant roster) would leave a confined administrator estate-wide reach through that one door. Two subtleties invited exactly that: the batch path shares one cached assignment vector across items naming different tenants, and the filter must compare against the tenant being acted on rather than the tenant the grants live in — which for this principal is the organization tenant every time, making every restriction vacuous.",
       "mitigation": "tenant_scope_reaches is written once in axiam-core and read by every consumer, so the engine, /auth/me and the tenant listing cannot drift apart on the rule. Enforced at four sites: the engine’s single and batch paths (the batch filter applied per item against each request’s tenant), require_organization_principal (an action naming no tenant is refused to a restricted account, with a reason naming the restriction), require_organization_principal_for_tenant for organization actions that name one tenant, and the header resolver refusing X-Axiam-Tenant for any tenant outside the account’s reach. Holding no roles is Unrestricted rather than confined-to-nothing, so the permission check refuses for the right reason; one unrestricted assignment makes the whole set unrestricted; an empty scope cannot be created; accepted scopes are deduplicated and sorted so equal grants store identically. /auth/me reports reachable_tenant_ids and withholds the * wildcard from a restricted principal (CONTRACT §5.2.3, contract 1.35). Pinned by engine property tests, a 14-case REST suite and a dedicated E2E matrix principal."
      },
      {
       "number": 226,
       "title": "An upgrade turns dormant unscoped role assignments into live tenant-wide grants",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "Before 1.0.0-beta09, assigning a role to a user or group without naming a resource granted nothing, anywhere, unless the role also carried `is_global`: the write succeeded, the assignment listed back correctly, and every check against it answered \"no applicable roles for this resource\" — which reads as though the resource were at fault rather than the assignment being inert. That contradicted the meaning the model gives the field in three places: `AssignmentScope::global()` is named for it, and both `AssignmentScope::resource_id` and `RoleAssignment::resource_id` document `None` as \"every resource in reach\". Two hazards follow. An operator who scoped a grant, saw no access, and removed the scope to widen it got the same refusal with nothing anywhere to say why — the pressure that produces global roles and over-broad grants. And once the engine honours the field, every assignment written into the inert state becomes a live tenant-wide grant at the moment of upgrade, with nobody having decided that.",
       "mitigation": "Fixed in 1.0.0-beta09. `applicable_role_ids` now treats an assignment naming no resource as tenant-wide, which is what the field has always been documented to mean; `is_global` keeps its own, independent meaning as a property of the role, so a global role still applies even when the assignment does name a resource — two ways to say \"everywhere\", both honoured. Tenant-wide, not organization-wide: `global_role_ids`, the path an organization-level principal takes across a tenant boundary, is deliberately unchanged, so an unscoped assignment in an organization's own tenant does not reach every tenant of that organization, and the organization-scope tests pin that boundary. Two regression tests reproduce the report that found this, one per half; the scoped half already passed and is kept because it proves groups, hierarchy cascade and scoped grants were never the problem. The upgrade hazard is handled as an upgrade note in `docs/admin/README.md`: what changes, and how to find assignments sitting in the inert state so an administrator reviews them before the upgrade makes them live. The effective-access preview in the admin UI now lists the tenant's own permissions rather than a hard-coded read/write/delete/admin vocabulary, and says so when the action typed matches none of them, so an administrator debugging a grant is no longer offered an action that does not exist."
      },
      {
       "number": 227,
       "title": "Scope inheritance down the hierarchy widens a grant to sibling or unrelated resources",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "A `Scope` belongs to exactly one resource and scope names are unique per resource — the auto-seeded name embeds the resource id precisely so two levels do not collide — so a parent's `billing` scope and a child's are always different records. Before 1.0.0-beta09 both halves of the engine compared them by id: `grant_applies` required the requested scope id to appear in the grant's `scope_ids`, so a grant written on a parent's scope matched nothing below it (reported as \"no permission grants action\", as though the permission were missing), and `resolve_scope` looked a name up only on the target resource, so asking about a scope the resource inherits was refused as malformed. Making scopes inherit down the lineage is the correct semantics, and it carries the hazard the fix has to avoid: reading \"the requested scope is not one of my scopes\" as \"therefore unconstrained\" would turn every scoped grant in the tenant into a wildcard on every other resource, and inheriting sideways would let a grant on `billing` reach `payroll` beside it. An authorization answer that depended on the order ancestors happen to be returned in would be a second, quieter defect.",
       "mitigation": "Fixed in 1.0.0-beta09. A grant naming a scope constrains the resource that scope lives on, and below it the grant is inherited whole — every scope of every descendant — until a deny says otherwise; denies inherit by the same rule, which is what makes a scoped deny on a parent a way to carve a subtree out of a broad grant. Two things deliberately do not widen, each pinned by a test: on the scope's own resource the constraint still bites (a grant on `billing` does not reach `payroll`), and a scope on an unrelated resource still grants nothing. Name resolution is nearest-first over the lineage — the resource's own scope beats an ancestor's of the same name, a nearer ancestor beats a further one — and the batch path keeps that order alongside the id set it already had, because an authorization answer that depends on row order is not an answer. `ScopeRepository::list_by_resources` reads the whole lineage in one bound-array `IN` query, the same shape as the `has_role` and `grants` reads, and `lineage_scope_lookup_is_index_satisfied` pins that `idx_scope_resource_name` serves it, so the correct semantics did not buy an unindexed scan on the hot path. The coalesced batch path mirrors all of it, and `batched_decisions_match_per_item_decisions_across_scopes` holds the two paths to the same answers."
      },
      {
       "number": 285,
       "title": "A non-inheritable role assignment reaches further, or less far, than it reads",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "DF-021 asked for a role assignment that applies at its resource and not below it. inherit: false on the has_role edge does that, and it can go wrong three ways. It can be honoured on one path and not another: the engine decides through evaluate and, for batches, evaluate_batch, and an assignment reaches a subject through two different SELECTs — direct and group-inherited — so a flag read on one of them leaves a non-inheritable allow cascading to every descendant on the other, and deny-override-design.md §5.1 records that exactly this class of regression in applicable_role_ids leaves every evaluator unit test green. It can be stored where the engine ignores it — an assignment naming no resource, or one of an is_global role — so an operator believes access stops at a node when it does not. And it moves access in both directions: false on an allow narrows, but false on a deny re-opens every descendant the deny covered, so a silent in-place toggle, or one a decision cache does not see, would widen access with nobody reviewing it.",
       "mitigation": "T22.11 (2026-09-22). One clause in applicable_role_ids — the assignment's own resource always applies, an ancestor's only when inherit is true — shared by evaluate and evaluate_batch; the repository reads the field in both the direct and the group-inherited SELECT and in every assignment listing. Schema v66 adds it as option<bool> with no backfill, and absent reads as true, so every existing assignment and every client that does not send the field keeps its meaning. The three assign routes (user, group, service account) refuse inherit: false with 400 when no resource_id is named and when the role is global, each with an I4 twin that the same request without the field, or with true, is accepted. There is no update: has_role is UNIQUE(in, out), so changing the flag is an unassign and an assign, each of which invalidates the subject's cached decisions (the tenant's, for a group), and the grant.pre_assign four-eyes hook payload carries inherit. Property tests over every rule set of a three-node chain: adding a deny never widens access whatever its flag; false on an allow never widens; false on a deny can, with row 10 as the asserted witness. Rows 9–11 are proved end to end through both evaluate and evaluate_batch, for a group-inherited assignment, and over gRPC CheckAccess and BatchCheckAccess; the clause was broken on purpose (the inherit guard alone, then the whole ancestor term) and the new tests went red both times. Residual, documented: making a role global after assigning it non-inheritably widens that assignment to everywhere, as it widens every assignment of the role. Amended 2026-09-23 (T22.11b, S-10b): the admin console offers the flag only where the server would store and apply it (a resource chosen, a role that is not global) and changes it as the same unassign then assign, restoring the old assignment when the second call is refused and saying in so many words when even the restore fails; the console decides nothing the three assign routes do not decide again. Saving a role as global while it has non-inheritable assignments now opens a confirmation that names them and the widening; the residual stands (the server accepts the change by design), and the console no longer lets it happen unannounced."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
      },
      {
       "number": 192,
       "title": "Revoked organization-level role survives in other tenants' decision caches",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "The decision cache shards by the tenant a decision was about, while an organization-level principal's roles live in exactly one tenant. Invalidating only the shard of the tenant the mutation happened in would leave a freshly revoked administrator holding cached allows in every other tenant until the TTL expired.",
       "mitigation": "invalidate_subject sweeps every shard (1.0.0-beta02); a subject id is unique across the deployment, so the sweep removes exactly that subject's entries and nothing else. SubKey carries subject_tenant_id, so cache-key correctness does not depend on a subject's home tenant being fixed."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
      },
      {
       "number": 203,
       "title": "Seeded tenant roles carry organization-level actions the guard has to refuse",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "After B-04’s scope guard landed, every tenant’s seeded super-admin still held ca_certificates:manage, organizations:create, tenants:delete and the rest — the grant data and the guard disagreed, and only one of them was saying no. Grants the API must never honour sitting in the graph are a standing hazard: any future handler registered without the scope guard, or any consumer trusting the stored edges, re-opens B-04 from the data side.",
       "mitigation": "Fixed in 1.0.0-beta05: ORGANIZATION_LEVEL_ACTIONS in axiam-core is the single nine-action, exact-match list both layers read. The seeder withholds those actions from an ordinary tenant’s super-admin and admin roles, and the reconciler learned to revoke — deliberately narrow: only the three seeded default roles, only the listed actions, only outside the organization scope, with a WARN naming each tenant it touches, so an operator’s own custom grants are never swept. The invariant — an action can be withheld only if every handler requiring it is scope-guarded — is enforced by a consistency test that reads the handler sources and fails in both directions; email_config:write is deliberately excluded because it also guards a tenant’s own mail configuration. Operational note: on the first boot after upgrade the revocation removes grants the scope guard was already refusing, so no working call stops working."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
       "mitigation": "Messages carry an HMAC signature over the payload that the consumer verifies before evaluating; the broker connection is TLS-only — AXIAM__AMQP__URL must be amqps:// and every other scheme is refused before a socket is opened, in a debug build exactly as in a release one, with the AXIAM__AMQP__ALLOW_PLAINTEXT escape hatch removed."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
    }
   ],
   "total": 27,
   "open": 0,
   "notApplicable": 0,
   "bySeverity": {
    "Critical": 6,
    "High": 14,
    "Medium": 7
   }
  },
  {
   "id": 5,
   "title": "PKI, certificates & IoT device identity",
   "description": "Organization and tenant CA lifecycle with per-CA key custody (sealed database row or Vault), tenant signing CAs beneath the organization CA, tenant certificate issuance with policy enforcement, mTLS device and workload authentication with full chain verification against hot-reloadable trust anchors, revocation by certificate status (AXIAM publishes no CRL and runs no OCSP responder, T-102), and the OpenPGP key service used for audit signing and GDPR export encryption. Extended for X3 with FIDO MDS3 metadata ingestion (BLOB trust-chain verification, rollback protection, staleness posture) feeding the WebAuthn attestation policy engine.",
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
     "open": 0,
     "notApplicable": 0
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
     "open": 1,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "description": "Organization and tenant CA lifecycle: generate, upload, rotate and revoke; tenant signing CAs created beneath the organization CA or signed from a PKCS#10 CSR; per-CA key custody with migrate-custody between database and Vault; organization CAs flagged as mTLS trust anchors.",
     "outOfScope": false,
     "threats": [
      {
       "number": 95,
       "title": "CA private key exfiltration",
       "type": "Information disclosure",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "The signing CA key allows forging any tenant, user, service or device identity in the organization.",
       "mitigation": "User-generated CAs are returned once and never stored. Only signing CAs whose key AXIAM must hold are persisted, and those are AES-256-GCM encrypted at rest in a separate, access-controlled table with the key held outside the datastore. Since 1.0.0-beta01 custody is recorded per CA and may instead be Vault — vault holds the sealed key, vault_pki has Vault hold a key it never hands over — the configured Vault is inherited for new keys, and an explicit database choice beside a working Vault is a startup warning naming the exposure (see T-196, T-197)."
      },
      {
       "number": 96,
       "title": "Weak key material from poor entropy",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "A CA or leaf key generated from a weak source is factorable or predictable, silently invalidating the whole hierarchy.",
       "mitigation": "Key generation uses the platform CSPRNG — Ed25519 through rcgen/ring, RSA-4096 through the rsa crate's OS-seeded generator handed to rcgen as PKCS#8, since ring deliberately implements no RSA key generation (1.0.0-beta01). No custom or seeded RNG is used anywhere in the PKI path."
      },
      {
       "number": 194,
       "title": "Tenant CSR signed into an unconstrained CA, or onto a key the requester does not hold",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "The tenant signing-CA endpoint signs a PKCS#10 request whose key was generated elsewhere. Honouring the request's own extensions would let a caller mint an unconstrained CA; skipping verification of the request's self-signature would mint a CA certificate for somebody else's public key.",
       "mitigation": "The CSR's subject is honoured; its requested extensions are not — AXIAM states CA:TRUE, path length zero and keyCertSign/cRLSign itself, so a request that asked to be an unconstrained CA does not become one (1.0.0-alpha44). from_pem verifies the request's self-signature as proof of possession. The parent must be unexpired, unrevoked, key-holding and not itself tenant-scoped — refused up front rather than downstream — the intermediate's validity is capped to the parent's expiry, and the row records custody External because AXIAM never held the key."
      },
      {
       "number": 197,
       "title": "Custody migration destroys the only copy of a CA signing key",
       "type": "Denial of service",
       "severity": "High",
       "status": "Mitigated",
       "description": "Migrating a CA's key from Vault into database custody wrote custody = database beside an emptied key column, then released the Vault copy — and returned Ok. The CA row claimed to hold a key it did not have, the key it named was gone, and no backup of the row helps, because the row never contained the key. That CA could no longer sign anything.",
       "mitigation": "Fixed in 1.0.0-beta02: the repository writes the ciphertext it is given in the same single statement that records the custodian, so the Vault→database direction carries the key and the database→Vault direction still clears the column — clearing is now the caller's decision, not the repository's assumption. The operation orders copy, record, then release, so a failure before the record leaves the CA exactly as it was. Five integration tests drive the real Vault key store against a mock HTTP server, including that a migrated-back key still decrypts and equals the one Vault handed over."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
       "mitigation": "max_certificate_validity_days is an org/tenant setting, and the hierarchical settings rule means a tenant can only make it stricter, never longer, than the organization baseline. Since 1.0.0-beta01 issuance also refuses a validity that would outlive the issuing CA and quotes the achievable number, rather than silently truncating to the issuer's notAfter — a truncation that left renewal calendars built on a date the certificate does not carry."
      },
      {
       "number": 98,
       "title": "Certificate issued for another tenant's subject",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "Issuing under a subject belonging to a different tenant would produce a credential that authenticates across the isolation boundary.",
       "mitigation": "Issuance is tenant-scoped from the authenticated context, and the signing CA is resolved from the requesting tenant's organization — a cross-tenant subject cannot be signed. Tenant signing CAs (1.0.0-alpha44) narrow the blast radius further: issuance for a tenant is anchored at that tenant's path-length-zero intermediate, so a compromised or misused issuer is revocable without touching any other tenant."
      },
      {
       "number": 99,
       "title": "Returned private key persisted in logs or audit records",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "The generated private key is returned once in the API response; if it reaches a log line or an audit payload it becomes durably stored in the clear.",
       "mitigation": "Key material is excluded from audit payloads, and secret-bearing types carry manual Debug implementations so they cannot reach a trace or error line (SEC-067 / SECHRD-09)."
      },
      {
       "number": 195,
       "title": "One tenant's compromised issuance burns the organization trust anchor",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "When every tenant's user, service and device certificates issue straight from the organization CA, a compromised issuance path in one tenant is the whole estate's problem: the anchor is long-lived, widely distributed and painful to replace, and rotating it is a coordinated change at every relying party.",
       "mitigation": "Tenant signing CAs (1.0.0-alpha44): an intermediate created beneath the organization CA, constrained to a path length of zero, named as issuer_ca_id when issuing for that tenant, its key held by the configured custodian — Vault where configured, even when the parent's key predates Vault adoption. Revoking it revokes exactly one tenant's issuance. Under vault_pki the signing chain deliberately reaches past the path-length-zero issuing intermediate to the root, because signing from the issuing intermediate would produce certificates Vault accepts and every chain validator rejects."
      },
      {
       "number": 268,
       "title": "Leaf CSR signed with the requester's extensions, a weak key, or onto a key the requester does not hold",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "POST /api/v1/certificates/sign-csr issues an end-entity certificate over a public key supplied by the caller. Three things a naive implementation gets wrong: it signs a request whose signature it never checked, minting a certificate over somebody else's public key; it honours the extensions the request asks for, so a CSR saying CA:TRUE and keyCertSign becomes a CA that can sign anything under the tenant's trust anchor; and it records the key algorithm the caller states rather than the one the key is, so an RSA-2048 key is signed and written down as Rsa4096 (the leaf twin of T-194, and T-96 on the leaf path).",
       "mitigation": "C-1 (2026-09-13): ca::inspect_csr parses the request once, verifies its self-signature before anything else — the only proof the sender holds the matching private key — and reports the subject, the key and the requested extensions from that single parse. The key must be Ed25519 or RSA with a measured modulus of at least 4096 bits; the label KeyAlgorithm::Rsa4096 is never taken on trust, which is what closes T-96 here. A CSR requesting subjectAltName, keyUsage or extendedKeyUsage is refused by name rather than silently stripped, and every other requested extension is discarded when rcgen's parameter set is overwritten with the shared leaf_params — the same function CertService::generate builds a generated leaf from, so the two paths cannot issue different shapes. basicConstraints needs no rule: the in-process path overwrites it and Vault ignores it outright, so a CSR asking to be a CA comes back a leaf on both. Under vault_pki custody the refusal of keyUsage and extendedKeyUsage is load-bearing rather than cosmetic: Vault's sign-verbatim discards the key_usage and ext_key_usage request parameters whenever the CSR carries those extensions and issues what the CSR asked for, so a silent strip would be a promise AXIAM keeps on one custodian and breaks on the other. Having refused them, the Vault request body states both as empty so the shape is AXIAM's decision and not a Vault default. Amended 2026-09-23 (T22.14): the body now states the per-type usage profile rather than empty lists, on both leaf paths, and exclude_cn_from_sans; what Vault does with it was observed against Vault 1.18.3 rather than taken from its documentation — key_usage and ext_key_usage apply when the CSR requests neither, and SANs are read from the CSR only. The issuer, the tenant scope and the validity come from the same prepare_leaf_issuance the generate path uses. No private key exists on this path, so the response type has no field for one. Twenty tests in sign_csr_test.rs, three against a Vault mock in vault_pki_test.rs, four at the HTTP layer, and one in mtls_test.rs proving a CSR-signed device certificate binds and authenticates exactly like a generated one."
      },
      {
       "number": 281,
       "title": "A tenant administrator issues a leaf under another tenant's signing CA, or directly under the organization anchor",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "Both leaf paths resolve the issuing CA through prepare_leaf_issuance, which fetched it with ca_repo.get_by_id(org_id, issuer_ca_id) — a query whose only scope is WHERE organization_id = $org_id — and never read ca_certificate.tenant_id, the column that records which tenant a signing CA signs for. Every CA of the organization was therefore reachable by every principal of the organization holding certificates:generate: a sibling tenant's signing CA, and the organization-level CA that is the trust anchor for the whole estate. The issued leaf was written with the caller's own tenant_id and the other tenant's issuer_ca_id, and chained to the root every relying party in the organization trusts — so a certificate minted in tenant A authenticated as a principal of tenant B against anything that verified the chain rather than the row. It is the isolation boundary the product is built on, crossed from inside by an ordinary tenant administrator, and it needed no bug in the caller: the API accepted the CA id and answered 201. This is the gap T-98 recorded as closed: its mitigation claimed issuance for a tenant was anchored at that tenant's intermediate, which tenant signing CAs made possible in 1.0.0-alpha44 and nothing made compulsory. The axiam-domo-demo dogfooding run reproduced it at runtime and rode the resulting certificate to a full MQTT session (DF-017, DF-025).",
       "mitigation": "S-1 (2026-09-22): prepare_leaf_issuance takes the tenant being acted on and an IssuingScope resolved from the caller's own record, and matches the CA against both immediately after the lookup — ahead of the status and validity-window checks, so a refusal cannot be used to learn that a CA exists, is revoked or has expired. A tenant signing CA is usable only by a caller acting on that tenant; an organization-level CA is usable only by a principal whose own record lives in the organization's reserved scope, resolved in the REST layer by the same residence test require_organization_principal uses and never from AuthenticatedUser::organization_level, a flag that is false for exactly these calls. The refusal is NotFound, following the cross-organization precedent a_ca_in_another_organization_is_not_found. One site covers both custodians: the check precedes custodian resolution, so the Vault path is bound by it too. Nine tests — five in sign_csr_test.rs including a_foreign_ca_is_not_found_even_when_it_is_revoked, which pins the ordering, and four generate twins in cert_test.rs — plus the end-to-end twin in axiam-api-rest's certificate_test.rs next to the cross-organization one. Certificates already issued across the boundary are not revoked on upgrade; docs/pki/README.md carries the reach table and the operator's remediation path."
      },
      {
       "number": 288,
       "title": "A tenant administrator mints a certificate for a name that is not theirs",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "AXIAM could not issue a certificate a TLS server can present (DF-001): leaves carried no subjectAltName and neither leaf request had a field for one, so every listener in a deployment anchored in the organization root was signed offline. Closing that gap creates the threat: a leaf carrying subjectAltName DNS:login.example.com, signed by a tenant signing CA under the organization root, is trusted by every relying party that trusts that root — browsers, gateways, MQTT clients — so a tenant administrator holding certificates:generate could mint a server certificate for a name that is not theirs: another tenant's host, the organization's own apex, or any public name, and impersonate it to every client of the organization. The same reach existed in a quieter form before this change: a leaf carried no extendedKeyUsage, which X.509 reads as any usage, and under vault_pki custody sign-verbatim would copy whatever SANs a CSR AXIAM built carried.",
       "mitigation": "T22.14 (S-7, 2026-09-23). A fourth certificate type, Server, is the only one that may carry SANs, and they come only from an explicit subject_alt_names request field — a CSR that requests a subjectAltName is still refused (inspect_csr), so nothing a caller's CSR says reaches the SAN list. Every SAN and the common name must be admitted by the tenant's effective server_cert_allowed_names: DNS suffixes (strictly below, on label boundaries), exact hosts and IP prefixes, case-insensitive, with trailing dots, Unicode labels, partial wildcards and IPv4-mapped IPv6 refused. The list is written in the organization baseline, is empty by default, and empty refuses every Server request. It rides the settings interlock every other override uses: a tenant may remove or narrow an entry and a widening one is a 400 at write time; when the baseline later shrinks, the effective list is the intersection, computed on every read, so a tenant never keeps a withdrawn name nor gains one it had removed. The fence runs before the issuing CA is looked up, on both leaf paths and both custodians. Under vault_pki custody the admitted names travel inside the CSR AXIAM builds, because sign-verbatim ignores alt_names and ip_sans (observed on Vault 1.18.3), and a caller-CSR Server request is refused because no channel for its names exists. Every leaf now carries a per-type profile — clientAuth for User, Service and Device, serverAuth for Server, keyEncipherment for RSA only — so a Server leaf fails the clientAuth check of the REST and gRPC client-certificate verifiers (InvalidPurposeContext), bind refuses it with 400 and device login refuses it. Tests: the matcher and interlock unit tests in axiam-core, two repository tests of the stored baseline and its shrinking, generate and sign-csr twins in cert_test.rs and sign_csr_test.rs (issued leaves parsed, the profile table for every type and key), four Vault twins, the bind and wire-level settings tests in axiam-api-rest, and a browser-shaped acceptance in axiam-server: a rustls client trusting only the organization root completes a handshake with an actix listener presenting the issued leaf, and fails for a name the leaf does not carry. Nine deliberate mutations of the fence each turned a named test red. Residual, recorded as decision D-7: the fence is AXIAM's and is not embedded in the tenant CA as X.509 nameConstraints, so a relying party trusts the chain for any name AXIAM was made to sign; a compromised AXIAM or a Vault token used outside AXIAM is not bounded by it. Embedding it would make every policy change a CA re-issuance and is deferred to the next PKI pass."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
      },
      {
       "number": 198,
       "title": "Revoked or unflagged CA lingers in the mTLS trust-anchor bundle",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Flagging an organization CA as an mTLS trust anchor exports its public certificate into the bundle rustls verifies client certificates against. A bundle that is not rewritten when a CA is unflagged or revoked leaves an anchor on disk that the live verifier — and every later restart — would still trust, so certificates chaining to a withdrawn CA keep authenticating.",
       "mitigation": "The trust-anchor reload rewrites the entire flagged set every time (1.0.0-beta01/beta02): unflagging removes an anchor, emptying the set empties the bundle rather than leaving stale anchors a reboot would trust, and the hot reload swaps the live verifier without a restart. Only public certificates are exported — the signing key is never copied. Client verification stays optional, so flagging a CA cannot lock every browser out of the admin UI, and an operator's own CLIENT_AUTH / CLIENT_CA_PATH configuration is never overridden by the convenience."
      },
      {
       "number": 206,
       "title": "Certificate chaining to a CA never enabled as a trust anchor authenticates on the proxy path",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "A certificate issued under an organization CA that was never flagged as an mTLS trust anchor authenticated successfully at POST /api/v1/auth/device (B-06). On the native-mTLS listener rustls enforces the flag, because the client-CA bundle is built from exactly the flagged anchors — but on the proxy-terminated path, the one docker-compose.prod.yml and the Kubernetes manifests actually use, nothing consulted mtls_trust_anchor: every Active CA in the organization was as good as every other, and un-flagging a CA — the documented way to stop trusting it — changed nothing. The “flat hierarchy” assumption this rested on had been stale since tenant signing CAs made intermediates real.",
       "mitigation": "Fixed in 1.0.0-beta05: require_trust_anchor runs on every device authentication, before the service-account binding. It walks up parent_ca_id until it reaches a CA flagged as an anchor — a walk, not a test of the immediate issuer, because a tenant signing CA is deliberately an unflagged intermediate — requires every CA on the way to be Active and inside its validity window (an anchor reached through a revoked intermediate is not reached), and bounds the walk at depth 8, because parent_ca_id is data and data can describe a cycle. Each refusal names its reason distinctly. The decisive test presents a bound, otherwise-valid certificate from an unflagged CA, so the refusal can only be about trust — the first draft presented an unbound one and passed for the wrong reason, which is recorded so the next assertion is written with one reason to succeed."
      },
      {
       "number": 263,
       "title": "Accepting an unchained certificate for RFC 8705 §2.2 lets a self-minted certificate authenticate as a device or as a `tls_client_auth` client",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "A `self_signed_tls_client_auth` client could never open a connection: `ReloadableClientCertVerifier` delegated to webpki, whose job is chain-building, and an RFC 8705 §2.2 certificate is self-signed by design — it chains to nothing, because the method identifies a client by the `x5t#S256` an administrator registered rather than by an issuer — so rustls sent `bad_certificate` before AXIAM saw a request (34 of 37 FAPI modules `INTERRUPTED` with no HTTP status). RFC 8705 puts two trust models under one transport: §2.1 is PKI, the identity a name a CA vouched for; §2.2 has no PKI in it, the certificate *is* the credential, and adding an issuer to the bundle cannot answer it. The hazard is in the fix: once the listener admits an unchained certificate, device and IoT authentication — whose entire model is chaining to a CA an administrator flagged as a trust anchor, the native-listener twin of B-06 — must not accept one, and a `tls_client_auth` DN match without a chain requirement makes `openssl req -subj \"/CN=<whatever was registered>\"` the entire attack.",
       "mitigation": "2d4cb59, four layers, and the third and fourth are where the safety is. (1) `ClientAuth::OptionalSelfSigned`, spelled `optional_self_signed`, a fourth policy: `off`, `optional` and `required` are byte-for-byte unchanged, every new branch is gated on `accepts_self_asserted()`, which only this variant answers true to, and the new behaviour is reachable only through a value no deployment sets today — which is what makes it non-regressive rather than merely tested. (2) The verifier tries webpki and, under the new policy only, accepts on failure, with an explicit `not_before`/`not_after` check on that branch because webpki performs the validity check as part of chain building and the path that skips chain building would silently lose it, for exactly the clients nobody else vouches for; the self-signature is deliberately not verified, since under §2.2 the identity is the SHA-256 of the DER and possession is proven by TLS 1.3's `CertificateVerify`, which rustls checks whether or not a chain was built. (3) `CertTrust::{ChainedToAnchor, SelfAsserted}` travels from the handshake to every consumer, on `VerifiedClientCert` and `PresentedCertificate` — an enum rather than a bool, **required** rather than defaulted, because a default would have handed the privileged value to any future call site that said nothing; it lives in `axiam-core` because the layering gate refuses the outward edge, and it is re-derived in the `on_connect` hook via `tls::peer_certificate_trust` because rustls's `ClientCertVerified` is an opaque token with no payload and the verifier is handed no connection handle to key a side channel on. (4) Only the one method specified to work this way may consume the weaker level: device/IoT certificate auth **refuses** `SelfAsserted` outright — rather than by falling through to the header branch, whose error text would advise setting `TRUST_FORWARDED_CLIENT_CERT`, advice that would widen a different trust boundary while chasing this one; `tls_client_auth` (§2.1) now **requires** `ChainedToAnchor`, a no-op until this commit and a real guard now that the invariant is configurable; `self_signed_tls_client_auth` (§2.2) accepts either, since the thumbprint comparison is the authentication and is no weaker for the certificate having also chained. Net effect: an unchained certificate can do exactly one thing — authenticate as a client whose exact SHA-256 an administrator registered — and every other path treats it as though the handshake had carried no certificate at all. A second listener for §2.2 was rejected: the per-client decision happens at the application layer either way, so an extra port buys only another listener to operate. The tests pin the operator-facing contract: a DN that *matches* is refused unchained with the chained case as a control on the same certificate; the §2.2 acceptance test computes the thumbprint the way an administrator does rather than reading it back off the value under test; the four documented policy strings are hard-coded; a real rustls TLS 1.3 handshake through `build_rustls_server_config` rejects the certificate under `optional` and accepts it under `optional_self_signed`; expired, not-yet-valid and non-certificate bytes are each refused."
      },
      {
       "number": 282,
       "title": "The one auth endpoint that performs a client-certificate handshake has no rate limiter",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "POST /api/v1/auth/device was registered as a bare route in axiam-api-rest's server.rs — no build_governor, no RateLimitShared — while every neighbouring auth resource carried both layers: /auth/login, the three OPAQUE routes, the six WebAuthn ceremony routes and the federation sign-in routes. The endpoint is in PUBLIC_PATHS and is CSRF-exempt, both of which it has to be, because a device holds no session and no cookie. The result is that the single endpoint whose happy path requires the server to complete a TLS handshake with a client certificate — asymmetric verification plus a full chain walk against the trust anchors, the most expensive work an unauthenticated caller can make this server do — was the one endpoint an unauthenticated caller could drive at line rate. Every other shape of the same attack was already bounded; this one was not, and nothing in the code said why, which is the signature of an omission rather than a decision.",
       "mitigation": "S-2 (2026-09-22): AXIAM__RATE_LIMIT__DEVICE_LOGIN_PER_MIN, default 60 per minute per IP, applied through both layers exactly as /auth/login does — build_governor for the per-process ceiling and RateLimitShared(\"device_login\") so the limit holds across replicas rather than multiplying by replica count. Per-IP unconditionally: the identity on this path is a certificate presented in the handshake and there is no OAuth2 client_id in the request to key a bucket on. The knob is in the machine family, so AXIAM__RATE_LIMIT__PROFILE scales it to 300 (gateway) and 3 000 (mesh), the same 5x and 50x token_per_min takes — which is the answer for a fleet behind one NAT, rather than raising the shipped default for everyone. Sized from the honest traffic and not from capacity: a device re-authenticates once per access-token lifetime, 900 s by default, so sixty per minute holds nine hundred devices on a single address and no deployment on the shipped posture sees a 429 it did not see before. Six tests in device_login_rate_limit_test.rs drive the real register_api_v1_routes wiring, so a regression to a bare route fails the suite; they include the per-IP isolation property, the I4 twin that login_per_min is untouched and uncharged, and the preset-multiplier check."
      },
      {
       "number": 283,
       "title": "A device's access token is a bearer credential, so stealing it is as good as stealing the key",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "POST /api/v1/auth/device authenticates a device by a TLS handshake with a client certificate — the strongest thing the device can prove — and then called issue_service_account_token, which had no cnf parameter at all and whose AccessTokenSpec::service_account never set one. The token that came back was a plain bearer credential: whoever holds it may use it. So the proof of possession bought nothing past the handshake that produced it. A token read off the device's flash, recovered from a log line, captured at a misconfigured egress proxy, or taken from a compromised Device Twin authenticated as that device for the whole of its lifetime, with no certificate and no key required. The machinery to close this already existed and was already used: AccessTokenClaims.cnf, CnfClaim with x5t#S256 per RFC 8705 §3.1, and verify_token_binding's decision table were all built for OAuth2 mTLS client credentials, which mint the claim. The device path was the one mint site that did not, which made it the weakest credential issued from the strongest authentication AXIAM performs (DF-014).",
       "mitigation": "S-3 (2026-09-22): issue_service_account_token takes a cnf and device_auth builds one from the thumbprint of the certificate rustls verified for this connection, so the token names the key the device proved it holds. No enforcement code changed, and that is the finding rather than a shortcut: both surfaces already refuse a cnf-bearing token whose evidence does not match — axiam-api-rest's enforce_sender_constraint runs inside validate_presented_token, which every extractor reaches including the service-account one, and axiam-api-grpc's interceptor reads peer_certs() and runs the same verify_token_binding. The claim was the only missing half. The thumbprint is recorded only where rustls verified the certificate on this connection: the trusted-proxy X-Client-Certificate path mints no cnf, deliberately, because the certificate is present at login and absent from every later request there, so a bound token would be one AXIAM itself refuses on first use — an asymmetry stated in CertificateAuthenticated::certificate_thumbprint's own documentation and in docs/pki/README.md rather than left to be discovered. Tokens minted before this change carry no cnf and are accepted exactly as before, so the migration lasts one access-token lifetime. Three unit tests in axiam-auth pin the stamp, the refusal without and with a wrong certificate, the acceptance with the right one, and the I1 that an unbound token demands nothing. Amended 2026-09-23 (T22.12, S-8): with AXIAM__GRPC_TLS_CLIENT_AUTH set to optional or required the gRPC listener verifies the device's certificate and the interceptor finds it in peer_certs(), so a device token is accepted over gRPC with its own certificate and refused with another device's or with none. Under off it is refused, as before. See T-286."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "9a80f354-ab85-50c6-8405-8a91a50e9681",
     "kind": "process",
     "x": 624,
     "y": 284,
     "w": 140,
     "h": 140,
     "name": "Revocation (status in AXIAM's store; no CRL published)",
     "lines": [
      "Revocation",
      "(status in",
      "AXIAM's",
      "store;",
      "no CRL",
      "published)"
     ],
     "description": "Revoke and rotate set the certificate row's status. AXIAM publishes no CRL and runs no OCSP responder: the CAs carry the cRLSign key-usage bit and nothing serves a list (T-102).",
     "outOfScope": false,
     "threats": [
      {
       "number": 102,
       "title": "A revoked certificate stays valid to every relying party that does not terminate at AXIAM",
       "type": "Spoofing",
       "severity": "High",
       "status": "Open",
       "description": "Revoking a certificate sets the status on its row in AXIAM's store. AXIAM publishes no CRL and runs no OCSP responder — its CAs carry the `cRLSign` key-usage bit and nothing serves a list — so a relying party that validates AXIAM-issued certificates itself (a FreeRADIUS server doing EAP-TLS, a VPN gateway, a peer service terminating its own mTLS) has no channel through which to learn of a revocation, and honours a revoked certificate until it expires. Until model 2.36.0 this entry described a CRL whose refresh interval bounded that window; the tree has never contained one.",
       "mitigation": "Open since model 2.36.0 (T23.11.1, item D7 of the RADIUS spike). Where AXIAM authenticates a device by its certificate, revocation takes effect at once: `DeviceAuthService::authenticate_der` reads the certificate's status on every device sign-in, and a revoked CA anywhere in the chain refuses the leaf. Nothing else AXIAM terminates reads it (corrected by the W6 F4 review, model 2.36.1): neither listener's TLS handshake checks revocation, and OAuth2 `tls_client_auth` matches the client's registered subject DN or SAN on a certificate that chains to a trust anchor, so a revoked AXIAM-issued leaf keeps authenticating its OAuth2 client until it expires or the registration changes. Outside AXIAM there is no revocation channel: the only bound is the leaf's own validity, capped per tenant by `max_cert_validity_days`, so a relying party that needs revocation today must let the connection terminate at AXIAM (the device authenticates there and presents the certificate-bound token it receives, T-283) or rely on short-lived leaves. Publishing a CRL per issuing CA, and deciding on OCSP, is tracked by ilpanich/axiam#565 (spike record §8, D1); this entry closes with it, together with the listeners' verifiers loading that list or `tls_client_auth` reading the certificate's status."
      }
     ],
     "open": 1,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "e006e495-addb-55a7-bbdf-44b2df1c1882",
     "kind": "store",
     "x": 1059,
     "y": 144,
     "w": 170,
     "h": 80,
     "name": "ca_certificate (sealed row or Vault custody)",
     "lines": [
      "ca_certificate",
      "(sealed row or",
      "Vault custody)"
     ],
     "description": "Organization and tenant CA rows with per-CA key custody: AES-256-GCM sealed into the row, held in Vault, held by Vault's PKI engine (never exported), or External (no key stored).",
     "outOfScope": false,
     "threats": [
      {
       "number": 196,
       "title": "Vault configured, CA keys silently sealed into database rows",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "CA key custody read its own PKI-specific Vault variable pair. A deployment that configured the secret provider's pair saw 'secret provider ready provider=vault' at startup and reasonably concluded its CA signing keys were in Vault — while custody fell through to database, sealing every organization and tenant CA private key into a ca_certificate row. A database dump plus one process's AXIAM__PKI__ENCRYPTION_KEY then yields every CA private key in the deployment, and nothing records the read.",
       "mitigation": "Fixed in 1.0.0-beta02: no PKI-specific pair now means the Vault the deployment already configured, not no Vault at all, and the startup custody line carries vault_inherited so an operator who never set a PKI variable can read why their keys are in Vault. The PKI pair still wins outright when set. Database custody beside a working Vault is reachable only by writing AXIAM__PKI__CA_KEY_STORE=database explicitly, and is reported at startup as a warning naming what is at stake. Custody is recorded per CA, and the migrate-custody endpoint moves existing keys into Vault without re-issuing anything."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
       "status": "Mitigated",
       "description": "A BLOB past its own nextUpdate date is deliberately not treated as a hard failure - ingestion still succeeds so a transient FIDO Alliance outage cannot brick registration - but this means an authenticator model FIDO has revoked or decertified since the last successful refresh keeps passing block_revoked_status / require_fido_certified / min_certification until the next successful refresh. Air-gapped deployments on AXIAM__PKI__MDS_BLOB_PATH have no automatic refresh path at all.",
       "mitigation": "CLOSED (T-153), opt-in. AXIAM__PKI__MDS_MAX_STALE_DAYS bounds the window: past that many days beyond nextUpdate, an attested registration is refused with AttestationDenyReason::MetadataStale before the ceremony is finished, so nothing is written and then rejected. Default 0 (disabled) keeps the documented fail-open behaviour deliberately: the right bound is a property of the deployment — a high-assurance tenant may want days, while an air-gapped one on MDS_BLOB_PATH, with no automatic refresh path at all, would be taken offline by anything short of months. Scoped to attested ceremonies only: under AttestationMode::None no metadata is consulted, and never-ingested metadata is the policy's unknown_aaguid setting's job. Staleness still never hard-fails ingestion, and air-gapped operators must still re-supply the BLOB themselves."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
    }
   ],
   "total": 30,
   "open": 2,
   "notApplicable": 0,
   "bySeverity": {
    "Critical": 7,
    "High": 18,
    "Medium": 5
   }
  },
  {
   "id": 6,
   "title": "Audit, webhooks, email & notifications",
   "description": "The append-only audit trail and its OpenPGP batch signing, webhook delivery with HMAC signatures and the SSRF guard, the pluggable email service and templates, and admin notification rules. Since Phase 23 (G-5, T23.5.2, model 2.27.0) it also covers the Shared Signals Framework transmitter: the SSF stream registry and its per-stream event buffer (`ssf_stream`, `ssf_event_buffer`), SET issuance with the deployment key, the stream management API and transmitter metadata a receiver calls with its own client credentials, and the push and poll flows to the receiver, across a boundary of their own (D-44 … D-52). Since model 2.29.0 (T23.5.4) the store also holds the step-up record (`ssf_step_up`, D-53 (1)) the authorization endpoint keeps for `assurance-level-change`. Since model 2.31.0 (D-55) the transmitter is inactive for every tenant while the deployment holds more than one tenant and serves no per-tenant issuers, so tenants never share an issuer. Since model 2.32.0 (G-6, T23.6.4) it also covers outbound SCIM provisioning: the target registry and its management routes (`scim_target`, contract §31), the link rows and delivery state (`scim_target_link`, `scim_target_state`), the provisioning source every user and group repository reports to, the `ScimPush` deliverer on the shared dispatcher, reconciliation, and the dead-letter row that reaches the notification rules, with the downstream SCIM service provider across a boundary of its own (D-57, D-58). At model 2.34.0 (T23.8.2, the review of the audit-write path in the minimal profile against T19.27) an instance's stop with audit rows still queued or in flight enters as T-444, Mitigated; T-405 is amended (a queued push is at-least-once in the full profile only) and T-108 reopened (its text now describes the controls the code has).",
   "width": 1438,
   "height": 1348,
   "boundaries": [
    {
     "id": "c0d71a54-aac0-5a7f-84bf-d3ac20259104",
     "x": 324,
     "y": 24,
     "w": 660,
     "h": 1300,
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
     "h": 1220,
     "label": "Data tier"
    },
    {
     "id": "22ad7639-84f9-58e1-9d96-5ddd89f8a00c",
     "x": 24,
     "y": 784,
     "w": 260,
     "h": 220,
     "label": "SSF receivers"
    },
    {
     "id": "07e47d12-b530-5a19-9c32-1e4b1df891bd",
     "x": 24,
     "y": 1084,
     "w": 260,
     "h": 220,
     "label": "SCIM downstreams"
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
       "status": "Open",
       "description": "If audit writes are best-effort, an attacker who can make the audit path fail — by exhausting the datastore or triggering a specific error — performs actions that leave no trace.",
       "mitigation": "Carried to the W5 F4 review (T23.8.2, review P23W5-A10). Until model 2.34.0 this entry read “audit writes share the transactional path with the action they record where the datastore allows it, and audit failures are surfaced as errors and raise a compliance notification rather than being swallowed”; no code does either. What is built: AXIAM's own request rows are written by the audit middleware off the request path — a bounded queue of 4 096 entries and one worker — so a full queue drops the entry with an `ERROR` line and a failed append is a `WARN` line while the action stands; the GDPR erasure and tenant-deletion records dead-letter a failed write to an append-only file and a structured `axiam.audit.dlq` event (T19.27, `write_erasure_audit_with_dlq`); every orderly stop drains the queue (T-444). What is not: a fallback for any other row, the GDPR request records included (P23W5-A8), and any counter or notification when a row is dropped or fails (P23W5-A10). An attacker who can exhaust the datastore can act while the rows recording it are dropped, and only the server log says so."
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
       "status": "Mitigated",
       "description": "The audit log is append-only by design, so any personal data written into it cannot later be erased — which is in direct tension with the GDPR Art. 17 erasure path AXIAM also offers.",
       "mitigation": "Both halves are now bounded. **Retention** (T-119): a default 730-day sweep through the table's only deletion path — deployment-wide, reachable from no HTTP handler, `0` to disable, both states logged at startup. **Collection** (R-7, 2026-09-12): `AXIAM__AUDIT__MINIMISE`, default `false`, applied in `SurrealAuditLogRepository::append` — the only code every audit row passes through, since the request middleware is one producer among eighteen and the rest call `append` directly. With it on, `ip_address` is truncated to its `/24` or `/48` prefix and a `user_agent` in `metadata` is reduced to a coarse family, immediately before the write because the table is append-only and there is no second chance by construction; an address that does not parse is **dropped** rather than written through, since a value that cannot be parsed cannot be shown to have been minimised. Three limits, each deliberate: the structured metadata producers write is never touched — the client and disposition on a refresh-token replay (T-254), the names of released claims (T-241), a federated subject (T-161) are accountability evidence other mitigations depend on, and dropping them would weaken three controls to narrow one; the switch is **deployment-wide and not per tenant**, because audit is a control the deployment relies on *including against a tenant administrator* and a tenant-level switch would let a tenant weaken the evidence used to investigate that tenant; and it is off by default, because reducing forensic precision is a lawful-basis judgement to make deliberately. Both states are logged at startup exactly as retention is. Erasure and export are unaffected and are asserted so rather than assumed: `pseudonymize_actor` clears `ip_address` outright so a truncated value is erased by the same statement as a whole one, and the Art. 15 export's `audit_entries` section reads `action`, `outcome`, `timestamp` and `resource_id` and never the address (`minimisation_leaves_every_field_the_art_15_export_reads`). The request-audit middleware's own metadata key set is pinned exactly — `http_status` and `authenticated`, nothing else — so \"no request metadata\" cannot regress into an append-only table with a 730-day window. Residual, accepted: the deployment still chooses, and one that leaves the switch off collects what it collects today. `docs/compliance/gdpr-compliance.md` §2a; `docs/deployment/README.md`."
      },
      {
       "number": 444,
       "title": "An instance stops while audit rows are queued or in flight, and they are lost",
       "type": "Repudiation",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The request audit middleware writes off the request path: an entry waits in a bounded queue (4 096) for the one worker that appends it, so a response can go out before its row is written. A process that ends abruptly loses that queue, a request between its write and its audit row, and a GDPR purge between the erasure and `gdpr.user_pseudonymized`. Two stops did exactly that until T23.8.2: the minimal profile's reaction to a lost singleton lease was `std::process::exit(1)` from the renewal task — and a lease is lost after its holder could not reach the datastore, which is when the queue fills — and an orderly SIGTERM dropped the queue with the runtime too, because the teardown only set a flag (review P23W5-A1, A2).",
       "mitigation": "Built (T23.8.2). A lost lease only raises a flag; the composition root then stops through the SIGTERM path — no new connections, in-flight requests finished, the cleanup task's current tick finished, so an erasure and its row stay together — and every orderly stop drains the audit queue with `AuditMiddleware::drain`, a FIFO barrier bounded at 5 s, before `serve` returns; after a lost lease it returns an error, the non-zero exit D-59 requires. The process exit survives only as a backstop after `LeaseTiming::lost_stop_deadline` (15 s). Tests: `crates/axiam-server/tests/minimal_profile_boot.rs` `an_instance_that_loses_its_lease_stops_in_order_and_keeps_its_audit_rows`; `crates/axiam-server/src/profile.rs` `a_lost_lease_starts_the_orderly_stop_at_once_and_the_backstop_only_after_the_deadline`, `an_orderly_stop_that_finishes_in_time_disarms_the_backstop`; `crates/axiam-audit/tests/service_and_middleware.rs` `drain_returns_once_every_queued_entry_is_written`, `drain_is_bounded_when_the_datastore_does_not_answer`. Residuals: a SIGKILL, an OOM kill and the backstop still lose the queue; the gRPC listener is not part of the orderly stop, and the full profile still exits mid-flight when an AMQP consumer dies (review P23W5-A11, A12)."
      }
     ],
     "open": 1,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
       "status": "Open",
       "description": "An attacker triggers thousands of notifiable events so the genuine signal is lost among them, and burns the mail quota along the way.",
       "mitigation": "Reopened at model 2.35.0 by the W5 F4 review (P23W5-13). Until then this entry read “notifications are delivered in configurable batches through the mail queue, and rules are per-category so a noisy category can be tuned without disabling the rest”; nothing batches them. What is built: rules are per event, so a noisy event can be taken out of a rule without disabling the rest; a mail is fixed text; the events a caller can provoke ride rate-limited routes (sign-in per address and per account, with brute-force lockout, T-27); and the one event a background process raises, `scim_delivery_failed`, is coalesced to one notification per target per hour (T-418, D-73). What is not: `NotificationDispatcher::dispatch` enqueues one mail per matched recipient per audit row, so a request-path event an attacker can produce in volume — failed sign-ins spread over addresses and accounts — mails each recipient of a rule for it once per event, with no coalescing, cool-down or digest. Open until per-rule coalescing exists (issue body in the W5 F4 review, §14)."
      }
     ],
     "open": 1,
     "notApplicable": 0
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
       "status": "Mitigated",
       "description": "Deleting a tenant removes its data; if audit records go with it, the evidence of what happened disappears exactly when it matters most.",
       "mitigation": "SECHRD-T118: closed in-product. DELETE /organizations/{org_id}/tenants/{tenant_id} refuses with 409 unless the tenant's audit trail was exported in the previous six hours. POST .../tenants/{tenant_id}/audit-export streams the whole trail as newline-delimited JSON — bounded memory, no truncation — and, only after the last row has been written, appends a receipt to that tenant's own audit log; the export's final line is a manifest carrying the record count, a SHA-256 over the exported entries and the receipt id, so an archived file can be re-hashed and tied back to the deletion it authorised. An export that dies half way leaves no receipt and unblocks nothing. The six-hour window is a constant, not a setting: a configurable freshness bound is one an operator can widen until it means nothing. The deletion itself is recorded in the SYSTEM audit log (nil tenant), naming the actor and the receipt — the tenant's own entries are gone by then, so that record is what outlives it. Residual, stated rather than hidden: this proves an identified principal was handed the trail minutes before the deletion, not that they kept the bytes; custody of a file the server gave away is not something the server can attest. GDPR Art. 17 is unaffected — erasure is delayed by one export, never refused, and there is no override parameter."
      },
      {
       "number": 119,
       "title": "Unbounded audit growth degrades the datastore",
       "type": "Denial of service",
       "severity": "Low",
       "status": "Mitigated",
       "description": "An append-only table with no retention policy grows without limit, eventually affecting query latency across the datastore.",
       "mitigation": "CLOSED (T-119). AXIAM now prunes audit records on a clock, defaulting to a 730-day retention window. AuditLogRepository::prune_older_than is the table's first deletion path and is deliberately narrow: reachable only from the background sweep, never from any HTTP handler — retention is a deployment-wide policy, not an operation an administrator can aim at a time range of their choosing — and deployment-wide rather than per-tenant, so one tenant's settings cannot decide how long another tenant's records survive on shared storage. 0 disables pruning and restores the old behaviour, and both states are logged at startup so the window in force is visible rather than inferable from config. Archival to an external WORM sink before the window expires remains the operator's choice (T-118)."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
       "mitigation": "Broker access is credentialed per service on the private network, and the transport is always TLS — the server refuses any non-amqps:// broker URL in every build profile; tokens are single-use and short-lived so a stale queued message has limited value."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "ca5dcc2e-8c77-530c-b35e-5fa3aac86bc9",
     "kind": "actor",
     "x": 49,
     "y": 864,
     "w": 150,
     "h": 80,
     "name": "SSF receiver (relying party)",
     "lines": [
      "SSF receiver",
      "(relying party)"
     ],
     "description": "A relying party that consumes CAEP and RISC events from AXIAM: receives SETs on its push endpoint (RFC 8935) or polls for them (RFC 8936), and manages its stream through the SSF 1.0 stream management API.",
     "outOfScope": false,
     "threats": [
      {
       "number": 385,
       "title": "Receiver impersonation on the stream management API",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "The SSF stream management API lets a receiver read its stream, repoint its push endpoint, change the push credential, change the stream's status and ask for verification events. A party that can pass for a receiver — a user session, a service account, a client token minted for another purpose, or another receiver's client — could redirect a tenant's security events, silence them, or learn which events and subjects a relying party watches.",
       "mitigation": "`SsfReceiverToken` (`handlers::ssf`, D-50): only an access token issued to an OAuth2 client by the client-credentials grant (`sub_kind` `OAuth2Client`) **and** carrying the dedicated scope `ssf.manage` is accepted; a user token (even an administrator's), a service-account token or a client token without the scope is `403`, no token `401`. A stream is the receiver's only when its administrator-set `receiver_client_id` is the token's `client_id`; every other stream answers the same `404` as one that does not exist. The scope reaches a client only through its registration (`OAuth2Client::scopes`, refused by the token endpoint otherwise) and the binding only through an administrator (§32). Tests: `crates/axiam-api-rest/tests/ssf_test.rs` `the_receiver_api_needs_a_client_token_with_the_scope`, `another_receivers_or_another_tenants_stream_is_not_found`."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "2cb70f89-99d6-5c6b-8862-a03dea020ff9",
     "kind": "process",
     "x": 374,
     "y": 784,
     "w": 140,
     "h": 160,
     "name": "SSF transmitter (SET issuance, stream API, discovery)",
     "lines": [
      "SSF",
      "transmitter",
      "(SET",
      "issuance,",
      "stream API,",
      "discovery)"
     ],
     "description": "`axiam_oauth2::ssf` and `handlers::ssf` / `handlers::ssf_admin` (T23.5.2): the stream registry's management routes (contract §32), the receiver's stream management API under `/ssf/v1`, `/.well-known/ssf-configuration`, and `sign_set`, the only SET signer, run at delivery by the push deliverer and the poll endpoint T23.5.3 builds.",
     "outOfScope": false,
     "threats": [
      {
       "number": 386,
       "title": "Cross-tenant or cross-receiver stream access",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "Streams of every tenant live in one table. A tenant administrator, or a receiver of one tenant, who can name another tenant's stream id — in a path, a `stream_id` query or a body — could read where that tenant's events go or change it.",
       "mitigation": "The tenant is never taken from the request: the management routes refuse a `{tenant_id}` that is not the caller's (`403`) and require `ssf_streams:read` / `ssf_streams:write` (a human-only family: a service-account token is `401`); the receiver API takes the tenant from the token. Every repository verb is tenant-scoped in its `WHERE` (`SurrealSsfStreamRepository`), so another tenant's id reads, updates, verifies, decrypts and deletes as `NotFound`. Tests: `crates/axiam-db/tests/ssf_stream_repository_test.rs` `tenants_cannot_read_update_verify_open_or_delete_each_others_streams`; `crates/axiam-api-rest/tests/ssf_test.rs` `another_receivers_or_another_tenants_stream_is_not_found`, `each_operation_needs_its_permission_its_tenant_and_a_human`."
      },
      {
       "number": 389,
       "title": "A SET is mistaken for another kind of JWT",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "SETs, ID tokens, logout tokens and access tokens are all signed with the same deployment key (D-13). A SET presented where an access token or an ID token is expected could be accepted as one if the verifier checks only the signature.",
       "mitigation": "Explicit typing and shape (SSF §4.1.1–§4.1.3, RFC 8417 §4.5–§4.7): `typ: secevent+jwt`, no `sub` and no `exp` (`SetClaims` has no field for either), an `events` claim, and an `aud` that is a receiver audience, never an AXIAM audience. AXIAM's own access-token validation therefore refuses a SET (no `exp`, wrong audience). Tests: `crates/axiam-oauth2/src/ssf.rs` `a_set_is_never_accepted_as_an_axiam_access_token`, `a_set_verifies_against_the_published_jwks_with_the_pinned_header_and_claims`."
      },
      {
       "number": 392,
       "title": "The push endpoint is used to reach internal services",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "The push endpoint is chosen by a tenant administrator and, since SSF lets a receiver update its delivery, by the receiver. AXIAM POSTs to it from inside the deployment. Pointed at a metadata service, a loopback admin port or a private address, it turns the transmitter into a request forger with a credential attached.",
       "mitigation": "Write time is built: every endpoint an administrator or a receiver supplies is held to the webhook outbound address policy (D-49, `validate_push_endpoint`): `https` only, no credentials or fragment, no IP literal that is not globally routable (loopback, private, link-local, the metadata address, IPv4-mapped forms), no `localhost`, `*.local` or `*.internal`. Tests: `crates/axiam-oauth2/src/ssf.rs` `the_push_endpoint_policy_is_the_webhook_one`; `crates/axiam-api-rest/tests/ssf_test.rs` `every_value_rule_and_the_receiver_binding_are_400s_that_name_the_rule`, `a_receiver_cannot_repoint_its_endpoint_to_a_refused_address`. **Built (T23.5.3, 2026-10-04).** At delivery every push goes through the shared `axiam_pki::ssrf` guard, reached as `axiam_federation::ssrf`, with `allow_private = false` and through nothing else: the name is resolved fresh, every address it resolves to must be globally routable, the validated address is pinned into the connection, and `https` is required. Since D-53 (9) (model 2.29.0 records it) the call is `guarded_fetch_no_redirect`, one guarded hop that returns a `3xx` as a response: a redirect, to an internal address or any other, is never resolved, let alone connected to, and the deliverer retries it, so neither the SET nor the `Authorization` header reaches a host the administrator never named (T-391). The response body is read to at most 64 KiB, and every reason string that reaches the audit log is a fixed phrase — never a URL, a header or a response. A name an administrator registered that resolves to an internal address is caught here, which the write-time policy cannot do. Tests (T23.5.3): `crates/axiam-oauth2/tests/ssf_delivery_test.rs` `the_address_guard_refuses_an_internal_endpoint_at_delivery` (127.0.0.1, `localhost`, `::1`, the metadata address and 10.0.0.5 are refused by the production deliverer with the listener untouched; a plaintext endpoint is dead-lettered before anything resolves), `a_redirect_is_not_followed` (a public target is not sent to), `a_redirect_to_a_reachable_receiver_is_not_followed_either` (a loopback target the test seam would admit receives nothing: the `Location` is never fetched; renamed in the W4 F4 review), `a_3xx_is_retried_and_never_followed`, `the_response_body_is_capped`; `crates/axiam-oauth2/src/ssf_delivery.rs` `push_goes_through_the_no_redirect_guarded_fetch_and_nothing_else` (the production source holds one `guarded_fetch_no_redirect` call, no call of the redirect-following `guarded_fetch`, no other HTTP client, and `allow_private` is set only by the hidden test seam), `a_transport_reason_never_carries_the_error_text`; `crates/axiam-pki/src/ssrf.rs` `no_redirect_keeps_the_guard_on_the_one_hop` (loopback, `localhost` and private literals blocked, plaintext refused before anything resolves), `no_redirect_returns_a_redirect_to_an_internal_address_without_fetching_it`; `crates/axiam-api-rest/tests/ssf_test.rs` `the_address_guard_refuses_a_private_endpoint_at_delivery_end_to_end` (the production deliverer behind the real outbox, a name that resolves to the receiver's own loopback address). Residual: the guard honours the operator's `AXIAM__PKI__SSRF_ALLOWED_HOSTS` exception (SEC-107) here exactly as it does for webhooks, for the named host only and never for a metadata endpoint."
      },
      {
       "number": 393,
       "title": "Flooding the stream management API or discovery",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The stream management API, the verification endpoint and the unauthenticated transmitter metadata are new inbound surfaces. A loop against them costs a datastore read per request, and verification additionally makes AXIAM sign and send an event, so it amplifies towards the receiver.",
       "mitigation": "Every route has its own bucket (plan §7 rule 6): `AXIAM__RATE_LIMIT__SSF_PER_MIN` (60 per minute per IP) on each receiver route and each discovery form, `AXIAM__RATE_LIMIT__SSF_ADMIN_PER_MIN` (30) on each management write, never moved by a profile preset. Each stream also enforces `min_verification_interval` (60 s) atomically in the datastore, `429` inside it. Tests: `crates/axiam-api-rest/tests/ssf_test.rs` `every_ssf_route_has_its_own_bucket`, `the_verification_event_is_submitted_signed_on_delivery_and_rate_limited_per_stream`; `crates/axiam-db/tests/ssf_stream_repository_test.rs` `a_verification_is_claimed_once_per_interval`."
      },
      {
       "number": 397,
       "title": "A receiver widens its events or overrides the administrator",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "SSF lets a receiver update its stream configuration and status. A receiver that could add event types beyond what the administrator allowed, change the delivery method, the audience or the subject format, or restart a stream the administrator stopped would receive personal data the tenant never agreed to send it.",
       "mitigation": "`apply_receiver_update` (D-50): `events_requested` may only narrow within the administrator's `events_allowed` (an allowed-but-unknown URI is ignored, a known one outside the allowance is `400`); transmitter-supplied members must match; the method is the administrator's; the audience, the subject format and the allowance are never receiver-writable. A status the administrator set to anything but `enabled` cannot be changed by the receiver (`403`, D-51); POST and DELETE on the configuration endpoint are `403`. Tests: `crates/axiam-oauth2/src/ssf.rs` `a_receiver_may_narrow_but_not_widen_its_events`, `transmitter_supplied_members_must_match`, `replace_deletes_what_it_omits_and_needs_a_delivery`; `crates/axiam-api-rest/tests/ssf_test.rs` `a_receiver_narrows_its_events_and_cannot_widen_them`, `the_receiver_sets_its_status_unless_an_administrator_stopped_the_stream`."
      },
      {
       "number": 399,
       "title": "Stream changes are not attributable",
       "type": "Repudiation",
       "severity": "Low",
       "status": "Mitigated",
       "description": "Where a tenant's security events go is a security decision. Without a record, a stream repointed to a collection endpoint, or a verification storm, cannot be traced to the administrator or the receiver that caused it.",
       "mitigation": "One audit row per write: `ssf_stream.created`, `ssf_stream.updated` (the **names** of the changed members), `ssf_stream.deleted` with the administrator as actor; `ssf_stream.receiver_updated`, `ssf_stream.receiver_status_changed` and `ssf_stream.verification_requested` with the receiver's `client_id`. Never the header, never a subject. Tests: `crates/axiam-api-rest/tests/ssf_test.rs` `an_administrator_registers_reads_lists_replaces_and_deletes_a_stream`, `a_receiver_narrows_its_events_and_cannot_widen_them`, `the_verification_event_is_submitted_signed_on_delivery_and_rate_limited_per_stream`."
      },
      {
       "number": 400,
       "title": "A stream is bound to a client that is not the tenant's receiver",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The receiver binding decides who may manage the stream and poll its events. Bound to a client of another tenant, to a client that cannot obtain a client-credentials token, or to a name no client has yet (to be registered later by someone else), it hands the stream to the wrong party.",
       "mitigation": "The administrator's write refuses (`400`, naming the rule) a `receiver_client_id` that is not an OAuth2 client of the tenant, not registered for the `client_credentials` grant, or not registered with the `ssf.manage` scope; a client of another tenant is not found in this tenant's lookup. Tests: `crates/axiam-api-rest/tests/ssf_test.rs` `every_value_rule_and_the_receiver_binding_are_400s_that_name_the_rule`."
      },
      {
       "number": 401,
       "title": "Transmitter metadata as a tenant oracle",
       "type": "Information disclosure",
       "severity": "Low",
       "status": "Mitigated",
       "description": "`/.well-known/ssf-configuration` is unauthenticated by specification. Answers that differ between an unknown tenant, a tenant with the transmitter off and a malformed id tell anyone which tenants exist and which send security events.",
       "mitigation": "One empty `404` for every way of having nothing to say — no or a malformed tenant id, an unknown tenant, a tenant whose effective `ssf_enabled` is off (the D-20 shape, D-45) — on both the root and the tenant-path form; the receiver API likewise answers a stream of a tenant whose transmitter is off as not found. Tests: `crates/axiam-api-rest/tests/ssf_test.rs` `discovery_answers_one_empty_404_for_every_way_of_having_nothing_to_say`, `with_the_transmitter_off_the_receiver_sees_no_stream`, `discovery_on_the_root_issuer_lists_the_endpoints_and_events`, `discovery_on_a_tenant_path_issuer_names_the_tenant_issuer`."
      },
      {
       "number": 403,
       "title": "Long polls hold the poll endpoint open",
       "type": "Denial of service",
       "severity": "Low",
       "status": "Mitigated",
       "description": "RFC 8936 lets a receiver poll without `returnImmediately`, and AXIAM then holds the request for up to 30 seconds, re-reading the stream and its buffer every half second until an event arrives. A receiver, or whoever holds a receiver's token, that opens many long polls at once ties up connections and spends datastore reads on each of them, and a per-minute rate limit does not bound how many wait at the same time.",
       "mitigation": "Built (T23.5.3, 2026-10-04; D-48, D-53 (11)). Nothing waits before the caller is shown to be the stream's receiver: the token (client credentials, `ssf.manage`) and the stream binding are checked first, and a stream that is not its own is `404` (T-385, T-386). At most **one long poll waits per stream per server instance** (`PollWaiters`: a slot taken the first time a request would wait and released when it answers or is dropped, including when the receiver hangs up). A second concurrent request on the same stream answers at once with what is held, as if `returnImmediately` were true. A wait ends after 30 seconds, or as soon as the stream is paused, disabled or deleted. The route has a bucket of its own, `ssf_poll`, under `AXIAM__RATE_LIMIT__SSF_PER_MIN` (60 a minute per client address, as in T-393), of which an honest long-polling receiver uses about two a minute. Tests: `crates/axiam-api-rest/tests/ssf_test.rs` `a_second_long_poll_on_a_stream_answers_at_once_while_one_is_waiting` (the second answers an empty `sets` in less than one wait step, the first still receives the event that arrives meanwhile, and the slot is free once it has answered), `an_empty_poll_returns_at_once_or_waits_for_an_event` (the 30-second cap), `the_poll_route_has_its_own_rate_limit_bucket`; `crates/axiam-api-rest/src/state/bundles.rs` `one_slot_per_stream_released_on_drop`. An abandoned long poll gives its slot back, and a held event the deployment key cannot sign is logged once per request rather than on every look (W4 F4, P23W4-03: before, about sixty `ERROR` lines per waiting receiver per half minute, a log flood a receiver could sustain by polling); the wait step cannot underflow past the 30-second cap. Tests (W4 F4): `an_unsignable_held_event_is_logged_once_per_poll_and_an_abandoned_poll_frees_its_slot`. Residuals: the slot is per instance, so *n* replicas can hold *n* long polls per stream, each re-reading about sixty times over a full wait. A receiver that runs several pollers on one stream turns all but one into immediate answers and busy-loops; what that spends is its own `ssf_poll` budget. It is self-inflicted, and costs others nothing beyond the per-address bound."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "380feb66-2da4-5fd3-aa96-231aa7263516",
     "kind": "store",
     "x": 1079,
     "y": 784,
     "w": 170,
     "h": 80,
     "name": "ssf_stream + ssf_event_buffer + ssf_step_up",
     "lines": [
      "ssf_stream +",
      "ssf_event_buffer +",
      "ssf_step_up"
     ],
     "description": "Schema v77: the stream registry (receiver binding, audience unique across the deployment, sealed push header) and the per-stream bounded buffer of unsigned pending events. Schema v78 (T23.5.3, D-53 (1)): the step-up record `ssf_step_up`, which the authorization endpoint's honour lane writes and its return leg consumes, one per (tenant, user), ten minutes. The push kind's broker queues (`axiam.ssf_push`, `.retry`, `.dlq`) hold the same unsigned pending events as the buffer and are drawn with it rather than as an element of their own.",
     "outOfScope": false,
     "threats": [
      {
       "number": 391,
       "title": "The push credential is disclosed or carried to another host",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "A receiver may require an `Authorization` header on its push endpoint. AXIAM stores it and presents it on every push, so it is a credential to a third party: readable from a response, a log or the database it is a key to the receiver's endpoint, and if the endpoint could be moved without it, AXIAM itself would hand it to whatever host the endpoint was moved to.",
       "mitigation": "Sealed with AES-256-GCM under `pki_encryption_key` (the key webhook secrets use), nonce and ciphertext in their own columns; no read projects them and the single path to the plaintext is `decrypt_authorization_header`, for the push deliverer (D-49). No response carries it (`authorization_header_set` says whether one is stored), `Debug` redacts it, audit rows name the field and never the value, and without the key a write that sets one is `503`. A stored header never follows the endpoint to another origin: moving it — by the administrator or the receiver — requires the header again or its removal (`400`). Contract §32.5 makes it `Sensitive<T>`. Tests: `crates/axiam-db/tests/ssf_stream_repository_test.rs` `create_round_trips_every_field_and_never_reads_the_header_back`, `without_the_key_a_header_cannot_be_stored_and_everything_else_works`, `an_update_keeps_replaces_or_clears_the_header`; `crates/axiam-api-rest/tests/ssf_test.rs` `an_administrator_registers_reads_lists_replaces_and_deletes_a_stream`, `moving_the_endpoint_to_another_origin_needs_the_header_again`, `a_receiver_cannot_repoint_its_endpoint_to_a_refused_address`; `crates/axiam-oauth2/src/ssf.rs` `repointing_the_endpoint_is_held_to_the_address_policy_and_the_credential_rule`, `debug_never_prints_a_subjects_address_or_a_receivers_header`; schema `v77_stores_the_push_header_sealed_and_no_signed_token`. **The redirect leg (T23.5.3, 2026-10-04; D-53 (9)).** A stored header could also leave with the push itself, if a push followed a redirect to another host. Every push goes through `guarded_fetch_no_redirect`, which makes one guarded hop and returns a `3xx` as a response, its `Location` never resolved, validated or fetched; the deliverer treats a `3xx` as a retry. The header and the SET therefore reach only the endpoint the administrator or the receiver set. Tests: `crates/axiam-pki/src/ssrf.rs` `no_redirect_returns_a_3xx_and_never_fetches_its_target`, `no_redirect_returns_a_redirect_to_an_internal_address_without_fetching_it`, `no_redirect_keeps_the_guard_on_the_one_hop`; `crates/axiam-oauth2/tests/ssf_delivery_test.rs` `a_3xx_is_retried_and_never_followed` (300, 301, 302, 303, 307 and 308 with a credential stored: each a retry, and the redirect target receives nothing), `a_redirect_is_not_followed`; `crates/axiam-oauth2/src/ssf_delivery.rs` `push_goes_through_the_no_redirect_guarded_fetch_and_nothing_else` (one call of that function, no call of the redirect-following `guarded_fetch`, no other HTTP client). Residual: once delivered, the header is the receiver's. A receiver that logs it, reflects it in a response or forwards it is outside AXIAM's control; AXIAM reads a response body only to find an RFC 8935 error code, at most 64 KiB, and never logs or stores it."
      },
      {
       "number": 395,
       "title": "The poll buffer grows without bound",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Events for a poll stream, and for any paused stream, wait in `ssf_event_buffer` until they are acknowledged or the stream resumes. A receiver that never polls, or a stream paused and forgotten, would accumulate rows for ever and grow the datastore.",
       "mitigation": "Built (T23.5.3, 2026-10-04; D-48). `SurrealSsfEventBufferRepository` holds at most 1 000 events per stream and drops the **oldest** to admit the newest (SSF §8.1.2 permits dropping held events), keeps each at most seven days (`expires_at`), has one row per `(tenant, stream, jti)` in the datastore, and loses its rows with their stream and their tenant. The poll endpoint never serves an expired row and an acknowledgement deletes exactly the named rows of that stream; the `ssf_event_buffer` sweep removes what has expired and is registered in `/health/jobs` from boot, in the cleanup loop. Tests: `crates/axiam-db/tests/ssf_event_buffer_test.rs` `the_buffer_is_bounded_and_drops_the_oldest` (1 001 pushes leave 1 000, the first gone, another stream's buffer untouched), `expired_events_are_not_served_and_the_sweep_removes_them`, `a_jti_is_buffered_once`, `delete_by_jti_removes_only_the_named_rows_of_this_stream`; `crates/axiam-db/tests/ssf_stream_repository_test.rs` `the_buffer_holds_one_row_per_jti`, `deleting_a_stream_removes_its_buffer_and_nothing_else`, `a_tenant_delete_removes_its_streams_and_buffers`; `crates/axiam-api-rest/tests/ssf_test.rs` `a_narrowed_stream_and_an_expired_event_are_not_served`, `an_acknowledgement_drains_exactly_the_named_rows_of_that_stream`, `a_set_error_deletes_the_row_and_writes_an_audit_row_with_the_code`; `crates/axiam-server/src/job_health.rs` `the_slo_sweeps_are_recorded_by_the_cleanup_loop_and_registered` (extended: the sweep is in the cleanup loop and in `SWEEP_JOBS`). Residual: an erased user's subject member can outlive the erasure in a buffer for up to seven days (recorded at T23.5.2; T-402 carries it, with the dead-letter queue)."
      },
      {
       "number": 402,
       "title": "Held and dead-lettered events keep a person's subject after it is needed",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "What waits to be delivered is the unsigned pending event (D-48), and it names a person: an `iss_sub` subject, or on an `email` stream an address. It waits in three places: the poll and pause buffer in the datastore, and the push kind's queues on the broker, the last of which, `axiam.ssf_push.dlq`, receives every event that exhausted its attempts or can never be accepted, and nothing drains it. Without a lifetime, a dead-lettered event would keep its subject indefinitely, outside every sweep and every erasure path, readable by anyone with access to the broker.",
       "mitigation": "Built (T23.5.3, 2026-10-04; D-48, D-53 (10)). Every place a pending event waits has a lifetime of at most seven days, D-48's bound for held events. **The dead-letter queue**: `axiam.ssf_push.dlq` is declared with an `x-message-ttl` of 604 800 000 ms and no other argument, so the broker drops a dead-lettered event seven days after it arrives. Besides it, only `axiam.scim_push.dlq` carries a TTL — the same seven days, since G-6 (T23.6.1; model 2.32.0 records it), on a queue that holds only references (T-415): the primary and the retry queue of every kind keep the declaration every kind uses, and the webhook DLQ keeps the arguments a running broker already holds (RabbitMQ refuses a redeclaration with other arguments). **The buffer**: seven days at most, swept on `/health/jobs`, 1 000 events per stream (T-395). No queue or table holds a signed SET or the push credential (T-391, T-398), and the broker's transport and credentials are T-121's. Tests: `crates/axiam-amqp/src/outbound/topology.rs` `the_ssf_push_dlq_declaration_is_pinned` (the DLQ's arguments are exactly the 604 800 000 ms TTL; the primary and the retry queue carry only their dead-letter routing), `only_the_ssf_push_and_scim_push_dlqs_have_a_message_ttl` (renamed in T23.6.1: exactly the SSF push and SCIM push DLQs carry one, and no primary or retry queue of any kind); `crates/axiam-db/tests/ssf_event_buffer_test.rs` `expired_events_are_not_served_and_the_sweep_removes_them`. Residuals, stated rather than hidden. **Erasure**: the Art. 17 erasure and the administrator's delete remove the person's step-up record (T-404) but not events already held in a buffer or a queue, so an erased person's subject can outlive the erasure there for up to seven days (carried from T23.5.2). The `account-purged` event does so on purpose: telling recipients of an erasure is its job. **The primary and retry queues** declare no TTL: a message there lives through its retry schedule (`AXIAM__SSF_PUSH__MAX_ATTEMPTS` attempts, each delay at most `AXIAM__SSF_PUSH__BACKOFF_CEILING_MS`), and waits in the primary queue for as long as no consumer runs."
      },
      {
       "number": 404,
       "title": "An assurance-level-change is forged, replayed or suppressed through the step-up record",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "CAEP `assurance-level-change` tells receivers that a user's authentication level moved, and a receiver may relax a restriction on an increase. AXIAM learns of a step-up across a browser round trip: the honour lane sends the user to sign in again, and a later authorization request comes back with the new session. If what links the two legs travelled with the browser (a marker in `return_to`, a parameter a relying party sets), a relying party or whoever controls the browser could forge a level change for a user who never stepped up, replay one, attach it to another user, or suppress a real one.",
       "mitigation": "Built (T23.5.3, 2026-10-04; D-53 (1)). The link is **server-side**. When the honour lane interacts for a step-up (`AcrUnsatisfied`) and the request carries a valid OP session, the authorization endpoint writes an `ssf_step_up` row `{tenant, user, previous_session_id, previous_acr}`: one per `(tenant, user)`, the latest replacing the earlier, ten minutes, `previous_acr` held by the datastore to the two published values. Nothing travels in `return_to`. The return leg consumes the row of **the user the request authenticates as**, in one `DELETE … RETURN BEFORE`, so a row is used once however many legs race for it, and emits only for a **new** session of that user whose `acr` differs from the recorded one, with `previous_level` the recorded value and `initiating_entity: user`. Nothing is written for a request with no readable session, an interaction that is not a step-up (`prompt=login`), or a tenant with SSF off or no stream carrying the event; nothing is emitted for another user's sign-in, the same session returning, an equal `acr`, or a row that expired or was already consumed. The row holds ids and an `acr` URN, no credential and no address; it is swept on `/health/jobs` (`ssf_step_up`) and removed with its tenant and by both erasure paths. Tests: `crates/axiam-api-rest/tests/ssf_test.rs` `a_step_up_upgrade_emits_assurance_level_change_with_previous_level_and_direction`, `a_return_with_the_same_acr_emits_nothing`, `the_same_session_returning_emits_nothing`, `a_different_users_return_leg_emits_nothing_and_leaves_the_record`, `an_expired_record_emits_nothing`, `a_step_up_record_is_consumed_once`, `the_latest_step_up_replaces_the_earlier_one`, `without_a_valid_op_session_no_step_up_record_is_written`, `an_interaction_that_is_not_a_step_up_writes_no_record`, `with_ssf_off_for_the_tenant_no_step_up_record_is_written`; `crates/axiam-db/tests/ssf_step_up_test.rs` `a_record_is_taken_once_and_then_it_is_gone`, `the_latest_record_replaces_the_earlier_one_for_a_user`, `a_record_is_one_users_in_one_tenant_only`, `an_expired_record_is_consumed_and_returns_nothing`, `the_sweep_removes_only_expired_records_in_every_tenant`, `the_datastore_refuses_an_acr_outside_the_vocabulary`, `deleting_a_tenant_removes_its_records_and_only_its_own`, `both_erasure_paths_remove_the_persons_record`; `crates/axiam-server/tests/cleanup_task.rs` `an_erasure_removes_the_persons_ssf_step_up_record`; `crates/axiam-server/src/job_health.rs` `the_slo_sweeps_are_recorded_by_the_cleanup_loop_and_registered` (extended to `ssf_step_up`). **Closed in the W4 F4 review (P23W4-02, 2026-10-04):** the return-leg marker is a query parameter any page can put on a link, and the handler used to consume the row before it validated the rest of the request, so a relying party, or any page that sent the user's browser to the authorization endpoint with the marker while it held the session, could spend the row early with the session that started the step-up and cost the one event the real return leg would have sent. The row is now consumed only once the authorization service has accepted the request (client, `redirect_uri` and the rest), and `take` leaves a row whose `previous_session_id` is the requesting session (`DELETE … WHERE previous_session_id != $current_session_id`), so a return leg in the session that was asked to step up spends nothing. Tests: `a_return_leg_the_authorization_endpoint_refuses_spends_nothing` (three forged return legs — no client, an unknown client, a `redirect_uri` the client never registered — leave the row and tell nobody, and the real return leg then emits), `the_same_session_returning_emits_nothing` (now also: the row is left); `crates/axiam-db/tests/ssf_step_up_test.rs` `a_take_in_the_asking_session_leaves_the_record`. Residual: a page that sends the browser through a complete, valid authorization request of a registered client after the user holds the new session makes the return leg the real one would have made — the event it emits is the true one. Nothing can create an event: an emission needs a step-up the user's own session started and a new session of the same user at another level, and the only party that can present such a session is the user."
      },
      {
       "number": 406,
       "title": "A stream write that overlaps another puts back what the other changed",
       "type": "Tampering",
       "severity": "Low",
       "status": "Mitigated",
       "description": "Every write of an SSF stream is read-modify-write: the receiver's `PATCH`, `PUT` and status write and the administrator's replacement each read the stream, decide, and write back the whole configuration they read. Two writes that overlap lose one: a receiver's write prepared before an administrator disabled, narrowed, re-bound or switched the subject format of its stream, landing after, puts the old status, allowance, binding and subject format back — undoing a `disabled` that D-51 says only an administrator may lift, without the administrator's page or audit row showing it, and a receiver can widen the window by writing at its rate limit. The push deliverer has the same shape across two reads: it reads the stream's endpoint, then opens its `Authorization` header, so a header supplied with a new endpoint in between is sent to the old one, against D-49's rule that a credential never follows an endpoint to another origin.",
       "mitigation": "Decided in the W4 F4 review (P23W4-01, 2026-10-04). Every stream write is conditional on the version it was prepared from: `SsfStreamUpdate::from_stream` carries the stream's `updated_at` and `SsfStreamRepository::update` writes `WHERE updated_at = $expected`, answering `Conflict` (not `NotFound`) when the stream exists but changed. The receiver's `PATCH`, `PUT` and status `POST` decide again from a fresh read when overtaken — so the D-51 check always judges the status the write would replace, and an administrator's `disabled` makes the retry a `403` — and answer `409` only if the stream kept changing over three attempts; the administrator's `PUT` answers `409` and the console reloads. The deliverer reads the stream again after opening the header and pushes only if it is still the version it signed against and whose endpoint it holds; otherwise the attempt is a retry. Contract §32.3 rule 4 and §32.6 say so (1.56, amended in place). Tests: `crates/axiam-db/tests/ssf_stream_repository_test.rs` `a_write_prepared_from_an_overtaken_read_does_not_land`; `crates/axiam-oauth2/tests/ssf_delivery_test.rs` `a_credential_supplied_for_a_new_endpoint_never_reaches_the_old_one`. Residual: the deliverer's second read and the send are not one step, so an endpoint moved after that read is used for one attempt with the header that was stored for it — the header and the endpoint still belong together."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "7a537749-2b71-511e-804c-75a29eff8ae7",
     "kind": "actor",
     "x": 49,
     "y": 1154,
     "w": 150,
     "h": 80,
     "name": "Downstream SCIM service provider",
     "lines": [
      "Downstream SCIM",
      "service provider"
     ],
     "description": "A SCIM 2.0 service provider a tenant administrator registered as a target (G-6): it receives `POST`, `PATCH`, `DELETE` and list requests for the tenant's users and groups, authenticated with a bearer token or with an OAuth2 client-credentials access token from its `token_url`. Trusted with the people the tenant sends it; never a source of AXIAM's directory data.",
     "outOfScope": false,
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "1116d6a2-4538-5cfe-8a2e-83ed3df4d0fc",
     "kind": "process",
     "x": 374,
     "y": 1114,
     "w": 140,
     "h": 160,
     "name": "Outbound SCIM provisioning (target API, deliverer, reconciliation)",
     "lines": [
      "Outbound",
      "SCIM",
      "provisioning",
      "(target",
      "API,",
      "deliverer,",
      "reconciliation)"
     ],
     "description": "`axiam_scim::outbound` and `handlers::scim_targets` (T23.6.1 … T23.6.4; D-57, D-58): the target registry's management routes (contract §31, human-only), the `ScimProvisioner` every user and group repository reports a committed change to (`ProvisioningSink`), the `ScimPushDeliverer` the shared dispatcher's `scim_push` consumer calls — one level-triggered attempt per queued reference — and reconciliation, nightly (`scim_reconcile`) and on demand, through the same deliverer. Its one way out is `guarded_fetch_no_redirect` with `allow_private = false`.",
     "outOfScope": false,
     "threats": [
      {
       "number": 408,
       "title": "The stored credential is sent to a host it was not registered for",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "AXIAM sends the stored bearer token to `base_url` and the client secret to `token_url`, from inside the deployment. If either URL could change without the credential being supplied again — by an administrator who may edit the target, by a write that overlaps another, or by a redirect the downstream answers with — AXIAM itself would hand the credential to whoever runs the new host, and an administrator who may change a target but was never given its credential could read it off a server of their own.",
       "mitigation": "Built (T23.6.1, T23.6.2, T23.6.4; D-57). **Bound on write**: changing `base_url` of a bearer target, `token_url` of a client-credentials target, or the authentication kind, without the credential in the same write is `400` naming the field and changes nothing (contract §31.3 rule 2). The repository applies the rule against the very row it replaces — its write is conditional on the version it checked, so a write racing it is a `409`, never a credential aimed at a URL the rule did not see — and applies it to an unconditional update too. **Checked again before it leaves**: the deliverer reads the target, opens the credential, reads the target once more and sends only if `updated_at` is still the version whose URL it holds; otherwise the attempt is a retry and nothing leaves (the T-406 precedent). The access-token cache is keyed by target **and** `updated_at`, so any administrator write retires a cached token. **No redirect followed**: every request, the token request included, goes through the outbound client's one `guarded_fetch_no_redirect` call, which returns a `3xx` as a response whose `Location` is never resolved or fetched; the deliverer and the token fetch treat it as a retry. Tests: `crates/axiam-db/tests/scim_target_repository_test.rs` `changing_a_bearer_targets_base_url_needs_the_credential`, `changing_a_client_credentials_token_url_needs_the_credential`, `switching_the_auth_kind_needs_the_credential_both_ways`, `an_unconditional_update_still_checks_the_url_binding`; `crates/axiam-api-rest/tests/scim_targets_test.rs` `a_bearer_credential_does_not_follow_the_base_url_to_another_one`, `a_client_secret_does_not_follow_the_token_url_nor_a_switch_of_kind`; `crates/axiam-scim/tests/outbound_scim_test.rs` `a_target_changed_between_the_read_and_the_send_is_a_retry_and_sends_nothing`, `a_redirect_is_a_retry_and_is_never_followed` (301, 302, 307 and 308: the `Location` host receives nothing), `the_client_credentials_token_is_fetched_once_and_reused`; `crates/axiam-scim/src/outbound/client.rs` `the_cache_is_per_target_version_and_flushable`; `crates/axiam-scim/src/outbound/deliverer.rs` `the_outbound_modules_use_the_no_redirect_guarded_fetch_and_nothing_else` (one call site across the five outbound modules, no redirect-following guard, no other HTTP client); `crates/axiam-pki/src/ssrf.rs` `no_redirect_returns_a_3xx_and_never_fetches_its_target`. Residuals: the second read and the send are not one step, and the requests of one attempt (a `POST`, the `GET` that adopts on `409`, the `PATCH` after it) or of one reconciliation run reuse the header opened at its start — always with the URLs of the version that header was checked against, so the credential and its URL still belong together. A client-credentials target's `base_url` is outside the binding by decision; what that lets reach another host is the access token rather than the secret, and T-409 carries it."
      },
      {
       "number": 409,
       "title": "An access token minted with the stored client secret follows a base URL moved without it",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A client-credentials target's secret goes to `token_url`, but every SCIM request carries the access token AXIAM obtained with it, and a write that moves `base_url` also moves `updated_at`, so the next attempt fetches a fresh token from the unchanged `token_url` and presents it to the new `base_url`. Were `base_url` free to move without the secret, an administrator who may change the target, and was never given its secret, could point it at a host they run and collect a live access token for the real downstream — usable there for its whole lifetime and with whatever the downstream grants AXIAM, which is more than AXIAM itself ever does with it (AXIAM touches no account whose `externalId` is not one of its tenant's, T-413). D-57 as first written bound the secret to `token_url` only, and contract §31.3 rule 2 called `base_url` “not the credential's destination”.",
       "mitigation": "Built (the W5 F4 review, P23W5-01; D-57 amended, contract 1.57 §31.3 rule 2 amended in place). A client-credentials target's secret is bound to `base_url` as well as to `token_url`: a write that moves either without the secret in the same write is `400` naming the field and changes nothing — in the repository, checked against the very row its conditional write replaces (T-416), and in the handler; the console asks for the secret as soon as either URL is edited. With the secret re-entered the move is an ordinary write; the token cache is keyed by the target's version, so no token minted for the old base outlives it. The move stays a human-only, audited write (T-411, T-420) to a public host (T-410). Tests: `crates/axiam-db/tests/scim_target_repository_test.rs` `a_client_credentials_base_url_needs_the_credential_too` (it replaced `a_client_credentials_base_url_may_change_without_the_credential`, and failed before the fix), `changing_a_client_credentials_token_url_needs_the_credential`; `crates/axiam-api-rest/tests/scim_targets_test.rs` `a_client_secret_does_not_follow_the_token_url_nor_a_switch_of_kind`; `frontend/src/services/scimTargets.test.ts` (`credentialRequiredFor`); `frontend/src/pages/scim-targets/ScimTargetsPage.test.tsx` `requires the secret again when a client-credentials target's base URL or token URL changes`. Residual: a token AXIAM already obtained is the downstream's and stays valid there for as long as its issuer says; AXIAM never sends it to another base and uses one for at most an hour."
      },
      {
       "number": 410,
       "title": "The SCIM base URL or token URL is used to reach internal services",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "A tenant administrator chooses `base_url` and, for a client-credentials target, `token_url`, and AXIAM sends requests to both from inside the deployment — with a credential attached, and, for reconciliation, reading the answers. Pointed at a metadata service, a loopback admin port or a private address, or at a public name that resolves to one, the deliverer becomes a request forger with a credential, and the target's delivery state an oracle for what answered.",
       "mitigation": "Built (T23.6.2, T23.6.4; D-57). **Write time**: both URLs are held to the webhook outbound address policy (`validate_push_endpoint`, as SSF push endpoints are, T-392): absolute `https`, a host, no userinfo or fragment, at most 2 048 bytes, no IP literal that is not globally routable (loopback, private, link-local, the metadata address, IPv4-mapped forms), no `localhost`, `*.localhost`, `*.local` or `*.internal`; a refused URL is `400` naming the field and is never echoed. **Delivery time**: every request — SCIM calls, reconciliation's listing and the OAuth2 token request alike — goes through `guarded_fetch_no_redirect` with `allow_private = false`, which only a hidden test seam sets: the name is resolved fresh, every address must be globally routable, the validated address is pinned into the connection, `https` is required, a `3xx` is returned and never followed, a request gets ten seconds, and a body is read to at most 64 KiB (1 MiB for a list). A name the write-time policy admitted that resolves to an internal address is caught here. What is recorded on the target's state and in the audit row is a fixed phrase (“the endpoint resolves to an address AXIAM does not connect to”), never the transport error's text, a URL or a body. Tests: `crates/axiam-api-rest/tests/scim_targets_test.rs` `a_base_url_or_token_url_that_breaks_the_outbound_address_policy_is_400_and_never_echoed`; `crates/axiam-scim/tests/outbound_scim_test.rs` `the_production_deliverer_refuses_a_loopback_endpoint` (the production deliverer: nothing reaches the loopback server); `crates/axiam-scim/tests/outbound_reconcile_test.rs` `the_production_deliverer_reads_no_loopback_downstream`; `crates/axiam-scim/src/outbound/deliverer.rs` `the_outbound_modules_use_the_no_redirect_guarded_fetch_and_nothing_else` (one guarded call; `allow_private` false but in the hidden seam); `crates/axiam-scim/src/outbound/client.rs` `a_transport_reason_never_carries_the_error_text`; `crates/axiam-pki/src/ssrf.rs` `no_redirect_keeps_the_guard_on_the_one_hop`, `no_redirect_returns_a_redirect_to_an_internal_address_without_fetching_it`, `no_redirect_honours_the_content_length_cap`. Residuals: the guard honours the operator's `AXIAM__PKI__SSRF_ALLOWED_HOSTS` exception (SEC-107) exactly as it does for webhooks and SSF; and the fixed phrases still tell an administrator, through `state`, whether a name was blocked, did not resolve or did not answer — what a public DNS lookup tells anyone."
      },
      {
       "number": 411,
       "title": "Cross-tenant or non-administrator access to a target, its links or its state",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "Targets, link rows and delivery state of every tenant live in shared tables, and a target decides where a tenant's people are sent and holds the credential to send them. A tenant administrator who could name another tenant's target — in a path, or another tenant's group in a scope — or a service account, a machine token or a principal allowed only to read, could repoint another tenant's directory, read where it goes, enrol another tenant's group into a push, or start reconciliations against it.",
       "mitigation": "Built (T23.6.1, T23.6.4). The tenant is the token's, never the request's: every route answers `404` for another tenant's target, exactly as for one that does not exist, and changes nothing; every repository verb of the three tables is tenant-scoped in its `WHERE`, so a foreign id is `NotFound` to every read, update, delete, credential opening and delivery-state write. A `groups` scope may name only groups of this tenant (`400` otherwise), on create and on replace. The namespace is **human-only**: `scim_targets:read` for `list` and `get`, `scim_targets:write` for the four writes, both in a `HUMAN_ONLY_FAMILIES` family, so a service-account token is `401` at the extractor whatever roles it holds (contract §31.3 rule 9). Tests: `crates/axiam-db/tests/scim_target_repository_test.rs` `every_verb_is_tenant_scoped`, `deleting_a_target_removes_its_links_and_state_and_only_its_own`, `the_tenant_delete_takes_the_tenants_scim_rows_and_only_those`; `crates/axiam-api-rest/tests/scim_targets_test.rs` `another_tenants_target_is_404_on_every_route_and_is_not_touched`, `a_group_scope_cannot_name_another_tenants_group_even_when_replacing`, `reads_need_scim_targets_read_and_writes_need_scim_targets_write`, `a_service_account_token_is_refused_on_every_route_even_with_every_role`, `the_family_is_human_only_and_every_route_requires_its_permission`. Residual: inside its own tenant an administrator holding `scim_targets:write` is trusted to choose where its people go (assumption 7); T-412 states what that trust covers."
      },
      {
       "number": 417,
       "title": "The provisioning queue is flooded, or AXIAM and a downstream feed each other in a loop",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Every user or group change of a tenant becomes work for every enabled target: a directory sync that touches thousands of accounts, a bulk import, a reconciliation that queues the whole tenant. And a downstream that is also an inbound SCIM client of AXIAM — an identity provider that receives AXIAM's pushes and pushes its own changes to `/scim/v2` — could turn each push into a write back into AXIAM, which reports the change, which is pushed again, without end.",
       "mitigation": "Built (T23.6.2, T23.6.3; D-57). **One reference per change per target**: the repositories report only after a committed write, a user `update` only when it writes a provisioned field (username, email, status, the name and display metadata), and login bookkeeping never. **Level-triggered and idempotent**: the deliverer computes the representation at the attempt and skips the `PATCH` when its digest equals the link's `synced_digest`, so a reference whose change was already sent — a duplicate, a retry, a reconciliation, or the echo of AXIAM's own push coming back through inbound SCIM — sends nothing, and a loop stops after one round trip because the echo carries what AXIAM sent. **Bounded per kind**: `scim_push` has a topology of its own, so a backlog delays only SCIM pushes, and the per-kind ceiling (`AXIAM__SCIM_PUSH__MAX_ATTEMPTS`, exponential backoff with a ceiling, then the dead-letter queue); a broker that refuses a reference costs one log line per report and never fails the write that reported it. Tests: `crates/axiam-db/tests/provisioning_sink_test.rs` `user_update_reports_only_a_change_to_a_provisioned_field`, `login_bookkeeping_never_reports`, `a_failed_write_reports_nothing`; `crates/axiam-scim/tests/outbound_scim_test.rs` `rename_propagates_as_patch_and_an_unchanged_resync_sends_nothing`, `a_5xx_and_a_429_retry_and_are_recorded_as_failures`; `crates/axiam-scim/tests/outbound_provisioner_test.rs` `a_user_change_enqueues_one_reference_per_enabled_target_of_the_tenant`, `a_tenant_with_no_target_enqueues_nothing`, `a_broker_that_is_down_never_fails_the_report`; `crates/axiam-scim/tests/outbound_reconcile_test.rs` `reconciliation_queues_references_only`; `crates/axiam-amqp/src/outbound/topology.rs` `the_scim_push_declaration_is_pinned`; `crates/axiam-amqp/src/outbound/retry.rs` `backoff_doubles_and_clamps` (the shared schedule). Residuals. A change is reported when a provisioned field is **written**, not only when its value changes, so an inbound SCIM client that rewrites every user queues one reference per user per target — each of which then sends nothing. A downstream that normalises a value (the case of an address) and writes it back changes AXIAM's copy once and converges on the next push; one that transforms a value differently every time keeps the loop going at the rate of its own inbound writes, which the `/scim/v2` bucket (600 a minute per address) bounds and nothing in AXIAM detects. Every attempt, a no-op included, writes a `scim_push.delivery_*` audit row, so the nightly reconciliation adds one row per in-scope resource per target per day, bounded by audit retention (T-119)."
      },
      {
       "number": 419,
       "title": "Reconciliation runs twice across replicas, or is driven in a loop",
       "type": "Denial of service",
       "severity": "Low",
       "status": "Mitigated",
       "description": "A reconciliation run queues a reference for every resource in scope and pages the downstream with AXIAM's credential. Run by every replica's cleanup loop at once, or started on demand again and again, it would multiply the queue, the downstream's load and the audit trail, and two runs adopting and dropping the same links at once could undo each other's repairs.",
       "mitigation": "Built (T23.6.1, T23.6.3, T23.6.4; D-58). A run first **claims** the target with a conditional write on `scim_target_state.last_reconciled_at` (the `claim_verification` pattern): one caller wins per interval across every replica, and the others match nothing. The scheduled job `scim_reconcile` (in the cleanup loop, registered in `SWEEP_JOBS`) claims for 24 hours; the on-demand `POST …/reconcile` claims for five minutes — the longest a run may take — and answers `409` while a run holds the claim or ran within it, `409` for a disabled target (no claim taken), and otherwise `202`, with the run on a task of its own. The route has its own bucket (`AXIAM__RATE_LIMIT__SCIM_TARGET_ADMIN_PER_MIN`, 30 a minute, never moved by a profile), needs `scim_targets:write` (T-411) and is audited (T-420). Tests: `crates/axiam-db/tests/scim_target_repository_test.rs` `claim_reconciliation_succeeds_once_within_the_interval`, `concurrent_claims_have_one_winner`; `crates/axiam-scim/tests/outbound_reconcile_test.rs` `a_second_run_within_the_interval_is_already_claimed_and_does_nothing`, `two_concurrent_requests_make_one_run`, `the_scheduled_job_runs_a_due_target_once_a_day_and_the_on_demand_entry_sees_its_claim`, `a_disabled_target_is_not_reconciled_and_its_claim_is_not_taken`, `a_background_start_answers_at_the_claim_and_the_run_finishes_on_its_own`; `crates/axiam-api-rest/tests/scim_targets_test.rs` `reconcile_now_is_202_when_claimed_then_409_while_the_claim_is_held`, `reconcile_now_on_a_disabled_target_is_409_and_on_an_unknown_one_404`, `every_write_route_has_its_own_bucket_and_reads_are_not_limited`, `the_shipped_bucket_is_thirty_a_minute`; `crates/axiam-server/tests/scim_reconcile_sweep_test.rs` `the_sweep_reconciles_a_due_target_once_and_reports_a_failed_run`; `crates/axiam-server/src/job_health.rs` `the_slo_sweeps_are_recorded_by_the_cleanup_loop_and_registered` (extended to `scim_reconcile`). Residuals: the claim stamps the **start** of a run and nothing marks its end, so a run that dies half way waits for the next interval (a day, or five minutes on demand); and an administrator can start one run per target every five minutes, each bounded by its page and time budgets (T-414)."
      },
      {
       "number": 420,
       "title": "Target changes and deliveries are not attributable",
       "type": "Repudiation",
       "severity": "Low",
       "status": "Mitigated",
       "description": "Where a tenant's people are sent is a security and a data-protection decision. Without a record, a target repointed at a collection host, a scope widened to everyone, a credential replaced, a reconciliation started, or a stream of deliveries a downstream later disputes could not be traced to the administrator or the attempt behind it.",
       "mitigation": "Built (T23.6.2, T23.6.4). One audit row per write, with the administrator as actor: `scim_target.created`, `scim_target.updated` (the **names** of the changed fields, and whether the credential was replaced), `scim_target.deleted` and `scim_target.reconcile_requested` — never a URL, never the credential. Every delivery attempt writes the dispatcher's row, with the system actor and a fixed-vocabulary reason: `scim_push.delivery_succeeded`, `.delivery_attempt`, `.delivery_failed`; the target's `state` counts failures and dead letters once each, and a reconciliation run logs its findings as one line. Tests: `crates/axiam-api-rest/tests/scim_targets_test.rs` `every_write_is_audited_with_names_never_a_url_or_the_credential`; `crates/axiam-scim/tests/outbound_reconcile_test.rs` `a_dead_letter_writes_the_counter_and_the_reason_once`, `the_last_retryable_attempt_is_counted_as_the_dead_letter_the_consumer_makes_of_it`; `crates/axiam-amqp/src/outbound/consumer.rs` `audit_entry_uses_the_system_actor_and_the_kind_prefix`. Residual: a reconciliation's repairs (digests cleared, links dropped, accounts adopted for deprovisioning) are counts in a log line, not audit rows; the deliveries they cause are audited one by one."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "833f36e5-7889-59c2-ac8f-1c476fa445fa",
     "kind": "store",
     "x": 1079,
     "y": 1154,
     "w": 170,
     "h": 80,
     "name": "scim_target + scim_target_link + scim_target_state",
     "lines": [
      "scim_target +",
      "scim_target_link +",
      "scim_target_state"
     ],
     "description": "Schema v79 (T23.6.1, D-57): `scim_target` (the registry; the credential sealed under `pki_encryption_key`, write-only), `scim_target_link` (an AXIAM id and the downstream id per target, unique on both, the digest of the last representation sent, `erase_pending`; ids only) and `scim_target_state` (delivery counters, the last failure in a fixed vocabulary, the reconciliation claim; written only atomically, never by the administrator). The push kind's broker queues (`axiam.scim_push`, `.retry`, `.dlq`) hold only references (`{resource_type, axiam_id}`) and are drawn with the store rather than as an element of their own.",
     "outOfScope": false,
     "threats": [
      {
       "number": 407,
       "title": "The target credential is disclosed at rest, in a response or in a log",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "A SCIM target holds a credential to a third party: the bearer token AXIAM presents to the downstream SCIM service provider, or the OAuth2 client secret it exchanges there for an access token. It is a key to the tenant's downstream directory: whoever reads it — from the datastore or a backup, a management response, a log line, an error or a `Debug` print — can create, change and delete accounts there as AXIAM, without AXIAM ever being involved.",
       "mitigation": "Built (T23.6.1, T23.6.4; D-57, in D-49's shape). Sealed with AES-256-GCM under `pki_encryption_key` (the key webhook secrets and SSF push headers use) with a fresh nonce per write, nonce and ciphertext in their own columns and a key version. Every read projects `PUBLIC_COLUMNS`, so the ciphertext leaves the datastore only through `ScimTargetRepository::decrypt_credential`, which only the deliverer calls; a value sealed under another key does not open. `ScimTarget` has no member for it, the write inputs redact it from `Debug`, the management API never returns it (no member of `ScimTargetResponse` says anything about it), audit rows name the field and whether the credential was replaced, never the value, and contract §31.5 makes it `Sensitive<T>`. Without the key, a write that carries a credential (every `create`) is `503` and stores nothing, while reads, `delete` and an update without a credential still answer. On the wire it is a header value marked sensitive; the client-credentials access token lives in memory only, per target version, for at most one hour, and is never persisted. Failure reasons are a fixed vocabulary, never a URL, a body or a value. Tests: `crates/axiam-db/tests/scim_target_repository_test.rs` `create_round_trips_every_field_and_never_reads_the_credential_back`, `decrypt_credential_round_trips`, `create_without_the_key_fails_closed_and_stores_nothing`, `an_update_that_supplies_a_credential_without_the_key_fails_closed`, `a_credential_sealed_under_another_key_does_not_open`; `crates/axiam-core/src/models/scim_target.rs` `the_target_serializes_with_the_decided_names_and_no_credential_member`, `debug_of_the_write_inputs_never_prints_the_credential`; `crates/axiam-api-rest/tests/scim_targets_test.rs` `a_client_credentials_target_round_trips_and_shows_its_token_endpoint_but_no_secret`, `without_the_sealing_key_a_credential_cannot_be_stored`, `every_write_is_audited_with_names_never_a_url_or_the_credential`; `crates/axiam-scim/tests/outbound_scim_test.rs` `no_reason_state_row_or_message_carries_a_credential_or_a_person`; `crates/axiam-scim/src/outbound/client.rs` `a_transport_reason_never_carries_the_error_text`, `a_token_lifetime_is_capped_at_one_hour`. Residual: `pki_encryption_key` together with the datastore opens every target's credential, as it opens every webhook secret and SSF push header; and once sent, the credential is the downstream's to keep — T-408 bounds where it is sent."
      },
      {
       "number": 415,
       "title": "An erased person lingers downstream, in AXIAM's queues or in its link rows",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Provisioning copies a person to a third party. An Art. 17 erasure or an administrator's delete that ended at AXIAM's own tables would leave the person in every downstream directory; a `DELETE` that failed once, with nothing remembering it, would leave them there for good; and the machinery that carries the `DELETE` — queued messages, the dead-letter queue, the link row that knows the downstream id — would itself keep something of the person after the erasure.",
       "mitigation": "Built (T23.6.2, T23.6.3; D-57, D-58). **Propagated**: `anonymize_user` and the delete path report to the provisioning sink like every other write, and the deliverer sends `DELETE` for an account that is `Deleted`, `Anonymized` or gone, **whatever** `deprovision` says; a `404` counts as done. **Remembered until it lands**: the link row survives the erasure cascade until that `DELETE` succeeds; an attempt that does not end in one (refused, retried, out of attempts) leaves the link `deprovisioned` with `erase_pending`; reconciliation re-queues every linked resource, so the `DELETE` is retried nightly until it lands, and a downstream account whose `externalId` names an erased user of this tenant is deleted when reconciliation finds it. **Nothing personal waits**: a queued message is `{resource_type, axiam_id}` and nothing else, the deliverer reads the person at the attempt, a link row holds ids and a digest, and `axiam.scim_push.dlq` drops a message seven days after it arrives (`x-message-ttl` 604 800 000 ms). `docs/compliance/gdpr-compliance.md` names the link table. Tests: `crates/axiam-server/tests/scim_erasure_propagation_test.rs` `an_erased_user_is_deleted_downstream_and_only_then_loses_the_link`, `a_failing_downstream_is_retried_and_the_link_goes_when_the_delete_succeeds`, `a_refused_erasure_keeps_the_link_pending_until_reconciliation_succeeds`, `the_admin_delete_endpoint_anonymises_and_deletes_downstream`; `crates/axiam-scim/tests/outbound_scim_test.rs` `a_deleted_user_is_deleted_downstream_whatever_the_policy_and_the_link_goes`, `an_anonymized_user_is_deleted_downstream_whatever_the_policy_and_the_link_goes`, `a_downstream_that_already_lost_the_user_counts_an_erasure_delete_as_done`, `no_attribute_of_a_person_is_ever_enqueued`; `crates/axiam-scim/tests/outbound_reconcile_test.rs` `a_pending_erasure_is_retried_by_reconciliation_until_the_delete_succeeds`, `an_erased_user_of_this_tenant_that_survives_downstream_is_deleted`, `reconciliation_queues_references_only`; `crates/axiam-db/tests/provisioning_sink_test.rs` `user_delete_and_anonymize_report_the_user`; `crates/axiam-amqp/src/outbound/topology.rs` `the_scim_push_declaration_is_pinned`, `only_the_ssf_push_and_scim_push_dlqs_have_a_message_ttl`. Residuals, stated rather than hidden. **Deleting a target** removes its links and state and deprovisions nothing downstream (contract §31.3 rule 8; the console says so before it deletes): the people AXIAM created there stay, a pending erasure included, and AXIAM no longer knows them — an administrator who wants them gone sets `deprovision` to `delete` and lets AXIAM push before deleting the target; deleting the tenant leaves the downstream the same way. **A downstream that refuses every `DELETE`** keeps the person; AXIAM retries nightly and says so on `state` and, where a rule asks, by mail (T-418). **A disabled target** sends nothing, an erasure included, until it is enabled again, which starts a reconciliation. An id in a dead-lettered reference lives up to seven days; the primary and retry queues declare no TTL and hold a reference through its retry schedule, or for as long as no consumer runs."
      },
      {
       "number": 416,
       "title": "A target write that overlaps another, or a delivery, puts back what the other changed",
       "type": "Tampering",
       "severity": "Low",
       "status": "Mitigated",
       "description": "Three writers meet on a target: administrators replacing its configuration, the deliverer recording each attempt, and reconciliation claiming runs and adopting links. Read-modify-write among them (T-406's class) would let a replacement prepared before another land after it and put back the old URL, scope or `enabled`; let a delivery's bookkeeping overwrite an administrator's change; lose dead-letter counts when many deliveries finish at once; or let two attempts link one resource twice.",
       "mitigation": "Built (T23.6.1, T23.6.4; D-57, T-406's rule). A replacement is conditional on the `updated_at` the route read for that request (`ScimTargetUpdate::expected_updated_at`): a write landing in between makes it change nothing, and it answers `409` (contract §31.3 rule 4). The deliverer and reconciliation **never write the target row**: delivery state lives in `scim_target_state`, written only with atomic increments and plain sets, retried on a write conflict up to 32 times so that no count is lost; the reconciliation claim is a conditional write (T-419). Links are written through both unique indexes, and an attempt that finds the resource linked meanwhile keeps that link if it names the same downstream id and retries otherwise. The deliverer reads the target again before the credential leaves (T-408). Tests: `crates/axiam-db/tests/scim_target_repository_test.rs` `a_stale_expected_updated_at_is_a_conflict_and_writes_nothing`, `update_with_the_current_version_writes_and_moves_the_version`, `an_update_of_a_missing_target_is_not_found_not_a_conflict`, `concurrent_dead_letters_are_all_counted`, `concurrent_failures_are_all_counted`, `the_link_unique_indexes_hold_on_both_axes`; `crates/axiam-api-rest/tests/scim_targets_test.rs` `a_replacement_overtaken_by_another_is_409_and_does_not_land`, `two_reads_then_two_writes_the_second_is_a_conflict`; `crates/axiam-scim/tests/outbound_scim_test.rs` `a_target_changed_between_the_read_and_the_send_is_a_retry_and_sends_nothing`. Residuals: the `PUT` carries no version from the client, so an administrator who saves a form loaded before another administrator's save replaces that save whole — last writer wins between two humans, each audited with the names of what it changed (T-420), and never a way to move the credential, whose binding is checked against the stored row (T-408). An attempt under way when an administrator narrows the scope or disables the target finishes on the version it read, and so does a reconciliation run, for up to its five-minute budget; the next attempt sees the change."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 1,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "c5f29b0a-ce93-5eed-b6fa-46dc9d9ba5b2",
     "path": "M374.5,872.7 L199,894.6",
     "name": "SET push / poll response",
     "description": "",
     "label": "SET push / poll response (HTTPS, RFC 8935 / 8936)",
     "labelLines": [
      "SET push / poll response (HTTPS, RFC",
      "8935 / 8936)"
     ],
     "lx": 286.8,
     "ly": 883.7,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS, RFC 8935 / 8936",
     "threats": [
      {
       "number": 387,
       "title": "A forged SET is accepted by a receiver",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "A receiver acts on a session-revoked, account-disabled or credential-change event by logging users out or locking accounts. Anyone who can make a receiver accept a SET AXIAM did not sign — an unsigned token, `alg: none`, a key the attacker chose, or a token for a different issuer — can log out or lock out any user of the relying party.",
       "mitigation": "Every SET is a JWS signed with the deployment's Ed25519 key (D-13), `alg: EdDSA`, `typ: secevent+jwt` and the `kid` the tenant's `jwks_uri` publishes; `sign_set` is the only signer and nothing unsigned is ever sent. `iss` is the tenant's issuer, identical to the transmitter metadata's `issuer` (SSF §4.1.6), which a receiver pins. Verification is the receiver's: contract §32.7 makes the optional receiver helper verify the signature against the JWKS, `typ`, `iss` and `aud` before anything else. Tests: `crates/axiam-oauth2/src/ssf.rs` `a_set_verifies_against_the_published_jwks_with_the_pinned_header_and_claims`, `a_set_does_not_verify_for_another_audience_or_issuer`, `the_issuer_follows_the_tenant_issuer_mode`. Forging still needs the deployment key, a principal asset."
      },
      {
       "number": 388,
       "title": "A captured SET is replayed to its receiver",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Open",
       "description": "A SET carries no `exp` (SSF §4.1.7 forbids it), so a SET captured in transit, from a receiver's logs or from a misrouted push stays valid forever. Replayed later, a session-revoked or account-disabled SET logs out or locks out its subject again.",
       "mitigation": "AXIAM's half is built: every SET has a fresh 128-bit `jti` from the OS CSPRNG, and a retried push or a repeated poll re-signs the same pending event to byte-identical SET (Ed25519 is deterministic), so one event is one `jti` (D-48). Tests: `crates/axiam-oauth2/src/ssf.rs` `every_jti_is_unique`, `signing_the_same_pending_event_twice_gives_the_same_set`. Push travels over TLS to an `https` endpoint only, and poll responses are `no-store`. Open because the control is the receiver's: RFC 8417 §4.1 / contract §32.7 require it to remember the `jti`s it processed and refuse a repeat, and the receiver helper that does so ships in the SDKs only after the post-merge fan-out (D-35); a receiver that does not de-duplicate stays exposed for as long as it treats an old SET as news."
      },
      {
       "number": 390,
       "title": "A SET is addressed to the wrong receiver",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "On a deployment without per-tenant issuer paths every tenant's SETs carry the same `iss` and are signed with the same key. If two streams — in two tenants — could share an audience, a tenant administrator could register a stream with another tenant's receiver audience, collect SETs about users they created (an email subject a victim also uses, say) and replay them to that receiver, which would accept them: right key, right issuer, right audience.",
       "mitigation": "The audience is unique **across the deployment**, enforced by the datastore (`idx_ssf_stream_audience` UNIQUE on `audience` alone, D-47): a second registration in any tenant is `409` without saying where. `aud` is the stream's audience, one string, never a list. **Tenants never share an issuer while SSF runs** (D-55, F4 W4 P23W4-11, the maintainer's decision on ilpanich/axiam#539): with tenant issuer paths `iss` is the tenant's own issuer; without them SSF runs only while the deployment holds a single tenant. The shared-issuer gate (`axiam_oauth2::ssf::SsfIssuerGate`) holds when paths are off **and** the deployment holds more than one tenant, counted across every organization; while it holds SSF behaves for every tenant as with `ssf_enabled` off, checked where an event is produced (the emitter), where a SET is signed (`sign_set` refuses, so a queued push is dead-lettered unsigned and a poll answers nothing) and at discovery (one empty `404`), never only at write time; turning `ssf_enabled` on while it holds is `400` naming the cause, and a stream and the settings API say SSF is inactive and why. A change is logged once at `WARN` and audited as `ssf.inactive_shared_issuer` per tenant with SSF on. So a squatted audience no longer buys SETs a receiver accepts on the issuer: either no tenant's SETs exist, or the squatter's carry its own tenant's `iss`, which a receiver checks (contract §32.7 step 6). Tests: `crates/axiam-db/tests/ssf_stream_repository_test.rs` `the_audience_is_unique_across_every_tenant`, `the_shared_issuer_count_spans_organizations_and_moves_the_generation`; `crates/axiam-api-rest/tests/ssf_test.rs` `an_audience_is_unique_across_tenants_and_a_header_needs_the_sealing_key`; `crates/axiam-api-rest/tests/ssf_shared_issuer_test.rs` `with_paths_off_and_two_tenants_ssf_behaves_as_switched_off` (discovery, stream, poll and verification `404`, no emission), `with_paths_off_and_two_tenants_turning_ssf_on_is_refused`, `with_paths_off_and_two_tenants_a_tenant_cannot_turn_ssf_back_on`, `with_paths_off_and_two_tenants_a_stream_and_the_settings_say_why`, `a_second_tenant_created_in_process_stops_ssf_without_waiting_for_the_cache`, `with_paths_off_and_one_tenant_turning_ssf_on_is_accepted`, `with_paths_on_two_tenants_keep_ssf_and_their_own_issuers` and `production_code_takes_the_issuer_check_only_from_the_gate`; `crates/axiam-api-rest/tests/ssf_shared_issuer_log_test.rs` `the_gate_is_logged_once_and_audited_per_tenant`; `crates/axiam-oauth2/tests/ssf_delivery_test.rs` `while_tenants_share_one_issuer_a_queued_push_is_dead_lettered_unsigned`, `with_tenant_issuers_two_tenants_still_deliver`; `crates/axiam-oauth2/src/ssf.rs` `a_set_does_not_verify_for_another_audience_or_issuer`, `sign_set_refuses_while_the_shared_issuer_gate_holds`, `with_tenant_issuers_a_set_of_one_tenant_does_not_verify_as_anothers`, `the_gate_caches_the_count_follows_the_generation_and_reports_each_change_once`. Residual: the tenant count is read from the datastore and reused for at most 60 s, so a second tenant created on **another** replica stops SSF there within a minute (at once on the replica that created it) and a SET signed in that minute still carries the root issuer; a single-tenant deployment keeps the root issuer and needs no gate, since no other tenant shares it, and an organization's own scope tenant is not counted beside its standard tenants because its principals already administer every tenant of their organization. An audience can still be squatted before its owner registers it; the legitimate registration then fails with `409`, which is how the squat is noticed, and the website's SSF page tells receivers to take `aud` from their stream, require the push header and check `iss`."
      },
      {
       "number": 394,
       "title": "A receiver is flooded with events",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "One administrative act can produce many SETs — revoking every session of a user, disabling accounts in bulk, a directory sync that deactivates hundreds. Pushed without a bound, or retried without a ceiling against a receiver that is slow or down, they overload the receiver and the dispatcher's queue.",
       "mitigation": "Built (T23.5.3, 2026-10-04; D-48, D-52). One SET per event per stream, and only for a stream that carries the event (the emitter lists `list_for_event`, then `prepare_event` checks again); push goes through the shared outbound dispatcher (D-36) as `OutboundKind::SsfPush` with queues of its own and the per-kind ceiling (`AXIAM__SSF_PUSH__MAX_ATTEMPTS`, exponential backoff with a ceiling, then the dead-letter queue), one attempt per message, so a receiver that is down receives a bounded number of attempts per event and never a retry storm. An answer that cannot change on retry — a `400` with an RFC 8935 error code, `401`, `403` — is dead-lettered at once instead of spending the budget. A paused stream receives nothing: its events are held in the bounded buffer; a disabled stream receives nothing and its queued events are dead-lettered. A retried push carries the byte-identical SET, one `jti`. Tests: `crates/axiam-oauth2/tests/ssf_delivery_test.rs` `the_retryable_statuses_are_retried`, `a_400_with_an_rfc_8935_error_is_dead_lettered_with_the_code`, `a_refused_credential_is_dead_lettered`, `a_disabled_stream_delivers_nothing_and_a_queued_event_is_dead_lettered`, `a_paused_stream_moves_the_event_to_the_buffer_and_acknowledges`, `a_retried_push_carries_the_identical_set`, `resuming_a_paused_push_stream_enqueues_the_held_events_oldest_first`; `crates/axiam-api-rest/tests/ssf_test.rs` `a_logout_reports_session_revoked_to_the_streams_that_carry_it` (a disabled stream, another tenant's and one that did not ask for the event are not sent to), `a_disabled_stream_delivers_and_holds_nothing`, `a_paused_stream_holds_and_delivers_on_resume`, `nothing_is_emitted_with_the_transmitter_off_or_no_stream_registered`; the dispatcher's retry schedule, attempt ceiling and dead-letter queue are pinned by `axiam-amqp`'s outbound tests (T23.5.1). The residual is by design: a mass revocation is as many SETs as sessions (SSF has no batching), and a receiver that answers `2xx` slowly is sent every event."
      },
      {
       "number": 396,
       "title": "Subject identifiers disclose or link personal data",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A SET names a person. An identifier that is an email address, or one that is the same at every receiver, lets receivers that compare notes follow a user across relying parties, and an address AXIAM never checked lets an attacker who registered it pass as its owner at an email-keyed receiver.",
       "mitigation": "D-46: `iss_sub` by default — the tenant issuer and the user id, which is the `sub` AXIAM's ID tokens already give every relying party (`subject_types_supported: public`), so SSF discloses no linkage a receiver did not hold. `email` only when an administrator chose it for the stream (a receiver cannot), and only for an address something vouched for — D-25's rule, `email_verified_at` set or the account `Active`; for any other account the event is not sent on that stream, never with another identifier. No event carries free text (`reason_admin`, `reason_user`, `friendly_name` are never sent), and the queue and the buffer hold only the subject member that will be sent. Tests: `crates/axiam-oauth2/src/ssf.rs` `both_subject_formats_are_rfc_9493_and_the_session_is_named`, `an_unvouched_address_is_never_sent_and_nothing_else_replaces_it`, `the_vouching_rule_is_d25s`, `each_of_the_six_events_has_its_pinned_shape`. Residual: a buffered event for an erased user keeps its subject member until it is acknowledged or expires (seven days); T-402 carries it, with the dead-letter queue."
      },
      {
       "number": 398,
       "title": "An event is delivered on a stream that was disabled or narrowed",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Delivery is asynchronous: an event can wait in the queue or the buffer while an administrator disables the stream, the receiver narrows its events, or the stream is deleted. Delivering it anyway sends personal data to a receiver that is no longer meant to have it.",
       "mitigation": "What travels is the **unsigned** pending event (D-48); the SET is signed by `sign_set` at the moment of delivery against the stream as it is then, and it refuses a stream that is not enabled or no longer carries the event — a disabled stream delivers nothing, a paused one holds, a narrowed one drops (D-51). The only event a non-enabled stream can sign is the stream-updated announcement of the status it is in (SSF §8.1.5). Tests: `crates/axiam-oauth2/src/ssf.rs` `no_set_for_a_disabled_or_paused_stream_or_an_event_it_does_not_carry`, `a_stream_updated_event_may_only_announce_the_current_status`; `crates/axiam-api-rest/tests/ssf_test.rs` `verification_needs_a_live_stream_and_a_wired_outbox`, `an_admin_status_change_announces_the_new_status`. T23.5.3's e2e test (a disabled stream delivers nothing) re-proves it end to end."
      },
      {
       "number": 405,
       "title": "A security event is lost and nobody is told",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Open",
       "description": "SSF signals exist so that a receiver can act on a change: end a session AXIAM revoked, stop trusting a disabled account. Production is best effort (D-52): an event that cannot be produced or queued is dropped with a log line, and the operation that caused it succeeds. A receiver that never hears of a revocation keeps the session it would have ended, and nothing tells it, the tenant or the user that an event was due.",
       "mitigation": "Accepted design trade-off (D-52, the webhook precedent): failing a logout, a password reset or an erasure because a receiver's queue is unavailable would trade a security action for the notice of it. Where an event can be lost, and what records it: a failure to read the streams, the tenant's settings or the subject, to prepare the event, to publish it to `axiam.ssf_push` or to write it to the buffer, and a step-up record that could not be written, each log a `WARN` on `axiam::ssf` and nothing else: no audit row, no counter. The buffer drops its oldest event at 1 000 (T-395) and the dead-letter queue its messages after seven days (T-402), both by design. What is not lost, in the full profile: once queued, push is at-least-once and a failed attempt retries on the dispatcher's schedule; every dead-lettered push writes an `ssf_push.delivery_failed` audit row with its reason; and a held event a poll cannot sign (the deployment key unusable) is logged at `ERROR` once per poll request (W4 F4, P23W4-03: a long poll used to log it on every half-second look) and stays in the buffer for the next poll, which answers an empty `sets` meanwhile. What bounds the consequence: a signal is a hint, never the only record. The website's SSF page (*Shared Signals (SSF) transmitter*, `#/docs/ssf`) tells receivers that production is best effort and to read the account's current state from AXIAM when they need certainty about it; an AXIAM access token still lives at most fifteen minutes; and where the revocation feed is on (T-39) the same session revocations reach SDK verifiers without SSF. Open because the loss is real and silent. A later decision could make it visible (a counter, or an audit row per event that was not queued) without making it fail the operation. In the minimal profile (`AXIAM__AMQP__ENABLED=false`, D-59) a queued push waits in an in-process queue and is lost on restart, and a dead letter is its audit row alone (T-445)."
      }
     ],
     "open": 2,
     "notApplicable": 0
    },
    {
     "id": "c18a02c4-5509-5935-9f28-9e14d95c1a2d",
     "path": "M199,894.6 L374.5,872.7",
     "name": "stream management + poll",
     "description": "",
     "label": "stream management + poll (HTTPS, client credentials)",
     "labelLines": [
      "stream management + poll (HTTPS,",
      "client credentials)"
     ],
     "lx": 286.8,
     "ly": 883.7,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS, client credentials",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "fa7ee1e5-990d-5faa-9f82-f7c132011459",
     "path": "M513.9,860.1 L1079,828.7",
     "name": "read / write streams, buffer",
     "description": "",
     "label": "read / write streams, buffer (SurrealQL)",
     "labelLines": [
      "read / write streams, buffer",
      "(SurrealQL)"
     ],
     "lx": 796.4,
     "ly": 844.4,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "dbedd6d1-2ad1-558f-91af-a1a4e13ff6bd",
     "path": "M374,1194 L199,1194",
     "name": "SCIM push / list",
     "description": "",
     "label": "SCIM push / list (HTTPS, RFC 7644)",
     "labelLines": [
      "SCIM push / list (HTTPS, RFC 7644)"
     ],
     "lx": 286.5,
     "ly": 1194,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS, RFC 7644",
     "threats": [
      {
       "number": 412,
       "title": "More people, or more about them, leave the tenant than the administrator chose",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A target pushes a tenant's people to a third party. Provisioning that reaches beyond the scope the administrator set — users outside the listed groups, groups never asked for, accounts that are not active, service accounts — or that carries more of a person than a directory needs (a password hash, factors, a telephone number, an address, free-form metadata), or that keeps sending after a target was disabled, discloses personal data the tenant never agreed to share. A tenant administrator exporting the tenant's directory to a SCIM endpoint of their choosing is the feature itself, so the threat is everything beyond that choice.",
       "mitigation": "Built (T23.6.2; D-57). **Who**: `all_users`, or `groups` — the direct members of up to 100 listed groups of this tenant; `push_groups` is off by default and, when on, pushes every group for `all_users` and only the listed ones otherwise; a group's `members` names only members already linked on that target, and a service account's membership is never reported. A user is created downstream only while `Active` and in scope — one who is not is never created inactive — and one who leaves scope or `Active` is deactivated or deleted per `deprovision`. A disabled target receives nothing: its queued references dead-letter (`target disabled`). **What**: a fixed attribute set, not a mapping language — `userName` (the username, or the email when the target says so), `name.givenName`, `name.familyName`, `displayName`, the primary email, `active` and `externalId` (the AXIAM id); an attribute AXIAM does not hold is omitted, and nothing else about a person is ever sent. Inside AXIAM only a reference travels (T-415). **The trust assumption**, stated rather than hidden (assumption 7): an administrator of the tenant holding `scim_targets:write` — a human (T-411) — decides which endpoint receives which of the tenant's people, and enabling a target starts a reconciliation that pushes everyone in scope at once; the choice is audited (T-420), shown in the console, and stated in contract §31. Tests: `crates/axiam-scim/tests/outbound_scim_test.rs` `create_propagates_as_post_with_the_axiam_id_as_external_id`, `the_user_name_follows_the_targets_mapping`, `a_change_to_a_name_the_mapping_carries_is_sent_and_one_it_does_not_is_not`, `a_user_entering_and_leaving_a_groups_scope_is_created_and_deprovisioned`, `group_membership_change_propagates_as_a_group_patch_of_linked_members`, `a_disabled_target_and_a_deleted_one_dead_letter`, `no_attribute_of_a_person_is_ever_enqueued`; `crates/axiam-scim/tests/outbound_provisioner_test.rs` `a_user_change_enqueues_one_reference_per_enabled_target_of_the_tenant`, `a_group_change_goes_only_to_targets_that_push_that_group`, `group_in_scope_is_push_groups_and_the_scope`; `crates/axiam-scim/src/outbound/wire.rs` `an_attribute_axiam_does_not_hold_is_omitted`, `a_patch_replaces_the_mapped_attributes_only`; `crates/axiam-db/tests/provisioning_sink_test.rs` `a_service_accounts_membership_is_not_provisioned`; `crates/axiam-api-rest/tests/scim_targets_test.rs` `a_group_scope_cannot_name_another_tenants_group_even_when_replacing`, `an_enabled_target_starts_a_reconciliation_when_created_or_switched_on`. Residual: what reaches a downstream is that downstream's to keep and protect; AXIAM's erasure reaches it (T-415), AXIAM's retention does not."
      },
      {
       "number": 413,
       "title": "A hostile or lying downstream steers what AXIAM links, overwrites or deprovisions",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The downstream's answers decide what AXIAM does next: the `id` of a created resource is linked and put into later paths, a `409` makes AXIAM look a resource up by `externalId` and adopt it, and reconciliation lists the downstream and repairs, re-creates or deprovisions what it finds. A downstream that lies — a compromised service provider, or one whose answers an attacker shapes — could try to make AXIAM adopt or overwrite an account that is not AXIAM's, deprovision accounts its own application created, link one AXIAM user to another's account, aim a later request at another path, or feed something back into AXIAM's directory.",
       "mitigation": "Built (T23.6.2, T23.6.3; D-57, D-58). **One way only**: nothing read from a downstream is ever written into an AXIAM user or group; an answer yields at most an id to link, a match to adopt or a digest to clear. **Adoption** takes exactly one resource whose `externalId` is the AXIAM id — a provider that ignores the filter and answers with everything matches nothing else — and none or several is a dead letter, `conflict`. **Links** are unique on (target, type, AXIAM id) and on (target, type, downstream id), so one downstream id never stands for two AXIAM resources. A downstream id is linked only if it is 1–256 bytes, not `.` or `..`, and free of control characters, and it is percent-encoded into every path, as the filter is into the query. **Reconciliation never touches** a downstream resource whose `externalId` is missing, not a UUID, or not the id of a resource of **this tenant** that should not be there; it deletes no account it did not create or adopt; an attribute the mapping does not carry is not drift; and only a listing read to its end may drop a link. What a lying downstream can do is to its own data: refuse, mis-report, or make AXIAM send again what it already holds. Tests: `crates/axiam-scim/tests/outbound_scim_test.rs` `a_409_on_post_adopts_the_resource_that_carries_our_external_id`, `a_409_with_no_resource_of_ours_dead_letters_as_a_conflict`, `a_404_on_patch_drops_the_link_and_retries_then_recreates`; `crates/axiam-scim/tests/outbound_reconcile_test.rs` `a_downstream_user_with_a_foreign_or_missing_external_id_is_never_touched`, `a_downstream_user_whose_external_id_is_a_user_of_another_tenant_is_untouched`, `an_unchanged_downstream_is_not_patched_and_attributes_it_owns_are_not_drift`, `an_unreachable_downstream_fails_the_run_without_dropping_anything`; `crates/axiam-scim/src/outbound/deliverer.rs` `a_downstream_id_that_could_redirect_a_path_is_not_linked`, `urls_are_built_from_the_base_with_the_id_and_filter_encoded`; `crates/axiam-db/tests/scim_target_repository_test.rs` `the_link_unique_indexes_hold_on_both_axes`. Residual: a downstream that answers `404` to every `PATCH`, or leaves a linked resource out of a complete listing, makes AXIAM drop the link and `POST` the person again — one more copy of what it already holds, on every attempt or every nightly run, bounded by T-414 and T-417."
      },
      {
       "number": 414,
       "title": "A downstream exhausts the deliverer or reconciliation with large, endless or slow answers",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "A downstream controls the size, the number and the pace of its answers. A response body without end, a list whose `totalResults` never runs out, pages that arrive slowly, or a group so large that its member list cannot travel in one request would hold the consumer, a reconciliation run or AXIAM's memory for as long as the downstream likes — and with it the provisioning of every other target behind it.",
       "mitigation": "Built (T23.6.2, T23.6.3; D-57, D-58). Every request has ten seconds, connect to last byte. A body is read to at most 64 KiB for a write and 1 MiB for a list; a larger one is a retry and is never buffered whole. A reconciliation run reads at most 100 pages of 100 per collection, for at most five minutes of wall clock, and a listing cut short by a budget is audited in part and never drops a link for what it did not reach. A group of more than 10 000 members dead-letters instead of being read whole, and AXIAM reads members 100 at a time. Retries follow the per-kind schedule (`AXIAM__SCIM_PUSH__*`: backoff with a ceiling, then the dead-letter queue), and `scim_push` has a topology of its own, so a slow downstream delays SCIM pushes and never webhooks or SSF events. Tests: `crates/axiam-scim/tests/outbound_reconcile_test.rs` `a_downstream_with_endless_pages_is_read_to_the_page_budget_and_no_link_is_dropped_for_it`, `a_large_downstream_is_read_in_pages_of_a_hundred`, `an_unreachable_downstream_fails_the_run_without_dropping_anything`; `crates/axiam-scim/src/outbound/reconcile.rs` `the_budgets_are_the_decided_ones`; `crates/axiam-scim/tests/outbound_scim_test.rs` `a_5xx_and_a_429_retry_and_are_recorded_as_failures`; `crates/axiam-pki/src/ssrf.rs` `read_capped_body_rejects_body_over_cap`, `no_redirect_honours_the_content_length_cap`; `crates/axiam-amqp/src/outbound/topology.rs` `the_scim_push_declaration_is_pinned`. Residuals: the 10 000-member bound is in the code (`MAX_GROUP_MEMBERS`) and no test pins it. And each replica's `scim_push` consumer makes one attempt at a time, for every tenant: a downstream that answers every request just inside ten seconds — or never, so that each attempt spends the full ten seconds, twenty with a token request — slows the SCIM pushes of every target on that replica, and a reconciliation that queues a whole tenant multiplies it (10 000 references at ten seconds each is more than a day). One tenant's chosen endpoint can delay another tenant's provisioning, never its webhooks, SSF events or sign-ins. The W5 F4 review reported it (P23W5-07) with a per-target circuit breaker as the proposed fix; the 10 000-member bound is reported as a coverage gap in the same issue."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "e42d7a8d-dcd9-5dd4-bec1-b2adc69052e6",
     "path": "M514,1194 L1079,1194",
     "name": "read targets, write links / state",
     "description": "",
     "label": "read targets, write links / state (SurrealQL)",
     "labelLines": [
      "read targets, write links / state",
      "(SurrealQL)"
     ],
     "lx": 796.5,
     "ly": 1194,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealQL",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "8dfb48c8-5a7d-5d6f-913e-b8d0db1045a0",
     "path": "M510.7,1172.7 L678.8,1118.9 Q694,1114 694,1098 L694,644",
     "name": "dead-letter audit row",
     "description": "",
     "label": "scim_push.delivery_failed (in-process)",
     "labelLines": [
      "scim_push.delivery_failed",
      "(in-process)"
     ],
     "lx": 694,
     "ly": 975.2,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [
      {
       "number": 418,
       "title": "One notification mail per dead letter floods a rule's recipients while a target is down",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "D-58 lets a tenant's notification rules mail administrators when an outbound SCIM delivery is dead-lettered: the dispatcher's `scim_push.delivery_failed` audit row maps to the event `scim_delivery_failed`, and the notifying audit log hands it to the rule dispatcher, which enqueues one mail per matching rule per recipient. A target that is down past its retry budget, or that refuses AXIAM's credential (a bearer `401` or `403` dead-letters at once), dead-letters every reference: each change of each user, and the whole tenant at once at the next reconciliation or when the target is switched on. Mailed once per dead letter, a tenant of 10 000 users in scope whose downstream credential was revoked would mail each recipient of such a rule some 10 000 times a night, burying every other alert (T-117's class) and spending the deployment's mail quota and sender reputation — and whoever can make the downstream refuse could set it off. Until the W5 F4 review that is what happened.",
       "mitigation": "Built (the W5 F4 review, P23W5-02, D-73). **One notification per target per hour.** The `scim_push` consumer's notifying audit log asks a `NotificationGate` before a dead letter reaches the rules, and the gate claims it with a conditional write on `scim_target_state.failure_notified_at` (schema v84; the `claim_reconciliation` pattern, so replicas agree; a target of another tenant, or one deleted since, claims nothing). **Every dead letter is still recorded**: its own `scim_push.delivery_failed` row, and a count on the target's `state` (`dead_lettered_total`, `last_failure_reason`), so the console shows the size of an outage the one mail announces. A gate that cannot decide stays silent and logs once rather than failing open into a flood, and `NotifyingAuditLog` has no constructor without a gate. Rules stay per event (T-117) and the mail is fixed text — the action and its outcome, never a URL, a person or the downstream's answer (D-16). Tests: `crates/axiam-server/tests/scim_dead_letter_notification_test.rs` `a_targets_dead_letters_mail_each_recipient_once_an_hour_not_once_each` (fifty dead letters, two mails; it failed before the fix with a hundred), `a_scim_dead_letter_row_mails_every_recipient_of_a_matching_rule`; `crates/axiam-db/tests/scim_target_repository_test.rs` `claim_failure_notification_succeeds_once_per_interval`, `concurrent_failure_notification_claims_have_one_winner`; `crates/axiam-db/src/schema.rs` `v84_adds_only_the_failure_notification_claim`; `crates/axiam-scim/tests/outbound_reconcile_test.rs` `a_dead_letter_writes_the_counter_and_the_reason_once`. Residual: a recovery is not announced (the console's `state` shows it), and a target that keeps failing mails each recipient once an hour until a rule or the target is changed."
      }
     ],
     "open": 0,
     "notApplicable": 0
    }
   ],
   "total": 55,
   "open": 5,
   "notApplicable": 0,
   "bySeverity": {
    "Medium": 34,
    "High": 12,
    "Low": 9
   }
  },
  {
   "id": 7,
   "title": "Deployment & platform (Kubernetes)",
   "description": "Runtime and platform view: the edge (ingress or reverse proxy), replicated AXIAM pods, scheduled jobs, monitoring, and the stateful tier — SurrealDB, RabbitMQ, Vault/Secrets and backups. Since 1.0.0-beta08 the edge routes by path to a server that terminates its own TLS, and since 1.0.0-beta11 the gRPC listener may be published through the same edge. Threats here are largely deployment responsibilities rather than application code. At model 2.34.0 (T23.8.2) the minimal profile (AXIAM__AMQP__ENABLED=false, D-59: SurrealDB only, single-instance by a singleton lease) enters with its accepted durability trade, T-445: queued deliveries and mail, and the audit rows they would have written, are lost on restart, and external audit ingestion is unavailable.",
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
     "open": 0,
     "notApplicable": 0
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
     "open": 1,
     "notApplicable": 0
    },
    {
     "id": "679db7b9-8d10-51ad-aff4-35b7abfee484",
     "kind": "actor",
     "x": 49,
     "y": 354,
     "w": 150,
     "h": 80,
     "name": "IoT device / service account",
     "lines": [
      "IoT device /",
      "service account"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 215,
       "title": "A forwarded client certificate authenticates whoever can set the header",
       "type": "Spoofing",
       "severity": "Critical",
       "status": "Mitigated",
       "description": "`CertificateAuthenticated::extract` prefers the rustls-verified peer certificate and falls back to an `X-Client-Certificate` header when the connection carries none. `DeviceAuthService::authenticate` then checks the fingerprint, the status, the expiry, and the chain to the tenant or organization CA — every one of which a **copy** of an enrolled device's certificate also satisfies. A certificate is public data: it is handed out at enrollment, it appears in every handshake, and the certificates API returns it to anyone who may read it. Nothing on that path proves possession of the private key, and nothing can — possession is proven by a handshake, and on that path there was none. The fallback was sound only while the header could not originate with the client, i.e. while a trusted proxy terminated mTLS and overwrote it. It stops being sound the moment anything else can reach the listener, which is what exposing the backend does — and Caddy forwards client headers verbatim unless told otherwise.",
       "mitigation": "Fixed in 1.0.0-beta08. `AXIAM__AUTH__TRUST_FORWARDED_CLIENT_CERT` gates the fallback and defaults to **false**, so the header is consulted only where an operator asserts that a proxy they run performs the mTLS handshake and overwrites the header on every request. Native mTLS is unaffected and always preferred: a certificate rustls verified on the connection is authoritative and the setting is never consulted. Defence in depth rather than a single gate — the edge Caddyfile and `docker/nginx.conf.template` both strip `X-Client-Certificate` from inbound requests, so neither half has to be the only one. The FAPI2 client-credential path never accepted the header at all and still does not (`claude_dev/threat-model-stride.md` §5.3, X5.1): a client credential must not be assertable by anything that can set a header, and this brings the device path to the same standard. Devices that need real mTLS get a route the edge does not terminate — a second hostname or a TCP-passthrough Service — where rustls verifies the certificate itself."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
       "status": "Mitigated",
       "description": "Without a NetworkPolicy, any workload in the cluster can call the AXIAM Service directly and skip the ingress, along with any edge protections applied there.",
       "mitigation": "CLOSED (SEC-053). AXIAM's own authn/authz still applies on every request, so this was always defence-in-depth rather than a bypass of access control — but the depth is now shipped: k8s/network-policy/ carries a namespace-wide default-deny-all (ingress and egress) plus the minimum allows a working deployment needs — DNS egress, server egress scoped to SurrealDB:8000 and RabbitMQ:5671, public HTTPS with RFC1918/CGN and the cluster CIDRs excluded, a fail-closed SMTP relay range — and receiver-side ingress policies for the server, frontend, SurrealDB and RabbitMQ pods. NetworkPolicy is evaluated at both ends of a connection, and the SurrealDB and RabbitMQ ingress policies existed as files but were missing from kustomization.yml, so they were never applied; both are now listed, and `kubectl kustomize k8s/` is the check that they stay listed. Two values are deliberately placeholders the operator must replace: the cluster pod/service CIDRs in the HTTPS except list, and the SMTP relay range, which ships as RFC 5737 TEST-NET-1 so mail egress is denied until configured rather than open by default."
      },
      {
       "number": 208,
       "title": "The shipped proxy config diverges from the proxy CI tests",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The nginx config in the shipped admin-UI image used location /oauth2 — a prefix match that captured the SPA’s own /oauth2-clients route and answered a bare 404 before React was ever reached (F-02), so ProtectedRoute never ran and there was nothing to render or refuse. The vite preview proxy had the same shape, with /auth/mfa swallowing /auth/mfa-setup. The deeper defect: the fix had been made in the dev and preview proxies and never mirrored into the nginx config the image ships — and CI ran the E2E suite against vite preview, so the suite was green while the shipped artifact was broken. A route the proxy captures never reaches the permission layer, and no downstream permission assertion can tell “correctly refused” from “unreachable”.",
       "mitigation": "Fixed in 1.0.0-beta05: the nginx rule is narrowed to location /oauth2/ — all nine backend OAuth2 endpoints live under the slash-terminated prefix — and the preview regex gained the same boundary. The generalising guard is the spa-routing E2E matrix spec, which asserts every registered SPA route answers 200 text/html unauthenticated: a server-level check, run against the production image rather than the preview proxy, so the artifact being measured is the artifact being shipped."
      },
      {
       "number": 212,
       "title": "An unaccounted proxy hop collapses every per-IP rate limit into one bucket",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "`XForwardedForKeyExtractor` selects `hops[len - 1 - trusted_hops]` and falls back to `peer_addr()` when `trusted_hops >= len`. Both the extractor's own doc comment and three documentation sites told operators to set `AXIAM__RATE_LIMIT__TRUSTED_HOPS` to the *number of trusted proxy hops* — \"1 behind a single ingress/nginx\". That is off by one: a proxy appends the address it received **from**, not its own, so the nearest proxy is the socket peer and never appears in the header. Following the advice behind one proxy makes `trusted_hops >= hops.len()`, the header is discarded, and every client on the internet keys to the proxy's address. The documented Compose topology hit the same failure from the other direction — it had **two** appending proxies with the default `0`, so the extractor selected the inner proxy's address for every request. Either way the effect is one global bucket, including on `/auth/login`, which is deliberately keyed per-IP and never per-principal precisely so an attacker cannot lock a victim out. Collapsed, it does exactly that: one attacker's flood exhausts the allowance every legitimate user shares.",
       "mitigation": "Fixed in 1.0.0-beta08. The rule is stated as `trusted_hops = proxies − 1` with a derivation and a per-topology table in `crates/axiam-api-rest/src/extractors/rate_limit.rs`, `docs/deployment/README.md` and the docs site. Five tests in `rate_limit_keying_test.rs` pin the table, including a regression witness asserting that the old advice really does collapse two different clients onto one key. Structurally, the topology change removes the second hop, so both shipped deployments now have exactly one proxy and the default `0` is correct — and both set it **explicitly** anyway, with the derivation in a comment, because a value that is right by accident is one nobody re-derives when they add a load balancer. The gRPC listener shares the same variable and the same derivation, which is why publishing gRPC is sound only through the same proxy (T-233). Made **observable** in 1.0.0-beta12 (R-4), which is what the rest of this mitigation was missing: the fallback was correct and silent, and silence is how this off-by-one went unnoticed in the first place — every client keyed on the proxy, one bucket for the whole deployment, and the symptom reads as \"the rate limit is mysteriously strict\", which an operator fixes by raising the limit. Both extractors now emit one `WARN` per process on the first discard, naming the hop count seen, the `trusted_hops` in force and the rule, and increment `axiam_rate_limit_xff_discarded_total{protocol=\"rest\"|\"grpc\"}` on every one; the boot log states the value and the rule together next to the rate-limit posture line. A request with no header is deliberately not counted — a client with no proxy is not a misconfiguration, and counting it would bury the signal — so the fault condition is the counter tracking total request volume, which a dashboard can show."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
       "mitigation": "CI runs cargo-audit, cargo-deny (advisories, licences, bans, sources) and npm audit at a high threshold, uploads SARIF, and Dependabot covers cargo, the frontend npm tree and GitHub Actions. Residual: the eleven SDK repositories are scanned separately and are not covered by this repository's CI (CI-03). Since 1.0.0-beta11 the gate also fails on a stale suppression and tells a registry outage apart from a clean audit (T-236). Exercised on 2026-09-14 (f6dfb6a): RUSTSEC-2026-0285 — rustls 0.23.43 accepting TLS 1.3 handshake messages across encryption-level boundaries, CVSS 5.3, fixed in 0.23.45 — was published, the Security Scan went red the same day on a branch that had not touched TLS, and the lock was moved with `cargo update --precise` (rustls, `rustls-webpki`, and the `aws-lc-rs` / `aws-lc-sys` native crypto underneath every listener) and verified by re-running the OIDF FAPI 2.0 mTLS plan against the rebuilt binary rather than by reading a lockfile diff. Stated plainly: the `1.0.0-beta14` release artefacts of 2026-09-13 carry 0.23.43, and the fix ships with the next release; until then the advisory's own severity and scope are a deployment's exposure."
      },
      {
       "number": 207,
       "title": "A rolling deployment logs every not-yet-replaced replica out of the datastore",
       "type": "Denial of service",
       "severity": "High",
       "status": "Mitigated",
       "description": "Starting a second AXIAM process against the same SurrealDB took the first from healthy to 401 on every query within five seconds — permanently: still 401 after a 350-second window, and after the second process was removed (B-07). A rolling deployment does exactly this to every pod it has not replaced yet. Two independent causes: boot ran DEFINE USER OVERWRITE … PASSWORD on every start, and PASSWORD re-hashes with a fresh salt while SurrealDB signs root tokens against that hash, so each boot invalidated every token already issued; and the health check recognised only the WebSocket engine’s statement-level auth error while AXIAM runs the HTTP engine, whose transport-level 401 arrived looking like an ordinary query failure — so the reconnect loop never ran.",
       "mitigation": "Fixed in 1.0.0-beta05: boot reads the current token TTL from INFO FOR ROOT and skips the redefine when it already meets the configured value, with every unreadable case falling through to the redefine — wrong that way costs a redefine, wrong the other way would leave the TTL at the ~1h default while the re-signin task waits weeks. Health classification maps the HTTP engine’s 401/403 — matched narrowly on the status phrase, so a timeout or refused connection still gets ordinary retry rather than a pool rebuild on a blip — to Unhealthy, and reconnection swaps the pooled handles without a restart. Verified against the live stack: a second replica leaves login at 200 throughout, and a provoked credential invalidation recovers in tens of milliseconds with no caller-visible error."
      },
      {
       "number": 213,
       "title": "Path-routing at the edge makes the health endpoints internet-reachable",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "`/health`, `/ready` and `/health/jobs` are served at the **server root**, not under `/api/v1`. While the edge forwarded everything to the frontend's nginx — which proxies only `/api`, `/oauth2` and `/.well-known` — they were unreachable from outside by accident rather than by decision. Routing by path forces the decision, and the wrong answer is expensive: `/health/jobs` reports per-job scheduler state (names, last-run timestamps, consecutive-failure counts), which is a free map of what a deployment runs and what is currently broken in it, and `/ready` answers \"can this instance reach its datastore\", a cheap oracle for whether an attack on the datastore is working. Neither is rate-limited the way `/api` is, because neither was ever internet-facing.",
       "mitigation": "Deliberately **not routed** at the edge. The Caddyfile in `claude_dev/rpi5-prod-google-federation-guide.md` §4.3 claims `/api`, `/oauth2` and `/.well-known` and nothing else, so `/health` falls through to the SPA route and returns `index.html` rather than the health payload. The probes that need them — the Docker healthcheck and the Kubernetes liveness/readiness probes — reach the server on the container or pod network, which is where a health probe belongs. The guide shows the loopback probe for an operator checking by hand. Documented since 1.0.0-beta12 (R-6): `/health/jobs` carried a `#[utoipa::path]` annotation and a route from the day it was written and was listed in `paths(…)` by nothing, so it existed in the server and in no generated document — which also meant this decision had nowhere canonical to be stated for it. It is in `sdks/openapi.json` now, under the `health` tag with its response schemas, and deliberately excluded from the §27 SDK surface with the reason recorded in `gen-management-registry.py`: unlike `/health` and `/ready`, which answer a fixed one-word contract, it returns a variable inventory of a deployment's background jobs, and an SDK talks to the edge this endpoint is not routed at."
      },
      {
       "number": 214,
       "title": "The TLS leaf expires because rustls binds it for the process's life",
       "type": "Denial of service",
       "severity": "High",
       "status": "Mitigated",
       "description": "rustls resolves the server certificate per handshake but reads nothing from disk: `with_single_cert` installed an immutable `SingleCertAndKey`, and actix binds the resulting config for the process's life. The certificate a server booted with was the certificate it served forever. Harmless for a leaf installed by hand once a year; a scheduled outage once an ACME client is involved, since Let's Encrypt issues for 90 days and clients renew at 60 — the renewed certificate lands on disk and changes nothing, and the listener starts failing every handshake on day 90. The only remedy was restarting an identity provider every couple of months, which drops in-flight requests and re-reads every secret out of Vault on a schedule.",
       "mitigation": "Fixed in 1.0.0-beta08. `ReloadableCertResolver` holds the certificate in an `ArcSwap` that rustls consults per handshake, so a renewal takes effect on the next connection with no restart and no dropped request — the same mechanism `ReloadableClientCertVerifier` already used for trust anchors, rather than a second one. Two triggers, because they fail differently: `SIGHUP` (immediate, what an ACME deploy hook sends, and a signal actix-server does not claim) and an hourly `stat` poll (`AXIAM__SERVER__TLS__RELOAD_INTERVAL_SECS`) for the case that actually happens — a hook nobody wired up, or a runtime that does not forward signals. The swap is validated before it happens: a reload that finds an unreadable or mismatched pair leaves the previous certificate serving and retries, which is what makes a renewal observed mid-write (certbot writes the chain and the key as two operations) a logged warning instead of a dead listener. A test drives two real TLS 1.3 handshakes against one `ServerConfig` and asserts the client is presented the renewed leaf on the second. The mechanism covers both listeners since 1.0.0-beta12: the gRPC listener resolves its leaf through the same `ReloadableCertResolver` instance whenever both are pointed at the same pair, so one trigger renews both — see T-234, closed by R-1."
      },
      {
       "number": 233,
       "title": "A gRPC listener published by port-forward keys every rate limit on a header the client writes",
       "type": "Spoofing",
       "severity": "High",
       "status": "Mitigated",
       "description": "The gRPC listener is loopback-bound in Compose and ClusterIP-only in Kubernetes, a rule filed as SEC-003 when `UserService` and `TokenService` had no authentication at all. That is no longer true — every service is built with `with_interceptor(AuthInterceptor)`, derives tenant and subject from verified claims rather than the request body, `ValidateCredentials` accrues lockout, and neither reflection nor the health service is registered — so publishing the surface became a defensible choice, and the obvious cheap way to do it is unsound for a reason that has nothing to do with TLS. `GrpcTrustedHopsKeyExtractor` reads `X-Forwarded-For` before the verified connection peer, exactly as the REST extractor does (T-212); with no proxy appending the real peer, a client that sends one entry is keyed on a value it chose, and a value it varies per call mints a fresh bucket per call, so every ceiling becomes decorative. No value of `TRUSTED_HOPS` repairs it — for `n`, `n+1` client-written entries select the leftmost and fewer fall back to the peer — and both protocols read the one `AXIAM__RATE_LIMIT__TRUSTED_HOPS`, so they cannot be given different values. Publishing the whole `axiam.v1` package would also put `ValidateCredentials`, a real Argon2id password check, and `ReactorAdminService`, an administrative surface rate-limited like the hot path, on the internet by default.",
       "mitigation": "Recorded at 1.0.0-beta11. The bind stays loopback by default, and the blanket rule becomes a default rather than a prohibition: gRPC is published **through the edge on 443, path-matched, or not at all**. Caddy speaks HTTP/2 to the client, re-encrypts to the backend's own gRPC listener and appends the real peer, so the hop count is one on both protocols and the shared `TRUSTED_HOPS` stays correct for both. The documented route is an **allowlist** of services — `AuthorizationService`, `UserInfoService`, `TokenService` — so `UserService` and `ReactorAdminService` stay off the public edge unless an operator names them, with what each costs written beside the line that would add it; anything under `/axiam.v1.*` not listed falls through to the SPA handler and gets HTML back, a confusing refusal but a safe one. The site-wide stripping of `X-Client-Certificate` and `X-Real-IP` applies to the route. The listener's own TLS is enabled only when both `AXIAM__GRPC_TLS_CERT_PATH` and `_KEY_PATH` are set, and the server panics at startup if either names a file it cannot read — a typo is a failed boot, never a listener that quietly came up in cleartext. The runbook sets `AXIAM__GRPC__STRICT_REVOCATION=true` for a public listener so a revoked session does not keep passing for up to fifteen minutes, and states the per-IP-is-not-per-client sizing behind NAT. `claude_dev/public-backend-tls-design.md` §13 and the Pi runbook §14 carry the argument; `ReactorAdminService` left the authz rate-limit family in 1.0.0-beta12 (R-5): it fell through `GrpcMethodFamily::classify`'s catch-all, which puts an unrecognised path in the strictest *limited* family so a new service is throttled rather than unlimited — safe as a default, wrong as an outcome for an administrative surface, which was therefore sized like the hot path at 100/s per IP and raised by the `gateway` and `mesh` profiles. It now maps to `Admin`, whose ceiling is the absolute `ADMIN_PER_SEC_DEFAULT` (10/s) that no profile raises; the catch-all arm is unchanged. The listener's TLS was 1.3-capable but 1.2-negotiable when this was recorded, because tonic's `ServerTlsConfig` exposed no protocol-version knob; R-1 removed that limit and both listeners are TLS 1.3-only (T-234)."
      },
      {
       "number": 234,
       "title": "The gRPC TLS leaf expires because tonic reads it once at startup",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "T-214 made the REST listener's certificate hot-reloadable so that an ACME renewal would never need a restart. That work covers the actix listener only: `axiam-api-grpc`'s `start_grpc_server` reads `AXIAM__GRPC_TLS_CERT_PATH` / `_KEY_PATH` once, hands the PEM to tonic's `ServerTlsConfig`, and the crate contains no reload path and no poll. A gRPC listener that is public is therefore a listener whose certificate expires at day 90 while REST keeps working — the failure mode T-214 exists to prevent, reintroduced on the other protocol, and the worst version of it because it presents as a gRPC bug. The same API limit keeps that leg TLS 1.2-negotiable where the REST listener is 1.3-only.",
       "mitigation": "Fixed in 1.0.0-beta12 (R-1). The gRPC listener no longer asks tonic to terminate TLS. `start_grpc_server` takes the rustls configuration as a value (`GrpcTls::Plaintext | Rustls(Arc<ServerConfig>)`), binds its own `TcpListener`, completes each handshake with `tokio-rustls`, and hands tonic an already-encrypted stream through `serve_with_incoming` — the hand-rolled accept loop this threat named as the structural fix, and it closes the reload gap and the TLS-version gap in the one change, as anticipated. The configuration is built by the composition root (`axiam_server::tls::build_grpc_rustls_server_config`), not by `axiam-api-grpc`: `ReloadableCertResolver` lives in `axiam-server` at layer 8 and the gRPC crate is layer 6, and `scripts/check-crate-layering.py` fails any edge pointing the other way. That builder resolves the leaf through `shared_resolver`, which returns the **same** resolver instance when both listeners name the same certificate and key — the documented topology, where there is no second certificate — so one `SIGHUP` or one hourly poll renews both; a deployment that really does point them at different files gets a second registered leaf reloaded on the same triggers, replacing the single-slot `OnceLock` that would have silently kept only the first. The configuration pins `with_protocol_versions(&[&rustls::version::TLS13])` and advertises ALPN `h2` alone, so the leg is TLS 1.3-**exclusive** rather than merely 1.3-capable. The flat env-var names and the panic-on-unreadable behaviour moved with the read and are unchanged: a typo is still a failed boot. Terminating the handshake here introduces one new denial-of-service surface — a client that opens TCP and never speaks — bounded by 512 concurrent handshakes taken with a non-blocking `try_acquire_owned` (so the accept loop is never starved, however many half-open clients are outstanding) and a 10-second handshake timeout that releases every permit; a failed or timed-out handshake logs at `debug` and drops that connection only, never the accept loop. Five tests carry it: a resolver swapped between two real handshakes against one running listener, with the connection established before the swap still usable after it; a TLS 1.2-only client refused rather than downgraded; a real TLS connection's peer address carried through `Connected::connect_info()` into the request extension and out of `GrpcTrustedHopsKeyExtractor` as the client's IP (verified against the pinned tonic before the code was written — had it come back `None` the limiter would have failed closed for everyone); sixty-four half-open connections not stopping a well-behaved client; and plaintext mode unchanged. On the server side, one reload covering every registered leaf, the shared-resolver identity asserted by pointer, and the boot panic for each half of an unreadable pair. The certbot deploy hook's container restart (Pi runbook §14.5) is now redundant rather than required. Follow-up closed 2026-09-23 (T22.12, S-8): R-1's builder recorded client-certificate policy as deferred, left at with_no_client_auth() as a deployment decision. It is now a setting, AXIAM__GRPC_TLS_CLIENT_AUTH, off by default so the handshake is unchanged unless an operator asks for more. See T-286."
      },
      {
       "number": 236,
       "title": "A registry outage or a stale suppression turns the dependency-audit gate into a rubber stamp",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The gate T-127 relies on failed in both directions at once. `npm audit` got `503` from the registry's audit endpoint, retried internally for seven minutes and exited `1` seconds after `npm ci` had reported zero vulnerabilities — a red job with no vulnerability anywhere in the tree, the kind of failure that teaches a team to re-run until green, and one that buried the line that explained it under four SARIF upload errors from producers that never ran. And four advisory suppressions had gone stale, emitting `advisory-not-detected` on every run: two for advisories already fixed upstream, two for crates no longer in the resolved feature graph at all. An ignore is keyed by advisory ID, not by version or crate, so one left behind after its crate leaves the graph silently re-suppresses that advisory if the crate ever comes back — a gate that has been quietly told what to ignore.",
       "mitigation": "Fixed in 1.0.0-beta11. The npm audit step retries with backoff and tells \"found advisories\" apart from \"could not reach the endpoint\" by the shape of the output rather than the exit code — npm exits `1` for both, but only a completed audit parses as JSON without an `error` key. A real HIGH/CRITICAL finding still fails the job; anything parseable that is not an error object counts as a real report, so an unfamiliar schema fails rather than being waved through; and a sustained outage ends in a `::warning::` that says explicitly it is not a clean bill of health. `cargo-deny` now runs with `-D advisory-not-detected`, so the next stale entry fails CI instead of scrolling past, and the two ignore-lists are allowed to differ legitimately — cargo-deny resolves the feature graph while cargo-audit reads `Cargo.lock` — under a containment check that demands an explicit `# audit-only: <ID> — <reason>` declaration and rejects one that is missing, unreasoned, contradictory or stale, with seven self-test cases. The yanked `chacha20 0.10.1` was bumped, and the four SARIF uploads are guarded on the file existing so a failed producer stops adding its own errors on top of the one that matters. `scripts/check-docker-context.py` closes the neighbouring class of the same shape — a gate that reads the worktree while the artifact is built from a filtered context, which is how the beta08 release lost both frontend image legs — by asking, for every `COPY`/`ADD` in every Dockerfile, whether at least one tracked file both exists and survives `.dockerignore`, cross-checked file by file against BuildKit's real context export. Narrowed deliberately at 1.0.0-beta13, and stated rather than folded into another change: the Trivy filesystem scan is scoped to what AXIAM ships — `crates/`, `frontend/`, `website/`, `examples/` and the root lockfile — and excludes the `benchmarks/` and `conformance/` harnesses, whose transitive CVEs (a netty CRITICAL under the Java bench) nothing in this repository can remediate and which were turning the gate red on every unrelated PR, which is how a red security check stops being read. The same wave removed 209 files of unbuilt design-system tooling that had entered the scan and the lint by accident."
      },
      {
       "number": 284,
       "title": "A re-minted bootstrap setup token is a second way to create the first administrator",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "Only the SHA-256 hash of the one-time bootstrap setup token is stored, and the first-boot mint is a no-op once a token row exists, so an operator who lost the token had exactly one documented recovery: wipe the volume (DF-019). A subcommand that re-mints it removes that cliff and introduces a second credential path to POST /api/v1/admin/bootstrap, the endpoint that creates the first super-admin. Ungated, it would work on a deployment that already has administrators, and would therefore be an account takeover available to anyone who can run a command in the pod — with no authentication in front of it and nothing in the audit trail naming a principal.",
       "mitigation": "axiam-server setup-token --remint refuses, with exit code 2 and no write at all, unless the deployment has no user row AND no redeemed setup token — that is, unless nobody has bootstrapped it. Before bootstrap there is no administrator to take over and no credential to reset, which is exactly the state an operator who lost the first-boot token is in; after it, the deployment has an authenticated way to create accounts and a password-reset flow, so re-minting is never the answer. Both gates are evaluated before the existing hash is deleted, so a refused call leaves the current token working. The token is printed to stdout only, never through tracing, so it does not reach the container log a second time; there is deliberately no --print, because the plaintext is not stored and storing it so that it could be printed would be the wrong fix. The subcommand parse is its own unit-tested function so that setup-token with the flag missing or mistyped exits 2 rather than silently starting a second server. Pinned by remint_replaces_the_previous_hash, remint_refuses_once_a_user_exists and remint_refuses_once_a_token_was_consumed, the last two asserting that the stored hash is unchanged after a refusal."
      },
      {
       "number": 445,
       "title": "The minimal profile loses queued deliveries and mail, and the audit rows they would have written, on restart",
       "type": "Repudiation",
       "severity": "Medium",
       "status": "Open",
       "description": "With `AXIAM__AMQP__ENABLED=false` webhooks, SSF push, outbound SCIM, CIBA ping and transactional mail ride bounded in-process queues. A message queued, or sleeping before a retry, when the process stops is gone, and so is the terminal audit row its delivery would have written: the trail ends at a `<kind>.delivery_attempt`, or holds nothing for a message never attempted, and an enqueue refused because a queue is full leaves only a log line. A lost `ExportReady` mail strands a ready GDPR export whose download token travelled only in it. External services' audit events have no ingestion path at all, and a producer that publishes to a broker left running is confirmed by the broker while nothing consumes.",
       "mitigation": "Accepted design trade-off (D-59): the profile exists to run without a broker, and a SurrealDB-backed durable queue was rejected as a second dispatcher. What bounds it: the profile is opt-in (`true` is the default) and says what it lacks at boot (a `WARN` naming the in-process queues as lost on restart and external audit ingestion as unavailable), in `/health` (`profile: minimal`; `unavailable` lists `amqp_audit_ingestion`) and in the deployment guide; AXIAM's own audit rows never rode the broker and are written directly in both profiles, and an orderly stop drains them (T-444); the GDPR erasure records keep their dead-letter fallback (T19.27); a delivery that exhausts its attempts writes `<kind>.delivery_failed` in both profiles; outbound SCIM is repaired by the next reconciliation. The review (`claude_dev/audit-durability-review-minimal-profile-2026-10-05.md`) states what the deployment documentation must say and proposes a terminal row for a delivery abandoned at stop or refused at enqueue (P23W5-A4). Open because the loss is real."
      }
     ],
     "open": 1,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
       "status": "Mitigated",
       "description": "The 30-day GDPR erasure grace period and certificate-expiry warnings depend on scheduled work. A job that fails quietly produces a compliance gap that nobody sees.",
       "mitigation": "CLOSED (T-129). GET /health/jobs reports every background sweep: when it last succeeded, when it last failed, the error text, the consecutive-failure count, and a computed stalled flag. stalled is measured from the last success (falling back to process start, so a sweep that never ran once is still caught), not from the last error — a job that errors was already visible in the log, but a job that stops running produces no log line at all. Alert on status == \"degraded\", or on a named job's stalled. Returns 200 even when degraded, deliberately: this is not a readiness gate, and a stuck sweep must not pull a serving pod from the load balancer. Three missed intervals are tolerated before flagging, because a sweep that overruns its interval under load is normal and an alert that fires on that gets muted."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
       "status": "Mitigated",
       "description": "A broker left on guest/guest, or with one credential shared by every service, lets any workload read authz decisions and audit events and publish forged ones.",
       "mitigation": "CLOSED (T-131). The shipped manifests never carried guest/guest — broker credentials come from the rabbitmq-credentials Secret, supplied at deploy time — and now add RABBITMQ_DEFAULT_VHOST: axiam, so AXIAM gets its own authorization boundary rather than sharing the default / with anything else on the broker. Fixing this exposed a defect that mattered more: the server's AXIAM__AMQP__URL lived in the ConfigMap with no credentials at all, so the shipped manifests could never have authenticated to their own broker; the URL now lives in axiam-secrets (it embeds a password) with the /axiam vhost suffix. Splitting one credential per service still belongs to whoever deploys. Unchanged and still applying: HMAC verification on consumed messages, and the amqps://-only transport, so a broker credential never travels in the clear."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "8fbbc2a9-a70f-513d-a1e0-ea9fdce2783b",
     "kind": "store",
     "x": 1089,
     "y": 484,
     "w": 170,
     "h": 80,
     "name": "Secrets (Vault / K8s Secrets / ConfigMap)",
     "lines": [
      "Secrets (Vault / K8s",
      "Secrets / ConfigMap)"
     ],
     "description": "",
     "outOfScope": false,
     "threats": [
      {
       "number": 132,
       "title": "Secret material placed in a ConfigMap or plain env var",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "ConfigMaps are not secret and environment variables appear in pod specs, crash dumps and debug output — a signing key or datastore password there is effectively public within the namespace.",
       "mitigation": "CLOSED (T-132). Two providers keep key material out of the container spec, and the manifests use one of them by default: the production stacks default to AXIAM__AUTH__SECRET_PROVIDER=vault (concentrating secrets behind one credential — T-180, which stays open), and for deployments without Vault, axiam-key-material mounts all eleven cryptographic secrets as files at /etc/axiam/secrets with AXIAM__AUTH__SECRET_PROVIDER=file — mode 0440 plus fsGroup 65532, because Kubernetes gives secret files to root:root. Three keys (opaque_session_key, opaque_setup_key, amqp_signing_key) were absent from the old env-var Secret entirely. The residual is closed (R-5, 2026-09-12): AXIAM__DB__USERNAME, AXIAM__DB__PASSWORD and AXIAM__AMQP__URL were read by the layered configuration before any provider existed, so a deployment that put every key in Vault still had its datastore password in the pod spec — the exact sentence this entry was closed on, one secret class short. They are now three more text secrets on the port (`db_username`, `db_password`, `amqp_url`), fetched in the same round trip as the other eleven, so **the Vault token (or the `file` provider's mount) is the only credential the container spec has to carry**. The two checks that forced the old shape — `load_config`'s assertions on the JWT keys — moved to run after the provider has been consulted; they did not move because they were wrong but because they ran at the one point where they could see only one of the two sources. The environment variables **stay permanently** (decision B), because `env` is a supported provider kind rather than a legacy path: a single-node deployment, the dev compose file and the E2E stack all use it deliberately, and deprecating the variables would deprecate the provider that reads them. The WARN is scoped to the one case where the operator believes something untrue — a *non-`env`* provider configured and the value arriving from the environment anyway. The seeder carries them and never **mints** them, which is the difference between a key and a credential: a 256-bit key is meaningful only to AXIAM, while an invented datastore password gives a Vault that looks configured and a server that cannot connect; an existing value always wins over a supplied one, so re-running the seeder with a stale variable cannot undo a rotation (T-231). `docker/vault/axiam-policy.hcl` needed **no change** — it grants `read` on `secret/data/axiam` and the three fields live in that entry; the policy is path-based, not field-based, which is worth stating because editing it is the reasonable first assumption. `DbConfig` and `AmqpConfig` gained hand-written redacting `Debug` impls: the broker URL embeds its credential inline by the AMQP URI's own design, so a derived `Debug` there is a password in every log line that renders a configuration — the shape of the three CodeQL findings T-260 closed, in the struct that most invites it. The datastore credentials are still one Vault credential away (T-180, which stays open, and now covers three more secrets). Enable etcd encryption at rest either way."
      },
      {
       "number": 180,
       "title": "Vault concentrates every long-lived secret behind one credential",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Open",
       "description": "With AXIAM__AUTH__SECRET_PROVIDER=vault the production default, all ten long-lived secrets — the JWT signing key, opaque_setup_key, the PKI, MFA, federation and email encryption keys, the password pepper, the GDPR pseudonym pepper and the AMQP signing key — sit behind one KV path. A Vault token with read on that path, or the unseal or root material, is equivalent to every one of them at once; a dev-mode Vault left in production holds them unsealed in memory.",
       "mitigation": "Deployment responsibility, stated in docs/deployment/vault.md rather than enforceable in-product: run a production-mode Vault with TLS (the shipped prod stack does — TLS material, init, unseal, then seed), scope AXIAM's token to read-only on its own KV path with the documented policy, keep unseal keys and the root token offline, and enable Vault's audit device so secret reads are attributable. The tooling is shaped to help, and since H-4 it CHECKS rather than merely advises: just vault-status queries sys/capabilities-self and reports the capabilities the token in hand actually holds on AXIAM's KV path, flagging anything beyond read — and a root token as what it is — with --strict to make it a failure in a deployment smoke test. It still reports secret presence only, never a value, and the seeder never rewrites a secret that already exists. Since 1.0.0-beta10 the token is no longer strictly read-only: it holds `read` on the startup path and `create`/`update` on `secret/data/axiam/ca-keys/*`, from the one policy file `docker/vault/axiam-policy.hcl`, and `just vault-status` reports missing capabilities as well as excess ones (T-232). Since 2026-09-12 (R-5) three more secrets sit behind that one credential — the datastore username and password and the broker URL, moved off the container spec to close T-132's follow-up — which widens exactly the concentration this entry records rather than narrowing it, and is the honest trade: a credential in a pod spec is readable by anyone with `get pod`, while a credential behind Vault is readable by whoever holds the token and revocable after the fact. The policy needed no change, because it grants `read` on the path rather than on fields."
      },
      {
       "number": 216,
       "title": "The unseal key sits on the same disk as the sealed data",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Open",
       "description": "`just prod-up` initialises Vault with a single Shamir share and writes it, with the root token, to `docker/.secrets/vault-init.json` — the same disk as the sealed data. That is not Shamir's scheme with the shares stored badly; it is no seal at all, and anyone who can read the disk can unseal and then read every long-lived secret AXIAM has (the set enumerated in T-180). The stack also handed the server that **root token**, so a credential visible in `docker inspect` could read, write and delete every secret, revoke tokens and mount engines — for a process that reads one path once at boot and never writes. Both were acceptable while `docker-compose.prod.yml` was only ever a laptop stack; they stopped being acceptable when a deployment guide pointed a real domain at it.",
       "mitigation": "Narrowed, not closed. `prod-up` now writes the read-only `axiam` policy from `docs/deployment/vault.md` §5.4 and issues a **scoped, periodic token** for the server, refusing to fall back to root if that fails; seeding keeps its own short-lived credential, because the seeding token and the serving token were never the same thing. Both the Compose stack and `k8s/vault/statefulset.yml` move from the `file` backend to **Raft**, which has a consistent backup story (`vault operator raft snapshot save`) and a migration path to three nodes that does not require a re-seed — a re-seed changes the OPAQUE setup key, i.e. a password reset for every user in every tenant. What remains **open** is auto-unseal, which cannot be closed from inside AXIAM: every Vault OSS seal type needs a cloud KMS or a second Vault elsewhere, and `pkcs11` is Enterprise-only, so a TPM is not an option whatever the hardware. `docs/deployment/vault.md` §5.3 and the Pi runbook §7.1 give the honest option table — GCP Cloud KMS at roughly $0.06 per key per month is the cheapest real answer — and state plainly that a deployment which configures none of them needs a human with three shares after every restart and is not production. A script that unseals from shares kept on the machine is explicitly **not** offered as an alternative: it removes the seal rather than automating it, and is strictly worse than Shamir because the shares are now in the one place an attacker already has. Two amendments since: the server's token is no longer strictly read-only — it holds `create`/`update` on the CA-key prefix, from the one policy file (T-232) — and the seeder that runs after unseal can no longer mistake a refused read for an empty Vault and mint fresh keys over the live ones (T-231). Vault itself runs unprivileged: the prod Compose stack chowns the Raft volume in a one-shot init container rather than running the process that holds every secret as root. Made **checkable** in 1.0.0-beta12 (R-7), the way H-4 made T-180's token scope checkable. `just vault-status` gains a Seal section from the unauthenticated `sys/seal-status` — so it answers even when the token is wrong and even when the Vault is sealed: it names the seal type, reads `OK` for any auto-unseal type, and for `shamir` says \"no auto-unseal; every restart needs t of n key shares, not production\" with the quorum quoted from the response. A Vault sealed at that instant gets its own line, because that is a state somebody is about to fix rather than a statement about the configured seal, and conflating the two would train an operator to ignore both; a request that fails reports `unknown`, never `OK`. `--strict` fails on an unconfirmed auto-unseal, and `just vault-status` still does not pass it so the dev stack's deliberate root-token-on-Shamir does not turn every local run red. **Status stays Open**: the control is a check, not a seal — nothing in this repository can configure auto-unseal, and R-7 does not pretend otherwise."
      },
      {
       "number": 231,
       "title": "A refused Vault read is indistinguishable from an empty Vault, and the seeder overwrites every live secret",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "The seeder's one invariant — a secret already present is never regenerated — was enforced by `vault_seed_payload.build()`, a pure function that has always been correct and unit-tested, behind a shell line that was not: `curl --fail … || echo '{}'` turned every failed read into \"the Vault is empty\", and `build()` cannot tell the two apart. `just prod-up` supplied the failure on a plate: Vault with Raft storage returns from `sys/unseal` while the node is still a standby contending for leadership, every request in that window is refused, and the recipe seeded immediately after unsealing — so a restart-driven run aimed the read straight at it. A revoked or write-only token reached the same end deterministically. The outcome was a full set of freshly minted keys written over the live ones, a `→ Seeded` line and exit 0; from then on every login answered `500` with `AES-GCM decrypt: aead::Error`, because `opaque_setup_key` no longer opened the OPAQUE records the datastore held (`mfa_encryption_key` fails the same way at the TOTP step). That is a password reset for every user in every tenant, caused by a restart. Reproduced against a fake Vault answering `500` to the read.",
       "mitigation": "Fixed in 1.0.0-beta11, in layers that each hold alone. `scripts/vault-seed.sh` waits for an **active** node — `sys/health` answering `200` — not merely a listening or unsealed one. The read's HTTP status reaches the payload builder: only `200` or `404` are statements about the contents of the path, `interpret_read` raises on everything else and the script exits non-zero with nothing written. The write is pinned with KV v2's `cas` to the version that was read — `0` to create, `N` to update — so even a stale-but-trusted read cannot clobber. `assert_preserved` refuses any payload that would replace a stored secret, with a carve-out only for the JWT pair's two documented replacement paths. `just prod-up` waits for `sys/health` to answer `200` after unsealing, before it seeds. `scripts/test_vault_seed_shell.py` drives the real script over real HTTP against a Vault answering `500`, `503`, `403` and `404` and asserts on what was written rather than on an exit code — eight of its twelve cases fail against the previous script — and both seeder test files now run in CI, which they never did: a well-tested pure function behind an untested boundary is exactly as safe as the boundary. Recovery for a deployment already hit: KV v2 keeps ten versions, and `docs/deployment/vault.md` §8.1 has the `vault kv patch` restore, which costs no password resets."
      },
      {
       "number": 232,
       "title": "The server's Vault policy is quoted in several places, and none of them is checked against what the server does",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "The policy `just prod-up` wrote — and the one the production ceremony documented — granted `read` on `secret/data/axiam` and nothing on `secret/data/axiam/ca-keys/*`, where CA key custody writes one secret per CA. Because custody inherits `AXIAM__AUTH__VAULT_ADDR` / `_TOKEN` when no `AXIAM__PKI__VAULT_*` pair is set, every such stack booted cleanly, served every request, and refused its first organization CA with a `403`. A policy that is too narrow fails late and looks like a product bug, and the reflex fix — handing the server a broader token, or the root token — is precisely the failure T-180 and T-216 exist to prevent. A policy quoted in three documents and a recipe is one nobody re-derives, in either direction.",
       "mitigation": "Fixed in 1.0.0-beta10. The policy lives in one file, `docker/vault/axiam-policy.hcl`: `read` on the startup path — the server reads it once at boot and never writes it — plus `create`, `read` and `update` confined to the CA-key prefix, and `delete` on that prefix's metadata so a custody migration can release a key. `scripts/vault-policy.sh` applies it, the docs quote it, and the status reporter's tests assert against it. One glob covers both CA tiers, because `CaKeyStore::store` is keyed by `(organization_id, ca_id)` with no tenant segment, so tenant intermediates land beside the organization root; `vault_pki` custody is deliberately not covered and now says so. `just vault-policy` applies it to a running deployment — Vault evaluates policies per request, so nothing is restarted, re-initialised or re-seeded and nothing already stored is lost. `just vault-status` reports **missing** capabilities as well as excess ones, so the misconfiguration is visible before it becomes a `403`, and a `403` from CA key custody prints the missing stanza as HCL addressed to the mount and prefix that deployment configured. The token is therefore no longer read-only, and T-180 and T-216 say so rather than repeating the older claim."
      },
      {
       "number": 264,
       "title": "A Vault CA bundle that parses to nothing silently replaces the operator's pin with the public trust store",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "`reqwest::Certificate::from_pem_bundle` errors on malformed PEM but answers `Ok` with an **empty** list for a file containing no PEM blocks at all — empty, truncated, DER rather than PEM, or a path that points at something else. The loop then added no roots and startup carried on, which is exactly the fallback the branch exists to prevent: continuing falls back to the default trust store, the check the operator asked for. Behind a publicly-trusted certificate the pinning is silently lost and everything appears to work; behind a private CA the connection fails with \"error sending request\", which reads as a network fault and sends the operator to the wrong place — and that is the likelier deployment, since `AXIAM__AUTH__VAULT_CA_CERT_PATH` exists precisely for it.",
       "mitigation": "c38879a: refused at the bundle, naming the file. Two tests under `tests/` so no fixture is instrumented — an unreadable path and a bundle that parses to nothing — and the empty-bundle case asserts the message is *not* a downstream \"error sending request\", because failing later, against Vault, was the original symptom. Found while writing tests for `SecretProviderKind::build`, the one place in that change where the code did not do what its comment said. The neighbouring invariant is now asserted too: `SettingsLockoutPolicy` falls back to the deployment default when a tenant is unresolvable or the settings store is unreachable, so brute force is still metered while the store is down — failure must not mean \"no lockout\" (T-178's rule)."
      }
     ],
     "open": 2,
     "notApplicable": 0
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
     "open": 1,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "39e44fbf-616d-5d6a-bef4-f851466a7e63",
     "path": "M434,234 L434,304",
     "name": "proxy → axiam-server",
     "description": "",
     "label": "proxy → axiam-server (TLS 1.3)",
     "labelLines": [
      "proxy → axiam-server (TLS 1.3)"
     ],
     "lx": 434,
     "ly": 269,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "TLS 1.3 (HTTP/1.1 or HTTP/2)",
     "threats": [
      {
       "number": 217,
       "title": "Credentials cross the internal network in cleartext",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "`docker/nginx.conf` proxied to `http://axiam-server:8090`. Every password on its way to `/api/v1/auth/login`, every bearer token, every session cookie and every OAuth2 client secret crossed the container network in the clear, readable by anything that could join that bridge or read the host's network namespace — which on a single host also running an operator's other containers is not hypothetical. The project's own standard (\"TLS 1.3 minimum for all external communication\") was satisfied only by treating the container network as not external, which is exactly the assumption CONTRACT §8b already refused to make for AMQP, where `AXIAM__AMQP__ALLOW_PLAINTEXT` was **removed** rather than left as an escape hatch. The REST leg was held to a weaker standard than the message bus for no recorded reason.",
       "mitigation": "Fixed in 1.0.0-beta08. `docker/nginx.conf` becomes a template whose upstream is rendered from `AXIAM_BACKEND_ORIGIN` / `AXIAM_BACKEND_SNI` / `AXIAM_BACKEND_CA`, and the documented topology points the edge at `https://` with the server terminating TLS 1.3 itself. Certificate verification is unconditional in every rendering: there is no `proxy_ssl_verify off` anywhere in the change and no documented setting that produces one, because a backend certificate that does not verify is a misconfiguration to fix and an escape hatch here is the first thing reached for at 3am. Defaults are unchanged, so the dev stack and the E2E suite keep the plaintext behaviour they rely on and reaching the frontend container directly keeps working."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 1,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "957d8f25-dba8-535f-b7ec-0f0987f377e6",
     "path": "M177.9,354 L377.8,205.7",
     "name": "device traffic",
     "description": "",
     "label": "device traffic (mTLS, or a forwarded certificate header)",
     "labelLines": [
      "device traffic (mTLS, or a forwarded",
      "certificate header)"
     ],
     "lx": 277.8,
     "ly": 279.9,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS (mTLS)",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    }
   ],
   "total": 29,
   "open": 6,
   "notApplicable": 0,
   "bySeverity": {
    "High": 17,
    "Critical": 2,
    "Medium": 10
   }
  },
  {
   "id": 8,
   "title": "Client SDKs & admin UI integration surface",
   "description": "The React admin UI and the eleven client SDKs (Rust, TypeScript, Python, Java, Kotlin, C#, PHP, Go, Swift, C, C++), which live in separate repositories and vendor CONTRACT.md, openapi.json and proto/ from here. Covers SDK transport and credential handling, token verification, the WebAuthn relying-party layer, account lifecycle and PAR operations (contract 1.28, §24–§26), AMQP HMAC consumption and the reactor protocol core, webhook verification and package-distribution supply chain.",
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
       "description": "The SDKs are published across the public registries — crates.io, npm, PyPI, Maven Central, NuGet, Packagist, the Go module proxy, Swift Package Index / CocoaPods, and GitHub Releases for C and C++. A typosquatted or hijacked package name delivers an attacker's code straight into an integrator's authentication path.",
       "mitigation": "Not fully controllable from this repository. Publish under reserved names, enable 2FA and trusted publishing on every registry, sign releases, and document the exact canonical package names in the SDK contract so integrators can verify what they installed."
      },
      {
       "number": 175,
       "title": "Sender-constrained token downgraded to a bearer token by a validator that cannot check `cnf`",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "Mitigated",
       "description": "With two confirmation methods now in use (`x5t#S256` and `jkt`), a resource server or SDK will eventually meet a `cnf` it does not understand -- an older SDK meeting a `jkt`, or any validator meeting a future method. The natural-looking implementation ('no x5t#S256 field, therefore unbound') silently converts a sender-constrained token back into a bearer token at exactly the moment a newer server has started issuing a constraint the validator predates. The same failure appears as 'check whichever confirmation we can' on a token that names both.",
       "mitigation": "`axiam_auth::token::verify_token_binding` refuses a `cnf` naming no method it can check, INCLUDING an empty object, and treats two confirmations as a conjunction rather than a disjunction. The narrower `verify_certificate_binding` is retained for validators that genuinely cannot verify a proof, and it REFUSES a jkt-bound token rather than passing it. SDK contract §10.1 rule 9 makes the same behaviour normative for all eleven SDKs and requires both the negative tests and a positive regression test that an UNBOUND token is still accepted with no evidence at all -- because the opposite failure, demanding a proof from every caller, would break every existing deployment."
      }
     ],
     "open": 1,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
      },
      {
       "number": 209,
       "title": "The admin UI keeps rendering the previous tenant’s data after a switch",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "Switching the acting tenant called queryClient.clear(), which removes and destroys cached queries — but a mounted observer keeps its reference to the orphaned query and goes on rendering the data it already had, with no refetch: the page the operator was looking at kept showing the previous tenant’s rows under the new tenant’s name. Two riders: pages rendered before /auth/me answered gated on the old tenant’s permission set, and page-local state survived the switch. Separately, the self-service endpoints scoped the caller’s own record to the acting tenant instead of principal_tenant_id, so an organization administrator with a tenant selected could not open their own profile, saw no MFA factors and could not enrol one — with nothing on screen changed but the tenant switcher.",
       "mitigation": "Fixed in 1.0.0-beta06: the query cache is namespaced by the acting tenant via queryKeyHashFn, so cross-tenant bleed is structurally impossible rather than procedurally avoided; the switch swaps the routed subtree for a spinner until /auth/me has answered, and the subtree is keyed by the acting tenant so page-local state resets. Server-side, user_scope_tenant states the self-vs-others rule once: a caller’s own resources resolve in principal_tenant_id, anybody else’s follow the acting-tenant header — written into CONTRACT §5.2.2 rule 4 (contract 1.36) so no SDK “fixes” the old 404 by stripping the header, which would break the administrative form of the same endpoints. Guards were added for the classes, not the instances: every /api/v1 literal in the app is checked against openapi.json, and an invalidation-coverage test fails on any cached root nothing can invalidate."
      },
      {
       "number": 211,
       "title": "The assignment dialog offers the widest possible grant as its only option",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "tenant_scope was reachable from exactly one of the places roles are assigned — the role page’s dialogs, and only while administering an organization scope, with both restrictions invisible. The user page’s Assign Role dialog posted a bare user id: no resource scope, no tenant scope, no sign either existed — and at organization scope an unscoped grant reaches every tenant of the organization, so the page offered the widest possible assignment as its only assignment, silently. A group — where “these people administer these tenants” is most naturally written down — could not be granted a role from its own page at all.",
       "mitigation": "Fixed in 1.0.0-beta06: one shared AssignRoleDialog serves the user and group pages with the same ResourceScopePicker and TenantScopePicker as the role page, in the same order — shared rather than written twice, because drift between two phrasings of one question is exactly what produced the defect. The scope picker distinguishes a principal that could switch to the organization scope (and is pointed at the selector) from one for whom that door does not exist, using the same predicate as the sidebar and the server’s own guard. Stated residual: has_role is created and deleted but never updated, so re-scoping an existing grant remains a revoke plus a fresh assignment — the transient under- or over-grant during the swap is the operator’s to sequence (docs/admin/organization-scope.md)."
      },
      {
       "number": 265,
       "title": "A gateway echoes a rejected request body and the UI renders a prefixed secret unredacted, or an Axios error path skips redaction",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "`redactSecrets` exists because the error body is not always written by AXIAM at all — a reverse proxy, a load balancer or a gateway can answer instead, and those echo requests routinely. Its key match used `\\b(password|api_key|…)\\b`; underscore is a word character, so `\\bpassword\\b` does not match inside `smtp_password`, and `smtp_password=hunter2`, `smtpPassword=…` and `provider_api_key=…` passed straight through — the key shape a gateway actually emits. Separately, four `onError` handlers in the email-configuration panel — the one panel in the application that handles SMTP passwords and provider API keys — rendered `err.message`, so a real `400` showed as \"Request failed with status code 400\" and never reached `redactSecrets()` at all.",
       "mitigation": "2646add: the key is now word characters *ending* in a named secret, still followed by `\\s*[:=]`, so widening the key does not widen what counts as a match — \"password too short: minimum 12\" and the SCIM \"does not hold scim:provision\" message stay intact, both already pinned — and a secret word counts only when it ends the key, so `password_policy` is not mistaken for a credential and configuration errors are not mangled, the failure mode that makes people stop trusting the UI and read the network tab instead. Checked for catastrophic backtracking at 2000-character runs, near-miss prefixes and 300 keys in one message. 0ac3d46: all four handlers go through `getApiErrorMessage`, the existing test that asserted the broken generic fallback now asserts the server's sentence, and a new test pins that a server-echoed password is redacted rather than rendered. Frontend line coverage moved from 92.6% to 96.6% with the threshold ratcheted to the achieved number, which is what found both."
      }
     ],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "478f32d2-ac93-5350-ade6-1f0a28f6401a",
     "kind": "process",
     "x": 414,
     "y": 294,
     "w": 140,
     "h": 140,
     "name": "SDK HTTP core (11 languages)",
     "lines": [
      "SDK HTTP",
      "core",
      "(11",
      "languages)"
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
      },
      {
       "number": 183,
       "title": "SDK reshapes the WebAuthn ceremony the server configured",
       "type": "Tampering",
       "severity": "High",
       "status": "Mitigated",
       "description": "Contract 1.28 (§24) gives every SDK the relying-party half of the WebAuthn ceremony — four JSON round trips against the server. Every field in the server's PublicKeyCredentialCreationOptions is a security parameter, every one looks locally adjustable, and an SDK that \"fixes\" one — relaxing userVerification because a CI authenticator kept prompting, supplying a timeout the server omitted, re-encoding base64url \"to be safe\" — has weakened or broken a ceremony the server believes it configured. The server cannot catch a relaxation: an assertion produced under weaker options is still a valid assertion.",
       "mitigation": "CONTRACT §24.0 makes the pass-through rules normative for every SDK claiming §24: the server does all of the crypto and all of the policy; the SDK hands the server's options to the authenticator unchanged (no defaulting, no filling in, no normalizing), may not refuse options it parsed — a client-side algorithm allow-list is a second policy engine, and the tenant's is the only one that counts — and posts the authenticator's response back verbatim. The only permitted addition is the authenticatorAttachment hint, which selects which authenticator is prompted for, not what the server accepts. §24.8's required tests pin byte-identical pass-through, and §24.4 rule 1 does not license dumping a raw response body into an error an integrator would then log."
      },
      {
       "number": 184,
       "title": "TOTP secret or setup token leaks through account-lifecycle serialization",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "Contract 1.28 (§25) brings MFA enrolment, email verification and password reset into every SDK, and with them a new crop of credential-bearing fields: secret_base32, the otpauth:// URI that contains it, the forced-enrolment setup_token that completes a login, and the single-use reset and verification tokens. totp_uri is the field an implementer skips: wrapping the secret while leaving the URI bare wraps nothing, because the URI is what the caller passes to a QR renderer — and therefore the field that actually gets logged.",
       "mitigation": "CONTRACT §25.3 wraps every one of these fields in Sensitive<T>, names totp_uri in its own row precisely because it embeds the secret, and requires each SDK's §25 test to scan serialized output for the secret value itself rather than for the field name — which catches the URI case automatically. Single-use tokens are wrapped too: single-use is not the same as harmless, and a token is a credential right up until it is spent."
      },
      {
       "number": 185,
       "title": "Lifecycle helpers turned into an account-enumeration oracle",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Six of §25's nine operations are deliberately unauthenticated — a user who cannot log in is the entire audience for a password reset. Each is an enumeration oracle in waiting: an SDK that surfaces a \"no such user\" state on request_password_reset (even inferred from timing), distinguishes unknown from expired from already-consumed on a reset token, or displays the account a token belongs to beside the form re-creates exactly the oracle the server's uniform responses exist to prevent.",
       "mitigation": "CONTRACT §25.4 forbids all three, normatively: request_password_reset answers 200 whether or not the address exists and an SDK may not improve on it; 404 on the reset context means unknown, expired or already-consumed and the SDK's presentation may not distinguish them either; and the context response discloses no identity — contract 1.26 removed the username when OPAQUE made it unnecessary, and an SDK must not reintroduce one by inferring the account from elsewhere."
      },
      {
       "number": 266,
       "title": "An SDK on a two-listener deployment authenticates at the front-channel host, or sends the secret over the header channel that intermediaries log",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Once discovery can name a separate mTLS host (T-245), an SDK that ignores `mtls_endpoint_aliases` presents its certificate to a listener that never asked for one and authenticates nothing; one that reads an absent member as \"unsupported\" breaks against every single-listener deployment; one that synthesises an alias for the front channel raises a certificate-chooser dialog in the user's browser. And a server that accepts `client_secret_basic` (T-253) invites an SDK to send a long-lived credential in the one channel routinely logged by intermediaries.",
       "mitigation": "Contract 1.40 adds §21.3 rule 2, normative for the §21 client role only: an SDK making a call over mTLS must prefer an alias over the top-level entry, must read an absent member as \"no separate host\" rather than \"unsupported\", must not synthesise aliases for the three excluded endpoints, and must keep validating `iss` against the unchanged issuer; the guard role (§10.1 rule 9) is untouched, and the change is additive and server-side — every existing SDK keeps working unchanged against every existing deployment, because none publishes the member until an operator configures it. Contract 1.41 keeps §5 rule 3's MUST NOT on Basic authentication verbatim and changes only its rationale, from \"the server documents no alternative\" to the reason that was always the better one: the two methods carry the identical credential and only the header channel is routinely logged. Contract 1.42 records the two RFC 8414 discovery members as informative; SDK decoders ignore unknown members, as they did for `dpop_signing_alg_values_supported` and `mtls_endpoint_aliases`. **The SDK half landed on 2026-09-12 (R-8, contract 1.43).** Rule 2 had been normative since 1.40 and was implemented by nobody, which is the residual this closes: the server published the member and every SDK ignored it. Three things were added here first. The clause that was implicit — **an alias's query component is preserved, not appended to**: AXIAM's aliases carry the tenant as a query component, so an SDK that appends its own `?tenant_id=` produces a duplicated parameter the server cannot resolve to one tenant, and one that rebuilds the URL from host and path strips whatever else the deployment put there. Displacing the `tenant_id` value with the caller's own is correct and is explicitly not what the clause forbids — the multi-tenant document names no tenant and the client supplies its own. Reading the Rust SDK, which had implemented rule 2 since contract 1.40, is what produced that distinction: a first draft of the clause said \"verbatim\" and would have forbidden the one behaviour a multi-tenant deployment requires. Either way the failure is one that shows up *only* on a two-listener deployment, which is the deployment the rule exists for. The **§21.3.1 test vectors** — present, absent, malformed — published inside `CONTRACT.md` itself rather than as a fourth vendored artifact, so eleven repositories pin the same bytes and the existing drift gate already covers them; vector C must be **refused** rather than fallen back from, because quietly presenting a certificate to the front-channel host authenticates nothing while appearing to work; its two defects are a non-absolute URL and a scheme **weaker than the top-level endpoint it replaces** — comparing like with like, because an alias substitutes for exactly one endpoint. Neither \"must be `https`\" nor \"weaker than the `issuer`\" survives contact with an implementation: the server accepts an `http` alias for local development, every SDK suite runs against a mock server speaking plain HTTP, and a test fixture (or a deployment behind a TLS-terminating proxy) routinely pairs a realistic `issuer` string with loopback endpoints. Both wordings were tried against the Rust SDK and both failed tests that were correct. The refusal sits at the point of use, so a client with no certificate never reads the member and a malformed alias cannot break the clients that never use it. And the **§21.10 per-SDK table**, in the §21.9 style, where an unrecorded row is not a supported answer and `declines` with a reason is. Server side, two tests pin what SDKs pin: the alias object has exactly the six meaningful endpoints and never the three front-channel ones, and an unusable base (relative, non-`https`, or carrying a query or fragment) fails discovery rather than being published — so no conformant deployment can serve vector C and an SDK's refusal is defence in depth. Conformance rows 161–164. **The eleven implementations landed on 2026-09-13** (the same PRs as the §10.4 poller: rust #104, typescript #103, python #80, java #92, kotlin #62, csharp #87, php #67, go #77, swift #60, c #59, cplusplus #60, each released at that SDK's 1.0.0-beta14): §21.10 now has `yes` in both columns for every SDK, none `declines`, and each carries the three §21.3.1 vectors as tests — vector C refused at the point of use, so a client with no certificate never reads the member and a malformed alias cannot break the clients that never use it. Three of the eleven were first reported as unreachable for toolchain reasons and two of those reports were wrong (the .NET SDK is in Ubuntu's apt repository and NuGet was reachable; PHPUnit installs from apt); the Swift SDK alone was verified by CI rather than locally, and its commit says so. The residual this entry carried — a normative rule implemented by nobody — is closed; what remains is the ordinary one, that an integrator has to be on an SDK release that carries it."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
       "status": "Mitigated",
       "description": "An SDK that verifies the access token locally cannot see a role removal or account disable until the token expires — the client-side face of the stateless-verification trade-off recorded on the token service.",
       "mitigation": "Bounded by the 15-minute access-token lifetime. CONTRACT §10 and §11 expose route-guard and declarative-authorization helpers; integrations needing immediate revocation can call gRPC introspection or CheckAccess rather than verifying locally. **The server half of the cheaper answer landed on 2026-09-12 (R-6, decision C); the client half landed in all eleven SDKs on 2026-09-13, and this entry is Mitigated from that date.** Contract 1.44 §10.4 defines an optional poller for `GET /oauth2/revocations` (see T-39 for what the server publishes and why it is safe to serve unauthenticated): default off, poll interval and cached set both bounded, never on the request path, and **never fail closed** — a guard that cannot fetch the document, gets a non-`200`, cannot parse it or sees an unknown `alg` behaves exactly as it does with the feature off, and specifically must not read any of those as an empty list, which would be a guard silently honouring no revocations while appearing to honour them. The feed can only ever turn an accept into a reject; every §10.1 rule still runs first and still decides. A token with no `sid` is never matched against it. §10.4.1 records, per SDK, whether it polls — and as in §21.9, an unrecorded row is not a supported answer. **As of 2026-09-13 every row says `yes`**: `RevocationFeed` (or the C ABI's `axiam_client_enable_revocation_feed`) attached to the JWKS verifier in each language, off unless the caller attaches it, with a test suite per SDK pinning the fail-open rule — the unreachable, non-`200`, unparseable and unknown-`alg` cases each asserted to verify exactly as with no feed, and never as an empty set — and the bounded interval and cache (§10.4 rule 2; the Rust poller, for one, drops the *whole* set on overflow rather than truncating it, because a truncated set admits some revoked sessions while reporting none). The eleven PRs are rust #104, typescript #103, python #80, java #92, kotlin #62, csharp #87, php #67, go #77, swift #60, c #59, cplusplus #60, merged and released at each SDK's 1.0.0-beta14. The residual is the poll interval itself, and that both sides are opt-in: an integration that attaches no poller is exactly where it was, which is the documented fifteen-minute trade and the gRPC introspection answer."
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
     "open": 0,
     "notApplicable": 0
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
      },
      {
       "number": 186,
       "title": "Caller-supplied reactor transport connects without TLS",
       "type": "Information disclosure",
       "severity": "High",
       "status": "Mitigated",
       "description": "Contract 1.28 (§22.11) brings the reactor protocol core — v2 HMAC over the canonical serialization, freshness in both directions, nonce and correlation binding, the §22.5 allow-lists — to Swift, C and C++ over a transport the caller supplies, because no vendorable AMQP client exists for those targets. The runtime never sees a broker URL, so it cannot enforce §8b itself: the integrator's transport is where a plaintext amqp:// connection or a verification-skip flag would slip in, carrying signed-but-cleartext events and replies. Before 1.28 these three shipped nothing from §22 at all, and the sharper risk was integrators re-implementing the signing protocol from prose — which is how a signing bug ships.",
       "mitigation": "§8b rule 7's second clause is the whole of their obligation and it is discharged in code, not documentation: each of the three ships the rule 1–5 guard as a public, tested function (amqpsEndpoint, axiam_amqps_endpoint, axiam::amqps_endpoint) — scheme refusal with no loopback exception, no plaintext fallback, no verification-skip switch, fail-closed on an unparseable URL — and calls it in its own example transport before anything opens a socket. The transport seam is deliberately no wider than deliver-inbound and publish-reply, so it cannot hand the integrator the topology tools §22.1 forbids; the protocol core itself is now library code, ending the hand-rolled-HMAC divergence. HMAC signing (§8/§22.2) remains mandatory on every message regardless of transport."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 1,
     "notApplicable": 0
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
       "description": "The contract is where SDK security behaviour is actually specified — TLS policy, secret redaction, AMQP HMAC, CSRF. Relaxing a clause silently relaxes it across eleven implementations at once.",
       "mitigation": "The contract lives in this repository under normal review, and the drift and buf gates make any change to the generated artifacts visible in CI rather than in a downstream repository."
      },
      {
       "number": 199,
       "title": "Two OpenAPI exports cannot be told apart, so vendored spec drift goes unseen",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "Eleven SDK repositories vendor openapi.json and the §27 management registry, and generate client surface from them. Without a content identity, a stale or altered copy is indistinguishable from a faithful one — and the failure mode is real: 1.0.0-beta02 itself shipped a spec whose digest described beta01, because the release flow rewrote info.version under an assumption the digest field had deliberately inverted.",
       "mitigation": "Every OpenAPI export carries info.x-axiam-spec-digest, a SHA-256 over the document with that field absent, so two exports can be told apart and a vendored copy can be checked against the spec it claims to be (1.0.0-beta02). check-spec-digest.py recomputes the digest on every commit with no toolchain and no build, the SDK drift gate watches sdks/openapi.json itself, and the release script re-stamps the digest and regenerates the registry immediately after its version substitution — verified by replaying the release that broke (1.0.0-beta03). The digest tells an operator that the vendored spec moved; since 1.0.0-beta11 the release script also regenerates what each SDK derives from it (T-235)."
      },
      {
       "number": 210,
       "title": "The contract documents an acting-tenant header the server never reads",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "CONTRACT §5.2, §5.2.2 and §5.2.3 told SDKs to switch the acting tenant by sending X-Tenant-ID — a header the server has never read (the extractor’s constant is X-Axiam-Tenant) — in eighteen places. The failure mode is silence, not a 4xx: an SDK following the contract to the letter sends a header nothing looks at, the request quietly acts on the principal’s own tenant, and the caller gets a successful response describing the wrong tenant’s data. §5.2.3’s rule that naming a tenant outside reachable_tenant_ids is refused could not be true as written, because nothing was read to refuse.",
       "mitigation": "Fixed in 1.0.0-beta06 (contract 1.36, closing #395): the three sections name X-Axiam-Tenant. §5 rule 2’s unconditional X-Tenant-ID is deliberately not renamed — folding a constructor-tenant header into the acting-tenant header would override the acting tenant on every request an organization-level principal made after switching, reintroducing the bug through its fix. It now carries a note that it exists for proxies, gateways and an SDK’s own §10 resource-server middleware, that AXIAM does not read it, and that it must not be renamed. The eleven contract-1.35 SDK fan-out PRs were expected to implement the real header, and the correction let them re-sync against a contract that agrees with the server. Amended at contract 1.51 (dogfooding remediation, DF-008): that last claim was not true of the code. Read on 2026-09-23, no SDK sends X-Axiam-Tenant from any code path; all eleven name it in doc comments only, so an organization-level principal switched tenant by hand-rolling the header. Contract 1.51 §5.2 rule 1 moves the helper from MAY to SHOULD with a fixed shape, and closes a second silent path to the same failure: the server parses the header as a UUID and silently ignores a value that does not parse, so the request acts on the caller's own tenant and succeeds. The helper MUST refuse a non-UUID client-side before any wire call, is sent only when set, and is REST-only because the gRPC server reads no tenant metadata. The server behaviour is unchanged and the status stays Mitigated; the per-SDK ports (dogfooding plan C-1 … C-11) carry the helper."
      },
      {
       "number": 235,
       "title": "A release tags an SDK whose generated management surface disagrees with the spec it vendors",
       "type": "Tampering",
       "severity": "Medium",
       "status": "Mitigated",
       "description": "`scripts/mass-tag.sh` copies `CONTRACT.md`, `openapi.json` and `management-registry.json` into every SDK clone as part of a release, so a tagged SDK ships the spec its server was tagged from (T-199). It did not re-run the generator that turns those documents into each SDK's CONTRACT §27 management surface, so a release carrying schema changes tagged eleven trees whose committed code disagreed with the artifacts sitting beside it. v1.0.0-beta09 was the worked example: it re-vendored a spec carrying the WebAuthn user-verification policy (T-229) and regenerated nothing. Only the Swift, C and C++ SDKs said so, because they are the only three whose `§27 management surface drift-check` runs on a tag push; the other eight gate that job — or, in the Rust and TypeScript SDKs, the whole test job — to `pull_request`, and published a surface missing the new policy with no signal at all. A pure version bump then carried the broken trees forward through beta10.",
       "mitigation": "Fixed in 1.0.0-beta11. `mass-tag.sh` runs each SDK's generator immediately after the re-vendor and stages exactly what it wrote: the dirty set is recorded as path-plus-checksum before and after the call and compared as a symmetric difference, so an operator's unrelated local edit is never staged and a file that was stale before and correct after is recognised as repaired rather than missed. The generator table names all eleven repositories even where the answer is the common one, so a missing repository is a visible hole; a missing generator or interpreter is fatal rather than a skip, because tagging a tree the repository's own CI rejects is the failure this closes. The regeneration is unconditional — a surface can also be stale from a merge that moved the artifacts without regenerating, which is how beta09 went out — and prints \"already current\" in the common case. Verified against the live clones with a deliberately reverted surface in the C SDK, which was detected and exactly its six files staged. The repository-side gate closed in 1.0.0-beta12 (R-2), in all eleven SDK repositories: the §27 drift-check runs on tag pushes as well as pull requests, and the publish/release job lists it in `needs:`, so a stale surface fails *before* a version number is spent. Three shapes were found and fixed in place — six repositories had a dedicated job carrying `if: github.event_name == 'pull_request'` (dropped); Rust and TypeScript had the check as a step inside a `pull_request`-only test job (split into its own job, with the toolchain each generator needs); C, C++ and Swift already ran it on tags but their release job did not depend on it (one entry added to one list). Every generator was verified to detect drift locally — clean, perturbed, restored — rather than by pushing a deliberately red commit to eleven pull requests. Nothing else in any workflow changed."
      }
     ],
     "open": 0,
     "notApplicable": 0
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
       "mitigation": "Partially enacted, and narrowed at beta03. Nine of the eleven pipelines carry no long-lived registry credential: Rust, TypeScript, Python and C# and the shared axiam-opaque core publish via Trusted Publishing (OIDC); PHP through Packagist's webhook; Go, Swift, C and C++ from git tags. Every release workflow in the fleet now pins its actions by commit digest, and every published artifact — the server's binary tarballs and CycloneDX SBOMs, the container images, and each SDK's release artifacts — carries a GitHub build-provenance attestation, so an integrator can verify build origin with `gh attestation verify`. Maven Central (Java, Kotlin) still requires a stored Portal user token: Central has no trusted-publishing equivalent, and its OIDC surfaces are account sign-in and Sigstore signing, neither of which authorises an upload — see claude_dev/maven-central-publishing-decision.md. Those two are bounded by compensating controls instead: the credential is an environment secret behind a required-reviewer GitHub environment restricted to v* tags, every published file carries a Sigstore bundle (`.sigstore.json`) alongside its PGP signature — keyless, signed against the release workflow's GitHub OIDC identity and validated by the Central Publisher Portal, so the artifact set Central itself serves carries a statement of build origin the Portal token cannot forge — and the token rotates quarterly. A pull-request gate in each of those two repositories performs a real keyless signing run of the real artifact set on every change, so a release-path misconfiguration surfaces on a pull request rather than at a tag. Open because a stored bearer credential still exists for two of eleven registries."
      }
     ],
     "open": 1,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
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
     "open": 0,
     "notApplicable": 0
    }
   ],
   "total": 28,
   "open": 3,
   "notApplicable": 0,
   "bySeverity": {
    "High": 14,
    "Medium": 12,
    "Critical": 2
   }
  },
  {
   "id": 9,
   "title": "RADIUS front end — not built (G-11, declined 2026-10-06)",
   "description": "A design-only diagram. G-11 asked whether AXIAM should speak RADIUS, with EAP-TLS validated against its own per-tenant PKI; the spike (T23.11.1, claude_dev/radius-eap-tls-spike-2026-10-06.md) declined a native front end on 2026-10-06 and recorded the FreeRADIUS-backend route for when an adopter asks. Nothing drawn here exists except the AuthService · DeviceAuthService · RBAC engine element, drawn as the callee a front end would reach. The W5 F4 review required the threat entries to exist anyway, so a build starts from them: every threat on this diagram is recorded Not applicable — neither Mitigated, because no control exists, nor Open, because nothing in AXIAM is exposed — and becomes Mitigated or Open, with its tests, in the commit that builds the element it sits on. The NAS ↔ AXIAM trust boundary separates the customer's network access devices from the front end.",
   "width": 1338,
   "height": 908,
   "boundaries": [
    {
     "id": "3ef77340-3414-5674-9f16-7e5b5fa6c653",
     "x": 24,
     "y": 24,
     "w": 260,
     "h": 420,
     "label": "Network access devices\n(customer equipment)"
    },
    {
     "id": "13cb10e6-d629-5f07-a5d1-5e831747ac80",
     "x": 24,
     "y": 484,
     "w": 260,
     "h": 160,
     "label": "Administrators"
    },
    {
     "id": "3c86c436-6a3b-559e-b094-407cbf66edf1",
     "x": 24,
     "y": 684,
     "w": 260,
     "h": 200,
     "label": "Operator-run FreeRADIUS\n(option B, not built)"
    },
    {
     "id": "15b8c1ad-c3cc-5c9e-958e-a4b6aec88388",
     "x": 324,
     "y": 24,
     "w": 640,
     "h": 620,
     "label": "AXIAM — RADIUS front end\n(not built · G-11 declined 2026-10-06)"
    },
    {
     "id": "4d8af166-2164-5b0d-a9c4-e8e5553ceb0d",
     "x": 324,
     "y": 684,
     "w": 640,
     "h": 200,
     "label": "AXIAM — core services and REST API"
    },
    {
     "id": "dd3a88da-8c45-5ad1-b182-4d03b14e17e5",
     "x": 1014,
     "y": 84,
     "w": 300,
     "h": 560,
     "label": "Data tier"
    }
   ],
   "nodes": [
    {
     "id": "2208055f-d9f2-5ff4-9e22-f2aa0e8b9e85",
     "kind": "actor",
     "x": 49,
     "y": 84,
     "w": 150,
     "h": 80,
     "name": "Supplicant (device with an AXIAM certificate)",
     "lines": [
      "Supplicant",
      "(device with an",
      "AXIAM certificate)"
     ],
     "description": "An 802.1X supplicant — an IoT or OT device, a gateway, a workload host — holding an AXIAM-issued Device certificate bound to a service account. It reaches AXIAM only through the NAS.",
     "outOfScope": true,
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "3f811f63-3d44-5405-be42-cb1021ed0506",
     "kind": "actor",
     "x": 49,
     "y": 304,
     "w": 150,
     "h": 80,
     "name": "NAS (switch, access point, VPN gateway)",
     "lines": [
      "NAS",
      "(switch, access",
      "point,",
      "VPN gateway)"
     ],
     "description": "A network access server registered to one tenant: it relays EAP and asks AXIAM to decide. On UDP it is authenticated by its source address and shared secret; on RadSec and RADIUS/1.1 by its certificate pin and its address.",
     "outOfScope": true,
     "threats": [
      {
       "number": 448,
       "title": "A host impersonates a registered NAS with its source address and a guessed or leaked shared secret",
       "type": "Spoofing",
       "severity": "High",
       "status": "NotApplicable",
       "description": "On RADIUS over UDP a network access server (a switch, an access point, a VPN gateway) is authenticated by its source address and a shared secret and nothing else. A host that can send from a registered address — spoofed on UDP, or on the same segment — and knows or guesses the secret is that NAS: its requests are decided in the NAS's tenant and the replies carry what the NAS would receive.",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record §6.3, §6.4, R1). Required of any build, from its first commit: `Message-Authenticator` verified with the NAS's own secret, in constant time, before any state, lookup or hash (T-449); secrets generated server-side at 128 bits or more, a supplied one refused below that floor (T-466); RadSec or, preferably, RADIUS/1.1 (RFC 9765), where the NAS is its certificate's SHA-256 pin **and** its registered address, verified against the tenant's own anchors; plain UDP served only to a NAS registered `legacy_udp`, marked as such in the API, the console and every audit row. If built as specified: Mitigated, with one accepted residual — a weak or leaked secret on a `legacy_udp` NAS."
      }
     ],
     "open": 0,
     "notApplicable": 1
    },
    {
     "id": "587c5aac-7cd9-5d9d-9398-1a442cd16eb8",
     "kind": "actor",
     "x": 49,
     "y": 534,
     "w": 150,
     "h": 80,
     "name": "Tenant administrator (console / API)",
     "lines": [
      "Tenant administrator",
      "(console / API)"
     ],
     "description": "Registers, rotates, moves and disables NASes through a tenant-scoped management API (not built).",
     "outOfScope": true,
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "830f5d18-eef4-58e2-b313-7838ea024cf5",
     "kind": "actor",
     "x": 49,
     "y": 744,
     "w": 150,
     "h": 80,
     "name": "FreeRADIUS (operator-run)",
     "lines": [
      "FreeRADIUS",
      "(operator-run)"
     ],
     "description": "Option B: the operator's FreeRADIUS terminates RADIUS and EAP-TLS itself, trusting a CA bundle exported from AXIAM, and may ask AXIAM for a decision through rlm_rest.",
     "outOfScope": true,
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "8f4b56af-1137-5ea6-a3fa-8dcfb0cdb5e1",
     "kind": "process",
     "x": 374,
     "y": 124,
     "w": 140,
     "h": 140,
     "name": "RADIUS / RadSec listener (codec, Message-Authenticator, limiter)",
     "lines": [
      "RADIUS /",
      "RadSec",
      "listener",
      "(codec,",
      "Message-Authenticator,",
      "limiter)"
     ],
     "description": "UDP and RadSec / RADIUS/1.1 sockets, the packet codec, Message-Authenticator verification and generation, the duplicate cache and the listener's own limiter. Outside the Actix middleware, so it carries every control itself.",
     "outOfScope": true,
     "threats": [
      {
       "number": 451,
       "title": "Credentials are guessed through a second front door that no limiter or lockout covers (the Keycloak 26.7.x class)",
       "type": "Spoofing",
       "severity": "High",
       "status": "NotApplicable",
       "description": "A RADIUS listener is an authentication path beside the REST login, reaching the same `AuthService` and the same certificate path, but it is a UDP or TLS socket outside the Actix middleware where every existing limiter lives. A surface that authenticates a credential and is covered by neither the limiters nor the lockout is the class T-429 recorded for CIBA: an attacker routes password guessing through it. The human login limiter is keyed per IP and no preset moves it, so for a NAS — one source address for a whole site — it is also the wrong key.",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record §6.1, R6). The W5 F4 review's constraint (§15): **the brute-force lockout and the limiters cover it from the first commit**. Required of any build: the listener has its own limiter, with `radius_*` fields in `RateLimitConfig` and `MachineLimitPreset` for `internet`, `gateway` and `mesh` (the human endpoints untouched), sized from a measured power-restore storm; it meters per authenticated NAS and per tenant once `Message-Authenticator` verifies, per (NAS, supplied identity) as a rate that is never a lockout, and per source address before verification as a drop that never answers; PAP failures go through the tenant's `LockoutPolicy` by `AuthService::record_failed_login` — the console's own counter, not a second one — and a name that matches no account through `UnknownNameLockout` (T-332); and a test enumerates every accept path (UDP, RadSec, each EAP state) and fails the build if one reaches `AuthService`, the certificate path or the NAS registry without passing the limiter. If built as specified: Mitigated."
      },
      {
       "number": 452,
       "title": "Unauthenticated packets reach the hash path, and a PAP flood starves the console's sign-in",
       "type": "Denial of service",
       "severity": "High",
       "status": "NotApplicable",
       "description": "Argon2id is expensive by design and its permits are shared across every password path (CQ-B02 backpressure). A packet that reaches a password verify, a certificate lookup or a secret's decryption before it is authenticated makes a spoofed UDP flood cost AXIAM work per packet; and an authenticated NAS forwarding a PAP flood can take every hash permit, so console and API sign-ins queue behind it.",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record §6.1, §6.3, R7). Required of any build: `Message-Authenticator` verified first — before any state, any hash, any certificate lookup and any decryption beyond the one secret the verify needs; a packet that fails it dropped in a per-source bucket that never answers; what passes metered per NAS and per tenant (T-451); and RADIUS given a sub-limit of the shared hash permits, so it can never hold all of them. If built as specified: Mitigated."
      },
      {
       "number": 453,
       "title": "A replayed or retransmitted Access-Request is decided twice",
       "type": "Tampering",
       "severity": "Medium",
       "status": "NotApplicable",
       "description": "RADIUS over UDP retransmits, and a captured request can be replayed. A server that treats each copy as new makes a second decision, counts a second failed sign-in toward a lockout, or advances an EAP conversation twice.",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record R20). Required of any build: duplicates detected by (NAS, Identifier, Request Authenticator) in a short cache that returns the identical cached answer without deciding again (RFC 5080 — recalled in the spike, to be read against the RFC before building), and every EAP `State` value bound to the NAS and its conversation. If built as specified: Mitigated."
      },
      {
       "number": 454,
       "title": "An unreviewed RADIUS crate, or a GPL-licensed RADIUS image, enters the build",
       "type": "Tampering",
       "severity": "Medium",
       "status": "NotApplicable",
       "description": "The packet codec and the EAP-TLS state machine parse unauthenticated network input. A third-party RADIUS crate whose maintenance, licence and fuzzing are unknown, or a recipe that builds and ships a FreeRADIUS image, brings code nobody here reviewed — or a licence the project did not choose — into the supply chain.",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record §5.1, §5.2, R25). The first task of any build (A-1) evaluates the existing crates' licence, maintenance and fuzzing before one is adopted, and the preferred route is a small in-house codec with `cargo-fuzz` targets; option B's recipe references an upstream image and ships none. If built as specified: Mitigated."
      }
     ],
     "open": 0,
     "notApplicable": 4
    },
    {
     "id": "d5377ed1-68a1-54e6-bb23-07a302aa7610",
     "kind": "process",
     "x": 374,
     "y": 404,
     "w": 140,
     "h": 140,
     "name": "EAP-TLS state machine (over rustls)",
     "lines": [
      "EAP-TLS",
      "state",
      "machine",
      "(over",
      "rustls)"
     ],
     "description": "Sans-IO rustls server inside EAP: fragmentation and reassembly, the conversation table, MSK / EMSK export, the EAP method allow-list (TLS only).",
     "outOfScope": true,
     "threats": [
      {
       "number": 455,
       "title": "In-flight EAP conversations or fragment reassembly exhaust memory",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "NotApplicable",
       "description": "An EAP-TLS handshake is larger than one RADIUS packet, so the server keeps a conversation per supplicant and reassembles fragmented TLS records. A compromised registered NAS, or a flood of conversation starts, fills the conversation table or grows a reassembly buffer without bound.",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record §4.4, R8). Required of any build: in-flight conversations capped per NAS and per tenant and expired on a TTL; the reassembled TLS record, the number of rounds and the certificate-chain size capped; `State` a server-generated random value bound to the NAS; the state machine fuzzed. If built as specified: Mitigated."
      },
      {
       "number": 456,
       "title": "A negotiation is downgraded: another EAP method, an older TLS version, or a RADIUS/1.1 NAS falling back to the shared-secret profile",
       "type": "Tampering",
       "severity": "High",
       "status": "NotApplicable",
       "description": "Three negotiations precede every decision: the EAP method (a supplicant may NAK EAP-TLS and propose another), the TLS version inside EAP-TLS, and — on RadSec — the RADIUS/1.1 profile negotiated with ALPN. A server that negotiates down accepts EAP-MD5, TLS 1.2 where 1.3 was configured, or the MD5-keyed profile RFC 9765 exists to remove.",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record §6.3, §6.9, R15). Required of any build: refuse rather than negotiate. The EAP method allow-list is `TLS` and nothing else, and a NAK is a reject; TLS 1.3 is the default and 1.2 a per-NAS opt-in for supplicants that need it; a NAS registered `radius_1_1` that fails ALPN is refused, never served the secret-based profile, and the two profiles never mix on one connection. If built as specified: Mitigated."
      }
     ],
     "open": 0,
     "notApplicable": 2
    },
    {
     "id": "8030e087-2b62-5307-b04f-b5027c8e6a4d",
     "kind": "process",
     "x": 654,
     "y": 254,
     "w": 140,
     "h": 140,
     "name": "RADIUS decision (tenant, authN, reply attributes)",
     "lines": [
      "RADIUS",
      "decision",
      "(tenant,",
      "authN,",
      "reply",
      "attributes)"
     ],
     "description": "Resolves the tenant from the authenticated NAS, authenticates (EAP-TLS through DeviceAuthService, PAP through AuthService), authorizes through the RBAC engine, builds the one Access-Reject or the Access-Accept and its reply profile, and audits the decision.",
     "outOfScope": true,
     "threats": [
      {
       "number": 457,
       "title": "Access-Reject is an oracle: unknown, locked or disabled users are told apart by content, silence or timing",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "NotApplicable",
       "description": "A RADIUS server that answers an unknown user differently from a wrong password — a `Reply-Message`, an EAP step skipped, an attribute present or absent, a faster reply — lets anyone at a NAS enumerate a tenant's accounts and learn which are locked or disabled. D-63 recorded the same obligation for CIBA's `bc-authorize`.",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record §6.2, R4). The W5 F4 review's constraint (§15): **an unknown user is not an oracle** (D-63's decoy). RADIUS already has one negative answer, so a build gives exactly one: for an unknown, locked, disabled, wrong-credential, wrong-tenant, revoked-certificate or unbound-certificate request alike, an Access-Reject (EAP-Failure inside, for EAP) with no `Reply-Message`, no vendor error attribute and no optional attribute; the reason goes to the audit row only. The EAP-TLS Start answers an EAP-Identity whatever it names — the identity is never looked up before the handshake. On the password path every rejecting branch costs the same Argon2id work as a wrong password (SEC-026's equalising verify), so no branch answers faster. Unregistered or unauthenticated sources get silence, the same for each. Acceptance tests: the decoded packet byte-identical across every rejecting condition (only the Identifier and the authenticators excluded), and a response-time band rather than equal bytes alone. If built as specified: Mitigated."
      },
      {
       "number": 458,
       "title": "Anyone at a NAS locks a named user out by typing wrong passwords",
       "type": "Denial of service",
       "severity": "Medium",
       "status": "NotApplicable",
       "description": "An account lockout keyed on a user's failed verifications can be provoked by whoever can submit that user's name with a wrong password — at a network port, anyone with physical access. A lockout keyed on a value the caller supplies (a MAC address, an EAP identity, a NAS, a source address) is worse: a denial of service against whoever that value names.",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record §6.1, R5). Required of any build: the only lockout is the one keyed on the user's own failed verifications — the tenant's `LockoutPolicy`, with the console's counter and backoff — bounded by a per-(NAS, identity) rate bucket; nothing keyed on a caller-supplied value is ever a lockout (D-69); EAP-TLS has no password to guess and never locks a service account. If built as specified: Mitigated, with the residual the console already carries — whoever can type a name and a wrong password can start that account's lockout."
      },
      {
       "number": 459,
       "title": "A NAS of tenant A authenticates a user or device of tenant B",
       "type": "Elevation of privilege",
       "severity": "Critical",
       "status": "NotApplicable",
       "description": "Tenants of one organization share its CA, so a device certificate issued under tenant B's signing CA chains to the same root a tenant A NAS would trust: chain verification alone does not separate tenants. And a server that takes the tenant from the packet — a realm in `User-Name`, `Called-Station-Id`, `NAS-Identifier`, a vendor attribute, the EAP identity — lets the sender choose it.",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record §6.5, R9, R10). Required of any build: the tenant is the authenticated NAS's and nothing the packet says; a source address is registered once across all tenants (a unique index on the normalised address, a collision refused at write time); after the EAP-TLS handshake the certificate is resolved by `DeviceAuthService::authenticate_der` and refused unless its row's `tenant_id` equals the NAS's; the handshake's anchors are that tenant's own `mtls_trust_anchor` CAs, not the deployment-wide set; every repository call is scoped by the NAS's tenant. Acceptance test: a valid certificate issued under tenant B, presented through tenant A's NAS, is rejected. If built as specified: Mitigated."
      },
      {
       "number": 460,
       "title": "The RADIUS path is a weaker way in: a password alone on a tenant that enforces MFA, or a client's token approving a pending request",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "NotApplicable",
       "description": "A second authentication path is only as strong as its weakest rule. PAP carries a password and nothing else, so a tenant with `mfa_enforced` that accepted a password-only RADIUS login would have an MFA policy any NAS bypasses. And a push approval later routed to a RADIUS user would reopen T-447 if an access token minted for a client — a RADIUS service account's — could approve it.",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record §6.8, §6.9, R16, R18). Required of any build: PAP refused for an `mfa_enforced` tenant, or followed by an Access-Challenge for the second factor (TOTP, deferred), never a password alone — the console's rule is the floor. No approval surface: if push approval is ever added it goes through CIBA's approval routes, which take a console sign-in only (P23W5-04, T-447). If built as specified: Mitigated."
      },
      {
       "number": 461,
       "title": "A reply profile assigns a VLAN or privilege level its writer could not grant",
       "type": "Elevation of privilege",
       "severity": "High",
       "status": "NotApplicable",
       "description": "An Access-Accept carries what the NAS enforces: a VLAN (`Tunnel-Private-Group-Id`), a session timeout, a vendor privilege level. Free-form reply profiles, or profiles writable under a broad permission, let an administrator who may not grant network administration write one that does, and make a vendor-specific attribute an escalation path.",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record §5.1, R17; the model is deferred item D5). Required of any build: `network:join` and `network:admin` checked on a network-segment resource through `check_access`; the reply profile hung off that resource, its attribute types taken from an allow-list and its values validated against the dictionary; profile writes behind their own permission and audit row; a profile that grants more than its writer holds refused; deny-override used to quarantine a subtree. If built as specified: Mitigated."
      },
      {
       "number": 462,
       "title": "A revoked certificate or disabled account keeps its network port until the session re-authenticates",
       "type": "Elevation of privilege",
       "severity": "Medium",
       "status": "NotApplicable",
       "description": "RADIUS decides at authentication time. Without dynamic authorization (RFC 5176 CoA / Disconnect) AXIAM cannot end a session a NAS has already admitted, so a device whose certificate is revoked, or an account that is disabled, keeps its port until the NAS re-authenticates it.",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record R21). Required of any build: `Session-Timeout` capped per tenant and the bound stated in the product. Dynamic authorization is a separate, later item and inherits T-467's binding rule: AXIAM's own messages, carrying session and user identifiers, go to the registered NAS address only. If built as specified this entry stays **Open** — a residual bounded by the session timeout until dynamic authorization ships."
      },
      {
       "number": 463,
       "title": "A RADIUS decision goes unaudited, or an unauthenticated sender chooses the audit volume",
       "type": "Repudiation",
       "severity": "Medium",
       "status": "NotApplicable",
       "description": "Every Accept and Reject is an access decision a tenant must be able to account for. A decision with no row, or with a row that lacks the NAS, the subject or the method, cannot be attributed; a row per forged packet hands an attacker control of audit volume and buries the rows that matter.",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record §6.6, R13). Required of any build: one append-only row per authenticated decision, accept and reject, with the NAS, the tenant, the subject when one was resolved, the method, the transport profile, the outcome and an internal reason — never a password, a shared secret, an EAP payload, a private key or an MSK; unauthenticated packets aggregated, one row per source per window. If built as specified: Mitigated."
      },
      {
       "number": 464,
       "title": "MAC addresses and user names enter the audit trail and escape the erasure paths",
       "type": "Information disclosure",
       "severity": "Medium",
       "status": "NotApplicable",
       "description": "`Calling-Station-Id` is a device's MAC address and `User-Name` a person's login: personal data. Written into audit rows and registry fields by a new surface, they would sit outside the personal-data register and survive an erasure request.",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record §6.6, R14). Required of any build: both entered in the personal-data register (`crates/axiam-core/src/personal_data.rs`) and its erasure paths in the commit that first writes them. If built as specified: Mitigated."
      },
      {
       "number": 465,
       "title": "A reject flood becomes a notification flood",
       "type": "Denial of service",
       "severity": "Low",
       "status": "NotApplicable",
       "description": "If a RADIUS event can notify — a wrong secret from a registered address, a lockout, a NAS going silent — whoever can provoke rejects can send mail, and one notification per packet buries the alert that matters (T-117, D-73).",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record §6.7, R19). Required of any build: RADIUS audit actions reach notification events only through a `NotificationGate` — at most one per NAS per hour, claimed in the datastore, `false` and logged once when it cannot decide — while every reject keeps its audit row. If built as specified: Mitigated."
      }
     ],
     "open": 0,
     "notApplicable": 9
    },
    {
     "id": "06bc2885-6802-5e8d-969c-cdc139c499da",
     "kind": "store",
     "x": 1079,
     "y": 304,
     "w": 170,
     "h": 80,
     "name": "nas (NAS registry, sealed secret)",
     "lines": [
      "nas (NAS registry,",
      "sealed secret)"
     ],
     "description": "One row per NAS: tenant, name, transport (radius_1_1 / radsec / legacy_udp), a source address unique across all tenants, the shared secret sealed under pki_encryption_key with its key version, the RadSec certificate pin, minimum TLS version, allowed EAP methods, enabled. Not built.",
     "outOfScope": true,
     "threats": [
      {
       "number": 466,
       "title": "The per-NAS shared secret is stored readable or read back, where it must be sealed and write-only",
       "type": "Information disclosure",
       "severity": "High",
       "status": "NotApplicable",
       "description": "The shared secret cannot be hashed: the server needs it to compute `Message-Authenticator` and, on UDP, the MD5 constructs, so it is stored in recoverable form. A plaintext column, a read that projects it, a log line or a weak operator-chosen value gives whoever reaches the API, the datastore or a backup the means to impersonate the NAS (T-448) and to undo what its traffic hides (T-450).",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record §6.4 items 1–2, R11). The W5 F4 review's constraint (§15): **the per-NAS secret is a credential sealed under `pki_encryption_key`, and write-only**. Required of any build: AES-256-GCM, a fresh nonce per write, nonce and ciphertext in their own columns and a key version, as `scim_target` seals its credential; any write that sets a secret refused when the key is absent (the handler answers `503`); no read projects it (`secret_set: true` and the key version only); generated server-side at 128 bits or more and shown once, a supplied one accepted only at the same floor; the plaintext zeroized inside the verifier. Its binding to the NAS address is T-467. If built as specified: Mitigated, with the residual every sealed credential carries — a datastore dump together with the process's `pki_encryption_key`."
      },
      {
       "number": 467,
       "title": "A NAS is moved to another address without its secret, redirecting what the secret yields (the P23W5-01 class)",
       "type": "Tampering",
       "severity": "High",
       "status": "NotApplicable",
       "description": "The secret authenticates one address, and what it yields — the session key in an Accept's `MS-MPPE-*`, and AXIAM's own messages to the NAS if dynamic authorization is ever added — goes to that address. An administrator who can change a NAS's source address, transport or RadSec certificate pin without presenting the secret redirects all of it to a host they control, holding a credential they never saw: the shape of P23W5-01, where an outbound SCIM target's `base_url` moved without its secret.",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record §6.4 items 3–6, R12). The W5 F4 review's constraint (§15): **the secret is bound to the NAS address it was registered for**. Required of any build: a write that changes the source address, the transport or the certificate pin without the new secret in the same write refused with `400` naming the field — enforced in the repository against the very row its conditional write replaces, so a racing write cannot slip past (the `moves_credential` rule of T-409 and T-416); every reply sent to the packet's authenticated source and never to an address named in an attribute (`NAS-IP-Address`, `NAS-Identifier` and `Called-Station-Id` are audit fields, not routing); for RadSec both the pin and the address checked; a disable, delete or rotation applied on the next packet, with an open RadSec connection of a disabled NAS closed. If built as specified: Mitigated."
      }
     ],
     "open": 0,
     "notApplicable": 2
    },
    {
     "id": "135a3dfe-73eb-570c-a055-9f10022ef81f",
     "kind": "process",
     "x": 374,
     "y": 714,
     "w": 140,
     "h": 140,
     "name": "Authorize endpoint for rlm_rest (option B)",
     "lines": [
      "Authorize",
      "endpoint",
      "for",
      "rlm_rest",
      "(option B)"
     ],
     "description": "Option B, deferred item D4: POST a certificate fingerprint and NAS identity, get allow and reply attributes. An ordinary authenticated REST route. Not built.",
     "outOfScope": true,
     "threats": [
      {
       "number": 468,
       "title": "Option B's authorize endpoint answers “is this certificate good in this tenant” to whoever holds its caller credential",
       "type": "Spoofing",
       "severity": "Medium",
       "status": "NotApplicable",
       "description": "If AXIAM backs an operator's FreeRADIUS with a decision endpoint for `rlm_rest`, that endpoint is an authenticated oracle on certificate status and policy. A stolen caller credential lets its holder probe which certificates and devices exist and are allowed, and a verbose deny would say why.",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record §5.2 B-3, R23; deferred item D4). Required of any build: the caller holds a dedicated permission, its token is bound to its own certificate (`cnf`), it is metered on a machine preset keyed on the authenticated caller, each decision writes an audit row, and a deny carries no reason. It is an ordinary authenticated REST route, and enters the model with its code (plan §7 rule 2). If built as specified: Mitigated."
      }
     ],
     "open": 0,
     "notApplicable": 1
    },
    {
     "id": "db19c1f9-1cbb-537c-8767-6f813254755d",
     "kind": "process",
     "x": 654,
     "y": 714,
     "w": 140,
     "h": 140,
     "name": "AuthService · DeviceAuthService · RBAC engine (built)",
     "lines": [
      "AuthService",
      "·",
      "DeviceAuthService",
      "·",
      "RBAC engine",
      "(built)"
     ],
     "description": "The existing authentication, device-certificate and authorization services, modelled on the Authentication, PKI and Authorization diagrams. Drawn here only as the callee a RADIUS front end would reach; nothing on this diagram changes them.",
     "outOfScope": false,
     "threats": [],
     "open": 0,
     "notApplicable": 0
    }
   ],
   "edges": [
    {
     "id": "4be70add-18b4-5e12-aeb8-26aff69a03d0",
     "path": "M124,164 L124,304",
     "name": "EAP over LAN",
     "description": "Not built (G-11 declined 2026-10-06).",
     "label": "EAP over LAN (802.1X)",
     "labelLines": [
      "EAP over LAN (802.1X)"
     ],
     "lx": 124,
     "ly": 234,
     "bidirectional": true,
     "encrypted": false,
     "publicNetwork": false,
     "protocol": "EAPOL",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "a1ad58e6-ffa1-5ed7-8977-6ddf5f4842f2",
     "path": "M199,308.8 L380.6,223.7",
     "name": "Access-Request / Accept / Reject / Challenge",
     "description": "Not built (G-11 declined 2026-10-06).",
     "label": "Access-Request / Accept / Reject / Challenge (UDP 1812, RadSec, RADIUS/1.1)",
     "labelLines": [
      "Access-Request / Accept / Reject /",
      "Challenge (UDP 1812, RadSec,",
      "RADIUS/1.1)"
     ],
     "lx": 289.8,
     "ly": 266.3,
     "bidirectional": true,
     "encrypted": false,
     "publicNetwork": true,
     "protocol": "RADIUS",
     "threats": [
      {
       "number": 449,
       "title": "Blast-RADIUS: an on-path attacker turns an Access-Reject into an Access-Accept because `Message-Authenticator` is not required",
       "type": "Tampering",
       "severity": "Critical",
       "status": "NotApplicable",
       "description": "The RADIUS Response Authenticator is MD5 over the packet and the shared secret (RFC 2865). CVE-2024-3596 (“Blast-RADIUS”) showed that an on-path attacker can use an MD5 chosen-prefix collision, through attribute bytes it controls such as `Proxy-State`, to turn any valid response into any other — a Reject into an Accept — without the secret, in any exchange where `Message-Authenticator` (HMAC-MD5, RFC 2869) is absent or unchecked. RFC 2869 made that attribute mandatory only alongside EAP, so password exchanges were exposed.",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record §4.2, §6.3, R2). The W5 F4 review's constraint (§15): **`Message-Authenticator` required**. On every profile that has a shared secret (UDP, classic RadSec) every Access-Request must carry it and every response carries it, positioned as the Blast-RADIUS guidance asks (first, as the spike recalls it — re-verified against the advisory before building); a request without it, or with one that does not verify, is dropped silently and counted, never answered, with no “optional for non-EAP” path; `Proxy-State` in a request is refused (AXIAM is not a proxy); a NAS that cannot send the attribute is refused registration rather than served. Under RADIUS/1.1 (RFC 9765) the secret and every MD5 construct are gone and the attribute is ignored if received; a NAS registered for that profile that fails to negotiate it is refused, never downgraded (T-456). Acceptance tests: a request without the attribute, and one with a forged attribute, each draw no answer. If built as specified: Mitigated."
      },
      {
       "number": 450,
       "title": "MD5-only attribute hiding gives up the Wi-Fi session key or a password to whoever holds the shared secret",
       "type": "Information disclosure",
       "severity": "High",
       "status": "NotApplicable",
       "description": "`User-Password` is hidden by an MD5 stream keyed with the secret and the Request Authenticator, and `MS-MPPE-Send-Key` / `MS-MPPE-Recv-Key` — which carry the EAP-TLS MSK, from which the access point derives the Wi-Fi session key — by an MD5 salt construction over the same secret (RFC 2865, RFC 2548). A passive observer who learns the secret, or guesses a weak one, recovers the password or the session key from captured traffic; over classic RadSec those constructs are keyed with a fixed, public string and add nothing. CHAP, MS-CHAP(v2) and EAP-MD5 are worse still: MD5, or MD4 and DES, over a password the server would have to hold in reversible form.",
       "mitigation": "Not built (G-11 declined 2026-10-06; spike record §4.2, §4.3, §6.3, R3). The W5 F4 review's constraint (§15): **MD5-only attributes treated as the weakness they are**. Required of any build: PAP and `MS-MPPE-*` carried only over RadSec or, preferably, RADIUS/1.1 over TLS 1.3, where the obfuscation is removed and TLS carries the confidentiality; on plain UDP only for a NAS registered `legacy_udp`, with a generated secret of at least 128 bits, flagged in the API, the console and each decision's audit row — never PAP over UDP without that flag; CHAP, MS-CHAP, MS-CHAPv2 and EAP-MD5 not implemented (an Argon2id store cannot verify them, and should not be able to); RADIUS accounting not implemented. If built as specified this entry stays **Open** for every `legacy_udp` NAS: the weakness is inherent in the legacy profile and is accepted only per NAS, by an explicit flag."
      }
     ],
     "open": 0,
     "notApplicable": 2
    },
    {
     "id": "3d4cf496-da07-5f78-8678-62f26526622f",
     "path": "M444,264 L444,404",
     "name": "EAP-Message (reassembled)",
     "description": "Not built (G-11 declined 2026-10-06).",
     "label": "EAP-Message (reassembled)",
     "labelLines": [
      "EAP-Message (reassembled)"
     ],
     "lx": 444,
     "ly": 334,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "c19d4368-0a26-5f3e-b3b9-2c1191d90202",
     "path": "M507.5,223.5 L660.5,294.5",
     "name": "authenticated request (NAS, tenant)",
     "description": "Not built (G-11 declined 2026-10-06).",
     "label": "authenticated request (NAS, tenant)",
     "labelLines": [
      "authenticated request (NAS, tenant)"
     ],
     "lx": 584,
     "ly": 259,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "ef5e59d4-556e-59e3-8f69-56330818cacc",
     "path": "M505.7,440.9 L662.3,357.1",
     "name": "client certificate after the handshake",
     "description": "Not built (G-11 declined 2026-10-06).",
     "label": "client certificate (DER) after the handshake",
     "labelLines": [
      "client certificate (DER) after the",
      "handshake"
     ],
     "lx": 584,
     "ly": 399,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "12768376-3ad4-56cc-b093-09779d2ab910",
     "path": "M514,195.2 L988,203.7 Q1004,204 1016,214.5 L1118.3,304",
     "name": "resolve NAS by source address; unseal secret",
     "description": "Not built (G-11 declined 2026-10-06).",
     "label": "resolve NAS by source address; unseal secret (SurrealQL)",
     "labelLines": [
      "resolve NAS by source address;",
      "unseal secret (SurrealQL)"
     ],
     "lx": 834.9,
     "ly": 201,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "SurrealDB",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "119c78ca-2161-5c62-8568-df1f78137e12",
     "path": "M199,581.8 L978.1,662.4 Q994,664 1001.5,649.9 L1142.8,384",
     "name": "register / rotate / move / disable a NAS",
     "description": "Not built (G-11 declined 2026-10-06).",
     "label": "register / rotate / move / disable a NAS (HTTPS, not built)",
     "labelLines": [
      "register / rotate / move / disable a",
      "NAS (HTTPS, not built)"
     ],
     "lx": 754.2,
     "ly": 639.2,
     "bidirectional": false,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "864f847c-2922-5143-83f9-0876d3abaf30",
     "path": "M724,394 L724,714",
     "name": "authenticate, authorize, audit",
     "description": "Not built (G-11 declined 2026-10-06).",
     "label": "authenticate, authorize, audit",
     "labelLines": [
      "authenticate, authorize, audit"
     ],
     "lx": 724,
     "ly": 554,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "f042ac97-146d-5dc1-a64c-2daef8c8d427",
     "path": "M199,784 L374,784",
     "name": "authorize (rlm_rest)",
     "description": "Not built (G-11 declined 2026-10-06).",
     "label": "authorize (HTTPS, token bound to the caller's certificate)",
     "labelLines": [
      "authorize (HTTPS, token bound to the",
      "caller's certificate)"
     ],
     "lx": 286.5,
     "ly": 784,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": true,
     "protocol": "HTTPS",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    },
    {
     "id": "54f403af-723f-5221-b1c1-21f2f3dc718d",
     "path": "M514,784 L654,784",
     "name": "certificate status and policy",
     "description": "Not built (G-11 declined 2026-10-06).",
     "label": "certificate status and policy",
     "labelLines": [
      "certificate status and policy"
     ],
     "lx": 584,
     "ly": 784,
     "bidirectional": true,
     "encrypted": true,
     "publicNetwork": false,
     "protocol": "in-process",
     "threats": [],
     "open": 0,
     "notApplicable": 0
    }
   ],
   "total": 21,
   "open": 0,
   "notApplicable": 21,
   "bySeverity": {
    "High": 9,
    "Medium": 9,
    "Critical": 2,
    "Low": 1
   }
  }
 ]
};
