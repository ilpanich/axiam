import type { DocBlock } from "./docs";
import { THREAT_MODEL_SUMMARY } from "./threatModelSummary";

/**
 * Content model for the Security section.
 *
 * The prose is the public-facing security write-up maintained at
 * `claude_dev/threat-modeling-and-security.md`; every claim in it is backed by
 * verified code, so this module transcribes it rather than paraphrasing. Three
 * things are deliberately preserved from the source and must survive any edit:
 *
 * - the hedges ("in AXIAM's own request path", "self-assessment, not a certified
 *   audit", the alpha caution) — they are load-bearing and scoped on purpose;
 * - the absence of extra claims — a plausible additional bullet would be the one
 *   line on the page that nothing verifies;
 * - the shared-responsibility section — it is what makes the rest credible, and
 *   it doubles as a deployment hardening checklist.
 *
 * The threat counts are not written out by hand: they are interpolated from
 * `threatModelSummary.ts`, which is generated from the Threat Dragon model, so
 * the page cannot drift from the model it describes.
 */

const GH = "https://github.com/ilpanich/axiam";
const GH_BLOB = `${GH}/blob/main`;

/** The security advisory form GitHub exposes for private vulnerability reports. */
export const SECURITY_ADVISORY_URL = `${GH}/security/advisories/new`;
export const SECURITY_POLICY_URL = `${GH_BLOB}/SECURITY.md`;

export interface SecSection {
  id: string;
  /** Sidebar entry. */
  navLabel: string;
  /** Sidebar grouping. */
  group: string;
  title: string;
  blocks: DocBlock[];
  /**
   * Renders the interactive Threat Dragon browser after this section's blocks.
   */
  explorer?: boolean;
}

const { total, open, mitigated, diagramCount, areas } = THREAT_MODEL_SUMMARY;

export const SEC_SECTIONS: SecSection[] = [
  /* ---- Overview --------------------------------------------------------- */
  {
    id: "glance",
    navLabel: "At a glance",
    group: "Overview",
    title: "Security at a glance",
    blocks: [
      {
        type: "p",
        text: "AXIAM is an identity and access-management platform, so it is itself a piece of security infrastructure: a weakness here is a weakness in every application that trusts it. The project treats that seriously. Security is not a feature bolted on at the end — it is designed in, verified continuously, and documented honestly, including the risks AXIAM cannot close on its own.",
      },
      { type: "p", text: "Three principles run through the whole system:" },
      {
        type: "list",
        items: [
          "**Secure by default.** The safe configuration is the one you get out of the box. Authorization is default-deny, TLS 1.3 is the floor for external traffic, tokens live in `HttpOnly` cookies, secrets are encrypted at rest, and a missing encryption key fails startup rather than silently substituting a weak one.",
          "**Defense in depth.** No single control is load-bearing. Tenant isolation is enforced at the handler, the query and the graph-traversal layers; a stolen token is short-lived, signature-pinned and revocable; a forged message must pass transport, signature and freshness checks before it is acted on.",
          "**Honest about the boundary.** A threat AXIAM cannot close from inside the application — backup encryption, cluster RBAC, per-service broker credentials — is written down as an open item with guidance, not quietly assumed away.",
        ],
      },
      {
        type: "p",
        text: `The system is verified against a **STRIDE threat model of ${total} threats** and a compliance self-assessment covering **OWASP ASVS Level 2, ISO/IEC 27001:2022, the EU Cyber Resilience Act and GDPR**, with its OAuth2/OIDC surface checked against the relevant RFC and OpenID conformance matrices.`,
      },
    ],
  },

  {
    id: "model",
    navLabel: "The threat model",
    group: "Overview",
    title: "The threat model",
    blocks: [
      {
        type: "p",
        text: "AXIAM maintains a formal threat model in **OWASP Threat Dragon** format, built with the **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege). It is a design-level model: it reasons about the system's data flows and trust boundaries, and records the specific control that answers each threat — or marks the threat open and says why.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["", ""],
        rows: [
          ["Methodology", "STRIDE, per-element"],
          ["Tool", `OWASP Threat Dragon (model schema v${THREAT_MODEL_SUMMARY.version.split(".")[0]})`],
          ["Diagrams", String(diagramCount)],
          ["Threats identified", String(total)],
          ["Mitigated / Open", `${mitigated} / ${open}`],
        ],
      },
      {
        type: "p",
        text: "Every threat is examined against the STRIDE categories that apply to its element type (actor, process, data store or data flow). A threat is marked **mitigated** only where a control exists in the codebase and can be pointed at; where the residual risk is accepted, deferred, or belongs to whoever deploys AXIAM, it stays **open** and explains itself. An honest open item is more useful than an optimistic closed one.",
      },
      { type: "h", id: "coverage", text: "Coverage by area" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Area", "Threats", "Open"],
        rows: areas.map((a) => [a.title, String(a.total), String(a.open)]),
      },
      {
        type: "p",
        text: "The concentration of open items in *Deployment* and *Client SDKs* is deliberate and expected: those are the two areas where security is a shared responsibility between AXIAM and the people who run and integrate it. AXIAM's own request path — authentication, authorization, tokens, PKI, federation — carries **no open Critical or High finding**.",
      },
    ],
  },

  {
    id: "diagrams",
    navLabel: "Diagrams & threats",
    group: "Overview",
    title: "Diagrams & threats",
    explorer: true,
    blocks: [
      {
        type: "p",
        text: `All ${diagramCount} data-flow diagrams below are rendered directly from the Threat Dragon model kept in the repository — the same JSON the maintainers edit. Pick a diagram, then click any element or flow to read the threats recorded against it, each with its STRIDE category, severity, status and the control that answers it (or, for an open item, the residual risk and who owns it).`,
      },
    ],
  },

  {
    id: "boundaries",
    navLabel: "Trust boundaries",
    group: "Overview",
    title: "Trust boundaries",
    blocks: [
      {
        type: "p",
        text: "Five trust boundaries recur across the system. A data flow that crosses one is a place where authentication, authorization, validation and transport protection all have to be re-established — nothing is assumed across a boundary.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Boundary", "Separates", "What must hold on every crossing"],
        rows: [
          [
            "Public Internet ↔ AXIAM",
            "Browsers, SDK callers, IoT devices, external IdPs",
            "TLS 1.3, authentication, rate limiting, CSRF on cookie requests, input validation",
          ],
          [
            "AXIAM ↔ data tier",
            "Application pods ↔ SurrealDB, RabbitMQ, Vault / Secrets",
            "Private network, credentialed connections, TLS-only AMQP, parameterised queries, tenant scoping at the repository layer",
          ],
          [
            "Tenant ↔ tenant",
            "Every tenant's data from every other's",
            "Tenant context derived from the verified session or JWT — never from request input — and enforced on every query and graph traversal",
          ],
          [
            "AXIAM ↔ third parties",
            "Outbound to IdPs, email providers, webhook receivers",
            "SSRF guard with resolve-and-pin, HTTPS enforcement, response-size caps, HMAC signatures on deliveries",
          ],
          [
            "Server ↔ SDK / admin UI",
            "The server contract from its client implementations",
            "One cross-language contract — TLS policy, secret redaction, CSRF, AMQP HMAC — enforced by CI drift and protobuf gates",
          ],
        ],
      },
      { type: "h", id: "assets", text: "The assets worth protecting" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Asset", "Protection", "Compromise would mean"],
        rows: [
          [
            "JWT signing key (Ed25519)",
            "Secret provider — Vault in production — never in the image",
            "Any identity in any tenant forged",
          ],
          [
            "Organization CA private key",
            "AES-256-GCM encrypted at rest",
            "Any user/service/device certificate minted",
          ],
          [
            "Password hashes",
            "Argon2id, per-user salt, pepper",
            "Offline cracking of credentials",
          ],
          [
            "OPAQUE setup key & per-tenant OPRF seeds",
            "Secret provider; seeds AES-256-GCM encrypted at rest",
            "Stolen OPAQUE records become dictionary-attackable",
          ],
          ["MFA secrets", "AES-256-GCM encrypted at rest", "Second factor defeated"],
          [
            "Refresh tokens & sessions",
            "Stored hashed, single-use rotation",
            "Sustained impersonation",
          ],
          [
            "Client & webhook secrets",
            "Hashed / encrypted, redacted from logs",
            "Service-account impersonation; forged events",
          ],
          [
            "Authorization graph",
            "Private data tier, API-only mutation, audited",
            "Silent privilege escalation",
          ],
          ["Audit log", "Append-only, OpenPGP-signed", "Loss of accountability"],
        ],
      },
    ],
  },

  /* ---- How AXIAM defends each layer ------------------------------------- */
  {
    id: "auth",
    navLabel: "Authentication & sessions",
    group: "How AXIAM defends each layer",
    title: "Authentication & sessions",
    blocks: [
      {
        type: "list",
        items: [
          "**Passwords** are hashed with **Argon2id** at OWASP-recommended parameters (~19 MiB memory cost, per-user salt, server-side pepper). Plaintext passwords are never stored or logged.",
          "**Login is enumeration-safe and brute-force-resistant**: unknown-user and bad-password return the same uniform failure, password verification runs on a dummy hash when the user does not exist so timing does not distinguish the two, and failed attempts drive an atomic, exponential-backoff lockout that is shared by every credential-checking path (REST and gRPC alike).",
          "**Rate limits are sized by what an operation costs, not by one global number.** A password verification is thousands of times more expensive than a permission check, so it gets its own much tighter ceiling — and that ceiling is deliberately *not* derived from the throughput knobs, so tuning a cluster for authorization volume cannot widen credential guessing as a side effect. The internet-facing human endpoints (login, registration, password reset, MFA) keep strict per-IP limits under every deployment profile, enforced structurally: the tuning presets are prevented from touching them at all. Every request path is bounded, including infrastructure endpoints like health and reflection — there is no unmetered route.",
          "**MFA** is built in — TOTP today, WebAuthn/passkeys for phishing-resistant, origin-bound second factors. TOTP codes are single-use within their window (replay is rejected with an atomic compare-and-set), and the MFA challenge is a distinct, single-use, no-authority token so the second factor can never be skipped by replaying it. Passkeys also work as a **usernameless, one-step sign-in** (discoverable credentials), and that path re-establishes every gate the password step would have run: account status and lockout are checked, the operator's login-veto hook still fires, and the anonymous start endpoint touches no storage — so it cannot be used to probe which workspaces or accounts exist.",
          "**Tokens**: access tokens are **EdDSA (Ed25519) JWTs**, 15 minutes long. The verifier pins the algorithm and never reads it from the token header, so `alg:none` and HMAC-key-confusion attacks are rejected outright. Refresh tokens are opaque, server-stored and **single-use with rotation**, consumed through an atomic delete-gate so a race cannot fork the session or hide a stolen-token reuse. In the browser, tokens live only in `Secure` / `HttpOnly` / `SameSite=Strict` cookies — never in `localStorage`, never in a URL.",
          "**Password reset** uses CSPRNG-generated, single-use, short-lived tokens (never time-ordered UUIDs), delivered over an authenticated POST, and consuming a reset invalidates every existing session. An optional **Have I Been Pwned** k-anonymity check (only a five-character hash prefix leaves the server, behind a circuit breaker) blocks known-breached passwords.",
          "**OPAQUE (RFC 9807) is available as an augmented PAKE** — off by default, enabled per organization or tenant, with a tenant able to tighten but never relax the organization baseline. With it enabled, the plaintext password never reaches the server at all: not a TLS-terminating proxy, not a request-body log, not a heap dump. Stolen OPAQUE records are not offline-attackable at KDF cost the way a hash corpus is — recovering a password additionally requires the tenant's OPRF seed, which is AES-256-GCM encrypted at rest under a key held in the secret provider. Unknown identities receive a stable, well-formed decoy response so the flow is enumeration-safe, and a failed exchange accrues toward the same lockout as a failed password. One audited implementation (`axiam-opaque`, with C-ABI and WebAssembly builds) serves all eleven SDKs and the admin UI, instead of eleven hand-written PAKEs.",
          "**SCIM provisioning uses purpose-bound long-lived tokens.** Okta and Entra can only present one static bearer string, so AXIAM mints one that is accepted on `/scim/v2/*` and nowhere else, carries no permissions of its own (the resolved tenant user's RBAC still decides), is stored hashed with the plaintext returned exactly once, and is expiring, revocable and audited. Deprovisioning a user through SCIM also revokes their live sessions and refresh tokens.",
        ],
      },
    ],
  },

  {
    id: "authz",
    navLabel: "Authorization & tenant isolation",
    group: "How AXIAM defends each layer",
    title: "Authorization & tenant isolation",
    blocks: [
      {
        type: "p",
        text: "Tenant isolation is the core guarantee of a multi-tenant IAM, so it is enforced redundantly rather than at one chokepoint:",
      },
      {
        type: "list",
        items: [
          "**Tenant context comes from the verified session or JWT, never from request input.** A caller cannot name a tenant it does not belong to. The organization claim in a token is derived server-side from the tenant record on both login and refresh — it is never accepted from the client.",
          "**Repository queries are tenant-scoped and parameterised.** Every SurrealQL statement uses bind parameters — no query is assembled by string concatenation of user input — and carries a `tenant_id` predicate. Cross-tenant graph edges are stripped during permission resolution rather than followed. The isolation is enforced twice over: an edge that would cross tenants cannot be *written* in the first place, and every traversal that reads one — including group membership, the indirect path by which roles are inherited — re-checks the tenant at read time rather than trusting the write-time guard.",
          "**The authorization engine is RBAC, default-deny, with explicit deny-override.** A route with no declared permission is refused, not allowed. Roles cascade down a resource hierarchy with bounded, cycle-safe traversal, and a grant carries `effect: \"allow\" | \"deny\"` — an explicit deny overrides every allow, at any depth of the hierarchy and at equal specificity, so adding a deny rule can never widen access and can never be undone by adding allows (asserted by an exhaustive property test).",
          "**The performance caches are off by default and never change an answer.** AXIAM offers two optional caches — one for authorization decisions, one for session validation. Both ship disabled, both are keyed per tenant, and both are invalidated by the mutations that could change their answer, so revoking a role or a session takes effect immediately on the replica that handled it. Enabling one is an explicit, logged decision that trades a few seconds of worst-case staleness for throughput — never correctness.",
          "**Revocation propagates across replicas, and a cache that cannot hear it switches itself off.** The decision cache can broadcast invalidations to every replica over the message broker. Those messages are signed with the same per-tenant authenticated envelope as the rest of AXIAM's messaging — nonce, timestamp and constant-time verification — so a party with broker access but no signing key cannot forge one, and a forged message could in any case only *drop* cache entries, never grant access. The design fails safe in both directions: a replica starts out not trusting its cache and only begins using it once it is successfully subscribed, and if a privilege-narrowing change cannot be broadcast, the change itself fails rather than leaving other replicas stale.",
          "**Three protocols, one engine.** REST middleware, gRPC `CheckAccess` and the async AMQP path all evaluate the same policy. The gRPC interceptor authenticates the caller and derives the tenant from its verified identity, so a service account cannot ask about a subject outside its own tenant.",
        ],
      },
    ],
  },

  {
    id: "oauth2",
    navLabel: "OAuth2 & OpenID Connect",
    group: "How AXIAM defends each layer",
    title: "OAuth2 & OpenID Connect",
    blocks: [
      {
        type: "p",
        text: "AXIAM is a full OAuth2 authorization server and OIDC provider, checked against the RFC 6749 / 7636 / 7009 / 7662 MUST matrices and OIDC Core/Discovery conformance:",
      },
      {
        type: "list",
        items: [
          "**Authorization Code with PKCE (S256 only)** — the `plain` method is rejected; public clients prove possession with the verifier rather than a secret. The implicit grant is not offered.",
          "**Redirect URIs are matched exactly** — no wildcards, no prefix matching, no normalisation of the `redirect_uri` that could widen the match, closing the open-redirect class.",
          "**Single-use authorization codes** bound to client and redirect URI; **refresh rotation** that can only narrow scope, never widen it; `state` and `nonce` required and verified.",
          "**Introspection and revocation require client authentication** and are scoped to the caller's own tenant; unknown tokens return the uniform inactive response.",
          "**userinfo is scope-filtered**; JWKS publishes the active key plus a bounded rotation-overlap window.",
          "**Clients can authenticate without a copyable secret, and tokens can be bound to their holder.** Mutual-TLS client authentication (RFC 8705) and `private_key_jwt` assertions (with a single-use `jti` and a hard lifetime cap) replace the shared `client_secret`; certificate-bound and DPoP (RFC 9449) access tokens make a leaked token useless without the private key that presented it — and a token obtained through token exchange inherits the sender-constraint the exchanging client proved, so the exchange path cannot be used to launder a bound token into a bearer one. Every authorization response carries the RFC 9207 `iss` parameter, closing the authorization-server mix-up class. Assertion and proof verification derives the algorithm from the key material, never from the token header.",
          "**Machine tokens and user tokens are not interchangeable.** Every machine credential — a service account's client secret, or an IoT device's client certificate — yields a token with a machine audience, while a human login yields a user audience; each is rejected where the other is expected, in both directions. Without that split, one device certificate would silently unlock every endpoint built for people. It is enforced at the request-extraction layer rather than left to individual handlers, so a new route inherits it by default, and the endpoints machines legitimately need — authorization checks — accept either principal while still recording which kind it was, so a device is never written into the audit trail as a person.",
        ],
      },
    ],
  },

  {
    id: "federation",
    navLabel: "Federation (SAML & OIDC)",
    group: "How AXIAM defends each layer",
    title: "Federation (SAML & OIDC)",
    blocks: [
      {
        type: "p",
        text: "Inbound federation is a deliberate delegation of trust to an external IdP, hardened against the classic federation attacks:",
      },
      {
        type: "list",
        items: [
          "**SAML** verifies the signature over the *exact* element it then consumes (XML Signature Wrapping defence), rejects unsigned or multiply-signed responses, checks `Conditions`, `NotBefore`/`NotOnOrAfter`, `Audience`, `Destination` and `InResponseTo`, and refuses replayed assertion IDs.",
          "**OIDC federation** requires `state` and `nonce` from server-side flow state (never from the request body), binds the federation-config id into `state` to stop IdP mix-up, and validates the issuer.",
          "**Every outbound IdP fetch** — discovery, token exchange, JWKS, SAML metadata — goes through one **SSRF guard** that resolves DNS fresh, rejects private, loopback, link-local and ULA addresses, **pins the validated IP for the actual connection** (closing the DNS-rebind window), enforces HTTPS on every hop including redirects, and caps the response body.",
          "**Attribute-to-role mapping is an explicit, tenant-scoped allow-list** set by an AXIAM administrator; unmapped IdP attributes are discarded, so an IdP cannot self-assign privileged roles.",
        ],
      },
    ],
  },

  {
    id: "pki",
    navLabel: "PKI & device identity",
    group: "How AXIAM defends each layer",
    title: "PKI, certificates & device identity",
    blocks: [
      {
        type: "list",
        items: [
          "Certificates are **per-tenant, signed by the organization CA**, using RSA-4096 or Ed25519 from the platform CSPRNG. **Private keys are never stored server-side** — they are returned exactly once at issuance and delivered only over TLS 1.3.",
          "**CA signing keys are AES-256-GCM encrypted at rest** in a separate, access-controlled table, with the key held outside the datastore.",
          "**mTLS device authentication verifies the full chain** to the tenant/org CA after the fingerprint lookup, checks the issuing CA is active and within its validity window, and enforces the certificate's own validity period and live revocation status on every connection — a fingerprint match alone is never enough.",
          "**OpenPGP keys** sign the audit trail and encrypt GDPR data exports, so both are independently verifiable and confidential.",
          "**WebAuthn attestation policy (X3)** verifies the FIDO Alliance's MDS3 metadata BLOB against a **digest-pinned vendored trust anchor** — chaining to the public GlobalSign root alone would only prove \"some GlobalSign EV customer\", so the leaf's SAN DNS identity and the CA/`basicConstraints` status of every issuer in the chain are checked too. Ingestion rejects a rollback to an older BLOB serial and never hard-fails on a stale one (logged, not blocking) — but an operator can now bound how stale is acceptable: past `AXIAM__PKI__MDS_MAX_STALE_DAYS` beyond the BLOB's own `nextUpdate`, attested registration is refused rather than decided on metadata too old to trust (off by default, because the right bound is a property of the deployment). This is opt-in (`AXIAM__PKI__MDS_ENABLED=false` by default, zero outbound calls) and enforced only at registration — existing credentials are never auto-revoked on a policy change.",
        ],
      },
    ],
  },

  {
    id: "audit",
    navLabel: "Audit & accountability",
    group: "How AXIAM defends each layer",
    title: "Audit & accountability",
    blocks: [
      {
        type: "list",
        items: [
          "The audit log is **append-only** — no UPDATE or DELETE paths — and batches are **OpenPGP-signed**, making tampering or selective deletion detectable rather than merely difficult.",
          "Every state-changing and authorization action is recorded with actor, actor type, IP, outcome and timestamp; **both allow and deny decisions** are captured, so probing shows up in the trail. Records are structured fields, not formatted strings, so log-injection cannot forge a synthetic entry.",
          "**Retention is bounded by default**: a background sweep prunes audit records older than 730 days through the table's only deletion path — deployment-wide, never reachable from any HTTP handler, so \"prune old records\" cannot become \"delete the evidence\". Set the window to match your lawful basis, or `0` to disable; either state is logged at startup.",
        ],
      },
    ],
  },

  {
    id: "messaging",
    navLabel: "Webhooks, email & messaging",
    group: "How AXIAM defends each layer",
    title: "Webhooks, email & messaging",
    blocks: [
      {
        type: "list",
        items: [
          "**Webhook deliveries are signed with a Stripe-style signed-timestamp HMAC** — HMAC-SHA256 over `<timestamp>.<body>`, so a stale or body-only forgery cannot be produced — and use the same resolve-and-pin SSRF guard as federation, so a webhook URL cannot be used to scan internal services.",
          "**AMQP messages** (async authz, audit ingestion, mail) carry an **HMAC-SHA256 signature over the canonical body with a per-tenant HKDF-derived subkey**, verified in constant time before processing; a bad signature is rejected without requeue. The v2 message format binds a **per-message nonce and timestamp** so a captured, validly-signed message cannot be replayed. Signing is mandatory in production builds — and the **broker connection is TLS-only**: `amqps://` is the only accepted scheme, refused before a socket is opened in every build profile, with no plaintext escape hatch left in the configuration surface.",
          "**Email** is built through a typed API that rejects header injection, renders templates with user values as escaped data (never as template source), and encrypts provider credentials at rest.",
        ],
      },
    ],
  },

  {
    id: "transport",
    navLabel: "Transport, secrets & SDKs",
    group: "How AXIAM defends each layer",
    title: "Transport, secrets & the SDKs",
    blocks: [
      {
        type: "list",
        items: [
          "**TLS 1.3 is the minimum** for all external communication; HSTS is emitted; the optional in-process TLS listener is TLS 1.3-only and fails fast rather than falling back to plaintext.",
          "**Secrets at rest** — MFA seeds, CA keys, OPAQUE OPRF seeds, federation and webhook and email secrets — are AES-256-GCM encrypted; passwords are Argon2id-hashed and client secrets are hashed under a **server-held key**, so a database disclosure alone does not yield an offline-crackable corpus. Secret-bearing types carry redacting `Debug`/`toString` implementations so a credential never reaches a log line. A **missing encryption key or pepper fails startup**; no code path substitutes an all-zero, constant or unkeyed fallback.",
          "**Long-lived secrets come from a pluggable secret provider — HashiCorp Vault by default in production.** All ten of them — the JWT signing key, the OPAQUE setup and session keys, the PKI, MFA, federation and email encryption keys, the password and pseudonym peppers, and the AMQP signing key — are fetched from Vault rather than the container spec, so none needs to exist as an environment variable or Kubernetes manifest at all. The seeder mints what is missing from a CSPRNG and **never regenerates a secret that already exists** (regenerating the OPAQUE setup key would mean a password reset for every user; regenerating the pepper would invalidate every stored hash), and the status tooling reports presence only, never values.",
          "**The eleven client SDKs conform to one cross-language contract.** Strict TLS verification is unconditional and TLS-bypass APIs are prohibited (CI greps for them); a plaintext `http://` base URL is refused at construction, with a loopback-only development exception matched on literal hostnames rather than resolved DNS; secrets are wrapped in redacting types; the browser flow keeps tokens in cookies with single-flight refresh; JWKS relying-party helpers pin the key set to the configured issuer's origin. The server is the single source of truth: a CI drift gate fails the build if an SDK's vendored OpenAPI/protobuf copy diverges.",
          "**Local token verification in the SDK route guards is strict by default, and the standard is written down.** A guard that only checked a signature would accept an expired token, and — because the JWKS is organization-wide — one minted for a different tenant. The SDK contract therefore defines a **normative minimum verification set** that every guard must enforce: algorithm pinned before key lookup, expiry required (not merely checked when present), not-before honoured, tenant asserted against the configured tenant and failing closed when there is nothing to compare against, issuer and audience checked when configured, and a named, bounded clock skew. Stating it once rather than leaving each language to infer it is deliberate — auditing eleven implementations against the written set found real gaps that per-SDK review had missed. Where a raw signature-only primitive still exists it is named to make accidental use hard.",
          "**A guard decides on the caller's credential and no other.** The rules above ask *\"is this token good?\"*; one more asks *\"is this the token the decision is about?\"* — because a guard can satisfy every claim rule and still be a bypass if a failed verification quietly routes into a second, successful one. So a guard must reject when the presented credential fails: never retry, never refresh, and never fall back to the application's own session, which would admit the caller under a service account's identity. Where an SDK offers a refresh-on-failure helper for its own outbound calls, that helper is a separate method that guards do not use.",
          "**Every SDK ships a webhook-signature verifier** (contract §13). Receivers no longer hand-roll the check: `verify_webhook(...)` implements one canonical spec across all eleven languages — HMAC-SHA256 over `<timestamp>.<raw_body>`, constant-time comparison on decoded signature bytes, a signature header with no `v1` value always failing rather than silently passing, multiple `v1` values accepted so secrets can be rotated without downtime, and a two-sided freshness window (default 300 seconds) that rejects future-dated timestamps as firmly as stale ones.",
        ],
      },
    ],
  },

  /* ---- Posture & practice ------------------------------------------------ */
  {
    id: "compliance",
    navLabel: "Compliance posture",
    group: "Posture & practice",
    title: "Compliance posture",
    blocks: [
      {
        type: "p",
        text: "AXIAM keeps an internal compliance self-assessment mapping its controls to recognised frameworks. This is a control-family self-assessment appropriate to a beta-stage product — **not** a certified ISO 27001 ISMS audit or a formal Cyber Resilience Act conformity assessment, and it says so plainly.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Framework", "Scope", "Status"],
        rows: [
          [
            "OWASP ASVS v4.0.3 Level 2",
            "103 controls across authentication, session, access control, cryptography, error handling, data protection, communications, malicious code, configuration",
            "94 Pass, 4 N/A, 5 Deferred — **no Deferred item is High or Critical**",
          ],
          [
            "ISO/IEC 27001:2022 Annex A",
            "Access control, secure authentication, cryptography, logging, network security, secure development",
            "Interpretive control-family mapping; code-level themes Pass",
          ],
          [
            "EU Cyber Resilience Act (Annex I)",
            "Secure-by-design, no known exploitable vulnerabilities, confidentiality, data minimisation, access control, vulnerability handling, security updates",
            "Themes Pass; SBOM deferred",
          ],
          [
            "GDPR",
            "Data-subject export (Art. 15) and erasure (Art. 17), pseudonymisation, data minimisation",
            "Export excludes secrets; erasure is durable and re-selectable on failure; audit actor identities are pseudonymised",
          ],
          [
            "OAuth2 / OIDC",
            "RFC 6749 / 7636 / 7009 / 7662 + OIDC Core/Discovery MUST matrices",
            "All tracked MUSTs pass; dedicated conformance suites",
          ],
        ],
      },
      {
        type: "p",
        text: "Dependency and supply-chain security is gated in CI — `cargo audit`, `cargo deny`, Trivy filesystem/config scans and `npm audit` at a high threshold, with Dependabot across the workspace's ecosystems and each SDK repository, SHA-pinned GitHub Actions, and signed release provenance.",
      },
    ],
  },

  {
    id: "responsibility",
    navLabel: "Shared responsibility",
    group: "Posture & practice",
    title: "Shared responsibility",
    blocks: [
      {
        type: "p",
        text: "Some risks cannot be closed from inside the application. AXIAM records them openly and tells you what to do about them. Treat the following as a deployment hardening checklist — most of the threat model's open items live here.",
      },
      { type: "h", id: "platform-ops", text: "Platform & operations" },
      {
        type: "list",
        items: [
          "Apply the shipped NetworkPolicies (`k8s/network-policy/` — a namespace-wide default-deny on ingress and egress, plus the minimum allows a working deployment needs) and replace their two deliberate placeholders: the cluster pod/service CIDRs in the HTTPS egress exception, and the SMTP relay range, which ships as an unroutable value so mail egress is denied until you configure it. Keep the data tier off any public route, and check with `kubectl kustomize k8s/` that every policy is actually applied — the SurrealDB and RabbitMQ ingress policies once existed as files but were missing from the kustomization, which enforces nothing.",
          "Give RabbitMQ **per-service credentials** — the manifests now ship a dedicated `axiam` vhost as AXIAM's own authorization boundary and carry the AMQP URL in a Secret rather than the ConfigMap, where it previously sat without credentials at all; AXIAM verifies message signatures and refuses any non-TLS broker URL, but splitting one credential per service is still yours.",
          "**Run Vault in production mode, and treat its posture as your secret posture.** The production stacks default to Vault for every long-lived secret, which concentrates all of them behind one KV path: give AXIAM a read-only token scoped to that path, keep unseal keys and the root token offline, enable Vault's audit device, and never run a dev-mode (in-memory, unsealed) Vault in production. For deployments without Vault, the manifests' `file` provider mounts every cryptographic secret as a file — prefer it over `AXIAM_*` environment variables, since a signing key in a ConfigMap or plain env var is effectively public within the namespace. The datastore and broker credentials are still env-supplied (read before any secret provider exists), so enable etcd encryption at rest either way.",
          "**Encrypt backups and volume snapshots** with a key separate from the cluster, restrict snapshot IAM, and include backup media in the same access review as the live data tier — a snapshot carries the same data under weaker controls.",
          "Restrict `kubectl exec` and Secret-read RBAC and enable Kubernetes audit logging; **cluster-admin is equivalent to full AXIAM compromise** and is outside the application's audit trail.",
          "Add edge protection (WAF, connection limits, autoscaling) for volumetric floods, and wire monitoring to `GET /health/jobs`, which reports every background sweep's last success, last failure and a computed `stalled` flag — alert on `status == \"degraded\"` so a silently stopped GDPR-erasure or certificate-expiry sweep is noticed, not only one that errors.",
          "**Run SurrealDB on a persistent storage engine** — `surrealkv:` or `rocksdb:`, never `memory:`. This is a correctness control, not a durability preference. AXIAM's three single-use credentials — UMA permission tickets, RFC 8628 device grants and RFC 9126 PAR `request_uri`s — are redeemed by a guarded `UPDATE` inside an explicit transaction, so a second concurrent redemption is a write-write conflict the engine must abort. Measured (`tools/surreal-race-probe`), `surrealkv` and `rocksdb` abort every one; the in-memory engine arbitrates at the same rate and then silently misses, admitting two winners in roughly 1% of contended rounds. A double redemption there yields two RPTs from one authorization decision, two token sets from one user approval, or a replayable authorization request ([ilpanich/axiam#302](https://github.com/ilpanich/axiam/issues/302)). The shipped compose files and k8s StatefulSet already pin `surrealkv:`; **the server cannot verify this for you** — SurrealDB exposes no datastore identity over the wire, so `axiam-server` logs a startup WARN that the engine could not be attested and the requirement lands here. A per-attempt redemption nonce, read back after the transaction commits, is the second layer that catches a missed conflict, so this is a defence-in-depth requirement rather than a single point of failure — but do not spend the second layer to save the first.",
        ],
      },
      { type: "h", id: "integration", text: "Integration & SDKs" },
      {
        type: "list",
        items: [
          "**Call the webhook verifier.** Every SDK now ships `verify_webhook(...)`, so the hard part is done — but a helper you never invoke protects nothing, and an unverified receiver acts on any POST that reaches its URL. Verify before you act on a delivery, and deduplicate on the delivery id. The same applies to AMQP: the contract requires HMAC verification on every consumed message.",
          "**Configure the tenant on any SDK route guard.** The guards bind each token to your configured tenant, which means they need to know it — a guard given no tenant to compare against fails closed and rejects every token, by design.",
          "Prefer **mTLS or short-lived workload identity** over static client secrets; rotate secrets through the rotation endpoint and enable secret scanning on your own repositories.",
          "Install SDKs under their **canonical package names**, commit lockfiles, and keep dependency scanning on — eleven public registries are eleven chances for a typosquat or a hijacked release.",
        ],
      },
      { type: "h", id: "tradeoffs", text: "Accepted, documented trade-offs" },
      {
        type: "list",
        items: [
          "**Access tokens survive revocation for up to 15 minutes** — the price of stateless verification. Where immediate revocation matters, verify through the gRPC introspection path instead of locally.",
          "**Audit records cannot be erased on demand, only aged out** — append-only by design, which is in tension with GDPR Art. 17; erasure anonymises the subject instead. Retention defaults to a 730-day pruning window applied by the background sweep; tune it (or disable with `0`) to match your lawful basis.",
        ],
      },
      {
        type: "warn",
        text: "**Caution — this is alpha software.** AXIAM is in active development and has not reached a stable release. It has not undergone an independent third-party penetration test or security certification. Do not use it to protect production systems until it reaches a stable, audited release. The controls described here are real and verified in the codebase, but a beta is a starting point for evaluation, not a guarantee.",
      },
    ],
  },

  {
    id: "maintained",
    navLabel: "How security is maintained",
    group: "Posture & practice",
    title: "How security is maintained",
    blocks: [
      {
        type: "list",
        items: [
          "**Continuous review.** AXIAM has been through repeated full security-review rounds — an initial audit, targeted remediation waves, and independent re-verification passes — each re-checking every prior finding against current code with file-and-line evidence, not trusting a checklist. Findings carry stable IDs so a fix can be traced back to the review that raised it.",
          "**A fix is not trusted until someone else checks it.** Remediation and verification are deliberately separated: after a round of fixes lands, an independent pass re-derives every claim from source. That discipline earns its keep — the most recent pass confirmed the fixes but also caught one that was only half complete, and found that a *performance* change had quietly raised a brute-force ceiling. Both are recorded as new findings rather than absorbed silently.",
          "**The threat model is living.** It is revisited when a new API surface, protocol or integration lands, when a trust boundary moves, when a review raises something with no corresponding threat, or when a deferred item ships. The Threat Dragon JSON is the source of truth and this section is generated from it.",
          "**Gates, not vibes.** Every commit runs formatting, lints (`-D warnings`), the test suite against real SurrealDB and RabbitMQ, dependency and container scans, and cross-language SDK contract-drift checks. Security-relevant fixes land with a regression or negative test.",
        ],
      },
    ],
  },

  {
    id: "report",
    navLabel: "Report a vulnerability",
    group: "Posture & practice",
    title: "Reporting a vulnerability",
    blocks: [
      {
        type: "p",
        text: "If you find a security issue, please report it privately to the maintainers rather than opening a public issue, and give us a reasonable window to remediate before disclosure.",
      },
      {
        type: "links",
        links: [
          {
            label: "Report a vulnerability privately",
            href: SECURITY_ADVISORY_URL,
            note: "GitHub private security advisory — visible only to you and the maintainers",
          },
          {
            label: "Security policy (SECURITY.md)",
            href: SECURITY_POLICY_URL,
            note: "what to include, what to expect, and the disclosure window",
          },
        ],
      },
      { type: "h", id: "references", text: "References" },
      {
        type: "links",
        links: [
          {
            label: "Threat Dragon model (JSON)",
            href: `${GH_BLOB}/ThreatDragonModels/Axiam/Axiam.json`,
            note: "the source of truth for this section",
          },
          {
            label: "STRIDE threat model",
            href: `${GH_BLOB}/claude_dev/threat-model-stride.md`,
          },
          {
            label: "Security analysis",
            href: `${GH_BLOB}/claude_dev/security-analysis-2026-08-02.md`,
            note: "code-level evidence, cited by file and line",
          },
          {
            label: "Compliance audit",
            href: `${GH_BLOB}/claude_dev/security-audit.md`,
          },
          { label: "SDK contract", href: `${GH_BLOB}/sdks/CONTRACT.md` },
          {
            label: "Compliance checklists",
            href: `${GH}/tree/main/docs/compliance`,
            note: "ASVS L2, GDPR, OAuth2 RFC and OIDC conformance matrices",
          },
          { label: "OWASP Threat Dragon", href: "https://www.threatdragon.com" },
        ],
      },
    ],
  },
];

export const SEC_GROUPS: { label: string; ids: string[] }[] = SEC_SECTIONS.reduce(
  (groups: { label: string; ids: string[] }[], section) => {
    const existing = groups.find((g) => g.label === section.group);
    if (existing) existing.ids.push(section.id);
    else groups.push({ label: section.group, ids: [section.id] });
    return groups;
  },
  [],
);
