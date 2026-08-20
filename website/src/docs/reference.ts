import type { DocPage } from "./types";

/**
 * "Reference" — the compliance posture and the SDK overview.
 *
 * The compliance page is the one place where the hedges are load-bearing: every
 * claim here is a self-assessment backed by a test-evidence matrix in the
 * repository, not a certification. Removing a hedge would make the page the
 * least trustworthy thing on the site.
 */
export const REFERENCE_PAGES: DocPage[] = [
  {
    slug: "compliance",
    section: "Reference",
    navLabel: "Standards & compliance",
    title: "Standards & compliance",
    intro:
      "Which specifications AXIAM implements, how conformance is evidenced, and — just as importantly — what the evidence is not.",
    blocks: [
      { type: "h", id: "honesty", text: "What these claims mean" },
      {
        type: "warn",
        text: "Everything on this page is a **self-assessment backed by test evidence**, not a third-party certification. Each conformance matrix in the repository maps a normative MUST to the test that exercises it, so a claim can be checked rather than believed. That is stronger than a marketing bullet and weaker than an audit — treat it accordingly.",
      },
      { type: "h", id: "protocols", text: "Protocol conformance" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Specification", "Coverage", "Evidence"],
        rows: [
          [
            "RFC 6749 — OAuth 2.0",
            "Authorization code, client credentials and refresh grants, with the error semantics.",
            "`docs/compliance/oauth2-rfc-compliance.md` — a MUST-by-MUST matrix naming the test for each row.",
          ],
          ["RFC 7636 — PKCE", "S256 challenge on the authorization code grant.", "Same matrix."],
          ["RFC 7009 — Token revocation", "`/oauth2/revoke`.", "Same matrix."],
          ["RFC 7662 — Token introspection", "`/oauth2/introspect`.", "Same matrix."],
          ["RFC 8628 — Device authorization grant", "The full non-interactive path.", "`docs/api/device-flow.md`."],
          ["RFC 8693 — Token exchange", "Delegation and impersonation, narrowing-only.", "`docs/api/token-exchange.md`."],
          ["RFC 9126 — Pushed authorization requests", "`/oauth2/par`, requirable per client.", "OAuth2 test suite."],
          [
            "OpenID Connect Core 1.0 & Discovery 1.0",
            "ID tokens, userinfo, discovery. `alg: none` is excluded from the discovery document and rejected at verification.",
            "`docs/compliance/oidc-conformance.md`.",
          ],
          [
            "OIDC RP-Initiated & Back-Channel Logout 1.0",
            "Session-scoped logout in both directions.",
            "`docs/api/logout.md`.",
          ],
          ["UMA 2.0", "Protection API and the ticket grant.", "`docs/api/uma.md`, CONTRACT §20."],
          [
            "FAPI 2.0 Security Profile (Final)",
            "An opt-in constraint bundle that a client cannot half-apply.",
            "`docs/admin/fapi2-profile.md`.",
          ],
          [
            "SCIM 2.0 — RFC 7643 / 7644",
            "Users and Groups CRUD plus PATCH; bulk and complex filters deliberately unsupported.",
            "`docs/api/scim-provisioning.md`.",
          ],
          ["WebAuthn / FIDO2", "Registration and authentication, with MDS3-backed attestation policy.", "`docs/admin/authenticator-policies.md`."],
          [
            "RFC 9807 — OPAQUE",
            "One audited implementation bound by every SDK, tested against shared vectors.",
            "`sdks/opaque-test-vectors.json`, CONTRACT §23.",
          ],
        ],
      },
      { type: "h", id: "security", text: "Security standards" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Standard", "Posture"],
        rows: [
          [
            "OWASP ASVS 4.0.3 Level 2",
            "Control-by-control checklist over V2, V3, V4, V6, V7, V8, V9, V10 and V14. Every in-scope control carries an explicit status — Pass, N/A or Deferred — with the deferrals tracked by finding id rather than left blank.",
          ],
          [
            "GDPR",
            "Data export (Art. 15) and erasure (Art. 17) endpoints, with audit-actor pseudonymisation so an append-only trail can coexist with a right to erasure. Exports can be PGP-encrypted.",
          ],
          [
            "ISO 27001",
            "Targeted through access control, cryptography and audit logging — the technical controls, not the management system, which is an organizational matter AXIAM cannot supply.",
          ],
          [
            "EU Cyber Resilience Act",
            "Secure-by-default posture and a private vulnerability-disclosure process.",
          ],
        ],
      },
      { type: "h", id: "crypto", text: "Cryptography at a glance" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Use", "Algorithm"],
        rows: [
          ["Password hashing", "Argon2id, OWASP-recommended parameters, with a server-side pepper"],
          ["Password-authenticated key exchange", "OPAQUE (RFC 9807), ristretto255-SHA512, Argon2id or scrypt as the client KSF"],
          ["Token signing", "EdDSA (Ed25519)"],
          ["Secrets at rest", "AES-256-GCM — MFA secrets, CA keys, federation secrets, OPRF seeds, email"],
          ["Webhook signatures", "HMAC-SHA256"],
          ["Audit signing & exports", "OpenPGP"],
          ["Certificates", "X.509 with RSA-4096 or Ed25519"],
          ["Transport", "TLS 1.3 minimum; the native listener is TLS 1.3-only by policy"],
        ],
      },
      { type: "h", id: "supply", text: "Supply chain & CI" },
      {
        type: "list",
        items: [
          "The OpenAPI document is **drift-gated** — a PR fails if the committed spec diverges from a fresh export from the server.",
          "The protobuf contract is guarded by `buf lint` and `buf breaking` on every change.",
          "Crate-layering invariants are enforced in CI: dependencies point inward, and adding a crate without placing it in the layering table is itself a failure.",
          "Remediation records are verified to resolve to commits reachable from the default branch — a claimed fix on an unmerged branch does not count as shipped.",
          "Every SDK is tested against the same cross-language behavioural contract and the same OPAQUE test vectors.",
        ],
      },
      {
        type: "cards",
        cards: [
          {
            title: "The security model →",
            body: "Threat model, trust boundaries and shared responsibility.",
            to: "security",
          },
          {
            title: "Production hardening →",
            body: "What compliance leaves to you, as a checklist.",
            to: "docs",
            doc: "hardening",
          },
        ],
      },
    ],
  },

  {
    slug: "sdks",
    section: "Reference",
    navLabel: "Client SDKs",
    title: "Client SDKs",
    intro:
      "Eleven official client libraries, all conforming to one cross-language behavioral contract — so an integration ported between languages keeps the same semantics.",
    blocks: [
      { type: "h", id: "contract", text: "One contract, many languages" },
      {
        type: "p",
        text: "AXIAM ships SDKs for Rust, TypeScript, Python, Java, C#, PHP, Go, Kotlin, Swift, C and C++. Each lives in its own repository, and each vendors the same `CONTRACT.md`, OpenAPI document and protobuf definitions — so behaviour is identical whichever language you pick, and a difference between two SDKs is a bug in one of them rather than a matter of taste.",
      },
      {
        type: "p",
        text: "The contract is not a style guide. It specifies the error taxonomy, CSRF behaviour, the cookie-jar requirement, tenant and organization context, TLS policy, the redacting secret type, the AMQP HMAC construction, the single-flight refresh guard, route-guard interfaces, declarative authorization helpers, OIDC relying-party helpers, webhook verification, the device grant, token exchange, retry policy, deterministic shutdown, telemetry hooks, UMA, FAPI 2.0, Reactors and OPAQUE.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Tier", "Languages", "Coverage"],
        rows: [
          [
            "Full contract",
            "Rust, TypeScript, Python, Java, C#, PHP, Go",
            "The complete §1–§11 surface including the gRPC and AMQP transports.",
          ],
          [
            "REST surface",
            "Kotlin, Swift, C, C++",
            "§1–§7 and §9–§11, including §6.1 mTLS. gRPC and AMQP are planned follow-ups.",
          ],
        ],
      },
      { type: "h", id: "guarantees", text: "What every SDK guarantees" },
      {
        type: "list",
        items: [
          "**Tenant is an explicit constructor parameter.** There is no default tenant and no ambient context to get wrong.",
          "**Secrets are wrapped in a redacting type** that cannot be printed, logged or serialised by accident.",
          "**Browser code never touches a token.** Tokens live in `httpOnly` cookies; the SDK forwards the CSRF token for you.",
          "**Concurrent 401s collapse into one refresh**, not N — the single-flight guard is normative, not an optimisation.",
          "**TLS is strict by default**, with mTLS supported everywhere including the REST-tier SDKs.",
          "**One OPAQUE implementation** is bound by all of them — compiled in, through WebAssembly, or behind a C ABI. No SDK implements OPAQUE itself.",
          "**Declarative route guards** in the idiom of the language — attribute, annotation, decorator, macro or middleware.",
        ],
      },
      { type: "h", id: "pick", text: "Pick your language" },
      {
        type: "cards",
        cards: [
          {
            title: "All SDKs →",
            body: "Install snippets, quickstarts and guard examples for every language.",
            to: "sdks",
          },
          {
            title: "Error reference →",
            body: "The three error types and the status mapping every SDK implements.",
            to: "docs",
            doc: "errors",
          },
        ],
      },
    ],
  },
];
