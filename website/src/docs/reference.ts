import type { Sdk } from "../types";
import { SDKS } from "../data";
import { contractLink } from "../contractAnchors";
import type { DocCodeTab, DocPage } from "./types";
import { DOCS_VERIFIED_RELEASE } from "../version";

/**
 * Conformance, as each SDK's own README states it.
 *
 * Transcribed from the eleven `## Contract conformance` statements and scope
 * tables at `1.0.0-beta07` / contract 1.36, in `sdks/CONTRACT.md` section
 * order. It is a snapshot for orientation: each SDK's README is the source, and
 * the contract itself is what any of them is measured against.
 *
 * `"—"` means the SDK does not ship that section; anything else is shipped, with
 * the qualification the README gives it.
 */
const YES = "✓";
const NO = "—";

/**
 * Evidence links for the compliance page.
 *
 * The Security section links its claims to the file that backs them; this page
 * asserted the same claims with a bare path in prose, which a reader cannot
 * click and cannot check. Same base as `security.ts` uses, kept local because
 * `reference.ts` has no other reason to import it.
 */
const GH_BLOB = "https://github.com/ilpanich/axiam/blob/main";
const COMPLIANCE = `${GH_BLOB}/docs/compliance`;
const API_DOCS = `${GH_BLOB}/docs/api`;
const ADMIN_DOCS = `${GH_BLOB}/docs/admin`;

const CONFORMANCE: { id: string; cells: string[] }[] = [
  { id: "rust", cells: [YES, YES, YES, YES, YES, YES, YES, YES, YES, YES] },
  { id: "typescript", cells: [YES, YES, YES, YES, YES, YES, YES, YES, YES, YES] },
  { id: "python", cells: [YES, YES, YES, YES, YES, YES, YES, YES, YES, YES] },
  { id: "java", cells: [YES, YES, YES, YES, YES, YES, YES, YES, YES, YES] },
  { id: "csharp", cells: [YES, YES, YES, YES, YES, YES, YES, YES, YES, YES] },
  { id: "php", cells: [YES, YES, YES, YES, YES, YES, YES, YES, YES, YES] },
  { id: "go", cells: [YES, YES, YES, YES, YES, YES, YES, YES, YES, YES] },
  { id: "kotlin", cells: [YES, NO, "reactor exchange only", YES, YES, YES, YES, YES, YES, YES] },
  { id: "swift", cells: [YES, NO, NO, YES, YES, YES, "transport yours", YES, YES, YES] },
  { id: "c", cells: [YES, NO, NO, YES, YES, YES, "transport yours", YES, YES, YES] },
  { id: "cpp", cells: [YES, NO, NO, YES, YES, YES, "transport yours", YES, YES, YES] },
];

const byId = (id: string): Sdk | undefined => SDKS.find((s) => s.id === id);

/**
 * The languages the samples below are shown in, in that order.
 *
 * Rust leads because the server, the OPAQUE core and the reference SDK are all
 * Rust — a reader comparing an SDK against the thing it talks to reads it first.
 */
const SAMPLE_IDS = ["rust", "typescript", "python", "go", "java"];
const SAMPLES: Sdk[] = SAMPLE_IDS.map(byId).filter((s): s is Sdk => Boolean(s));

const tabs = (pick: (sdk: Sdk) => string): DocCodeTab[] =>
  SAMPLES.map((sdk) => ({ label: sdk.name, code: pick(sdk) }));

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
    verifiedRelease: DOCS_VERIFIED_RELEASE,
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
            `[OAuth2 RFC compliance matrix](${COMPLIANCE}/oauth2-rfc-compliance.md) — MUST by MUST, naming the test for each row.`,
          ],
          [
            "RFC 7636 — PKCE",
            "S256 challenge on the authorization code grant.",
            `[Same matrix](${COMPLIANCE}/oauth2-rfc-compliance.md).`,
          ],
          [
            "RFC 7009 — Token revocation",
            "`/oauth2/revoke`.",
            `[Same matrix](${COMPLIANCE}/oauth2-rfc-compliance.md).`,
          ],
          [
            "RFC 7662 — Token introspection",
            "`/oauth2/introspect`.",
            `[Same matrix](${COMPLIANCE}/oauth2-rfc-compliance.md).`,
          ],
          [
            "RFC 8628 — Device authorization grant",
            "The full non-interactive path.",
            `[Device flow reference](${API_DOCS}/device-flow.md).`,
          ],
          [
            "RFC 8693 — Token exchange",
            "Delegation and impersonation, narrowing-only.",
            `[Token exchange reference](${API_DOCS}/token-exchange.md).`,
          ],
          [
            "RFC 9126 — Pushed authorization requests",
            "`/oauth2/par`, requirable per client.",
            `[Integration test suite](${GH_BLOB}/crates/axiam-api-rest/tests/par_test.rs), over [the PAR implementation](${GH_BLOB}/crates/axiam-oauth2/src/par.rs).`,
          ],
          [
            "OpenID Connect Core 1.0 & Discovery 1.0",
            "ID tokens, userinfo, discovery. `alg: none` is excluded from the discovery document and rejected at verification.",
            `[OIDC Core conformance matrix](${COMPLIANCE}/oidc-conformance.md).`,
          ],
          [
            "OIDC RP-Initiated & Back-Channel Logout 1.0",
            "Session-scoped logout in both directions.",
            `[Logout reference](${API_DOCS}/logout.md).`,
          ],
          [
            "UMA 2.0",
            "Protection API and the ticket grant.",
            `[UMA reference](${API_DOCS}/uma.md), and [CONTRACT §20](${contractLink("20")}).`,
          ],
          [
            "FAPI 2.0 Security Profile (Final)",
            "An opt-in constraint bundle that a client cannot half-apply.",
            `[FAPI 2.0 profile guide](${ADMIN_DOCS}/fapi2-profile.md).`,
          ],
          [
            "SCIM 2.0 — RFC 7643 / 7644",
            "Users and Groups CRUD plus PATCH; bulk and complex filters deliberately unsupported.",
            `[SCIM provisioning reference](${API_DOCS}/scim-provisioning.md).`,
          ],
          [
            "WebAuthn / FIDO2",
            "Registration and authentication, with MDS3-backed attestation policy.",
            `[Authenticator policy guide](${ADMIN_DOCS}/authenticator-policies.md).`,
          ],
          [
            "RFC 9807 — OPAQUE",
            "One audited implementation bound by every SDK, tested against shared vectors.",
            `[Shared test vectors](${GH_BLOB}/sdks/opaque-test-vectors.json), and [CONTRACT §23](${contractLink("23")}).`,
          ],
        ],
      },
      { type: "h", id: "security", text: "Security standards" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Standard", "Posture", "Evidence"],
        rows: [
          [
            "OWASP ASVS 4.0.3 Level 2",
            "Control-by-control checklist over V2, V3, V4, V6, V7, V8, V9, V10 and V14. Every in-scope control carries an explicit status — Pass, N/A or Deferred — with the deferrals tracked by finding id rather than left blank.",
            `[ASVS L2 checklist](${COMPLIANCE}/asvs-l2-checklist.md), with the deferrals in the [findings register](${COMPLIANCE}/FINDINGS.md).`,
          ],
          [
            "GDPR",
            "Data export (Art. 15) and erasure (Art. 17) endpoints, with audit-actor pseudonymisation so an append-only trail can coexist with a right to erasure. Exports can be PGP-encrypted.",
            `[GDPR compliance record](${COMPLIANCE}/gdpr-compliance.md) — export completeness, erasure durability and consent, article by article.`,
          ],
          [
            "ISO 27001",
            "Targeted through access control, cryptography and audit logging — the technical controls, not the management system, which is an organizational matter AXIAM cannot supply.",
            `[Security audit](${GH_BLOB}/claude_dev/security-audit.md) — which also states the ISMS certification scope it deliberately excludes.`,
          ],
          [
            "EU Cyber Resilience Act",
            "Secure-by-default posture and a private vulnerability-disclosure process.",
            `[Security audit](${GH_BLOB}/claude_dev/security-audit.md) for the essential-requirements mapping; [SECURITY.md](${GH_BLOB}/SECURITY.md) for the disclosure process.`,
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
          "The OpenAPI document is **drift-gated** — a PR fails if the committed spec diverges from a fresh export from the server — and carries its own SHA-256 content digest at `info.x-axiam-spec-digest`, verified on every commit, so a vendored copy can be checked for currency exactly rather than by comparing version strings.",
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
    verifiedRelease: DOCS_VERIFIED_RELEASE,
    blocks: [
      { type: "h", id: "contract", text: "One contract, many languages" },
      {
        type: "p",
        text: `AXIAM ships SDKs for Rust, TypeScript, Python, Java, C#, PHP, Go, Kotlin, Swift, C and C++. Each lives in its own repository, and each vendors the same three artifacts from this one — [CONTRACT.md](${GH_BLOB}/sdks/CONTRACT.md), [openapi.json](${GH_BLOB}/sdks/openapi.json) and [management-registry.json](${GH_BLOB}/sdks/management-registry.json) — alongside the protobuf definitions. Behaviour is therefore identical whichever language you pick, and a difference between two SDKs is a bug in one of them rather than a matter of taste.`,
      },
      {
        type: "p",
        text: "The contract is not a style guide. It specifies the error taxonomy, CSRF behaviour, the cookie-jar requirement, tenant and organization context, TLS policy, the redacting secret type, the AMQP HMAC construction, the single-flight refresh guard, route-guard interfaces, declarative authorization helpers, OIDC relying-party helpers, webhook verification, the device grant, token exchange, retry policy, deterministic shutdown, telemetry hooks, UMA, FAPI 2.0, Reactors, OPAQUE, WebAuthn, the account-lifecycle and MFA-enrolment operations, pushed authorization requests, and the management API.",
      },
      {
        type: "p",
        text: `The last of those is generated rather than written. \`management-registry.json\` classifies the spec's operations into 24 namespaces and names the 155 that make up the administrative surface, deliberately excluding the protocol endpoints that have their own hand-written sections; each SDK ships a generator over it and a CI job that regenerates and diffs, so a new endpoint reaches all eleven by regeneration rather than by eleven people remembering. See [CONTRACT §27](${contractLink("27")}) and [Managing AXIAM from an SDK](#/docs/rest).`,
      },
      { type: "h", id: "matrix", text: "What each SDK ships" },
      {
        type: "table",
        proseFirstCol: true,
        headers: [
          "SDK",
          "REST core §1–§7, §9–§13",
          "gRPC",
          "AMQP §8",
          "Device & exchange §14–§15",
          "Retry, memo, shutdown, telemetry §16–§19",
          "UMA §20",
          "Reactors §22",
          "OPAQUE §23",
          "WebAuthn, lifecycle, PAR §24–§26",
          "Management API §27",
        ],
        rows: CONFORMANCE.map((row) => [byId(row.id)?.name ?? row.id, ...row.cells]),
      },
      {
        type: "p",
        text: "Read the columns as *what the library gives you*, not as tiers. The REST core is universal — every SDK carries the method-naming map, the three error types, CSRF and cookie handling, required tenant context, strict TLS with mTLS, the redacting secret type, single-flight refresh, route guards, declarative authorization, the OIDC relying-party helpers and the webhook verifier. Reactors reach all eleven: the eight managed runtimes bundle an AMQP client, and Swift, C and C++ ship the same protocol core over a transport you supply.",
      },
      {
        type: "note",
        text: "Two nuances the table cannot hold. **Kotlin's AMQP is reactor-only** — it implements the v2 HMAC and transport rules for the reactor exchange, but not the async-authz and audit-ingestion message types. And **§21's DPoP posture differs per SDK**: PHP and Swift verify proofs but do not generate them, and C and C++ decline proof verification and reject `jkt`-bound tokens outright, which is what the route-guard rules require of them. CONTRACT §21.9 is the per-SDK index.",
      },
      {
        type: "warn",
        text: "This table is transcribed from the eleven SDK READMEs at `1.0.0-beta07` and is a snapshot for orientation. Each README's conformance statement is the SDK's own claim and the thing to check before you depend on a section.",
      },
      {
        type: "p",
        text: "A release ships the surface it derives from the spec it vendors: tagging an SDK re-vendors the contract, the OpenAPI document and the management registry, then regenerates that SDK's §27 management surface from them and stages exactly what the generator wrote. A missing generator stops the release rather than tagging a tree the SDK's own drift-check would reject.",
      },
      { type: "h", id: "packages", text: "Canonical package names" },
      {
        type: "p",
        text: "Install under exactly these names. Eleven public registries are eleven chances for a typosquat, so pin versions, commit lockfiles and keep dependency scanning on — the threat model carries this as an open, shared-responsibility item.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["SDK", "Registry", "Package", "Install"],
        rows: SDKS.map((sdk) => [
          sdk.name,
          `[${sdk.registry}](${sdk.registryUrl})`,
          `\`${sdk.pkg}\``,
          `\`${sdk.install}\``,
        ]),
      },
      { type: "h", id: "login", text: "Connect and check" },
      {
        type: "p",
        text: "The shape is the same everywhere: construct a client with an explicit tenant and organization, sign in, ask a question about a resource. Tokens land in `HttpOnly` cookies and the SDK forwards the CSRF token — browser code never touches a token.",
      },
      {
        type: "codegroup",
        caption: "login and an authorization check",
        tabs: tabs((sdk) => sdk.quickstart),
      },
      { type: "h", id: "guards", text: "Guarding a route" },
      {
        type: "p",
        text: "Each SDK expresses the same guard in the idiom of its framework — decorator, dependency, middleware, annotation, attribute or macro. The check runs **before** the handler body, so a denied request never reaches your code, and a guard with no tenant configured fails closed rather than admitting everything.",
      },
      {
        type: "codegroup",
        caption: "declarative route guards",
        tabs: tabs((sdk) => sdk.guardExample),
      },
      { type: "h", id: "guarantees", text: "What every SDK guarantees" },
      {
        type: "list",
        items: [
          "**Tenant is an explicit constructor parameter.** There is no default tenant and no ambient context to get wrong.",
          "**Secrets are wrapped in a redacting type** that cannot be printed, logged or serialised by accident.",
          "**Browser code never touches a token.** Tokens live in `httpOnly` cookies; the SDK forwards the CSRF token for you.",
          "**Concurrent 401s collapse into one refresh**, not N — the single-flight guard is normative, not an optimisation.",
          "**TLS is strict by default**, with mTLS supported everywhere including the SDKs that ship REST only.",
          "**One OPAQUE implementation** is bound by all of them — compiled in, through WebAssembly, or behind a C ABI. No SDK implements OPAQUE itself.",
          "**Declarative route guards** in the idiom of the language — attribute, annotation, decorator, macro or middleware.",
          "**A webhook verifier** that takes the raw bytes, compares in constant time and fails closed. See [Webhooks](#/docs/webhooks).",
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
