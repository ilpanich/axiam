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
> ## Handoff — this document and the website section
>
> **Status: source current as of 2026-09-04 (`1.0.0-beta11`, model 2.11.0). The
> website section is behind it and is brought up by
> [`website-security-beta11-update-plan.md`](website-security-beta11-update-plan.md),
> which is the entry point for that pass.**
>
> **Beta12 remediation pass (`remediation-plan-2026-09-04.md`).** The wave below
> wrote down, in the model's own words, what it could not close. This pass is
> those residuals. **R-1 has landed**: the gRPC listener no longer asks tonic to
> terminate TLS — it completes each handshake with `tokio-rustls` and hands tonic
> an already-encrypted stream — which lets it resolve its leaf through the *same*
> `ReloadableCertResolver` the REST listener serves from, and lets the
> configuration pin TLS 1.3. That closes **T-234** (the only *open* threat the
> wave added) and removes the TLS-version caveat T-233 and T-214 both carried,
> taking the model to **236 threats, 220 mitigated / 16 open**; the deployment
> diagram goes from 6 open to 5. The open register below loses T-234 accordingly.
>
> **R-3 has landed** alongside it: the deployment-origin rule on a federated
> `redirect_uri` now applies to all four start operations rather than the two
> cross-site ones, so on the OIDC and plain-OAuth2 flows the identity provider's
> registered-redirect comparison is a second, independent layer instead of the
> only server-side check — narrowing **T-219** and retiring `TODO(T19.14)`, whose
> per-config allowlist is superseded rather than deferred. Contract §12.1 rule
> 12a widened to match (1.39), additive and restrictive server-side only, with no
> SDK code changes. It asks one thing of one class of deployment: an SPA on an
> origin other than the issuer's, signing in through OIDC or OAuth2, must set
> `AXIAM__AUTH__SSO_SPA_ORIGINS` — the requirement the other two flows have
> imposed since beta08. T-219 was already Mitigated, so no count moves with it.
>
> The remaining items of that plan — R-2 and R-4…R-7 — are separate passes and
> are not reflected here yet.
>
> **Beta08…beta11 wave (model 2.11.0).** Twenty-five threats enter the model,
> bringing it to **236 threats, 219 mitigated / 17 open**, in three groups. Two of
> them had been written into the STRIDE document at beta08 but never into the
> Threat Dragon JSON, so the website has been rendering a model its own source
> document had outgrown. The first is the public login-provider surface — the
> unauthenticated providers listing that cannot distinguish an unknown organization
> from an unconfigured one, the 60-second single-use handoff codes confined to the
> deployment's own SPA origin, the plain-OAuth2 variant with its downgrade stated,
> provider emails adopted only when affirmatively verified, Entra's templated
> issuer, organization→tenant inheritance and the uploaded button icons
> (T-218…T-225, on four new federation-diagram elements). The second is the
> publicly exposed backend terminating its own TLS — the `TRUSTED_HOPS`
> off-by-one, the unrouted health endpoints, the hot-reloaded leaf, the
> forwarded-client-certificate header now off by default, the Vault seal, and the
> cleartext container hop (T-212…T-217, on a new device actor and the renamed
> proxy → server flow). The login-provider threats had been numbered T-163…T-170,
> continuing the federation section's own sequence, which collided with numbers the
> model already held for the OAuth2 single-use credentials and the SDK `cnf`
> threats; they were renumbered T-218…T-225 on entering the model, and the four
> code comments that cite them moved with them. The third group is new for
> beta09…beta11 (T-226…T-236): an assignment naming no resource is tenant-wide
> rather than inert, with the upgrade hazard that creates written down (T-226);
> scoped grants inherit down the resource lineage without widening sideways or to
> unrelated resources (T-227); the authorization-check endpoints resolve the acting
> tenant through the same reach check as every other route, in one implementation
> rather than two (T-228); WebAuthn user verification is a tightening-only security
> setting, defaulting to `preferred`, that the usernameless path ignores and that
> never weakens a credential enrolled under `required` (T-229, T-230); the Vault
> seeder can no longer mistake a refused read for an empty Vault and mint fresh
> keys over the live ones — a password reset for every user, caused by a restart
> (T-231); the server's Vault policy is one checked file, and the token holds
> read plus CA-key writes rather than read-only, which T-180 and T-216 now say
> (T-232); gRPC may be published, but only through the same edge as REST and only
> as a service allowlist, because a bare port-forward lets a client mint its own
> rate-limit buckets (T-233); the gRPC certificate could not be hot-reloaded, recorded
> **open** with the restart the runbook used to bridge it — closed since, by R-1
> above (T-234); a
> release regenerates each SDK's §27 surface from the spec it vendors (T-235); and
> the dependency-audit gate tells a registry outage apart from a clean audit and
> fails on a stale suppression (T-236). Nine existing entries gained
> cross-referencing clauses (T-43, T-127, T-180, T-193, T-199, T-201, T-212,
> T-214, T-216). The open register below loses T-118 — closed at beta03 but still
> listed here — and gains T-216 and T-234; AXIAM's own request path still carries
> no open Critical or High finding. The coverage tables are refreshed from the
> model, and the prose under *How AXIAM defends each layer* gains the matching
> paragraphs. **The website was not touched in this pass**: `npm run
> gen:threat-model` was run only to confirm the model parses and yields these
> numbers, and reverted. `src/security.ts`, `src/version.ts`, the generated files
> and the Docs pages the same releases changed are the plan's job.
>
> **Beta05…beta06 wave (model 2.10.0).** Twelve new mitigated threats,
> T-200…T-211, bring the model to **211 threats, 196 mitigated / 15 open** —
> most of them found by the E2E permission matrix run against the production
> image rather than the preview proxy. On the authorization diagram: the
> organization-principal guard (B-04 — a tenant super-admin could flip a CA's
> mTLS trust-anchor flag and mint sibling-tenant identities; T-202, which also
> records B-08's MDS-refresh gap and B-09's `/auth/me` wildcard), the single
> `ORGANIZATION_LEVEL_ACTIONS` list that makes the seeded grant data agree with
> the guard (T-203), tenant-scoped role assignments — `tenant_scope`, schema 51
> — enforced at all four doors (T-204), and reach-filtered organization and
> tenant rosters (T-205). Enrolling a passkey now turns the second-factor
> requirement on (T-201); a bearer-only machine caller is exempt from the CSRF
> cookie while bearer-plus-cookie deliberately is not (T-200); device
> authentication requires the chain to reach a CA enabled as an mTLS trust
> anchor on the proxy-terminated path exactly as on the native one (T-206); a
> rolling deployment no longer logs the surviving replicas out of SurrealDB
> (T-207); the shipped nginx config is now the artifact CI measures (T-208);
> the admin UI namespaces its query cache by acting tenant so a switch cannot
> keep rendering the previous tenant's rows (T-209); the contract names the
> acting-tenant header the server actually reads — `X-Axiam-Tenant`, contract
> 1.36 (T-210); and the assignment dialogs offer the same scope pickers
> everywhere roles are assigned (T-211). `npm run gen:threat-model` has been
> re-run, `src/version.ts` stamps `1.0.0-beta06` / 2026-08-30, and the prose is
> mirrored in `src/security.ts` in the same change: the passkey-is-a-factor
> clause under *Authentication & sessions*, the organization-principal-guard
> and tenant-scope bullets under *Authorization & tenant isolation*, the
> trust-anchor chain-walk clause under *PKI*, and the tenant ↔ tenant boundary
> row.
>
> **Not affected by the beta07 docs pass (2026-08-30).** The Docs, News and
> Roadmap sections were brought to `1.0.0-beta07` in a separate pass
> ([`website-docs-beta06-improvement-plan.md`](website-docs-beta06-improvement-plan.md),
> which carries its execution record). That pass did not touch `security.ts`,
> `threatModel.ts`, `threatModelSummary.ts` or the Threat Dragon model, and
> `SECURITY_VERIFIED_RELEASE` deliberately stays at `1.0.0-beta06`: beta07
> changed nothing security-relevant, and the constant records when someone last
> re-derived these claims rather than the newest tag. `npm run
> gen:threat-model` was re-run to confirm the generated files are in sync with
> the model; it produced no diff.
>
> **Beta03 hardening pass (model 2.9.0).** Three mitigations changed after the
> wave below, and one threat closed. T-118 (audit trail deleted along with the
> tenant) is **Mitigated**: deleting a tenant now requires its audit trail to
> have been exported in the previous six hours, and the deletion is recorded in
> the system audit log naming the export that authorised it. T-180 (Vault
> concentrates every long-lived secret) and T-148 (compromised release pipeline)
> stay Open with narrower residuals — `just vault-status` now reports the token's
> real capabilities rather than only which secrets exist, and every release
> workflow in the fleet pins its actions by digest and attests the artifacts it
> publishes. T-148's residual narrowed once more when the two Maven Central
> pipelines — the only two of eleven that still hold a stored registry
> credential — began publishing keyless Sigstore bundles alongside their PGP
> signatures, so the artifact set Central itself serves carries a statement of
> build origin the Portal token cannot forge. The model is **199 threats, 184
> mitigated / 15 open**; `npm run gen:threat-model` has been re-run.
>
> The 1.0.0-beta03 pass records the beta01…beta03 wave as thirteen new mitigated
> threats, T-187…T-199, bringing the model to **199 threats, 183 mitigated / 16
> open** (model 2.8.0 — see the beta03 hardening note above for the three
> mitigations that moved after it): organization-level principals and the explicit
> `SubjectScope` cross-tenant claim on the authorization diagram (T-190…T-193);
> tenant signing CAs, per-CA Vault key custody with inheritance, the
> custody-migration key-destruction fix, CSR constraint enforcement and the mTLS
> trust-anchor bundle with hot reload on the PKI diagram (T-194…T-198); the
> organization-threshold lockout fix and the logout removal-cookie fix on the
> authentication diagram (T-188, T-189); the user-deletion erasure/identifier-release
> fix on the system diagram (T-187); and the OpenAPI content digest that keeps the
> eleven vendored SDK specs honest (T-199). T-95…T-98 gained the matching custody,
> RSA-keygen, issuer-bound-validity and tenant-CA clauses, and the tenant ↔ tenant
> trust-boundary row now names the organization-scope claim. `npm run
> gen:threat-model` has been re-run, `src/version.ts` stamps `1.0.0-beta03` /
> 2026-08-28, and the prose changes are mirrored in `src/security.ts` in the same
> change: the cross-tenant-claim bullet and decision-cache sweep under
> *Authorization & tenant isolation*, the tenant-signing-CA / custody /
> mTLS-anchor bullets under *PKI*, the lockout-threshold and removal-cookie
> clauses under *Authentication & sessions*, and the boundary and asset-table
> rows. The Docs section (not Security) has its own pending pass, planned in
> [`website-docs-beta03-improvement-plan.md`](website-docs-beta03-improvement-plan.md).
>
> Before that: the alpha38 change to the section was presentational and added no claim: the
> threat-model explorer now renders each threat's `T-nnn` identifier as a
> copyable anchor and keeps the diagram, element and threat selection in the URL
> (`#/security/diagram/8/T-186`), so a threat cited in a commit message, the
> STRIDE model or the SDK contract can be linked to; it filters by severity,
> STRIDE category and free text as well as by open-only. Coverage by STRIDE
> category and by severity, and the open risk register, are now on the page —
> all three emitted by `scripts/gen-threat-model.mjs` into
> `src/threatModelSummary.ts` rather than typed in, so they cannot drift from the
> model. Compliance rows link to the evidence file behind each status, and the
> release the claims were verified against is stamped on the page from one
> constant, `website/src/version.ts`. The corresponding tables and the stamp are
> mirrored in this document.
>
> The alpha38 pass records the contract 1.28 SDK surface —
> WebAuthn (§24), account lifecycle and MFA enrolment (§25) and PAR (§26) in all
> eleven SDKs, plus the §22 reactor protocol core in Swift, C and C++ over a
> caller-supplied transport — as four new mitigated threats on the SDK diagram
> (T-183…T-186), and notes on T-182 that the passkey `finish` handlers now emit
> the same cookie triple and CSRF header as the password path (the alpha38
> server fix). That brings the model to 186 threats, 170 mitigated / 16 open;
> `npm run gen:threat-model` has been re-run and the SDK bullets below extended
> in the same change. Before that: the alpha37 pass closed six threats the remediation work
> shipped — NetworkPolicies applied (T-125), a jobs-health endpoint (T-129), the
> broker vhost (T-131), the file/Vault secret providers in the manifests (T-132),
> the MDS staleness bound (T-153) and the default audit-retention window
> (T-119) — and added T-182 for the usernameless passkey sign-in path, with
> `src/security.ts` and the generated model files updated in the same change. Before that, the page
> first went live from a version of this document verified against `3ede4d19`
> (2026-08-04). Both were then brought up to `1.0.0-alpha34`:
> OPAQUE (RFC 9807) replacing SRP, HashiCorp Vault as the production secret
> provider, TLS-only AMQP, SCIM provisioning tokens, deny-override shipping
> (SEC-040 closed — it is no longer listed as an accepted trade-off),
> sender-constrained OAuth2 clients and tokens, the WebAuthn MDS3 attestation
> policy, the SurrealDB persistent-storage-engine requirement, and the
> SEC-096…SEC-107 remediation wave. `npm run gen:threat-model` has been re-run
> (the Threat Dragon model gained threats T-176…T-181 and closed T-16/T-87, and
> `src/threatModel.ts` / `src/threatModelSummary.ts` are regenerated from it),
> and the prose blocks in `src/security.ts` now match the sections below. The
> alpha34 claims were written against the shipped code and its design documents
> (`opaque-design.md`, `docs/deployment/vault.md`,
> `scim-provisioning-token-design.md`, `remediation-plan-2026-08-15.md`); the
> older claims retain their 2026-08-04 file-and-line verification in the analysis
> document.
>
> **Keeping the two in step.** When this document changes, mirror the change into
> `src/security.ts` in the same commit. Three bullets there deliberately place
> their emphasis differently from the Markdown here — the `redirect_uri` bullet,
> the mounted-Secret-files clause, and the SurrealDB storage-engine bullet. The
> site's inline renderer splits on backticks before it handles `**`, so a bold
> span that encloses a code span leaves the rest of the sentence bold; in each
> case the claim is identical and only the bold markers moved.
>
> **Where it lives.** A top-level **Security** nav entry, alongside Docs, SDKs,
> Benchmarks and Roadmap. In `website/`:
>
> 1. `src/types.ts` — `"security"` is part of the `Page` union.
> 2. `src/components/Header.tsx` — the `Security` nav item; `src/App.tsx` routes it.
> 3. `src/security.ts` — this document as `DocBlock` content, one entry per section.
> 4. `src/pages/Security.tsx` — the page: hero, sticky section index, article.
> 5. `src/components/ThreatModelExplorer.tsx` — the interactive diagram browser.
> 6. `src/threatModel.ts` / `src/threatModelSummary.ts` — **generated**, do not edit.
>    Run `npm run gen:threat-model` after changing the Threat Dragon model; the
>    generator (`website/scripts/gen-threat-model.mjs`) reads
>    `ThreatDragonModels/Axiam/Axiam.json` and re-emits both.
> 7. `src/version.ts` — the release and date the claims were last verified
>    against, quoted by the page's stamp. Hand-maintained on purpose: it records
>    when someone re-derived the claims, which no version file can tell us.
>
> All nine diagrams render from that model, and every number on the page — the
> headline stats, the coverage tables by area, STRIDE category and severity, and
> the open risk register — is interpolated from the generated summary rather than
> typed in, so the page cannot drift from the model. Prose numbers quoted in this
> document are the only ones maintained by hand.
>
> **Content mapping.** The structure here maps onto the existing `DocBlock` model
> in `src/docs.ts`: `##`→`h`, paragraphs→`p`, bullet lists→`list`, tables→`table`,
> and the blockquote marked **Caution**→`warn`. The eight subsections under
> *"How AXIAM defends each layer"* are the sidebar entries under that group.
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
> **Resolved TODO:** the closing line used to carry a placeholder security
> contact. [`SECURITY.md`](../SECURITY.md) now exists at the repository root —
> supported versions, what to include in a report, the response and disclosure
> timeline, and what is out of scope — and the page links to it alongside GitHub's
> private advisory form. Keep the two in step if either changes.

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

The system is verified against a **STRIDE threat model of 236 threats** and a
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
| Threats identified | 236 |
| Mitigated / Open | 219 / 17 |

Every threat is examined against the STRIDE categories that apply to its element
type (actor, process, data store or data flow). A threat is marked **mitigated**
only where a control exists in the codebase and can be pointed at; where the
residual risk is accepted, deferred, or belongs to whoever deploys AXIAM, it stays
**open** and explains itself. An honest open item is more useful than an
optimistic closed one.

### Coverage by area

| Area | Threats | Open |
|---|---|---|
| System context | 29 | 2 |
| Authentication & session management | 32 | 1 |
| OAuth2 / OIDC authorization server | 24 | 0 |
| Federation (SAML SP & OIDC RP) | 31 | 1 |
| Authorization engine (RBAC, hierarchy, scopes) | 26 | 0 |
| PKI, certificates & IoT device identity | 24 | 1 |
| Audit, webhooks, email & notifications | 18 | 2 |
| Deployment & platform (Kubernetes) | 26 | 6 |
| Client SDKs & admin-UI integration surface | 26 | 4 |

The concentration of open items in *Deployment* and *Client SDKs* is deliberate
and expected: those are the two areas where security is a shared responsibility
between AXIAM and the people who run and integrate it. AXIAM's own request path —
authentication, authorization, tokens, PKI, federation — carries **no open
Critical or High finding**.

### Coverage by STRIDE category

Each element is examined against the STRIDE categories that apply to its type — an
actor can be spoofed or repudiate an action, a data flow can be tampered with,
disclosed or flooded, a process can be all six — so the distribution below follows
the shape of the system rather than a quota. Every threat is counted once, under
the category recorded against it in the model.

| Category | Threats | Open |
|---|---|---|
| Spoofing | 58 | 3 |
| Tampering | 49 | 1 |
| Repudiation | 5 | 0 |
| Information disclosure | 57 | 7 |
| Denial of service | 22 | 3 |
| Elevation of privilege | 45 | 3 |

### Coverage by severity

| Severity | Threats | Open |
|---|---|---|
| Critical | 28 | 1 |
| High | 113 | 8 |
| Medium | 88 | 7 |
| Low | 7 | 1 |

Severity records the impact if the threat were realised, so it does not change
when the threat is mitigated: a closed Critical stays Critical, because that is
the weight the control carries. The 17 still-open items are listed one by one in
the open risk register under [Shared responsibility](#shared-responsibility), each
with the element it sits on and where responsibility for it lands.

---

## Trust boundaries

Five trust boundaries recur across the system. A data flow that crosses one is a
place where authentication, authorization, validation and transport protection all
have to be re-established — nothing is assumed across a boundary.

| Boundary | Separates | What must hold on every crossing |
|---|---|---|
| **Public Internet ↔ AXIAM** | Browsers, SDK callers, IoT devices, external IdPs | TLS 1.3 — terminated by the server itself on the documented topology — authentication, rate limiting keyed on a peer address derived by a stated rule, CSRF on cookie requests, input validation; forwarded headers (`X-Forwarded-For`, `X-Client-Certificate`) trusted only from a proxy the deployment runs |
| **AXIAM ↔ data tier** | Application pods ↔ SurrealDB, RabbitMQ, Vault / Secrets | Private network, credentialed connections, TLS-only AMQP, parameterised queries, tenant scoping at the repository layer |
| **Tenant ↔ tenant** | Every tenant's data from every other's | Tenant context derived from the verified session or JWT — never from request input — and enforced on every query and graph traversal; cross-tenant reach only as an explicit organization-scope claim — narrowable to named tenants per role assignment — verified to stay inside the caller's organization and reach |
| **AXIAM ↔ third parties** | Outbound to IdPs, email providers, webhook receivers | SSRF guard with resolve-and-pin, HTTPS enforcement, response-size caps, HMAC signatures on deliveries |
| **Server ↔ SDK / admin UI** | The server contract from its client implementations | One cross-language contract — TLS policy, secret redaction, CSRF, AMQP HMAC — enforced by CI drift and protobuf gates |

### The assets worth protecting

| Asset | Protection | Compromise would mean |
|---|---|---|
| JWT signing key (Ed25519) | Secret provider — Vault in production — never in the image | Any identity in any tenant forged |
| Organization CA private key | Per-CA custody: AES-256-GCM at rest, or held in Vault | Any user/service/device certificate minted |
| Tenant signing CA private key | Same per-CA custody; path-length-zero intermediate | One tenant's certificates minted; revocation scoped to that tenant |
| Password hashes | Argon2id, per-user salt, pepper | Offline cracking of credentials |
| OPAQUE setup key & per-tenant OPRF seeds | Secret provider; seeds AES-256-GCM encrypted at rest | Stolen OPAQUE records become dictionary-attackable |
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
  by every credential-checking path — REST, OPAQUE and gRPC alike — and metered
  against the organization's own effective threshold (org baseline, tenant
  override), with the deployment default only as a fail-safe floor when settings
  cannot be resolved.
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
  skipped by replaying it. Passkeys also work as a **usernameless, one-step
  sign-in** (discoverable credentials), and that path re-establishes every gate
  the password step would have run: account status and lockout are checked, the
  operator's login-veto hook still fires, and the anonymous start endpoint
  touches no storage — so it cannot be used to probe which workspaces or
  accounts exist. A completed passkey ceremony also leaves the browser in the
  same session posture as a password login — the same `HttpOnly` cookie triple
  and CSRF token — while non-browser clients adopt the token pair from the
  response body, as the SDK contract has them do. And enrolling a passkey is
  enrolling a *factor*: from the moment a WebAuthn credential exists, the next
  sign-in demands a second factor — an abandoned, unconfirmed TOTP enrollment is
  dropped rather than silently promoted alongside it — and removing the last
  credential turns the requirement back off.
- **User verification on a WebAuthn ceremony is a policy, not a library
  constant.** `webauthn_user_verification` is an organization baseline every
  tenant inherits and may only tighten — `required` > `preferred` >
  `discouraged` — and it defaults to `preferred`, so a security key with no PIN
  can be enrolled as a *second* factor and the server records whether
  verification happened. Two ceremonies ignore the setting on purpose:
  usernameless passkey sign-in keeps `required`, because there the credential is
  the only factor and possession alone must never be a complete login, and
  attested registration keeps the `required` the library imposes. A relaxed
  setting weakens no existing credential — the policy a credential was enrolled
  under is recorded and honoured for the rest of its life — and the setting is a
  required field on the settings write, so a client cannot relax it by omission.
- **Tokens**: access tokens are **EdDSA (Ed25519) JWTs**, 15 minutes long. The
  verifier pins the algorithm and never reads it from the token header, so
  `alg:none` and HMAC-key-confusion attacks are rejected outright. Refresh tokens
  are opaque, server-stored and **single-use with rotation**, consumed through an
  atomic delete-gate so a race cannot fork the session or hide a stolen-token
  reuse. In the browser, tokens live only in `Secure` / `HttpOnly` /
  `SameSite=Strict` cookies — never in `localStorage`, never in a URL — and
  logout's removal cookies are built from the same setters they clear, so the
  protective attributes are mirrored by construction rather than restated.
- **Password reset** uses CSPRNG-generated, single-use, short-lived tokens
  (never time-ordered UUIDs), delivered over an authenticated POST, and consuming a
  reset invalidates every existing session. An optional **Have I Been Pwned**
  k-anonymity check (only a five-character hash prefix leaves the server, behind a
  circuit breaker) blocks known-breached passwords.
- **OPAQUE (RFC 9807) is available as an augmented PAKE** — off by default,
  enabled per organization or tenant, with a tenant able to tighten but never
  relax the organization baseline. With it enabled, the plaintext password never
  reaches the server at all: not a TLS-terminating proxy, not a request-body log,
  not a heap dump. Stolen OPAQUE records are not offline-attackable at KDF cost
  the way a hash corpus is — recovering a password additionally requires the
  tenant's OPRF seed, which is AES-256-GCM encrypted at rest under a key held in
  the secret provider. Unknown identities receive a stable, well-formed decoy
  response so the flow is enumeration-safe, and a failed exchange accrues toward
  the same lockout as a failed password. One audited implementation
  (`axiam-opaque`, with C-ABI and WebAssembly builds) serves all eleven SDKs and
  the admin UI, instead of eleven hand-written PAKEs.
- **SCIM provisioning uses purpose-bound long-lived tokens.** Okta and Entra can
  only present one static bearer string, so AXIAM mints one that is accepted on
  `/scim/v2/*` and nowhere else, carries no permissions of its own (the resolved
  tenant user's RBAC still decides), is stored hashed with the plaintext returned
  exactly once, and is expiring, revocable and audited. Deprovisioning a user
  through SCIM also revokes their live sessions and refresh tokens.

### Authorization & tenant isolation

Tenant isolation is the core guarantee of a multi-tenant IAM, so it is enforced
redundantly rather than at one chokepoint:

- **Tenant context comes from the verified session or JWT, never from request
  input.** A caller cannot name a tenant it does not belong to. The organization
  claim in a token is derived server-side from the tenant record on both login and
  refresh — it is never accepted from the client.
- **Cross-tenant reach is an explicit claim, never an inference.** Organizations
  hold their estate-wide principals in one reserved organization scope — itself a
  tenant, so every isolation control applies to it. The engine reads a subject's
  grants across a tenant boundary only under an explicit organization-scope claim
  (`SubjectScope`), which an ordinary tenant principal cannot express at all, and
  only *global* grants carry across: a resource-scoped grant names a resource in
  the organization scope, and a same-named resource in another tenant is a
  different thing. The claim is produced in exactly one place, after resolving the
  tenant record and checking it is the organization's reserved scope, and the
  `X-Axiam-Tenant` header an organization-level principal switches tenants with is
  verified to stay inside its own organization — failing closed when it cannot be
  verified. Revoking an organization-level role sweeps the decision cache in every
  tenant, not just the one the revocation happened in.
- **Organization-level actions require an organization-scoped principal, not
  merely the permission.** Creating organizations or tenants, every CA operation
  and the FIDO metadata refresh are refused to any caller whose record does not
  live in the organization's reserved scope — keyed on where the principal lives,
  not on what its roles carry, and failing closed when that cannot be resolved.
  The grant data agrees with the guard: tenant roles are seeded *without* the
  organization-level actions, a boot-time reconciler revokes ones seeded earlier,
  and a consistency test reads the handler sources to prove every withheld action
  is scope-guarded. Deployment-wide rosters honour the same boundary — an
  organization sees only itself in the organization listing, and the tenant
  roster answers each administrator with exactly the tenants it reaches.
- **Cross-tenant reach can be narrowed to named tenants.** A role assignment can
  carry a `tenant_scope` confining an organization-level account to particular
  tenants of its organization. The rule is written once and enforced at every
  door: the engine's single and batch paths filter per decision, organization-wide
  actions are refused to a confined account, the `X-Axiam-Tenant` switch refuses
  tenants outside the account's reach, and `/auth/me` reports
  `reachable_tenant_ids` and withholds the `*` wildcard so the admin UI never
  offers a control the server would refuse. Existing assignments are untouched by
  the migration — an unrestricted grant stays unrestricted until an administrator
  narrows it.
- **What a grant reaches is what the model says it reaches.** An assignment that
  names no resource is tenant-wide — the meaning the field has always been
  documented to carry, and one the engine had failed to honour, leaving such
  grants silently inert and nudging administrators toward wider ones.
  Tenant-wide, not organization-wide: an unscoped assignment in an organization's
  own tenant does not reach its member tenants. A grant on a scope constrains the
  resource that scope lives on and is inherited whole by everything beneath it,
  with denies inheriting by the same rule — and it never widens sideways (a grant
  on `billing` does not reach `payroll`) or to a scope on an unrelated resource,
  both pinned by tests. Because the first of these turns previously dormant
  assignments into live grants at upgrade, the upgrade note says how to find them
  first.
- **One acting-tenant resolution, for every extractor.** The organization-reach
  check that lets an organization-level principal act on one of its tenants is
  implemented once and shared by both request extractors, including the one the
  authorization-check endpoints bind — a second copy of that check, or a path
  without it, is exactly how a guard drifts on one route and not the others.
- **Repository queries are tenant-scoped and parameterised.** Every SurrealQL
  statement uses bind parameters — no query is assembled by string concatenation of
  user input — and carries a `tenant_id` predicate. Cross-tenant graph edges are
  stripped during permission resolution rather than followed. The isolation is
  enforced twice over: an edge that would cross tenants cannot be *written* in the
  first place, and every traversal that reads one — including group membership,
  the indirect path by which roles are inherited — re-checks the tenant at read
  time rather than trusting the write-time guard.
- **The authorization engine is RBAC, default-deny, with explicit deny-override.**
  A route with no declared permission is refused, not allowed. Roles cascade down a
  resource hierarchy with bounded, cycle-safe traversal, and a grant carries
  `effect: "allow" | "deny"` — an explicit deny overrides every allow, at any depth
  of the hierarchy and at equal specificity, so adding a deny rule can never widen
  access and can never be undone by adding allows (asserted by an exhaustive
  property test).
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
- **Clients can authenticate without a copyable secret, and tokens can be bound
  to their holder.** Mutual-TLS client authentication (RFC 8705) and
  `private_key_jwt` assertions (with a single-use `jti` and a hard lifetime cap)
  replace the shared `client_secret`; certificate-bound and DPoP (RFC 9449)
  access tokens make a leaked token useless without the private key that
  presented it — and a token obtained through token exchange inherits the
  sender-constraint the exchanging client proved, so the exchange path cannot be
  used to launder a bound token into a bearer one. Every authorization response
  carries the RFC 9207 `iss` parameter, closing the authorization-server mix-up
  class. Assertion and proof verification derives the algorithm from the key
  material, never from the token header.
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
- **The public login surface is designed for the fact that it is public.** The
  providers listing a login page renders its buttons from is unauthenticated, and
  it answers `200` with an empty list for an unknown organization exactly as for
  a known one with nothing configured, so it cannot be used to enumerate which
  organizations a deployment hosts; it returns only what a button needs, under
  the same per-IP budget as the sign-in endpoints.
- **Cross-site returns get a session through a handoff code that can only be
  delivered home.** SAML and Apple return cross-site, where `SameSite=Strict`
  cookies would not travel, so the return carries a 256-bit, single-use,
  60-second code stored only as a hash and exchanged same-origin for the session.
  Where that code may be delivered is not the caller's choice: the redirect is
  confined to the deployment's own issuer origin plus any operator-named SPA
  origin, compared as origins so a path, port or scheme cannot smuggle a second
  host past it, and enforced at login start, at the mint and on the error
  redirect — because on these two flows the identity provider never sees the SPA
  URL, so nothing else would have checked it. The **same rule governs the OIDC
  and plain-OAuth2 flows**, where the provider does see the URL and does compare
  it against its registered set: that comparison is only as strict as each
  provider's registration hygiene, and it is not a control this deployment owns,
  so it sits behind AXIAM's own rule as a second layer rather than in place of
  it.
- **The plain-OAuth2 variant states its downgrade instead of hiding it.**
  Providers that issue no ID token (GitHub, Facebook) authenticate by a userinfo
  call with no signature, `nonce` or `aud`. AXIAM refuses that protocol for every
  provider that supports OIDC properly, makes server-side PKCE mandatory on it,
  takes its three endpoints only from operator configuration — never from
  anything the provider says at runtime — through the same SSRF guard as every
  other fetch, and adopts an email address only when the provider affirmatively
  marks it verified. A templated issuer such as Entra's `common` authority
  requires an explicit list of accepted tenants, refused at write time and again
  at sign-in without one, so "every Microsoft account on earth" can never be the
  accidental default. An organization's provider inherited by its tenants
  provisions the user in the *requesting* tenant, and an uploaded button icon is
  raster-only and size-bounded before it is served to every visitor.

### PKI, certificates & device identity

- Certificates are **per-tenant, issued beneath the organization CA** — optionally
  through a **tenant signing CA**, a path-length-zero intermediate signed by the
  organization CA whose revocation is scoped to exactly that tenant, so one
  tenant's compromised issuance no longer burns the estate-wide trust anchor.
  Keys are RSA-4096 or Ed25519 from the platform CSPRNG. **Private keys are never
  stored server-side** — returned exactly once at issuance, delivered only over
  TLS 1.3 — and issuance **refuses a certificate that would outlive its issuer**,
  quoting the achievable validity instead of silently truncating. A tenant CA
  minted from a customer's own CSR keeps only the CSR's subject: the constraints
  (CA:TRUE, path length zero, certificate-signing key usage) are stated by AXIAM,
  and the request's self-signature is verified as proof of possession.
- **CA signing keys live where you choose, and the choice is recorded per CA**:
  sealed AES-256-GCM into a separate, access-controlled table with the key held
  outside the datastore, held in HashiCorp Vault, or generated inside Vault's PKI
  engine and never exported at all. A deployment that configured Vault inherits it
  for CA custody rather than silently falling back to database rows; an explicit
  database choice beside a working Vault is called out at startup; and an existing
  key can be moved between custodians without re-issuing anything beneath it, in a
  copy-record-release order that can never leave the CA without its key.
- **mTLS device authentication verifies the full chain** to the tenant/org CA after
  the fingerprint lookup, checks the issuing CA is active and within its validity
  window, and enforces the certificate's own validity period and live revocation
  status on every connection — a fingerprint match alone is never enough. The
  chain must also reach a CA an administrator has **enabled as an mTLS trust
  anchor** — on the proxy-terminated path exactly as on the native listener,
  where the client-CA bundle is built from the flagged anchors. The walk climbs
  the issuing chain (a tenant signing CA is deliberately an unflagged
  intermediate), requires every CA on the way to be active and in date, and is
  depth-bounded, so un-flagging a CA — the documented way to stop trusting it —
  takes effect everywhere.
- **An organization CA can anchor mTLS directly.** Flagging it exports only the
  public certificate into the client-verification bundle — the signing key is never
  copied — and the bundle is rewritten as the whole flagged set on every change and
  hot-reloaded into the live verifier, so unflagging or revoking a CA removes its
  anchor instead of leaving one a restart would still trust. Client verification
  stays optional, and an operator's own explicitly configured bundle is never
  overridden.
- **OpenPGP keys** sign the audit trail and encrypt GDPR data exports, so both are
  independently verifiable and confidential.
- **WebAuthn attestation policy (X3)** verifies the FIDO Alliance's MDS3 metadata
  BLOB against a **digest-pinned vendored trust anchor** — chaining to the public
  GlobalSign root alone would only prove "some GlobalSign EV customer", so the
  leaf's SAN DNS identity and the CA/`basicConstraints` status of every issuer in
  the chain are checked too. Ingestion rejects a rollback to an older BLOB serial
  and never hard-fails on a stale one (logged, not blocking) — but an operator can
  now bound how stale is acceptable: past `AXIAM__PKI__MDS_MAX_STALE_DAYS` beyond
  the BLOB's own `nextUpdate`, attested registration is refused rather than decided
  on metadata too old to trust (off by default, because the right bound is a
  property of the deployment). This is opt-in (`AXIAM__PKI__MDS_ENABLED=false` by
  default, zero outbound calls) and enforced only at registration — existing
  credentials are never auto-revoked on a policy change.

### Audit & accountability

- The audit log is **append-only** — no UPDATE or DELETE paths — and batches are
  **OpenPGP-signed**, making tampering or selective deletion detectable rather than
  merely difficult.
- Every state-changing and authorization action is recorded with actor, actor type,
  IP, outcome and timestamp; **both allow and deny decisions** are captured, so
  probing shows up in the trail. Records are structured fields, not formatted
  strings, so log-injection cannot forge a synthetic entry.
- **Retention is bounded by default**: a background sweep prunes audit records
  older than 730 days through the table's only deletion path — deployment-wide,
  never reachable from any HTTP handler, so "prune old records" cannot become
  "delete the evidence". Set the window to match your lawful basis, or `0` to
  disable; either state is logged at startup.

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
  production builds — and the **broker connection is TLS-only**: `amqps://` is the
  only accepted scheme, refused before a socket is opened in every build profile,
  with no plaintext escape hatch left in the configuration surface.
- **Email** is built through a typed API that rejects header injection, renders
  templates with user values as escaped data (never as template source), and
  encrypts provider credentials at rest.

### Transport, secrets & the SDKs

- **TLS 1.3 is the minimum** for all external communication; HSTS is emitted; the
  optional in-process TLS listener is TLS 1.3-only and fails fast rather than
  falling back to plaintext.
- **The backend can sit on the public origin, terminating its own TLS.** The
  documented topology routes by path at the edge — the SPA at `/`, and `/api`,
  `/oauth2` and `/.well-known` to the server over TLS 1.3 the server terminates —
  which removed a proxy hop and the cleartext container-network leg that every
  password and token used to cross. The leaf certificate is hot-reloaded on
  `SIGHUP` and by an hourly poll, validated before it is swapped, so an ACME
  renewal needs no restart; the health endpoints are deliberately not routed at
  the edge; the rate-limit key follows a stated rule — `TRUSTED_HOPS` is proxies
  *minus one*, with a per-topology table and tests — rather than the off-by-one
  advice the documentation used to give; and a forwarded `X-Client-Certificate`
  header is trusted **only** when an operator asserts that a proxy they run
  performs the mTLS handshake — off by default, and stripped by the shipped edge
  configurations either way, because a certificate is public data and a header
  cannot prove possession of the key. gRPC may be published through the same
  edge, as an allowlist of services, and never by a bare port-forward: without a
  proxy appending the real peer, a client keys its own rate-limit bucket. The
  gRPC listener terminates its own TLS rather than delegating to tonic, which is
  what lets it share the REST listener's reloadable certificate — one `SIGHUP`
  renews both — and pin TLS 1.3 exclusively, as REST has always done.
- **Vault is run as the production secret store it is.** Both shipped Vault
  deployments use Raft storage; the server holds a scoped, periodic token whose
  policy is one checked file — read on the startup secrets, writes confined to
  the CA-key prefix — rather than the root token, and `just vault-status` reports
  the capabilities the token lacks as well as the ones it should not have. The
  seeder waits for an *active* node, treats only `200` and `404` as statements
  about what the Vault holds, pins every write to the version it read, and
  refuses any payload that would replace a stored secret — closing a path by
  which a restart could silently rotate the OPAQUE setup key and reset every
  password in every tenant. Auto-unseal remains the one production step AXIAM
  cannot take for you.
- **Secrets at rest** — MFA seeds, CA keys, OPAQUE OPRF seeds, federation and
  webhook and email secrets — are AES-256-GCM encrypted; passwords are
  Argon2id-hashed and client secrets are hashed under a **server-held key**, so a
  database disclosure alone does not yield an offline-crackable corpus.
  Secret-bearing types carry redacting `Debug`/`toString` implementations so a
  credential never reaches a log line. A **missing encryption key or pepper fails
  startup**; no code path substitutes an all-zero, constant or unkeyed fallback.
- **Long-lived secrets come from a pluggable secret provider — HashiCorp Vault by
  default in production.** All ten of them — the JWT signing key, the OPAQUE setup
  and session keys, the PKI, MFA, federation and email encryption keys, the
  password and pseudonym peppers, and the AMQP signing key — are fetched from
  Vault rather than the container spec, so none needs to exist as an environment
  variable or Kubernetes manifest at all. The seeder mints what is missing from a
  CSPRNG and **never regenerates a secret that already exists** (regenerating the
  OPAQUE setup key would mean a password reset for every user; regenerating the
  pepper would invalidate every stored hash), and the status tooling reports
  presence only, never values.
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
- **WebAuthn ceremonies pass through the SDKs unchanged.** Contract §24 gives every
  SDK the relying-party half of a passkey ceremony — four JSON round trips — while
  the server keeps all of the crypto and all of the policy. The rules are written for
  the failure that would be invisible: an SDK must not default, fill in, reorder or
  re-encode any field of the server's ceremony options, and must not refuse options
  it parsed — every field is a security parameter, and an assertion produced under
  locally "improved" options is one the server cannot tell from a correct one. The
  authenticator's response goes back verbatim, and the required tests pin
  byte-identical pass-through.
- **Account-lifecycle helpers keep the server's enumeration safety, and their new
  secrets are redacted.** Contract §25 brings MFA enrolment, email verification and
  password reset into every SDK. The credential-bearing fields it introduces — the
  TOTP secret, the `otpauth://` URI that *contains* it, the forced-enrolment setup
  token, the single-use reset and verification tokens — are all wrapped in redacting
  types, with tests that scan serialized output for the secret value rather than the
  field name. And the deliberately uniform server responses stay uniform in the SDK:
  no "no such user" state on a reset request, no distinguishing an unknown reset
  token from an expired one, no displaying the account a token belongs to.
- **Pushed authorization requests (RFC 9126) take the authorization request out of
  the browser.** Contract §26 has the SDKs POST the scope, redirect URI, `state` and
  PKCE challenge over an authenticated back channel and put only an opaque,
  single-use `request_uri` in the redirect — what travels through the user agent is
  a random string that cannot be edited into meaning something else. It is required
  for any SDK claiming the FAPI 2.0 client profile.
- **The reactor signing protocol is library code in all eleven SDKs.** The eight
  managed-runtime SDKs already shipped it; contract §22.11 brings the protocol core —
  v2 HMAC over the canonical serialization, freshness in both directions, nonce and
  correlation binding, the mutable-field allow-lists — to Swift, C and C++ over a
  transport the caller supplies, so no integrator re-implements the sharp half from
  prose. Because that runtime never sees a broker URL, each of the three exposes the
  §8b transport guard — `amqps://` only, no loopback exception, no plaintext
  fallback, no verification-skip switch — as a public, tested function and calls it
  in its own example transport.
- **A release ships the surface it derives from the spec it vendors.** Tagging an
  SDK re-vendors the contract, the OpenAPI document and the management registry
  and then regenerates that SDK's §27 management surface from them, staging
  exactly what the generator wrote; a missing generator stops the release rather
  than tagging a tree the SDK's own drift-check would reject.

---

## Compliance posture

AXIAM keeps an internal compliance self-assessment mapping its controls to
recognised frameworks. This is a control-family self-assessment appropriate to a
beta-stage product — **not** a certified ISO 27001 ISMS audit or a formal Cyber
Resilience Act conformity assessment, and it says so plainly.

| Framework | Scope | Status | Evidence |
|---|---|---|---|
| **OWASP ASVS v4.0.3 Level 2** | 103 controls across authentication, session, access control, cryptography, error handling, data protection, communications, malicious code, configuration | 94 Pass, 4 N/A, 5 Deferred — **no Deferred item is High or Critical** | [ASVS L2 checklist](../docs/compliance/asvs-l2-checklist.md) |
| **ISO/IEC 27001:2022 Annex A** | Access control, secure authentication, cryptography, logging, network security, secure development | Interpretive control-family mapping; code-level themes Pass | [Annex A mapping](security-audit.md#3-iso-27001-annex-a--control-family-mapping) |
| **EU Cyber Resilience Act (Annex I)** | Secure-by-design, no known exploitable vulnerabilities, confidentiality, data minimisation, access control, vulnerability handling, security updates | Themes Pass; SBOM deferred | [Essential-requirement mapping](security-audit.md#4-cybersecurity-act--essential-requirement-theme-mapping) |
| **GDPR** | Data-subject export (Art. 15) and erasure (Art. 17), pseudonymisation, data minimisation | Export excludes secrets; erasure is durable and re-selectable on failure; audit actor identities are pseudonymised | [GDPR compliance](../docs/compliance/gdpr-compliance.md) |
| **OAuth2 / OIDC** | RFC 6749 / 7636 / 7009 / 7662 + OIDC Core/Discovery MUST matrices | All tracked MUSTs pass; dedicated conformance suites | [OAuth2 RFC matrix](../docs/compliance/oauth2-rfc-compliance.md) · [OIDC conformance](../docs/compliance/oidc-conformance.md) |

Each matrix is checked in per control, with the test or source location that
satisfies it, so a status here can be read back to the line that earns it rather
than taken on trust.

Dependency and supply-chain security is gated in CI — `cargo audit`, `cargo deny`,
Trivy filesystem/config scans and `npm audit` at a high threshold, with Dependabot
across the workspace's ecosystems and each SDK repository, SHA-pinned GitHub
Actions, and signed release provenance — and the gate tells a registry outage
apart from a clean audit and fails on a suppression that no longer matches
anything, so it cannot quietly be told what to ignore.

---

## Shared responsibility

Some risks cannot be closed from inside the application. AXIAM records them openly
and tells you what to do about them. Treat the following as a deployment hardening
checklist — most of the threat model's open items live here.

**The open risk register**

Every threat the model does not record as mitigated, most severe first — 17 of
236. On the website this table is generated from the Threat Dragon model, so it
cannot fall behind the diagrams; the full text of each entry, with the element it
sits on, is in [§6 of the STRIDE model](threat-model-stride.md#6-open-risk-register),
which also groups them by who owns them and carries the review history behind
each.

| Threat | Severity | Where it sits |
|---|---|---|
| T-148 — Compromised release pipeline publishes a backdoored SDK | Critical | Public package registries · *Client SDKs & admin UI integration surface* |
| T-18 — Backup or snapshot exfiltration | High | SurrealDB cluster (all tenant data) · *System diagram* |
| T-94 — Key extracted from device firmware or flash | High | IoT device · *PKI, certificates & IoT device identity* |
| T-124 — Operator credentials grant unaudited data access | High | Cluster operator / SRE · *Deployment & platform (Kubernetes)* |
| T-133 — Backup media accessible outside the cluster | High | Backups / volume snapshots · *Deployment & platform (Kubernetes)* |
| T-135 — Dependency-confusion or typosquatted SDK package | High | Integrator / developer · *Client SDKs & admin UI integration surface* |
| T-146 — Long-lived client secret committed to a repository | High | SDK configuration (client secrets, CA bundles) · *Client SDKs & admin UI integration surface* |
| T-180 — Vault concentrates every long-lived secret behind one credential | High | Secrets (Vault / K8s Secrets / ConfigMap) · *Deployment & platform (Kubernetes)* |
| T-216 — The unseal key sits on the same disk as the sealed data | High | Secrets (Vault / K8s Secrets / ConfigMap) · *Deployment & platform (Kubernetes)* |
| T-9 — Connection flood exhausts ingress capacity | Medium | Ingress / TLS 1.3 termination · *System diagram* |
| T-39 — Access token still valid after entitlement revocation | Medium | Token service EdDSA JWT + refresh rotation · *Authentication & session management* |
| T-110 — Personal data over-collected into an immutable log | Medium | Audit middleware & service · *Audit, webhooks, email & notifications* |
| T-123 — Final mail hop is not confidential | Medium | deliver mail · *Audit, webhooks, email & notifications* |
| T-134 — Backup stream unencrypted in transit | Medium | scheduled backup · *Deployment & platform (Kubernetes)* |
| T-143 — Local JWT verification misses a revoked entitlement | Medium | SDK token verification (JWKS cache, iss/aud) · *Client SDKs & admin UI integration surface* |
| T-161 — A partner's IdP silently populates the AXIAM user table (X4) | Low | Attribute mapping & JIT provisioning · *Federation — SAML SP & OIDC relying party* |

None of these is an unhandled defect in AXIAM's own request path: they are
accepted design trade-offs, responsibilities that land on whoever deploys AXIAM,
or gaps on the SDK and distribution side. The rest of this section is the same
list read as a checklist — what to do about each, grouped by who does it.

**Platform & operations**

- Apply the shipped NetworkPolicies (`k8s/network-policy/` — a namespace-wide
  default-deny on ingress *and* egress, plus the minimum allows a working
  deployment needs) and replace their two deliberate placeholders: the cluster
  pod/service CIDRs in the HTTPS egress exception, and the SMTP relay range, which
  ships as an unroutable value so mail egress is denied until you configure it.
  Keep the data tier off any public route, and check with `kubectl kustomize k8s/`
  that every policy is actually applied — the SurrealDB and RabbitMQ ingress
  policies once existed as files but were missing from the kustomization, which
  enforces nothing.
- Give RabbitMQ **per-service credentials** — the manifests now ship a dedicated
  `axiam` vhost as AXIAM's own authorization boundary and carry the AMQP URL in a
  Secret rather than the ConfigMap, where it previously sat without credentials at
  all; AXIAM verifies message signatures and refuses any non-TLS broker URL, but
  splitting one credential per
  service is still yours.
- **Run Vault in production mode, and treat its posture as your secret posture.**
  The production stacks default to Vault for every long-lived secret, which
  concentrates all of them behind one KV path: give AXIAM a token carrying the
  shipped policy and nothing more (`docker/vault/axiam-policy.hcl` — read on the
  startup path, writes confined to the CA-key prefix — applied with `just
  vault-policy` and checked with `just vault-status`), keep unseal keys and the
  root token offline, enable Vault's audit device, and never run a dev-mode (in-memory, unsealed) Vault in production. For
  deployments without Vault, the manifests' `file` provider mounts every
  cryptographic secret as a file — prefer it over `AXIAM_*` environment variables,
  since a signing key in a ConfigMap or plain env var is effectively public within
  the namespace. The datastore and broker credentials are still env-supplied
  (read before any secret provider exists), so enable etcd encryption at rest
  either way.
- **Encrypt backups and volume snapshots** with a key separate from the cluster,
  restrict snapshot IAM, and include backup media in the same access review as the
  live data tier — a snapshot carries the same data under weaker controls.
- Restrict `kubectl exec` and Secret-read RBAC and enable Kubernetes audit logging;
  **cluster-admin is equivalent to full AXIAM compromise** and is outside the
  application's audit trail.
- Add edge protection (WAF, connection limits, autoscaling) for volumetric floods,
  and wire monitoring to **`GET /health/jobs`**, which reports every background
  sweep's last success, last failure and a computed `stalled` flag — alert on
  `status == "degraded"` so a silently stopped GDPR-erasure or certificate-expiry
  sweep is noticed, not only one that errors.
- **Configure auto-unseal on Vault before you go live.** Without it every
  restart leaves Vault sealed and the server crash-looping until a human with
  enough shares arrives. A cloud KMS seal is the cheap answer; a transit seal
  against a Vault you already run elsewhere is the other. A script that unseals
  from shares kept on the same machine is not auto-unseal — it removes the seal
  rather than automating it.
- **Derive `AXIAM__RATE_LIMIT__TRUSTED_HOPS` for your own topology** — the
  number of proxies in front of the server *minus one*. Too high and too low
  both collapse every client into one rate-limit bucket, including on
  `/auth/login`, which is keyed per IP precisely so an attacker cannot lock a
  victim out. The shipped values are right for the shipped topologies and stop
  being right the moment you add a load balancer or a CDN.
- **Strip `X-Forwarded-For` and `X-Client-Certificate` at the edge**, and at
  the firewall on any route that reaches the server without a proxy. Leave
  `AXIAM__AUTH__TRUST_FORWARDED_CLIENT_CERT` off unless a proxy you run performs
  the mTLS handshake and overwrites that header on every request; devices that
  need real mTLS get a route the edge does not terminate.
- **Publish gRPC only through the edge, as an allowlist, or not at all.** A port
  forwarded straight at the listener lets a client mint its own rate-limit bucket
  per call, and no setting repairs that. If you enable the gRPC listener's TLS,
  point it at the *same* certificate and key the REST listener uses — there is no
  second certificate and there must not be — and your existing `SIGHUP` deploy
  hook renews both. A hook carrying the container restart earlier releases needed
  is now redundant; deleting it saves the downtime.
- **Run SurrealDB on a persistent storage engine — `surrealkv:` or `rocksdb:`,
  never `memory:`.** This is a correctness control, not a durability preference.
  AXIAM's three single-use credentials — UMA permission tickets, RFC 8628 device
  grants and RFC 9126 PAR `request_uri`s — are redeemed by a guarded `UPDATE`
  inside an explicit transaction, so a second concurrent redemption is a
  write-write conflict the engine must abort. Measured
  (`tools/surreal-race-probe`), `surrealkv` and `rocksdb` abort every one; the
  in-memory engine arbitrates at the same rate and then silently misses,
  admitting two winners in roughly 1% of contended rounds. A double redemption
  there yields two RPTs from one authorization decision, two token sets from one
  user approval, or a replayable authorization request
  ([ilpanich/axiam#302](https://github.com/ilpanich/axiam/issues/302)). The
  shipped compose files and k8s StatefulSet already pin `surrealkv:`; **the
  server cannot verify this for you** — SurrealDB exposes no datastore identity
  over the wire, so `axiam-server` logs a startup WARN that the engine could not
  be attested and the requirement lands here. A per-attempt redemption nonce,
  read back after the transaction commits, is the second layer that catches a
  missed conflict, so this is a defence-in-depth requirement rather than a
  single point of failure — but do not spend the second layer to save the first.

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
- **Audit records cannot be erased on demand, only aged out** — append-only by
  design, which is in tension with GDPR Art. 17; erasure anonymises the subject
  instead. Retention defaults to a 730-day pruning window applied by the
  background sweep; tune it (or disable with `0`) to match your lawful basis.

> **Caution — this is beta software.** AXIAM is in active development and has not
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

Everything in this document was last re-derived from source at
**`1.0.0-beta11`** on 2026-09-04; the handoff block at the top of this file says
what that pass covered and what it changed. The website carries its own stamp,
from a single constant in `website/src/version.ts`, recording the release *its*
Security section was last re-derived against; it moves when that section does.

**Reporting a vulnerability.** If you find a security issue, please report it
privately to the maintainers rather than opening a public issue, and give us a
reasonable window to remediate before disclosure. Use
[GitHub's private advisory form](https://github.com/ilpanich/axiam/security/advisories/new);
[`SECURITY.md`](../SECURITY.md) sets out what to include, what to expect and the
disclosure window.

---

*References — [STRIDE threat model](threat-model-stride.md) · [security analysis](security-analysis-2026-08-02.md) · [compliance audit](security-audit.md) · [`sdks/CONTRACT.md`](../sdks/CONTRACT.md) · [`docs/compliance/`](../docs/compliance/) · [OWASP Threat Dragon](https://www.threatdragon.com)*
