# AXIAM vs Keycloak — competitor comparison

> Baseline written 2026-10-02 against **Keycloak 26.8.0** (released
> 2026-10-01) and AXIAM `1.0.0-beta17`. Part of the competitor series with
> [`competitor-comparison-zitadel.md`](competitor-comparison-zitadel.md) and
> [`competitor-comparison-authentik.md`](competitor-comparison-authentik.md).
> It consolidates, and supersedes as the living reference, the Keycloak
> rationale scattered through Track B of
> [`improvement-after-run5-benchmark.md`](improvement-after-run5-benchmark.md)
> and [`extra-B-track-features.md`](extra-B-track-features.md).
>
> **Sourcing note.** Claims about Keycloak cite its GitHub repository pinned at
> tag `26.8.0`; the documentation on keycloak.org is built from the `docs/`
> tree linked below. Feature maturity comes from `Profile.java` (the server's
> own feature registry) and the specification table. Performance figures come
> from this repository's run-5 benchmark, which measured Keycloak 26.7.0.
> **Run 6 is the re-measurement:** it measures Keycloak 26.8.0, Zitadel
> v4.19.4 and authentik 2026.8.3 against AXIAM `1.0.0-beta18` on the same G-box
> with the run-5 caps (G-10; the authentik target now exists in
> `benchmarks/targets/authentik/`). Its numbers follow the run; until then every
> performance figure here is run 5's, taken against Keycloak 26.7.0.

## 1. Overview

Keycloak is the reference open-source IAM: Apache-2.0, Java on Quarkus, an
Infinispan cache layer and a choice of relational databases [K1][K2]. Its
strength is **breadth**. It implements nearly every relevant OAuth/OIDC
specification and marks FAPI 2.0 as passed [K3]. It brokers OIDC, SAML and
social identity providers, federates LDAP/AD and Kerberos, ships a full
Authorization Services engine with UMA 2.0, and can be extended through
Java SPIs [K4][K5].

AXIAM does not try to out-breadth Keycloak. Its claim is **efficiency and a
machine-first shape**. On identical hardware and caps, run 5 measured ~8× the
client-credentials throughput, 2.4× the introspection rate and a server RSS
under 8% of Keycloak's (`benchmarks/PUBLIC_BENCH_ANALYSIS.md` §1, §5, §10).
On top of that come authorization decisions as a first-class API, gRPC and
AMQP transports, deny-override RBAC, and safer defaults.

The comparison therefore turns on one question: how much of Keycloak's breadth
does a service/IoT deployment actually need? The gaps below are ranked by that
question.

## 2. Feature comparison

| Capability | AXIAM | Keycloak 26.8 | Source (Keycloak) |
|---|---|---|---|
| Tenancy | Organizations → tenants, full data isolation | Realms are isolated; Organizations add "multi-tenancy within a realm" (supported) | [K6][K7] |
| RBAC | Hierarchical resources, roles, groups, scopes; **deny-override** | Realm/client roles, composite roles, hierarchical groups | [K8] |
| Explicit deny semantics | **Global deny-override** at any depth and at equal specificity | No global deny. NEGATIVE logic inverts a single policy; decision strategies are Unanimous (default), Affirmative or Consensus. Admin FGAP v2 prefers resource-specific permissions | [K9][K10][K11] |
| Fine-grained authorization / UMA 2.0 | Yes (UMA 2.0 mapped onto RBAC) | Yes — Authorization Services (supported, on by default), UMA 2.0 | [K3][K5] |
| Decision API for services | **REST, gRPC and AMQP, single and batch** | Authorization Services evaluation over HTTP; OpenID AuthZEN API **experimental** | [K3][K5] |
| Device grant, PAR, DPoP | Yes | Yes (all supported, on by default) | [K5] |
| CIBA | **Yes** (since G-7, Phase 23 W5): poll and ping, signed authentication requests and the FAPI-CIBA client. *Not done:* no push mode, no `user_code`; a federated account gets no approval mail (D-74) but finds its request in the console's pending list (1.0.0, #566); see item 6 below | Yes | [K5] |
| FAPI 2.0 | Conformance runs published, not yet certified | Security Profile and Message Signing marked "Passed" | [K3] |
| mTLS client auth, X.509 user auth | Yes, plus an **integrated per-org CA** | Yes (RFC 8705, X.509 authenticator); no built-in CA | [K3][K12] |
| WebAuthn / passkeys / OTP | Yes, with a FIDO MDS attestation policy | Yes (passkeys supported, HOTP and TOTP, recovery codes) | [K13] |
| OPAQUE (RFC 9807) | **Yes** (opt-in) | No | — |
| RP-initiated / back-channel logout | Yes | Yes | [K3] |
| Front-channel logout | No — declined by design (D-6); back-channel logout shipped | Yes | [K3] |
| Token exchange (RFC 8693) | Internal + external-IdP, delegation (`act`), opt-in impersonation | Standard v2 supported (internal-to-internal); **delegation preview in 26.8** | [K14][K15] |
| Dynamic client registration | Yes (RFC 7591 + RFC 7592) | Yes | [K16] |
| Client ID Metadata Document | **Yes** | Experimental | [K3] |
| MCP authorization server | **Yes**, end to end | Documentation for MCP integration; CIMD experimental | [K15] |
| SCIM 2.0 server | Yes; and, since G-6 (Phase 23, W5), an outbound SCIM client for downstream applications (*one delivery attempt at a time per replica; since #550 a per-target breaker stops calling a downstream after five consecutive failures until its backoff has passed, and more than one delivery in flight is deferred to 1.0.x*) | Yes — promoted to supported in 26.8 (the specification table still reads "Tech Preview") | [K3][K15] |
| SAML 2.0 | IdP (G-2, Phase 23) and SP | IdP and broker | [K3][K17] |
| LDAP/AD, Kerberos federation | LDAP/AD yes (G-3, Phase 23; read-only, JIT, group mapping, sync); Kerberos no (D-1) | Yes | [K18] |
| Social login | Google, GitHub, Microsoft, Apple, generic OIDC/OAuth2 | Large catalogue (Google, GitHub, Microsoft, LinkedIn, …) | [K17] |
| Verifiable credentials | No — design written, implementation gated on a go/no-go (G-9) | OID4VCI **preview**, OID4VP **experimental** (26.8) | [K15] |
| Shared Signals (CAEP/RISC) | Yes (G-5, Phase 23; transmitter, push and poll) | Experimental | [K15] |
| Extension model | **Reactors**: external AMQP actors in any SDK language; webhooks | In-process Java SPIs | [K4] |
| Brute-force / abuse protection | Rate limits **on by default**, posture presets | Brute-force detection **disabled by default** | [K19] |
| gRPC API | **Yes** (authz, userinfo data plane) | None found | [K5] |
| Async (AMQP) authz | **Yes** | No | — |
| Server RSS (run 5, 26.7.0; run 6 re-measures 26.8.0) | 88–119 MiB | 710–853 MiB | `benchmarks/PUBLIC_BENCH_ANALYSIS.md` §5 |
| Licence | Apache-2.0 | Apache-2.0 | [K1] |

## 3. AXIAM gaps, by priority

**P1 — close soon**

1. **SAML 2.0 identity provider.** Keycloak signs SAML for any service
   provider [K17]. Enterprise SaaS still depends on it, and AXIAM only
   consumes SAML. *Closed by G-2 (Phase 23, W4): AXIAM is a per-tenant SAML
   2.0 IdP with SSO, SLO and a signing credential from the tenant's own CA.*
2. **LDAP/AD and Kerberos federation.** This is the most common reason
   organizations pick Keycloak [K18]. *Closed for LDAP/AD by G-3 (Phase 23,
   2026-10-04, [remediation plan](competitor-gap-remediation-plan-2026-10-02.md));
   Kerberos (SPNEGO) remains declined for now (D-1).*
3. **Certification.** Keycloak lists FAPI 2.0 as passed [K3]. AXIAM's
   conformance runs (`docs/conformance/`, latest 2026-09-25) still show open
   modules. Closing them and submitting (roadmap X5/X7) turns an engineering
   fact into a procurement fact.

**P2 — valuable, not blocking**

4. **Verifiable credentials (OID4VCI/OID4VP).** These moved to preview and
   experimental in 26.8 [K15]. EU digital-identity wallets make this
   strategic for an IAM that names GDPR and the CyberSecurity Act among its
   targets. It is still early enough to design rather than chase.
   **Design written (2026-10-02, G-9):**
   [`verifiable-credentials-design.md`](verifiable-credentials-design.md) —
   verifier first, SD-JWT VC first, implementation gated on specification
   stability and one concrete adopter.
5. **Shared Signals Framework.** Keycloak has it as experimental [K15]. It
   would extend AXIAM's revocation story (webhooks, AMQP) to relying parties
   in a standard way. *Closed by G-5 (Phase 23, W4): AXIAM is an SSF 1.0
   transmitter (CAEP and RISC events, push and poll, contract §32).*
6. **CIBA** [K5]. It serves decoupled flows such as call-centre and payment
   approvals, and pairs naturally with FAPI. *Closed by G-7 (Phase 23, W5):
   AXIAM serves OpenID Connect CIBA Core 1.0 in poll and ping modes with the
   FAPI-CIBA signed-request profile; the user approves on the console after a
   full sign-in with step-up, and the limiter and the brute-force lockout both
   cover the grant (the class of defect in the 26.7.x CVEs); contract §33.*
   **What it does not do:** there is **no push mode** (poll and ping only; FAPI-CIBA
   forbids push, D-65) and **no `user_code`** (`user_code` is refused at
   registration and on the request, and discovery says
   `backchannel_user_code_parameter_supported: false`; a code checked against
   the password would be a password oracle, D-64). The approval e-mail goes only
   to an address D-25's rule vouches for (`email_verified_at` set, or the account
   `Active`), so **a federated account gets no approval mail** unless an address
   was verified: it stays `PendingVerification` for life (T-160). The request is
   still stored and answered as before, and the user finds it in the console: a
   badge on the user menu lists their pending requests (`GET /api/v1/ciba/requests`,
   1.0.0, #566; D-74). The user is told by
   e-mail only, with no phone push channel
   (`crates/axiam-oauth2/src/ciba.rs`, `ciba_notifier.rs`, `oidc.rs`).

**P3 — watch**

7. **Front-channel logout** [K3] — **declined (recorded 2026-10-02).** It is
   fragile under third-party-cookie restrictions, and back-channel logout
   covers the robust case. See [design-document.md §4.5](design-document.md#front-channel-logout--declined-d-6-2026-10-02) and the [remediation plan G-12](competitor-gap-remediation-plan-2026-10-02.md).
8. **Social-provider breadth** [K17]. Generic OIDC covers most providers.
   Adding named presets is cheap when users ask for them.
9. **Admin-console breadth and theming.** This is a maturity gap, not a
   capability gap.

**Closed since Track B was written.** Deny-override (B1), device grant (B2),
token exchange (B3), SCIM (B4), the logout and PAR triad (B5), UMA 2.0 (X2),
WebAuthn attestation policy (X3) and external-IdP token exchange (X4) have
all shipped. They now appear in §2 as parity or advantage.

## 4. AXIAM advantages

1. **Efficiency is the product.** Run 5 measured about 8× the tokens/s, 2.4×
   the introspection rate and 6–13× the JWKS reads, in under 8% of Keycloak's
   server memory (`benchmarks/PUBLIC_BENCH_ANALYSIS.md` §1, §5). For
   infrastructure that sits in front of every request, that is a cost and
   latency floor, not a vanity number. Keycloak 26.8 reports reduced memory
   usage [K15], so the figure is re-measured rather than assumed: run 6
   measures Keycloak 26.8.0 against AXIAM `1.0.0-beta18` on the same G-box with
   the run-5 caps. Until its numbers land, this paragraph is run 5's.
2. **Deny that means deny.** AXIAM's explicit deny overrides every allow at any
   depth (`claude_dev/deny-override-design.md`). Keycloak instead combines
   per-policy NEGATIVE logic with per-permission decision strategies, and its
   admin FGAP v2 prefers the most specific permission [K9][K10][K11]. That is
   expressive, but harder to audit, which is exactly the property a security
   reviewer cares about.
3. **Authorization as a data plane.** Single and batch checks run over REST,
   gRPC and AMQP, with a 12 000+/s gRPC userinfo path. Keycloak's evaluation
   API is HTTP-only, and AuthZEN is still experimental [K3].
4. **Safe by default.** Rate limits ship enabled, while Keycloak's brute-force
   detection is disabled by default [K19]. The 26.7.x patch series fixed
   about 56 CVEs, including brute-force lockout not applying to the CIBA and
   device grants [K20]. That is a reminder that breadth multiplies attack
   surface.
5. **Integrated PKI and OPAQUE.** AXIAM includes a per-organization CA,
   certificate issuance for users, services and devices, and in-process mTLS
   (`crates/axiam-pki/`). OPAQUE is available as an option. Keycloak
   validates certificates but issues none.
6. **Extensions outside the security kernel.** Reactors run as external
   processes in any SDK language. Keycloak SPIs load third-party JARs into
   the server JVM [K4].
7. **MCP-ready today.** CIMD, RFC 8707 and loopback public clients are
   implemented and tested (`claude_dev/mcp-authorization-server-plan.md`).
   Keycloak's CIMD is experimental [K3].

## 5. Change log

| Date | Change | Sources |
|---|---|---|
| 2026-10-10 | CIBA limit restated (1.0.0, #566, documentation only): a federated account, which D-74 sends no approval mail, can now approve a request, because the console lists the signed-in user's own pending requests (`GET /api/v1/ciba/requests?status=pending`, a badge on the user menu); the "waits on a page nobody can reach" statement in the CIBA row and item 6 is withdrawn. The compared Keycloak surface is unchanged. | — |
| 2026-10-09 | Outbound SCIM limit restated (1.0.0, #550, documentation only): the per-target breaker shipped — a target with five consecutive failures is not called again until its backoff has passed — so an unresponsive downstream no longer holds a replica's other targets back for every queued reference; more than one delivery in flight per replica is deferred to 1.0.x. | — |
| 2026-10-06 | W6 comparison refresh (G-10, G-11). **G-10 (benchmark currency)**: the run-5 figures stay as they are, because they are still run 5's against Keycloak 26.7.0; the header, the RSS row and §4 item 1 now say that run 6 re-measures Keycloak 26.8.0, Zitadel v4.19.4 and authentik 2026.8.3 against AXIAM `1.0.0-beta18` on the same G-box with the run-5 caps, and that numbers follow. **G-11 (RADIUS)**: decided (D-77) to decline a native RADIUS front end for now; Keycloak has no RADIUS in the product (a community extension only), so no row here changes, and AXIAM publishes no CRL today (T-102 reopened), see [the record](radius-eap-tls-spike-2026-10-06.md). **Not-do statements:** CIBA has no push mode and no `user_code`, and a federated account gets no approval mail (D-74); outbound SCIM delivers one attempt at a time per replica, so a slow downstream can stall that replica's provisioning until #550 (P23W5-07) is decided. | [K5][K15] |
| 2026-10-05 | G-7 (CIBA) complete on the Phase 23 W5 branch: `POST /oauth2/bc-authorize` and the CIBA grant at the token endpoint, poll and ping modes (no push), `login_hint` and `id_token_hint`, signed authentication requests and the FAPI-CIBA client, user approval on the console after a full sign-in with step-up, an approval e-mail, rate-limit and lockout coverage of the grant (the Keycloak 26.7.x CVE class: tested), contract §33 and the website page; the row's AXIAM cell flips from No to Yes and the P2 gap item is closed. The compared Keycloak surface is unchanged. | [K5][K20] |
| 2026-10-05 | G-6 (outbound SCIM provisioning) complete on the Phase 23 W5 branch: AXIAM can push a tenant's users and groups to downstream SCIM 2.0 service providers (contract §31). The compared Keycloak surface is the SCIM *server*, so the row's Keycloak cell is unchanged; AXIAM's cell now also names the outbound client. | — |
| 2026-10-04 | G-2 (SAML 2.0 identity provider) complete on the Phase 23 W4 branch: per-tenant IdP with SP- and IdP-initiated Web Browser SSO over HTTP-Redirect and HTTP-POST, always-signed assertions under a tenant credential issued by the tenant's own CA (issue / promote / retire), a pairwise persistent `NameID` by default, per-SP `SessionIndex` and single logout tied to session revocation and the revocation feed, IdP metadata, SP metadata import as a reviewed draft, the SP registry API (contract §29) and console page; round-tripped with samael as a reference SP and with a real Keycloak 26.7.0 brokering to AXIAM. Assertion encryption and the artifact binding stay out (D-2). | — |
| 2026-10-04 | G-5 (Shared Signals Framework transmitter) complete on the Phase 23 W4 branch: SSF 1.0 with CAEP `session-revoked`, `credential-change`, `assurance-level-change` and RISC `account-disabled` / `account-enabled` / `account-purged` as EdDSA-signed SETs, push (RFC 8935) through the outbound address guard and poll (RFC 8936), the receiver's stream management API under an `ssf.manage` client credential, discovery, administrator-registered streams (contract §32). The optional SDK receiver helper follows the merge (D-35). | — |
| 2026-10-04 | G-3 (LDAP / Active Directory identity source) complete on the Phase 23 W3 branch: bind-as-user over mandatory TLS, JIT provisioning, explicit group mapping with nesting, incremental and nightly sync with soft-delete, the address guard, the management API (contract §30) and the console page; tested against a real OpenLDAP and a real Samba AD DC. Kerberos stays out of scope (D-1), so the row reads LDAP/AD yes, Kerberos no. | — |
| 2026-10-02 | Baseline written. Since the run-5 baseline (26.7.0): SCIM promoted to supported, so the Track B premise "Keycloak only via extensions" is obsolete and SCIM is now parity. Token-exchange delegation is preview, and impersonation tokens carry `act`. OID4VCI is preview and OID4VP experimental. Stateless multi-cluster is supported. Login failures are persisted by default. 26.7.1–26.7.5 shipped about 56 CVE fixes. | [K15][K20] |
| 2026-10-03 | G-9: verifiable-credentials design written (design only, go/no-go in its §13); the row and P2 item 4 point at it. G-4: RFC 7592 shipped on the Phase 23 W1 branch, so the dynamic-registration cell names both RFCs. | — |
| 2026-10-02 | G-12 (front-channel logout) declined and recorded in the design document (D-6); row and gap list updated. Revisit only on an adopter request. | — |

## Sources

Pinned to tag `26.8.0` of `github.com/keycloak/keycloak` unless stated.
`K-SA` = `docs/documentation/server_admin/topics/`.

- [K1] Licence — <https://github.com/keycloak/keycloak/blob/26.8.0/LICENSE.txt>
- [K2] Quarkus runtime, caching, databases — <https://github.com/keycloak/keycloak/blob/26.8.0/quarkus/README.md>, <https://github.com/keycloak/keycloak/blob/26.8.0/docs/guides/server/caching.adoc>, <https://github.com/keycloak/keycloak/blob/26.8.0/docs/guides/server/db.adoc>
- [K3] Supported specifications — <https://github.com/keycloak/keycloak/blob/26.8.0/docs/guides/securing-apps/specifications.adoc>
- [K4] Service Provider Interfaces — <https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/server_development/topics/providers.adoc>
- [K5] Feature registry and maturity (`Profile.java`) — <https://github.com/keycloak/keycloak/blob/26.8.0/common/src/main/java/org/keycloak/common/Profile.java>
- [K6] Realms — <https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/server_admin/topics/realms.adoc>
- [K7] Organizations — <https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/server_admin/topics/organizations/intro.adoc>
- [K8] Roles and groups — <https://github.com/keycloak/keycloak/tree/26.8.0/docs/documentation/server_admin/topics/roles-groups>
- [K9] Decision strategies — <https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/authorization_services/topics/permission-decision-strategy.adoc>
- [K10] Policy logic (positive/negative) — <https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/authorization_services/topics/policy-logic.adoc>
- [K11] Fine-grained admin permissions v2 — <https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/server_admin/topics/admin-console-permissions/fine-grain-v2.adoc>
- [K12] X.509 user authentication — <https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/server_admin/topics/authentication/x509.adoc>
- [K13] WebAuthn, passkeys, OTP — <https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/server_admin/topics/authentication/webauthn.adoc>, <https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/server_admin/topics/authentication/passkeys.adoc>, <https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/server_admin/topics/authentication/otp-policies.adoc>
- [K14] Token exchange — <https://github.com/keycloak/keycloak/blob/26.8.0/docs/guides/securing-apps/token-exchange.adoc>
- [K15] 26.8.0 release notes — <https://github.com/keycloak/keycloak/releases/tag/26.8.0>
- [K16] Client registration — <https://github.com/keycloak/keycloak/blob/26.8.0/docs/guides/securing-apps/client-registration.adoc>
- [K17] SAML and identity brokering — <https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/server_admin/topics/sso-protocols/con-saml.adoc>, <https://github.com/keycloak/keycloak/tree/26.8.0/docs/documentation/server_admin/topics/identity-broker>
- [K18] LDAP/AD and Kerberos — <https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/server_admin/topics/user-federation/ldap.adoc>, <https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/server_admin/topics/authentication/kerberos.adoc>
- [K19] Brute force detection ("disabled by default") — <https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/server_admin/topics/threat/brute-force.adoc>
- [K20] 26.7.x security releases — <https://github.com/keycloak/keycloak/releases/tag/26.7.1>, <https://github.com/keycloak/keycloak/releases/tag/26.7.2>, <https://github.com/keycloak/keycloak/releases/tag/26.7.3>, <https://github.com/keycloak/keycloak/releases/tag/26.7.4>, <https://github.com/keycloak/keycloak/releases/tag/26.7.5>
