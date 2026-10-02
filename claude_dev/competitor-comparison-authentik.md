# AXIAM vs Authentik — competitor comparison

> Baseline written 2026-10-02 against **authentik 2026.8.3** (latest release,
> 2026-09-17) and AXIAM `1.0.0-beta17`. Part of the competitor series with
> [`competitor-comparison-keycloak.md`](competitor-comparison-keycloak.md) and
> [`competitor-comparison-zitadel.md`](competitor-comparison-zitadel.md); kept
> current by the fortnightly release monitor (see §5).
>
> **Sourcing note.** Every claim about authentik cites its GitHub repository.
> `docs.goauthentik.io` is generated from `website/docs/` in that repository,
> so each `website/docs/…` link below is the source of the corresponding
> official documentation page. Claims about AXIAM cite this repository.

## 1. Overview

Authentik is a self-hosted identity provider whose centre of gravity is the
**human user in front of an application portfolio**. Its distinguishing ideas
are *flows and stages* (login, enrolment and recovery are visual pipelines of
configurable steps), a policy engine that runs **Python expressions** against
the flow context, and *outposts* that bring identity to applications which do
not speak modern protocols: a forward-auth reverse proxy, an LDAP server, a
RADIUS server and a remote-access gateway [A1][A2]. Its core is MIT-licensed,
with a separately licensed `authentik/enterprise/` tree [A3]. The stack is
Python/Django plus PostgreSQL; Redis was dropped in 2025.10 [A4], and 2026.8
rewrote the server entrypoint and proxy outpost from Go to Rust [A5].

AXIAM aims at a different centre of gravity: **services and devices asking
"may I?" at high rate**, with strict multi-tenant isolation, a hierarchical
RBAC engine exposed as a decision API over REST, gRPC and AMQP, and an
integrated PKI for mTLS fleets.

The thesis of this document follows from that contrast. Authentik is the
stronger product for *integrating heterogeneous human-facing applications*
(proxying, LDAP/RADIUS, a large integration catalogue, a visual flow designer,
and an OpenID certification AXIAM does not yet hold). AXIAM is stronger
wherever **isolation, authorization depth and high-assurance protocols**
matter: true multi-tenancy, deny-override RBAC with a decision endpoint,
FAPI 2.0, certificate-bound tokens, and an open-source mTLS/PKI story. The
gaps worth closing are therefore the ones that block AXIAM's own niche
(enterprise directory integration, SAML IdP, certification), not the ones that
would turn it into an application-portal product.

## 2. Feature comparison

| Capability | AXIAM | authentik 2026.8 | Source (authentik) |
|---|---|---|---|
| Multi-tenancy with data isolation | **Yes** — organizations → tenants, every entity tenant-scoped | Enterprise-only **alpha** ("Use at your own risk"); **removed** in the 2026.11 draft notes | [A6][A7] |
| RBAC model | Hierarchical resources, roles, groups, scopes; **deny-override** (`effect: deny`) | Allow-only permissions (global and per-object); access via policy bindings (any/all, negation) | [A8][A9] |
| Authorization decision API | **Yes** — single and batch checks over REST, gRPC, AMQP | None documented; decisions happen inside flows and application bindings | [A9] |
| Policy language | Declarative RBAC + Reactors (external AMQP actors in any SDK language) | Python expression policies, plus reputation, GeoIP, event-matcher, password policies | [A9][A10] |
| OAuth2: code + PKCE, client credentials, refresh | Yes | Yes | [A11] |
| Device authorization grant (RFC 8628) | Yes | Yes | [A11] |
| Token exchange (RFC 8693), delegation with `act` | Yes (delegation, opt-in impersonation, depth-capped chains) | Yes since 2026.8 (`actor_token` on-behalf-of) | [A5][A12] |
| Dynamic client registration (RFC 7591) | Yes | Yes since 2026.8 (no RFC 7592 management endpoints) | [A5][A13] |
| Client ID Metadata Document (CIMD) | **Yes** | No | — |
| PAR / JAR / FAPI 2.0 | **Yes** — FAPI 2.0 conformance runs published | Not documented | [A11] |
| DPoP | **Yes** — access tokens sender-constrained | Partial — binds ID tokens only; access tokens stay `Bearer` | [A14] |
| RP-initiated / back-channel logout | Yes | Yes | [A15] |
| Front-channel logout | No | Yes | [A15] |
| OpenID certification | Not yet (conformance suites run and published) | **OpenID Certified** for OP and logout profiles (2026.8) | [A5] |
| SAML 2.0 | Service provider only | IdP **and** SP; WS-Federation (enterprise) | [A5][A16] |
| SCIM 2.0 | Inbound endpoint (RFC 7643/7644) | Inbound SCIM source **and** outbound SCIM provider | [A17][A18] |
| LDAP / Kerberos as user source | No | Yes | [A16] |
| LDAP / RADIUS / proxy / RAC outposts | No | Yes (RADIUS EAP-TLS enterprise) | [A2] |
| MFA | TOTP, WebAuthn passkeys and security keys, attestation policy (FIDO MDS) | TOTP, WebAuthn (AAGUID allowlist via FIDO MDS), Duo, SMS, email OTP, recovery codes, device trust | [A19][A20] |
| Augmented PAKE (OPAQUE, RFC 9807) | **Yes** (opt-in per org/tenant) | No | — |
| X.509 / mTLS user and device authentication | **Yes**, open source, with an integrated per-org CA | mTLS stage, **enterprise-only**; no CA | [A21] |
| MCP authorization server profile | **Yes** (RFC 8414, 8707, 7591, CIMD, loopback clients) | No MCP-specific feature; third parties document it as an MCP AS | [A22] |
| Delegated agent identities | Service accounts + RFC 8693 delegation | "Agent accounts" (enterprise, 2026.8) | [A5] |
| Shared Signals Framework | No | Provider (enterprise) | [A3] |
| Abuse rate limits | **On by default**, posture presets | Reputation scoring (opt-in policy), OTP throttling; no global limiter documented | [A23] |
| gRPC / AMQP transports | **Yes** | No (REST + WebSocket to outposts) | [A2] |
| Official SDKs | 11 languages | Generated API clients | — |
| Licence | Apache-2.0, single tree | MIT core + enterprise licence | [A3] |

## 3. AXIAM gaps, by priority

Priority reflects AXIAM's positioning (machine/IoT-first, enterprise-grade),
not authentik's.

**P1 — close soon**

1. **OpenID certification.** Authentik became OpenID Certified in 2026.8 [A5];
   Keycloak lists FAPI 2.0 as "Passed" in its own specification table. AXIAM runs the suites
   (`docs/conformance/`, latest 2026-09-25: Basic OP 30/35, FAPI 2.0 34/37 and
   52/56) but holds no certificate. For buyers this is a checkbox that
   precedes any technical evaluation; the roadmap already carries X5/X7.
2. **SAML 2.0 identity provider.** AXIAM consumes SAML but cannot issue it
   (`crates/axiam-federation/src/saml.rs` is SP-only). Authentik, Keycloak and
   Zitadel all act as SAML IdPs; many enterprise SaaS products still require
   it.
3. **LDAP / Active Directory as a user source.** Authentik syncs LDAP
   (nested groups since 2026.8) and Kerberos [A5][A16]. Without it, AXIAM
   cannot sit in front of an existing corporate directory, which blocks most
   brownfield adoptions.

**P2 — valuable, not blocking**

4. **Outbound SCIM provisioning.** Authentik pushes users and groups to
   downstream applications [A18]; AXIAM only receives SCIM.
5. **Shared Signals Framework (CAEP/RISC).** Offered by authentik (enterprise)
   and Keycloak (experimental). It fits AXIAM's event story (webhooks, AMQP)
   and would let relying parties revoke sessions in near real time.
6. **RADIUS interface.** Relevant to AXIAM's IoT and network-device audience;
   authentik ships it as an outpost [A2].

**P3 — watch, do not chase**

7. **Identity-aware reverse proxy / forward auth** and **remote-access (RAC)**
   outposts [A2]: portal features outside AXIAM's API-first scope.
8. **Front-channel logout** [A15]: browser-iframe based and increasingly
   unreliable under third-party-cookie restrictions; back-channel logout,
   which AXIAM has, is the robust variant.
9. **Visual flow designer**: AXIAM's extension point is Reactors; a designer
   is a UX investment, not a capability gap.
10. **Privileged-access requests and offboarding workflows** (enterprise,
    2026.8) [A5]: governance features adjacent to, not part of, IAM core.

## 4. AXIAM advantages

1. **Multi-tenancy is a foundation, not an add-on.** Every AXIAM entity is
   tenant-scoped under an organization. Authentik's tenants were an
   enterprise-only alpha and are slated for removal in 2026.11 [A6][A7];
   operators who need isolation will have to run one authentik instance per
   tenant. This is now AXIAM's clearest differentiator against authentik.
2. **Authorization as a product.** Hierarchical RBAC with explicit deny that
   overrides every allow (`claude_dev/deny-override-design.md`), scopes, UMA
   2.0, and a decision endpoint with batch semantics on REST, gRPC and AMQP.
   Authentik's permissions are allow-only and its policy engine answers
   "may this user pass this flow or open this app", not "may this subject do
   this action on this resource" [A8][A9].
3. **High-assurance OAuth profile.** PAR, JAR, DPoP-bound access tokens,
   private_key_jwt and mTLS client authentication, with FAPI 2.0 conformance
   runs in `docs/conformance/`. Authentik documents none of PAR, JAR or FAPI,
   and its DPoP support binds ID tokens only [A14].
4. **Certificates for people, services and devices, open source.** An
   integrated per-organization CA (`crates/axiam-pki/`), certificate issuance
   per tenant, and in-process mTLS. Authentik's mTLS stage is enterprise-only
   and relies on externally managed CAs [A21].
5. **Agent and MCP readiness.** AXIAM implements the MCP authorization profile
   end to end, including CIMD and RFC 8707 resource indicators
   (`claude_dev/mcp-authorization-server-plan.md`). Authentik has the building
   blocks (DCR, token exchange) but no CIMD and no MCP-specific support [A22].
6. **Machine-grade transports and SDKs.** gRPC and AMQP alongside REST, eleven
   SDKs sharing one contract (`sdks/CONTRACT.md`).
7. **Safer defaults.** Rate limits on by default with deployment presets
   (`crates/axiam-api-rest/src/config/rate_limit.rs`), OPAQUE as an option,
   Argon2id, EdDSA short-lived tokens, append-only audit.
8. **One licence.** Everything AXIAM ships is Apache-2.0; with authentik,
   several security-relevant features (mTLS, RADIUS EAP-TLS, account lockdown,
   password history, SSF) sit behind the enterprise licence [A3].

No performance claim is made here: authentik has not been benchmarked with
`benchmarks/`, and its 2026.8 move to Rust entrypoints makes older intuitions
unreliable. Adding it as a benchmark target is the honest way to settle that.

## 5. Change log

| Date | Change | Sources |
|---|---|---|
| 2026-10-02 | Baseline written. Recent authentik changes already folded in: 2026.8 adds token exchange with on-behalf-of, DCR, OpenID certification, agent accounts (enterprise) and the Rust server; the 2026.11 draft removes multi-tenancy. | [A5][A7] |

## Sources

All authentik links point at `github.com/goauthentik/authentik` (branch `main`
unless stated); `website/docs/X` is published as `docs.goauthentik.io/X`.

- [A1] Flows and stages — <https://github.com/goauthentik/authentik/tree/main/website/docs/add-secure-apps/flows-stages>
- [A2] Outposts — <https://github.com/goauthentik/authentik/blob/main/website/docs/add-secure-apps/outposts/index.mdx>
- [A3] Licence and enterprise features — <https://github.com/goauthentik/authentik/blob/main/LICENSE>, <https://github.com/goauthentik/authentik/blob/main/website/docs/enterprise/enterprise-features.mdx>
- [A4] 2025.10 release notes ("authentik no longer uses Redis at all") — <https://github.com/goauthentik/authentik/blob/main/website/docs/releases/2025/v2025.10.mdx>
- [A5] 2026.8 release notes — <https://github.com/goauthentik/authentik/blob/main/website/docs/releases/2026/v2026.8.mdx>; release tag — <https://github.com/goauthentik/authentik/releases/tag/version%2F2026.8.0>
- [A6] Tenancy (enterprise, alpha) — <https://github.com/goauthentik/authentik/blob/version-2026.8/website/docs/sys-mgmt/tenancy.mdx>
- [A7] 2026.11 release notes, draft ("Multi-tenancy (an alpha feature) has been removed.") — <https://github.com/goauthentik/authentik/blob/main/website/docs/releases/2026/v2026.11.mdx>
- [A8] Permissions — <https://github.com/goauthentik/authentik/blob/main/website/docs/users-sources/access-control/permissions.mdx>
- [A9] Policies — <https://github.com/goauthentik/authentik/blob/main/website/docs/customize/policies/index.mdx>
- [A10] Policy types — <https://github.com/goauthentik/authentik/tree/main/website/docs/customize/policies/types>
- [A11] OAuth2 provider — <https://github.com/goauthentik/authentik/blob/main/website/docs/add-secure-apps/providers/oauth2/index.mdx>
- [A12] Token exchange — <https://github.com/goauthentik/authentik/blob/main/website/docs/add-secure-apps/providers/oauth2/token_exchange.mdx>
- [A13] Dynamic client registration — <https://github.com/goauthentik/authentik/blob/main/website/docs/add-secure-apps/providers/oauth2/dynamic-client-registration.mdx>
- [A14] OIDC key binding — <https://github.com/goauthentik/authentik/blob/main/website/docs/add-secure-apps/providers/oauth2/key-binding.mdx>
- [A15] Front- and back-channel logout — <https://github.com/goauthentik/authentik/blob/main/website/docs/add-secure-apps/providers/oauth2/frontchannel_and_backchannel_logout.mdx>
- [A16] Sources (SAML, LDAP, Kerberos) — <https://github.com/goauthentik/authentik/tree/main/website/docs/users-sources/sources/protocols>
- [A17] SCIM source (inbound) — <https://github.com/goauthentik/authentik/blob/main/website/docs/users-sources/sources/protocols/scim/index.mdx>
- [A18] SCIM provider (outbound) — <https://github.com/goauthentik/authentik/blob/main/website/docs/add-secure-apps/providers/scim/index.mdx>
- [A19] WebAuthn authenticator stage — <https://github.com/goauthentik/authentik/blob/main/website/docs/add-secure-apps/flows-stages/stages/authenticator_webauthn/index.mdx>
- [A20] Stages — <https://github.com/goauthentik/authentik/tree/main/website/docs/add-secure-apps/flows-stages/stages>
- [A21] mTLS stage (enterprise) — <https://github.com/goauthentik/authentik/blob/main/website/docs/add-secure-apps/flows-stages/stages/mtls/index.mdx>
- [A22] Third-party MCP integration (agentgateway, not authentik) — <https://agentgateway.dev/docs/kubernetes/main/mcp/auth/authentik/>
- [A23] Reputation policy and settings — <https://github.com/goauthentik/authentik/blob/main/website/docs/customize/policies/types/reputation.mdx>, <https://github.com/goauthentik/authentik/blob/main/website/docs/sys-mgmt/settings.mdx>
