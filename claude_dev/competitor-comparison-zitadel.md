# AXIAM vs Zitadel — competitor comparison

> Baseline written 2026-10-02 against **Zitadel v4.19.4** (released
> 2026-10-01) and AXIAM `1.0.0-beta17`. Part of the competitor series with
> [`competitor-comparison-keycloak.md`](competitor-comparison-keycloak.md) and
> [`competitor-comparison-authentik.md`](competitor-comparison-authentik.md).
> It consolidates the Zitadel rationale from Track B of
> [`improvement-after-run5-benchmark.md`](improvement-after-run5-benchmark.md)
> and [`extra-B-track-features.md`](extra-B-track-features.md).
>
> **Sourcing note.** Claims about Zitadel cite `github.com/zitadel/zitadel`:
> release pages, protobuf definitions, `cmd/defaults.yaml` and the
> documentation sources under `apps/docs/content/`, which zitadel.com/docs is
> built from. Performance figures come from this repository's run-5
> benchmark, which measured Zitadel v4.16.2.

## 1. Overview

Zitadel is the closest competitor to AXIAM in spirit. It is a modern,
API-first IAM written in Go, multi-tenant by design (instances contain
organizations, and projects are granted across organizations for B2B
delegation) and event-sourced, so every mutation is an immutable event and the
audit trail is a by-product of storage [Z1][Z2][Z3]. Since v3 it runs on
PostgreSQL only and is licensed under AGPL-3.0 [Z4]. A cloud offering is
advertised in its README [Z1].

The two products overlap on tenancy, API-first design and a strong audit
story. They diverge on **authorization depth and protocol assurance**.
Zitadel's role model is grant-only: it has no explicit deny and no
permission-check API, so roles reach applications as token claims and each
application decides for itself [Z5]. Zitadel also lacks PAR, DPoP and mTLS
client authentication, all of which are still open issues [Z6]. Those are the
exact areas where AXIAM invests. Zitadel, in turn, is ahead on SAML IdP
support, LDAP as an external IdP and the polish of a mature hosted product.

## 2. Feature comparison

| Capability | AXIAM | Zitadel v4.19 | Source (Zitadel) |
|---|---|---|---|
| Multi-tenancy | Organizations → tenants, full data isolation | Instances → organizations; project grants for B2B self-service | [Z2] |
| RBAC | Hierarchical resources, roles, groups, scopes, **deny-override** | Project roles and role assignments (grants); **no explicit deny** | [Z5] |
| Authorization decision API | **REST, gRPC, AMQP; single and batch** | **None**: roles are delivered as token claims | [Z5] |
| Audit trail | Append-only audit; OpenPGP keys for audit signing (`crates/axiam-pki/src/pgp.rs`) | Event-sourced store; audit retention can be unlimited | [Z3] |
| Device grant | Yes | Yes | [Z7] |
| Token exchange (RFC 8693) | Delegation (`act`), opt-in impersonation, external-IdP exchange | Supported and on by default; impersonation via `actor_token` | [Z7][Z8] |
| Dynamic client registration | RFC 7591 + RFC 7592 (Phase 23 W1, T23.4.1) | RFC 7591 + RFC 7592 (since v4.17.0) | [Z9] |
| Client ID Metadata Document | **Yes** | Not released (pull request open) | [Z10] |
| PAR | **Yes** | No (issue #10239 open) | [Z6] |
| DPoP | **Yes** | No (issue #5402 open since 2023) | [Z6] |
| mTLS client auth (RFC 8705), X.509 users/devices | **Yes**, with an integrated per-org CA | No (issue #8597 open) | [Z6] |
| private_key_jwt / JWT profile | Yes | Yes | [Z11] |
| FAPI 2.0 | Conformance runs published | Not possible without PAR, DPoP or mTLS | [Z6] |
| Passkeys / WebAuthn, TOTP, OTP SMS/email | Passkeys, security keys, TOTP; FIDO MDS attestation policy | Passkeys, U2F, TOTP, OTP SMS and email | [Z12] |
| OPAQUE (RFC 9807) | **Yes** (opt-in) | No | — |
| RP-initiated / back-channel logout | Yes | Yes | [Z7][Z13] |
| SAML 2.0 | SP only | **IdP** (and SAML external IdPs) | [Z14][Z15] |
| External IdPs | OIDC, OAuth2, SAML, Google, GitHub, Microsoft, Apple | OIDC, OAuth2, JWT, SAML, **LDAP**, Azure AD, GitHub, GitLab, Google, Apple, Zitadel | [Z15] |
| SCIM 2.0 server | Yes (users and groups) | **Preview**; users documented | [Z16] |
| Extension model | Reactors (external AMQP actors, any SDK language), HMAC-signed webhooks | Actions v2: signed webhook/call targets on request, response, function and event | [Z17] |
| APIs | REST, gRPC, AMQP | gRPC, connectRPC and REST for every resource (management-oriented) | [Z1] |
| Rate limiting | **On by default**, posture presets | No built-in limiter; lockout off by default (`MaxPasswordAttempts: 0`) | [Z18] |
| Server RSS (run 5, v4.16.2) | 88–119 MiB | 138–154 MiB | `benchmarks/PUBLIC_BENCH_ANALYSIS.md` §5 |
| Whole-stack RSS (run 5) | 375–533 MiB (server + SurrealDB + RabbitMQ) | 281–457 MiB (server + PostgreSQL) | idem |
| Licence | Apache-2.0 | AGPL-3.0 (since v3) | [Z4] |

## 3. AXIAM gaps, by priority

**P1 — close soon**

1. **SAML 2.0 identity provider.** Zitadel serves `/saml/v2/SSO` and its
   metadata [Z14]. Keycloak and Authentik also act as SAML IdPs. AXIAM is
   the only one of the four that cannot.
2. **LDAP as an identity source.** Zitadel offers LDAP among its external
   IdP types [Z15]. This gap is shared with the Keycloak comparison and has
   the same consequence: AXIAM cannot sit in front of an existing directory.

**P2 — valuable, not blocking**

3. **Resting footprint of the whole stack.** AXIAM's server is lighter, but
   its whole stack (SurrealDB and RabbitMQ) idles above Zitadel's server plus
   PostgreSQL (`benchmarks/PUBLIC_BENCH_ANALYSIS.md` §5, §10). A documented
   "AMQP-less" profile, or a smaller broker footprint, would remove the one
   efficiency cell Zitadel wins.
4. **RFC 7592 client management** — **closed (2026-10-03, G-4).** Zitadel
   added it next to RFC 7591 in v4.17.0 [Z9]. AXIAM now serves `GET`/`PUT`/`DELETE
   /oauth2/register/{client_id}` behind a per-client registration access
   token ([`docs/admin/dynamic-client-registration.md`](../docs/admin/dynamic-client-registration.md),
   contract §28.12). The row in §2 is now parity.
5. **Hosted offering and operational maturity.** Zitadel sells a managed
   cloud [Z1]. This is a go-to-market gap rather than an engineering one,
   but buyers weigh it.

**P3 — watch**

6. **`zitadel/nextgen`.** This is a public AGPL repository that rebuilds the
   storage core and API surface "for developers and AI agents alike". It
   ships an agent-friendly CLI and `/mcp` documentation endpoints, and is
   intended to become the next major version [Z19]. It is not released yet.
   Watch it for an agent-identity story that could compete with AXIAM's MCP
   positioning. AXIAM's own story is now written down: [*Identity for
   agents*](../docs/guides/identity-for-agents.md) (G-15, 2026-10-02).

## 4. AXIAM advantages

1. **Authorization depth.** AXIAM has hierarchical resources, scopes, UMA 2.0
   and an explicit deny that overrides every allow. Decisions are served
   over REST, gRPC and AMQP, with batch semantics. Zitadel issues role
   claims and stops there: it has no deny and no check API [Z5]. For
   microservices and IoT this is the decisive difference, because every
   service would otherwise re-implement policy evaluation.
2. **High-assurance OAuth.** AXIAM supports PAR, DPoP, mTLS client
   authentication and certificate-bound tokens, with FAPI 2.0 conformance
   runs published in `docs/conformance/`. None of the three building blocks
   is available in Zitadel [Z6].
3. **Certificates and IoT.** AXIAM includes a per-organization CA,
   per-tenant issuance and in-process mTLS for devices (`crates/axiam-pki/`).
   Zitadel has no certificate-based client or user authentication [Z6].
4. **Data-plane performance.** Run 5 measured about 6.5× Zitadel's
   client-credentials throughput and 4.8× its introspection rate. AXIAM's
   gRPC userinfo served 12 307/s, against Zitadel's 191–201/s on its own
   gRPC surface (`benchmarks/PUBLIC_BENCH_ANALYSIS.md` §1). Zitadel's gRPC
   is a management API; AXIAM's is a data plane.
5. **Safe defaults.** AXIAM enables rate limiting by default. Zitadel ships
   no limiter and leaves lockout disabled (`MaxPasswordAttempts: 0`) [Z18].
   Zitadel's 4.16–4.19 line also fixed several critical account-takeover
   advisories, including passkey enrollment, IdP linking and SAML IdP
   confusion [Z20].
6. **MCP readiness.** AXIAM implements CIMD and RFC 8707 resource indicators
   today (`claude_dev/mcp-authorization-server-plan.md`). Zitadel's CIMD
   pull request is still under SSRF review [Z10].
7. **Permissive licence.** AXIAM's Apache-2.0 lets vendors embed or modify
   it without AGPL network-copyleft obligations [Z4]. That matters to device
   makers and to anyone offering AXIAM as part of a hosted product.

## 5. Change log

| Date | Change | Sources |
|---|---|---|
| 2026-10-02 | Baseline written. Since the run-5 baseline (v4.16.2): v4.17.0 added RFC 7591/7592 dynamic client registration, "Sign in with Zitadel" and native app links for passkeys. v4.17.2 fixed token-exchange downscoping. v4.18.0 was withdrawn ("skip this release"). v4.19.2 made session-cookie signing mandatory (breaking change). Several critical and high advisories were fixed. The CIMD pull request is still open. `zitadel/nextgen` appeared as the preview of the next major version. | [Z9][Z10][Z19][Z20] |
| 2026-10-03 | G-4 (RFC 7592) shipped on the Phase 23 W1 branch: the dynamic-registration row is parity and P2 item 4 is closed. G-15: AXIAM's agent-identity story is documented, so the `zitadel/nextgen` watch item now has a named counterpart. | — |
| 2026-10-02 | G-12 (front-channel logout) declined and recorded in the design document (D-6). This comparison has no front-channel row or gap-list entry, so none changed. Revisit only on an adopter request. | — |

## Sources

All links point at `github.com/zitadel/zitadel` on `main` unless stated.
`apps/docs/content/X` is the source of `zitadel.com/docs/X`.

- [Z1] README — <https://github.com/zitadel/zitadel>
- [Z2] Instances and granted projects — <https://github.com/zitadel/zitadel/blob/main/apps/docs/content/concepts/structure/instance.mdx>, <https://github.com/zitadel/zitadel/blob/main/apps/docs/content/concepts/structure/granted_projects.mdx>
- [Z3] Audit trail — <https://github.com/zitadel/zitadel/blob/main/apps/docs/content/concepts/features/audit-trail.mdx>
- [Z4] Licence and v3.0.0 notes (AGPL switch, CockroachDB removed) — <https://github.com/zitadel/zitadel/blob/main/LICENSE>, <https://github.com/zitadel/zitadel/releases/tag/v3.0.0>
- [Z5] Authorization and permission services — <https://github.com/zitadel/zitadel/blob/main/proto/zitadel/authorization/v2/authorization_service.proto>, <https://github.com/zitadel/zitadel/blob/main/proto/zitadel/internal_permission/v2/internal_permission_service.proto>
- [Z6] Open issues: PAR #10239, DPoP #5402, mTLS #8597 — <https://github.com/zitadel/zitadel/issues/10239>, <https://github.com/zitadel/zitadel/issues/5402>, <https://github.com/zitadel/zitadel/issues/8597>
- [Z7] Grant types and endpoints — <https://github.com/zitadel/zitadel/blob/main/apps/docs/content/apis/openidoauth/grant-types.mdx>, <https://github.com/zitadel/zitadel/blob/main/apps/docs/content/apis/openidoauth/endpoints.mdx>
- [Z8] Token exchange request — <https://github.com/zitadel/zitadel/blob/main/apps/docs/content/apis/openidoauth/_token_exchange_request.mdx>
- [Z9] v4.17.0 release — <https://github.com/zitadel/zitadel/releases/tag/v4.17.0>
- [Z10] CIMD pull requests — <https://github.com/zitadel/zitadel/pull/12316>, <https://github.com/zitadel/zitadel/pull/12860>
- [Z11] Client authentication methods — <https://github.com/zitadel/zitadel/blob/main/apps/docs/content/apis/openidoauth/authn-methods.mdx>
- [Z12] User service (passkeys, U2F, OTP) — <https://github.com/zitadel/zitadel/blob/main/proto/zitadel/user/v2/user_service.proto>
- [Z13] Feature flags (back-channel logout always on) — <https://github.com/zitadel/zitadel/blob/main/proto/zitadel/feature/v2/instance.proto>
- [Z14] SAML endpoints — <https://github.com/zitadel/zitadel/blob/main/apps/docs/content/apis/saml/endpoints.mdx>
- [Z15] Identity provider types — <https://github.com/zitadel/zitadel/blob/main/proto/zitadel/idp/v2/idp.proto>
- [Z16] SCIM 2.0 (preview) — <https://github.com/zitadel/zitadel/blob/main/apps/docs/content/apis/scim2.mdx>
- [Z17] Actions v2 — <https://github.com/zitadel/zitadel/blob/main/apps/docs/content/concepts/features/actions_v2.mdx>, <https://github.com/zitadel/zitadel/blob/main/proto/zitadel/action/v2/target.proto>
- [Z18] Runtime defaults — <https://github.com/zitadel/zitadel/blob/main/cmd/defaults.yaml>
- [Z19] Next-generation preview — <https://github.com/zitadel/nextgen>
- [Z20] Releases and security advisories — <https://github.com/zitadel/zitadel/releases>, <https://github.com/zitadel/zitadel/security/advisories>
