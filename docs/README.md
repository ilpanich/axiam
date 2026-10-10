# AXIAM Documentation

**Milestone:** `1.0.0` — first stable release
**Last verified:** 2026-10-09

This is the top-level landing page for all AXIAM documentation. Each section
below **links out** to its own page rather than duplicating content — this
page is an index, not a second copy (D-09). If a linked page and this index
ever disagree, the linked page is authoritative.

## API docs

Contract references for all three protocols AXIAM exposes — REST (OpenAPI),
gRPC (Protocol Buffers), and AMQP (AsyncAPI).

- [`api/README.md`](./api/README.md) — landing page: how to view each spec
  - [`api/openapi.json`](./api/openapi.json) — REST OpenAPI spec (symlink to [`sdks/openapi.json`](../sdks/openapi.json), drift-gated in CI)
  - [`api/grpc.md`](./api/grpc.md) — gRPC usage guide, referencing [`proto/axiam/v1/`](../proto/axiam/v1/)
  - [`api/asyncapi.yml`](./api/asyncapi.yml) — AMQP AsyncAPI 2.6 spec
  - [`api/scim-provisioning.md`](./api/scim-provisioning.md) — SCIM 2.0
    (`/scim/v2`) user/group provisioning: endpoints, field mapping, PATCH
    subset, tenant scoping, Okta + Entra walkthroughs
  - [`api/device-flow.md`](./api/device-flow.md) — Device Authorization Grant
    (RFC 8628) for input-constrained clients: endpoints, the polling answers,
    the verification page's API
  - [`api/token-exchange.md`](./api/token-exchange.md) — OAuth2 Token Exchange
    (RFC 8693): delegation vs impersonation, scope narrowing, the lifetime cap
  - [`api/federated-token-exchange.md`](./api/federated-token-exchange.md) —
    accepting a partner identity provider's token at the token-exchange
    endpoint and receiving an AXIAM token for it
  - [`api/resource-indicators.md`](./api/resource-indicators.md) — Resource
    Indicators (RFC 8707): addressing an access token's `aud` at another
    service
  - [`api/mcp.md`](./api/mcp.md) — fronting a Model Context Protocol server
    with AXIAM as its OAuth 2.0 authorization server
  - [`api/uma.md`](./api/uma.md) — UMA 2.0: the Protection API and the
    permission-ticket grant
  - [`api/logout.md`](./api/logout.md) — OIDC RP-Initiated and Back-Channel
    Logout

## Deployment & operations

- [`deployment/README.md`](./deployment/README.md) — Docker Compose and
  Kubernetes deployment guide: required environment variables, secrets, and
  NetworkPolicies
- [`deployment/rate-limit-sizing.md`](./deployment/rate-limit-sizing.md) —
  sizing your rate limits: the measured hardware envelope, the
  `internet`/`gateway`/`mesh` posture presets, and the security caveats of
  per-client keying
- [`deployment/authz-read-path.md`](./deployment/authz-read-path.md) — what an
  authorization check costs against SurrealDB, which cache removes which
  round-trip, and the read-replica design note
- [`deployment/vault.md`](./deployment/vault.md) — AXIAM's long-lived secrets,
  where they come from, how to run HashiCorp Vault for them, and what to use if
  you are not a Vault shop
- [`deployment/rpi5-k3s.md`](./deployment/rpi5-k3s.md) — operator runbook for
  one Raspberry Pi 5 on k3s, provisioned with OpenTofu
- [`security-profiles.md`](./security-profiles.md) — the native in-process TLS
  listener's security decisions, and how the benchmark TLS profiles (p0–p3) map
  onto them

## Admin & PKI guides

Task-oriented guides for operators and integrators.

- [`admin/README.md`](./admin/README.md) — first-run bootstrap and day-to-day
  admin operations (organizations/tenants, users, roles, permissions)
- [`admin/authenticator-policies.md`](./admin/authenticator-policies.md) —
  WebAuthn attestation policy: policy fields and decision order, the passkey
  caveat, FIDO MDS3 refresh/air-gap operations, trust-anchor update
  procedure, and the compliance report
- [`admin/reactors.md`](./admin/reactors.md) — Reactors (X1): what they are,
  webhook vs. listener Reactor, failure-policy implications, the listener
  idempotency note, and how to register one; the wire protocol itself is
  normative in [`sdks/CONTRACT.md` §22](../sdks/CONTRACT.md)
- [`admin/email-delivery.md`](./admin/email-delivery.md) — how an email
  configuration resolves through the org→tenant cascade, which fields are
  tri-state, the delivery self-test endpoint, and what each provider requires
  of the sender domain before it will accept a message
- [`admin/organization-scope.md`](./admin/organization-scope.md) —
  organization-level users, roles and service accounts: the two levels of
  principal
- [`admin/fapi2-profile.md`](./admin/fapi2-profile.md) — the FAPI 2.0 Security
  Profile (Final) constraint bundle, mTLS client authentication and
  certificate-bound access tokens, each opt-in per client
- [`admin/browser-login-hop.md`](./admin/browser-login-hop.md) — the
  `browser_sso` per-client switch that lets a relying party's redirect reach a
  sign-in page
- [`admin/oidc-authn-parameters.md`](./admin/oidc-authn-parameters.md) — the
  `authn_request_params` per-client switch: `prompt`, `max_age`, `acr_values`
  and `id_token_hint`
- [`admin/public-clients.md`](./admin/public-clients.md) — public clients
  (`token_endpoint_auth_method: "none"`) and RFC 8252 loopback redirects
- [`admin/dynamic-client-registration.md`](./admin/dynamic-client-registration.md) —
  dynamic client registration (RFC 7591) and the client configuration endpoint
  (RFC 7592)
- [`admin/client-id-metadata-documents.md`](./admin/client-id-metadata-documents.md) —
  accepting a `client_id` that is a URL, and fetching the registration it names
- [`pki/README.md`](./pki/README.md) — certificate lifecycle: CA issuance,
  leaf cert issuance, mTLS binding, revocation and how far a revocation reaches

## User guides

- [`user/passkeys.md`](./user/passkeys.md) — passkeys and security keys, for
  the people who sign in with them

## Federation & provisioning

AXIAM as a SAML identity provider, a directory client, a Shared Signals
transmitter, a CIBA authorization server and an outbound SCIM client, and the
broker-less deployment profile. Each item links to where it is specified; none
is restated here.

- Operations — [`deployment/README.md`](./deployment/README.md):
  [What a tenant's directory needs (LDAP / Active Directory)](./deployment/README.md#what-a-tenants-directory-needs-ldap--active-directory)
  and [Minimal profile (no broker)](./deployment/README.md#minimal-profile-no-broker)
- Design — [`../claude_dev/design-document.md`](../claude_dev/design-document.md):
  [8d, Directory Identity Source](../claude_dev/design-document.md#8d-directory-identity-source-ldap--active-directory),
  [8e, SAML 2.0 Identity Provider](../claude_dev/design-document.md#8e-saml-20-identity-provider),
  [8f, RFC 7592 Client Configuration](../claude_dev/design-document.md#8f-rfc-7592-client-configuration),
  [8g, Shared Signals Framework Transmitter](../claude_dev/design-document.md#8g-shared-signals-framework-transmitter),
  [8h, Outbound SCIM Provisioning](../claude_dev/design-document.md#8h-outbound-scim-provisioning),
  [8i, CIBA](../claude_dev/design-document.md#8i-ciba-client-initiated-backchannel-authentication) and
  [8j, The Minimal Deployment Profile](../claude_dev/design-document.md#8j-the-minimal-deployment-profile-no-broker)
- Contract — [`../sdks/CONTRACT.md`](../sdks/CONTRACT.md):
  [§29 SAML service provider registration](../sdks/CONTRACT.md#§29-saml-service-provider-registration-management-api-contract-155),
  [§30 Directory configuration](../sdks/CONTRACT.md#§30-directory-configuration-management-api-contract-154),
  [§31 Outbound SCIM targets](../sdks/CONTRACT.md#§31-outbound-scim-targets-management-api-contract-157),
  [§32 SSF stream registration and the receiver helper](../sdks/CONTRACT.md#§32-ssf-stream-registration-and-the-receiver-helper-contract-156),
  [§33 CIBA](../sdks/CONTRACT.md#§33-ciba--client-initiated-backchannel-authentication-contract-158)
- Website guides —
  [LDAP and Active Directory](https://ilpanich.github.io/axiam/#/docs/directory),
  [AXIAM as a SAML identity provider](https://ilpanich.github.io/axiam/#/docs/saml-idp),
  [Shared Signals (SSF) transmitter](https://ilpanich.github.io/axiam/#/docs/ssf),
  [CIBA (backchannel authentication)](https://ilpanich.github.io/axiam/#/docs/ciba),
  [Outbound SCIM provisioning](https://ilpanich.github.io/axiam/#/docs/scim-outbound)
- Routes — [`api/README.md`](./api/README.md), one short section per surface

## Guides

Cross-cutting walkthroughs that follow one scenario across several pages.

- [`guides/identity-for-agents.md`](./guides/identity-for-agents.md) — Identity
  for agents: registering an agent, RFC 8693 delegation with `act`, RFC 8707
  resource indicators, the MCP resource-server helpers (CONTRACT §28), and
  revocation, with SDK snippets

## Compliance

Detailed backing evidence for each standard, plus the top-level security
audit citation index.

- [`compliance/asvs-l2-checklist.md`](./compliance/asvs-l2-checklist.md) — OWASP ASVS Level 2, control-by-control
- [`compliance/FINDINGS.md`](./compliance/FINDINGS.md) — deferred/finding rows referenced by the ASVS checklist
- [`compliance/oauth2-rfc-compliance.md`](./compliance/oauth2-rfc-compliance.md) — OAuth2 RFC conformance
- [`compliance/oidc-conformance.md`](./compliance/oidc-conformance.md) — OpenID Connect conformance
- [`compliance/sc4-coverage.md`](./compliance/sc4-coverage.md) — federation/test coverage evidence
- [`compliance/gdpr-compliance.md`](./compliance/gdpr-compliance.md) — GDPR export/erasure/consent (CMPL-02)
- [`conformance/README.md`](./conformance/README.md) — OpenID Foundation
  conformance-suite results, published in full, green and red alike;
  [`conformance/index.md`](./conformance/index.md) lists the generated reports
- [`../claude_dev/security-audit.md`](../claude_dev/security-audit.md) — **master citation index**
  mapping controls to OWASP ASVS L2, ISO 27001, and the CyberSecurity Act
  (CMPL-01); cites the files above rather than duplicating them

## SDKs

Official client SDKs, one per language. Each README is the getting-started
guide for that SDK — linked here, not copied.

Each SDK lives in its own repository. The first seven implement the full
contract surface, gRPC and AMQP transports included; Kotlin, Swift, C and C++
cover the REST surface (§1–§7, §9–§11, including §6.1 mTLS).

- [axiam-rust-sdk](https://github.com/ilpanich/axiam-rust-sdk) — Rust
- [axiam-typescript-sdk](https://github.com/ilpanich/axiam-typescript-sdk) — TypeScript / JavaScript
- [axiam-python-sdk](https://github.com/ilpanich/axiam-python-sdk) — Python
- [axiam-java-sdk](https://github.com/ilpanich/axiam-java-sdk) — Java
- [axiam-csharp-sdk](https://github.com/ilpanich/axiam-csharp-sdk) — C#
- [axiam-php-sdk](https://github.com/ilpanich/axiam-php-sdk) — PHP
- [axiam-go-sdk](https://github.com/ilpanich/axiam-go-sdk) — Go
- [axiam-kotlin-sdk](https://github.com/ilpanich/axiam-kotlin-sdk) — Kotlin
- [axiam-swift-sdk](https://github.com/ilpanich/axiam-swift-sdk) — Swift
- [axiam-c-sdk](https://github.com/ilpanich/axiam-c-sdk) — C
- [axiam-cplusplus-sdk](https://github.com/ilpanich/axiam-cplusplus-sdk) — C++

See [`../sdks/CONTRACT.md`](../sdks/CONTRACT.md) for the cross-language SDK contract.

## Other references

- [`dev-environment.md`](./dev-environment.md) — local development environment setup
- [`../CLAUDE.md`](../CLAUDE.md) — repository conventions for AI coding agents
- [`../claude_dev/roadmap.md`](../claude_dev/roadmap.md) — project roadmap

---

Internal links on this page and across `docs/**/*.md` are validated by
[`../scripts/check-doc-links.sh`](../scripts/check-doc-links.sh) (D-11,
zero-dependency, fails closed on any broken relative link).
