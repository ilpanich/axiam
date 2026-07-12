# AXIAM Documentation

**Milestone:** v1.2 (MVP Release Hardening) — Beta
**Last verified:** 2026-07-06

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

## Deployment & operations

- [`deployment/README.md`](./deployment/README.md) — Docker Compose and
  Kubernetes deployment guide: required environment variables, secrets, and
  NetworkPolicies

## Admin & PKI guides

Task-oriented guides for operators and integrators.

- [`admin/README.md`](./admin/README.md) — first-run bootstrap and day-to-day
  admin operations (organizations/tenants, users, roles, permissions)
- [`pki/README.md`](./pki/README.md) — certificate lifecycle: CA issuance,
  leaf cert issuance, mTLS binding, revocation

## Compliance

Detailed backing evidence for each standard, plus the top-level security
audit citation index.

- [`compliance/asvs-l2-checklist.md`](./compliance/asvs-l2-checklist.md) — OWASP ASVS Level 2, control-by-control
- [`compliance/FINDINGS.md`](./compliance/FINDINGS.md) — deferred/finding rows referenced by the ASVS checklist
- [`compliance/oauth2-rfc-compliance.md`](./compliance/oauth2-rfc-compliance.md) — OAuth2 RFC conformance
- [`compliance/oidc-conformance.md`](./compliance/oidc-conformance.md) — OpenID Connect conformance
- [`compliance/sc4-coverage.md`](./compliance/sc4-coverage.md) — federation/test coverage evidence
- [`compliance/gdpr-compliance.md`](./compliance/gdpr-compliance.md) — GDPR export/erasure/consent (CMPL-02)
- [`../claude_dev/security-audit.md`](../claude_dev/security-audit.md) — **master citation index**
  mapping controls to OWASP ASVS L2, ISO 27001, and the CyberSecurity Act
  (CMPL-01); cites the files above rather than duplicating them

## SDKs

Official client SDKs, one per language. Each README is the getting-started
guide for that SDK — linked here, not copied.

Each SDK lives in its own repository:

- [axiam-rust-sdk](https://github.com/ilpanich/axiam-rust-sdk) — Rust
- [axiam-typescript-sdk](https://github.com/ilpanich/axiam-typescript-sdk) — TypeScript / JavaScript
- [axiam-python-sdk](https://github.com/ilpanich/axiam-python-sdk) — Python
- [axiam-java-sdk](https://github.com/ilpanich/axiam-java-sdk) — Java
- [axiam-csharp-sdk](https://github.com/ilpanich/axiam-csharp-sdk) — C#
- [axiam-php-sdk](https://github.com/ilpanich/axiam-php-sdk) — PHP
- [axiam-go-sdk](https://github.com/ilpanich/axiam-go-sdk) — Go

See [`../sdks/CONTRACT.md`](../sdks/CONTRACT.md) for the cross-language SDK contract.

## Other references

- [`dev-environment.md`](./dev-environment.md) — local development environment setup
- [`../CLAUDE.md`](../CLAUDE.md) — repository conventions for AI coding agents
- [`../claude_dev/roadmap.md`](../claude_dev/roadmap.md) — project roadmap

---

Internal links on this page and across `docs/**/*.md` are validated by
[`../scripts/check-doc-links.sh`](../scripts/check-doc-links.sh) (D-11,
zero-dependency, fails closed on any broken relative link).
