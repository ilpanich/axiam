# Phase 25: Security Hardening II — Federation, PKI, Data-Protection & Infra - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-04
**Phase:** 25-security-hardening-ii-federation-pki-data-protection-infra
**Areas discussed:** SSRF guard architecture, AMQP per-tenant signing, GDPR erasure durability, K8s egress tightening (+ 8 second/third-order sub-decisions)

---

## Area selection (gray-area multi-select)

The user opted to discuss **all 4** primary gray areas. The remaining SECHRD items (05 mTLS CA status/validity, 07 nonce-from-server-state, 09 secret non-serialization) plus prescriptive sub-mechanics were flagged as planner-discretion up front and not put to a vote.

---

## SSRF guard architecture (SECHRD-02)

| Option | Description | Selected |
|--------|-------------|----------|
| Shared guarded client | One SSRF-guarded HTTP client/resolver funnels ALL outbound fetches (webhook + OIDC discovery/token + SAML metadata + JWKS) through a single private-IP check + resolve-once-pin; generalize `is_private_jwks_ip`. DRY, single audit point. | ✓ |
| Extend each call site | Add the guard inline at each fetch; less refactor, but duplicated logic and more places to miss. | |

**User's choice:** Shared guarded client
**Notes:** Consistent with Phase 24's "shared store" robust choice.

### Follow-on — redirect handling

| Option | Description | Selected |
|--------|-------------|----------|
| Disable, re-validate | Follow no redirects; on 3xx re-run the SSRF guard against the new URL and re-issue. Closes the 302→internal bypass with least surface. | ✓ |
| Re-guard per hop | Follow redirects but check each hop's resolved IP via a custom redirect policy. Same protection, more moving parts. | |

**User's choice:** Disable, re-validate

### Follow-on — DNS resolution + IPv6

| Option | Description | Selected |
|--------|-------------|----------|
| Fresh per request, A+AAAA | No cross-request DNS cache; resolve both A and AAAA, reject if any is private, pin the exact connected IP. | ✓ |
| Cache with short TTL | Reuse validated resolutions briefly for perf; reintroduces a rebind window at cache-expiry edges. | |

**User's choice:** Fresh per request, A+AAAA

---

## AMQP per-tenant signing (SECHRD-08)

| Option | Description | Selected |
|--------|-------------|----------|
| HKDF-derived per-tenant | One master `AXIAM__AMQP__SIGNING_KEY`; per-tenant subkey = HKDF(master, tenant_id). No per-tenant secret storage; minimal change to existing HMAC path. | ✓ |
| Stored per-tenant keys | Generate + store an encrypted key per tenant (AES-256-GCM at rest); more moving parts + per-tenant rotation. | |
| Per-tenant queues + ACLs | Broker-level isolation via per-tenant queues/vhosts + ACLs; strong but heavy operationally, changes deploy/provisioning. | |

**User's choice:** HKDF-derived per-tenant
**Notes:** Currently `messages.rs` uses one shared HMAC key. Signing also made mandatory/fail-closed in prod.

### Follow-on — HKDF construction

| Option | Description | Selected |
|--------|-------------|----------|
| Domain-sep + key_version | HKDF-SHA256, fixed app salt, info = "axiam-amqp-v1"‖tenant_id, plus a `key_version` byte on the message for future master-key rotation. | ✓ |
| Minimal (info=tenant_id) | HKDF with info = tenant_id only, no version byte. Simplest, but no rotation path or domain separation. | |

**User's choice:** Domain-sep + key_version

### Follow-on — dev/test signing

| Option | Description | Selected |
|--------|-------------|----------|
| Never unsigned; dev key shipped | Signing always required in every env; ship a documented dev key in `config`/`.env.example`. No unsigned code path to regress. | ✓ |
| Allow unsigned in dev only | Permit missing key when env=dev (warn loudly); prod fail-closed. Keeps a warn-and-process bypass branch alive. | |

**User's choice:** Never unsigned; dev key shipped

---

## GDPR erasure durability (SECHRD-06)

| Option | Description | Selected |
|--------|-------------|----------|
| Proof-last + idempotent retry | Run PII-bearing steps in order; write the (unique-per-user) erasure proof only after every step succeeds; on failure leave re-selection flags set so a retry re-runs cleanly. | ✓ |
| Single wrapped transaction | Wrap the whole multi-step purge in one DB transaction, roll back on any failure. Cleanest atomicity but fragile across multi-table + cross-store side-effects. | |

**User's choice:** Proof-last + idempotent retry

### Follow-on — export session scope

| Option | Description | Selected |
|--------|-------------|----------|
| Metadata, redact tokens | Export session rows (created_at/expires_at/last_seen/ip/user_agent) but NOT the opaque token or its hash. | ✓ |
| Full session rows | Include every stored field; risks exporting live credential material. | |

**User's choice:** Metadata, redact tokens

### Follow-on — erasure-proof idempotency

| Option | Description | Selected |
|--------|-------------|----------|
| Unique index on user_id | DB-level UNIQUE constraint on the proof's user_id; retry's duplicate CREATE no-ops idempotently. | ✓ |
| Deterministic proof id | Derive proof record id from user_id (upsert). Equivalent guarantee, more application code. | |

**User's choice:** Unique index on user_id

---

## K8s egress tightening (SECHRD-10)

| Option | Description | Selected |
|--------|-------------|----------|
| Configurable relay CIDR | Allow 25/465/587 only to a Helm/kustomize-parameterized SMTP-relay CIDR (documented placeholder), keeping default-deny meaningful. | ✓ |
| Open 587 to 0.0.0.0/0 | Allow 25/465/587 to any destination; simplest, works out of the box, but a broad hole in default-deny. | |

**User's choice:** Configurable relay CIDR

### Follow-on — relay CIDR default

| Option | Description | Selected |
|--------|-------------|----------|
| Fail-closed (mail off) | Restrictive placeholder (empty selector / example CIDR) so no SMTP egress until the operator configures the relay CIDR. | ✓ |
| Works-out-of-box (0.0.0.0/0) | Default allows 587 broadly so mail works immediately; ships the broad hole this requirement exists to close. | |

**User's choice:** Fail-closed (mail off)

---

## Claude's Discretion

- SSRF pin mechanism (reqwest `resolve()` vs custom `dns_resolver`).
- mTLS clock source (system UTC, as already used for leaf-cert validity).
- mTLS depth decided as **immediate issuing CA only** (full-chain walk deferred).
- ExportReady `org_id` resolution site (producer vs consumer) + backoff delay value/curve.
- Federation nonce-from-server-state (SECHRD-07) and secret `skip_serializing` + Debug scrubbing (SECHRD-09) — single-path prescriptive ACs.
- `443` cluster-CIDR exclusion values (kustomize/Helm placeholders, cluster-specific).
- Test placement in owning crates' `tests/`; per-crate build discipline; per-PLAN ASVS threat-model block.

## Deferred Ideas

- Full CA-chain-walk mTLS validation (flat CA hierarchy today).
- CRL/OCSP revocation checking for mTLS (post-v1.0-beta).
- PGP-encrypted GDPR export (ties to CMPL-02 compliance phase).
- Per-tenant broker queues + RabbitMQ ACLs (rejected in favor of HKDF keys).
- Single wrapped DB transaction for the GDPR purge (rejected in favor of proof-last).
- DNS-resolution caching for outbound fetches (rejected to avoid a rebind window).
- Master-key rotation runbook/tooling (docs/ops item; `key_version` byte makes it rotation-ready).
- Phase 26–29 + compliance/docs items (CORR/PERF/FUNC/QUAL/CMPL/DOCS).
