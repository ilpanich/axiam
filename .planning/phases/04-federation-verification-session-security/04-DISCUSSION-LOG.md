# Phase 4: Federation Verification & Session Security - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-12
**Phase:** 04-federation-verification-session-security
**Areas discussed:** OIDC verify policy, SAML sig + replay, Fed secret encryption, Session kill scope, Service-account token type, First-time SSO

---

## Gray-Area Selection

| Area | Selected |
|------|----------|
| OIDC verify policy | ✓ |
| SAML sig + replay | ✓ |
| Fed secret encryption | ✓ |
| Session kill scope | ✓ |

User selected all four offered gray areas. Two upstream picker questions were also presented and decided in the same pass.

---

## Service-Account Token Discrimination

| Option | Description | Selected |
|--------|-------------|----------|
| `sub_kind` claim (Recommended) | New custom claim `sub_kind: "User" \| "ServiceAccount"`. Absent → User for back-compat. | |
| Token-type via `aud` | Distinct OAuth2 audiences (`axiam:user`, `axiam:m2m`). Standards-compliant. | ✓ |
| Separate `client_id` claim | Add `client_id` only on SA tokens. Fragile (absence-as-signal). | |
| New `typ` JWT header | `at+jwt` vs `at+jwt+sa`. Less idiomatic. | |

**User's choice:** Token-type via `aud`.
**Notes:** Standards-compliant path. Drives D-19..D-21 in CONTEXT.md, including the 15-minute backward-compat window for tokens issued before the change.

---

## First-Time SSO Endpoints

| Option | Description | Selected |
|--------|-------------|----------|
| New public endpoints (Recommended) | `POST /api/v1/auth/federation/{oidc,saml}/{start,callback,login,acs}` under `/auth`, allowlisted. Existing `/federation/oidc/authorize` stays for link-account. | ✓ |
| Make existing endpoints optionally public | Drop `AuthenticatedUser` extractor; branch on session cookie presence. | |
| IdP-initiated SAML only, OIDC stays SP-initiated | Asymmetric design. | |

**User's choice:** New public endpoints.
**Notes:** Clean separation of "first-time login" vs "link account to logged-in user". Drives D-22..D-24.

---

## OIDC Verify Policy

### JWKS kid miss

| Option | Description | Selected |
|--------|-------------|----------|
| Refetch once, then fail (Recommended) | Force one refetch bypassing TTL; rate-limited to 1/60s/config. | ✓ |
| Refetch unconditionally | No rate limit, amplification risk. | |
| Fail immediately, no refetch | Strictest; breaks legitimate key rollover. | |

**User's choice:** Refetch once, then fail. → D-02.

### JWKS outage

| Option | Description | Selected |
|--------|-------------|----------|
| Stale-while-revalidate (Recommended) | Serve last-known-good up to 24h past TTL on unreachable IdP. | ✓ |
| Fail closed always | No serving past TTL on failure. | |
| Serve stale forever | Indefinite staleness. | |

**User's choice:** Stale-while-revalidate. → D-03.

### Algorithm pinning

| Option | Description | Selected |
|--------|-------------|----------|
| New `allowed_algorithms` column, default `[RS256]` (Recommended) | Per-config allowlist; `none` hardcoded-rejected. | ✓ |
| Hardcode `RS256, ES256` globally | No DB change; rigid. | |
| Single `algorithm` field | Strictest; breaks during alg-mixed JWKS rollovers. | |

**User's choice:** `allowed_algorithms` column with `[RS256]` default. → D-04.

---

## SAML Signature & Replay

### XML-sig library

| Option | Description | Selected |
|--------|-------------|----------|
| Enable samael `xmlsec` feature (Recommended) | Flip default-features. Adds `libxml2` + `libxmlsec1` to Docker runtime stage. | ✓ |
| Custom verifier on top of samael Signature types | Pure Rust; hand-written c14n (foot-gun). | |
| Shell out to xmlsec1 CLI | Process-spawn overhead, binary dep. | |

**User's choice:** Enable samael `xmlsec`. → D-06. Triggers Dockerfile change.

### IdP cert source

| Option | Description | Selected |
|--------|-------------|----------|
| Persisted `idp_signing_cert_pem` column (Recommended) | Pasted/auto-extracted at config time. | ✓ |
| Re-fetch IdP metadata per login | Network call per login. | |
| Fetch + cache (TTL 24h) | Additional cache layer + refresher task. | |

**User's choice:** Persisted column. → D-07. Drives `idp_signing_cert_pem: Option<String>` migration.

### Replay store

| Option | Description | Selected |
|--------|-------------|----------|
| SurrealDB table with TTL (Recommended) | `saml_assertion_replay` with `expires_at`, unique on (tenant_id, assertion_id). | ✓ |
| In-memory LRU per pod | Breaks horizontal scaling. | |
| RabbitMQ-based replay log | Overkill, adds dep on auth-critical path. | |

**User's choice:** SurrealDB table. → D-09.

---

## Federation Secret Encryption

### Encryption key

| Option | Description | Selected |
|--------|-------------|----------|
| New dedicated `AXIAM_FEDERATION_ENCRYPTION_KEY` (Recommended) | Mirrors `mfa_encryption_key` pattern; separate blast radius. | ✓ |
| Reuse `mfa_encryption_key` | Single key for MFA + federation. | |
| Per-tenant DEK wrapped by master KEK | Strongest isolation; heavyweight for MVP. | |

**User's choice:** Dedicated env var. → D-10.

### Ciphertext format

| Option | Description | Selected |
|--------|-------------|----------|
| Versioned envelope `v1:<nonce>:<ct>` base64 (Recommended) | Reuses existing `client_secret` column; prefix-based version dispatch. | |
| Separate columns: ciphertext, nonce, key_version | Explicit schema, cleaner queries, requires schema migration. | ✓ |
| Single binary blob, no version | No rotation path. | |

**User's choice:** Separate columns. → D-11.
**Notes:** Diverges from the "Recommended" option. Drives a wider schema migration but yields cleaner introspection (`SELECT WHERE key_version = 1`).

### Migration

| Option | Description | Selected |
|--------|-------------|----------|
| Startup migration with detection heuristic (Recommended) | Server boot encrypts plaintext rows; idempotent; audit-logged. | ✓ |
| Explicit `just migrate-federation-secrets` admin task | Manual, needs feature flag. | |
| Fail boot until manually migrated | Requires downtime. | |

**User's choice:** Startup migration. → D-12.
**Notes:** Original "Recommended" wording referenced a `v1:` string prefix as the detection key, but since the user picked separate columns above, the heuristic is reconciled to "legacy `client_secret IS NOT NULL` AND new `client_secret_ciphertext IS NULL`". Captured in CONTEXT.md D-12 and the `<specifics>` block.

---

## Session Kill Scope

### Password-change endpoint scope

| Option | Description | Selected |
|--------|-------------|----------|
| In scope — add minimal endpoint (Recommended) | `POST /api/v1/auth/password/change`, Argon2 verify, password policy. | ✓ |
| Out of scope — reset flow covers the AC | REQ-7 vacuously satisfied. | |
| Out of scope, file as deferred | Defer to followup. | |

**User's choice:** In scope. → D-14.

### Which sessions die on change/reset

| Option | Description | Selected |
|--------|-------------|----------|
| All sessions die, no exceptions (Recommended) | One chokepoint, simplest. | |
| All other sessions die, current survives on change | Better UX on change; adds `revoke_all_sessions_except`. | ✓ |
| Session list with selective revocation | Belongs in dedicated UI phase. | |

**User's choice:** Other-sessions-die-current-survives-on-change. → D-15 / D-16.
**Notes:** Reset still kills everything (no caller session exists). Change requires a new repo method that filters by current session_id.

### Refresh-token revocation

| Option | Description | Selected |
|--------|-------------|----------|
| Session invalidation cascades (Recommended) | Single chokepoint at `invalidate_user_sessions`. | ✓ |
| Explicit refresh-token table sweep | Two-step revocation. | |
| JWT denylist by `sub` | Hot-path DB lookup per request. | |

**User's choice:** Session cascades. → D-18. Planner must verify `invalidate_user_sessions` actually nukes refresh-token rows today.

---

## Claude's Discretion

Captured in CONTEXT.md under `### Claude's Discretion`:
- JWKS cache crate choice (custom vs `moka`)
- AES-256-GCM crate (likely `aes-gcm`) and nonce generation
- Repository-level vs service-level placement of `revoke_all_sessions_except`
- Audience-check granularity per route group
- Whether first-time SSO endpoints set cookies only (recommended) or also return JSON
- Background-job mechanism for replay/state cleanup (tokio task vs AMQP scheduled vs DB TTL)
- Frontend "Continue with SSO" button — minimal-scope add only
- Whether to also revoke OAuth2 authorization codes / device codes on password change

## Deferred Ideas

- Federation key-rotation procedure (rewrap rows from v1 to v2)
- Dropping the legacy `client_secret` column after backfill stabilizes
- Tightening the 15-minute `aud` backward-compat window into a hard reject
- Federation metadata auto-refresh + auto-extracting `idp_signing_cert_pem`
- "My sessions" user-facing UI
- Admin-initiated `revoke-all` endpoint for forcing logout on any user
