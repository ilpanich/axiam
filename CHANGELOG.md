# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **WebAuthn attestation policy enforcement (X3).** Registration has always
  accepted any authenticator; tenants can now opt into "only FIDO-certified /
  non-revoked / explicitly-allowed authenticators may register," backed by
  the FIDO Alliance's Metadata Service (MDS3).

  `axiam-pki` gains an MDS3 ingestion pipeline: fetch (or load, air-gapped)
  the ~10 MB signed BLOB, verify its RS256 JWT signature chain against a
  **digest-pinned** vendored GlobalSign Root CA – R3 anchor — matching the
  pinned SHA-256 is the check, the anchor is never re-fetched at runtime —
  pin the leaf's SAN DNS identity (chaining to a public CA root by itself
  only proves "some GlobalSign EV customer," not "FIDO Alliance"), require
  every issuer in the chain to actually be a CA (closing an end-entity
  certificate splice a naive verifier would miss), reject a rollback to an
  older BLOB serial, and mark a BLOB stale past its own `nextUpdate` without
  ever hard-failing ingestion over it. Ingestion is opt-in
  (`AXIAM__PKI__MDS_ENABLED=false` by default — zero outbound calls) with a
  weekly background refresh, an admin-triggered `POST /api/v1/mds/refresh`,
  status via `GET /api/v1/mds/status`, and an `AXIAM__PKI__MDS_BLOB_PATH`
  escape hatch for air-gapped deployments (the BLOB itself is not vendored in
  git).

  Per-tenant policy (`GET|PUT /api/v1/tenants/{tenant_id}/webauthn/attestation-policy`)
  controls attestation mode, required certification level, AAGUID
  allow/block lists, and revoked-status blocking, evaluated by a pure,
  exhaustively-tested decision function
  (`axiam_core::models::webauthn_policy::evaluate`): blocklist beats
  allowlist, compromise/revocation status is sticky across the authenticator's
  whole history, and an AAGUID explicitly allow-listed by an admin is trusted
  even with no MDS entry for it. The default (`mode: none`) reproduces
  today's behavior byte-for-byte, with no MDS lookup at all.

  **Every non-`none` mode excludes synced passkeys** (iCloud Keychain, Google
  Password Manager) **and hybrid sign-in**, not only the strictest setting —
  `webauthn-rs` always requires user verification and always rejects
  synchronised authenticators once attestation is requested at all. AXIAM's
  `mode: indirect` still requests `direct` conveyance on the wire; it differs
  from `mode: direct_required` only in policy strictness afterwards. See
  [`docs/admin/authenticator-policies.md`](docs/admin/authenticator-policies.md)
  for the full trade-off before enabling it.

  Denials return a fixed, non-specific error and audit
  `webauthn.attestation_denied` with the AAGUID and machine-readable reason —
  never a raw library error to the end user. **Existing credentials are never
  auto-revoked** on a policy change: `GET
  /api/v1/tenants/{tenant_id}/webauthn/compliance-report` lists which
  registered credentials would now fail the current policy (a credential
  with no recorded AAGUID — every credential registered before X3 — is
  reported `unknown`, never as a violation), and revocation stays the
  existing admin credential-delete path, a deliberate human action.

  Known, documented limitation: `block_revoked_status` covers `REVOKED` and
  the three `*_COMPROMISE` statuses, not `USER_VERIFICATION_BYPASS` — an
  authenticator with only a UV-bypass advisory still passes that check.
  Operators who care should use `blocked_aaguids`.

- **OIDC logout: RP-initiated and back-channel (B5).**
  `GET`/`POST /oauth2/end_session` ends the session named by a signed
  `id_token_hint`, and every client that participated in that session and
  registered a `backchannel_logout_uri` is POSTed a signed logout token.
  Advertised in discovery as `end_session_endpoint`,
  `backchannel_logout_supported` and `backchannel_logout_session_supported`.

  Both halves operate on a **session**, not a user: a user with a phone and a
  laptop who logs out on the laptop keeps the phone signed in. ID tokens now
  carry `sid`, and it survives refresh-token rotation so an RP that stored it
  at login can still match a logout token to its own session.

  The endpoint is unauthenticated by necessity — a user whose session already
  expired must still be able to complete a logout — so what identifies the
  target is the *signature* on the hint. Expiry on the hint is deliberately
  not checked (a logging-out user's ID token has usually expired already); the
  signature is. An unverifiable hint ends **nothing**: there is no fallback to
  "end every session for the named subject", which would be a
  denial-of-service primitive for anyone who knows a user id.

  `post_logout_redirect_uri` is honoured only on **exact match** against the
  client's new `post_logout_redirect_uris` allow-list — a separate list from
  `redirect_uris`, because one receives authorization codes and the other
  receives a browser after logout. A non-matching URI still logs the user out
  and renders AXIAM's own page: refusing to log someone out because their RP
  sent a bad parameter is the wrong failure.

  Logout tokens carry the mandatory `events` member, always name `sid`, live
  120 s, and can never carry `nonce` (the issuer takes no such parameter, so
  it cannot emit one by accident — its presence is how an ID token gets
  replayed as a logout token). Delivery is best-effort with a bounded retry
  and never blocks the logout.

  New: `AXIAM__RATE_LIMIT__END_SESSION_PER_MIN` (30). See
  [`docs/api/logout.md`](docs/api/logout.md) and CONTRACT.md §12.7.

- **Pushed Authorization Requests (RFC 9126, B5).** `POST /oauth2/par` accepts
  an authorization request over a direct, client-authenticated POST and returns
  an opaque single-use `request_uri` to put in the browser redirect instead of
  the parameters. `/oauth2/authorize` accepts it, refuses to mix it with inline
  parameters (where parameter confusion lives), and a client registered
  `require_par` may not send its parameters through the browser at all. New:
  `AXIAM__RATE_LIMIT__PAR_PER_MIN` (120). Required by FAPI 2.0.

- **OAuth2 Token Exchange (RFC 8693, B3).** A service holding a user's access
  token can exchange it for a *narrower* one —
  `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` on
  `POST /oauth2/token`, advertised in OIDC discovery. Previously a mesh caller
  had two options, both wrong: forward the user's token verbatim
  (over-privileged, and the second hop cannot tell the caller from the user)
  or use its own service credentials (right privileges, no user context).

  One rule governs the feature: **an exchange may only ever narrow.** No
  parameter, configuration or client grant makes the issued token permit
  something the subject token did not already permit. Concretely:

  - `granted = requested ∩ subject_scopes ∩ client_allowed_scopes`. A
    requested scope the subject does not hold is **refused** (`invalid_scope`),
    not silently dropped — silent narrowing produces a token that works for
    some calls and not others, and the caller finds out at the *next* service.
    The client's own registration bounds the result even when the subject token
    is broader, which is what stops a compromised low-privilege service holding
    an admin's token from minting an admin token.
  - `exp = now + min(subject_remaining, max_exchange_lifetime)`. The exchanged
    token never outlives its subject, so an exchange cannot launder lifetime.
    For the same reason **no refresh token is issued** — one would defeat the
    cap outright — and naming `requested_token_type=…:refresh_token` is
    refused rather than answered with an access token.
  - `audience`/`resource` must be registered to the exchanging client; an
    unconstrained `aud` is the mesh equivalent of an open redirect.

  **Delegation vs impersonation** is selected by the presence of `actor_token`,
  and the two are not equally available. Delegation adds an `act` claim naming
  the actor (nested on re-exchange, capped at depth 3 so a signed token cannot
  grow an unbounded field). Impersonation issues a token indistinguishable from
  one the user obtained directly, so it is **off by default** — a client needs
  the explicit `urn:axiam:params:oauth:grant-type:may-impersonate` grant, and
  one without it is refused (`unauthorized_client`) rather than quietly
  downgraded to delegation. Every exchange is audited with client, subject,
  actor, kind, requested and granted scopes, audience and outcome; for
  impersonation that record is the *only* evidence the acting party was not the
  subject.

  v1 accepts AXIAM-issued subject tokens only — accepting another IdP's token
  means accepting whatever it asserts about the subject, and the trust
  configuration that makes that safe is its own feature (X4). A cross-tenant
  subject token answers `invalid_grant` rather than a distinct error, because
  learning a token is valid *somewhere else* is a tenant-enumeration signal.

  New rate-limit bucket `AXIAM__RATE_LIMIT__TOKEN_EXCHANGE_PER_MIN` (120): an
  exchange verifies an inbound JWT, reads the client registration and writes an
  audit record, and it is what an attacker holding one stolen token would
  hammer looking for a widening path. See
  [`docs/api/token-exchange.md`](docs/api/token-exchange.md).

- **OAuth2 Device Authorization Grant is reachable (RFC 8628, B2).** The
  grant's core, storage and state machine landed earlier; nothing was mounted,
  so no device could use it. Now: `POST /oauth2/device_authorization` issues
  the code pair, `POST /oauth2/token` serves
  `grant_type=urn:ietf:params:oauth:grant-type:device_code` with the full §3.5
  answer table (`authorization_pending`, `slow_down`, `expired_token`,
  `access_denied`, `invalid_grant`), and
  `GET /api/v1/device/verify` + `POST /api/v1/device/decide` back the
  verification page. The endpoint is advertised in OIDC discovery, because a
  device that can read discovery is exactly the client that cannot be told the
  URL out of band.

  The verification endpoints live under `/api/v1`, not `/oauth2`, and that is
  the design: approval records the approver as the subject the token is minted
  for (so the caller must be authenticated), and a short typed code is
  guessable from another origin (so CSRF double-submit is what stops a
  malicious page approving on a victim's session — RFC 8628 §5.4's phishing
  shape from the other direction). Unknown, expired and already-decided codes
  answer identically, so the page is not an oracle for which codes are live.

  Two new rate-limit buckets, neither sized from benchmark capacity:
  `AXIAM__RATE_LIMIT__DEVICE_AUTHORIZATION_PER_MIN` (12) because the endpoint
  is unauthenticated *and* allocates state, and
  `AXIAM__RATE_LIMIT__DEVICE_VERIFY_PER_MIN` (10), the user-code brute-force
  bound — `RateLimitConfig::validate` now **asserts** the OWASP condition
  against the grant lifetime, so raising it past the point where an
  8-character typed code becomes guessable fails at startup rather than in an
  incident review. See [`docs/api/device-flow.md`](docs/api/device-flow.md).

- **Passkeys and security keys in the admin UI.** The server had shipped the
  full WebAuthn registration and authentication ceremonies for releases, but
  the frontend had zero WebAuthn references — the MFA page advertised passkeys
  as "Coming soon" and the login page could not exercise them. Both are now
  wired: enrol a platform passkey or a cross-platform security key from
  Profile → MFA methods, and sign in with a passkey via browser autofill
  (conditional mediation), an explicit button, or as a second factor. The MFA
  list distinguishes `Passkey` from `Security key` rather than labelling both
  "WebAuthn". All ceremony policy stays server-side.
- **Deny-effect selector in the role editor**, with a distinct `DENY` badge on
  granted permissions. Deny rules were creatable over the API from the moment
  B1 landed and invisible in the console — the worst of both worlds.
- **Frontend coverage matrix** (`claude_dev/frontend-coverage-matrix.md`) plus
  a CI check that fails when a REST handler module has no row, so a new server
  surface cannot ship without someone recording whether it needs a UI.
- **axe-core accessibility smoke suite** over the main pages and the
  design-system components the audit fixed, wired into the fast frontend CI job.
- **RBAC deny-override (explicit deny).** A role→permission grant now carries
  `effect: "allow" | "deny"`, defaulting to `"allow"`. A deny grant overrides
  **every** allow, at any depth of the resource hierarchy and at equal
  specificity — deny-override, not most-specific-wins. Closes SEC-040 and the
  "no explicit deny" entry in the comparison page's cons list. Check responses
  gain `reason_code` (`allowed` | `no_grant` | `denied_by_rule`) so a caller
  can tell "ask an admin for access" apart from "an admin has already
  decided". Fully backward compatible: existing grants and `effect`-less
  requests both mean allow, and no migration is required beyond the additive
  schema field.

- **AMQP transport encryption (`amqps://`).** Broker traffic was plaintext in
  every deployment artifact. `AmqpConfig` now accepts `amqps://` URLs with an
  optional TLS block (custom CA bundle, optional client certificate for mutual
  TLS toward the broker), and the prod compose stack and k8s manifests speak
  TLS 1.3 on port 5671 with the plaintext listener switched off. There is
  deliberately no verification-skip option: `ca_cert_path` covers the
  legitimate reason to want one. HMAC signing stays mandatory — TLS is
  confidentiality in transit, HMAC is end-to-end authenticity across broker
  hops, and neither substitutes for the other. SDK contract §8b.
- **gRPC strict session-revocation mode** (`AXIAM__GRPC__STRICT_REVOCATION`).
  Opt-in per-request revocation enforcement on the gRPC data plane, matching
  REST. See "Changed" for the default this makes explicit.
- **Read-replica routing primitive** (`AXIAM__DB__READ_REPLICAS`, off by
  default) with a documented staleness contract; authorization, identity and
  JWKS reads are replica-eligible, session revocation and write-path reads are
  pinned to the primary and cannot be configured otherwise.
- Rate-limit scenarios for the three limiter families that had none (`revoke`,
  gRPC admin, gRPC infra), so all eight families appear in the enforcement
  verdict table.

### Changed

- **BREAKING (release builds): a plaintext `amqp://` broker URL is now
  refused** unless `AXIAM__AMQP__ALLOW_PLAINTEXT=true`. Mirrors the existing
  fail-closed posture for the AMQP signing key. Debug builds are unaffected,
  so `cargo test` and `cargo run` keep working untouched — but note that the
  dev, e2e and benchmark compose stacks all run the *published release image*
  and so are subject to the guard like any deployment. All three now set
  `AXIAM__AMQP__ALLOW_PLAINTEXT=true` explicitly, each with a comment stating
  why plaintext is acceptable for that stack. Any other release-image stack
  with an `amqp://` URL must do the same or move to `amqps://`; it will
  otherwise refuse to start, by design.
- **Rate limiting: enforcement now matches configuration in both directions.**
  gRPC families were admitting 1/20–1/33 of their configured ceiling under a
  single-IP flood (the shared 60-second pre-check was charging requests the
  per-second governor then rejected), while REST machine endpoints
  over-admitted by up to +50% (fixed-window boundary doubling). The shared
  counter now uses a sliding window, counts admitted capacity rather than
  arrivals, and refunds downstream rejections; a newly seen key gets its
  pro-rata share of the window plus an explicit, documented 10% burst
  allowance — except below 20/min (every human endpoint, no machine one),
  where smoothing a five-request budget would cost a legitimate first-time
  user a whole request for no security benefit. Rollback:
  `AXIAM__RATE_LIMIT__SHARED_WINDOW=fixed`.
- **Refresh rotation is three datastore round trips instead of five**, via an
  atomic `consume_by_token_hash` (which also removes the read-then-delete
  window rather than tolerating it) and a TTL cache for the per-refresh tenant
  lookup. Single-use rotation, the user-status check, and consuming expired
  tokens are all unchanged.
- **Documented: gRPC does not check session revocation by default.** A user
  who logs out keeps passing gRPC authorization until their access token
  expires (up to 15 minutes). This was always true; it is now written down,
  and `AXIAM__GRPC__STRICT_REVOCATION=true` changes it.

## [1.0.0-alpha24] - 2026-08-04

### Added

- Add the Threat Modeling & Security section
- Service-account client_credentials grant + SEC review (#267)
- Cross-replica decision-cache invalidation over RabbitMQ fanout
- Install the client-secret hasher at startup (OBS-1 fail-closed gate)
- Key client-secret hashing with the server pepper (OBS-1)

### Changed

- Close the review series; make the website section handoff-ready
- Fix the §22.3 residuals (#272)
- Verify §20/§21 — every finding closed
- Bump the minor-patch group across 1 directory with 3 updates
- Record the rule-8 guardrail tests as closed (§21)
- Close SEC-086 fully and SEC-087, fix the CHANGELOG inversion (#269)
- Verify d15878a2 — device audience narrowed; SEC-086 partial, SEC-087 new
- Close SEC-086 and the §17 residuals, narrow the device audience (#268)
- Verify §16 and review the new service-account grant
- Bump pem from 3.0.6 to 4.0.0
- Bump the minor-patch group with 2 updates
- Bump taiki-e/install-action from 2.85.2 to 2.85.5
- Bump github/codeql-action/upload-sarif
- Bump the minor-patch group in /frontend with 8 updates
- Bump docker/login-action from 4.5.1 to 4.6.0
- Bump hadolint/hadolint-action from 3.3.0 to 3.4.0
- Close the §15 partials and observations (#259)
- Verify §14 — SEC-085 closed, no open findings remain
- Close every open item from the 2026-08-02 security analysis (§13) (#258)
- Final verification pass — §12 claims confirmed; one new HIGH (SEC-085)
- Close §4 residual 2 — cross-replica cache invalidation shipped
- Record the CONTRACT §10.1 sweep — five new findings; correct §10.7
- Normative SDK local-verification set; close residual 10.4-3 as misdescribed
- Verify the SEC-079/080 remediation; all findings closed
- Record §10 remediation status as claims pending verification
- Independent re-verification pass; sync threat model for T-145
- Add exact-command reference to the run-5 runbook; fix three harness defects it exposed
- Generate the query-plan fixture password instead of hard-coding it
- Add run-5 runbook; add CONTRACT §13 webhook verification
- Record remediation status for SEC-071..078 and T-145
- Fix authz-path table scans, add session-validation cache and CC stage timings
- Add 2026-08-02 code-level security analysis
- Add public-facing Threat Modeling & Security website section
- Update benchmarks page to run 4 and add resource usage
- Run-4 analysis — post-fix matrix verified, resource usage, prod-limit guidance

### Fixed

- Supply the mandatory auth pepper to release-mode stacks
- Propagate session-revocation failures; warn on mintable rate-limit key; verify remediation evidence
- Decouple gRPC admin ceiling from authz; bound infra family; tenant-filter member_of; reorder session-cache invalidation
- SDK bench correctness/telemetry + run-5 harness prep (I9-I19)
- Correct gRPC units, scope limits per method, revise internet defaults

## [Unreleased]

### Changed

- **⚠ BREAKING — a certificate-authenticated device now receives a machine
  token (`aud: axiam:m2m`), not a user token.** `POST /api/v1/auth/device`
  stamped `aud: axiam:user`, so any device that authenticated by mTLS passed
  **every** user-facing route guard. It now stamps `axiam:m2m`, matching the
  client-credentials grant: a service account is the same principal however it
  authenticated, and §4.3/`SEC-006` route narrowing finally applies to both.

  **What breaks.** A device token is no longer accepted on user-facing REST
  routes. It *is* accepted on the authorization-check endpoints — `POST
  /api/v1/authz/check` and `/api/v1/authz/check/batch` — which are the
  machine-facing surface and were widened in the same change so that no
  required device call started failing. Any other endpoint a fleet calls with a
  device token must be migrated deliberately; that access was implicit rather
  than designed.

  **Before upgrading**, check whether your devices call anything beyond the
  authz-check endpoints. SDK guards fronting a resource server that accepts
  device callers must be configured to expect `axiam:m2m` (`CONTRACT.md` §10.1
  rule 6, §12.1) — a guard set to `axiam:user` will now reject device tokens,
  which is the narrowing working as intended.

  gRPC is unchanged: its interceptor accepts both audiences on all services, so
  the m2m/user split is REST-only.

### Security

- **A client-existence oracle survived on the `authorization_code` grant
  (SEC-086, second pass).** The first pass unified every token-endpoint
  `error_description` behind one constant, but only two of the three grants
  ordered their checks safely. On `authorization_code` the client lookup ran
  *before* the secret-presence check and the grant-type check ran *before*
  secret verification, so an unauthenticated caller could still separate "no
  such client" from "client exists" — with no secret at all, and again with any
  dummy secret. Both checks now follow verification, matching
  `client_credentials` and `refresh_token`. `unauthorized_client` is now
  reachable only by a caller who has already proven possession of the secret.

- **The failed-client-auth audit row could be written into any tenant
  (SEC-087).** `/oauth2/token` is unauthenticated and takes `tenant_id` from a
  query parameter, so the audit row added in the previous change let an
  anonymous caller append rows to an arbitrary — or nonexistent — tenant's
  append-only log. The tenant is now resolved before the write; the
  caller-supplied `client_id` is truncated; and the recorded IP is the
  transport peer address, with the forgeable `X-Forwarded-For` value kept in
  metadata under a name marking it untrusted.

- **Neither half of the decision-cache staleness bound is operator-removable any
  more (§15.2).** Two gaps compounded: `decision_cache_ttl_secs` was an
  unbounded `u64` (unlike `cleanup_interval_secs`, clamped since T-04-35), and
  the cross-replica heartbeat that shortens the undelivered-invalidation window
  could be switched off with `..._HEARTBEAT_SECS=0` and only a warning. An
  operator could therefore set a multi-hour stale-allow window *and* disable the
  mechanism that detects a replica whose queue has been unbound.

  The TTL is now clamped to 300 s — in the accessor `build_decision_cache`
  calls, not in `main.rs`, so every construction path is covered. Heartbeats
  cannot be disabled while broadcast is on; out-of-range intervals clamp to
  `1..=60`. The `0` escape hatch was introduced in this same unreleased change,
  so removing it breaks nothing.

- **A replayed heartbeat can no longer satisfy the liveness watchdog (§15.2).**
  Heartbeats bypass the replay `NonceGuard` deliberately — they arrive on a
  fixed interval from every replica and would evict real invalidation nonces
  from its bounded capacity. That left a narrow path: a party with broker rights
  who captured one signed heartbeat could replay it inside the freshness window
  to keep a replica's watchdog satisfied while its queue was unbound, which is
  the exact adversary the heartbeat exists to detect. Acceptance is now bound to
  nonces the replica itself published and has not yet seen back.

### Added

- **Service accounts can now authenticate via OAuth2 client-credentials.**
  `POST /api/v1/service-accounts` and `rotate-secret` have always returned a
  `client_secret` to the operator — but **no flow accepted it**. A service
  account's only working authentication path was mTLS
  (`POST /api/v1/auth/device`); the client-credentials grant verified against
  the `oauth2_client` table only, and nothing ever compared
  `service_account.client_secret_hash` against a presented secret.

  The grant now dispatches on the `client_id` prefix — `oa_` for `oauth2_client`,
  `sa_` for `service_account`, both server-generated and disjoint, so one lookup
  still suffices. The prefix is **not** a security decision: it only selects the
  table, and the presented secret must still verify against the row found.

  Three deliberate properties:
  - **The secret is verified before the status check**, so a caller cannot
    distinguish "exists but disabled" from "does not exist" by timing. A
    non-Active account returns the same generic `invalid_client`.
  - **No scope may be requested.** A service account registers no scopes, and
    the subset rule leaves the empty set as the only valid request; its
    authorization comes from the roles assigned to it, as on the mTLS path.
  - **The token's `sub` is the service-account id**, not the client id, and its
    `aud` is `axiam:m2m`, so §4.3/`SEC-006` route narrowing keeps it off user
    routes. A service account is now the same principal however it authenticated
    — see the breaking device-audience change below, which makes the mTLS path
    stamp `axiam:m2m` as well.

- **Legacy client-secret hashes in `service_account` are now countable
  (§15.2).** `count_legacy_secret_hashes(tenant)` plus a startup warning.
  With the grant above in place these rows now migrate lazily on first
  authentication, exactly as `oauth2_client` rows do; the count covers the case
  migration cannot reach — a service account that never authenticates — which is
  what decides whether the legacy hash arm can be retired. **Rotation** clears
  such a row.

### Fixed

- **The cache-invalidation publisher no longer serialises mutations behind a
  network round-trip (§15.3.4).** The channel-slot mutex was held across the
  broker confirm, so every access-narrowing mutation in the process queued on
  one lock while the heartbeat task contended for it — a throughput cliff under
  a slow broker, and a regression against the pre-§13.4 code, which shared the
  channel with no lock at all. The lock now covers only channel acquisition. The
  failure path clears the slot **only if it still holds the same channel**, so a
  concurrent reopen is not discarded.

- **`with_previous_pepper` now carries the weak-pepper warning (§15.3.7)** that
  `from_pepper` has always emitted. Lower impact — a previous key can only
  verify existing hashes, never produce one — but an operator rotating *away*
  from a weak pepper is precisely who should be told it was weak.

- **Cache-invalidation liveness heartbeats (§13.4 observation 1).** Decision-cache
  trust followed **consumer** liveness alone. A party with broker `configure`
  rights could `queue.unbind` a replica's queue from the fanout exchange and the
  replica would notice nothing: its consumer stays subscribed to a queue nothing
  routes to, so trust stays on and it keeps serving cached allows it will never
  be told to invalidate. The publisher sees nothing either — `mandatory` is off,
  so the broker acks an unroutable message. Invalidations were silently
  suppressed, bounded only by `decision_cache_ttl_secs`.

  Each replica now publishes a **self-addressed heartbeat** every
  `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_HEARTBEAT_SECS` (default `10`) and
  watches for its own to come back — a round trip that exercises the whole loop
  (publish → exchange → binding → queue → consumer), so an unbound queue breaks
  it immediately. After three consecutive missed intervals the cache is marked
  UNTRUSTED and the replica falls back to uncached evaluation.

  The watchdog can only **revoke** trust, never grant it: trust is still granted
  in exactly one place, by the consumer on a successful subscribe, so it can
  never resurrect trust on a replica whose consumer has died. Heartbeats never
  touch the cache and never enter the replay-nonce guard. Only applies when
  cross-replica broadcast is enabled. (Superseded below: heartbeats can no
  longer be disabled, and the interval is clamped to `1..=60`.)

- **Cached authorization decisions are now invalidated on user delete/update
  (§13.4 observation 9).** `users::update` and `users::delete` did not invalidate,
  so a deleted or deactivated user's cached `Allow` survived on every replica
  until the TTL expired. Nothing on the session-authenticated request path
  re-reads user status, so the cache was the only place the stale grant could be
  cleared. Both handlers now flush the affected subject.

- **Pepper rotation is no longer an unversioned hard break (§13.4 observation 3).**
  `AXIAM__AUTH__PEPPER` keys client-secret hashing, and the `v2.hs256$` tag
  versions the *algorithm*, not the *key* — so rotating the pepper invalidated
  **every** client secret at once, and every OAuth2 client and service account
  had to be re-issued in lockstep with the restart.

  Set the new `AXIAM__AUTH__PEPPER_PREVIOUS` to the outgoing value for the
  duration of a rotation: pre-rotation hashes still verify, and each secret is
  transparently rewritten under the new pepper the first time its owner
  authenticates, so the rotation drains itself with no downtime and no
  re-issuance. Nothing is ever *written* under the previous key. **See the
  rotation procedure in `docs/deployment/README.md` before rotating.**

  A stored key id was deliberately not used instead: it would hand anyone with a
  table dump an offline oracle for testing pepper guesses, which does not exist
  today. Both keys are tried unconditionally while a rotation is configured, so
  response time does not reveal which pepper era a row is in.

- **Service-account client secrets can now migrate hash schemes (§13.4
  observation 4).** `service_account` wrote the current scheme on create/rotate
  but had no `upgrade_client_secret_hash`, so an existing row never migrated no
  matter how often it authenticated — meaning the legacy v1 verifier arm could
  not be retired on the strength of "no v1 `oauth2_client` rows remain". The
  repository now exposes the same tenant-scoped compare-and-swap upgrade the
  OAuth2 client repository has, which also carries pepper-rotation rewrites.
  (Superseded above: the seam has no production caller because nothing verifies
  a service-account secret, so these rows migrate by **rotation**, not lazily.)

- **The cache-invalidation publisher recovers its channel (§13.4 observation 2).**
  It held one channel created at startup and never replaced, while the consumer
  side was fully supervised with backoff — so a single channel-level exception
  made every access-narrowing mutation return `503` for the rest of the process
  lifetime, clearing only on restart. The channel is now opened lazily and
  reopened after any failure.

- **Cross-replica authorization decision-cache invalidation over RabbitMQ (§4.2, threat-model `T-88`).**
  The decision cache invalidated **process-locally**: on a replica that did not
  handle the mutation, a revoked grant could stay `Allow` until its entry
  TTL-expired (default 5 s). That residual was documented and accepted; it is
  now closable. Setting `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED=true`
  (on top of `AXIAM__AUTHZ__DECISION_CACHE_ENABLED=true`) publishes every
  invalidation to the **fanout** exchange `axiam.authz.cache.invalidate`; each
  replica binds its own exclusive auto-delete queue
  `axiam.authz.cache.invalidate.<replica-uuid>` and applies what it receives,
  so a revocation reaches *all* replicas in broker-latency time. Fanout, not a
  work queue: a shared queue would deliver each invalidation to exactly one
  consumer and leave every other replica stale.

  **Default off, and inert when off.** With the switch unset, `invalidate_*` is
  local-only and infallible, no AMQP dependency is acquired by enabling the
  cache, and the previously documented TTL-bounded behaviour is unchanged.

  **Two deliberate behaviour changes when it is on**, both loud:
  - A mutation whose broadcast the broker does not confirm returns **503**
    (`"could not be broadcast to other replicas"`). The database write is
    durable but the fan-out did not happen, and reporting success would hand
    back the TTL window the operator enabled this to remove. These mutations are
    idempotent in the narrowing direction — retry is safe.
  - A replica whose invalidation consumer is not connected (startup, broker
    outage, partition) **stops serving from its cache** and evaluates every
    check against the database — correct, just slower — instead of serving
    allows it can no longer invalidate. Logged at ERROR
    (`AuthZ decision cache UNTRUSTED …`) and surfaced as `trusted` / `bypassed`
    on the periodic `AuthZ decision cache stats (D7)` line. Trust follows the
    consumer's connection liveness **only** — no inbound message can revoke it,
    so a captured broadcast cannot be used as a cache-disabling lever.

  Messages carry the existing §8 envelope (`CacheInvalidationMessage`):
  per-tenant HKDF-SHA256 subkey, `key_version >= 2` floor, per-message `nonce`,
  and an `issued_at` freshness window
  (`AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_SKEW_SECS`, default 30 s, tighter
  than the 5-minute AMQP default because an invalidation is only useful for
  about as long as the cache TTL). Nonce dedup is **per replica, in memory** —
  never the shared durable nonce store, which on a fanout would let one replica
  win and make all the others reject the invalidation as a replay. The
  publisher's own echo is a no-op, and cannot loop: a received message only ever
  reaches `DecisionCache`, never the publishing path. Granularity is exactly the
  cache's existing `invalidate_subject` / `invalidate_tenant`; no finer key is
  invented.

  Requires `AXIAM__AMQP__SIGNING_KEY` (already mandatory) to be shared by every
  replica. Documented in `docs/deployment/README.md`, `docs/admin/README.md` and
  `docs/deployment/authz-read-path.md`.

- **Client secrets are now hashed with HMAC-SHA256 keyed by the server pepper (OBS-1).**
  OAuth2 client secrets and service-account secrets were stored as an unsalted,
  single-round SHA-256 digest — safe only while every secret is 32 CSPRNG bytes with
  no operator-supplied path, an assumption held by nothing stronger than a code
  comment. The digest is now keyed, so a database dump is not offline-attackable
  without the pepper, and the guarantee no longer depends on secret entropy.
  HMAC rather than a KDF is deliberate: the client-credentials grant stays
  MAC-bound, not KDF-bound, and does not regress (verification is now
  allocation-free, where it previously allocated a `String` per request).

  **Operator action required.** `AXIAM__AUTH__PEPPER` is now **mandatory** — a
  release build fails closed at startup if it is unset, the same posture as
  `AXIAM__AUTH__SIGNING_KEY`/`AXIAM__AMQP__SIGNING_KEY` (SECHRD-08 / D-05c).
  There is no unkeyed fallback: silently degrading when unconfigured is exactly
  what OBS-1 objected to. A debug build resolves a documented dev-only pepper
  with a warning. Do not change the pepper after deployment without re-issuing
  every client secret — v2 hashes are not portable across peppers.

  Existing hashes cannot be re-derived (only the digest was stored), so the
  scheme is versioned and migrates lazily. Stored hashes are now tagged
  `v2.hs256$<hex>`; an untagged 64-hex value is verified against the legacy
  scheme and, **on a successful verification only**, rewritten in the new scheme
  with a compare-and-swap so a concurrent secret rotation is never clobbered. A
  failed verification never rehashes and never writes. No schema change and no
  backfill: migration completes as each client next authenticates.

  `axiam_db::hash_client_secret` is removed; hashing is a method on
  `axiam_auth::client_secret::ClientSecretHasher`, so no call site can hash
  without a key. `OAuth2ClientRepository` gains `upgrade_client_secret_hash`
  (breaking for out-of-tree implementors).

- **Session-revocation failures are no longer silently swallowed (OBS-3).**
  `invalidate`, `invalidate_user_sessions` and `cleanup_expired` never checked
  the DELETE result, so a statement-level database error was discarded and the
  method returned `Ok(())` — logout, password-reset revocation and MFA reset
  reported success when the statement may have failed. All five session-deleting
  methods now propagate a `DbError`. Cache invalidation is deliberately ordered
  *above* the newly-fallible step in every path, so a failing DELETE cannot
  strand a positive cache entry.

- **Startup advisory when the rate-limit bucket key is attacker-mintable (§4.1).**
  Under `AXIAM__RATE_LIMIT__KEY=client_id` the whole bucket key is read from the
  unauthenticated form body before the credential check, so a caller rotating
  `client_id` values mints fresh buckets. The shipped default (`ip`) is silent;
  `client_id` now emits a `warn!` naming the caveat and pointing at the sizing
  guide, and `ip_client_id` a softer `info!` — its unforgeable IP half confines
  the collateral to the attacker's own source.

### Added

- **CI gate: remediation evidence must resolve on `main` (§11.2).**
  `scripts/check-remediation-evidence.py` parses the remediation tables in
  `claude_dev/security-analysis-*.md` and verifies every cited commit is
  reachable from `origin/main` in the repository it claims. A recorded commit
  hash is not evidence a fix shipped — a hash exists the moment a commit is
  authored, on any branch — and this pass caught a real instance of a fix
  recorded as remediated while still unmerged. Rows that cannot be verified are
  printed individually under an explicit `SKIPPED, NOT VERIFIED` banner rather
  than passing silently.

- **`sdks/CONTRACT.md` §10.1 — minimum local-verification set (normative).**
  States once, for every SDK, what a guard must check before turning a token
  into an identity: signature with `alg` pinned before key lookup, `exp`
  REQUIRED, `nbf` honoured when present, `tenant_id` asserted against the
  configured tenant, `iss`/`aud` checked when configured, and a named bounded
  clock skew — all fail-closed. Written because `SEC-071` and `SEC-080` were the
  same defect found independently in two SDKs: each verified a different subset,
  and each subset looked complete in isolation.

### Fixed

- **gRPC admin ceiling no longer derives from the read-sized authz ceiling
  (SEC-079).** See the entry below for the units correction that made this
  necessary.

## [1.0.0-alpha23] - 2026-08-02

### Added

- Rust benchmark improved release build optimizations
- Present the client certificate in the PHP SDK bench
- Wire TLS into the C# SDK bench (CA + client certificate)
- Present the client certificate in the TypeScript SDK bench
- Wire TLS into the Kotlin SDK bench (CA + client certificate)
- Present the client certificate in the Java SDK bench
- Present the client certificate in the Python SDK bench
- Present the client certificate in the Rust SDK bench
- Present the client certificate in the Go SDK bench

### Changed

- All eleven SDK benches now pass the client-cert gate
- Complete the STRIDE threat model in Threat Dragon format

### Fixed

- Make the p2-tls13 and p3-mtls SDK matrices pass
- Make the p3-mtls path actually reachable end to end

## [1.0.0-alpha22] - 2026-07-31

### Added

- Add a dry-run mode to rehearse the matrix in minutes
- Raised RAM resources in benchmarks to improve Keycloak performance (Axiam and Zitadel performs well even with 1024m)

### Fixed

- Hold a live pool reference in repositories, not a boot-time clone

## [Unreleased]

### Added

- **OAuth2 Device Authorization Grant is reachable (RFC 8628, B2).** The
  grant's core, storage and state machine landed earlier; nothing was mounted,
  so no device could use it. Now: `POST /oauth2/device_authorization` issues
  the code pair, `POST /oauth2/token` serves
  `grant_type=urn:ietf:params:oauth:grant-type:device_code` with the full §3.5
  answer table (`authorization_pending`, `slow_down`, `expired_token`,
  `access_denied`, `invalid_grant`), and
  `GET /api/v1/device/verify` + `POST /api/v1/device/decide` back the
  verification page. The endpoint is advertised in OIDC discovery, because a
  device that can read discovery is exactly the client that cannot be told the
  URL out of band.

  The verification endpoints live under `/api/v1`, not `/oauth2`, and that is
  the design: approval records the approver as the subject the token is minted
  for (so the caller must be authenticated), and a short typed code is
  guessable from another origin (so CSRF double-submit is what stops a
  malicious page approving on a victim's session — RFC 8628 §5.4's phishing
  shape from the other direction). Unknown, expired and already-decided codes
  answer identically, so the page is not an oracle for which codes are live.

  Two new rate-limit buckets, neither sized from benchmark capacity:
  `AXIAM__RATE_LIMIT__DEVICE_AUTHORIZATION_PER_MIN` (12) because the endpoint
  is unauthenticated *and* allocates state, and
  `AXIAM__RATE_LIMIT__DEVICE_VERIFY_PER_MIN` (10), the user-code brute-force
  bound — `RateLimitConfig::validate` now **asserts** the OWASP condition
  against the grant lifetime, so raising it past the point where an
  8-character typed code becomes guessable fails at startup rather than in an
  incident review. See [`docs/api/device-flow.md`](docs/api/device-flow.md).

- gRPC rate limits are now scoped **per method family** instead of server-wide (I2). One
  bucket each for authz-check (`axiam.v1.AuthorizationService`), identity-read
  (`axiam.v1.UserInfoService`, `axiam.v1.TokenService`) and admin
  (`axiam.v1.UserService`), with gRPC reflection and health explicitly never limited and
  an unrecognized path failing safe into the strictest bucket. Two new knobs,
  `AXIAM__GRPC__GRPC_IDENTITY_PER_SEC` (default 5x the authz ceiling = 500/s) and
  `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` (default a flat 10/s — see the posture note under
  *Security* below); leaving `GRPC_IDENTITY_PER_SEC` unset derives it from
  `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC`, so a posture preset still moves that pair with one
  variable. Previously a `GetUserInfo` read — measured at 12 665/s — was throttled
  by the *authz* ceiling, because a single server-wide bucket made an authorization sizing
  decision into a userinfo sizing decision
- Startup advisory for mis-sized machine limits: when the shipped `internet` defaults are
  what a process is actually enforcing (no posture preset, no machine limit pinned by
  hand) and the sustained 429 ratio on the machine endpoints exceeds ~50% over a 5-minute
  interval, the server logs "your limits are throttling what looks like legitimate machine
  traffic; see rate-limit-sizing". Built on the write-behind rate-limit counter's existing
  flusher pass — no new background task, no new timer, and human endpoints are excluded
  from the ratio by construction (a 429 storm on `/auth/login` is a credential-stuffing
  signal, not a sizing signal)
- Benchmark dry-run mode (`just bench-dry-run`, `just dry=1 bench-run`) — rehearses the
  whole target × profile matrix over the same bring-up/seed/run/tear-down path in minutes,
  grading each cell on the k6 client contract (connect, request, expected response) instead
  of on performance, so a break surfaces before an hours-long matrix commits to it
- Optional **session-validation cache** (I6), `AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS`
  (default `0` = off). Every authenticated REST request re-reads the `session` row behind
  the access token's `jti` to enforce D-15 revocation; that read is not covered by the
  authorization decision cache, which is why turning the decision cache on lifted gRPC
  authorization checks 13.1x but REST checks only 5% in benchmark run 4 — the gRPC
  interceptor has no equivalent read. The cache stores **positive answers only**, carries
  each session's own `expires_at` (so expiry is never extended), and is invalidated by every
  session-deleting method on the repository, so on a single replica a logout still takes
  effect immediately. Multi-replica deployments inherit the same bounded-staleness caveat as
  the decision cache and should leave it off or match its TTL
- `AXIAM__SERVER__TCP_NODELAY` (default `true`, I5) — actix-web leaves `TCP_NODELAY` unset
  unless asked, so the REST listener ran with Nagle's algorithm enabled while the gRPC
  listener (tonic, which defaults it on) did not. Set `false` to restore the previous
  behaviour for A/B measurement
- Per-stage timing instrumentation on the OAuth2 client-credentials path (I5) —
  `client_lookup_us`, `secret_verify_us`, `tenant_lookup_us`, `token_mint_us`,
  `handler_total_us` on the `oauth2.client_credentials` span, plus `exchange_us`,
  `serialize_us` and `response_body_bytes` from the token endpoint, re-emitted as DEBUG
  events on `target: "axiam::perf"`. Measurement is unconditional (five `Instant::now()`
  reads, well under 0.1% of the handler) and only reporting is gated by the tracing level
- `crates/axiam-db/tests/authz_query_plan_test.rs` — `EXPLAIN`-based query-plan pins for
  the authorization hot path, so a rewrite that reintroduces a table scan fails in CI rather
  than in production. Includes witness tests proving the removed forms really did scan
- [`docs/deployment/authz-read-path.md`](docs/deployment/authz-read-path.md) — what one
  authorization check costs against SurrealDB, which cache removes which round-trip, and a
  design note on read-replica topology for authorization reads (analysis only; not
  implemented)

### Changed

- Revised the shipped `internet` machine-endpoint rate-limit defaults (I3), sized from the
  run-4 measured capacity of each endpoint: `TOKEN_PER_MIN` 20 → **120**,
  `INTROSPECT_PER_MIN` 10 → **600**, `AUTHZ_CHECK_PER_MIN` 300 → **1800**,
  `REVOKE_PER_MIN` 10 → **60**. The old numbers sat four to five orders of magnitude below
  the machine's ceiling (token 20/min against ~163 000/min of capacity) and broke the first
  healthy integration behind a NAT without protecting anything the new ones fail to
  protect; every revised value still stays 25–2 700x below measured capacity. **Human
  endpoints (login, register, password-reset, MFA) are unchanged** — they are sized against
  credential guessing, never against capacity. The `gateway`/`mesh` presets are unchanged.
  If you pinned any of these with an env var, nothing changes for you: explicit env still
  beats both the preset and the shipped default

### Fixed

- Two **full table scans on the authorization hot path** (I7). Every uncached authorization
  check — REST, gRPC and AMQP alike — walked the whole `grants` table (every role-to-permission
  grant of every tenant) and the whole `has_role` table (every role assignment of every user
  of every tenant), because both predicates were written in forms the SurrealDB planner
  cannot serve from an index: `WHERE meta::id(in) IN $role_ids` wraps the indexed field in a
  function call, and `WHERE in IN (SELECT VALUE out FROM member_of WHERE ...)` leaves a
  correlated sub-select on the right-hand side. `EXPLAIN` reported
  `TableScan { pre_decode_filter: "no (unsupported predicate)" }` for both. They now compare
  against bound record ids and a pre-resolved `LET` binding respectively and plan as
  `IndexScan` over the existing `idx_grants_unique` / `idx_has_role_unique` composite indexes
  — no schema change, identical rows returned. The cost was invisible on a small seed and
  grew with total database size, which is consistent with SurrealDB showing up as the
  product's throughput ceiling in benchmark run 4
- gRPC rate limits were enforced at **1/60th of the configured rate** (I1). The gRPC
  ceiling is per second, but the cross-replica shared pre-check runs the same fixed
  60-second window as the REST limiter and was handed the per-second number verbatim; since
  the stricter of the two cooperating layers wins, `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC=100`
  admitted ~100 requests per *minute*. The per-second → per-window conversion now happens
  once, at the layer boundary, with a saturating multiply, and the production constructor
  takes per-second ceilings so a caller cannot get the units wrong again. Found by benchmark
  run 4's production-posture pass. **Read the gRPC admin-ceiling entry under *Security*
  below before upgrading** — correcting these units raised every gRPC ceiling 60x, which is
  a posture change and not only a units fix
- Stale DB handles after a reconnect: every repository was built at boot from a one-time
  `pool.handle_for_repo()` **clone** of the pooled SurrealDB connection, so when the pool's
  reconnect loop evicted a poisoned connection (observed ~7 minutes into a sustained load
  run) every repository stayed pinned to the dead one and returned 401 permanently until
  the process restarted — while `/ready`, which probes through the pool slot, still
  reported healthy. Repositories now hold a live `DbHandle` over the pool slot and resolve
  the current connection per query, so a swap is picked up on the very next query. The REST
  `AppState.db` (bootstrap handler, tenant seeder) and the gRPC layer's handle held the same
  boot-time clone and were fixed the same way
- `meta.json` could be written as invalid JSON when a host fact spanned two lines — a
  `docker version` against an unreachable daemon prints an empty line and *then* fails, so
  the `|| echo unknown` fallback produced a literal newline mid-string and took `report.py`
  down with an "Invalid control character" for the whole run

### Security

- **gRPC admin/credential-check ceiling is now an absolute 10/s (600/min per IP), not the
  authz ceiling (SEC-079). This is a posture change — read it even if you skipped the
  units fix above.** Correcting the gRPC rate-limit units (I1, under *Fixed*) changed what
  every gRPC ceiling actually enforces from `N` per **minute** to `N` per **second**. The
  units bug had been accidentally supplying 60x more protection than the configuration
  said, so an operator who reads only "corrected gRPC units" will not realise their
  deployed gRPC ceiling rose 60x on upgrade. That matters most on
  `axiam.v1.UserService/ValidateCredentials`, which performs a real Argon2id password
  verification (~19 MiB of memory arena each): its per-IP ceiling would have gone from
  ~100/min to ~6 000/min — a 60x increase in online password-guessing throughput and in the
  Argon2id CPU a caller can conscript. The admin family therefore no longer derives from
  `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC` at all; it takes a CPU-appropriate absolute default of
  10/s, unchanged by `AXIAM__RATE_LIMIT__PROFILE`, so raising the authz ceiling for
  service-mesh capacity can no longer widen credential guessing as a side effect. The
  family holds only `GetUser` and `ValidateCredentials`; the high-volume identity read is
  `GetUserInfo` on `UserInfoService`, which is in the identity-read family and unaffected.
  **Action:** if a provisioning or admin workload legitimately exceeds 600 `UserService`
  calls per minute from one source IP, pin `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` — explicit
  configuration still wins over both the default and any posture preset. Per-account
  lockout, the shared failure metering and the process-wide crypto semaphore are unchanged
- gRPC reflection and health are no longer an **unlimited pass-through**. The family is
  selected by prefix-matching the client-supplied gRPC `:path` (`/grpc.reflection.`,
  `/grpc.health.`) and used to bypass both limiter layers entirely. Neither service is
  registered today — requests terminate `Unimplemented`, so the practical effect was
  unmetered HTTP/2 stream churn rather than database work — but registering a health
  service would have made it a genuinely unmetered endpoint. It now has its own bucket at a
  fixed 100/s per IP: orders of magnitude above any real probe cadence, so a liveness probe
  still answers during an incident when every other family is saturated, while the surface
  stops being unbounded
- Group-membership traversal on the authorization read path now carries a read-time tenant
  predicate. `get_user_role_assignments` resolved `member_of` edges with no
  `out.tenant_id` filter; this was not exploitable — group membership is validated against
  the tenant at write time and the outer `has_role` predicate still confined the resulting
  role — but it left group-inherited roles as the one authorization edge with no read-time
  tenant check, so a migration or bulk import writing `member_of` directly would have
  bypassed it. The predicate is served by the existing `idx_member_of_unique` index; the
  query-plan pins confirm the plan is still an `IndexScan`
- Session-cache invalidation now runs immediately after the `DELETE` commits, before the
  deleted rows are deserialized, in `consume` and `invalidate_user_sessions_except`. The
  `DELETE` has already succeeded at the database once the await returns, so a deserialize
  failure of the returned BEFORE image used to return early and leave a **positive**
  session-validation cache entry live for up to the TTL — a deleted session that kept
  validating. Only reachable with the opt-in
  `AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS` enabled
- **Session revocation no longer reports success when the `DELETE` failed (OBS-3).**
  `SessionRepository::invalidate`, `invalidate_user_sessions` and `cleanup_expired` awaited
  their `DELETE` and returned `Ok(())` without ever calling `.check()` or `.take()`, so a
  statement-level SurrealDB failure was discarded — logout, password-reset session
  revocation and MFA reset all told the caller sessions were revoked when the statement may
  never have run. All five session-deleting methods now `.check()` the response and
  propagate a `DbError`, which surfaces as `500` at `POST /api/v1/auth/logout` and the GDPR
  disable path rather than as a silent `204`. Cache invalidation deliberately still runs
  **before** the new fallible step, so the ordering fix above cannot be reintroduced: an
  erroring `DELETE` drops the cache entry (costing at most one avoidable re-read) instead of
  stranding a positive "still valid" entry
- Startup **warning** when `AXIAM__RATE_LIMIT__KEY=client_id` is active. In that mode the
  rate-limit bucket key for `/oauth2/{token,introspect,revoke}` is the `client_id` read from
  the unauthenticated form body (RFC 6749 §2.3.1) **before** any credential check, so a
  caller rotating `client_id` values mints a fresh bucket per value; under this mode those
  limits are a fairness control between cooperating clients, not an anti-abuse control, and
  the mode assumes an edge (mTLS / API gateway / WAF) that already authenticates callers.
  The warning names that and points at `docs/deployment/rate-limit-sizing.md` §5. The
  shipped default (`ip`) is not attacker-mintable and stays **silent**; the partially
  mintable `ip_client_id` gets a softer `info!` note, because its source-IP half still
  prevents a third party from exhausting a known `client_id`'s bucket from elsewhere. No
  behaviour or limit changes — advisory only, matching the I3 machine-traffic advisory and
  the session-validation cache's startup `warn!`
- CI now verifies that **remediation evidence actually shipped**
  (`scripts/check-remediation-evidence.py`, wired into `docs-ci.yml`). A remediation record
  citing a commit hash is not evidence a fix merged — a hash exists the moment a commit is
  authored, on any branch, and the 2026-08-03 review pass caught a real instance (a Swift
  fix recorded as remediated while still unmerged). Every `(finding id, repo, commit)`
  triple in a remediation table of `claude_dev/security-analysis-*.md` must now resolve to a
  commit reachable from the default branch of the repo it claims: locally via
  `git merge-base --is-ancestor`, and for the out-of-tree SDK repos via the GitHub API when
  the token can read them. Rows that cannot be verified are printed as **SKIPPED by name**
  rather than passing silently, and a row that cannot be parsed into a triple **fails** the
  check naming the row

## [1.0.0-alpha21] - 2026-07-30

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha20.

## [1.0.0-alpha20] - 2026-07-30

### Added

- Opt-in rate-limit posture presets + TLS/h2 tuning surface (G7, G8 in progress)
- G9 — throttle-aware metrics and the gRPC/REST authz analysis
- G2 harness countermeasures, G4 refresh fix, G5 cache-sweep scenario
- Per-task data-collection script for the pre-MVP plan
- Run-3 benchmark page refresh + benchmark-derived sizing docs

### Changed

- Add the run-4 execution runbook
- Bump the version marker to 1.6 and record the follow-up audit findings
- Add §9 rule 6 — single-flight guard implementation invariants (contract 1.6)
- Bump frontend/coverage/website-publish Node from 20 to 22
- Bump jsonwebtoken from 10.4.0 to 11.0.0
- Bump jsdom from 29.1.1 to 30.0.1 in /frontend
- Use the obviously-fake password fixture convention in the users split test
- Verify the write-behind clamp fix on a local rl-fix-local build
- Document the write-behind shared counter and its security bound
- Note why REST and gRPC each hold their own shared counter
- Adapt the shared-store middleware suite to write-behind counting
- Serve shared rate-limit decisions from the write-behind counter
- Add write-behind SharedRateLimitCounter + increment_by
- Mark the bench admin default in h5-revocation-check.sh as a throwaway fixture
- H10(5): finalize §6 execution record with the validated H10 outcome
- H10(4): report.py — settle_timeout refusal is now scenario-aware, not session-wide
- H10(3): consistency pass — methodology.md §12 + append §6 execution record
- H10(2): E4 — fourth public benchmark draft
- H10(1): consistency pass — reconcile PRIVATE_BENCH_ANALYSIS.md with H2/H3/H4/H5/H9 verdicts
- H8(5): profile-scope SDK result storage, README truthful status table, per-language TODO notes
- H8(4): wire BENCH_CA_CERT into 5 SDK benches for p2, integrate E1.3 overhead table into report.py
- H8(3): fix refresh-op concurrency in python/typescript benches (HARNESS-SPEC required conc=1, neither implemented it)
- H8(2): fix server CSRF header-echo + go bench org_slug — both blocked every SDK bench end-to-end
- H8(1): per-language SDK bench fixes — rust seed env, python venv, ts npm link, go.sum, java compile, csharp preflight, php minimum-stability
- H7(1): confirm the REST/gRPC classifier wiring live; correct the stale G9 note
- H7(3b,4): measure the gateway rate-limit preset live; close the Keycloak p0-vs-p2 login asymmetry
- H7(1,3a,5): protocol-variant label, maintainer sign-off block, H4 control-build fix
- H6(7): measure the CC clamp control instead of asserting it, and price the noise
- H6(6): publish the B2 position — TLS priced, HTTP/2 acquitted, CC still open
- H6(5): close B2 in the private analysis
- H6(4): document bench_http_proto in the methodology metric list
- H6(3): the h2 hypothesis is refuted by counting connections
- H6(2): h6-tls-proto task + a connection/worker-affinity probe
- H6(1): capture the negotiated HTTP protocol, and make the h1 control honest
- H5(4,5): decision-cache verdict — default STAYS opt-in, flip blocked on C1/C2/C4
- H5(3): automate the live-stack revocation check; run the K-sweep under TLS
- H5(1): fix the three decision-cache defects surfaced by the G5 review
- H9: DB-pool default decision — keep pool_size=1, close negative
- H2: G1 endgame — the "post-seed transient" is the shared rate-limit write
- H1: drain pause after settle gate to prevent straggler-traffic contamination
- H4: jemalloc as the release-container default allocator (executes G6 PASS)
- H1.5: report.py refuses cells whose meta records settle_timeout:true
- H1.2: fix bench-matrix results-dir clobber + fail-fast task-script guard
- H1.1: settle gate v2 — concurrent burst probe replaces serial canary
- H3: flip authz batch strategy default to coalesced (G3 decision)
- Phase H plan from the verified 2026-07-28 G-task results
- Use UUIDv7 for persisted record identifiers
- Amend CONTRACT to 1.5 from the cross-SDK §12 conformance review
- Add CONTRACT §12 OIDC/SSO relying-party helpers (contract 1.4)
- Add SDK OIDC/SSO relying-party helpers implementation plan
- Correct the published client_id rate-limit guidance with its security caveat
- G7 rate-limit posture decision record
- G8 security-profiles update + implementation status for the pre-MVP plan
- G8 — B2 HTTP/2 investigation and the ALPN knob fix
- Bump base64 from 0.22.1 to 0.23.0
- Bump the minor-patch group in /frontend with 12 updates
- Bump actions/download-artifact from 4.3.0 to 8.0.1
- Bump taiki-e/install-action from 2.83.2 to 2.85.2
- Bump bufbuild/buf-action from 1.4.0 to 1.5.0
- Bump coverallsapp/github-action from 2.3.7 to 2.3.8
- Bump docker/login-action from 3.4.0 to 4.5.1
- Use UUIDv7 for persisted record identifiers
- Amend CONTRACT to 1.5 from the cross-SDK §12 conformance review
- Add CONTRACT §12 OIDC/SSO relying-party helpers (contract 1.4)
- Add SDK OIDC/SSO relying-party helpers implementation plan
- Run-3 analysis, D9 experiment script, pre-MVP improvement plan

### Fixed

- Select jsonwebtoken 11's rust_crypto backend explicitly
- Stop charging GET /api/v1/users to the users_create limiter
- Make g1-dbdirect's direct SurrealDB probe actually run
- Resolve g1-dbdirect's DB credentials from the running stack
- Interrupt-safe teardown for every task that holds a stack
- Unwedge the G1 tasks' telemetry sampler
- Dial gRPC over TLS in p3-mtls; record real gRPC status
- Resolve p3-mtls client cert path from any CWD

## [1.0.0-alpha19] - 2026-07-25

### Fixed

- Migrate react-router-dom v7 -> react-router v8 (GHSA-qwww-vcr4-c8h2)

## [1.0.0-alpha18] - 2026-07-24

### Changed

- Workspace coverage improvements toward >=90% (T2-T6), scanner-clean
- Plan to push Coveralls badge over 90% with per-task model picks
- Ratchet line-coverage floor 77 -> 80 and surface achieved total
- Runtime-generate the new-password arg in confirm_reset test
- Close residual gaps in password_reset and pgp
- Satisfy rustfmt, clippy, and CodeQL on the new coverage tests
- Exclude axiam-server binary composition root from coverage
- Cover SAML/OIDC non-xmlsec logic and negative paths
- Broker-free seams for authz/audit consumers + fix auth rand_core
- Cover residual repository CRUD/error paths + seeder + nonce-replay
- Cover cleanup.rs expiry sweeps and erasure pipeline branches
- Cover federation/auth/webhook/password-reset/rbac error paths
- Round-2 test-coverage plan for server + C SDK with per-task model picks
- Bump docker/build-push-action from 6.15.0 to 7.3.0 (#213)
- Bump @testing-library/jest-dom in /frontend (#216)
- Bump actions/setup-node from 6.4.0 to 7.0.0 (#214)
- Bump dtolnay/rust-toolchain (#212)
- Test-coverage improvement plan for server + 11 SDKs (2026-07-23 baseline) (#227)
- Bump the minor-patch group in /frontend with 8 updates (#215)
- Bump actions/checkout from 7.0.0 to 7.0.1 (#211)
- Bump actions/attest-build-provenance from 2.4.0 to 4.1.1 (#210)
- Correct model attribution and add phase dates to roadmap (#226)
- Rewrite laptop runbook for run 3 against released 1.0.0-alpha17

## [1.0.0-alpha17] - 2026-07-22

### Changed

- Updated dependencies for security fixes

## [1.0.0-alpha16] - 2026-07-22

### Added

- Add AXIAM gRPC userinfo scenario + protocol-efficiency pairing
- Implement UserInfoService and integration tests
- Add gRPC UserInfoService/GetUserInfo (contract 1.3)
- Add missing SDKs, gRPC + config docs, real benchmark data
- Implement run-2 follow-up tasks (A8, A9, D10, D11, report polish)

### Changed

- Use a random seeded-user password in userinfo tests
- Add gRPC userinfo implementation plan
- Run-2 analysis (1.0.0-alpha15) — update public/private bench docs + plan

### Fixed

- Make concurrent batch future boxable behind AuthzChecker trait

## [1.0.0-alpha15] - 2026-07-21

### Added

- F2 — DbPool of N independent handles, wire repositories, close CQ-B48
- F1 — connection-pool design doc + boundary instrumentation
- D7 — decision caching behind a flag (default off) with revocation invalidation
- D8 — configurable rate-limiter key (ip|client_id|ip_client_id)
- D3 — native mTLS (client-certificate) auth
- B1 — bound concurrent Argon2id hashing (perf + memory-DoS fix)
- AXIAM native (in-process) TLS for the p2-tls13 profile
- TLS profiles for keycloak + zitadel; RSA certs; port pre-flight
- Auto-provision Zitadel client via management API

### Changed

- Regression test for gRPC-over-TLS crypto provider
- Fix stale F1/F2 status rows (still showed "planned" post-merge)
- Mark E1.2 done (four stub SDK benches wired)
- Wire the four stub SDK benches (c, cpp, kotlin, swift)
- Cargo fmt F2 (DbPool)
- Cargo fmt F1 instrumentation wiring
- Laptop re-run runbook + Phase F (DB connection pooling)
- Cargo fmt (rustfmt CI fix)
- Per-task implementation status table
- D9 — optional jemalloc allocator for RSS-retention experiment
- Drive gRPC over TLS at p2 (native gRPC TLS wiring)
- B3 — JWKS in-process cache + HTTP caching headers (ETag/304)
- D1 — coalesce same-subject authz batches + tracing
- B2 — TLS 1.3 throughput diagnosis + fixes on token endpoints
- Zitadel gRPC benchmark coverage
- AMQP async-authz load harness design
- Real Zitadel login via session API v2 (password verification)
- SurrealDB tuning investigation — preliminary static analysis
- Re-run protocol — median-of-N, DB tuning, laptop runbook, prod posture
- Harness correctness & honesty (A1–A7)
- Expand plan E1 — implement & validate the SDK client benches
- Benchmark improvement implementation plan; refine throttling assessment
- Add public + private analysis of the first full benchmark run
- Re-enabled pepper and moved compose to latest AXIAM image version

### Fixed

- Make Keycloak and Zitadel seed users loginable
- Install ring rustls CryptoProvider so gRPC-over-TLS works
- Serialize F1 gauge tests against shared-static race (flaky CI)
- Give the E2E backend-startup step real timeout margin
- Correct actix test app-factory return type (D8 integration test)
- Fill new config fields in remaining test literals
- Clippy collapsible-if, grpc test field, OpenAPI drift
- Gate bench-up on target HTTP readiness

## [1.0.0-alpha12] - 2026-07-19

### Fixed

- Require organization context for login/refresh (#204)

## [1.0.0-alpha11] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha10.

## [1.0.0-alpha10] - 2026-07-18

### Added

- Add --changelog to summarize commits into CHANGELOG.md

### Changed

- Wire org context into the TypeScript bench; list all 11 SDKs in README (#199)

### Fixed

- Wire Keycloak TLS via entrypoint; stop passing empty KC_HTTPS_*
- Correct image labeling metadata for GHCR
- Drop --optimized from Keycloak first start
- Dial gRPC plaintext regardless of HTTP TLS profile
- Merge tlsOptions() into gRPC scenarios so cert-skip applies
- Skip k6 server-cert verify for private-CA TLS profiles
- Neutralize rate limits so p0 measures endpoint capacity
- Apply the configured password pepper when hashing the admin (#200)
- Don't set AXIAM__AUTH__PEPPER (breaks bootstrap-admin login)
- Write resource CSV rows; configure OAuth2/optional secrets; skip OAuth2 when unset
- Supply org context on login; make bench-down work without secrets
- Provide mandatory AMQP signing key for the AXIAM target
- Bootstrap AXIAM secrets in bench-up; auto-track image tag
- Correct just variable-override ordering so bench-matrix works

## [1.0.0-alpha3] - 2026-07-16

Third alpha. Build/release tuning and project-infrastructure changes only. No
server runtime or API behavior changes — the OpenAPI specification is
byte-for-byte identical apart from its `info.version` string.

### Added

- **Public marketing & documentation website**, deployed to GitHub Pages.

### Changed

- **Release build profile** — added `[profile.release]` to the workspace-root
  `Cargo.toml`, tuned for execution speed first and footprint second:
  `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `strip = "symbols"`.
  Cargo only honors profiles at the workspace root, so this single section
  covers `axiam-server` and every crate it links. `panic = "abort"` is
  intentionally omitted to preserve per-request panic isolation on the
  long-running REST/gRPC/AMQP server. Release builds are slower in exchange for
  faster runtime.

## [1.0.0-alpha2] - 2026-07-16

Second alpha. Adds the SDK declarative-authorization contract and release-prep
polish; no server runtime/API behavior changes.

### Added

- **CONTRACT.md §11 — Declarative Authorization Helpers**: the canonical
  `require_auth` / `require_access(action, resource[, scope])` / `require_role`
  vocabulary layered on the §10 guard, with the per-language naming map and
  normative semantics (subject propagation, 401/403/400/503 error mapping,
  fail-closed on transport error, no decision caching). Marked SHOULD-level and
  recorded as non-breaking/additive; contract version bumped to 1.1.
- README build/coverage/license badges.

### Changed

- Roadmap "Development Progress": Phase 17 (SDKs) and Phase 18 (security audit)
  marked Done.

### Fixed / CI

- Added a free-disk-space step to the heavy Rust `test` and `cargo-llvm-cov`
  jobs to prevent the RabbitMQ disk-space alarm that intermittently failed CI.

## [1.0.0-alpha1] - 2026-07-16

Patch release over `1.0.0-alpha` that fixes the release pipeline so the
aarch64 server binary and the OpenAPI drift gate build cleanly. There are no
functional or API changes — the OpenAPI specification is byte-for-byte
identical apart from its `info.version` string.

### Fixed

- **aarch64 release build** — the *Build Release Binary (aarch64)* job failed
  at "Install build dependencies" because the native `ubuntu-24.04-arm` runner
  intermittently could not reach `ports.ubuntu.com` (IPv6 unreachable, IPv4
  timeouts). The apt step now forces IPv4, prefers Azure's in-network ports
  mirror, and retries with backoff, without changing the installed package set.
- **OpenAPI version drift** — the REST spec's `info.version` was a hardcoded
  literal that fell out of sync with the crate version and failed the OpenAPI
  drift gate. It is now bound to `CARGO_PKG_VERSION`, so it always tracks the
  workspace version and cannot drift on a future version bump.

[1.0.0-alpha1]: https://github.com/ilpanich/axiam/releases/tag/axiam-server/v1.0.0-alpha1

## [1.0.0-alpha] - 2026-07-15

First alpha release of AXIAM (Access eXtended Identity and Authorization
Management). This is an early, pre-production preview intended for evaluation
and feedback — APIs and data models may still change before the beta and
stable releases.

### Added

- **Multi-tenancy** — organizations as top-level entities containing fully
  data-isolated tenants; all domain entities (users, groups, roles,
  permissions, resources, certificates) are tenant-scoped.
- **Authentication** — username/password (Argon2id), MFA (TOTP), social login
  and certificate-based (mTLS) authentication; EdDSA (Ed25519) JWT access
  tokens with opaque, single-use, rotating refresh tokens.
- **Authorization** — additive, default-deny RBAC engine with role
  inheritance through hierarchical resources, scopes for sub-resource
  granularity, and group-inherited role assignments.
- **OAuth2 / OpenID Connect** — authorization server and OIDC provider
  (Authorization Code + PKCE, Client Credentials, Refresh Token).
- **Federation** — SAML SP and OpenID Connect federation for cross-domain SSO.
- **APIs** — REST (Actix-Web, OpenAPI-documented), gRPC (Tonic) for
  low-latency authz checks, and AMQP (Lapin) for async/deferred authz, audit
  ingestion and event notifications.
- **PKI** — per-tenant X.509 certificate management signed by an organization
  CA, with CA private keys encrypted at rest (AES-256-GCM); GnuPG/OpenPGP
  integration for audit signing and encrypted data exports.
- **Auditing** — append-only audit logging.
- **Webhooks** — real-time event notifications to external systems, signed
  with HMAC-SHA256.
- **Admin frontend** — React + TypeScript administration UI.
- **Packaging & deployment** — multi-arch (amd64/arm64) container images and
  standalone server binaries, Docker Compose and Kubernetes manifests.
- **Client SDKs** — Rust, TypeScript, Python, Java, C#, PHP and Go SDKs, each
  released in its own repository against the shared API contract.

[1.0.0-alpha]: https://github.com/ilpanich/axiam/releases/tag/axiam-server/v1.0.0-alpha
