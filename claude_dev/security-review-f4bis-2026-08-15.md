# F4-bis — Consolidated security review of everything after 2026-08-10

> **Scope:** the work that landed after
> [`security-review-b-track-2026-08-10.md`](security-review-b-track-2026-08-10.md)
> (F4) closed at SEC-092 — X3 (MDS3/WebAuthn attestation), X4 (external-IdP token
> exchange), X5/X5.1 (FAPI, mTLS, DPoP, `private_key_jwt`), X6 (single-use
> redemption), X1/R2.2 (Reactors, now reachable code) and B4 (SCIM 2.0) — plus the
> three surfaces F4 §6 recorded as **sampled, not exhausted** and Wave R6 promotes
> to read-in-full: `par.rs`, the AMQP TLS config/connection path, and the gRPC
> strict-revocation interceptor.
>
> **Reviewer:** Opus 5, per the R6 model recommendation.
>
> **Verdict: three HIGH findings, and they block.** Two are live at HEAD
> (SEC-093, SEC-094); one is latent only because the reactor transport it depends
> on has not merged (SEC-095), and is cheapest to close in the same change that
> merges it. Eight medium findings and four low follow. The six items routed to
> this review during the run are adjudicated in §14.

---

## 0. BLOCKERS — read this section first

| ID | Finding | Live at HEAD? | One-line fix direction |
|---|---|---|---|
| **SEC-093** | Five OAuth2 endpoints authenticate a client by **shared secret only**, ignoring the `token_endpoint_auth_method` its registration declares. A `tls_client_auth` / `private_key_jwt` client's auto-generated secret is a working credential at PAR, revoke, introspect, token-exchange and uma-ticket. | **Yes** | Route those five through `authenticate_client_credential`, not `authenticate_client`. |
| **SEC-094** | `axiam_pki::ssrf::is_disallowed_ip` does not canonicalise **IPv4-mapped IPv6**. An `AAAA` record of `::ffff:169.254.169.254` (or `::ffff:127.0.0.1`, or any RFC1918 address) passes the guard and is then *pinned* into the connection. Reachable by any tenant admin who can set a webhook URL, a `jwks_uri`, a SAML/OIDC metadata URL or the MDS URL. | **Yes** | `ip.to_canonical()` before the match; add `100.64.0.0/10`. |
| **SEC-095** | The `login.post_auth` reactor veto fires **only on the password login path**. SAML and OIDC SSO logins create a session without ever consulting the gate. The plan's own canonical example for the feature is an "embargoed-region login veto". | Latent — no dispatch can succeed until the lapin transport merges | Either hook the two federation call sites, or state the scope normatively in §22 and in the event registry description. |

Everything below SEC-095 is medium or lower and does not block.

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| External-IdP subject-token verification | X4 | `crates/axiam-federation/src/token_exchange.rs` (833) | **read in full** |
| External exchange grant + ports | X4 | `crates/axiam-oauth2/src/token_exchange.rs` (1839) | **read in full** |
| RBAC scope authority (X4 gate 3) | X4 | `crates/axiam-api-rest/src/token_exchange.rs` (246 + tests) | **read in full** |
| Trust config / validation | X4 | `crates/axiam-core/src/models/federation.rs` §X4 block | **read in full** |
| DPoP | X5.1 | `crates/axiam-oauth2/src/dpop.rs` (932) | **read in full** |
| `private_key_jwt` | X5.1 | `crates/axiam-oauth2/src/private_key_jwt.rs` (1040) | **read in full** |
| mTLS client auth + binding | X5.1 | `crates/axiam-oauth2/src/mtls.rs` | **read in full** |
| Binding-enforcement order in the token path | X5.1 | `token.rs:551-660, 930-1060, 1274-1330, 1434-1490`; `handlers/oauth2.rs:303-635` | **read in full** |
| FAPI profile gate | X5 | `crates/axiam-oauth2/src/fapi.rs` | **read in full** |
| MDS3 BLOB chain verification | X3 | `crates/axiam-pki/src/mds/{blob,mod}.rs` | **read in full** |
| Attestation enforcement diff | X3 | `axiam-auth/src/{attestation,webauthn}.rs`, `axiam-core/models/webauthn_policy.rs` | **read in full** |
| Layered single-use + engine attestation | X6 | `axiam-db/src/repository/permission_ticket.rs`, `engine_attestation.rs` (486); `device_grant.rs` / `pushed_auth_request.rs` headers + `consume` | **read in full** (ticket), header+consume (other two) |
| Reactor gate, dispatcher, protocol, registry | X1/R2.2 | `axiam-amqp/src/reactor/{gate,dispatcher,protocol}.rs`, `axiam-core/models/reactor.rs`, `axiam-api-rest/src/reactor_hooks.rs`, five call sites, `axiam-server/src/main.rs:585-660` | **read in full** |
| SCIM 2.0 | B4 | whole `crates/axiam-scim` (`auth`, `routes`, `users`, `groups`, `patch`, `filter`, `schema`, `error`) | **read in full** |
| PAR | B5a | `crates/axiam-oauth2/src/par.rs` (295) + the authorize call site | **promoted to read-in-full** |
| AMQP TLS | A6 | `crates/axiam-amqp/src/{config,connection}.rs` TLS paths | **promoted to read-in-full** |
| gRPC strict revocation | A4 | `axiam-api-grpc/src/middleware/{strict_revocation,auth}.rs` | **promoted to read-in-full** |
| SSRF guard | SECHRD-02 | `crates/axiam-pki/src/ssrf.rs` (518) | **read in full** (routed item 6) |

Sampled, not exhausted, and named as such in §13: `axiam-amqp`'s consumers,
`axiam-db`'s non-X6 repositories beyond the `delete` survey in SEC-104, and the
frontend.

**Nothing was run against a live stack.** There is no docker daemon in this
environment, so every claim below is from reading code, except SEC-094, whose
address-classification behaviour was reproduced with a standalone `rustc`
program (§4.1).

---

## 2. SEC-093 — the registration's client-authentication method is not enforced at five endpoints

**Severity: HIGH. Live at HEAD.**

`TokenService` has two client-authentication entry points and they do not agree.

The private one honours the registration:

```rust
// crates/axiam-oauth2/src/token.rs:551-571
async fn authenticate_client_credential(…) -> Result<(), OAuth2Error> {
    if client.token_endpoint_auth_method.is_mtls() {
        return crate::mtls::authenticate_mtls_client(client, ctx.client_certificate.as_ref());
    }
    if client.token_endpoint_auth_method.is_private_key_jwt() {
        return self.authenticate_client_assertion(tenant_id, client, ctx).await;
    }
    let secret = presented_secret.ok_or_else(…)?;
    self.verify_client_secret(tenant_id, client, secret).await
}
```

and its doc comment states the invariant exactly:

```rust
// crates/axiam-oauth2/src/token.rs:535-545
/// The **registration** decides, not the request. … Letting the request choose
/// would turn the two methods into an OR: an attacker holding either credential
/// could authenticate, which is strictly weaker than holding the one the
/// operator registered.
```

The public one does not:

```rust
// crates/axiam-oauth2/src/token.rs:1778-1815
pub async fn authenticate_client(&self, tenant_id, client_id, client_secret) -> … {
    let client = self.client_repo.get_by_client_id(tenant_id, client_id).await…;
    if client.tenant_id != tenant_id { … }
    self.verify_client_secret(tenant_id, &client, client_secret).await?;   // ← secret. Only.
    Ok(client)
}
```

`authenticate_client_credential` is reached from exactly three grants —
authorization_code (`token.rs:981`), client_credentials (`:1274`) and
refresh_token (`:1434`). **Every other client-authenticating endpoint calls
`authenticate_client`:**

| Endpoint | Call site |
|---|---|
| `POST /oauth2/token`, `grant_type=…:token-exchange` | `crates/axiam-api-rest/src/handlers/oauth2.rs:1406-1413` |
| `POST /oauth2/token`, `grant_type=…:uma-ticket` | `crates/axiam-api-rest/src/handlers/oauth2.rs:1195-1203` |
| `POST /oauth2/par` | `crates/axiam-api-rest/src/handlers/oauth2.rs:1702-1709` |
| `POST /oauth2/revoke` | `crates/axiam-oauth2/src/token.rs:1645` |
| `POST /oauth2/introspect` | `crates/axiam-oauth2/src/token.rs:1678` |

**Why this is exploitable rather than theoretical.** Every client gets a secret,
unconditionally, whatever authentication method it registers:

```rust
// crates/axiam-db/src/repository/oauth2_client.rs:263-270
async fn create(&self, input: CreateOAuth2Client) -> AxiamResult<(OAuth2Client, String)> {
    let client_id = generate_client_id();
    let raw_secret = generate_client_secret();
    let secret_hash = client_secret::global()?.hash(&raw_secret);
```

The plaintext is returned once (`handlers/oauth2_clients.rs:377`) and the hash is
stored forever. So a FAPI 2.0 client registered with `tls_client_auth` — whose
registration validation *forbids* shared-secret authentication
(`fapi.rs::validate_registration`, `WeakClientAuth`) — nonetheless holds a live
shared secret that authenticates it at PAR, revoke, introspect, token-exchange
and uma-ticket. The operator's mental model is "this client authenticates with a
certificate"; the reality is an OR over two credentials, one of which they were
told to discard at creation time.

PAR is the sharpest instance: FAPI 2.0 §5.3.1.1 requires strong client
authentication and FAPI 2.0 requires PAR, so a FAPI deployment's PAR endpoint
accepting `client_secret_post` is both an authentication downgrade and a
conformance failure that R8.1's suite would find.

**Recommended fix.** Give `authenticate_client` the same body as
`authenticate_client_credential` — it already has the `OAuth2Client` row; it
needs a `&TokenRequestContext`. Four of the five call sites already have a
`HttpRequest` in scope and can build one with `token_request_context(&req)`;
`revoke`/`introspect` take their request through `TokenService` and need the
context threaded the same way `exchange` does.

**Regression test to add:** register a client with
`token_endpoint_auth_method = tls_client_auth`, then POST its `client_secret` to
`/oauth2/par` and assert `invalid_client`. Name it after what it stops.

---

## 3. SEC-094 — the SSRF guard does not canonicalise IPv4-mapped IPv6 addresses

**Severity: HIGH. Live at HEAD.**

```rust
// crates/axiam-pki/src/ssrf.rs:85-101
pub fn is_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local()
            || v4.is_broadcast() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified()
            || (v6.segments()[0] & 0xffc0 == 0xfe80)   // fe80::/10
            || (v6.segments()[0] & 0xfe00 == 0xfc00),  // fc00::/7
    }
}
```

`Ipv6Addr::is_loopback()` is true for `::1` and nothing else. An IPv4-mapped
address (`::ffff:a.b.c.d`) has `segments()[0] == 0x0000`, so it matches none of
the four V6 arms, and the V4 arms are never consulted because the value is an
`IpAddr::V6`.

### 3.1 Reproduced

Compiled and run against the exact predicate above (standalone `rustc`, no
project dependencies):

```
::ffff:127.0.0.1         disallowed=false   canonical_disallowed=true
::ffff:169.254.169.254   disallowed=false   canonical_disallowed=true
::ffff:10.0.0.1          disallowed=false   canonical_disallowed=true
::ffff:192.168.1.1       disallowed=false   canonical_disallowed=true
::1                      disallowed=true
fd00::1                  disallowed=true
100.64.0.1               disallowed=false   ← RFC 6598 CGNAT, also unblocked
```

### 3.2 Why it reaches a socket

`resolve_and_pick` (`ssrf.rs:108-128`) takes whatever `tokio::net::lookup_host`
returns — and `getaddrinfo` returns an `AAAA` record's contents verbatim, so a
DNS zone the requester controls can publish `::ffff:169.254.169.254`. The guard
passes it, and then `pinned_client` (`ssrf.rs:139-147`) *pins* it:

```rust
reqwest::Client::builder().resolve(host, SocketAddr::new(ip, port))
```

so the socket that opens is the one that was validated. On a dual-stack Linux
host, `connect()` to an IPv4-mapped address on an `AF_INET6` socket reaches the
IPv4 destination. The pinning that closes the DNS-rebind window (D-01c) here
*guarantees* the attacker's address is used.

### 3.3 Blast radius

One module, six production call sites, all of them admin- or tenant-supplied
URLs:

- `crates/axiam-api-rest/src/webhook.rs:264` — tenant-admin-supplied webhook URL
- `crates/axiam-federation/src/jwks_cache.rs:255` — `jwks_uri` (federation **and**
  `private_key_jwt` client registration, `private_key_jwt.rs:522-524`)
- `crates/axiam-federation/src/discovery_cache.rs:206` — OIDC discovery
- `crates/axiam-federation/src/oidc.rs:483` — IdP token endpoint
- `crates/axiam-federation/src/saml.rs:153` — SAML metadata
- `crates/axiam-pki/src/mds/mod.rs:111` — MDS3 BLOB

The lowest-privilege reachable path is a tenant admin registering a webhook.
Webhook delivery is a signed POST, so straight IMDSv1 credential theft needs the
GET-shaped surfaces (JWKS / discovery / metadata / MDS), which a federation admin
controls. Either way the control that exists to make private-network addresses
unreachable does not make them unreachable.

### 3.4 Fix

```rust
pub fn is_disallowed_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {                        // ::ffff:a.b.c.d → V4(a.b.c.d)
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local()
            || v4.is_broadcast() || v4.is_unspecified()
            || v4.is_shared()                        // 100.64.0.0/10 (RFC 6598)
            || v4.octets()[0] == 0,                  // 0.0.0.0/8, not just 0.0.0.0
        IpAddr::V6(v6) => …unchanged…,
    }
}
```

`to_canonical` also folds the IPv4-compatible form (`::a.b.c.d`). Consider
rejecting NAT64 (`64:ff9b::/96`) too; it is a smaller surface but the same class.

The webhook tests at `crates/axiam-api-rest/src/webhook.rs:404-422` assert
`127.0.0.1`, `10.x`, `172.16.x`, `192.168.x` are blocked — add the `::ffff:`
form of each. Those four assertions passing is exactly why this survived.

---

## 4. SEC-095 — `login.post_auth` does not fire on SSO logins

**Severity: HIGH, latent.** Not exploitable at HEAD because
`UnavailableReactorTransport` means no reactor reply can ever be produced
(`dispatcher.rs:119-143`). It becomes live the moment the lapin transport merges,
which is the change that should also close it.

The hook is placed correctly on the path it is on:

```rust
// crates/axiam-auth/src/service.rs:328-357
// 5c. X1 `login.post_auth` — after the credentials verify, before any
//     session or challenge is issued.
match self.reactor_gate.intercept(input.tenant_id, reactor_events::LOGIN_POST_AUTH, …)
```

That is the *only* call. Session issuance has four other entry points:

| Path | Site | Gated? |
|---|---|---|
| Password login | `service.rs:339` → `:433` | ✅ |
| MFA completion | `service.rs:509` | ✅ (same login, gated at `:339`) |
| MFA-setup completion | `service.rs:1040` | ✅ (same login) |
| WebAuthn `authenticate/finish` | `handlers/webauthn.rs:304` | ✅ — the ceremony requires an MFA challenge token minted by the password login (`handlers/webauthn.rs:258-261`), so it is a *second factor*, already gated |
| **SAML ACS** | `handlers/federation.rs:1420` | ❌ |
| **OIDC callback** | `handlers/federation.rs:1655` | ❌ |

Both federation paths call `create_session_and_tokens` directly and issue a full
session plus access/refresh tokens.

Nothing scopes the event to password logins. The registry says:

```rust
// crates/axiam-core/src/models/reactor.rs:174-182
name: "login.post_auth",
description: "After credentials verify, before session issuance: veto or require step-up MFA.",
```

and `sdks/CONTRACT.md` §22.5 repeats that table verbatim with no carve-out. An
operator who registers the very reactor R2.5 uses as its worked example — an
"embargoed-region login veto" — gets a control that is bypassed by clicking
"Sign in with Okta".

**Two honest fixes, in preference order:**

1. **Wire it.** Both federation sites already have `tenant_id` and the resolved
   `user`; the payload shape is the same minus `mfa_enabled`. A veto there must
   refuse *before* `create_session_and_tokens`, exactly as the password path does.
   `require_mfa` needs a decision at those sites (the natural answer is the same
   `MfaSetupRequired` / `MfaRequired` branch, which SSO does not currently have —
   so `RequireMfa` should be refused as `impossible(…)` there rather than
   silently dropped, following `reactor_hooks.rs:52-65`).
2. **Scope it normatively.** Rename the event or add "password-authentication
   only" to the registry description, §22.5 and `GET /api/v1/reactors/events`,
   and say so in the reactor product docs. This is a docs-only change and is
   defensible — but only if it is *stated*, because the current text promises
   the opposite.

Doing neither ships a security hook whose coverage an operator can only discover
by reading `service.rs`.

---

## 5. SEC-096 — token exchange strips sender-constraining, and skips the FAPI gate

**Severity: Medium.**

`issue_exchanged_token` has no confirmation-claim parameter at all:

```rust
// crates/axiam-auth/src/token.rs:500-512
pub fn issue_exchanged_token(
    subject: &str, sub_kind: SubjectKind, tenant_id: Uuid, org_id: Uuid,
    scopes: &[String], config: &AuthConfig, jti: String, aud: &str,
    expires_at: i64, act: Option<ActClaim>, ext_exchange: Option<ExtExchangeClaim>,
) -> Result<String, AuthError>
```

so **no exchanged token is ever `cnf`-bound**, on either the B3 same-domain path
(`axiam-oauth2/src/token_exchange.rs:658-672`) or the X4 external path (`:878-898`).

Nor is the profile gate consulted. `fapi::enforce_token_request` and
`certificate_binding_for` are called from three places only — `token.rs:983`,
`:1278`, `:1436` — all inside `TokenService`. The token-exchange, uma-ticket and
device-code grants `return` from `handlers/oauth2.rs` at `:330`, `:361` and `:368`,
*before* `dpop_from_request` (`:385`) and before `TokenService::exchange` (`:390`).

Two consequences:

1. **A client that asked for binding can launder it away.** A client with
   `dpop_bound_access_tokens: true` holds a `cnf.jkt` token that is useless to a
   thief. It exchanges that token — and gets back a plain bearer token with the
   same subject and a subset of the same scopes. `certificate_binding_for`'s own
   doc comment calls the equivalent silent downgrade "the worst possible
   behaviour" (`token.rs:612-618`); the exchange path does it by omission.
2. **A `fapi2` client can obtain an unconstrained token.**
   `enforce_token_request` refuses exactly this for the three grants it guards
   (`fapi.rs:432-448`, `is_sender_constrained`); the exchange grant is not one of
   them. FAPI 2.0 requires every access token to be sender-constrained, so this
   is also a conformance defect R8.1 should surface.

Note the mitigating bound: the exchange still requires client credentials, so
this is a downgrade available to the client itself (or, under SEC-093, to anyone
holding its discarded secret) — not to a bare token thief.

**Recommended fix.** Move the four grant dispatches in `handlers::token` to
*after* `token_request_context` + `dpop_from_request`, pass the `ctx` into
`handle_token_exchange` / `handle_uma_ticket`, and have both call
`fapi::enforce_token_request` and `certificate_binding_for` after client
authentication, exactly as the three guarded grants do. Then give
`issue_exchanged_token` a `cnf: Option<CnfClaim>` parameter — `None` reproduces
today's bytes for every unbound client, the same property
`issue_access_token_bound` was given for the same reason (`token.rs:359-365`).

The device-code grant is deliberately excluded from this: RFC 8628 targets public
clients and performs no client authentication at all
(`handlers/oauth2.rs:326-329`), so there is no registration in hand to enforce.
A `fapi2` client registered for `device_code` is a registration error;
`validate_registration` should probably refuse it, which is a separate, smaller
change.

---

## 6. SEC-097 — `dpop_require_nonce` is an inert flag

**Severity: Medium.**

The field exists end to end: the model (`axiam-core/src/models/oauth2_client.rs:275`),
the schema (`axiam-db/src/schema.rs:2106`), create and update
(`axiam-db/src/repository/oauth2_client.rs:338, 543`), the admin DTOs and OpenAPI
(`handlers/oauth2_clients.rs:103, 193, 359, 540`). Nothing reads it.

`enforce_token_request` does not consult it (`fapi.rs:410-455`), and the one
place a nonce could be demanded hard-codes the opposite:

```rust
// crates/axiam-api-rest/src/handlers/oauth2.rs:549-563
let expect = DpopExpectation {
    htm: req.method().as_str(),
    htu: &htu,
    // The nonce a rotating deployment would compare against is not stored
    // per client today; `dpop_require_nonce` is a per-client switch that
    // makes the *first* request of a session a challenge, and the client
    // then echoes the nonce this server issued in the challenge. …
    expected_nonce: None,
    require_nonce: false,
```

The comment's middle sentence is not true of this code: `require_nonce: false` is
unconditional, so the switch makes nothing a challenge. `verify_dpop_proof`
implements the nonce rules correctly and completely (`dpop.rs:429-451`, tests at
`:757-826`) — the mechanism exists and is simply never engaged.

**Severity reasoning.** The marginal security loss is small: the token endpoint
already makes every proof single-use through `insert_proof_jti`
(`handlers/oauth2.rs:584-616`), which is the stronger of the two controls, and
FAPI 2.0 does not mandate DPoP nonces. What earns "medium" is that an operator
can set a security switch in the admin API, see it persisted and echoed back, and
get nothing — the same class of defect as SEC-092's "unrecognised effect read back
as allow", in the direction of a control that silently does not exist.

**Two acceptable dispositions, pick one and say so:**

1. Implement the minimal form the comment describes: when
   `client.dpop_require_nonce` is set, pass `require_nonce: true`. A proof with
   no nonce then gets `use_dpop_nonce` + a fresh `DPoP-Nonce` header, which
   `dpop_error_response` already emits (`:623-635`). Without server-side storage
   the echoed nonce cannot be *verified* on the retry — so pair it with
   `expected_nonce` derived from a keyed, time-bounded MAC over
   `(tenant, client_id, window)`, or say plainly that v1 only proves liveness.
2. Remove the field from the create/update DTOs and the schema, and record in
   `docs/security-profiles.md` that DPoP nonces are not implemented.

What is not acceptable is leaving a persisted, documented, API-visible switch
that does nothing and a code comment asserting that it does.

---

## 7. SEC-098 — `scim:provision` confers password-set on every user in the tenant

**Severity: Medium. Intra-tenant privilege escalation.**

SCIM's `PATCH /scim/v2/Users/{id}` accepts and applies a password:

```rust
// crates/axiam-scim/src/users.rs:607-628
let password_hash = match &delta.password {
    Some(pw) => Some(password::hash_password(pw, pepper)…?),
    None => None,
};
let update = UpdateUser { …, password_hash, ..Default::default() };
```

(parsed at `crates/axiam-scim/src/patch.rs:188-193`; RFC 7643 §4.1.1 does define
`password` as writable, so this is spec-conformant.)

The native admin API has no equivalent. `handlers::users::update` never sets
`password_hash`; the only native password writes are self-service change and
reset, both in `AuthService`. So the single permission

```rust
// crates/axiam-api-rest/src/permissions.rs:227-229
("scim:provision", "Provision/deprovision users and groups via the SCIM 2.0 endpoint"),
```

is strictly more powerful than `users:create` + `users:update` combined: its
holder can set the tenant administrator's password and then log in as them. An
operator granting it to an Okta or Entra integration identity — which is exactly
what the provisioning guide tells them to do — is granting tenant-wide account
takeover, and neither the permission description nor `axiam-scim/src/auth.rs`
says so.

**Two secondary gaps in the same handler, both at parity with native but wrong
for the SCIM use case:**

- **A SCIM password write revokes nothing.** The native paths revoke every other
  session *and* every OAuth2 refresh token (`service.rs:806-870`,
  `revoke_all_sessions` / `revoke_all_sessions_except`). SCIM's PATCH calls
  `authz.invalidate_subject` — the *decision* cache — and nothing else. A
  password rotated to lock out a compromised account leaves the attacker's
  session and refresh token live.
- **A SCIM deactivation (`active: false`, `users.rs:619-627`) and
  `DELETE /Users/{id}` (`:663`, a soft-delete to `Inactive`) likewise leave live
  sessions alone.** The refresh path does re-read the user and call
  `check_user_status` (`service.rs:734-737`), so refresh is correctly blocked;
  the exposure is bounded to the current access token's remaining lifetime
  (≤ 15 min) plus the session row, which the extractor still treats as valid.
  This is the product-wide posture — `handlers::users::delete` behaves identically
  (`handlers/users.rs:391-401`) — but SCIM is the path an IdP drives *offboarding*
  through, which is precisely where immediacy is assumed.

**Recommended disposition.** (a) State the password capability in the
`scim:provision` description, in `axiam-scim/src/auth.rs`'s module header and in
`docs/api/scim-provisioning.md`, in the operator's words: *"a holder of
`scim:provision` can set any user's password in this tenant, including an
administrator's."* (b) Call `revoke_all_sessions` after a SCIM password write and
after a deactivate/delete — one line each, and it is what the RFC's consumers
expect deprovisioning to mean. (c) Consider splitting password writes behind a
second permission or a per-tenant switch, since most Okta/Entra deployments
federate and never push a password.

**Tenant isolation itself: no findings.** See §12.1 — that half of B4 is sound,
and I checked it adversarially rather than taking the module header's word.

---

## 8. SEC-099 — the reactor gate applies `listen`-mode registrations' failure policy

**Severity: Medium (over-denial; fail-safe direction).**

`run_chain` correctly consults interceptors only:

```rust
// crates/axiam-amqp/src/reactor/dispatcher.rs:235
for reactor in reactors.iter().filter(|r| r.mode == ReactorMode::Intercept) {
```

The gate's two out-of-chain failure paths do not. `intercept` builds the filtered
`interceptors` list at `gate.rs:758-764`, then passes the **unfiltered** slice to
`fail_whole_chain`:

```rust
// crates/axiam-amqp/src/reactor/gate.rs:768-782
let _permit = match self.limiter(tenant_id).try_enter_owned() {
    …
    Err(failure) => {
        return self.fail_whole_chain(tenant_id, event, &reactors, failure).await;
        //                                             ^^^^^^^^^ all modes
```

```rust
// crates/axiam-amqp/src/reactor/gate.rs:529-548
for reactor in reactors {
    metrics::record_failure(&failure);
    self.audit_failure(…).await;
    if let ReactorOutcome::Deny { reason } = resolve_failure(reactor.failure_policy, &failure) {
        outcome = ReactorOutcome::Deny { reason };
    }
}
```

So a `listen`-mode registration on `login.post_auth` — which
`default_failure_policy_for` gives `fail_closed`
(`axiam-core/src/models/reactor.rs:512-522`) — **denies the login** when the
per-tenant in-flight cap is breached. `ReactorMode::Listen`'s own doc says the
opposite: *"The server never waits and never reads a reply, so a listener cannot
affect any outcome"* (`reactor.rs:45-47`).

The same slice is used on the unreadable-registry path, where the whole chain is
skipped anyway (see SEC-100), so both out-of-chain paths share the defect.

**Related, and worth stating in the same finding: `listen` mode is entirely
inert.** `ReactorTransport::publish_listen` (`dispatcher.rs:76-82`) has **no
caller anywhere in the tree** — `run_chain` filters listeners out and never
publishes to them, and `intercept` returns `Allow` early when the interceptor
list is empty (`gate.rs:762-764`). So a `listen` registration today receives
nothing and can only ever *deny*, which is the exact inverse of its contract.

**Fix:** pass `&interceptors` (or filter inside `fail_whole_chain`), and either
implement the listen fan-out or refuse `mode: listen` at registration until it
exists. A test worth writing: register one `listen` + `fail_closed` reactor on
`login.post_auth`, saturate the limiter, assert `Allow`.

---

## 9. SEC-100 — the unreadable-registry rule denies for tenants that have no reactors

**Severity: Medium.** This is the concrete half of routed item 2 (§14.2).

```rust
// crates/axiam-amqp/src/reactor/gate.rs:727-755
let reactors = match self.routing.resolve(tenant_id, event).await {
    Ok(list) => list,
    Err(e) => {
        …
        return match spec.default_failure_policy {
            FailurePolicy::FailOpen => ReactorOutcome::Allow,
            FailurePolicy::FailClosed => ReactorOutcome::Deny { … },
        };
    }
};
```

The `Err` arm returns **before** step 3's "nobody is listening" check
(`:757-764`). So when `ReactorSource::enabled_for_event` fails and
`ReactorRoutingTable::stale` has nothing cached (`:192-197, 230-245`), the gate
denies `login.post_auth`, `user.pre_create`, `user.pre_update` and
`grant.pre_assign` for **every tenant** — including the overwhelming majority
that have never registered a reactor and for whom the correct answer is provably
"there is nothing to consult".

It also uses the **event's** default rather than the registrations' own policies,
so a tenant that deliberately registered only `fail_open` reactors on
`login.post_auth` is still denied. That is inconsistent with the cap-breach path
one screen below, which resolves each registration's own policy.

The stale-serve path (`:232-241`) and the 5 s TTL bound the window considerably —
after one successful resolve the empty list is cached — and the login path has
already read the `user` table by the time the gate runs, so a total outage is not
the realistic trigger. A *partial* one is: a permissions error on the `reactor`
table, a schema migration in flight, a per-table timeout.

**Recommended fix.** Keep the rule — it is the right rule, and §14.2 argues why —
but scope it to the population it protects. Two options, both cheap:

1. Cache negative results with a longer TTL and treat "this tenant has been
   observed to have zero reactors within the last N minutes" as sufficient to
   allow. This preserves the property that an unreadable registry cannot skip a
   *registered* veto, which is the whole point.
2. Keep an in-process per-tenant "has ever had ≥1 registration" bit, maintained
   by the same CRUD hooks that already call `invalidate_tenant`
   (`handlers/reactors.rs:275, 420, 452`); deny only when that bit is set.

Either way, the deny should resolve the *registrations'* policies when a stale
list exists, not the event default.

---

## 10. SEC-101 — a registered `fail_closed` reactor is a self-service denial of service today

**Severity: Medium.** This is routed item 4 (§14.4).

```rust
// crates/axiam-amqp/src/reactor/dispatcher.rs:119-131
impl ReactorTransport for UnavailableReactorTransport {
    async fn round_trip(…) -> Result<ReactorReply, DispatchFailure> {
        Err(DispatchFailure::Transport(REACTOR_TRANSPORT_UNAVAILABLE.to_string()))
    }
```

composed unconditionally in production:

```rust
// crates/axiam-server/src/main.rs:618-628
let reactor_gate: SharedReactorGate = Arc::new(DispatchingReactorGate::new(
    Arc::clone(&reactor_routing),
    axiam_amqp::UnavailableReactorTransport,
    …
```

Fail-closed **is** the right default here, and §14.4 argues that at length. The
finding is about what stands between an operator and the consequence: one
`tracing::warn!` at startup (`main.rs:634-644`), which is thorough and correct
and is also a log line that scrolls past during boot.

Meanwhile `POST /api/v1/reactors` will happily accept an `intercept`-mode
registration on `login.post_auth` right now
(`handlers/reactors.rs:252-275`; `validate_registration`,
`axiam-core/src/models/reactor.rs:479-502`, checks name/events/mode/timeout and
nothing about transport availability), and the frontend `ReactorsPage` offers the
form. The result is a tenant-scoped, self-inflicted, *complete* login outage
created by a supported admin action with no warning at the point of action.

**Recommended fix.** Make the gate report whether its transport can dispatch —
a `fn can_dispatch(&self) -> bool` on `ReactorTransport`, `false` for
`UnavailableReactorTransport` — and have the create/update handlers refuse
`mode: intercept` with a 409 naming the reason while it is false. `mode: listen`
would also be refused, for SEC-099's reason. The startup WARN stays; it is now
the explanation for an error an operator will actually encounter.

If that is judged too much for this wave, the minimum is: say it in the reactor
product docs (R2.6) and in the admin UI's create form, not only in the boot log.

---

## 11. Lower-severity findings

### SEC-102 — DPoP `htu` is derived from the `Host` header

**Severity: Low-medium.**

```rust
// crates/axiam-api-rest/src/handlers/oauth2.rs:548
let htu = req.full_url().to_string();
```

`HttpRequest::full_url()` builds the authority from `ConnectionInfo`, which
prefers `Forwarded`, then `X-Forwarded-Host`, then `Host`. All three are
request-controlled unless a trusted-proxy layer normalises them, and I found no
such layer.

RFC 9449 §4.3 step 9 compares `htu` against "the HTTP URI used for the request,
without query and fragment parts" — meaning the server's own view of its
endpoint. Sourcing the authority from the request lets the caller choose both
sides of the comparison, which reduces the `htu` check to "the proof names
*some* authority consistently".

The path is still server-derived, so cross-*endpoint* replay (a `/oauth2/par`
proof at `/oauth2/token`) remains blocked, and the attacker must hold the proof
key. The realistic residual is a client phished into signing a proof for
`https://attacker.example/oauth2/token`, which the attacker then presents to
AXIAM with a matching `Host`. Combined with a stolen authorization code and PKCE
verifier that is a bindable path; on its own it is not.

**Fix:** build `htu` from the configured issuer / external base URL
(`auth_config.effective_issuer()` is already in `AppState`) plus `req.path()`.
That is one line and removes the caller from one side of the comparison.

### SEC-103 — reactor replies are authenticated per tenant, not per reactor

**Severity: Low. Design property, recorded so it is not rediscovered.**

The signing key is derived from `(master, key_version, tenant_id)` and nothing
else:

```rust
// crates/axiam-amqp/src/messages.rs:101-111
pub fn derive_tenant_key(master: &[u8], tenant_id: Uuid, key_version: u8) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(APP_SALT), master);
    let mut info = …; info.push(key_version); info.extend_from_slice(tenant_id.as_bytes());
```

So every reactor registered in a tenant holds the same key and can produce a
reply the server will accept as any *other* reactor in that tenant. Today the
only thing preventing reactor A from answering for reactor B is that
`correlation_id` is a fresh `Uuid::new_v4()` per reactor per dispatch
(`dispatcher.rs:268`) delivered only to B's own queue
(`protocol.rs:32-34`) — i.e. secrecy of a value, not authentication of a party.

Two second-order notes in the same area:

- **`ReactorReply::nonce` is signed but never checked.** The field exists
  (`protocol.rs:94`), it is covered by the MAC, and `into_outcome`
  (`:237-309`) never consults a dedup store — unlike the audit and authz
  consumers, which use `AmqpNonceRepository`. Single-use therefore rests entirely
  on freshness (±300 s, `messages.rs:58`) plus the transport awaiting exactly one
  reply per `correlation_id`. That second half is implemented **nowhere**, because
  the transport is unmerged. The execution log records this divergence; it should
  also be a named acceptance criterion on the lapin transport PR.
- The rejection order in `into_outcome` is correct and deliberate (identity →
  freshness → signature → semantics) and matches §22.4's table exactly.

**Recommendation:** no code change now. Add `reactor_id` to the HKDF `info` when
the lapin transport lands — it is free at that point and impossible afterwards —
and make "exactly one reply is consumed per `correlation_id`" an explicit test in
that PR.

### SEC-104 — a cross-tenant or unknown-id `delete` answers 204

**Severity: Low.** This is routed item 5 (§14.5).

```rust
// crates/axiam-db/src/repository/group.rs:274-300
"BEGIN TRANSACTION; \
 DELETE member_of WHERE out = group:`{id_str}` AND out.tenant_id = $tenant_id; \
 DELETE type::record('group', $id) WHERE tenant_id = $tenant_id; \
 COMMIT TRANSACTION"
```

The `WHERE tenant_id` predicates are correct — **no other tenant's data is ever
touched** — but the result is not inspected, so `Ok(())` is returned whether or
not a row matched.

- SCIM pre-checks and gets it right (`axiam-scim/src/groups.rs:441-453`, with a
  comment naming precisely this).
- The native handler does not (`axiam-api-rest/src/handlers/groups.rs:174-195`)
  and returns 204.

This is **not group-specific**. Surveying the repositories: `user`
(`repository/user.rs:504-510`) and `webhook` (`:256-258`) do check and return
`NotFound`; `group`, `role`, `resource`, `permission` and `service_account` do
not.

**Severity reasoning: low, and it is not an oracle.** Because the answer is
uniformly 204 — for a foreign id, a nonexistent id and a real one — a caller
learns nothing about what exists in other tenants. What it costs is an admin who
deletes the wrong id, gets 204, and believes the group is gone. It also makes
`DELETE` non-idempotent-detectable, which the SCIM RFC does care about (RFC 7644
§3.6 wants 404 for a missing resource) and which the native API does not.

**Recommended disposition:** make the five repositories consistent with `user`
and `webhook` — `RETURN BEFORE`, check for an empty row set, map to
`DbError::NotFound`. Mechanical, one shape, and it lets `axiam-scim`'s pre-check
be deleted rather than duplicated for every future resource type.

### SEC-105 — X6's "the nonce catches any missed conflict" claim is stronger than the mechanism

**Severity: Low. Documentation, not code.**

The module header states the backstop as complete:

```
// crates/axiam-db/src/repository/permission_ticket.rs:26-31
//   2. **The nonce audits it.** … This asks the engine for nothing, so a conflict
//      the engine misses is still caught here — it is what turns 0-in-40 000 from
//      strong evidence into a mechanism that does not depend on that evidence holding.
```

The read-back is a separate query issued after the caller's own commit
(`:267-293`), which is the right shape and closes the snapshot-isolation trap
`SCHEMA_V31` records. But it has its own interleaving window: if racer A commits,
A reads back and sees its own nonce (A wins), and only *then* racer B's
concurrent transaction commits, B's later read-back sees B's nonce and B also
wins. Both callers report a redemption.

That requires the engine to have already missed the write-write conflict, which
is the layering's whole premise — so the mechanism is genuinely "a double
redemption needs two independent failures", which is what §X6.2 promises. It is
not "the nonce catches any conflict the engine misses", which is what the module
header says. The project's own measurement agrees with me and not with the header:
`extra-B-track-features.md` §X6.1 records the nonce-with-read-back shape at
**1/640** on `kv-mem`.

**Recommended fix:** amend the three module headers (`permission_ticket.rs:26-31`
and the equivalents in `device_grant.rs:30-31`, `pushed_auth_request.rs:25`) to
say "a conflict the engine misses is caught unless the two commits interleave
around the read-back — two independent failures, not one". #302's culture is
exactly this kind of precision; the header should not be the one place that
rounds it off.

### SEC-106 — the AMQP client pins no minimum TLS version, and a supplied CA adds to system roots

**Severity: Low.**

`build_tls_config` (`crates/axiam-amqp/src/connection.rs:19-54`) produces a
`lapin::tcp::OwnedTLSConfig { identity, cert_chain }` and
`Connection::connect_with_config` is called with `ConnectionProperties::default()`
(`:154-170`). Neither sets a protocol-version floor. CLAUDE.md's stated standard
is "TLS 1.3 minimum for all external communication", and six SDKs consume the
broker directly, so this connection crosses a service boundary by design — but a
broker offering TLS 1.2 is accepted.

Second, smaller point: with lapin's `native-tls` backend a supplied
`cert_chain` is *added* as an extra root, not substituted for the system store.
An operator who sets `AXIAM__AMQP__TLS__CA_CERT_PATH` to pin their private broker
CA has widened the trust set, not narrowed it, which is the opposite of what
`config.rs:37-40`'s "Set this when the broker presents a private CA" implies.

Everything else about A6 is right and worth recording: there is no
`verify_peer: false` and the reasoning for its absence is stated
(`config.rs:23-32`); there is no silent plaintext fallback
(`connection.rs:141-146`); a plaintext URL fails closed in release builds unless
`AXIAM__AMQP__ALLOW_PLAINTEXT` is set, with a warning that correctly distinguishes
authenticity from confidentiality (`config.rs:215-262`); and the half-identity
case is refused rather than silently downgraded (`config.rs:63-78`).

### SEC-107 — the SSRF guard has no operator override

**Severity: Low (usability / operational lock-in), not a vulnerability.** This is
routed item 6 (§14.6); the reasoning is there. Recorded with a number because the
recommendation is a change, not "leave it".

---

## 12. Surfaces reviewed without findings — and what that means here

### 12.1 B4 SCIM tenant isolation — no findings

This was the specific question routed to R6, so it was checked adversarially
rather than by reading the module header's claim.

- Every handler takes `user: AuthenticatedUser` and passes `user.tenant_id` —
  and only `user.tenant_id` — to every repository call. I traced all 18 call
  sites across `users.rs` and `groups.rs`; there is no path where a tenant id
  comes from the URL, the body, a header or a filter. `AuthenticatedUser::tenant_id`
  comes from the validated JWT claim.
- The `{id}` path segment is typed `web::Path<Uuid>`, so a foreign UUID reaches
  `get_by_id(tenant_id, id)` and 404s. Cross-tenant GET/PUT/PATCH/DELETE all
  reduce to that one lookup.
- **Group membership cannot cross tenants.** This was the one place a
  two-object operation could have checked only one of them, and it does not:
  `GroupRepository::add_member` verifies *both* the user and the group belong to
  the caller's tenant before creating the edge
  (`axiam-db/src/repository/group.rs:355-390`), returning `NotFound` for either.
  Without that, `POST /scim/v2/Groups` with a foreign `members[].value` would have
  granted another tenant's user this tenant's inherited roles.
- **`RELATE` uses string interpolation** (`group.rs:392`) — but both interpolated
  values are `Uuid::to_string()`, so there is no injectable surface. Same for
  `delete`'s `{id_str}`.
- The filter parser never reaches the query layer as a string: it produces a
  typed `EqFilter` whose `value` is passed as a bound parameter to
  `get_by_username(tenant_id, value)`, and it refuses a smuggled conjunction
  explicitly (`filter.rs:76-80` and `unquote`'s trailing-content check).
- `scim:provision` is a real registry entry seeded per tenant like every other
  permission (`permissions.rs:227-229`), enforced through the same
  `RequirePermission` guard (`auth.rs:61-69`), on every one of the 14 routes —
  including the discovery endpoints, which are deliberately not in
  `PUBLIC_PATHS`.

The isolation property holds. SEC-098 is about how much power the permission
carries *within* a tenant, which is a different question.

### 12.2 X4 external-IdP token exchange — no findings

Read in full, against the three invariants R6 named.

**No transitive exchange.** Enforced on both sides. The external path refuses a
subject token carrying `ext_exchange`
(`axiam-federation/src/token_exchange.rs:422-427`) and the internal path refuses
one on the way back round (`axiam-oauth2/src/token_exchange.rs:501-507`) — the
comment at `:498-500` is right that you need both or trust composes silently.
Delegation across the boundary is refused outright, before the token is verified
so the answer does not depend on whether it was good
(`axiam-oauth2/src/token_exchange.rs:727-733`).

**Never widen.** Four gates, and the partner's token is not one of them.
`scope_map` output is deny-by-default with no passthrough mode
(`axiam-core/src/models/federation.rs:254-267`), intersected with the client's
registration through the *same* `narrow_scopes` the B3 path uses
(`:766-784`), then filtered by the RBAC engine at mint time (`:792-809`).
`RbacScopeAuthority` (`axiam-api-rest/src/token_exchange.rs:196-221`) takes
deny-override at its broadest reading — a deny anywhere in the subject's
applicable roles withholds the scope entirely — and the argument for that
asymmetry (`:123-140`) is correct: a bearer scope cannot express "except on
resource X", so the only honest answers are all or nothing, and the conservative
one is the one that cannot be widened by adding a deny rule.

**Lifetime min.** `subject_remaining.min(max_lifetime_secs).min(provider_max)`
with a positive-remaining check on both sides (`:854-869`).

Also verified, because each is a place the trust boundary could have leaked:

- The unverified `iss` selects *which key* the token faces, never *whether* it
  faces one (`:473-481`, and `axiam-federation/…:329-346`).
- `list_token_exchange_enabled` filters on `token_exchange_enabled = true` **and**
  `enabled = true` **and** `protocol = 'OidcConnect'` **and** `tenant_id`, in one
  place (`axiam-db/src/repository/federation_config.rs:589-626`) — so a provider
  configured for login is not thereby usable for exchange, and a disabled row with
  a populated `accepted_audiences` cannot be reached.
- An empty `allowed_algorithms` is a refusal, not "accept the header's choice"
  (`axiam-federation/…:354-361`) — this is the `alg:none` shape one layer up.
- `validate_aud = false` on the decoder is deliberate and correct: the audience is
  checked against `accepted_audiences` with exact equality both directions and no
  normalisation (`federation.rs:240-244`), and there is no accept-all value
  (`:193-195`). A non-string `aud` flattens to nothing rather than to its decimal
  spelling (`axiam-federation/…:168-177`).
- ID tokens and refresh tokens are refused by *positive* markers
  (`nonce`/`at_hash`/`c_hash`/`s_hash`, and a `typ` allow-list) rather than by
  absence of an access-token marker (`:239-272`) — the right direction.
- `check_age` refuses a missing `iat` rather than treating it as unbounded
  (`:279-298`), and `max_token_age_secs` is ceiling-bounded at 3600
  (`federation.rs:63, 204-208`).
- Accepting `PendingVerification` is argued rather than assumed
  (`axiam-federation/…:506-515`) and the argument holds: `provision_new_user`
  never moves a federated user off it, so requiring `Active` would refuse the
  entire population X4 exists for while stopping nobody — the three states that
  mean "do not use this account" are refused.

One observation, not a finding: `resolve_trusted_provider` walks every
exchange-enabled provider calling `self.discover(metadata_url)` until an issuer
matches (`:554-597`). A token bearing an unknown `iss` therefore costs one
discovery lookup per configured provider. The discovery cache absorbs this in
steady state and providers are bounded by admin action, so it is not a finding —
but the exchange endpoint's rate limit
(`handlers/oauth2.rs:1430-1441`) is what bounds it, and that is worth knowing if
the limit is ever relaxed.

### 12.3 X5.1 DPoP, `private_key_jwt`, mTLS — no findings in the primitives

The three verifiers are the strongest code in this review and I could not find a
defect in any of them. SEC-096, SEC-097 and SEC-102 are all about *wiring*, not
about these functions.

**DPoP** (`dpop.rs`): `typ` is checked before the key is even looked at
(`:353-364`), so an access token signed by a client's own key cannot reach the
verification path. The algorithm comes from the embedded key, never the header
(`:382-384`, and `jose::verify_permitted_header`). Private key material is
detected against the **raw** header JSON (`:317-323`) because
`jsonwebtoken::Jwk` has no fields for `d`/`p`/`q` and would silently discard
them — that reasoning is exactly right and the test at `:640-661` builds the
proof by hand for the same reason. `htu` comparison is a plain string operation
with a stated argument against parsing (`:295-306`), and
`htu_comparison_does_not_normalise_paths` (`:741-753`) pins it. `ath` is compared
in constant time (`:461-469`). An empty `jti` is refused because a proof that
cannot be made single-use is not a proof (`:472-477`).

**`private_key_jwt`** (`private_key_jwt.rs`): keys come from the registration
only, and `kid` narrows the candidate set but can never widen it or introduce a
key from the assertion (`:272-277`) — the stated difference from a DPoP proof,
and the correct one. `iss` and `sub` are both pinned to `client_id` per OIDC Core
§9 (`:321-332`). Lifetime is bounded **even when `iat` is omitted**
(`:354-360`), which closes the "omit one optional claim, get an unbounded
assertion" asymmetry. The `jti` is recorded *after* verification so a garbage
assertion cannot fill the table (`:565-580`), and a replay guard that cannot
record refuses rather than authenticating (`:588-600`). A malformed inline `jwks`
degrades to `ClientKeySource::None` rather than surfacing a parse error, so it is
not an existence oracle (`:390-427`).

**mTLS** (`mtls.rs`): the `X-Client-Certificate` proxy header is absent *by
construction* on this path rather than gated by configuration, and the argument
for why (`:26-36`) is correct. More than one `tls_client_auth_*` parameter is a
refusal rather than an OR over credentials (`:263-272`). A `tls_client_auth`
client with no registered expectation is refused rather than matching everything
(`:250-258`). No wildcard handling in SAN-DNS matching, argued (`:304-313`). The
X.509 parse is lazy and the type system records which operations need it.
`token_request_context` reads only `VerifiedClientCert` from `conn_data`, never a
header (`handlers/oauth2.rs:482-490`).

**Binding-enforcement order** on the three guarded grants is right: presence-of-
*a*-credential (decidable before the lookup, preserving SEC-086) → client lookup
→ registration-driven authentication → profile gate → grant check → code/PKCE →
`cnf` → reactor. The comment at `token.rs:968-983` explains why the profile gate
runs after authentication (it reports a fact about the registration, which would
be an oracle otherwise) and the code does what it says. `verify_token_binding`
treats a `cnf` carrying both methods as a conjunction (`axiam-auth/token.rs:220-226`),
which is the only safe reading.

### 12.4 X3 MDS3 BLOB chain verification and enforcement — no findings

`verify_and_parse_with_anchor` (`axiam-pki/src/mds/blob.rs:222-385`) implements
D4 steps 1-9 in order and fails closed at each. The load-bearing control is
`assert_is_issuer` (`:58-76`): because the vendored anchor is GlobalSign Root
CA – R3 — a *public* root — signature-chaining alone is satisfiable by a chain
an attacker assembles from an ordinary EE certificate they legitimately hold.
Requiring `basicConstraints: CA=true` at every issuing position is what stops it,
and the doc comment states the attack it stops. `pathLenConstraint` is enforced
(`:85-96`, and the depth arithmetic at `:288` and `:303` is correct). The leaf is
refused if it is itself a CA (`:316-318`). `alg` is read once from the header, is
never taken from the payload, and the payload is not parsed until after the
signature verifies (`:241-245`, `:348-353`). Leaf identity pins the SAN DNS name
and falls back to CN only when there is **no SAN extension at all** (`:322-335`).
`x5c` is bounded at 8. The anchor is digest-pinned and re-verified on every load
(`mds/mod.rs:81-93`).

Enforcement in `axiam-auth` is wired correctly, which is the half that matters:
the REST handlers call `start_registration_for_policy` /
`finish_registration_for_policy` (`handlers/webauthn.rs:163, 217`), not the
ceremony-specific methods — and the doc comment at `webauthn.rs:700-712` names
exactly the downgrade that reaching for the wrong one would cause. An empty
`ca_list` is a refusal, never a silent fallback to the unattested ceremony
(`:506-509`). The `ca_list` is stripped from the encrypted state token and the
**current** one re-inserted at finish (`:530-552`, `:604-613`), so an MDS refresh
between start and finish takes effect. An unattested ceremony finishing against a
tenant whose policy has since tightened is denied rather than completed
(`:780-793`). Both cache-invalidation triggers the module header describes as
"later-wave work" are in fact wired — `handlers/mds.rs:191` and
`handlers/webauthn_policy.rs:213`, plus the refresh job at `main.rs:1534` — so
that header sentence is now stale (worth a one-line docs fix, not a finding).

The policy function itself (`webauthn_policy.rs:204-295`) is a clean ordered
matrix; `effective_unknown_aaguid` resolving `None` to deny under
`direct_required` and allow otherwise (`:117-124`) is the right shape, and the
reasoning — that no single struct-level default is correct for both modes and the
wrong one is wrong in the dangerous direction — is sound. An attestation format
this crate does not expect yields `(None, None)` from
`extract_attestation_metadata` (`:817-823`), which under `direct_required` fails
closed at step 2.

Two things I could not assess: the accept-half needs a real YubiKey capture
(already tracked as R8.4), and the real 10 MB BLOB is not in the tree, so the
positive path is exercised only through the injected-anchor seam.

### 12.5 X6 — no findings beyond SEC-105

The layered mechanism is present in all three repositories: the guarded `UPDATE`
inside an explicit `BEGIN`/`COMMIT`, the per-attempt nonce read back in a
**separate query after the commit**, and `WHERE consumed = false` retained so a
later non-concurrent replay matches nothing and leaves the first winner's nonce
undisturbed (`permission_ticket.rs:225-293`, and the equivalent shapes at
`device_grant.rs:286-346` and `pushed_auth_request.rs`). A loser's transaction
abort maps to `Ok(None)` — "someone else redeemed first" — rather than to a 500,
at every one of the four places a conflict can surface. `client_id` is matched
inside the statement rather than checked on the returned row, so a wrong-client
attempt cannot burn the rightful holder's ticket (`:55-61`).

Engine attestation (`axiam-db/src/engine_attestation.rs`) is the most honest
module in the tree. It enumerates every wire-reachable surface of
`surrealdb-core` 3.2.4 and concludes the engine is **not** detectable (`:20-50`),
rejects behavioural fingerprinting with a specific reason (`:44-50`), and then
still ships a total, defensive probe (`:138-142`) plus a test that pins "this
returns `None` today" as an executable fact — so a future release that starts
publishing the name makes the hard guard live with no code change. `classify` and
`decide` are pure and the policy table is stated. The override is read from the
environment by hand rather than through `config`, with the reason given
(`:99-115`), and fails closed on a typo.

The practical consequence is worth stating plainly and the module does state it:
on SurrealDB 3.2.4 attestation *always* lands on "cannot attest → WARN", so
enforcement rests entirely on the deployment layer. That is a documented,
argued position, not a gap.

### 12.6 PAR — no findings (promoted to read-in-full)

`redirect_uri` is validated at push time, while the client is authenticated
(`par.rs:143-147`). `request_uri` is 256 bits of CSPRNG stored only as SHA-256
(`:57-76`). Unknown, expired and already-consumed collapse to one answer
(`:206-212`). The pushed request is bound to the client that pushed it
(`:217-221`) — without which a second client could spend another's `request_uri`.
Lifetime is 60 s with a `const` assertion guarding the constant against a
well-meaning edit (`:284-294`), and there is deliberately no knob.

The authorize side does not merge: a `request_uri` accompanied by inline
parameters is refused (`handlers/oauth2.rs:127-140`), and on the PAR branch
`state`, `nonce`, `code_challenge` and `code_challenge_method` **all** come from
the pushed request (`:158-164`). One imprecision, not a finding:
`has_inline_params` (`par.rs:232-239`) checks `response_type`, `redirect_uri`,
`scope` and `code_challenge` but not `state` or `nonce`, so a request carrying
`request_uri` + inline `state` is accepted rather than refused — but the inline
values are then discarded in favour of the pushed ones, so nothing is confusable.
RFC 9126 §4 would have it refused; the outcome is safe either way.

### 12.7 gRPC strict revocation — no findings (promoted to read-in-full)

The layer can only ever **deny** (`strict_revocation.rs:34-51`), which is what
makes the design sound, and `SessionRevocationCheck` implementations are required
to fail *open* on a datastore error so a blip is not a mesh-wide outage
(`:82-93`). The checker handed in at composition is the same repository instance
the REST path uses, so every REST-side invalidation hook already serves gRPC
(`:126-136`, and the comment says exactly why a second instance would be wrong).
`UNAUTHENTICATED` rather than `PERMISSION_DENIED` is the right status for a
credential a client should respond to by refreshing (`:105-113`).

One doc/code drift: the module header justifies the design by saying it "decodes
the claims without verifying" (`:34-46`), but `session_ref_from_request` calls
`decode_access_token`, which verifies signature and expiry
(`:165-180`). The code is *stricter* than documented, so this is safe — but the
performance argument the header makes (avoiding a second Ed25519 verify on a path
sustaining ~12 700 reads/s) is not true of what shipped, and someone reading it
before a benchmark will be surprised. Worth a one-line correction.

The sender-constraint interceptor beside it (`middleware/auth.rs:112-150`) is
right for the harder reason: it refuses a `jkt`-bound token rather than
verifying a proof it cannot bind to a method and URI, and the table at `:100-107`
states why verifying without `htm`/`htu` would be worse than not verifying.

### 12.8 X1 patch allow-list and `ext.` rendering — no findings

The allow-list is enforced at three independent layers and the third is
structural. `ReactorReply::into_outcome` refuses a forbidden key per reply
(`protocol.rs:301-305`), with no partial application. The gate re-checks the
*merged* patch and denies the whole operation on a violation
(`gate.rs:677-703`) — and the comment explaining why the redundancy exists
("'the layer below already checks it' is the sentence that precedes every
allow-list bypass") is the right instinct. The handler then has an exhaustive
`match` with nowhere for an unknown field to go (`reactor_hooks.rs:78-111`),
which is what makes the property survive someone adding a field to the registry
without deciding what it means.

`patch_field_allowed`'s prefix rule (`reactor.rs:133-141`) is correct: `"ext."`
requires at least one character after the dot, so bare `ext.` and bare `ext` are
both refused, and `sub`/`aud`/`exp`/`scope` are unreachable because none of them
start with `ext.`. The `user.pre_*` list is `username`, `email`, `metadata.` —
never a credential, never `tenant_id`, never a role field — and
`a_field_outside_the_allow_list_cannot_be_written_by_the_handler`
(`reactor_hooks.rs:321-354`) asserts exactly that against the keys that matter.

Event payloads carry no credential: no password on `user.pre_create`
(`reactor_hooks.rs:124-131`), no password/token/session id on `login.post_auth`
(`service.rs:343-353`), no token or signing key on `token.pre_issue`
(`token.rs:402-411`). `require_mfa` composes with tenant policy by OR, never by
replacement (`service.rs:394-411`), and is not waived for federated users when a
reactor asked for it after seeing the login.

`ext.` claim rendering carries no security consequence — argued in §14.3.

---

## 13. What "no findings" does not mean

Everything in §12 was read in full, so "no findings" there means "read and
nothing found", not "sampled". What remains unexamined:

- **`axiam-amqp`'s audit and authz consumers** and the durable nonce dedup they
  use. They were read only far enough to establish the contrast in SEC-103.
- **The rest of `axiam-db`.** The `delete` survey behind SEC-104 covered eight
  repositories' delete methods; nothing else in that crate outside X6 and the
  federation/group queries cited above was read.
- **The frontend.** `frontend/src/pages/reactors/**` is being edited concurrently
  and is out of R6's named scope.
- **The lapin reactor transport**, because it does not exist. Every claim in this
  document about reactor *dispatch* is a claim about `gate.rs` and
  `dispatcher.rs` reasoning over a transport that always fails. The HMAC/replay
  path R6 asked me to "review under mutation" is reviewable only at the protocol
  layer (`protocol.rs`, done — §12.8, SEC-103); the half that enforces one reply
  per `correlation_id` has no implementation to review. **That should be an
  explicit R6 follow-up gate on the transport PR, not silently counted as done
  here.**
- **Anything requiring execution.** No compose stack, no broker, no SurrealDB, no
  bench hardware. The X6 probe was not re-run; the FAPI conformance suite was not
  run; SEC-094 was reproduced only at the level of the address predicate, not
  end-to-end through `reqwest`.

---

## 14. The six routed dispositions

### 14.1 Should an admin-API caller be able to confer `may-impersonate`?

**Disposition: no. Keep the omission, and make the omission legible.**

The current state: `KNOWN_GRANT_TYPES`
(`handlers/oauth2_clients.rs:239-246`) was widened to admit the device-code and
token-exchange grants, and deliberately does not admit
`urn:axiam:params:oauth:grant-type:may-impersonate`; a test pins it
(`tests/oauth2_client_test.rs:905-925`).

The design comment on `MAY_IMPERSONATE_GRANT`
(`axiam-oauth2/src/token_exchange.rs:65-71`) argues the capability belongs in
`grant_types` "so an operator reading `grant_types` sees this capability in the
same place as every other one". **That argument is about where the capability is
*stored and displayed*, and it is right. It is not an argument about who may
*write* it, and the two have been conflated.**

Three reasons the write should stay out of band:

1. **It is not a grant.** Every other entry in that list names a protocol flow a
   client may execute. This one names an authority: *"tokens minted for this
   client need not name an actor, and the resulting token is indistinguishable
   from one the subject obtained directly."* The exchange code says so —
   impersonation is off unless explicitly granted, and a client without it is
   *refused* rather than downgraded (`token_exchange.rs:548-563`) — and the audit
   record is documented as **the only surviving evidence** that the acting party
   was not the subject (`:208-213`).
2. **The permission that would gate it is the wrong shape.**
   `oauth2_clients:create` / `:update` is a routine client-administration
   permission. Conferring impersonation through it means a role granted for
   "manage our OAuth clients" silently also means "mint tokens as any user in
   this tenant". That is SEC-089's mistake — a change reviewed under one question
   answering a second, more sensitive one — repeated with a much larger blast
   radius.
3. **SEC-090 interacts.** F4 recorded that an impersonation exchange resets the
   actor-chain depth bound, and accepted it *precisely because* impersonation
   requires a grant no ordinary client has. Making that grant self-service through
   the admin API removes the bound F4's acceptance rested on.

**What to do instead:** the omission is currently a comment in a constant array
and a test. Make it a stated posture — the validator's error message should name
`may-impersonate` explicitly ("this capability is not settable through the API;
see …") rather than listing it as merely "unknown", and
`docs/api/token-exchange.md` should say how an operator *does* set it and what
review that is expected to carry. An operator who tries and gets "unknown
grant_type" will reasonably conclude the feature does not exist.

### 14.2 Is R2.2's unreadable-registry rule right?

**Disposition: the rule is right; the implementation over-applies it. See
SEC-100.**

The rule — *a registry that cannot be read is not evidence that no veto was
registered* — is correct, and the alternative is worse in a way that is easy to
underrate: if an unreadable registry meant "no reactors", then anyone who can
degrade the reactor table's availability can disable every `fail_closed` fraud
check in the deployment. That is a security control with an availability-shaped
off switch, which is the failure mode the whole `fail_closed` default exists to
avoid. The implementer chose correctly, and the choice is a genuine addition to
§22 rather than a deviation from it — §22.8 specifies per-registration policy for
a *dispatch*, and says nothing about the case where the registration list itself
is unknown, so this is filling a gap, not contradicting the contract.

Two things are wrong with how it is applied, both in SEC-100: it denies for
tenants that have provably never registered a reactor, and it resolves the
*event's* default rather than the registrations' own policies. Fix those and the
rule stands.

**One contract action:** §22 should say this. It is a normative server behaviour
an SDK author cannot infer, and an operator reading §22.8's per-registration
table would not predict a deny with no registration in sight.

### 14.3 Does `ext.` nesting have a security consequence?

**Disposition: no — and the nested form is the *safer* of the two. No finding.**

The rendering (`axiam-auth/src/token.rs:145-164`, `ext_claims_from_patch` at
`:187-207`) produces `ext: {"department": "…"}` rather than a top-level
`ext.department` claim, and the stated reason is performance:
`#[serde(flatten)]` forces buffered deserialization of the whole struct on every
access-token validation, which is the product's hottest path.

The performance argument is correct, and the security argument runs the same way:

- **Nesting makes claim-name collision structurally impossible.** Flattened
  custom claims share a namespace with `sub`, `aud`, `exp`, `scope`, `cnf`, `act`,
  `ext_exchange`, `tenant_id` and `org_id`. Whether a reactor-supplied key could
  shadow one of those would then depend on serde's field ordering and on the
  allow-list holding perfectly — three layers deep, but *one* of them being the
  only thing between a third party and `sub`. Nested, there is no ordering
  question to get wrong.
- The prefix is stripped by exactly one function, which drops (and logs at
  `error`) anything not in the namespace rather than writing it under a fallback
  name (`:191-204`).
- Values are `String` only (`patch: BTreeMap<String, String>`,
  `protocol.rs:89`), so there is no type-confusion surface for a resource server.
- Nothing inside AXIAM reads `claims.ext`, so no internal decision can be
  influenced by it.

The only consequence is **interop**, and it is worth writing down rather than
leaving for an SDK author to discover: a resource server or SDK middleware that
expects custom claims at the top level will not find them. §22 and the
"Writing a Reactor" doc page (R2.6) should state the rendering explicitly —
`ext.department` in the patch becomes `ext.department` in the *JSON path*, not a
claim literally named `ext.department` — with a one-line example of the decoded
token.

### 14.4 Is `UnavailableReactorTransport`'s fail-closed posture correct, and is the startup warning enough?

**Disposition: the posture is correct. The warning is not sufficient. See
SEC-101.**

**The posture is right and the alternatives are worse.** The three options were:
compose no gate (a registered `fail_closed` fraud check silently does nothing —
the exact failure reactors exist to prevent, and an operator who registered one
believes their logins are protected); compose a gate that special-cases the
missing transport as `Allow` (same outcome, with a code path that must be
remembered and removed later); or compose a transport that fails, and let each
registration's own `failure_policy` decide. The third is the only one where the
answer an operator gets matches the policy they configured, and it is audited and
counted per dispatch (`gate.rs:588-665`). The doc comment at
`dispatcher.rs:86-110` enumerates the consequences correctly, including that a
tenant with no registered reactor is completely unaffected.

**The warning is not sufficient**, for one specific reason: it is emitted at a
time and place disconnected from the action that triggers the consequence. The
`tracing::warn!` fires once at boot (`main.rs:634-644`), for every deployment,
including the overwhelming majority that will never register a reactor — which is
the classic recipe for a warning that is filtered out. The action that causes the
outage is `POST /api/v1/reactors` with `mode: intercept`, hours or weeks later, in
a UI that gives no indication anything is wrong.

Refuse the registration while the transport cannot dispatch. SEC-101 has the
shape.

### 14.5 Cross-tenant delete no-op — severity and disposition

**Disposition: Low. Fix in `axiam-db`, not in each handler. See SEC-104.**

Severity is low and it is important to be precise about why, because "cross-tenant
delete" sounds worse than it is: the `WHERE tenant_id = $tenant_id` predicate is
present and correct, so **no other tenant's data is ever touched**, and because
the 204 is returned uniformly — for a foreign id, a nonexistent id and a real one
— it is not an existence oracle either. What is actually lost is that an
administrator who deletes the wrong id is told it worked.

The disposition should not be "add a pre-check to the native handler to match
SCIM". That is the second copy of a check that belongs in one place, and the
third and fourth copies arrive with the next two resource types. `user` and
`webhook` already do it correctly in the repository (`RETURN BEFORE`, empty-row
check, `DbError::NotFound`); make `group`, `role`, `resource`, `permission` and
`service_account` match, and then delete `axiam-scim`'s pre-check
(`groups.rs:451`) rather than replicating it.

### 14.6 Is the SSRF guard's lack of an operator override right?

**Disposition: the *default* is right and must stay. The *absence of any
override* is a genuine hazard, and the current test-only seam is the wrong shape
for it. Recorded as SEC-107.**

**Why the default is right.** `allow_private` exists solely as an
integration-test seam, is `false` at all six production call sites, and — the
detail that shows the design was thought through — is honoured **only for the
first hop**, with every redirect target validated strictly regardless
(`ssrf.rs:29-42`). A `Location` header is attacker-influenced response data, not
the admin-configured URL the caller chose to trust, and holding it to the relaxed
standard would defeat the whole redirect defence. That is exactly right.

**Why the absence is nonetheless a hazard.** The guard is a *network-topology*
control being used as a *trust* control, and those diverge in real deployments:

- A Kubernetes-internal Keycloak or Entra-proxy at `10.x` is a perfectly
  legitimate IdP. Today AXIAM cannot federate with it at all.
- The same applies to an internal webhook consumer, an internal MDS mirror, and
  an air-gapped deployment where *everything* is RFC1918.
- It has already cost this project measurable work: R5.4's cross-vendor
  Keycloak test cannot use the containerized server for precisely this reason,
  and R8.1's conformance harness will hit the same wall.

An operator's only recourse today is to run AXIAM outside the guard's assumptions
or to patch the binary. That is not a security posture; it is a posture that gets
patched around, and a patched-around guard protects nobody.

**Recommended shape**, in preference order:

1. A **per-destination allowlist**, not a global switch — e.g.
   `AXIAM__PKI__SSRF_ALLOWED_HOSTS` as an explicit list of host names (not CIDRs),
   checked *in addition to* the resolved-address rule, so an operator names the
   exact IdP they intend to reach. A host-scoped exception cannot be widened by a
   DNS answer, which a CIDR exception can.
2. If that is too much for this wave, keep the absolute block and **document it as
   a deployment requirement** in `docs/deployment/README.md` at MUST level, so an
   operator planning a same-network IdP learns it before they build it rather
   than from a runtime `SsrfError::Blocked`.

What must not happen is a boolean `AXIAM__PKI__SSRF_ALLOW_PRIVATE=true`. That is
the `verify_peer: false` of this module, and `axiam-amqp`'s config already
contains the argument for why it should not exist (`config.rs:23-32`).

**Independently of all this: SEC-094 must be fixed first.** An override debate
about a guard that does not currently block `::ffff:169.254.169.254` is a debate
about the wrong thing.

---

## 15. Disposition

| ID | Finding | Severity | Action |
|---|---|---|---|
| **SEC-093** | Registration's client-auth method not enforced at PAR / revoke / introspect / token-exchange / uma-ticket | **High** | **Fix before merge** — route through `authenticate_client_credential` |
| **SEC-094** | SSRF guard does not canonicalise IPv4-mapped IPv6; CGNAT unblocked | **High** | **Fix before merge** — `to_canonical()` + `is_shared()` + tests |
| **SEC-095** | `login.post_auth` bypassed by SAML and OIDC SSO | **High** (latent until the lapin transport merges) | **Fix or scope normatively** before the transport ships |
| SEC-096 | Exchange strips sender-constraining; FAPI gate not applied to 3 grants | Medium | Fix — move grant dispatch after `dpop_from_request`; add `cnf` to `issue_exchanged_token` |
| SEC-097 | `dpop_require_nonce` is an inert, API-visible flag; comment misstates it | Medium | **Decide** — implement, or remove and document |
| SEC-098 | `scim:provision` sets any user's password; no session revocation on SCIM password/deactivate/delete | Medium | Fix (revoke) + document (the capability) |
| SEC-099 | `listen`-mode registrations deny on cap breach; `publish_listen` has no caller | Medium | Fix — filter to interceptors; implement or refuse `listen` |
| SEC-100 | Unreadable registry denies for tenants with zero reactors; uses event default not registration policy | Medium | Fix — negative caching or a "has registrations" bit |
| SEC-101 | Registering a `fail_closed` interceptor is a self-service login outage today | Medium | Fix — refuse `intercept` registration while the transport cannot dispatch |
| SEC-102 | DPoP `htu` derived from the `Host`/`Forwarded` headers | Low-medium | Fix — build from the configured issuer + `req.path()` |
| SEC-103 | Reactor replies authenticated per tenant, not per reactor; `nonce` signed but unchecked | Low | Add `reactor_id` to the HKDF info when the transport lands; gate single-use on that PR |
| SEC-104 | `delete` returns 204 for a foreign or unknown id in five repositories | Low | Fix in `axiam-db`; drop SCIM's pre-check |
| SEC-105 | X6 module headers overstate the nonce backstop's completeness | Low | Docs — amend three module headers |
| SEC-106 | AMQP client sets no minimum TLS version; a supplied CA adds to system roots | Low | Pin TLS 1.3; correct the `ca_cert_path` doc |
| SEC-107 | SSRF guard has no operator override for same-network IdPs | Low (usability) | **Decide** — host allowlist, or document as a MUST-level deployment constraint |
| — | X4 external token exchange | — | No findings (§12.2) |
| — | X5.1 DPoP / `private_key_jwt` / mTLS primitives | — | No findings (§12.3) |
| — | X3 MDS3 chain verification + enforcement | — | No findings (§12.4) |
| — | X6 layered single-use + engine attestation | — | No findings beyond SEC-105 (§12.5) |
| — | B4 SCIM tenant isolation | — | No findings (§12.1) |
| — | PAR, AMQP TLS, gRPC strict revocation (promoted) | — | No findings beyond SEC-106 (§12.6-12.7) |
| — | Reactor patch allow-list + `ext.` rendering | — | No findings (§12.8, §14.3) |

> **Remediation status (2026-08-15, after #323/#324): see §16.** SEC-093 …
> SEC-095 are closed and merged. Of the twelve below, nine are fixed, two are
> decided-and-implemented (SEC-097, SEC-107), and one is deferred with a
> precise residual (SEC-103, blocked on the lapin transport). SEC-106 is split:
> the CA-trust documentation is corrected, the TLS 1.3 floor is not settable
> through lapin's public API and is now a MUST-level broker-side deployment
> requirement.

**Gate status for the execution plan.** R6's gate is "no new HIGH open".
SEC-093 and SEC-094 are open and live; SEC-095 is open and latent. The gate is
**not** met.

**One closing note on scope.** SEC-093, SEC-096 and SEC-102 all live in the same
40 lines of `handlers/oauth2.rs` and `token.rs` — the token endpoint's grant
dispatch, which grew a `return` per grant and now has four early exits that skip
three shared controls between them. Fixing the three findings separately will
produce three patches to the same fork. The cheaper change is to restructure that
dispatch once so every grant passes through context construction, DPoP
verification, registration-driven client authentication and the profile gate
before it branches — and then the properties hold for the fifth grant nobody has
written yet.

---

## 16. Remediation of SEC-096 … SEC-107 (2026-08-15, post-#323/#324)

Every one of the twelve was re-triaged against the tree at `cd1af8f` before
anything was changed. None of them had been closed by #323 or #324 — those
merges added the SCIM crate, the SCIM rate-limit bucket, the coverage ratchet
and the three HIGH fixes, and touched none of the code below. Two findings
turned out to be *narrower* than §5–§11 described, and one turned out to be
*wider*; those three are called out by name.

| ID | Triage verdict at HEAD | Disposition |
|---|---|---|
| SEC-096 | Still applies — `handlers/oauth2.rs:363, 385` still `return`ed above `dpop_from_request` | **Fixed** |
| SEC-097 | Still applies — `oauth2.rs:549-563`'s comment verbatim; no reader of the field anywhere | **Decided: refuse the switch, keep the field** |
| SEC-098 | Still applies — `scim/users.rs` PATCH/PUT/DELETE called only `invalidate_subject` | **Fixed + documented** |
| SEC-099 | Still applies, **narrower than written**: the cap-breach path passes the unfiltered slice; the unreadable-registry path does not use `fail_whole_chain` at all | **Fixed** |
| SEC-100 | Still applies, **narrower than written**: `resolve`'s unbounded stale-serve already covers a warm process. The live defect is the cold cache | **Fixed for the population it hurt; residual recorded** |
| SEC-101 | Still applies, **wider than written**: `axiam-api-grpc`'s `ReactorAdminService` is a second, unguarded door onto the same outage | **Fixed on both surfaces** |
| SEC-102 | Still applies, **wider than written**: `extractors/auth.rs:285` has the same defect at the resource-server end | **Fixed at both sites** |
| SEC-103 | Still applies and still blocked — `UnavailableReactorTransport` is composed at `main.rs:625`; no lapin transport in the tree | **Deferred; residual recorded below** |
| SEC-104 | Still applies — `group`, `role`, `resource`, `permission`, `service_account` all `Ok(())` | **Fixed in `axiam-db`; SCIM pre-check deleted** |
| SEC-105 | Still applies — all three headers verbatim | **Fixed (docs)** |
| SEC-106 | Still applies, with one correction: the TLS backend is **rustls-connector**, not native-tls. The "adds a root" behaviour is the same (`tcp-stream 0.34/src/rustls_impl.rs` calls `add_parsable_certificates`) | **Half fixed, half deferred with a MUST-level deployment requirement** |
| SEC-107 | Still applies | **Decided: host allowlist implemented** |

### 16.1 SEC-097 — the decision, and why

Neither of §6's two options is taken verbatim, because both have a cost the
review did not price.

*Implementing it* requires the client row at `dpop_from_request` time, which is
before the client is looked up; the comment at that function explicitly argues
against loading the client twice and putting "does this client need a proof" in
two places. And without server-side nonce storage the echoed nonce cannot be
*verified* on the retry — so the honest version of option 1 is a second control
that does less than it appears to, which is the same defect one layer along.

*Removing the field* is a wire break: it is in `sdks/openapi.json` and therefore
in eleven downstream SDK repos, for a value that is always `false`.

**What was done instead:** the field stays (no wire break, `false` still
round-trips), the lying comment is gone, and `POST`/`PUT
/api/v1/oauth2-clients` now **refuse `dpop_require_nonce: true` with 400**,
naming the reason. That removes exactly what §6 said was unacceptable — a
persisted, API-visible switch that does nothing — at the point of the action,
which is the same shape as SEC-101's fix. `docs/security-profiles.md` records
the posture and the `jti` single-use control that actually carries the weight.
The refusal is one `if` a future nonce implementation deletes.

**Owed elsewhere:** `claude_dev/fapi-conformance-runbook.md:168` describes a
client "registered with `dpop_require_nonce: true`". That row is now
unreachable and needs amending; it was outside this change's file scope.

### 16.2 SEC-100 — what is fixed and what is not

The review's two options have the same residual, and it is worth stating so
nobody re-opens this expecting more. `ReactorRoutingTable::resolve` already
serves a stale entry **without a TTL bound**, so option 1 ("treat 'observed to
have zero reactors within the last N minutes' as sufficient") was already in
place for any process that has completed one successful resolve. Option 2's
in-process bit has the same hole. Both fail in exactly one case: a **cold
replica** whose very first read of `(tenant, event)` fails.

That case is now handled by asking a *different, broader* question —
`ReactorSource::tenant_has_registrations`, backed by a one-row `list` with its
own 60-second cache — and allowing only on `Ok(false)`. A per-table timeout or a
bad plan on the event index can take out one query and not the other, which is
the realistic trigger §9 names. An **error** from the probe is deliberately not
folded into "no registrations": that would rebuild the availability-shaped off
switch the rule exists to remove.

**Residual:** when both the per-event read and the presence probe fail on a cold
cache, the deny stands and resolves the **event's** default policy rather than
the registrations' own. That is not fixable — the premise of the arm is that the
registration list is unknown, so there are no per-registration policies to
resolve. Recorded in `gate.rs` beside the code.

### 16.3 SEC-103 — deferred, with the residual stated precisely

**No code change.** The lapin transport has not landed:
`axiam-server/src/main.rs:625` still composes `UnavailableReactorTransport`, and
`ReactorTransport::round_trip` has exactly one implementation, which always
fails. Adding `reactor_id` to `derive_tenant_key`'s HKDF `info` now would change
a key derivation that no deployed reactor can yet exercise, in a change nobody
can test end to end — and would then have to be re-verified against the
transport when it arrives. It is free at that point and impossible afterwards,
which is the argument for doing it *with* the transport, not before it.

**The residual, unchanged and unmitigated:**

1. Every reactor registered in a tenant derives the same reply-signing key from
   `(master, key_version, tenant_id)` (`axiam-amqp/src/messages.rs:101-111`), so
   reactor A can produce a reply the server accepts as reactor B's. The only
   thing preventing it is that `correlation_id` is a fresh `Uuid::new_v4()`
   delivered to B's own queue — secrecy of a value, not authentication of a
   party.
2. `ReactorReply::nonce` is signed and covered by the MAC and **never checked**
   (`protocol.rs:94`, `into_outcome` at `:237-309`). Single-use rests entirely on
   ±300 s freshness plus "the transport awaits exactly one reply per
   `correlation_id`", and that second half has no implementation.

**Both are acceptance criteria on the lapin transport PR, not on this change:**
add `reactor_id` to the HKDF `info`, and make "exactly one reply is consumed per
`correlation_id`" an explicit test.

### 16.4 SEC-106 — the TLS 1.3 floor cannot be set client-side

The `ca_cert_path` documentation is corrected in `axiam-amqp/src/config.rs` and
in `docs/deployment/README.md`: a supplied bundle is **added to** the platform
roots, so an operator pinning their private broker CA has widened the trust set,
not narrowed it. (The review attributed this to lapin's native-tls backend; the
backend here is rustls-connector, and it does the same thing via
`add_parsable_certificates`.)

**The version floor is deferred, and it is a dependency limit rather than a
choice.** lapin 4.10's only TLS-carrying entry point is
`Connection::connect_with_config(uri, props, OwnedTLSConfig, runtime)`, and
`OwnedTLSConfig` (`tcp-stream 0.34`) has exactly two fields — `identity` and
`cert_chain`. There is no seam for a rustls `ClientConfig`, so a client-side
floor means reimplementing `AMQPUriTcpExt::connect_with_config` against
`tcp_stream::TcpStream::into_rustls` and owning lapin's handshake sequencing.
rustls 0.23's default version set is TLS 1.2 + 1.3, so a broker offering only
1.2 is accepted today.

`docs/deployment/README.md` now states `ssl_options.versions.1 = tlsv1.3` on the
broker as a **MUST-level** deployment requirement, with the `openssl s_client`
commands to verify it, and `connection.rs::build_tls_config` carries the same
note beside the code so the next reader does not re-derive it. Revisit if lapin
gains a connector hook.

### 16.5 SEC-107 — the allowlist, and the five things that keep it from being a hole

`AXIAM__PKI__SSRF_ALLOWED_HOSTS` is implemented as §14.6's preferred option: a
per-destination **host** list, never a boolean and never a CIDR. It is
default-empty; installed once in the composition root and not re-armable;
matched by ASCII-lowercased **exact** equality with no wildcard or suffix
semantics; honoured on the **first hop only**, with every redirect target still
validated strictly; and it cannot reach a cloud metadata endpoint —
`169.254.0.0/16`, `fe80::/10`, `fd00:ec2::254`, `100.100.100.200`,
`192.0.0.192` and the deprecated `::/96` encoding stay refused for an
allowlisted host, with the IPv4-mapped spelling canonicalised **before** that
check so SEC-094 is not re-opened. Every use logs at WARN; an allowlisted host
resolving to a metadata endpoint logs at ERROR and is refused.

### 16.6 New findings turned up during the work

* **SEC-102 has a second site.** `axiam-api-rest/src/extractors/auth.rs:285`
  built the resource-server `htu` from `req.full_url()` too — the same defect at
  the other end of the same comparison. Fixed in the same change, fail-closed
  (no `AuthConfig` in scope ⇒ no proof verifies ⇒ a `jkt`-bound token is
  refused rather than accepted against an attacker-chosen `htu`).
* **SEC-101 has a second door.** `axiam-api-grpc`'s `ReactorAdminService`
  accepts registrations through `create_reactor`/`update_reactor` and never saw
  the gate. Refusing only in REST would have left the outage one `grpcurl`
  away. Both surfaces now read the same `can_dispatch()` off the same composed
  gate.
* **Two existing tests asserted the behaviour SEC-104 removes**, and both have
  been rewritten rather than relaxed:
  `axiam-db/tests/role_permission_test.rs::delete_role_does_not_strip_foreign_tenant_edge`
  (the survival assertions — the actual security property — are unchanged; only
  the status the caller is told changes) and
  `axiam-api-rest/tests/rbac_handlers_gaps_test.rs::delete_permission_not_found_is_idempotent_204`,
  which called the old 204 "idempotence" when what it actually was is an
  uninspected statement result.
