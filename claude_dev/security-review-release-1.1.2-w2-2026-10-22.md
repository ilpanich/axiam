# Security review — release 1.1.2, wave W2 (F4)

**Date:** 2026-10-22.
**Against:** `claude/release-1.1.2-w2`, the whole wave diff `dc5bfd4..8839345` (13 commits,
32 files, 2 749 lines added and 404 removed): `802f15c` (W2.1, #751), `dd76988` (W2.2, #752,
D-5), `ec6a779` (W2.3, #754, D-4), `d3f10b0` (W2.4, #731), `763a655` (W2.5, #732), `1c6f7a6`
and `e8f0628` (W2.6, #733, #758 (g)), `d74c95d` (W2.7, #735), `dfad1c2` (W2.8, #741, D-2),
`16e5f74`, `e2b1f53` and `aa2a35f` (W2.9, #758 (a), (c), (d), D-3, D-12), `8839345` (W2.10,
#734). Every commit carries one `gpgsig` header (SSH signing; the sandbox has no
`allowedSignersFile`, so `%G?` cannot verify).
**Scope:** plan §3: the carrier rule (`crates/axiam-auth/src/carrier.rs`, the audit middleware,
`extractors/auth.rs`), the client-address rule (`crates/axiam-core/src/forwarded_for.rs`,
`client_info.rs`, `request_span.rs`), the principal key and its refund (`extractors/rate_limit.rs`,
`middleware/rate_limit_shared.rs`), the boot (`crates/axiam-server/src/boot.rs`), the AMQP
provenance stamp (`crates/axiam-amqp/src/audit_consumer.rs`, the console's audit page), the two
scans (`rate_limit_bucket_names_test.rs`, the action-grammar pin in `models/audit.rs`), and
T-118, T-212, T-289 (its SEC-087 note), T-428, T-474 and T-477 in both copies.
**Method:** that of the 1.1.1 W2 review, with its severity scale. Every commit message was read
in full and each claim checked against the tree (§9). Five claims were settled by scratch code in
a separate `git worktree` with its own target directory, run and discarded (the branch was never
touched; §8): the revoked-session drain of R112W2-01 (probe B), the `AuthenticatedPrincipal`
verdict of R112W2-02 (probe A), the grammar pin's blind spots of R112W2-03 (five mutants), and
the W2.6 audit-wrap mutation (§6). The full test binaries of `axiam-core`, `axiam-auth`,
`axiam-audit`, `axiam-amqp`, `axiam-oauth2`, `axiam-api-grpc` (and `--features client`),
`axiam-api-rest` (SAML on, one `--test` at a time) and `axiam-server` (`--no-default-features`)
were run (§8). This review fixes nothing. IDs: `R112W2-nn`.

---

## 0. Summary

**No Critical, High or Medium finding.** The carrier rule is one rule: the audit middleware, the
REST extractors and therefore the rate-limit key now read the same token on every path, so no
request is audited as one principal and served as another (§2). The client-address rule is one
function for the REST limiters, the request row, the handlers' rows and the span, and `none`,
non-UTF-8 and mixed values are handled as stated (§4). W2.3's principal key is a faithful
synchronous mirror of what `AuthenticatedUser` admits, and the refund cannot be farmed (§3). The
AMQP stamp cannot be set, changed or removed by a producer (§5). The `compose_app` refactor
changes no production behaviour, and the behavioural audit-wrap test does fail when the wrap is
removed (§6). The threat-model copies are byte-identical (§7).

One **Low** finding concerns the issue's own attack. #754 names three tokens that drain a user's
principal bucket: a device-grant token, a resource-audience token, and a token whose session was
revoked. The first two are now keyed on the address. The third is refunded by the shared counter
only. The in-process governor sits beneath it **with the same allowance** and has no refund, so
in the production composition a revoked-session token still empties the user's allowance on
every replica it reaches. Probe B: three revoked-session requests (the allowance), then the
user's own live session gets `429`. W2.3's refund tests use a composition with no governor, so
they cannot show this; the residual is documented in T-474 and the sizing guide, but it is
the attack #754 was filed for.

Four **Informational** findings follow. (02) D-12's verdict is recorded by `AuthenticatedUser` and
`ConsoleSignIn` only. `AuthenticatedPrincipal`, on 98 handler sites, refuses synchronously without
it, so a validly signed token it refuses `401` is still recorded `authenticated: true` (probe A).
(03) The grammar pin does not see a `pub(crate)` constant or a `&'static str` one (mutants pass).
(04) The admin guide says "a row without `ingested_via` was written by the server", which is
false for rows ingested before 1.1.2, and no text dates the stamp. (05) The gRPC listener keeps its own copy of the
address rule, and no gRPC test exercises `none`.

| ID | Finding | Severity | Surface / threat | Origin | Issue | Model for the fix |
|---|---|---|---|---|---|---|
| R112W2-01 | A token whose session was revoked still spends its user's principal allowance. The shared counter refunds that `401`, but the principal-keyed in-process governor beneath it has the same allowance and no refund. In the production composition (`register_api_v1_routes`), `END_SESSION_PER_MIN` such requests from as many addresses leave the user's own live session at `429`, on each replica, for the stale token's remaining lifetime (≤ 15 min). This is #754's third named token; W2.3's refund tests use a governor-less app. | Low | `server.rs:1528-1552, 2104-2132` (`build_principal_governor` under `keyed_on_principal`); `rate_limit_shared.rs:326-343, 518`; `extractors/rate_limit.rs:342-360`; T-474 | wave (W2.3 closed #754 for two of its three tokens) | [#786](https://github.com/ilpanich/axiam/issues/786) | **Opus 5.5** |
| R112W2-02 | The D-12 verdict (`AuthVerdict`) is left only by `AuthenticatedUser`, `ConsoleSignIn` and `AuthenticatedPrincipal`'s user-branch async half. `AuthenticatedPrincipal`'s synchronous refusals (`extract_principal`: audience, session id, `sub`/`tenant_id`/`org_id`, `sub_kind`, the tenant path binding) and its machine branch's DPoP replay check leave none. So do the UMA PAT, SSF receiver, `CertificateBoundServiceAccount` and `AuthenticatedServiceAccount` extractors. A validly signed token one of them refuses is still recorded `authenticated: true`. Probe A: the same token (unparseable session id) gets `401` on both kinds of route, and is recorded `false` on the `AuthenticatedUser` route and `true` on the `AuthenticatedPrincipal` route. | Informational | `extractors/auth.rs:1553-1612, 1614-1660`; `handlers/uma.rs:54-90`; `handlers/ssf.rs:237, 267`; `handlers/network_decide.rs:277`; `axiam-audit/src/middleware.rs` (`authenticated`) | wave (W2.9 (c) covered one extractor family of several) | [#787](https://github.com/ilpanich/axiam/issues/787) | Sonnet 5.5 |
| R112W2-03 | The action-grammar pin does not see constants declared `pub(crate) const`, `pub(super) const` or `pub(in …) const`, or typed `&'static str`. It strips only the prefixes `pub const ` and `const `, and splits on `": &str ="`. Mutants `pub(crate) const ZZ_ACTION: &str = "bad  two spaces";` and `pub const ZZ_ACTION: &'static str = "bad  two spaces";` pass the test, while the same value as `pub const ZZ_AUDIT_ACTION` fails it. The commit says it covers "any constant added later in any crate". None of the tree's constants is in either form today. | Informational | `crates/axiam-core/src/models/audit.rs:129-215` | wave (W2.9 (d)) | [#788](https://github.com/ilpanich/axiam/issues/788) | Sonnet 5.5 |
| R112W2-04 | The admin guide says "a row without `ingested_via` was written by the server". T-118's amendment and the AsyncAPI text say only that the server never sets the key, and none of the three says when the stamp started. Rows ingested over AMQP before the upgrade carry no stamp, so for those the guide's inference is false. The console badge has the same blind spot. | Informational | `docs/admin/README.md:556-578`; T-118 (both copies); `docs/api/asyncapi.yml`; `AuditLogsPage.tsx` (badge doc comment) | wave (W2.8) | [#789](https://github.com/ilpanich/axiam/issues/789) | Sonnet 5.5 |
| R112W2-05 | The address rule is one function for REST (`select_client_ip`), but `GrpcTrustedHopsKeyExtractor::extract` keeps a hand-copied twin, and `trusted_hops_from_env` a second reading of `TRUSTED_HOPS`. They agree today, `none` included (by `honours_forwarded_for`). No gRPC test sets `none`, although W2.9 (a)'s commit and the guide say both listeners honour it. | Informational | `crates/axiam-api-grpc/src/middleware/rate_limit.rs:104-109, 228-260`; `forwarded_for.rs` (`select_client_ip`) | wave (W2.2 left gRPC untouched; W2.9 (a) tested REST only) | [#790](https://github.com/ilpanich/axiam/issues/790) | Sonnet 5.5 |

---

## 1. What was reviewed, and how

| Point of the brief | Where answered |
|---|---|
| W2.1 × W2.9 (c): audited as one principal, served as another; the verdict against the carrier on every path | §2; R112W2-02 |
| W2.3: every refusal of `AuthenticatedUser` against `verified_principal`; the farming bound; a client token with `sid`; the revoked-session drain | §3; R112W2-01 |
| W2.2 × W2.9 (a): one rule for limiter and audit IP; `none`, empty, list, non-UTF-8, mixed; IPv4-mapped; `forwarded_for_claimed` injection | §4; R112W2-05 |
| W2.8: a producer cannot set or remove `ingested_via`; non-object metadata; the badge vs `source`; old rows | §5; R112W2-04 |
| W2.6: the audit-wrap test fails without the wrap; `compose_app` changes nothing | §6 |
| W2.9 (d): the grammar pin catches a later constant | §7.1; R112W2-03 |
| Threat-model copies | §7.2 |
| Test binaries, `check-config-key-coverage.py`, frontend | §8 |

---

## 2. W2.1 and W2.9 (c): the carrier and the verdict

### 2.1 One token per request

`access_token_carrier(cookie, authorization)` returns the `axiam_access` cookie when it is present
and non-blank, and otherwise the `Authorization` credentials under `Bearer` or `DPoP` (case-
insensitive), or `None`. Both readers now call it with the same two values from the same request:
`extract_or_cache_user_info` in the audit middleware, and `parse_validated_claims` in the
extractors. Both read the cookie with `req.cookie(ACCESS_COOKIE)` (actix's first match, the same
function on `ServiceRequest` and `HttpRequest`) and the header with `headers().get(…).to_str().ok()`
(the first value). Path by path:

| Request carries | Middleware names | Extractor serves | Same? |
|---|---|---|---|
| cookie only | the cookie's subject (if it verifies) | the cookie's subject | yes |
| `Bearer` / `DPoP` only | the header's subject | the header's subject | yes |
| valid cookie + `Basic …` / junk `Bearer x` | the cookie's subject (#751 fixed) | the cookie's subject | yes |
| valid cookie + valid `Bearer` of another user | the cookie's subject | the cookie's subject | yes (cookie-first, as the extractor always was) |
| invalid cookie + valid `Bearer` | nobody (validation fails, nothing cached) | `401` (not retried against the header) | yes: neither admits |
| blank cookie `axiam_access=` + `Bearer` | the header's subject | the header's subject | yes |
| non-ASCII `Authorization` | treated as absent | `401` "invalid scheme" (`contains_key`) | yes: neither admits |

The extractor admits from the middleware's cache only through `cached_identity`, which re-checks
`cnf` against this request, and the cache was filled from the same carrier. So the token the row
names, the token the rate-limit key reads (`verified_principal` reads the same cache) and the
token the handler is served under are one token. Before W2.1 the middleware and the key read the
header while the extractor read the cookie. That divergence is gone. No path admits a request as
one principal and records it as another.

The plan's "a header that yields no verified token falls back to the cookie" is what cookie-first
gives without a second pass. The commit's plan-vs-tree note is accurate.

### 2.2 The verdict

`refused()` marks `AuthVerdict::Refused` (and `SessionCredentialRefused`) on every error of
`extract_user` and of `admit_credential`. `apply` marks `Admitted` after `admit_credential`, before
the active-tenant decision. The middleware reads the verdict from the response's request after the
handler, and sets `authenticated = user_info.is_some() && verdict != Refused`. Because the
carrier is shared (§2.1), whenever the middleware verified a token, the verdict on that request is
about the same token.

- **`true` for a refused token** remains possible wherever the refusing extractor is not
  `AuthenticatedUser`/`ConsoleSignIn` (R112W2-02). The middleware verifies signature, expiry,
  issuer and `aud ∈ {user, m2m}` (`decode_access_token`), so a resource-audience token is not
  verified at all and is recorded `false` everywhere. But a user token with an unusable session
  id, a machine-audience token that is not a service account's, or a token for another tenant's
  `/t/` path verifies in the middleware, and `AuthenticatedPrincipal` refuses it without a verdict.
  `extract_principal`'s `Err` is returned through `start?` and never passes `refused()`. Probe A
  (§8) shows `GET /probe/principal → 401, authenticated: true` beside
  `GET /probe/user → 401, authenticated: false` for one token. The same holds for the PAT
  extractor's `403` to a user token, the SSF receiver's refusals and the machine branch's DPoP
  replay.
- **`false` for an admitted token** happens only where the middleware cannot name the token. That
  is a client-credentials token (`sub` is `oa_…`, not a UUID) admitted by the PAT or SSF
  extractor, and the RFC 6750 §2.2 body carrier of `POST /oauth2/userinfo`, which the middleware
  does not read. Both are 1.1.1 behaviour, with actor `System`, and not this wave's. They are
  noted in R112W2-02's issue so the fix can decide them.
- `MaybeAuthenticatedUser` (`/oauth2/authorize`) records `Refused` and the handler continues
  anonymously. `false` is right there.
- An extractor run twice on one request (a tuple of extractors) can only overwrite `Admitted` with
  `Refused`, never the reverse, because a refusal ends the request.

---

## 3. W2.3: the principal key and the refund

### 3.1 The mirror

`may_admit_as_session` requires three things. `user_session_of` must pass: it is the extractor's
own function, split out of `check_user_aud_and_parse_jti`, covering audience and session id. The
token must not be a session-less grant (`sid` absent and any of `client_id`, `permissions`, `act`,
`ext_exchange`). And the tenant path binding must match. Against `AuthenticatedUser`'s refusals,
one by one:

| Refusal | Decidable synchronously? | `verified_principal` |
|---|---|---|
| no token, bad signature, expired, another issuer | yes (nothing cached) | `None` → address |
| `aud` absent outside the window, `m2m`, unknown | yes | `user_session_of` → address |
| `sid`/`jti` not a UUID | yes | `user_session_of` → address |
| `sub`/`tenant_id`/`org_id` not a UUID | yes | the middleware caches nothing → address |
| tenant path binding | yes | mirrored → address |
| `cnf` not proved on this request | yes, but not mirrored | keyed `(address, principal)` (`sender_constrained`): an address cannot spend another's |
| device grant, RPT, exchanged token (no `sid`) | the extractor refuses at the session lookup, by `jti` | mirrored as "grant without session" → address |
| session revoked or expired | no (datastore) | principal; shared counter refunds; **governor does not** (R112W2-01) |
| DPoP proof replayed | no (datastore) | `(address, principal)`; refunded on the shared counter |
| `ConsoleSignIn` 403 to a client token | not on these routes (all five take `AuthenticatedUser`) | n/a |

The only way the mirror can say "address" where the extractor would admit is a client token with
no `sid` whose `jti` names a live session. That shape existed before `sid` (#681) and has no
issuer today. It is the safe direction anyway: such a token would be keyed on its address and not
on the user.

The plan-vs-tree decision is sound. `minted_for_client()` would key every relying party's
code-grant token on its address and undo #633's relay. "What `AuthenticatedUser` admits" is
the right rule, and `a_client_token_with_a_live_session_spends_its_users_bucket` pins it.

### 3.2 Farming

`refunds_the_charge` refunds `401`/`403` only when the charge was principal-keyed and the
extractor left `SessionCredentialRefused`. The marker is written only on the extractor's own
refusal, so a refused request never reached a handler. All five routes take `AuthenticatedUser`
as a **required** extractor (`federation.rs:1419, 1503, 1720, 1768, 1834`), and no handler in the
crate takes `Option<AuthenticatedUser>` or `Result<AuthenticatedUser, _>`. An attacker therefore
gets no extra attempt at anything the bucket protects. Address-keyed charges are never refunded,
and a handler's `401`/`403` is never refunded. A refunded request has cost one session lookup, or
one DPoP `jti` write for the caller's own key. The in-process governor still counts it.
`the_refund_is_bound_to_the_extractors_refusal_of_a_principal` pins both arms. The commit's
farming bound holds.

### 3.3 The revoked-session token (R112W2-01)

The issue's attack is "any party holding an unbound token minted for user X can drain X's bucket".
Take a relying party, or anyone who saw X's token, after X's session is revoked: by logout,
password change, or MFA reset. The token passes `may_admit_as_session`, since it carries a `sid`
and the user audience. Each of the five resources is wrapped, from the outside in, by
`build_federation_flow_backstop` (address, 10×), `RateLimitShared … keyed_on_principal()`, and
`build_principal_governor(end_session_per_min)`. The shared layer charges X and refunds the `401`.
The governor charged X too, from the same `bucket_key_part`, and actix-governor has no refund.
After `end_session_per_min` stale requests, X's own requests on that replica get the governor's
`429`. The shared counter's refund does not help X, because the governor is the tighter of two
equal limits. With several replicas, the attacker spreads the requests until every replica is
spent. The backstop does not help either: the attacker needs only one request per address, or
thirty from one address.

Probe B composes the routes exactly as `routes_app!` does, with the shared counter on, the audit
middleware and a session validator that knows only X's live session. Three requests (`PER_MIN`)
with X's revoked-session token come back `[401, 401, 401]`, and X's live session then gets **429**.
W2.3's `the_shared_counter_refunds_a_revoked_sessions_401` and
`…_console_only_routes_403` pass because `shared_only_app!` mounts the shared counter with no
governor. The commit states the residual, and so do T-474 and the sizing guide. But it is one of
the three tokens #754 lists, so #754 is not closed by this wave as written.

**Fix (proposal).** The governor cannot be refunded, so the key has to be right before it charges.
On the five principal-keyed resources, decide session liveness before either limiter charges.
`RateLimitShared::call` is already async and outermost of the two. In `keyed_on_principal` mode it
can await the registered `SessionValidator` for the cached identity's `(tenant, session_id)` and
insert a `PrincipalSessionLive` extension. `verified_principal` then returns the principal only
when that extension is present, and the address otherwise. That costs one session read per request
on five human-speed routes. The extractor's own lookup could reuse the result (store it beside the
marker), so the net cost is zero. The design must hold with `AXIAM__RATE_LIMIT__SHARED=off`, where
the shared layer does not run. Either split the liveness pre-check into its own middleware placed
outside the governor, or keep the shared layer's pre-check when the counter is off. An alternative
is to give the governor a refund (wrap it and re-credit on the marker). That is harder with
actix-governor's API and leaves a race between replicas.
**Test:** probe B as a permanent test in `rate_limit_principal_test.rs` (`routes_app!` with the
counter on and off): `PER_MIN + 1` revoked-session requests from as many addresses get `401`, and
X's live session is then served `PER_MIN` times and gets `429` after. Keep `shared_only_app!` for
the refund arithmetic.

---

## 4. W2.2, W2.4, W2.5 and W2.9 (a): the address rule

- **One rule (REST).** `select_client_ip` is the only selector. It is called by
  `select_rate_limit_ip` (both REST limiters), the audit middleware's request row (through
  `ClientIpRule`, default `configured()`), `client_info::client_ip` (the handlers' rows,
  `network_decide` included) and `http.client_ip` on the span. Every caller reads
  `configured_trusted_hops()` and `TrustedProxies::configured()`, the same `OnceLock`. The body
  is the 1.1.1 `select_rate_limit_ip` body moved, unchanged. `X-Real-IP` and `Forwarded`, which
  `realip_remote_addr` used to honour, are no longer read, which is stricter.
- **gRPC.** There is no gRPC audit row with an address (`ip_address` does not occur in
  `axiam-api-grpc/src`). The gRPC key extractor applies the same rule through its own copy
  (R112W2-05).
- **Values.** Unset → empty (honour every peer, the WARN on native TLS). `none`, in any case,
  surrounded by blanks or with blank entries (`"none,"`) → `nobody()`: honour no peer, no WARN,
  one INFO. `none` beside a block, or twice → `NoneMixed`, which stops the boot by name. A
  non-UTF-8 value → `NotUnicode`, which stops the boot without echoing the bytes. A bad entry →
  `Entry`. A near miss (`nonexistent`) → `Entry`. `TrustedProxies::configured()` still maps an
  error to the empty list, but only the boot's `trusted_proxies_for_boot` decides whether to
  start, and it panics first on every error. `configured()` is reached in production only inside
  a running server. `is_empty()` is false for `none`, so the WARN and the INFO cannot both fire.
- **The WARN (W2.4)** is now emitted after `grpc_tls_from_env` resolves, decided on
  `server.tls.enabled` and `GrpcTls::Rustls(_)`, and it names the listener(s). A bad list still
  stops the boot at the parse, which comes earlier.
- **IPv4-mapped IPv6.** `IpNetwork::contains` canonicalises (`canonical(ip)`), so a mapped peer
  matches a v4 block. The row prints the peer as `peer_addr()` gives it, the same string the
  limiter keys on. `forwarded_for_claimed` compares parsed addresses, so a mapped/unmapped spelling
  of one address can produce a redundant claim, but never a missing one.
- **`forwarded_for_claimed` injection.** It is the leftmost entry of a header that passed
  `HeaderValue::to_str()`, so visible ASCII plus tab only (no CR/LF, no non-ASCII). It is trimmed,
  cut to 45 characters, stored as a JSON string in `metadata`, escaped on serialisation, and
  rendered by React as text. It is recorded only when it differs from the recorded address, and
  never used for a decision. Nothing reaches a log line unescaped.

---

## 5. W2.8: the provenance stamp

`stamp_ingested` builds the row's metadata from the producer's value: an object is kept, `null`
or absent becomes `{}`, and any other JSON value is moved under `producer_metadata`. It then
**inserts** `ingested_via = "amqp"`, so a producer-supplied `ingested_via` (any type) is
overwritten and cannot be removed. The insertion is the last write before
`CreateAuditLogEntry`, so the producer has no later hook. No other ingestion path exists: no
REST or gRPC route appends a caller-supplied audit entry; the only `post()` routes near the audit
log are the export and the PGP batch signature. No server writer sets `ingested_via`
(`git grep`). The badge tests `metadata?.ingested_via === "amqp"` only, so `metadata.source`,
which producers and server writers both use, cannot raise or hide it. The reverse spoof would
need a server writer that copies caller JSON into audit metadata, and none was found. Rows
ingested before 1.1.2 carry no stamp and read as server-written (R112W2-04).

---

## 6. W2.6: the audit-wrap pin and `compose_app`

**The refactor.** `compose_app` is the former closure body, line for line: the same four
`.wrap`s in the same order, the same seven `app_data` registrations plus `AppState`, and the same
four `configure` calls. The per-worker clones (`rest_authz.clone()`, … `rl.clone()`) become one
`deps.clone()` of a `#[derive(Clone)]` struct whose fields are the same `Arc`s, `AppState` and
`RateLimitConfig`. `AuditMiddleware` was cloned per worker before and still is. Nothing moved into
`deps` is read after `HttpServer::new` (the crate compiles with the moves). Production behaviour is
unchanged.

**The mutation.** In the worktree, `.wrap(deps.audit_middleware)` in `compose_app` was commented
out and `cargo test -p axiam-server --no-default-features --test audit_wraps_routes` was run:
exit **101**. Both pins fail.
`a_request_to_a_federation_route_is_audited_and_keyed_on_its_principal` panics at `:157`: the
request that should meet the principal's spent bucket from a new address gets `400`, i.e. it was
served, keyed on its address. `the_audit_middleware_is_on_the_app_new_chain` panics at `:254`
with its message. `a_commented_out_wrap_does_not_satisfy_the_scan` passes, as it should, since it
reads a synthetic source. The behavioural test does depend on the wrap.

**The gRPC sweep test** (`governor_sweep_families_test.rs`) builds the method-scoped layer's four
governors, feeds fifty peers to each, waits past the replenish period and sweeps. It asserts four
registered limiters, no cells, and none kept alive after the layer is dropped. It reads the
registry, not a source scan, which is what #733 asked for.

---

## 7. Audit actions and the threat model

### 7.1 The grammar pin (R112W2-03)

`is_valid_audit_action` is printable ASCII with at most one inner space, so `"Bad Action!"` is a
valid action, and the first mutant chosen with it passed for the right reason. With an invalid
value (`"bad  two spaces"`):

| Mutant appended to `models/audit.rs` | Result |
|---|---|
| `pub const ZZ_AUDIT_ACTION: &str = "bad  two spaces";` | **fails** (named in the message) |
| `pub(crate) const ZZ_ACTION: &str = "bad  two spaces";` | passes |
| `pub const ZZ_ACTION: &'static str = "bad  two spaces";` | passes |
| `pub const ZZ_ACTION:&str = "bad  two spaces";` | passes (rustfmt would rewrite it; not a finding) |
| `pub const ZZ_CREATED: &str = "bad  two spaces";` | passes (by design: the name does not claim an action) |

**Fix:** match declarations with `^\s*(pub(\([^)]*\))?\s+)?const\s+(NAME)\s*:\s*&\s*('static\s+)?str\s*=`.
**Test:** a synthetic-source unit test of the matcher over the four declaration forms, in the
style of W2.7's `an_increment_by_prefix_collides_with_a_middleware_name`.

The W1.6 and W4.2 actions are on other branches. Their names (`network_role.unassigned`,
`network_role.deleted`) are within the grammar, and the merge note in `aa2a35f` is correct.

### 7.2 Threat-model copies

Each paragraph W2 changed in `threat-model-stride.md` was compared, by script, with the
`Axiam.json` threats. Every one occurs verbatim in exactly the matching entry's `mitigation`:
T-118 (#741), T-212 (W2.2, W2.4, W2.5, W2.9 (a), W2.10), T-289 (the SEC-087 note, W2.2), T-428
(W2.10), T-474 (W2.3, W2.7) and T-477 (W2.6). `Axiam.json` parses and is still `2.43.0`. T-110 is
not touched, and the commit says why (its key set is unchanged: the key appears only when a claim
differs). The amendments are dated, and the older text stays.

---

## 8. Checks run (each tool's own exit code)

`CARGO_PROFILE_{DEV,TEST}_DEBUG=0`, `CARGO_INCREMENTAL=0`; `protobuf-compiler`, `libxml2-dev` and
`libxmlsec1-dev` installed (the first REST pass failed in `samael`'s build script for want of
`libxmlsec1-dev` and was re-run; not a code failure); swagger placeholder set. One `--test` at a
time, each binary's own exit code.

| Command | Exit |
|---|---|
| `cargo test -p axiam-core` (lib, `models_coverage`, `req14_pagination_test`) | 0 each (570 passed) |
| `cargo test -p axiam-auth` (lib + 18 binaries) | 0 each (464 passed, 1 ignored) |
| `cargo test -p axiam-audit` (lib + `dead_letter_bounds`, `dead_letter_env`, `dead_letter_failure_log`, `request_audit_loss`, `service_and_middleware`) | 0 each (88 passed) |
| `cargo test -p axiam-amqp` (lib + 13 binaries; the containerized ones skip their bodies without Docker) | 0 each (297 passed, 11 ignored) |
| `cargo test -p axiam-oauth2` (lib + 6 binaries) | 0 each (839 passed) |
| `cargo test -p axiam-api-grpc` (lib + 8 binaries; `grpc_auth_test`, `grpc_authz_test`, `grpc_reactor_test`, `grpc_userinfo_test` require `client` and are covered below) | 0 each (114 passed, 0 failed) |
| `cargo test -p axiam-api-grpc --features client` | 0 (149 passed) |
| `cargo check -p axiam-api-rest --no-default-features` | 0 |
| `cargo test -p axiam-api-rest` (SAML on), lib + 113 binaries | running at this commit; recorded in the follow-up commit |
| `cargo test -p axiam-server --no-default-features`, lib + 28 binaries | running at this commit; recorded in the follow-up commit |
| `cargo fmt -p` (the eight crates) `-- --check` | 0 |
| `npx vitest run src/pages/audit/AuditLogsPage.test.tsx` | 0 (18 passed) |
| `npx tsc -b --noEmit` (frontend) | 0 |
| `python3 scripts/check-config-key-coverage.py` | 0 |
| `python3 scripts/check-crate-layering.py` | 0 |
| `bash scripts/check-doc-links.sh` | 0 (537 links, 78 files) |
| `python3 scripts/check-remediation-evidence.py` | 0 (5 verified, 32 skipped) |
| `python3 -c 'json.load(…Axiam.json)'` | 0 |
| Threat-model copy comparison (script, §7.2) | every changed paragraph verbatim in the matching entry |
| `git cat-file -p <c> \| grep -c gpgsig`, 13 commits | 1 each |
| Probe B (worktree, appended to `rate_limit_principal_test.rs`, `--no-default-features`) | 101 by design: `stale=[401, 401, 401] own_after=429` (R112W2-01) |
| Probe A (same file) | 101 by design: `/probe/user → 401, authenticated: false`; `/probe/principal → 401, authenticated: true` (R112W2-02) |
| Grammar-pin mutants (worktree, `cargo test -p axiam-core --lib every_server_action_constant`) | 101, 0, 0, 0, 0 (§7.1; R112W2-03) |
| W2.6 mutation (worktree, `.wrap(deps.audit_middleware)` removed; `--test audit_wraps_routes`) | 101: both pins fail (§6) |

The worktree and its target directory were deleted afterwards; the branch carries none of the
scratch code.

---

## 9. Commit messages and §10

| Commit | Claim | Verdict |
|---|---|---|
| `802f15c` | one carrier rule, cookie first; a non-carrier header never shadows the cookie; an invalid cookie is not retried | true (§2.1) |
| `dd76988` | every audit and log IP from the limiters' rule; `forwarded_for_claimed` when it differs, cut to 45; gRPC untouched | true (§4); gRPC's copy noted (R112W2-05) |
| `ec6a779` | principal only for what `AuthenticatedUser` admits; refund only on the extractor's marker; the farming bound; the governor residual | true (§3.1, §3.2); the residual is #754's own third case and leaves the issue open in substance (R112W2-01) |
| `d3f10b0` | WARN on both listeners, naming each; emitted after gRPC TLS resolves | true (§4) |
| `763a655` | `NotUnicode` stops the boot without echoing; `from_lookup` twin | true (§4) |
| `1c6f7a6` | `compose_app` unchanged; behavioural pin | true (§6) |
| `e8f0628` | four family governors swept | true (§6) |
| `d74c95d` | `increment*` keys read; an untraceable one refused | true: the scan panics on a key it cannot trace, so a new writer is counted or fails |
| `dfad1c2` | the stamp after the merge; non-object kept; console badge; export | true (§5); old rows (R112W2-04) |
| `16e5f74` | `none` honours nobody on both listeners; mixed refused | true by inspection on both; tested on REST only (R112W2-05) |
| `e2b1f53` | `authenticated` is the extractor's verdict | true for `AuthenticatedUser`/`ConsoleSignIn` routes only (R112W2-02) |
| `aa2a35f` | every action constant pinned, "any constant added later in any crate" | true for the `pub const NAME: &str` form; not for `pub(crate)` / `&'static str` (R112W2-03) |
| `8839345` | T-212 and T-428 corrected, dated, both copies | true (§7.2) |

§10: every commit is signed. There is no contract edit, migration, route or crate; the layering
check passes. Each row's test is in its commit. No new assertion interpolates a token or a secret:
the new tests build tokens at run time and print statuses and row metadata.

---

## 10. What could not be verified

- The gRPC listener under `none` with a real transport (R112W2-05): by inspection only.
- Multi-replica behaviour of R112W2-01: argued from the per-replica governor; probe B is one
  replica.
- The console badge in a browser: the vitest test renders it; no visual check.
- `check-remediation-evidence.py`'s SDK rows (the SDK repositories are 403 from this sandbox).

---

## 11. For later tasks

- **W7.1** (contract): the carrier precedence (cookie first; an invalid cookie is not retried
  against the header) may be stated for SDK authors who send both. `authenticated` in the request
  row is the extractor's verdict where `AuthenticatedUser` ran, a server-side matter with no
  contract surface. §8 of the contract gets the `ingested_via` sentence (W7.1 (d)): the key is
  server-owned, overwritten, and absent on rows ingested before 1.1.2.
- **W8.3** (threat model): T-474 must not read as if #754 were closed for revoked sessions until
  R112W2-01's fix lands. T-118 needs "since 1.1.2" (R112W2-04). `website/src/threatModel.ts` was
  not regenerated by any W2 commit.
- **W8.4** (CHANGELOG): `TRUSTED_PROXIES=none` (a direct deployment should set it; a placeholder
  entry still works; `none` mixed with blocks or a non-UTF-8 value now stops the boot); the request
  row's `ip_address` is now the limiters' address with `forwarded_for_claimed` beside it, and
  `X-Real-IP`/`Forwarded` are no longer read for it; `metadata.ingested_via = "amqp"` on rows
  ingested from 1.1.2 on, absent on earlier ones; the carrier rule (cookie first) for the audit row.

---

## 12. Issues

Filed on `ilpanich/axiam`, milestone `1.1.x`:

| ID | Severity | Issue | Model |
|---|---|---|---|
| R112W2-01 | Low | [#786](https://github.com/ilpanich/axiam/issues/786) | Opus 5.5 |
| R112W2-02 | Informational | [#787](https://github.com/ilpanich/axiam/issues/787) | Sonnet 5.5 |
| R112W2-03 | Informational | [#788](https://github.com/ilpanich/axiam/issues/788) | Sonnet 5.5 |
| R112W2-04 | Informational | [#789](https://github.com/ilpanich/axiam/issues/789) | Sonnet 5.5 |
| R112W2-05 | Informational | [#790](https://github.com/ilpanich/axiam/issues/790) | Sonnet 5.5 |

Per plan §1.4 the wave's sweep slot takes them in order of severity (R112W2-01 first, at Opus 5.5),
and this review gains an addendum on the sweep's diff. #754 should not be closed by the wave's
merge until R112W2-01 is fixed; #741, #751, #752, #731, #732, #733, #734, #735 and #758 (a), (c),
(d), (g) are met by the wave as reviewed (#758 (c) subject to R112W2-02, #758 (d) to R112W2-03).
