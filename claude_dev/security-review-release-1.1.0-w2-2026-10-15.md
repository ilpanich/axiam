# Security review — release 1.1.0, wave W2 (F4)

**Date:** 2026-10-15.
**Against:** `claude/release-1.1.0-w2`, the whole wave diff `3d011573e..c7ec9a1c2`
(5 commits, 23 files, 1 999 lines added and 112 removed). Every commit carries a
signature (`gpgsig` header in 5 of 5; the sandbox has no
`gpg.ssh.allowedSignersFile`, so `%G?` cannot verify them here).
**Scope:** every W2 task of the release-1.1.0 plan (§3): W2.1 #654 (the SAML
waits on the shared crypto semaphore bounded, `cad058673`, and its SAML-off
follow-up `fea3b64d6`), W2.2 #632 (the authenticated federation callbacks get
buckets of their own; a duplicate-name scan, `b1ddc8947`), W2.3 #633 (the five
authenticated federation flow routes keyed on the verified principal,
`ff8ca52a0`), W2.4 #634 (the IdP's self-checks parse with the receiver's
options, `c7ec9a1c2`).
**Method:** adversarial reading of the diff and of every sibling path it
implies, against [`threat-model-stride.md`](threat-model-stride.md) and
`Axiam.json` (model 2.41.0, 477 threats), the plan's §10 rules, and the OWASP
ASVS 5.0 areas the diff touches (V2 anti-automation, V7/V9 session and token
handling, V13 configuration, V16 logging). Claims were checked against the code,
not the commit messages; every commit message was read in full and its claims
are answered in §3 … §8. No probe was needed: every point the orchestrator
raised was settled by reading and by the wave's own tests, which were run
(§11). This review fixes nothing: every finding has evidence, a proposed fix and
an issue body (§12). IDs: `R110W2-nn`.

---

## 0. Summary

**No finding is Medium or higher. Two Low and four Informational.**

The wave does what its four issues ask. The shared crypto semaphore has no
unbounded **unauthenticated** waiter left; a busy ACS reads exactly like a
signature that does not verify; the IdP's busy `503` is written before any
state; the principal key cannot be minted or pointed at another principal, and
it reads only an identity the server verified on the same request. What the
review adds:

* **R110W2-01 (Low, wave — W2.3).** Principal keying removed the per-address
  bound on the five routes for any caller that presents a valid token. One
  address holding *K* verified principals now gets *K* allowances, without
  limit. Such principals are cheap to collect on a tenant with self-registration,
  or for anyone who can mint service-account tokens. The tree's own precedent for
  principal keying keeps a per-address backstop: the CIBA pending list
  (R101W3-04, `server.rs:854-866`), at ten times the per-user allowance.
  Recommended in-wave: about ten lines in `server.rs` (§2).
* **R110W2-02 (Low, pre-existing; the executor's DPoP follow-up, widened).** The
  audit middleware caches an identity only for the `Bearer` scheme or the
  cookie. A `DPoP`-scheme request therefore has two gaps:
  * its request-audit row is written with a nil actor and a nil tenant
    (`authenticated: false`);
  * on the five routes, it is keyed on its address.

  Caching the `DPoP` scheme is safe, because every reader of the cache enforces
  the sender constraint (§5.4).

| ID | Finding | Severity | Surface / threat | Origin | Disposition |
|---|---|---|---|---|---|
| **R110W2-01** | The five principal-keyed routes have no per-address bound left for a caller with a valid token. One address with many principals (self-registration, service accounts) multiplies `end_session_per_min` without limit. The CIBA list, the tree's precedent for principal keying, keeps a NAT-sized per-address backstop. | **Low** | `server.rs:1458-1478,1898-1925`; `extractors/rate_limit.rs:287-316` → T-474 | wave (W2.3) | Issue; **recommended in-wave** (§2) |
| **R110W2-02** | The audit middleware returns no identity for an `Authorization: DPoP …` request (`middleware.rs:644`). The request-audit row of every DPoP-scheme call is unattributed (nil actor, nil tenant), and the five routes key it on the address. | **Low** | `axiam-audit/src/middleware.rs:636-669` → T-474, the request-audit entries | pre-existing (W2.3 relies on it) | Issue |
| R110W2-03 | Unbounded acquirers remain on the shared crypto semaphore: the IdP's assertion signing (`saml_idp.rs:1306`), its SLO signing (`saml_idp_slo.rs:777`), and **eight PKI sites**. The PKI sites are certificate issuance ×3, CA generate, intermediate and sign ×3, and PGP generate and sign ×2. T-102's amendment says the IdP signing is "what remains unbounded". Every one of them is authenticated, and every one is self-limiting now that the waiters ahead of it are bounded. | Informational | `cert.rs:507,601,860`; `ca.rs:153,466,637`; `pgp.rs:54,160` → T-102, T-477 | pre-existing | Issue (executor follow-up confirmed) |
| R110W2-04 | The bucket-name scan reads only `RateLimitShared::<…>::ctor(` registrations. Four kinds of name in the same key space are outside it: a call without the turbofish; the handler-side `shared_rate_limit.check_at*` keys (`oauth2_par:…`, `ciba_notify:…`, …); the gRPC families (`grpc_authz`, …); and anything in `rate_limit_shared.rs`. None collides today. | Informational | `tests/rate_limit_bucket_names_test.rs:105-200` → T-474 | wave (W2.2) | Issue |
| R110W2-05 | No in-process governor is ever swept. actix-governor 0.10 evicts nothing, and no code calls `retain_recent`. The new principal-keyed maps grow with the number of distinct principals; the CIBA precedent sweeps its map. Every address-keyed map has the same property, and with IPv6 it is worse. | Informational | `server.rs:41-116`; `ciba_list_limiter.rs:20-97` | pre-existing (W2.3 adds five maps) | Issue |
| R110W2-06 | Text and pins behind the code (details in §12). In the threat model: two false statements in T-102 and T-477, an imprecise one in T-477, and T-474 omits the DPoP case. In the deployment docs: two rows still say "per IP". Nothing pins `boot.rs`'s audit-before-limiter order. The website's threat-model copy is not regenerated (the plan defers it to W8.3). A busy ACS consumes the one-time login state, which no document says. | Informational | STRIDE/`Axiam.json`, `docs/deployment/*`, `boot.rs:3069` | wave | Issue |

**What held.**
* **W2.1.** Every SAML verification acquires through `CryptoGate`, with the
  configured wait, at both composition roots (§3).
  * The type change means no caller can hand over a bare semaphore any more.
    A composition that forgets `with_crypto_gate` still gets a bounded private
    gate.
  * The ACS's busy answer equals a tampered response's answer in status, body,
    headers, request-audit row and caller-visible logs. Only timing differs,
    and timing tells the caller about load, never about the document.
  * The IdP's `503` is written before any binding cookie or pending row.
* **W2.2.** The two allow-listed names are deliberate. In each case, one limit
  and one seeding rule cover one resource or one API (§4).
* **W2.3.** The principal comes only from `validate_access_token` run by the
  audit middleware on the same request (§5):
  * the only writer of the extension is that middleware;
  * the request cannot write extensions;
  * both layers use one key function;
  * the other key modes are byte-identical;
  * no route other than the five changed;
  * `principal` is refused in `AXIAM__RATE_LIMIT__KEY`;
  * in `boot.rs`, the audit middleware wraps the whole app, outside every
    route limiter.
* **W2.4.** Both `sign.rs` sites changed. No libxml parse in the workspace
  uses the default options any more. The remaining default-option parse is
  samael's re-parse inside xmlsec, T-474's stated residual (§6).
* **§10 rules.** Every rule holds for what the wave added (§7).
* **CI parity.** The SAML-off `check` (lib and `--tests`) and clippy on the
  touched crates pass with `RUSTFLAGS=-Dwarnings` (§11).
* **Threat model.** The amended entries are identical in `Axiam.json` and the
  STRIDE document (§8).

**Verdict on merge.** Nothing blocks. R110W2-01 is Low, but the wave puts
`Closes #633` on a change that drops a bound the tree's own precedent keeps,
and its fix is one extra `.wrap` per route. It is better taken now than filed.
The rest are issues for the next patch milestone.

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| Bounded crypto gate; ACS/metadata/IdP refusals | W2.1 #654 + `fea3b64` | `saml_gate.rs`, `saml.rs` (`verify_signature_off_worker`, `handle_saml_response_for`), `saml_metadata.rs` (`parse_idp_metadata_off_worker`, `SamlMetadataCache::resolve`), `handlers/saml_idp.rs` (`accept`, `verify_post_signature_off_worker`, `busy_page`, `issue`), `handlers/saml_idp_slo.rs` (`receive`, `verify`, `sign_with_active_key`), `handlers/federation_login.rs`, `federation.rs` (both ACS), `error.rs` (both crates), `state/mod.rs`, `boot.rs`; **every acquirer of the semaphore in the workspace** (`rg acquire`) | **read in full**; the REST busy tests read and run |
| Bucket names, the scan | W2.2 #632 | `rate_limit_bucket_names_test.rs`, `server.rs`, `axiam-scim/src/routes.rs`, `rate_limit_shared.rs`; every writer of the shared counter's key space (middleware, handlers, gRPC) | **read in full**; escapes enumerated |
| Principal keying | W2.3 #633 | `config/rate_limit.rs`, `extractors/rate_limit.rs`, `middleware/rate_limit_shared.rs`, `server.rs`, `axiam-audit/src/middleware.rs` (`call`, `extract_or_cache_user_info`), `extractors/auth.rs` (`parse_validated_claims`, `cached_identity`, `extract_user`), `axiam-auth/src/token.rs` (`decode_access_token`), `boot.rs` App composition, the five handlers, `ciba_list_limiter.rs` and the CIBA wiring (precedent), actix-governor 0.10 source | **read in full**; tests run |
| Self-check parse | W2.4 #634 | `saml_idp/sign.rs`, `tests/receiver_parser_options.rs`; every `Parser::default()` / `parse_string*` in `crates/*/src` | read in full; tests run |
| Threat model, docs | all | T-102, T-474, T-477 in both copies; `docs/deployment/README.md`, `rate-limit-sizing.md`; `website/src/threatModel.ts` | compared (§8, §9) |

Not run: the frontend, a multi-replica deployment, and the Keycloak SLO
binaries. The wave changes nothing they exercise: the IdP's signing paths are
untouched.

## 2. R110W2-01 — principal keying removed the per-address bound for authenticated callers

**Severity: Low. Wave-introduced (W2.3). Recommended for a fix in the wave.**

**The design, as committed.** `bucket_key_part` (`extractors/rate_limit.rs:287-316`)
picks the key as follows:

| The request carries | Its key |
|---|---|
| A verified bearer token | `principal:{tenant}:{sub}` |
| A verified `cnf` token | `{ip}:principal:{tenant}:{sub}` |
| Nothing verified | `{ip}` |

The five routes now carry only that key (`server.rs:1458-1478,1898-1925`):
* `build_governor`, the address-keyed governor, was *replaced* by
  `build_principal_governor`;
* the shared bucket was re-keyed.

No layer of these routes keys on the address any more once a token verifies.
The commit body chose "the principal alone" over `(address, sub)` on the
plan's first oracle, and that choice is right as far as it goes: one token from
many addresses must be one bucket.

**What it gave up.** Before #633, one address could spend 30 a minute
(`end_session_per_min`) on each route, whatever tokens it presented. Now one
address can spend 30 a minute **per verified principal**, and the number of
principals one party can hold is not bounded by anything on these routes:
* **Self-registration.** On a tenant with self-registration, accounts and their
  tokens accumulate at the registration and login limits (per address, per
  minute), and each live token is a fresh bucket for 15 minutes.
* **Service accounts.** A tenant administrator (or a stolen administrator token)
  can mint service-account tokens. These carry a UUID `sub` and verify at the
  audit middleware, so they are keyed on the principal even though the
  extractor then refuses their audience. The refusal comes after the limiter
  has charged a fresh bucket.

**What it costs per request:**

| Route | Cost of one request |
|---|---|
| `oidc/authorize` | one `federation_login_state` row (10-minute TTL) |
| `oidc/callback` | one outbound token exchange to the configured IdP |
| `saml/acs` | one SAML verification on the shared crypto semaphore. It needs no stored state on this path (`handle_saml_response` with `expected_request_id = None`, `federation.rs:1786`). |
| `authn-request`, `metadata` | a configuration read and a cached metadata lookup |

The ACS is the one that matters: the semaphore it spends is the one Argon2id
logins and the CRL re-sign wait on (T-102, T-477).

**Why Low and not more.** A distributed sender reaches the public ACS without
any account, so the ceiling on semaphore pressure is not this route's. Every
principal costs a real account and a real login. The crypto wait is now bounded
(W2.1).

**The precedent.** The tree has one other principal-keyed limiter, the CIBA
pending list (D-4, R101W3-04). It keeps an address-keyed governor at
`CIBA_LIST_BACKSTOP_FACTOR = 10` times the per-user allowance
(`server.rs:22-26,854-866`). The reasoning is in its comment: "NAT-sized, so
thirty tabs (and an office of them) behind one address never meet it". W2.3
did not carry that half over, and neither the commit body nor T-474 mentions
it.

**Proposed fix.** On each of the five resources, add an address-keyed backstop
outside the principal layers, sized like the CIBA one:

```rust
.wrap(build_principal_governor(rate_limit_cfg.end_session_per_min))
.wrap(RateLimitShared::<C>::browser_preset("federation_link_saml_acs", rate_limit_cfg)
    .keyed_on_principal())
// R110W2-01: the per-address backstop the principal key would otherwise drop.
.wrap(build_governor(
    rate_limit_cfg.end_session_per_min.saturating_mul(FEDERATION_FLOW_BACKSTOP_FACTOR),
))
```

* Use a `const FEDERATION_FLOW_BACKSTOP_FACTOR: u32 = 10;` beside
  `CIBA_LIST_BACKSTOP_FACTOR`, or reuse that one.
* A per-replica governor is enough, as it is for the CIBA list. If a
  cross-replica backstop is wanted, use a `RateLimitShared::new(…_addr, …)` with
  a distinct name, which the W2.2 scan will then check.
* A relay of up to ten users at full speed, or many more at human speed, never
  meets the backstop. A party holding hundreds of principals behind one address
  does.

**Tests (in `rate_limit_principal_test.rs`):**
* *k* principals from one address, with *k* × `PER_MIN` above the backstop, meet
  `429` at the backstop;
* *k* principals below it each get their own allowance (the existing relay test
  stays green);
* one token from many addresses is still one bucket.

**Threat model:** T-474's #633 correction gains the backstop sentence and names
the test.

## 3. W2.1 — the crypto gate (orchestrator point 1)

### 3.1 Every acquirer of the shared semaphore

The composition root builds one semaphore (`boot.rs:705`) and hands it to the
services at `:850, 1054, 1059, 1067, 1074, 1399, 1438, 2574, 2912`.
`AppState::for_test` does the same (`state/mod.rs:593-985`). Acquirers on HEAD:

| Acquirer | Reached by | Wait | Wave |
|---|---|---|---|
| Argon2id hash/verify (login, reset, gRPC user, directory bind) | public login, reset; authenticated gRPC | `acquire_hash_permit`, `hash_acquire_timeout_secs` (5 s) | — |
| CRL re-sign | public `GET …/crl` | `timeout(DEFAULT_CRL_PERMIT_WAIT = 5 s)` (`crl.rs:576`) | — |
| SP ACS verification, public and link | public `/auth/federation/saml/acs`, `/acs/form`; authenticated `/federation/saml/acs` | `CryptoGate::acquire("saml_acs")` (`saml.rs:755-759`) | **bounded** |
| IdP metadata verification (sign-in cache miss, admin fetch) | public `/saml/login` on a miss; admin | `CryptoGate::acquire("saml_metadata")` (`saml_metadata.rs:294`) | **bounded** |
| IdP SSO/SLO POST receiver | public `/saml/v2/{t}/sso`, `/slo` | `CryptoGate::acquire("saml_idp_receiver")` (`saml_idp.rs:648-655`) | **bounded** |
| IdP assertion signing | after an authenticated sign-in (`issue`) | `acquire_owned().await`, **no bound** (`saml_idp.rs:1306`) | residual |
| IdP SLO message signing | a logout run's next hop | **no bound** (`saml_idp_slo.rs:777`) | residual |
| Certificate issue / CSR sign | admin and user certificate routes | **no bound** (`cert.rs:507,601,860`) | not named by T-102 |
| CA generate / intermediate / sign | admin | **no bound** (`ca.rs:153,466,637`) | not named |
| PGP generate / sign | admin; the audit-signing export | **no bound** (`pgp.rs:54,160`) | not named |

Not acquirers:
* the Redirect-binding query check (`RedirectQuery::verify_signature`,
  `request.rs:924`), which runs inline (one RSA public-key operation, §3.5);
* the DB pool's and the directory client's semaphores, which are other
  semaphores.

**So every unauthenticated acquirer is now bounded.** Ten authenticated ones
are not (R110W2-03). Because every waiter that can queue ahead of them now
gives up within its bound, an unbounded authenticated waiter waits at most about
one bound plus the service time of the permits ahead of it. T-102's amendment
names only the IdP's two signing sites as what remains unbounded, which is
false as text (R110W2-06).

**Composition.**
* `with_crypto_semaphore(Arc<Semaphore>)` is gone, and `with_crypto_gate`
  takes a `CryptoGate`, so no caller can hand over a semaphore without a wait.
* Both compositions call it with `hash_acquire_timeout_secs` (`boot.rs:1436-1440`,
  `state/mod.rs:982-986`).
* A `SamlFederationService::new` left without it gets a **private** semaphore
  with `DEFAULT_WAIT = 5 s` (`saml.rs:180-183`). That is bounded, but it does
  not share the deployment's permit budget. Nothing in the tree builds one that
  way outside unit tests.
* The IdP side builds its gate per request from `state.crypto_semaphore` and
  `state.auth_config` (`saml_idp.rs:678-683`), the same Arc and the same
  configuration as `boot.rs:2912`.
* `fea3b64` gates the `for_test` binding on `saml`, as its consumer is. The
  SAML-off build has no other gated binding left (§11).

### 3.2 The ACS: is busy really indistinguishable from invalid?

**Order.** `handle_saml_response_for` does its work in this order (`saml.rs:448-501`):
1. the enabled and protocol checks;
2. base64, UTF-8, the encoding and DTD refusals;
3. samael's quick-xml parse;
4. **then** `verify_signature_off_worker`, which takes the permit before
   anything in `verify_signature` reads the signature.

A document that fails step 1, 2 or 3 is refused identically with the gate free
or busy. A document that reaches step 4 is refused with
`SamlSignatureInvalid("Encountered an invalid signature")` (`saml.rs:157,759`),
whether the gate was busy or the signature did not verify. That string is
samael's text for a tampered response, and the unit test
`r101_02_acs_verification_gives_up_when_the_gate_is_held` compares the two, so
a samael bump that rewords it fails the test.

**What the caller can compare:**

| Channel | Busy vs invalid |
|---|---|
| Status | 401 both: `AuthenticationFailed` (`federation/error.rs:159-161`, `api-rest/error.rs:50`) |
| Body | identical: `{"error":"authentication_failed", …reason…}`; asserted byte-for-byte by `federation_test::r101_02_…` |
| Headers | identical: same error path, same `ResponseError` |
| Request-audit row | identical: `POST {path}`, `http_status: 401`, `authenticated: false` (public) or the same user (link route) |
| Logs | a `warn` with `site` and `wait_ms` on busy (`saml_gate.rs:70-75`): server-side only, no request content |
| Timing | **differs**: busy answers after `hash_acquire_timeout_secs` (5 s by default); a verdict takes milliseconds |

The timing difference reveals that the deployment is saturated, which is not a
property of the document. It is no oracle on the signature, the certificate or
the configuration, which is the property that matters, and §10's "one verify
per refusal" rule exists to protect exactly that (§7).

**Collateral.** The public ACS consumes the one-time login state *before* the
verification (`federation_login.rs:1063` before `:1077`;
`federation.rs:2637` before `:2656` likewise). A busy refusal therefore ends that sign-in
attempt: the user starts again, and the operator sees an "invalid signature"
`401` plus the gate's `warn`. That is acceptable, since it is the same thing a
tampered response does, but it is undocumented (R110W2-06 (f)).

**Metadata.** A busy gate refuses with "metadata verification is busy; retry
shortly" (`saml_metadata.rs:294-300`). The text is distinguishable, but it
says only that the deployment is loaded. A failure stores nothing
(`resolve`, `:529-536`), so a busy refusal does not poison the cache. The
fetch happens before the gate (`:529`), as it did before the wave; a
saturated gate turns each `/saml/login` cache miss into a wasted fetch, bounded
by `login_per_min`.

### 3.3 The IdP receiver's `503`: is the permit taken before request-dependent work?

**No, and it does not need to be.** `accept` (`saml_idp.rs:698-760`) does all
of the following before `verify_post_signature_off_worker`:
* parses the `AuthnRequest`;
* refuses a Redirect-binding enveloped signature;
* looks up the SP **by the request's own `Issuer`** (`:716-728`, `unknown_sp`
  → 400);
* decodes the SP's certificate;
* decides whether the request is signed.

The SLO `verify` (`saml_idp_slo.rs:440-479`) runs after the SP lookup and the
`sp_disabled` check. So a `503` tells a caller, while the gate is saturated,
that the `Issuer` names an enabled, registered SP with a signing certificate,
and that the message passed parsing.

It is not a new oracle:
* **Already observable.** An unsigned request naming a registered SP that does
  not require signatures is answered `303`. The SLO route answers `403
  sp_disabled` and `sp_has_no_certificate` already.
* **Public anyway.** SP entity ids are published in the SPs' own metadata.
* **Costly to use.** Reading the `503` needs the shared semaphore held
  saturated for the whole wait, which is itself the denial of service.

What is wrong is the *text*. T-477 and the code comment at `saml_idp.rs:641`
say "the permit is taken before the document is evaluated", which is true of
the signature only (R110W2-06 (b)).

**State before the `503`.** None:
* `accept` writes nothing before `hold` (`:853`), which is reached only after
  verification;
* `refusal_page` writes no audit row;
* the SLO path writes nothing before `handle_request` / `handle_response`.

`saml_idp_sso_test::r101_02_…` asserts no binding cookie and no pending row.
`Retry-After: 5` is a fixed header and is not tied to the configured wait,
which is harmless.

### 3.4 The left-unbounded IdP signing (executor follow-up 1)

**Confirmed, Informational** (R110W2-03). The two signing sites can be reached
only through:
* an authenticated browser session completing `sso_continue` (assertion
  signing), or
* a logout run already in flight (SLO signing), which needs either a
  `LogoutRequest` whose signature verified, the user's own `sso_logout`, or a
  `LogoutResponse` whose `InResponseTo` matches a run.

T-477's residual says the SLO signing is reached "only after the SP's
signature has verified". That is imprecise: an SP that registered no
certificate advances the chain with an *unsigned* `LogoutResponse`
(`saml_idp_slo.rs:971-975`), which still needs the run's random request id
(R110W2-06 (a)).

Bounding these sites needs a deliberate failure answer:
* for assertion signing, a signed `Responder` status needs a signature, so the
  answer would have to be an unsigned error page or a retry page;
* for SLO signing, the hop would be marked partial, as an unsignable
  participant already is (`sign_with_active_key` returns `Err("signing")` and
  `next_hop` marks the run partial).

The SLO case therefore has its failure path already; only the assertion case
needs a design.

### 3.5 The Redirect-binding check (executor follow-up 2)

**Confirmed, Informational, pre-existing.** `RedirectQuery::verify_signature`
(`request.rs:924-970`) runs inline on the async worker: one RSA public-key
verification over the query string. The string is bounded by the URL limit,
and the SP's key is whatever its administrator registered. A public-exponent
verification is microseconds at the sizes SPs use. It does not need the gate,
and putting it there would make it wait on Argon2id. **Not filed separately:**
recorded in R110W2-03's body as "decided: stays ungated".

## 4. W2.2 — the bucket-name scan (orchestrator point 2)

**What it reads.** Registrations of the shape `RateLimitShared::<…>::{new,
browser_preset, new_client_identity_aware}(…)` in `crates/*/src`, with:
* whole-line comments blanked;
* `middleware/rate_limit_shared.rs` excluded (`:113`);
* the first argument read as a literal or as a same-file `const NAME: &str`.

An unknown constructor, a `format!`, a parameter, a `$macro_var` or a const
declared in another file each **panic** (refused, not skipped), and
`a_bucket_name_the_scan_cannot_read_is_refused` pins that.

**What escapes it** (R110W2-04):

1. **A call without the turbofish.** The scan's anchor is `RateLimitShared::<`
   (`:147`). `RateLimitShared::new("x", n)` with the type inferred, a
   `use … as` alias, or a `Self::new` in an impl is not seen. Every call in the
   tree today uses the turbofish (`rg 'RateLimitShared::(new|browser_preset)'`
   finds none without it), so this is a guard against tomorrow.
2. **The same key space, written elsewhere.** Several writers share one
   counter, and its `{endpoint}:{key}` space is persisted in `rate_limit_bucket`:
   * the handlers that call `state.shared_rate_limit.check_at*` directly:
     `oauth2_token_public:…`, `oauth2_uma_ticket:…`, `oauth2_token_exchange:…`,
     `oauth2_par:…`, `oauth2_bc_authorize_client:…`, `ciba_approval_list:…`,
     `ciba_notify:…`, and `ciba_hint_cap:…` in `axiam-oauth2`;
   * the gRPC layer (`grpc_authz`, `grpc_identity`, `grpc_admin`, `grpc_infra`,
     `axiam-api-grpc/src/middleware/rate_limit.rs:349-356`).

   None of these prefixes is a `RateLimitShared` name today. `oauth2_par` the
   middleware does not use; checked by listing both sets. Their keys also
   differ in shape: a tenant UUID with hyphens never equals an IP literal. So
   nothing collides, but nothing would notice if one did.
3. **The excluded file.** A real registration added to `rate_limit_shared.rs`
   would not be counted.
4. **Block comments.** `/* … */` is not blanked. That fails closed: a commented
   registration counts.

**The allow-list.** Both entries are deliberate:
* `directory_config` ×3 is `PUT`/`PATCH`/`DELETE` of
  `/tenants/{t}/directory` (`server.rs:1534-1561`): one limit
  (`directory_admin_per_min`), plain `new` (one seeding rule), and a comment at
  the registration stating the sharing.
* `uma_rreg` ×2 is `/rreg/resource_set` and `/{id}` (`server.rs:652-668`):
  one limit (`uma_perm_per_min`), plain `new`, and `uma_perm` apart on purpose.

The commit's "Plan vs tree" on `login` and `oauth2_authorize` is right:
* each appears once outside the excluded file;
* each entry records its exact count, so a stale or a grown entry fails.

## 5. W2.3 — the principal key (orchestrator point 3)

### 5.1 Can the limiter read an identity the server did not verify, or another principal's?

**No.**
* **One writer.** The extension `Arc<CachedUserIdentity>` is written in one
  place in the workspace: `extract_or_cache_user_info`
  (`axiam-audit/src/middleware.rs:612-669`), immediately after
  `validate_access_token` succeeded. That function checks the EdDSA signature
  over AXIAM's key, `exp` (60 s leeway), the issuer (pinned, or `enforce_issuer`
  under tenant paths), and `aud` ∈ {user, m2m} when present
  (`token.rs:1627-1666`); it then requires the `sub`, `tenant_id` and
  `org_id` claims to parse as UUIDs.
* **No other writer.** `rg CachedUserIdentity crates/*/src` finds no other
  writer. Request extensions are server-side only, and no header or cookie is
  copied into them.
* **No re-verification.** `verified_principal` (`extractors/rate_limit.rs:266-275`)
  only reads the extension.

**Whose identity it is.** It is the one the handler will act as. On a
disagreement between carriers, the cache wins in the handler too:
`extract_user` returns the cached identity before reading any carrier
(`extractors/auth.rs:1004-1022`).

| The request carries | The audit middleware caches | The limiter keys on | The handler acts as |
|---|---|---|---|
| `Bearer A` + cookie `B` | `A` (header first, `middleware.rs:636-652`) | `A` | `A` (the cache) |
| A non-Bearer header (`Basic`, `DPoP`) + cookie `B` | nothing (`:644`) | the address | `B` (`auth.rs:655`, cookie first) |
| Garbage `Bearer` + cookie `B` | nothing | the address | `B` |

The limiter never charges a principal other than the one the request
authenticates as. The opposite case does happen (the limiter falls back to the
address where the handler finds a principal), and it is fail-safe: it is the
pre-#633 key.

**Tokens the extractor later refuses** are still keyed on their principal.
That covers:
* an M2M-audience service-account token;
* a token whose tenant does not match a `/t/{tenant}` path;
* a revoked but unexpired session.

In each case the bucket charged is the token's own principal's. Charging it
needs that principal's token, which is the stated residual: a stolen or revoked
token spends its principal's allowance on five account-linking routes for at
most one access-token lifetime. Informational; T-474 states it.

### 5.2 Is the cached tenant the request's tenant?

**It is the token's tenant**, the `tenant_id` claim, which the issuer check
makes coherent with `iss`. The five handlers act in `user.tenant_id`
(`federation.rs:1458,1549,1736,1787,1847`), which is the same value unless an
organization-level principal selects another tenant by header. Keying on the
token's `(tenant, sub)` is then correct: the allowance belongs to who is
calling, not to where they act. A principal acting in several tenants has one
bucket.

### 5.3 Ordering, in the real composition and in the harnesses

**Real composition.** In `boot.rs:3062-3070`, `App::new()` wraps, from the
outside in: CORS, then `audit_middleware`, then the tracing logger, then the
security headers. The routes' own `.wrap`s are innermost. The audit middleware
computes the identity in `call` **before** calling the inner service
(`middleware.rs:521`). Only `/health` and `/ready` skip it (`SKIP_PATHS`), and
it is unconditional. So the order is right.

**Harnesses.**
* `rate_limit_principal_test.rs` builds its own app: the audit middleware
  around `register_api_v1_routes`.
* `federation_test.rs` has no audit middleware, so it exercises the address
  fallback, and its comment says so.

**What if the audit middleware is absent?** Then every request keys on its
address, the pre-#633 behaviour. That is fail-safe: no request reaches a
principal's bucket it did not verify, and every request is still limited.
Acceptable. But **nothing pins `boot.rs`'s order.** The App is built inline in
the `HttpServer::new` closure, which no test can instantiate. A refactor that
moved `.wrap(audit_middleware)` inside a scope, or made it conditional, would
silently turn the documented property off: T-474, the deployment README and
the sizing guide would all be wrong, and every test would stay green.
R110W2-06 (e) proposes a source pin of the kind `rate_limit_bucket_names_test`
already uses.

### 5.4 DPoP, `cnf`, revocation, the two counter modes, the environment

* **DPoP-scheme requests: confirmed** (executor follow-up 3), and wider than
  stated (R110W2-02).
  * The audit middleware returns `None` for any scheme but `Bearer`
    (`middleware.rs:640-646`). It does not fall back to the cookie when a
    header is present.
  * On the five routes, a DPoP-bound client is therefore keyed on its address.
  * The same early return also leaves the **request-audit row of every
    DPoP-scheme request** with `actor_id = nil`, `tenant_id = nil`,
    `actor_type = System` and `authenticated: false`, unless the handler sets an
    `AuditAttribution` (`:557-566`). Those rows never reach the tenant's audit
    log. This predates the wave: it dates from X5.1, which taught the extractor
    the `DPoP` scheme (`auth.rs:668-677`) but not the audit middleware.

  Caching under `DPoP` is safe. Every reader of the cache that admits a request
  goes through `cached_identity`, which enforces the sender constraint against
  *this* request's proof on every use (`auth.rs:950-957`). The limiter keys a
  `cnf` token on `(ip, tenant, sub)`, so a DPoP-bound caller would get the
  per-address-and-principal bucket.
* **`cnf` tokens** are keyed `{ip}:principal:{tenant}:{sub}`
  (`extractors/rate_limit.rs:301-303`). A replayed copy from another address
  never reaches the holder's bucket. Tested by
  `a_sender_constrained_token_is_keyed_on_its_address_and_principal_together`.
* **Revoked but unexpired:** see §5.1. It is the stated residual.
* **Both counter modes.** The shared middleware and `ClientAwareKeyExtractor`
  both call `bucket_key_part` (`rate_limit_shared.rs:394-406`,
  `extractors/rate_limit.rs:359-372`). With `AXIAM__RATE_LIMIT__SHARED=off` the
  counter admits everything and the governor keys identically. Tested by
  `the_in_process_governor_alone_…` and `the_shared_counter_alone_…`.
* **The environment.** `RateLimitKeyMode::Principal` carries
  `#[serde(skip_deserializing)]` (`config/rate_limit.rs:77`), so
  `AXIAM__RATE_LIMIT__KEY=principal` is an unknown variant and is refused at
  startup. The profile presets set `key` in code and never to `Principal`.
  Tested by `the_principal_key_mode_cannot_be_selected_from_the_environment`.

### 5.5 Cardinality and memory

* **Shared counter.** It prunes buckets older than two windows that have
  nothing pending (`rate_limit_counter.rs:1206`). Principal keys are therefore
  bounded by the principals seen in two minutes. They are also persisted to
  `rate_limit_bucket` keyed `{endpoint}:principal:{tenant}:{sub}`, a user id in
  a table nothing sweeps. That is no different in kind from the CIBA list's
  `ciba_approval_list:{tenant}:{user}`.
* **In-process governors.** actix-governor 0.10 never evicts. Its docs leave
  `retain_recent` to the caller, and nothing in the tree calls it except
  `ciba_list_limiter.rs:85-97`. The five new maps grow with the distinct
  principals (plus fallback addresses) seen since start. Every address-keyed
  map in the server grows with distinct addresses, which with IPv6 a single
  sender chooses. Pre-existing; R110W2-05.

### 5.6 Does the change alter the keying of any other route?

**No.**
* **The five routes.** `server.rs` changes only them.
* **Other modes, byte-identical.** `bucket_key_part` gives the same strings
  for `ip`, `client_id` and `ip_client_id` as the two `match` blocks it
  replaces. Diffed against `ff8ca52^`, and pinned by
  `the_modes_do_not_read_each_others_identity`.
* **The principal is read only in `Principal` mode.** Both layers compute it
  only then (`rate_limit_shared.rs:394-397`, `extractors/rate_limit.rs:359-362`).
* **The client-aware routes.** `new_client_identity_aware` and the three OAuth2
  routes are untouched.

## 6. W2.4 — the self-check parses (orchestrator point 4)

* **Both sites changed.** `verify_output` (`sign.rs:184-186`) and
  `verify_root_signed` (`:279-281`) now call
  `parse_string_with_options(.., receiver_parser_options())`.
  `receiver_parser_options::the_idp_self_checks_parse_with_the_receiver_options`
  pins both and forbids a bare `.parse_string(` in the file.
* **No other default-option parse is left.** Every libxml parse in
  `crates/*/src` now passes `receiver_parser_options()`:
  * `request.rs:458`, `sp_metadata.rs:240`;
  * `saml.rs:958,1253`;
  * `saml_metadata.rs:316`;
  * `sign.rs:184,279`;
  * plus a test at `saml.rs:2084`.

  `rg 'Parser::default\(\)'` shows no other caller, and no crate uses
  `quick_xml`, `roxmltree` or `xmltree` directly.
* **What remains.** samael's quick-xml deserialisation (`Response`,
  `EntityDescriptorType`), which takes no DTD, and samael's own libxml re-parse
  inside `reduce_xml_to_signed_with_allowed_algorithms`, which is T-474's
  stated residual: it is reached only by text that passed AXIAM's byte
  refusals and its strict parse.
* **No threat-model edit.** None was needed, as the commit says: no entry lists
  the self-check sites.

## 7. The §10 rules, against what the wave added (orchestrator point 5)

| Rule | Verdict |
|---|---|
| A new route carries a limiter from its first commit | No route added (the `server.rs` diff re-keys five and renames two buckets) |
| Credential-bearing outbound requests use `guarded_fetch_no_redirect` | None added |
| Every refusal of a credential check costs one verify | **Holds for its purpose.** W2.3: the limiter verifies nothing. A `429` costs the audit middleware's one verify; a refused token costs what it cost before the wave. W2.1: a busy ACS refusal costs no verify, against one for a tampered document. It differs in timing, but the permit is taken before the signature is read, so the difference carries no information about the credential (§3.2). |
| Two-writer registries written conditionally | None added |
| Schema | No migration |
| Contract / spec | `sdks/CONTRACT.md` and `sdks/openapi.json` untouched. The IdP routes are not in the spec, so their new `503` needs no spec change. |
| Threat model: edit only named entries; the test the mitigation names exists | T-102, T-474 and T-477 were edited; T-477 is not named by the plan but holds the claim being corrected ("Plan vs tree" in `cad0586`). Every test named exists and passes (§11). |
| No `[lints] workspace = true` on an undocumented crate; no new crate | Holds. `saml_gate` is a module of `axiam-federation`, documented. |
| `--no-default-features` build clean under `-Dwarnings` | Holds after `fea3b64` (§11) |

## 8. Threat-model text against the code (orchestrator point 6)

| Entry | Verdict |
|---|---|
| T-477, amended 2026-10-15 (#654) | **Mostly true.** The bound, the refusals, the `warn`, the tests: all true. Three faults: "the permit is taken before the document is evaluated" is true of the signature only (§3.3); "every refusal it has is a `400`" is loose (`413`, `500`, `403 sp_disabled`); the SLO-signing residual's "only after the SP's signature has verified" misses the unsigned `LogoutResponse` from a certificate-less SP (§3.4). |
| T-102, amended 2026-10-15 (#654) | "what remains unbounded on the semaphore is the authenticated signing of the IdP's assertion and SLO message" is **false**: eight PKI acquirers are also unbounded (§3.1). The rest is true. |
| T-474, amended (#654 metadata) | true (§3.2) |
| T-474, corrected (#632) | true. The allow-list text matches the test, and the original #614 sentence is kept with its correction appended. |
| T-474, corrected (#633) | true for `Bearer` and cookie tokens. It omits that a `DPoP`-scheme request with a valid token is keyed on its address (R110W2-02). It does not mention the dropped per-address bound (R110W2-01). |

* **Placement.** Each paragraph sits in the right threat's `mitigation` in
  `Axiam.json` (474, 477, 102).
* **Both copies agree.** All 31 sentences added to the STRIDE document are
  present verbatim in `Axiam.json`, after stripping Markdown emphasis and code
  spans.
* **Dates.** Every new paragraph is dated 2026-10-15, the commit date, and
  labelled as an amendment or correction in the entry's own text.
* **Model version.** It stays 2.41.0 with `threatTop` 477. No threat was added,
  and the bump is W8.3's.
* **The website copy.** `node website/scripts/gen-threat-model.mjs` (477
  threats: 443 / 19 / 15) leaves a 3-line diff in `website/src/threatModel.ts`.
  The wave did not regenerate it, and the plan gives that reconciliation to
  W8.3. Not a gate: no CI job checks it. The file was restored after the run.

## 9. Documentation claims

| Claim (where) | Verdict |
|---|---|
| "past it the ACS answers as for an invalid signature, the IdP receiver answers `503` with `Retry-After`" (`docs/deployment/README.md`, `HASH_ACQUIRE_TIMEOUT_SECS` row) | true |
| "The browser-endpoint preset, **per IP** …" then "keyed on the caller's verified principal" (`README.md`, `END_SESSION_PER_MIN` row) | the opening "per IP" now contradicts the end of the same row for five routes; wording (R110W2-06 (c)) |
| "The posture did not change: still strict, still per-IP" (`rate-limit-sizing.md`, after the table) | no longer true for five routes; wording |
| "a token that does not verify is keyed on its address" (both docs, T-474) | true; also true of a token that verifies but arrives under `DPoP` (R110W2-02) |
| "A backend relaying many people's federated sign-ins … does not need to [raise the knob]" | true, and after R110W2-01's fix still true up to the backstop |
| `cad0586` "the permit is taken before the document is evaluated: no oracle either way" | true for the signature; not for the IdP's SP lookup (§3.3) |
| `ff8ca52` "A composition without the audit middleware keys these routes on the address" | true, and unpinned for the real composition (§5.3) |
| `b1ddc89` "an unreadable name or unknown constructor is refused, not skipped" | true for what the anchor matches; a non-turbofish call is not matched at all (§4) |

## 10. Executors' follow-ups, confirmed or rejected

| Follow-up | Verdict |
|---|---|
| Bound the IdP's own assertion signing and SLO signing (needs a deliberate failure answer) | **Confirmed, Informational** (R110W2-03), together with the eight PKI acquirers T-102 does not name. All are authenticated and self-limiting now. The SLO case already has a failure path (partial hop); only the assertion case needs a design. |
| The Redirect-binding query signature check is still ungated | **Confirmed as a residual; decided to stay ungated.** One RSA public-key operation inline is cheaper than a wait behind Argon2id (§3.5). Recorded in R110W2-03's body, not filed. |
| DPoP-scheme requests keyed on address on these five routes | **Confirmed and widened** into R110W2-02 (Low). The same early return leaves every DPoP request's audit row unattributed. |

## 11. Checks run

Each command's own exit code was captured. Logs are in the session scratchpad.
All cargo commands ran with `RUSTFLAGS=-Dwarnings`, `CARGO_INCREMENTAL=0`,
`CARGO_PROFILE_{DEV,TEST}_DEBUG=line-tables-only` and the swagger placeholder,
as CI and the executor rules require.

| Check | Exit | Result |
|---|---|---|
| `cargo fmt -p axiam-federation -- --check` | 0 | clean |
| `cargo fmt -p axiam-api-rest -- --check` | 0 | clean |
| `cargo fmt -p axiam-server -- --check` | 0 | clean |
| `cargo check -p axiam-federation -p axiam-api-rest -p axiam-server --no-default-features` (CI "Build (SAML off)") | 0 | pass (`fea3b64` removed the one unused binding W2.1 left) |
| `cargo check -p axiam-federation -p axiam-api-rest -p axiam-server --no-default-features --tests` | 0 | pass |
| `cargo clippy -p axiam-federation --lib --tests -- -D warnings` | 0 | clean |
| `cargo clippy -p axiam-api-rest --lib --tests -- -D warnings` | 0 | clean |
| `cargo clippy -p axiam-server --lib --tests -- -D warnings` | 0 | clean (default features; `boot.rs` touched) |
| `cargo test -p axiam-federation --lib` | 0 | 347 passed (incl. `saml_gate::tests`, `saml::tests::r101_02_…`, `saml_metadata::tests::r101_02_…`) |
| `cargo test -p axiam-federation --test receiver_parser_options` | 0 | 3 passed (incl. the W2.4 source pin) |
| `cargo test -p axiam-api-rest --lib -- rate_limit` | 0 | 37 passed (the principal-mode unit tests, `keyed_on_principal_…`, the environment refusal) |
| `cargo test -p axiam-api-rest --test rate_limit_bucket_names_test` | 0 | 5 passed |
| `cargo test -p axiam-api-rest --test rate_limit_principal_test` | 0 | 8 passed |
| `cargo test -p axiam-api-rest --test federation_test -- r101_02 the_federation_flow_routes` | 0 | 2 passed (the ACS busy test; the per-route limiter test) |
| `cargo test -p axiam-api-rest --test saml_idp_sso_test -- r101_02` | 0 | 1 passed |
| `cargo test -p axiam-api-rest --test saml_idp_slo_test -- r101_02` | 0 | 1 passed |
| `python3 scripts/check-remediation-evidence.py` | 0 | 37 verified, 0 failed, 0 skipped |
| `scripts/check-doc-links.sh` | 0 | 503 links across 78 files |
| `node website/scripts/gen-threat-model.mjs` | 0 | 477 threats (443 / 19 / 15); a 3-line diff in the website copy (deferred to W8.3), restored |
| T-102 / T-474 / T-477: STRIDE additions against `Axiam.json` | — | 31 of 31 sentences present |
| Commit signatures | — | 5 of 5 carry `gpgsig` |

`cargo clean` was run at the end.

## 12. Issue bodies

### R110W2-01 (Low) — the federation flow routes lost their per-address bound for authenticated callers

**Where:** `crates/axiam-api-rest/src/server.rs:1458-1478,1898-1925` (#633,
`ff8ca52`); precedent `server.rs:22-26,854-866` (R101W3-04). Threat: T-474.

**The gap.** #633 replaced the address-keyed governor on the five
authenticated federation flow routes with a principal-keyed one, and re-keyed
their shared buckets. A caller presenting a valid token is now limited only per
`(tenant, sub)`, so one address holding *K* principals gets *K* ×
`end_session_per_min`. Such principals come from:
* self-registration;
* service-account tokens, which the audit middleware verifies and the limiter
  charges before the extractor refuses their audience.

Each request costs one of: a login-state row, an outbound token exchange to
the IdP, or a SAML verification on the semaphore Argon2id and the CRL re-sign
share. The CIBA pending list, the tree's other principal-keyed limiter, keeps an
address-keyed backstop at ten times the per-user allowance.

**Fix:** on each of the five resources, add
`.wrap(build_governor(end_session_per_min.saturating_mul(10)))` outside the
principal layers. Use a named constant, as `CIBA_LIST_BACKSTOP_FACTOR` is. If a
cross-replica backstop is wanted, add a distinctly named address-keyed
`RateLimitShared`.

**Tests:** *k* principals from one address meet `429` at the backstop; fewer
each keep their own allowance; one token from many addresses is still one
bucket.

**Threat model:** T-474's #633 correction names the backstop and the test.

### R110W2-02 (Low) — DPoP-scheme requests are not attributed by the audit middleware

**Where:** `crates/axiam-audit/src/middleware.rs:636-669`
(`extract_or_cache_user_info`). Pre-existing since X5.1 taught the extractor the
`DPoP` scheme (`crates/axiam-api-rest/src/extractors/auth.rs:668-677`).

**The gap.** The middleware returns no identity when the `Authorization`
scheme is not `Bearer`, and does not then read the cookie. A request carrying
`Authorization: DPoP <token>` therefore has two gaps:
* **The audit row.** It is written with a nil actor, a nil tenant,
  `actor_type = System` and `authenticated: false`, so it never appears in the
  tenant's audit log, although the handler authenticates the caller.
* **The limiter.** On the five principal-keyed federation routes (#633) it is
  keyed on its address.

**Fix:** accept `DPoP` (case-insensitive, as `axiam_oauth2::dpop::is_dpop_scheme`)
alongside `Bearer` when choosing the token to validate and cache. This is safe:
every admitting reader of the cache (`cached_identity`) enforces the `cnf`
sender constraint against the request's own proof on every use, and the limiter
keys a `cnf` token on `(ip, tenant, sub)`.

**Tests:**
* a DPoP-scheme request with a valid proof produces an audit row naming the
  user and tenant;
* the same request without a proof is still refused by the extractor;
* on `/federation/oidc/authorize`, a DPoP-bound token is keyed on `(ip,
  principal)`.

### R110W2-03 (Informational) — unbounded waiters left on the shared crypto semaphore

**Where:**
* `crates/axiam-api-rest/src/handlers/saml_idp.rs:1306` (assertion signing);
* `saml_idp_slo.rs:777` (SLO signing);
* `crates/axiam-pki/src/cert.rs:507,601,860`;
* `ca.rs:153,466,637`;
* `pgp.rs:54,160`.

Threats: T-102, T-477.

**The state.** #654 bounded every unauthenticated waiter. These ten
authenticated ones still `acquire().await` without a bound. Because every
waiter that can queue ahead of them now gives up within its own bound, each
waits at most about that bound plus the service time ahead of it, so none is an
unbounded queue in practice. T-102's 2026-10-15 amendment names only the two
IdP sites as "what remains unbounded".

**Suggestion:** route all ten through a bounded acquire
(`axiam_auth::crypto_gate::acquire_hash_permit` or a `CryptoGate`), with these
failure answers:
* the PKI routes: their existing `503 ServiceUnavailable`;
* SLO signing: `Err("signing")`, which `next_hop` already turns into a partial
  hop;
* assertion signing: a deliberate retry page, since a signed `Responder`
  status needs the permit it could not get.

Decided, not to do: the Redirect-binding query check
(`saml_idp/request.rs:924`) stays ungated. It is one RSA public-key operation,
cheaper than a wait behind Argon2id.

### R110W2-04 (Informational) — the bucket-name scan sees only turbofish registrations

**Where:** `crates/axiam-api-rest/tests/rate_limit_bucket_names_test.rs:105-200`.
Threat: T-474.

**The gap.** The scan anchors on `RateLimitShared::<` and skips
`middleware/rate_limit_shared.rs` entirely. It does not see four things:
* a constructor called without the turbofish (or through an alias or
  `Self::`);
* a registration in the excluded file;
* the handler-side keys spent directly on the same counter (`oauth2_par:`,
  `oauth2_uma_ticket:`, `oauth2_token_exchange:`, `oauth2_token_public:`,
  `oauth2_bc_authorize_client:`, `ciba_approval_list:`, `ciba_notify:`,
  `ciba_hint_cap:`);
* the gRPC families (`grpc_authz`, `grpc_identity`, `grpc_admin`,
  `grpc_infra`), which share the persisted `rate_limit_bucket` key space.

No name collides today.

**Fix:** widen the anchor to `RateLimitShared(::<[^>]*>)?::(\w+)\(` and refuse
`Self::`/aliases outside the defining file. Collect the literal prefixes of
`shared_rate_limit.check_at*` keys and of the gRPC `shared_endpoint` into the
same uniqueness check. Within the excluded file, skip only `#[cfg(test)]` and
doc text.

**Test:** synthetic sources for each escape are flagged.

### R110W2-05 (Informational) — in-process rate-limit governors are never swept

**Where:** `crates/axiam-api-rest/src/server.rs:41-116` (every
`build_*governor`); actix-governor 0.10 (no eviction). Precedent:
`ciba_list_limiter.rs:20-97`.

**The gap.** Every keyed governor's map keeps one cell per key seen since start:
* address keys, which an IPv6 sender rotates at will;
* since #633, the principal keys of the five federation routes.

Nothing calls `retain_recent` / `shrink_to_fit` except the CIBA list limiter.

**Fix:** keep a handle to each governor's limiter (`GovernorConfig` clones share
it), and sweep all of them on one interval task, as `CibaListLimiter` does,
since a cell replenishes within a minute.

**Test:** after a sweep past one replenish period, a map that saw *n* distinct
keys holds none.

### R110W2-06 (Informational) — text and pins behind the code after W2

* **(a) T-477's residual.** It says the SLO signing is reached only after the
  SP's signature verified. A certificate-less SP's unsigned `LogoutResponse`
  advances the chain too (`saml_idp_slo.rs:971-975`), behind the run's random
  request id.
* **(b) "The permit is taken before the document is evaluated."** T-477 and the
  `saml_idp.rs:641` comment say this. The IdP receiver parses the request and
  looks up its SP first. The statement is true of the signature only, and
  during saturation the `503` shows that the `Issuer` is an enabled registered
  SP with a certificate (public data). Also in T-477: "every refusal it has is a
  `400`" (there are `413`, `500` and SLO's `403`).
* **(c) The deployment docs.** The `END_SESSION_PER_MIN` row
  (`docs/deployment/README.md`) opens "per IP"; `rate-limit-sizing.md` says
  "still per-IP". Neither is true of the five federation routes.
* **(d) T-474's #633 correction.** It omits that a `DPoP`-scheme request is
  keyed on its address (R110W2-02).
* **(e) No pin on the composition.** Nothing pins that `boot.rs` wraps the App
  in the audit middleware outside the routes (`boot.rs:3069`). Removing it
  silently reverts the five routes to address keying while every test passes.
  A source-scan test in `axiam-server` (the closure's `.wrap(audit_middleware`
  precedes `.configure(… register_api_v1_routes_with`) would hold it.
* **(f) The ACS under load.** Nothing documents that a busy ACS consumes the
  one-time login state, so the user must start the sign-in again. The operator
  signal is the `saml_acs` `warn`. One sentence in the README's
  `HASH_ACQUIRE_TIMEOUT_SECS` row.
* **(g) T-102's amendment.** It says what remains unbounded is the IdP's
  signing. The PKI acquirers are unbounded too (R110W2-03).
* **(h) The website copy.** `website/src/threatModel.ts` is behind `Axiam.json`
  by the three amended entries; W8.3 regenerates it.

## 13. Invariants

* **I1** (nothing registered today changes behaviour unless the wave says so)
  holds. The behaviour changes the wave does announce:
  * a SAML verification gives up after `hash_acquire_timeout_secs` (ACS: `401`,
    as invalid; metadata: a metadata failure; the IdP receiver: `503` with
    `Retry-After`);
  * the authenticated SAML ACS and OIDC callback have new bucket names;
  * the five routes key on the principal;
  * the IdP's self-checks refuse output they would once have repaired.
* **Contract and schema.** No contract file and no schema migration changed.
* **This review.** It changed no file but itself. The website copy regenerated
  for §8 was restored, and no probe was written.
