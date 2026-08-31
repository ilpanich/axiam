# "Sign in with …" — federated login providers, end to end

**Status:** design, written before the implementation and updated as it landed.
**Scope:** branch `claude/axiam-sso-login-providers`.
**Baseline:** `1.0.0-beta07`, commit `e921e1f`.

This document is the reasoning behind the change that turns AXIAM's *existing*
first-time-SSO backend into something a person can actually click. Everything
normative that comes out of it lands in `sdks/CONTRACT.md` §12.1 and in
`claude_dev/threat-model-stride.md`; this file is where the choices are argued.

Its companion is
[`rpi5-prod-google-federation-guide.md`](rpi5-prod-google-federation-guide.md),
the operator runbook whose §0 named the gap: *"the backend implements first-time
SSO but the frontend has no way to use it."*

---

## 1. What was actually missing

Four separate things, only the first of which was obvious.

1. **No UI.** `frontend/src/pages/LoginPage.tsx` was password/MFA only,
   `frontend/src/router.tsx` had no SSO callback route, and
   `frontend/src/services/federation.ts` exposed only `federation-configs` and
   `federation-links` CRUD. The four public endpoints
   (`/api/v1/auth/federation/{oidc/start,oidc/callback,saml/login,saml/acs}`)
   worked and nothing called them.

2. **No way to know what to render.** There was — and could not be — a "Sign in
   with X" button, because no endpoint told an unauthenticated browser which
   providers a workspace has. Every existing federation read
   (`GET /api/v1/federation-configs`) is gated on `federation:list`, which a
   person at a login page does not hold.

3. **Two of the five requested providers do not fit the OIDC shape.**
   `FederationProtocol` was `{OidcConnect, Saml}` and the OIDC path *requires* a
   discovery document and a signed `id_token`
   (`crates/axiam-federation/src/oidc.rs`: `discover()` →
   `build_authorization_url()` → `handle_callback()` → `verify_id_token()`).
   GitHub publishes neither. Facebook's web flow publishes discovery but does not
   return an `id_token` to a confidential web client.

4. **Federation configs did not inherit.** `POST /api/v1/federation-configs`
   writes `tenant_id: user.tenant_id` — the *signed-in* user's tenant. The
   bootstrap super-admin lives in the organization-scope tenant (slug
   `organization`, `ORGANIZATION_TENANT_SLUG`), so an organization administrator
   configuring Google produced a row no ordinary tenant could see or use.

Plus two defects the prompt called "smaller", which are not small if you are the
operator they lie to:

- `attribute_map` was **collected by the UI, stored by the database, and never
  read by anything**. `provision_new_user` took username and email straight off
  the `email` claim.
- `allowed_algorithms` rendered **only for SAML** in the admin UI, while the
  repository defaults it to `["RS256"]` for OIDC configs — so the one protocol
  where the value is load-bearing (Apple signs with ES256 and would have been
  rejected) had no way to set it.

---

## 2. Protocol matrix

The single biggest design constraint: the five named providers do not share one
shape. This table is what the implementation is built against. Rows marked
**verified live** were fetched from the provider during this work; the rest come
from provider documentation cited inline.

| Provider | `provider_kind` | Protocol | Discovery | ID token | Notes |
|---|---|---|---|---|---|
| Google | `google` | `OidcConnect` | `https://accounts.google.com/.well-known/openid-configuration` | RS256 | Worked before this change; unchanged. |
| Microsoft Entra ID | `microsoft` | `OidcConnect` | tenant-specific, or `common`/`organizations` | RS256 | **Verified live:** the `common` authority publishes `issuer` = `https://login.microsoftonline.com/{tenantid}/v2.0`, literally, placeholder included. See §6. |
| Apple | `apple` | `OidcConnect` | `https://appleid.apple.com/.well-known/openid-configuration` | RS256 | Three quirks: an ES256 **client secret that expires**, scopes `name email`, and `response_mode=form_post`. See §7. |
| Facebook | `facebook` | `OAuth2` (default) | n/a on this path | none | Discovery exists, but the web `authorization_code` flow returns only an `access_token` to a confidential client; Limited Login (which does mint an `id_token`) is a mobile-SDK feature. Facebook therefore defaults to the OAuth2 variant. An operator whose app *does* return an `id_token` may configure it as `generic_oidc` instead. |
| GitHub | `github` | `OAuth2` | none — GitHub publishes no discovery document and issues no `id_token` | none | The reason the OAuth2 variant exists. Needs a second userinfo call for a verified email (§5.3). PKCE (S256) supported since 2025-07. |
| — | `generic_oidc` | `OidcConnect` | operator-supplied | per config | |
| — | `generic_oauth2` | `OAuth2` | n/a | none | Explicit endpoints required. |
| — | `generic_saml` | `Saml` | operator-supplied metadata | n/a | |

`provider_kind` is a **new enum column**, not a rename of the free-text
`provider` display name. It exists for three reasons that all needed it
independently: it selects the button's branding, it selects the per-kind
defaults, and it is the key on which tenant override is decided (§4). `provider`
stays exactly what it was — a display name an operator can type anything into,
and therefore a bad key for any of those three jobs.

### 2.1 Per-kind defaults

Canonical, in `axiam_core::models::federation::ProviderKind`. The frontend
mirrors them as *form prefills* only; every value is sent explicitly on the wire,
so the server never has to guess what an older client meant.

| kind | protocol | scopes | `allowed_algorithms` | endpoints |
|---|---|---|---|---|
| `google` | OIDC | `openid email profile` | `RS256` | discovery |
| `microsoft` | OIDC | `openid email profile` | `RS256` | discovery |
| `apple` | OIDC | `name email` | `RS256` | discovery |
| `facebook` | OAuth2 | `email public_profile` | — | `https://www.facebook.com/v21.0/dialog/oauth`, `https://graph.facebook.com/v21.0/oauth/access_token`, `https://graph.facebook.com/v21.0/me?fields=id,name,email` |
| `github` | OAuth2 | `read:user user:email` | — | `https://github.com/login/oauth/authorize`, `https://github.com/login/oauth/access_token`, `https://api.github.com/user` |
| `generic_oidc` | OIDC | `openid email profile` | `RS256` | discovery |
| `generic_oauth2` | OAuth2 | *(none — required)* | — | *(all three required)* |
| `generic_saml` | SAML | — | *(empty)* | metadata |

Two of those deserve a note. **Apple's scope default is `name email`, not
`openid email profile`** — Apple rejects `profile`, and the previously
hard-coded `openid email profile` in `build_authorization_url` is precisely why
Apple could not have worked before this change. And the Graph API version in
Facebook's endpoints is pinned in the *prefill*, not in the code path: the values
are stored per config, so an operator moves to a newer version by editing a
field, not by waiting for an AXIAM release.

---

## 3. The OAuth2 variant, and the trust it does not have

`FederationProtocol::OAuth2` is a third variant alongside `OidcConnect` and
`Saml`. It authenticates by **calling a configured userinfo endpoint with the
access token just received**, because there is no ID token to verify.

### 3.1 State this plainly: it is a downgrade

On the OIDC path, AXIAM verifies a JWS signature against the provider's JWKS by
`kid`, with `alg` checked against an allow-list, and validates `iss`, `aud`,
`exp`, `iat` and `nonce`. Every one of those is a *cryptographic* statement bound
to the specific login attempt.

On the OAuth2 path **none of them exist**. There is no signature, no `nonce`, no
`aud`. The entire trust argument is one sentence:

> The access token we just received, at a token endpoint we configured, using a
> client secret only we hold, works against a userinfo endpoint we configured.

That is a real statement — it is what the whole OAuth2-as-authentication world
runs on — but it is weaker, and it is weaker in a specific way: it is *transport
and configuration* trust rather than *cryptographic* trust. A compromised or
substituted `userinfo_endpoint` is an authentication bypass with no signature to
catch it, which is why that field is validated as absolute HTTPS on write and why
it is never derived from anything the IdP sends at runtime.

Three consequences, all enforced rather than documented:

1. **It cannot be selected by accident.** The admin UI offers the OAuth2 variant
   only for kinds whose default protocol is OAuth2 (`facebook`, `github`,
   `generic_oauth2`). Selecting it for `google`, `microsoft` or `apple` — all of
   which support OIDC properly — is refused by `validate_protocol_for_kind` at
   create and update time, not merely discouraged in a tooltip.
2. **PKCE is mandatory here**, not optional. It is the only replay protection
   left once `nonce` is gone. `code_challenge_method=S256` is always sent and the
   verifier is always stored server-side in `federation_login_state`. Honest
   caveat: a provider that *ignores* `code_challenge` gives us nothing for it —
   we cannot make a remote server do PKCE. GitHub has supported S256 since July
   2025; for a provider that does not, the residual protection is the single-use
   256-bit server-side `state` plus the confidential-client secret at the token
   endpoint, and that is what an operator is relying on.
3. **The three endpoints are explicit and HTTPS-only**, validated by the same
   `validate_metadata_url` the OIDC `metadata_url` goes through
   (`crates/axiam-federation/src/lib.rs`). There is no discovery document to
   derive them from and deriving them from anything else would be inventing one.

### 3.2 Why PKCE is *not* also mandated on the OIDC path

It is recommended and supported there, and not required, for one reason: an OIDC
config that predates this change has no stored verifier, and turning PKCE into a
hard requirement would break every existing Google login on deploy. The OIDC path
already has the protection PKCE substitutes for — a server-side `nonce` bound
into a signed ID token that the client never sees and cannot supply (`D-22`,
`T-04-31`). Operators who want PKCE on OIDC get it by opting in per config; the
default preserves behaviour.

### 3.3 Claim mapping is one mechanism, not two

The OAuth2 userinfo response is mapped onto an AXIAM user through **the same
`attribute_map` machinery** built for defect 1 (§8), not a parallel one. That is
the point: a claim-mapping bug should be fixable in one place, and an operator
should not have to learn two syntaxes because we happened to implement two
protocols in different years.

---

## 4. Inheritance: organization → tenant

### 4.1 The rule

A federation config now carries `allow_tenant_inheritance: bool` (default
**false** — an existing row keeps meaning exactly what it meant).

```
effective_providers(org, tenant):
    own       = enabled configs whose tenant_id == tenant
    if tenant is the organization tenant:  return own
    org_scope = get_organization_tenant(org)
    inherited = enabled configs whose tenant_id == org_scope
                and allow_tenant_inheritance == true
                and override_key ∉ { override_key(c) for c in own }
    return own ++ inherited
```

### 4.2 Override identity

`override_key` is:

- the `provider_kind` alone, for the branded kinds (`google`, `github`,
  `facebook`, `apple`, `microsoft`);
- `provider_kind + ":" + provider_slug` for the three `generic_*` kinds, where
  `provider_slug` is an **optional** lowercase `[a-z0-9-]` identifier. A generic
  config without one keys on `generic_oidc:` — exactly as a branded kind keys on
  its kind alone.

  The slug is optional rather than required for a compatibility reason worth
  stating: a `POST /api/v1/federation-configs` that omits `provider_kind` — which
  is every request written before this change — derives a *generic* kind, and
  demanding a slug there would turn a working call into a `400`. The admin UI
  fills one in from the display name, so configs created through it get distinct
  keys without the API having to insist.

A branded kind cannot appear twice in one tenant, which is exactly what makes
"the tenant's Google overrides the organization's Google" a well-defined
sentence. The generic kinds can, because an organization legitimately federates
to two different Okta tenants, and then the slug is what distinguishes them.

### 4.3 Precedence table

| Organization-level config | Tenant-level config with same key | Effective for the tenant |
|---|---|---|
| absent | absent | *(nothing)* |
| absent | present, enabled | tenant's |
| absent | present, disabled | *(nothing)* |
| present, `allow_tenant_inheritance = false` | absent | *(nothing)* |
| present, `allow_tenant_inheritance = false` | present, enabled | tenant's |
| present, `allow_tenant_inheritance = true`, enabled | absent | **organization's (inherited)** |
| present, `allow_tenant_inheritance = true`, enabled | present, enabled | tenant's (**overrides**) |
| present, `allow_tenant_inheritance = true`, enabled | present, **disabled** | *(nothing)* — see below |
| present, `allow_tenant_inheritance = true`, **disabled** | absent | *(nothing)* |

The row that needs defending is the disabled-tenant-override one. A tenant
administrator who creates a Google config and disables it has said something
about Google in this tenant, and the something is *no*. Falling back to the
inherited organization config there would make "disable" mean "re-enable the
other one", which is the opposite of what the switch reads as. So an override
suppresses the inherited config **whether or not the override is enabled** — the
key match is what shadows, not the enabled bit.

### 4.4 The login path has to follow it

`handle_callback` did `federation_config_repo.get_by_id(tenant_id, config_id)`,
which by construction cannot find a config that lives in the organization tenant.
Resolution now goes through one function:

```rust
resolve_effective_config(org_id, requesting_tenant_id, config_id)
    -> (FederationConfig, ResolvedFrom)   // Own | InheritedFromOrganization
```

and both the start and the callback halves of all three protocols call it. The
critical invariant, restated because it is the thing most likely to be got wrong
in a later change:

> **The config may live in the organization tenant. The user and the federation
> link are always created in the *requesting* tenant.**

`FederationLink`'s uniqueness index is
`(tenant_id, federation_config_id, external_subject) UNIQUE`
(`idx_fed_link_subject`, schema v7). With an inherited config that becomes
`(requesting tenant, org-level config id, sub)`, which is still exactly one link
per external identity per tenant — and the same Google account signing into two
tenants through one inherited config gets two AXIAM users, one per tenant. That
is correct, not a bug: tenants are data-isolation boundaries, and a single user
row spanning two of them would be the actual defect. **No index change is
required**; this was verified rather than assumed.

---

## 5. New and changed HTTP surface

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/api/v1/auth/federation/providers` | none | List the buttons to render for an org/tenant (§5.1). |
| `POST` | `/api/v1/auth/federation/oauth2/start` | none | OAuth2-variant authorize URL + PKCE. |
| `POST` | `/api/v1/auth/federation/oauth2/callback` | none | OAuth2-variant completion (SPA-driven, same-origin). |
| `POST` | `/api/v1/auth/federation/oidc/callback/form` | none | `response_mode=form_post` return (Apple). Cross-site form POST → 303 handoff (§5.2). |
| `POST` | `/api/v1/auth/federation/saml/acs/form` | none | Real SAML IdP POST, `application/x-www-form-urlencoded` (§5.4). |
| `POST` | `/api/v1/auth/federation/handoff` | none | Exchange a handoff code for session cookies (§5.2). |

Every one is registered in **both** `PUBLIC_PATHS`
(`crates/axiam-api-rest/src/permissions.rs`) and `CSRF_EXEMPT_SUFFIXES`
(`crates/axiam-api-rest/src/middleware/csrf.rs`) — both registries must cover a
route for it to work unauthenticated, which is a thing this codebase has already
been bitten by once (28-05/CQ-B40). Every one is rate-limited with the same
`login_per_min` budget the existing SSO endpoints use, through both the
per-process governor and the shared `RateLimitShared` limiter.

### 5.1 The providers endpoint

```
GET /api/v1/auth/federation/providers?org_slug=acme&tenant_slug=eu
```

returns

```json
{ "providers": [
  { "id": "…uuid…", "provider_kind": "google", "display_name": "Google",
    "protocol": "OidcConnect", "inherited": true }
] }
```

and **nothing else**. Not `client_id`, not `metadata_url`, not the OAuth2
endpoint URLs, not `attribute_map`, not any secret column — a login button needs
four fields and every additional one is reconnaissance an anonymous caller gets
for free. The response type is a dedicated struct, not a narrowed
`FederationConfigResponse`, so a field added to the admin response cannot leak
here by inheritance.

**Unknown org/tenant returns `200` with an empty list**, deliberately different
from `oidc_start_public`'s `401`. Both choices are anti-enumeration; they differ
because the endpoints differ. `oidc_start_public` has one answer shape, so 401
for a bad slug is indistinguishable from 401 for a bad config — no information.
This endpoint has a *list* answer, so `401` for an unknown org against `200 []`
for a known-but-unconfigured org would be a two-valued oracle and a perfect
organization-slug enumerator. `200 []` for both is the shape that leaks nothing,
and it is also the only shape the SPA can render without a special case. The
endpoint is rate-limited on the login budget, which is what bounds the guessing
rate.

**UX consequence.** The login page does not know the organization until the user
types it, so the provider list loads when the workspace step is submitted — not
on mount. Before that there is no provider section at all, rather than an empty
one; an empty state that says "no providers" before we have asked is a lie. While
the request is in flight the section renders a skeleton of fixed height, so the
password form does not jump when the answer arrives.

### 5.2 The handoff code, and why `SameSite=Strict` forced it

`access_cookie` / `refresh_cookie` / `csrf_cookie` are all built with
`SameSite::Strict` (`middleware/csrf.rs`). That is right, and it is not being
weakened.

- **OIDC as designed is fine.** The browser returns from the IdP by a top-level
  GET to the SPA route; the *SPA* then makes a same-origin `POST` to
  `/oidc/callback`, and the cookies are set on a same-site response. Nothing
  cross-site touches them.
- **SAML and Apple are not.** Both have the IdP perform a **cross-site form
  POST** directly to an AXIAM endpoint. Setting `Strict` cookies on that response
  is permitted, but the navigation that follows is part of a cross-site-initiated
  chain and the browser will not *send* them. The user lands back in the SPA
  logged out, with a session they cannot use.

**The mechanism.** The receiving endpoint verifies the assertion or code,
provisions/links the user, fires the `login.post_auth` reactor gate, and then —
instead of setting cookies — mints a **handoff code** and answers `303 See Other`
to `<spa_redirect_uri>?axiam_handoff=<code>`. The SPA's callback route reads the
code, `POST`s it same-origin to `/api/v1/auth/federation/handoff`, and *that*
response sets the cookies on a same-site request. It also immediately strips the
parameter from the URL with `history.replaceState`.

**Properties, all enforced in code:**

| Property | Value | Why |
|---|---|---|
| Entropy | 256 bits, `base64url` | Same generator as `state` (`random_base64url`). |
| Storage | **SHA-256 hash only** | A database read must not yield a usable credential. `state` is stored raw today; a handoff code is a session-bearer credential, so it gets the stronger treatment. |
| TTL | **60 s** | It exists to survive one redirect. |
| Uses | **exactly one**, consumed atomically | Same `DELETE … RETURN BEFORE` pattern as `consume_by_state`. |
| Binds | `user_id`, `tenant_id`, `redirect_uri` | The session is minted from the row, not from anything the redeeming request says. |
| Carries | **no token material** | The access/refresh tokens are created at redemption, not at mint. |

**The residual risk, stated rather than hidden:** the code appears in a URL, and
URLs reach browser history and `Referer`. That is why the TTL is 60 s rather than
10 minutes, why it is single-use, why the SPA strips it on arrival, and why the
redirect target is the already-validated `redirect_uri` from the login state row
(absolute HTTPS, or HTTP only for loopback) rather than anything the IdP supplies.
An attacker who reads the URL within 60 seconds and redeems it before the
legitimate SPA does gets a session — and the legitimate user gets a visible
failure, because the code is gone. This is the same trade the OAuth authorization
code itself makes, and it is bounded the same way.

**Alternatives considered and rejected.** `SameSite=Lax` on the session cookies
would fix SAML and Apple and re-open the CSRF surface `Strict` was chosen to
close, across every endpoint, permanently — a global weakening to serve two
flows. A separate `Lax` "bootstrap" cookie is the same weakening with more moving
parts. Posting the assertion into the SPA and having the SPA forward it means the
raw SAMLResponse passes through JavaScript, which is strictly worse. The handoff
code confines the compromise to a 60-second single-use token whose only power is
to create the session the user just legitimately earned.

### 5.3 GitHub's email problem

`GET https://api.github.com/user` frequently returns `email: null` (the user has
it private) or an address GitHub has not verified. So for `provider_kind =
github` the flow makes a second, mandatory call to
`GET https://api.github.com/user/emails` and takes the entry with
`primary == true && verified == true`.

**Policy: if there is no primary verified address, the login is refused** with
`FederationError::UnverifiedExternalEmail`, rather than provisioning without one.

The reasoning, because the other choice is defensible too: AXIAM keys account
recovery, email verification and administrative notification on the email
address. Provisioning a user with a synthesized `…@federated.local` address gives
them an account that cannot do any of those and an operator a user row that looks
real. Adopting the *unverified* address is worse still — it is account takeover
by whoever typed that address into GitHub first. Refusing is the only outcome
that neither lies nor lets someone in. In practice this is rarely hit: GitHub
returns the `…@users.noreply.github.com` address as primary-and-verified for
users who keep their email private.

The same rule applies to every OAuth2-variant provider, not only GitHub: an
`email` that the provider does not affirmatively mark verified is never adopted
as an AXIAM identity. Where a provider offers no verification signal at all
(`facebook` returns `email` with no flag), the config-level decision is the
operator's: the mapped `email_verified` claim is absent, and AXIAM treats absent
as unverified, so a Facebook config that maps no verification claim will refuse.
An operator who accepts Facebook's assertion maps a literal in `attribute_map`
(`"email_verified": "@true"`) and thereby writes the decision down where it can be
audited, instead of AXIAM making it silently for them.

### 5.4 The SAML ACS could not receive a real IdP POST

`saml_acs_public` takes `web::Json<SamlAcsPublicRequest>`. Real IdPs POST
`application/x-www-form-urlencoded` with `SAMLResponse` and `RelayState`. The
JSON endpoint was therefore unreachable by any actual SAML IdP.

**Both are kept.** `POST /api/v1/auth/federation/saml/acs` (JSON) stays exactly
as it is — it is published SDK surface, it is how a non-browser client drives the
flow, and deprecating it would break SDKs for no gain. The new
`POST /api/v1/auth/federation/saml/acs/form` is the one an IdP is pointed at: it
takes the form encoding the standard requires, and it answers `303` with a
handoff code (§5.2) because the request is cross-site. A deployment's SP metadata
should name the `/form` variant as its `AssertionConsumerService` Location.

---

## 6. Microsoft's templated issuer

**Verified live during this work:**
`https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration`
returns

```
issuer = https://login.microsoftonline.com/{tenantid}/v2.0
```

— the placeholder is literal. `verify_id_token` does
`validation.set_issuer(&[&discovery.issuer])`, so a token whose `iss` is
`…/9188040d-…/v2.0` fails against the string `…/{tenantid}/v2.0`. Every
multi-tenant Entra login would be rejected with a claim error.

**Decision: support templated issuers, with a mandatory allow-list.**

When the discovered issuer contains `{tenantid}`:

1. The token's `tid` claim is read from the **unverified** payload, purely to
   construct the expected issuer string. It is validated as a UUID first; a
   non-UUID `tid` is refused outright.
2. That `tid` must appear in the config's new `allowed_issuer_tenants` list.
3. `{tenantid}` is substituted and the resulting concrete issuer is what
   `set_issuer` receives. Signature verification is unchanged — the JWKS still
   comes from the discovery document's `jwks_uri`.

Reading a claim before verifying the signature is the part that deserves scrutiny.
It is safe here because the value is used **only** to select which of a
closed, operator-written set of issuer strings to require — a forged `tid` either
names a tenant the operator listed (and then the signature check still has to
pass against Microsoft's keys, and the `iss` in the verified token must equal the
constructed string) or it does not, and the login is refused. It cannot widen the
accepted set.

**The allow-list is mandatory, and a config with a templated issuer and an empty
list is refused at create/update time.** This is the important half. Microsoft
signs every tenant's tokens at `common` with the same keys, so "templated issuer,
accept anything" means *every Microsoft account on earth can sign into this
tenant* — which is occasionally what an operator wants and never what they want
by accident. The error message says so and points at the two ways out: use a
tenant-specific authority, or list the Entra tenant IDs you accept.

A tenant-specific authority
(`https://login.microsoftonline.com/<guid>/v2.0/.well-known/…`) publishes a
concrete issuer and needs none of this.

---

## 7. Apple's expiring client secret

Apple's `client_secret` is not a string an operator pastes once. It is an
ES256-signed JWT with `iss` = Team ID, `sub` = Services ID (the `client_id`),
`aud` = `https://appleid.apple.com`, and `exp` at most **15777000 seconds
(6 months)** after `iat`, signed with a `.p8` key whose 10-character Key ID goes
in the JOSE header `kid`.

**Decision: mint it server-side, per token exchange.** The `.p8` private key is
what the operator stores, in the existing `client_secret_ciphertext` /
`client_secret_nonce` / `client_secret_key_version` columns — it *is* the secret,
so it gets the AES-256-GCM-at-rest treatment SEC-045 already provides, unchanged.
Two new non-secret columns, `apple_team_id` and `apple_key_id`, carry the rest.
At exchange time AXIAM mints a fresh JWT with a **5-minute** lifetime.

The alternative — accept a pasted JWT and warn about its expiry in the UI — was
rejected as the primary mechanism for a reason worth writing down: *a secret that
silently expires in six months is an outage nobody diagnoses quickly*. It expires
on a Tuesday, "Sign in with Apple" starts returning `invalid_client`, and the
person who generated it left. Minting per request removes the failure mode
instead of scheduling a warning about it.

The admin UI still shows expiry information, because the operator needs it:
Apple's `.p8` keys do not expire but can be revoked, and the UI displays the
derived Key ID, the Team ID, and the fact that AXIAM mints 5-minute secrets — so
an operator debugging `invalid_client` can see immediately that the answer is the
key or the IDs, never a stale secret. A config that *does* carry a pasted static
JWT (an operator who prefers to manage it themselves) is accepted, and there the
UI parses `exp` and warns 30 days out.

Apple's other two quirks are handled in the same pass: the scope default is
`name email` (§2.1), requesting them forces `response_mode=form_post`, which
routes Apple through `/oidc/callback/form` and the handoff code (§5.2); and the
user's name arrives **once**, in the `user` form field of that POST rather than in
the ID token, so `/oidc/callback/form` reads it and feeds it into claim mapping
alongside the ID token claims. A second sign-in will not carry it, which is why
it is captured at provisioning time or not at all.

---

## 8. `attribute_map`, finally applied

### 8.1 Shape

A JSON object mapping **AXIAM field → external claim path**:

```json
{
  "external_subject": "sub",
  "username": "preferred_username",
  "email": "email",
  "email_verified": "email_verified",
  "display_name": "name"
}
```

- Five recognised AXIAM fields: `external_subject`, `username`, `email`,
  `email_verified`, `display_name`. An unrecognised key is a validation error at
  write time, not a silently ignored one — the whole defect being fixed here is a
  field that looked configured and did nothing.
- Values are dotted paths (`user.email`) so nested userinfo responses work.
- A value prefixed `@` is a **literal**, not a path: `"email_verified": "@true"`.
  This is how an operator states "I accept this provider's unflagged email as
  verified" in a place that shows up in an audit diff.
- An **empty map preserves today's behaviour exactly**, per kind. That is a test,
  not an intention.

### 8.2 Per-kind defaults

| kind | `external_subject` | `username` | `email` | `email_verified` | `display_name` |
|---|---|---|---|---|---|
| OIDC kinds | `sub` | `email` | `email` | `email_verified` | `name` |
| `github` | `id` | `login` | *(from `/user/emails`)* | *(from `/user/emails`)* | `name` |
| `facebook` | `id` | `email` | `email` | *(absent → unverified)* | `name` |
| `generic_oauth2` | `sub` | `email` | `email` | `email_verified` | `name` |
| SAML | NameID | email attr | `urn:oid:0.9.2342.19200300.100.1.3` / `email` | *(assertion is the assurance)* | `displayName` |

The OIDC row reproduces `provision_new_user`'s current behaviour precisely,
including its fallbacks (`federated-<config_id>-<sub>` for a missing username,
`<sub>.<config_id>@federated.local` for a missing email), so an existing Google
config behaves identically before and after this change.

`display_name` has no column on `User`; it is written into the user's `metadata`
alongside the existing `provisioned_by` / `federation_config_id` /
`external_subject` keys.

### 8.3 `allowed_algorithms` for OIDC

Rendered for OIDC as well as SAML, defaulted per kind (`RS256` everywhere except
where a kind says otherwise), and **hidden entirely for the OAuth2 variant**,
where there is no signature and the field would be an inert control implying a
check that does not happen.

---

## 9. Frontend

- **Buttons** render on the credentials step, below the password form, from the
  providers endpoint. Branding follows each provider's published sign-in-button
  rules (wording, mark, colour, minimum size). All marks are **local SVG assets**
  under `frontend/src/assets/providers/` — `docker/nginx.conf`'s CSP is
  `default-src 'self'; img-src 'self' data:`, so a remote logo URL is blocked
  silently, which is the worst possible failure mode for a brand requirement.
- **`/auth/sso/callback`** is one route handling three arrivals: OIDC/OAuth2
  (`?code=…&state=…` → POST the matching completion endpoint), handoff
  (`?axiam_handoff=…` → POST `/handoff`), and error
  (`?error=access_denied` and friends). Each failure gets a real message and a
  route back to `/login` — cancelled at the provider, expired state, provider
  error, and network failure are four different sentences, not one blank page.
- **`FederationPage`** gains `provider_kind` (which drives every default),
  `allow_tenant_inheritance`, the OAuth2 endpoints, scopes, `allowed_issuer_tenants`,
  the Apple fields, and the two defect fixes. An **inherited** config is listed
  with an "Inherited" badge, is not editable in the tenant, and offers a single
  action — "Override in this tenant", which opens the create form prefilled from
  the inherited config.

---

## 10. Data model changes

All additive, all `DEFINE FIELD IF NOT EXISTS` (schema **v52**), following the
pattern the table already uses. The one exception is the `protocol` field's
`ASSERT`, which must be replaced rather than added to — SurrealDB replaces a
field definition rather than merging it, so the new assertion restates
`'OidcConnect'` and `'Saml'` alongside `'OAuth2'`. Dropping either would strand
every row that already holds one; there is a test that says so.

`federation_config`:

| column | type | legacy row reads back as |
|---|---|---|
| `provider_kind` | `option<string>` | `NONE` → derived from `protocol` (`OidcConnect`→`generic_oidc`, `Saml`→`generic_saml`) |
| `provider_slug` | `option<string>` | `NONE` → override key is the kind alone |
| `allow_tenant_inheritance` | `bool DEFAULT false` | `false` — invisible to other tenants, exactly as today |
| `scopes` | `array<string> DEFAULT []` | `[]` → per-kind default → `openid email profile` for OIDC, i.e. today's hard-coded value |
| `authorization_endpoint` / `token_endpoint` / `userinfo_endpoint` | `option<string>` | `NONE` — unused by OIDC and SAML |
| `allowed_issuer_tenants` | `array<string> DEFAULT []` | `[]` — only consulted for a templated issuer |
| `apple_team_id` / `apple_key_id` | `option<string>` | `NONE` |
| `require_pkce` | `bool DEFAULT false` | `false` — today's OIDC behaviour; forced `true` for OAuth2 in code |

`federation_login_state`: `code_verifier` (`option<string>`) and
`idp_redirect_uri` (`option<string>`). The second is the one to read twice: for
`response_mode=form_post` providers the URI registered at the IdP is an AXIAM
*server* endpoint, not the SPA route, and the token exchange must echo **that**
value. `NONE` means "the SPA `redirect_uri` was sent", which is every row written
before this change.

`federation_handoff_code` (new): `code_hash`, `user_id`, `tenant_id`,
`redirect_uri`, `expires_at`, `created_at`, with a UNIQUE index on `code_hash`
and an index on `expires_at` for the sweeper.

**Migration note for existing deployments.** No backfill runs and no row is
rewritten. An existing Google config keeps working with no operator action: it
reads back as `generic_oidc`, `allow_tenant_inheritance = false`, empty scopes
(→ `openid email profile`) and empty attribute map (→ today's mapping). The only
thing an operator must do to *use* the new features is edit the config and say so.

---

## 11. Where the public base URL comes from

`response_mode=form_post` and the SAML ACS both need AXIAM to know its own
externally-reachable origin, to build the `redirect_uri` it registers with the
IdP. **No new configuration key was added.** It is derived from
`AuthConfig::effective_issuer()` — the value that already has to be the
deployment's public origin for OIDC discovery to be correct, and which is already
validated as a URL at startup. A deployment that has that wrong has a broken
OIDC provider already; this change does not add a way to get it wrong, it adds a
second thing that notices.

---

## 12. Testing

- **Unit** — override-key computation and the full §4.3 precedence table;
  claim-mapping including the empty-map-preserves-behaviour property, literals,
  dotted paths and unknown-key rejection; per-kind defaults; templated-issuer
  substitution and allow-list refusal; Apple client-secret JWT shape; the
  protocol/kind compatibility matrix.
- **Integration** — the providers endpoint (visibility, inheritance, override,
  disabled, unknown org, and a leak test asserting the response body contains no
  secret-bearing field name); handoff mint/redeem/expire/replay; the form-encoded
  ACS and form-post callback.
- **Frontend** — buttons shown/hidden per configuration, the three callback
  arrivals, and the inherited-config read-only affordance.
- **E2E** — one full OIDC round-trip and one OAuth2/userinfo round-trip against
  mock IdPs.

No existing test is weakened, skipped or quarantined to get any of this green.

---

## 13. Deployment problems found, for the follow-up session

Deployment topology is explicitly out of scope here. These were found while doing
this work and are written down rather than fixed:

1. **`docker/nginx.conf`'s CSP has no `form-action`.** The SAML and Apple flows
   involve a cross-site form POST *into* the origin, which `form-action`
   constrains in the other direction — but the absence means an injected form on
   the SPA can post anywhere. Worth adding `form-action 'self'` plus the IdP
   origins a deployment actually uses.
2. **No `Referrer-Policy` is set on the SPA responses.** With the handoff code
   travelling in a URL for one hop, `Referrer-Policy: strict-origin-when-cross-origin`
   (or stricter) is a cheap belt on top of the 60-second TTL. AXIAM's own
   `security_headers` middleware covers API responses; the static SPA is served
   by nginx, which does not set it.
3. **The prod compose file has no sweeper schedule for `federation_handoff_code`.**
   Rows are consumed on use and expire in 60 s, but an abandoned login leaves a
   row. The existing cleanup task in `axiam-server/src/cleanup.rs` is where it
   belongs; this change adds it there, but a deployment that disables that task
   will accumulate rows.
4. **`AXIAM__AUTH__OAUTH2_ISSUER_URL` is now load-bearing for two more flows**
   (§11) and the prod compose file leaves it to a default. The deployment guide
   should say that a deployment using Apple or SAML must set it to the public
   origin.
5. **The Pi guide's §7.3 tells the operator to register `/login` as the Google
   redirect URI.** With a real callback route it should be
   `https://<host>/auth/sso/callback`. The guide is on another branch; it needs
   the one-line change when both land.
