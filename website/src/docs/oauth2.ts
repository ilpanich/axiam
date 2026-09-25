import type { DocPage } from "./types";
import { DOCS_VERIFIED_RELEASE } from "../version";

/**
 * "OAuth2 & OIDC" — the authorization-server surface.
 *
 * The overview page is the one to keep honest about tenant selection: discovery
 * is deployment-wide (one configured issuer), and the tenant is named by the
 * `tenant_id` query parameter on the token-family endpoints or derived from
 * `client_id` on `/authorize`. An earlier revision of these docs described a per-tenant,
 * path-based discovery document; the server rejects a path-based *configured*
 * issuer, so that text described something that could not work. The opt-in
 * per-tenant path issuers of `1.0.0-beta16` are a different thing: derived from
 * the root issuer as `{root}/t/{tenant_id}`, never configured.
 */
export const OAUTH2_PAGES: DocPage[] = [
  {
    slug: "oauth2",
    section: "OAuth2 & OIDC",
    navLabel: "Authorization server",
    title: "OAuth2 & OpenID Connect",
    intro:
      "AXIAM is a complete OAuth2 authorization server and OpenID Connect provider — discovery, JWKS, five grant types, introspection, revocation and userinfo.",
    verifiedRelease: DOCS_VERIFIED_RELEASE,
    blocks: [
      { type: "h", id: "grants", text: "Supported grants" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Grant", "Use it for", "Notes"],
        rows: [
          [
            "Authorization Code + PKCE",
            "Browser and mobile applications.",
            "PKCE is required for a public client, one registered with no secret at all — see *Public clients* below. Pushed authorization requests (PAR) can be required per client.",
          ],
          [
            "Client Credentials",
            "Machine-to-machine access with a service account or confidential client.",
            "Authenticate with a secret, or with mutual TLS instead — see [FAPI 2.0 & mTLS clients](#/docs/fapi2).",
          ],
          [
            "Refresh Token",
            "Extending a session without re-authenticating.",
            "Opaque, server-stored, single-use, rotating on every refresh — the predecessor is revoked, except on a `fapi2` client. See the lifetimes table below.",
          ],
          [
            "Device Authorization",
            "Televisions, CLIs, headless commissioning — anything with no browser.",
            "See [Device authorization grant](#/docs/device-flow).",
          ],
          [
            "Token Exchange",
            "A service calling another service on a user's behalf.",
            "Narrowing only, always. See [Token exchange](#/docs/token-exchange).",
          ],
        ],
      },
      { type: "h", id: "endpoints", text: "Endpoints" },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/.well-known/openid-configuration", summary: "OIDC discovery document.", public: true },
          { method: "GET", path: "/.well-known/oauth-authorization-server", summary: "The same document at the RFC 8414 path — an alias, not a second implementation. Always on.", public: true },
          { method: "GET", path: "/oauth2/jwks", summary: "Signing keys, cached with an ETag and Cache-Control.", public: true },
          { method: "GET", path: "/oauth2/authorize", summary: "Authorization endpoint. Tenant is derived from client_id.", public: true },
          { method: "POST", path: "/oauth2/par", summary: "Pushed authorization request (RFC 9126).", public: true },
          { method: "POST", path: "/oauth2/token", summary: "Token endpoint — every grant.", public: true },
          { method: "POST", path: "/oauth2/introspect", summary: "Token introspection (RFC 7662).", public: true },
          { method: "POST", path: "/oauth2/revoke", summary: "Token revocation (RFC 7009).", public: true },
          { method: "GET", path: "/oauth2/userinfo", summary: "OIDC userinfo claims for the bearer. Also accepts POST — see below.", public: true },
          { method: "POST", path: "/oauth2/userinfo", summary: "The same claims, with the token in an Authorization header or (POST only) an access_token form field.", public: true },
          { method: "GET", path: "/oauth2/revocations", summary: "Hashed ids of recently revoked sessions. Optional, off by default.", public: true },
          { method: "POST", path: "/oauth2/device_authorization", summary: "Begin a device grant (RFC 8628).", public: true },
          { method: "POST", path: "/oauth2/register", summary: "Dynamic client registration (RFC 7591). Off by default on every tenant: `403` until enabled.", public: true },
          { method: "GET", path: "/oauth2/end_session", summary: "RP-initiated logout.", public: true },
        ],
      },
      {
        type: "note",
        text: "`/oauth2/userinfo` answers **`GET` and `POST`** since `1.0.0-beta13`. The token may ride the `Authorization` header on either, or — on `POST` only — an `access_token` field in an `application/x-www-form-urlencoded` body, which is RFC 6750 §2.2's form-encoded carrier. Presenting it **twice** is refused rather than resolved in the caller's favour, and the query-string carrier (RFC 6750 §2.3) is never read on either method.",
      },
      { type: "h", id: "revocations", text: "The session revocation feed" },
      {
        type: "p",
        text: "An access token is self-contained and lives fifteen minutes, so a logout, a role removal or an account disable does not reach one already in a caller's hands until it expires. The documented answer has been to route the decision through gRPC introspection — correct, and a network round trip per request. Since `1.0.0-beta14` a deployment can instead set `AXIAM__AUTH__REVOCATION_FEED_ENABLED=true` and publish `GET /oauth2/revocations`.",
      },
      {
        type: "code",
        caption: "GET /oauth2/revocations",
        code: "{\n  \"alg\": \"SHA-256\",\n  \"issued_at\": 1757664000,\n  \"ttl\": 900,\n  \"revoked\": [\"i9N2lYMTV4FhA0husWjGYCqJXXTb7_fMBuomhWjSsgQ\"]\n}",
      },
      {
        type: "list",
        items: [
          "**What an entry is.** The base64url-unpadded SHA-256 of a session id, in the exact string form the `sid` claim carries. Never an id, a subject, a tenant or a timestamp — so the feed says neither who was revoked nor how many people are behind the entries.",
          "**What bounds it.** An entry is published for exactly one access-token lifetime, after which every token naming that session has expired on its own `exp`. The document's size therefore tracks your revocation rate over fifteen minutes and never your history, and it is cacheable with an `ETag` like the JWKS beside it.",
          "**What it is not.** It is **not a control**. A guard that cannot fetch the feed behaves exactly as it does without it — the [SDK contract §10.4](#/docs/sdks) requires that — the feed can only ever turn an accept into a reject, and every local verification rule still runs first and still decides.",
          "**With it off** — the default — the route is not mounted, no revocation row is written, and the deployment is byte-identical to one built before the feed existed. See the [`AXIAM__AUTH__REVOCATION_FEED_ENABLED` row](#/docs/configuration) and the deployment guide.",
        ],
      },
      {
        type: "note",
        text: "Both halves are opt-in, and a feed nobody polls narrows nothing: turn it on where sign-out has to take effect faster than fifteen minutes *and* attach the SDK poller (contract §10.4, shipped by all eleven SDKs since `1.0.0-beta14`).",
      },
      { type: "h", id: "tenant", text: "Naming the tenant" },
      {
        type: "p",
        text: "AXIAM is multi-tenant and has no default tenant, so every OAuth2 request has to say which one it means. There are two mechanisms, and which applies depends on the endpoint:",
      },
      {
        type: "list",
        items: [
          "**`tenant_id` as a query parameter** — required on `/oauth2/token`, `/oauth2/par` and `/oauth2/end_session`.",
          "**Derived from `client_id`** — on `/oauth2/authorize`, because an OAuth2 client belongs to exactly one tenant.",
        ],
      },
      {
        type: "warn",
        text: "There is **one configured issuer**, served at `/.well-known/openid-configuration` — and, since `1.0.0-beta16`, at the RFC 8414 path `/.well-known/oauth-authorization-server` too — and `AXIAM__AUTH__OAUTH2_ISSUER_URL` must be an origin — a path-based issuer is rejected at startup. The opt-in per-tenant path issuers described below are derived from that origin and never configured. Since `1.0.0-beta13` the document can *describe* a tenant: `GET /.well-known/openid-configuration?tenant_id=<uuid>` returns the same document with the tenant carried in the endpoint URLs that need one. `issuer` is never aliased and never changes, so `iss` validation is unaffected. An off-the-shelf OIDC client that cannot add a `tenant_id` query parameter to the token endpoint can therefore be pointed at the tenant-scoped document instead of needing a shim.",
      },
      {
        type: "list",
        items: [
          "**An unknown tenant is answered identically to a known one**, apart from the value it echoes — the document is not an enumeration oracle.",
          "**`AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID`** names the tenant an unparameterised request describes. It states a fact in a document and is not a fallback in a handler: no endpoint's behaviour changes, and a caller that names a different tenant gets that one. A value that does not parse as a UUID is ignored and **reported once at boot**, describing the value's shape and never the value — so a deployment that set it can tell that it did not take, without the variable's contents reaching a log.",
          "**`mtls_endpoint_aliases`** (RFC 8705 §5) appears when `AXIAM__AUTH__OAUTH2_MTLS_BASE_URL` is set, naming a separate mTLS host for the six back-channel endpoints. Absent by default; the front channel is never aliased. An unusable value fails discovery with a `500` rather than being silently dropped.",
          "**`claims_parameter_supported: true`** — the OIDC Core §5.5 `claims` parameter is honoured for its `userinfo` member. On a client in the honour lane it also reads `claims.id_token.acr`.",
        ],
      },
      {
        type: "code",
        caption: "discovery",
        code: "curl -s https://iam.acme.dev/.well-known/openid-configuration | jq .\n\n# and the keys a relying party verifies tokens with\ncurl -s https://iam.acme.dev/oauth2/jwks | jq .",
      },
      { type: "h", id: "code-flow", text: "Authorization Code + PKCE, end to end" },
      {
        type: "p",
        text: "The grant to use for anything with a browser or a mobile front end. PKCE binds the eventual token request to the party that started the flow, so an authorization code intercepted on the redirect is worthless without the verifier that never left the client.",
      },
      {
        type: "steps",
        steps: [
          {
            title: "Generate a verifier and its challenge",
            body: "The verifier is a high-entropy random string the client keeps. The challenge is its SHA-256, base64url-encoded. Only `S256` is accepted — `plain` would defeat the purpose, since the value on the wire would be the secret itself.",
            code: "code_verifier  = <43-128 chars, base64url, random>\ncode_challenge = BASE64URL(SHA256(code_verifier))",
          },
          {
            title: "Send the user to the authorization endpoint",
            body: "The tenant is derived from `client_id` here — an OAuth2 client belongs to exactly one tenant — so no `tenant_id` parameter is needed on this call. `state` is yours to check on the way back.",
            code: "GET /oauth2/authorize\n  ?response_type=code\n  &client_id=<client-id>\n  &redirect_uri=https://app.acme.dev/callback\n  &scope=openid%20profile%20email\n  &state=<opaque-to-the-server>\n  &code_challenge=<challenge>\n  &code_challenge_method=S256",
          },
          {
            title: "The user authenticates and consents",
            body: "AXIAM runs whatever the tenant requires — password or OPAQUE, then MFA or a passkey. None of that is the client's concern; the client sees only the redirect that follows.",
          },
          {
            title: "Handle the redirect",
            body: "Check `state` against what you sent, and check `iss` names the server you started with. The code is single-use and short-lived — and since `1.0.0-beta13` presenting it a second time **revokes the session it minted**, as RFC 6749 §10.5 asks. The cost is worth stating: a legitimate client that retries after a lost token response is signed out exactly as an attacker would be, so retry the *authorization request*, not the redemption.",
            code: "GET https://app.acme.dev/callback\n  ?code=<authorization-code>\n  &state=<what-you-sent>\n  &iss=https://iam.acme.dev",
          },
          {
            title: "Redeem the code for tokens",
            body: "`tenant_id` **is** required here, as a query parameter, because the token endpoint does not derive it. Send the verifier, not the challenge — the server recomputes the hash and compares.",
            code: "POST /oauth2/token?tenant_id=<uuid>\nContent-Type: application/x-www-form-urlencoded\n\ngrant_type=authorization_code\n&code=<authorization-code>\n&redirect_uri=https://app.acme.dev/callback\n&client_id=<client-id>\n&code_verifier=<verifier>",
          },
        ],
      },
      {
        type: "warn",
        text: "The `tenant_id` asymmetry between the two endpoints is the single most common integration mistake here. `/oauth2/authorize` derives the tenant from `client_id`; `/oauth2/token`, `/oauth2/par` and `/oauth2/end_session` all require it as a query parameter. An off-the-shelf OIDC client that cannot add one needs a shim or a per-tenant gateway route.",
      },
      { type: "h", id: "iss", text: "Checking who answered — RFC 9207" },
      {
        type: "p",
        text: "Every authorization response carries an `iss` parameter naming the server that sent it, and AXIAM emits it for **every** client rather than only FAPI ones. It defends against the mix-up attack: a client that talks to more than one authorization server on a shared redirect URI cannot otherwise tell which one answered, so an attacker controlling one of them can have a code minted by an honest server delivered to their own token endpoint.",
      },
      {
        type: "note",
        text: "It is on the **error** redirect too, and validating it there is not a formality — one variant of the mix-up attack works by injecting an error response, so a client that checks `iss` on success and skips it on failure has left the door it just closed ajar. Making emission conditional was rejected for the matching reason: mix-up is precisely the attack a client does not know it is under, so protection that depends on somebody remembering to switch it on is not protection.",
      },
      { type: "h", id: "dpop", text: "DPoP — binding a token to a key" },
      {
        type: "p",
        text: "A bearer token is usable by whoever holds it. DPoP (RFC 9449) binds one to a key pair the client generates: the token carries a `cnf` claim naming the key's thumbprint, and each request carries a proof signed with it. A stolen token alone is then not enough.",
      },
      {
        type: "warn",
        text: "A token carrying `cnf` is **not** a bearer token, and a resource server that accepts one without verifying possession has silently converted it back into one. The SDK contract makes the check mandatory rather than optional, and phrases it as *reject when you cannot verify* rather than *verify when you can*: middleware that does not understand `cnf` must refuse the token, not ignore the claim. See [FAPI 2.0 & mTLS clients](#/docs/fapi2).",
      },
      { type: "h", id: "tokens", text: "The tokens you get back" },
      {
        type: "p",
        text: "Access tokens are EdDSA (Ed25519) JWTs, short-lived, and verifiable offline against the JWKS — which is the fast path for a resource server, and the one to prefer over introspecting on every request. ID tokens carry `sid`, the session identifier, which is stable across refresh; since `1.0.0-beta13` the access tokens the code and refresh grants issue carry the **same `sid`**, so a password or MFA reset revokes the tokens in flight rather than only the session behind them. Refresh tokens are opaque and single-use.",
      },
      {
        type: "p",
        text: "Introspection exists for the cases offline verification cannot answer: whether a token has been revoked since it was issued, and what an opaque token refers to. A resource server that introspects on every request should expect to make roughly ten to twenty introspection calls per token issued — the shipped rate limits are sized for that ratio.",
      },
      { type: "h", id: "anatomy", text: "What is inside an access token" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Claim", "Meaning", "When present"],
        rows: [
          ["`sub`", "The subject's id.", "Always."],
          ["`tenant_id`, `org_id`", "The tenant and organization the token is scoped to.", "Always — there is no default tenant."],
          ["`iss`", "The issuer: the root origin — or `{root}/t/{tenant_id}` for a token minted under a per-tenant path issuer.", "Always."],
          ["`iat`, `exp`", "Issued-at and expiry, as Unix timestamps.", "Always."],
          [
            "`jti`",
            "Token id. For a user flow this is the issuing session's id, which is what makes session revocation able to find it; for machine-to-machine it is a random UUID.",
            "Always.",
          ],
          ["`aud`", "`axiam:user` or `axiam:m2m` — or, when the grant named an RFC 8707 `resource`, that resource's URI, which AXIAM's own endpoints refuse.", "Always on a current token."],
          ["`scope`", "Space-separated OAuth2 scopes.", "When non-empty scopes were granted."],
          ["`sub_kind`", "Whether the subject is a user, a service account or an OAuth2 client. Informational — it does not affect validation or authorization.", "Always."],
          [
            "`cnf`",
            "The confirmation key this token is bound to, by certificate thumbprint or JWK thumbprint.",
            "Only on a sender-constrained token.",
          ],
          [
            "`act`",
            "RFC 8693 actor claim — who is acting for the subject. Nested for chained delegation and depth-capped.",
            "Only on a **delegation** exchange. Deliberately absent on impersonation.",
          ],
          [
            "`permissions`",
            "The UMA resource and scope pairs allowed at issue time. Its presence is what makes a token an RPT; there is no separate token type.",
            "Only on an RPT.",
          ],
        ],
      },
      {
        type: "table",
        headers: ["Token", "Lifetime", "Shape"],
        rows: [
          ["Access token", "15 minutes", "EdDSA (Ed25519) JWT, verifiable offline against the JWKS."],
          ["Authorization code", "10 minutes — 60 seconds on a `fapi2` client", "Single-use. A second presentation revokes the session the first one minted (RFC 6749 §10.5)."],
          [
            "Refresh token",
            "30 days",
            "Opaque, server-stored, single-use, rotating on every refresh — the predecessor is revoked and a second presentation refused. On a `fapi2` client it instead stays redeemable for 60 seconds after rotation (FAPI 2.0 §5.3.2.1-9), then expires. A refresh token presented after rotation is audited as `oauth2.refresh_token_replayed` either way, and counted on its session ([T-254](#/security/diagram/2/T-254), closed).",
          ],
          ["MFA challenge", "5 minutes", "Single-use."],
        ],
      },
      {
        type: "note",
        text: "Two claims are worth reading twice. `act` is absent on an impersonation exchange **by design** — impersonation's whole definition is that the result is indistinguishable from a token the subject obtained directly, which is why it is off by default, gated per client, and visible only in the audit record. And `permissions` is a record of a decision already made, never an input to a future one: nothing in the authorization path reads it to grant anything, and a live check re-evaluates against the engine.",
      },
      { type: "h", id: "claims-request", text: "The `claims` request, and what survives a refresh" },
      {
        type: "p",
        text: "A relying party can ask for individual claims with the OIDC Core §5.5 `claims` parameter; AXIAM advertises `claims_parameter_supported: true` and honours the `userinfo` member. Since `1.0.0-beta14` (schema v61) the request **rides the refresh token**, and rotation copies it, so a refreshed access token asserts the same requested claims as the code-exchanged one did — before, a long-lived session quietly lost the request at its first refresh. The release filter still runs only at the authorization endpoint, and every consent gate is re-asked at UserInfo, so carrying the request forward widens nothing: it carries the *request*, not a decision.",
      },
      { type: "h", id: "browser-sso", text: "Signing in from a relying party" },
      {
        type: "p",
        text: "A third-party relying party redirects the browser to `/oauth2/authorize` cross-site, and the `SameSite=Strict` API cookie does not travel on that navigation — so until `1.0.0-beta13` an anonymous authorization request could only be answered `401`. A per-client `browser_sso` switch, **off by default**, lets AXIAM answer it with a sign-in page instead.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["The browser", "The answer"],
        rows: [
          ["carries a valid `axiam_op_session` cookie for this tenant", "authorized as that user; the ordinary code redirect follows"],
          ["carries none", "`302` to `/login?return_to=…`, and back here afterwards"],
          ["carries one that names no live session", "`302` to `/login?return_to=…&reauth=1`; the dead cookie is cleared"],
        ],
      },
      {
        type: "list",
        items: [
          "**With the switch off — the default — nothing changes.** The answer is the same `401` object it always was, byte for byte, and the `axiam_op_session` cookie is not read at all.",
          "**The cookie is a fourth cookie**, beside the three that already exist and change in no way: `HttpOnly`, `Path=/oauth2/authorize`, `SameSite=Lax` and `Secure` **unconditionally** — it is the only `SameSite=Lax` cookie AXIAM sets, so unlike the other three it does not follow the deployment's cookie-`Secure` flag. Only its SHA-256 is stored. `Lax` is the point: it travels on a top-level navigation and not inside a frame, so cross-site hidden-iframe silent renew does not work and **fails closed** — which is the same property that defeats cross-site login-status probing. Relying parties renew with a top-level `prompt=none` navigation, or with a refresh token.",
          "**`return_to` is validated three times** — by the builder, by the deployment-origin rule, and by the SPA before it navigates. It is exactly the authorization endpoint plus a query, on the API's own origin.",
          "**A chain is bounded at two authorization requests and one sign-in page.** Every login redirect carries an `axiam_login_hop=1` marker, and a request that arrives with it is never redirected again; if it still has no principal the answer is `login_required`, naming the two candidates — a browser refusing the cookie, or a sign-in against a different tenant.",
          "**An anonymous request must name its tenant**, with the same `tenant_id` parameter `/oauth2/token` and `/oauth2/end_session` already take. It is ignored whenever a principal was resolved from an access token, and omitting it gives today's `401` — which is why adding the parameter changed nothing for any client registered today.",
        ],
      },
      {
        type: "note",
        text: "Unlike the other lane switch below, `browser_sso` **is** permitted on a `fapi2` client. Full detail: [`docs/admin/browser-login-hop.md`](https://github.com/ilpanich/axiam/blob/main/docs/admin/browser-login-hop.md).",
      },
      { type: "h", id: "authn-params", text: "Authentication-request parameters" },
      {
        type: "p",
        text: "`prompt`, `max_age`, `acr_values` and `id_token_hint` change what a token *means*. A server that accepts them and acts on none has told the relying party it got a guarantee it did not get, so AXIAM does not: a per-client `authn_request_params` field selects `ignore` (the default, and what every client registered before `1.0.0-beta13` is) or `honour`.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Parameter", "On the `honour` lane"],
        rows: [
          ["`prompt`", "`login` reauthenticates; `none` is answered without interaction and is refused outright for an anonymous browser and on a return leg; `select_account` can answer `account_selection_required`. `none` combined with another value is `invalid_request`."],
          ["`max_age`", "Compared as `elapsed >= max_age`, with **no leeway** in the relying party's disfavour — so `max_age=0` can never succeed, and a relying party meaning *authenticate them now* wants `prompt=login`."],
          ["`acr_values` / `claims.id_token.acr`", "Matched against the session's own recorded authentication evidence through a function no request parameter can reach. An **essential** `acr` the end user cannot reach is `unmet_authentication_requirements`."],
          ["`id_token_hint`", "Checked against the established session; naming somebody else is `login_required`."],
          ["`login_hint`, `display`, `ui_locales`, `claims_locales`", "Cosmetic, and honoured without becoming an oracle: `login_hint` is carried and **looked up by nothing**, `display` is allow-listed, `ui_locales` is matched server-side (RFC 4647) against the five shipped locales, `claims_locales` is ignored."],
        ],
      },
      {
        type: "list",
        items: [
          "**A FAPI 2.0 client is refused the lane outright**, on create and on update: the two settings are two answers to the same question, and a registration may hold at most one.",
          "**Request objects are rejected, not half-implemented** — `request` gives `request_not_supported` and a non-PAR `request_uri` gives `request_uri_not_supported`.",
          "**Authentication evidence is the provider's for a federated login** — `auth_time` comes from the upstream `auth_time` or `AuthnInstant`, never AXIAM's clock — and is copied, never restamped, across a refresh.",
          "**On the `ignore` lane none of the new refusals can occur**: a value AXIAM cannot parse is dropped, exactly as it always was.",
        ],
      },
      {
        type: "note",
        text: "`prompt=none` is inherently a login-status oracle for a registered relying party. It is bounded to clients registered in the tenant with exact `redirect_uri` matching, and every outcome is audited as `oauth2.prompt_none.code` or `oauth2.prompt_none.login_required` with the `client_id`, so a relying party polling it is visible. Full detail: [`docs/admin/oidc-authn-parameters.md`](https://github.com/ilpanich/axiam/blob/main/docs/admin/oidc-authn-parameters.md).",
      },
      { type: "h", id: "sensitive-scopes", text: "The `address` and `phone` scopes" },
      {
        type: "p",
        text: "These two OIDC scopes release data AXIAM holds for no purpose of its own, so they sit behind four gates — all four checked at **every** UserInfo call, not once at issuance:",
      },
      {
        type: "list",
        items: [
          "the **organization** must enable them (`sensitive_scopes_enabled`; a tenant may only *disable*, never enable — see [Settings](#/docs/settings));",
          "the **operator** must register them on the client;",
          "the **end user** must consent, per client and per exact scope set, at the consent screen served at `/consent` in the five shipped languages;",
          "the client must **not** be on the FAPI profile, which collects no consent.",
        ],
      },
      {
        type: "p",
        text: "Because the gates are re-checked per call, a withdrawal takes effect on the relying party's *next* request with the token it already holds. The claims are returned from UserInfo only and never in an ID token, the `claims` parameter cannot name them into release, and a release is audited by claim name and never by value.",
      },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/account/consents", summary: "What the signed-in subject has consented to, per client." },
          { method: "POST", path: "/api/v1/account/consents/oidc-scopes", summary: "Grant consent for a client and an exact scope set." },
          { method: "DELETE", path: "/api/v1/account/consents/oidc-scopes", summary: "Withdraw all OIDC scope consent." },
          { method: "DELETE", path: "/api/v1/account/consents/oidc-scopes/{client_id}", summary: "Withdraw it for one client." },
        ],
      },
      {
        type: "note",
        text: "Withdrawal is one call with **no confirmation step** — GDPR Art. 7(3) requires it to be as easy to withdraw as to give. These endpoints take no `user_id`: consent is the subject's own (Art. 4(11)). See [`docs/compliance/gdpr-compliance.md`](https://github.com/ilpanich/axiam/blob/main/docs/compliance/gdpr-compliance.md) §3.1.",
      },
      { type: "h", id: "authz-errors", text: "How an authorization error reaches you" },
      {
        type: "list",
        items: [
          "**By redirect, with `state` and `iss`**, whenever the client and its `redirect_uri` are registered — which is what lets a relying party handle the failure in code rather than showing the user a server page.",
          "**As a page, only on an explicit `Accept: text/html`**, and that page echoes nothing the request carried.",
          "**Before the login hop, when the request cannot succeed at all.** A `request_uri` that is unknown, expired, already spent or issued to another client, and a missing or unsupported `response_type`, are both decided before the browser is sent to sign in — nobody types a password for a request that was dead before they started. `response_type` is decided this way only when no `request_uri` is present, because with PAR the pushed value is the authoritative one (RFC 9126 §4). Both are delivered under the rule above: redirected to a `redirect_uri` the client registered, with the request's own `state` — as `invalid_request_uri` for a dead handle (RFC 6749 §4.1.2.1, OIDC Core §3.1.2.6) — or answered in place otherwise. A handle issued to a different client keeps `invalid_request`. See [Pushed authorization](#/docs/par).",
          "**`error_description` is ASCII** (RFC 6749 §5.2 `NQSCHAR`): a `§` is transliterated to the word rather than silently stripped, so a description is never truncated at the first non-ASCII byte. See [Error reference](#/docs/errors).",
        ],
      },
      { type: "h", id: "par", text: "Pushed authorization requests" },
      {
        type: "p",
        text: "With PAR (RFC 9126) the client posts the authorization parameters to AXIAM directly and receives a `request_uri` to put in the browser redirect, instead of placing every parameter in a URL the user agent can see and modify. It can be required per client, and **is** required for any client registered under the FAPI 2.0 profile. The flow, the four rules that trip implementations up and the SDK helpers are on [Pushed authorization](#/docs/par).",
      },
      { type: "h", id: "clients", text: "Registering clients" },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/oauth2-clients", summary: "List the tenant's clients." },
          { method: "POST", path: "/api/v1/oauth2-clients", summary: "Register one." },
          { method: "GET", path: "/api/v1/oauth2-clients/{id}", summary: "Read one." },
          { method: "PUT", path: "/api/v1/oauth2-clients/{id}", summary: "Update it." },
          { method: "DELETE", path: "/api/v1/oauth2-clients/{id}", summary: "Delete it." },
          { method: "POST", path: "/api/v1/oauth2-clients/registration-tokens", summary: "Mint a single-use initial access token for dynamic registration. Shown once." },
          { method: "GET", path: "/api/v1/oauth2-clients/registration-tokens", summary: "List them — metadata only; the handle is not stored." },
        ],
      },
      {
        type: "code",
        caption: "a browser application",
        code: "POST /api/v1/oauth2-clients\n{\n  \"name\": \"acme-web\",\n  \"redirect_uris\": [\"https://app.acme.dev/callback\"],\n  \"grant_types\": [\"authorization_code\", \"refresh_token\"],\n  \"scopes\": [\"openid\", \"profile\", \"email\"]\n}",
      },
      {
        type: "note",
        text: "The SDKs ship OIDC relying-party helpers — the redirect, the PKCE verifier, the callback exchange and the token store — so integrating a web application is not a matter of hand-rolling the flow. See [Client SDKs](#/docs/sdks).",
      },
      { type: "h", id: "public-clients", text: "Public clients" },
      {
        type: "p",
        text: "Since `1.0.0-beta16` a client that cannot keep a secret — a desktop or command-line tool such as Claude Code, VS Code or the MCP Inspector, a single-page application, a mobile app — can be registered with **no credential at all**: `token_endpoint_auth_method: \"none\"` (RFC 6749 §2.1). A public registration is not a way to skip secret management; it removes a credential, and PKCE is what replaces what that credential was protecting. Anything that runs on a server you control stays a confidential client.",
      },
      {
        type: "code",
        caption: "a desktop client",
        code: "POST /api/v1/oauth2-clients\n{\n  \"name\": \"claude-code\",\n  \"redirect_uris\": [\"http://localhost/callback\"],\n  \"grant_types\": [\"authorization_code\", \"refresh_token\"],\n  \"scopes\": [\"openid\", \"profile\"],\n  \"token_endpoint_auth_method\": \"none\"\n}",
      },
      {
        type: "list",
        items: [
          "**No secret is minted**, and the creation response carries **no `client_secret` member** — not an empty one, which would read as a secret that happens to be empty. The admin UI offers the method as *Public client (no secret)* and skips the one-time secret dialog.",
          "**PKCE is required at both ends** — `/oauth2/authorize` refuses a request with no `code_challenge`, and `/oauth2/token` refuses to redeem a code that carries no stored challenge.",
          "**What a public registration is refused**, with a `400` naming the contradiction: the `client_credentials` and token-exchange grants, the `fapi2` profile, and any mTLS or `private_key_jwt` credential. At request time a public client that presents a credential anyway is `invalid_client`, introspection is refused (revocation is not), and so is the UMA ticket grant.",
          "**A confidential client never becomes public by omission.** One registered for a secret that sends none is still `invalid_client`, and `token_endpoint_auth_method` cannot be moved across the public/confidential line by an update.",
          "`none` is advertised last in `token_endpoint_auth_methods_supported` — a statement about the deployment, not about any client.",
        ],
      },
      { type: "h", id: "loopback", text: "Loopback redirect URIs" },
      {
        type: "p",
        text: "A desktop client asks the operating system for a free port at launch, so the port cannot be known when the client is registered. RFC 8252 §7.3 requires the authorization server to accept any port on a loopback redirect, and AXIAM does, for a **registered** URI whose scheme is `http` and whose host is `127.0.0.1`, `[::1]` or `localhost`. The allowance widens the port and nothing else.",
      },
      {
        type: "table",
        headers: ["Registered", "Presented", "Result"],
        rows: [
          ["`http://127.0.0.1/callback`", "`http://127.0.0.1:51703/callback`", "accepted"],
          ["`http://127.0.0.1:8080/callback`", "`http://127.0.0.1:51703/callback`", "accepted"],
          ["`http://127.0.0.1/callback`", "`http://localhost:51703/callback`", "**refused** — each loopback host matches only itself"],
          ["`http://127.0.0.1/callback`", "`http://127.0.0.1:51703/callback/`", "**refused** — the path must be identical"],
          ["`https://localhost/callback`", "`https://localhost:8443/callback`", "**refused** — `https` keeps exact matching"],
        ],
      },
      {
        type: "list",
        items: [
          "**The token request is still exact.** The code stores the `redirect_uri` as presented, so the redemption must repeat it: a client that authorized on port 51703 cannot redeem on 51704.",
          "**Errors reach the ephemeral port too.** A request refused before the registration is looked up — a missing `response_type`, a dead `request_uri` — is redirected to the presented URI on exactly the terms above, so a client waiting on its port reads the error instead of watching a page it cannot see. Those six refusal paths had compared the URI exactly while the success path applied the port rule; the T21.8 security review found it, and it was fixed before `1.0.0-beta16` shipped ([T-280](#/security/diagram/2/T-280), closed).",
          "**`http://[::1]/…` can be registered.** The validator had compared the host without its brackets and so refused the IPv6 loopback it named as allowed; it is one host, reachable only from the machine the user is sitting at, and a routable IPv6 literal over `http` is still refused.",
          "`localhost` and `127.0.0.1` are **not** interchangeable, and the two clients this exists for disagree — VS Code registers `http://127.0.0.1/callback`, Claude Code `http://localhost/callback`. Register what your client actually uses.",
        ],
      },
      {
        type: "links",
        links: [
          { label: "Public clients and loopback redirects", href: "https://github.com/ilpanich/axiam/blob/main/docs/admin/public-clients.md", note: "when to register one, every refusal, a worked desktop-client example" },
        ],
      },
      { type: "h", id: "resource-indicators", text: "Resource indicators — a token for someone else" },
      {
        type: "p",
        text: "By default an AXIAM access token is addressed at AXIAM: `aud` is `axiam:user` or `axiam:m2m`. That is the wrong answer the moment the token is going to an MCP server, a partner API or one service in a mesh. Since `1.0.0-beta16` a client can send `resource=<absolute URI>` (RFC 8707) on `/oauth2/authorize`, `/oauth2/par`, `/oauth2/device_authorization` or `/oauth2/token`, and the token it receives carries that URI as its `aud` — so the resource server can check that the token in its hand was minted for **it**. A request that sends no `resource` gets exactly the token it always got.",
      },
      {
        type: "list",
        items: [
          "**A client names only what its registration lists** in `allowed_resources` — empty on every client that existed before, so such a client may name nothing. Entries are absolute URIs without a fragment, compared after RFC 3986 §6.2.2 normalisation and **never by prefix**. An unregistered or malformed value is `invalid_target`, and so is a second value: an AXIAM token carries one `aud`.",
          "**A grant's audience is decided when the grant is made.** The resource travels onto the code, the device grant and the refresh token, and each rotation copies it forward, so a refresh re-mints the same audience. Repeating it or omitting it is fine; naming a different one — or naming one at all on a grant issued without one — is `invalid_target`. A token cannot be widened by refreshing it.",
          "**A resource-bound token is not a token for AXIAM.** AXIAM's own REST endpoints answer it `401` and gRPC `UNAUTHENTICATED`. A client that needs both needs two tokens, from two authorizations.",
          "**Introspection reports `aud`** (RFC 7662 §2.2), and describes a resource-bound token rather than calling it inactive — an introspecting resource server's whole audience check is *is this token for me*.",
          "**The `axiam` scheme is reserved.** `axiam:user` and `axiam:m2m` are well-formed absolute URIs, so they could once be registered and requested as resources — letting `client_credentials` mint a token with the *user* audience. Registration and every grant now answer `invalid_target` for any `axiam:` value (MCP-02, closed in `1.0.0-beta16` before release).",
          "Sender-constraining is orthogonal: a token can carry both a `cnf` confirmation and a third-party `aud`. For a token that leaves AXIAM's estate that is the recommended posture.",
        ],
      },
      {
        type: "links",
        links: [
          { label: "Resource indicators (RFC 8707)", href: "https://github.com/ilpanich/axiam/blob/main/docs/api/resource-indicators.md", note: "the parameter on each grant, the comparison rules, the `invalid_target` table" },
        ],
      },
      { type: "h", id: "dynamic-registration", text: "Dynamic client registration" },
      {
        type: "p",
        text: "An MCP client handed a URL and nothing else creates its own `client_id` at `POST /oauth2/register?tenant_id=<uuid>` (RFC 7591, since `1.0.0-beta16`). It is the first endpoint in AXIAM that writes for a caller holding no credential, so it is **off by default on every tenant**: the endpoint answers `403` shaped like every other refusal, and the tenant's discovery document carries no `registration_endpoint`. The tenant policy `dynamic_registration` selects the mode.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Mode", "Who may register", "Use it when"],
        rows: [
          ["`disabled` (default)", "Nobody — `403` for every request.", "Always, unless you have decided otherwise."],
          ["`initial_access_token`", "A caller presenting a single-use token an administrator minted.", "You want self-registration, but not from strangers."],
          ["`anonymous`", "Anybody who can reach the endpoint.", "You front MCP servers for end users whose desktop clients register themselves."],
        ],
      },
      {
        type: "list",
        items: [
          "**Initial access tokens** are minted and listed at `/api/v1/oauth2-clients/registration-tokens` (`oauth2_clients:create` / `oauth2_clients:list`), single-use — also under concurrent redemption — TTL-bounded, shown once, and refused for a tenant not in that mode. Its quota cannot be spent by somebody with no credential, which is the reason to prefer this mode that matters most.",
          "**A self-registered client cannot choose its own audiences** (D3): it inherits the tenant's `external_client_allowed_resources` verbatim, and AXIAM refuses to store a policy that enables `anonymous` registration while that list is empty — an empty list would leave a stranger's client able to obtain the `axiam:user` tokens AXIAM's own APIs accept.",
          "**It always gets a consent screen** (D4): the first authorization per end user goes through the consent hop whatever scopes it asked for, recorded as an ordinary OIDC-scope consent the user can withdraw from the account page.",
          "**What it may say is narrowed.** Redirect URIs pass the admin API's validator and then the tenant's `dcr_allowed_redirect_hosts` globs (the loopback hosts are always allowed); grants are limited to the authorization code and refresh; scopes to `dcr_allowed_scopes`, which may not contain `address` or `phone`; the profile is forced to `standard`; a `software_statement` is refused.",
          "**Every client records its provenance** in `managed_by`: `admin` for one an administrator created, `dcr` for a self-registered one, `cimd` for one resolved from a metadata document. It is set by the creating code path and absent from the update API. A client that is not `admin` is never on the FAPI profile, is always consent-gated, and is the only kind the sweeper touches.",
          "**Abuse controls**: a per-IP limit of 5 a minute (`AXIAM__RATE_LIMIT__DCR_PER_MIN`, the smallest in AXIAM), a per-tenant ceiling (`dcr_max_clients`, default 20; the next registration is `403`), a sweep of self-registered clients unused for `dcr_unused_client_ttl_days` (default 30; `0` disables it; reported at `/health/jobs` as `dcr_unused_clients`), and an audit event for every attempt, successful or not.",
          "**A registration nobody authorized is reclaimed in an hour** in a tenant whose effective mode is `anonymous` — whatever the TTL says, and even with the TTL at `0`. In `anonymous` mode the ceiling is also an availability budget a stranger could fill in about four minutes; the T21.8 security review found it held for thirty days, and the hour closed that before release ([T-272](#/security/diagram/2/T-272)). A per-address share of the quota is not implemented — the accepted residual.",
        ],
      },
      {
        type: "links",
        links: [
          { label: "Dynamic client registration", href: "https://github.com/ilpanich/axiam/blob/main/docs/admin/dynamic-client-registration.md", note: "every policy field, the error codes, the sweeper and its second clock, MCP Inspector translated from Keycloak's guide" },
        ],
      },
      { type: "h", id: "client-id-metadata", text: "Client ID metadata documents" },
      {
        type: "p",
        text: "Since `1.0.0-beta16` a tenant can accept a `client_id` that is an `https` URL, fetch the JSON document published there, and treat it as the client's registration — which lets a desktop MCP client be the same client at every deployment it talks to, with nothing created in advance. It is **off by default** (`cimd.enabled: false`): a URL-shaped `client_id` is then an unknown client, and nothing is ever fetched. A tenant that enables it advertises `client_id_metadata_document_supported` in its discovery document.",
      },
      {
        type: "list",
        items: [
          "**You must name your audiences first.** Enabling it is refused while `external_client_allowed_resources` is empty — the same D3 interlock as anonymous registration.",
          "**You must name your publishers first.** Enabling it is refused while `cimd.trusted_client_id_domains` is empty, because the fetch is triggered by an unauthenticated request that names the URL. The list refuses `*` and a wildcard over a whole top-level domain (`*.com`), which mean the same thing as an empty one; `*.github.io` still passes, because trusting shared hosting is an operator's decision.",
          "**The fetch goes through AXIAM's shared SSRF guard** — resolve, canonicalise, validate, pin, no automatic redirects — with a streaming size cap, a content-type check and a timeout, and only to a host on the trusted list, checked before anything is fetched.",
          "**What the document may not decide**: its audiences are the tenant's, its profile is forced to `standard`, its provenance to `managed_by: cimd`, consent is forced on, and it can hold no shared secret. A document published at a `client_id` an administrator already registered is ignored entirely.",
          "**The rows it creates are bounded and swept.** They count against `dcr_max_clients` separately from self-registered clients, checked *before* the fetch so a tenant at its ceiling is not an outbound amplifier either; they are swept once nobody has presented the document for `dcr_unused_client_ttl_days` (reported as `cimd_unused_clients`), and re-materialise on the next request if the document is still published.",
        ],
      },
      {
        type: "links",
        links: [
          { label: "Client ID metadata documents", href: "https://github.com/ilpanich/axiam/blob/main/docs/admin/client-id-metadata-documents.md", note: "the URL and document rules, every policy field, the two profiles, what it costs you" },
        ],
      },
      { type: "h", id: "tenant-issuers", text: "Per-tenant issuers" },
      {
        type: "p",
        text: "An issuer may not carry a query string (RFC 8414 §2), so the `?tenant_id=` form cannot be published as one tenant's issuer — and an MCP client is handed exactly one thing, the `authorization_servers` entry of the MCP server's RFC 9728 document, which is an issuer. Since `1.0.0-beta16`, `AXIAM__AUTH__TENANT_ISSUER_PATHS=true` gives each tenant a second, query-free issuer, `{root}/t/{tenant_id}`, derived from the root and never configured. With the flag unset — the default — nothing is mounted and every existing document is byte-identical.",
      },
      {
        type: "code",
        caption: "the three discovery forms, one document",
        code: "# RFC 8414 §3.1 — insert the well-known segment after the host\ncurl -s https://iam.acme.dev/.well-known/oauth-authorization-server/t/<tenant-id>\n\n# the same insertion at the OIDC discovery path\ncurl -s https://iam.acme.dev/.well-known/openid-configuration/t/<tenant-id>\n\n# OpenID Connect Discovery 1.0 §4 — append to the issuer\ncurl -s https://iam.acme.dev/t/<tenant-id>/.well-known/openid-configuration",
      },
      {
        type: "list",
        items: [
          "**The same handlers, re-based.** Every OAuth2 endpoint is served under `/t/{tenant_id}` as well as at the root, and the `iss` of everything minted there is the tenant issuer — the access token, the ID token, the RFC 9207 authorization-response parameter and the Back-Channel Logout token.",
          "**One key set signs every tenant**, which RFC 8414 permits, so the signature does not say which tenant a token is for. Two checks do: a token whose `iss` names a different tenant from its `tenant_id` claim is refused, and a token presented under `/t/{B}` that was minted for tenant A is refused with `401` — the same answer a request with no credential gets.",
          "**A `tenant_id` query parameter on a tenant path is `invalid_request`**, agreeing or not: two tenant selectors on one request is the shape a confused-deputy bug takes.",
          "Turn it on when **one** AXIAM fronts MCP servers for **more than one** tenant. A single-tenant deployment needs none of it: `AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID` makes the bare document name its one tenant.",
        ],
      },
      {
        type: "links",
        links: [
          { label: "The issuer, and per-tenant path issuers", href: "https://github.com/ilpanich/axiam/blob/main/docs/deployment/README.md", note: "the deployment guide's issuer section — the boot checks, the discovery forms, what an MCP server puts in `authorization_servers`" },
        ],
      },
      { type: "h", id: "mcp-servers", text: "MCP servers" },
      {
        type: "p",
        text: "AXIAM can front a Model Context Protocol server as its OAuth 2.0 authorization server — public clients with PKCE for desktop MCP clients (Claude Code, VS Code, MCP Inspector), RFC 8707 resource indicators so a token is addressed at the MCP server rather than at AXIAM, RFC 7591 dynamic client registration and Client ID Metadata Documents for clients nobody registered in advance, and an opt-in per-tenant issuer for a deployment fronting more than one tenant's MCP servers — each described in its section above. Publishing the RFC 9728 protected-resource document and checking `aud` is the MCP server's own job — built with the SDK's §28 resource-server helpers — not anything AXIAM the authorization server exposes.",
      },
      {
        type: "links",
        links: [
          { label: "Fronting an MCP server with AXIAM", href: "https://github.com/ilpanich/axiam/blob/main/docs/api/mcp.md", note: "the RFC 9728 document, the WWW-Authenticate challenge, SDK middleware configuration, tenant settings translated from Keycloak's guide, one worked example per registration mode" },
          { label: "The runnable example", href: "https://github.com/ilpanich/axiam/tree/main/examples/b7-mcp-server", note: "a real MCP server, guarded, with a walkthrough script" },
        ],
      },
    ],
  },

  {
    slug: "device-flow",
    section: "OAuth2 & OIDC",
    navLabel: "Device grant",
    title: "Device authorization grant",
    intro:
      "For clients that cannot show a browser or accept typed input: a television, a set-top box, a CLI on a headless machine, an IoT sensor being commissioned.",
    blocks: [
      { type: "h", id: "flow", text: "The flow" },
      {
        type: "p",
        text: "The device shows a short code; the user types it on a phone or laptop; the device polls until they approve. AXIAM implements the non-interactive path of RFC 8628 in full.",
      },
      {
        type: "code",
        caption: "who talks to whom",
        code: "  device                        AXIAM                    user's phone\n    |                             |                            |\n    |-- POST /oauth2/device_authorization -->                  |\n    |<- device_code, user_code, verification_uri --            |\n    |                             |                            |\n  shows \"go to id.acme.dev/device and enter WXYZ-1234\"        |\n    |                             |<-- GET /api/v1/device/verify\n    |                             |--- client + scopes ------->|\n    |                             |<-- POST /api/v1/device/decide\n    |-- POST /oauth2/token (device_code) -->                   |\n    |<- authorization_pending ----|   (repeatedly, at interval)|\n    |-- POST /oauth2/token (device_code) -->                   |\n    |<- access_token + refresh_token                           |",
      },
      { type: "h", id: "start", text: "1. Start" },
      {
        type: "code",
        code: "POST /oauth2/device_authorization?tenant_id=<uuid>\nContent-Type: application/x-www-form-urlencoded\n\nclient_id=oa_...&scope=openid",
      },
      {
        type: "code",
        caption: "response",
        code: "{\n  \"device_code\": \"...\",\n  \"user_code\": \"WXYZ-1234\",\n  \"verification_uri\": \"https://id.acme.dev/device\",\n  \"verification_uri_complete\": \"https://id.acme.dev/device?user_code=WXYZ-1234\",\n  \"expires_in\": 600,\n  \"interval\": 5\n}",
      },
      {
        type: "note",
        text: "Show `verification_uri` and `user_code` separately, and use `verification_uri_complete` for a QR code. A user who scans the code should not then have to type it.",
      },
      { type: "h", id: "approve", text: "2. The user approves" },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/device/verify", summary: "What the verification page needs: the client and the scopes being requested." },
          { method: "POST", path: "/api/v1/device/decide", summary: "Approve or deny the pending request." },
        ],
      },
      {
        type: "p",
        text: "These two back the verification page. The user is authenticated at AXIAM in the ordinary way before deciding — the page shows *which application* is asking and *what for*, because a code typed from a screen carries no context on its own.",
      },
      { type: "h", id: "poll", text: "3. The device polls" },
      {
        type: "p",
        text: "The device posts the device grant to the token endpoint at `interval` seconds. Every non-success answer is one of four RFC 8628 errors, and each has exactly one correct reaction:",
      },
      {
        type: "table",
        headers: ["Answer", "Meaning", "What the device does"],
        rows: [
          ["authorization_pending", "The user has not decided yet.", "Keep polling at the same interval."],
          ["slow_down", "You are polling too fast.", "Increase the interval, then keep polling."],
          ["access_denied", "The user refused.", "Stop. Show that it was declined."],
          ["expired_token", "The device code expired.", "Stop, and start a new request with a fresh code."],
        ],
      },
      {
        type: "warn",
        text: "Polling faster than `interval` is what earns `slow_down`, and ignoring `slow_down` is what earns a rate-limit refusal. Treat the interval as a floor set by the server, not as a suggestion.",
      },
    ],
  },

  {
    slug: "token-exchange",
    section: "OAuth2 & OIDC",
    navLabel: "Token exchange",
    title: "Token exchange (RFC 8693)",
    intro:
      "A service holding a user's token needs a narrower one to call the next service — fewer scopes, a specific audience, and a record of who acted for whom.",
    blocks: [
      { type: "h", id: "why", text: "Why not just forward the token" },
      {
        type: "p",
        text: "A service in a mesh receives a request carrying a user's access token. To call a second service on that user's behalf it has two bad options and one good one. Forwarding the user's token verbatim is over-privileged, and the second service cannot tell the caller from the user. Using the service's own credentials has the right privileges and loses the user context entirely.",
      },
      {
        type: "p",
        text: "Token exchange is the third option: present the token you hold, receive one that is *narrower* and that records the delegation.",
      },
      {
        type: "note",
        text: "The rule everything below serves: **an exchange may only ever narrow.** There is no parameter, no configuration and no client grant that makes the issued token permit something the subject token did not already permit.",
      },
      { type: "h", id: "request", text: "The request" },
      {
        type: "code",
        code: "POST /oauth2/token?tenant_id=<uuid>\nContent-Type: application/x-www-form-urlencoded\n\ngrant_type=urn:ietf:params:oauth:grant-type:token-exchange\n&subject_token=<jwt>\n&subject_token_type=urn:ietf:params:oauth:token-type:access_token\n&actor_token=<jwt>                    # optional — presence selects delegation\n&actor_token_type=urn:ietf:params:oauth:token-type:access_token\n&scope=read:orders write:orders       # optional — defaults to the subject's scopes\n&audience=https://orders.internal     # optional\n&resource=https://orders.internal/v1  # optional\n&client_id=oa_...&client_secret=...",
      },
      {
        type: "table",
        headers: ["Parameter", "Required", "Notes"],
        rows: [
          ["grant_type", "yes", "`urn:ietf:params:oauth:grant-type:token-exchange`"],
          ["subject_token", "yes", "The token being exchanged. AXIAM-issued access tokens only."],
          ["subject_token_type", "yes", "`urn:ietf:params:oauth:token-type:access_token`"],
          ["actor_token", "no", "Present ⇒ **delegation**. Absent ⇒ **impersonation**."],
          ["actor_token_type", "with actor_token", "Same value as above."],
          ["scope", "no", "Must be a subset of the subject's scopes. Defaults to all of them."],
          ["audience / resource", "no", "Narrows who the issued token is for. Since `1.0.0-beta16` the target must be one of AXIAM's own audiences or appear in the client's `allowed_resources`; a target registered only as one of its `redirect_uris` is still accepted for a deprecation period, with a warning naming the client and the target — move it to `allowed_resources`."],
        ],
      },
      { type: "h", id: "modes", text: "Delegation vs impersonation" },
      {
        type: "p",
        text: "Supplying an `actor_token` selects **delegation**: the issued token says *this actor is acting for this subject*, and both are visible to whatever receives it. Omitting it selects **impersonation**: the issued token speaks as the subject alone.",
      },
      {
        type: "p",
        text: "Prefer delegation. Impersonation is occasionally the only thing a downstream service will accept, but it erases the caller from the audit trail at exactly the moment you would most want to know who it was.",
      },
      { type: "h", id: "narrowing", text: "What narrowing means, concretely" },
      {
        type: "list",
        items: [
          "**Scopes** — the requested set must be a subset of the subject token's. Asking for more is refused, not silently trimmed.",
          "**Audience** — an issued token can be bound to one downstream service, so a leak at that service does not yield a token usable everywhere. The allow-list is the same `allowed_resources` field [resource indicators](#/docs/oauth2) read — see [`docs/api/token-exchange.md`](https://github.com/ilpanich/axiam/blob/main/docs/api/token-exchange.md#audience).",
          "**Lifetime** — the issued token never outlives the subject token.",
          "**Authorization** — the subject's own grants still apply. Exchange does not confer authority; it repackages it.",
        ],
      },
      {
        type: "warn",
        text: "Because exchange only narrows, it is not a privilege-escalation mechanism — and it is also not a way to *grant* a service access to something the user cannot reach. If a downstream call needs authority the user does not have, that is a role-model problem, not an exchange problem.",
      },
      {
        type: "links",
        links: [
          {
            label: "Federated token exchange",
            href: "https://github.com/ilpanich/axiam/blob/main/docs/api/federated-token-exchange.md",
            note: "Accepting a partner IdP's token — Entra, Okta or Keycloak — and turning it into an AXIAM one.",
          },
        ],
      },
    ],
  },

  {
    slug: "logout",
    section: "OAuth2 & OIDC",
    navLabel: "Logout & sessions",
    title: "Logout — RP-initiated and back-channel",
    intro:
      "When a session ends, who else needs to know? AXIAM implements both halves of the answer.",
    blocks: [
      { type: "h", id: "why", text: "Two holes, two mechanisms" },
      {
        type: "p",
        text: "A federation deployment is AXIAM plus N relying parties, and each logout mechanism closes a hole the other leaves open:",
      },
      {
        type: "list",
        items: [
          "**Without RP-initiated logout**, a user who logs out of a relying party stays logged in at AXIAM — so the next \"sign in with AXIAM\" silently signs them straight back in. From the user's point of view, they did not log out.",
          "**Without back-channel logout**, a user who logs out *of AXIAM* stays logged in at every relying party indefinitely, because nothing tells them. This is the one that matters in an incident: revoking a compromised account otherwise leaves N live sessions behind.",
        ],
      },
      { type: "h", id: "sessions", text: "Sessions, not users" },
      {
        type: "p",
        text: "Both operate on a **session**. A user with a phone and a laptop who logs out on the laptop expects the phone to stay signed in, and the specification agrees. That is why AXIAM's ID tokens carry `sid`, and why every logout token names it — an ID token identifying only the user would force both halves to be all-or-nothing.",
      },
      {
        type: "note",
        text: "`sid` is stable across refresh: a token minted by the refresh grant carries the same `sid` as the one issued at login, so a relying party that stored it can still match a logout token to its own session — and since `1.0.0-beta13` the access tokens the code and refresh grants issue carry the same `sid` too, so a session ending reaches the tokens in flight and not only the session row.",
      },
      { type: "h", id: "rp", text: "RP-initiated logout" },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/oauth2/end_session", summary: "End the session and redirect the browser back.", public: true },
        ],
      },
      {
        type: "note",
        text: "`end_session` also clears the `axiam_op_session` cookie the [browser login hop](#/docs/oauth2) sets, so a relying party that signed the user in through AXIAM's own sign-in page does not leave a cookie behind that would silently re-authorize the next authorization request.",
      },
      {
        type: "table",
        headers: ["Parameter", "Required", "Meaning"],
        rows: [
          [
            "tenant_id",
            "yes",
            "Which tenant's session is ending.",
          ],
          [
            "id_token_hint",
            "SHOULD",
            "A previously-issued ID token — the only *authenticated* statement of which session and which client this is about.",
          ],
          [
            "post_logout_redirect_uri",
            "no",
            "Where to send the browser afterwards. Honoured only when it is on the client's allow-list.",
          ],
          ["state", "no", "Round-tripped back to the redirect URI."],
          ["client_id", "no", "Identifies the requesting client."],
        ],
      },
      {
        type: "warn",
        text: "Send `id_token_hint`. Without it AXIAM cannot tell *which* session the browser means, and a `post_logout_redirect_uri` cannot be validated against a specific client's allow-list — so an unhinted logout is both less precise and less able to redirect you anywhere useful.",
      },
      { type: "h", id: "backchannel", text: "Back-channel logout" },
      {
        type: "p",
        text: "When a session ends at AXIAM — through logout, administrative revocation, or an incident response — every relying party registered for back-channel logout receives a signed **logout token** naming the `sid`. The notification is server-to-server, so it works even when the user's browser is closed.",
      },
      {
        type: "p",
        text: "On the relying-party side, the handler's job is: verify the token's signature against the tenant JWKS, confirm it is a logout token, read the `sid`, and destroy the local session that matches it. Do not destroy every session for that user unless you have specifically decided that is what you want.",
      },
      {
        type: "note",
        text: "This is the mechanism that makes \"revoke this account now\" mean something across a federation. Register your relying parties for it before you need it — an incident is a bad time to discover that logging out of AXIAM does nothing anywhere else.",
      },
    ],
  },

  {
    slug: "fapi2",
    section: "OAuth2 & OIDC",
    navLabel: "FAPI 2.0 & mTLS",
    title: "FAPI 2.0 profile & mTLS clients",
    intro:
      "Register a client under the FAPI 2.0 Security Profile, authenticate it with mutual TLS instead of a shared secret, and issue certificate-bound tokens that a stolen copy cannot use.",
    blocks: [
      { type: "h", id: "optin", text: "All of it is opt-in" },
      {
        type: "p",
        text: "Every field on this page defaults to what an AXIAM client already was. **A deployment that changes nothing behaves exactly as it did before** — that is the design's load-bearing property, and it is asserted by tests rather than assumed.",
      },
      { type: "h", id: "switch", text: "The one switch" },
      {
        type: "code",
        caption: "registering a FAPI 2.0 client",
        code: "POST /api/v1/oauth2-clients\n{\n  \"name\": \"payments-rp\",\n  \"redirect_uris\": [\"https://rp.example/callback\"],\n  \"grant_types\": [\"authorization_code\", \"refresh_token\"],\n  \"scopes\": [\"openid\"],\n\n  \"profile\": \"fapi2\",\n  \"require_par\": true,\n  \"token_endpoint_auth_method\": \"tls_client_auth\",\n  \"tls_client_auth_san_dns\": \"payments-rp.example\",\n  \"tls_client_certificate_bound_access_tokens\": true\n}",
      },
      {
        type: "p",
        text: "`profile: \"fapi2\"` is not a label. The server **refuses the registration** unless it also carries `require_par`, a strong `token_endpoint_auth_method`, and some form of sender-constraining — and the refusal names which one is missing:",
      },
      {
        type: "code",
        code: "400 a fapi2 client must set require_par: FAPI 2.0 §5.3.1.2 requires pushed\n    authorization requests",
      },
      {
        type: "p",
        text: "A client carrying `require_par` is then refused at `/oauth2/authorize` if it arrives with **no** `request_uri`, so the constraint holds at use as well as at registration. Parameters sent *beside* a `request_uri` are ignored rather than refused — see [Pushed authorization](#/docs/par).",
      },
      {
        type: "note",
        text: "That refusal is the point. A client satisfying eleven of twelve FAPI constraints is not \"mostly FAPI\" — it is a client with a hole. The bundle cannot be half-applied, so a reviewer can answer *is this client conformant?* by reading one field.",
      },
      { type: "h", id: "client-auth", text: "The client-authentication methods" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Method", "On a `fapi2` client", "Notes"],
        rows: [
          ["`tls_client_auth`", "yes", "A CA-chained client certificate. Requires a chain — a self-asserted certificate is not this method."],
          ["`self_signed_tls_client_auth`", "yes", "RFC 8705 §2.2. Needs `AXIAM__SERVER__TLS__CLIENT_AUTH=optional_self_signed` on the listener."],
          ["`private_key_jwt`", "yes", "A signed assertion with a single-use `jti` and a hard lifetime cap."],
          ["`client_secret_post`", "**refused**", "A copyable shared secret in the body."],
          ["`client_secret_basic`", "**refused**", "Accepted on an ordinary client since `1.0.0-beta13`, and **not recommended** — see below."],
        ],
      },
      {
        type: "p",
        text: "**`client_secret_basic` is accepted, and not recommended.** The OpenID Foundation's Basic OP plan runs 37 of its 38 modules with it, so AXIAM accepts it — decoded as RFC 6749 §2.3.1 actually specifies, and kept out of every log AXIAM writes. It is refused on a `fapi2` client exactly as `client_secret_post` is. The **registration decides the channel**, so it is never a second way in: a body secret sent by a client registered for Basic is `invalid_request`, and a Basic header presented by a client registered for the body channel is ignored with a `warn`. AXIAM's own SDKs never send it.",
      },
      {
        type: "warn",
        text: "Audit what your ingress logs before you register a client for `client_secret_basic`. AXIAM keeps the `Authorization` header out of its own logs, but a proxy in front of it may log headers by default, and a client secret in an access log is the same exposure as one in a repository. Prefer `client_secret_post` for a shared secret, and a strong method for anything that matters.",
      },
      {
        type: "list",
        items: [
          "**`private_key_jwt` now works** — it was defined but never wired until `1.0.0-beta13`. On a `fapi2` client the assertion's `aud` **must be the issuer identifier as a string**; an array is refused even when it contains the issuer. `client_id` may be omitted beside the assertion, which the conformance suite sends that way.",
          "**`tls_client_auth` compares the registered DN against both correct renderings** — the `openssl -nameopt rfc2253` order and the encoded order — by exact match, because the two are both legitimate spellings of the same name and picking one silently refuses half of real certificates.",
          "**`self_signed_tls_client_auth` needs the listener to admit a chainless certificate.** `AXIAM__SERVER__TLS__CLIENT_AUTH=optional_self_signed` does that, and nothing else changes: the trust level a certificate earned travels with it to every consumer, so a self-asserted certificate authenticates exactly the client whose thumbprint an administrator registered — and is **refused outright** as a device identity (see [PKI & mTLS](#/docs/pki)) and for `tls_client_auth`, which requires a chain.",
        ],
      },
      { type: "h", id: "mtls", text: "mTLS client authentication" },
      {
        type: "p",
        text: "`tls_client_auth` replaces the shared secret with a client certificate, matched against a configured identifier — `tls_client_auth_san_dns` and its siblings. The certificate is verified by AXIAM's own TLS listener; **no proxy-asserted identity header is in the trusted path**, so there is no `X-Client-Certificate` to forge.",
      },
      {
        type: "p",
        text: "The listener settings that make this work — `AXIAM__SERVER__TLS__CLIENT_AUTH`, `CLIENT_CA_PATH` and `CLIENT_CA_BUNDLE_PATH` — are documented once, under [mTLS for devices and services](#/docs/pki). This page used to restate them, and the copy fell behind: it never gained `CLIENT_CA_BUNDLE_PATH`, so a reader configuring FAPI 2.0 from here would not learn that flagging an organization CA as an mTLS trust anchor fills the first two in for them, and hot-reloads the anchor set without a restart.",
      },
      {
        type: "warn",
        text: "Startup **fails fast** when client authentication is enabled but the CA path is unset, unreadable, empty or malformed. A misconfigured mTLS server never starts serving — it does not fall back to accepting anonymous clients.",
      },
      { type: "h", id: "bound", text: "Certificate-bound access tokens" },
      {
        type: "p",
        text: "With `tls_client_certificate_bound_access_tokens`, an issued token carries a confirmation claim tying it to the thumbprint of the certificate that requested it. A resource server checks that the presenting client's certificate matches, which makes the token **sender-constrained**: copying it out of a log, a proxy or a memory dump gains an attacker nothing without the corresponding private key.",
      },
      {
        type: "p",
        text: "This is the single highest-value item on this page for an ordinary deployment, FAPI or not. Bearer tokens are bearer material; sender-constrained tokens are not.",
      },
      { type: "h", id: "dpop", text: "DPoP on the FAPI lane" },
      {
        type: "list",
        items: [
          "**The authorization code can be bound to a DPoP key.** Send `dpop_jkt` on the PAR request or on the plain authorization request, or a `DPoP` header on the PAR request — RFC 9449 §10.1 names both carriers. A mismatch between the two is `invalid_dpop_proof`; a code bound to a key the caller cannot demonstrate is `invalid_grant`, refused **before** the code is consumed, so a wrong caller cannot burn it.",
          "**Proofs are single-use at the resource endpoints too**, not only at the token endpoint. The `jti` is recorded through the same store *after* the proof verifies, so a forged proof cannot burn a victim's key, and a proof that cannot be recorded is refused rather than admitted.",
          "**`htu` is compared in canonical form** — scheme and host lowercased, the default port and any query or fragment removed — so a proof is not refused for a spelling of the URL the caller had no way to predict.",
        ],
      },
      { type: "h", id: "lifetimes", text: "What the profile changes about lifetimes" },
      {
        type: "list",
        items: [
          "**The authorization code is capped at 60 seconds** on a `fapi2` client, rather than the ordinary 10 minutes.",
          "**A rotated refresh token stays redeemable for 60 seconds**, then expires — FAPI 2.0 §5.3.2.1-9's recovery for a client whose rotation response was lost in transit. The profile can afford it because every token on it is sender-constrained, so a replay inside the window needs the client's private key as well. **This is a `fapi2` behaviour only**: every other client has its predecessor revoked at rotation and a second presentation refused ([T-254](#/security/diagram/2/T-254)).",
          "**`state` and `nonce` are bounded at 256 characters at the push.** `POST /oauth2/par` refuses either beyond that with `invalid_request` when the client's profile is `fapi2` — six times what a 32-byte value needs once base64url-encoded, and below the 384- and 1000-character probes the OpenID Foundation suite requires to be refused, with the cap pinned by a `const` block so a future edit cannot silently drop under them. It counts characters rather than bytes, because the value is opaque and the count the client can reason about is the one to bound. A `standard` client is **deliberately not bounded**: an opaque value carries no meaning past its entropy, but a cap is a breaking change for a client that packs data into `state`, and there the exposure is an authenticated client reflecting text into its own registered `redirect_uri` under the 16 KiB form-body cap and a 60-second handle ([T-271](#/security/diagram/2/T-271)).",
        ],
      },
      {
        type: "note",
        text: "Either way, a refresh token presented **after** it was rotated is marked on its session and written to the audit log as `oauth2.refresh_token_replayed`, naming the client, its profile and a disposition of `accepted_under_fapi_grace` or `refused` — and never the token or its digest. `GET /api/v1/users/{user_id}/sessions` reads the counters; the admin UI shows them as badges on the **Sessions** action of any row in *Users*. Alert on `refused`: nothing a conformant client does produces one.",
      },
      { type: "h", id: "conformance", text: "Conformance" },
      {
        type: "p",
        text: "AXIAM is run against the OpenID Foundation's conformance suite — the OIDC Core Basic OP plan and the three FAPI 2.0 Security Profile (Final) variants (mTLS, self-signed, `private_key_jwt`). The latest full sweep, all four plans on 2026-09-18, was **165 modules with zero `FAILED`**: 150 `PASSED`, 10 `REVIEW`, 3 `WARNING`, 2 `SKIPPED`. That is a self-run against a working-tree build, **not a certification**, and the `REVIEW` and `WARNING` verdicts are published rather than counted as passes: the ten `REVIEW`s — four on the Basic plan, two on each FAPI plan — are screenshot-evidence modules a human must judge, and the screenshot each one uploaded is published beside the receipts and matched to its condition; there is one `WARNING` per FAPI plan; and `conformance-run` itself exits non-zero on them. The eight modules that passed only when run individually after 2026-09-14 — the three FAPI PAR `request_uri` refusals, `oidcc-response-type-missing`, and the four long or mismatched `state` / `nonce` probes — are passes in that sweep. The 2026-09-11 run, the first full one, stays in the archive.",
      },
      {
        type: "links",
        links: [
          { label: "Conformance receipts", href: "https://github.com/ilpanich/axiam/blob/main/docs/conformance/README.md", note: "how the runs are made, and the hedges that go with them" },
          { label: "The latest run", href: "https://github.com/ilpanich/axiam/blob/main/docs/conformance/index.md", note: "every report committed in full, green and red alike" },
        ],
      },
      { type: "h", id: "who", text: "Who needs this" },
      {
        type: "list",
        items: [
          "**Open banking and regulated financial APIs** — where FAPI 2.0 conformance is a requirement rather than a preference.",
          "**Any high-value machine-to-machine path** — the mTLS and token-binding halves are worth having on their own, without the full profile.",
          "**Nobody else, yet.** If you are starting out, register ordinary clients. The profile is here for when a compliance obligation or a threat model asks for it.",
        ],
      },
    ],
  },

  {
    slug: "par",
    section: "OAuth2 & OIDC",
    navLabel: "Pushed authorization (PAR)",
    title: "Pushed authorization requests",
    intro:
      "RFC 9126 — send the authorization request over an authenticated back channel and put an opaque handle in the browser, so what travels through the user agent is a random string that cannot be edited into meaning something else.",
    blocks: [
      { type: "h", id: "what", text: "What PAR changes" },
      {
        type: "p",
        text: "In a plain authorization code flow, `scope`, `redirect_uri`, `state` and the PKCE challenge all ride through the user agent in a URL. Anything that can see or rewrite that URL — a malicious extension, a referrer leak, a tampered deep link — is party to the request. PAR moves the whole thing: the client `POST`s the parameters straight to AXIAM over an authenticated connection, gets back an opaque `request_uri`, and redirects with that instead.",
      },
      {
        type: "p",
        text: "This is an **extension of the normal flow, not a replacement**. Discovery, the token exchange, refresh and the whole ID-token validation checklist are unchanged, and a client that never pushes behaves exactly as it did.",
      },
      {
        type: "api",
        endpoints: [
          {
            method: "POST",
            path: "/oauth2/par?tenant_id={uuid}",
            summary: "Push an authorization request. Form-encoded, client-authenticated, answers **`201`**.",
          },
          {
            method: "GET",
            path: "/oauth2/authorize?client_id={id}&request_uri={uri}",
            summary: "Redeem it — exactly those two parameters and no others. Needs the user's session, as it always did.",
          },
        ],
      },
      { type: "h", id: "flow", text: "The flow, end to end" },
      {
        type: "steps",
        steps: [
          {
            title: "Build the request as you always did",
            body: "Your SDK's `oidc_begin` produces `state`, `nonce`, the PKCE verifier and its `S256` challenge. PAR does not compute anything of its own — there is no second generator, and the `code_verifier` you keep for the exchange is the one this step already gave you.",
          },
          {
            title: "Push it",
            body: "`POST /oauth2/par` with the parameters form-encoded, `tenant_id` as a **query** parameter, and client authentication. A `201` returns `request_uri` and `expires_in`.",
            code: `HTTP/1.1 201 Created
Content-Type: application/json

{
  "request_uri": "urn:ietf:params:oauth:request_uri:…",
  "expires_in": 60
}`,
          },
          {
            title: "Redirect with the handle",
            body: "Send the user to `/oauth2/authorize` with **only** `client_id` and `request_uri`. Everything else was pushed, and the server reads it from there.",
          },
          {
            title: "Exchange the code unchanged",
            body: "The callback and the token exchange are exactly what they were: the same `authorization_code` grant, the same `code_verifier`, and the `redirect_uri` that was pushed. Storing the pushed parameters and the exchange parameters separately just creates two places for them to disagree.",
          },
        ],
      },
      { type: "h", id: "rules", text: "Four rules worth reading before you implement it" },
      {
        type: "warn",
        text: "**It answers `201`, not `200`.** RFC 9126 §2.2 specifies Created, and the response names a resource that did not exist before the call. A success predicate written as `status == 200` treats every successful push as a failure — this is the single most likely defect in a PAR implementation, which is why it leads the list.",
      },
      {
        type: "list",
        items: [
          "**The authorization URL carries exactly two parameters.** Not `response_type`, not `redirect_uri`, not `scope`, not `state`, not the PKCE pair. The server **reads only the pushed copy**; anything sent inline beside a `request_uri` is ignored, so it cannot be confused with the pushed value. RFC 9101 §6.3 says the server MUST use only the request object's parameters, and RFC 9126 §4 never asked for a refusal. The security argument is unchanged: re-adding them “for compatibility” would restore the parameter-confusion attack, where an attacker supplies the inline value they want and lets the pushed copy satisfy whichever check reads the other one.",
          "**The `request_uri` is single-use and short-lived** — 60 seconds, consumed when `/oauth2/authorize` reads it. There is deliberately no configuration knob: the window only has to cover one browser redirect, and a tunable that only trends longer is a tunable that only widens a replay window. A second use is **refused**, never a duplicate-suppressed success — and contract 1.46 §26.2 rule 3 writes down both forms that refusal takes. A handle that is unknown, expired, already spent, or issued to a different client is answered **directly** — `invalid_request` as a JSON error body, or the same code as an HTML error page for a browser — when the request named no `redirect_uri`, or named one this client did not register; **this is the only form a conformant SDK can reach**, because the authorization URL above carries no `redirect_uri` at all. When the request *did* name a `redirect_uri` the client registered, the refusal is **redirected to the relying party** as `error=invalid_request_uri` carrying the request's own `state` (RFC 6749 §4.1.2.1, OIDC Core §3.1.2.6) — the code a relying party can act on by pushing again and restarting. A handle issued to a **different** client keeps `invalid_request`: that is a different failure, and it stays distinguishable from a handle that is simply gone.",
          "**A push is never retried.** It is a `POST` that creates server state, so it sits outside the SDKs' read-only retry eligibility. A transport failure after the request left the client is surfaced rather than retried — the safe recovery is a fresh push, which costs one round trip and cannot double-consume anything.",
          "**Treat the `request_uri` as opaque.** Do not parse it, do not validate its `urn:` prefix as a precondition, do not reconstruct one. Checking the prefix buys nothing and breaks the moment the format is versioned.",
          "**A pushed `request_uri` is refused.** RFC 9126 §2.1 forbids it: pushing a handle to a request object at the endpoint that mints handles is a fetch AXIAM would have to perform, and an SSRF surface it declines to open.",
          "**PAR errors are JSON**, not a redirect and not an HTML page — there is no user agent on this call to send anywhere.",
          "**`dpop_jkt` rides the pushed copy** (or a `DPoP` header on the push itself), which is where a FAPI 2.0 client binds its code to a key — see [FAPI 2.0 & mTLS](#/docs/fapi2).",
          "**A handle that is already dead is refused before the sign-in page.** `/oauth2/authorize` reads the `request_uri` first, by a read that spends nothing, so a handle that was already used, has expired, or was issued to another client is refused without sending anyone to type a password for a request that cannot succeed. A handle that is merely *unfinished* still reaches the sign-in page — the same `request_uri` may still be presented twice before the first authorization completes, and the single-use decision stays exactly where it was, in the handler. A handle lives 60 seconds and a person typing a password can take longer, so a relying party that uses PAR *and* sends its end users to sign in at AXIAM should still expect `invalid_request_uri` on a return leg, and recover by pushing again.",
        ],
      },
      { type: "h", id: "auth", text: "It is authenticated, and that is the point" },
      {
        type: "p",
        text: "Unlike the device authorization endpoint, `/oauth2/par` requires client authentication — the parameters stop travelling through the browser, and the ones that arrive are attributable to a client that proved it holds a credential. Which credential follows the client's registered method: `client_secret` for `client_secret_post`, a `client_assertion` for `private_key_jwt`, and **nothing at all** for the two mTLS methods, whose credential is the TLS connection itself.",
      },
      {
        type: "note",
        text: "`invalid_client` on a push has three usual causes, and the second is the one that wastes an afternoon: a wrong secret; a secret sent by a client registered for `tls_client_auth`, `private_key_jwt` or `self_signed_tls_client_auth`, which is **refused rather than ignored**; or a client certificate the transport never presented. See [FAPI 2.0 & mTLS](#/docs/fapi2).",
      },
      { type: "h", id: "fapi", text: "Required for FAPI 2.0" },
      {
        type: "p",
        text: "Registering a client with `profile: \"fapi2\"` forces `require_par`, and a client with `require_par` set is **refused** at `/oauth2/authorize` when it sends **no** `request_uri` at all. A FAPI 2.0 client therefore cannot authorize any other way — which is the intent: the profile is a constraint bundle a client cannot half-apply. Inline parameters sent *beside* a `request_uri` are ignored rather than refused, as above.",
      },
      { type: "h", id: "sdks", text: "From an SDK" },
      {
        type: "p",
        text: "All eleven SDKs ship the push as a single operation that extends the existing OIDC helpers rather than introducing a parallel vocabulary. It returns the authorization URL already built, plus the `nonce` and `code_verifier` the begin step produced.",
      },
      {
        type: "codegroup",
        caption: "push, redirect, exchange",
        tabs: [
          {
            label: "Rust",
            code: `let configuration = client.oidc_discover().await?;
let request = client.oidc_begin(&configuration, OidcBeginParams {
    redirect_uri: redirect_uri.clone(),
    scope: Some("openid profile".into()),
    ..Default::default()
})?;

let pushed = client.oidc_par(OidcParParams {
    request,
    redirect_uri: redirect_uri.clone(),
    scope: Some("openid profile".into()),
    tenant_id: None,
    configuration: Some(configuration),
}).await?;

redirect(&pushed.url);`,
          },
          {
            label: "TypeScript",
            code: `const configuration = await oidc.oidcDiscover();
const request = oidc.oidcBegin({ configuration, redirectUri, scope: 'openid profile' });

const pushed = await oidc.oidcPar({ request, redirectUri, scope: 'openid profile', configuration });

redirect(pushed.authorizationUrl);

// …on the callback, unchanged by PAR:
const tokens = await oidc.oidcExchange({
  code, redirectUri, nonce: pushed.nonce, codeVerifier: pushed.codeVerifier,
});`,
          },
          {
            label: "Python",
            code: `configuration = client.oidc_discover()
request = client.oidc_begin(configuration=configuration, redirect_uri=uri, scope="openid profile")

pushed = client.oidc_par(
    request=request,
    redirect_uri=uri,
    scope="openid profile",
    configuration=configuration,
    tenant_id=tenant_id,
)
redirect(pushed.authorization_url)

# …on the callback, unchanged by PAR:
tokens = client.oidc_exchange(
    code=code,
    redirect_uri=uri,
    nonce=pushed.nonce,
    code_verifier=pushed.code_verifier,
)`,
          },
        ],
      },
      {
        type: "note",
        text: "`request_uri` is wrapped in each SDK's redacting secret type. It is short-lived and single-use, and both of those are reasons it gets treated as harmless — but between the push and the redirect it is a bearer handle to a fully-formed authorization request, and a log line is the wrong place for it to sit for the length of that window. The normative rules are [CONTRACT §26](https://github.com/ilpanich/axiam/blob/main/sdks/CONTRACT.md); the server side is `crates/axiam-oauth2/src/par.rs`.",
      },
    ],
  },
];
