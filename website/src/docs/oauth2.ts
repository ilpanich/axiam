import type { DocPage } from "./types";

/**
 * "OAuth2 & OIDC" — the authorization-server surface.
 *
 * The overview page is the one to keep honest about tenant selection: discovery
 * is deployment-wide (one issuer), and the tenant is named by the `tenant_id`
 * query parameter on the token-family endpoints or derived from `client_id` on
 * `/authorize`. An earlier revision of these docs described a per-tenant,
 * path-based discovery document; the server rejects path-based issuers, so that
 * text described something that could not work.
 */
export const OAUTH2_PAGES: DocPage[] = [
  {
    slug: "oauth2",
    section: "OAuth2 & OIDC",
    navLabel: "Authorization server",
    title: "OAuth2 & OpenID Connect",
    intro:
      "AXIAM is a complete OAuth2 authorization server and OpenID Connect provider — discovery, JWKS, five grant types, introspection, revocation and userinfo.",
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
            "PKCE is the expected shape for public clients; pushed authorization requests (PAR) can be required per client.",
          ],
          [
            "Client Credentials",
            "Machine-to-machine access with a service account or confidential client.",
            "Authenticate with a secret, or with mutual TLS instead — see [FAPI 2.0 & mTLS clients](#/docs/fapi2).",
          ],
          [
            "Refresh Token",
            "Extending a session without re-authenticating.",
            "Opaque, server-stored, single-use, rotating on every refresh.",
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
          { method: "GET", path: "/oauth2/jwks", summary: "Signing keys, cached with an ETag and Cache-Control.", public: true },
          { method: "GET", path: "/oauth2/authorize", summary: "Authorization endpoint. Tenant is derived from client_id.", public: true },
          { method: "POST", path: "/oauth2/par", summary: "Pushed authorization request (RFC 9126).", public: true },
          { method: "POST", path: "/oauth2/token", summary: "Token endpoint — every grant.", public: true },
          { method: "POST", path: "/oauth2/introspect", summary: "Token introspection (RFC 7662).", public: true },
          { method: "POST", path: "/oauth2/revoke", summary: "Token revocation (RFC 7009).", public: true },
          { method: "GET", path: "/oauth2/userinfo", summary: "OIDC userinfo claims for the bearer.", public: true },
          { method: "POST", path: "/oauth2/device_authorization", summary: "Begin a device grant (RFC 8628).", public: true },
          { method: "GET", path: "/oauth2/end_session", summary: "RP-initiated logout.", public: true },
        ],
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
        text: "The discovery document is **deployment-wide**, not per-tenant: one issuer, served at `/.well-known/openid-configuration`. `AXIAM__AUTH__OAUTH2_ISSUER_URL` must be an origin — a path-based issuer is rejected at startup. An off-the-shelf OIDC client that cannot add a `tenant_id` query parameter to the token endpoint therefore needs a small shim, or a per-tenant gateway route in front of AXIAM.",
      },
      {
        type: "code",
        caption: "discovery",
        code: "curl -s https://iam.acme.dev/.well-known/openid-configuration | jq .\n\n# and the keys a relying party verifies tokens with\ncurl -s https://iam.acme.dev/oauth2/jwks | jq .",
      },
      { type: "h", id: "tokens", text: "The tokens you get back" },
      {
        type: "p",
        text: "Access tokens are EdDSA (Ed25519) JWTs, short-lived, and verifiable offline against the JWKS — which is the fast path for a resource server, and the one to prefer over introspecting on every request. ID tokens carry `sid`, the session identifier, which is stable across refresh. Refresh tokens are opaque and single-use.",
      },
      {
        type: "p",
        text: "Introspection exists for the cases offline verification cannot answer: whether a token has been revoked since it was issued, and what an opaque token refers to. A resource server that introspects on every request should expect to make roughly ten to twenty introspection calls per token issued — the shipped rate limits are sized for that ratio.",
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
          ["audience / resource", "no", "Narrows who the issued token is for."],
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
          "**Audience** — an issued token can be bound to one downstream service, so a leak at that service does not yield a token usable everywhere.",
          "**Lifetime** — the issued token never outlives the subject token.",
          "**Authorization** — the subject's own grants still apply. Exchange does not confer authority; it repackages it.",
        ],
      },
      {
        type: "warn",
        text: "Because exchange only narrows, it is not a privilege-escalation mechanism — and it is also not a way to *grant* a service access to something the user cannot reach. If a downstream call needs authority the user does not have, that is a role-model problem, not an exchange problem.",
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
        text: "`sid` is stable across refresh: a token minted by the refresh grant carries the same `sid` as the one issued at login, so a relying party that stored it can still match a logout token to its own session.",
      },
      { type: "h", id: "rp", text: "RP-initiated logout" },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/oauth2/end_session", summary: "End the session and redirect the browser back.", public: true },
        ],
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
        text: "A client carrying `require_par` is then refused at `/oauth2/authorize` if it sends its parameters inline, so the constraint holds at use as well as at registration — see [Pushed authorization](#/docs/par).",
      },
      {
        type: "note",
        text: "That refusal is the point. A client satisfying eleven of twelve FAPI constraints is not \"mostly FAPI\" — it is a client with a hole. The bundle cannot be half-applied, so a reviewer can answer *is this client conformant?* by reading one field.",
      },
      { type: "h", id: "mtls", text: "mTLS client authentication" },
      {
        type: "p",
        text: "`tls_client_auth` replaces the shared secret with a client certificate, matched against a configured identifier — `tls_client_auth_san_dns` and its siblings. The certificate is verified by AXIAM's own TLS listener; **no proxy-asserted identity header is in the trusted path**, so there is no `X-Client-Certificate` to forge.",
      },
      {
        type: "table",
        headers: ["Variable", "Values", "Default", "Meaning"],
        rows: [
          ["AXIAM__SERVER__TLS__CLIENT_AUTH", "off | optional | required", "off", "Client-certificate policy on the native listener."],
          ["AXIAM__SERVER__TLS__CLIENT_CA_PATH", "PEM bundle path", "—", "Trust anchors for client certificates."],
        ],
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
          "**The authorization URL carries exactly two parameters.** Not `response_type`, not `redirect_uri`, not `scope`, not `state`, not the PKCE pair. The server **refuses** a request that mixes a `request_uri` with any inline authorization parameter rather than merging them — and re-adding them “for compatibility” restores the parameter-confusion attack the refusal prevents, where an attacker supplies the inline value they want and lets the pushed copy satisfy whichever check reads the other one.",
          "**The `request_uri` is single-use and short-lived** — 60 seconds, consumed the moment `/oauth2/authorize` reads it. There is deliberately no configuration knob: the window only has to cover one browser redirect, and a tunable that only trends longer is a tunable that only widens a replay window. A second use is `invalid_request`, not a duplicate-suppressed success.",
          "**A push is never retried.** It is a `POST` that creates server state, so it sits outside the SDKs' read-only retry eligibility. A transport failure after the request left the client is surfaced rather than retried — the safe recovery is a fresh push, which costs one round trip and cannot double-consume anything.",
          "**Treat the `request_uri` as opaque.** Do not parse it, do not validate its `urn:` prefix as a precondition, do not reconstruct one. Checking the prefix buys nothing and breaks the moment the format is versioned.",
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
        text: "Registering a client with `profile: \"fapi2\"` forces `require_par`, and a client with `require_par` set is **refused** at `/oauth2/authorize` when it sends its parameters inline. A FAPI 2.0 client therefore cannot authorize any other way — which is the intent: the profile is a constraint bundle a client cannot half-apply.",
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
