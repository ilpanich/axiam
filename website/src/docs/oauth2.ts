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
        text: "With PAR (RFC 9126) the client posts the authorization parameters to AXIAM directly and receives a `request_uri` to put in the browser redirect, instead of placing every parameter in a URL the user agent can see and modify. It can be required per client, and **is** required for any client registered under the FAPI 2.0 profile.",
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
];
