# B5 — relying-party example app: login + the logout triad

No relying-party example app existed anywhere in the repository before this
— `claude_dev/improvement-after-run5-benchmark.md` §B5 calls for "one RP
example app update" and none was found (checked `docs/`, and everywhere
else in the tree). This is that app, new.

**What this demonstrates.** A small Express/TypeScript backend playing the
role of a relying party (RP) integrating against AXIAM's OIDC provider:

1. **Login** — `authorization_code` + PKCE, pushed through PAR (RFC 9126,
   `POST /oauth2/par` — see `crates/axiam-api-rest/src/handlers/oauth2.rs`'s
   `pushed_authorization_request` doc comment, and
   [`docs/admin/fapi2-profile.md`](../../docs/admin/fapi2-profile.md) for
   the profile that makes it mandatory) by default (`AXIAM_USE_PAR=false`
   to see the plain redirect instead), then the full `sdks/CONTRACT.md`
   §12.4 ID-token validation checklist (EdDSA only,
   issuer/audience/time/nonce, all-or-nothing failure).
2. **RP-Initiated Logout** (`GET /logout`) — builds the
   `end_session_endpoint` redirect from `id_token_hint` +
   `post_logout_redirect_uri` + `state`, per §12.7.2.
3. **Back-Channel Logout** (`POST /backchannel-logout`) — the receiver
   endpoint AXIAM POSTs a signed logout token to when a session this app
   participated in ends *anywhere*, verified against every check in §12.7.3
   (signature, `iss`/`aud`, the `events` key, absence of `nonce`, `sid`/`sub`
   presence, freshness, `jti` surfaced for dedup) before ending the matching
   local session — and **only** that session when `sid` is present, never
   every session for the subject.

Implemented directly against the documented wire protocol (`fetch` + `jose`
— see [`src/oidc.ts`](src/oidc.ts)'s file header for why this doesn't depend
on the published `axiam-sdk` npm package), so it doubles as a from-scratch
reference for integrating against AXIAM's OIDC surface in any language.

## What it requires

- Node.js 20+ and npm.
- A running, bootstrapped AXIAM instance (see
  [`scripts/e2e-bootstrap.sh`](../../scripts/e2e-bootstrap.sh)) with an
  OAuth2 client registered for this app — **no grant-type blocker here**
  (unlike [`../b2-iot-device-quickstart`](../b2-iot-device-quickstart/README.md)
  and [`../b3-mesh-delegation-grpc`](../b3-mesh-delegation-grpc/README.md)):
  `authorization_code`/`refresh_token` are already accepted by the REST
  client-registration endpoint, and `post_logout_redirect_uris` /
  `backchannel_logout_uri` are plain fields on the same request, not grants.

```bash
docker compose -f docker/docker-compose.e2e.yml up -d --wait
./scripts/e2e-bootstrap.sh

# Register this app as an AXIAM OAuth2 client (adjust ports/URIs to taste):
curl -sS -X POST http://localhost:8090/api/v1/oauth2-clients \
  -H "Content-Type: application/json" -b admin-cookies.txt -H "X-CSRF-Token: $CSRF" \
  -d '{
    "name": "b5-rp-logout-app",
    "redirect_uris": ["http://localhost:9999/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scopes": ["openid", "profile"],
    "post_logout_redirect_uris": ["http://localhost:9999/"],
    "backchannel_logout_uri": "http://localhost:9999/backchannel-logout"
  }'
# (see examples/b1-deny-override/walkthrough.sh for the full login/CSRF dance
# this curl call assumes — admin-cookies.txt + $CSRF come from the same
# X-CSRF-Token-capture pattern used there)

cd examples/b5-rp-logout-app
npm install
AXIAM_URL=http://localhost:8090 \
AXIAM_TENANT_ID=<tenant uuid from the login response> \
AXIAM_CLIENT_ID=<client_id from the registration response> \
AXIAM_CLIENT_SECRET=<client_secret from the registration response> \
  npm start
# then open http://localhost:9999/ in a browser
```

## Not covered

- **Session storage.** `sessionsByCookie` / `pendingByState` /
  `cookieBySid` in `src/server.ts` are plain in-memory `Map`s that reset on
  restart and do not scale past one process. A real RP replaces them with a
  real session store; nothing about the AXIAM-facing logic in
  `src/oidc.ts` changes if you do.
- **TLS.** This app runs over plain HTTP on `localhost` for the same reason
  `docker-compose.dev.yml` sets `AXIAM__AUTH__COOKIE_SECURE=false` for local
  dev — never do this in production; OIDC's security properties assume
  HTTPS front to back.
- **A durable `jti` dedup store.** `seenLogoutJti` is an in-memory `Set`
  (see `docs/api/logout.md` "jti is the dedup key" — delivery is
  at-least-once, so a valid token legitimately arrives twice). A restart
  loses it, which just means a legitimate retry is treated as a first
  delivery — safe, since ending an already-ended session is a no-op here.

## Verification status

The app (`src/`) typechecks cleanly (`npm run typecheck`, `tsc --noEmit`)
and builds (`npm run build`) against the real, published `express`, `jose`,
and `typescript` package versions pinned in `package-lock.json`.
[`smoke-test.sh`](smoke-test.sh) (`bash -n` and `shellcheck` both clean) is
registered in `.github/workflows/examples-smoke.yml`'s `runtime-smoke` job
and drives the full login → RP-Initiated Logout → Back-Channel Logout chain
with plain `curl` — no headless browser needed, because a single curl
cookie jar correctly carries both AXIAM's session cookie and this app's
`rp_session` cookie across the redirect chain (see the script's own header
comment). **None of this has actually been run** — no docker daemon in the
environment this was authored in (see the repo root `examples/README.md`),
so the login/logout/back-channel logic is protocol-correct against
`sdks/CONTRACT.md` and `docs/api/logout.md` by construction and review, and
the smoke script is believed correct by the same kind of review, but neither
has been observed to run.
