# Release 1.2.0 — upgrade notes

For operators upgrading from 1.1.x (1.1.3 is the previous release). The same
points, shorter, are in the `[1.2.0]` section of [`CHANGELOG.md`](../CHANGELOG.md).
Plan: [`social-login-gap-plan-2026-10-30.md`](social-login-gap-plan-2026-10-30.md).
Release 1.2.0 adds native sign-in with a provider ID token (G-A), a provider
hint and a per-client default provider (G-B), a session revocation on a
refresh-token replay (G-C) and `client_id` on exchanged tokens (G-D). Only G-C
and the logout change of §1a (D-N39) change behaviour for a client you already
run.

## 1. A replayed refresh token now revokes the session (G-C, #818)

Before 1.2.0, presenting an already-rotated refresh token was answered `400
invalid_grant`, marked on the session and audited as
`oauth2.refresh_token_replayed`, and nothing else happened. From 1.2.0 the
default also **invalidates the session** the token belongs to and **revokes every
refresh token issued under it**, the successor included (OAuth 2.0 Security BCP,
RFC 9700 §4.14.2; the authorization-code replay path already did this). It applies
to `standard` clients and to `fapi2` clients once the 60-second grace window has
passed. The client's answer is unchanged.

- **Who is affected.** A client that loses a rotation response and retries with
  the old token was already refused and had to re-authorize; it now also signs
  its user out of that session. A client that sends two refreshes with the same
  token at once will see its session revoked rather than one request refused.
  Other sessions of the same user are untouched.
- **To keep the 1.1.x behaviour** (refuse, mark, audit; revoke nothing), set the
  security setting `oauth2.refresh_reuse_response` to `refuse`:

  ```
  PUT /api/v1/organizations/{org_id}/settings
  { ..., "refresh_reuse_response": "refuse" }
  ```

  The setting is tighten-only (D-N8): a tenant may choose `refuse` only when its
  organization is on `refuse`. Do it before the upgrade or right after.
- **An organization settings `PUT` from a pre-1.2.0 client** omits the field,
  which then defaults, so it moves an organization you set to `refuse` back to
  `revoke_session` (the stricter direction). Re-send `refuse` from an updated
  client, or keep the older client away from organization settings.
- **Alerting.** The `oauth2.refresh_token_replayed` row gains `response`
  (`revoked_session`, `refused`, `refused_unverified_presenter`,
  `revocation_failed`) and `token_client_id`. `refused_unverified_presenter` means
  a revocation that would otherwise have run was withheld because another client,
  or a bound token without its key's proof, presented the token; under `refuse`,
  or when the token names no session, the value is `refused`.
  `revocation_failed` (with `failed_writes`) is a replay whose successor may
  still be live: alert on it.
- **No back-channel logout is sent** to the relying parties that share the revoked
  console session; their access tokens stop at the session check and, with the
  revocation feed on, through `GET /oauth2/revocations`.

The full behaviour, with the cases that are not a replay, is in the deployment
guide, [Refresh-token replay revokes the session](../docs/deployment/README.md#refresh-token-replay-revokes-the-session-g-c-818).
This section does not repeat it.

## 1a. Logout now ends the session's refresh tokens (D-N39, #839)

Before 1.2.0, logging one session out deleted the session and nothing else. Its
access tokens stopped at the session check, but every OAuth2 refresh token issued
under the session stayed live and kept minting access tokens: refused by AXIAM's
session-checked APIs and UserInfo, but `active` at `POST /oauth2/introspect` and
accepted by a resource server that verifies the JWT locally. From 1.2.0 a
single-session logout (`POST /api/v1/auth/logout`, RP-initiated logout at
`/oauth2/end_session` with or without `id_token_hint`, and SAML single logout)
also **revokes every refresh token issued under that session**, for every client
and grant bound to it: authorization code and native sign-in alike. The user's
other sessions keep theirs.

- **Who is affected.** A relying party that kept refreshing after its user
  signed out of the session (through it, or through another relying party
  sharing the session) now gets `invalid_grant` and must sign the user in again.
  A native app that signs out with `end_session` or `/auth/logout` no longer has
  to call `/oauth2/revoke` as well (it still may).
- **Not a replay.** Presenting a token revoked at logout is `invalid_grant` with
  no `oauth2.refresh_token_replayed` row and no further revocation.
- **A failed revocation fails the logout** rather than answering "signed out":
  `/auth/logout` answers `500`; `end_session` answers a `500` page that does not
  redirect to the relying party; SAML single logout shows its
  `revocation_failed` page. The server log names the write that failed
  (`failed_writes`: `refresh_tokens_revoke` or `session_invalidate`).
- **Retrying it works with the same credential** (F4-R12-07, D-N43). The
  refresh tokens are revoked first and the session is deleted only after that
  succeeded, so every failure leaves the session live: repeating
  `/auth/logout` with the same bearer token, `end_session` with the same
  `id_token_hint`, or a new SAML `LogoutRequest` completes the logout. The
  failure pages clear the API cookies; the OP-session cookie is cleared too,
  except on the two paths where it is what names the session (the cookie hop
  `/oauth2/authorize/logout` and IdP-initiated SAML logout), whose page keeps it
  so that "Please try again" reaches the session.
- **Back-channel logout** now reaches a native-sign-in client that registered a
  `backchannel_logout_uri`: the grant records it as a participant of the session
  it creates, and RP-initiated logout with an `id_token_hint` naming that session
  notifies it.
- **Limit.** A code grant names the browser session as it was at
  `/oauth2/authorize`. Once the console session has refreshed, it has a new id,
  and `POST /auth/logout` of the console no longer reaches that grant.
  RP-initiated logout with the grant's own ID token still does.
- **A replayed authorization code** (D-N41, #842) now does the same to the
  session the code was issued from: beside invalidating that session (RFC 6749
  §10.5, unchanged), it revokes every refresh token issued under it, the code's
  own and any sibling grant's. A client that retries a code exchange after
  losing the `200` loses its refresh token as well as its session. The answer is
  still `invalid_grant`; a failed revocation is logged (`revocation_failed`,
  `failed_writes`) and does not change it.
- No setting and no schema change.

## 2. Schema v110 to v113 — all additive

The runner applies these at boot; nothing is backfilled and no statement redefines
an existing object, so a rolling update needs no special ordering.

| Version | What |
|---|---|
| v110 | the optional `security_settings.oauth2_refresh_reuse_response` field (no backfill: a row written before it reads as the default `revoke_session`) and the index `idx_refresh_token_session` on `oauth2_refresh_token(tenant_id, session_id)` |
| v111 | `native_login` trust block on OIDC federation configs (off by default) |
| v112 | `federation_id_token_replay` (the single-use record of provider ID tokens; not tenant data, so the tenant purge leaves it to its sweep, and a new cleanup job of the same name appears in `GET /health/jobs`) |
| v113 | `oauth2_client.default_idp` |

**A development database that ran a pre-sweep v112 build** (a branch build from
before 2026-10-31, never a release) keeps the old required fields of
`federation_id_token_replay` and fails closed on native sign-in. Drop the table
and the v112 stamp, then restart so the runner re-applies it (F4-W2-15):

```
REMOVE TABLE federation_id_token_replay;
DELETE _migration WHERE version = 112;
```

No release is affected. Read `SELECT * FROM _migration WHERE version = 112` before
deleting, and leave v113's stamp alone (it does not depend on v112).

## 3. Native sign-in is off until you register it (G-A, #816)

The grant `urn:axiam:params:oauth:grant-type:provider-id-token` at `POST
/oauth2/token` does nothing on upgrade. It needs **both**:

1. **Per provider.** On the OIDC federation config, `PUT
   /api/v1/federation-configs/{id}` with `native_login` (`enabled: true`, the
   app's `client_ids`, and optionally `max_token_age_secs`, 1 to 3600, default 300),
   or the trust card of the admin console. The provider's own web client ID is
   not an app ID: list the Android and iOS client IDs only.
2. **Per client.** The OAuth2 client's `grant_types` must list the grant (the
   client form offers it). Public clients may use it. Register it only on the
   clients that are the listed native apps: the trust is per tenant, not per
   client in 1.2.0 (T-489) — and, for a provider the organization's tenant
   shares by inheritance, per organization. Keep apps of different privilege on
   different providers, or turn inheritance off for a provider with native
   sign-in on (or shadow it in a tenant that must not accept it).

The grant is listed in the discovery document's `grant_types_supported`. It is
rate limited per tenant and address in the bucket `oauth2_provider_id_token`
(`AXIAM__RATE_LIMIT__LOGIN_PER_MIN`). See
[`docs/api/native-sign-in.md`](../docs/api/native-sign-in.md).

## 4. Provider hint and the `fresh=1` hop parameter (G-B, #817)

- `axiam_idp_hint` (a provider UUID, slug or branded kind name) on
  `/oauth2/authorize` and `/oauth2/par`, and `default_idp` on an OAuth2 client,
  send the user straight to a provider. Nothing changes for a client that sends
  neither. There is no `kc_idp_hint` alias; a Keycloak client changes its
  parameter name (migration note in
  [`docs/admin/oidc-authn-parameters.md`](../docs/admin/oidc-authn-parameters.md)).
- The login hop gains one query parameter, **`fresh=1`**, written by the server on
  the first hop of an `honour`-lane request that demands a fresh authentication
  (`prompt=login`, `max_age=0`) and by the sign-in page when it strips `reauth`
  or `acr`. It stops the page from starting a provider by itself; the server
  never reads it back. A reverse proxy, WAF or custom login page that allow-lists
  the `/login` query string must allow it.
- A provider sign-in started from the login hop now returns to the relying party
  (#832); the SAML and Apple handoff redirects carry the spent `state` (#835).
  A custom front end that consumed those handoffs must tolerate the extra
  parameter.

## 5. Smaller changes

- Exchanged tokens (RFC 8693 and X4) carry `client_id` and a marker
  `axiam_exchanged: true`; they are never accepted as an `actor_token`. Introspection
  now echoes `client_id` for every access token that carries it (G-D, #819).
- Administrator OAuth2 client create, update and delete are audited
  (`oauth2.client_created`, `oauth2.client_updated` with `changed_fields`,
  `oauth2.client_deleted`) (#834).

## 6. SDKs — read this before bumping one

SDK contract is **1.65**. The eleven SDKs ship as **minor releases** (D-N32); each
lists its source-breaking changes in its own CHANGELOG (Rust `OidcBeginParams`
gained a public field; Java records, Kotlin data classes and PHP constructors
gained parameters; C# dropped `adoptAsCredential`). Binary consumers rebuild:
the **C SDK is SOVERSION 3** and the **C++ SDK SOVERSION 5**.

**Server floor (D-N33).** `native_login` is a required member of federation-config
responses, so the federation-config admin calls of a 1.2-line SDK need an AXIAM
server of **1.2.0 or later**; against an older server they cannot decode the
response. Upgrade the server first, then the SDKs. The new helpers
(`login_with_provider_id_token`, `idp_hint`) also need the grant and the parameter,
which only a 1.2.0 server has.

| SDK | Pull request |
|---|---|
| Rust | [axiam-rust-sdk#145](https://github.com/ilpanich/axiam-rust-sdk/pull/145) |
| TypeScript | [axiam-typescript-sdk#157](https://github.com/ilpanich/axiam-typescript-sdk/pull/157) |
| Python | [axiam-python-sdk#107](https://github.com/ilpanich/axiam-python-sdk/pull/107) |
| Java | [axiam-java-sdk#127](https://github.com/ilpanich/axiam-java-sdk/pull/127) |
| Kotlin | [axiam-kotlin-sdk#82](https://github.com/ilpanich/axiam-kotlin-sdk/pull/82) |
| C# | [axiam-csharp-sdk#115](https://github.com/ilpanich/axiam-csharp-sdk/pull/115) |
| PHP | [axiam-php-sdk#89](https://github.com/ilpanich/axiam-php-sdk/pull/89) |
| Go | [axiam-go-sdk#107](https://github.com/ilpanich/axiam-go-sdk/pull/107) |
| Swift | [axiam-swift-sdk#80](https://github.com/ilpanich/axiam-swift-sdk/pull/80) |
| C | [axiam-c-sdk#79](https://github.com/ilpanich/axiam-c-sdk/pull/79) |
| C++ | [axiam-cplusplus-sdk#82](https://github.com/ilpanich/axiam-cplusplus-sdk/pull/82) |

Open after the contract review: C165-24 (Info, record text) and C165-28 (Info, a
Kotlin test flake).
