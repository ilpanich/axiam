# Frontend coverage matrix — REST handler surface vs admin UI

> C4 from `claude_dev/improvement-after-run5-benchmark.md`. One row per REST
> handler module in `crates/axiam-api-rest/src/handlers/`. Checked in CI by
> `scripts/check-frontend-coverage.py`, which fails when a handler module has
> no row — so a new server surface cannot silently ship with no UI and no
> record of the decision.
>
> **A missing UI is not automatically a bug.** Several handler modules are
> deliberately headless (machine-to-machine, or bootstrap-only). The point of
> the matrix is that each of those is a *stated* decision rather than an
> oversight nobody noticed.

## Severity key

| | Meaning |
|---|---|
| **covered** | An admin can do the module's normal work from the UI. |
| **partial** | Some operations are reachable; the gap is named. |
| **gap** | Reachable only via API. Severity says how much that costs. |
| **headless** | Deliberately no UI. The reason is stated. |

## Matrix

| Handler module | UI surface | Status | Notes |
|---|---|---|---|
| `audit` | `audit/AuditLogsPage` | covered | |
| `auth` | `LoginPage`, `auth/*`, `profile/ChangePasswordPage` | covered | login, MFA verify, password reset/change, email verification |
| `authz_check` | `resources/EffectiveAccessPanel` (on `resources/ResourcesPage`) | covered | R4.2e. Pick a subject (self, or any user with `authz:check_as`) and an action/scope against the selected resource; calls `POST /api/v1/authz/check` and shows Allow/Deny/No-grant plus the raw `reason_code`. A `denied_by_rule` result triggers a `POST /api/v1/authz/check/batch` sweep of every descendant of the checked resource and feeds the denied ids to `ResourceTree`'s new red **DENY** badge — the inheritance preview. Previews the tree's current *saved* state only; there is no what-if-I-added-this-grant endpoint to preview an unsaved edit against |
| `bootstrap` | `BootstrapPage` | covered | |
| `ca_certificates` | `certificates/CertificatesPage` | partial | CA listing is visible; CA creation/rotation is API-only |
| `certificates` | `certificates/CertificatesPage` | covered | |
| `device` | `device/DevicePage` | covered | R4.1. `/device` (no permission gate — authentication only, same class as `/profile`): enter/paste a user code (or land via `?user_code=` from a QR link), see the requesting client and scopes from `GET /api/v1/device/verify`, then Approve/Deny via `POST /api/v1/device/decide`. All three verify failure modes (unknown/expired/already-decided) render one generic message per the handler's own doc comment |
| `email_config` | `settings/SettingsPage` | **gap (P2), unresolved — no backend endpoint** | Provider config is editable, but there is no test-send capability, and unlike the rest of R4.2 this is not a UI-only gap: `crates/axiam-api-rest/src/handlers/email_config.rs` has no test-send route at all (`grep`-confirmed; no `test_email`/`send_test_email` anywhere in the crate), so there is nothing for a frontend button to call. Building one would mean fabricating a request against an endpoint that doesn't exist. Needs a backend handler first |
| `email_verification` | `auth/VerifyEmailPage` | covered | |
| `federation` | `federation/FederationPage` | covered | |
| `gdpr` | `privacy/PrivacyPage` | covered | R4.2a. `/privacy` (no permission gate — self-service by default): request an export (`POST /api/v1/account/export`), redeem a mailed download token (`GET /api/v1/account/export/{token}`, triggers a browser download), request erasure with a confirm dialog (`POST /api/v1/account/delete`), and cancel a pending erasure with a mailed token (public `GET /api/v1/auth/account/delete/cancel`). Admins with `gdpr:export` / `users:erase` get an additional "act on behalf of" user-id field on export/erasure respectively |
| `groups` | `groups/GroupsPage`, `groups/GroupDetailPage` | covered | |
| `mds` | `settings/AttestationPolicyPage` | covered | X3 wave 4. `GET /api/v1/mds/status` renders serial (`no`), `next_update`, `entry_count`, `last_refreshed_at`, and a Fresh/Stale badge; `POST /api/v1/mds/refresh` is an admin-only "Refresh now" button (gated on `ca_certificates:generate`) whose outcome (Initial/Replaced/NoOpRefresh/RollbackRejected) is shown verbatim. A never-ingested deployment gets an explanatory message rather than blank fields. A viewer with `webauthn_policy:read` but not `ca_certificates:list` sees a permission note instead of a failed request |
| `mfa_methods` | `profile/MfaManagementPage` | covered | includes passkeys and security keys since C1 |
| `mod` | — | n/a | module wiring, not a surface |
| `notification_rules` | `notifications/NotificationRulesPage` | covered | |
| `oauth2` | — | headless | the OAuth2/OIDC protocol endpoints are for clients, not admins. The **device-verification page** (`/device`) is the one exception (R4.1, shipped) |
| `oauth2_clients` | `oauth2/OAuth2ClientsPage` | **partial (P3)** | R4.2d added B5 session/logout settings to the create/edit forms: a per-client `post_logout_redirect_uris` allow-list and `backchannel_logout_uri`, both submitted on create/update. **Known backend gap**: `OAuth2ClientResponse` (`crates/axiam-api-rest/src/handlers/oauth2_clients.rs`) does not serialize either field back, even though `Create`/`UpdateOAuth2ClientRequest` both accept and persist them — so a save succeeds but the edit form cannot pre-fill the currently-saved value until that response DTO adds the two fields. Write path works today; read-back needs the backend fix |
| `organizations` | `organizations/*` | covered | |
| `password_reset` | `auth/ForgotPasswordPage`, `auth/ResetPasswordPage` | covered | |
| `permissions` | `permissions/PermissionsPage`, `roles/RoleDetailPage` | covered | The **deny-effect selector** shipped in B1's API has UI: `roles/RoleDetailPage` grants an Allow/Deny effect with an explicit radiogroup (deny is not styled as "a red allow"), a confirming caption on selecting deny, and a red **DENY** badge on granted-permission rows so a deny rule doesn't read like every other grant. R4.2e closed the remaining ResourceTree-level gap — see the `authz_check` row for the inheritance preview |
| `pgp_keys` | `pgp/PgpKeysPage` | covered | |
| `reactors` | `reactors/ReactorsPage` | **partial (P3)** | List, editor and delete are covered, and the event options render from `GET /api/v1/reactors/events` rather than a hard-coded list. Health is covered for the two signals the API exposes: `last_seen_at` distinguishes never-connected from silent-since, and `fail_closed` carries a badge. The third planned signal — **recent timeouts and vetoes** — is blocked on the server, not on the UI: the dispatcher builds `ChainResult.failures` but no caller persists it and no reactor audit action exists, so there is nothing to render. See §Planned |
| `resources` | `resources/ResourcesPage` | covered | includes the `ResourceTree` |
| `roles` | `roles/RolesPage`, `roles/RoleDetailPage` | covered | |
| `scim_tokens` | `scim/ScimTokensPage` | covered | Issue, list and revoke the long-lived provisioning token an IdP pastes into its SCIM connector. The credential exists because `/scim/v2` previously had only 15-minute access tokens, which Okta and Entra cannot refresh — see `claude_dev/scim-provisioning-token-design.md`. Create is gated on `scim_tokens:create`, revoke on `scim_tokens:revoke`, both deliberately separate from `scim:provision` so a provisioner cannot mint more of itself. The handle is shown once via `SecretRevealModal` and stored only as a hash, so there is nothing for the list to display and nothing to re-reveal |
| `scopes` | `permissions/PermissionsPage`, `resources/ScopesPanel` (on `resources/ResourcesPage`) | covered | R4.2c. Scopes are still selectable when granting a permission (`permissions/PermissionsPage`); standalone CRUD now lives on `resources/ScopesPanel`, shown for the currently-selected resource since scopes are always nested under one (`/api/v1/resources/{resource_id}/scopes`). Create is gated on `scopes:create` |
| `service_accounts` | `service-accounts/ServiceAccountsPage` | covered | |
| `settings` | `settings/SettingsPage` | covered | |
| `tenants` | `tenants/TenantsPage`, `organizations/TenantDetailPage` | covered | |
| `uma` | `resources/ResourcesPage` (UMA badge) | headless + badge | X2. The Protection API (`/uma2/perm`, `/uma2/rreg/*`) is machine-to-machine by construction: its caller is a **resource server** holding a client-credentials PAT, not a human at a screen, so there is nothing for an admin to do on those endpoints and a page would have no user. What an admin *does* need is to see the consequences, and those already have a home — a resource registered through UMA is an ordinary AXIAM resource, so it appears on the existing resources page, and its scopes on the existing scope surfaces. The one thing added is a read-only **UMA badge** on resources carrying `uma_registered_by`, so an admin can tell "a resource server created this" from "somebody made this by hand". Deliberately not editable: the badge asserts provenance, and a marker the UI could write would be decoration that reads like evidence |
| `users` | `users/UsersPage`, `users/UserDetailPage` | covered | |
| `webauthn` | `profile/MfaManagementPage`, `LoginPage` | covered | C1/C2 |
| `webauthn_policy` | `settings/AttestationPolicyPage` (linked from `settings/SettingsPage`) | **partial (P3)** | X3 wave 4. `GET`/`PUT .../attestation-policy`: mode selector, `require_fido_certified`, `min_certification`, `block_revoked_status`, a tri-state `unknown_aaguid` editor (Use mode default / Always allow / Always deny, with the resolved default shown live for the selected mode), and allow/block AAGUID list editors (with the `null` vs `[]` "deliberate lockout" distinction preserved) are all covered, gated on `webauthn_policy:write`. The passkey caveat from the admin guide is surfaced the moment a non-`none` mode is chosen (not just on save) and requires an explicit acknowledgement checkbox before saving. `GET .../compliance-report` is a read-only table distinguishing Compliant/Unknown/Violation, with the no-AAGUID bucket always rendered as Unknown (never a violation) and no revoke action anywhere in the panel — revocation stays the existing per-credential delete path on `users/UserDetailPage`. The **partial** gap: `authenticator_name` (deliverable 4, "wherever credentials are listed") is only available from the compliance-report endpoint and is shown there; `profile/MfaManagementPage` and `users/UserDetailPage` list credentials via `GET /users/{id}/mfa-methods`, whose `MfaMethodResponse` DTO (`crates/axiam-api-rest/src/handlers/mfa_methods.rs`) does not carry the field, so those two pages cannot show authenticator model names without a backend DTO change |
| `webhooks` | `webhooks/WebhooksPage` | covered | |

## Planned surfaces

These follow from features this improvement plan adds, and are tracked here so
the matrix stays the single place that answers "can an admin actually do this".
Everything that shipped in R4.1/R4.2 has moved to its row above; two items
remain genuinely open.

| Surface | Follows | What it needs |
|---|---|---|
| Reactor failure history | X1 | **Server-side first.** The console ships without the "recent timeouts and vetoes" panel because the data does not exist: `ChainResult.failures` is computed in `axiam-amqp`'s dispatcher and dropped on the floor — no caller writes it to the audit trail, and the audit action catalogue has no reactor entry. A `fail_open` timeout is invisible in the outcome by design, so absent an audit record it is invisible everywhere, which is exactly the case the dispatcher's own comment says must not happen. Persist the failures, then the panel is a small page change |
*(SCIM token management, previously listed here, shipped — see the
`scim_tokens` row above. It needed a backend first: there was no long-lived
credential to manage, only 15-minute access tokens.)*

## How the CI check works

`scripts/check-frontend-coverage.py` lists `crates/axiam-api-rest/src/handlers/*.rs`
and asserts each module name appears in a row of the table above. It is
deliberately dumb — it checks that a decision was *recorded*, not that the
decision was right, because "is this UI adequate" is not a thing a grep can
answer. What it does prevent is a handler module shipping with nobody having
asked the question.
