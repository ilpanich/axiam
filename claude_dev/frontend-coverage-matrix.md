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
| `authz_check` | — | **gap (P1)** | No "effective access" explorer. Now more visible than it was: with deny-override (B1) an admin can compose rules whose net effect is genuinely non-obvious, and the only way to find out is to call the endpoint. See §Planned below. |
| `bootstrap` | `BootstrapPage` | covered | |
| `ca_certificates` | `certificates/CertificatesPage` | partial | CA listing is visible; CA creation/rotation is API-only |
| `certificates` | `certificates/CertificatesPage` | covered | |
| `device` | — | **gap (P1)** | B2's verification page. The device-flow API is complete and the *only* way a user can approve a device today is to call `/api/v1/device/verify` and `/api/v1/device/decide` by hand — which no owner of a television is going to do. A `/device` route that takes a code (or reads `?user_code=` from the QR link), shows the requesting client and scopes, and offers Approve/Deny is what makes the grant usable. Small page; it is the last thing standing between B2 and a working feature |
| `email_config` | `settings/SettingsPage` | **gap (P2)** | Provider config is editable, but there is no **test-send** button — so the only way to find out an SMTP config is wrong is a user failing to receive a password reset |
| `email_verification` | `auth/VerifyEmailPage` | covered | |
| `federation` | `federation/FederationPage` | covered | |
| `gdpr` | — | **gap (P1)** | Export and erasure requests are API-only. These are the operations with statutory deadlines attached, which makes "there is a CLI for it" a weak answer |
| `groups` | `groups/GroupsPage`, `groups/GroupDetailPage` | covered | |
| `mfa_methods` | `profile/MfaManagementPage` | covered | includes passkeys and security keys since C1 |
| `mod` | — | n/a | module wiring, not a surface |
| `notification_rules` | `notifications/NotificationRulesPage` | covered | |
| `oauth2` | — | headless | the OAuth2/OIDC protocol endpoints are for clients, not admins. The **device-verification page** (`/device`) is the one exception and is planned with B2 |
| `oauth2_clients` | `oauth2/OAuth2ClientsPage` | covered | |
| `organizations` | `organizations/*` | covered | |
| `password_reset` | `auth/ForgotPasswordPage`, `auth/ResetPasswordPage` | covered | |
| `permissions` | `permissions/PermissionsPage`, `roles/RoleDetailPage` | **partial (P1)** | Grants are manageable, but the **deny-effect selector** shipped in B1's API has no UI yet — deny rules can be created over the API and are invisible in the console, which is the worst of both worlds. See §Planned |
| `pgp_keys` | `pgp/PgpKeysPage` | covered | |
| `reactors` | `reactors/ReactorsPage` | **partial (P3)** | List, editor and delete are covered, and the event options render from `GET /api/v1/reactors/events` rather than a hard-coded list. Health is covered for the two signals the API exposes: `last_seen_at` distinguishes never-connected from silent-since, and `fail_closed` carries a badge. The third planned signal — **recent timeouts and vetoes** — is blocked on the server, not on the UI: the dispatcher builds `ChainResult.failures` but no caller persists it and no reactor audit action exists, so there is nothing to render. See §Planned |
| `resources` | `resources/ResourcesPage` | covered | includes the `ResourceTree` |
| `roles` | `roles/RolesPage`, `roles/RoleDetailPage` | covered | |
| `scopes` | `permissions/PermissionsPage` | partial | scopes are selectable when granting; there is no standalone scope CRUD |
| `service_accounts` | `service-accounts/ServiceAccountsPage` | covered | |
| `settings` | `settings/SettingsPage` | covered | |
| `tenants` | `tenants/TenantsPage`, `organizations/TenantDetailPage` | covered | |
| `uma` | `resources/ResourcesPage` (UMA badge) | headless + badge | X2. The Protection API (`/uma2/perm`, `/uma2/rreg/*`) is machine-to-machine by construction: its caller is a **resource server** holding a client-credentials PAT, not a human at a screen, so there is nothing for an admin to do on those endpoints and a page would have no user. What an admin *does* need is to see the consequences, and those already have a home — a resource registered through UMA is an ordinary AXIAM resource, so it appears on the existing resources page, and its scopes on the existing scope surfaces. The one thing added is a read-only **UMA badge** on resources carrying `uma_registered_by`, so an admin can tell "a resource server created this" from "somebody made this by hand". Deliberately not editable: the badge asserts provenance, and a marker the UI could write would be decoration that reads like evidence |
| `users` | `users/UsersPage`, `users/UserDetailPage` | covered | |
| `webauthn` | `profile/MfaManagementPage`, `LoginPage` | covered | C1/C2 |
| `webhooks` | `webhooks/WebhooksPage` | covered | |

## Planned surfaces

These follow from features this improvement plan adds, and are tracked here so
the matrix stays the single place that answers "can an admin actually do this".

| Surface | Follows | What it needs |
|---|---|---|
| Deny-effect selector on the role/permission editor | B1 | An effect control on the grant form, a visually distinct **DENY** badge (deny is not "a red allow" — it is the rule that beats every allow, and the UI has to make that legible), and inheritance preview on the `ResourceTree` showing which descendants a deny reaches |
| Effective-access preview panel | B1 | Pick a subject and a resource, call `authz/check`, and show the outcome **and its `reason_code`** before saving. With deny-override the net effect of a rule set is genuinely not obvious by inspection; this is the difference between an admin who can reason about their rules and one who tries them in production |
| `/device` verification page | B2 | Enter user code → authenticate → consent → approve. Public route, since the point is that the device cannot show it |
| Reactor failure history | X1 | **Server-side first.** The console ships without the "recent timeouts and vetoes" panel because the data does not exist: `ChainResult.failures` is computed in `axiam-amqp`'s dispatcher and dropped on the floor — no caller writes it to the audit trail, and the audit action catalogue has no reactor entry. A `fail_open` timeout is invisible in the outcome by design, so absent an audit record it is invisible everywhere, which is exactly the case the dispatcher's own comment says must not happen. Persist the failures, then the panel is a small page change |
| SCIM token management | B4 | Issue/revoke provisioning tokens, scoped to `scim:provision` |
| Session/logout settings | B5 | Per-client `post_logout_redirect_uri` allow-list and back-channel logout URI |
| GDPR export/erasure console | existing gap | Above; statutory deadlines make this the highest-value existing gap |
| Email test-send | existing gap | One button on the email config panel |

## How the CI check works

`scripts/check-frontend-coverage.py` lists `crates/axiam-api-rest/src/handlers/*.rs`
and asserts each module name appears in a row of the table above. It is
deliberately dumb — it checks that a decision was *recorded*, not that the
decision was right, because "is this UI adequate" is not a thing a grep can
answer. What it does prevent is a handler module shipping with nobody having
asked the question.
