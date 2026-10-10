# Security review — release 1.0.0, wave W1 (F4)

**Date:** 2026-10-10.
**Against:** `claude/release-1.0.0-w1`, the whole wave diff `fe369eb..418e039`
(24 commits, 177 files, about 15 900 lines added and 1 600 removed; `fe369eb` is
the merge of #587 on `main`). Every commit carries a signature (`gpgsig` present
on all 24; the sandbox has no `allowedSignersFile`, so `%G?` cannot verify them
here).
**Scope:** every W1 task of the release plan (§2): W1.1 #549 (device approval,
T-447), W1.2 #564 (the lockout verify, T-469), W1.3 #565 (the CRL and the
`tls_client_auth` status lookup, T-102) with T-470 (Vault revocation
forwarding), W1.4 #517 (client deletion), W1.5 #518 (`actor_token`, T-471), W1.6
#519 (session refresh), W1.7 #523 (tenant tombstone and purge, T-472), W1.8 #529
(the email address guard, T-473), W1.9 #520 (`claims.id_token.sub`,
`account_may_act` at UserInfo and introspection, scope narrowing at refresh),
W1.10 #532 (`/oauth2/authorize` limiter, the browser preset), W1.11 #531
(SHA-1 and DTDs in the SP verifier), W1.12 #525 (omitted SMTP/API secret),
W1.13 #524 (`require_par` before the login hop), W1.14 #526 (discovery auth
methods, phone verification), W1.15 #530 (metadata signature and cache, T-474)
and the follow-ups (`c404174` null-clearing, `418e039` T-474 audit).
**Method:** adversarial reading of the diff and of every sibling path it
implies, against [`threat-model-stride.md`](threat-model-stride.md) and
`Axiam.json` (model 2.38.0, 474 threats: 434 / 19 / 21), the plan's §7 rules,
the W6 F4 review's §15 preconditions, and the OWASP ASVS 5.0 areas the diff
touches (V2 business logic, V4 API, V6 authentication, V7 session, V8
authorization, V9 tokens and certificates, V12 SSRF, V13 configuration, V14 data
protection, V16 logging). Claims were checked against the code, not the commit
messages; two were checked by a probe (§11). This review fixes nothing (the
orchestrator's instruction): every finding is reported with evidence, a proposed
fix and an issue body (§12). IDs follow the W2 review's scheme (`R1W1-nn`).

---

## 0. Summary

**One Medium finding introduced by the wave, and one High finding that predates
it but sits exactly on the question the wave's T-102 work answers.**

* **R1W1-01 (Medium, wave — #523 × #565).** Deleting a tenant revokes none of
  its certificates or tenant signing CAs, and the purge then **deletes** the
  `certificate` and `ca_certificate` rows. The organization CA's revocation
  list is computed from those rows, so a leaf that was revoked before the
  deletion **drops off the list** once the tenant is purged — a probe measured
  one entry before the deletion, one after the tombstone and **zero** after the
  purge — and every still-active leaf and tenant CA of the deleted tenant stays
  valid to every external relying party until it expires. The same purge
  removes revocations still waiting to be forwarded to Vault (T-470), and a
  purged leaf becomes `NotIssuedHere` to the `tls_client_auth` status lookup.
  T-102 ("an entry for every revoked and unexpired certificate the CA signed")
  and T-472 are both untrue after a tenant purge.
* **R1W1-02 (High, pre-existing since X5.1 and the trust-anchor flag).**
  `tls_client_auth` matches a registered subject DN or SAN against a
  certificate that chains to **any** anchor of the deployment's one listener,
  and any organization administrator with `ca_certificates:manage` can flag a
  CA of their own organization — including an imported, keyless CA whose key
  they hold offline — as such an anchor. A certificate minted under one
  organization's anchor with another organization's client DN therefore
  authenticates as that client. The wave's new inventory lookup has the issuing
  tenant in hand and does not compare it with the client's; a certificate
  AXIAM did not issue (`NotIssuedHere`) is not constrained at all.

Seven Low and four Informational findings are reported for `1.0.x` (§12).

| ID | Finding | Severity | Surface / threat | Origin | Disposition |
|---|---|---|---|---|---|
| **R1W1-01** | Tenant deletion revokes no certificate or tenant CA, and the purge deletes their rows: revoked leaves drop off the org CA's CRL, active ones stay trusted by external RPs, pending Vault forwards are lost. | **Medium** | `tenant_purge.rs`, `crl.rs`, `tenants.rs` → T-102, T-470, T-472 | wave | **Fix in wave** (proposed §2) |
| **R1W1-02** | `tls_client_auth` trusts a DN/SAN match under any deployment-wide anchor; org admins choose anchors; the inventory lookup ignores the issuing tenant/org. Cross-organization client impersonation. | **High** | `mtls.rs`, `ca_certificates.rs` → T-102, T-263 | pre-existing | **Decide now** (proposed §3) |
| R1W1-03 | A tombstoned tenant's OAuth2 clients still authenticate (`authenticate_client` reads no tenant): `bc-authorize` stores requests and mails the deleted tenant's users, introspection answers its live tokens, PAR rows are written. | Low | token service, CIBA → T-472 | wave | Reported |
| R1W1-04 | The purge destroys audit rows written after the export receipt (up to six hours before the delete, and everything until the purge), which no export covers. | Low | `tenant_purge.rs` → T-118 | wave | Reported |
| R1W1-05 | The `vault_revocation` sweep re-reads the same oldest 100 rows every tick: 100 rows Vault permanently refuses block every later revocation; every replica runs it. | Low | `certificate.rs`, `cert.rs` → T-470 | wave | Reported |
| R1W1-06 | Device-grant redemption re-reads the user but does not ask `account_may_act` (the CIBA redemption does). | Low | `device_service.rs` → T-39, T-160 | pre-existing | Reported |
| R1W1-07 | The "plainly UTF-8" refusal reads the XML declaration only when the text starts with `<?xml`; a leading byte-order mark skips it, and libxml2 then honours whatever the declaration names. Three parse sites also use libxml's default options. | Low | `saml_idp/request.rs`, `saml.rs`, `saml_metadata.rs` → T-67, T-69 | pre-existing, widened | Reported |
| R1W1-08 | `allow_sha1_signatures` passes no list at all: it admits every algorithm xmlsec verifies, not SHA-1 only. | Low | `saml.rs` → T-67 | wave | Reported |
| R1W1-09 | The CRL service holds one global cache mutex across the custodian `load`, the crypto-semaphore wait and the signing, and every unauthenticated request reads every revoked PEM of the CA. | Low | `crl.rs` → T-102 (availability) | wave | Reported |
| R1W1-10 | Each replica signs its own list (different bytes, ETag, CRL number; a lower number can follow a higher one), and `max-age` to `nextUpdate` lets a shared cache serve a pre-revocation list for up to a day. | Informational | `crl.rs`, `handlers/crl.rs` | wave | Reported |
| R1W1-11 | `CrlDistribution` stores the trimmed input rather than the URL it validated. | Informational | `crl.rs` | wave | Reported |
| R1W1-12 | Text and test hygiene: the STRIDE open register still lists T-470 as open; a stale test comment; the `tls_client_auth` revocation test drives the service, not the endpoint, and has no cross-tenant case; the purge and Vault sweeps race across replicas. | Informational | STRIDE, tests, `cleanup.rs` | wave | Reported |
| R1W1-13 | The Vault client follows redirects with `X-Vault-Token`, and replacing a SAML config's **assertion** certificate is not audited while the metadata certificate is. | Informational | `vault_pki.rs`, `federation.rs` | pre-existing | Reported |

**What held.** Every §7 rule holds for what the wave added (§4): the one new
route (the CRL) carries its limiter and its own bucket from its first commit
(`d3ea7ef`), and the email self-test routes gained one each; both approval
surfaces of the device grant answer a token carrying `client_id` `403` before
reading the code; every new refusal of a credential check (the lockout branch,
every gRPC `ValidateCredentials` refusal) costs one verify under the same
permit; the email provider's HTTP calls use `guarded_fetch_no_redirect`. The
`actor_token` binding (§6), `account_may_act` at session refresh, UserInfo and
introspection on both transports (§6), the refresh narrowing (only ever
narrows, §6), the `require_par` placement (§6), the email address guard
(IPv4-mapped, IPv4-compatible, 6to4 and NAT64 forms, pinning, TLS name, no
redirect; §7), #525's same-destination rule (§7), the metadata signature
placement and pre-digest read (§8), and the metadata cache keying (§8) are
correct. The browser preset is used only on browser routes; no machine bucket
changed (§5). Threat-model counts agree across `Axiam.json`, the STRIDE
document and the generated website files (474: 434 / 19 / 21), and a generator
run leaves no diff (§10).

**Verdict on merge.** R1W1-01 should be fixed in the wave: the wave publishes a
list whose purpose is to be trusted by parties AXIAM does not front, and its own
tenant purge silently un-revokes certificates on it. R1W1-02 is not this wave's
regression, but it is High and the wave touched the exact function where its
first half is a three-line fix; the maintainer should decide now whether it
ships in 1.0.0 (recommended) or is filed with a release note. Nothing else
blocks.

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| CRL route, service, distribution point | W1.3 #565 | `handlers/crl.rs`, `axiam-pki/src/crl.rs`, `cert.rs`, `ca.rs`, repositories, schema v90, `server.rs`, `permissions.rs` | **read in full**; caching, ETag/304, 404 cases, re-sign triggers, CDP construction; tests run |
| `tls_client_auth` status lookup | W1.3 #565 | `axiam-oauth2/src/mtls.rs`, `token.rs`, `ca_certificates.rs`, PKI guide | **read in full**; fingerprint, cross-tenant/org, self-signed path |
| Vault revocation forwarding | T-470 | `cert.rs`, `vault_pki.rs`, `certificate.rs`, `cleanup.rs`, schema v94, PKI guide | **read in full**; token scope, retry, mount path |
| Tenant tombstone and purge | W1.7 #523 | `tenant.rs`, `tenant_purge.rs`, `session.rs`, `settings.rs`, `tenants.rs`, `cleanup.rs`, `tenant_org_cache.rs` | **read in full**; read paths, purge order, slug, audit rows; **probed** against the CRL (§11) |
| Email egress | W1.8 #529, W1.12 #525 | `axiam-email/src/egress.rs`, providers, `axiam-pki/src/address.rs`, `axiam-core/src/ip_class.rs`, `email_config.rs` (handler and repo), `boot.rs` | **read in full**; tests run |
| Device approval, lockout | W1.1 #549, W1.2 #564 | `device.rs`, `extractors/auth.rs`, `service.rs`, gRPC `user.rs`, `password.rs` | **read in full** |
| Token exchange actor | W1.5 #518 | `token_exchange.rs`, client-id generation | **read** |
| Grants, UserInfo, introspection | W1.6 #519, W1.9 #520 | `token.rs`, `honour.rs`, `authn_params.rs`, `fapi.rs`, `oauth2.rs`, gRPC `token.rs`/`userinfo.rs`, `token_ciba.rs`, `device_service.rs` | **read**; every `account_may_act` call site listed |
| `require_par`, authorize limiter | W1.13 #524, W1.10 #532 | `oauth2.rs`, `authorize.rs`, `rate_limit_shared.rs`, `rate_limit_counter.rs`, `rate_limit.rs` | **read**; every `browser_preset` caller listed |
| Client deletion | W1.4 #517 | `client_grants.rs`, `oauth2_clients.rs`, `dcr.rs`, `cleanup.rs` | **read** |
| SAML SP | W1.11 #531, W1.15 #530, follow-ups | `saml.rs`, `saml_metadata.rs`, `saml_idp/request.rs`, `federation.rs` (handler, repo), samael 0.0.22 `xmlsec` provider, `FederationPage.tsx` | **read in full** (verifier, metadata); parse sites listed |
| Threat model and docs | all | STRIDE, write-up, `Axiam.json`, website, PKI guide | entries named in the brief compared with the code (§9, §10) |

Not run: the REST integration suites for the wave (each needs an `axiam-api-rest`
build; the targeted crate tests in §11 cover the logic they pin), the frontend
suites (`frontend/node_modules` is absent), a real Vault, a multi-replica
deployment.

## 2. R1W1-01 — a tenant purge un-revokes certificates on the CRL

**Severity: Medium. Wave-introduced (the interaction of #523 and #565).
Proposed for a fix in the wave.**

**Resolution:** fixed in the wave by `fix(pki,tenants): a deleted tenant's
certificates are revoked and stay on the CRL until they expire (R1W1-01)` — the
deletion revokes every unexpired certificate and signing CA of the tenant
(services, then the tombstone transaction), and the purge keeps revoked,
unexpired rows until `notAfter` (the schema-scan test's one exemption).

**Evidence.**
* `crates/axiam-api-rest/src/handlers/tenants.rs:686-703` — the deletion revokes
  sessions and refresh tokens, then tombstones. No certificate and no tenant
  signing CA is revoked, in the request or in the tombstone transaction
  (`crates/axiam-db/src/repository/tenant.rs`, `delete`).
* `crates/axiam-db/src/repository/tenant_purge.rs:197-198` —
  `PurgeStep::by_tenant("certificate", Configuration)` and
  `PurgeStep::by_tenant("ca_certificate", Configuration)`: every row is
  deleted, revoked or not, expired or not.
* `crates/axiam-pki/src/crl.rs:319-320` — the list is
  `list_revoked_by_issuer(ca.id)` plus `list_revoked_children(ca.id)`, both read
  from those rows. A row that is gone is not on the list.
* **Probe (§11):** an organization root, a tenant leaf issued under it, the leaf
  revoked, the tenant deleted and purged through the repositories the server
  uses. The root's list held **1** entry before the deletion, **1** after the
  tombstone and **0** after the purge.

**Consequences.**
1. A leaf revoked before its tenant was deleted — a compromised device key, the
   reason the list exists — becomes valid again to every relying party that
   validates against the organization CA's list (FreeRADIUS, a VPN gateway, a
   peer service: T-102's whole audience) for the rest of its validity.
2. A revoked tenant signing CA leaves its parent's list the same way, so every
   leaf it signed chains again.
3. The tenant's still-active leaves and its tenant signing CAs are never
   revoked at all: deleting a tenant leaves its certificate population valid
   outside AXIAM until expiry. Before the wave the rows stayed (orphaned), so
   nothing was ever un-revoked; there was also no list.
4. A `vault_pki` leaf revoked but not yet forwarded (`vault_revoked_at = NONE`)
   is purged and never reaches Vault's list (T-470).
5. A purged leaf presented at the token endpoint is `NotIssuedHere`
   (`crates/axiam-oauth2/src/mtls.rs:536-541`), so its revocation no longer
   counts there either — relevant with R1W1-02.

**Proposed fix.**
* **Revoke at the tombstone.** In the tombstone transaction (or immediately
  before it, as for sessions), set `status = 'Revoked', revoked_at = revoked_at
  ?? time::now()` on every `certificate` and every `ca_certificate` with
  `tenant_id = $id`; forward `vault_pki` leaves as `CertService::revoke` does
  (the sweep picks up the rest).
* **Keep revocation evidence past the purge.** The purge must not delete a
  revoked certificate or CA row whose `not_after` is still in the future: either
  skip those rows (`DELETE certificate WHERE tenant_id = $id AND (status !=
  'Revoked' OR not_after <= time::now())`, likewise `ca_certificate`) and let a
  later sweep remove them once expired, or move them to an organization-scoped
  `revoked_certificate` table holding only `issuer_ca_id`, the PEM (or serial),
  `fingerprint`, `revoked_at`, `not_after` — no subject metadata, so GDPR is
  unaffected — which the two list reads also read. The purge-completeness test
  then needs an explicit exemption with the reason.
* **Text.** T-102 and T-472 say what happens to a deleted tenant's
  certificates; the PKI guide says deletion revokes them.
* **Tests.** The probe above as a test (the revoked leaf is still listed after
  the purge, and a live one is listed after the tombstone); a tenant CA revoked
  by the deletion is on its parent's list; a pending Vault forward survives the
  purge.

## 3. R1W1-02 — `tls_client_auth` accepts another organization's anchor

**Severity: High. Pre-existing (X5.1 with the per-organization trust-anchor flag,
T23-era); not introduced by W1, but on the path the wave's T-102 lookup changed.
Proposed for a decision now.**

**Resolution:** fixed in the wave by `fix(oauth2,tls): tls_client_auth accepts
only a certificate of the client's own organization (R1W1-02)` — the listener
carries the verified chain's fingerprints, an AXIAM-issued leaf must be the
client's tenant's, and any other must chain to a CA the client's organization
holds (T-475).

**Evidence.**
* `crates/axiam-oauth2/src/mtls.rs:340-430` — under `tls_client_auth` the only
  conditions are that the handshake built a chain to *some* configured anchor
  (`cert.trust.is_chained_to_anchor()`) and that the registered subject DN (or
  one SAN) equals the certificate's. Nothing compares the issuer with the
  client's tenant or organization.
* `crates/axiam-core/src/repository.rs:2813-2823` and the PKI guide ("Flagging a
  CA instead"): the listener's anchor set is every flagged CA **across all
  organizations**; `PUT /api/v1/organizations/{org_id}/ca-certificates/{id}/mtls-trust-anchor`
  (`crates/axiam-api-rest/src/handlers/ca_certificates.rs:523-560`) needs only
  `ca_certificates:manage` in the caller's own organization, and imposes no
  custody restriction, so an imported CA AXIAM holds no key for — whose key its
  importer keeps — can be flagged.
* `crates/axiam-oauth2/src/mtls.rs:536-566` — the new inventory lookup reads the
  certificate row (with its `tenant_id`) and the issuing CA row (with its
  `organization_id`) and answers `Active` without comparing either with the
  client.

**Consequence.** On a deployment that hosts more than one organization (the
multi-tenant shape AXIAM is built for), an administrator of organization X can
obtain a certificate whose subject equals the registered DN of a
`tls_client_auth` client of organization Y — by issuing an AXIAM leaf whose
common name is that DN's CN (AXIAM leaves carry a CN-only subject, so every
client using AXIAM-issued certificates registers a CN-only DN), or, with an
imported anchor, any DN or SAN at all — and authenticate at Y's token endpoint
as Y's client: client-credentials tokens with Y's client scopes, PAR, CIBA.
Device sign-in is not affected (it binds the fingerprint to a tenant's service
account).

**Proposed fix.**
1. **In the wave's lookup (small, closes the AXIAM-issued case).** Give
   `IssuedCertificateLookup::standing` the client (or its tenant and
   organization) and answer a new `IssuedElsewhere` when the certificate's
   `tenant_id` differs from the client's, or at least when its issuing CA's
   `organization_id` differs from the client's organization;
   `refuse_a_certificate_axiam_revoked` refuses it as `NotActive` is refused.
2. **For a certificate AXIAM did not issue.** Carry the anchor the handshake
   chained to on `VerifiedClientCert`/`PresentedCertificate` (the verifier knows
   which root it built to) and require, under `tls_client_auth`, that the anchor
   belong to the client's organization; or, without touching the verifier, find
   the leaf's issuer among the client's organization's CAs by its
   authority key identifier and verify the leaf's signature under it.
3. **Docs and model.** The PKI guide and T-263 say that `tls_client_auth` is
   bound to the client's organization's anchors; until (2) lands, that a DN or
   SAN must be unique across every organization that flags an anchor.
4. **Tests.** A leaf of organization X with a CN equal to organization Y's
   client DN is refused for Y's client (and accepted for an X client registered
   with it); an externally signed certificate chaining to X's flagged import is
   refused for Y's client.

## 4. The §7 rules, against what the wave added

| Rule | Verdict | Evidence |
|---|---|---|
| Every new route carries a limiter from its first commit | **holds** | `GET`/`HEAD /pki/v1/{org_id}/ca/{ca_id}/crl`: `build_governor(crl_per_min)` + `RateLimitShared("crl")` in `d3ea7ef` (`server.rs:651-661`, route at `:656`); the two `…/email-config/test` routes gained `email_test_org`/`email_test_tenant` buckets (`c22f644`); `/oauth2/authorize` gained `oauth2_authorize` on both mounts (`7700973`) |
| Every approval surface takes a console sign-in only | **holds** | `device.rs` `verify`/`decide` answer `403` on `minted_for_client()` before reading the code; `ciba_approval.rs` uses the same predicate. Every OAuth2 user-token mint site passes `client_id` (`token.rs:2056`, `token_ciba.rs:250`, `issue_access_token_for_client` callers); only login paths pass `None` |
| Credential-bearing outbound requests use `guarded_fetch_no_redirect` | **holds for what is tenant-chosen** | email HTTP providers (`egress.rs` `post`); the new Vault `revoke` is operator-configured and uses the Vault client, which follows redirects (R1W1-13) |
| Every refusal of a credential check costs one verify | **holds** | `service.rs:368-383` (lockout, under the permit, before the directory); gRPC `user.rs` refusals verify the dummy hash under the permit acquired before the branch |
| Two-writer registries are written conditionally on the version read | **not exercised** | no new two-writer registry; the Vault stamp is `vault_revoked_at ?? time::now()` (idempotent) |

## 5. W1.10 — the browser preset

`RateLimitShared::browser_preset` is called on exactly nine resources: the six
SAML IdP routes (which already used `end_session_per_min`), `/oauth2/authorize`,
`/oauth2/end_session` and `/oauth2/authorize/logout`. Every other bucket still
uses `new`/`new_client_aware` and `check_at` with the cold-entry seed, so **no
machine bucket was weakened**. The only effect of `check_at_human` is to skip
the pro-rata seed; the sliding-window carry still applies (pinned by
`a_browser_preset_key_still_carries_the_sliding_window`), so a key first seen at
second 59 gets 30 and then about none at second 61 — at most one window's
budget per sliding minute. The SAML metadata route is fetched by machines, not
people, but at 30 a minute per IP the change is immaterial.

## 6. Grants, tokens and the account

* **`actor_token` (T-471).** `actor_token_client` (`token_exchange.rs:89-95`)
  returns the `client_id` claim when present and the `sub` only for an
  `axiam:m2m` token without one. `client_id` values are generated server-side
  (`oa_…`) or are CIMD URLs, so a service account's UUID `sub` can never equal
  one; AXIAM tokens carry no `azp`, so "both `client_id` and `azp`" cannot
  arise; `sub_kind` is not consulted. Holds.
* **`account_may_act`.** Called at the code grant (`token.rs:1977`), refresh
  (`:2569`), REST introspection for both token kinds (`:3027`, `:3080`), REST
  UserInfo (`oauth2.rs:3658`), gRPC `IntrospectToken` and `GetUserInfo`, the
  session refresh (`service.rs:1209`), and (as `user_may_be_subject`) the CIBA
  redemption. Introspection checks only `sub_kind == User`, whose serde default
  is `User`, so a pre-claim token is still checked. **Missing at the device-grant
  redemption** (R1W1-06). gRPC `ValidateToken` and `CheckAccess` stay read-free,
  as T-39 says.
* **Refresh narrowing (#520).** `stored.scopes ∩ client.scopes`, in grant order
  (`token.rs:2587-2591`); used for the access token, the rotated refresh token,
  the ID token and the response. A registration that *gains* a scope adds
  nothing: the filter iterates the stored grant. `client.scopes` is a strict
  allow-list everywhere else (`authorize.rs:411`, `device_service.rs:170`), so
  an empty registration cannot mean "any". Holds.
* **`claims.id_token.sub`.** Parsed strictly (`authn_params.rs`
  `parse_claims_sub`); a valued `sub` is security-bearing (refused on `fapi2`,
  unreadable members included); on the honour lane a mismatch sends the browser
  to sign in on the first leg and is `login_required` /
  `account_selection_required` on the return leg or under `prompt=none`,
  compared case-sensitively. The ignore lane drops it, as D-12 decides for the
  other parameters.
* **`require_par` (#524).** The anonymous arm refuses `client.require_par &&
  request_uri.is_none()` before the `prompt=none` redirect and the login hop,
  with the non-redirecting `ParRequired` page; a browser with a session still
  reaches the service's own step 1b. A bogus `request_uri` still reaches the
  login hop and is refused on the return leg — the property #524 cares about
  (no redirect on an unpushed channel) holds.
* **Client deletion (#517).** Revoke, delete, revoke again on the admin path;
  delete then revoke on RFC 7592 (the delete is the credential check). Pending
  device grants and CIBA requests of the client are not voided; a CIMD client
  re-materialised within a device code's lifetime could redeem one. Folded into
  R1W1-12.

## 7. W1.8 and W1.12 — the email provider

* **Guard.** `axiam_pki::address` is the directory's guard moved, not copied;
  `canonical` folds IPv4-mapped IPv6, and `classify_v6` treats IPv4-compatible
  `::/96`, 6to4 and NAT64 forms by the IPv4 address they embed. Every resolved
  address must pass; the SMTP transport is built on the vetted IP literal
  (`builder_dangerous(address.ip())`), so `lettre` resolves nothing, and TLS is
  checked against the configured host. A DNS answer that changes between save
  and send is judged again at the send (`dns_rebinding_between_save_and_send_never_reaches_loopback`).
  The production policy carries the operator allow-list and both listener ports
  (`boot.rs:312`); `allowing_private_http_for_tests` has no production caller.
* **HTTP providers.** `guarded_fetch_no_redirect`, https only, pinned; the
  built-in endpoint constants are not checked, by design.
* **#525.** An omitted secret follows only the same host (case-insensitive),
  port and TLS mode, or the same `api_url` / the kind's own endpoint, and only
  within the same provider kind; an empty stored secret may follow. Holds.
* **Error shapes.** One sentence for a refused name, one for an unreachable
  provider; an SMTP server's own reply text is still returned for permanent and
  transient errors, which is the server the guard admitted.

## 8. W1.11 and W1.15 — the SAML SP

* **XSW.** With a metadata certificate configured, the root must be one
  `md:EntityDescriptor` whose `ID` occurs once in the document; the IdP
  receiver's `signature_placement` admits only the root's own enveloped
  signature with one reference to that ID; xmlsec verifies every signature, SHA-2
  only, and what is parsed is the **pre-digest** output, so nothing outside the
  signed bytes is read. Holds.
* **Cache poisoning.** Keyed by federation-config id and checked against the
  metadata URL and `updated_at`; every update bumps `updated_at`. No entry is
  shared across configurations or tenants; a refused document is never stored;
  an expired entry is never served.
* **DTD and encoding refusal.** Runs on the ACS text and on every metadata
  document before either parser; see R1W1-07 for the gap.
* **SHA-1 escape hatch.** Audited on the transition to `true` and at creation;
  see R1W1-08 for what it admits.
* **Null-clearing (`c404174`, `418e039`).** An explicit `null` now clears
  `metadata_url`, `idp_signing_cert_pem`, the OAuth2 endpoints, the Apple ids,
  `provider_slug`, `button_icon` and the metadata certificate. Clearing the
  assertion certificate or the metadata URL fails closed (`ConfigIncomplete`);
  clearing or replacing the metadata certificate is audited. The one
  security-relevant edit left unaudited is *replacing* the assertion
  certificate (R1W1-13).

## 9. Threat-model text against the code

| Entry | Verdict |
|---|---|
| T-447 (device approval) | true (`device.rs`) |
| T-469, T-30 | true (§4) |
| T-102 | true for a live tenant; **false after a tenant purge** (R1W1-01); "AXIAM's own `tls_client_auth` refuses a revoked leaf" true for leaves still in the inventory |
| T-470 | true, with R1W1-05's starvation and R1W1-01's purge loss unstated |
| T-471 | true |
| T-472 | "removes … its certificates and CA material" is true and is the problem (R1W1-01); "gone from every read and sign-in at once" holds for reads through the tenant repository, not for client authentication (R1W1-03) |
| T-473, T-300, T-301 | true |
| T-474, T-67, T-69 | true, with R1W1-07 and R1W1-08 as gaps in the "plainly UTF-8" and "SHA-1 escape hatch" wording |
| T-289, T-272 … T-280 | true (narrowing, client-deletion revocation) |
| T-160, T-39 | true; T-39 omits the device redemption (R1W1-06) |
| T-239, T-55 | true |
| T-118 (correction) | implies the purge destroys only exported rows; it does not (R1W1-04) |
| Open register (STRIDE §register, line 4597) | still lists T-470 as open with "1.0.x" advice although T-470 is Mitigated (R1W1-12) |

Totals: `Axiam.json` 2.38.0, `threatTop` 474, 434 Mitigated / 19 Open / 21 Not
applicable, matching the STRIDE document and the generated files. W2's branch
closes T-108 and T-117 against 2.37.0; the W3/W4 merge must reconcile the two
totals.

## 10. Documentation claims

| Claim (where) | Verdict |
|---|---|
| "a revocation is in the next response" (CRL module, T-102) | **true at the origin**; a shared cache may serve the earlier list until `nextUpdate` (R1W1-10) |
| "monotonic across replicas" CRL number (CRL module) | **true of issuance**; a replica's cached list can carry a lower number than one another replica already served (R1W1-10) |
| "the purge destroys nothing the operator does not hold a copy of" (`tenant_purge.rs` module doc) | **false** for rows after the export (R1W1-04) |
| "Every certificate AXIAM signs … carries a CRL distribution point" (PKI guide) | true when a base URL resolves; `vault_pki` leaves excepted, as said |
| "`tls_client_auth` refuses a leaf AXIAM revoked" (website `security.ts:475`) | true for leaves still in the inventory (R1W1-01 item 5) |

## 11. Checks run

Each command with its own exit code (logs in the scratchpad; `cargo clean` after
the last build).

| Check | Result |
|---|---|
| `cargo test -p axiam-pki --test crl_test` | pass (6) |
| `cargo test -p axiam-pki --test vault_pki_test` | pass (21) |
| **R1W1-01 probe** — a temporary `crates/axiam-pki/tests/zz_f4_probe.rs` (org root, tenant leaf, revoke, `TenantRepository::delete`, `purge_tombstoned`, `CrlService::current` at each step), run and deleted | entries **1 → 1 → 0** |
| `cargo test -p axiam-db --test tenant_purge_test --test client_grant_deletion_test` | pass (5, 2) |
| `cargo test -p axiam-db --lib every_tenant_scoped_table_is_purged` | pass |
| `cargo test -p axiam-email --test egress_test` | pass (7) |
| `cargo test -p axiam-oauth2 --lib mtls` | pass (36) |
| `node website/scripts/gen-threat-model.mjs` | 474 threats (434 / 19 / 21); no diff |
| XML-declaration handling (R1W1-07) | checked against the sandbox's libxml2 2.9.14 with `xmllint`: a non-UTF-8 declaration after a UTF-8 byte-order mark is honoured |
| Commit signatures | 24 of 24 carry `gpgsig` |

## 12. Issue bodies

### R1W1-01 (Medium) — a tenant purge un-revokes the tenant's certificates on its CA's revocation list

Deleting a tenant (#523) revokes its sessions and refresh tokens but none of its
certificates or tenant signing CAs, and the `tenant_purge` sweep then deletes
every `certificate` and `ca_certificate` row of the tenant
(`tenant_purge.rs:197-198`). The CRL (#565) is computed from those rows
(`crl.rs:319-320`), so a leaf revoked before the deletion disappears from the
organization CA's list after the purge (probe: 1 → 1 → 0 entries), a revoked
tenant CA disappears from its parent's list, every still-active leaf and tenant
CA stays valid to external relying parties until expiry, unforwarded `vault_pki`
revocations are lost (T-470), and a purged leaf is `NotIssuedHere` to the
`tls_client_auth` lookup. **Fix:** revoke every certificate and tenant CA of the
tenant at the tombstone (with `revoked_at`, forwarding to Vault); have the purge
keep revoked, unexpired certificate and CA rows (or move them to an
organization-scoped table with only issuer, PEM/serial, fingerprint,
`revoked_at`, `not_after`) until they expire, with an explicit exemption in the
purge-completeness test; amend T-102, T-472 and the PKI guide. **Tests:** the
revoked leaf is still listed after the purge; the tenant's active leaf and its
tenant CA are listed after the tombstone; a pending Vault forward survives.

### R1W1-02 (High) — `tls_client_auth` accepts a certificate chained to another organization's anchor

`tls_client_auth` (`mtls.rs:340-430`) requires only a chain to some anchor of
the deployment-wide listener and a DN/SAN equal to the registration. Any
organization administrator with `ca_certificates:manage` can flag a CA of their
organization — including a keyless import whose key they hold — as an anchor
(`ca_certificates.rs:523`). An administrator of organization X can therefore
present a certificate whose subject is a `tls_client_auth` client's DN in
organization Y and obtain that client's tokens. The #565 inventory lookup
(`mtls.rs:536-566`) reads the certificate's tenant and issuing CA but does not
compare them with the client. **Fix:** (1) pass the client to the lookup and
refuse an AXIAM-issued certificate whose tenant (at least whose issuing CA's
organization) is not the client's; (2) for a certificate AXIAM did not issue,
carry the anchor the handshake chained to and require it to belong to the
client's organization (or locate the leaf's issuer among that organization's
CAs by AKI and verify the leaf under it); (3) document that `tls_client_auth`
is bound to the client's organization's anchors and amend T-263. **Tests:** an
X leaf with Y's client CN is refused for Y's client; an external certificate
under X's flagged import is refused for Y's client; both accepted for an X
client registered with them.

### R1W1-03 (Low) — a tombstoned tenant's clients still authenticate

`TokenService::authenticate_client` (`token.rs:3160`) reads the client row,
which survives until the purge, and never the tenant. Minting paths refuse
(they read the tenant for `org_id`), but `bc-authorize` stores a request and
sends the user a notification mail, introspection reports the tenant's
unexpired access tokens `active`, revocation and PAR write rows, and anything
written after the purge passed its table leaves an orphan until the daily scan.
T-472 says the tenant leaves every read at once. **Fix:** refuse client
authentication for a tombstoned tenant (one cached tenant read in
`authenticate_client`, or delete/disable `oauth2_client`, webhooks, notification
rules and reactors in the tombstone transaction, as for the other act-for-tenant
rows). **Test:** after the `204`, `client_credentials`, `bc-authorize`,
introspection and PAR are `invalid_client`, and no mail is sent.

### R1W1-04 (Low) — the purge destroys audit rows no export covers

The deletion accepts an export receipt up to six hours old (T-118), and the
purge then deletes every `audit_log` row of the tenant (`tenant_purge.rs:179`),
including rows written after the export and between the deletion and the purge
(the deletion's own revocations, refused sign-ins, CIBA attempts). The module
documentation says the purge destroys nothing the operator lacks a copy of.
**Fix:** purge only rows created at or before the receipt's export time and
move later rows to the system log (tagged with the tenant id), or refuse the
deletion when rows newer than the receipt exist other than the receipt itself.
**Test:** a row written after the export survives the purge in the system log.

### R1W1-05 (Low) — the Vault revocation sweep can starve

`list_unforwarded_revocations` reads the oldest 100 unforwarded rows
(`certificate.rs:412`, `ORDER BY revoked_at LIMIT $limit`) and the pass tries
each once (`cert.rs` `forward_pending_revocations`). A row Vault refuses
permanently (an unknown serial on a `no_store` role, a mount since reconfigured)
is retried at every tick forever, and 100 of them keep every later revocation
from Vault's list. The cleanup job runs on every replica, so each tick costs N
calls per row. **Fix:** record `vault_forward_attempts`, `last_error` and a
`next_attempt_at` with backoff, order by `next_attempt_at`, and surface rows
past a threshold as a distinct job-health error; optionally a lease so one
replica runs the sweep.

### R1W1-06 (Low) — device-grant redemption does not ask `account_may_act`

`device_service.rs:333-339` re-reads the user and mints an access token, an ID
token and a refresh token without `account_may_act`, unlike the CIBA redemption
(`token_ciba.rs:201-212`) and every other grant. A user suspended between
approval and the device's next poll gets a fresh access token (the refresh is
then refused). **Fix:** apply `account_may_act` (and the lockout check CIBA
uses) before minting; `invalid_grant` otherwise. **Test:** approve, suspend,
poll → `invalid_grant`, nothing minted.

### R1W1-07 (Low) — the UTF-8 refusal does not see past a byte-order mark

`refuse_other_encodings` (`saml_idp/request.rs:292-314`) reads the XML
declaration only when the trimmed text starts with `<?xml`; `trim_start` does
not remove U+FEFF, so a document that begins with a byte-order mark skips the
check, and libxml2 (2.9.14 here) honours the encoding the declaration names, so
the byte-level markup-declaration scan and the parser no longer read the same
characters. Defence in depth (no external entity is loaded, and the signature
must still verify), but it is the guarantee T-67/T-69 and T-474 state. Three
libxml parse sites also use `Parser::default()` rather than the receiver's
options (`saml.rs:731`, `saml.rs:1022`, `saml_metadata.rs:270`). **Fix:** refuse
(or strip) a leading U+FEFF before both checks, or refuse any document whose
first non-whitespace character is not `<`; parse everywhere with the receiver's
options (`ignore_enc`, `encoding: UTF-8`, `no_net`, `no_def_dtd`). **Test:** a
BOM-prefixed document with a non-UTF-8 declaration is refused at the ACS, at the
metadata parse and at the IdP receiver.

### R1W1-08 (Low) — the SHA-1 escape hatch admits every algorithm

With `allow_sha1_signatures = true` the verifier passes `None`
(`saml.rs:752-753`), which samael reads as "no restriction": every signature
and digest algorithm the linked xmlsec verifies, not SHA-1 alone. **Fix:** pass
an explicit list — the SHA-2 set plus `rsa-sha1`/`ecdsa-sha1` with the SHA-1
digest (needs the variant in samael's `AllowedSignatureAlgorithm`, or a
pre-check on the `SignatureMethod`/`DigestMethod` URIs before calling it).
**Test:** with the flag on, an MD5-based signature is refused and an `rsa-sha1`
one verifies.

### R1W1-09 (Low) — the CRL route's lock and per-request read

`CrlService::current` takes one process-wide `Mutex` (`crl.rs:324`) and holds it
through the custodian `load` (a remote call for a non-database custodian), the
crypto-semaphore wait (shared with issuance) and the blocking signature, so one
slow re-sign stalls every CA's route, cached answers included. Every request,
unauthenticated, reads every revoked certificate's PEM of the CA (`:319-320`).
**Fix:** a per-CA single-flight (or drop the global lock before `load`); decide
"unchanged" from a light read (fingerprints and `revoked_at`, or a count plus
the latest `revoked_at`) and read PEMs only to sign.

### R1W1-10 (Informational) — CRL consistency across replicas and caches

Each replica signs and caches its own list: different bytes and `ETag`s for the
same state (a relying party behind a balancer gets `200`s instead of `304`s),
and a replica's cached list can carry a lower CRL number and earlier
`thisUpdate` than one another replica already served. `Cache-Control: public,
max-age` runs to `nextUpdate` (`handlers/crl.rs:101`), so an intermediary can
serve the pre-revocation list for up to a day although the origin re-signs at
once. **Fix:** derive the number deterministically (e.g. from the latest
`revoked_at` and the refresh epoch) or keep it in the datastore; a shorter
`max-age` with `ETag` revalidation; say so in T-102.

### R1W1-11 (Informational) — the distribution point is not the URL validated

`CrlDistribution::new` validates `url::Url::parse(trimmed)` but stores
`trimmed` (`crl.rs:174`); the parser removes tabs and newlines and
percent-encodes, so the URI written into certificates can differ from the one
checked. Operator configuration only. **Fix:** store the parsed URL's string
form (without a trailing slash).

### R1W1-12 (Informational) — text, tests and sweeps

(a) The STRIDE open register (`threat-model-stride.md:4597`) still describes
T-470 as open with "1.0.x" advice; T-470 is Mitigated. (b)
`tenant_issuer_paths_test.rs` `permissive_rate_limits` says the preset pro-rates
a late peer, which `b04c93e` changed. (c)
`a_revoked_leaf_is_refused_at_the_token_endpoint_under_tls_client_auth` drives
`TokenService::exchange`, not the route, and no test covers a certificate of
another tenant (R1W1-02). (d) The `tenant_purge` and `vault_revocation` sweeps
run on every replica: two replicas purging one tenant write two
`tenants.purged` rows or mark the job failed when the second finds the row gone.
(e) Deleting a client does not void its pending device grants and CIBA requests;
a CIMD client re-materialised within a device code's lifetime can redeem one.
**Fix:** correct (a) and (b); add the cross-tenant case to (c); treat "already
purged" as success in (d); void device grants and CIBA requests in
`ClientGrantStores::revoke` (e).

### R1W1-13 (Informational) — two unaudited or unguarded edges

(a) The Vault client (`vault_pki.rs:218`) follows redirects with the
`X-Vault-Token` header (reqwest strips only the standard credential headers on
a cross-host redirect); the new `revoke` call is one more credential-bearing
request through it. Operator-configured, so an exception to the §7 rule that
should be stated or closed (`redirect(Policy::none())`). (b) Replacing a SAML
configuration's assertion certificate (`idp_signing_cert_pem`) — the anchor of
every federated sign-in — writes no specific audit row, while replacing the
metadata certificate does. **Fix:** (a) no redirects, or document the exception;
(b) a `federation.assertion_signing_cert_changed` row on replacement.

## 13. Invariants

I1 (nothing registered today changes behaviour unless the wave says so) holds
for what was read: the behaviour changes are the documented ones — SHA-1
refused by default, a `localhost` SMTP relay refused, `/oauth2/authorize`
limited, a `require_par` request refused before the login hop, refresh grants
narrowed, deleted tenants' sessions revoked. No contract field was reviewed as
changed beyond the OpenAPI notes the wave lists (`403` on device approval, the
CRL route, `429` on authorize, the optional `client_id` at revoke and
introspect). This review changed no file but itself; the probe test was removed
before the commit.
