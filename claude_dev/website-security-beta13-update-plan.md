# Website — the 1.0.0-beta13 security and docs catch-up pass

> **Who this is for.** A fresh Claude session (Opus 5) tasked with bringing the
> website's **Security** section, and the **Docs**, **News** and **Roadmap**
> content the same releases touched, up to `1.0.0-beta13`. It is the entry point:
> read this, then work the waves in §4–§8. When the pass is done, add an
> **EXECUTED** blockquote at the top of this file in the style of
> [`website-security-beta11-update-plan.md`](website-security-beta11-update-plan.md),
> recording what landed, what was deliberately left, and the stamps.
>
> **The headline.** Two releases — beta12 and beta13 — carried the OpenID Connect
> **Basic OP** programme (waves W1–W9 of [`basic-op-gap-plan.md`](basic-op-gap-plan.md))
> and the first runs of the OpenID Foundation's conformance suite against a live
> AXIAM. The Threat Dragon model is at **2.12.0 — 266 threats, 249 mitigated /
> 17 open**, with a tenth element on the OAuth2 diagram; the generated files under
> `website/src/` still render **236 / 220 / 16**, the Security prose is at
> `1.0.0-beta11`, and `SECURITY_VERIFIED_RELEASE` says so. The OAuth2 Docs pages
> describe an authorization server that could not answer an anonymous browser,
> a UserInfo endpoint that answered only GET, and a refresh token that was
> refused on second use. This pass closes that gap.

**Sources of truth, in order.** [`threat-modeling-and-security.md`](threat-modeling-and-security.md)
(the website section's source, current as of 2026-09-12 — its handoff block
records what this wave changed and why), [`threat-model-stride.md`](threat-model-stride.md)
(the STRIDE model, mirroring the JSON), `ThreatDragonModels/Axiam/Axiam.json`
(the model the generator reads), and for the Docs pages the admin, compliance and
conformance documents named per item in §6. The website is the readable front
door; it links out for anything binding and **never carries a claim these
documents do not**.

---

## 1. What moved between beta11 and beta13

| Release | Security-relevant change | Threats |
|---|---|---|
| beta12 | The remediation pass R-1…R-7 (already mirrored by the beta11 website pass after its rebase — verify, do not redo) | T-234 closed; T-212, T-213, T-214, T-216, T-219, T-233, T-235 amended |
| beta12 | RFC 8705 §5 `mtls_endpoint_aliases` in discovery behind `AXIAM__AUTH__OAUTH2_MTLS_BASE_URL`; absent by default, front channel never aliased, unusable value fails discovery with `500`; contract 1.40 §21.3 rule 2 | T-245, T-266 |
| beta13 | **W1** per-client `authn_request_params: ignore \| honour` (default `ignore`) and `browser_sso` (default `false`), schema v54; the nine OIDC authentication-request parameters parsed totally and honoured by nobody; `request` → `request_not_supported`, non-PAR `request_uri` → `request_uri_not_supported`; every signed JWT header carries the JWKS `kid`; registration gates on `fapi2` | T-239, T-258 |
| beta13 | **W2** session authentication evidence — `authenticated_at`, `amr` (closed RFC 8176 enum), `auth_time`/`acr`/`amr` on the code, upstream `auth_time`/`AuthnInstant` for federated logins, copied across rotation; schema v55 | T-240 |
| beta13 | **W3** the browser login hop: `axiam_op_session` (`HttpOnly; Secure` unconditionally; `SameSite=Lax; Path=/oauth2/authorize`), `/login?return_to=` validated three times, loop guard, `reauth` mode, optional `tenant_id` on `/oauth2/authorize`; schema v56 | T-237, T-238 |
| beta13 | **W4** the honour lane: `prompt`, `max_age`, `acr_values` / `claims.id_token.acr`, `id_token_hint` honoured for `honour` clients, `acr` derived from evidence only, `max_age` with no leeway, `prompt=none` refused anonymous and on a return leg | T-239 |
| beta13 | **W5** `login_hint` (never looked up), `display` (allow-listed), `ui_locales` (server-side RFC 4647 match against five shipped locales), `claims_locales` (ignored); a typed i18n layer in the SPA, five locales, CI drift gate | T-257 |
| beta13 | **W6** `POST /oauth2/userinfo` (RFC 6750 §2.2 body carrier; two carriers refused; query never read); `POST /oauth2/authorize` declined with a revisit condition | T-243 |
| beta13 | **W7** `address` and `phone` scopes behind four gates re-asked at every UserInfo call; userinfo-only release; `sensitive_scopes_enabled` (org, disable-only); consent screen at `/consent` in five languages; Art. 7 self-service `GET /api/v1/account/consents`, `POST`/`DELETE …/oidc-scopes`; SCIM `phoneNumbers`/`addresses`; discovery `?tenant_id`; erasure and export name the new columns; schema v57; `gdpr-compliance.md` §3.1 | T-241, T-261 |
| beta13 | **W8** `client_secret_basic` accepted server-side, decoded per RFC 6749 §2.3.1, header kept out of logs, registration decides the channel; contract 1.41 (§5 rule 3 rationale only); `docs/admin/fapi2-profile.md` "accepted, and not recommended" | T-253, T-266 |
| beta13 | **W9 and the conformance runs** (2026-09-08, 09-10, 09-11): the identity cache laundering a bound token into a bearer one (**the hole**); ID token stripped of `tenant_id`/`org_id`/`email`; UserInfo emitting `email_verified`, the names, then the full §5.1 `profile` set; RFC 6749 §10.5 code-replay revocation reachable; FAPI 60-second code cap per client; PAR inline parameters ignored not refused; pushed `request_uri` refused; PAR errors as JSON; `private_key_jwt` wired (FAPI `aud` = issuer string only); `client_id` optional beside an assertion; DN compared against both correct renderings; `sid` on OAuth2 access tokens; discovery endpoint URLs carry the tenant (`AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID`); two RFC 8414 members; DPoP `dpop_jkt` binding (schema v58); DPoP `jti` single-use at resource endpoints; `htu` canonical comparison; `error_description` NQSCHAR; authorization errors by redirect when registered, HTML on explicit `Accept: text/html`; `claims` parameter honoured (`userinfo` member; schema v59); a Cancel that yields `access_denied`; refresh rotation **supersedes** with a 60-second grace | T-242, T-244, T-246…T-252, T-255, T-256, T-259; T-254 **open**; T-37, T-58, T-172 amended |
| beta13 | `self_signed_tls_client_auth` can complete a handshake: `AXIAM__SERVER__TLS__CLIENT_AUTH=optional_self_signed`, `CertTrust` carried to every consumer, device auth refuses a self-asserted certificate, `tls_client_auth` requires a chain | T-263; T-166 amended |
| beta13 | A Vault CA bundle that parses to no certificates is refused at startup, naming the file | T-264 |
| beta13 | Contended SurrealDB writes retried through `retry_on_write_conflict`; the v3 conflict phrasing recognised by the single-use consume guard; `DbError::Conflict` | T-262; T-163, T-164 amended |
| beta13 | Admin UI `redactSecrets` matches prefixed keys (`smtp_password`); the email panel's four error paths go through redaction; frontend coverage 96.6% | T-265 |
| beta13 | Three CodeQL alerts of one class — a credential in a derived `Debug` or a panic message — closed with redacting impls and compare-then-assert tests | T-260 |
| beta13 | Trivy filesystem scan scoped to what AXIAM ships (`benchmarks/`, `conformance/` excluded, stated) | T-236 amended |
| beta13 | Conformance receipts: `docs/conformance/` — four plans, 165 modules, zero `FAILED` on 2026-09-11; `REVIEW`/`WARNING` published, not counted as passes; not a submission | Compliance row |

Seven existing entries gained clauses: T-37, T-58, T-163, T-164, T-166, T-172,
T-236. The open register gains **T-254** (Medium, accepted trade-off) and loses
nothing, so it is 17. AXIAM's own request path still carries **no open Critical
or High** finding — keep that sentence, and keep the new sentence after it that
names T-254 as the one Medium.

## 2. Ground rules (unchanged; they are why the pass has value)

- **Do not upgrade the hedges.** "No open Critical or High finding *in AXIAM's
  own request path*", "self-assessment, not a certified audit", "a self-run
  against a working-tree build, not a certification", and the beta caution are
  all load-bearing. The conformance result is **zero `FAILED`**, not "passed"
  and not "certified": four `REVIEW`s on the Basic plan and ten on each FAPI
  plan are screenshot-evidence modules a human must judge, one `WARNING` per
  FAPI plan is a module that now runs where it used to be skipped, and
  `conformance-run` itself exits non-zero on them. Say exactly that.
- **Do not add claims.** Every sentence in `threat-modeling-and-security.md` is
  backed by code, a commit or a conformance receipt this pass verified. Copy its
  prose; do not improve it.
- **Keep the shared-responsibility section**, and keep the open register
  generated. T-254 is new there and is *AXIAM's* trade-off, not a deployment
  responsibility — it belongs under **Accepted, documented trade-offs**, where
  the source document put it, not under Platform & operations. The one new
  Integration bullet (audit ingress logs before `client_secret_basic`) *is* an
  integrator responsibility.
- **Mirror, do not paraphrase.** `src/security.ts` mirrors the Markdown section
  for section; the three bullets whose bold markers deliberately differ stay as
  they are, for the reason recorded in the handoff block.
- **Stamps record verification, not releases.** `SECURITY_VERIFIED_RELEASE`
  moves only with the Security section; `DOCS_VERIFIED_RELEASE` is one constant
  stamped on 30 pages, so bumping it re-asserts every one of them — §8 says what
  that costs.
- **The model's new element is not yours to draw around.** The OAuth2 diagram
  gained a process at model coordinates `(370, 640)` and two flows; the
  generator lays them out. If a label overlaps, adjust coordinates in the JSON
  and regenerate — never edit `threatModel.ts` by hand.

## 3. Current state (verified 2026-09-12, at beta13)

| What | Where | State |
|---|---|---|
| Security stamp | `website/src/version.ts` | `SECURITY_VERIFIED_RELEASE = "1.0.0-beta11"`, `SECURITY_VERIFIED_DATE = "2026-09-04"` |
| Docs stamp | `website/src/version.ts` | `DOCS_VERIFIED_RELEASE = "1.0.0-beta11"` |
| Generated model | `website/src/threatModel.ts`, `threatModelSummary.ts` | 236 threats / 220 / 16, model 2.11.0 — `node scripts/gen-threat-model.mjs` was run against 2.12.0 in this pass and printed `threatModel.ts: 9 diagrams, 266 threats (249 mitigated, 17 open)`, then **reverted** so the generated files and the prose move together |
| Security prose | `website/src/security.ts` | At beta11: nothing on the login hop, the honour lane, the sensitive scopes, `POST /oauth2/userinfo`, the conformance runs, the identity-cache hole, the resource-endpoint DPoP replay, the code-replay revocation, `client_secret_basic`, the self-signed listener policy, the grace window, or the Vault CA bundle |
| Contract anchors | `website/src/contractAnchors.ts` | `CONTRACT_VERSION = "1.39"` — behind `sdks/CONTRACT.md`, which moved to **1.42** (1.40 §21.3 rule 2; 1.41 §5 rule 3 rationale; 1.42 §21.5 discovery members); `gen:contract-anchors` will produce a diff |
| API index | `website/src/apiIndex.ts` | 213 operations / 148 paths — behind `sdks/openapi.json`, now **217 / 151**: `POST /oauth2/userinfo`, and the three consent paths `GET /api/v1/account/consents`, `POST`/`DELETE /api/v1/account/consents/oidc-scopes`, `DELETE …/oidc-scopes/{client_id}` |
| News | `website/src/data.ts` — post `beta-phase` ("AXIAM reaches beta") | Addendum dated 5 September 2026 says "236 threats, 220 mitigated and 16 open" |
| Roadmap | `website/src/data.ts` — phase 20 "Beta line — stabilisation toward 1.0" | `focus` ends at "Vault run as a production secret store"; nothing about Basic OP, conformance or FAPI |
| Docs pages already touched since beta11 | `configuration.ts` lists `AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID`, `AXIAM__AUTH__OAUTH2_MTLS_BASE_URL`, `AXIAM__AUTH__VAULT_CA_CERT_PATH` and `AXIAM__SERVER__TLS__CLIENT_AUTH` by name (the page carries every documented key, and the config-key-coverage gate keeps it so) — verify each row's description rather than rewriting it; `operate.ts` names `CLIENT_AUTH` and `VAULT_CA_CERT_PATH` in prose. `oauth2.ts` still lists `GET /oauth2/userinfo` only, says "single-use, rotating on every refresh", and says three times that inline parameters beside `request_uri` are refused | Everything else in §6 is new work |

The explorer (`src/components/ThreatModelExplorer.tsx`) needs no functional
change. The OAuth2 diagram is the one to open first in the built site: it has a
new node and two new flows, and it now carries 47 threats and one open item, so
the open-only filter on diagram 2 (`#/security/diagram/2`) must show exactly
T-254.

## 4. Wave 0 — regenerate

Run from `website/`, in this order, and commit the generated files together with
the prose that describes them (Wave 1), never alone:

```sh
npm run gen:threat-model     # expect: threatModel.ts: 9 diagrams, 266 threats (249 mitigated, 17 open)
npm run gen:api-index        # expect: POST /oauth2/userinfo, and the three consent paths — 217 operations / 151 paths
npm run gen:contract-anchors # expect: CONTRACT_VERSION 1.39 → 1.42, and the §21.3 / §21.5 anchors if the generator emits them
```

Read the `threatModel.ts` diff once: the OAuth2 diagram gains the process
`Resource-endpoint token validation (cnf, DPoP jti, sid)` at model coordinates
`(370, 640)` and two flows (`validate presented token`, from the resource-server
actor; `check session, record proof jti`, to the access/refresh token store).
The open register loses nothing and gains T-254. No generated file is
hand-edited.

## 5. Wave 1 — the Security section

Mirror `threat-modeling-and-security.md` into `src/security.ts`, section by
section. The table below is the checklist; the Markdown is the text.

| `security.ts` section | Change |
|---|---|
| Security at a glance | "STRIDE threat model of **266** threats"; the closing sentence gains "and run against the OpenID Foundation's conformance suite, with the receipts published green and red alike" |
| The threat model | Table: 266 threats, 249 / 17. Coverage by area, STRIDE category and severity are generated — confirm the page renders 266 / 17, OAuth2 47 / 1, and that the area rows match §Appendix A. The paragraph after the area table gains the T-254 sentence ("Its one open item is a Medium recorded as an accepted trade-off…") |
| Trust boundaries | The **Public Internet ↔ AXIAM** row's third column gains the OP-session-cookie clause. The assets table's **Refresh tokens & sessions** row reads "single-use rotation with a 60-second grace after rotation" |
| Authentication & sessions | The **Tokens** bullet's rotation sentence is replaced by the grace-clock sentence (three sentences, ending "…the ways to close it are decisions the register names") |
| OAuth2 & OpenID Connect | The intro paragraph gains the conformance-suite sentences (zero `FAILED`, self-run, `REVIEW`/`WARNING` not passes). The **Clients can authenticate without a copyable secret** bullet gains the `dpop_jkt`, self-signed-certificate and `mtls_endpoint_aliases` sentences. **Six new bullets** in this order: *A bound token is checked against this request, every time*; *Relying parties reach a sign-in page, and only the ones that opted in*; *A parameter AXIAM will not honour is refused, never silently dropped*; *Sensitive claims sit behind four gates, re-asked on every call*; *Discovery describes a tenant without enumerating tenants*; *Basic client authentication is accepted, and not recommended* |
| Federation (SAML & OIDC) | The **OIDC federation** bullet gains the upstream-`auth_time` sentence |
| PKI, certificates & device identity | The **mTLS device authentication** bullet gains the "certificate the listener admitted *without* a chain … is refused here outright" sentence |
| Transport, secrets & the SDKs | **Secrets at rest**: the redacting-`Debug` sentence gains the "including the three types this wave added…" clause and the Vault-CA-bundle clause. **The eleven client SDKs**: gains the alias and Basic-header sentences. One new bullet after it: **The admin UI redacts what a gateway echoes** |
| Compliance posture | The **GDPR** row's scope and status change (Art. 7 consent; explicit column lists). The **OAuth2 / OIDC** row changes substance: the OIDF suite named in scope, "165 suite modules, zero `FAILED` on 2026-09-11 — a self-run against a working-tree build, not a certification; `REVIEW` and `WARNING` verdicts are published, not counted as passes", and a third evidence link to `docs/conformance/README.md` |
| Shared responsibility | "17 of 266". The register is generated — confirm T-254 appears between T-143 and T-161. **Integration & SDKs** gains the *Audit what your ingress logs before registering a client for `client_secret_basic`* bullet. **Accepted, documented trade-offs** gains *A rotated refresh token stays redeemable for 60 seconds* |
| How security is maintained | New bullet **External suites are run, and their receipts kept**; closing sentence: last re-derived at **`1.0.0-beta13`** on 2026-09-12 |

Then `src/version.ts`: `SECURITY_VERIFIED_RELEASE = "1.0.0-beta13"`,
`SECURITY_VERIFIED_DATE = "2026-09-12"`. That constant is what the page quotes;
it moves in the same commit as the prose, never earlier.

## 6. Wave 2 — Docs pages the same releases changed

Each row names the page by slug, the claim to make, and the document the claim
comes from. Read the source before writing; the wording on the page should be
recognisably that document's, shortened. Two sources recur and should be opened
first: `docs/admin/browser-login-hop.md` and `docs/admin/oidc-authn-parameters.md`
(new at beta13), and `docs/admin/fapi2-profile.md`, which gained the
`client_secret_basic` and self-signed sections.

| Page (slug) | What to add or correct | Source |
|---|---|---|
| `oauth2` | **The endpoint table**: `/oauth2/userinfo` is `GET` *and* `POST` (header or, on POST only, form-body token; two carriers refused; query never read). **Token lifetimes table**: refresh token "single-use, rotating on every refresh" becomes "rotating on every refresh; the previous token stays redeemable for 60 seconds after rotation (FAPI 2.0 §5.3.2.1-9), then expires" — and link the open item T-254; authorization code "10 minutes" gains "60 seconds on a `fapi2` client". **The flow walkthrough**: a code used twice now revokes the session it minted (RFC 6749 §10.5), and the retry-after-lost-response cost is stated. **Tokens paragraph**: access tokens issued by the code and refresh grants carry `sid`, the same session the ID token names — a reset revokes them. **A new section, *Signing in from a relying party***: `browser_sso` per client (default off), what the three anonymous answers are, the `axiam_op_session` cookie's attributes and why `Lax`, `return_to` validation, the loop bound, `tenant_id` on the anonymous request; link `docs/admin/browser-login-hop.md`. **A new section, *Authentication-request parameters***: `authn_request_params` `ignore`/`honour`, what each of the five security-bearing parameters does on the honour lane, that `fapi2` refuses them, that request objects are rejected (`request_not_supported`, `request_uri_not_supported`), the four cosmetic parameters and that `login_hint` is never looked up; link `docs/admin/oidc-authn-parameters.md`. **A new section, *The `address` and `phone` scopes***: the four gates, userinfo-only, re-asked per call, the consent screen at `/consent`, the self-service consent endpoints, `sensitive_scopes_enabled`; link `docs/compliance/gdpr-compliance.md` §3.1. **Discovery**: optional `?tenant_id=`, endpoint URLs carry the tenant, `AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID` states a fact and changes no endpoint; `mtls_endpoint_aliases` when `AXIAM__AUTH__OAUTH2_MTLS_BASE_URL` is set; `claims_parameter_supported: true` and the `userinfo` member honoured. **Errors**: delivered by redirect with `state` when the client and `redirect_uri` are registered; a page only on `Accept: text/html`; `error_description` is ASCII (`§` becomes "section") | `docs/admin/browser-login-hop.md`; `docs/admin/oidc-authn-parameters.md`; `docs/compliance/oidc-conformance.md` rows 23–154; `docs/compliance/gdpr-compliance.md` §3.1; commits `cdfe000`, `318db2a`, `02b41cd`, `5de8df7`, `16d646a`, `065f37c`, `a76161b`, `b9232f3`, `49916b4`; T-237…T-244, T-249, T-250, T-254, T-255 |
| `fapi2` | **Client authentication**: `client_secret_basic` is a fifth method, accepted and not recommended, refused on `fapi2` exactly as `client_secret_post`; the registration decides the channel (body secret on a Basic client → `invalid_request`; Basic header on a post client ignored with a `warn`); AXIAM's SDKs never send it. **`private_key_jwt`**: now works (it was never wired), `aud` must be the issuer identifier as a string on a `fapi2` client — an array is refused even when it contains the issuer; `client_id` may be omitted beside the assertion. **`tls_client_auth`**: the registered DN may be either the `openssl -nameopt rfc2253` rendering or the encoded-order one — exact match against both. **`self_signed_tls_client_auth`**: needs `AXIAM__SERVER__TLS__CLIENT_AUTH=optional_self_signed` on the listener; what that policy admits and what it never admits (device auth, `tls_client_auth`). **DPoP**: `dpop_jkt` on PAR or the plain request, or a `DPoP` header on the PAR request; mismatch → `invalid_dpop_proof`; a code bound to a key the caller cannot prove → `invalid_grant`; proofs are single-use at the resource endpoints too; `htu` compared in canonical form. **Authorization code lifetime** capped at 60 s on `fapi2`. **Refresh rotation grace** of 60 s, required by §5.3.2.1-9, and why the profile can afford it. **Conformance**: link `docs/conformance/README.md` and state the 2026-09-11 result exactly as §2 words it | `docs/admin/fapi2-profile.md`; `docs/conformance/README.md`; commits `57016c9`, `fb7956f`, `62284e2`, `2d4cb59`, `246c163`, `4b737e7`, `28ffdcf`; T-247, T-251…T-254, T-263 |
| `par` | **The page is wrong on one point and says it three times**: "the server **refuses** a request that mixes inline parameters with `request_uri`" (the two-parameters callout and the `fapi2` paragraph, and the `require_par` sentence on the `fapi2` page). Since `a76161b` inline parameters beside a `request_uri` are **ignored**, not refused — RFC 9101 §6.3 says the server MUST only use the request object's parameters, and RFC 9126 §4 never said to refuse. Rewrite all three: "the server reads only the pushed copy; anything sent inline beside `request_uri` is ignored, so it cannot be confused with the pushed value" — and keep the security argument, which is unchanged. A `require_par` client that sends *no* `request_uri` is still refused. Then: a pushed `request_uri` is refused; PAR errors are JSON; `dpop_jkt` rides the pushed copy; a `request_uri` that expires during a login hop answers `invalid_request_uri` on the return leg | `a76161b`, `065f37c`, `246c163`, `cdfe000`; T-238, T-251, T-256 |
| `logout` | `end_session` also clears the OP session cookie; the `sid` sentence gains "and the access tokens the code and refresh grants issue carry the same `sid`" | `cdfe000`, `49916b4` |
| `auth` | The session-cookie paragraph: a fourth cookie, `axiam_op_session`, exists for the authorization endpoint only, `SameSite=Lax` by necessity, `Secure` unconditionally — the three API cookies stay `Strict`. Authentication evidence (`authenticated_at`, `amr`) is recorded at sign-in and copied across refresh | `cdfe000`, `b9f5cbf`, `97acce9`; T-237, T-240 |
| `federation` | One sentence: a federated login's `auth_time` is the provider's own instant, carried across the handoff, never AXIAM's clock | `97acce9`; T-240 |
| `scim` | `phoneNumbers` and `addresses` map onto the user (create, replace, patch); `remove` and an empty array erase them; provisioning them is not authorising their release — the OIDC gates decide that; the concurrent-PATCH write conflict is retried rather than returned as `500` | `16d646a`, `743786f`, `2d371ad`; T-261, T-262 |
| `settings` | Add `sensitive_scopes_enabled` (organization, **disable-only** for a tenant — the only such field) and `default_locale` (refused for a tag the build does not ship) to the settings rows | `16d646a`, `02b41cd`; T-241 |
| `configuration` | The four rows exist — **verify, then extend**: `AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID` (a fact in the discovery document; no endpoint behaviour changes; unparseable = unset); `AXIAM__AUTH__OAUTH2_MTLS_BASE_URL` (six aliases; unparseable fails discovery with `500`, deliberately unlike the default-tenant row); `AXIAM__SERVER__TLS__CLIENT_AUTH` gains the fourth value `optional_self_signed` and one sentence on what it admits and what it never admits; `AXIAM__AUTH__VAULT_CA_CERT_PATH` gains "a bundle that parses to no certificates fails startup naming the file" | `docs/deployment/README.md`; `docs/admin/fapi2-profile.md`; `db887d2`, `fbc33a2`, `2d4cb59`, `c38879a`; T-244, T-245, T-263, T-264 |
| `hardening`, `deploy` | The mTLS listener: `optional_self_signed` exists, is opt-in, and what stays byte-for-byte unchanged under the other three values; a two-listener topology (front channel on the issuer, back channel on the mTLS listener) is the documented shape for a separate mTLS host, published through `mtls_endpoint_aliases`; audit ingress header logging before `client_secret_basic` | `2d4cb59`, `fbc33a2`, `b918f46`; `docs/admin/fapi2-profile.md`; T-245, T-253, T-263 |
| `secrets` | One sentence under the Vault TLS rows: an empty, truncated or DER `VAULT_CA_CERT_PATH` bundle is refused at startup rather than silently trusting the public store | `c38879a`; T-264 |
| `troubleshooting` | Three new signatures: `401 "session revoked or expired"` at `/oauth2/userinfo` seconds after issuance on a pre-beta13 token (the `sid` fix; re-issue); `400 Query deserialize error: missing field tenant_id` when calling an endpoint at the URL a pre-beta13 discovery document published (set `OAUTH2_DEFAULT_TENANT_ID` or pass `?tenant_id=`); the self-signed mTLS client whose handshake dies with no HTTP status (`optional_self_signed`) | `49916b4`, `b9232f3`, `2d4cb59` |
| `compliance` | The OAuth2/OIDC row as in Wave 1, with the same hedges; the GDPR row gains Art. 7 and the explicit-column-list warning; link `docs/conformance/`. **Read the receipts, not the README's prose, for the numbers**: `docs/conformance/README.md` is hand-maintained and its narrative stops at the first run of 2026-09-08 (66 non-passing modules, one real assertion failure); the 2026-09-11 result is in `index.md` and the four dated `2026-09-11-*.md` reports (30/4/1/0, 26/10/1/0 twice, 44/10/1/1 — PASSED/REVIEW/SKIPPED or WARNING/FAILED) and in commit `92c7f05`. Do not describe the 09-08 run as current | `docs/conformance/index.md`, the `2026-09-11-*.md` reports, `docs/conformance/README.md` (method and hedges only); `docs/compliance/gdpr-compliance.md` §1–§3.1 |
| `sdks` | Contract 1.42: §21.3 rule 2 (prefer the mTLS alias; absence means no separate host), §5 rule 3's rationale, §21.5's two informative discovery members; no SDK code changed for any of the three | `sdks/CONTRACT.md`; T-266 |
| `errors` | `error_description` is `NQSCHAR` (RFC 6749 §5.2): ASCII only, `§` transliterated, never silently stripped; `invalid_dpop_proof` (400) for a missing proof where `invalid_client` (401) used to be answered; `login_required`, `consent_required`, `interaction_required`, `invalid_request_uri`, `request_not_supported`, `request_uri_not_supported` added | `52ded73`, `065f37c`, `900f0e3`, `cdfe000`, `318db2a` |
| `rest` | `POST /oauth2/userinfo` in any endpoint listing; the three consent endpoints under account self-service (no `user_id` parameter: consent is the subject's own, Art. 4(11)) | `1d55b0a`; `sdks/openapi.json` |
| `pki` | The mTLS listener paragraph: a self-asserted certificate is never a device identity, whatever policy the listener runs | `2d4cb59`; T-263 |

Pages **not** to touch for this pass: `opaque`, `mfa`, `passkeys`,
`service-accounts`, `device-flow`, `token-exchange`, `authz`, `rbac`,
`organization-scope`, `deny`, `uma`, `grpc`, `amqp`, `webhooks`, `reactors`,
`audit`, `observability`, `overview`, `quickstart`, `installation`, `bootstrap`,
`concepts`, `tutorial`. Re-read them in Wave 4; do not rewrite them in Wave 2.

## 7. Wave 3 — News and Roadmap

- **News.** Do not rewrite "AXIAM reaches beta" and do not touch its 5 September
  addendum; both were true when written. Add a **new post**, dated 12 September
  2026, tag `Release`, titled for the OpenID Connect Basic OP work — the
  conformance suite run for the first time, four plans, 165 modules, zero
  `FAILED`, receipts committed green and red alike, **not a certification**.
  One paragraph on what the Basic OP waves added (the login hop, the honour
  lane, the sensitive scopes, `client_secret_basic`, `POST /oauth2/userinfo`).
  One paragraph on what the suite found, naming the hole
  ([T-246](#/security/diagram/2/T-246)) and the resource-endpoint replay
  ([T-247](#/security/diagram/2/T-247)) plainly — the point of publishing
  receipts is that the reader learns it from us. One paragraph on the model:
  266 threats, 249 / 17, and that the one new open item is AXIAM's own
  trade-off ([T-254](#/security/diagram/2/T-254)), recorded rather than
  absorbed. Every anchor checked against the generated model. Keep the beta
  caution in the post's own words.
- **Roadmap.** Phase 20 stays `ongoing`. Extend its `focus` with "the OpenID
  Connect Basic OP surface and the first OpenID Foundation conformance runs".
  Do not close anything and do not add a phase; a certification submission is
  not on the roadmap until one is made.

## 8. Wave 4 — sweep and stamp

`DOCS_VERIFIED_RELEASE` is stamped on 30 pages through one constant, so bumping
it to `1.0.0-beta13` asserts that every one of them was re-read against beta13.
Either do that — the beta11 pass found four real errors this way — or leave the
constant at beta11 and say so in the EXECUTED note. Do not bump it because Wave
2 touched some pages.

Claims most likely to have gone stale, to check first on every page that carries
them: "userinfo is GET"; "a refresh token used twice is refused"; "the
authorization endpoint requires an access token / answers 401"; any list of
`token_endpoint_auth_methods_supported` that omits `client_secret_basic`; any
statement that request objects are unsupported without saying they are
*refused*; "the discovery document is deployment-wide" or "has no tenant"; any
count of threats, mitigated or open; the environment-variable tables; any
sentence saying the ID token carries `tenant_id` or `email`.

## 9. Verification

```sh
cd website
npm ci
npm run gen:threat-model && npm run gen:api-index && npm run gen:contract-anchors
git diff --stat                      # only the files this plan names
npm run build                        # tsc -b && vite build
npm run lint                         # oxlint
grep -rn "236 threats\|220 mitigated\|16 open\|beta11" src/ | grep -v threatModel.ts   # expect only the historical news addendum
cd .. && scripts/check-doc-links.sh
```

`docSectionsAreComplete()` in `website/src/docs/index.ts` asserts navigation and
content agree; the build runs it. Open `#/security/diagram/2` in the built site
with the open-only filter and confirm exactly T-254; open
`#/security/diagram/2/T-246` and confirm it selects the new node.

## 10. Out of scope

- Server work: the decision T-254 waits on (in-window reuse detection, or
  grace confined to sender-constrained clients) is the maintainer's, not this
  pass's. The website says the item is open and why.
- A conformance *submission*. The receipts are self-run; the website must not
  say or imply otherwise.
- The eleven SDK repositories' own documentation of contract 1.40–1.42.
- Threat Dragon diagram aesthetics beyond what the generator lays out.

---

## Appendix A — the numbers (model 2.12.0, 2026-09-12)

Headline: **266 threats, 249 mitigated / 17 open**, 9 diagrams, `threatTop` 266.

| Area | Threats | Open |
|---|---|---|
| System context | 31 | 2 |
| Authentication & session management | 33 | 1 |
| OAuth2 / OIDC authorization server | 47 | 1 |
| Federation (SAML SP & OIDC RP) | 31 | 1 |
| Authorization engine (RBAC, hierarchy, scopes) | 26 | 0 |
| PKI, certificates & IoT device identity | 25 | 1 |
| Audit, webhooks, email & notifications | 18 | 2 |
| Deployment & platform (Kubernetes) | 27 | 5 |
| Client SDKs & admin-UI integration surface | 28 | 4 |

By STRIDE category: Spoofing 66 (4 open), Tampering 57 (1), Repudiation 6 (0),
Information disclosure 65 (7), Denial of service 24 (2), Elevation of
privilege 48 (3). By severity: Critical 30 (1 open), High 122 (8), Medium 106
(7), Low 8 (1). The open items are T-148, T-18, T-94, T-124, T-133, T-135,
T-146, T-180, T-216, T-9, T-39, T-110, T-123, T-134, T-143, T-254, T-161. Every
one of these numbers is emitted by the generator; they are here so a wrong
regeneration is noticed, not so they can be typed in.

## Appendix B — the prompt for the session that executes this plan

> Read `claude_dev/website-security-beta13-update-plan.md` in the `ilpanich/axiam`
> repository and execute it, waves 0 to 4 in order, on a feature branch. The
> sources of truth are `claude_dev/threat-modeling-and-security.md` (mirror it
> into `website/src/security.ts` section by section), `claude_dev/threat-model-stride.md`
> and `ThreatDragonModels/Axiam/Axiam.json` (regenerate, never hand-edit the
> generated files), and the admin, compliance and conformance documents the plan
> names per Docs page. Do not add claims the source documents do not make, do not
> weaken the hedges the plan lists — the conformance result is "zero FAILED,
> self-run, not a certification", never "passed" or "certified" — keep the open
> risk register generated, and move `SECURITY_VERIFIED_RELEASE` to `1.0.0-beta13`
> only in the same commit as the Security prose. Bump `DOCS_VERIFIED_RELEASE`
> only if you re-read every stamped page. Verify with the commands in §9, then
> add the EXECUTED blockquote at the top of the plan recording what landed and
> what was left, and open a PR that references this plan.
