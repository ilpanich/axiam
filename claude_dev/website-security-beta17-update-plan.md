# Website — the beta16 + beta17 security and docs catch-up pass (model 2.17.0)

**Date:** 2026-09-25
**Validated against:** `axiam` main @ `80bc7aa` (PR #500, contract 1.52); every SDK repository at the head that vendors contract 1.52 (`scripts/check-sdk-artifact-drift.py`: 11 repositories, 0 problems)
**Executes on:** `main`, directly — one commit per wave, no pull request, no feature branch
**Model:** Opus 5
**Prerequisite:** [`threat-model-reconciliation-2026-09-25-plan.md`](threat-model-reconciliation-2026-09-25-plan.md) has been executed (its EXECUTED block exists and `gen-threat-model.mjs` prints 288). Do not start Wave 0 before it.
**Status: PLANNED.**

> **What this pass is, in one paragraph.** The website's Security section was
> last re-derived at `1.0.0-beta15` on 2026-09-15. Two releases' worth of
> security-relevant work has landed since and none of it is on the site:
> `1.0.0-beta16` (tagged 2026-09-19 — Phase 21, the MCP authorization
> surfaces, nine threats T-272 … T-280, the T21.8 security review and its four
> fixes, contracts 1.47 … 1.50, and a full re-sweep of the OpenID Foundation
> suite on 2026-09-18), and the unreleased Phase 22 dogfooding remediation
> that `1.0.0-beta17` will carry (S-1 … S-11 and the two console follow-ups,
> eight threats T-281 … T-288, contracts 1.51 and 1.52 with the eleven SDK
> ports and the eleven C-12 fix PRs). The Docs pages are in better shape —
> Phase 22 kept the pages its changes touched current, and T21.7 added the
> MCP block — but the beta16 OAuth2 surface (public clients, resource
> indicators, dynamic client registration, client ID metadata documents,
> per-tenant issuers) has one paragraph on the whole site, and one page still
> says a lost setup token cannot be re-minted. The maintainer tags
> `1.0.0-beta17` **after** this pass, from a head that contains it.

> **The stamp decision, made here rather than left to the session.** The
> previous passes stamped a release only if it was already tagged, and
> `main@<sha>` otherwise. This pass runs immediately *before* the tag, on the
> maintainer's stated sequence (docs, then tag), and every change it describes
> will be in `1.0.0-beta17`. So: stamp **`1.0.0-beta17`** for
> `SECURITY_VERIFIED_RELEASE` and, if Wave 4 earns it, `DOCS_VERIFIED_RELEASE`,
> and say in the EXECUTED note that the tag was pending at the time of writing
> and is expected on a head that carries the pass. Write every sentence about
> Phase 22 as "in `1.0.0-beta17`", never "on `main` since 2026-09-2x"; write
> every sentence about Phase 21 as "in `1.0.0-beta16`", which is simply true.
> One generated value cannot follow: `API_VERSION` in `apiIndex.ts` is read
> off `sdks/openapi.json`, which says `1.0.0-beta16` until the release-prep
> commit bumps it — accept `1.0.0-beta16` there, and tell the maintainer in
> the EXECUTED note that the beta17 release-prep commit must re-run
> `npm run gen:api-index` after bumping the spec (the beta16 release-prep
> commit did not, which is why the site's API index says beta15 today).

**Sources of truth, in order.** [`threat-modeling-and-security.md`](threat-modeling-and-security.md)
(the Security section's source — **its body sections do not yet carry either
wave**; the handoff block carries Phase 22 as one paragraph and Phase 21 not
at all, so this pass extends the source first, then mirrors it — see §5),
[`threat-model-stride.md`](threat-model-stride.md) (the STRIDE model; the
seventeen entries' full text is there, T-272 … T-288),
`ThreatDragonModels/Axiam/Axiam.json` (what the generator reads, 288 after the
prerequisite), [`security-review-mcp-2026-09-17.md`](security-review-mcp-2026-09-17.md)
(the T21.8 review — its §0 table is the wording for MCP-01 … MCP-06 and V1 … V3),
[`dogfooding-findings-fix-plan.md`](dogfooding-findings-fix-plan.md) (each
task's EXECUTED block says what actually shipped, which is not always what the
task said), `CHANGELOG.md` (`[1.0.0-beta16]` and `[Unreleased]`), and for the
Docs pages the documents named per row in §6. The website is the readable
front door; it links out for anything binding and **never carries a claim
these documents do not**.

---

## 1. What moved since the beta15 pass

### 1.1 `1.0.0-beta16` (tagged 2026-09-19 at `2617eae`) — Phase 21, the MCP authorization surfaces

| Landed | Security-relevant change | Threats |
|---|---|---|
| T21.1 | `GET /.well-known/oauth-authorization-server` — the RFC 8414 alias of the OIDC discovery document, same body, both root and per-tenant forms | — |
| T21.2 | **Public clients**: `token_endpoint_auth_method: "none"`, no secret ever minted, PKCE required, `client_secret` absent (never empty) on the creation response; contract 1.47. **Loopback redirect URIs accept any port** (RFC 8252 §7.3) and `http://[::1]/…` registers; the matcher widens a registration by a port and by nothing else (review V1) | **T-278** new |
| T21.3 | **RFC 8707 resource indicators** end to end: `resource` on authorize, PAR, token, device and exchange; the audience travels with the grant and cannot widen at refresh or exchange; `aud` in the introspection response; `allowed_resources` per client, and token exchange reads it | **T-277** new |
| T21.4 | **RFC 7591 dynamic client registration** at `POST /oauth2/register?tenant_id=`: off by default (`dynamic_registration: disabled`, a `403` shaped like every other refusal), `anonymous` or `initial_access_token` mode, registration tokens minted and listed at `/api/v1/oauth2-clients/registration-tokens` and single-use under concurrency (V3); a self-registered client cannot choose its own audiences (D3) and always gets a consent screen (D4); `managed_by` on every client (D5: `admin` / `dcr` / `cimd`); `dcr_max_clients`, `dcr_unused_client_ttl_days`, `AXIAM__RATE_LIMIT__DCR_PER_MIN` | **T-273**, **T-272** new |
| T21.5 | **Client ID metadata documents** (CIMD): a `client_id` that is an HTTPS URL is fetched, through the federation client's SSRF guard, only from a host the tenant's `cimd.trusted_client_id_domains` names; the fetched client becomes a `cimd` shadow row | **T-274**, **T-276**, **T-275** new |
| T21.6 | **Per-tenant path issuers** `{root}/t/{tenant_id}`, opt-in (`AXIAM__AUTH__TENANT_ISSUER_PATHS`); one key set signs every tenant, so a token minted for tenant A is refused on tenant B's path by an issuer and a path-binding check (V2) | **T-279** new |
| T21.8 | The security review: MCP-02 fixed in the task (`013903d` — the `axiam` scheme is reserved, so AXIAM's own audiences are not registrable as resources); **MCP-03, MCP-04, MCP-05, MCP-01 filed as #469 … #472 and closed the same day** in #475 / #476 (`0a273ec` no `*` in the trusted-publisher list; `0b216c6` CIMD rows bounded and swept; `c4d9ea2` a never-authorized registration reclaimed in an hour; `b8bc508` an error redirected to a loopback client's ephemeral port); MCP-06 accepted and pinned. Nine entries into the STRIDE document — and, until the prerequisite plan, into nothing else | T-272 … T-280; **T-272, T-275, T-276, T-280 closed** |
| T21.9 | **Contract 1.48 §28** — the MCP resource-server helpers (RFC 9728 document, `WWW-Authenticate` challenge, `resource_metadata_url`), TypeScript reference `axiam-typescript-sdk#110`, ten ports (rust #109, python #83, java #98, kotlin #65, csharp #91, php #70, go #81, swift #63, c #62, cplusplus #63), all merged; **1.49** the §28.11 cross-SDK review, no open row; **1.50** the DCR initial access token `Sensitive<T>` in every SDK | — |
| 2026-09-18 | **The OpenID Foundation suite re-swept as four full plans**: 165 modules, zero `FAILED` — 150 `PASSED`, 10 `REVIEW` (4 Basic, 2 per FAPI plan) with screenshot evidence published under `docs/conformance/evidence/2026-09-18/`, 3 `WARNING`, 2 `SKIPPED`. The beta15 hedge "eight modules pass individually, not yet re-swept as a plan" is **discharged** — they are in the sweep. Still a self-run, still not a certification | — |
| 2026-09-18 | Dependency update (`8fc27c2`), with the audit gate catching its own stale `rkyv` suppression (`d30c1df`) — the "fails on a suppression that no longer matches anything" sentence exercised again | — |

### 1.2 Unreleased — Phase 22, the dogfooding remediation (`1.0.0-beta17`)

| Task | Security-relevant change | Threats |
|---|---|---|
| S-1 (T22.1) | **A signing CA issues only for the tenant it signs for.** `prepare_leaf_issuance` never read the CA row's `tenant_id`, so a tenant administrator could issue under another tenant's CA, or directly under the organization anchor; a foreign CA is now a `404` ahead of the status checks. T-98's mitigation had claimed the binding since alpha44 and is corrected in place | **T-281** new; T-98 corrected |
| S-2 (T22.2) | **The device mTLS login is rate-limited**: `POST /api/v1/auth/device` had no governor at all; `AXIAM__RATE_LIMIT__DEVICE_LOGIN_PER_MIN`, default 60 per IP, machine family | **T-282** new |
| S-3 (T22.3) | **Device tokens carry `cnf.x5t#S256`** and are enforced against the presenting certificate on REST and gRPC; no enforcement code changed because both surfaces already refused a mismatched `cnf` | **T-283** new |
| S-4 (T22.4) | An unbound, untrusted or unknown certificate at the device login is a **`401`**, not a `403`, and the string match on the error message is gone | — |
| S-5 (T22.9) | Docs corrections: device certificates **require** the bind (the guide said the opposite — DF-002); RSA-4096 CA generation works under every custodian (the guide said it failed — DF-015); RabbitMQ auth-backend caveats; the AMQP TLS ordering constraint | — |
| S-6a (T22.5) | Four documented secret variables were read by nothing: the env provider resolves every secret to `AXIAM__AUTH__<NAME>`; docs, messages and the OpenAPI descriptions now say so, and a startup warning names a legacy spelling | — |
| S-6b (T22.6) | `subject` is a common name; one `CN=` prefix is understood and stripped, on every CA and leaf path | — |
| S-6c (T22.7) | `axiam-server setup-token --remint`, refused with exit 2 on any deployment that has a user or a redeemed token | **T-284** new |
| S-6d (T22.8) | `axiam-server healthcheck` probes a TLS listener: derived default, `AXIAM_HEALTHCHECK_*` (single underscore), an optional CA file, **no switch that skips verification** | — |
| S-7 / S-7b (T22.14/b) | **`Server` certificates**, `subject_alt_names`, the organization's `server_cert_allowed_names` fence (empty by default, tighten-only, intersection on every read), a per-type `keyUsage` / `extendedKeyUsage` profile on every leaf; Vault `sign_csr` of a `Server` CSR refused by design; console dialogs and the Server Certificate Names card; `nameConstraints` deferred (D-7) | **T-288** new |
| S-8 (T22.12) | **Client-certificate verification on the gRPC listener**: `AXIAM__GRPC_TLS_CLIENT_AUTH` (`off` / `optional` / `required`) and `AXIAM__GRPC_TLS_CLIENT_CA_PATH`, the REST listener's reloadable verifier installed on gRPC as a second instance fed by the same reload, seven misconfigurations refuse to boot | **T-286** new; T-234, T-283 amended |
| S-9 (T22.13) | **Service accounts on the management routes**: eight families (D-5), authorized by their own roles, `403` without one; the audit log tells a machine's write from a person's; four latent extractor gaps closed | **T-287** new |
| S-10 / S-10b (T22.11/b) | **`inherit: false`** on a role assignment, refused where the engine would ignore it, changeable only by unassign-and-assign; the console's *Also applies to the resource's descendants* and the global-role confirmation | **T-285** new; T-16, T-87 amended |
| S-11 (T22.10) | The console's nginx resolves `AXIAM_BACKEND_ORIGIN` per request (30 s cache) instead of three literal `proxy_pass` targets at startup | — |
| C-0 … C-12 | **Contract 1.51** (PR H): `authenticate_device()` in §6.1 with the certificate-bound token, the acting-tenant helper `X-Axiam-Tenant` a SHOULD (REST only), §1.1.1 `TokenService` wrappers reading `cnf`, §27.6.1 manifest bindings, §27.13 DTO changes; Rust reference `axiam-rust-sdk#115`, ten ports (typescript #116, python #88, java #102, csharp #95, php #73, go #86, kotlin #68, swift #66, c #65, cplusplus #66) plus two SSO-gate follow-ups (typescript #117, go #87); **contract 1.52** (PR #500): the C-12 review, six clarifications N1 … N6, no wire change, §27.14 with 37 divergences and none open, **one fix PR per SDK** (rust #116, typescript #119, python #90, java #103, kotlin #69, csharp #97, php #75, go #88, swift #67, c #66, cplusplus #68) and one re-vendor PR per SDK, all merged; drift check 0. What every SDK had: the device credential outlived a later login or logout (eight), a device token entered the refresh guard (six), tenant IDs compared as strings (six) | T-210, T-235 (verify their text still holds; amend only if the source does) |

The open register neither gains nor loses. Appendix A is what the generator
must print.

## 2. Ground rules

- **Do not upgrade the hedges.** "No open finding at all *in AXIAM's own
  request path*" (still true: OAuth2 0 open after the reconciliation),
  "self-assessment, not a certified audit", and the beta caution are
  load-bearing. **The conformance sentence changes, and it changes in one
  direction only:** the 2026-09-18 sweep supersedes the 2026-09-11 one and
  discharges the per-module hedge, so say "165 modules, zero `FAILED` on
  2026-09-18, four full plans" — and keep "a self-run against a working-tree
  build, not a certification; `REVIEW` and `WARNING` verdicts are published,
  not counted as passes". Never "certified", never "passes the suite".
- **Do not add claims.** Every sentence must be backed by a task's EXECUTED
  block, a commit, a merged PR, the STRIDE entry or a conformance receipt.
  Three things are easy to overstate here — do not: (a) the k8s console
  finding (§13 row 5 of the dogfooding plan) is **unobserved** and is not on
  the site; (b) `nameConstraints` in tenant CAs is **deferred** (D-7), the
  fence is AXIAM-side; (c) a Vault-custody `Server` certificate is issued by
  `POST /certificates` only; the CSR path is refused there by design.
- **Corrections are stated as corrections.** Three previous claims were wrong
  and the site carried two of them: device certificates "are not bound to
  anything" (fixed on the `pki` page by S-5; say it was wrong before
  `1.0.0-beta16`), RSA-4096 CA generation "fails" (never on the site;
  verify), and "there is no way to re-read or re-mint" the setup token
  (**still on the `bootstrap` page today** — line 422 of
  `getting-started.ts`; now false). T-98's correction is in the model.
- **Extend the source before mirroring.** Every earlier pass could say "every
  sentence is already in the source". This one cannot: Wave 1a writes the
  body prose for both waves into `threat-modeling-and-security.md`, from the
  STRIDE entries and the EXECUTED blocks, in the document's own register
  (one bold lead per control, the mechanism, then the residual). Wave 1b
  mirrors. The handoff block gets a new status line and a Phase 21
  paragraph it never had.
- **Keep the shared-responsibility section, and keep the open register
  generated.** T-39, T-110, T-143 and T-254 do not appear in it; nothing
  from either wave does either.
- **Mirror, do not paraphrase.** `src/security.ts` mirrors the Markdown
  section for section; the four bullets whose bold markers deliberately
  differ stay as they are, for the reason recorded in the handoff block.
- **Stamps record verification.** `SECURITY_VERIFIED_RELEASE` moves in the
  same commit as the Security prose and the generated files, never earlier;
  `DOCS_VERIFIED_RELEASE` is stamped on 29 pages and moves only after Wave 4.
- **Elements moved this time, by design.** The reconciliation adds four
  elements and four flows to diagram 2. Wave 0's diff must show exactly
  those and nothing else moving; the generated summary must match Appendix A.

## 3. Current state (verified 2026-09-25)

| What | Where | State |
|---|---|---|
| Security stamp | `website/src/version.ts` | `SECURITY_VERIFIED_RELEASE = "1.0.0-beta15"`, `SECURITY_VERIFIED_DATE = "2026-09-15"` — correct for what the section says today |
| Docs stamp | `website/src/version.ts` | `DOCS_VERIFIED_RELEASE = "1.0.0-beta15"`, on 29 of 41 pages via `DocPage.verifiedRelease` |
| Generated model | `threatModel.ts`, `threatModelSummary.ts` | **271 / 258 / 13, model 2.16.0** — two waves behind. After the prerequisite the generator prints 288 / 275 / 13 |
| Security prose | `security.ts` | At beta15. Missing everything in §1 |
| Contract anchors | `contractAnchors.ts` | **Current**: `CONTRACT_VERSION = "1.52"`, 184 sections — regenerated by PR #500. `gen:contract-anchors` produces no diff |
| API index | `apiIndex.ts` | **Stale**: `API_VERSION = "1.0.0-beta15"`, 222 operations / 156 paths. The generator prints `229 operations across 162 paths, 11 domains` and `1.0.0-beta16` (a 46-line diff: `/oauth2/register`, the registration tokens, the RFC 8414 alias, the `/t/{tenant_id}` forms, `setup-token`-adjacent nothing — read it) |
| News | `data.ts` | Latest post 15 September 2026 (beta15). **No post for beta16**, which was tagged 2026-09-19 |
| Roadmap | `data.ts` — phase 20 | `focus` ends at "…refusing a request that cannot succeed before anyone signs in for it"; nothing about MCP or the dogfooding wave |
| Docs pages already current for Phase 22 | `authorization.ts` (`inherit: false` prose and three precedence rows), `configuration.ts` (the two gRPC client-auth keys, `DEVICE_LOGIN_PER_MIN`, the `AXIAM__AUTH__<KEY>` rule and three renamed rows), `operate.ts` `pki` (the bind for devices stated as a correction, `subject` as a CN, Server certificates, the fence, the usage-profile table), `authentication.ts` `service-accounts` (the bind note; the management-families paragraph), `integrate.ts` (two renamed variables), `reference.ts` `sdks` (rows 1.47 … 1.52, the "thirteen amendments" paragraph). **Verify, then extend**; do not rewrite |
| Docs pages current for Phase 21 | `oauth2.ts` — the *MCP servers* block (T21.7) and the two links; `configuration.ts` — `AXIAM__AUTH__TENANT_ISSUER_PATHS`, `AXIAM__RATE_LIMIT__DCR_PER_MIN`; `reference.ts` `sdks` — the 1.47 … 1.50 rows. **Nothing on the site says "dynamic client registration", "CIMD", "public client" or "resource indicator" outside those** |
| Stale sentence on the site | `getting-started.ts:422` (`bootstrap`) | "there is no way to re-read or re-mint it" — false since T22.7 |
| Stale numbers on the site | `reference.ts` `compliance` (table "Plan (2026-09-11)"), `oauth2.ts:730`, `security.ts:319` and `:496` | the 2026-09-11 run; the 2026-09-18 sweep supersedes it |

The explorer (`src/components/ThreatModelExplorer.tsx`) needs no functional
change. After Wave 0 open `#/security/diagram/2/T-273` and confirm it selects
the new `/oauth2/register` node and renders Mitigated; `/2/T-279` the
per-tenant path issuers node; `/2/T-275` the store; `/2/T-278` the authorize
node (now eleven threats); `/5/T-281`, `/5/T-288` the certificate-issuance
process (seven → nine threats); `/5/T-282`, `/5/T-283` the mTLS device-auth
process; `/4/T-285` the RBAC engine; `/7/T-284` the deployment; `/0/T-286` the
gRPC API and `/0/T-287` the REST API on the system diagram. The open-only
filter on diagrams 1, 2 and 4 must be **empty**.

## 4. Wave 0 — regenerate

Only after the prerequisite plan's EXECUTED block exists. From `website/`, in
this order; commit the generated files together with Wave 1's prose, never
alone:

```sh
npm run gen:threat-model     # expect: threatModel.ts: 9 diagrams, 288 threats (275 mitigated, 13 open)
npm run gen:api-index        # expect: apiIndex.ts: 229 operations across 162 paths, 11 domains — API_VERSION "1.0.0-beta16" (see §0)
npm run gen:contract-anchors # expect: contractAnchors.ts: 184 sections at contract 1.52 — and no diff
```

Read the `threatModel.ts` diff once: on diagram 2, four new nodes and four
new flows, nine threats (two on existing nodes); on diagrams 0, 4, 5 and 7,
eight threats on existing nodes; **no existing node or flow coordinate
changed** (a boundary box's size may have); the open register byte-identical
to what the site renders today. The summary must match Appendix A row for
row. No generated file is hand-edited.

## 5. Wave 1 — the Security section

### 5.1 Wave 1a — extend the source, `threat-modeling-and-security.md`

The body sections carry one Phase 22 clause (the `inherit: false` clause in
the RBAC bullet) and no Phase 21 material. Write the following, in the
document's register, from the STRIDE entries' text and the EXECUTED blocks —
the entries are already prose; do not invent mechanism the entry does not
name. Then update the handoff block: a new status line ("source current as
of 2026-09-2x, `main` before `1.0.0-beta17`, model 2.17.0 — the Phase 21 MCP
wave of `1.0.0-beta16` and the Phase 22 dogfooding wave"), a Phase 21
paragraph in the style of the existing wave paragraphs (nine threats, four
new elements, the review, the four same-day closures, the 2026-09-18 sweep),
and the conformance sentences in the existing paragraphs moved to
2026-09-18.

| Section | Change |
|---|---|
| Opening ("The system is verified against a **STRIDE threat model of 288 threats**") | Already 288. Verify |
| The threat model, coverage tables | Corrected by the prerequisite. Verify against Appendix A |
| Authentication & sessions | **Rate limits are sized by what an operation costs** gains T-282: the device login was the one auth resource with no governor while its happy path completes a client-certificate handshake; `DEVICE_LOGIN_PER_MIN`, 60 per IP, machine family, scaled by the posture presets |
| Authorization & tenant isolation | **The authorization engine is RBAC…** — the `inherit: false` clause is there; extend with T-285's three conditions (read in the one shared function and in both SELECTs; refused with `400` on a tenant-wide assignment and on a global role; changeable only by unassign-and-assign, both flushing the cache; `false` on a deny re-opens every descendant, which the console makes a confirmed act). **New bullet**, after *Three protocols, one engine*: *Automation authenticates as itself on the management API* — T-287: no management route accepted a service-account token, so provisioning automation held a human administrator's password with all that person's roles; eight families now admit a service account (D-5, name them: resources, scopes, permissions, roles and assignments, groups, service accounts, certificates, webhooks) authorized by its own roles and refused `403` without one; everything else keeps a human audience until argued family by family; a registry sweep and an OpenAPI walk pin both directions; the four latent extractor gaps (the exchanged user token accepted as a machine with no session, the session id read from the wrong claim — say what the entry says); the audit log tells a machine's write from a person's |
| OAuth2 & OpenID Connect | The intro paragraph's conformance sentence → 2026-09-18 (§1.1 row). **Four new bullets**, after *Machine tokens and user tokens are not interchangeable*: (1) *Public clients hold no secret, and a loopback redirect is widened by a port and by nothing else* — T-278, V1, `[::1]`, PKCE required, and T-280 closed: an error raised before the redirect matcher is still redirected to the ephemeral port (MCP-01, `b8bc508`). (2) *A token is addressed at the resource that will receive it* — RFC 8707, the audience travels with the grant and cannot widen, `aud` in introspection, `allowed_resources`; T-277 and MCP-02: the `axiam` scheme reserved so AXIAM's own audiences are not registrable as resources. (3) *Clients nobody registered in advance are admitted on the tenant's terms* — DCR off by default with a `403` shaped like every refusal; `anonymous` vs `initial_access_token`, the token single-use under concurrency (V3); the quota, the per-IP limit, the anchored host glob; a self-registered client cannot choose its audiences (D3) and always sees consent (D4); `managed_by`; T-273, and T-272 closed (`c4d9ea2`: a never-authorized registration reclaimed in an hour, with the entry's two stated residuals kept as residuals). CIMD in the same bullet or a fourth: the fetch through the federation client's SSRF guard (T-274; SEC-094 closed on the path CIMD uses), only from a trusted publisher, and T-276 closed (`0a273ec`: `*` refused); shadow rows bounded and swept, T-275 closed (`0b216c6`). (4) *A tenant can have an issuer of its own, and one key set still cannot cross tenants* — T-279, V2 (`enforce_issuer`, `enforce_tenant_path_binding`), the RFC 8414 alias, MCP-06 accepted and pinned |
| Federation | Unchanged |
| PKI, certificates & device identity | The first bullet (leaf issuance) gains **three** things, or three new bullets — the section is short enough that new bullets read better: *A signing CA issues only for the tenant it signs for* (T-281: the row's `tenant_id` read ahead of the status checks, a foreign CA a `404` so an outsider cannot distinguish "no such CA", and T-98's claim corrected rather than deleted — say so); *A certificate says what it is for, and a server certificate names only what the tenant may name* (T-288: `Server`, `subject_alt_names`, the fence empty by default, tighten-only, intersection, every SAN and the CN admitted, the `clientAuth` / `serverAuth` profile on every leaf so a server certificate never authenticates as a client, a rustls client trusting only the root accepting the leaf for its name and no other; D-7 deferred; the Vault CSR refusal; `subject` is a CN). **mTLS device authentication verifies the full chain** gains: the bind is required for `Device` certificates and the guide said the opposite (DF-002, corrected 2026-09-22); an unbound or unknown certificate is a `401`; and *A device's token is as strong as its handshake* (T-283: `cnf.x5t#S256` minted on the device path — the one mint site that omitted it while OAuth2 mTLS clients had it — enforced on REST and on gRPC against the certificate rustls verified, no enforcement code changed, a token minted before carries no `cnf` and is accepted as before until it expires). One sentence in the CA-custody bullet: RSA-4096 generation under every custodian, the guide's contrary claim corrected (DF-015) |
| Audit & accountability | One sentence in **Retention** or a new short bullet: the audit log now records whether a management write was a person's or a machine's (from S-9), if the source's Phase 22 paragraph says so — it does; copy it |
| Webhooks, email & messaging | Unchanged |
| Transport, secrets & the SDKs | **New bullet** after *The backend can sit on the public origin*: *The gRPC listener can verify client certificates* (T-286: `with_no_client_auth()` with no setting could change it, a deferral from T-234, while `ReactorAdminService` joined `CheckAccess` on the listener; `off` / `optional` / `required`, the REST verifier as a second instance fed by the same reload, seven misconfigurations refuse to boot including client auth on a plaintext listener, `off` proved to be the old handshake; T-234 amended). **Long-lived secrets come from a pluggable secret provider** gains T22.5: the env provider resolves every secret to `AXIAM__AUTH__<NAME>`, four documented names were read by nothing, and a startup warning now names a legacy spelling — stated as a correction. **Secrets at rest** or the bootstrap sentence gains T-284: only the hash is stored, `setup-token --remint` refused with exit 2 on any deployment with a user or a redeemed token, and why re-minting after bootstrap is never the answer. One sentence for S-6d: the healthcheck probes a TLS listener with no switch that skips verification; one for S-11: the console resolves its backend per request. **The eleven client SDKs conform to one cross-language contract** gains the contract 1.47 … 1.52 sentence (§1 rows): §28 helpers in all eleven; the `Sensitive` initial access token; 1.51 ported in all eleven with the certificate-bound `authenticate_device()`, the acting-tenant header sent when set and absent when not, and the gRPC wrappers reading `cnf`; 1.52's review and the eleven fix PRs — say what every SDK had (the three classes), because it is the honest half |
| Compliance posture | The **OAuth2 / OIDC** row: replace "165 suite modules, zero `FAILED` on 2026-09-11 … since 2026-09-14 eight further modules pass when run individually … not yet re-swept as a plan" with the 2026-09-18 sweep: 165 modules, zero `FAILED`, 150 `PASSED`, 10 `REVIEW` with published evidence, 3 `WARNING`, 2 `SKIPPED`; the hedge stays. The dependency paragraph: one sentence for the 2026-09-18 update and the stale-suppression catch, if the source paragraph's "the gate has been exercised" sentence is where that belongs — it is |
| Shared responsibility | "**13** of 288". Register generated and unchanged. No new bullet in any group — neither wave adds an open item |
| How security is maintained | Closing sentence: last re-derived at `1.0.0-beta17` (model 2.17.0) on the pass date |

### 5.2 Wave 1b — mirror into `website/src/security.ts`

Section by section, the same rows as 5.1, in the same order. Also:

- `security.ts:319` (the OAuth2 intro): the conformance sentence → 2026-09-18.
- `security.ts:437` (the SDK bullet): append the contract sentence; do not
  restate the 1.45/1.46 history it already carries.
- `security.ts:496` (the compliance row) and the dependency paragraph.
- `src/version.ts`: `SECURITY_VERIFIED_RELEASE = "1.0.0-beta17"`,
  `SECURITY_VERIFIED_DATE` the date of this pass. Same commit as the prose
  and the Wave 0 files.

## 6. Wave 2 — Docs pages

Open the sources first: `CHANGELOG.md` (`[1.0.0-beta16]` *Added*, *Changed*,
*Fixed*, *Security*; `[Unreleased]` all five headings), `docs/api/README.md`
(*Authentication — who may call which route*, *Errors*, *Discovery — OIDC and
RFC 8414*, *OAuth2 public clients*, *OAuth2 dynamic client registration*,
*OAuth2 resource indicators*, *MCP servers*), `docs/api/mcp.md`,
`docs/api/resource-indicators.md`, `docs/admin/README.md` (*I lost the setup
token*, *Stopping an assignment at its resource*), `docs/deployment/README.md`
(*Secrets follow one further rule*, *Recovering the bootstrap setup token*,
*The console resolves the backend per request*, *The gRPC listener: TLS and
client certificates*, *Container healthcheck*, *Two things to decide before you
put AXIAM in front of RabbitMQ*), `docs/pki/README.md` (*Which CA a caller may
issue under*, *Server certificates, and the names they may carry*, *What every
leaf may be used for*, *Bind a certificate for mTLS*, *The token a device gets
back is bound to its certificate*), `sdks/CONTRACT.md` §5.2, §6.1, §27.13,
§27.14, and the four 2026-09-18 conformance reports.

| Page (slug) | What to do | Source |
|---|---|---|
| `oauth2` | **Extend**, substantially — this is the largest single item. Before the *MCP servers* block, add the beta16 surface the block only alludes to, one `h` each: *Public clients* (`none`, PKCE required, no secret, `client_secret` absent never empty, the admin-UI toggle; loopback redirects any port including `[::1]`, widened by a port and nothing else; an error still reaches the ephemeral port); *Resource indicators* (`resource` on every grant, audience cannot widen, `aud` in introspection, `allowed_resources`, the `axiam` scheme reserved); *Dynamic client registration* (`POST /oauth2/register?tenant_id=`, off by default, the two modes, registration tokens endpoints, single-use, quota + TTL + per-IP limit + the one-hour reclaim for a never-authorized row, D3/D4, `managed_by`); *Client ID metadata documents* (the URL as `client_id`, the trusted-publisher list with no `*`, the SSRF guard, the shadow rows bounded and swept); *Per-tenant issuers* (`/t/{tenant_id}`, the RFC 8414 alias, opt-in, what isolation rests on). Keep every hedge the changelog keeps. **Verify** the MCP block and update `:730` (the conformance sentence) to 2026-09-18 | CHANGELOG beta16; `docs/api/README.md`; `docs/api/mcp.md`; `docs/api/resource-indicators.md`; T-272 … T-280 |
| `token-exchange` | **Verify** the audience material says token exchange reads `allowed_resources` for `audience` / `resource` (beta16 *Changed*); extend with one sentence if it does not | CHANGELOG beta16 *Changed*; `docs/api/token-exchange.md#audience` |
| `settings` | **Extend**: the tenant-settings families beta16 added (`dynamic_registration`, `dcr_*`, `cimd.trusted_client_id_domains` — never `*`) and Phase 22's `certificate.server_cert_allowed_names` (organization baseline, tenant narrows only, intersection, the Security Overrides distinction between "follow the organization" and "issue none") | `docs/admin/README.md`; `docs/pki/README.md`; CHANGELOG T22.14b |
| `rest` | **Extend**: a short *Who may call which route* passage mirroring `docs/api/README.md`'s section (human vs machine audience per family; the eight families a service account may call); **verify** the endpoint listings against the regenerated index (`/oauth2/register`, `/api/v1/oauth2-clients/registration-tokens`, `/.well-known/oauth-authorization-server`, the `/t/{tenant_id}` forms — the index carries them; the page may list by hand) | `docs/api/README.md`; `sdks/openapi.json` |
| `grpc` | **Extend**: the client-certificate policy (`AXIAM__GRPC_TLS_CLIENT_AUTH`, the CA path, boot refusals, the shared reload) and certificate-bound device tokens over gRPC (the `cnf` matched against the certificate rustls verified on the connection; refused under `off`); that `ReactorAdminService` rides the same listener. Link `configuration` for the keys | `docs/deployment/README.md` *The gRPC listener*; `docs/pki/README.md` *Over gRPC*; T-286, T-283 |
| `pki` | **Verify** the Phase 22 material already there (bind, subject, Server certificates, the fence, the profile table, the `1.0.0-beta17` note). **Extend**: *Which CA a caller may issue under* (a tenant's signing CA issues for that tenant only; a foreign CA is `404`; the upgrade note); the device token's `cnf` (what it binds, where the claim is not made and why, the upgrade note); RSA-4096 CA generation works under every custodian, stated as a correction; a `Server` CSR under `vault_pki` is refused and `POST /certificates` is the path; the device-login rate limit and the `401` for an unbound certificate in the *Let it connect over mTLS* step or its note | `docs/pki/README.md`; CHANGELOG T22.1, T22.3, T22.4, T22.2, DF-015 |
| `service-accounts` | **Verify** the management-families paragraph (Phase 22 added it). **Extend** with one sentence: `403` without a role, and the audit log distinguishing a machine's write | CHANGELOG T22.13; T-287 |
| `errors` | **Extend** the device-login rows: every certificate refusal at `POST /auth/device` is `401` (the `403` is gone — say since when); `429` `rate_limit_exceeded` with `Retry-After` on the same route. **Verify** `write_contention` and the DCR refusals (`403` when disabled, the quota's status) if the page lists OAuth2 registration errors | CHANGELOG T22.4, T22.2; `docs/api/README.md` *Errors* |
| `bootstrap` | **Fix** `getting-started.ts:422`: the token can be re-minted with `axiam-server setup-token --remint`, refused with exit 2 on any deployment that has a user or a redeemed token; keep the advice to prefer `AXIAM_BOOTSTRAP_ADMIN_EMAIL` for anything unattended. One `h` *I lost the setup token* mirroring the admin guide | `docs/admin/README.md`; `docs/deployment/README.md` *Recovering…*; T-284 |
| `deploy` | **Extend**: the healthcheck probing a TLS listener (derived default, `AXIAM_HEALTHCHECK_*` with the single-underscore note, the CA file, where the anchors come from with no CA file, no skip switch); the console resolving its backend per request (`AXIAM_BACKEND_ORIGIN`, 30 s, `docker/console-backend-resolver.envsh`). **Do not** mention the k8s `readOnlyRootFilesystem` question — unobserved | `docs/deployment/README.md` *Container healthcheck*, *The console resolves…*; CHANGELOG T22.8, T22.10 |
| `configuration` | **Verify only**: `DCR_PER_MIN`, `TENANT_ISSUER_PATHS`, the two gRPC client-auth keys, `DEVICE_LOGIN_PER_MIN`, the `AXIAM__AUTH__<KEY>` rule; add the `AXIAM_HEALTHCHECK_*` variables if the page has a table they belong in. `scripts/check-config-key-coverage.py` must pass | `docs/deployment/README.md` |
| `secrets` | **Verify** the naming rule and the legacy-spelling warning are stated; extend with the warning if not | `docs/deployment/README.md` *Secrets follow one further rule*; CHANGELOG T22.5 |
| `amqp` | **Extend** with the two RabbitMQ decisions (broker-wide `fail_if_no_peer_cert` and AXIAM's own client at startup — read the source's ordering argument before copying; it is about AXIAM's own connection at boot and is unaffected by `Server` certificates; and access tokens not being consumable by the broker's HTTP auth backend without the certificate-login pairing) and the AMQP TLS ordering constraint | `docs/deployment/README.md` *Two things to decide…*; CHANGELOG *Documentation* (DF-007, DF-020) |
| `rbac`, `deny`, `authz` | **Verify only** — `inherit: false` landed in `authorization.ts` with three precedence rows. Confirm which page carries the prose and that the console paragraph names the badge and the confirmation | `docs/admin/README.md` *Stopping an assignment…*; T-285 |
| `sdks` | **Verify** the 1.47 … 1.52 rows and the "thirteen amendments … six changed SDK code" paragraph; add the fix-PR class sentence for 1.52 if the row does not carry it. No SDK release version is claimed — check each repository's tags before naming one | contract Breaking Changes Log 1.47 … 1.52; dogfooding plan §6, §8.1 |
| `compliance` | **Replace** the "Plan (2026-09-11)" table with the 2026-09-18 sweep — `oidcc-basic-static` 35 / 30 / 4 / 1 / 0 / 0; `fapi2-…-mtls` 37 / 34 / 2 / 0 / 1 / 0; `fapi2-…-self-signed` 37 / 34 / 2 / 0 / 1 / 0; `fapi2-…-private-key-jwt` 56 / 52 / 2 / 1 / 1 / 0 — keeping one sentence that the 2026-09-11 run stands in the archive, and link the evidence README. The `warn` block stays: 165 modules, zero `FAILED`, not a certification | `docs/conformance/2026-09-18-*.md`; `docs/conformance/evidence/2026-09-18/README.md`; `docs/conformance/index.md` |
| `hardening` | **Extend** the gRPC checklist line ("gRPC is loopback by default…") with client-certificate verification available and `off` by default, and the device-login limiter under rate limits; the beta14 rustls sentence stays as history | CHANGELOG; T-286, T-282 |
| `troubleshooting` | **Extend**: the legacy secret spelling (`AXIAM__PKI__ENCRYPTION_KEY` and three others read by nothing; the startup warning); the lost setup token → remint; a `Server` CSR refused under Vault custody; the healthcheck failing against a TLS listener whose certificate does not cover the probed address | `docs/deployment/README.md`; `docs/pki/README.md` |
| `installation`, `quickstart` | **Verify only** — the Compose healthcheck and the console image changed; the pages may describe neither | `docker/` |

Pages **not** to touch for this pass: `opaque`, `mfa`, `passkeys`,
`federation`, `organization-scope`, `uma`, `overview`, `concepts`,
`tutorial`, `scim`, `webhooks`, `reactors`, `device-flow`, `logout`, `fapi2`,
`par`, `audit`, `observability`. Re-read them in Wave 4; do not rewrite them
in Wave 2.

## 7. Wave 3 — News and Roadmap

- **News.** Do not rewrite the 15 September post. **One new post**, tag
  `Release`, dated the pass date, covering both releases under two headings,
  because beta16 was tagged without a post and beta17 follows this pass:
  *`1.0.0-beta16`* — the MCP authorization surfaces (public clients and
  loopback ports, resource indicators, DCR, CIMD, per-tenant issuers,
  contract 1.48's §28 helpers in all eleven SDKs), the T21.8 review with its
  four findings closed the same day (anchors
  [T-272](#/security/diagram/2/T-272), [T-275](#/security/diagram/2/T-275),
  [T-276](#/security/diagram/2/T-276), [T-280](#/security/diagram/2/T-280)),
  and the 2026-09-18 full sweep with the hedge; *`1.0.0-beta17`* — the
  dogfooding remediation, told from the operator's side: what
  `axiam-domo-demo` found, the eight threats ([T-281](#/security/diagram/5/T-281)
  … [T-288](#/security/diagram/5/T-288), each linked to its diagram), the
  three corrections stated as corrections (devices must be bound; RSA-4096
  works; the four secret names that were read by nothing — **if your
  deployment set `AXIAM__PKI__ENCRYPTION_KEY` or its three siblings, they
  were ignored and the startup warning now says so**), the upgrade notes
  (leaves issued before carry no usage profile; a device token minted before
  carries no `cnf`; the Vault `Server` CSR refusal), contracts 1.51 / 1.52 and
  what the C-12 review found in every SDK. The model: **288 threats, 275
  mitigated / 13 open**. Every anchor checked against the regenerated model.
  Write the beta17 half as shipping in `1.0.0-beta17`, per §0.
- **Roadmap.** Phase 20 stays `ongoing`. Extend its `focus` with "the MCP
  authorization surfaces — public clients, resource indicators, dynamic
  registration, client ID metadata documents and per-tenant issuers — and
  the remediation of what the first external integration found: a signing CA
  bound to its tenant, certificate-bound device tokens, server certificates
  behind a name fence, client certificates on gRPC, and service accounts on
  the management API". Do not close anything and do not add a phase.

## 8. Wave 4 — sweep and stamp

`DOCS_VERIFIED_RELEASE` is stamped on 29 of 41 pages through one constant.
Bump it to `1.0.0-beta17` only if every stamped page is re-read against
`main` — the beta11, beta14 and beta15 passes each found real errors this
way — otherwise leave it at `1.0.0-beta15` and say so in the EXECUTED note.
The twelve unstamped pages stay unstamped unless the maintainer asks.

Claims most likely to have gone stale, to check first on every page that
carries them: any sentence that a `Device` certificate needs no bind; any
"a setup token cannot be re-minted"; any secret variable named without the
`AXIAM__AUTH__` prefix (`grep -rn "AXIAM__PKI__ENCRYPTION_KEY\|AXIAM__EMAIL_ENCRYPTION_KEY\|AXIAM__GDPR_PSEUDONYM_PEPPER\|AXIAM__FEDERATION_ENCRYPTION_KEY" src/` must return nothing outside historical text); any `subject` example carrying `CN=` as if required; any statement that leaves carry no `keyUsage` / `extendedKeyUsage`; any "the gRPC listener does not verify client certificates" or "no config key exists"; any `403` for a certificate refusal at the device login; any "role inheritance is unconditional"; any statement that no management route accepts a service-account token; any "the contract is at 1.4x"; "222 operations" / "156 paths" / "155" or "160" management operations (verify the current registry count and say it once); any count of threats, mitigated or open; "eight modules pass individually … not re-swept"; any "2026-09-11" presented as the latest run; any "since 1.0.0-beta15" attached to Phase 21 or Phase 22 work.

## 9. Verification

```sh
cd website
npm ci
npm run gen:threat-model && npm run gen:api-index && npm run gen:contract-anchors
git diff --stat                      # only the files this plan names
npm run build                        # tsc -b && vite build; runs docSectionsAreComplete()
npm run lint                         # oxlint
grep -rn "271 threats\|258 mitigated\|279 threats\|266 mitigated\|contract 1.4[0-9]\b" src/ | grep -v threatModel.ts | grep -v "1\.4[0-9] —"   # expect only historical news text and the sdks amendment table
grep -rn "2026-09-11" src/ | grep -v -i "archive\|earlier\|first run\|history"   # expect nothing presented as current
grep -rn "re-mint\|remint" src/docs/getting-started.ts                            # expect the new sentence, not the old one
grep -rn "AXIAM__PKI__ENCRYPTION_KEY\|AXIAM__EMAIL_ENCRYPTION_KEY\|AXIAM__GDPR_PSEUDONYM_PEPPER" src/ | grep -v "read by nothing\|legacy\|were ignored"   # expect nothing
cd .. && scripts/check-doc-links.sh && python3 scripts/check-config-key-coverage.py
```

Open the anchors §3 lists in the built site and confirm each selects its node
and renders Mitigated; confirm the open-only filter on `#/security/diagram/1`,
`/2` and `/4` is empty; confirm `#/security` shows 288 / 275 / 13 and the
model version 2.17.0.

One commit per wave on `main` (Wave 0 and Wave 1 together, since the
generated files move with the prose): `docs(website): the Security section at
1.0.0-beta17 — model 2.17.0`, `docs(website): bring the Docs pages up to
1.0.0-beta17 (wave 2)`, `docs(website): announce 1.0.0-beta16 and beta17, and
extend phase 20 (wave 3)`, `docs(website): sweep every stamped page, move
DOCS_VERIFIED_RELEASE to beta17 (wave 4)`. Then the EXECUTED blockquote at the
top of this plan: what landed, what was left, the stamps, the generator lines,
and the `gen:api-index` note for the release-prep commit.

## 10. Out of scope

- Server work. Everything this plan describes has shipped; nothing here
  re-opens a decision. The dogfooding plan's §13 rows other than row 6 are
  the maintainer's and are not mentioned on the site.
- A conformance *submission*. The 2026-09-18 sweep is described as a sweep
  and nothing more.
- Tagging `1.0.0-beta17` and its release-prep commit. The maintainer's; the
  EXECUTED note carries the one thing that commit must do for the site.
- The eleven SDK repositories' READMEs, which vendor 1.52 already.
- Threat Dragon diagram aesthetics beyond what the generator lays out, and
  the JSON itself — the prerequisite plan owns it.
- A separate Phase 21 or Phase 22 row on the website roadmap.

---

## Appendix A — the numbers (model 2.17.0, after the prerequisite)

Headline: **288 threats, 275 mitigated / 13 open**, 9 diagrams, `threatTop` 288.

| Area | Threats | Open |
|---|---|---|
| System context | 33 | 2 |
| Authentication & session management | 35 | 0 |
| OAuth2 / OIDC authorization server | 58 | 0 |
| Federation (SAML SP & OIDC RP) | 31 | 1 |
| Authorization engine (RBAC, hierarchy, scopes) | 27 | 0 |
| PKI, certificates & IoT device identity | 30 | 1 |
| Audit, webhooks, email & notifications | 18 | 1 |
| Deployment & platform (Kubernetes) | 28 | 5 |
| Client SDKs & admin-UI integration surface | 28 | 3 |

By STRIDE category: Spoofing 70 (3 open), Tampering 59 (1), Repudiation 6 (0),
Information disclosure 67 (6), Denial of service 28 (2), Elevation of
privilege 58 (1). By severity: Critical 32 (1 open), High 135 (8), Medium 111
(3), Low 10 (1). The open items, most severe first: T-148, T-18, T-94, T-124,
T-133, T-135, T-146, T-216, T-180, T-9, T-123, T-134, T-161 — unchanged since
2.14.0 (order per the generator). API index: 229 operations, 162 paths, 11
domains. Contract anchors: 184 sections at 1.52. Every one of these numbers is
emitted by a generator; they are here so a wrong regeneration is noticed, not
so they can be typed in.

## Appendix B — the prompt for the session that executes this plan

> Read `claude_dev/website-security-beta17-update-plan.md` in the
> `ilpanich/axiam` repository and execute it, waves 0 to 4 in order,
> committing directly on `main` — one commit per wave, no pull request. First
> confirm its prerequisite: `claude_dev/threat-model-reconciliation-2026-09-25-plan.md`
> must carry an EXECUTED block and `node website/scripts/gen-threat-model.mjs`
> must print `9 diagrams, 288 threats (275 mitigated, 13 open)`; if not, stop
> and execute that plan first. The stamp is decided in the plan's §0: stamp
> `1.0.0-beta17`, which the maintainer tags after this pass, and write Phase
> 22 as shipping in it. The source of the Security section,
> `claude_dev/threat-modeling-and-security.md`, does not yet carry either wave
> in its body: extend it first (Wave 1a), from the STRIDE entries T-272 … T-288
> in `claude_dev/threat-model-stride.md`, the T21.8 review and the dogfooding
> plan's EXECUTED blocks, then mirror it into `website/src/security.ts` section
> by section (Wave 1b). Do not add claims the sources do not make; state the
> three corrections as corrections; move the conformance claim to the
> 2026-09-18 sweep and keep its hedge — a self-run, not a certification;
> keep the open risk register generated; move `SECURITY_VERIFIED_RELEASE`
> only in the same commit as the Security prose and the regenerated files.
> Then the Docs pages in §6 — the `oauth2` page gets the whole beta16 surface
> and the `bootstrap` page loses a sentence that is now false — the News post
> covering both releases, the phase-20 focus, and the Wave 4 sweep before
> moving `DOCS_VERIFIED_RELEASE`. Verify with §9, then add the EXECUTED
> blockquote at the top of the plan, including the note that the beta17
> release-prep commit must re-run `npm run gen:api-index` after bumping
> `sdks/openapi.json`.
