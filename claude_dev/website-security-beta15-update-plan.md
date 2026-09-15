# Website — the post-beta14 security and docs catch-up pass (model 2.16.0)

> **Who this is for.** A fresh Claude session (Opus 5) tasked with bringing the
> website's **Security** section, and the **Docs**, **News** and **Roadmap**
> content the same changes touched, up to the state of `main` on 2026-09-15 —
> two waves after the executed
> [`website-security-beta14-update-plan.md`](website-security-beta14-update-plan.md).
> It is the entry point: read this, then work the waves in §4–§8. When the pass
> is done, add an **EXECUTED** blockquote at the top of this file in the style
> of the beta14 plan, recording what landed, what was deliberately left, and
> the stamps.
>
> **The headline.** The website's Security section was re-derived at
> `1.0.0-beta14` / model 2.14.0 on 2026-09-13 and is correct as of that
> morning. Two waves landed after it, both on `main` and **neither yet in a
> tagged release**: the 2026-09-13 **MFA-and-CSR wave** (model 2.15.0 — three
> threats, T-267…T-269; PR #447, which updated the Docs pages for MFA and PKI
> but not the Security section) and the 2026-09-14 **early-refusal pass**
> (model 2.16.0 — two threats, T-270 and T-271, six entries amended; PRs #449,
> #450, #455). The model is now **271 threats, 258 mitigated / 13 open**; the
> generated files under `website/src/` render **266 / 253 / 13** at 2.14.0, the
> contract anchors are at 1.44 against a contract at **1.46**, and the API
> index is already current (222 operations / 156 paths, regenerated in #447).
> Nothing on the open register moved: the thirteen open items are the same
> thirteen, in the same order.
>
> **One decision the executing session must make first: the stamp.** The
> workspace is still `1.0.0-beta14` and every change here is unreleased.
> `SECURITY_VERIFIED_RELEASE` records the release the claims were verified
> against, and stamping `1.0.0-beta14` would be false — beta14 predates both
> waves. Either (a) `1.0.0-beta15` has been tagged by the time this runs, in
> which case stamp it (the recommended path — the release also ships the
> RUSTSEC-2026-0285 fix, which is a reason to cut it), or (b) it has not, in
> which case stamp the commit, `main@<short sha>` with the date, as the page
> did once before (`3ede4d19`, 2026-08-04), and say so in the EXECUTED note.
> Never stamp a release that does not contain the change.

**Sources of truth, in order.** [`threat-modeling-and-security.md`](threat-modeling-and-security.md)
(the website section's source, current as of 2026-09-15 — its handoff block
carries one paragraph per wave, and the prose sections already contain every
sentence this plan asks the site to carry), [`threat-model-stride.md`](threat-model-stride.md)
(the STRIDE model, mirroring the JSON), `ThreatDragonModels/Axiam/Axiam.json`
(what the generator reads), and for the Docs pages the documents named per row
in §6. The website is the readable front door; it links out for anything
binding and **never carries a claim these documents do not**.

---

## 1. What moved since the beta14 pass

| Landed | Security-relevant change | Threats |
|---|---|---|
| 2026-09-13, #447 (M-1) | An administrative MFA reset evicts **every** factor — the WebAuthn credentials as well as the TOTP secret — in the same call that clears `mfa_enabled` and revokes the sessions. Before: the credential rows survived, the forced TOTP setup turned the flag back on, and the authenticator the account was reset *because of* was a live second factor again | T-34 amended |
| 2026-09-13, #447 (M-2) | A user can no longer take their own account below the tenant's MFA floor: `POST /users/{own id}/reset-mfa` answers `403` with the error code `mfa_enforced` where the caller's tenant enforces MFA; `users:admin` is unaffected; where the tenant does not enforce MFA the self-service reset still works. Contract 1.45 §5.2 rule 4 | **T-267** new |
| 2026-09-13, #447 (M-3) | A passkey or a security key can be the **first** factor: `POST /api/v1/auth/webauthn/setup/register/start` and `/finish` run the registration ceremony from the setup token, under the same attestation and user-verification policies as the profile-page ceremony, and refuse an account that already has a factor. Contract 1.45 §24, §25 | **T-269** new |
| 2026-09-13, #447 (M-4) | Forced first-login enrolment carries the login-hop `return_to`, so a new user who arrived through `/oauth2/authorize` lands back at the relying party. Admin UI only | — |
| 2026-09-13, #447 (M-5, not taken) | A single-use setup token was assessed and not built; T-32's mitigation now says precisely what is consumed (the TOTP step, not the challenge token) | T-32 corrected |
| 2026-09-13, #447 (C-1) | `POST /api/v1/certificates/sign-csr` — an end-entity certificate for a key AXIAM never sees. Possession proved by the CSR's own signature; key Ed25519 or RSA with a *measured* modulus ≥ 4096; `subjectAltName`, `keyUsage`, `extendedKeyUsage` refused by name (Vault's `sign-verbatim` would otherwise honour them); every other requested extension discarded; a CSR asking to be a CA comes back a leaf; no key field in the response. Contract 1.45 §27 `certificates.sign_csr` (159 → 160 management operations) | **T-268** new |
| 2026-09-13, F-1 | The contract 1.45 SDK fan-out in all eleven repositories: rust #105, typescript #104, python #81, java #93, kotlin #63, csharp #88, php #68, go #78, swift #61, c #60, cplusplus #61 — all merged | — |
| 2026-09-13, #449 | The SCIM endpoint's own error type answers a contended write with `503` + `Retry-After: 1`; until then it fell through its 5xx catch-all as `500`, on the one surface the defect had been found on, while REST and gRPC already answered as R-4 said | T-262 corrected |
| 2026-09-14, #455 | A `request_uri` that is already spent, expired or another client's is refused **before** the login hop, by a read that does not spend it (`ParService::peek`); a merely unfinished handle still reaches the sign-in page. A missing or unsupported `response_type` is refused before the hop too, when no `request_uri` is present | **T-270** new; T-163, T-238, T-255, T-256 amended |
| 2026-09-14, #455 | The refusal reaches the relying party as `error=invalid_request_uri` with the request's own `state` when the request named a `redirect_uri` the client registered (RFC 6749 §4.1.2.1, OIDC Core §3.1.2.6); answered in place otherwise; a wrong-client handle keeps `invalid_request`. Contract **1.46** §26.2 rule 3 — documentation only, no SDK change, since a conformant SDK's authorization URL carries no `redirect_uri`. Re-vendored by all eleven SDKs | T-270 |
| 2026-09-14, #455 | A `fapi2` client's `state` and `nonce` are bounded at push: 256 characters, `invalid_request` beyond it, the cap pinned by a `const` block against the OIDF suite's probes; the `standard` profile deliberately unbounded (a 16 KiB body cap and a 60-second handle bound the residual) | **T-271** new |
| 2026-09-14, #455 | Eight OpenID Foundation modules moved from `REVIEW` to `PASSED` **when run individually** with `conformance/scripts/run-some.sh`: the three FAPI PAR `request_uri` refusals, `oidcc-response-type-missing`, `-with-long-state`, `-with-long-nonce`, `-different-nonce-inside-and-outside-request-object`, `-different-state-inside-and-outside-request-object`. **No full plan was re-swept; the committed receipts remain the 2026-09-11 runs** | — |
| 2026-09-14, #450 | rustls 0.23.43 → 0.23.45 for RUSTSEC-2026-0285 (TLS 1.3 handshake messages accepted across encryption-level boundaries, CVSS 5.3); verified by re-running the FAPI 2.0 mTLS plan. The `1.0.0-beta14` artefacts carry 0.23.43 | T-127 amended |

The open register neither gains nor loses. Authentication goes to **35 / 0**,
OAuth2 to **49 / 0**, PKI to **26 / 1**; Tampering to 59, Elevation of
privilege to 51, High to 126, Low to 9. **Check the model rather than this
paragraph** — Appendix A is what the generator must print.

## 2. Ground rules (unchanged; they are why the pass has value)

- **Do not upgrade the hedges.** "No open finding at all *in AXIAM's own
  request path*", "self-assessment, not a certified audit", "a self-run
  against a working-tree build, not a certification", and the beta caution are
  load-bearing. The conformance result is still **165 modules, zero `FAILED`
  on 2026-09-11**; the eight modules that now pass were run *individually*
  and are described that way, never as a new sweep, a new count, or "passed
  the plan". The revocation feed is **a narrowing, not a control**.
- **Do not add claims.** Every sentence in `threat-modeling-and-security.md` is
  backed by code, a commit, a merged SDK PR or a conformance receipt. Copy its
  prose; do not improve it. In particular: the `standard`-profile `state`
  residual is *stated* on T-271 — do not turn it into "unbounded" or into
  "bounded"; say what the source says.
- **Say the release plainly.** Neither wave is in `1.0.0-beta14`. Any sentence
  that says "since 1.0.0-beta14" about M-1…C-1 or the early refusals is false.
  Use "since 2026-09-13 / 2026-09-14 on `main`" until a release carries them,
  then the release.
- **Keep the shared-responsibility section**, and keep the open register
  generated. T-39, T-110, T-143 and T-254 do not appear in it; nothing new
  does either.
- **Mirror, do not paraphrase.** `src/security.ts` mirrors the Markdown section
  for section; the four bullets whose bold markers deliberately differ stay as
  they are, for the reason recorded in the handoff block.
- **Stamps record verification, not releases.** `SECURITY_VERIFIED_RELEASE`
  moves only with the Security section and only to something that contains
  the change (see the decision above); `DOCS_VERIFIED_RELEASE` is stamped on
  30 pages, so bumping it re-asserts every one of them — §8 says what that
  costs.
- **No element moved.** Neither wave added a node or a flow to any diagram:
  T-267 and T-269 sit on the existing *MFA verification* process, T-268 on
  *Certificate issuance*, T-270 on `/oauth2/authorize (+ consent)`, T-271 on
  the *single-use credentials* store. If `threatModel.ts` shows a coordinate
  change, the JSON was edited by hand — stop and look.

## 3. Current state (verified 2026-09-15)

| What | Where | State |
|---|---|---|
| Security stamp | `website/src/version.ts` | `SECURITY_VERIFIED_RELEASE = "1.0.0-beta14"`, `SECURITY_VERIFIED_DATE = "2026-09-13"` — correct for what the section says today |
| Docs stamp | `website/src/version.ts` | `DOCS_VERIFIED_RELEASE = "1.0.0-beta14"` |
| Generated model | `website/src/threatModel.ts`, `threatModelSummary.ts` | 266 / 253 / 13, model 2.14.0 — `node scripts/gen-threat-model.mjs` was run against 2.16.0 on 2026-09-15 and printed `threatModel.ts: 9 diagrams, 271 threats (258 mitigated, 13 open)`, then **reverted** so the generated files and the prose move together |
| Security prose | `website/src/security.ts` | At beta14. Missing: everything in §5 here |
| Contract anchors | `website/src/contractAnchors.ts` | `CONTRACT_VERSION = "1.44"` — `gen:contract-anchors` was run on 2026-09-15 and produced `167 sections at contract 1.46` (a one-line diff), then reverted |
| API index | `website/src/apiIndex.ts` | **Current**: 222 operations / 156 paths, regenerated in #447 (`sign-csr`, the two setup-registration paths). `gen:api-index` prints the same and produces no diff |
| News | `website/src/data.ts` | Latest post dated 13 September 2026 covers beta12 → beta14; nothing about either wave, correctly, since neither is released |
| Roadmap | `website/src/data.ts` — phase 20 | `focus` ends at "…landed in all eleven repositories"; nothing about the MFA/CSR wave or the early refusals |
| Docs pages already touched | `authentication.ts` (the forced-enrolment passkey choice, the setup-registration endpoint rows, the reset-mfa row's "every factor"), `operate.ts` (the leaf-CSR paragraph and endpoint row) — both from #447. **Verify, then extend**; do not rewrite | Everything else in §6 is new work |

The explorer (`src/components/ThreatModelExplorer.tsx`) needs no functional
change. After Wave 0, open `#/security/diagram/2/T-270` and confirm it selects
the `/oauth2/authorize (+ consent)` node (now nine threats) and renders
Mitigated; `#/security/diagram/2/T-271` selects the single-use-credentials
store; `#/security/diagram/1/T-267` and `/T-269` the MFA process;
`#/security/diagram/5/T-268` the certificate-issuance process. The open-only
filter on diagrams 1 and 2 must still be **empty**.

## 4. Wave 0 — regenerate

Run from `website/`, in this order, and commit the generated files together with
the prose that describes them (Wave 1), never alone:

```sh
npm run gen:threat-model     # expect: threatModel.ts: 9 diagrams, 271 threats (258 mitigated, 13 open)
npm run gen:api-index        # expect: apiIndex.ts: 222 operations across 156 paths, 11 domains — and no diff
npm run gen:contract-anchors # expect: contractAnchors.ts: 167 sections at contract 1.46
```

Read the `threatModel.ts` diff once: five threats added across three existing
nodes, six mitigations extended, no node, flow or coordinate changed. The
open register is byte-identical to what the site renders today. No generated
file is hand-edited.

## 5. Wave 1 — the Security section

The Markdown is the text; the source document was re-derived on 2026-09-15 and
every sentence below is already in it.

| `security.ts` section | Change |
|---|---|
| Security at a glance | "**271** threats" |
| The threat model | Table: 271 threats, **258 / 13**. Coverage by area is generated — confirm the page renders 271 / 13, **Authentication 35 / 0**, **OAuth2 49 / 0**, **PKI 26 / 1**, Audit 18 / 1, and that the rows match Appendix A. The paragraph after the area table is unchanged (the T-254 and T-39/T-143 sentences stay). The by-category and by-severity tables are generated; the prose sentence after them still says **13** |
| Trust boundaries | Unchanged |
| Authentication & sessions | The **MFA** bullet gains the source's four new sentences: a passkey or security key as the *first* factor from the setup token under the same policies, a setup token adds a first factor and never a second, reset evicts every factor in the call that revokes the sessions, and the self-service reset refused with `mfa_enforced` where the tenant enforces MFA. The **SCIM** bullet gains the one-sentence correction (the SCIM endpoint's own error type carried `500` for a day; `503` since 2026-09-13, tested over the wire) |
| Authorization & tenant isolation | Unchanged |
| OAuth2 & OpenID Connect | **One new bullet** after *Discovery describes a tenant without enumerating tenants*: *A request that cannot succeed is refused before anyone is asked to sign in for it* — the dead-handle read that spends nothing, the unfinished handle still reaching the sign-in page, `response_type` decided before the hop and only without a `request_uri`, delivery as `invalid_request_uri` only to a registered `redirect_uri` with `state`, the wrong-client handle keeping `invalid_request`, the `fapi2` 256-character cap with the `standard` profile deliberately left alone and its residual stated, and the closing hedge — eight modules per module, receipts still the 2026-09-11 full runs. Copy it whole |
| Federation (SAML & OIDC) | Unchanged |
| PKI, certificates & device identity | The first bullet gains the leaf-CSR sentences: proof of possession, the measured modulus, the three extensions refused by name and *why* (Vault's `sign-verbatim`), everything else discarded, a CA request comes back a leaf, no key field in the response |
| Audit & accountability | Unchanged |
| Webhooks, email & messaging | Unchanged |
| Transport, secrets & the SDKs | **The eleven client SDKs** bullet gains the contract 1.45 / 1.46 sentence (1.45 landed in all eleven on 2026-09-13; 1.46 documentation only, vendored by all eleven). Everything else unchanged |
| Compliance posture | The **OAuth2 / OIDC** row's status gains the clause "since 2026-09-14 eight further modules pass when run individually (…), not yet re-swept as a plan" — exactly that, with the hedge. The dependency paragraph gains the RUSTSEC-2026-0285 sentences, including "the `1.0.0-beta14` release artefacts predate it and carry the vulnerable version; the fix ships with the next release" — keep that sentence; it is the honest one |
| Shared responsibility | "**13** of 271". Register generated and unchanged. No new bullet in any group — the source added none |
| How security is maintained | Closing sentence: last re-derived at `main` after `1.0.0-beta14` (model 2.16.0) on 2026-09-15 — or at `1.0.0-beta15`, if the stamp decision went that way; the two must agree |

Then `src/version.ts`: `SECURITY_VERIFIED_RELEASE` per the decision at the top,
`SECURITY_VERIFIED_DATE` the date of this pass. The constant moves in the same
commit as the prose, never earlier.

## 6. Wave 2 — Docs pages the same changes touched

Open the sources first: `CHANGELOG.md` *Unreleased* (Security, Added, Changed),
`docs/admin/browser-login-hop.md` (*A handle that is already dead never reaches
the sign-in page*), `docs/pki/README.md` (*Or bring a CSR*), `sdks/CONTRACT.md`
§5.2 rule 4, §24, §25, §26.2 rule 3, §27.1 and its Breaking Changes Log
entries for 1.45 and 1.46.

| Page (slug) | What to do | Source |
|---|---|---|
| `mfa` | **Verify** the forced-enrolment section already offers the passkey / security-key choice and the two setup-registration rows (#447 put them there). **Extend**: the reset-mfa row's sentence with the self-service rule — refused with `403` and `mfa_enforced` where the tenant enforces MFA, the administrator resets it for them, `users:admin` unaffected; and that a reset evicts WebAuthn credentials too, so "every factor" is now literally true. Add the operational sentence from the changelog: an operator who reset an account because a key was lost should know that, before this change, the key still worked | CHANGELOG *Security* (M-1, M-2); contract §5.2 rule 4; T-34, T-267 |
| `passkeys` | One paragraph: the setup-token registration pair, same ceremony, same attestation and user-verification policy as the profile page, first factor only, both routes public and CSRF-exempt because the caller has no session. Link to `mfa` | CHANGELOG *Added* (M-3); contract §24.1, §24.5, §24.7, §24.8; T-269 |
| `pki` | **Verify** the leaf-CSR paragraph and the `sign-csr` row (#447). **Extend** only if a rule is missing: possession by the CSR's signature, the measured modulus, the three refused extensions and the Vault reason, the discarded rest, no key in the response, permission `certificates:generate` | `docs/pki/README.md` *Or bring a CSR*; T-268 |
| `par` | The single-use bullet ("A second use is `invalid_request`, not a duplicate-suppressed success") becomes the contract's rule 3: a second use is **refused**, never a duplicate-suppressed success — and the refusal is delivered *directly* (`invalid_request`, JSON or the error page) when the request named no registered `redirect_uri`, which is the only form a conformant SDK's two-parameter URL can reach; or *redirected* as `error=invalid_request_uri` with `state` when it named one the client registered. A wrong-client handle keeps `invalid_request`. Add one sentence: a handle that is already dead is refused before the sign-in page, and a merely unfinished one still reaches it | contract §26.2 rule 3 (1.46); `docs/admin/browser-login-hop.md`; T-270 |
| `oauth2` | Under the login-hop / error-delivery material: a dead `request_uri` and a missing or unsupported `response_type` are now refused **before** the hop, delivered by the same RFC 6749 §4.1.2.1 rule (registered target → redirect with `state`; otherwise in place). Keep the "the page echoes nothing" sentence | `docs/admin/browser-login-hop.md`; T-255, T-270 |
| `fapi2` | One item: on a `fapi2` client `state` and `nonce` are bounded at 256 characters at `POST /oauth2/par` (`invalid_request` beyond it); `standard` clients are not bounded, deliberately. Say why in the source's words (opaque values carry no meaning past their entropy; a cap is a breaking change the profile agreed to). If the page lists suite modules or counts, add the eight per-module passes with the hedge — **not** a new plan result | `crates/axiam-oauth2/src/par.rs` (`MAX_FAPI_OPAQUE_PARAM_CHARS`); CHANGELOG; T-271 |
| `scim` | **Verify only.** The page already says a contended write answers `503` + `write_contention` + `Retry-After: 1`; that sentence is now true of the SCIM endpoint's own renderer as well. No new text unless the page dates the behaviour | T-262 |
| `errors` | **Verify only** the `write_contention` row | `docs/api/README.md` *Errors* |
| `rest` | **Verify** the endpoint listings include `POST /api/v1/certificates/sign-csr` and the two `webauthn/setup/register/*` paths (the index does; the page may list by hand) | `sdks/openapi.json` |
| `sdks` | Contract **1.46**, not 1.44. Add: 1.45 — `certificates.sign_csr` in §27 (159 → 160 operations, response is a `Certificate`, never a `GeneratedCertificate`-shaped model), the two setup-registration operations in §24/§25, §5.2 rule 4; SDK code **did** change, in all eleven, PRs rust #105, typescript #104, python #81, java #93, kotlin #63, csharp #88, php #68, go #78, swift #61, c #60, cplusplus #61. 1.46 — documentation only, §26.2 rule 3, re-vendored by all eleven, no code change. Do not claim an SDK release version; check each repository's tags before naming one | contract Breaking Changes Log 1.45, 1.46; `mfa-first-login-and-csr-issuance-plan.md` §9.1 |
| `hardening` | One sentence under dependency hygiene, if the page has such a section: `1.0.0-beta14` images carry rustls 0.23.43 (RUSTSEC-2026-0285, CVSS 5.3); the fix is on `main` and ships with the next release. Plain, no editorialising | CHANGELOG *Security*; T-127 |
| `configuration` | **Verify only** — no configuration key was added by either wave | `docs/deployment/README.md` |

Pages **not** to touch for this pass: `opaque`, `federation`, `service-accounts`,
`authz`, `rbac`, `organization-scope`, `deny`, `uma`, `grpc`, `amqp`,
`webhooks`, `reactors`, `audit`, `observability`, `overview`, `quickstart`,
`installation`, `bootstrap`, `concepts`, `tutorial`, `device-flow`,
`token-exchange`, `logout`, `deploy`, `secrets`, `settings`, `troubleshooting`,
`compliance`. Re-read them in Wave 4; do not rewrite them in Wave 2.

## 7. Wave 3 — News and Roadmap

- **News.** Do not rewrite the 13 September post. **Add a post only if a
  release carrying these changes has been tagged** (the stamp decision). If it
  has: one post, tag `Release`, covering the MFA-and-CSR wave (M-1…M-4, C-1,
  with the operator-facing sentence about a reset key that still worked), the
  early-refusal pass ([T-270](#/security/diagram/2/T-270),
  [T-271](#/security/diagram/2/T-271)) with the per-module hedge, the T-262
  correction stated as a correction, the rustls advisory and the fact that the
  previous release carried it, and the model: **271 threats, 258 mitigated /
  13 open**. Every anchor checked against the generated model. If no release
  has been tagged, add nothing — the site does not announce unreleased work.
- **Roadmap.** Phase 20 stays `ongoing`. Extend its `focus` with "the
  first-login enrolment residuals and end-entity certificates from a CSR, and
  the authorization endpoint refusing a request that cannot succeed before
  anyone signs in for it". Do not close anything and do not add a phase.

## 8. Wave 4 — sweep and stamp

`DOCS_VERIFIED_RELEASE` is stamped on 30 pages through one constant. Bump it
only if every stamped page is re-read against `main` (or the new release) —
the beta11 and beta14 passes each found real errors this way — and only to a
value that contains the changes (the same decision as the Security stamp).
Otherwise leave it at `1.0.0-beta14` and say so in the EXECUTED note.

Claims most likely to have gone stale, to check first on every page that carries
them: "reset MFA clears the TOTP secret" without the credentials; any statement
that forced enrolment is TOTP-only; "a second use of a `request_uri` is
`invalid_request`" without the redirected form; any sentence implying the
sign-in page is shown for a spent handle; "no bound on `state`" or a bound on
the wrong profile; any count of threats, mitigated or open; any contract version
below 1.46; any "since 1.0.0-beta14" attached to either wave; any sentence that
turns eight per-module passes into a plan result.

## 9. Verification

```sh
cd website
npm ci
npm run gen:threat-model && npm run gen:api-index && npm run gen:contract-anchors
git diff --stat                      # only the files this plan names
npm run build                        # tsc -b && vite build
npm run lint                         # oxlint
grep -rn "266 threats\|253 mitigated\|contract 1.44\|1\.44\b" src/ | grep -v threatModel.ts   # expect only historical news text
grep -rn "since 1.0.0-beta14" src/ | grep -i "csr\|sign-csr\|reset-mfa\|request_uri\|response_type\|state.*nonce"   # expect nothing
cd .. && scripts/check-doc-links.sh
```

`docSectionsAreComplete()` in `website/src/docs/index.ts` asserts navigation and
content agree; the build runs it. Open the five anchors §3 lists in the built
site and confirm each selects its node and renders Mitigated; confirm the
open-only filter on `#/security/diagram/1` and `#/security/diagram/2` is empty.

## 10. Out of scope

- Server work. Everything this plan describes shipped by 2026-09-15; nothing
  here re-opens a decision.
- A conformance *submission*, or a new full-plan sweep. The eight per-module
  passes are described as such; the receipts are the 2026-09-11 ones until a
  sweep is run and committed under `docs/conformance/`.
- Tagging `1.0.0-beta15`. The plan says what to do in either case; the release
  is the maintainer's call.
- The eleven SDK repositories' own READMEs, which already vendor 1.46.
- Threat Dragon diagram aesthetics beyond what the generator lays out.

---

## Appendix A — the numbers (model 2.16.0, 2026-09-15)

Headline: **271 threats, 258 mitigated / 13 open**, 9 diagrams, `threatTop` 271.

| Area | Threats | Open |
|---|---|---|
| System context | 31 | 2 |
| Authentication & session management | 35 | 0 |
| OAuth2 / OIDC authorization server | 49 | 0 |
| Federation (SAML SP & OIDC RP) | 31 | 1 |
| Authorization engine (RBAC, hierarchy, scopes) | 26 | 0 |
| PKI, certificates & IoT device identity | 26 | 1 |
| Audit, webhooks, email & notifications | 18 | 1 |
| Deployment & platform (Kubernetes) | 27 | 5 |
| Client SDKs & admin-UI integration surface | 28 | 3 |

By STRIDE category: Spoofing 66 (3 open), Tampering 59 (1), Repudiation 6 (0),
Information disclosure 65 (6), Denial of service 24 (2), Elevation of
privilege 51 (1). By severity: Critical 30 (1 open), High 126 (8), Medium 106
(3), Low 9 (1). The open items, most severe first: T-148, T-18, T-94, T-124,
T-133, T-135, T-146, T-180, T-216, T-9, T-123, T-134, T-161 — unchanged since
2.14.0. Every one of these numbers is emitted by the generator; they are here so
a wrong regeneration is noticed, not so they can be typed in.

## Appendix B — the prompt for the session that executes this plan

> Read `claude_dev/website-security-beta15-update-plan.md` in the `ilpanich/axiam`
> repository and execute it, waves 0 to 4 in order, on a feature branch. First
> make the stamp decision its header describes: check whether a release
> containing the 2026-09-13 and 2026-09-14 changes has been tagged, and stamp
> that release if so, or `main@<short sha>` with the date if not — never a
> release that predates the change. The sources of truth are
> `claude_dev/threat-modeling-and-security.md` (mirror it into
> `website/src/security.ts` section by section), `claude_dev/threat-model-stride.md`
> and `ThreatDragonModels/Axiam/Axiam.json` (regenerate, never hand-edit the
> generated files), and the admin, PKI, contract and changelog sources the plan
> names per Docs page. Do not add claims the source documents do not make, do
> not weaken the hedges the plan lists — the conformance result is still "165
> modules, zero FAILED on 2026-09-11, self-run, not a certification", and the
> eight modules that now pass were run individually and are never described as
> a new sweep or a plan result — keep the open risk register generated, and
> move `SECURITY_VERIFIED_RELEASE` only in the same commit as the Security
> prose. Bump `DOCS_VERIFIED_RELEASE` only if you re-read every stamped page.
> Add a News post only if a release has been tagged. Verify with the commands
> in §9, then add the EXECUTED blockquote at the top of the plan recording what
> landed, what was left, and the stamps, and open a PR that references the
> plan.
