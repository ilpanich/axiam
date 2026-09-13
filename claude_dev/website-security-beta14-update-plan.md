# Website — the 1.0.0-beta14 security and docs catch-up pass

> **Who this is for.** A fresh Claude session (Opus 5) tasked with bringing the
> website's **Security** section, and the **Docs**, **News** and **Roadmap**
> content the same releases touched, up to `1.0.0-beta14`. It is the entry
> point: read this, then work the waves in §4–§8. When the pass is done, add an
> **EXECUTED** blockquote at the top of this file in the style of
> [`website-security-beta11-update-plan.md`](website-security-beta11-update-plan.md),
> recording what landed, what was deliberately left, and the stamps.
>
> **This plan supersedes
> [`website-security-beta13-update-plan.md`](website-security-beta13-update-plan.md),
> which was never executed.** That plan is still the right text for everything
> beta12 and beta13 changed — its §5 (Security section checklist) and §6 (Docs
> pages) are executed **as written**, under the overrides in §5 and §6 here,
> which exist because three things moved after it was written: the model's
> numbers, the residual pass's prose, and the SDK half of two contract
> additions. Where the two plans disagree, this one wins; where this one is
> silent, that one stands.
>
> **The headline.** Three releases since the website was last re-derived at
> `1.0.0-beta11`. beta12 and beta13 carried the OpenID Connect **Basic OP**
> programme and the first runs of the OpenID Foundation's conformance suite
> (the beta13 plan's §1 table). beta14 carried the **2026-09-12 residual pass**
> ([`remediation-plan-2026-09-12.md`](remediation-plan-2026-09-12.md), R-1…R-8)
> and, the next day, its **SDK fan-out**: the revocation-feed poller and the
> mTLS-alias handling in all eleven SDKs, which closed **T-39 and T-143** — two
> Medium items open since the first version of the model. The Threat Dragon
> model is at **2.14.0 — 266 threats, 253 mitigated / 13 open**, with the
> authentication diagram carrying **no open item**. The generated files under
> `website/src/` still render **236 / 220 / 16** at model 2.11.0, the Security
> prose is at `1.0.0-beta11`, `SECURITY_VERIFIED_RELEASE` says so, the
> contract anchors are at 1.39 against a contract at **1.44**, and the API
> index is six paths short.

**Sources of truth, in order.** [`threat-modeling-and-security.md`](threat-modeling-and-security.md)
(the website section's source, current as of 2026-09-13 — its handoff block
records each wave), [`threat-model-stride.md`](threat-model-stride.md) (the
STRIDE model, mirroring the JSON), `ThreatDragonModels/Axiam/Axiam.json` (the
model the generator reads), and for the Docs pages the admin, deployment,
compliance and conformance documents named per item in §6 here and in the
beta13 plan's §6. The website is the readable front door; it links out for
anything binding and **never carries a claim these documents do not**.

---

## 1. What moved between beta13 and beta14

The beta11 → beta13 table is the beta13 plan's §1 and is not repeated. What
moved after it:

| Release | Security-relevant change | Threats |
|---|---|---|
| beta14 | **R-1** one declared personal-data inventory for the `user` table (`axiam_core::personal_data::USER_COLUMNS`), both erasure statements rendered from it, a test that introspects the live schema after migrations and fails on a column classified nowhere — and the other way round | T-261 amended (residual gone) |
| beta14 | **R-2** the OIDC Core §5.5 `claims` request rides the refresh token (schema v61) and rotation copies it, so a refreshed access token asserts what the code-exchanged one did; the release filter still runs only at the authorization endpoint | T-241 amended |
| beta14 | **R-3** one `WARN` at boot when `AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID` does not parse — describing the value's shape, never the value; nothing on the request path; discovery unchanged | T-244 amended |
| beta14 | **R-4** a contended write that stays lost answers **`503` + `write_contention` + `Retry-After: 1`** over REST and `UNAVAILABLE` over gRPC, not `500`; uniqueness and state preconditions keep `409`; SDKs need no change (§16 already treats `5xx` as transient and honours `Retry-After` as a floor; a contended `PATCH` is never auto-retried) | T-262 amended |
| beta14 | **R-5** `db_username`, `db_password`, `amqp_url` fetched through the secret provider in the same round trip as the other eleven secrets — the Vault token (or the `file` mount) is the only credential a container spec must carry; the env vars stay permanently (`env` is a provider kind); a non-`env` deployment that still supplies one gets a `WARN` naming the variable; `just vault-seed` carries them and never invents them; `DbConfig`/`AmqpConfig` redact | T-132 amended (residual gone); T-180 amended (three more secrets behind the one credential) |
| beta14 | **R-6, server** `AXIAM__AUTH__REVOCATION_FEED_ENABLED` (default `false`): `GET /oauth2/revocations` publishes the base64url SHA-256 of each session id revoked within the last access-token lifetime, nothing else; bounded, cacheable (`ETag`), unauthenticated by argument; off means not mounted, no row written; three revocation paths publish, the two single-use redemptions do not; schema v62; contract 1.44 §10.4 | T-39, T-143 narrowed, **kept Open** |
| beta14 | **R-6, SDKs (2026-09-13)** every SDK ships a §10.4 poller — opt-in, never on the request path, never fail-closed (unreachable / non-`200` / unparseable / unknown `alg` verify as with no feed, never as an empty list), reject-only, no `sid` never matched; contract §10.4.1 records the attachment point per SDK, no row `declines`; PRs rust #104, typescript #103, python #80, java #92, kotlin #62, csharp #87, php #67, go #77, swift #60, c #59, cplusplus #60, each released at that SDK's `1.0.0-beta14` | **T-39, T-143 closed** |
| beta14 | **R-7** `AXIAM__AUDIT__MINIMISE` (default `false`): client address truncated to `/24` or `/48`, user-agent reduced to a family, immediately before the append; an unparseable address dropped; structured accountability metadata untouched; deployment-wide, not per tenant; both states logged at startup | T-110 closed (already counted in the beta13 plan's numbers) |
| beta14 | **R-8, contract 1.43** §21.3 rule 2 clause 4 (preserve an alias's query component — no appending, no stripping; displacing the tenant is correct), §21.3.1 vectors A/B/C inside `CONTRACT.md`, vector C **refused** not fallen back from; §21.10 per-SDK table | T-266 amended |
| beta14 | **R-8, SDKs (2026-09-13)** the same eleven PRs: §21.10 reads `yes` in both columns for every SDK, vector C refused at the point of use | T-266 amended (residual gone) |
| beta14 | A hygiene fix: the two R-5 redaction tests mint their fixture password through `axiam_test_support::test_password` rather than writing a literal a secret scanner cannot tell from a real one; no scanner exemption added | T-260 amended |

The open register loses **T-39 and T-143** (and T-110, which the beta13 plan's
numbers already excluded). It keeps the accepted-trade-off bullet for the
fifteen-minute window, rewritten: the window is now *fifteen minutes or one poll
interval*, the feed narrows the trade rather than removing it, and both sides
are opt-in. The authentication diagram goes to **0 open**, the SDK diagram to
**3**, Medium-severity open to **3**, elevation-of-privilege open to **1**.
**Check the model rather than this paragraph** — Appendix A is what the
generator must print.

## 2. Ground rules (unchanged from the beta13 plan; they are why the pass has value)

- **Do not upgrade the hedges.** "No open Critical or High finding *in AXIAM's
  own request path*", "self-assessment, not a certified audit", "a self-run
  against a working-tree build, not a certification", and the beta caution are
  all load-bearing. The conformance result is **zero `FAILED`**, never "passed"
  or "certified". The revocation feed is **a narrowing, not a control** — every
  sentence about it on the site says so, as the source document does.
- **Do not add claims.** Every sentence in `threat-modeling-and-security.md` is
  backed by code, a commit, a merged SDK PR or a conformance receipt. Copy its
  prose; do not improve it.
- **Keep the shared-responsibility section**, and keep the open register
  generated. T-39, T-110, T-143 and T-254 do **not** appear in it. The
  **Accepted, documented trade-offs** bullets stay, in the post-beta14 shape
  the source now carries (the window bullet, the audit bullet with
  minimisation, the FAPI grace bullet). The **new Integration bullet** —
  attach the poller where sign-out must be faster than a token lifetime, and
  turn the feed on server-side — *is* an integrator responsibility.
- **Mirror, do not paraphrase.** `src/security.ts` mirrors the Markdown section
  for section; the three bullets whose bold markers deliberately differ stay as
  they are, for the reason recorded in the handoff block.
- **Stamps record verification, not releases.** `SECURITY_VERIFIED_RELEASE`
  moves only with the Security section; `DOCS_VERIFIED_RELEASE` is one constant
  stamped on 30 pages, so bumping it re-asserts every one of them — §8 says what
  that costs.
- **The model's new element is not yours to draw around.** The OAuth2 diagram
  gained a process at model coordinates `(370, 640)` and two flows at beta13;
  the generator lays them out. If a label overlaps, adjust coordinates in the
  JSON and regenerate — never edit `threatModel.ts` by hand.

## 3. Current state (verified 2026-09-13, at beta14)

| What | Where | State |
|---|---|---|
| Security stamp | `website/src/version.ts` | `SECURITY_VERIFIED_RELEASE = "1.0.0-beta11"`, `SECURITY_VERIFIED_DATE = "2026-09-04"` |
| Docs stamp | `website/src/version.ts` | `DOCS_VERIFIED_RELEASE = "1.0.0-beta11"` |
| Generated model | `website/src/threatModel.ts`, `threatModelSummary.ts` | 236 threats / 220 / 16, model 2.11.0 — `node scripts/gen-threat-model.mjs` was run against 2.14.0 on 2026-09-13 and printed `threatModel.ts: 9 diagrams, 266 threats (253 mitigated, 13 open)`, then **reverted** so the generated files and the prose move together |
| Security prose | `website/src/security.ts` | At beta11: everything the beta13 plan's §3 lists is still missing, plus everything in §5 here |
| Contract anchors | `website/src/contractAnchors.ts` | `CONTRACT_VERSION = "1.39"` — `gen:contract-anchors` was run on 2026-09-13 and produced `167 sections at contract 1.44`, then reverted |
| API index | `website/src/apiIndex.ts` | 213 operations / 148 paths — `gen:api-index` was run and produced **219 operations across 153 paths, 11 domains**: `POST /oauth2/userinfo`, the three consent paths, `GET /api/v1/users/{user_id}/sessions` (T-254) and `GET /oauth2/revocations` (T-39), then reverted |
| News | `website/src/data.ts` — post `beta-phase` ("AXIAM reaches beta") | Addendum dated 5 September 2026 says "236 threats, 220 mitigated and 16 open" |
| Roadmap | `website/src/data.ts` — phase 20 "Beta line — stabilisation toward 1.0" | `focus` ends at "Vault run as a production secret store"; nothing about Basic OP, conformance, the residual pass or the SDK fan-out |
| Docs pages already touched since beta11 | `configuration.ts` carries rows for `AXIAM__AUTH__REVOCATION_FEED_ENABLED` and `AXIAM__AUDIT__MINIMISE` (the config-key-coverage gate put them there — verify each row's description against `docs/deployment/README.md`, do not rewrite it), plus the four rows the beta13 plan names. Nothing else on the site mentions the feed, the sessions endpoint, minimisation, `write_contention` or the three provider-supplied credentials | Everything else in §6 is new work |

The explorer (`src/components/ThreatModelExplorer.tsx`) needs no functional
change. Open the **authentication** diagram first in the built site
(`#/security/diagram/1`): it carries 33 threats and, for the first time, **no**
open item, so the open-only filter there must show an empty list, exactly as
on the OAuth2 diagram (`#/security/diagram/2`). T-39 is on diagram 1 and T-143
on diagram 8, both Mitigated; either surfacing under the open-only filter means
the model was regenerated from a stale JSON.

## 4. Wave 0 — regenerate

Run from `website/`, in this order, and commit the generated files together with
the prose that describes them (Wave 1), never alone:

```sh
npm run gen:threat-model     # expect: threatModel.ts: 9 diagrams, 266 threats (253 mitigated, 13 open)
npm run gen:api-index        # expect: apiIndex.ts: 219 operations across 153 paths, 11 domains
npm run gen:contract-anchors # expect: contractAnchors.ts: 167 sections at contract 1.44
```

Read the `threatModel.ts` diff once: the OAuth2 diagram gains the process
`Resource-endpoint token validation (cnf, DPoP jti, sid)` at model coordinates
`(370, 640)` and two flows (`validate presented token`, from the resource-server
actor; `check session, record proof jti`, to the access/refresh token store).
The open register loses T-39, T-110 and T-143 against what the site renders
today and gains nothing. No generated file is hand-edited.

## 5. Wave 1 — the Security section

Execute the beta13 plan's §5 table row by row, then apply these overrides and
additions. The Markdown is the text; the source document was re-derived on
2026-09-13 and every sentence below is already in it.

| `security.ts` section | Override / addition |
|---|---|
| Security at a glance | As the beta13 plan says ("266 threats"; the conformance-suite clause) |
| The threat model | Table: 266 threats, **253 / 13** (not 250 / 16). Coverage by area is generated — confirm the page renders 266 / 13, **Authentication 33 / 0**, OAuth2 47 / 0, Audit 18 / 1, **SDKs 28 / 3**, and that the rows match Appendix A. The paragraph after the area table keeps the "no open finding at all" and T-254 sentences, and gains the closing sentence: the two Medium items on the token service and the SDK guard — the fifteen-minute window seen from each side — closed together at beta14 when the feed gained a poller in all eleven SDKs (T-39, T-143). The by-category and by-severity tables are generated; the prose sentence after them says **13** still-open items |
| Trust boundaries | As the beta13 plan |
| Authentication & sessions | As the beta13 plan for the **Tokens** bullet, then **one new bullet** immediately after it: *Sign-out can reach a token before it expires, without a round trip per request* — the fifteen-minute window, `GET /oauth2/revocations` off by default, hashes and nothing else, bounded by the revocation rate over fifteen minutes, cacheable like the JWKS, polled by every SDK guard, and "a narrowing and deliberately not a control" with its three clauses. The **SCIM** bullet gains the contended-write sentence (`503` + `Retry-After: 1`, not `500`, and why an IdP cares) |
| Authorization & tenant isolation | Unchanged |
| OAuth2 & OpenID Connect | As the beta13 plan (six new bullets etc.). No beta14 change to this section's prose — the R-2 and R-3 items are Docs-page material (§6) |
| Federation (SAML & OIDC) | As the beta13 plan |
| PKI, certificates & device identity | As the beta13 plan |
| Audit & accountability | **One new bullet** after *Retention is bounded by default*: *Collection is bounded too, where a lawful basis needs it* — `AXIAM__AUDIT__MINIMISE`, the two reductions before the append, an unparseable address dropped, structured accountability metadata untouched, deployment-wide and not per tenant, both states logged |
| Webhooks, email & messaging | Unchanged |
| Transport, secrets & the SDKs | **Secrets at rest**: the redacting-`Debug` sentence now names "the three types the beta13 wave added, the datastore and broker configuration (…), and the test assertions…" and keeps the Vault-CA-bundle clause. **Long-lived secrets come from a pluggable secret provider**: gains the beta14 sentences — the three credentials through the same provider in the same round trip, the Vault token or `file` mount as the only credential a spec must carry, the env vars as a permanent supported fallback with the boot `WARN`, and the seeder never inventing them. **The eleven client SDKs**: the alias sentence gains "preserves the alias's query component rather than appending to it, and refuses a malformed alias outright … since 1.0.0-beta14 in all eleven SDKs, against three test vectors the contract itself publishes". **One new bullet** after *A guard decides on the caller's credential and no other*: *Every SDK route guard can poll the revocation feed* (contract §10.4) — off unless attached, never on the request path, never fail-closed with the four cases and the empty-list clause, reject-only, no `sid` never matched, all eleven implement it, an unrecorded row is not a supported answer. The *admin UI redacts what a gateway echoes* bullet from the beta13 plan stays |
| Compliance posture | The **GDPR** row's status: replace the explicit-column-list clause with "every personal-data column of the user record is classified in one declared inventory that both erasure statements and the export render from, and a test introspects the live schema after migrations and fails on any column the inventory does not classify". The **OAuth2 / OIDC** row as the beta13 plan |
| Shared responsibility | "**13** of 266". The register is generated — confirm T-39, T-110, T-143 and T-254 are absent and the thirteen of Appendix A are present in that order. **Platform & operations → Run Vault**: the sentence "The datastore and broker credentials are still env-supplied…" is replaced by the beta14 sentence (leave the three variables blank on a provider deployment; the boot `WARN`; etcd encryption either way). **Integration & SDKs**: the beta13 plan's `client_secret_basic` bullet, plus **one new bullet** *Attach the revocation-feed poller where sign-out has to take effect faster than a token lifetime*. **Accepted, documented trade-offs**: the window bullet becomes *Access tokens survive revocation for up to 15 minutes — or one poll interval* with its three sentences; the audit bullet gains the `AXIAM__AUDIT__MINIMISE` clause; the FAPI-grace bullet as the beta13 plan |
| How security is maintained | The beta13 plan's new bullet; closing sentence: last re-derived at **`1.0.0-beta14`** on **2026-09-13** |

Then `src/version.ts`: `SECURITY_VERIFIED_RELEASE = "1.0.0-beta14"`,
`SECURITY_VERIFIED_DATE = "2026-09-13"`. That constant is what the page quotes;
it moves in the same commit as the prose, never earlier.

## 6. Wave 2 — Docs pages the same releases changed

Execute the beta13 plan's §6 table as written — every row, every source — with
the corrections below, then the additions. Two sources are new for beta14 and
should be opened first: `docs/deployment/README.md` (the *Session revocation
feed*, *Audit collection minimisation* and *Errors* sections) and
`docs/deployment/vault.md` (*The datastore and broker credentials*).

**Corrections to the beta13 plan's rows**

| Page (slug) | Correction |
|---|---|
| `scim` | "the concurrent-PATCH write conflict is retried rather than returned as `500`" becomes: retried, and if it stays lost answered **`503` with slug `write_contention` and `Retry-After: 1`** — not `409` (which in SCIM means the request conflicts with the resource's state, RFC 7644 §3.12) and not `500` (which an IdP reads as a failed sync). Source `docs/deployment/README.md` *Errors*; T-262 |
| `oauth2` | The **Discovery** item: `AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID` "states a fact and changes no endpoint" gains "an unparseable value is ignored and **reported once at boot**, describing the value's shape and never the value" (T-244). A new item under **Tokens**: a `claims` request (OIDC Core §5.5) is carried across a refresh — the refreshed access token asserts the same requested claims as the code-exchanged one; the release filter still runs only at the authorization endpoint, and every consent gate is re-asked at UserInfo (T-241, schema v61) |
| `sdks` | Contract **1.44**, not 1.42. Add: 1.43 — §21.3 rule 2 clause 4 (preserve the alias's query component; displacing the tenant is correct) and the §21.3.1 vectors inside the contract, vector C refused; 1.44 — §10.4 the optional revocation-feed poller with its four rules and the SHOULD level, §10.4.1 per SDK. **SDK code did change** for both, in all eleven, released at each SDK's `1.0.0-beta14`; say so and link §10.4.1 and §21.10 through the contract anchors. Drop "no SDK code changed for any of the three" — true at 1.42, false at 1.44 |
| `compliance` | The GDPR row as §5 here (the declared inventory and the schema gate), not the explicit-column-list warning |
| `configuration` | Two more rows exist — **verify, then extend**: `AXIAM__AUTH__REVOCATION_FEED_ENABLED` and `AXIAM__AUDIT__MINIMISE`, both against `docs/deployment/README.md`. Add: `AXIAM__DB__USERNAME`, `AXIAM__DB__PASSWORD`, `AXIAM__AMQP__URL` rows (or their existing rows) gain "resolvable through the secret provider as `db_username` / `db_password` / `amqp_url` since beta14; leave blank on a Vault or `file` deployment; a non-`env` deployment that still sets one is warned at boot" |

**Additions for beta14**

| Page (slug) | What to add | Source |
|---|---|---|
| `oauth2` | In the endpoint table: `GET /oauth2/revocations` (optional, public, off by default) — the document's four members (`alg`, `issued_at`, `ttl`, `revoked`), what an entry is (base64url SHA-256 of the `sid` string), what it never carries, that it is bounded by one token lifetime and cacheable, and that it is a narrowing and not a control. Link the `configuration` row and the SDK contract §10.4 anchor | `docs/deployment/README.md` *Session revocation feed*; `sdks/CONTRACT.md` §10.4; T-39 |
| `rest` | `GET /oauth2/revocations` and `GET /api/v1/users/{user_id}/sessions` (T-254: per-session replay counters, `fapi_grace_retry` / `replay_refused`) in the endpoint listings, alongside the beta13 additions | `sdks/openapi.json`; CHANGELOG beta14 *A refresh token presented after rotation is now recorded* |
| `auth` | One paragraph on the **Sessions** view: `GET /api/v1/users/{user_id}/sessions`, surfaced in the admin UI as a *Sessions* action per user, with the amber "FAPI grace retry" and red "Replay refused" badges; a `refused` is worth alerting on, a `fapi_grace_retry` on a `fapi2` client is the mechanism working | CHANGELOG beta14; T-254 |
| `audit` | A section on **collection minimisation**: `AXIAM__AUDIT__MINIMISE`, the table of the two reductions, the unparseable-address rule, what is deliberately untouched and why, deployment-wide not per tenant, erasure and export unaffected, both states logged at startup. Keep the retention section beside it: retention bounds how long, minimisation bounds what | `docs/deployment/README.md` *Audit collection minimisation*; T-110, T-119 |
| `secrets` | Under the provider section: the three credential fields (`db_username`, `db_password`, `amqp_url`) with their environment fallbacks in a table; that until beta13 they were the one class of secret that had to be in the container spec; that the Vault policy needed no change (path-based, not field-based); that `just vault-seed` carries an operator's values forward and never invents a datastore password, and an existing value always wins; the boot `WARN` on a non-`env` provider | `docs/deployment/vault.md` *The datastore and broker credentials*; T-132 |
| `errors` | The `503` `write_contention` row with `Retry-After: 1`, marked retryable; why not `409` or `500`; over gRPC `UNAVAILABLE`, distinct from `RESOURCE_EXHAUSTED`; SDK retry policy already honours it as a floor, and a contended `PATCH` is not auto-retried | `docs/deployment/README.md` *Errors*; T-262 |
| `hardening`, `deploy` | Two opt-ins to consider before go-live: the revocation feed (turn it on where sign-out must be faster than fifteen minutes and per-request introspection is too expensive; off means one fewer public endpoint; "a feed nobody polls narrows nothing", so pair it with the SDK poller) and audit minimisation (a lawful-basis decision; reduces forensic precision). And the credential move: on a Vault or `file` deployment the three env vars are left blank | `docs/deployment/README.md`; `docs/deployment/vault.md` |
| `troubleshooting` | Three new signatures: a boot `WARN` naming `AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID` (the value is not a UUID; discovery serves the tenant-less document); a boot `WARN` that a datastore or broker credential "was read from the environment; the configured secret provider has no entry for it" (move it into the provider, or leave it — it is a warning, not a refusal); the two startup lines for audit minimisation and the two for the revocation feed, so an operator can read the posture in force from the log | `crates/axiam-server/src/main.rs` (the four `tracing::info!`/`warn!` sites); CHANGELOG beta14 |
| `sdks` | Per-SDK: a short table or sentence that every SDK ships `RevocationFeed` (the C SDK's `axiam_client_enable_revocation_feed`) with the attachment point from §10.4.1, and that each was released at `1.0.0-beta14` | `sdks/CONTRACT.md` §10.4.1, §21.10; the eleven SDK `CHANGELOG.md` files |

Pages **not** to touch for this pass: `opaque`, `mfa`, `passkeys`,
`service-accounts`, `device-flow`, `token-exchange`, `authz`, `rbac`,
`organization-scope`, `deny`, `uma`, `grpc`, `amqp`, `webhooks`, `reactors`,
`observability`, `overview`, `quickstart`, `installation`, `bootstrap`,
`concepts`, `tutorial`. Re-read them in Wave 4; do not rewrite them in Wave 2.
(`audit` leaves that list for this pass; `pki` and `logout` are in the beta13
plan's table.)

## 7. Wave 3 — News and Roadmap

- **News.** Do not rewrite "AXIAM reaches beta" and do not touch its 5 September
  addendum; both were true when written. Add **one new post**, dated
  13 September 2026, tag `Release`, covering beta12 → beta14 — the beta13
  plan's post, extended rather than a second post. Its paragraphs: the Basic
  OP waves and the conformance suite run for the first time (four plans, 165
  modules, zero `FAILED`, receipts committed green and red alike, **not a
  certification**); what the suite found, naming the hole
  ([T-246](#/security/diagram/2/T-246)) and the resource-endpoint replay
  ([T-247](#/security/diagram/2/T-247)) plainly; the residual pass — five
  residuals inside entries the model already called Mitigated, made structural,
  and two open entries whose remedy had never been built, now built; the SDK
  fan-out the next day, eleven repositories, and what it closed
  ([T-39](#/security/diagram/1/T-39), [T-143](#/security/diagram/8/T-143)),
  with the honest residual (one poll interval, both sides opt-in); and the
  model: **266 threats, 253 mitigated / 13 open**, the authentication diagram
  with no open item, and the one item the beta13 wave opened on the request
  path ([T-254](#/security/diagram/2/T-254)) recorded rather than absorbed and
  then closed by a decision in the same release. Every anchor checked against
  the generated model (the diagram index in the anchor is the diagram's
  position in the model's order: 1 authentication, 2 OAuth2, 8 SDKs). Keep the
  beta caution in the post's own words.
- **Roadmap.** Phase 20 stays `ongoing`. Extend its `focus` with "the OpenID
  Connect Basic OP surface, the first OpenID Foundation conformance runs, and
  the residual pass that made the model's remaining caveats structural — with
  the SDK half of every contract addition landed in all eleven repositories".
  Do not close anything and do not add a phase; a certification submission is
  not on the roadmap until one is made.

## 8. Wave 4 — sweep and stamp

`DOCS_VERIFIED_RELEASE` is stamped on 30 pages through one constant, so bumping
it to `1.0.0-beta14` asserts that every one of them was re-read against beta14.
Either do that — the beta11 pass found four real errors this way — or leave the
constant at beta11 and say so in the EXECUTED note. Do not bump it because Wave
2 touched some pages.

Claims most likely to have gone stale, to check first on every page that carries
them: everything the beta13 plan's §8 lists, plus: "a revoked token stays valid
until it expires" with no mention of the feed; "verify through introspection" as
the *only* answer to revocation reach; "the datastore credentials must be set as
environment variables"; any `500` on a write conflict; any list of the secret
provider's contents that says "ten" or "eleven" without the three credentials;
any statement that a `claims` request is honoured on the first token only; any
count of threats, mitigated or open; any contract version.

## 9. Verification

```sh
cd website
npm ci
npm run gen:threat-model && npm run gen:api-index && npm run gen:contract-anchors
git diff --stat                      # only the files this plan names
npm run build                        # tsc -b && vite build
npm run lint                         # oxlint
grep -rn "236 threats\|220 mitigated\|16 open\|15 open\|251 mitigated\|beta11\|beta13" src/ | grep -v threatModel.ts   # expect only the historical news addendum
cd .. && scripts/check-doc-links.sh
```

`docSectionsAreComplete()` in `website/src/docs/index.ts` asserts navigation and
content agree; the build runs it. Open `#/security/diagram/1` and
`#/security/diagram/2` in the built site with the open-only filter and confirm
both are **empty**; open `#/security/diagram/1/T-39` and confirm it selects the
token-service node and renders Mitigated; open `#/security/diagram/2/T-246` and
confirm it selects the new node.

## 10. Out of scope

- Server work. Everything this plan describes shipped by 2026-09-13; nothing
  here re-opens a decision.
- A conformance *submission*. The receipts are self-run; the website must not
  say or imply otherwise.
- The eleven SDK repositories' own READMEs and changelogs, which already carry
  contract 1.43–1.44.
- Threat Dragon diagram aesthetics beyond what the generator lays out.

---

## Appendix A — the numbers (model 2.14.0, 2026-09-13)

Headline: **266 threats, 253 mitigated / 13 open**, 9 diagrams, `threatTop` 266.

| Area | Threats | Open |
|---|---|---|
| System context | 31 | 2 |
| Authentication & session management | 33 | 0 |
| OAuth2 / OIDC authorization server | 47 | 0 |
| Federation (SAML SP & OIDC RP) | 31 | 1 |
| Authorization engine (RBAC, hierarchy, scopes) | 26 | 0 |
| PKI, certificates & IoT device identity | 25 | 1 |
| Audit, webhooks, email & notifications | 18 | 1 |
| Deployment & platform (Kubernetes) | 27 | 5 |
| Client SDKs & admin-UI integration surface | 28 | 3 |

By STRIDE category: Spoofing 66 (3 open), Tampering 57 (1), Repudiation 6 (0),
Information disclosure 65 (6), Denial of service 24 (2), Elevation of
privilege 48 (1). By severity: Critical 30 (1 open), High 122 (8), Medium 106
(3), Low 8 (1). The open items, most severe first: T-148, T-18, T-94, T-124,
T-133, T-135, T-146, T-180, T-216, T-9, T-123, T-134, T-161. Every one of these
numbers is emitted by the generator; they are here so a wrong regeneration is
noticed, not so they can be typed in.

## Appendix B — the prompt for the session that executes this plan

> Read `claude_dev/website-security-beta14-update-plan.md` in the `ilpanich/axiam`
> repository and execute it, waves 0 to 4 in order, on a feature branch. It
> supersedes `claude_dev/website-security-beta13-update-plan.md`, which was
> never executed: that plan's §5 and §6 tables are part of the work and are
> executed as written, under the overrides the beta14 plan lists. The sources
> of truth are `claude_dev/threat-modeling-and-security.md` (mirror it into
> `website/src/security.ts` section by section), `claude_dev/threat-model-stride.md`
> and `ThreatDragonModels/Axiam/Axiam.json` (regenerate, never hand-edit the
> generated files), and the admin, deployment, compliance and conformance
> documents the two plans name per Docs page. Do not add claims the source
> documents do not make, do not weaken the hedges the plan lists — the
> conformance result is "zero FAILED, self-run, not a certification", never
> "passed" or "certified", and the revocation feed is a narrowing, never a
> control — keep the open risk register generated, and move
> `SECURITY_VERIFIED_RELEASE` to `1.0.0-beta14` only in the same commit as the
> Security prose. Bump `DOCS_VERIFIED_RELEASE` only if you re-read every
> stamped page. Verify with the commands in §9, then add the EXECUTED
> blockquote at the top of the beta14 plan recording what landed and what was
> left, and open a PR that references both plans.
