# Website docs section — the 1.0.0-beta03 catch-up pass

> **Who this is for.** A fresh Claude session tasked with bringing the website's
> **Docs** section up to `1.0.0-beta03`. It is self-contained: read this, then
> work the waves in §7. The predecessor plan,
> [`website-docs-improvement-plan.md`](website-docs-improvement-plan.md)
> (2026-08-22, against `1.0.0-alpha38`), was executed almost completely — its
> page-deepening waves all landed — so this document is not "do that plan";
> it is the delta that has accumulated since: three releases (beta01 2026-08-26,
> beta02 2026-08-27, beta03 2026-08-28) whose features reached the website in
> exactly **five lines** (`6a3d3cf`), plus the structural debt the old plan left
> open.
>
> **The Security section is out of scope and already current.** The 2026-08-28
> threat-model pass (T-187…T-199, model 2.8.0) updated
> `ThreatDragonModels/Axiam/Axiam.json`, regenerated
> `src/threatModel.ts`/`src/threatModelSummary.ts`, mirrored the prose into
> `src/security.ts` and stamped `SECURITY_VERIFIED_RELEASE = "1.0.0-beta03"`.
> Do not touch those files except where §3.1 names one. The handoff record is in
> [`threat-modeling-and-security.md`](threat-modeling-and-security.md).

## 1. Ground rules (unchanged from the previous plan, plus one)

1. **The site is the readable front door, not the normative source.** Normative
   detail lives in `docs/`, `sdks/CONTRACT.md` and the specs; the site links out
   for anything binding (CLAUDE.md states this too). When a section below says
   "cover X", it means a readable page-level treatment plus a link to the
   normative source — not a transcription of it.
2. **Do not invent.** Every claim must be checked against the code or a document
   that was checked against the code. The commit messages cited below are
   accurate and unusually detailed; `git show -s <hash>` is a legitimate source.
3. **Check the currency of everything you touch.** A page you edit gets fully
   re-read against beta03 behaviour, not just appended to.
4. **Stamp only what you re-verify.** `DOCS_VERIFIED_RELEASE`
   (`src/version.ts:32`) is quoted per page via `DocPage.verifiedRelease`.
   Bumping the constant silently re-stamps all 18 currently-stamped pages —
   `types.ts:92-98` explicitly forbids stamping without re-deriving. So: bump
   the constant to `1.0.0-beta03` **only after** re-reading every stamped page
   in the same pass (they are listed in §6), and add the stamp to an unstamped
   page only when you have verified it end to end.

## 2. Mechanics you need (60-second recap)

- Content modules: `website/src/docs/{getting-started,authentication,authorization,oauth2,integrate,configuration,operate,reference}.ts`;
  assembly and page order in `website/src/docs/index.ts`
  (`docSectionsAreComplete()` must stay clean — it is checked in dev only).
  Note the 2:1 case: **both `configuration.ts` and `operate.ts` feed the
  "Operate" section** — a new Operate page goes in `operate.ts`.
- Block vocabulary in `website/src/docs/types.ts`: `h, p, list, code, note,
  warn, table(proseFirstCol), cards, links, steps, api, codegroup`. Prefer
  `steps` for procedures, `api` for endpoints, `codegroup` for multi-language
  samples.
- Renderer quirk: the inline renderer splits on backticks **before** it handles
  `**`, so never let a bold span enclose a code span.
- Generators (committed output, CI does not regenerate):
  `npm run gen:api-index`, `npm run gen:contract-anchors`,
  `npm run gen:threat-model` (the last one is done — leave it).
- CI gates that will catch you: `scripts/check-config-key-coverage.py` (every
  env key the server reads must appear in `website/src/docs/`),
  `scripts/check-doc-links.py` / `check-doc-links.sh`, `tsc -b`, `oxlint`.

## 3. Wave 0 — regenerate what is generated, re-pin what is pinned

Mechanical, do first, one commit:

1. `npm run gen:api-index` — `src/apiIndex.ts` is stamped `1.0.0-alpha38`,
   **181 operations / 121 paths**; the spec is at beta02+ with **195 / 132**.
   This is also what makes the new endpoints (tenant `signing-cas`,
   `sign-csr`, `migrate-custody`, `users/me/resend-verification`) appear in the
   REST page's generated index at all.
2. `npm run gen:contract-anchors` — `src/contractAnchors.ts` says
   `CONTRACT_VERSION = "1.28"` and its anchors stop at §26.6. The contract is at
   **1.32** and ends at **§27** (management API). Confirm §27 headings produce
   anchors; the compliance and SDK pages deep-link through this file.
3. `website/src/data.ts:153,312,361` — the Java, Kotlin and Swift install
   snippets pin `1.0.0-alpha38`. Re-pin to the current SDK release line (check
   each `axiam-<lang>-sdk` repo's latest tag; do not guess).
4. `website/src/docs/reference.ts:11` and `:283` — the comment and the `warn`
   block date the conformance matrix at `1.0.0-alpha38` / contract 1.28.
   Re-derive the matrix (§4.2 below) and update both.

There is **no occurrence of the string "beta" anywhere in `website/src/`**
today; when this pass is done that should no longer be true.

## 4. Wave 1 — the beta01…beta03 feature gaps (the reason this plan exists)

Ordered by user impact. For each: target page, what to say, where the truth is.

### 4.1 Organization-level principals — NEW PAGE (P1)

The largest feature of the beta line has **zero** website coverage (no hit for
`SubjectScope`, "organization-level", "organization scope" in
`website/src/docs/`).

- **New page** in the Authorization section (suggested slug `organization-scope`,
  after `rbac`), covering: the reserved organization tenant (`kind:
  organization`) and why the scope is modelled as a tenant; what an
  organization-level principal is and how it differs from a tenant principal;
  the one evaluation rule (only *global* grants carry across a tenant boundary —
  a resource-scoped grant names a resource in the organization scope and does
  not reach look-alike resources in member tenants); tenant switching with
  `X-Axiam-Tenant` (verified to stay inside the caller's organization, in-place
  switching in the admin UI, no sign-out); bootstrap now creating the
  organization scope and super-admin **without** a tenant; signing in with the
  tenant field blank (resolves to the organization scope; a blank
  `tenant_slug` means "none" — CONTRACT §5.2.1, a MUST, contract 1.32);
  `LoginUserInfo.organization_level` for SDKs (CONTRACT §5.2, contract 1.31).
- **Sources**: `docs/admin/organization-scope.md` (the normative doc, link it),
  `claude_dev/organization-scope-design.md`, `examples/b6-organization-scope/`,
  commits `d0d551f`, `fbd6203`, `4b05944`.
- Touch-ups that follow from it: `concepts` (organizations & tenants block gains
  the reserved scope), `bootstrap` (no longer creates a tenant;
  `tenant_name`/`tenant_slug` accepted-and-ignored), `auth` (login with no
  tenant named — password, OPAQUE **and** discoverable-passkey paths all
  resolve the organization scope since beta03, `4b05944`), `rbac` (grant
  reach), `service-accounts` (org-level service accounts).

### 4.2 Management API / CONTRACT §27 (P1)

§27 is implemented in **all eleven SDKs** (`0ca1fc8`, #385) and the site says
nothing (`grep -r "§27\|management API" website/src/docs/` is empty).

- `sdks` page (`reference.ts`): add a §27 column to the `CONFORMANCE` matrix
  (all eleven ✓), re-derive the whole matrix at contract 1.32, and mention
  `sdks/management-registry.json` — the third vendored artifact CONTRACT's
  header names, currently invisible on the site.
- `rest` page: a short "Managing AXIAM from an SDK" block — the management
  surface is generated from `openapi.json` + the registry (146 operations, 24
  namespaces), pagination + `search` semantics (§27.4 rule 4: `search` is
  applied server-side before `offset`/`limit`, on all twenty paginated
  operations; client-side filtering is forbidden), sparse-update vs
  full-replacement PUT classification (`befddf9`).
- While in `rest`: document the **OpenAPI content digest**
  (`info.x-axiam-spec-digest`, SHA-256 over the digest-less document,
  `check-spec-digest.py` verifies on every commit — #384/#387) in "The
  specification" section, and the admin-list **search & paging** parameters
  (`6ce5108`) — today only SCIM paging is documented.

### 4.3 PKI: tenant signing CAs, Vault custody inheritance, mTLS anchors (P1)

The `pki` page still describes a flat org-CA → leaf hierarchy, and the one
paragraph the site gained (`operate.ts:430`) now says something **wrong**: it
claims the anchor bundle applies at "the next server start", but the trust
anchor **hot-reloads** without a restart (`docs/pki/README.md` §"How it applies
without a restart"; tests in `a2ee778`).

- `pki` page: tenant signing CAs (path-length-zero intermediates signed by the
  org CA, per-tenant revocation, generate vs sign-CSR, key custody follows the
  *configured* custodian — `27fb419`); issuance refusing a validity that
  outlives the issuer, quoting the achievable number (`bacc92a`); CA key
  custody per CA with `migrate-custody` (`5ccefa2`, `fd5ce74`); the org CA as
  mTLS trust anchor with **hot reload** — and fix the stale restart claim in
  `operate.ts:430`.
- `configuration` page: the CA-custody section predates **Vault inheritance**
  (`04652c8`): no PKI-specific `AXIAM__PKI__VAULT_*` pair now means "the Vault
  you already configured", `vault_inherited` in the custody log line, and the
  startup warning for explicit database custody beside a working Vault.
- `fapi2` page (`oauth2.ts:491`): the server-TLS client-auth table is a
  **duplicate** of the one in `operate.ts` and was not updated with
  `CLIENT_CA_BUNDLE_PATH`. Either sync it or (better) collapse it to a link to
  the Operate copy so it cannot drift again.
- Link `docs/pki/README.md` from the `pki` page — 593 lines of normative PKI
  doc with no inbound link from the site (the single biggest link-out gap).

### 4.4 Authentication & settings accuracy (P2)

- `auth` (Lockout) and `settings` (Lockout policy): both predate `4891176` —
  say the threshold and backoff resolve from the **organization's effective
  settings** (org baseline, tenant tighten-only override) on every credential
  path (REST, OPAQUE, gRPC), with the deployment default only as the fail-safe
  when settings cannot be resolved.
- `auth` (Account lifecycle): add `POST /api/v1/users/me/resend-verification`
  (CONTRACT §25.7 `resend_own_verification`, contract 1.31) beside the existing
  anonymous endpoint, with the reasoning: the anonymous one answers a constant
  `200 {"sent": true}` because it must; the signed-in one reports real
  outcomes (`9faf07e`, `c3586f1`).
- `auth` (Session termination): one sentence — logout's removal cookies are
  built from the setters they mirror, so attributes match by construction
  (`e2d0ef8`/`673e55b`, beta03).

### 4.5 GDPR deletion semantics (P2)

`audit` covers erasure as actor pseudonymisation and `rest` lists the GDPR
endpoints, but nothing says what `646bc44` changed: administrator **deletion
now erases personal data** (username/email/metadata overwritten with
id-derived values; WebAuthn credentials, federation links, password history
removed) and **frees the identifiers** for genuine re-registration — while the
Art. 17 pipeline remains the only path that pseudonymises audit references and
produces an erasure proof. `docs/compliance/gdpr-compliance.md` states the
distinction; the `audit` page (and a line on `rest`) should carry the readable
version and the link.

### 4.6 Admin console changes (P3, or fold into existing pages)

Three beta features are admin-UI-facing with no home: search & paging on every
list, grant display showing what a grant reaches (`6ce5108`), certificate
handover and tenant-CA management (`ad2052c`). There is **no admin-UI page at
all**. Either add one (Operate section) or fold each into the feature's page
(`rbac` for grant reach, `pki` for certificate handover). Do not let "no page
exists" mean "never documented".

## 5. Wave 2 — link-out debt and orphan pages

`docs/` files with no website link, in priority order:
`docs/pki/README.md` (→ `pki`), `docs/admin/organization-scope.md` (→ new page),
`docs/admin/README.md` (→ `authz`/`rbac`; also the decision-cache/invalidation
story the `authz` page still lacks a heading for — an open item from the old
plan), `docs/admin/email-delivery.md` (→ `settings`/`troubleshooting`),
`docs/admin/reactors.md` (→ `reactors`), `docs/security-profiles.md`
(→ `hardening`), `docs/api/grpc.md` (→ `grpc`),
`docs/api/federated-token-exchange.md` (→ `token-exchange`),
`docs/deployment/vault.md` (→ `secrets`), `docs/compliance/sc4-coverage.md`
(→ `compliance`).

Eleven pages have **no inbound cross-link** from any other page: `amqp, audit,
auth, federation, grpc, installation, overview, rbac, rest, troubleshooting,
tutorial`. Add `cards`/`links` where a reader would actually travel (e.g.
`quickstart` → `tutorial`, `concepts` → `rbac`/`auth`, `deploy` →
`troubleshooting`). Do not force all eleven.

## 6. Wave 3 — the re-verification sweep and the stamp

Re-read the 18 stamped pages against beta03 (`tutorial, opaque, federation,
service-accounts, authz, deny, oauth2, grpc, amqp, scim, deploy, configuration,
pki, observability, hardening, troubleshooting, compliance, sdks`), correct
anything the betas moved, then bump `DOCS_VERIFIED_RELEASE` to `1.0.0-beta03`
in the same commit. Extend the stamp to the pages this pass rewrites (`auth`,
`rest`, `rbac`, `settings`, `audit`, the new pages). Leave a page unstamped
rather than stamping it unread.

Known stale content to catch in that sweep: `authentication.ts:525,641` quote
"contract 1.28" / "arrived in 1.0.0-alpha38" as history (fine, but check they
read correctly beside a beta stamp); the three thinnest OAuth2 pages
(`device-flow`, `token-exchange`, `logout`) are still one-flow pages — the old
plan's P3 for them remains open and is optional here.

## 7. Suggested execution order

1. **Wave 0** (§3) — regenerate + re-pin. One commit, no prose.
2. **Organization scope** (§4.1) — new page + the five touch-ups.
3. **Management API + REST accuracy** (§4.2).
4. **PKI + configuration + fapi2 dedup** (§4.3).
5. **Auth/settings/GDPR accuracy** (§4.4, §4.5).
6. **Admin-console coverage** (§4.6) and **link-out/orphan pass** (§5).
7. **Re-verification sweep + stamp bump** (§6). Last, deliberately: it asserts
   everything before it.

## 8. Verify before every commit

```sh
cd website
npm run gen:api-index && npm run gen:contract-anchors   # must be no-ops after Wave 0
npx tsc -b && npx oxlint
cd ..
python3 scripts/check-config-key-coverage.py
bash scripts/check-doc-links.sh
python3 scripts/check-website-links.py
```

`docSectionsAreComplete()` is dev-only; after adding a page, load the dev
server once or add a quick node check that the function returns `[]`. (Making
it a CI check is a worthwhile side quest the old plan also noted — smallest
version: a node script that imports `docs/index.ts` via vite-node or a tsx
runner and fails on a non-empty result.)
