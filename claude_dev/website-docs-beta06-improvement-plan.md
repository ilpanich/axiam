# Website docs section — the 1.0.0-beta06 cumulative catch-up pass

> **Who this is for.** A fresh Claude session (Opus 5) tasked with bringing the
> website's **Docs**, **News** and **Roadmap** content up to the beta line. It is
> the entry point: read this, then work the waves in §8.
>
> **This plan is cumulative, and that is the headline.** The predecessor,
> [`website-docs-beta03-improvement-plan.md`](website-docs-beta03-improvement-plan.md),
> was audited on 2026-08-30 and **none of it was executed — zero items landed**.
> Its own tripwire still fires: `grep -rn "beta" website/src/docs/` returns
> nothing. The last commit touching `website/src/docs` is still `6a3d3cf`, the
> five-line change that plan was written to supersede. So the work here is that
> entire plan **plus** the delta of three more releases (beta04 2026-08-28,
> beta05 and beta06 both 2026-08-30) **plus** two surfaces neither plan covered:
> News and Roadmap. §3 carries the corrections that re-base the old plan; do not
> re-derive them.
>
> **One release ahead: 1.0.0-beta07.** An issue in the SDK contract fan-out means
> a `1.0.0-beta07` will be released and is intended as **the official beta
> candidate**. At session start, check `git tag` / `CHANGELOG.md`: if beta07 is
> out, verify against it and stamp it (`DOCS_VERIFIED_RELEASE`, install pins, the
> news entry's version); if not, stamp beta06 and write the news entry so it does
> not need rewriting when beta07 lands (see §5). Never stamp a release you did
> not verify against.
>
> **The Security section is out of scope and already current.** The 2026-08-30
> threat-model pass (T-200…T-211, model 2.10.0) updated
> `ThreatDragonModels/Axiam/Axiam.json`, regenerated `src/threatModel.ts` /
> `src/threatModelSummary.ts`, mirrored the prose into `src/security.ts` and
> stamped `SECURITY_VERIFIED_RELEASE = "1.0.0-beta06"`. Do not touch those files.
> The handoff record is in
> [`threat-modeling-and-security.md`](threat-modeling-and-security.md).

## 1. Ground rules (unchanged; they are why the pass has value)

1. **The site is the readable front door, not the normative source.** Normative
   detail lives in `docs/`, `sdks/CONTRACT.md` and the specs; the site links out
   for anything binding (CLAUDE.md states this too). "Cover X" below means a
   readable page-level treatment plus a link to the normative source.
2. **Do not invent.** Every claim must be checked against the code or a document
   that was checked against the code. Commit messages in this repository are
   unusually detailed and are a legitimate source (`git show -s <hash>`), as are
   `claude_dev/e2e-findings.md` and `CHANGELOG.md`.
3. **Check the currency of everything you touch.** A page you edit gets fully
   re-read against current behaviour, not just appended to.
4. **Stamp only what you re-verify.** `DOCS_VERIFIED_RELEASE`
   (`src/version.ts:32`) is quoted per page via `DocPage.verifiedRelease`.
   Bumping the constant silently re-stamps all 18 currently-stamped pages, so
   bump it **only after** re-reading every stamped page in the same pass, and
   add the stamp to an unstamped page only when verified end to end.

## 2. Current state (verified 2026-08-30, at beta06)

What the site says today versus what is true:

| Surface | Site says | Truth at beta06 |
|---|---|---|
| `src/version.ts:32` `DOCS_VERIFIED_RELEASE` | `1.0.0-alpha38` | beta06 (beta07 imminent) |
| `src/apiIndex.ts` (generated) | `1.0.0-alpha38`, 181 ops / 121 paths | `1.0.0-beta06`, **207 ops / 142 paths** |
| `src/contractAnchors.ts` (generated) | contract `1.28`, last anchor §26.6 | contract **1.36**, includes **§27 Management API** |
| `src/data.ts:153,312,361` install pins (Java/Kotlin/Swift) | `1.0.0-alpha38` | current release |
| `src/docs/reference.ts:11,283` prose | "at 1.0.0-alpha38 / contract 1.28" | current release / contract |
| News (`src/data.ts` `POSTS`) | newest post July 2026, "before AXIAM can move to beta…"; a "seven SDKs" post | six betas shipped; **eleven** SDKs |
| Roadmap (`src/data.ts` `PHASES`, `Roadmap.tsx`) | phase 19 "hardening **toward beta**", only open phase | the beta line exists; beta07 = official beta candidate |
| `NewsIndex.tsx:30-37` | "posts are Markdown files in `content/news/`" | no such directory; posts are the TS array |
| `Benchmarks.tsx` pins `1.0.0-alpha24` | — | **deliberate** (digest-pinned benchmark image) — leave alone |
| `authentication.ts:641` "arrived in 1.0.0-alpha38" | — | historical statement, correct — leave alone |

Docs content inventory (40 pages, 7 sections, which pages are stamped, where
news/roadmap live and their exact TS shapes) is in the beta03 plan §2 and
below in §6–§7; it was re-verified unchanged on 2026-08-30.

## 3. Execute the beta03 plan — with these corrections

Work [`website-docs-beta03-improvement-plan.md`](website-docs-beta03-improvement-plan.md)
in full — every wave, nothing was consumed — applying these re-basings:

1. **Versions.** Wherever it says "beta03", read "the current release" (beta06,
   or beta07 once tagged). Its §3 regeneration targets are now: `apiIndex` at
   207 operations / 142 paths, `contractAnchors` at contract ≥ 1.36 with the
   `§27` anchors present.
2. **Contract references.** The plan cites contract 1.32. The contract is now
   ≥ 1.36; the additions since matter to its own items:
   - **§5.2.2** (acting-tenant on self-service endpoints, rule 4 added at 1.36)
     and **§5.2.3** (tenant-scoped role assignments, added at 1.35) extend the
     organization-scope page the plan's §4.1 designs — see §4.1 below.
   - The `X-Tenant-ID` → `X-Axiam-Tenant` erratum (1.36, issue #395): any docs
     prose that mentions tenant switching must name **`X-Axiam-Tenant`**. §5
     rule 2's `X-Tenant-ID` is a *different*, deliberately-unrenamed header
     that AXIAM does not read — do not conflate them (commit `76535c5` has the
     full reasoning).
3. **Its §4.1 organization-scope page grows a `tenant_scope` treatment** — the
   feature shipped in beta05 after the plan was written (see §4 item 1 below).
4. **Its §4.3d stale-restart claim** (`operate.ts:430`) is still live and still
   wrong; the trust-anchor story also gained the chain-walk requirement (§4
   item 4 below) — fix both in one edit.
5. **Its §6 stamp list is unchanged** (still 18 stamped pages, still
   alpha38-stamped). The target stamp is the release you verified against
   (§ preamble).

## 4. New docs content from beta04…beta06 (beyond the beta03 plan)

Sources: `CHANGELOG.md` (beta04–beta06), `claude_dev/e2e-findings.md`, and the
commit messages cited. Each item names the page(s) it belongs on.

1. **Tenant-scoped role assignments** (`tenant_scope`, schema 51, beta05,
   commit `16843f6`; contract 1.35 §5.2.3). The organization-scope page the
   beta03 plan §4.1 creates must cover: an organization-level account can be
   confined to named tenants of its organization; `tenant_scope` on the three
   assignment endpoints (`POST /roles/{id}/users|groups|service-accounts`);
   `reachable_tenant_ids` on `GET /auth/me` (absent = unrestricted; the login
   response deliberately omits it); a restricted account is refused
   organization-level actions, sees only the tenants it reaches in the roster,
   is refused `X-Axiam-Tenant` outside its reach, and gets no `*` wildcard;
   existing assignments are untouched (no backfill); re-scoping a grant is
   revoke + re-assign (`has_role` is never updated — `79ae471` states this as a
   documented residual). Normative source to link:
   `docs/admin/organization-scope.md` and CONTRACT §5.2.3.
2. **Organization-level actions require an organization principal** (beta05,
   `cc52db9` B-04, `4d63c53`). The `rbac` page (and the §4.1 page) should state
   plainly: creating organizations or tenants, all CA operations and the MDS
   refresh require a principal whose record lives in the organization scope —
   holding the permission from a tenant role is not enough, and tenant roles
   are no longer seeded with those actions (a boot-time reconciler revokes
   previously-seeded ones; upgrade note worth a `warn` block: grants the guard
   was already refusing disappear from tenant roles on first boot).
3. **Passkey enrolment enables MFA** (beta05, `5fa88b5` W5-01). `passkeys` and
   `mfa` pages: enrolling a passkey or security key turns the second-factor
   requirement on, exactly like confirming TOTP; removing the last one turns it
   off; an unconfirmed TOTP enrolment is never silently promoted. Link
   `docs/user/passkeys.md` (already updated in the fix).
4. **mTLS trust-anchor chain requirement** (beta05, `4fe5f55` B-06). `pki` page
   (with the beta03 plan's §4.3 items): device authentication requires the
   certificate's chain to reach a CA **enabled as an mTLS trust anchor**, on
   the proxy-terminated path as well as the native listener; the walk crosses
   tenant signing CAs (deliberately unflagged intermediates), requires every CA
   on the way Active and in date, and is depth-bounded. Operator-facing
   consequence for a `warn` block: deployments authenticating devices through a
   proxy with never-flagged CAs start seeing refusals that name the reason —
   flag the CA.
5. **Bearer-only callers and CSRF** (beta05, `21e798d` B-05). `rest` page (API
   conventions): browser sessions use the cookie + `X-CSRF-Token` pair; a
   request authenticated **only** by a bearer token needs no CSRF token; a
   bearer header alongside a session cookie is still CSRF-checked, by design.
6. **First-run honesty** (beta05, `9076cd2` B-01/B-02/B-03). `bootstrap` page:
   an empty `AXIAM_BOOTSTRAP_ADMIN_EMAIL` no longer closes the gate (compose's
   `${FOO:-}` pitfall); duplicate tenant creation answers 409, not 500; with a
   setup token, a second bootstrap is refused by the gate *before* the
   already-initialised check — deliberate, so an unauthenticated caller is not
   told whether the deployment is initialised. Also fold in the beta03 plan's
   §4.1b bootstrap corrections (no ordinary tenant is created; `tenant_name` /
   `tenant_slug` accepted-and-ignored) — that page is currently **actively
   wrong** at `getting-started.ts:347,428-429,469`.
7. **Acting-tenant self-service rule** (beta06, `8b16053`; contract 1.36
   §5.2.2 rule 4). `rest` page: with `X-Axiam-Tenant` set, endpoints on the
   caller's *own* resources (profile, password, MFA enrolment, WebAuthn
   registration, GDPR §25 requests, `/oauth2/userinfo`) resolve in the
   caller's home tenant; anybody else's id follows the header.
8. **Replica resilience** (beta05, `830fa93` B-07). `deploy` page, one
   paragraph: multiple replicas against one SurrealDB no longer invalidate each
   other's datastore sessions on boot, and a replica that is logged out
   detects it and reconnects without a restart — rolling deployments are safe.
   (Keep it short; the threat model T-207 carries the detail.)
9. **Admin-console notes** (beta06, `79ae471`, `8b16053`, `595c609`): if the
   beta03 plan's §4.6 admin-console coverage is taken up, add: role assignment
   from user and group pages carries the same resource/tenant scope pickers as
   the role page; the UI refreshes and re-gates completely on tenant switch;
   the selected tenant persists per browser tab.

## 5. The news entry (explicitly requested)

Mechanics: prepend to `POSTS` in `src/data.ts` (line ~493 — the array is
reverse-chronological and the UI does not sort). Shape and a verbatim sample
are in §7. While editing `NewsIndex.tsx`, also fix its false claim that posts
are Markdown files in `content/news/` (lines 30-37) — they are this array.

Content the entry must carry (adjust the version to what is actually released
when you run — see the beta07 note in the preamble):

- **AXIAM has officially reached the beta phase.** With `1.0.0-beta06` the
  project moved from alpha to beta; `1.0.0-beta07`, correcting an SDK contract
  fan-out issue, is intended as the **official beta candidate**.
- **Beta does not mean production-ready.** State plainly that AXIAM is still
  **not usable in production**: everything needs deeper testing.
- **Some surfaces need testing from the ground up**: federation, SCIM
  provisioning, SAML and OIDC federation are implemented but have not yet been
  exercised end to end; call them out by name so nobody reads "beta" as
  "tested".
- What the beta line has hardened so far (honest, concrete, one short
  paragraph): six releases of E2E-driven fixes — tenant-isolation and
  organization-scope enforcement, passkey/MFA correctness, mTLS trust-anchor
  verification, rolling-deployment resilience — with the threat model grown to
  211 threats and every finding written down (link the Security section).
- A pointer at how to try it (quickstart) and where to report issues.

Suggested skeleton (rewrite freely, keep the hedges):

```ts
{
  slug: "beta-phase",
  date: "<publish date>",
  dateShort: "<Mon YYYY>",
  tag: "Release",
  author: "The AXIAM team",
  title: "AXIAM reaches beta",
  excerpt:
    "Six beta releases in, AXIAM officially enters its beta phase — still not for production, but now the hardening is the work.",
  body: [
    { type: "p", text: "…beta06/beta07 story, what beta means here…" },
    { type: "h", text: "What beta does not mean" },
    { type: "p", text: "…not production-usable; deeper testing everywhere; federation, SCIM, SAML and OIDC still need complete end-to-end testing…" },
    { type: "h", text: "What has been hardened so far" },
    { type: "p", text: "…E2E matrix findings, threat model 211 threats, link #/security…" },
    { type: "p", text: "…try the quickstart, report issues on GitHub…" },
  ],
},
```

While in `POSTS`: the `seven-sdks` post (May 2026) says seven SDKs; the rest of
the site says eleven. Do not rewrite history — the post was true when written —
but the new entry (or a one-line edit to that post's excerpt) should carry the
current number so the contradiction is resolved for a reader.

## 6. The roadmap section (explicitly requested)

Where: `PHASES` in `src/data.ts:614-775` (type `Phase` in `types.ts:66-76`),
rendered by `src/pages/Roadmap.tsx`. Two hardcoded copies of the headline
numbers live outside the data: `Roadmap.tsx:37` ("64 tasks. 19 phases. And
counting.") and `Home.tsx:69-74` (`HERO_STATS`). Update all three together.

What to change:

1. **Phase 19 is stale.** Its focus reads "hardening **toward beta**" and it is
   the only non-done phase. Either close it (end date = the beta01 release,
   status done) and add a new ongoing phase for the beta line, or reword it —
   but the page must stop describing beta as future.
2. **Add the beta line as its own phase** (suggested: `n: 20`, title "Beta
   line — stabilisation toward 1.0", focus naming what beta means here:
   E2E-driven hardening, SDK contract fan-out, deeper testing of federation /
   SCIM / SAML / OIDC before 1.0; start "Aug 26, 2026", end "Ongoing",
   status "ongoing"). Note the `status` union has exactly two values; adding a
   third ("planned") means editing `types.ts:75` and `Roadmap.tsx` — only do
   that if you actually need it.
3. **Phase 17's focus lists seven SDKs** — there are eleven; fix the string.
4. **Subtitle** (`Roadmap.tsx:39-44`): update "AXIAM remains a work in progress
   until a stable release" framing to name the beta phase explicitly.
5. Keep dates in the established format ("Aug 26, 2026" — `formatRange()`
   drops the year when both ends share it, and passes "Ongoing" through).

## 7. Mechanics recap (verified 2026-08-30)

- Docs content modules: `website/src/docs/{getting-started,authentication,authorization,oauth2,integrate,configuration,operate,reference}.ts`;
  assembly + page order in `website/src/docs/index.ts` (`docSectionsAreComplete()`
  must stay clean). Both `configuration.ts` and `operate.ts` feed "Operate".
- Block vocabulary in `website/src/docs/types.ts`: `h, p, list, code, note,
  warn, table(proseFirstCol), cards, links, steps, api, codegroup`.
- Generators: `npm run gen:api-index`, `npm run gen:contract-anchors` (and
  `gen:threat-model`, which this pass must not need). Generated output is
  committed; CI does not regenerate.
- News: `Post` in `types.ts:48-64` — `{slug, date, dateShort, tag, author,
  title, excerpt, body: PostBlock[]}` with `PostBlock.type ∈ p|h|quote`.
  Existing tags: `Release`, `Milestone`, `SDKs`, `Engineering` (free-form).
  Prepend new entries; `App.tsx:42` default `postSlug` may deserve updating to
  the new entry. News navigation is `useState`-based, not hash-routed — posts
  are not deep-linkable; do not promise URLs to specific posts.
- Roadmap: `Phase` in `types.ts:66-76`; ascending `n`; see §6.
- Verify before every commit: `npm run build` (tsc + vite) and `npx oxlint`
  from `website/`; `python3 scripts/check-website-links.py` for links you add
  (external checks 403 behind the sandbox proxy — judge those by eye).

## 8. Suggested execution order

1. **Wave 0 — mechanical**: beta03 plan §3 with §3-corrections above
   (regenerate `apiIndex` + `contractAnchors`, re-pin the three install
   snippets, fix `reference.ts` prose). Commit.
2. **Wave 1 — News + Roadmap** (§5, §6 — the surfaces a visitor sees first,
   and the user's explicit asks). Commit.
3. **Wave 2 — the feature pages**: beta03 plan §4 (org-scope page first — it
   is the biggest gap and §4 items 1–2 above extend it), then the beta04–06
   items in §4 above, folding each into the page it names. Commit per coherent
   group.
4. **Wave 3 — link-out debt**: beta03 plan §5 (ten orphaned `docs/` files,
   eleven docs pages with no inbound link).
5. **Wave 4 — the re-verification sweep and the stamp**: beta03 plan §6, with
   the stamp at the release actually verified (see the beta07 note).

## 9. Out of scope

- The **Security** section (`security.ts`, `threatModel*.ts`, `version.ts`'s
  `SECURITY_VERIFIED_RELEASE`) — current as of this pass; only §3.1 of the
  beta03 plan (regenerating `apiIndex`) touches a file near it.
- The **Benchmarks** page's `1.0.0-alpha24` pins — deliberate.
- SDK repositories and the contract fan-out itself — that is the beta07 work,
  tracked outside this plan.
