# Fix plan — Issues #469, #470, #471, #472 (T21.8 findings MCP-03, MCP-04, MCP-05, MCP-01)

**Date:** 2026-09-17
**Validated against:** `main` @ `881d7feb9` (Phase 21 merged; carries T21.1–T21.9d)
**Source of the findings:** [`security-review-mcp-2026-09-17.md`](security-review-mcp-2026-09-17.md)
§§3–7; threat model rows T-276, T-275, T-272, T-280 in
[`threat-model-stride.md`](threat-model-stride.md) §5.3 and §6.
**Verdict: fix all four now, and the IPv6 loopback gap with them; keep MCP-06
accepted.** Two of the four are cheaper than filed, one is more expensive than
filed, and one changes which of the other three matters. Details below, in the
order the work should be done.

| Issue | Finding | Severity as filed | Decision | Effort | Touches generated artifacts? |
|---|---|---|---|---|---|
| [#469](https://github.com/ilpanich/axiam/issues/469) | MCP-03 — `trusted_client_id_domains` refuses `[]` and admits `*` | Medium | **Fix now.** One condition in the validator that already holds the empty-list refusal | Small | No |
| [#470](https://github.com/ilpanich/axiam/issues/470) | MCP-04 — `cimd` shadow rows have no quota and no sweep | Medium | **Fix now**, and it needs **no migration**: the row is upserted on every resolve, so `updated_at` is already the last-seen stamp the issue asks to add | Medium | Yes (a doc comment on a `ToSchema` field) |
| [#471](https://github.com/ilpanich/axiam/issues/471) | MCP-05 — a stranger fills `dcr_max_clients` in four minutes and holds it for thirty days | Medium | **Fix now**, as a second clock on the sweeper. The per-IP quota share is **not now**, and the condition that would change that is named | Medium–Large: it is a settings field, which is the most expensive kind of change this repo has | Yes (new field, spec + registry + SDK re-sync) |
| [#472](https://github.com/ilpanich/axiam/issues/472) | MCP-01 — six error paths compare `redirect_uri` exactly | Low | **Fix now.** Mechanical, own commit, inverts one test deliberately | Small | No |
| — | `http://[::1]/…` cannot be registered (docs/admin/dynamic-client-registration.md) | unfiled | **Fix in the same PR as #472**, own commit, flagged as the one change that makes a refused request succeed | Trivial | No |
| — | MCP-06 — tenant-path guard reads the raw query string | Informational | **Stay accepted.** Reopen conditions named | — | — |

---

## 0. How to read this document

The brief for this plan was to decide before planning: every one of the four
has a defensible leave-it case — three are unreachable on default settings and
the fourth is fail-closed — and a filed issue is not automatically a fix. Each
section below therefore opens with the leave-it case stated as strongly as I
can state it, and then says why it loses (or, for the per-IP share and the
race overshoot, why it wins).

Cost is counted per the checklist PR #474 taught the series: a settings field
means the org-baseline interlock, both validators, the admin card and the spec;
any `ToSchema` field or doc comment means `sdks/openapi.json` **and**
`sdks/management-registry.json`, enforced by two different CI jobs; a schema
change means migration v66 and the tripwire in `crates/axiam-db/src/schema.rs`.
Where a fix avoids one of those, that is said, because it is what reordered two
of the decisions here.

**Nothing in this document is implemented.** It is a plan for a later session.

---

## 1. What reading `main` established that the filings did not have

The issues were written against `claude/t21-8-mcp-harness`, from the review's
reading of five surfaces. Reading the merged code for this plan turned up six
facts that change the cost or shape of a fix. They are listed here once so the
sections below can refer to them.

1. **A CIMD shadow row is written on every resolve, not on every fetch.**
   `materialise_if_cimd` (`crates/axiam-api-rest/src/cimd.rs:154`) calls
   `upsert_cimd_client` after every successful `cimd::resolve`, and resolve
   returns from the in-memory cache on a hit — so the upsert runs whether or
   not a fetch happened. The `UPDATE` arm of `upsert_cimd_client`
   (`crates/axiam-db/src/repository/oauth2_client.rs:513`) sets
   `updated_at = time::now()` and does not touch `last_authorized_at`. It is
   called from authorize, token and PAR (`handlers/oauth2.rs:1182`, `:1912`,
   `:5051`). **`updated_at` on a `cimd` row is therefore already "last
   presented"**, with a resolution of one request. #470's `last_resolved_at`
   column, the v66 migration, the tripwire bump and the additivity test are
   all unnecessary.
2. **`last_authorized_at` is stamped on `cimd` rows too.** `touch_last_authorized`
   guards on `managed_by != 'admin'`, not `== 'dcr'`, and the `CREATE` arm of
   the upsert is the only place it is reset. So a sweep that reads
   `max(updated_at, last_authorized_at, created_at)` is strictly safe.
3. **There is no admin UI for the CIMD policy.** `frontend/src/services/settings.ts`
   and `frontend/src/pages/settings/SettingsPage.tsx` contain no reference to
   `cimd` or any of its nine fields; T21.5 shipped without a T4b-equivalent
   and `check-frontend-coverage.py` did not notice because the resolver lives
   in `src/cimd.rs`, not under `handlers/`. Consequence for this plan: #469
   and #470 have **no client-side refusal to mirror**, which removes the most
   error-prone item on the checklist. Consequence for the roadmap: an operator
   can only set a CIMD posture through the API, and that gap deserves its own
   entry — it is not this plan's.
4. **Both settings doors already run the same validator.** `validate_cimd_policy`
   is called from `validate_org_settings` (`settings.rs:1228`) and from
   `validate_tenant_override` on the merged policy (`settings.rs:1982`). A
   condition added to it is enforced at both doors with no second edit. Two
   existing tests use `["*"]` as a convenient org fixture
   (`a_tenant_may_state_a_stricter_cimd_posture`,
   `the_cimd_posture_merges_and_diffs_whole`) and will need a different
   fixture; neither asserts anything about `*`.
5. **Doc comments on settings fields are in the OpenAPI spec.** `dcr_max_clients`'s
   description in `sdks/openapi.json:16615` is its Rust doc comment verbatim.
   Any change to a doc comment on `OidcPolicy`, `SetOrgSettings` or
   `TenantSettingsOverride` is a spec change and trips `sdk-openapi-drift.yml`
   and, one step later, the registry digest in Architecture Invariants. #470
   and #471 both change such a comment; #469 changes one on `CimdPolicy`,
   whose fields currently carry no description in the spec (`:12811`), so the
   regeneration is expected to be a no-op there but must be run to prove it.
6. **The IPv6 loopback bug is in exactly one place.** `validate_redirect_uris`
   (`handlers/oauth2_clients.rs:408`) compares `host_str()` against `::1`; the
   `url` crate returns `[::1]`. The CIMD document validator already tests both
   spellings (`crates/axiam-oauth2/src/cimd.rs:630`), the DCR host allow-list
   is spelled `[::1]` (`dcr.rs:82`), and the matcher's arm is tested. One
   comparison, shared by the admin endpoint and the DCR endpoint.

One further thing the review did not name, which belongs with #470: the
in-memory `ClientMetadataCache` (`cimd.rs:674`) is a `HashMap<(Uuid, String), _>`
with no eviction of any kind. It is the same finding in RAM — bounded by the
number of distinct trusted URLs a caller can name — and the same fix.

---

## 2. Issue #469 — the trusted-publisher interlock admits `*` (MCP-03, T-276)

### The leave-it case

CIMD is off by default, the list ships empty, and an operator has to write `*`
themselves. The SSRF guard holds on this path (review §10), so the residual is
outbound request forgery against the public internet, not a way into the
network. The operator page already says, in its own voice, that `*` is "a
reason to name specific hosts rather than `*`". An operator who reads that and
writes `*` anyway has made a choice.

### Why it loses

The argument for refusing the empty list — T21.5 amendment 2, quoted in full in
the review — is not that an unrestricted list is a bad *default*; it is that an
unrestricted list is a request-forgery primitive offered to strangers **and
there is no second control that does that job**. A control with no second
control behind it cannot have a one-character bypass and still be the control.
The validator today refuses the posture and, forty lines down, recommends the
spelling that produces it. Either the empty-list refusal is worth having, in
which case `*` must be refused with it, or it is not, in which case it should
go — and amendment 2's reasoning is right, so it is the former.

The cost is one condition and one message, at both doors (fact 4), with no UI
to mirror (fact 3). There is no cheaper Medium in this series.

### The fix

In `validate_cimd_policy` (`crates/axiam-core/src/models/settings.rs:738`),
after the empty-list refusal:

- Refuse any entry of `cimd.trusted_client_id_domains` that is `*`.
- Refuse any entry whose wildcard suffix is a single label — `*.com`, `*.io`.
  This is `*` for one top-level domain, spelled longer, and the honest
  version of the finding is "the list must name a publisher", not "the list
  must not contain one particular character". It is a floor, stated as such:
  it is not a public-suffix check, `*.github.io` still passes, and that is the
  operator's decision to make (§3 is what bounds it). If the maintainer wants
  the narrower fix the review literally proposed, deleting this bullet is one
  line and no test depends on it.
- Split the entry-shape message at `:795` so the `trusted_client_id_domains`
  variant no longer offers `*` as a valid form; the `trusted_redirect_domains`
  variant keeps it, because amendment 2's own reasoning shows those entries
  are not fetch targets and empty is a working posture there.
- Update the doc comment on `CimdPolicy::trusted_client_id_domains`
  (`settings.rs:590`, "or `*` for any"), and `host_glob_matches`'s comment in
  `crates/axiam-oauth2/src/dcr.rs:255` only if it claims `*` is for trusted
  publishers (it does not; it stays).

`host_glob_matches` itself is unchanged: `*` remains a valid glob, because
`trusted_redirect_domains` and `dcr_allowed_redirect_hosts` still admit it.

**Rows that already hold `*`.** Validation runs on write, not on read
(`get_effective_settings` does not re-validate), so a stored `*` keeps working
until the next save of that settings row, which is then refused with the new
message. Phase 21 is unreleased — the CIMD entry is under `[Unreleased]` in
`CHANGELOG.md` — so no released deployment has such a row. Say this in the
CHANGELOG line rather than adding a startup check.

### Cost, counted

| Item | Needed? | Where |
|---|---|---|
| Validator condition + message | yes | `settings.rs::validate_cimd_policy` |
| Org-baseline interlock in `validate_tenant_overrides` | **no** — the merged policy already passes through the same function (fact 4) | — |
| Admin UI mirror | **no** — no CIMD card exists (fact 3) | — |
| New `AXIAM__*` key | no | — |
| Handler module / coverage-matrix row | no | — |
| Schema / migration | no | — |
| OpenAPI + registry | regenerate to prove a no-op (fact 5); expected unchanged | `sdks/openapi.json`, `sdks/management-registry.json` |
| Tests | new: `a_wildcard_trusted_publisher_is_refused` (both `*` and `*.com`, at both doors); re-fixture two existing tests to `*.example.com` | `settings.rs` tests |
| Docs | glob-syntax list at `docs/admin/client-id-metadata-documents.md:112` gains "refused for `trusted_client_id_domains`, admitted for `trusted_redirect_domains`"; the "name specific hosts rather than `*`" sentence at `:289` becomes "AXIAM refuses `*`" | one page |
| CHANGELOG | one line under `[Unreleased]` → `Security` | `CHANGELOG.md` |
| Records | T-276 → Closed in §5.3 and removed from §6's open register (count `17 of 280` → `16`); review §0 table state → "Closed — `<commit>`" as MCP-02's reads | threat model, review |

### I1

Unreachable with `cimd.enabled = false`: the function returns before the
condition (`settings.rs:742`). With it on, a request path is not touched at
all — this is a settings-write refusal. Additive and opt-in by construction.

---

## 3. Issue #470 — `cimd` rows have no quota and no sweep (MCP-04, T-275)

### Severity after #469

The review and the threat model both say the finding "compounds with MCP-03:
`*` makes every domain shared hosting", and the brief asks whether fixing #469
reorders this one. It does not lower it. With `*` refused the bound is the
publishers an operator names, and the review's own example of an operator
naming shared hosting — `*.github.io`, `*.pages.dev`, an object-store domain —
is a plausible thing for a tenant fronting hobbyist MCP tools to do, and
nothing on the settings page refuses it or should. What #469 removes is the
*one-character* path; the *one-settings-line* path remains, and it is the path
the issue was filed about. **Medium stands.** What changes is cost, not
severity: fact 1 removes the migration.

### The leave-it case

For the recommended profile — one named publisher — the row count is the
number of JSON files that publisher serves, and the finding is theoretical.
Every row is also self-limiting in one sense: a withdrawn document stops
working within a day of its TTL, so the rows are inert, not live. And the
sweeper's own doc comment argues that deleting a row whose document is still
published is pointless, since it comes back on the next request.

### Why it loses

The doc comment's argument is about TTL semantics and is correct about them;
it says nothing about storage, and the review's one-line rebuttal — "a cache
that is never evicted is not a cache" — is the whole case. An inert row is
still a row: it is listed on the OAuth2 clients page, counted in every
`list_all_by_managed_by` the sweeper runs, and a permanent write a stranger
made at the cost of one unauthenticated request. Eviction on last-seen is
*consistent* with the doc comment's reasoning: a row deleted while its document
is still published is re-materialised on the next request, which is exactly
what a cache should do.

### The fix — three parts, none of them a migration

**(a) A quota, checked before the fetch.** In `materialise_if_cimd`
(`crates/axiam-api-rest/src/cimd.rs`), move the `get_by_client_id` lookup
ahead of `cimd::resolve` and, when no row exists, count
`count_by_managed_by(tenant_id, ManagedBy::Cimd)` against the ceiling. Refuse
above it **before any fetch** — a tenant at quota should not be an outbound
amplifier either — with an audit row (`oauth2.client_registration_refused`,
`managed_by: cimd`, a `client_quota_exhausted` code, the caller's IP, and no
client-supplied string, exactly as T21.4a's refusal event is shaped) and the
`debug`-not-`warn` log the module already argues for. A refresh of an existing
row never counts and never costs the query. The request then proceeds as it
does after any other resolution failure: an unknown client.

The ceiling is **`dcr_max_clients`, as a separate count against the same
number**. The repository comment at `oauth2_client.rs:975` asks for separate
ceilings "so a CIMD shadow row materialised by a legitimate client cannot
exhaust the allowance for self-registration"; two counts against one number
honours that. Not a new `cimd.max_clients` field, and the precedent is T21.5
amendment 4: `dcr_allowed_scopes` governs both mechanisms, keeps its `dcr_`
name because DCR defined it, and the documentation says so. A tenth CIMD field
would cost a spec change, an ordering decision in `validate_tenant_override`,
a range check, and a rewrite of the test that asserts the posture "overrides
all nine" — for a number an operator has already chosen once.

**(b) A sweep on last-seen, with no new column.** Generalise
`sweep_unused_dcr_clients` (`crates/axiam-server/src/cleanup.rs:173`) over the
provenance it lists and the clock it reads: `dcr` keeps
`last_authorized_at.unwrap_or(created_at)`; `cimd` reads
`max(updated_at, last_authorized_at, created_at)` (facts 1 and 2). The TTL is
`dcr_unused_client_ttl_days`, reused on the same precedent as (a), with `0`
still meaning "never sweep". Register it as its own job — `cimd_unused_clients`
beside `dcr_unused_clients` — so `/health/jobs` distinguishes them; and rewrite
the "Not `cimd` either" paragraph of the doc comment at `cleanup.rs:148`, whose
argument this fix adopts rather than refutes. `list_all_by_managed_by` and
`delete` already exist; no repository method is added.

**(c) Prune the in-memory cache.** On the insert path of
`ClientMetadataCache::get_or_fetch`, drop entries whose `fetched_at + ttl_secs`
plus the 24-hour stale window has passed. O(n) under the write lock, on a miss
only, and n is bounded by the prune itself. Not a per-tenant cap: (a) already
refuses before the fetch that would populate the cache.

### Cost, counted

| Item | Needed? | Where |
|---|---|---|
| Settings field | **no** — `dcr_max_clients` and `dcr_unused_client_ttl_days` reused | — |
| Org-baseline interlock, tenant/org validators, admin card | no field, so none | — |
| New `AXIAM__*` key | no (the cleanup interval is the existing `cleanup_interval_secs`) | — |
| Handler module / coverage-matrix row | no new module; the `dcr` row's notes gain a sentence about the `cimd` sweep | `frontend-coverage-matrix.md:34` |
| Schema / migration v66 | **no** (fact 1) | — |
| OpenAPI + registry | **yes** — the doc comments on `dcr_max_clients` and `dcr_unused_client_ttl_days` must say they now bound `cimd` rows too, and those comments are spec descriptions (fact 5) | regenerate both |
| Repository | none new; `count_by_managed_by`, `list_all_by_managed_by`, `delete` exist | — |
| Job registration | one `Self::record(..)` call and one health name | `cleanup.rs:522` area |
| Tests | quota: a harness test in `mcp_authorization_test.rs` that the N+1th distinct document is refused before any fetch (assert the wiremock server received no request) and audited; sweep: `cleanup_task.rs` test in the style of `dcr_sweep_removes_an_unused_client_and_leaves_an_admin_one`, plus a unit test of the clock choosing `updated_at`; cache: a unit test in `cimd.rs` that an expired entry is gone after the next insert; I1: a `cimd.enabled = false` tenant sweeps nothing and counts nothing | four files |
| Docs | `docs/admin/client-id-metadata-documents.md` §"Cleaning up" is rewritten (it currently states there is no sweeper and why); §"What it costs you" gains the quota row; `dynamic-client-registration.md` §"Abuse controls" notes the two fields govern both; `/health/jobs` snippet gains the new name | two pages |
| CHANGELOG | one line under `[Unreleased]` → `Security` | `CHANGELOG.md` |
| Records | T-275 → Closed; register count; review §0 | threat model, review |

### I1

Every new branch is behind `cimd.enabled`, which is false by default, or
inside a sweep that lists `managed_by = 'cimd'` and finds nothing on a
deployment that never enabled it — the same one indexed query per interval the
`dcr` sweep already makes. The quota query runs only for a URL-shaped
`client_id` with no existing row, on a CIMD tenant. Additive and opt-in.

**Ordering note.** The overshoot the review recorded for DCR — the count and
the write are separated by an `await` — applies here identically and is
accepted here for the same reason: a handful of rows in flight is not a
finding, and closing it needs a conditional insert the schema does not
express.

---

## 4. Issue #471 — quota exhaustion denies registration for a month (MCP-05, T-272)

### The leave-it case

`anonymous` mode is opt-in, is refused while `external_client_allowed_resources`
is empty, and is documented as the mode for a tenant that has decided strangers
may register. The endpoint is rate-limited and every attempt is audited, so
the denial is noisy and attributable. `initial_access_token` mode has no
exposure at all. A tenant that hits this has a documented way out — switch
modes, or raise `dcr_max_clients` — and the sweeper will clear the rows in a
month regardless.

### Why it loses, and which half wins

The quota is doing what it was written for; the review's phrasing is exact:
"the same number is also the availability budget, and one unauthenticated
stranger can spend all of it." What makes it a month rather than an hour is
that `dcr_client_is_due_for_sweep` (`cleanup.rs:133`) reads one TTL for two
situations that have nothing in common. The 30-day default is sized, in its
own doc comment, for "a client somebody uses monthly"; a client registered and
never authorized is not that client. Every MCP client this phase exists to
serve — Inspector, Claude Code, VS Code — authorizes within seconds of
registering, because registration is the first step of the same flow. A
never-authorized `dcr` row that is an hour old is either abandoned or hostile,
and the sweeper can tell the two situations apart today with no new data: the
row already carries `last_authorized_at: None`.

So the brief's framing is right: the real fix is a **second clock**, not a
bigger quota. The other two recommendations in the review:

- **A per-IP or per-subnet share of the quota — not now.** It needs a ledger
  per (tenant, address) that no store today holds, it is defeated by "a
  handful of source addresses" as the review itself says, and the mode it
  protects is the one the documentation will now say is for tenants that
  accept this exposure. *The condition that would change this:* a deployment
  reporting quota exhaustion from distributed sources in `anonymous` mode
  with the second clock in place. If that arrives, the answer is still more
  likely to be `initial_access_token` than a subnet ledger, and the plan for
  it should say so first.
- **The documentation half — yes, in the same commit.** The page's
  "three modes" section does not currently give the one reason to prefer
  `initial_access_token` that matters most: its quota cannot be spent by
  someone with no credential. Adding that sentence costs nothing and is the
  only part of this fix a tenant on `anonymous` today can act on immediately.

The **race overshoot** (quota check and write separated by an `await`) stays
as recorded: a handful of rows, and the second clock makes the burst cheap to
recover from rather than cheap to cause.

### The fix

A new ordered field on `OidcPolicy`, **`dcr_unauthorized_client_ttl_secs`**
(default `3600`; `0` means "no second clock, use the days TTL"; floor `60`),
read by the sweeper for a `dcr` row whose `last_authorized_at` is `None`
**and whose tenant's effective `dynamic_registration` is `anonymous`**. In
`initial_access_token` mode the row exists because an administrator minted a
handle for it, the exposure does not exist, and the thirty-day clock is the
right one — an operator who hands someone a registration token on Friday
should not find the registration gone on Monday. The sweeper already resolves
each row's tenant settings (`cleanup.rs:200`), so the mode is one more field
read from a struct it already holds.

Why a field and not a constant, given what a field costs here: every sweep
window in this file is a tenant setting, and the doc comment at `cleanup.rs:158`
says why — the owner of the decision is the tenant, not the datastore. A
hard-coded hour would be the first window in the sweeper an operator could
not see or change, on the one sweep that deletes rows created by strangers.
The fallback, if the maintainer judges the spec churn not worth it for this
release, is a constant with the same value and the same mode gate, which
removes every row below marked "field only"; the sweeper logic and its tests
are identical either way.

Strictness ordering follows `dcr_ttl_strictness`: smaller is stricter, `0`
maps to the top of the range, a tenant may shorten and never lengthen.

### Cost, counted — this is the expensive one

| Item | Needed? | Where |
|---|---|---|
| `OidcPolicy` field, default fn, `SetOrgSettings` input, `TenantSettingsOverride` option, `effective_settings` merge, the override diff, `settings_from_org_input`, `system_defaults` | field only | `settings.rs` — eight sites; grep `dcr_unused_client_ttl_days` and mirror every one |
| Ordering in `validate_tenant_override` + `clamp_overrides_to_org` (a second `*_strictness` map) | field only | `settings.rs:1655`, `:1423` |
| Range check in `validate_dcr_policy` (floor 60, ceiling 30 days, or 0) | field only | `settings.rs:443` |
| Org-baseline interlock in `validate_tenant_overrides` | covered by the ordering row; no cross-field interlock (the field means nothing outside `anonymous`, and refusing it in other modes would stop a tenant staging a posture, which T21.5 deliberately allows) | — |
| Admin UI card | field only — the Dynamic Client Registration card shows the two DCR numbers in an edit form (`SettingsPage.tsx:460–476`) and a read-only view (`:521–526`), plus `services/settings.ts` types and defaults, plus `SettingsPage.test.tsx` | three frontend files |
| New `AXIAM__*` key | no | — |
| Handler module / coverage-matrix row | no new module; the `dcr` row's notes list the new field with the other two | `frontend-coverage-matrix.md:34` |
| Schema / migration | **no** — `OidcPolicy` lives in the settings JSON; a missing key deserialises to the default | — |
| OpenAPI + registry | **yes**, and unavoidable even in the constant variant (the sweeper doc comment is not in the spec, but the `dcr_unused_client_ttl_days` description must say what it no longer governs) | regenerate both; SDK re-sync from merged `main` per §4.0 item 5 |
| Sweeper | `dcr_client_is_due_for_sweep` takes the mode and both TTLs; the per-tenant cache in `sweep_unused_dcr_clients` holds a small struct instead of `Option<u32>` | `cleanup.rs` |
| Tests | unit: the predicate table — never-authorized + anonymous + 1h → due; never-authorized + IAT + 1h → not due; authorized 2h ago + anonymous → not due; `0` → days clock; integration in `cleanup_task.rs`: twenty anonymous registrations, one authorized, clock advanced 61 minutes → nineteen swept, one kept, an `admin` client untouched; settings: ordering and range at both doors; frontend: the card round-trips the field; I1: a `disabled` tenant sweeps nothing and the discovery document is unchanged | five files |
| Docs | `dynamic-client-registration.md`: field table (§"Every policy field"), §"Abuse controls" table row, §"The sweeper" (which currently says the fallback to `created_at` "is what the TTL is really for" — that sentence now belongs to the new clock), and the sentence in §"The three modes" that gives the reason to prefer `initial_access_token`; `docs/api/mcp.md:209` lists the DCR fields with no Keycloak equivalent and gains the third | two pages |
| CHANGELOG | one line under `[Unreleased]` → `Security`, naming the field and its default | `CHANGELOG.md` |
| Records | T-272 → Closed with the per-IP share recorded as the accepted residual; register count; review §0 | threat model, review |

### I1

The field defaults to a value that only the `anonymous` arm of the sweeper
reads, and `anonymous` is opt-in behind D3. Discovery does not advertise it.
A tenant on `disabled` or `initial_access_token` takes byte-for-byte the path
it takes today. Additive and opt-in.

---

## 5. Issue #472 — six error paths compare `redirect_uri` exactly (MCP-01, T-280)

> **Landed** as `b8bc508` on `claude/fix-472-loopback-errors`. The section is
> accurate as written, with one correction: it lists six sites and calls four of
> them match arms in `resolve_authorize_principal`, which is right, but the
> line numbers have moved with the comment rewrites. The test inversion went
> exactly as §5 describes.

### The leave-it case

Fail-closed in the direction that matters: no error is ever redirected to a
URI that was not registered, so the exact comparison is the safe mistake. The
affected refusals are the ones raised *before* the matcher runs — `response_type`
absent, and the `request_uri` family — which a conforming client does not
trigger. Every refusal a real client is likely to hit is redirected correctly
(the review's own probe with `response_type=token` showed this).

### Why it loses

Because it is cheap, it is on exactly the client family Phase 21 exists to
serve, and leaving it means AXIAM disagrees with itself: the success path and
the post-matcher refusals apply RFC 8252 §7.3, and six sites in the same file
do not. `any_redirect_uri_matches` short-circuits on string equality
(`redirect_uri.rs:85`) and takes the port allowance only when the *registered*
URI is `http` on a loopback host, so routing the six sites through it changes
the answer for one shape of registration and no other. A desktop client
waiting on an ephemeral port for a callback that never comes, while the user
looks at an error page the client cannot read, is the worst interoperability
failure a public-client story can have, and it costs six lines to remove.

### The fix

One commit, on its own, in `crates/axiam-api-rest/src/handlers/oauth2.rs`:

| Site | Today | After |
|---|---|---|
| `:565` | `client.redirect_uris.iter().any(\|r\| r == uri)` | `any_redirect_uri_matches(&client.redirect_uris, uri)` |
| `:663` | same | same; the comment above it ("Exact match, the same comparison `AuthorizeService::authorize` makes") is wrong today — authorize has used the matcher since T21.2a — and is rewritten |
| `:734` | same | same |
| `:791` | same; comment says "compared exactly" | same; comment rewritten |
| `:1452` | `.filter(\|client\| client.redirect_uris.contains(candidate))` | `.filter(\|client\| any_redirect_uri_matches(&client.redirect_uris, candidate))` |
| `:4554` | `client.redirect_uris.iter().any(\|r\| r == uri)` | `any_redirect_uri_matches(&client.redirect_uris, uri)` |

And **invert one assertion deliberately**:
`mcp01_an_error_is_not_redirected_to_an_ephemeral_loopback_port`
(`crates/axiam-api-rest/tests/mcp_authorization_test.rs:1309`) asserts
`status != 302` and names this fix in its failure message. It becomes
`mcp01_an_error_is_redirected_to_an_ephemeral_loopback_port`, asserting a
`302` whose `Location` is `http://127.0.0.1:49999/callback` with
`error=invalid_request`, and keeps its second half (the post-matcher contrast)
unchanged. The plan's §1 rule — a task that changes an existing test's
expectation stops and says which — is satisfied by saying so here, in the
commit message, and on the PR: the test was written to be inverted, and its
own message says so.

### Cost, counted

| Item | Needed? |
|---|---|
| Settings, UI, keys, modules, schema, OpenAPI | none |
| Tests | the inversion above; a second case for the `request_uri` path (`:4554`) since the harness pins only `:1452` today; `oauth2_conformance.rs` and `par_test.rs` unchanged and green |
| Docs | `docs/admin/public-clients.md`'s port rule gains one sentence: errors are redirected under the same rule |
| CHANGELOG | one line under `[Unreleased]` → `Fixed` |
| Records | T-280 → Closed; register count; review §0; plan §9 item 12 needs no edit (it already records the defect as an error-path one) |

### I1

For every registration that is not an `http` loopback URI, the matcher is a
string comparison and the six sites answer exactly as they do today. For an
`http` loopback registration presenting a different port, an error that was
rendered in-browser is now redirected — which is a changed response, but for
a request that before T21.2a could not have completed the success path
either, so no pre-Phase-21 working flow changes. Additive, and it needs no
flag because the widening is already gated by what the client registered.

---

## 6. The IPv6 loopback gap — `http://[::1]/…` cannot be registered

> **Landed** as `7ab890d`, its own commit on the same branch, flagged on the PR
> as §6 requires. One thing §6 did not anticipate: the harness test it asks for
> — "a subsequent authorize on `http://[::1]:49999/cb` is matched" — has to
> drive the D4 consent hop before a code appears, because an externally
> registered client asks the end user first. The test does.

### Decision: same PR as #472, its own commit, flagged

The brief asks whether this belongs here or stays separate. It belongs here,
because #472 is the commit that makes the redirect story consistent and this
is the last inconsistency in it: the matcher has a tested `[::1]` arm
(`redirect_uri.rs:133`), the CIMD document validator accepts both spellings
(`cimd.rs:630`), the DCR host allow-list is spelled `[::1]` (`dcr.rs:82`), and
the one validator both registration endpoints share compares against `::1`
and can never match. `docs/admin/dynamic-client-registration.md:280` carries
an eight-line paragraph apologising for it. Leaving it means the paragraph
outlives the phase.

**It is the one change in this plan that makes a refused request succeed**, and
that is the exact clause I1 names, so it is a separate commit and is flagged on
the PR as T21.4a's amendment 4 was. The argument that it is nonetheless
correct: the widening admits one host, the IPv6 loopback, which the page's own
reasoning says "adds no reach: a loopback URI is reachable only from the
machine the user is sitting at"; RFC 8252 §7.3 lists it beside `127.0.0.1`;
neither OIDF conformance plan registers it; and the refusal was never a
decision — the doc comment on the line says "localhost/127.0.0.1/::1" and
means to accept it. A validator that refuses what its own error message says
it allows is a bug, and I1 is a promise about behaviour, not about bugs.

### The fix

`handlers/oauth2_clients.rs:408`: compare against `"[::1]"` (what
`Url::host_str` returns for an IPv6 literal). Delete the paragraph at
`dynamic-client-registration.md:280–288`. Tests: `http://[::1]/cb` registers
through `POST /api/v1/oauth2-clients` and through `/oauth2/register`, and a
subsequent authorize on `http://[::1]:49999/cb` is matched — which is the
first time the matcher's `[::1]` arm is reached end to end. One line under
`Fixed` in the CHANGELOG.

---

## 7. MCP-06 — the tenant-path guard reads the raw query string

> **Pinned** in the third commit of the #472 PR, as §7's first bullet asks, and
> still accepted. Writing the test corrected one clause of the review: the
> `400` §7 quotes needs a credential to be reached, because authentication is
> refused before the query is deserialised. An unauthenticated
> `tenant%5Fid=` gets a `401`. The acceptance is unaffected and the test pins
> both refusals; the review's §7 now says so.

**Agree with the acceptance.** The review's reasoning has two parts and both
hold on `main`: the request is refused either way (the middleware appends
`&tenant_id={path tenant}`, the extractor then sees two pairs decoding to one
non-sequence field, and `serde_urlencoded` answers `duplicate field`), and the
fix would put a percent-decoder in front of a security check, which is the
thing `redirect_uri.rs` and `resource.rs` argue against in this same phase. A
better error message is not worth a decoder on the guard.

Two things worth adding to the record:

- **What the acceptance rests on.** The refusal is a property of the
  extractor's field type and of a dependency's duplicate-field behaviour, not
  of the guard. The review says "it is not exploitable" and does not say
  "asserted"; no test in `crates/axiam-api-rest/tests/` sends `tenant%5Fid=`
  on a tenant path. That is the one gap I would close: a single harness case
  in `mcp_authorization_test.rs` beside V2, asserting the `400`, so that a
  future change to the extractor cannot silently turn an accepted
  informational into an open Medium. It pins current behaviour; it changes
  nothing. Put it in the #472 PR if that PR is opened, and nowhere otherwise.
- **The reopen conditions.** (1) Any route under `/t/{tenant_id}` whose
  handler reads `tenant_id` through something other than the non-sequence
  `serde_urlencoded` field — a `Vec`, a hand-rolled parser, a path-only
  extractor that ignores the query. (2) The scope being widened to `/api/v1`,
  which the review's §9 already flags for a different reason. Either turns
  the second `400` into no `400`, and the fix then becomes decoding in the
  guard after all, argued on the security and not the message.

---

## 8. Order, and how many pull requests

**Two PRs, not one**, and the split is by generated-artifact exposure rather
than by severity:

**PR A — #469, #470, #471, in that order.** The three Mediums share files
(`settings.rs`, `cleanup.rs`, both operator pages) and their decisions
cascade: #469 settles what bounds #470, and #470's generalised sweeper is the
one #471's second clock is added to, so doing them in sequence on one branch
means one sweeper refactor and one spec regeneration rather than three. This
PR carries the whole §5 gate plus its two errata plus the regeneration block,
and is the one that can go red on `sdk-openapi-drift` or Architecture
Invariants; keeping that exposure in one PR keeps the other one clean.

1. **#469** first — smallest, and it decides the frame the next one is argued
   in.
2. **#470** second — reuses the two DCR fields, generalises the sweep.
3. **#471** third — adds the field and the second clock to the sweep #470 just
   generalised. Do it last in the PR because it is the only one that touches
   the frontend, so its failures are the ones most likely to need a second
   push.

**PR B — #472, then `[::1]`, then the MCP-06 pin.** A handler file, one
validator line, one doc page, three tests. It touches no `ToSchema` type, so
it cannot hit either generated-artifact job; its gate is §5's cargo lines
without the regeneration block. It is independent of PR A at the file level
and can be opened first, or in parallel, if the interoperability fix is wanted
before the settings work lands — nothing in it waits on anything in A.

Both PRs: feature branch, signed commits, opened by the agent on behalf of the
maintainer, referencing the issues they close (A: #469, #470, #471; B: #472);
issues are closed on merge, not before; nothing merges itself.

---

## 9. The gate each PR runs before it pushes

§5 of the plan, both errata, and the four things PR #474 found the gate does
not cover. Every line captures cargo's own exit code (redirect to a log, test
`$?`; never `| tail`).

```bash
apt-get install -y protobuf-compiler                       # PR A only: the spec regen builds axiam-server
export SWAGGER_UI_DOWNLOAD_URL="file://$(scripts/make-swagger-ui-placeholder.sh)"

cargo fmt --all -- --check
cargo clippy -p axiam-core -p axiam-oauth2 -p axiam-api-rest -p axiam-server \
  --all-targets --no-default-features -- -D warnings      # axiam-server was missing from §5
cargo test -p axiam-core --lib                            # settings validators, both doors
cargo test -p axiam-oauth2 --lib                          # matcher, glob, cache prune
cargo test -p axiam-db --lib                              # the schema tripwire — never run by §5; stays at v65
cargo test -p axiam-api-rest --lib --no-default-features
cargo test -p axiam-api-rest --no-default-features \
  --test mcp_authorization_test --test oauth2_conformance --test oidc_conformance \
  --test oauth2_flow_test --test par_test --test oauth2_client_test
cargo test -p axiam-server --test cleanup_task            # PR A: both sweeps

python3 scripts/check-crate-layering.py
python3 scripts/check-frontend-coverage.py
python3 scripts/check-config-key-coverage.py

# PR A only — the regeneration block, verbatim from gate erratum 1
cargo build -p axiam-server --no-default-features
./target/debug/axiam-server --dump-openapi > sdks/openapi.json
python3 scripts/check-spec-digest.py
python3 scripts/gen-management-registry.py && python3 scripts/gen-management-registry.py --check
diff <(./target/debug/axiam-server --dump-openapi) sdks/openapi.json

# PR A only — the card
(cd frontend && npm test -- --run && npx tsc -p tsconfig.app.json --noEmit)
```

`cargo clean` between PRs, never during one; the `axiam-server` build for the
regeneration is the ~6 GB step and should be the last cargo command before it.
Verify what is committed, not the working tree: run `check-spec-digest.py`
and `gen-management-registry.py --check` only on a clean `git status`, so the
files they read are the committed ones, and
`git show HEAD:crates/axiam-db/src/schema.rs | grep 'Some(&65)'` to prove
nobody bumped the tripwire.

---

## 10. Records each PR updates, so the three documents keep agreeing

- `claude_dev/threat-model-stride.md` §5.3: T-276, T-275, T-272 (PR A) and
  T-280 (PR B) from **Open** to **Closed** with the commit; §6's register
  loses each row and its opening sentence's count (`17 of 280`) moves with
  them; the paragraph that introduces the four as "a different kind from the
  other thirteen" is rewritten once all four are closed, since its point was
  that they were filed defects on the request path and they no longer are.
- `claude_dev/security-review-mcp-2026-09-17.md` §0: the four rows' state
  column, in MCP-02's form (`Closed — <commit>`); §7 gains a line that the
  MCP-06 refusal is now pinned, if PR B adds the test.
- `claude_dev/mcp-authorization-server-plan.md` §9: no edit. Item 12 already
  records the defect correctly.
- `CHANGELOG.md` `[Unreleased]`: four `Security`/`Fixed` lines, one per
  issue, each naming the setting that gates it or saying it is ungated.
- `docs/admin/client-id-metadata-documents.md`, `docs/admin/dynamic-client-registration.md`,
  `docs/admin/public-clients.md`, `docs/api/mcp.md`: as itemised per section.
- `claude_dev/frontend-coverage-matrix.md:34`: the `dcr` row's notes, twice
  (PR A).

Not in either PR, and recorded here so it is not lost: **T21.5 has no admin
UI** (fact 3). The CIMD posture — nine fields, two of them interlocked, all of
them security controls by the struct's own doc comment — is settable only
through the API. That is the T4b-shaped task the phase skipped, and it should
be filed against T21.5 as its own issue rather than folded into PR A, which
has enough frontend surface in #471 already.
