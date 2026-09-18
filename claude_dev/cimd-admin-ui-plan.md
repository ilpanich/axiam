# Plan — the CIMD policy has no admin UI, and the organization page erases it

**Date:** 2026-09-18
**Validated against:** `main` @ `0bc7cb1` (Phase 21 merged; the #469–#472 fix plan committed, not yet executed)
**Origin:** [`issues-469-472-fix-plan.md`](issues-469-472-fix-plan.md) §1 fact 3 and §10, which record the gap and defer it here.
**Issue:** to be filed against T21.5 by the executing session — see §7 for the title and body. Search first: the session executing the #469–#472 plan was also told to file it.
**Verdict: this is two defects, not one gap, and the second is worse than the first.** The CIMD posture cannot be set from the admin UI at either level (the gap the fix plan named). Separately, and found while sizing that gap, **every save of the organization settings page silently resets the organization's DCR and CIMD posture to the defaults**, and the tenant overrides beneath it are then cleared by the baseline clamp. The reset is fixed first, in its own commit, because it is the only item here that destroys a working configuration.

| # | Finding | Kind | Decision | Effort | Touches backend? |
|---|---|---|---|---|---|
| A | `OrganizationDetailPage`'s settings save sends a `SetOrgSettings` without the six DCR fields or `cimd`; the backend defaults every one and replaces the row | **Bug** — a working posture is turned off by an unrelated save | **Fix first**, one commit, before any card exists | Small | No |
| B | No card for the CIMD posture on the tenant settings page, the organization settings tab, or the org admin's per-tenant override panel | Gap (T21.5 shipped no T4b-equivalent) | **Fix**, on all three surfaces, whole-posture | Medium | No |
| C | The T21.4b DCR card exists only on the tenant page, where `dynamic_registration` is tighten-only against an organization baseline that defaults to `disabled` — so DCR cannot be *enabled* from the UI at all | Gap, adjacent | **Fix with B**: the same component mounted on the organization tab | Small (reuse) | No |
| D | `check-frontend-coverage.py` demands a matrix row per `handlers/*.rs`; `src/cimd.rs` is not a handler, so nothing asked for one | Process | **Add the row; do not widen the script** | Trivial | No |

Nothing here changes an API, a schema, a settings field, an `AXIAM__*` key or a
generated artifact. It is frontend, one operator page, the matrix and the
CHANGELOG. It should be a **Sonnet 5** session by the Phase 21 model rule
(§2 of the plan assigns UI tasks there).

---

## 0. What reading `main` established

Six facts, each with the line that shows it.

1. **The organization settings form drops the Phase 21 fields.** The frontend
   `SetOrgSettings` (`frontend/src/services/organizations.ts:214`) has no
   `dynamic_registration`, no `dcr_*`, no `external_client_allowed_resources`
   and no `cimd`; `flattenOrgSettings` (`:259`) therefore never carries them;
   `SettingsTab` (`OrganizationDetailPage.tsx:1011`) holds "the FULL flat
   SetOrgSettings — PUT requires every field" (its own comment, `:1027`) and
   sends it verbatim (`:1133`).
2. **The backend defaults what is absent and replaces the row.** Every one of
   those fields on the backend `SetOrgSettings` is `#[serde(default)]`
   (`crates/axiam-core/src/models/settings.rs:1034–1053`); `set_org_settings`
   (`handlers/settings.rs:341`) builds the row from the input and stores it.
   There is no merge with the existing row, by design — the frontend type's
   comment on `webauthn_user_verification` states the rule and its
   consequence exactly: "omitting it from a save would silently relax an
   organization that had set `required` — with nothing in the response to say
   so." That comment was written for one field and is now true of eight.
3. **The clamp then clears the tenants.** After an organization write,
   `clamp_overrides_to_org` (`handlers/settings.rs:252`) drops any tenant
   override more permissive than the new baseline — including a whole
   `cimd` posture whose `enabled` the organization no longer has
   (`settings.rs:1630`). So one save of, say, a password-history count on the
   organization page turns CIMD off org-wide **and** discards every tenant's
   stated posture. Nothing in the response says so.
4. **The tenant DCR card cannot enable DCR.** `dynamic_registration` is ordered
   (`settings.ts:84`: "a tenant may move down it and never up"), the
   organization default is `disabled`, and the organization page has no DCR
   fields. T21.4b's CHANGELOG entry ("a Dynamic Client Registration card for
   every T21.4 policy field") is true of the tenant page and silent about the
   fact that the ceiling it edits under is set only by the API.
5. **The org admin's per-tenant panel is group-based and already fits a whole
   posture.** `SecurityOverridePanel` (`frontend/src/pages/organizations/SecurityOverridePanel.tsx`)
   overrides by *group* — "Checking 'Password policy' takes over the whole
   block; leaving it unchecked inherits the whole block" — and builds a sparse
   `TenantSettingsOverride` from checked groups only (`overrideFromForm`,
   `:156`). That is exactly the semantics of `Option<CimdPolicy>` on the
   backend override (`settings.rs:957`) and of T21.5 amendment 3 ("a tenant
   states its whole CIMD posture or none of it"). A CIMD group needs no new
   model. The same panel today has no DCR group, so saving any group from it
   also drops a tenant's DCR override set through `SettingsPage` — the same
   shape as fact 1, at the tenant level.
6. **Everything else the UI needs already exists.** The effective settings
   `GET /api/v1/settings` carries `oidc.cimd` (the backend `OidcPolicy` has the
   field; the frontend `OidcPolicy` type at `settings.ts:100` simply omits it);
   `OAuth2ClientsPage` already badges `cimd` clients and shows them read-only
   (`:155`, `:683`); the audit viewer already recognises the registration
   event the CIMD materialisation writes (`AuditLogsPage.tsx:48`). No new
   endpoint, no new event, no new badge set.

---

## 1. Finding A — the organization save resets DCR and CIMD

### Decision: fix first, alone, before any card

The leave-it case is that the fields can be re-sent by API after every UI
save. That is not a posture an operator can hold: the reset is silent, it
cascades to tenants (fact 3), and the operator who triggered it was editing
something unrelated. A security control that any admin can switch off by
accident is not a control.

Two ways to fix it, and the client-side one is right:

- **Client-side (chosen).** `flattenOrgSettings` carries the six DCR fields
  and the whole `cimd` object through from `SecuritySettings.oidc`, with the
  server's defaults when the response omits them (a settings row written
  before v64/v65 has no `oidc` block; `DEFAULT_DCR_MAX_CLIENTS` and friends
  already exist in `settings.ts:112`). The frontend `SetOrgSettings` type
  gains the same fields, required, with the comment the OPAQUE fields
  already carry. The form then round-trips them whether or not a card renders
  them.
- **Server-side (rejected).** Making the backend `SetOrgSettings` fields
  `Option` with "absent means keep" would change the endpoint's contract
  (whole-row replace, which the frontend type's own comments rely on), touch
  `sdks/openapi.json` and the registry, and re-sync eleven SDKs — for a bug
  that lives in one client. Two callers with two conventions is how the next
  field gets lost.

### Cost

| Item | Where |
|---|---|
| `SetOrgSettings` type + `flattenOrgSettings` | `frontend/src/services/organizations.ts:214`, `:259` |
| `OidcPolicy` type gains `cimd?: CimdPolicy`; new `CimdPolicy` type and `DEFAULT_CIMD_POLICY` mirroring `CimdPolicy::default()` (`settings.rs:647`) | `frontend/src/services/settings.ts:100` |
| `computeIsDirty` / `shouldSeedForm` (`settingsForm.ts`) — no change if they compare the whole object; verify | `frontend/src/pages/organizations/settingsForm.ts` |
| Test: with `oidc` present in the GET, saving the password section sends the DCR and CIMD values **unchanged**; with `oidc` absent, sends the defaults | `OrganizationDetailPage.component.test.tsx` (payload assertions at `:240` are the style) |
| CHANGELOG | `[Unreleased]` → `Fixed`, one line, naming the eight fields |
| Backend | none |

This commit lands before anything else in the PR and is the one to cherry-pick
if the rest waits.

---

## 2. Finding B — a card for the CIMD posture, on three surfaces

### Decision: build it, whole-posture, and mirror the server's refusals

The leave-it case: CIMD is off by default, its operator page gives the `curl`,
and the posture is nine fields most tenants will never touch. Against that:
the two refusals that make CIMD safe (D3 and the trusted-publisher interlock)
are enforced at the settings layer, and today the only place an operator meets
them is a `400` body after a `curl`. The DCR card exists precisely so that D3
is met in the form, in the server's words, before the request is made
(T21.4b's CHANGELOG line). CIMD carries the same interlock plus one of its own
and got no form. The asymmetry is the gap, not the missing convenience.

### Shape

One shared module, `frontend/src/pages/settings/cimdPolicy.tsx` (beside the
DCR fields, which should move out of `SettingsPage.tsx` into a sibling
`dcrPolicy.tsx` for the same reason — finding C mounts them twice):

- **`CimdPolicyFields`** — the nine fields. `enabled` as the gate; the two
  host lists as one-per-line textareas exactly like `dcr-allowed-redirect-hosts`
  (`SettingsPage.tsx:389`); `restrict_same_domain` and `confidential_only` as
  switches with the help text from the operator page's "two profiles" section
  (desktop clients need `restrict_same_domain` **off**, and the form says so
  where the switch is); the three bounds as numbers with the server's floor and
  ceiling as `min`/`max`.
- **`CimdPolicySummary`** — read mode. **I1 rule, copied from
  `DcrPolicySummary` (`:495`)**: while `enabled` is false, render "Disabled"
  and nothing else; an empty publisher list and default bounds are true but
  invite an operator to read significance into a policy that does nothing.
- **`validateCimdPolicy`** in `services/settings.ts`, the client-side mirror
  of `validate_cimd_policy` (`settings.rs:738`), in the server's words, exactly
  as `validateDcrPolicy` (`settings.ts:236`) mirrors `validate_dcr_policy`.
  Only when `enabled`:
  1. D3 — empty `external_client_allowed_resources` (the message at
     `settings.rs:749`);
  2. empty `trusted_client_id_domains` (`:759`);
  3. entry shape — a URL, path, `host:port` or whitespace in either list
     (`:795`);
  4. the three range checks (`:802–830`);
  5. **after #469 lands:** `*` or a single-label wildcard in
     `trusted_client_id_domains`. This is why §6 sequences this plan after
     PR A of the fix plan: the mirror must quote the message that PR
     writes. If this must ship first, omit item 5 and add it as one line and
     one test case when #469 merges — do not invent the message.
  Every refusal is a `role="alert"` block under the field it names, as the D3
  block is (`:441`), and the Save button is disabled while any is present.

Mounted on three surfaces:

| Surface | Level | What it edits | Semantics |
|---|---|---|---|
| `OrganizationDetailPage` → `SettingsTab`, new section "Client ID metadata documents" after "WebAuthn" (`:1507`) | Organization baseline | `SetOrgSettings.cimd` (whole object, required) | This is where `enabled` and `allow_http` can be turned **on**; the section's intro says so, because the tenant surfaces can only turn them off |
| `SettingsPage`, new card after "Dynamic Client Registration" (`:1196`) | Tenant, own override | `TenantSettingsOverride.cimd` | Sends the whole posture (the page already sends every field it shows — `SettingsPage.test.tsx:500`) |
| `SecurityOverridePanel`, new group "Client ID metadata documents" | Tenant, set by the org admin | `TenantSettingsOverride.cimd`, present only when the group is checked | Group checked → the whole posture; unchecked → the key is absent and the tenant inherits (fact 5). The ordering rule is shown, not enforced client-side: `enabled` and `allow_http` render disabled with "your organization has this off" when the baseline has them false, matching the server's `cimd.enabled: cannot enable … at tenant level` refusal (`settings.rs:1926`) |

### Cost

| Item | Where |
|---|---|
| Types, defaults, `validateCimdPolicy` | `services/settings.ts` |
| `CimdPolicyFields`, `CimdPolicySummary` | new `pages/settings/cimdPolicy.tsx` |
| Three mounts | `OrganizationDetailPage.tsx`, `SettingsPage.tsx`, `SecurityOverridePanel.tsx` (+ `groupsFromOverride`, `overrideFromForm`, `NO_GROUPS`) |
| Tests — `SettingsPage.test.tsx`, in the T21.4 describe's style (`:375`): I1 (view mode shows only "Disabled"); pre-fill from the loaded policy; each refusal blocks Save with the server's text; a save sends the full nine-field object; **`services/settings.test.ts`**: `validateCimdPolicy` table, one row per server violation. **`SecurityOverridePanel.test.tsx`** (`:118` is the style): unchecked group → no `cimd` key in the PUT; checked → the whole object; baseline-off → `enabled` control disabled. **`OrganizationDetailPage.component.test.tsx`**: the section renders and its values reach the PUT | four test files |
| `frontend/src/test/a11y.test.tsx` — CI runs it (`ci.yml:648`); the new switches and alerts need labels | one file |
| Docs — `docs/admin/client-id-metadata-documents.md` §"Every policy field" opens with "resolved through the ordinary organization-baseline-plus-tenant-override chain" and gives only `curl`; add one paragraph naming the three UI surfaces and which of them can turn `enabled` on. `docs/admin/dynamic-client-registration.md` §"Enabling it" likewise (its `curl` at the org level is, today, the only way) | two pages |
| CHANGELOG | `[Unreleased]` → `Added`, one entry in the T21.4b entry's shape (`CHANGELOG.md:218`), ending with "Default (`enabled: false`) tenants see none of it" |
| Backend, OpenAPI, registry, schema, keys | none |

---

## 3. Finding C — the DCR card on the organization tab

### Decision: same PR, same commit as the organization CIMD section

Once `DcrPolicyFields` lives in its own module, mounting it in `SettingsTab`
beside the CIMD section is the second `import`. Without it the organization
tab would let an operator enable CIMD — which needs `external_client_allowed_resources`,
a DCR-card field — and not DCR, which is the same list. The D3 alert already
in `DcrPolicyFields` (`:441`) fires on the organization baseline exactly as
it does on the tenant override, because `validate_dcr_policy` runs at both
doors (`settings.rs:1224`, `:1978`).

**Cost:** the mount, one test that the organization PUT carries an edited
`dynamic_registration`, and one sentence in `dynamic-client-registration.md`
§"Enabling it". The `SecurityOverridePanel` gets a "Dynamic client
registration" group in the same commit, for the reason fact 5 gives: without
it, an org admin saving any group on a tenant drops that tenant's DCR
override. That is finding A's shape at the tenant level and is closed the
same way.

---

## 4. Finding D — the coverage matrix

Add a `cimd` row to `claude_dev/frontend-coverage-matrix.md` naming the three
surfaces and, until §2 lands, status **gap** with this document as the reason.
`check-frontend-coverage.py` only complains about handler modules with no row
(`:61–66`); an extra row is inert. **Do not widen the script** to non-handler
modules: the matrix's premise is "one row per REST handler module", the CIMD
resolver has no route of its own (it runs inside authorize, token and PAR),
and a script that guessed which `src/*.rs` files are "surfaces" would be a
heuristic nobody could predict. The matrix header gets one sentence saying so,
so the next non-handler surface is added by hand rather than missed.

---

## 5. I1, and what this plan does not change

Every line here is frontend, documentation or the matrix. No request to the
server takes a different path; a tenant or organization on the default
posture sees a "Disabled" badge and nothing more, by the same rule the DCR
card follows. Finding A's fix changes what the organization page **sends** —
from "the defaults, silently" to "what the server reported" — which is the
only I1-relevant change, and it restores the invariant rather than bending
it: today a save from that page makes an existing request (a CIMD client's
authorize) take a different path than it took before the save.

Not in this plan, and said so it is not assumed:

- No server-side "absent means keep" on `PUT /organizations/{id}/settings`
  (§1, rejected).
- No per-field CIMD override. The posture is whole on the backend and whole
  here.
- No client-side enforcement of the *ordering* rules; the server refuses and
  the form shows the refusal, as everywhere else in `SettingsPage`.
- No change to `OAuth2ClientsPage` or the audit viewer; both already handle
  `cimd`.

---

## 6. Order, sequencing against the #469–#472 plan, and the gate

One PR, four commits, in this order:

1. **Finding A** — `flattenOrgSettings` and the types; the round-trip test;
   the `Fixed` line. Stands alone.
2. **Extract** `DcrPolicyFields`/`DcrPolicySummary` into `dcrPolicy.tsx` with
   no behaviour change (the T21.4 tests must pass unmodified — that is the
   proof the extraction is pure).
3. **Findings B and C** — the CIMD module, the validator mirror, the three
   mounts for CIMD and the two new mounts for DCR, their tests, the docs, the
   `Added` line.
4. **Finding D** — the matrix row and header sentence.

**Sequence after PR A of [`issues-469-472-fix-plan.md`](issues-469-472-fix-plan.md)**
so that item 5 of `validateCimdPolicy` quotes the message #469 writes. Branch
from `main` once that PR has merged; if the maintainer wants this first,
§2 says what to leave out.

The gate is the frontend half of `ci.yml` plus the two invariant scripts the
matrix touches:

```bash
(cd frontend && npm ci && npm run lint && npx tsc -b && npm run typecheck:e2e)
(cd frontend && npm test -- --run)          # vitest, including the a11y suite
(cd frontend && npm run build)
python3 scripts/check-frontend-coverage.py
python3 scripts/check-config-key-coverage.py  # no key changes; run it to prove that
```

No cargo command is needed: nothing under `crates/` changes. If a session
finds itself editing a Rust file for this plan, it has left the plan.

Feature branch, signed commits, PR opened by the agent on behalf of the
maintainer, referencing the issue §7 files; closed on merge, not before.

---

## 7. The issue to file

Search `is:issue T21.5 admin UI` before filing; the session executing the
#469–#472 plan was told to file this too, and two issues for one gap is worse
than none.

**Title:** T21.5: the CIMD policy has no admin UI, and the organization
settings page resets DCR and CIMD on every save

**Body:**

> Found while planning the fixes for #469–#472 (`claude_dev/issues-469-472-fix-plan.md`
> §1 fact 3). Plan: `claude_dev/cimd-admin-ui-plan.md`.
>
> **Two defects.**
>
> 1. The organization settings page's save builds `SetOrgSettings` without
>    `dynamic_registration`, the three DCR lists, the two DCR numbers, or
>    `cimd` (`frontend/src/services/organizations.ts:214`, `:259`). Every one is
>    `#[serde(default)]` on the backend and the row is replaced, so any save
>    from that page turns DCR and CIMD off org-wide, and
>    `clamp_overrides_to_org` then clears every tenant's stated CIMD posture.
>    Silent; nothing in the response says so.
> 2. The CIMD posture (nine fields, two interlocked) has no card anywhere:
>    not the tenant settings page, not the organization tab, not the org
>    admin's per-tenant override panel. The two refusals that make CIMD safe
>    are met only as a `400` after a `curl`. Adjacent: the T21.4b DCR card is
>    tenant-only and tighten-only, so DCR cannot be *enabled* from the UI
>    either.
>
> **Severity:** the first is a bug (a working security posture is switched
> off by an unrelated edit); the second is the T4b-shaped task T21.5 did not
> get. Frontend-only; no API, schema or spec change.

---

## 8. Records to update in the PR

- `claude_dev/issues-469-472-fix-plan.md` §1 fact 3 and §10: add the issue
  number and a pointer here, so the two plans agree.
- `claude_dev/frontend-coverage-matrix.md`: the `cimd` row (§4) and the `dcr`
  row's notes, which should now name the organization tab and the override
  panel as surfaces.
- `claude_dev/mcp-authorization-server-plan.md` §9: one item, "T5 had no
  admin-surface sub-task, and the organization settings form was never
  extended for T4a's or T5's fields; both were found after the phase closed."
  That is the kind of omission §9 exists to record.
- `CHANGELOG.md`: the `Fixed` line (finding A) and the `Added` line (B, C).
