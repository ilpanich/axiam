# Threat model — reconciling the Threat Dragon file with its own text (model 2.17.0)

> **EXECUTED 2026-09-25, on `main`, in one commit** —
> `docs(threat-model): the nine Phase 21 entries enter the Threat Dragon file — model 2.17.0`
> (the commit carrying this block, so it is named by its subject rather than a
> SHA it cannot contain). No pull request, no feature branch.
>
> **What the generator printed.** `node website/scripts/gen-threat-model.mjs`:
> `threatModel.ts: 9 diagrams, 288 threats (275 mitigated, 13 open)` — exactly
> §3's line. §3's first check passed: every number 1 … 288 present once, 13
> `Open` (T-9, T-18, T-94, T-123, T-124, T-133, T-134, T-135, T-146, T-148,
> T-161, T-180, T-216 — the register, unchanged), `version` 2.17.0, `threatTop`
> 288. The summary diff moved totals only, to Appendix A's numbers; no open count
> moved. The two generated files were read and then reverted with
> `git checkout`; they are not in this commit.
>
> **The JSON.** Four elements on diagram 2, each a deep copy of the plan's
> template cell (`7a5c9644-…` for the processes, `authorization codes
> (single-use)` for the store) with a fresh UUID, `data.name` = `attrs.text.text`
> = the STRIDE element string, `description` left empty (no prose),
> `hasOpenThreats` false: `per-tenant path issuers` at (810, 260), beside the OIDC
> discovery process it serves; `/oauth2/register` at (810, 460), beside client
> registration; `Client ID metadata document fetch` at (810, 640) — the three in
> the provider box's free right-hand column, inside it without resizing; and
> `externally registered clients (dcr, cimd)` at (1075, 910), below the Data
> tier's last row. The Data tier box grew `height` 780 → 940 to hold it, which
> takes the diagram's rendered height from 868 to 1028; **no existing
> `position` changed**, and the regenerated `threatModel.ts` showed no moved
> coordinate on any other cell. T-277 was appended to the resource-endpoint
> validation process (now 5) and T-278, T-280 to `/oauth2/authorize` (now 11).
>
> **Flows: five, not four.** §1.1's heading says "add four" and its list names
> five (`register (RFC 7591)`, `create dcr row`, `resolve client_id URL`,
> `cache cimd shadow row`, `discovery at /t/{tenant_id}`); §3's "four new flows"
> inherits the heading. All five were added — each is a separate sentence of the
> list and the diagram does not read without the discovery edge — copied from
> `cfb25907-…`, threat-free; the public one carries `isPublicNetwork` true and
> `HTTPS`, the two store writes `SurrealQL` as `register / rotate` does, the
> other two `in-process`.
>
> **What the nine entries' text needed.** Nothing re-worded. Each `description`
> is the detail block's first paragraph; each `mitigation` is the rest, the `>`
> quoting removed and paragraphs joined by a blank line (T-219's shape), with
> backticks and bold kept as T-219 and T-249 keep them. Markdown links were
> reduced to their text (`#471`), because no entry in the file carries one. The
> four closed entries begin with §1.1's prefix (for T-272, "Closed in
> `c4d9ea2` (MCP-05, #471): ") and continue with the block verbatim, so T-272's
> next words are the block's own "Bounded, not closed." That is the history the STRIDE text keeps (the bound
> came first, the closure the same day) and was left as written rather than
> edited here, per §2.
>
> **Threat Dragon was not opened** — this session had no desktop. The
> generator, which is the gate CI has, read the file; the commit message says so.

**Date:** 2026-09-25
**Validated against:** `axiam` main @ `80bc7aa` (the merge of PR #500, contract 1.52)
**Executes on:** `main`, directly, one commit — no pull request, no feature branch
**Model:** Opus 5
**Status: EXECUTED 2026-09-25** (see the block above). It precedes
[`website-security-beta17-update-plan.md`](website-security-beta17-update-plan.md),
whose Wave 0 regenerates the website from the file this plan repairs. Run this
first; the website plan says so in its §0.

> **Why this exists.** The STRIDE model is kept in three artifacts that must
> agree: [`threat-model-stride.md`](threat-model-stride.md) (the readable
> model), `ThreatDragonModels/Axiam/Axiam.json` (what the website generator
> reads), and [`threat-modeling-and-security.md`](threat-modeling-and-security.md)
> (the website Security section's source). The 2026-09-17 MCP wave (Phase 21,
> T21.8) wrote nine entries — T-272 … T-280 — into the first artifact and
> neither of the other two. The 2026-09-22/23 dogfooding wave (Phase 22) wrote
> eight more — T-281 … T-288 — into all three, allocated them from a
> `threatTop` that already counted the nine, and recorded the gap in
> `threat-modeling-and-security.md`'s handoff block as "a maintainer task". The
> dogfooding plan carries it as
> [§13 row 6](dogfooding-findings-fix-plan.md#13-open-after-pr-g). This is that
> task, written so a session can take it.

---

## 0. The state, measured

Counted on 2026-09-25 from the files, not from what the documents say about
themselves:

| Artifact | Threats | Mitigated / Open | Version it claims |
|---|---|---|---|
| `Axiam.json` | **279** (`number` 1 … 288, nine absent: 272 … 280) | 266 / 13 | `version` **2.16.0**, `threatTop` 288 |
| `threat-model-stride.md` | **288** (the nine are in §5.3's table and its `<details>`) | 275 / 13 in §6 — but §5.3 and §7 count **17** open | — |
| `threat-modeling-and-security.md` | says **288**, 275 / 13 | the per-area table sums to **273**; the category and severity tables are still beta15's (271) | handoff says the dogfooding wave is **2.17.0** |
| `website/src/threatModel.ts` (generated, committed) | **271** | 258 / 13 | 2.16.0 — the beta15 pass; nothing since has been regenerated and committed |

`node website/scripts/gen-threat-model.mjs` today prints
`threatModel.ts: 9 diagrams, 279 threats (266 mitigated, 13 open)` — the JSON
is what the website would render, and it is nine short.

The "17 open" in the STRIDE document is an internal inconsistency of its own:
the nine Phase 21 entries were written when four of them were **Open**
(T-272, T-275, T-276, T-280, filed from
[`security-review-mcp-2026-09-17.md`](security-review-mcp-2026-09-17.md) as
#469 … #472). All four closed the same day — `c4d9ea2`, `0b216c6`, `0a273ec`,
`b8bc508`, PRs #475 and #476 — and their rows and detail blocks were updated
to **Closed** with the commit, but the per-diagram line under §5.3 and the
§7 open columns were not. §6's "13 of 288" is the correct number.

## 1. What the commit does

Four files. Nothing is regenerated and committed here: the website's generated
files move with the website prose, in the beta17 website plan's Wave 0, so
that the page and the model it describes land together (the discipline every
website pass has kept since beta11).

### 1.1 `ThreatDragonModels/Axiam/Axiam.json`

**Add four elements to diagram 2, `OAuth2 / OIDC authorization server`**, the
ones §5.3's intro paragraph names ("Four new elements carry them"). Names are
the STRIDE document's element strings, verbatim, so the website's element
column and the document agree:

| Element | Shape (`data.type`) | Threats it carries |
|---|---|---|
| `/oauth2/register\n(RFC 7591,\nunauthenticated)` | `process` (`tm.Process`) | T-273, T-272 |
| `Client ID metadata\ndocument fetch` | `process` (`tm.Process`) | T-274, T-276 |
| `externally registered\nclients (dcr, cimd)` | `store` (`tm.Store`) | T-275 |
| `per-tenant path issuers\n(/t/{tenant_id})` | `process` (`tm.Process`) | T-279 |

**Add two threats to existing elements** of the same diagram:

| Element (exists) | Threats added | Count after |
|---|---|---|
| `Resource-endpoint\ntoken validation\n(cnf, DPoP jti, sid)` | T-277 | 5 |
| `/oauth2/authorize\n(+ consent)` | T-278, T-280 | 11 |

**The nine threats**, from §5.3's table (line 804 … 812) and `<details>` blocks
(`**T-272 —` … `**T-280 —`, lines 1160 … 1230). For each: `number`, `title`
(the table's *Threat* column), `type` (the STRIDE category spelled as the
generator's `CATEGORY_ORDER` spells it: `Spoofing`, `Tampering`,
`Repudiation`, `Information disclosure`, `Denial of service`,
`Elevation of privilege`), `severity` (`Critical` / `High` / `Medium` / `Low`),
`status`, `description` (the detail block's first paragraph), `mitigation`
(the rest of the block, including the `>` residual paragraphs, as prose),
`modelType: "STRIDE"`, a fresh UUID `id`:

| # | Element | STRIDE | Severity | `status` in the JSON |
|---|---|---|---|---|
| T-273 | `/oauth2/register` | Spoofing | High | `Mitigated` |
| T-272 | `/oauth2/register` | Denial of service | Medium | `Mitigated` — the mitigation text begins "Closed in `c4d9ea2` (MCP-05, #471): …" |
| T-274 | Client ID metadata document fetch | Information disclosure | High | `Mitigated` |
| T-276 | Client ID metadata document fetch | Information disclosure | Medium | `Mitigated` — "Closed in `0a273ec` (MCP-03, #469): …" |
| T-275 | externally registered clients | Denial of service | Medium | `Mitigated` — "Closed in `0b216c6` (MCP-04, #470): …" |
| T-277 | Resource-endpoint token validation | Elevation of privilege | Medium | `Mitigated` |
| T-278 | `/oauth2/authorize (+ consent)` | Elevation of privilege | Critical | `Mitigated` |
| T-280 | `/oauth2/authorize (+ consent)` | Denial of service | Low | `Mitigated` — "Closed in `b8bc508` (MCP-01, #472): …" |
| T-279 | per-tenant path issuers | Elevation of privilege | Critical | `Mitigated` |

Threat Dragon has no `Closed` status; the STRIDE document's **Closed** means
"was Open when filed, then fixed", and the JSON records that as `Mitigated`
with the closing commit first in the mitigation text — the way T-16/T-87
(deny-override) and T-39/T-143 (the revocation feed) were closed. Every
`hasOpenThreats` on the four new elements is `false`; the two existing
elements keep `false`.

**Shape of a cell.** Copy the `Resource-endpoint token validation` process
(`id` `7a5c9644-3db1-4d22-ad8d-fdd39b62946a`, the element the Basic OP pass
added at 2.11.0, so it is the precedent for "an element added after the
diagram was drawn"): `shape`, `size` 140 × 140 for a process, `attrs.text.text`
equal to `data.name`, `zIndex` 1, `visible` true, `data.type`, the
`outOfScope` / `isTrustBoundary` / `privilegeLevel` fields. A store copies the
`authorization codes (single-use)` cell instead. Every new `id` is a fresh
UUID; the generator keys nothing on them, but Threat Dragon does.

**Placement.** The diagram's cells occupy `x` 20 … 1075, `y` 20 … 750, with
the `AXIAM OAuth2 / OIDC provider` trust boundary box drawn around the
processes. Place the three new processes inside that box and the store in the
`Data tier` box, enlarging a boundary box's `size` where a new cell would
otherwise sit outside it — the generator lays out from the model's bounding
box plus a margin, so the SVG grows on its own. **No existing element's
`position` changes.** If the regenerated `threatModel.ts` shows a moved
coordinate on a cell this plan does not name, the JSON was edited by hand
somewhere else: stop and look.

**Flows.** Add four, threat-free, so the diagram reads: `OAuth2 client app` →
`/oauth2/register` ("register (RFC 7591)", `isPublicNetwork` true, HTTPS);
`/oauth2/register` → `externally registered clients` ("create dcr row");
`/oauth2/authorize` → `Client ID metadata document fetch` ("resolve client_id
URL") and the fetch → `externally registered clients` ("cache cimd shadow
row"); `per-tenant path issuers` → `OIDC /userinfo, /jwks, discovery`
("discovery at /t/{tenant_id}"). Copy a flow cell's shape from
`validate presented token` (`id` `cfb25907-…`): `shape: "flow"`, `connector:
"smooth"`, `zIndex` 10, one label at position 0.5, `source.cell` /
`target.cell` by id, `data.type: "tm.Flow"`, `threats: []`. Flows carry no
threats in this wave and carry none of the nine.

**Version.** Top-level `version` `2.16.0` → **`2.17.0`**. The handoff block in
`threat-modeling-and-security.md` already calls the dogfooding wave 2.17.0 and
nothing has rendered 2.17.0 yet, so one version covers the nine, the eight,
and this reconciliation. Leave the per-diagram `version` fields (`2.12.0`)
alone; the generator reads the top-level one. `threatTop` stays 288 — it was
right; the file was behind it.

### 1.2 `claude_dev/threat-model-stride.md`

Three corrections, no new entries:

- **§5.3, the count line** (line 751): `*58 threats — 5 critical, 25 high, 24
  medium, 4 low; 4 open.*` → `… ; 0 open.*`.
- **§5.3, the intro paragraph** (line 749) says the four "are recorded
  **open** from `security-review-mcp-2026-09-17.md`, which is the first entry
  in this model's history where a review's findings arrive already filed
  rather than already fixed". Keep that — it is history and it is the point —
  and add one sentence after it: all four closed within the day, in
  [#475](https://github.com/ilpanich/axiam/pull/475) (`b8bc508`) and
  [#476](https://github.com/ilpanich/axiam/pull/476) (`0a273ec`, `0b216c6`,
  `c4d9ea2`), which the rows record; and that the nine entered
  `Axiam.json` on 2026-09-25 at model 2.17.0, eight days after this text.
- **§7 Coverage**: the open columns. *By severity*: Medium 6 → **3**, Low 2 →
  **1** (Critical 1 and High 8 stay). *By diagram*: OAuth2 4 → **0**. Totals
  in every table are already right (288; 70 / 59 / 6 / 67 / 28 / 58; 32 /
  135 / 111 / 10; 33 / 35 / 58 / 31 / 27 / 30 / 18 / 28 / 28) — check them
  against Appendix A rather than trusting this sentence.
- **§9 Maintaining this model** gains one bullet, in the list's own register:
  a wave is not in the model until it is in all three artifacts, and the
  generator's one-line summary is the check — the 2026-09-17 entries lived
  eight days in this document alone, the next wave allocated numbers past
  them, and the website would have rendered 279 against a text saying 288.
  Say what the check is: `node website/scripts/gen-threat-model.mjs` must
  print the total this document's §7 carries, on every commit that touches
  either.

### 1.3 `claude_dev/threat-modeling-and-security.md`

Only the counting. The prose for both waves is the beta17 website plan's Wave
1 and is not written here.

- **Coverage by area** (the table under `### Coverage by area`): System
  context 32 → **33**, OAuth2 / OIDC 49 → **58**, PKI 26 → **30**, Deployment
  27 → **28** (Authorization is already 27). Open column unchanged. Sum 288.
- **Coverage by STRIDE category**: Spoofing 66 → **70**, Information
  disclosure 65 → **67**, Denial of service 24 → **28**, Elevation of
  privilege 51 → **58** (Tampering 59, Repudiation 6 stay). Open column
  unchanged (3 / 1 / 0 / 6 / 2 / 1).
- **Coverage by severity**: Critical 30 → **32**, High 126 → **135**, Medium
  106 → **111**, Low 9 → **10**. Open column unchanged (1 / 8 / 3 / 1).
- **The handoff paragraph "A counting correction belongs with it"**: its last
  sentence — "which is why `threatTop` in the model file reads 281 while the
  file carries 272" — was already wrong when written (`threatTop` is 288 and
  the file carried 279). Replace the sentence from "The nine entries still
  have to be written …" with: the nine entered the Threat Dragon file on
  2026-09-25, at model **2.17.0**, with four new elements on the OAuth2
  diagram; the three artifacts agree at 288 / 275 / 13.

### 1.4 `claude_dev/dogfooding-findings-fix-plan.md`

§13 row 6 (*Threat-model reconciliation*): mark it done in place — "Done
2026-09-25, this plan, commit `<sha>`" in the *Next step* column — rather than
deleting the row. The dogfooding plan is a record.

## 2. What this commit must not do

- **Not** regenerate and commit `website/src/threatModel.ts` or
  `threatModelSummary.ts`. Run the generator to verify (§3), then `git
  checkout` both. The website plan commits them with the prose that
  describes them.
- **Not** touch `website/src/security.ts`, `version.ts`, the Docs pages or
  the News. Same reason.
- **Not** add prose for T-281 … T-288 or T-272 … T-280 to
  `threat-modeling-and-security.md`'s body sections. That is the website
  plan's Wave 1a, where it is done section by section against the site.
- **Not** renumber, re-order or re-word any existing threat. The nine are
  copied from the STRIDE document; if a detail block reads wrong, fix the
  STRIDE document in a separate commit and say so.
- **Not** change any open item. The open set is the thirteen the register
  lists (T-148, T-18, T-94, T-124, T-133, T-135, T-146, T-216, T-180, T-9,
  T-123, T-134, T-161), before and after.

## 3. Verification

```sh
# 1. the JSON parses, every number 1..288 is present exactly once, 13 are Open
python3 - <<'EOF'
import json
m = json.load(open("ThreatDragonModels/Axiam/Axiam.json"))
nums = {}
for i, dg in enumerate(m["detail"]["diagrams"]):
    for c in dg["cells"]:
        for t in (c.get("data", {}).get("threats") or []):
            assert t["number"] not in nums, t["number"]
            nums[t["number"]] = (i, t["status"])
assert sorted(nums) == list(range(1, 289)), [n for n in range(1, 289) if n not in nums]
assert sum(1 for v in nums.values() if v[1] == "Open") == 13
assert m["version"] == "2.17.0" and m["detail"]["threatTop"] == 288
print("ok", len(nums))
EOF

# 2. the generator agrees with the STRIDE document's §7 and Appendix A here
cd website && node scripts/gen-threat-model.mjs
# expect exactly: threatModel.ts: 9 diagrams, 288 threats (275 mitigated, 13 open)
git diff --stat -- src/threatModel.ts src/threatModelSummary.ts   # read it once, then:
git checkout -- src/threatModel.ts src/threatModelSummary.ts
cd ..

# 3. the three documents carry the same totals
grep -n "288" claude_dev/threat-model-stride.md claude_dev/threat-modeling-and-security.md | head
grep -n "4 open\|17 open" claude_dev/threat-model-stride.md            # expect nothing
```

Read the `threatModel.ts` diff before reverting it: four new nodes and four
new flows on diagram 2, nine threats added (two on existing nodes), no
existing node or flow coordinate changed, the open register byte-identical to
what the site renders today. If the summary diff shows any open count moving,
a status was typed wrong.

Open the JSON in Threat Dragon if a desktop is available — the file must load
and the OAuth2 diagram must show the four elements inside their boundaries.
If no desktop is available, say so in the commit message; the generator is the
gate CI has.

## 4. Records

One commit on `main`:

```
docs(threat-model): the nine Phase 21 entries enter the Threat Dragon file — model 2.17.0

T-272 … T-280 lived in threat-model-stride.md since 2026-09-17 and in
Axiam.json never; the dogfooding wave allocated T-281 … T-288 past them.
Four elements join the OAuth2 diagram (/oauth2/register, the CIMD fetch,
the externally registered client rows, the per-tenant path issuers); the
four findings closed in #475/#476 enter as Mitigated with their commit.
The STRIDE document's §5.3 count line and §7 open columns are corrected
(13 open, not 17); threat-modeling-and-security.md's three coverage tables
are corrected to 288. The generator now prints 288 / 275 / 13; the generated
website files are regenerated in the beta17 website pass, with the prose.
```

Then the EXECUTED block at the top of this file: the commit, what the
generator printed, whether Threat Dragon opened the file, and anything the
nine entries' text turned out to need.

---

## Appendix A — the numbers after this commit (model 2.17.0)

Headline: **288 threats, 275 mitigated / 13 open**, 9 diagrams, `threatTop` 288.

| Diagram | Threats | Open |
|---|---|---|
| System diagram | 33 | 2 |
| Authentication & session management | 35 | 0 |
| OAuth2 / OIDC authorization server | 58 | 0 |
| Federation — SAML SP & OIDC relying party | 31 | 1 |
| Authorization engine — RBAC, hierarchy & scopes | 27 | 0 |
| PKI, certificates & IoT device identity | 30 | 1 |
| Audit, webhooks, email & notifications | 18 | 1 |
| Deployment & platform (Kubernetes) | 28 | 5 |
| Client SDKs & admin UI integration surface | 28 | 3 |

By STRIDE category: Spoofing 70 (3 open), Tampering 59 (1), Repudiation 6 (0),
Information disclosure 67 (6), Denial of service 28 (2), Elevation of
privilege 58 (1). By severity: Critical 32 (1 open), High 135 (8), Medium 111
(3), Low 10 (1). The open items are the thirteen of 2.14.0, unchanged. The
OAuth2 diagram's 58 split 5 critical, 25 high, 24 medium, 4 low, as §5.3 says.

Derivation, so a wrong regeneration is noticed: the JSON today is 279 with
Spoofing 69, Information disclosure 65, Denial of service 25, Elevation of
privilege 55, Critical 30, High 133, Medium 107, Low 9; the nine add S+1,
I+2, D+3, E+3 and Critical+2, High+2, Medium+4, Low+1.

## Appendix B — the prompt for the session that executes this plan

> Read `claude_dev/threat-model-reconciliation-2026-09-25-plan.md` in the
> `ilpanich/axiam` repository and execute it: one commit directly on `main`,
> no pull request. Write T-272 … T-280 into
> `ThreatDragonModels/Axiam/Axiam.json` from the text
> `claude_dev/threat-model-stride.md` §5.3 already holds — four new elements
> on the OAuth2 diagram plus two threats on existing elements, the four
> "Closed" entries as `Mitigated` with their closing commit named first in
> the mitigation — bump the model version to 2.17.0, and correct the counts
> the plan lists in the STRIDE document (§5.3 line, §7 open columns, a §9
> bullet) and in `threat-modeling-and-security.md` (three coverage tables,
> one handoff sentence). Copy an existing cell's shape for every new cell,
> move no existing coordinate, and add no prose for any threat — that is the
> website plan's job. Verify with the plan's §3: the generator must print
> `9 diagrams, 288 threats (275 mitigated, 13 open)`, and the generated
> website files are then reverted, not committed. Add the EXECUTED blockquote
> at the top of the plan and mark `dogfooding-findings-fix-plan.md` §13 row 6
> done in the same commit.
