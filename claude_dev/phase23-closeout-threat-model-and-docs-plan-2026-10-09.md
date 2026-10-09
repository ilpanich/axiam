# Phase 23 close-out — bringing the threat model and the documentation to the shipped state (model 2.37.0)

> **Status: PLAN — ready to execute.** Written on 2026-10-09 against `main` at
> `21a9c22` (the merge of PR #575, `1.0.0-beta19`) and against the eleven SDK
> repositories at their `claude/contract-1.58-sync` merges of the same day. It
> is the document the Phase 23 summary in
> [`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md)
> §5 and the W6 F4 review's §15 both assume will exist: the work left on the
> *record* once the work on the *product* is done. Everything here is
> documentation, the threat model included; nothing here changes a route, a
> shape or a default.
>
> **Execution target.** The threat-model and documentation commits land on
> `main` directly, as the 2026-09-25 reconciliation did
> ([`threat-model-reconciliation-2026-09-25-plan.md`](threat-model-reconciliation-2026-09-25-plan.md)):
> one commit per wave, no feature branch. The one exception is Wave B, the
> contract 1.59 review, because it edits normative text every SDK vendors; it
> goes through a pull request as 1.49 (PR for §28.11) and 1.52 (PR #500) did.
> See D-1 below if the maintainer prefers otherwise.

---

## 0. The state, measured

Counted on 2026-10-09 from the files and the repositories, not from what the
documents say about themselves.

### 0.1 The remediation plan — every activity accounted for

| Item | Plan status | Verified against | Finding |
|---|---|---|---|
| G-1 certification | Shipped, submissions pending | #513 open; `docs/conformance/` last run 2026-09-25; `fapi-conformance.yml` first end-to-end run under D-60 | Correct. The remaining step is the maintainer's browser-driven runs and the submission. Not this plan's work |
| G-2 SAML IdP | Shipped (W3–W4) | design chapter 8e, contract §29, T-304 … T-384, website `saml-idp` page, PR #573 (the participant-record race, `b2d83ec`) | Correct and current |
| G-3 LDAP / AD | Shipped (W2–W3) | design chapter 8d, contract §30, T-291 … T-355, `docs/deployment/README.md` directory section, website `directory` page | Correct and current |
| G-4 RFC 7592 | Shipped (W1) | contract §28.12, T-289 | Correct. `docs/api/README.md`'s registration section still names RFC 7591 only (§3.2 below) |
| G-5 SSF | Shipped (W4) | contract §32, T-385 … T-406, website `ssf` page | Correct. **T-388 is still Open** although its closing condition is met (§1) |
| G-6 outbound SCIM | Shipped (W5) | contract §31, T-407 … T-420, website `scim-outbound` page | Correct and current |
| G-7 CIBA | Shipped (W5) | contract §33, T-421 … T-447, website `ciba` page | Correct and current |
| G-8 minimal profile | Shipped (W5) | `docs/deployment/README.md` *Minimal profile (no broker)*, T-444, T-445 | Correct and current |
| G-9 verifiable credentials | Design only | [`verifiable-credentials-design.md`](verifiable-credentials-design.md) | Correct |
| G-10 benchmark currency | Half shipped (W6a) | #561 open; `benchmarks/PUBLIC_BENCH_ANALYSIS.md` is the sixth draft; the website's Benchmarks page cites run 5 (Keycloak 26.7.0, Zitadel v4.16.2) | Correct. **W6b has not run**: no run-6 numbers exist anywhere in the tree. This is the "profiling" the maintainer expects to still be open, and this plan does not wait for it (§5) |
| G-11 RADIUS | Spike done, declined | [`radius-eap-tls-spike-2026-10-06.md`](radius-eap-tls-spike-2026-10-06.md), §5.10 of the STRIDE model, T-448 … T-468 Not applicable, #562 closed, #563 open on request | Correct |
| G-12, G-13, G-14, G-15 | Declined / on demand / watch / documentation | D-6; `docs/guides/identity-for-agents.md`; website `agents` page | Correct |
| F4 reviews | Six, 79 findings | the six review documents; 26 finding issues open (#517 … #569) | Correct. The findings are tracked work, not plan activities |

Nothing in the plan is unaccounted for. Two activities remain open by design
and belong to the maintainer: the G-1 submissions (#513) and run 6 (#561).

### 0.2 The SDK fan-out — done, and not yet recorded anywhere in this repository

All four tracking issues of decision D-35 are open with every checkbox
unticked: #540 (contracts 1.53–1.55), #541 (1.56), #547 (1.57) and #548 (1.58).
The repositories say otherwise. Each of the eleven merged a pull request from
`claude/contract-1.58-sync` on 2026-10-09:

| SDK | Merge | `CONTRACT.md` | `openapi.json` digest | Conformance statement |
|---|---|---|---|---|
| Rust | #123 | byte-identical to `main` | `a74b9a35…` = `main` | contract 1.58: … §28.12, §29, §30, §31, §32, §32.7, §33, §33.2 signed |
| TypeScript | #131 | identical | identical | same claim |
| Python | #93 | identical | identical | same claim |
| Java | #108 | identical | identical | same claim |
| C# | #101 | identical | identical | same claim (§33.2 via `CibaRequestSigner`, PS256 / ES256 / EdDSA) |
| PHP | #78 | identical | identical | same claim |
| Go | #93 | identical | identical | same claim |
| Kotlin | #72 | identical | identical | same claim — the four REST-only SDKs took the §32.7 and §33 MAYs as well |
| Swift | #70 | identical | identical | same claim |
| C | #69 | identical | identical | same claim |
| C++ | #71 | identical | identical | same claim |

Every SDK ships the four management namespaces (`directory`, `saml`,
`scim_targets`, `ssf` — 190 operations across 28 namespaces), the §32.7
receiver helper with the seven-day replay floor, and the §33 CIBA helper with
the signed form. The replay test the contract requires (§32.8 helper test 6)
exists in each repository, which is what T-388's closing condition names:

| SDK | Replay test |
|---|---|
| Rust | `tests/ssf_receiver_test.rs::a_replay_is_refused_and_a_short_window_is_refused_at_configuration` |
| TypeScript | `test/node/ssfReceiver.test.ts` — `describe('§32.8 receiver (6) — a replay is refused; a short window is refused at configuration')` / `it('the second sighting is replayed')` |
| Python | `tests/test_ssf_receiver.py::test_a_replay_is_refused_and_a_short_window_is_refused_at_configuration` |
| Java | `src/test/java/io/axiam/sdk/ssf/SsfReceiverTest.java#aReplayIsRefusedAndAShortWindowIsRefusedAtConfiguration` |
| C# | `tests/Axiam.Sdk.Tests/SsfReceiverTests.cs#ASecondSightingIsReplayedAndAShortWindowIsRefused` |
| PHP | `tests/Contract158/SsfReceiverTest.php::testAReplayIsRefusedAndAShortWindowIsRefusedAtConfiguration` |
| Go | `ssf_receiver_test.go::TestSsfReceiver_AReplayIsRefusedAndAShortWindowIsRefusedAtConfiguration` |
| Kotlin | `src/test/kotlin/io/axiam/sdk/ssf/SsfReceiverTest.kt` — `` `a replay is refused and a short window is refused at configuration` `` |
| Swift | `Tests/AxiamSDKTests/SsfReceiverTests.swift#testAReplayIsRefusedAndAShortWindowIsRefusedAtConfiguration` |
| C | `tests/test_ssf_receiver.c::test_the_same_set_twice_is_replayed_and_the_window_has_a_floor` |
| C++ | `tests/test_ssf_receiver.cpp` `"§32.8 helper (6): the same SET twice is replayed …"` |

No SDK has tagged a release carrying 1.58: every repository's latest tag is
`v1.0.0-beta17`. That is the SDKs' own release cadence and is not a blocker
here; the ports are merged on their default branches, which is what D-35 and
plan §7 rule 1 require.

What this repository still says about the fan-out, all of it now false:

- `sdks/CONTRACT.md` §29.10, §30.10, §31.10, §32.10 and §33.10 each open with
  "**No SDK implements** §NN". These tables are filled "by the review that reads
  the merged ports" (§28.10's rule) — contract **1.59**, which does not exist yet.
- `ThreatDragonModels/Axiam/Axiam.json`, `threat-model-stride.md` and
  `threat-modeling-and-security.md` carry **T-388 Open**, "until the §32
  receiver helper ships in the seven full-surface SDKs".
- `website/src/security.ts` line 504 and `website/src/docs/reference.ts`
  (the `sdks` page: heading "What moved in contract 1.40–1.52", rows ending at
  1.52, "the drift check reports every repository at 1.52").
- The four tracking issues.

### 0.3 The threat model — three artifacts, one website, all agreeing at 2.36.1

| Artifact | Threats | Mitigated / Open / Not applicable | Version |
|---|---|---|---|
| `ThreatDragonModels/Axiam/Axiam.json` | 469, numbers 1 … 469 each exactly once | 425 / 23 / 21 | 2.36.1, `threatTop` 469 |
| `threat-model-stride.md` §6, §7 | 469 | 425 / 23 / 21 | 2.36.1 |
| `threat-modeling-and-security.md` tables | 469 | 425 / 23 / 21 | 2.36.1 in the handoff |
| `website/src/threatModel.ts`, `threatModelSummary.ts` (generated, committed) | 469 | 425 / 23 / 21 | 2.36.1 |

`node website/scripts/gen-threat-model.mjs` prints
`threatModel.ts: 10 diagrams, 469 threats (425 mitigated, 23 open, 21 not applicable)`
and produces **no diff** against the committed files; neither do
`gen-api-index.mjs` (`276 operations across 189 paths, 12 domains`) nor
`gen-contract-anchors.mjs` (`247 sections at contract 1.58`). Unlike
2026-09-25, there is no reconciliation to do: the waves kept the three artifacts
level, commit by commit. What is stale is *prose around the numbers*, and one
status:

- `threat-modeling-and-security.md` line 1124 — "a **STRIDE threat model of 447
  threats**" — in *Security at a glance*, two waves behind the table nineteen
  lines below it (the website computes this sentence from the model and is
  right; the source is wrong).
- The same document's handoff **status line** still reads "source current as of
  2026-09-25 (`main` before `1.0.0-beta17`, model 2.17.0)", followed by eleven
  Phase 23 paragraphs it never summarised in a new status line; and its closing
  stamp, "last re-derived from source at `main` before `1.0.0-beta17` (model
  2.17.0) on 2026-09-25".
- `website/src/version.ts`: `SECURITY_VERIFIED_RELEASE = "1.0.0-beta17"`,
  `SECURITY_VERIFIED_DATE = "2026-09-25"`, `DOCS_VERIFIED_RELEASE = "1.0.0-beta17"`
  — the Security prose was mirrored wave by wave (line 136 of `security.ts`
  already speaks of model 2.36.1) but the stamp never moved, and 32 docs pages
  carry a stamp that says beta17 while describing beta18 behaviour.
- **T-388** (§0.2): the one entry whose status is wrong.

The 23 open entries by kind, as the W6 review's §15 left them: five defects
with a fix filed (T-447 #549, T-469 #564, T-102 #565, T-108 #553, T-117 #551),
five accepted trade-offs (T-306, T-380, T-161, T-405, T-445), **one waiting on
the fan-out (T-388)**, eight deployment responsibilities, four on the
integrator or distribution side. After this plan the third row is gone.

### 0.4 The documentation — current on the website, behind in `docs/` and the design document

The website carries a page for every Phase 23 surface (`directory`, `saml-idp`,
`ssf`, `ciba`, `scim-outbound`, `agents`, the minimal profile under `deploy`),
and `docSectionsAreComplete()` holds. The repository's own documentation does
not keep up with it:

| Where | What is stale or missing | Evidence |
|---|---|---|
| [`design-document.md`](design-document.md) | Chapters **8d** (directory) and **8e** (SAML IdP) exist. There is **no chapter** for RFC 7592 (G-4), the SSF transmitter (G-5), outbound SCIM (G-6), CIBA (G-7) or the minimal profile (G-8); the strings `bc-authorize`, `Shared Signals`, `scim_target`, `AMQP__ENABLED` and `minimal profile` do not occur in it. G-9's design document is not linked | `grep` over the file |
| `docs/README.md` | "Last verified 2026-07-06", milestone "v1.2"; lists **seven** SDK repositories of eleven; no entry for `security-profiles.md`, `conformance/`, `admin/fapi2-profile.md`, `admin/browser-login-hop.md`, `admin/oidc-authn-parameters.md`, `admin/client-id-metadata-documents.md`, `admin/organization-scope.md`, `admin/public-clients.md`, `api/device-flow.md`, `api/token-exchange.md`, `api/federated-token-exchange.md`, `api/resource-indicators.md`, `api/mcp.md`, `api/uma.md`, `api/logout.md`, `user/passkeys.md`, `deployment/vault.md`, `deployment/rpi5-k3s.md`; nothing on the directory, SAML IdP, SSF, CIBA, outbound SCIM or the minimal profile | read |
| `docs/api/README.md` | "Last verified 2026-07-06". The registration section names RFC 7591 only (no 7592); no section for CIBA (`POST /oauth2/bc-authorize`, the grant, the approval routes), SSF (`/ssf/v1/*`, RFC 8935 push, RFC 8936 poll, the stream registry), the SAML IdP endpoints (behind the `saml` feature, excluded from the committed spec — say so), outbound SCIM targets or directory management | read |
| `docs/admin/README.md` | No task-oriented entry for the four new console pages (Directory, SAML Service Providers, SSF streams, SCIM targets) or for CIBA approvals; the pattern for a feature is a page under `docs/admin/` (`dynamic-client-registration.md`, `fapi2-profile.md`) | read |
| `docs/pki/README.md` | "Last verified 2026-07-06"; the words "CRL" and "revocation list" do not occur, although T-102 is Open since 2.36.0 for exactly that and #565 tracks it; the guide must state the reach of a revocation (device sign-in by certificate: immediate; TLS handshakes and `tls_client_auth`: no status check; relying parties outside AXIAM: no channel) | `grep` over the file |
| `docs/compliance/oidc-conformance.md`, `oauth2-rfc-compliance.md` | No matrix row for CIBA Core 1.0, RFC 7592, RFC 8417 / 8935 / 8936 (SSF), the SAML 2.0 IdP profiles or the directory's RFC 4511 / 4513 / 4515 obligations; `oauth2-rfc-compliance.md` stops at RFC 7662 | read |
| `docs/compliance/asvs-l2-checklist.md` | The V2, V3 and V9 rows cite no Phase 23 control: the directory bind (TLS before bind, RFC 4515 escaping, the lockout in front of the directory), the SAML IdP's signed assertions and SLO, CIBA's approval-only-by-console rule | `grep` over the file |
| [`security-audit.md`](security-audit.md) | "Last verified 2026-07-06", commit `c79b66e`; the scope list has no `axiam-directory`, no SSF, CIBA or outbound SCIM; it is the **master citation index** the website's compliance posture links to | read |
| `SECURITY.md` | "This is alpha software", "the next `1.0.0-alpha*` release" — the tree is at `1.0.0-beta19` | read |
| `README.md` | The feature list says "SAML and OIDC for cross-domain SSO; SCIM 2.0 for IdP-driven user and group lifecycle" — nothing on the SAML *identity provider*, LDAP / AD, SSF, CIBA, outbound SCIM or the broker-less profile | `grep` over the file |
| `website/src/docs/reference.ts` (`sdks`) | Rows stop at 1.52; heading "What moved in contract 1.40–1.52"; "the drift check reports every repository at 1.52" | read |
| `website/src/security.ts` line 504 | "Contracts 1.47 to 1.52 followed … the drift check reports all eleven at 1.52" | read |
| `website/src/data.ts` (news) | Latest post dated September 25, 2026, covering beta16 and beta17; **no post for `1.0.0-beta18`** (the whole Phase 23 release) or `1.0.0-beta19` | read |
| `website/src/data.ts` (roadmap) | Phase 20's `focus` is the open-ended beta line; it does not mention Phase 23's eight gaps, the way the beta17 pass folded Phases 21–22 into it | read |
| `website/src/pages/Benchmarks.tsx`, `data.ts` | Run 5, Keycloak 26.7.0, Zitadel v4.16.2 — **waits for W6b** and is not this plan's work | read |
| [`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md) | Its status block ends at W6a; the fan-out's completion and this plan are not recorded there | read |

The three competitor comparisons were refreshed in W6a and need nothing until
run 6. `CHANGELOG.md`, `roadmap.md` and `CLAUDE.md` are current.

---

## 1. What changes in the threat model, and what does not

**One status flips.** T-388 — *A captured SET is replayed to its receiver* —
moves from Open to **Mitigated**. Its closing condition was written into the
entry at 2.27.0 and repeated at 2.28.0, in §6 and in the W6 review's §15: the
§32.7 receiver helper, with `jti` de-duplication over a window of at least
seven days, shipped in the SDKs. It has, in all eleven (§0.2), each with the
replay test the contract requires. The AXIAM half of the control was already in
the entry (a 128-bit CSPRNG `jti` per event, byte-identical SETs on retry,
D-48).

This is the second-half rule of §9 of the STRIDE model — "for a control with a
server half and a client half, when the *second* half lands" — exactly as T-39
and T-143 closed on 2026-09-13 when every SDK polled the revocation feed. The
entry text keeps its history and gains the closing paragraph; nothing is
rewritten.

**Nothing else changes in the model.** No threat enters (next id stays
**T-470**, `threatTop` stays **469**), no element or flow moves, no other
status changes, no mitigation text is re-judged. The 22 that stay open are the
W6 review's list minus T-388; each has its reason in §6 and this plan does not
revisit them. In particular T-447, T-469 and T-102 stay open until #549, #564
and #565 land code, which is not documentation work.

**Version.** The counts change, so the model moves to **2.37.0** (the 2.28.0
precedent: "the model version is bumped … because the counts change"). After
the commit:

| | Before | After |
|---|---|---|
| Threats | 469 | 469 |
| Mitigated / Open / Not applicable | 425 / 23 / 21 | **426 / 22 / 21** |
| §7 by category — Tampering, Open | 2 | **1** |
| §7 by severity — Medium, Open | 10 | **9** |
| §7 by diagram — *Audit, webhooks, email & notifications*, Open | 5 | **4** |
| Generator line | `469 threats (425 mitigated, 23 open, 21 not applicable)` | `469 threats (426 mitigated, 22 open, 21 not applicable)` |

Every other row of every §7 table is unchanged.

---

## 2. Wave A — the threat model at 2.37.0 (one commit on `main`)

Model: **Opus 5.5** (plan §6 rule (b): a threat-model entry is normative text).
Size: S.

### 2.1 `ThreatDragonModels/Axiam/Axiam.json`

On diagram *Audit, webhooks, email & notifications*, flow `SET push / poll
response`, threat `number` 388:

- `status`: `Open` → `Mitigated`.
- `mitigation`: keep the existing text up to and including "(D-48). Tests:
  `crates/axiam-oauth2/src/ssf.rs` `every_jti_is_unique`,
  `signing_the_same_pending_event_twice_gives_the_same_set`. Push travels over
  TLS to an `https` endpoint only, and poll responses are `no-store`." Replace
  the sentence beginning "Open because the control is the receiver's" with a
  paragraph in this shape (the eleven test names are in §0.2's table, read
  from the repositories; cite them as written there):

  > Closed on 2026-10-09 (contract 1.58 fan-out, D-35): the receiver's half is
  > the §32.7 helper, which remembers every `jti` it accepted in a pluggable
  > store over a window that cannot be configured below seven days and refuses
  > a repeat with `replayed`. It shipped in all eleven SDKs, the four REST-only
  > ones included, each with contract §32.8 helper test 6 — Rust
  > `tests/ssf_receiver_test.rs::a_replay_is_refused_and_a_short_window_is_refused_at_configuration`,
  > … (one per SDK, from §0.2). A receiver written without the helper is still
  > exposed for as long as it treats an old SET as news, which is why RFC 8417
  > §4.1 and §32.7 make it a MUST for any receiver, not a property of AXIAM.

- `hasOpenThreats` on that flow cell: recompute from the statuses of the
  threats it carries (the flag is derived; the generator counts statuses, but
  the JSON should agree with itself — the 2026-09-12 precedent).
- `version`: `2.36.1` → `2.37.0`. `threatTop` stays `469`.

Nothing else in the file changes. The diff is one threat object and the
version field.

### 2.2 `claude_dev/threat-model-stride.md`

- Header table: model version 2.37.0; Mitigated / Open / Not applicable
  **426 / 22 / 21**.
- §5.7 (*Audit, webhooks, email & notifications*): the T-388 row (line ~3171)
  reads `Mitigated`; the detail block (line ~3356) takes the mitigation text
  of §2.1 verbatim in the `>` quoted form the document uses; the
  per-diagram intro paragraph that narrates 2.27.0 → 2.28.0 ("**T-388** stays
  Open: the receiver's `jti` de-duplication ships in the SDK receiver helper")
  gains one sentence recording the 2.37.0 closure rather than being edited.
- §6: the opening paragraph's count ("23 of 469 threats remain open") →
  **22**; remove the T-388 row from the register table; in *Grouping*, remove
  the bullet "A replayed SET (T-388) is the receiver's to refuse …" and, where
  the prose says T-388 "stays until the receiver helper … ships in the SDKs",
  append "— it did, on 2026-10-09, and T-388 is Mitigated at 2.37.0" rather
  than deleting the history.
- §7: the three cells of §1's table.
- §9: add the 2.37.0 example to the second-half bullet, after the T-39 / T-143
  sentence: "T-388 is the 2026-10-09 example: Open from 2.27.0 through four
  waves because the control was the receiver's, closed when the §32.7 helper
  shipped in all eleven SDKs, each with its replay test."

### 2.3 `claude_dev/threat-modeling-and-security.md`

- **Handoff block.** Replace the status line with: "**Status: source current as
  of 2026-10-09 (`main` at `1.0.0-beta19`, model 2.37.0 — Phase 23, the
  competitor-gap closure of `1.0.0-beta18`, and the contract 1.58 SDK
  fan-out).** The Phase 23 paragraphs below record the waves; this plan
  ([`phase23-closeout-threat-model-and-docs-plan-2026-10-09.md`](phase23-closeout-threat-model-and-docs-plan-2026-10-09.md))
  records the close-out." Then add one paragraph at the top of the dated
  paragraphs, in the register of the others: "**The contract 1.58 SDK fan-out
  (model 2.37.0 — T-388 closed).** …" — four or five sentences: what the
  helper does, that all eleven shipped it with the replay test, the counts.
- *Security at a glance*: "447 threats" → **469**.
- *The threat model* table: Mitigated / Open **426 / 22**.
- *Coverage by area*: *Audit, webhooks, email & notifications* Open 5 → 4.
  *Coverage by STRIDE category*: Tampering Open 2 → 1. *Coverage by severity*:
  Medium Open 10 → 9. "The 23 still-open items" → 22.
- The OAuth2 section paragraph that ends "leaving only T-388" (line ~1227) and
  the long *Federation* paragraph's clause "leaving a replayed SET open until
  the SDK receiver helper that de-duplicates its `jti` ships (T-388)": amend
  each to say it shipped and closed, in one clause.
- *Shared responsibility*: "23 of 469" → **22 of 469**; remove the T-388 row.
- *How security is maintained*, closing stamp: "last re-derived from source at
  `main` at **`1.0.0-beta19`** (model 2.37.0) on 2026-10-09".

### 2.4 `website/`

From `website/`: `npm run gen:threat-model`, then commit `src/threatModel.ts`
and `src/threatModelSummary.ts` **in the same commit** as §2.1 … §2.3 (every
website pass since beta11 has kept the page and the model together). Expected
summary: `version 2.37.0`, `open 22`, `mitigated 426`, the audit diagram's
`open` 4. Then mirror §2.3 into `src/security.ts`: the paragraph at line 136
(the T-388 clause), the line-504 SDK paragraph (§4.2 below carries the full
rewrite; here only "1.52" → the 1.58 sentence if Wave D is not run in the same
session), and the open-register prose if it is hand-written anywhere (it is
generated; verify). Move `SECURITY_VERIFIED_RELEASE` to `"1.0.0-beta19"` and
`SECURITY_VERIFIED_DATE` to `"2026-10-09"` in `src/version.ts` **in this
commit** — the stamp moves with the Security prose and the generated files,
never earlier and never alone (beta17 plan §2).

Before moving the stamp, diff `security.ts` against `threat-modeling-and-security.md`
section by section (the beta17 plan's Wave 1b discipline: mirror, do not
paraphrase; the four bullets whose bold markers deliberately differ stay). The
waves mirrored as they went, so this should be a reading pass, not a rewrite;
if a Phase 23 paragraph of the source has no counterpart on the site, add it
before stamping.

### 2.5 Commit

`docs(threat-model): T-388 closes with the contract 1.58 fan-out — model 2.37.0`.
The body names the eleven merges and the generator line. Signed, as every
roadmap commit is.

---

## 3. Wave C — the repository documentation (one commit on `main`)

Model: **Sonnet 5.5**, with one exception noted. Size: M. Order the edits so
`scripts/check-doc-links.sh` passes at the end; it fails closed on any broken
relative link.

### 3.1 `claude_dev/design-document.md` — the missing chapters

**Opus 5.5 for this file** (plan §6 rule (c): it is the cross-crate record).
Write, in the shape and length of **8d** and **8e** (a paragraph of what and
why, then "where each part lives" with crate and module paths, then the
decisions that bind it, then links to the contract section, the operator's
page and the threat entries):

- **8f — RFC 7592 client configuration** (G-4, T23.4.1): `dcr.rs`'s
  configuration endpoint, the registration access token, contract §28.12,
  T-289. Short.
- **8g — Shared Signals Framework transmitter** (G-5, W4): the shared outbound
  dispatcher extracted from the webhook engine (T23.5.1), streams, SET
  issuance, push (RFC 8935) and poll (RFC 8936), the step-up record, the
  per-tenant issuer rule (D-55), the seven-day DLQ TTL; contract §32;
  T-385 … T-406.
- **8h — Outbound SCIM provisioning** (G-6, W5): `ScimTarget`, the lifecycle
  translation on the dispatcher, reconciliation, dead letters and GDPR erasure
  propagation, the `base_url`-bound credential (T-409), one notification per
  target per hour (D-73); contract §31; T-407 … T-420. Say plainly that one
  unresponsive downstream stalls a replica's provisioning until #550 is
  decided.
- **8i — CIBA** (G-7, W5): `bc-authorize`, `auth_req_id` lifecycle, poll and
  ping, no push and no `user_code` (D-64, D-65), signed requests and the
  `fapi2` client (D-61), the approval-by-console-only rule (T-447), the
  vouched-address rule for the approval mail (D-74 as amended by P23W6-07);
  contract §33; T-421 … T-447.
- **8j — The minimal deployment profile** (G-8, W5): `AXIAM__AMQP__ENABLED=false`,
  what the broker carried and what replaces it in-process, the singleton lease
  and the orderly stop (T-444), what is lost on restart and why that is
  accepted for a single instance (T-445), the audit-path review's result
  (T23.8.2). Link `docs/deployment/README.md` *Minimal profile (no broker)*.
- In the federation chapter list or the table of contents, link
  [`verifiable-credentials-design.md`](verifiable-credentials-design.md) as
  the G-9 design and [`radius-eap-tls-spike-2026-10-06.md`](radius-eap-tls-spike-2026-10-06.md)
  as the G-11 decision, one line each.

Every claim comes from the plan's EXECUTED blocks, the contract sections and
the threat entries; nothing is written from memory of the code. Where a
chapter would duplicate a contract rule, link the rule.

### 3.2 `docs/` — index and landing pages

- `docs/README.md`: milestone and *Last verified* to `1.0.0-beta19` /
  2026-10-09; the SDK list to all eleven repositories; add every page listed
  as absent in §0.4 under its section; add a **Federation & provisioning**
  group linking `deployment/README.md`'s directory and minimal-profile
  sections, the design chapters 8d … 8j, the website pages for SAML IdP, SSF,
  CIBA and outbound SCIM, and contract §29 … §33 — the index links out, it does
  not duplicate (D-09).
- `docs/api/README.md`: *Last verified*; the registration section gains RFC
  7592 (the configuration endpoint, the registration access token, contract
  §28.12); new sections, each three to eight lines with the route list and a
  link to the contract section and the website page: **CIBA**, **Shared
  Signals Framework** (push and poll, the stream registry, the `ssf` and
  `ssf-receiver` tags, "not generated beyond `poll`"), **SAML identity
  provider** (behind the `saml` feature; the committed spec excludes it, as the
  *OpenAPI Export Feature Flag* note in the contract says), **Outbound SCIM
  targets**, **Directory** (`/api/v1/tenants/{tenant_id}/directory`). The
  *Authentication — who may call which route* table gains the rule that
  approval routes and every Phase 23 management family are human-only.
- `docs/admin/README.md`: one short section, *Phase 23 console pages*, naming
  the Directory, SAML Service Providers, SSF streams and SCIM targets pages
  and the CIBA approval surface, each linking its website page and the
  deployment-guide section where one exists. Do not write four new admin
  guides here; that is on-demand work (D-2).
- `docs/pki/README.md`: *Last verified*; a **Revocation reach** subsection
  stating what T-102's entry states at 2.36.1 — a device signing in by
  certificate is refused at once; neither listener's TLS handshake nor OAuth2
  `tls_client_auth` reads a certificate's status; no CRL or OCSP responder is
  published, so a relying party that validates AXIAM-issued certificates itself
  has no revocation channel (#565). The website's PKI page already says this
  (P23W6-04); the guide must not say less than the site.

### 3.3 `docs/compliance/` and the audit index

- `oauth2-rfc-compliance.md`: new sections **RFC 7592**, **RFC 8417 / 8935 /
  8936 (SSF)** and **OpenID Connect CIBA Core 1.0**, in the existing row
  shape (`#`, requirement, spec §, status, test). Rows cite the tests the
  contract change-log entries and the threat entries name; do not invent a
  row for a requirement no test covers — mark it *Partial* with the reason.
  Keep it to the MUSTs; the website's compliance page says "all tracked MUSTs
  pass", and a row this file cannot back is a claim the site then makes.
- `oidc-conformance.md`: a **CIBA** section pointing at the new matrix, and a
  note that FAPI-CIBA is the next certification target (plan D-5), unsubmitted.
- `asvs-l2-checklist.md`: no new rows. In the evidence column of V2.2.1
  (anti-automation), V2.2.2 (lockout), V3.5.1 (server-side session tokens) and
  V9.1.1 (TLS on every connection), add the Phase 23 controls: the directory bind over TLS only with
  the lockout in front of it (T-291 … T-303), SAML assertions signed and SLO
  tied to revocation (T-317 … T-330, T-370 … T-384), CIBA's lockout at request,
  approval and redemption (T-428, T-429). Update the *Summary* count only if a
  status changes; none should.
- `claude_dev/security-audit.md`: a dated **2026-10-09 addendum** at the top
  (do not rewrite the 2026-07-06 audit): the Phase 23 crates and surfaces now
  in scope (`axiam-directory`, the SAML IdP in `axiam-federation`, SSF, CIBA
  and outbound SCIM in `axiam-oauth2` / `axiam-scim`), the six F4 reviews as
  the review trail for them, and the threat-model version. *Last verified*
  moves only for the addendum's scope; say so.

### 3.4 Root files

- `SECURITY.md`: "alpha" → beta throughout; the supported-versions table reads
  `main` / latest `1.0.0-beta*`; keep the caution that there has been no
  independent audit or certification.
- `README.md`: the feature list gains the SAML 2.0 identity provider, LDAP /
  Active Directory as an identity source, the SSF transmitter, CIBA, outbound
  SCIM and the broker-less profile, one clause each; its phase table stops at
  Phase 18 — add rows for Phases 19–23 in the roadmap's wording, or replace
  the table with a link to `claude_dev/roadmap.md`'s summary.
- `CLAUDE.md` *Technology Stack* / SDK sentence: optional one-line note that,
  at contract 1.58, Kotlin, Swift, C and C++ also ship §32.7 and §33 (the MAYs
  taken). Only if Wave B's review confirms it from the ports.

### 3.5 The plan's own record

Append to the status block of
[`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md):
"**SDK fan-out complete, 2026-10-09:** all eleven repositories merged contract
1.58 (§0.2 of
[`phase23-closeout-threat-model-and-docs-plan-2026-10-09.md`](phase23-closeout-threat-model-and-docs-plan-2026-10-09.md));
#540, #541, #547, #548 close with contract 1.59; T-388 closes at model
2.37.0." And in the Phase 23 summary table, G-5's *What stays open* loses
"SDK receiver helper #541 (T-388)" and G-7's loses "SDK helper #548".

### 3.6 Commit

`docs: bring the repository documentation to Phase 23 — design chapters 8f–8j, API and PKI guides, compliance matrices`.

---

## 4. Wave D — the website (one commit on `main`)

Model: **Sonnet 5.5**. Size: S–M. Runs after Wave A (the stamp) and may run in
the same session as Wave C.

### 4.1 Ground rules (unchanged from every website pass)

Do not add claims: every sentence is backed by an EXECUTED block, a merged PR,
a threat entry or a conformance receipt. Do not upgrade the hedges: "a
self-run, not a certification", "`REVIEW` and `WARNING` are published, not
counted as passes", and now "no run-6 number exists yet". Corrections are
stated as corrections. `DOCS_VERIFIED_RELEASE` moves only after the sweep.

### 4.2 Edits

- `src/docs/reference.ts`, the `sdks` page: rows **1.53, 1.54, 1.55, 1.56,
  1.57, 1.58** in the existing row shape, each one sentence from the contract
  change-log entry; the heading becomes "What moved in contract 1.40–1.58";
  the paragraph rewritten to say: nineteen amendments since 1.39; the six
  Phase 23 contracts carried four management namespaces, the SSF receiver
  helper and the CIBA helper into all eleven repositories on 2026-10-09, the
  four REST-only SDKs taking the MAYs; the drift check reports every
  repository at 1.58; the cross-SDK review is 1.59 (link it once Wave B
  merges, else say "pending").
- `src/security.ts` line 504: the same facts in the Security section's
  register, replacing "Contracts 1.47 to 1.52 followed … reports all eleven at
  1.52" with the 1.53–1.58 sentence. Mirror the sentence into
  `threat-modeling-and-security.md`'s *Transport, secrets & the SDKs* section
  first if Wave A did not already (source before mirror).
- `src/data.ts`, news: one post, dated the day of the commit, titled for
  `1.0.0-beta18` and `1.0.0-beta19` together (the beta16/17 post is the
  precedent for a two-release post). Structure: the eight gaps closed and what
  each means to an integrator; the threat model from 2.17.0 to 2.37.0 in one
  paragraph, with the open register's movement stated honestly (13 → 22 open,
  and why: the specified-ahead entries all closed, the open ones are the W5
  and W6 reviews' findings and the trade-offs, listed by kind); the declined
  items (Kerberos, assertion encryption, front-channel logout, RADIUS, CIBA
  push) so nobody rediscovers them; beta19's three fixes; the SDK fan-out;
  what is still coming (run 6, the certification submissions). Every number
  from the CHANGELOG or the model, none from this plan's prose.
- `src/data.ts`, roadmap: phase 20's `focus` gains one sentence naming Phase
  23 (the beta17 precedent), unless the maintainer prefers a phase-23 row —
  D-3.
- Docs sweep: read the 32 stamped pages for any sentence Phase 23 made false
  (the beta17 pass found two such sentences; expect the `deploy` page's broker
  wording, the `federation` page's "SP only" framing if any, the `pki` page's
  revocation wording, the `compliance` page's conformance table and the
  `sdks` page). Fix, then move `DOCS_VERIFIED_RELEASE` to `"1.0.0-beta19"`.
- `src/docs/reference.ts`, the `compliance` page: confirm the conformance
  sentence cites the latest published reports (`docs/conformance/2026-09-25-*`)
  and says that the workflow's first unattended run (D-60, 2026-10-05) is a
  smoke run, not evidence. Nothing about a submission until #513 closes.

### 4.3 Verification

`npm run build` from `website/`; `docSectionsAreComplete()` holds; the three
generators produce no diff; open `#/security/diagram/6/T-388` (the audit
diagram's index as the explorer numbers it — confirm) and see Mitigated; the
open-only filter on that diagram lists four.

### 4.4 Commit

`docs(website): the Security and Docs sections at 1.0.0-beta19 — model 2.37.0, contract 1.58, the beta18/19 post`.

---

## 5. Wave B — contract 1.59, the cross-SDK review of the 1.53–1.58 ports (pull request)

Model: **Opus 5.5** (normative text). Size: M. Independent of Waves A, C, D;
A's T-388 text does not wait for it.

The contract's own rule (§28.10, repeated in §29.10 … §33.10) is that a
posture table is filled by the review that reads the merged ports, never by
the ports' reports of themselves. 1.49 (§28.11) and 1.52 (§27.14) are the
precedents; this is the third such review and the largest: five sections,
eleven repositories, 190 operations across 28 namespaces, two helpers.

- Read each repository at its 2026-10-09 merge (the table in §0.2). For each
  of §29 … §33: the namespace or helper present; `Sensitive<T>` on every member
  §NN.5 names; the required tests of §NN.8 present by name; the call-site
  documentation of §NN.3; the §21.3.1 pin at seven keys and the §21.10 row
  re-run; the conformance statement's wording. Record divergences as §27.14
  did (an id, the rule, the SDK, the fix or the reason it is not one).
- Fill **§29.10, §30.10, §31.10, §32.10, §33.10** with the per-SDK table, one
  row per SDK, `implemented` / `declines` with a reason; "not yet" is not a
  row. Record that the four REST-only SDKs took §32.7 and §33.
- A **§34 (or §33.11) — cross-SDK review, contract 1.59**, in §28.11's shape:
  what was read, the divergence table, the clarifications (expect a few: the
  helper's replay-store contract, `ciba_await`'s clock injection, the
  `update_stream` header-kept rule), no wire change.
- Change-log entry **2026-10 (contract 1.59)**, non-breaking; the Conformance
  Statement gains nothing new.
- `website/scripts/gen-contract-anchors.mjs` regenerated in the same PR
  (`CONTRACT_VERSION` → `"1.59"`).
- The PR closes **#540, #541, #547, #548** (tick every box first; the issues
  are the record of what was asked, the review of what was done). Per
  `CLAUDE.md`, issues close on merge.
- Then the eleven re-vendor PRs (the 1.52 precedent: one re-vendor per
  repository from the **merged** commit, never from the branch), tracked in
  one new issue.

**T-388's text does not cite 1.59.** It cites the ports and their tests, which
exist whether or not the review has been written; the review may later amend
the entry if it finds a helper that does not meet §32.7, which is the normal
course of a review and not a reason to leave the entry wrong today.

---

## 6. What this plan does not do

- **Run 6 and W6b** (#561): the seventh benchmark draft, the comparisons'
  performance rows and the website's Benchmarks page wait for the maintainer's
  measurement of `1.0.0-beta18`. Wave D's news post says so in one sentence.
  When W6b lands it brings its own website edit; nothing here pre-empts it.
- **The G-1 submissions** (#513): the website's conformance mark changes only
  when the OpenID Foundation lists AXIAM. Nothing here says "certified".
- **The 26 open review findings** (#517 … #569) and **#563**: code, not
  documentation. Three of them move threat statuses when they land (#549
  T-447, #564 T-469, #565 T-102); each such PR carries its own threat-model
  edit in the same commit, as plan §7 rule 2 requires.
- **No re-judging of open entries**, no renumbering, no new diagram, no change
  to `roadmap.md`'s Phase 23 line (it is correct), no edit to the six F4
  review documents (they are dated records; the W6 review's "one waiting on
  the fan-out" row is true of 2026-10-06 and stays).
- **No SDK repository is touched** by Waves A, C or D. Wave B's re-vendor PRs
  are the only SDK-side work, and they follow its merge.

---

## 7. Decisions requested from the maintainer

| # | Question | Recommendation |
|---|---|---|
| D-1 | Waves A, C and D directly on `main`, Wave B as a PR? | **Yes.** Documentation and the model have landed on `main` directly since 2026-09-25; the contract is normative and SDK-visible, so it keeps the PR discipline 1.49 and 1.52 used |
| D-2 | Four new `docs/admin/` guides for the Phase 23 console pages? | **No.** The website pages are the task-oriented guides (plan §7 rule 7); `docs/admin/README.md` links them. Write a repository guide when an adopter asks for one offline |
| D-3 | The website roadmap: extend phase 20's `focus`, or add rows for Phases 21–23? | **Extend phase 20**, the beta17 precedent; the roadmap page presents the beta line as one open-ended phase and the CHANGELOG is the per-release record |
| D-4 | Tag `v1.0.0-beta18` of each SDK after the 1.59 re-vendor? | **Maintainer's call, outside this plan.** The ports are merged and vendored; a tag is the SDKs' own release step and the website's SDK page says "merged", not "released", until then |

---

## 8. Verification, end to end

Run after Wave A, again after Wave D:

```bash
# 1. the JSON: every number 1..469 exactly once, 426 / 22 / 21, version 2.37.0, threatTop 469
python3 - <<'EOF'
import json, collections
m = json.load(open('ThreatDragonModels/Axiam/Axiam.json')); d = m['detail']
nums = collections.Counter(); st = collections.Counter()
for dg in d['diagrams']:
    for c in dg['cells']:
        for t in c.get('data', {}).get('threats') or []:
            nums[t['number']] += 1; st[t['status']] += 1
assert m['version'] == '2.37.0' and d['threatTop'] == 469
assert sorted(nums) == list(range(1, 470)) and max(nums.values()) == 1
assert st == {'Mitigated': 426, 'Open': 22, 'NotApplicable': 21}, st
print('ok', st)
EOF

# 2. the generator agrees, and the committed files carry what it prints
node website/scripts/gen-threat-model.mjs   # expect: 10 diagrams, 469 threats (426 mitigated, 22 open, 21 not applicable)
node website/scripts/gen-api-index.mjs
node website/scripts/gen-contract-anchors.mjs
git status --short                          # expect nothing after the wave's commit

# 3. the three documents carry the same totals
grep -c 'T-388' claude_dev/threat-model-stride.md claude_dev/threat-modeling-and-security.md
grep -n '469\b' claude_dev/threat-modeling-and-security.md | grep -i 'threats'   # no "447"
grep -n '447 threats' claude_dev/threat-modeling-and-security.md               # expect nothing

# 4. the docs
scripts/check-doc-links.sh
python3 scripts/check-spec-digest.py        # unchanged: no route changed
grep -rn 'alpha' SECURITY.md                # expect nothing but the history, if any
grep -n 'Last verified' docs/README.md docs/api/README.md docs/pki/README.md   # 2026-10-09

# 5. the website
cd website && npm run build && cd ..
grep -n 'VERIFIED' website/src/version.ts   # SECURITY_* and DOCS_VERIFIED_RELEASE at 1.0.0-beta19
```

---

## Appendix A — the numbers after Wave A (model 2.37.0)

| | |
|---|---|
| Model version | 2.37.0 |
| `threatTop` / next id | 469 / T-470 |
| Threats | 469 |
| Mitigated / Open / Not applicable | 426 / 22 / 21 |
| Open, by kind | defects with a fix filed 5 (T-447, T-469, T-102, T-108, T-117); accepted trade-offs 5 (T-306, T-380, T-161, T-405, T-445); deployment responsibility 8 (T-9, T-18, T-123, T-124, T-133, T-134, T-180, T-216); integrator, device and distribution side 4 (T-94, T-135, T-146, T-148) |
| Open ids | 9, 18, 94, 102, 108, 117, 123, 124, 133, 134, 135, 146, 148, 161, 180, 216, 306, 380, 405, 445, 447, 469 |
| Diagrams | 10 (§5.10 not built) |
| Trust boundaries | 10 built + 1 drawn, not built |
| Contract | 1.58 vendored by all eleven SDKs; 1.59 = the review (Wave B) |
| Stamps | `SECURITY_VERIFIED_RELEASE` 1.0.0-beta19 / 2026-10-09 (Wave A); `DOCS_VERIFIED_RELEASE` 1.0.0-beta19 (Wave D) |

## Appendix B — the prompt for the session that executes this plan

> Read `claude_dev/phase23-closeout-threat-model-and-docs-plan-2026-10-09.md`
> in full, then §0.2 of it again: the eleven SDK merges are the evidence for
> everything in Wave A, and you cite their test names from the repositories,
> not from the plan. Execute Wave A as one signed commit on `main`
> (`ThreatDragonModels/Axiam/Axiam.json`, `claude_dev/threat-model-stride.md`,
> `claude_dev/threat-modeling-and-security.md`, the two generated website
> files, `website/src/security.ts`, `website/src/version.ts`), and stop if
> the generator prints anything other than
> `10 diagrams, 469 threats (426 mitigated, 22 open, 21 not applicable)`.
> Then Wave C and Wave D, one signed commit each, running §8 after each. Do
> not open Wave B in the same session unless asked: it is a pull request with
> its own review. Add nothing to the model, re-judge nothing, and record a
> correction as a correction. Where this plan and a file disagree, the file
> wins and you say so in the commit body.
