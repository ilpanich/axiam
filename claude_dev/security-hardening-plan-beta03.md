# Security hardening plan — the beta03 gate and the open-threat backlog

> **Written 2026-08-28, hours before the `1.0.0-beta03` tag.** This document
> answers one question and plans the follow-up: *do any threats in the model
> require a security fix?* Each task below names the cheapest model adequate to
> it — **Sonnet 5** for mechanical, well-anchored changes; **Opus 5** only where
> a design decision or cross-repo judgment has to be made. Companion documents:
> [`threat-model-stride.md`](threat-model-stride.md) (the model, 199 threats at
> 2.8.0), [`threat-modeling-and-security.md`](threat-modeling-and-security.md)
> (the website Security source + handoff).

## 0. Verdict

**No. None of the 199 threats records an unfixed vulnerability in AXIAM's
code, and nothing security-blocking stands between the current `main` and the
beta03 tag.**

The evidence, checked 2026-08-28 against `main` (`ff7a6ad`):

- **183 threats are Mitigated**, each pointing at a control in the codebase or
  the SDK contract. The beta03-window fixes themselves (removal cookies
  `e2d0ef8`/`673e55b`, organization-level sign-in `4b05944`, the spec-digest
  re-stamp `3a1146a`) are merged and recorded as T-189, T-190…T-193 context and
  T-199.
- **The 16 Open threats are open by design, not unfixed defects.** Every one
  states where responsibility lands: deployment edge protection (T-9),
  backup/snapshot custody (T-18, T-133, T-134), cluster-operator and Vault
  credential hygiene (T-124, T-180), device hardware (T-94), the final mail hop
  (T-123), integrator-side secret handling (T-146), registry-side supply chain
  (T-135, T-148), the accepted stateless-JWT revocation window (T-39, T-143),
  the off-by-default JIT growth bound (T-161), and the GDPR-vs-audit tension
  (T-110, T-118). An open item here is a documented residual risk with
  guidance, not a missing patch.
- **The findings register is clean.** `docs/compliance/FINDINGS.md` carries no
  open finding — F-03 (HIBP) turned out to be stale, not open: the check is
  shipped (`check_hibp` + `hibp_breaker.rs`, opt-in, k-anonymity, circuit
  breaker) and issue #99 is closed. The register was corrected in the same
  commit as this plan, along with T-110's equally stale "AXIAM does not enforce
  a retention period today" clause (the 730-day default sweep has existed since
  T-119 closed).
- **There are zero open GitHub issues** on `ilpanich/axiam`.

What follows is therefore a **hardening backlog** — tasks that close or narrow
Open threats — not a vulnerability queue. §1 is the short list worth running
before the tag; §2 is post-beta03.

## 1. Before the tag (P0)

### P0-1 · Confirm the scanning dashboards are clean · **human (or Sonnet 5 with `security-events` access)**

The beta03 cookie fix records CodeQL alerts #519–521 as fixed and the three
replacement `rust/insecure-cookie` flags as dismissed false positives
(`673e55b`). Before tagging, confirm on the GitHub Security tab that:
code scanning shows **no open, non-dismissed alert**; Dependabot shows no
open advisory-driven update on a runtime dependency; secret scanning shows no
hit. This is a two-minute browser check. (It could not be performed from the
session that wrote this plan — no code-scanning API access — which is the only
reason it is listed rather than done.)

### P0-2 · Release provenance for the beta03 artifacts · **Sonnet 5** · *optional — only if a validation run fits in the window*

The one code change worth considering pre-tag, because it pays off most if it
is in place *at* the tag: `.github/workflows/release.yml` already builds
binary tarballs and CycloneDX SBOMs on `v*` tags (the SBOM-01 job); it does
not yet publish **build-provenance attestations**, which is the exact clause
T-148 (the model's only open Critical) names as outstanding for integrator
verification.

- Add `actions/attest-build-provenance` (pinned by digest, like every other
  action in this repo's CI) over the release tarballs and SBOMs, with
  `permissions: id-token: write, attestations: write, contents: read` scoped to
  that job. Purely additive: it must not gate or reorder the existing jobs.
- **The caveat that makes this optional**: `release.yml` runs on the tag you
  are about to push, and an untested workflow change hours before a release is
  how releases break. Do it only if you can validate first — a
  `workflow_dispatch` trigger added alongside, or a throwaway `v0.0.0-wftest`
  tag on a branch, then delete both. If the window does not allow that,
  this becomes the first post-beta03 task, unchanged.
- After it lands and a release has attested artifacts, update T-148's
  mitigation (see the update rule in §3) — the threat stays Open until the SDK
  repos follow (H-1), but the server half of the provenance clause closes.

### Already done in the commit that carries this plan

- `docs/compliance/FINDINGS.md`: F-03 corrected Deferred → Fixed; the
  deferred-findings summary now states no open finding remains.
- T-110's mitigation no longer claims AXIAM ships no retention bound; model,
  generated website data and the stride document all updated.

**If P0-2 is skipped, tagging beta03 requires only P0-1 — the two-minute
dashboard check.**

## 2. After the tag — the hardening backlog, in value order

### H-1 · T-148 (Critical, Open): the SDK release pipelines · **Sonnet 5** for the per-repo work, **Opus 5** for one memo

The largest open risk in the model. Per its mitigation text: Rust, TypeScript,
Python, C# and `axiam-opaque` publish via Trusted Publishing (OIDC, no stored
token); PHP via Packagist webhook; Go/Swift/C/C++ from git tags; **Java and
Kotlin still publish to Maven Central with stored credentials**.

1. **Opus 5, first, one page**: a decision memo on the Maven Central path —
   what Sonatype's current publishing options are (research the current state;
   do not trust training data on this), whether stored credentials can be
   eliminated, and if not, the compensating controls: a GitHub environment with
   required reviewers around the publish job, short-lived scoped tokens,
   rotation cadence. Opus because this is judgment about an external ecosystem
   that moves, and the wrong call either blocks releases or leaves the gap open
   while claiming to close it.
2. **Sonnet 5, then, mechanical and per-repo** across the eleven
   `axiam-<lang>-sdk` repos: verify every release workflow pins actions by
   digest; add `attest-build-provenance` to each; confirm Trusted Publishing is
   actually configured registry-side where the model says it is; implement the
   memo's Maven decision. One PR per repo, same shape.
3. Fold the outcome back into T-148's mitigation. If Maven ends up
   credential-free and provenance ships everywhere, T-148 is a candidate to
   flip Mitigated; otherwise it stays Open with a narrower residual.

### H-2 · T-118 (Medium, Open): audit records deleted with the tenant · **Opus 5** design memo, then **Sonnet 5** implementation

Today, deleting a tenant deletes its audit trail — evidence disappearing
exactly when it matters — and the model punts to "export to a WORM sink
first". This is closable in-product, but it is a design decision because it
sits on the GDPR-erasure tension: refuse tenant deletion until an export is
acknowledged? auto-export to a configured sink when one exists? require an
explicit `?discard_audit=true` acknowledgment? Opus writes the memo choosing
one (with the Art. 17 interaction argued); Sonnet implements it behind the
existing handler + audit-service seams. Closing this flips T-118 to Mitigated.

### H-3 · T-9 (Medium, Open): ingress edge hardening in the shipped manifests · **Sonnet 5**

AXIAM cannot absorb a connection flood in-app, but the shipped `k8s/`
manifests can carry the edge posture instead of leaving it entirely to the
reader: ingress-nginx rate-limit/connection-limit annotations (commented,
off-by-default, sized from `docs/deployment/rate-limit-sizing.md`), plus a
hardening-checklist row on the website's `hardening` page. T-9 stays Open —
the edge is still the deployment's — but its residual narrows and the guidance
becomes copy-pasteable.

### H-4 · T-180 (High, Open): make the Vault posture checkable · **Sonnet 5**

Nothing in-product can stop an over-scoped Vault token, but
`scripts/vault-status.py` (presence-only reporting, by design) can additionally
warn when the token it holds has more than read on AXIAM's KV path — the
exact misconfiguration T-180 describes — without ever printing a value. Small,
self-contained, and turns a documented rule into a checked one.

### H-5 · T-135 (High, Open): registry account hygiene · **human + Sonnet 5**

The controls are account-side: reserved/verified package names, 2FA on every
registry account, and (once H-1 lands) a "verify what you installed" section
on the website's `sdks` page showing the provenance-verification command per
ecosystem. The account actions are the owner's; the docs half is Sonnet.

### Explicitly no action — so nobody re-litigates them

| Threats | Why no task exists |
|---|---|
| T-39, T-143 | The stateless-JWT revocation window is an accepted trade-off, bounded at 15 minutes, with the introspection path documented for deployments that need immediacy. Re-architecting token verification is not a beta-line item. |
| T-18, T-133, T-134 | Backup custody and transport are the deployment's; AXIAM ships the guidance and cannot enforce it from inside a pod. |
| T-94 | Device-side key extraction is the integrator's hardware problem; AXIAM already bounds it (per-device certs, validity caps, immediate revocation). |
| T-123 | The provider-to-recipient mail hop is inherent to email; tokens carried in mail are single-use and short-lived. |
| T-124 | Cluster-admin equals full compromise by assumption 4 of the model; that is governed outside AXIAM. |
| T-146 | Integrator-side secret handling; the product already offers the alternatives (mTLS, rotation endpoint). |
| T-161 | Off by default, audited, role-less on creation, rate-bounded; accepted with eyes open. |
| T-110 | Now correctly described (bounded retention + minimised metadata + pseudonymising erasure); the residual is the deployment's lawful-basis setting, which no default can choose for them. |

## 3. Rules for whichever session runs this

- **Every task that changes a control updates the model in the same PR**:
  `ThreatDragonModels/Axiam/Axiam.json` (the source of truth), then
  `npm run gen:threat-model` in `website/`, then the matching rows/blocks in
  `threat-model-stride.md` — §9 of that document states the procedure, and
  threat numbers are append-only (`threatTop` currently 199). Flipping a threat
  to Mitigated also moves it out of the stride doc's §6 register and changes
  the count lines and §7 tables.
- **Do not invent controls in mitigation text.** A mitigation is written only
  after the control exists and can be pointed at — the model's credibility is
  that rule.
- **CI expectations**: `cargo fmt`/`clippy -D warnings` (scope with `-p`),
  `tsc -b` + `oxlint` for `website/`, `bash scripts/check-doc-links.sh`,
  actions pinned by digest, signed-off commits. Build-environment notes
  (swagger-ui placeholder, `--no-default-features` without libxml2, disk
  hygiene) are in `CLAUDE.md`.
- **Workflow changes get a validation run before they meet a real tag** —
  the P0-2 caveat generalises.
