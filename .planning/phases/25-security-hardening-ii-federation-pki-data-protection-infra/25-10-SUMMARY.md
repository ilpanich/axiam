---
phase: 25-security-hardening-ii-federation-pki-data-protection-infra
plan: 10
subsystem: infra
tags: [kubernetes, networkpolicy, egress, secrets, ci, security]

# Dependency graph
requires:
  - phase: 25-security-hardening-ii-federation-pki-data-protection-infra
    provides: Phase-11 default-deny NetworkPolicy posture (default-deny.yml, allow-dns-egress.yml)
provides:
  - "SMTP egress NetworkPolicy rule (25/465/587) scoped to a fail-closed placeholder relay CIDR"
  - "Wide 443 egress rule's pod/service cluster-CIDR exclusions filled (no remaining TODO placeholders)"
  - "Completed k8s Secret key set (federation/email/GDPR/pepper keys)"
  - "Corrected CI test-job AXIAM__DB__/AXIAM__AMQP__ double-underscore env prefix"
affects: [k8s/network-policy/server-egress.yml, k8s/server/secret.yml, .github/workflows/ci.yml deploy consumers]

# Tech tracking
tech-stack:
  added: []
  patterns: [fail-closed placeholder CIDR (RFC 5737 TEST-NET-1) for operator-configured egress rules, kustomize/Helm-overridable CIDR exclusions on wide egress rules]

key-files:
  created:
    - .planning/phases/99-followups/25-10-networkpolicy-cluster-verification.md
  modified:
    - k8s/network-policy/server-egress.yml
    - k8s/server/secret.yml
    - .github/workflows/ci.yml

key-decisions:
  - "SMTP egress default CIDR set to 192.0.2.0/24 (RFC 5737 TEST-NET-1, documentation-only range never assigned to real hosts) rather than an empty/disabled rule — keeps the manifest structurally valid and self-documenting while guaranteeing fail-closed behavior until the operator supplies their real relay CIDR"
  - "Task 3 (checkpoint:human-verify NetworkPolicy enforcement + secret resolution on a live/kind cluster) deferred to deploy time rather than blocking phase completion — no cluster was available in the executing session; recorded as a tracked followup with the exact 5 verification steps and placeholder values an operator must replace"

requirements-completed: [SECHRD-10]

coverage:
  - id: D1
    description: "SMTP egress NetworkPolicy rule (25/465/587) exists, scoped to a configurable relay CIDR, never internet-wide"
    requirement: "SECHRD-10"
    verification:
      - kind: static
        ref: "python3 -c \"import yaml; list(yaml.safe_load_all(open('k8s/network-policy/server-egress.yml')))\" -- yaml-ok"
        status: pass
      - kind: manual
        ref: "99-followups/25-10-networkpolicy-cluster-verification.md step 2-3 (runtime enforcement)"
        status: deferred
    human_judgment: true
  - id: D2
    description: "Wide 443 egress rule's except: block contains pod-CIDR and service-CIDR exclusions, no remaining TODO placeholders"
    requirement: "SECHRD-10"
    verification:
      - kind: static
        ref: "k8s/network-policy/server-egress.yml except: block (10.244.0.0/16, 10.96.0.0/12)"
        status: pass
      - kind: manual
        ref: "99-followups/25-10-networkpolicy-cluster-verification.md step 3 (runtime enforcement)"
        status: deferred
    human_judgment: true
  - id: D3
    description: "k8s Secret includes federation/email/GDPR/pepper keys; CI test job uses AXIAM__DB__*/AXIAM__AMQP__* double-underscore prefix"
    requirement: "SECHRD-10"
    verification:
      - kind: static
        ref: "grep -Eq 'AXIAM__DB__URL' .github/workflows/ci.yml && grep -Eq 'AXIAM__AMQP__URL' .github/workflows/ci.yml -- prefix-ok"
        status: pass
      - kind: manual
        ref: "99-followups/25-10-networkpolicy-cluster-verification.md step 4-5 (secret resolution on a live pod)"
        status: deferred
    human_judgment: true

duration: 4min (Tasks 1-2 execution) + continuation session
completed: 2026-07-04
status: complete
---

# Phase 25 Plan 10: Network Egress & K8s Secret Completeness Summary

**Completed the SMTP egress NetworkPolicy rule, filled the wide-443 rule's cluster-CIDR exclusions, added the 4 missing k8s Secret keys, and fixed the CI env-prefix bug — all code/manifest deliverables for SECHRD-10 are done and fail-closed by construction; runtime cluster verification (NetworkPolicy enforcement + secret resolution) is deferred to deploy time and tracked as a followup.**

## Performance

- **Duration:** ~4 min (Tasks 1-2), continuation session for Task 3 resolution + closeout
- **Completed:** 2026-07-04
- **Tasks:** 3/3 (2 auto tasks executed; 1 checkpoint:human-verify resolved via deferral)
- **Files modified:** 3 (+ 1 followup file created)

## Accomplishments

- Added an SMTP egress `NetworkPolicy` rule to `server-egress.yml` (ports 25/465/587, TCP) scoped to a fail-closed default CIDR — `192.0.2.0/24` (RFC 5737 TEST-NET-1, a documentation-only range assigned to no real host) — so no SMTP egress is possible until an operator sets their real relay CIDR via a kustomize/Helm overlay. Never internet-wide (D-07b).
- Filled the two `# TODO` cluster-CIDR exclusion placeholders on the existing wide `443` egress rule's `except:` block with documented pod-CIDR (`10.244.0.0/16`, flannel/calico default) and service-CIDR (`10.96.0.0/12`, kubeadm default) example values, parameterized for per-cluster override (D-07c).
- Added the 4 missing keys to `k8s/server/secret.yml`: `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY`, `AXIAM__EMAIL_ENCRYPTION_KEY`, `AXIAM__GDPR_PSEUDONYM_PEPPER`, `AXIAM__AUTH__PEPPER` — matching the existing manifest style (blank values, deploy-time injection) and the `AXIAM__…` env names the app reads.
- Fixed the CI `test` job's env block: replaced the wrong-section, single-underscore `AXIAM_DATABASE__*` / `AXIAM_AMQP__URL` keys with the correct `AXIAM__DB__URL` / `AXIAM__DB__USERNAME` / `AXIAM__DB__PASSWORD` / `AXIAM__AMQP__URL` double-underscore form matching `main.rs`'s `Environment::with_prefix("AXIAM").separator("__")` and `AppConfig`'s `db` field.
- Resolved the Task 3 `checkpoint:human-verify` gate: no kind/live Kubernetes cluster was available in the executing session, so — per explicit user decision — runtime NetworkPolicy enforcement and Secret-resolution verification is **deferred to deploy time** rather than blocking phase completion. Recorded as `.planning/phases/99-followups/25-10-networkpolicy-cluster-verification.md`, which captures the exact 5 operator verification steps (dry-run apply; allowlisted SMTP egress ALLOWED once the relay CIDR is set; non-allowlisted egress DENIED; all 4 Secret keys resolve on pod startup; CI env prefix re-check) and the 3 placeholder values (`192.0.2.0/24` SMTP relay CIDR, `10.244.0.0/16` pod CIDR, `10.96.0.0/12` service CIDR) an operator must replace before relying on this configuration in production.

## Task Commits

1. **Task 1: Add SMTP egress rule + fill 443 CIDR exclusions + complete the k8s Secret** - `20f5a2b` (feat)
2. **Task 2: Fix the CI test-job env prefix to the AXIAM__ double-underscore form** - `f9e6db1` (fix)
3. **Task 3: checkpoint:human-verify — resolved via user decision "defer & complete"; see Deviations below** — no code commit (checkpoint resolution + followup file, this commit)

**State commit (pause point):** `d788d2e` (docs — STATE.md paused-at-checkpoint marker, superseded by this plan's closeout)

**Plan metadata:** (this commit, following SUMMARY.md write)

## Files Created/Modified

- `k8s/network-policy/server-egress.yml` — new SMTP egress rule (25/465/587) + filled pod/service CIDR exclusions on the wide 443 rule
- `k8s/server/secret.yml` — 4 new keys (federation encryption, email encryption, GDPR pepper, auth pepper)
- `.github/workflows/ci.yml` — corrected `test` job env prefix
- `.planning/phases/99-followups/25-10-networkpolicy-cluster-verification.md` — new followup tracking deferred runtime cluster verification

## Decisions Made

- Used RFC 5737 TEST-NET-1 (`192.0.2.0/24`) as the SMTP egress rule's default CIDR rather than an empty selector or a disabled rule — this keeps the manifest structurally valid, self-documenting via inline comments, and unambiguously fail-closed (the range resolves to no real host) until an operator configures a real relay.
- Deferred Task 3's `checkpoint:human-verify` (NetworkPolicy enforcement + secret resolution on a real/kind cluster) to deploy time per explicit user decision — no cluster was available in this session. This is represented honestly as a deferred verification, not as a completed one; the exact steps and placeholder values are tracked in a `99-followups/` entry rather than silently dropped.

## Deviations from Plan

**1. [Checkpoint resolution] Task 3 human-verify gate deferred rather than executed**
- **Found during:** Task 3 (checkpoint:human-verify)
- **Issue:** The plan's Task 3 requires applying manifests to a real or `kind` Kubernetes cluster to verify NetworkPolicy enforcement (allow relay SMTP, deny non-allowlisted egress) and Secret key resolution. No cluster was available in the executing environment.
- **Resolution:** Per explicit user decision ("defer & complete"), the runtime cluster verification is deferred to deploy time and tracked as a followup rather than blocking plan/phase completion. The code/manifest deliverables (Tasks 1-2) are complete, YAML-valid, and fail-closed by construction — only the *runtime enforcement* check is deferred, not the implementation.
- **Files created:** `.planning/phases/99-followups/25-10-networkpolicy-cluster-verification.md`
- **Commit:** this plan's closeout commit

No other deviations — Tasks 1-2 executed exactly as written.

## Issues Encountered

None beyond the expected absence of a Kubernetes cluster in the executor sandbox (see Deviations above).

## User Setup Required

- **Kubernetes cluster access** — an operator with a real or `kind` cluster must run through the 5 verification steps in `.planning/phases/99-followups/25-10-networkpolicy-cluster-verification.md` before relying on this NetworkPolicy + Secret configuration in production, and must replace the 3 placeholder CIDR values (SMTP relay, pod CIDR, service CIDR) documented there and inline in `server-egress.yml`.

## Next Phase Readiness

- SECHRD-10 code/manifest deliverables complete: SMTP egress rule, filled 443 CIDR exclusions, completed secret set, corrected CI prefix — all YAML-valid and fail-closed by construction.
- Runtime cluster verification (NetworkPolicy enforcement + secret resolution) is deferred and tracked in `99-followups/25-10-networkpolicy-cluster-verification.md` — not a blocker for subsequent phases, but should be closed out before a production deploy that relies on this egress posture.
- This was the final plan (10 of 10) in Phase 25 — phase closeout follows.

---
*Phase: 25-security-hardening-ii-federation-pki-data-protection-infra*
*Completed: 2026-07-04*

## Self-Check: PASSED

All modified files verified present on disk; task commit hashes (20f5a2b, f9e6db1) and state-pause commit (d788d2e) verified present in git log; followup file verified present on disk.
