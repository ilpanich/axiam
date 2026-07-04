---
type: verification
status: open
created: 2026-07-04
source: 25-10-PLAN.md Task 3 checkpoint:human-verify (deferred — no cluster available in executor session)
---

# NetworkPolicy egress + k8s Secret cluster verification (SECHRD-10)

## Problem

Plan 25-10 completed the code/manifest deliverables for SECHRD-10 (Network
Egress & K8s Secret Completeness):

- SMTP egress `NetworkPolicy` rule (ports 25/465/587), fail-closed by default
  (`k8s/network-policy/server-egress.yml`)
- Filled pod/service CIDR exclusions on the existing wide `443` egress rule
  (`k8s/network-policy/server-egress.yml`)
- Completed `k8s/server/secret.yml` key set (federation/email/GDPR/pepper keys
  added)
- Corrected CI `test` job env prefix to `AXIAM__DB__*` / `AXIAM__AMQP__*`
  (`.github/workflows/ci.yml`)

These are YAML-valid and fail-closed by construction (verified via
`yaml.safe_load_all` + `grep` in Tasks 1-2), but `NetworkPolicy` **enforcement**
cannot be asserted without a real or `kind` Kubernetes cluster — this was
flagged in the plan's own VALIDATION.md manual-only row. No cluster was
available in the executing session, so the plan's Task 3
`checkpoint:human-verify` gate is being deferred to deploy time rather than
blocking phase completion.

## Required operator verification steps (deploy time)

Before relying on this NetworkPolicy + Secret configuration in a real
deployment, an operator with cluster access MUST perform:

1. **Dry-run apply** — confirm both manifests are accepted by the API server:
   ```bash
   kubectl apply --dry-run=server \
     -f k8s/network-policy/server-egress.yml \
     -f k8s/server/secret.yml
   ```

2. **Allowlisted SMTP egress ALLOWED** — after replacing the placeholder relay
   CIDR (`192.0.2.0/24`, RFC 5737 TEST-NET-1) with the real SMTP relay's CIDR,
   confirm SMTP egress (port 587, or 25/465 as applicable) to the relay is
   permitted and verification/GDPR-export mail actually sends from a pod with
   `component: server`.

3. **Non-allowlisted egress DENIED** — confirm that under default-deny:
   - SMTP egress to any address *outside* the configured relay CIDR is denied.
   - `443` egress to an address inside the pod/service CIDR ranges (i.e. an
     in-cluster address that should be excluded from the wide 443 rule) is
     denied — this proves the CIDR exclusions actually take effect and lateral
     movement via the wide 443 allowance is blocked.

4. **All four new Secret keys resolve** — confirm the server pod starts
   without CrashLoop / missing-key errors once real values are populated for:
   - `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY`
   - `AXIAM__EMAIL_ENCRYPTION_KEY`
   - `AXIAM__GDPR_PSEUDONYM_PEPPER`
   - `AXIAM__AUTH__PEPPER`

5. **CI env prefix matches the loader** — confirm the CI `test` job env keys
   are `AXIAM__DB__URL` / `AXIAM__DB__USERNAME` / `AXIAM__DB__PASSWORD` /
   `AXIAM__AMQP__URL` (double-underscore, correct section names) — this is
   static and can be re-checked with:
   ```bash
   grep -E 'AXIAM__DB__URL|AXIAM__AMQP__URL' .github/workflows/ci.yml
   ```

## Placeholder values the operator MUST replace

| Placeholder | Location | Current value | Must become |
|---|---|---|---|
| SMTP relay CIDR | `k8s/network-policy/server-egress.yml` SMTP egress rule | `192.0.2.0/24` (RFC 5737 TEST-NET-1, fail-closed — resolves to no real host) | The real SMTP relay's CIDR (single IP as `/32` or the provider's documented range) |
| Cluster pod CIDR | `k8s/network-policy/server-egress.yml` wide-443 rule `except:` block | `10.244.0.0/16` (flannel/calico default) | The actual pod CIDR for the target cluster |
| Cluster service CIDR | `k8s/network-policy/server-egress.yml` wide-443 rule `except:` block | `10.96.0.0/12` (kubeadm default) | The actual service CIDR for the target cluster |

These are documented inline as comments in `server-egress.yml`; a kustomize
overlay or Helm value substitution is the recommended mechanism so the base
manifest stays fail-closed / example-safe while per-cluster overrides live in
the deploy overlay.

## Resolution

Close this followup once an operator has run through the 5 steps above
against a real or `kind` cluster and confirmed all pass. Record the outcome
(pass/fail + any manifest fixes needed) in this file or a linked
verification log before flipping `status` to `resolved`.
