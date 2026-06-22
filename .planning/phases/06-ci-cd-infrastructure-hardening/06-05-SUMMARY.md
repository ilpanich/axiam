---
phase: 06-ci-cd-infrastructure-hardening
plan: "05"
subsystem: k8s-security
tags: [network-policy, pod-security, psa, securitycontext, secret-hygiene]
dependency_graph:
  requires: []
  provides: [k8s-network-policy, psa-labels, restricted-securitycontext]
  affects: [k8s/namespace.yml, k8s/server/deployment.yml, k8s/frontend/deployment.yml, k8s/surrealdb/statefulset.yml, k8s/rabbitmq/statefulset.yml]
tech_stack:
  added: [Kubernetes NetworkPolicy, Pod Security Admission]
  patterns: [default-deny-egress, ipBlock-except-RFC1918, restricted-securityContext, PSA-warn-audit]
key_files:
  created:
    - k8s/network-policy/default-deny.yml
    - k8s/network-policy/allow-dns-egress.yml
    - k8s/network-policy/server-egress.yml
    - k8s/network-policy/allow-ingress-to-server.yml
    - k8s/network-policy/allow-ingress-to-frontend.yml
  modified:
    - k8s/kustomization.yml
    - k8s/namespace.yml
    - k8s/server/deployment.yml
    - k8s/frontend/deployment.yml
    - k8s/surrealdb/statefulset.yml
    - k8s/rabbitmq/statefulset.yml
decisions:
  - "D-11: default-deny ingress+egress with explicit allows for server→surrealdb/rabbitmq and ingress→server/frontend; DNS carve-out to kube-system UDP/TCP 53 mandatory"
  - "D-12: TCP/443 external egress via ipBlock 0.0.0.0/0 except RFC1918+CGN; cluster pod/service CIDRs are documented placeholders for operator to fill"
  - "D-13: PSA warn+audit=restricted at namespace v1.29; server+frontend compliant-by-construction; datastores best-effort; enforce deferred"
  - "D-14: no inline value: secret literals confirmed; all secrets use secretRef/secretKeyRef"
  - "frontend readOnlyRootFilesystem enabled with emptyDir volumes for /tmp, /var/cache/nginx, /var/run (nginx-unprivileged compatibility)"
  - "RabbitMQ best-effort UID 999 (official image rabbitmq user); initContainer chown documented as fallback if volume permission errors occur"
metrics:
  duration: "15m"
  completed_date: "2026-06-04"
  tasks_completed: 2
  files_count: 11
---

# Phase 6 Plan 05: K8s NetworkPolicy + Pod Security Standards Summary

**One-liner:** Default-deny NetworkPolicy with DNS+datastore+external-HTTPS egress carve-outs, restricted-profile securityContexts on all workloads, and PSA warn+audit=restricted namespace labels.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | NetworkPolicy manifests + kustomization | 784f6bd | k8s/network-policy/*.yml, k8s/kustomization.yml |
| 2 | Restricted securityContexts + PSA labels + secret hygiene | 7710f77 | k8s/namespace.yml, k8s/server/deployment.yml, k8s/frontend/deployment.yml, k8s/surrealdb/statefulset.yml, k8s/rabbitmq/statefulset.yml |

## What Was Built

### Task 1: NetworkPolicy Manifests

Five manifests in `k8s/network-policy/`:

1. **`default-deny.yml`** — podSelector `{}` policyTypes Ingress+Egress, no rules. Denies all pod-to-pod and pod-to-external traffic by default (D-11).

2. **`allow-dns-egress.yml`** — podSelector `{}` egress UDP+TCP 53 to `kube-system` namespace via `kubernetes.io/metadata.name: kube-system` selector. Mandatory DNS carve-out — without this, service-name resolution breaks (D-11 Pitfall 3).

3. **`server-egress.yml`** — server pod egress to:
   - `component: surrealdb` port 8000 (D-11)
   - `component: rabbitmq` port 5672 (D-11)
   - TCP/443 to `ipBlock cidr: 0.0.0.0/0 except: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10]` for external HTTPS (OIDC JWKS, SAML IdP, email APIs) with operator placeholders for cluster pod/service CIDRs (D-12)

4. **`allow-ingress-to-server.yml`** — `ingress-nginx` namespace → server:8090 (D-11, operator must adjust namespace label)

5. **`allow-ingress-to-frontend.yml`** — `ingress-nginx` namespace → frontend:8080 (D-11, operator must adjust namespace label)

All five wired into `k8s/kustomization.yml` resource list.

### Task 2: Restricted securityContexts + PSA Labels + Secret Hygiene

**Server deployment:**
- `runAsUser: 1000` → `runAsUser: 65532` (distroless nonroot UID, D-08/D-13)
- Added `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile.type: RuntimeDefault`

**Frontend deployment:**
- Added `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile.type: RuntimeDefault`
- Added `emptyDir` volumes for `/tmp`, `/var/cache/nginx`, `/var/run` (nginx-unprivileged requires these writable)

**SurrealDB StatefulSet (best-effort):**
- Added `runAsNonRoot: true`, `runAsUser: 65532`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile.type: RuntimeDefault`

**RabbitMQ StatefulSet (best-effort):**
- Added `runAsNonRoot: true`, `runAsUser: 999` (rabbitmq user in official image), `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile.type: RuntimeDefault`

**Namespace PSA labels:**
- `pod-security.kubernetes.io/warn: restricted`
- `pod-security.kubernetes.io/warn-version: v1.29`
- `pod-security.kubernetes.io/audit: restricted`
- `pod-security.kubernetes.io/audit-version: v1.29`

**D-14 secret hygiene:** `grep -rn 'value:' k8s/ | grep -iE 'password|secret|key|token'` returns empty. All secrets use `secretKeyRef` (surrealdb, rabbitmq) or `envFrom.secretRef` (server).

## Deviations from Plan

### Auto-added: emptyDir volumes for frontend nginx

**Found during:** Task 2

**Issue:** Plan noted "if readOnlyRootFilesystem breaks nginx, add emptyDir mounts" — nginx-unprivileged requires `/tmp`, `/var/cache/nginx`, `/var/run` to be writable at runtime.

**Fix:** Added `volumeMounts` + `volumes` entries for all three paths as `emptyDir: {}`. This is the standard pattern for nginx-unprivileged with readOnlyRootFilesystem (nginx writes pid file, cache, and temp files to these directories).

**Files modified:** `k8s/frontend/deployment.yml`

**Rule:** Rule 2 (missing critical functionality for correct operation)

## Operator TODO Items

The following items require operator-specific values before deploying:

1. **`k8s/network-policy/server-egress.yml`** — cluster pod CIDR and service CIDR must be added to the `except` list (e.g. `10.244.0.0/16` for flannel, `10.96.0.0/12` for kubeadm default service CIDR).

2. **`k8s/network-policy/allow-ingress-to-server.yml`** and **`allow-ingress-to-frontend.yml`** — `kubernetes.io/metadata.name: ingress-nginx` must match the actual ingress controller namespace label in the target cluster.

3. **RabbitMQ UID** — if the RabbitMQ image uses a different UID than 999 (e.g. on ARM builds), `runAsUser` must be updated; add `initContainer` chown if volume permission errors occur.

## Known Stubs

None — all manifests are functional configurations, not placeholders.

## Threat Flags

None — all new surfaces (NetworkPolicy, PSA labels, securityContext fields) are defensive controls, not new attack surface.

## Human Checkpoint Required

A `checkpoint:human-verify` task follows. Verification requires:
1. `kubectl apply --dry-run=client -k k8s/` — validates all manifests parse and kustomization resolves
2. kind/minikube with Calico CNI: test allowed flows (server→surrealdb:8000, DNS) and denied flows (server→arbitrary pod)
3. External 443 egress test (after filling cluster-CIDR placeholders)
4. PSA warn quiet for server/frontend under `axiam` namespace

## Self-Check: PASSED

Files verified to exist:
- k8s/network-policy/default-deny.yml: FOUND
- k8s/network-policy/allow-dns-egress.yml: FOUND
- k8s/network-policy/server-egress.yml: FOUND
- k8s/network-policy/allow-ingress-to-server.yml: FOUND
- k8s/network-policy/allow-ingress-to-frontend.yml: FOUND
- k8s/namespace.yml: FOUND (PSA labels present)
- k8s/server/deployment.yml: FOUND (restricted securityContext present)
- k8s/frontend/deployment.yml: FOUND (restricted securityContext + emptyDir)
- k8s/surrealdb/statefulset.yml: FOUND (best-effort securityContext)
- k8s/rabbitmq/statefulset.yml: FOUND (best-effort securityContext)

Commits verified:
- 784f6bd: feat(06-05): NetworkPolicy manifests — FOUND
- 7710f77: feat(06-05): extend securityContexts — FOUND
