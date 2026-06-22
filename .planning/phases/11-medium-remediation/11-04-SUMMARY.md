---
phase: 11-medium-remediation
plan: "04"
subsystem: infra
tags: [k8s, docker, nginx, security, config-rs, SEC-016, SEC-023, SEC-052, SEC-053]
dependency_graph:
  requires: []
  provides: [REQ-15-AC-4]
  affects: [k8s/server/configmap.yml, k8s/server/secret.yml, k8s/namespace.yml, k8s/network-policy, k8s/ingress.yml, docker/nginx.conf, docker/docker-compose.prod.yml]
tech_stack:
  added: []
  patterns: [AXIAM__ double-underscore env key, PSA restricted enforce, receiver-side NetworkPolicy, nginx proxy_pass with security headers, Docker Compose fail-fast ${VAR:?msg}]
key_files:
  created:
    - k8s/network-policy/allow-ingress-to-surrealdb.yml
    - k8s/network-policy/allow-ingress-to-rabbitmq.yml
  modified:
    - k8s/server/configmap.yml
    - k8s/server/secret.yml
    - k8s/namespace.yml
    - k8s/ingress.yml
    - docker/nginx.conf
    - docker/docker-compose.prod.yml
decisions:
  - "AMQP URL creds (axiam:axiam embedded in docker-compose.prod.yml line 35) also replaced with fail-fast refs — plan only mentioned RabbitMQ env vars but the URL is the same surface (SEC-023 correctness)"
  - "nginx proxy location blocks repeat security headers explicitly to prevent silent regression on future header additions"
metrics:
  duration: 25m
  completed: "2026-06-13"
  tasks: 3
  files: 7
---

# Phase 11 Plan 04: k8s/Docker/nginx Infrastructure Hardening Summary

**One-liner:** AXIAM__ double-underscore ConfigMap/Secret keys, PSA restricted enforcement, receiver-side NetworkPolicies for SurrealDB/RabbitMQ, nginx+ingress /oauth2+/.well-known proxies, and fail-fast prod compose creds.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | AXIAM__ ConfigMap/Secret keys + RUST_LOG + key secrets (SEC-052) | 6a9f3c6 | k8s/server/configmap.yml, k8s/server/secret.yml |
| 2 | PSA enforce + receiver-side NetworkPolicies (SEC-053) | c4bad84 | k8s/namespace.yml, k8s/network-policy/allow-ingress-to-surrealdb.yml, k8s/network-policy/allow-ingress-to-rabbitmq.yml |
| 3 | nginx + ingress /oauth2 + /.well-known proxy; prod compose creds (SEC-016/023) | 71fc19d | docker/nginx.conf, k8s/ingress.yml, docker/docker-compose.prod.yml |

## Verification Results

All grep-assertion acceptance criteria passed:

- `grep -v '^[[:space:]]*#' k8s/server/configmap.yml | grep -c 'AXIAM__'` → 6 (all config keys)
- No `AXIAM_[A-Z]` single-underscore keys remain
- `RUST_LOG: "info"` (no `axiam=debug`)
- `AXIAM__DB__URL: "surrealdb:8000"` (bare host:port — no websocket scheme prefix, per SurrealDB v3 WsClient)
- JWT + encryption key secrets present in secret.yml
- `grep -c 'pod-security.kubernetes.io/enforce: restricted' k8s/namespace.yml` → 1
- `allow-ingress-to-surrealdb.yml` contains `component: surrealdb` + ingress from `component: server` on TCP 8000
- `allow-ingress-to-rabbitmq.yml` contains `component: rabbitmq` + ingress from `component: server` on TCP 5672
- `grep -c 'location /oauth2' docker/nginx.conf` → 1
- `grep -c 'location /.well-known' docker/nginx.conf` → 1
- No literal `root`/`axiam` default creds in docker-compose.prod.yml

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical Fix] AMQP URL embedded creds also replaced (SEC-023)**
- **Found during:** Task 3
- **Issue:** `AXIAM__AMQP__URL` had literal `axiam:axiam` credentials embedded in the AMQP connection string — same SEC-023 surface as the explicit env vars the plan mentioned
- **Fix:** Changed to use `${RABBITMQ_DEFAULT_USER:?...}:${RABBITMQ_DEFAULT_PASS:?...}` interpolation in the connection string — same fail-fast pattern, consistent with the RABBITMQ_DEFAULT_USER/PASS env vars now required
- **Files modified:** docker/docker-compose.prod.yml
- **Commit:** 71fc19d

## Known Stubs

None. All infra-only changes; no data source wiring or UI stubs involved.

## Threat Flags

None beyond what the plan's threat model already covers. All new surfaces (NetworkPolicy files, nginx location blocks, ingress paths) are mitigations, not new attack surfaces.

## Self-Check: PASSED

- k8s/server/configmap.yml: exists, 6 AXIAM__ keys, no single-underscore
- k8s/server/secret.yml: exists, AXIAM__ keys, JWT + MFA/PKI encryption secrets present
- k8s/namespace.yml: PSA enforce: restricted label present
- k8s/network-policy/allow-ingress-to-surrealdb.yml: exists, component: surrealdb, port 8000
- k8s/network-policy/allow-ingress-to-rabbitmq.yml: exists, component: rabbitmq, port 5672
- docker/nginx.conf: location /oauth2 + /.well-known present with security headers
- k8s/ingress.yml: /oauth2 + /.well-known paths present
- docker/docker-compose.prod.yml: no literal root/axiam creds, all fail-fast references
- Commits: 6a9f3c6 (task 1), c4bad84 (task 2), 71fc19d (task 3) — all present
