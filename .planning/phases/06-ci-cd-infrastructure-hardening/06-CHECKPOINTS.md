# Phase 6 — Outstanding Human-Verify Checkpoints

**Status:** Phase EXECUTED (all 5 plans coded + committed on `feature/full-review`), NOT yet Complete.
**Created:** 2026-06-07
**Why these are pending:** each proves a behavioral success criterion that requires live infrastructure (GitHub Actions, a built Docker image, a kind/Calico cluster) — none can be asserted from local static checks. Code is in place; only the live proof remains.

When all four pass → run `/gsd:verify-work 6` (or `/gsd:ship`) to close the phase.
If any fails → report the failure; the owning plan's code gets fixed and re-verified.

---

## ☐ CP-1 — CI vuln gate fires (Plan 06-01 · ROADMAP success criterion #1)

**Claim:** "A PR with a known vulnerable dependency fails CI."

1. Red path: on a throwaway branch, add a known-vulnerable dep (e.g. `time = "0.1"` → RUSTSEC-2020-0071) to any crate's `[dev-dependencies]`, push, open a PR → confirm the `security-scan` job goes **RED** (cargo-audit or cargo-deny fails). Delete the branch after.
2. Green path: confirm the clean `feature/full-review` PR shows `security-scan` **GREEN**.
3. SARIF: confirm results appear under **Security → Code scanning** for categories `hadolint-server`, `hadolint-frontend`, `trivy-fs`, `trivy-config`.

---

## ☐ CP-2 — Distroless server image (Plan 06-03 · ROADMAP success criterion #2)

**Claim:** "Docker images run as non-root with a minimal base image" + SAML-on still works (xmlsec `.so` present).

```
docker build -f docker/Dockerfile.server -t axiam-server:p6 .
```
1. Confirm the builder `RUN ldd` step prints xmlsec-related `.so` entries; build completes.
2. Run against a dev DB + broker → confirm NO `error while loading shared libraries` in `docker logs`; `/health` returns 200.
3. `docker run --rm axiam-server:p6 healthcheck` → exit 0 against a running instance, exit 1 when /health is down.
4. `docker inspect axiam-server:p6 --format='{{.Config.User}}'` → `nonroot` (UID 65532).

*If a library is missing: report the `.so` name → add it to the COPY block in `docker/Dockerfile.server`.*

---

## ☐ CP-3 — K8s NetworkPolicy enforcement (Plan 06-05 · ROADMAP success criterion #3)

**Claim:** "K8s NetworkPolicy restricts pod-to-pod traffic to only required paths."

**Operator prep first:** fill the two cluster pod/service CIDR `TODO`s in `k8s/network-policy/server-egress.yml` (`ipBlock.except`); confirm `ingress-nginx` matches your ingress controller namespace in `allow-ingress-to-server.yml` + `allow-ingress-to-frontend.yml`.

1. Syntax: `kubectl apply --dry-run=client -k k8s/` → all resources parse, no errors.
2. kind + Calico: apply manifests; from a test pod confirm `curl surrealdb:8000` + DNS resolve (allowed) and `curl rabbitmq-management:15672` times out (denied); from server pod confirm `curl https://example.com` works (allowed 443) and `curl http://172.16.0.1` times out (denied RFC1918).
3. PSA: under the `axiam` namespace, server + frontend pods emit no PSA warnings (datastores may warn — expected, best-effort).
4. Secret hygiene re-confirm: `grep -rn 'value:' k8s/ --include='*.yml' | grep -iE 'password|secret|key|token'` → empty.

---

## ☐ CP-4 — Release image scan gate (Plan 06-02 · ROADMAP success criterion #4)

**Claim:** "Container image scan runs on every Docker build" (release-time `trivy image` blocks before publish/sign).

1. Push a test tag (`git tag v0.0.1-test && git push origin v0.0.1-test`) or trigger via `workflow_dispatch` → confirm Actions runs **Build (load) → Trivy image scan → Upload SARIF → Build and push → cosign sign → attest provenance** in that order.
2. SARIF appears under Security → Code scanning, categories `trivy-image-server` / `trivy-image-frontend`.
3. cosign signs the digest from the push step (matches the "Build and push" output digest).
4. (Optional negative proof) temporarily set `severity: LOW,MEDIUM,HIGH,CRITICAL` to force a finding → confirm the job blocks BEFORE the push step.

---

## ✅ Already verified locally (no checkpoint needed)

- **Criterion #5 (OpenAPI parity, Plan 06-04):** `cargo test -p axiam-api-rest route_openapi_parity` passes under default features AND `--no-default-features`.
- License Apache-2.0 in all 4 locations; deny.toml; dependabot 3 ecosystems; 5 netpol manifests; secret hygiene clean; ci.yml `security-scan` job + intact `build-no-saml` guard; SRI hashes + no sourcemaps; healthcheck subcommand; distroless base.

---

## Notes / known non-issues

- `bindings.rs` / `xmldsig.rs` (`_xmlSecDSigCtx`) rust-analyzer errors are the pre-existing **xmlsec SAML-on-Arch local-build** limitation — verified via the real SAML build in CI/Docker (CP-2 exercises this). Not a Phase 6 regression.
- Baseline: 3 pre-existing SAML `federation_test` failures (saml_acs / saml_authn / saml_metadata) under `--no-default-features`. A 4th+ failure would be a real regression.
