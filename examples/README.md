# AXIAM examples

Runnable, end-to-end examples of AXIAM's protocol surface — REST, OAuth2/OIDC
grants, and gRPC. Each subdirectory is self-contained: its own README stating
exactly what it demonstrates and what it requires, and its own runnable code
in whichever language best fits what it's showing (see each README's
rationale). None of them depend on each other.

This tree did not exist before task R5.1 of
`claude_dev/remediation-plan-2026-08-15.md` — it closes the "F3 examples
tree" gap that plan records (`claude_dev/improvement-after-run5-benchmark.md`
called for these four specifically: B1, B2, B3, B5).

| Directory | Demonstrates | Language | Referenced from |
|---|---|---|---|
| [`b1-deny-override/`](b1-deny-override/README.md) | RBAC deny-override: "grant admin on `/fleet`, deny on `/fleet/decommissioned`" — the canonical scenario from `claude_dev/deny-override-design.md` §2.2 | Bash + curl (protocol-level, language-neutral) | The five flagship SDK repos (rust, typescript, python, go, java) link here for the wire-level walkthrough behind their own language-idiomatic examples |
| [`b2-iot-device-quickstart/`](b2-iot-device-quickstart/README.md) | OAuth2 Device Authorization Grant (RFC 8628) on a headless device, both sides of the ceremony | Bash + curl | `docs/api/device-flow.md` |
| [`b3-mesh-delegation-grpc/`](b3-mesh-delegation-grpc/README.md) | OAuth2 Token Exchange (RFC 8693) delegation, end to end onto the gRPC `AuthorizationService` — the service-mesh scenario | Rust (own Cargo workspace) | `docs/api/token-exchange.md` |
| [`b5-rp-logout-app/`](b5-rp-logout-app/README.md) | A relying-party app: OIDC login (authorization_code + PKCE, pushed through PAR), RP-Initiated Logout, Back-Channel Logout | TypeScript / Express | New — no RP example app existed anywhere in the repo before this |

## Running any of these

Every example needs a running, bootstrapped AXIAM instance:

```bash
docker compose -f docker/docker-compose.e2e.yml up -d --wait
./scripts/e2e-bootstrap.sh
```

`b3-mesh-delegation-grpc` additionally needs the gRPC port published and
bound off loopback — see its own README and
[`docker-compose.grpc-port.override.yml`](b3-mesh-delegation-grpc/docker-compose.grpc-port.override.yml)
for the one-line, smoke-testing-only compose override that does it.

Each example's own README has the exact commands from there.

## CI

[`.github/workflows/examples-smoke.yml`](../.github/workflows/examples-smoke.yml)
runs four fast static-verification jobs on every PR touching this tree
(shellcheck on the three bash scripts — `b1`, `b2`, and `b5`'s
`smoke-test.sh` — `cargo build`/`fmt`/`clippy` on the Rust one,
`tsc`/`npm run build` on the TypeScript one, YAML validation on the workflow
and compose-override files themselves), then a docker-backed `runtime-smoke`
job, gated on all four, that brings up the e2e stack and actually runs every
example against it — see that file for the exact job and step names.

## Verification status of this tree

Authored and verified in an environment **with no docker daemon** — every
example is compile-checked, typechecked, or shellchecked (see each README's
own "Verification status" section for exactly how), and none of them has
been observed to run end to end against a live AXIAM instance by the agent
that wrote them. Every assertion — `b1-deny-override`'s three deny-override
checks, `b2-iot-device-quickstart`'s polling state table,
`b3-mesh-delegation-grpc`'s gRPC response fields, `b5-rp-logout-app`'s login/
logout/back-channel chain — is written against the real response shapes
documented in `docs/api/` and `sdks/CONTRACT.md`, cross-checked against the
handler/engine source, not guessed. The docker-backed `runtime-smoke` job in
`examples-smoke.yml` is what closes that last gap once it runs in an
environment that has a docker daemon (CI does).

Two implementation gaps were found and fixed while building these examples
(see git history around this change): the REST client-registration
endpoint's `KNOWN_GRANT_TYPES` allow-list did not include the device-flow or
token-exchange grant URNs, which would have silently blocked `b2` and `b3`
from ever registering a working client through the public API — not just
in this tree.
