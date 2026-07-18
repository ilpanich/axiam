# AXIAM Benchmark Framework

A vendor-neutral, protocol-driven benchmark harness for comparing **AXIAM** against
other open-source IAM systems (Keycloak, Zitadel, Authentik, Ory, …) across three
dimensions:

1. **Performance** — throughput (req/s) and latency (p50/p95/p99) under load.
2. **Resource efficiency** — CPU and memory consumed to deliver that performance,
   so we can answer *"can AXIAM match the competition with a smaller footprint?"*
3. **Security posture** — the same workload is replayed across a matrix of
   **security profiles** (from plaintext HTTP up to mTLS with client-certificate
   authentication and TLS 1.3-only), measuring the cost of stronger security.

It also includes **per-SDK client-side benchmarks**, so the client overhead of each
official AXIAM SDK (Rust, TypeScript, Python, Java, C#, PHP, Go — each published from
its own `ilpanich/axiam-<lang>-sdk` repository) can be measured against the raw
protocol baseline. All 7 SDKs are implemented and **all 7 bench harnesses are wired
to their SDKs** (see `sdk/README.md`); each builds against the sibling SDK checkout
via a local path/replace/project reference until the alpha package lands on the
public registry.

## Why a custom framework?

There is **no vendor-neutral standard benchmark** for IAM systems. The de-facto
reference is [`keycloak-benchmark`](https://github.com/keycloak/keycloak-benchmark)
(Gatling-based), but it is Keycloak-specific in its provisioning, dataset add-on,
and endpoint assumptions.

AXIAM and every serious competitor speak the **same wire standards** — OAuth2
(RFC 6749), OIDC, token introspection (RFC 7662), JWKS (RFC 7517). So instead of
re-implementing a vendor-coupled tool, this framework drives those *standard flows*
through a thin per-target **adapter layer** (`scenarios/lib/targets.js`). Every
target is hit with the identical logical workload; only the endpoint paths and
request encodings differ. That keeps the comparison apples-to-apples.

The load generator is [**k6**](https://k6.io): a single static binary, scriptable
in JavaScript, with native HTTP + gRPC support, built-in latency/throughput
metrics, threshold gating, and machine-readable JSON output. It is deliberately
lighter than a JVM-based generator (Gatling) so the load tool does not starve the
system-under-test of the CPU we are trying to measure.

## Directory layout

```
benchmarks/
├── README.md                 # this file
├── justfile                  # convenience commands (bench-up, bench-run, bench-report…)
├── docs/
│   ├── methodology.md        # how a fair run is defined; metric definitions
│   ├── security-profiles.md  # the TLS/cert profile matrix
│   └── interpreting-results.md
├── targets/                  # each system-under-test as a resource-capped compose file
│   ├── axiam/docker-compose.yml
│   ├── keycloak/docker-compose.yml
│   └── zitadel/docker-compose.yml
├── profiles/                 # security profiles (env files + registry)
│   ├── profiles.yaml
│   ├── p0-plaintext.env
│   ├── p1-tls12.env
│   ├── p2-tls13.env
│   └── p3-mtls.env
├── scenarios/                # k6 load scenarios (vendor-neutral)
│   ├── lib/{config,targets,metrics,auth}.js
│   ├── oauth2_password_login.js
│   ├── oauth2_client_credentials.js
│   ├── token_introspection.js
│   ├── token_refresh.js
│   ├── jwks_fetch.js
│   ├── userinfo.js
│   ├── authz_check_rest.js     # AXIAM-only; SDK check_access wire baseline
│   ├── authz_batch_rest.js     # AXIAM-only; SDK batch_check wire baseline
│   ├── authz_check_grpc.js
│   └── authz_batch_grpc.js
├── resource/                 # resource-consumption sampling
│   ├── sampler.sh            # docker stats → CSV
│   └── cadvisor-compose.yml  # optional richer telemetry
├── runner/
│   ├── run-benchmark.sh      # orchestrator: target × profile × scenario matrix
│   ├── seed.sh               # provision org/tenant/user/client per target
│   └── report.py             # aggregate raw results → comparative report
├── sdk/                      # per-language SDK client-side benchmarks (scaffolds)
│   ├── HARNESS-SPEC.md       # the JSON contract every SDK bench must emit
│   ├── run-all.sh
│   └── {rust,typescript,python,go,java,csharp,php}/
└── results/                  # run outputs (gitignored)
```

## Quick start

```bash
# 0. Prerequisites: docker, docker compose, k6, python3, jq, openssl, bash.
cd benchmarks

# The AXIAM target needs a JWT keypair + DB/RabbitMQ creds. `bench-up` bootstraps
# throwaway local-only ones under docker/.secrets/ automatically (or reuses
# docker/.secrets/env if you provide real ones). By default it pulls the prebuilt
# server image ghcr.io/ilpanich/axiam/server:<version>; GHCR packages are private
# by default, so run `docker login ghcr.io` first (PAT with read:packages), set
# BENCH_AXIAM_IMAGE to an image you can pull, or build from source with build=1.

# NOTE: `just` variable overrides (target=…, profile=…) must come BEFORE the
# recipe name — placed after, `just` reads them as another recipe and errors
# with "justfile does not contain recipe `target=…`".

# 1. Bring up a target under a chosen security profile and seed it.
#    AXIAM uses the published ghcr image by default (no source build); pin a
#    different tag with BENCH_AXIAM_IMAGE, or force a local build with build=1.
just target=axiam profile=p2-tls13 bench-up            # prebuilt image
# just target=axiam profile=p2-tls13 build=1 bench-up  # local source build
just target=axiam bench-seed

# 2. Run the full scenario suite (load + resource sampling) for that target/profile.
just target=axiam profile=p2-tls13 bench-run

# 3. Repeat for a competitor.
just target=keycloak profile=p2-tls13 bench-up
just target=keycloak bench-seed
just target=keycloak profile=p2-tls13 bench-run

# 4. Generate a comparative report across everything in results/.
just bench-report

# 5. Tear down.
just target=axiam bench-down
just target=keycloak bench-down
```

Or run the entire matrix (all targets × all profiles × all scenarios) unattended:

```bash
just targets="axiam keycloak" profiles="p0-plaintext p2-tls13 p3-mtls" bench-matrix
```

See [`docs/methodology.md`](docs/methodology.md) for the rules that make a run
comparable, and [`docs/security-profiles.md`](docs/security-profiles.md) for the
profile definitions.

## Status of components

| Component                         | State                                                        |
|-----------------------------------|--------------------------------------------------------------|
| k6 protocol scenarios             | Implemented (HTTP); authz check + batch scenarios over both REST and gRPC |
| AXIAM target + seeding            | Implemented (prebuilt ghcr image by default, local build fallback); seeds org/tenant/admin via the gated bootstrap flow plus a resource/role/grant for authz checks |
| Keycloak / Zitadel targets        | Implemented (Keycloak 26.7.0, Zitadel v4.15.2)               |
| Security profile matrix           | Implemented (p0–p3); mTLS requires per-target cert wiring; SDK benches cover p0–p2 (no SDK client-cert option yet) |
| Resource sampler + report         | Implemented (stdlib python, no external deps)                 |
| SDK client benchmarks             | All 7 wired to their SDKs (see `sdk/README.md`)              |
| AMQP async-authz benchmarking     | Out of scope for v1.0-beta (see below)                        |

> Every SDK bench builds against its sibling `ilpanich/axiam-<lang>-sdk` checkout
> via a local path/replace/project reference until the alpha package is published —
> see each language's `sdk/<lang>/TODO.md`. `sdk/HARNESS-SPEC.md` documents the
> shared result contract every bench emits.

## Out of scope (v1.0-beta)

**AMQP async-authz benchmarking** (server `axiam-amqp` + the Go/Python/TypeScript
SDKs' AMQP modules) is deliberately deferred. k6 has no AMQP executor/protocol
plugin, so measuring the async-authz-over-AMQP flow needs a custom load harness
(publish decision requests, consume results, measure end-to-end latency and
consumer throughput) rather than a k6 scenario. This is planned as a follow-up,
not part of the current `scenarios/`/`sdk/` frameworks.
