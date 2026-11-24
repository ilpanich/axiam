# AXIAM Benchmark Analysis — Seventh Draft (Runs 6, 6b and 6c: the cloud-VM runs)

> **Status: seventh benchmark draft — the first on server-class hardware,
> the first with four targets, and the first that sizes a datastore
> regression with a controlled experiment.** Three runs on one qualified
> 16-vCPU AMD EPYC Genoa cloud VM:
>
> - **Run 6** (2026-11-20/21) — the run of record: AXIAM **1.3.0**, the
>   published image by digest, on SurrealDB **4.0.1**, against Keycloak
>   26.8.1, Zitadel v4.19.5 and — new — authentik 2026.8.5; three profiles
>   (plaintext, TLS 1.3, native mTLS), median-of-3, 2-CPU caps; plus
>   resting footprints and the 11-SDK pass.
> - **Run 6b** (2026-11-21/22) — the same plaintext comparison with every
>   server and every database at **4 CPUs** instead of 2, and a 2-CPU
>   control pass of AXIAM **1.3.1**.
> - **Run 6c** (2026-11-23/24) — the same AXIAM 1.3.1 image against a
>   SurrealDB **3.3.5** server (unsupported, benchmark-only) at both cap
>   levels, to measure what the 4.0.1 server costs AXIAM.
>
> The story of this draft is not flattering, and it is told first: AXIAM
> is **database-bound on every cell that touches data**, its lead narrowed,
> and **Keycloak now wins two head-to-head cells** (introspection and REST
> userinfo). Run 6b shows the 2-CPU caps, not the products, set run 6's
> numbers — doubling them doubles AXIAM and Keycloak alike and changes no
> winner. Run 6c measures the SurrealDB 4.0.1 server as costing AXIAM
> **13–38% of its throughput at 2 CPUs and 8–37% at 4** — a real part of
> the drop since run 5, not all of it. §5 answers the question that
> follows: what is left to optimise.

**Reading rule for this whole document.** Run 6 is not comparable with
run 5 (§2). Runs 6b and 6c are labelled sensitivity passes: they are never
medianed with run 6, and run 6c never enters a head-to-head table. Every
number names its run. The previous (sixth) draft, run 5 on the laptop, is
in this file's git history; the parts of it this draft carries forward are
labelled as such (§9, Appendix A).

## 0. Setup at a glance

| | |
|---|---|
| Host | Infomaniak Public Cloud, flavor `a16-ram64-disk80-perf1`: **AMD EPYC Genoa, 16 vCPUs, 64 GiB**, local disk, Ubuntu 24.04, kernel 6.8.0. One instance for all three runs (created 2026-11-20). |
| Qualification | sysbench 3 runs within **0.32%**; CPU steal **0.00%** under load; no period above 5% steal during any run (`vmstat` sampled throughout) |
| Load | k6 v2.3.0, 50 VUs closed-loop, 30 s warm-up + 120 s measure, median-of-3 repeats per cell |
| Caps — runs 6, 6b A, 6c A | every server 2 CPU / 2 048 MiB; every database 2 CPU / 1 024 MiB; RabbitMQ 1 CPU / 512 MiB; authentik's worker carries the server cap |
| Caps — runs 6b B, 6c B | every server **and** every database **4 CPU**; memory and RabbitMQ unchanged. Stack ceilings: Keycloak, Zitadel 8 CPU; AXIAM 9; authentik 12 |
| Targets | **AXIAM 1.3.0** (run 6) / **1.3.1** (runs 6b, 6c), `ghcr.io/ilpanich/axiam/server`, by digest; SurrealDB **4.0.1** (runs 6, 6b) / **3.3.5** (run 6c), by digest; RabbitMQ 4 over TLS · **Keycloak 26.8.1** · **Zitadel v4.19.5** · **authentik 2026.8.5** (server + worker, no Redis) — competitors on PostgreSQL 16, uniformly tuned, the same digests in every run |
| Profiles | run 6 and run 6c: p0-plaintext, p2-tls13, p3-mtls (in-process; authentik's p2 is its own TLS listener over HTTP/1.1 and it has no p3) · run 6b: p0 only |
| Validity | run 6 **66/84** · run 6b **11/11** (A) and **22/30** (B) · run 6c **33/33** + **33/33**. The invalid cells are the same in every run: all of authentik's, and Zitadel's login and fallback refresh (§6) |
| Provenance | every container's image and digest in every cell's `meta.json`; settle gate cleared first-probe on every cell. Harness-only local changes (SDK bench manifests, the AXIAM target compose file) recorded in `provenance/run-after.txt`; the C# SDK bench retargeted to .NET 10 for the SDK pass |

**SurrealDB, the two open upstream bugs.** Both are open with no fix
merged, both report 4.0.x as a regression from 3.3.x:

- [surrealdb/surrealdb#7667](https://github.com/surrealdb/surrealdb/issues/7667):
  every write statement costs ~350 µs of CPU in `exec::ir`, 10–17× more
  than 3.3.5; a later comment finds 4.0.1 unchanged. It is on AXIAM's
  request path.
- [surrealdb/surrealdb#7716](https://github.com/surrealdb/surrealdb/issues/7716):
  every `CREATE` that fires a `DEFINE EVENT` re-plans the whole event body.
  **AXIAM's shipped schema defines no events** (`git grep 'DEFINE EVENT'
  v1.3.1 -- crates/` finds two, both in test code), so #7716 does not
  affect these measurements. It is listed because it is a regression of
  the exact build pinned.

Run 6c (§4) measures the cost of the whole 4.0.1 server against 3.3.5 —
#7667 plus anything else that changed in 4.0.

## 1. Headline results (p0-plaintext, median-of-3)

Each table lists, per scenario, run 6 (2/2, all targets), run 6b's AXIAM
control at 2/2 (1.3.1 on 4.0.1), run 6c's AXIAM at 2/2 (1.3.1 on 3.3.5),
run 6b at 4/4 (all targets) and run 6c at 4/4. `stack cores` is the
whole-stack CPU actually used; `cpu·ms/req` is whole-stack CPU per request
(lower is better); `bottleneck` names the container at ≥ 95% of its cap.
Rows marked ✗ failed the validity gate and are shown so no target goes
silently missing; they are never part of a claim. TLS and mTLS results
are in §6, every profile and every row in §10.

**Which rows are the comparison.** Head-to-head claims use run 6 (2/2)
and run 6b B (4/4), all on SurrealDB 4.0.1 — the only server AXIAM 1.3
supports. The run-6c rows (marked 3.3.5) are a sensitivity pass that
sizes the SurrealDB 4.0.1 regression; they are, in our reading, the
figures that represent AXIAM's own performance, and the level we expect
back once SurrealDB fixes the 4.0 regressions — but a supported
deployment gets the 4.0.1 rows today.

### Machine-to-machine token issuance (`oauth2_client_credentials`)

| pass | caps | target | thr (req/s) | p50 (ms) | p95 (ms) | stack cores | cpu·ms/req | bottleneck | valid |
|---|---|---|---|---|---|---|---|---|---|
| run 6 | 2/2 | axiam | 1 610 | 14.9 | 69.1 | 2.96 | 1.836 | axiam-surrealdb | ✓ 3/3 |
| run 6 | 2/2 | keycloak | 411 | 99.5 | 201.0 | 2.14 | 5.214 | keycloak | ✓ 3/3 |
| run 6 | 2/2 | zitadel | 425 | 109.2 | 135.7 | 3.82 | 8.986 | zitadel | ✓ 3/3 |
| run 6 | 2/2 | authentik | 5 | 6340.2 | 27855.0 | 3.83 | 832.023 | none | ✗ 0/3 |
| run 6b A | 2/2 | axiam | 1 448 | 16.6 | 71.4 | 3.02 | 2.085 | axiam-surrealdb | ✓ 3/3 |
| run 6c A (3.3.5) | 2/2 | axiam | 1 970 | 12.0 | 65.7 | 3.22 | 1.635 | axiam-surrealdb | ✓ 3/3 |
| run 6b B | 4/4 | axiam | 3 234 | 13.7 | 19.9 | 6.13 | 1.894 | axiam-surrealdb | ✓ 3/3 |
| run 6b B | 4/4 | keycloak | 934 | 20.8 | 96.9 | 4.32 | 4.621 | keycloak | ✓ 3/3 |
| run 6b B | 4/4 | zitadel | 704 | 65.3 | 79.1 | 7.04 | 9.998 | none | ✓ 3/3 |
| run 6b B | 4/4 | authentik | 4 | 6766.9 | 32616.0 | 4.07 | 1025.501 | none | ✗ 0/3 |
| run 6c B (3.3.5) | 4/4 | axiam | 3 853 | 11.3 | 17.6 | 6.42 | 1.666 | axiam-surrealdb | ✓ 3/3 |

AXIAM issues **3.9× Keycloak's and 3.8× Zitadel's tokens/s at 2 CPUs,
3.5× and 4.6× at 4**, at a 15 ms p50 against 99–109 ms. Its lead was 7.9×
/ 6.5× in run 5; the AXIAM server used 0.70 of its 2 cores here while
SurrealDB sat at its cap, so this cell now measures the database tier.
Zitadel is the one competitor that reaches no cap at 4/4 (server 3.65,
PostgreSQL 3.38 of 4).

### Token introspection (RFC 7662)

| pass | caps | target | thr (req/s) | p50 (ms) | p95 (ms) | stack cores | cpu·ms/req | bottleneck | valid |
|---|---|---|---|---|---|---|---|---|---|
| run 6 | 2/2 | axiam | 1 582 | 15.2 | 69.4 | 2.94 | 1.859 | axiam-surrealdb | ✓ 3/3 |
| run 6 | 2/2 | keycloak | 1 940 | 5.4 | 85.1 | 2.51 | 1.296 | keycloak | ✓ 3/3 |
| run 6 | 2/2 | zitadel | 827 | 53.6 | 75.9 | 3.90 | 4.715 | zitadel,zitadel-postgres | ✓ 3/3 |
| run 6 | 2/2 | authentik | 19 | 2505.2 | 3483.4 | 2.73 | 146.066 | authentik-postgres | ✗ 0/3 |
| run 6b A | 2/2 | axiam | 1 438 | 16.8 | 71.9 | 2.95 | 2.050 | axiam-surrealdb | ✓ 3/3 |
| run 6c A (3.3.5) | 2/2 | axiam | 1 661 | 14.3 | 69.3 | 3.16 | 1.904 | axiam-surrealdb | ✓ 3/3 |
| run 6b B | 4/4 | axiam | 3 272 | 13.5 | 19.7 | 6.01 | 1.836 | axiam-surrealdb | ✓ 3/3 |
| run 6b B | 4/4 | keycloak | 3 952 | 4.9 | 57.5 | 5.07 | 1.283 | keycloak | ✓ 3/3 |
| run 6b B | 4/4 | zitadel | 1 522 | 30.4 | 39.8 | 7.33 | 4.819 | none | ✓ 3/3 |
| run 6b B | 4/4 | authentik | 36 | 1248.5 | 1754.8 | 5.37 | 148.453 | authentik-postgres | ✗ 1/3 |
| run 6c B (3.3.5) | 4/4 | axiam | 3 609 | 12.2 | 18.6 | 6.27 | 1.736 | axiam-surrealdb | ✓ 3/3 |

**Keycloak wins this cell** — 1,940 vs 1,582 req/s at 2/2, 3,952 vs 3,272
at 4/4 — with a lower p50 (5 vs 15 ms) and, at 2/2, a higher p95 (85 vs
69 ms). AXIAM led 2.4× in run 5. On 3.3.5 AXIAM gains among the least here
(+16% / +10%), so even the 3.3.5 figure stays behind Keycloak. Server-only, AXIAM spends 0.42 cpu·ms per introspection against
Keycloak's 1.04 (§7); the difference is database work per request (§5).

### JWKS fetch (RFC 7517)

| pass | caps | target | thr (req/s) | p50 (ms) | p95 (ms) | stack cores | cpu·ms/req | bottleneck | valid |
|---|---|---|---|---|---|---|---|---|---|
| run 6 | 2/2 | axiam | 43 640 | 0.8 | 1.8 | 2.15 | 0.049 | none | ✓ 3/3 |
| run 6 | 2/2 | keycloak | 5 529 | 1.9 | 73.5 | 2.02 | 0.366 | keycloak | ✓ 3/3 |
| run 6 | 2/2 | zitadel | 2 031 | 10.4 | 69.3 | 3.04 | 1.498 | zitadel-postgres | ✓ 3/3 |
| run 6 | 2/2 | authentik | 24 | 1905.3 | 2790.4 | 2.93 | 122.444 | authentik-postgres | ✗ 0/3 |
| run 6b A | 2/2 | axiam | 41 523 | 0.8 | 1.9 | 2.18 | 0.052 | none | ✓ 3/3 |
| run 6c A (3.3.5) | 2/2 | axiam | 40 430 | 0.8 | 2.0 | 1.83 | 0.045 | none | ✓ 3/3 |
| run 6b B | 4/4 | axiam | 43 232 | 0.8 | 1.9 | 2.37 | 0.055 | none | ✓ 3/3 |
| run 6b B | 4/4 | keycloak | 10 832 | 1.9 | 5.6 | 4.06 | 0.375 | keycloak | ✓ 3/3 |
| run 6b B | 4/4 | zitadel | 3 953 | 8.5 | 36.8 | 6.36 | 1.608 | zitadel-postgres | ✓ 3/3 |
| run 6b B | 4/4 | authentik | 45 | 1041.7 | 1528.7 | 4.75 | 105.503 | none | ✗ 1/3 |
| run 6c B (3.3.5) | 4/4 | axiam | 41 737 | 0.8 | 1.9 | 2.04 | 0.049 | none | ✓ 3/3 |

The one cell that never touches the database, and the cleanest read of
AXIAM's own request path: **43,640 req/s at a 1.8 ms p95 — 7.9× Keycloak
and 21× Zitadel** at 2/2. It is load-generator-bound: k6 used 7.5 cores
and the AXIAM server 1.3 of its 2, in every pass, so its 4/4 cell is
flagged `generator_saturated` and is not a capacity figure (Keycloak at
4/4: 10,832). The SurrealDB version makes no difference here (within 3%).

### OIDC userinfo — REST and gRPC

| pass | caps | target | thr (req/s) | p50 (ms) | p95 (ms) | stack cores | cpu·ms/req | bottleneck | valid |
|---|---|---|---|---|---|---|---|---|---|
| run 6 | 2/2 | axiam | 1 411 | 17.4 | 71.9 | 2.83 | 2.007 | axiam-surrealdb | ✓ 3/3 |
| run 6 | 2/2 | keycloak | 3 862 | 2.4 | 80.4 | 2.02 | 0.522 | keycloak | ✓ 3/3 |
| run 6 | 2/2 | zitadel | 859 | 51.9 | 85.9 | 2.94 | 3.421 | zitadel-postgres | ✓ 3/3 |
| run 6 | 2/2 | authentik | 20 | 2343.3 | 3022.4 | 3.08 | 154.855 | authentik-postgres | ✗ 0/3 |
| run 6b A | 2/2 | axiam | 1 320 | 18.7 | 73.8 | 2.87 | 2.172 | axiam-surrealdb | ✓ 3/3 |
| run 6c A (3.3.5) | 2/2 | axiam | 2 081 | 11.2 | 65.1 | 3.27 | 1.572 | axiam-surrealdb | ✓ 3/3 |
| run 6b B | 4/4 | axiam | 2 963 | 15.1 | 21.5 | 5.79 | 1.952 | axiam-surrealdb | ✓ 3/3 |
| run 6b B | 4/4 | keycloak | 7 807 | 2.3 | 51.2 | 4.05 | 0.518 | keycloak | ✓ 3/3 |
| run 6b B | 4/4 | zitadel | 1 677 | 19.4 | 54.4 | 6.25 | 3.727 | zitadel-postgres | ✓ 3/3 |
| run 6b B | 4/4 | authentik | 30 | 1706.0 | 2465.7 | 5.60 | 189.514 | none | ✗ 0/3 |
| run 6c B (3.3.5) | 4/4 | axiam | 4 372 | 10.0 | 15.5 | 6.60 | 1.510 | axiam-surrealdb | ✓ 2/3 |

| pass | caps | target | thr (req/s) | p50 (ms) | p95 (ms) | stack cores | cpu·ms/req | bottleneck | valid |
|---|---|---|---|---|---|---|---|---|---|
| run 6 | 2/2 | axiam | 3 078 | 7.0 | 59.0 | 3.11 | 1.010 | axiam-surrealdb | ✓ 3/3 |
| run 6b A | 2/2 | axiam | 2 795 | 8.0 | 61.0 | 3.08 | 1.104 | axiam-surrealdb | ✓ 3/3 |
| run 6c A (3.3.5) | 2/2 | axiam | 4 026 | 6.0 | 54.0 | 3.36 | 0.835 | axiam-surrealdb | ✓ 3/3 |
| run 6b B | 4/4 | axiam | 6 369 | 7.0 | 11.0 | 6.25 | 0.981 | axiam-surrealdb | ✓ 3/3 |
| run 6c B (3.3.5) | 4/4 | axiam | 8 743 | 5.0 | 8.0 | 7.00 | 0.801 | axiam-surrealdb | ✓ 2/3 |

| pass | caps | target | thr (req/s) | p50 (ms) | p95 (ms) | stack cores | cpu·ms/req | bottleneck | valid |
|---|---|---|---|---|---|---|---|---|---|
| run 6 | 2/2 | zitadel | 245 | 200.0 | 203.0 | 1.94 | 7.913 | none | ✓ 3/3 |
| run 6b B | 4/4 | zitadel | 226 | 200.0 | 270.0 | 2.29 | 10.125 | none | ✓ 3/3 |

**Keycloak serves 2.7× AXIAM's REST userinfo** (3,862 vs 1,411 at 2/2;
7,807 vs 2,963 at 4/4) and answers it without touching PostgreSQL (0.01
cores) — AXIAM reads SurrealDB on every call and SurrealDB is pegged.
AXIAM still leads Zitadel by 1.6–1.8×. This is the cell where 3.3.5 helps
AXIAM most among the identity reads (+58% at 2/2), and it still does not
close the gap (2,081 / 4,372 on 3.3.5). AXIAM's **gRPC userinfo** serves
3,078 req/s at 2/2 and 6,369 at 4/4 — 2.2× its own REST path and 12.6× /
28× Zitadel's gRPC userinfo, which holds a flat **200 ms p50** at both cap
levels with neither of its containers busy (a fixed floor, not CPU; its
gRPC surface is a management API, which is fair). Keycloak and authentik
expose no gRPC equivalent. Zitadel's userinfo token is minted with
client credentials in setup (`cc-token-setup`); the endpoint measured is
the labelled one.

### Authorization decisions (AXIAM-only — no competitor equivalent)

Full RBAC evaluation (tenant-scoped roles, resource hierarchy, scopes)
against live data, decision cache **off**. Batch rows are operations/s; a
batch is five checks.

| pass | caps | target | thr (req/s) | p50 (ms) | p95 (ms) | stack cores | cpu·ms/req | bottleneck | valid |
|---|---|---|---|---|---|---|---|---|---|
| run 6 | 2/2 | axiam | 492 | 96.3 | 152.5 | 2.66 | 5.400 | axiam-surrealdb | ✓ 3/3 |
| run 6b A | 2/2 | axiam | 451 | 100.2 | 163.8 | 2.69 | 5.957 | axiam-surrealdb | ✓ 3/3 |
| run 6c A (3.3.5) | 2/2 | axiam | 714 | 77.3 | 94.8 | 2.95 | 4.140 | axiam-surrealdb | ✓ 3/3 |
| run 6b B | 4/4 | axiam | 1 007 | 45.0 | 60.2 | 5.30 | 5.267 | axiam-surrealdb | ✓ 3/3 |
| run 6c B (3.3.5) | 4/4 | axiam | 1 593 | 28.4 | 40.1 | 5.83 | 3.660 | axiam-surrealdb | ✓ 3/3 |

| pass | caps | target | thr (req/s) | p50 (ms) | p95 (ms) | stack cores | cpu·ms/req | bottleneck | valid |
|---|---|---|---|---|---|---|---|---|---|
| run 6 | 2/2 | axiam | 645 | 83.0 | 100.0 | 2.59 | 4.024 | axiam-surrealdb | ✓ 3/3 |
| run 6b A | 2/2 | axiam | 572 | 88.0 | 106.0 | 2.69 | 4.713 | axiam-surrealdb | ✓ 3/3 |
| run 6c A (3.3.5) | 2/2 | axiam | 914 | 33.0 | 86.0 | 2.82 | 3.089 | axiam-surrealdb | ✓ 3/3 |
| run 6b B | 4/4 | axiam | 1 320 | 34.0 | 48.0 | 5.25 | 3.976 | axiam-surrealdb | ✓ 3/3 |
| run 6c B (3.3.5) | 4/4 | axiam | 1 955 | 23.0 | 33.0 | 5.68 | 2.903 | axiam-surrealdb | ✓ 3/3 |

| pass | caps | target | thr (req/s) | p50 (ms) | p95 (ms) | stack cores | cpu·ms/req | bottleneck | valid |
|---|---|---|---|---|---|---|---|---|---|
| run 6 | 2/2 | axiam | 485 | 96.9 | 152.9 | 2.69 | 5.541 | axiam-surrealdb | ✓ 3/3 |
| run 6b A | 2/2 | axiam | 445 | 100.6 | 165.0 | 2.74 | 6.160 | axiam-surrealdb | ✓ 3/3 |
| run 6c A (3.3.5) | 2/2 | axiam | 716 | 77.0 | 96.9 | 2.92 | 4.073 | axiam-surrealdb | ✓ 3/3 |
| run 6b B | 4/4 | axiam | 974 | 46.6 | 62.6 | 5.40 | 5.541 | axiam-surrealdb | ✓ 3/3 |
| run 6c B (3.3.5) | 4/4 | axiam | 1 556 | 29.0 | 40.7 | 5.82 | 3.744 | axiam-surrealdb | ✓ 3/3 |

| pass | caps | target | thr (req/s) | p50 (ms) | p95 (ms) | stack cores | cpu·ms/req | bottleneck | valid |
|---|---|---|---|---|---|---|---|---|---|
| run 6 | 2/2 | axiam | 620 | 85.0 | 102.0 | 2.65 | 4.276 | axiam-surrealdb | ✓ 3/3 |
| run 6b A | 2/2 | axiam | 577 | 88.0 | 106.0 | 2.69 | 4.674 | axiam-surrealdb | ✓ 3/3 |
| run 6c A (3.3.5) | 2/2 | axiam | 679 | 79.0 | 99.0 | 2.79 | 4.103 | axiam-surrealdb | ✓ 3/3 |
| run 6b B | 4/4 | axiam | 1 229 | 37.0 | 52.0 | 5.23 | 4.257 | axiam-surrealdb | ✓ 3/3 |
| run 6c B (3.3.5) | 4/4 | axiam | 1 540 | 29.0 | 42.0 | 5.50 | 3.572 | axiam-surrealdb | ✓ 3/3 |

In checks/s at 2/2 (run 6): REST 492 single / 2,425 batched; gRPC 645 /
3,100 — batching still multiplies the decision rate by ~4.9× on REST, as
in run 5. At 4/4: 1,007 / 4,870 and 1,320 / 6,145. On 3.3.5 every
authorization cell rises 1.18–1.61× at 2/2 — among the largest gains of
run 6c (§4). Run 5 measured 1,032 / 1,268 singles and 5,130 / 4,640
batched checks on the laptop; the database tier is the whole difference
(SurrealDB at its cap, server 0.38–0.43 of 2 cores).

### Session/token refresh — published under the protocol-variant label

> ⚠️ **Comparability: protocol-variant.** AXIAM supports the OAuth2
> refresh-token grant, but this cell obtains user tokens through a password
> login, and AXIAM's token endpoint has no password (ROPC) grant. So AXIAM's
> cell measures **session-cookie refresh** (`POST /api/v1/auth/refresh`,
> CSRF double-submit, single-use rotation), while Keycloak's measures the
> **OAuth2 refresh-token grant**. Zitadel's and authentik's cells are
> fallback operations and are excluded. The like-for-like cell,
> `oauth2_refresh_grant` (AXIAM seeded through the authorization-code flow
> with PKCE, every target measured on `grant_type=refresh_token`), was added
> after this round and has no results yet.

| pass | caps | target | thr (req/s) | p50 (ms) | p95 (ms) | stack cores | cpu·ms/req | bottleneck | valid |
|---|---|---|---|---|---|---|---|---|---|
| run 6 | 2/2 | axiam | 347 | 115.8 | 191.8 | 2.51 | 7.233 | axiam-surrealdb | ✓ 3/3 |
| run 6 | 2/2 | keycloak | 435 | 98.2 | 201.4 | 2.07 | 4.769 | keycloak | ✓ 3/3 |
| run 6 | 2/2 | zitadel | 1 | 5648.8 | 9411.8 | 2.06 | 1426.974 | zitadel | ✗ 0/3 |
| run 6 | 2/2 | authentik | 3 | 9839.9 | 37470.5 | 4.01 | 1529.849 | none | ✗ 0/3 |
| run 6b A | 2/2 | axiam | 305 | 129.6 | 210.2 | 2.54 | 8.311 | axiam-surrealdb | ✓ 3/3 |
| run 6c A (3.3.5) | 2/2 | axiam | 450 | 98.9 | 162.2 | 2.64 | 5.866 | axiam-surrealdb | ✓ 3/3 |
| run 6b B | 4/4 | axiam | 707 | 61.9 | 88.7 | 4.87 | 6.892 | axiam-surrealdb | ✓ 3/3 |
| run 6b B | 4/4 | keycloak | 943 | 18.0 | 100.4 | 4.09 | 4.340 | keycloak | ✓ 3/3 |
| run 6b B | 4/4 | zitadel | 3 | 2183.9 | 4522.4 | 4.11 | 1268.068 | zitadel | ✗ 0/3 |
| run 6b B | 4/4 | authentik | 3 | 9642.7 | 36407.6 | 4.40 | 1554.479 | none | ✗ 0/3 |
| run 6c B (3.3.5) | 4/4 | axiam | 771 | 54.5 | 82.9 | 4.67 | 6.049 | none | ✓ 2/3 |

**Keycloak is ahead this run** (435 vs 347 at 2/2; 943 vs 707 at 4/4).
AXIAM's session refresh is three database round trips with SurrealDB
pegged.
On 3.3.5 at 4/4 its limit is no longer database CPU (SurrealDB 3.73 of 4,
server 0.68, bottleneck none) — something else bounds it (§5).

### Password login (all targets hash for real)

AXIAM Argon2id (OWASP parameters), Keycloak Argon2id (default), Zitadel
bcrypt (default cost), authentik its default hasher (protocol-variant
cell).

| pass | caps | target | thr (req/s) | p50 (ms) | p95 (ms) | stack cores | cpu·ms/req | bottleneck | valid |
|---|---|---|---|---|---|---|---|---|---|
| run 6 | 2/2 | axiam | 49 | 1004.9 | 1046.1 | 2.63 | 53.638 | none | ✓ 3/3 |
| run 6 | 2/2 | keycloak | 47 | 1010.2 | 1213.2 | 2.07 | 44.294 | keycloak | ✓ 3/3 |
| run 6 | 2/2 | zitadel | 2 | 29243.8 | 33365.0 | 2.04 | 1333.228 | zitadel | ✗ 0/3 |
| run 6 | 2/2 | authentik | 1 | 25908.5 | 54250.8 | 4.19 | 3437.963 | authentik-postgres | ✗ 0/3 |
| run 6b A | 2/2 | axiam | 46 | 1053.3 | 1128.4 | 2.73 | 59.037 | none | ✓ 3/3 |
| run 6c A (3.3.5) | 2/2 | axiam | 47 | 1033.7 | 1117.3 | 2.50 | 53.553 | none | ✓ 3/3 |
| run 6b B | 4/4 | axiam | 93 | 523.6 | 561.7 | 5.17 | 55.706 | none | ✓ 3/3 |
| run 6b B | 4/4 | keycloak | 98 | 473.2 | 586.3 | 4.15 | 42.144 | keycloak | ✓ 3/3 |
| run 6b B | 4/4 | zitadel | 3 | 15067.6 | 16803.9 | 4.06 | 1292.769 | zitadel | ✗ 0/3 |
| run 6b B | 4/4 | authentik | 1 | 29557.5 | 66803.4 | 4.11 | 3030.012 | none | ✗ 0/3 |
| run 6c B (3.3.5) | 4/4 | axiam | 89 | 545.6 | 572.0 | 4.65 | 52.043 | none | ✓ 3/3 |

**A draw.** AXIAM 49 vs Keycloak 47 logins/s at 2/2 (AXIAM's p95 tighter,
1,046 vs 1,213 ms); 93 vs 98 at 4/4, inside Keycloak's ±4.3% spread. Both
are CPU-bound on hashing and both double with the cores. **Keycloak's
login is valid at every profile for the first time in this series**, at
the same 2 GiB cap as everyone else. AXIAM's server holds 73 MiB during
the burst against Keycloak's 708. Zitadel's default bcrypt cost keeps it
at a ~29 s p50 (expected and tunable).

## 2. What changed since draft six (run 5), and why the numbers moved

Run 6 is **not a like-for-like re-run of run 5**. Four things changed at
once, and each is named wherever a run-5 figure is quoted:

| Change | Run 5 | Runs 6–6c | Effect |
|---|---|---|---|
| Host | Dell XPS 15 laptop (i7-8750H, 12 threads, thermally limited) | Cloud VM, AMD EPYC Genoa, 16 vCPUs, qualified, 0% steal | Competitors are the control: on the same cells Keycloak moved **+3% to +21%** and Zitadel **−14% to −1%** — a host effect is small and not one-directional |
| AXIAM | 1.0.0-alpha24 | 1.3.0 (run 6), 1.3.1 (6b, 6c) | ~40 releases: OPAQUE, CIBA, SAML IdP, SCIM outbound, directory sources, AMQP over TLS, refresh in three round trips, two-layer single-use redemption (schema v84) |
| Datastore | SurrealDB 3 | **SurrealDB 4.0.1** (runs 6, 6b); 3.3.5 (run 6c) | AXIAM 1.3 requires 4.0. Run 6c sizes the server's share (§4) |
| Targets | AXIAM, Keycloak 26.7.0, Zitadel v4.16.2 | + **authentik 2026.8.5**; Keycloak 26.8.1, Zitadel v4.19.5 | authentik produced no valid cell (§8) |

**What moved, run 5 → run 6 (AXIAM, p0, 2/2):** client credentials 2,804
→ 1,610 (−43%), introspection 4,504 → 1,582 (−65%), REST userinfo 4,752 →
1,411 (−70%), gRPC userinfo 12,307 → 3,078 (−75%), single authorization
checks 1,032 → 492 (−52%) — while **JWKS rose 26,680 → 43,640 (+64%)**. A
host change cannot move database-bound and database-free cells in
opposite directions: the drop lives in the database tier. Run 6c puts a
number on the SurrealDB 4.0.1 server's share (13–38%); the remainder —
on 3.3.5, token issuance is 1,970 against run 5's 2,804 on a different
host — is not yet explained, and §5 names the candidates.

**AXIAM 1.3.0 → 1.3.1 at equal caps (run 6b A against run 6): −5% to
−12%** on every cell (client credentials −10%, introspection −9%,
userinfo −6%, gRPC userinfo −9%, refresh −12%, authorization −7% to
−11%, JWKS −5%, login −6%). That is outside run 6's ±0.3–4.5% run-to-run
spread. 1.3.1's changelog lists dependency bumps and test fixes and no
performance change; the control pass ran a day later with no competitor
alongside it, so release and day-to-day host drift cannot be separated.
It is reported, not absorbed: the run-6b cap factors and the run-6c
server factors both use 1.3.1 at 2/2 as AXIAM's baseline, so neither is
contaminated by it.

## 3. Run 6b: twice the cores — was it the caps?

In run 6 nearly every cell stopped at the 2-CPU cap of one container
while the host had more than half its CPU free: SurrealDB for AXIAM
(2.00–2.04 cores on all 27 database-bound cells, the server at
0.27–0.84), the server for Keycloak (2.01 everywhere), the server or
PostgreSQL for Zitadel, PostgreSQL for authentik. Run 6b raised **every
server and every database to 4 CPUs** — the same step for every target
and role, memory unchanged — on the same competitor and SurrealDB
digests. AXIAM's factor is measured against its own 1.3.1 control at 2/2.

| scenario | AXIAM 2/2 → 4/4 | Keycloak 2/2 → 4/4 | Zitadel 2/2 → 4/4 |
|---|---|---|---|
| client credentials | 1,448 → 3,234 · **2.23×** · SurrealDB | 411 → 934 · **2.27×** · server | 425 → 704 · **1.66×** · none ≥ 95% |
| token introspection | 1,438 → 3,272 · **2.28×** · SurrealDB | 1,940 → 3,952 · **2.04×** · server | 827 → 1,522 · **1.84×** · none ≥ 95% |
| userinfo REST | 1,320 → 2,963 · **2.24×** · SurrealDB | 3,862 → 7,807 · **2.02×** · server | 859 → 1,677 · **1.95×** · PostgreSQL |
| userinfo gRPC | 2,795 → 6,369 · **2.28×** · SurrealDB | — | 245 → 226 · **0.92×** · none (200 ms floor) |
| JWKS | 41,523 → 43,232 · 1.04× · load generator | 5,529 → 10,832 · **1.96×** · server | 2,031 → 3,953 · **1.95×** · PostgreSQL |
| password login | 46 → 93 · **2.02×** · none ≥ 95% (server 3.7) | 47 → 98 · **2.09×** · server | ✗ |
| refresh | 305 → 707 · **2.32×** · SurrealDB | 435 → 943 · **2.17×** · server | ✗ |
| authz check REST / gRPC | 451 / 572 → 1,007 / 1,320 · **2.23× / 2.31×** · SurrealDB | — | — |
| authz batch REST / gRPC (ops/s) | 445 / 577 → 974 / 1,229 · **2.19× / 2.13×** · SurrealDB | — | — |

What it shows:

1. **AXIAM and Keycloak were cap-limited, not product-limited.** Both
   roughly double and stay bound in the same container.
2. **SurrealDB's per-statement cost parallelises.** If #7667's cost could
   not run in parallel, more database cores would not help; AXIAM's
   database-bound cells more than doubled. The regression costs cores; it
   does not serialise.
3. **Zitadel has a limit that is not CPU** on token issuance and
   introspection (no container at 95% at 4/4), and a fixed 200 ms floor on
   gRPC userinfo.
4. **No head-to-head winner changed** (§1).
5. **Run 6's shared 65–90 ms p95 band was CPU-quota throttling.** At 4/4
   AXIAM's token-issuance p95 fell 69 → 20 ms with its p50 almost unchanged
   (14.9 → 13.7 ms), introspection 69 → 20 ms, gRPC userinfo 59 → 11 ms;
   Keycloak's JWKS p95 73.5 → 5.6 ms. A tail that collapses when a
   container stops hitting its quota while the median stays put is what
   CFS throttling looks like. Every run-6 p95 on a pegged container
   carries it, for every target alike.

## 4. Run 6c: what the SurrealDB 4.0.1 server costs AXIAM

**One variable: the database server.** The same AXIAM 1.3.1 image, by
digest, ran the matrix (all three profiles) against a **SurrealDB 3.3.5**
server — the last release before 4.0 — at both cap levels, on the same
VM, on a freshly created database volume for every block (a 4.x volume
cannot be opened by 3.x). The dry runs passed at both caps and all 66
cells are valid. It is compared at p0-plaintext with run 6b's AXIAM 1.3.1
on 4.0.1 at equal caps.

> **Label on every run-6c number: SurrealDB 3.3.5 server, unsupported,
> benchmark-only.** AXIAM 1.3 requires 4.0. Its locked 4.0.0 client
> accepts a 3.x server (`SUPPORTED_VERSIONS = ">=3.0.0-alpha.1, <5.0.0"`),
> and the only SurrealQL change between the last 3.x commit and v1.3.1 is
> a bound `$cutoff` in the rate-limit sweep — but CI last ran these
> queries against 3.3.4, not 3.3.5, and never with a 4.0 client against a
> 3.x server. Passing dry runs show the benchmarked paths work, not that
> the product does. 3.3.5 also carries RUSTSEC-2026-0452 and
> RUSTSEC-2026-0454, which 4.0 fixed.

| scenario (p0) | 2/2: 4.0.1 → 3.3.5 · ratio · **4.0.1's cost** | 4/4: 4.0.1 → 3.3.5 · ratio · **4.0.1's cost** | SurrealDB cores per 1,000 req, 2/2 |
|---|---|---|---|
| client credentials | 1,448 → 1,970 · 1.36× · **26%** | 3,234 → 3,853 · 1.19× · **16%** | 1.40 → 1.04 (−26%) |
| token introspection | 1,438 → 1,661 · 1.16× · **13%** | 3,272 → 3,609 · 1.10× · **9%** | 1.41 → 1.23 (−13%) |
| userinfo REST | 1,320 → 2,081 · 1.58× · **37%** | 2,963 → 4,372 · 1.48× · **32%** | 1.54 → 0.98 (−36%) |
| userinfo gRPC | 2,795 → 4,026 · 1.44× · **31%** | 6,369 → 8,743 · 1.37× · **27%** | 0.73 → 0.51 (−30%) |
| refresh | 305 → 450 · 1.48× · **32%** | 707 → 771 · 1.09× · **8%** | 6.62 → 4.49 (−32%) |
| authz check REST | 451 → 714 · 1.58× · **37%** | 1,007 → 1,593 · 1.58× · **37%** | 4.48 → 2.84 (−37%) |
| authz check gRPC | 572 → 914 · 1.60× · **37%** | 1,320 → 1,955 · 1.48× · **32%** | 3.53 → 2.22 (−37%) |
| authz batch REST (ops/s) | 445 → 716 · 1.61× · **38%** | 974 → 1,556 · 1.60× · **37%** | 4.54 → 2.84 (−38%) |
| authz batch gRPC (ops/s) | 577 → 679 · 1.18× · **15%** | 1,229 → 1,540 · 1.25× · **20%** | 3.50 → 2.99 (−15%) |
| password login | 46 → 47 · 1.02× | 93 → 89 · 0.96× | 14.8 → 8.1 |
| JWKS (no database) | 41,523 → 40,430 · 0.97× | 43,232 → 41,737 · 0.97× | — |

"4.0.1's cost" is `1 − thr(4.0.1) ÷ thr(3.3.5)`: how much throughput the
4.0.1 server takes from AXIAM.

**How much the two bugs cost AXIAM, measured.** On the nine
database-bound cells the **SurrealDB 4.0.1 server costs AXIAM 13–38% of
its throughput at 2 CPUs (median 32%) and 8–37% at 4 CPUs (median
27%)**; on 3.3.5 the database needs 13–38% less CPU per request.
Attributed carefully:

- **#7716 contributes nothing**: AXIAM defines no events.
- **#7667 is the known candidate**, and the measurement is of the whole
  4.0.1 server against 3.3.5 — #7667 plus anything else that changed in
  4.0. The shape **does not follow #7667 alone**. #7667 describes a cost on
  write statements with reads almost unchanged, so the write-heavy cells
  (token issuance, refresh, login) should gain most on 3.3.5. At 4 CPUs
  they gain least — 4.0.1 costs token issuance, introspection and refresh
  **8–16%** — and the read-heavy authorization checks and userinfo gain
  most, **20–37%**. The gRPC cells settle which explanation holds: gRPC
  userinfo is **one read** per request and gRPC authorization **three
  reads**, with no session check and no audit row by default (§5.1) — no
  write at all — and 4.0.1 still costs them **15–37%** (single checks and userinfo 27–37%, batches 15–20%). **4.0.1's extra
  cost is not only on writes.** The REST cells also write one audit row
  per request (§5.1), which is #7667's territory, but the read cost alone
  is enough to explain most of the loss.
- **The bottleneck does not move.** SurrealDB stays at its cap in every
  database-bound cell except refresh at 4/4 (3.73 of 4 cores, server 0.68,
  bottleneck none). Each request simply costs the database less.
- **Login and JWKS do not depend on the server version** (within ±5% and
  ±3%), as predicted.
- **3.3.5 recovers part of the drop since run 5, not all of it** (§2), and
  even on 3.3.5 Keycloak would still lead introspection and REST userinfo
  at both cap levels.

**Our reading.** The run-6c figures are the ones that represent AXIAM's
own performance; the 4.0.1 figures carry the server regression on top.
We expect AXIAM to return to the 3.3.5 level once SurrealDB fixes its 4.0
regressions, and the database-bound cells will be re-measured on this VM
when a fixed release ships. Until then, the 4.0.1 figures are what a
supported deployment gets.

## 5. Is there more to optimise? Yes — and it is the database work per request

Runs 6–6c point the same way. The AXIAM server is not the constraint: it
used 0.27–2.7 cores on cells where the database was pegged, and
server-only it spends the least CPU per request of any target on every
cell (§7). TLS and mTLS cost nothing measurable on database-bound cells,
and RabbitMQ stays near 0.2 cores. **What limits every data-touching cell
is how much database work each request asks for**, multiplied by what
each statement costs on the server version. A fixed SurrealDB release
would lower the second factor by 8–38% (§4); everything in this section is
about the first, which is ours, and it matters on 3.3.5 as much as on
4.0.1 — even on 3.3.5 Keycloak leads introspection and REST userinfo.

### 5.1 What each request asks of the database (from source, v1.3.1 defaults)

Decision cache and session-validation cache off (the shipped defaults);
every step is one SurrealDB query over the HTTP engine, and **every step
within a request is awaited sequentially** (no concurrent fan-out on any
single-request path).

| endpoint | DB round trips per request | SurrealDB cores per 1,000 req (run 6c, 3.3.5, 2/2) | Keycloak's database for the same cell (run 6, 2/2) |
|---|---|---|---|
| REST userinfo | **2 reads** — session revocation (`is_session_active_checked`), then user — + 1 audit write | 0.98 | PostgreSQL 0.01 cores in total: served from memory |
| gRPC userinfo | **1 read** (user); no session check (`strict_revocation=false`), no audit | 0.51 | — |
| introspection (user access token) | **3 reads** — client, tenant liveness, user — + 1 audit write | 1.23 | PostgreSQL 0.51 cores ≈ 0.26 per 1,000 req |
| client credentials | **2 reads** — client, tenant liveness — + 1 audit write; no token row persisted | 1.04 | PostgreSQL 0.13 cores ≈ 0.32 per 1,000 req |
| authz check, REST (user token) | **1 + 3 reads** — session, then role assignments, ancestors, grants (4 with a scope) — + 1 audit write | 2.84 | — |
| authz check, gRPC | **3 reads** (4 with a scope); no session check, no audit | 2.22 | — |
| session refresh | **3 round trips** — consume (delete + read), user, create — + 1 audit write; tenant→org cached 60 s | 4.49 | — |

Two things in that table are worth stating separately:

- **Every REST request writes one `audit_log` row**, through an in-process
  channel and **a single background task that appends one row per round
  trip** (`axiam-audit/src/middleware.rs`, `audit_worker`). It is off the
  request path, but it is a write statement per request — #7667's cost —
  and one worker appending one row at a time has a throughput ceiling of
  its own. When the 4,096-slot channel is full, new rows are shed to the
  dead-letter file and counted (`RequestAuditLoss`, reported on
  `/health/jobs`). **At the REST rates measured here (1,000–4,400 req/s)
  it is likely that the worker did not keep up and rows were shed during
  the benchmark.** The run did not capture the loss counter, so this is
  an inference from the code, not a measurement; it is the first thing to
  check, because if it holds, the benchmark's REST database cost is
  *understated* by the rows that were never written, and the audit trail
  under sustained load is incomplete — a compliance issue before it is a
  performance one.
- **Keycloak answers userinfo without its database** and introspects with
  a fraction of AXIAM's database work. That is the two cells AXIAM loses,
  and it is a design difference, not an engine one: Keycloak keeps
  sessions and users in an in-memory cache (Infinispan), AXIAM re-reads
  them on every call so that a revocation or a disabled account takes
  effect on the next request.

### 5.2 The levers, in the order the evidence ranks them

1. **Batch the audit writes.** Replace the one-row-per-round-trip worker
   with a multi-row insert (drain up to N queued rows, one statement, one
   round trip). It removes most of a write statement per REST request —
   the cost #7667 inflates — and lifts the worker's ceiling far above the
   request rate. Measure first: add the lost-row counter to the harness's
   per-cell capture, then re-run the REST cells before and after.
2. **One round trip per request instead of two to four.** The
   authorization engine already runs its reads in sequence over one
   handle; role assignments, ancestors and grants can be issued as one
   multi-statement query (the repository layer already uses
   multi-statement queries for role assignments). The same applies to
   introspection's client + tenant + user and to REST userinfo's session +
   user. Each round trip on the HTTP engine is a separate authenticated
   HTTP request that SurrealDB parses, authenticates and plans; fewer
   round trips cut fixed per-request cost on either server version and
   shorten the serial chain that sets latency. This needs a database-side
   CPU profile per query shape before it is built, so the gain is
   predicted rather than hoped for.
3. **Cache what is read on every request, with the revocation contract
   stated.** The mechanisms exist and are measured: the session-validation
   cache and the decision cache lifted REST authorization from 1,013 to
   11,647 checks/s in run 5's 2×2, and revocation through the API still
   took effect 262 ms after the call with them on (Appendix A). Both ship
   **off** on purpose. Candidates, each with an explicit staleness bound:
   tenant liveness and OAuth client records on token issuance and
   introspection (today read on every call, deliberately, so a suspended
   tenant stops immediately); the user record behind userinfo; the
   session check behind REST requests. Turning any of them on by default
   is a security-posture decision, not a benchmark one, and belongs in the
   threat model first; offering a measured "throughput" profile beside the
   strict default is the honest middle.
4. **Find which reads got more expensive on 4.0.1, and report them.** The
   gRPC cells (no writes) lose 15–37% on 4.0.1 (§4): a read regression
   that #7667 does not describe. A per-statement timing of AXIAM's hot
   queries on 3.3.5 and 4.0.1 — `EXPLAIN` plus server-side CPU — names the
   statements, and a reproduction belongs upstream next to #7667. If a
   query shape that 4.0's planner handles badly can be rewritten, that part
   is ours to fix without waiting.
5. **Explain the 1.3.0 → 1.3.1 drop of 5–12%** (§2) with a same-day
   control that runs both images and one competitor in the same session.
   Until it is explained it is a regression on the books.
6. **Refresh's non-CPU limit.** On 3.3.5 at 4/4, refresh stops at 771
   req/s with no container at its cap (SurrealDB 3.73 of 4, server 0.68).
   The consume step is a single-winner delete under concurrency;
   write-conflict retries or the single client handle (`DB__POOL_SIZE=1`,
   the shipped default) are the suspects, and the existing pool knob
   (`AXIAM__DB__POOL_SIZE`) is a cheap first sensitivity cell.
7. **Read scaling.** The read-replica routing primitive exists and is off.
   With the database the ceiling on every read-heavy cell, it is the
   architectural lever after the per-request work is reduced — but it
   adds replicas to operate and staleness to document, so it comes last.

What is **not** worth optimising on this evidence: the AXIAM server's own
CPU path, TLS, the broker, and the SDKs (eight of nine concurrent SDKs
add 0.5–3.2 ms at p95, §11).

## 6. Security cost of TLS 1.3 and mutual TLS (run 6, vs p0, valid cells)

| target / scenario | Δ thr p2 (TLS 1.3) | Δ thr p3 (mTLS) |
|---|---|---|
| axiam / oauth2_client_credentials | −0.9% | −1.9% |
| axiam / token_introspection | −1.4% | +0.4% |
| axiam / userinfo REST / gRPC | +1.0% / −0.1% | +0.6% / −0.4% |
| axiam / authz check REST / gRPC | −1.2% / −1.4% | +0.8% / 0.0% |
| axiam / authz batch REST / gRPC | +0.8% / +2.1% | +1.9% / +1.3% |
| axiam / token_refresh | +0.3% | −2.0% |
| axiam / oauth2_password_login | 0.0% | 0.0% |
| axiam / jwks_fetch | **−16.0%** | **−12.7%** |
| keycloak / jwks, introspection, userinfo | −5.6%, −6.5%, −9.2% | **−17.0%**, −9.8%, −10.1% |
| keycloak / client credentials, refresh, login | −2.9%, +2.8%, −2.1% | +3.2%, −1.8%, −2.1% (valid at p3 this run) |
| zitadel (valid cells) | −2.1% … +2.6% | −2.0% … 0.0% |

**Native mTLS — client certificates verified in-process, no sidecar —
stays within ±2% of plaintext on every database-bound AXIAM cell**, for a
reason that must be stated with it: TLS work lands on the AXIAM server,
which has spare cores, while the ceiling is the database. JWKS, the one
cell where the server works hardest, shows the cost of the cryptography
itself: −16.0% / −12.7%. Run 6c measured all three profiles on 3.3.5 as
well and tells the same story at both cap levels: database-bound cells
within −5% to +6% of plaintext, JWKS −12% to −15% (§10.4, §10.5). Most REST rows
measure TLS *plus* an HTTP/1.1 → 2 change together (the `http` column of
the raw report says which).

## 7. Resource usage (graph-ready)

Average RSS of the *server* container, MiB, p0, median-of-3 (run 6, 2/2):

| scenario | AXIAM | Keycloak | Zitadel |
|---|---|---|---|
| jwks_fetch | **54** | 784 | 133 |
| oauth2_client_credentials | **57** | 782 | 129 |
| token_introspection | **58** | 941 | 130 |
| token_refresh | **57** | 877 | — |
| userinfo | **57** | 878 | 127 |
| oauth2_password_login | **73** | 708 | — |
| authz check/batch | 57 | — | — |

Across the whole run-6 matrix AXIAM's server averaged **54–75 MiB**,
Keycloak's 708–941 MiB and Zitadel's 127–137 MiB, all against the same
2 GiB cap. At 4/4 (run 6b) AXIAM's server rose to 89–133 MiB and
Keycloak's to 1,082–1,170 MiB. **Keycloak 26.8.1 shows no reduction
against the 710–853 MiB Keycloak 26.7.0 averaged in run 5** — a different
host, so a direction, not a measurement of its release-note claim.

Whole stack, CPU and memory efficiency (run 6, p0, 2/2):

| scenario | metric | AXIAM | Keycloak | Zitadel |
|---|---|---|---|---|
| client credentials | cpu·ms/req, whole stack | **1.84** | 5.21 | 8.99 |
| 〃 | cpu·ms/req, server only | **0.44** | 4.89 | 4.61 |
| token introspection | cpu·ms/req, whole stack | 1.86 | **1.30** | 4.72 |
| 〃 | cpu·ms/req, server only | **0.42** | 1.04 | 2.31 |
| jwks_fetch | cpu·ms/req, whole stack | **0.05** | 0.37 | 1.50 |
| userinfo REST | cpu·ms/req, whole stack | 2.01 | **0.52** | 3.42 |
| 〃 | cpu·ms/req, server only | **0.42** | 0.52 | 1.05 |
| client credentials | req/s per GiB of stack RAM | **4 554** | 456 | 1 240 |
| token introspection | 〃 | **3 913** | 1 798 | 2 122 |
| userinfo REST | 〃 | 3 630 | **3 777** | 2 205 |
| jwks_fetch | 〃 | **140 970** | 6 493 | 7 908 |

Whole-stack, **Keycloak now wins introspection and userinfo** on CPU per
request, and userinfo per GiB narrowly; server-only, AXIAM is the
cheapest on every row. The whole-stack gap is the database work of §5.

**At rest** (whole stack, freshly started, median of 6–8 samples):

| target | RSS, fresh / with fixture (MiB) | cgroup working set, fresh (MiB) | what's in it |
|---|---|---|---|
| AXIAM | **373** / 398 | 216 | server 92 + SurrealDB 119 + RabbitMQ 162 (RSS) |
| Zitadel | 593 / 639 | **172** | server 167 + PostgreSQL 427 (RSS) |
| Keycloak | 1 074 / 1 102 | 934 | server 891 + PostgreSQL 183 (RSS) |
| authentik | 1 668 / 1 682 | 819 | server 983 + worker 347 + PostgreSQL 338 (RSS) |

Which stack is smallest at rest depends on the measure: by resident set
AXIAM's, by cgroup working set Zitadel's — PostgreSQL's shared buffers
count in its resident set. The minimal profile (no broker) was not
re-measured in this round; Appendix A carries its 2026-10-05 figures.

## 8. Weaknesses and caveats (the honest section)

- **AXIAM lost two head-to-head cells it used to win** — introspection
  and REST userinfo, to Keycloak, at both cap levels and even on 3.3.5
  (§1, §5). We publish the losses as plainly as the wins.
- **The SurrealDB 4.0.1 server costs AXIAM 13–38% at 2 CPUs and 8–37% at
  4** (§4), and AXIAM 1.3 cannot run on anything else in support. The two
  upstream issues are open with no fix merged.
- **AXIAM 1.3.1 measured 5–12% below 1.3.0 at equal caps**, unexplained
  (§2).
- **The audit worker may shed rows under sustained REST load** (§5.1) —
  inferred from the code, not measured; to be checked first.
- **authentik produced no valid cell** in any run. Its PostgreSQL is
  pegged at 2/2; at 4/4 it roughly doubles and stays above the 2 s p95
  gate (two cells 1/3 valid). With the worker carrying the server cap its
  stack has 6 CPU / 5 GiB at 2/2 against Keycloak's 4 / 3. Its p2 is its
  own TLS listener over HTTP/1.1, it has no p3, its login is
  protocol-variant and its refresh a fallback operation. **We make no
  performance statement about authentik from these runs.**
- **Zitadel**: login invalid (default bcrypt cost, ~29 s p50 at 2/2),
  refresh a fallback operation, userinfo via a client-credentials token;
  a non-CPU limit on token issuance and introspection and a fixed 200 ms
  gRPC userinfo floor that we have not explained and do not quote as
  product ceilings.
- **The p95 of every pegged container at 2/2 carries CPU-quota
  throttling** (§3); p50 is the better cross-target latency figure for
  run 6, and run 6b's p95 the better tail figure.
- **Run 6c is an unsupported pairing** (a 4.0 client on a 3.3.5 server,
  never in AXIAM's CI) carrying two RUSTSEC advisories; it sizes the bug
  and is not a deployment recommendation.
- **Scope.** This round measured the comparison only. Deferred, and
  therefore **not** re-verified: the production rate-limit table (§9
  carries run 5's, with its failing rows), the new-feature cells, the
  minimal profile, and the investigation passes (refresh stage timings,
  strict revocation, decision-cache sensitivity).
- **One cloud VM, shared tenancy.** Qualified and steal-free throughout,
  but its vCPUs are SMT threads; absolute figures describe this instance
  class. AXIAM's JWKS cell saturates the load generator in every pass.

## 9. Production rate limits — carried from run 5, not re-measured

Run 6 deferred the production-posture pass, so **nothing in this section
was measured on the cloud VM**. The table below is run 5's (laptop,
1.0.0-alpha24) and is kept because the failing rows are still open: they
have been neither confirmed fixed nor re-measured. The capacity column is
run 5's capacity. **Run 6's lower database-bound capacities narrow the
margins, and one falls below the bar the codebase itself asserts.** The
unit test `revised_machine_defaults_stay_far_below_measured_capacity`
(`axiam-api-rest/src/config/rate_limit.rs`) requires every machine default
to sit at least 25× below measured capacity, with run-5 capacities. With
run 6's REST authorization capacity at 2/2 — 492 checks/s ≈ 29,500/min
on SurrealDB 4.0.1 — the 1,800/min `authz_check` default is **16×**
below it, under the bar (on 3.3.5, 714/s ≈ 42,800/min, 24×; at 4/4,
1,007/s, 34×). Token issuance (≈96,600/min, 805×) and introspection
(≈94,900/min, 158×) stay far above it. Whether the default or the bar
moves is a posture decision; it is recorded here so it is taken with the
current numbers.

| endpoint | shipped default (`internet`, per-IP) | run-5 capacity (2c server / 2c DB) | flood enforcement in run 5 (admitted vs configured, ±10% bar) |
|---|---|---|---|
| `POST /api/v1/auth/login` | 10/min | ~69/s (Argon2id-bound) | ✅ PASS — 11/min |
| `POST /oauth2/token` | 120/min | ~2 804/s | ❌ FAIL — 135/min (+12%) |
| `POST /oauth2/introspect` | 600/min | ~4 504/s | ❌ FAIL — 889/min (+48%) |
| `POST /api/v1/authz/check` | 1 800/min | ~1 032/s | ❌ FAIL — 2 699/min (+50%) |
| gRPC authz | 100/s | ~1 268/s | ❌ FAIL — 181/min (~1/33) |
| gRPC identity | 500/s | ~12 307/s | ❌ FAIL — 1 504/min (~1/20) |
| `POST /oauth2/revoke`, gRPC admin / infra | 60/min, 10/s / 100/s | — | not covered by a scenario |

Posture guidance is unchanged: `internet` (default), `gateway` or `mesh`;
human endpoints keep strict per-IP limits in every profile. The standing
caveat, verbatim: `client_id`-keyed modes are fairness controls between
authenticated well-behaved clients, not abuse controls — the client_id is
attacker-mintable before authentication — so use them only behind an edge
that authenticates callers. `ip` remains the only attacker-resistant key
and stays the default.

## 10. Full result matrix (graph-ready)

One row per (scenario, profile, target) and pass; `±` is the throughput
spread across the three repeats; `cpu` whole-stack cores; `mem`
whole-stack MiB; `bottleneck` the container at ≥ 95% of its cap. Rows
failing a validity gate or carrying a label say so and **must not be
charted as an unqualified head-to-head**. Run-6c rows are SurrealDB 3.3.5,
unsupported, benchmark-only.

### 10.1 Run 6 — AXIAM 1.3.0, SurrealDB 4.0.1, 2/2, all profiles

| scenario | profile | target | thr (req/s) | ± | p50 (ms) | p95 (ms) | p99 (ms) | cpu | mem | bottleneck | valid / label |
|---|---|---|---|---|---|---|---|---|---|---|---|
| authz_batch_grpc | p0 | axiam | 620 | 1.6% | 85.0 | 102.0 | 112.0 | 2.65 | 398 | axiam-surrealdb | ✓ |
| authz_batch_grpc | p2 | axiam | 633 | 2.0% | 84.0 | 101.0 | 109.0 | 2.66 | 397 | axiam-surrealdb | ✓ |
| authz_batch_grpc | p3 | axiam | 628 | 0.5% | 84.0 | 101.0 | 109.0 | 2.65 | 403 | axiam-surrealdb | ✓ |
| authz_batch_rest | p0 | axiam | 485 | 1.9% | 96.9 | 152.9 | 169.0 | 2.69 | 287 | axiam-surrealdb | ✓ |
| authz_batch_rest | p2 | axiam | 489 | 3.9% | 96.7 | 154.7 | 169.5 | 2.68 | 289 | axiam-surrealdb | ✓ |
| authz_batch_rest | p3 | axiam | 494 | 2.5% | 96.1 | 123.1 | 167.3 | 2.69 | 290 | axiam-surrealdb | ✓ |
| authz_check_grpc | p0 | axiam | 645 | 0.6% | 83.0 | 100.0 | 107.0 | 2.59 | 292 | axiam-surrealdb | ✓ |
| authz_check_grpc | p2 | axiam | 636 | 4.5% | 84.0 | 100.0 | 109.0 | 2.65 | 299 | axiam-surrealdb | ✓ |
| authz_check_grpc | p3 | axiam | 645 | 1.1% | 83.0 | 100.0 | 107.0 | 2.63 | 294 | axiam-surrealdb | ✓ |
| authz_check_rest | p0 | axiam | 492 | 1.4% | 96.3 | 152.5 | 168.4 | 2.66 | 298 | axiam-surrealdb | ✓ |
| authz_check_rest | p2 | axiam | 486 | 3.1% | 96.9 | 154.4 | 168.4 | 2.68 | 302 | axiam-surrealdb | ✓ |
| authz_check_rest | p3 | axiam | 496 | 2.0% | 95.8 | 118.3 | 166.7 | 2.65 | 301 | axiam-surrealdb | ✓ |
| jwks_fetch | p0 | axiam | 43640 | 3.6% | 0.8 | 1.8 | 2.5 | 2.15 | 312 | none | ✓ |
| jwks_fetch | p0 | keycloak | 5529 | 8.6% | 1.9 | 73.5 | 77.9 | 2.02 | 917 | keycloak | ✓ |
| jwks_fetch | p0 | zitadel | 2031 | 2.0% | 10.4 | 69.3 | 72.2 | 3.04 | 263 | zitadel-postgres | ✓ |
| jwks_fetch | p0 | authentik | 24 | 0.8% | 1905.3 | 2790.4 | 3167.7 | 2.93 | 1250 | authentik-postgres | ✗ invalid |
| jwks_fetch | p2 | axiam | 36648 | 1.3% | 1.0 | 2.1 | 2.8 | 2.45 | 316 | none | ✓ |
| jwks_fetch | p2 | keycloak | 5218 | 7.4% | 2.2 | 72.3 | 76.6 | 2.03 | 1058 | keycloak | ✓ |
| jwks_fetch | p2 | zitadel | 2084 | 2.4% | 11.5 | 64.3 | 67.6 | 3.20 | 274 | zitadel-postgres | ✓ |
| jwks_fetch | p2 | authentik | 24 | 1.8% | 1894.4 | 2715.2 | 3113.2 | 2.91 | 1265 | authentik-postgres | ✗ invalid |
| jwks_fetch | p3 | axiam | 38117 | 2.5% | 0.9 | 2.0 | 2.7 | 2.43 | 315 | none | ✓ |
| jwks_fetch | p3 | keycloak | 4589 | 5.0% | 2.4 | 74.7 | 78.5 | 2.02 | 976 | keycloak | ✓ |
| jwks_fetch | p3 | zitadel | 2030 | 2.8% | 11.9 | 65.1 | 68.8 | 3.20 | 272 | zitadel-postgres | ✓ |
| oauth2_client_credentials | p0 | axiam | 1610 | 0.5% | 14.9 | 69.1 | 73.4 | 2.96 | 359 | axiam-surrealdb | ✓ |
| oauth2_client_credentials | p0 | keycloak | 411 | 10.4% | 99.5 | 201.0 | 293.6 | 2.14 | 938 | keycloak | ✓ |
| oauth2_client_credentials | p0 | zitadel | 425 | 5.1% | 109.2 | 135.7 | 148.1 | 3.82 | 352 | zitadel | ✓ |
| oauth2_client_credentials | p0 | authentik | 5 | 10.7% | 6340.2 | 27855.0 | 41836.8 | 3.83 | 1280 | none | ✗ invalid |
| oauth2_client_credentials | p2 | axiam | 1596 | 0.5% | 15.0 | 69.2 | 73.5 | 3.01 | 366 | axiam-surrealdb | ✓ |
| oauth2_client_credentials | p2 | keycloak | 399 | 13.4% | 100.1 | 201.1 | 293.6 | 2.13 | 890 | keycloak | ✓ |
| oauth2_client_credentials | p2 | zitadel | 416 | 3.1% | 111.3 | 139.6 | 152.5 | 3.83 | 353 | zitadel | ✓ |
| oauth2_client_credentials | p2 | authentik | 5 | 16.3% | 6518.5 | 25132.5 | 38588.1 | 3.91 | 1265 | none | ✗ invalid |
| oauth2_client_credentials | p3 | axiam | 1580 | 0.7% | 15.3 | 69.4 | 73.8 | 3.13 | 364 | axiam-surrealdb | ✓ |
| oauth2_client_credentials | p3 | keycloak | 424 | 8.8% | 99.1 | 198.9 | 288.8 | 2.15 | 983 | keycloak | ✓ |
| oauth2_client_credentials | p3 | zitadel | 417 | 3.5% | 111.3 | 140.4 | 153.3 | 3.85 | 354 | zitadel | ✓ |
| oauth2_password_login | p0 | axiam | 49 | 0.6% | 1004.9 | 1046.1 | 1062.3 | 2.63 | 393 | none | ✓ |
| oauth2_password_login | p0 | keycloak | 47 | 3.4% | 1010.2 | 1213.2 | 1315.9 | 2.07 | 856 | keycloak | ✓ |
| oauth2_password_login | p0 | zitadel | 2 | 1.4% | 29243.8 | 33365.0 | 35445.9 | 2.04 | 393 | zitadel | ✗ invalid |
| oauth2_password_login | p0 | authentik | 1 | 17.4% | 25908.5 | 54250.8 | 56366.8 | 4.19 | 1329 | authentik-postgres | ✗ invalid, protocol-variant, protocol-variant |
| oauth2_password_login | p2 | axiam | 49 | 1.4% | 995.8 | 1043.6 | 1067.9 | 2.65 | 392 | none | ✓ |
| oauth2_password_login | p2 | keycloak | 46 | 14.4% | 1002.4 | 1216.4 | 1352.3 | 2.07 | 866 | keycloak | ✓ |
| oauth2_password_login | p2 | zitadel | 2 | 1.1% | 28819.5 | 32851.2 | 34455.4 | 2.04 | 398 | zitadel | ✗ invalid |
| oauth2_password_login | p2 | authentik | 1 | 28.5% | 31277.5 | 43472.6 | 50303.5 | 4.17 | 1298 | authentik-postgres | ✗ invalid, protocol-variant, protocol-variant |
| oauth2_password_login | p3 | axiam | 49 | 0.8% | 999.5 | 1040.2 | 1051.6 | 2.67 | 389 | none | ✓ |
| oauth2_password_login | p3 | keycloak | 46 | 6.7% | 1029.2 | 1185.3 | 1293.0 | 2.07 | 853 | keycloak | ✓ |
| oauth2_password_login | p3 | zitadel | 2 | 1.2% | 29339.2 | 33680.4 | 35659.6 | 2.04 | 399 | zitadel | ✗ invalid |
| token_introspection | p0 | axiam | 1582 | 0.6% | 15.2 | 69.4 | 73.9 | 2.94 | 414 | axiam-surrealdb | ✓ |
| token_introspection | p0 | keycloak | 1940 | 3.2% | 5.4 | 85.1 | 88.6 | 2.51 | 1107 | keycloak | ✓ |
| token_introspection | p0 | zitadel | 827 | 1.9% | 53.6 | 75.9 | 83.6 | 3.90 | 399 | zitadel,zitadel-postgres | ✓ |
| token_introspection | p0 | authentik | 19 | 14.0% | 2505.2 | 3483.4 | 3851.3 | 2.73 | 1258 | authentik-postgres | ✗ invalid |
| token_introspection | p2 | axiam | 1560 | 2.7% | 15.4 | 69.7 | 74.2 | 2.95 | 415 | axiam-surrealdb | ✓ |
| token_introspection | p2 | keycloak | 1814 | 3.2% | 5.9 | 85.7 | 89.5 | 2.49 | 1034 | keycloak | ✓ |
| token_introspection | p2 | zitadel | 824 | 1.6% | 55.0 | 77.5 | 85.8 | 3.93 | 406 | zitadel,zitadel-postgres | ✓ |
| token_introspection | p2 | authentik | 19 | 24.0% | 2499.7 | 3462.9 | 3892.5 | 2.82 | 1271 | authentik-postgres | ✗ invalid |
| token_introspection | p3 | axiam | 1588 | 0.6% | 15.1 | 69.2 | 73.7 | 2.98 | 415 | axiam-surrealdb | ✓ |
| token_introspection | p3 | keycloak | 1749 | 4.3% | 6.1 | 86.3 | 90.2 | 2.49 | 973 | keycloak | ✓ |
| token_introspection | p3 | zitadel | 817 | 3.1% | 55.1 | 77.0 | 85.6 | 3.95 | 407 | zitadel,zitadel-postgres | ✓ |
| token_refresh | p0 | axiam | 347 | 0.3% | 115.8 | 191.8 | 207.3 | 2.51 | 397 | axiam-surrealdb | ✓, protocol-variant, protocol-variant |
| token_refresh | p0 | keycloak | 435 | 2.9% | 98.2 | 201.4 | 296.5 | 2.07 | 1046 | keycloak | ✓, protocol-variant, protocol-variant |
| token_refresh | p0 | zitadel | 1 | 0.6% | 5648.8 | 9411.8 | 9965.9 | 2.06 | 400 | zitadel | ✗ invalid, fallback-op+protocol-variant, fallback-op |
| token_refresh | p0 | authentik | 3 | 20.1% | 9839.9 | 37470.5 | 59235.5 | 4.01 | 1290 | none | ✗ invalid, fallback-op+protocol-variant, fallback-op |
| token_refresh | p2 | axiam | 348 | 2.5% | 115.7 | 192.0 | 208.4 | 2.52 | 394 | axiam-surrealdb | ✓, protocol-variant, protocol-variant |
| token_refresh | p2 | keycloak | 447 | 1.0% | 97.9 | 199.0 | 292.4 | 2.08 | 1047 | keycloak | ✓, protocol-variant, protocol-variant |
| token_refresh | p2 | zitadel | 1 | 0.3% | 6250.0 | 8846.2 | 9336.0 | 2.06 | 406 | zitadel | ✗ invalid, fallback-op+protocol-variant, fallback-op |
| token_refresh | p2 | authentik | 2 | 13.7% | 10068.8 | 41873.2 | 57036.5 | 3.88 | 1290 | none | ✗ invalid, fallback-op+protocol-variant, fallback-op |
| token_refresh | p3 | axiam | 340 | 0.2% | 116.8 | 193.4 | 210.0 | 2.51 | 401 | axiam-surrealdb | ✓, protocol-variant, protocol-variant |
| token_refresh | p3 | keycloak | 427 | 1.5% | 98.8 | 200.5 | 295.2 | 2.07 | 985 | keycloak | ✓, protocol-variant, protocol-variant |
| token_refresh | p3 | zitadel | 1 | 0.2% | 6406.5 | 9407.2 | 9996.8 | 2.06 | 408 | zitadel | ✗ invalid, fallback-op+protocol-variant, fallback-op |
| userinfo | p0 | axiam | 1411 | 1.6% | 17.4 | 71.9 | 76.4 | 2.83 | 398 | axiam-surrealdb | ✓ |
| userinfo | p0 | keycloak | 3862 | 0.6% | 2.4 | 80.4 | 83.6 | 2.02 | 1047 | keycloak | ✓ |
| userinfo | p0 | zitadel | 859 | 1.6% | 51.9 | 85.9 | 92.3 | 2.94 | 402 | zitadel-postgres | ✓, cc-token-setup |
| userinfo | p0 | authentik | 20 | 2.4% | 2343.3 | 3022.4 | 3289.6 | 3.08 | 1229 | authentik-postgres | ✗ invalid |
| userinfo | p2 | axiam | 1425 | 0.3% | 17.2 | 71.7 | 76.0 | 2.91 | 401 | axiam-surrealdb | ✓ |
| userinfo | p2 | keycloak | 3505 | 3.1% | 2.6 | 81.3 | 84.4 | 2.02 | 1046 | keycloak | ✓ |
| userinfo | p2 | zitadel | 845 | 1.6% | 53.1 | 86.4 | 94.1 | 3.02 | 412 | zitadel-postgres | ✓, cc-token-setup |
| userinfo | p2 | authentik | 20 | 0.8% | 2389.5 | 3030.0 | 3303.3 | 3.13 | 1249 | authentik-postgres | ✗ invalid |
| userinfo | p3 | axiam | 1419 | 0.2% | 17.3 | 71.7 | 76.0 | 2.87 | 399 | axiam-surrealdb | ✓ |
| userinfo | p3 | keycloak | 3471 | 3.2% | 2.6 | 81.1 | 84.5 | 2.02 | 956 | keycloak | ✓ |
| userinfo | p3 | zitadel | 851 | 3.3% | 51.6 | 86.3 | 94.1 | 3.03 | 410 | zitadel-postgres | ✓, cc-token-setup |
| userinfo_grpc | p0 | axiam | 3078 | 4.1% | 7.0 | 59.0 | 63.0 | 3.11 | 407 | axiam-surrealdb | ✓ |
| userinfo_grpc | p2 | axiam | 3076 | 3.9% | 7.0 | 59.0 | 63.0 | 3.10 | 408 | axiam-surrealdb | ✓ |
| userinfo_grpc | p3 | axiam | 3066 | 1.6% | 8.0 | 59.0 | 63.0 | 3.14 | 406 | axiam-surrealdb | ✓ |
| zitadel_userinfo_grpc | p0 | zitadel | 245 | 1.5% | 200.0 | 203.0 | 227.0 | 1.94 | 404 | none | ✓, cc-token-setup |
| zitadel_userinfo_grpc | p2 | zitadel | 241 | 2.6% | 200.0 | 229.0 | 248.0 | 1.92 | 412 | none | ✓, cc-token-setup |
| zitadel_userinfo_grpc | p3 | zitadel | 240 | 4.6% | 200.0 | 227.0 | 244.0 | 1.85 | 410 | none | ✓, cc-token-setup |

### 10.2 Run 6b pass A — AXIAM 1.3.1 control, SurrealDB 4.0.1, 2/2, p0

| scenario | profile | target | thr (req/s) | ± | p50 (ms) | p95 (ms) | p99 (ms) | cpu | mem | bottleneck | valid / label |
|---|---|---|---|---|---|---|---|---|---|---|---|
| authz_batch_grpc | p0 | axiam | 577 | 1.2% | 88.0 | 106.0 | 156.0 | 2.69 | 378 | axiam-surrealdb | ✓ |
| authz_batch_rest | p0 | axiam | 445 | 2.8% | 100.6 | 165.0 | 177.6 | 2.74 | 290 | axiam-surrealdb | ✓ |
| authz_check_grpc | p0 | axiam | 572 | 1.6% | 88.0 | 106.0 | 156.0 | 2.69 | 293 | axiam-surrealdb | ✓ |
| authz_check_rest | p0 | axiam | 451 | 1.9% | 100.2 | 163.8 | 176.8 | 2.69 | 302 | axiam-surrealdb | ✓ |
| jwks_fetch | p0 | axiam | 41523 | 0.5% | 0.8 | 1.9 | 2.7 | 2.18 | 312 | none | ✓ |
| oauth2_client_credentials | p0 | axiam | 1448 | 1.6% | 16.6 | 71.4 | 76.2 | 3.02 | 365 | axiam-surrealdb | ✓ |
| oauth2_password_login | p0 | axiam | 46 | 0.8% | 1053.3 | 1128.4 | 1159.1 | 2.73 | 384 | none | ✓ |
| token_introspection | p0 | axiam | 1438 | 3.3% | 16.8 | 71.9 | 76.8 | 2.95 | 405 | axiam-surrealdb | ✓ |
| token_refresh | p0 | axiam | 305 | 3.7% | 129.6 | 210.2 | 277.2 | 2.54 | 419 | axiam-surrealdb | ✓, protocol-variant, protocol-variant |
| userinfo | p0 | axiam | 1320 | 2.7% | 18.7 | 73.8 | 78.7 | 2.87 | 374 | axiam-surrealdb | ✓ |
| userinfo_grpc | p0 | axiam | 2795 | 1.8% | 8.0 | 61.0 | 64.0 | 3.08 | 381 | axiam-surrealdb | ✓ |

### 10.3 Run 6b pass B — all targets, 4/4, p0

| scenario | profile | target | thr (req/s) | ± | p50 (ms) | p95 (ms) | p99 (ms) | cpu | mem | bottleneck | valid / label |
|---|---|---|---|---|---|---|---|---|---|---|---|
| authz_batch_grpc | p0 | axiam | 1229 | 5.3% | 37.0 | 52.0 | 59.0 | 5.23 | 457 | axiam-surrealdb | ✓ |
| authz_batch_rest | p0 | axiam | 974 | 7.5% | 46.6 | 62.6 | 70.2 | 5.40 | 335 | axiam-surrealdb | ✓ |
| authz_check_grpc | p0 | axiam | 1320 | 3.9% | 34.0 | 48.0 | 54.0 | 5.25 | 339 | axiam-surrealdb | ✓ |
| authz_check_rest | p0 | axiam | 1007 | 3.1% | 45.0 | 60.2 | 67.2 | 5.30 | 357 | axiam-surrealdb | ✓ |
| jwks_fetch | p0 | axiam | 43232 | 8.2% | 0.8 | 1.9 | 2.7 | 2.37 | 370 | none | ✓, generator_saturated |
| jwks_fetch | p0 | keycloak | 10832 | 2.2% | 1.9 | 5.6 | 49.7 | 4.06 | 1268 | keycloak | ✓ |
| jwks_fetch | p0 | zitadel | 3953 | 1.5% | 8.5 | 36.8 | 40.1 | 6.36 | 359 | zitadel-postgres | ✓ |
| jwks_fetch | p0 | authentik | 45 | 0.0% | 1041.7 | 1528.7 | 1868.5 | 4.75 | 1231 | none | ✗ invalid |
| oauth2_client_credentials | p0 | axiam | 3234 | 1.6% | 13.7 | 19.9 | 23.2 | 6.13 | 432 | axiam-surrealdb | ✓ |
| oauth2_client_credentials | p0 | keycloak | 934 | 3.5% | 20.8 | 96.9 | 108.1 | 4.32 | 1254 | keycloak | ✓ |
| oauth2_client_credentials | p0 | zitadel | 704 | 2.6% | 65.3 | 79.1 | 95.4 | 7.04 | 424 | none | ✓ |
| oauth2_client_credentials | p0 | authentik | 4 | 18.5% | 6766.9 | 32616.0 | 44174.1 | 4.07 | 1319 | none | ✗ invalid |
| oauth2_password_login | p0 | axiam | 93 | 1.6% | 523.6 | 561.7 | 575.2 | 5.17 | 500 | none | ✓ |
| oauth2_password_login | p0 | keycloak | 98 | 4.3% | 473.2 | 586.3 | 633.9 | 4.15 | 1222 | keycloak | ✓ |
| oauth2_password_login | p0 | zitadel | 3 | 1.5% | 15067.6 | 16803.9 | 17555.0 | 4.06 | 530 | zitadel | ✗ invalid |
| oauth2_password_login | p0 | authentik | 1 | 22.3% | 29557.5 | 66803.4 | 67913.3 | 4.11 | 1243 | none | ✗ invalid, protocol-variant, protocol-variant |
| token_introspection | p0 | axiam | 3272 | 1.9% | 13.5 | 19.7 | 22.8 | 6.01 | 511 | axiam-surrealdb | ✓ |
| token_introspection | p0 | keycloak | 3952 | 1.8% | 4.9 | 57.5 | 62.6 | 5.07 | 1268 | keycloak | ✓ |
| token_introspection | p0 | zitadel | 1522 | 2.1% | 30.4 | 39.8 | 43.0 | 7.33 | 518 | none | ✓ |
| token_introspection | p0 | authentik | 36 | 0.0% | 1248.5 | 1754.8 | 2342.0 | 5.37 | 1259 | authentik-postgres | ✗ invalid |
| token_refresh | p0 | axiam | 707 | 3.3% | 61.9 | 88.7 | 105.3 | 4.87 | 459 | axiam-surrealdb | ✓, protocol-variant, protocol-variant |
| token_refresh | p0 | keycloak | 943 | 0.7% | 18.0 | 100.4 | 177.3 | 4.09 | 1330 | keycloak | ✓, protocol-variant, protocol-variant |
| token_refresh | p0 | zitadel | 3 | 1.7% | 2183.9 | 4522.4 | 5350.8 | 4.11 | 527 | zitadel | ✗ invalid, fallback-op+protocol-variant, fallback-op |
| token_refresh | p0 | authentik | 3 | 8.7% | 9642.7 | 36407.6 | 54499.9 | 4.40 | 1311 | none | ✗ invalid, fallback-op+protocol-variant, fallback-op |
| userinfo | p0 | axiam | 2963 | 0.1% | 15.1 | 21.5 | 24.7 | 5.79 | 455 | axiam-surrealdb | ✓ |
| userinfo | p0 | keycloak | 7807 | 2.0% | 2.3 | 51.2 | 59.0 | 4.05 | 1353 | keycloak | ✓ |
| userinfo | p0 | zitadel | 1677 | 5.9% | 19.4 | 54.4 | 57.0 | 6.25 | 521 | zitadel-postgres | ✓, cc-token-setup |
| userinfo | p0 | authentik | 30 | 1.3% | 1706.0 | 2465.7 | 2880.4 | 5.60 | 1171 | none | ✗ invalid |
| userinfo_grpc | p0 | axiam | 6369 | 1.2% | 7.0 | 11.0 | 13.0 | 6.25 | 459 | axiam-surrealdb | ✓ |
| zitadel_userinfo_grpc | p0 | zitadel | 226 | 2.3% | 200.0 | 270.0 | 288.0 | 2.29 | 524 | none | ✓, cc-token-setup |

### 10.4 Run 6c pass A — AXIAM 1.3.1, SurrealDB 3.3.5 (unsupported, benchmark-only), 2/2, all profiles

| scenario | profile | target | thr (req/s) | ± | p50 (ms) | p95 (ms) | p99 (ms) | cpu | mem | bottleneck | valid / label |
|---|---|---|---|---|---|---|---|---|---|---|---|
| authz_batch_grpc | p0 | axiam | 679 | 10.4% | 79.0 | 99.0 | 106.0 | 2.79 | 270 | axiam-surrealdb | ✓ |
| authz_batch_grpc | p2 | axiam | 691 | 14.3% | 79.0 | 98.0 | 105.0 | 2.75 | 257 | axiam-surrealdb | ✓ |
| authz_batch_grpc | p3 | axiam | 688 | 15.8% | 79.0 | 99.0 | 106.0 | 2.75 | 269 | axiam-surrealdb | ✓ |
| authz_batch_rest | p0 | axiam | 716 | 9.6% | 77.0 | 96.9 | 104.5 | 2.92 | 230 | axiam-surrealdb | ✓ |
| authz_batch_rest | p2 | axiam | 748 | 14.7% | 74.9 | 93.3 | 99.5 | 2.99 | 236 | axiam-surrealdb | ✓ |
| authz_batch_rest | p3 | axiam | 728 | 12.9% | 76.1 | 95.0 | 101.6 | 3.02 | 238 | axiam-surrealdb | ✓ |
| authz_check_grpc | p0 | axiam | 914 | 0.7% | 33.0 | 86.0 | 92.0 | 2.82 | 236 | axiam-surrealdb | ✓ |
| authz_check_grpc | p2 | axiam | 903 | 2.8% | 34.0 | 86.0 | 92.0 | 2.84 | 242 | axiam-surrealdb | ✓ |
| authz_check_grpc | p3 | axiam | 867 | 3.1% | 58.0 | 88.0 | 94.0 | 2.85 | 244 | axiam-surrealdb | ✓ |
| authz_check_rest | p0 | axiam | 714 | 0.7% | 77.3 | 94.8 | 101.0 | 2.95 | 249 | axiam-surrealdb | ✓ |
| authz_check_rest | p2 | axiam | 740 | 2.1% | 75.4 | 93.8 | 100.1 | 2.97 | 251 | axiam-surrealdb | ✓ |
| authz_check_rest | p3 | axiam | 733 | 2.0% | 75.8 | 93.7 | 99.6 | 2.93 | 249 | axiam-surrealdb | ✓ |
| jwks_fetch | p0 | axiam | 40430 | 2.7% | 0.8 | 2.0 | 2.8 | 1.83 | 274 | none | ✓ |
| jwks_fetch | p2 | axiam | 35535 | 1.6% | 1.0 | 2.2 | 3.0 | 2.08 | 271 | none | ✓ |
| jwks_fetch | p3 | axiam | 34281 | 0.8% | 1.0 | 2.3 | 3.1 | 2.08 | 278 | none | ✓ |
| oauth2_client_credentials | p0 | axiam | 1970 | 0.3% | 12.0 | 65.7 | 70.5 | 3.22 | 308 | axiam-surrealdb | ✓ |
| oauth2_client_credentials | p2 | axiam | 1923 | 1.6% | 12.3 | 66.2 | 71.0 | 3.29 | 310 | axiam-surrealdb | ✓ |
| oauth2_client_credentials | p3 | axiam | 1922 | 0.8% | 12.3 | 65.9 | 70.9 | 3.44 | 307 | axiam-surrealdb | ✓ |
| oauth2_password_login | p0 | axiam | 47 | 2.6% | 1033.7 | 1117.3 | 1154.2 | 2.50 | 334 | none | ✓ |
| oauth2_password_login | p2 | axiam | 47 | 1.1% | 1031.3 | 1108.1 | 1140.9 | 2.44 | 336 | none | ✓ |
| oauth2_password_login | p3 | axiam | 47 | 1.0% | 1033.7 | 1110.9 | 1148.5 | 2.46 | 342 | none | ✓ |
| token_introspection | p0 | axiam | 1661 | 7.9% | 14.3 | 69.3 | 74.4 | 3.16 | 248 | axiam-surrealdb | ✓ |
| token_introspection | p2 | axiam | 1758 | 3.6% | 13.6 | 67.9 | 73.0 | 3.21 | 252 | axiam-surrealdb | ✓ |
| token_introspection | p3 | axiam | 1658 | 7.6% | 14.2 | 68.9 | 73.9 | 3.18 | 255 | axiam-surrealdb | ✓ |
| token_refresh | p0 | axiam | 450 | 1.6% | 98.9 | 162.2 | 180.3 | 2.64 | 324 | axiam-surrealdb | ✓, protocol-variant, protocol-variant |
| token_refresh | p2 | axiam | 436 | 1.4% | 100.3 | 166.1 | 184.3 | 2.66 | 324 | axiam-surrealdb | ✓, protocol-variant, protocol-variant |
| token_refresh | p3 | axiam | 445 | 1.9% | 98.8 | 164.8 | 185.9 | 2.62 | 327 | axiam-surrealdb | ✓, protocol-variant, protocol-variant |
| userinfo | p0 | axiam | 2081 | 2.0% | 11.2 | 65.1 | 70.0 | 3.27 | 261 | axiam-surrealdb | ✓ |
| userinfo | p2 | axiam | 2058 | 2.2% | 11.3 | 65.2 | 70.0 | 3.31 | 257 | axiam-surrealdb | ✓ |
| userinfo | p3 | axiam | 2030 | 1.7% | 11.5 | 65.3 | 70.1 | 3.30 | 258 | axiam-surrealdb | ✓ |
| userinfo_grpc | p0 | axiam | 4026 | 1.2% | 6.0 | 54.0 | 59.0 | 3.36 | 272 | axiam-surrealdb | ✓ |
| userinfo_grpc | p2 | axiam | 4000 | 2.0% | 6.0 | 53.0 | 58.0 | 3.40 | 272 | axiam-surrealdb | ✓ |
| userinfo_grpc | p3 | axiam | 4072 | 0.9% | 6.0 | 53.0 | 58.0 | 3.41 | 267 | axiam-surrealdb | ✓ |

### 10.5 Run 6c pass B — AXIAM 1.3.1, SurrealDB 3.3.5 (unsupported, benchmark-only), 4/4, all profiles

| scenario | profile | target | thr (req/s) | ± | p50 (ms) | p95 (ms) | p99 (ms) | cpu | mem | bottleneck | valid / label |
|---|---|---|---|---|---|---|---|---|---|---|---|
| authz_batch_grpc | p0 | axiam | 1540 | 12.1% | 29.0 | 42.0 | 48.0 | 5.50 | 311 | axiam-surrealdb | ✓ |
| authz_batch_grpc | p2 | axiam | 1557 | 9.8% | 29.0 | 42.0 | 48.0 | 5.56 | 329 | axiam-surrealdb | ✓ |
| authz_batch_grpc | p3 | axiam | 1535 | 14.6% | 29.0 | 42.0 | 47.0 | 5.50 | 316 | axiam-surrealdb | ✓ |
| authz_batch_rest | p0 | axiam | 1556 | 10.6% | 29.0 | 40.7 | 46.2 | 5.82 | 276 | axiam-surrealdb | ✓ |
| authz_batch_rest | p2 | axiam | 1520 | 9.7% | 29.7 | 43.0 | 49.3 | 5.86 | 280 | axiam-surrealdb | ✓ |
| authz_batch_rest | p3 | axiam | 1615 | 9.8% | 28.0 | 39.3 | 44.4 | 5.85 | 280 | axiam-surrealdb | ✓ |
| authz_check_grpc | p0 | axiam | 1955 | 1.6% | 23.0 | 33.0 | 37.0 | 5.68 | 291 | axiam-surrealdb | ✓ |
| authz_check_grpc | p2 | axiam | 1944 | 3.8% | 23.0 | 33.0 | 38.0 | 5.75 | 293 | axiam-surrealdb | ✓ |
| authz_check_grpc | p3 | axiam | 1975 | 1.6% | 23.0 | 33.0 | 38.0 | 5.73 | 295 | axiam-surrealdb | ✓ |
| authz_check_rest | p0 | axiam | 1593 | 4.1% | 28.4 | 40.1 | 45.6 | 5.83 | 307 | axiam-surrealdb | ✓ |
| authz_check_rest | p2 | axiam | 1569 | 1.3% | 28.5 | 39.8 | 45.2 | 5.85 | 309 | axiam-surrealdb | ✓ |
| authz_check_rest | p3 | axiam | 1609 | 1.4% | 28.1 | 39.4 | 44.6 | 5.84 | 308 | axiam-surrealdb | ✓ |
| jwks_fetch | p0 | axiam | 41737 | 1.5% | 0.8 | 1.9 | 2.7 | 2.04 | 338 | none | ✓, generator_saturated |
| jwks_fetch | p2 | axiam | 36672 | 2.2% | 1.0 | 2.2 | 2.9 | 2.42 | 336 | none | ✓, generator_saturated |
| jwks_fetch | p3 | axiam | 36159 | 2.2% | 1.0 | 2.2 | 3.0 | 2.46 | 337 | none | ✓, generator_saturated |
| oauth2_client_credentials | p0 | axiam | 3853 | 3.3% | 11.3 | 17.6 | 20.8 | 6.42 | 320 | axiam-surrealdb | ✓ |
| oauth2_client_credentials | p2 | axiam | 3895 | 2.8% | 11.2 | 17.4 | 20.5 | 6.60 | 313 | axiam-surrealdb | ✓ |
| oauth2_client_credentials | p3 | axiam | 3748 | 5.6% | 11.6 | 17.7 | 20.8 | 6.74 | 312 | axiam-surrealdb | ✓ |
| oauth2_password_login | p0 | axiam | 89 | 1.5% | 545.6 | 572.0 | 593.7 | 4.65 | 342 | none | ✓ |
| oauth2_password_login | p2 | axiam | 88 | 1.0% | 547.7 | 595.4 | 614.3 | 4.56 | 343 | none | ✓ |
| oauth2_password_login | p3 | axiam | 89 | 2.0% | 547.5 | 582.1 | 625.9 | 4.56 | 344 | none | ✓ |
| token_introspection | p0 | axiam | 3609 | 1.4% | 12.2 | 18.6 | 21.8 | 6.27 | 359 | axiam-surrealdb | ✓ |
| token_introspection | p2 | axiam | 3682 | 1.0% | 11.9 | 18.2 | 21.2 | 6.36 | 360 | axiam-surrealdb | ✓ |
| token_introspection | p3 | axiam | 3628 | 0.9% | 12.0 | 18.4 | 21.4 | 6.42 | 357 | axiam-surrealdb | ✓ |
| token_refresh | p0 | axiam | 771 | 5.5% | 54.5 | 82.9 | 101.3 | 4.67 | 365 | none | ✓, protocol-variant, protocol-variant |
| token_refresh | p2 | axiam | 796 | 0.9% | 52.8 | 77.2 | 96.5 | 4.72 | 377 | none | ✓, protocol-variant, protocol-variant |
| token_refresh | p3 | axiam | 756 | 4.4% | 55.7 | 81.5 | 100.0 | 4.71 | 371 | none | ✓, protocol-variant, protocol-variant |
| userinfo | p0 | axiam | 4372 | 0.4% | 10.0 | 15.5 | 18.0 | 6.60 | 311 | axiam-surrealdb | ✓ |
| userinfo | p2 | axiam | 4402 | 1.8% | 9.9 | 15.4 | 18.0 | 6.62 | 320 | axiam-surrealdb | ✓ |
| userinfo | p3 | axiam | 4413 | 1.1% | 9.9 | 15.4 | 17.8 | 6.64 | 306 | axiam-surrealdb | ✓ |
| userinfo_grpc | p0 | axiam | 8743 | 0.5% | 5.0 | 8.0 | 10.0 | 7.00 | 315 | axiam-surrealdb | ✓ |
| userinfo_grpc | p2 | axiam | 8699 | 1.1% | 5.0 | 8.0 | 10.0 | 7.05 | 341 | axiam-surrealdb | ✓ |
| userinfo_grpc | p3 | axiam | 8753 | 1.0% | 5.0 | 8.0 | 10.0 | 7.09 | 313 | axiam-surrealdb | ✓ |


## 11. SDK client benchmarks — median-of-3, with a matched wire baseline (run 6)

All eleven SDKs (1.3.1) ran the same four operations against the same
seeded AXIAM (1.3.0 on SurrealDB 4.0.1, 2/2) at plaintext, three passes
each, medianed, with a k6 wire baseline at the same concurrency on the
same host (authorization-check p95 71.1 ms at 16 VUs). Every SDK ran all
three passes with zero errors. Concurrency-16 SDKs:

| sdk | login p50 (ms) | refresh p50 (ms) | check p50 (ms) | check p95 (ms) | check thr (rps) | check p95 overhead vs wire (ms) |
|---|---|---|---|---|---|---|
| cpp | 327.1 | 10.4 | 18.4 | 72.0 | 465 | +0.8 |
| go | 332.9 | 11.1 | 18.7 | 71.8 | 462 | +0.7 |
| java | 326.6 | 11.2 | 18.7 | 71.8 | 456 | +0.7 |
| kotlin | 324.6 | 10.5 | 18.9 | 71.9 | 453 | +0.7 |
| csharp | 336.0 | 12.1 | 19.4 | 73.3 | 436 | +2.2 |
| swift | 323.8 | 10.3 | 18.7 | 71.6 | 434 | **+0.5** |
| rust | 329.4 | 10.9 | 20.3 | 73.8 | 424 | +2.7 |
| typescript | 331.7 | 11.5 | 21.7 | 74.3 | 414 | +3.2 |
| python | 327.0 | 11.4 | 39.3 | 92.4 | 344 | +21.2 |

Serial harnesses, excluded from cross-SDK throughput comparison (one
worker by design; their login never queues behind other hashes): **C**
login 49.0 / refresh 11.5 / check 5.6 p50, 7.0 p95, 176 rps; **PHP** 52.8 /
10.4 / 6.6, 8.2, 150 rps.

Client-side footprint (median of three passes):

| sdk | runtime | client CPU (s, whole bench) | peak RSS (MiB) |
|---|---|---|---|
| c *(serial)* | gcc 13, C11 | **2.7** | **10** |
| cpp | g++ 13, C++17 | **3.0** | 15 |
| go | go 1.27 | 4.4 | 35 |
| swift | swift 6.4 | 7.9 | 54 |
| php *(serial)* | php 8.3 | 8.7 | 39 |
| csharp | .NET 10 | 13.9 | 91 |
| typescript | node 22 | 14.5 | 127 |
| kotlin | JVM 21 | 19.4 | 623 |
| rust | rustc 1.99 | 22.1 | 23 |
| java | JVM 21 | 24.0 | 335 |
| python | python 3.12, uvloop | 62.1 | 89 |

- **The server sets the floor**: login 324–336 ms p50 and refresh
  10.3–12.1 ms across the nine concurrent SDKs; check throughput is bounded
  by the same pegged SurrealDB as the matrix.
- **Hot-path overhead is under 3.5 ms at p95** for eight of nine
  concurrent SDKs (+0.5 to +3.2 ms).
- **Two run-5 flags are cleared**: C++'s reconnect-shaped tail is gone
  (p95 72.0 ms against a 71.1 ms baseline), and TypeScript's negative
  overhead is a coherent +3.2 ms.
- **Python remains the outlier** (check p50 39 ms, +21 ms p95) on uvloop
  with one worker thread; the gap belongs to the SDK/runtime.
- **Rust's client CPU (22 s) reads high** against its 23 MiB footprint
  and its latency, for the second run in a row; to be traced.
- Some login overheads read negative (down to −7.9 ms); login latency is
  queuing behind server-side hashing, so those deltas are noise and no
  login overhead is claimed.

## 12. Why build AXIAM at all?

A fair question given this field, and a sharper one after this round:
Keycloak is mature and ubiquitous, Zitadel is modern and well-engineered,
and on two cells of this draft Keycloak is simply faster. The answer,
from the measurements, with the cons attached:

**1. The server is efficient; the database tier is the work in front of
us.** Server-only, AXIAM spends the least CPU per request on every cell
— 0.44 cpu·ms per token against Keycloak's 4.89 and Zitadel's 4.61, 0.42
per introspection and per userinfo — and serves 43,640 JWKS reads/s from
a 54 MiB server. That is the floor Rust buys. Runs 6–6c also say plainly
that the stack is as fast as its slowest tier: SurrealDB 4.0.1 takes
13–38% of AXIAM's throughput, and the database work per request (§5) is
what Keycloak's in-memory design avoids. Both are now the measured
priority, with a ranked plan.

**2. Nobody else treats the machine/IoT edge as the main stage.**
Authorization decisions as a first-class, benchmarked hot path
(2,425–6,145 hierarchy-aware RBAC checks/s batched, cache off, at 2–4
database cores); a gRPC data plane that serves 12.6–28× Zitadel's gRPC
userinfo; and in-process mutual TLS at no measurable cost on
database-bound cells, which makes per-device client certificates the
cheap option for IoT fleets. If your workload is humans logging into web
apps, Keycloak serves you well today. If it is services and devices
asking "may I?" many times a second, that workload is what AXIAM is
shaped around.

**3. Security posture as defaults, and the costs it carries, measured.**
AXIAM re-reads the session and the user on every REST request so that a
revocation or a disabled account takes effect on the next call, writes an
audit row per request, and ships abuse rate limits on by default —
Argon2id, EdDSA short-lived tokens, single-use rotating refresh tokens,
append-only audit and encrypted-at-rest secrets are defaults, not
options. Part of the userinfo and introspection gap to Keycloak is that
posture's price, and §5 says how to lower it without giving the posture
up silently. The process is part of the posture too: this series has
found and published a synchronous rate-limit write, a ×60 limiter units
bug, a Nagle TLS cliff, two authorization table scans, and now a
datastore regression and a possible audit-shedding path — in public,
before each was understood.

**4. Deny-override RBAC and a real device flow.** An explicit deny grant
beats every allow, at any depth of the resource hierarchy; the OAuth2
Device Authorization Grant ships end to end for headless devices and
CLIs.

**And the honest cons, in the same breath.** AXIAM is young: a fraction of
Keycloak's protocol surface, extension ecosystem, hosting options and
community. In this draft Keycloak beats it on introspection and REST
userinfo throughput and on whole-stack CPU for both; AXIAM's full stack
carries SurrealDB and RabbitMQ, and by working set Zitadel's stack is
smaller at rest; SurrealDB is a decade younger than PostgreSQL, and its
4.0 line is the tier this round found regressed. Choosing AXIAM today
means choosing a young system whose server efficiency, machine-first
design and measurement culture you value over incumbent breadth — with
its database tier as the open item.

## 13. Summary and what happens next

**Strengths.** The first server-class, four-target, median-of-3 matrix:
token issuance **3.8–3.9×** Keycloak and Zitadel at 2 CPUs and
**3.5–4.6×** at 4; JWKS **7.9×/21×**; gRPC userinfo **12.6–28×**
Zitadel's; login on par with Keycloak; native mTLS at no measurable cost
on database-bound cells; a 54–75 MiB server under load against
708–941 MiB for Keycloak; the cheapest server-only CPU per request on
every cell; and an SDK fleet within +0.5 to +3.2 ms of the wire on eight
of nine concurrent clients.

**Weaknesses, as plainly.** Database-bound on every data cell; Keycloak
ahead on introspection and REST userinfo; SurrealDB 4.0.1 costing 13–38%;
an unexplained 5–12% between 1.3.0 and 1.3.1; a possible audit-shedding
path under load; the rate-limit enforcement failures of run 5 still
un-re-measured; no valid authentik cell.

**Next round**, in order:

1. Re-run the database-bound cells on this VM once surrealdb/surrealdb#7667
   is fixed in a SurrealDB release.
2. Capture the audit-loss counter per cell; batch the audit writes; re-run
   the REST cells (§5.2.1).
3. A database-side CPU profile of AXIAM's hot queries on 3.3.5 and 4.0.1 —
   names the read regression for upstream and sizes the single-round-trip
   rewrite (§5.2.2, §5.2.4).
4. A same-day 1.3.0 / 1.3.1 control with one competitor alongside.
5. A labelled cache-profile pass (session-validation, decision, client and
   tenant caches) with the revocation cell repeated, to put numbers on the
   posture trade-off (§5.2.3).
6. The deferred passes: production rate limits, minimal profile,
   new-feature cells, refresh stage timings, strict revocation.
7. The first `oauth2_refresh_grant` cells — the OAuth2 refresh grant, like
   for like with Keycloak — at 2/2 and 4/4.
8. Zitadel's non-CPU limit and 200 ms gRPC floor; a larger authentik
   envelope or an explanation.

---

## Appendix A. Carried forward from draft six (run 5, laptop) — not re-measured

These results come from run 5 (1.0.0-alpha24, SurrealDB 3, Dell XPS 15)
and are kept because later sections rely on them. None was re-measured
on the cloud VM.

**The three run-5 investigations, closed.**

- *The TLS plateau was Nagle's algorithm.* With `TCP_NODELAY=false`, TLS
  token issuance sat at 1,172 req/s on a flat 42.8 / 44.1 ms p50/p95
  plateau; with it on (the shipped default since), 2,642 req/s against a
  2,757 plaintext control. An in-namespace `ss -ti` capture showed 18 of
  20 connections frozen behind one unacked segment, waiting out the
  peer's 40 ms delayed-ACK timer.
- *The REST/gRPC authorization asymmetry was the session-revocation
  read.* The 2×2 (decision cache × session-validation cache, checks/s):
  both off REST 1,013 / gRPC 1,248; decision cache on REST 5,597 / gRPC
  11,122; both on REST **11,647** / gRPC 11,172. Revocation with caches on
  (TTL 5 s): through the API a deny was served **262 ms** after the call;
  by out-of-band database deletion, stale allows stopped at 5.2 s, inside
  the TTL-plus-slack bound. Part of gRPC's speed is that it does not
  re-check session revocation per call (`strict_revocation=false` by
  default); token expiry (15 min max) is its revocation bound.
- *The database ceiling.* Two full-table scans on the authorization read
  path were removed (CI now fails on any regression to a table scan);
  capped checks went 753 → 1,010–1,032/s, and the 2 → 4 database-core
  delta narrowed to +75–79%, reframing the ceiling as database
  concurrency rather than per-query waste. Run 6b's doubling (§3) is
  consistent with it.

**Minimal-profile resting footprint (T23.8.3, 2026-10-05, sandbox, native
server binary, SurrealDB 3.2.5).** Minimal (server + SurrealDB) **207.3
MiB** RSS; full (+ RabbitMQ) **330.9 MiB**; the broker is about 124 MiB,
37% of the full stack, at rest. Method and raw samples in
[`benchmarks/resting-footprint/`](resting-footprint/2026-10-05/). Not
comparable cell for cell with §7's container figures.

---
*Sources: run 6 (2026-11-20/21: median-of-3 capped matrix × p0/p2/p3 × four
targets, 66/84 valid; resting footprints of four stacks at two stages;
11-SDK median-of-3 pass with matched-VU wire baseline and client CPU/RSS),
run 6b (2026-11-21/22: AXIAM 1.3.1 control at 2/2, 11/11; all four targets
at 4/4, p0, 22/30) and run 6c (2026-11-23/24: AXIAM 1.3.1 on SurrealDB
3.3.5 at 2/2 and 4/4, p0/p2/p3, 66/66), all on one Infomaniak Public Cloud
`a16-ram64-disk80-perf1` instance (AMD EPYC Genoa, 16 vCPUs, 64 GiB);
per-cell k6 summaries, 1-second container and host telemetry, steal
sampled throughout, every image digest in every cell's metadata;
aggregated by `runner/report.py`. Execution runbook:
`claude_dev/bench-vm-runbook.md` §§9, 13, 14. Images: AXIAM 1.3.0
(`sha256:c0e3a2ec…`) and 1.3.1 (`sha256:ca4c5afd…`); SurrealDB 4.0.1
(`sha256:408eb8e5…`) and 3.3.5 (`sha256:3db515b8…`); Keycloak 26.8.1,
Zitadel v4.19.5, authentik 2026.8.5, PostgreSQL 16, RabbitMQ 4 — digests
in `results/provenance/images.txt`. Per-endpoint round-trip counts in §5.1
read from source at v1.3.1. Metric definitions:
[`docs/methodology.md`](docs/methodology.md).*
