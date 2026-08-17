#!/usr/bin/env python3
"""Aggregate raw benchmark outputs into a comparative Markdown report.

Walks results/<target>/<profile>/<scenario>.{meta.json,k6.json,res.csv,host.csv},
joins them, computes performance + resource + efficiency metrics, the
security-cost matrix, host-telemetry honesty flags, and validity gates (see
docs/methodology.md), then writes a report.

Stdlib only — no external dependencies.

Usage:
  report.py --results benchmarks/results [--out benchmarks/results/report.md]
            [--max-error 0.01] [--min-samples 10]
"""
import argparse
import csv
import json
import os
import re
import statistics
import sys
from collections import defaultdict


def pct(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * (p / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def median(values):
    """statistics.median with an empty-list guard (C1: median-of-N)."""
    return statistics.median(values) if values else 0.0


def dash(value, fmt):
    """Format `value` with `fmt`, or an em dash when `value` is None (used to
    blank throughput/latency columns on a 100%-error cell — A5.2)."""
    return "—" if value is None else format(value, fmt)


def is_full_outage(perf):
    """True when every iteration failed — throughput/latency then describe the
    failure path, not the operation being measured, so they get blanked to an
    em dash (A5.2, generalized here to gRPC — "Report labeling polish").

    Keys off the custom bench_* metrics (bench_error_rate / bench_ok /
    bench_failed) that every scenario emits uniformly for REST *and* gRPC
    alike (scenarios/lib/metrics.js) — never an HTTP-specific field like
    http_req_failed, which doesn't exist at all in a pure-gRPC scenario's k6
    summary (e.g. zitadel_userinfo_grpc, run 2: ~1725 "req/s" of throughput
    that was actually 100% non-OK gRPC statuses). The ok_count/failed_count
    check is a defensive fallback for the edge case where bench_error_rate
    itself is absent/zero (e.g. a very old summary predating that Rate
    metric) but the counters still show every iteration failed.
    """
    if perf["error_rate"] >= 1.0:
        return True
    return perf["failed_count"] > 0 and perf["ok_count"] == 0


def classify_fallback(fallback_count, iteration_count):
    """Distinguish the two situations `bench_fallback` (scenarios/lib/metrics.js)
    can signal (run-2 analysis, "Report labeling polish" — fold into A5 follow-up):

    - "fallback-op": a PER-ITERATION fallback — the cell measures the WRONG
      operation on (nearly) every iteration, e.g. token_refresh.js falling
      back to client_credentials issuance every time. fallback_count is on
      the order of the iteration count itself (run-2's numbers: AXIAM 145555,
      Keycloak 32566, Zitadel 34408 — each approx. equal to iterations). This
      class must stay excluded from head-to-head winner tables — it's a
      genuinely different (usually cheaper) operation than the label says.
    - "cc-token-setup": a SETUP-ONLY provenance note — the cell measures the
      RIGHT operation; only the *token's provenance* is a caveat, e.g.
      Zitadel's userinfo/userinfo-gRPC setup() minting a client-credentials
      token exactly once because a real user token wasn't obtainable.
      fallback_count is a tiny constant (typically 1) no matter how many
      thousands of iterations ran. This class is kept in comparisons.
    - "none": bench_fallback never fired for this cell.

    Threshold: fallback_count <= max(2, 1% of iterations) is "clearly a
    small, bounded, setup-time event" — comfortably above a stray
    single/double setup-fallback, comfortably below the ~100%-of-iterations
    rate every per-iteration fallback case observed so far actually has —
    so it's classified cc-token-setup. Anything above that line recurs on
    (nearly) every iteration, so it's fallback-op.
    """
    if fallback_count <= 0:
        return "none"
    threshold = max(2, 0.01 * iteration_count)
    return "cc-token-setup" if fallback_count <= threshold else "fallback-op"


# H6: decode `bench_http_proto` (scenarios/lib/metrics.js) back to a human
# label. The metric is a Trend of 10/11/20/30 (= HTTP/1.0, 1.1, 2.0, 3), so a
# cell whose min and max disagree ran over MORE THAN ONE protocol and must not
# be read as an h1 or an h2 cell at all.
PROTO_NAMES = {10: "1.0", 11: "1.1", 20: "2.0", 30: "3"}


def proto_label(perf):
    """Render one cell's negotiated-protocol column.

    "—"                 the scenario recorded no sample (pre-H6 results tree,
                        a gRPC scenario that still hand-rolls its metrics, or a
                        cell in which every request failed at the transport
                        level before any protocol was negotiated).
    "1.1" / "2.0"       every measured response used that protocol.
    "mixed(1.1,2.0)"    the cell is NOT a single-protocol cell — void as a
                        controlled h1-vs-h2 comparison.
    "?<n>"              k6 reported a protocol string this table doesn't know.
    """
    if not perf.get("proto_samples"):
        return "—"
    lo, hi = int(round(perf["proto_min"])), int(round(perf["proto_max"]))
    if lo == hi:
        return PROTO_NAMES.get(lo, f"?{lo}")
    return "mixed({},{})".format(PROTO_NAMES.get(lo, f"?{lo}"),
                                 PROTO_NAMES.get(hi, f"?{hi}"))


def load_k6_summary(path):
    """Extract throughput, latency percentiles, error rate from a k6 summary."""
    with open(path) as f:
        data = json.load(f)
    metrics = data.get("metrics", {})

    def trend(name, stat, dflt=0.0):
        m = metrics.get(name, {})
        # summary-export uses keys like "p(95)", "avg", "med"
        return float(m.get(stat, dflt) or 0.0)

    def counter_rate(name):
        m = metrics.get(name, {})
        return float(m.get("rate", 0.0) or 0.0)

    def counter_count(name):
        m = metrics.get(name, {})
        return float(m.get("count", 0.0) or 0.0)

    def rate_value(name):
        m = metrics.get(name, {})
        # Rate metric -> {"value": <fraction true>}
        return float(m.get("value", 0.0) or 0.0)

    throughput = counter_rate("bench_ok")
    # fall back to iteration rate if custom counter absent
    if throughput == 0.0:
        throughput = counter_rate("iterations")

    ok_count = counter_count("bench_ok")
    failed_count = counter_count("bench_failed")
    fallback_count = counter_count("bench_fallback")
    # Iterations the server rejected with 429 / RESOURCE_EXHAUSTED
    # (scenarios/lib/metrics.js's bench_throttled). Already counted inside
    # bench_failed — this is the *reason* breakdown, and it is what lets
    # expected_throttle() below tell "the limiter did its job" apart from "the
    # endpoint broke", which are indistinguishable in error_rate alone.
    throttled_count = counter_count("bench_throttled")
    # Iteration-count proxy for classify_fallback()'s heuristic: bench_ok +
    # bench_failed already accounts for every measured iteration for both
    # REST and gRPC scenarios alike (scenarios/lib/metrics.js), so reuse them
    # rather than depending on k6's own built-in "iterations" metric.
    iteration_count = ok_count + failed_count

    return {
        "throughput": throughput,
        "ok_count": ok_count,
        "failed_count": failed_count,
        "error_rate": rate_value("bench_error_rate"),
        "p50": trend("bench_op_latency_ms", "med"),
        "p95": trend("bench_op_latency_ms", "p(95)"),
        "p99": trend("bench_op_latency_ms", "p(99)"),
        "avg": trend("bench_op_latency_ms", "avg"),
        # A3: iterations that measured a fallback op (e.g. Zitadel login() ->
        # client_credentials, or a userinfo setup() that fell back) rather than
        # the labelled logical op.
        "fallback_count": fallback_count,
        "throttled_count": throttled_count,
        # Report labeling polish: which of the two very different situations
        # above this cell's bench_fallback count represents — see
        # classify_fallback().
        "fallback_class": classify_fallback(fallback_count, iteration_count),
        # D11: gRPC status Trend, present only when the scenario is a gRPC one
        # (scenarios/lib/metrics.js's bench_grpc_status). Absent entirely for
        # REST cells and for any results tree predating D11 — tolerated via
        # has_grpc_status rather than assumed present.
        "has_grpc_status": "bench_grpc_status" in metrics,
        "grpc_status_avg": trend("bench_grpc_status", "avg"),
        "grpc_status_max": trend("bench_grpc_status", "max"),
        # H6: negotiated wire protocol (scenarios/lib/metrics.js's
        # bench_http_proto). k6's summary export gives a Trend only its
        # statistics — there is no `count` key — so presence of the metric
        # itself is the "was anything recorded" flag. Absent for any results
        # tree predating H6, in which case proto_label() renders "—" rather
        # than claiming a protocol the run never measured.
        "proto_min": trend("bench_http_proto", "min"),
        "proto_max": trend("bench_http_proto", "max"),
        "proto_samples": 1.0 if "bench_http_proto" in metrics else 0.0,
    }


def load_resource_csv(path):
    """Sum per-timestamp across containers for the whole-stack aggregate, and
    keep per-container time-averages for bottleneck attribution (A5.3) and the
    server-container-only efficiency variant (A5.5)."""
    empty = {
        "cpu_cores_avg": 0.0, "cpu_cores_p95": 0.0,
        "mem_mib_avg": 0.0, "mem_mib_p95": 0.0, "samples": 0,
        "containers": {},
    }
    if not path or not os.path.exists(path):
        return empty
    by_ts_cpu = defaultdict(float)
    by_ts_mem = defaultdict(float)
    by_container_cpu = defaultdict(list)
    by_container_mem = defaultdict(list)
    with open(path) as f:
        for row in csv.DictReader(f):
            try:
                ts = row["epoch_ms"]
                cname = row["container"]
                cpu = float(row["cpu_cores"])
                mem = float(row["mem_mib"])
            except (ValueError, KeyError):
                continue
            by_ts_cpu[ts] += cpu
            by_ts_mem[ts] += mem
            by_container_cpu[cname].append(cpu)
            by_container_mem[cname].append(mem)
    cpu = list(by_ts_cpu.values())
    mem = list(by_ts_mem.values())
    containers = {}
    for cname, vals in by_container_cpu.items():
        mvals = by_container_mem.get(cname, [])
        containers[cname] = {
            "cpu_avg": statistics.fmean(vals) if vals else 0.0,
            "mem_avg": statistics.fmean(mvals) if mvals else 0.0,
        }
    return {
        "cpu_cores_avg": statistics.fmean(cpu) if cpu else 0.0,
        "cpu_cores_p95": pct(cpu, 95),
        "mem_mib_avg": statistics.fmean(mem) if mem else 0.0,
        "mem_mib_p95": pct(mem, 95),
        "samples": len(cpu),
        "containers": containers,
    }


def load_host_csv(path):
    """A6 host telemetry: CPU frequency, thermal, host utilization, k6 CPU
    headroom over the measure window. Missing/old cells (no host.csv) degrade
    to all-zero rather than crashing report generation (A4 tolerance)."""
    empty = {
        "mhz_avg": 0.0, "mhz_min": 0.0, "mhz_max": 0.0, "temp_max": 0.0,
        "host_cpu_util_avg": 0.0, "k6_cores_avg": 0.0, "samples": 0,
    }
    if not path or not os.path.exists(path):
        return empty
    mhz_avgs, mhz_mins, temps, utils, k6cores = [], [], [], [], []
    with open(path) as f:
        for row in csv.DictReader(f):
            try:
                mhz_avgs.append(float(row["cpu_mhz_avg"]))
                mhz_mins.append(float(row["cpu_mhz_min"]))
                temps.append(float(row["temp_c_max"]))
                utils.append(float(row["host_cpu_util_pct"]))
                k6cores.append(float(row["k6_cpu_cores"]))
            except (ValueError, KeyError):
                continue
    return {
        "mhz_avg": statistics.fmean(mhz_avgs) if mhz_avgs else 0.0,
        "mhz_min": min(mhz_mins) if mhz_mins else 0.0,
        # "the window's max" for the clock_variance rule is the max of the
        # per-sample mean-MHz-across-cores series (mirrors mhz_avg's series).
        "mhz_max": max(mhz_avgs) if mhz_avgs else 0.0,
        "temp_max": max(temps) if temps else 0.0,
        "host_cpu_util_avg": statistics.fmean(utils) if utils else 0.0,
        "k6_cores_avg": statistics.fmean(k6cores) if k6cores else 0.0,
        "samples": len(mhz_avgs),
    }


# Compose-file CPU cap defaults (targets/*/docker-compose.yml), used as a
# fallback when a container isn't listed in meta.json["containers"] (old
# results predating A4, or a container the sampler saw but run-benchmark.sh's
# containers_json() didn't — e.g. it exited between sampling and inspection).
def default_cpu_cap(container_name):
    if container_name.endswith("-surrealdb") or container_name.endswith("-postgres"):
        return 2.0  # BENCH_DB_CPUS
    if container_name.endswith("-rabbitmq"):
        return 1.0  # BENCH_MQ_CPUS
    if container_name.endswith("-tls"):
        return 1.0  # BENCH_EDGE_CPUS
    return 2.0  # BENCH_CPUS (the main server/app container)


# Same fallback, for mem (MiB) — used by the C2 DB-sensitivity appendix column
# below when a meta.json predates the "mem_cap_mib" field.
def default_mem_cap(container_name):
    if container_name.endswith("-surrealdb") or container_name.endswith("-postgres"):
        return 1024.0  # BENCH_DB_MEM
    if container_name.endswith("-rabbitmq"):
        return 512.0  # BENCH_MQ_MEM
    if container_name.endswith("-tls"):
        return 128.0  # BENCH_EDGE_MEM
    return 1024.0  # BENCH_MEM (the main server/app container)


def bottleneck(meta, res):
    """The container(s) whose average CPU >= 0.95x their configured cap, or
    'none'. Caps come from meta.json's "containers" (A4); fall back to the
    compose defaults above when meta predates that field or omits a
    container. (A5.3)"""
    containers_meta = {c.get("name"): c for c in (meta.get("containers") or [])}
    hot = []
    for cname, stats in (res.get("containers") or {}).items():
        cap = None
        cm = containers_meta.get(cname)
        if cm is not None and cm.get("cpu_cap") not in (None, ""):
            try:
                cap = float(cm["cpu_cap"])
            except (TypeError, ValueError):
                cap = None
        if cap is None:
            cap = default_cpu_cap(cname)
        if cap and stats.get("cpu_avg", 0.0) >= 0.95 * cap:
            hot.append(cname)
    return ",".join(sorted(hot)) if hot else "none"


# Primary app/server container per target (excludes db/mq/edge), used for the
# server-container-only efficiency variant (A5.5).
SERVER_CONTAINER = {
    "axiam": "bench-axiam-server",
    "keycloak": "bench-keycloak",
    "zitadel": "bench-zitadel",
}


# D4: scenarios with no genuine cross-vendor equivalent — either an AXIAM-only
# capability (gRPC authz) or a vendor-specific native-API scenario (Zitadel's
# gRPC identity RPC). Each of these is wired into exactly one target's
# scenario list in runner/run-benchmark.sh (AXIAM_ONLY_SCENARIOS /
# ZITADEL_ONLY_SCENARIOS), so a same-name cell from a second target never
# actually exists — the "Efficiency comparison (across targets)" loop below
# would already skip them via its `len(group_all) < 2` guard. This set makes
# that exclusion explicit/defensive (self-documenting, and robust to a future
# scenario coincidentally sharing a name across targets) rather than relying
# only on that structural accident. See docs/methodology.md §5 "Comparability:
# protocol-efficiency (gRPC vs REST, same vendor)".
NON_COMPARATIVE_SCENARIOS = {
    "authz_check_grpc", "authz_batch_grpc", "authz_check_rest", "authz_batch_rest",
    "zitadel_userinfo_grpc",
    # AXIAM's own gRPC identity RPC (axiam.v1.UserInfoService/GetUserInfo).
    # AXIAM-only (Keycloak has no gRPC userinfo), so it never forms a cross-vendor
    # cell; it does form an AXIAM within-vendor REST-vs-gRPC efficiency pair below.
    "userinfo_grpc",
}

# Within-vendor REST-vs-gRPC pairs for the same logical operation — the
# "protocol-efficiency" comparison docs/methodology.md describes, distinct
# from (and never merged into) the cross-vendor tables. Keyed by target;
# value is (rest_scenario, grpc_scenario, logical_op_label).
PROTOCOL_EFFICIENCY_PAIRS = {
    "axiam": [
        ("authz_check_rest", "authz_check_grpc", "authorization decision"),
        ("authz_batch_rest", "authz_batch_grpc", "batch authorization decision"),
        ("userinfo", "userinfo_grpc", "identity read (userinfo)"),
    ],
    "zitadel": [
        ("userinfo", "zitadel_userinfo_grpc", "identity read (userinfo)"),
    ],
}

# H7/G4 residual (claude_dev/refresh-harness-diagnosis.md §6): scenarios where
# every target's cell IS a real, non-fallback measurement of "renew an access
# credential without re-authenticating" at the PRODUCT level, but the targets
# do NOT all hit the same protocol-level operation — unlike fallback-op (a
# per-iteration accident, see classify_fallback()), this is a permanent,
# structural fact about the scenario itself, so it can't be derived from
# bench_fallback and is instead a static per-scenario label. Distinct from
# cc-token-setup (a one-time setup() provenance caveat) and from fallback-op
# (the wrong op measured, excluded from head-to-head tables): a
# protocol-variant cell measures the RIGHT (labelled) op for its own target,
# it's just not the SAME op as its row-mates, so it stays in the table
# (never excluded, like cc-token-setup) with a caveat naming the divergence.
PROTOCOL_VARIANT_SCENARIOS = {"token_refresh"}

# Per-scenario, per-target prose naming exactly what that target's cell
# measures, for the caveat rendered next to PROTOCOL_VARIANT_SCENARIOS rows.
# token_refresh: AXIAM deliberately ships no OAuth 2.1 ROPC/password grant
# (refresh-harness-diagnosis.md §6), so its refresh cell is a SESSION refresh
# (cookie + CSRF double-submit against axiam-auth's SessionRepository), while
# Keycloak's/Zitadel's is the OAuth2 refresh_token grant. Both renew an access
# credential without re-authenticating, so the row stays comparable at that
# level, but never at the protocol level.
PROTOCOL_VARIANT_NOTES = {
    "token_refresh": {
        "axiam": "session refresh (POST /api/v1/auth/refresh, cookie + CSRF "
                 "double-submit, axiam-auth SessionRepository — no OAuth2 "
                 "ROPC/password grant exists to seed an OAuth2 refresh token)",
        "keycloak": "OAuth2 refresh grant (grant_type=refresh_token against "
                    "the realm token endpoint)",
        "zitadel": "OAuth2 refresh grant (via a Session-API-v2-seeded login; "
                   "see the fallback flag if this cell also reads fallback-op)",
    },
}

# H10: which AXIAM scenarios can actually be affected by the settle gate's
# clamp. The settle gate (settle_gate() in run-benchmark.sh) runs ONCE per
# run-benchmark.sh invocation and stamps its settle_timeout verdict into
# EVERY cell of that session (methodology.md §12.1 — "the same value across
# every cell of one bench-run invocation, since the gate runs once per
# invocation"). That was the right design when the transient was believed to
# be a global post-seed effect. H2's investigation
# (claude_dev/postseed-transient-investigation.md §2) reframed it: the clamp
# is architecturally scoped to exactly six endpoints wrapped by
# `RateLimitShared` (POST /api/v1/authz/check, POST /oauth2/token,
# POST /oauth2/introspect, POST /oauth2/revoke, POST /api/v1/auth/login, and
# GET /api/v1/users — no scenario in this harness drives that last one).
# Blanket-refusing every cell in a clamped session — including jwks_fetch,
# userinfo, userinfo_grpc and token_refresh, none of which touch that
# middleware and none of which the H2 clamp map ever found slow — is a false
# positive the harness can now avoid, since which scenarios are affected is
# no longer a guess. Scenario -> wrapped-endpoint mapping: authz_check_rest/
# _grpc and authz_batch_rest/_grpc -> /api/v1/authz/check (batch coalesces
# into the same checked path); oauth2_client_credentials -> /oauth2/token;
# token_introspection -> /oauth2/introspect; oauth2_password_login ->
# /api/v1/auth/login. jwks_fetch (/oauth2/jwks), userinfo/userinfo_grpc
# (/oauth2/userinfo, unwrapped) and token_refresh (/api/v1/auth/refresh, not
# in the wrapped set per the H2 map) are deliberately absent — a
# settle_timeout in the same session must NOT refuse them.
CLAMP_SENSITIVE_SCENARIOS = {
    "authz_check_rest", "authz_check_grpc",
    "authz_batch_rest", "authz_batch_grpc",
    "oauth2_client_credentials", "token_introspection",
    "oauth2_password_login",
}


# Scenarios whose limiter family has a ceiling NO rate-limit posture can lift,
# so a closed-loop `ramping-vus` probe is throttled at every posture by
# construction. This set MUST stay identical to `EXPECTED_THROTTLE` in
# runner/run-benchmark.sh's dry_verdict() — that function is the source of
# truth and carries the full per-member justification. Summarised:
#
#   grpc_infra     `INFRA_PER_SEC = 100` (axiam-api-grpc/src/middleware/
#                  rate_limit.rs) is a hardcoded constant with NO env var.
#   device_verify  the knob exists, but `RateLimitConfig::validate` asserts the
#                  OWASP user-code bound and caps it at 2559/min; past that the
#                  server PANICS AT STARTUP rather than boot with a guessable
#                  user code.
#
# Why this is a *labeling* fix and not an exemption: these cells stay INVALID.
# Their throughput and latency describe the governor's reject path, not the
# endpoint, so admitting them to a median or a head-to-head table would be
# strictly worse than excluding them. What changes is the REASON. Before this,
# they were excluded as "error_rate 0.999 > 0.05" + "k6 threshold breach" —
# wording indistinguishable from a broken run, which repeatedly sent readers
# hunting for a fault that does not exist (it is the first thing anyone asks
# about after a run). Now they say so explicitly.
#
# Do NOT add a scenario here to quiet a 429 you could have neutralized: an
# un-neutralized family belongs in targets/axiam/docker-compose.yml's
# rate-limit block. The bar for membership is "no legal setting of any knob
# lets this scenario measure the endpoint".
EXPECTED_THROTTLE = {"grpc_infra", "device_verify"}


def expected_throttle(scenario, perf):
    """True when `scenario` is a structurally-unmeasurable limiter family AND
    this cell's failures actually are throttle rejections.

    The `throttled_count` half is load-bearing: membership alone would relabel
    a genuinely broken `grpc_infra` cell (connection refused, TLS failure, a
    setup() that threw — all of which produce failures with ZERO
    bench_throttled) as "expected", which is precisely the kind of silencing
    the run-benchmark.sh note warns against."""
    return scenario in EXPECTED_THROTTLE and perf.get("throttled_count", 0) > 0


def settle_timeout_applies(meta):
    """True only when settle_timeout:true AND this scenario is one the H2
    clamp map actually implicates (see CLAMP_SENSITIVE_SCENARIOS above).
    Non-AXIAM targets have no RateLimitShared-equivalent clamp documented,
    so this only ever suppresses the refusal for AXIAM scenarios outside the
    six-endpoint map; Keycloak/Zitadel cells are unaffected either way."""
    return bool(meta.get("settle_timeout")) and meta.get("scenario") in CLAMP_SENSITIVE_SCENARIOS


def derive(perf, res):
    thr = perf["throughput"]
    cpu = res["cpu_cores_avg"]
    mem_gib = res["mem_mib_avg"] / 1024.0
    return {
        "throughput_per_core": (thr / cpu) if cpu > 0 else 0.0,
        "throughput_per_gib": (thr / mem_gib) if mem_gib > 0 else 0.0,
        "cpu_ms_per_request": (cpu * 1000.0 / thr) if thr > 0 else 0.0,
    }


def derive_server_only(perf, res, target):
    """Same derived numbers as derive(), but scoped to just the server
    container's CPU/mem — so AXIAM's broker (RabbitMQ) + DB inclusion in the
    whole-stack numbers doesn't silently understate its per-request cost
    relative to a single-process competitor (A5.5)."""
    cname = SERVER_CONTAINER.get(target)
    stats = (res.get("containers") or {}).get(cname) if cname else None
    if not stats:
        return {"throughput_per_core": 0.0, "throughput_per_gib": 0.0, "cpu_ms_per_request": 0.0}
    server_res = {"cpu_cores_avg": stats.get("cpu_avg", 0.0), "mem_mib_avg": stats.get("mem_avg", 0.0)}
    return derive(perf, server_res)


def host_flags(meta, host):
    """A6: clock_variance (window mean MHz sagged >15% below the window max —
    i.e. the run was not at a flat sustained clock) and generator_saturated
    (k6 itself was eating too much of the host's non-stack CPU headroom to
    trust it as a clean load generator).

    G2/H1: settle_timeout — the post-seed settle gate (run-benchmark.sh's
    settle_gate(), a concurrent burst probe as of H1) hit its hard timeout
    without ever clearing BENCH_SETTLE_PROBE_THR ops/s (or
    BENCH_SETTLE_PROBE_P50_MS p50) under BENCH_SETTLE_BURST_VUS concurrency,
    so this cell may still be inside (or just leaving) the post-seed
    serialized-DB transient (PRIVATE_BENCH_ANALYSIS.md §1) even though the
    gate proceeded anyway. As of H1 this also makes the cell invalid (see
    collect_dir()/aggregate_cell()) — kept here too so it's visible directly
    in the "All results" table's host_flags column, not just the "Excluded"
    one. meta.get() defaults to falsy for any meta.json predating G2, so old
    trees render exactly as before (no flag)."""
    flags = []
    mhz_avg, mhz_max = host.get("mhz_avg", 0.0), host.get("mhz_max", 0.0)
    if mhz_max > 0 and mhz_avg < 0.85 * mhz_max:
        flags.append("clock_variance")
    if settle_timeout_applies(meta):
        flags.append("settle_timeout")

    containers = meta.get("containers") or []
    if containers:
        stack_cap_cpus = sum(float(c.get("cpu_cap", 0) or 0) for c in containers)
    else:
        try:
            stack_cap_cpus = float((meta.get("caps") or {}).get("cpus", 2))
        except (TypeError, ValueError):
            stack_cap_cpus = 2.0
    try:
        host_cpus = float((meta.get("host") or {}).get("cpus"))
    except (TypeError, ValueError):
        host_cpus = 0.0
    headroom = host_cpus - stack_cap_cpus
    if headroom > 0 and host.get("k6_cores_avg", 0.0) > 0.8 * headroom:
        flags.append("generator_saturated")
    return flags


def collect_dir(results_dir, max_error, min_samples):
    """Walk ONE flat results tree (results/<target>/<profile>/<scenario>.*) and
    return its raw (unaggregated) cells. This is the entire single-run
    collection logic from before C1 — unchanged — reused both for the classic
    single-run layout and, once per `results/run-<i>/` directory, by the C1
    median-of-N aggregator below."""
    cells = []
    for target in sorted(os.listdir(results_dir)):
        tdir = os.path.join(results_dir, target)
        if not os.path.isdir(tdir):
            continue
        for profile in sorted(os.listdir(tdir)):
            pdir = os.path.join(tdir, profile)
            if not os.path.isdir(pdir):
                continue
            for fn in sorted(os.listdir(pdir)):
                if not fn.endswith(".meta.json"):
                    continue
                meta = json.load(open(os.path.join(pdir, fn)))
                # Dry-run cells (run-benchmark.sh --dry-run / `just dry=1
                # bench-run`) rehearse the harness over a ~5-second window with
                # the post-seed settle gate deliberately skipped — a client
                # smoke test, never a measurement. They normally live under
                # results/dry-run/, one level deeper than this walk reaches, but
                # an operator who points BENCH_RESULTS_DIR at the shared tree
                # would otherwise have them silently medianed in with real
                # cells. The flag is authoritative; the directory is just the
                # default.
                if meta.get("dry_run"):
                    continue
                k6_name = meta.get("k6_summary_file")
                if not k6_name:
                    continue
                k6file = os.path.join(pdir, k6_name)
                if not os.path.exists(k6file):
                    continue
                perf = load_k6_summary(k6file)
                res_name = meta.get("resource_csv")
                res = load_resource_csv(os.path.join(pdir, res_name) if res_name else None)
                host_name = meta.get("host_csv")  # A6/A4: absent on pre-A6 meta
                host = load_host_csv(os.path.join(pdir, host_name) if host_name else None)
                der = derive(perf, res)
                der_server = derive_server_only(perf, res, meta.get("target", target))
                reasons = []
                is_expected_throttle = expected_throttle(meta["scenario"], perf)
                if is_expected_throttle:
                    # Still invalid — but say WHY honestly. The error_rate and
                    # k6-exit-code gates below would both fire here and both
                    # would describe a fault; this cell has none. See
                    # EXPECTED_THROTTLE's note.
                    reasons.append(
                        f"expected throttle: the {meta['scenario']} limiter family has a "
                        f"ceiling no rate-limit posture can lift, so this cell measures the "
                        f"governor's reject path, not the endpoint "
                        f"({perf['throttled_count']:.0f} throttled iterations). "
                        f"Not a fault — see EXPECTED_THROTTLE in runner/run-benchmark.sh")
                else:
                    if perf["error_rate"] > max_error:
                        reasons.append(f"error_rate {perf['error_rate']:.3f} > {max_error}")
                    if meta.get("k6_exit_code", 0) != 0:
                        reasons.append("k6 threshold breach")
                if res["samples"] < min_samples:
                    reasons.append(f"only {res['samples']} resource samples")
                # H1 item 5: settle_timeout:true means the post-seed settle
                # gate (run-benchmark.sh's settle_gate()) never cleared its
                # BENCH_SETTLE_PROBE_THR/BENCH_SETTLE_PROBE_P50_MS bar before
                # hitting BENCH_SETTLE_TIMEOUT_SECS — this cell may still be
                # inside (or just leaving) the post-seed clamp even though the
                # gate proceeded anyway. REFUSE it (excluded from `valid`,
                # same as any other invalid cell) rather than only flagging it
                # in host_flags — a contaminated cell silently entering a
                # median/head-to-head table is exactly the G run's
                # cross-cutting data-quality failure (PRIVATE_BENCH_ANALYSIS.md
                # §1) this task exists to stop repeating.
                if settle_timeout_applies(meta):
                    reasons.append("settle_timeout: true (post-seed settle gate hit its hard "
                                    "timeout — cell may still be inside the post-seed clamp)")
                cells.append({
                    "target": meta["target"], "profile": meta["profile"],
                    "scenario": meta["scenario"], "meta": meta,
                    "rate_limits": meta.get("rate_limits", "unknown"),
                    "perf": perf, "res": res, "der": der, "der_server": der_server,
                    "host": host, "host_flags": host_flags(meta, host),
                    "bottleneck": bottleneck(meta, res),
                    # Report labeling polish: only "fallback-op" (the cell
                    # measured the wrong op) is exclusion-worthy; "cc-token-setup"
                    # (right op, token-provenance caveat) stays comparable — see
                    # classify_fallback().
                    "is_fallback": perf["fallback_class"] == "fallback-op",
                    "valid": not reasons, "reasons": reasons,
                    "expected_throttle": is_expected_throttle,
                })
    return cells


# --- C1: median-of-N run aggregation ----------------------------------------
# `bench-matrix` (justfile) now runs the whole target×profile×scenario matrix
# `repeat` times (default 3), each pass writing into its own
# `results/run-<i>/<target>/<profile>/...` tree using the exact same flat
# per-cell layout `collect_dir` already understands. When one or more
# `results/run-*/` directories are present, aggregate each (target, profile,
# scenario) cell by taking the MEDIAN independently per metric across the
# valid runs, rather than reporting a single run's numbers. Results trees that
# predate this (no `run-*/` dirs — e.g. the existing 2026-07-19 tree) fall
# through to the old single-run behavior completely unchanged.
RUN_DIR_RE = re.compile(r"run-\d+")

# Fields medianed independently per the C1 spec ("throughput, p50/p95/p99,
# cpu, mem"), plus the other numeric perf/res/host fields for consistency.
PERF_MEDIAN_FIELDS = [
    "throughput", "ok_count", "failed_count", "error_rate",
    "p50", "p95", "p99", "avg", "fallback_count", "throttled_count",
    "grpc_status_avg", "grpc_status_max",
]
RES_MEDIAN_FIELDS = ["cpu_cores_avg", "cpu_cores_p95", "mem_mib_avg", "mem_mib_p95", "samples"]
HOST_MEDIAN_FIELDS = ["mhz_avg", "mhz_min", "mhz_max", "temp_max", "host_cpu_util_avg", "k6_cores_avg", "samples"]


def _median_of(dicts, fields):
    return {f: median([d.get(f, 0.0) for d in dicts]) for f in fields}


def _median_res(res_list):
    """Median the whole-stack res fields AND, per container, cpu_avg/mem_avg —
    so bottleneck() and the per-container appendix still work on aggregated
    cells exactly as they do on single-run ones."""
    agg = _median_of(res_list, RES_MEDIAN_FIELDS)
    names = set()
    for r in res_list:
        names.update((r.get("containers") or {}).keys())
    containers = {}
    for name in names:
        cpu_vals = [(r.get("containers") or {}).get(name, {}).get("cpu_avg", 0.0)
                    for r in res_list if name in (r.get("containers") or {})]
        mem_vals = [(r.get("containers") or {}).get(name, {}).get("mem_avg", 0.0)
                    for r in res_list if name in (r.get("containers") or {})]
        containers[name] = {"cpu_avg": median(cpu_vals), "mem_avg": median(mem_vals)}
    agg["containers"] = containers
    return agg


def aggregate_cell(runs):
    """Median-aggregate one (target, profile, scenario)'s per-run raw cells
    (as produced by collect_dir, one per results/run-<i>/) into a single cell
    with the same shape build_report expects, plus n_valid_runs/n_runs and the
    throughput min-max spread. A cell is only marked `valid` when >=2 of its
    runs were individually valid (C1) — with 0 or 1 valid runs there is no
    meaningful median, so it's reported (for visibility) but excluded from
    headline comparisons, same as any other invalid cell."""
    target, profile, scenario = runs[0]["target"], runs[0]["profile"], runs[0]["scenario"]
    valid_runs = [r for r in runs if r["valid"]]
    n_valid, n_total = len(valid_runs), len(runs)
    basis = valid_runs if valid_runs else runs

    perf = _median_of([r["perf"] for r in basis], PERF_MEDIAN_FIELDS)
    res = _median_res([r["res"] for r in basis])
    host = _median_of([r["host"] for r in basis], HOST_MEDIAN_FIELDS)

    # Report labeling polish: fallback_class/has_grpc_status aren't numeric,
    # so _median_of (PERF_MEDIAN_FIELDS) can't aggregate them — combine
    # across ALL raw runs (not just `basis`) the same way `is_fallback` used
    # to, below. fallback-op wins over cc-token-setup if the runs disagree
    # (shouldn't happen for a stable scenario, but fallback-op is the more
    # conservative/exclusion-worthy label).
    fb_classes = {r["perf"].get("fallback_class", "none") for r in runs}
    if "fallback-op" in fb_classes:
        perf["fallback_class"] = "fallback-op"
    elif "cc-token-setup" in fb_classes:
        perf["fallback_class"] = "cc-token-setup"
    else:
        perf["fallback_class"] = "none"
    perf["has_grpc_status"] = any(r["perf"].get("has_grpc_status") for r in basis)

    # H6: the protocol column must NOT be medianed — the question it answers is
    # "did every request in every run of this cell use one protocol?", so take
    # the min of mins and the max of maxes across the runs. If two runs of the
    # same cell negotiated different protocols (e.g. one run raced a
    # BENCH_NGINX_CONF change), the aggregated cell correctly reads "mixed".
    proto_runs = [r["perf"] for r in basis if r["perf"].get("proto_samples")]
    perf["proto_samples"] = 1.0 if proto_runs else 0.0
    perf["proto_min"] = min((p["proto_min"] for p in proto_runs), default=0.0)
    perf["proto_max"] = max((p["proto_max"] for p in proto_runs), default=0.0)

    thr_vals = [r["perf"]["throughput"] for r in basis]
    thr_median = perf["throughput"]
    thr_spread_pct = (((max(thr_vals) - min(thr_vals)) / 2.0) / thr_median * 100.0
                       if thr_vals and thr_median else 0.0)

    meta = dict(basis[0]["meta"])  # containers/caps/scenario_sha etc. are stable across runs
    # G2: settle_wait_secs/settle_timeout are NOT stable across runs by design
    # (cell-order rotation means this cell isn't the first cell — and doesn't
    # necessarily hit the same settle wait — in every repeat), so unlike the
    # rest of `meta` they're recombined across ALL raw runs rather than just
    # taken from basis[0]: the worst-case (max) wait, and timeout if ANY run's
    # gate hit its hard timeout. meta.get() on older per-run meta.json files
    # (predating G2) returns None/falsy, so this degrades to "no data" rather
    # than crashing on a mixed old/new results tree.
    settle_waits = [r["meta"].get("settle_wait_secs") for r in runs
                     if r["meta"].get("settle_wait_secs") is not None]
    if settle_waits:
        meta["settle_wait_secs"] = max(settle_waits)
    if any("settle_timeout" in r["meta"] for r in runs):
        meta["settle_timeout"] = any(r["meta"].get("settle_timeout") for r in runs)
    # axiam_env should be identical across runs of the same labeled pass (same
    # bench-up); basis[0] usually has it, but fall back to any run that does
    # (e.g. basis[0] happened to predate G2 while a later repeat didn't).
    if not meta.get("axiam_env"):
        for r in runs:
            if r["meta"].get("axiam_env"):
                meta["axiam_env"] = r["meta"]["axiam_env"]
                break
    der = derive(perf, res)
    der_server = derive_server_only(perf, res, target)

    reasons = []
    # An expected-throttle cell can never accumulate valid runs, so "only 0/3
    # valid run(s)" is a true but useless restatement of the same structural
    # fact. Lead with the fact itself; the run tally still shows in the
    # `runs(valid/n)` column either way.
    is_expected_throttle = any(r.get("expected_throttle") for r in runs)
    if is_expected_throttle:
        reasons.append(next(
            (r for run in runs for r in run["reasons"] if r.startswith("expected throttle")),
            f"expected throttle: {scenario} is a structurally-unmeasurable limiter family"))
    elif n_valid < 2:
        reasons.append(f"only {n_valid}/{n_total} valid run(s) (need >=2 for a median)")
        # When NO run was valid, "only 0/N valid" alone says a cell failed but
        # not how — the reader has to go open the raw run trees to find out,
        # which is exactly the detour that makes a real defect (e.g. a cell
        # returning 44% gRPC INTERNAL) look the same as a bookkeeping shortfall.
        # Carry the underlying per-run reasons up, deduplicated and order-stable.
        if n_valid == 0:
            seen = {}
            for run in runs:
                for r in run["reasons"]:
                    seen.setdefault(r, None)
            if seen:
                reasons.append("run reason(s): " + "; ".join(seen))
    # H1 item 5: same refusal as collect_dir() above, recombined across ALL
    # raw runs (not just `basis`) the same way settle_wait_secs/settle_timeout
    # themselves are recombined a few lines up — one run hitting the settle
    # timeout is enough to distrust the whole aggregated cell.
    if settle_timeout_applies(meta):
        reasons.append("settle_timeout: true on at least one run (post-seed settle gate hit "
                        "its hard timeout — cell may still be inside the post-seed clamp)")

    return {
        "target": target, "profile": profile, "scenario": scenario, "meta": meta,
        "rate_limits": basis[0]["rate_limits"],
        "perf": perf, "res": res, "der": der, "der_server": der_server,
        "host": host, "host_flags": host_flags(meta, host),
        "bottleneck": bottleneck(meta, res),
        "is_fallback": perf["fallback_class"] == "fallback-op",
        "valid": n_valid >= 2 and not reasons,
        "reasons": reasons,
        "expected_throttle": is_expected_throttle,
        "n_valid_runs": n_valid, "n_runs": n_total, "thr_spread_pct": thr_spread_pct,
    }


def collect(results_dir, max_error, min_samples):
    """Top-level entry point: detect whether `results_dir` holds a
    `results/run-*/` median-of-N layout or the classic flat single-run layout,
    and branch (C1). Returns (cells, multi_run)."""
    try:
        entries = sorted(os.listdir(results_dir))
    except OSError:
        entries = []
    run_dirs = [os.path.join(results_dir, e) for e in entries
                if RUN_DIR_RE.fullmatch(e) and os.path.isdir(os.path.join(results_dir, e))]

    if not run_dirs:
        # Classic single-run layout — completely unchanged behavior.
        cells = collect_dir(results_dir, max_error, min_samples)
        for c in cells:
            c["n_valid_runs"] = 1 if c["valid"] else 0
            c["n_runs"] = 1
            c["thr_spread_pct"] = 0.0
        return cells, False

    grouped = defaultdict(list)
    for run_dir in run_dirs:
        for c in collect_dir(run_dir, max_error, min_samples):
            grouped[(c["target"], c["profile"], c["scenario"])].append(c)
    cells = [aggregate_cell(runs) for runs in grouped.values()]
    return cells, True


def posture_bucket(posture):
    """Collapse a rate-limit posture into a comparability class.

    A head-to-head is only meaningful when every target in the group is
    effectively unthrottled: AXIAM run with `neutralized` limits vs competitors
    (`n/a` — they ship no per-IP limiter). AXIAM in `prod` posture is throttled
    and cannot be compared to an unthrottled competitor; a missing/`unknown`
    marker (e.g. results from before posture stamping) is treated as unknown so
    it is flagged rather than silently mixed in.
    """
    if posture in ("neutralized", "n/a", "none", ""):
        return "unthrottled"
    if posture == "prod":
        return "throttled"
    return "unknown"


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


PROFILE_RANK = {"p0-plaintext": 0, "p1-tls12": 1, "p2-tls13": 2, "p3-mtls": 3}


def build_report(cells, multi_run=False):
    lines = ["# AXIAM Benchmark Report", ""]
    valid = [c for c in cells if c["valid"]]
    invalid = [c for c in cells if not c["valid"]]
    targets = sorted({c["target"] for c in cells})
    scenarios = sorted({c["scenario"] for c in cells})
    profiles = sorted({c["profile"] for c in cells}, key=lambda p: PROFILE_RANK.get(p, 99))
    lines += [
        f"- Targets: {', '.join(targets) or '—'}",
        f"- Profiles: {', '.join(profiles) or '—'}",
        f"- Scenarios: {', '.join(scenarios) or '—'}",
        f"- Valid cells: {len(valid)} / {len(cells)}"
        + (f" ({sum(1 for c in cells if c.get('expected_throttle'))} excluded by design — "
           f"expected throttle, see below)"
           if any(c.get("expected_throttle") for c in cells) else ""),
        "",
        "> Efficiency headline: **throughput_per_core** (req/s per CPU core) and "
        "**cpu_ms_per_request** answer *can AXIAM match competitors at lower cost?* "
        "Compare across targets at equal profile + latency.",
        "",
        "> `http` = the wire protocol every measured response actually "
        "negotiated (`bench_http_proto`, k6's `res.proto`), **not** what the "
        "profile or the nginx conf was supposed to serve. `mixed(a,b)` means "
        "the cell spanned two protocols and is void as a controlled "
        "h1-vs-h2 comparison; `—` means the cell predates H6 or recorded no "
        "response. Added in H6 because the G8 TLS conviction attempt could "
        "not state which protocol its cells had used.",
        "",
        "> `fallback` = `fallback-op` when the cell measured a fallback "
        "operation instead of the labelled logical op (e.g. Zitadel's "
        "login() falling back to client_credentials — see "
        "docs/methodology.md). fallback-op cells are excluded from "
        "head-to-head winner tables but kept here for the full picture. "
        "`cc-token-setup` means only the *token's provenance* is a caveat — "
        "a client-credentials token was minted once in setup() (e.g. "
        "Zitadel's userinfo/userinfo-gRPC scenarios, when a real user token "
        "wasn't obtainable) but the measured operation is still the "
        "labelled one, so these cells stay in head-to-head comparisons "
        "(Report labeling polish).",
        "",
        "> `bottleneck` names the stack container(s) whose average CPU reached "
        "≥ 95% of their configured cap during the measure window — `none` "
        "means nothing in the stack saturated (the client, network, or an "
        "un-pegged serialization point is the limiter instead).",
        "",
        "> Cells with 100% error have their throughput/latency columns "
        "blanked (`—`) — those numbers would describe the failure path, not "
        "the operation being measured. This applies to gRPC cells too "
        "(keyed off `bench_error_rate`/`bench_ok`/`bench_failed`, not an "
        "HTTP-specific field, since a pure-gRPC scenario's k6 summary has no "
        "http_req_* metrics at all); see the gRPC status appendix below for "
        "which status code dominated a failing gRPC cell.",
        "",
    ]
    if multi_run:
        max_n = max((c.get("n_runs", 1) for c in cells), default=1)
        lines += [
            f"> **Median-of-N aggregation (C1):** this report was generated from "
            f"`results/run-*/` (up to N={max_n} repeats per cell). Every metric "
            "below (throughput, p50/p95/p99, cpu, mem, host telemetry) is the "
            "MEDIAN taken independently across that cell's valid runs — not a "
            "single run. `runs(valid/n)` shows how many of the N repeats were "
            "individually valid; a cell needs **≥2 valid runs** to be marked "
            "`valid` itself (fewer than that, there's no meaningful median — see "
            "docs/methodology.md). `±thr%` is the throughput spread across valid "
            "runs, `(max−min)/2` as a percentage of the median.",
            "",
        ]

    # 1. Full results table
    lines += ["## All results", ""]
    rows = []
    for c in sorted(cells, key=lambda c: (c["scenario"], c["profile"], c["target"])):
        p, r, d, h = c["perf"], c["res"], c["der"], c["host"]
        full_outage = is_full_outage(p)
        thr = None if full_outage else p["throughput"]
        p50 = None if full_outage else p["p50"]
        p95 = None if full_outage else p["p95"]
        p99 = None if full_outage else p["p99"]
        thr_core = None if full_outage else d["throughput_per_core"]
        cpu_ms = None if full_outage else d["cpu_ms_per_request"]
        mhz_ratio = (h["mhz_min"] / h["mhz_max"]) if h["mhz_max"] > 0 else 0.0
        fb_class = p.get("fallback_class", "none")
        flags = list(c["host_flags"])
        if fb_class == "fallback-op":
            flags.append("fallback-op")
        fb_label = fb_class if fb_class != "none" else "no"
        # H7: protocol-variant is a static per-scenario label (see
        # PROTOCOL_VARIANT_SCENARIOS above), orthogonal to bench_fallback —
        # append rather than replace so a cell that's ALSO fallback-op (e.g.
        # Zitadel's token_refresh) still shows both.
        if c["scenario"] in PROTOCOL_VARIANT_SCENARIOS:
            fb_label = (fb_label + "+protocol-variant") if fb_label != "no" else "protocol-variant"
        row = [
            c["scenario"], c["profile"], c["target"], c["rate_limits"],
            proto_label(p),
            dash(thr, ".0f"), dash(p50, ".1f"), dash(p95, ".1f"), dash(p99, ".1f"),
            f"{p['error_rate']*100:.2f}%",
            f"{r['cpu_cores_avg']:.2f}", f"{r['mem_mib_avg']:.0f}",
            dash(thr_core, ".0f"), dash(cpu_ms, ".3f"),
            c["bottleneck"],
            fb_label,
            f"{h['mhz_avg']:.0f}", f"{mhz_ratio:.2f}", f"{h['temp_max']:.0f}",
            f"{h['k6_cores_avg']:.2f}",
            ";".join(flags) or "-",
            "✓" if c["valid"] else "✗",
        ]
        if multi_run:
            row += [f"{c.get('n_valid_runs', 0)}/{c.get('n_runs', 1)}",
                    f"±{c.get('thr_spread_pct', 0.0):.1f}%"]
        rows.append(row)
    headers = ["scenario", "profile", "target", "rate_limits", "http", "thr(req/s)", "p50(ms)",
               "p95(ms)", "p99(ms)", "err", "cpu(cores)", "mem(MiB)", "thr/core",
               "cpu_ms/req", "bottleneck", "fallback", "mhz_avg", "mhz_min/max",
               "temp_max(C)", "k6_cores", "host_flags", "valid"]
    if multi_run:
        headers += ["runs(valid/n)", "±thr%"]
    lines += [md_table(headers, rows), ""]

    # 1b. C4: AXIAM production rate-limit-posture cells, called out separately
    # so they never get lost among (or silently averaged into) the neutralized
    # comparison numbers above. posture_bucket()/the efficiency-comparison loop
    # below already refuse to place a `prod`-posture cell head-to-head against
    # an unthrottled competitor; this section is the human-readable label for
    # the same rule, and the one place a `prod` run is summarized on its own.
    prod_cells = [c for c in cells if c["rate_limits"] == "prod"]
    if prod_cells:
        lines += [
            "## AXIAM production rate-limit posture — NOT comparable to competitors",
            "",
            "> These cells were run with `rl=prod` (`just target=axiam rl=prod …`): "
            "AXIAM's shipped-default per-IP rate limits ACTIVE (see the `rl` "
            "variable at the top of `justfile`). They measure the limiter's "
            "throttling behavior, not raw endpoint capacity, and are excluded "
            "from every head-to-head table above/below (`posture_bucket()` "
            "buckets `prod` separately from `neutralized`/`n/a`, so a mixed or "
            "unknown-posture comparison group is refused rather than silently "
            "rendered). The intended framing: *AXIAM ships per-IP rate limits by "
            "default; Keycloak and Zitadel don't* — compare a `prod` row only "
            "against AXIAM's own `neutralized` row for the same "
            "(scenario, profile), never against another target.",
            "",
        ]
        rows = []
        for c in sorted(prod_cells, key=lambda c: (c["scenario"], c["profile"])):
            p = c["perf"]
            full_outage = is_full_outage(p)
            rows.append([
                c["scenario"], c["profile"],
                dash(None if full_outage else p["throughput"], ".0f"),
                dash(None if full_outage else p["p50"], ".1f"),
                dash(None if full_outage else p["p95"], ".1f"),
                f"{p['error_rate'] * 100:.2f}%",
                "posture: prod — NOT comparable to competitors",
            ])
        lines += [md_table(
            ["scenario", "profile", "thr(req/s)", "p50(ms)", "p95(ms)", "err", "label"],
            rows), ""]

    # 2. Efficiency comparison per (scenario, profile) across targets
    lines += ["## Efficiency comparison (across targets)", "",
              "Higher `thr/core` and lower `cpu_ms/req` is better. "
              "`server-only` recomputes both against just the primary "
              "server/app container's CPU+mem (excludes DB/broker/edge), so "
              "AXIAM's RabbitMQ+SurrealDB inclusion in the whole-stack numbers "
              "is visible rather than silently folded in (A5.5).", ""]
    for sc in scenarios:
        # D4: never render AXIAM-only/vendor-only scenarios here, even if a
        # future scenario file name collision would otherwise let >=2 cells
        # slip into group_all below — these are protocol-efficiency-only
        # (see the dedicated section below) or single-vendor capability
        # metrics, not cross-vendor numbers (docs/methodology.md §5).
        if sc in NON_COMPARATIVE_SCENARIOS:
            continue
        for pr in profiles:
            group_all = [c for c in valid if c["scenario"] == sc and c["profile"] == pr]
            if len(group_all) < 2:
                continue
            fallback_cells = [c for c in group_all if c["is_fallback"]]
            group = [c for c in group_all if not c["is_fallback"]]
            # Report labeling polish: cc-token-setup cells (right op, only the
            # token's provenance is a caveat) are NOT excluded — `group`
            # already includes them since is_fallback is fallback-op-only —
            # just called out with a lighter footnote below.
            cc_cells = [c for c in group if c["perf"].get("fallback_class") == "cc-token-setup"]
            lines += [f"### {sc} @ {pr}", ""]
            if fallback_cells:
                lines += [
                    "> ⚠️ fallback-op cell(s) excluded from this head-to-head: "
                    + ", ".join(sorted(f"{c['target']}" for c in fallback_cells))
                    + " (see the full matrix above; comparability: fallback-op).", "",
                ]
            if cc_cells:
                lines += [
                    "> ℹ️ cc-token-setup provenance note (kept in this "
                    "head-to-head): "
                    + ", ".join(sorted(f"{c['target']}" for c in cc_cells))
                    + " — the measured operation is the labelled one; only the "
                    "token used to reach it was minted via client_credentials "
                    "once in setup() (comparability: cc-token-setup).", "",
                ]
            if sc in PROTOCOL_VARIANT_SCENARIOS:
                notes = PROTOCOL_VARIANT_NOTES.get(sc, {})
                desc = "; ".join(
                    f"**{c['target']}** = {notes.get(c['target'], 'operation shape not documented')}"
                    for c in sorted(group, key=lambda c: c["target"])
                )
                lines += [
                    "> ⚠️ **comparability: protocol-variant** (kept in this "
                    "head-to-head, never excluded — each target's cell is a "
                    "real, correct measurement of ITS OWN op, they're just not "
                    f"the same op): {desc}. Read this table as each target's own "
                    "capability at renewing a credential without "
                    "re-authenticating, never as \"target A is Nx target B\" "
                    "(see claude_dev/refresh-harness-diagnosis.md §6).", "",
                ]
            if len(group) < 2:
                lines += ["_Fewer than 2 non-fallback targets — nothing to compare._", ""]
                continue
            # Refuse to render a head-to-head across incomparable rate-limit
            # postures (e.g. AXIAM throttled vs an unthrottled competitor, or a
            # cell with an unknown posture). This is the guard that stops the
            # p0-plaintext limiter incident from silently recurring.
            buckets = {posture_bucket(c["rate_limits"]) for c in group}
            if len(buckets) > 1 or "unknown" in buckets:
                postures = ", ".join(sorted(
                    f"{c['target']}={c['rate_limits']}" for c in group))
                lines += [
                    "> ⚠️ **Not comparable — mixed or unknown rate-limit posture** "
                    f"({postures}). A head-to-head is only meaningful when every "
                    "target is unthrottled (AXIAM `neutralized` vs competitors, "
                    "which have no per-IP limiter). Re-run AXIAM with "
                    "`just rl=neutralized … bench-up`; results run in `prod` "
                    "posture measure the limiter, not endpoint capacity.", "",
                ]
                continue
            rows = []
            best = max(group, key=lambda c: c["der"]["throughput_per_core"])
            for c in sorted(group, key=lambda c: -c["der"]["throughput_per_core"]):
                d, ds, p = c["der"], c["der_server"], c["perf"]
                marker = " 🏆" if c is best else ""
                note = " (cc-token-setup)" if p.get("fallback_class") == "cc-token-setup" else ""
                if sc in PROTOCOL_VARIANT_SCENARIOS:
                    note += " (protocol-variant)"
                rows.append([c["target"] + marker + note, f"{p['throughput']:.0f}",
                             f"{p['p50']:.1f}", f"{p['p95']:.1f}",
                             f"{d['throughput_per_core']:.0f}", f"{d['throughput_per_gib']:.0f}",
                             f"{d['cpu_ms_per_request']:.3f}",
                             f"{ds['throughput_per_core']:.0f}", f"{ds['cpu_ms_per_request']:.3f}"])
            lines += [md_table(
                ["target", "thr(req/s)", "p50(ms)", "p95(ms)", "thr/core", "thr/GiB",
                 "cpu_ms/req", "server-only thr/core", "server-only cpu_ms/req"],
                rows), ""]

    # 2b. Protocol efficiency: REST vs gRPC for the same logical op, WITHIN a
    # single vendor (D4). Distinct from — and deliberately never merged into —
    # section 2's cross-vendor tables: this answers "does gRPC cost less than
    # REST for the same operation on the same server?", not "is target A
    # faster than target B?" (docs/methodology.md §5, "Comparability:
    # protocol-efficiency (gRPC vs REST, same vendor)").
    lines += ["## Protocol efficiency (gRPC vs REST, within a vendor)", "",
              "Same logical operation, two wire protocols, same target — NOT a "
              "cross-vendor comparison (see docs/methodology.md §5). "
              "`Δ-throughput` and `Δ-cpu_ms/req` are gRPC relative to REST "
              "(negative Δ-cpu_ms/req = gRPC cheaper per request).", ""]
    any_pair_rendered = False
    for tg, pairs in PROTOCOL_EFFICIENCY_PAIRS.items():
        for rest_sc, grpc_sc, op_label in pairs:
            for pr in profiles:
                rest_c = next((c for c in valid
                               if c["target"] == tg and c["scenario"] == rest_sc and c["profile"] == pr), None)
                grpc_c = next((c for c in valid
                               if c["target"] == tg and c["scenario"] == grpc_sc and c["profile"] == pr), None)
                if not rest_c or not grpc_c:
                    continue
                # Report labeling polish: only fallback-op (wrong op measured)
                # skips the pair. cc-token-setup cells (e.g. Zitadel's
                # userinfo/userinfo-gRPC, whose setup() mints a
                # client-credentials token once) still measure the labelled
                # op and are kept, with a footnote on the affected row(s).
                if rest_c["is_fallback"] or grpc_c["is_fallback"]:
                    continue  # A3: a fallback-op cell measures a different operation — skip the pair.
                any_pair_rendered = True
                lines += [f"### {tg}: {op_label} @ {pr}", ""]
                rp, gp = rest_c["perf"], grpc_c["perf"]
                rd, gd = rest_c["der"], grpc_c["der"]
                d_thr = ((gp["throughput"] - rp["throughput"]) / rp["throughput"] * 100.0
                         if rp["throughput"] else 0.0)
                d_cpu_ms = gd["cpu_ms_per_request"] - rd["cpu_ms_per_request"]
                rest_note = " (cc-token-setup)" if rp.get("fallback_class") == "cc-token-setup" else ""
                grpc_note = " (cc-token-setup)" if gp.get("fallback_class") == "cc-token-setup" else ""
                rows = [
                    ["REST (" + rest_sc + ")" + rest_note, f"{rp['throughput']:.0f}", f"{rp['p50']:.1f}",
                     f"{rp['p95']:.1f}", f"{rd['throughput_per_core']:.0f}",
                     f"{rd['cpu_ms_per_request']:.3f}", "baseline"],
                    ["gRPC (" + grpc_sc + ")" + grpc_note, f"{gp['throughput']:.0f}", f"{gp['p50']:.1f}",
                     f"{gp['p95']:.1f}", f"{gd['throughput_per_core']:.0f}",
                     f"{gd['cpu_ms_per_request']:.3f}", f"{d_thr:+.1f}% thr, {d_cpu_ms:+.3f} cpu_ms/req"],
                ]
                lines += [md_table(
                    ["protocol (scenario)", "thr(req/s)", "p50(ms)", "p95(ms)",
                     "thr/core", "cpu_ms/req", "Δ vs REST"],
                    rows), ""]
    if not any_pair_rendered:
        lines += ["_No matching (REST, gRPC) pair had both cells valid and "
                  "non-fallback for the same (target, profile) yet._", ""]

    # 3. Security-cost matrix per (target, scenario)
    lines += ["## Security cost (relative to p0-plaintext)", "",
              "What each stronger security profile costs vs the plaintext baseline.", ""]
    for tg in targets:
        for sc in scenarios:
            group = [c for c in valid if c["target"] == tg and c["scenario"] == sc]
            base = next((c for c in group if c["profile"] == "p0-plaintext"), None)
            others = [c for c in group if c["profile"] != "p0-plaintext"]
            if not base or not others:
                continue
            lines += [f"### {tg} / {sc}", ""]
            rows = [["p0-plaintext (base)", proto_label(base["perf"]),
                     f"{base['perf']['throughput']:.0f}",
                     f"{base['perf']['p50']:.1f}", f"{base['perf']['p95']:.1f}",
                     "baseline", "baseline"]]
            for c in sorted(others, key=lambda c: PROFILE_RANK.get(c["profile"], 99)):
                tb, pb = base["perf"]["throughput"], base["perf"]["p95"]
                t, p = c["perf"]["throughput"], c["perf"]["p95"]
                d_thr = (1 - t / tb) * 100 if tb else 0.0
                d_p95 = p - pb
                rows.append([c["profile"], proto_label(c["perf"]),
                             f"{t:.0f}", f"{c['perf']['p50']:.1f}", f"{p:.1f}",
                             f"{-d_thr:+.1f}%", f"{d_p95:+.1f}"])
            lines += [md_table(
                ["profile", "http", "thr(req/s)", "p50(ms)", "p95(ms)",
                 "Δ-throughput", "Δ-p95(ms)"],
                rows), ""]
            # H6: a security-cost row compares p0 against p2 — but if the two
            # cells did not run over the same wire protocol, the delta bundles
            # "TLS" together with "h1 vs h2" and is not a TLS cost at all. Say
            # so in the table rather than leaving the reader to notice.
            protos = {proto_label(c["perf"]) for c in [base] + others}
            protos.discard("—")
            if len(protos) > 1:
                lines += [
                    "> **Protocol confound (H6):** the rows above did not all "
                    "negotiate the same HTTP version (`" + ", ".join(sorted(protos))
                    + "`). Each Δ therefore measures TLS **and** the protocol "
                      "change together. See `claude_dev/b2-tls-h2-investigation.md`.",
                    "",
                ]

    # 4. Appendix: per-container resource breakdown (A5.3)
    lines += ["## Appendix: per-container resource breakdown", "",
              "Per-cell, per-container average CPU/mem from the resource sampler, "
              "the caps it was measured against (from meta.json's `cpu_cap`/"
              "`mem_cap_mib` — C2 — falling back to the compose default when "
              "absent), and whether it hit the CPU bottleneck threshold "
              "(cpu_avg ≥ 95% of cpu_cap). `mem_cap(MiB)` is what a "
              "`dbcaps=uncapped` (C2) run shows raised for the `-surrealdb`/"
              "`-postgres` container.", ""]
    rows = []
    for c in sorted(valid, key=lambda c: (c["scenario"], c["profile"], c["target"])):
        containers_meta = {cm.get("name"): cm for cm in (c["meta"].get("containers") or [])}
        for cname, stats in sorted((c["res"].get("containers") or {}).items()):
            cm = containers_meta.get(cname)
            if cm is not None and cm.get("cpu_cap") not in (None, ""):
                try:
                    cap = float(cm["cpu_cap"])
                except (TypeError, ValueError):
                    cap = default_cpu_cap(cname)
            else:
                cap = default_cpu_cap(cname)
            if cm is not None and cm.get("mem_cap_mib") not in (None, ""):
                try:
                    mem_cap = float(cm["mem_cap_mib"])
                except (TypeError, ValueError):
                    mem_cap = default_mem_cap(cname)
            else:
                mem_cap = default_mem_cap(cname)
            hot = "✓" if stats.get("cpu_avg", 0.0) >= 0.95 * cap else "·"
            rows.append([c["scenario"], c["profile"], c["target"], cname,
                         f"{stats.get('cpu_avg', 0.0):.2f}", f"{cap:.2f}",
                         f"{stats.get('mem_avg', 0.0):.0f}", f"{mem_cap:.0f}", hot])
    if rows:
        lines += [md_table(
            ["scenario", "profile", "target", "container", "cpu_avg(cores)",
             "cpu_cap", "mem_avg(MiB)", "mem_cap(MiB)", "hot"],
            rows), ""]
    else:
        lines += ["_No per-container samples available (no res.csv rows)._", ""]

    # 4b. Appendix: gRPC status codes (D11 + Report labeling polish). Only
    # rendered for cells whose k6 summary actually carried the
    # bench_grpc_status Trend (gRPC scenarios only — absent for REST cells
    # and for any results tree predating D11, tolerated via has_grpc_status
    # rather than assumed present). Lets a 100%-error gRPC cell (throughput/
    # latency blanked above) be diagnosed straight from the report: which
    # status code dominated.
    grpc_cells = [c for c in cells if c["perf"].get("has_grpc_status")]
    if grpc_cells:
        lines += [
            "## Appendix: gRPC status codes", "",
            "`status_avg`/`status_max` are the average/maximum raw gRPC "
            "status code seen during the measure window (e.g. 0=OK, "
            "7=PermissionDenied, 16=Unauthenticated) — only present for gRPC "
            "scenarios (scenarios/lib/metrics.js's `bench_grpc_status` "
            "Trend). Useful for diagnosing a 100%-error gRPC cell where the "
            "throughput/latency columns in \"All results\" are blanked "
            "(`—`).", "",
        ]
        rows = []
        for c in sorted(grpc_cells, key=lambda c: (c["scenario"], c["profile"], c["target"])):
            p = c["perf"]
            rows.append([
                c["scenario"], c["profile"], c["target"],
                f"{p['error_rate'] * 100:.2f}%",
                f"{p['grpc_status_avg']:.1f}", f"{p['grpc_status_max']:.0f}",
            ])
        lines += [md_table(
            ["scenario", "profile", "target", "err", "status_avg", "status_max"],
            rows), ""]

    # 4c. Appendix: post-seed settle gate (G2). settle_wait_secs/settle_timeout
    # come from run-benchmark.sh's settle_gate() (see docs/methodology.md
    # "Post-seed settle gate & cell-order rotation"). Only rendered when at
    # least one cell actually carries the field — meta.json files predating
    # G2 have neither key, so a mixed-vintage results tree (e.g. the existing
    # run-1/run-2/run-3 trees alongside a fresh G2 run) renders this section
    # only for the cells that have the data and never crashes on the ones
    # that don't (host_flags() above degrades the same way for the
    # `settle_timeout` flag in the main results table).
    settle_cells = [c for c in cells if c["meta"].get("settle_wait_secs") is not None]
    if settle_cells:
        lines += [
            "## Appendix: post-seed settle gate", "",
            "`settle_wait(s)` is how long run-benchmark.sh's settle gate "
            "waited, before this run's FIRST cell, for a concurrent burst "
            "probe (`BENCH_SETTLE_BURST_VUS` workers, default 20, for "
            "`BENCH_SETTLE_BURST_SECS` seconds, default 15) to clear "
            "`BENCH_SETTLE_PROBE_THR` ops/s (default 400) OR "
            "`BENCH_SETTLE_PROBE_P50_MS` p50 (default 150ms) under that "
            "concurrency (H1 — a serial 1 rps canary could not detect the "
            "post-seed clamp: the ~22ms serialized unit reads as \"fast\" at "
            "1 rps whether the server can sustain ~44 ops/s or ~730-750 "
            "ops/s; only a concurrent burst can see the difference — see "
            "\"Post-seed settle gate v2\" in docs/methodology.md). Every "
            "cell in the same run records the same wait, since the gate "
            "runs once per `bench-run` invocation, not per cell. `timeout` "
            "marks a cell whose gate hit its hard `BENCH_SETTLE_TIMEOUT_SECS` "
            "(default 600s) without ever clearing the threshold — the run "
            "proceeded anyway (the gate never fails the harness) but the "
            "cell may still be inside the post-seed serialized-DB transient "
            "(PRIVATE_BENCH_ANALYSIS.md §1). As of H1 a `timeout` cell was "
            "REFUSED outright (marked invalid). **As of H10**, refusal is "
            "narrowed to the scenarios H2's clamp map actually implicates "
            "(`RateLimitShared`-wrapped endpoints — authz_check/_batch "
            "rest+grpc, oauth2_client_credentials, token_introspection, "
            "oauth2_password_login): a `timeout` this session no longer "
            "refuses jwks_fetch, userinfo(_grpc) or token_refresh, since the "
            "H2 investigation found those endpoints structurally immune to "
            "the clamp regardless of what the session-wide gate probe saw "
            "(`postseed-transient-investigation.md` §2). The `refused` "
            "column below shows which of the two applied to THIS cell. For "
            "median-of-N cells, `settle_wait(s)` is the MAX across the "
            "repeat's runs (worst case) and `timeout` is set if ANY run's "
            "gate timed out.", "",
        ]
        rows = []
        for c in sorted(settle_cells, key=lambda c: (c["scenario"], c["profile"], c["target"])):
            rows.append([
                c["scenario"], c["profile"], c["target"],
                f"{c['meta'].get('settle_wait_secs', 0):.0f}",
                "✓" if c["meta"].get("settle_timeout") else "·",
                "✓" if settle_timeout_applies(c["meta"]) else "·",
            ])
        lines += [md_table(
            ["scenario", "profile", "target", "settle_wait(s)", "timeout", "refused"],
            rows), ""]

    # 4d. Appendix: AXIAM env knobs / labeled passes (G2). meta.json's
    # "axiam_env" is every AXIAM__* env var the server container actually
    # received, with secret-shaped values (PASSWORD/SECRET/KEY/PEPPER/PEM/
    # TOKEN in the var name) redacted to the literal "<redacted>" — see
    # run-benchmark.sh's axiam_env_json(). This makes a labeled sensitivity
    # pass (pool size, batch strategy, decision cache, hash concurrency, ...)
    # identifiable straight from the metadata rather than the results-
    # directory name (PRIVATE_BENCH_ANALYSIS.md §2.2). Grouped by
    # (target, profile), one representative cell per group, rather than
    # repeated per scenario — every cell from the same `bench-up` shares one
    # running server container, so its axiam_env is identical across that
    # target/profile's scenarios. Absent entirely (section omitted) for any
    # results tree predating G2, and for non-AXIAM targets (axiam_env_json()
    # only inspects the AXIAM server container).
    env_groups = {}
    for c in cells:
        env = c["meta"].get("axiam_env")
        if not env:
            continue
        key = (c["target"], c["profile"])
        if key not in env_groups or c["scenario"] < env_groups[key][0]:
            env_groups[key] = (c["scenario"], env)
    if env_groups:
        lines += [
            "## Appendix: AXIAM env knobs (labeled passes)", "",
            "One representative cell's `axiam_env` per (target, profile) — "
            "see the note above. `<redacted>` means the setting was present "
            "but its value is a secret (never packed/shared — see "
            "`just bench-pack`'s leak check in `justfile`).", "",
        ]
        rows = []
        for (target, profile), (scenario, env) in sorted(env_groups.items()):
            for k, v in sorted(env.items()):
                rows.append([target, profile, scenario, k, v])
        lines += [md_table(
            ["target", "profile", "representative scenario", "AXIAM__ var", "value"],
            rows), ""]

    # 5. Excluded — split so a structurally-unmeasurable cell is never read as
    # a run that went wrong. Both groups are equally excluded; only one is
    # something a person could act on.
    throttle_excluded = [c for c in invalid if c.get("expected_throttle")]
    fault_excluded = [c for c in invalid if not c.get("expected_throttle")]
    if fault_excluded:
        lines += ["## Excluded (invalid) cells", ""]
        rows = [[c["target"], c["profile"], c["scenario"], "; ".join(c["reasons"])]
                for c in fault_excluded]
        lines += [md_table(["target", "profile", "scenario", "reason"], rows), ""]
    if throttle_excluded:
        lines += [
            "## Excluded by design (expected throttle)", "",
            "These scenarios drive a limiter family whose ceiling **no "
            "rate-limit posture can lift** — `grpc_infra`'s `INFRA_PER_SEC` is "
            "a hardcoded constant with no env var, and `device_verify`'s knob "
            "is capped by `RateLimitConfig::validate`'s OWASP user-code bound "
            "(raising it past 2559/min makes the server refuse to boot). A "
            "closed-loop probe against them is throttled by construction, so "
            "their throughput and latency describe the governor's reject path "
            "rather than the endpoint, and they are excluded from every median "
            "and head-to-head table above.", "",
            "**Nothing here is a fault or a regression.** They are listed "
            "separately from the table above precisely so a run's genuine "
            "problems stay visible. See `EXPECTED_THROTTLE` in "
            "`runner/run-benchmark.sh` for the full justification.", "",
        ]
        rows = [[c["target"], c["profile"], c["scenario"],
                 f"{c['perf'].get('throttled_count', 0):.0f}",
                 f"{c['perf']['ok_count']:.0f}"]
                for c in throttle_excluded]
        lines += [md_table(
            ["target", "profile", "scenario", "throttled", "admitted"], rows), ""]

    lines += ["---", "_Generated by runner/report.py. See docs/methodology.md for "
              "metric definitions and validity gates._"]
    return "\n".join(lines)


def append_sdk_section(report_text, results_dir):
    """H8/E1.3: fold sdk/collect.py's SDK-client-overhead section into the
    main report so a single `report.py` run publishes both the server-side
    matrix and the SDK overhead table together, instead of leaving the two
    as separate files a reader has to know to cross-reference. Best-effort:
    if sdk/collect.py can't be imported (e.g. this script run from outside
    the benchmarks/ tree) or there are no SDK records yet, the main report
    is still written unchanged — this is additive, never load-bearing for
    the server-side report."""
    sdk_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sdk")
    try:
        sys.path.insert(0, sdk_dir)
        import collect as sdk_collect  # sdk/collect.py
    except ImportError:
        return report_text
    finally:
        if sdk_dir in sys.path:
            sys.path.remove(sdk_dir)
    recs = sdk_collect.load_sdk_records(results_dir)
    if not recs:
        return report_text
    sdk_section = sdk_collect.build(results_dir, recs)
    return report_text + "\n\n---\n\n" + sdk_section + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--max-error", type=float, default=0.01)
    ap.add_argument("--min-samples", type=int, default=10)
    args = ap.parse_args()

    if not os.path.isdir(args.results):
        print(f"no results dir: {args.results}", file=sys.stderr)
        sys.exit(1)
    cells, multi_run = collect(args.results, args.max_error, args.min_samples)
    if not cells:
        print("no result cells found — run a benchmark first", file=sys.stderr)
        sys.exit(1)
    if multi_run:
        print(f"[report] median-of-N layout detected ({len(cells)} aggregated cells)")
    # H1 item 5: loudly flag settle_timeout cells at the CLI too, not just in
    # the "Excluded (invalid) cells" table buried in the generated report —
    # this is the failure mode that let contaminated post-seed cells enter
    # the G run's published numbers.
    settle_timeout_cells = [c for c in cells
                             if any("settle_timeout" in r for r in c.get("reasons", []))]
    if settle_timeout_cells:
        print(f"[report] WARN: {len(settle_timeout_cells)} cell(s) REFUSED — "
              f"settle_timeout:true (post-seed settle gate hit its hard timeout):",
              file=sys.stderr)
        for c in settle_timeout_cells:
            print(f"[report]   - {c['target']}/{c['profile']}/{c['scenario']}", file=sys.stderr)
    report = build_report(cells, multi_run=multi_run)
    # H8/E1.3: append the SDK client-overhead table (sdk/collect.py) so the
    # published report carries both halves of the harness in one file.
    report = append_sdk_section(report, args.results)
    out = args.out or os.path.join(args.results, "report.md")
    with open(out, "w") as f:
        f.write(report)
    print(f"wrote {out} ({len(cells)} cells)")
    print(report)


if __name__ == "__main__":
    main()
