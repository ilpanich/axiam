#!/usr/bin/env python3
"""AXIAM Python SDK benchmark (reference harness, wired to axiam_sdk).

Times ``axiam_sdk.AxiamClient``'s canonical CONTRACT.md §1 operations —
``login``, ``refresh``, ``check_access``, ``batch_check`` — against a running,
seeded AXIAM target. ``oauth2_token``/``introspect``/``userinfo`` are
protocol-level ops with no SDK wrapper (see ../HARNESS-SPEC.md) and are not
measured here. Keep the stdout JSON contract (axiam.sdk-bench/v1) intact.

Run: python3 bench.py   (or: just sdk-bench sdk=python)
"""
import concurrent.futures as cf
import json
import os
import platform
import time

ITER = int(os.environ.get("SDK_BENCH_ITERATIONS", "2000"))
WARMUP = int(os.environ.get("SDK_BENCH_WARMUP", "200"))
CONC = int(os.environ.get("SDK_BENCH_CONCURRENCY", "16"))

CFG = {
    "base_url": f"{os.environ.get('BENCH_SCHEME','http')}://"
                f"{os.environ.get('BENCH_HOST','localhost')}:{os.environ.get('BENCH_PORT','8090')}",
    "tenant_slug": os.environ.get("BENCH_TENANT_SLUG", "default"),
    "username": os.environ.get("BENCH_USERNAME", "benchuser"),
    "password": os.environ.get("BENCH_PASSWORD", "Bench@User123!"),
    "action": os.environ.get("BENCH_ACTION", "read"),
    "resource_id": os.environ.get("BENCH_RESOURCE_ID", "bench-resource"),
}

OP_KEYS = ("login", "refresh", "check_access", "batch_check")

try:
    from axiam_sdk import AccessCheck, AxiamClient

    SDK_WIRED = True
    SDK_IMPORT_ERROR = None
except ImportError as exc:  # SDK not installed in this environment
    SDK_WIRED = False
    SDK_IMPORT_ERROR = str(exc)


def pct(arr, p):
    if not arr:
        return 0.0
    s = sorted(arr)
    k = (len(s) - 1) * (p / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def build_ops():
    """Build one logged-in AxiamClient and return {op_key: zero-arg fn}.

    ``login`` builds and discards its own short-lived client per call (a
    fresh, unauthenticated session per iteration mirrors what the op
    measures); ``refresh``/``check_access``/``batch_check`` share one
    already-authenticated client — refresh is routed through the SDK's
    single-flight guard, so concurrent callers are safe.
    """
    client = AxiamClient(base_url=CFG["base_url"], tenant_slug=CFG["tenant_slug"])
    client.login(CFG["username"], CFG["password"])
    checks = [
        AccessCheck(action=CFG["action"], resource_id=f"{CFG['resource_id']}-{i}")
        for i in range(3)
    ]

    def do_login():
        fresh = AxiamClient(base_url=CFG["base_url"], tenant_slug=CFG["tenant_slug"])
        try:
            fresh.login(CFG["username"], CFG["password"])
        finally:
            fresh.close()

    return {
        "login": do_login,
        "refresh": client.refresh,
        "check_access": lambda: client.check_access(CFG["action"], CFG["resource_id"]),
        "batch_check": lambda: client.batch_check(checks),
    }


def time_op(fn):
    lat, errors = [], 0
    for _ in range(WARMUP):
        try:
            fn()
        except Exception:
            errors += 1
    start = time.perf_counter()

    def one(_):
        t0 = time.perf_counter()
        try:
            fn()
            return (time.perf_counter() - t0) * 1000.0
        except Exception:
            return None

    with cf.ThreadPoolExecutor(max_workers=CONC) as ex:
        for r in ex.map(one, range(ITER)):
            if r is None:
                errors += 1
            else:
                lat.append(r)
    secs = time.perf_counter() - start
    return {"p50_ms": pct(lat, 50), "p95_ms": pct(lat, 95), "p99_ms": pct(lat, 99),
            "throughput_rps": (len(lat) / secs) if secs else 0.0, "errors": errors}


def zero_ops():
    return {k: {"p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "throughput_rps": 0, "errors": 0} for k in OP_KEYS}


def emit(status, ops, iterations, concurrency, notes):
    print(json.dumps({
        "schema": "axiam.sdk-bench/v1", "sdk": "python",
        "sdk_version": "unreleased",
        "language_runtime": f"python {platform.python_version()}",
        "target": os.environ.get("BENCH_TARGET", "axiam"),
        "profile": os.environ.get("BENCH_PROFILE", "p0-plaintext"),
        "status": status, "iterations": iterations, "concurrency": concurrency,
        "ops": ops, "client_cpu_ms_total": 0, "client_rss_mib_peak": 0, "notes": notes,
    }, indent=2))


def main():
    if not SDK_WIRED:
        emit("pending", zero_ops(), 0, 0,
             f"axiam_sdk not installed — pip install axiam-sdk ({SDK_IMPORT_ERROR}).")
        return

    try:
        ops_fns = build_ops()
    except Exception as exc:  # server not running / seed missing / auth failed
        emit("error", zero_ops(), 0, 0, f"server unreachable or setup failed: {exc}")
        return

    ops = {k: time_op(fn) for k, fn in ops_fns.items()}
    emit("ok", ops, ITER, CONC, "")


if __name__ == "__main__":
    main()
