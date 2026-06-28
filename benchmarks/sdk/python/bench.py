#!/usr/bin/env python3
"""AXIAM Python SDK benchmark (reference scaffold).

The timing harness is complete; only the SDK calls are TODO, because the Python
SDK is still under development (feature/phase-17, T17.3). When it lands:
`pip install axiam-sdk`, implement the four ops, and set SDK_WIRED = True. Keep
the stdout JSON contract (axiam.sdk-bench/v1) intact.

Run: python3 bench.py   (or: just sdk-bench sdk=python)
"""
import concurrent.futures as cf
import json
import os
import time

ITER = int(os.environ.get("SDK_BENCH_ITERATIONS", "2000"))
WARMUP = int(os.environ.get("SDK_BENCH_WARMUP", "200"))
CONC = int(os.environ.get("SDK_BENCH_CONCURRENCY", "16"))

CFG = {
    "base_url": f"{os.environ.get('BENCH_SCHEME','http')}://"
                f"{os.environ.get('BENCH_HOST','localhost')}:{os.environ.get('BENCH_PORT','8090')}",
    "tenant_id": os.environ.get("BENCH_TENANT_ID", ""),
    "client_id": os.environ.get("BENCH_CLIENT_ID", "bench-client"),
    "client_secret": os.environ.get("BENCH_CLIENT_SECRET", ""),
}


def pct(arr, p):
    if not arr:
        return 0.0
    s = sorted(arr)
    k = (len(s) - 1) * (p / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


# ---------------------------------------------------------------------------
# TODO(feature/phase-17 T17.3): build the client and implement each op.
#   from axiam_sdk import AxiamClient
#   client = AxiamClient(base_url=CFG["base_url"], tenant_id=CFG["tenant_id"],
#                        client_id=CFG["client_id"], client_secret=CFG["client_secret"])
#   OPS = {
#     "client_credentials": lambda tok: client.auth.client_credentials(scope="openid"),
#     "introspect":        lambda tok: client.tokens.introspect(tok),
#     "userinfo":          lambda tok: client.oidc.userinfo(tok),
#     "authz_check":       lambda tok: client.authz.check(action="read", resource_id="bench"),
#   }
SDK_WIRED = False
OPS = None
# ---------------------------------------------------------------------------


def time_op(fn):
    lat, errors = [], 0
    for _ in range(WARMUP):
        try:
            fn(None)
        except Exception:
            errors += 1
    start = time.perf_counter()

    def one(_):
        t0 = time.perf_counter()
        try:
            fn(None)
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


def main():
    ops, status, notes = {}, "ok", ""
    if not SDK_WIRED or not OPS:
        status, notes = "pending", \
            "SDK not yet wired — implement OPS in sdk/python/bench.py (T17.3)."
        for k in ("client_credentials", "introspect", "userinfo", "authz_check"):
            ops[k] = {"p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "throughput_rps": 0, "errors": 0}
    else:
        for k, fn in OPS.items():
            ops[k] = time_op(fn)
    import platform
    print(json.dumps({
        "schema": "axiam.sdk-bench/v1", "sdk": "python",
        "sdk_version": "unreleased",
        "language_runtime": f"python {platform.python_version()}",
        "target": os.environ.get("BENCH_TARGET", "axiam"),
        "profile": os.environ.get("BENCH_PROFILE", "p0-plaintext"),
        "status": status, "iterations": ITER if status == "ok" else 0,
        "concurrency": CONC if status == "ok" else 0,
        "ops": ops, "client_cpu_ms_total": 0, "client_rss_mib_peak": 0, "notes": notes,
    }, indent=2))


if __name__ == "__main__":
    main()
