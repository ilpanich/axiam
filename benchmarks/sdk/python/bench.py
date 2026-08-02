#!/usr/bin/env python3
"""AXIAM Python SDK benchmark (reference harness, wired to axiam_sdk).

Times ``axiam_sdk.AxiamClient``'s canonical CONTRACT.md §1 operations —
``login``, ``refresh``, ``check_access``, ``batch_check`` — against a running,
seeded AXIAM target. ``oauth2_token``/``introspect``/``userinfo`` are
protocol-level ops with no SDK wrapper (see ../HARNESS-SPEC.md) and are not
measured here. Keep the stdout JSON contract (axiam.sdk-bench/v1) intact.

Run: python3 bench.py   (or: just sdk=python sdk-bench)
"""
import concurrent.futures as cf
import functools
import json
import os
import platform
import time

ITER = int(os.environ.get("SDK_BENCH_ITERATIONS", "2000"))
WARMUP = int(os.environ.get("SDK_BENCH_WARMUP", "200"))
CONC = int(os.environ.get("SDK_BENCH_CONCURRENCY", "16"))

def _read_custom_ca():
    """H8 fix: HARNESS-SPEC.md documents BENCH_CA_CERT (a file PATH) as an
    input every SDK bench should honor under the TLS profiles (p2), but this
    reference bench never read it — every p2 run failed at the first HTTPS
    call with 'certificate verify failed: unable to get local issuer
    certificate' against the profile's throwaway CA.

    AxiamClient's `custom_ca` accepts EITHER a file path or inline PEM text
    (`_looks_like_pem()` in _session.py) when a client cert is also supplied
    (the mTLS-context branch), but the plain server-trust-only branch
    (`self._verify = custom_ca if custom_ca else True`, no client cert)
    hands the value straight to httpx's `verify=`, which only accepts a
    bool/SSLContext/file-path — NOT inline PEM content (that raises 'File
    name too long' since it tries to stat() the huge string as a path).
    Pass BENCH_CA_CERT's PATH through unchanged: it is valid input to BOTH
    branches, so this stays correct whether or not the p3 client identity
    below is configured."""
    path = os.environ.get("BENCH_CA_CERT", "")
    return path or None


@functools.lru_cache(maxsize=1)
def _read_client_identity():
    """Read the p3-mtls client identity (CONTRACT.md §6.1).

    HARNESS-SPEC.md documents BENCH_CLIENT_CERT/BENCH_CLIENT_KEY as file
    PATHS (the same pair k6 hands to `tlsAuth` and seed.sh to `curl --cert`),
    but `AxiamClient(client_cert=…, client_key=…)` wants PEM *content* (str
    or bytes — see the SDK's `_tls_identity.normalize_pem`), so read them
    here. Returns (None, None) when unset, leaving the SDK's default
    bearer-cookie behavior untouched (§6.1 rule 5: mTLS is opt-in), so p0/p1/
    p2 runs are byte-for-byte unaffected.

    The pair is all-or-nothing: the SDK itself raises ValueError on a
    half-configured identity (§6.1 rule 1), but failing here names the env
    var the operator actually got wrong instead of surfacing an SDK-internal
    Called lazily from :func:`new_client` (i.e. inside ``build_ops``' try
    block), NOT at import time: a bad/unreadable path must surface as this
    harness' contractual ``status:"error"`` record with the reason in
    ``notes`` (HARNESS-SPEC.md), not as an import-time traceback that emits
    no record at all. ``lru_cache`` keeps the files off the per-iteration
    ``login`` path.
    """
    cert_path = os.environ.get("BENCH_CLIENT_CERT", "")
    key_path = os.environ.get("BENCH_CLIENT_KEY", "")
    if not cert_path and not key_path:
        return None, None
    if bool(cert_path) != bool(key_path):
        raise RuntimeError(
            "BENCH_CLIENT_CERT and BENCH_CLIENT_KEY must be set together "
            f"(cert={cert_path!r}, key={key_path!r}) — mTLS needs both "
            "(CONTRACT.md §6.1 rule 1)")
    with open(cert_path, "rb") as fh:
        cert_pem = fh.read()
    with open(key_path, "rb") as fh:
        key_pem = fh.read()
    return cert_pem, key_pem


CFG = {
    "base_url": f"{os.environ.get('BENCH_SCHEME','http')}://"
                f"{os.environ.get('BENCH_HOST','localhost')}:{os.environ.get('BENCH_PORT','8090')}",
    "tenant_slug": os.environ.get("BENCH_TENANT_SLUG", "default"),
    "org_slug": os.environ.get("BENCH_ORG_SLUG", "bench-org"),
    "username": os.environ.get("BENCH_USERNAME", "benchuser"),
    "password": os.environ.get("BENCH_PASSWORD", "Bench@User123!"),
    "action": os.environ.get("BENCH_ACTION", "read"),
    "resource_id": os.environ.get("BENCH_RESOURCE_ID", "bench-resource"),
    "custom_ca": _read_custom_ca(),
}


def new_client():
    """Construct an AxiamClient from CFG.

    Single construction site so the TLS wiring (custom CA + §6.1 client
    identity) cannot drift between the shared client and the fresh one the
    `login` op builds per iteration — under p3-mtls a client built without
    the identity fails the handshake, which would have shown up as `login`
    errors only.
    """
    client_cert, client_key = _read_client_identity()
    return AxiamClient(
        base_url=CFG["base_url"],
        tenant_slug=CFG["tenant_slug"],
        org_slug=CFG["org_slug"],
        custom_ca=CFG["custom_ca"],
        client_cert=client_cert,
        client_key=client_key,
    )

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
    client = new_client()
    client.login(CFG["username"], CFG["password"])
    # Every check reuses the one seeded resource UUID: the server rejects
    # non-UUID resource_ids, so the old `${resource}-${i}` suffixing would 400.
    checks = [
        AccessCheck(action=CFG["action"], resource_id=CFG["resource_id"])
        for _ in range(3)
    ]
    # Fail fast if the grant is missing — otherwise we'd silently benchmark the
    # deny fast-path instead of a real allow decision.
    warm = client.check_access(CFG["action"], CFG["resource_id"])
    if not getattr(warm, "allowed", False):
        raise RuntimeError(
            f"warm-up check_access denied for action={CFG['action']} "
            f"resource_id={CFG['resource_id']} — seed the resource/role/grant "
            "(see runner/seed.sh)")

    def do_login():
        fresh = new_client()
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


def time_op(fn, conc=None):
    """Run fn WARMUP times uncounted, then ITER times measured across `conc`
    worker threads (default CONC). HARNESS-SPEC.md requires `refresh` to be
    measured at concurrency 1 — every SDK guards refresh() with a
    single-flight lock keyed on the in-flight call, but under genuine
    concurrent callers (not just N references to one already-in-flight
    future) the underlying refresh_token is single-use/rotating (opaque,
    server-stored, rotated on every use per CLAUDE.md); overlapping refresh
    attempts race on which token wins, and the loser's reuse of an
    already-rotated token can trip reuse-detection and revoke the whole
    session — cascading into 100% errors on every subsequent check_access/
    batch_check call for the rest of the run. H8 fix: callers must pass
    conc=1 for the refresh op; see main()'s call site below."""
    conc = CONC if conc is None else conc
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

    with cf.ThreadPoolExecutor(max_workers=conc) as ex:
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
        "sdk_version": "1.0.0a2",
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

    # refresh must run at concurrency 1 (HARNESS-SPEC.md) — see time_op's
    # docstring for why concurrent refresh is not just "uninteresting" but
    # actively breaks the session for every op measured after it.
    ops = {k: time_op(fn, conc=1 if k == "refresh" else CONC) for k, fn in ops_fns.items()}
    emit("ok", ops, ITER, CONC, "")


if __name__ == "__main__":
    main()
