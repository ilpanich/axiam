#!/usr/bin/env python3
"""AXIAM Python SDK benchmark (reference harness, wired to axiam_sdk).

Times ``axiam_sdk``'s canonical CONTRACT.md §1 operations — ``login``,
``refresh``, ``check_access``, ``batch_check`` — against a running, seeded
AXIAM target. ``oauth2_token``/``introspect``/``userinfo`` are protocol-level
ops with no SDK wrapper (see ../HARNESS-SPEC.md) and are not measured here.
Keep the stdout JSON contract (axiam.sdk-bench/v1) intact.

I10 (improvement-after-run4-benchmark.md §C/§D): driven through the SDK's
``AsyncAxiamClient`` via ``asyncio``, NOT the synchronous ``AxiamClient``
through a ``ThreadPoolExecutor`` (the pre-I10 shape of this file). The Python
SDK investigation that motivated this found `check_access`'s p50 30.3 ms
(vs. 10-11 ms for Go/Java/Rust at the same concurrency) to be substantially a
harness artifact: driving a synchronous, GIL-bound client through
``ThreadPoolExecutor(max_workers=16)`` sharing one ``httpx.Client`` makes
per-call latency scale ~linearly with thread count while aggregate throughput
stays flat — the Little's-Law fingerprint of a fixed-capacity queueing point
(GIL scheduling + httpcore's single per-pool lock), not extra per-call work.
The SDK ships a dedicated ``AsyncAxiamClient`` (CONTRACT.md SDK-Q08) built on
``httpx.AsyncClient``, which gives ``asyncio`` coroutines genuine concurrent
I/O instead of GIL-serialized OS threads — an apples-to-apples comparison
with Go/Rust/Java's true parallelism.

Run: python3 bench.py   (or: just sdk=python sdk-bench)
"""
import asyncio
import functools
import json
import os
import platform
import sys
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

    AsyncAxiamClient's `custom_ca` accepts EITHER a file path or inline PEM
    text (`_looks_like_pem()` in _session.py) when a client cert is also
    supplied (the mTLS-context branch), but the plain server-trust-only
    branch (`self._verify = custom_ca if custom_ca else True`, no client
    cert) hands the value straight to httpx's `verify=`, which only accepts
    a bool/SSLContext/file-path — NOT inline PEM content (that raises 'File
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
    but `AsyncAxiamClient(client_cert=…, client_key=…)` wants PEM *content*
    (str or bytes — see the SDK's `_tls_identity.normalize_pem`), so read
    them here. Returns (None, None) when unset, leaving the SDK's default
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
    """Construct an AsyncAxiamClient from CFG.

    Single construction site so the TLS wiring (custom CA + §6.1 client
    identity) cannot drift between the shared client and the fresh one the
    `login` op builds per iteration — under p3-mtls a client built without
    the identity fails the handshake, which would have shown up as `login`
    errors only.
    """
    client_cert, client_key = _read_client_identity()
    return AsyncAxiamClient(
        base_url=CFG["base_url"],
        tenant_slug=CFG["tenant_slug"],
        org_slug=CFG["org_slug"],
        custom_ca=CFG["custom_ca"],
        client_cert=client_cert,
        client_key=client_key,
    )


OP_KEYS = ("login", "refresh", "check_access", "batch_check")

try:
    from axiam_sdk import AccessCheck, AsyncAxiamClient

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


async def build_ops():
    """Build one logged-in AsyncAxiamClient and return
    ``({op_key: zero-arg async fn}, client)``.

    ``login`` builds and discards its own short-lived client per call (a
    fresh, unauthenticated session per iteration mirrors what the op
    measures); ``refresh``/``check_access``/``batch_check`` share one
    already-authenticated client — refresh is routed through the SDK's
    single-flight guard, so concurrent callers are safe.
    """
    client = new_client()
    await client.login(CFG["username"], CFG["password"])
    # Every check reuses the one seeded resource UUID: the server rejects
    # non-UUID resource_ids, so the old `${resource}-${i}` suffixing would 400.
    checks = [
        AccessCheck(action=CFG["action"], resource_id=CFG["resource_id"])
        for _ in range(3)
    ]
    # Fail fast if the grant is missing — otherwise we'd silently benchmark the
    # deny fast-path instead of a real allow decision.
    warm = await client.check_access(CFG["action"], CFG["resource_id"])
    if not getattr(warm, "allowed", False):
        raise RuntimeError(
            f"warm-up check_access denied for action={CFG['action']} "
            f"resource_id={CFG['resource_id']} — seed the resource/role/grant "
            "(see runner/seed.sh)")

    async def do_login():
        fresh = new_client()
        try:
            await fresh.login(CFG["username"], CFG["password"])
        finally:
            await fresh.aclose()

    return {
        "login": do_login,
        "refresh": client.refresh,
        "check_access": lambda: client.check_access(CFG["action"], CFG["resource_id"]),
        "batch_check": lambda: client.batch_check(checks),
    }, client


async def time_op(fn, conc=None):
    """Run fn WARMUP times uncounted, then ITER times measured across at
    most `conc` concurrent in-flight coroutines (default CONC), bounded by
    an ``asyncio.Semaphore``. HARNESS-SPEC.md requires `refresh` to be
    measured at concurrency 1 — every SDK guards refresh() with a
    single-flight lock keyed on the in-flight call, but under genuine
    concurrent callers (not just N references to one already-in-flight
    future) the underlying refresh_token is single-use/rotating (opaque,
    server-stored, rotated on every use per CLAUDE.md); overlapping refresh
    attempts race on which token wins, and the loser's reuse of an
    already-rotated token can trip reuse-detection and revoke the whole
    session — cascading into 100% errors on every subsequent check_access/
    batch_check call for the rest of the run. H8 fix (still true under I10's
    asyncio rewrite): callers must pass conc=1 for the refresh op; see
    main()'s call site below."""
    conc = CONC if conc is None else conc
    lat, errors = [], 0
    for _ in range(WARMUP):
        try:
            await fn()
        except Exception:
            errors += 1
    start = time.perf_counter()

    sem = asyncio.Semaphore(max(1, conc))

    async def one():
        nonlocal errors
        async with sem:
            t0 = time.perf_counter()
            try:
                await fn()
                lat.append((time.perf_counter() - t0) * 1000.0)
            except Exception:
                errors += 1

    await asyncio.gather(*(one() for _ in range(ITER)))
    secs = time.perf_counter() - start
    return {"p50_ms": pct(lat, 50), "p95_ms": pct(lat, 95), "p99_ms": pct(lat, 99),
            "throughput_rps": (len(lat) / secs) if secs else 0.0, "errors": errors}


def zero_ops():
    return {k: {"p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "throughput_rps": 0, "errors": 0} for k in OP_KEYS}


# I9 (improvement-after-run4-benchmark.md §C): a floor below which a measured
# `refresh` latency is not plausibly a real HTTP round trip. The C# bench
# recorded p50 1.2 microseconds ("752 k rps") because its SDK's RefreshGuard
# cached a completed token result on a shared client for up to ~15 minutes
# (wall-clock freshness, no observed-token check), so only the FIRST refresh
# in a ~2200-call run ever touched the wire. axiam_sdk's RefreshGuard
# (src/axiam_sdk/token/refresh_guard.py) instead keys on the caller's
# currently observed access token, which this bench's `client.refresh` call
# updates after every real refresh — so a same-client loop keeps hitting the
# wire — but this floor is kept as a language-agnostic regression guard
# against that class of bug reappearing here too (a cache hit completes in
# low single-digit microseconds; every genuine wire call recorded across this
# harness' 11 languages averages ~17 ms, so 0.2 ms leaves a wide margin).
MIN_PLAUSIBLE_REFRESH_MS = 0.2


def assert_refresh_hit_the_wire(refresh_op, iterations):
    """I9 shared-driver-style regression guard: fail loudly (non-zero exit)
    instead of silently publishing a fake number if `refresh` looks like it
    never left the process."""
    had_samples = refresh_op["errors"] < iterations
    if had_samples and refresh_op["p50_ms"] < MIN_PLAUSIBLE_REFRESH_MS:
        print(
            f"[python] I9 guard: refresh p50={refresh_op['p50_ms']:.4f}ms is below the "
            f"{MIN_PLAUSIBLE_REFRESH_MS}ms plausible-wire-call floor despite successful "
            "samples — this looks like a cached no-op (CONTRACT.md §9 guard reuse), not a "
            "real HTTP round trip. Failing the bench run instead of publishing a fake number "
            "(see improvement-after-run4-benchmark.md I9).",
            file=sys.stderr,
        )
        sys.exit(1)


def client_resource_usage():
    """I13 (improvement-after-run4-benchmark.md §C): `client_cpu_ms_total`/
    `client_rss_mib_peak` recorded 0.0 for every SDK bench — the sampler was
    never wired. The stdlib `resource` module gives an exact, cheap
    high-water-mark read with no polling thread needed: `ru_maxrss` is
    already a lifetime peak (not a snapshot), and `ru_utime`/`ru_stime` are
    cumulative CPU seconds since process start — so one read at the end of
    the run, right before `emit()`, captures the whole bench's client-side
    cost. Linux reports `ru_maxrss` in KiB (matches this harness' Docker/K8s
    Linux deployment target per CLAUDE.md); macOS reports bytes, so this is
    normalized for both. Returns (cpu_ms_total, rss_mib_peak); (0.0, 0.0) if
    `resource` is unavailable (e.g. Windows, which lacks the module)."""
    try:
        import resource
    except ImportError:
        return 0.0, 0.0
    usage = resource.getrusage(resource.RUSAGE_SELF)
    cpu_ms_total = (usage.ru_utime + usage.ru_stime) * 1000.0
    # ru_maxrss: KiB on Linux, bytes on macOS/BSD.
    rss_divisor = 1024.0 if sys.platform == "darwin" else 1.0
    rss_mib_peak = usage.ru_maxrss / rss_divisor / 1024.0
    return cpu_ms_total, rss_mib_peak


# D1/J5: which event loop actually ran. Set by __main__ below. Run 5's Python
# row (311 rps, p50 40.2 ms) turned out to be the CPython+httpx per-request
# ceiling rather than anything AXIAM does — three client processes against a
# ZERO-WORK stub server reached 320+308+301 rps, each capped at the same ~310
# — and uvloop moves that ceiling by ~20% of client CPU. A CPU number that
# does not say which loop produced it is therefore not comparable to the next
# run's. See the Python SDK's PERFORMANCE.md.
EVENT_LOOP = "asyncio"


def emit(status, ops, iterations, concurrency, notes):
    cpu_ms_total, rss_mib_peak = client_resource_usage()
    print(json.dumps({
        "schema": "axiam.sdk-bench/v1", "sdk": "python",
        "sdk_version": "1.0.0a2",
        "language_runtime": f"python {platform.python_version()}",
        "target": os.environ.get("BENCH_TARGET", "axiam"),
        "profile": os.environ.get("BENCH_PROFILE", "p0-plaintext"),
        "status": status, "iterations": iterations, "concurrency": concurrency,
        "ops": ops, "client_cpu_ms_total": cpu_ms_total, "client_rss_mib_peak": rss_mib_peak,
        "event_loop": EVENT_LOOP,
        # One process, one event-loop thread: `concurrency` in-flight calls all
        # queue on it. This is published so a reader can see that the Python
        # row's latency is dominated by client-side queueing, not by AXIAM.
        "client_worker_threads": 1,
        "notes": notes,
    }, indent=2))


async def main():
    if not SDK_WIRED:
        emit("pending", zero_ops(), 0, 0,
             f"axiam_sdk not installed — pip install axiam-sdk ({SDK_IMPORT_ERROR}).")
        return

    try:
        ops_fns, client = await build_ops()
    except Exception as exc:  # server not running / seed missing / auth failed
        emit("error", zero_ops(), 0, 0, f"server unreachable or setup failed: {exc}")
        return

    ops = {}
    for k, fn in ops_fns.items():
        # refresh must run at concurrency 1 (HARNESS-SPEC.md) — see time_op's
        # docstring for why concurrent refresh is not just "uninteresting"
        # but actively breaks the session for every op measured after it.
        ops[k] = await time_op(fn, conc=1 if k == "refresh" else CONC)
    await client.aclose()

    emit("ok", ops, ITER, CONC,
         "I10: driven through AsyncAxiamClient via asyncio (genuine concurrent I/O, not a "
         "GIL-bound ThreadPoolExecutor over the sync client) — see "
         "improvement-after-run4-benchmark.md I10.")
    assert_refresh_hit_the_wire(ops["refresh"], ITER)


if __name__ == "__main__":
    # D1/J5: prefer uvloop when the environment has it (axiam-sdk[speed]).
    # Measured on this bench's own check_access path against a zero-work
    # server at 16 in-flight calls: client CPU 2 182 -> 1 735 us/call (-20%),
    # p95 68 -> 55 ms, throughput +7%. Set SDK_BENCH_EVENT_LOOP=asyncio to
    # force the stdlib loop for an A/B; the record says which one ran either
    # way, so the two are never silently mixed in a median.
    _want = os.environ.get("SDK_BENCH_EVENT_LOOP", "auto")
    if _want in ("auto", "uvloop"):
        try:
            import uvloop
            EVENT_LOOP = "uvloop"
        except ImportError:
            if _want == "uvloop":
                print("[python] SDK_BENCH_EVENT_LOOP=uvloop but uvloop is not "
                      "installed — falling back to stdlib asyncio "
                      "(pip install 'axiam-sdk[speed]')", file=sys.stderr)
            uvloop = None
    else:
        uvloop = None

    if uvloop is not None:
        uvloop.run(main())
    else:
        asyncio.run(main())
