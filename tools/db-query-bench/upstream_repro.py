#!/usr/bin/env python3
"""Minimal, AXIAM-free reproduction of SurrealDB 4.0.x per-statement CPU cost.

Not posted anywhere: written to sit beside surrealdb/surrealdb#7667 if the
maintainers want it. Standard library only. Usage:

    surreal start --user root --pass root --bind 127.0.0.1:8000 memory &
    python3 upstream_repro.py 127.0.0.1:8000 <server-pid>

For each statement shape it sends N requests to /sql, one statement shape per
request, sequentially, and reports the server's on-CPU time per request (summed
over every thread, from /proc/<pid>/task/*/schedstat) and the median latency.
Run it against 3.3.x and 4.0.x on the same machine and compare.
"""
import json
import sys
import time
import urllib.request
import uuid
from pathlib import Path

ADDR, PID = sys.argv[1], int(sys.argv[2])
N = int(sys.argv[3]) if len(sys.argv) > 3 else 2000

# A bearer token from one signin, as the Rust SDK's HTTP engine sends it. Basic
# auth on /sql re-verifies the root password (Argon2) on EVERY request, which
# costs ~25 ms of server CPU and would swamp everything measured here.
_signin = urllib.request.Request(
    f"http://{ADDR}/signin", data=b'{"user":"root","pass":"root"}', method="POST"
)
_signin.add_header("Accept", "application/json")
with urllib.request.urlopen(_signin) as _r:
    AUTH = "Bearer " + json.loads(_r.read())["token"]


def sql(text, ns=True):
    req = urllib.request.Request(f"http://{ADDR}/sql", data=text.encode(), method="POST")
    req.add_header("Authorization", AUTH)
    req.add_header("Accept", "application/json")
    if ns:
        # 3.x reads Surreal-NS / Surreal-DB, earlier releases NS / DB.
        for h in ("Surreal-NS", "NS"):
            req.add_header(h, "repro")
        for h in ("Surreal-DB", "DB"):
            req.add_header(h, "repro")
    with urllib.request.urlopen(req) as r:
        out = json.loads(r.read())
    for stmt in out:
        if stmt.get("status") != "OK":
            raise RuntimeError(stmt)
    return out


def cpu_ns():
    total = 0
    for t in Path(f"/proc/{PID}/task").iterdir():
        try:
            total += int((t / "schedstat").read_text().split()[0])
        except OSError:
            pass
    return total


def row(i):
    return (
        f"{{ id: audit:⟨{uuid.uuid4()}⟩, tenant: 't', actor: 'a', action: 'GET /x', "
        f"outcome: 'Success', meta: {{ seq: {i} }} }}"
    )


def measure(name, make, n=N, rows_per_request=1):
    for i in range(50):
        sql(make(i))
    lat = []
    c0 = cpu_ns()
    for i in range(n):
        t = time.perf_counter()
        sql(make(i))
        lat.append(time.perf_counter() - t)
    cpu = cpu_ns() - c0
    lat.sort()
    per = cpu / n / 1e3
    print(
        f"{name:34} cpu/request {per:8.0f} µs   cpu/row {per / rows_per_request:7.0f} µs   "
        f"p50 {lat[len(lat) // 2] * 1e6:7.0f} µs"
    )


sql("DEFINE NAMESPACE IF NOT EXISTS repro; USE NS repro; DEFINE DATABASE IF NOT EXISTS repro;", ns=False)
sql(
    "DEFINE TABLE IF NOT EXISTS audit SCHEMAFULL; "
    "DEFINE FIELD IF NOT EXISTS tenant ON audit TYPE string; "
    "DEFINE FIELD IF NOT EXISTS actor ON audit TYPE string; "
    "DEFINE FIELD IF NOT EXISTS action ON audit TYPE string; "
    "DEFINE FIELD IF NOT EXISTS outcome ON audit TYPE string ASSERT $value IN ['Success', 'Failure']; "
    "DEFINE FIELD IF NOT EXISTS meta ON audit TYPE object FLEXIBLE DEFAULT {}; "
    "DEFINE FIELD IF NOT EXISTS ts ON audit TYPE datetime DEFAULT time::now(); "
    "DEFINE INDEX IF NOT EXISTS audit_tenant_ts ON audit COLUMNS tenant, ts; "
    "DEFINE TABLE IF NOT EXISTS item SCHEMAFULL; "
    "DEFINE FIELD IF NOT EXISTS tenant ON item TYPE string; "
    "DEFINE FIELD IF NOT EXISTS name ON item TYPE string;"
)
sql("FOR $i IN 0..1000 { CREATE type::record('item', <string> $i) SET tenant = 't', name = 'n' };")

print(f"server pid {PID}, {N} sequential requests per shape")
measure("RETURN 1", lambda i: "RETURN 1;")
measure("SELECT one record by id", lambda i: f"SELECT * FROM item:⟨{i % 1000}⟩ WHERE tenant = 't';")
measure("CREATE one row", lambda i: f"CREATE audit CONTENT {row(i)} RETURN NONE;")
measure(
    "8 CREATE statements, one request",
    lambda i: " ".join(f"CREATE audit CONTENT {row(i * 8 + k)} RETURN NONE;" for k in range(8)),
    n=N // 8,
    rows_per_request=8,
)
measure(
    "INSERT 8 rows, one statement",
    lambda i: f"INSERT INTO audit [{', '.join(row(i * 8 + k) for k in range(8))}] RETURN NONE;",
    n=N // 8,
    rows_per_request=8,
)
measure(
    "INSERT 64 rows, one statement",
    lambda i: f"INSERT INTO audit [{', '.join(row(i * 64 + k) for k in range(64))}] RETURN NONE;",
    n=max(N // 64, 20),
    rows_per_request=64,
)
out = sql("RETURN [time::now(), time::now()];")
a, b = out[0]["result"]
print(f"time::now() twice in one statement: {'same instant' if a == b else 'distinct instants'}")
