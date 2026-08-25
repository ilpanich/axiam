#!/usr/bin/env python3
"""Grade one SDK bench record for `sdk/dry-run.sh`.

Reads the record a language bench wrote to stdout and prints ONE line:

    <VERDICT><space><detail...>

so the caller can `read -r verdict detail`. VERDICT is PASS / WARN / SKIP /
FAIL, matching the vocabulary `just bench-dry-run` already uses for k6 cells.

The grading is the SDK client contract, never performance:

  PASS  a well-formed `status:"ok"` record whose four contractual ops
        (HARNESS-SPEC.md) all completed with zero errors
  WARN  it worked, but something about it should not be trusted silently —
        a non-zero exit alongside an ok record, or errors on an OPTIONAL op
  SKIP  `status:"pending"` — the toolchain or SDK package is not installed
        here. That is a fact about this machine, not about the SDK, so it must
        never fail the sweep (same rule as test-client-cert-wiring.sh)
  FAIL  anything else: a build that died, no record at all, a malformed one,
        `status:"error"`, a missing contractual op, or errors on one

Env: SDK_NAME, RC (the bench's exit status), SECS (wall clock).
"""

import json
import os
import re
import sys

# HARNESS-SPEC.md §"Operations": every bench must implement these four.
# `userinfo_grpc` is deliberately absent — it is optional and REST-only SDKs
# (Kotlin, Swift, C, C++) must not implement it at all.
REQUIRED_OPS = ("login", "refresh", "check_access", "batch_check")

SCHEMA = "axiam.sdk-bench/v1"


def emit(verdict: str, detail: str) -> None:
    # One line, always — the caller splits on the first space.
    print(f"{verdict} {' '.join(detail.split())}")
    sys.exit(0)


def main() -> None:
    path = sys.argv[1]
    sdk = os.environ.get("SDK_NAME", "?")
    rc = os.environ.get("RC", "?")
    secs = os.environ.get("SECS", "?")

    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError as exc:
        emit("FAIL", f"could not read the record file ({exc})")

    if not raw.strip():
        emit(
            "FAIL",
            f"exited {rc} after {secs}s and wrote no record at all — this is "
            f"almost always a build failure; see {sdk}.dryrun.log",
        )

    # Be forgiving about a bench that prints a stray line alongside its record:
    # take the outermost {...} rather than demanding the whole file parse.
    try:
        rec = json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", raw, re.S)
        if not match:
            emit(
                "FAIL",
                f"exited {rc} and its stdout is not a JSON record — "
                f"see {sdk}.dryrun.log",
            )
        try:
            rec = json.loads(match.group(0))
        except json.JSONDecodeError as exc:
            emit("FAIL", f"emitted malformed JSON ({exc.msg}) — see {sdk}.dryrun.log")

    if not isinstance(rec, dict):
        emit("FAIL", "emitted JSON that is not an object")

    if rec.get("schema") != SCHEMA:
        emit("FAIL", f"schema is {rec.get('schema')!r}, expected {SCHEMA!r}")

    status = rec.get("status")
    notes = " ".join(str(rec.get("notes") or "").split())

    if status == "pending":
        emit("SKIP", notes or "toolchain or SDK package not installed here")

    if status == "error":
        emit("FAIL", notes or f"emitted status:\"error\" with no notes — see {sdk}.dryrun.log")

    if status != "ok":
        emit("FAIL", f"status is {status!r}, expected one of ok/pending/error")

    ops = rec.get("ops")
    if not isinstance(ops, dict):
        emit("FAIL", "record has no `ops` object")

    missing = [op for op in REQUIRED_OPS if op not in ops]
    if missing:
        emit("FAIL", f"record omits contractual op(s): {', '.join(missing)}")

    def errors_of(name: str) -> int:
        entry = ops.get(name)
        if not isinstance(entry, dict):
            return 0
        try:
            return int(entry.get("errors") or 0)
        except (TypeError, ValueError):
            return 0

    broken = [(op, errors_of(op)) for op in REQUIRED_OPS if errors_of(op) > 0]
    if broken:
        detail = ", ".join(f"{op}={n}" for op, n in broken)
        emit(
            "FAIL",
            f"built and ran, but contractual op(s) errored against the server: "
            f"{detail} of {rec.get('iterations', '?')} iterations — see {sdk}.dryrun.log",
        )

    optional_broken = [
        (op, errors_of(op))
        for op in ops
        if op not in REQUIRED_OPS and errors_of(op) > 0
    ]

    runtime = rec.get("language_runtime") or "?"
    version = rec.get("sdk_version") or "?"

    if optional_broken:
        detail = ", ".join(f"{op}={n}" for op, n in optional_broken)
        emit(
            "WARN",
            f"{version} on {runtime}: the four contractual ops are clean, but "
            f"optional op(s) errored: {detail}",
        )

    if rc not in ("0", "?"):
        emit(
            "WARN",
            f"{version} on {runtime}: emitted a clean record but exited {rc} — "
            f"see {sdk}.dryrun.log",
        )

    def p50(name: str) -> str:
        entry = ops.get(name) or {}
        value = entry.get("p50_ms")
        return "?" if value is None else f"{value:g}" if isinstance(value, (int, float)) else str(value)

    emit(
        "PASS",
        f"{version} on {runtime}, {secs}s — p50 login={p50('login')}ms "
        f"refresh={p50('refresh')}ms check={p50('check_access')}ms "
        f"batch={p50('batch_check')}ms",
    )


if __name__ == "__main__":
    main()
