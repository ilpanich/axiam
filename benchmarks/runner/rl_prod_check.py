#!/usr/bin/env python3
"""rl_prod_check.py — I19 (improvement-after-run4-benchmark.md §D): per-endpoint
expected-admission assertions for a `rl=prod` (shipped rate-limit posture)
sensitivity pass.

Before this script, the "admitted ≈ configured" check that caught I1's gRPC
×60 units bug was done BY HAND by an analyst reading k6 summaries. This
script automates exactly that comparison — configured limit vs. measured
admission rate, per endpoint — for a results tree produced by a `rl=prod`
pass (`just rl=prod target=axiam ... bench-run` / `bench-matrix`), and:

  - prints PASS/FAIL per endpoint (exit 1 if any FAIL, so a units-bug class
    of regression fails the harness/CI instead of an analyst's manual read),
  - writes a small `rl-prod-summary.md` (configured vs. admitted, per
    endpoint) into the results dir.

Configured limits are NOT hardcoded here — hardcoding them would silently go
stale the next time someone tunes a default. Instead this script extracts
the current numeric defaults directly (regex, READ-ONLY) from the two files
that actually own them:

  - crates/axiam-api-rest/src/config/rate_limit.rs
    (`impl Default for RateLimitConfig`: login/register/password_reset/mfa/
    token/introspect/revoke/authz_check, the B2/B3/X2 device, token-exchange
    and UMA buckets, and the B4 `scim` bucket — each already per-minute)
  - crates/axiam-api-grpc/src/config.rs + .../middleware/rate_limit.rs
    (`default_grpc_authz_per_sec()`, `IDENTITY_PER_SEC_MULTIPLE`,
    `ADMIN_PER_SEC_DEFAULT`, `INFRA_PER_SEC`, and `WINDOW_SECS` — the I1 fix
    means gRPC admits `per_sec * WINDOW_SECS` per window, not `per_sec` per
    window)

SEC-079 note: admin used to track authz 1:1, and this script hard-coded that
ratio. It no longer does — `GrpcRateLimits::from_authz_per_sec` pins admin to
the absolute `ADMIN_PER_SEC_DEFAULT`, *independently of authz and of any
posture preset*, precisely so raising the mesh authz ceiling can never raise
the administrative one. A fourth family (`Infra`: reflection + health) was
added at the fixed `INFRA_PER_SEC`; it used to be unlimited. Both are now
extracted from source like everything else rather than assumed here.

This only reflects the shipped `internet` posture defaults (no
`AXIAM__RATE_LIMIT__*` override, no `gateway`/`mesh` preset) — pass
--configured-json to override any field for a run against a different
posture/override set (e.g. a `gateway`-preset rl=prod pass).

Results layout (M2): `--results` accepts either tree the harness produces —
the flat `<results>/<target>/<profile>/…` a plain `bench-run` writes, or the
`<results>/run-<i>/<target>/<profile>/…` a `bench-matrix` pass writes (which
it does even at `repeat=1`). Reading only the flat one made a bare
`just rl-prod-check` against a matrix tree report "no data" for every
endpoint — a whole rl=prod pass silently unverified. Multi-pass trees are
medianed per cell, the same aggregation `report.py` applies.

Usage:
    python3 rl_prod_check.py --results results --target axiam --profile p0-plaintext
    python3 rl_prod_check.py --results results --target axiam --profile p0-plaintext \\
        --configured-json '{"token_per_min": 6000}'   # e.g. gateway preset override
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))  # runner/ -> benchmarks/ -> repo root

REST_RATE_LIMIT_RS = os.path.join(
    REPO_ROOT, "crates", "axiam-api-rest", "src", "config", "rate_limit.rs")
GRPC_CONFIG_RS = os.path.join(REPO_ROOT, "crates", "axiam-api-grpc", "src", "config.rs")
GRPC_RATE_LIMIT_RS = os.path.join(
    REPO_ROOT, "crates", "axiam-api-grpc", "src", "middleware", "rate_limit.rs")

# I1's own acceptance bar ("admitted-per-minute ≈ configured×60 (±10%)"),
# reused uniformly here for every endpoint, REST and gRPC alike.
TOLERANCE = 0.10

# C1's per-pass directory shape, as `report.py` spells it (`RUN_DIR_RE` there).
# `bench-matrix` writes `results/run-<i>/<target>/<profile>/…` even at
# `repeat=1`; see load_k6_admitted_per_min for why this script has to know.
RUN_DIR_RE = re.compile(r"run-\d+")

# endpoint key -> (k6 scenario filename, human label).
#
# Run-5 J1c closed the last three holes: `revoke`, `grpc_admin` and
# `grpc_infra` had no scenario at all, so a third of the limiter families
# reported "no scenario — not checked" and the public §7 verdict table could
# not speak to them. All eight families now have one, which is the point —
# an unmeasured limiter is an unverified limiter, and the two gRPC ones it
# left unmeasured were the CPU guard (Argon2id) and the unauthenticated
# surface (reflection/health).
#
# The scenario=None path is kept (not deleted) so that adding a ninth family
# without a scenario degrades to an honest "not checked" row rather than
# silently vanishing from the table.
#
# R5.2 (A1 §5 / J1c follow-on) added the five rows below: the device family
# (B2's own buckets, `device_authorization_per_min`/`device_verify_per_min`),
# `token_exchange_per_min` (B3, RFC 8693) and the two UMA 2.0 buckets (X2,
# `uma_perm_per_min`/`uma_ticket_per_min`) all shipped with a configured
# limit and no scenario driving it — the same hole J1c closed for
# revoke/grpc_admin/grpc_infra in run 5. The R5.2 tail then closed the
# inverse hole for SCIM: a shipped ENDPOINT with no configured limit at all.
# Every rate-limited family AXIAM ships now has a row here.
ENDPOINTS = {
    "login_per_min": ("oauth2_password_login.js", "POST /api/v1/auth/login"),
    "token_per_min": ("oauth2_client_credentials.js", "POST /oauth2/token (client_credentials)"),
    "introspect_per_min": ("token_introspection.js", "POST /oauth2/introspect"),
    "revoke_per_min": ("oauth2_revoke.js", "POST /oauth2/revoke"),
    "authz_check_per_min": ("authz_check_rest.js", "POST /api/v1/authz/check"),
    "authz_batch_per_min": ("authz_batch_rest.js", "POST /api/v1/authz/check/batch (shares authz_check_per_min)"),
    "grpc_authz_per_min": ("authz_check_grpc.js", "gRPC AuthzService/Check (grpc_authz family)"),
    "grpc_identity_per_min": ("userinfo_grpc.js", "gRPC UserInfoService/GetUserInfo (grpc_identity family)"),
    "grpc_admin_per_min": ("grpc_admin_validate.js", "gRPC UserService/ValidateCredentials (grpc_admin family, SEC-079 absolute)"),
    "grpc_infra_per_min": ("grpc_infra.js", "gRPC reflection + health (grpc_infra family, fixed ceiling)"),
    "device_authorization_per_min": (
        "device_authorization.js",
        "POST /oauth2/device_authorization (RFC 8628 device flow)",
    ),
    "device_verify_per_min": (
        "device_verify.js",
        "GET /api/v1/device/verify (device flow, user-code lookup; shares device_verify_per_min with /device/decide)",
    ),
    "token_exchange_per_min": ("token_exchange.js", "POST /oauth2/token (token-exchange grant, RFC 8693)"),
    "uma_perm_per_min": ("uma2_perm.js", "POST /uma2/perm (UMA 2.0 permission ticket)"),
    "uma_ticket_per_min": ("uma_ticket_grant.js", "POST /oauth2/token (uma-ticket grant)"),
    # R5.2 tail: SCIM (B4) was the last family with no bucket at all —
    # `axiam-scim` landed in R3.1 exposing /scim/v2 with no `scim_*_per_min`
    # field anywhere in `crates/`. It now has one, sized at the gRPC Admin
    # family's absolute 600/min ceiling (see `RateLimitConfig::scim_per_min`).
    # ONE bucket covers the whole scope — reads, writes and the RFC 7643
    # discovery endpoints — so there is one row here, not two.
    "scim_per_min": (
        "scim_provisioning.js",
        "PATCH /scim/v2/Users/{id} (SCIM 2.0 provisioning, B4; one bucket spans all of /scim/v2)",
    ),
}


def _extract_int(text, pattern, label, path):
    m = re.search(pattern, text)
    if not m:
        raise RuntimeError(f"could not find {label} in {path} (pattern: {pattern!r}) — "
                            "the source may have moved; update rl_prod_check.py's extraction")
    return int(m.group(1).replace("_", ""))


def _extract_default_impl_block(path):
    """Isolate ONLY the `impl Default for RateLimitConfig { ... }` block's
    text. The file also defines `gateway`/`mesh` PRESET struct literals
    earlier (RateLimitProfile::Gateway/::Mesh apply_rate_limit_preset
    tables) that reuse the SAME field names with different numbers — a
    plain whole-file regex search finds whichever occurrence comes first in
    the file, which is one of the presets, not the shipped `internet`
    default. Scoping to this block is what makes the extraction correct."""
    with open(path) as f:
        text = f.read()
    m = re.search(r"impl Default for RateLimitConfig\s*\{.*?\n\}\n", text, re.DOTALL)
    if not m:
        raise RuntimeError(
            f"could not find 'impl Default for RateLimitConfig' in {path} — "
            "the source may have moved; update rl_prod_check.py's extraction")
    return m.group(0)


def read_configured_defaults():
    """READ-ONLY extraction of the current shipped `internet` posture
    defaults from the two rate-limit config files. Never writes to either
    file."""
    default_block = _extract_default_impl_block(REST_RATE_LIMIT_RS)
    rest_defaults = {}
    for field in ("login_per_min", "register_per_min", "password_reset_per_min",
                  "mfa_per_min", "token_per_min", "introspect_per_min",
                  "revoke_per_min", "authz_check_per_min",
                  # R5.2: B2/B3/X2 buckets — same extraction, no special-casing.
                  "device_authorization_per_min", "device_verify_per_min",
                  "token_exchange_per_min", "uma_perm_per_min", "uma_ticket_per_min",
                  # R5.2 tail: B4 SCIM — same extraction, no special-casing.
                  "scim_per_min"):
        rest_defaults[field] = _extract_int(
            default_block, rf"\b{field}:\s*([0-9_]+)", field, REST_RATE_LIMIT_RS)

    with open(GRPC_CONFIG_RS) as f:
        grpc_config_text = f.read()
    with open(GRPC_RATE_LIMIT_RS) as f:
        grpc_rate_limit_text = f.read()

    grpc_authz_per_sec = _extract_int(
        grpc_config_text, r"fn default_grpc_authz_per_sec\(\)\s*->\s*u32\s*\{\s*([0-9_]+)\s*\}",
        "default_grpc_authz_per_sec", GRPC_CONFIG_RS)
    identity_multiple = _extract_int(
        grpc_rate_limit_text, r"IDENTITY_PER_SEC_MULTIPLE:\s*u32\s*=\s*([0-9_]+)",
        "IDENTITY_PER_SEC_MULTIPLE", GRPC_RATE_LIMIT_RS)
    window_secs = _extract_int(
        grpc_rate_limit_text, r"WINDOW_SECS:\s*i64\s*=\s*([0-9_]+)", "WINDOW_SECS", GRPC_RATE_LIMIT_RS)
    # identity_per_sec is still a MULTIPLE of authz (I2). admin_per_sec is NOT:
    # SEC-079 decoupled it to an absolute constant so widening the mesh authz
    # ceiling cannot widen the administrative one. Extract both, assume neither.
    admin_per_sec_default = _extract_int(
        grpc_rate_limit_text, r"ADMIN_PER_SEC_DEFAULT:\s*u32\s*=\s*([0-9_]+)",
        "ADMIN_PER_SEC_DEFAULT", GRPC_RATE_LIMIT_RS)
    # Infra (reflection + health) is a fixed ceiling, not configurable per
    # instance — `GrpcRateLimits::per_sec` returns INFRA_PER_SEC directly.
    infra_per_sec = _extract_int(
        grpc_rate_limit_text, r"INFRA_PER_SEC:\s*u32\s*=\s*([0-9_]+)",
        "INFRA_PER_SEC", GRPC_RATE_LIMIT_RS)
    grpc_identity_per_sec = grpc_authz_per_sec * identity_multiple
    grpc_admin_per_sec = admin_per_sec_default

    configured = dict(rest_defaults)
    configured["authz_batch_per_min"] = rest_defaults["authz_check_per_min"]
    # I1 fix: the gRPC shared window admits per_sec * WINDOW_SECS per window,
    # i.e. per-minute admission == per_sec * 60 (WINDOW_SECS is 60 today but
    # read from source rather than assumed, in case it ever changes).
    configured["grpc_authz_per_min"] = grpc_authz_per_sec * window_secs
    configured["grpc_identity_per_min"] = grpc_identity_per_sec * window_secs
    configured["grpc_admin_per_min"] = grpc_admin_per_sec * window_secs
    configured["grpc_infra_per_min"] = infra_per_sec * window_secs
    return configured


def _import_report():
    """Import runner/report.py without leaving `runner/` on sys.path."""
    sys.path.insert(0, HERE)
    try:
        import report as bench_report  # runner/report.py
    finally:
        if HERE in sys.path:
            sys.path.remove(HERE)
    return bench_report


def _admitted_per_min_from_cell_dir(bench_report, cell_dir, scenario_file):
    """ops/min actually admitted (bench_ok) for one flat
    `<target>/<profile>/` cell dir, or None when that cell wasn't run."""
    meta_path = os.path.join(cell_dir, f"{scenario_file[:-3]}.meta.json")
    if not os.path.exists(meta_path):
        return None
    with open(meta_path) as f:
        meta = json.load(f)
    k6_path = os.path.join(cell_dir, meta.get("k6_summary_file", ""))
    if not os.path.exists(k6_path):
        return None
    perf = bench_report.load_k6_summary(k6_path)
    return perf["throughput"] * 60.0  # ops/s -> ops/min


def run_dirs(results):
    """M2: the `results/run-<i>/` passes inside `results`, sorted, or [] for a
    classic flat tree. Same detection `report.collect` does (RUN_DIR_RE), kept
    here rather than imported so the two can be read side by side."""
    try:
        entries = sorted(os.listdir(results))
    except OSError:
        return []
    return [os.path.join(results, e) for e in entries
            if RUN_DIR_RE.fullmatch(e) and os.path.isdir(os.path.join(results, e))]


def load_k6_admitted_per_min(results, target, profile, scenario_file):
    """Best-effort: ops/min actually admitted (bench_ok), read via the same
    report.py helper report.py itself uses, so this script can never drift
    from how the main report computes throughput.

    M2: `bench-matrix` writes `results/run-<i>/<target>/<profile>/…` even at
    `repeat=1`, while a plain `bench-run` writes the flat
    `results/<target>/<profile>/…`. Reading only the flat layout meant a
    matrix tree reported "no data" for EVERY endpoint — a whole rl=prod pass
    silently unverified. Try flat first (unchanged behaviour for a
    `BENCH_RESULTS_DIR`-scoped single cell), then fall back to the `run-*/`
    passes, medianing across them exactly as `report.aggregate_cell` does so
    the two scripts never disagree about a repeat>1 tree."""
    bench_report = _import_report()

    flat = _admitted_per_min_from_cell_dir(
        bench_report, os.path.join(results, target, profile), scenario_file)
    if flat is not None:
        return flat

    per_run = [_admitted_per_min_from_cell_dir(
                   bench_report, os.path.join(d, target, profile), scenario_file)
               for d in run_dirs(results)]
    per_run = [v for v in per_run if v is not None]
    if not per_run:
        return None
    return bench_report.median(per_run)


def check(results, target, profile, configured_overrides):
    configured = read_configured_defaults()
    configured.update(configured_overrides or {})

    rows = []
    any_fail = False
    for field, (scenario_file, label) in ENDPOINTS.items():
        configured_limit = configured[field]
        if scenario_file is None:
            rows.append((label, configured_limit, None, "no scenario — not checked"))
            continue
        admitted = load_k6_admitted_per_min(results, target, profile, scenario_file)
        if admitted is None:
            rows.append((label, configured_limit, None, "no data (run this cell under rl=prod first)"))
            continue
        low, high = configured_limit * (1 - TOLERANCE), configured_limit * (1 + TOLERANCE)
        verdict = "PASS" if low <= admitted <= high else "FAIL"
        if verdict == "FAIL":
            any_fail = True
        rows.append((label, configured_limit, admitted, verdict))

    return rows, any_fail


def _layout_note(results):
    """One line of provenance: which results layout the admitted numbers were
    read from. A matrix tree's cells are medianed across its passes, a flat
    tree's are a single measurement — the reader should not have to guess."""
    passes = len(run_dirs(results))
    if passes == 0:
        return ("Layout: flat single-run tree (`<target>/<profile>/…`); each admitted "
                "figure is one measured cell.")
    if passes == 1:
        return ("Layout: `bench-matrix` tree with 1 pass (`run-1/<target>/<profile>/…`); "
                "each admitted figure is that single pass's cell.")
    return (f"Layout: `bench-matrix` tree with {passes} passes "
            "(`run-<i>/<target>/<profile>/…`); each admitted figure is the MEDIAN "
            "across the passes that ran the cell, as `report.py` aggregates.")


def write_summary(results, profile, rows):
    lines = [
        "# rl-prod sensitivity summary (I19)",
        "",
        f"Profile: `{profile}`. Configured limits extracted read-only from "
        "`crates/axiam-api-rest/src/config/rate_limit.rs` and "
        "`crates/axiam-api-grpc/src/{config.rs,middleware/rate_limit.rs}` "
        f"(shipped `internet` posture unless overridden). Tolerance: ±{int(TOLERANCE * 100)}% "
        "(I1's own acceptance bar).",
        "",
        _layout_note(results),
        "",
        "| endpoint | configured (per min) | admitted (per min) | verdict |",
        "|---|---|---|---|",
    ]
    for label, configured_limit, admitted, verdict in rows:
        configured_str = configured_limit if configured_limit is not None else "—"
        admitted_str = f"{admitted:.0f}" if admitted is not None else "—"
        lines.append(f"| {label} | {configured_str} | {admitted_str} | {verdict} |")
    lines += ["", "A `FAIL` here is exactly the shape of bug I1 was — a units/scoping "
              "mismatch between the configured limit and what the server actually "
              "admits — caught by this script instead of a by-hand k6-summary read."]
    out_path = os.path.join(results, "rl-prod-summary.md")
    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return out_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--target", default="axiam")
    ap.add_argument("--profile", default="p0-plaintext")
    ap.add_argument("--configured-json", default=None,
                     help="JSON object overriding any configured-limit field "
                          "(e.g. a gateway/mesh preset's numbers)")
    args = ap.parse_args()

    overrides = json.loads(args.configured_json) if args.configured_json else {}
    rows, any_fail = check(args.results, args.target, args.profile, overrides)
    out_path = write_summary(args.results, args.profile, rows)

    print(f"wrote {out_path}")
    for label, configured_limit, admitted, verdict in rows:
        configured_str = f"{configured_limit}/min" if configured_limit is not None else "—"
        admitted_str = f"{admitted:.0f}/min" if admitted is not None else "—"
        print(f"  [{verdict:>4}] {label}: configured={configured_str} admitted={admitted_str}")

    if any_fail:
        print("[rl-prod-check] FAIL: at least one endpoint's admission rate is outside "
              f"±{int(TOLERANCE * 100)}% of its configured limit — see rl-prod-summary.md", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
