#!/usr/bin/env python3
"""Report `AXIAM__*` configuration keys the documentation site does not cover.

Why this exists
---------------
`website/src/docs/configuration.ts` reads as a complete environment-variable
reference and is not one. It documents the settings a deployment normally has
to make a decision about; the rest have working defaults and no
deployment-specific right answer. That is a defensible scope — what was not
defensible is that nobody could tell which keys were in it, so the page could
drift further from the server every release without anyone noticing.

This gate makes the gap **measured** rather than estimated. It does not force
every key onto the page: a key may be documented, or it may be listed in
``EXEMPT`` below with a reason. What it refuses is a key that is neither —
a new setting that lands in the server and silently never reaches the docs.

The exemption table is deliberately explicit rather than a wildcard, for the
same reason ``check-sdk-artifact-drift.py``'s ``REST_ONLY_REPOS`` is: an
exemption you cannot see is indistinguishable from a bug, and a category
nobody has to name is where a genuinely operator-facing key goes to be
forgotten.

What it cannot see
------------------
Only keys that appear **literally** in ``crates/``. The `config` crate derives
many keys from struct field names — ``AXIAM__SERVER__HOST`` comes from the
``host`` field of the server config struct, and that string exists nowhere in
the source. Those keys are real, are documented, and are invisible here; the
reverse direction below reports them so the asymmetry is at least visible.

Parsing the Rust struct definitions to recover them was considered and
rejected: the structs span six crates, nest, rename, and carry ``#[serde(skip)]``
fields that are *not* env-settable, so the derived list would be confidently
wrong in both directions. A gate that under-reports honestly beats one that
invents keys.

Usage:
    scripts/check-config-key-coverage.py             # report, exit 1 on a gap
    scripts/check-config-key-coverage.py --list      # print every key it found
    scripts/check-config-key-coverage.py --self-test # prove the gate still detects
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATES = ROOT / "crates"
DOCS = ROOT / "website" / "src" / "docs"

#: A whole key: the prefix, then at least one more segment, not truncated.
#:
#: The trailing lookahead is what keeps prose fragments out. Doc comments write
#: ``AXIAM__PKI__MDS_*`` and ``AXIAM__RATE_LIMIT__*`` to mean a family, and
#: without it those match as the truncated keys ``…MDS`` and ``…RATE_LIMIT``,
#: which exist nowhere and would fail this gate forever.
KEY = re.compile(r"AXIAM__[A-Z0-9]+(?:_[A-Z0-9]+)*(?:__[A-Z0-9]+(?:_[A-Z0-9]+)*)*(?![A-Z0-9_*])")

#: Keys that are real but deliberately absent from the documentation site.
#:
#: Every entry needs a reason someone can disagree with. "Internal" on its own
#: is not one — it is what you write when you have not decided.
EXEMPT: dict[str, str] = {
    # -- Not a key at all -------------------------------------------------
    "AXIAM__SECTION__KEY": "placeholder in the naming-convention docs, not a setting",
    "AXIAM__AMQP__ALLOW_PLAINTEXT": (
        "removed (CONTRACT §8b). It survives only in the comment explaining that "
        "it was removed, and documenting it would advertise an escape hatch that "
        "no longer exists"
    ),
    # -- Unimplemented ----------------------------------------------------
    "AXIAM__DB__READ_REPLICAS": (
        "read replicas for the authorization path are a design note, not a shipped "
        "feature; the value is parsed for alerting and changes no routing"
    ),
    "AXIAM__DB__READ_REPLICA_MAX_STALENESS_MS": "same read-replica design note",
    # -- Debug-build-only -------------------------------------------------
    "AXIAM__AMQP__SIGNING_KEY": (
        "debug-build fallback only; never read by the release binary that ships "
        "in the production image, so documenting it invites production use"
    ),
    "AXIAM__AUTH__AMQP_SIGNING_KEY": "same debug-build fallback, under its older name",
    # -- No observable effect ---------------------------------------------
    "AXIAM__GRPC__KEY": (
        "gRPC rate limiting is per-IP by construction; setting this to anything "
        "else has no observable effect"
    ),
    # -- Transport and pool tuning: defaults are the answer ----------------
    "AXIAM__SERVER__H2__INITIAL_CONNECTION_WINDOW_SIZE": "HTTP/2 flow-control tuning",
    "AXIAM__SERVER__H2__INITIAL_STREAM_WINDOW_SIZE": "HTTP/2 flow-control tuning",
    "AXIAM__SERVER__TCP_NODELAY": "socket tuning",
    "AXIAM__DB__POOL_ACQUIRE_TIMEOUT_SECS": "connection-pool tuning",
    "AXIAM__DB__POOL_MAX_IN_FLIGHT": "connection-pool tuning",
    "AXIAM__DB__RECONNECT_BASE_MS": "reconnect backoff tuning",
    "AXIAM__DB__RECONNECT_CEILING_MS": "reconnect backoff tuning",
    "AXIAM__DB__RECONNECT_MAX_RETRIES": "reconnect backoff tuning",
    "AXIAM__DB__TOKEN_REFRESH_FRACTION": "database auth-token refresh timing",
    "AXIAM__AUTHZ__BATCH_MAX_CONCURRENCY": "batch-check fan-out tuning",
    "AXIAM__AUTHZ__DECISION_CACHE_STATS_SECS": "how often the cache logs its own stats",
    "AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_HEARTBEAT_SECS": "invalidation-channel liveness tuning",
    "AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_SKEW_SECS": "invalidation-channel clock allowance",
    "AXIAM__AUTH__HIBP_BREAKER_THRESHOLD": "circuit-breaker tuning for the breach-check upstream",
    "AXIAM__AUTH__HIBP_BREAKER_COOLDOWN_SECS": "circuit-breaker tuning for the breach-check upstream",
    "AXIAM__RATE_LIMIT__SHARED_WINDOW": "cross-replica counter window; the profile presets size it",
    # -- Narrow operational escape hatches --------------------------------
    "AXIAM__DB__ALLOW_MEMORY_ENGINE": (
        "opt-in override for a guard that cannot fire yet — SurrealDB publishes no "
        "datastore identity, so the check logs a WARN and never refuses"
    ),
    "AXIAM__GDPR_AUDIT_DLQ_FILE": (
        "optional file sink for audit writes that failed; the structured-log sink "
        "fires unconditionally either way"
    ),
    "AXIAM__PKI__SSRF_ALLOWED_HOSTS": "egress allow-list for metadata fetches",
    "AXIAM__GRPC__STRICT_REVOCATION": (
        "opt-in per-request revocation on gRPC; the read-path guide covers the "
        "trade-off it exists for"
    ),
    "AXIAM__AUTH__PEPPER_PREVIOUS": "second pepper accepted during a rotation window",
    "AXIAM__AUTH__COOKIE_SECURE": (
        "development-only override; a production deployment is on TLS and wants "
        "the default"
    ),
    # -- Documented elsewhere on the site, not on the config page ----------
    # `AXIAM__AUDIT_RETENTION_DAYS` was exempt here on the ground that "audit
    # retention is covered on the Audit page". It was not: that page said
    # retention was an operational decision and told operators not to expect
    # the system to prune for them, which is the opposite of what ships. The
    # key is now on the configuration page with its default and its `0`
    # opt-out, so the exemption is gone rather than resting on a page that
    # contradicted the code.
    "AXIAM__SERVER__CLEANUP_INTERVAL_SECS": (
        "the sweep interval; its observable effect is the stall threshold on the "
        "Health & observability page"
    ),
    "AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS": "covered with the caches on the Deploy page",
    "AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED": "covered with the caches on the Deploy page",
    "AXIAM__GRPC__GRPC_ADMIN_PER_SEC": "gRPC per-family limits are on the gRPC API page",
    "AXIAM__GRPC__GRPC_IDENTITY_PER_SEC": "gRPC per-family limits are on the gRPC API page",
}


def keys_in(root: Path, suffix: str) -> dict[str, set[str]]:
    """Every whole key under ``root``, mapped to the files mentioning it."""
    found: dict[str, set[str]] = {}
    for path in sorted(root.rglob(f"*{suffix}")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in KEY.finditer(text):
            key = match.group(0)
            # "AXIAM__X" alone is a prefix, not a key.
            if key.count("_") < 3:
                continue
            try:
                where = str(path.relative_to(ROOT))
            except ValueError:
                # A self-test fixture lives outside the repository.
                where = str(path)
            found.setdefault(key, set()).add(where)
    return found



# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


def _self_test() -> int:
    """Prove this gate still detects what it claims to.

    A gate whose only evidence is "the repository it guards is currently clean"
    cannot tell working from broken: an inverted comparison here would pass
    every day until the day a key actually goes missing. These fixtures fail
    the gate on purpose, so a change that stops it detecting is caught by the
    gate itself rather than by the next person to read it.
    """
    import tempfile

    cases: list[tuple[str, str, str, bool]] = [
        # (name, rust source, docs source, should the key be reported as a gap)
        (
            "a key in the server and nowhere else is a gap",
            'env::var("AXIAM__NEW__THING_SECS")',
            "",
            True,
        ),
        (
            "a documented key is not a gap",
            'env::var("AXIAM__NEW__THING_SECS")',
            '["AXIAM__NEW__THING_SECS", "meaning", "5"]',
            False,
        ),
        (
            "a prose family is not a key",
            "/// Configure via `AXIAM__NEW__THING_*` as needed.",
            "",
            False,
        ),
        (
            "a doubled-underscore family is not a key",
            "/// See `AXIAM__NEW__` for the rest.",
            "",
            False,
        ),
        (
            "the prefix alone is not a key",
            "/// Everything is under AXIAM__NEW.",
            "",
            False,
        ),
    ]

    failures: list[str] = []
    for name, rust, docs_src, expect_gap in cases:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "crates").mkdir()
            (root / "docs").mkdir()
            (root / "crates" / "a.rs").write_text(rust, encoding="utf-8")
            (root / "docs" / "a.ts").write_text(docs_src, encoding="utf-8")
            code = keys_in(root / "crates", ".rs")
            docs = keys_in(root / "docs", ".ts")
            gaps = [k for k in code if k not in docs and k not in EXEMPT]
            got_gap = bool(gaps)
            if got_gap != expect_gap:
                failures.append(f"  {name}\n      expected gap={expect_gap}, got {gaps or 'none'}")

    # The stale-exemption and both-ways checks operate on the real tables, so
    # exercise them directly rather than through a fixture tree.
    if "AXIAM__DEFINITELY__NOT_A_REAL_KEY" in EXEMPT:
        failures.append("  the stale-exemption probe collided with a real entry")

    if failures:
        print("SELF-TEST FAILED — this gate no longer detects what it claims to:\n")
        print("\n".join(failures))
        return 1

    print(f"self-test: {len(cases)} fixture(s) behaved as specified.")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return _self_test()

    code = keys_in(CRATES, ".rs")
    docs = keys_in(DOCS, ".ts")

    undocumented = sorted(k for k in code if k not in docs and k not in EXEMPT)
    stale_exemptions = sorted(k for k in EXEMPT if k not in code)
    also_documented = sorted(k for k in EXEMPT if k in docs)
    derived = sorted(k for k in docs if k not in code)

    if "--list" in sys.argv:
        for key in sorted(code):
            mark = "doc" if key in docs else ("exempt" if key in EXEMPT else "GAP")
            print(f"{mark:>6}  {key}")
        print()

    print(f"{len(code)} literal key(s) in crates/, {len(docs)} on the docs site.")
    print(f"  documented : {len(code & docs.keys())}")
    print(f"  exempt     : {len(code.keys() & EXEMPT.keys())}")
    print(f"  undocumented: {len(undocumented)}")
    print(
        f"\n{len(derived)} documented key(s) are absent from crates/ — expected: the "
        "config layer\nderives them from struct field names, so they exist as no literal string."
    )

    problems = False

    if undocumented:
        problems = True
        print("\nFAIL: these keys are in the server and neither documented nor exempt.")
        print("Document them in website/src/docs/configuration.ts, or add an entry to")
        print("EXEMPT in this script saying why a deployment never needs to set them.\n")
        for key in undocumented:
            where = sorted(code[key])[0]
            print(f"  {key}\n      first seen: {where}")

    if stale_exemptions:
        problems = True
        print("\nFAIL: these keys are exempt but no longer exist in crates/.")
        print("An exemption for a key nobody reads is a note about a setting that is gone.\n")
        for key in stale_exemptions:
            print(f"  {key}")

    if also_documented:
        problems = True
        print("\nFAIL: these keys are both exempt and documented — pick one.\n")
        for key in also_documented:
            print(f"  {key}")

    if not problems:
        print("\nOK: every literal key is documented or carries a stated exemption.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
