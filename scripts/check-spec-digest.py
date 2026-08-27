#!/usr/bin/env python3
"""Assert ``sdks/openapi.json``'s ``info.x-axiam-spec-digest`` matches its content.

Why this exists
---------------
The digest is a SHA-256 over the OpenAPI document with the digest field itself
**absent** -- see ``stamp_spec_digest()`` in
``crates/axiam-api-rest/src/openapi.rs``. ``info.version`` is deliberately
*inside* it, so a release bump changes the digest even when no path did.

That last property is what went wrong. ``scripts/mass-tag.sh`` bumped
``info.version`` with a targeted string rewrite -- correct, and no rebuild
needed -- but the rewrite invalidated the digest in the same stroke, and
1.0.0-beta02 shipped carrying the beta01 digest. Nothing caught it:

* the §27 management-registry gate copies the digest out of the spec verbatim,
  so it agrees with a stale one;
* ``sdk-openapi-drift.yml`` *would* have caught it -- a fresh ``--dump-openapi``
  recomputes the digest -- but it was path-filtered to the server crates, and
  the release commit touched only ``sdks/openapi.json``.

Both holes are now closed (the gate's paths include the spec, and mass-tag
re-stamps). This gate is the cheap third one: it needs no Rust toolchain and no
build, so it can run on *every* commit in the Architecture Invariants job and
answer the one question the other two only answer conditionally.

Cross-implementation check
--------------------------
The canonical form below -- compact separators, ``ensure_ascii=False``, file key
order -- is a reimplementation of ``serde_json::to_vec``. Running ``--check``
against the committed spec is itself the proof the two agree: that digest was
produced by the Rust code, so a mismatch in the canonicalisation shows up here
as drift rather than as a silent divergence between the two implementations.

Usage::

    scripts/check-spec-digest.py             # verify (CI)
    scripts/check-spec-digest.py --write     # re-stamp after a version bump
    scripts/check-spec-digest.py --self-test # fixtures

Exit codes: 0 in sync (or re-stamped), 1 drifted, 2 could not run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = REPO_ROOT / "sdks" / "openapi.json"

DIGEST_KEY = "x-axiam-spec-digest"


class GateError(Exception):
    """Raised when the gate cannot run, as opposed to finding drift."""


def compute_digest(text: str) -> str:
    """Return the digest a freshly exported spec with this content would carry.

    The field is removed before hashing, which is what makes the digest a
    function of the document rather than of itself -- and therefore what makes
    re-stamping idempotent.
    """
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise GateError(f"spec is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("info"), dict):
        raise GateError("spec has no `info` object")

    doc["info"].pop(DIGEST_KEY, None)
    canonical = json.dumps(doc, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def committed_digest(text: str) -> str:
    """Return the digest recorded in the document, or raise if there is none."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise GateError(f"spec is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("info"), dict):
        raise GateError("spec has no `info` object")

    recorded = doc["info"].get(DIGEST_KEY)
    if recorded is None:
        # Not a GateError: the server stamps this field unconditionally, so a
        # spec without it has drifted from what the server emits. Reporting
        # "could not run" would file a real defect under "inconclusive".
        return ""
    if not isinstance(recorded, str):
        raise GateError(f"info.{DIGEST_KEY} is {type(recorded).__name__}, not a string")
    return recorded


def restamp(text: str) -> tuple[str, str, str]:
    """Return (new_text, old_digest, new_digest) with the digest corrected.

    The substitution is textual on purpose. Re-serialising would reformat the
    whole file -- the committed spec is serde's pretty-printed output -- and a
    re-stamp must change exactly one string.
    """
    old = committed_digest(text)
    if not old:
        raise GateError(
            f"cannot re-stamp: info.{DIGEST_KEY} is absent. Regenerate the spec "
            "with `cargo build -p axiam-server --no-default-features && "
            "./target/debug/axiam-server --dump-openapi > sdks/openapi.json`."
        )
    new = compute_digest(text)
    if old == new:
        return text, old, new

    if text.count(old) != 1:
        raise GateError(
            f"the digest string appears {text.count(old)} times in the spec; "
            "a targeted rewrite would be ambiguous"
        )
    return text.replace(old, new), old, new


def self_test() -> int:
    """Exercise the gate against fixtures, including its refusal cases."""
    print("self-test: spec digest gate\n")

    def spec(version: str, digest: str | None, title: str = "AXIAM") -> str:
        info: dict[str, object] = {"title": title, "version": version}
        if digest is not None:
            info[DIGEST_KEY] = digest
        return json.dumps({"openapi": "3.1.0", "info": info, "paths": {}}, indent=2)

    failures = 0

    def case(name: str, ok: bool) -> None:
        nonlocal failures
        if not ok:
            failures += 1
        print(f"  [{'ok' if ok else 'FAIL'}] {name}")

    # A correctly stamped document round-trips.
    stamped, _, _ = restamp(spec("1.0.0", "sha256:" + "0" * 64))
    case("re-stamp corrects a wrong digest",
         committed_digest(stamped) == compute_digest(stamped))
    case("re-stamping is idempotent", restamp(stamped)[0] == stamped)
    case("a correct digest is reported in sync",
         committed_digest(stamped) == compute_digest(stamped))

    # The digest covers info.version -- the property the whole bug turned on.
    bumped, _, _ = restamp(spec("1.0.1", "sha256:" + "0" * 64))
    case("info.version is inside the digest",
         committed_digest(stamped) != committed_digest(bumped))

    # ...and the rest of the document too.
    retitled, _, _ = restamp(spec("1.0.0", "sha256:" + "0" * 64, title="Other"))
    case("document content is inside the digest",
         committed_digest(stamped) != committed_digest(retitled))

    # A bumped version with the old digest left in place is exactly the defect
    # that shipped in 1.0.0-beta02.
    shipped_stale = spec("1.0.1", committed_digest(stamped))
    case("detects the 1.0.0-beta02 failure shape",
         committed_digest(shipped_stale) != compute_digest(shipped_stale))

    # Re-stamping changes one string and nothing else.
    before = spec("1.0.1", committed_digest(stamped))
    after, old, new = restamp(before)
    case("re-stamp rewrites exactly the digest",
         after == before.replace(old, new) and before.count(old) == 1)

    # Non-ASCII must be emitted raw, not \u-escaped: serde_json::to_vec does
    # not escape it, and a mismatch here would desynchronise the two
    # implementations for any spec with an accented word in a description.
    accented = json.dumps({"info": {"title": "Größe", "version": "1"}}, indent=2)
    case("non-ASCII is hashed unescaped",
         compute_digest(accented) == "sha256:" + hashlib.sha256(
             '{"info":{"title":"Größe","version":"1"}}'.encode("utf-8")
         ).hexdigest())

    # A spec with no digest at all is drift, not an inconclusive run.
    case("absent digest reads as drift", committed_digest(spec("1.0.0", None)) == "")

    for name, text in (
        ("not JSON", "{"),
        ("no info object", '{"openapi":"3.1.0"}'),
        ("digest is not a string", '{"info":{"' + DIGEST_KEY + '":7}}'),
    ):
        try:
            committed_digest(text)
        except GateError:
            print(f"  [ok] refuses to run: {name}")
        else:
            print(f"  [FAIL] silently passed with {name}")
            failures += 1

    try:
        restamp(spec("1.0.0", None))
    except GateError:
        print("  [ok] refuses to re-stamp a spec with no digest field")
    else:
        print("  [FAIL] re-stamped a spec with no digest field")
        failures += 1

    if failures:
        print(f"\nself-test: {failures} case(s) failed")
        return 1
    print("\nself-test: all cases passed")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true",
                        help="re-stamp the digest in place instead of checking it")
    parser.add_argument("--self-test", action="store_true",
                        help="run the fixtures and exit")
    parser.add_argument("--spec", type=Path, default=SPEC_PATH,
                        help=f"spec to operate on (default: {SPEC_PATH})")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        text = args.spec.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot read {args.spec}: {exc}", file=sys.stderr)
        return 2

    rel = args.spec
    try:
        rel = args.spec.relative_to(REPO_ROOT)
    except ValueError:
        pass

    if args.write:
        try:
            new_text, old, new = restamp(text)
        except GateError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if old == new:
            print(f"{rel}: spec digest already current ({new})")
            return 0
        args.spec.write_text(new_text, encoding="utf-8")
        print(f'{rel}: spec digest "{old}" -> "{new}"')
        return 0

    try:
        recorded, expected = committed_digest(text), compute_digest(text)
    except GateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if recorded == expected:
        print(f"{rel}: spec digest matches its content ({expected})")
        return 0

    print(f"{rel}: info.{DIGEST_KEY} does not match the document it describes.\n",
          file=sys.stderr)
    print(f"  recorded: {recorded or '(absent)'}", file=sys.stderr)
    print(f"  computed: {expected}\n", file=sys.stderr)
    print(
        "The digest is taken over the spec with this field removed, and covers\n"
        "info.version. The usual cause is an edit to sdks/openapi.json that did\n"
        "not go through the server -- a release version bump, most often.\n\n"
        "Fix it with:  scripts/check-spec-digest.py --write\n"
        "or by re-exporting the spec:\n"
        "  cargo build -p axiam-server --no-default-features\n"
        "  ./target/debug/axiam-server --dump-openapi > sdks/openapi.json\n"
        "Either way, follow it with: scripts/gen-management-registry.py",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
