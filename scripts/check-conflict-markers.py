#!/usr/bin/env python3
"""Assert that UNIQUE-violation detection lives in exactly one place (D-09).

Why this exists
---------------
SurrealDB reports a UNIQUE-index violation as free text --
``Database index `idx_replay_uniq` already contains [...]`` -- so deciding
"was this a conflict?" means matching substrings in an error message. Three
markers do it: ``already contains``, ``already exists``, ``unique``.

Whether that match succeeds is a **security** outcome, not a cosmetic one. At
the replay guards it is the difference between refusing a replayed SAML
assertion, AMQP nonce or DPoP proof and accepting it as fresh. At the
bootstrap handler it is the difference between one admin and a race for the
first one.

``axiam_db::helpers::classify_write_error`` has documented itself as the only
place allowed to inspect that text since D-09:

    Per D-09, this is the ONLY place that inspects error text for these
    markers -- call sites must not add their own inline `contains(...)`
    checks.

Five sites did anyway. Each was a careful copy, and one of them
(``oauth2_proof_replay``) even explains why it was copied: "kept identical so
the three replay guards cannot drift into disagreeing about what a conflict
looks like." That is the right worry, and copy-paste is the wrong mechanism
for it -- a marker added to four sites out of five is a security fix with a
hole in it, and nothing would have failed.

The rule was already written down. This gate is what makes it true.

The rule
--------
Only ``crates/axiam-db/src/helpers.rs`` may contain the marker strings. Every
other site calls one of its three classifiers:

    classify_write_error           -> DbError::AlreadyExists   (409)
    classify_conflict_write_error  -> AxiamError::AlreadyExists (409)
    classify_replay_write_error    -> AxiamError::ReplayDetected

Test files are exempt: a test asserting that a given server message is
classified correctly has to name the message, and that is the point of it.

Usage:
    scripts/check-conflict-markers.py
    scripts/check-conflict-markers.py --self-test

Exit status:
    0 = the markers appear only where they are allowed to
    1 = an inline copy was found, named with the file and line
    2 = the gate could not run
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
CRATES_DIR = os.path.join(REPO_ROOT, "crates")

# The one file allowed to name them, relative to the repo root.
OWNER = os.path.join("crates", "axiam-db", "src", "helpers.rs")

# Matched as they appear in source: a Rust string literal. Looking for the bare
# words would flag prose ("the row already exists") in every doc comment in the
# workspace, which is noise rather than a finding.
MARKER_LITERALS = ('"already contains"', '"already exists"', '"unique"')

# A `#[cfg(test)]` module, or a file under tests/, may name a marker: asserting
# that a real server message is classified correctly requires quoting it.
TEST_PATH_MARKERS = (os.sep + "tests" + os.sep, os.sep + "benches" + os.sep)


def is_test_file(rel_path: str) -> bool:
    return any(m in rel_path for m in TEST_PATH_MARKERS)


def first_cfg_test_line(lines: list[str]) -> int:
    """1-based line of the first `#[cfg(test)]`, or a line past the end."""
    for i, line in enumerate(lines, start=1):
        if re.match(r"\s*#\[cfg\(test\)\]", line):
            return i
    return len(lines) + 1


def scan(crates_dir: str) -> list[tuple[str, list[tuple[int, str]]]]:
    """Return ``[(rel_path, [(line, marker), ...]), ...]``, one entry per file."""
    findings: list[tuple[str, list[tuple[int, str]]]] = []
    for root, _dirs, files in os.walk(crates_dir):
        for name in sorted(files):
            if not name.endswith(".rs"):
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, REPO_ROOT)
            if rel == OWNER or is_test_file(rel):
                continue
            with open(path, encoding="utf-8", errors="ignore") as fh:
                lines = fh.read().split("\n")
            cutoff = first_cfg_test_line(lines)
            hits: list[tuple[int, str]] = []
            for lineno, line in enumerate(lines, start=1):
                if lineno >= cutoff:
                    break  # inside #[cfg(test)] -- allowed to quote a message
                for marker in MARKER_LITERALS:
                    if marker in line:
                        hits.append((lineno, marker))
            if hits:
                findings.append((rel, hits))
    return sorted(findings)


def self_test() -> int:
    """Exercise the gate's own decisions on synthetic lines."""
    cases = [
        ('if msg.contains("already contains") {', True),
        ('    || msg.contains("unique")', True),
        ('/// the row already exists in the table', False),
        ("// a unique index guards this", False),
        ("if is_unique_violation(&msg) {", False),
        ('AxiamError::AlreadyExists { entity: "user".into() }', False),
    ]
    failures = 0
    for line, expected in cases:
        got = any(m in line for m in MARKER_LITERALS)
        status = "ok  " if got == expected else "FAIL"
        if got != expected:
            failures += 1
        print(f"  {status} {'flags' if expected else 'ignores':7s} {line.strip()}")

    # The owner file must actually still define the markers; a gate pointing at
    # a file that no longer holds them is worse than no gate.
    owner_path = os.path.join(REPO_ROOT, OWNER)
    if not os.path.isfile(owner_path):
        print(f"  FAIL owner file {OWNER} does not exist")
        failures += 1
    else:
        owner_src = open(owner_path, encoding="utf-8").read()
        for marker in MARKER_LITERALS:
            if marker not in owner_src:
                print(f"  FAIL owner file {OWNER} no longer defines {marker}")
                failures += 1
        if "fn is_unique_violation" not in owner_src:
            print(f"  FAIL owner file {OWNER} no longer defines is_unique_violation")
            failures += 1

    if failures:
        print(f"\nself-test FAILED: {failures} case(s)", file=sys.stderr)
        return 1
    print(f"\nself-test OK: {len(cases)} case(s) + owner-file invariants")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    if not os.path.isdir(CRATES_DIR):
        print(f"conflict-marker gate could not run: no {CRATES_DIR}", file=sys.stderr)
        return 2
    findings = scan(CRATES_DIR)
    if findings:
        total = sum(len(hits) for _rel, hits in findings)
        print("Conflict-marker check FAILED:\n", file=sys.stderr)
        for rel, hits in findings:
            where = ", ".join(f"{line}:{marker}" for line, marker in hits)
            print(f"  - {rel}\n      {where}", file=sys.stderr)
        print(
            f"\n{total} inline marker(s) across {len(findings)} file(s).\n"
            f"\nUNIQUE-violation detection lives only in {OWNER}. Replace the\n"
            f"inline check with whichever classifier matches what the conflict\n"
            f"means at that call site:\n"
            f"    classify_replay_write_error(err)          -> ReplayDetected\n"
            f"    classify_conflict_write_error(err, what)  -> AxiamError::AlreadyExists\n"
            f"    classify_write_error(err, what)           -> DbError::AlreadyExists\n"
            f"\nFive inline copies existed before D-09 was enforced. A marker added\n"
            f"to four of them would have been a security fix with a hole in it, and\n"
            f"nothing would have failed.",
            file=sys.stderr,
        )
        return 1
    print(
        f"Conflict-marker check OK: UNIQUE-violation detection appears only in "
        f"{OWNER}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
