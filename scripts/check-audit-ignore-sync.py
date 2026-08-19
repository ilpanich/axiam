#!/usr/bin/env python3
"""Assert the two advisory ignore-lists agree.

Why this exists
---------------
AXIAM suppresses a handful of RUSTSEC advisories, and it has to say so
**twice**: ``cargo-deny`` reads ``[advisories].ignore`` from ``deny.toml``,
while ``cargo-audit`` (via ``actions-rust-lang/audit``) reads its list from an
``ignore:`` input in the CI workflow and ignores ``deny.toml`` entirely. The
workflow already states the invariant in a comment:

    Ignored advisories MUST stay in sync with deny.toml [advisories].ignore.

That comment was the whole enforcement mechanism. Nothing failed if the two
drifted, and drift is silent in the direction that matters: an ID present in
``deny.toml`` but missing from the workflow leaves ``cargo audit`` red for a
reason nobody wrote down, while an ID present in the workflow but missing from
``deny.toml`` means ``cargo deny`` is still gating on an advisory the team
believes it has triaged -- or, worse, that the *rationale* for suppressing it
exists in neither file.

The rationale lives in ``deny.toml``, which is the file with room for it. This
gate makes the workflow's list provably a mirror of it.

Exit codes: 0 in sync, 1 drifted, 2 could not run (deliberately not 0).
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DENY_TOML = REPO_ROOT / "deny.toml"
CI_YAML = REPO_ROOT / ".github" / "workflows" / "ci.yml"

# Matched instead of parsing the YAML so the gate has no third-party
# dependency: the audit action's list is a single flat `ignore:` scalar, and a
# regex over it cannot be wrong in a way a YAML parser would have caught.
CI_IGNORE_RE = re.compile(r"^\s*ignore:\s*(RUSTSEC-[\w,\-]+)\s*$", re.MULTILINE)

ADVISORY_ID_RE = re.compile(r"^RUSTSEC-\d{4}-\d{4}$")


class GateError(Exception):
    """Raised when the gate cannot run, as opposed to finding drift."""


def deny_ignore_ids(text: str) -> list[str]:
    """Return the advisory IDs listed in deny.toml's [advisories].ignore."""
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise GateError(f"deny.toml is not valid TOML: {exc}") from exc

    entries = parsed.get("advisories", {}).get("ignore")
    if entries is None:
        raise GateError("deny.toml has no [advisories].ignore list")

    ids = []
    for entry in entries:
        # The repo's convention is { id = "...", reason = "..." }; a bare
        # string is legal cargo-deny too, so accept both rather than reject a
        # form the tool itself would take.
        ident = entry if isinstance(entry, str) else entry.get("id")
        if not ident:
            raise GateError(f"deny.toml ignore entry has no id: {entry!r}")
        ids.append(ident)
    return ids


def ci_ignore_ids(text: str) -> list[str]:
    """Return the advisory IDs passed to the cargo-audit action in CI."""
    matches = CI_IGNORE_RE.findall(text)
    if not matches:
        raise GateError(
            "no `ignore: RUSTSEC-...` line found in the workflow -- if the "
            "cargo audit step was renamed or its input reshaped, update this "
            "gate rather than deleting it"
        )
    if len(matches) > 1:
        raise GateError(
            f"expected exactly one `ignore:` line in the workflow, found {len(matches)}"
        )
    return [part.strip() for part in matches[0].split(",") if part.strip()]


def check(deny_text: str, ci_text: str) -> list[str]:
    """Return a list of human-readable problems; empty means in sync."""
    deny_ids = deny_ignore_ids(deny_text)
    ci_ids = ci_ignore_ids(ci_text)

    problems = []

    for label, ids in (("deny.toml", deny_ids), ("ci.yml", ci_ids)):
        for ident in ids:
            if not ADVISORY_ID_RE.match(ident):
                problems.append(f"{label}: {ident!r} is not a RUSTSEC-YYYY-NNNN id")
        duplicates = {i for i in ids if ids.count(i) > 1}
        for ident in sorted(duplicates):
            problems.append(f"{label}: {ident} is listed more than once")

    missing_from_ci = sorted(set(deny_ids) - set(ci_ids))
    missing_from_deny = sorted(set(ci_ids) - set(deny_ids))

    for ident in missing_from_ci:
        problems.append(
            f"{ident} is ignored in deny.toml but NOT in ci.yml -- cargo audit "
            f"will fail on an advisory cargo deny considers triaged"
        )
    for ident in missing_from_deny:
        problems.append(
            f"{ident} is ignored in ci.yml but NOT in deny.toml -- cargo deny "
            f"will fail on it, and the rationale for suppressing it is written "
            f"down nowhere"
        )

    return problems


def self_test() -> int:
    """Run the gate against fixtures, not against this repository.

    A gate whose only evidence is "the repo it guards is currently clean"
    cannot tell working from broken.
    """
    ci = lambda ids: f"        with:\n          ignore: {ids}\n"  # noqa: E731
    deny = lambda ids: (  # noqa: E731
        "[advisories]\nignore = [\n"
        + "".join(f'    {{ id = "{i}", reason = "x" }},\n' for i in ids)
        + "]\n"
    )

    cases = [
        (
            "in sync",
            deny(["RUSTSEC-2023-0071"]),
            ci("RUSTSEC-2023-0071"),
            0,
        ),
        (
            "in sync, several, order differs",
            deny(["RUSTSEC-2023-0071", "RUSTSEC-2026-0258"]),
            ci("RUSTSEC-2026-0258,RUSTSEC-2023-0071"),
            0,
        ),
        (
            "missing from ci.yml",
            deny(["RUSTSEC-2023-0071", "RUSTSEC-2026-0258"]),
            ci("RUSTSEC-2023-0071"),
            1,
        ),
        (
            "missing from deny.toml",
            deny(["RUSTSEC-2023-0071"]),
            ci("RUSTSEC-2023-0071,RUSTSEC-2026-0258"),
            1,
        ),
        (
            "bare-string entry in deny.toml is accepted",
            '[advisories]\nignore = ["RUSTSEC-2023-0071"]\n',
            ci("RUSTSEC-2023-0071"),
            0,
        ),
        (
            "duplicate in ci.yml",
            deny(["RUSTSEC-2023-0071"]),
            ci("RUSTSEC-2023-0071,RUSTSEC-2023-0071"),
            1,
        ),
        (
            "malformed id",
            deny(["RUSTSEC-2023-71"]),
            ci("RUSTSEC-2023-71"),
            1,
        ),
    ]

    failures = 0
    for name, deny_text, ci_text, expected in cases:
        problems = check(deny_text, ci_text)
        actual = 1 if problems else 0
        status = "ok" if actual == expected else "FAIL"
        if actual != expected:
            failures += 1
        print(f"  [{status}] {name}")
        if actual != expected:
            for problem in problems:
                print(f"          {problem}")

    # The gate must also refuse to pass when it cannot read its inputs.
    for name, deny_text, ci_text in (
        ("no [advisories].ignore", "[licenses]\n", ci("RUSTSEC-2023-0071")),
        ("no ignore: line in workflow", deny(["RUSTSEC-2023-0071"]), "jobs:\n"),
        ("two ignore: lines in workflow", deny(["RUSTSEC-2023-0071"]),
         ci("RUSTSEC-2023-0071") + ci("RUSTSEC-2023-0071")),
    ):
        try:
            check(deny_text, ci_text)
        except GateError:
            print(f"  [ok] refuses to run: {name}")
        else:
            print(f"  [FAIL] silently passed with {name}")
            failures += 1

    if failures:
        print(f"\nself-test: {failures} case(s) failed")
        return 1
    print("\nself-test: all cases passed")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()

    try:
        deny_text = DENY_TOML.read_text(encoding="utf-8")
        ci_text = CI_YAML.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot read gate inputs: {exc}", file=sys.stderr)
        return 2

    try:
        problems = check(deny_text, ci_text)
    except GateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if problems:
        print("Advisory ignore-lists have drifted:\n", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print(
            "\nThe two lists must match. deny.toml is the file that carries the "
            "rationale for each entry; add or remove the ID there first, then "
            "mirror it into the cargo audit step's `ignore:` input.",
            file=sys.stderr,
        )
        return 1

    ids = deny_ignore_ids(deny_text)
    print(f"deny.toml and ci.yml agree on {len(ids)} ignored advisory(ies):")
    for ident in ids:
        print(f"  {ident}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
