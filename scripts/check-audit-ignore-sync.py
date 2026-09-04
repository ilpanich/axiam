#!/usr/bin/env python3
"""Assert the two advisory ignore-lists agree.

Why this exists
---------------
AXIAM suppresses a handful of RUSTSEC advisories, and it has to say so
**twice**: ``cargo-deny`` reads ``[advisories].ignore`` from ``deny.toml``,
while ``cargo-audit`` (via ``actions-rust-lang/audit``) reads its list from an
``ignore:`` input in the CI workflow and ignores ``deny.toml`` entirely.
Nothing failed if the two drifted, and drift is silent in the direction that
matters: an ID present in ``deny.toml`` but missing from the workflow leaves
``cargo audit`` red for a reason nobody wrote down, while an ID present in the
workflow and nowhere else means the *rationale* for suppressing it exists in no
file at all.

The rationale lives in ``deny.toml``, which is the file with room for it.

The lists are not equal, and requiring that they be was wrong
------------------------------------------------------------
This gate originally demanded set equality, which held right up until it
didn't. The two tools do not examine the same set of crates:

* ``cargo-deny`` resolves the **feature graph**. A dependency declared
  ``optional = true`` that no enabled feature activates is not in the graph, so
  there is nothing for an ignore entry to match -- and cargo-deny reports the
  unmatched entry as ``advisory-not-detected``, which the CI job escalates with
  ``-D advisory-not-detected``.
* ``cargo-audit`` reads **Cargo.lock**, which records optional dependencies
  whether or not any feature ever pulls them in, so it still reports them.

RUSTSEC-2023-0089 (atomic-polyfill) and RUSTSEC-2026-0235 (rkyv) live in that
gap today: cargo-audit needs them suppressed, cargo-deny fails if they are.
Equality is therefore unsatisfiable, and the honest invariant is containment
plus an explicit declaration:

1. Every ID in ``deny.toml``'s ``[advisories].ignore`` MUST appear in the
   workflow's ``ignore:`` input. (cargo-audit sees a superset of cargo-deny's
   crates, so anything cargo-deny suppresses, cargo-audit will hit too.)
2. Every extra ID in the workflow MUST be declared in ``deny.toml`` as an
   ``# audit-only: RUSTSEC-YYYY-NNNN -- reason`` comment. The declaration is
   what keeps "the lists differ" from becoming indistinguishable from "the
   lists drifted".
3. A declaration must not be stale: an ``audit-only`` ID that is absent from
   the workflow, or that also appears in ``ignore``, is an error.

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

# `# audit-only: RUSTSEC-YYYY-NNNN -- why`, anywhere in deny.toml. A comment
# rather than a TOML key on purpose: deny.toml is parsed by cargo-deny, and a
# key it does not know is a warning on every run of the job this gate protects.
AUDIT_ONLY_RE = re.compile(
    r"^\s*#\s*audit-only:\s*(RUSTSEC-\d{4}-\d{4})\b(.*)$", re.MULTILINE
)

# An audit-only entry without a reason is the failure mode this gate exists to
# prevent, one indirection later. Long enough to be a sentence, not a shrug.
MIN_REASON_CHARS = 20


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


def audit_only_ids(text: str) -> dict[str, str]:
    """Return {advisory id: reason} for deny.toml's `# audit-only:` declarations."""
    found: dict[str, str] = {}
    for ident, reason in AUDIT_ONLY_RE.findall(text):
        if ident in found:
            raise GateError(f"deny.toml declares {ident} audit-only more than once")
        found[ident] = reason.strip().lstrip("-–—").strip()
    return found


def check(deny_text: str, ci_text: str) -> list[str]:
    """Return a list of human-readable problems; empty means in sync."""
    deny_ids = deny_ignore_ids(deny_text)
    ci_ids = ci_ignore_ids(ci_text)
    audit_only = audit_only_ids(deny_text)

    problems = []

    for label, ids in (("deny.toml", deny_ids), ("ci.yml", ci_ids)):
        for ident in ids:
            if not ADVISORY_ID_RE.match(ident):
                problems.append(f"{label}: {ident!r} is not a RUSTSEC-YYYY-NNNN id")
        duplicates = {i for i in ids if ids.count(i) > 1}
        for ident in sorted(duplicates):
            problems.append(f"{label}: {ident} is listed more than once")

    # (1) Anything cargo-deny suppresses, cargo-audit must suppress too:
    # cargo-audit reads Cargo.lock, a superset of the resolved feature graph, so
    # it will hit every advisory cargo-deny does and then some.
    for ident in sorted(set(deny_ids) - set(ci_ids)):
        problems.append(
            f"{ident} is ignored in deny.toml but NOT in ci.yml -- cargo audit "
            f"will fail on an advisory cargo deny considers triaged"
        )

    # (2) The reverse direction is legal, but only when declared and explained.
    for ident in sorted(set(ci_ids) - set(deny_ids)):
        if ident not in audit_only:
            problems.append(
                f"{ident} is ignored in ci.yml but is neither in deny.toml's "
                f"[advisories].ignore nor declared there as `# audit-only: "
                f"{ident} -- <reason>` -- so the rationale for suppressing it "
                f"is written down nowhere"
            )
        elif len(audit_only[ident]) < MIN_REASON_CHARS:
            problems.append(
                f"{ident} is declared audit-only in deny.toml without a real "
                f"reason (got {audit_only[ident]!r}) -- say why cargo-audit "
                f"sees it and cargo-deny does not"
            )

    # (3) A declaration that no longer describes reality is worse than none: it
    # reads as triage that has already happened.
    for ident in sorted(audit_only):
        if not ADVISORY_ID_RE.match(ident):
            problems.append(f"deny.toml: audit-only {ident!r} is not a RUSTSEC id")
        if ident in deny_ids:
            problems.append(
                f"{ident} is declared audit-only in deny.toml AND listed in its "
                f"[advisories].ignore -- it is one or the other; cargo deny "
                f"fails the ignore entry under -D advisory-not-detected if the "
                f"crate really is invisible to it"
            )
        elif ident not in ci_ids:
            problems.append(
                f"{ident} is declared audit-only in deny.toml but is not in "
                f"ci.yml's ignore list -- a stale declaration; delete it"
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
            "extra in ci.yml, undeclared",
            deny(["RUSTSEC-2023-0071"]),
            ci("RUSTSEC-2023-0071,RUSTSEC-2026-0258"),
            1,
        ),
        (
            "extra in ci.yml, declared audit-only with a reason",
            "# audit-only: RUSTSEC-2026-0258 -- lockfile-only, not in the resolved graph\n"
            + deny(["RUSTSEC-2023-0071"]),
            ci("RUSTSEC-2023-0071,RUSTSEC-2026-0258"),
            0,
        ),
        (
            "audit-only declaration with no reason is rejected",
            "# audit-only: RUSTSEC-2026-0258\n" + deny(["RUSTSEC-2023-0071"]),
            ci("RUSTSEC-2023-0071,RUSTSEC-2026-0258"),
            1,
        ),
        (
            "audit-only declaration with a shrug for a reason is rejected",
            "# audit-only: RUSTSEC-2026-0258 -- n/a\n" + deny(["RUSTSEC-2023-0071"]),
            ci("RUSTSEC-2023-0071,RUSTSEC-2026-0258"),
            1,
        ),
        (
            "stale audit-only declaration (not in ci.yml)",
            "# audit-only: RUSTSEC-2026-0258 -- lockfile-only, not in the resolved graph\n"
            + deny(["RUSTSEC-2023-0071"]),
            ci("RUSTSEC-2023-0071"),
            1,
        ),
        (
            "audit-only AND in deny.toml's ignore is contradictory",
            "# audit-only: RUSTSEC-2026-0258 -- lockfile-only, not in the resolved graph\n"
            + deny(["RUSTSEC-2023-0071", "RUSTSEC-2026-0258"]),
            ci("RUSTSEC-2023-0071,RUSTSEC-2026-0258"),
            1,
        ),
        (
            "audit-only never excuses a deny.toml id missing from ci.yml",
            "# audit-only: RUSTSEC-2026-0258 -- lockfile-only, not in the resolved graph\n"
            + deny(["RUSTSEC-2023-0071", "RUSTSEC-2026-0194"]),
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
        ("duplicate audit-only declaration",
         "# audit-only: RUSTSEC-2026-0258 -- lockfile-only, not in the graph\n"
         "# audit-only: RUSTSEC-2026-0258 -- lockfile-only, not in the graph\n"
         + deny(["RUSTSEC-2023-0071"]),
         ci("RUSTSEC-2023-0071,RUSTSEC-2026-0258")),
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
            "\ndeny.toml is the file that carries the rationale for every "
            "suppression. Add or remove the ID there first -- in "
            "[advisories].ignore if cargo-deny sees the crate, or as an "
            "`# audit-only: <ID> -- <reason>` comment if only cargo-audit does "
            "-- then mirror it into the cargo audit step's `ignore:` input.",
            file=sys.stderr,
        )
        return 1

    ids = deny_ignore_ids(deny_text)
    audit_only = audit_only_ids(deny_text)
    print(f"deny.toml and ci.yml agree on {len(ids) + len(audit_only)} suppression(s):")
    for ident in ids:
        print(f"  {ident}  (cargo-deny + cargo-audit)")
    for ident in sorted(audit_only):
        print(f"  {ident}  (cargo-audit only: {audit_only[ident]})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
