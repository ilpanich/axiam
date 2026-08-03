#!/usr/bin/env python3
"""Verify that remediation evidence in the security analysis actually shipped.

Why this exists (security-analysis-2026-08-02 §11.2): a remediation record that
cites a **commit hash** is not evidence the fix **shipped**. A hash exists the
moment a commit is authored, on any branch. That pass caught a real instance —
the Swift SEC-080 fix was recorded as remediated while it still sat only on a
feature branch, one commit ahead of that repo's default branch.

So: every ``(finding id, repo, commit)`` triple claimed in a remediation table
must resolve to a commit **reachable from the default branch** of the repository
it names.

  * Commits claimed in **this** repo are checked with
    ``git merge-base --is-ancestor <sha> <base-ref>`` (default ``origin/main``).
  * Commits claimed in an **SDK** repo cannot be checked locally — this
    repository has no clone of them. If a GitHub token is present they are
    checked over the API; otherwise each such row is reported **SKIPPED, by
    name**. A check that silently passes on the rows it cannot verify is worse
    than no check at all, so the skipped rows are always printed and always
    counted in the summary.

A row that cannot be parsed into a triple is a **failure**, not a skip: the
whole point is that unverified claims must not look verified.

Usage:
    scripts/check-remediation-evidence.py [DOC ...]

Environment:
    REMEDIATION_BASE_REF   git ref the local claims must be reachable from
                           (default: ``origin/main``).
    GITHUB_TOKEN / GH_TOKEN
                           token used for the SDK-repo checks. Absent ⇒ those
                           rows are reported SKIPPED.
    GITHUB_ORG             owner of the SDK repositories (default ``ilpanich``).

Exit status: 0 = every parsed claim verified or explicitly skipped;
             1 = a claim failed to verify, or a row could not be parsed.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DOCS = [REPO_ROOT / "claude_dev" / "security-analysis-2026-08-02.md"]

BASE_REF = os.environ.get("REMEDIATION_BASE_REF", "origin/main")
GITHUB_ORG = os.environ.get("GITHUB_ORG", "ilpanich")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

#: This repository's own name, as written in the tables.
THIS_REPO = "axiam"

#: Header cell names that carry a commit claim. A markdown table is treated as
#: a *remediation* table if and only if one of its header cells is one of these
#: — that is the rule, stated once, and the run prints every table it saw and
#: what it decided, so the classification is auditable rather than implicit.
COMMIT_HEADERS = {"commit", "commits", "where"}
#: Header cell names that carry the finding id (or, in §9.2, the SDK name).
ID_HEADERS = {"id", "item", "finding", "sdk"}
#: Header cell names that carry the repository.
REPO_HEADERS = {"repo", "repos", "repository"}

#: Language name → repository name. §9.2's table names languages, and §9.1's
#: multi-repo rows list them in prose ("Kotlin, Swift, C, C++").
LANG_TO_REPO = {
    "rust": "axiam-rust-sdk",
    "typescript": "axiam-typescript-sdk",
    "ts": "axiam-typescript-sdk",
    "python": "axiam-python-sdk",
    "java": "axiam-java-sdk",
    "c#": "axiam-csharp-sdk",
    "csharp": "axiam-csharp-sdk",
    "go": "axiam-go-sdk",
    "php": "axiam-php-sdk",
    "kotlin": "axiam-kotlin-sdk",
    "swift": "axiam-swift-sdk",
    "c": "axiam-c-sdk",
    "c++": "axiam-cplusplus-sdk",
    "cpp": "axiam-cplusplus-sdk",
}

SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
FINDING_ID_RE = re.compile(
    r"(SEC-\d+|OBS-\d+|T-\d+|SDK-[A-Z0-9]+|Residual\s+\d+|§?\d+(?:\.\d+)*\s+residual)",
    re.IGNORECASE,
)
#: A commit cell that defers to another table rather than claiming a hash.
CROSS_REF_RE = re.compile(r"\bsee\s+§", re.IGNORECASE)
#: A commit cell that explicitly claims no commit.
NO_CLAIM = {"", "—", "-", "–", "n/a", "none"}


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


@dataclass
class Claim:
    """One ``(finding id, repo, commit)`` triple, with where it came from."""

    finding_id: str
    repo: str
    commit: str
    section: str
    line_no: int
    raw: str


@dataclass
class Row:
    """A parsed table row that produced zero or more claims, or an error."""

    section: str
    line_no: int
    raw: str
    claims: list[Claim] = field(default_factory=list)
    note: str | None = None
    error: str | None = None


def split_cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def is_separator(line: str) -> bool:
    body = line.strip().strip("|")
    return bool(body) and all(
        re.fullmatch(r":?-{2,}:?", c.strip()) for c in body.split("|")
    )


def normalize_header(cell: str) -> str:
    return cell.strip().strip("*`").strip().lower()


def tokens(cell: str) -> list[str]:
    """Backticked tokens first, then bare words — both are used in the doc."""
    ticked = re.findall(r"`([^`]+)`", cell)
    if ticked:
        return [t.strip() for t in ticked if t.strip()]
    stripped = re.sub(r"\*\*|\*|_", "", cell)
    return [t.strip() for t in re.split(r"[,/;]| and ", stripped) if t.strip()]


def resolve_repo(token: str) -> str | None:
    t = token.strip().strip("`*").strip().lower()
    if t == THIS_REPO or t.startswith("axiam-"):
        return t
    return LANG_TO_REPO.get(t)


def parse_doc(path: Path) -> tuple[list[Row], list[tuple[str, str, str]]]:
    """Returns (rows, table_log). ``table_log`` records every table seen."""
    lines = path.read_text(encoding="utf-8").splitlines()
    rows: list[Row] = []
    table_log: list[tuple[str, str, str]] = []

    section = "(preamble)"
    section_finding = ""
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("#"):
            section = line.lstrip("#").strip()
            m = FINDING_ID_RE.search(section)
            section_finding = m.group(1) if m else ""
            i += 1
            continue

        # A table is a header line followed by a separator line.
        if (
            line.strip().startswith("|")
            and i + 1 < len(lines)
            and is_separator(lines[i + 1])
        ):
            header = split_cells(line)
            norm = [normalize_header(c) for c in header]
            body_start = i + 2
            body_end = body_start
            while body_end < len(lines) and lines[body_end].strip().startswith("|"):
                body_end += 1

            if not any(h in COMMIT_HEADERS for h in norm):
                table_log.append(
                    (section, f"line {i + 1}", "skipped — no commit/where column")
                )
                i = body_end
                continue

            table_log.append(
                (
                    section,
                    f"line {i + 1}",
                    f"remediation table — {body_end - body_start} row(s), "
                    f"columns: {', '.join(h or '(blank)' for h in norm)}",
                )
            )
            for j in range(body_start, body_end):
                rows.append(
                    parse_row(
                        norm, split_cells(lines[j]), section, section_finding, j + 1,
                        lines[j].strip(),
                    )
                )
            i = body_end
            continue

        i += 1

    return rows, table_log


def parse_row(
    headers: list[str],
    cells: list[str],
    section: str,
    section_finding: str,
    line_no: int,
    raw: str,
) -> Row:
    """Split one table row into records and turn each into claims.

    A *record* runs from an id/repo column up to and including the next
    commit column, which is what makes §9.2's doubled ``| SDK | Commit | |
    SDK | Commit |`` layout parse as two records rather than one broken one.
    """
    row = Row(section=section, line_no=line_no, raw=raw)
    records: list[dict[str, list[str]]] = []
    current: dict[str, list[str]] = {"id": [], "repo": [], "commit": []}

    for header, cell in zip(headers, cells):
        if header in ID_HEADERS:
            current["id"].append(cell)
        elif header in REPO_HEADERS:
            current["repo"].append(cell)
        elif header in COMMIT_HEADERS:
            current["commit"].append(cell)
            records.append(current)
            current = {"id": [], "repo": [], "commit": []}

    if not records:
        row.error = "row has no commit cell"
        return row

    notes: list[str] = []
    for rec in records:
        id_cell = " ".join(rec["id"]).strip()
        repo_cell = " ".join(rec["repo"]).strip()
        commit_cell = " ".join(rec["commit"]).strip()

        # An entirely blank record is the spacer column in §9.2's doubled
        # table (its last row has no second pair) — not an error.
        if not any([id_cell, repo_cell, commit_cell]):
            continue

        m = FINDING_ID_RE.search(re.sub(r"[`*]", "", id_cell))
        finding_id = m.group(1) if m else section_finding
        if not finding_id:
            row.error = f"no finding id in row or enclosing heading (id cell: {id_cell!r})"
            return row

        commits = [t.lower() for t in tokens(commit_cell) if SHA_RE.match(t.lower())]
        if not commits:
            plain = re.sub(r"[`*]", "", commit_cell).strip().lower()
            if CROSS_REF_RE.search(commit_cell):
                notes.append(
                    f"{finding_id}: evidence delegated to another table ({commit_cell!r}) "
                    f"— verified there"
                )
                continue
            if plain in NO_CLAIM:
                notes.append(f"{finding_id}: no commit claimed ({commit_cell!r})")
                continue
            row.error = (
                f"{finding_id}: commit cell {commit_cell!r} claims neither a SHA, "
                f"a cross-reference, nor 'no commit'"
            )
            return row

        # Repos may come from a dedicated column, from the commit cell
        # (§10.7 writes "`axiam` `04dc674`"), or from the id cell (§9.2
        # names the SDK's language there).
        repo_source = repo_cell or commit_cell or id_cell
        repos = [r for r in (resolve_repo(t) for t in tokens(repo_source)) if r]
        if not repos and repo_source is not id_cell:
            repos = [r for r in (resolve_repo(t) for t in tokens(id_cell)) if r]
        if not repos:
            row.error = (
                f"{finding_id}: cannot resolve a repository from {repo_source!r} "
                f"(add it to LANG_TO_REPO if this is a new SDK)"
            )
            return row

        if len(commits) == len(repos):
            pairs = list(zip(repos, commits))
        elif len(commits) == 1:
            pairs = [(r, commits[0]) for r in repos]
        elif len(repos) == 1:
            pairs = [(repos[0], c) for c in commits]
        else:
            row.error = (
                f"{finding_id}: {len(repos)} repo(s) {repos} and {len(commits)} "
                f"commit(s) {commits} cannot be paired"
            )
            return row

        for repo, commit in pairs:
            row.claims.append(
                Claim(finding_id, repo, commit, section, line_no, raw)
            )

    if notes:
        row.note = "; ".join(notes)
    return row


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    )


def verify_local(commit: str) -> tuple[str, str]:
    if git("rev-parse", "--verify", "--quiet", f"{BASE_REF}^{{commit}}").returncode != 0:
        return "SKIPPED", f"base ref {BASE_REF} is not present in this clone"
    if git("cat-file", "-e", f"{commit}^{{commit}}").returncode != 0:
        return "FAIL", f"commit {commit} does not exist in this repository"
    if git("merge-base", "--is-ancestor", commit, BASE_REF).returncode == 0:
        return "PASS", f"reachable from {BASE_REF}"
    return "FAIL", f"commit {commit} exists but is NOT reachable from {BASE_REF}"


def gh_api(path: str) -> tuple[int, dict | None]:
    req = urllib.request.Request(
        f"https://api.github.com{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "User-Agent": "axiam-remediation-evidence-check",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, TimeoutError) as e:  # network unavailable
        return 0, {"error": str(e)}


_repo_default_branch: dict[str, tuple[str | None, str]] = {}


def default_branch(repo: str) -> tuple[str | None, str]:
    """Returns ``(default_branch, reason_if_unavailable)``."""
    if repo not in _repo_default_branch:
        status, body = gh_api(f"/repos/{GITHUB_ORG}/{repo}")
        if status == 200 and body:
            _repo_default_branch[repo] = (body["default_branch"], "")
        elif status == 0:
            reason = (body or {}).get("error", "network unreachable")
            _repo_default_branch[repo] = (None, f"GitHub API unreachable ({reason})")
        else:
            _repo_default_branch[repo] = (
                None,
                f"GET /repos/{GITHUB_ORG}/{repo} returned HTTP {status} "
                f"(token lacks access, or egress is blocked)",
            )
    return _repo_default_branch[repo]


def verify_remote(repo: str, commit: str) -> tuple[str, str]:
    if not GITHUB_TOKEN:
        return (
            "SKIPPED",
            "no GITHUB_TOKEN/GH_TOKEN — this repo has no clone of the SDK repos",
        )
    branch, reason = default_branch(repo)
    if branch is None:
        return "SKIPPED", reason
    status, body = gh_api(f"/repos/{GITHUB_ORG}/{repo}/compare/{branch}...{commit}")
    if status == 404:
        return "FAIL", f"commit {commit} unknown to {GITHUB_ORG}/{repo}"
    if status != 200 or body is None:
        return "SKIPPED", f"GitHub API returned {status} for {GITHUB_ORG}/{repo}"
    state = body.get("status")
    if state in ("identical", "behind"):
        return "PASS", f"reachable from {GITHUB_ORG}/{repo}@{branch}"
    return (
        "FAIL",
        f"commit {commit} is '{state}' relative to {GITHUB_ORG}/{repo}@{branch} "
        f"— authored but NOT merged",
    )


def verify(claim: Claim) -> tuple[str, str]:
    if claim.repo == THIS_REPO:
        return verify_local(claim.commit)
    return verify_remote(claim.repo, claim.commit)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    docs = [Path(a) for a in argv[1:]] or DEFAULT_DOCS
    exit_code = 0

    for doc in docs:
        if not doc.exists():
            print(f"::error::{doc} does not exist")
            return 1
        try:
            label = doc.resolve().relative_to(REPO_ROOT)
        except ValueError:
            label = doc
        print(f"=== {label} ===")
        rows, table_log = parse_doc(doc)

        print(f"\n-- tables inspected ({len(table_log)}) --")
        for section, where, verdict in table_log:
            print(f"  [{where}] {section}: {verdict}")

        parse_errors = [r for r in rows if r.error]
        notes = [r for r in rows if r.note]
        claims = [c for r in rows for c in r.claims]

        if notes:
            print(f"\n-- rows claiming no commit ({len(notes)}) --")
            for r in notes:
                print(f"  [line {r.line_no}] {r.note}")

        print(f"\n-- claims ({len(claims)}) --")
        results = [(c, *verify(c)) for c in claims]
        width = max((len(f"{c.finding_id} {c.repo}") for c, _, _ in results), default=0)
        for claim, status, detail in results:
            label = f"{claim.finding_id} {claim.repo}".ljust(width)
            print(f"  {status:<8} {label}  {claim.commit}  — {detail}")

        failed = [(c, d) for c, s, d in results if s == "FAIL"]
        skipped = [(c, d) for c, s, d in results if s == "SKIPPED"]
        passed = [c for c, s, _ in results if s == "PASS"]

        if skipped:
            print(f"\n-- SKIPPED, NOT VERIFIED ({len(skipped)}) --")
            print(
                "  These rows were NOT checked. They are listed by name so the run "
                "cannot be read as a clean pass."
            )
            for claim, detail in skipped:
                print(
                    f"  ::notice::SKIPPED {claim.finding_id} {claim.repo} "
                    f"{claim.commit} (§ {claim.section}, line {claim.line_no}) — {detail}"
                )

        if parse_errors:
            print(f"\n-- UNPARSEABLE ROWS ({len(parse_errors)}) --")
            for r in parse_errors:
                print(f"  ::error::line {r.line_no} [{r.section}] {r.error}")
                print(f"      row: {r.raw}")

        if failed:
            print(f"\n-- FAILURES ({len(failed)}) --")
            for claim, detail in failed:
                print(
                    f"  ::error::{claim.finding_id} claims {claim.repo}@{claim.commit} "
                    f"(§ {claim.section}, line {claim.line_no}) — {detail}"
                )

        print(
            f"\nsummary: {len(passed)} verified, {len(failed)} failed, "
            f"{len(skipped)} skipped, {len(parse_errors)} unparseable row(s)"
        )
        if failed or parse_errors:
            exit_code = 1

    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
