#!/usr/bin/env python3
"""Detect stale copies of this repo's vendored artifacts in the SDK repositories.

Why this exists (publishing-and-secrets.md §8): three artifacts are authored
**here** and vendored **there** —

    sdks/CONTRACT.md         -> <sdk repo>/CONTRACT.md
    sdks/openapi.json        -> <sdk repo>/openapi.json
    proto/axiam/v1/*.proto   -> <sdk repo>/proto/axiam/v1/*.proto

This repo's CI already guards the **sources**: ``sdk-openapi-drift.yml`` fails if
``sdks/openapi.json`` drifts from a fresh ``--dump-openapi`` export, and
``sdk-buf-gates.yml`` runs buf lint/breaking/format over ``proto/``. Nothing
detected a **stale copy downstream**, which §8 names as "the single sharpest edge
introduced by the multi-repo split — a silently stale ``proto/`` in one SDK
produces stubs that compile fine and talk to the server incorrectly".

The justification is empirical, not hypothetical. During the 2026-08-15 R5.8
re-vendoring pass, **eight** SDK repos were found pinned at contract 1.17 while
this repo was at 1.19 — and the plan driving that pass believed they were at
1.15. Both the staleness and the belief about the staleness were wrong. That is
precisely the class of unverified belief an automated gate replaces.

Comparison is by **git blob hash**, so it is exact and content-addressed: a copy
either is the same bytes as the source or it is not. Line-ending or trailing
-whitespace "equivalence" is deliberately not modelled — a vendored artifact that
differs at all has diverged from the thing it claims to be a copy of.

What this gate does NOT cover
-----------------------------
It compares the *vendored artifacts*. It does **not** compare an SDK's
*generated stubs* against that SDK's own vendored proto — a different failure,
and a real one: ``axiam-php-sdk``'s committed ``CheckAccessResponse.php`` was
missing ``reason_code = 3`` while its vendored ``authorization.proto`` was
perfectly current. A cross-repo artifact-hash job would have passed that repo.
Codegen drift is each SDK repo's own gate (``axiam-go-sdk``'s buf drift-check is
the reference). Both gates are needed; neither subsumes the other.

The reference-vector fixture in §8's table is likewise out of scope here: it is
vendored to different paths per language (``testdata/`` for Rust/TS/Python/Go,
an in-test-tree equivalent for C#/Java/PHP), so "same path, same bytes" is not
the right model for it.

Repos that legitimately vendor no protos
----------------------------------------
``axiam-c-sdk`` and ``axiam-cplusplus-sdk`` are pure REST/libcurl SDKs. They have
no ``.proto``, no generated stubs, and no ``protoc`` in their CMake or CI. A
naive "every repo has every artifact" check therefore fails **permanently** on
them — this was discovered the hard way in R5.8.

The exemption is expressed as an explicit, named policy in ``REST_ONLY_REPOS``
below rather than as a silent "404 means fine", so it is auditable and so the
*converse* is also caught: a repo declared REST-only that suddenly starts
vendoring protos is reported as a failure telling you to update the table. An
exemption you cannot see is indistinguishable from a bug.

Usage:
    scripts/check-sdk-artifact-drift.py                 # via the GitHub API
    scripts/check-sdk-artifact-drift.py --local-root ..  # via sibling clones

``--local-root`` compares against local clones of the SDK repos (reading the
blob ids straight out of each clone's default-branch tree, so a clone sitting on
a feature branch still reports on its default branch). It needs no token and no
egress, which makes the gate testable offline and usable from a developer's
machine before pushing an artifact change.

Environment:
    SDK_DRIFT_TOKEN / GITHUB_TOKEN / GH_TOKEN
                     token used to read the SDK repos. The default Actions
                     ``GITHUB_TOKEN`` is scoped to **this** repository only and
                     will NOT be able to read them — see the workflow comment.
    GITHUB_ORG       owner of the SDK repositories (default ``ilpanich``).

Exit status:
    0 = every artifact in every reachable repo matches this repo's source
    1 = drift found (a stale, missing or unexpected artifact)
    2 = the gate could not run — no repo could be inspected at all

Exit 2 is deliberately NOT exit 0. "I checked nothing" is not "nothing is
stale", and a scheduled job that goes green when its credentials are missing is
worse than no job, because it manufactures confidence.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

GITHUB_ORG = os.environ.get("GITHUB_ORG", "ilpanich")
TOKEN = (
    os.environ.get("SDK_DRIFT_TOKEN")
    or os.environ.get("GITHUB_TOKEN")
    or os.environ.get("GH_TOKEN")
)

#: Every SDK repository that vendors artifacts from this one.
SDK_REPOS = [
    "axiam-rust-sdk",
    "axiam-typescript-sdk",
    "axiam-python-sdk",
    "axiam-java-sdk",
    "axiam-kotlin-sdk",
    "axiam-csharp-sdk",
    "axiam-go-sdk",
    "axiam-php-sdk",
    "axiam-swift-sdk",
    "axiam-c-sdk",
    "axiam-cplusplus-sdk",
]

#: Repos that vendor NO protos, and why. See the module docstring: this is a
#: declared policy, not an inferred one, so that a repo which starts vendoring
#: protos is reported rather than silently absorbed.
REST_ONLY_REPOS = {
    "axiam-c-sdk": "pure REST/libcurl SDK — no .proto, no stubs, no protoc in CMake or CI",
    "axiam-cplusplus-sdk": "pure REST/libcurl SDK — no .proto, no stubs, no protoc in CMake or CI",
}

#: ``(path in this repo, path in the SDK repo)``. The flat artifacts; the proto
#: set is handled separately because its *membership* is part of what is checked.
FLAT_ARTIFACTS = [
    ("sdks/CONTRACT.md", "CONTRACT.md"),
    ("sdks/openapi.json", "openapi.json"),
]

#: Directory holding the vendored proto set, identical on both sides.
PROTO_DIR = "proto/axiam/v1"

OK = "OK"
STALE = "STALE"
MISSING = "MISSING"
UNEXPECTED = "UNEXPECTED"
SKIPPED = "SKIPPED"

#: Verdicts that mean the gate found a real problem.
FAILING = {STALE, MISSING, UNEXPECTED}


@dataclass
class Result:
    repo: str
    artifact: str
    verdict: str
    detail: str


@dataclass
class RepoReport:
    repo: str
    results: list[Result] = field(default_factory=list)
    #: True when the repo could not be inspected at all (unreachable, no token,
    #: no clone). Distinct from "inspected and clean".
    unreachable: bool = False
    unreachable_reason: str = ""


# ---------------------------------------------------------------------------
# This repo's side: the sources of truth
# ---------------------------------------------------------------------------


def git(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd or REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def source_hashes() -> dict[str, str]:
    """Blob id of every artifact as it stands in THIS working tree.

    The working tree, not ``HEAD``: on the scheduled run the tree *is* the
    default branch, and for a developer running this locally the tree is what
    they are about to publish, which is the thing they want compared.
    """
    proto_sources = sorted(
        p.relative_to(REPO_ROOT).as_posix()
        for p in (REPO_ROOT / PROTO_DIR).glob("*.proto")
    )
    if not proto_sources:
        sys.exit(f"error: no protos found under {PROTO_DIR} — wrong working directory?")

    paths = [src for src, _ in FLAT_ARTIFACTS] + proto_sources
    for path in paths:
        if not (REPO_ROOT / path).is_file():
            sys.exit(f"error: source artifact {path} is missing from this repo")

    proc = git("hash-object", "--", *paths)
    if proc.returncode != 0:
        sys.exit(f"error: git hash-object failed: {proc.stderr.strip()}")
    hashes = proc.stdout.split()
    if len(hashes) != len(paths):
        sys.exit("error: git hash-object returned an unexpected number of ids")

    out: dict[str, str] = {}
    for path, blob in zip(paths, hashes):
        # Map source path -> the path the SDK repo is expected to carry it at.
        vendored = dict(FLAT_ARTIFACTS).get(path, path)
        out[vendored] = blob
    return out


# ---------------------------------------------------------------------------
# The SDK side: two interchangeable readers
# ---------------------------------------------------------------------------


class Unreachable(Exception):
    """The repo could not be inspected — never conflated with 'clean'."""


class Reader:
    def blob(self, repo: str, path: str) -> str | None:
        """Blob id of ``path`` on the repo's default branch, or None if absent."""
        raise NotImplementedError

    def listdir(self, repo: str, path: str) -> dict[str, str] | None:
        """``{filename: blob id}`` for ``path``, or None if the dir is absent."""
        raise NotImplementedError


class ApiReader(Reader):
    """Reads blob ids over the GitHub contents API."""

    def __init__(self) -> None:
        self._default_branch: dict[str, str] = {}

    def _get(self, path: str) -> tuple[int, object]:
        req = urllib.request.Request(
            "https://api.github.com" + path,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {TOKEN}",
                "User-Agent": "axiam-sdk-artifact-drift-check",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, None
        except (urllib.error.URLError, TimeoutError) as e:
            raise Unreachable(f"GitHub API unreachable ({e})") from e

    def branch(self, repo: str) -> str:
        if repo not in self._default_branch:
            if not TOKEN:
                raise Unreachable(
                    "no SDK_DRIFT_TOKEN/GITHUB_TOKEN/GH_TOKEN in the environment"
                )
            status, body = self._get(f"/repos/{GITHUB_ORG}/{repo}")
            if status != 200 or not isinstance(body, dict):
                raise Unreachable(
                    f"GET /repos/{GITHUB_ORG}/{repo} returned HTTP {status} "
                    f"— the token cannot read this repository, or egress is blocked"
                )
            self._default_branch[repo] = body["default_branch"]
        return self._default_branch[repo]

    def _contents(self, repo: str, path: str) -> tuple[int, object]:
        ref = urllib.parse.quote(self.branch(repo), safe="")
        return self._get(
            f"/repos/{GITHUB_ORG}/{repo}/contents/"
            f"{urllib.parse.quote(path)}?ref={ref}"
        )

    def blob(self, repo: str, path: str) -> str | None:
        status, body = self._contents(repo, path)
        if status == 404:
            return None
        if status != 200 or not isinstance(body, dict) or "sha" not in body:
            raise Unreachable(f"GET contents/{path} returned HTTP {status}")
        return body["sha"]

    def listdir(self, repo: str, path: str) -> dict[str, str] | None:
        status, body = self._contents(repo, path)
        if status == 404:
            return None
        if status != 200 or not isinstance(body, list):
            raise Unreachable(f"GET contents/{path} returned HTTP {status}")
        return {
            e["name"]: e["sha"]
            for e in body
            if isinstance(e, dict) and e.get("type") == "file"
        }


class LocalReader(Reader):
    """Reads blob ids out of sibling clones' default-branch trees.

    Reads the *tree*, not the checked-out files, so a clone parked on a feature
    branch still reports on what its default branch actually carries — which is
    the only thing a downstream consumer would ever receive.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self._ref: dict[str, str] = {}

    def _clone(self, repo: str) -> Path:
        path = self.root / repo
        if not (path / ".git").exists():
            raise Unreachable(f"no clone at {path}")
        return path

    def ref(self, repo: str) -> str:
        if repo not in self._ref:
            clone = self._clone(repo)
            for candidate in ("origin/main", "main", "origin/master", "master"):
                if git("rev-parse", "--verify", "--quiet", f"{candidate}^{{commit}}",
                       cwd=clone).returncode == 0:
                    self._ref[repo] = candidate
                    break
            else:
                raise Unreachable(f"no default branch ref found in {clone}")
        return self._ref[repo]

    def blob(self, repo: str, path: str) -> str | None:
        clone = self._clone(repo)
        proc = git("rev-parse", "--verify", "--quiet", f"{self.ref(repo)}:{path}",
                   cwd=clone)
        return proc.stdout.strip() or None

    def listdir(self, repo: str, path: str) -> dict[str, str] | None:
        clone = self._clone(repo)
        proc = git("ls-tree", f"{self.ref(repo)}:{path}", cwd=clone)
        if proc.returncode != 0:
            return None
        out: dict[str, str] = {}
        for line in proc.stdout.splitlines():
            meta, _, name = line.partition("\t")
            parts = meta.split()
            if len(parts) == 3 and parts[1] == "blob":
                out[name] = parts[2]
        return out


# ---------------------------------------------------------------------------
# The comparison
# ---------------------------------------------------------------------------


def check_repo(repo: str, reader: Reader, sources: dict[str, str]) -> RepoReport:
    report = RepoReport(repo=repo)
    try:
        for _, vendored in FLAT_ARTIFACTS:
            expected = sources[vendored]
            actual = reader.blob(repo, vendored)
            if actual is None:
                report.results.append(
                    Result(repo, vendored, MISSING, "not present on the default branch")
                )
            elif actual != expected:
                report.results.append(
                    Result(
                        repo,
                        vendored,
                        STALE,
                        f"vendored {actual[:12]} != source {expected[:12]}",
                    )
                )
            else:
                report.results.append(Result(repo, vendored, OK, actual[:12]))

        report.results.extend(check_protos(repo, reader, sources))
    except Unreachable as e:
        report.unreachable = True
        report.unreachable_reason = str(e)
    return report


def check_protos(repo: str, reader: Reader, sources: dict[str, str]) -> list[Result]:
    expected = {
        Path(path).name: blob
        for path, blob in sources.items()
        if path.startswith(PROTO_DIR + "/")
    }
    listing = reader.listdir(repo, PROTO_DIR)
    rest_only = repo in REST_ONLY_REPOS

    if listing is None:
        if rest_only:
            return [
                Result(
                    repo,
                    PROTO_DIR,
                    OK,
                    f"no protos, as declared ({REST_ONLY_REPOS[repo]})",
                )
            ]
        return [
            Result(
                repo,
                PROTO_DIR,
                MISSING,
                f"the whole {PROTO_DIR} tree is absent, and this repo is not "
                f"declared REST-only in REST_ONLY_REPOS",
            )
        ]

    if rest_only:
        return [
            Result(
                repo,
                PROTO_DIR,
                UNEXPECTED,
                f"declared REST-only in REST_ONLY_REPOS, but now vendors "
                f"{len(listing)} proto file(s) — update that table, and check the "
                f"repo actually generates and ships stubs for them",
            )
        ]

    results: list[Result] = []
    for name in sorted(expected):
        want = expected[name]
        got = listing.get(name)
        path = f"{PROTO_DIR}/{name}"
        if got is None:
            results.append(Result(repo, path, MISSING, "not present on the default branch"))
        elif got != want:
            results.append(
                Result(repo, path, STALE, f"vendored {got[:12]} != source {want[:12]}")
            )
        else:
            results.append(Result(repo, path, OK, got[:12]))

    for name in sorted(set(listing) - set(expected)):
        results.append(
            Result(
                repo,
                f"{PROTO_DIR}/{name}",
                UNEXPECTED,
                "present downstream but not in this repo's proto set — a leftover "
                "from a removed proto, or a proto that was never upstreamed",
            )
        )
    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def render(reports: list[RepoReport], sources: dict[str, str], mode: str) -> int:
    print(f"SDK vendored-artifact drift check ({mode})")
    print(f"Source of truth: {REPO_ROOT}")
    print()
    print("Source blob ids:")
    for path in sorted(sources):
        print(f"  {sources[path][:12]}  {path}")
    print()

    inspected = [r for r in reports if not r.unreachable]
    unreachable = [r for r in reports if r.unreachable]
    drifted: list[Result] = []

    for report in reports:
        if report.unreachable:
            print(f"{report.repo}: SKIPPED — {report.unreachable_reason}")
            continue
        bad = [r for r in report.results if r.verdict in FAILING]
        drifted.extend(bad)
        if bad:
            print(f"{report.repo}: {len(bad)} problem(s)")
            for r in report.results:
                marker = "  !" if r.verdict in FAILING else "   "
                print(f"{marker} {r.verdict:<10} {r.artifact}  ({r.detail})")
        else:
            print(f"{report.repo}: up to date ({len(report.results)} artifacts)")

    print()
    print(
        f"Summary: {len(inspected)} repo(s) inspected, "
        f"{len(unreachable)} skipped, {len(drifted)} artifact problem(s)."
    )

    if not inspected:
        print()
        print(
            "FAIL: no repository could be inspected, so nothing was verified.\n"
            "      This is reported as a failure, not a pass: 'I checked nothing'\n"
            "      is not 'nothing is stale'. Provide a token that can read the\n"
            "      SDK repos (see the workflow comment) or use --local-root."
        )
        return 2

    if drifted:
        print()
        print("FAIL: the vendored copies below have drifted from this repo's sources.")
        for r in drifted:
            print(f"  {r.repo}: {r.verdict} {r.artifact} — {r.detail}")
        print()
        print(
            "Fix by re-vendoring in the named repo(s): copy the source artifact\n"
            "over the vendored one, re-run that SDK's codegen, and open a PR there.\n"
            "See publishing-and-secrets.md §8."
        )
        return 1

    if unreachable:
        print()
        print(
            "NOTE: the skipped repos above were NOT verified. They are named rather\n"
            "      than folded into the pass so this run cannot be misread as clean."
        )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--local-root",
        type=Path,
        help="compare against sibling clones under this directory instead of "
        "the GitHub API (no token, no egress)",
    )
    parser.add_argument(
        "--repo",
        action="append",
        dest="repos",
        help="limit to this repo (repeatable); default is all of them",
    )
    args = parser.parse_args(argv)

    repos = args.repos or SDK_REPOS
    unknown = sorted(set(repos) - set(SDK_REPOS))
    if unknown:
        sys.exit(f"error: not an SDK repo: {', '.join(unknown)}")

    if args.local_root:
        root = args.local_root.resolve()
        if not root.is_dir():
            sys.exit(f"error: --local-root {root} is not a directory")
        reader: Reader = LocalReader(root)
        mode = f"local clones under {root}"
    else:
        reader = ApiReader()
        mode = f"GitHub API, org {GITHUB_ORG}"

    sources = source_hashes()
    reports = [check_repo(repo, reader, sources) for repo in repos]
    return render(reports, sources, mode)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
