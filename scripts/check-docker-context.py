#!/usr/bin/env python3
"""Assert every ``COPY`` source in ``docker/Dockerfile.*`` survives ``.dockerignore``.

Why this exists
---------------
``.dockerignore`` excludes ``docker/`` wholesale and re-includes exactly the one
file the frontend image needs. That negation is coupled to the Dockerfile *by
name*, and nothing enforced the coupling::

    docker/
    !docker/nginx.conf          # the file this named was renamed away

Commit e26e171 renamed ``docker/nginx.conf`` to ``docker/nginx.conf.template``
and updated the ``COPY`` in ``docker/Dockerfile.frontend``, but not the
negation. With the negation matching nothing, the template was filtered out of
the build context before BuildKit ever saw it, and the build died on::

    COPY docker/nginx.conf.template /etc/nginx/templates/default.conf.template
    ERROR: failed to compute cache key: "/docker/nginx.conf.template": not found

The file was present and tracked in git the whole time. That is what makes this
class of break nasty: every local check agrees the file is there, because every
local check looks at the worktree rather than at the *context*.

It was invisible until release. CI does not build the images -- it only
hadolints the Dockerfiles, which cannot see a context -- so the first build of
the frontend image in the whole pipeline happens in ``release.yml``, on a
version tag. Both frontend legs of the ``v1.0.0-beta08`` release sank, ~4
seconds in, on a one-word mismatch that had been sitting in main for hours.

This gate answers the same question the release build would, without a daemon,
a registry login, or a build: for each ``COPY`` source that comes from the build
context, is there at least one file that both exists and is not excluded? It
needs no toolchain, so it runs on every commit rather than on a path filter --
the release-bump gap in ``check-spec-digest.py``'s docstring is the same lesson.

What it does not do
-------------------
It does not build anything, so it cannot catch a Dockerfile that is well-formed
and context-correct but fails to compile. It checks ``COPY``/``ADD`` sources
that read from the context; ``--from=<stage>`` sources are copied from an
earlier stage rather than the context and are skipped, because their existence
is a property of the build, not of ``.dockerignore``.

Files come from ``git ls-files``, not a directory walk: CI checks out tracked
files only, so the tracked set *is* the context, and asking git keeps the gate
from wandering into ``target/`` or ``node_modules/``.

Cross-implementation check
--------------------------
``DockerIgnore`` reimplements moby/patternmatcher's ``MatchesOrParentMatches``
(the matcher BuildKit uses for ``.dockerignore``): patterns are cleaned, a
directory match excludes everything beneath it, and the *last* matching pattern
decides, so a ``!`` exception only re-includes what it literally matches. The
self-test pins that semantics -- including the exact rename that broke beta08 --
against fixtures rather than against this repository, so the gate keeps failing
for the right reason on a day when the repository happens to be clean.

Usage::

    scripts/check-docker-context.py             # verify (CI)
    scripts/check-docker-context.py --self-test # fixtures

Exit codes: 0 every source resolves, 1 a source is missing or excluded,
2 could not run.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKER_DIR = REPO_ROOT / "docker"
DOCKERIGNORE = REPO_ROOT / ".dockerignore"


class GateError(Exception):
    """Raised when the gate cannot run, as opposed to finding a broken source."""


# --------------------------------------------------------------------------
# .dockerignore
# --------------------------------------------------------------------------


def _compile(pattern: str) -> re.Pattern[str]:
    """Translate one .dockerignore pattern to a regex, as patternmatcher does.

    ``*`` stops at a separator, ``**`` spans them, ``?`` is a single non-separator
    character, and everything else is literal. The result is anchored, so a
    pattern matches a whole path segment sequence and never a substring.
    """
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                i += 2
                if i >= n:
                    # A trailing ** matches everything that follows, if anything.
                    out.append(".*")
                    continue
                if pattern[i] == "/":
                    # `a/**/b` must also match `a/b`: the separator is optional.
                    i += 1
                out.append("(.*/)?")
                continue
            out.append("[^/]*")
            i += 1
            continue
        if ch == "?":
            out.append("[^/]")
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(re.escape(ch))
        i += 1
    return re.compile("^" + "".join(out) + "$")


def _clean(pattern: str) -> str:
    """Normalise a pattern the way filepath.Clean does for .dockerignore."""
    pattern = pattern.strip().replace("\\", "/").lstrip("/")
    while pattern.endswith("/") and pattern != "/":
        pattern = pattern[:-1]
    return pattern


class DockerIgnore:
    """The subset of moby/patternmatcher that .dockerignore actually uses."""

    def __init__(self, lines: list[str]) -> None:
        self.patterns: list[tuple[bool, str, re.Pattern[str]]] = []
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            exclusion = line.startswith("!")
            if exclusion:
                line = line[1:]
            cleaned = _clean(line)
            if not cleaned or cleaned == ".":
                continue
            self.patterns.append((exclusion, cleaned, _compile(cleaned)))

    @classmethod
    def load(cls, path: Path) -> "DockerIgnore":
        if not path.exists():
            return cls([])
        return cls(path.read_text(encoding="utf-8").splitlines())

    def is_excluded(self, path: str) -> bool:
        """True when *path* would not be sent to the daemon.

        Mirrors ``MatchesOrParentMatches``: a pattern is only consulted when it
        could change the current verdict, a match against any parent directory
        counts as a match, and the last pattern to match wins -- which is why a
        stale ``!docker/nginx.conf`` leaves ``docker/nginx.conf.template``
        excluded instead of re-including it.
        """
        parts = PurePosixPath(path).parts
        parents = ["/".join(parts[: i + 1]) for i in range(len(parts) - 1)]

        excluded = False
        for exclusion, _, regex in self.patterns:
            # An exception can only matter if we are currently excluding, and an
            # exclusion can only matter if we are not.
            if exclusion != excluded:
                continue
            if regex.match(path) or any(regex.match(p) for p in parents):
                excluded = not exclusion
        return excluded


# --------------------------------------------------------------------------
# Dockerfile parsing
# --------------------------------------------------------------------------

_INSTRUCTION = re.compile(r"^\s*(COPY|ADD)\b(.*)$", re.IGNORECASE)
_FLAG = re.compile(r"^--[A-Za-z0-9-]+(=\S*)?$")


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash continuations, keeping the line number of each start."""
    joined: list[tuple[int, str]] = []
    buffer, start = "", 0
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not buffer:
            if not stripped or stripped.startswith("#"):
                continue
            start = lineno
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        joined.append((start, buffer + stripped))
        buffer = ""
    if buffer:
        joined.append((start, buffer.strip()))
    return joined


def parse_context_sources(text: str) -> list[tuple[int, str]]:
    """Return ``(lineno, source)`` for COPY/ADD sources read from the context.

    ``--from=<stage>`` instructions are skipped: they copy from an earlier build
    stage, so ``.dockerignore`` has no say over them.
    """
    found: list[tuple[int, str]] = []
    for lineno, line in _logical_lines(text):
        match = _INSTRUCTION.match(line)
        if not match:
            continue
        tokens = match.group(2).split()
        flags = [t for t in tokens if _FLAG.match(t)]
        if any(f.lower().startswith("--from=") for f in flags):
            continue
        operands = [t for t in tokens if not _FLAG.match(t)]
        if len(operands) < 2:
            raise GateError(f"line {lineno}: cannot read COPY/ADD operands from {line!r}")
        for source in operands[:-1]:  # the last operand is the destination
            if source.startswith(("http://", "https://")):
                continue  # ADD from a URL never touches the context
            found.append((lineno, source))
    return found


# --------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------


def resolve(source: str, files: list[str], ignore: DockerIgnore) -> tuple[list[str], list[str]]:
    """Return ``(included, excluded)`` context files covered by *source*.

    A source covers a file when it matches the path or any of its parent
    directories -- ``COPY crates/ crates/`` reaches every file under ``crates``.
    """
    cleaned = _clean(source.lstrip("./") if source.startswith("./") else source)
    if not cleaned or cleaned == ".":
        regex = re.compile("^.*$")
    else:
        regex = _compile(cleaned)

    included, excluded = [], []
    for path in files:
        parts = PurePosixPath(path).parts
        prefixes = ["/".join(parts[: i + 1]) for i in range(len(parts))]
        if not any(regex.match(p) for p in prefixes):
            continue
        (excluded if ignore.is_excluded(path) else included).append(path)
    return included, excluded


def tracked_files() -> list[str]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError(f"cannot list tracked files: {exc}") from exc
    return [p for p in out.split("\0") if p]


def check(dockerfiles: list[Path]) -> int:
    ignore = DockerIgnore.load(DOCKERIGNORE)
    files = tracked_files()
    if not files:
        raise GateError("git reported no tracked files; refusing to pass vacuously")

    failures: list[str] = []
    checked = 0
    for dockerfile in dockerfiles:
        rel = dockerfile.relative_to(REPO_ROOT)
        text = dockerfile.read_text(encoding="utf-8")
        try:
            sources = parse_context_sources(text)
        except GateError as exc:
            raise GateError(f"{rel}: {exc}") from exc

        for lineno, source in sources:
            checked += 1
            included, excluded = resolve(source, files, ignore)
            if included:
                continue
            if excluded:
                sample = ", ".join(excluded[:3])
                more = f" (+{len(excluded) - 3} more)" if len(excluded) > 3 else ""
                failures.append(
                    f"{rel}:{lineno}: COPY {source}\n"
                    f"    exists in git but .dockerignore keeps it out of the context:\n"
                    f"    {sample}{more}"
                )
            else:
                failures.append(
                    f"{rel}:{lineno}: COPY {source}\n"
                    f"    matches no tracked file at all."
                )

    if failures:
        print(
            "Docker build context is missing sources these Dockerfiles COPY.\n",
            file=sys.stderr,
        )
        for failure in failures:
            print(f"  {failure}\n", file=sys.stderr)
        print(
            "Each of these would fail the image build with\n"
            '  ERROR: failed to compute cache key: "/<path>": not found\n'
            "and -- because CI only hadolints the Dockerfiles -- it would fail for\n"
            "the first time in the Release workflow, on a version tag.\n\n"
            "Fix by pointing .dockerignore's negation at the path the Dockerfile\n"
            "actually COPYs (a rename is the usual cause), or by correcting the\n"
            "COPY source.",
            file=sys.stderr,
        )
        return 1

    names = ", ".join(str(d.relative_to(REPO_ROOT)) for d in dockerfiles)
    print(f"{checked} context COPY sources resolve after .dockerignore ({names})")
    return 0


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------


def self_test() -> int:
    failures: list[str] = []

    def expect(label: str, got: object, want: object) -> None:
        if got != want:
            failures.append(f"{label}: got {got!r}, want {want!r}")

    # --- the beta08 regression, both sides of it ----------------------------
    stale = DockerIgnore(["docker/", "!docker/nginx.conf"])
    expect(
        "stale negation leaves the renamed template excluded",
        stale.is_excluded("docker/nginx.conf.template"),
        True,
    )
    expect(
        "stale negation still re-includes the old name",
        stale.is_excluded("docker/nginx.conf"),
        False,
    )
    fixed = DockerIgnore(["docker/", "!docker/nginx.conf.template"])
    expect(
        "corrected negation re-includes the template",
        fixed.is_excluded("docker/nginx.conf.template"),
        False,
    )
    expect(
        "corrected negation keeps the rest of docker/ out",
        fixed.is_excluded("docker/docker-compose.dev.yml"),
        True,
    )

    # --- matcher semantics ---------------------------------------------------
    nested = DockerIgnore(["target/"])
    expect("a directory pattern excludes what is beneath it",
           nested.is_excluded("target/debug/build.rs"), True)
    expect("a directory pattern does not excludes a sibling",
           nested.is_excluded("targeting/x.rs"), False)

    star = DockerIgnore(["*.md"])
    expect("* matches within a segment", star.is_excluded("README.md"), True)
    expect("* does not cross a separator", star.is_excluded("docs/README.md"), False)

    doublestar = DockerIgnore(["**/*.md"])
    expect("** crosses separators", doublestar.is_excluded("docs/a/README.md"), True)
    expect("**/ also matches at the root", doublestar.is_excluded("README.md"), True)

    order = DockerIgnore(["docker/", "!docker/keep", "docker/keep/secret"])
    expect("last matching pattern wins", order.is_excluded("docker/keep/secret"), True)
    expect("earlier exception still holds elsewhere",
           order.is_excluded("docker/keep/other"), False)

    comments = DockerIgnore(["# a comment", "", "  ", "target/"])
    expect("comments and blank lines are skipped", len(comments.patterns), 1)

    # --- Dockerfile parsing --------------------------------------------------
    parsed = parse_context_sources(
        "FROM scratch AS builder\n"
        "COPY Cargo.toml Cargo.lock ./\n"
        "COPY --from=builder /app/dist /usr/share/nginx/html\n"
        "COPY --chown=1000:1000 docker/nginx.conf.template /etc/nginx/t\n"
        "COPY crates/ \\\n"
        "     crates/\n"
        "# COPY commented.txt /x\n"
    )
    expect(
        "parser keeps context sources, drops --from and comments, joins continuations",
        parsed,
        [(2, "Cargo.toml"), (2, "Cargo.lock"), (4, "docker/nginx.conf.template"), (5, "crates/")],
    )

    # --- resolution ----------------------------------------------------------
    files = ["docker/nginx.conf.template", "crates/axiam-core/src/lib.rs", "README.md"]
    included, excluded = resolve("docker/nginx.conf.template", files, stale)
    expect("resolve reports the stale case as excluded, not missing",
           (included, excluded), ([], ["docker/nginx.conf.template"]))
    included, excluded = resolve("docker/nginx.conf.template", files, fixed)
    expect("resolve reports the fixed case as included",
           (included, excluded), (["docker/nginx.conf.template"], []))
    included, _ = resolve("crates/", files, fixed)
    expect("a directory source reaches files beneath it",
           included, ["crates/axiam-core/src/lib.rs"])
    included, excluded = resolve("missing/path.txt", files, fixed)
    expect("an absent source resolves to nothing at all",
           (included, excluded), ([], []))

    if failures:
        print("check-docker-context self-test FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("check-docker-context self-test passed")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true", help="run fixture tests and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    dockerfiles = sorted(DOCKER_DIR.glob("Dockerfile.*"))
    try:
        if not dockerfiles:
            raise GateError(f"no Dockerfiles found under {DOCKER_DIR}")
        return check(dockerfiles)
    except GateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
