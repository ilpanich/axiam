#!/usr/bin/env python3
"""Assert the FreeRADIUS recipe vendors nothing and references its image by digest.

Why this exists
---------------
Threat T-454 ("an unreviewed RADIUS crate, or a GPL-licensed RADIUS image,
enters the build") is judged Mitigated for the operator-run recipe on one
claim: ``docker/docker-compose.radius.yml`` *references* the upstream
``freeradius/freeradius-server`` image and this repository builds, ships and
redistributes none of it (FreeRADIUS is GPLv2). The entry's first named test,
the end-to-end ``radius_e2e.rs``, pulls the digest and runs. Nothing it asserts
would fail if a Dockerfile, FreeRADIUS sources or a built image entered the
tree (R101W6-11), so the claim "vendors nothing" had no test of its own.

This is that test. It fails when

  * ``docker/radius/`` holds a file named ``Dockerfile*`` or ``Containerfile*``
    (or ``*.dockerfile``), or any file with a ``FROM <image>`` instruction
    line: the recipe would be building an image, not referencing one;
  * ``docker/docker-compose.radius.yml`` names an ``image:`` that lacks an
    ``@sha256:<64 hex>`` digest (a tag moves; a digest is what was reviewed),
    declares a ``build:`` key, or names no ``image:`` at all (a gate that
    passes because it found nothing to check is not a gate).

The crate half of T-454 ("a RADIUS crate enters ``Cargo.lock``") is held by
``cargo-deny``'s licence allow-list (``deny.toml``, ``[licenses]``): a GPL
crate fails unless it is named. The entry cites both as its tests.

Needs no toolchain and no daemon, so it runs on every commit in the
Architecture Invariants job rather than behind a path filter.

Usage::

    scripts/check-radius-vendors-nothing.py              # check the tree
    scripts/check-radius-vendors-nothing.py --self-test  # run the fixtures

Exit status: 0 = clean; 1 = a finding (or a self-test case failed);
             2 = the gate could not run (a path it guards is missing).
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RADIUS_DIR = REPO_ROOT / "docker" / "radius"
COMPOSE_FILE = REPO_ROOT / "docker" / "docker-compose.radius.yml"

#: A file name that is, or is named for, an image build recipe.
BUILD_RECIPE_NAME = re.compile(r"^(dockerfile|containerfile)|\.(dockerfile|containerfile)$", re.I)
#: A Dockerfile ``FROM`` instruction line (instructions are conventionally
#: upper case; matching case-sensitively keeps prose such as "from the CA"
#: out of the net).
FROM_LINE = re.compile(r"^\s*FROM\s+(--\S+\s+)?\S+", re.M)
#: ``image:`` / ``build:`` as a YAML mapping key, optionally a list item.
IMAGE_KEY = re.compile(r"^\s*(?:-\s+)?image:\s*(.*)$")
BUILD_KEY = re.compile(r"^\s*(?:-\s+)?build:")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}(?![0-9a-zA-Z])")


class GateError(Exception):
    """The gate could not run, as opposed to finding a problem."""


def check_radius_dir(root: Path) -> list[str]:
    """Findings for a ``docker/radius/``-shaped directory."""
    if not root.is_dir():
        raise GateError(f"{root} is not a directory")
    findings: list[str] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        if BUILD_RECIPE_NAME.search(path.name):
            findings.append(f"docker/radius/{rel}: an image build recipe; the recipe references an upstream image and builds none")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary: a FROM line cannot be read from it
        m = FROM_LINE.search(text)
        if m:
            line = text.count("\n", 0, m.start()) + 1
            findings.append(f"docker/radius/{rel}:{line}: a `FROM` instruction line ({m.group(0).strip()!r}); the recipe references an upstream image and builds none")
    return findings


def strip_comment(line: str) -> str:
    """Drop a trailing YAML comment (`` #`` outside nothing a digest contains)."""
    return re.sub(r"(^|\s)#.*$", "", line)


def check_compose(compose: Path) -> list[str]:
    """Findings for a compose file: every ``image:`` pinned, no ``build:``."""
    if not compose.is_file():
        raise GateError(f"{compose} is not a file")
    findings: list[str] = []
    images = 0
    for n, raw in enumerate(compose.read_text(encoding="utf-8").splitlines(), 1):
        line = strip_comment(raw)
        if BUILD_KEY.match(line):
            findings.append(f"{compose.name}:{n}: a `build:` key; the recipe references an upstream image and builds none")
            continue
        m = IMAGE_KEY.match(line)
        if not m:
            continue
        images += 1
        ref = m.group(1).strip().strip("'\"")
        if not DIGEST.search(ref):
            findings.append(f"{compose.name}:{n}: image {ref!r} has no `@sha256:<64 hex>` digest; a tag moves, a digest is what was reviewed")
    if images == 0:
        findings.append(f"{compose.name}: names no `image:` at all; the check would pass on nothing")
    return findings


def check(radius_dir: Path, compose: Path) -> list[str]:
    return check_radius_dir(radius_dir) + check_compose(compose)


GOOD_COMPOSE = (
    "services:\n"
    "  freeradius:\n"
    "    image: freeradius/freeradius-server:3.2.8@sha256:" + "a" * 64 + "  # pinned\n"
)


def self_test() -> int:
    """Run the gate against synthetic trees, each bad in exactly one way."""
    failures = 0
    total = 0

    def case(name: str, files: dict[str, str | bytes], compose: str | None, expect: int | None, needle: str = "") -> None:
        """``expect`` is the finding count, or None for 'raises GateError'."""
        nonlocal failures, total
        total += 1
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "radius"
            root.mkdir()
            for rel, body in files.items():
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                if isinstance(body, bytes):
                    p.write_bytes(body)
                else:
                    p.write_text(body, encoding="utf-8")
            cf = Path(tmp) / "docker-compose.radius.yml"
            if compose is not None:
                cf.write_text(compose, encoding="utf-8")
            try:
                got = check(root, cf)
            except GateError:
                got = None
        ok = (got is None) if expect is None else (got is not None and len(got) == expect and all(needle in f for f in got))
        if not ok:
            failures += 1
        print(f"  {'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f"  -> {got!r}"))

    clean = {"README.md": "Take the CRL from the CA.\nfrom the start\n", "raddb/default": "authorize {\n}\n"}
    case("clean tree and pinned compose pass", clean, GOOD_COMPOSE, 0)
    case("Dockerfile is refused", {**clean, "Dockerfile": "x\n"}, GOOD_COMPOSE, 1, "build recipe")
    case("Dockerfile.radius is refused", {**clean, "build/Dockerfile.radius": "x\n"}, GOOD_COMPOSE, 1, "build recipe")
    case("Containerfile is refused", {**clean, "Containerfile": "x\n"}, GOOD_COMPOSE, 1, "build recipe")
    case("a FROM line in any file is refused", {**clean, "raddb/image.txt": "# c\nFROM debian:12\nRUN x\n"}, GOOD_COMPOSE, 1, "FROM")
    case("FROM with --platform is refused", {**clean, "x.sh": "  FROM --platform=linux/amd64 alpine\n"}, GOOD_COMPOSE, 1, "FROM")
    case("prose 'from' and a mid-line FROM pass", {**clean, "n.md": "SELECT a FROM b\nwe pull from upstream\n"}, GOOD_COMPOSE, 0)
    case("a binary file is skipped, not a crash", {**clean, "k.bin": b"\xff\xfe\x00FROM x\n"}, GOOD_COMPOSE, 0)
    case("image without a digest is refused", clean, "services:\n  f:\n    image: freeradius/freeradius-server:3.2.8\n", 1, "digest")
    case("image with a short digest is refused", clean, "services:\n  f:\n    image: x/y:1@sha256:abc123\n", 1, "digest")
    case("a digest only in a comment is refused", clean, "services:\n  f:\n    image: x/y:1  # @sha256:" + "a" * 64 + "\n", 1, "digest")
    case("a second unpinned image is refused", clean, GOOD_COMPOSE + "  g:\n    image: busybox:latest\n", 1, "busybox")
    case("quoted pinned image passes", clean, "services:\n  f:\n    image: 'x/y:1@sha256:" + "b" * 64 + "'\n", 0)
    case("a commented-out unpinned image is ignored", clean, GOOD_COMPOSE + "    # image: busybox:latest\n", 0)
    case("a build: key is refused", clean, GOOD_COMPOSE + "    build: ./docker/radius\n", 1, "build:")
    case("a compose file naming no image is refused", clean, "services: {}\n", 1, "no `image:`")
    case("a missing compose file cannot run", clean, None, None)

    # The bare directory case: a missing radius directory cannot run either.
    total += 1
    with tempfile.TemporaryDirectory() as tmp:
        try:
            check_radius_dir(Path(tmp) / "absent")
            ok = False
        except GateError:
            ok = True
    failures += 0 if ok else 1
    print(f"  {'ok  ' if ok else 'FAIL'} a missing docker/radius directory cannot run")

    if failures:
        print(f"\nself-test FAILED: {failures} case(s)", file=sys.stderr)
        return 1
    print(f"\nself-test OK: {total} case(s)")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    try:
        findings = check(RADIUS_DIR, COMPOSE_FILE)
    except GateError as exc:
        print(f"radius vendors-nothing gate could not run: {exc}", file=sys.stderr)
        return 2
    if findings:
        print("RADIUS recipe vendors-nothing check FAILED (T-454):\n", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        print(f"\n{len(findings)} problem(s).", file=sys.stderr)
        return 1
    n = sum(1 for p in RADIUS_DIR.rglob("*") if p.is_file())
    print(f"RADIUS recipe vendors nothing: {n} file(s) under docker/radius/ with no build recipe or FROM line; every compose image: is digest-pinned.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
