#!/usr/bin/env python3
"""C4 — assert every REST handler module has a row in the frontend coverage matrix.

Why this exists: the server's REST surface grows faster than the admin console,
which is fine, but it should be *deliberate*. Before this check, a new handler
module could ship with no UI and no record that anyone had considered whether it
needed one — and the gap only surfaced when an operator asked how to do
something and the answer turned out to be "curl".

What it checks is deliberately shallow: that the module name appears in the
matrix. It does NOT check that the UI is adequate, or that the recorded status
is honest — neither is a thing a grep can answer. It checks that the question
was asked.

Exit 0 = every module has a row. Exit 1 = at least one does not, named.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
HANDLERS_DIR = os.path.join(REPO_ROOT, "crates", "axiam-api-rest", "src", "handlers")
MATRIX = os.path.join(REPO_ROOT, "claude_dev", "frontend-coverage-matrix.md")


def handler_modules():
    if not os.path.isdir(HANDLERS_DIR):
        sys.exit(f"handler directory not found: {HANDLERS_DIR}")
    return sorted(
        f[:-3]
        for f in os.listdir(HANDLERS_DIR)
        if f.endswith(".rs")
    )


def matrix_rows(text):
    """Module names appearing in the first column of a matrix row.

    Rows look like `| \\`module\\` | ... |`, so the first backticked token on a
    table line is the module the row is about.
    """
    names = set()
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        first_cell = line.split("|")[1] if line.count("|") >= 2 else ""
        m = re.search(r"`([a-z0-9_]+)`", first_cell)
        if m:
            names.add(m.group(1))
    return names


def main():
    if not os.path.isfile(MATRIX):
        sys.exit(f"coverage matrix not found: {MATRIX}")
    with open(MATRIX) as f:
        covered = matrix_rows(f.read())

    modules = handler_modules()
    missing = [m for m in modules if m not in covered]

    if missing:
        print("Frontend coverage matrix is out of date.", file=sys.stderr)
        print("", file=sys.stderr)
        for m in missing:
            print(f"  - handlers/{m}.rs has no row in the matrix", file=sys.stderr)
        print("", file=sys.stderr)
        print(
            "Add a row to claude_dev/frontend-coverage-matrix.md saying whether this\n"
            "surface has a UI, is a deliberate gap, or is deliberately headless.\n"
            "A row saying 'headless, machine-to-machine only' is a perfectly good\n"
            "answer -- the check is that somebody decided, not that a page exists.",
            file=sys.stderr,
        )
        return 1

    print(f"frontend coverage matrix: {len(modules)} handler modules, all recorded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
