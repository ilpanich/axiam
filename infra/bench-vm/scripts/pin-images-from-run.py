#!/usr/bin/env python3
"""Print `export BENCH_*_IMAGE=<repo>@<digest>` lines for the images a past run measured.

    pin-images-from-run.py <results-tree> [--except VAR ...]

<results-tree> is a run's results directory as the harness wrote it (e.g.
results/run-1): every <target>/<profile>/<scenario>.meta.json under it records,
per container, the image reference and the registry digest it ran
(containers[].image / .image_digest). A follow-up run that must measure the
SAME competitors and datastore pins them from there, by digest, instead of by
tags that a registry can move.

Refuses to print anything when a role ran with more than one digest across the
tree, or with no digest at all (an image built locally has none): either would
make "the same image as before" ambiguous. --except leaves a variable out, e.g.
--except BENCH_AXIAM_IMAGE when the follow-up measures a new AXIAM release.

    eval "$(python3 -I pin-images-from-run.py results/run-1 --except BENCH_AXIAM_IMAGE)"
"""
import glob
import json
import os
import sys

# (target, role) -> the variable each target's compose file reads.
VARIABLE = {
    ("axiam", "server"): "BENCH_AXIAM_IMAGE",
    ("axiam", "db"): "BENCH_SURREALDB_IMAGE",
    ("axiam", "mq"): "BENCH_RABBITMQ_IMAGE",
    ("keycloak", "server"): "BENCH_KEYCLOAK_IMAGE",
    ("keycloak", "db"): "BENCH_PG_IMAGE",
    ("zitadel", "server"): "BENCH_ZITADEL_IMAGE",
    ("zitadel", "db"): "BENCH_PG_IMAGE",
    ("authentik", "server"): "BENCH_AUTHENTIK_IMAGE",
    ("authentik", "worker"): "BENCH_AUTHENTIK_IMAGE",
    ("authentik", "db"): "BENCH_PG_IMAGE",
}


def repository(ref):
    """'quay.io/keycloak/keycloak:26.8.1' -> 'quay.io/keycloak/keycloak' (a registry port is kept)."""
    ref = ref.split("@", 1)[0]
    head, _, last = ref.rpartition("/")
    return f"{head}/{last.split(':', 1)[0]}" if head else last.split(":", 1)[0]


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        raise SystemExit(__doc__)
    tree, rest = argv[1], argv[2:]
    skip = set()
    while rest:
        if rest[0] != "--except" or len(rest) < 2:
            raise SystemExit(__doc__)
        skip.add(rest[1])
        rest = rest[2:]

    metas = sorted(glob.glob(os.path.join(tree, "*", "*", "*.meta.json")))
    if not metas:
        raise SystemExit(f"no <target>/<profile>/*.meta.json under {tree}")

    seen = {}  # variable -> {(repository, digest)}
    for path in metas:
        with open(path, encoding="utf-8") as f:
            meta = json.load(f)
        for c in meta.get("containers", []):
            var = VARIABLE.get((meta.get("target"), c.get("role")))
            if var is None or var in skip:
                continue
            digest = c.get("image_digest") or ""
            if not digest.startswith("sha256:"):
                raise SystemExit(f"{path}: {c.get('name')} has no registry digest ({digest!r}); "
                                 "it was not a pulled image, so it cannot be pinned")
            seen.setdefault(var, set()).add((repository(c.get("image", "")), digest))

    lines = []
    for var in sorted(seen):
        refs = seen[var]
        if len(refs) != 1:
            raise SystemExit(f"{var} ran with {len(refs)} different images in {tree}: "
                             + ", ".join(f"{r}@{d[:19]}…" for r, d in sorted(refs)))
        repo, digest = next(iter(refs))
        lines.append(f"export {var}={repo}@{digest}")
    print("\n".join(lines))


if __name__ == "__main__":
    main(sys.argv)
