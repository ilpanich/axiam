#!/usr/bin/env python3
"""Assert the workspace's crate dependency graph still points inward.

Why this exists
---------------
The 2026-08 SOLID/clean-architecture review found the layering in this
workspace to be **sound and entirely unenforced**. ``axiam-core`` has no
internal dependencies, the graph flows one way, and the three protocol
adapters all delegate authorization to one engine rather than re-implementing
it -- but nothing in CI fails when a new ``axiam-`` line is added to the wrong
``Cargo.toml``. A rule that holds only by discipline is a rule with a
half-life.

The failure this prevents is quiet and expensive. Nobody adds a bad edge on
purpose; they add ``axiam-db`` to ``axiam-authz``'s ``[dependencies]`` because
a query was convenient, the build stays green, and six months later the policy
engine cannot be unit-tested without a datastore. By then the edge has load
bearing on it. The cheap moment to catch that is the pull request that
introduces it.

The rule
--------
Layers are numbered outward from the domain. **A crate may depend only on
crates in a strictly lower layer.** This is the Clean Architecture dependency
rule: dependencies point inward, toward the domain, never outward.

Two consequences are worth stating because they are easy to misread as
violations:

* ``axiam-db`` (an infrastructure adapter, layer 2) depending on ``axiam-auth``
  and ``axiam-pki`` (domain services, layer 1) is **correct**, not a violation.
  Password hashing belongs next to the write; the adapter reaching inward for a
  domain service is exactly what the dependency rule permits. Re-implementing
  Argon2id inside ``axiam-db`` to "fix" the edge would be the actual mistake.

* ``axiam-scim`` sitting *above* ``axiam-api-rest`` rather than beside it is a
  deliberate placement, not an accident of alphabetical order. SCIM is a REST
  sub-surface mounted into the same Actix app -- it consumes the REST crate's
  ``AppState`` and extractors. Placing it one layer out records that "SCIM may
  use REST, REST may never use SCIM", which is the invariant that matters.

Dev-dependencies are checked separately
---------------------------------------
Three crates invert the rule in ``[dev-dependencies]`` only: ``axiam-auth``,
``axiam-authz`` and ``axiam-pki`` each reach *outward* to ``axiam-db`` so their
unit tests can run against a real repository rather than a hand-rolled double.
That is a legitimate and common pattern -- the inversion never reaches a
shipped artifact, because ``[dev-dependencies]` do not.

It is still worth naming. An undeclared test-only inversion is how a
"temporary" test helper becomes a production import: somebody moves one
function out of ``#[cfg(test)]`` and the edge silently promotes itself. So
every inverting test edge must appear in ``TEST_ONLY_INVERSIONS`` below with a
reason. New ones are a finding until somebody writes the reason down.

Usage:
    scripts/check-crate-layering.py             # check this workspace
    scripts/check-crate-layering.py --graph     # print the layer table and exit 0
    scripts/check-crate-layering.py --self-test # run the gate's own fixtures

Exit status:
    0 = every edge points inward, and every test-only inversion is declared
    1 = at least one edge violates the rule, or a crate is not placed in a layer
    2 = the gate could not run (workspace not found, unparseable manifest)
"""

import os
import sys
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
CRATES_DIR = os.path.join(REPO_ROOT, "crates")

PREFIX = "axiam-"

# ---------------------------------------------------------------------------
# The policy
# ---------------------------------------------------------------------------
#
# Layer 0 is the domain. Each step out may reach in, never out. Adding a crate
# to the workspace WITHOUT adding it here is itself a failure: an unplaced
# crate has no rule to violate, which is the one state this gate must never
# report as healthy.
LAYERS: dict[str, int] = {
    # 0 -- the domain, and the test scaffolding that must never grow a
    #      dependency of its own.
    "axiam-core": 0,          # entities, value objects, and the repository ports
    "axiam-test-support": 0,  # test-only helpers; deliberately dependency-free
    # axiam-opaque is layer 0 for a reason worth stating: it is the single
    # definition of AXIAM's OPAQUE ciphersuite and key-stretching functions,
    # and it is compiled into the eleven client SDKs as well as into the
    # server. Anything it depended on would become a dependency of every SDK,
    # and any drift between a server-side and a client-side definition of the
    # suite would be a silent cross-language break. Keeping it dependency-free
    # is what makes "one implementation, not twelve" enforceable rather than
    # aspirational.
    "axiam-opaque": 0,
    # 1 -- domain services: policy and cryptography expressed over layer 0's
    #      types, with no knowledge of storage or transport.
    # The two packaging wrappers around axiam-opaque. Layer 1 because they
    # depend on a layer-0 crate, though neither is a domain service: they are
    # leaf artifacts that nothing in the workspace depends on, existing only so
    # the SDKs without a native binding have something to link or import.
    #
    # `axiam-opaque-wasm` is not a Cargo workspace *member* — it only builds for
    # wasm32 and wasm-pack drives it directly — but it is a crate in this
    # directory and its dependency direction is checked here like any other.
    # Exempting it because of how it is built would be exempting it for a reason
    # that has nothing to do with what this gate measures.
    "axiam-opaque-ffi": 1,
    "axiam-opaque-wasm": 1,
    "axiam-auth": 1,
    "axiam-authz": 1,
    "axiam-pki": 1,
    "axiam-email": 1,
    # 2 -- infrastructure adapters implementing layer 0's ports.
    "axiam-db": 2,
    "axiam-audit": 2,
    # 3/4 -- federation protocol logic, then the OAuth2/OIDC authorization
    #        server that builds on it. Two layers rather than one because
    #        axiam-oauth2 consumes axiam-federation and the reverse must stay
    #        impossible.
    "axiam-federation": 3,
    "axiam-oauth2": 4,
    # 5 -- the messaging adapter, which both HTTP adapters publish through.
    "axiam-amqp": 5,
    # 6 -- protocol adapters.
    "axiam-api-rest": 6,
    "axiam-api-grpc": 6,
    # 7 -- a REST sub-surface mounted into axiam-api-rest (see module docstring).
    "axiam-scim": 7,
    # 8 -- the composition root. Everything may be reached from here and
    #      nothing may reach back.
    "axiam-server": 8,
}

LAYER_NAMES = {
    0: "domain",
    1: "domain services",
    2: "infrastructure",
    3: "federation protocol",
    4: "authorization server",
    5: "messaging adapter",
    6: "protocol adapters",
    7: "REST sub-surface",
    8: "composition root",
}

# Outward edges that exist only in [dev-dependencies]. Each entry is
# (crate, dependency) -> why it is acceptable. An inverting test edge that is
# NOT listed here is a finding: write the reason down, or do not add the edge.
TEST_ONLY_INVERSIONS: dict[tuple[str, str], str] = {
    ("axiam-auth", "axiam-db"): (
        "AuthService's unit tests exercise login, lockout and refresh rotation "
        "against real repositories rather than doubles, because the behaviour "
        "under test is the interaction with them"
    ),
    ("axiam-authz", "axiam-db"): (
        "the engine's tests seed real role/permission/resource rows: a "
        "hand-rolled double would encode this gate's own assumptions about "
        "hierarchy traversal instead of testing them"
    ),
    ("axiam-pki", "axiam-db"): (
        "certificate issuance tests persist and re-read the issued material to "
        "prove the private key is never stored"
    ),
}


class GateError(Exception):
    """The gate could not run -- distinct from the gate finding a violation."""


def load_workspace(crates_dir: str) -> dict[str, dict[str, list[str]]]:
    """Return ``{crate: {"dependencies": [...], "dev-dependencies": [...]}}``.

    Only ``axiam-``-prefixed entries are returned; third-party dependencies are
    not this gate's business. Both ``{ workspace = true }`` and ``{ path = ... }``
    forms are picked up, because they are equally capable of introducing an
    edge and have in fact both been used in this workspace.
    """
    if not os.path.isdir(crates_dir):
        raise GateError(f"no crates directory at {crates_dir}")

    graph: dict[str, dict[str, list[str]]] = {}
    for name in sorted(os.listdir(crates_dir)):
        manifest = os.path.join(crates_dir, name, "Cargo.toml")
        if not os.path.isfile(manifest):
            continue
        try:
            with open(manifest, "rb") as fh:
                data = tomllib.load(fh)
        except tomllib.TOMLDecodeError as exc:
            raise GateError(f"{manifest} is not valid TOML: {exc}") from exc

        crate = data.get("package", {}).get("name", name)
        sections: dict[str, list[str]] = {}
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            sections[section] = sorted(
                k for k in data.get(section, {}) if k.startswith(PREFIX)
            )
        # Platform-gated dependency tables are edges too.
        for target in data.get("target", {}).values():
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                extra = [k for k in target.get(section, {}) if k.startswith(PREFIX)]
                sections[section] = sorted(set(sections[section]) | set(extra))
        graph[crate] = sections
    if not graph:
        raise GateError(f"no crate manifests found under {crates_dir}")
    return graph


def check(graph: dict[str, dict[str, list[str]]], layers: dict[str, int],
          inversions: dict[tuple[str, str], str]) -> list[str]:
    """Return a list of human-readable findings; empty means the gate passes."""
    findings: list[str] = []

    unplaced = sorted(set(graph) - set(layers))
    for crate in unplaced:
        findings.append(
            f"{crate} is in the workspace but not placed in LAYERS. An unplaced "
            f"crate cannot violate the dependency rule, which makes it the one "
            f"thing this gate must not pass. Decide which layer it belongs to "
            f"and add it to scripts/check-crate-layering.py."
        )

    stale = sorted(set(layers) - set(graph))
    for crate in stale:
        findings.append(
            f"{crate} is placed in LAYERS but no longer exists in the workspace. "
            f"Remove it from scripts/check-crate-layering.py so the table keeps "
            f"describing something real."
        )

    for crate in sorted(graph):
        if crate not in layers:
            continue  # already reported as unplaced
        here = layers[crate]

        # Production edges: strictly inward, no exceptions.
        for dep in graph[crate]["dependencies"] + graph[crate]["build-dependencies"]:
            if dep not in layers:
                continue  # the unplaced-crate finding above covers this
            there = layers[dep]
            if there >= here:
                relation = "its own layer" if there == here else "an outer layer"
                findings.append(
                    f"{crate} (layer {here}, {LAYER_NAMES.get(here, '?')}) depends on "
                    f"{dep} (layer {there}, {LAYER_NAMES.get(there, '?')}) -- {relation}. "
                    f"Dependencies point inward. Either the edge is wrong, or the "
                    f"layer table is: whichever it is, it needs a decision rather "
                    f"than a default."
                )

        # Test edges: may invert, must be declared.
        for dep in graph[crate]["dev-dependencies"]:
            if dep not in layers:
                continue
            there = layers[dep]
            if there >= here and (crate, dep) not in inversions:
                findings.append(
                    f"{crate} dev-depends on {dep}, which is at layer {there} -- "
                    f"outward from {crate}'s layer {here}. Test-only inversions are "
                    f"allowed but must be named: add ({crate!r}, {dep!r}) to "
                    f"TEST_ONLY_INVERSIONS with the reason the test needs the real "
                    f"thing. An inversion nobody wrote down is one nobody reviews "
                    f"when it later escapes #[cfg(test)]."
                )

    # A declared inversion that no longer exists is dead policy.
    for (crate, dep), _reason in sorted(inversions.items()):
        if crate not in graph:
            findings.append(
                f"TEST_ONLY_INVERSIONS names {crate}, which is not in the workspace."
            )
        elif dep not in graph[crate]["dev-dependencies"]:
            findings.append(
                f"TEST_ONLY_INVERSIONS declares {crate} -> {dep}, but {crate} no "
                f"longer dev-depends on {dep}. Drop the entry: a granted exemption "
                f"that nothing uses reads as precedent."
            )

    return findings


def print_graph(graph: dict[str, dict[str, list[str]]], layers: dict[str, int]) -> None:
    by_layer: dict[int, list[str]] = {}
    for crate, layer in sorted(layers.items()):
        by_layer.setdefault(layer, []).append(crate)
    print("Crate layering (dependencies point inward, toward layer 0):\n")
    for layer in sorted(by_layer):
        print(f"  {layer}  {LAYER_NAMES.get(layer, '?')}")
        for crate in by_layer[layer]:
            deps = graph.get(crate, {}).get("dependencies", [])
            rendered = ", ".join(f"{d}({layers[d]})" for d in deps if d in layers)
            print(f"       {crate:22s} -> {rendered or '(none)'}")
    if TEST_ONLY_INVERSIONS:
        print("\n  Declared test-only inversions:")
        for (crate, dep), reason in sorted(TEST_ONLY_INVERSIONS.items()):
            print(f"       {crate} -[dev]-> {dep}")
            print(f"         {reason}")


# ---------------------------------------------------------------------------
# Self-test -- fixtures rather than the live workspace, so the gate's own
# failure modes are exercised even on a day when the workspace is clean.
# ---------------------------------------------------------------------------

def self_test() -> int:
    layers = {"a": 0, "b": 1, "b2": 1, "c": 2}

    def g(**kw):
        return {
            name: {
                "dependencies": list(spec.get("deps", [])),
                "dev-dependencies": list(spec.get("dev", [])),
                "build-dependencies": list(spec.get("build", [])),
            }
            for name, spec in kw.items()
        }

    cases: list[tuple[str, dict, dict, int]] = [
        (
            "inward edges pass",
            g(a={}, b={"deps": ["a"]}, c={"deps": ["a", "b"]}),
            {},
            0,
        ),
        (
            "an outward production edge fails",
            g(a={"deps": ["b"]}, b={}, c={}),
            {},
            1,
        ),
        (
            "a same-layer production edge fails",
            g(a={}, b={"deps": ["b2"]}, b2={"deps": []}, c={}),
            {},
            1,
        ),
        (
            "a crate absent from the layer table fails",
            g(a={}, b={}, c={}, newcomer={"deps": ["a"]}),
            {},
            1,
        ),
        (
            "an undeclared outward dev edge fails",
            g(a={"dev": ["c"]}, b={}, c={}),
            {},
            1,
        ),
        (
            "a declared outward dev edge passes",
            g(a={"dev": ["c"]}, b={}, c={}),
            {("a", "c"): "the unit test needs the real thing"},
            0,
        ),
        (
            "a declared inversion that no longer exists fails",
            g(a={}, b={}, c={}),
            {("a", "c"): "stale"},
            1,
        ),
        (
            "an outward build-dependency fails",
            g(a={"build": ["c"]}, b={}, c={}),
            {},
            1,
        ),
    ]

    cases.append(
        (
            "a layer-table entry with no crate behind it fails",
            g(a={}, b={}),
            {},
            1,
        )
    )

    failures = 0
    for index, (label, graph, inversions, expected) in enumerate(cases):
        # Every case but the last is scoped to the crates it actually declares,
        # so the "stale table entry" finding cannot fire as a side effect of a
        # fixture being small. The last case deliberately keeps the full table
        # in order to exercise exactly that finding.
        scoped = layers if index == len(cases) - 1 else {
            k: v for k, v in layers.items() if k in graph
        }
        findings = check(graph, scoped, inversions)
        got = 1 if findings else 0
        status = "ok  " if got == expected else "FAIL"
        if got != expected:
            failures += 1
        print(f"  {status} {label}")
        if got != expected:
            for f in findings:
                print(f"         {f}")

    # The live table must also be internally consistent: every layer number
    # used must have a name, or the failure messages become unreadable.
    for layer in sorted(set(LAYERS.values())):
        if layer not in LAYER_NAMES:
            print(f"  FAIL layer {layer} has no entry in LAYER_NAMES")
            failures += 1

    if failures:
        print(f"\nself-test FAILED: {failures} case(s)", file=sys.stderr)
        return 1
    print(f"\nself-test OK: {len(cases)} case(s)")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()

    try:
        graph = load_workspace(CRATES_DIR)
    except GateError as exc:
        print(f"crate layering gate could not run: {exc}", file=sys.stderr)
        return 2

    if "--graph" in argv:
        print_graph(graph, LAYERS)
        return 0

    findings = check(graph, LAYERS, TEST_ONLY_INVERSIONS)
    if findings:
        print("Crate layering check FAILED:\n", file=sys.stderr)
        for f in findings:
            print(f"  - {f}\n", file=sys.stderr)
        print(
            f"{len(findings)} problem(s) across {len(graph)} crate(s). "
            f"Run `scripts/check-crate-layering.py --graph` to see the table "
            f"this is checked against.",
            file=sys.stderr,
        )
        return 1

    edges = sum(
        len(s["dependencies"]) + len(s["build-dependencies"]) for s in graph.values()
    )
    print(
        f"Crate layering OK: {len(graph)} crates, {edges} internal production "
        f"edge(s), all pointing inward; "
        f"{len(TEST_ONLY_INVERSIONS)} declared test-only inversion(s)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
