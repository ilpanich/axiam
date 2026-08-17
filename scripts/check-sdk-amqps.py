#!/usr/bin/env python3
"""CONTRACT.md §8b rule 7 — assert every SDK ENFORCES amqps://, rather than documenting it.

Why this exists, precisely
--------------------------

§8b has said "an SDK MUST NOT fall back to plaintext" since contract 1.6. Three
SDKs satisfied that sentence by writing it down. The TypeScript reactor runtime
carried this comment::

    Broker URL. Must be `amqps://` for any routable host (§8b) — there is no
    verification-skip switch and no plaintext fallback.

directly above ``await amqp.connect(config.amqpUrl)`` — no scheme check, no TLS
options, and an ``amqp://`` URL connected without complaint. Java and C# stated
the same requirement in a doc comment on a parameter that accepted any channel
the caller had already opened.

Documented-but-unenforced is the worst of the three states: it reads as a
guarantee at review time and behaves as an invitation at runtime. Rule 7 exists
because of that, and this check is rule 7's enforcement.

What it checks
--------------

For each SDK repo that speaks AMQP, one **named enforcement point** must exist —
the symbol §8b's per-SDK index says is responsible — and it must be reachable
from the SDK's connection code. This is deliberately a structural check on the
presence of a named guard, not an attempt to prove the guard is correct: the
per-SDK unit tests do that, and they assert the stronger property (that no
socket is opened on a refusal). What no unit test catches is a *new* connection
path added later that forgets to route through the guard, which is exactly the
regression this file is for.

It also scans ``examples/`` for a plaintext ``amqp://`` URL. Since the server
became TLS-only such a URL points at a listener that does not exist, and an
example is precisely what gets copied into someone's service.

The scan is scoped to ``examples/`` on purpose. Library and test sources mention
``amqp://`` legitimately and often — a test asserting that plaintext is refused
has to name it, and the doc comment explaining *why* it is refused has to quote
it. Widening the scan to those produced 26 false findings against 3 real ones on
its first run, and a check with that ratio teaches people to ignore it.

Exit 0 = every SDK enforces §8b. Exit 1 = at least one does not, named.

Run from anywhere; SDK repos are located as siblings of this repository, matching
how the drift checker and `just` recipes already find them.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
SIBLINGS = os.path.dirname(REPO_ROOT)

# The §8b per-SDK index, as executable form. `guard` is the symbol that must
# exist; `dials` are the files that open a connection and must therefore be able
# to reach it.
SDKS = {
    "axiam-rust-sdk": {
        "guard": ("src/amqp/transport.rs", r"pub fn ensure_amqps"),
        "dials": ["src/amqp/consumer.rs", "src/amqp/reactor/runtime.rs"],
        "reaches": r"connect_amqps|ensure_amqps",
    },
    "axiam-typescript-sdk": {
        "guard": ("src/amqp/transport.ts", r"export function assertAmqpsUrl"),
        "dials": ["src/amqp/consumer.ts", "src/amqp/reactor/runtime.ts"],
        "reaches": r"buildAmqpConnectOptions|assertAmqpsUrl",
    },
    "axiam-python-sdk": {
        "guard": ("src/axiam_sdk/amqp/_reactor.py", r"def aio_pika_dialer"),
        "dials": ["src/axiam_sdk/amqp/_reactor.py"],
        "reaches": r'startswith\("amqps://"\)',
    },
    "axiam-go-sdk": {
        "guard": ("amqp/reactor_transport.go", r"func AMQPSDialer"),
        "dials": ["amqp/reactor_transport.go"],
        "reaches": r'HasPrefix\(strings\.ToLower\(url\), "amqps://"\)',
    },
    "axiam-php-sdk": {
        "guard": ("src/Reactor/AmqpLibReactorTransport.php", r"function parseAmqpsUrl"),
        "dials": ["src/Reactor/AmqpLibReactorTransport.php"],
        "reaches": r"parseAmqpsUrl",
    },
    "axiam-kotlin-sdk": {
        "guard": (
            "src/main/kotlin/io/axiam/sdk/reactor/RabbitMqReactorTransport.kt",
            r"fun reactorConnectionFactory",
        ),
        "dials": ["src/main/kotlin/io/axiam/sdk/reactor/RabbitMqReactorTransport.kt"],
        "reaches": r'scheme != "amqps"',
    },
    "axiam-java-sdk": {
        "guard": (
            "src/main/java/io/axiam/sdk/reactor/ReactorConnections.java",
            r"public static void requireAmqps",
        ),
        "dials": ["src/main/java/io/axiam/sdk/reactor/ReactorConnections.java"],
        "reaches": r"requireAmqps",
    },
    "axiam-csharp-sdk": {
        "guard": ("Axiam.Sdk/Reactor/ReactorConnections.cs", r"public static void RequireAmqps"),
        "dials": ["Axiam.Sdk/Reactor/ReactorConnections.cs", "Axiam.Sdk/Amqp/AxiamAmqpConsumer.cs"],
        "reaches": r"RequireAmqps",
    },
}

# Swift, C and C++ ship no AMQP runtime (§22.11), so they have nothing to
# enforce. Named here rather than omitted so a reader can tell "deliberately
# absent" from "forgotten".
NO_AMQP_RUNTIME = ("axiam-swift-sdk", "axiam-c-sdk", "axiam-cplusplus-sdk")

# Where a plaintext URL would be copied from. Vendored contract/spec files are
# excluded: CONTRACT.md quotes `amqp://` when explaining why it is refused.
SCAN_SUFFIXES = (
    ".rs", ".ts", ".py", ".go", ".php", ".kt", ".java", ".cs", ".md",
)
SCAN_SKIP_DIRS = {
    "node_modules", "target", "build", "bin", "obj", "dist", ".git",
    "vendor", "__pycache__", ".venv", "venv",
}
SCAN_SKIP_FILES = {"CONTRACT.md", "CHANGELOG.md", "openapi.json"}
# Only examples are scanned — see the module docstring for why.
SCAN_ROOT = "examples"

PLAINTEXT_URL = re.compile(r"amqp://", re.IGNORECASE)
# A line that mentions amqp:// only to say it is refused is not a finding. This
# is intentionally generous: the cost of a missed comment is a false positive on
# a line a human then reads, and the cost of being strict is that people learn
# to ignore the check.
REFUSAL_CONTEXT = re.compile(
    r"refus|reject|must use|must be|not allowed|forbidden|no plaintext|§8b|8b rule"
    r"|deprecated|instead of|rather than|was |used to|previously|expect_err|assertThrows"
    r"|Assert\.Throws|rejects\.toThrow|is_err|InlineData|expect\(",
    re.IGNORECASE,
)


def read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def check_guard(repo_path, spec, findings, sdk):
    guard_file, guard_pattern = spec["guard"]
    full = os.path.join(repo_path, guard_file)
    if not os.path.isfile(full):
        findings.append(
            f"{sdk}: §8b enforcement point {guard_file} is missing. Rule 7 requires the "
            f"amqps:// check to live in code; CONTRACT.md §8b's per-SDK index names this file."
        )
        return
    if not re.search(guard_pattern, read(full)):
        findings.append(
            f"{sdk}: {guard_file} exists but does not define the guard "
            f"(expected /{guard_pattern}/). §8b rule 7."
        )


def check_dials_reach_guard(repo_path, spec, findings, sdk):
    reaches = re.compile(spec["reaches"])
    for rel in spec["dials"]:
        full = os.path.join(repo_path, rel)
        if not os.path.isfile(full):
            findings.append(f"{sdk}: expected connection path {rel} is missing")
            continue
        if not reaches.search(read(full)):
            findings.append(
                f"{sdk}: {rel} opens an AMQP connection but does not reach the §8b guard "
                f"(expected /{spec['reaches']}/). A new dial path that skips the guard is "
                f"exactly the regression rule 7 exists to prevent."
            )


def check_no_plaintext_urls(repo_path, findings, sdk):
    examples = os.path.join(repo_path, SCAN_ROOT)
    if not os.path.isdir(examples):
        return
    for dirpath, dirnames, filenames in os.walk(examples):
        dirnames[:] = [d for d in dirnames if d not in SCAN_SKIP_DIRS and not d.startswith(".")]
        for name in sorted(filenames):
            if name in SCAN_SKIP_FILES or not name.endswith(SCAN_SUFFIXES):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, repo_path)
            for lineno, line in enumerate(read(path).splitlines(), 1):
                if PLAINTEXT_URL.search(line) and not REFUSAL_CONTEXT.search(line):
                    findings.append(
                        f"{sdk}: {rel}:{lineno} shows a plaintext amqp:// URL. The AXIAM "
                        f"server is TLS-only and has no plaintext listener, so this points at "
                        f"nothing — and it is how a plaintext default gets copied into a "
                        f"downstream service. Use amqps:// on 5671."
                    )


def main():
    findings = []
    checked = 0

    for sdk, spec in SDKS.items():
        repo_path = os.path.join(SIBLINGS, sdk)
        if not os.path.isdir(repo_path):
            print(f"  (skipped {sdk}: not checked out beside this repo)")
            continue
        checked += 1
        check_guard(repo_path, spec, findings, sdk)
        check_dials_reach_guard(repo_path, spec, findings, sdk)
        check_no_plaintext_urls(repo_path, findings, sdk)

    for sdk in NO_AMQP_RUNTIME:
        repo_path = os.path.join(SIBLINGS, sdk)
        if os.path.isdir(repo_path):
            print(f"  ({sdk}: no AMQP runtime by design — CONTRACT.md §22.11)")

    if findings:
        print("\nSDK §8b enforcement check FAILED:\n", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        print(
            f"\n{len(findings)} problem(s) across {checked} SDK(s).\n"
            f"CONTRACT.md §8b rule 7: rules 1-5 MUST be enforced in code, not stated in "
            f"documentation.",
            file=sys.stderr,
        )
        return 1

    if checked == 0:
        # Exit 2 = "the gate could not run", a distinct code from 1 = "the gate
        # found a problem". Returning 0 here would report "nothing was checked"
        # as "nothing is wrong", which is the manufactured confidence this
        # repository's other cross-repo gate exits 2 to refuse. Checking out the
        # SDK repos beside this one is what makes the gate real.
        print(
            "SDK §8b enforcement could NOT run: no SDK repo found beside "
            f"{REPO_ROOT}. Clone the axiam-*-sdk repos as siblings, or run this from a "
            "checkout that has them.",
            file=sys.stderr,
        )
        return 2

    print(f"SDK §8b enforcement OK: {checked} SDK(s), each with a named guard on its dial path.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
