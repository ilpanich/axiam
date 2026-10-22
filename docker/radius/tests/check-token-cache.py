#!/usr/bin/env python3
"""Assert that no call on the Live token cache can create an entry it should not.

Why this exists
---------------
``docker/radius/raddb/live/check-eap-tls`` caches FreeRADIUS's own AXIAM token
in ``axiam_token_cache`` (``rlm_cache``, ``raddb/live/axiam_live``). Each call on
that module is atomic (the rbtree driver holds its mutex for the call), two
calls by one thread are not, and what a call does is decided by the ``Cache-*``
control attributes set before it, which ``mod_cache_it`` removes when it returns
(``rlm_cache.c`` 3.2.8, :547-560). From the 3.2.8 source (``mod_cache_it``,
:467-534):

  * ``Cache-Status-Only := yes`` answers found / not found and touches nothing;
  * ``Cache-Read-Only := yes`` never inserts: a live entry is merged into the
    request (or expired, with ``Cache-TTL := 0``), an absent one is ``notfound``;
  * a negative ``Cache-TTL`` expires whatever entry is there and inserts this
    request's value;
  * anything else (no attribute, a zero or positive ``Cache-TTL``) inserts this
    request's value when the entry is absent and merges the entry over this
    request's value when it is present.

The last kind is what R111W5-01 (#720) and R112W5-01 (#764) are made of: a
plain call that runs after another thread dropped the entry inserts whatever
``Tmp-String-2`` holds (the refused token, or the sentinel), and a positive store
that finds another thread's entry decides with that entry instead of the token
the request just fetched. Which interleaving brings that about is a matter of
microseconds; the shape of the calls is not. This test checks the shape:

  1. no ``Cache-Status-Only := yes`` anywhere: a probe is only ever followed by
     a second call, and the window between the two is R112W5-01;
  2. every ``axiam_token_cache`` call is directly preceded by an
     ``update control`` block that sets ``Cache-Read-Only := yes`` or a negative
     ``Cache-TTL`` (``-N`` or ``"%{expr:0 - ...}"``);
  3. a call that is not read-only (a store) stores a token this request fetched:
     the last ``Tmp-String-2`` assignment before it is ``"%{1}"``;
  4. the rule the file's own comment states ("every attribute a check reads is
     given a value that matches nothing first"): no literal assigned to a
     ``Tmp-String-N`` passes a ``!~`` check of that attribute (the sentinel ``-``
     passed the token check, R112W5-01).

With the rules held, no interleaving of any number of threads can leave an
entry holding anything but a token a request fetched, nor make a request that
fetched a token decide with another one. That the cache module behaves as the
four bullets above say in the pinned image is ``token-cache-test.sh``'s job.

Usage::

    docker/radius/tests/check-token-cache.py              # check the shipped file
    docker/radius/tests/check-token-cache.py <file>       # check another one
    docker/radius/tests/check-token-cache.py --self-test  # run the fixtures

Exit status: 0 = clean; 1 = a finding (or a self-test case failed);
             2 = the file is missing, or holds no call on the cache.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

CHECK_EAP_TLS = Path(__file__).resolve().parent.parent / "raddb" / "live" / "check-eap-tls"
MODULE = "axiam_token_cache"
TOKEN = "Tmp-String-2"

ASSIGN = re.compile(r"^\s*(&?[A-Za-z][A-Za-z0-9-]*)\s*(:=|!\*)\s*(.*?)\s*$")
CHECK = re.compile(r"^\s*if \(&control:(Tmp-String-\d+) !~ /(.*)/\) \{\s*$")
# A call: bare, with an action block (`axiam_token_cache {`), optional (`-axiam_token_cache`).
CALL = re.compile(rf"^-?{MODULE}(\s*\{{)?$")
NEGATIVE_TTL = re.compile(r'^(-[1-9][0-9]*|"%\{expr:0 - [^"]+\}")$')


def code(line: str) -> str:
    """The line without its comment (the file has no `#` inside a string)."""
    return line.split("#", 1)[0].strip()


def check(text: str) -> list[str]:
    lines = text.splitlines()
    findings: list[str] = []
    calls = 0
    last_block: tuple[int, dict[str, str]] | None = None  # (end line, assignments)
    last_statement_end = 0
    in_block: dict[str, str] | None = None
    action_depth = 0  # inside the action block of a call: its lines are not statements
    token_value: str | None = None
    literals: dict[str, list[tuple[int, str]]] = {}
    checks: list[tuple[int, str, str]] = []

    for number, raw in enumerate(lines, 1):
        line = code(raw)
        if not line:
            continue
        if action_depth:
            action_depth += line.count("{") - line.count("}")
            if action_depth <= 0:
                action_depth = 0
                last_statement_end = number
            continue
        if in_block is not None:
            if line == "}":
                last_block = (number, in_block)
                last_statement_end = number
                in_block = None
                continue
            match = ASSIGN.match(line)
            if match:
                name, op, value = match.groups()
                in_block[name] = value if op == ":=" else "!*"
                if op == ":=" and name.startswith("Tmp-String-") and "%{" not in value:
                    literals.setdefault(name, []).append((number, value.strip('"')))
                if name == TOKEN and op == ":=":
                    token_value = value
                if name == "Cache-Status-Only" and op == ":=" and value == "yes":
                    findings.append(
                        f"{number}: Cache-Status-Only := yes is a probe; the call after it "
                        "is a second call, and another thread's drop can land between the two"
                    )
            continue
        if re.fullmatch(r"update control \{", line):
            in_block = {}
            continue
        match = CHECK.match(raw)
        if match:
            checks.append((number, match.group(1), match.group(2).replace(r"\/", "/")))
        call = CALL.match(line)
        if call:
            calls += 1
            attrs = last_block[1] if last_block and last_block[0] == last_statement_end else {}
            read_only = attrs.get("Cache-Read-Only") == "yes"
            ttl = attrs.get("Cache-TTL")
            if not read_only and not (ttl and NEGATIVE_TTL.match(ttl)):
                findings.append(
                    f"{number}: {MODULE} is called without Cache-Read-Only := yes or a negative "
                    "Cache-TTL in the update control block directly before it, so it can insert "
                    f"this request's {TOKEN} or merge another thread's entry over it"
                )
            elif not read_only and token_value != '"%{1}"':
                findings.append(
                    f"{number}: {MODULE} stores {TOKEN} = {token_value}, not a token this "
                    "request fetched (\"%{1}\")"
                )
        last_statement_end = number
        if call and call.group(1):
            action_depth = 1

    for number, name, pattern in checks:
        for at, literal in literals.get(name, []):
            if re.search(pattern, literal):
                findings.append(
                    f"{at}: {name} := \"{literal}\" passes the check at line {number} "
                    f"(/{pattern}/); a value set first must match nothing"
                )
    if calls == 0:
        findings.append(f"no call on {MODULE}: a gate that finds nothing to check is not a gate")
    return findings


def self_test() -> int:
    failed = 0
    head = (
        "update control {\n\tTmp-String-2 := \"!\"\n}\n"
        "if (&control:Tmp-String-2 !~ /^[A-Za-z0-9._~+\\/=-]+$/) {\n\treject\n}\n"
    )
    read_only = "update control {\n\tCache-Read-Only := yes\n}\naxiam_token_cache\n"
    store = (
        "update control {\n\tTmp-String-2 := \"%{1}\"\n}\n"
        "# the TTL\nupdate control {\n\tCache-TTL := \"%{expr:0 - %{1} / 2}\"\n}\naxiam_token_cache\n"
    )
    optional = "update control {\n\tCache-Read-Only := yes\n}\n-axiam_token_cache\n"
    actions = "axiam_token_cache {\n\tnotfound = ok\n}\n"
    cases = [
        ("the fixed shape", head + read_only + "if (notfound) {\n" + store + "}\n", None),
        ("a read-only drop", head + "update control {\n\tCache-Read-Only := yes\n\tCache-TTL := 0\n}\naxiam_token_cache\n", None),
        ("a literal negative TTL", head + "update control {\n\tTmp-String-2 := \"%{1}\"\n\tCache-TTL := -450\n}\naxiam_token_cache\n", None),
        ("the probe (R112W5-01)", head + "update control {\n\tCache-Status-Only := yes\n}\naxiam_token_cache\nif (notfound) {\n}\nelse {\n\taxiam_token_cache\n}\n", "Cache-Status-Only"),
        ("a plain call", head + "axiam_token_cache\n", "without Cache-Read-Only"),
        ("a positive store (1.1.1's first fetch)", head + "update control {\n\tTmp-String-2 := \"%{1}\"\n\tCache-TTL := \"%{expr:%{1} / 2}\"\n}\naxiam_token_cache\n", "without Cache-Read-Only"),
        ("a drop that is not read-only (1.1.1's)", head + "update control {\n\tCache-TTL := 0\n}\naxiam_token_cache\n", "without Cache-Read-Only"),
        ("a block that is not the one directly before", head + "update control {\n\tCache-Read-Only := yes\n}\nok\naxiam_token_cache\n", "without Cache-Read-Only"),
        ("a store of the sentinel", head + "update control {\n\tCache-TTL := -450\n}\naxiam_token_cache\n", "not a token this"),
        ("the sentinel `-` (R112W5-01)", head.replace('"!"', '"-"') + read_only, "passes the check"),
        ("a plain call with an action block", head + actions, "without Cache-Read-Only"),
        ("a read-only call with an action block", head + "update control {\n\tCache-Read-Only := yes\n}\n" + actions, None),
        ("an optional plain call", head + "-axiam_token_cache\n", "without Cache-Read-Only"),
        ("an optional read-only call", head + optional, None),
        ("an optional plain call with an action block", head + "-" + actions, "without Cache-Read-Only"),
        ("an optional read-only call with an action block", head + "update control {\n\tCache-Read-Only := yes\n}\n-" + actions, None),
        ("an optional store of the sentinel", head + "update control {\n\tCache-TTL := -450\n}\n-axiam_token_cache\n", "not a token this"),
        ("an optional store of a fetched token, with an action block", head + "update control {\n\tTmp-String-2 := \"%{1}\"\n\tCache-TTL := -450\n}\n-" + actions, None),
        ("a call after an action block does not inherit its block", head + read_only + actions, "without Cache-Read-Only"),
        ("no call at all", head, "no call on"),
    ]
    for name, text, needle in cases:
        findings = check(text)
        good = (not findings) if needle is None else any(needle in f for f in findings)
        print(f"  {'ok  ' if good else 'FAIL'} {name}")
        if not good:
            failed += 1
            for finding in findings:
                print(f"         {finding}")
    print(f"{len(cases) - failed} passed, {failed} failed")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    path = Path(argv[1]) if len(argv) > 1 else CHECK_EAP_TLS
    if not path.is_file():
        print(f"check-token-cache: {path} is missing", file=sys.stderr)
        return 2
    findings = check(path.read_text(encoding="utf-8"))
    for finding in findings:
        print(f"{path}:{finding}")
    if findings and findings[-1].startswith("no call on"):
        return 2
    if findings:
        return 1
    print(f"check-token-cache: {path}: every call on {MODULE} is read-only or a fetched token's store")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
