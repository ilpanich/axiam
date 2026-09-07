#!/usr/bin/env python3
"""Assert the server's locale allow-list and the SPA's message bundles agree.

Why this exists
---------------
W5 (``claude_dev/basic-op-gap-plan.md`` §4.6) gives the sign-in page a real
internationalisation layer, and the list of languages it ships is written down
**twice**:

* ``crates/axiam-oauth2/src/locale.rs`` -- ``ALL_LOCALES``, the authoritative
  allow-list. ``/oauth2/authorize`` matches a relying party's ``ui_locales``
  against it and forwards the *selected* tag, so this is the list that decides
  what a browser can ever be asked to render.
* ``frontend/src/i18n/messages.ts`` -- the ``MESSAGES`` catalogue, and
  ``frontend/src/i18n/locales.ts`` -- the ``LOCALES`` array the page indexes it
  with.

Two mirrors of one list drift, and both directions of drift are bad in a way
nobody notices for a while:

1. **A locale the server can select and the SPA cannot render.** ``ui_locales=pt``
   succeeds, the redirect carries ``ui_locale=pt``, and the page delivers
   English. That is strictly worse than answering "no match" and delivering
   English, because the relying party was told its request was honoured.
2. **A locale the SPA translates and the server will never select.** Dead
   weight, and a translator's work nobody can reach.

TypeScript already covers part of this: ``MESSAGES`` is declared
``Record<Locale, Bundle>``, so a tag in ``LOCALES`` without a bundle does not
compile. What it cannot see is Rust. That is this gate's job.

What is checked
---------------
1. ``ALL_LOCALES`` (Rust), ``LOCALES`` (TypeScript) and the keys of ``MESSAGES``
   are the same set -- and in the same order, because both files present the
   list to a human reader and two orders invite the reader to believe there are
   two lists.
2. Every tag the Rust enum can emit has an ``as_tag`` arm, so the enum's
   variants and its wire spellings cannot come apart.
3. Every bundle in ``MESSAGES`` has exactly the keys the English bundle has.
   TypeScript enforces this too; it is repeated here because this gate runs
   without a Node toolchain and is therefore the check that still fires when
   the frontend build is skipped.

Parsed with regular expressions rather than by importing anything: the gate has
no third-party dependency, needs neither ``cargo`` nor ``node``, and therefore
runs in the Architecture Invariants job beside ``check-crate-layering.py`` and
``check-audit-ignore-sync.py`` on every commit. The cost is that it reads a
*shape* rather than a value -- so the self-test below runs against fixtures,
including malformed ones, rather than only against a workspace that happens to
be clean today.

Exit codes: 0 in sync, 1 drifted, 2 could not run (deliberately not 0).

Usage::

    scripts/check-locale-bundle-sync.py             # verify (CI)
    scripts/check-locale-bundle-sync.py --self-test # fixtures
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCALE_RS = REPO_ROOT / "crates" / "axiam-oauth2" / "src" / "locale.rs"
LOCALES_TS = REPO_ROOT / "frontend" / "src" / "i18n" / "locales.ts"
MESSAGES_TS = REPO_ROOT / "frontend" / "src" / "i18n" / "messages.ts"


class GateError(Exception):
    """The gate could not read what it needs. Exit 2, never 0."""


# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------

# `pub const ALL_LOCALES: [Locale; 5] = [ Locale::English, ... ];`
_ALL_LOCALES = re.compile(
    r"pub const ALL_LOCALES\s*:\s*\[\s*Locale\s*;\s*\d+\s*\]\s*=\s*\[(?P<body>[^\]]*)\]",
    re.S,
)
_VARIANT = re.compile(r"Locale::(\w+)")

# The `as_tag` match arms: `Self::English => "en",`
_AS_TAG_FN = re.compile(
    r"pub const fn as_tag\(self\)\s*->\s*&'static str\s*\{(?P<body>.*?)\n    \}",
    re.S,
)
_AS_TAG_ARM = re.compile(r"Self::(\w+)\s*=>\s*\"([^\"]*)\"")


def rust_locales(source: str) -> list[str]:
    """The tags ``ALL_LOCALES`` names, in order, resolved through ``as_tag``."""
    all_match = _ALL_LOCALES.search(source)
    if not all_match:
        raise GateError(
            "could not find `pub const ALL_LOCALES: [Locale; N] = [...]` in locale.rs"
        )
    variants = _VARIANT.findall(all_match.group("body"))
    if not variants:
        raise GateError("ALL_LOCALES names no `Locale::` variants")

    fn_match = _AS_TAG_FN.search(source)
    if not fn_match:
        raise GateError("could not find `Locale::as_tag` in locale.rs")
    tags = dict(_AS_TAG_ARM.findall(fn_match.group("body")))

    missing = [v for v in variants if v not in tags]
    if missing:
        raise GateError(
            "these ALL_LOCALES variants have no `as_tag` arm: " + ", ".join(missing)
        )
    return [tags[v] for v in variants]


# ---------------------------------------------------------------------------
# TypeScript
# ---------------------------------------------------------------------------

# `export const LOCALES = ["en", "it", ...] as const;`
_LOCALES_ARRAY = re.compile(
    r"export const LOCALES\s*=\s*\[(?P<body>[^\]]*)\]\s*as const", re.S
)
_QUOTED = re.compile(r"\"([^\"]*)\"")

# `export const MESSAGES: Record<Locale, Bundle> = { en, it, fr, de, es };`
_MESSAGES_MAP = re.compile(
    r"export const MESSAGES\s*:\s*Record<\s*Locale\s*,\s*Bundle\s*>\s*=\s*\{(?P<body>[^}]*)\}",
    re.S,
)


def ts_locales(source: str) -> list[str]:
    """The tags ``LOCALES`` lists, in order."""
    match = _LOCALES_ARRAY.search(source)
    if not match:
        raise GateError(
            "could not find `export const LOCALES = [...] as const` in locales.ts"
        )
    tags = _QUOTED.findall(match.group("body"))
    if not tags:
        raise GateError("LOCALES is empty")
    return tags


def ts_bundles(source: str) -> list[str]:
    """The bundle names ``MESSAGES`` maps, in order."""
    match = _MESSAGES_MAP.search(source)
    if not match:
        raise GateError(
            "could not find `export const MESSAGES: Record<Locale, Bundle> = { … }` "
            "in messages.ts"
        )
    names = [
        part.split(":", 1)[0].strip()
        for part in match.group("body").split(",")
        if part.strip()
    ]
    if not names:
        raise GateError("MESSAGES maps no bundles")
    return names


# `const it: Bundle = { key: "…", … };` -- one bundle's declared keys.
def bundle_keys(source: str, name: str) -> list[str]:
    """The message keys one bundle declares, in declaration order."""
    if name == "en":
        opener = re.search(r"\nconst en = \{", source)
    else:
        opener = re.search(rf"\nconst {re.escape(name)}\s*:\s*Bundle\s*=\s*\{{", source)
    if not opener:
        raise GateError(f"could not find the `{name}` bundle in messages.ts")

    # Brace-match from the opening `{` so a `{provider}` placeholder inside a
    # string cannot end the object early.
    start = source.index("{", opener.start())
    depth = 0
    in_string = False
    end = None
    i = start
    while i < len(source):
        ch = source[i]
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
        i += 1
    if end is None:
        raise GateError(f"the `{name}` bundle in messages.ts is not brace-balanced")

    body = source[start + 1 : end]
    # Keys are at the start of a line, two spaces in, followed by a colon.
    return re.findall(r"^  (\w+)\s*:", body, re.M)


# ---------------------------------------------------------------------------
# The check itself
# ---------------------------------------------------------------------------


def check(locale_rs: str, locales_ts: str, messages_ts: str) -> list[str]:
    """Every way the three files can disagree. Empty means in sync."""
    findings: list[str] = []

    rust = rust_locales(locale_rs)
    spa = ts_locales(locales_ts)
    bundles = ts_bundles(messages_ts)

    if rust != spa:
        findings.append(
            f"the locale lists differ:\n"
            f"      axiam_oauth2::locale::ALL_LOCALES = {rust}\n"
            f"      frontend LOCALES                  = {spa}\n"
            f"    A locale the server can select and the SPA cannot render "
            f"delivers English while telling the relying party it was honoured; "
            f"a locale only the SPA has is a translation nobody can reach."
        )

    if bundles != spa:
        findings.append(
            f"MESSAGES does not map the same locales LOCALES lists:\n"
            f"      LOCALES  = {spa}\n"
            f"      MESSAGES = {bundles}"
        )

    # Key completeness, per bundle, against English.
    if "en" in bundles:
        english = bundle_keys(messages_ts, "en")
        if not english:
            findings.append("the `en` bundle declares no message keys")
        for name in bundles:
            if name == "en":
                continue
            keys = bundle_keys(messages_ts, name)
            missing = [k for k in english if k not in keys]
            extra = [k for k in keys if k not in english]
            if missing:
                findings.append(f"the `{name}` bundle is missing: {', '.join(missing)}")
            if extra:
                findings.append(
                    f"the `{name}` bundle has keys `en` does not: {', '.join(extra)}"
                )
    else:
        findings.append("MESSAGES has no `en` bundle to check the others against")

    return findings


# ---------------------------------------------------------------------------
# Self-test -- fixtures rather than the live tree, so the gate's own failure
# modes are exercised even on a day when the tree is clean.
# ---------------------------------------------------------------------------

_RS_OK = """
pub const ALL_LOCALES: [Locale; 3] = [
    Locale::English,
    Locale::Italian,
    Locale::French,
];

impl Locale {
    pub const fn as_tag(self) -> &'static str {
        match self {
            Self::English => "en",
            Self::Italian => "it",
            Self::French => "fr",
        }
    }
}
"""

_TS_OK = 'export const LOCALES = ["en", "it", "fr"] as const;\n'

_MSG_OK = '''
const en = {
  hello: "Hello",
  bye: "Goodbye {name}",
} as const;

const it: Bundle = {
  hello: "Ciao",
  bye: "Arrivederci {name}",
};

const fr: Bundle = {
  hello: "Bonjour",
  bye: "Au revoir {name}",
};

export const MESSAGES: Record<Locale, Bundle> = { en, it, fr };
'''


def self_test() -> int:
    cases: list[tuple[str, str, str, str, int]] = [
        ("in sync", _RS_OK, _TS_OK, _MSG_OK, 0),
        (
            "a locale only the server has",
            _RS_OK.replace(
                "    Locale::French,\n]",
                "    Locale::French,\n    Locale::German,\n]",
            ).replace(
                '            Self::French => "fr",',
                '            Self::French => "fr",\n            Self::German => "de",',
            ),
            _TS_OK,
            _MSG_OK,
            1,
        ),
        (
            "a locale only the SPA has",
            _RS_OK,
            'export const LOCALES = ["en", "it", "fr", "de"] as const;\n',
            _MSG_OK,
            1,
        ),
        (
            "the same locales in a different order",
            _RS_OK,
            'export const LOCALES = ["en", "fr", "it"] as const;\n',
            _MSG_OK,
            1,
        ),
        (
            "a bundle missing a key",
            _RS_OK,
            _TS_OK,
            _MSG_OK.replace('  bye: "Arrivederci {name}",\n', ""),
            1,
        ),
        (
            "a bundle with an extra key",
            _RS_OK,
            _TS_OK,
            _MSG_OK.replace(
                '  bye: "Au revoir {name}",',
                '  bye: "Au revoir {name}",\n  extra: "?",',
            ),
            1,
        ),
        (
            "MESSAGES missing a bundle the list names",
            _RS_OK,
            _TS_OK,
            _MSG_OK.replace(
                "Record<Locale, Bundle> = { en, it, fr }",
                "Record<Locale, Bundle> = { en, it }",
            ),
            1,
        ),
    ]

    failures = 0
    for name, rs, ts, msg, expected in cases:
        try:
            findings = check(rs, ts, msg)
            actual = 1 if findings else 0
        except GateError as exc:
            print(f"  FAIL {name}: gate could not run: {exc}")
            failures += 1
            continue
        if actual != expected:
            print(f"  FAIL {name}: expected exit {expected}, got {actual}")
            for f in findings:
                print(f"       {f}")
            failures += 1
        else:
            print(f"  ok   {name}")

    # The unreadable cases must be exit 2, not a silent pass.
    for name, rs, ts, msg in [
        ("locale.rs without ALL_LOCALES", "// nothing here\n", _TS_OK, _MSG_OK),
        ("locales.ts without LOCALES", _RS_OK, "// nothing here\n", _MSG_OK),
        ("messages.ts without MESSAGES", _RS_OK, _TS_OK, "// nothing here\n"),
        (
            "a variant with no as_tag arm",
            _RS_OK.replace('            Self::French => "fr",\n', ""),
            _TS_OK,
            _MSG_OK,
        ),
    ]:
        try:
            check(rs, ts, msg)
        except GateError:
            print(f"  ok   {name} (unreadable, exit 2)")
        else:
            print(f"  FAIL {name}: should have been unreadable")
            failures += 1

    # A placeholder in a string must not end the object early.
    keys = bundle_keys(_MSG_OK, "it")
    if keys != ["hello", "bye"]:
        print(f"  FAIL brace matching stopped at a placeholder: {keys}")
        failures += 1
    else:
        print("  ok   a {placeholder} inside a string does not end the bundle")

    if failures:
        print(f"\nself-test FAILED: {failures} case(s)", file=sys.stderr)
        return 1
    print(f"\nself-test OK: {len(cases) + 5} case(s)")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()

    try:
        locale_rs = LOCALE_RS.read_text(encoding="utf-8")
        locales_ts = LOCALES_TS.read_text(encoding="utf-8")
        messages_ts = MESSAGES_TS.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"locale sync gate could not run: {exc}", file=sys.stderr)
        return 2

    try:
        findings = check(locale_rs, locales_ts, messages_ts)
    except GateError as exc:
        print(f"locale sync gate could not run: {exc}", file=sys.stderr)
        return 2

    if findings:
        print("Locale bundle sync check FAILED:\n", file=sys.stderr)
        for f in findings:
            print(f"  - {f}\n", file=sys.stderr)
        print(
            "The server's allow-list is `crates/axiam-oauth2/src/locale.rs`; the "
            "SPA's bundles are `frontend/src/i18n/`. A language belongs in both "
            "or in neither -- a stub bundle that falls through to English is "
            "worse than not offering the language at all.",
            file=sys.stderr,
        )
        return 1

    tags = rust_locales(locale_rs)
    keys = bundle_keys(messages_ts, "en")
    print(
        f"Locale bundle sync OK: {len(tags)} locale(s) ({', '.join(tags)}), "
        f"{len(keys)} message key(s), server and SPA agree."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
