#!/usr/bin/env python3
"""A6 -- assert every deployment artifact talks to the broker over TLS.

Why this exists: the server refuses any broker URL that is not ``amqps://``,
in every build profile. Broker traffic carries authorization requests, audit
events and mail payloads across service boundaries, and HMAC signing protects
their authenticity but not their confidentiality.

It also has an unfriendly failure mode. A stack that violates the rule does not
fail a test; it fails to *boot*, and only once something actually starts the
container. That is exactly how it went wrong once already: the dev, e2e and
benchmark stacks were all assumed to be exempt debug builds, all three actually
run the published release image, and nobody found out until the E2E job's
server panicked at startup and took 108 unrelated Playwright tests down with it
as collateral.

This check moves that discovery to PR time. For every service that sets
``AXIAM__AMQP__URL``, the URL must be ``amqps://``.

**This check used to be weaker, and the history is the point.** It previously
accepted plaintext ``amqp://`` as long as the service also set
``AXIAM__AMQP__ALLOW_PLAINTEXT``, on the reasoning that a stack should merely
have to *state* its posture rather than justify it -- plaintext on an ephemeral
CI broker carrying synthetic fixtures being a reasonable trade, and the
benchmark harness having a real interest in not measuring TLS it did not ask
for. Every one of those arguments was locally sound. Collectively they meant
four of this project's five stacks ran plaintext, and "AMQP is TLS-only"
described the production compose file and nothing else. The flag is gone from
the server, so it is gone from here.

Exit 0 = every service uses amqps://. Exit 1 = at least one does not, named.
"""

import os
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - environment problem, not a finding
    sys.exit(
        "PyYAML is required by this check but is not installed.\n"
        "Install it with: python3 -m pip install pyyaml"
    )

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)


class ComposeLoader(yaml.SafeLoader):
    """SafeLoader that tolerates Compose's own YAML tags.

    Compose merge files use ``!override`` and ``!reset``, which plain
    ``safe_load`` rejects outright. Without this the check would report a
    perfectly valid compose file as unparseable -- a false finding, and the
    fastest way to teach people to ignore a check.
    """


def _passthrough(loader, _suffix, node):
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_scalar(node)


ComposeLoader.add_multi_constructor("", _passthrough)

# Directories holding deployment artifacts. k8s manifests are included because
# they carry the same env vars and the same guard applies to them.
SEARCH_DIRS = ("docker", "benchmarks", "k8s")

URL_KEY = "AXIAM__AMQP__URL"
# The retired plaintext escape hatch. Still named here so that a stack which
# copies an old snippet gets told the flag is gone, rather than silently
# carrying a variable the server no longer reads.
RETIRED_ALLOW_KEY = "AXIAM__AMQP__ALLOW_PLAINTEXT"


def yaml_files():
    for base in SEARCH_DIRS:
        root = os.path.join(REPO_ROOT, base)
        if not os.path.isdir(root):
            continue
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in sorted(filenames):
                if name.endswith((".yml", ".yaml")):
                    yield os.path.join(dirpath, name)


def env_mappings(node):
    """Yield every env-like mapping in a parsed YAML document.

    Handles both shapes the repo uses: compose's ``environment:`` mapping, and
    k8s's ``env:`` list of ``{name, value}`` pairs. Walks the whole tree rather
    than assuming a schema, so a manifest kind nobody anticipated still gets
    checked instead of silently skipped.
    """
    if isinstance(node, dict):
        env = node.get("environment")
        if isinstance(env, dict):
            yield {str(k): v for k, v in env.items()}
        elif isinstance(env, list):
            # compose also accepts a ["KEY=value", ...] list form
            pairs = {}
            for item in env:
                if isinstance(item, str) and "=" in item:
                    k, _, v = item.partition("=")
                    pairs[k.strip()] = v.strip()
            if pairs:
                yield pairs

        k8s_env = node.get("env")
        if isinstance(k8s_env, list):
            pairs = {}
            for item in k8s_env:
                if isinstance(item, dict) and "name" in item:
                    pairs[str(item["name"])] = item.get("value", "")
            if pairs:
                yield pairs

        for value in node.values():
            yield from env_mappings(value)
    elif isinstance(node, list):
        for item in node:
            yield from env_mappings(item)


def main():
    findings = []
    checked = 0

    for path in yaml_files():
        rel = os.path.relpath(path, REPO_ROOT)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                docs = list(yaml.load_all(fh, Loader=ComposeLoader))
        except (yaml.YAMLError, UnicodeDecodeError) as exc:
            findings.append(f"{rel}: could not parse as YAML ({exc.__class__.__name__})")
            continue

        for doc in docs:
            for env in env_mappings(doc):
                # The retired flag is worth reporting wherever it appears, even
                # on a service that has already moved to amqps:// — a leftover
                # here is a stale copy of an old snippet, and the next thing
                # copied from it will be the amqp:// URL that went with it.
                if RETIRED_ALLOW_KEY in env:
                    findings.append(
                        f"{rel}: {RETIRED_ALLOW_KEY} is set, but that flag no longer "
                        f"exists — AMQP is TLS-only in every build profile. Remove the "
                        f"variable; the server does not read it."
                    )

                if URL_KEY not in env:
                    continue
                checked += 1
                url = str(env[URL_KEY]).strip().strip("\"'").lower()

                if url.startswith("amqps://"):
                    continue
                if url.startswith("amqp://"):
                    findings.append(
                        f"{rel}: {URL_KEY} is plaintext amqp://. AMQP is TLS-only and "
                        f"there is no flag that changes that — the server refuses this "
                        f"before opening a socket, in a debug build as in a release "
                        f"one. Move to amqps:// on port 5671 and give the broker a "
                        f"certificate (scripts/gen-broker-tls.sh mints one)."
                    )
                else:
                    findings.append(
                        f"{rel}: {URL_KEY} is {env[URL_KEY]!r}, which is not amqps://. "
                        f"The server rejects every other scheme before opening a socket."
                    )

    if findings:
        print("AMQP transport posture check FAILED:\n", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        print(
            f"\n{len(findings)} problem(s) across {checked} service(s) setting {URL_KEY}.",
            file=sys.stderr,
        )
        return 1

    print(f"AMQP transport posture OK: {checked} service(s) setting {URL_KEY}, all amqps://.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
