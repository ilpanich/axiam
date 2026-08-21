#!/usr/bin/env python3
"""Verify every outbound SDK link advertised by the public website.

Two properties are checked per URL, and the second is the one that matters:

1. It resolves — no DNS failure, no 4xx/5xx.
2. It does not leave the domain it claims to be on.

Property 2 exists because of a real incident. The C# SDK's documentation link
pointed at ``fuget.org``; that domain lapsed, was re-registered by someone
else, and began serving an unrelated commercial site. It returned HTTP 200
throughout. Any check that looks only at status codes reports that as healthy,
which is how a link on an identity product's website ended up delivering
visitors to a stranger for months.

Domains are compared at the registrable-domain level, so ``npmjs.com`` ->
``www.npmjs.com`` is fine while ``fuget.org`` -> ``roseburgroofingandgutters.com``
is not.

Usage:
    python3 scripts/check-website-links.py [--data website/src/data.ts]

Exits non-zero if any link fails. Standard library only — this has to run in a
bare CI container without an install step.
"""

from __future__ import annotations

import argparse
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import urlsplit

# Fields in data.ts that hold an outbound URL.
URL_FIELDS = (
    "docsUrl",
    "registryUrl",
    "repoUrl",
    "examplesUrl",
    "coverageUrl",
)

TIMEOUT_SECS = 30
ATTEMPTS = 3

# Hosts that deliberately refuse automated clients, so their status code says
# nothing about whether the link works in a browser. Verified by hand while
# writing this: crates.io answers 403 to curl and 404 to a browser user-agent
# for a crate that demonstrably exists (its own JSON API lists every version),
# and coveralls.io answers 403 to everything without a session.
#
# npmjs.com was added after this check first ran: the package page answers 403
# to a browser user-agent for `axiam-sdk`, for `react`, and for a package name
# that does not exist at all. A status that is identical for a hugely popular
# package and for a nonexistent one is carrying no information about the link.
# The registry API is the authority and it lists axiam-sdk with 19 published
# versions, so the page is fine and only the scraping is blocked.
#
# For these, a non-success status is reported as UNVERIFIED rather than failed.
# The check that still applies to them — and the one this script exists for —
# is the off-domain redirect check, which does not depend on the status code.
#
# This list is deliberately small and explicit. Adding a host to it is choosing
# to stop status-checking that host, so it should happen only after confirming
# by hand that the block is the host's policy rather than a broken link.
BOT_HOSTILE_DOMAINS = frozenset({
    "crates.io",
    "coveralls.io",
    "npmjs.com",
})

# Some hosts refuse an unadorned urllib request outright. Presenting a normal
# browser UA is about getting a representative answer, not evading anything —
# a 403 caused by the client string would be indistinguishable from a link that
# genuinely broke.
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 axiam-link-check"
)


def registrable_domain(host: str) -> str:
    """Last two labels of a hostname.

    Deliberately naive rather than pulling in a Public Suffix List dependency:
    the failure mode of the naive version on a multi-part suffix (``foo.co.uk``
    -> ``co.uk``) is that two *different* sites under the same suffix would
    compare equal, which loosens the check. It never tightens it into a false
    alarm, and none of the hosts here use such a suffix.
    """
    labels = host.lower().strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


@dataclass
class Result:
    url: str
    field: str
    sdk: str
    status: int | None
    final_url: str | None
    error: str | None = None

    @property
    def off_domain(self) -> bool:
        if not self.final_url:
            return False
        a = registrable_domain(urlsplit(self.url).hostname or "")
        b = registrable_domain(urlsplit(self.final_url).hostname or "")
        return a != b

    @property
    def bot_hostile(self) -> bool:
        return registrable_domain(urlsplit(self.url).hostname or "") in BOT_HOSTILE_DOMAINS

    @property
    def unverified(self) -> bool:
        """Reachable, on-domain, but the host refuses to tell us more."""
        return (
            self.bot_hostile
            and self.error is None
            and self.status is not None
            and not self.off_domain
        )

    @property
    def ok(self) -> bool:
        if self.off_domain:
            return False
        if self.unverified:
            return True
        if self.error or self.status is None:
            return False
        return 200 <= self.status < 400


def extract_links(path: str) -> list[tuple[str, str, str]]:
    """Return (sdk_id, field, url) for every outbound URL in data.ts."""
    source = open(path, encoding="utf-8").read()
    out: list[tuple[str, str, str]] = []
    # Entries are object literals; splitting on the `id:` key keeps each URL
    # attributed to the SDK it belongs to, so a failure names the right one.
    for chunk in re.split(r"\n  \{\n", source):
        id_match = re.search(r'id:\s*"([^"]+)"', chunk)
        if not id_match:
            continue
        sdk = id_match.group(1)
        for field in URL_FIELDS:
            m = re.search(field + r':\s*"(https?://[^"]+)"', chunk)
            if m:
                out.append((sdk, field, m.group(1)))
    return out


def check(sdk: str, field: str, url: str) -> Result:
    last_error: str | None = None
    for attempt in range(ATTEMPTS):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECS) as resp:
                return Result(url, field, sdk, resp.status, resp.geturl())
        except urllib.error.HTTPError as e:
            # Retry the statuses that describe the server's mood rather than
            # the link: rate limits and 5xx. A scheduled job that fails on a
            # one-off 502 trains everyone to ignore it, and an ignored link
            # checker is worse than none — it looks like coverage.
            transient = e.code == 429 or 500 <= e.code < 600
            if transient and attempt < ATTEMPTS - 1:
                last_error = f"{e.code} transient"
                time.sleep(2 ** attempt)
                continue
            return Result(url, field, sdk, e.code, e.url or url)
        except Exception as e:  # noqa: BLE001 — network errors are all equal here
            last_error = f"{type(e).__name__}: {e}"
    return Result(url, field, sdk, None, None, last_error)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="website/src/data.ts")
    args = ap.parse_args()

    links = extract_links(args.data)
    if not links:
        print(f"✗ no URLs extracted from {args.data} — the parser has drifted "
              f"from the file format, which would silently check nothing")
        return 1

    print(f"Checking {len(links)} links from {args.data}\n")
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda t: check(*t), links))

    failures = [r for r in results if not r.ok]
    unverified = [r for r in results if r.unverified and not (200 <= (r.status or 0) < 400)]
    for r in sorted(results, key=lambda r: (r.sdk, r.field)):
        if r.unverified and not (200 <= (r.status or 0) < 400):
            mark = "----"
            detail = f"{r.status} — host refuses automated clients; on-domain, not status-checked"
        elif r.ok:
            mark = "ok  "
            detail = str(r.status)
        elif r.off_domain:
            mark = "FAIL"
            detail = f"{r.status} REDIRECTS OFF-DOMAIN -> {r.final_url}"
        elif r.error:
            mark = "FAIL"
            detail = r.error
        else:
            mark = "FAIL"
            detail = str(r.status)
        print(f"  [{mark}] {r.sdk:<12} {r.field:<14} {r.url}\n           {detail}")

    print()
    if failures:
        print(f"✗ {len(failures)} of {len(results)} links failed")
        for r in failures:
            if r.off_domain:
                print(f"    {r.sdk}.{r.field} leaves its domain: "
                      f"{urlsplit(r.url).hostname} -> {urlsplit(r.final_url or '').hostname}. "
                      f"Treat this as a hijacked or lapsed domain until proven otherwise.")
        return 1

    checked = len(results) - len(unverified)
    print(f"✓ {checked} links resolve and stay on-domain")
    if unverified:
        print(f"  ({len(unverified)} on bot-hostile hosts checked for off-domain "
              f"redirects only — see BOT_HOSTILE_DOMAINS)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
