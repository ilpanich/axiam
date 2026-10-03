#!/usr/bin/env python3
"""Export the screenshots the suite holds for REVIEW modules (T23.1.6).

A `REVIEW` module is closed by a human reading its log and the image the run
uploaded. The 2026-09-15, -18 and -25 evidence directories were each produced by
hand from the suite's own API, and `docs/conformance/evidence/<date>/README.md`
describes the recipe in five lines. This is that recipe as a script, so the
maintainer's final run produces evidence the same way the baseline did and the
manifest has the same shape.

For every module in `conformance/.run/results/*.results.json` whose verdict is
REVIEW (or every module, with `--all`) it calls

    GET <SUITE_BASE_URL>/api/log/<testId>/images

takes the entries whose `img` field is set (a filled screenshot slot; `upload`
is set only while the slot is still EMPTY — runbook, "Reading the evidence"),
decodes the `data:` URI and writes

    <out>/<plan>__<module without its plan prefix>__<md5[:10]>.jpg
    <out>/manifest.json

Nothing is sent to the suite and nothing to anybody else: it only reads.

It refuses to write into a directory that already holds a `manifest.json`.
Evidence is added alongside earlier evidence, never over it
(docs/conformance/README.md), and a re-run into the same directory is how an
earlier capture gets quietly replaced.

The script does NOT judge the images. Open every distinct one and compare it
with the module's condition (`manifest.json` carries the condition text) before
writing anything down about it — that is the whole point of REVIEW.

Stdlib only. The suite serves upstream's self-signed certificate, so TLS
verification is off for this one conversation with the suite, exactly as the
`curl -k` of run-plan.sh is; AXIAM is not contacted.

Usage:
    SUITE_BASE_URL=https://localhost.emobix.co.uk:8442 \\
      conformance/scripts/export-evidence.py --out docs/conformance/evidence/<date>
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import ssl
import sys
import urllib.request

# Longest-first so that `fapi2-security-profile-final-` wins over a shorter
# prefix if one is ever added. The existing file names were produced with these
# two stripped: `oidcc-prompt-login` -> `prompt-login`.
PLAN_PREFIXES = ("fapi2-security-profile-final-", "oidcc-")


def short_module(module: str) -> str:
    for prefix in PLAN_PREFIXES:
        if module.startswith(prefix):
            return module[len(prefix):]
    return module


def get_json(base: str, path: str):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(f"{base}{path}", context=ctx, timeout=30) as resp:
        return json.load(resp)


def decode_image(data_uri: str) -> bytes | None:
    """`data:image/jpeg;base64,<payload>` -> bytes, or None if it is not one."""
    if not isinstance(data_uri, str) or "," not in data_uri:
        return None
    header, payload = data_uri.split(",", 1)
    if not header.startswith("data:") or ";base64" not in header:
        return None
    try:
        return base64.b64decode(payload, validate=False)
    except (ValueError, TypeError):
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", default="conformance/.run/results",
                    help="directory holding *.results.json from run-plan.sh")
    ap.add_argument("--out", required=True,
                    help="evidence directory, e.g. docs/conformance/evidence/2026-10-20")
    ap.add_argument("--suite", default=os.environ.get("SUITE_BASE_URL", ""),
                    help="suite base URL (default: $SUITE_BASE_URL)")
    ap.add_argument("--all", action="store_true",
                    help="every module, not only those whose verdict is REVIEW")
    args = ap.parse_args()

    if not args.suite:
        print("[evidence] SUITE_BASE_URL is not set — source conformance/suite.env", file=sys.stderr)
        return 1
    base = args.suite.rstrip("/")

    results_dir = pathlib.Path(args.results)
    files = sorted(results_dir.glob("*.results.json")) if results_dir.is_dir() else []
    if not files:
        print(f"[evidence] no *.results.json under {results_dir}", file=sys.stderr)
        return 1

    out = pathlib.Path(args.out)
    if (out / "manifest.json").exists():
        print(f"[evidence] {out}/manifest.json already exists. Evidence is added "
              "alongside earlier evidence, never over it — pick a new directory.",
              file=sys.stderr)
        return 1
    out.mkdir(parents=True, exist_ok=True)

    manifest = []
    problems = 0
    for path in files:
        run = json.loads(path.read_text())
        plan = path.name.replace(".results.json", "")
        for m in run.get("modules", []):
            verdict = (m.get("result") or m.get("status") or "").upper()
            if not args.all and verdict != "REVIEW":
                continue
            test_id = m.get("testId")
            if not test_id:
                continue
            try:
                entries = get_json(base, f"/api/log/{test_id}/images")
            except Exception as e:  # noqa: BLE001 - report and carry on to the next module
                print(f"[evidence] {plan} {m['module']} ({test_id}): {e}", file=sys.stderr)
                problems += 1
                continue
            filled = [e for e in entries if isinstance(e, dict) and e.get("img")]
            if not filled:
                # A REVIEW with no image is a module whose evidence was never
                # uploaded — the finding, not something to paper over.
                print(f"[evidence] {plan} {m['module']} ({test_id}): NO IMAGE UPLOADED",
                      file=sys.stderr)
                problems += 1
                continue
            for entry in filled:
                blob = decode_image(entry["img"])
                if not blob:
                    print(f"[evidence] {plan} {m['module']} ({test_id}): "
                          "an `img` entry that is not a base64 data URI", file=sys.stderr)
                    problems += 1
                    continue
                md5 = hashlib.md5(blob).hexdigest()  # noqa: S324 - an identifier, as in earlier manifests
                name = f"{plan}__{short_module(m['module'])}__{md5[:10]}.jpg"
                (out / name).write_bytes(blob)
                manifest.append({
                    "plan": plan,
                    "module": m["module"],
                    "testId": test_id,
                    "condition": entry.get("msg", ""),
                    "image": name,
                    "md5": md5,
                    "bytes": len(blob),
                    "images_uploaded": len(filled),
                })
                print(f"[evidence] {name}")

    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    distinct = len({e["md5"] for e in manifest})
    print(f"[evidence] {len(manifest)} image(s), {distinct} distinct, manifest at {out}/manifest.json")
    if problems:
        print(f"[evidence] {problems} module(s) produced no usable image — see above",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
