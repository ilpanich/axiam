#!/usr/bin/env python3
"""Install a Go release from the Go module proxy, verified by the checksum database.

Used by 02-sdk-toolchains.sh when the release tarball on go.dev cannot be
downloaded. It is the channel the `go` command itself uses to fetch toolchains
(GOTOOLCHAIN): the module golang.org/toolchain@v0.0.1-go<version>.<os>-<arch>
on proxy.golang.org, whose `h1:` hash is published in sum.golang.org, a public
append-only log. The zip is accepted only if the hash recomputed from its
contents matches the log's.

    go-toolchain.py <version> <zip> <sumdb-lookup-file> <dest-dir>

<zip> and <sumdb-lookup-file> are fetched by the caller (curl, through the
same proxy settings as every other download); this script only verifies and
unpacks, and writes nothing unless the hash matches.
"""
import base64
import hashlib
import os
import stat
import sys
import zipfile


def module_version(version):
    return f"v0.0.1-go{version}.linux-amd64"


def h1(zf):
    """golang.org/x/mod/sumdb/dirhash.Hash1 over the zip's files."""
    lines = []
    for name in sorted(i.filename for i in zf.infolist() if not i.is_dir()):
        if "\n" in name:
            raise SystemExit(f"refusing a file name with a newline: {name!r}")
        lines.append(f"{hashlib.sha256(zf.read(name)).hexdigest()}  {name}\n")
    return "h1:" + base64.b64encode(hashlib.sha256("".join(lines).encode()).digest()).decode()


def expected_h1(lookup_text, mod, ver):
    for line in lookup_text.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == mod and parts[1] == ver:
            return parts[2]
    raise SystemExit(f"sum.golang.org has no hash for {mod}@{ver}")


def main():
    if len(sys.argv) != 5:
        raise SystemExit(__doc__)
    version, zip_path, lookup_path, dest = sys.argv[1:]
    mod, ver = "golang.org/toolchain", module_version(version)
    prefix = f"{mod}@{ver}/"

    with open(lookup_path, encoding="utf-8") as f:
        want = expected_h1(f.read(), mod, ver)
    with zipfile.ZipFile(zip_path) as zf:
        got = h1(zf)
        if got != want:
            raise SystemExit(f"checksum mismatch for {mod}@{ver}: zip {got}, sum.golang.org {want}")
        print(f"verified {mod}@{ver} {got} against sum.golang.org")

        if os.path.exists(dest):
            raise SystemExit(f"{dest} exists; the caller removes the old toolchain first")
        root = os.path.realpath(dest)
        for info in zf.infolist():
            if not info.filename.startswith(prefix):
                raise SystemExit(f"unexpected entry outside {prefix}: {info.filename}")
            rel = info.filename[len(prefix):]
            if not rel or info.is_dir():
                continue
            out = os.path.realpath(os.path.join(root, rel))
            if not out.startswith(root + os.sep):
                raise SystemExit(f"refusing a path that leaves {dest}: {info.filename}")
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with zf.open(info) as src, open(out, "wb") as dst:
                dst.write(src.read())

    # Module zips carry no permission bits; like cmd/go's own toolchain
    # download, make the binaries executable.
    for sub in ("bin", os.path.join("pkg", "tool", "linux_amd64")):
        d = os.path.join(root, sub)
        if os.path.isdir(d):
            for name in os.listdir(d):
                p = os.path.join(d, name)
                if os.path.isfile(p):
                    os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"installed Go {version} into {dest}")


if __name__ == "__main__":
    main()
