#!/usr/bin/env bash
# pull-pinned-images.sh — pull every image a benchmark run uses, record the digest
# each one resolved to, and write a file that pins the run to those digests.
#
# T23.10.2(a). Run 5 pinned two images by hand (the AXIAM server and SurrealDB) and
# left the rest on floating tags; run 6 has eight (AXIAM, SurrealDB, RabbitMQ,
# Keycloak, Zitadel, authentik and the two PostgreSQL stacks share one), and the
# provenance of a published number is only as good as its weakest tag. The image
# references are NOT repeated here: each is read from the `${BENCH_*_IMAGE:-default}`
# line of the compose file that owns it, so a pin bumped in a compose file is
# the pin this script pulls. Anything already exported (BENCH_KEYCLOAK_IMAGE=
# keycloak/keycloak:26.8.0 on a host that cannot reach quay.io, say) wins, and is
# what gets pulled and recorded.
#
# A failed pull is a hard error, on purpose: `bench-up` falls back to a LOCAL SOURCE
# BUILD when the AXIAM image cannot be pulled, which in a long matrix scrolls past and
# silently stops measuring the release (run-5 runbook §1.0). Pulling here makes the
# failure loud, before any k6 time is spent.
#
# Writes, under OUT (default results/provenance/):
#   pinned-images.sh   `export BENCH_<X>_IMAGE=<repo>@sha256:…` per image — SOURCE IT
#   images.txt         a human-readable table (variable, reference, digest)
# Both are small and carry no credential; `bench-pack` includes images.txt.
#
# Usage: pull-pinned-images.sh [out-dir]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH="$(cd "$HERE/.." && pwd)"
OUT="${1:-$BENCH/results/provenance}"
mkdir -p "$OUT"

# variable -> default reference, read from the compose files
declare -A DEFAULT
while IFS='|' read -r var ref; do
  [ -n "$var" ] && DEFAULT["$var"]="$ref"
done < <(python3 -I - "$BENCH" <<'PY'
import glob, os, re, sys
bench = sys.argv[1]
seen = {}
for f in sorted(glob.glob(os.path.join(bench, "targets", "*", "docker-compose*.yml"))):
    for m in re.finditer(r"image:\s*\$\{(BENCH_[A-Z_]+_IMAGE):-([^}]+)\}", open(f).read()):
        seen.setdefault(m.group(1), m.group(2).strip())
for k, v in sorted(seen.items()):
    print(f"{k}|{v}")
PY
)
[ "${#DEFAULT[@]}" -ge 6 ] || { echo "[pull] found only ${#DEFAULT[@]} BENCH_*_IMAGE variables in the compose files (expected at least 6) — did the image: lines change shape?" >&2; exit 1; }

# the AXIAM image's default is the workspace version, exactly as `bench-up` derives it
VER="$(grep -m1 '^version' "$BENCH/../Cargo.toml" | cut -d'"' -f2)"
DEFAULT[BENCH_AXIAM_IMAGE]="ghcr.io/ilpanich/axiam/server:${VER}"

: > "$OUT/images.txt"
{ echo "# Source this file: it pins the run to the digests recorded in images.txt."; } > "$OUT/pinned-images.sh"
printf '%-26s %-52s %s\n' "variable" "reference pulled" "digest" >> "$OUT/images.txt"

for var in $(printf '%s\n' "${!DEFAULT[@]}" | sort); do
  ref="${!var:-${DEFAULT[$var]}}"
  # an already-pinned reference (name@sha256:…) is pulled as is
  echo "[pull] $var = $ref"
  if ! docker pull "$ref" >/dev/null; then
    echo "[pull] FAILED: cannot pull $ref ($var). Fix registry access (docker login ghcr.io for the AXIAM image; BENCH_KEYCLOAK_IMAGE=keycloak/keycloak:<tag> for quay.io) before running anything." >&2
    exit 1
  fi
  # the repository part: strip a digest, then a tag (a colon after the last slash)
  repo="${ref%%@*}"
  case "${repo##*/}" in *:*) repo="${repo%:*}" ;; esac
  repo="$(printf '%s' "$repo" | sed 's#^docker\.io/library/##; s#^docker\.io/##')"
  digest="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$ref" \
              | sed 's#^docker\.io/library/##; s#^docker\.io/##' \
              | grep -F "$repo@" | head -1 || true)"
  if [ -z "$digest" ]; then
    # a mirror pulled under a different name still has exactly one RepoDigest
    digest="$(docker image inspect --format '{{index .RepoDigests 0}}' "$ref" 2>/dev/null || true)"
  fi
  [ -n "$digest" ] && [ "$digest" != "<no value>" ] || { echo "[pull] $ref has no RepoDigest (a locally built image?) — a run must measure a pulled image" >&2; exit 1; }
  printf '%-26s %-52s %s\n' "$var" "$ref" "${digest#*@}" >> "$OUT/images.txt"
  printf 'export %s=%s\n' "$var" "$digest" >> "$OUT/pinned-images.sh"
done
cat "$OUT/images.txt"
echo
echo "[pull] source ${OUT#"$BENCH"/}/pinned-images.sh in the shell that runs the matrix. Docker/compose: $(docker version --format '{{.Server.Version}}' 2>/dev/null), $(docker compose version --short 2>/dev/null)." >&2
