#!/usr/bin/env bash
# Docker Engine (>= 25), Compose (>= 2.24) and the pinned k6. Idempotent.
#
# Runbook: claude_dev/bench-vm-runbook.md §3-§4. Docker comes from Docker's own
# repository (Ubuntu's docker.io lags); Engine >= 25 because the authentik
# healthcheck uses start_interval, Compose >= 2.24 because the minimal overlay
# uses !reset/!override (run6-runbook.md §1.2).
#
# Usage:  ./01-docker-k6.sh           Then: log out and in (docker group), ./02-sdk-toolchains.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"
# shellcheck source=versions.env
source "$HERE/versions.env"

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
    say "Installing Docker Engine and the Compose plugin"
    $SUDO install -m 0755 -d /etc/apt/keyrings
    fetch_to https://download.docker.com/linux/ubuntu/gpg /etc/apt/keyrings/docker.asc 0644
    # shellcheck disable=SC1091
    codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $codename stable" \
        | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null
    $SUDO apt-get update -q
    apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

# Bounded container logs, so a 20-hour run cannot fill the disk. Rotation does
# not change what is measured. An existing, different daemon.json is someone
# else's decision: report it rather than overwrite it.
DAEMON_JSON='{ "log-driver": "json-file", "log-opts": { "max-size": "50m", "max-file": "3" } }'
if [[ ! -f /etc/docker/daemon.json ]]; then
    echo "$DAEMON_JSON" | $SUDO tee /etc/docker/daemon.json >/dev/null
    $SUDO systemctl restart docker
    ok "container log rotation configured (50 MiB x 3)"
elif jq -e '."log-opts"."max-size"' /etc/docker/daemon.json >/dev/null 2>&1; then
    ok "container log rotation already configured"
else
    warn "/etc/docker/daemon.json exists without log rotation; left as it is. Wanted: $DAEMON_JSON"
fi

$SUDO systemctl enable --now docker >/dev/null 2>&1

dv="$($SUDO docker version --format '{{.Server.Version}}')"
cv="$($SUDO docker compose version --short)"
version_ge "$dv" 25 || die "Docker Engine $dv; >= 25 is required."
version_ge "${cv#v}" 2.24 || die "Docker Compose $cv; >= 2.24 is required."
ok "Docker Engine $dv, Compose $cv"

if [[ -n "$SUDO" ]] && ! id -nG "$USER" | tr ' ' '\n' | grep -qx docker; then
    $SUDO usermod -aG docker "$USER"
    warn "Added $USER to the docker group: log out and in before ./02-sdk-toolchains.sh (the harness runs docker without sudo)."
fi

# ---------------------------------------------------------------------------
# k6, pinned
# ---------------------------------------------------------------------------
if command -v k6 >/dev/null 2>&1 && k6 version 2>/dev/null | grep -q "v${K6_VERSION}\b"; then
    ok "k6 $K6_VERSION already installed"
else
    say "Installing k6 $K6_VERSION"
    tmp="$(mktemp -d)"
    curl --fail --location --silent --show-error --retry 3 \
        "https://github.com/grafana/k6/releases/download/v${K6_VERSION}/k6-v${K6_VERSION}-linux-amd64.tar.gz" \
        | tar -xz -C "$tmp"
    $SUDO install -m 0755 "$tmp/k6-v${K6_VERSION}-linux-amd64/k6" /usr/local/bin/k6
    rm -rf "$tmp"
    k6 version | grep -q "v${K6_VERSION}\b" || die "k6 did not install as $K6_VERSION: $(k6 version | head -1)"
    ok "k6 $K6_VERSION"
fi

ok "Standard-benchmark tooling installed. Next: log out and in, the registry logins (runbook §4), then ./02-sdk-toolchains.sh"
