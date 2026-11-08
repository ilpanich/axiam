#!/usr/bin/env bash
# The eleven SDK toolchains, at the versions in versions.env. Idempotent: a
# toolchain already at its pinned version is left alone.
#
# Runbook: claude_dev/bench-vm-runbook.md §5, whose table says which SDK file
# each requirement comes from:
#
#   rust        Rust (RUST_VERSION) via rustup          REST feature only, no protoc
#   typescript  Node NODE_MAJOR.x via NodeSource        engines: node >= 22
#   python      Python 3.12 (Ubuntu) + venv             requires-python >= 3.11
#   java        OpenJDK 21 + Maven (Ubuntu)             maven.compiler.release 21
#   kotlin      the same JDK; Gradle via the wrapper
#   csharp      .NET SDK DOTNET_CHANNEL via dotnet-install.sh   net10.0
#   php         PHP 8.3 + sodium/sockets + Composer     php >= 8.2, ext-sodium
#   go          Go GO_VERSION from go.dev               go 1.26.0
#   swift       Swift SWIFT_VERSION via swiftly         swift-tools-version 6.2
#   c, cpp      CMake, gcc/g++, libcurl, OpenSSL        cmake >= 3.16, C11 / C++17
#
# Usage:  ./02-sdk-toolchains.sh      Then: exec bash -l, ./03-checkouts.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"
# shellcheck source=versions.env
source "$HERE/versions.env"
bench_path

$SUDO apt-get update -q

# ---------------------------------------------------------------------------
# Distribution packages: C/C++, Java, PHP, Python venv, Swift's runtime deps
# ---------------------------------------------------------------------------
say "Distribution packages (C/C++, JDK 21, Maven, PHP 8.3, Composer, Swift's dependencies)"
apt_install build-essential cmake pkg-config libcurl4-openssl-dev libssl-dev \
            openjdk-21-jdk-headless maven \
            php8.3-cli php8.3-curl php8.3-mbstring php8.3-xml composer \
            python3-venv libicu74 \
            binutils gnupg2 libc6-dev libedit2 libgcc-13-dev libncurses-dev libpython3-dev \
            libsqlite3-0 libstdc++-13-dev libxml2-dev libz3-dev tzdata zlib1g-dev
for ext in sodium sockets curl; do
    php -m | grep -qix "$ext" || die "PHP extension $ext is missing (php -m). The PHP SDK needs sodium; its bench loads sockets."
done
ok "distribution packages"

# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------
if ! command -v rustup >/dev/null 2>&1; then
    say "Installing rustup with Rust $RUST_VERSION"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain "$RUST_VERSION" --no-modify-path
    bench_path
elif ! rustc --version 2>/dev/null | grep -q "^rustc ${RUST_VERSION} "; then
    say "Switching Rust to $RUST_VERSION"
    rustup toolchain install "$RUST_VERSION" --profile minimal
    rustup default "$RUST_VERSION"
fi
ok "$(rustc --version)"

# ---------------------------------------------------------------------------
# Node (NodeSource repository, added by hand rather than through its setup
# script piped into a root shell)
# ---------------------------------------------------------------------------
if ! node --version 2>/dev/null | grep -q "^v${NODE_MAJOR}\."; then
    say "Installing Node $NODE_MAJOR.x"
    $SUDO install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        | $SUDO gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
        | $SUDO tee /etc/apt/sources.list.d/nodesource.list >/dev/null
    $SUDO apt-get update -q
    apt_install nodejs
fi
ok "node $(node --version)"

# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------
if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "go${GO_VERSION} "; then
    say "Installing Go $GO_VERSION"
    tmp="$(mktemp -d)"
    curl --fail --location --silent --show-error --retry 3 \
        -o "$tmp/go.tgz" "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf "$tmp/go.tgz"
    rm -rf "$tmp"
fi
ok "$(/usr/local/go/bin/go version)"

# ---------------------------------------------------------------------------
# .NET
# ---------------------------------------------------------------------------
if ! /opt/dotnet/dotnet --list-sdks 2>/dev/null | grep -q "^${DOTNET_CHANNEL}\."; then
    say "Installing the .NET $DOTNET_CHANNEL SDK into /opt/dotnet"
    tmp="$(mktemp -d)"
    curl --fail --location --silent --show-error --retry 3 -o "$tmp/dotnet-install.sh" https://dot.net/v1/dotnet-install.sh
    $SUDO bash "$tmp/dotnet-install.sh" --channel "$DOTNET_CHANNEL" --install-dir /opt/dotnet
    rm -rf "$tmp"
fi
ok ".NET SDK $(/opt/dotnet/dotnet --list-sdks | awk '{print $1}' | tail -1)"

# ---------------------------------------------------------------------------
# Swift (swiftly, the official installer; it verifies toolchain signatures)
# ---------------------------------------------------------------------------
if ! command -v swiftly >/dev/null 2>&1; then
    say "Installing swiftly"
    tmp="$(mktemp -d)"
    curl --fail --location --silent --show-error --retry 3 \
        -o "$tmp/swiftly.tgz" "https://download.swift.org/swiftly/linux/swiftly-$(uname -m).tar.gz"
    tar -xzf "$tmp/swiftly.tgz" -C "$tmp"
    "$tmp/swiftly" init --assume-yes --quiet-shell-followup --skip-install
    rm -rf "$tmp"
    bench_path
fi
if ! swift --version 2>/dev/null | grep -q "Swift version ${SWIFT_VERSION}\b"; then
    say "Installing Swift $SWIFT_VERSION (a large download)"
    swiftly install "$SWIFT_VERSION" --use --assume-yes
    bench_path
fi
ok "$(swift --version 2>&1 | grep -m1 'Swift version')"

# ---------------------------------------------------------------------------
# PATH for every later shell (one marked block, replaced on a re-run)
# ---------------------------------------------------------------------------
BEGIN="# >>> axiam bench-vm toolchains >>>"
END="# <<< axiam bench-vm toolchains <<<"
touch "$HOME/.bashrc"
sed -i "/^${BEGIN}\$/,/^${END}\$/d" "$HOME/.bashrc"
cat >> "$HOME/.bashrc" <<EOF
$BEGIN
export PATH="/usr/local/go/bin:\$HOME/go/bin:/opt/dotnet:\$HOME/.cargo/bin:\$PATH"
export DOTNET_ROOT=/opt/dotnet DOTNET_CLI_TELEMETRY_OPTOUT=1
[ -f "\$HOME/.local/share/swiftly/env.sh" ] && . "\$HOME/.local/share/swiftly/env.sh"
$END
EOF
ok "PATH block written to ~/.bashrc"

ok "SDK toolchains installed. Next: exec bash -l, then ./03-checkouts.sh"
