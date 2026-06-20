# AXIAM development commands

# Start development dependencies (SurrealDB, RabbitMQ)
dev-up:
    docker compose -f docker/docker-compose.dev.yml up -d
    @echo "SurrealDB: http://localhost:8000"
    @echo "RabbitMQ Management: http://localhost:15672 (axiam/axiam)"

# Stop development dependencies
dev-down:
    docker compose -f docker/docker-compose.dev.yml down

# Stop and remove all data volumes
dev-clean:
    docker compose -f docker/docker-compose.dev.yml down -v

# Build all crates
build:
    cargo build --workspace

# Run all tests
test:
    cargo test --workspace

# Run a specific test
test-one NAME:
    cargo test --workspace {{NAME}}

# Run clippy linter
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Apply formatting
fmt:
    cargo fmt --all

# Run all checks (fmt + clippy + test)
check: fmt-check lint test

# Run the AXIAM server (saml-on; needs a compatible system libxml2 — CI/Docker)
run:
    RUST_LOG=axiam=debug cargo run --bin axiam-server

# Run axiam-server without saml (local dev on Arch/incompatible libxml2; OIDC still works).
# Self-contained: generates a local-only Ed25519 JWT keypair on first run (shared
# with prod-up, gitignored under docker/.secrets/), points AMQP at the dev-up
# RabbitMQ creds, and disables Secure cookies so auth works over http://localhost.
# Requires `just dev-up` (SurrealDB + RabbitMQ) running first.
run-local:
    #!/usr/bin/env bash
    set -euo pipefail
    SECRETS_DIR="docker/.secrets"
    PRIV="$SECRETS_DIR/jwt_ed25519.pem"
    PUB="$SECRETS_DIR/jwt_ed25519.pub.pem"
    if [[ ! -f "$PRIV" || ! -f "$PUB" ]]; then
        echo "→ Generating Ed25519 JWT keypair in $SECRETS_DIR/ (first-run only)"
        mkdir -p "$SECRETS_DIR"
        openssl genpkey -algorithm ed25519 -out "$PRIV"
        openssl pkey -in "$PRIV" -pubout -out "$PUB"
        chmod 600 "$PRIV"
    fi
    export AXIAM__AUTH__JWT_PRIVATE_KEY_PEM="$(cat "$PRIV")"
    export AXIAM__AUTH__JWT_PUBLIC_KEY_PEM="$(cat "$PUB")"
    # 32-byte (64-hex-char) AES-256-GCM keys for at-rest secret encryption.
    # Generated once and persisted (gitignored) so secrets survive restarts.
    # Without the MFA key, POST /api/v1/auth/mfa/enroll 500s ("MFA encryption
    # key not configured"); without the federation key, OIDC client secrets
    # cannot be decrypted at use.
    gen_hex_key() {
        local f="$SECRETS_DIR/$1"
        if [[ ! -f "$f" ]]; then
            openssl rand -hex 32 > "$f"
            chmod 600 "$f"
        fi
        cat "$f"
    }
    export AXIAM__AUTH__MFA_ENCRYPTION_KEY="$(gen_hex_key mfa_enc.hex)"
    export AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY="$(gen_hex_key federation_enc.hex)"
    export AXIAM__PKI__ENCRYPTION_KEY="$(gen_hex_key pki_enc.hex)"
    # Enables the mail consumer + GDPR Art.15 export sweep (both skipped without it).
    export AXIAM__EMAIL_ENCRYPTION_KEY="$(gen_hex_key email_enc.hex)"
    # D-18: cookies must work over plain http://localhost in local dev. NEVER false in prod.
    export AXIAM__AUTH__COOKIE_SECURE="false"
    # dev-up RabbitMQ runs as axiam/axiam with the default guest user disabled.
    export AXIAM__AMQP__URL="${AXIAM__AMQP__URL:-amqp://axiam:axiam@localhost:5672}"
    RUST_LOG="${RUST_LOG:-axiam=debug}" cargo run --bin axiam-server --no-default-features

# Start frontend dev server
frontend-dev:
    cd frontend && npm run dev

# Build frontend for production
frontend-build:
    cd frontend && npm run build

# Run frontend E2E tests
frontend-test:
    cd frontend && npx playwright test

# Start full production-like stack (build images + run all services).
# Generates a local-only Ed25519 JWT signing keypair on first run under
# docker/.secrets/ (gitignored) and exports it into the shell so the compose
# file can forward it to axiam-server. Host port 80 is left free so a local
# HTTPS reverse proxy (e.g. Caddy) can sit in front of the frontend on :8081.
prod-up:
    #!/usr/bin/env bash
    set -euo pipefail
    SECRETS_DIR="docker/.secrets"
    PRIV="$SECRETS_DIR/jwt_ed25519.pem"
    PUB="$SECRETS_DIR/jwt_ed25519.pub.pem"
    if [[ ! -f "$PRIV" || ! -f "$PUB" ]]; then
        echo "→ Generating Ed25519 JWT keypair in $SECRETS_DIR/ (first-run only)"
        mkdir -p "$SECRETS_DIR"
        openssl genpkey -algorithm ed25519 -out "$PRIV"
        openssl pkey -in "$PRIV" -pubout -out "$PUB"
        chmod 600 "$PRIV"
    fi
    export AXIAM__AUTH__JWT_PRIVATE_KEY_PEM="$(cat "$PRIV")"
    export AXIAM__AUTH__JWT_PUBLIC_KEY_PEM="$(cat "$PUB")"
    docker compose -f docker/docker-compose.prod.yml up --build -d
    echo "AXIAM Frontend: http://localhost:8081 (front it with Caddy for HTTPS)"
    echo "AXIAM REST API: http://localhost:8090"
    echo "AXIAM gRPC:     localhost:50051"
    echo ""
    echo "For HTTPS cookie tests, in another terminal run:"
    echo "  sudo caddy reverse-proxy --from https://localhost --to :8081"

# Stop production-like stack
prod-down:
    docker compose -f docker/docker-compose.prod.yml down

# Stop production-like stack and remove volumes
prod-clean:
    docker compose -f docker/docker-compose.prod.yml down -v

# Requires: `just dev-up` (SurrealDB on :8000) + `just run-local` (AXIAM on :8090).
# Defaults: E2E_ORG_SLUG=test-org, E2E_TENANT_SLUG=default, E2E_ADMIN_EMAIL=admin@axiam.dev
# Override E2E_*, AXIAM_URL, SURREAL_URL, AXIAM__DB__DATABASE env vars as needed.
# Seed org+tenant+admin against the run-local server; unblocks 12-HUMAN-UAT smoke.
bootstrap-local:
    #!/usr/bin/env bash
    set -euo pipefail
    export AXIAM_URL="${AXIAM_URL:-http://localhost:8090}"
    export SURREAL_URL="${SURREAL_URL:-http://localhost:8000}"
    # Must match the database run-local targets (DbConfig default: main).
    export AXIAM__DB__DATABASE="${AXIAM__DB__DATABASE:-main}"
    bash scripts/e2e-bootstrap.sh
