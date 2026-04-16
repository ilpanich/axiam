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

# Run the AXIAM server
run:
    RUST_LOG=axiam=debug cargo run --bin axiam-server

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
