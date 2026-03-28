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

# Start full production-like stack (build images + run all services)
prod-up:
    docker compose -f docker/docker-compose.prod.yml up --build -d
    @echo "AXIAM Frontend: http://localhost"
    @echo "AXIAM REST API: http://localhost:8080"
    @echo "AXIAM gRPC:     localhost:50051"

# Stop production-like stack
prod-down:
    docker compose -f docker/docker-compose.prod.yml down

# Stop production-like stack and remove volumes
prod-clean:
    docker compose -f docker/docker-compose.prod.yml down -v
