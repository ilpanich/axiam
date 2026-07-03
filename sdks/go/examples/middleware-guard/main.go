// Command middleware-guard demonstrates wrapping a sample net/http route
// with middleware.Middleware (CONTRACT.md §10, SC#1).
//
// The middleware extracts the session from the Authorization: Bearer header
// (falling back to the axiam_access cookie), verifies it locally via a
// JWKS-backed verifier (no per-request AXIAM-server round-trip on a cache
// hit), enforces the configured-tenant claim, injects the authenticated
// identity into the request context, and returns 401/403 automatically
// before the wrapped handler ever runs.
//
// This example is illustrative/compilable — it starts a real net/http
// server bound to AXIAM_LISTEN_ADDR (default 127.0.0.1:8080) and does not
// require a live AXIAM server to `go build ./examples/middleware-guard/...`
// (SC#1). Serving real traffic requires the configured AXIAM_BASE_URL to be
// a reachable AXIAM server (for the verifier's JWKS fetch).
//
// Run: go run ./examples/middleware-guard
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	axiam "github.com/ilpanich/axiam/sdks/go"
	"github.com/ilpanich/axiam/sdks/go/middleware"
)

func main() {
	baseURL := getenv("AXIAM_BASE_URL", "https://localhost:8443")
	tenantSlug := getenv("AXIAM_TENANT_SLUG", "acme")
	listenAddr := getenv("AXIAM_LISTEN_ADDR", "127.0.0.1:8080")

	// NewJWKSVerifier is the middleware-guard-friendly entry point exposed
	// alongside axiam.NewClient — it constructs the same local JWKS
	// verification primitive the middleware requires, bound to
	// {baseURL}/oauth2/jwks (§10, D-06).
	verifier, err := axiam.NewJWKSVerifier(context.Background(), baseURL, nil)
	if err != nil {
		log.Fatalf("failed to construct JWKS verifier: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/protected", protectedHandler)

	// middleware.Middleware wraps the mux with local session verification,
	// cross-tenant rejection, and identity injection (§10). Verification
	// failures return standardized 401/403 JSON before the handler runs.
	guarded := middleware.Middleware(verifier, tenantSlug)(mux)

	fmt.Printf("Listening on http://%s — GET /protected requires an AXIAM session\n", listenAddr)
	if err := http.ListenAndServe(listenAddr, guarded); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}

// protectedHandler reads the identity middleware.Middleware injected into
// the request context via middleware.UserFromContext.
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		http.Error(w, "no authenticated user in context", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "Hello, user %s (tenant %s) — roles: %v\n", user.UserID, user.TenantID, user.Roles)
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
