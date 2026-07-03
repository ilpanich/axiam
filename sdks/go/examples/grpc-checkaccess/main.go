// Command grpc-checkaccess demonstrates the gRPC authorization transport:
// CheckAccess and BatchCheck over a lazily-connected *grpc.ClientConn
// (CONTRACT.md §1, §5, §9).
//
// grpc.NewGRPCClient wraps grpc.NewClient (never the deprecated grpc.Dial)
// — per grpc-go 1.63+, NewClient performs no I/O at construction time; the
// actual TCP+TLS handshake happens lazily on the first RPC
// (RESEARCH.md Pitfall 5). This example builds its own
// grpc.UnaryClientInterceptor (the grpc package's own interceptor
// constructor is unexported) that injects the bearer token and tenant ID
// metadata on every outgoing call, backed by a REST login to obtain the
// initial access token.
//
// This example is illustrative/compilable — it reads connection details
// from environment variables and does not require a live AXIAM server to
// `go build ./examples/grpc-checkaccess/...`. Running it end-to-end
// requires a reachable AXIAM gRPC endpoint.
//
// Run: go run ./examples/grpc-checkaccess
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	axiam "github.com/ilpanich/axiam/sdks/go"
	axiamgrpc "github.com/ilpanich/axiam/sdks/go/grpc"
)

func main() {
	baseURL := getenv("AXIAM_BASE_URL", "https://localhost:8443")
	grpcTarget := getenv("AXIAM_GRPC_TARGET", "dns:///localhost:9443")
	tenantSlug := getenv("AXIAM_TENANT_SLUG", "acme")
	email := getenv("AXIAM_EMAIL", "user@example.com")
	password := getenv("AXIAM_PASSWORD", "changeme")
	resourceID := getenv("AXIAM_RESOURCE_ID", "00000000-0000-0000-0000-000000000000")
	subjectID := getenv("AXIAM_SUBJECT_ID", "00000000-0000-0000-0000-000000000000")

	// A REST login populates the initial access token/tenant_id shared with
	// the gRPC transport below (§9 — the same single-flight refresh guard
	// backs both transports in a full integration; this example keeps the
	// token cache minimal and thread-safe on its own).
	restClient, err := axiam.NewClient(baseURL, tenantSlug)
	if err != nil {
		log.Fatalf("failed to construct REST client: %v", err)
	}

	ctx := context.Background()
	loginResult, err := restClient.Login(ctx, email, password)
	if err != nil {
		log.Fatalf("login failed: %v", err)
	}
	if loginResult.MFARequired {
		fmt.Println("MFA is required for this account — see examples/login-mfa first.")
		return
	}

	tokenCache := newTokenCache()
	// The access token itself is Sensitive and never printed; this example
	// only demonstrates wiring, so a placeholder marks that a real
	// integration would seed the cache from the REST client's session here.
	tokenCache.set(os.Getenv("AXIAM_ACCESS_TOKEN"))

	// §6: strict TLS is always on; no custom CA in this example (production
	// callers with a private CA would pass its PEM bytes here instead).
	creds, err := axiamgrpc.NewTLSCredentials(nil)
	if err != nil {
		log.Fatalf("failed to build TLS credentials: %v", err)
	}

	tenantID := getenv("AXIAM_TENANT_ID", "00000000-0000-0000-0000-000000000000")
	interceptor := authInterceptor(tokenCache, tenantID)

	conn, err := axiamgrpc.NewGRPCClient(grpcTarget, creds, interceptor)
	if err != nil {
		log.Fatalf("failed to construct gRPC client: %v", err)
	}
	defer conn.Close()

	authzClient := axiamgrpc.NewAuthzClient(conn, nil)

	// CheckAccess (CONTRACT.md §1).
	decision, denyReason, err := authzClient.CheckAccess(ctx, axiamgrpc.CheckAccessRequest{
		TenantID:   tenantID,
		SubjectID:  subjectID,
		Action:     "resource:read",
		ResourceID: resourceID,
	})
	if err != nil {
		log.Fatalf("gRPC CheckAccess failed: %v", err)
	}
	fmt.Printf("gRPC CheckAccess -> allowed: %v, deny_reason: %q\n", decision, denyReason)

	// BatchCheck — results preserve input order (CONTRACT.md §1).
	batch := []axiamgrpc.CheckAccessRequest{
		{TenantID: tenantID, SubjectID: subjectID, Action: "resource:read", ResourceID: resourceID},
		{TenantID: tenantID, SubjectID: subjectID, Action: "resource:delete", ResourceID: resourceID, Scope: "admin"},
	}
	results, err := authzClient.BatchCheck(ctx, batch)
	if err != nil {
		log.Fatalf("gRPC BatchCheck failed: %v", err)
	}
	for i, r := range results {
		fmt.Printf("gRPC BatchCheck[%d] -> allowed: %v\n", i, r.Allowed)
	}
}

// tokenCache is a minimal thread-safe holder for the current access token,
// backing a axiamgrpc.TokenFunc closure (RESEARCH.md Pitfall 3 — the
// interceptor MUST read this non-blockingly on the hot RPC path).
type tokenCache struct {
	mu    sync.RWMutex
	token string
}

func newTokenCache() *tokenCache { return &tokenCache{} }

func (t *tokenCache) set(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.token = token
}

func (t *tokenCache) get() (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.token, t.token != ""
}

// authInterceptor injects "authorization: Bearer <token>" and
// "x-tenant-id: <tenantID>" metadata on every outgoing unary RPC
// (CONTRACT.md §5), mirroring the grpc package's own (unexported)
// interceptor. tokenCache.get is non-blocking, matching the requirement
// that this closure never acquire the async single-flight refresh mutex
// directly on the hot RPC path.
func authInterceptor(cache *tokenCache, tenantID string) grpclib.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpclib.ClientConn, invoker grpclib.UnaryInvoker, opts ...grpclib.CallOption) error {
		if token, ok := cache.get(); ok {
			ctx = metadata.AppendToOutgoingContext(ctx,
				"authorization", "Bearer "+token,
				"x-tenant-id", tenantID,
			)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
