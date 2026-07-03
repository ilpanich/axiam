// Command authz-check demonstrates the REST authorization surface:
// CheckAccess, Can (the browser/UI alias), and BatchCheck (CONTRACT.md §1).
//
// It logs in first (see examples/login-mfa for the full MFA-aware flow),
// then exercises POST /api/v1/authz/check and
// POST /api/v1/authz/check/batch (FND-04).
//
// This example is illustrative/compilable — it reads connection details
// from environment variables and does not require a live AXIAM server to
// `go build ./examples/authz-check/...`.
//
// Run: go run ./examples/authz-check
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	axiam "github.com/ilpanich/axiam/sdks/go"
)

func main() {
	baseURL := getenv("AXIAM_BASE_URL", "https://localhost:8443")
	tenantSlug := getenv("AXIAM_TENANT_SLUG", "acme")
	email := getenv("AXIAM_EMAIL", "user@example.com")
	password := getenv("AXIAM_PASSWORD", "changeme")
	resourceID := getenv("AXIAM_RESOURCE_ID", "00000000-0000-0000-0000-000000000000")

	client, err := axiam.NewClient(baseURL, tenantSlug)
	if err != nil {
		log.Fatalf("failed to construct client: %v", err)
	}

	ctx := context.Background()

	result, err := client.Login(ctx, email, password)
	if err != nil {
		log.Fatalf("login failed: %v", err)
	}
	if result.MFARequired {
		fmt.Println("MFA is required for this account — see examples/login-mfa first.")
		return
	}

	// POST /api/v1/authz/check — single access check.
	allowed, reason, err := client.CheckAccess(ctx, "resource:read", resourceID)
	if err != nil {
		log.Fatalf("CheckAccess failed: %v", err)
	}
	fmt.Printf("CheckAccess -> allowed: %v, reason: %q\n", allowed, reason)

	// Can — the browser/UI-facing alias for CheckAccess (CONTRACT.md §1
	// note); returns only the allowed boolean.
	canWrite, err := client.Can(ctx, "resource:write", resourceID)
	if err != nil {
		log.Fatalf("Can failed: %v", err)
	}
	fmt.Printf("Can(resource:write) -> %v\n", canWrite)

	// POST /api/v1/authz/check/batch — an ordered batch of checks; results
	// preserve input order.
	batch := []axiam.AccessCheck{
		{Action: "resource:read", ResourceID: resourceID},
		{Action: "resource:delete", ResourceID: resourceID, Scope: "admin"},
	}
	results, err := client.BatchCheck(ctx, batch)
	if err != nil {
		log.Fatalf("BatchCheck failed: %v", err)
	}
	for i, r := range results {
		fmt.Printf("BatchCheck[%d] -> allowed: %v\n", i, r.Allowed)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
