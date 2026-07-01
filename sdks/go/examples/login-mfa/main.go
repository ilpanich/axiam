// Command login-mfa demonstrates the two-phase Login/VerifyMfa flow
// (CONTRACT.md §1, §5).
//
// It constructs an axiam.Client with a non-optional tenantSlug (§5 — there
// is no default tenant), calls Login, and branches on
// LoginResult.MFARequired: when the server responds with an MFA challenge
// instead of a completed session, it calls VerifyMfa with the challenge
// token and a TOTP code to complete the flow.
//
// This example is illustrative/compilable — it reads connection details
// from environment variables and does not require a live AXIAM server to
// `go build ./examples/login-mfa/...`. Running it end-to-end requires a
// reachable AXIAM server matching the configured base URL.
//
// Run: go run ./examples/login-mfa
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
	totpCode := getenv("AXIAM_TOTP_CODE", "000000")

	// §5: tenantSlug is a non-optional constructor parameter — an empty
	// value returns an *axiam.AuthError, never a silent default.
	client, err := axiam.NewClient(baseURL, tenantSlug)
	if err != nil {
		log.Fatalf("failed to construct client: %v", err)
	}

	ctx := context.Background()

	// POST /api/v1/auth/login (CONTRACT.md §1).
	result, err := client.Login(ctx, email, password)
	if err != nil {
		log.Fatalf("login failed: %v", err)
	}

	if result.MFARequired {
		fmt.Printf("MFA required — available methods: %v\n", result.AvailableMethods)

		// POST /api/v1/auth/mfa/verify — completes the two-phase flow
		// (CONTRACT.md §1's exact VerifyMfa(mfaToken, code) signature).
		// The challenge token is Sensitive and is never logged or printed.
		completed, err := client.VerifyMfa(ctx, result.MFAToken, totpCode)
		if err != nil {
			log.Fatalf("MFA verification failed: %v", err)
		}
		fmt.Printf("MFA verified — session_id: %s, expires_in: %ds\n", completed.SessionID, completed.ExpiresIn)
	} else {
		fmt.Printf("Login complete (no MFA) — session_id: %s, expires_in: %ds\n", result.SessionID, result.ExpiresIn)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
