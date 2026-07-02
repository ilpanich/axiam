package axiam

import (
	"context"
	"net/http"

	"github.com/ilpanich/axiam/sdks/go/internal/jwks"
)

// JWKSVerifier is the public entry point for this SDK's local JWKS
// verification primitive (CONTRACT.md §10, D-06) — the shared local-verify
// mechanism consumed by the net/http middleware (package middleware). It is
// a thin re-export of the internal jwks.Verifier so callers outside this
// module never need to import an internal/ package directly.
//
// IMPORTANT: JWKSVerifier.Verify validates the token SIGNATURE ONLY — it does
// NOT check expiry. Callers using this type directly (rather than via
// middleware.Middleware, which checks expiry for you) MUST compare the
// returned Claims.Exp against time.Now().Unix() before trusting the token
// (WR-03).
type JWKSVerifier = jwks.Verifier

// NewJWKSVerifier constructs a JWKSVerifier bound to {baseURL}/oauth2/jwks
// (trailing slash on baseURL trimmed before joining). hc may be nil, in
// which case a default *http.Client is used. The cache is registered but
// not eagerly populated; the first Verify call triggers the initial fetch.
//
// This is the exported constructor middleware.Middleware examples wire
// against — see examples/middleware-guard.
func NewJWKSVerifier(ctx context.Context, baseURL string, hc *http.Client) (*JWKSVerifier, error) {
	return jwks.NewVerifier(ctx, baseURL, hc)
}
