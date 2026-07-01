// Package refreshguard implements the sync.Mutex single-flight refresh
// guard required by CONTRACT.md §9: exactly one in-flight
// POST /api/v1/auth/refresh call across any number of concurrent callers
// observing the same expired access token, with a double-check-after-lock
// pattern and no retry loop on failure (§9.3).
//
// This package lives at sdks/go/internal/refreshguard so it can be shared
// by the REST 401 path (client.go) and, later, a caller-supplied closure
// driving the gRPC interceptor's UNAUTHENTICATED path — both share exactly
// one in-flight refresh per session (D-05).
package refreshguard

import (
	"context"
	"sync"
)

// Sensitive mirrors the root package's axiam.Sensitive type (a string that
// redacts itself from fmt/JSON output). It is redefined here — rather than
// imported from the module root — because the root package imports this
// package to build *Client, and Go forbids import cycles; this alias is
// documented as intentionally mirroring the root type's wire-level shape
// (a plain string at the type level) so the root package can freely
// convert between axiam.Sensitive and refreshguard.Sensitive at the call
// boundary without any lossy behavior.
type Sensitive string

// RefreshedTokens is the shape of a successful refresh outcome, decoupled
// from any particular transport response type so this package has no HTTP
// dependency of its own beyond what the caller-supplied doRefresh closure
// requires.
type RefreshedTokens struct {
	Access  Sensitive
	Refresh Sensitive
	Exp     int64
}

// Guard is the sync.Mutex single-flight refresh guard (§9). The zero value
// is ready to use.
type Guard struct {
	mu      sync.Mutex
	access  Sensitive
	refresh Sensitive
	exp     int64
	hasAny  bool
}

// RefreshIfNeeded performs at most one underlying refresh call across any
// number of concurrent callers that observed the same expired
// observedAccess token.
//
// Locking makes the FIRST caller to acquire mu the single in-flight
// refresher; every other concurrent caller blocks on the same lock and,
// upon acquiring it, re-checks (double-check) whether a newer token
// already exists before deciding whether to call doRefresh again. If the
// cached access token differs from observedAccess, another goroutine
// already refreshed while this caller waited — the cached token is
// returned immediately, WITHOUT invoking doRefresh.
//
// doRefresh is invoked at most once per call to RefreshIfNeeded. Its error,
// if any, is propagated as-is — no retry loop (§9.3): the caller must
// re-authenticate from scratch on refresh failure.
func (g *Guard) RefreshIfNeeded(ctx context.Context, observedAccess string, doRefresh func(ctx context.Context) (RefreshedTokens, error)) (Sensitive, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Double-check: another goroutine may have already refreshed while we
	// waited for the lock. If the cached access token is populated and
	// differs from what this caller observed failing, just return it — no
	// refresh call needed.
	if g.hasAny && string(g.access) != observedAccess {
		return g.access, nil
	}

	tokens, err := doRefresh(ctx) // §9.3: no retry loop on failure — propagate as-is.
	if err != nil {
		return "", err
	}

	g.access = tokens.Access
	if tokens.Refresh != "" {
		g.refresh = tokens.Refresh
	}
	g.exp = tokens.Exp
	g.hasAny = true

	return g.access, nil
}

// CachedAccessToken is a non-blocking read of the most recently cached
// access token, used by the future gRPC interceptor (which must never
// synchronously acquire the refresh mutex on the hot RPC path — RESEARCH.md
// Pitfall 3 carried forward from the Rust reference). Returns ok=false if
// no token has been cached yet.
func (g *Guard) CachedAccessToken() (Sensitive, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.access, g.hasAny
}

// CachedRefreshToken is a non-blocking read of the most recently cached
// refresh token. Returns ok=false if no token has been cached yet.
func (g *Guard) CachedRefreshToken() (Sensitive, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.refresh, g.hasAny
}

// CachedExp is a non-blocking read of the most recently cached access token
// expiry (unix seconds). Returns ok=false if no token has been cached yet.
func (g *Guard) CachedExp() (int64, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.exp, g.hasAny
}

// Seed primes the guard's cache with an already-known token triple (used
// by the client after a successful Login/VerifyMfa, before any refresh has
// ever run, so a subsequent 401 sees the correct observedAccess baseline).
func (g *Guard) Seed(access, refresh Sensitive, exp int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.access = access
	if refresh != "" {
		g.refresh = refresh
	}
	g.exp = exp
	g.hasAny = true
}
