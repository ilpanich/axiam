package jwks

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// jwksPath is the AXIAM JWKS endpoint path — organization-wide, not
// tenant-scoped, serving exactly one Ed25519 key today (RESEARCH.md D-11,
// mirrors sdks/rust/src/token/jwks.rs::JWKS_PATH). This is NOT a generic
// OIDC discovery-style `/.well-known/jwks.json` path; do not substitute one.
const jwksPath = "/oauth2/jwks"

const (
	// minRefetchInterval is the forced-refetch cooldown floor (CF-03;
	// matches the Rust reference's FORCED_REFETCH_MIN_INTERVAL).
	minRefetchInterval = 60 * time.Second
	// maxCacheInterval is the normal (non-forced) refresh TTL ceiling
	// (CF-03; matches the Rust reference's JWKS_CACHE_TTL).
	maxCacheInterval = 300 * time.Second
)

// Verifier fetches, caches, and locally verifies AXIAM access tokens against
// the organization-wide EdDSA JWKS (D-06). It is the shared local-verify
// primitive consumed by the net/http middleware (Plan 05).
type Verifier struct {
	cache   *jwk.Cache
	jwksURL string

	// refreshMu serializes the forced-refetch path so a concurrent burst of
	// unknown-kid verifications collapses to exactly one network fetch
	// (D-08/D-09). We do NOT rely on jwx/httprc's internal coalescing
	// (Assumption A2) — the mutex wraps only the fetch/refresh decision,
	// never the jws.Verify call itself.
	refreshMu sync.Mutex
}

// NewVerifier constructs a Verifier bound to {baseURL}/oauth2/jwks (trailing
// slash on baseURL trimmed before joining). The cache is registered but not
// eagerly populated; the first Verify call triggers the initial fetch.
func NewVerifier(ctx context.Context, baseURL string, hc *http.Client) (*Verifier, error) {
	jwksURL := strings.TrimRight(baseURL, "/") + jwksPath

	var client *httprc.Client
	if hc != nil {
		client = httprc.NewClient(httprc.WithHTTPClient(hc))
	} else {
		client = httprc.NewClient()
	}

	cache, err := jwk.NewCache(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("jwks: failed to construct cache: %w", err)
	}

	if err := cache.Register(ctx, jwksURL,
		jwk.WithMinInterval(minRefetchInterval),
		jwk.WithMaxInterval(maxCacheInterval),
	); err != nil {
		return nil, fmt.Errorf("jwks: failed to register %s: %w", jwksURL, err)
	}

	return &Verifier{cache: cache, jwksURL: jwksURL}, nil
}

// Verify parses and verifies token's signature against the cached JWKS,
// returning the token's Claims on success.
//
// The protected header's alg is checked against an explicit EdDSA allowlist
// BEFORE any keyset lookup — the token's own alg header never selects the
// verification algorithm (algorithm-confusion defense). An unknown kid
// triggers exactly one forced JWKS refetch, then a single retry; if the kid
// is still unknown after that, verification fails.
//
// Verify does NOT check token expiry — it validates the signature only.
// Callers MUST compare the returned Claims.Exp against time.Now().Unix()
// themselves before trusting the result (see middleware.Middleware for a
// reference implementation). A signature-valid but expired token will verify
// successfully here.
func (v *Verifier) Verify(ctx context.Context, token []byte) (Claims, error) {
	msg, err := jws.Parse(token)
	if err != nil {
		return Claims{}, fmt.Errorf("jwks: invalid token: %w", err)
	}

	// Fail closed if the message carries no signatures: an empty loop would
	// otherwise skip the EdDSA allowlist entirely and fall through to keyset
	// verification, silently violating the "only EdDSA, checked BEFORE any
	// keyset lookup" invariant above (WR-02).
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return Claims{}, fmt.Errorf("jwks: token has no signatures")
	}
	for _, sig := range sigs {
		alg, ok := sig.ProtectedHeaders().Algorithm()
		if !ok || alg != jwa.EdDSA() {
			return Claims{}, fmt.Errorf("jwks: unexpected alg %q: only EdDSA is accepted", alg.String())
		}
	}

	keySet, err := v.cache.CachedSet(v.jwksURL)
	if err != nil {
		return Claims{}, fmt.Errorf("jwks: JWKS fetch failed: %w", err)
	}

	payload, verifyErr := jws.Verify(token, jws.WithKeySet(keySet, jws.WithInferAlgorithmFromKey(false)))
	if verifyErr != nil {
		// Unknown kid (or stale cache after key rotation) → force exactly
		// one refetch, then retry verification exactly once. The mutex
		// serializes this section so a concurrent burst of unknown-kid
		// verifications triggers a single v.cache.Refresh call (D-08/D-09):
		// each waiter re-checks CachedSet under the lock first, since
		// another goroutine may have already performed the refetch while
		// this one was waiting.
		v.refreshMu.Lock()
		if cachedSet, cachedErr := v.cache.CachedSet(v.jwksURL); cachedErr == nil {
			if p, retryErr := jws.Verify(token, jws.WithKeySet(cachedSet, jws.WithInferAlgorithmFromKey(false))); retryErr == nil {
				v.refreshMu.Unlock()
				return parseClaims(p)
			}
		}
		refreshed, refreshErr := v.cache.Refresh(ctx, v.jwksURL)
		v.refreshMu.Unlock()
		if refreshErr != nil {
			return Claims{}, fmt.Errorf("jwks: token verification failed and JWKS refetch also failed: %w", verifyErr)
		}
		payload, verifyErr = jws.Verify(token, jws.WithKeySet(refreshed, jws.WithInferAlgorithmFromKey(false)))
		if verifyErr != nil {
			return Claims{}, fmt.Errorf("jwks: token signature invalid after forced refetch: %w", verifyErr)
		}
	}

	return parseClaims(payload)
}
