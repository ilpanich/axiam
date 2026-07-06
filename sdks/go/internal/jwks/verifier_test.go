package jwks

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// generateKey creates a fresh Ed25519 key pair and its corresponding public
// jwk.Key tagged with kid + alg (deterministic, no live network — RESEARCH.md
// D-10).
func generateKey(t *testing.T, kid string) (ed25519.PrivateKey, jwk.Key) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	pubJWK, err := jwk.Import(pub)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}
	if err := pubJWK.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := pubJWK.Set(jwk.AlgorithmKey, jwa.EdDSA()); err != nil {
		t.Fatalf("set alg: %v", err)
	}
	return priv, pubJWK
}

func marshalSet(t *testing.T, keys ...jwk.Key) []byte {
	t.Helper()
	set := jwk.NewSet()
	for _, k := range keys {
		if err := set.AddKey(k); err != nil {
			t.Fatalf("AddKey: %v", err)
		}
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return body
}

// mutableJWKSServer serves a JSON JWK Set body at /oauth2/jwks that can be
// swapped mid-test (simulating key rotation), and counts the number of
// times the endpoint is hit.
type mutableJWKSServer struct {
	*httptest.Server
	hits int32

	mu   sync.Mutex
	body []byte
}

func newMutableJWKSServer(t *testing.T, initialBody []byte) *mutableJWKSServer {
	t.Helper()
	s := &mutableJWKSServer{body: initialBody}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/jwks", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&s.hits, 1)
		s.mu.Lock()
		body := s.body
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Server.Close)
	return s
}

func (s *mutableJWKSServer) setBody(body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body = body
}

func (s *mutableJWKSServer) Hits() int32 {
	return atomic.LoadInt32(&s.hits)
}

func signEdDSA(t *testing.T, priv ed25519.PrivateKey, kid string, claims Claims) []byte {
	t.Helper()
	payload := map[string]any{
		"sub":       claims.Subject,
		"tenant_id": claims.TenantID,
		"org_id":    claims.OrgID,
		"exp":       claims.Exp,
		"scope":     strings.Join(claims.Roles, " "),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	pk, err := jwk.Import(priv)
	if err != nil {
		t.Fatalf("jwk.Import priv: %v", err)
	}
	if err := pk.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}

	signed, err := jws.Sign(payloadBytes, jws.WithKey(jwa.EdDSA(), pk))
	if err != nil {
		t.Fatalf("jws.Sign: %v", err)
	}
	return signed
}

// signHS256 builds a well-formed but wrong-algorithm (HS256) token, to
// prove the alg allowlist rejects it BEFORE any keyset lookup.
func signHS256(t *testing.T) []byte {
	t.Helper()
	payload := []byte(`{"sub":"u","tenant_id":"t","org_id":"o","exp":9999999999,"scope":""}`)
	signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), []byte("irrelevant-secret")))
	if err != nil {
		t.Fatalf("jws.Sign HS256: %v", err)
	}
	return signed
}

func TestJWKS_RejectsWrongAlg(t *testing.T) {
	_, pubJWK := generateKey(t, "kid-1")
	srv := newMutableJWKSServer(t, marshalSet(t, pubJWK))

	ctx := context.Background()
	v, err := NewVerifier(ctx, srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	before := srv.Hits()

	token := signHS256(t)
	if _, err := v.Verify(ctx, token); err == nil {
		t.Fatal("expected HS256 token to be rejected, got nil error")
	}

	after := srv.Hits()
	if after != before {
		t.Fatalf("expected NO keyset lookup for a wrong-alg token; hits before=%d after=%d", before, after)
	}
}

func TestJWKS_VerifiesEdDSAAndParsesClaims(t *testing.T) {
	priv, pubJWK := generateKey(t, "kid-1")
	srv := newMutableJWKSServer(t, marshalSet(t, pubJWK))

	ctx := context.Background()
	v, err := NewVerifier(ctx, srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	want := Claims{
		Subject:  "user-123",
		TenantID: "tenant-abc",
		OrgID:    "org-xyz",
		Roles:    []string{"admin", "reader"},
		Exp:      time.Now().Add(time.Hour).Unix(),
	}
	token := signEdDSA(t, priv, "kid-1", want)

	got, err := v.Verify(ctx, token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject != want.Subject || got.TenantID != want.TenantID || got.OrgID != want.OrgID {
		t.Fatalf("claims mismatch: got %+v want %+v", got, want)
	}
	if len(got.Roles) != 2 || got.Roles[0] != "admin" || got.Roles[1] != "reader" {
		t.Fatalf("roles mismatch: got %v", got.Roles)
	}

	// Tampered signature must fail verification, not return a claims result.
	tampered := append([]byte(nil), token...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := v.Verify(ctx, tampered); err == nil {
		t.Fatal("expected tampered signature to fail verification")
	}
}

func TestJWKS_UnknownKidRefetchesOnce(t *testing.T) {
	priv1, pubJWK1 := generateKey(t, "kid-1")
	priv2, pubJWK2 := generateKey(t, "kid-2")

	// Server starts out only knowing kid-1.
	srv := newMutableJWKSServer(t, marshalSet(t, pubJWK1))

	ctx := context.Background()
	v, err := NewVerifier(ctx, srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	// Prime the cache with kid-1 via an initial verify.
	primeClaims := Claims{Subject: "priming", TenantID: "t", OrgID: "o", Exp: time.Now().Add(time.Hour).Unix()}
	primeToken := signEdDSA(t, priv1, "kid-1", primeClaims)
	if _, err := v.Verify(ctx, primeToken); err != nil {
		t.Fatalf("priming Verify: %v", err)
	}

	hitsBeforeRotation := srv.Hits()

	// Rotate: server now serves both keys; sign a token with kid-2, which
	// the verifier's cache does not yet know about.
	srv.setBody(marshalSet(t, pubJWK1, pubJWK2))
	unknownClaims := Claims{Subject: "user-456", TenantID: "t2", OrgID: "o2", Exp: time.Now().Add(time.Hour).Unix()}
	tokenKid2 := signEdDSA(t, priv2, "kid-2", unknownClaims)

	got, err := v.Verify(ctx, tokenKid2)
	if err != nil {
		t.Fatalf("Verify after rotation: %v", err)
	}
	if got.Subject != unknownClaims.Subject {
		t.Fatalf("claims mismatch after refetch: got %+v want %+v", got, unknownClaims)
	}

	hitsAfterRefetch := srv.Hits()
	if hitsAfterRefetch != hitsBeforeRotation+1 {
		t.Fatalf("expected exactly ONE forced refetch, got %d additional hits (before=%d after=%d)",
			hitsAfterRefetch-hitsBeforeRotation, hitsBeforeRotation, hitsAfterRefetch)
	}

	// A kid unknown even after the refetch must fail cleanly (not hang or
	// refetch indefinitely). Sign with kid-3, a key the server never serves.
	priv3, _ := generateKey(t, "kid-3")
	stillUnknownToken := signEdDSA(t, priv3, "kid-3", unknownClaims)
	if _, err := v.Verify(ctx, stillUnknownToken); err == nil {
		t.Fatal("expected verification to fail for a kid unknown even after refetch")
	}
}

// TestJWKS_ConcurrentUnknownKidSingleFlight proves D-08/D-09: a burst of
// concurrent Verify calls against an unknown kid (cold cache) collapses to
// exactly one forced JWKS refetch, not one per goroutine.
func TestJWKS_ConcurrentUnknownKidSingleFlight(t *testing.T) {
	priv1, pubJWK1 := generateKey(t, "kid-1")
	priv2, pubJWK2 := generateKey(t, "kid-2")

	// Server starts out only knowing kid-1.
	srv := newMutableJWKSServer(t, marshalSet(t, pubJWK1))

	ctx := context.Background()
	v, err := NewVerifier(ctx, srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	// Prime the cache with kid-1 via an initial verify.
	primeClaims := Claims{Subject: "priming", TenantID: "t", OrgID: "o", Exp: time.Now().Add(time.Hour).Unix()}
	primeToken := signEdDSA(t, priv1, "kid-1", primeClaims)
	if _, err := v.Verify(ctx, primeToken); err != nil {
		t.Fatalf("priming Verify: %v", err)
	}

	hitsBeforeRotation := srv.Hits()

	// Rotate: server now serves both keys; sign a token with kid-2, which
	// the verifier's cache does not yet know about (cold-cache miss for
	// every goroutine in the burst below).
	srv.setBody(marshalSet(t, pubJWK1, pubJWK2))
	unknownClaims := Claims{Subject: "user-456", TenantID: "t2", OrgID: "o2", Exp: time.Now().Add(time.Hour).Unix()}
	tokenKid2 := signEdDSA(t, priv2, "kid-2", unknownClaims)

	const goroutines = 8
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, verifyErr := v.Verify(ctx, tokenKid2)
			errs[idx] = verifyErr
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		if e != nil {
			t.Fatalf("goroutine %d: Verify failed: %v", i, e)
		}
	}

	hitsAfterBurst := srv.Hits()
	if hitsAfterBurst != hitsBeforeRotation+1 {
		t.Fatalf("expected exactly ONE JWKS fetch for the concurrent unknown-kid burst, got %d additional hits (before=%d after=%d)",
			hitsAfterBurst-hitsBeforeRotation, hitsBeforeRotation, hitsAfterBurst)
	}

	// Subsequent verification after the refresh must reuse the cache (no
	// extra fetch).
	hitsBeforeReuse := srv.Hits()
	if _, err := v.Verify(ctx, tokenKid2); err != nil {
		t.Fatalf("post-refresh Verify: %v", err)
	}
	if srv.Hits() != hitsBeforeReuse {
		t.Fatalf("expected cache reuse after refresh, got an extra fetch (before=%d after=%d)", hitsBeforeReuse, srv.Hits())
	}
}
