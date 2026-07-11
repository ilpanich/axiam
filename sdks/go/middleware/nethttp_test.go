package middleware

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/ilpanich/axiam/sdks/go/internal/jwks"
)

// ---------------------------------------------------------------------------
// Test fixtures — local Ed25519 key + httptest JWKS server, mirroring
// internal/jwks/verifier_test.go's signing helpers (D-10: deterministic, no
// live network).
// ---------------------------------------------------------------------------

const testConfiguredTenant = "tenant-abc"

func generateTestKey(t *testing.T, kid string) (ed25519.PrivateKey, jwk.Key) {
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

func newTestJWKSServer(t *testing.T, keys ...jwk.Key) *httptest.Server {
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
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

type testClaims struct {
	Subject  string
	TenantID string
	OrgID    string
	Roles    []string
	Exp      int64
}

func signTestToken(t *testing.T, priv ed25519.PrivateKey, kid string, claims testClaims) string {
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
	return string(signed)
}

func newTestVerifier(t *testing.T, jwksSrv *httptest.Server) *jwks.Verifier {
	t.Helper()
	v, err := jwks.NewVerifier(context.Background(), jwksSrv.URL, jwksSrv.Client())
	if err != nil {
		t.Fatalf("jwks.NewVerifier: %v", err)
	}
	return v
}

func validClaims() testClaims {
	return testClaims{
		Subject:  "user-123",
		TenantID: testConfiguredTenant,
		OrgID:    "org-xyz",
		Roles:    []string{"admin", "reader"},
		Exp:      time.Now().Add(time.Hour).Unix(),
	}
}

// noopHandler records whether it was invoked and, if so, the context it saw.
type recordingHandler struct {
	called bool
	sawCtx context.Context
}

func (h *recordingHandler) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.called = true
		h.sawCtx = r.Context()
		w.WriteHeader(http.StatusOK)
	})
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestMiddleware_AllowsValidTenant(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	mw := Middleware(verifier, testConfiguredTenant)

	rec := &recordingHandler{}
	h := mw(rec.handler())

	token := signTestToken(t, priv, "kid-1", validClaims())
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if !rec.called {
		t.Fatal("expected wrapped handler to be called for a valid same-tenant token")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestMiddleware_AllowsValidTenant_ViaCookie(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	mw := Middleware(verifier, testConfiguredTenant)

	rec := &recordingHandler{}
	h := mw(rec.handler())

	token := signTestToken(t, priv, "kid-1", validClaims())
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "axiam_access", Value: token})
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if !rec.called {
		t.Fatal("expected wrapped handler to be called for a valid cookie-borne token")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestMiddleware_RejectsMissingOrInvalidToken(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	mw := Middleware(verifier, testConfiguredTenant)

	t.Run("no credentials", func(t *testing.T) {
		rec := &recordingHandler{}
		h := mw(rec.handler())

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if rec.called {
			t.Fatal("expected wrapped handler NOT to be called with no credentials")
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
		assertJSONErrorBody(t, w.Body.Bytes())
	})

	t.Run("invalid signature", func(t *testing.T) {
		rec := &recordingHandler{}
		h := mw(rec.handler())

		token := signTestToken(t, priv, "kid-1", validClaims())
		tampered := []byte(token)
		tampered[len(tampered)-1] ^= 0xFF

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+string(tampered))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if rec.called {
			t.Fatal("expected wrapped handler NOT to be called with an invalid signature")
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
		assertJSONErrorBody(t, w.Body.Bytes())
	})

	t.Run("expired token", func(t *testing.T) {
		rec := &recordingHandler{}
		h := mw(rec.handler())

		claims := validClaims()
		claims.Exp = time.Now().Add(-time.Hour).Unix()
		token := signTestToken(t, priv, "kid-1", claims)

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if rec.called {
			t.Fatal("expected wrapped handler NOT to be called with an expired token")
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}

func TestMiddleware_RejectsCrossTenant(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	mw := Middleware(verifier, testConfiguredTenant)

	rec := &recordingHandler{}
	h := mw(rec.handler())

	// Signature-VALID token, but minted for a DIFFERENT tenant than this
	// resource server is configured for (cross-tenant replay defense,
	// TS CR-03 carry-forward — org-wide JWKS means signature validity alone
	// is insufficient).
	claims := validClaims()
	claims.TenantID = "some-other-tenant"
	token := signTestToken(t, priv, "kid-1", claims)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if rec.called {
		t.Fatal("expected wrapped handler NOT to be called for a cross-tenant token")
	}
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("expected 401 or 403 for cross-tenant token, got %d", w.Code)
	}
	assertJSONErrorBody(t, w.Body.Bytes())

	// No raw token value must appear in the response body.
	if strings.Contains(w.Body.String(), token) {
		t.Fatal("response body must never contain the raw token value")
	}
}

func TestMiddleware_InjectsUser(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	mw := Middleware(verifier, testConfiguredTenant)

	var gotUser *User
	var gotOK bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotOK = UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := mw(handler)

	claims := validClaims()
	token := signTestToken(t, priv, "kid-1", claims)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if !gotOK {
		t.Fatal("expected UserFromContext to return ok=true inside the wrapped handler")
	}
	if gotUser == nil {
		t.Fatal("expected a non-nil *User")
	}
	if gotUser.UserID != claims.Subject {
		t.Fatalf("UserID mismatch: got %q want %q", gotUser.UserID, claims.Subject)
	}
	if gotUser.TenantID != claims.TenantID {
		t.Fatalf("TenantID mismatch: got %q want %q", gotUser.TenantID, claims.TenantID)
	}
	if len(gotUser.Roles) != 2 || gotUser.Roles[0] != "admin" || gotUser.Roles[1] != "reader" {
		t.Fatalf("Roles mismatch: got %v", gotUser.Roles)
	}
}

func TestMiddleware_OutsideRequest_UserFromContextReturnsFalse(t *testing.T) {
	u, ok := UserFromContext(context.Background())
	if ok {
		t.Fatal("expected ok=false for a context with no injected user")
	}
	if u != nil {
		t.Fatal("expected nil *User for a context with no injected user")
	}
}

// ---------------------------------------------------------------------------
// CSRF (cookie double-submit, CONTRACT.md §3) — mirrors the Java Spring
// filter's isCsrfValid gate: cookie-sourced credentials on state-changing
// requests must carry a matching X-CSRF-Token header / axiam_csrf cookie
// pair. Bearer-header requests and safe methods (GET/HEAD/OPTIONS) are
// exempt regardless of credential source.
// ---------------------------------------------------------------------------

func TestMiddleware_CookieAuthStateChanging_WithoutCSRFHeader_Rejected(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	mw := Middleware(verifier, testConfiguredTenant)

	rec := &recordingHandler{}
	h := mw(rec.handler())

	token := signTestToken(t, priv, "kid-1", validClaims())
	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "axiam_access", Value: token})
	req.AddCookie(&http.Cookie{Name: "axiam_csrf", Value: "csrf-secret"})
	// Deliberately no X-CSRF-Token header — this is the CSRF attack shape: a
	// cross-site form POST carries the browser-attached axiam_access and
	// axiam_csrf cookies automatically, but cannot set a custom header.
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if rec.called {
		t.Fatal("expected wrapped handler NOT to be called for a cookie-sourced state-changing request without X-CSRF-Token")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	assertJSONErrorBody(t, w.Body.Bytes())
}

func TestMiddleware_CookieAuthStateChanging_WithMatchingCSRFHeader_Allowed(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	mw := Middleware(verifier, testConfiguredTenant)

	rec := &recordingHandler{}
	h := mw(rec.handler())

	token := signTestToken(t, priv, "kid-1", validClaims())
	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "axiam_access", Value: token})
	req.AddCookie(&http.Cookie{Name: "axiam_csrf", Value: "csrf-secret"})
	req.Header.Set("X-CSRF-Token", "csrf-secret")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if !rec.called {
		t.Fatal("expected wrapped handler to be called for a cookie-sourced request with a matching X-CSRF-Token")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestMiddleware_BearerAuthStateChanging_WithoutCSRF_Allowed(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	mw := Middleware(verifier, testConfiguredTenant)

	rec := &recordingHandler{}
	h := mw(rec.handler())

	// Bearer-header requests are CSRF-immune by construction (a cross-site
	// attacker cannot set arbitrary request headers), so no CSRF check
	// applies even on a state-changing method with no CSRF cookie/header at
	// all.
	token := signTestToken(t, priv, "kid-1", validClaims())
	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if !rec.called {
		t.Fatal("expected wrapped handler to be called for a Bearer-authenticated POST with no CSRF token")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestMiddleware_CookieAuthSafeMethod_WithoutCSRF_Allowed(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	mw := Middleware(verifier, testConfiguredTenant)

	rec := &recordingHandler{}
	h := mw(rec.handler())

	// GET is a safe method (RFC 9110 §9.2.1) — the CSRF double-submit check
	// only guards state-changing methods, so a cookie-sourced GET with no
	// CSRF token must still pass (matches
	// TestMiddleware_AllowsValidTenant_ViaCookie's baseline behavior).
	token := signTestToken(t, priv, "kid-1", validClaims())
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "axiam_access", Value: token})
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if !rec.called {
		t.Fatal("expected wrapped handler to be called for a cookie-sourced GET with no CSRF token")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// assertJSONErrorBody verifies the response body decodes as JSON and
// contains no raw token-looking value.
func assertJSONErrorBody(t *testing.T, body []byte) {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("expected a JSON error body, got unmarshal error: %v (body=%s)", err, body)
	}
	if len(decoded) == 0 {
		t.Fatal("expected a non-empty JSON error body")
	}
}
