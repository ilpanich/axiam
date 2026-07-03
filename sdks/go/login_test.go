package axiam

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

// makeAccessTokenWithOrgID builds a syntactically-valid (unsigned-signature)
// JWT whose payload carries the given org_id claim, so tests can exercise
// the base64url-decode path in login.go without needing a real EdDSA
// signature (verification is explicitly out of scope for this plan per
// PLAN.md's <action> — "do not verify signature here").
func makeAccessTokenWithOrgID(t *testing.T, orgID string) string {
	t.Helper()
	header := map[string]string{"alg": "EdDSA", "typ": "JWT"}
	payload := map[string]any{
		"sub":       "11111111-1111-1111-1111-111111111111",
		"tenant_id": "22222222-2222-2222-2222-222222222222",
		"org_id":    orgID,
		"exp":       time.Now().Add(time.Hour).Unix(),
		"jti":       "33333333-3333-3333-3333-333333333333",
	}
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	p, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(h) + "." + enc.EncodeToString(p) + "." + enc.EncodeToString([]byte("sig"))
}

// TestLogin_MFARequiredDiscriminates proves CF-04: a 200 login response
// yields MFARequired:false; an MFA challenge (202) yields
// MFARequired:true with a Sensitive MFA token, not an error.
func TestLogin_MFARequiredDiscriminates(t *testing.T) {
	t.Run("200 success discriminates MFARequired=false", func(t *testing.T) {
		token := makeAccessTokenWithOrgID(t, "44444444-4444-4444-4444-444444444444")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/auth/login" {
				t.Fatalf("unexpected path: %s", r.URL.Path)
			}
			http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: token, Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "axiam_refresh", Value: "refresh-tok", Path: "/"})
			w.Header().Set("X-CSRF-Token", "csrf-tok")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user":       map[string]any{"id": "11111111-1111-1111-1111-111111111111", "username": "alice", "email": "alice@example.test"},
				"session_id": "33333333-3333-3333-3333-333333333333",
				"expires_in": 900,
			})
		}))
		defer server.Close()

		client, err := NewClient(server.URL, "acme", WithOrgID(uuid.MustParse("44444444-4444-4444-4444-444444444444")))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		result, err := client.Login(context.Background(), "alice@example.test", "hunter2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.MFARequired {
			t.Fatalf("expected MFARequired=false on 200 response")
		}
		if result.MFAToken != "" {
			t.Fatalf("expected no MFAToken on a completed login")
		}
	})

	t.Run("202 MFA challenge discriminates MFARequired=true, not an error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"mfa_required":      true,
				"challenge_token":   "challenge-abc",
				"available_methods": []string{"totp"},
			})
		}))
		defer server.Close()

		client, err := NewClient(server.URL, "acme")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		result, err := client.Login(context.Background(), "alice@example.test", "hunter2")
		if err != nil {
			t.Fatalf("expected MFA-required to be a typed result, not an error: %v", err)
		}
		if !result.MFARequired {
			t.Fatalf("expected MFARequired=true on 202 response")
		}
		if result.MFAToken != Sensitive("challenge-abc") {
			t.Fatalf("expected MFAToken to carry the challenge token")
		}
	})
}

// TestLogin_ResolvesOrgIDForRefresh proves RESEARCH.md Pitfall 3: the org
// UUID is decoded from the access token's org_id claim and cached so
// Refresh's body can include it.
func TestLogin_ResolvesOrgIDForRefresh(t *testing.T) {
	const wantOrgID = "55555555-5555-5555-5555-555555555555"
	token := makeAccessTokenWithOrgID(t, wantOrgID)

	var refreshBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/login":
			http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: token, Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "axiam_refresh", Value: "refresh-tok", Path: "/"})
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user":       map[string]any{"id": "1", "username": "alice", "email": "a@example.test"},
				"session_id": "33333333-3333-3333-3333-333333333333",
				"expires_in": 900,
			})
		case "/api/v1/auth/refresh":
			_ = json.NewDecoder(r.Body).Decode(&refreshBody)
			http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: token, Path: "/"})
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"expires_in": 900})
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := client.Login(context.Background(), "alice@example.test", "hunter2"); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	if err := client.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	gotOrgID, _ := refreshBody["org_id"].(string)
	if gotOrgID != wantOrgID {
		t.Fatalf("expected refresh body org_id=%s, got %v", wantOrgID, refreshBody)
	}
}

// TestRefresh_401IsAuthErrorNoRetry proves §9.3: a 401 on the refresh call
// itself is AuthError, with no second refresh attempt.
func TestRefresh_401IsAuthErrorNoRetry(t *testing.T) {
	const orgID = "66666666-6666-6666-6666-666666666666"
	token := makeAccessTokenWithOrgID(t, orgID)

	var refreshCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/login":
			http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: token, Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "axiam_refresh", Value: "refresh-tok", Path: "/"})
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user":       map[string]any{"id": "1", "username": "alice", "email": "a@example.test"},
				"session_id": "33333333-3333-3333-3333-333333333333",
				"expires_in": 900,
			})
		case "/api/v1/auth/refresh":
			refreshCalls++
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid refresh token"}`))
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := client.Login(context.Background(), "alice@example.test", "hunter2"); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	err = client.Refresh(context.Background())
	if err == nil {
		t.Fatalf("expected an error on 401 refresh")
	}
	var authErr *AuthError
	if !isAuthError(err, &authErr) {
		t.Fatalf("expected *AuthError, got %T: %v", err, err)
	}
	if refreshCalls != 1 {
		t.Fatalf("expected exactly 1 refresh attempt (no retry loop, §9.3), got %d", refreshCalls)
	}
}
