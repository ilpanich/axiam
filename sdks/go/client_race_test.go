package axiam

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestClient_ConcurrentRefreshLogout_NoDataRace is the CR-01 regression guard.
//
// Before the fix, Client.guard was a plain *refreshguard.Guard field: Logout
// reassigned it (c.guard = &Guard{}) with no synchronization while concurrent
// Refresh/Login calls dereferenced it, producing a real data race that Go's
// race detector reproduces (WARNING: DATA RACE on the c.guard read vs the
// Logout write). The field is now an atomic.Pointer, so Load()/Store() make
// the swap race-free.
//
// This test only asserts the ABSENCE of a data race / panic under `-race` for
// the exact "one *Client shared across concurrent goroutines" pattern the
// single-flight guard exists to support (CONTRACT.md §9); the returned errors
// are intentionally ignored because Logout racing Refresh legitimately yields
// transient failures.
func TestClient_ConcurrentRefreshLogout_NoDataRace(t *testing.T) {
	const orgID = "55555555-5555-5555-5555-555555555555"
	token := makeAccessTokenWithOrgID(t, orgID)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/login", "/api/v1/auth/refresh":
			http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: token, Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "axiam_refresh", Value: "refresh-tok", Path: "/"})
			w.Header().Set("X-CSRF-Token", "csrf-tok")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"expires_in": 900})
		case "/api/v1/auth/logout":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Seed a session so Refresh reaches the guard (it resolves tenant/org
	// from the access cookie before touching c.guard).
	if _, err := client.Login(context.Background(), "alice@example.test", "hunter2"); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	const goroutines = 50
	const iters = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				switch (id + i) % 3 {
				case 0:
					_ = client.Refresh(context.Background())
				case 1:
					_ = client.Logout(context.Background())
				default:
					_, _ = client.Login(context.Background(), "alice@example.test", "hunter2")
				}
			}
		}(g)
	}
	wg.Wait()
}
