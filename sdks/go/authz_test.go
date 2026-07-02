package axiam

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBatchCheck_PreservesOrder proves §1: batch_check results are
// returned in the same order as input.
func TestBatchCheck_PreservesOrder(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/authz/check/batch" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var body struct {
			Checks []AccessCheck `json:"checks"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		// Respond with results whose "allowed" flag alternates based on
		// input order, so the test can detect if order is scrambled.
		results := make([]AccessResult, len(body.Checks))
		for i, c := range body.Checks {
			results[i] = AccessResult{Allowed: c.Action == "users:read" && i%2 == 0 || c.Action == "users:write" && i%2 == 1}
			if i == 0 {
				results[i] = AccessResult{Allowed: true}
			} else if i == 1 {
				results[i] = AccessResult{Allowed: false, Reason: "denied"}
			} else {
				results[i] = AccessResult{Allowed: true}
			}
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	reqs := []AccessCheck{
		{Action: "users:read", ResourceID: "r1"},
		{Action: "users:write", ResourceID: "r2"},
		{Action: "users:delete", ResourceID: "r3"},
	}
	results, err := client.BatchCheck(context.Background(), reqs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if !results[0].Allowed {
		t.Fatalf("expected results[0].Allowed=true (order preserved)")
	}
	if results[1].Allowed {
		t.Fatalf("expected results[1].Allowed=false (order preserved)")
	}
	if !results[2].Allowed {
		t.Fatalf("expected results[2].Allowed=true (order preserved)")
	}
}

// TestCheckAccess_MapsStatuses proves §2 status mapping is applied to the
// authz surface: 403 maps to AuthzError.
func TestCheckAccess_MapsStatuses(t *testing.T) {
	t.Run("200 returns AccessResult", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/authz/check" {
				t.Fatalf("unexpected path: %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"allowed": true})
		}))
		defer server.Close()

		client, err := NewClient(server.URL, "acme")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		allowed, reason, err := client.CheckAccess(context.Background(), "users:read", "r1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatalf("expected allowed=true")
		}
		if reason != "" {
			t.Fatalf("expected empty reason on allow, got %q", reason)
		}
	})

	t.Run("403 maps to AuthzError", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
		}))
		defer server.Close()

		client, err := NewClient(server.URL, "acme")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_, _, err = client.CheckAccess(context.Background(), "users:delete", "r1")
		if err == nil {
			t.Fatalf("expected an error on 403")
		}
		var authzErr *AuthzError
		v, ok := err.(*AuthzError)
		if ok {
			authzErr = v
		}
		if !ok {
			t.Fatalf("expected *AuthzError, got %T: %v", err, err)
		}
		_ = authzErr
	})

	t.Run("Can is an alias returning only the boolean", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"allowed": false, "reason": "no permission"})
		}))
		defer server.Close()

		client, err := NewClient(server.URL, "acme")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		allowed, err := client.Can(context.Background(), "users:delete", "r1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Fatalf("expected allowed=false")
		}
	})
}
