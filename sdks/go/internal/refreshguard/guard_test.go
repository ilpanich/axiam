package refreshguard

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// TestRefreshGuard_SingleFlight fires 5 concurrent goroutines against the
// same observed (expired) access token and asserts doRefresh is invoked
// exactly once (CONTRACT.md §9, SC#2). Table-driven per plan requirement,
// even though the concurrency case is the only meaningful table entry today
// (leaves room to add more scenarios without restructuring).
func TestRefreshGuard_SingleFlight(t *testing.T) {
	tests := []struct {
		name       string
		goroutines int
	}{
		{name: "5 concurrent callers trigger exactly 1 refresh", goroutines: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &Guard{}
			var refreshCount int64
			const observed = "expired-access-token"

			doRefresh := func(ctx context.Context) (RefreshedTokens, error) {
				atomic.AddInt64(&refreshCount, 1)
				return RefreshedTokens{
					Access:  Sensitive("new-access-token"),
					Refresh: Sensitive("new-refresh-token"),
					Exp:     9999999999,
				}, nil
			}

			var wg sync.WaitGroup
			results := make([]Sensitive, tt.goroutines)
			errs := make([]error, tt.goroutines)
			for i := 0; i < tt.goroutines; i++ {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					access, err := g.RefreshIfNeeded(context.Background(), observed, doRefresh)
					results[idx] = access
					errs[idx] = err
				}(i)
			}
			wg.Wait()

			if got := atomic.LoadInt64(&refreshCount); got != 1 {
				t.Fatalf("expected exactly 1 refresh call across %d goroutines, got %d", tt.goroutines, got)
			}

			for i, err := range errs {
				if err != nil {
					t.Fatalf("goroutine %d: unexpected error: %v", i, err)
				}
				if results[i] != Sensitive("new-access-token") {
					t.Fatalf("goroutine %d: expected all callers to receive the new access token, got %q", i, results[i])
				}
			}
		})
	}
}

// TestRefreshGuard_DoubleCheck proves that a caller observing an
// ALREADY-superseded access token gets the cached (newer) token without
// invoking doRefresh again.
func TestRefreshGuard_DoubleCheck(t *testing.T) {
	g := &Guard{}
	var refreshCount int64

	doRefresh := func(ctx context.Context) (RefreshedTokens, error) {
		atomic.AddInt64(&refreshCount, 1)
		return RefreshedTokens{Access: Sensitive("token-v2"), Exp: 1}, nil
	}

	// First caller refreshes from "token-v1" (the initially observed token).
	access, err := g.RefreshIfNeeded(context.Background(), "token-v1", doRefresh)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if access != Sensitive("token-v2") {
		t.Fatalf("expected token-v2, got %q", access)
	}

	// A second caller who ALSO observed "token-v1" (stale) must get the
	// cached token-v2 WITHOUT triggering another refresh.
	access2, err := g.RefreshIfNeeded(context.Background(), "token-v1", doRefresh)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if access2 != Sensitive("token-v2") {
		t.Fatalf("expected cached token-v2 on double-check, got %q", access2)
	}
	if got := atomic.LoadInt64(&refreshCount); got != 1 {
		t.Fatalf("expected exactly 1 refresh call (double-check should short-circuit), got %d", got)
	}
}

// TestRefreshGuard_NoRetryOnFailure proves a doRefresh error is propagated
// as-is with no retry loop (§9.3).
func TestRefreshGuard_NoRetryOnFailure(t *testing.T) {
	g := &Guard{}
	var callCount int64
	wantErr := errors.New("refresh failed: 401")

	doRefresh := func(ctx context.Context) (RefreshedTokens, error) {
		atomic.AddInt64(&callCount, 1)
		return RefreshedTokens{}, wantErr
	}

	_, err := g.RefreshIfNeeded(context.Background(), "expired", doRefresh)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected error to propagate as-is, got %v", err)
	}
	if got := atomic.LoadInt64(&callCount); got != 1 {
		t.Fatalf("expected exactly 1 call to doRefresh (no retry loop), got %d", got)
	}

	// A subsequent call with the SAME observed token should attempt again
	// (the guard does not cache failures), but still only once per call.
	_, err = g.RefreshIfNeeded(context.Background(), "expired", doRefresh)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected error to propagate as-is on second attempt, got %v", err)
	}
	if got := atomic.LoadInt64(&callCount); got != 2 {
		t.Fatalf("expected 2 total calls after 2 separate top-level invocations, got %d", got)
	}
}

// TestGuard_CachedAccessToken proves the non-blocking accessor used by the
// future gRPC interceptor reflects the most recently cached token.
func TestGuard_CachedAccessToken(t *testing.T) {
	g := &Guard{}
	if _, ok := g.CachedAccessToken(); ok {
		t.Fatalf("expected no cached token before any refresh")
	}

	doRefresh := func(ctx context.Context) (RefreshedTokens, error) {
		return RefreshedTokens{Access: Sensitive("cached-token"), Exp: 42}, nil
	}
	if _, err := g.RefreshIfNeeded(context.Background(), "old", doRefresh); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, ok := g.CachedAccessToken()
	if !ok {
		t.Fatalf("expected a cached token after refresh")
	}
	if token != Sensitive("cached-token") {
		t.Fatalf("expected cached-token, got %q", token)
	}
}
