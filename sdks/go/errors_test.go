package axiam

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// TestNetworkError_RedactsSensitiveHeaders proves that a NetworkError built
// from an *http.Response carrying Set-Cookie/Authorization/Cookie headers
// never surfaces the raw token value through %v/%+v/%#v/json.Marshal of the
// resulting error (D-04, Phase 17 CR-04 carry-forward).
//
// A non-vacuous control case (constructing a NetworkError WITHOUT going
// through the redacting constructor) proves this test would fail without
// sanitizeResponse — i.e. the test is not accidentally vacuous.
func TestNetworkError_RedactsSensitiveHeaders(t *testing.T) {
	const rawToken = "axiam_access=REALTOKENVALUE12345"

	newResponseWithSensitiveHeaders := func() *http.Response {
		h := http.Header{}
		h.Set("Set-Cookie", rawToken)
		h.Set("Authorization", "Bearer "+rawToken)
		h.Set("Cookie", rawToken)
		h.Set("Content-Type", "application/json")
		return &http.Response{StatusCode: 500, Header: h}
	}

	t.Run("redacted via newNetworkError", func(t *testing.T) {
		resp := newResponseWithSensitiveHeaders()
		err := newNetworkError("server error", resp, nil)

		surfaces := map[string]string{
			"%v":      fmt.Sprintf("%v", err),
			"%+v":     fmt.Sprintf("%+v", err),
			"%#v":     fmt.Sprintf("%#v", err),
			"Error()": err.Error(),
			// Unwrap() is the actual leak surface: newNetworkError builds
			// cause from resp's headers, so this is where redaction must
			// take effect.
			"Unwrap()": fmt.Sprintf("%v", err.Unwrap()),
		}
		for name, out := range surfaces {
			if strings.Contains(out, rawToken) {
				t.Fatalf("%s leaked raw token: %q", name, out)
			}
		}

		b, jerr := json.Marshal(err)
		if jerr != nil {
			t.Fatalf("json.Marshal returned error: %v", jerr)
		}
		if strings.Contains(string(b), rawToken) {
			t.Fatalf("json.Marshal leaked raw token: %s", string(b))
		}

		// Verify the original caller's response was NOT mutated.
		if resp.Header.Get("Set-Cookie") != rawToken {
			t.Fatalf("caller's original response was mutated by newNetworkError")
		}
	})

	t.Run("non-vacuous control: unredacted wrapper DOES leak (proves test validity)", func(t *testing.T) {
		resp := newResponseWithSensitiveHeaders()
		// Deliberately bypass sanitizeResponse (skip newNetworkError, wrap the
		// raw *http.Response's headers directly into cause) to prove the
		// assertions above would catch a real leak if redaction were absent
		// — i.e. this test is not vacuously passing regardless of behavior.
		unredacted := &NetworkError{Message: "server error", cause: fmt.Errorf("headers: %v", resp.Header)}

		// The leak surface is the wrapped cause reachable via Unwrap()/%+v
		// of the cause chain — NetworkError.Error() itself intentionally
		// never includes the cause's text, so we inspect the cause directly,
		// exactly as errors.Unwrap(err) or %+v-with-cause formatting would.
		out := fmt.Sprintf("%v", unredacted.Unwrap())
		if !strings.Contains(out, rawToken) {
			t.Fatalf("control case did not leak as expected — test may be vacuous; got %q", out)
		}
	})
}

// TestNetworkError_RedactsCustomSensitiveHeader proves the X-3 allowlist
// redacts a custom sensitive header (X-Auth-Token) that a small denylist of
// {Set-Cookie, Authorization, Cookie} would NOT catch, while an allowlisted
// header (X-Request-Id) survives into the wrapped cause.
func TestNetworkError_RedactsCustomSensitiveHeader(t *testing.T) {
	const customSecret = "super-secret-custom-token"
	const safeValue = "req-abc-123"

	h := http.Header{}
	h.Set("X-Auth-Token", customSecret)
	h.Set("X-Request-Id", safeValue)
	resp := &http.Response{StatusCode: 500, Header: h}

	err := newNetworkError("server error", resp, nil)
	out := fmt.Sprintf("%v", err.Unwrap())

	if strings.Contains(out, customSecret) {
		t.Fatalf("custom sensitive header X-Auth-Token leaked: %q", out)
	}
	if !strings.Contains(out, safeValue) {
		t.Fatalf("allowlisted header X-Request-Id value must survive, got %q", out)
	}
	if !strings.Contains(out, redactedHeader) {
		t.Fatalf("expected redacted placeholder in output, got %q", out)
	}

	// Caller's original response must not be mutated.
	if resp.Header.Get("X-Auth-Token") != customSecret {
		t.Fatalf("caller's original response was mutated by newNetworkError")
	}
}

// TestErrors_As_Is verifies errors.As discriminates AuthError/AuthzError/
// NetworkError and errors.Is matches each sentinel.
func TestErrors_As_Is(t *testing.T) {
	t.Run("AuthError", func(t *testing.T) {
		var err error = &AuthError{Message: "bad credentials"}

		var target *AuthError
		if !errors.As(err, &target) {
			t.Fatalf("errors.As failed to discriminate *AuthError")
		}
		if !errors.Is(err, ErrAuth) {
			t.Fatalf("errors.Is(err, ErrAuth) = false, want true")
		}
		if errors.Is(err, ErrAuthz) {
			t.Fatalf("errors.Is(err, ErrAuthz) = true, want false")
		}
	})

	t.Run("AuthzError", func(t *testing.T) {
		var err error = &AuthzError{Message: "denied", Action: "read", ResourceID: "res-1"}

		var target *AuthzError
		if !errors.As(err, &target) {
			t.Fatalf("errors.As failed to discriminate *AuthzError")
		}
		if target.Action != "read" || target.ResourceID != "res-1" {
			t.Fatalf("AuthzError fields not preserved: %+v", target)
		}
		if !errors.Is(err, ErrAuthz) {
			t.Fatalf("errors.Is(err, ErrAuthz) = false, want true")
		}
		if errors.Is(err, ErrAuth) {
			t.Fatalf("errors.Is(err, ErrAuth) = true, want false")
		}
	})

	t.Run("NetworkError", func(t *testing.T) {
		cause := fmt.Errorf("connection refused")
		var err error = newNetworkError("transport failure", nil, cause)

		var target *NetworkError
		if !errors.As(err, &target) {
			t.Fatalf("errors.As failed to discriminate *NetworkError")
		}
		if !errors.Is(err, ErrNetwork) {
			t.Fatalf("errors.Is(err, ErrNetwork) = false, want true")
		}
		if !errors.Is(err, cause) {
			t.Fatalf("errors.Is(err, cause) = false, want true — Unwrap() must expose the cause")
		}
	})
}

// TestErrorFromHTTPStatus verifies the CONTRACT.md §2 HTTP status -> error
// type mapping table.
func TestErrorFromHTTPStatus(t *testing.T) {
	cases := []struct {
		status int
		want   string // "auth" | "authz" | "network"
	}{
		{400, "network"},
		{401, "auth"},
		{403, "authz"},
		{408, "network"},
		{409, "authz"},
		{429, "network"},
		{500, "network"},
		{502, "network"},
		{503, "network"},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("status_%d", tc.status), func(t *testing.T) {
			err := errorFromHTTPStatus(tc.status, "message", nil, nil)
			assertErrorKind(t, err, tc.want)
		})
	}
}

// TestErrorFromGRPCStatus verifies the CONTRACT.md §2 gRPC status -> error
// type mapping table.
func TestErrorFromGRPCStatus(t *testing.T) {
	const (
		codeDeadlineExceeded  = 4
		codePermissionDenied  = 7
		codeResourceExhausted = 8
		codeInternal          = 13
		codeUnavailable       = 14
		codeUnauthenticated   = 16
	)

	cases := []struct {
		name string
		code int
		want string
	}{
		{"UNAUTHENTICATED", codeUnauthenticated, "auth"},
		{"PERMISSION_DENIED", codePermissionDenied, "authz"},
		{"UNAVAILABLE", codeUnavailable, "network"},
		{"DEADLINE_EXCEEDED", codeDeadlineExceeded, "network"},
		{"INTERNAL", codeInternal, "network"},
		{"RESOURCE_EXHAUSTED", codeResourceExhausted, "network"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := errorFromGRPCStatus(tc.code, "message")
			assertErrorKind(t, err, tc.want)
		})
	}
}

func assertErrorKind(t *testing.T, err error, want string) {
	t.Helper()
	switch want {
	case "auth":
		var target *AuthError
		if !errors.As(err, &target) {
			t.Fatalf("expected *AuthError, got %T", err)
		}
	case "authz":
		var target *AuthzError
		if !errors.As(err, &target) {
			t.Fatalf("expected *AuthzError, got %T", err)
		}
	case "network":
		var target *NetworkError
		if !errors.As(err, &target) {
			t.Fatalf("expected *NetworkError, got %T", err)
		}
	default:
		t.Fatalf("unknown want kind %q", want)
	}
}
