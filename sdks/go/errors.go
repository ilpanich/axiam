package axiam

import (
	"errors"
	"fmt"
	"net/http"

	"google.golang.org/grpc/codes"
)

// AuthError represents an authentication failure: wrong credentials, expired
// session, MFA failure, or a 401 on refresh (CONTRACT.md §2).
type AuthError struct {
	Message string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("authentication failed: %s", e.Message)
}

// Is reports whether target is the ErrAuth sentinel, enabling
// errors.Is(err, ErrAuth) to match any *AuthError.
func (e *AuthError) Is(target error) bool {
	return target == ErrAuth
}

// AuthzError represents an authorization failure: the caller is
// authenticated but lacks permission for the requested operation
// (CONTRACT.md §2). Action/ResourceID are optional and populated when known
// from the response body.
type AuthzError struct {
	Message    string
	Action     string
	ResourceID string
}

func (e *AuthzError) Error() string {
	return fmt.Sprintf("authorization denied: %s", e.Message)
}

// Is reports whether target is the ErrAuthz sentinel, enabling
// errors.Is(err, ErrAuthz) to match any *AuthzError.
func (e *AuthzError) Is(target error) bool {
	return target == ErrAuthz
}

// NetworkError represents a transport-level failure: connection refused,
// timeout, TLS error, DNS failure, or a server-side 5xx (CONTRACT.md §2).
//
// cause is unexported and MUST only ever be populated via newNetworkError,
// which redacts sensitive headers from any wrapped *http.Response BEFORE
// constructing the error (D-04, Phase 17 CR-04 carry-forward) — never
// construct a NetworkError directly from an unredacted *http.Response.
type NetworkError struct {
	Message string
	cause   error
}

func (e *NetworkError) Error() string {
	return fmt.Sprintf("network error: %s", e.Message)
}

// Unwrap exposes the underlying (already-redacted) cause for errors.Is/As
// and errors.Unwrap chains.
func (e *NetworkError) Unwrap() error {
	return e.cause
}

// Is reports whether target is the ErrNetwork sentinel, enabling
// errors.Is(err, ErrNetwork) to match any *NetworkError.
func (e *NetworkError) Is(target error) bool {
	return target == ErrNetwork
}

// Sentinel errors for errors.Is-based discrimination convenience
// (CONTRACT.md §2, D-04). These are never returned directly — only
// *AuthError/*AuthzError/*NetworkError instances are, each of which
// implements Is(target) to match the corresponding sentinel.
var (
	ErrAuth    = errors.New("axiam: authentication error")
	ErrAuthz   = errors.New("axiam: authorization error")
	ErrNetwork = errors.New("axiam: network error")
)

// sensitiveResponseHeaders lists response headers that must never survive
// into a NetworkError's wrapped cause (D-04, CR-04 carry-forward).
var sensitiveResponseHeaders = []string{"Set-Cookie", "Authorization", "Cookie"}

// sanitizeResponse returns a shallow copy of resp with Set-Cookie/
// Authorization/Cookie headers stripped, WITHOUT mutating the caller's
// original *http.Response. Returns nil if resp is nil.
func sanitizeResponse(resp *http.Response) *http.Response {
	if resp == nil {
		return nil
	}
	clone := *resp
	clone.Header = resp.Header.Clone()
	for _, h := range sensitiveResponseHeaders {
		clone.Header.Del(h)
	}
	return &clone
}

// newNetworkError constructs a *NetworkError. This is the SINGLE choke point
// for building a NetworkError from an *http.Response — it is the only
// caller-facing constructor that accepts a response, and it ALWAYS derives
// the wrapped cause from a sanitized (Set-Cookie/Authorization/Cookie
// stripped) copy of resp, never the raw response (D-04, Phase 17 CR-04
// carry-forward: redact BEFORE wrap, never after).
//
// resp may be nil (pure transport failure with no HTTP response, e.g. DNS/
// connection-refused/TLS handshake failure) — in that case cause is used
// as-is, since there is no response to redact. When resp is non-nil, any
// caller-supplied cause is IGNORED in favor of an error built from the
// sanitized response, so a caller cannot accidentally smuggle raw response
// data into cause by pre-building it from the unredacted resp before
// calling this constructor.
func newNetworkError(message string, resp *http.Response, cause error) *NetworkError {
	if resp != nil {
		sanitized := sanitizeResponse(resp)
		return &NetworkError{
			Message: message,
			cause:   fmt.Errorf("http status %d, headers: %v", sanitized.StatusCode, sanitized.Header),
		}
	}
	return &NetworkError{Message: message, cause: cause}
}

// errorFromHTTPStatus maps an HTTP status code to an AxiamError-family
// value per CONTRACT.md §2's HTTP status table:
//
//	400           -> NetworkError (malformed request / SDK programming error)
//	401           -> AuthError
//	403           -> AuthzError
//	408, 429      -> NetworkError (timeout / rate-limited)
//	409           -> AuthzError (resource-level conflict)
//	5xx           -> NetworkError
//	other         -> NetworkError
//
// message is caller-controlled and MUST NOT contain a raw token value. resp,
// if non-nil, is redacted before being wrapped into a NetworkError cause.
func errorFromHTTPStatus(status int, message string, resp *http.Response, cause error) error {
	switch {
	case status == 401:
		return &AuthError{Message: message}
	case status == 403 || status == 409:
		return &AuthzError{Message: message}
	default:
		return newNetworkError(message, resp, cause)
	}
}

// errorFromGRPCStatus maps a gRPC status code to an AxiamError-family value
// per CONTRACT.md §2's gRPC status table:
//
//	UNAUTHENTICATED (16)    -> AuthError
//	PERMISSION_DENIED (7)   -> AuthzError
//	UNAVAILABLE (14)        -> NetworkError
//	DEADLINE_EXCEEDED (4)   -> NetworkError
//	INTERNAL (13)           -> NetworkError
//	RESOURCE_EXHAUSTED (8)  -> NetworkError
//	other                   -> NetworkError
//
// message is caller-controlled and MUST NOT contain a raw token value.
func errorFromGRPCStatus(code int, message string) error {
	switch codes.Code(code) {
	case codes.Unauthenticated:
		return &AuthError{Message: message}
	case codes.PermissionDenied:
		return &AuthzError{Message: message}
	default:
		return newNetworkError(message, nil, nil)
	}
}

// Note on JSON safety: AuthError/AuthzError have no unexported/sensitive
// fields, so their default json.Marshal encoding is already safe.
// NetworkError's cause is unexported and thus never included in default
// json.Marshal output either (encoding/json only marshals exported fields),
// which is itself part of the redaction guarantee for D-04/CR-04.
