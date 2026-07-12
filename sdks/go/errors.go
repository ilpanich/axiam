package axiam

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

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

// safeResponseHeaders is the ALLOWLIST (X-3) of response headers preserved
// verbatim in a NetworkError's wrapped cause; every header NOT listed here has
// its value redacted to a placeholder, so a custom sensitive header (e.g.
// X-Auth-Token) can never survive into a thrown error — unlike a small
// denylist, which only catches the headers it happens to enumerate. Keys are
// lower-case and compared case-insensitively. Keep small and strictly
// non-secret: standard diagnostic response headers plus this SDK's own
// non-secret request headers (e.g. x-tenant-id).
var safeResponseHeaders = map[string]struct{}{
	"content-type":   {},
	"content-length": {},
	"date":           {},
	"server":         {},
	"retry-after":    {},
	"x-request-id":   {},
	"x-tenant-id":    {},
}

// redactedHeader is the placeholder substituted for the value of any
// non-allowlisted response header.
const redactedHeader = "[REDACTED]"

// sanitizeResponse returns a shallow copy of resp in which every header not on
// safeResponseHeaders has its value redacted to redactedHeader, WITHOUT
// mutating the caller's original *http.Response. Returns nil if resp is nil.
func sanitizeResponse(resp *http.Response) *http.Response {
	if resp == nil {
		return nil
	}
	clone := *resp
	clone.Header = resp.Header.Clone()
	for name := range clone.Header {
		if _, ok := safeResponseHeaders[strings.ToLower(name)]; !ok {
			clone.Header.Set(name, redactedHeader)
		}
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

// authzErrorBody is the shape of the server's structured authorization-denied
// error body, e.g.:
//
//	{"error":"authorization_denied","message":"...","action":"users:get","resource_id":"<uuid>"}
//
// `action` is present when the denied action is known; `resource_id` is
// present only for a resource-scoped denial (absent otherwise). We only ever
// read the two structured fields here — the body's own `message`/`error`
// keys are intentionally ignored (see readBodyForError's WR-01 redaction
// rationale in login.go): only Action/ResourceID are safe, bounded,
// non-free-text values to lift out of a server-controlled body.
type authzErrorBody struct {
	Action     string `json:"action"`
	ResourceID string `json:"resource_id"`
}

// parseAuthzFields best-effort decodes body (the raw, bounded HTTP error
// response body) as an authzErrorBody and returns its action/resource_id
// fields. Any decode failure (non-JSON body, unexpected shape, empty body)
// is swallowed and both results are "" — this is best-effort diagnostic
// enrichment of an AuthzError, never load-bearing, so a malformed or
// adversarial body must never surface as a decode error here.
func parseAuthzFields(body []byte) (action, resourceID string) {
	var parsed authzErrorBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", ""
	}
	return parsed.Action, parsed.ResourceID
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
//
// Unlike the HTTP path, a gRPC status carries no structured JSON body to
// parse action/resource_id out of, so the resulting AuthzError always leaves
// those fields "" (CONTRACT.md §2: they are SHOULD-carry-if-available, not
// MUST).
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
