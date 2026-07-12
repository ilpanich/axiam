package middleware

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ilpanich/axiam/sdks/go/internal/jwks"
)

// csrfCookieName is the non-httpOnly cookie AXIAM's login flow sets
// alongside axiam_access specifically so same-site consumer apps can read it
// back for a cookie double-submit check (CONTRACT.md §3).
const csrfCookieName = "axiam_csrf"

// csrfHeaderName is the request header a same-site browser client is
// expected to echo the axiam_csrf cookie value into on state-changing
// requests (CONTRACT.md §3).
const csrfHeaderName = "X-CSRF-Token"

// safeMethods are exempt from the cookie double-submit CSRF check: they must
// not have side effects (RFC 9110 §9.2.1), so there is nothing for a
// cross-site forgery to change.
var safeMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
}

// jwksVerifier is the minimal interface this package needs from
// internal/jwks.Verifier (Plan 04) — kept as an interface so tests may
// substitute a fake without a live JWKS server, and so this package does not
// hard-depend on the concrete type's constructor signature.
type jwksVerifier interface {
	Verify(ctx context.Context, token []byte) (jwks.Claims, error)
}

// errorBody is the standardized JSON error body surfaced on 401/403
// (CONTRACT.md §10 closing requirement). It carries no raw token value.
type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// Middleware constructs a net/http middleware (CONTRACT.md §10, D-06) that:
//  1. Extracts the session from the `Authorization: Bearer <token>` header,
//     falling back to the `axiam_access` session cookie.
//  2. Verifies the token LOCALLY via the supplied Plan-04 JWKS verifier — no
//     per-request round-trip to the AXIAM server on a cache hit.
//  3. Enforces claims.tenant_id == configuredTenant BEFORE trusting the
//     token (cross-tenant replay defense — the JWKS is organization-wide,
//     not tenant-scoped, so signature validity alone is insufficient;
//     mirrors TS CR-03).
//  4. Injects the authenticated identity (user_id, tenant_id, roles) via
//     context.WithValue, retrievable by UserFromContext.
//  5. Surfaces AuthError -> HTTP 401 and AuthzError -> HTTP 403 with a
//     standardized JSON error body; the wrapped handler is never called on
//     failure.
//
// CSRF (cookie double-submit, CONTRACT.md §3): when the credential was
// sourced from the axiam_access COOKIE (not the Authorization header) and
// the request method is state-changing (anything other than GET/HEAD/
// OPTIONS), this middleware additionally requires the X-CSRF-Token request
// header to be present and equal, constant-time, to the axiam_csrf cookie
// value — rejecting with 403 on mismatch/absence. Bearer-header requests are
// CSRF-immune by construction (a cross-site attacker cannot set arbitrary
// request headers), but a cookie the browser attaches automatically is not:
// in any same-site deployment where axiam_access reaches this app, the
// non-httpOnly axiam_csrf cookie does too. This mirrors, locally, the same
// double-submit check the AXIAM server performs on its own endpoints (§3;
// see also the equivalent gate in the Java Spring filter,
// AxiamAuthenticationFilter#isCsrfValid).
//
// logger is optional (nil is safe) and, when supplied, MUST NOT be given a
// logger that would emit raw token values — this middleware never passes
// the token itself to the logger regardless.
func Middleware(verifier jwksVerifier, configuredTenant string, opts ...Option) func(http.Handler) http.Handler {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, fromCookie, err := extractToken(r)
			if err != nil {
				writeError(w, cfg, http.StatusUnauthorized, "authentication_failed", err.Error())
				return
			}

			// Cookie-sourced credentials aren't CSRF-immune the way a
			// Bearer header is: a cross-site form/fetch can't set custom
			// headers, but the browser attaches cookies automatically. Gate
			// state-changing requests behind the cookie double-submit check
			// BEFORE spending a JWKS verification on them.
			if fromCookie && !safeMethods[r.Method] && !isCsrfValid(r) {
				writeError(w, cfg, http.StatusForbidden, "csrf_validation_failed", "missing or invalid X-CSRF-Token for cookie-sourced credentials")
				return
			}

			claims, err := verifier.Verify(r.Context(), []byte(token))
			if err != nil {
				writeError(w, cfg, http.StatusUnauthorized, "authentication_failed", "invalid or expired token")
				return
			}

			// The Plan-04 verifier checks the signature only, not exp — the
			// middleware is the resource-server trust boundary, so it MUST
			// additionally reject a signature-valid but expired token (§10
			// "MUST NOT cache session verification results longer than the
			// token's remaining TTL" implies expired tokens are never
			// trusted).
			if claims.Exp != 0 && time.Now().Unix() >= claims.Exp {
				writeError(w, cfg, http.StatusUnauthorized, "authentication_failed", "invalid or expired token")
				return
			}

			// Cross-tenant replay defense (T-18-19, TS CR-03 carry-forward):
			// a signature-VALID token minted for the org-wide JWKS may
			// belong to a different tenant. Enforce the configured-tenant
			// claim check BEFORE trusting the token any further.
			if claims.TenantID == "" || claims.TenantID != configuredTenant {
				writeError(w, cfg, http.StatusUnauthorized, "authentication_failed", "token tenant_id does not match the configured tenant")
				return
			}

			// If the caller also supplied an X-Tenant-ID header, it must agree
			// with the token's own tenant_id claim — the header narrows which
			// tenant is being asserted for this request and can never
			// substitute for or override the claim (WR-04). Absent the header,
			// the claim check above is sufficient.
			if h := r.Header.Get("X-Tenant-ID"); h != "" && h != claims.TenantID {
				writeError(w, cfg, http.StatusUnauthorized, "authentication_failed", "X-Tenant-ID header does not match token tenant_id")
				return
			}

			user := &User{
				UserID:   claims.Subject,
				TenantID: claims.TenantID,
				Roles:    claims.Roles,
			}

			ctx := withUser(r.Context(), user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractToken reads the bearer token from the Authorization header,
// falling back to the axiam_access session cookie (CONTRACT.md §10.1). The
// returned bool reports whether the credential came from the cookie (as
// opposed to the header) — callers use it to decide whether the CSRF
// double-submit check applies (§3).
func extractToken(r *http.Request) (string, bool, error) {
	if header := r.Header.Get("Authorization"); header != "" {
		scheme, credentials, found := strings.Cut(strings.TrimSpace(header), " ")
		if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(credentials) == "" {
			return "", false, errMissingCredentials
		}
		return strings.TrimSpace(credentials), false, nil
	}

	if cookie, err := r.Cookie("axiam_access"); err == nil && cookie.Value != "" {
		return cookie.Value, true, nil
	}

	return "", false, errMissingCredentials
}

// isCsrfValid implements the cookie double-submit check (CONTRACT.md §3):
// the X-CSRF-Token request header must be present and equal, constant-time,
// to the axiam_csrf cookie value. Absence of either side fails closed.
func isCsrfValid(r *http.Request) bool {
	header := r.Header.Get(csrfHeaderName)
	if header == "" {
		return false
	}
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	// ConstantTimeCompare requires equal-length inputs to say anything about
	// content; a length mismatch is itself decisive (and safe to short
	// circuit on, since the lengths of a header/cookie pair aren't secret).
	if len(header) != len(cookie.Value) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(header), []byte(cookie.Value)) == 1
}

var errMissingCredentials = missingCredentialsError{}

// missingCredentialsError is a small sentinel-style error type; kept local
// (not the root package's AuthError) since this failure occurs before any
// verifier call and never carries a raw token value.
type missingCredentialsError struct{}

func (missingCredentialsError) Error() string { return "missing authentication credentials" }

// writeError writes the standardized JSON error body (CONTRACT.md §10) and
// status code. No raw token value is ever included.
func writeError(w http.ResponseWriter, cfg *config, status int, errCode, message string) {
	if cfg.logger != nil {
		cfg.logger.Warn("axiam middleware rejected request", slog.Int("status", status), slog.String("error", errCode))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: errCode, Message: message})
}

// config holds the middleware's optional settings (CF-02: injectable,
// redaction-aware logger, OFF by default).
type config struct {
	logger *slog.Logger
}

// Option configures optional Middleware behavior.
type Option func(*config)

// WithLogger sets an optional structured logger for rejected requests. The
// logger is never given a raw token value. Off by default (nil logger).
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}
