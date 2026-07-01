package axiam

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"

	"github.com/ilpanich/axiam/sdks/go/internal/refreshguard"
)

const (
	loginPath     = "/api/v1/auth/login"
	mfaVerifyPath = "/api/v1/auth/mfa/verify"
	refreshPath   = "/api/v1/auth/refresh"
	logoutPath    = "/api/v1/auth/logout"
	accessCookie  = "axiam_access"
	refreshCookie = "axiam_refresh"
)

// ---------------------------------------------------------------------------
// Wire request/response shapes (mirror crates/axiam-api-rest/src/handlers/
// auth.rs exactly — mirror only, no server dependency).
// ---------------------------------------------------------------------------

type loginRequestBody struct {
	TenantID        *uuid.UUID `json:"tenant_id,omitempty"`
	OrgID           *uuid.UUID `json:"org_id,omitempty"`
	TenantSlug      *string    `json:"tenant_slug,omitempty"`
	OrgSlug         *string    `json:"org_slug,omitempty"`
	UsernameOrEmail string     `json:"username_or_email"`
	Password        string     `json:"password"`
}

type mfaVerifyRequestBody struct {
	ChallengeToken string `json:"challenge_token"`
	TotpCode       string `json:"totp_code"`
}

type refreshRequestBody struct {
	TenantID uuid.UUID `json:"tenant_id"`
	OrgID    uuid.UUID `json:"org_id"`
}

type logoutRequestBody struct {
	SessionID uuid.UUID `json:"session_id"`
}

type loginSuccessResponseWire struct {
	SessionID uuid.UUID `json:"session_id"`
	ExpiresIn uint64    `json:"expires_in"`
}

type mfaRequiredResponseWire struct {
	ChallengeToken   string   `json:"challenge_token"`
	AvailableMethods []string `json:"available_methods"`
}

type refreshSuccessResponseWire struct {
	ExpiresIn uint64 `json:"expires_in"`
}

// ---------------------------------------------------------------------------
// Public result type — CONTRACT.md §1, CF-04 (discriminated login result)
// ---------------------------------------------------------------------------

// LoginResult is the outcome of Login/VerifyMfa (CF-04). MFA required is an
// expected outcome, not an error: check MFARequired before assuming the
// session is established.
type LoginResult struct {
	// MFARequired is true when the server responded with an MFA challenge
	// instead of a completed session; call VerifyMfa next with MFAToken.
	MFARequired bool
	// MFAToken carries the opaque challenge token when MFARequired is
	// true. Treated as sensitive (short-lived bearer of "logging in as
	// this user").
	MFAToken Sensitive
	// AvailableMethods lists MFA methods available to satisfy the
	// challenge (only populated when MFARequired is true).
	AvailableMethods []string
	// SessionID is the server-issued session id (only populated on a
	// completed, non-MFA-pending login/verify_mfa).
	SessionID string
	// ExpiresIn is the access token lifetime in seconds, as reported by
	// the server (only populated on a completed login/verify_mfa).
	ExpiresIn uint64
}

// ---------------------------------------------------------------------------
// Minimal unverified JWT claim decode (org_id resolution only)
// ---------------------------------------------------------------------------

// unverifiedClaims is the subset of access-token claims this plan needs to
// decode WITHOUT verifying the signature — signature verification is the
// middleware/JWKS concern of a later plan (per this task's <action>).
type unverifiedClaims struct {
	Sub      string `json:"sub"`
	TenantID string `json:"tenant_id"`
	OrgID    string `json:"org_id"`
	Jti      string `json:"jti"`
	Exp      int64  `json:"exp"`
}

// decodeUnverifiedClaims base64url-decodes a JWT's payload segment without
// verifying its signature (RESEARCH.md Pitfall 3 / this plan's <action>:
// "base64url JWT payload parse — do not verify signature here").
func decodeUnverifiedClaims(token string) (unverifiedClaims, error) {
	var claims unverifiedClaims
	parts := splitJWT(token)
	if len(parts) != 3 {
		return claims, fmt.Errorf("malformed JWT: expected 3 segments, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, fmt.Errorf("failed to decode JWT payload: %w", err)
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, fmt.Errorf("failed to parse JWT claims: %w", err)
	}
	return claims, nil
}

func splitJWT(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}

// ---------------------------------------------------------------------------
// Shared post-success handling: extract cookies, decode claims, cache state
// ---------------------------------------------------------------------------

// absorbSessionCookies reads the access/refresh tokens the server just set
// via Set-Cookie (already captured by the SDK's cookie jar), decodes the
// access token's org_id claim (RESEARCH.md Pitfall 3) and caches it, and
// seeds the refresh guard so a subsequent 401 has the correct observed
// baseline.
func (c *Client) absorbSessionCookies() error {
	access := c.cookieValue(accessCookie)
	if access == "" {
		return &AuthError{Message: "server response did not set the axiam_access cookie"}
	}
	refresh := c.cookieValue(refreshCookie)

	claims, err := decodeUnverifiedClaims(access)
	if err != nil {
		return &AuthError{Message: fmt.Sprintf("failed to decode access token claims: %v", err)}
	}

	if claims.OrgID != "" {
		if orgUUID, err := uuid.Parse(claims.OrgID); err == nil {
			c.setResolvedOrgID(orgUUID)
		}
	}

	c.guard.Seed(refreshguard.Sensitive(access), refreshguard.Sensitive(refresh), claims.Exp)
	return nil
}

// cookieValue reads a named cookie's value out of the SDK's cookie jar for
// the client's configured base URL.
func (c *Client) cookieValue(name string) string {
	for _, ck := range c.httpc.Jar.Cookies(c.baseURL) {
		if ck.Name == name {
			return ck.Value
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Public REST auth methods (CONTRACT.md §1, D-05 ctx-first)
// ---------------------------------------------------------------------------

// Login performs POST /api/v1/auth/login (CONTRACT.md §1). On success (no
// MFA), tokens are already present in the cookie jar and the org_id claim
// has been resolved+cached. When the server signals MFA is required,
// returns LoginResult{MFARequired: true, ...} — this is an expected
// outcome, not an error.
func (c *Client) Login(ctx context.Context, email, password string) (LoginResult, error) {
	body := c.buildLoginBody(email, password)
	payload, err := json.Marshal(body)
	if err != nil {
		return LoginResult{}, &NetworkError{Message: fmt.Sprintf("failed to encode login request: %v", err)}
	}

	req, err := c.newRequest(ctx, http.MethodPost, loginPath, bytes.NewReader(payload))
	if err != nil {
		return LoginResult{}, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return LoginResult{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var wire loginSuccessResponseWire
		if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
			return LoginResult{}, deserErr(err)
		}
		if err := c.absorbSessionCookies(); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{SessionID: wire.SessionID.String(), ExpiresIn: wire.ExpiresIn}, nil
	case http.StatusAccepted:
		var wire mfaRequiredResponseWire
		if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
			return LoginResult{}, deserErr(err)
		}
		return LoginResult{
			MFARequired:      true,
			MFAToken:         Sensitive(wire.ChallengeToken),
			AvailableMethods: wire.AvailableMethods,
		}, nil
	default:
		return LoginResult{}, mapErrorResponse(resp)
	}
}

// VerifyMfa performs POST /api/v1/auth/mfa/verify (CONTRACT.md §1),
// completing the two-phase flow started by Login when MFARequired was
// true.
func (c *Client) VerifyMfa(ctx context.Context, mfaToken Sensitive, code string) (LoginResult, error) {
	body := mfaVerifyRequestBody{
		ChallengeToken: mfaToken.expose(),
		TotpCode:       code,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return LoginResult{}, &NetworkError{Message: fmt.Sprintf("failed to encode verify_mfa request: %v", err)}
	}

	req, err := c.newRequest(ctx, http.MethodPost, mfaVerifyPath, bytes.NewReader(payload))
	if err != nil {
		return LoginResult{}, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return LoginResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return LoginResult{}, mapErrorResponse(resp)
	}

	var wire loginSuccessResponseWire
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return LoginResult{}, deserErr(err)
	}
	if err := c.absorbSessionCookies(); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{SessionID: wire.SessionID.String(), ExpiresIn: wire.ExpiresIn}, nil
}

// Refresh performs POST /api/v1/auth/refresh (CONTRACT.md §1), routed
// through the sync.Mutex single-flight guard (§9) so concurrent 401s share
// exactly one in-flight refresh call. A 401 on the refresh call itself is
// AuthError with no retry (§9.3).
func (c *Client) Refresh(ctx context.Context) error {
	observedAccess := c.cookieValue(accessCookie)
	if observedAccess == "" {
		return &AuthError{Message: "no access token to refresh — call Login() first"}
	}

	tenantID, ok := c.resolvedOrgTenantID()
	if !ok {
		return &AuthError{Message: "tenant_id could not be resolved; Login() must succeed before Refresh()"}
	}
	orgID, ok := c.resolvedOrgID()
	if !ok {
		return &AuthError{Message: "org_id could not be resolved; Login() must succeed before Refresh() — supply WithOrgID/WithOrgSlug or call Login() first"}
	}

	_, err := c.guard.RefreshIfNeeded(ctx, observedAccess, func(ctx context.Context) (refreshguard.RefreshedTokens, error) {
		body := refreshRequestBody{TenantID: tenantID, OrgID: orgID}
		payload, err := json.Marshal(body)
		if err != nil {
			return refreshguard.RefreshedTokens{}, &NetworkError{Message: fmt.Sprintf("failed to encode refresh request: %v", err)}
		}

		req, err := c.newRequest(ctx, http.MethodPost, refreshPath, bytes.NewReader(payload))
		if err != nil {
			return refreshguard.RefreshedTokens{}, err
		}

		resp, err := c.doRequest(req)
		if err != nil {
			return refreshguard.RefreshedTokens{}, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			// §9.3: 401 (or any non-200) on the refresh call itself is
			// propagated as-is — no retry loop.
			return refreshguard.RefreshedTokens{}, mapErrorResponse(resp)
		}

		var wire refreshSuccessResponseWire
		if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
			return refreshguard.RefreshedTokens{}, deserErr(err)
		}

		newAccess := c.cookieValue(accessCookie)
		if newAccess == "" {
			return refreshguard.RefreshedTokens{}, &AuthError{Message: "refresh response did not set axiam_access"}
		}
		newRefresh := c.cookieValue(refreshCookie)
		claims, err := decodeUnverifiedClaims(newAccess)
		if err != nil {
			return refreshguard.RefreshedTokens{}, &AuthError{Message: fmt.Sprintf("failed to decode refreshed access token claims: %v", err)}
		}
		return refreshguard.RefreshedTokens{
			Access:  refreshguard.Sensitive(newAccess),
			Refresh: refreshguard.Sensitive(newRefresh),
			Exp:     claims.Exp,
		}, nil
	})

	return err
}

// Logout performs POST /api/v1/auth/logout (CONTRACT.md §1) and clears
// in-memory token state.
func (c *Client) Logout(ctx context.Context) error {
	access := c.cookieValue(accessCookie)
	if access == "" {
		return &AuthError{Message: "no active session to log out"}
	}
	claims, err := decodeUnverifiedClaims(access)
	if err != nil {
		return &AuthError{Message: fmt.Sprintf("failed to decode access token claims: %v", err)}
	}
	sessionID, err := uuid.Parse(claims.Jti)
	if err != nil {
		return &AuthError{Message: "access token has no session id (jti) to log out"}
	}

	body := logoutRequestBody{SessionID: sessionID}
	payload, err := json.Marshal(body)
	if err != nil {
		return &NetworkError{Message: fmt.Sprintf("failed to encode logout request: %v", err)}
	}

	req, err := c.newRequest(ctx, http.MethodPost, logoutPath, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return mapErrorResponse(resp)
	}

	c.guard = &refreshguard.Guard{}
	return nil
}

func (c *Client) buildLoginBody(email, password string) loginRequestBody {
	body := loginRequestBody{
		TenantSlug:      strPtr(c.tenantSlug),
		UsernameOrEmail: email,
		Password:        password,
	}
	switch {
	case c.org.id != nil:
		body.OrgID = c.org.id
	case c.org.slug != "":
		body.OrgSlug = strPtr(c.org.slug)
	}
	return body
}

// resolvedOrgTenantID returns the tenant UUID to send in the Refresh body.
// The server's RefreshRequest requires a UUID (not a slug) — resolved from
// the access token's tenant_id claim after login, since the client may
// have been constructed with a tenant SLUG.
func (c *Client) resolvedOrgTenantID() (uuid.UUID, bool) {
	access := c.cookieValue(accessCookie)
	if access == "" {
		return uuid.UUID{}, false
	}
	claims, err := decodeUnverifiedClaims(access)
	if err != nil || claims.TenantID == "" {
		return uuid.UUID{}, false
	}
	id, err := uuid.Parse(claims.TenantID)
	if err != nil {
		return uuid.UUID{}, false
	}
	return id, true
}

func strPtr(s string) *string { return &s }

func deserErr(err error) error {
	return &NetworkError{Message: fmt.Sprintf("failed to parse response body: %v", err)}
}

// mapErrorResponse maps a non-2xx REST response to an error per
// CONTRACT.md §2, using the 18-01 status mappers. resp is consumed
// (Body read and discarded) but NOT closed here — callers close it via
// their own defer.
func mapErrorResponse(resp *http.Response) error {
	message := readBodyForError(resp.Body)
	return errorFromHTTPStatus(resp.StatusCode, message, resp, nil)
}

func readBodyForError(r io.Reader) string {
	b, err := io.ReadAll(io.LimitReader(r, 4096))
	if err != nil || len(b) == 0 {
		return "no response body"
	}
	return string(b)
}
