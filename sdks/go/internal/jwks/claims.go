// Package jwks implements local JWKS fetch/cache/verification via
// lestrrat-go/jwx/v3 (D-06/§10), the shared local-verify primitive consumed
// by the net/http middleware (Plan 05) and any proactive-refresh check.
package jwks

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Claims is the SDK's plain claims struct, matching the field names AXIAM
// issues in its access tokens (mirrors sdks/rust/src/token/jwks.rs::Claims —
// mirror only, no server dependency).
type Claims struct {
	// Subject is the user ID (UUID string) — the token's "sub" claim.
	Subject string
	// TenantID is the tenant UUID string.
	TenantID string
	// OrgID is the organization UUID string.
	OrgID string
	// Roles is parsed from the space-separated "scope" claim — AXIAM's
	// AccessTokenClaims has no roles field server-side (mirrors Rust 16-05).
	Roles []string
	// Exp is the expiration (Unix timestamp).
	Exp int64
}

// rawClaims is the wire shape of the JWS payload this SDK decodes.
type rawClaims struct {
	Sub      string `json:"sub"`
	TenantID string `json:"tenant_id"`
	OrgID    string `json:"org_id"`
	Exp      int64  `json:"exp"`
	Scope    string `json:"scope"`
}

// parseClaims decodes a verified JWS payload into Claims, deriving Roles
// from the space-separated "scope" claim.
func parseClaims(payload []byte) (Claims, error) {
	var raw rawClaims
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Claims{}, fmt.Errorf("jwks: failed to parse claims: %w", err)
	}

	var roles []string
	if raw.Scope != "" {
		for _, r := range strings.Fields(raw.Scope) {
			roles = append(roles, r)
		}
	}

	return Claims{
		Subject:  raw.Sub,
		TenantID: raw.TenantID,
		OrgID:    raw.OrgID,
		Roles:    roles,
		Exp:      raw.Exp,
	}, nil
}
