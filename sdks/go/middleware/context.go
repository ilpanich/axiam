// Package middleware implements the net/http middleware / route-guard
// interface (CONTRACT.md §10, D-06). It runs inside the CONSUMER's own Go
// process, wrapping their handlers — not the AXIAM server.
package middleware

import "context"

// User is the authenticated identity injected into the request context on a
// successful verification (CONTRACT.md §10 closing requirement: "at minimum
// user_id, tenant_id, roles").
type User struct {
	UserID   string
	TenantID string
	Roles    []string
}

// contextKey is an unexported type so this package's context key can never
// collide with a key defined by another package (standard Go context-key
// idiom).
type contextKey struct{}

// userContextKey is the single key this package uses to store/retrieve the
// authenticated *User.
var userContextKey = contextKey{}

// UserFromContext retrieves the authenticated identity injected by
// Middleware, if present. ok is false when no identity was injected (e.g.
// the request never passed through the middleware, or the caller is
// inspecting a context that predates injection).
func UserFromContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userContextKey).(*User)
	return u, ok
}

// withUser returns a copy of ctx carrying user, retrievable via
// UserFromContext.
func withUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}
