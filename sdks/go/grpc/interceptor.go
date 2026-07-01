package grpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// TokenFunc is a non-blocking accessor for the currently cached access
// token, supplied by the caller (e.g. backed by
// internal/refreshguard.Guard.CachedAccessToken). ok is false when no token
// has been cached yet (caller has not logged in, or a refresh has not yet
// completed).
//
// This package intentionally does not import internal/refreshguard directly
// so it stays independently buildable without pulling in the REST client
// (RESEARCH.md D-05 / this plan's <action>) — the caller wires the closure.
type TokenFunc func() (token string, ok bool)

// authUnaryInterceptor injects "authorization: Bearer <token>" and
// "x-tenant-id: <tenantID>" metadata on every outgoing unary RPC
// (CONTRACT.md §5). tokenFn is read synchronously on every call and MUST be
// non-blocking — this closure runs on the hot RPC path and must NEVER
// acquire the async single-flight refresh mutex directly (RESEARCH.md
// Pitfall 3 / Anti-Patterns; mirrors sdks/rust/src/grpc/interceptor.rs).
func authUnaryInterceptor(tokenFn TokenFunc, tenantID string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if token, ok := tokenFn(); ok {
			ctx = metadata.AppendToOutgoingContext(ctx,
				"authorization", "Bearer "+token,
				"x-tenant-id", tenantID,
			)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
