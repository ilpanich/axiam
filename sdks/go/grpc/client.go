package grpc

import (
	"context"
	"fmt"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	axiam "github.com/ilpanich/axiam/sdks/go"
	axiamv1 "github.com/ilpanich/axiam/sdks/go/internal/gen/axiam/v1"
)

// NewGRPCClient constructs a *grpclib.ClientConn for target using creds and
// interceptor. It uses grpclib.NewClient (NOT the deprecated grpclib.Dial) —
// per grpc-go 1.63+, NewClient does not dial eagerly: connection errors
// (bad target, TLS handshake failure) surface on the first actual RPC call,
// not at construction time (RESEARCH.md Pitfall 5).
func NewGRPCClient(target string, creds credentials.TransportCredentials, interceptor grpclib.UnaryClientInterceptor) (*grpclib.ClientConn, error) {
	return grpclib.NewClient(target,
		grpclib.WithTransportCredentials(creds),
		grpclib.WithUnaryInterceptor(interceptor),
	)
}

// RefreshFunc performs the caller-owned single-flight refresh (§9) and
// returns once a fresh access token is cached. Supplied by the caller so
// this package never depends on the REST transport directly (RESEARCH.md
// D-05 / this plan's <action>).
type RefreshFunc func(ctx context.Context) error

// AuthzClient is a typed wrapper over the committed axiam.v1
// AuthorizationServiceClient stubs, exposing CheckAccess/BatchCheck
// (CONTRACT.md §1) with §2 gRPC status mapping and a single-flight-refresh
// retry on UNAUTHENTICATED.
type AuthzClient struct {
	inner   axiamv1.AuthorizationServiceClient
	refresh RefreshFunc
}

// NewAuthzClient wraps conn (built via NewGRPCClient, already carrying the
// auth/tenant interceptor) with the committed AuthorizationServiceClient
// stub. refresh drives the shared single-flight refresh (§9) on
// UNAUTHENTICATED; it may be nil, in which case UNAUTHENTICATED errors are
// returned immediately without a retry.
func NewAuthzClient(conn grpclib.ClientConnInterface, refresh RefreshFunc) *AuthzClient {
	return &AuthzClient{
		inner:   axiamv1.NewAuthorizationServiceClient(conn),
		refresh: refresh,
	}
}

// CheckAccessRequest is a single access check (CONTRACT.md §1), the gRPC
// analog of the REST authz-check request shape.
type CheckAccessRequest struct {
	TenantID   string
	SubjectID  string
	Action     string
	ResourceID string
	Scope      string
}

func (r CheckAccessRequest) toWire() *axiamv1.CheckAccessRequest {
	wire := &axiamv1.CheckAccessRequest{
		TenantId:   r.TenantID,
		SubjectId:  r.SubjectID,
		Action:     r.Action,
		ResourceId: r.ResourceID,
	}
	if r.Scope != "" {
		wire.Scope = &r.Scope
	}
	return wire
}

// CheckAccess evaluates a single authorization check (CONTRACT.md §1),
// returning (allowed, denyReason, error). On UNAUTHENTICATED, drives the
// caller-supplied single-flight refresh (§9) and retries exactly once —
// never a second time (§9.3).
func (c *AuthzClient) CheckAccess(ctx context.Context, req CheckAccessRequest) (bool, string, error) {
	wire := req.toWire()

	resp, err := c.inner.CheckAccess(ctx, wire)
	if err != nil {
		if c.refresh != nil && status.Code(err) == codes.Unauthenticated {
			if refreshErr := c.refresh(ctx); refreshErr != nil {
				return false, "", refreshErr
			}
			resp, err = c.inner.CheckAccess(ctx, wire)
		}
		if err != nil {
			return false, "", mapGRPCError(err)
		}
	}
	return resp.GetAllowed(), resp.GetDenyReason(), nil
}

// BatchCheck evaluates an ordered list of checks; results are returned in
// the same order as reqs (CONTRACT.md §1). Shares the same
// UNAUTHENTICATED single-flight-retry behavior as CheckAccess.
func (c *AuthzClient) BatchCheck(ctx context.Context, reqs []CheckAccessRequest) ([]CheckAccessResult, error) {
	wire := make([]*axiamv1.CheckAccessRequest, len(reqs))
	for i, r := range reqs {
		wire[i] = r.toWire()
	}
	batchReq := &axiamv1.BatchCheckAccessRequest{Requests: wire}

	resp, err := c.inner.BatchCheckAccess(ctx, batchReq)
	if err != nil {
		if c.refresh != nil && status.Code(err) == codes.Unauthenticated {
			if refreshErr := c.refresh(ctx); refreshErr != nil {
				return nil, refreshErr
			}
			resp, err = c.inner.BatchCheckAccess(ctx, batchReq)
		}
		if err != nil {
			return nil, mapGRPCError(err)
		}
	}

	results := make([]CheckAccessResult, len(resp.GetResults()))
	for i, r := range resp.GetResults() {
		results[i] = CheckAccessResult{Allowed: r.GetAllowed(), DenyReason: r.GetDenyReason()}
	}
	return results, nil
}

// CheckAccessResult is a single result within a BatchCheck response.
type CheckAccessResult struct {
	Allowed    bool
	DenyReason string
}

// mapGRPCError maps a terminal gRPC error to the CONTRACT.md §2 error
// taxonomy (AuthError/AuthzError/NetworkError) via the shared status-code
// table:
//
//	UNAUTHENTICATED (16)    -> AuthError
//	PERMISSION_DENIED (7)   -> AuthzError
//	UNAVAILABLE (14)        -> NetworkError
//	DEADLINE_EXCEEDED (4)   -> NetworkError
//	INTERNAL (13)           -> NetworkError
//	RESOURCE_EXHAUSTED (8)  -> NetworkError
//	other                   -> NetworkError
func mapGRPCError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return &axiam.NetworkError{Message: fmt.Sprintf("grpc: %v", err)}
	}
	switch st.Code() {
	case codes.Unauthenticated:
		return &axiam.AuthError{Message: st.Message()}
	case codes.PermissionDenied:
		return &axiam.AuthzError{Message: st.Message()}
	default:
		return &axiam.NetworkError{Message: fmt.Sprintf("grpc status %s: %s", st.Code(), st.Message())}
	}
}
