# axiam SDK (Go)

Official Go client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended Identity and Authorization Management.

## Package identity

- **Go module:** `github.com/ilpanich/axiam/sdks/go`
- **Version tags:** `sdks/go/vX.Y.Z` (monorepo subdir tagging convention, D-13)
- **License:** Apache-2.0

## Contract conformance

This SDK conforms to CONTRACT.md §1-§10.

See [`../CONTRACT.md`](../CONTRACT.md) for the full cross-language behavioral contract.

## Status

Implemented (Phase 18). REST client (login/MFA/refresh/logout, authz
check/can/batch-check), gRPC client, AMQP consumer with HMAC verification,
local JWKS verification, and `net/http` middleware are all available. Five
runnable examples live under [`examples/`](./examples).

## Installation

```bash
go get github.com/ilpanich/axiam/sdks/go@sdks/go/vX.Y.Z
```

```go
import axiam "github.com/ilpanich/axiam/sdks/go"
```

## Usage

### Login + MFA (§1, §5)

```go
client, err := axiam.NewClient(baseURL, tenantSlug) // tenantSlug is required — no default tenant (§5)
if err != nil {
	// handle error
}

result, err := client.Login(ctx, email, password)
if err != nil {
	// handle error
}
if result.MFARequired {
	completed, err := client.VerifyMfa(ctx, result.MFAToken, totpCode)
	// ...
}
```

See [`examples/login-mfa`](./examples/login-mfa).

### REST authorization checks — CheckAccess / Can / BatchCheck (§1)

```go
allowed, reason, err := client.CheckAccess(ctx, "resource:read", resourceID)
canWrite, err := client.Can(ctx, "resource:write", resourceID)
results, err := client.BatchCheck(ctx, []axiam.AccessCheck{
	{Action: "resource:read", ResourceID: resourceID},
})
```

See [`examples/authz-check`](./examples/authz-check).

### gRPC authorization checks (§1, §5, §9)

```go
creds, err := axiamgrpc.NewTLSCredentials(nil) // strict TLS; pass a custom CA PEM for dev servers (§6)
conn, err := axiamgrpc.NewGRPCClient(target, creds, interceptor)
authzClient := axiamgrpc.NewAuthzClient(conn, refreshFn)

allowed, denyReason, err := authzClient.CheckAccess(ctx, axiamgrpc.CheckAccessRequest{
	TenantID: tenantID, SubjectID: subjectID, Action: "resource:read", ResourceID: resourceID,
})
```

See [`examples/grpc-checkaccess`](./examples/grpc-checkaccess).

### AMQP consumer with HMAC verification (§8)

```go
handler := func(ctx context.Context, event amqp.Event) error {
	// process event.Fields — hmac_signature has already been verified and removed
	return nil // Ack; return amqp.ErrDrop for a poison message (Nack, no requeue)
}
err := amqp.Consume(ctx, ch, queue, signingKey, handler)
```

See [`examples/amqp-consumer`](./examples/amqp-consumer).

### `net/http` middleware (§10)

```go
verifier, err := axiam.NewJWKSVerifier(ctx, baseURL, nil)
guarded := middleware.Middleware(verifier, tenantSlug)(mux)

// inside a handler:
user, ok := middleware.UserFromContext(r.Context())
```

See [`examples/middleware-guard`](./examples/middleware-guard).

## Versioning

Releases are tagged `sdks/go/vX.Y.Z` (monorepo subdir tagging convention,
D-13). A push of a tag matching this pattern triggers the module-publish CI
job; pull-request events never trigger publish.
