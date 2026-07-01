// Package grpc implements the gRPC transport for AuthorizationService
// (CheckAccess/BatchCheckAccess) with strict TLS and a sync-safe auth/tenant
// interceptor (sdks/CONTRACT.md §5/§6, SC#3).
package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"google.golang.org/grpc/credentials"
)

// newTLSCredentials builds strict TLS transport credentials (TLS 1.3
// minimum, per CLAUDE.md's project-wide TLS floor). When customCAPEM is
// non-empty, it is added to the certificate verification pool; an invalid
// PEM returns an error. Certificate verification is never disabled in this
// function — this is the ONLY TLS-related escape hatch the SDK
// exposes (CONTRACT.md §6, SC#3 absolute prohibition).
func newTLSCredentials(customCAPEM []byte) (credentials.TransportCredentials, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}

	if len(customCAPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(customCAPEM) {
			return nil, fmt.Errorf("grpc: invalid custom CA PEM")
		}
		tlsConfig.RootCAs = pool
	}

	return credentials.NewTLS(tlsConfig), nil
}

// NewTLSCredentials is the exported entry point for constructing this
// package's strict TLS transport credentials (§6) — the credentials.
// TransportCredentials value NewGRPCClient requires as its second argument.
// It is a thin, behavior-identical wrapper over newTLSCredentials: TLS 1.3
// minimum, no verification bypass, customCAPEM is the sole optional escape
// hatch for a development CA (mirrors WithCustomCA on the root REST
// Client).
func NewTLSCredentials(customCAPEM []byte) (credentials.TransportCredentials, error) {
	return newTLSCredentials(customCAPEM)
}
