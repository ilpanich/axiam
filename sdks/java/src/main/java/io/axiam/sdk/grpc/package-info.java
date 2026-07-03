/**
 * The AXIAM Java SDK's gRPC transport (CONTRACT.md &sect;1, &sect;2, &sect;5,
 * &sect;6, &sect;9, D-11/D-12). {@link io.axiam.sdk.grpc.GrpcAuthzClient} wraps
 * one long-lived, strict-TLS {@code ManagedChannel} shared by both the
 * blocking and {@code CompletableFuture}-adapted async stubs;
 * {@link io.axiam.sdk.grpc.AuthClientInterceptor} injects
 * {@code authorization}/{@code x-tenant-id} metadata via a non-blocking
 * token accessor and owns the strict-TLS channel-construction seam.
 *
 * <p>Both funnel {@code UNAUTHENTICATED} responses through the SAME
 * {@link io.axiam.sdk.internal.RefreshGuard} instance
 * {@link io.axiam.sdk.rest.AuthInterceptor}/{@link io.axiam.sdk.rest.AuthAuthenticator}
 * use (D-07) — never a second guard per transport.
 */
@NullMarked
package io.axiam.sdk.grpc;

import org.jspecify.annotations.NullMarked;
