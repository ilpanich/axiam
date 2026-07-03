/**
 * Internal, transport-independent verification/concurrency primitives shared
 * by the REST (§4/§9), gRPC (§9/§11), and Spring Security (§10) layers.
 *
 * <p>{@link io.axiam.sdk.internal.RefreshGuard} is the {@code ReentrantLock}
 * + {@code CompletableFuture}-in-{@code AtomicReference} single-flight
 * refresh primitive (D-07, CONTRACT.md &sect;9) — exactly one instance is
 * constructed per {@code AxiamClient} and shared by every transport (D-07's
 * "one guard" requirement).
 *
 * <p>{@link io.axiam.sdk.internal.JwksVerifier} is the nimbus
 * {@code RemoteJWKSet}-backed, EdDSA-pinned local JWT verifier (D-19) with
 * the mandatory cross-tenant claim-check helper.
 *
 * <p>{@link io.axiam.sdk.internal.Retry} is the hand-rolled bounded
 * exponential-backoff-with-jitter helper for idempotent operations only
 * (D-26).
 *
 * <p>Types in this package are NOT part of the SDK's public API surface —
 * nothing here is imported by SDK consumers directly.
 */
@NullMarked
package io.axiam.sdk.internal;

import org.jspecify.annotations.NullMarked;
