package io.axiam.sdk.grpc;

import axiam.v1.Authorization.BatchCheckAccessRequest;
import axiam.v1.Authorization.BatchCheckAccessResponse;
import axiam.v1.Authorization.CheckAccessRequest;
import axiam.v1.Authorization.CheckAccessResponse;
import axiam.v1.AuthorizationServiceGrpc;
import axiam.v1.AuthorizationServiceGrpc.AuthorizationServiceBlockingStub;
import axiam.v1.AuthorizationServiceGrpc.AuthorizationServiceFutureStub;

import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.MoreExecutors;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.ErrorMapper;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.internal.RefreshGuard;
import io.axiam.sdk.internal.SessionState;

import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;

import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * gRPC authz transport (CONTRACT.md &sect;1/&sect;2/&sect;5/&sect;9, D-11).
 * Wraps ONE long-lived {@code ManagedChannel} (via
 * {@link AuthClientInterceptor#channelBuilder}, strict TLS + the
 * metadata-injecting interceptor), sharing both a blocking and a
 * {@code CompletableFuture}-adapted async ({@code ListenableFuture}-backed)
 * stub over that same channel.
 *
 * <p>Constructed from the SAME {@link RefreshGuard} + {@link SessionState}
 * {@code AxiamClient}'s REST transport uses (D-07/D-11's "one guard") — never
 * a second guard instance. On {@code UNAUTHENTICATED}, drives exactly one
 * {@link RefreshGuard#refreshIfNeeded} call then retries exactly once
 * (&sect;9.3); a terminal error routes through the central
 * {@link ErrorMapper#fromGrpcStatus}.
 *
 * <p>{@code tenant_id}/{@code subject_id} on the wire request are resolved
 * from the CURRENT access token's (unverified-decode) claims, not the raw
 * configured tenant identifier — the real server
 * ({@code axiam-api-grpc/src/services/authorization.rs}) cross-validates
 * both body fields against the verified JWT claims and rejects on any
 * mismatch (PERMISSION_DENIED), so a human-readable {@code tenantSlug}
 * would never pass that check.
 */
public final class GrpcAuthzClient implements AutoCloseable {

    private final RefreshGuard refreshGuard;
    private final SessionState session;
    private final ManagedChannel channel;
    private final AuthorizationServiceBlockingStub blockingStub;
    private final AuthorizationServiceFutureStub futureStub;

    /**
     * Creates a gRPC authz client bound to {@code target}, sharing the given refresh
     * guard and session with the SDK's REST transport.
     *
     * @param target       a plain gRPC target (e.g. {@code "dns:///host:9443"}) for
     *                      AXIAM's {@code AuthorizationService} — distinct from the
     *                      REST {@code baseUrl}
     * @param refreshGuard the SAME {@link RefreshGuard} instance the client's REST
     *                      transport uses (D-07) — never a second guard
     * @param session       the client's shared {@link SessionState} (tenant id,
     *                      cached access token, {@code doHttpRefresh()})
     * @param customCaPem   optional PEM-encoded custom CA (&sect;6) — {@code null}
     *                      to trust only the system trust store
     */
    public GrpcAuthzClient(String target, RefreshGuard refreshGuard, SessionState session,
                            byte @Nullable [] customCaPem) {
        this.refreshGuard = refreshGuard;
        this.session = session;

        NettyChannelBuilder channelBuilder = AuthClientInterceptor.channelBuilder(target, customCaPem)
                .intercept(new AuthClientInterceptor(() -> currentAccessToken(refreshGuard, session), session.tenantId()));
        this.channel = channelBuilder.build();
        this.blockingStub = AuthorizationServiceGrpc.newBlockingStub(channel);
        this.futureStub = AuthorizationServiceGrpc.newFutureStub(channel);
    }

    /**
     * Test-only seam: builds from an already-constructed {@link ManagedChannel} (e.g. an
     * in-process channel with its own {@link AuthClientInterceptor} attached by the caller),
     * bypassing the public constructor's strict-TLS Netty channel construction.
     * Package-private — only {@code GrpcAuthzClientTest} (same package) uses this.
     */
    GrpcAuthzClient(ManagedChannel channel, RefreshGuard refreshGuard, SessionState session) {
        this.refreshGuard = refreshGuard;
        this.session = session;
        this.channel = channel;
        this.blockingStub = AuthorizationServiceGrpc.newBlockingStub(channel);
        this.futureStub = AuthorizationServiceGrpc.newFutureStub(channel);
    }

    // ------------------------------------------------------------------
    // AutoCloseable (D-09) — the channel is shut down with the client.
    // ------------------------------------------------------------------

    @Override
    public void close() {
        channel.shutdown();
        try {
            if (!channel.awaitTermination(5, TimeUnit.SECONDS)) {
                channel.shutdownNow();
            }
        } catch (InterruptedException e) {
            channel.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    // ------------------------------------------------------------------
    // Public request/result shapes (CONTRACT.md §1)
    // ------------------------------------------------------------------

    /** The outcome of a single authorization check (mirrors {@code CheckAccessResponse}).
     *
     * @param allowed whether the checked action is permitted
     * @param reason  a human-readable deny reason, or {@code null} when {@code allowed}
     *                is {@code true} or the server did not supply one
     */
    public record AccessResult(boolean allowed, @Nullable String reason) {
    }

    /** A single access check request for {@link #batchCheck}. {@code subjectId} defaults to
     * the caller (the current access token's {@code sub} claim) when {@code null}.
     *
     * @param subjectId  the subject to check, or {@code null} to default to the caller
     *                   (the current access token's {@code sub} claim)
     * @param action     the action being checked (CONTRACT.md &sect;1)
     * @param resourceId the resource identifier the action is checked against
     * @param scope      an optional sub-resource scope qualifier, or {@code null}
     */
    public record AccessCheck(@Nullable String subjectId, String action, String resourceId,
                               @Nullable String scope) {
        /** Convenience constructor for a check on the caller's own subject, with no scope.
         *
         * @param action     the action being checked
         * @param resourceId the resource identifier the action is checked against
         */
        public AccessCheck(String action, String resourceId) {
            this(null, action, resourceId, null);
        }

        /** Convenience constructor for a check on the caller's own subject.
         *
         * @param action     the action being checked
         * @param resourceId the resource identifier the action is checked against
         * @param scope      an optional sub-resource scope qualifier, or {@code null}
         */
        public AccessCheck(String action, String resourceId, @Nullable String scope) {
            this(null, action, resourceId, scope);
        }
    }

    // ------------------------------------------------------------------
    // checkAccess (blocking + async)
    // ------------------------------------------------------------------

    /** {@link #checkAccess(String, String, String, String)} on the caller's own subject, with no scope.
     *
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @return the check outcome (allowed/denied, with an optional deny reason)
     */
    public AccessResult checkAccess(String action, String resourceId) {
        return checkAccess(null, action, resourceId, null);
    }

    /** {@link #checkAccess(String, String, String, String)} on the caller's own subject.
     *
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @param scope      an optional sub-resource scope qualifier, or {@code null}
     * @return the check outcome (allowed/denied, with an optional deny reason)
     */
    public AccessResult checkAccess(String action, String resourceId, @Nullable String scope) {
        return checkAccess(null, action, resourceId, scope);
    }

    /**
     * {@code CheckAccess} (CONTRACT.md &sect;1). On {@code UNAUTHENTICATED}, drives the shared
     * {@link RefreshGuard} exactly once and retries the RPC exactly once (&sect;9.3); a terminal
     * error maps via {@link ErrorMapper#fromGrpcStatus}.
     *
     * @param subjectId  the subject to check, or {@code null} to default to the caller
     *                   (the current access token's {@code sub} claim)
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @param scope      an optional sub-resource scope qualifier, or {@code null}
     * @return the check outcome (allowed/denied, with an optional deny reason)
     */
    public AccessResult checkAccess(@Nullable String subjectId, String action, String resourceId,
                                     @Nullable String scope) {
        CheckAccessRequest wire = toWire(subjectId, action, resourceId, scope);
        AuthorizationServiceBlockingStub stub = deadlinedBlockingStub(AuthClientInterceptor.CHECK_ACCESS_DEADLINE);
        return callWithRefreshRetry(() -> toAccessResult(stub.checkAccess(wire)));
    }

    /** {@link #checkAccessAsync(String, String, String, String)} on the caller's own subject, with no scope.
     *
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @return a future resolving to the check outcome
     */
    public CompletableFuture<AccessResult> checkAccessAsync(String action, String resourceId) {
        return checkAccessAsync(null, action, resourceId, null);
    }

    /** {@link #checkAccessAsync(String, String, String, String)} on the caller's own subject.
     *
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @param scope      an optional sub-resource scope qualifier, or {@code null}
     * @return a future resolving to the check outcome
     */
    public CompletableFuture<AccessResult> checkAccessAsync(String action, String resourceId, @Nullable String scope) {
        return checkAccessAsync(null, action, resourceId, scope);
    }

    /** {@code CompletableFuture} async twin of {@link #checkAccess}, adapting the
     * {@code ListenableFuture}-based future stub (D-02). Same shared-guard refresh-retry
     * semantics as the blocking path.
     *
     * @param subjectId  the subject to check, or {@code null} to default to the caller
     *                   (the current access token's {@code sub} claim)
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @param scope      an optional sub-resource scope qualifier, or {@code null}
     * @return a future resolving to the check outcome
     */
    public CompletableFuture<AccessResult> checkAccessAsync(@Nullable String subjectId, String action,
                                                              String resourceId, @Nullable String scope) {
        CheckAccessRequest wire = toWire(subjectId, action, resourceId, scope);
        AuthorizationServiceFutureStub stub = deadlinedFutureStub(AuthClientInterceptor.CHECK_ACCESS_DEADLINE);
        return callAsyncWithRefreshRetry(() -> stub.checkAccess(wire)).thenApply(GrpcAuthzClient::toAccessResult);
    }

    // ------------------------------------------------------------------
    // batchCheck (blocking + async) — results preserve input order
    // ------------------------------------------------------------------

    /**
     * {@code BatchCheckAccess} (CONTRACT.md &sect;1); results are returned in the same order as
     * {@code checks}. Shares the same UNAUTHENTICATED single-flight-retry behavior as
     * {@link #checkAccess}.
     *
     * @param checks the ordered list of checks to evaluate
     * @return the outcomes, in the same order as {@code checks}
     */
    public List<AccessResult> batchCheck(List<AccessCheck> checks) {
        BatchCheckAccessRequest wire = toWireBatch(checks);
        AuthorizationServiceBlockingStub stub = deadlinedBlockingStub(AuthClientInterceptor.BATCH_CHECK_ACCESS_DEADLINE);
        return callWithRefreshRetry(() -> toAccessResults(stub.batchCheckAccess(wire)));
    }

    /** {@code CompletableFuture} async twin of {@link #batchCheck}.
     *
     * @param checks the ordered list of checks to evaluate
     * @return a future resolving to the outcomes, in the same order as {@code checks}
     */
    public CompletableFuture<List<AccessResult>> batchCheckAsync(List<AccessCheck> checks) {
        BatchCheckAccessRequest wire = toWireBatch(checks);
        AuthorizationServiceFutureStub stub = deadlinedFutureStub(AuthClientInterceptor.BATCH_CHECK_ACCESS_DEADLINE);
        return callAsyncWithRefreshRetry(() -> stub.batchCheckAccess(wire)).thenApply(GrpcAuthzClient::toAccessResults);
    }

    // ------------------------------------------------------------------
    // Deadlines (D-12) — default per Task 1's constants, overridable at the
    // call site via the returned stub's own withDeadlineAfter.
    // ------------------------------------------------------------------

    private AuthorizationServiceBlockingStub deadlinedBlockingStub(java.time.Duration deadline) {
        return blockingStub.withDeadlineAfter(deadline.toMillis(), TimeUnit.MILLISECONDS);
    }

    private AuthorizationServiceFutureStub deadlinedFutureStub(java.time.Duration deadline) {
        return futureStub.withDeadlineAfter(deadline.toMillis(), TimeUnit.MILLISECONDS);
    }

    // ------------------------------------------------------------------
    // Shared-guard refresh-retry (§9.3: retry exactly once, never a loop)
    // ------------------------------------------------------------------

    private <T> T callWithRefreshRetry(Supplier<T> call) {
        try {
            return call.get();
        } catch (StatusRuntimeException e) {
            if (isUnauthenticated(e)) {
                doRefresh();
                try {
                    return call.get();
                } catch (StatusRuntimeException retryException) {
                    throw mapToRuntime(retryException);
                }
            }
            throw mapToRuntime(e);
        }
    }

    private <T> CompletableFuture<T> callAsyncWithRefreshRetry(Supplier<ListenableFuture<T>> call) {
        return toCompletableFuture(call.get())
                .handle((result, error) -> {
                    if (error == null) {
                        return CompletableFuture.completedFuture(result);
                    }
                    Throwable cause = unwrap(error);
                    if (isUnauthenticated(cause)) {
                        return CompletableFuture.runAsync(this::doRefresh)
                                .thenCompose(unused -> toCompletableFuture(call.get()))
                                .handle((retryResult, retryError) -> {
                                    if (retryError != null) {
                                        throw mapToRuntime(unwrap(retryError));
                                    }
                                    return retryResult;
                                });
                    }
                    CompletableFuture<T> failed = new CompletableFuture<>();
                    failed.completeExceptionally(mapToRuntime(cause));
                    return failed;
                })
                .thenCompose(Function.identity());
    }

    /** Drives the SAME {@link RefreshGuard} instance REST uses (D-07/D-11) — never a second
     * guard, mirroring {@code AxiamClient.refresh()}'s exact call shape. */
    private void doRefresh() {
        String observedAccess = currentAccessToken(refreshGuard, session);
        refreshGuard.refreshIfNeeded(observedAccess == null ? "" : observedAccess, session::doHttpRefresh);
    }

    /**
     * The token this transport currently considers "current": the shared
     * {@link RefreshGuard}'s cache when populated, falling back to the
     * {@link SessionState} cookie-jar-backed token otherwise. The guard's
     * cache is empty until the FIRST refresh ever happens on this client —
     * {@code AxiamClient.login()} only sets cookies, it never seeds the
     * guard — so a gRPC call made immediately after {@code login()} (before
     * any refresh) still needs the cookie-jar fallback, exactly like the
     * REST {@code AuthInterceptor}'s token source. Non-blocking: neither
     * read acquires {@link RefreshGuard}'s lock.
     */
    static @Nullable String currentAccessToken(RefreshGuard refreshGuard, SessionState session) {
        String cached = refreshGuard.cachedAccessToken();
        return cached != null ? cached : session.cachedAccessToken();
    }

    // ------------------------------------------------------------------
    // Wire mapping (proto/axiam/v1/authorization.proto)
    // ------------------------------------------------------------------

    private CheckAccessRequest toWire(@Nullable String subjectId, String action, String resourceId,
                                       @Nullable String scope) {
        SessionState.Claims claims = resolveClaims();
        String resolvedSubjectId = subjectId != null ? subjectId : requireClaim(claims.sub(), "sub");
        String resolvedTenantId = requireClaim(claims.tenantId(), "tenant_id");

        CheckAccessRequest.Builder builder = CheckAccessRequest.newBuilder()
                .setTenantId(resolvedTenantId)
                .setSubjectId(resolvedSubjectId)
                .setAction(action)
                .setResourceId(resourceId);
        if (scope != null) {
            builder.setScope(scope);
        }
        return builder.build();
    }

    private BatchCheckAccessRequest toWireBatch(List<AccessCheck> checks) {
        BatchCheckAccessRequest.Builder builder = BatchCheckAccessRequest.newBuilder();
        for (AccessCheck check : checks) {
            builder.addRequests(toWire(check.subjectId(), check.action(), check.resourceId(), check.scope()));
        }
        return builder.build();
    }

    private SessionState.Claims resolveClaims() {
        String access = currentAccessToken(refreshGuard, session);
        if (access == null) {
            throw new AuthError("no active session — call login() before checkAccess()/batchCheck()");
        }
        SessionState.Claims claims = SessionState.decodeUnverifiedClaims(access);
        if (claims == null) {
            throw new AuthError("failed to decode the current access token's claims");
        }
        return claims;
    }

    private static String requireClaim(@Nullable String value, String claimName) {
        if (value == null) {
            throw new AuthError("access token is missing the '" + claimName
                    + "' claim required for gRPC authz checks");
        }
        return value;
    }

    private static AccessResult toAccessResult(CheckAccessResponse resp) {
        String reason = resp.getDenyReason();
        return new AccessResult(resp.getAllowed(), reason.isEmpty() ? null : reason);
    }

    private static List<AccessResult> toAccessResults(BatchCheckAccessResponse resp) {
        List<AccessResult> results = new ArrayList<>();
        for (CheckAccessResponse item : resp.getResultsList()) {
            results.add(toAccessResult(item));
        }
        return results;
    }

    // ------------------------------------------------------------------
    // ListenableFuture -> CompletableFuture adaptation + error mapping (D-02, §2)
    // ------------------------------------------------------------------

    private static <T> CompletableFuture<T> toCompletableFuture(ListenableFuture<T> future) {
        CompletableFuture<T> completable = new CompletableFuture<>();
        Futures.addCallback(future, new FutureCallback<T>() {
            @Override
            public void onSuccess(T result) {
                completable.complete(result);
            }

            @Override
            public void onFailure(Throwable t) {
                completable.completeExceptionally(t);
            }
        }, MoreExecutors.directExecutor());
        return completable;
    }

    private static Throwable unwrap(Throwable t) {
        return (t instanceof CompletionException && t.getCause() != null) ? t.getCause() : t;
    }

    private static boolean isUnauthenticated(Throwable t) {
        return t instanceof StatusRuntimeException sre && sre.getStatus().getCode() == Status.Code.UNAUTHENTICATED;
    }

    /** Central status&rarr;error mapping (CONTRACT.md &sect;2) via {@link ErrorMapper#fromGrpcStatus} —
     * the single choke point for turning a terminal gRPC failure into the SDK's error taxonomy. */
    private static RuntimeException mapToRuntime(Throwable t) {
        if (t instanceof StatusRuntimeException sre) {
            String description = sre.getStatus().getDescription();
            return ErrorMapper.fromGrpcStatus(sre.getStatus().getCode(),
                    description != null ? description : sre.getStatus().getCode().name());
        }
        if (t instanceof RuntimeException re) {
            return re;
        }
        return new NetworkError("gRPC call failed: " + t.getMessage(), t);
    }
}
