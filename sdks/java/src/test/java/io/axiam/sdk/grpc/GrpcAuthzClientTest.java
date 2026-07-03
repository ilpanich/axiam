package io.axiam.sdk.grpc;

import axiam.v1.Authorization.BatchCheckAccessRequest;
import axiam.v1.Authorization.BatchCheckAccessResponse;
import axiam.v1.Authorization.CheckAccessRequest;
import axiam.v1.Authorization.CheckAccessResponse;
import axiam.v1.AuthorizationServiceGrpc;

import io.axiam.sdk.errors.AuthzError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.internal.RefreshGuard;
import io.axiam.sdk.internal.SessionState;
import io.axiam.sdk.internal.TokenPair;

import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerInterceptors;
import io.grpc.Status;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;

import okhttp3.JavaNetCookieJar;
import okhttp3.OkHttpClient;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code GrpcAuthzClient}/{@code AuthClientInterceptor} acceptance (CONTRACT.md
 * &sect;1/&sect;2/&sect;5/&sect;9, D-11/D-12): allow/deny mapping, exactly-one
 * shared-guard refresh-and-retry-once on {@code UNAUTHENTICATED}, &sect;2 error
 * mapping, outgoing {@code authorization}/{@code x-tenant-id} metadata, and
 * batch-order preservation — all driven over an in-process gRPC server (no
 * live network dependency).
 */
class GrpcAuthzClientTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String ORG_ID = "44444444-4444-4444-4444-444444444444";
    private static final String SUBJECT_ID = "11111111-1111-1111-1111-111111111111";
    private static final String RESOURCE_ID = "22222222-2222-2222-2222-222222222222";

    private final List<Server> servers = new ArrayList<>();
    private final List<ManagedChannel> channels = new ArrayList<>();
    private MockWebServer restServer;

    @AfterEach
    void tearDown() throws Exception {
        for (ManagedChannel channel : channels) {
            channel.shutdownNow();
        }
        for (Server server : servers) {
            server.shutdownNow();
        }
        if (restServer != null) {
            restServer.close();
        }
    }

    @Test
    void checkAccessAllowedMapsToAllowedTrue() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession(newCookieManager(), null);
        seedValidToken(guard, 900);

        try (GrpcAuthzClient client = buildClient(FakeAuthorizationService.alwaysAllow(), guard, session, new CopyOnWriteArrayList<>())) {
            GrpcAuthzClient.AccessResult result = client.checkAccess("users:get", RESOURCE_ID);
            assertTrue(result.allowed());
        }
    }

    @Test
    void checkAccessDeniedYieldsReason() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession(newCookieManager(), null);
        seedValidToken(guard, 900);

        try (GrpcAuthzClient client = buildClient(FakeAuthorizationService.alwaysDeny("missing permission users:delete"),
                guard, session, new CopyOnWriteArrayList<>())) {
            GrpcAuthzClient.AccessResult result = client.checkAccess("users:delete", RESOURCE_ID);
            assertFalse(result.allowed());
            assertEquals("missing permission users:delete", result.reason());
        }
    }

    @Test
    void unauthenticatedThenSuccessTriggersExactlyOneSharedGuardRefreshAndOneRetry() throws Exception {
        restServer = startRestRefreshServer();
        RefreshGuard guard = new RefreshGuard();
        // Seed the SESSION's cookie jar (not the guard) with a soon-to-expire token via a REAL
        // HTTP response — the guard starts empty, mirroring the real gap between
        // AxiamClient.login() (sets cookies only) and the first-ever refresh (which is what
        // populates the guard's cache). A manually-inserted CookieStore entry (bypassing an
        // actual response round-trip) leaves a stale duplicate that java.net.CookieManager never
        // replaces on the later refresh response — seeding via a real response, exactly like
        // login() does in production, is required for correct replace-on-refresh semantics.
        SessionState session = newSessionSeededByLoginResponse(restServer);
        String staleToken = session.cachedAccessToken();
        assertNotNull(staleToken);
        long requestsBeforeCheckAccess = restServer.getRequestCount();

        FakeAuthorizationService service = FakeAuthorizationService.unauthenticatedOnceThenAllow();
        try (GrpcAuthzClient client = buildClient(service, guard, session, new CopyOnWriteArrayList<>())) {
            GrpcAuthzClient.AccessResult result = client.checkAccess("users:get", RESOURCE_ID);

            assertTrue(result.allowed());
            assertEquals(2, service.callCount(), "expected the RPC to be attempted exactly twice (fail once, retry once)");
            assertEquals(1, restServer.getRequestCount() - requestsBeforeCheckAccess,
                    "expected exactly one refresh POST across the retry (§9.3)");
            assertNotNull(guard.cachedAccessToken(), "the shared RefreshGuard must now hold the refreshed token");
            assertNotEquals(staleToken, guard.cachedAccessToken(), "the guard's cache must reflect the NEW token, not the stale one");
        }
    }

    @Test
    void permissionDeniedMapsToAuthzErrorAndUnavailableMapsToNetworkError() throws Exception {
        RefreshGuard guard1 = new RefreshGuard();
        SessionState session1 = newSession(newCookieManager(), null);
        seedValidToken(guard1, 900);
        try (GrpcAuthzClient client = buildClient(
                FakeAuthorizationService.terminalError(Status.PERMISSION_DENIED.withDescription("no permission")),
                guard1, session1, new CopyOnWriteArrayList<>())) {
            assertThrows(AuthzError.class, () -> client.checkAccess("users:get", RESOURCE_ID));
        }

        RefreshGuard guard2 = new RefreshGuard();
        SessionState session2 = newSession(newCookieManager(), null);
        seedValidToken(guard2, 900);
        try (GrpcAuthzClient client = buildClient(
                FakeAuthorizationService.terminalError(Status.UNAVAILABLE.withDescription("server unreachable")),
                guard2, session2, new CopyOnWriteArrayList<>())) {
            assertThrows(NetworkError.class, () -> client.checkAccess("users:get", RESOURCE_ID));
        }
    }

    @Test
    void outgoingMetadataCarriesAuthorizationAndTenantId() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession(newCookieManager(), null);
        String token = seedValidToken(guard, 900);

        List<Metadata> captured = new CopyOnWriteArrayList<>();
        try (GrpcAuthzClient client = buildClient(FakeAuthorizationService.alwaysAllow(), guard, session, captured)) {
            client.checkAccess(SUBJECT_ID, "users:get", RESOURCE_ID, null);
        }

        assertEquals(1, captured.size());
        Metadata headers = captured.get(0);
        Metadata.Key<String> tenantKey = Metadata.Key.of("x-tenant-id", Metadata.ASCII_STRING_MARSHALLER);
        Metadata.Key<String> authKey = Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
        assertEquals(TENANT_ID, headers.get(tenantKey));
        assertEquals("Bearer " + token, headers.get(authKey));
    }

    @Test
    void batchCheckReturnsResultsInInputOrder() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession(newCookieManager(), null);
        seedValidToken(guard, 900);

        try (GrpcAuthzClient client = buildClient(FakeAuthorizationService.batchInOrder(), guard, session, new CopyOnWriteArrayList<>())) {
            List<GrpcAuthzClient.AccessResult> results = client.batchCheck(List.of(
                    new GrpcAuthzClient.AccessCheck(SUBJECT_ID, "users:get", RESOURCE_ID, null),
                    new GrpcAuthzClient.AccessCheck(SUBJECT_ID, "users:delete", RESOURCE_ID, null),
                    new GrpcAuthzClient.AccessCheck(SUBJECT_ID, "users:list", RESOURCE_ID, null)));

            assertEquals(3, results.size());
            assertTrue(results.get(0).allowed());
            assertFalse(results.get(1).allowed());
            assertEquals("no", results.get(1).reason());
            assertTrue(results.get(2).allowed());
        }
    }

    // ------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------

    private GrpcAuthzClient buildClient(AuthorizationServiceGrpc.AuthorizationServiceImplBase service,
                                         RefreshGuard guard, SessionState session,
                                         List<Metadata> capturedMetadata) throws Exception {
        String serverName = InProcessServerBuilder.generateName();
        ServerInterceptor captureInterceptor = new ServerInterceptor() {
            @Override
            public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
                    ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
                capturedMetadata.add(headers);
                return next.startCall(call, headers);
            }
        };
        Server server = InProcessServerBuilder.forName(serverName)
                .directExecutor()
                .addService(ServerInterceptors.intercept(service, captureInterceptor))
                .build()
                .start();
        servers.add(server);

        // Same seam GrpcAuthzClient's public constructor wires internally (guard-then-session
        // fallback) — built here explicitly since this test bypasses that constructor to swap in
        // an in-process channel instead of a real strict-TLS Netty one.
        ManagedChannel channel = InProcessChannelBuilder.forName(serverName)
                .directExecutor()
                .intercept(new AuthClientInterceptor(() -> GrpcAuthzClient.currentAccessToken(guard, session), session.tenantId()))
                .build();
        channels.add(channel);

        return new GrpcAuthzClient(channel, guard, session);
    }

    private static CookieManager newCookieManager() {
        return new CookieManager(null, CookiePolicy.ACCEPT_ALL);
    }

    private static SessionState newSession(CookieManager cookieManager, @org.jspecify.annotations.Nullable MockWebServer restServer) {
        String baseUrl = restServer != null ? restServer.url("/").toString() : "http://localhost:0";
        SessionState session = new SessionState(cookieManager, baseUrl, TENANT_ID, null, UUID.fromString(ORG_ID));
        session.attachHttpClient(new OkHttpClient.Builder().cookieJar(new JavaNetCookieJar(cookieManager)).build());
        return session;
    }

    /** Seeds the shared {@link RefreshGuard}'s cache directly (as if a refresh already
     * happened) with a well-formed fake access token, returning the raw token string. */
    private static String seedValidToken(RefreshGuard guard, long expiresInSeconds) {
        String token = fakeAccessToken(SUBJECT_ID, TENANT_ID, ORG_ID, expiresInSeconds);
        guard.refreshIfNeeded("", () -> new TokenPair(token, "seed-refresh-token",
                System.currentTimeMillis() + expiresInSeconds * 1000));
        return token;
    }

    private static MockWebServer startRestRefreshServer() throws Exception {
        MockWebServer server = new MockWebServer();
        // "login" response — consumed by newSessionSeededByLoginResponse to seed a stale token
        // via a REAL Set-Cookie round-trip (see Deviations).
        server.enqueue(new MockResponse()
                .setResponseCode(200)
                .addHeader("Set-Cookie", "axiam_access=" + fakeAccessToken(SUBJECT_ID, TENANT_ID, ORG_ID, 60) + "; Path=/; HttpOnly")
                .setHeader("Content-Type", "application/json")
                .setBody("{}"));
        // "refresh" response — consumed by GrpcAuthzClient's UNAUTHENTICATED-triggered doRefresh().
        server.enqueue(new MockResponse()
                .setResponseCode(200)
                .addHeader("Set-Cookie", "axiam_access=" + fakeAccessToken(SUBJECT_ID, TENANT_ID, ORG_ID, 900) + "; Path=/; HttpOnly")
                .addHeader("Set-Cookie", "axiam_refresh=new-refresh-token; Path=/; HttpOnly")
                .setHeader("Content-Type", "application/json")
                .setBody("{\"expires_in\":900}"));
        server.start();
        return server;
    }

    /** Builds a {@link SessionState} whose cookie jar's stale access token was seeded via a
     * REAL HTTP response round-trip (consuming {@code startRestRefreshServer}'s first enqueued
     * response) rather than a manual {@code CookieStore.add} — required for
     * {@code java.net.CookieManager} to correctly replace it on the subsequent refresh response. */
    private static SessionState newSessionSeededByLoginResponse(MockWebServer restServer) throws Exception {
        CookieManager cookieManager = newCookieManager();
        OkHttpClient httpClient = new OkHttpClient.Builder().cookieJar(new JavaNetCookieJar(cookieManager)).build();
        SessionState session = new SessionState(cookieManager, restServer.url("/").toString(), TENANT_ID, null,
                UUID.fromString(ORG_ID));
        session.attachHttpClient(httpClient);

        try (okhttp3.Response ignored = httpClient.newCall(new okhttp3.Request.Builder()
                .url(restServer.url("/fake-login")).get().build()).execute()) {
            // discard — this call's only purpose is to trigger the CookieJar's saveFromResponse.
        }
        return session;
    }

    private static String fakeAccessToken(String sub, String tenantId, String orgId, long expiresInSeconds) {
        String header = base64Url("{\"alg\":\"EdDSA\"}");
        String payload = base64Url("{\"sub\":\"" + sub + "\",\"tenant_id\":\"" + tenantId + "\",\"org_id\":\"" + orgId
                + "\",\"jti\":\"22222222-2222-2222-2222-222222222222\",\"exp\":"
                + (System.currentTimeMillis() / 1000 + expiresInSeconds) + "}");
        return header + "." + payload + ".fake-signature";
    }

    private static String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    /** Configurable fake {@code AuthorizationService} implementation. */
    private static final class FakeAuthorizationService extends AuthorizationServiceGrpc.AuthorizationServiceImplBase {
        private final AtomicInteger callCount = new AtomicInteger(0);
        private final Function<Integer, StreamObserverAction> checkAccessBehavior;
        private final Function<BatchCheckAccessRequest, BatchCheckAccessResponse> batchBehavior;

        private FakeAuthorizationService(Function<Integer, StreamObserverAction> checkAccessBehavior,
                                          Function<BatchCheckAccessRequest, BatchCheckAccessResponse> batchBehavior) {
            this.checkAccessBehavior = checkAccessBehavior;
            this.batchBehavior = batchBehavior;
        }

        int callCount() {
            return callCount.get();
        }

        @Override
        public void checkAccess(CheckAccessRequest request, StreamObserver<CheckAccessResponse> responseObserver) {
            int attempt = callCount.incrementAndGet();
            checkAccessBehavior.apply(attempt).run(responseObserver);
        }

        @Override
        public void batchCheckAccess(BatchCheckAccessRequest request, StreamObserver<BatchCheckAccessResponse> responseObserver) {
            responseObserver.onNext(batchBehavior.apply(request));
            responseObserver.onCompleted();
        }

        static FakeAuthorizationService alwaysAllow() {
            return new FakeAuthorizationService(
                    attempt -> obs -> {
                        obs.onNext(CheckAccessResponse.newBuilder().setAllowed(true).build());
                        obs.onCompleted();
                    },
                    req -> BatchCheckAccessResponse.getDefaultInstance());
        }

        static FakeAuthorizationService alwaysDeny(String reason) {
            return new FakeAuthorizationService(
                    attempt -> obs -> {
                        obs.onNext(CheckAccessResponse.newBuilder().setAllowed(false).setDenyReason(reason).build());
                        obs.onCompleted();
                    },
                    req -> BatchCheckAccessResponse.getDefaultInstance());
        }

        static FakeAuthorizationService unauthenticatedOnceThenAllow() {
            return new FakeAuthorizationService(
                    attempt -> obs -> {
                        if (attempt == 1) {
                            obs.onError(Status.UNAUTHENTICATED.withDescription("expired token").asRuntimeException());
                        } else {
                            obs.onNext(CheckAccessResponse.newBuilder().setAllowed(true).build());
                            obs.onCompleted();
                        }
                    },
                    req -> BatchCheckAccessResponse.getDefaultInstance());
        }

        static FakeAuthorizationService terminalError(Status status) {
            return new FakeAuthorizationService(
                    attempt -> obs -> obs.onError(status.asRuntimeException()),
                    req -> BatchCheckAccessResponse.getDefaultInstance());
        }

        static FakeAuthorizationService batchInOrder() {
            return new FakeAuthorizationService(
                    attempt -> obs -> {
                        obs.onNext(CheckAccessResponse.newBuilder().setAllowed(true).build());
                        obs.onCompleted();
                    },
                    req -> {
                        BatchCheckAccessResponse.Builder builder = BatchCheckAccessResponse.newBuilder();
                        List<CheckAccessRequest> requests = req.getRequestsList();
                        for (int i = 0; i < requests.size(); i++) {
                            String action = requests.get(i).getAction();
                            boolean allowed = !"users:delete".equals(action);
                            CheckAccessResponse.Builder resp = CheckAccessResponse.newBuilder().setAllowed(allowed);
                            if (!allowed) {
                                resp.setDenyReason("no");
                            }
                            builder.addResults(resp.build());
                        }
                        return builder.build();
                    });
        }

        @FunctionalInterface
        private interface StreamObserverAction {
            void run(StreamObserver<CheckAccessResponse> observer);
        }
    }
}
