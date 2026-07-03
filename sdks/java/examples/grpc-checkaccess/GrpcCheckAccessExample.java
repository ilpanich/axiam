package io.axiam.sdk.examples.grpccheckaccess;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.grpc.GrpcAuthzClient;
import io.axiam.sdk.grpc.GrpcAuthzClient.AccessCheck;
import io.axiam.sdk.grpc.GrpcAuthzClient.AccessResult;

import java.util.List;

/**
 * Demonstrates gRPC authorization checks (CONTRACT.md &sect;1) via
 * {@link GrpcAuthzClient#checkAccess} and {@link GrpcAuthzClient#batchCheck}.
 * Imports ONLY public SDK entry points ({@code io.axiam.sdk.AxiamClient} and
 * {@code io.axiam.sdk.grpc.GrpcAuthzClient} — never {@code io.axiam.sdk.internal.*}).
 *
 * <p>{@link GrpcAuthzClient} shares the SAME {@link AxiamClient#refreshGuard()}
 * instance the REST transport uses (D-07/D-11 "one guard") — obtained from
 * the {@link AxiamClient} that performed {@link AxiamClient#login}, never a
 * second independently-constructed guard.
 *
 * <p>Run: {@code AXIAM_BASE_URL=... AXIAM_GRPC_TARGET=... AXIAM_TENANT_ID=... java GrpcCheckAccessExample.java}
 */
public final class GrpcCheckAccessExample {

    public static void main(String[] args) {
        String baseUrl = getenv("AXIAM_BASE_URL", "https://localhost:8443");
        String grpcTarget = getenv("AXIAM_GRPC_TARGET", "dns:///localhost:9443");
        String tenantId = getenv("AXIAM_TENANT_ID", "acme");
        String email = getenv("AXIAM_EMAIL", "user@example.com");
        String password = getenv("AXIAM_PASSWORD", "changeme");

        try (AxiamClient client = AxiamClient.builder(baseUrl, tenantId).build()) {
            // REST login() establishes the session both transports share —
            // the gRPC client below reuses this same client's guard/session.
            client.login(email, password);

            try (GrpcAuthzClient grpcAuthz = new GrpcAuthzClient(
                    grpcTarget, client.refreshGuard(), client.session(), client.customCa())) {

                AccessResult single = grpcAuthz.checkAccess("read", "documents/123");
                System.out.println("checkAccess read documents/123: allowed=" + single.allowed()
                        + " reason=" + single.reason());

                List<AccessResult> batch = grpcAuthz.batchCheck(List.of(
                        new AccessCheck("read", "documents/123"),
                        new AccessCheck("delete", "documents/123")));
                for (int i = 0; i < batch.size(); i++) {
                    AccessResult result = batch.get(i);
                    System.out.println("batchCheck[" + i + "]: allowed=" + result.allowed()
                            + " reason=" + result.reason());
                }
            }
        }
    }

    private static String getenv(String key, String fallback) {
        String v = System.getenv(key);
        return (v == null || v.isBlank()) ? fallback : v;
    }

    private GrpcCheckAccessExample() {
    }
}
