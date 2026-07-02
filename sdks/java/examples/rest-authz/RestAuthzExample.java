package io.axiam.sdk.examples.restauthz;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.AxiamClient.AccessCheck;
import io.axiam.sdk.AxiamClient.AccessResult;

import java.util.List;

/**
 * Demonstrates REST authorization checks (CONTRACT.md &sect;1): the
 * browser/UI-scenario alias {@link AxiamClient#can}, the single-check
 * {@link AxiamClient#checkAccess}, and the order-preserving
 * {@link AxiamClient#batchCheck}. Imports ONLY public SDK entry points.
 *
 * <p>Run: {@code AXIAM_BASE_URL=... AXIAM_TENANT_ID=... java RestAuthzExample.java}
 */
public final class RestAuthzExample {

    public static void main(String[] args) {
        String baseUrl = getenv("AXIAM_BASE_URL", "https://localhost:8443");
        String tenantId = getenv("AXIAM_TENANT_ID", "acme");
        String email = getenv("AXIAM_EMAIL", "user@example.com");
        String password = getenv("AXIAM_PASSWORD", "changeme");

        try (AxiamClient client = AxiamClient.builder(baseUrl, tenantId).build()) {
            // login() establishes the httpOnly session cookies every
            // subsequent authz call rides on (§4 cookie-jar requirement).
            client.login(email, password);

            // can(action, resourceId) — browser/UI-scenario alias for
            // checkAccess(...), returning a plain boolean.
            boolean allowed = client.can("read", "documents/123");
            System.out.println("can read documents/123: " + allowed);

            // checkAccess(action, resourceId, scope) — single evaluated
            // check with an optional sub-resource scope.
            AccessResult single = client.checkAccess("write", "documents/123", "draft");
            System.out.println("checkAccess write documents/123 (scope=draft): allowed="
                    + single.allowed() + " reason=" + single.reason());

            // batchCheck(checks) — results are returned in the SAME order
            // as the input list.
            List<AccessResult> batch = client.batchCheck(List.of(
                    new AccessCheck("read", "documents/123"),
                    new AccessCheck("delete", "documents/123")));
            for (int i = 0; i < batch.size(); i++) {
                AccessResult result = batch.get(i);
                System.out.println("batchCheck[" + i + "]: allowed=" + result.allowed()
                        + " reason=" + result.reason());
            }
        }
    }

    private static String getenv(String key, String fallback) {
        String v = System.getenv(key);
        return (v == null || v.isBlank()) ? fallback : v;
    }

    private RestAuthzExample() {
    }
}
