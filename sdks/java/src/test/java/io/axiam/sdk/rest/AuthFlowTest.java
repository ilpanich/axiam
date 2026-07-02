package io.axiam.sdk.rest;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.LoginResult;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code AxiamClient} auth-flow acceptance (CONTRACT.md &sect;1): a login
 * returning the MFA challenge yields {@code mfaRequired() == true}; a plain
 * login yields {@code false} plus a populated user; {@code refresh()} posts
 * to {@code /api/v1/auth/refresh} with the resolved {@code org_id}/
 * {@code tenant_id} (RESEARCH.md Pitfall 2).
 */
class AuthFlowTest {

    @Test
    void loginReturningMfaChallengeYieldsMfaRequiredTrue() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse()
                    .setResponseCode(202)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"mfa_required\":true,\"challenge_token\":\"chal-abc\",\"available_methods\":[\"totp\"]}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme")
                    .orgSlug("acme-org")
                    .build()) {
                LoginResult result = client.login("alice@example.com", "wrong-ish-password");

                assertTrue(result.mfaRequired());
                assertNotNull(result.challengeToken());
            }
        }
    }

    @Test
    void plainLoginYieldsMfaRequiredFalseWithPopulatedUser() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(loginSuccessResponse());
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme")
                    .orgSlug("acme-org")
                    .build()) {
                LoginResult result = client.login("alice@example.com", "correct horse battery staple");

                assertFalse(result.mfaRequired());
                assertNotNull(result.user());
                assertEquals("11111111-1111-1111-1111-111111111111", result.user().userId());
            }
        }
    }

    @Test
    void refreshIncludesOrgIdAndTenantIdInBody() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(loginSuccessResponse());
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .addHeader("Set-Cookie", "axiam_access=" + fakeAccessToken(900) + "; Path=/; HttpOnly")
                    .addHeader("Set-Cookie", "axiam_refresh=fake-refresh-token-2; Path=/; HttpOnly")
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"expires_in\":900}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme")
                    .orgSlug("acme-org")
                    .build()) {
                client.login("alice@example.com", "correct horse battery staple");
                server.takeRequest(); // consume the login request

                client.refresh();

                RecordedRequest refreshRequest = server.takeRequest();
                assertEquals("/api/v1/auth/refresh", refreshRequest.getPath());
                String body = refreshRequest.getBody().readUtf8();
                assertTrue(body.contains("\"org_id\":\"44444444-4444-4444-4444-444444444444\""),
                        "refresh body must include the resolved org_id (Pitfall 2)");
                assertTrue(body.contains("\"tenant_id\":\"33333333-3333-3333-3333-333333333333\""),
                        "refresh body must include the resolved tenant_id");
            }
        }
    }

    private static MockResponse loginSuccessResponse() {
        return new MockResponse()
                .setResponseCode(200)
                .addHeader("Set-Cookie", "axiam_access=" + fakeAccessToken(900) + "; Path=/; HttpOnly")
                .addHeader("Set-Cookie", "axiam_refresh=fake-refresh-token; Path=/; HttpOnly")
                .setHeader("Content-Type", "application/json")
                .setBody("{\"user\":{\"id\":\"11111111-1111-1111-1111-111111111111\",\"username\":\"alice\",\"email\":\"alice@example.com\"},"
                        + "\"session_id\":\"22222222-2222-2222-2222-222222222222\",\"expires_in\":900}");
    }

    private static String fakeAccessToken(long expiresInSeconds) {
        String header = base64Url("{\"alg\":\"EdDSA\"}");
        String payload = base64Url("{\"sub\":\"11111111-1111-1111-1111-111111111111\","
                + "\"tenant_id\":\"33333333-3333-3333-3333-333333333333\","
                + "\"org_id\":\"44444444-4444-4444-4444-444444444444\","
                + "\"jti\":\"22222222-2222-2222-2222-222222222222\","
                + "\"exp\":" + (System.currentTimeMillis() / 1000 + expiresInSeconds) + "}");
        return header + "." + payload + ".fake-signature";
    }

    private static String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
