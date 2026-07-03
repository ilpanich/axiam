package io.axiam.sdk.rest;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.errors.AuthzError;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * checkAccess/can/batchCheck over FND-04 REST (CONTRACT.md &sect;1, &sect;2):
 * checkAccess/can hit {@code /api/v1/authz/check}, batchCheck hits
 * {@code /api/v1/authz/check/batch} and preserves input order, and non-2xx
 * responses route through the central {@code ErrorMapper} (403 -&gt;
 * {@link AuthzError}).
 */
class AuthzTest {

    @Test
    void checkAccessAllowedTrue() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                    .setBody("{\"allowed\":true}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                AxiamClient.AccessResult result = client.checkAccess("users:get", "11111111-1111-1111-1111-111111111111");
                assertTrue(result.allowed());

                RecordedRequest recorded = server.takeRequest();
                assertEquals("/api/v1/authz/check", recorded.getPath());
            }
        }
    }

    @Test
    void checkAccessDeniedYieldsReason() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                    .setBody("{\"allowed\":false,\"reason\":\"missing permission users:get\"}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                AxiamClient.AccessResult result = client.checkAccess("users:get", "11111111-1111-1111-1111-111111111111");
                assertFalse(result.allowed());
                assertEquals("missing permission users:get", result.reason());
            }
        }
    }

    @Test
    void forbiddenResponseMapsToAuthzError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            // Retry only fires on NetworkError, so a single 403 enqueue is sufficient.
            server.enqueue(new MockResponse().setResponseCode(403).setBody("forbidden"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                assertThrows(AuthzError.class,
                        () -> client.checkAccess("users:delete", "11111111-1111-1111-1111-111111111111"));
            }
        }
    }

    @Test
    void batchCheckReturnsResultsInOrder() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                    .setBody("{\"results\":[{\"allowed\":true},{\"allowed\":false,\"reason\":\"no\"},{\"allowed\":true}]}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                List<AxiamClient.AccessResult> results = client.batchCheck(List.of(
                        new AxiamClient.AccessCheck("users:get", "11111111-1111-1111-1111-111111111111"),
                        new AxiamClient.AccessCheck("users:delete", "22222222-2222-2222-2222-222222222222"),
                        new AxiamClient.AccessCheck("users:list", "33333333-3333-3333-3333-333333333333")));

                assertEquals(3, results.size());
                assertTrue(results.get(0).allowed());
                assertFalse(results.get(1).allowed());
                assertEquals("no", results.get(1).reason());
                assertTrue(results.get(2).allowed());

                RecordedRequest recorded = server.takeRequest();
                assertEquals("/api/v1/authz/check/batch", recorded.getPath());
            }
        }
    }

    @Test
    void canIsAliasForCheckAccessAllowed() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                    .setBody("{\"allowed\":true}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                assertTrue(client.can("users:get", "11111111-1111-1111-1111-111111111111"));
            }
        }
    }
}
