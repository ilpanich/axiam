package io.axiam.sdk.rest;

import io.axiam.sdk.internal.RefreshGuard;
import io.axiam.sdk.internal.SessionState;

import okhttp3.JavaNetCookieJar;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.net.CookieManager;
import java.net.CookiePolicy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Task 1 acceptance: CSRF round-trips (captured from a response header,
 * echoed on the next mutating request), {@code X-Tenant-Id} is present on
 * every request, GET never carries {@code X-CSRF-Token} (CONTRACT.md
 * &sect;3/&sect;5), and {@link AuthAuthenticator} gives up (returns
 * {@code null}) once two prior responses are already recorded (&sect;9.3 —
 * no retry loop).
 */
class CsrfInterceptorTest {

    @Test
    void csrfCapturedFromResponseAndEchoedOnlyOnMutatingRequests() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("X-CSRF-Token", "csrf-abc")
                    .setBody("{}"));
            server.enqueue(new MockResponse().setResponseCode(200).setBody("{}"));
            server.enqueue(new MockResponse().setResponseCode(200).setBody("{}"));
            server.start();

            String baseUrl = server.url("/").toString();
            CookieManager cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
            SessionState session = new SessionState(cookieManager, baseUrl, "acme-tenant", null, null);
            RefreshGuard guard = new RefreshGuard();

            OkHttpClient client = new OkHttpClient.Builder()
                    .cookieJar(new JavaNetCookieJar(cookieManager))
                    .addInterceptor(new AuthInterceptor(guard, session))
                    .build();
            session.attachHttpClient(client);

            // 1) First GET — no CSRF cached yet; the response carries one to capture.
            try (Response r = client.newCall(new Request.Builder().url(baseUrl + "api/v1/auth/me").get().build()).execute()) {
                assertEquals(200, r.code());
            }
            RecordedRequest req1 = server.takeRequest();
            assertEquals("acme-tenant", req1.getHeader("X-Tenant-Id"));
            assertNull(req1.getHeader("X-CSRF-Token"), "GET must never carry X-CSRF-Token");

            // 2) A subsequent POST echoes the captured CSRF token.
            RequestBody body = RequestBody.create("{}", MediaType.get("application/json"));
            try (Response r = client.newCall(new Request.Builder().url(baseUrl + "api/v1/authz/check").post(body).build()).execute()) {
                assertEquals(200, r.code());
            }
            RecordedRequest req2 = server.takeRequest();
            assertEquals("csrf-abc", req2.getHeader("X-CSRF-Token"));
            assertEquals("acme-tenant", req2.getHeader("X-Tenant-Id"));

            // 3) A further GET still omits the CSRF header despite one being cached.
            try (Response r = client.newCall(new Request.Builder().url(baseUrl + "api/v1/auth/me").get().build()).execute()) {
                assertEquals(200, r.code());
            }
            RecordedRequest req3 = server.takeRequest();
            assertNull(req3.getHeader("X-CSRF-Token"), "GET must never carry X-CSRF-Token even after capture");
        }
    }

    @Test
    void authenticatorReturnsNullAfterTwoPriorResponses() {
        RefreshGuard guard = new RefreshGuard();
        CookieManager cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        SessionState session = new SessionState(cookieManager, "https://api.axiam.test", "acme-tenant", null, null);
        AuthAuthenticator authenticator = new AuthAuthenticator(guard, session);

        Request original = new Request.Builder().url("https://api.axiam.test/api/v1/authz/check").get().build();
        Response first = new Response.Builder()
                .request(original).protocol(Protocol.HTTP_1_1).code(401).message("Unauthorized").build();
        Response second = new Response.Builder()
                .request(original).protocol(Protocol.HTTP_1_1).code(401).message("Unauthorized")
                .priorResponse(first).build();

        assertNull(assertDoesNotThrowAuthenticate(authenticator, second),
                "§9.3: no retry loop — must give up once 2 prior responses are already recorded");
    }

    private static Request assertDoesNotThrowAuthenticate(AuthAuthenticator authenticator, Response response) {
        try {
            return authenticator.authenticate(null, response);
        } catch (java.io.IOException e) {
            throw new AssertionError(e);
        }
    }
}
