package io.axiam.sdk;

import io.axiam.sdk.errors.AuthError;

import okhttp3.JavaNetCookieJar;
import okhttp3.OkHttpClient;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * SC#1: {@code AxiamClient.builder(baseUrl, tenantId)} is the ONLY
 * construction path — a blank {@code tenantId} is rejected and there is no
 * no-arg builder. D-27/SC#4: a supplied {@code OkHttpClient} is always
 * rebuilt with the SDK's own {@code CookieManager}-backed jar.
 */
class AxiamClientBuilderTest {

    @Test
    void blankTenantIdThrowsAuthError() {
        assertThrows(AuthError.class, () -> AxiamClient.builder("https://api.axiam.test", ""));
        assertThrows(AuthError.class, () -> AxiamClient.builder("https://api.axiam.test", "   "));
        assertThrows(AuthError.class, () -> AxiamClient.builder("https://api.axiam.test", null));
    }

    @Test
    void noNoArgBuilderFactoryExists() {
        boolean hasNoArgBuilder = Arrays.stream(AxiamClient.class.getDeclaredMethods())
                .anyMatch(m -> m.getName().equals("builder") && m.getParameterCount() == 0);
        assertFalse(hasNoArgBuilder, "AxiamClient must not expose a no-arg builder() factory (SC#1)");

        // The ONLY reachable construction path is the two-arg static factory
        // above — Builder itself must have no public constructor.
        for (Constructor<?> ctor : AxiamClient.Builder.class.getDeclaredConstructors()) {
            assertFalse(Modifier.isPublic(ctor.getModifiers()),
                    "AxiamClient.Builder must have no public constructor");
        }
    }

    @Test
    void suppliedHttpClientWithoutCookieJarStillGetsJavaNetCookieJarAfterBuild() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            OkHttpClient bareOverride = new OkHttpClient.Builder().build(); // no cookie jar configured

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme")
                    .httpClient(bareOverride)
                    .build()) {
                assertInstanceOf(JavaNetCookieJar.class, client.okHttpClient().cookieJar(),
                        "D-27: the SDK's own cookie jar must always be re-applied over a supplied client");
            }
        }
    }

    @Test
    void loginReturnsTypedLoginResult() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .addHeader("Set-Cookie", "axiam_access=" + fakeAccessToken() + "; Path=/; HttpOnly")
                    .addHeader("Set-Cookie", "axiam_refresh=fake-refresh-token; Path=/; HttpOnly")
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"user\":{\"id\":\"11111111-1111-1111-1111-111111111111\",\"username\":\"alice\",\"email\":\"alice@example.com\"},"
                            + "\"session_id\":\"22222222-2222-2222-2222-222222222222\",\"expires_in\":900}"));
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

    private static String fakeAccessToken() {
        String header = base64Url("{\"alg\":\"EdDSA\"}");
        String payload = base64Url("{\"sub\":\"11111111-1111-1111-1111-111111111111\","
                + "\"tenant_id\":\"33333333-3333-3333-3333-333333333333\","
                + "\"org_id\":\"44444444-4444-4444-4444-444444444444\","
                + "\"jti\":\"22222222-2222-2222-2222-222222222222\","
                + "\"exp\":" + (System.currentTimeMillis() / 1000 + 900) + "}");
        return header + "." + payload + ".fake-signature";
    }

    private static String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
