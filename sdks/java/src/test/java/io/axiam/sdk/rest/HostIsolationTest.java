package io.axiam.sdk.rest;

import io.axiam.sdk.internal.SessionState;

import org.junit.jupiter.api.Test;

import java.net.CookieManager;
import java.net.CookiePolicy;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Host-isolation guard (3A): {@link SessionState#isBaseHost} recognises only
 * the session's own origin host, so {@link AuthInterceptor} attaches the
 * tenant id, bearer token, and CSRF token exclusively to same-origin requests
 * — never to an absolute third-party URL or a followed cross-host redirect.
 */
class HostIsolationTest {

    private static SessionState session() {
        CookieManager cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        return new SessionState(cookieManager, "https://api.axiam.test", "acme-tenant", null, null);
    }

    @Test
    void recognisesOwnOriginHostCaseInsensitively() {
        SessionState session = session();
        assertTrue(session.isBaseHost("api.axiam.test"));
        assertTrue(session.isBaseHost("API.AXIAM.TEST"));
    }

    @Test
    void rejectsForeignAndNullHosts() {
        SessionState session = session();
        assertFalse(session.isBaseHost("evil.example"));
        assertFalse(session.isBaseHost("api.axiam.test.evil.example"));
        assertFalse(session.isBaseHost(null));
    }
}
