package io.axiam.sdk.rest;

import io.axiam.sdk.internal.RefreshGuard;
import io.axiam.sdk.internal.SessionState;

import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.util.Set;

/**
 * Proactive (near-expiry) refresh + header injection (CONTRACT.md
 * &sect;3/&sect;5/&sect;9, D-08, RESEARCH.md Pattern 3). Registered as an
 * APPLICATION interceptor ({@code OkHttpClient.Builder.addInterceptor},
 * NOT {@code addNetworkInterceptor}) — application interceptors see the
 * logical request once, the correct layer for business-logic header
 * injection and proactive refresh.
 *
 * <p>Every request gets {@code X-Tenant-Id} (&sect;5); a bearer token is
 * added when one is cached; the stored CSRF token is echoed on
 * POST/PUT/PATCH/DELETE (&sect;3); a fresh {@code X-CSRF-Token} response
 * header is captured for the next request.
 *
 * <p>The proactive-refresh check performs a non-blocking cached-token read
 * ({@link SessionState#cachedAccessToken()}) — it never acquires
 * {@link RefreshGuard}'s lock synchronously on this hot path; refreshing
 * itself funnels through {@link RefreshGuard#refreshIfNeeded}, the SAME
 * guard {@link AuthAuthenticator}'s reactive 401 path uses (D-08).
 *
 * <p>The refresh call's own request path is special-cased (skipped) here:
 * {@link SessionState#doHttpRefresh()} sends its POST through this same
 * OkHttpClient, so without this guard a near-expiry access token observed
 * mid-refresh would recursively re-enter {@link RefreshGuard#refreshIfNeeded}
 * on the same thread and deadlock on its own in-flight future.
 */
public final class AuthInterceptor implements Interceptor {

    /** Proactive-refresh buffer — refresh once the access token is within this
     * many milliseconds of its {@code exp} claim. */
    private static final long NEAR_EXPIRY_BUFFER_MILLIS = 30_000;

    private static final Set<String> STATE_CHANGING_METHODS = Set.of("POST", "PUT", "PATCH", "DELETE");

    private final RefreshGuard guard;
    private final SessionState session;

    public AuthInterceptor(RefreshGuard guard, SessionState session) {
        this.guard = guard;
        this.session = session;
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request original = chain.request();
        boolean isRefreshCall = SessionState.isRefreshPath(original.url().encodedPath());

        // Non-blocking read — never session/guard.lock() synchronously here.
        String access = session.cachedAccessToken();
        if (!isRefreshCall && access != null && session.isNearExpiry(access, NEAR_EXPIRY_BUFFER_MILLIS)) {
            access = guard.refreshIfNeeded(access, session::doHttpRefresh).access();
        }

        Request.Builder builder = original.newBuilder()
                .header("X-Tenant-Id", session.tenantId());
        if (access != null) {
            builder.header("Authorization", "Bearer " + access);
        }
        String csrf = session.csrfToken();
        if (csrf != null && STATE_CHANGING_METHODS.contains(original.method())) {
            builder.header("X-CSRF-Token", csrf);
        }

        Response response = chain.proceed(builder.build());

        String newCsrf = response.header("X-CSRF-Token");
        if (newCsrf != null) {
            session.setCsrfToken(newCsrf);
        }
        return response;
    }
}
