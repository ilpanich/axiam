package io.axiam.sdk.rest;

import io.axiam.sdk.internal.RefreshGuard;
import io.axiam.sdk.internal.SessionState;
import io.axiam.sdk.internal.TokenPair;

import okhttp3.Authenticator;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;

import org.jspecify.annotations.Nullable;

/**
 * Reactive 401 fallback (CONTRACT.md &sect;9, D-08, RESEARCH.md Pattern 3).
 * Funnels into the SAME {@link RefreshGuard} instance {@link AuthInterceptor}
 * uses for proactive refresh — never a second guard.
 *
 * <p><strong>No retry loop (&sect;9.3):</strong> once two prior responses are
 * already recorded on the response chain (i.e. this would be a third
 * consecutive 401 for the same logical call), {@code null} is returned so
 * OkHttp gives up rather than retrying indefinitely. The refresh call's own
 * 401 is also never retried here — that response IS the terminal
 * {@code AuthError} the caller (via {@link SessionState#doHttpRefresh()})
 * surfaces.
 */
public final class AuthAuthenticator implements Authenticator {

    private final RefreshGuard guard;
    private final SessionState session;

    public AuthAuthenticator(RefreshGuard guard, SessionState session) {
        this.guard = guard;
        this.session = session;
    }

    @Override
    public @Nullable Request authenticate(@Nullable Route route, Response response) throws java.io.IOException {
        if (SessionState.isRefreshPath(response.request().url().encodedPath()) || responseCount(response) >= 2) {
            return null;
        }

        String staleAccess = session.cachedAccessToken();
        if (staleAccess == null) {
            return null; // never authenticated — nothing to refresh
        }

        TokenPair refreshed;
        try {
            refreshed = guard.refreshIfNeeded(staleAccess, session::doHttpRefresh);
        } catch (RuntimeException e) {
            // Refresh itself failed — surface the original 401, no retry (§9.3).
            return null;
        }

        return response.request().newBuilder()
                .header("Authorization", "Bearer " + refreshed.access())
                .build();
    }

    private static int responseCount(Response response) {
        int count = 1;
        Response prior = response.priorResponse();
        while (prior != null) {
            count++;
            prior = prior.priorResponse();
        }
        return count;
    }
}
