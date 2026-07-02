package io.axiam.sdk.internal;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.ErrorMapper;
import io.axiam.sdk.errors.NetworkError;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.URI;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Per-{@code AxiamClient} session/cookie/CSRF/tenant/org state (CONTRACT.md
 * &sect;3/&sect;4/&sect;5). Holds no access/refresh token cache of its own —
 * {@link #cachedAccessToken()} always reads the live {@code axiam_access}
 * cookie out of the shared {@link CookieManager}, which the SDK's
 * {@code OkHttpClient} (via {@code JavaNetCookieJar}) keeps in sync
 * automatically on every response. This mirrors {@code sdks/go}'s
 * {@code cookieValue()} helper and avoids a second, potentially-stale,
 * in-memory copy of the token.
 *
 * <p>{@link #doHttpRefresh()} is the {@code Supplier<TokenPair>} handed to
 * {@link RefreshGuard#refreshIfNeeded}: it performs the actual
 * {@code POST /api/v1/auth/refresh} call, whose body carries the resolved
 * {@code tenant_id}/{@code org_id} UUIDs (both non-optional per the real
 * handler, RESEARCH.md Pitfall 2) decoded, unverified, from the current
 * access token's claims. Signature verification remains
 * {@link JwksVerifier}'s exclusive responsibility elsewhere (resource-server/
 * Spring middleware use) — the decode here is only ever used as an
 * operational hint (tenant/org resolution, near-expiry check), never as an
 * authorization decision.
 */
public final class SessionState {

    private static final String ACCESS_COOKIE = "axiam_access";
    private static final String REFRESH_COOKIE = "axiam_refresh";

    /** The refresh endpoint path — special-cased by {@code AuthInterceptor}/
     * {@code AuthAuthenticator} so a refresh call can never recursively
     * trigger a nested refresh (this call itself runs through the same
     * OkHttpClient those two are registered on). */
    public static final String REFRESH_PATH = "/api/v1/auth/refresh";

    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final CookieManager cookieManager;
    private final URI baseUri;
    private final String baseUrl;
    private final String tenantId;
    private final @Nullable String configuredOrgSlug;
    private final @Nullable UUID configuredOrgId;

    private final AtomicReference<String> csrfToken = new AtomicReference<>();
    // Set once, right after AxiamClient finishes building its OkHttpClient —
    // this session's own HTTP calls (the refresh POST) run through that same
    // client so they pick up the shared cookie jar + tenant header injection.
    private final AtomicReference<OkHttpClient> httpClient = new AtomicReference<>();

    public SessionState(CookieManager cookieManager, String baseUrl, String tenantId,
                         @Nullable String configuredOrgSlug, @Nullable UUID configuredOrgId) {
        this.cookieManager = cookieManager;
        this.baseUrl = stripTrailingSlash(baseUrl);
        this.baseUri = URI.create(this.baseUrl);
        this.tenantId = tenantId;
        this.configuredOrgSlug = configuredOrgSlug;
        this.configuredOrgId = configuredOrgId;
    }

    /** Two-phase wiring: called once by {@code AxiamClient} right after it builds
     * the OkHttpClient this session's {@link #doHttpRefresh()} call is sent through. */
    public void attachHttpClient(OkHttpClient client) {
        httpClient.set(client);
    }

    public String tenantId() {
        return tenantId;
    }

    public String baseUrl() {
        return baseUrl;
    }

    public @Nullable String configuredOrgSlug() {
        return configuredOrgSlug;
    }

    public @Nullable UUID configuredOrgId() {
        return configuredOrgId;
    }

    public static boolean isRefreshPath(String encodedPath) {
        return REFRESH_PATH.equals(encodedPath);
    }

    public @Nullable String csrfToken() {
        return csrfToken.get();
    }

    /** Captures a freshly-observed {@code X-CSRF-Token} response header value (&sect;3). */
    public void setCsrfToken(String token) {
        csrfToken.set(token);
    }

    /**
     * Non-blocking read of the current access token, sourced from the shared
     * cookie jar — never acquires {@link RefreshGuard}'s lock. Safe to call
     * from the {@code AuthInterceptor}/{@code AuthAuthenticator} hot path.
     */
    public @Nullable String cachedAccessToken() {
        return cookieValue(ACCESS_COOKIE);
    }

    /**
     * Local, unverified {@code exp}-claim check (no network round trip) —
     * used ONLY as a proactive-refresh hint by {@code AuthInterceptor}. The
     * interceptor hot path must never block on a full, signature-verifying
     * JWKS fetch ({@link JwksVerifier#verify}).
     */
    public boolean isNearExpiry(String accessToken, long bufferMillis) {
        Claims claims = decodeUnverifiedClaims(accessToken);
        if (claims == null || claims.exp() <= 0) {
            return false;
        }
        return System.currentTimeMillis() >= (claims.exp() * 1000L) - bufferMillis;
    }

    /** Resets locally-cached derived state after logout. The cookie jar itself
     * is cleared by the server's clear-cookie {@code Set-Cookie} response
     * headers, captured automatically by the shared {@link CookieManager}. */
    public void clear() {
        csrfToken.set(null);
    }

    private @Nullable String cookieValue(String name) {
        List<HttpCookie> cookies = cookieManager.getCookieStore().get(baseUri);
        for (HttpCookie cookie : cookies) {
            if (cookie.getName().equals(name)) {
                return cookie.getValue();
            }
        }
        return null;
    }

    /**
     * Performs {@code POST /api/v1/auth/refresh} (CONTRACT.md &sect;1). Body
     * carries the tenant/org UUIDs resolved from the CURRENT access token's
     * claims (unverified decode) — the real {@code RefreshRequest} handler
     * requires both as non-optional UUIDs. Runs through the SDK's shared
     * OkHttpClient; the refresh path is special-cased in
     * {@code AuthInterceptor}/{@code AuthAuthenticator} so this call can
     * never recursively trigger a nested refresh.
     *
     * @throws AuthError    if no access token / tenant_id / org_id can be
     *                       resolved, or the server rejects the refresh
     *                       (&sect;9.3: propagated as-is, no retry)
     * @throws NetworkError on request encode/transport failure
     */
    public TokenPair doHttpRefresh() {
        String observedAccess = cachedAccessToken();
        if (observedAccess == null) {
            throw new AuthError("no access token to refresh — call login() first");
        }
        Claims observedClaims = decodeUnverifiedClaims(observedAccess);
        if (observedClaims == null || observedClaims.tenantId() == null) {
            throw new AuthError("tenant_id could not be resolved; login() must succeed before refresh()");
        }
        UUID tenantUuid = parseUuidOrThrow(observedClaims.tenantId(), "tenant_id");
        UUID orgUuid = resolveOrgId(observedClaims);
        if (orgUuid == null) {
            throw new AuthError("org_id could not be resolved; login() must succeed before refresh() "
                    + "— supply orgId()/orgSlug() or call login() first");
        }

        ObjectNode body = MAPPER.createObjectNode();
        body.put("tenant_id", tenantUuid.toString());
        body.put("org_id", orgUuid.toString());

        byte[] payload;
        try {
            payload = MAPPER.writeValueAsBytes(body);
        } catch (IOException e) {
            throw new NetworkError("failed to encode refresh request: " + e.getMessage());
        }

        Request request = new Request.Builder()
                .url(baseUrl + REFRESH_PATH)
                .post(RequestBody.create(payload, JSON))
                .build();

        OkHttpClient client = httpClient.get();
        if (client == null) {
            throw new IllegalStateException("SessionState.attachHttpClient() was never called");
        }

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                // §9.3: no retry — RefreshGuard propagates this as-is to every waiter.
                throw ErrorMapper.fromHttpStatus(response.code(), "token refresh failed", response);
            }
            String newAccess = cookieValue(ACCESS_COOKIE);
            if (newAccess == null) {
                throw new AuthError("refresh response did not set the axiam_access cookie");
            }
            String newRefresh = cookieValue(REFRESH_COOKIE);
            Claims newClaims = decodeUnverifiedClaims(newAccess);
            long expiresAtEpochMs = newClaims != null && newClaims.exp() > 0
                    ? newClaims.exp() * 1000L
                    : System.currentTimeMillis();
            return new TokenPair(newAccess, newRefresh == null ? "" : newRefresh, expiresAtEpochMs);
        } catch (IOException e) {
            throw new NetworkError("refresh request failed: " + e.getMessage());
        }
    }

    private @Nullable UUID resolveOrgId(Claims fallbackClaims) {
        if (configuredOrgId != null) {
            return configuredOrgId;
        }
        if (fallbackClaims.orgId() != null) {
            try {
                return UUID.fromString(fallbackClaims.orgId());
            } catch (IllegalArgumentException ignored) {
                // fall through — no usable org_id
            }
        }
        return null;
    }

    private static UUID parseUuidOrThrow(String value, String claimName) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException e) {
            throw new AuthError(claimName + " claim is not a valid UUID");
        }
    }

    // ------------------------------------------------------------------
    // Unverified JWT payload decode (tenant_id/org_id/jti/scope/exp
    // resolution ONLY — mirrors sdks/go's decodeUnverifiedClaims). NOT a
    // substitute for JwksVerifier's signature verification.
    // ------------------------------------------------------------------

    /**
     * The subset of access-token claims this class needs, decoded WITHOUT
     * verifying the signature. {@code roles} is derived from the
     * space-separated {@code scope} claim (empty when absent) — AXIAM's
     * access tokens have no dedicated {@code roles} claim.
     */
    public record Claims(@Nullable String sub, @Nullable String tenantId, @Nullable String orgId,
                          @Nullable String jti, List<String> roles, long exp) {
    }

    public static @Nullable Claims decodeUnverifiedClaims(String token) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            return null;
        }
        byte[] payloadBytes;
        try {
            payloadBytes = Base64.getUrlDecoder().decode(padBase64Url(parts[1]));
        } catch (IllegalArgumentException e) {
            return null;
        }
        JsonNode node;
        try {
            node = MAPPER.readTree(payloadBytes);
        } catch (IOException e) {
            return null;
        }
        String scope = textOrNull(node, "scope");
        List<String> roles = (scope == null || scope.isBlank())
                ? List.of()
                : List.of(scope.trim().split("\\s+"));
        long exp = node.hasNonNull("exp") ? node.get("exp").asLong() : 0L;
        return new Claims(textOrNull(node, "sub"), textOrNull(node, "tenant_id"), textOrNull(node, "org_id"),
                textOrNull(node, "jti"), roles, exp);
    }

    private static @Nullable String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static String padBase64Url(String s) {
        int rem = s.length() % 4;
        return rem == 0 ? s : s + "====".substring(rem);
    }

    private static String stripTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
