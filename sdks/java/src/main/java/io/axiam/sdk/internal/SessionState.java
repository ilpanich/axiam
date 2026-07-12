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

    /**
     * Creates the session state for one {@code AxiamClient}.
     *
     * @param cookieManager       the SDK's shared cookie jar (access/refresh/CSRF cookies)
     * @param baseUrl             the AXIAM server base URL (trailing slash stripped)
     * @param tenantId            the client's configured tenant identifier
     * @param configuredOrgSlug   the configured organization slug, or {@code null}
     * @param configuredOrgId     the configured organization UUID, or {@code null}
     */
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
     * the OkHttpClient this session's {@link #doHttpRefresh()} call is sent through.
     *
     * @param client the shared {@code OkHttpClient} the SDK's REST transport uses;
     *               this session's own refresh POST is routed through it so it
     *               shares the same cookie jar and header injection */
    public void attachHttpClient(OkHttpClient client) {
        httpClient.set(client);
    }

    /** Returns this session's configured tenant identifier.
     *
     * @return this session's configured tenant identifier */
    public String tenantId() {
        return tenantId;
    }

    /** Returns this session's base URL.
     *
     * @return this session's trailing-slash-stripped base URL */
    public String baseUrl() {
        return baseUrl;
    }

    /**
     * Host-isolation guard (3A, defense in depth): returns {@code true} when
     * {@code host} is this session's own origin host. The tenant identifier,
     * bearer token, and CSRF token are attached only to same-origin requests,
     * so they never leak to an absolute third-party URL or a followed
     * cross-host redirect. Host comparison is case-insensitive; a {@code null}
     * host fails closed (treated as foreign).
     *
     * @param host the request URL's host, or {@code null}
     * @return {@code true} if {@code host} equals this session's configured base
     *         URL host (case-insensitive); {@code false} for any other host,
     *         including {@code null}
     */
    public boolean isBaseHost(@Nullable String host) {
        return host != null && host.equalsIgnoreCase(baseUri.getHost());
    }

    /** Returns the configured organization slug, if any.
     *
     * @return the configured organization slug, or {@code null} if none/an org id was configured instead */
    public @Nullable String configuredOrgSlug() {
        return configuredOrgSlug;
    }

    /** Returns the configured organization UUID, if any.
     *
     * @return the configured organization UUID, or {@code null} if none/a slug was configured instead */
    public @Nullable UUID configuredOrgId() {
        return configuredOrgId;
    }

    /**
     * Checks whether {@code encodedPath} is the refresh endpoint's path.
     *
     * @param encodedPath a request URL's encoded path
     * @return {@code true} if {@code encodedPath} is the refresh endpoint's path
     */
    public static boolean isRefreshPath(String encodedPath) {
        return REFRESH_PATH.equals(encodedPath);
    }

    /** Returns the last captured CSRF token, if any.
     *
     * @return the last captured CSRF token, or {@code null} if none has been observed yet */
    public @Nullable String csrfToken() {
        return csrfToken.get();
    }

    /** Captures a freshly-observed {@code X-CSRF-Token} response header value (&sect;3).
     *
     * @param token the CSRF token value read from the response's {@code X-CSRF-Token} header */
    public void setCsrfToken(String token) {
        csrfToken.set(token);
    }

    /**
     * Non-blocking read of the current access token, sourced from the shared
     * cookie jar — never acquires {@link RefreshGuard}'s lock. Safe to call
     * from the {@code AuthInterceptor}/{@code AuthAuthenticator} hot path.
     *
     * @return the current {@code axiam_access} cookie value, or {@code null} if
     *         no session cookie is present in the shared {@link CookieManager}
     */
    public @Nullable String cachedAccessToken() {
        return cookieValue(ACCESS_COOKIE);
    }

    /**
     * Local, unverified {@code exp}-claim check (no network round trip) —
     * used ONLY as a proactive-refresh hint by {@code AuthInterceptor}. The
     * interceptor hot path must never block on a full, signature-verifying
     * JWKS fetch ({@link JwksVerifier#verify}).
     *
     * @param accessToken  the access token whose {@code exp} claim is checked
     * @param bufferMillis how many milliseconds before the token's actual
     *                     {@code exp} it should already be treated as near-expiry
     * @return {@code true} once wall-clock time is within {@code bufferMillis} of
     *         the token's {@code exp} claim; {@code false} if the token has no
     *         decodable {@code exp} claim (treated conservatively as not-yet-near,
     *         since this is only a proactive-refresh hint) or the buffer has not
     *         yet been reached
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
     * @return the newly issued {@link TokenPair} — the fresh access token, the
     *         fresh refresh token (empty string if the response does not resend
     *         one), and the expiry epoch millis derived from the new access
     *         token's {@code exp} claim (falling back to "now" if undecodable)
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
            throw new NetworkError("failed to encode refresh request: " + e.getMessage(), e);
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
            throw new NetworkError("refresh request failed: " + e.getMessage(), e);
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
     *
     * @param sub      the token subject (user id) from the {@code sub} claim, or {@code null} if absent
     * @param tenantId the resolved tenant UUID string from the {@code tenant_id} claim, or {@code null} if absent
     * @param orgId    the resolved organization UUID string from the {@code org_id} claim, or {@code null} if absent
     * @param jti      the JWT id from the {@code jti} claim (used as the refresh {@code session_id}), or {@code null} if absent
     * @param roles    the {@code scope} claim split on whitespace into individual tokens; empty (never {@code null}) when the claim is absent or blank
     * @param exp      the {@code exp} claim as epoch seconds, or {@code 0} if absent
     */
    public record Claims(@Nullable String sub, @Nullable String tenantId, @Nullable String orgId,
                          @Nullable String jti, List<String> roles, long exp) {
    }

    /**
     * Decodes {@code token}'s claims WITHOUT verifying its signature (see {@link Claims}).
     *
     * @param token a compact-serialized JWT
     * @return the decoded claims, or {@code null} if {@code token} is malformed
     *         (wrong segment count, unparseable Base64url, or invalid JSON)
     */
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
