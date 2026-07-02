package io.axiam.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.ErrorMapper;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.internal.JwksVerifier;
import io.axiam.sdk.internal.RefreshGuard;
import io.axiam.sdk.internal.Retry;
import io.axiam.sdk.internal.SessionState;

import okhttp3.JavaNetCookieJar;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

import org.jspecify.annotations.Nullable;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * The AXIAM Java SDK's public REST entry point (CONTRACT.md &sect;1&ndash;&sect;6,
 * &sect;9). {@link #builder(String, String)} is the ONLY construction path —
 * {@code tenantId} is a required, positional argument (SC#1); there is no
 * no-arg builder factory.
 *
 * <p>Owns exactly ONE {@link RefreshGuard}, ONE {@link SessionState}, and ONE
 * {@link JwksVerifier} per client — shared by the REST interceptor/
 * authenticator here and, by future plans, the gRPC transport (D-07/D-08:
 * "one guard"). Package-internal accessors ({@link #refreshGuard()},
 * {@link #tenantId()}, {@link #baseUrl()}, {@link #okHttpClient()},
 * {@link #customCa()}, {@link #session()}) expose this seam without
 * requiring the gRPC plan (20-08) or the examples (20-09) to edit this
 * class.
 */
public final class AxiamClient implements AutoCloseable {

    private static final String LOGIN_PATH = "/api/v1/auth/login";
    private static final String MFA_VERIFY_PATH = "/api/v1/auth/mfa/verify";
    private static final String LOGOUT_PATH = "/api/v1/auth/logout";
    private static final String CHECK_PATH = "/api/v1/authz/check";
    private static final String BATCH_CHECK_PATH = "/api/v1/authz/check/batch";

    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String baseUrl;
    private final String tenantId;
    private final byte @Nullable [] customCaPem;
    private final OkHttpClient httpClient;
    private final RefreshGuard refreshGuard;
    private final JwksVerifier jwksVerifier;
    private final SessionState session;

    /**
     * The ONLY construction path (SC#1) — {@code tenantId} is required and
     * positional; there is no no-arg builder factory reachable from this
     * class. A blank {@code tenantId} is a runtime guard backing the
     * compile-time guarantee (this factory is the sole way to obtain a
     * {@link Builder}, whose constructor is private).
     *
     * @throws AuthError if {@code tenantId} is {@code null} or blank
     *                    (CONTRACT.md &sect;5 — AXIAM is multi-tenant, there
     *                    is no default tenant)
     */
    public static Builder builder(String baseUrl, @Nullable String tenantId) {
        if (tenantId == null || tenantId.isBlank()) {
            throw new AuthError("tenantId is required — AXIAM is multi-tenant "
                    + "and there is no default tenant (CONTRACT.md §5)");
        }
        return new Builder(baseUrl, tenantId);
    }

    public static final class Builder {
        private final String baseUrl;
        private final String tenantId;
        private @Nullable String orgSlug;
        private @Nullable UUID orgId;
        private byte @Nullable [] customCaPem;
        private @Nullable OkHttpClient overrideHttpClient;
        private Duration connectTimeout = Duration.ofSeconds(10);
        private Duration readTimeout = Duration.ofSeconds(30);
        private Duration writeTimeout = Duration.ofSeconds(30);

        private Builder(String baseUrl, String tenantId) {
            this.baseUrl = baseUrl;
            this.tenantId = tenantId;
        }

        /** Mutually exclusive with {@link #orgId(UUID)} — last call wins. The
         * real login/refresh endpoints need an org identifier beyond §5's
         * documented tenant-only minimum (Pitfall 2). */
        public Builder orgSlug(String slug) {
            this.orgSlug = slug;
            this.orgId = null;
            return this;
        }

        /** Mutually exclusive with {@link #orgSlug(String)} — last call wins. */
        public Builder orgId(UUID id) {
            this.orgId = id;
            this.orgSlug = null;
            return this;
        }

        /** The ONLY TLS escape hatch (§6) — adds a PEM-encoded CA certificate to
         * the verification chain, alongside (never instead of) the system trust
         * store. There is no API surface anywhere in this SDK that disables or
         * weakens certificate verification. */
        public Builder customCa(byte[] pem) {
            this.customCaPem = pem;
            return this;
        }

        /** Supplies a base {@code OkHttpClient} whose non-TLS/jar configuration
         * (e.g. connection pool, timeouts, custom interceptors) is adopted. The
         * SDK ALWAYS re-applies its own cookie jar and strict TLS config over
         * this via {@code newBuilder()} afterward (D-27, SC#4) — an override
         * can never silently drop the jar or weaken TLS verification. */
        public Builder httpClient(OkHttpClient client) {
            this.overrideHttpClient = client;
            return this;
        }

        public Builder connectTimeout(Duration d) {
            this.connectTimeout = d;
            return this;
        }

        public Builder readTimeout(Duration d) {
            this.readTimeout = d;
            return this;
        }

        public Builder writeTimeout(Duration d) {
            this.writeTimeout = d;
            return this;
        }

        public AxiamClient build() {
            return new AxiamClient(this);
        }
    }

    private AxiamClient(Builder b) {
        this.baseUrl = stripTrailingSlash(b.baseUrl);
        this.tenantId = b.tenantId;
        this.customCaPem = b.customCaPem;

        CookieManager cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        this.refreshGuard = new RefreshGuard();
        this.jwksVerifier = new JwksVerifier(this.baseUrl);
        this.session = new SessionState(cookieManager, this.baseUrl, this.tenantId, b.orgSlug, b.orgId);

        X509TrustManager trustManager = buildTrustManager(b.customCaPem);
        SSLContext sslContext = buildStrictSslContext(trustManager);

        OkHttpClient.Builder clientBuilder = b.overrideHttpClient != null
                ? b.overrideHttpClient.newBuilder()
                : new OkHttpClient.Builder();

        // D-27/SC#4: ALWAYS re-apply the SDK's own cookie jar + strict TLS
        // (system trust store + optional customCa, strict hostname
        // verification), regardless of what an overridden client had
        // configured — an override can never silently drop the jar or
        // weaken TLS.
        clientBuilder
                .cookieJar(new JavaNetCookieJar(cookieManager))
                .sslSocketFactory(sslContext.getSocketFactory(), trustManager)
                .hostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier())
                .connectTimeout(b.connectTimeout)
                .readTimeout(b.readTimeout)
                .writeTimeout(b.writeTimeout)
                .addInterceptor(new io.axiam.sdk.rest.AuthInterceptor(refreshGuard, session))
                .authenticator(new io.axiam.sdk.rest.AuthAuthenticator(refreshGuard, session));

        this.httpClient = clientBuilder.build();
        this.session.attachHttpClient(this.httpClient);
    }

    // ------------------------------------------------------------------
    // AutoCloseable (D-09)
    // ------------------------------------------------------------------

    @Override
    public void close() {
        httpClient.dispatcher().executorService().shutdown();
        httpClient.connectionPool().evictAll();
        okhttp3.Cache cache = httpClient.cache();
        if (cache != null) {
            try {
                cache.close();
            } catch (IOException ignored) {
                // best-effort — nothing actionable on a failed cache close.
            }
        }
    }

    // ------------------------------------------------------------------
    // SDK-internal accessors (gRPC seam, 20-08) — not part of the public API
    // contract, but Java has no cross-package "friend" visibility; the
    // `internal`-style comment here is the boundary marker, not enforced by
    // the language (mirrors the `internal` package's own convention).
    // ------------------------------------------------------------------

    public RefreshGuard refreshGuard() {
        return refreshGuard;
    }

    public String tenantId() {
        return tenantId;
    }

    public String baseUrl() {
        return baseUrl;
    }

    public OkHttpClient okHttpClient() {
        return httpClient;
    }

    public byte @Nullable [] customCa() {
        return customCaPem;
    }

    /**
     * The SAME {@link SessionState} instance this client's REST transport
     * uses — required by {@link io.axiam.sdk.grpc.GrpcAuthzClient}'s public
     * constructor so the gRPC transport shares one session/guard pair with
     * REST (D-07/D-08 "one guard"), never a second, independently
     * constructed session.
     */
    public SessionState session() {
        return session;
    }

    // ------------------------------------------------------------------
    // Auth methods (CONTRACT.md §1): login / verifyMfa / refresh / logout
    // ------------------------------------------------------------------

    /**
     * {@code POST /api/v1/auth/login}. Returns a typed {@link LoginResult} —
     * an MFA challenge (HTTP 202) is an expected outcome, not an exception;
     * check {@link LoginResult#mfaRequired()} before assuming a session was
     * established.
     */
    public LoginResult login(String email, String password) {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("tenant_slug", tenantId);
        UUID orgId = session.configuredOrgId();
        String orgSlug = session.configuredOrgSlug();
        if (orgId != null) {
            body.put("org_id", orgId.toString());
        } else if (orgSlug != null) {
            body.put("org_slug", orgSlug);
        }
        body.put("username_or_email", email);
        body.put("password", password);

        try (Response response = executeJsonPost(LOGIN_PATH, body)) {
            if (response.code() == 200) {
                consumeBody(response);
                return new LoginResult(false, null, buildUser());
            }
            if (response.code() == 202) {
                JsonNode wire = readJson(response);
                String challengeToken = wire.path("challenge_token").asText();
                return new LoginResult(true, Sensitive.of(challengeToken), null);
            }
            throw ErrorMapper.fromHttpStatus(response.code(), "login failed", response);
        }
    }

    public CompletableFuture<LoginResult> loginAsync(String email, String password) {
        return CompletableFuture.supplyAsync(() -> login(email, password));
    }

    /**
     * {@code POST /api/v1/auth/mfa/verify} (CONTRACT.md &sect;1), completing
     * the two-phase flow started by {@link #login} when {@code mfaRequired}
     * was {@code true}.
     */
    public LoginResult verifyMfa(Sensitive mfaToken, String totpCode) {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("challenge_token", mfaToken.expose());
        body.put("totp_code", totpCode);

        try (Response response = executeJsonPost(MFA_VERIFY_PATH, body)) {
            if (response.code() != 200) {
                throw ErrorMapper.fromHttpStatus(response.code(), "MFA verification failed", response);
            }
            consumeBody(response);
            return new LoginResult(false, null, buildUser());
        }
    }

    public CompletableFuture<LoginResult> verifyMfaAsync(Sensitive mfaToken, String totpCode) {
        return CompletableFuture.supplyAsync(() -> verifyMfa(mfaToken, totpCode));
    }

    /**
     * {@code POST /api/v1/auth/refresh} (CONTRACT.md &sect;1), routed through
     * the single-flight {@link RefreshGuard} (&sect;9). A 401 on the refresh
     * call itself is {@link AuthError} with no retry (&sect;9.3).
     */
    public void refresh() {
        String observedAccess = session.cachedAccessToken();
        if (observedAccess == null) {
            throw new AuthError("no access token to refresh — call login() first");
        }
        refreshGuard.refreshIfNeeded(observedAccess, session::doHttpRefresh);
    }

    public CompletableFuture<Void> refreshAsync() {
        return CompletableFuture.runAsync(this::refresh);
    }

    /**
     * {@code POST /api/v1/auth/logout} (CONTRACT.md &sect;1) and clears
     * in-memory session state. The session id comes from the current access
     * token's {@code jti} claim.
     */
    public void logout() {
        String access = session.cachedAccessToken();
        if (access == null) {
            throw new AuthError("no active session to log out");
        }
        SessionState.Claims claims = SessionState.decodeUnverifiedClaims(access);
        if (claims == null || claims.jti() == null) {
            throw new AuthError("access token has no session id (jti) to log out");
        }

        ObjectNode body = MAPPER.createObjectNode();
        body.put("session_id", claims.jti());

        try (Response response = executeJsonPost(LOGOUT_PATH, body)) {
            if (response.code() >= 300) {
                throw ErrorMapper.fromHttpStatus(response.code(), "logout failed", response);
            }
            consumeBody(response);
            session.clear();
        }
    }

    public CompletableFuture<Void> logoutAsync() {
        return CompletableFuture.runAsync(this::logout);
    }

    private AxiamUser buildUser() {
        String access = session.cachedAccessToken();
        if (access == null) {
            throw new AuthError("login succeeded but no access token was set");
        }
        SessionState.Claims claims = SessionState.decodeUnverifiedClaims(access);
        if (claims == null || claims.sub() == null || claims.tenantId() == null) {
            throw new AuthError("failed to decode access token claims after login");
        }
        return new AxiamUser(claims.sub(), claims.tenantId(), claims.roles());
    }

    // ------------------------------------------------------------------
    // Authz methods (CONTRACT.md §1): checkAccess / can / batchCheck
    // ------------------------------------------------------------------

    /** A single authorization check request (CONTRACT.md &sect;1). */
    public record AccessCheck(String action, String resourceId, @Nullable String scope) {
        public AccessCheck(String action, String resourceId) {
            this(action, resourceId, null);
        }
    }

    /** The outcome of a single authorization check (mirrors {@code CheckAccessResponse}). */
    public record AccessResult(boolean allowed, @Nullable String reason) {
    }

    /**
     * {@code POST /api/v1/authz/check} — evaluates a single authorization
     * check. Read-only/idempotent: eligible for {@link Retry}'s bounded
     * backoff on a transient {@link NetworkError}.
     */
    public AccessResult checkAccess(String action, String resourceId, @Nullable String scope) {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("action", action);
        body.put("resource_id", resourceId);
        if (scope != null) {
            body.put("scope", scope);
        }
        return Retry.withRetry(() -> sendCheckAccess(body), AxiamClient::isRetryableNetworkError);
    }

    public AccessResult checkAccess(String action, String resourceId) {
        return checkAccess(action, resourceId, null);
    }

    public CompletableFuture<AccessResult> checkAccessAsync(String action, String resourceId, @Nullable String scope) {
        return CompletableFuture.supplyAsync(() -> checkAccess(action, resourceId, scope));
    }

    public CompletableFuture<AccessResult> checkAccessAsync(String action, String resourceId) {
        return checkAccessAsync(action, resourceId, null);
    }

    /** Browser/UI-scenario alias for {@link #checkAccess} (CONTRACT.md &sect;1 note). */
    public boolean can(String action, String resourceId, @Nullable String scope) {
        return checkAccess(action, resourceId, scope).allowed();
    }

    public boolean can(String action, String resourceId) {
        return can(action, resourceId, null);
    }

    public CompletableFuture<Boolean> canAsync(String action, String resourceId, @Nullable String scope) {
        return CompletableFuture.supplyAsync(() -> can(action, resourceId, scope));
    }

    public CompletableFuture<Boolean> canAsync(String action, String resourceId) {
        return canAsync(action, resourceId, null);
    }

    /**
     * {@code POST /api/v1/authz/check/batch} — evaluates an ordered list of
     * checks; results are returned in the same order as {@code checks}.
     * Read-only/idempotent: eligible for {@link Retry}'s bounded backoff.
     */
    public List<AccessResult> batchCheck(List<AccessCheck> checks) {
        ArrayNode checksArray = MAPPER.createArrayNode();
        for (AccessCheck check : checks) {
            ObjectNode item = MAPPER.createObjectNode();
            item.put("action", check.action());
            item.put("resource_id", check.resourceId());
            if (check.scope() != null) {
                item.put("scope", check.scope());
            }
            checksArray.add(item);
        }
        ObjectNode body = MAPPER.createObjectNode();
        body.set("checks", checksArray);

        return Retry.withRetry(() -> sendBatchCheck(body), AxiamClient::isRetryableNetworkError);
    }

    public CompletableFuture<List<AccessResult>> batchCheckAsync(List<AccessCheck> checks) {
        return CompletableFuture.supplyAsync(() -> batchCheck(checks));
    }

    private AccessResult sendCheckAccess(ObjectNode body) {
        try (Response response = executeJsonPost(CHECK_PATH, body)) {
            if (!response.isSuccessful()) {
                throw ErrorMapper.fromHttpStatus(response.code(), "checkAccess failed", response);
            }
            JsonNode wire = readJson(response);
            boolean allowed = wire.path("allowed").asBoolean(false);
            String reason = wire.hasNonNull("reason") ? wire.get("reason").asText() : null;
            return new AccessResult(allowed, reason);
        }
    }

    private List<AccessResult> sendBatchCheck(ObjectNode body) {
        try (Response response = executeJsonPost(BATCH_CHECK_PATH, body)) {
            if (!response.isSuccessful()) {
                throw ErrorMapper.fromHttpStatus(response.code(), "batchCheck failed", response);
            }
            JsonNode wire = readJson(response);
            List<AccessResult> results = new ArrayList<>();
            for (JsonNode item : wire.path("results")) {
                boolean allowed = item.path("allowed").asBoolean(false);
                String reason = item.hasNonNull("reason") ? item.get("reason").asText() : null;
                results.add(new AccessResult(allowed, reason));
            }
            return results;
        }
    }

    private static boolean isRetryableNetworkError(RuntimeException e) {
        return e instanceof NetworkError;
    }

    // ------------------------------------------------------------------
    // Shared HTTP mechanics
    // ------------------------------------------------------------------

    private Response executeJsonPost(String path, ObjectNode body) {
        byte[] payload;
        try {
            payload = MAPPER.writeValueAsBytes(body);
        } catch (IOException e) {
            throw new NetworkError("failed to encode request: " + e.getMessage());
        }
        Request request = new Request.Builder()
                .url(baseUrl + path)
                .post(RequestBody.create(payload, JSON))
                .build();
        try {
            return httpClient.newCall(request).execute();
        } catch (IOException e) {
            throw new NetworkError("request failed: " + e.getMessage());
        }
    }

    private static JsonNode readJson(Response response) {
        try {
            ResponseBody responseBody = response.body();
            if (responseBody == null) {
                return MAPPER.createObjectNode();
            }
            return MAPPER.readTree(responseBody.byteStream());
        } catch (IOException e) {
            throw new NetworkError("failed to parse response body: " + e.getMessage());
        }
    }

    private static void consumeBody(Response response) {
        ResponseBody body = response.body();
        if (body != null) {
            body.close();
        }
    }

    // ------------------------------------------------------------------
    // TLS setup (§6, D-27) — system trust store + optional customCa, never a
    // bypass. Composite trust manager: server certs are accepted if EITHER
    // the system trust store OR the custom CA validates the chain.
    // ------------------------------------------------------------------

    private static X509TrustManager buildTrustManager(byte @Nullable [] customCaPem) {
        try {
            TrustManagerFactory systemTmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            systemTmf.init((KeyStore) null);
            X509TrustManager systemTm = firstX509(systemTmf.getTrustManagers());

            if (customCaPem == null || customCaPem.length == 0) {
                return systemTm;
            }

            KeyStore customStore = KeyStore.getInstance(KeyStore.getDefaultType());
            customStore.load(null, null);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate customCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(customCaPem));
            customStore.setCertificateEntry("custom-ca", customCert);

            TrustManagerFactory customTmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            customTmf.init(customStore);
            X509TrustManager customTm = firstX509(customTmf.getTrustManagers());

            return new CompositeX509TrustManager(systemTm, customTm);
        } catch (GeneralSecurityException | IOException e) {
            // §6: a non-PEM/invalid custom CA MUST return a clear error at
            // construction time.
            throw new NetworkError("invalid custom CA PEM: " + e.getMessage());
        }
    }

    private static X509TrustManager firstX509(TrustManager[] tms) {
        for (TrustManager tm : tms) {
            if (tm instanceof X509TrustManager x509) {
                return x509;
            }
        }
        throw new IllegalStateException("no X509TrustManager found in the default TrustManagerFactory");
    }

    private static SSLContext buildStrictSslContext(X509TrustManager trustManager) {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{trustManager}, new SecureRandom());
            return ctx;
        } catch (GeneralSecurityException e) {
            throw new NetworkError("failed to initialize TLS context: " + e.getMessage());
        }
    }

    private static final class CompositeX509TrustManager implements X509TrustManager {
        private final X509TrustManager primary;
        private final X509TrustManager secondary;

        CompositeX509TrustManager(X509TrustManager primary, X509TrustManager secondary) {
            this.primary = primary;
            this.secondary = secondary;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            primary.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            try {
                primary.checkServerTrusted(chain, authType);
            } catch (CertificateException primaryFailure) {
                // Strict: only trust if the secondary (custom CA) validates —
                // never silently bypass on a first-manager failure.
                secondary.checkServerTrusted(chain, authType);
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            X509Certificate[] a = primary.getAcceptedIssuers();
            X509Certificate[] b = secondary.getAcceptedIssuers();
            X509Certificate[] combined = Arrays.copyOf(a, a.length + b.length);
            System.arraycopy(b, 0, combined, a.length, b.length);
            return combined;
        }
    }

    private static String stripTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
