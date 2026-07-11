package io.axiam.sdk.grpc;

import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.internal.RefreshGuard;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ForwardingClientCall;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContext;

import org.jspecify.annotations.Nullable;

import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.function.Supplier;

/**
 * Non-blocking {@code authorization}/{@code x-tenant-id} metadata injection
 * on every outgoing gRPC call (CONTRACT.md &sect;5, D-11/D-12) plus the
 * strict-TLS {@code ManagedChannel} construction seam
 * ({@link #channelBuilder(String, byte[])}) shared by {@link GrpcAuthzClient}.
 *
 * <p>The token accessor is a caller-supplied, non-blocking {@link Supplier}
 * (mirrors {@code sdks/go/grpc/interceptor.go}'s {@code TokenFunc}) — this
 * class NEVER calls {@link RefreshGuard#refreshIfNeeded} synchronously on
 * the {@code interceptCall}/{@code start} hot path. {@link GrpcAuthzClient}
 * wires this to a fallback of {@code RefreshGuard.cachedAccessToken()} then
 * {@code SessionState.cachedAccessToken()} — the guard's cache is empty
 * until the first refresh ever happens, so a call made immediately after
 * {@code login()} (before any refresh) still needs to fall back to the
 * cookie-jar-backed session token, exactly as the REST {@code AuthInterceptor}
 * does.
 */
public final class AuthClientInterceptor implements ClientInterceptor {

    /** Default {@code CheckAccess} per-call deadline (Assumption A4, D-12) — overridable via
     * {@code stub.withDeadlineAfter(...)} at the call site. */
    public static final Duration CHECK_ACCESS_DEADLINE = Duration.ofMillis(3000);

    /** Default {@code BatchCheckAccess} per-call deadline (Assumption A4, D-12) — overridable via
     * {@code stub.withDeadlineAfter(...)} at the call site. */
    public static final Duration BATCH_CHECK_ACCESS_DEADLINE = Duration.ofMillis(10_000);

    private static final Metadata.Key<String> AUTHORIZATION_KEY =
            Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
    private static final Metadata.Key<String> TENANT_KEY =
            Metadata.Key.of("x-tenant-id", Metadata.ASCII_STRING_MARSHALLER);

    private final Supplier<@Nullable String> tokenAccessor;
    private final String tenantId;

    /**
     * Creates an interceptor that injects the {@code authorization} bearer token
     * and {@code x-tenant-id} metadata on every outgoing gRPC call.
     *
     * @param tokenAccessor a non-blocking accessor for the currently cached access token
     *                      ({@code null} when none is available yet) — MUST NOT acquire
     *                      {@link RefreshGuard}'s lock or perform I/O
     * @param tenantId      the client's configured tenant identifier
     *                      (CONTRACT.md &sect;5), injected as {@code x-tenant-id}
     *                      metadata on every call — mirrors the REST
     *                      {@code X-Tenant-Id} header's use of the raw
     *                      configured value
     */
    public AuthClientInterceptor(Supplier<@Nullable String> tokenAccessor, String tenantId) {
        this.tokenAccessor = tokenAccessor;
        this.tenantId = tenantId;
    }

    @Override
    public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(
            MethodDescriptor<ReqT, RespT> method, CallOptions callOptions, Channel next) {
        ClientCall<ReqT, RespT> call = next.newCall(method, callOptions);
        return new ForwardingClientCall.SimpleForwardingClientCall<>(call) {
            @Override
            public void start(Listener<RespT> responseListener, Metadata headers) {
                // Non-blocking read — NEVER refreshGuard.refreshIfNeeded()
                // synchronously on this hot path (mirrors the REST AuthInterceptor and
                // sdks/go/grpc/interceptor.go's TokenFunc discipline).
                String token = tokenAccessor.get();
                if (token != null) {
                    headers.put(AUTHORIZATION_KEY, "Bearer " + token);
                }
                headers.put(TENANT_KEY, tenantId);
                super.start(responseListener, headers);
            }
        };
    }

    // ------------------------------------------------------------------
    // Strict-TLS ManagedChannel construction (D-11, T-20-01) — system trust
    // store + optional customCa, never a bypass. Mirrors
    // io.axiam.sdk.AxiamClient's composite trust-manager approach (&sect;6);
    // duplicated here (rather than shared) so the grpc/ package stays
    // independently buildable without a REST-package dependency, matching
    // the same isolation sdks/go/grpc and sdks/python's grpc subpackage keep
    // from their respective REST transports.
    // ------------------------------------------------------------------

    /**
     * Returns a {@code NettyChannelBuilder} for {@code target} (a plain
     * {@code host:port} gRPC target, e.g. {@code "dns:///localhost:9443"} —
     * distinct from the SDK's REST {@code baseUrl}, since AXIAM's gRPC
     * {@code AuthorizationService} listens on its own port) configured with
     * strict TLS (system trust store, plus {@code customCaPem} when
     * supplied). Callers still need to call {@code .intercept(...)} and
     * {@code .build()} themselves.
     *
     * @param target      a plain {@code host:port} gRPC target (e.g.
     *                    {@code "dns:///localhost:9443"})
     * @param customCaPem optional PEM-encoded custom CA (&sect;6) to trust in
     *                    addition to the system trust store, or {@code null}
     * @return a {@code NettyChannelBuilder} configured with strict TLS, not yet
     *         built (caller still adds the interceptor and calls {@code .build()})
     */
    public static NettyChannelBuilder channelBuilder(String target, byte @Nullable [] customCaPem) {
        SslContext sslContext = buildSslContext(customCaPem);
        return NettyChannelBuilder.forTarget(target)
                .sslContext(sslContext);
    }

    private static SslContext buildSslContext(byte @Nullable [] customCaPem) {
        try {
            X509TrustManager trustManager = buildTrustManager(customCaPem);
            return GrpcSslContexts.forClient()
                    .trustManager(trustManager)
                    .build();
        } catch (SSLException e) {
            throw new NetworkError("failed to initialize gRPC TLS context: " + e.getMessage(), e);
        }
    }

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
            // §6: a non-PEM/invalid custom CA MUST return a clear error at construction time.
            throw new NetworkError("invalid custom CA PEM: " + e.getMessage(), e);
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

    /** Server certs are accepted if EITHER the system trust store OR the custom CA validates
     * the chain — strict: never silently bypasses on a first-manager failure. */
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
}
