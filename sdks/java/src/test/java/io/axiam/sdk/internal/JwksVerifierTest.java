package io.axiam.sdk.internal;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.axiam.sdk.errors.AuthError;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Proves D-19/T-20-06/T-20-07: a valid EdDSA token verifies against the
 * cached JWKS, a non-EdDSA-alg token is rejected BEFORE key lookup, the
 * Ed25519 verify path exercises the Tink runtime dependency without
 * {@code NoClassDefFoundError}, and {@link JwksVerifier#assertTenant}
 * enforces the cross-tenant claim control.
 */
class JwksVerifierTest {

    @Test
    void validEdDsaTokenVerifiesAndReturnsClaims() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");

        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(jwksResponse(keyPair.toPublicJWK()));
            server.start();

            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = signEdDsa(keyPair, claims("tenant-a"));

            JWTClaimsSet result = verifier.verify(token);

            assertEquals("tenant-a", result.getStringClaim("tenant_id"));
        }
    }

    @Test
    void nonEdDsaAlgTokenIsRejected() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");

        try (MockWebServer server = new MockWebServer()) {
            // JWSVerificationKeySelector returns an empty key list for a
            // non-matching alg WITHOUT ever consulting the JWKS source, so
            // this enqueued response is expected to go unconsumed.
            server.enqueue(jwksResponse(keyPair.toPublicJWK()));
            server.start();

            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String hs256Token = signHs256("some-shared-secret-key-material-32b", claims("tenant-a"));

            assertThrows(AuthError.class, () -> verifier.verify(hs256Token));
        }
    }

    @Test
    void assertTenantThrowsOnMismatchAndPassesOnMatch() throws Exception {
        JWTClaimsSet matching = claims("tenant-a");
        JWTClaimsSet mismatched = claims("tenant-b");

        assertDoesNotThrow(() -> JwksVerifier.assertTenant(matching, "tenant-a"));
        assertThrows(AuthError.class, () -> JwksVerifier.assertTenant(mismatched, "tenant-a"));
    }

    @Test
    void assertTenantThrowsWhenClaimAbsent() throws Exception {
        JWTClaimsSet noTenant = new JWTClaimsSet.Builder()
                .subject("user-1")
                .expirationTime(new Date(System.currentTimeMillis() + 900_000))
                .build();

        assertThrows(AuthError.class, () -> JwksVerifier.assertTenant(noTenant, "tenant-a"));
    }

    /**
     * Tink-presence smoke test (RESEARCH.md Pattern 4's "Tink dependency
     * note"): verifying a real Ed25519-signed token must not raise
     * {@code NoClassDefFoundError} — catches a missing Tink runtime
     * dependency early rather than only against a live server.
     */
    @Test
    void ed25519VerificationDoesNotRaiseNoClassDefFoundError() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");

        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(jwksResponse(keyPair.toPublicJWK()));
            server.start();

            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = signEdDsa(keyPair, claims("tenant-a"));

            assertDoesNotThrow(() -> verifier.verify(token));
        }
    }

    /**
     * Proves D-08/D-09: a burst of concurrent {@link JwksVerifier#verify}
     * calls against a cold cache collapses to exactly one JWKS fetch, not
     * one fetch per thread.
     */
    @Test
    void concurrentVerifyBurstTriggersExactlyOneJwksFetch() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("kid-burst");
        AtomicInteger fetchCount = new AtomicInteger(0);

        try (MockWebServer server = new MockWebServer()) {
            server.setDispatcher(new Dispatcher() {
                @Override
                public MockResponse dispatch(RecordedRequest request) {
                    fetchCount.incrementAndGet();
                    return jwksResponse(keyPair.toPublicJWK());
                }
            });
            server.start();

            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = signEdDsa(keyPair, claims("tenant-a"));

            int threadCount = 8;
            ExecutorService pool = Executors.newFixedThreadPool(threadCount);
            CountDownLatch ready = new CountDownLatch(threadCount);
            CountDownLatch start = new CountDownLatch(1);
            CountDownLatch done = new CountDownLatch(threadCount);
            List<Throwable> errors = java.util.Collections.synchronizedList(new java.util.ArrayList<>());

            for (int i = 0; i < threadCount; i++) {
                pool.submit(() -> {
                    ready.countDown();
                    try {
                        start.await();
                        verifier.verify(token);
                    } catch (Throwable t) {
                        errors.add(t);
                    } finally {
                        done.countDown();
                    }
                });
            }

            ready.await();
            start.countDown();
            assertTrue(done.await(10, TimeUnit.SECONDS), "verify burst did not complete in time");
            pool.shutdown();

            assertTrue(errors.isEmpty(), "unexpected verify failures: " + errors);
            assertEquals(1, fetchCount.get(), "expected exactly one JWKS fetch for the concurrent unknown-kid burst");
        }
    }

    private static OctetKeyPair generateEd25519KeyPair(String kid) throws Exception {
        return new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID(kid)
                .generate();
    }

    private static JWTClaimsSet claims(String tenantId) {
        return new JWTClaimsSet.Builder()
                .subject("user-1")
                .claim("tenant_id", tenantId)
                .expirationTime(new Date(System.currentTimeMillis() + 900_000))
                .build();
    }

    private static String signEdDsa(OctetKeyPair keyPair, JWTClaimsSet claims) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .type(JOSEObjectType.JWT)
                .keyID(keyPair.getKeyID())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new Ed25519Signer(keyPair));
        return jwt.serialize();
    }

    private static String signHs256(String secret, JWTClaimsSet claims) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT)
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new MACSigner(secret.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        return jwt.serialize();
    }

    private static MockResponse jwksResponse(OctetKeyPair publicKey) {
        String body = new JWKSet(java.util.List.of(publicKey)).toString();
        return new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(body);
    }
}
