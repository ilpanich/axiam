package io.axiam.sdk.spring;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.axiam.sdk.internal.JwksVerifier;

import jakarta.servlet.FilterChain;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration test for {@link AxiamAuthenticationFilter} (20-06 acceptance
 * criteria): a matching-tenant valid token authenticates AND a
 * valid-signature wrong-tenant token is rejected (cross-tenant control is
 * enforced, non-vacuous), an expired token is rejected, and a request with
 * no token passes through unauthenticated. Uses a {@link MockFilterChain} +
 * {@link JwksVerifier} backed by a real {@link MockWebServer} (same pattern
 * as {@code JwksVerifierTest}) rather than a full Spring
 * {@code ApplicationContext}.
 */
class AxiamAuthenticationFilterIT {

    private static final String CONFIGURED_TENANT = "tenant-a";

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void matchingTenantValidTokenAuthenticatesAndReachesProtectedEndpoint() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);
            String token = signEdDsa(keyPair, claims(CONFIGURED_TENANT, 900_000));

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer " + token);
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();

            filter.doFilter(request, response, chain);

            assertTrue(chain.invoked, "the protected endpoint (downstream filter chain) must be reached");
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            assertEquals("user-1", auth.getName());
            assertEquals(200, response.getStatus());
        }
    }

    @Test
    void validSignatureWrongTenantTokenIsRejectedEvenThoughSignatureIsValid() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);
            // Validly signed by the SAME key/JWKS, but minted for a different tenant —
            // proves the cross-tenant replay defense (T-20-07), not just signature checking.
            String wrongTenantToken = signEdDsa(keyPair, claims("tenant-b", 900_000));

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer " + wrongTenantToken);
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();

            filter.doFilter(request, response, chain);

            assertFalse(chain.invoked, "the protected endpoint must NOT be reached for a cross-tenant token");
            assertEquals(401, response.getStatus());
            assertNull(SecurityContextHolder.getContext().getAuthentication());
            assertTrue(response.getContentAsString().contains("authentication_failed"));
        }
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);
            String expiredToken = signEdDsa(keyPair, claims(CONFIGURED_TENANT, -60_000));

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer " + expiredToken);
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();

            filter.doFilter(request, response, chain);

            assertFalse(chain.invoked, "the protected endpoint must NOT be reached for an expired token");
            assertEquals(401, response.getStatus());
            assertNull(SecurityContextHolder.getContext().getAuthentication());
        }
    }

    @Test
    void noTokenPassesThroughUnauthenticated() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);

            MockHttpServletRequest request = new MockHttpServletRequest();
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();

            filter.doFilter(request, response, chain);

            assertTrue(chain.invoked, "an unauthenticated request must reach the chain so Spring Security's own"
                    + " access-control rules can 401/403 it");
            assertNull(SecurityContextHolder.getContext().getAuthentication());
        }
    }

    private static AxiamAuthenticationFilter filterFor(MockWebServer server, String configuredTenantId) {
        JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
        return new AxiamAuthenticationFilter(verifier, configuredTenantId);
    }

    private static MockWebServer startJwksServer(OctetKeyPair keyPair) throws Exception {
        MockWebServer server = new MockWebServer();
        // Enqueue generously: RemoteJWKSet may re-fetch on cache-miss checks
        // across the four independent test methods sharing this helper.
        for (int i = 0; i < 4; i++) {
            server.enqueue(jwksResponse(keyPair.toPublicJWK()));
        }
        server.start();
        return server;
    }

    private static OctetKeyPair generateEd25519KeyPair(String kid) throws Exception {
        return new OctetKeyPairGenerator(Curve.Ed25519).keyID(kid).generate();
    }

    private static JWTClaimsSet claims(String tenantId, long expiresInMillis) {
        return new JWTClaimsSet.Builder()
                .subject("user-1")
                .claim("tenant_id", tenantId)
                .claim("scope", "users:read users:write")
                .expirationTime(new Date(System.currentTimeMillis() + expiresInMillis))
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

    private static MockResponse jwksResponse(OctetKeyPair publicKey) {
        String body = new JWKSet(java.util.List.of(publicKey)).toString();
        return new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(body);
    }

    /** Records whether the downstream chain (the protected endpoint) was reached. */
    private static final class RecordingFilterChain implements FilterChain {
        private boolean invoked = false;

        @Override
        public void doFilter(jakarta.servlet.ServletRequest request, jakarta.servlet.ServletResponse response) {
            invoked = true;
        }
    }
}
