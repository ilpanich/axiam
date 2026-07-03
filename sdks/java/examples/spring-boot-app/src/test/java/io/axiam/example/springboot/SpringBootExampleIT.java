package io.axiam.example.springboot;

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

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Boots the COMPLETE Spring Boot 3.x application context (SC#3's "complete
 * working application context") with a real {@link org.springframework.boot.web.server.WebServer}
 * and asserts the {@code /hello} endpoint is guarded by
 * {@link io.axiam.sdk.spring.AxiamAuthenticationFilter} end-to-end: 401
 * without a token, 200 with a valid matching-tenant token.
 *
 * <p>{@code JwksVerifier} is not mocked at the Spring bean level — instead
 * a real {@link MockWebServer} serves {@code /oauth2/jwks} and
 * {@code axiam.base-url} is pointed at it via {@link DynamicPropertySource},
 * so {@link SecurityConfig}'s beans are constructed exactly as they would be
 * in production, just against a test double for the AXIAM server itself.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SpringBootExampleIT {

    private static final String CONFIGURED_TENANT = "example-tenant";

    private static MockWebServer jwksServer;
    private static OctetKeyPair keyPair;

    @DynamicPropertySource
    static void axiamProperties(DynamicPropertyRegistry registry) throws Exception {
        keyPair = new OctetKeyPairGenerator(Curve.Ed25519).keyID("key-1").generate();
        jwksServer = new MockWebServer();
        // Enqueue generously — RemoteJWKSet may re-fetch across the
        // multiple HTTP requests this test class issues.
        for (int i = 0; i < 8; i++) {
            jwksServer.enqueue(jwksResponse(keyPair.toPublicJWK()));
        }
        jwksServer.start();

        registry.add("axiam.base-url", () -> jwksServer.url("/").toString());
        registry.add("axiam.tenant-id", () -> CONFIGURED_TENANT);
    }

    @AfterAll
    static void stopJwksServer() throws Exception {
        jwksServer.close();
    }

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void contextBootsWithACompleteApplicationContext() {
        // The mere fact @SpringBootTest above reached this test method proves
        // the full ApplicationContext (SecurityConfig + HelloController +
        // AxiamAuthenticationFilter beans) refreshed successfully (SC#3).
        assertThat(restTemplate).isNotNull();
    }

    @Test
    void protectedEndpointRejectsRequestWithoutToken() {
        ResponseEntity<String> response = restTemplate.getForEntity("/hello", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void protectedEndpointAcceptsValidMatchingTenantToken() throws Exception {
        String token = signEdDsa(keyPair, claims(CONFIGURED_TENANT, 900_000));

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        ResponseEntity<String> response = restTemplate.exchange(
                "/hello", HttpMethod.GET, new HttpEntity<>(headers), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("user-1");
    }

    @Test
    void protectedEndpointRejectsValidSignatureWrongTenantToken() throws Exception {
        // Validly signed by the SAME key/JWKS, but minted for a different
        // tenant — proves the cross-tenant replay defense (T-20-07) is wired
        // through the full application context, not just unit-tested.
        String wrongTenantToken = signEdDsa(keyPair, claims("other-tenant", 900_000));

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(wrongTenantToken);
        ResponseEntity<String> response = restTemplate.exchange(
                "/hello", HttpMethod.GET, new HttpEntity<>(headers), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
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
        String body = new JWKSet(List.of(publicKey)).toString();
        return new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(body);
    }
}
