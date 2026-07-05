package io.axiam.sdk.internal;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.source.DefaultJWKSetCache;
import com.nimbusds.jose.jwk.source.JWKSetCache;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.axiam.sdk.errors.AuthError;

import java.net.URI;
import java.net.URL;
import java.text.ParseException;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Local JWT verification against the organization-wide EdDSA JWKS (D-19,
 * CONTRACT.md &sect;9's local-verify companion). Sources keys from
 * {@code {baseUrl}/oauth2/jwks} via nimbus's {@link RemoteJWKSet}, cached
 * with {@link DefaultJWKSetCache} (TTL 300s / forced-refetch cooldown 60s,
 * matching the Rust/Go/Python reference SDKs' proven defaults) and rotated
 * on an unknown {@code kid} (built into {@link RemoteJWKSet#get}).
 *
 * <p><strong>Implementation note (Assumption A5 resolved against the
 * installed nimbus-jose-jwt 10.7 sources):</strong> the "obvious" nimbus
 * pipeline researched for this phase &mdash;
 * {@code DefaultJWTProcessor} + {@code JWSVerificationKeySelector(EdDSA,
 * jwkSource)} &mdash; does NOT work for OKP/Ed25519 keys in this release:
 * {@code JWSVerificationKeySelector.selectJWSKeys} converts every matched
 * {@link JWK} to a raw {@code java.security.Key} via
 * {@code KeyConverter.toJavaKeys}, which for an {@link OctetKeyPair} calls
 * {@code OctetKeyPair.toKeyPair()} &mdash; a method that unconditionally
 * throws {@code JOSEException("Export to java.security.KeyPair not
 * supported")} in nimbus-jose-jwt 10.7. That exception is silently
 * swallowed by {@code KeyConverter.toJavaKeys} ("Key conversion exceptions
 * are silently ignored"), so a correctly-signed EdDSA token is rejected
 * with a misleading {@code BadJOSEException("...no matching key(s)
 * found")} even though the JWKS fetch and key match succeeded. Separately,
 * {@code DefaultJWSVerifierFactory.createJWSVerifier} has no EdDSA/OKP
 * branch at all (only HMAC/RSA/EC) even if a converted key did exist. This
 * class therefore builds the key lookup directly against the same
 * {@link RemoteJWKSet} + {@link DefaultJWKSetCache} (preserving D-19's
 * "Don't Hand-Roll: use RemoteJWKSet+DefaultJWKSetCache" mandate for
 * fetch/cache/rotation) and constructs {@link Ed25519Verifier} directly
 * from the matched {@link OctetKeyPair}, which nimbus DOES support
 * natively.
 *
 * <p><strong>Algorithm pinning (T-20-06):</strong> the header {@code alg}
 * is checked against an explicit {@code EdDSA} allowlist BEFORE any JWKS
 * lookup is attempted &mdash; the token's own {@code alg} header never
 * selects the verification algorithm (algorithm-confusion defense; the
 * same idiom the Go/Rust/Python sibling SDKs implement by hand, since
 * nimbus's own algorithm-pinning key-selector class cannot drive OKP
 * verification in this release).
 *
 * <p><strong>Cross-tenant carry-forward (T-20-07, MUST-carry-forward
 * control):</strong> the JWKS endpoint is organization-wide, not
 * tenant-scoped &mdash; signature validity alone does NOT imply tenant
 * authorization. Every caller MUST additionally call
 * {@link #assertTenant(JWTClaimsSet, String)} after {@link #verify(String)}
 * succeeds (the 20-06 Spring filter does this).
 */
public final class JwksVerifier {

    private final RemoteJWKSet<SecurityContext> jwkSource;

    /**
     * Serializes the forced-refetch path so a concurrent burst of
     * unknown-{@code kid} verifications collapses to exactly one Nimbus
     * refetch (D-08/D-09) &mdash; we do NOT rely on {@link RemoteJWKSet}'s
     * own thread-safety for this guarantee (Assumption A3). The lock wraps
     * only the fetch/refetch decision below; the EdDSA signature
     * verification in {@link #verify(String)} is unaffected.
     */
    private final ReentrantLock refreshLock = new ReentrantLock();

    /**
     * @param baseUrl the AXIAM server base URL (trailing slash tolerated);
     *                the JWKS URL is derived as {@code {baseUrl}/oauth2/jwks}
     */
    public JwksVerifier(String baseUrl) {
        String trimmed = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        URL jwksUrl;
        try {
            jwksUrl = URI.create(trimmed + "/oauth2/jwks").toURL();
        } catch (java.net.MalformedURLException e) {
            throw new IllegalArgumentException("invalid AXIAM base URL: " + baseUrl, e);
        }

        // TTL 300s, forced-refetch cooldown 60s — matches the Rust
        // (JWKS_CACHE_TTL=300s / FORCED_REFETCH_MIN_INTERVAL=60s), Go
        // (jwx minInterval=60s / maxInterval=300s), and Python
        // (PyJWKClient lifespan=300) reference SDKs' proven defaults.
        JWKSetCache cache = new DefaultJWKSetCache(300, 60, TimeUnit.SECONDS);
        this.jwkSource = new RemoteJWKSet<>(jwksUrl, null, cache);
    }

    /**
     * Verifies the token's signature (alg pinned to EdDSA, key sourced from
     * the cached/rotated JWKS) and returns its claims on success.
     *
     * <p>This method verifies signature only — it does NOT check expiry or
     * tenant scoping. Callers MUST separately check {@code exp} and call
     * {@link #assertTenant(JWTClaimsSet, String)}.
     *
     * @throws AuthError if the token is malformed, the alg is not EdDSA,
     *                    no matching key is found in the JWKS (including
     *                    after a forced refetch on an unknown {@code kid}),
     *                    or the signature is invalid
     */
    public JWTClaimsSet verify(String token) {
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(token);
        } catch (ParseException e) {
            throw new AuthError("malformed token: " + e.getMessage());
        }

        JWSHeader header = jwt.getHeader();

        // Algorithm pinning HERE, before any JWKS lookup: reject anything
        // but EdDSA without ever consulting the key source, closing the
        // algorithm-confusion class of attack (T-20-06).
        if (!JWSAlgorithm.EdDSA.equals(header.getAlgorithm())) {
            throw new AuthError("unexpected JWS algorithm " + header.getAlgorithm() + ": only EdDSA is accepted");
        }

        OctetKeyPair key = selectKey(header);

        JWSVerifier verifier;
        try {
            verifier = new Ed25519Verifier(key);
        } catch (JOSEException e) {
            throw new AuthError("failed to construct EdDSA verifier: " + e.getMessage());
        }

        boolean valid;
        try {
            valid = jwt.verify(verifier);
        } catch (JOSEException e) {
            throw new AuthError("signature verification failed: " + e.getMessage());
        }
        if (!valid) {
            throw new AuthError("invalid token signature");
        }

        try {
            return jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new AuthError("malformed claims: " + e.getMessage());
        }
    }

    /**
     * Looks up the EdDSA/Ed25519 signing key matching {@code header}'s
     * {@code kid} in the cached JWKS, sourced from {@link #jwkSource}
     * ({@link RemoteJWKSet}, which itself forces exactly one refetch +
     * retry when the sought {@code kid} is not found in the cached set —
     * key-rotation support carried by the library, not hand-rolled).
     *
     * <p>D-08/D-09: a concurrent burst of unknown-{@code kid} lookups must
     * collapse to exactly one Nimbus refetch. The fast path below matches
     * against {@link RemoteJWKSet#getCachedJWKSet()} — which never triggers
     * a network call — before ever acquiring {@link #refreshLock}. Only on
     * a cache miss is the lock acquired; the cache is re-checked once more
     * under the lock (another thread may have just refreshed it while this
     * one waited), and {@link RemoteJWKSet#get} — the call that may
     * perform the actual network refetch — is invoked only if the key is
     * still missing.
     */
    private OctetKeyPair selectKey(JWSHeader header) {
        JWKMatcher matcher = new JWKMatcher.Builder()
                .keyType(KeyType.OKP)
                .keyID(header.getKeyID())
                .keyUses(KeyUse.SIGNATURE, null)
                .algorithms(JWSAlgorithm.EdDSA, null)
                .curves(Curve.Ed25519, Curve.Ed448)
                .build();
        JWKSelector selector = new JWKSelector(matcher);

        OctetKeyPair fastKey = selectFromCache(selector);
        if (fastKey != null) {
            return fastKey;
        }

        refreshLock.lock();
        try {
            OctetKeyPair recheckKey = selectFromCache(selector);
            if (recheckKey != null) {
                return recheckKey;
            }

            List<JWK> matches;
            try {
                matches = jwkSource.get(selector, null);
            } catch (KeySourceException e) {
                throw new AuthError("JWKS fetch failed: " + e.getMessage());
            }

            OctetKeyPair key = firstOctetKeyPair(matches);
            if (key == null) {
                throw new AuthError("no matching EdDSA key found in JWKS (kid=" + header.getKeyID() + ")");
            }
            return key;
        } finally {
            refreshLock.unlock();
        }
    }

    /**
     * Matches {@code selector} against whatever is currently in
     * {@link RemoteJWKSet#getCachedJWKSet()} WITHOUT triggering a network
     * fetch (returns {@code null} on a cold/empty cache or no match).
     */
    private OctetKeyPair selectFromCache(JWKSelector selector) {
        com.nimbusds.jose.jwk.JWKSet cached = jwkSource.getCachedJWKSet();
        if (cached == null) {
            return null;
        }
        return firstOctetKeyPair(selector.select(cached));
    }

    private static OctetKeyPair firstOctetKeyPair(List<JWK> jwks) {
        for (JWK jwk : jwks) {
            if (jwk instanceof OctetKeyPair okp) {
                return okp;
            }
        }
        return null;
    }

    /**
     * The MUST-carry-forward cross-tenant control (T-20-07): the JWKS
     * endpoint is organization-wide, so signature validity alone does not
     * imply the token belongs to the caller's configured tenant. Throws if
     * the token's {@code tenant_id} claim is absent or does not match
     * {@code configuredTenantId}.
     *
     * @throws AuthError if {@code tenant_id} is missing or mismatched
     */
    public static void assertTenant(JWTClaimsSet claims, String configuredTenantId) {
        String tenantId;
        try {
            tenantId = claims.getStringClaim("tenant_id");
        } catch (ParseException e) {
            throw new AuthError("token tenant_id claim is malformed");
        }
        if (tenantId == null || !tenantId.equals(configuredTenantId)) {
            throw new AuthError("token tenant_id does not match the configured tenant");
        }
    }
}
