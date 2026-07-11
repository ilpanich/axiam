package io.axiam.sdk.spring;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import com.nimbusds.jwt.JWTClaimsSet;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.AuthzError;
import io.axiam.sdk.internal.JwksVerifier;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * Spring Security {@code OncePerRequestFilter} that locally verifies the
 * bearer/cookie token, enforces the MUST-carry-forward cross-tenant claim
 * check, and populates {@code SecurityContextHolder} (D-14, CONTRACT.md
 * &sect;10 "Spring Boot" row).
 *
 * <p><strong>Sequence</strong> (RESEARCH.md Pattern 8, mirrors
 * {@code sdks/go/middleware/nethttp.go}'s extract &rarr; verify &rarr; exp
 * check &rarr; cross-tenant check &rarr; inject-identity &rarr; 401/403 JSON):
 * {@link #extractToken(HttpServletRequest)} reads the {@code Authorization:
 * Bearer} header first, then the {@code axiam_access} cookie. When no
 * credentials are presented, the request is passed through unauthenticated
 * — Spring Security's own {@code authorizeHttpRequests} rules 401/403 it.
 * When a token IS presented: {@link JwksVerifier#verify(String)} checks the
 * signature (EdDSA-pinned, key sourced from the cached/rotated JWKS); an
 * explicit {@code exp} check rejects a signature-valid but expired token
 * (the resource-server trust boundary must not trust an expired token even
 * though {@link JwksVerifier#verify(String)} does not itself check expiry);
 * {@link JwksVerifier#assertTenant(JWTClaimsSet, String)} enforces the
 * cross-tenant claim check (T-20-07) — the JWKS is organization-wide, so
 * signature validity alone never implies tenant authorization. On success,
 * an {@code Authentication} is built from the verified subject and
 * scope-derived authorities and set on {@code SecurityContextHolder}.
 *
 * <p>{@link AuthError} maps to HTTP 401, {@link AuthzError} maps to HTTP
 * 403, both via a standardized JSON error body ({@link #writeJsonError}) —
 * the wrapped filter chain is never invoked on failure.
 *
 * <p><strong>CSRF (cookie double-submit, CONTRACT.md &sect;3):</strong> when
 * the credential was sourced from the {@code axiam_access} COOKIE (not the
 * {@code Authorization} header) and the request method is state-changing
 * (anything other than GET/HEAD/OPTIONS), this filter additionally requires
 * the {@code X-CSRF-Token} request header to be present and equal (constant
 * time) to the {@code axiam_csrf} cookie value, rejecting with 403 on
 * mismatch/absence. Bearer-header requests are CSRF-immune by construction
 * — a cross-site attacker cannot set arbitrary request headers — but a
 * cookie automatically attached by the browser is not, and in any
 * same-site deployment where {@code axiam_access} reaches this app, the
 * non-{@code httpOnly} {@code axiam_csrf} cookie does too. This mirrors,
 * locally, the same double-submit check the AXIAM server performs on its
 * own endpoints (&sect;3) — {@code AxiamAutoConfiguration} disables Spring
 * Security's own CSRF filter specifically because this filter now covers
 * that ground for cookie-sourced requests.
 */
public final class AxiamAuthenticationFilter extends OncePerRequestFilter {

    private static final String ACCESS_COOKIE_NAME = "axiam_access";
    private static final String CSRF_COOKIE_NAME = "axiam_csrf";
    private static final String CSRF_HEADER_NAME = "X-CSRF-Token";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final JwksVerifier jwksVerifier;
    private final String configuredTenantId;

    public AxiamAuthenticationFilter(JwksVerifier jwksVerifier, String configuredTenantId) {
        this.jwksVerifier = jwksVerifier;
        this.configuredTenantId = configuredTenantId;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Credential credential = extractToken(request);
        if (credential == null) {
            // No credentials presented; let the request through unauthenticated
            // — Spring Security's own access-control rules 401/403 it.
            chain.doFilter(request, response);
            return;
        }

        if (credential.fromCookie() && !SAFE_METHODS.contains(request.getMethod().toUpperCase(java.util.Locale.ROOT))
                && !isCsrfValid(request)) {
            writeJsonError(response, HttpServletResponse.SC_FORBIDDEN, "csrf_validation_failed");
            return;
        }

        String token = credential.value();
        try {
            JWTClaimsSet claims = jwksVerifier.verify(token); // signature + alg=EdDSA pinned

            Date expiration = claims.getExpirationTime();
            if (expiration != null && expiration.before(new Date())) {
                throw new AuthError("token expired");
            }

            // MUST-carry-forward cross-tenant control (T-20-07): the JWKS is
            // organization-wide, so signature validity alone does not imply
            // tenant authorization.
            JwksVerifier.assertTenant(claims, configuredTenantId);

            List<GrantedAuthority> authorities = scopeToAuthorities(claims);
            var authentication = new UsernamePasswordAuthenticationToken(claims.getSubject(), null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        } catch (AuthzError e) {
            writeJsonError(response, HttpServletResponse.SC_FORBIDDEN, e.getMessage());
        } catch (AuthError e) {
            writeJsonError(response, HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
        } catch (RuntimeException e) {
            // Any other verification failure (malformed claims, etc.) is an
            // authentication failure — never let an unexpected exception
            // fall through to an authenticated SecurityContext.
            writeJsonError(response, HttpServletResponse.SC_UNAUTHORIZED, "invalid or expired token");
        }
    }

    /** Maps the space-separated {@code scope} claim to Spring {@link GrantedAuthority} instances. */
    private static List<GrantedAuthority> scopeToAuthorities(JWTClaimsSet claims) {
        String scope;
        try {
            scope = claims.getStringClaim("scope");
        } catch (ParseException e) {
            scope = null;
        }
        if (scope == null || scope.isBlank()) {
            return List.of();
        }
        List<GrantedAuthority> authorities = new ArrayList<>();
        for (String s : scope.split(" ")) {
            if (!s.isBlank()) {
                authorities.add(new SimpleGrantedAuthority(s));
            }
        }
        return authorities;
    }

    /** Bearer header first, then the {@code axiam_access} cookie; {@code null} when neither is present. */
    private static @Nullable Credential extractToken(HttpServletRequest request) {
        String auth = request.getHeader("Authorization");
        if (auth != null && auth.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            String credentials = auth.substring(BEARER_PREFIX.length()).trim();
            if (!credentials.isEmpty()) {
                return new Credential(credentials, false);
            }
        }
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie c : cookies) {
                if (ACCESS_COOKIE_NAME.equals(c.getName()) && !c.getValue().isEmpty()) {
                    return new Credential(c.getValue(), true);
                }
            }
        }
        return null;
    }

    /** A verified-candidate token plus whether it was sourced from the {@code axiam_access} cookie. */
    private record Credential(String value, boolean fromCookie) {}

    /**
     * Cookie double-submit check (CONTRACT.md &sect;3): the {@code X-CSRF-Token} header
     * must be present and equal, constant-time, to the {@code axiam_csrf} cookie value.
     */
    private static boolean isCsrfValid(HttpServletRequest request) {
        String header = request.getHeader(CSRF_HEADER_NAME);
        if (header == null || header.isEmpty()) {
            return false;
        }
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return false;
        }
        for (Cookie c : cookies) {
            if (CSRF_COOKIE_NAME.equals(c.getName())) {
                return MessageDigest.isEqual(
                        header.getBytes(StandardCharsets.UTF_8), c.getValue().getBytes(StandardCharsets.UTF_8));
            }
        }
        return false;
    }

    /**
     * Writes a standardized JSON error body via Jackson (not manual string
     * concatenation) so an error message containing quotes/control
     * characters can never produce malformed or injected JSON.
     */
    private static void writeJsonError(HttpServletResponse response, int status, @Nullable String message)
            throws IOException {
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        ObjectNode body = MAPPER.createObjectNode();
        body.put("error", status == HttpServletResponse.SC_FORBIDDEN ? "authorization_denied" : "authentication_failed");
        body.put("message", message == null ? "invalid or expired token" : message);
        response.getWriter().write(MAPPER.writeValueAsString(body));
    }
}
