package io.axiam.example.springboot;

import io.axiam.sdk.internal.JwksVerifier;
import io.axiam.sdk.spring.AxiamAuthenticationFilter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Explicit {@link SecurityFilterChain} wiring (RESEARCH.md Pattern 8, D-15's
 * "explicit example + zero-config convenience" pairing — this class takes
 * precedence over {@code AxiamAutoConfiguration}'s
 * {@code @ConditionalOnMissingBean} defaults precisely because it defines
 * its own {@link AxiamAuthenticationFilter} and {@link SecurityFilterChain}
 * beans).
 *
 * <p>Constructs ONE {@link JwksVerifier} against the configured AXIAM
 * {@code axiam.base-url}, builds an {@link AxiamAuthenticationFilter} bound
 * to {@code axiam.tenant-id}, disables Spring Security's own CSRF protection
 * (this app has no Spring session-cookie auth for it to protect — it's the
 * one AxiamAuthenticationFilter targets, and Spring's CSRF filter would 403
 * legitimate Bearer-token requests, which never carry a Spring CSRF token;
 * {@link AxiamAuthenticationFilter} enforces its OWN cookie double-submit
 * check, {@code X-CSRF-Token} vs {@code axiam_csrf}, CONTRACT.md &sect;3, for
 * any request authenticated via the {@code axiam_access} cookie — see the
 * filter's class Javadoc), permits {@code /public/**}, requires
 * authentication for everything else, and inserts the AXIAM filter
 * immediately before {@link UsernamePasswordAuthenticationFilter} in the
 * chain.
 */
@Configuration
public class SecurityConfig {

    @Bean
    public JwksVerifier jwksVerifier(@Value("${axiam.base-url}") String axiamBaseUrl) {
        return new JwksVerifier(axiamBaseUrl);
    }

    @Bean
    public AxiamAuthenticationFilter axiamAuthenticationFilter(
            JwksVerifier jwksVerifier, @Value("${axiam.tenant-id}") String axiamTenantId) {
        return new AxiamAuthenticationFilter(jwksVerifier, axiamTenantId);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AxiamAuthenticationFilter axiamAuthenticationFilter)
            throws Exception {
        http
                // See class Javadoc: AxiamAuthenticationFilter enforces its own
                // cookie double-submit CSRF check for axiam_access-cookie-sourced
                // requests, so Spring's CSRF filter (which targets a different
                // auth mechanism) is redundant and would break Bearer-token
                // clients.
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/public/**").permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(axiamAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                // Without an explicit AuthenticationEntryPoint, Spring
                // Security falls back to Http403ForbiddenEntryPoint for an
                // unauthenticated request to a protected resource (no
                // formLogin/httpBasic is configured here) — a REST API
                // MUST distinguish "no/invalid credentials" (401) from
                // "authenticated but forbidden" (403), matching this
                // filter's own writeJsonError contract.
                .exceptionHandling(handling -> handling.authenticationEntryPoint(
                        new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
        return http.build();
    }
}
