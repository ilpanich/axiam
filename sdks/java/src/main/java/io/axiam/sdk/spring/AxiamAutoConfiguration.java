package io.axiam.sdk.spring;

import io.axiam.sdk.internal.JwksVerifier;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Zero-config Spring Boot auto-registration for {@link AxiamAuthenticationFilter}
 * (D-15, RESEARCH.md Pattern 9). Registered via {@code
 * META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports}
 * (the Spring Boot 3.x mechanism; NOT the legacy {@code spring.factories}
 * path).
 *
 * <p>{@code @ConditionalOnClass(SecurityFilterChain.class)} keeps this
 * configuration inert unless Spring Security is actually on the classpath —
 * combined with the {@code provided}/{@code optional} Spring dependencies in
 * {@code pom.xml}, a non-Spring consumer's classpath is never affected.
 *
 * <p>Reads {@code axiam.base-url} and {@code axiam.tenant-id} from the
 * Spring {@code Environment} to build a default {@link AxiamAuthenticationFilter}
 * and, if the consuming application has not defined its OWN
 * {@link SecurityFilterChain} bean, a default one that requires
 * authentication for every request via that filter. Both beans are
 * {@code @ConditionalOnMissingBean} — a consumer who wires the filter
 * explicitly in their own {@code SecurityFilterChain} (the example app's
 * pattern, 20-09) takes precedence and this auto-configuration yields
 * entirely (D-15's "explicit example + zero-config convenience").
 */
@AutoConfiguration
@ConditionalOnClass(SecurityFilterChain.class)
public class AxiamAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(AxiamAuthenticationFilter.class)
    public AxiamAuthenticationFilter axiamAuthenticationFilter(
            @Value("${axiam.base-url}") String baseUrl, @Value("${axiam.tenant-id}") String tenantId) {
        return new AxiamAuthenticationFilter(new JwksVerifier(baseUrl), tenantId);
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain axiamSecurityFilterChain(HttpSecurity http, AxiamAuthenticationFilter filter)
            throws Exception {
        http
                // AXIAM's own X-CSRF-Token/cookie double-submit (CONTRACT.md
                // §3) supersedes Spring's default CSRF token — do not
                // double-protect (RESEARCH.md Pattern 8 example comment).
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
