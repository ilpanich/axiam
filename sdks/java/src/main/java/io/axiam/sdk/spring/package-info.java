/**
 * Optional Spring Security integration (D-14/D-15/D-16, CONTRACT.md
 * &sect;10 "Spring Boot" row).
 *
 * <p>{@link io.axiam.sdk.spring.AxiamAuthenticationFilter} is an
 * {@code OncePerRequestFilter} that extracts the bearer/cookie token,
 * verifies it locally via {@link io.axiam.sdk.internal.JwksVerifier},
 * enforces the MUST-carry-forward cross-tenant claim check, and populates
 * {@code SecurityContextHolder}.
 *
 * <p>{@link io.axiam.sdk.spring.AxiamAutoConfiguration} is the optional
 * zero-config registration path (D-15); the Spring Security dependencies
 * this package touches are {@code optional}/{@code provided} scope in
 * {@code pom.xml} so a non-Spring consumer never pulls them transitively.
 */
@NullMarked
package io.axiam.sdk.spring;

import org.jspecify.annotations.NullMarked;
