package io.axiam.example.springboot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Complete, bootable Spring Boot 3.x application demonstrating explicit
 * {@link io.axiam.sdk.spring.AxiamAuthenticationFilter} wiring via a
 * {@link org.springframework.security.web.SecurityFilterChain} {@code @Bean}
 * (see {@link SecurityConfig}), proving CONTRACT.md &sect;10's Spring Boot
 * middleware row and Phase 20's SC#3 "complete working application context".
 */
@SpringBootApplication
public class SpringBootExampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringBootExampleApplication.class, args);
    }
}
