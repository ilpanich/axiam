package io.axiam.example.springboot;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A protected endpoint guarded by {@link SecurityConfig}'s
 * {@code SecurityFilterChain}: reachable only after
 * {@link io.axiam.sdk.spring.AxiamAuthenticationFilter} has populated
 * {@code SecurityContextHolder} (SC#3).
 */
@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello(Authentication authentication) {
        return "Hello, " + authentication.getName() + "!";
    }
}
