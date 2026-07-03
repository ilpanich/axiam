package io.axiam.sdk.examples.loginmfa;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.AxiamUser;
import io.axiam.sdk.LoginResult;
import io.axiam.sdk.Sensitive;
import io.axiam.sdk.errors.AuthError;

/**
 * Demonstrates the two-phase {@code login()}/{@code verifyMfa()} flow
 * (CONTRACT.md &sect;1, &sect;5), importing ONLY public SDK entry points
 * ({@code io.axiam.sdk.AxiamClient} and friends — never {@code io.axiam.sdk.internal.*}).
 *
 * <p>Constructs an {@link AxiamClient} with a non-optional {@code tenantId}
 * (&sect;5 — there is no default tenant), calls {@link AxiamClient#login},
 * and branches on {@link LoginResult#mfaRequired()}: when the server
 * responds with an MFA challenge instead of a completed session, it calls
 * {@link AxiamClient#verifyMfa} with the {@link Sensitive}-wrapped challenge
 * token and a TOTP code to complete the flow.
 *
 * <p>This example is illustrative/compilable against the SDK's public API —
 * reads connection details from environment variables and requires a
 * reachable AXIAM server matching the configured base URL to run end-to-end.
 *
 * <p>Run: {@code AXIAM_BASE_URL=... AXIAM_TENANT_ID=... java LoginMfaExample.java}
 */
public final class LoginMfaExample {

    public static void main(String[] args) {
        String baseUrl = getenv("AXIAM_BASE_URL", "https://localhost:8443");
        String tenantId = getenv("AXIAM_TENANT_ID", "acme");
        String email = getenv("AXIAM_EMAIL", "user@example.com");
        String password = getenv("AXIAM_PASSWORD", "changeme");
        String totpCode = getenv("AXIAM_TOTP_CODE", "000000");

        // §5: tenantId is a required, positional builder argument — a blank
        // value throws AuthError, never a silent default. TLS is always
        // strict (§6) — the only escape hatch is Builder.customCa(pem),
        // never a boolean bypass. try-with-resources ensures the client's
        // OkHttp connection pool/dispatcher are released (AutoCloseable).
        try (AxiamClient client = AxiamClient.builder(baseUrl, tenantId).build()) {
            LoginResult result;
            try {
                result = client.login(email, password);
            } catch (AuthError e) {
                System.err.println("login failed: " + e.getMessage());
                return;
            }

            if (result.mfaRequired()) {
                System.out.println("MFA required — completing the two-phase flow");
                Sensitive challengeToken = result.challengeToken();
                // verifyMfa(mfaToken, code) completes the flow started by
                // login() when mfaRequired was true.
                LoginResult completed = client.verifyMfa(challengeToken, totpCode);
                AxiamUser user = completed.user();
                System.out.println("MFA verified — userId: " + user.userId()
                        + ", tenantId: " + user.tenantId() + ", roles: " + user.roles());
            } else {
                AxiamUser user = result.user();
                System.out.println("Login complete (no MFA) — userId: " + user.userId()
                        + ", tenantId: " + user.tenantId() + ", roles: " + user.roles());
            }
        }
    }

    private static String getenv(String key, String fallback) {
        String v = System.getenv(key);
        return (v == null || v.isBlank()) ? fallback : v;
    }

    private LoginMfaExample() {
    }
}
