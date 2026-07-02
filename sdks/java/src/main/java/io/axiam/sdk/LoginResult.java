package io.axiam.sdk;

import org.jspecify.annotations.Nullable;

/**
 * Outcome of {@code login()}/{@code verifyMfa()} (D-03/D-04, CONTRACT.md
 * &sect;1). MFA-required is an expected outcome, represented as a flag —
 * never thrown as an exception: callers MUST check {@link #mfaRequired()}
 * before assuming a session was established.
 *
 * @param mfaRequired    {@code true} when the server responded with an MFA
 *                       challenge instead of a completed login
 * @param challengeToken the opaque, sensitive MFA challenge token to pass to
 *                       {@code verifyMfa()}; populated only when
 *                       {@code mfaRequired} is {@code true}
 * @param user           the authenticated user; populated only on a
 *                       completed (non-MFA-pending) login/verifyMfa
 */
public record LoginResult(boolean mfaRequired, @Nullable Sensitive challengeToken, @Nullable AxiamUser user) {
}
