using Axiam.Sdk.Core;

namespace Axiam.Sdk.Auth;

/// <summary>
/// Outcome of <c>LoginAsync</c>/<c>VerifyMfaAsync</c> (CONTRACT.md &#167;1). MFA-required
/// is an expected outcome represented as a flag — never thrown as an exception: callers
/// MUST check <see cref="MfaRequired"/> before assuming a session was established.
/// Mirrors the Java sibling's <c>LoginResult</c> (20-03) field shape.
/// </summary>
/// <param name="MfaRequired">
/// <c>true</c> when the server responded with an MFA challenge instead of a completed
/// login.
/// </param>
/// <param name="ChallengeToken">
/// The opaque MFA challenge token to pass to <c>VerifyMfaAsync</c>; populated only when
/// <paramref name="MfaRequired"/> is <c>true</c>. Wrapped in <see cref="Sensitive{T}"/>
/// per CONTRACT.md &#167;7's blanket token-field rule — every token-carrying field in the
/// SDK is redacted from <see cref="object.ToString"/>/JSON/logs, with no single field
/// exempted as "not sensitive enough."
/// </param>
public sealed record LoginResult(bool MfaRequired, Sensitive<string>? ChallengeToken = null);
