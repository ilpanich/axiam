using Axiam.Sdk.Core;

namespace Axiam.Sdk.Auth;

/// <summary>
/// An access/refresh token pair with an expiry timestamp. Both token values are wrapped
/// in <see cref="Sensitive{T}"/> (CONTRACT.md &#167;7, D-12) so neither can leak via
/// <see cref="object.ToString"/>, JSON serialization, or a log call.
/// </summary>
public sealed record TokenPair(
    Sensitive<string> AccessToken,
    Sensitive<string> RefreshToken,
    DateTimeOffset ExpiresAt);
