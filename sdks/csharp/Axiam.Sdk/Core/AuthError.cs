namespace Axiam.Sdk.Core;

/// <summary>
/// Authentication failure: wrong credentials, expired session, MFA failure, or a 401 on
/// refresh (CONTRACT.md &#167;2, D-12). Always constructed via <see cref="ErrorMapper"/>
/// so REST and gRPC transports cannot drift on the error taxonomy.
/// </summary>
public sealed class AuthError : Exception
{
    public AuthError(string message) : base(message)
    {
    }
}
