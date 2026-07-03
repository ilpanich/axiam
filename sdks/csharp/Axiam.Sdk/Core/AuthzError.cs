namespace Axiam.Sdk.Core;

/// <summary>
/// Authorization failure: the caller lacks permission for the requested operation
/// (CONTRACT.md &#167;2, D-12). Always constructed via <see cref="ErrorMapper"/> so REST
/// and gRPC transports cannot drift on the error taxonomy.
/// </summary>
public sealed class AuthzError : Exception
{
    public AuthzError(string message) : base(message)
    {
    }
}
