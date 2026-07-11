namespace Axiam.Sdk.Core;

/// <summary>
/// Authorization failure: the caller lacks permission for the requested operation
/// (CONTRACT.md &#167;2, D-12). Always constructed via <see cref="ErrorMapper"/> so REST
/// and gRPC transports cannot drift on the error taxonomy.
/// </summary>
public sealed class AuthzError : Exception
{
    /// <summary>
    /// The denied action (e.g. <c>"users:get"</c>), when known. Populated from the
    /// server's structured 403 body's <c>action</c> field (CONTRACT.md &#167;2: AuthzError
    /// SHOULD carry the denied action/resource_id if available). Null when the transport
    /// has no body to parse (gRPC <c>PERMISSION_DENIED</c>) or the field was absent.
    /// </summary>
    public string? Action { get; }

    /// <summary>
    /// The resource UUID the denial was scoped to. Populated from the server's
    /// structured 403 body's <c>resource_id</c> field — present only for a
    /// resource-scoped denial. Null for a non-resource-scoped denial or when the
    /// transport has no body to parse (gRPC <c>PERMISSION_DENIED</c>).
    /// </summary>
    public string? ResourceId { get; }

    /// <summary>
    /// Constructs a message-only <see cref="AuthzError"/> — <see cref="Action"/> and
    /// <see cref="ResourceId"/> are left null. Used when no structured 403 body was
    /// available to parse (e.g. gRPC <c>PERMISSION_DENIED</c>, which carries no body).
    /// </summary>
    /// <param name="message">Describes the authorization failure (CONTRACT.md &#167;2 MUST).</param>
    public AuthzError(string message) : base(message)
    {
    }

    /// <summary>
    /// Constructs an <see cref="AuthzError"/> carrying the structured <c>action</c>/
    /// <c>resource_id</c> fields parsed from the server's 403 <c>authorization_denied</c>
    /// body by <see cref="ErrorMapper"/>. Either may be null — <c>action</c> when not
    /// known, <c>resourceId</c> when the denial was not resource-scoped.
    /// </summary>
    public AuthzError(string message, string? action, string? resourceId) : base(message)
    {
        Action = action;
        ResourceId = resourceId;
    }
}
