using System.Text.Json.Serialization;

namespace Axiam.Sdk.Auth;

/// <summary>
/// A single JSON Web Key from the AXIAM organization-wide JWKS document
/// (<c>GET /oauth2/jwks</c>). Shape confirmed against
/// <c>crates/axiam-oauth2/src/oidc.rs</c>: <c>kty=OKP</c>, <c>crv=Ed25519</c>,
/// <c>x</c> = base64url-encoded raw 32-byte Ed25519 public key, with a deterministic
/// <c>kid</c>. Property names are explicitly pinned via <see cref="JsonPropertyNameAttribute"/>
/// to the exact lowercase wire field names — never rely on a naming-policy convention.
/// </summary>
public sealed record Jwk(
    [property: JsonPropertyName("kty")] string Kty,
    [property: JsonPropertyName("crv")] string Crv,
    [property: JsonPropertyName("x")] string X,
    [property: JsonPropertyName("kid")] string Kid,
    [property: JsonPropertyName("use")] string? Use = null,
    [property: JsonPropertyName("alg")] string? Alg = null);

/// <summary>The JWKS document envelope returned by <c>GET /oauth2/jwks</c>: <c>{ "keys": [...] }</c>.</summary>
public sealed record JwksDocument(
    [property: JsonPropertyName("keys")] Jwk[] Keys);
