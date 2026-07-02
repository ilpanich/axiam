using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Axiam.Sdk.Auth;

/// <summary>
/// Local EdDSA (Ed25519) JWKS verification (D-02, CONTRACT.md &#167;10 local-verification
/// fast path). .NET has no native Ed25519/EdDSA support anywhere in
/// <c>System.Security.Cryptography</c> (confirmed research finding — <c>dotnet/runtime</c>
/// #14741/#63174 remain unimplemented through .NET 10 GA), so this class uses
/// <c>BouncyCastle.Cryptography</c>'s <see cref="Ed25519Signer"/> /
/// <see cref="Ed25519PublicKeyParameters"/> directly — the single, well-vetted,
/// verify-only crypto dependency D-02 permits.
/// </summary>
/// <remarks>
/// Security-critical invariants (T-21-06, T-21-07):
/// <list type="bullet">
/// <item>
/// <description>
/// <c>alg</c> is pinned to <c>"EdDSA"</c> and checked BEFORE any key (<c>kid</c>) lookup —
/// the token's own header is never trusted to select its verifier (alg-confusion
/// defense).
/// </description>
/// </item>
/// <item>
/// <description>
/// AFTER signature verification succeeds, the <c>tenant_id</c> claim is checked against
/// the caller-supplied expected tenant. The JWKS document is organization-wide, not
/// tenant-scoped, so a valid signature alone never implies tenant authorization
/// (Pitfall 3 — independently confirmed by every sibling SDK).
/// </description>
/// </item>
/// <item>
/// <description>
/// <see cref="VerifyAsync"/> NEVER throws for attacker-controlled input — every failure
/// mode (bad alg, unknown kid, tampered/invalid signature, wrong tenant, expired token,
/// malformed/non-base64/truncated token) returns <c>null</c>. This matches the AMQP
/// HMAC verifier's fail-closed convention (<c>Amqp/Hmac.cs</c>).
/// </description>
/// </item>
/// </list>
/// </remarks>
public sealed class JwksVerifier
{
    private readonly HttpClient _http;
    private readonly Uri _jwksUri;
    private readonly TimeSpan _cacheTtl;

    private Dictionary<string, byte[]> _keysByKid = new();
    private DateTimeOffset _fetchedAt = DateTimeOffset.MinValue;

    /// <param name="httpClient">Used only to fetch the JWKS document; ownership stays with the caller.</param>
    /// <param name="baseUrl">The AXIAM server base URL; the JWKS path is resolved relative to it.</param>
    /// <param name="cacheTtl">How long a fetched JWKS document is trusted before a refetch is forced.</param>
    public JwksVerifier(HttpClient httpClient, Uri baseUrl, TimeSpan cacheTtl)
    {
        _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        ArgumentNullException.ThrowIfNull(baseUrl);
        // NOT /.well-known/jwks.json — AXIAM does not serve that path
        // (crates/axiam-api-rest/src/handlers/oauth2.rs: GET /oauth2/jwks, org-wide).
        _jwksUri = new Uri(baseUrl, "/oauth2/jwks");
        _cacheTtl = cacheTtl;
    }

    /// <summary>
    /// Verifies <paramref name="jwt"/>'s EdDSA signature against the cached (or freshly
    /// fetched) org-wide JWKS AND checks the mandatory <c>tenant_id</c> claim against
    /// <paramref name="expectedTenantId"/>. Returns the decoded claims payload on success;
    /// returns <c>null</c> for ANY failure. Never throws on malformed or attacker-controlled
    /// input — see the type-level remarks for the fail-closed contract.
    /// </summary>
    public async Task<JsonElement?> VerifyAsync(string jwt, string expectedTenantId, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrEmpty(jwt) || string.IsNullOrEmpty(expectedTenantId))
                return null;

            string[] parts = jwt.Split('.');
            if (parts.Length != 3 || Array.Exists(parts, string.IsNullOrEmpty))
                return null;

            byte[] headerJson = Base64UrlDecode(parts[0]);
            using JsonDocument header = JsonDocument.Parse(headerJson);

            // alg-pin BEFORE any key lookup — never let the token select its own verifier
            // (alg-confusion defense, T-21-06).
            if (!header.RootElement.TryGetProperty("alg", out JsonElement algEl) ||
                algEl.ValueKind != JsonValueKind.String ||
                algEl.GetString() != "EdDSA")
            {
                return null;
            }

            if (!header.RootElement.TryGetProperty("kid", out JsonElement kidEl) ||
                kidEl.ValueKind != JsonValueKind.String)
            {
                return null;
            }
            string? kid = kidEl.GetString();
            if (string.IsNullOrEmpty(kid))
                return null;

            await EnsureFreshAsync(kid, cancellationToken).ConfigureAwait(false);
            if (!_keysByKid.TryGetValue(kid, out byte[]? rawPublicKey))
                return null; // unknown kid even after the one refetch attempt above

            byte[] signingInput = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
            byte[] signature = Base64UrlDecode(parts[2]);

            var verifier = new Ed25519Signer();
            verifier.Init(forSigning: false, new Ed25519PublicKeyParameters(rawPublicKey));
            verifier.BlockUpdate(signingInput, 0, signingInput.Length);
            if (!verifier.VerifySignature(signature))
                return null;

            byte[] payloadJson = Base64UrlDecode(parts[1]);
            using JsonDocument payload = JsonDocument.Parse(payloadJson);
            JsonElement claims = payload.RootElement.Clone();

            // Mandatory cross-tenant check, performed AFTER signature verification
            // succeeds — a valid org-wide JWKS signature alone never authorizes a
            // specific tenant (T-21-07, Pitfall 3).
            if (!claims.TryGetProperty("tenant_id", out JsonElement tenantEl) ||
                tenantEl.ValueKind != JsonValueKind.String ||
                tenantEl.GetString() != expectedTenantId)
            {
                return null;
            }

            if (claims.TryGetProperty("exp", out JsonElement expEl) &&
                expEl.TryGetInt64(out long expSeconds) &&
                DateTimeOffset.FromUnixTimeSeconds(expSeconds) < DateTimeOffset.UtcNow)
            {
                return null; // expired — caller falls back to the reactive refresh path
            }

            return claims;
        }
        catch
        {
            // Fail closed on ANY malformed/attacker-controlled input (bad base64,
            // truncated/invalid JSON, wrong-length key, etc.) — never let a
            // parsing/crypto exception escape to the caller.
            return null;
        }
    }

    /// <summary>
    /// Refetches the JWKS document when the cache is stale OR <paramref name="unknownKid"/>
    /// is not already known — at most once per <see cref="VerifyAsync"/> call (no retry
    /// loop). Leaves the existing cache untouched if the fetch itself fails; the caller
    /// fails closed on the still-unknown <c>kid</c>.
    /// </summary>
    private async Task EnsureFreshAsync(string unknownKid, CancellationToken cancellationToken)
    {
        bool expired = DateTimeOffset.UtcNow - _fetchedAt > _cacheTtl;
        bool unknown = !_keysByKid.ContainsKey(unknownKid);
        if (!expired && !unknown)
            return;

        JwksDocument? document = await _http.GetFromJsonAsync<JwksDocument>(_jwksUri, cancellationToken).ConfigureAwait(false);
        if (document is null)
            return;

        var map = new Dictionary<string, byte[]>();
        foreach (Jwk jwk in document.Keys)
        {
            if (jwk.Kty != "OKP" || jwk.Crv != "Ed25519")
                continue; // ignore non-EdDSA entries defensively — alg is pinned by the caller too
            map[jwk.Kid] = Base64UrlDecode(jwk.X); // raw 32-byte Ed25519 public key
        }

        _keysByKid = map;
        _fetchedAt = DateTimeOffset.UtcNow;
    }

    private static byte[] Base64UrlDecode(string s)
    {
        string padded = s.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }
}
