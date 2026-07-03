using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace Axiam.Sdk.Tests.Fixtures;

/// <summary>
/// Committed test helper that generates a real Ed25519 keypair via BouncyCastle, builds
/// an AXIAM-shaped JWKS document (<c>kty=OKP</c>, <c>crv=Ed25519</c>, <c>x</c> = base64url
/// raw 32-byte public key, deterministic <c>kid</c>), and signs an AXIAM-shaped JWT
/// (header <c>alg=EdDSA</c>/<c>kid</c>; payload <c>sub</c>/<c>tenant_id</c>/<c>roles</c>/
/// <c>exp</c>) using <see cref="Ed25519Signer"/> with <c>forSigning: true</c>.
/// </summary>
/// <remarks>
/// This signer path is intentionally independent of the SDK's (future) <c>JwksVerifier</c>
/// verify path (which will use <c>Ed25519Signer</c> with <c>forSigning: false</c>) — tests
/// built on this fixture are NOT a vacuous self-round-trip; they exercise a real signature
/// produced by a code path the SDK's own verifier never touches.
/// </remarks>
public sealed class JwksFixture
{
    public Ed25519PrivateKeyParameters PrivateKey { get; }
    public Ed25519PublicKeyParameters PublicKey { get; }
    public string Kid { get; }

    public JwksFixture()
    {
        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();
        PrivateKey = (Ed25519PrivateKeyParameters)pair.Private;
        PublicKey = (Ed25519PublicKeyParameters)pair.Public;

        // Deterministic kid derived from the public key bytes — mirrors the AXIAM server's
        // first-16-hex(SHA256(rawkey)) shape (21-RESEARCH.md Pattern 1).
        Kid = Convert.ToHexString(SHA256.HashData(PublicKey.GetEncoded()))[..16].ToLowerInvariant();
    }

    /// <summary>Builds the AXIAM-shaped JWKS document containing this fixture's public key.</summary>
    public string BuildJwksDocument()
    {
        var jwk = new
        {
            kty = "OKP",
            crv = "Ed25519",
            x = Base64UrlEncode(PublicKey.GetEncoded()),
            kid = Kid,
            use = "sig",
            alg = "EdDSA",
        };
        return JsonSerializer.Serialize(new { keys = new[] { jwk } });
    }

    /// <summary>
    /// Signs an AXIAM-shaped JWT via BouncyCastle's <see cref="Ed25519Signer"/> with
    /// <c>forSigning: true</c> — never via the SDK's own verifier.
    /// </summary>
    public string SignJwt(string subject, string tenantId, string[] roles, DateTimeOffset expiresAt, string? kidOverride = null)
    {
        var header = new { alg = "EdDSA", kid = kidOverride ?? Kid };
        var payload = new
        {
            sub = subject,
            tenant_id = tenantId,
            roles,
            exp = expiresAt.ToUnixTimeSeconds(),
        };
        string headerB64 = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(header));
        string payloadB64 = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(payload));
        byte[] signingInput = Encoding.ASCII.GetBytes($"{headerB64}.{payloadB64}");

        var signer = new Ed25519Signer();
        signer.Init(forSigning: true, PrivateKey);
        signer.BlockUpdate(signingInput, 0, signingInput.Length);
        byte[] signature = signer.GenerateSignature();

        return $"{headerB64}.{payloadB64}.{Base64UrlEncode(signature)}";
    }

    /// <summary>
    /// Mints a JWT identical to <see cref="SignJwt"/> but with the last signature byte
    /// flipped — MUST fail verification in the consuming SDK's future JwksVerifier tests.
    /// </summary>
    public string SignJwtWithTamperedSignature(string subject, string tenantId, string[] roles, DateTimeOffset expiresAt)
    {
        string valid = SignJwt(subject, tenantId, roles, expiresAt);
        string[] parts = valid.Split('.');
        byte[] sig = Base64UrlDecode(parts[2]);
        sig[^1] ^= 0xFF;
        return $"{parts[0]}.{parts[1]}.{Base64UrlEncode(sig)}";
    }

    /// <summary>
    /// Mints a validly-signed JWT for a tenant other than the one the caller will check
    /// against — proves signature validity alone does not imply tenant authorization
    /// (JWKS is organization-wide, not tenant-scoped; 21-RESEARCH.md Pitfall 3).
    /// </summary>
    public string SignJwtForTenant(string subject, string actualTenantId, string[] roles, DateTimeOffset expiresAt) =>
        SignJwt(subject, actualTenantId, roles, expiresAt);

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

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
