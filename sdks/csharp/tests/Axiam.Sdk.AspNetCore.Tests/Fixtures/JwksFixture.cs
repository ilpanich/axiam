using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace Axiam.Sdk.AspNetCore.Tests.Fixtures;

/// <summary>
/// Committed test helper — a copy of <c>sdks/csharp/tests/Axiam.Sdk.Tests/Fixtures/
/// JwksFixture.cs</c> (21-01) in this test project's own namespace, rather than a
/// fragile test-project-to-test-project <c>ProjectReference</c>. Generates a real
/// Ed25519 keypair via BouncyCastle, builds an AXIAM-shaped JWKS document
/// (<c>kty=OKP</c>, <c>crv=Ed25519</c>, <c>x</c> = base64url raw 32-byte public key,
/// deterministic <c>kid</c>), and signs an AXIAM-shaped JWT (header
/// <c>alg=EdDSA</c>/<c>kid</c>; payload <c>sub</c>/<c>tenant_id</c>/<c>roles</c>/
/// <c>exp</c>) using <see cref="Ed25519Signer"/> with <c>forSigning: true</c> —
/// intentionally independent of <c>AxiamAuthMiddleware</c>'s (via
/// <c>AxiamClient.JwksVerifier</c>) verify path (<c>forSigning: false</c>), so tests
/// built on this fixture are NOT a vacuous self-round-trip.
/// </summary>
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

        // Deterministic kid derived from the public key bytes — mirrors the AXIAM
        // server's first-16-hex(SHA256(rawkey)) shape (21-RESEARCH.md Pattern 1).
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

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
