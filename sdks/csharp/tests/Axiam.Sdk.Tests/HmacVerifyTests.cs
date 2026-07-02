using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using Axiam.Sdk.Amqp;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Proves <see cref="Hmac.Verify"/> reproduces the server's byte-for-byte
/// wire-order canonical JSON HMAC-SHA256 (<c>sdks/CONTRACT.md</c> §8) against
/// the real, Rust-signed <c>Fixtures/amqp_hmac_vectors.json</c> vectors
/// (committed in 21-01, byte-identical to the Java sibling SDK's fixture).
/// </summary>
[Trait("Category", "Fast")]
public class HmacVerifyTests
{
    private static readonly string FixturePath =
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "amqp_hmac_vectors.json");

    private sealed record Vector(string Name, string SigningKeyHex, JsonObject Message, bool ExpectedValid);

    private static List<Vector> LoadVectors()
    {
        string json = File.ReadAllText(FixturePath);
        JsonObject root = JsonNode.Parse(json)!.AsObject();
        JsonArray vectors = root["vectors"]!.AsArray();

        var result = new List<Vector>();
        foreach (JsonNode? v in vectors)
        {
            JsonObject obj = v!.AsObject();
            result.Add(new Vector(
                obj["name"]!.GetValue<string>(),
                obj["signing_key_hex"]!.GetValue<string>(),
                obj["message"]!.AsObject().DeepClone().AsObject(),
                obj["expected_valid"]!.GetValue<bool>()));
        }

        return result;
    }

    /// <summary>
    /// Reconstructs the exact bytes that would arrive over the wire for a
    /// fixture vector's "message" object: compact (non-indented) JSON
    /// preserving the field order the fixture file recorded (Rust struct
    /// declaration order) — the same canonical form <see cref="Hmac.Verify"/>
    /// itself produces internally after removing <c>hmac_signature</c>.
    /// </summary>
    private static byte[] CanonicalBody(JsonObject message) => Encoding.UTF8.GetBytes(message.ToJsonString());

    private static Vector Find(List<Vector> vectors, string name) => vectors.Single(v => v.Name == name);

    [Fact]
    public void AllFixtureVectors_VerifyMatchesExpectedValidity()
    {
        foreach (Vector vector in LoadVectors())
        {
            byte[] key = Convert.FromHexString(vector.SigningKeyHex);
            byte[] body = CanonicalBody(vector.Message);

            bool actual = Hmac.Verify(key, body);

            Assert.True(
                actual == vector.ExpectedValid,
                $"vector '{vector.Name}' expected {vector.ExpectedValid} but Hmac.Verify returned {actual}");
        }
    }

    [Fact]
    public void TamperedSignature_FailsVerification_NonVacuous()
    {
        List<Vector> vectors = LoadVectors();
        Vector valid = Find(vectors, "authz_request_valid");
        Vector tampered = Find(vectors, "authz_request_tampered_action");

        byte[] key = Convert.FromHexString(valid.SigningKeyHex);

        // Confirm the baseline verifies true first — otherwise the tampered
        // assertion below would be vacuously true for the wrong reason.
        Assert.True(Hmac.Verify(key, CanonicalBody(valid.Message)), "baseline vector must verify true");
        Assert.False(Hmac.Verify(key, CanonicalBody(tampered.Message)), "tampered-action vector must verify false");
    }

    [Fact]
    public void WrongKey_FailsVerification_NonVacuous()
    {
        List<Vector> vectors = LoadVectors();
        Vector valid = Find(vectors, "audit_event_valid");
        Vector wrongKey = Find(vectors, "audit_event_wrong_key");

        byte[] correctKey = Convert.FromHexString(valid.SigningKeyHex);
        byte[] incorrectKey = Convert.FromHexString(wrongKey.SigningKeyHex);
        byte[] body = CanonicalBody(valid.Message);

        Assert.True(Hmac.Verify(correctKey, body), "baseline vector must verify true with its own key");
        Assert.False(Hmac.Verify(incorrectKey, body), "same body/signature must verify false under a different key");
    }

    [Fact]
    public void MissingHmacSignature_FailsClosed()
    {
        Vector vector = Find(LoadVectors(), "missing_hmac_signature");
        byte[] key = Convert.FromHexString(vector.SigningKeyHex);

        Assert.False(Hmac.Verify(key, CanonicalBody(vector.Message)));
    }

    [Fact]
    public void NonHexSignature_FailsClosed_WithoutThrowing()
    {
        Vector vector = Find(LoadVectors(), "non_hex_signature");
        byte[] key = Convert.FromHexString(vector.SigningKeyHex);

        Assert.False(Hmac.Verify(key, CanonicalBody(vector.Message)));
    }

    [Fact]
    public void WrongLengthSignature_FailsClosed_WithoutThrowing()
    {
        Vector vector = Find(LoadVectors(), "wrong_length_signature");
        byte[] key = Convert.FromHexString(vector.SigningKeyHex);

        Assert.False(Hmac.Verify(key, CanonicalBody(vector.Message)));
    }

    [Fact]
    public void MalformedInput_NeverThrows_ReturnsFalse()
    {
        byte[] key = { 1, 2, 3, 4 };

        Assert.False(Hmac.Verify(key, Encoding.UTF8.GetBytes("not json at all")));
        Assert.False(Hmac.Verify(key, Array.Empty<byte>()));
        Assert.False(Hmac.Verify(key, Encoding.UTF8.GetBytes("[1,2,3]"))); // valid JSON, not an object
    }
}
