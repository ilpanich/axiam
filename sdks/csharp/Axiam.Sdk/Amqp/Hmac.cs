using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Axiam.Sdk.Amqp;

/// <summary>
/// HMAC-SHA256 verify-before-handler primitive for inbound AMQP messages
/// (<c>sdks/CONTRACT.md</c> §8, D-11).
///
/// <para>
/// <b>Canonicalization is wire/insertion-order preserving, NEVER
/// alphabetically sorted.</b> The canonical Rust signer
/// (<c>crates/axiam-amqp/src/messages.rs</c>'s <c>sign_payload</c>) signs the
/// <c>serde_json</c> struct-declaration-order serialization of the message
/// body (with <c>hmac_signature</c> absent). <see cref="JsonObject"/> is
/// backed by an ordered dictionary and preserves insertion order from
/// parsing by default — <see cref="JsonObject.Remove"/> mutates that same
/// ordered map in place, preserving the relative order of all remaining
/// keys. This is the single load-bearing property of this class: do NOT
/// introduce an alphabetized copy, <c>OrderBy</c>/<c>Sort</c>, or a POCO
/// deserialize-then-reserialize round-trip here — any of those would
/// silently reorder fields and break every cross-language HMAC
/// verification.
/// </para>
/// </summary>
public static class Hmac
{
    /// <summary>
    /// Returns <c>true</c> iff <paramref name="body"/>'s <c>hmac_signature</c>
    /// field matches HMAC-SHA256(<paramref name="signingKey"/>,
    /// canonical_json_of(body_without_hmac_signature)), computed via a
    /// constant-time comparison.
    ///
    /// <para>
    /// Never throws: malformed JSON, a missing/null signature, non-hex
    /// signature text, or a wrong-length signature all verify as
    /// <c>false</c> — matching §8.3's strict-mode default that rejects
    /// (rather than silently accepts) an unparseable or absent signature.
    /// </para>
    /// </summary>
    /// <param name="signingKey">The per-tenant AMQP HMAC signing secret (§8.1).</param>
    /// <param name="body">The raw AMQP delivery body bytes.</param>
    /// <returns><c>true</c> if the signature is valid, <c>false</c> otherwise.</returns>
    public static bool Verify(byte[] signingKey, byte[] body)
    {
        try
        {
            JsonObject? node = JsonNode.Parse(body)?.AsObject();
            if (node is null)
            {
                return false;
            }

            if (!node.TryGetPropertyValue("hmac_signature", out JsonNode? sigNode) || sigNode is null)
            {
                return false; // §8.3 strict mode: missing signature = reject
            }

            string sigHex = sigNode.GetValue<string>();

            // Remove() mutates the SAME ordered-dictionary-backed JsonObject in
            // place, preserving the relative order of all remaining keys — this
            // is the load-bearing property documented in the class remarks above.
            node.Remove("hmac_signature");
            byte[] canonical = Encoding.UTF8.GetBytes(node.ToJsonString());

            byte[] expected = Convert.FromHexString(sigHex);
            byte[] computed = HMACSHA256.HashData(signingKey, canonical);

            return computed.Length == expected.Length
                && CryptographicOperations.FixedTimeEquals(computed, expected);
        }
        catch
        {
            // Parse failure / bad hex / bad key / non-object body -> reject,
            // never throw. Attacker-controlled input must never crash the consumer.
            return false;
        }
    }
}
