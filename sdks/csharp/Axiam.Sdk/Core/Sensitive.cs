using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization;

// Grants the Wave 0 test project access to internal-only members (Sensitive<T>'s
// internal constructor/Reveal(), the internal Sensitive.Of<T> factory) so
// SensitiveRedactionTests can exercise the redaction behavior directly without
// widening any public surface (CONTRACT.md §7 requires these stay internal-only).
[assembly: InternalsVisibleTo("Axiam.Sdk.Tests")]

// 21-06: grants the Axiam.Sdk.AspNetCore companion package access to AxiamClient's
// internal seam (specifically JwksVerifier — AxiamAuthMiddleware's local
// verification fast path, D-06/§10) without widening any public surface. Also
// grants the Axiam.Sdk.AspNetCore.Tests project access to the internal
// AxiamClient.CreateForTesting(...) seam so the SC#3 WebApplicationFactory
// integration test can point the middleware's JwksVerifier/Authz client at a fake
// transport instead of a real socket (mirrors the exact same test-only seam
// Axiam.Sdk.Tests already uses).
[assembly: InternalsVisibleTo("Axiam.Sdk.AspNetCore")]
[assembly: InternalsVisibleTo("Axiam.Sdk.AspNetCore.Tests")]

namespace Axiam.Sdk.Core;

/// <summary>
/// Wraps a token-carrying value so it can never be accidentally exposed via
/// <see cref="object.ToString"/>, <c>System.Text.Json</c> serialization, or a public
/// getter (CONTRACT.md &#167;7, D-12). Only SDK-internal code may construct an instance
/// or read the wrapped value, via <see cref="Reveal"/> — there is intentionally no
/// public accessor.
/// </summary>
/// <remarks>
/// Per CONTRACT.md &#167;7's C# row ("Struct with <c>ToString()</c> override returning
/// <c>"[SENSITIVE]"</c>"): <see cref="ToString"/> and the paired
/// <see cref="SensitiveJsonConverter{T}"/> both always emit the literal
/// <c>"[SENSITIVE]"</c>, regardless of the wrapped value. <see cref="Equals(object?)"/>
/// and <see cref="GetHashCode"/> are intentionally NOT overridden to compare/hash the
/// wrapped value — the default reference-identity behavior for the boxed comparison
/// avoids opening a value-equality/timing side channel that could otherwise be used to
/// probe the redacted value.
/// </remarks>
[JsonConverter(typeof(SensitiveJsonConverter<>))]
public readonly struct Sensitive<T>
{
    private readonly T _value;

    /// <summary>Internal-only constructor — only SDK-internal code may wrap a value.</summary>
    internal Sensitive(T value) => _value = value;

    /// <summary>Internal-only accessor — never a public getter (CONTRACT.md &#167;7).</summary>
    internal T Reveal() => _value;

    /// <summary>Always returns the redacted literal, never the wrapped value.</summary>
    public override string ToString() => "[SENSITIVE]";
}

/// <summary>
/// Internal factory for <see cref="Sensitive{T}"/> — keeps every construction site
/// within the SDK's own assembly explicit and searchable.
/// </summary>
internal static class Sensitive
{
    internal static Sensitive<T> Of<T>(T value) => new(value);
}

/// <summary>
/// <c>System.Text.Json</c> converter for <see cref="Sensitive{T}"/>. Write always emits
/// the redacted literal; Read is intentionally unsupported — a <see cref="Sensitive{T}"/>
/// is a write-only-for-serialization type, so no wire format can ever deserialize a real
/// value back into one.
/// </summary>
public sealed class SensitiveJsonConverter<T> : JsonConverter<Sensitive<T>>
{
    public override Sensitive<T> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => throw new NotSupportedException("Sensitive<T> is write-only for serialization.");

    public override void Write(Utf8JsonWriter writer, Sensitive<T> value, JsonSerializerOptions options)
        => writer.WriteStringValue("[SENSITIVE]");
}
