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
/// <c>"[SENSITIVE]"</c>, regardless of the wrapped value. <see cref="Equals(object?)"/>,
/// <see cref="IEquatable{T}.Equals(T)"/> and <see cref="GetHashCode"/> are overridden to
/// make a <see cref="Sensitive{T}"/> <b>never value-comparable</b>: <see cref="Equals(object?)"/>
/// always returns <c>false</c> and <see cref="GetHashCode"/> always returns a constant.
/// This is deliberate — the default <see cref="System.ValueType"/> equality a struct would
/// otherwise inherit performs a structural, field-by-field <em>value</em> comparison (via
/// reflection, and, for a <c>string</c> field, a non-constant-time <c>string.Equals</c>),
/// which would open a value-equality/timing side channel on the redacted value and would
/// transitively leak into any compiler-synthesized record equality of a type that carries
/// a <see cref="Sensitive{T}"/> field. Overriding to a constant closes that channel.
/// </remarks>
[JsonConverter(typeof(SensitiveJsonConverterFactory))]
public readonly struct Sensitive<T> : IEquatable<Sensitive<T>>
{
    private readonly T _value;

    /// <summary>Internal-only constructor — only SDK-internal code may wrap a value.</summary>
    internal Sensitive(T value) => _value = value;

    /// <summary>Internal-only accessor — never a public getter (CONTRACT.md &#167;7).</summary>
    internal T Reveal() => _value;

    /// <summary>Always returns the redacted literal, never the wrapped value.</summary>
    public override string ToString() => "[SENSITIVE]";

    /// <summary>
    /// A <see cref="Sensitive{T}"/> is intentionally never equal to anything — this
    /// suppresses the structural value comparison a struct would otherwise inherit from
    /// <see cref="System.ValueType"/>, which would be a value-equality/timing side channel
    /// on the wrapped secret.
    /// </summary>
    public bool Equals(Sensitive<T> other) => false;

    /// <inheritdoc cref="Equals(Sensitive{T})"/>
    public override bool Equals(object? obj) => false;

    /// <summary>Always returns a constant — never derives a hash from the wrapped value.</summary>
    public override int GetHashCode() => 0;

    /// <summary>Never equal (see <see cref="Equals(object?)"/>).</summary>
    public static bool operator ==(Sensitive<T> left, Sensitive<T> right) => false;

    /// <summary>Always unequal (see <see cref="Equals(object?)"/>).</summary>
    public static bool operator !=(Sensitive<T> left, Sensitive<T> right) => true;
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
/// Factory that produces the closed <see cref="SensitiveJsonConverter{T}"/> for a given
/// <see cref="Sensitive{T}"/>. An open-generic converter referenced from a
/// <see cref="JsonConverterAttribute"/> MUST be a <see cref="JsonConverterFactory"/>:
/// <c>System.Text.Json</c> cannot instantiate an open-generic <c>JsonConverter&lt;T&gt;</c>
/// directly (it throws because the type still contains generic parameters).
/// </summary>
public sealed class SensitiveJsonConverterFactory : JsonConverterFactory
{
    /// <inheritdoc />
    public override bool CanConvert(Type typeToConvert)
        => typeToConvert.IsGenericType
           && typeToConvert.GetGenericTypeDefinition() == typeof(Sensitive<>);

    /// <inheritdoc />
    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options)
    {
        Type valueType = typeToConvert.GetGenericArguments()[0];
        Type converterType = typeof(SensitiveJsonConverter<>).MakeGenericType(valueType);
        return (JsonConverter)Activator.CreateInstance(converterType)!;
    }
}

/// <summary>
/// <c>System.Text.Json</c> converter for <see cref="Sensitive{T}"/>. Write always emits
/// the redacted literal; Read is intentionally unsupported — a <see cref="Sensitive{T}"/>
/// is a write-only-for-serialization type, so no wire format can ever deserialize a real
/// value back into one.
/// </summary>
public sealed class SensitiveJsonConverter<T> : JsonConverter<Sensitive<T>>
{
    /// <summary>
    /// Always throws — a <see cref="Sensitive{T}"/> is write-only for serialization, so no
    /// wire format can ever deserialize a real value back into one (see type-level remarks).
    /// </summary>
    /// <exception cref="NotSupportedException">Always thrown; reading is never supported.</exception>
    public override Sensitive<T> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => throw new NotSupportedException("Sensitive<T> is write-only for serialization.");

    /// <summary>Writes the redacted literal <c>"[SENSITIVE]"</c>, never the wrapped value.</summary>
    public override void Write(Utf8JsonWriter writer, Sensitive<T> value, JsonSerializerOptions options)
        => writer.WriteStringValue("[SENSITIVE]");
}
