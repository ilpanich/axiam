using System.Net.Http;

namespace Axiam.Sdk.Core;

/// <summary>
/// Transport-level failure: connection refused, timeout, TLS error, DNS failure, or a
/// server-side 5xx (CONTRACT.md &#167;2).
/// </summary>
/// <remarks>
/// <para>
/// <b>Redact-before-wrap (D-12, CR-04 carry-forward):</b> this is the ONLY error class
/// that may be constructed from an HTTP response, and there is exactly ONE construction
/// path that accepts a live <see cref="HttpResponseMessage"/> — the static
/// <see cref="FromResponse"/> factory. There is no public or internal constructor that
/// accepts an <see cref="HttpResponseMessage"/> directly; the live response object is
/// NEVER stored as the <see cref="Exception.InnerException"/> or in
/// <see cref="Exception.Data"/> — only a pre-sanitized message string survives. This
/// structurally prevents the token-leak-via-error class of bug first found in the
/// TypeScript sibling SDK (Phase 17 CR-04, <c>sdks/typescript/src/core/errorMapper.ts</c>
/// <c>sanitizeAxiosError</c>) and mirrored across every later sibling SDK.
/// </para>
/// </remarks>
public sealed class NetworkError : Exception
{
    /// <summary>
    /// Headers stripped from any wrapped response before a message is ever built —
    /// case-sensitive per the literal names used in CONTRACT.md &#167;2/&#167;7 and the
    /// Go/Java sibling implementations; HTTP header lookups in .NET are already
    /// case-insensitive, so this list need not enumerate casing variants.
    /// </summary>
    private static readonly HashSet<string> SensitiveResponseHeaders =
        new(StringComparer.OrdinalIgnoreCase) { "Set-Cookie", "Authorization", "Cookie" };

    private NetworkError(string message, Exception? inner) : base(message, inner)
    {
    }

    /// <summary>
    /// Builds a <see cref="NetworkError"/> from a live <see cref="HttpResponseMessage"/>.
    /// This is the ONLY construction path that accepts a live response — every other
    /// code path in the SDK MUST go through this factory (or <see cref="FromException"/>)
    /// rather than constructing a <see cref="NetworkError"/> directly from a raw
    /// response/exception.
    /// </summary>
    public static NetworkError FromResponse(HttpResponseMessage response, string context)
    {
        ArgumentNullException.ThrowIfNull(response);
        var sanitizedHeaders = response.Headers
            .Where(h => !SensitiveResponseHeaders.Contains(h.Key))
            .Select(h => $"{h.Key}: {string.Join(",", h.Value)}");
        var message =
            $"{context}: HTTP {(int)response.StatusCode} — headers: [{string.Join("; ", sanitizedHeaders)}]";
        // The raw `response` object itself is NEVER stored as InnerException/Data —
        // only the pre-sanitized string above survives past this method.
        return new NetworkError(message, inner: null);
    }

    /// <summary>
    /// Builds a <see cref="NetworkError"/> from a caught exception (e.g. a socket/TLS/DNS
    /// failure). The exception's own <see cref="Exception.Message"/> is defensively
    /// regex-sanitized before being folded into the resulting message, in case a
    /// lower-level exception echoed a request header verbatim.
    /// </summary>
    public static NetworkError FromException(Exception ex, string context)
    {
        ArgumentNullException.ThrowIfNull(ex);
        var message = $"{context}: {ex.GetType().Name} — {SanitizeMessage(ex.Message)}";
        return new NetworkError(message, inner: null);
    }

    /// <summary>
    /// Defense-in-depth regex redaction: strips any <c>set-cookie</c>/<c>authorization</c>/
    /// <c>cookie</c>-shaped fragment from an arbitrary string, in case a leaked header
    /// fragment reaches a message via a path other than <see cref="FromResponse"/>
    /// (e.g. embedded in a lower-level transport exception's own message text).
    /// </summary>
    internal static string SanitizeMessage(string raw) =>
        System.Text.RegularExpressions.Regex.Replace(
            raw,
            @"(?i)(set-cookie|authorization|cookie)\s*:\s*[^\r\n]+",
            "$1: [SENSITIVE]");
}
