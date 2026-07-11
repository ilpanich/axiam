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
    /// X-3: ALLOWLIST of response headers whose <em>values</em> are known to be safe to
    /// surface in an error/diagnostic message. Anything NOT on this list is redacted to
    /// <c>[REDACTED]</c>. A denylist (Set-Cookie/Authorization/Cookie only) previously let
    /// a custom sensitive header such as <c>X-Auth-Token</c> survive verbatim into an
    /// exception message/log; an allowlist is fail-closed — a header we have not vetted is
    /// never leaked. Kept deliberately small: only non-secret transport/caching/diagnostic
    /// headers. HTTP header lookups in .NET are case-insensitive, so casing variants need
    /// not be enumerated.
    /// </summary>
    private static readonly HashSet<string> SafeResponseHeaders =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "Content-Type", "Content-Length", "Content-Language", "Content-Encoding",
            "Date", "Server", "Cache-Control", "ETag", "Last-Modified", "Expires",
            "Age", "Vary", "Retry-After", "Accept-Ranges",
            // Non-secret diagnostic correlation IDs — useful for tracing, never carry credentials.
            "X-Request-Id", "X-Correlation-Id",
        };

    private NetworkError(string message, Exception? inner) : base(message, inner)
    {
    }

    /// <summary>
    /// CONTRACT.md &#167;2 MUST: "NetworkError MUST carry the underlying OS/transport
    /// error as a `cause` (or equivalent chained exception)" — <see cref="Exception.InnerException"/>
    /// must never be null. This sanitized carrier is the ONLY exception type ever placed
    /// there: it holds nothing but a redacted summary string, so chaining a cause can
    /// never reintroduce the token/header leak this file's class-level remarks describe
    /// (no live <see cref="HttpResponseMessage"/>, no unredacted caught-exception message,
    /// ever reaches it).
    /// </summary>
    private sealed class SanitizedCause : Exception
    {
        public SanitizedCause(string sanitizedSummary) : base(sanitizedSummary)
        {
        }
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
        // X-3: fail-closed allowlist — a header whose name is not vetted as safe has its
        // value replaced with [REDACTED]; only the name is kept for diagnostic context.
        var sanitizedHeaders = response.Headers
            .Select(h => SafeResponseHeaders.Contains(h.Key)
                ? $"{h.Key}: {string.Join(",", h.Value)}"
                : $"{h.Key}: [REDACTED]");
        var message =
            $"{context}: HTTP {(int)response.StatusCode} — headers: [{string.Join("; ", sanitizedHeaders)}]";
        // The raw `response` object itself is NEVER stored as InnerException/Data —
        // only a sanitized status-code summary (no header values, safe or otherwise)
        // survives past this method, satisfying the §2 MUST for a non-null cause chain.
        var inner = new SanitizedCause($"HTTP {(int)response.StatusCode}");
        return new NetworkError(message, inner);
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
        string sanitizedDetail = SanitizeMessage(ex.Message);
        var message = $"{context}: {ex.GetType().Name} — {sanitizedDetail}";
        // Chain a cause per §2 MUST — never the caught exception itself (it may carry an
        // unsanitized message/stack referencing request internals); only its type name
        // plus the already-redacted detail above.
        var inner = new SanitizedCause($"{ex.GetType().Name}: {sanitizedDetail}");
        return new NetworkError(message, inner);
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
