using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Auth;

namespace Axiam.Sdk.Rest;

/// <summary>
/// Cross-cutting REST transport concerns shared by every request an <c>AxiamClient</c>
/// sends (CONTRACT.md &#167;3/&#167;5/&#167;9): injects <c>X-Tenant-Id</c> (&#167;5) and, when a
/// session exists, <c>Authorization: Bearer &lt;access&gt;</c> read from the shared
/// cookie jar; captures the <c>X-CSRF-Token</c> response header and echoes it on
/// subsequent state-changing requests (&#167;3, non-browser SDK); and drives a single
/// reactive 401&#8594;refresh&#8594;retry through the shared <see cref="RefreshGuard"/> — never
/// a second, independent guard, and never a retry loop (&#167;9.3).
/// </summary>
/// <remarks>
/// Registered as the outermost link of <c>AxiamClient</c>'s <see cref="HttpClient"/>
/// handler chain, with the SDK's own <see cref="HttpClientHandler"/> (cookie jar +
/// TLS policy, <c>AxiamHttpClientFactory.CreatePrimaryHandler</c>) as
/// <see cref="DelegatingHandler.InnerHandler"/>.
/// </remarks>
public sealed class AxiamHttpMessageHandler : DelegatingHandler
{
    /// <summary>
    /// The refresh endpoint's own request path — exempted from the reactive
    /// 401&#8594;refresh retry below so a refresh call can never recursively re-enter
    /// <see cref="RefreshGuard.RefreshIfNeededAsync"/> on itself and deadlock on its own
    /// in-flight task (mirrors the Java sibling's <c>AuthInterceptor</c>/
    /// <c>AuthAuthenticator</c> refresh-path exemption).
    /// </summary>
    public const string RefreshPath = "/api/v1/auth/refresh";

    private const string AccessCookieName = "axiam_access";
    private const string CsrfHeaderName = "X-CSRF-Token";
    private const string TenantHeaderName = "X-Tenant-Id";
    private const string AuthorizationHeaderName = "Authorization";

    private static readonly HashSet<string> StateChangingMethods =
        new(StringComparer.OrdinalIgnoreCase) { "POST", "PUT", "PATCH", "DELETE" };

    private static readonly HttpRequestOptionsKey<bool> RetryMarkerKey = new("axiam-sdk-retried-once");

    private readonly CookieContainer _cookieContainer;
    private readonly Uri _baseUri;
    private readonly string _tenantId;
    private readonly RefreshGuard _refreshGuard;

    private volatile string? _csrfToken;

    public AxiamHttpMessageHandler(CookieContainer cookieContainer, Uri baseUri, string tenantId, RefreshGuard refreshGuard)
    {
        _cookieContainer = cookieContainer ?? throw new ArgumentNullException(nameof(cookieContainer));
        _baseUri = baseUri ?? throw new ArgumentNullException(nameof(baseUri));
        _tenantId = tenantId ?? throw new ArgumentNullException(nameof(tenantId));
        _refreshGuard = refreshGuard ?? throw new ArgumentNullException(nameof(refreshGuard));
    }

    /// <summary>
    /// Clears locally-cached derived state after logout. The cookie jar itself is
    /// cleared by the server's clear-cookie <c>Set-Cookie</c> response headers,
    /// captured automatically by the shared <see cref="CookieContainer"/>.
    /// </summary>
    internal void ResetCsrfToken() => _csrfToken = null;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        bool isRetry = request.Options.TryGetValue(RetryMarkerKey, out bool retried) && retried;
        bool isRefreshCall = string.Equals(request.RequestUri?.AbsolutePath, RefreshPath, StringComparison.Ordinal);

        // Buffer the body up front (needed to build a single retry-clone below; every
        // request body this SDK sends is a small, fully-materialized JSON payload, not
        // a one-shot stream).
        byte[]? bodyBytes = null;
        string? contentType = null;
        if (request.Content is not null)
        {
            bodyBytes = await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            contentType = request.Content.Headers.ContentType?.ToString();
        }

        ApplyHeaders(request);

        HttpResponseMessage response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        CaptureCsrfToken(response);

        if (response.StatusCode == HttpStatusCode.Unauthorized && !isRefreshCall && !isRetry)
        {
            TokenPair refreshed;
            try
            {
                refreshed = await _refreshGuard.RefreshIfNeededAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                // Refresh itself failed — surface the ORIGINAL 401 to the caller, no
                // retry loop (CONTRACT.md §9.3). `response` already holds that original
                // 401; nothing further to do here.
                return response;
            }

            response.Dispose();

            var retryRequest = new HttpRequestMessage(request.Method, request.RequestUri);
            if (bodyBytes is not null)
            {
                var retryContent = new ByteArrayContent(bodyBytes);
                if (contentType is not null)
                {
                    retryContent.Headers.TryAddWithoutValidation("Content-Type", contentType);
                }
                retryRequest.Content = retryContent;
            }
            // Marks this clone so a second 401 on the retry itself does NOT trigger yet
            // another refresh attempt — exactly one retry, never a loop (§9.3).
            retryRequest.Options.Set(RetryMarkerKey, true);
            ApplyHeaders(retryRequest, refreshed.AccessToken.Reveal());

            response = await base.SendAsync(retryRequest, cancellationToken).ConfigureAwait(false);
            CaptureCsrfToken(response);
        }

        return response;
    }

    private void ApplyHeaders(HttpRequestMessage request, string? overrideAccessToken = null)
    {
        request.Headers.Remove(TenantHeaderName);
        request.Headers.TryAddWithoutValidation(TenantHeaderName, _tenantId);

        string? access = overrideAccessToken ?? ReadAccessTokenFromCookieJar();
        if (access is not null)
        {
            request.Headers.Remove(AuthorizationHeaderName);
            request.Headers.TryAddWithoutValidation(AuthorizationHeaderName, $"Bearer {access}");
        }

        string? csrf = _csrfToken;
        if (csrf is not null && StateChangingMethods.Contains(request.Method.Method))
        {
            request.Headers.Remove(CsrfHeaderName);
            request.Headers.TryAddWithoutValidation(CsrfHeaderName, csrf);
        }
    }

    private void CaptureCsrfToken(HttpResponseMessage response)
    {
        if (response.Headers.TryGetValues(CsrfHeaderName, out IEnumerable<string>? values))
        {
            string? newToken = values.FirstOrDefault();
            if (!string.IsNullOrEmpty(newToken))
            {
                _csrfToken = newToken;
            }
        }
    }

    private string? ReadAccessTokenFromCookieJar()
    {
        CookieCollection cookies = _cookieContainer.GetCookies(_baseUri);
        foreach (Cookie cookie in cookies)
        {
            if (cookie.Name == AccessCookieName)
            {
                return cookie.Value;
            }
        }
        return null;
    }
}
