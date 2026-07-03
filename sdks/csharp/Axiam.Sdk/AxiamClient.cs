using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Axiam.Sdk.Rest;

namespace Axiam.Sdk;

/// <summary>
/// The AXIAM C# SDK's public REST entry point (CONTRACT.md &#167;1&#8211;&#167;6, &#167;9). The
/// public constructor is the ONLY construction path — <c>tenantId</c> is a required,
/// positional argument with no default and no overload that omits it (SC#1).
/// </summary>
/// <remarks>
/// Owns exactly ONE <see cref="RefreshGuard"/> and ONE <see cref="JwksVerifier"/> per
/// client — shared by the REST auth flow here and, by a later plan, the gRPC transport
/// (D-10's "one guard across REST + gRPC on one client" requirement). Internal
/// accessors (<see cref="RefreshGuard"/>, <see cref="JwksVerifier"/>,
/// <see cref="CurrentAccessToken"/>, <see cref="BaseUrl"/>, <see cref="CustomCaPem"/>,
/// <see cref="TransportHttpClient"/>) expose this seam without requiring the gRPC plan
/// (21-05) or the ASP.NET Core plan (21-06) to edit this file.
/// </remarks>
public sealed class AxiamClient : IDisposable
{
    private const string LoginPath = "/api/v1/auth/login";
    private const string MfaVerifyPath = "/api/v1/auth/mfa/verify";
    private const string RefreshPath = "/api/v1/auth/refresh";
    private const string LogoutPath = "/api/v1/auth/logout";

    private const string AccessCookieName = "axiam_access";
    private const string RefreshCookieName = "axiam_refresh";

    private readonly TenantContext _tenant;
    private readonly AxiamClientOptions _options;
    private readonly Uri _baseUrl;
    private readonly CookieContainer _cookieContainer;
    private readonly HttpClient _httpClient;
    private readonly AxiamHttpMessageHandler _authHandler;
    private readonly RefreshGuard _refreshGuard;
    private readonly JwksVerifier _jwksVerifier;
    private readonly AuthzRestClient _authz;

    /// <summary>
    /// The ONLY construction path (SC#1) — <paramref name="tenantId"/> is required and
    /// positional; there is no overload reachable from this class that permits omitting
    /// it (CONTRACT.md &#167;5: AXIAM is multi-tenant, there is no default tenant). A
    /// blank <paramref name="tenantId"/> is a runtime guard (via <see cref="TenantContext"/>)
    /// backing this compile-time guarantee.
    /// </summary>
    /// <param name="baseUrl">The AXIAM server's base URL.</param>
    /// <param name="tenantId">The tenant slug or tenant UUID (as a string) — required, no default.</param>
    /// <param name="options">
    /// Optional tuning (custom CA, org id/slug, timeouts, JWKS cache TTL). When
    /// omitted, sane defaults are used and <see cref="AxiamClientOptions.BaseUrl"/>/
    /// <see cref="AxiamClientOptions.TenantId"/> are populated from
    /// <paramref name="baseUrl"/>/<paramref name="tenantId"/>.
    /// </param>
    public AxiamClient(Uri baseUrl, string tenantId, AxiamClientOptions? options = null)
        : this(baseUrl, tenantId, options, transportOverride: null)
    {
    }

    /// <summary>
    /// Test-only seam (internal): builds an <see cref="AxiamClient"/> whose transport
    /// bottoms out at <paramref name="transportHandler"/> instead of a real
    /// <see cref="HttpClientHandler"/> — lets unit tests fully exercise the auth-flow
    /// methods and this class's <see cref="AxiamHttpMessageHandler"/> wiring against a
    /// fake server, without a real socket. Never used by any production code path; kept
    /// `internal` (not part of the public constructor surface counted by SC#1's
    /// reflection test).
    /// </summary>
    internal static AxiamClient CreateForTesting(Uri baseUrl, string tenantId, AxiamClientOptions? options, HttpMessageHandler transportHandler) =>
        new(baseUrl, tenantId, options, transportHandler);

    private AxiamClient(Uri baseUrl, string tenantId, AxiamClientOptions? options, HttpMessageHandler? transportOverride)
    {
        ArgumentNullException.ThrowIfNull(baseUrl);
        _tenant = new TenantContext(tenantId, options?.OrgId, options?.OrgSlug); // throws ArgumentException on blank tenantId (SC#1)

        _baseUrl = baseUrl;
        AxiamClientOptions baseOptions = options ?? new AxiamClientOptions { BaseUrl = baseUrl, TenantId = _tenant.TenantId };
        // ctor params are always the source of truth for BaseUrl/TenantId (SC#1),
        // regardless of what an optional options object happened to carry.
        _options = baseOptions with { BaseUrl = baseUrl, TenantId = _tenant.TenantId };

        HttpMessageHandler primaryHandler = transportOverride ?? AxiamHttpClientFactory.CreatePrimaryHandler(_options.CustomCaPem);
        _cookieContainer = (primaryHandler as HttpClientHandler)?.CookieContainer ?? new CookieContainer();

        _refreshGuard = new RefreshGuard(DoHttpRefreshAsync);

        _authHandler = new AxiamHttpMessageHandler(_cookieContainer, _baseUrl, _tenant.TenantId, _refreshGuard)
        {
            InnerHandler = primaryHandler,
        };

        _httpClient = new HttpClient(_authHandler)
        {
            BaseAddress = _baseUrl,
            Timeout = _options.RequestTimeout,
        };

        _jwksVerifier = new JwksVerifier(_httpClient, _baseUrl, _options.JwksCacheTtl);
        _authz = new AuthzRestClient(_httpClient);
    }

    /// <summary>REST authorization checks (CONTRACT.md &#167;1, FND-04): <c>CheckAccessAsync</c>/<c>CanAsync</c>/<c>BatchCheckAsync</c>.</summary>
    public AuthzRestClient Authz => _authz;

    // ------------------------------------------------------------------
    // Internal seam (gRPC plan 21-05 / ASP.NET Core plan 21-06) — not part
    // of the public API contract. These accessors let both later plans compose
    // against the SAME RefreshGuard/session this client's REST transport uses,
    // without either plan needing to modify this file.
    // ------------------------------------------------------------------

    internal RefreshGuard RefreshGuard => _refreshGuard;

    internal JwksVerifier JwksVerifier => _jwksVerifier;

    internal Uri BaseUrl => _baseUrl;

    internal byte[]? CustomCaPem => _options.CustomCaPem;

    internal HttpClient TransportHttpClient => _httpClient;

    internal string TenantId => _tenant.TenantId;

    /// <summary>Non-blocking read of the current access token from the shared cookie jar; <c>null</c> if never logged in.</summary>
    internal string? CurrentAccessToken => ReadCookie(AccessCookieName);

    public void Dispose()
    {
        _httpClient.Dispose();
        _refreshGuard.Dispose();
    }

    // ------------------------------------------------------------------
    // Auth methods (CONTRACT.md §1): LoginAsync / VerifyMfaAsync / RefreshAsync / LogoutAsync
    // All async-only + CancellationToken + ConfigureAwait(false) throughout (D-10).
    // ------------------------------------------------------------------

    /// <summary>
    /// <c>POST /api/v1/auth/login</c>. Returns a typed <see cref="LoginResult"/> — an
    /// MFA challenge (HTTP 202) is an expected outcome, not an exception: check
    /// <see cref="LoginResult.MfaRequired"/> before assuming a session was established.
    /// </summary>
    public async Task<LoginResult> LoginAsync(string email, string password, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        var body = new Dictionary<string, object?>
        {
            ["username_or_email"] = email,
            ["password"] = password,
        };
        ApplyTenantAndOrgFields(body);

        using HttpResponseMessage response = await PostJsonAsync(LoginPath, body, cancellationToken).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.OK)
        {
            return new LoginResult(false);
        }

        if (response.StatusCode == HttpStatusCode.Accepted)
        {
            JsonElement wire = await ReadJsonAsync(response, cancellationToken).ConfigureAwait(false);
            string challengeToken = wire.TryGetProperty("challenge_token", out JsonElement tokenEl)
                ? tokenEl.GetString() ?? string.Empty
                : string.Empty;
            return new LoginResult(true, Sensitive.Of(challengeToken));
        }

        throw ErrorMapper.FromHttpResponse(response, "login failed");
    }

    /// <summary>
    /// <c>POST /api/v1/auth/mfa/verify</c> (CONTRACT.md &#167;1), completing the
    /// two-phase flow started by <see cref="LoginAsync"/> when
    /// <see cref="LoginResult.MfaRequired"/> was <c>true</c>.
    /// </summary>
    public async Task<LoginResult> VerifyMfaAsync(Sensitive<string> challengeToken, string totpCode, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(totpCode);

        var body = new Dictionary<string, object?>
        {
            ["challenge_token"] = challengeToken.Reveal(),
            ["totp_code"] = totpCode,
        };

        using HttpResponseMessage response = await PostJsonAsync(MfaVerifyPath, body, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw ErrorMapper.FromHttpResponse(response, "MFA verification failed");
        }

        return new LoginResult(false);
    }

    /// <summary>
    /// <c>POST /api/v1/auth/refresh</c> (CONTRACT.md &#167;1), routed through the single-
    /// flight <see cref="RefreshGuard"/> (&#167;9). A 401 on the refresh call itself
    /// surfaces as <see cref="AuthError"/> with no retry (&#167;9.3).
    /// </summary>
    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        if (ReadCookie(AccessCookieName) is null)
        {
            throw new AuthError("no access token to refresh — call LoginAsync() first");
        }

        await _refreshGuard.RefreshIfNeededAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>POST /api/v1/auth/logout</c> (CONTRACT.md &#167;1) and clears in-memory
    /// session state. The session id comes from the current access token's <c>jti</c>
    /// claim (unverified decode — an operational hint only, never an authorization
    /// decision).
    /// </summary>
    public async Task LogoutAsync(CancellationToken cancellationToken = default)
    {
        string? access = ReadCookie(AccessCookieName);
        if (access is null)
        {
            throw new AuthError("no active session to log out");
        }

        JsonElement? claims = DecodeUnverifiedClaims(access);
        string? jti = claims is { } c && c.TryGetProperty("jti", out JsonElement jtiEl) ? jtiEl.GetString() : null;
        if (jti is null)
        {
            throw new AuthError("access token has no session id (jti) to log out");
        }

        var body = new Dictionary<string, object?> { ["session_id"] = jti };
        using HttpResponseMessage response = await PostJsonAsync(LogoutPath, body, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw ErrorMapper.FromHttpResponse(response, "logout failed");
        }

        _authHandler.ResetCsrfToken();
    }

    // ------------------------------------------------------------------
    // RefreshGuard delegate — performs the actual POST /api/v1/auth/refresh call.
    // Runs through the SAME HttpClient/AxiamHttpMessageHandler chain as every other
    // request; the refresh path is exempted there from triggering a NESTED refresh
    // (AxiamHttpMessageHandler.RefreshPath), so this call can never recursively
    // re-enter RefreshIfNeededAsync on itself.
    // ------------------------------------------------------------------

    private async Task<TokenPair> DoHttpRefreshAsync(CancellationToken cancellationToken)
    {
        string? access = ReadCookie(AccessCookieName);
        if (access is null)
        {
            throw new AuthError("no access token to refresh — call LoginAsync() first");
        }

        JsonElement? claims = DecodeUnverifiedClaims(access);
        string? tenantIdClaim = claims is { } tc && tc.TryGetProperty("tenant_id", out JsonElement tEl) ? tEl.GetString() : null;
        if (tenantIdClaim is null || !Guid.TryParse(tenantIdClaim, out Guid tenantGuid))
        {
            throw new AuthError("tenant_id could not be resolved from the current access token; LoginAsync() must succeed before RefreshAsync()");
        }

        Guid? orgGuid = _tenant.OrgId;
        if (orgGuid is null && claims is { } oc && oc.TryGetProperty("org_id", out JsonElement oEl) &&
            Guid.TryParse(oEl.GetString(), out Guid parsedOrg))
        {
            orgGuid = parsedOrg;
        }

        if (orgGuid is null)
        {
            throw new AuthError("org_id could not be resolved; supply OrgId/OrgSlug via AxiamClientOptions or call LoginAsync() first");
        }

        var body = new Dictionary<string, object?>
        {
            ["tenant_id"] = tenantGuid.ToString(),
            ["org_id"] = orgGuid.Value.ToString(),
        };

        using HttpResponseMessage response = await PostJsonAsync(RefreshPath, body, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            // §9.3: no retry here — RefreshGuard propagates this exception as-is to
            // every waiter.
            throw ErrorMapper.FromHttpResponse(response, "token refresh failed");
        }

        string? newAccess = ReadCookie(AccessCookieName);
        if (newAccess is null)
        {
            throw new AuthError("refresh response did not set the axiam_access cookie");
        }
        string? newRefresh = ReadCookie(RefreshCookieName);

        JsonElement? newClaims = DecodeUnverifiedClaims(newAccess);
        DateTimeOffset expiresAt = newClaims is { } nc && nc.TryGetProperty("exp", out JsonElement expEl) && expEl.TryGetInt64(out long expSeconds)
            ? DateTimeOffset.FromUnixTimeSeconds(expSeconds)
            : DateTimeOffset.UtcNow;

        return new TokenPair(Sensitive.Of(newAccess), Sensitive.Of(newRefresh ?? string.Empty), expiresAt);
    }

    // ------------------------------------------------------------------
    // Shared HTTP mechanics
    // ------------------------------------------------------------------

    private void ApplyTenantAndOrgFields(IDictionary<string, object?> body)
    {
        if (Guid.TryParse(_tenant.TenantId, out Guid tenantGuid))
        {
            body["tenant_id"] = tenantGuid.ToString();
        }
        else
        {
            body["tenant_slug"] = _tenant.TenantId;
        }

        if (_tenant.OrgId is Guid orgId)
        {
            body["org_id"] = orgId.ToString();
        }
        else if (_tenant.OrgSlug is string orgSlug)
        {
            body["org_slug"] = orgSlug;
        }
    }

    private async Task<HttpResponseMessage> PostJsonAsync(string path, object body, CancellationToken cancellationToken)
    {
        try
        {
            return await _httpClient.PostAsJsonAsync(path, body, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw NetworkError.FromException(ex, $"POST {path} failed");
        }
        catch (OperationCanceledException ex) when (ex.CancellationToken != cancellationToken)
        {
            // An OperationCanceledException/TaskCanceledException whose token is NOT the
            // caller's token comes from HttpClient.Timeout expiring (RequestTimeout) — a
            // transport-level timeout, which CONTRACT.md §2 maps to NetworkError. A genuine
            // caller-supplied cancellation (ex.CancellationToken == cancellationToken) is
            // deliberately NOT caught here and propagates as-is.
            throw NetworkError.FromException(ex, $"POST {path} timed out");
        }
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using (stream.ConfigureAwait(false))
        {
            using JsonDocument doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            return doc.RootElement.Clone();
        }
    }

    private string? ReadCookie(string name)
    {
        CookieCollection cookies = _cookieContainer.GetCookies(_baseUrl);
        foreach (Cookie cookie in cookies)
        {
            if (cookie.Name == name)
            {
                return cookie.Value;
            }
        }
        return null;
    }

    private static JsonElement? DecodeUnverifiedClaims(string jwt)
    {
        string[] parts = jwt.Split('.');
        if (parts.Length != 3)
        {
            return null;
        }

        try
        {
            byte[] payloadBytes = Base64UrlDecode(parts[1]);
            using JsonDocument doc = JsonDocument.Parse(payloadBytes);
            return doc.RootElement.Clone();
        }
        catch
        {
            return null;
        }
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
