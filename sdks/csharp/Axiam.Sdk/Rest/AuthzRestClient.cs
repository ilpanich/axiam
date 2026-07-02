using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Core;

namespace Axiam.Sdk.Rest;

/// <summary>
/// REST authorization client (CONTRACT.md &#167;1, FND-04): <c>CheckAccessAsync</c>/
/// <c>CanAsync</c>/<c>BatchCheckAsync</c> over <c>POST /api/v1/authz/check</c> and
/// <c>POST /api/v1/authz/check/batch</c> (mirrors the gRPC
/// <c>CheckAccess</c>/<c>BatchCheckAccess</c> semantics a later plan wires up over the
/// same shared session). Exposed as <c>AxiamClient.Authz</c>.
/// </summary>
/// <remarks>
/// This class holds NO local cache of any authorization decision — every call hits the
/// server fresh. AXIAM's RBAC engine is additive-only (allow-wins, default-deny,
/// SEC-040; project constraint per CLAUDE.md); a client-side cache or short-circuit
/// could silently diverge from the server's live decision, which this SDK must never
/// risk.
/// </remarks>
public sealed class AuthzRestClient
{
    private const string CheckPath = "/api/v1/authz/check";
    private const string BatchCheckPath = "/api/v1/authz/check/batch";

    private readonly HttpClient _http;

    internal AuthzRestClient(HttpClient httpClient)
    {
        _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    }

    /// <summary>A single authorization check request item for <see cref="BatchCheckAsync"/>.</summary>
    /// <param name="Action">The action to check (e.g. <c>"users:get"</c>).</param>
    /// <param name="ResourceId">The resource UUID the action targets.</param>
    /// <param name="Scope">Optional scope for sub-resource granularity.</param>
    /// <param name="SubjectId">
    /// Optional "check-as" subject override. Requires the caller to hold
    /// <c>authz:check_as</c> server-side; omit to check on behalf of the authenticated
    /// caller.
    /// </param>
    public sealed record AccessCheck(string Action, Guid ResourceId, string? Scope = null, Guid? SubjectId = null);

    private sealed record CheckAccessWireRequest(
        [property: JsonPropertyName("action")] string Action,
        [property: JsonPropertyName("resource_id")] Guid ResourceId,
        [property: JsonPropertyName("scope")] string? Scope,
        [property: JsonPropertyName("subject_id")] Guid? SubjectId);

    private sealed record CheckAccessWireResponse(
        [property: JsonPropertyName("allowed")] bool Allowed,
        [property: JsonPropertyName("reason")] string? Reason);

    private sealed record BatchCheckWireRequest(
        [property: JsonPropertyName("checks")] IReadOnlyList<CheckAccessWireRequest> Checks);

    private sealed record BatchCheckWireResponse(
        [property: JsonPropertyName("results")] IReadOnlyList<CheckAccessWireResponse> Results);

    /// <summary>
    /// <c>POST /api/v1/authz/check</c> (FND-04). Evaluates fresh every time — no
    /// client-side authz caching/short-circuiting. Returns the response's
    /// <c>allowed</c> field.
    /// </summary>
    public async Task<bool> CheckAccessAsync(
        string action, Guid resourceId, string? scope = null, Guid? subjectId = null, CancellationToken cancellationToken = default)
    {
        var wireRequest = new CheckAccessWireRequest(action, resourceId, scope, subjectId);
        using HttpResponseMessage response = await _http.PostAsJsonAsync(CheckPath, wireRequest, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw ErrorMapper.FromHttpResponse(response, "checkAccess failed");
        }

        CheckAccessWireResponse? wire = await response.Content
            .ReadFromJsonAsync<CheckAccessWireResponse>(cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        return wire?.Allowed ?? false;
    }

    /// <summary>
    /// Browser/UI-scenario ergonomic alias for <see cref="CheckAccessAsync"/>
    /// (CONTRACT.md &#167;1 "can" alias note) — the exact same fresh server call and
    /// no-cache guarantee; async-only per D-10 (no bare synchronous <c>Can</c> method).
    /// </summary>
    public Task<bool> CanAsync(string action, Guid resourceId, string? scope = null, CancellationToken cancellationToken = default) =>
        CheckAccessAsync(action, resourceId, scope, subjectId: null, cancellationToken);

    /// <summary>
    /// <c>POST /api/v1/authz/check/batch</c> (FND-04). Returns results in the same
    /// order as <paramref name="checks"/>. Fresh, uncached, per &#167;1/FND-04.
    /// </summary>
    public async Task<IReadOnlyList<bool>> BatchCheckAsync(IEnumerable<AccessCheck> checks, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checks);
        List<CheckAccessWireRequest> wireChecks = checks
            .Select(c => new CheckAccessWireRequest(c.Action, c.ResourceId, c.Scope, c.SubjectId))
            .ToList();
        var wireRequest = new BatchCheckWireRequest(wireChecks);

        using HttpResponseMessage response = await _http.PostAsJsonAsync(BatchCheckPath, wireRequest, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw ErrorMapper.FromHttpResponse(response, "batchCheck failed");
        }

        BatchCheckWireResponse? wire = await response.Content
            .ReadFromJsonAsync<BatchCheckWireResponse>(cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        return wire?.Results.Select(r => r.Allowed).ToList() ?? new List<bool>();
    }
}
