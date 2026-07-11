using System.Net;
using System.Net.Http;
using System.Text;
using Axiam.Sdk.Core;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// SDK-Q02 regression suite: proves <see cref="ErrorMapper"/> parses the server's
/// structured 403 authorization-denied body (<c>{"error":"authorization_denied",
/// "message":"...","action":"users:get","resource_id":"&lt;uuid&gt;"}</c>) into
/// <see cref="AuthzError.Action"/>/<see cref="AuthzError.ResourceId"/>, and that
/// <c>resource_id</c> is null when the denial was not resource-scoped (CONTRACT.md
/// &#167;2: AuthzError SHOULD carry the denied action/resource_id if available).
/// </summary>
[Trait("Category", "Fast")]
public class AuthzErrorBodyTests
{
    private static HttpResponseMessage ForbiddenWithBody(string json)
    {
        var response = new HttpResponseMessage(HttpStatusCode.Forbidden)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
        return response;
    }

    [Fact]
    public void ActionAndResourceIdBothPresent_ArePopulatedOnAuthzError()
    {
        const string resourceId = "3fa85f64-5717-4562-b3fc-2c963f66afa6";
        using HttpResponseMessage response = ForbiddenWithBody(
            $$"""{"error":"authorization_denied","message":"forbidden","action":"users:get","resource_id":"{{resourceId}}"}""");

        Exception error = ErrorMapper.FromHttpResponse(response, "checkAccess failed");

        var authzError = Assert.IsType<AuthzError>(error);
        Assert.Equal("users:get", authzError.Action);
        Assert.Equal(resourceId, authzError.ResourceId);
    }

    [Fact]
    public void OnlyActionPresent_ResourceIdIsNull()
    {
        using HttpResponseMessage response = ForbiddenWithBody(
            """{"error":"authorization_denied","message":"forbidden","action":"users:list"}""");

        Exception error = ErrorMapper.FromHttpResponse(response, "checkAccess failed");

        var authzError = Assert.IsType<AuthzError>(error);
        Assert.Equal("users:list", authzError.Action);
        Assert.Null(authzError.ResourceId);
    }

    [Fact]
    public void NoBody_ActionAndResourceIdAreNull()
    {
        using HttpResponseMessage response = new(HttpStatusCode.Forbidden) { Content = new StringContent("") };

        Exception error = ErrorMapper.FromHttpResponse(response, "checkAccess failed");

        var authzError = Assert.IsType<AuthzError>(error);
        Assert.Null(authzError.Action);
        Assert.Null(authzError.ResourceId);
    }

    [Fact]
    public void MalformedBody_FallsBackToMessageOnlyAuthzError_NeverThrows()
    {
        using HttpResponseMessage response = ForbiddenWithBody("{not valid json");

        Exception error = ErrorMapper.FromHttpResponse(response, "checkAccess failed");

        var authzError = Assert.IsType<AuthzError>(error);
        Assert.Equal("checkAccess failed", authzError.Message);
        Assert.Null(authzError.Action);
        Assert.Null(authzError.ResourceId);
    }

    [Fact]
    public void GrpcPermissionDenied_HasNoBody_ActionAndResourceIdAreNull()
    {
        Exception error = ErrorMapper.FromGrpcStatus(global::Grpc.Core.StatusCode.PermissionDenied, "permission denied");

        var authzError = Assert.IsType<AuthzError>(error);
        Assert.Null(authzError.Action);
        Assert.Null(authzError.ResourceId);
    }
}
