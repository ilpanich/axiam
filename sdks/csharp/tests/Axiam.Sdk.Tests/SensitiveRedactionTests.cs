using System.Net;
using System.Net.Http;
using System.Text.Json;
using Axiam.Sdk.Core;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CR-04 regression test (D-12, carried forward from Phase 17's
/// <c>sdks/typescript/src/core/errorMapper.ts</c> <c>sanitizeAxiosError</c> finding and
/// mirrored by every later sibling SDK): proves <see cref="ErrorMapper"/>/
/// <see cref="NetworkError"/> never let a raw <c>Set-Cookie</c> token value reach a
/// thrown error's <see cref="Exception.ToString"/>, <see cref="Exception.Message"/>, or a
/// <c>JsonSerializer.Serialize</c> of the error — while a non-secret control header value
/// DOES survive, proving redaction is selective rather than a blanket wipe that would
/// trivially pass this test.
/// </summary>
[Trait("Category", "Fast")]
public class SensitiveRedactionTests
{
    private const string RawToken = "abc123token";
    private const string ControlHeaderValue = "req-123";

    private const string CustomAuthTokenValue = "xauth-secret-999";

    private static HttpResponseMessage BuildResponse(HttpStatusCode status)
    {
        var response = new HttpResponseMessage(status);
        response.Headers.TryAddWithoutValidation("Set-Cookie", $"axiam_access={RawToken}; HttpOnly");
        // Non-vacuous control: a benign, non-secret header that MUST survive redaction.
        response.Headers.TryAddWithoutValidation("X-Request-Id", ControlHeaderValue);
        // X-3: a CUSTOM sensitive header not on the old denylist — must be redacted by the allowlist.
        response.Headers.TryAddWithoutValidation("X-Auth-Token", CustomAuthTokenValue);
        return response;
    }

    [Fact]
    public void NetworkErrorNeverLeaksRawSetCookieToken()
    {
        using HttpResponseMessage response = BuildResponse(HttpStatusCode.InternalServerError);

        Exception error = ErrorMapper.FromHttpResponse(response, "server error");

        Assert.IsType<NetworkError>(error);
        string toStringOutput = error.ToString();
        string messageOutput = error.Message;
        string serialized = JsonSerializer.Serialize(error, error.GetType());

        Assert.DoesNotContain(RawToken, toStringOutput);
        Assert.DoesNotContain(RawToken, messageOutput);
        Assert.DoesNotContain(RawToken, serialized);
    }

    [Fact]
    public void NetworkErrorRetainsNonSensitiveControlHeader()
    {
        // Non-vacuous control: a benign, allowlisted header value (X-Request-Id) MUST
        // survive redaction, proving the filter is selective rather than a blanket wipe
        // of every header.
        using HttpResponseMessage response = BuildResponse(HttpStatusCode.InternalServerError);

        Exception error = ErrorMapper.FromHttpResponse(response, "server error");

        Assert.Contains(ControlHeaderValue, error.Message);
    }

    [Fact]
    public void NetworkErrorRedactsCustomSensitiveHeaderNotOnAllowlist()
    {
        // X-3 regression: a custom sensitive header (X-Auth-Token) that no denylist would
        // have caught must NOT leak its value — the allowlist is fail-closed, so anything
        // unvetted is [REDACTED]. The header NAME may remain for diagnostic context.
        using HttpResponseMessage response = BuildResponse(HttpStatusCode.InternalServerError);

        Exception error = ErrorMapper.FromHttpResponse(response, "server error");

        Assert.DoesNotContain(CustomAuthTokenValue, error.Message);
        Assert.DoesNotContain(CustomAuthTokenValue, error.ToString());
        Assert.DoesNotContain(CustomAuthTokenValue, JsonSerializer.Serialize(error, error.GetType()));
        // The allowlisted header still comes through, proving redaction is selective.
        Assert.Contains(ControlHeaderValue, error.Message);
    }

    [Fact]
    public void HttpStatusMappingMatchesContract()
    {
        Assert.IsType<AuthError>(ErrorMapper.FromHttpResponse(BuildResponse(HttpStatusCode.Unauthorized), "unauthenticated"));
        Assert.IsType<AuthzError>(ErrorMapper.FromHttpResponse(BuildResponse(HttpStatusCode.Forbidden), "forbidden"));
        Assert.IsType<AuthzError>(ErrorMapper.FromHttpResponse(BuildResponse(HttpStatusCode.Conflict), "conflict"));
        Assert.IsType<NetworkError>(ErrorMapper.FromHttpResponse(BuildResponse(HttpStatusCode.BadRequest), "bad request"));
        Assert.IsType<NetworkError>(ErrorMapper.FromHttpResponse(BuildResponse(HttpStatusCode.TooManyRequests), "rate limited"));
        Assert.IsType<NetworkError>(ErrorMapper.FromHttpResponse(BuildResponse(HttpStatusCode.ServiceUnavailable), "unavailable"));
    }

    [Fact]
    public void GrpcStatusMappingMatchesContract()
    {
        Assert.IsType<AuthError>(ErrorMapper.FromGrpcStatus(Grpc.Core.StatusCode.Unauthenticated, "unauthenticated"));
        Assert.IsType<AuthzError>(ErrorMapper.FromGrpcStatus(Grpc.Core.StatusCode.PermissionDenied, "permission denied"));
        Assert.IsType<NetworkError>(ErrorMapper.FromGrpcStatus(Grpc.Core.StatusCode.Unavailable, "unavailable"));
        Assert.IsType<NetworkError>(ErrorMapper.FromGrpcStatus(Grpc.Core.StatusCode.DeadlineExceeded, "deadline exceeded"));
        Assert.IsType<NetworkError>(ErrorMapper.FromGrpcStatus(Grpc.Core.StatusCode.Internal, "internal"));
        Assert.IsType<NetworkError>(ErrorMapper.FromGrpcStatus(Grpc.Core.StatusCode.ResourceExhausted, "resource exhausted"));
    }

    [Fact]
    public void SensitiveToStringAlwaysRedacts()
    {
        var sensitive = Axiam.Sdk.Core.Sensitive.Of(RawToken);

        Assert.Equal("[SENSITIVE]", sensitive.ToString());
        Assert.DoesNotContain(RawToken, sensitive.ToString());
    }

    [Fact]
    public void SensitiveJsonSerializationAlwaysRedacts()
    {
        var sensitive = Axiam.Sdk.Core.Sensitive.Of(RawToken);

        string json = JsonSerializer.Serialize(sensitive);

        Assert.Equal("\"[SENSITIVE]\"", json);
        Assert.DoesNotContain(RawToken, json);
    }

    [Fact]
    public void SensitiveJsonDeserializationIsUnsupported()
    {
        Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<Sensitive<string>>("\"anything\""));
    }

    // CR-02 regression: Sensitive<T> must NEVER be value-comparable. Left un-overridden,
    // a struct inherits System.ValueType's structural (value) equality/hash, which is a
    // side channel on the wrapped secret (and would leak into any record carrying a
    // Sensitive<T> field). Overriding Equals/==/GetHashCode to constants closes it.

    [Fact]
    public void TwoSensitivesWrappingTheSameValueAreNeverEqual()
    {
        var a = Axiam.Sdk.Core.Sensitive.Of("secret1");
        var b = Axiam.Sdk.Core.Sensitive.Of("secret1");

        Assert.False(a.Equals(b));
        Assert.False(a.Equals((object)b));
        Assert.False(a == b);
        Assert.True(a != b);
    }

    [Fact]
    public void SensitiveIsNeverEqualEvenToItself()
    {
        var a = Axiam.Sdk.Core.Sensitive.Of("secret1");

        // Not even a copy of itself compares equal — there is no value-equality path at all.
        Assert.False(a.Equals(a));
        Assert.False(a.Equals((object?)null));
        Assert.False(a.Equals("secret1"));
    }

    [Fact]
    public void SensitiveHashCodeIsAConstant_NeverDerivedFromTheValue()
    {
        int hashSecret1 = Axiam.Sdk.Core.Sensitive.Of("secret1").GetHashCode();
        int hashSecret2 = Axiam.Sdk.Core.Sensitive.Of("a-totally-different-secret").GetHashCode();

        Assert.Equal(0, hashSecret1);
        Assert.Equal(hashSecret1, hashSecret2);
    }
}
