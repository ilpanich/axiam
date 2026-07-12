using System.Net;
using System.Net.Http;
using Axiam.Sdk.Core;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// SDK-Q02 regression suite: proves <see cref="NetworkError"/> satisfies CONTRACT.md
/// &#167;2's MUST — "NetworkError MUST carry the underlying OS/transport error as a
/// `cause` (or equivalent chained exception)" — for both construction paths
/// (<see cref="NetworkError.FromResponse"/> and <see cref="NetworkError.FromException"/>),
/// while proving the chained cause never carries a sensitive marker (a raw header value
/// or an unsanitized caught-exception message), consistent with this class's redact-
/// before-wrap invariant (D-12, CR-04 carry-forward).
/// </summary>
[Trait("Category", "Fast")]
public class NetworkErrorCauseChainTests
{
    private const string SensitiveMarker = "super-secret-token-should-never-leak";

    [Fact]
    public void FromResponse_InnerExceptionIsNotNull_AndCarriesNoSensitiveMarker()
    {
        using var response = new HttpResponseMessage(HttpStatusCode.InternalServerError);
        response.Headers.TryAddWithoutValidation("Set-Cookie", $"axiam_access={SensitiveMarker}; HttpOnly");

        NetworkError error = NetworkError.FromResponse(response, "server error");

        Assert.NotNull(error.InnerException);
        Assert.DoesNotContain(SensitiveMarker, error.InnerException!.Message);
        Assert.DoesNotContain(SensitiveMarker, error.InnerException.ToString());
    }

    [Fact]
    public void FromException_InnerExceptionIsNotNull_AndCarriesNoSensitiveMarker()
    {
        var caught = new HttpRequestException($"Authorization: Bearer {SensitiveMarker}");

        NetworkError error = NetworkError.FromException(caught, "checkAccess failed");

        Assert.NotNull(error.InnerException);
        Assert.DoesNotContain(SensitiveMarker, error.InnerException!.Message);
        Assert.DoesNotContain(SensitiveMarker, error.InnerException.ToString());
        // The cause is chained (not the caught exception itself), but its type is still
        // discoverable in the sanitized summary for diagnostics.
        Assert.Contains(nameof(HttpRequestException), error.InnerException.Message);
    }
}
