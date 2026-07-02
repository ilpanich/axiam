using Axiam.Sdk;
using Axiam.Sdk.Amqp;
using Axiam.Sdk.Grpc;

// Quickstart: demonstrates AxiamClient's four core capabilities using ONLY the
// SDK's PUBLIC entry points (the Axiam.Sdk surface — no internal/generated
// references): two-phase login+MFA, REST authorization, gRPC authorization, and
// AMQP event consumption with HMAC verify-before-handler. Running this against a
// live AXIAM server/broker is manual-only (21-VALIDATION.md) — see README.md.
// Each phase is wrapped so the example still documents the shape and compiles
// cleanly even without a reachable server.

Uri baseUrl = new(Environment.GetEnvironmentVariable("AXIAM_BASE_URL") ?? "https://localhost:8443");
string tenantId = Environment.GetEnvironmentVariable("AXIAM_TENANT_ID") ?? "acme";

// SC#1: tenantId is a required, positional constructor argument — there is no
// overload or default that omits it.
using AxiamClient client = new(baseUrl, tenantId);

try
{
    // --- 1. Two-phase login (LoginAsync -> VerifyMfaAsync) -----------------
    LoginResultShim login = await LoginAsync(client);
    Console.WriteLine("Login complete.");

    // --- 2. REST authorization (CheckAccessAsync / CanAsync) ---------------
    Guid documentId = Guid.NewGuid();
    bool canRead = await client.Authz.CanAsync("documents:read", documentId);
    Console.WriteLine($"REST CanAsync(documents:read) => {canRead}");

    // --- 3. gRPC authorization (CheckAccessAsync over Grpc.Net.Client) -----
    using AxiamGrpcAuthzClient grpcAuthz = new(client);
    bool grpcAllowed = await grpcAuthz.CheckAccessAsync("documents:read", documentId.ToString());
    Console.WriteLine($"gRPC CheckAccessAsync(documents:read) => {grpcAllowed}");
}
catch (Exception ex)
{
    Console.WriteLine($"Login/authz phase skipped — no reachable AXIAM server ({ex.Message}). See README.md.");
}

// --- 4. AMQP event consumption (AsyncEventingBasicConsumer + HMAC verify) --
await using AxiamAmqpConsumer amqpConsumer = new();
try
{
    string amqpUri = Environment.GetEnvironmentVariable("AXIAM_AMQP_URI") ?? "amqp://guest:guest@localhost:5672";
    byte[] signingKey = Convert.FromHexString(Environment.GetEnvironmentVariable("AXIAM_AMQP_SIGNING_KEY_HEX") ?? "00");

    // The handler is invoked ONLY after Hmac.Verify succeeds — it never sees an
    // unverified message (§8, D-11).
    await amqpConsumer.StartAsync(amqpUri, "axiam.audit.events", signingKey, async (body, ct) =>
    {
        Console.WriteLine($"Verified AMQP event received ({body.Length} bytes).");
        await Task.CompletedTask;
    });

    Console.WriteLine("AMQP consumer registered — press Ctrl+C to exit.");
    await Task.Delay(Timeout.Infinite);
}
catch (Exception ex)
{
    Console.WriteLine($"AMQP phase skipped — no reachable broker ({ex.Message}). See README.md.");
}

// Local helper isolating the two-phase MFA dance so the top-level flow above
// reads linearly; returns once a session has been fully established.
static async Task<LoginResultShim> LoginAsync(AxiamClient client)
{
    Axiam.Sdk.Auth.LoginResult login = await client.LoginAsync(
        email: Environment.GetEnvironmentVariable("AXIAM_EMAIL") ?? "alice@example.com",
        password: Environment.GetEnvironmentVariable("AXIAM_PASSWORD") ?? "correct horse battery staple");

    if (login.MfaRequired)
    {
        Console.WriteLine("MFA challenge issued — verifying with a TOTP code...");
        // login.ChallengeToken is a Sensitive<string> (CONTRACT.md §7) — passed
        // straight through to VerifyMfaAsync; this example never reveals it.
        login = await client.VerifyMfaAsync(
            login.ChallengeToken!.Value,
            totpCode: Environment.GetEnvironmentVariable("AXIAM_TOTP_CODE") ?? "123456");
    }

    return new LoginResultShim(login.MfaRequired);
}

// Minimal marker type so the local LoginAsync helper's return value cannot
// accidentally leak a Sensitive<string> outward — the caller only ever needs to
// know the flow completed.
internal sealed record LoginResultShim(bool MfaRequired);
