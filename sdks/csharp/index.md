# AXIAM .NET SDK

API reference for the AXIAM .NET packages:

- **`Axiam.Sdk`** — the client: cookie-session authentication (`LoginAsync`,
  `VerifyMfaAsync`, `RefreshAsync`, `LogoutAsync`), authorization
  (`CheckAccessAsync`, `BatchCheckAsync`), the gRPC authorization client, and the
  AMQP consumer with HMAC verification and replay protection.
- **`Axiam.Sdk.AspNetCore`** — the resource-server middleware for ASP.NET Core:
  verifies the AXIAM JWT locally against a cached JWKS, enforces the cross-tenant
  claim check, and applies the CSRF double-submit check to cookie-authenticated
  state-changing requests.

See the [AXIAM SDK contract](https://github.com/ilpanich/axiam/blob/main/sdks/CONTRACT.md)
for the behaviour every AXIAM SDK guarantees.
