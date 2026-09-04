import type {
  Sdk,
  Post,
  Phase,
  BenchScenario,
  BenchEfficiencyRow,
  BenchResourceRow,
  BenchSdkRow,
  BenchSdkFootprintRow,
} from "./types";

/**
 * Content model for the AXIAM website. Mirrors the design's data source: the
 * eleven official client SDKs, the news posts, the 19-phase roadmap, and the
 * preliminary benchmark scenarios.
 */

export const SDKS: Sdk[] = [
  {
    id: "rust",
    name: "Rust",
    abbr: "Rs",
    registry: "crates.io",
    registryUrl: "https://crates.io/crates/axiam-sdk",
    docsLabel: "docs.rs",
    docsUrl: "https://docs.rs/axiam-sdk",
    repoUrl: "https://github.com/ilpanich/axiam-rust-sdk",
    examplesUrl: "https://github.com/ilpanich/axiam-rust-sdk/tree/main/examples",
    coverageUrl: "https://coveralls.io/github/ilpanich/axiam-rust-sdk?branch=main",
    pkg: "axiam-sdk",
    install: "cargo add axiam-sdk",
    blurb: "Native async client with the full REST, gRPC and AMQP surface.",
    highlights: [
      "REST, gRPC & AMQP transports",
      "Tokio-native async, TLS always on",
      "Sensitive<T> wrappers redact secrets",
    ],
    quickstart: `use axiam_sdk::AxiamClient;

let axiam = AxiamClient::builder()
    .base_url("https://iam.acme.dev")
    .tenant_slug("acme")
    .org_slug("acme")
    .build()?;

axiam.login(&email, &password).await?;
let ok = axiam.can("read", "doc:1").await?;`,
    guardLabel: "Guard by macro",
    guardExample: `use axiam_sdk::require;

// The attribute macro runs the authorization check before the
// handler body — a 403 short-circuits automatically.
#[require("read", "doc:{id}")]
async fn get_doc(path: web::Path<String>) -> impl Responder {
    HttpResponse::Ok().body("secret document")
}`,
  },
  {
    id: "typescript",
    name: "TypeScript",
    abbr: "Ts",
    registry: "npm",
    registryUrl: "https://www.npmjs.com/package/axiam-sdk",
    docsLabel: "API reference",
    docsUrl: "https://ilpanich.github.io/axiam-typescript-sdk/",
    repoUrl: "https://github.com/ilpanich/axiam-typescript-sdk",
    examplesUrl: "https://github.com/ilpanich/axiam-typescript-sdk/tree/main/examples",
    coverageUrl: "https://coveralls.io/github/ilpanich/axiam-typescript-sdk?branch=main",
    pkg: "axiam-sdk",
    install: "npm install axiam-sdk",
    blurb:
      "One package, two personas — tree-shaken REST for the browser, gRPC/AMQP for Node.",
    highlights: [
      "Browser + Node subpath entries",
      "Express / Fastify / NestJS guards",
      "httpOnly cookies, auto CSRF & refresh",
    ],
    quickstart: `import { AxiamClient } from 'axiam-sdk';

const axiam = new AxiamClient({
  baseUrl: 'https://iam.acme.dev',
  tenantSlug: 'acme',
  orgSlug: 'acme',
});

await axiam.login(email, password);
const ok = await axiam.can('read', 'doc:1');`,
    guardLabel: "Guard by decorator (NestJS)",
    guardExample: `import { RequirePermission } from 'axiam-sdk/nest';

@Controller('docs')
export class DocsController {
  // The decorator guards the route — the check runs before the method.
  @Get(':id')
  @RequirePermission('read', 'doc:{id}')
  findOne(@Param('id') id: string) {
    return this.docs.find(id);
  }
}`,
  },
  {
    id: "python",
    name: "Python",
    abbr: "Py",
    registry: "PyPI",
    registryUrl: "https://pypi.org/project/axiam-sdk/",
    docsLabel: "API reference",
    docsUrl: "https://ilpanich.github.io/axiam-python-sdk/",
    repoUrl: "https://github.com/ilpanich/axiam-python-sdk",
    examplesUrl: "https://github.com/ilpanich/axiam-python-sdk/tree/main/examples",
    coverageUrl: "https://coveralls.io/github/ilpanich/axiam-python-sdk?branch=main",
    pkg: "axiam-sdk",
    install: "pip install axiam-sdk",
    blurb:
      "Sync and async clients with FastAPI dependency and Django middleware extras.",
    highlights: [
      "AxiamClient + AsyncAxiamClient",
      "FastAPI & Django integrations",
      "grpcio / grpc.aio + aio-pika",
    ],
    quickstart: `from axiam_sdk import AxiamClient

with AxiamClient(base_url="https://iam.acme.dev",
                 tenant_slug="acme",
                 org_slug="acme") as axiam:
    axiam.login(email, password)
    ok = axiam.can("resource:read", "doc:1")`,
    guardLabel: "Guard by dependency (FastAPI)",
    guardExample: `from fastapi import Depends, FastAPI
from axiam_sdk.fastapi import requires

app = FastAPI()

# The dependency enforces the check before the handler runs.
@app.get("/docs/{doc_id}")
def read_doc(doc_id: str,
             _=Depends(requires("read", "doc:{doc_id}"))):
    return {"id": doc_id}`,
  },
  {
    id: "java",
    name: "Java",
    abbr: "Jv",
    registry: "Maven Central",
    registryUrl:
      "https://central.sonatype.com/artifact/io.github.ilpanich/axiam-sdk",
    docsLabel: "javadoc.io",
    docsUrl: "https://javadoc.io/doc/io.github.ilpanich/axiam-sdk",
    repoUrl: "https://github.com/ilpanich/axiam-java-sdk",
    examplesUrl: "https://github.com/ilpanich/axiam-java-sdk/tree/main/examples",
    coverageUrl: "https://coveralls.io/github/ilpanich/axiam-java-sdk?branch=main",
    pkg: "io.github.ilpanich:axiam-sdk",
    install: 'implementation("io.github.ilpanich:axiam-sdk:1.0.0-beta07")',
    blurb:
      "Fluent builder client for the JVM, with servlet and Spring-friendly guards.",
    highlights: [
      "Builder-style construction",
      "Blocking & reactive call sites",
      "Ships generated gRPC stubs",
    ],
    quickstart: `AxiamClient axiam = AxiamClient.builder()
    .baseUrl("https://iam.acme.dev")
    .tenantSlug("acme")
    .orgSlug("acme")
    .build();

axiam.login(email, password);
boolean ok = axiam.can("read", "doc:1");`,
    guardLabel: "Guard by annotation",
    guardExample: `import io.github.ilpanich.axiam.RequirePermission;

@RestController
class DocController {
    // The annotation guards the endpoint before it is invoked.
    @GetMapping("/docs/{id}")
    @RequirePermission(action = "read", resource = "doc:{id}")
    Doc getDoc(@PathVariable String id) {
        return service.find(id);
    }
}`,
  },
  {
    id: "csharp",
    name: "C#",
    abbr: "C#",
    registry: "NuGet",
    registryUrl: "https://www.nuget.org/packages/Axiam.Sdk",
    docsLabel: "API reference",
    docsUrl: "https://ilpanich.github.io/axiam-csharp-sdk/",
    repoUrl: "https://github.com/ilpanich/axiam-csharp-sdk",
    examplesUrl: "https://github.com/ilpanich/axiam-csharp-sdk/tree/main/examples",
    coverageUrl: "https://coveralls.io/github/ilpanich/axiam-csharp-sdk?branch=main",
    pkg: "Axiam.Sdk",
    install: "dotnet add package Axiam.Sdk",
    blurb:
      "Async-first .NET client with ASP.NET Core middleware for authN and authZ.",
    highlights: [
      "Task-based async API",
      "ASP.NET Core middleware",
      "TLS pinning via custom CA",
    ],
    quickstart: `var axiam = new AxiamClient(new AxiamOptions {
    BaseUrl = "https://iam.acme.dev",
    TenantSlug = "acme",
    OrgSlug = "acme",
});

await axiam.LoginAsync(email, password);
bool ok = await axiam.CanAsync("read", "doc:1");`,
    guardLabel: "Guard by attribute",
    guardExample: `[ApiController]
[Route("docs")]
public class DocsController : ControllerBase
{
    // The attribute guards the action before it executes.
    [HttpGet("{id}")]
    [AxiamAuthorize("read", "doc:{id}")]
    public IActionResult Get(string id) => Ok(_docs.Find(id));
}`,
  },
  {
    id: "php",
    name: "PHP",
    abbr: "Php",
    registry: "Packagist",
    registryUrl: "https://packagist.org/packages/axiam/axiam-sdk",
    docsLabel: "API reference",
    docsUrl: "https://ilpanich.github.io/axiam-php-sdk/",
    repoUrl: "https://github.com/ilpanich/axiam-php-sdk",
    examplesUrl: "https://github.com/ilpanich/axiam-php-sdk/tree/main/examples",
    coverageUrl: "https://coveralls.io/github/ilpanich/axiam-php-sdk?branch=main",
    pkg: "axiam/axiam-sdk",
    install: "composer require axiam/axiam-sdk",
    blurb: "PSR-friendly client with middleware for Laravel and Symfony apps.",
    highlights: [
      "PSR-7 / PSR-18 compatible",
      "Laravel & Symfony guards",
      "Composer-installable, no build step",
    ],
    quickstart: `use Axiam\\AxiamClient;

$axiam = new AxiamClient([
    'baseUrl' => 'https://iam.acme.dev',
    'tenantSlug' => 'acme',
    'orgSlug' => 'acme',
]);

$axiam->login($email, $password);
$ok = $axiam->can('read', 'doc:1');`,
    guardLabel: "Guard by attribute",
    guardExample: `use Axiam\\Attributes\\RequirePermission;

class DocController
{
    // The PHP 8 attribute guards the action before it runs.
    #[RequirePermission('read', 'doc:{id}')]
    public function show(string $id): Response
    {
        return response()->json(Doc::find($id));
    }
}`,
  },
  {
    id: "go",
    name: "Go",
    abbr: "Go",
    registry: "pkg.go.dev",
    registryUrl: "https://pkg.go.dev/github.com/ilpanich/axiam-go-sdk",
    docsLabel: "pkg.go.dev",
    docsUrl: "https://pkg.go.dev/github.com/ilpanich/axiam-go-sdk#section-documentation",
    repoUrl: "https://github.com/ilpanich/axiam-go-sdk",
    examplesUrl: "https://github.com/ilpanich/axiam-go-sdk/tree/main/examples",
    coverageUrl: "https://coveralls.io/github/ilpanich/axiam-go-sdk?branch=main",
    pkg: "github.com/ilpanich/axiam-go-sdk",
    install: "go get github.com/ilpanich/axiam-go-sdk",
    blurb:
      "Context-aware client with net/http middleware and idiomatic error types.",
    highlights: [
      "context.Context on every call",
      "net/http middleware",
      "Generated gRPC + protobuf types",
    ],
    quickstart: `client, _ := axiam.New(axiam.Config{
    BaseURL:    "https://iam.acme.dev",
    TenantSlug: "acme",
    OrgSlug:    "acme",
})

client.Login(ctx, email, password)
ok, _ := client.Can(ctx, "read", "doc:1")`,
    guardLabel: "Guard by middleware",
    guardExample: `mux := http.NewServeMux()

// Require wraps the handler with an authorization check that
// runs before it — a denied request never reaches getDoc.
mux.Handle("GET /docs/{id}",
    axiam.Require("read", "doc:{id}")(http.HandlerFunc(getDoc)))`,
  },
  {
    id: "kotlin",
    name: "Kotlin",
    abbr: "Kt",
    registry: "Maven Central",
    registryUrl:
      "https://central.sonatype.com/artifact/io.github.ilpanich/axiam-sdk-kotlin",
    docsLabel: "javadoc.io",
    docsUrl: "https://javadoc.io/doc/io.github.ilpanich/axiam-sdk-kotlin",
    repoUrl: "https://github.com/ilpanich/axiam-kotlin-sdk",
    examplesUrl: "https://github.com/ilpanich/axiam-kotlin-sdk/tree/main/examples",
    coverageUrl: "https://coveralls.io/github/ilpanich/axiam-kotlin-sdk?branch=main",
    pkg: "io.github.ilpanich:axiam-sdk-kotlin",
    install: 'implementation("io.github.ilpanich:axiam-sdk-kotlin:1.0.0-beta07")',
    blurb:
      "Coroutine-native REST client for the JVM, with Ktor route guards and declarative helpers.",
    highlights: [
      "Coroutines — every op is a suspend fn",
      "Ktor plugin + guard annotations",
      "Sensitive<T> secrets, strict TLS & mTLS",
    ],
    quickstart: `import io.axiam.sdk.AxiamClient
import kotlinx.coroutines.runBlocking

runBlocking {
    AxiamClient.builder("https://iam.acme.dev", tenantId = "acme")
        .orgSlug("acme")
        .build()
        .use { axiam ->
            val result = axiam.login(email, password)
            if (result.mfaRequired)
                axiam.verifyMfa(result.challengeToken!!, totpCode)
            val ok = axiam.can("read", resourceId = "doc:1")
        }
}`,
    guardLabel: "Guard by Ktor plugin",
    guardExample: `import io.axiam.sdk.ktor.*

install(AxiamAuthentication) { client = axiamClient }

routing {
    // requireAccess runs the check before the body — a deny short-circuits.
    get("/documents/{id}") {
        val user = call.requireAccess("read", call.parameters["id"]!!)
            ?: return@get
        call.respondText("hello \${user.userId}")
    }
}`,
  },
  {
    id: "swift",
    name: "Swift",
    abbr: "Sw",
    registry: "SwiftPM",
    registryUrl: "https://github.com/ilpanich/axiam-swift-sdk",
    docsLabel: "DocC",
    docsUrl: "https://ilpanich.github.io/axiam-swift-sdk/",
    repoUrl: "https://github.com/ilpanich/axiam-swift-sdk",
    examplesUrl: "https://github.com/ilpanich/axiam-swift-sdk/tree/main/Examples",
    coverageUrl: "https://coveralls.io/github/ilpanich/axiam-swift-sdk?branch=main",
    pkg: "AxiamSDK",
    install:
      '.package(url: "https://github.com/ilpanich/axiam-swift-sdk.git", from: "1.0.0-beta07")',
    blurb:
      "Cross-platform REST client on SwiftNIO — client-cert mTLS works on Linux and Apple platforms alike.",
    highlights: [
      "AsyncHTTPClient + NIOSSL, one code path",
      "async/await, single-flight refresh",
      "Sensitive<T>, custom-CA & client-cert mTLS",
    ],
    quickstart: `import AxiamSDK

let config = try AxiamConfig(
    baseURL: URL(string: "https://iam.acme.dev")!,
    tenantSlug: "acme",
    orgSlug: "acme")
let axiam = try AxiamClient(config: config)

switch try await axiam.login(email: email, password: password) {
case .authenticated(let user): print("in as \\(user.userID)")
case .mfaRequired:             try await axiam.verifyMfa(totpCode)
case .mfaSetupRequired:        break
}
let ok = try await axiam.can("read", resource: "doc:1")`,
    guardLabel: "Guard by helper factory",
    guardExample: `// makeGuards() returns declarative check factories (§11).
let guards = axiam.makeGuards()
let requireRead = guards.requireAccess("read", resource: "doc:1")

let ctx = AxiamRequestContext(
    headers: ["Authorization": "Bearer \\(jwt)", "X-Tenant-ID": "acme"],
    cookies: ["axiam_access": cookieJwt])

// Throws AuthzError (403) if denied — never reaches your handler.
let user = try await requireRead(ctx)`,
  },
  {
    id: "c",
    name: "C",
    abbr: "C",
    registry: "vcpkg · CMake",
    registryUrl: "https://github.com/ilpanich/axiam-c-sdk#install",
    docsLabel: "Doxygen",
    docsUrl: "https://ilpanich.github.io/axiam-c-sdk/",
    repoUrl: "https://github.com/ilpanich/axiam-c-sdk",
    examplesUrl: "https://github.com/ilpanich/axiam-c-sdk/tree/main/examples",
    coverageUrl: "https://coveralls.io/github/ilpanich/axiam-c-sdk?branch=main",
    pkg: "axiam-c-sdk",
    install: "vcpkg install axiam-c-sdk --overlay-ports=./ports",
    blurb:
      "C11 client over libcurl + OpenSSL — a small, offline-friendly REST surface with mTLS.",
    highlights: [
      "C11, every symbol axiam_-prefixed",
      "libcurl HTTP, strict TLS & in-memory mTLS",
      "Framework-agnostic route guard",
    ],
    quickstart: `#include <axiam/axiam.h>

axiam_client_config_t *cfg = axiam_client_config_new();
axiam_client_config_set_base_url(cfg, "https://iam.acme.dev");
axiam_client_config_set_tenant_slug(cfg, "acme");
axiam_client_config_set_org_slug(cfg, "acme");

axiam_error_t err;
axiam_client_t *axiam = axiam_client_new(cfg, &err);
axiam_client_config_free(cfg);

axiam_login_result_t login = {0};
axiam_login(axiam, email, password, &login, &err);

axiam_check_result_t res = {0};
axiam_check_access(axiam, "read", "doc:1", NULL, NULL, &res, &err);
printf("allowed: %d\\n", res.allowed);`,
    guardLabel: "Guard by macro",
    guardExample: `#include <axiam/guard.h>

// The adapter fills axiam_headers_t from the real request; the guard
// verifies the session (JWKS) then runs the check — fail closed.
axiam_guard_status_t st =
    AXIAM_REQUIRE_ACCESS(axiam, &headers, "read", "doc:1", NULL);

if (st != AXIAM_GUARD_ALLOW)
    return respond(st);   // 401 / 403 / 503 — never reaches the handler`,
  },
  {
    id: "cpp",
    name: "C++",
    abbr: "C++",
    registry: "vcpkg · Conan",
    registryUrl: "https://github.com/ilpanich/axiam-cplusplus-sdk#install",
    docsLabel: "Doxygen",
    docsUrl: "https://ilpanich.github.io/axiam-cplusplus-sdk/",
    repoUrl: "https://github.com/ilpanich/axiam-cplusplus-sdk",
    examplesUrl:
      "https://github.com/ilpanich/axiam-cplusplus-sdk/tree/main/examples",
    coverageUrl: "https://coveralls.io/github/ilpanich/axiam-cplusplus-sdk?branch=main",
    pkg: "axiam-cpp-sdk",
    install: "vcpkg install axiam-cpp-sdk --overlay-ports=./ports",
    blurb:
      "Idiomatic C++17 client over libcurl + OpenSSL — exceptions, RAII and framework-agnostic guards.",
    highlights: [
      "C++17, axiam:: namespace, RAII",
      "libcurl + OpenSSL, strict TLS & mTLS",
      "Route guards + AXIAM_REQUIRE_ACCESS",
    ],
    quickstart: `#include <axiam/axiam.hpp>

axiam::Client axiam = axiam::Client::builder()
    .base_url("https://iam.acme.dev")
    .tenant_slug("acme")
    .org_slug("acme")
    .build();

auto login = axiam.login(email, password);
if (login.mfa_required)
    login = axiam.verify_mfa(login.challenge_token, totp);

axiam::AccessDecision d = axiam.check_access("read", "doc:1");
std::cout << "allowed=" << std::boolalpha << d.allowed << "\\n";`,
    guardLabel: "Guard by helper",
    guardExample: `#include <axiam/guard.hpp>

// The host adapter authenticates the request into an AxiamUser; the
// helpers compose on top of check_access and fail closed.
void handler(axiam::Client& axiam,
             const std::optional<axiam::AxiamUser>& user) {
    axiam::require_auth(user);                 // 401 if unauthenticated
    AXIAM_REQUIRE_ACCESS(axiam, user, "read", "doc:1");  // 403 if denied
    // ... serve the protected resource ...
}`,
  },
];

export const POSTS: Post[] = [
  {
    slug: "beta-phase",
    date: "August 30, 2026",
    dateShort: "Aug 2026",
    tag: "Release",
    author: "The AXIAM team",
    title: "AXIAM reaches beta",
    excerpt:
      "Seven beta releases in, AXIAM officially enters its beta phase — still not for production, but from here the hardening is the work.",
    body: [
      {
        type: "p",
        text: "AXIAM has left alpha. The beta line opened with 1.0.0-beta01 on 26 August 2026 and has run to 1.0.0-beta07, which — correcting an issue in the SDK contract fan-out — is the release we intend as the official beta candidate. All eleven SDKs are tagged alongside it.",
      },
      {
        type: "p",
        text: "Beta means the shape of the system is settled. The domain model, the wire contracts and the security posture are no longer moving under integrators: the OpenAPI document is content-digested, the SDK behavioral contract is versioned and vendored, and a drift gate in CI fails the build when any of the eleven SDK repositories falls behind either one. What changes from here should be defects, not design.",
      },
      { type: "h", text: "What beta does not mean" },
      {
        type: "p",
        text: "It does not mean production-ready, and we would rather say so plainly than let the label imply it. AXIAM is not yet usable in production. Everything in it needs deeper testing than it has had, and it has had no independent third-party penetration test or security certification.",
      },
      {
        type: "p",
        text: "Some surfaces need testing from the ground up, and they are worth naming rather than leaving a reader to discover: SAML and OIDC federation, and SCIM provisioning. All three are implemented, specified and unit-tested, and the admin UI drives their configuration — but no end-to-end run has yet exercised them against a real external identity provider or a real Okta or Entra tenant. The end-to-end federation tests today mock the external IdP redirect. Treat those three as implemented-but-unproven, not as tested.",
      },
      {
        type: "quote",
        text: "Beta is where the label stops being about features and starts being about evidence. We would rather name the surfaces we have not proven than let the word do it for us.",
      },
      { type: "h", text: "What the beta line has hardened so far" },
      {
        type: "p",
        text: "Seven releases in five days, almost all of them driven by one thing: a full end-to-end permission matrix run against the production container image rather than a development proxy. That run found problems no unit test was ever going to. A tenant administrator could flip a certificate authority's mTLS trust-anchor flag and mint identities trusted across sibling tenants. The machine-facing REST surface was unreachable by a machine. An empty environment variable closed the first-run bootstrap gate entirely. The admin console could keep rendering the previous tenant's rows after a switch.",
      },
      {
        type: "p",
        text: "Those are fixed, and the fixes brought structure with them: organization-level actions now require a principal that lives in the organization scope rather than merely holding the permission; a role assignment can be confined to named tenants; enrolling a passkey turns the second-factor requirement on; device authentication requires the certificate chain to reach a CA an administrator has enabled as a trust anchor, on the proxy-terminated path exactly as on the native one; and a rolling deployment no longer logs its surviving replicas out of the datastore.",
      },
      {
        type: "p",
        text: "The STRIDE threat model grew to 211 threats across nine diagrams, 196 of them mitigated and 15 recorded openly as shared-responsibility or accepted items. Every one of the findings above is written down there rather than quietly absorbed — the Security section carries the model, the compliance self-assessment and the open risk register in full.",
      },
      {
        type: "p",
        text: "Addendum, 4 September 2026: four releases on, the model is now 236 threats, 219 mitigated and 17 open. Two of the waves it grew by had been written into the STRIDE document at beta08 without ever reaching the Threat Dragon JSON, so the site spent three releases rendering a model its own source had outgrown; that gap is closed.",
      },
      {
        type: "p",
        text: "What those four releases changed, one sentence each. The backend now sits on the public origin terminating its own TLS 1.3, which removed a proxy hop and the cleartext container-network leg every password and token used to cross, and fixed the rate-limit key with it ([T-212](#/security/diagram/7/T-212)…[T-217](#/security/diagram/7/T-217)). A public login surface arrived — an unauthenticated providers listing that cannot tell an unknown organization from an unconfigured one, sign-in buttons, a plain-OAuth2 variant with its downgrade stated, and 60-second single-use handoff codes that can only be delivered to the deployment's own origins ([T-218](#/security/diagram/3/T-218)…[T-225](#/security/diagram/3/T-225)). An assignment naming no resource became tenant-wide rather than silently inert, scoped grants now inherit down the resource lineage without widening sideways, and the authorization-check endpoints resolve the acting tenant through the same reach check as every other route ([T-226](#/security/diagram/4/T-226)…[T-228](#/security/diagram/4/T-228)). WebAuthn user verification became a tightening-only policy instead of a library constant, so a security key with no PIN enrols as a second factor ([T-229](#/security/diagram/1/T-229), [T-230](#/security/diagram/1/T-230)). And Vault is run as the production secret store it is: Raft storage, a policy that is one checked file, and a seeder that can no longer mistake a refused read for an empty Vault and mint fresh keys over the live ones ([T-231](#/security/diagram/7/T-231), [T-232](#/security/diagram/7/T-232)).",
      },
      {
        type: "p",
        text: "Two of the new entries are recorded open rather than closed, which is the point of keeping the register honest: the unseal key sitting on the same disk as the sealed data ([T-216](#/security/diagram/7/T-216)), and the gRPC listener reading its certificate once at startup ([T-234](#/security/diagram/7/T-234)) — bridged by a restart in the deploy hook until it is fixed. Neither is on AXIAM's own request path, which still carries no open Critical or High finding.",
      },
      { type: "h", text: "Trying it, and telling us what breaks" },
      {
        type: "p",
        text: "The quickstart in the documentation brings a full stack up on Docker Compose and walks the first-run bootstrap. Run it against something you do not mind breaking, and please report what you find — issues on GitHub for defects, and the private advisory form in SECURITY.md for anything security-relevant. Reproductions from people integrating against the SDKs are the most useful thing we can receive right now, and federation, SAML, OIDC and SCIM are where we most need them.",
      },
    ],
  },
  {
    slug: "alpha-release",
    date: "July 16, 2026",
    dateShort: "Jul 2026",
    tag: "Release",
    author: "The AXIAM team",
    title: "AXIAM ships its first alpha release",
    excerpt:
      "The first alpha is out. The platform is feature-complete, but heavy testing and benchmarking lie ahead before it can reach beta.",
    body: [
      {
        type: "p",
        text: "Today AXIAM cuts its first alpha release. Every phase on the roadmap is implemented — authentication and MFA, the RBAC authorization engine, REST/gRPC/AMQP surfaces, OAuth2 & OIDC, SAML/OIDC federation, PKI, webhooks and the tamper-evident audit trail are all in place and wired together end to end.",
      },
      {
        type: "p",
        text: "Alpha means exactly what it says: the feature set is complete, but the release is early. Before AXIAM can move to beta it needs a great deal more testing under load and a real, measured benchmark campaign — and until those land, it should not be used in production.",
      },
      { type: "h", text: "What happens before beta" },
      {
        type: "p",
        text: "The road to beta is about confidence, not features. We are expanding integration and end-to-end coverage, running long-duration soak and fuzz tests across every protocol, and hardening the security-sensitive paths. In parallel, the benchmark harness will replace the placeholder figures on the Benchmarks page with real, reproducible numbers comparing AXIAM against other open-source IAM systems.",
      },
      {
        type: "quote",
        text: "Feature-complete is the start line for hardening, not the finish line. Alpha is where the heavy testing and benchmarking begin.",
      },
      {
        type: "p",
        text: "We'll publish results and progress here as the test and benchmark corpus grows. Feedback, bug reports and reproductions from early adopters are hugely welcome while we drive toward a stable beta.",
      },
    ],
  },
  {
    slug: "feature-complete",
    date: "June 18, 2026",
    dateShort: "Jun 2026",
    tag: "Milestone",
    author: "The AXIAM team",
    title: "AXIAM reaches feature-complete across all 19 phases",
    excerpt:
      "From project foundation to a security-audited, SDK-complete platform — every phase on the roadmap is now marked done.",
    body: [
      {
        type: "p",
        text: "Nineteen phases and sixty-four tasks after the first commit, AXIAM has reached feature-complete. Authentication, the authorization engine, REST/gRPC/AMQP surfaces, OAuth2 & OIDC, federation, PKI, webhooks and the audit trail are all in place — and each was built through human-AI pair programming.",
      },
      { type: "h", text: 'What "done" means' },
      {
        type: "p",
        text: "Every phase shipped with tests and passed review. That said, AXIAM remains a work in progress and should not be used in production until it reaches a stable release; the core is complete, hardening continues.",
      },
      {
        type: "quote",
        text: "One architect, pairing with an AI coding agent, producing a production-quality IAM system — that was always the experiment.",
      },
      {
        type: "p",
        text: "Next up: expanding the benchmark corpus against Keycloak and Zitadel, and cutting the first tagged SDK releases.",
      },
    ],
  },
  {
    slug: "seven-sdks",
    date: "May 2, 2026",
    dateShort: "May 2026",
    tag: "SDKs",
    author: "The AXIAM team",
    title: "Seven SDKs, one behavioral contract",
    excerpt:
      "Rust, TypeScript, Python, Java, C#, PHP and Go — each vendoring the same cross-language contract, OpenAPI spec and protobufs.",
    body: [
      {
        type: "p",
        text: "AXIAM now ships seven official client SDKs. They live in their own repositories, but each one vendors a copy of the same CONTRACT.md, openapi.json and proto/ definitions — so behavior is identical no matter which language you reach for.",
      },
      { type: "h", text: "A shared contract" },
      {
        type: "p",
        text: "The contract spans §1–§11: login and MFA, REST/gRPC/AMQP authorization, Sensitive<T> secret handling, strict TLS, single-flight refresh, and declarative route guards. CI gates enforce conformance per language.",
      },
      {
        type: "p",
        text: "Tenant is always an explicit constructor parameter — AXIAM is multi-tenant, and there is no default tenant.",
      },
      {
        type: "p",
        text: "Addendum, August 2026: there are now eleven. Kotlin, Swift, C and C++ joined the seven above, and the contract they all vendor has grown well past §11 — UMA, OPAQUE, reactors, WebAuthn, the account lifecycle, pushed authorization requests and the management API. The SDKs page carries the current set and what each one covers.",
      },
    ],
  },
  {
    slug: "why-rust",
    date: "March 14, 2026",
    dateShort: "Mar 2026",
    tag: "Engineering",
    author: "The AXIAM team",
    title: "Why we built AXIAM in Rust on SurrealDB",
    excerpt:
      "Performance, memory safety and a smaller footprint — plus a document/graph store that maps naturally to a resource hierarchy.",
    body: [
      {
        type: "p",
        text: "IAM is on the hot path of every request. Rust lets AXIAM deliver competitor-level throughput at a smaller footprint, with memory safety that closes off entire vulnerability classes by construction.",
      },
      { type: "h", text: "Why SurrealDB" },
      {
        type: "p",
        text: "Roles, permissions and groups cascade through resource trees. A document/graph hybrid models that hierarchy directly, instead of forcing it into rows and join tables.",
      },
      {
        type: "p",
        text: "The crypto stack — Argon2id, EdDSA (Ed25519) and AES-256-GCM — rounds out a system that is secure by design.",
      },
    ],
  },
];

/**
 * Roadmap phases. Start/end dates are approximate, reconstructed from the
 * project's GitHub issue tracker (each task issue carries a `phase:N` label and
 * a close date) and commit history; phases are sequential and do not overlap.
 * Phases 0–18 are the delivered 64-task roadmap; phase 19 is the hardening
 * effort that began after the platform reached feature-complete and closed
 * when it reached beta; phase 20 is the open-ended beta line.
 */
export const PHASES: Phase[] = [
  {
    n: 0,
    title: "Project foundation",
    focus: "CI, dev environment, tooling",
    start: "Feb 24, 2026",
    end: "Feb 25, 2026",
    status: "done",
  },
  {
    n: 1,
    title: "Core domain types & DB repositories",
    focus: "Domain model on SurrealDB",
    start: "Feb 25, 2026",
    end: "Feb 26, 2026",
    status: "done",
  },
  {
    n: 2,
    title: "Authentication",
    focus: "Password, JWT, MFA",
    start: "Feb 26, 2026",
    end: "Feb 27, 2026",
    status: "done",
  },
  {
    n: 3,
    title: "Authorization engine",
    focus: "RBAC with resource hierarchy",
    start: "Feb 27, 2026",
    end: "Feb 28, 2026",
    status: "done",
  },
  {
    n: 4,
    title: "REST API",
    focus: "Actix-Web",
    start: "Feb 28, 2026",
    end: "Mar 3, 2026",
    status: "done",
  },
  {
    n: 5,
    title: "gRPC API",
    focus: "Tonic + Protocol Buffers",
    start: "Mar 3, 2026",
    end: "Mar 4, 2026",
    status: "done",
  },
  {
    n: 6,
    title: "AMQP integration",
    focus: "RabbitMQ via Lapin",
    start: "Mar 4, 2026",
    end: "Mar 5, 2026",
    status: "done",
  },
  {
    n: 7,
    title: "Audit logging",
    focus: "Append-only, tamper-evident",
    start: "Mar 5, 2026",
    end: "Mar 6, 2026",
    status: "done",
  },
  {
    n: 8,
    title: "PKI & certificates",
    focus: "Hierarchical X.509, mTLS",
    start: "Mar 6, 2026",
    end: "Mar 8, 2026",
    status: "done",
  },
  {
    n: 9,
    title: "Webhook system",
    focus: "HMAC-SHA256 signed delivery",
    start: "Mar 8, 2026",
    end: "Mar 10, 2026",
    status: "done",
  },
  {
    n: 10,
    title: "OAuth2 & OIDC",
    focus: "PKCE, client credentials, rotation",
    start: "Mar 10, 2026",
    end: "Mar 14, 2026",
    status: "done",
  },
  {
    n: 11,
    title: "Federation",
    focus: "SAML + OIDC SSO",
    start: "Mar 14, 2026",
    end: "Mar 15, 2026",
    status: "done",
  },
  {
    n: 12,
    title: "Hierarchical settings & password policy",
    focus: "Cascading configuration",
    start: "Mar 15, 2026",
    end: "Mar 19, 2026",
    status: "done",
  },
  {
    n: 13,
    title: "Email service & account flows",
    focus: "Verification, recovery",
    start: "Mar 19, 2026",
    end: "Mar 22, 2026",
    status: "done",
  },
  {
    n: 14,
    title: "Advanced MFA",
    focus: "TOTP step-up and beyond",
    start: "Mar 22, 2026",
    end: "Mar 26, 2026",
    status: "done",
  },
  {
    n: 15,
    title: "Admin frontend",
    focus: "React admin UI",
    start: "Mar 26, 2026",
    end: "Mar 28, 2026",
    status: "done",
  },
  {
    n: 16,
    title: "Docker & Kubernetes",
    focus: "Deployment manifests",
    start: "Mar 28, 2026",
    end: "Mar 31, 2026",
    status: "done",
  },
  {
    n: 17,
    title: "SDKs",
    focus: "Rust, TS, Python, Java, C#, PHP, Go — Kotlin, Swift, C and C++ followed",
    start: "Mar 31, 2026",
    end: "Jul 3, 2026",
    status: "done",
  },
  {
    n: 18,
    title: "Security audit, compliance, docs",
    focus: "Hardening & documentation",
    start: "Jul 3, 2026",
    end: "Jul 12, 2026",
    status: "done",
  },
  {
    n: 19,
    title: "Benchmarking, testing, fixing & improving",
    focus: "Load & soak testing, benchmarks, bug fixes and the hardening that reached beta",
    start: "Jul 12, 2026",
    end: "Aug 26, 2026",
    status: "done",
  },
  {
    n: 20,
    title: "Beta line — stabilisation toward 1.0",
    focus:
      "End-to-end-driven hardening, SDK contract fan-out, and the deeper testing federation, SAML, OIDC and SCIM still need before 1.0 — plus the beta08…beta11 wave: the backend on the public origin terminating its own TLS, a public login-provider surface, the authorization-reach fixes, and Vault run as a production secret store",
    start: "Aug 26, 2026",
    end: "Ongoing",
    status: "ongoing",
  },
];

/**
 * Benchmark scenarios, transcribed from
 * `benchmarks/PUBLIC_BENCH_ANALYSIS.md` (sixth draft, run 5 of 2026-08-05/06,
 * AXIAM 1.0.0-alpha24 — the published, digest-pinned release image — vs
 * Keycloak 26.7.0 vs Zitadel v4.16.2). All figures are the p0-plaintext
 * profile from the capped matrix (§1/§8), **median of 3 runs** (per-cell
 * throughput spread ±0.3–2.1% on AXIAM cells, ±12–17% on the batch cells).
 * Only valid cells are charted; comparability labels are carried onto the
 * chart.
 */
export const BENCH_SCENARIOS: BenchScenario[] = [
  {
    id: "client_credentials",
    title: "Machine-to-machine token issuance",
    unit: "throughput · requests/s · plaintext · median of 3",
    bars: [
      { target: "AXIAM", value: 2804, display: "2,804", axiam: true },
      { target: "Zitadel", value: 431, display: "431" },
      { target: "Keycloak", value: 354, display: "354" },
    ],
    takeaway:
      "AXIAM issues 7.9× more tokens/s than Keycloak and 6.5× more than Zitadel — and, new this run, roughly 8× under TLS 1.3 and mutual TLS too. The previous draft's one glaring asterisk, a −57% drop on this endpoint under TLS, is gone: the cause was Nagle's algorithm interacting with delayed ACKs, and with TCP_NODELAY shipped as the default the TLS penalty is now −2.0%.",
  },
  {
    id: "introspection",
    title: "Token introspection (RFC 7662)",
    unit: "throughput · requests/s · plaintext · median of 3",
    bars: [
      { target: "AXIAM", value: 4504, display: "4,504", axiam: true },
      { target: "Keycloak", value: 1888, display: "1,888" },
      { target: "Zitadel", value: 941, display: "941" },
    ],
    takeaway:
      "2.4× Keycloak and 4.8× Zitadel, with a ~1.8× better p95 (48 vs 82 ms) and a near-zero TLS/mTLS penalty (−2.5% / −2.8%). Held within ±0.5% across three runs on the released image.",
  },
  {
    id: "jwks",
    title: "JWKS fetch (RFC 7517)",
    unit: "throughput · requests/s · plaintext · median of 3",
    bars: [
      { target: "AXIAM", value: 26680, display: "26,680", axiam: true },
      { target: "Keycloak", value: 4573, display: "4,573" },
      { target: "Zitadel", value: 2091, display: "2,091" },
    ],
    takeaway:
      "A 5.8–12.8× gap — and still limited by the load generator rather than by AXIAM: k6 itself burned ~5 CPU cores while the AXIAM server sat below 1.7 of its 2, so the true ceiling is higher. This cell measures latency, not capacity.",
  },
  {
    id: "userinfo",
    title: "OIDC userinfo — REST",
    unit: "throughput · requests/s · plaintext · median of 3",
    bars: [
      { target: "AXIAM", value: 4752, display: "4,752", axiam: true },
      { target: "Keycloak", value: 3721, display: "3,721" },
      { target: "Zitadel", value: 995, display: "995" },
    ],
    takeaway:
      "AXIAM leads 1.3× Keycloak and 4.8× Zitadel while its database is pegged. On whole-stack req/s-per-core Keycloak again wins this cell; on server-only CPU per request AXIAM is 2.1× cheaper (0.25 vs 0.53 cpu·ms). Both are published, as in every draft.",
  },
  {
    id: "userinfo_grpc",
    title: "OIDC userinfo — gRPC",
    unit: "throughput · requests/s · plaintext · median of 3",
    bars: [
      { target: "AXIAM", value: 12307, display: "12,307", axiam: true },
      { target: "Zitadel", value: 191, display: "191" },
    ],
    takeaway:
      "12,307 identity reads/s at a 6 ms p95 — 2.6× AXIAM's own REST path and 3.3× Keycloak's best userinfo number. Zitadel's own gRPC userinfo measured 191–201/s on the same harness, 80% below its REST cell: its gRPC surface is a management API, which is fair, and is exactly why treating gRPC as a first-class data plane is a differentiator. Keycloak exposes no gRPC equivalent.",
  },
  {
    id: "password_login",
    title: "Password login (real hashing)",
    unit: "throughput · requests/s · plaintext · median of 3",
    bars: [
      { target: "AXIAM", value: 69, display: "69", axiam: true },
      { target: "Keycloak", value: 47, display: "(47)" },
      { target: "Zitadel", value: 2.0, display: "(2)" },
    ],
    takeaway:
      "AXIAM is the only target valid at every profile — 69 req/s at a 761 ms p95, on ~119 MiB of average server memory. Parenthesized numbers failed our own validity gate: Keycloak completed 1 of 3 runs cleanly at p0 (it did produce its first valid login cell of the series at p2 — 51 req/s), and Zitadel's default bcrypt cost puts it at ~22 s p50. The promised 4 GiB Keycloak attempt ran, and did not rescue it: ~21 req/s at a ~2.5 s p95, slower than its 2 GiB survivor runs.",
    note: "2 of 3 targets excluded by the validity gate",
  },
  {
    id: "token_refresh",
    title: "Session / token refresh",
    unit: "throughput · requests/s · plaintext · median of 3",
    bars: [
      { target: "AXIAM", value: 545, display: "545", axiam: true },
      { target: "Keycloak", value: 377, display: "377" },
    ],
    takeaway:
      "Informational, not a like-for-like race: AXIAM has no ROPC/password grant by design, so its cell measures session-cookie refresh (CSRF double-submit, single-use rotation) while Keycloak's measures the OAuth2 refresh-token grant. Honesty first — AXIAM's refresh regressed 35% since the previous draft (839 → 545 req/s, p50 47.5 → 88.8 ms), with no harness change on that path; the suspects are our own post-run-4 security hardening and/or database version drift, and the bisection is open. Zitadel needs an offline_access flow the harness doesn't implement.",
    note: "protocol-variant — and a −35% regression we introduced ourselves",
  },
];

/**
 * Whole-stack efficiency, head-to-head (p0-plaintext, median-of-3, run 5).
 * `req/s per core` is higher-is-better; `cpu·ms/req` is lower-is-better.
 * AXIAM's figures still carry its audit broker and, on some cells, a
 * saturated database inside them — which is why Keycloak edges it on the
 * userinfo cpu·ms/req cell (server-only, AXIAM's server is 2.1× cheaper
 * there; both breakdowns are published in the raw report).
 */
export const BENCH_EFFICIENCY: BenchEfficiencyRow[] = [
  { scenario: "Client credentials", perCore: ["816", "171", "122"], cpuMs: ["1.23", "5.85", "8.21"] },
  { scenario: "Token introspection", perCore: ["1,269", "799", "252"], cpuMs: ["0.79", "1.25", "3.98"] },
  { scenario: "JWKS fetch", perCore: ["15,855", "2,288", "701"], cpuMs: ["0.06", "0.44", "1.43"] },
  { scenario: "OIDC userinfo", perCore: ["1,437", "1,863", "346"], cpuMs: ["0.70", "0.54", "2.89"] },
];

/**
 * AXIAM-only authorization decisions (no head-to-head — Keycloak and Zitadel
 * expose no equivalent endpoint). Each check is a full RBAC evaluation against
 * live data. Values are p0-plaintext throughput (requests/s, median-of-3; the
 * cache-ON rows are a labeled best-case sensitivity pass, not the default).
 */
export const BENCH_AUTHZ: BenchScenario = {
  id: "authz",
  title: "Authorization decisions (AXIAM-only)",
  unit: "decisions/s · plaintext · median of 3 · decision cache OFF unless labelled",
  bars: [
    { target: "REST · single", value: 1032, display: "1,032", axiam: true },
    { target: "gRPC · single", value: 1268, display: "1,268", axiam: true },
    { target: "REST · batch", value: 5130, display: "5,130", axiam: true },
    { target: "gRPC · batch", value: 4640, display: "4,640", axiam: true },
    { target: "REST · caches ON", value: 11647, display: "11,647", axiam: true },
    { target: "gRPC · cache ON", value: 11172, display: "11,172", axiam: true },
  ],
  takeaway:
    "Single checks are up +37% (REST) and +43% (gRPC) on the released image, the direct result of removing two full-table scans found with EXPLAIN after run 4 — a fix now guarded by CI tests that fail if any hot authorization query regresses to a table scan. The batch cells finally measure the strategy the product actually ships (`coalesced`), and the settled claim reproduces at matrix scale: 1,026 REST batch ops/s = 5,130 checks/s = 4.97× singles. The two cache rows are a labelled best-case pass, not the default: with both the decision cache and the session-validation cache on (5 s TTL), REST reaches parity with gRPC — confirming that REST's deficit was one extra database round-trip, its per-request session-revocation read. Caches stay OFF by default, and revocation through the API was measured to take effect 262 ms after the call even with them on.",
  note: "AXIAM-only — no competitor exposes an equivalent decision endpoint",
};

/**
 * Resource usage during the tests (run 5 §5) — p0-plaintext, median-of-3,
 * every server container capped identically at 2 CPUs / 2,048 MiB.
 * Values are `[AXIAM, Keycloak, Zitadel]`.
 */

/** Average RSS of the *server* container in MiB, by scenario. */
export const BENCH_MEMORY_AVG: BenchResourceRow[] = [
  { scenario: "JWKS fetch", values: [88, 836, 154] },
  { scenario: "Client credentials", values: [90, 710, 138] },
  { scenario: "Token introspection", values: [95, 752, 153] },
  { scenario: "Token refresh", values: [95, 755, null] },
  { scenario: "OIDC userinfo", values: [94, 756, 153] },
  { scenario: "Password login", values: [119, 853, 154], marker: "*" },
  { scenario: "Authorization check / batch", values: [94, null, null], marker: "†" },
];

/** The highest per-scenario server average observed anywhere in the run, in MiB. */
export const BENCH_MEMORY_WORST: BenchResourceRow = {
  scenario: "Highest scenario average, whole run",
  values: [119, 853, 154],
};

/** The identical per-server container memory cap, in MiB. */
export const BENCH_MEMORY_CAP = 2048;

/** Whole-stack memory range (server + database + broker), in MiB. */
export const BENCH_STACK_MEMORY: [string, string, string][] = [
  ["AXIAM", "375–533 MiB", "server + SurrealDB + RabbitMQ"],
  ["Keycloak", "816–973 MiB", "server + PostgreSQL"],
  ["Zitadel", "281–457 MiB", "server + PostgreSQL"],
];

/** CPU-milliseconds per request, whole stack unless noted (lower is better). */
export const BENCH_CPU_PER_REQ: BenchResourceRow[] = [
  { scenario: "Client credentials", values: [1.23, 5.85, 8.21] },
  { scenario: "Token introspection", values: [0.79, 1.25, 3.98] },
  { scenario: "JWKS fetch", values: [0.06, 0.44, 1.43] },
  { scenario: "OIDC userinfo", values: [0.7, 0.54, 2.89] },
  { scenario: "OIDC userinfo (server only)", values: [0.25, 0.53, 0.86] },
];

/** Requests per second per GiB of whole-stack RAM (higher is better). */
export const BENCH_RPS_PER_GIB: BenchResourceRow[] = [
  { scenario: "Client credentials", values: [6528, 416, 1239] },
  { scenario: "Token introspection", values: [9312, 2134, 2228] },
  { scenario: "OIDC userinfo", values: [11522, 4319, 2319] },
  { scenario: "JWKS fetch", values: [66270, 5022, 7351] },
];

/**
 * Security cost of TLS 1.3 (p2) and native, in-process mutual TLS (p3),
 * as a throughput delta against the plaintext (p0) cell of the same
 * scenario — run 5 §4, median-of-3, valid cells only. Negative is a cost.
 */
export const BENCH_TLS_COST: { scenario: string; tls: string; mtls: string }[] = [
  { scenario: "Client credentials", tls: "−2.0%", mtls: "−3.8%" },
  { scenario: "Token introspection", tls: "−2.5%", mtls: "−2.8%" },
  { scenario: "OIDC userinfo — REST / gRPC", tls: "−3.5% / −2.9%", mtls: "−6.6% / −3.0%" },
  { scenario: "Authz check — REST / gRPC", tls: "−0.8% / −0.2%", mtls: "−1.5% / −0.7%" },
  { scenario: "Authz batch — REST / gRPC", tls: "−1.1% / −1.2%", mtls: "−2.2% / −0.3%" },
  { scenario: "Session refresh", tls: "−0.9%", mtls: "−0.5%" },
  { scenario: "Password login", tls: "+0.3%", mtls: "−2.1%" },
  { scenario: "JWKS fetch", tls: "−9.7%", mtls: "−10.2%" },
];

/**
 * SDK client benchmarks — run 5 §9. All eleven official SDKs ran the same
 * four operations against the same seeded AXIAM at plaintext, **three passes
 * each, medianed**, with a matched-concurrency k6 wire baseline measured on
 * the same host first — which is what makes the overhead column meaningful
 * for the first time in this series.
 */
export const BENCH_SDK_LATENCY: BenchSdkRow[] = [
  { sdk: "Rust", login: "257.5", refresh: "17.3", checkP50: "10.0", checkP95: "59.8", thr: "869", overhead: "+2.7", best: true },
  { sdk: "Go", login: "253.8", refresh: "17.3", checkP50: "10.1", checkP95: "60.0", thr: "840", overhead: "+2.9" },
  { sdk: "Java", login: "254.7", refresh: "17.3", checkP50: "10.3", checkP95: "60.1", thr: "835", overhead: "+3.0" },
  { sdk: "C#", login: "234.6", refresh: "17.2", checkP50: "10.3", checkP95: "60.8", thr: "821", overhead: "+3.7", flag: "merged 2 of 3 passes" },
  { sdk: "TypeScript", login: "255.7", refresh: "16.7", checkP50: "18.1", checkP95: "34.2", thr: "805", overhead: "(−22.9)", flag: "baseline comparability under audit" },
  { sdk: "Kotlin", login: "233.4", refresh: "17.2", checkP50: "11.0", checkP95: "61.7", thr: "773", overhead: "+4.6" },
  { sdk: "Swift", login: "231.7", refresh: "17.3", checkP50: "11.3", checkP95: "61.4", thr: "747", overhead: "+4.3" },
  { sdk: "Python", login: "238.9", refresh: "17.3", checkP50: "40.2", checkP95: "116.8", thr: "311", overhead: "+59.7", flag: "slow outlier — being profiled" },
  { sdk: "C++", login: "242.2", refresh: "17.2", checkP50: "3.2", checkP95: "280.2", thr: "313", overhead: "+223.1", flag: "reconnect-shaped p95 tail, under investigation" },
  { sdk: "C", login: "—", refresh: "—", checkP50: "3.0", checkP95: "3.8", thr: "318", overhead: "—", serial: true },
  { sdk: "PHP", login: "—", refresh: "—", checkP50: "3.6", checkP95: "4.3", thr: "272", overhead: "—", serial: true },
];

/**
 * Each SDK's own client-side process cost over its whole bench — new in run 5,
 * and half the story for IoT and sidecar deployments where the client, not the
 * server, is the constrained side.
 */
export const BENCH_SDK_FOOTPRINT: BenchSdkFootprintRow[] = [
  { sdk: "Go", runtime: "go 1.26", cpu: 3.3, rss: 36 },
  { sdk: "PHP", runtime: "php 8.5", cpu: 5.6, rss: 59, serial: true },
  { sdk: "C#", runtime: ".NET 8", cpu: 10.3, rss: 105 },
  { sdk: "TypeScript", runtime: "node 22", cpu: 13.1, rss: 125 },
  { sdk: "Swift", runtime: "swift 6.3", cpu: 13.3, rss: 48 },
  { sdk: "C", runtime: "gcc 16, C11", cpu: 13.9, rss: 13, serial: true },
  { sdk: "Kotlin", runtime: "JVM 21", cpu: 17.1, rss: 458 },
  { sdk: "C++", runtime: "g++ 16", cpu: 17.6, rss: 39 },
  { sdk: "Java", runtime: "JVM 21", cpu: 21.1, rss: 306 },
  { sdk: "Rust", runtime: "cargo", cpu: 23.4, rss: 23 },
  { sdk: "Python", runtime: "python 3.14", cpu: 40.0, rss: 88 },
];

export const GITHUB_URL = "https://github.com/ilpanich/axiam";

/**
 * Line coverage for the server workspace and the admin frontend, reported to
 * Coveralls by `.github/workflows/coverage.yml` on every push to main. Each
 * SDK repository reports its own coverage the same way — see `coverageUrl` on
 * the entries in `SDKS`.
 */
export const COVERALLS_URL =
  "https://coveralls.io/github/ilpanich/axiam?branch=main";
