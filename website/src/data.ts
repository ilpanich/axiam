import type {
  Sdk,
  Post,
  Phase,
  BenchScenario,
  BenchEfficiencyRow,
  BenchResourceRow,
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
    docsLabel: "tsdocs.dev",
    docsUrl: "https://tsdocs.dev/docs/axiam-sdk",
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
    docsLabel: "Read the Docs",
    docsUrl: "https://axiam-sdk.readthedocs.io/",
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
    install: 'implementation("io.github.ilpanich:axiam-sdk:1.0.0")',
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
    docsLabel: "fuget.org",
    docsUrl: "https://www.fuget.org/packages/Axiam.Sdk",
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
    install: 'implementation("io.github.ilpanich:axiam-sdk-kotlin:1.0.0-alpha15")',
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
      '.package(url: "https://github.com/ilpanich/axiam-swift-sdk.git", from: "1.0.0-alpha15")',
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
 * Phases 0–18 are the delivered 64-task roadmap; phase 19 is the open-ended
 * hardening effort that began after the platform reached feature-complete.
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
    focus: "Rust, TS, Python, Java, C#, PHP, Go",
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
    focus: "Load & soak testing, benchmarks, bug fixes and hardening toward beta",
    start: "Jul 12, 2026",
    end: "Ongoing",
    status: "ongoing",
  },
];

/**
 * Benchmark scenarios, transcribed from
 * `benchmarks/PUBLIC_BENCH_ANALYSIS.md` (fifth draft, run 4 of 2026-08-01/02,
 * AXIAM post-fix build vs Keycloak 26.7.0 vs Zitadel v4.15.2) — the first
 * matrix measured after the shared rate-limit write-behind fix. All figures
 * are the p0-plaintext profile from the capped matrix (§1/§8), **median of 3
 * runs** (per-cell throughput spread ±0.2–2.8% on AXIAM cells). Only valid
 * cells are charted; comparability labels are carried onto the chart.
 */
export const BENCH_SCENARIOS: BenchScenario[] = [
  {
    id: "client_credentials",
    title: "Machine-to-machine token issuance",
    unit: "throughput · requests/s · plaintext · median of 3",
    bars: [
      { target: "AXIAM", value: 2727, display: "2,727", axiam: true },
      { target: "Zitadel", value: 425, display: "425" },
      { target: "Keycloak", value: 354, display: "354" },
    ],
    takeaway:
      "AXIAM issues 7.7× more tokens/s than Keycloak and 6.4× more than Zitadel — up from 5.2×/4.3× in run 3, entirely from removing the synchronous rate-limit write (+50% on this endpoint). Reproduced within ±0.4% across three runs.",
  },
  {
    id: "introspection",
    title: "Token introspection (RFC 7662)",
    unit: "throughput · requests/s · plaintext · median of 3",
    bars: [
      { target: "AXIAM", value: 4387, display: "4,387", axiam: true },
      { target: "Keycloak", value: 1860, display: "1,860" },
      { target: "Zitadel", value: 932, display: "932" },
    ],
    takeaway:
      "Run 3's closest head-to-head is no longer close: +97% post-fix puts AXIAM at 2.4× Keycloak and 4.7× Zitadel, with a 1.7× better p95 (48 vs 82 ms) and a near-zero TLS penalty (−1.6%).",
  },
  {
    id: "jwks",
    title: "JWKS fetch (RFC 7517)",
    unit: "throughput · requests/s · plaintext · median of 3",
    bars: [
      { target: "AXIAM", value: 26371, display: "26,371", axiam: true },
      { target: "Keycloak", value: 4565, display: "4,565" },
      { target: "Zitadel", value: 2096, display: "2,096" },
    ],
    takeaway:
      "A 5.8–12.6× gap — and still limited by the load generator rather than by AXIAM: k6 itself burned ~5 CPU cores while the AXIAM server sat at 1.6 of its 2, so the true ceiling is higher.",
  },
  {
    id: "userinfo",
    title: "OIDC userinfo — REST",
    unit: "throughput · requests/s · plaintext · median of 3",
    bars: [
      { target: "AXIAM", value: 4547, display: "4,547", axiam: true },
      { target: "Keycloak", value: 3783, display: "3,783" },
      { target: "Zitadel", value: 1000, display: "1,000" },
    ],
    takeaway:
      "AXIAM leads 1.2× Keycloak and 4.5× Zitadel while its database is pegged — uncapped to 4 DB cores the same cell reaches 7,215 req/s. On whole-stack req/s-per-core Keycloak wins this cell; on server-only CPU per request AXIAM is 2.1× cheaper. Both are published.",
  },
  {
    id: "userinfo_grpc",
    title: "OIDC userinfo — gRPC",
    unit: "throughput · requests/s · plaintext · median of 3",
    bars: [
      { target: "AXIAM", value: 12665, display: "12,665", axiam: true },
      { target: "Zitadel", value: 180, display: "180" },
    ],
    takeaway:
      "The biggest single change in this run: 12,665 identity reads/s at a 6 ms p95 — 2.8× AXIAM's own REST path and 3.3× Keycloak's best number — where run 3 measured 3,294/s (every gRPC call used to pay the rate-limit write). Zitadel's own gRPC userinfo measured 180–185/s on the same harness, 82% below its REST cell; Keycloak exposes no gRPC equivalent.",
  },
  {
    id: "password_login",
    title: "Password login (real hashing)",
    unit: "throughput · requests/s · plaintext · median of 3",
    bars: [
      { target: "AXIAM", value: 69, display: "69", axiam: true },
      { target: "Keycloak", value: 44, display: "(44)" },
      { target: "Zitadel", value: 2.0, display: "(2)" },
    ],
    takeaway:
      "AXIAM is the only target valid at both profiles — 69 req/s at a 774 ms p95, on ≤ 140 MiB of server memory. Parenthesized numbers failed our own validity gate and are shown only for transparency: Keycloak completed 1 of 3 runs cleanly even at the raised 2 GiB cap (it wants ~3.5–4 GiB under sustained hashing; next run gives it exactly that, labeled), and Zitadel's default bcrypt cost puts it at ~22 s p50.",
    note: "2 of 3 targets excluded by the validity gate",
  },
  {
    id: "token_refresh",
    title: "Session / token refresh",
    unit: "throughput · requests/s · plaintext · median of 3",
    bars: [
      { target: "AXIAM", value: 839, display: "839", axiam: true },
      { target: "Keycloak", value: 377, display: "377" },
    ],
    takeaway:
      "Informational, not a like-for-like race: AXIAM has no ROPC/password grant by design, so its cell measures session-cookie refresh (CSRF double-submit, single-use rotation) while Keycloak's measures the OAuth2 refresh-token grant. Both are real, both rotate; new this run is that AXIAM's cell is a full median-of-3 (run 3 had a single confirm run). Zitadel needs an offline_access flow the harness doesn't implement.",
    note: "protocol-variant — two different protocols doing a related job",
  },
];

/**
 * Whole-stack efficiency, head-to-head (p0-plaintext, median-of-3, run 4).
 * `req/s per core` is higher-is-better; `cpu·ms/req` is lower-is-better.
 * AXIAM's figures still carry its audit broker and, on some cells, a
 * saturated database inside them — which is why Keycloak edges it on the
 * userinfo cpu·ms/req cell (server-only, AXIAM's server is 2.1× cheaper
 * there; both breakdowns are published in the raw report).
 */
export const BENCH_EFFICIENCY: BenchEfficiencyRow[] = [
  { scenario: "Client credentials", perCore: ["835", "171", "122"], cpuMs: ["1.20", "5.84", "8.20"] },
  { scenario: "Token introspection", perCore: ["1,288", "786", "250"], cpuMs: ["0.78", "1.27", "4.00"] },
  { scenario: "JWKS fetch", perCore: ["16,184", "2,278", "703"], cpuMs: ["0.06", "0.44", "1.42"] },
  { scenario: "OIDC userinfo", perCore: ["1,376", "1,891", "348"], cpuMs: ["0.73", "0.53", "2.88"] },
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
  unit: "throughput · requests/s · plaintext",
  bars: [
    { target: "REST · single", value: 753, display: "753", axiam: true },
    { target: "gRPC · single", value: 887, display: "887", axiam: true },
    { target: "REST · cache ON", value: 791, display: "791", axiam: true },
    { target: "gRPC · cache ON", value: 11598, display: "11,598", axiam: true },
  ],
  takeaway:
    "gRPC now leads REST by 18% at half the p50 — run 3 had gRPC 18% behind, and that whole deficit was the rate-limit write. Both single-check paths are database-saturated at the 2-core DB cap and scale to 1,434 / 1,678 req/s with 4 DB cores. The optional decision cache is charted at its best case: 13.1× on gRPC at a favorable keyspace, but only +5% on REST, where per-request session-cookie validation (a database read the cache deliberately doesn't cover) becomes the limiter. It stays off by default; the realistic-keyspace measurement is +32%. Batch: the shipped `coalesced` default measured 744 batch ops/s = 3,721 checks/s (4.98× singles) — carried from run 3, because this run's batch cells accidentally exercised the non-default `concurrent` strategy.",
};

/**
 * Resource usage during the tests (run 4 §5) — p0-plaintext, median-of-3,
 * every server container capped identically at 2 CPUs / 2,048 MiB.
 * Values are `[AXIAM, Keycloak, Zitadel]`.
 */

/** Per-server peak RSS in MiB, by scenario. */
export const BENCH_MEMORY_PEAK: BenchResourceRow[] = [
  { scenario: "JWKS fetch", values: [98, 973, 163] },
  { scenario: "Client credentials", values: [106, 979, 147] },
  { scenario: "Token introspection", values: [104, 795, 161] },
  { scenario: "Token refresh", values: [106, 804, null] },
  { scenario: "OIDC userinfo", values: [105, 806, 162] },
  { scenario: "Password login", values: [140, 796, 131], marker: "*" },
];

/** Worst-case server RSS observed anywhere in the run, in MiB. */
export const BENCH_MEMORY_WORST: BenchResourceRow = {
  scenario: "Worst case, whole run",
  values: [172, 1070, 216],
};

/** The identical per-server container memory cap, in MiB. */
export const BENCH_MEMORY_CAP = 2048;

/** Whole-stack memory range (server + database + broker), in MiB. */
export const BENCH_STACK_MEMORY: [string, string, string][] = [
  ["AXIAM", "415–590 MiB", "server + SurrealDB + RabbitMQ"],
  ["Keycloak", "814–1,129 MiB", "server + PostgreSQL"],
  ["Zitadel", "293–443 MiB", "server + PostgreSQL"],
];

/** CPU-milliseconds per request, whole stack unless noted (lower is better). */
export const BENCH_CPU_PER_REQ: BenchResourceRow[] = [
  { scenario: "Client credentials", values: [1.2, 5.84, 8.2] },
  { scenario: "Token introspection", values: [0.78, 1.27, 4.0] },
  { scenario: "JWKS fetch", values: [0.06, 0.44, 1.42] },
  { scenario: "OIDC userinfo", values: [0.73, 0.53, 2.88] },
  { scenario: "OIDC userinfo (server only)", values: [0.25, 0.53, 0.86] },
];

/** Requests per second per GiB of whole-stack RAM (higher is better). */
export const BENCH_RPS_PER_GIB: BenchResourceRow[] = [
  { scenario: "Client credentials", values: [5988, 338, 1218] },
  { scenario: "Token introspection", values: [8709, 1939, 2199] },
  { scenario: "OIDC userinfo", values: [8948, 3999, 2312] },
  { scenario: "JWKS fetch", values: [60723, 5741, 7330] },
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
