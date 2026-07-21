import type {
  Sdk,
  Post,
  Phase,
  BenchScenario,
  BenchEfficiencyRow,
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

export const PHASES: Phase[] = [
  { n: 0, title: "Project foundation", focus: "CI, dev environment, tooling" },
  {
    n: 1,
    title: "Core domain types & DB repositories",
    focus: "Domain model on SurrealDB",
  },
  { n: 2, title: "Authentication", focus: "Password, JWT, MFA" },
  { n: 3, title: "Authorization engine", focus: "RBAC with resource hierarchy" },
  { n: 4, title: "REST API", focus: "Actix-Web" },
  { n: 5, title: "gRPC API", focus: "Tonic + Protocol Buffers" },
  { n: 6, title: "AMQP integration", focus: "RabbitMQ via Lapin" },
  { n: 7, title: "Audit logging", focus: "Append-only, tamper-evident" },
  { n: 8, title: "PKI & certificates", focus: "Hierarchical X.509, mTLS" },
  { n: 9, title: "Webhook system", focus: "HMAC-SHA256 signed delivery" },
  {
    n: 10,
    title: "OAuth2 & OIDC",
    focus: "PKCE, client credentials, rotation",
  },
  { n: 11, title: "Federation", focus: "SAML + OIDC SSO" },
  {
    n: 12,
    title: "Hierarchical settings & password policy",
    focus: "Cascading configuration",
  },
  {
    n: 13,
    title: "Email service & account flows",
    focus: "Verification, recovery",
  },
  { n: 14, title: "Advanced MFA", focus: "TOTP step-up and beyond" },
  { n: 15, title: "Admin frontend", focus: "React admin UI" },
  { n: 16, title: "Docker & Kubernetes", focus: "Deployment manifests" },
  { n: 17, title: "SDKs", focus: "Rust, TS, Python, Java, C#, PHP, Go" },
  {
    n: 18,
    title: "Security audit, compliance, docs",
    focus: "Hardening & documentation",
  },
];

/**
 * Preliminary benchmark scenarios, transcribed from
 * `benchmarks/PUBLIC_BENCH_ANALYSIS.md` (draft 2, run of 2026-07-21, AXIAM
 * 1.0.0-alpha15 vs Keycloak 26.7.0 vs Zitadel v4.15.2). All figures are the
 * p0-plaintext profile from the capped matrix (§3/§7), single run — a credible
 * signal, not a final verdict. Only valid, comparable cells are charted.
 */
export const BENCH_SCENARIOS: BenchScenario[] = [
  {
    id: "client_credentials",
    title: "Machine-to-machine token issuance",
    unit: "throughput · requests/s · plaintext",
    bars: [
      { target: "AXIAM", value: 1788, display: "1,788", axiam: true },
      { target: "Zitadel", value: 419, display: "419" },
      { target: "Keycloak", value: 346, display: "346" },
    ],
    takeaway:
      "AXIAM issues 4.3× more tokens/s than Zitadel and 5.2× more than Keycloak, at a p99 of 36 ms.",
  },
  {
    id: "introspection",
    title: "Token introspection (RFC 7662)",
    unit: "throughput · requests/s · plaintext",
    bars: [
      { target: "AXIAM", value: 2229, display: "2,229", axiam: true },
      { target: "Keycloak", value: 1765, display: "1,765" },
      { target: "Zitadel", value: 923, display: "923" },
    ],
    takeaway:
      "The closest head-to-head: AXIAM leads Keycloak by 1.26× (2.4× vs Zitadel) with a 3× better p95 and zero TLS penalty.",
  },
  {
    id: "jwks",
    title: "JWKS fetch (RFC 7517)",
    unit: "throughput · requests/s · plaintext",
    bars: [
      { target: "AXIAM", value: 27059, display: "27,059", axiam: true },
      { target: "Keycloak", value: 3855, display: "3,855" },
      { target: "Zitadel", value: 2034, display: "2,034" },
    ],
    takeaway:
      "A 7–13× gap — and AXIAM's server sat under its CPU cap while the load generator saturated, so its true ceiling is higher still.",
  },
  {
    id: "userinfo",
    title: "OIDC userinfo",
    unit: "throughput · requests/s · plaintext",
    bars: [
      { target: "AXIAM", value: 5457, display: "5,457", axiam: true },
      { target: "Keycloak", value: 3561, display: "3,561" },
      { target: "Zitadel", value: 967, display: "967" },
    ],
    takeaway:
      "AXIAM leads throughput (1.5× Keycloak, 5.6× Zitadel) even while DB-limited; on whole-stack CPU per request Keycloak is narrowly more efficient here.",
  },
  {
    id: "password_login",
    title: "Password login (real hashing)",
    unit: "throughput · requests/s · plaintext",
    bars: [
      { target: "AXIAM", value: 67.5, display: "67.5", axiam: true },
      { target: "Keycloak", value: 22.3, display: "22.3" },
      { target: "Zitadel", value: 2.0, display: "2.0" },
    ],
    takeaway:
      "At 50 concurrent users on 2 CPUs, AXIAM is the only target under the 2 s p95 gate. Hash configuration dominates this cell — Zitadel's default bcrypt cost is simply very expensive.",
  },
];

/**
 * Whole-stack efficiency, head-to-head (p0-plaintext). `req/s per core` is
 * higher-is-better; `cpu·ms/req` is lower-is-better. AXIAM's figures still
 * carry its audit broker and, on some cells, a saturated database inside them —
 * which is why Keycloak edges it on the userinfo cpu·ms/req cell.
 */
export const BENCH_EFFICIENCY: BenchEfficiencyRow[] = [
  { scenario: "Client credentials", perCore: ["617", "167", "117"], cpuMs: ["1.62", "6.00", "8.53"] },
  { scenario: "Token introspection", perCore: ["936", "753", "250"], cpuMs: ["1.07", "1.33", "4.01"] },
  { scenario: "JWKS fetch", perCore: ["16,388", "1,922", "681"], cpuMs: ["0.061", "0.52", "1.47"] },
  { scenario: "OIDC userinfo", perCore: ["1,453", "1,778", "340"], cpuMs: ["0.69", "0.56", "2.94"] },
];

/**
 * AXIAM-only authorization decisions (no head-to-head — Keycloak and Zitadel
 * expose no equivalent endpoint). Each check is a full RBAC evaluation against
 * live data. Values are p0-plaintext throughput (requests/s).
 */
export const BENCH_AUTHZ: BenchScenario = {
  id: "authz",
  title: "Authorization decisions (AXIAM-only)",
  unit: "throughput · requests/s · plaintext",
  bars: [
    { target: "REST · single", value: 745, display: "745", axiam: true },
    { target: "gRPC · single", value: 722, display: "722", axiam: true },
    { target: "REST · batch ×5", value: 46, display: "46" },
    { target: "gRPC · batch ×5", value: 23, display: "23" },
  ],
  takeaway:
    "Single checks improved 1.5–2.5× since draft 1 and now run at DB saturation (gRPC p99 tail collapsed 850 → 90 ms). The batch endpoints remain the known weak spot — currently slower than repeated single checks, and under investigation.",
};

export const GITHUB_URL = "https://github.com/ilpanich/axiam";
