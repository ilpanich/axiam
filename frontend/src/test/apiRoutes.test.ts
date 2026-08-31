import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";

/**
 * Every `/api/v1/...` path this app requests must exist in the OpenAPI
 * document the server generates.
 *
 * # Why this test exists
 *
 * `OAuth2ClientsPage` asked for `/api/v1/oauth2/clients` for an entire release.
 * The route is `/api/v1/oauth2-clients`; the `/oauth2/...` prefix belongs to
 * the protocol endpoints and is not under `/api/v1` at all. Every load of the
 * page answered 404, and because the page renders an empty table for an empty
 * result it looked like a tenant with no OAuth2 clients rather than like a
 * broken request.
 *
 * Nothing caught it. The page's own unit tests mock `api.get` to resolve for
 * *any* URL — which is the right thing for a component test to do, and exactly
 * why a component test can never notice that the URL is wrong. The type system
 * cannot help either: a request path is a string.
 *
 * So this checks the one thing neither of those can: that the set of paths the
 * client asks for is a subset of the set the server serves. `sdks/openapi.json`
 * is generated from the `#[utoipa::path]` annotations on the handlers and is
 * already the contract the SDKs are built against, which makes it the right
 * source of truth here too — a route that moves without the document moving
 * with it is a separate failure, caught by the OpenAPI drift check in CI.
 *
 * # What it does not check
 *
 * Methods, parameters, and response shapes: those are the SDK contract tests'
 * job. This is about paths, because paths are what silently 404.
 */

const REPO_ROOT = resolve(__dirname, "../../..");
const SRC_ROOT = resolve(__dirname, "..");

/**
 * Paths that are legitimately absent from the OpenAPI document.
 *
 * Keep this list short and each entry explained — an unexplained exemption is
 * indistinguishable from the bug this test exists to catch.
 */
const EXEMPT = new Set<string>([
  // A base-URL constant, concatenated with "/user/{id}" or "/{id}" at the call
  // site. Both concrete paths are checked; the bare prefix is never requested.
  "/api/v1/federation-links",
  // Real, routed, and absent from the document this test reads: the committed
  // `sdks/openapi.json` is generated with `--no-default-features`, which is the
  // build the `OpenAPI Drift Gate (SAML off)` job compares against, and the SAML
  // endpoints only exist when the `saml` feature is on. Exempting the one path
  // the admin UI calls is narrower than committing a second spec — and the
  // route is covered on the server side by `federation_test.rs`.
  "/api/v1/auth/federation/saml/login",
]);

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...sourceFiles(full));
      continue;
    }
    // Test files are excluded: they name paths as *expectations*, and a test
    // asserting the 404 behaviour of an unknown route is not a bug.
    if (/\.test\.tsx?$/.test(entry)) continue;
    if (/\.tsx?$/.test(entry)) out.push(full);
  }
  return out;
}

/**
 * Every `/api/v1/...` literal in a source file, template holes normalised.
 *
 * `${id}` becomes `{p}` so a template literal compares against an OpenAPI path
 * template on equal terms. Query strings are dropped — they are not part of the
 * path — and so is a trailing slash.
 */
function requestedPaths(file: string): string[] {
  const text = readFileSync(file, "utf8");
  const found = new Set<string>();
  for (const m of text.matchAll(/["'`](\/api\/v1\/[^"'`\s]*)["'`]/g)) {
    const path = m[1]
      .replace(/\$\{[^}]*\}/g, "{p}")
      .split("?")[0]
      .replace(/\/$/, "");
    if (path.includes("{p}") || /^\/api\/v1\/[\w\-/{}.]*$/.test(path)) {
      found.add(path);
    }
  }
  return [...found];
}

/** Turn an OpenAPI path template into a matcher, with `{param}` as a wildcard. */
function templateMatcher(template: string): RegExp {
  const body = template
    .split("/")
    .map((seg) =>
      seg.startsWith("{") && seg.endsWith("}")
        ? "[^/]+"
        : seg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
    )
    .join("/");
  return new RegExp(`^${body}$`);
}

const spec = JSON.parse(
  readFileSync(join(REPO_ROOT, "sdks/openapi.json"), "utf8"),
) as { paths: Record<string, unknown> };

const matchers = Object.keys(spec.paths).map(templateMatcher);

describe("frontend API paths exist in the server's OpenAPI document", () => {
  it("has a non-trivial OpenAPI document to check against", () => {
    // Guards the test itself: an empty or misread spec would make every
    // assertion below vacuously pass.
    expect(Object.keys(spec.paths).length).toBeGreaterThan(50);
    expect(Object.keys(spec.paths)).toContain("/api/v1/oauth2-clients");
  });

  const files = sourceFiles(SRC_ROOT);

  it("scans the whole source tree", () => {
    expect(files.length).toBeGreaterThan(50);
  });

  const offenders: string[] = [];
  for (const file of files) {
    for (const path of requestedPaths(file)) {
      if (EXEMPT.has(path)) continue;
      if (matchers.some((re) => re.test(path))) continue;
      offenders.push(`${relative(REPO_ROOT, file)}: ${path}`);
    }
  }

  it("requests no path the server does not serve", () => {
    expect(offenders).toEqual([]);
  });
});
