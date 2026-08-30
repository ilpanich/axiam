/**
 * Generate `src/apiIndex.ts` from the committed OpenAPI document.
 *
 * The server exposes far more REST surface than a hand-written page can carry:
 * the documentation site used to show a dozen endpoints out of 177, chosen by
 * whoever last edited the page. `sdks/openapi.json` is drift-gated against a
 * fresh export from the running server, so generating the index from it makes
 * the page as current as the spec — and makes "we forgot to document that one"
 * impossible rather than merely unlikely.
 *
 * Run it after the OpenAPI document changes:
 *
 *   npm run gen:api-index
 *
 * The generated file is committed; CI does not regenerate it.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const SPEC = resolve(here, "../../sdks/openapi.json");
const OUT = resolve(here, "../src/apiIndex.ts");

const METHODS = ["get", "post", "put", "patch", "delete"];

/**
 * Which domain each OpenAPI tag belongs to, and the order the domains are
 * shown in.
 *
 * Every tag in the document must appear here — an unplaced tag fails the
 * generator rather than being dropped into an "other" bucket, for the same
 * reason the crate-layering table refuses an unplaced crate: a silent bucket is
 * where a new API surface goes to be forgotten.
 */
const DOMAINS = [
  {
    label: "Authentication & sessions",
    blurb:
      "Signing in, keeping a session alive, the account lifecycle, and the WebAuthn ceremonies.",
    tags: ["auth", "webauthn", "webauthn-policy", "mds", "device"],
  },
  {
    label: "OAuth2 & OpenID Connect",
    blurb: "The authorization server, its clients, and the discovery documents.",
    tags: ["oauth2", "oauth2-clients", "oidc"],
  },
  {
    label: "Federation",
    blurb: "SAML service provider and OIDC relying-party configuration, and the SSO entry points.",
    tags: ["federation", "federation-sso"],
  },
  {
    label: "Identity",
    blurb: "Users, the groups they belong to, and the service accounts that act without one.",
    tags: ["users", "groups", "service-accounts"],
  },
  {
    label: "Data-subject rights",
    blurb:
      "GDPR export (Art. 15) and erasure (Art. 17), acting on the caller's own account.",
    tags: ["gdpr"],
  },
  {
    label: "Authorization",
    blurb:
      "The graph a decision is read from — roles, permissions, resources and scopes — the check endpoints, and UMA's protection API.",
    tags: ["roles", "permissions", "resources", "scopes", "authz", "uma"],
  },
  {
    label: "Organizations & tenants",
    blurb:
      "The tenancy boundary itself, the first-run bootstrap that creates it, and the settings and mail configuration that hang off it.",
    tags: ["admin", "organizations", "tenants", "settings", "email-config"],
  },
  {
    label: "PKI & certificates",
    blurb: "Certificate authorities, issued certificates, and the OpenPGP keys audit exports are signed with.",
    tags: ["ca-certificates", "certificates", "pgp-keys"],
  },
  {
    label: "Eventing",
    blurb: "Webhooks, reactors and notification rules — everything that tells something else what happened.",
    tags: ["webhooks", "reactors", "notification_rules"],
  },
  {
    label: "Provisioning",
    blurb: "SCIM provisioning tokens. The SCIM 2.0 endpoints themselves are served under `/scim/v2`.",
    tags: ["scim-tokens"],
  },
  {
    label: "Audit & operations",
    blurb: "The append-only trail, and the endpoints a monitor reads.",
    tags: ["audit", "health"],
  },
];

const DOMAIN_OF = new Map();
for (const domain of DOMAINS) {
  for (const tag of domain.tags) {
    if (DOMAIN_OF.has(tag)) {
      throw new Error(`tag "${tag}" is listed under two domains`);
    }
    DOMAIN_OF.set(tag, domain.label);
  }
}

const spec = JSON.parse(readFileSync(SPEC, "utf8"));

/**
 * The one-line summary to show beside an operation.
 *
 * Most operations' `summary` is the utoipa doc comment's first line, which for
 * a CRUD handler is just the method and path restated — carrying that into a
 * table that already has both columns would be noise. Where a handler has a
 * real description, its first sentence is used instead; where it has neither,
 * the row is the method and the path, which for `GET /api/v1/roles` is all
 * there is to say.
 */
function summarize(method, path, operation) {
  const summary = (operation.summary ?? "").trim();
  const echo = summary.replace(/`/g, "").trim().toLowerCase();
  const isEcho =
    echo === `${method} ${path}`.toLowerCase() ||
    echo.startsWith(`${method} ${path} `.toLowerCase());

  if (summary && !isEcho) {
    // A summary that says something beyond the route: keep it, minus the
    // leading "`METHOD /path` — " the doc comments open with. When nothing is
    // left, the whole summary *was* the route — one with a query string, say,
    // which the equality test above cannot recognise — so fall through to the
    // description rather than returning an empty cell.
    const stripped = summary.replace(/^`[^`]+`\s*(?:[—–-]{1,2}\s*)?/, "").trim();
    if (stripped) return stripped;
  }

  const description = (operation.description ?? "").trim();
  if (!description) return "";

  // First sentence, on one line. Doc comments wrap, so join first — and skip a
  // period that ends an abbreviation rather than a sentence, or "Enqueues an
  // async GDPR Art. 15 data-export job." becomes "Enqueues an async GDPR Art."
  const flat = description.replace(/\s+/g, " ").replace(/^\*\*[^*]+\*\*\s*/, "");
  const ABBREVIATIONS = /(?:^|\s)(?:Art|art|Sec|No|Nos|e\.g|i\.e|cf|vs|Fig|approx|Dr|Mr|Ms)$/;
  for (let i = 0; i < flat.length; i++) {
    if (flat[i] !== ".") continue;
    const next = flat[i + 1];
    if (next !== undefined && next !== " ") continue;
    if (ABBREVIATIONS.test(flat.slice(0, i))) continue;
    return flat.slice(0, i + 1).trim();
  }
  return flat.trim();
}

const rank = new Map(METHODS.map((m, i) => [m, i]));

const operations = [];
for (const [path, item] of Object.entries(spec.paths)) {
  for (const [method, operation] of Object.entries(item)) {
    if (!METHODS.includes(method)) continue;
    const tags = operation.tags ?? [];
    if (tags.length === 0) {
      throw new Error(`${method.toUpperCase()} ${path} carries no tag`);
    }
    const tag = tags[0];
    const domain = DOMAIN_OF.get(tag);
    if (!domain) {
      throw new Error(
        `tag "${tag}" (${method.toUpperCase()} ${path}) is not placed in a domain — add it to DOMAINS`,
      );
    }
    operations.push({
      domain,
      tag,
      method: method.toUpperCase(),
      path,
      summary: summarize(method, path, operation),
      // Every operation declares its security requirement; the ones that
      // declare none are reachable without a token, which is the single most
      // useful thing an index can say about a route.
      isPublic: !operation.security || operation.security.length === 0,
    });
  }
}

/** Stable heading anchor for a domain — part of the URL, so derived once here. */
const anchor = (label) =>
  label
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");

const groups = DOMAINS.map((domain) => ({
  id: `api-${anchor(domain.label)}`,
  label: domain.label,
  blurb: domain.blurb,
  operations: operations
    .filter((op) => op.domain === domain.label)
    .sort(
      (a, b) =>
        a.path.localeCompare(b.path) || (rank.get(a.method.toLowerCase()) ?? 9) - (rank.get(b.method.toLowerCase()) ?? 9),
    )
    .map(({ method, path, summary, isPublic }) => ({
      method,
      path,
      summary,
      ...(isPublic ? { public: true } : {}),
    })),
}));

const placed = groups.reduce((n, g) => n + g.operations.length, 0);
if (placed !== operations.length) {
  throw new Error(`${operations.length - placed} operations were not emitted`);
}

writeFileSync(
  OUT,
  `// AUTO-GENERATED — do not edit by hand.
//
// Produced by \`npm run gen:api-index\` from \`sdks/openapi.json\`, which is
// itself drift-gated in CI against a fresh export from the server. Re-run the
// generator whenever the OpenAPI document changes.

/** One REST operation, in the shape the docs \`api\` block renders. */
export interface ApiOperation {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  summary: string;
  /** Reachable without an access token. */
  public?: boolean;
}

/** One domain's operations, in path order. */
export interface ApiGroup {
  /** Heading anchor, stable across regenerations. */
  id: string;
  label: string;
  blurb: string;
  operations: ApiOperation[];
}

/** The API version the document was exported from. */
export const API_VERSION = ${JSON.stringify(spec.info?.version ?? "")};
export const API_OPERATION_COUNT = ${operations.length};
export const API_PATH_COUNT = ${Object.keys(spec.paths).length};

export const API_INDEX: ApiGroup[] = ${JSON.stringify(groups, null, 1)};
`,
);

console.log(
  `apiIndex.ts: ${operations.length} operations across ${Object.keys(spec.paths).length} paths, ${groups.length} domains`,
);
