import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";

import { INVALIDATION_GRAPH } from "./queryInvalidation";

/**
 * Every query-key root the app caches under must be reachable from the
 * invalidation graph, or be declared standalone here with a reason.
 *
 * # What this catches
 *
 * A cached view nothing invalidates. `["topbar-tenants", orgSlug]` was one:
 * the tenant switcher holds the same list the Tenants page does, but under a
 * root that appeared in no graph entry — so creating a tenant refreshed the
 * page and left the switcher answering from its own minute-old copy. The
 * operator saw the tenant they had just made and could not switch to it.
 *
 * That failure is invisible from any single file. The page invalidates
 * correctly, the switcher fetches correctly, and the missing edge between them
 * exists in neither. Only a whole-tree view can see it, which is what this is.
 *
 * # Why a declaration list rather than a rule
 *
 * "Reachable from the graph" cannot be inferred: a genuinely standalone
 * collection — webhooks, reactors, the audit log — correctly has no incoming
 * edges, because `relatedQueryKeys` falls back to invalidating the root itself
 * and its own page does exactly that. The difference between "standalone" and
 * "forgotten" is a judgement, so it is written down rather than guessed, and a
 * new root forces somebody to make it.
 */

const SRC_ROOT = resolve(__dirname, "..");
const REPO_ROOT = resolve(__dirname, "../../..");

/**
 * Roots that intentionally have no incoming graph edge.
 *
 * Each is a collection no other view holds a copy of: its own page invalidates
 * its own root after a mutation, and nothing else in the app shows those rows.
 * Add to this list only after checking that claim — the whole point of the test
 * is that "no other view shows this" is asserted rather than assumed.
 */
const STANDALONE: Record<string, string> = {
  "audit-logs": "append-only log; no other view holds its rows",
  "federation-configs":
    "shown only on the Federation page, and on the user detail page as a name lookup that a config change cannot invalidate meaningfully",
  "mds-status": "FIDO metadata freshness probe; read-only, server-side state",
  "notification-rules": "shown only on the Notification Rules page",
  "oauth2-clients": "shown only on the OAuth2 Clients page",
  "pgp-keys": "shown only on the PGP Keys page",
  reactors: "shown only on the Reactors page",
  "reactor-events": "append-only event feed, read-only",
  "scim-tokens": "shown only on the SCIM Tokens page",
  webhooks: "shown only on the Webhooks page",
  "group-service-accounts":
    "service-account membership of a group, invalidated by its own page alongside `service-accounts`",
  "role-service-accounts":
    "service-account assignments of a role, invalidated by its own page alongside `service-accounts`",
  "user-federation-links":
    "external identity links for one user, invalidated by the page that unlinks them",
};

/** Roots that are test scaffolding rather than real cached views. */
const NOT_A_REAL_ROOT = new Set(["t", "things"]);

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...sourceFiles(full));
      continue;
    }
    if (/\.test\.tsx?$/.test(entry)) continue;
    if (/\.tsx?$/.test(entry)) out.push(full);
  }
  return out;
}

/** The first, literal element of every `queryKey` and `usePaginatedList` key. */
function queryKeyRoots(file: string): string[] {
  const text = readFileSync(file, "utf8");
  const roots: string[] = [];
  for (const m of text.matchAll(/queryKey:\s*\[\s*"([a-zA-Z0-9_-]+)"/g)) {
    roots.push(m[1]);
  }
  for (const m of text.matchAll(
    /usePaginatedList<[^>]*>\(\s*\[\s*"([a-zA-Z0-9_-]+)"/g,
  )) {
    roots.push(m[1]);
  }
  return roots;
}

const files = sourceFiles(SRC_ROOT);

/** Every root any graph entry names, including the entry keys themselves. */
const reachable = new Set<string>([
  ...Object.keys(INVALIDATION_GRAPH),
  ...Object.values(INVALIDATION_GRAPH).flat(),
]);

describe("invalidation graph covers every cached view", () => {
  it("scans the whole source tree", () => {
    expect(files.length).toBeGreaterThan(50);
  });

  it("finds the roots it is supposed to check", () => {
    // Guards the scan itself: a regex that silently matched nothing would make
    // every assertion below vacuously pass.
    const all = new Set(files.flatMap(queryKeyRoots));
    expect(all.has("users")).toBe(true);
    expect(all.has("topbar-tenants")).toBe(true);
  });

  it("leaves no cached root that nothing can invalidate", () => {
    const orphans: string[] = [];
    for (const file of files) {
      for (const root of queryKeyRoots(file)) {
        if (NOT_A_REAL_ROOT.has(root)) continue;
        if (reachable.has(root)) continue;
        if (root in STANDALONE) continue;
        orphans.push(`${relative(REPO_ROOT, file)}: ["${root}", …]`);
      }
    }
    expect([...new Set(orphans)]).toEqual([]);
  });

  it("declares nothing standalone that the graph already reaches", () => {
    // Keeps the exemption list honest: an entry that stops being needed is a
    // stale claim about the app, and stale claims are how the list rots into a
    // blanket suppression.
    const redundant = Object.keys(STANDALONE).filter((k) => reachable.has(k));
    expect(redundant).toEqual([]);
  });

  it("declares nothing standalone that no longer exists", () => {
    const inUse = new Set(files.flatMap(queryKeyRoots));
    const dead = Object.keys(STANDALONE).filter((k) => !inUse.has(k));
    expect(dead).toEqual([]);
  });
});
