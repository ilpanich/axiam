import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

/**
 * Every permission string the UI gates on must be one the backend issues.
 *
 * A misspelt permission is the one UI gating bug that is invisible from inside
 * the UI. `usePermissions().can("scim_tokens:crate")` does not throw and does
 * not warn — it simply never matches, so the control is hidden from **everyone**
 * and the page still works perfectly for the people who were going to be
 * refused anyway. The only person who notices is an administrator who holds the
 * permission, cannot find the button, and has no way to tell that from "I was
 * not granted it".
 *
 * The permission matrix cannot catch it either: the only principal that could
 * act as the registry is the organization super-admin, and it holds `*`, which
 * matches a typo as happily as a real permission. Every other principal
 * correctly fails to hold the misspelt string, so "the control is absent" is
 * exactly what the matrix expects to see.
 *
 * Both lists are source files in this repository, so no server is needed:
 * `crates/axiam-api-rest/src/permissions.rs` is the registry, and the gates are
 * literals in `frontend/src`. Comparing them offline is the whole test.
 */

// `process.cwd()` rather than `import.meta.url`: Vite rewrites module URLs to
// its `/@fs/...` form, which `readFileSync` cannot open. Vitest runs from
// `frontend/`, so the repository root is one level up.
const REPO_ROOT = join(process.cwd(), "..");
const REGISTRY = join(REPO_ROOT, "crates/axiam-api-rest/src/permissions.rs");
const FRONTEND_SRC = join(REPO_ROOT, "frontend/src");

/**
 * Every `object:action` literal the backend registry mentions.
 *
 * The character class includes digits. Without them `oauth2_clients:list` — a
 * real, granted permission — is missing from this set while the frontend gate
 * that names it is found, and the test reports a defect that does not exist.
 * It did exactly that on its first run.
 */
function backendPermissions(): Set<string> {
  const source = readFileSync(REGISTRY, "utf8");
  return new Set(
    [...source.matchAll(/"([a-z0-9_]+:[a-z0-9_]+)"/g)].map((m) => m[1]),
  );
}

/** Where each permission string is gated in the frontend. */
interface Gate {
  permission: string;
  file: string;
}

/**
 * The four shapes a permission gate takes in this codebase:
 * `can("x")` in a component, `requiredPermission: "x"` in the sidebar table,
 * and `permission="x"` / `permission: "x"` on a `ProtectedRoute`.
 */
const GATE_PATTERNS = [
  /\bcan\(\s*"([^"]+)"\s*\)/g,
  /\brequiredPermission:\s*"([^"]+)"/g,
  /\bpermission=\{?"([^"]+)"/g,
  /\bpermission:\s*"([^"]+)"/g,
];

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      walk(full, out);
    } else if (/\.tsx?$/.test(entry) && !/\.test\.tsx?$/.test(entry)) {
      out.push(full);
    }
  }
  return out;
}

function frontendGates(): Gate[] {
  const gates: Gate[] = [];
  for (const file of walk(FRONTEND_SRC)) {
    const source = readFileSync(file, "utf8");
    for (const pattern of GATE_PATTERNS) {
      for (const match of source.matchAll(pattern)) {
        gates.push({ permission: match[1], file: file.slice(REPO_ROOT.length) });
      }
    }
  }
  return gates;
}

describe("permission strings", () => {
  it("finds both lists, so a passing run means something", () => {
    // Either half reading empty would make every assertion below vacuous — and
    // a path that silently resolves to nothing is exactly how a guard like this
    // rots after a directory move.
    expect(backendPermissions().size).toBeGreaterThan(50);
    expect(frontendGates().length).toBeGreaterThan(20);
  });

  it("every permission the UI gates on exists in the backend registry", () => {
    const registry = backendPermissions();
    const unknown = frontendGates()
      .filter((g) => !registry.has(g.permission))
      .map((g) => `${g.permission} (${g.file})`)
      .sort();

    expect(
      [...new Set(unknown)],
      "permission strings gated on in the frontend that crates/axiam-api-rest/src/" +
        "permissions.rs never issues. Each hides its control from every user, " +
        "permanently and without any error — including from administrators who " +
        "hold the permission it was meant to name.",
    ).toEqual([]);
  });
});
