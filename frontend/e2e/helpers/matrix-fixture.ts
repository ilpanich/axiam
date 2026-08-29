import { Api, items } from "./api";

/**
 * The RBAC / PKI fixture the permission matrix is measured against.
 *
 * Shape (see `claude_dev/E2E-TESTS.md` §1). Everything is prefixed `mx-` so a run can be
 * told apart from the `default` tenant's own seed data, and so a re-run can
 * find what a previous run left behind.
 *
 * ```
 *   organization test-org
 *   ├── (organization scope)  admin ................ org super-admin
 *   ├── tenant `default` (A)
 *   │    ├── resources  mx-root → mx-a → mx-b → mx-c → mx-d      (depth 5)
 *   │    │                        └→ mx-b-sibling               (sibling of mx-b)
 *   │    ├── scopes on mx-b      invoices, reports
 *   │    ├── roles      mx-role-viewer      global, read-only
 *   │    │              mx-role-editor      resource-scoped, resources:update
 *   │    │              mx-role-deny        resource-scoped, DENY resources:update
 *   │    │              mx-role-scope-deny  resource-scoped, DENY resources:get on `invoices`
 *   │    ├── groups     mx-group-alpha  carries mx-role-viewer (global)
 *   │    │              mx-group-beta   carries mx-role-editor on mx-b
 *   │    ├── users      mx-viewer   mx-role-viewer, globally
 *   │    │              mx-editor   mx-role-editor on mx-b        (reaches mx-c, mx-d; not mx-b-sibling)
 *   │    │              mx-denied   mx-role-editor on mx-d + mx-role-deny on mx-a
 *   │    │              mx-grouped  no direct role; member of mx-group-alpha
 *   │    │              mx-nobody   no roles at all
 *   │    └── service accounts
 *   │              mx-sa-direct  mx-role-viewer assigned directly
 *   │              mx-sa-group   no direct role; member of mx-group-alpha
 *   │              mx-sa-cert    bound to an end-entity certificate
 *   ├── tenant `mx-tenant-b` (B)
 *   │    └── users      mx-b-admin  super-admin within B only
 *   └── PKI
 *        ├── mx-org-ca         root CA, ENABLED as an mTLS trust anchor
 *        ├── mx-untrusted-ca   root CA, NOT a trust anchor
 *        ├── mx-signing-ca-a   intermediate under mx-org-ca, tenant A's signer
 *        └── certificates      mx-cert-sa        bound to mx-sa-cert
 *                              mx-cert-unbound   bound to nothing
 *                              mx-cert-revoked   revoked after issue
 *                              mx-cert-untrusted issued under mx-untrusted-ca
 * ```
 *
 * **Resilience is a requirement, not a nicety.** The backend image is Rust and
 * rebuilds slowly, so a wave that aborts on the first broken fixture step buys
 * one finding per image build. Every step here therefore records its failure in
 * {@link MatrixFixture.problems} and lets the rest of the build continue; the
 * specs then assert against whatever did get built and report the rest as
 * "unverified — blocked", never as a pass.
 *
 * **Idempotence is also a requirement**: a second wave must be able to run
 * against a stack that already carries some of this, without a wiped database.
 * Every `ensure*` helper treats a 409 as "already there, go find it".
 */

export const PASSWORD =
  process.env["E2E_ADMIN_PASSWORD"] ?? "Test@Admin123!";
export const ORG_SLUG = process.env["E2E_ORG_SLUG"] ?? "test-org";
export const TENANT_A_SLUG = process.env["E2E_TENANT_SLUG"] ?? "default";
export const TENANT_B_SLUG = "mx-tenant-b";

/** Where the built fixture is written for the specs to read. Gitignored. */
export const FIXTURE_STATE = "e2e/.auth/matrix-fixture.json";

/**
 * Where one principal's captured browser session lives. One file per
 * principal, so a principal whose sign-in is broken costs only its own block —
 * the isolation `claude_dev/E2E-TESTS.md` §5 asks for, at the session layer.
 */
export function storageStateFor(principalKey: string): string {
  return `e2e/.auth/mx-${principalKey}.json`;
}

export interface MatrixUser {
  id: string;
  username: string;
  email: string;
}

export interface MatrixFixture {
  orgId: string;
  tenantA: string;
  tenantB: string;
  /** Resource ids, keyed by the short name in the tree above. */
  resources: Record<string, string>;
  /** Scope ids on `mx-b`, keyed by name. */
  scopes: Record<string, string>;
  roles: Record<string, string>;
  groups: Record<string, string>;
  users: Record<string, MatrixUser>;
  serviceAccounts: Record<string, { id: string; clientId?: string; clientSecret?: string }>;
  caCertificates: Record<string, string>;
  certificates: Record<string, string>;
  /**
   * Fixture steps that did not complete. Each entry is a spec-readable reason;
   * a spec whose subject appears here reports "unverified — blocked" rather
   * than failing as if the behaviour were wrong.
   */
  problems: string[];
}

function emptyFixture(): MatrixFixture {
  return {
    orgId: "",
    tenantA: "",
    tenantB: "",
    resources: {},
    scopes: {},
    roles: {},
    groups: {},
    users: {},
    serviceAccounts: {},
    caCertificates: {},
    certificates: {},
    problems: [],
  };
}

type Rec = Record<string, unknown>;

/** Runs `fn`, recording any throw or unexpected status as a fixture problem. */
async function step<T>(
  fx: MatrixFixture,
  label: string,
  fn: () => Promise<T>,
): Promise<T | undefined> {
  try {
    return await fn();
  } catch (e) {
    fx.problems.push(`${label}: ${e instanceof Error ? e.message : String(e)}`);
    return undefined;
  }
}

/** 2xx, or a 409 that means "already exists". Anything else throws. */
function created(res: { status: number; body: unknown }, what: string): Rec | null {
  if (res.status >= 200 && res.status < 300) return (res.body ?? {}) as Rec;
  if (res.status === 409) return null;
  throw new Error(
    `${what} -> HTTP ${res.status}: ${JSON.stringify(res.body).slice(0, 300)}`,
  );
}

async function findBy(
  api: Api,
  path: string,
  field: string,
  value: string,
): Promise<Rec | undefined> {
  const res = await api.get(path);
  return items<Rec>(res.body).find((r) => r[field] === value);
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/**
 * Builds (or completes) the fixture as the ORGANIZATION super-admin.
 *
 * The org super-admin is the right builder for all of it: it is the only
 * principal that can create a tenant, and the only one that can then reach
 * *into* a freshly created tenant to provision its first administrator. Tenant
 * A's data is written with `X-Axiam-Tenant` pointed at A, tenant B's at B.
 */
export async function buildMatrixFixture(api: Api): Promise<MatrixFixture> {
  const fx = emptyFixture();

  // --- organization -------------------------------------------------------
  const orgs = await api.get("/api/v1/organizations");
  const org = items<Rec>(orgs.body).find((o) => o["slug"] === ORG_SLUG);
  if (!org) {
    fx.problems.push(
      `organization ${ORG_SLUG} not found (GET /organizations -> ${orgs.status}); ` +
        `run scripts/e2e-bootstrap.sh first`,
    );
    return fx;
  }
  fx.orgId = String(org["id"]);

  // --- tenants ------------------------------------------------------------
  const tenantsPath = `/api/v1/organizations/${fx.orgId}/tenants`;
  const tenantA = await findBy(api, tenantsPath, "slug", TENANT_A_SLUG);
  if (!tenantA) {
    fx.problems.push(`tenant ${TENANT_A_SLUG} not found; run scripts/e2e-bootstrap.sh first`);
    return fx;
  }
  fx.tenantA = String(tenantA["id"]);

  await step(fx, `create tenant ${TENANT_B_SLUG}`, async () => {
    // Look first, create second. Re-creating an existing (org, slug) pair does
    // NOT answer 409 — it answers 500, because the unique index
    // `idx_tenant_org_slug` raises a database error that is mapped to a generic
    // internal error (recorded as a finding). Creating blind and treating 409
    // as "already there" is therefore not enough here, and a fixture that has
    // to survive a second wave against a live database cannot depend on it.
    const existing = await findBy(api, tenantsPath, "slug", TENANT_B_SLUG);
    if (existing) {
      fx.tenantB = String(existing["id"]);
      return;
    }
    const res = await api.post(tenantsPath, {
      name: "Matrix Tenant B",
      slug: TENANT_B_SLUG,
    });
    created(res, `POST ${tenantsPath}`);
    const t = await findBy(api, tenantsPath, "slug", TENANT_B_SLUG);
    if (!t) throw new Error("tenant B is neither created nor findable");
    fx.tenantB = String(t["id"]);
  });

  // --- an organization principal restricted to tenant A -------------------
  //
  // Built here, while the client is still in the ORGANIZATION scope, because
  // that is where the account lives and where its role assignment is written.
  // It exists to prove the half of organization scope that has no other
  // witness: an organization-level account whose roles name particular tenants
  // reaches those and nothing else — not tenant B, and not the organization
  // itself.
  await step(fx, "tenant-scoped organization admin", async () => {
    if (!fx.tenantA) throw new Error("tenant A is unknown");
    const u = await ensureUser(api, fx, "org-a-admin", "mx-org-a-admin");
    if (!u) return;
    const role = await findBy(api, "/api/v1/roles", "name", "super-admin");
    if (!role) throw new Error("the organization scope has no seeded super-admin role");
    const res = await api.post(`/api/v1/roles/${role["id"]}/users`, {
      user_id: u.id,
      // The whole point of the principal. Without it this is just a second
      // organization administrator and every assertion below would pass for
      // the wrong reason.
      tenant_scope: [fx.tenantA],
    });
    if (res.status >= 300 && res.status !== 409) {
      throw new Error(
        `assign tenant-scoped super-admin -> HTTP ${res.status}: ` +
          JSON.stringify(res.body).slice(0, 200),
      );
    }
  });

  // --- everything below is tenant A --------------------------------------
  api.actingTenant(fx.tenantA);

  await buildResourceTree(api, fx);
  await buildRoles(api, fx);
  await buildGroups(api, fx);
  await buildUsers(api, fx);
  await buildServiceAccounts(api, fx);
  await buildGrants(api, fx);

  // --- tenant B -----------------------------------------------------------
  if (fx.tenantB) {
    api.actingTenant(fx.tenantB);
    await step(fx, "tenant B admin", async () => {
      const u = await ensureUser(api, fx, "b-admin", "mx-b-admin");
      if (!u) return;
      const role = await findBy(api, "/api/v1/roles", "name", "super-admin");
      if (!role) throw new Error("tenant B has no seeded super-admin role");
      const res = await api.post(`/api/v1/roles/${role["id"]}/users`, {
        user_id: u.id,
      });
      created(res, "assign super-admin in tenant B");
    });
    await step(fx, "tenant B resource", async () => {
      const res = await api.post("/api/v1/resources", {
        name: "mx-b-only",
        resource_type: "folder",
      });
      const body = created(res, "POST /resources (tenant B)");
      const found =
        body?.["id"] ??
        (await findBy(api, "/api/v1/resources", "name", "mx-b-only"))?.["id"];
      if (found) fx.resources["b-only"] = String(found);
    });
    // A service account in tenant B, so `mx-b-admin` has a ROW on
    // `/service-accounts`. Without one the per-row bind-certificate gate is
    // unmeasurable for the only principal that could exercise it in tenant B —
    // and "no rows" renders identically to "the action is correctly hidden",
    // which is the confusion `in-page-controls.spec.ts` exists to avoid.
    // Bound to nothing: the row is the point, not the certificate.
    await step(fx, "tenant B service account", async () => {
      const name = "mx-b-sa";
      let sa = await findBy(api, "/api/v1/service-accounts", "name", name);
      if (!sa) {
        const res = await api.post("/api/v1/service-accounts", {
          name,
          description: "matrix fixture service account in tenant B",
        });
        created(res, `POST /service-accounts ${name} (tenant B)`);
        sa = await findBy(api, "/api/v1/service-accounts", "name", name);
      }
      if (!sa) throw new Error("created but not findable");
      fx.serviceAccounts["mx-b-sa"] = { id: String(sa["id"]) };
    });
  }

  // --- PKI (organization level, so no acting tenant for the CA calls) -----
  api.actingTenant(null);
  await buildPki(api, fx);

  api.actingTenant(fx.tenantA);
  return fx;
}

// ---------------------------------------------------------------------------

async function buildResourceTree(api: Api, fx: MatrixFixture): Promise<void> {
  // Depth is the point: a role granted on `mx-b` must be shown to reach `mx-c`
  // and `mx-d` beneath it and NOT `mx-b-sibling` beside it. A two-level tree
  // cannot tell inheritance from coincidence.
  const chain: Array<[key: string, name: string, parent: string | null]> = [
    ["root", "mx-root", null],
    ["a", "mx-a", "root"],
    ["b", "mx-b", "a"],
    ["c", "mx-c", "b"],
    ["d", "mx-d", "c"],
    ["b-sibling", "mx-b-sibling", "a"],
  ];
  for (const [key, name, parentKey] of chain) {
    await step(fx, `resource ${name}`, async () => {
      const existing = await findBy(api, "/api/v1/resources", "name", name);
      if (existing) {
        fx.resources[key] = String(existing["id"]);
        return;
      }
      const parentId = parentKey ? fx.resources[parentKey] : null;
      if (parentKey && !parentId) {
        throw new Error(`parent ${parentKey} was not built`);
      }
      const res = await api.post("/api/v1/resources", {
        name,
        resource_type: "folder",
        ...(parentId ? { parent_id: parentId } : {}),
      });
      const body = created(res, `POST /resources ${name}`);
      const id =
        body?.["id"] ??
        (await findBy(api, "/api/v1/resources", "name", name))?.["id"];
      if (!id) throw new Error("created but not findable");
      fx.resources[key] = String(id);
    });
  }

  // Scopes hang off `mx-b`, the node the scoped grants are made on, so a
  // scoped deny can be shown to narrow only the scope it names.
  for (const name of ["invoices", "reports"]) {
    await step(fx, `scope ${name}`, async () => {
      const b = fx.resources["b"];
      if (!b) throw new Error("mx-b was not built");
      const path = `/api/v1/resources/${b}/scopes`;
      const existing = await findBy(api, path, "name", name);
      if (existing) {
        fx.scopes[name] = String(existing["id"]);
        return;
      }
      const res = await api.post(path, {
        name,
        description: `matrix fixture scope ${name}`,
      });
      const body = created(res, `POST ${path}`);
      const id = body?.["id"] ?? (await findBy(api, path, "name", name))?.["id"];
      if (!id) throw new Error("created but not findable");
      fx.scopes[name] = String(id);
    });
  }
}

/** The permission actions the fixture roles are built out of. */
const ROLE_PERMISSIONS: Record<
  string,
  { global: boolean; grants: Array<{ action: string; effect?: "allow" | "deny"; scopes?: string[] }> }
> = {
  // A deliberately read-only reach: enough to see several pages, enough to
  // prove the pages it must NOT see stay shut.
  "mx-role-viewer": {
    global: true,
    grants: [
      { action: "users:list" },
      { action: "users:get" },
      { action: "roles:list" },
      { action: "groups:list" },
      { action: "resources:list" },
      { action: "resources:get" },
    ],
  },
  // Scoped write. Assigned on a *node*, never globally.
  "mx-role-editor": {
    global: false,
    grants: [
      { action: "resources:get" },
      { action: "resources:update" },
      { action: "resources:list_children" },
    ],
  },
  // The deny-override case: an explicit deny that must beat an allow granted
  // deeper in the tree.
  "mx-role-deny": {
    global: false,
    grants: [{ action: "resources:update", effect: "deny" }],
  },
  // A *scoped* deny: it must narrow only the scope it names, leaving the same
  // action allowed on every other scope and unscoped.
  "mx-role-scope-deny": {
    global: false,
    grants: [{ action: "resources:get", effect: "deny", scopes: ["invoices"] }],
  },
};

async function buildRoles(api: Api, fx: MatrixFixture): Promise<void> {
  const perms = await api.get("/api/v1/permissions");
  const byAction = new Map(
    items<Rec>(perms.body).map((p) => [String(p["action"]), String(p["id"])]),
  );

  for (const [name, spec] of Object.entries(ROLE_PERMISSIONS)) {
    await step(fx, `role ${name}`, async () => {
      let role = await findBy(api, "/api/v1/roles", "name", name);
      if (!role) {
        const res = await api.post("/api/v1/roles", {
          name,
          description: `matrix fixture role ${name}`,
          is_global: spec.global,
        });
        created(res, `POST /roles ${name}`);
        role = await findBy(api, "/api/v1/roles", "name", name);
      }
      if (!role) throw new Error("created but not findable");
      const roleId = String(role["id"]);
      fx.roles[name] = roleId;

      for (const g of spec.grants) {
        const permId = byAction.get(g.action);
        if (!permId) {
          fx.problems.push(
            `role ${name}: permission "${g.action}" is not registered in this tenant`,
          );
          continue;
        }
        const res = await api.post(`/api/v1/roles/${roleId}/permissions`, {
          permission_id: permId,
          ...(g.effect ? { effect: g.effect } : {}),
          ...(g.scopes
            ? { scope_ids: g.scopes.map((s) => fx.scopes[s]).filter(Boolean) }
            : {}),
        });
        // 409 = the grant is already there, which is the idempotent case.
        if (res.status >= 300 && res.status !== 409) {
          fx.problems.push(
            `role ${name}: granting ${g.action}${g.effect ? ` (${g.effect})` : ""} ` +
              `-> HTTP ${res.status}: ${JSON.stringify(res.body).slice(0, 200)}`,
          );
        }
      }
    });
  }
}

async function buildGroups(api: Api, fx: MatrixFixture): Promise<void> {
  for (const name of ["mx-group-alpha", "mx-group-beta"]) {
    await step(fx, `group ${name}`, async () => {
      let g = await findBy(api, "/api/v1/groups", "name", name);
      if (!g) {
        const res = await api.post("/api/v1/groups", {
          name,
          description: `matrix fixture group ${name}`,
        });
        created(res, `POST /groups ${name}`);
        g = await findBy(api, "/api/v1/groups", "name", name);
      }
      if (!g) throw new Error("created but not findable");
      fx.groups[name] = String(g["id"]);
    });
  }
}

async function ensureUser(
  api: Api,
  fx: MatrixFixture,
  key: string,
  username: string,
): Promise<MatrixUser | undefined> {
  const email = `${username}@axiam.dev`;
  let u = await findBy(api, `/api/v1/users?search=${username}`, "username", username);
  if (!u) {
    const res = await api.post("/api/v1/users", {
      username,
      email,
      password: PASSWORD,
    });
    created(res, `POST /users ${username}`);
    u = await findBy(api, `/api/v1/users?search=${username}`, "username", username);
  }
  if (!u) throw new Error(`user ${username} created but not findable`);
  const id = String(u["id"]);

  // REST-created users land `PendingVerification` and there is no mailbox to
  // click a link in. Left alone they sign in fine for 24h and then start
  // failing with "account is pending verification", which turns a fixture into
  // a time bomb. Activate explicitly.
  if (u["status"] !== "Active") {
    const res = await api.put(`/api/v1/users/${id}`, { status: "Active" });
    if (res.status >= 300) {
      fx.problems.push(
        `user ${username}: activation -> HTTP ${res.status}: ` +
          JSON.stringify(res.body).slice(0, 200),
      );
    }
  }

  const rec = { id, username, email };
  fx.users[key] = rec;
  return rec;
}

async function buildUsers(api: Api, fx: MatrixFixture): Promise<void> {
  const wanted: Array<[string, string]> = [
    ["viewer", "mx-viewer"],
    ["editor", "mx-editor"],
    ["denied", "mx-denied"],
    ["grouped", "mx-grouped"],
    ["nobody", "mx-nobody"],
  ];
  for (const [key, username] of wanted) {
    await step(fx, `user ${username}`, () => ensureUser(api, fx, key, username));
  }
}

async function buildServiceAccounts(api: Api, fx: MatrixFixture): Promise<void> {
  for (const name of ["mx-sa-direct", "mx-sa-group", "mx-sa-cert"]) {
    await step(fx, `service account ${name}`, async () => {
      let sa = await findBy(api, "/api/v1/service-accounts", "name", name);
      let clientSecret: string | undefined;
      if (!sa) {
        const res = await api.post("/api/v1/service-accounts", {
          name,
          description: `matrix fixture service account ${name}`,
        });
        const body = created(res, `POST /service-accounts ${name}`);
        // The secret is returned exactly once, on creation. A re-run against a
        // stack that already has the account cannot recover it, which is why
        // the client-credentials assertions skip rather than fail when it is
        // absent — that is a property of the system, not a defect.
        clientSecret =
          (body?.["client_secret"] as string | undefined) ??
          (body?.["secret"] as string | undefined);
        sa = await findBy(api, "/api/v1/service-accounts", "name", name);
      }
      if (!sa) throw new Error("created but not findable");
      const id = String(sa["id"]);

      // A client secret is returned exactly once, at creation, so a second wave
      // against a stack that already has the account could never authenticate
      // as it. Rotating gives every wave a usable credential without needing a
      // wiped database — and rotation is itself part of the surface under test.
      if (!clientSecret) {
        const rot = await api.post<Rec>(`/api/v1/service-accounts/${id}/rotate-secret`, {});
        if (rot.status >= 200 && rot.status < 300) {
          clientSecret =
            (rot.body?.["client_secret"] as string | undefined) ??
            (rot.body?.["secret"] as string | undefined);
        } else {
          fx.problems.push(
            `service account ${name}: rotate-secret -> HTTP ${rot.status}: ` +
              JSON.stringify(rot.body).slice(0, 200),
          );
        }
      }

      fx.serviceAccounts[name] = {
        id,
        clientId: sa["client_id"] ? String(sa["client_id"]) : undefined,
        ...(clientSecret ? { clientSecret } : {}),
      };
    });
  }
}

/**
 * Wires principals to roles. Split out from creation so a failure to *create*
 * a role does not also cost the assignments that do not depend on it.
 */
async function buildGrants(api: Api, fx: MatrixFixture): Promise<void> {
  const assignUser = async (label: string, roleName: string, userKey: string, resourceKey?: string) =>
    step(fx, label, async () => {
      const roleId = fx.roles[roleName];
      const user = fx.users[userKey];
      if (!roleId || !user) throw new Error("role or user was not built");
      const resourceId = resourceKey ? fx.resources[resourceKey] : undefined;
      if (resourceKey && !resourceId) throw new Error(`resource ${resourceKey} was not built`);
      const res = await api.post(`/api/v1/roles/${roleId}/users`, {
        user_id: user.id,
        ...(resourceId ? { resource_id: resourceId } : {}),
      });
      if (res.status >= 300 && res.status !== 409) {
        throw new Error(`HTTP ${res.status}: ${JSON.stringify(res.body).slice(0, 200)}`);
      }
    });

  // mx-viewer: read-only, everywhere in tenant A.
  await assignUser("grant mx-role-viewer to mx-viewer", "mx-role-viewer", "viewer");

  // mx-editor: write, but only from `mx-b` down. The sibling is the control.
  await assignUser("grant mx-role-editor to mx-editor on mx-b", "mx-role-editor", "editor", "b");
  await assignUser("grant mx-role-viewer to mx-editor", "mx-role-viewer", "editor");

  // mx-denied: an allow at the deepest node, masked by a deny two levels up.
  // Deny-override means the deny wins wherever it sits — the whole point.
  await assignUser("grant mx-role-editor to mx-denied on mx-d", "mx-role-editor", "denied", "d");
  await assignUser("grant mx-role-deny to mx-denied on mx-a", "mx-role-deny", "denied", "a");
  await assignUser("grant mx-role-viewer to mx-denied", "mx-role-viewer", "denied");

  // mx-grouped holds nothing directly; everything it can do arrives through
  // mx-group-alpha, and must disappear the moment it leaves.
  await step(fx, "group mx-group-alpha carries mx-role-viewer", async () => {
    const roleId = fx.roles["mx-role-viewer"];
    const groupId = fx.groups["mx-group-alpha"];
    if (!roleId || !groupId) throw new Error("role or group was not built");
    const res = await api.post(`/api/v1/roles/${roleId}/groups`, { group_id: groupId });
    if (res.status >= 300 && res.status !== 409) {
      throw new Error(`HTTP ${res.status}: ${JSON.stringify(res.body).slice(0, 200)}`);
    }
  });
  await step(fx, "group mx-group-beta carries mx-role-editor on mx-b", async () => {
    const roleId = fx.roles["mx-role-editor"];
    const groupId = fx.groups["mx-group-beta"];
    const resourceId = fx.resources["b"];
    if (!roleId || !groupId || !resourceId) throw new Error("role, group or resource was not built");
    const res = await api.post(`/api/v1/roles/${roleId}/groups`, {
      group_id: groupId,
      resource_id: resourceId,
    });
    if (res.status >= 300 && res.status !== 409) {
      throw new Error(`HTTP ${res.status}: ${JSON.stringify(res.body).slice(0, 200)}`);
    }
  });
  await step(fx, "mx-grouped joins mx-group-alpha", async () => {
    const groupId = fx.groups["mx-group-alpha"];
    const user = fx.users["grouped"];
    if (!groupId || !user) throw new Error("group or user was not built");
    const res = await api.post(`/api/v1/groups/${groupId}/members`, { user_id: user.id });
    if (res.status >= 300 && res.status !== 409) {
      throw new Error(`HTTP ${res.status}: ${JSON.stringify(res.body).slice(0, 200)}`);
    }
  });

  // Service accounts: one direct grant, one that arrives only through a group.
  // A machine identity inherits a group's roles exactly as a person does, and
  // that path is newly implemented — it is exercised, not assumed.
  await step(fx, "mx-sa-direct holds mx-role-viewer directly", async () => {
    const roleId = fx.roles["mx-role-viewer"];
    const sa = fx.serviceAccounts["mx-sa-direct"];
    if (!roleId || !sa) throw new Error("role or service account was not built");
    const res = await api.post(`/api/v1/roles/${roleId}/service-accounts`, {
      service_account_id: sa.id,
    });
    if (res.status >= 300 && res.status !== 409) {
      throw new Error(`HTTP ${res.status}: ${JSON.stringify(res.body).slice(0, 200)}`);
    }
  });
  await step(fx, "mx-sa-group joins mx-group-alpha", async () => {
    const groupId = fx.groups["mx-group-alpha"];
    const sa = fx.serviceAccounts["mx-sa-group"];
    if (!groupId || !sa) throw new Error("group or service account was not built");
    const res = await api.post(`/api/v1/groups/${groupId}/service-accounts`, {
      service_account_id: sa.id,
    });
    if (res.status >= 300 && res.status !== 409) {
      throw new Error(`HTTP ${res.status}: ${JSON.stringify(res.body).slice(0, 200)}`);
    }
  });
}

async function buildPki(api: Api, fx: MatrixFixture): Promise<void> {
  const caPath = `/api/v1/organizations/${fx.orgId}/ca-certificates`;

  const ensureCa = async (key: string, subject: string) =>
    step(fx, `CA ${subject}`, async () => {
      const existing = await findBy(api, caPath, "subject", subject);
      if (existing) {
        fx.caCertificates[key] = String(existing["id"]);
        return;
      }
      const res = await api.post(caPath, {
        subject,
        key_algorithm: "Ed25519",
        validity_days: 365,
      });
      const body = created(res, `POST ${caPath} ${subject}`);
      const id =
        body?.["id"] ??
        (body?.["ca_certificate"] as Rec | undefined)?.["id"] ??
        (await findBy(api, caPath, "subject", subject))?.["id"];
      if (!id) throw new Error("created but not findable");
      fx.caCertificates[key] = String(id);
    });

  await ensureCa("org-ca", "CN=mx-org-ca");
  await ensureCa("untrusted-ca", "CN=mx-untrusted-ca");

  // Only the first is enabled as an mTLS trust anchor. The second exists to be
  // refused: a certificate from an untrusted CA must not authenticate.
  await step(fx, "enable mx-org-ca as an mTLS trust anchor", async () => {
    const id = fx.caCertificates["org-ca"];
    if (!id) throw new Error("mx-org-ca was not built");
    const res = await api.put(`${caPath}/${id}/mtls-trust-anchor`, { enabled: true });
    if (res.status >= 300) {
      throw new Error(`HTTP ${res.status}: ${JSON.stringify(res.body).slice(0, 200)}`);
    }
  });

  // Tenant A's signing CA — an intermediate beneath the org CA, which is the
  // shape the docs describe: organizations hold the root, tenants sign under it.
  await step(fx, "tenant A signing CA", async () => {
    const parent = fx.caCertificates["org-ca"];
    if (!parent) throw new Error("mx-org-ca was not built");
    const path = `/api/v1/organizations/${fx.orgId}/tenants/${fx.tenantA}/signing-cas`;
    const subject = "CN=mx-signing-ca-a";
    const existing = await findBy(api, path, "subject", subject);
    if (existing) {
      fx.caCertificates["signing-ca-a"] = String(existing["id"]);
      return;
    }
    const res = await api.post(path, {
      parent_ca_id: parent,
      subject,
      key_algorithm: "Ed25519",
      validity_days: 180,
    });
    const body = created(res, `POST ${path}`);
    const id =
      body?.["id"] ??
      (body?.["ca_certificate"] as Rec | undefined)?.["id"] ??
      (await findBy(api, path, "subject", subject))?.["id"];
    if (!id) throw new Error("created but not findable");
    fx.caCertificates["signing-ca-a"] = String(id);
  });

  // End-entity certificates are tenant-scoped.
  api.actingTenant(fx.tenantA);
  const issue = async (key: string, subject: string, caKey: string) =>
    step(fx, `certificate ${subject}`, async () => {
      const issuer = fx.caCertificates[caKey];
      if (!issuer) throw new Error(`${caKey} was not built`);
      const existing = await findBy(api, "/api/v1/certificates", "subject", subject);
      if (existing) {
        fx.certificates[key] = String(existing["id"]);
        return;
      }
      const res = await api.post("/api/v1/certificates", {
        issuer_ca_id: issuer,
        subject,
        cert_type: "Service",
        key_algorithm: "Ed25519",
        validity_days: 90,
      });
      const body = created(res, `POST /certificates ${subject}`);
      const id =
        body?.["id"] ??
        (body?.["certificate"] as Rec | undefined)?.["id"] ??
        (await findBy(api, "/api/v1/certificates", "subject", subject))?.["id"];
      if (!id) throw new Error("created but not findable");
      fx.certificates[key] = String(id);
    });

  await issue("sa", "CN=mx-cert-sa", "signing-ca-a");
  await issue("unbound", "CN=mx-cert-unbound", "signing-ca-a");
  await issue("revoked", "CN=mx-cert-revoked", "signing-ca-a");
  await issue("untrusted", "CN=mx-cert-untrusted", "untrusted-ca");

  await step(fx, "bind mx-cert-sa to mx-sa-cert", async () => {
    const certId = fx.certificates["sa"];
    const sa = fx.serviceAccounts["mx-sa-cert"];
    if (!certId || !sa) throw new Error("certificate or service account was not built");
    const res = await api.post(`/api/v1/service-accounts/${sa.id}/bind-certificate`, {
      certificate_id: certId,
    });
    if (res.status >= 300 && res.status !== 409) {
      throw new Error(`HTTP ${res.status}: ${JSON.stringify(res.body).slice(0, 200)}`);
    }
  });

  await step(fx, "revoke mx-cert-revoked", async () => {
    const certId = fx.certificates["revoked"];
    if (!certId) throw new Error("mx-cert-revoked was not built");
    const res = await api.post(`/api/v1/certificates/${certId}/revoke`, {
      reason: "matrix fixture: this certificate exists to be refused",
    });
    // 409 = already revoked by an earlier wave.
    if (res.status >= 300 && res.status !== 409) {
      throw new Error(`HTTP ${res.status}: ${JSON.stringify(res.body).slice(0, 200)}`);
    }
  });
}
