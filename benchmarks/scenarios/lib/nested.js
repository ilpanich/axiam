// N1 — per-target adapter for "authorize a resource nested N levels deep".
//
// This is the nested-resource counterpart of lib/targets.js: the ONLY place
// where the three products' differing authorization MODELS live, so that
// authz_nested_rest.js / authz_nested_grpc.js stay a single, uniform request
// loop. It is a separate module rather than more surface on targets.js because
// targets.js is the OAuth2/OIDC operation table — every builder there is a
// token-endpoint shape — while everything here is an authorization-decision
// shape plus the provisioning each product needs before such a decision can
// even be asked for.
//
// ---------------------------------------------------------------------------
// What "depth" means, and why the three targets cannot mean the same thing
// ---------------------------------------------------------------------------
//
// AXIAM is the only one of the three with a first-class hierarchical resource
// model. A role assignment scoped to a resource cascades to every descendant
// (`crates/axiam-authz/src/engine.rs` `applicable_role_ids` accepts an
// assignment scoped to any ancestor of the target; the ancestor set comes from
// `crates/axiam-db/src/repository/resource.rs` `get_ancestors`, one recursive
// graph query over the `child_of` edge). So AXIAM's depth-N cell is literal:
// provision a chain of N resources under the seeded `bench-resource`, leave the
// seeded grant where it is, and ask for a decision on the leaf. The engine
// cannot answer without resolving the chain.
//
// KEYCLOAK Authorization Services has resources, scopes, policies and
// permissions — but no parent/child resource relation and therefore no
// inheritance. Its idiomatic way to express "one grant covers this subtree" is
// URI matching: register a resource whose URI is `/<root>/*`, attach one
// scope-based permission to it, and ask for the decision on the full leaf PATH
// with `permission_resource_format=uri` + `permission_resource_matching_uri=true`
// so the server resolves the path to that resource itself. That is the
// `wildcard` mode below and it is the default, because it is the only Keycloak
// modelling where a SINGLE administrative act covers an unbounded subtree — the
// property AXIAM's cascade actually provides. The `per-node` mode (one
// resource + one permission per level, decision names the leaf resource
// directly) is available behind BENCH_KC_NESTED_MODE for two narrow purposes:
// as a control that isolates path-matching cost from resolution cost, and as
// the fallback if a given Keycloak build's path matcher does not recurse
// through `/*`. It is not the default and must not be published as one: its
// decision cost is depth-flat by construction and its admin cost is O(N).
//
// ZITADEL has no server-side per-resource authorization decision API at all.
// Its model is project roles carried in the token and evaluated by the
// application. There is no endpoint that can be asked "may this subject read
// resource X", nested or otherwise, so there is no depth to sweep. The arm
// here therefore measures Zitadel's NEAREST equivalent — the round trip a
// resource server actually makes before deciding locally, i.e. token
// introspection returning the project-role claims — and declares itself
// `depth_invariant`, which the nested report renders as a capability gap
// rather than as a flat curve. The request is byte-identical at every depth by
// construction; that is the finding, not a defect in the measurement.
//
// Every adapter's setup() ends in a FAIL-CLOSED PROBE: the decision at the
// requested depth must come back with the expected verdict before a single
// measured request is sent. Without it a misprovisioned fixture would quietly
// measure a short deny path (or an error path) and publish it as a nested
// authorization number — the exact failure authz_check_rest.js's G5 gate
// exists to prevent, for the same reason.
import http from 'k6/http';
import { cfg, baseUrl } from './config.js';
import { loginSession } from './auth.js';
import { adapter as oauthAdapter } from './targets.js';

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

// AXIAM's `get_ancestors` errors (rather than truncating) at
// MAX_ANCESTOR_DEPTH = 50 ancestors — see lib/config.js `authzDepth`. Clamp
// well below it so the deepest cell still measures the authorization path and
// not the depth-overflow error path, and so the same ladder is legal on a
// fixture that already carries a few levels of its own.
export const MAX_NESTED_DEPTH = 40;

function formBody(obj) {
  return Object.keys(obj)
    .filter((k) => obj[k] !== undefined && obj[k] !== '')
    .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(obj[k])}`)
    .join('&');
}

// The sweep's depth for this cell, clamped and integer-ised. 0 is legal and
// meaningful (the control point — see config.js), so this floors at 0, not 1.
export function nestedDepth() {
  const d = Math.floor(Number(cfg.authzDepth));
  if (!Number.isFinite(d) || d < 0) return 0;
  return Math.min(d, MAX_NESTED_DEPTH);
}

// Path segment names for the chain, deterministic so a re-run reuses what is
// already provisioned instead of duplicating it.
function levelName(i) {
  return `${cfg.nestedPrefix}-d${i}`;
}

// ---------------------------------------------------------------------------
// AXIAM
// ---------------------------------------------------------------------------

// Log in as the bootstrap admin (runner/seed.sh's `admin` user) for the
// provisioning half of setup(). This mirrors the identically-shaped helper in
// authz_check_rest.js's G5 block rather than reaching into it: that copy is
// documented there as G5-only, and importing across scenario files would make
// a change to one silently retune the other's cell. Provisioning is never a
// measured operation in either.
function axiamAdminSession() {
  const jar = http.cookieJar();
  const url = `${baseUrl()}/api/v1/auth/login`;
  const body = { username_or_email: cfg.adminUsername, password: cfg.adminPassword };
  if (cfg.orgId) body.org_id = cfg.orgId;
  else if (cfg.orgSlug) body.org_slug = cfg.orgSlug;
  if (cfg.tenantId) body.tenant_id = cfg.tenantId;
  else if (cfg.tenantSlug) body.tenant_slug = cfg.tenantSlug;

  const res = http.post(url, JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } });
  if (res.status !== 200) {
    throw new Error(
      `nested[axiam]: admin login failed (status ${res.status}). The depth sweep provisions its resource ` +
        'chain through the admin REST API; set BENCH_ADMIN_USERNAME/BENCH_ADMIN_PASSWORD to match runner/seed.sh.',
    );
  }
  const cookies = jar.cookiesForURL(url);
  const access = cookies.axiam_access && cookies.axiam_access[0];
  const csrf = cookies.axiam_csrf && cookies.axiam_csrf[0];
  if (!access || !csrf) throw new Error('nested[axiam]: admin login returned no axiam_access/axiam_csrf cookie');
  return {
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${access}`, 'X-CSRF-Token': csrf },
    cookies: { axiam_csrf: csrf },
  };
}

// `GET /api/v1/resources/{id}/children` returns an UNPAGINATED Vec<Resource>
// (crates/axiam-api-rest/src/handlers/resources.rs `list_children`), so one
// call per level is enough. A failure is non-fatal — we provision from scratch.
function axiamChildByName(sess, parentId, name) {
  const res = http.get(`${baseUrl()}/api/v1/resources/${parentId}/children`, { headers: sess.headers });
  if (res.status !== 200) return null;
  let items;
  try {
    const body = res.json();
    items = Array.isArray(body) ? body : body.items || [];
  } catch (_e) {
    return null;
  }
  for (const r of items) {
    if (r && r.name === name && r.id) return r.id;
  }
  return null;
}

// Provision (or reuse) a chain of `depth` resources hanging off the seeded
// `bench-resource`, and return every id from the root down. Exported because
// the gRPC scenario needs the identical chain — the whole point of the REST/
// gRPC pair is that the two transports resolve the SAME hierarchy.
//
// `POST /api/v1/resources` with `parent_id` writes BOTH the `parent_id` field
// and the `child_of` graph edge in one query
// (crates/axiam-db/src/repository/resource.rs), and `get_ancestors` walks the
// edge — so a chain built this way is walked exactly as a real one is.
export function provisionAxiamChain(depth) {
  const root = __ENV.BENCH_RESOURCE_ID || '';
  if (!UUID_RE.test(root)) {
    throw new Error(
      `nested[axiam]: BENCH_RESOURCE_ID is "${root}", not a UUID — the depth sweep parents its chain on the ` +
        'seeded resource. Source .seed/axiam.seed.env (runner/seed.sh) before running this cell.',
    );
  }
  const ids = [root];
  if (depth <= 0) return ids;

  const sess = axiamAdminSession();
  let parent = root;
  let created = 0;
  for (let i = 1; i <= depth; i++) {
    const name = levelName(i);
    let id = axiamChildByName(sess, parent, name);
    if (!id) {
      const res = http.post(
        `${baseUrl()}/api/v1/resources`,
        JSON.stringify({ name, resource_type: 'bench-nested', parent_id: parent }),
        { headers: sess.headers, cookies: sess.cookies },
      );
      if (res.status !== 201) {
        throw new Error(
          `nested[axiam]: creating ${name} (level ${i}/${depth}) failed (status ${res.status}): ` +
            String(res.body).slice(0, 200),
        );
      }
      try {
        id = res.json().id;
      } catch (_e) {
        id = null;
      }
      if (!id) throw new Error(`nested[axiam]: create ${name} returned no id`);
      created++;
    }
    ids.push(id);
    parent = id;
  }
  console.log(
    `nested[axiam]: chain ready — depth=${depth}, ${created} level(s) created, ` +
      `${depth - created} reused; leaf=${ids[ids.length - 1]}`,
  );
  return ids;
}

function axiamCheckBody(leafId) {
  return JSON.stringify({ action: 'read', resource_id: leafId });
}

const axiam = {
  key: 'axiam',
  // The decision genuinely traverses the hierarchy, so depth is expected to
  // move the number. That expectation is what the sweep tests.
  depthInvariant: false,
  model: 'hierarchical resource tree; one role assignment on the root cascades to every descendant',
  setup(depth) {
    const chain = provisionAxiamChain(depth);
    const leaf = chain[chain.length - 1];
    const session = loginSession();
    const data = {
      target: 'axiam',
      depth,
      leaf_id: leaf,
      chain_len: chain.length,
      access_token: session.access_token,
      csrf_token: session.csrf_token,
    };

    // Fail-closed probe. A DENY here means the grant did NOT cascade, so the
    // engine took the short "no applicable roles" path and every measured
    // number below would be the cost of NOT walking the hierarchy.
    const probe = http.post(`${baseUrl()}/api/v1/authz/check`, axiamCheckBody(leaf), {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${session.access_token}`,
        'X-CSRF-Token': session.csrf_token,
      },
      cookies: { axiam_csrf: session.csrf_token },
    });
    if (probe.status !== 200) {
      throw new Error(
        `nested[axiam]: depth-${depth} probe returned ${probe.status}, not a decision: ` +
          String(probe.body).slice(0, 200),
      );
    }
    let decision = {};
    try {
      decision = probe.json();
    } catch (_e) { /* handled by the allowed check below */ }
    if (decision.allowed !== true) {
      throw new Error(
        `nested[axiam]: the depth-${depth} leaf evaluated to DENY (reason: ${decision.reason}). The seeded ` +
          'bench-reader grant on bench-resource did not cascade down the chain, so this cell would measure ' +
          'the SHORT deny path instead of an ancestor walk. Re-seed and re-provision.',
      );
    }
    console.log(`nested[axiam]: depth=${depth} probe = ALLOW (${decision.reason_code || 'allowed'})`);
    return data;
  },
  buildCheck(data) {
    return {
      method: 'POST',
      url: `${baseUrl()}/api/v1/authz/check`,
      body: axiamCheckBody(data.leaf_id),
      params: {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${data.access_token}`,
          'X-CSRF-Token': data.csrf_token,
        },
        cookies: { axiam_csrf: data.csrf_token },
      },
      expect: 200,
    };
  },
};

// ---------------------------------------------------------------------------
// Keycloak
// ---------------------------------------------------------------------------

function kcRealmBase() {
  return `${baseUrl()}/realms/${cfg.realm}`;
}

function kcAdminToken() {
  const res = http.post(
    `${baseUrl()}/realms/master/protocol/openid-connect/token`,
    formBody({
      grant_type: 'password',
      client_id: 'admin-cli',
      username: cfg.kcAdminUsername,
      password: cfg.kcAdminPassword,
    }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
  );
  if (res.status !== 200) {
    throw new Error(
      `nested[keycloak]: master-realm admin token failed (status ${res.status}). The depth sweep provisions ` +
        "Keycloak's Authorization Services config, which has no non-admin API; set BENCH_KC_ADMIN/" +
        'BENCH_KC_ADMIN_PASSWORD to match runner/seed.sh.',
    );
  }
  const token = res.json().access_token;
  if (!token) throw new Error('nested[keycloak]: admin token response carried no access_token');
  return { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
}

// Parse a response body as JSON, or null. Shared by every adapter below.
function jsonOf(res) {
  try {
    return res.json();
  } catch (_e) {
    return null;
  }
}

function kcGet(h, path) {
  const res = http.get(`${baseUrl()}${path}`, { headers: h });
  if (res.status !== 200) {
    throw new Error(`nested[keycloak]: GET ${path} -> ${res.status}: ${String(res.body).slice(0, 200)}`);
  }
  return jsonOf(res);
}

// Find a named object in one of the resource-server collections, tolerating
// Keycloak's partial-name matching by filtering exactly on the client side.
// `idField` differs by collection: resources are keyed `_id`, everything else
// `id`.
function kcFindNamed(h, path, name, idField) {
  const rows = kcGet(h, path) || [];
  for (const row of rows) {
    if (row && row.name === name) return row[idField] || null;
  }
  return null;
}

// Create-or-reuse. Keycloak answers 409 on a duplicate name, which is a
// legitimate outcome on a re-run against a live stack, so a conflict re-reads
// rather than failing.
function kcEnsure(h, listPath, createPath, name, body, idField) {
  const existing = kcFindNamed(h, listPath, name, idField);
  if (existing) return existing;
  const res = http.post(`${baseUrl()}${createPath}`, JSON.stringify(body), { headers: h });
  if (res.status === 201 || res.status === 200) {
    const created = jsonOf(res);
    if (created && (created[idField] || created.id)) return created[idField] || created.id;
  } else if (res.status !== 409) {
    throw new Error(
      `nested[keycloak]: POST ${createPath} (${name}) -> ${res.status}: ${String(res.body).slice(0, 200)}`,
    );
  }
  const found = kcFindNamed(h, listPath, name, idField);
  if (!found) throw new Error(`nested[keycloak]: ${name} was neither created nor found under ${listPath}`);
  return found;
}

// The leaf path a depth-N decision asks about: `/bench-nest/bench-nest-d1/…`.
// Depth 0 is the root path itself, which keeps the control point on the same
// URI space as every other rung of the ladder.
function kcLeafPath(depth) {
  let p = `/${cfg.nestedPrefix}`;
  for (let i = 1; i <= depth; i++) p += `/${levelName(i)}`;
  return p;
}

const keycloak = {
  key: 'keycloak',
  depthInvariant: false,
  model: 'flat resource set; nesting expressed as URI paths resolved by the server (no inheritance relation)',
  setup(depth) {
    const mode = cfg.kcNestedMode === 'per-node' ? 'per-node' : 'wildcard';
    const h = kcAdminToken();
    const realm = cfg.realm;
    const rsName = `${cfg.nestedPrefix}-rs`;

    // 1. A DEDICATED resource-server client. The seeded `bench-client` is
    //    deliberately left alone: flipping authorizationServicesEnabled on it
    //    would change the fixture every other cell in the harness measures
    //    against.
    //
    //    Not routed through kcEnsure(): clients are the one collection keyed by
    //    `clientId` rather than by `name` (the `name` field is an optional
    //    display label), and `POST /clients` answers 201 with an EMPTY body and
    //    a Location header — so the generic find-by-name-then-create shape
    //    would fail to recognise a client someone had already created without a
    //    display name, POST a duplicate, take the 409 and then report it as
    //    missing. The query below is Keycloak's own exact clientId filter.
    const clientPath = `/admin/realms/${realm}/clients?clientId=${rsName}`;
    let clients = kcGet(h, clientPath) || [];
    if (clients.length === 0) {
      const created = http.post(
        `${baseUrl()}/admin/realms/${realm}/clients`,
        JSON.stringify({
          clientId: rsName,
          name: rsName,
          enabled: true,
          publicClient: false,
          serviceAccountsEnabled: true,
          authorizationServicesEnabled: true,
          standardFlowEnabled: false,
          directAccessGrantsEnabled: false,
        }),
        { headers: h },
      );
      // 409 = someone else won the race; re-read rather than fail.
      if (created.status !== 201 && created.status !== 409) {
        throw new Error(
          `nested[keycloak]: creating resource-server client '${rsName}' failed (status ${created.status}): ` +
            String(created.body).slice(0, 200),
        );
      }
      clients = kcGet(h, clientPath) || [];
    }
    const rs = clients[0];
    if (!rs || !rs.id) {
      throw new Error(`nested[keycloak]: resource-server client '${rsName}' not found after provisioning`);
    }
    if (rs.authorizationServicesEnabled !== true) {
      throw new Error(
        `nested[keycloak]: client '${rsName}' has authorizationServicesEnabled=${rs.authorizationServicesEnabled}. ` +
          'It exists but is not a resource server, so it has no policies to evaluate — delete it in the admin ' +
          'console and re-run this cell so it is recreated correctly.',
      );
    }
    const authz = `/admin/realms/${realm}/clients/${rs.id}/authz/resource-server`;

    // 2. Remove Keycloak's auto-created "Default Permission" and "Default
    //    Resource". The default pair is a grant-all policy over the URI `/*`,
    //    which would both decide our request for us AND compete with our own
    //    resource during URI resolution — a cell that measured it would report
    //    a number for Keycloak's default policy, not for the fixture.
    for (const [coll, label, idField] of [
      ['permission', 'Default Permission', 'id'],
      ['resource', 'Default Resource', '_id'],
    ]) {
      const id = kcFindNamed(h, `${authz}/${coll}`, label, idField);
      if (id) {
        const del = http.del(`${baseUrl()}${authz}/${coll}/${id}`, null, { headers: h });
        if (del.status !== 204 && del.status !== 200 && del.status !== 404) {
          throw new Error(
            `nested[keycloak]: could not delete the auto-created ${label} (status ${del.status}) — with it in ` +
              'place the decision would be answered by Keycloak\'s grant-all default, not by the fixture.',
          );
        }
        console.log(`nested[keycloak]: removed auto-created ${label}`);
      }
    }

    // 3. The `read` scope — the counterpart of AXIAM's `read` action, so both
    //    products are asked the same question and not merely a similar one.
    const scopeId = kcEnsure(h, `${authz}/scope`, `${authz}/scope`, 'read', { name: 'read' }, 'id');

    // 4. A user policy naming the seeded bench user. A user policy rather than
    //    a role policy keeps the fixture free of realm-role plumbing that the
    //    other cells would then also see.
    const users = kcGet(h, `/admin/realms/${realm}/users?username=${cfg.username}&exact=true`) || [];
    const userId = users[0] && users[0].id;
    if (!userId) {
      throw new Error(
        `nested[keycloak]: seeded user '${cfg.username}' not found — run 'just target=keycloak bench-seed' first.`,
      );
    }
    const policyId = kcEnsure(
      h,
      `${authz}/policy?name=${cfg.nestedPrefix}-user`,
      `${authz}/policy/user`,
      `${cfg.nestedPrefix}-user`,
      { name: `${cfg.nestedPrefix}-user`, users: [userId], logic: 'POSITIVE' },
      'id',
    );

    // 5. The resource(s) + scope-based permission(s), per the selected mode.
    const leafPath = kcLeafPath(depth);
    if (mode === 'wildcard') {
      const resName = `${cfg.nestedPrefix}-root`;
      const resId = kcEnsure(
        h,
        `${authz}/resource`,
        `${authz}/resource`,
        resName,
        {
          name: resName,
          type: `urn:${cfg.nestedPrefix}:resource`,
          // Both the root itself and everything under it, so the depth-0
          // control and the depth-N rungs resolve to the SAME single resource
          // — which is the property being measured.
          uris: [`/${cfg.nestedPrefix}`, `/${cfg.nestedPrefix}/*`],
          scopes: [{ name: 'read' }],
          ownerManagedAccess: false,
        },
        '_id',
      );
      kcEnsure(
        h,
        `${authz}/permission?name=${cfg.nestedPrefix}-perm`,
        `${authz}/permission/scope`,
        `${cfg.nestedPrefix}-perm`,
        {
          name: `${cfg.nestedPrefix}-perm`,
          resources: [resId],
          scopes: [scopeId],
          policies: [policyId],
          decisionStrategy: 'AFFIRMATIVE',
        },
        'id',
      );
    } else {
      // per-node: one resource + one permission per level, each pinned to its
      // own exact URI. O(N) administrative acts for the same reach one
      // wildcard grant covers — which is the cost this control makes visible.
      //
      // The `-pn-` infix keeps every per-node object in a NAMESPACE OF ITS OWN,
      // disjoint from the wildcard arm's `<prefix>-root`. Without it, running
      // the per-node control and then the wildcard arm against the same live
      // Keycloak would have the wildcard arm find the per-node root by name and
      // reuse it — URIs and all — so it would silently measure an exact-path
      // resource while reporting itself as the wildcard arm. The two arms now
      // coexist on one realm and neither can inherit the other's fixture.
      for (let i = 0; i <= depth; i++) {
        const nodeName = `${cfg.nestedPrefix}-pn-${i}`;
        const resId = kcEnsure(
          h,
          `${authz}/resource`,
          `${authz}/resource`,
          nodeName,
          {
            name: nodeName,
            type: `urn:${cfg.nestedPrefix}:resource`,
            uris: [kcLeafPath(i)],
            scopes: [{ name: 'read' }],
            ownerManagedAccess: false,
          },
          '_id',
        );
        kcEnsure(
          h,
          `${authz}/permission?name=${nodeName}-perm`,
          `${authz}/permission/scope`,
          `${nodeName}-perm`,
          {
            name: `${nodeName}-perm`,
            resources: [resId],
            scopes: [scopeId],
            policies: [policyId],
            decisionStrategy: 'AFFIRMATIVE',
          },
          'id',
        );
      }
    }

    // 6. The bench user's own access token. `loginSession()` routes through
    //    targets.js's keycloak.login() (the ROPC grant on the seeded
    //    bench-client), so the subject of the decision is the same human user
    //    AXIAM's arm authorizes — not a service account.
    const session = loginSession();
    const data = {
      target: 'keycloak',
      depth,
      mode,
      leaf_path: leafPath,
      audience: rsName,
      access_token: session.access_token,
    };

    // Fail-closed probe. Keycloak answers a REFUSED decision with 403
    // (`access_denied`), so a wrongly-provisioned fixture would otherwise show
    // up as a 100%-failed cell after the full measured window rather than in
    // the first second of setup.
    const probe = http.post(`${kcRealmBase()}/protocol/openid-connect/token`, kcDecisionBody(data), {
      headers: kcDecisionHeaders(data),
    });
    if (probe.status !== 200 || !(jsonOf(probe) || {}).result) {
      throw new Error(
        `nested[keycloak]: the depth-${depth} decision probe on ${leafPath} returned ${probe.status} ` +
          `(${String(probe.body).slice(0, 200)}). In '${mode}' mode this means the permission did not cover the ` +
          'leaf path. If this Keycloak build\'s path matcher does not recurse through `/*`, re-run the cell ' +
          'with BENCH_KC_NESTED_MODE=per-node and label it as the per-node control.',
      );
    }
    console.log(`nested[keycloak]: depth=${depth} mode=${mode} probe = GRANT on ${leafPath}`);
    return data;
  },
  buildCheck(data) {
    return {
      method: 'POST',
      url: `${kcRealmBase()}/protocol/openid-connect/token`,
      body: kcDecisionBody(data),
      params: kcDecisionHeaders(data),
      // 200 == granted. Keycloak returns 403 access_denied for a refusal, so
      // status alone is a faithful pass/fail here (unlike AXIAM, whose deny is
      // also a 200 — hence that arm's probe checks `allowed`).
      expect: 200,
    };
  },
};

// UMA 2.0 permission request in `decision` response mode: the standard
// Keycloak "is this subject allowed?" call. `permission_resource_format=uri` +
// `permission_resource_matching_uri=true` are what make the server resolve the
// nested PATH to a registered resource rather than requiring the caller to
// already know which resource covers it — i.e. they are the whole point of the
// wildcard arm. They are harmless in per-node mode, where the path is an exact
// registered URI.
function kcDecisionBody(data) {
  return formBody({
    grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
    audience: data.audience,
    permission: `${data.leaf_path}#read`,
    permission_resource_format: 'uri',
    permission_resource_matching_uri: 'true',
    response_mode: 'decision',
  });
}

function kcDecisionHeaders(data) {
  return {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: `Bearer ${data.access_token}`,
    },
  };
}

// ---------------------------------------------------------------------------
// Zitadel
// ---------------------------------------------------------------------------

const zitadel = {
  key: 'zitadel',
  // Not a measurement artefact — a fact about the product. See the module
  // header. The nested report renders this as a capability gap and refuses to
  // plot it as a depth curve.
  depthInvariant: true,
  model: 'no per-resource decision API; project roles ride in the token and are evaluated by the application',
  setup(depth) {
    const a = oauthAdapter();
    const cc = a.clientCredentials();
    const res = http.request(cc.method, cc.url, cc.body || null, cc.params || {});
    if (res.status !== (cc.expect || 200)) {
      throw new Error(
        `nested[zitadel]: could not mint a token for the introspection arm (status ${res.status}) — ` +
          "run 'just target=zitadel bench-seed' first.",
      );
    }
    const token = (jsonOf(res) || {}).access_token;
    if (!token) throw new Error('nested[zitadel]: client_credentials response carried no access_token');

    // Fail-closed probe: the introspection must come back `active`, otherwise
    // the arm would be measuring a rejection rather than the claim-fetch a
    // resource server really performs.
    const built = a.introspect(token);
    const probe = http.request(built.method, built.url, built.body || null, built.params || {});
    const body = jsonOf(probe) || {};
    if (probe.status !== (built.expect || 200) || body.active !== true) {
      throw new Error(
        `nested[zitadel]: introspection probe returned ${probe.status} active=${body.active} — ` +
          `${String(probe.body).slice(0, 200)}`,
      );
    }
    console.log(
      `nested[zitadel]: depth=${depth} is DEPTH-INVARIANT by construction — Zitadel exposes no per-resource ` +
        'authorization decision endpoint, so this arm measures the role-claim round trip a resource server ' +
        'makes before deciding locally. The request is byte-identical at every depth.',
    );
    return { target: 'zitadel', depth, token, depth_invariant: true };
  },
  buildCheck(data) {
    return oauthAdapter().introspect(data.token);
  },
};

const ADAPTERS = { axiam, keycloak, zitadel };

export function nestedAdapter() {
  const a = ADAPTERS[cfg.target];
  if (!a) {
    throw new Error(
      `nested: no nested-authz adapter for target '${cfg.target}' (have: ${Object.keys(ADAPTERS).join(', ')})`,
    );
  }
  return a;
}
