import type { DocPage } from "./types";

/**
 * "Authorization" — the RBAC engine and the entities it evaluates over.
 *
 * The deny-override page is deliberately separate from the engine overview
 * rather than a section inside it: it is the part of the model most likely to
 * be misread, and the worked precedence table is the thing to link somebody to.
 */
export const AUTHORIZATION_PAGES: DocPage[] = [
  {
    slug: "authz",
    section: "Authorization",
    navLabel: "Authorization engine",
    title: "The authorization engine",
    intro:
      "Role-based, default-deny, evaluated over a cascading resource hierarchy — and reachable over REST, gRPC or AMQP with the same answer from each.",
    blocks: [
      { type: "h", id: "model", text: "The evaluation model" },
      {
        type: "p",
        text: "Every check asks one question: *may this principal perform this action on this resource, in this scope?* The answer is computed from the grants attached to the roles the principal holds — directly, through a group, or inherited from an ancestor resource.",
      },
      {
        type: "p",
        text: "Precedence is short and worth memorising, because everything else follows from it:",
      },
      {
        type: "steps",
        steps: [
          {
            title: "Default deny",
            body: "Nothing is permitted unless something permits it. An unknown action on an unknown resource is denied with `no_grant`, not with an error.",
          },
          {
            title: "An applicable allow grant permits the action",
            body: "Grants apply through directly assigned roles, group-inherited roles, and roles assigned on any ancestor of the resource.",
          },
          {
            title: "An applicable deny grant refuses it — and beats every allow",
            body: "Wherever either sits in the hierarchy. Deny wins; it is not \"most specific wins\". See [Deny grants & precedence](#/docs/deny).",
          },
        ],
      },
      { type: "h", id: "hierarchy", text: "Hierarchy & cascade" },
      {
        type: "p",
        text: "Resources form a tree. A role assigned on a parent cascades to every descendant, so you grant broadly at the top and refine below rather than enumerating every leaf. A resource's ancestors and children are both queryable, which is what makes an admin UI able to explain *why* a decision came out the way it did.",
      },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/resources/{resource_id}/ancestors", summary: "The chain a grant can cascade down from." },
          { method: "GET", path: "/api/v1/resources/{resource_id}/children", summary: "The subtree a grant here would reach." },
        ],
      },
      { type: "h", id: "scopes", text: "Scopes" },
      {
        type: "p",
        text: "A **scope** narrows a permission to part of a resource — `read` on a customer record limited to the `billing` scope, say, rather than to everything the record contains. A grant carries a list of scope ids; an empty list means *all scopes*, including unscoped checks.",
      },
      {
        type: "warn",
        text: "Read that wildcard rule carefully in the deny direction: a **resource-level deny with no scopes is stronger than a scoped one**, because it matches every request for that action regardless of what scope the request names.",
      },
      { type: "h", id: "checks", text: "Making a check" },
      {
        type: "p",
        text: "Every SDK exposes the same `can(action, resource)` call — a plain yes/no — alongside a fuller form that also returns *why* a refusal was refused (`no_grant` versus `denied_by_rule`), and a batched form for when one request needs several decisions. The transport underneath is a deployment choice, not a semantic one.",
      },
      {
        type: "api",
        endpoints: [
          { method: "POST", path: "/api/v1/authz/check", summary: "One decision." },
          { method: "POST", path: "/api/v1/authz/check/batch", summary: "Several decisions in one round trip." },
        ],
      },
      {
        type: "codegroup",
        caption: "single and batched checks",
        tabs: [
          {
            label: "TypeScript",
            code: "// one decision\nconst allowed = await client.can('read', 'doc:1');\n\n// several in one round trip — results preserve input order\nconst decisions = await client.batchCheck([\n  { action: 'read', resourceId: 'doc:1' },\n  { action: 'write', resourceId: 'doc:1' },\n]);",
          },
          {
            label: "Python",
            code: "allowed = client.can(\"read\", resource_id)\n\ndecisions = client.batch_check([\n    AccessCheck(action=\"read\", resource_id=resource_id),\n    AccessCheck(action=\"write\", resource_id=resource_id),\n])",
          },
          {
            label: "Rust",
            code: "// `can` answers yes/no; `check_access` returns the full decision,\n// including the reason a refusal was refused.\nlet allowed = client.can(\"read\", resource_id, None).await?;\nlet decision = client.check_access(\"read\", resource_id, None).await?;",
          },
          {
            label: "Go",
            code: "allowed, err := client.Can(ctx, \"read\", resourceID)\n\nallowed, reason, err := client.CheckAccess(ctx, \"read\", resourceID)\n\nresults, err := client.BatchCheck(ctx, []axiam.AccessCheck{\n    {Action: \"read\", ResourceID: resourceID},\n    {Action: \"write\", ResourceID: resourceID},\n})",
          },
          {
            label: "Java",
            code: "boolean allowed = client.can(\"read\", \"doc:1\");",
          },
        ],
      },
      { type: "h", id: "guards", text: "Declarative guards" },
      {
        type: "p",
        text: "Calling `can()` by hand at the top of a handler works, and is easy to forget. Every SDK also ships the declarative form idiomatic to its language — a middleware, a dependency, an attribute macro or an annotation — so the requirement sits on the route rather than buried in its body.",
      },
      {
        type: "codegroup",
        caption: "the same guard, four ways",
        tabs: [
          {
            label: "TypeScript",
            code: "import { requireAccess, fromParam } from 'axiam-sdk/middleware';\n\napp.get(\n  '/documents/:id',\n  requireAccess(authzSession, 'read', fromParam('id')),\n  (req, res) => res.json({ documentId: req.params.id }),\n);",
          },
          {
            label: "Python",
            code: "from axiam_sdk.fastapi import AxiamUser, require_access\n\nrequire_doc_read = require_access(\n    verifier, \"acme\", authz_client, \"documents:read\", resource_param=\"doc_id\"\n)\n\n\n@app.get(\"/docs/{doc_id}\")\nasync def get_doc(doc_id: str, user: AxiamUser = Depends(require_doc_read)):\n    return {\"message\": f\"user {user.user_id} may read document {doc_id}\"}",
          },
          {
            label: "Rust",
            code: "use axiam_sdk::{require_access, require_auth};\nuse axiam_sdk::middleware::AxiamUser;\n\n#[require_access(action = \"read\", resource_param = \"id\")]\nasync fn get_document(user: AxiamUser) -> String {\n    format!(\"user {} may read this document\", user.user_id)\n}",
          },
          {
            label: "Java",
            code: "@RestController\npublic class DocumentController {\n\n    @AxiamRequireAccess(action = \"read\", resourceParam = \"id\")\n    @GetMapping(\"/documents/{id}\")\n    public String read(@PathVariable(\"id\") String id) {\n        return \"document \" + id;\n    }\n}",
          },
        ],
      },
      {
        type: "note",
        text: "Each of these runs strictly **after** authentication, and issues the check for the *request's* authenticated caller — never for the application's own, usually service-account, session. That distinction is the one thing to get right when writing a guard by hand, and it is why using the shipped one is worth it.",
      },
      {
        type: "warn",
        text: "Every SDK also offers a `requireRole`-style helper. It is a **local, no-round-trip** check against the verified identity's roles: cheaper, coarser, and **not** a substitute for the authoritative resource-level check. A role check cannot see a deny grant on the resource.",
      },
      { type: "h", id: "perf", text: "The hot path" },
      {
        type: "p",
        text: "An authorization check is the most frequently executed operation in the product, so the evaluation is a **single pass over grants that were already fetched**. Denies live on the same edge as allows and arrive in the same batched read — there is no deny-specific query, and a tenant with no deny rules pays nothing for the feature existing.",
      },
      {
        type: "p",
        text: "Deny short-circuits and allows are only remembered, so the result does not depend on the order grants come back in: a rule set has one answer, not one answer per query plan.",
      },
      {
        type: "p",
        text: "Where checks dominate your traffic, two levers matter. **Database CPU** is the main ceiling — measured gains of roughly 90% from a second pair of database cores. The optional **decision cache** sits on top: transformative on gRPC checks, marginal on REST ones, because REST's per-request session-cookie validation is a database read the cache does not cover. Both are covered in [Configuration](#/docs/configuration).",
      },
      {
        type: "note",
        text: "Enabling the decision cache changes performance only, never the decision returned. Every access-narrowing mutation invalidates the affected entries immediately, so a revocation cannot leave a stale allow behind; the TTL is a bounded-staleness backstop, not the invalidation mechanism.",
      },
    ],
  },

  {
    slug: "rbac",
    section: "Authorization",
    navLabel: "Roles & resources",
    title: "Roles, permissions, resources & groups",
    intro:
      "The entities the engine evaluates over, how they relate, and the API for managing each.",
    blocks: [
      { type: "h", id: "shape", text: "How they fit together" },
      {
        type: "code",
        caption: "the access graph",
        code: "User ──────┐\n           ├──> Role ──> Permission (action + effect [+ scopes])\nGroup ─────┘              │\n  ▲                       └──> applies at a Resource\n  └─ users inherit every role assigned to their groups\n\nResource tree:   /fleet\n                   └── /fleet/decommissioned\n                         └── /fleet/decommissioned/unit-7\n                 a role assigned on /fleet reaches all three",
      },
      { type: "h", id: "permissions", text: "Permissions" },
      {
        type: "p",
        text: "A permission is an action name plus an effect. AXIAM seeds **113 built-in permissions across 25 families** into every tenant at bootstrap — `users:*`, `roles:*`, `resources:*`, `oauth2_clients:*`, `certificates:*`, `ca_certificates:*`, `audit_logs:*`, `federation:*`, `webhooks:*`, `reactors:*`, `scim_tokens:*`, `gdpr:*` and the rest. These are the actions the REST API's own route guards check against, so an administrator's authority over AXIAM is expressed in the same model as an application's authority over its own resources.",
      },
      {
        type: "p",
        text: "You are not limited to them: define your own action names for your application's domain and grant them the same way.",
      },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/permissions", summary: "List permissions in the tenant." },
          { method: "POST", path: "/api/v1/permissions", summary: "Define one." },
          { method: "GET", path: "/api/v1/permissions/{permission_id}", summary: "Read one." },
          { method: "PUT", path: "/api/v1/permissions/{permission_id}", summary: "Update it." },
          { method: "DELETE", path: "/api/v1/permissions/{permission_id}", summary: "Delete it." },
        ],
      },
      { type: "h", id: "roles", text: "Roles" },
      {
        type: "p",
        text: "A role is a named collection of permissions, assignable to users and to groups, and either global or bound to a specific resource. Three are seeded at bootstrap: `super-admin` (every permission), `admin` (all entity CRUD) and `viewer` (list and get only).",
      },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/roles", summary: "List roles." },
          { method: "POST", path: "/api/v1/roles", summary: "Create one." },
          { method: "PUT", path: "/api/v1/roles/{role_id}", summary: "Update it." },
          { method: "DELETE", path: "/api/v1/roles/{role_id}", summary: "Delete it." },
          { method: "POST", path: "/api/v1/roles/{role_id}/permissions", summary: "Grant a permission to the role." },
          { method: "DELETE", path: "/api/v1/roles/{role_id}/permissions/{permission_id}", summary: "Revoke it." },
          { method: "POST", path: "/api/v1/roles/{role_id}/users", summary: "Assign the role to a user." },
          { method: "DELETE", path: "/api/v1/roles/{role_id}/users/{user_id}", summary: "Unassign it." },
          { method: "POST", path: "/api/v1/roles/{role_id}/groups", summary: "Assign the role to a group." },
          { method: "DELETE", path: "/api/v1/roles/{role_id}/groups/{group_id}", summary: "Unassign it." },
        ],
      },
      { type: "h", id: "groups", text: "Groups" },
      {
        type: "p",
        text: "A group is a named collection of users, and roles assigned to it are inherited by every member. Groups are how you avoid per-user grants — and how you make offboarding a single operation rather than an audit.",
      },
      {
        type: "note",
        text: "Group membership inherits **denies** exactly as it inherits allows. A deny reached through a group beats an allow assigned directly to the user.",
      },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/groups", summary: "List groups." },
          { method: "POST", path: "/api/v1/groups", summary: "Create one." },
          { method: "PUT", path: "/api/v1/groups/{group_id}", summary: "Update it." },
          { method: "DELETE", path: "/api/v1/groups/{group_id}", summary: "Delete it." },
          { method: "GET", path: "/api/v1/groups/{group_id}/members", summary: "List members." },
          { method: "POST", path: "/api/v1/groups/{group_id}/members", summary: "Add a member." },
          { method: "DELETE", path: "/api/v1/groups/{group_id}/members/{user_id}", summary: "Remove one." },
        ],
      },
      { type: "h", id: "resources", text: "Resources & scopes" },
      {
        type: "p",
        text: "Resources are the things being protected, arranged in a tree. Model them to match how authority actually delegates in your domain — an organizational unit, a project, a device fleet — because that shape is what a grant cascades along.",
      },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/resources", summary: "List resources." },
          { method: "POST", path: "/api/v1/resources", summary: "Create one, optionally under a parent." },
          { method: "PUT", path: "/api/v1/resources/{resource_id}", summary: "Update it." },
          { method: "DELETE", path: "/api/v1/resources/{resource_id}", summary: "Delete it." },
          { method: "GET", path: "/api/v1/resources/{resource_id}/scopes", summary: "List its scopes." },
          { method: "POST", path: "/api/v1/resources/{resource_id}/scopes", summary: "Define a scope on it." },
          { method: "PUT", path: "/api/v1/resources/{resource_id}/scopes/{scope_id}", summary: "Update a scope." },
          { method: "DELETE", path: "/api/v1/resources/{resource_id}/scopes/{scope_id}", summary: "Delete one." },
        ],
      },
      { type: "h", id: "design", text: "Designing a role model that survives" },
      {
        type: "list",
        items: [
          "**Grant to groups, not to users.** A per-user grant is invisible in every summary view and is the thing that outlives an employee's departure.",
          "**Grant high in the tree, refine low.** Enumerating leaves is a model that has to be maintained forever as the tree grows.",
          "**Use deny for carve-outs, and keep them narrow.** A deny cannot be undone by an allow, which is its value and its cost — you cannot express \"deny the subtree except this leaf\".",
          "**Name actions after what they permit, not after who does them.** `invoices:approve` survives a reorganisation; `finance-team-action` does not.",
          "**Prefer scopes to resource explosion.** If you are creating one resource per field, you probably want one resource with scopes.",
        ],
      },
    ],
  },

  {
    slug: "deny",
    section: "Authorization",
    navLabel: "Deny grants",
    title: "Deny grants & precedence",
    intro:
      "An explicit deny refuses regardless of what else allows it — at any depth of the hierarchy and at equal specificity. This page is the precedence table, and the reasoning behind choosing that rule.",
    blocks: [
      { type: "h", id: "rule", text: "The rule" },
      {
        type: "p",
        text: "A permission grant carries an `effect` of `allow` or `deny`. Evaluation is: **default deny → an applicable allow permits → an applicable deny refuses and beats every allow.**",
      },
      {
        type: "p",
        text: "Deny wins. Always. It is not *most specific wins*, and the difference is the whole design.",
      },
      { type: "h", id: "table", text: "Worked precedence table" },
      {
        type: "p",
        text: "Resources: `/fleet` → `/fleet/decommissioned` → `/fleet/decommissioned/unit-7`. Every check below is on the leaf.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Rules", "Check", "Result", "Why"],
        rows: [
          ["allow `read` on `/fleet`", "read", "**allow**", "An allow cascades to descendants."],
          ["*(nothing)*", "read", "**deny** (`no_grant`)", "Default deny."],
          [
            "allow `read` on `/fleet`, deny `read` on `/fleet/decommissioned`",
            "read",
            "**deny** (`denied_by_rule`)",
            "A deny cascades down and beats the ancestor allow.",
          ],
          [
            "deny `read` on `/fleet`, allow `read` on `/fleet/decommissioned`",
            "read",
            "**deny** (`denied_by_rule`)",
            "**A child allow does not override an inherited deny.** This is the row to read twice.",
          ],
          [
            "allow `read` on `/fleet`, deny `write` on `/fleet`",
            "read",
            "**allow**",
            "Denies are per action; `write` says nothing about `read`.",
          ],
          [
            "allow and deny of the same action on the same node",
            "read",
            "**deny** (`denied_by_rule`)",
            "Deny wins at equal specificity too — there is no tie to break.",
          ],
          [
            "allow via a directly assigned role, deny via a group-inherited role",
            "read",
            "**deny** (`denied_by_rule`)",
            "Denies inherit through groups exactly as allows do.",
          ],
          [
            "allow via a global role, deny on a resource-scoped role",
            "read",
            "**deny** (`denied_by_rule`)",
            "Global versus resource-scoped changes applicability, not precedence.",
          ],
        ],
      },
      { type: "h", id: "scopes", text: "Scope interaction" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Deny rule", "Effect"],
        rows: [
          [
            "deny `read`, **no scopes** (wildcard)",
            "Masks `read` entirely on that node and its descendants — every scope, and unscoped checks too.",
          ],
          [
            "deny `read`, scopes = [`pii`]",
            "Masks only `read` + `pii`. `read` + `billing` and unscoped `read` are unaffected.",
          ],
        ],
      },
      {
        type: "warn",
        text: "A resource-level deny is *stronger* than a scope-level one, because it matches every request for that action regardless of the scope named. If you meant to carve out one scope, say so — an empty scope list is a wildcard, not a default.",
      },
      { type: "h", id: "why", text: "Why deny-override and not most-specific-wins" },
      {
        type: "p",
        text: "Most-specific-wins reads as more expressive, and it is a security footgun. Under it the meaning of a deny depends on where every *other* rule sits, which produces three properties nobody wants:",
      },
      {
        type: "list",
        items: [
          "Adding an allow deeper in the tree silently re-opens something a deny closed.",
          "A reviewer cannot answer \"is X denied?\" by looking at the deny — they must enumerate every rule that might out-specify it.",
          "Moving a resource in the hierarchy can change access without any rule changing.",
        ],
      },
      {
        type: "p",
        text: "Deny-override buys one property that is worth more than the expressiveness: **adding a deny can never widen access, and can never be undone by adding allows.** That is checkable, and it is asserted as a property test rather than left as a claim.",
      },
      {
        type: "note",
        text: "The cost is real and worth stating: you cannot express \"deny the subtree, except this one leaf\". The answer is to narrow the deny, not to widen the allow.",
      },
      { type: "h", id: "using", text: "Using deny well" },
      {
        type: "list",
        items: [
          "**Reach for deny for carve-outs and containment**, not as the everyday tool. A model where most rules are denies is a model whose allows are too broad.",
          "**Keep each deny as narrow as the thing you are actually excluding** — the right action, the right scope, the lowest node that covers it.",
          "**Denies are excellent for incident response.** One deny on a compromised principal's role closes access across the whole tree immediately, and no allow anywhere can reopen it.",
          "**Expect surprise on row 4.** Somebody will eventually add an allow below a deny and file a bug. It is working correctly; that is the property.",
        ],
      },
    ],
  },

  {
    slug: "uma",
    section: "Authorization",
    navLabel: "UMA 2.0",
    title: "UMA 2.0 — protecting resources you do not own",
    intro:
      "A resource server describes what a request would require; AXIAM decides whether the requesting party may have it. The resource server never decides.",
    blocks: [
      { type: "h", id: "problem", text: "The problem it solves" },
      {
        type: "p",
        text: "A service guards resources it does not own. A caller arrives without the authority to touch them, and the service needs a way to say *what the caller would need* — precisely, and without becoming the authority itself.",
      },
      {
        type: "p",
        text: "User-Managed Access is that mechanism. The guarding service — the **resource server** — registers its resources, asks AXIAM to mint a **permission ticket** describing what a given request requires, and the ticket is exchanged for a **Requesting Party Token** (RPT) that says the authorization engine agreed.",
      },
      {
        type: "note",
        text: "The rule everything here serves: **the resource server never decides.** It describes what it needs; AXIAM decides, using the same RBAC check a live request would run. That is why a deny grant vetoes an RPT exactly as it vetoes anything else — it *is* the same check.",
      },
      { type: "h", id: "mapping", text: "What maps onto what" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["UMA", "AXIAM", "Note"],
        rows: [
          ["resource set `_id`", "the resource id", "**The same id** — there is no parallel resource store."],
          ["resource set `name` / `type`", "`resource.name` / `resource.resource_type`", ""],
          [
            "`resource_scopes`",
            "`Scope` rows on that resource",
            "The allow-list of names a resource server may ask for.",
          ],
          [
            "a resource scope, when evaluated",
            "the AXIAM **action**",
            "`view` on the resource, not a sub-resource scope.",
          ],
          ["PAT", "an access token with the `uma_protection` scope", "An ordinary client-credentials token."],
          [
            "RPT",
            "an access token with a `permissions` claim",
            "An ordinary token; the claim is what makes it an RPT.",
          ],
        ],
      },
      {
        type: "p",
        text: "A resource registered through UMA is an ordinary AXIAM resource. It appears in the admin console, role assignments cascade through it, and the engine already understands it. The only thing marking it as UMA-registered is a read-only provenance field.",
      },
      { type: "h", id: "endpoints", text: "The Protection API" },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/.well-known/uma2-configuration", summary: "Discovery — token, introspection, permission and registration endpoints.", public: true },
          { method: "GET", path: "/uma2/rreg/resource_set", summary: "List registered resource sets." },
          { method: "POST", path: "/uma2/rreg/resource_set", summary: "Register one." },
          { method: "GET", path: "/uma2/rreg/resource_set/{id}", summary: "Read one." },
          { method: "PUT", path: "/uma2/rreg/resource_set/{id}", summary: "Update it." },
          { method: "DELETE", path: "/uma2/rreg/resource_set/{id}", summary: "Deregister it." },
          { method: "POST", path: "/uma2/perm", summary: "Mint a permission ticket for a request that lacked authority." },
        ],
      },
      { type: "h", id: "flow", text: "The flow" },
      {
        type: "steps",
        steps: [
          {
            title: "Register the resource",
            body: "Once, at deployment or on first use. The resource server holds a PAT — an ordinary client-credentials token carrying the `uma_protection` scope.",
          },
          {
            title: "A caller arrives without authority",
            body: "The resource server does not guess and does not decide. It asks AXIAM for a permission ticket naming the resource and the scopes this request would need.",
            code: "POST /uma2/perm\n{ \"resource_id\": \"<id>\", \"resource_scopes\": [\"view\"] }",
          },
          {
            title: "Return the ticket to the caller",
            body: "As an RFC 7235 `WWW-Authenticate: UMA realm=..., as_uri=..., ticket=...` challenge — the standard way of saying \"here is what you would need, and here is who can grant it\".",
          },
          {
            title: "The caller exchanges the ticket for an RPT",
            body: "At the token endpoint, using the UMA ticket grant. AXIAM runs the ordinary RBAC check for that requesting party. A deny grant refuses here exactly as it would refuse a live request.",
          },
          {
            title: "The caller retries with the RPT",
            body: "The resource server validates it — introspection, or offline verification against the tenant JWKS — and reads the `permissions` claim.",
          },
        ],
      },
      {
        type: "note",
        text: "A `403` from the Protection API at `/uma2/*` is an ordinary authorization refusal and maps to an authorization error in the SDKs, not to an OAuth2 protocol error. A refusal from the ticket grant at the token endpoint is an OAuth2 protocol error and carries an `error` field to dispatch on — see [Error reference](#/docs/errors).",
      },
    ],
  },
];
