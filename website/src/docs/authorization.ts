import type { DocPage } from "./types";
import { contractLink } from "../contractAnchors";
import { DOCS_VERIFIED_RELEASE } from "../version";

const GH_BLOB = "https://github.com/ilpanich/axiam/blob/main";

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
    verifiedRelease: DOCS_VERIFIED_RELEASE,
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
      { type: "h", id: "worked", text: "A worked resolution" },
      {
        type: "p",
        text: "One tree, one allow at the top, one deny partway down — and the answer at every node. This is the whole cascade in one example.",
      },
      {
        type: "code",
        caption: "the resource tree",
        code: "/fleet                              <- allow read  (role assigned here)\n├── /fleet/active\n│   └── /fleet/active/unit-3\n└── /fleet/decommissioned           <- deny read\n    └── /fleet/decommissioned/unit-7",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Check `read` on", "Answer", "Reason code", "Why"],
        rows: [
          ["/fleet", "allow", "`allowed`", "The grant is here."],
          ["/fleet/active", "allow", "`allowed`", "The allow cascades to a descendant."],
          ["/fleet/active/unit-3", "allow", "`allowed`", "Depth does not weaken a cascade."],
          [
            "/fleet/decommissioned",
            "deny",
            "`denied_by_rule`",
            "The deny is here, and it beats the allow it inherited from the parent.",
          ],
          [
            "/fleet/decommissioned/unit-7",
            "deny",
            "`denied_by_rule`",
            "The deny cascades too. A deny reaches every descendant exactly as an allow does.",
          ],
        ],
      },
      {
        type: "p",
        text: "Now add one more rule — an explicit allow of `read` on `/fleet/decommissioned/unit-7`, the deepest and most specific node — and ask again.",
      },
      {
        type: "warn",
        text: "The answer on that leaf is still **deny**. A child allow does not override an inherited deny, however specific the child is. This is the rule to internalise: **adding an allow can never re-open something a deny closed.** It is the property the design is built to guarantee, and it is asserted as a property test rather than left to convention.",
      },
      {
        type: "p",
        text: "The consequence for a role model is direct: you cannot express *deny the subtree except this one leaf*. The answer is to narrow the deny rather than to widen the allow — move it to the nodes you actually mean, or split the subtree. Full precedence, including how denies behave through groups and across global versus resource-scoped roles, is on [Deny grants](#/docs/deny).",
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
          { method: "POST", path: "/api/v1/roles/{role_id}/service-accounts", summary: "Assign the role to a service account." },
          { method: "DELETE", path: "/api/v1/roles/{role_id}/service-accounts/{service_account_id}", summary: "Unassign it." },
        ],
      },
      {
        type: "p",
        text: "How far an assignment reaches is a property of the assignment, not only of the role. Made in an ordinary tenant it reaches that tenant. Made in the organization's reserved scope it reaches **every** tenant of the organization if it is global, and only that scope if it names a resource — and the three assignment bodies above accept a `tenant_scope` list that confines it to named tenants instead. [Organization-level principals](#/docs/organization-scope) is the page for all of it.",
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
      { type: "h", id: "org-actions", text: "Actions a role cannot carry into a tenant" },
      {
        type: "p",
        text: "A handful of actions operate on the organization rather than on a tenant, and for those, holding the permission is not enough: the caller's own record must live in the organization scope. Creating, updating or deleting organizations and tenants, every CA operation — including the mTLS trust-anchor flag — and the FIDO metadata refresh are all refused to a principal that lives in an ordinary tenant, however its roles are written. The guard keys on where the principal lives, which is a row it cannot edit, and fails closed when that cannot be resolved.",
      },
      {
        type: "p",
        text: "The grant data agrees with the guard rather than contradicting it: an ordinary tenant's seeded `super-admin` and `admin` roles are created *without* those actions, and a boot-time reconciler revokes them where an earlier version granted them. `viewer` is unaffected by construction — it is seeded only with `:list` and `:get` actions, and every withheld action is a mutation. So a role listing in an ordinary tenant looks different after the upgrade, while nothing that used to work stops working: the guard was already refusing every one of these calls.",
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
    slug: "organization-scope",
    section: "Authorization",
    navLabel: "Organization scope",
    title: "Organization-level principals",
    intro:
      "One administrator for every tenant an organization will ever have — expressed as a claim the engine reads explicitly, never as an inference, and narrowable to named tenants.",
    verifiedRelease: DOCS_VERIFIED_RELEASE,
    blocks: [
      { type: "h", id: "two-levels", text: "Two levels of principal" },
      {
        type: "p",
        text: "A **tenant** principal belongs to one tenant. Its grants apply there and nowhere else — this is every user, group, role and service account AXIAM had before 1.0.0. An **organization** principal lives in the organization's own reserved tenant, and its *global* grants apply to every tenant in that organization, including tenants created long after the grant was written.",
      },
      {
        type: "p",
        text: "The super-admin created at bootstrap is an organization principal. That is what makes it an administrator of every tenant the organization ever has, without anybody writing a grant per tenant.",
      },
      {
        type: "note",
        text: "This exists because a newly created tenant used to be unreachable by everybody, the bootstrap super-admin included. Tenant creation seeded permissions and stopped there, while the engine filters every lookup by tenant — so the answer for the new tenant was `no roles assigned` for all callers. Deriving reach at check time fixes that for tenants that do not exist yet, which no amount of fanning out grants at creation time can.",
      },
      { type: "h", id: "reserved-tenant", text: "The organization scope is itself a tenant" },
      {
        type: "p",
        text: "Every organization has exactly one, created with the organization, flagged `kind: \"organization\"` and slugged `organization`. It is an ordinary tenant row in every other respect, and that is the point: organization-level users, groups, roles, permissions and service accounts are ordinary rows in it, evaluated by the same RBAC engine and audited the same way. Every isolation control that protects a tenant therefore protects it too.",
      },
      {
        type: "p",
        text: "You cannot create a second one — a marker row whose record id *is* the constraint prevents it, and `POST /api/v1/organizations/{org_id}/tenants` refuses the reserved slug. Uniqueness falls out of the existing indexes rather than needing a new rule: an organization-level `user1` is unique across the whole organization, while a tenant-level `user1` need only be unique within its tenant.",
      },
      {
        type: "p",
        text: "Living in the organization scope grants nothing by itself. An organization user with no roles is denied exactly like anyone else.",
      },
      { type: "h", id: "one-rule", text: "The one evaluation rule" },
      {
        type: "p",
        text: "When a subject's grants are read across a tenant boundary, **only global grants carry**.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Assignment", "Lives in", "Applies to"],
        rows: [
          ["Global (`is_global`, no resource)", "organization scope", "Every resource in every tenant of the organization"],
          ["Resource-scoped", "organization scope", "That resource, in the organization scope only"],
          ["Global", "an ordinary tenant", "Every resource in that tenant"],
          ["Resource-scoped", "an ordinary tenant", "That resource and its descendants"],
        ],
      },
      {
        type: "p",
        text: "A resource-scoped assignment names a resource id in the organization scope. No resource with that id exists in a member tenant, and one that happened to share a *name* would be an unrelated thing — carrying the assignment across would turn a narrow grant into a grant on something else entirely, across an isolation boundary.",
      },
      {
        type: "p",
        text: "Everything else is unchanged. Deny-override still wins at any depth, scopes still narrow, group membership still inherits. An organization principal acting on the organization scope itself is not crossing anything and gets ordinary resource-scoped evaluation there.",
      },
      {
        type: "note",
        text: "Cross-tenant reach is an explicit claim, never an inference. The engine reads a subject's grants across a tenant boundary only under a `SubjectScope` claim that an ordinary tenant principal cannot express at all, produced in exactly one place after resolving the tenant record and confirming it is the organization's reserved scope. Revoking an organization-level role sweeps the decision cache in *every* tenant, not only the one the revocation happened in.",
      },
      { type: "h", id: "org-actions", text: "Organization-level actions need an organization principal" },
      {
        type: "p",
        text: "A handful of actions operate on the organization rather than on a tenant, and holding the permission is not enough to perform them: the caller's own record must live in the organization scope. The guard keys on **where the principal lives** — a row it cannot edit — rather than on what its roles happen to carry, and fails closed when that cannot be resolved.",
      },
      {
        type: "list",
        items: [
          "`organizations:create`, `organizations:update`, `organizations:delete`",
          "`tenants:create`, `tenants:update`, `tenants:delete`",
          "`ca_certificates:generate`, `ca_certificates:revoke`, `ca_certificates:manage` — the last one covers the mTLS trust-anchor flag",
          "The FIDO metadata (MDS) refresh, whose trust store is deployment-global",
          "The organization's own email configuration (a tenant's own mail config stays a tenant administrator's job, so the *action* is not withheld — only the organization half is guarded)",
        ],
      },
      {
        type: "p",
        text: "The CA row is the one that matters most. A tenant administrator holding `ca_certificates:manage` could flag a CA as an mTLS trust anchor for the whole deployment and, with that CA's key, mint certificates authenticating as principals in sibling tenants. Two independent layers now stop it: the scope guard on the handler, and a single list — `axiam_core::permission_scope::ORGANIZATION_LEVEL_ACTIONS` — that withholds these actions from an ordinary tenant's seeded roles so the grant is not there to be relied on in the first place. A consistency test reads the handler sources to prove every withheld action is scope-guarded, rather than trusting a comment.",
      },
      {
        type: "warn",
        text: "**Upgrade note.** A boot-time reconciler revokes these actions from ordinary tenants' seeded `super-admin` and `admin` roles where an earlier version granted them. Nothing you could actually do stops working — the scope guard was already refusing every one of these calls — but the grants themselves disappear from those roles on first boot, so a role listing looks different afterwards. The `viewer` role is unaffected by construction: it is seeded only with `:list` and `:get` actions, and every action here is a mutation. Read actions are deliberately absent from both layers; the tenant switcher needs them and they leak nothing across the boundary.",
      },
      { type: "h", id: "tenant-scope", text: "Confining an account to named tenants" },
      {
        type: "p",
        text: "The rule above is all-or-nothing: an organization principal's global grants reach *every* tenant of the organization. That is right for the organization's own administrator and wrong for an operator who should administer two of your twelve tenants. A role assignment can therefore name the tenants it reaches.",
      },
      {
        type: "code",
        caption: "restricting an assignment to two tenants",
        code: 'POST /api/v1/roles/{role_id}/users\nContent-Type: application/json\n\n{\n  "user_id": "…",\n  "tenant_scope": ["<tenant-a>", "<tenant-b>"]\n}',
      },
      {
        type: "p",
        text: "The same field is accepted on the group and service-account assignment endpoints. Omit it and nothing changes — the assignment reaches wherever the role does, which is what every assignment written before this existed means and keeps meaning.",
      },
      {
        type: "p",
        text: "The rule is written once and enforced at every door a restricted account could reach through:",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Surface", "For a confined principal"],
        rows: [
          ["Any tenant-scoped action", "Allowed only in the named tenants — the engine drops the assignment everywhere else, on the single and the batch path alike"],
          ["Organization-level actions", "**Refused.** They name no tenant, so there is nothing to compare a scope against; the guard is explicit rather than derived"],
          ["A tenant's signing CA (`…/tenants/{tenant}/signing-cas`)", "Allowed when the reach covers *that* tenant — organization-level, but what it produces belongs to one tenant"],
          ["`GET /api/v1/organizations/{org}/tenants`", "Returns only the tenants in reach"],
          ["`X-Axiam-Tenant` naming another tenant", "`403` at the header, rather than a 403 on every request that follows"],
          ["`GET /api/v1/auth/me`", "`permissions` is computed for the tenant being acted on, and the `*` wildcard is **not** emitted"],
        ],
      },
      {
        type: "p",
        text: "\"Nowhere else\" includes the organization's own scope: an account confined to two tenants is not an organization-wide administrator, and letting its grants apply with no tenant selected would hand back exactly the reach the restriction removes. A confined operator signing in is therefore placed in the first tenant it reaches, and its tenant switcher lists only those tenants.",
      },
      {
        type: "note",
        text: "Reach is a property of the whole set. Holding one *unrestricted* assignment makes the principal unrestricted however many confined ones sit beside it — a tenant scope adds tenants, it cannot take any away from a grant that already reaches everywhere. Confining an account means every one of its assignments must name tenants; leaving the organization's `super-admin` on it beside a narrow role restricts nothing.",
      },
      {
        type: "p",
        text: "`GET /api/v1/auth/me` reports the result as `reachable_tenant_ids`: **absent** when the principal is unrestricted, a list when it is not. The login response deliberately omits the field — reach is a property of the session's current scope, not of the credential. A client that sees no field should read it as \"unrestricted\", which is also how it reads against a server older than contract 1.35.",
      },
      {
        type: "p",
        text: "Three requests are refused rather than silently accepted, each because accepting one would report a restriction that was not applied: `tenant_scope` on an assignment made in an ordinary tenant (the only tenant it could name is that tenant itself); an empty `tenant_scope` list (a grant that reaches nowhere is not a restriction, and is the hardest kind to debug); and a tenant belonging to another organization, or the organization's own scope.",
      },
      {
        type: "warn",
        text: "**Changing an assignment's reach is a revoke and a re-assign.** The `has_role` edge is created and deleted, never updated, so there is no \"edit scope\" control anywhere — unassign the grant and make it again with the tenants you want. Existing assignments are untouched by the migration that added the field: schema 51 is additive with no backfill, and an unrestricted grant stays unrestricted until an administrator narrows it.",
      },
      { type: "h", id: "signing-in", text: "Signing in, and acting on a tenant" },
      {
        type: "p",
        text: "The tenant is optional at login. Omitting it signs you in at organization level. A tenant user who omits the tenant is not found in the organization scope and gets the same enumeration-safe 401 as a wrong password — so a tenant user must name their tenant, and learns nothing by failing to. Password, OPAQUE and discoverable-passkey sign-in all resolve the organization scope the same way; nothing on those paths knows or cares which kind of tenant it is authenticating against. The login response carries `organization_level: true`.",
      },
      {
        type: "code",
        caption: "signing in at organization level, and then acting on a tenant",
        code: 'POST /api/v1/auth/login\n{ "org_slug": "acme", "username_or_email": "root", "password": "…" }\n\nGET /api/v1/users\nX-Axiam-Tenant: 0193f2a1-…      # any tenant in your organization',
      },
      {
        type: "p",
        text: "An organization principal switches tenant with the `X-Axiam-Tenant` header and **without signing in again** — it is already a principal of every tenant in its organization. The header is honoured only for a principal whose own tenant is the organization scope, and only for a tenant in that principal's own organization. Anything else is a 403 rather than a silent fallback, including a request made where no tenant resolver is configured, which fails closed. Without the header, an organization principal acts on the organization scope.",
      },
      {
        type: "warn",
        text: "The acting-tenant header is `X-Axiam-Tenant`. Contract versions before 1.36 named it `X-Tenant-ID`, which the server does not read — a client following that letter switched nothing and got a successful response describing its own tenant's data. `X-Tenant-ID` still exists and is deliberately *not* renamed: it is the unconditional constructor-tenant header, and renaming it would make it override the acting tenant on every request made after a switch.",
      },
      { type: "h", id: "own-account", text: "The caller's own account is not the acting tenant" },
      {
        type: "p",
        text: "`X-Axiam-Tenant` says which tenant a request **acts on**. It says nothing about where the caller *lives*, and for the caller's own record that second tenant is the one that matters. The rule: **a request about the caller's own record is scoped to the tenant the caller lives in, whatever the header says.** Everything else follows the header.",
      },
      {
        type: "list",
        items: [
          "`GET /api/v1/auth/me` — the account and its permission array",
          "`POST /api/v1/auth/password/change` — the password, and the OPAQUE record, live where the principal does",
          "`GET`/`PUT /api/v1/users/{id}` **for the caller's own id** — \"open my profile\" and \"save my profile\"",
          "The caller's own MFA methods, `POST /api/v1/auth/mfa/enroll` and `/confirm`, and `POST /api/v1/users/{id}/reset-mfa`",
          "`POST /api/v1/auth/webauthn/register/start` and `/finish` — including the attestation policy applied, which is the policy of the tenant the credential is stored in",
          "`POST /api/v1/users/me/resend-verification`",
          "The GDPR self-service endpoints (`/account/export`, `/account/delete`) for the caller's own id",
          "`GET /oauth2/userinfo` — the token subject's own",
        ],
      },
      {
        type: "p",
        text: "Reading the acting tenant for any of these has a distinctive symptom: an organization administrator selects a child tenant and, with nothing on screen changed but the tenant switcher, cannot open its own profile (404), cannot change its own password (404), sees an empty list of its own MFA methods, and cannot stay signed in (401). The rule is named once server-side rather than repeated per handler, and `GET /api/v1/auth/me` returns both tenants so a client can act on the distinction.",
      },
      {
        type: "code",
        caption: "GET /api/v1/auth/me, for an organization principal acting on a child tenant",
        code: '{\n  "user": {\n    "tenant_id": "…",             // the tenant being acted on\n    "principal_tenant_id": "…",   // the tenant this principal lives in\n    "principal_tenant_slug": "organization",\n    "org_id": "…",                // addressable directly, no lookup needed\n    "organization_level": true\n  },\n  "permissions": ["*"]\n}',
      },
      {
        type: "p",
        text: "`permissions` is the caller's effective actions in the scope it is acting on, and across a tenant boundary carries only global grants — mirroring the engine exactly. It is a UI hint; the server enforces every action independently. `org_id` is there so a client never has to call `GET /api/v1/organizations` to turn a slug into an id.",
      },
      { type: "h", id: "creating-tenants", text: "Creating a tenant, and giving it its first administrator" },
      {
        type: "p",
        text: "`POST /api/v1/organizations/{org_id}/tenants` seeds the new tenant's permissions **and** its default roles (`super-admin`, `admin`, `viewer`), so it is administrable immediately. It assigns those roles to nobody, deliberately: organization principals already reach the tenant by the rule above, so writing assignments at creation time would grant nothing new, would miss every organization principal created afterwards, and would have to be undone in every tenant to revoke.",
      },
      {
        type: "p",
        text: "Provisioning a tenant's first *tenant-level* administrator is three ordinary calls, all made from the organization session that just created the tenant:",
      },
      {
        type: "code",
        caption: "the new tenant's first administrator",
        code: 'POST /api/v1/users                 X-Axiam-Tenant: <new tenant>\nPUT  /api/v1/users/{id}            X-Axiam-Tenant: <new tenant>   # {"status":"Active"}\nPOST /api/v1/roles/{role}/users    X-Axiam-Tenant: <new tenant>   # role = super-admin',
      },
      { type: "h", id: "admin-ui", text: "In the admin console" },
      {
        type: "p",
        text: "Tenant switching is the top-right selector, listing **Organization** plus the organization's tenants. Switching takes effect immediately and in place: the page is unmounted, the cache for the tenant being left is dropped, `/auth/me` is re-read in the new scope and the page is mounted again. That pause — shown as *Switching tenant…* — is not cosmetic. It avoids rendering the previous tenant's rows under the new tenant's name, and avoids gating the page on the previous tenant's permission set, which would offer controls the server refuses and hide ones it allows. Anything typed into a form is discarded with it, deliberately: after a switch it refers to ids in a tenant nobody is looking at. The selected tenant persists per browser tab.",
      },
      {
        type: "p",
        text: "A tenant-level principal sees the same selector, but switching signs it out and back in, because for it the premise is false: a principal of one tenant is not a principal of another, and no server-side operation could make it one.",
      },
      {
        type: "p",
        text: "Every role-assignment dialog carries a **Tenants** picker beside the resource **Scope** one, in all three places an assignment can be made — from a role (*Assign User* / *Assign Group* / *Assign Service Account*), from a user (*Assign Role*) and from a group (*Assign Role*, which every member inherits). Leaving it empty means every tenant of the organization. The picker only offers tenants while you are administering the organization scope; an organization administrator who has switched into a tenant is told exactly that and pointed at the scope selector, rather than shown a control that vanished. An assignment that names tenants is badged with them rather than \"Organization-wide\", which for such a grant would be precisely wrong.",
      },
      { type: "h", id: "upgrading", text: "Upgrading an existing deployment" },
      {
        type: "p",
        text: "Migration 50 adds `kind`, defaulting to `standard` — every tenant you have is an ordinary tenant and reads back as one, and every grant keeps meaning what it meant. Migration 51 adds `tenant_scope` to the `has_role` edge, optional and with no backfill. The migration creates each organization's reserved scope and **moves nobody into it**: your users stay where they are with the access they have, and nothing about who can reach what changes on upgrade.",
      },
      {
        type: "p",
        text: "Promoting an existing administrator to organization level is therefore a deliberate act — create an account in the organization scope and assign it `super-admin` there. Relocating accounts between tenants is not something a version upgrade should decide on your behalf, and the deployment that most needs the promotion is exactly the one where a human should look at it first.",
      },
      {
        type: "links",
        links: [
          {
            label: "Organization-level users, roles and service accounts",
            href: `${GH_BLOB}/docs/admin/organization-scope.md`,
            note: "The normative admin guide — the full endpoint-by-endpoint table, what tenants inherit from the organization, and the OPAQUE `required` gate.",
          },
          {
            label: "CONTRACT §5.2 — organization-level principals",
            href: contractLink("5.2"),
            note: "What an SDK must do: §5.2.1 signing one in, §5.2.2 acting tenant vs principal tenant, §5.2.3 tenant-scoped assignments.",
          },
          {
            label: "Design note — why the organization scope is a tenant",
            href: `${GH_BLOB}/claude_dev/organization-scope-design.md`,
            note: "Why a reserved tenant rather than an `Option<Uuid>`, and why access is derived at check time rather than fanned out.",
          },
          {
            label: "Worked example — `examples/b6-organization-scope`",
            href: `${GH_BLOB}/examples/b6-organization-scope`,
            note: "The whole flow with assertions, from bootstrap to a new tenant's first administrator.",
          },
        ],
      },
      {
        type: "cards",
        cards: [
          {
            title: "Roles, permissions & resources",
            body: "The entities an organization-level grant is written over, and the API for each.",
            to: "docs",
            doc: "rbac",
          },
          {
            title: "The authorization engine",
            body: "How a decision is computed, and where the cross-tenant claim enters it.",
            to: "docs",
            doc: "authz",
          },
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
    verifiedRelease: DOCS_VERIFIED_RELEASE,
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
      {
        type: "links",
        links: [
          {
            label: "Deny-override design note",
            href: "https://github.com/ilpanich/axiam/blob/main/claude_dev/deny-override-design.md",
            note: "The full precedence table, the scope interaction, and why most-specific-wins was rejected.",
          },
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
