/**
 * Which cached queries a change to one entity invalidates.
 *
 * # The problem this solves
 *
 * Every mutation in the admin UI used to invalidate its *own* query key and
 * stop there — `permissionService.remove` invalidated `["permissions"]`, and
 * nothing else. But `["role-permissions", roleId]` holds a copy of those same
 * permissions, and with `staleTime: 60_000` react-query has no reason to refetch
 * it. So: delete a permission, open a role that had it granted, and there it is,
 * listed as a live grant on a permission that no longer exists. The server was
 * right the whole time; the page was showing a minute-old answer.
 *
 * The same shape recurs everywhere two views hold the same rows — a role's
 * members and a user's roles, a group's members and the user list, a resource's
 * scopes and the grants constrained to them. Fixing them one mutation at a time
 * means every new page re-learns the lesson.
 *
 * # The shape of the fix
 *
 * One table, here, from an entity to the query-key roots that embed it. It is
 * deliberately a *static* table and not something derived at runtime: the
 * relationships are facts about the API, they change when someone adds an
 * endpoint, and a table you have to edit is one a reviewer can see is wrong.
 *
 * # Over- rather than under-invalidating
 *
 * Entries name key **roots**, and react-query matches key prefixes, so
 * `["role-permissions"]` invalidates that query for *every* role, not only the
 * one on screen. That is intentional. The alternative — working out exactly
 * which roles granted the deleted permission — needs data the client does not
 * have at deletion time, and getting it wrong reintroduces the bug. An
 * unnecessary refetch of a query nobody is watching costs nothing: react-query
 * only refetches keys with active observers, so in practice this refetches the
 * page the user is looking at and marks the rest stale.
 */

/**
 * Entity → the query-key roots a change to it invalidates, itself included.
 *
 * Read as: "when this changes, these views may be showing something stale".
 */
export const INVALIDATION_GRAPH: Record<string, readonly string[]> = {
  // A permission's action string and its very existence are copied into every
  // role's grant list.
  permissions: ["permissions", "role-permissions", "role"],

  // Deleting or renaming a role reaches its members, the groups it is assigned
  // to, and the permission summary shown beside it. `user` and `users` because
  // the user detail page lists the roles a user holds.
  roles: ["roles", "role", "role-permissions", "role-users", "role-groups", "group-roles", "user", "users"],

  // Grants are the edge between a role and a permission; both sides list them.
  // `roles` as well as `role`: the roles *list* shows a permission count
  // beside each row, so granting or revoking changes it too.
  "role-permissions": ["role-permissions", "role", "roles", "permissions"],

  // Membership edges: a user's roles and a role's users are the same fact from
  // two ends, and neither view can tell the other changed.
  "role-users": ["role-users", "role", "roles", "user", "users"],
  "role-groups": ["role-groups", "role", "roles", "group", "group-roles", "groups"],

  // A group's members appear on the group page and its roles on the user page.
  groups: ["groups", "group", "group-members", "group-roles", "role-groups", "user", "users"],
  "group-members": ["group-members", "group", "groups", "users", "user"],
  "group-roles": ["group-roles", "group", "groups", "role-groups", "role", "user"],

  // A user's own row is echoed in group membership and role assignment lists,
  // and in the picker `UserSearchDialog` caches under its own root — which is
  // how a freshly created user stayed unfindable in the "add a member" dialog
  // for up to `staleTime` after appearing in the list right behind it.
  users: [
    "users",
    "user",
    "group-members",
    "role-users",
    "currentUser",
    "user-search",
  ],

  // Scopes live under a resource, and a scoped grant names them by id — so a
  // deleted scope leaves a grant pointing at nothing until the grant list is
  // refetched.
  resources: ["resources", "scopes", "role-permissions", "role"],
  scopes: ["scopes", "resources", "role-permissions", "role"],

  // A certificate can be bound to a service account, which lists it.
  certificates: ["certificates", "service-accounts"],
  "service-accounts": ["service-accounts", "certificates"],
  "ca-certificates": ["ca-certificates", "certificates"],

  // A tenant belongs to an organization, whose detail page lists its tenants.
  //
  // Two other views hold the same list under their own roots and neither is a
  // page: the topbar's tenant switcher and the assignment-scope picker. Leaving
  // them out is what made "create a tenant, then switch to it" fail for a
  // minute — the tenant existed, the list on screen said so, and the switcher
  // was still answering from the copy it had fetched before the tenant did.
  tenants: [
    "tenants",
    "organizations",
    "topbar-tenants",
    "assignment-scope-tenants",
  ],
  organizations: [
    "organizations",
    "tenants",
    "ca-certificates",
    "topbar-tenants",
    "assignment-scope-tenants",
  ],

  // Settings cascade org → tenant, so an org change alters what a tenant
  // resolves to even though the tenant's own overrides did not move.
  "org-settings": ["org-settings", "settings", "tenant-settings-override", "system-settings"],
  settings: ["settings", "org-settings", "tenant-settings-override"],
  "tenant-settings-override": ["tenant-settings-override", "settings"],
  "org-email-config": ["org-email-config", "tenant-email-config"],

  // The compliance report is DERIVED from the attestation policy — it is the
  // server's verdict on whether the tenant's registered authenticators satisfy
  // it. Saving a policy without this left the verdict beside the form
  // contradicting the policy in it for up to `staleTime`.
  "webauthn-attestation-policy": [
    "webauthn-attestation-policy",
    "webauthn-compliance-report",
  ],

  // MFA state is shown both on the user's own profile and on their admin page.
  mfaMethods: ["mfaMethods", "user-mfa", "currentUser"],
  "user-mfa": ["user-mfa", "mfaMethods", "user"],
};

/**
 * The query-key roots to invalidate when `entity` changes.
 *
 * An entity with no entry in the graph invalidates only itself, which is the
 * behaviour every mutation had before this existed and is correct for anything
 * genuinely standalone (webhooks, reactors, audit logs).
 *
 * @example
 * ```ts
 * relatedQueryKeys("permissions");
 * // → ["permissions", "role-permissions", "role"]
 *
 * relatedQueryKeys("webhooks");
 * // → ["webhooks"]
 * ```
 */
export function relatedQueryKeys(entity: string): string[] {
  return [...(INVALIDATION_GRAPH[entity] ?? [entity])];
}

/** The subset of `QueryClient` this module needs, so tests need no real one. */
export interface InvalidatingClient {
  invalidateQueries(filters: { queryKey: unknown[] }): Promise<void> | void;
}

/**
 * Invalidate `entity` and everything the graph says embeds it.
 *
 * Pass the key root — `"permissions"`, not `["permissions", page]`. Prefix
 * matching takes care of the parameterised variants.
 *
 * @example
 * ```ts
 * // After deleting a permission: the role detail pages holding it as a grant
 * // are refetched too, instead of showing it for up to `staleTime` longer.
 * invalidateEntity(queryClient, "permissions");
 * ```
 */
export function invalidateEntity(
  client: InvalidatingClient,
  entity: string,
): void {
  for (const key of relatedQueryKeys(entity)) {
    void client.invalidateQueries({ queryKey: [key] });
  }
}

/**
 * Invalidate several entities at once, without invalidating any key twice.
 *
 * Mutations that touch two things — assigning a role to a group, binding a
 * certificate to a service account — would otherwise fire overlapping
 * invalidations for the keys the two graphs share.
 */
export function invalidateEntities(
  client: InvalidatingClient,
  entities: readonly string[],
): void {
  const seen = new Set<string>();
  for (const entity of entities) {
    for (const key of relatedQueryKeys(entity)) {
      if (!seen.has(key)) {
        seen.add(key);
        void client.invalidateQueries({ queryKey: [key] });
      }
    }
  }
}
