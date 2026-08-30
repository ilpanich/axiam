# Keeping the admin UI's cache honest about which tenant it is showing

Every list in the admin UI is tenant-scoped. Almost none of the ~45 react-query
keys say so.

`["users", 1, ""]` does not mean "page 1 of the users". It means "page 1 of the
users of whichever tenant `X-Axiam-Tenant` named at the moment the request went
out" — and for an organization-level principal that tenant changes whenever
somebody uses the switcher in the top-right corner. The key records the page and
the search term. It records nothing about the thing that changes the answer
completely.

This document is what was done about that, and why the obvious fix was not one.

## The bug, precisely

The switch used to be four lines:

```ts
selectTenant(tenantId, tenantName);   // move the header
queryClient.clear();                  // drop the old tenant's data
const refreshed = await fetchCurrentUser();
if (refreshed) setUser(refreshed);
```

`queryClient.clear()` does not do what it reads as. In query-core it is:

```js
clear() { this.getAll().forEach((query) => this.remove(query)); }
remove(query) { query.destroy(); this.#queries.delete(query.queryHash); … }
```

`destroy()` cancels the in-flight retryer. It does **not** detach observers, and
`remove` does not tell a mounted `QueryObserver` to go and fetch again. So the
component that was on screen when the operator switched keeps its reference to a
`Query` that is no longer in the cache, keeps rendering `state.data`, and never
refetches — because from its point of view nothing happened.

The result is the single worst thing a multi-tenant admin console can do: one
tenant's rows, displayed under another tenant's name, with no error anywhere.

Two smaller problems rode along with it:

* **Stale permissions.** The permission array `/auth/me` returns is computed for
  the tenant being *acted on*. Between the header moving and the re-read
  landing, any page still mounted gates on the previous tenant's permissions
  while its requests go to the new tenant — offering controls the server will
  refuse and hiding ones it will allow.
* **Stale page-local state.** A half-filled form, a selected row, an open dialog
  holding an id. After a switch every one of those refers to a tenant nobody is
  looking at.

## The fix, in three parts

### 1. The cache is namespaced by the acting tenant

`lib/queryClient.ts` sets a `queryKeyHashFn`:

```ts
export function tenantScopedQueryKeyHash(queryKey: readonly unknown[]): string {
  return hashKey([getActiveTenant() ?? OWN_SCOPE_CACHE_SLOT, ...queryKey]);
}
```

One tenant's `["users", 1, ""]` and another's are now different cache entries.
No amount of forgetting to invalidate can put one on screen under the other.

This does not break invalidation. `invalidateQueries` and friends match on the
key **array** (`partialMatchKey`), not on the hash, so
`invalidateQueries({ queryKey: ["users"] })` still matches every page of every
tenant exactly as before. Only cache *identity* changes.

It is also not, by itself, enough — see part 3.

### 2. The switch is a visible, ordered operation

`hooks/useTenantSwitch.ts` raises `isSwitchingTenant`, which makes `AppLayout`
render *Switching tenant…* in place of the routed subtree. That unmounts every
page, taking its query observers and its local state with it. Only then does the
header move, the cache empty, and `/auth/me` get re-read; the flag comes down in
a `finally`, so a failed re-read leaves the app usable rather than stuck on a
spinner.

Emptying the cache is not what makes the result correct — part 1 already
guarantees that. It is a data-hygiene choice: an IAM console should not go on
holding one tenant's users, roles and audit rows in memory while an operator
works in another. The cost is that switching back re-fetches.

### 3. The routed subtree is keyed by the acting tenant

```tsx
<div key={activeTenantId ?? OWN_SCOPE_CACHE_SLOT}>
  <Outlet />
</div>
```

This is the part that turns the namespace into an actual fetch. A mounted
`QueryObserver` keeps the key — and therefore the cache entry — it was created
with; re-rendering it under a new tenant changes nothing. Only a fresh mount
computes the namespace again, misses, and fetches.

`AppLayout.test.tsx` counts mounts rather than asserting on rendered output,
because "did this remount" is not otherwise observable from outside, and a test
that checked the rendered rows instead would pass for a component that merely
re-rendered.

## The other half: views nothing invalidates

Namespacing fixes *cross-tenant* staleness. Within one tenant, staleness is the
job of `lib/queryInvalidation.ts`'s `INVALIDATION_GRAPH`, which maps an entity
to the query-key roots that embed it.

The graph had a blind spot of its own, with the same shape as the one above: a
cached view held under a root that **no entry named at all**. The tenant
switcher's `["topbar-tenants", orgSlug]` was one. Creating a tenant invalidated
`["tenants"]` and `["organizations"]`, the page refreshed, and the switcher went
on answering from the copy it had fetched before the tenant existed — so the
obvious next action, switching into the tenant you had just made, was impossible
for up to the 60-second stale time.

That failure is invisible from any single file: the page invalidates correctly,
the switcher fetches correctly, and the missing edge between them exists in
neither. `lib/queryInvalidationCoverage.test.ts` walks the whole source tree and
asserts that every query-key root is either reachable from the graph or listed
as standalone with a written reason. It also asserts the standalone list contains
nothing stale, so the exemptions cannot quietly rot into a blanket suppression.

## Related: a request path is a string

`src/test/apiRoutes.test.ts` is a sibling gate in the same spirit, and exists
because the OAuth2 Clients page shipped a release asking for an `/oauth2/…`
sub-path that is not a route. Every load answered 404, and because the page
renders an empty table for an empty result, it looked like a tenant with no
OAuth2 clients.

Nothing could catch it. The page's own tests mock `api.get` to resolve for any
URL — correct for a component test, and exactly why a component test cannot
notice. The type system cannot help: a request path is a string.

So the test checks the one thing neither can: that the set of paths the client
asks for is a subset of the set `sdks/openapi.json` says the server serves.
