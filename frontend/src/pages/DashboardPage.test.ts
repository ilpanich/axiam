import { describe, it, expect } from "vitest";
import { DASHBOARD_USER_COUNT_QUERY_KEY } from "@/lib/queryClient";

// D-18 regression guard: Dashboard's user-count probe query key must never
// structurally collide with UsersPage's ["users", page, search] key. A prior
// ["users", 1, ""] key was byte-for-byte identical to the page-1/no-filter
// UsersPage key, so navigating Dashboard <-> Users cross-contaminated the
// shared react-query cache (one page's response silently overwrote the
// other's cached data).
describe("DASHBOARD_USER_COUNT_QUERY_KEY", () => {
  it("shares the 'users' entity namespace with UsersPage's key", () => {
    expect(DASHBOARD_USER_COUNT_QUERY_KEY[0]).toBe("users");
  });

  it("does not collide with UsersPage's [users, page, search] key for any page/search value", () => {
    // UsersPage's key is always [entity, number, string] — simulate the
    // collision-prone page-1/no-filter case that previously matched.
    const usersPageKey = ["users", 1, ""] as const;

    // A real structural collision requires identical length AND identical
    // values at every index. The Dashboard key is shorter (length 2 vs 3)
    // and its second element is a string ("dashboard-count"), never a
    // number, so it can never equal any [users, page, search] tuple.
    expect(DASHBOARD_USER_COUNT_QUERY_KEY.length).not.toBe(usersPageKey.length);
    expect(typeof DASHBOARD_USER_COUNT_QUERY_KEY[1]).toBe("string");
    expect(DASHBOARD_USER_COUNT_QUERY_KEY).not.toEqual(usersPageKey);

    // Guard against every page number × common search value the collision
    // could historically occur at (page 1 with an empty search string was
    // the actual reported bug, D-18).
    for (const page of [1, 2, 3]) {
      for (const search of ["", "alice", "bob"]) {
        expect(DASHBOARD_USER_COUNT_QUERY_KEY).not.toEqual(["users", page, search]);
      }
    }
  });

  it("is a distinct, descriptive second segment (not a page number)", () => {
    expect(DASHBOARD_USER_COUNT_QUERY_KEY[1]).toBe("dashboard-count");
  });
});
