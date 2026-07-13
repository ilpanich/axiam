import { describe, it, expect } from "vitest";
import { router } from "@/router";

describe("router", () => {
  it("builds a non-empty routes array", () => {
    expect(Array.isArray(router.routes)).toBe(true);
    expect(router.routes.length).toBeGreaterThan(0);
  });

  it("registers expected top-level public paths", () => {
    const topLevelPaths = router.routes.map((r) => r.path);
    expect(topLevelPaths).toContain("/login");
    expect(topLevelPaths).toContain("/bootstrap");
    expect(topLevelPaths).toContain("/auth/forgot-password");
    expect(topLevelPaths).toContain("/auth/reset-password");
    expect(topLevelPaths).toContain("/auth/verify-email");
    expect(topLevelPaths).toContain("/auth/mfa-setup");
    expect(topLevelPaths).toContain("*");
  });

  it("registers the protected AppLayout root with nested children", () => {
    const root = router.routes.find((r) => r.path === "/");
    expect(root).toBeTruthy();
    expect(root?.children && root.children.length).toBeGreaterThan(0);

    const childPaths = (root?.children ?? []).flatMap((c) =>
      c.path ? [c.path] : (c.children ?? []).map((gc) => gc.path)
    );
    expect(childPaths).toContain("dashboard");
    expect(childPaths).toContain("users");
    expect(childPaths).toContain("organizations");
    expect(childPaths).toContain("audit-logs");
  });
});
