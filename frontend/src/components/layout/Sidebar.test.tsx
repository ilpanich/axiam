import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { Sidebar } from "@/components/layout/Sidebar";
import { activeNavPath } from "@/components/layout/navSections";
import { useAuthStore, type AuthUser } from "@/stores/auth";

const superUser: AuthUser = {
  id: "u1",
  username: "admin",
  email: "a@x.io",
  permissions: ["*"],
  tenant_id: "t1",
};

const limitedUser: AuthUser = {
  id: "u2",
  username: "viewer",
  email: "v@x.io",
  permissions: ["users:list"],
  tenant_id: "t1",
};

beforeEach(() => {
  useAuthStore.setState({
    user: superUser,
    isAuthenticated: true,
    isInitializing: false,
    tenantSlug: null,
    orgSlug: null,
  });
});

function renderSidebar(path = "/dashboard", props: { mobile?: boolean; onClose?: () => void } = {}) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Sidebar {...props} />
    </MemoryRouter>
  );
}

describe("Sidebar", () => {
  it("renders all section titles and nav items", () => {
    renderSidebar();
    expect(screen.getByText("Overview")).toBeInTheDocument();
    expect(screen.getByText("Identity")).toBeInTheDocument();
    expect(screen.getByText("Infrastructure")).toBeInTheDocument();
    expect(screen.getByText("Developers")).toBeInTheDocument();
    expect(screen.getByText("Account")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Dashboard/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Users/ })).toBeInTheDocument();
    expect(screen.getByText("AXIAM")).toBeInTheDocument();
    expect(screen.getByText("AXIAM v1.0.0-beta09")).toBeInTheDocument();
  });

  it("marks the current route's link as active with aria-current", () => {
    renderSidebar("/users");
    const usersLink = screen.getByRole("link", { name: /Users/ });
    expect(usersLink).toHaveAttribute("aria-current", "page");
  });

  it("marks dashboard active only on exact match, not via startsWith", () => {
    renderSidebar("/dashboard");
    const dashboardLink = screen.getByRole("link", { name: /Dashboard/ });
    expect(dashboardLink).toHaveAttribute("aria-current", "page");
  });

  it("treats nested paths under a section as active via startsWith", () => {
    renderSidebar("/users/123");
    const usersLink = screen.getByRole("link", { name: /Users/ });
    expect(usersLink).toHaveAttribute("aria-current", "page");
  });

  it("disables nav items the user lacks permission for", () => {
    useAuthStore.setState({ user: limitedUser });
    renderSidebar("/dashboard");
    const orgsLink = screen.getByRole("link", { name: /Organizations/ });
    expect(orgsLink).toHaveAttribute("aria-disabled", "true");
    expect(orgsLink).toHaveAttribute("tabIndex", "-1");

    const usersLink = screen.getByRole("link", { name: /Users/ });
    expect(usersLink).not.toHaveAttribute("aria-disabled");
  });

  it("prevents navigation clicks on disabled items", async () => {
    useAuthStore.setState({ user: limitedUser });
    renderSidebar("/dashboard");
    const orgsLink = screen.getByRole("link", { name: /Organizations/ });
    await userEvent.click(orgsLink);
    // Still on dashboard — no crash, click was prevented.
    expect(screen.getByRole("link", { name: /Dashboard/ })).toHaveAttribute(
      "aria-current",
      "page"
    );
  });

  it("shows a close button and calls onClose when mobile and a nav link is clicked", async () => {
    const onClose = vi.fn();
    renderSidebar("/dashboard", { mobile: true, onClose });
    expect(screen.getByLabelText("Close navigation")).toBeInTheDocument();

    await userEvent.click(screen.getByLabelText("Close navigation"));
    expect(onClose).toHaveBeenCalledTimes(1);

    onClose.mockClear();
    await userEvent.click(screen.getByRole("link", { name: /Users/ }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("does not render a close button in desktop (non-mobile) mode", () => {
    renderSidebar("/dashboard");
    expect(screen.queryByLabelText("Close navigation")).not.toBeInTheDocument();
  });

  // ── Active-route matching ────────────────────────────────────────────────
  //
  // The bug: `location.pathname.startsWith(item.to)` decided this per item.
  // Tenant detail is routed as `/organizations/:orgId/tenants/:tenantId`, so
  // opening one from the Tenants list lit **Organizations** — the sidebar
  // disagreed with the page beside it.

  it("highlights Tenants — not Organizations — on a tenant detail page", () => {
    renderSidebar("/organizations/org-abc/tenants/tenant-xyz");

    expect(screen.getByRole("link", { name: /Tenants/ })).toHaveAttribute(
      "aria-current",
      "page"
    );
    expect(
      screen.getByRole("link", { name: /Organizations/ })
    ).not.toHaveAttribute("aria-current");
  });

  it("still highlights Organizations on an organization detail page", () => {
    renderSidebar("/organizations/org-abc");

    expect(
      screen.getByRole("link", { name: /Organizations/ })
    ).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: /Tenants/ })).not.toHaveAttribute(
      "aria-current"
    );
  });

  it("highlights exactly one entry for any route", () => {
    // Two entries lit at once is the other half of what per-item `startsWith`
    // allowed, and is just as wrong as the wrong one being lit.
    for (const path of [
      "/dashboard",
      "/users",
      "/users/u-1",
      "/roles/r-1",
      "/organizations",
      "/organizations/org-1",
      "/organizations/org-1/tenants/t-1",
      "/tenants",
      "/settings",
      "/settings/webauthn-attestation-policy",
      "/profile/change-password",
    ]) {
      const { unmount } = renderSidebar(path);
      const current = screen
        .getAllByRole("link")
        .filter((el) => el.getAttribute("aria-current") === "page");
      expect(current, `route ${path}`).toHaveLength(1);
      unmount();
    }
  });
});

describe("Sidebar — organization-level sections", () => {
  /**
   * `superUser` above holds `"*"`, which satisfies every permission check —
   * including `organizations:list` — and is exactly the principal that
   * exposed the defect: a tenant's own `super-admin` is granted the entire
   * permission registry and is still refused every organization-level action
   * by `handlers::org_scope`. So a wildcard is not enough to enable the
   * Organizations entry, and these say which principals are.
   */
  it("disables Organizations for a tenant principal holding the wildcard", () => {
    useAuthStore.setState({ user: { ...superUser, organization_level: false } });
    renderSidebar();
    expect(screen.getByRole("link", { name: /organizations/i })).toHaveAttribute(
      "aria-disabled",
      "true",
    );
  });

  it("enables Organizations for the organization's own administrator", () => {
    useAuthStore.setState({ user: { ...superUser, organization_level: true } });
    renderSidebar();
    expect(
      screen.getByRole("link", { name: /organizations/i }),
    ).not.toHaveAttribute("aria-disabled");
  });

  it("disables Organizations for an organization principal confined to tenants", () => {
    useAuthStore.setState({
      user: {
        ...superUser,
        organization_level: true,
        reachable_tenant_ids: ["t-a"],
      },
    });
    renderSidebar();
    expect(screen.getByRole("link", { name: /organizations/i })).toHaveAttribute(
      "aria-disabled",
      "true",
    );
  });

  it("leaves Tenants enabled for a tenant administrator", () => {
    // Deliberately NOT organization-gated: the roster the server returns is
    // filtered to the tenants the caller can act on, so a tenant administrator
    // sees its own tenant and can open it. Hiding the section would take away
    // a page that works.
    useAuthStore.setState({ user: { ...superUser, organization_level: false } });
    renderSidebar();
    expect(screen.getByRole("link", { name: /tenants/i })).not.toHaveAttribute(
      "aria-disabled",
    );
  });
});

describe("activeNavPath", () => {
  it("matches on path segments, not string prefixes", () => {
    // `startsWith` would have let `/tenants` claim this.
    expect(activeNavPath("/tenants-archive")).toBeNull();
    expect(activeNavPath("/tenants")).toBe("/tenants");
    expect(activeNavPath("/tenants/t-1")).toBe("/tenants");
  });

  it("resolves a route parameter in an alsoMatches pattern", () => {
    expect(activeNavPath("/organizations/org-1/tenants/t-1")).toBe("/tenants");
    expect(activeNavPath("/organizations/org-1/tenants")).toBe("/tenants");
  });

  it("prefers the more specific of two matching prefixes", () => {
    // Both `/organizations` and `/organizations/:orgId/tenants` match a tenant
    // detail path; the longer one has to win, and independently of the order
    // the sections happen to be declared in.
    expect(activeNavPath("/organizations/org-1/tenants/t-1")).toBe("/tenants");
    expect(activeNavPath("/organizations/org-1")).toBe("/organizations");
  });

  it("gives Dashboard nothing below itself", () => {
    // "/" redirects to /dashboard and Dashboard owns no sub-routes, so it must
    // never win by prefix the way every other entry can.
    expect(activeNavPath("/dashboard")).toBe("/dashboard");
    expect(activeNavPath("/dashboard/anything")).toBeNull();
  });

  it("returns null for a route no nav entry owns", () => {
    expect(activeNavPath("/auth/verify-email")).toBeNull();
  });
});
