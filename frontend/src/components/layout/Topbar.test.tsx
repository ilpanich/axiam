import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter } from "react-router";
import { RouterProvider } from "react-router/dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { Topbar } from "@/components/layout/Topbar";
import { useAuthStore, type AuthUser } from "@/stores/auth";
import { makeClient } from "@/test/renderWithProviders";
import { res } from "@/test/apiMock";

const { apiMock } = vi.hoisted(() => ({
  apiMock: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
}));

vi.mock("@/lib/api", () => ({ default: apiMock }));

const user: AuthUser = {
  id: "u1",
  username: "admin",
  email: "admin@x.io",
  permissions: ["*"],
  tenant_id: "t1",
};

function renderTopbar(
  onMenuClick: () => void = vi.fn(),
  opts: { initialPath?: string; routes?: unknown[] } = {}
) {
  const client = makeClient();
  const routes = opts.routes ?? [
    {
      path: "/organizations",
      handle: { crumb: "Organizations" },
      children: [
        {
          path: ":orgId",
          element: <Topbar onMenuClick={onMenuClick} />,
          handle: { crumb: "Organization Details" },
        },
      ],
    },
  ];
  const router = createMemoryRouter(routes as never, {
    initialEntries: [opts.initialPath ?? "/organizations/123"],
  });
  return render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  useAuthStore.setState({
    user,
    isAuthenticated: true,
    isInitializing: false,
    tenantSlug: null,
    orgSlug: null,
  });
});

describe("Topbar", () => {
  it("renders the breadcrumb trail built from route handles", () => {
    renderTopbar();
    expect(screen.getByText("AXIAM")).toBeInTheDocument();
    expect(screen.getByText("Organizations")).toBeInTheDocument();
    expect(screen.getByText("Organization Details")).toBeInTheDocument();
  });

  it("calls onMenuClick when the hamburger button is clicked", async () => {
    const onMenuClick = vi.fn();
    renderTopbar(onMenuClick);
    await userEvent.click(screen.getByLabelText("Open navigation menu"));
    expect(onMenuClick).toHaveBeenCalledTimes(1);
  });

  it("shows 'Select tenant' when no tenant context is set", () => {
    renderTopbar();
    expect(screen.getByText("Select tenant")).toBeInTheDocument();
  });

  it("shows org/tenant slugs when tenant context is set", () => {
    useAuthStore.setState({ tenantSlug: "acme", orgSlug: "org1" });
    renderTopbar();
    expect(screen.getByText("org1 / acme")).toBeInTheDocument();
  });

  it("shows the user's initial and username, falling back to 'U'/'User' when absent", () => {
    renderTopbar();
    expect(screen.getByText("A")).toBeInTheDocument();
    expect(screen.getByText("admin")).toBeInTheDocument();

    useAuthStore.setState({ user: null });
  });

  it("falls back to default avatar/label when there is no user", () => {
    useAuthStore.setState({ user: null });
    renderTopbar();
    expect(screen.getByText("U")).toBeInTheDocument();
    expect(screen.getByText("User")).toBeInTheDocument();
  });

  it("opens the tenant menu and closes the user menu when tenant button clicked", async () => {
    renderTopbar();
    await userEvent.click(screen.getByLabelText("User menu"));
    expect(screen.getByRole("menu", { name: "User menu" })).toBeInTheDocument();

    await userEvent.click(screen.getByText(/Select tenant/).closest("button")!);
    expect(screen.getByRole("menu", { name: "Tenant selector" })).toBeInTheDocument();
    expect(screen.queryByRole("menu", { name: "User menu" })).not.toBeInTheDocument();
  });

  // ─── Tenant switching ───────────────────────────────────────────────────────

  const orgs = [{ id: "o1", name: "AXIAM Corp", slug: "axiam-corp" }];
  const tenantRows = [
    { id: "t1", name: "Default", slug: "default", organization_id: "o1" },
    { id: "t2", name: "Research & Development", slug: "rd", organization_id: "o1" },
  ];

  /** Route the two GETs the switcher makes; anything else is empty. */
  function mockTenantLookup() {
    apiMock.get.mockImplementation((url: string) => {
      if (url === "/api/v1/organizations") return res({ items: orgs, total: 1 });
      if (url === "/api/v1/organizations/o1/tenants")
        return res({ items: tenantRows, total: tenantRows.length });
      return res({ items: [], total: 0 });
    });
  }

  it("lists the organization's tenants and marks the current one", async () => {
    useAuthStore.setState({ user, tenantSlug: "default", orgSlug: "axiam-corp" });
    mockTenantLookup();
    renderTopbar();

    await userEvent.click(
      screen.getByText(/axiam-corp \/ default/).closest("button")!
    );

    const current = await screen.findByRole("menuitem", { name: /Default/ });
    expect(current).toHaveAttribute("aria-current", "true");
    expect(
      screen.getByRole("menuitem", { name: /Research & Development/ })
    ).not.toHaveAttribute("aria-current");
  });

  it("signs out and hands the login page the target tenant", async () => {
    // A session is bound to one tenant and a user record belongs to one tenant,
    // so switching cannot re-scope the current session — it has to end it and
    // re-authenticate against the target. The pre-filled slugs are what keep
    // that from being a dead end.
    useAuthStore.setState({ user, tenantSlug: "default", orgSlug: "axiam-corp" });
    mockTenantLookup();
    apiMock.post.mockResolvedValue(res({}));
    renderTopbar();

    await userEvent.click(
      screen.getByText(/axiam-corp \/ default/).closest("button")!
    );
    await userEvent.click(
      await screen.findByRole("menuitem", { name: /Research & Development/ })
    );

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/logout")
    );
    await waitFor(() =>
      expect(useAuthStore.getState().isAuthenticated).toBe(false)
    );
  });

  it("picking the tenant you are already in just closes the menu", async () => {
    useAuthStore.setState({ user, tenantSlug: "default", orgSlug: "axiam-corp" });
    mockTenantLookup();
    apiMock.post.mockResolvedValue(res({}));
    renderTopbar();

    await userEvent.click(
      screen.getByText(/axiam-corp \/ default/).closest("button")!
    );
    await userEvent.click(await screen.findByRole("menuitem", { name: /Default/ }));

    await waitFor(() =>
      expect(
        screen.queryByRole("menu", { name: "Tenant selector" })
      ).not.toBeInTheDocument()
    );
    expect(apiMock.post).not.toHaveBeenCalled();
    expect(useAuthStore.getState().isAuthenticated).toBe(true);
  });

  it("says so plainly when no tenant is visible", async () => {
    useAuthStore.setState({ user, tenantSlug: "default", orgSlug: "axiam-corp" });
    apiMock.get.mockResolvedValue(res({ items: [], total: 0 }));
    renderTopbar();

    await userEvent.click(
      screen.getByText(/axiam-corp \/ default/).closest("button")!
    );
    expect(
      await screen.findByText(/No other tenant is visible to you/)
    ).toBeInTheDocument();
  });

  it("does not query tenants without the permissions to list them", async () => {
    useAuthStore.setState({
      user: { ...user, permissions: ["users:list"] },
      tenantSlug: "default",
      orgSlug: "axiam-corp",
    });
    mockTenantLookup();
    renderTopbar();

    await userEvent.click(
      screen.getByText(/axiam-corp \/ default/).closest("button")!
    );
    expect(
      await screen.findByText(/No other tenant is visible to you/)
    ).toBeInTheDocument();
    // The only read is the user menu's pending sign-in list, never a tenant lookup.
    for (const [url] of apiMock.get.mock.calls) {
      expect(url).toBe("/api/v1/ciba/requests");
    }
  });

  it("opens the user menu showing username/email and a sign-out option", async () => {
    renderTopbar();
    await userEvent.click(screen.getByLabelText("User menu"));
    const menu = screen.getByRole("menu", { name: "User menu" });
    expect(menu).toBeInTheDocument();
    expect(screen.getByText("admin@x.io")).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: /Sign out/ })).toBeInTheDocument();
  });

  it("closes open menus when Escape is pressed", async () => {
    renderTopbar();
    await userEvent.click(screen.getByLabelText("User menu"));
    expect(screen.getByRole("menu", { name: "User menu" })).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("menu", { name: "User menu" })).not.toBeInTheDocument();
  });

  it("closes open menus when the backdrop is clicked", async () => {
    renderTopbar();
    await userEvent.click(screen.getByLabelText("User menu"));
    expect(screen.getByRole("menu", { name: "User menu" })).toBeInTheDocument();
    const backdrop = document.querySelector(".fixed.inset-0.z-40");
    expect(backdrop).toBeTruthy();
    fireEvent.click(backdrop!);
    expect(screen.queryByRole("menu", { name: "User menu" })).not.toBeInTheDocument();
  });

  it("navigates the menu items with ArrowDown/ArrowUp/Home/End", async () => {
    renderTopbar();
    await userEvent.click(screen.getByLabelText("User menu"));
    const menu = screen.getByRole("menu", { name: "User menu" });
    const signOut = screen.getByRole("menuitem", { name: /Sign out/ });
    await waitFor(() => expect(document.activeElement).toBe(signOut));

    fireEvent.keyDown(menu, { key: "ArrowDown" });
    expect(document.activeElement).toBe(signOut);
    fireEvent.keyDown(menu, { key: "ArrowUp" });
    expect(document.activeElement).toBe(signOut);
    fireEvent.keyDown(menu, { key: "Home" });
    expect(document.activeElement).toBe(signOut);
    fireEvent.keyDown(menu, { key: "End" });
    expect(document.activeElement).toBe(signOut);
  });

  it("logs out successfully: posts to logout, clears query cache and auth, navigates to /login", async () => {
    apiMock.post.mockResolvedValue(res({}));
    renderTopbar(vi.fn(), {
      routes: [
        {
          path: "/organizations",
          handle: { crumb: "Organizations" },
          children: [
            {
              path: ":orgId",
              element: <Topbar onMenuClick={vi.fn()} />,
              handle: { crumb: "Organization Details" },
            },
          ],
        },
        { path: "/login", element: <div>Login screen</div> },
      ],
    });
    await userEvent.click(screen.getByLabelText("User menu"));
    await userEvent.click(screen.getByRole("menuitem", { name: /Sign out/ }));

    await waitFor(() => expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/logout"));
    await waitFor(() => expect(screen.getByText("Login screen")).toBeInTheDocument());
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });

  // ─── Pending sign-in requests (CIBA, D-74, #566) ────────────────────────────

  const pendingRequest = (id: string, name: string) => ({
    request_id: id,
    version: 0,
    client_id: "cc_1",
    client_name: name,
    scopes: ["openid"],
    binding_message: "W4SCT",
    requested_acr: [],
    step_up_required: null,
    expires_at: new Date(Date.now() + 5 * 60_000).toISOString(),
  });

  it("badges the user menu with the number of waiting sign-in requests", async () => {
    apiMock.get.mockResolvedValue(
      res({
        requests: [
          pendingRequest("0b7f3a52-6c1e-4f0a-9d63-1f2a3b4c5d6e", "Call Centre"),
          pendingRequest("1c8f4b63-7d2f-4a1b-8e74-2a3b4c5d6e7f", "Kiosk"),
        ],
      }),
    );
    renderTopbar();

    expect(await screen.findByTestId("pending-sign-ins-badge")).toHaveTextContent("2");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/ciba/requests", {
      params: { status: "pending" },
    });
    expect(
      screen.getByRole("button", { name: "User menu, 2 sign-in requests waiting" }),
    ).toBeInTheDocument();
  });

  it("shows no badge when nothing is waiting, or when the list is refused", async () => {
    apiMock.get.mockResolvedValue(res({ requests: [] }));
    const { unmount } = renderTopbar();
    await waitFor(() => expect(apiMock.get).toHaveBeenCalled());
    expect(screen.queryByTestId("pending-sign-ins-badge")).not.toBeInTheDocument();
    unmount();

    apiMock.get.mockRejectedValue(new Error("403"));
    renderTopbar();
    await waitFor(() => expect(apiMock.get).toHaveBeenCalledTimes(2));
    expect(screen.queryByTestId("pending-sign-ins-badge")).not.toBeInTheDocument();
    expect(screen.getByLabelText("User menu")).toBeInTheDocument();
  });

  it("lists the waiting requests in the menu and opens the approval page", async () => {
    const id = "0b7f3a52-6c1e-4f0a-9d63-1f2a3b4c5d6e";
    apiMock.get.mockResolvedValue(res({ requests: [pendingRequest(id, "Call Centre")] }));
    renderTopbar(vi.fn(), {
      routes: [
        {
          path: "/organizations/:orgId",
          element: <Topbar onMenuClick={vi.fn()} />,
        },
        { path: "/ciba/approve", element: <div>Approval page</div> },
      ],
    });
    await screen.findByTestId("pending-sign-ins-badge");
    await userEvent.click(screen.getByRole("button", { name: /^User menu/ }));
    await userEvent.click(screen.getByRole("menuitem", { name: /Call Centre/ }));

    expect(await screen.findByText("Approval page")).toBeInTheDocument();
  });

  it("still clears auth and navigates to /login even when the logout request fails", async () => {
    apiMock.post.mockRejectedValue(new Error("network down"));
    renderTopbar(vi.fn(), {
      routes: [
        {
          path: "/organizations",
          handle: { crumb: "Organizations" },
          children: [
            {
              path: ":orgId",
              element: <Topbar onMenuClick={vi.fn()} />,
              handle: { crumb: "Organization Details" },
            },
          ],
        },
        { path: "/login", element: <div>Login screen</div> },
      ],
    });
    await userEvent.click(screen.getByLabelText("User menu"));
    await userEvent.click(screen.getByRole("menuitem", { name: /Sign out/ }));

    await waitFor(() => expect(screen.getByText("Login screen")).toBeInTheDocument());
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });
});

describe("Topbar — organization-level tenant selector", () => {
  const orgUser: AuthUser = { ...user, organization_level: true };
  const tenantRows = [
    { id: "t1", name: "Default", slug: "default", organization_id: "o1" },
    { id: "t2", name: "Research", slug: "rd", organization_id: "o1" },
  ];

  function mockLookups() {
    apiMock.get.mockImplementation((url: string) => {
      if (url === "/api/v1/organizations")
        return res({ items: [{ id: "o1", name: "AXIAM Corp", slug: "axiam-corp" }], total: 1 });
      if (url === "/api/v1/organizations/o1/tenants")
        return res({ items: tenantRows, total: tenantRows.length });
      if (url === "/api/v1/auth/me")
        return res({
          user: { ...orgUser, id: "u1" },
          permissions: ["*"],
          tenant_slug: "rd",
          org_slug: "axiam-corp",
        });
      return res({ items: [], total: 0 });
    });
  }

  async function openMenu(label: RegExp) {
    await userEvent.click(screen.getByText(label).closest("button")!);
    return screen.findByRole("menu", { name: "Tenant selector" });
  }

  it("shows the organization scope as current, and switching to a tenant re-reads /auth/me", async () => {
    useAuthStore.setState({
      user: orgUser,
      orgSlug: "axiam-corp",
      activeTenantId: null,
      activeTenantName: null,
    });
    mockLookups();
    renderTopbar();

    await openMenu(/axiam-corp \/ Organization/);
    expect(await screen.findByRole("menuitem", { name: /Organization/ })).toHaveAttribute(
      "aria-current",
      "true",
    );

    await userEvent.click(await screen.findByRole("menuitem", { name: /Research/ }));

    await waitFor(() => expect(useAuthStore.getState().activeTenantId).toBe("t2"));
    expect(useAuthStore.getState().activeTenantName).toBe("Research");
    await waitFor(() => expect(apiMock.get).toHaveBeenCalledWith("/api/v1/auth/me"));
    await waitFor(() => expect(useAuthStore.getState().isSwitchingTenant).toBe(false));
    // The menu closed on selection.
    expect(screen.queryByRole("menu", { name: "Tenant selector" })).not.toBeInTheDocument();
  });

  it("returns to the organization scope from a tenant", async () => {
    useAuthStore.setState({
      user: orgUser,
      orgSlug: "axiam-corp",
      activeTenantId: "t2",
      activeTenantName: "Research",
    });
    mockLookups();
    renderTopbar();

    await openMenu(/axiam-corp \/ Research/);
    const research = await screen.findByRole("menuitem", { name: /Research/ });
    expect(research).toHaveAttribute("aria-current", "true");
    await userEvent.click(screen.getByRole("menuitem", { name: /^Organization/ }));

    await waitFor(() => expect(useAuthStore.getState().activeTenantId).toBeNull());
    await waitFor(() => expect(useAuthStore.getState().isSwitchingTenant).toBe(false));
  });

  it("does not offer the organization scope to a principal confined to particular tenants", async () => {
    useAuthStore.setState({
      user: { ...orgUser, reachable_tenant_ids: ["t2"] },
      orgSlug: "axiam-corp",
      activeTenantId: "t2",
      activeTenantName: "Research",
    });
    mockLookups();
    renderTopbar();

    await openMenu(/axiam-corp \/ Research/);
    await screen.findByRole("menuitem", { name: /Research/ });
    expect(screen.queryByRole("menuitem", { name: /^Organization/ })).not.toBeInTheDocument();
  });
});

afterEach(() => {
  useAuthStore.setState({
    user: null,
    activeTenantId: null,
    activeTenantName: null,
    isAuthenticated: false,
    isInitializing: false,
    tenantSlug: null,
    orgSlug: null,
  });
});
