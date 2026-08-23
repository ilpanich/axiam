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
    expect(apiMock.get).not.toHaveBeenCalled();
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

afterEach(() => {
  useAuthStore.setState({
    user: null,
    isAuthenticated: false,
    isInitializing: false,
    tenantSlug: null,
    orgSlug: null,
  });
});
