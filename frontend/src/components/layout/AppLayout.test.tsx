import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { AppLayout } from "@/components/layout/AppLayout";
import { useAuthStore, type AuthUser } from "@/stores/auth";
import { makeClient } from "@/test/renderWithProviders";

// Topbar (rendered inside AppLayout) imports the axios instance; provide a mock
// so it never reaches a real HTTP client.
const { apiMock } = vi.hoisted(() => ({
  apiMock: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
}));
vi.mock("@/lib/api", () => ({ default: apiMock }));

const superUser: AuthUser = {
  id: "u1",
  username: "admin",
  email: "admin@x.io",
  permissions: ["*"],
  tenant_id: "t1",
};

// AppLayout uses <Outlet/> and its Topbar child calls useMatches(), so it must
// be mounted inside a data router (createMemoryRouter/RouterProvider).
function renderLayout(initialPath = "/dashboard") {
  const client = makeClient();
  const router = createMemoryRouter(
    [
      {
        path: "/",
        element: <AppLayout />,
        children: [
          {
            path: "dashboard",
            handle: { crumb: "Dashboard" },
            element: <div>Dashboard body content</div>,
          },
        ],
      },
      { path: "/login", element: <div>Login screen</div> },
    ],
    { initialEntries: [initialPath] }
  );
  return render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  useAuthStore.setState({
    user: superUser,
    isAuthenticated: true,
    isInitializing: false,
    tenantSlug: null,
    orgSlug: null,
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

describe("AppLayout", () => {
  it("renders the routed outlet content along with the sidebar and topbar", () => {
    renderLayout();
    // Outlet child
    expect(screen.getByText("Dashboard body content")).toBeInTheDocument();
    // "AXIAM" branding appears in both the sidebar logo and the topbar
    // breadcrumb — at least one is present.
    expect(screen.getAllByText("AXIAM").length).toBeGreaterThan(0);
    // "Dashboard" appears both as the breadcrumb crumb (from the route handle)
    // and as the sidebar nav link label.
    expect(screen.getAllByText("Dashboard").length).toBeGreaterThan(0);
    // Sidebar landmark (an <aside> → complementary role, labelled).
    expect(
      screen.getByRole("complementary", { name: "Main navigation" })
    ).toBeInTheDocument();
    // Topbar hamburger
    expect(screen.getByLabelText("Open navigation menu")).toBeInTheDocument();
  });

  it("redirects to /login when the user is not authenticated", () => {
    useAuthStore.setState({ isAuthenticated: false, user: null });
    renderLayout();
    expect(screen.getByText("Login screen")).toBeInTheDocument();
    expect(screen.queryByText("Dashboard body content")).not.toBeInTheDocument();
  });

  it("opens the mobile sidebar drawer when the topbar menu button is clicked", async () => {
    renderLayout();
    expect(
      screen.queryByRole("dialog", { name: "Navigation menu" })
    ).not.toBeInTheDocument();

    await userEvent.click(screen.getByLabelText("Open navigation menu"));

    const drawer = screen.getByRole("dialog", { name: "Navigation menu" });
    expect(drawer).toBeInTheDocument();
    // The drawer hosts a mobile Sidebar with a Close button.
    expect(screen.getByLabelText("Close navigation")).toBeInTheDocument();
  });

  it("closes the mobile drawer when Escape is pressed", async () => {
    renderLayout();
    await userEvent.click(screen.getByLabelText("Open navigation menu"));
    expect(
      screen.getByRole("dialog", { name: "Navigation menu" })
    ).toBeInTheDocument();

    fireEvent.keyDown(document, { key: "Escape" });

    expect(
      screen.queryByRole("dialog", { name: "Navigation menu" })
    ).not.toBeInTheDocument();
  });

  it("closes the mobile drawer when the backdrop is clicked", async () => {
    renderLayout();
    await userEvent.click(screen.getByLabelText("Open navigation menu"));
    expect(
      screen.getByRole("dialog", { name: "Navigation menu" })
    ).toBeInTheDocument();

    const backdrop = document.querySelector(".fixed.inset-0.z-40");
    expect(backdrop).toBeTruthy();
    fireEvent.click(backdrop!);

    expect(
      screen.queryByRole("dialog", { name: "Navigation menu" })
    ).not.toBeInTheDocument();
  });
});
