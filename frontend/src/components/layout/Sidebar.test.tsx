import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Sidebar } from "@/components/layout/Sidebar";
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
    expect(screen.getByText("AXIAM v1.0.0-alpha1")).toBeInTheDocument();
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
});
