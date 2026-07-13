import { describe, it, expect, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import { useAuthStore, type AuthUser } from "@/stores/auth";

const user: AuthUser = {
  id: "u1",
  username: "a",
  email: "a@x.io",
  permissions: ["users:read"],
  tenant_id: "t1",
};

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/login" element={<div>Login screen</div>} />
        <Route element={<ProtectedRoute permission="users:read" />}>
          <Route path="/users" element={<div>Users screen</div>} />
        </Route>
      </Routes>
    </MemoryRouter>
  );
}

beforeEach(() => {
  useAuthStore.setState({
    user: null,
    isAuthenticated: false,
    isInitializing: false,
  });
});

describe("ProtectedRoute", () => {
  it("redirects unauthenticated users to /login", () => {
    renderAt("/users");
    expect(screen.getByText("Login screen")).toBeInTheDocument();
  });

  it("renders nothing while auth is still initializing", () => {
    useAuthStore.setState({ isAuthenticated: true, isInitializing: true });
    const { container } = renderAt("/users");
    expect(container.textContent).toBe("");
  });

  it("renders ForbiddenPage when the permission is missing", () => {
    useAuthStore.setState({
      user: { ...user, permissions: [] },
      isAuthenticated: true,
      isInitializing: false,
    });
    renderAt("/users");
    expect(screen.getByText("Access Denied")).toBeInTheDocument();
  });

  it("renders the child route when permitted", () => {
    useAuthStore.setState({ user, isAuthenticated: true, isInitializing: false });
    renderAt("/users");
    expect(screen.getByText("Users screen")).toBeInTheDocument();
  });
});
