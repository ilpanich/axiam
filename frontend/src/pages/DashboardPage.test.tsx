import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

const navigate = vi.fn();
vi.mock("react-router-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router-dom")>();
  return { ...actual, useNavigate: () => navigate };
});

import { DashboardPage } from "./DashboardPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore } from "@/stores/auth";

const auditItems = [
  {
    id: "a1",
    tenant_id: "t1",
    actor_id: "admin",
    actor_type: "User",
    action: "user.created",
    resource_id: "u9",
    outcome: "Success",
    ip_address: "10.0.0.1",
    metadata: null,
    timestamp: "2026-07-01T10:00:00Z",
  },
  {
    id: "a2",
    tenant_id: "t1",
    actor_id: "bob",
    actor_type: "User",
    action: "user.login_failed",
    resource_id: null,
    outcome: "Failure",
    ip_address: null,
    metadata: null,
    timestamp: "2026-07-02T10:00:00Z",
  },
];

const certs = [
  {
    id: "c1",
    tenant_id: "t1",
    issuer_ca_id: "ca1",
    subject: "svc.active.far",
    public_cert_pem: "PEM",
    fingerprint: "fp1",
    cert_type: "Service",
    key_algorithm: "Rsa4096",
    not_before: "2020-01-01T00:00:00Z",
    not_after: "2099-01-01T00:00:00Z",
    status: "Active",
    metadata: null,
    created_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "c2",
    tenant_id: "t1",
    issuer_ca_id: "ca1",
    subject: "svc.expiring.soon",
    public_cert_pem: "PEM",
    fingerprint: "fp2",
    cert_type: "Service",
    key_algorithm: "Rsa4096",
    not_before: "2020-01-01T00:00:00Z",
    not_after: "2020-06-01T00:00:00Z",
    status: "Active",
    metadata: null,
    created_at: "2026-01-01T00:00:00Z",
  },
];

function routeGet(overrides: Record<string, unknown> = {}) {
  apiMock.get.mockImplementation((url: string) => {
    if (url.startsWith("/api/v1/users?"))
      return Promise.resolve(res(overrides.users ?? { items: [], total: 42, offset: 0, limit: 1 }));
    if (url.startsWith("/api/v1/audit-logs?"))
      return Promise.resolve(res(overrides.audit ?? { items: auditItems, total: 2, offset: 0, limit: 8 }));
    if (url === "/api/v1/groups") return Promise.resolve(res(overrides.groups ?? [{ id: "g1", name: "G1", created_at: "t" }, { id: "g2", name: "G2", created_at: "t" }]));
    if (url === "/api/v1/roles") return Promise.resolve(res(overrides.roles ?? [{ id: "r1", name: "R1", is_global: false, created_at: "t" }]));
    if (url === "/api/v1/certificates") return Promise.resolve(res(overrides.certs ?? certs));
    return Promise.resolve(res([]));
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  useAuthStore.setState({
    user: { id: "u1", username: "admin", email: "admin@x.io", permissions: ["*"], tenant_id: "t1" },
    isAuthenticated: true,
    isInitializing: false,
    tenantSlug: "acme",
    orgSlug: "org1",
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

describe("DashboardPage", () => {
  it("greets the user and shows the workspace slug", async () => {
    routeGet();
    renderWithProviders(<DashboardPage />);
    expect(await screen.findByText("admin")).toBeInTheDocument();
    expect(screen.getByText(/Welcome back/)).toBeInTheDocument();
    expect(screen.getByText("org1/acme")).toBeInTheDocument();
  });

  it("renders the stat card values from the queries", async () => {
    routeGet();
    renderWithProviders(<DashboardPage />);
    // Users total.
    expect(await screen.findByText("42")).toBeInTheDocument();
    // Groups length (2) and Roles length (1). Active certs count (2).
    expect(screen.getByText("Groups").closest(".glass-card")).toHaveTextContent("2");
    expect(screen.getByText("Roles").closest(".glass-card")).toHaveTextContent("1");
  });

  it("shows the certificate expiry warning for expiring active certs", async () => {
    routeGet();
    renderWithProviders(<DashboardPage />);
    expect(
      await screen.findByText("1 certificate expiring within 30 days")
    ).toBeInTheDocument();
    expect(screen.getByText("svc.expiring.soon")).toBeInTheDocument();
    expect(screen.getByText("1 expiring soon")).toBeInTheDocument();
  });

  it("renders recent activity entries", async () => {
    routeGet();
    renderWithProviders(<DashboardPage />);
    expect(await screen.findByText("user.created")).toBeInTheDocument();
    expect(screen.getByText("user.login_failed")).toBeInTheDocument();
  });

  it("shows the empty activity state when there are no logs", async () => {
    routeGet({ audit: { items: [], total: 0, offset: 0, limit: 8 } });
    renderWithProviders(<DashboardPage />);
    expect(await screen.findByText("No activity recorded yet.")).toBeInTheDocument();
  });

  it("navigates when a quick action is clicked", async () => {
    routeGet();
    renderWithProviders(<DashboardPage />);
    await screen.findByText("42");
    await userEvent.click(screen.getByRole("button", { name: "Create User" }));
    expect(navigate).toHaveBeenCalledWith("/users");
  });

  it("shows loading skeletons while the queries are pending", () => {
    apiMock.get.mockReturnValue(new Promise(() => {}));
    renderWithProviders(<DashboardPage />);
    expect(screen.getAllByLabelText("Loading").length).toBeGreaterThan(0);
  });
});
