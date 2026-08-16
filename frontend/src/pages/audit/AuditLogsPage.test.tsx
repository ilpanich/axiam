import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { AuditLogsPage } from "./AuditLogsPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore, type AuthUser } from "@/stores/auth";

const logs = [
  {
    id: "l1",
    tenant_id: "t1",
    actor_id: "admin",
    actor_type: "User",
    action: "user.created",
    resource_id: "u9",
    outcome: "Success",
    ip_address: "10.0.0.1",
    metadata: { key: "value" },
    timestamp: "2026-01-01T10:00:00Z",
  },
  {
    id: "l2",
    tenant_id: "t1",
    actor_id: "bob",
    actor_type: "User",
    action: "user.login_failed",
    resource_id: null,
    outcome: "Failure",
    ip_address: null,
    metadata: null,
    timestamp: "2026-01-02T10:00:00Z",
  },
];

function page(items: unknown[], total: number) {
  return { items, total, offset: 0, limit: 20 };
}

/** The System tab is gated on audit_logs:list_system. */
function asSystemAuditor(permissions = ["audit_logs:list", "audit_logs:list_system"]) {
  const u: AuthUser = {
    id: "admin",
    username: "admin",
    email: "admin@x.io",
    permissions,
    tenant_id: "t1",
  };
  useAuthStore.setState({ user: u, isAuthenticated: true, isInitializing: false });
}

beforeEach(() => {
  vi.clearAllMocks();
  useAuthStore.setState({
    user: null,
    isAuthenticated: false,
    isInitializing: false,
  });
});

describe("AuditLogsPage", () => {
  it("renders the fetched audit logs with outcome badges", async () => {
    apiMock.get.mockResolvedValue(res(page(logs, 2)));
    renderWithProviders(<AuditLogsPage />);
    expect(await screen.findByText("user.created")).toBeInTheDocument();
    expect(screen.getByText("user.login_failed")).toBeInTheDocument();
    // "Success"/"Failure" also appear as filter <option>s, so match all.
    expect(screen.getAllByText("Success").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Failure").length).toBeGreaterThan(0);
    expect(screen.getByText("admin")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.1")).toBeInTheDocument();
    // resource-less / ip-less row falls back to em-dashes.
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
  });

  it("shows the empty state and 'No records' when there are no logs", async () => {
    apiMock.get.mockResolvedValue(res(page([], 0)));
    renderWithProviders(<AuditLogsPage />);
    expect(await screen.findByText("No audit log entries found.")).toBeInTheDocument();
    expect(screen.getByText("No records")).toBeInTheDocument();
  });

  it("toggles the details expander for a row with metadata", async () => {
    apiMock.get.mockResolvedValue(res(page(logs, 2)));
    renderWithProviders(<AuditLogsPage />);
    await screen.findByText("user.created");
    const showBtn = screen.getByRole("button", { name: "Show" });
    await userEvent.click(showBtn);
    expect(await screen.findByText(/"key": "value"/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Hide" }));
    await waitFor(() =>
      expect(screen.queryByText(/"key": "value"/)).not.toBeInTheDocument()
    );
  });

  it("filters by outcome and requeries with the outcome param", async () => {
    apiMock.get.mockResolvedValue(res(page(logs, 2)));
    renderWithProviders(<AuditLogsPage />);
    await screen.findByText("user.created");
    await userEvent.selectOptions(screen.getByLabelText("Outcome"), "Failure");
    await waitFor(() =>
      expect(
        apiMock.get.mock.calls.some(([url]) => String(url).includes("outcome=Failure"))
      ).toBe(true)
    );
  });

  it("shows a Clear button when a filter is set and clears it", async () => {
    apiMock.get.mockResolvedValue(res(page(logs, 2)));
    renderWithProviders(<AuditLogsPage />);
    await screen.findByText("user.created");
    await userEvent.type(screen.getByLabelText("Actor"), "admin");
    await userEvent.type(screen.getByLabelText("Action"), "user");
    const clear = await screen.findByRole("button", { name: /Clear/ });
    await userEvent.click(clear);
    expect(screen.getByLabelText("Actor")).toHaveValue("");
    expect(screen.getByLabelText("Action")).toHaveValue("");
    expect(screen.queryByRole("button", { name: /Clear/ })).not.toBeInTheDocument();
  });

  it("debounces the actor filter into a requery with actor_id", async () => {
    apiMock.get.mockResolvedValue(res(page(logs, 2)));
    renderWithProviders(<AuditLogsPage />);
    await screen.findByText("user.created");
    await userEvent.type(screen.getByLabelText("Actor"), "bob");
    await waitFor(
      () =>
        expect(
          apiMock.get.mock.calls.some(([url]) => String(url).includes("actor_id=bob"))
        ).toBe(true),
      { timeout: 2000 }
    );
  });

  it("paginates to the next page and requeries with a new offset", async () => {
    apiMock.get.mockResolvedValue(res(page(logs, 45)));
    renderWithProviders(<AuditLogsPage />);
    await screen.findByText("user.created");
    expect(screen.getByText("Page 1 of 3 (45 total records)")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Previous page" })).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Next page" }));
    await waitFor(() =>
      expect(
        apiMock.get.mock.calls.some(([url]) => String(url).includes("offset=20"))
      ).toBe(true)
    );
    expect(await screen.findByText("Page 2 of 3 (45 total records)")).toBeInTheDocument();
    // Now Previous is enabled — go back to page 1.
    await userEvent.click(screen.getByRole("button", { name: "Previous page" }));
    expect(await screen.findByText("Page 1 of 3 (45 total records)")).toBeInTheDocument();
  });

  it("filters by action (debounced) and to-date and requeries", async () => {
    apiMock.get.mockResolvedValue(res(page(logs, 2)));
    renderWithProviders(<AuditLogsPage />);
    await screen.findByText("user.created");
    await userEvent.type(screen.getByLabelText("Action"), "user.created");
    await userEvent.type(screen.getByLabelText("To"), "2026-02-01");
    await waitFor(
      () =>
        expect(
          apiMock.get.mock.calls.some(
            ([url]) =>
              String(url).includes("action=user.created") &&
              String(url).includes("to=2026-02-01T23%3A59%3A59Z")
          )
        ).toBe(true),
      { timeout: 2000 }
    );
  });

  it("filters by the from-date and requeries with a full-day bound", async () => {
    apiMock.get.mockResolvedValue(res(page(logs, 2)));
    renderWithProviders(<AuditLogsPage />);
    await screen.findByText("user.created");
    const from = screen.getByLabelText("From");
    await userEvent.type(from, "2026-01-01");
    await waitFor(() =>
      expect(
        apiMock.get.mock.calls.some(([url]) =>
          String(url).includes("from=2026-01-01T00%3A00%3A00Z")
        )
      ).toBe(true)
    );
  });

  // ─── System trail ──────────────────────────────────────────────────────────

  it("hides the scope switch without audit_logs:list_system", async () => {
    apiMock.get.mockResolvedValue(res({ items: logs, total: 2, offset: 0, limit: 20 }));
    renderWithProviders(<AuditLogsPage />);
    await screen.findByText("user.created");
    expect(
      screen.queryByRole("tablist", { name: "Audit log scope" })
    ).not.toBeInTheDocument();
  });

  it("switches to the system endpoint and back", async () => {
    asSystemAuditor();
    apiMock.get.mockResolvedValue(res({ items: logs, total: 2, offset: 0, limit: 20 }));
    renderWithProviders(<AuditLogsPage />);

    await screen.findByText("user.created");
    expect(apiMock.get.mock.calls[0][0]).toContain("/api/v1/audit-logs?");

    await userEvent.click(screen.getByRole("tab", { name: "System" }));
    await waitFor(() =>
      expect(
        apiMock.get.mock.calls.some((c) =>
          (c[0] as string).startsWith("/api/v1/audit-logs/system?")
        )
      ).toBe(true)
    );
    // The description follows the scope, so the page never claims the system
    // trail is "performed in this tenant" — system entries carry no tenant.
    expect(
      screen.getByText(/unauthenticated and system requests/)
    ).toBeInTheDocument();

    await userEvent.click(screen.getByRole("tab", { name: "Tenant" }));
    await waitFor(() =>
      expect(screen.getByText(/performed in this tenant/)).toBeInTheDocument()
    );
  });

  it("resets to page 1 when the scope changes", async () => {
    asSystemAuditor();
    apiMock.get.mockResolvedValue(
      res({ items: logs, total: 100, offset: 0, limit: 20 })
    );
    renderWithProviders(<AuditLogsPage />);
    await screen.findByText("user.created");

    await userEvent.click(screen.getByRole("button", { name: /Next/i }));
    await waitFor(() =>
      expect(
        apiMock.get.mock.calls.some((c) => (c[0] as string).includes("offset=20"))
      ).toBe(true)
    );

    apiMock.get.mockClear();
    await userEvent.click(screen.getByRole("tab", { name: "System" }));

    // The two trails do not share a page count, so carrying offset=20 across
    // the switch would land the operator on a blank page.
    await waitFor(() => expect(apiMock.get).toHaveBeenCalled());
    expect(apiMock.get.mock.calls[0][0]).toContain(
      "/api/v1/audit-logs/system?offset=0"
    );
  });
});
