import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { EffectiveAccessPanel } from "./EffectiveAccessPanel";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore } from "@/stores/auth";
import type { Resource } from "@/services/resources";

function setUser(permissions: string[]) {
  useAuthStore.setState({
    user: { id: "u1", username: "admin", email: "a@x.io", permissions, tenant_id: "t1" },
    tenantSlug: "acme-tenant",
    orgSlug: "acme",
    isAuthenticated: true,
    isInitializing: false,
  });
}

function r(id: string, name: string, parent_id?: string): Resource {
  return { id, name, resource_type: "api", parent_id, created_at: "t" };
}

const resources: Resource[] = [
  r("root", "Root"),
  r("child1", "Child One", "root"),
  r("child2", "Child Two", "root"),
];

beforeEach(() => {
  vi.clearAllMocks();
  setUser([]);
});

describe("EffectiveAccessPanel", () => {
  it("prompts to select a resource when none is selected", () => {
    renderWithProviders(
      <EffectiveAccessPanel
        resources={resources}
        selectedResource={undefined}
        onDenyResourceIdsChange={vi.fn()}
      />
    );
    expect(
      screen.getByText("Select a resource in the tree to preview effective access for it.")
    ).toBeInTheDocument();
  });

  it("hides the subject picker without authz:check_as", () => {
    renderWithProviders(
      <EffectiveAccessPanel
        resources={resources}
        selectedResource={resources[0]}
        onDenyResourceIdsChange={vi.fn()}
      />
    );
    expect(screen.queryByRole("button", { name: /Choose user/ })).not.toBeInTheDocument();
    expect(screen.getByText(/preview your own effective access/)).toBeInTheDocument();
  });

  it("shows the subject picker with authz:check_as", () => {
    setUser(["authz:check_as"]);
    renderWithProviders(
      <EffectiveAccessPanel
        resources={resources}
        selectedResource={resources[0]}
        onDenyResourceIdsChange={vi.fn()}
      />
    );
    expect(screen.getByRole("button", { name: /Choose user/ })).toBeInTheDocument();
  });

  it("checks access for self and shows an Allow badge", async () => {
    apiMock.post.mockResolvedValue(
      res({ allowed: true, reason_code: "allowed" })
    );
    const onDenyChange = vi.fn();
    renderWithProviders(
      <EffectiveAccessPanel
        resources={resources}
        selectedResource={resources[0]}
        onDenyResourceIdsChange={onDenyChange}
      />
    );
    await userEvent.click(screen.getByRole("button", { name: "Check access" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/authz/check", {
        action: "read",
        resource_id: "root",
        scope: undefined,
        subject_id: undefined,
      })
    );
    expect(await screen.findByText("Allow")).toBeInTheDocument();
    expect(onDenyChange).toHaveBeenCalledWith(new Set());
  });

  it("shows a Deny badge and previews inheritance to descendants", async () => {
    apiMock.post.mockImplementation((url: string, body: unknown) => {
      if (url === "/api/v1/authz/check") {
        return Promise.resolve(
          res({ allowed: false, reason_code: "denied_by_rule", reason: "explicit deny" })
        );
      }
      if (url === "/api/v1/authz/check/batch") {
        const checks = (body as { checks: { resource_id: string }[] }).checks;
        return Promise.resolve(
          res({
            results: checks.map((c) => ({
              allowed: false,
              reason_code: c.resource_id === "child1" ? "denied_by_rule" : "no_grant",
            })),
          })
        );
      }
      return Promise.reject(new Error("unexpected url"));
    });
    const onDenyChange = vi.fn();
    renderWithProviders(
      <EffectiveAccessPanel
        resources={resources}
        selectedResource={resources[0]}
        onDenyResourceIdsChange={onDenyChange}
      />
    );
    await userEvent.click(screen.getByRole("button", { name: "Check access" }));
    expect(await screen.findByText("Deny")).toBeInTheDocument();
    await waitFor(() =>
      expect(onDenyChange).toHaveBeenCalledWith(new Set(["root", "child1"]))
    );
    expect(
      await screen.findByText(/This deny reaches 1 descendant resource/)
    ).toBeInTheDocument();
  });

  it("surfaces an error when the check fails", async () => {
    apiMock.post.mockRejectedValue(new Error("Forbidden"));
    renderWithProviders(
      <EffectiveAccessPanel
        resources={resources}
        selectedResource={resources[0]}
        onDenyResourceIdsChange={vi.fn()}
      />
    );
    await userEvent.click(screen.getByRole("button", { name: "Check access" }));
    expect(await screen.findByText("Forbidden")).toBeInTheDocument();
  });
});
