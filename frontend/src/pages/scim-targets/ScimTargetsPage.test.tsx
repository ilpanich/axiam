import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, fireEvent, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { ScimTargetsPage } from "./ScimTargetsPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore, type AuthUser } from "@/stores/auth";
import type { ScimTarget } from "@/services/scimTargets";

const TARGETS = "/api/v1/scim-targets";

const adminUser: AuthUser = {
  id: "u1",
  username: "admin",
  email: "a@x.io",
  permissions: ["*"],
  tenant_id: "t1",
  org_id: "org1",
  tenantSlug: "acme",
  orgSlug: "acme-org",
};

function as(...permissions: string[]) {
  useAuthStore.setState({ user: { ...adminUser, permissions } });
}

const emptyState = {
  last_success_at: null,
  last_failure_at: null,
  last_failure_reason: null,
  consecutive_failures: 0,
  dead_lettered_total: 0,
  last_reconciled_at: null,
};

function target(overrides: Partial<ScimTarget> = {}): ScimTarget {
  return {
    id: "s1",
    tenant_id: "t1",
    name: "HR system",
    base_url: "https://scim.example.com/scim/v2",
    enabled: true,
    auth: { type: "bearer" },
    scope: { type: "all_users" },
    push_groups: false,
    user_name_from: "username",
    deprovision: "deactivate",
    created_at: "2026-10-01T00:00:00Z",
    updated_at: "2026-10-01T00:00:00Z",
    state: {
      ...emptyState,
      last_success_at: "2026-10-04T10:00:00Z",
      last_reconciled_at: "2026-10-04T09:00:00Z",
    },
    ...overrides,
  };
}

const oauthTarget = target({
  id: "s2",
  name: "Okta",
  base_url: "https://okta.example.com/scim/v2",
  enabled: false,
  auth: {
    type: "oauth2_client_credentials",
    token_url: "https://okta.example.com/oauth/token",
    client_id: "axiam",
    scope: "scim",
  },
  scope: { type: "groups", group_ids: ["g1", "g2"] },
  state: {
    ...emptyState,
    consecutive_failures: 3,
    last_failure_reason: "downstream unavailable",
    dead_lettered_total: 2,
  },
});

const groups = [
  { id: "g1", name: "Engineering" },
  { id: "g2", name: "Operations" },
  { id: "g3", name: "Finance" },
];

function page<T>(items: T[]) {
  return res({ items, total: items.length, offset: 0, limit: 20 });
}

function mockGets(rows: ScimTarget[] = [target(), oauthTarget]) {
  apiMock.get.mockImplementation((url: string) => {
    if (url === TARGETS) return Promise.resolve(page(rows));
    if (url === "/api/v1/groups") return Promise.resolve(page(groups));
    return Promise.reject(new Error(`unexpected GET ${url}`));
  });
}

/** A credential value made at run time: no literal secret in the test source. */
function credentialValue() {
  return `c${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;
}

beforeEach(() => {
  vi.clearAllMocks();
  useAuthStore.setState({
    user: adminUser,
    tenantSlug: "acme",
    orgSlug: "acme-org",
    isAuthenticated: true,
    isInitializing: false,
  });
});

describe("ScimTargetsPage — list", () => {
  it("lists targets with their authentication, scope, status and delivery state", async () => {
    mockGets();
    renderWithProviders(<ScimTargetsPage />);
    expect(await screen.findByText("HR system")).toBeInTheDocument();
    expect(screen.getByText("https://scim.example.com/scim/v2")).toBeInTheDocument();
    expect(screen.getByText("Bearer token")).toBeInTheDocument();
    expect(screen.getByText("OAuth 2.0 client credentials")).toBeInTheDocument();
    expect(screen.getByText("All users")).toBeInTheDocument();
    expect(screen.getByText("2 groups")).toBeInTheDocument();
    // Enabled / disabled, and a failing, dead-lettering target.
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText("Inactive")).toBeInTheDocument();
    expect(
      screen.getByText(/Failing \(3 in a row: downstream unavailable\)/),
    ).toBeInTheDocument();
    expect(screen.getByText("2 dead-lettered")).toBeInTheDocument();
    // A target nothing has been delivered to says so.
    expect(screen.getAllByText("Never").length).toBeGreaterThan(0);
  });

  it("shows the empty state when there are no targets", async () => {
    mockGets([]);
    renderWithProviders(<ScimTargetsPage />);
    expect(await screen.findByText("No SCIM targets configured.")).toBeInTheDocument();
  });

  it("never renders a credential: none is on a row, in a dialog or in the DOM", async () => {
    mockGets();
    renderWithProviders(<ScimTargetsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit SCIM target HR system" }),
    );
    const dialog = screen.getByRole("dialog");
    const field = within(dialog).getByLabelText("Bearer token");
    expect(field).toHaveValue("");
    expect(field).toHaveAttribute("type", "password");
  });

  it("hides every write control from a reader", async () => {
    as("scim_targets:read");
    mockGets();
    renderWithProviders(<ScimTargetsPage />);
    expect(await screen.findByText("HR system")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /New SCIM target/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Edit SCIM target/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Delete SCIM target/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Reconcile now/ })).not.toBeInTheDocument();
  });
});

describe("ScimTargetsPage — create", () => {
  async function openCreate() {
    mockGets();
    renderWithProviders(<ScimTargetsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New SCIM target/ }));
    return screen.getByRole("dialog");
  }

  it("requires a name, a https URL and a credential before any request", async () => {
    const dialog = await openCreate();
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Bearer token is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();

    await userEvent.type(within(dialog).getByLabelText(/^Bearer token/), credentialValue());
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();

    await userEvent.type(within(dialog).getByLabelText("Name *"), "HR");
    await userEvent.type(within(dialog).getByLabelText("Base URL *"), "http://scim.example.com");
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Base URL must use https.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("creates a bearer target for every user, with the documented defaults", async () => {
    const dialog = await openCreate();
    apiMock.post.mockResolvedValue(res(target({ id: "s3" })));
    const secretValue = credentialValue();
    await userEvent.type(within(dialog).getByLabelText("Name *"), "HR system");
    await userEvent.type(
      within(dialog).getByLabelText("Base URL *"),
      "https://scim.example.com/scim/v2",
    );
    await userEvent.type(within(dialog).getByLabelText(/^Bearer token/), secretValue);
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(TARGETS, {
        name: "HR system",
        base_url: "https://scim.example.com/scim/v2",
        enabled: true,
        auth: { type: "bearer" },
        credential: secretValue,
        scope: { type: "all_users" },
        push_groups: false,
        user_name_from: "username",
        deprovision: "deactivate",
      }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("switches the auth kind to client credentials and asks for its fields", async () => {
    const dialog = await openCreate();
    apiMock.post.mockResolvedValue(res(oauthTarget));
    const secretValue = credentialValue();
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Authentication"),
      "oauth2_client_credentials",
    );
    expect(within(dialog).getByLabelText("Client secret *")).toBeInTheDocument();
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Okta");
    await userEvent.type(
      within(dialog).getByLabelText("Base URL *"),
      "https://okta.example.com/scim/v2",
    );
    // A token URL and a client id are required.
    await userEvent.type(within(dialog).getByLabelText("Client secret *"), secretValue);
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Token URL is required.")).toBeInTheDocument();
    await userEvent.type(
      within(dialog).getByLabelText("Token URL *"),
      "https://okta.example.com/oauth/token",
    );
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Client ID is required.")).toBeInTheDocument();
    await userEvent.type(within(dialog).getByLabelText("Client ID *"), "axiam");
    await userEvent.type(within(dialog).getByLabelText("Scope"), "scim");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        TARGETS,
        expect.objectContaining({
          auth: {
            type: "oauth2_client_credentials",
            token_url: "https://okta.example.com/oauth/token",
            client_id: "axiam",
            scope: "scim",
          },
          credential: secretValue,
        }),
      ),
    );
  });

  it("picks the groups in scope from the tenant's groups, and needs at least one", async () => {
    const dialog = await openCreate();
    apiMock.post.mockResolvedValue(res(oauthTarget));
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Scoped");
    await userEvent.type(
      within(dialog).getByLabelText("Base URL *"),
      "https://scim.example.com/scim/v2",
    );
    await userEvent.type(within(dialog).getByLabelText(/^Bearer token/), credentialValue());
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Users to provision"),
      "groups",
    );
    expect((await within(dialog).findAllByText("Select at least one group.")).length).toBeGreaterThan(0);
    fireEvent.submit(dialog.querySelector("form")!);
    expect(apiMock.post).not.toHaveBeenCalled();

    await userEvent.click(await within(dialog).findByRole("checkbox", { name: "Operations" }));
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "Engineering" }));
    await userEvent.click(within(dialog).getByLabelText("Push groups"));
    await userEvent.selectOptions(within(dialog).getByLabelText("Downstream userName"), "email");
    await userEvent.selectOptions(
      within(dialog).getByLabelText("When a user leaves scope"),
      "delete",
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        TARGETS,
        expect.objectContaining({
          scope: { type: "groups", group_ids: ["g2", "g1"] },
          push_groups: true,
          user_name_from: "email",
          deprovision: "delete",
        }),
      ),
    );
  });

  it("surfaces a server refusal inside the dialog", async () => {
    const dialog = await openCreate();
    apiMock.post.mockRejectedValue({
      response: {
        status: 400,
        data: { error: "validation_error", message: "base_url must not point to a non-public address" },
      },
    });
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Bad");
    await userEvent.type(
      within(dialog).getByLabelText("Base URL *"),
      "https://internal.example.com/scim",
    );
    await userEvent.type(within(dialog).getByLabelText(/^Bearer token/), credentialValue());
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(
      await screen.findByText("base_url must not point to a non-public address"),
    ).toBeInTheDocument();
  });
});

describe("ScimTargetsPage — edit", () => {
  async function openEdit(name = "HR system") {
    mockGets();
    renderWithProviders(<ScimTargetsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: `Edit SCIM target ${name}` }),
    );
    return screen.getByRole("dialog");
  }

  it("pre-fills the target, leaves the credential blank and optional, and omits it from the replacement", async () => {
    const dialog = await openEdit();
    apiMock.put.mockResolvedValue(res(target()));
    expect(within(dialog).getByLabelText("Name *")).toHaveValue("HR system");
    expect(within(dialog).getByLabelText("Base URL *")).toHaveValue(
      "https://scim.example.com/scim/v2",
    );
    const field = within(dialog).getByLabelText("Bearer token");
    expect(field).toHaveValue("");
    expect(field).toHaveAttribute("placeholder", "Leave blank to keep the stored credential");

    await userEvent.clear(within(dialog).getByLabelText("Name *"));
    await userEvent.type(within(dialog).getByLabelText("Name *"), "HR (renamed)");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    const [url, body] = apiMock.put.mock.calls[0];
    expect(url).toBe(`${TARGETS}/s1`);
    expect(body).not.toHaveProperty("credential");
    // The version the form was opened from travels with the replacement (T-416).
    expect(body).toHaveProperty("expected_updated_at", "2026-10-01T00:00:00Z");
    expect(body).toMatchObject({
      name: "HR (renamed)",
      base_url: "https://scim.example.com/scim/v2",
      auth: { type: "bearer" },
      scope: { type: "all_users" },
    });
  });

  it("requires the credential again when the base URL of a bearer target changes", async () => {
    const dialog = await openEdit();
    apiMock.put.mockResolvedValue(res(target()));
    await userEvent.clear(within(dialog).getByLabelText("Base URL *"));
    await userEvent.type(
      within(dialog).getByLabelText("Base URL *"),
      "https://other.example.com/scim/v2",
    );
    // The field turns required, with the reason.
    expect(within(dialog).getByLabelText("Bearer token *")).toBeInTheDocument();
    expect(
      within(dialog).getByText(/Changing the base URL sends the credential somewhere new/),
    ).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(
      await screen.findByText(/Changing the base URL requires the bearer token to be entered again/),
    ).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();

    const replacement = credentialValue();
    await userEvent.type(within(dialog).getByLabelText("Bearer token *"), replacement);
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    expect(apiMock.put.mock.calls[0][1]).toMatchObject({
      base_url: "https://other.example.com/scim/v2",
      credential: replacement,
    });
  });

  it("requires the secret again when a client-credentials target's base URL or token URL changes", async () => {
    const dialog = await openEdit("Okta");
    apiMock.put.mockResolvedValue(res(oauthTarget));
    // The base URL is where every access token the secret yields goes (T-409).
    await userEvent.clear(within(dialog).getByLabelText("Base URL *"));
    await userEvent.type(
      within(dialog).getByLabelText("Base URL *"),
      "https://okta2.example.com/scim/v2",
    );
    expect(within(dialog).getByLabelText("Client secret *")).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(
      await screen.findByText(/Changing the base URL requires the client secret to be entered again/),
    ).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
    // Back to the stored base URL: nothing is required again.
    await userEvent.clear(within(dialog).getByLabelText("Base URL *"));
    await userEvent.type(
      within(dialog).getByLabelText("Base URL *"),
      oauthTarget.base_url,
    );
    expect(within(dialog).getByLabelText("Client secret")).toBeInTheDocument();
    // The token URL is the secret's own destination.
    await userEvent.clear(within(dialog).getByLabelText("Token URL *"));
    await userEvent.type(
      within(dialog).getByLabelText("Token URL *"),
      "https://elsewhere.example.com/token",
    );
    expect(within(dialog).getByLabelText("Client secret *")).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(
      await screen.findByText(/Changing the token URL requires the client secret to be entered again/),
    ).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("requires the credential when the authentication kind is switched", async () => {
    const dialog = await openEdit();
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Authentication"),
      "oauth2_client_credentials",
    );
    expect(within(dialog).getByLabelText("Client secret *")).toBeInTheDocument();
    await userEvent.type(
      within(dialog).getByLabelText("Token URL *"),
      "https://idp.example.com/token",
    );
    await userEvent.type(within(dialog).getByLabelText("Client ID *"), "axiam");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(
      await screen.findByText(/Switching the authentication kind requires the client secret/),
    ).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("sends the updated_at the form was opened from as expected_updated_at", async () => {
    const dialog = await openEdit("Okta");
    apiMock.put.mockResolvedValue(res(oauthTarget));
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    expect(apiMock.put.mock.calls[0][1].expected_updated_at).toBe(oauthTarget.updated_at);
  });

  it("shows a conflict from an overtaken save inside the dialog", async () => {
    const dialog = await openEdit();
    apiMock.put.mockRejectedValue({
      response: {
        status: 409,
        data: {
          error: "conflict",
          message: "the SCIM target changed since it was read; read it again and retry",
        },
      },
    });
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(await screen.findByText(/changed since it was read/)).toBeInTheDocument();
  });
});

describe("ScimTargetsPage — delete and reconcile", () => {
  it("warns that deleting does not deprovision downstream, then deletes", async () => {
    mockGets();
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<ScimTargetsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Delete SCIM target HR system" }),
    );
    const dialog = screen.getByRole("dialog");
    expect(
      within(dialog).getByText(/does not deprovision anything downstream/),
    ).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(apiMock.delete).toHaveBeenCalledWith(`${TARGETS}/s1`));
  });

  it("starts a reconciliation and says so", async () => {
    mockGets();
    apiMock.post.mockResolvedValue(res({ target_id: "s1", status: "started" }));
    renderWithProviders(<ScimTargetsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Reconcile now HR system" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(`${TARGETS}/s1/reconcile`),
    );
    expect(
      await screen.findByText('Reconciliation of "HR system" started.'),
    ).toBeInTheDocument();
  });

  it("shows the server's 409 when a run already holds the claim", async () => {
    mockGets();
    apiMock.post.mockRejectedValue({
      response: {
        status: 409,
        data: {
          error: "conflict",
          message: "a reconciliation of this target is running or has only just finished",
        },
      },
    });
    renderWithProviders(<ScimTargetsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Reconcile now HR system" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/running or has only just finished/);
  });
});

describe("ScimTargetsPage — form behaviour and dismissal", () => {
  it("a group ticked by mistake can be unticked, and the target is created disabled when asked", async () => {
    mockGets();
    apiMock.post.mockResolvedValue(res(target({ id: "s7" })));
    renderWithProviders(<ScimTargetsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New SCIM target/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Scoped");
    await userEvent.type(
      within(dialog).getByLabelText("Base URL *"),
      "https://scim.example.com/scim/v2",
    );
    await userEvent.type(within(dialog).getByLabelText(/^Bearer token/), credentialValue());
    await userEvent.selectOptions(within(dialog).getByLabelText("Users to provision"), "groups");
    const finance = await within(dialog).findByRole("checkbox", { name: "Finance" });
    await userEvent.click(finance);
    expect(finance).toBeChecked();
    await userEvent.click(finance);
    expect(finance).not.toBeChecked();
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "Engineering" }));

    const enabled = within(dialog).getByLabelText("Enabled");
    expect(enabled).toBeChecked();
    await userEvent.click(enabled);
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    await waitFor(() => expect(apiMock.post).toHaveBeenCalledTimes(1));
    expect(apiMock.post.mock.calls[0][1]).toMatchObject({
      enabled: false,
      scope: { type: "groups", group_ids: ["g1"] },
    });
  });

  it("an edit that fails validation shows the problem in the dialog and sends nothing", async () => {
    mockGets();
    renderWithProviders(<ScimTargetsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit SCIM target HR system" }),
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.clear(within(dialog).getByLabelText("Name *"));
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await within(dialog).findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("Cancel on the create dialog discards the draft", async () => {
    mockGets();
    renderWithProviders(<ScimTargetsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New SCIM target/ }));
    await userEvent.type(
      within(screen.getByRole("dialog")).getByLabelText("Name *"),
      "abandoned",
    );
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /New SCIM target/ }));
    expect(within(screen.getByRole("dialog")).getByLabelText("Name *")).toHaveValue("");
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("Cancel on the edit and delete dialogs sends nothing", async () => {
    mockGets();
    renderWithProviders(<ScimTargetsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit SCIM target HR system" }),
    );
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Delete SCIM target HR system" }));
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
    expect(apiMock.delete).not.toHaveBeenCalled();
  });
});
