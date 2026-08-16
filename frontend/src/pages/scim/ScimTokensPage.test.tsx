import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { ScimTokensPage } from "./ScimTokensPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore, type AuthUser } from "@/stores/auth";

const TOKENS_URL = "/api/v1/scim-tokens";

const tokens = [
  {
    id: "st1",
    tenant_id: "t1",
    user_id: "u-prov",
    name: "okta-production",
    created_by: "u-admin",
    status: "active",
    expires_at: "2027-01-01T00:00:00Z",
    last_used_at: "2026-08-16T10:00:00Z",
    revoked_at: null,
    created_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "st2",
    tenant_id: "t1",
    user_id: "u-prov",
    name: "entra-staging",
    created_by: "u-admin",
    status: "revoked",
    expires_at: "2027-01-01T00:00:00Z",
    last_used_at: null,
    revoked_at: "2026-06-01T00:00:00Z",
    created_at: "2026-01-01T00:00:00Z",
  },
];

const usersPage = {
  items: [
    {
      id: "u-prov",
      username: "scim-provisioner",
      email: "scim@example.com",
      status: "Active",
      created_at: "2026-01-01T00:00:00Z",
    },
  ],
  total: 1,
  offset: 0,
  limit: 200,
};

function asAdmin(
  permissions = ["scim_tokens:list", "scim_tokens:create", "scim_tokens:revoke"]
) {
  const u: AuthUser = {
    id: "u-admin",
    username: "admin",
    email: "admin@example.com",
    permissions,
    tenant_id: "t1",
  };
  useAuthStore.setState({ user: u, isAuthenticated: true, isInitializing: false });
}

/** The page reads tokens always, and users only once the dialog opens. */
function routeGet() {
  apiMock.get.mockImplementation((url: string) => {
    if (url === TOKENS_URL) return Promise.resolve(res(tokens));
    if (url.startsWith("/api/v1/users")) return Promise.resolve(res(usersPage));
    return Promise.resolve(res([]));
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  asAdmin();
});

describe("ScimTokensPage", () => {
  it("lists tokens with status and the user each authenticates as", async () => {
    routeGet();
    renderWithProviders(<ScimTokensPage />);

    expect(await screen.findByText("okta-production")).toBeInTheDocument();
    expect(screen.getByText("entra-staging")).toBeInTheDocument();
    expect(screen.getByText("active")).toBeInTheDocument();
    expect(screen.getByText("revoked")).toBeInTheDocument();
    // Never used reads as "Never" rather than a blank cell.
    expect(screen.getByText("Never")).toBeInTheDocument();
  });

  it("shows the empty state", async () => {
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<ScimTokensPage />);
    expect(
      await screen.findByText("No provisioning tokens yet.")
    ).toBeInTheDocument();
  });

  it("offers revoke only for an active token", async () => {
    routeGet();
    renderWithProviders(<ScimTokensPage />);

    expect(
      await screen.findByRole("button", { name: "Revoke okta-production" })
    ).toBeInTheDocument();
    // A revoked token has nothing left to revoke — the button would be a no-op.
    expect(
      screen.queryByRole("button", { name: "Revoke entra-staging" })
    ).not.toBeInTheDocument();
  });

  it("hides create and revoke controls without the permissions", async () => {
    asAdmin(["scim_tokens:list"]);
    routeGet();
    renderWithProviders(<ScimTokensPage />);

    expect(await screen.findByText("okta-production")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /New Token/ })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /^Revoke / })
    ).not.toBeInTheDocument();
  });

  it("mints a token and reveals the handle exactly once", async () => {
    routeGet();
    apiMock.post.mockResolvedValue(
      res({ ...tokens[0], provisioning_token: "axiam_scim_SECRETVALUE" })
    );
    renderWithProviders(<ScimTokensPage />);

    await userEvent.click(
      await screen.findByRole("button", { name: /New Token/ })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.type(
      within(dialog).getByLabelText("Name *"),
      "okta-production"
    );
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Authenticates As *"),
      "u-prov"
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(TOKENS_URL, {
        name: "okta-production",
        user_id: "u-prov",
        expires_in_days: 365,
      })
    );

    const reveal = await screen.findByRole("alertdialog");
    expect(
      within(reveal).getByText("axiam_scim_SECRETVALUE")
    ).toBeInTheDocument();
  });

  it("requires a bound user before submitting", async () => {
    routeGet();
    renderWithProviders(<ScimTokensPage />);

    await userEvent.click(
      await screen.findByRole("button", { name: /New Token/ })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "no-user");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    expect(
      await within(dialog).findByText(
        "Select the user this token will authenticate as."
      )
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("surfaces the server's refusal verbatim when the user lacks scim:provision", async () => {
    routeGet();
    // The backend message names the missing permission and the remedy; a
    // generic "failed to create" would throw that away.
    apiMock.post.mockRejectedValue({
      isAxiosError: true,
      response: {
        status: 400,
        // AXIAM's ErrorBody: `error` is a machine code, `message` is the human
        // sentence — see createErrorMessage for why the page prefers the latter.
        data: {
          error: "validation_error",
          message:
            "the named user does not hold scim:provision, so a token bound to them could not provision anything. Grant the permission first.",
        },
      },
    });
    renderWithProviders(<ScimTokensPage />);

    await userEvent.click(
      await screen.findByRole("button", { name: /New Token/ })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "bad");
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Authenticates As *"),
      "u-prov"
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    expect(
      await within(dialog).findByText(/does not hold scim:provision/)
    ).toBeInTheDocument();
  });

  it("revokes after confirmation", async () => {
    routeGet();
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<ScimTokensPage />);

    await userEvent.click(
      await screen.findByRole("button", { name: "Revoke okta-production" })
    );
    const confirm = await screen.findByRole("dialog");
    await userEvent.click(
      within(confirm).getByRole("button", { name: "Revoke" })
    );

    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith(`${TOKENS_URL}/st1`)
    );
  });
});
