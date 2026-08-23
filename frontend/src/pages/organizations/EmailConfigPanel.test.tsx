import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import {
  OrgEmailConfigPanel,
  TenantEmailConfigPanel,
} from "./EmailConfigPanel";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore, type AuthUser } from "@/stores/auth";

const admin: AuthUser = {
  id: "u1",
  username: "admin",
  email: "admin@example.com",
  permissions: ["email_config:read", "email_config:write"],
  tenant_id: "t1",
};

const orgConfig = {
  id: "e1",
  scope: "Organization",
  scope_id: "o1",
  enabled: true,
  from_name: "Example Identity",
  from_email: "no-reply@example.com",
  reply_to: null,
  provider: {
    kind: "smtp",
    host: "smtp.example.com",
    port: 587,
    username: "mailer",
    starttls: true,
  },
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

beforeEach(() => {
  vi.clearAllMocks();
  useAuthStore.setState({
    user: admin,
    isAuthenticated: true,
    isInitializing: false,
  });
});

describe("OrgEmailConfigPanel", () => {
  it("pre-fills the stored configuration, but never the secret", async () => {
    apiMock.get.mockResolvedValue(res(orgConfig));
    renderWithProviders(<OrgEmailConfigPanel orgId="o1" />);

    expect(await screen.findByLabelText("From Name *")).toHaveValue(
      "Example Identity"
    );
    expect(screen.getByLabelText("From Address *")).toHaveValue(
      "no-reply@example.com"
    );
    expect(screen.getByLabelText("SMTP Host *")).toHaveValue(
      "smtp.example.com"
    );
    expect(screen.getByLabelText("Port *")).toHaveValue(587);
    // The backend marks the password `skip_serializing`, so there is nothing
    // to pre-fill and the field must stay blank rather than show a fake value.
    expect(screen.getByLabelText("Password")).toHaveValue("");
  });

  it("tells the operator when no configuration exists yet", async () => {
    apiMock.get.mockRejectedValue({ response: { status: 404 } });
    renderWithProviders(<OrgEmailConfigPanel orgId="o1" />);
    expect(
      await screen.findByText(/No email configuration is set/)
    ).toBeInTheDocument();
  });

  it("refuses to render an editable form when the config fails to load", async () => {
    apiMock.get.mockRejectedValue(new Error("gateway timeout"));
    renderWithProviders(<OrgEmailConfigPanel orgId="o1" />);

    // A blank form here would read as "not configured" and a save from it
    // would replace a live config the panel never managed to show.
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /Could not load the email configuration/
    );
    expect(
      screen.queryByRole("button", { name: "Save Configuration" })
    ).not.toBeInTheDocument();
  });

  it("stops promising a stored secret after the provider kind changes", async () => {
    apiMock.get.mockResolvedValue(res(orgConfig));
    renderWithProviders(<OrgEmailConfigPanel orgId="o1" />);

    expect(
      await screen.findByText(/A secret is already stored/)
    ).toBeInTheDocument();

    await userEvent.selectOptions(screen.getByLabelText("Provider"), "send_grid");

    // There is no stored SendGrid key, so a blank field would store an empty
    // secret rather than preserve anything.
    expect(screen.queryByText(/A secret is already stored/)).not.toBeInTheDocument();
    expect(screen.getByText(/never returned by the API/)).toBeInTheDocument();
  });

  it("saves the full configuration, sending a blank password to preserve it", async () => {
    apiMock.get.mockResolvedValue(res(orgConfig));
    apiMock.put.mockResolvedValue(res(orgConfig));
    renderWithProviders(<OrgEmailConfigPanel orgId="o1" />);

    await userEvent.click(
      await screen.findByRole("button", { name: "Save Configuration" })
    );

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(
        "/api/v1/organizations/o1/email-config",
        {
          enabled: true,
          from_name: "Example Identity",
          from_email: "no-reply@example.com",
          reply_to: null,
          provider: {
            kind: "smtp",
            host: "smtp.example.com",
            port: 587,
            username: "mailer",
            password: "",
            starttls: true,
          },
        }
      )
    );
  });

  it("blocks a save with a malformed from address before it reaches the API", async () => {
    apiMock.get.mockResolvedValue(res(orgConfig));
    renderWithProviders(<OrgEmailConfigPanel orgId="o1" />);

    const fromEmail = await screen.findByLabelText("From Address *");
    await userEvent.clear(fromEmail);
    await userEvent.type(fromEmail, "nobody");
    await userEvent.click(
      screen.getByRole("button", { name: "Save Configuration" })
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /valid email address/
    );
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("swaps to the API-provider fields when the provider changes", async () => {
    apiMock.get.mockResolvedValue(res(orgConfig));
    renderWithProviders(<OrgEmailConfigPanel orgId="o1" />);

    await userEvent.selectOptions(
      await screen.findByLabelText("Provider"),
      "send_grid"
    );

    expect(screen.getByLabelText("API Key")).toBeInTheDocument();
    expect(screen.queryByLabelText("SMTP Host *")).not.toBeInTheDocument();
  });

  it("hides the write controls from a read-only operator", async () => {
    useAuthStore.setState({
      user: { ...admin, permissions: ["email_config:read"] },
      isAuthenticated: true,
    });
    apiMock.get.mockResolvedValue(res(orgConfig));
    renderWithProviders(<OrgEmailConfigPanel orgId="o1" />);

    expect(await screen.findByLabelText("From Name *")).toBeDisabled();
    expect(
      screen.queryByRole("button", { name: "Save Configuration" })
    ).not.toBeInTheDocument();
  });

  it("removes the configuration after confirmation", async () => {
    apiMock.get.mockResolvedValue(res(orgConfig));
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<OrgEmailConfigPanel orgId="o1" />);

    await userEvent.click(await screen.findByRole("button", { name: /Remove/ }));
    const confirm = await screen.findByRole("dialog");
    await userEvent.click(within(confirm).getByRole("button", { name: "Remove" }));

    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith(
        "/api/v1/organizations/o1/email-config"
      )
    );
  });

  it("surfaces the provider's own rejection from a delivery self-test", async () => {
    // The regression this exists for: an unverified sender domain produced a
    // 403 that only ever reached the mail consumer's dead-letter log, so the
    // admin UI reported the configuration saved and nothing else.
    apiMock.get.mockResolvedValue(res(orgConfig));
    apiMock.post.mockRejectedValue({
      response: {
        status: 400,
        data: {
          message:
            "Email delivery failed: Resend returned 403 Forbidden: the example.com domain is not verified",
        },
      },
    });
    renderWithProviders(<OrgEmailConfigPanel orgId="o1" />);

    await userEvent.click(
      await screen.findByRole("button", { name: /Send test email/ })
    );

    expect(apiMock.post).toHaveBeenCalledWith(
      "/api/v1/organizations/o1/email-config/test"
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /domain is not verified/
    );
  });
});

describe("TenantEmailConfigPanel", () => {
  it("sends only the groups the operator explicitly overrode", async () => {
    apiMock.get.mockRejectedValue({ response: { status: 404 } });
    apiMock.put.mockResolvedValue(res({}));
    renderWithProviders(<TenantEmailConfigPanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override sender identity/ })
    );
    await userEvent.type(screen.getByLabelText("From Name *"), "Tenant Co");
    await userEvent.type(
      screen.getByLabelText("From Address *"),
      "hello@tenant.example"
    );
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    // No `enabled` and no provider key — an absent field inherits the org
    // baseline, which is the entire point of the override endpoint. `reply_to`
    // is `null` rather than absent because the sender group is being
    // overridden and the box was left empty, which means "clear it".
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(
        "/api/v1/tenants/t1/email-config",
        {
          from_name: "Tenant Co",
          from_email: "hello@tenant.example",
          reply_to: null,
        }
      )
    );
  });

  it("overrides reply-to along with the rest of the sender identity", async () => {
    apiMock.get.mockRejectedValue({ response: { status: 404 } });
    apiMock.put.mockResolvedValue(res({}));
    renderWithProviders(<TenantEmailConfigPanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override sender identity/ })
    );
    await userEvent.type(screen.getByLabelText("From Name *"), "Tenant Co");
    await userEvent.type(
      screen.getByLabelText("From Address *"),
      "hello@tenant.example"
    );
    await userEvent.type(
      screen.getByLabelText("Reply-To"),
      "support@tenant.example"
    );
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(
        "/api/v1/tenants/t1/email-config",
        {
          from_name: "Tenant Co",
          from_email: "hello@tenant.example",
          reply_to: "support@tenant.example",
        }
      )
    );
  });

  it("leaves the delivery switch un-overridden unless the operator asks", async () => {
    // The regression: the tenant row stored `enabled` unconditionally and read
    // it back as an override, so every tenant that touched this panel also
    // took over the organization's delivery switch.
    apiMock.get.mockResolvedValue(
      res({ from_name: "Tenant Co", from_email: "hello@tenant.example" })
    );
    renderWithProviders(<TenantEmailConfigPanel tenantId="t1" />);

    const deliveryToggle = await screen.findByRole("checkbox", {
      name: /Override delivery on\/off/,
    });
    expect(deliveryToggle).not.toBeChecked();
    expect(
      screen.getByRole("checkbox", { name: /Override sender identity/ })
    ).toBeChecked();
  });

  it("surfaces a failed load rather than showing empty toggles", async () => {
    apiMock.get.mockRejectedValue(new Error("Forbidden"));
    renderWithProviders(<TenantEmailConfigPanel tenantId="t-other" />);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /Could not load this tenant's email overrides/
    );
    expect(
      screen.queryByRole("button", { name: "Save Overrides" })
    ).not.toBeInTheDocument();
  });

  it("sends an empty body when nothing is overridden", async () => {
    apiMock.get.mockRejectedValue({ response: { status: 404 } });
    apiMock.put.mockResolvedValue(res({}));
    renderWithProviders(<TenantEmailConfigPanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("button", { name: "Save Overrides" })
    );

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(
        "/api/v1/tenants/t1/email-config",
        {}
      )
    );
  });

  it("seeds the override toggles from what the tenant already overrides", async () => {
    apiMock.get.mockResolvedValue(
      res({ from_name: "Tenant Co", from_email: "hello@tenant.example" })
    );
    renderWithProviders(<TenantEmailConfigPanel tenantId="t1" />);

    expect(
      await screen.findByRole("checkbox", { name: /Override sender identity/ })
    ).toBeChecked();
    expect(
      screen.getByRole("checkbox", { name: /Override provider/ })
    ).not.toBeChecked();
    expect(screen.getByLabelText("From Name *")).toHaveValue("Tenant Co");
  });

  it("validates an overridden sender before sending it", async () => {
    apiMock.get.mockRejectedValue({ response: { status: 404 } });
    renderWithProviders(<TenantEmailConfigPanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override sender identity/ })
    );
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/From name/);
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("sends a delivery self-test through the tenant's effective config", async () => {
    apiMock.get.mockRejectedValue({ response: { status: 404 } });
    apiMock.post.mockResolvedValue(
      res({ provider: "resend", to: "admin@example.com", message_id: "m-1" })
    );
    renderWithProviders(<TenantEmailConfigPanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("button", { name: /Send test email/ })
    );

    expect(apiMock.post).toHaveBeenCalledWith(
      "/api/v1/tenants/t1/email-config/test"
    );
    expect(await screen.findByRole("status")).toHaveTextContent(
      /resend accepted a message to admin@example.com/
    );
  });
});
