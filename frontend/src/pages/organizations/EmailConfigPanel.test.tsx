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

// ─── Provider editing, failures, and the tenant provider override ─────────────
//
// The panels above are covered for the paths an operator walks when everything
// works. These cover the rest: editing each provider field, the API-provider
// shape (a different branch of `providerFromForm` than SMTP), the four mutation
// failure handlers, and the tenant's provider-override group — which has its
// own validation and is the only way `payload.provider` is ever populated.

/** The same org config, but on an API provider rather than SMTP. */
const apiOrgConfig = {
  ...orgConfig,
  provider: { kind: "send_grid", api_url: "https://api.sendgrid.example" },
};

describe("OrgEmailConfigPanel — provider fields and failures", () => {
  it("sends every edited SMTP field, including a replacement password", async () => {
    apiMock.get.mockResolvedValue(res(orgConfig));
    apiMock.put.mockResolvedValue(res(orgConfig));
    renderWithProviders(<OrgEmailConfigPanel orgId="o1" />);

    const host = await screen.findByLabelText("SMTP Host *");
    await userEvent.clear(host);
    await userEvent.type(host, "smtp.relay.example");
    const port = screen.getByLabelText("Port *");
    await userEvent.clear(port);
    await userEvent.type(port, "465");
    const username = screen.getByLabelText("Username");
    await userEvent.clear(username);
    await userEvent.type(username, "relay-user");
    await userEvent.type(screen.getByLabelText("Password"), "s3cret");
    // Unchecking STARTTLS is how implicit TLS on 465 is expressed.
    await userEvent.click(
      screen.getByRole("checkbox", { name: /Use STARTTLS/ })
    );
    await userEvent.click(
      screen.getByRole("button", { name: "Save Configuration" })
    );

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(
        "/api/v1/organizations/o1/email-config",
        expect.objectContaining({
          provider: {
            kind: "smtp",
            host: "smtp.relay.example",
            port: 465,
            username: "relay-user",
            password: "s3cret",
            starttls: false,
          },
        })
      )
    );
  });

  it("sends the API-provider shape, not the SMTP one, for a non-SMTP provider", async () => {
    // `providerFromForm` has two branches and the payloads share no fields:
    // sending `{host, port, username}` to a SendGrid-shaped endpoint would be
    // refused by the backend's `#[serde(tag = "kind")]` enum.
    apiMock.get.mockResolvedValue(res(orgConfig));
    apiMock.put.mockResolvedValue(res(orgConfig));
    renderWithProviders(<OrgEmailConfigPanel orgId="o1" />);

    await userEvent.selectOptions(
      await screen.findByLabelText("Provider"),
      "resend"
    );
    await userEvent.type(screen.getByLabelText("API Key"), "re_live_key");
    await userEvent.type(
      screen.getByLabelText("API URL"),
      "https://api.resend.example"
    );
    await userEvent.click(
      screen.getByRole("button", { name: "Save Configuration" })
    );

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(
        "/api/v1/organizations/o1/email-config",
        expect.objectContaining({
          provider: {
            kind: "resend",
            api_key: "re_live_key",
            api_url: "https://api.resend.example",
          },
        })
      )
    );
  });

  it("seeds the API URL from a stored API provider and sends a null for a blank one", async () => {
    // A blank API URL means "use the provider's default", which the backend
    // models as `Option<String>` — so it must go out as null, not "".
    apiMock.get.mockResolvedValue(res(apiOrgConfig));
    apiMock.put.mockResolvedValue(res(apiOrgConfig));
    renderWithProviders(<OrgEmailConfigPanel orgId="o1" />);

    const apiUrl = await screen.findByLabelText("API URL");
    expect(apiUrl).toHaveValue("https://api.sendgrid.example");
    await userEvent.clear(apiUrl);
    await userEvent.click(
      screen.getByRole("button", { name: "Save Configuration" })
    );

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(
        "/api/v1/organizations/o1/email-config",
        expect.objectContaining({
          provider: { kind: "send_grid", api_key: "", api_url: null },
        })
      )
    );
  });

  it("sends the delivery switch the operator turned off", async () => {
    apiMock.get.mockResolvedValue(res(orgConfig));
    apiMock.put.mockResolvedValue(res(orgConfig));
    renderWithProviders(<OrgEmailConfigPanel orgId="o1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Email delivery enabled/ })
    );
    await userEvent.click(
      screen.getByRole("button", { name: "Save Configuration" })
    );

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(
        "/api/v1/organizations/o1/email-config",
        expect.objectContaining({ enabled: false })
      )
    );
  });

  it("reports a rejected save rather than showing it as saved", async () => {
    apiMock.get.mockResolvedValue(res(orgConfig));
    apiMock.put.mockRejectedValue({
      response: { status: 400, data: { message: "SMTP host is unreachable" } },
    });
    renderWithProviders(<OrgEmailConfigPanel orgId="o1" />);

    await userEvent.click(
      await screen.findByRole("button", { name: "Save Configuration" })
    );

    // The SERVER's sentence, not the generic fallback. These four handlers used
    // `err instanceof Error ? err.message : fallback`, and an AxiosError IS an
    // Error, so the operator was shown "Request failed with status code 400" —
    // or, when the shape did not match, a fallback that told them nothing about
    // what the provider actually rejected.
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "SMTP host is unreachable"
    );
    expect(screen.queryByText("Saved.")).not.toBeInTheDocument();
  });

  it("redacts a secret the server echoed back into its error message", async () => {
    // The reason the four handlers had to go through getApiErrorMessage rather
    // than merely being made to read `data.message`: that helper runs
    // redactSecrets(), and this is the one panel in the application that handles
    // SMTP passwords and provider API keys. A server error that quotes the
    // offending request — which is an ordinary thing for a validation error to
    // do — must not put the credential on screen.
    // `password` is the real wire field (services/emailConfig.ts: SmtpProvider),
    // so this is the shape a gateway echoing the rejected body would actually
    // produce — not an invented one.
    apiMock.get.mockResolvedValue(res(orgConfig));
    apiMock.put.mockRejectedValue({
      response: {
        status: 400,
        data: {
          message: 'rejected: {"password":"hunter2-not-on-screen"}',
        },
      },
    });
    renderWithProviders(<OrgEmailConfigPanel orgId="o1" />);

    await userEvent.click(
      await screen.findByRole("button", { name: "Save Configuration" })
    );

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/rejected/);
    expect(alert).not.toHaveTextContent("hunter2-not-on-screen");
  });

  it("reports a rejected removal and closes the dialog", async () => {
    apiMock.get.mockResolvedValue(res(orgConfig));
    apiMock.delete.mockRejectedValue({ response: { status: 403 } });
    renderWithProviders(<OrgEmailConfigPanel orgId="o1" />);

    await userEvent.click(await screen.findByRole("button", { name: /Remove/ }));
    const confirm = await screen.findByRole("dialog");
    await userEvent.click(within(confirm).getByRole("button", { name: "Remove" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Failed to delete email configuration."
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    );
  });

  it("cancelling the removal dialog leaves the configuration alone", async () => {
    apiMock.get.mockResolvedValue(res(orgConfig));
    renderWithProviders(<OrgEmailConfigPanel orgId="o1" />);

    await userEvent.click(await screen.findByRole("button", { name: /Remove/ }));
    const confirm = await screen.findByRole("dialog");
    await userEvent.click(within(confirm).getByRole("button", { name: "Cancel" }));

    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    );
    expect(apiMock.delete).not.toHaveBeenCalled();
  });
});

describe("TenantEmailConfigPanel — provider override and failures", () => {
  it("sends the whole provider block when the provider group is overridden", async () => {
    // There is no partial merge within a provider: an override replaces the
    // organization's provider outright, so every field goes out together.
    apiMock.get.mockRejectedValue({ response: { status: 404 } });
    apiMock.put.mockResolvedValue(res({}));
    renderWithProviders(<TenantEmailConfigPanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override provider/ })
    );
    await userEvent.type(screen.getByLabelText("SMTP Host *"), "smtp.tenant.example");
    const port = screen.getByLabelText("Port *");
    await userEvent.clear(port);
    await userEvent.type(port, "2525");
    await userEvent.type(screen.getByLabelText("Username"), "tenant-mailer");
    await userEvent.type(screen.getByLabelText("Password"), "tenant-secret");
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(
        "/api/v1/tenants/t1/email-config",
        {
          provider: {
            kind: "smtp",
            host: "smtp.tenant.example",
            port: 2525,
            username: "tenant-mailer",
            password: "tenant-secret",
            starttls: true,
          },
        }
      )
    );
  });

  it("refuses an SMTP provider override with no host", async () => {
    apiMock.get.mockRejectedValue({ response: { status: 404 } });
    renderWithProviders(<TenantEmailConfigPanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override provider/ })
    );
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "SMTP host must not be empty."
    );
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("refuses an SMTP provider override with a cleared port", async () => {
    // An empty port parses to NaN, which would serialize as null and fail the
    // backend's u16 parse with a message about JSON rather than about the port.
    apiMock.get.mockRejectedValue({ response: { status: 404 } });
    renderWithProviders(<TenantEmailConfigPanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override provider/ })
    );
    await userEvent.type(screen.getByLabelText("SMTP Host *"), "smtp.tenant.example");
    await userEvent.clear(screen.getByLabelText("Port *"));
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "SMTP port must be greater than 0."
    );
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("sends an API provider override without any SMTP fields", async () => {
    apiMock.get.mockRejectedValue({ response: { status: 404 } });
    apiMock.put.mockResolvedValue(res({}));
    renderWithProviders(<TenantEmailConfigPanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override provider/ })
    );
    await userEvent.selectOptions(screen.getByLabelText("Provider"), "postmark");
    await userEvent.type(screen.getByLabelText("API Key"), "pm_token");
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(
        "/api/v1/tenants/t1/email-config",
        { provider: { kind: "postmark", api_key: "pm_token", api_url: null } }
      )
    );
  });

  it("refuses an overridden sender whose from address has no @", async () => {
    apiMock.get.mockRejectedValue({ response: { status: 404 } });
    renderWithProviders(<TenantEmailConfigPanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override sender identity/ })
    );
    await userEvent.type(screen.getByLabelText("From Name *"), "Tenant Co");
    await userEvent.type(screen.getByLabelText("From Address *"), "nobody");
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "From address must be a valid email address."
    );
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("refuses an overridden reply-to that is not an address", async () => {
    // A non-empty reply-to is validated; an empty one is the deliberate
    // "clear the organization's reply-to" case and must stay allowed.
    apiMock.get.mockRejectedValue({ response: { status: 404 } });
    renderWithProviders(<TenantEmailConfigPanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override sender identity/ })
    );
    await userEvent.type(screen.getByLabelText("From Name *"), "Tenant Co");
    await userEvent.type(
      screen.getByLabelText("From Address *"),
      "hello@tenant.example"
    );
    await userEvent.type(screen.getByLabelText("Reply-To"), "support");
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Reply-to must be a valid email address."
    );
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("sends the delivery switch only once the operator overrides it", async () => {
    // Turning delivery *off* for one tenant is the reason this group exists;
    // the inner switch starts at the inherited-looking "on".
    apiMock.get.mockRejectedValue({ response: { status: 404 } });
    apiMock.put.mockResolvedValue(res({}));
    renderWithProviders(<TenantEmailConfigPanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override delivery on\/off/ })
    );
    const inner = screen.getByRole("checkbox", {
      name: /Email delivery enabled for this tenant/,
    });
    expect(inner).toBeChecked();
    await userEvent.click(inner);
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(
        "/api/v1/tenants/t1/email-config",
        { enabled: false }
      )
    );
  });

  it("clears every override back to the organization baseline", async () => {
    apiMock.get.mockResolvedValue(res({ enabled: false }));
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<TenantEmailConfigPanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("button", { name: /Clear All/ })
    );
    const confirm = await screen.findByRole("dialog");
    await userEvent.click(
      within(confirm).getByRole("button", { name: "Clear overrides" })
    );

    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith(
        "/api/v1/tenants/t1/email-config"
      )
    );
    // The toggles re-arm: nothing is overridden any more.
    await waitFor(() =>
      expect(
        screen.getByRole("checkbox", { name: /Override delivery on\/off/ })
      ).not.toBeChecked()
    );
  });

  it("reports a rejected clear and closes the dialog", async () => {
    apiMock.get.mockResolvedValue(res({ enabled: false }));
    apiMock.delete.mockRejectedValue({ response: { status: 403 } });
    renderWithProviders(<TenantEmailConfigPanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("button", { name: /Clear All/ })
    );
    const confirm = await screen.findByRole("dialog");
    await userEvent.click(
      within(confirm).getByRole("button", { name: "Clear overrides" })
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Failed to remove email override."
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    );
  });

  it("cancelling the clear dialog leaves the tenant's overrides in place", async () => {
    apiMock.get.mockResolvedValue(res({ enabled: false }));
    renderWithProviders(<TenantEmailConfigPanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("button", { name: /Clear All/ })
    );
    const confirm = await screen.findByRole("dialog");
    await userEvent.click(within(confirm).getByRole("button", { name: "Cancel" }));

    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    );
    expect(apiMock.delete).not.toHaveBeenCalled();
    expect(
      screen.getByRole("checkbox", { name: /Override delivery on\/off/ })
    ).toBeChecked();
  });

  it("reports a rejected override save", async () => {
    apiMock.get.mockRejectedValue({ response: { status: 404 } });
    apiMock.put.mockRejectedValue({ response: { status: 400 } });
    renderWithProviders(<TenantEmailConfigPanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override delivery on\/off/ })
    );
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Failed to save email override."
    );
  });
});
