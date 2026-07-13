import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { NotificationRulesPage } from "./NotificationRulesPage";
import { renderWithProviders } from "@/test/renderWithProviders";

const rules = [
  {
    id: "r1",
    tenant_id: "t1",
    name: "Security alerts",
    description: "Notify security team",
    events: ["login_failure", "account_locked"],
    recipient_emails: ["sec@example.com", "ops@example.com"],
    enabled: true,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "r2",
    tenant_id: "t1",
    name: "Empty events rule",
    description: "",
    events: [],
    recipient_emails: ["solo@example.com"],
    enabled: false,
    created_at: "2026-01-02T00:00:00Z",
    updated_at: "2026-01-02T00:00:00Z",
  },
];

beforeEach(() => {
  vi.clearAllMocks();
});

describe("NotificationRulesPage", () => {
  it("renders the fetched rules with event labels and recipient overflow", async () => {
    apiMock.get.mockResolvedValue(res(rules));
    renderWithProviders(<NotificationRulesPage />);
    expect(await screen.findByText("Security alerts")).toBeInTheDocument();
    expect(screen.getByText("Login failure")).toBeInTheDocument();
    expect(screen.getByText("Account locked")).toBeInTheDocument();
    expect(screen.getByText("sec@example.com")).toBeInTheDocument();
    expect(screen.getByText("+1 more")).toBeInTheDocument();
    expect(screen.getByText("Notify security team")).toBeInTheDocument();
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText("Inactive")).toBeInTheDocument();

    // Second rule has no events -> em-dash, and no description -> em-dash
    expect(screen.getByText("Empty events rule")).toBeInTheDocument();
    expect(screen.getByText("solo@example.com")).toBeInTheDocument();
  });

  it("shows the empty state when there are no rules", async () => {
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<NotificationRulesPage />);
    expect(
      await screen.findByText("No notification rules configured."),
    ).toBeInTheDocument();
  });

  it("requires a name before creating a rule", async () => {
    apiMock.get.mockResolvedValue(res(rules));
    renderWithProviders(<NotificationRulesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Rule/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByLabelText("Login failure"));
    await userEvent.type(
      within(dialog).getByLabelText("Recipient Emails (one per line)"),
      "a@example.com",
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("requires at least one event before creating a rule", async () => {
    apiMock.get.mockResolvedValue(res(rules));
    renderWithProviders(<NotificationRulesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Rule/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "New rule");
    await userEvent.type(
      within(dialog).getByLabelText("Recipient Emails (one per line)"),
      "a@example.com",
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(
      await screen.findByText("At least one event is required."),
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("validates recipient emails and reports invalid addresses", async () => {
    apiMock.get.mockResolvedValue(res(rules));
    renderWithProviders(<NotificationRulesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Rule/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "New rule");
    await userEvent.click(within(dialog).getByLabelText("Login failure"));
    await userEvent.type(
      within(dialog).getByLabelText("Recipient Emails (one per line)"),
      "not-an-email",
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(
      await screen.findByText("Invalid email: not-an-email"),
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("requires at least one recipient email", async () => {
    apiMock.get.mockResolvedValue(res(rules));
    renderWithProviders(<NotificationRulesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Rule/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "New rule");
    await userEvent.click(within(dialog).getByLabelText("Login failure"));
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(
      await screen.findByText("At least one recipient email is required."),
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("creates a rule with trimmed name/description, selected events and parsed emails", async () => {
    apiMock.get.mockResolvedValue(res(rules));
    apiMock.post.mockResolvedValue(
      res({
        id: "r3",
        tenant_id: "t1",
        name: "New rule",
        description: "desc",
        events: ["login_failure"],
        recipient_emails: ["a@example.com", "b@example.com"],
        enabled: true,
        created_at: "t",
        updated_at: "t",
      }),
    );
    renderWithProviders(<NotificationRulesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Rule/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "  New rule  ");
    await userEvent.click(within(dialog).getByLabelText("Login failure"));
    await userEvent.type(
      within(dialog).getByLabelText("Recipient Emails (one per line)"),
      "a@example.com{enter}b@example.com",
    );
    await userEvent.type(within(dialog).getByLabelText("Description"), "  desc  ");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/notification-rules", {
        name: "New rule",
        description: "desc",
        events: ["login_failure"],
        recipient_emails: ["a@example.com", "b@example.com"],
      }),
    );
  });

  it("toggling an event checkbox off removes it from the selection", async () => {
    apiMock.get.mockResolvedValue(res(rules));
    apiMock.post.mockResolvedValue(res({ ...rules[0], id: "r9" }));
    renderWithProviders(<NotificationRulesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Rule/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "toggle rule");
    const checkbox = within(dialog).getByLabelText("Login failure");
    await userEvent.click(checkbox);
    expect(checkbox).toBeChecked();
    await userEvent.click(checkbox);
    expect(checkbox).not.toBeChecked();
    // No events selected now -> submit should be rejected client-side
    await userEvent.type(
      within(dialog).getByLabelText("Recipient Emails (one per line)"),
      "a@example.com",
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(
      await screen.findByText("At least one event is required."),
    ).toBeInTheDocument();
  });

  it("surfaces a create error from the service", async () => {
    apiMock.get.mockResolvedValue(res(rules));
    apiMock.post.mockRejectedValue(new Error("Rule name already exists"));
    renderWithProviders(<NotificationRulesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Rule/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Dup rule");
    await userEvent.click(within(dialog).getByLabelText("Login failure"));
    await userEvent.type(
      within(dialog).getByLabelText("Recipient Emails (one per line)"),
      "a@example.com",
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Rule name already exists")).toBeInTheDocument();
  });

  it("edits an existing rule, prefilling its current values", async () => {
    apiMock.get.mockResolvedValue(res(rules));
    apiMock.put.mockResolvedValue(res({ ...rules[0], name: "Security alerts v2" }));
    renderWithProviders(<NotificationRulesPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit rule Security alerts" }),
    );
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("Name *")).toHaveValue("Security alerts");
    expect(within(dialog).getByLabelText("Login failure")).toBeChecked();
    expect(within(dialog).getByLabelText("Account locked")).toBeChecked();
    expect(
      within(dialog).getByLabelText("Recipient Emails (one per line)"),
    ).toHaveValue("sec@example.com\nops@example.com");
    expect(within(dialog).getByLabelText("Enabled")).toBeChecked();

    const nameField = within(dialog).getByLabelText("Name *");
    await userEvent.clear(nameField);
    await userEvent.type(nameField, "Security alerts v2");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/notification-rules/r1", {
        name: "Security alerts v2",
        description: "Notify security team",
        events: ["login_failure", "account_locked"],
        recipient_emails: ["sec@example.com", "ops@example.com"],
        enabled: true,
      }),
    );
  });

  it("blocks saving an edit with a blank name", async () => {
    apiMock.get.mockResolvedValue(res(rules));
    renderWithProviders(<NotificationRulesPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit rule Security alerts" }),
    );
    const dialog = screen.getByRole("dialog");
    const nameField = within(dialog).getByLabelText("Name *");
    await userEvent.clear(nameField);
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("surfaces an edit error from the service", async () => {
    apiMock.get.mockResolvedValue(res(rules));
    apiMock.put.mockRejectedValue(new Error("Update rejected"));
    renderWithProviders(<NotificationRulesPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit rule Security alerts" }),
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(await screen.findByText("Update rejected")).toBeInTheDocument();
  });

  it("deletes a rule after confirmation", async () => {
    apiMock.get.mockResolvedValue(res(rules));
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<NotificationRulesPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Delete rule Empty events rule" }),
    );
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Delete Notification Rule/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/notification-rules/r2"),
    );
  });
});
