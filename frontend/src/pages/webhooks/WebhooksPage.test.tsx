import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, fireEvent, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { WebhooksPage } from "./WebhooksPage";
import { renderWithProviders } from "@/test/renderWithProviders";

const webhooks = [
  {
    id: "w1",
    url: "https://hooks.example.com/one",
    events: ["user.created", "user.updated"],
    enabled: true,
    retry_policy: { max_retries: 3, initial_delay_secs: 20, backoff_multiplier: 1.5 },
    created_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "w2",
    url: "https://hooks.example.com/two",
    events: ["role.assigned"],
    enabled: false,
    retry_policy: { max_retries: 5, initial_delay_secs: 10, backoff_multiplier: 2 },
    created_at: "2026-01-02T00:00:00Z",
  },
];

beforeEach(() => {
  vi.clearAllMocks();
});

describe("WebhooksPage", () => {
  it("renders the fetched webhooks with event counts and status", async () => {
    apiMock.get.mockResolvedValue(res(webhooks));
    renderWithProviders(<WebhooksPage />);
    expect(await screen.findByText("https://hooks.example.com/one")).toBeInTheDocument();
    expect(screen.getByText("https://hooks.example.com/two")).toBeInTheDocument();
    expect(screen.getByText("2 events")).toBeInTheDocument();
    expect(screen.getByText("1 event")).toBeInTheDocument();
  });

  it("shows the empty state when there are no webhooks", async () => {
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<WebhooksPage />);
    expect(await screen.findByText("No webhooks configured.")).toBeInTheDocument();
  });

  it("requires a URL before creating", async () => {
    apiMock.get.mockResolvedValue(res(webhooks));
    renderWithProviders(<WebhooksPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Webhook/ }));
    const dialog = screen.getByRole("dialog");
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("URL is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("requires at least one event type", async () => {
    apiMock.get.mockResolvedValue(res(webhooks));
    renderWithProviders(<WebhooksPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Webhook/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("URL *"), "https://x/cb");
    fireEvent.submit(dialog.querySelector("form")!);
    // The hint and the validation error share the same copy — both render.
    expect(
      (await screen.findAllByText("Select at least one event type.")).length
    ).toBeGreaterThan(0);
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("requires a secret before creating", async () => {
    apiMock.get.mockResolvedValue(res(webhooks));
    renderWithProviders(<WebhooksPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Webhook/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("URL *"), "https://x/cb");
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "user.created" }));
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Secret is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("creates a webhook with selected events and a secret", async () => {
    apiMock.get.mockResolvedValue(res(webhooks));
    apiMock.post.mockResolvedValue(res({ id: "w3", url: "https://x/cb", events: [], enabled: true, created_at: "t" }));
    renderWithProviders(<WebhooksPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Webhook/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("URL *"), "https://x/cb");
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "user.created" }));
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "mfa.reset" }));
    await userEvent.type(within(dialog).getByLabelText("Secret *"), "sh4red");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/webhooks", {
        url: "https://x/cb",
        events: ["user.created", "mfa.reset"],
        secret: "sh4red",
        retry_policy: { max_retries: 5, initial_delay_secs: 10, backoff_multiplier: 2 },
      })
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("surfaces a create error inside the dialog", async () => {
    apiMock.get.mockResolvedValue(res(webhooks));
    apiMock.post.mockRejectedValue(new Error("URL rejected"));
    renderWithProviders(<WebhooksPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Webhook/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("URL *"), "https://x/cb");
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "user.created" }));
    await userEvent.type(within(dialog).getByLabelText("Secret *"), "s");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("URL rejected")).toBeInTheDocument();
  });

  it("edits a webhook, pre-filling its current values", async () => {
    apiMock.get.mockResolvedValue(res(webhooks));
    apiMock.put.mockResolvedValue(res({ ...webhooks[0], enabled: false }));
    renderWithProviders(<WebhooksPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit webhook https://hooks.example.com/one" })
    );
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("URL *")).toHaveValue("https://hooks.example.com/one");
    expect(within(dialog).getByRole("checkbox", { name: "user.created" })).toBeChecked();
    // Toggle enabled off and drop an event.
    await userEvent.click(within(dialog).getByLabelText("Enabled"));
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "user.updated" }));
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/webhooks/w1", {
        url: "https://hooks.example.com/one",
        events: ["user.created"],
        enabled: false,
        retry_policy: { max_retries: 3, initial_delay_secs: 20, backoff_multiplier: 1.5 },
      })
    );
  });

  it("pre-fills the retry policy and sends an edited one", async () => {
    apiMock.get.mockResolvedValue(res(webhooks));
    apiMock.put.mockResolvedValue(res(webhooks[0]));
    renderWithProviders(<WebhooksPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit webhook https://hooks.example.com/one" })
    );
    const dialog = screen.getByRole("dialog");
    const maxRetries = within(dialog).getByLabelText("Max retries");
    expect(maxRetries).toHaveValue(3);
    expect(within(dialog).getByLabelText("Initial delay (s)")).toHaveValue(20);
    expect(within(dialog).getByLabelText("Backoff multiplier")).toHaveValue(1.5);

    fireEvent.change(maxRetries, { target: { value: "7" } });
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(
        "/api/v1/webhooks/w1",
        expect.objectContaining({
          retry_policy: {
            max_retries: 7,
            initial_delay_secs: 20,
            backoff_multiplier: 1.5,
          },
        })
      )
    );
  });

  it("rejects an out-of-range retry policy before the request", async () => {
    apiMock.get.mockResolvedValue(res(webhooks));
    renderWithProviders(<WebhooksPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit webhook https://hooks.example.com/one" })
    );
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Max retries"), {
      target: { value: "42" },
    });
    fireEvent.submit(dialog.querySelector("form")!);
    expect(
      await screen.findByText("Max retries must be a whole number between 0 and 10.")
    ).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  // D-02: an untouched field must leave the stored secret alone. The server
  // rejects an empty string rather than reading it as "no change", so the key
  // has to be absent, not blank.
  it("omits the secret unless one was typed, and sends it when it was", async () => {
    apiMock.get.mockResolvedValue(res(webhooks));
    apiMock.put.mockResolvedValue(res(webhooks[0]));
    renderWithProviders(<WebhooksPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit webhook https://hooks.example.com/one" })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    expect(apiMock.put.mock.calls[0][1]).not.toHaveProperty("secret");

    await userEvent.click(
      await screen.findByRole("button", { name: "Edit webhook https://hooks.example.com/one" })
    );
    const dialog2 = screen.getByRole("dialog");
    await userEvent.type(within(dialog2).getByLabelText("Rotate secret"), "rotated");
    await userEvent.click(within(dialog2).getByRole("button", { name: "Save Changes" }));
    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(2));
    expect(apiMock.put.mock.calls[1][1]).toMatchObject({ secret: "rotated" });
  });

  it("validates a blank URL when editing", async () => {
    apiMock.get.mockResolvedValue(res(webhooks));
    renderWithProviders(<WebhooksPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit webhook https://hooks.example.com/one" })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.clear(within(dialog).getByLabelText("URL *"));
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("URL is required.")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("surfaces an edit error inside the dialog", async () => {
    apiMock.get.mockResolvedValue(res(webhooks));
    apiMock.put.mockRejectedValue(new Error("Update failed"));
    renderWithProviders(<WebhooksPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit webhook https://hooks.example.com/one" })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(await screen.findByText("Update failed")).toBeInTheDocument();
  });

  it("deletes a webhook after confirmation", async () => {
    apiMock.get.mockResolvedValue(res(webhooks));
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<WebhooksPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Delete webhook https://hooks.example.com/two" })
    );
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Delete Webhook/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/webhooks/w2")
    );
  });
});
