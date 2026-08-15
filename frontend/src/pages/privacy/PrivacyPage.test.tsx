import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { PrivacyPage } from "./PrivacyPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore } from "@/stores/auth";
import { setToastDispatch } from "@/hooks/useToast";

function setUser(permissions: string[]) {
  useAuthStore.setState({
    user: { id: "u1", username: "admin", email: "a@x.io", permissions, tenant_id: "t1" },
    tenantSlug: "acme-tenant",
    orgSlug: "acme",
    isAuthenticated: true,
    isInitializing: false,
  });
}

const toastSpy = vi.fn();

beforeEach(() => {
  vi.clearAllMocks();
  setUser([]);
  setToastDispatch(toastSpy);
});

afterEach(() => {
  setToastDispatch(null);
});

describe("PrivacyPage", () => {
  it("renders the four self-service sections", () => {
    renderWithProviders(<PrivacyPage />);
    expect(screen.getByText("Export your data")).toBeInTheDocument();
    expect(screen.getByText("Redeem a download link")).toBeInTheDocument();
    expect(screen.getByText("Delete your account")).toBeInTheDocument();
    expect(screen.getByText("Cancel a pending deletion")).toBeInTheDocument();
  });

  it("hides the 'act on behalf of' fields without gdpr:export / users:erase", () => {
    renderWithProviders(<PrivacyPage />);
    expect(screen.queryByLabelText(/Act on behalf of/)).not.toBeInTheDocument();
  });

  it("shows the export 'act on behalf of' field with gdpr:export", () => {
    setUser(["gdpr:export"]);
    renderWithProviders(<PrivacyPage />);
    expect(screen.getAllByLabelText(/Act on behalf of/).length).toBe(1);
  });

  it("requests a self-service export", async () => {
    apiMock.post.mockResolvedValue(res({ queued: true }));
    renderWithProviders(<PrivacyPage />);
    await userEvent.click(screen.getByRole("button", { name: "Request Export" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/account/export", {
        user_id: undefined,
      })
    );
    expect(toastSpy).toHaveBeenCalledWith(
      expect.objectContaining({ description: expect.stringContaining("Export requested") })
    );
  });

  it("redeems a download token and triggers a download", async () => {
    apiMock.get.mockResolvedValue(res({ some: "export-data" }));
    // jsdom doesn't implement anchor click download side effects meaningfully,
    // but createObjectURL must exist for the save helper to run without throwing.
    URL.createObjectURL = vi.fn(() => "blob:mock");
    URL.revokeObjectURL = vi.fn();
    renderWithProviders(<PrivacyPage />);
    await userEvent.type(screen.getByLabelText("Download token"), "tok-123");
    await userEvent.click(screen.getByRole("button", { name: "Download" }));
    await waitFor(() =>
      expect(apiMock.get).toHaveBeenCalledWith("/api/v1/account/export/tok-123")
    );
  });

  it("shows an error inline when the download token is rejected", async () => {
    apiMock.get.mockRejectedValue(new Error("Token not found"));
    renderWithProviders(<PrivacyPage />);
    await userEvent.type(screen.getByLabelText("Download token"), "bad-token");
    await userEvent.click(screen.getByRole("button", { name: "Download" }));
    expect(await screen.findByText("Token not found")).toBeInTheDocument();
  });

  it("requests erasure after confirmation", async () => {
    apiMock.post.mockResolvedValue(res({ scheduled: true }));
    renderWithProviders(<PrivacyPage />);
    await userEvent.click(screen.getByRole("button", { name: "Request Erasure" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Request Erasure" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/account/delete", {
        user_id: undefined,
      })
    );
  });

  it("cancels a pending deletion", async () => {
    apiMock.get.mockResolvedValue(res({ cancelled: true }));
    renderWithProviders(<PrivacyPage />);
    await userEvent.type(screen.getByLabelText("Cancellation token"), "cancel-tok");
    await userEvent.click(screen.getByRole("button", { name: "Cancel Deletion" }));
    await waitFor(() =>
      expect(apiMock.get).toHaveBeenCalledWith("/api/v1/auth/account/delete/cancel", {
        params: { token: "cancel-tok" },
      })
    );
  });
});
