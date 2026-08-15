import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { DevicePage } from "./DevicePage";
import { renderWithProviders } from "@/test/renderWithProviders";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("DevicePage", () => {
  it("renders the code entry form", () => {
    renderWithProviders(<DevicePage />);
    expect(screen.getByLabelText("Device code")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Continue" })).toBeInTheDocument();
  });

  it("shows the consent screen with client and scopes when the code is found", async () => {
    apiMock.get.mockResolvedValue(
      res({ found: true, client_id: "tv-app", scopes: ["openid", "profile"] })
    );
    renderWithProviders(<DevicePage />);
    await userEvent.type(screen.getByLabelText("Device code"), "wxyz-1234");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    await waitFor(() =>
      expect(apiMock.get).toHaveBeenCalledWith("/api/v1/device/verify", {
        params: { user_code: "WXYZ1234" },
      })
    );
    expect(await screen.findByText("tv-app")).toBeInTheDocument();
    expect(screen.getByText("openid")).toBeInTheDocument();
    expect(screen.getByText("profile")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Deny" })).toBeInTheDocument();
  });

  it("shows a generic error for an unknown/expired/decided code", async () => {
    apiMock.get.mockResolvedValue(res({ found: false }));
    renderWithProviders(<DevicePage />);
    await userEvent.type(screen.getByLabelText("Device code"), "BADCODE1");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByText(/wasn't found/)).toBeInTheDocument();
  });

  it("requires a non-blank code", async () => {
    renderWithProviders(<DevicePage />);
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(
      await screen.findByText("Enter the code shown on your device.")
    ).toBeInTheDocument();
    expect(apiMock.get).not.toHaveBeenCalled();
  });

  it("approves a device and shows the success state", async () => {
    apiMock.get.mockResolvedValue(res({ found: true, client_id: "tv-app", scopes: [] }));
    apiMock.post.mockResolvedValue(res({ ok: true }));
    renderWithProviders(<DevicePage />);
    await userEvent.type(screen.getByLabelText("Device code"), "WXYZ1234");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    await screen.findByRole("button", { name: "Approve" });
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/device/decide", {
        user_code: "WXYZ1234",
        approved: true,
      })
    );
    expect(await screen.findByText("Device approved")).toBeInTheDocument();
  });

  it("denies a device and shows the denied state", async () => {
    apiMock.get.mockResolvedValue(res({ found: true, client_id: "tv-app", scopes: [] }));
    apiMock.post.mockResolvedValue(res({ ok: true }));
    renderWithProviders(<DevicePage />);
    await userEvent.type(screen.getByLabelText("Device code"), "WXYZ1234");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    await screen.findByRole("button", { name: "Deny" });
    await userEvent.click(screen.getByRole("button", { name: "Deny" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/device/decide", {
        user_code: "WXYZ1234",
        approved: false,
      })
    );
    expect(await screen.findByText("Access denied")).toBeInTheDocument();
  });

  it("shows a failure state when decide comes back ok:false", async () => {
    apiMock.get.mockResolvedValue(res({ found: true, client_id: "tv-app", scopes: [] }));
    apiMock.post.mockResolvedValue(res({ ok: false }));
    renderWithProviders(<DevicePage />);
    await userEvent.type(screen.getByLabelText("Device code"), "WXYZ1234");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    await screen.findByRole("button", { name: "Approve" });
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));
    expect(
      await screen.findByText("Couldn't record your decision")
    ).toBeInTheDocument();
  });

  it("auto-verifies from a ?user_code= query param (QR code path)", async () => {
    apiMock.get.mockResolvedValue(
      res({ found: true, client_id: "qr-app", scopes: ["email"] })
    );
    renderWithProviders(<DevicePage />, { route: "/device?user_code=ABCD-5678" });
    await waitFor(() =>
      expect(apiMock.get).toHaveBeenCalledWith("/api/v1/device/verify", {
        params: { user_code: "ABCD5678" },
      })
    );
    expect(await screen.findByText("qr-app")).toBeInTheDocument();
  });
});
