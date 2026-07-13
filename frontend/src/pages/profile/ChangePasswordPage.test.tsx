import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { ChangePasswordPage } from "./ChangePasswordPage";
import { renderWithProviders } from "@/test/renderWithProviders";

// A password that satisfies checkPasswordPolicy (>=12 chars, upper/lower/digit/symbol)
const STRONG_PW = "Str0ng!Passw0rd";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("ChangePasswordPage", () => {
  it("renders the form fields", async () => {
    renderWithProviders(<ChangePasswordPage />);
    expect(screen.getByLabelText("Current Password")).toBeInTheDocument();
    expect(screen.getByLabelText("New Password")).toBeInTheDocument();
    expect(screen.getByLabelText("Confirm New Password")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Update Password" })).toBeDisabled();
  });

  it("shows the password policy checklist once typing starts", async () => {
    renderWithProviders(<ChangePasswordPage />);
    await userEvent.type(screen.getByLabelText("New Password"), "a");
    expect(screen.getByLabelText("Password requirements")).toBeInTheDocument();
  });

  it("shows a mismatch message once confirm field is touched and differs", async () => {
    renderWithProviders(<ChangePasswordPage />);
    await userEvent.type(screen.getByLabelText("New Password"), STRONG_PW);
    await userEvent.type(screen.getByLabelText("Confirm New Password"), "different");
    await userEvent.tab();
    expect(await screen.findByText("Passwords do not match.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Update Password" })).toBeDisabled();
  });

  it("enables submit only when policy is met and passwords match", async () => {
    renderWithProviders(<ChangePasswordPage />);
    await userEvent.type(screen.getByLabelText("New Password"), STRONG_PW);
    await userEvent.type(screen.getByLabelText("Confirm New Password"), STRONG_PW);
    expect(screen.getByRole("button", { name: "Update Password" })).toBeEnabled();
  });

  it("submits and shows the success screen", async () => {
    apiMock.post.mockResolvedValue(res(undefined));
    renderWithProviders(<ChangePasswordPage />);
    await userEvent.type(screen.getByLabelText("Current Password"), "OldPassw0rd!");
    await userEvent.type(screen.getByLabelText("New Password"), STRONG_PW);
    await userEvent.type(screen.getByLabelText("Confirm New Password"), STRONG_PW);
    await userEvent.click(screen.getByRole("button", { name: "Update Password" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/password/change", {
        current_password: "OldPassw0rd!",
        new_password: STRONG_PW,
      })
    );
    expect(
      await screen.findByText("Password changed successfully")
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Back to Profile/ })).toHaveAttribute(
      "href",
      "/profile"
    );
  });

  it("surfaces a server error message from the response", async () => {
    apiMock.post.mockRejectedValue({
      response: { data: { message: "Current password is incorrect." } },
    });
    renderWithProviders(<ChangePasswordPage />);
    await userEvent.type(screen.getByLabelText("Current Password"), "wrong");
    await userEvent.type(screen.getByLabelText("New Password"), STRONG_PW);
    await userEvent.type(screen.getByLabelText("Confirm New Password"), STRONG_PW);
    await userEvent.click(screen.getByRole("button", { name: "Update Password" }));

    expect(
      await screen.findByText("Current password is incorrect.")
    ).toBeInTheDocument();
  });

  it("falls back to a generic error message when the response has no message/error", async () => {
    apiMock.post.mockRejectedValue({ response: { data: {} } });
    renderWithProviders(<ChangePasswordPage />);
    await userEvent.type(screen.getByLabelText("Current Password"), "wrong");
    await userEvent.type(screen.getByLabelText("New Password"), STRONG_PW);
    await userEvent.type(screen.getByLabelText("Confirm New Password"), STRONG_PW);
    await userEvent.click(screen.getByRole("button", { name: "Update Password" }));

    expect(
      await screen.findByText("Failed to change password. Please try again.")
    ).toBeInTheDocument();
  });

  it("has a Cancel link back to the profile page", () => {
    renderWithProviders(<ChangePasswordPage />);
    expect(screen.getByRole("link", { name: "Cancel" })).toHaveAttribute(
      "href",
      "/profile"
    );
  });
});
