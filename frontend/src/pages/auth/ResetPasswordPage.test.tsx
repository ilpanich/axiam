import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

let searchParamsString = "token=tok-1&tenant_id=ten-1";
vi.mock("react-router-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router-dom")>();
  return {
    ...actual,
    useSearchParams: () => [new URLSearchParams(searchParamsString), vi.fn()],
  };
});

import { ResetPasswordPage } from "./ResetPasswordPage";
import { renderWithProviders } from "@/test/renderWithProviders";

const STRONG_PASSWORD = "Str0ng!Passw0rd";

beforeEach(() => {
  vi.clearAllMocks();
  searchParamsString = "token=tok-1&tenant_id=ten-1";
});

describe("ResetPasswordPage", () => {
  it("shows the invalid-link state when token or tenant_id is missing", () => {
    searchParamsString = "";
    renderWithProviders(<ResetPasswordPage />);
    expect(screen.getByText("Invalid reset link")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Request new reset link" })
    ).toHaveAttribute("href", "/auth/forgot-password");
    expect(screen.getByRole("link", { name: /Back to login/ })).toHaveAttribute(
      "href",
      "/login"
    );
  });

  it("accepts the tenant alias query param", () => {
    searchParamsString = "token=tok-1&tenant=ten-1";
    renderWithProviders(<ResetPasswordPage />);
    expect(screen.getByText("Set your new password")).toBeInTheDocument();
  });

  it("renders the form and disables submit until the policy and match requirements are met", async () => {
    renderWithProviders(<ResetPasswordPage />);
    expect(screen.getByText("Set your new password")).toBeInTheDocument();
    const submit = screen.getByRole("button", { name: "Reset Password" });
    expect(submit).toBeDisabled();

    await userEvent.type(screen.getByLabelText("New Password"), STRONG_PASSWORD);
    expect(submit).toBeDisabled();

    await userEvent.type(screen.getByLabelText("Confirm Password"), STRONG_PASSWORD);
    expect(submit).toBeEnabled();
  });

  it("shows a mismatch error once the confirm field is touched and blurred", async () => {
    renderWithProviders(<ResetPasswordPage />);
    await userEvent.type(screen.getByLabelText("New Password"), STRONG_PASSWORD);
    await userEvent.type(screen.getByLabelText("Confirm Password"), "different");
    await userEvent.tab();
    expect(await screen.findByText("Passwords do not match.")).toBeInTheDocument();
  });

  it("shows the password policy checklist once typing starts", async () => {
    renderWithProviders(<ResetPasswordPage />);
    await userEvent.type(screen.getByLabelText("New Password"), "short");
    expect(screen.getByLabelText("Password requirements")).toBeInTheDocument();
  });

  it("submits the reset and shows the success state", async () => {
    apiMock.post.mockResolvedValue(res(undefined));
    renderWithProviders(<ResetPasswordPage />);

    await userEvent.type(screen.getByLabelText("New Password"), STRONG_PASSWORD);
    await userEvent.type(screen.getByLabelText("Confirm Password"), STRONG_PASSWORD);
    await userEvent.click(screen.getByRole("button", { name: "Reset Password" }));

    expect(await screen.findByText("Password reset successfully")).toBeInTheDocument();
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/reset/confirm", {
      tenant_id: "ten-1",
      token: "tok-1",
      new_password: STRONG_PASSWORD,
    });
    expect(screen.getByRole("link", { name: "Go to Login" })).toHaveAttribute(
      "href",
      "/login"
    );
  });

  it("surfaces a server error message from the response body", async () => {
    apiMock.post.mockRejectedValue({
      response: { data: { message: "Token expired" } },
    });
    renderWithProviders(<ResetPasswordPage />);

    await userEvent.type(screen.getByLabelText("New Password"), STRONG_PASSWORD);
    await userEvent.type(screen.getByLabelText("Confirm Password"), STRONG_PASSWORD);
    await userEvent.click(screen.getByRole("button", { name: "Reset Password" }));

    expect(await screen.findByText("Token expired")).toBeInTheDocument();
  });

  it("falls back to the error field and then to a generic message", async () => {
    apiMock.post.mockRejectedValueOnce({ response: { data: { error: "Bad token" } } });
    renderWithProviders(<ResetPasswordPage />);
    await userEvent.type(screen.getByLabelText("New Password"), STRONG_PASSWORD);
    await userEvent.type(screen.getByLabelText("Confirm Password"), STRONG_PASSWORD);
    await userEvent.click(screen.getByRole("button", { name: "Reset Password" }));
    expect(await screen.findByText("Bad token")).toBeInTheDocument();
  });

  it("shows a generic error message when the response has no data", async () => {
    apiMock.post.mockRejectedValueOnce(new Error("network fail"));
    renderWithProviders(<ResetPasswordPage />);
    await userEvent.type(screen.getByLabelText("New Password"), STRONG_PASSWORD);
    await userEvent.type(screen.getByLabelText("Confirm Password"), STRONG_PASSWORD);
    await userEvent.click(screen.getByRole("button", { name: "Reset Password" }));
    expect(
      await screen.findByText(
        "This reset link is invalid or has expired. Please request a new one."
      )
    ).toBeInTheDocument();
  });
});
