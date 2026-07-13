import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

vi.mock("react-router-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router-dom")>();
  return {
    ...actual,
    useSearchParams: () => [new URLSearchParams("org=acme&tenant=main"), vi.fn()],
  };
});

import { ForgotPasswordPage } from "./ForgotPasswordPage";
import { renderWithProviders } from "@/test/renderWithProviders";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("ForgotPasswordPage", () => {
  it("renders the request form initially", () => {
    renderWithProviders(<ForgotPasswordPage />);
    expect(screen.getByRole("heading", { name: "Reset your password" })).toBeInTheDocument();
    expect(screen.getByLabelText("Email address")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Send Reset Link" })).toBeInTheDocument();
  });

  it("submits the email and shows the success state, forwarding org/tenant slugs", async () => {
    apiMock.post.mockResolvedValue(res(undefined));
    renderWithProviders(<ForgotPasswordPage />);

    await userEvent.type(screen.getByLabelText("Email address"), "user@example.com");
    await userEvent.click(screen.getByRole("button", { name: "Send Reset Link" }));

    expect(await screen.findByText("Check your email")).toBeInTheDocument();
    expect(
      screen.getByText(/If an account with that email exists/)
    ).toBeInTheDocument();
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/reset", {
      email: "user@example.com",
      org_slug: "acme",
      tenant_slug: "main",
    });
  });

  it("still shows the success state when the request fails (enumeration-safe)", async () => {
    apiMock.post.mockRejectedValue(new Error("network down"));
    renderWithProviders(<ForgotPasswordPage />);

    await userEvent.type(screen.getByLabelText("Email address"), "user@example.com");
    await userEvent.click(screen.getByRole("button", { name: "Send Reset Link" }));

    expect(await screen.findByText("Check your email")).toBeInTheDocument();
  });

  it("shows a pending state while the request is in flight", async () => {
    let resolvePost: (() => void) | undefined;
    apiMock.post.mockReturnValue(
      new Promise((resolve) => {
        resolvePost = () => resolve(res(undefined));
      })
    );
    renderWithProviders(<ForgotPasswordPage />);

    await userEvent.type(screen.getByLabelText("Email address"), "user@example.com");
    await userEvent.click(screen.getByRole("button", { name: "Send Reset Link" }));

    expect(await screen.findByText("Sending…")).toBeInTheDocument();

    resolvePost?.();
    expect(await screen.findByText("Check your email")).toBeInTheDocument();
  });

  it("provides a back-to-login link", () => {
    renderWithProviders(<ForgotPasswordPage />);
    expect(screen.getByRole("link", { name: /Back to login/ })).toHaveAttribute(
      "href",
      "/login"
    );
  });

  it("provides a back-to-login link from the success state", async () => {
    apiMock.post.mockResolvedValue(res(undefined));
    renderWithProviders(<ForgotPasswordPage />);
    await userEvent.type(screen.getByLabelText("Email address"), "user@example.com");
    await userEvent.click(screen.getByRole("button", { name: "Send Reset Link" }));
    expect(await screen.findByText("Check your email")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Back to login/ })).toHaveAttribute(
      "href",
      "/login"
    );
  });
});
