import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen } from "@testing-library/react";
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

import { VerifyEmailPage } from "./VerifyEmailPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore } from "@/stores/auth";

beforeEach(() => {
  vi.clearAllMocks();
  searchParamsString = "token=tok-1&tenant_id=ten-1";
  useAuthStore.setState({
    user: null,
    tenantSlug: null,
    orgSlug: null,
    isAuthenticated: false,
    isInitializing: false,
  });
});

describe("VerifyEmailPage", () => {
  it("shows the no-token state when the link is missing required params", () => {
    searchParamsString = "";
    renderWithProviders(<VerifyEmailPage />);
    expect(screen.getByText("Invalid verification link")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to Login" })).toHaveAttribute(
      "href",
      "/login"
    );
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("accepts the tenant alias query param", () => {
    searchParamsString = "token=tok-1&tenant=ten-1";
    apiMock.post.mockResolvedValue(res(undefined));
    renderWithProviders(<VerifyEmailPage />);
    expect(screen.getByText("Verifying your email address…")).toBeInTheDocument();
  });

  it("shows a loading state then success, calling the verify endpoint once", async () => {
    apiMock.post.mockResolvedValue(res(undefined));
    renderWithProviders(<VerifyEmailPage />);

    expect(screen.getByText("Verifying your email address…")).toBeInTheDocument();

    expect(await screen.findByText("Email verified!")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Go to Dashboard" })).toHaveAttribute(
      "href",
      "/dashboard"
    );
    expect(apiMock.post).toHaveBeenCalledTimes(1);
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/verify-email", {
      tenant_id: "ten-1",
      token: "tok-1",
    });
  });

  it("shows a server error message and a login link for unauthenticated users on failure", async () => {
    apiMock.post.mockRejectedValue({
      response: { data: { message: "Link already used" } },
    });
    renderWithProviders(<VerifyEmailPage />);

    expect(await screen.findByText("Verification failed")).toBeInTheDocument();
    expect(screen.getByText("Link already used")).toBeInTheDocument();
    expect(
      screen.getByText(/please log in to your account first/)
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Log in to resend" })).toHaveAttribute(
      "href",
      "/login"
    );
  });

  it("falls back to the error field and then a generic message on failure", async () => {
    apiMock.post.mockRejectedValueOnce({ response: { data: { error: "Bad token" } } });
    renderWithProviders(<VerifyEmailPage />);
    expect(await screen.findByText("Bad token")).toBeInTheDocument();
  });

  it("shows a generic error message when the failure has no response data", async () => {
    apiMock.post.mockRejectedValueOnce(new Error("network fail"));
    renderWithProviders(<VerifyEmailPage />);
    expect(
      await screen.findByText("Verification failed. The link may be expired or already used.")
    ).toBeInTheDocument();
  });

  it("offers a profile link instead of a login link when the user is authenticated", async () => {
    useAuthStore.setState({
      user: {
        id: "u1",
        username: "a",
        email: "a@x.io",
        permissions: ["*"],
        tenant_id: "ten-1",
      },
      isAuthenticated: true,
    });
    apiMock.post.mockRejectedValue(new Error("fail"));
    renderWithProviders(<VerifyEmailPage />);

    expect(await screen.findByText("Verification failed")).toBeInTheDocument();
    expect(
      screen.getByText(/request a new verification email from your profile settings/)
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Go to Profile" })).toHaveAttribute(
      "href",
      "/profile"
    );
  });
});
