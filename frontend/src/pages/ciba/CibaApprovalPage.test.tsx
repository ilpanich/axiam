import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AxiosError, type AxiosResponse } from "axios";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { CibaApprovalPage } from "./CibaApprovalPage";
import { stepUpLoginPath } from "@/services/ciba";
import { renderWithProviders } from "@/test/renderWithProviders";
import { sanitizeRequiredAcr, ACR_MULTI_FACTOR } from "@/lib/reauth";
import { sanitizeReturnTo } from "@/lib/returnTo";

const ID = "0b7f3a52-6c1e-4f0a-9d63-1f2a3b4c5d6e";
const ROUTE = `/ciba/approve?request_id=${ID}`;

function request(over: Record<string, unknown> = {}) {
  return {
    request_id: ID,
    version: 3,
    client_id: "cc_1",
    client_name: "Call Centre",
    scopes: ["openid", "profile"],
    binding_message: "W4SCT",
    requested_acr: [],
    step_up_required: null,
    expires_at: new Date(Date.now() + 5 * 60_000).toISOString(),
    ...over,
  };
}

/** An axios error carrying an HTTP status and body, as the api instance rejects. */
function httpError(status: number, data: unknown = {}) {
  return new AxiosError(
    `HTTP ${status}`,
    "ERR_BAD_REQUEST",
    undefined,
    undefined,
    { status, data } as AxiosResponse,
  );
}

let assign: ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.clearAllMocks();
  assign = vi.fn();
  Object.defineProperty(window, "location", {
    configurable: true,
    value: { ...window.location, assign },
  });
});

describe("CibaApprovalPage", () => {
  it("shows the client, its scopes and the binding message", async () => {
    apiMock.get.mockResolvedValue(res(request()));
    renderWithProviders(<CibaApprovalPage />, { route: ROUTE });

    expect(await screen.findByText("Call Centre")).toBeInTheDocument();
    expect(apiMock.get).toHaveBeenCalledWith(`/api/v1/ciba/requests/${ID}`);
    expect(screen.getByText("openid")).toBeInTheDocument();
    expect(screen.getByText("profile")).toBeInTheDocument();
    expect(screen.getByTestId("binding-message")).toHaveTextContent("W4SCT");
    expect(screen.getByRole("button", { name: "Approve" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Deny" })).toBeInTheDocument();
    // Never asks to step up when nothing requires it.
    expect(screen.queryByRole("button", { name: "Sign in again" })).toBeNull();
  });

  it("renders the binding message as text, never as markup", async () => {
    const hostile = '<img src=x onerror="alert(1)"><b>pay</b>';
    apiMock.get.mockResolvedValue(res(request({ binding_message: hostile })));
    renderWithProviders(<CibaApprovalPage />, { route: ROUTE });

    const box = await screen.findByTestId("binding-message");
    expect(box.textContent).toBe(hostile);
    expect(box.querySelector("img, b")).toBeNull();
  });

  it("approves with the version it read and says so", async () => {
    apiMock.get.mockResolvedValue(res(request({ version: 7 })));
    apiMock.post.mockResolvedValue(res({ ok: true, decision: "approved" }));
    renderWithProviders(<CibaApprovalPage />, { route: ROUTE });

    await userEvent.click(await screen.findByRole("button", { name: "Approve" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        `/api/v1/ciba/requests/${ID}/approve`,
        { version: 7 },
      ),
    );
    expect(await screen.findByText("Sign-in approved")).toBeInTheDocument();
  });

  it("denies with the version it read and says so", async () => {
    apiMock.get.mockResolvedValue(res(request({ version: 7 })));
    apiMock.post.mockResolvedValue(res({ ok: true, decision: "denied" }));
    renderWithProviders(<CibaApprovalPage />, { route: ROUTE });

    await userEvent.click(await screen.findByRole("button", { name: "Deny" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        `/api/v1/ciba/requests/${ID}/deny`,
        { version: 7 },
      ),
    );
    expect(await screen.findByText("Sign-in refused")).toBeInTheDocument();
  });

  it("answers one way for every request that cannot be decided", async () => {
    apiMock.get.mockRejectedValue(httpError(404, { error: "not_found" }));
    renderWithProviders(<CibaApprovalPage />, { route: ROUTE });
    expect(await screen.findByText("Request not found")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
  });

  it("says the same when the request is decided from elsewhere first", async () => {
    apiMock.get.mockResolvedValue(res(request()));
    apiMock.post.mockRejectedValue(httpError(404, { error: "not_found" }));
    renderWithProviders(<CibaApprovalPage />, { route: ROUTE });

    await userEvent.click(await screen.findByRole("button", { name: "Approve" }));
    expect(await screen.findByText("Couldn't record your decision")).toBeInTheDocument();
  });

  it("does not call the API for a link with no usable request id", () => {
    renderWithProviders(<CibaApprovalPage />, { route: "/ciba/approve?request_id=abc" });
    expect(screen.getByText("Request not found")).toBeInTheDocument();
    expect(apiMock.get).not.toHaveBeenCalled();

    renderWithProviders(<CibaApprovalPage />, { route: "/ciba/approve" });
    expect(apiMock.get).not.toHaveBeenCalled();
  });

  it("shows an error, not 'not found', when the read fails for another reason", async () => {
    apiMock.get.mockRejectedValue(httpError(500, { message: "boom" }));
    renderWithProviders(<CibaApprovalPage />, { route: ROUTE });
    expect(await screen.findByText("Couldn't load the request")).toBeInTheDocument();
  });

  describe("step-up", () => {
    it("offers the step-up up front when the session has not achieved the class", async () => {
      apiMock.get.mockResolvedValue(
        res(
          request({
            requested_acr: [ACR_MULTI_FACTOR],
            step_up_required: ACR_MULTI_FACTOR,
          }),
        ),
      );
      renderWithProviders(<CibaApprovalPage />, { route: ROUTE });

      const stepUp = await screen.findByRole("button", { name: "Sign in again" });
      expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
      // Refusing needs no stronger sign-in.
      expect(screen.getByRole("button", { name: "Deny" })).toBeEnabled();

      await userEvent.click(stepUp);
      expect(assign).toHaveBeenCalledTimes(1);
      const target = assign.mock.calls[0][0] as string;
      expect(target).toBe(stepUpLoginPath(ID, ACR_MULTI_FACTOR));
      // Through the existing login hop: reauthenticate, with the class named,
      // and come back to this page -- a destination the login page accepts.
      const url = new URL(target, "https://x.example");
      expect(url.pathname).toBe("/login");
      expect(url.searchParams.get("reauth")).toBe("1");
      expect(sanitizeRequiredAcr(url.searchParams.get("acr"))).toBe(ACR_MULTI_FACTOR);
      expect(sanitizeReturnTo(url.searchParams.get("return_to"))).toBe(ROUTE);
      expect(apiMock.post).not.toHaveBeenCalled();
    });

    it("turns a refused approval into the step-up, deciding nothing", async () => {
      apiMock.get.mockResolvedValue(res(request()));
      apiMock.post.mockRejectedValue(
        httpError(403, {
          error: "step_up_required",
          message: "stronger",
          required_acr: ACR_MULTI_FACTOR,
        }),
      );
      renderWithProviders(<CibaApprovalPage />, { route: ROUTE });

      await userEvent.click(await screen.findByRole("button", { name: "Approve" }));
      expect(
        await screen.findByRole("button", { name: "Sign in again" }),
      ).toBeInTheDocument();
      expect(screen.queryByText("Sign-in approved")).toBeNull();
      expect(screen.queryByText("Couldn't record your decision")).toBeNull();
    });

    it("treats any other 403 as an error to show, not a step-up", async () => {
      apiMock.get.mockResolvedValue(res(request()));
      apiMock.post.mockRejectedValue(httpError(403, { error: "authorization_denied" }));
      renderWithProviders(<CibaApprovalPage />, { route: ROUTE });

      await userEvent.click(await screen.findByRole("button", { name: "Approve" }));
      await waitFor(() => expect(apiMock.post).toHaveBeenCalled());
      expect(screen.queryByRole("button", { name: "Sign in again" })).toBeNull();
      expect(screen.getByRole("button", { name: "Approve" })).toBeInTheDocument();
    });

    it("never builds a login URL with a class outside the vocabulary", () => {
      const path = stepUpLoginPath(ID, "urn:evil:acr");
      const url = new URL(path, "https://x.example");
      expect(url.searchParams.get("acr")).toBe(ACR_MULTI_FACTOR);
    });
  });
});
