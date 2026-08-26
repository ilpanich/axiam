import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

const navigate = vi.fn();
vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return { ...actual, useNavigate: () => navigate };
});

import { BootstrapPage } from "./BootstrapPage";
import { renderWithProviders } from "@/test/renderWithProviders";

const STRONG_PASSWORD = "StrongPass1!";

// Typing the organization name auto-derives the org slug ("Acme Corp" ->
// "acme-corp"). No tenant fields: bootstrap no longer creates one.
async function fillValidForm() {
  await userEvent.type(screen.getByLabelText("Organization name"), "Acme Corp");
  await userEvent.type(screen.getByLabelText("Email address"), "admin@example.com");
  await userEvent.type(screen.getByLabelText("Username"), "admin");
  await userEvent.type(screen.getByLabelText("Password"), STRONG_PASSWORD);
}

const EXPECTED_PAYLOAD = {
  organization_name: "Acme Corp",
  organization_slug: "acme-corp",
  // No tenant. Bootstrap provisions the organization's own scope and puts the
  // administrator in it, so that administrator reaches every tenant created
  // afterwards. Creating a tenant here is what used to leave every *later*
  // tenant unreachable by everybody, the bootstrap admin included.
  email: "admin@example.com",
  username: "admin",
  password: STRONG_PASSWORD,
  // Always sent, always `disabled` unless the operator opens the OPAQUE
  // section and changes it. The server defaults every one of the three, so
  // sending them explicitly changes nothing for a default bootstrap.
  opaque_mode: "disabled",
  opaque_suite: "ristretto255_sha512",
  opaque_ksf: "argon2id",
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("BootstrapPage", () => {
  it("renders the initialize form", () => {
    renderWithProviders(<BootstrapPage />);
    expect(
      screen.getByRole("heading", { name: "Initialize AXIAM" })
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Create Organization & Admin" })
    ).toBeInTheDocument();
  });

  it("requires the core fields before submitting", async () => {
    renderWithProviders(<BootstrapPage />);
    await userEvent.click(
      screen.getByRole("button", { name: "Create Organization & Admin" })
    );
    expect(
      await screen.findByText(
        "Organization, email, username and password are required."
      )
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("shows the password policy checker once a password is entered", async () => {
    renderWithProviders(<BootstrapPage />);
    await userEvent.type(screen.getByLabelText("Password"), "a");
    expect(screen.getByLabelText("Password requirements")).toBeInTheDocument();
  });

  it("rejects a password that does not meet policy", async () => {
    renderWithProviders(<BootstrapPage />);
    await userEvent.type(screen.getByLabelText("Organization name"), "Acme Corp");
    await userEvent.type(screen.getByLabelText("Email address"), "admin@example.com");
    await userEvent.type(screen.getByLabelText("Username"), "admin");
    await userEvent.type(screen.getByLabelText("Password"), "weak");
    await userEvent.click(
      screen.getByRole("button", { name: "Create Organization & Admin" })
    );
    expect(
      await screen.findByText("Password does not meet the requirements.")
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("submits the bootstrap request and navigates on success", async () => {
    apiMock.post.mockResolvedValue(res({ user_id: "admin-1" }));
    renderWithProviders(<BootstrapPage />);
    await fillValidForm();
    await userEvent.click(
      screen.getByRole("button", { name: "Create Organization & Admin" })
    );
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        "/api/v1/admin/bootstrap",
        EXPECTED_PAYLOAD
      )
    );
    // No `tenant` param either: the login page reads a blank tenant as
    // "sign in at organization level", which is what this administrator is.
    expect(navigate).toHaveBeenCalledWith("/login?bootstrapped=1&org=acme-corp");
  });

  it("includes the setup token when provided", async () => {
    apiMock.post.mockResolvedValue(res({ user_id: "admin-1" }));
    renderWithProviders(<BootstrapPage />);
    await fillValidForm();
    await userEvent.type(screen.getByLabelText(/Setup token/), "tok-123");
    await userEvent.click(
      screen.getByRole("button", { name: "Create Organization & Admin" })
    );
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/admin/bootstrap", {
        ...EXPECTED_PAYLOAD,
        setup_token: "tok-123",
      })
    );
  });

  it("bootstraps with OPAQUE on when the operator asks for it", async () => {
    // The gap this closes: bootstrap is the one enrolment path where the
    // server holds the plaintext and builds the record itself, so it is the
    // only moment a deployment can start with OPAQUE already working. The page
    // offered no way to ask for it, so every browser-bootstrapped deployment
    // began with OPAQUE off and both OPAQUE tables empty.
    apiMock.post.mockResolvedValue(res({ user_id: "admin-1" }));
    renderWithProviders(<BootstrapPage />);
    await fillValidForm();

    await userEvent.click(screen.getByText(/OPAQUE sign-in/));
    await userEvent.selectOptions(screen.getByLabelText("Mode"), "optional");
    await userEvent.click(
      screen.getByRole("button", { name: "Create Organization & Admin" })
    );

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/admin/bootstrap", {
        ...EXPECTED_PAYLOAD,
        opaque_mode: "optional",
      })
    );
  });

  it("shows a busy state while the request is in flight", async () => {
    let resolvePost: (v: unknown) => void = () => {};
    apiMock.post.mockReturnValue(
      new Promise((resolve) => {
        resolvePost = resolve;
      })
    );
    renderWithProviders(<BootstrapPage />);
    await fillValidForm();
    const submitButton = screen.getByRole("button", {
      name: "Create Organization & Admin",
    });
    await userEvent.click(submitButton);
    await waitFor(() =>
      expect(submitButton).toHaveAttribute("aria-busy", "true")
    );
    expect(submitButton).toBeDisabled();
    resolvePost(res({ user_id: "admin-1" }));
    await waitFor(() => expect(navigate).toHaveBeenCalled());
  });

  it("shows an authorization error on 403", async () => {
    apiMock.post.mockRejectedValue({ response: { status: 403 } });
    renderWithProviders(<BootstrapPage />);
    await fillValidForm();
    await userEvent.click(
      screen.getByRole("button", { name: "Create Organization & Admin" })
    );
    expect(
      await screen.findByText(
        "Bootstrap is not authorized. Check the email gate or paste a valid setup token."
      )
    ).toBeInTheDocument();
    expect(navigate).not.toHaveBeenCalled();
  });

  it("shows the already-initialized view on 409 and links back to sign in", async () => {
    apiMock.post.mockRejectedValue({ response: { status: 409 } });
    renderWithProviders(<BootstrapPage />);
    await fillValidForm();
    await userEvent.click(
      screen.getByRole("button", { name: "Create Organization & Admin" })
    );
    expect(
      await screen.findByRole("heading", { name: "Already Initialized" })
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Go to sign in" })
    ).toHaveAttribute("href", "/login");
  });

  it("surfaces a server-provided error message on other failures", async () => {
    apiMock.post.mockRejectedValue({
      response: { status: 500, data: { message: "Bootstrap failed" } },
    });
    renderWithProviders(<BootstrapPage />);
    await fillValidForm();
    await userEvent.click(
      screen.getByRole("button", { name: "Create Organization & Admin" })
    );
    expect(await screen.findByText("Bootstrap failed")).toBeInTheDocument();
  });

  it("falls back to the error field and then a default message", async () => {
    apiMock.post.mockRejectedValue({
      response: { status: 500, data: { error: "err-field" } },
    });
    const { unmount } = renderWithProviders(<BootstrapPage />);
    await fillValidForm();
    await userEvent.click(
      screen.getByRole("button", { name: "Create Organization & Admin" })
    );
    expect(await screen.findByText("err-field")).toBeInTheDocument();
    unmount();
  });

  it("shows the default error message for a network failure with no response", async () => {
    apiMock.post.mockRejectedValue(new Error("Network Error"));
    renderWithProviders(<BootstrapPage />);
    await fillValidForm();
    await userEvent.click(
      screen.getByRole("button", { name: "Create Organization & Admin" })
    );
    expect(
      await screen.findByText(
        "Could not initialize AXIAM. Verify the server is running and check the server logs."
      )
    ).toBeInTheDocument();
  });

  it("sets the document title on mount and restores it on unmount", async () => {
    const previousTitle = document.title;
    const { unmount } = renderWithProviders(<BootstrapPage />);
    expect(document.title).toBe("Initialize AXIAM — AXIAM");
    unmount();
    expect(document.title).toBe(previousTitle);
  });
});
