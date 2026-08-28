import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, waitFor, within, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

const navigate = vi.fn();
vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return { ...actual, useNavigate: () => navigate };
});

import { UsersPage } from "./UsersPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { setToastDispatch } from "@/hooks/useToast";
import { useAuthStore } from "@/stores/auth";

// Stands in for the WebAssembly build of `crates/axiam-opaque` — a checkout
// that has not run the Rust toolchain has no artifact to load, and `lib/opaque`
// resolves it through a runtime specifier that `vi.mock` cannot reach.
const opaqueModuleMock = {
  default: vi.fn(async () => undefined),
  opaqueAvailable: () => true,
  OpaqueKsf: {
    argon2id: (memoryKib: number, iterations: number, parallelism: number) => ({
      kind: "argon2id",
      memoryKib,
      iterations,
      parallelism,
    }),
    scrypt: (logN: number, r: number, p: number) => ({ kind: "scrypt", logN, r, p }),
  },
  OpaqueLogin: class {
    ke1 = "aa".repeat(96);
    constructor(_password: string) {}
    finish() {
      return { ke3: "bb".repeat(64), sessionKey: "cc".repeat(64), exportKey: "dd".repeat(64) };
    }
  },
  OpaqueRegistration: class {
    request = "ee".repeat(32);
    constructor(_password: string) {}
    finish() {
      return { record: "ff".repeat(192), exportKey: "dd".repeat(64) };
    }
  },
};

// ─── Fixtures ─────────────────────────────────────────────────────────────────
// Raw shape as returned by the backend (UserResponseDto): display_name lives
// in `metadata`, not top-level — the service maps it onto `User.display_name`.

function rawUser(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "u1",
    username: "alice",
    email: "alice@x.io",
    metadata: { display_name: "Alice A" },
    mfa_enabled: true,
    email_verified: true,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    status: "Active",
    is_locked: false,
    locked_until: null,
    failed_login_attempts: 0,
    ...overrides,
  };
}

const alice = rawUser();
const bob = rawUser({
  id: "u2",
  username: "bob",
  email: "bob@x.io",
  metadata: {},
  mfa_enabled: false,
  email_verified: false,
  created_at: "2026-01-02T00:00:00Z",
  updated_at: "2026-01-02T00:00:00Z",
  status: "Inactive",
  is_locked: true,
  locked_until: "2026-02-01T00:00:00Z",
  failed_login_attempts: 5,
});

function listResponse(items: unknown[], total = items.length, limit = 20) {
  return res({ items, total, offset: 0, limit });
}

/** An axios-shaped rejection carrying an HTTP status. */
function httpError(status: number) {
  return Object.assign(new Error(`HTTP ${status}`), { response: { status } });
}

/**
 * A signed-in administrator of the tenant this page acts on.
 *
 * Every test here reaches the create dialog through an authenticated session,
 * so the store has to hold one: the dialog seals the new account's OPAQUE record
 * against the tenant it is creating the account IN, and reads that tenant id
 * from the active-tenant selection or, absent one, the caller's own tenant.
 */
function signedInAdmin() {
  useAuthStore.setState({
    user: {
      id: "u1",
      username: "admin",
      email: "admin@example.com",
      permissions: [],
      tenant_id: "t1",
      principal_tenant_id: "t1",
      orgSlug: "acme",
      tenantSlug: "default",
    },
    activeTenantId: null,
    isAuthenticated: true,
    isInitializing: false,
  });
}

/**
 * Route `register/start` to a 404 and everything else to `resolved`.
 *
 * 404 is how the server says this tenant has OPAQUE disabled, which is the
 * default and what most tests here are about. The dialog now always asks rather
 * than consulting a cached policy — that cache is what made switching a tenant
 * to `optional` appear to do nothing — so the question has to be answered.
 */
function opaqueDisabledExcept(resolved: unknown) {
  apiMock.post.mockImplementation((url: string) => {
    if (url === "/api/v1/auth/opaque/register/start") {
      return Promise.reject(httpError(404));
    }
    return Promise.resolve(resolved);
  });
}

beforeEach(async () => {
  vi.clearAllMocks();
  signedInAdmin();
  const { __setOpaqueModuleForTests } = await import("@/lib/opaque");
  __setOpaqueModuleForTests(opaqueModuleMock);
});

afterEach(async () => {
  setToastDispatch(null);
  const { __resetOpaqueModuleForTests } = await import("@/lib/opaque");
  __resetOpaqueModuleForTests();
});

describe("UsersPage", () => {
  it("renders fetched users with status, MFA, locked and verified badges", async () => {
    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    renderWithProviders(<UsersPage />);

    expect(await screen.findByText("Alice A")).toBeInTheDocument();
    // "bob" shows in both the Display Name (falls back to username) and
    // Username columns, so there are two matching nodes.
    expect(screen.getAllByText("bob").length).toBeGreaterThan(0);
    expect(screen.getByText("alice@x.io")).toBeInTheDocument();
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText("Inactive")).toBeInTheDocument();
    // "Locked" is both the status badge (a <span>) and the filter <button>;
    // scope to the badge span.
    expect(screen.getByText("Locked", { selector: "span" })).toBeInTheDocument();
    expect(screen.getByText("Enabled")).toBeInTheDocument();
    expect(screen.getByText("Disabled")).toBeInTheDocument();
    expect(screen.getByLabelText("Email verified")).toBeInTheDocument();
    expect(screen.getByLabelText("Email not verified")).toBeInTheDocument();
  });

  it("shows the empty state when there are no users", async () => {
    apiMock.get.mockResolvedValue(listResponse([]));
    renderWithProviders(<UsersPage />);
    expect(await screen.findByText("No users found.")).toBeInTheDocument();
  });

  it("navigates to the user detail page", async () => {
    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    renderWithProviders(<UsersPage />);
    await userEvent.click(await screen.findByRole("button", { name: "View alice" }));
    expect(navigate).toHaveBeenCalledWith("/users/u1");
  });

  it("filters by search term (client-side, via the service)", async () => {
    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    renderWithProviders(<UsersPage />);
    await screen.findAllByText("bob");

    await userEvent.type(screen.getByPlaceholderText("Search users…"), "bob");
    await waitFor(
      () => expect(screen.queryByText("Alice A")).not.toBeInTheDocument(),
      { timeout: 2000 }
    );
    expect(screen.getAllByText("bob").length).toBeGreaterThan(0);
  });

  it("toggles the locked-only filter", async () => {
    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    renderWithProviders(<UsersPage />);
    await screen.findByText("Alice A");

    await userEvent.click(screen.getByRole("button", { name: "Locked" }));
    expect(await screen.findByRole("button", { name: "Locked (1)" })).toBeInTheDocument();
    expect(screen.queryByText("Alice A")).not.toBeInTheDocument();
    expect(screen.getAllByText("bob").length).toBeGreaterThan(0);
  });

  it("shows the locked-only empty message when no accounts are locked", async () => {
    apiMock.get.mockResolvedValue(listResponse([alice]));
    renderWithProviders(<UsersPage />);
    await screen.findByText("Alice A");
    await userEvent.click(screen.getByRole("button", { name: "Locked" }));
    expect(await screen.findByText("No locked accounts.")).toBeInTheDocument();
  });

  it("paginates using offset/limit derived from total", async () => {
    apiMock.get.mockResolvedValue(listResponse([alice, bob], 45, 20));
    renderWithProviders(<UsersPage />);
    expect(await screen.findByText("Page 1 of 3")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();

    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(screen.getByText("Page 2 of 3")).toBeInTheDocument());
    await waitFor(() =>
      expect(apiMock.get).toHaveBeenLastCalledWith("/api/v1/users?offset=20&limit=20")
    );

    await userEvent.click(screen.getByRole("button", { name: "Previous" }));
    await waitFor(() => expect(screen.getByText("Page 1 of 3")).toBeInTheDocument());
  });

  it("validates required fields before creating (whitespace trims to empty)", async () => {
    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    renderWithProviders(<UsersPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New User/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Username *"), "   ");
    await userEvent.type(within(dialog).getByLabelText("Email *"), "a@x.io");
    await userEvent.type(within(dialog).getByLabelText("Password *"), "Str0ng!Passw0rd");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(
      await screen.findByText("Username, email, and password are required.")
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("rejects a password that does not meet the policy", async () => {
    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    renderWithProviders(<UsersPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New User/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Username *"), "carol");
    await userEvent.type(within(dialog).getByLabelText("Email *"), "carol@x.io");
    await userEvent.type(within(dialog).getByLabelText("Password *"), "weakpass1");
    // Password policy checklist should render once a password is typed.
    expect(within(dialog).getByLabelText("Password requirements")).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(
      await screen.findByText("Password does not meet the requirements.")
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("creates a user with a display name and refetches", async () => {
    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    opaqueDisabledExcept(res(rawUser({ id: "u3", username: "carol" })));
    renderWithProviders(<UsersPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New User/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Username *"), "carol");
    await userEvent.type(within(dialog).getByLabelText("Email *"), "carol@x.io");
    await userEvent.type(within(dialog).getByLabelText("Password *"), "Str0ng!Passw0rd");
    await userEvent.type(within(dialog).getByLabelText("Display Name"), "Carol C");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/users", {
        username: "carol",
        email: "carol@x.io",
        password: "Str0ng!Passw0rd",
        metadata: { display_name: "Carol C" },
      })
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("creates a user without a display name (no metadata sent)", async () => {
    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    opaqueDisabledExcept(res(rawUser({ id: "u3", username: "carol" })));
    renderWithProviders(<UsersPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New User/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Username *"), "carol");
    await userEvent.type(within(dialog).getByLabelText("Email *"), "carol@x.io");
    await userEvent.type(within(dialog).getByLabelText("Password *"), "Str0ng!Passw0rd");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/users", {
        username: "carol",
        email: "carol@x.io",
        password: "Str0ng!Passw0rd",
      })
    );
  });

  it("enrols an OPAQUE record for the new account when the tenant uses OPAQUE", async () => {
    // The gap this closes: change-password and reset-completion built a record,
    // and this dialog did not. Under `optional` every operator-created account
    // stayed password-only forever; under `required` creation failed outright,
    // because the server refuses a new account with no record — an account that
    // could never authenticate — and the UI had no way to supply one.
    useAuthStore.setState({
      user: {
        id: "u1",
        username: "admin",
        email: "admin@example.com",
        permissions: [],
        tenant_id: "t1",
        orgSlug: "acme",
        tenantSlug: "default",
        opaque: {
          opaque_mode: "optional",
          opaque_suite: "ristretto255_sha512",
          opaque_ksf: "argon2id",
        },
      },
      isAuthenticated: true,
      isInitializing: false,
    });

    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    apiMock.post.mockImplementation((url: string) => {
      if (url === "/api/v1/auth/opaque/register/start") {
        return res({
          opaque_session: "sealed",
          registration_response: "aa".repeat(32),
          suite: "ristretto255_sha512",
          ksf: "argon2id",
          memory_kib: 19456,
          iterations: 2,
          parallelism: 1,
        });
      }
      return res(rawUser({ id: "u3", username: "carol" }));
    });

    renderWithProviders(<UsersPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New User/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Username *"), "carol");
    await userEvent.type(within(dialog).getByLabelText("Email *"), "carol@x.io");
    await userEvent.type(within(dialog).getByLabelText("Password *"), "Str0ng!Passw0rd");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        "/api/v1/users",
        expect.objectContaining({
          username: "carol",
          opaque: {
            opaque_session: "sealed",
            registration_record: "ff".repeat(192),
          },
        })
      )
    );
  });

  it("seals the record against the tenant the account is created in", async () => {
    // The reported 400: "Validation error: the OPAQUE session was issued for a
    // different tenant". An organization administrator selects a child tenant,
    // `POST /api/v1/users` is scoped to it by the `X-Axiam-Tenant` header the
    // API client attaches, and the record has to be sealed against THAT tenant's
    // key material. The dialog built it from the signed-in administrator's own
    // identity instead, so the session was minted for the organization scope and
    // redeemed against the child — and creating a user anywhere but your own
    // tenant was impossible for as long as OPAQUE was on.
    useAuthStore.setState({
      user: {
        id: "u1",
        username: "super-admin",
        email: "super-admin@example.com",
        permissions: ["*"],
        tenant_id: "org-tenant",
        principal_tenant_id: "org-tenant",
        organization_level: true,
        orgSlug: "acme",
        tenantSlug: "organization",
      },
      activeTenantId: "child-tenant",
      activeTenantName: "Child",
      isAuthenticated: true,
      isInitializing: false,
    });

    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    apiMock.post.mockImplementation((url: string) => {
      if (url === "/api/v1/auth/opaque/register/start") {
        return Promise.resolve(
          res({
            opaque_session: "sealed",
            registration_response: "aa".repeat(32),
            suite: "ristretto255_sha512",
            ksf: "argon2id",
            memory_kib: 19456,
            iterations: 2,
            parallelism: 1,
          })
        );
      }
      return Promise.resolve(res(rawUser({ id: "u3", username: "carol" })));
    });

    renderWithProviders(<UsersPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New User/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Username *"), "carol");
    await userEvent.type(within(dialog).getByLabelText("Email *"), "carol@x.io");
    await userEvent.type(within(dialog).getByLabelText("Password *"), "Str0ng!Passw0rd");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        "/api/v1/auth/opaque/register/start",
        expect.objectContaining({ tenant_id: "child-tenant" })
      )
    );
  });

  it("reports a failed enrolment instead of creating an unenrollable account", async () => {
    // Swallowing this is what let an account be created with no record under
    // `optional` — silently unenrolled — or refused by the server under
    // `required` with a message about a missing record the operator had no way
    // to act on. Anything but a 404 is now surfaced, and no user is created.
    setToastDispatch(vi.fn());
    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    apiMock.post.mockImplementation((url: string) =>
      url === "/api/v1/auth/opaque/register/start"
        ? Promise.reject(httpError(500))
        : Promise.resolve(res(rawUser({ id: "u3", username: "carol" })))
    );

    renderWithProviders(<UsersPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New User/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Username *"), "carol");
    await userEvent.type(within(dialog).getByLabelText("Email *"), "carol@x.io");
    await userEvent.type(within(dialog).getByLabelText("Password *"), "Str0ng!Passw0rd");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    expect(
      await screen.findByText(/Could not prepare secure login/)
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalledWith("/api/v1/users", expect.anything());
  });

  it("surfaces a create error via toast and inline message", async () => {
    setToastDispatch(vi.fn());
    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    apiMock.post.mockImplementation((url: string) =>
      url === "/api/v1/auth/opaque/register/start"
        ? Promise.reject(httpError(404))
        : Promise.reject(new Error("Username taken"))
    );
    renderWithProviders(<UsersPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New User/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Username *"), "carol");
    await userEvent.type(within(dialog).getByLabelText("Email *"), "carol@x.io");
    await userEvent.type(within(dialog).getByLabelText("Password *"), "Str0ng!Passw0rd");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Username taken")).toBeInTheDocument();
  });

  it("edits a user, toggling active status off", async () => {
    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    apiMock.put.mockResolvedValue(res(rawUser({ status: "Inactive" })));
    renderWithProviders(<UsersPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit alice" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("Email *")).toHaveValue("alice@x.io");
    await userEvent.click(within(dialog).getByLabelText("Active"));
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() =>
      // The service routes `display_name` into the backend `metadata` blob.
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/users/u1", {
        email: "alice@x.io",
        metadata: { display_name: "Alice A" },
        status: "Inactive",
      })
    );
  });

  it("validates that email is required when editing", async () => {
    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    renderWithProviders(<UsersPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit alice" }));
    const dialog = screen.getByRole("dialog");
    const emailInput = within(dialog).getByLabelText("Email *");
    // A whitespace-only value: set it directly (userEvent.type drops spaces on a
    // type="email" input) and submit the form directly (native `required`
    // validation would otherwise block the click before the JS handler runs).
    fireEvent.change(emailInput, { target: { value: "   " } });
    fireEvent.submit(emailInput.closest("form")!);
    expect(await screen.findByText("Email is required.")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("surfaces an edit error via toast", async () => {
    setToastDispatch(vi.fn());
    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    apiMock.put.mockRejectedValue(new Error("Email already in use"));
    renderWithProviders(<UsersPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit alice" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(await screen.findByText("Email already in use")).toBeInTheDocument();
  });

  it("deletes a user after confirmation", async () => {
    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<UsersPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete bob" }));
    const dialog = screen.getByRole("dialog");
    expect(screen.getByText(/delete "bob"/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/users/u2"));
  });

  it("surfaces a delete error via toast", async () => {
    const toastFn = vi.fn();
    setToastDispatch(toastFn);
    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    apiMock.delete.mockRejectedValue(new Error("Cannot delete"));
    renderWithProviders(<UsersPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete bob" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(toastFn).toHaveBeenCalledWith({
        description: "Cannot delete",
        variant: "destructive",
      })
    );
  });

  it("unlocks a locked account", async () => {
    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    apiMock.post.mockResolvedValue(res(rawUser({ id: "u2", is_locked: false })));
    renderWithProviders(<UsersPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Unlock bob" }));
    const dialog = screen.getByRole("dialog", { name: "Unlock Account" });
    // The confirmation copy names the account being unlocked.
    expect(within(dialog).getByText(/log in immediately/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Unlock Account" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/users/u2/unlock")
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("cancels the unlock dialog without calling the API", async () => {
    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    renderWithProviders(<UsersPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Unlock bob" }));
    const dialog = screen.getByRole("dialog", { name: "Unlock Account" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("surfaces an unlock error via toast", async () => {
    const toastFn = vi.fn();
    setToastDispatch(toastFn);
    apiMock.get.mockResolvedValue(listResponse([alice, bob]));
    apiMock.post.mockRejectedValue(new Error("Unlock failed"));
    renderWithProviders(<UsersPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Unlock bob" }));
    const dialog = screen.getByRole("dialog", { name: "Unlock Account" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Unlock Account" }));
    await waitFor(() =>
      expect(toastFn).toHaveBeenCalledWith({
        description: "Unlock failed",
        variant: "destructive",
      })
    );
  });
});
