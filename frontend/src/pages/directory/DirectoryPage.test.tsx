import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { DirectoryPage } from "./DirectoryPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore, type AuthUser } from "@/stores/auth";
import type { DirectoryConfig, DirectorySyncStatus } from "@/services/directory";

const TENANT = "t1";
const BASE = `/api/v1/tenants/${TENANT}/directory`;

const adminUser: AuthUser = {
  id: "u1",
  username: "admin",
  email: "a@x.io",
  permissions: ["*"],
  tenant_id: TENANT,
  tenantSlug: "acme",
  orgSlug: "acme-org",
};

/** A fresh value per call, from a CSPRNG: nothing here is a literal credential. */
function bindValue(): string {
  const bytes = new Uint8Array(12);
  globalThis.crypto.getRandomValues(bytes);
  return `Bv${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}7`;
}

function config(overrides: Partial<DirectoryConfig> = {}): DirectoryConfig {
  return {
    id: "d1",
    tenant_id: TENANT,
    enabled: true,
    kind: "open_ldap",
    url: "ldaps://ldap.example.com",
    start_tls: false,
    bind_dn: "cn=svc,dc=example,dc=com",
    base_dn: "dc=example,dc=com",
    user_filter: "(uid={username})",
    user_attribute_map: {
      username: "uid",
      email: "mail",
      display_name: "displayName",
      external_id: "entryUUID",
    },
    group_base_dn: "ou=groups,dc=example,dc=com",
    group_filter: null,
    group_member_attribute: "member",
    group_nesting_depth: 5,
    group_mappings: [],
    sync_interval_secs: 3600,
    jit_provisioning: false,
    trust_anchors_pem: [],
    created_at: "2026-10-01T00:00:00Z",
    updated_at: "2026-10-01T00:00:00Z",
    ...overrides,
  };
}

const freshStatus: DirectorySyncStatus = {
  last_result: null,
  last_attempt_at: null,
  last_full_run_at: null,
  full_required: false,
  has_watermark: false,
};

const groups = [
  { id: "g1", name: "Staff", created_at: "2026-01-01T00:00:00Z" },
  { id: "g2", name: "Admins", created_at: "2026-01-01T00:00:00Z" },
];

const alice = {
  id: "user-alice",
  username: "alice",
  email: "alice@example.com",
  mfa_enabled: false,
  email_verified: true,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  status: "Active",
  is_locked: false,
  locked_until: null,
  failed_login_attempts: 0,
};

function notFound() {
  return Promise.reject({ response: { status: 404, data: { error: "not_found", message: "no" } } });
}

/** Route every GET this page issues. `null` is "not configured" (a 404). */
function mockGets({
  stored = config() as DirectoryConfig | null,
  status = freshStatus as DirectorySyncStatus,
}: { stored?: DirectoryConfig | null; status?: DirectorySyncStatus } = {}) {
  apiMock.get.mockImplementation((url: string) => {
    if (url === BASE) return stored ? Promise.resolve(res(stored)) : notFound();
    if (url === `${BASE}/sync-status`) return Promise.resolve(res(status));
    if (url === "/api/v1/groups") {
      return Promise.resolve(res({ items: groups, total: groups.length, offset: 0, limit: 200 }));
    }
    if (url.startsWith("/api/v1/users")) {
      return Promise.resolve(res({ items: [alice], total: 1, offset: 0, limit: 20 }));
    }
    return Promise.reject(new Error(`unexpected GET ${url}`));
  });
}

function rejection(status: number, error: string, message: string) {
  return Promise.reject({ response: { status, data: { error, message } } });
}

beforeEach(() => {
  vi.clearAllMocks();
  useAuthStore.setState({
    user: adminUser,
    tenantSlug: "acme",
    orgSlug: "acme-org",
    isAuthenticated: true,
    isInitializing: false,
  });
});

async function openEdit() {
  await userEvent.click(await screen.findByRole("button", { name: /^Edit$/ }));
}

describe("DirectoryPage — viewing", () => {
  it("shows the configuration and says the secret is write-only", async () => {
    mockGets();
    renderWithProviders(<DirectoryPage />);
    expect(await screen.findByText("ldaps://ldap.example.com")).toBeInTheDocument();
    expect(screen.getByText(/Write-only — never shown/)).toBeInTheDocument();
    expect(screen.getByText("Enabled")).toBeInTheDocument();
  });

  it("offers no change to a reader without directory:write", async () => {
    useAuthStore.setState({ user: { ...adminUser, permissions: ["directory:read"] } });
    mockGets();
    renderWithProviders(<DirectoryPage />);
    await screen.findByText("ldaps://ldap.example.com");
    for (const name of [/^Edit$/, /^Replace$/, /^Delete$/, /Link an account/]) {
      expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
    }
  });

  it("shows an empty state, with Configure only for a writer", async () => {
    mockGets({ stored: null });
    renderWithProviders(<DirectoryPage />);
    expect(await screen.findByText("No directory configured")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Configure a directory/ })).toBeInTheDocument();
  });

  it("hides Configure from a reader", async () => {
    useAuthStore.setState({ user: { ...adminUser, permissions: ["directory:read"] } });
    mockGets({ stored: null });
    renderWithProviders(<DirectoryPage />);
    await screen.findByText("No directory configured");
    expect(screen.queryByRole("button", { name: /Configure a directory/ })).not.toBeInTheDocument();
  });
});

describe("DirectoryPage — creating", () => {
  it("creates with PUT, secret included, and never shows it afterwards", async () => {
    mockGets({ stored: null });
    apiMock.put.mockResolvedValue(res(config()));
    renderWithProviders(<DirectoryPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Configure a directory/ }));

    const typed = bindValue();
    const url = screen.getByLabelText("URL");
    await userEvent.clear(url);
    await userEvent.type(url, "ldaps://ldap.example.com");
    await userEvent.type(screen.getByLabelText("Bind DN"), "cn=svc,dc=example,dc=com");
    await userEvent.type(screen.getByLabelText("Bind secret (required)"), typed);
    await userEvent.type(screen.getByLabelText("Base DN"), "dc=example,dc=com");
    await userEvent.click(screen.getByRole("button", { name: /^Create$/ }));

    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    const [url_, body] = apiMock.put.mock.calls[0];
    expect(url_).toBe(BASE);
    expect(body).toMatchObject({
      enabled: true,
      kind: "open_ldap",
      url: "ldaps://ldap.example.com",
      start_tls: false,
      bind_dn: "cn=svc,dc=example,dc=com",
      base_dn: "dc=example,dc=com",
      bind_secret: typed,
    });
    expect(await screen.findByText(/configuration created/i)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(typed);
  });

  it("refuses to submit without a secret, and says so", async () => {
    mockGets({ stored: null });
    renderWithProviders(<DirectoryPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Configure a directory/ }));
    const url = screen.getByLabelText("URL");
    await userEvent.clear(url);
    await userEvent.type(url, "ldaps://ldap.example.com");
    await userEvent.type(screen.getByLabelText("Bind DN"), "cn=svc");
    await userEvent.type(screen.getByLabelText("Base DN"), "dc=x");
    await userEvent.click(screen.getByRole("button", { name: /^Create$/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Enter the bind secret.");
    expect(apiMock.put).not.toHaveBeenCalled();
  });
});

describe("DirectoryPage — editing", () => {
  it("never pre-fills the secret field", async () => {
    mockGets();
    renderWithProviders(<DirectoryPage />);
    await openEdit();
    const field = screen.getByLabelText("Bind secret") as HTMLInputElement;
    expect(field.value).toBe("");
    expect(field.type).toBe("password");
    expect(field.autocomplete).toBe("new-password");
  });

  it("sends only what changed — and no secret — for an edit that leaves the connection alone", async () => {
    mockGets();
    apiMock.patch.mockResolvedValue(res(config({ jit_provisioning: true })));
    renderWithProviders(<DirectoryPage />);
    await openEdit();
    expect(screen.queryByText(/Enter the bind secret again/)).not.toBeInTheDocument();
    await userEvent.click(screen.getByLabelText("Provision accounts at first sign-in"));
    await userEvent.click(screen.getByRole("button", { name: /Save changes/ }));
    await waitFor(() => expect(apiMock.patch).toHaveBeenCalledTimes(1));
    expect(apiMock.patch).toHaveBeenCalledWith(BASE, { jit_provisioning: true });
  });

  it("asks for the secret again as soon as the URL changes, and will not save without it", async () => {
    mockGets();
    renderWithProviders(<DirectoryPage />);
    await openEdit();
    const url = screen.getByLabelText("URL");
    await userEvent.clear(url);
    await userEvent.type(url, "ldaps://other.example.com");

    expect(await screen.findByText(/You changed the URL/)).toBeInTheDocument();
    expect(screen.getByLabelText("Bind secret (required)")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Save changes/ }));
    expect((await screen.findAllByRole("alert")).map((a) => a.textContent).join(" ")).toMatch(
      /Enter the bind secret again/,
    );
    expect(apiMock.patch).not.toHaveBeenCalled();
  });

  it.each([
    ["StartTLS", "Use StartTLS", null],
    ["bind DN", "Bind DN", "cn=other,dc=example,dc=com"],
    ["trust anchors", "Trust anchors (PEM)", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"],
  ])("asks for the secret again when the %s changes", async (what, label, typed) => {
    mockGets();
    renderWithProviders(<DirectoryPage />);
    await openEdit();
    const field = screen.getByLabelText(label);
    if (typed === null) {
      await userEvent.click(field);
    } else {
      await userEvent.clear(field);
      await userEvent.type(field, typed.replaceAll("\n", "{Enter}"));
    }
    expect(await screen.findByText(new RegExp(`You changed the .*${what}`))).toBeInTheDocument();
  });

  it("sends the URL with the secret once it is entered, and clears the field after", async () => {
    mockGets();
    apiMock.patch.mockResolvedValue(res(config({ url: "ldaps://other.example.com" })));
    renderWithProviders(<DirectoryPage />);
    await openEdit();
    const url = screen.getByLabelText("URL");
    await userEvent.clear(url);
    await userEvent.type(url, "ldaps://other.example.com");
    const typed = bindValue();
    await userEvent.type(screen.getByLabelText("Bind secret (required)"), typed);
    await userEvent.click(screen.getByRole("button", { name: /Save changes/ }));
    await waitFor(() => expect(apiMock.patch).toHaveBeenCalledTimes(1));
    expect(apiMock.patch).toHaveBeenCalledWith(BASE, {
      url: "ldaps://other.example.com",
      bind_secret: typed,
    });
    expect(await screen.findByText(/configuration saved/i)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(typed);
  });

  it("shows a 400 rule verbatim and does not keep the typed secret", async () => {
    mockGets();
    const rule = "directory url: the directory host resolves to a loopback address (refused)";
    apiMock.patch.mockImplementation(() => rejection(400, "validation_error", rule));
    renderWithProviders(<DirectoryPage />);
    await openEdit();
    const url = screen.getByLabelText("URL");
    await userEvent.clear(url);
    await userEvent.type(url, "ldaps://loopback.example.com");
    await userEvent.type(screen.getByLabelText("Bind secret (required)"), bindValue());
    await userEvent.click(screen.getByRole("button", { name: /Save changes/ }));
    expect(await screen.findByText(rule)).toBeInTheDocument();
    expect((screen.getByLabelText("Bind secret (required)") as HTMLInputElement).value).toBe("");
  });

  it("shows the opaque_mode conflict (409) verbatim", async () => {
    mockGets({ stored: config({ enabled: false }) });
    const conflict =
      "an enabled directory cannot coexist with opaque_mode `required`: under `required` the tenant refuses password sign-in";
    apiMock.patch.mockImplementation(() => rejection(409, "conflict", conflict));
    renderWithProviders(<DirectoryPage />);
    await openEdit();
    await userEvent.click(screen.getByLabelText("Enabled"));
    await userEvent.click(screen.getByRole("button", { name: /Save changes/ }));
    expect(await screen.findByText(conflict)).toBeInTheDocument();
  });

  it("replaces with PUT carrying every member and no secret when the connection is unchanged", async () => {
    mockGets();
    apiMock.put.mockResolvedValue(res(config()));
    renderWithProviders(<DirectoryPage />);
    await userEvent.click(await screen.findByRole("button", { name: /^Replace$/ }));
    expect(screen.getByText(/saves every member of this form/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /^Replace$/ }));
    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    const body = apiMock.put.mock.calls[0][1];
    expect(body.bind_secret).toBeUndefined();
    expect(body.group_mappings).toEqual([]);
    expect(body.group_filter).toBeNull();
    expect(body.url).toBe("ldaps://ldap.example.com");
  });

  it("edits the group-mapping table with an AXIAM group picker", async () => {
    mockGets();
    apiMock.patch.mockResolvedValue(res(config()));
    renderWithProviders(<DirectoryPage />);
    await openEdit();
    await userEvent.click(screen.getByRole("button", { name: /Add mapping/ }));
    await userEvent.type(
      screen.getByLabelText("Directory group DN for mapping 1"),
      "cn=staff,ou=groups,dc=example,dc=com",
    );
    const picker = screen.getByLabelText("AXIAM group for mapping 1");
    await waitFor(() => expect(within(picker).getByRole("option", { name: "Staff" })).toBeInTheDocument());
    await userEvent.selectOptions(picker, "g1");
    await userEvent.click(screen.getByRole("button", { name: /Save changes/ }));
    await waitFor(() => expect(apiMock.patch).toHaveBeenCalledTimes(1));
    expect(apiMock.patch).toHaveBeenCalledWith(BASE, {
      group_mappings: [{ directory_group_dn: "cn=staff,ou=groups,dc=example,dc=com", group_id: "g1" }],
    });
  });

  it("will not save a mapping row with no group", async () => {
    mockGets();
    renderWithProviders(<DirectoryPage />);
    await openEdit();
    await userEvent.click(screen.getByRole("button", { name: /Add mapping/ }));
    await userEvent.type(screen.getByLabelText("Directory group DN for mapping 1"), "cn=staff");
    await userEvent.click(screen.getByRole("button", { name: /Save changes/ }));
    expect(await screen.findByText(/choose an AXIAM group/)).toBeInTheDocument();
    expect(apiMock.patch).not.toHaveBeenCalled();
  });

  it("removes a mapping row", async () => {
    mockGets({
      stored: config({
        group_mappings: [{ directory_group_dn: "cn=staff,ou=groups", group_id: "g1" }],
      }),
    });
    apiMock.patch.mockResolvedValue(res(config()));
    renderWithProviders(<DirectoryPage />);
    await openEdit();
    await userEvent.click(screen.getByRole("button", { name: "Remove mapping 1" }));
    await userEvent.click(screen.getByRole("button", { name: /Save changes/ }));
    await waitFor(() => expect(apiMock.patch).toHaveBeenCalledTimes(1));
    expect(apiMock.patch).toHaveBeenCalledWith(BASE, { group_mappings: [] });
  });

  it("cancels back to the summary without a request", async () => {
    mockGets();
    renderWithProviders(<DirectoryPage />);
    await openEdit();
    await userEvent.click(screen.getByRole("button", { name: /Cancel/ }));
    expect(await screen.findByText(/Write-only — never shown/)).toBeInTheDocument();
    expect(apiMock.patch).not.toHaveBeenCalled();
    expect(apiMock.put).not.toHaveBeenCalled();
  });
});

describe("DirectoryPage — deleting", () => {
  it("says what it leaves behind, and deletes on confirmation", async () => {
    mockGets();
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<DirectoryPage />);
    await userEvent.click(await screen.findByRole("button", { name: /^Delete$/ }));
    expect(screen.getByText(/keep working until they expire/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Delete directory/ }));
    await waitFor(() => expect(apiMock.delete).toHaveBeenCalledWith(BASE));
    expect(await screen.findByText(/configuration deleted/i)).toBeInTheDocument();
  });
});

describe("DirectoryPage — sync status", () => {
  it("shows a never-run job plainly", async () => {
    mockGets();
    renderWithProviders(<DirectoryPage />);
    expect(await screen.findByText("Not run yet")).toBeInTheDocument();
    expect(screen.getByText("Full reconciliation")).toBeInTheDocument();
  });

  it("explains the safety valve", async () => {
    mockGets({
      status: {
        last_result: "safety_valve",
        last_attempt_at: "2026-10-03T10:00:00Z",
        last_full_run_at: null,
        full_required: true,
        has_watermark: false,
      },
    });
    renderWithProviders(<DirectoryPage />);
    expect(await screen.findByText("Safety valve")).toBeInTheDocument();
    expect(screen.getByText(/more than 10% of this tenant/)).toBeInTheDocument();
  });

  it("shows a result it does not know as it is", async () => {
    mockGets({ status: { ...freshStatus, last_result: "brand_new_result" } });
    renderWithProviders(<DirectoryPage />);
    expect(await screen.findByText("brand_new_result")).toBeInTheDocument();
  });
});

describe("DirectoryPage — linking an account", () => {
  async function pickAlice() {
    await userEvent.click(await screen.findByRole("button", { name: /Link an account…/ }));
    await userEvent.type(screen.getByLabelText("Search users"), "al");
    await userEvent.click(await screen.findByRole("button", { name: "Link" }));
  }

  it("warns that the owner is signed out everywhere, then links after confirmation", async () => {
    mockGets();
    apiMock.post.mockResolvedValue(
      res({
        user_id: alice.id,
        directory_external_id: "entry-1",
        webauthn_credentials_deleted: 2,
        certificates_revoked: 1,
        was_already_linked: false,
      }),
    );
    renderWithProviders(<DirectoryPage />);
    expect(await screen.findByText(/The owner is signed out everywhere/)).toBeInTheDocument();
    await pickAlice();
    expect(apiMock.post).not.toHaveBeenCalled();
    await userEvent.click(await screen.findByRole("button", { name: /Link account/ }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(`${BASE}/links`, { user_id: alice.id }),
    );
    expect(await screen.findByText(/alice is linked to directory entry entry-1/)).toBeInTheDocument();
    expect(screen.getByText(/2 passkey\(s\) deleted, 1 certificate\(s\) revoked/)).toBeInTheDocument();
  });

  it("shows the directory's own refusal verbatim", async () => {
    mockGets();
    const refusal = "that directory entry is already linked to another account";
    apiMock.post.mockImplementation(() => rejection(409, "conflict", refusal));
    renderWithProviders(<DirectoryPage />);
    await pickAlice();
    await userEvent.click(await screen.findByRole("button", { name: /Link account/ }));
    expect(await screen.findByText(refusal)).toBeInTheDocument();
  });

  it("is unavailable while the directory is disabled", async () => {
    mockGets({ stored: config({ enabled: false }) });
    renderWithProviders(<DirectoryPage />);
    const button = await screen.findByRole("button", { name: /Link an account…/ });
    expect(button).toBeDisabled();
    expect(screen.getByText(/Enable the directory to link accounts/)).toBeInTheDocument();
  });

  it("is not offered without directory:link", async () => {
    useAuthStore.setState({
      user: { ...adminUser, permissions: ["directory:read", "directory:write"] },
    });
    mockGets();
    renderWithProviders(<DirectoryPage />);
    await screen.findByText("ldaps://ldap.example.com");
    expect(screen.queryByText(/Link an existing account/)).not.toBeInTheDocument();
  });
});
