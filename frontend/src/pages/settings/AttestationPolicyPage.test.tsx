import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { AttestationPolicyPage } from "./AttestationPolicyPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore, type AuthUser } from "@/stores/auth";
import { DEFAULT_ATTESTATION_POLICY } from "@/services/webauthnPolicy";
import type { WebauthnAttestationPolicy } from "@/services/webauthnPolicy";
import type { MdsStatus } from "@/services/mds";

const adminUser: AuthUser = {
  id: "u1",
  username: "admin",
  email: "a@x.io",
  permissions: ["*"],
  tenant_id: "t1",
  tenantSlug: "acme",
  orgSlug: "acme-org",
};

const readOnlyUser: AuthUser = {
  ...adminUser,
  permissions: ["webauthn_policy:read", "ca_certificates:list"],
};

const complianceReport = [
  {
    credential_id: "c1",
    user_id: "u1",
    name: "Work laptop",
    aaguid: "ee882879-721c-4913-9775-3dfcce97072a",
    authenticator_name: "YubiKey 5",
    compliant: true,
    reason: null,
  },
  {
    credential_id: "c2",
    user_id: "u2",
    name: "Old passkey",
    aaguid: null,
    authenticator_name: null,
    compliant: true,
    reason: "registered before attestation policy was enabled",
  },
  {
    credential_id: "c3",
    user_id: "u3",
    name: "Untrusted key",
    aaguid: "11111111-1111-1111-1111-111111111111",
    authenticator_name: "Unknown Vendor",
    compliant: false,
    reason: "aaguid_blocked",
  },
];

const mdsStatus: MdsStatus = {
  no: 42,
  next_update: "2026-09-01",
  entry_count: 1200,
  last_refreshed_at: "2026-08-01T00:00:00Z",
  stale: false,
};

/** Route every GET this page issues to its payload, by URL. */
function mockGets({
  policy = DEFAULT_ATTESTATION_POLICY,
  report = complianceReport,
  mds = mdsStatus,
}: {
  policy?: WebauthnAttestationPolicy;
  report?: typeof complianceReport;
  mds?: MdsStatus;
} = {}) {
  apiMock.get.mockImplementation((url: string) => {
    if (url === "/api/v1/tenants/t1/webauthn/attestation-policy") {
      return Promise.resolve(res(policy));
    }
    if (url === "/api/v1/tenants/t1/webauthn/compliance-report") {
      return Promise.resolve(res(report));
    }
    if (url === "/api/v1/mds/status") {
      return Promise.resolve(res(mds));
    }
    return Promise.reject(new Error(`unexpected GET ${url}`));
  });
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

describe("AttestationPolicyPage — policy summary", () => {
  it("shows the default policy in view mode", async () => {
    mockGets();
    renderWithProviders(<AttestationPolicyPage />);

    expect(
      await screen.findByText(/None \(default\)/),
    ).toBeInTheDocument();
    expect(screen.getByText("All except blocked")).toBeInTheDocument();
  });

  it("hides the Edit Policy button for a user without write permission", async () => {
    useAuthStore.setState({ user: readOnlyUser });
    mockGets();
    renderWithProviders(<AttestationPolicyPage />);

    await screen.findByText(/None \(default\)/);
    expect(
      screen.queryByRole("button", { name: /Edit Policy/ }),
    ).not.toBeInTheDocument();
  });
});

describe("AttestationPolicyPage — passkey caveat", () => {
  it("shows no caveat banner while mode is none", async () => {
    mockGets();
    renderWithProviders(<AttestationPolicyPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Policy/ }));

    expect(
      screen.queryByText(/iCloud Keychain/),
    ).not.toBeInTheDocument();
  });

  it("surfaces the caveat the moment a non-none mode is chosen, and blocks save until acknowledged", async () => {
    mockGets();
    renderWithProviders(<AttestationPolicyPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Policy/ }));

    await userEvent.selectOptions(
      screen.getByLabelText("Mode"),
      "direct_required",
    );

    // Caveat must appear immediately, before any save attempt.
    const caveat = await screen.findByRole("alert");
    expect(caveat.textContent).toMatch(/iCloud Keychain/);
    // And it must say the caveat applies to indirect too, not just direct_required.
    expect(caveat.textContent).toMatch(/Indirect mode exactly as much as Direct required/);

    await userEvent.click(screen.getByRole("button", { name: /Save Policy/ }));
    expect(
      await screen.findByText(/Acknowledge the passkey caveat/),
    ).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("also shows the caveat for indirect mode, not only direct_required", async () => {
    mockGets();
    renderWithProviders(<AttestationPolicyPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Policy/ }));

    await userEvent.selectOptions(screen.getByLabelText("Mode"), "indirect");
    const caveat = await screen.findByRole("alert");
    expect(caveat.textContent).toMatch(/iCloud Keychain/);
  });

  it("saves once the caveat is acknowledged", async () => {
    mockGets();
    apiMock.put.mockResolvedValue(
      res({ ...DEFAULT_ATTESTATION_POLICY, mode: "direct_required" }),
    );
    renderWithProviders(<AttestationPolicyPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Policy/ }));

    await userEvent.selectOptions(screen.getByLabelText("Mode"), "direct_required");
    await userEvent.click(
      screen.getByRole("checkbox", { name: /I understand this excludes iCloud Keychain/ }),
    );
    await userEvent.click(screen.getByRole("button", { name: /Save Policy/ }));

    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    const [, body] = apiMock.put.mock.calls[0];
    expect(body.mode).toBe("direct_required");
  });
});

describe("AttestationPolicyPage — unknown_aaguid tri-state", () => {
  it("defaults to 'Use mode default' and shows the resolved action for the selected mode", async () => {
    mockGets();
    renderWithProviders(<AttestationPolicyPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Policy/ }));

    // mode = none -> resolves to Allow.
    expect(
      screen.getByText(/Use mode default — currently resolves to Allow/),
    ).toBeInTheDocument();

    await userEvent.selectOptions(screen.getByLabelText("Mode"), "direct_required");
    await userEvent.click(
      screen.getByRole("checkbox", { name: /I understand this excludes iCloud Keychain/ }),
    );

    expect(
      screen.getByText(/Use mode default — currently resolves to Deny/),
    ).toBeInTheDocument();
  });

  it("sends null on the wire for the default option, and an explicit value when chosen", async () => {
    mockGets();
    apiMock.put.mockResolvedValue(res(DEFAULT_ATTESTATION_POLICY));
    renderWithProviders(<AttestationPolicyPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Policy/ }));

    await userEvent.selectOptions(
      screen.getByLabelText("Unknown AAGUID (no FIDO metadata)"),
      "deny",
    );
    await userEvent.click(screen.getByRole("button", { name: /Save Policy/ }));

    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    expect(apiMock.put.mock.calls[0][1].unknown_aaguid).toBe("deny");
  });

  it("clears require_fido_certified and min_certification when switching back to mode none", async () => {
    mockGets({
      policy: {
        ...DEFAULT_ATTESTATION_POLICY,
        mode: "direct_required",
        require_fido_certified: true,
        min_certification: "L2",
      },
    });
    apiMock.put.mockResolvedValue(res(DEFAULT_ATTESTATION_POLICY));
    renderWithProviders(<AttestationPolicyPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Policy/ }));

    await userEvent.selectOptions(screen.getByLabelText("Mode"), "none");
    await userEvent.click(screen.getByRole("button", { name: /Save Policy/ }));

    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    const body = apiMock.put.mock.calls[0][1];
    expect(body.require_fido_certified).toBe(false);
    expect(body.min_certification).toBeNull();
  });

  it("refreshes the compliance report after saving the policy", async () => {
    // The report is the server's verdict on THIS policy. Invalidating only the
    // policy left the verdict beside the form contradicting the policy in it
    // for up to the 60s stale time — the operator saved a stricter policy and
    // the panel next to the button kept saying the tenant was compliant.
    mockGets();
    apiMock.put.mockResolvedValue(res(DEFAULT_ATTESTATION_POLICY));
    const { client } = renderWithProviders(<AttestationPolicyPage />);
    const invalidate = vi.spyOn(client, "invalidateQueries");

    await userEvent.click(await screen.findByRole("button", { name: /Edit Policy/ }));
    await userEvent.click(screen.getByRole("button", { name: /Save Policy/ }));

    await waitFor(() =>
      expect(invalidate).toHaveBeenCalledWith({
        queryKey: ["webauthn-compliance-report"],
      })
    );
    expect(invalidate).toHaveBeenCalledWith({
      queryKey: ["webauthn-attestation-policy"],
    });
  });
});

describe("AttestationPolicyPage — compliance report", () => {
  it("renders compliant, unknown and violation rows as visually distinct, never mislabeling unknown as a violation", async () => {
    mockGets();
    renderWithProviders(<AttestationPolicyPage />);

    const table = await screen.findByText("Work laptop");
    const row1 = table.closest("tr")!;
    expect(within(row1).getByText("Compliant")).toBeInTheDocument();

    const row2 = screen.getByText("Old passkey").closest("tr")!;
    expect(within(row2).getByText("Unknown")).toBeInTheDocument();
    expect(within(row2).queryByText("Violation")).not.toBeInTheDocument();
    expect(
      within(row2).getByText(/registered before attestation policy was enabled/),
    ).toBeInTheDocument();

    const row3 = screen.getByText("Untrusted key").closest("tr")!;
    expect(within(row3).getByText("Violation")).toBeInTheDocument();
  });

  it("never renders a revoke/delete action — revocation stays the per-credential admin delete path", async () => {
    mockGets();
    renderWithProviders(<AttestationPolicyPage />);
    await screen.findByText("Work laptop");

    expect(
      screen.queryByRole("button", { name: /revoke/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /delete/i }),
    ).not.toBeInTheDocument();
    // The only per-row action is a link to the user, not a mutation.
    expect(screen.getAllByRole("link", { name: "View user" }).length).toBe(3);
  });
});

describe("AttestationPolicyPage — MDS status panel", () => {
  it("renders serial, next_update, entry_count, last_refreshed_at and freshness", async () => {
    mockGets();
    renderWithProviders(<AttestationPolicyPage />);

    expect(await screen.findByText("42")).toBeInTheDocument();
    expect(screen.getByText("2026-09-01")).toBeInTheDocument();
    // Formatted the same way the component formats it. `entry_count` is
    // rendered with a bare `toLocaleString()`, which follows the HOST locale —
    // so a hard-coded "1,200" asserts en-US grouping and fails for every
    // developer whose machine is set to anything else (it-IT renders "1.200").
    // CI happened to run in a locale where the literal held, which is why this
    // only ever broke locally.
    expect(screen.getByText((1200).toLocaleString())).toBeInTheDocument();
    expect(screen.getByText("Fresh")).toBeInTheDocument();
  });

  it("shows a stale badge when the server reports stale: true", async () => {
    mockGets({ mds: { ...mdsStatus, stale: true } });
    renderWithProviders(<AttestationPolicyPage />);
    expect(await screen.findByText(/Stale — past next_update/)).toBeInTheDocument();
  });

  it("shows a never-ingested explanation rather than blank fields", async () => {
    mockGets({
      mds: { no: null, next_update: null, entry_count: 0, last_refreshed_at: null, stale: false },
    });
    renderWithProviders(<AttestationPolicyPage />);
    expect(
      await screen.findByText(/MDS has never been ingested/),
    ).toBeInTheDocument();
  });

  it("refresh button triggers POST /api/v1/mds/refresh and shows the outcome", async () => {
    mockGets();
    apiMock.post.mockResolvedValue(
      res({ outcome: "replaced", no: 43, entry_count: 1250 }),
    );
    renderWithProviders(<AttestationPolicyPage />);

    await userEvent.click(await screen.findByRole("button", { name: /Refresh now/ }));

    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/mds/refresh");
    expect(
      await screen.findByText(/Ingested a newer BLOB — serial 43/),
    ).toBeInTheDocument();
  });

  it("hides the refresh button and shows a permission note for a user without ca_certificates:generate/list", async () => {
    useAuthStore.setState({ user: { ...adminUser, permissions: ["webauthn_policy:read"] } });
    mockGets();
    renderWithProviders(<AttestationPolicyPage />);

    await screen.findByText(/None \(default\)/);
    expect(
      screen.queryByRole("button", { name: /Refresh now/ }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/don.t have permission to view MDS/),
    ).toBeInTheDocument();
  });
});
