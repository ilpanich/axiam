import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, within, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { CertificatesPage } from "./CertificatesPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore } from "@/stores/auth";
import { setToastDispatch } from "@/hooks/useToast";

const soon = new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString();
const far = new Date(Date.now() + 400 * 24 * 60 * 60 * 1000).toISOString();

const certs = [
  {
    id: "c1",
    tenant_id: "t1",
    issuer_ca_id: "ca1",
    subject: "CN=device-001",
    public_cert_pem: "PEM",
    fingerprint: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55",
    cert_type: "Device",
    key_algorithm: "Rsa4096",
    not_before: "2026-01-01T00:00:00Z",
    not_after: soon,
    status: "Active",
    metadata: null,
    created_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "c2",
    tenant_id: "t1",
    issuer_ca_id: "ca1",
    subject: "CN=user-1",
    public_cert_pem: "PEM",
    fingerprint: "short",
    cert_type: "User",
    key_algorithm: "Ed25519",
    not_before: "2026-01-01T00:00:00Z",
    not_after: far,
    status: "Revoked",
    metadata: null,
    created_at: "2026-01-02T00:00:00Z",
  },
  {
    id: "c3",
    tenant_id: "t1",
    issuer_ca_id: "ca1",
    subject: "CN=svc-1",
    public_cert_pem: "PEM",
    fingerprint: "expired-fp",
    cert_type: "Service",
    key_algorithm: "Rsa4096",
    not_before: "2020-01-01T00:00:00Z",
    not_after: "2021-01-01T00:00:00Z",
    status: "Expired",
    metadata: null,
    created_at: "2020-01-01T00:00:00Z",
  },
];

const orgs = [{ id: "org1", name: "Acme", slug: "acme", created_at: "2026-01-01T00:00:00Z" }];

const activeCa = {
  id: "ca1",
  organization_id: "org1",
  subject: "CN=Acme Root CA",
  fingerprint: "ca-fp",
  key_algorithm: "Rsa4096",
  not_after: "2030-01-01T00:00:00Z",
  status: "Active",
  created_at: "2026-01-01T00:00:00Z",
};

const revokedCa = { ...activeCa, id: "ca2", status: "Revoked" };

function mockGetRoutes({
  certificates = certs,
  organizations = orgs,
  caCertificates = [activeCa],
}: {
  certificates?: unknown[];
  organizations?: unknown[];
  caCertificates?: unknown[];
} = {}) {
  apiMock.get.mockImplementation((url: string) => {
    if (url.includes("ca-certificates")) return Promise.resolve(res(caCertificates));
    if (url.includes("/organizations")) return Promise.resolve(res(organizations));
    if (url.includes("/certificates")) return Promise.resolve(res(certificates));
    return Promise.resolve(res([]));
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  useAuthStore.setState({
    user: { id: "u1", username: "admin", email: "a@x.io", permissions: ["*"], tenant_id: "t1" },
    tenantSlug: "acme-tenant",
    orgSlug: "acme",
    isAuthenticated: true,
    isInitializing: false,
  });
});

afterEach(() => {
  setToastDispatch(null);
});

describe("CertificatesPage", () => {
  it("renders fetched certificates with status, expiry highlighting, and truncated fingerprint", async () => {
    mockGetRoutes();
    renderWithProviders(<CertificatesPage />);
    expect(await screen.findByText("CN=device-001")).toBeInTheDocument();
    expect(screen.getByText("CN=user-1")).toBeInTheDocument();
    expect(screen.getByText("CN=svc-1")).toBeInTheDocument();
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText("Revoked")).toBeInTheDocument();
    expect(screen.getByText("Inactive")).toBeInTheDocument(); // Expired badge
    // A fingerprint longer than 17 chars is truncated to the first 17 plus an
    // ellipsis, with the full value preserved in the title attribute.
    const fpCell = screen.getByTitle("AA:BB:CC:DD:EE:FF:00:11:22:33:44:55");
    expect(fpCell).toHaveTextContent("AA:BB:CC:DD:EE:FF…");
    expect(screen.getByText("short")).toBeInTheDocument();
  });

  it("disables the revoke action for non-active certificates", async () => {
    mockGetRoutes();
    renderWithProviders(<CertificatesPage />);
    await screen.findByText("CN=user-1");
    expect(
      screen.getByRole("button", { name: "Revoke certificate for CN=user-1" })
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Revoke certificate for CN=device-001" })
    ).toBeEnabled();
  });

  it("shows the empty state when there are no certificates", async () => {
    mockGetRoutes({ certificates: [] });
    renderWithProviders(<CertificatesPage />);
    expect(await screen.findByText("No certificates found.")).toBeInTheDocument();
  });

  it("shows a 'no active CA' message and blocks generation when no CA is available", async () => {
    mockGetRoutes({ caCertificates: [revokedCa] });
    renderWithProviders(<CertificatesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Generate Certificate/ }));
    const dialog = screen.getByRole("dialog");
    expect(
      within(dialog).getByText("No active CA available")
    ).toBeInTheDocument();
    expect(
      within(dialog).getByText(/Create an organization CA certificate first/)
    ).toBeInTheDocument();
    await userEvent.type(within(dialog).getByLabelText("Subject *"), "CN=x");
    await userEvent.click(within(dialog).getByRole("button", { name: "Generate" }));
    expect(
      await screen.findByText("An active CA certificate is required.")
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("shows a loading indicator for CA options while orgs are still resolving", async () => {
    let resolveOrgs!: (v: unknown) => void;
    const pendingOrgs = new Promise((resolve) => {
      resolveOrgs = resolve;
    });
    apiMock.get.mockImplementation((url: string) => {
      if (url.includes("/organizations")) return pendingOrgs;
      if (url.includes("/certificates")) return Promise.resolve(res(certs));
      return Promise.resolve(res([]));
    });
    renderWithProviders(<CertificatesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Generate Certificate/ }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText("Loading CAs…")).toBeInTheDocument();
    resolveOrgs(res(orgs));
    await waitFor(() => expect(apiMock.get).toHaveBeenCalled());
  });

  it("validates that a non-blank subject is required before generating", async () => {
    mockGetRoutes();
    renderWithProviders(<CertificatesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Generate Certificate/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Subject *"), "   ");
    await userEvent.click(within(dialog).getByRole("button", { name: "Generate" }));
    expect(await screen.findByText("Subject is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("generates a certificate and reveals the private key once", async () => {
    mockGetRoutes();
    apiMock.post.mockResolvedValue(
      res({
        ...certs[0],
        id: "c99",
        subject: "CN=device-002",
        private_key_pem: "-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----",
      })
    );
    renderWithProviders(<CertificatesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Generate Certificate/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Subject *"), "CN=device-002");
    await userEvent.selectOptions(within(dialog).getByLabelText("Certificate Type"), "Service");
    await userEvent.selectOptions(within(dialog).getByLabelText("Key Algorithm"), "Ed25519");
    const validityInput = within(dialog).getByLabelText("Validity Days");
    await userEvent.clear(validityInput);
    await userEvent.type(validityInput, "90");
    await userEvent.click(within(dialog).getByRole("button", { name: "Generate" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/certificates", {
        issuer_ca_id: "ca1",
        subject: "CN=device-002",
        cert_type: "Service",
        key_algorithm: "Ed25519",
        validity_days: 90,
      })
    );

    expect(await screen.findByText("Certificate Generated")).toBeInTheDocument();
    // The PEM renders in a <pre> preserving newlines. getByText's default
    // normalizer collapses the node's newlines to spaces but leaves the raw
    // matcher string untouched, so match on the exact rendered node text.
    const pemValue = "-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----";
    expect(
      screen.getByText(
        (_, node) => node?.tagName === "PRE" && node.textContent === pemValue
      )
    ).toBeInTheDocument();
    await userEvent.click(
      screen.getByRole("button", { name: "I've saved this information" })
    );
    expect(screen.queryByText("Certificate Generated")).not.toBeInTheDocument();
  });

  it("surfaces a generate error via inline message and toast", async () => {
    mockGetRoutes();
    const toastSpy = vi.fn();
    setToastDispatch(toastSpy);
    apiMock.post.mockRejectedValue(new Error("CA is not active"));
    renderWithProviders(<CertificatesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Generate Certificate/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Subject *"), "CN=fail");
    await userEvent.click(within(dialog).getByRole("button", { name: "Generate" }));
    expect(await screen.findByText("CA is not active")).toBeInTheDocument();
    expect(toastSpy).toHaveBeenCalledWith({
      description: "CA is not active",
      variant: "destructive",
    });
  });

  it("revokes a certificate after confirmation", async () => {
    mockGetRoutes();
    apiMock.post.mockResolvedValue(res(undefined));
    renderWithProviders(<CertificatesPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Revoke certificate for CN=device-001" })
    );
    const dialog = screen.getByRole("dialog");
    expect(
      within(dialog).getByText(/Are you sure you want to revoke the certificate for "CN=device-001"/)
    ).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Revoke" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/certificates/c1/revoke")
    );
  });

  it("surfaces a revoke error via toast", async () => {
    mockGetRoutes();
    const toastSpy = vi.fn();
    setToastDispatch(toastSpy);
    apiMock.post.mockRejectedValue(new Error("Cannot revoke"));
    renderWithProviders(<CertificatesPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Revoke certificate for CN=device-001" })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Revoke" }));
    await waitFor(() =>
      expect(toastSpy).toHaveBeenCalledWith({
        description: "Cannot revoke",
        variant: "destructive",
      })
    );
  });

  it("closes the generate dialog via cancel and resets the form", async () => {
    mockGetRoutes();
    renderWithProviders(<CertificatesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Generate Certificate/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Subject *"), "CN=temp");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
