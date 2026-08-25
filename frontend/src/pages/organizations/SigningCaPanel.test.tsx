import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { SigningCaPanel } from "./SigningCaPanel";
import { renderWithProviders } from "@/test/renderWithProviders";

const orgCa = {
  id: "ca1",
  organization_id: "org1",
  subject: "CN=Acme Root CA",
  public_cert_pem: "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----",
  fingerprint: "ca-fp",
  key_algorithm: "Ed25519",
  status: "Active",
  key_custody: "vault_pki",
  not_before: "2026-01-01T00:00:00Z",
  not_after: "2036-01-01T00:00:00Z",
};

/** A CA imported as a trust anchor: no key, so it cannot sign anything. */
const anchorOnlyCa = {
  ...orgCa,
  id: "ca2",
  subject: "CN=Partner Anchor",
  key_custody: "external",
};

/** A tenant signing CA — path length zero, so it cannot parent another. */
const existingSigningCa = {
  ...orgCa,
  id: "sca1",
  subject: "CN=Acme R&D Signing CA",
  tenant_id: "t1",
  parent_ca_id: "ca1",
  key_custody: "vault_pki",
  chain_pem: "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----",
};

function mockRoutes({
  signingCas = [existingSigningCa],
  caCertificates = [orgCa, anchorOnlyCa, existingSigningCa],
}: { signingCas?: unknown[]; caCertificates?: unknown[] } = {}) {
  apiMock.get.mockImplementation((url: string) => {
    if (url.includes("/signing-cas")) return Promise.resolve(res(signingCas));
    if (url.includes("/ca-certificates"))
      return Promise.resolve(res(caCertificates));
    return Promise.resolve(res([]));
  });
}

function renderPanel() {
  return renderWithProviders(
    <SigningCaPanel orgId="org1" tenantId="t1" tenantName="R&D" />
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("SigningCaPanel", () => {
  it("lists the tenant's signing CAs", async () => {
    mockRoutes();
    renderPanel();
    expect(await screen.findByText("CN=Acme R&D Signing CA")).toBeInTheDocument();
    expect(
      apiMock.get.mock.calls.some((call) =>
        String(call[0]).includes("/organizations/org1/tenants/t1/signing-cas")
      )
    ).toBe(true);
  });

  it("offers only organization CAs that can actually sign as the parent", async () => {
    const user = userEvent.setup();
    mockRoutes();
    renderPanel();
    await screen.findByText("CN=Acme R&D Signing CA");

    await user.click(screen.getByRole("button", { name: /Create Signing CA/ }));
    const select = await screen.findByLabelText(/Signed by/);
    const options = within(select).getAllByRole("option");
    const labels = options.map((o) => o.textContent);

    expect(labels).toContain("CN=Acme Root CA");
    // A trust anchor AXIAM holds no key for cannot sign, and the server refuses
    // it — offering it here would be an invitation to a 400.
    expect(labels).not.toContain("CN=Partner Anchor");
    // A tenant signing CA has a path length of zero and cannot parent another.
    expect(labels).not.toContain("CN=Acme R&D Signing CA");
  });

  it("creates a signing CA and reveals the private key exactly once", async () => {
    const user = userEvent.setup();
    mockRoutes();
    apiMock.post.mockResolvedValue(
      res({
        ...existingSigningCa,
        id: "sca2",
        subject: "CN=New Signing CA",
        private_key_pem: "-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----",
      })
    );
    renderPanel();
    await screen.findByText("CN=Acme R&D Signing CA");

    await user.click(screen.getByRole("button", { name: /Create Signing CA/ }));
    await user.type(screen.getByLabelText(/Subject/), "CN=New Signing CA");
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(apiMock.post).toHaveBeenCalledTimes(1));
    const [url, payload] = apiMock.post.mock.calls[0];
    expect(url).toBe("/api/v1/organizations/org1/tenants/t1/signing-cas");
    expect(payload).toMatchObject({
      parent_ca_id: "ca1",
      subject: "CN=New Signing CA",
      key_algorithm: "Ed25519",
    });

    expect(await screen.findByText("Signing CA Created")).toBeInTheDocument();
    // Matched on `textContent` rather than by string: `getByText` collapses
    // whitespace on both sides, which flattens a multi-line PEM into one line
    // and stops it matching the `<pre>` it was rendered into.
    expect(
      screen.getByText(
        (_content, element) =>
          element?.tagName === "PRE" &&
          element.textContent ===
            "-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----"
      )
    ).toBeInTheDocument();
  });

  it("does not claim a key was withheld when the custodian produced none", async () => {
    const user = userEvent.setup();
    mockRoutes();
    // Vault's PKI engine generates the key inside itself and exports nothing,
    // so the response omits the field. A reveal modal here would tell the
    // operator to save something that does not exist.
    apiMock.post.mockResolvedValue(
      res({ ...existingSigningCa, id: "sca3", subject: "CN=Vault Signing CA" })
    );
    renderPanel();
    await screen.findByText("CN=Acme R&D Signing CA");

    await user.click(screen.getByRole("button", { name: /Create Signing CA/ }));
    await user.type(screen.getByLabelText(/Subject/), "CN=Vault Signing CA");
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(apiMock.post).toHaveBeenCalledTimes(1));
    expect(screen.queryByText("Signing CA Created")).not.toBeInTheDocument();
  });

  it("rejects a paste that is not a certificate signing request", async () => {
    const user = userEvent.setup();
    mockRoutes();
    renderPanel();
    await screen.findByText("CN=Acme R&D Signing CA");

    await user.click(screen.getByRole("button", { name: /Sign a CSR/ }));
    await user.type(
      screen.getByLabelText(/Certificate signing request/),
      "just some text"
    );
    await user.click(screen.getByRole("button", { name: "Sign" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /PEM-encoded certificate signing request/
    );
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("signs a CSR and shows the certificate, which is the whole product of the call", async () => {
    const user = userEvent.setup();
    mockRoutes();
    apiMock.post.mockResolvedValue(
      res({
        ...existingSigningCa,
        id: "sca4",
        subject: "CN=Offline Tenant CA",
        key_custody: "external",
      })
    );
    renderPanel();
    await screen.findByText("CN=Acme R&D Signing CA");

    await user.click(screen.getByRole("button", { name: /Sign a CSR/ }));
    await user.type(
      screen.getByLabelText(/Certificate signing request/),
      "-----BEGIN CERTIFICATE REQUEST-----\nreq\n-----END CERTIFICATE REQUEST-----"
    );
    await user.click(screen.getByRole("button", { name: "Sign" }));

    await waitFor(() => expect(apiMock.post).toHaveBeenCalledTimes(1));
    const [url, payload] = apiMock.post.mock.calls[0];
    expect(url).toBe(
      "/api/v1/organizations/org1/tenants/t1/signing-cas/sign-csr"
    );
    expect(payload).toMatchObject({ parent_ca_id: "ca1" });

    // No key reveal — nothing was generated here — so the certificate dialog is
    // what tells the operator the call succeeded and hands them the result.
    expect(
      await screen.findByRole("dialog", { name: /Signing CA Certificate/ })
    ).toBeInTheDocument();
    expect(screen.queryByText("Signing CA Created")).not.toBeInTheDocument();
  });

  it("says why there is nothing to create a signing CA under", async () => {
    const user = userEvent.setup();
    mockRoutes({ signingCas: [], caCertificates: [anchorOnlyCa] });
    renderPanel();
    await screen.findByText(/No signing CAs yet/);

    await user.click(screen.getByRole("button", { name: /Create Signing CA/ }));
    expect(
      await screen.findByText(/This organization has no CA that can sign/)
    ).toBeInTheDocument();
  });
});
