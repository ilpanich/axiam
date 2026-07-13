import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, fireEvent, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { PgpKeysPage } from "./PgpKeysPage";
import { renderWithProviders } from "@/test/renderWithProviders";

const keys = [
  {
    id: "k1",
    tenant_id: "t1",
    name: "Audit Key",
    purpose: "AuditSigning",
    public_key_armored: "-----BEGIN PGP PUBLIC KEY-----audit",
    fingerprint: "AAAA1111BBBB2222CCCC3333DDDD4444",
    algorithm: "Ed25519",
    status: "Active",
    created_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "k2",
    tenant_id: "t1",
    name: "Export Key",
    purpose: "Export",
    public_key_armored: "-----BEGIN PGP PUBLIC KEY-----export",
    fingerprint: "SHORTFINGERPRINT",
    algorithm: "Rsa4096",
    status: "Active",
    created_at: "2026-01-02T00:00:00Z",
  },
  {
    id: "k3",
    tenant_id: "t1",
    name: "Old Key",
    purpose: "Export",
    public_key_armored: "-----BEGIN PGP PUBLIC KEY-----old",
    fingerprint: "OLDFINGERPRINT0000",
    algorithm: "Rsa4096",
    status: "Revoked",
    created_at: "2026-01-03T00:00:00Z",
  },
];

beforeEach(() => {
  vi.clearAllMocks();
});

describe("PgpKeysPage", () => {
  it("renders the fetched PGP keys", async () => {
    apiMock.get.mockResolvedValue(res(keys));
    renderWithProviders(<PgpKeysPage />);
    expect(await screen.findByText("Audit Key")).toBeInTheDocument();
    expect(screen.getByText("Export Key")).toBeInTheDocument();
    expect(screen.getByText("Audit Signing")).toBeInTheDocument();
    expect(screen.getAllByText("Export").length).toBeGreaterThan(0);
    // Long fingerprint is truncated with an ellipsis.
    expect(screen.getByText(/AAAA1111BBBB2222CCCC3333…/)).toBeInTheDocument();
  });

  it("shows the empty state when there are no keys", async () => {
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<PgpKeysPage />);
    expect(await screen.findByText("No PGP keys found.")).toBeInTheDocument();
  });

  it("requires a name before generating", async () => {
    apiMock.get.mockResolvedValue(res(keys));
    renderWithProviders(<PgpKeysPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Generate PGP Key/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "   ");
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("requires an email before generating", async () => {
    apiMock.get.mockResolvedValue(res(keys));
    renderWithProviders(<PgpKeysPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Generate PGP Key/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Signing");
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Email is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("generates an Export key and reveals the one-time private key", async () => {
    apiMock.get.mockResolvedValue(res(keys));
    apiMock.post.mockResolvedValue(
      res({ ...keys[1], id: "k9", private_key_armored: "-----BEGIN PGP PRIVATE KEY-----secret" })
    );
    renderWithProviders(<PgpKeysPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Generate PGP Key/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "New Export");
    await userEvent.type(within(dialog).getByLabelText("Email *"), "e@x.io");
    await userEvent.selectOptions(within(dialog).getByLabelText("Purpose"), "Export");
    await userEvent.click(within(dialog).getByRole("button", { name: "Generate" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/pgp-keys", {
        name: "New Export",
        email: "e@x.io",
        purpose: "Export",
        algorithm: "Rsa4096",
      })
    );
    const secret = await screen.findByRole("alertdialog");
    expect(within(secret).getByText("PGP Key Generated")).toBeInTheDocument();
    expect(
      within(secret).getByText("-----BEGIN PGP PRIVATE KEY-----secret")
    ).toBeInTheDocument();
    await userEvent.click(
      within(secret).getByRole("button", { name: "I've saved this information" })
    );
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("generates an AuditSigning key without revealing a private key", async () => {
    apiMock.get.mockResolvedValue(res(keys));
    apiMock.post.mockResolvedValue(res({ ...keys[0], id: "k8" })); // no private_key_armored
    renderWithProviders(<PgpKeysPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Generate PGP Key/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Audit 2");
    await userEvent.type(within(dialog).getByLabelText("Email *"), "a@x.io");
    await userEvent.selectOptions(within(dialog).getByLabelText("Algorithm"), "Ed25519");
    await userEvent.click(within(dialog).getByRole("button", { name: "Generate" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/pgp-keys", {
        name: "Audit 2",
        email: "a@x.io",
        purpose: "AuditSigning",
        algorithm: "Ed25519",
      })
    );
    // No reveal modal for AuditSigning keys.
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("surfaces a generate error inside the dialog", async () => {
    apiMock.get.mockResolvedValue(res(keys));
    apiMock.post.mockRejectedValue(new Error("Key limit reached"));
    renderWithProviders(<PgpKeysPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Generate PGP Key/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Dup");
    await userEvent.type(within(dialog).getByLabelText("Email *"), "d@x.io");
    await userEvent.click(within(dialog).getByRole("button", { name: "Generate" }));
    expect(await screen.findByText("Key limit reached")).toBeInTheDocument();
  });

  it("views a public key in a modal", async () => {
    apiMock.get.mockResolvedValue(res(keys));
    renderWithProviders(<PgpKeysPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "View public key for Audit Key" })
    );
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText("Public Key")).toBeInTheDocument();
    expect(
      within(dialog).getByText("AAAA1111BBBB2222CCCC3333DDDD4444")
    ).toBeInTheDocument();
    expect(
      within(dialog).getByText("-----BEGIN PGP PUBLIC KEY-----audit")
    ).toBeInTheDocument();
    // Both the header "✕" and the footer button expose the name "Close".
    await userEvent.click(within(dialog).getAllByRole("button", { name: "Close" })[1]);
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("revokes an active key after confirmation", async () => {
    apiMock.get.mockResolvedValue(res(keys));
    apiMock.post.mockResolvedValue(res(undefined));
    renderWithProviders(<PgpKeysPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Revoke key Audit Key" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Revoke PGP Key/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Revoke" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/pgp-keys/k1/revoke")
    );
  });

  it("requires data before encrypting", async () => {
    apiMock.get.mockResolvedValue(res(keys));
    renderWithProviders(<PgpKeysPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Encrypt data with Export Key" })
    );
    const dialog = screen.getByRole("dialog");
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Data is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("encrypts data and reveals the ciphertext", async () => {
    apiMock.get.mockResolvedValue(res(keys));
    apiMock.post.mockResolvedValue(
      res({ recipient_key_id: "k2", ciphertext_armored: "-----BEGIN PGP MESSAGE-----ct" })
    );
    renderWithProviders(<PgpKeysPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Encrypt data with Export Key" })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Data to Encrypt *"), "hello");
    await userEvent.click(within(dialog).getByRole("button", { name: "Encrypt" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/pgp-keys/k2/encrypt", {
        data_base64: "aGVsbG8=",
      })
    );
    const secret = await screen.findByRole("alertdialog");
    expect(within(secret).getByText("Data Encrypted")).toBeInTheDocument();
    expect(
      within(secret).getByText("-----BEGIN PGP MESSAGE-----ct")
    ).toBeInTheDocument();
    // Acknowledging the reveal closes both the reveal and the encrypt modal.
    await userEvent.click(
      within(secret).getByRole("button", { name: "I've saved this information" })
    );
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument());
  });

  it("copies the public key from the view modal", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });
    apiMock.get.mockResolvedValue(res(keys));
    renderWithProviders(<PgpKeysPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "View public key for Audit Key" })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Copy" }));
    await waitFor(() =>
      expect(writeText).toHaveBeenCalledWith("-----BEGIN PGP PUBLIC KEY-----audit")
    );
    expect(await within(dialog).findByText("Copied!")).toBeInTheDocument();
  });

  it("closes the generate dialog on cancel", async () => {
    apiMock.get.mockResolvedValue(res(keys));
    renderWithProviders(<PgpKeysPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Generate PGP Key/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Temp");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    // Reopening starts blank.
    await userEvent.click(screen.getByRole("button", { name: /Generate PGP Key/ }));
    expect(within(screen.getByRole("dialog")).getByLabelText("Name *")).toHaveValue("");
  });

  it("closes the encrypt dialog on cancel", async () => {
    apiMock.get.mockResolvedValue(res(keys));
    renderWithProviders(<PgpKeysPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Encrypt data with Export Key" })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Data to Encrypt *"), "junk");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("still calls revoke when the request fails (error is toasted)", async () => {
    apiMock.get.mockResolvedValue(res(keys));
    apiMock.post.mockRejectedValue(new Error("boom"));
    renderWithProviders(<PgpKeysPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Revoke key Audit Key" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Revoke" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/pgp-keys/k1/revoke")
    );
  });

  it("surfaces an encrypt error inside the dialog", async () => {
    apiMock.get.mockResolvedValue(res(keys));
    apiMock.post.mockRejectedValue(new Error("Encrypt failed"));
    renderWithProviders(<PgpKeysPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Encrypt data with Export Key" })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Data to Encrypt *"), "hi");
    await userEvent.click(within(dialog).getByRole("button", { name: "Encrypt" }));
    expect(await screen.findByText("Encrypt failed")).toBeInTheDocument();
  });
});
