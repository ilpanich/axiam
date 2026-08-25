import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

// `vi.hoisted` because `vi.mock` is lifted above every import, and a plain
// `const` declared here would still be in its temporal dead zone when the
// factory runs.
const { downloadTextFile } = vi.hoisted(() => ({ downloadTextFile: vi.fn() }));
vi.mock("@/lib/download", async () => {
  const actual = await vi.importActual<typeof import("@/lib/download")>(
    "@/lib/download"
  );
  return { ...actual, downloadTextFile };
});

import { CertificateViewDialog } from "./CertificateViewDialog";

const CERT_PEM = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----";
const CHAIN_PEM = "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----";

/**
 * Find the `<pre>` holding an exact PEM block.
 *
 * `getByText` with a string collapses whitespace on both sides of the
 * comparison, which turns a multi-line PEM into one long line and stops it
 * matching the element it came from. Comparing `textContent` directly is what
 * actually asserts the block was rendered intact — newlines included, which is
 * the part that matters for a format defined line by line.
 */
function pemBlock(pem: string) {
  return screen.getByText(
    (_content, element) =>
      element?.tagName === "PRE" && element.textContent === pem
  );
}

function renderDialog(props: Partial<Parameters<typeof CertificateViewDialog>[0]> = {}) {
  return render(
    <CertificateViewDialog
      open
      onClose={vi.fn()}
      subject="CN=device-001"
      publicCertPem={CERT_PEM}
      details={[{ label: "Fingerprint", value: "AA:BB" }]}
      {...props}
    />
  );
}

beforeEach(() => {
  downloadTextFile.mockClear();
});

describe("CertificateViewDialog", () => {
  it("renders nothing when closed", () => {
    renderDialog({ open: false });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("shows the public certificate and its summary fields", () => {
    renderDialog();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(pemBlock(CERT_PEM)).toBeInTheDocument();
    expect(screen.getByText("Fingerprint")).toBeInTheDocument();
    expect(screen.getByText("AA:BB")).toBeInTheDocument();
  });

  it("downloads the certificate under a filesystem-safe name", async () => {
    const user = userEvent.setup();
    renderDialog();
    await user.click(screen.getByRole("button", { name: /Certificate \(\.crt\)/ }));
    expect(downloadTextFile).toHaveBeenCalledTimes(1);
    const [filename, contents] = downloadTextFile.mock.calls[0];
    expect(filename).toBe("device-001.crt");
    // A PEM without a trailing newline is one that several parsers reject, so
    // the download normalises it rather than shipping whatever the API sent.
    expect(contents).toBe(`${CERT_PEM}\n`);
  });

  it("offers a full-chain download only when there is a chain", async () => {
    const user = userEvent.setup();
    const { unmount } = renderDialog();
    expect(
      screen.queryByRole("button", { name: /Full chain/ })
    ).not.toBeInTheDocument();
    unmount();

    renderDialog({ chainPem: CHAIN_PEM });
    expect(pemBlock(CHAIN_PEM)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Full chain/ }));
    const [filename, contents] = downloadTextFile.mock.calls[0];
    expect(filename).toBe("device-001-fullchain.pem");
    // Leaf first, then its issuers — the order every TLS stack expects from a
    // single bundle file.
    expect(contents).toBe(`${CERT_PEM}\n${CHAIN_PEM}\n`);
  });

  it("closes on Escape and on the close button", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    renderDialog({ onClose });
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "Close dialog" }));
    expect(onClose).toHaveBeenCalledTimes(2);
  });
});
