import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
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

  it("closes when the backdrop behind it is clicked", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const { container } = renderDialog({ onClose });
    const backdrop = container.querySelector('[aria-hidden="true"]');
    expect(backdrop).not.toBeNull();
    await user.click(backdrop!);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("keeps Tab inside the dialog in both directions", () => {
    renderDialog({ chainPem: CHAIN_PEM });
    const buttons = screen.getAllByRole("button");
    const first = buttons[0];
    const last = buttons[buttons.length - 1];
    // The trap is what stops Tab walking out of a modal into the page behind
    // it, which for a screen-reader user is the difference between a dialog
    // and a decoration.
    expect(first).toHaveAttribute("aria-label", "Close dialog");

    last.focus();
    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).toBe(first);

    first.focus();
    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(last);
  });

  it("leaves a Tab in the middle of the dialog alone", () => {
    renderDialog();
    const buttons = screen.getAllByRole("button");
    const middle = buttons[1];
    middle.focus();
    fireEvent.keyDown(document, { key: "Tab" });
    // Neither end of the ring, so the browser's own focus order applies and
    // the handler must not move anything.
    expect(document.activeElement).toBe(middle);
  });
});

// ─── Copy-to-clipboard ───────────────────────────────────────────────────────
//
// Driven with `fireEvent` and a hand-placed `navigator.clipboard` rather than
// `userEvent.setup()`, which installs a clipboard stub of its own and would
// make the unavailable-API branch unreachable.

describe("CertificateViewDialog copy buttons", () => {
  const realClipboard = Object.getOwnPropertyDescriptor(
    Navigator.prototype,
    "clipboard"
  );

  /**
   * jsdom defines `navigator.clipboard` as a getter-only accessor, so plain
   * assignment throws. Redefining the property is what lets a test choose
   * between the Clipboard API and the branch for contexts that have none.
   */
  function setClipboard(value: unknown) {
    Object.defineProperty(navigator, "clipboard", {
      value,
      configurable: true,
      writable: true,
    });
  }

  afterEach(() => {
    delete (navigator as { clipboard?: unknown }).clipboard;
    if (realClipboard) {
      Object.defineProperty(Navigator.prototype, "clipboard", realClipboard);
    }
    vi.useRealTimers();
  });

  it("copies each PEM block from its own button", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    setClipboard({ writeText });
    renderDialog({ chainPem: CHAIN_PEM });

    fireEvent.click(screen.getByRole("button", { name: "Copy certificate PEM" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(CERT_PEM));

    // The chain has a button of its own: an operator pinning an issuer wants
    // the chain, not the leaf, and picking the wrong block is silent.
    fireEvent.click(screen.getByRole("button", { name: "Copy chain PEM" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(CHAIN_PEM));
  });

  it("acknowledges the copy and reverts after two seconds", async () => {
    vi.useFakeTimers();
    const writeText = vi.fn().mockResolvedValue(undefined);
    setClipboard({ writeText });
    renderDialog();

    fireEvent.click(screen.getByRole("button", { name: "Copy certificate PEM" }));
    // The click handler is async; let its microtasks settle before asserting.
    await act(async () => {});
    expect(
      screen.getByRole("button", { name: "certificate PEM copied" })
    ).toBeInTheDocument();

    act(() => vi.advanceTimersByTime(2000));
    expect(
      screen.getByRole("button", { name: "Copy certificate PEM" })
    ).toBeInTheDocument();
  });

  it("clears a pending acknowledgement timer on unmount", async () => {
    vi.useFakeTimers();
    const clearTimeoutSpy = vi.spyOn(globalThis, "clearTimeout");
    setClipboard({ writeText: vi.fn().mockResolvedValue(undefined) });
    const { unmount } = renderDialog();

    fireEvent.click(screen.getByRole("button", { name: "Copy certificate PEM" }));
    await act(async () => {});
    unmount();
    // Left running, the timer would call `setCopied` on an unmounted component.
    expect(clearTimeoutSpy).toHaveBeenCalled();
    clearTimeoutSpy.mockRestore();
  });

  it("falls back to execCommand where the Clipboard API is unavailable", async () => {
    // Non-secure contexts and older browsers expose no `navigator.clipboard`,
    // and a Copy button that silently does nothing there is worse than none.
    setClipboard(undefined);
    const execCommand = vi.fn().mockReturnValue(true);
    Object.assign(document, { execCommand });
    renderDialog();

    fireEvent.click(screen.getByRole("button", { name: "Copy certificate PEM" }));
    await waitFor(() => expect(execCommand).toHaveBeenCalledWith("copy"));
    // The scratch textarea is removed again rather than left in the document.
    expect(document.querySelector("textarea")).toBeNull();
    expect(
      await screen.findByRole("button", { name: "certificate PEM copied" })
    ).toBeInTheDocument();
  });

  it("swallows a refused clipboard write", async () => {
    const writeText = vi.fn().mockRejectedValue(new Error("denied"));
    setClipboard({ writeText });
    renderDialog();

    fireEvent.click(screen.getByRole("button", { name: "Copy certificate PEM" }));
    await waitFor(() => expect(writeText).toHaveBeenCalled());
    // No acknowledgement, because nothing was copied — and no crash, because
    // the download button beside it still works.
    expect(
      screen.getByRole("button", { name: "Copy certificate PEM" })
    ).toBeInTheDocument();
  });
});
