import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TotpSetupPanel } from "./TotpSetupPanel";

const setupData = {
  secret_base32: "ABCD1234WXYZ",
  totp_uri: "otpauth://totp/AXIAM:admin?secret=ABCD1234WXYZ&issuer=AXIAM",
};

const writeText = vi.fn().mockResolvedValue(undefined);

beforeEach(() => {
  vi.clearAllMocks();
  Object.defineProperty(navigator, "clipboard", {
    value: { writeText },
    configurable: true,
  });
});

describe("TotpSetupPanel", () => {
  it("renders the QR code and manual secret for an otpauth URI", () => {
    render(
      <TotpSetupPanel
        setupData={setupData}
        code=""
        onCodeChange={vi.fn()}
        onConfirm={vi.fn()}
        error={null}
        isPending={false}
      />
    );
    expect(screen.getByText("ABCD1234WXYZ")).toBeInTheDocument();
    expect(screen.getByTitle("TOTP QR code — scan with your authenticator app")).toBeInTheDocument();
    // For an otpauth:// URI the panel renders a client-side QRCodeSVG. The svg
    // exposes role="img" with its <title> as the accessible name (there is no
    // <img> element — that path is only taken for a data: URL).
    const qr = screen.getByRole("img", { name: /TOTP QR code/ });
    expect(qr.tagName.toLowerCase()).toBe("svg");
  });

  it("renders an <img> instead of the QR component when the URI is a data: URL", () => {
    render(
      <TotpSetupPanel
        setupData={{ secret_base32: "SECRETXX", totp_uri: "data:image/png;base64,AAAA" }}
        code=""
        onCodeChange={vi.fn()}
        onConfirm={vi.fn()}
        error={null}
        isPending={false}
      />
    );
    const img = screen.getByRole("img", { name: /TOTP QR code/ });
    expect(img).toHaveAttribute("src", "data:image/png;base64,AAAA");
  });

  it("copies the secret to the clipboard and shows a checkmark that reverts", async () => {
    // Real timers throughout: userEvent under fake timers can hang, and a hung
    // interaction would leave fake timers installed for the rest of the file.
    // The component reverts the checkmark after a real 2s setTimeout, which the
    // second waitFor (with an extended timeout) observes directly.
    render(
      <TotpSetupPanel
        setupData={setupData}
        code=""
        onCodeChange={vi.fn()}
        onConfirm={vi.fn()}
        error={null}
        isPending={false}
      />
    );
    const copyButton = screen.getByRole("button", { name: "Copy secret key" });
    await userEvent.click(copyButton);
    expect(writeText).toHaveBeenCalledWith("ABCD1234WXYZ");
    // The Copy icon swaps for a green Check icon while `copied` is true.
    await waitFor(() =>
      expect(copyButton.querySelector("svg.text-emerald-400")).toBeTruthy()
    );
    // After ~2s the checkmark reverts to the copy icon.
    await waitFor(
      () => expect(copyButton.querySelector("svg.text-emerald-400")).toBeFalsy(),
      { timeout: 2500 }
    );
  });

  it("strips non-digits and caps the verification code at 6 characters", async () => {
    const onCodeChange = vi.fn();
    render(
      <TotpSetupPanel
        setupData={setupData}
        code=""
        onCodeChange={onCodeChange}
        onConfirm={vi.fn()}
        error={null}
        isPending={false}
      />
    );
    await userEvent.type(screen.getByLabelText("Verification Code"), "12a3456789");
    // Each keystroke invokes onCodeChange with the sanitized+sliced value
    // computed from that single-character input event (component is
    // controlled with a fixed `code=""` in this test), so the final
    // call reflects the last keystroke's own transformation.
    expect(onCodeChange).toHaveBeenCalled();
    for (const call of onCodeChange.mock.calls) {
      expect(call[0]).toMatch(/^[0-9]{0,6}$/);
    }
  });

  it("disables submit until exactly 6 digits are present, and calls onConfirm on submit", async () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    const { rerender } = render(
      <TotpSetupPanel
        setupData={setupData}
        code="123"
        onCodeChange={vi.fn()}
        onConfirm={onConfirm}
        error={null}
        isPending={false}
      />
    );
    expect(screen.getByRole("button", { name: "Confirm" })).toBeDisabled();

    rerender(
      <TotpSetupPanel
        setupData={setupData}
        code="123456"
        onCodeChange={vi.fn()}
        onConfirm={onConfirm}
        error={null}
        isPending={false}
      />
    );
    const submitBtn = screen.getByRole("button", { name: "Confirm" });
    expect(submitBtn).toBeEnabled();
    await userEvent.click(submitBtn);
    expect(onConfirm).toHaveBeenCalledWith("123456");
  });

  it("shows the error alert when provided", () => {
    render(
      <TotpSetupPanel
        setupData={setupData}
        code="123456"
        onCodeChange={vi.fn()}
        onConfirm={vi.fn()}
        error="Invalid or expired code."
        isPending={false}
      />
    );
    expect(screen.getByRole("alert")).toHaveTextContent("Invalid or expired code.");
  });

  it("shows the pending label and disables submit while isPending", () => {
    render(
      <TotpSetupPanel
        setupData={setupData}
        code="123456"
        onCodeChange={vi.fn()}
        onConfirm={vi.fn()}
        error={null}
        isPending={true}
        confirmPendingLabel="Confirming…"
      />
    );
    expect(screen.getByText("Confirming…")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Confirming…/ })).toBeDisabled();
  });

  it("renders custom confirm/cancel labels and invokes onCancel", async () => {
    const onCancel = vi.fn();
    render(
      <TotpSetupPanel
        setupData={setupData}
        code="123456"
        onCodeChange={vi.fn()}
        onConfirm={vi.fn()}
        error={null}
        isPending={false}
        confirmLabel="Verify"
        onCancel={onCancel}
        cancelLabel="Nevermind"
      />
    );
    expect(screen.getByRole("button", { name: "Verify" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Nevermind" }));
    expect(onCancel).toHaveBeenCalled();
  });

  it("omits the cancel button when onCancel is not provided", () => {
    render(
      <TotpSetupPanel
        setupData={setupData}
        code="123456"
        onCodeChange={vi.fn()}
        onConfirm={vi.fn()}
        error={null}
        isPending={false}
      />
    );
    expect(screen.queryByRole("button", { name: "Cancel" })).not.toBeInTheDocument();
  });
});
