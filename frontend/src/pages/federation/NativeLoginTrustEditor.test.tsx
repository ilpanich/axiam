import { describe, it, expect, vi } from "vitest";
import { useState } from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { NativeLoginTrustEditor } from "./NativeLoginTrustEditor";
import {
  DEFAULT_NATIVE_LOGIN_TRUST,
  validateNativeLoginClientId,
  validateNativeLoginTrust,
  type NativeLoginTrust,
} from "@/services/federation";

const enabled = (over: Partial<NativeLoginTrust> = {}): NativeLoginTrust => ({
  ...DEFAULT_NATIVE_LOGIN_TRUST,
  enabled: true,
  client_ids: ["com.example.app"],
  ...over,
});

describe("validateNativeLoginTrust", () => {
  it("accepts the server default", () => {
    expect(validateNativeLoginTrust(DEFAULT_NATIVE_LOGIN_TRUST)).toBeNull();
  });

  it("refuses enabling with no client IDs, naming the web client ID", () => {
    const msg = validateNativeLoginTrust(enabled({ client_ids: [] }));
    expect(msg).toContain("at least one client ID");
    expect(msg).toContain("web client ID");
  });

  it("allows a disabled block with no client IDs", () => {
    expect(
      validateNativeLoginTrust({ ...DEFAULT_NATIVE_LOGIN_TRUST, enabled: false }),
    ).toBeNull();
  });

  it("refuses a blank entry even when disabled", () => {
    expect(
      validateNativeLoginTrust(enabled({ enabled: false, client_ids: ["a", " "] })),
    ).toContain("blank");
  });

  it("refuses a duplicate, naming it", () => {
    expect(
      validateNativeLoginTrust(enabled({ client_ids: ["a", "b", "a"] })),
    ).toContain("'a'");
  });

  it("bounds length at 512 and count at 64", () => {
    expect(validateNativeLoginTrust(enabled({ client_ids: ["x".repeat(512)] }))).toBeNull();
    expect(
      validateNativeLoginTrust(enabled({ client_ids: ["x".repeat(513)] })),
    ).toContain("too long");
    const ids = Array.from({ length: 64 }, (_, i) => `id${i}`);
    expect(validateNativeLoginTrust(enabled({ client_ids: ids }))).toBeNull();
    expect(
      validateNativeLoginTrust(enabled({ client_ids: [...ids, "one-more"] })),
    ).toContain("maximum is 64");
  });

  it("counts length in bytes, as the server does", () => {
    // 200 three-byte characters = 600 bytes.
    expect(
      validateNativeLoginTrust(enabled({ client_ids: ["€".repeat(200)] })),
    ).toContain("too long");
  });

  it("bounds the token age at both ends and rejects fractions", () => {
    expect(validateNativeLoginTrust(enabled({ max_token_age_secs: 0 }))).not.toBeNull();
    expect(validateNativeLoginTrust(enabled({ max_token_age_secs: 1 }))).toBeNull();
    expect(validateNativeLoginTrust(enabled({ max_token_age_secs: 3600 }))).toBeNull();
    expect(validateNativeLoginTrust(enabled({ max_token_age_secs: 3601 }))).not.toBeNull();
    expect(validateNativeLoginTrust(enabled({ max_token_age_secs: 1.5 }))).not.toBeNull();
  });
});

describe("validateNativeLoginClientId", () => {
  it("accepts a fresh ID", () => {
    expect(validateNativeLoginClientId("a", ["b"])).toBeNull();
  });
  it("refuses blank, long, duplicate and over-count in turn", () => {
    expect(validateNativeLoginClientId("  ", [])).toContain("blank");
    expect(validateNativeLoginClientId("x".repeat(513), [])).toContain("too long");
    expect(validateNativeLoginClientId("a", ["a"])).toContain("already listed");
    const full = Array.from({ length: 64 }, (_, i) => `id${i}`);
    expect(validateNativeLoginClientId("new", full)).toContain("At most 64");
  });
});

describe("NativeLoginTrustEditor", () => {
  function Harness({
    initial = DEFAULT_NATIVE_LOGIN_TRUST,
    isOidc = true,
    onTrust,
  }: {
    initial?: NativeLoginTrust;
    isOidc?: boolean;
    onTrust?: (t: NativeLoginTrust) => void;
  }) {
    const [value, setValue] = useState(initial);
    return (
      <form onSubmit={(e) => e.preventDefault()}>
        <NativeLoginTrustEditor
          value={value}
          onChange={(next) => {
            setValue(next);
            onTrust?.(next);
          }}
          isOidc={isOidc}
          idPrefix="nl"
        />
      </form>
    );
  }

  it("explains itself away on a non-OIDC provider instead of offering controls", () => {
    render(<Harness isOidc={false} />);
    expect(screen.getByText(/Available for OpenID Connect providers only/)).toBeInTheDocument();
    expect(
      screen.queryByLabelText("Accept this provider's ID tokens from native apps"),
    ).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/Accepted client IDs/)).not.toBeInTheDocument();
  });

  it("starts off, and says browser login does not imply it", () => {
    render(<Harness />);
    expect(
      screen.getByLabelText("Accept this provider's ID tokens from native apps"),
    ).not.toBeChecked();
    expect(screen.getByTestId("native-login-trust")).toHaveTextContent(
      /does not imply accepting app tokens/,
    );
    expect(screen.getByTestId("native-login-trust")).toHaveTextContent(
      /web client ID is not accepted unless you list it/,
    );
  });

  it("toggles enabled without touching anything else", async () => {
    const onTrust = vi.fn();
    render(<Harness onTrust={onTrust} />);
    await userEvent.click(
      screen.getByLabelText("Accept this provider's ID tokens from native apps"),
    );
    expect(onTrust).toHaveBeenLastCalledWith({
      ...DEFAULT_NATIVE_LOGIN_TRUST,
      enabled: true,
    });
  });

  it("adds a client ID with the button and with Enter, trimming it", async () => {
    const onTrust = vi.fn();
    render(<Harness onTrust={onTrust} />);
    const input = screen.getByLabelText(/Accepted client IDs/);

    await userEvent.type(input, "  com.example.app  ");
    await userEvent.click(screen.getByRole("button", { name: "Add client ID" }));
    expect(onTrust).toHaveBeenLastCalledWith(
      expect.objectContaining({ client_ids: ["com.example.app"] }),
    );
    expect(input).toHaveValue("");

    await userEvent.type(input, "apple.app.id{Enter}");
    expect(onTrust).toHaveBeenLastCalledWith(
      expect.objectContaining({ client_ids: ["com.example.app", "apple.app.id"] }),
    );
    expect(screen.getByText("apple.app.id")).toBeInTheDocument();
  });

  it("removes a client ID", async () => {
    const onTrust = vi.fn();
    render(<Harness initial={enabled({ client_ids: ["a", "b"] })} onTrust={onTrust} />);
    await userEvent.click(screen.getByRole("button", { name: "Remove client ID a" }));
    expect(onTrust).toHaveBeenLastCalledWith(
      expect.objectContaining({ client_ids: ["b"] }),
    );
    expect(screen.queryByText("a")).not.toBeInTheDocument();
  });

  it("refuses a blank ID, adds nothing, and clears the message on typing", async () => {
    const onTrust = vi.fn();
    render(<Harness onTrust={onTrust} />);
    await userEvent.click(screen.getByRole("button", { name: "Add client ID" }));
    expect(screen.getByRole("alert")).toHaveTextContent("must not be blank");
    expect(onTrust).not.toHaveBeenCalled();
    await userEvent.type(screen.getByLabelText(/Accepted client IDs/), "x");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("refuses a duplicate", async () => {
    const onTrust = vi.fn();
    render(<Harness initial={enabled()} onTrust={onTrust} />);
    await userEvent.type(
      screen.getByLabelText(/Accepted client IDs/),
      "com.example.app{Enter}",
    );
    expect(screen.getByRole("alert")).toHaveTextContent("already listed");
    expect(onTrust).not.toHaveBeenCalled();
  });

  it("refuses an over-long ID", async () => {
    const onTrust = vi.fn();
    render(<Harness onTrust={onTrust} />);
    fireEvent.change(screen.getByLabelText(/Accepted client IDs/), {
      target: { value: "x".repeat(513) },
    });
    await userEvent.click(screen.getByRole("button", { name: "Add client ID" }));
    expect(screen.getByRole("alert")).toHaveTextContent("too long");
    expect(onTrust).not.toHaveBeenCalled();
  });

  it("falls back to the default max age rather than storing zero, then accepts a value", async () => {
    const onTrust = vi.fn();
    render(<Harness onTrust={onTrust} />);
    const age = screen.getByLabelText("Max token age (seconds)");
    expect(age).toHaveValue(300);
    await userEvent.clear(age);
    expect(onTrust).toHaveBeenLastCalledWith(
      expect.objectContaining({ max_token_age_secs: 300 }),
    );
    fireEvent.change(age, { target: { value: "120" } });
    expect(onTrust).toHaveBeenLastCalledWith(
      expect.objectContaining({ max_token_age_secs: 120 }),
    );
  });

  it("flags an out-of-range age inline", () => {
    render(<Harness initial={enabled({ max_token_age_secs: 5000 })} />);
    expect(screen.getByRole("alert")).toHaveTextContent("between 1 and 3600");
  });
});
