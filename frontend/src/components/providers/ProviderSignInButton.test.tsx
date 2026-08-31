import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { ProviderSignInButton } from "./ProviderSignInButton";
import type { PublicFederationProvider } from "@/services/ssoLogin";
import type { ProviderKind } from "@/services/federation";

function provider(
  over: Partial<PublicFederationProvider> = {},
): PublicFederationProvider {
  return {
    id: "p1",
    provider_kind: "google",
    display_name: "Google",
    protocol: "OidcConnect",
    has_bundled_mark: true,
    inherited: false,
    ...over,
  };
}

describe("ProviderSignInButton", () => {
  /**
   * The wording is not ours to choose. Each of these is the phrase the brand's
   * own sign-in-button guidelines require, and Meta's is the one most likely to
   * be "tidied" into matching the others.
   */
  it.each<[ProviderKind, string]>([
    ["google", "Sign in with Google"],
    ["microsoft", "Sign in with Microsoft"],
    ["apple", "Sign in with Apple"],
    ["github", "Sign in with GitHub"],
    ["facebook", "Continue with Facebook"],
  ])("uses the wording %s's guidelines require", (kind, label) => {
    render(
      <ProviderSignInButton
        provider={provider({ provider_kind: kind, display_name: "ignored" })}
        onSelect={vi.fn()}
      />,
    );
    expect(screen.getByRole("button", { name: label })).toBeInTheDocument();
  });

  /**
   * A branded button ignores the operator's display name, because the brand
   * fixes the wording. A generic one is the only place the display name
   * appears — which is what makes it worth typing.
   */
  it("names a generic provider by the operator's display name", () => {
    render(
      <ProviderSignInButton
        provider={provider({
          provider_kind: "generic_oidc",
          display_name: "Acme SSO",
          has_bundled_mark: false,
        })}
        onSelect={vi.fn()}
      />,
    );
    expect(
      screen.getByRole("button", { name: "Sign in with Acme SSO" }),
    ).toBeInTheDocument();
  });

  it("renders an uploaded icon for a generic provider", () => {
    const icon = "data:image/png;base64,iVBORw0KGgo=";
    const { container } = render(
      <ProviderSignInButton
        provider={provider({
          provider_kind: "generic_oidc",
          display_name: "Acme SSO",
          has_bundled_mark: false,
          button_icon: icon,
        })}
        onSelect={vi.fn()}
      />,
    );
    const img = container.querySelector("img");
    expect(img).toBeTruthy();
    expect(img).toHaveAttribute("src", icon);
  });

  /**
   * The mark a brand requires is not replaceable. The server refuses to store
   * an icon for a branded kind; this asserts the client would not honour one
   * even if a stale row carried it, so the two cannot disagree.
   */
  it("ignores an uploaded icon on a provider that ships its own mark", () => {
    const { container } = render(
      <ProviderSignInButton
        provider={provider({
          provider_kind: "google",
          button_icon: "data:image/png;base64,iVBORw0KGgo=",
        })}
        onSelect={vi.fn()}
      />,
    );
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("svg")).toBeTruthy();
  });

  it("hands the whole provider back on click", async () => {
    const onSelect = vi.fn();
    const p = provider();
    render(<ProviderSignInButton provider={p} onSelect={onSelect} />);
    await userEvent.click(screen.getByRole("button"));
    expect(onSelect).toHaveBeenCalledWith(p);
  });

  it("cannot be clicked twice while its flow is starting", async () => {
    const onSelect = vi.fn();
    render(
      <ProviderSignInButton provider={provider()} onSelect={onSelect} busy />,
    );
    const button = screen.getByRole("button");
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("aria-busy", "true");
    await userEvent.click(button);
    expect(onSelect).not.toHaveBeenCalled();
  });

  it("keeps its accessible name while busy", () => {
    render(
      <ProviderSignInButton provider={provider()} onSelect={vi.fn()} busy />,
    );
    // The visible text is swapped for a spinner; the name must not disappear
    // with it, or the control becomes unfindable mid-flow.
    expect(
      screen.getByRole("button", { name: "Sign in with Google" }),
    ).toBeInTheDocument();
  });
});
