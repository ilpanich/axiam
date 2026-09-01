import { Loader2 } from "lucide-react";

import { cn } from "@/lib/utils";
import type { ProviderKind } from "@/services/federation";
import type { PublicFederationProvider } from "@/services/ssoLogin";

import { ProviderMark } from "./ProviderMark";

/**
 * A branded "Sign in with X" button.
 *
 * # Brand guidelines are requirements, not suggestions
 *
 * Google, Apple, Microsoft and Meta each publish sign-in-button rules covering
 * the wording, the mark, the colours and a minimum size, and a relying party
 * that ignores them is out of compliance with the terms it agreed to when it
 * registered the client. What is implemented here:
 *
 * - **Wording is per brand and not editable.** Meta's rule for Facebook Login
 *   is "Continue with Facebook", not "Sign in with"; the others are "Sign in
 *   with <brand>". The operator's own display name is used only for a provider
 *   with no brand of its own.
 * - **Marks are unmodified** and, where the brand requires a fixed palette
 *   (Google, Microsoft), rendered in it regardless of the button's own colours.
 * - **Colours are the brand's own.** AXIAM's admin UI is dark, so each brand's
 *   *dark* variant is used where one is published, rather than recolouring a
 *   light one.
 * - **Minimum height** of 40px, above every published floor.
 *
 * A provider with no brand — the `generic_*` kinds — gets AXIAM's own neutral
 * styling, the operator's display name, and their uploaded icon if they set one.
 * That is the case the server permits a custom icon for, and the only one.
 */

interface BrandStyle {
  /** Exact wording. Meta requires "Continue with"; everyone else "Sign in with". */
  label: (displayName: string) => string;
  className: string;
}

const BRANDS: Partial<Record<ProviderKind, BrandStyle>> = {
  google: {
    label: () => "Sign in with Google",
    // Google's dark theme: #131314 surface, #8E918F outline, #E3E3E3 text.
    className:
      "bg-[#131314] text-[#E3E3E3] border-[#8E918F] hover:bg-[#1e1f20] focus-visible:ring-[#8E918F]",
  },
  microsoft: {
    label: () => "Sign in with Microsoft",
    // Microsoft's dark button: #2F2F2F surface, #8C8C8C border, white text.
    className:
      "bg-[#2F2F2F] text-white border-[#8C8C8C] hover:bg-[#3b3b3b] focus-visible:ring-[#8C8C8C]",
  },
  apple: {
    label: () => "Sign in with Apple",
    // Apple's black button, with the mark taking `currentColor` (white).
    className:
      "bg-black text-white border-black hover:bg-[#1a1a1a] focus-visible:ring-white/60",
  },
  github: {
    label: () => "Sign in with GitHub",
    className:
      "bg-[#24292f] text-white border-[#444c56] hover:bg-[#32383f] focus-visible:ring-[#444c56]",
  },
  facebook: {
    // Meta's mandated wording for Facebook Login.
    label: () => "Continue with Facebook",
    className:
      "bg-[#1877F2] text-white border-[#1877F2] hover:bg-[#166fe5] focus-visible:ring-[#1877F2]",
  },
};

const GENERIC: BrandStyle = {
  label: (displayName) => `Sign in with ${displayName}`,
  className:
    "bg-white/5 text-foreground border-primary/20 hover:bg-white/10 focus-visible:ring-primary/40",
};

export interface ProviderSignInButtonProps {
  provider: PublicFederationProvider;
  onSelect: (provider: PublicFederationProvider) => void;
  /** Shows a spinner and blocks re-entry while this provider's flow starts. */
  busy?: boolean;
  /** Blocks the button while some *other* action owns the page. */
  disabled?: boolean;
}

export function ProviderSignInButton({
  provider,
  onSelect,
  busy = false,
  disabled = false,
}: ProviderSignInButtonProps) {
  const brand = BRANDS[provider.provider_kind] ?? GENERIC;
  const label = brand.label(provider.display_name);

  return (
    <button
      type="button"
      onClick={() => onSelect(provider)}
      disabled={busy || disabled}
      // `aria-label` repeats the visible text rather than replacing it: the
      // label is the accessible name either way, and stating it keeps the
      // button findable by name in tests and by voice control even while the
      // visible text is swapped for the busy state.
      aria-label={label}
      aria-busy={busy || undefined}
      className={cn(
        // 40px floor clears every published minimum.
        "flex h-10 w-full items-center justify-center gap-3 rounded-md border",
        "px-4 text-sm font-medium transition-colors duration-200",
        "focus-visible:outline-hidden focus-visible:ring-2",
        "disabled:cursor-not-allowed disabled:opacity-60",
        brand.className,
      )}
    >
      {busy ? (
        <Loader2 size={18} className="animate-spin" aria-hidden="true" />
      ) : (
        <ProviderMark
          kind={provider.provider_kind}
          buttonIcon={provider.button_icon}
        />
      )}
      <span>{label}</span>
    </button>
  );
}
