/**
 * The words the settings policy cards render, and the list parser they read
 * their textareas with.
 *
 * Separate from the card modules for the reason `components/layout/navSections`
 * is separate from the sidebar: a module that exports both a component and a
 * plain value breaks React Fast Refresh (oxlint
 * `react(only-export-components)`). It is the better shape regardless — what a
 * control *says* about a security setting is worth reading in one place,
 * without the JSX around it.
 */

import type {
  DynamicRegistrationMode,
  SurfaceKey,
} from "@/services/settings";

/** The label each disable-only switch is shown under, and named by in messages. */
export const SURFACE_LABELS: Record<SurfaceKey, string> = {
  saml_idp_enabled: "SAML 2.0 identity provider",
  ssf_enabled: "Shared Signals Framework transmitter",
};

/** `"a\nb\n  \nc"` → `["a", "b", "c"]` — one entry per non-blank line. */
export function parseLines(raw: string): string[] {
  return raw
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export const DYNAMIC_REGISTRATION_LABELS: Record<DynamicRegistrationMode, string> = {
  disabled: "Disabled — no self-registered client may exist",
  initial_access_token: "Initial access token — requires an administrator-minted credential",
  anonymous: "Anonymous — open to anybody who can reach the endpoint",
};

export const DYNAMIC_REGISTRATION_HELP: Record<DynamicRegistrationMode, string> = {
  disabled:
    "Every client is an administrator's decision. What every AXIAM deployment does today.",
  initial_access_token:
    "RFC 7591 §1.2's \"protected\" profile: the endpoint is open, the act is not. Mint a " +
    "single-use credential from the OAuth2 Clients page and hand it to the registering client.",
  anonymous:
    "RFC 7591 §1.2's \"open\" profile — the one MCP Inspector, Claude Code and VS Code use. " +
    "Refused while Allowed audiences is empty (D3, below).",
};
