import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import axe from "axe-core";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore, type AuthUser } from "@/stores/auth";
import { LoginPage } from "@/pages/LoginPage";
import { MfaManagementPage } from "@/pages/profile/MfaManagementPage";
import { DataTable } from "@/components/DataTable";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Input } from "@/components/ui/input";
import { ToggleField } from "@/components/shared";
import { CimdPolicyFields } from "@/pages/settings/cimdPolicy";
import { DEFAULT_CIMD_POLICY } from "@/services/settings";

/**
 * C3 — axe-core smoke run over the main surfaces.
 *
 * # What this is, and what it deliberately is not
 *
 * Automated accessibility checking catches roughly a third of real WCAG
 * failures. It cannot tell whether a label is *meaningful*, whether a focus
 * order makes sense, or whether an error message helps — those stay the
 * reviewer's job, and the audit in `claude_dev/AXIAM-frontend-audit.md` is
 * where they were done by hand.
 *
 * What this suite is for is regression: the audit's fixes (contrast tokens,
 * `aria-invalid` wiring, `scope="col"`, focus tokens, control sizes) are
 * exactly the class of thing axe *can* see, and exactly the class of thing
 * that quietly comes undone when someone restyles a component. A green run
 * here does not mean "accessible"; a red run means something the audit fixed
 * has been un-fixed.
 *
 * # Why the rule set is narrowed
 *
 * jsdom has no layout engine, so any rule that needs computed geometry or
 * real colour compositing (`color-contrast`, target-size rules) cannot run
 * meaningfully — axe itself reports them as "incomplete" rather than passing
 * or failing. Including them would produce noise that trains people to ignore
 * this suite. Contrast is instead pinned by the design tokens themselves
 * (`--border-strong`, the `@supports` glass fallback) and was verified by hand
 * in the audit.
 */

const RULES: axe.RunOptions = {
  runOnly: {
    type: "tag",
    values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"],
  },
  rules: {
    // Needs real layout + compositing; jsdom has neither. Covered by tokens
    // and by the manual audit instead.
    "color-contrast": { enabled: false },
    // These fire on a *document*, and every case here renders a fragment
    // into a test container rather than a whole page.
    region: { enabled: false },
    "page-has-heading-one": { enabled: false },
    "landmark-one-main": { enabled: false },
    "html-has-lang": { enabled: false },
  },
};

async function expectNoViolations(container: HTMLElement) {
  const results = await axe.run(container, RULES);
  const summary = results.violations.map(
    (v) => `${v.id} (${v.impact}): ${v.help}\n  ${v.nodes.map((n) => n.html).join("\n  ")}`,
  );
  expect(summary, summary.join("\n\n")).toEqual([]);
}

const user: AuthUser = {
  id: "u1",
  username: "admin",
  email: "a@x.io",
  permissions: ["*"],
  tenant_id: "t1",
  tenantSlug: "acme",
  orgSlug: "acme-org",
};

beforeEach(() => {
  vi.clearAllMocks();
  apiMock.get.mockResolvedValue(res([]));
  Object.defineProperty(window, "PublicKeyCredential", {
    value: function PublicKeyCredential() {},
    configurable: true,
    writable: true,
  });
});

afterEach(() => {
  useAuthStore.setState({
    user: null,
    tenantSlug: null,
    orgSlug: null,
    isAuthenticated: false,
    isInitializing: true,
  });
});

describe("a11y smoke — pages", () => {
  it("LoginPage has no automatically detectable violations", async () => {
    const { container } = renderWithProviders(<LoginPage />, { route: "/login" });
    await expectNoViolations(container);
  });

  it("MfaManagementPage has no automatically detectable violations", async () => {
    useAuthStore.setState({
      user,
      tenantSlug: "acme",
      orgSlug: "acme-org",
      isAuthenticated: true,
      isInitializing: false,
    });
    const { container, findByText } = renderWithProviders(<MfaManagementPage />);
    await findByText("Passkeys & security keys");
    await expectNoViolations(container);
  });
});

describe("a11y smoke — design-system components", () => {
  /** Audit item 8: `scope="col"` on header cells. */
  it("DataTable", async () => {
    const { container } = renderWithProviders(
      <DataTable
        columns={[
          { key: "name", header: "Name" },
          { key: "status", header: "Status" },
        ]}
        data={[{ name: "alice", status: "Active" }]}
      />,
    );
    await expectNoViolations(container);
  });

  /** Audit item 8, the other half: the empty state's decorative glyph. */
  it("DataTable empty state", async () => {
    const { container } = renderWithProviders(
      <DataTable columns={[{ key: "name", header: "Name" }]} data={[]} />,
    );
    await expectNoViolations(container);
  });

  /** Audit item 3: dialog semantics (focus restore and scroll lock are
      behavioural and are asserted in dialogs.test.tsx). */
  it("ConfirmDialog", async () => {
    const { container } = renderWithProviders(
      <ConfirmDialog
        open
        onClose={() => {}}
        onConfirm={() => {}}
        title="Remove thing"
        description="This cannot be undone."
      />,
    );
    await expectNoViolations(container);
  });

  /** Audit item 2: an invalid input must announce, not just turn red. */
  it("Input in its error state", async () => {
    const { container } = renderWithProviders(
      <div>
        <label htmlFor="email">Email</label>
        <Input id="email" error="That address is not valid." />
      </div>,
    );
    await expectNoViolations(container);
  });

  /** Audit item 7: the label row is the target, and it is associated. */
  it("ToggleField", async () => {
    const { container } = renderWithProviders(
      <ToggleField id="enabled" label="Enable webhooks" checked onChange={() => {}} />,
    );
    await expectNoViolations(container);
  });

  /**
   * T21.5. The card this covers is the densest control group in the console —
   * four switches, two list editors and three bounded numbers — and it is
   * mounted on three surfaces, so a label that came undone would come undone
   * three times. Rendered in the state that shows every refusal at once, since
   * an alert with no accessible name is the failure mode worth catching: on the
   * default posture the card renders no alert at all.
   */
  it("CimdPolicyFields with every refusal showing", async () => {
    const { container } = renderWithProviders(
      <CimdPolicyFields
        idPrefix="a11y"
        value={{
          ...DEFAULT_CIMD_POLICY,
          enabled: true,
          trusted_client_id_domains: ["*"],
          trusted_redirect_domains: ["https://app.example.com"],
          min_cache_secs: 1,
          max_metadata_bytes: 0,
        }}
        externalResources={[]}
        onChange={() => {}}
      />,
    );
    await expectNoViolations(container);
  });
});
