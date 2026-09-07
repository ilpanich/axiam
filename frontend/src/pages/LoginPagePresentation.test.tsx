/**
 * **W5 — the sign-in page's presentation** (`claude_dev/basic-op-gap-plan.md`
 * §4.5/§4.6, tests T5.2 and the frontend half of T6.*).
 *
 * `/oauth2/authorize` hands this page three things when the relying party
 * asked for them and the client is on the honour lane: a `login_hint` to
 * pre-fill, a `display` to lay out by, and a `ui_locale` to render in. All
 * three have already been allow-listed by the server; this file tests what the
 * page does with them, and — the half that matters more — what it does with
 * values the server would never have sent, because anybody can write a
 * `/login?…` URL.
 *
 * Kept beside `LoginPage.test.tsx` rather than inside it: that file is 64
 * tests about authenticating, and this one is about rendering.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, within } from "@testing-library/react";
import { apiMock } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

const navigate = vi.fn();
vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return { ...actual, useNavigate: () => navigate };
});

import { LoginPage } from "./LoginPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { LOCALES, MESSAGES, type Locale } from "@/i18n";

beforeEach(() => {
  vi.clearAllMocks();
  document.documentElement.removeAttribute("lang");
});

afterEach(() => {
  document.documentElement.removeAttribute("lang");
});

/** Render the sign-in page as the login hop would have delivered it. */
function renderLogin(query = "") {
  return renderWithProviders(<LoginPage />, {
    route: `/login${query}`,
  });
}

// ---------------------------------------------------------------------------
// The five locales
// ---------------------------------------------------------------------------

describe("ui_locale", () => {
  /**
   * Each shipped language renders its own page. Asserted against the catalogue
   * rather than against copied string literals: a test holding its own copy of
   * the Italian is a second translation that can drift from the first.
   */
  it.each(LOCALES)("renders the whole first step in %s", (locale: Locale) => {
    renderLogin(`?ui_locale=${locale}`);
    const m = MESSAGES[locale];

    expect(
      screen.getByRole("group", { name: m.workspaceLegend }),
    ).toBeInTheDocument();
    expect(screen.getByText(m.workspaceHelp)).toBeInTheDocument();
    expect(screen.getByLabelText(m.orgSlugLabel)).toBeInTheDocument();
    expect(
      screen.getByPlaceholderText(m.orgSlugPlaceholder),
    ).toBeInTheDocument();
    expect(
      screen.getByPlaceholderText(m.tenantSlugPlaceholder),
    ).toBeInTheDocument();
    expect(screen.getByText(m.tenantSlugHelp)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: new RegExp(m.continueAction) }),
    ).toBeInTheDocument();
  });

  /**
   * The reauthentication and step-up notices W3 and W4 added are translated
   * too — they are the messages a relying party's `prompt=login` or `acr_values`
   * produces, which is precisely the traffic `ui_locales` arrives with.
   */
  it.each(LOCALES)("renders the reauthentication notice in %s", async (locale: Locale) => {
    renderLogin(`?ui_locale=${locale}&reauth=1`);
    expect(
      await screen.findByText(MESSAGES[locale].reauthNotice),
    ).toBeInTheDocument();
  });

  it.each(LOCALES)("renders the step-up notice in %s", async (locale: Locale) => {
    renderLogin(`?ui_locale=${locale}&reauth=1&acr=urn:axiam:acr:mfa`);
    expect(
      await screen.findByText(MESSAGES[locale].reauthNoticeMfa),
    ).toBeInTheDocument();
  });

  /** The accessibility half: a screen reader picks its pronunciation here. */
  it.each(LOCALES)("sets <html lang> to %s", (locale: Locale) => {
    renderLogin(`?ui_locale=${locale}`);
    expect(document.documentElement.getAttribute("lang")).toBe(locale);
  });

  /**
   * A value the server would never have sent renders the default language,
   * silently. Never an error, and — the point — never as text on the page.
   */
  it("falls back to English for anything outside the allow-list", () => {
    for (const outside of [
      "zz",
      "fr-CA",
      "<img src=x onerror=alert(1)>",
      "en it",
    ]) {
      const { unmount } = renderLogin(
        `?ui_locale=${encodeURIComponent(outside)}`,
      );
      expect(screen.getByText(MESSAGES.en.workspaceHelp)).toBeInTheDocument();
      expect(document.body.innerHTML).not.toContain("onerror");
      expect(document.body.textContent).not.toContain(outside);
      unmount();
    }
  });

  /**
   * **Invariant 4.** No parameter at all — which is every client on the
   * `ignore` lane, because the server forwards them nothing — renders the
   * English page, with no layout class on the card.
   */
  it("renders the English page with no layout wrapper when nothing was asked for", () => {
    const { container } = renderLogin();
    expect(screen.getByText(MESSAGES.en.workspaceHelp)).toBeInTheDocument();
    expect(
      screen.getByRole("group", { name: "Select your workspace" }),
    ).toBeInTheDocument();
    // The wrapper this wave introduced does not exist at all when no `display`
    // was asked for, so the markup is exactly what it was before W5. Asserted
    // against the card's first child, which is the step indicator — as it was.
    const card = container.querySelector(".glass-card");
    expect(card?.firstElementChild?.className).toContain("flex items-center");
    expect(container.innerHTML).not.toContain("max-w-sm");
  });
});

// ---------------------------------------------------------------------------
// display
// ---------------------------------------------------------------------------

describe("display", () => {
  it("applies the compact layout for popup and nothing else", () => {
    const compact = renderLogin("?display=popup");
    const wrapper = compact.container.querySelector(".glass-card")
      ?.firstElementChild;
    expect(wrapper?.className).toContain("max-w-sm");
    compact.unmount();

    for (const other of ["page", "touch", "wap"]) {
      const { container, unmount } = renderLogin(`?display=${other}`);
      expect(container.innerHTML).not.toContain("max-w-sm");
      unmount();
    }
  });

  /** Never rendered as text, and never used as a class name of its own. */
  it("never renders the parameter's value", () => {
    for (const value of ["popup", "modal", "<script>alert(1)</script>"]) {
      const { container, unmount } = renderLogin(
        `?display=${encodeURIComponent(value)}`,
      );
      expect(container.textContent).not.toContain(value);
      expect(container.innerHTML).not.toContain("alert(1)");
      unmount();
    }
  });
});

// ---------------------------------------------------------------------------
// T5.2 — login_hint
// ---------------------------------------------------------------------------

describe("login_hint", () => {
  it("pre-fills the username field", () => {
    renderLogin("?login_hint=ada%40example.com&org=acme&tenant=default");
    expect(screen.getByLabelText("Username or email")).toHaveValue(
      "ada@example.com",
    );
  });

  it("leaves the field empty when no hint was sent", () => {
    renderLogin("?org=acme&tenant=default");
    expect(screen.getByLabelText("Username or email")).toHaveValue("");
  });

  /**
   * **T5.2.** The page is mounted with `login_hint=<script>alert(1)</script>`
   * and that string appears in the DOM **only** as the input's `value`.
   *
   * Three assertions, because "it is escaped" and "it is only in the value"
   * are different claims and the second is the one the plan asks for: no
   * `<script>` element exists, no text node carries the string, and the input's
   * value is exactly it — React's value binding, doing the one job it is
   * relied on for here.
   */
  it("shows a hostile hint only as the input's value", () => {
    const hostile = "<script>alert(1)</script>";
    const { container } = renderLogin(
      `?login_hint=${encodeURIComponent(hostile)}&org=acme&tenant=default`,
    );

    const field = screen.getByLabelText("Username or email");
    expect(field).toHaveValue(hostile);

    expect(container.querySelector("script")).toBeNull();
    expect(document.querySelector("script")).toBeNull();
    // No text node anywhere carries it: `textContent` walks the tree and does
    // not include an input's `value`, so this is exactly the claim.
    expect(container.textContent ?? "").not.toContain("alert(1)");
    expect(container.textContent ?? "").not.toContain("<script>");
    // …and the *only* place the string occurs in the serialised markup is
    // inside an attribute value. Blanking every `value="…"` and then looking
    // for it again is the precise form of "in the DOM only as the input's
    // value": an HTML serialiser does not escape `<` inside an attribute
    // (it has no need to — an attribute is not markup), so asserting on
    // `&lt;` would be asserting on the serialiser rather than on the page.
    const html = container.innerHTML;
    expect(html).toContain(`value="${hostile}"`);
    expect(html.replace(/ value="[^"]*"/g, " value=\"\"")).not.toContain(
      "<script>",
    );
  });

  it("drops a hint the server would never have sent", () => {
    for (const dropped of ["", "   ", "x".repeat(257)]) {
      const { unmount } = renderLogin(
        `?login_hint=${encodeURIComponent(dropped)}&org=acme&tenant=default`,
      );
      expect(screen.getByLabelText("Username or email")).toHaveValue("");
      unmount();
    }
  });

  /**
   * A hint is a guess about who is at the keyboard, so the field must stay
   * editable: it is seeded as the initial value, not forced on every render.
   */
  it("lets the user replace the pre-filled value", async () => {
    renderLogin("?login_hint=ada%40example.com&org=acme&tenant=default");
    const field = screen.getByLabelText("Username or email");
    const { default: userEvent } = await import("@testing-library/user-event");
    await userEvent.clear(field);
    await userEvent.type(field, "bob");
    expect(field).toHaveValue("bob");
  });
});

// ---------------------------------------------------------------------------
// The three together
// ---------------------------------------------------------------------------

describe("the three together", () => {
  /**
   * A step-up in Italian, in a popup, with a hint — the shape a relying party
   * that sends everything produces. Nothing interferes with anything else.
   */
  it("renders a step-up in a chosen language and layout with a pre-filled hint", async () => {
    const { container } = renderLogin(
      "?ui_locale=it&display=popup&login_hint=ada%40example.com" +
        "&reauth=1&acr=urn:axiam:acr:mfa&org=acme&tenant=default",
    );

    expect(
      await screen.findByText(MESSAGES.it.reauthNoticeMfa),
    ).toBeInTheDocument();
    expect(document.documentElement.getAttribute("lang")).toBe("it");
    expect(container.innerHTML).toContain("max-w-sm");
    expect(screen.getByLabelText(MESSAGES.it.usernameLabel)).toHaveValue(
      "ada@example.com",
    );
    // The ACR URN decides which factor the form demands; it is never displayed.
    expect(container.textContent).not.toContain("urn:axiam:acr:mfa");
  });

  /**
   * `<html lang>` is restored on unmount, because the admin console this page
   * navigates into is not translated and a `lang="it"` English console is the
   * same lie in the other direction.
   */
  it("restores <html lang> when the page goes away", () => {
    document.documentElement.setAttribute("lang", "en");
    const { unmount } = renderLogin("?ui_locale=de");
    expect(document.documentElement.getAttribute("lang")).toBe("de");
    unmount();
    expect(document.documentElement.getAttribute("lang")).toBe("en");
  });
});

// ---------------------------------------------------------------------------
// Reload
// ---------------------------------------------------------------------------

describe("a reload", () => {
  /**
   * Unlike `reauth` and `acr`, the three presentation parameters are not
   * stripped from the URL: a user who reloads mid-typing must not have the
   * page switch back to English, shed its layout, or lose the username filled
   * in for them. `within` is used only to keep the assertion scoped to the
   * remounted tree.
   */
  it("keeps the presentation across a remount", () => {
    const query =
      "?ui_locale=fr&display=popup&login_hint=ada%40example.com&org=acme&tenant=default";
    const first = renderLogin(query);
    expect(
      within(first.container).getByLabelText(MESSAGES.fr.usernameLabel),
    ).toHaveValue("ada@example.com");
    first.unmount();

    const second = renderLogin(query);
    expect(
      within(second.container).getByLabelText(MESSAGES.fr.usernameLabel),
    ).toHaveValue("ada@example.com");
    expect(document.documentElement.getAttribute("lang")).toBe("fr");
  });
});
