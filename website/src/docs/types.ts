import type { Page } from "../types";

/**
 * Content model shared by the documentation site and the Security section.
 *
 * Prose is authored as arrays of blocks rather than as markup so that both
 * sections render through one component (`components/DocBlocks.tsx`) and stay
 * visually identical, and so the docs shell can derive navigation, an "On this
 * page" table of contents and the client-side search index from the content
 * itself rather than from a second hand-maintained list.
 */

/** An external reference rendered as a labelled link with an optional note. */
export interface DocLink {
  label: string;
  href: string;
  note?: string;
}

/** An internal cross-link rendered as a clickable card. */
export interface DocCard {
  title: string;
  body: string;
  to: Page;
  /**
   * When `to` is `"docs"`, the documentation page to open. Without it a card
   * lands on the docs section's default page, which for a card promising a
   * specific topic is a small betrayal.
   */
  doc?: string;
}

/** One numbered step in a `steps` block. */
export interface DocStep {
  title: string;
  body: string;
  code?: string;
}

/** One HTTP operation row in an `api` block. */
export interface DocEndpoint {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  summary: string;
  /** Marks an endpoint reachable without an access token. */
  public?: boolean;
}

/** One language tab in a `codegroup` block. */
export interface DocCodeTab {
  label: string;
  code: string;
}

export type DocBlock =
  | { type: "h"; id: string; text: string }
  | { type: "p"; text: string }
  | { type: "list"; items: string[] }
  | { type: "code"; caption?: string; code: string }
  | { type: "note"; text: string }
  | { type: "warn"; text: string }
  | {
      type: "table";
      headers: string[];
      rows: string[][];
      /**
       * Render the first column as ordinary prose rather than the default
       * monospace, non-wrapping key column — used where the first cell is a
       * phrase (an asset, a trust boundary, a framework) rather than an
       * identifier.
       */
      proseFirstCol?: boolean;
    }
  | { type: "cards"; cards: DocCard[] }
  | { type: "links"; links: DocLink[] }
  /** A numbered procedure. Use where order matters and prose would obscure it. */
  | { type: "steps"; steps: DocStep[] }
  /** An HTTP endpoint reference table, method-coloured. */
  | { type: "api"; endpoints: DocEndpoint[] }
  /** One sample in several languages, shown as tabs. */
  | { type: "codegroup"; caption?: string; tabs: DocCodeTab[] };

export interface DocPage {
  slug: string;
  section: string;
  navLabel: string;
  title: string;
  intro: string;
  blocks: DocBlock[];
}

export interface DocSectionGroup {
  label: string;
  slugs: string[];
}
