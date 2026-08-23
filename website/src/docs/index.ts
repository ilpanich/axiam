import type { DocPage, DocSectionGroup } from "./types";
import { GETTING_STARTED_PAGES } from "./getting-started";
import { AUTHENTICATION_PAGES } from "./authentication";
import { AUTHORIZATION_PAGES } from "./authorization";
import { OAUTH2_PAGES } from "./oauth2";
import { INTEGRATE_PAGES } from "./integrate";
import { CONFIGURATION_PAGES } from "./configuration";
import { OPERATE_PAGES } from "./operate";
import { REFERENCE_PAGES } from "./reference";

export type {
  DocBlock,
  DocCard,
  DocCodeTab,
  DocEndpoint,
  DocLink,
  DocPage,
  DocSectionGroup,
  DocStep,
} from "./types";

/**
 * Documentation content model.
 *
 * The docs section is a self-contained documentation site: an ordered set of
 * pages grouped into sidebar sections. Each page is a list of blocks (headings,
 * prose, code, callouts, tables, endpoint lists, link cards) that the Docs
 * renderer turns into an article, an auto-generated "On this page" table of
 * contents built from the `h` blocks, and a client-side search index.
 *
 * Pages are authored one module per section rather than in a single file: the
 * set is large enough that a single module made every edit a merge conflict,
 * and the section boundaries are the natural seams.
 *
 * `DOC_SECTIONS` is the source of truth for **order** — both the sidebar's and
 * the previous/next pager's. A page whose slug is missing from it is
 * unreachable from the navigation, which `docSectionsAreComplete` asserts
 * against at module load in development.
 */

export const DOC_PAGES: DocPage[] = [
  ...GETTING_STARTED_PAGES,
  ...AUTHENTICATION_PAGES,
  ...AUTHORIZATION_PAGES,
  ...OAUTH2_PAGES,
  ...INTEGRATE_PAGES,
  ...CONFIGURATION_PAGES,
  ...OPERATE_PAGES,
  ...REFERENCE_PAGES,
];

export const DOC_SECTIONS: DocSectionGroup[] = [
  {
    label: "Getting started",
    slugs: ["overview", "quickstart", "installation", "bootstrap", "concepts", "tutorial"],
  },
  {
    label: "Authentication",
    slugs: ["auth", "opaque", "mfa", "passkeys", "federation", "service-accounts"],
  },
  {
    label: "Authorization",
    slugs: ["authz", "rbac", "deny", "uma"],
  },
  {
    label: "OAuth2 & OIDC",
    slugs: ["oauth2", "device-flow", "token-exchange", "logout", "fapi2", "par"],
  },
  {
    label: "APIs & integration",
    slugs: ["rest", "grpc", "amqp", "scim", "webhooks", "reactors", "errors"],
  },
  {
    label: "Operate",
    slugs: [
      "deploy",
      "configuration",
      "secrets",
      "settings",
      "pki",
      "audit",
      "observability",
      "hardening",
      "troubleshooting",
    ],
  },
  {
    label: "Reference",
    slugs: ["compliance", "sdks"],
  },
];

/** Every page in navigation order — the order the previous/next pager walks. */
export const DOC_ORDER: string[] = DOC_SECTIONS.flatMap((s) => s.slugs);

/** Look a page up by slug. */
export function findDocPage(slug: string): DocPage | undefined {
  return DOC_PAGES.find((p) => p.slug === slug);
}

/**
 * Assert that navigation and content agree: every authored page appears in
 * exactly one section, and every slug a section lists resolves to a page.
 *
 * Returns the problems rather than throwing, so the caller decides whether a
 * mismatch is fatal. `Docs.tsx` surfaces it in development only — a docs site
 * that refuses to render because one page is unlisted would be a worse failure
 * than the one it is reporting.
 */
export function docSectionsAreComplete(): string[] {
  const problems: string[] = [];
  const listed = new Set<string>();

  for (const section of DOC_SECTIONS) {
    for (const slug of section.slugs) {
      if (listed.has(slug)) problems.push(`slug listed twice in navigation: ${slug}`);
      listed.add(slug);
      if (!findDocPage(slug)) problems.push(`navigation lists an unknown page: ${slug}`);
    }
  }

  for (const page of DOC_PAGES) {
    if (!listed.has(page.slug)) problems.push(`page is not in any section: ${page.slug}`);
  }

  return problems;
}
