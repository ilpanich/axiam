/**
 * Generate `src/contractAnchors.ts` from the committed `sdks/CONTRACT.md`.
 *
 * The docs pages link into the SDK contract constantly, and most of those
 * links used to point at the file rather than at the section — which lands a
 * reader at the top of a 5,600-line document and asks them to search. Writing
 * the anchor by hand instead is worse: GitHub's slug algorithm drops `.` from
 * `§22.11`, keeps `§`, collapses `C++` to `c`, and leaves a double hyphen
 * wherever an em dash was. A hand-typed anchor that is subtly wrong still
 * renders as a link and still fails silently.
 *
 * So the anchors are derived from the headings themselves. The algorithm is
 * verified against CONTRACT.md's own internal links, which use the same slugs:
 * if this file's output ever stops matching those, the check below fails
 * rather than emitting links that quietly go nowhere.
 *
 * Run it after CONTRACT.md changes:
 *
 *   npm run gen:contract-anchors
 *
 * The generated file is committed; CI does not regenerate it.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const CONTRACT = resolve(here, "../../sdks/CONTRACT.md");
const OUT = resolve(here, "../src/contractAnchors.ts");

const source = readFileSync(CONTRACT, "utf8");

/**
 * GitHub's heading-anchor slug: lowercase, drop everything that is not a word
 * character, whitespace, hyphen or section sign, then spaces to hyphens.
 */
const slug = (heading) =>
  heading
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s\-_§]/gu, "")
    .replace(/\s/g, "-");

/** Every `§N`-prefixed heading, in document order. */
const sections = [];
for (const line of source.split("\n")) {
  const m = /^#{1,6}\s+(§([\d.]+[a-z]?)\s.*)$/.exec(line);
  if (!m) continue;
  const [, heading, number] = m;
  sections.push({ number, heading, anchor: `#${slug(heading)}` });
}

if (sections.length === 0) {
  throw new Error("gen-contract-anchors: no §-numbered headings found in CONTRACT.md");
}

/**
 * Verify against the contract's own internal links.
 *
 * CONTRACT.md links to its own sections as `[§22.11](#§2211-swift-…)`. Every
 * such link should resolve to a heading this generator produced, so a link
 * that does not is one of two real defects, and the message says both because
 * they are fixed in different files:
 *
 *   - this slug function has drifted from GitHub's, or
 *   - CONTRACT.md carries a broken anchor.
 *
 * The second is not hypothetical. When this check was first written it found
 * §14.1's link to `device_login` spelled with one hyphen where the same
 * heading's two other links used two — a link that rendered fine and went
 * nowhere.
 */
const known = new Set(sections.map((s) => s.anchor));

const missed = [];
for (const m of source.matchAll(/\]\((#§[^)]+)\)/g)) {
  if (!known.has(m[1])) missed.push(m[1]);
}
if (missed.length > 0) {
  throw new Error(
    `gen-contract-anchors: CONTRACT.md links to anchors no heading produces. ` +
      `Either the slug function below has drifted from GitHub's, or the contract ` +
      `carries a broken anchor — check whether the target heading exists before ` +
      `changing this file:\n  ${[...new Set(missed)].join("\n  ")}`,
  );
}

/** Duplicate section numbers would make lookup by number ambiguous. */
const seen = new Map();
for (const s of sections) {
  if (seen.has(s.number)) {
    throw new Error(
      `gen-contract-anchors: §${s.number} appears twice ("${seen.get(s.number)}" and "${s.heading}")`,
    );
  }
  seen.set(s.number, s.heading);
}

const version = /^\*Contract version: ([^\s—]+)/m.exec(source)?.[1] ?? "";

const table = Object.fromEntries(sections.map((s) => [s.number, s.anchor]));

writeFileSync(
  OUT,
  `// AUTO-GENERATED — do not edit by hand.
//
// Produced by \`npm run gen:contract-anchors\` from \`sdks/CONTRACT.md\`.
// Re-run the generator whenever the contract's headings change.

const BLOB = "https://github.com/ilpanich/axiam/blob/main/sdks/CONTRACT.md";

/** The contract version these anchors were derived from. */
export const CONTRACT_VERSION = ${JSON.stringify(version)};

/** Section number (without the \`§\`) to its GitHub heading anchor. */
export const CONTRACT_ANCHORS: Record<string, string> = ${JSON.stringify(table, null, 1)};

/**
 * A deep link to one contract section.
 *
 * Falls back to the file when the section is unknown, so a link is never
 * broken — but the section really should be there, since the generator reads
 * the same file the reader lands in.
 */
export function contractLink(section: string): string {
  const anchor = CONTRACT_ANCHORS[section];
  return anchor ? \`\${BLOB}\${anchor}\` : BLOB;
}
`,
);

console.log(`contractAnchors.ts: ${sections.length} sections at contract ${version || "?"}`);
