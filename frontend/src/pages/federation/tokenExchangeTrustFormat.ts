/**
 * X4 — text formats for the token-exchange trust editor.
 *
 * Separate from the component because these are pure functions with their own
 * tests, and the lint rule that keeps fast-refresh working requires a component
 * file to export only components. Both reasons point the same way.
 */

/** Parse the audience textarea: one per line, blanks dropped. */
export function parseAudiences(raw: string): string[] {
  return raw
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s !== "");
}

export function stringifyAudiences(audiences: string[]): string {
  return audiences.join("\n");
}

/**
 * Parse the scope map from `partner.value = axiam:scope another:scope` lines.
 *
 * A line-oriented format rather than raw JSON: this is a mapping an operator
 * reads and edits far more often than they write, and `{"a": ["b"]}` obscures
 * the one thing they are checking — which partner claim buys which scope.
 *
 * Returns the parsed map, or an error naming the offending line. Never returns
 * a partial map: a half-parsed trust configuration submitted by accident is
 * exactly the failure this whole form is careful about.
 */
export function parseScopeMap(
  raw: string,
): { value: Record<string, string[]> } | { error: string } {
  const map: Record<string, string[]> = {};
  const lines = raw.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === "" || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq === -1) {
      return {
        error: `Line ${i + 1}: expected "partner.value = axiam:scope [more:scopes]".`,
      };
    }
    const key = line.slice(0, eq).trim();
    const scopes = line
      .slice(eq + 1)
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter((s) => s !== "");
    if (key === "") {
      return { error: `Line ${i + 1}: the partner value is blank.` };
    }
    if (scopes.length === 0) {
      return {
        error: `Line ${i + 1}: "${key}" maps to no AXIAM scopes. Remove the line instead — an empty mapping grants nothing and reads as if it grants something.`,
      };
    }
    map[key] = scopes;
  }
  return { value: map };
}

export function stringifyScopeMap(map: Record<string, string[]>): string {
  return Object.entries(map)
    .map(([key, scopes]) => `${key} = ${scopes.join(" ")}`)
    .join("\n");
}
