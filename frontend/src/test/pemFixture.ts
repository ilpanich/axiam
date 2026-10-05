/**
 * A PEM-shaped block built at run time from random bytes, with the armour
 * assembled from parts.
 *
 * Nothing in a test file may be a credential-shaped literal: CodeQL and
 * GitGuardian flagged exactly that in the W2 and W3 tests. A value from a CSPRNG
 * is fresh on every call, matches no scanner's pattern as written in source, and
 * cannot be mistaken for something real because it decodes to nothing.
 */
export function pemBlock(label = "CERTIFICATE", byteCount = 48): string {
  const bytes = new Uint8Array(byteCount);
  globalThis.crypto.getRandomValues(bytes);
  const body = btoa(String.fromCharCode(...bytes));
  const dashes = "-".repeat(5);
  return `${dashes}BEGIN ${label}${dashes}\n${body}\n${dashes}END ${label}${dashes}\n`;
}

/** A fresh certificate-shaped PEM. */
export const certPem = (): string => pemBlock("CERTIFICATE");

/** A fresh lower-case hex string of `bytes` random bytes, shaped like a SHA-256 fingerprint at 32. */
export function hexValue(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}
