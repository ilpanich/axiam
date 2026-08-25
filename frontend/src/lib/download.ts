/**
 * Hand the browser a file it did not fetch.
 *
 * Certificates are the reason this exists. The public half of a certificate is
 * not a secret and every relying party needs a copy of it, but AXIAM has no
 * endpoint that serves one as a file — it is a field inside a JSON document,
 * and an operator who needs `acme-device-001.crt` on disk should not have to
 * select text out of a `<pre>` and hope the trailing newline survived.
 *
 * A `Blob` and an object URL rather than a `data:` URI: Chrome caps `data:`
 * navigations at a few megabytes and a PEM chain from a long PKI can exceed it,
 * and a `data:` URL leaks the whole file into the URL bar and any extension
 * watching it.
 */
export function downloadTextFile(
  filename: string,
  contents: string,
  mimeType = "application/x-pem-file"
): void {
  const url = URL.createObjectURL(new Blob([contents], { type: mimeType }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  // Appended before clicking: Firefox ignores a click on an anchor that is not
  // in the document, and does so silently.
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  // Deferred, because revoking synchronously races the download in Safari,
  // which has not necessarily read the blob by the time `click()` returns.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/**
 * A filename that survives a filesystem.
 *
 * Certificate subjects are X.500 distinguished names — `CN=device-001,
 * OU=Fleet/EU` — and contain slashes, commas, spaces and colons, several of
 * which are path separators or reserved on at least one of the three platforms
 * an operator might be using. Everything outside a conservative set becomes a
 * hyphen, runs collapse, and an empty result falls back to `certificate` rather
 * than producing a file named `.pem` that most file managers hide.
 */
export function certificateFilename(subject: string, extension: string): string {
  const stem = subject
    .replace(/^CN=/i, "")
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return `${stem || "certificate"}.${extension}`;
}
