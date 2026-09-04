/**
 * The release the Security section's claims were last verified against.
 *
 * One constant, quoted everywhere the page makes a dated claim, so a reader can
 * see at a glance whether what they are reading was checked against the server
 * they are running. It is maintained by hand on purpose: it records when a
 * human last re-derived the claims from source, which is not something the
 * workspace version can tell us — reading `Cargo.toml` here would make every
 * release bump silently re-assert a verification that never happened.
 *
 * Update it only together with the handoff block in
 * `claude_dev/threat-modeling-and-security.md`, which is the record of what that
 * verification covered.
 */
export const SECURITY_VERIFIED_RELEASE = "1.0.0-beta11";

/** Date of that verification pass, ISO 8601. */
export const SECURITY_VERIFIED_DATE = "2026-09-04";

/**
 * The release a documentation page's claims were last verified against.
 *
 * Separate from `SECURITY_VERIFIED_RELEASE` and hand-maintained for the same
 * reason: it records when someone last re-derived a page's contents from
 * source, which no automatic value can tell us.
 *
 * It is stamped **per page**, via `DocPage.verifiedRelease`, rather than across
 * the section. A section-wide banner would assert a verification that did not
 * happen for pages nobody looked at, which is worse than saying nothing — an
 * unstamped page reads as "not checked recently", which is exactly what it is.
 */
export const DOCS_VERIFIED_RELEASE = "1.0.0-beta07";
