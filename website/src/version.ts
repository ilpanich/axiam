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
export const SECURITY_VERIFIED_RELEASE = "1.0.0-alpha38";

/** Date of that verification pass, ISO 8601. */
export const SECURITY_VERIFIED_DATE = "2026-08-22";
