# Deferred Items — Phase 09 Critical Remediation

Out-of-scope discoveries found during execution. NOT fixed (per SCOPE BOUNDARY rule).

## 09-01 (SEC-002)

- **Pre-existing clippy lint in `crates/axiam-api-rest/src/middleware/csrf.rs:240`**
  - `error: items after a test module` — surfaces only under `cargo clippy --tests -D warnings`.
  - Last touched in Phase 6 (commit `c0503a7`, D-18); NOT introduced by 09-01.
  - Unrelated to org-ownership guards. Should be tracked under Phase 19 (TODO/lint cleanup).
  - Fix: move the `clear_csrf_cookie()` fn (and any other items) above the `#[cfg(test)] mod tests` block in `csrf.rs`.
