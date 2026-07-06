# Deferred Items

Out-of-scope findings discovered during plan execution, logged per the executor's
scope-boundary rule (only fix issues directly caused by the current task's changes).

## 29-04

- **Pre-existing test failure (unrelated to 29-04's changes):**
  `req14_tenant_isolation_test::resource_delete_with_children_rejected` fails against
  `resource.rs`'s `delete()` method — a multi-statement `BEGIN TRANSACTION ... THROW
  'cannot delete resource with children' ... COMMIT TRANSACTION` query. The `.check()`
  call surfaces `"Migration failed: The query was not executed due to a failed
  transaction"` instead of the expected `"cannot delete resource with children"` THROW
  message, so the test's substring assertion fails. Confirmed pre-existing: `delete()`
  was not touched by 29-04 (verified via `git diff` — zero lines changed in that
  method), and the failure reproduces identically when tested against the 29-04 Task 1
  commit alone (before any Task 2 dedup changes). Likely a SurrealDB v3 `.check()`/THROW
  error-surfacing behavior change unrelated to this phase's refactor. Needs its own
  investigation — out of scope for QUAL-02/QUAL-07's mechanical dedup pass.

- **Pre-existing clippy warning (different crate, not touched by 29-04):**
  `crates/axiam-auth/src/token.rs:42` — `impl Default for SubjectKind` triggers
  `clippy::derivable_impls` (`cargo clippy -p axiam-db --lib --tests -- -D warnings`
  fails only because it also lints the `axiam-auth` dependency in the same invocation).
  `axiam-db` itself has zero clippy warnings (`cargo clippy -p axiam-db --lib --tests`
  without `-D warnings` compiles clean). Not fixed here — `axiam-auth/src/token.rs` is
  outside this plan's `files_modified` list.

- **Unused `argon2` dependency in `crates/axiam-db/Cargo.toml`:** After deleting the
  pepper-less `verify_password` (QUAL-07), the `argon2` crate is no longer referenced
  anywhere in `axiam-db/src/`. Left in `Cargo.toml` since `Cargo.toml` is not in this
  plan's `files_modified` list and no `unused_crate_dependencies` lint is enabled in
  this workspace (so it does not fail any gate). Candidate for a future cleanup pass.

## 29-05

- Both pre-existing issues above (the `resource_delete_with_children_rejected` test
  failure and the `axiam-auth/src/token.rs` clippy warning) were re-confirmed present
  and unrelated to 29-05's changes: `resource.rs` and `axiam-auth/src/token.rs` are not
  in 29-05's `files_modified` list and were not touched. No new out-of-scope findings
  discovered during 29-05's file-group-B dedup + `federation_link.rs` parse_uuid removal.

## RESOLVED — `resource_delete_with_children_rejected` was a 29-02 regression, not pre-existing

Orchestrator follow-up (post-29-05): the "pre-existing" label above was **incorrect**.
Investigation traced the failure to 29-02 (`3e8394a`), which moved `resource::delete`'s
child guard from a Rust pre-check (returning `AxiamError::Validation { "cannot delete
resource with children" }`) into an in-transaction `THROW`. The THROW message fires on
its own statement slot, but the trailing `DELETE`/`COMMIT` slots report the generic
"not executed due to a failed transaction" error, and `Response::check()` surfaced one
of those instead of the THROW text — so the guard rejection was silently downgraded to
an opaque `DbError::Migration`, failing the test's `contains("children")` assertion.
(The sibling cycle/depth guards pass because they are pure-Rust checks, not SQL THROWs;
`account_deletion`'s THROW test only asserts `is_err()`, so it never caught this class.)
Fixed by scanning **all** statement errors via `Response::take_errors()` instead of
relying on `check()`'s single surfaced message, preserving 29-02's in-transaction
TOCTOU fix. `req14_tenant_isolation_test` now 7/7. The `axiam-auth` clippy warning and
unused `argon2` dep remain genuinely deferred (out of this phase's file scope).
