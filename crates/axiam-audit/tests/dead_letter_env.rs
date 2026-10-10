//! `AXIAM__GDPR_AUDIT_DLQ_FILE` selects the dead-letter writer: set, a writer
//! for that file; unset or empty, none. One test, in its own binary, because it
//! changes the process environment.

use axiam_audit::{DEAD_LETTER_FILE_ENV, DeadLetterWriter};

#[tokio::test]
async fn the_environment_variable_selects_the_writer() {
    let path = std::env::temp_dir().join(format!("axiam-dlq-env-{}.jsonl", std::process::id()));
    // SAFETY: the only test in this binary, so nothing else reads the
    // environment concurrently.
    unsafe {
        std::env::remove_var(DEAD_LETTER_FILE_ENV);
    }
    assert!(!DeadLetterWriter::from_env().is_configured(), "unset");
    unsafe {
        std::env::set_var(DEAD_LETTER_FILE_ENV, "");
    }
    assert!(!DeadLetterWriter::from_env().is_configured(), "empty");
    unsafe {
        std::env::set_var(DEAD_LETTER_FILE_ENV, &path);
    }
    assert!(DeadLetterWriter::from_env().is_configured(), "set");
    unsafe {
        std::env::remove_var(DEAD_LETTER_FILE_ENV);
    }
}
