//! `AXIAM__GDPR_AUDIT_DLQ_FILE` selects the dead-letter writer: set, a writer
//! for that file; unset or empty, none. `AXIAM__GDPR_AUDIT_DLQ_MAX_BYTES`
//! bounds it, and a value that is not a budget is refused (R1W2-02). One test,
//! in its own binary, because it changes the process environment.

use axiam_audit::dead_letter::{
    DEFAULT_MAX_BYTES, MAX_BYTES_ENV, MIN_MAX_BYTES, max_bytes_from_env,
};
use axiam_audit::{DEAD_LETTER_FILE_ENV, DeadLetterWriter};

#[tokio::test]
async fn the_environment_variable_selects_the_writer() {
    let path = std::env::temp_dir().join(format!("axiam-dlq-env-{}.jsonl", std::process::id()));
    // SAFETY: the only test in this binary, so nothing else reads the
    // environment concurrently.
    unsafe {
        std::env::remove_var(DEAD_LETTER_FILE_ENV);
    }
    assert!(
        !DeadLetterWriter::from_env().unwrap().is_configured(),
        "unset"
    );
    unsafe {
        std::env::set_var(DEAD_LETTER_FILE_ENV, "");
    }
    assert!(
        !DeadLetterWriter::from_env().unwrap().is_configured(),
        "empty"
    );
    unsafe {
        std::env::set_var(DEAD_LETTER_FILE_ENV, &path);
    }
    assert!(DeadLetterWriter::from_env().unwrap().is_configured(), "set");

    // The budget: unset is the default, a whole number of bytes at or above
    // the minimum is taken, anything else fails (the boot, in the server).
    unsafe {
        std::env::remove_var(MAX_BYTES_ENV);
    }
    assert_eq!(max_bytes_from_env(), Ok(DEFAULT_MAX_BYTES));
    for (value, expected) in [
        ("201326592", Some(201_326_592)),
        (" 1048576 ", Some(MIN_MAX_BYTES)),
        ("1048575", None),
        ("0", None),
        ("192Mi", None),
        ("-1", None),
    ] {
        unsafe {
            std::env::set_var(MAX_BYTES_ENV, value);
        }
        assert_eq!(max_bytes_from_env().ok(), expected, "{value:?}");
        if expected.is_none() {
            let error = DeadLetterWriter::from_env().err().expect("refused");
            assert!(error.contains(MAX_BYTES_ENV), "{error}");
        }
    }
    unsafe {
        std::env::remove_var(MAX_BYTES_ENV);
        std::env::remove_var(DEAD_LETTER_FILE_ENV);
    }
}
