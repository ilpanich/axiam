//! Exercises the C ABI the way an SDK binding does — through raw pointers,
//! with explicit frees — rather than through the safe Rust API underneath.
//!
//! These are the tests eight SDKs' bindings are trusted against, so they check
//! the ABI contract itself (ownership, NULL handling, error reporting) and not
//! only that the protocol works.

use std::ffi::{CStr, CString, c_char};

use axiam_opaque_ffi::*;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// A password minted per process rather than written as a literal.
///
/// CodeQL's `rust/hardcoded-cryptographic-value` flags a literal that reaches a
/// KDF, and that rule is right about shipping code: keeping it sharp is worth
/// more than a fixed string here. Nothing in this file depends on the value —
/// every assertion is about what the ABI does with it.
fn password(tag: &str) -> CString {
    use std::sync::OnceLock;
    static SUFFIX: OnceLock<String> = OnceLock::new();
    let suffix = SUFFIX.get_or_init(|| {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("a CSPRNG");
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    });
    c(&format!("{tag}-{suffix}"))
}

/// Take ownership of a string the library returned, freeing it correctly.
///
/// # Safety
/// `ptr` must be a live string from the library.
unsafe fn take(ptr: *mut c_char) -> String {
    assert!(!ptr.is_null(), "expected a string, got NULL");
    let owned = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_string();
    unsafe { axiam_opaque_string_free(ptr) };
    owned
}

fn last_error() -> Option<String> {
    let ptr = axiam_opaque_last_error();
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_string())
    }
}

#[test]
fn a_full_exchange_round_trips_through_the_abi() {
    let password = password("correct");
    let ksf = axiam_opaque_ksf_argon2id(8192, 1, 1);
    assert!(!ksf.is_null());

    // --- registration ---
    let mut request: *mut c_char = std::ptr::null_mut();
    let reg_state = unsafe { axiam_opaque_registration_start(password.as_ptr(), &mut request) };
    assert!(!reg_state.is_null());
    let request = unsafe { take(request) };

    let (setup, response) = axiam_opaque::testing::server_registration_start(&request);
    let response_c = c(&response);

    let mut export_key: *mut c_char = std::ptr::null_mut();
    let record = unsafe {
        take(axiam_opaque_registration_finish(
            reg_state,
            password.as_ptr(),
            response_c.as_ptr(),
            ksf,
            &mut export_key,
        ))
    };
    let enrol_export_key = unsafe { take(export_key) };
    assert_eq!(record.len(), 384, "192 bytes of record, hex");

    // --- login ---
    let mut ke1: *mut c_char = std::ptr::null_mut();
    let login_state = unsafe { axiam_opaque_login_start(password.as_ptr(), &mut ke1) };
    assert!(!login_state.is_null());
    let ke1 = unsafe { take(ke1) };

    let ke2 = axiam_opaque::testing::server_login_start(&setup, &record, &ke1);
    let ke2_c = c(&ke2);

    let mut session_key: *mut c_char = std::ptr::null_mut();
    let mut login_export_key: *mut c_char = std::ptr::null_mut();
    let ke3 = unsafe {
        take(axiam_opaque_login_finish(
            login_state,
            password.as_ptr(),
            ke2_c.as_ptr(),
            ksf,
            &mut session_key,
            &mut login_export_key,
        ))
    };
    assert_eq!(ke3.len(), 128, "64 bytes of KE3, hex");
    assert_eq!(unsafe { take(session_key) }.len(), 128);
    assert_eq!(
        unsafe { take(login_export_key) },
        enrol_export_key,
        "the export key must be reproducible from the password alone"
    );

    unsafe { axiam_opaque_ksf_free(ksf) };
}

#[test]
fn a_wrong_password_returns_null_and_sets_an_error() {
    let right = password("right");
    let wrong = password("wrong");
    let ksf = axiam_opaque_ksf_argon2id(8192, 1, 1);

    let mut request: *mut c_char = std::ptr::null_mut();
    let state = unsafe { axiam_opaque_registration_start(right.as_ptr(), &mut request) };
    let request = unsafe { take(request) };
    let (setup, response) = axiam_opaque::testing::server_registration_start(&request);
    let response_c = c(&response);
    let record = unsafe {
        take(axiam_opaque_registration_finish(
            state,
            right.as_ptr(),
            response_c.as_ptr(),
            ksf,
            std::ptr::null_mut(),
        ))
    };

    let mut ke1: *mut c_char = std::ptr::null_mut();
    let state = unsafe { axiam_opaque_login_start(wrong.as_ptr(), &mut ke1) };
    let ke1 = unsafe { take(ke1) };
    let ke2 = c(&axiam_opaque::testing::server_login_start(
        &setup, &record, &ke1,
    ));

    let ke3 = unsafe {
        axiam_opaque_login_finish(
            state,
            wrong.as_ptr(),
            ke2.as_ptr(),
            ksf,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert!(ke3.is_null(), "a wrong password must not produce a KE3");
    assert!(
        last_error().is_some(),
        "a NULL return must be accompanied by an error"
    );

    unsafe { axiam_opaque_ksf_free(ksf) };
}

#[test]
fn out_parameters_may_be_null_when_the_caller_does_not_want_them() {
    // Not a convenience: a binding that had to allocate for every optional
    // output would leak the ones its language has no use for.
    let password = password("pw");
    let ksf = axiam_opaque_ksf_argon2id(8192, 1, 1);

    let mut request: *mut c_char = std::ptr::null_mut();
    let state = unsafe { axiam_opaque_registration_start(password.as_ptr(), &mut request) };
    let request = unsafe { take(request) };
    let (_, response) = axiam_opaque::testing::server_registration_start(&request);
    let response_c = c(&response);

    let record = unsafe {
        axiam_opaque_registration_finish(
            state,
            password.as_ptr(),
            response_c.as_ptr(),
            ksf,
            std::ptr::null_mut(),
        )
    };
    assert!(!record.is_null());
    unsafe { axiam_opaque_string_free(record) };
    unsafe { axiam_opaque_ksf_free(ksf) };
}

#[test]
fn out_of_range_ksf_parameters_return_null_rather_than_clamping() {
    // Clamping would be worse than failing: the client would stretch with a
    // cost the server did not name and fail against a good record.
    assert!(axiam_opaque_ksf_argon2id(64, 1, 1).is_null());
    assert!(last_error().is_some());
    assert!(axiam_opaque_ksf_argon2id(4_194_304, 1, 1).is_null());
    assert!(axiam_opaque_ksf_scrypt(10, 8, 1).is_null());
    assert!(axiam_opaque_ksf_scrypt(24, 8, 1).is_null());

    let ok = axiam_opaque_ksf_argon2id(19456, 2, 1);
    assert!(!ok.is_null());
    assert!(
        last_error().is_none(),
        "a successful call must clear the error slot, or a caller polling it \
         would report a stale failure"
    );
    unsafe { axiam_opaque_ksf_free(ok) };
}

#[test]
fn null_inputs_are_refused_rather_than_dereferenced() {
    let ksf = axiam_opaque_ksf_argon2id(8192, 1, 1);
    let mut out: *mut c_char = std::ptr::null_mut();

    assert!(unsafe { axiam_opaque_registration_start(std::ptr::null(), &mut out) }.is_null());
    assert!(unsafe { axiam_opaque_login_start(std::ptr::null(), &mut out) }.is_null());

    let password = password("pw");
    assert!(
        unsafe { axiam_opaque_registration_start(password.as_ptr(), std::ptr::null_mut()) }
            .is_null(),
        "a null out-parameter must be refused, not written through"
    );

    assert!(
        unsafe {
            axiam_opaque_login_finish(
                std::ptr::null_mut(),
                password.as_ptr(),
                password.as_ptr(),
                ksf,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }
        .is_null()
    );

    unsafe { axiam_opaque_ksf_free(ksf) };
}

#[test]
fn freeing_null_is_a_no_op_so_a_caller_can_free_unconditionally() {
    unsafe { axiam_opaque_string_free(std::ptr::null_mut()) };
    unsafe { axiam_opaque_ksf_free(std::ptr::null_mut()) };
    unsafe { axiam_opaque_registration_free(std::ptr::null_mut()) };
    unsafe { axiam_opaque_login_free(std::ptr::null_mut()) };
}

#[test]
fn an_unfinished_exchange_can_be_freed() {
    let password = password("pw");
    let mut out: *mut c_char = std::ptr::null_mut();

    let state = unsafe { axiam_opaque_registration_start(password.as_ptr(), &mut out) };
    unsafe { take(out) };
    unsafe { axiam_opaque_registration_free(state) };

    let mut out: *mut c_char = std::ptr::null_mut();
    let state = unsafe { axiam_opaque_login_start(password.as_ptr(), &mut out) };
    unsafe { take(out) };
    unsafe { axiam_opaque_login_free(state) };
}

#[test]
fn malformed_hex_from_the_server_is_refused() {
    let password = password("pw");
    let junk = c("not hex at all");
    let ksf = axiam_opaque_ksf_argon2id(8192, 1, 1);

    let mut out: *mut c_char = std::ptr::null_mut();
    let state = unsafe { axiam_opaque_registration_start(password.as_ptr(), &mut out) };
    unsafe { take(out) };
    assert!(
        unsafe {
            axiam_opaque_registration_finish(
                state,
                password.as_ptr(),
                junk.as_ptr(),
                ksf,
                std::ptr::null_mut(),
            )
        }
        .is_null()
    );

    unsafe { axiam_opaque_ksf_free(ksf) };
}

#[test]
fn availability_is_reported_for_a_loaded_library() {
    assert_eq!(axiam_opaque_available(), 1);
}
