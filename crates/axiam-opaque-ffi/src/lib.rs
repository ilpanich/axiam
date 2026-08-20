//! C ABI for AXIAM's OPAQUE (RFC 9807) client.
//!
//! Eight SDKs bind this rather than implementing OPAQUE: Python, Java, Kotlin,
//! C#, PHP, Swift, C and C++. See `sdks/CONTRACT.md` §23.1 for why none of them
//! is permitted to write its own.
//!
//! # Shape of the interface
//!
//! Everything crosses this boundary as **NUL-terminated lowercase hex**, which
//! is also the AXIAM wire encoding. That is a deliberate narrowing: a
//! `const char *` API is expressible in every one of those eight languages
//! without anyone inventing a byte-buffer ownership convention, and hex has no
//! variant spellings to disagree about the way base64 does. The cost is a
//! constant factor on message sizes that top out at 320 bytes.
//!
//! Two rules an integrator must follow, and one they cannot get wrong:
//!
//! 1. **Every non-null `char *` returned by this library must be released with
//!    [`axiam_opaque_string_free`].** It was allocated by Rust and cannot be
//!    freed by the caller's allocator.
//! 2. **Every state handle must be released**, either by passing it to its
//!    `finish` function — which consumes it — or by calling the matching
//!    `_free`. A handle is single-use; calling `finish` twice on one is not
//!    possible because the first call takes ownership.
//! 3. A `NULL` return means failure. [`axiam_opaque_last_error`] returns a
//!    description for the calling thread. It is deliberately coarse: a caller
//!    that could distinguish "the server sent a malformed KE2" from "your
//!    password is wrong" would be reporting a fact it cannot establish.
//!
//! # Thread safety
//!
//! Every function is safe to call from any thread. State handles are **not**
//! shared: a handle must be used by one thread at a time, which is the natural
//! shape anyway since it belongs to one in-flight exchange. The last-error slot
//! is thread-local, so an error raised on one thread is never observed on
//! another.
//!
//! # Panics
//!
//! Every entry point is wrapped so that a Rust panic becomes a `NULL` return
//! rather than an unwind across the ABI boundary, which is undefined behaviour.

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};

use axiam_opaque::{AxiamKsf, ClientLoginState, ClientRegistrationState};

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_error(message: &str) {
    let stored = CString::new(message).unwrap_or_else(|_| {
        CString::new("OPAQUE error message contained an interior NUL").expect("static string")
    });
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(stored));
}

fn clear_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
}

/// Run `body`, turning a panic or an error into a `NULL` return with the error
/// slot set.
fn guard<T>(body: impl FnOnce() -> Result<*mut T, String>) -> *mut T {
    clear_error();
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(value)) => value,
        Ok(Err(message)) => {
            set_error(&message);
            std::ptr::null_mut()
        }
        Err(_) => {
            // A panic must never unwind across the ABI boundary.
            set_error("internal error");
            std::ptr::null_mut()
        }
    }
}

/// Read a caller-supplied C string.
///
/// # Safety
/// `ptr` must be NULL or a valid NUL-terminated string.
unsafe fn read_str<'a>(ptr: *const c_char, label: &str) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err(format!("{label} must not be null"));
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| format!("{label} must be valid UTF-8"))
}

fn to_c_string(value: &str) -> Result<*mut c_char, String> {
    CString::new(value)
        .map(CString::into_raw)
        .map_err(|_| "value contained an interior NUL".to_string())
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

/// Release a string returned by this library.
///
/// Passing `NULL` is a no-op, so a caller can free unconditionally after a
/// failed call.
///
/// # Safety
/// `ptr` must be NULL or a pointer previously returned by this library and not
/// already freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn axiam_opaque_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(unsafe { CString::from_raw(ptr) });
    }
}

/// A description of the most recent failure **on this thread**, or `NULL` if
/// the last call succeeded.
///
/// The returned pointer is owned by the library and is valid until the next
/// call on this thread. Copy it before calling anything else; do **not** pass
/// it to [`axiam_opaque_string_free`].
#[unsafe(no_mangle)]
pub extern "C" fn axiam_opaque_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| match slot.borrow().as_ref() {
        Some(message) => message.as_ptr(),
        None => std::ptr::null(),
    })
}

/// Non-zero when this build can perform OPAQUE.
///
/// Always `1` here — if the library loaded at all, it works. It exists so that
/// an SDK's `opaqueAvailable()` (CONTRACT §23.2) has something to call after a
/// successful `dlopen`, and so that a binding which failed to load can answer
/// the same question with `0` without a special case.
#[unsafe(no_mangle)]
pub extern "C" fn axiam_opaque_available() -> i32 {
    1
}

// ---------------------------------------------------------------------------
// Key-stretching parameters
// ---------------------------------------------------------------------------

/// An opaque handle to key-stretching parameters.
pub struct AxiamOpaqueKsf(AxiamKsf);

/// Build Argon2id parameters, range-checked per CONTRACT §23.4 rule 4.
///
/// Returns `NULL` if any value is out of range.
#[unsafe(no_mangle)]
pub extern "C" fn axiam_opaque_ksf_argon2id(
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> *mut AxiamOpaqueKsf {
    guard(|| {
        let ksf =
            AxiamKsf::argon2id(memory_kib, iterations, parallelism).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(AxiamOpaqueKsf(ksf))))
    })
}

/// Build scrypt parameters, range-checked per CONTRACT §23.4 rule 4.
#[unsafe(no_mangle)]
pub extern "C" fn axiam_opaque_ksf_scrypt(log_n: u8, r: u32, p: u32) -> *mut AxiamOpaqueKsf {
    guard(|| {
        let ksf = AxiamKsf::scrypt(log_n, r, p).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(AxiamOpaqueKsf(ksf))))
    })
}

/// Release KSF parameters.
///
/// # Safety
/// `ptr` must be NULL or a handle from `axiam_opaque_ksf_*`, not already freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn axiam_opaque_ksf_free(ptr: *mut AxiamOpaqueKsf) {
    if !ptr.is_null() {
        drop(unsafe { Box::from_raw(ptr) });
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// An opaque handle to in-flight registration state.
pub struct AxiamOpaqueRegistration(ClientRegistrationState);

/// Begin an enrolment.
///
/// On success writes the hex `RegistrationRequest` to `*out_request` — which
/// the caller must release with [`axiam_opaque_string_free`] — and returns a
/// state handle to pass to [`axiam_opaque_registration_finish`].
///
/// # Safety
/// `password` must be a valid NUL-terminated UTF-8 string; `out_request` must
/// be a valid, writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn axiam_opaque_registration_start(
    password: *const c_char,
    out_request: *mut *mut c_char,
) -> *mut AxiamOpaqueRegistration {
    guard(|| {
        if out_request.is_null() {
            return Err("out_request must not be null".into());
        }
        let password = unsafe { read_str(password, "password") }?;
        let (state, request) =
            ClientRegistrationState::start(password).map_err(|e| e.to_string())?;
        unsafe { *out_request = to_c_string(&request)? };
        Ok(Box::into_raw(Box::new(AxiamOpaqueRegistration(state))))
    })
}

/// Complete an enrolment, **consuming** `state`.
///
/// Returns the hex `RegistrationRecord` to embed in the request body's `opaque`
/// object. `out_export_key` may be `NULL` if the caller does not want the
/// export key; when non-NULL it receives a string the caller must release.
///
/// `state` is consumed whether this succeeds or fails, so the caller must not
/// free it afterwards.
///
/// # Safety
/// `state` must be a handle from [`axiam_opaque_registration_start`] that has
/// not already been consumed or freed. `ksf` must be a live KSF handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn axiam_opaque_registration_finish(
    state: *mut AxiamOpaqueRegistration,
    password: *const c_char,
    registration_response: *const c_char,
    ksf: *const AxiamOpaqueKsf,
    out_export_key: *mut *mut c_char,
) -> *mut c_char {
    guard(|| {
        if state.is_null() {
            return Err("state must not be null".into());
        }
        if ksf.is_null() {
            return Err("ksf must not be null".into());
        }
        // Taken unconditionally: the state is single-use and must not survive a
        // failed finish, or a caller could retry with a different password and
        // reuse one blind across two exchanges.
        let state = unsafe { Box::from_raw(state) };
        let password = unsafe { read_str(password, "password") }?;
        let response = unsafe { read_str(registration_response, "registration_response") }?;
        let ksf = unsafe { &*ksf };

        let outcome = state
            .0
            .finish(password, response, &ksf.0)
            .map_err(|e| e.to_string())?;

        if !out_export_key.is_null() {
            unsafe { *out_export_key = to_c_string(&outcome.export_key)? };
        }
        to_c_string(&outcome.record)
    })
}

/// Release registration state that was never finished.
///
/// # Safety
/// `ptr` must be NULL or an unconsumed handle from
/// [`axiam_opaque_registration_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn axiam_opaque_registration_free(ptr: *mut AxiamOpaqueRegistration) {
    if !ptr.is_null() {
        drop(unsafe { Box::from_raw(ptr) });
    }
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

/// An opaque handle to in-flight login state.
pub struct AxiamOpaqueLogin(ClientLoginState);

/// Begin a login. Writes the hex `KE1` to `*out_ke1`.
///
/// # Safety
/// As [`axiam_opaque_registration_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn axiam_opaque_login_start(
    password: *const c_char,
    out_ke1: *mut *mut c_char,
) -> *mut AxiamOpaqueLogin {
    guard(|| {
        if out_ke1.is_null() {
            return Err("out_ke1 must not be null".into());
        }
        let password = unsafe { read_str(password, "password") }?;
        let (state, ke1) = ClientLoginState::start(password).map_err(|e| e.to_string())?;
        unsafe { *out_ke1 = to_c_string(&ke1)? };
        Ok(Box::into_raw(Box::new(AxiamOpaqueLogin(state))))
    })
}

/// Complete a login, **consuming** `state`. Returns the hex `KE3`.
///
/// A `NULL` return is the whole of the client's authentication check, and it
/// covers both halves of the mutual authentication: the envelope only opens
/// under the right password, and `KE2`'s MAC only verifies if the server
/// actually holds the record. Per CONTRACT §23.4 rule 7 the caller MUST NOT
/// send anything to `login/finish` after a `NULL` here.
///
/// `out_session_key` and `out_export_key` may be `NULL`; when non-NULL they
/// receive strings the caller must release.
///
/// # Safety
/// As [`axiam_opaque_registration_finish`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn axiam_opaque_login_finish(
    state: *mut AxiamOpaqueLogin,
    password: *const c_char,
    ke2: *const c_char,
    ksf: *const AxiamOpaqueKsf,
    out_session_key: *mut *mut c_char,
    out_export_key: *mut *mut c_char,
) -> *mut c_char {
    guard(|| {
        if state.is_null() {
            return Err("state must not be null".into());
        }
        if ksf.is_null() {
            return Err("ksf must not be null".into());
        }
        let state = unsafe { Box::from_raw(state) };
        let password = unsafe { read_str(password, "password") }?;
        let ke2 = unsafe { read_str(ke2, "ke2") }?;
        let ksf = unsafe { &*ksf };

        let outcome = state
            .0
            .finish(password, ke2, &ksf.0)
            .map_err(|e| e.to_string())?;

        if !out_session_key.is_null() {
            unsafe { *out_session_key = to_c_string(&outcome.session_key)? };
        }
        if !out_export_key.is_null() {
            unsafe { *out_export_key = to_c_string(&outcome.export_key)? };
        }
        to_c_string(&outcome.ke3)
    })
}

/// Release login state that was never finished.
///
/// # Safety
/// `ptr` must be NULL or an unconsumed handle from
/// [`axiam_opaque_login_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn axiam_opaque_login_free(ptr: *mut AxiamOpaqueLogin) {
    if !ptr.is_null() {
        drop(unsafe { Box::from_raw(ptr) });
    }
}
