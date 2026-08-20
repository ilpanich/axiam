//! WebAssembly build of AXIAM's OPAQUE (RFC 9807) client.
//!
//! Bound by the TypeScript SDK and the React admin UI. See `sdks/CONTRACT.md`
//! §23.1 for why neither implements OPAQUE itself.
//!
//! # Shape of the interface
//!
//! Hex strings in, hex strings out — the same narrowing the C ABI makes, and
//! the same one AXIAM's wire format uses. A `string` API needs no shared memory
//! views and no manual frees, so a TypeScript caller never touches the WASM
//! heap.
//!
//! State is held in JavaScript objects (`OpaqueRegistration`, `OpaqueLogin`)
//! whose `finish` methods **consume** them: `wasm_bindgen` moves the Rust value
//! out, so calling `finish` twice throws rather than reusing one OPRF blind
//! across two exchanges.
//!
//! # Errors
//!
//! Every failure is a thrown `Error` with a coarse message. A caller that could
//! distinguish "the server sent a malformed KE2" from "your password is wrong"
//! would be reporting a fact it cannot establish — a wrong password and a
//! hostile server both surface as an envelope that will not open.

use wasm_bindgen::prelude::*;

use axiam_opaque::{AxiamKsf, ClientLoginState, ClientRegistrationState};

/// Install the panic hook so a Rust panic surfaces as a stack trace in the
/// browser console rather than `unreachable executed`.
///
/// Idempotent; a caller may invoke it once at module init.
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// Non-zero when this build can perform OPAQUE.
///
/// Always `true` — if the module instantiated, it works. It exists so a
/// TypeScript `opaqueAvailable()` (CONTRACT §23.2) has something to call after
/// a successful `init()`, and so a build whose WASM failed to load can answer
/// the same question with `false` without a special case.
#[wasm_bindgen(js_name = opaqueAvailable)]
pub fn opaque_available() -> bool {
    true
}

/// Key-stretching parameters, as named by the server.
///
/// A caller MUST build this from the `ksf` fields of a `register/start` or
/// `login/start` response rather than from its own configuration: a credential
/// enrolled under one cost keeps working after a tenant raises its policy, so a
/// client that guessed would derive a different randomized password and fail
/// against a record that is perfectly good.
#[wasm_bindgen]
pub struct OpaqueKsf {
    inner: AxiamKsf,
}

#[wasm_bindgen]
impl OpaqueKsf {
    /// Argon2id parameters, range-checked per CONTRACT §23.4 rule 4.
    #[wasm_bindgen(js_name = argon2id)]
    pub fn argon2id(
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<OpaqueKsf, JsError> {
        Ok(OpaqueKsf {
            inner: AxiamKsf::argon2id(memory_kib, iterations, parallelism)
                .map_err(|e| JsError::new(&e.to_string()))?,
        })
    }

    /// scrypt parameters, range-checked per CONTRACT §23.4 rule 4.
    #[wasm_bindgen(js_name = scrypt)]
    pub fn scrypt(log_n: u8, r: u32, p: u32) -> Result<OpaqueKsf, JsError> {
        Ok(OpaqueKsf {
            inner: AxiamKsf::scrypt(log_n, r, p).map_err(|e| JsError::new(&e.to_string()))?,
        })
    }
}

/// The result of a completed enrolment.
#[wasm_bindgen]
pub struct OpaqueRegistrationResult {
    record: String,
    export_key: String,
}

#[wasm_bindgen]
impl OpaqueRegistrationResult {
    /// Hex `RegistrationRecord`, to embed in the request body's `opaque` object.
    #[wasm_bindgen(getter)]
    pub fn record(&self) -> String {
        self.record.clone()
    }

    /// Hex `export_key`. AXIAM does not use it and no endpoint accepts it; it
    /// is surfaced because it cannot be re-derived later without the password.
    #[wasm_bindgen(getter, js_name = exportKey)]
    pub fn export_key(&self) -> String {
        self.export_key.clone()
    }
}

/// In-flight registration state.
#[wasm_bindgen]
pub struct OpaqueRegistration {
    inner: ClientRegistrationState,
    request: String,
}

#[wasm_bindgen]
impl OpaqueRegistration {
    /// Blind the password. The `request` getter carries the hex
    /// `RegistrationRequest` to post to `/auth/opaque/register/start`.
    #[wasm_bindgen(constructor)]
    pub fn new(password: &str) -> Result<OpaqueRegistration, JsError> {
        let (inner, request) =
            ClientRegistrationState::start(password).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(OpaqueRegistration { inner, request })
    }

    /// Hex `RegistrationRequest`.
    #[wasm_bindgen(getter)]
    pub fn request(&self) -> String {
        self.request.clone()
    }

    /// Unblind, stretch and seal the envelope. **Consumes** this object.
    pub fn finish(
        self,
        password: &str,
        registration_response: &str,
        ksf: &OpaqueKsf,
    ) -> Result<OpaqueRegistrationResult, JsError> {
        let outcome = self
            .inner
            .finish(password, registration_response, &ksf.inner)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(OpaqueRegistrationResult {
            record: outcome.record,
            export_key: outcome.export_key,
        })
    }
}

/// The result of a completed login.
#[wasm_bindgen]
pub struct OpaqueLoginResult {
    ke3: String,
    session_key: String,
    export_key: String,
}

#[wasm_bindgen]
impl OpaqueLoginResult {
    /// Hex `KE3`, to post to `/auth/opaque/login/finish`.
    #[wasm_bindgen(getter)]
    pub fn ke3(&self) -> String {
        self.ke3.clone()
    }

    /// Hex mutually authenticated session key. AXIAM issues ordinary session
    /// cookies rather than binding anything to this.
    #[wasm_bindgen(getter, js_name = sessionKey)]
    pub fn session_key(&self) -> String {
        self.session_key.clone()
    }

    /// Hex `export_key`, identical to the enrolment's for the same password.
    #[wasm_bindgen(getter, js_name = exportKey)]
    pub fn export_key(&self) -> String {
        self.export_key.clone()
    }
}

/// In-flight login state.
#[wasm_bindgen]
pub struct OpaqueLogin {
    inner: ClientLoginState,
    ke1: String,
}

#[wasm_bindgen]
impl OpaqueLogin {
    /// Blind the password and generate the client's ephemeral share.
    #[wasm_bindgen(constructor)]
    pub fn new(password: &str) -> Result<OpaqueLogin, JsError> {
        let (inner, ke1) =
            ClientLoginState::start(password).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(OpaqueLogin { inner, ke1 })
    }

    /// Hex `KE1`, to post to `/auth/opaque/login/start`.
    #[wasm_bindgen(getter)]
    pub fn ke1(&self) -> String {
        self.ke1.clone()
    }

    /// Open the envelope and produce `KE3`. **Consumes** this object.
    ///
    /// A thrown error here is the *whole* of the client's authentication check,
    /// and it covers both halves of the mutual authentication: the envelope
    /// only opens under the right password, and `KE2`'s MAC only verifies if
    /// the server actually holds the record. Per CONTRACT §23.4 rule 7 the
    /// caller MUST NOT post anything to `login/finish` after it throws.
    pub fn finish(
        self,
        password: &str,
        ke2: &str,
        ksf: &OpaqueKsf,
    ) -> Result<OpaqueLoginResult, JsError> {
        let outcome = self
            .inner
            .finish(password, ke2, &ksf.inner)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(OpaqueLoginResult {
            ke3: outcome.ke3,
            session_key: outcome.session_key,
            export_key: outcome.export_key,
        })
    }
}
