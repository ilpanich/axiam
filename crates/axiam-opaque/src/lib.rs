//! AXIAM's OPAQUE (RFC 9807) ciphersuite, key-stretching functions and client
//! operations.
//!
//! # Why this crate exists
//!
//! AXIAM speaks OPAQUE from twelve places: the server, the React admin UI, and
//! eleven client SDKs. Every one of them must agree on every byte, and OPAQUE
//! is not the kind of protocol that can be hand-written twelve times and be
//! expected to agree — it needs an oblivious PRF, `hash_to_curve`,
//! `expand_message_xmd`, an envelope construction and a three-message AKE.
//!
//! The SRP implementation this replaces *was* hand-written eleven times,
//! because SRP is modular arithmetic and every language has a bignum. That
//! produced a bundled Montgomery modular exponentiation in the Swift SDK, a
//! PHP SDK that reported itself unavailable without `ext-gmp`, and a
//! cross-language conformance fixture that existed to catch the drift. None of
//! that is a criticism of the implementations; it is what shipping eleven
//! independent implementations of an authentication primitive costs.
//!
//! So this crate is the *only* implementation. It is compiled directly into
//! the Rust SDK and the server, to WebAssembly for the TypeScript SDK and the
//! admin UI, and behind a C ABI for the rest. That is also why it sits at
//! layer 0 with no internal dependencies: anything it depended on would become
//! a dependency of every SDK.
//!
//! # What is here, and what is not
//!
//! Here: the ciphersuite, the key-stretching functions, and the four
//! **client**-side operations. The client half is what needs to exist in every
//! language.
//!
//! Not here: the server half — key material, sealed sessions, credential
//! identifiers, lockout attribution. That lives in `axiam-auth` and has no
//! business being compiled into a client. The one thing the server borrows
//! from this crate is [`AxiamOpaqueSuite`], so that there is exactly one
//! definition of the suite and the two halves cannot drift.
//!
//! # Wire encoding
//!
//! Every protocol message crosses the AXIAM API as lowercase hex, so this
//! crate's public surface is hex in and hex out. That is a deliberate
//! narrowing: a `&str` API is expressible in every SDK language and across a C
//! ABI without anyone inventing a byte-buffer convention, and hex has no
//! variant spellings to disagree about the way base64 does.
//!
//! # Example
//!
//! ```
//! use axiam_opaque::{AxiamKsf, ClientLoginState, ClientRegistrationState};
//!
//! // --- registration ---
//! let ksf = AxiamKsf::argon2id(19456, 2, 1).unwrap();
//! let (state, request) = ClientRegistrationState::start("hunter2").unwrap();
//! // ... server evaluates the OPRF and returns `registration_response` ...
//! # let (setup, response) = axiam_opaque::testing::server_registration_start(&request);
//! # let registration_response = response;
//! let record = state.finish("hunter2", &registration_response, &ksf).unwrap();
//!
//! // --- login ---
//! let (state, ke1) = ClientLoginState::start("hunter2").unwrap();
//! # let ke2 = axiam_opaque::testing::server_login_start(&setup, &record.record, &ke1);
//! // ... server returns `ke2` ...
//! let finished = state.finish("hunter2", &ke2, &ksf).unwrap();
//! assert_eq!(finished.ke3.len(), 128); // 64 bytes, hex
//! ```

use opaque_ke::generic_array::{ArrayLength, GenericArray};
use opaque_ke::ksf::Ksf;
// `rand 0.8` explicitly rather than through `opaque_ke::rand`: the re-export
// only carries `OsRng` when a feature somewhere else in the tree happens to
// enable it, and a cryptographic RNG that appears or disappears by feature
// unification is not something an authentication crate should rely on.
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use rand08::rngs::OsRng;

/// The `sha2` generation `opaque-ke` 4.0.1 is built against (`digest 0.10`),
/// aliased so a workspace bump to `digest 0.11` cannot silently retype the
/// ciphersuite out from under the wire format.
use sha2_v10 as opaque_sha2;

/// AXIAM's OPAQUE ciphersuite: `OPAQUE-3DH` over ristretto255 with SHA-512,
/// HKDF-SHA-512 and HMAC-SHA-512 — the RFC 9807 recommended configuration.
///
/// One suite ships today. RFC 9807 also defines a P-256/SHA-256 profile, which
/// is the slot a FIPS deployment would want; it is not shipped because every
/// additional suite multiplies the cross-language conformance surface, which is
/// the hardest part of this to keep correct.
pub struct AxiamOpaqueSuite;

impl CipherSuite for AxiamOpaqueSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, opaque_sha2::Sha512>;
    type Ksf = AxiamKsf;
}

/// Anything that can go wrong on the client side.
///
/// Deliberately coarse. A client that could distinguish "the server sent a
/// malformed KE2" from "your password is wrong" would be reporting a fact it
/// cannot actually establish — a wrong password and a hostile server both
/// surface as an envelope that will not open.
#[derive(Debug, thiserror::Error)]
pub enum OpaqueError {
    /// A hex input was not valid hex, or was not a valid protocol message.
    #[error("malformed OPAQUE message: {0}")]
    Malformed(&'static str),
    /// The exchange failed. For a login this means the password is wrong, the
    /// account has no record, or the server is not the one that holds it.
    #[error("OPAQUE exchange failed")]
    Failed,
    /// KSF parameters outside the accepted band.
    #[error("invalid KSF parameters: {0}")]
    InvalidKsf(&'static str),
}

// ---------------------------------------------------------------------------
// Key-stretching
// ---------------------------------------------------------------------------

/// A key-stretching function carrying its own cost parameters (RFC 9807 §3.1,
/// `Stretch`).
///
/// Parameters live *in the value* rather than in the type because a credential
/// enrolled under one cost must keep working after a tenant raises its policy.
/// The server stores the parameters a record was created with and echoes them
/// at login; a client that stretched with anything else derives a different
/// randomized password and cannot open its own envelope.
///
/// Both variants are memory-hard. The SRP scheme this replaces offered
/// PBKDF2-HMAC-SHA256 as a fallback, purely because three SDK languages had no
/// usable Argon2id — a constraint that a single shared implementation removes,
/// so there is no longer a reason to offer a KSF that a GPU farm enjoys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AxiamKsf {
    /// Argon2id.
    Argon2id {
        /// Memory cost in KiB.
        memory_kib: u32,
        /// Time cost (number of passes).
        iterations: u32,
        /// Degree of parallelism.
        parallelism: u32,
    },
    /// scrypt.
    Scrypt {
        /// CPU/memory cost, as log2(N).
        log_n: u8,
        /// Block size.
        r: u32,
        /// Parallelism.
        p: u32,
    },
}

impl AxiamKsf {
    /// Argon2id with the given costs, range-checked.
    ///
    /// The bounds match `axiam_core::models::opaque::OpaqueKsfParams::validate`.
    /// They are repeated here rather than shared because this crate is layer 0
    /// and is compiled into every SDK: a client must be able to reject absurd
    /// parameters handed to it by a server without linking the domain model.
    pub fn argon2id(
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<Self, OpaqueError> {
        if !(8192..=1_048_576).contains(&memory_kib) {
            return Err(OpaqueError::InvalidKsf("argon2id memory_kib out of range"));
        }
        if !(1..=10).contains(&iterations) {
            return Err(OpaqueError::InvalidKsf("argon2id iterations out of range"));
        }
        if !(1..=16).contains(&parallelism) {
            return Err(OpaqueError::InvalidKsf("argon2id parallelism out of range"));
        }
        Ok(Self::Argon2id {
            memory_kib,
            iterations,
            parallelism,
        })
    }

    /// scrypt with the given costs, range-checked.
    pub fn scrypt(log_n: u8, r: u32, p: u32) -> Result<Self, OpaqueError> {
        if !(14..=20).contains(&log_n) {
            return Err(OpaqueError::InvalidKsf("scrypt log_n out of range"));
        }
        if !(1..=16).contains(&r) {
            return Err(OpaqueError::InvalidKsf("scrypt r out of range"));
        }
        if !(1..=16).contains(&p) {
            return Err(OpaqueError::InvalidKsf("scrypt p out of range"));
        }
        Ok(Self::Scrypt { log_n, r, p })
    }
}

impl Default for AxiamKsf {
    /// The OWASP-aligned Argon2id defaults, matching AXIAM's server-side
    /// password hashing cost.
    ///
    /// `Default` exists only because `opaque_ke::ksf::Ksf` requires it. Nothing
    /// in AXIAM constructs a KSF this way — the parameters always come from the
    /// server, per credential — and a client that silently fell back to a
    /// default would derive a randomized password no record agrees with.
    fn default() -> Self {
        Self::Argon2id {
            memory_kib: 19456,
            iterations: 2,
            parallelism: 1,
        }
    }
}

impl Ksf for AxiamKsf {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, opaque_ke::errors::InternalError> {
        let mut output = GenericArray::default();
        match *self {
            Self::Argon2id {
                memory_kib,
                iterations,
                parallelism,
            } => {
                let params = argon2::Params::new(memory_kib, iterations, parallelism, None)
                    .map_err(|_| opaque_ke::errors::InternalError::KsfError)?;
                let argon2 = argon2::Argon2::new(
                    argon2::Algorithm::Argon2id,
                    argon2::Version::V0x13,
                    params,
                );
                // RFC 9807 stretches a value that is already the output of an
                // OPRF over the password, so it carries full entropy from the
                // KSF's point of view and there is nothing for a salt to
                // separate. A fixed all-zero salt is what the reference
                // implementation uses; anything per-client here would be a
                // value both sides would have to agree on for no benefit.
                argon2
                    .hash_password_into(&input, &[0u8; argon2::RECOMMENDED_SALT_LEN], &mut output)
                    .map_err(|_| opaque_ke::errors::InternalError::KsfError)?;
            }
            Self::Scrypt { log_n, r, p } => {
                let params = scrypt::Params::new(log_n, r, p, output.len())
                    .map_err(|_| opaque_ke::errors::InternalError::KsfError)?;
                scrypt::scrypt(&input, &[0u8; 32], &params, &mut output)
                    .map_err(|_| opaque_ke::errors::InternalError::KsfError)?;
            }
        }
        Ok(output)
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// A finished registration, ready to post to the server.
#[derive(Debug, Clone)]
pub struct RegistrationOutcome {
    /// Lowercase-hex serialized RFC 9807 `RegistrationRecord`.
    pub record: String,
    /// The client's `export_key`, lowercase hex.
    ///
    /// RFC 9807 yields this as a by-product: a 64-byte key derived from the
    /// password that the server never learns and cannot derive. AXIAM does not
    /// use it, and no AXIAM endpoint accepts it. It is surfaced because
    /// discarding it silently would remove an application's ability to build
    /// end-to-end encryption on top of a login it already performs, and
    /// re-deriving it later is impossible without the password.
    pub export_key: String,
}

/// Client state between the two messages of a registration.
///
/// Not `Clone`, and consumed by [`Self::finish`]: the OPRF blind inside it is
/// good for exactly one exchange.
pub struct ClientRegistrationState {
    inner: ClientRegistration<AxiamOpaqueSuite>,
}

impl ClientRegistrationState {
    /// Blind the password. Returns the state and the lowercase-hex
    /// `RegistrationRequest` to send to `/auth/opaque/register/start`.
    pub fn start(password: &str) -> Result<(Self, String), OpaqueError> {
        let mut rng = OsRng;
        let started = ClientRegistration::<AxiamOpaqueSuite>::start(&mut rng, password.as_bytes())
            .map_err(|_| OpaqueError::Failed)?;
        Ok((
            Self {
                inner: started.state,
            },
            hex::encode(started.message.serialize()),
        ))
    }

    /// Unblind the server's evaluation, stretch it, and seal the envelope.
    ///
    /// `password` must be the same string passed to [`Self::start`], and `ksf`
    /// must carry the parameters the server named in its response.
    pub fn finish(
        self,
        password: &str,
        registration_response_hex: &str,
        ksf: &AxiamKsf,
    ) -> Result<RegistrationOutcome, OpaqueError> {
        let bytes = hex::decode(registration_response_hex)
            .map_err(|_| OpaqueError::Malformed("registration_response is not hex"))?;
        let response = RegistrationResponse::<AxiamOpaqueSuite>::deserialize(&bytes)
            .map_err(|_| OpaqueError::Malformed("registration_response"))?;

        let mut rng = OsRng;
        let finished = self
            .inner
            .finish(
                &mut rng,
                password.as_bytes(),
                response,
                ClientRegistrationFinishParameters::new(Default::default(), Some(ksf)),
            )
            .map_err(|_| OpaqueError::Failed)?;

        Ok(RegistrationOutcome {
            record: hex::encode(finished.message.serialize()),
            export_key: hex::encode(finished.export_key),
        })
    }
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

/// A finished login, ready to post to the server.
#[derive(Debug, Clone)]
pub struct LoginOutcome {
    /// Lowercase-hex serialized RFC 9807 `KE3`.
    pub ke3: String,
    /// The mutually authenticated session key, lowercase hex.
    ///
    /// Both sides derive it; neither transmits it. AXIAM issues ordinary
    /// session cookies rather than binding anything to this, so no SDK is
    /// required to do anything with it. Surfaced for the same reason as
    /// [`RegistrationOutcome::export_key`].
    pub session_key: String,
    /// The client's `export_key`, lowercase hex. Identical to the value
    /// produced at registration for the same password.
    pub export_key: String,
}

/// Client state between the two messages of a login.
pub struct ClientLoginState {
    inner: ClientLogin<AxiamOpaqueSuite>,
}

impl ClientLoginState {
    /// Blind the password and generate the client's ephemeral share. Returns
    /// the state and the lowercase-hex `KE1` to send to
    /// `/auth/opaque/login/start`.
    pub fn start(password: &str) -> Result<(Self, String), OpaqueError> {
        let mut rng = OsRng;
        let started = ClientLogin::<AxiamOpaqueSuite>::start(&mut rng, password.as_bytes())
            .map_err(|_| OpaqueError::Failed)?;
        Ok((
            Self {
                inner: started.state,
            },
            hex::encode(started.message.serialize()),
        ))
    }

    /// Open the envelope and produce `KE3`.
    ///
    /// An `Err` here is the *whole* of the client's authentication check, and
    /// it covers both halves of the mutual authentication: the envelope only
    /// opens under the right password, and `KE2`'s MAC only verifies if the
    /// server actually holds the record. That is why the AXIAM login response
    /// carries no server proof for the client to check afterwards — under SRP
    /// it had to, and an SDK that forgot silently kept only half the protocol.
    pub fn finish(
        self,
        password: &str,
        ke2_hex: &str,
        ksf: &AxiamKsf,
    ) -> Result<LoginOutcome, OpaqueError> {
        let bytes = hex::decode(ke2_hex).map_err(|_| OpaqueError::Malformed("ke2 is not hex"))?;
        let ke2 = CredentialResponse::<AxiamOpaqueSuite>::deserialize(&bytes)
            .map_err(|_| OpaqueError::Malformed("ke2"))?;

        let mut rng = OsRng;
        let finished = self
            .inner
            .finish(
                &mut rng,
                password.as_bytes(),
                ke2,
                ClientLoginFinishParameters::new(None, Default::default(), Some(ksf)),
            )
            .map_err(|_| OpaqueError::Failed)?;

        Ok(LoginOutcome {
            ke3: hex::encode(finished.message.serialize()),
            session_key: hex::encode(finished.session_key),
            export_key: hex::encode(finished.export_key),
        })
    }
}

// ---------------------------------------------------------------------------
// Testing support
// ---------------------------------------------------------------------------

/// Minimal server-side operations, for doctests and for `axiam-auth`'s and the
/// SDKs' conformance fixtures.
///
/// **Not the AXIAM server implementation.** That lives in `axiam-auth` and adds
/// everything that actually matters operationally: per-tenant key material
/// encrypted at rest, sealed sessions, credential identifiers, decoy exchanges
/// for identities that do not exist, and lockout attribution. What is here is
/// the bare protocol, so that a test can complete an exchange without standing
/// up a server.
pub mod testing {
    use super::*;
    use opaque_ke::{
        CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin,
        ServerLoginParameters, ServerRegistration, ServerSetup,
    };

    /// A throwaway server setup, hex-encoded.
    pub type SetupHex = String;

    /// Evaluate the OPRF over a client's blinded password.
    ///
    /// Returns `(setup, registration_response)`, both lowercase hex.
    pub fn server_registration_start(request_hex: &str) -> (SetupHex, String) {
        let mut rng = OsRng;
        let setup = ServerSetup::<AxiamOpaqueSuite>::new(&mut rng);
        let request = RegistrationRequest::<AxiamOpaqueSuite>::deserialize(
            &hex::decode(request_hex).unwrap(),
        )
        .unwrap();
        let started =
            ServerRegistration::<AxiamOpaqueSuite>::start(&setup, request, b"test-credential")
                .unwrap();
        (
            hex::encode(setup.serialize()),
            hex::encode(started.message.serialize()),
        )
    }

    /// Produce a `KE2` for a stored record. Returns lowercase hex.
    pub fn server_login_start(setup_hex: &str, record_hex: &str, ke1_hex: &str) -> String {
        let mut rng = OsRng;
        let setup =
            ServerSetup::<AxiamOpaqueSuite>::deserialize(&hex::decode(setup_hex).unwrap()).unwrap();
        let record = ServerRegistration::<AxiamOpaqueSuite>::finish(
            RegistrationUpload::deserialize(&hex::decode(record_hex).unwrap()).unwrap(),
        );
        let ke1 =
            CredentialRequest::<AxiamOpaqueSuite>::deserialize(&hex::decode(ke1_hex).unwrap())
                .unwrap();
        let started = ServerLogin::<AxiamOpaqueSuite>::start(
            &mut rng,
            &setup,
            Some(record),
            ke1,
            b"test-credential",
            ServerLoginParameters::default(),
        )
        .unwrap();
        hex::encode(started.message.serialize())
    }
}
