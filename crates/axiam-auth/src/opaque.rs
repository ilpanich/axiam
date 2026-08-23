//! OPAQUE (RFC 9807) — server side.
//!
//! The domain types, the enforcement modes, and the rationale for adopting
//! OPAQUE at all live in [`axiam_core::models::opaque`]. This module is the
//! protocol engine behind the four endpoints:
//!
//! - `POST /api/v1/auth/opaque/register/start`
//! - `POST /api/v1/auth/opaque/register/finish`
//! - `POST /api/v1/auth/opaque/login/start`
//! - `POST /api/v1/auth/opaque/login/finish`
//!
//! # The exchanges
//!
//! ```text
//!   REGISTRATION                                     server
//!     |  RegistrationRequest (blinded password)         |
//!     | ----------------------------------------------> |  evaluate OPRF
//!     |  RegistrationResponse, ksf params, session      |
//!     | <---------------------------------------------- |
//!     |   stretch, seal an envelope under the OPRF output
//!     |  RegistrationRecord, session                    |
//!     | ----------------------------------------------> |  store verbatim
//!
//!   LOGIN                                            server
//!     |  KE1 (blinded password + client ephemeral)      |
//!     | ----------------------------------------------> |  evaluate OPRF,
//!     |                                                  |  mask the envelope
//!     |  KE2, ksf params, session                       |
//!     | <---------------------------------------------- |
//!     |   stretch, open the envelope, derive the AKE keys
//!     |  KE3 (client MAC), session                      |
//!     | ----------------------------------------------> |  verify the MAC
//!     |  the ordinary login result                      |
//!     | <---------------------------------------------- |
//! ```
//!
//! # Why this module is thin
//!
//! Every byte of the protocol is [`opaque_ke`], which implements RFC 9807 and
//! has been independently audited. This module supplies four things the crate
//! deliberately leaves to the application, and nothing else:
//!
//! 1. **Where the server's key material lives** — per tenant, encrypted at
//!    rest (see [`OpaqueServer::create_server_setup`]).
//! 2. **How state survives between the two messages** — sealed into a token
//!    rather than a table.
//! 3. **What a credential identifier is** — random per credential, so a
//!    rename cannot invalidate a record.
//! 4. **How a failure is attributed** — so a wrong password still counts
//!    toward lockout.
//!
//! Resisting the temptation to "improve" anything inside the protocol is the
//! point. AXIAM's SRP implementation carried two deliberate divergences from
//! RFC 5054 because that RFC was not good enough to adopt as written; RFC 9807
//! is, and a divergence here would be a defect.
//!
//! # Why the server state is sealed into a token rather than stored
//!
//! Between the two messages of each exchange the server has to remember what
//! it derived. The obvious approach is a session table with a TTL; this module
//! instead seals the state into an AES-256-GCM token the client carries back,
//! exactly as [`crate::service::AuthService`] already does for the MFA
//! challenge, and as the SRP implementation this replaces did. Three reasons:
//!
//! 1. **It works across replicas with no coordination.** A DB-backed session
//!    would add a write and a read to every login on the hot path, in a system
//!    whose whole point is horizontal scaling.
//! 2. **There is nothing to garbage-collect.** Expiry is a field inside the
//!    sealed blob, checked on open; an abandoned exchange costs nothing.
//! 3. **A replayed token grants no new power.** Opening it requires the server
//!    key, and *using* it still requires a valid `KE3`, which still requires
//!    the password. An attacker who can replay a captured pair has, by
//!    construction, already broken TLS — at which point they have the session
//!    cookie the exchange would have produced anyway. The 120-second lifetime
//!    bounds even that.
//!
//! A registration session and a login session are sealed under the same key
//! but carry distinct `kind` tags that are checked on open, so a token minted
//! by one exchange cannot be presented to the other.
//!
//! # Account enumeration
//!
//! An unknown identity must produce a response indistinguishable from a known
//! one, or `/auth/opaque/login/start` becomes a faster user-enumeration oracle
//! than anything else in the API.
//!
//! Under SRP this needed hand-built machinery: a fabricated but *stable* salt
//! derived by HMAC, plus a dummy verifier chosen so the modular exponentiation
//! cost matched. RFC 9807 designs the case in, and `opaque_ke` implements it:
//! passing `password_file: None` to `ServerLogin::start` produces a `KE2` of
//! identical shape from the setup's dummy public key. What this module adds is
//! the *stability* half — a decoy credential identifier derived as
//! `HMAC(decoy_key, tenant_id || identity)` so that probing the same
//! non-existent name twice yields the same answer, where a random identifier
//! would announce non-existence as loudly as a `404`.
//!
//! One residual is worth stating rather than hiding: the KSF parameters
//! returned for a decoy are the tenant's *current* policy, while a real user
//! carries whatever they enrolled under. An attacker who knows a tenant
//! changed its KSF cost, and who can find a user still on the old cost, learns
//! that that account exists. The window closes as users rotate passwords, it
//! requires knowledge of the tenant's policy history, and it is the same
//! residual the SRP design carried for the same reason.
//!
//! # What is never logged
//!
//! No value in this module — sealed sessions, KE messages, registration
//! records, the server setup, session keys — may appear in a log record at any
//! level. [`OpaqueServer`] and [`OpaqueServerKeys`] have hand-written `Debug`
//! impls that render nothing for exactly this reason.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};

use axiam_core::models::opaque::{
    OpaqueCredential, OpaqueKsfParams, OpaqueLoginStartResponse, OpaqueMode,
    OpaqueRegisterStartResponse, OpaqueServerSetup, OpaqueSuite, ksf_wire_fields, normalize_hex,
};

use crate::crypto::{aes256gcm_decrypt, aes256gcm_encrypt};
use crate::error::AuthError;

type HmacSha256 = Hmac<Sha256>;

/// How long an `opaque_session` stays openable. Long enough for a client to
/// run Argon2id on a slow phone, short enough that an abandoned exchange is
/// not a standing replay target.
const SESSION_LIFETIME_SECS: i64 = 120;

/// Sealed-blob format version, so the layout can change without a flag day.
const SEALED_VERSION: u8 = 1;

/// Domain-separation tag for a registration session.
const KIND_REGISTER: &str = "register";
/// Domain-separation tag for a login session.
const KIND_LOGIN: &str = "login";

// ---------------------------------------------------------------------------
// Ciphersuite
// ---------------------------------------------------------------------------

/// AXIAM's OPAQUE ciphersuite, re-exported under the name this module uses
/// throughout.
///
/// Defined in [`axiam_opaque`] rather than here, deliberately. That crate is
/// compiled into the eleven client SDKs and the admin UI as well as into this
/// server, and a suite defined twice is a suite that can drift — silently, and
/// across a language boundary where nothing would catch it until a login
/// stopped working in one SDK and not the others.
///
/// The KSF associated type is the real Argon2id/scrypt implementation for the
/// same reason, even though **this half of the protocol never evaluates it**:
/// RFC 9807 stretches client-side, and none of the server entry points
/// (`ServerRegistration::start`, `ServerLogin::start`, `ServerLogin::finish`)
/// take a KSF. Naming the real one here costs nothing and keeps the two halves
/// provably the same type.
type Ristretto255Sha512 = axiam_opaque::AxiamOpaqueSuite;

// ---------------------------------------------------------------------------
// Sealed session state
// ---------------------------------------------------------------------------

/// What the server carries between the two messages of a *registration*,
/// sealed under AES-256-GCM. Never readable or forgeable by the client.
///
/// Note what is absent: any user identifier. Registration is used while
/// creating a user who does not exist yet (`POST /api/v1/users`, and
/// bootstrap), so this exchange knows only the tenant and the credential
/// identifier it minted. Binding the record to an account is the caller's job,
/// from its own authenticated context — a client that could name the account
/// could enrol a record against somebody else's.
#[derive(Debug, Serialize, Deserialize)]
struct SealedRegistration {
    v: u8,
    kind: String,
    tenant_id: Uuid,
    /// Hex 32-byte credential identifier minted for this enrolment.
    credential_identifier: String,
    suite: OpaqueSuite,
    ksf_params: OpaqueKsfParams,
    expires_at: DateTime<Utc>,
}

/// What the server carries between `login/start` and `login/finish`, sealed
/// under AES-256-GCM.
#[derive(Debug, Serialize, Deserialize)]
struct SealedLogin {
    v: u8,
    kind: String,
    tenant_id: Uuid,
    org_id: Uuid,
    /// `None` for a decoy exchange against an identity that does not exist.
    user_id: Option<Uuid>,
    /// Hex serialized `ServerLogin` KE2 state.
    ke2_state: String,
    expires_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

/// A validated registration, ready for the caller to bind to a user.
#[derive(Debug, Clone)]
pub struct OpaqueEnrolled {
    /// Tenant the enrolment was scoped to.
    pub tenant_id: Uuid,
    /// Hex 32-byte credential identifier the server minted.
    pub credential_identifier: String,
    /// Ciphersuite the record was created under.
    pub suite: OpaqueSuite,
    /// KSF parameters the client stretched with.
    pub ksf_params: OpaqueKsfParams,
    /// Hex serialized `RegistrationRecord`, validated for shape.
    pub record: String,
}

/// Why an OPAQUE login was refused.
///
/// The split exists for exactly one reason: a failed `KE3` is a wrong password
/// and MUST accrue toward account lockout, and accruing it needs to know
/// *whose* account. Collapsing both cases into one opaque error — the obvious
/// shape — would mean that turning OPAQUE on silently removed brute-force
/// protection from every account that adopted it. An attacker could then grind
/// passwords against `/auth/opaque/login/finish` without ever tripping a
/// lockout that the password endpoint would have tripped in five attempts.
///
/// The distinction never reaches the HTTP response; both map to one `401`.
#[derive(Debug, Clone)]
pub enum OpaqueRejection {
    /// The session blob could not be opened, was tampered with, carried the
    /// wrong kind or version, or has expired. There is no identity to
    /// attribute this to.
    Unusable,
    /// The session opened and the client's MAC did not verify — one failed
    /// password attempt by whoever this is.
    BadCredentials {
        /// Tenant the exchange was scoped to.
        tenant_id: Uuid,
        /// The account, when the exchange was a real one. `None` for a decoy
        /// exchange against an identity that does not exist, where there is
        /// nothing to lock out.
        user_id: Option<Uuid>,
    },
}

/// Outcome of a successful `login/finish`.
#[derive(Debug, Clone)]
pub struct OpaqueVerified {
    /// Tenant the exchange was scoped to.
    pub tenant_id: Uuid,
    /// Organization the exchange was scoped to.
    pub org_id: Uuid,
    /// The authenticated user.
    pub user_id: Uuid,
}

// ---------------------------------------------------------------------------
// Server keys
// ---------------------------------------------------------------------------

/// The two keys the OPAQUE server needs, which are deliberately *not* the same
/// key.
///
/// They differ in the only way that matters operationally — what rotating them
/// costs:
///
/// - `session_key` seals 120 seconds of in-flight state. Rotating it
///   invalidates exchanges in flight and nothing else. It can be rotated on
///   any schedule an operator likes.
/// - `setup_key` encrypts each tenant's [`OpaqueServerSetup`] at rest.
///   Rotating it means re-encrypting those rows; **losing** it means every
///   registration record in every tenant becomes unopenable and the entire
///   estate needs a password reset.
///
/// Sharing one key would put the cheap rotation and the catastrophic one on
/// the same schedule, which is how an operator ends up doing neither.
#[derive(Clone, Copy)]
pub struct OpaqueServerKeys {
    /// Seals in-flight exchange state.
    pub session_key: [u8; 32],
    /// Encrypts per-tenant server key material at rest.
    pub setup_key: [u8; 32],
}

impl std::fmt::Debug for OpaqueServerKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render either key, not even as a length.
        f.debug_struct("OpaqueServerKeys").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// OPAQUE server operations.
#[derive(Clone)]
pub struct OpaqueServer {
    keys: OpaqueServerKeys,
}

impl std::fmt::Debug for OpaqueServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpaqueServer").finish_non_exhaustive()
    }
}

impl OpaqueServer {
    /// Build a server bound to `keys`.
    pub fn new(keys: OpaqueServerKeys) -> Self {
        Self { keys }
    }

    // -- key material ---------------------------------------------------

    /// Mint fresh key material for a tenant.
    ///
    /// Called once, on the tenant's first OPAQUE operation. The result must be
    /// persisted through
    /// [`OpaqueServerSetupRepository::get_or_create`][goc], which is
    /// idempotent under concurrency: two simultaneous first logins must agree
    /// on one setup, because a tenant whose seed depended on which request won
    /// a race would have records that only sometimes open.
    ///
    /// [goc]: axiam_core::repository::OpaqueServerSetupRepository::get_or_create
    pub fn create_server_setup(
        &self,
        tenant_id: Uuid,
        suite: OpaqueSuite,
    ) -> Result<OpaqueServerSetup, AuthError> {
        require_supported_suite(suite)?;
        let mut rng = OsRng;

        let setup = ServerSetup::<Ristretto255Sha512>::new(&mut rng);
        let sealed_setup = self.seal_at_rest(&setup.serialize())?;

        // A separate 32-byte key, stored beside the setup, drives the stable
        // decoy identifiers. It is per tenant so that one tenant's decoys
        // cannot be correlated with another's.
        let mut decoy = [0u8; 32];
        use opaque_ke::rand::RngCore;
        rng.fill_bytes(&mut decoy);
        let sealed_decoy_key = self.seal_at_rest(&decoy)?;

        Ok(OpaqueServerSetup {
            tenant_id,
            suite,
            sealed_setup,
            sealed_decoy_key,
            created_at: Utc::now(),
        })
    }

    // -- registration ---------------------------------------------------

    /// First message of an enrolment: evaluate the OPRF over the client's
    /// blinded password.
    ///
    /// The credential identifier is minted here, randomly, and sealed into the
    /// returned session. Two consequences worth being explicit about:
    ///
    /// - **A rename cannot break a credential**, because the identifier has no
    ///   relationship to any human-readable name. Under SRP the equivalent
    ///   binding was the username itself, so `PUT /users/{id}` had to drop the
    ///   verifier on a rename to keep the state honest.
    /// - **This endpoint is safe to expose unauthenticated**, which it must be,
    ///   because it is used while creating a user who does not exist yet. An
    ///   attacker calling it repeatedly obtains OPRF evaluations under
    ///   identifiers they did not choose and cannot predict, which tells them
    ///   nothing about any real account. Had the identifier been
    ///   caller-supplied, this would instead be an oracle for grinding a
    ///   chosen user's OPRF offline.
    pub fn register_start(
        &self,
        server_setup: &OpaqueServerSetup,
        ksf_params: OpaqueKsfParams,
        registration_request_hex: &str,
    ) -> Result<OpaqueRegisterStartResponse, AuthError> {
        require_supported_suite(server_setup.suite)?;
        let setup = self.open_setup(server_setup)?;

        let request_bytes = decode_hex(registration_request_hex, "registration_request")?;
        let request = RegistrationRequest::<Ristretto255Sha512>::deserialize(&request_bytes)
            .map_err(|_| AuthError::OpaqueMalformed("registration_request".into()))?;

        let mut rng = OsRng;
        let mut credential_identifier = [0u8; 32];
        use opaque_ke::rand::RngCore;
        rng.fill_bytes(&mut credential_identifier);

        let started = ServerRegistration::<Ristretto255Sha512>::start(
            &setup,
            request,
            &credential_identifier,
        )
        .map_err(|_| AuthError::Crypto("OPAQUE registration start failed".into()))?;

        let sealed = SealedRegistration {
            v: SEALED_VERSION,
            kind: KIND_REGISTER.to_string(),
            tenant_id: server_setup.tenant_id,
            credential_identifier: hex::encode(credential_identifier),
            suite: server_setup.suite,
            ksf_params,
            expires_at: Utc::now() + Duration::seconds(SESSION_LIFETIME_SECS),
        };

        let (ksf, memory_kib, iterations, parallelism, log_n, r, p) = ksf_wire_fields(ksf_params);

        Ok(OpaqueRegisterStartResponse {
            opaque_session: self.seal_session(&sealed)?,
            registration_response: hex::encode(started.message.serialize()),
            suite: server_setup.suite.to_string(),
            ksf,
            memory_kib,
            iterations,
            parallelism,
            log_n,
            r,
            p,
        })
    }

    /// Second message of an enrolment: validate the client's record and hand
    /// it back for the caller to persist against a user.
    ///
    /// The record is round-tripped through `opaque_ke`'s parser rather than
    /// merely length-checked. A record that only fails to parse at the user's
    /// next login would present as "your correct password is wrong", with
    /// nothing in the logs pointing at the enrolment that caused it.
    pub fn register_finish(
        &self,
        opaque_session: &str,
        registration_record_hex: &str,
    ) -> Result<OpaqueEnrolled, AuthError> {
        let sealed: SealedRegistration = self
            .open_session(opaque_session, KIND_REGISTER)
            .ok_or_else(|| AuthError::OpaqueMalformed("opaque_session".into()))?;

        let record = normalize_hex(
            registration_record_hex,
            "registration_record",
            Some(sealed.suite.record_len()),
        )
        .map_err(|e| AuthError::OpaqueMalformed(e.to_string()))?;

        let record_bytes = decode_hex(&record, "registration_record")?;
        RegistrationUpload::<Ristretto255Sha512>::deserialize(&record_bytes)
            .map_err(|_| AuthError::OpaqueMalformed("registration_record".into()))?;

        Ok(OpaqueEnrolled {
            tenant_id: sealed.tenant_id,
            credential_identifier: sealed.credential_identifier,
            suite: sealed.suite,
            ksf_params: sealed.ksf_params,
            record,
        })
    }

    // -- login ----------------------------------------------------------

    /// First message of a login, for a user who *has* a record.
    pub fn login_start(
        &self,
        server_setup: &OpaqueServerSetup,
        credential: &OpaqueCredential,
        org_id: Uuid,
        ke1_hex: &str,
    ) -> Result<OpaqueLoginStartResponse, AuthError> {
        let record_bytes = decode_stored_hex(&credential.record, "OPAQUE record")?;
        let record = ServerRegistration::<Ristretto255Sha512>::deserialize(&record_bytes)
            .map_err(|_| AuthError::Crypto("stored OPAQUE record is malformed".into()))?;
        let credential_identifier =
            decode_stored_hex(&credential.credential_identifier, "credential_identifier")?;

        self.build_login(
            server_setup,
            Some(record),
            &credential_identifier,
            credential.ksf_params,
            credential.tenant_id,
            org_id,
            Some(credential.user_id),
            ke1_hex,
        )
    }

    /// First message of a login for an identity with no record — an unknown
    /// user, or a known user who has never enrolled.
    ///
    /// Produces a `KE2` of exactly the shape a real one has, from the setup's
    /// dummy public key. The decoy credential identifier is
    /// `HMAC(decoy_key, tenant_id || identity)` so that it is **stable**: an
    /// attacker who probes the same name twice and sees two different answers
    /// learns immediately that the account does not exist, which is precisely
    /// the leak this branch exists to close.
    ///
    /// `identity` is lowercased before derivation so that `Alice` and `alice`
    /// are one decoy rather than two, matching how the user lookup that failed
    /// treats them.
    #[allow(clippy::too_many_arguments)]
    pub fn login_start_decoy(
        &self,
        server_setup: &OpaqueServerSetup,
        ksf_params: OpaqueKsfParams,
        identity: &str,
        tenant_id: Uuid,
        org_id: Uuid,
        ke1_hex: &str,
    ) -> Result<OpaqueLoginStartResponse, AuthError> {
        let credential_identifier = self.decoy_identifier(server_setup, tenant_id, identity)?;
        self.build_login(
            server_setup,
            None,
            &credential_identifier,
            ksf_params,
            tenant_id,
            org_id,
            None,
            ke1_hex,
        )
    }

    /// Second message of a login: verify the client's `KE3`.
    ///
    /// The [`OpaqueRejection`] variants are for the *caller's* lockout
    /// accounting only — every one of them must be rendered to the client as
    /// the same `401`, or the distinction becomes a progress signal.
    pub fn login_finish(
        &self,
        opaque_session: &str,
        ke3_hex: &str,
    ) -> Result<OpaqueVerified, OpaqueRejection> {
        let sealed: SealedLogin = self
            .open_session(opaque_session, KIND_LOGIN)
            .ok_or(OpaqueRejection::Unusable)?;

        // From here on the session is authentic, so a refusal is attributable
        // and must count against the account.
        let bad = OpaqueRejection::BadCredentials {
            tenant_id: sealed.tenant_id,
            user_id: sealed.user_id,
        };

        let state_bytes = hex::decode(&sealed.ke2_state).map_err(|_| OpaqueRejection::Unusable)?;
        let state = ServerLogin::<Ristretto255Sha512>::deserialize(&state_bytes)
            .map_err(|_| OpaqueRejection::Unusable)?;

        let Ok(ke3_bytes) = hex::decode(ke3_hex) else {
            return Err(bad);
        };
        let Ok(ke3) = CredentialFinalization::<Ristretto255Sha512>::deserialize(&ke3_bytes) else {
            return Err(bad);
        };

        // `finish` performs the MAC comparison in constant time internally;
        // this module must not add a comparison of its own.
        if state.finish(ke3, ServerLoginParameters::default()).is_err() {
            return Err(bad);
        }

        // A decoy exchange cannot be "passed" without forging a MAC under a
        // key nobody holds; it still must not authenticate anybody, because
        // there is nobody to authenticate.
        let Some(user_id) = sealed.user_id else {
            return Err(OpaqueRejection::Unusable);
        };

        Ok(OpaqueVerified {
            tenant_id: sealed.tenant_id,
            org_id: sealed.org_id,
            user_id,
        })
    }

    // -- internals ------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn build_login(
        &self,
        server_setup: &OpaqueServerSetup,
        record: Option<ServerRegistration<Ristretto255Sha512>>,
        credential_identifier: &[u8],
        ksf_params: OpaqueKsfParams,
        tenant_id: Uuid,
        org_id: Uuid,
        user_id: Option<Uuid>,
        ke1_hex: &str,
    ) -> Result<OpaqueLoginStartResponse, AuthError> {
        require_supported_suite(server_setup.suite)?;
        let setup = self.open_setup(server_setup)?;

        let ke1_bytes = decode_hex(ke1_hex, "ke1")?;
        let ke1 = CredentialRequest::<Ristretto255Sha512>::deserialize(&ke1_bytes)
            .map_err(|_| AuthError::OpaqueMalformed("ke1".into()))?;

        let mut rng = OsRng;
        let started = ServerLogin::<Ristretto255Sha512>::start(
            &mut rng,
            &setup,
            record,
            ke1,
            credential_identifier,
            ServerLoginParameters::default(),
        )
        .map_err(|_| AuthError::OpaqueMalformed("ke1".into()))?;

        let sealed = SealedLogin {
            v: SEALED_VERSION,
            kind: KIND_LOGIN.to_string(),
            tenant_id,
            org_id,
            user_id,
            ke2_state: hex::encode(started.state.serialize()),
            expires_at: Utc::now() + Duration::seconds(SESSION_LIFETIME_SECS),
        };

        let (ksf, memory_kib, iterations, parallelism, log_n, r, p) = ksf_wire_fields(ksf_params);

        Ok(OpaqueLoginStartResponse {
            opaque_session: self.seal_session(&sealed)?,
            ke2: hex::encode(started.message.serialize()),
            suite: server_setup.suite.to_string(),
            ksf,
            memory_kib,
            iterations,
            parallelism,
            log_n,
            r,
            p,
            // The mode is a settings question and this crate holds no
            // settings. The REST handler, which read the policy to get here in
            // the first place, stamps it before the response goes out.
            mode: OpaqueMode::default(),
        })
    }

    /// Decrypt and parse a tenant's stored `ServerSetup`.
    fn open_setup(
        &self,
        server_setup: &OpaqueServerSetup,
    ) -> Result<ServerSetup<Ristretto255Sha512>, AuthError> {
        let plaintext = self.open_at_rest(&server_setup.sealed_setup)?;
        ServerSetup::<Ristretto255Sha512>::deserialize(&plaintext).map_err(|_| {
            AuthError::Crypto(
                "stored OPAQUE server setup is malformed or was sealed under a different key"
                    .into(),
            )
        })
    }

    /// `HMAC(decoy_key, tenant_id || lowercased identity)`, truncated to the
    /// 32 bytes a credential identifier occupies.
    fn decoy_identifier(
        &self,
        server_setup: &OpaqueServerSetup,
        tenant_id: Uuid,
        identity: &str,
    ) -> Result<Vec<u8>, AuthError> {
        let key = self.open_at_rest(&server_setup.sealed_decoy_key)?;
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&key)
            .map_err(|_| AuthError::Crypto("OPAQUE decoy key is the wrong length".into()))?;
        mac.update(tenant_id.as_bytes());
        mac.update(b"\x00");
        mac.update(identity.to_lowercase().as_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn seal_at_rest(&self, plaintext: &[u8]) -> Result<String, AuthError> {
        aes256gcm_encrypt(&self.keys.setup_key, plaintext)
    }

    fn open_at_rest(&self, sealed: &str) -> Result<Vec<u8>, AuthError> {
        aes256gcm_decrypt(&self.keys.setup_key, sealed)
    }

    /// Seal exchange state and re-encode URL-safe, so the token survives being
    /// put in a header, a query string, or a JSON body without escaping.
    fn seal_session<T: Serialize>(&self, sealed: &T) -> Result<String, AuthError> {
        let plaintext =
            serde_json::to_vec(sealed).map_err(|e| AuthError::Crypto(format!("seal: {e}")))?;
        let standard_b64 = aes256gcm_encrypt(&self.keys.session_key, &plaintext)?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&standard_b64)
            .map_err(|e| AuthError::Crypto(format!("seal re-encode: {e}")))?;
        Ok(URL_SAFE_NO_PAD.encode(raw))
    }

    /// Open an exchange token, checking version, kind and expiry.
    ///
    /// Returns `None` for every failure mode rather than distinguishing them:
    /// a caller that could tell "expired" from "forged" would hand an attacker
    /// a probe for the server key.
    fn open_session<T: for<'de> Deserialize<'de> + HasEnvelope>(
        &self,
        token: &str,
        expected_kind: &str,
    ) -> Option<T> {
        let raw = URL_SAFE_NO_PAD.decode(token).ok()?;
        let plaintext = aes256gcm_decrypt(
            &self.keys.session_key,
            &base64::engine::general_purpose::STANDARD.encode(&raw),
        )
        .ok()?;
        let value: T = serde_json::from_slice(&plaintext).ok()?;
        if value.version() != SEALED_VERSION
            || value.kind() != expected_kind
            || Utc::now() > value.expires_at()
        {
            return None;
        }
        Some(value)
    }
}

/// The three fields every sealed exchange token carries, so
/// [`OpaqueServer::open_session`] can validate them once instead of each call
/// site remembering to.
///
/// A trait rather than a shared header struct because the two sealed types are
/// flat JSON objects on the wire, and nesting them would change the sealed
/// layout for no benefit.
trait HasEnvelope {
    fn version(&self) -> u8;
    fn kind(&self) -> &str;
    fn expires_at(&self) -> DateTime<Utc>;
}

impl HasEnvelope for SealedRegistration {
    fn version(&self) -> u8 {
        self.v
    }
    fn kind(&self) -> &str {
        &self.kind
    }
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

impl HasEnvelope for SealedLogin {
    fn version(&self) -> u8 {
        self.v
    }
    fn kind(&self) -> &str {
        &self.kind
    }
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

/// Reject a suite this build cannot speak.
///
/// Currently total, and deliberately written as a check anyway: when
/// `P256Sha256` is added, every entry point already refuses a suite it has no
/// implementation for rather than silently computing under the wrong one.
fn require_supported_suite(suite: OpaqueSuite) -> Result<(), AuthError> {
    match suite {
        OpaqueSuite::Ristretto255Sha512 => Ok(()),
    }
}

/// Decode hex that came from a **client**. A failure is the caller's mistake.
fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>, AuthError> {
    hex::decode(value).map_err(|_| AuthError::OpaqueMalformed(format!("{label} is not valid hex")))
}

/// Decode hex that came from **AXIAM's own storage**. A failure is corruption,
/// not a bad request, and must not be reported to the caller as one.
fn decode_stored_hex(value: &str, label: &str) -> Result<Vec<u8>, AuthError> {
    hex::decode(value).map_err(|_| AuthError::Crypto(format!("stored {label} is not valid hex")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::opaque::OpaqueKsf;
    use opaque_ke::generic_array::{ArrayLength, GenericArray};
    use opaque_ke::{CipherSuite, CredentialResponse, ksf::Ksf};
    use opaque_ke::{
        ClientLogin, ClientLoginFinishParameters, ClientRegistration,
        ClientRegistrationFinishParameters, RegistrationResponse,
    };
    use std::sync::OnceLock;

    // ---------------------------------------------------------------
    // A client, so the tests exercise the real protocol rather than the
    // server talking to itself.
    // ---------------------------------------------------------------

    /// Client-side suite with no stretching. The KSF is client-only and
    /// orthogonal to everything the server does, so most tests skip its cost;
    /// `a_client_that_stretches_differently_cannot_open_its_own_envelope`
    /// covers the one property that does depend on it.
    struct FastClient;
    impl CipherSuite for FastClient {
        type OprfCs = opaque_ke::Ristretto255;
        type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2_v10::Sha512>;
        type Ksf = opaque_ke::ksf::Identity;
    }

    /// A KSF that is cheap but *not* the identity, used to prove that a
    /// mismatch between enrolment and login is fatal.
    #[derive(Default)]
    struct CountingKsf(u8);
    impl Ksf for CountingKsf {
        fn hash<L: ArrayLength<u8>>(
            &self,
            input: GenericArray<u8, L>,
        ) -> Result<GenericArray<u8, L>, opaque_ke::errors::InternalError> {
            let mut out = input;
            for byte in out.iter_mut() {
                *byte ^= 0xA5 ^ self.0;
            }
            Ok(out)
        }
    }
    struct StretchingClient;
    impl CipherSuite for StretchingClient {
        type OprfCs = opaque_ke::Ristretto255;
        type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2_v10::Sha512>;
        type Ksf = CountingKsf;
    }

    /// Keys minted per process rather than written as literals.
    ///
    /// CodeQL's `rust/hardcoded-cryptographic-value` flags a literal that
    /// reaches a cipher, and that rule is right about shipping code: keeping it
    /// sharp is worth more than a fixed array here. Nothing in this file
    /// depends on the values — every assertion is about what the engine does
    /// with them — and minting them per run additionally means a test that
    /// accidentally hard-coded an expectation about a key fails immediately.
    fn keys() -> OpaqueServerKeys {
        static KEYS: OnceLock<OpaqueServerKeys> = OnceLock::new();
        *KEYS.get_or_init(|| {
            use opaque_ke::rand::RngCore;
            let mut rng = OsRng;
            let mut session_key = [0u8; 32];
            let mut setup_key = [0u8; 32];
            rng.fill_bytes(&mut session_key);
            rng.fill_bytes(&mut setup_key);
            OpaqueServerKeys {
                session_key,
                setup_key,
            }
        })
    }

    /// A distinct key, for the "sealed under another key" cases.
    fn other_key() -> [u8; 32] {
        static KEY: OnceLock<[u8; 32]> = OnceLock::new();
        *KEY.get_or_init(|| {
            use opaque_ke::rand::RngCore;
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            key
        })
    }

    /// A password minted per process, for the same reason as [`keys`].
    fn password(tag: &str) -> &'static [u8] {
        use std::collections::HashMap;
        use std::sync::Mutex;
        static CACHE: OnceLock<Mutex<HashMap<String, &'static [u8]>>> = OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        let mut guard = cache.lock().unwrap();
        guard.entry(tag.to_string()).or_insert_with(|| {
            use opaque_ke::rand::RngCore;
            let mut bytes = [0u8; 16];
            OsRng.fill_bytes(&mut bytes);
            let value: &'static str =
                Box::leak(format!("{tag}-{}", hex::encode(bytes)).into_boxed_str());
            value.as_bytes()
        })
    }

    fn server() -> OpaqueServer {
        OpaqueServer::new(keys())
    }

    fn params() -> OpaqueKsfParams {
        OpaqueKsfParams::defaults_for(OpaqueKsf::Argon2id)
    }

    /// Drive a full enrolment and return the stored credential.
    fn enrol(
        srv: &OpaqueServer,
        setup: &OpaqueServerSetup,
        user_id: Uuid,
        password: &[u8],
    ) -> OpaqueCredential {
        let mut rng = OsRng;
        let start = ClientRegistration::<FastClient>::start(&mut rng, password).unwrap();
        let resp = srv
            .register_start(setup, params(), &hex::encode(start.message.serialize()))
            .unwrap();

        let server_msg = RegistrationResponse::<FastClient>::deserialize(
            &hex::decode(&resp.registration_response).unwrap(),
        )
        .unwrap();
        let finished = start
            .state
            .finish(
                &mut rng,
                password,
                server_msg,
                ClientRegistrationFinishParameters::default(),
            )
            .unwrap();

        let enrolled = srv
            .register_finish(
                &resp.opaque_session,
                &hex::encode(finished.message.serialize()),
            )
            .unwrap();

        OpaqueCredential {
            id: Uuid::new_v4(),
            tenant_id: enrolled.tenant_id,
            user_id,
            credential_identifier: enrolled.credential_identifier,
            suite: enrolled.suite,
            ksf_params: enrolled.ksf_params,
            record: enrolled.record,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// Full login round trip: returns the server's verdict.
    fn login(
        srv: &OpaqueServer,
        setup: &OpaqueServerSetup,
        credential: Option<&OpaqueCredential>,
        identity: &str,
        tenant_id: Uuid,
        org_id: Uuid,
        password: &[u8],
    ) -> (
        OpaqueLoginStartResponse,
        Result<OpaqueVerified, OpaqueRejection>,
    ) {
        let mut rng = OsRng;
        let start = ClientLogin::<FastClient>::start(&mut rng, password).unwrap();
        let ke1 = hex::encode(start.message.serialize());

        let started = match credential {
            Some(c) => srv.login_start(setup, c, org_id, &ke1).unwrap(),
            None => srv
                .login_start_decoy(setup, params(), identity, tenant_id, org_id, &ke1)
                .unwrap(),
        };

        let ke2 =
            CredentialResponse::<FastClient>::deserialize(&hex::decode(&started.ke2).unwrap())
                .unwrap();
        let finished = start.state.finish(
            &mut rng,
            password,
            ke2,
            ClientLoginFinishParameters::default(),
        );

        let verdict = match finished {
            Ok(f) => srv.login_finish(&started.opaque_session, &hex::encode(f.message.serialize())),
            // The client could not open the envelope. A real client stops
            // here; the tests still poke the server with a junk KE3 so that
            // the server's own refusal path is what gets asserted.
            Err(_) => srv.login_finish(&started.opaque_session, &hex::encode([0u8; 64])),
        };
        (started, verdict)
    }

    // ---------------------------------------------------------------
    // Happy path
    // ---------------------------------------------------------------

    #[test]
    fn a_full_enrolment_and_login_authenticates_the_right_user() {
        let srv = server();
        let tenant = Uuid::new_v4();
        let org = Uuid::new_v4();
        let user = Uuid::new_v4();
        let setup = srv
            .create_server_setup(tenant, OpaqueSuite::Ristretto255Sha512)
            .unwrap();

        let cred = enrol(&srv, &setup, user, password("correct"));
        let (_, verdict) = login(
            &srv,
            &setup,
            Some(&cred),
            "alice",
            tenant,
            org,
            password("correct"),
        );

        let ok = verdict.expect("a correct password must authenticate");
        assert_eq!(ok.user_id, user);
        assert_eq!(ok.tenant_id, tenant);
        assert_eq!(ok.org_id, org);
    }

    #[test]
    fn a_credential_carries_no_username_so_a_rename_cannot_invalidate_it() {
        // The whole reason SRP needed `PUT /users/{id}` to drop the verifier
        // on a username change. There is nothing here to go stale.
        let srv = server();
        let tenant = Uuid::new_v4();
        let setup = srv
            .create_server_setup(tenant, OpaqueSuite::Ristretto255Sha512)
            .unwrap();
        let cred = enrol(&srv, &setup, Uuid::new_v4(), password("pw"));

        assert_eq!(cred.credential_identifier.len(), 64);
        assert!(
            hex::decode(&cred.credential_identifier).is_ok(),
            "credential identifier must be hex"
        );
    }

    #[test]
    fn two_enrolments_mint_different_credential_identifiers() {
        let srv = server();
        let tenant = Uuid::new_v4();
        let setup = srv
            .create_server_setup(tenant, OpaqueSuite::Ristretto255Sha512)
            .unwrap();
        let a = enrol(&srv, &setup, Uuid::new_v4(), password("pw"));
        let b = enrol(&srv, &setup, Uuid::new_v4(), password("pw"));
        assert_ne!(a.credential_identifier, b.credential_identifier);
        // Same password, different identifier => different record.
        assert_ne!(a.record, b.record);
    }

    // ---------------------------------------------------------------
    // Failure attribution — the lockout property
    // ---------------------------------------------------------------

    #[test]
    fn a_wrong_password_is_attributable_so_it_can_count_toward_lockout() {
        let srv = server();
        let tenant = Uuid::new_v4();
        let org = Uuid::new_v4();
        let user = Uuid::new_v4();
        let setup = srv
            .create_server_setup(tenant, OpaqueSuite::Ristretto255Sha512)
            .unwrap();
        let cred = enrol(&srv, &setup, user, password("right"));

        let (_, verdict) = login(
            &srv,
            &setup,
            Some(&cred),
            "alice",
            tenant,
            org,
            password("wrong"),
        );
        match verdict {
            Err(OpaqueRejection::BadCredentials { tenant_id, user_id }) => {
                assert_eq!(tenant_id, tenant);
                assert_eq!(
                    user_id,
                    Some(user),
                    "without the user id the caller cannot accrue a lockout, and \
                     enabling OPAQUE would silently remove brute-force protection"
                );
            }
            other => panic!("expected BadCredentials, got {other:?}"),
        }
    }

    #[test]
    fn a_decoy_failure_names_no_user_because_there_is_nobody_to_lock_out() {
        let srv = server();
        let tenant = Uuid::new_v4();
        let org = Uuid::new_v4();
        let setup = srv
            .create_server_setup(tenant, OpaqueSuite::Ristretto255Sha512)
            .unwrap();

        let (_, verdict) = login(
            &srv,
            &setup,
            None,
            "nobody",
            tenant,
            org,
            password("anything"),
        );
        match verdict {
            Err(OpaqueRejection::BadCredentials { tenant_id, user_id }) => {
                assert_eq!(tenant_id, tenant);
                assert_eq!(user_id, None);
            }
            Err(OpaqueRejection::Unusable) => {}
            Ok(_) => panic!("a decoy exchange must never authenticate anybody"),
        }
    }

    // ---------------------------------------------------------------
    // Enumeration resistance
    // ---------------------------------------------------------------

    #[test]
    fn a_decoy_ke2_is_the_same_shape_as_a_real_one() {
        let srv = server();
        let tenant = Uuid::new_v4();
        let org = Uuid::new_v4();
        let setup = srv
            .create_server_setup(tenant, OpaqueSuite::Ristretto255Sha512)
            .unwrap();
        let cred = enrol(&srv, &setup, Uuid::new_v4(), password("pw"));

        let (real, _) = login(
            &srv,
            &setup,
            Some(&cred),
            "alice",
            tenant,
            org,
            password("pw"),
        );
        let (decoy, _) = login(&srv, &setup, None, "nobody", tenant, org, password("pw"));

        assert_eq!(
            real.ke2.len(),
            decoy.ke2.len(),
            "a length difference is a free account-enumeration oracle"
        );
        assert_eq!(real.suite, decoy.suite);
        assert_eq!(real.ksf, decoy.ksf);
        assert_eq!(real.memory_kib, decoy.memory_kib);
        assert_eq!(real.iterations, decoy.iterations);
        assert_eq!(real.parallelism, decoy.parallelism);
    }

    #[test]
    fn a_decoy_identifier_is_stable_for_one_name_and_differs_across_names() {
        let srv = server();
        let tenant = Uuid::new_v4();
        let setup = srv
            .create_server_setup(tenant, OpaqueSuite::Ristretto255Sha512)
            .unwrap();

        let a1 = srv.decoy_identifier(&setup, tenant, "ghost").unwrap();
        let a2 = srv.decoy_identifier(&setup, tenant, "ghost").unwrap();
        let b = srv.decoy_identifier(&setup, tenant, "phantom").unwrap();

        assert_eq!(
            a1, a2,
            "an unstable decoy announces non-existence as loudly as a 404"
        );
        assert_ne!(a1, b);
        assert_eq!(a1.len(), 32);
    }

    #[test]
    fn a_decoy_identifier_is_case_insensitive_like_the_lookup_that_failed() {
        let srv = server();
        let tenant = Uuid::new_v4();
        let setup = srv
            .create_server_setup(tenant, OpaqueSuite::Ristretto255Sha512)
            .unwrap();
        assert_eq!(
            srv.decoy_identifier(&setup, tenant, "Ghost").unwrap(),
            srv.decoy_identifier(&setup, tenant, "ghost").unwrap(),
        );
    }

    #[test]
    fn decoys_do_not_correlate_across_tenants() {
        let srv = server();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        let s1 = srv
            .create_server_setup(t1, OpaqueSuite::Ristretto255Sha512)
            .unwrap();
        let s2 = srv
            .create_server_setup(t2, OpaqueSuite::Ristretto255Sha512)
            .unwrap();

        assert_ne!(
            srv.decoy_identifier(&s1, t1, "ghost").unwrap(),
            srv.decoy_identifier(&s2, t2, "ghost").unwrap(),
        );
    }

    // ---------------------------------------------------------------
    // Session handling
    // ---------------------------------------------------------------

    #[test]
    fn a_registration_session_cannot_be_replayed_as_a_login_session() {
        // Both are sealed under the same key. Only the `kind` tag stops one
        // exchange's token from being fed to the other.
        let srv = server();
        let tenant = Uuid::new_v4();
        let setup = srv
            .create_server_setup(tenant, OpaqueSuite::Ristretto255Sha512)
            .unwrap();

        let mut rng = OsRng;
        let start = ClientRegistration::<FastClient>::start(&mut rng, password("pw")).unwrap();
        let resp = srv
            .register_start(&setup, params(), &hex::encode(start.message.serialize()))
            .unwrap();

        match srv.login_finish(&resp.opaque_session, &hex::encode([0u8; 64])) {
            Err(OpaqueRejection::Unusable) => {}
            other => panic!("expected Unusable, got {other:?}"),
        }
    }

    #[test]
    fn a_login_session_cannot_be_replayed_as_a_registration_session() {
        let srv = server();
        let tenant = Uuid::new_v4();
        let org = Uuid::new_v4();
        let setup = srv
            .create_server_setup(tenant, OpaqueSuite::Ristretto255Sha512)
            .unwrap();
        let cred = enrol(&srv, &setup, Uuid::new_v4(), password("pw"));
        let (started, _) = login(
            &srv,
            &setup,
            Some(&cred),
            "alice",
            tenant,
            org,
            password("pw"),
        );

        assert!(
            srv.register_finish(&started.opaque_session, &"00".repeat(192))
                .is_err()
        );
    }

    #[test]
    fn a_tampered_session_is_unusable() {
        let srv = server();
        let tenant = Uuid::new_v4();
        let org = Uuid::new_v4();
        let setup = srv
            .create_server_setup(tenant, OpaqueSuite::Ristretto255Sha512)
            .unwrap();
        let cred = enrol(&srv, &setup, Uuid::new_v4(), password("pw"));
        let (started, _) = login(
            &srv,
            &setup,
            Some(&cred),
            "alice",
            tenant,
            org,
            password("pw"),
        );

        let mut token = started.opaque_session.clone();
        // Flip a character in the ciphertext body.
        let mid = token.len() / 2;
        let replacement = if token.as_bytes()[mid] == b'A' {
            'B'
        } else {
            'A'
        };
        token.replace_range(mid..mid + 1, &replacement.to_string());

        match srv.login_finish(&token, &hex::encode([0u8; 64])) {
            Err(OpaqueRejection::Unusable) => {}
            other => panic!("expected Unusable, got {other:?}"),
        }
    }

    #[test]
    fn a_session_sealed_under_another_key_is_unusable() {
        let srv = server();
        let other = OpaqueServer::new(OpaqueServerKeys {
            session_key: other_key(),
            setup_key: keys().setup_key,
        });
        let tenant = Uuid::new_v4();
        let org = Uuid::new_v4();
        let setup = srv
            .create_server_setup(tenant, OpaqueSuite::Ristretto255Sha512)
            .unwrap();
        let cred = enrol(&srv, &setup, Uuid::new_v4(), password("pw"));
        let (started, _) = login(
            &srv,
            &setup,
            Some(&cred),
            "alice",
            tenant,
            org,
            password("pw"),
        );

        match other.login_finish(&started.opaque_session, &hex::encode([0u8; 64])) {
            Err(OpaqueRejection::Unusable) => {}
            other => panic!("expected Unusable, got {other:?}"),
        }
    }

    #[test]
    fn an_expired_session_is_unusable() {
        let srv = server();
        let sealed = SealedLogin {
            v: SEALED_VERSION,
            kind: KIND_LOGIN.to_string(),
            tenant_id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            user_id: Some(Uuid::new_v4()),
            ke2_state: hex::encode([0u8; 128]),
            expires_at: Utc::now() - Duration::seconds(1),
        };
        let token = srv.seal_session(&sealed).unwrap();
        match srv.login_finish(&token, &hex::encode([0u8; 64])) {
            Err(OpaqueRejection::Unusable) => {}
            other => panic!("expected Unusable, got {other:?}"),
        }
    }

    #[test]
    fn a_session_of_an_unknown_version_is_unusable() {
        let srv = server();
        let sealed = SealedLogin {
            v: SEALED_VERSION + 1,
            kind: KIND_LOGIN.to_string(),
            tenant_id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            user_id: Some(Uuid::new_v4()),
            ke2_state: hex::encode([0u8; 128]),
            expires_at: Utc::now() + Duration::seconds(60),
        };
        let token = srv.seal_session(&sealed).unwrap();
        match srv.login_finish(&token, &hex::encode([0u8; 64])) {
            Err(OpaqueRejection::Unusable) => {}
            other => panic!("expected Unusable, got {other:?}"),
        }
    }

    #[test]
    fn a_non_base64_session_is_unusable() {
        let srv = server();
        match srv.login_finish("!!!not base64!!!", &hex::encode([0u8; 64])) {
            Err(OpaqueRejection::Unusable) => {}
            other => panic!("expected Unusable, got {other:?}"),
        }
    }

    // ---------------------------------------------------------------
    // Key material
    // ---------------------------------------------------------------

    #[test]
    fn a_setup_sealed_under_a_different_key_is_refused_rather_than_misread() {
        let srv = server();
        let tenant = Uuid::new_v4();
        let setup = srv
            .create_server_setup(tenant, OpaqueSuite::Ristretto255Sha512)
            .unwrap();

        let other = OpaqueServer::new(OpaqueServerKeys {
            session_key: keys().session_key,
            setup_key: other_key(),
        });
        let mut rng = OsRng;
        let start = ClientRegistration::<FastClient>::start(&mut rng, password("pw")).unwrap();
        assert!(
            other
                .register_start(&setup, params(), &hex::encode(start.message.serialize()))
                .is_err()
        );
    }

    #[test]
    fn each_tenant_gets_independent_key_material() {
        let srv = server();
        let a = srv
            .create_server_setup(Uuid::new_v4(), OpaqueSuite::Ristretto255Sha512)
            .unwrap();
        let b = srv
            .create_server_setup(Uuid::new_v4(), OpaqueSuite::Ristretto255Sha512)
            .unwrap();
        assert_ne!(a.sealed_setup, b.sealed_setup);
        assert_ne!(a.sealed_decoy_key, b.sealed_decoy_key);
    }

    #[test]
    fn a_record_enrolled_in_one_tenant_does_not_open_in_another() {
        let srv = server();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        let org = Uuid::new_v4();
        let s1 = srv
            .create_server_setup(t1, OpaqueSuite::Ristretto255Sha512)
            .unwrap();
        let s2 = srv
            .create_server_setup(t2, OpaqueSuite::Ristretto255Sha512)
            .unwrap();

        let cred = enrol(&srv, &s1, Uuid::new_v4(), password("pw"));
        // Same record, wrong tenant's OPRF seed.
        let (_, verdict) = login(&srv, &s2, Some(&cred), "alice", t2, org, password("pw"));
        assert!(
            verdict.is_err(),
            "a record must be useless outside the tenant whose seed sealed it"
        );
    }

    // ---------------------------------------------------------------
    // Input validation
    // ---------------------------------------------------------------

    #[test]
    fn register_finish_rejects_a_record_of_the_wrong_width() {
        let srv = server();
        let tenant = Uuid::new_v4();
        let setup = srv
            .create_server_setup(tenant, OpaqueSuite::Ristretto255Sha512)
            .unwrap();
        let mut rng = OsRng;
        let start = ClientRegistration::<FastClient>::start(&mut rng, password("pw")).unwrap();
        let resp = srv
            .register_start(&setup, params(), &hex::encode(start.message.serialize()))
            .unwrap();

        assert!(
            srv.register_finish(&resp.opaque_session, &"00".repeat(191))
                .is_err()
        );
    }

    #[test]
    fn register_finish_rejects_a_record_that_is_the_right_width_but_not_parseable() {
        // Length alone is not validation. A record that only fails at the
        // user's next login presents as "your correct password is wrong",
        // with nothing pointing back at the enrolment that caused it.
        let srv = server();
        let tenant = Uuid::new_v4();
        let setup = srv
            .create_server_setup(tenant, OpaqueSuite::Ristretto255Sha512)
            .unwrap();
        let mut rng = OsRng;
        let start = ClientRegistration::<FastClient>::start(&mut rng, password("pw")).unwrap();
        let resp = srv
            .register_start(&setup, params(), &hex::encode(start.message.serialize()))
            .unwrap();

        // All-zero bytes are the right length but not a valid ristretto255
        // public key.
        assert!(
            srv.register_finish(&resp.opaque_session, &"00".repeat(192))
                .is_err()
        );
    }

    #[test]
    fn register_start_rejects_a_malformed_request() {
        let srv = server();
        let setup = srv
            .create_server_setup(Uuid::new_v4(), OpaqueSuite::Ristretto255Sha512)
            .unwrap();
        assert!(srv.register_start(&setup, params(), "not hex").is_err());
        assert!(
            srv.register_start(&setup, params(), &"00".repeat(31))
                .is_err()
        );
    }

    #[test]
    fn login_start_rejects_a_malformed_ke1() {
        let srv = server();
        let tenant = Uuid::new_v4();
        let setup = srv
            .create_server_setup(tenant, OpaqueSuite::Ristretto255Sha512)
            .unwrap();
        let cred = enrol(&srv, &setup, Uuid::new_v4(), password("pw"));
        assert!(
            srv.login_start(&setup, &cred, Uuid::new_v4(), "zz")
                .is_err()
        );
        assert!(
            srv.login_start(&setup, &cred, Uuid::new_v4(), &"00".repeat(10))
                .is_err()
        );
    }

    #[test]
    fn login_start_rejects_a_stored_record_that_is_corrupt() {
        let srv = server();
        let tenant = Uuid::new_v4();
        let setup = srv
            .create_server_setup(tenant, OpaqueSuite::Ristretto255Sha512)
            .unwrap();
        let mut cred = enrol(&srv, &setup, Uuid::new_v4(), password("pw"));
        cred.record = "zz".repeat(192);

        let mut rng = OsRng;
        let start = ClientLogin::<FastClient>::start(&mut rng, password("pw")).unwrap();
        assert!(
            srv.login_start(
                &setup,
                &cred,
                Uuid::new_v4(),
                &hex::encode(start.message.serialize())
            )
            .is_err()
        );
    }

    // ---------------------------------------------------------------
    // KSF agreement
    // ---------------------------------------------------------------

    #[test]
    fn a_client_that_stretches_differently_cannot_open_its_own_envelope() {
        // This is why the KSF and its parameters are stored per credential and
        // echoed at login rather than read from current policy: a client that
        // used different parameters derives a different randomized password
        // and fails against a record that is perfectly good.
        let srv = server();
        let tenant = Uuid::new_v4();
        let setup = srv
            .create_server_setup(tenant, OpaqueSuite::Ristretto255Sha512)
            .unwrap();
        let mut rng = OsRng;

        // Enrol stretching with CountingKsf(0).
        let start =
            ClientRegistration::<StretchingClient>::start(&mut rng, password("pw")).unwrap();
        let resp = srv
            .register_start(&setup, params(), &hex::encode(start.message.serialize()))
            .unwrap();
        let server_msg = RegistrationResponse::<StretchingClient>::deserialize(
            &hex::decode(&resp.registration_response).unwrap(),
        )
        .unwrap();
        let finished = start
            .state
            .finish(
                &mut rng,
                password("pw"),
                server_msg,
                ClientRegistrationFinishParameters::new(Default::default(), Some(&CountingKsf(0))),
            )
            .unwrap();
        let enrolled = srv
            .register_finish(
                &resp.opaque_session,
                &hex::encode(finished.message.serialize()),
            )
            .unwrap();

        let cred = OpaqueCredential {
            id: Uuid::new_v4(),
            tenant_id: enrolled.tenant_id,
            user_id: Uuid::new_v4(),
            credential_identifier: enrolled.credential_identifier,
            suite: enrolled.suite,
            ksf_params: enrolled.ksf_params,
            record: enrolled.record,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Log in stretching with CountingKsf(1) — same password, different KSF.
        let start = ClientLogin::<StretchingClient>::start(&mut rng, password("pw")).unwrap();
        let started = srv
            .login_start(
                &setup,
                &cred,
                Uuid::new_v4(),
                &hex::encode(start.message.serialize()),
            )
            .unwrap();
        let ke2 = CredentialResponse::<StretchingClient>::deserialize(
            &hex::decode(&started.ke2).unwrap(),
        )
        .unwrap();

        assert!(
            start
                .state
                .finish(
                    &mut rng,
                    password("pw"),
                    ke2,
                    ClientLoginFinishParameters::new(
                        None,
                        Default::default(),
                        Some(&CountingKsf(1)),
                    ),
                )
                .is_err(),
            "a KSF mismatch must fail, which is why the server dictates the parameters"
        );
    }

    // ---------------------------------------------------------------
    // Secrets never render
    // ---------------------------------------------------------------

    #[test]
    fn debug_renders_no_key_material() {
        // Asserted against the actual key bytes rather than against a fixed
        // digit, so the test still means something now that the keys are
        // minted per run.
        let srv = server();
        let hexed = hex::encode(keys().session_key);
        for rendered in [format!("{srv:?}"), format!("{:?}", keys())] {
            assert!(!rendered.contains(&hexed), "{rendered}");
            assert!(!rendered.contains("32"), "no length either: {rendered}");
        }
    }
}
