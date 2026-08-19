//! Secure Remote Password (SRP-6a) — server side.
//!
//! The domain types, the enforcement modes, and the rationale for adopting SRP
//! at all live in [`axiam_core::models::srp`]. This module is the arithmetic
//! and the two-message exchange that sits behind `POST /api/v1/auth/srp/challenge`
//! and `POST /api/v1/auth/srp/verify`.
//!
//! # The exchange
//!
//! ```text
//!   client                                            server
//!     |  I, A = g^a mod N                               |
//!     | ----------------------------------------------> |   challenge
//!     |                                                  |   b <- random
//!     |                                                  |   B = (k*v + g^b) mod N
//!     |  s, B, group, kdf, params, srp_session           |
//!     | <---------------------------------------------- |
//!     |   x = KDF(I ":" p, s)                           |
//!     |   S = (B - k*g^x)^(a + u*x) mod N               |
//!     |   K = H(S);  M1 = H(H(N)^H(g) | H(I) | s | A | B | K)
//!     |  srp_session, M1                                |
//!     | ----------------------------------------------> |   verify
//!     |                                                  |   compare M1 in constant time
//!     |  M2 = H(A | M1 | K), + the ordinary login result |
//!     | <---------------------------------------------- |
//! ```
//!
//! Both sides arrive at the same `S` — the client from `a` and `x`, the server
//! from `b` and `v` — without either learning the other's secret.
//!
//! # Why the server state is sealed into a token rather than stored
//!
//! Between the two messages the server has to remember what it derived. The
//! obvious approach is a `srp_session` table with a TTL; this module instead
//! seals the derived state into an AES-256-GCM token the client carries back,
//! exactly as [`crate::service::AuthService`] already does for the MFA
//! challenge. Three reasons:
//!
//! 1. **It works across replicas with no coordination.** A DB-backed session
//!    would add a write and a read to every login on the hot path, in a system
//!    whose whole point is horizontal scaling.
//! 2. **There is nothing to garbage-collect.** Expiry is a field inside the
//!    sealed blob, checked on open; an abandoned exchange costs nothing.
//! 3. **A replayed token grants no new power.** Opening it requires the server
//!    key, and *using* it still requires `M1`, which still requires the
//!    password. An attacker who can replay a captured `(srp_session, M1)` pair
//!    has, by construction, already broken TLS — at which point they have the
//!    session cookie the exchange would have produced anyway. The 120-second
//!    lifetime bounds even that.
//!
//! # Constant-time properties, stated precisely
//!
//! `num_bigint::BigUint::modpow` is **not** constant-time, so it is worth being
//! exact about what that does and does not expose here.
//!
//! - The verifier `v` — the only long-term secret — is used as a *base*
//!   (`v.modpow(&u, n)`), never as an exponent. Exponent-dependent timing is
//!   the leak `modpow` has; base-dependent timing is not, so `v` is not
//!   exposed.
//! - The exponent `b` is freshly generated per request and discarded when the
//!   exchange completes. Recovering it would let an attacker finish one
//!   already-in-flight exchange for which they would still need `M1`.
//! - The password never reaches this module in any form.
//!
//! The `M1` comparison — the one place a timing signal would be directly
//! exploitable — uses [`subtle::ConstantTimeEq`].
//!
//! # Account enumeration
//!
//! An unknown identity must produce a response indistinguishable from a known
//! one, or `/auth/srp/challenge` becomes a faster user-enumeration oracle than
//! anything else in the API. [`SrpServer::challenge`] handles this by
//! fabricating a *stable* salt — `HMAC(server_key, tenant_id || identity)`, so
//! the same unknown user yields the same salt on every attempt, which a random
//! salt would not — and a well-formed `B` derived from a dummy verifier. The
//! full modular exponentiation is performed in that branch too, so the timing
//! matches. The caller cannot tell the difference, and the subsequent
//! `/auth/srp/verify` fails as an ordinary bad-password would.

use std::sync::OnceLock;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, KeyInit, Mac};
use num_bigint::BigUint;
use num_traits::Zero;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use axiam_core::models::srp::{SrpChallenge, SrpCredential, SrpGroup, SrpKdfParams};

use crate::crypto::{aes256gcm_decrypt, aes256gcm_encrypt};
use crate::error::AuthError;

type HmacSha256 = Hmac<Sha256>;

/// How long a `srp_session` stays openable. Long enough for a client to run
/// Argon2id on a slow phone, short enough that an abandoned exchange is not a
/// standing replay target.
const SESSION_LIFETIME_SECS: i64 = 120;

/// Width of the server's private ephemeral `b`. RFC 5054 §3 requires at least
/// 256 bits; 256 is used because `b`'s only job is to be unguessable for the
/// ~2 minutes the exchange lives.
const EPHEMERAL_BITS: usize = 256;

// ---------------------------------------------------------------------------
// RFC 5054 Appendix A groups
// ---------------------------------------------------------------------------
//
// These are verbatim RFC 5054 Appendix A (the 3072- and 4096-bit entries are
// the RFC 3526 MODP groups the RFC adopts). Each is asserted in the unit tests
// below to be the right width, prime, a *safe* prime, and to have `g`
// generating the order-(N-1)/2 subgroup — a transcription error in any of
// these constants is a silent, total break of the protocol's security, and it
// would not otherwise show up in a test where client and server share the
// same wrong constant.

const N_2048_HEX: &str = concat!(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050",
    "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50",
    "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8",
    "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B",
    "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748",
    "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6",
    "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6",
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
);
const G_2048: u32 = 2;

const N_3072_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33",
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2",
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
);
const G_3072: u32 = 5;

const N_4096_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33",
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2",
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7",
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8",
    "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2",
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9",
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
);
const G_4096: u32 = 5;

/// Parsed, cached group parameters.
struct GroupParams {
    n: BigUint,
    g: BigUint,
    /// `k = H(N | PAD(g))` — the SRP-6a multiplier, cached because it depends
    /// only on the group.
    k: BigUint,
    byte_len: usize,
}

fn group_params(group: SrpGroup) -> &'static GroupParams {
    static G2048: OnceLock<GroupParams> = OnceLock::new();
    static G3072: OnceLock<GroupParams> = OnceLock::new();
    static G4096: OnceLock<GroupParams> = OnceLock::new();

    fn build(n_hex: &str, g: u32, byte_len: usize) -> GroupParams {
        let n = BigUint::parse_bytes(n_hex.as_bytes(), 16)
            .expect("compile-time SRP group modulus is valid hex");
        let g = BigUint::from(g);
        let k = hash_to_int(&[&to_bytes(&n, byte_len), &to_bytes(&g, byte_len)]);
        GroupParams { n, g, k, byte_len }
    }

    match group {
        SrpGroup::Rfc5054_2048 => G2048.get_or_init(|| build(N_2048_HEX, G_2048, 256)),
        SrpGroup::Rfc5054_3072 => G3072.get_or_init(|| build(N_3072_HEX, G_3072, 384)),
        SrpGroup::Rfc5054_4096 => G4096.get_or_init(|| build(N_4096_HEX, G_4096, 512)),
    }
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/// `PAD(x)`: big-endian bytes, left-padded with zeros to the group width.
///
/// Every hash input in SRP-6a is padded to the modulus width. Skipping it is
/// the classic SRP interop bug — two implementations agree until the day a
/// value happens to have a leading zero byte, and then one login in 256 fails.
fn to_bytes(value: &BigUint, byte_len: usize) -> Vec<u8> {
    let raw = value.to_bytes_be();
    if raw.len() >= byte_len {
        return raw;
    }
    let mut out = vec![0u8; byte_len - raw.len()];
    out.extend_from_slice(&raw);
    out
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn hash_to_int(parts: &[&[u8]]) -> BigUint {
    BigUint::from_bytes_be(&hash_parts(parts))
}

/// `u = H(PAD(A) | PAD(B))`.
fn compute_u(a_pub: &BigUint, b_pub: &BigUint, byte_len: usize) -> BigUint {
    hash_to_int(&[&to_bytes(a_pub, byte_len), &to_bytes(b_pub, byte_len)])
}

/// `M1 = H( H(N) XOR H(PAD(g)) | H(I) | s | PAD(A) | PAD(B) | K )`.
fn compute_m1(
    params: &GroupParams,
    identity: &str,
    salt: &[u8],
    a_pub: &BigUint,
    b_pub: &BigUint,
    session_key: &[u8; 32],
) -> [u8; 32] {
    let h_n = hash_parts(&[&to_bytes(&params.n, params.byte_len)]);
    let h_g = hash_parts(&[&to_bytes(&params.g, params.byte_len)]);
    let mut xored = [0u8; 32];
    for i in 0..32 {
        xored[i] = h_n[i] ^ h_g[i];
    }
    let h_i = hash_parts(&[identity.as_bytes()]);

    hash_parts(&[
        &xored,
        &h_i,
        salt,
        &to_bytes(a_pub, params.byte_len),
        &to_bytes(b_pub, params.byte_len),
        session_key,
    ])
}

/// `M2 = H( PAD(A) | M1 | K )`.
fn compute_m2(a_pub: &BigUint, m1: &[u8; 32], session_key: &[u8; 32], byte_len: usize) -> [u8; 32] {
    hash_parts(&[&to_bytes(a_pub, byte_len), m1, session_key])
}

// ---------------------------------------------------------------------------
// Sealed session state
// ---------------------------------------------------------------------------

/// What the server carries between the two messages, sealed under
/// AES-256-GCM. Never readable or forgeable by the client.
#[derive(Debug, Serialize, Deserialize)]
struct SealedSession {
    /// Format version, so the sealed layout can change without a flag day.
    v: u8,
    tenant_id: Uuid,
    org_id: Uuid,
    /// `None` for a simulated (unknown-identity) exchange.
    user_id: Option<Uuid>,
    /// The identity the client was told to use. Echoed into audit records.
    identity: String,
    /// Hex `M1` the client must produce.
    expected_client_proof: String,
    /// Hex `M2` to return once `M1` matches.
    server_proof: String,
    expires_at: DateTime<Utc>,
}

/// Outcome of opening and checking a `srp_session` + `M1` pair.
#[derive(Debug, Clone)]
pub struct SrpVerified {
    /// Tenant the exchange was scoped to.
    pub tenant_id: Uuid,
    /// Organization the exchange was scoped to.
    pub org_id: Uuid,
    /// The authenticated user.
    pub user_id: Uuid,
    /// Canonical identity used in the exchange.
    pub identity: String,
    /// Hex `M2`, the server's proof to return so the client can authenticate
    /// *the server*. Withholding it would drop half of SRP's mutual
    /// authentication and leave clients unable to detect a rogue endpoint.
    pub server_proof: String,
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// SRP-6a server operations, parameterised by the key that seals session
/// state.
///
/// The key is a dedicated 256-bit secret (`AXIAM__AUTH__SRP_SESSION_KEY`),
/// deliberately not shared with TOTP or federation encryption: those keys have
/// different rotation cadences, and reusing one would couple an SRP outage to
/// an unrelated key rotation.
#[derive(Clone)]
pub struct SrpServer {
    session_key: [u8; 32],
}

impl std::fmt::Debug for SrpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the key, not even as a length.
        f.debug_struct("SrpServer").finish_non_exhaustive()
    }
}

impl SrpServer {
    /// Build a server bound to `session_key`.
    pub fn new(session_key: [u8; 32]) -> Self {
        Self { session_key }
    }

    /// Produce the challenge for a *known* user.
    ///
    /// `a_pub_hex` is the client's `A`. Returns the wire challenge; the sealed
    /// session inside it is what [`Self::verify`] consumes.
    pub fn challenge(
        &self,
        credential: &SrpCredential,
        org_id: Uuid,
        a_pub_hex: &str,
    ) -> Result<SrpChallenge, AuthError> {
        let params = group_params(credential.group);
        let a_pub = parse_public_value(a_pub_hex, params)?;

        let verifier = BigUint::parse_bytes(credential.verifier.as_bytes(), 16)
            .ok_or_else(|| AuthError::Crypto("stored SRP verifier is not valid hex".into()))?;
        let salt = hex::decode(&credential.salt)
            .map_err(|_| AuthError::Crypto("stored SRP salt is not valid hex".into()))?;

        self.build_challenge(
            params,
            credential.group,
            credential.kdf_params,
            &credential.identity,
            &salt,
            &verifier,
            &a_pub,
            credential.tenant_id,
            org_id,
            Some(credential.user_id),
        )
    }

    /// Produce a challenge indistinguishable from a real one for an identity
    /// that has no verifier — an unknown user, or a known user who has never
    /// enrolled.
    ///
    /// The salt is `HMAC(session_key, "srp-fake-salt" | tenant_id | identity)`
    /// so that it is **stable**: an attacker who probes the same name twice
    /// and sees two different salts learns immediately that the account does
    /// not exist, which is precisely the leak this branch exists to close.
    #[allow(clippy::too_many_arguments)]
    pub fn simulated_challenge(
        &self,
        group: SrpGroup,
        kdf_params: SrpKdfParams,
        identity: &str,
        tenant_id: Uuid,
        org_id: Uuid,
        a_pub_hex: &str,
    ) -> Result<SrpChallenge, AuthError> {
        let params = group_params(group);
        let a_pub = parse_public_value(a_pub_hex, params)?;

        let salt = self.stable_fake_salt(tenant_id, identity);
        // A dummy verifier derived the same deterministic way, so the
        // exponentiation below costs exactly what a real one costs.
        let dummy = BigUint::from_bytes_be(&self.derive(b"srp-fake-verifier", tenant_id, identity))
            % &params.n;
        let verifier = if dummy.is_zero() {
            BigUint::from(2u32)
        } else {
            dummy
        };

        self.build_challenge(
            params, group, kdf_params, identity, &salt, &verifier, &a_pub, tenant_id, org_id, None,
        )
    }

    /// Open a `srp_session` and check the client's `M1`.
    ///
    /// Returns `InvalidCredentials` for every failure mode — expired session,
    /// tampered blob, wrong proof, simulated exchange — so that none of them
    /// is distinguishable from the others by a caller.
    pub fn verify(
        &self,
        srp_session: &str,
        client_proof_hex: &str,
    ) -> Result<SrpVerified, AuthError> {
        let sealed = URL_SAFE_NO_PAD
            .decode(srp_session)
            .map_err(|_| AuthError::InvalidCredentials)?;
        let plaintext = aes256gcm_decrypt(
            &self.session_key,
            &base64::engine::general_purpose::STANDARD.encode(&sealed),
        )
        .map_err(|_| AuthError::InvalidCredentials)?;
        let session: SealedSession =
            serde_json::from_slice(&plaintext).map_err(|_| AuthError::InvalidCredentials)?;

        if session.v != 1 {
            return Err(AuthError::InvalidCredentials);
        }
        if Utc::now() > session.expires_at {
            return Err(AuthError::InvalidCredentials);
        }

        // Constant-time over the raw bytes, not the hex text: comparing hex
        // strings would leak through length and through early-exit on the
        // first differing nibble.
        let expected = hex::decode(&session.expected_client_proof)
            .map_err(|_| AuthError::InvalidCredentials)?;
        let supplied = hex::decode(client_proof_hex).map_err(|_| AuthError::InvalidCredentials)?;
        if expected.len() != supplied.len() {
            return Err(AuthError::InvalidCredentials);
        }
        if !bool::from(expected.ct_eq(&supplied)) {
            return Err(AuthError::InvalidCredentials);
        }

        // A simulated exchange can, with negligible probability, be "passed"
        // only by someone who guessed a 256-bit value; it still must not
        // authenticate anybody, because there is nobody to authenticate.
        let user_id = session.user_id.ok_or(AuthError::InvalidCredentials)?;

        Ok(SrpVerified {
            tenant_id: session.tenant_id,
            org_id: session.org_id,
            user_id,
            identity: session.identity,
            server_proof: session.server_proof,
        })
    }

    // -- internals ------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn build_challenge(
        &self,
        params: &GroupParams,
        group: SrpGroup,
        kdf_params: SrpKdfParams,
        identity: &str,
        salt: &[u8],
        verifier: &BigUint,
        a_pub: &BigUint,
        tenant_id: Uuid,
        org_id: Uuid,
        user_id: Option<Uuid>,
    ) -> Result<SrpChallenge, AuthError> {
        // b <- random, B = (k*v + g^b) mod N
        let b_priv = random_ephemeral();
        let b_pub = (&params.k * verifier + params.g.modpow(&b_priv, &params.n)) % &params.n;
        if b_pub.is_zero() {
            // B ≡ 0 (mod N) would let any client authenticate. Astronomically
            // improbable, but the cost of handling it is one branch.
            return Err(AuthError::Crypto("SRP server ephemeral was zero".into()));
        }

        let u = compute_u(a_pub, &b_pub, params.byte_len);
        if u.is_zero() {
            return Err(AuthError::Crypto(
                "SRP scrambling parameter was zero".into(),
            ));
        }

        // S = (A * v^u)^b mod N
        let s = ((a_pub * verifier.modpow(&u, &params.n)) % &params.n).modpow(&b_priv, &params.n);
        let session_key = hash_parts(&[&to_bytes(&s, params.byte_len)]);

        let m1 = compute_m1(params, identity, salt, a_pub, &b_pub, &session_key);
        let m2 = compute_m2(a_pub, &m1, &session_key, params.byte_len);

        let sealed = SealedSession {
            v: 1,
            tenant_id,
            org_id,
            user_id,
            identity: identity.to_string(),
            expected_client_proof: hex::encode(m1),
            server_proof: hex::encode(m2),
            expires_at: Utc::now() + Duration::seconds(SESSION_LIFETIME_SECS),
        };
        let plaintext =
            serde_json::to_vec(&sealed).map_err(|e| AuthError::Crypto(format!("seal: {e}")))?;
        let standard_b64 = aes256gcm_encrypt(&self.session_key, &plaintext)?;
        // Re-encode as URL-safe so the token survives being put in a header,
        // a query string, or a JSON body without escaping.
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&standard_b64)
            .map_err(|e| AuthError::Crypto(format!("seal re-encode: {e}")))?;

        let (memory_kib, iterations, parallelism) = match kdf_params {
            SrpKdfParams::Argon2id {
                memory_kib,
                iterations,
                parallelism,
            } => (Some(memory_kib), iterations, Some(parallelism)),
            SrpKdfParams::Pbkdf2Sha256 { iterations } => (None, iterations, None),
        };

        Ok(SrpChallenge {
            srp_session: URL_SAFE_NO_PAD.encode(raw),
            identity: identity.to_string(),
            salt: hex::encode(salt),
            group: group.to_string(),
            kdf: kdf_params.kdf().to_string(),
            memory_kib,
            iterations,
            parallelism,
            b_pub: hex::encode(to_bytes(&b_pub, params.byte_len)),
        })
    }

    /// Domain-separated HMAC over the server key — the one place fake material
    /// is derived from, so that it is deterministic per (tenant, identity).
    fn derive(&self, domain: &[u8], tenant_id: Uuid, identity: &str) -> [u8; 32] {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&self.session_key)
            .expect("HMAC accepts a 32-byte key");
        mac.update(domain);
        mac.update(tenant_id.as_bytes());
        mac.update(identity.as_bytes());
        mac.finalize().into_bytes().into()
    }

    fn stable_fake_salt(&self, tenant_id: Uuid, identity: &str) -> Vec<u8> {
        self.derive(b"srp-fake-salt", tenant_id, identity).to_vec()
    }
}

/// Parse and validate a client public value `A`.
///
/// `A ≡ 0 (mod N)` must be rejected: it forces `S = 0` on the server for any
/// `b`, so an attacker who sends it can compute `K` — and therefore `M1` —
/// with no knowledge of the password at all. This is *the* classic SRP
/// implementation break.
fn parse_public_value(hex_value: &str, params: &GroupParams) -> Result<BigUint, AuthError> {
    if hex_value.is_empty()
        || hex_value.len() > params.byte_len * 2
        || !hex_value.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(AuthError::InvalidCredentials);
    }
    let value =
        BigUint::parse_bytes(hex_value.as_bytes(), 16).ok_or(AuthError::InvalidCredentials)?;
    if (&value % &params.n).is_zero() {
        return Err(AuthError::InvalidCredentials);
    }
    Ok(value)
}

fn random_ephemeral() -> BigUint {
    let mut rng = rand::rng();
    let mut bytes = [0u8; EPHEMERAL_BITS / 8];
    rng.fill_bytes(&mut bytes);
    // Force the top bit so `b` is always full-width; a short `b` is not a
    // security problem at 256 bits but makes test vectors non-uniform.
    bytes[0] |= 0x80;
    BigUint::from_bytes_be(&bytes)
}

// ---------------------------------------------------------------------------
// Reference client — test-only
// ---------------------------------------------------------------------------

/// A minimal SRP-6a **client**, used by this crate's tests and by the
/// integration tests in `axiam-api-rest`.
///
/// It is deliberately compiled into the library rather than living in a test
/// module: the eleven SDKs each implement this same computation, and this is
/// the executable definition they are checked against. It performs no KDF —
/// callers pass `x` directly — because the KDF is the one part that differs by
/// language and is specified in `sdks/CONTRACT.md` rather than here.
pub mod reference_client {
    use super::*;

    /// The client's ephemeral state between the two messages.
    pub struct ClientSession {
        /// Client public value `A`, lowercase hex.
        pub a_pub_hex: String,
        a_priv: BigUint,
        group: SrpGroup,
    }

    /// Start an exchange: pick `a`, compute `A = g^a mod N`.
    pub fn begin(group: SrpGroup) -> ClientSession {
        let params = group_params(group);
        let a_priv = random_ephemeral();
        let a_pub = params.g.modpow(&a_priv, &params.n);
        ClientSession {
            a_pub_hex: hex::encode(to_bytes(&a_pub, params.byte_len)),
            a_priv,
            group,
        }
    }

    /// Compute the verifier `v = g^x mod N` for enrolment.
    pub fn verifier_hex(group: SrpGroup, x: &[u8]) -> String {
        let params = group_params(group);
        let x = BigUint::from_bytes_be(x) % &params.n;
        hex::encode(to_bytes(&params.g.modpow(&x, &params.n), params.byte_len))
    }

    impl ClientSession {
        /// Finish the exchange from the server's challenge, returning
        /// `(M1_hex, expected_M2_hex)`.
        ///
        /// `S = (B - k*g^x)^(a + u*x) mod N`. The subtraction is done modulo
        /// `N` with an added `N` first, because `k*g^x` can exceed `B` and
        /// `BigUint` has no negative values.
        pub fn finish(
            &self,
            identity: &str,
            salt_hex: &str,
            b_pub_hex: &str,
            x: &[u8],
        ) -> Result<(String, String), AuthError> {
            let params = group_params(self.group);
            let b_pub = BigUint::parse_bytes(b_pub_hex.as_bytes(), 16)
                .ok_or(AuthError::InvalidCredentials)?;
            if (&b_pub % &params.n).is_zero() {
                // B ≡ 0 means the server is broken or hostile.
                return Err(AuthError::InvalidCredentials);
            }
            let salt = hex::decode(salt_hex).map_err(|_| AuthError::InvalidCredentials)?;
            let x = BigUint::from_bytes_be(x) % &params.n;

            let u = compute_u(
                &BigUint::parse_bytes(self.a_pub_hex.as_bytes(), 16)
                    .ok_or(AuthError::InvalidCredentials)?,
                &b_pub,
                params.byte_len,
            );

            let kgx = (&params.k * params.g.modpow(&x, &params.n)) % &params.n;
            let base = ((&b_pub % &params.n) + &params.n - kgx) % &params.n;
            let exp = &self.a_priv + &u * &x;
            let s = base.modpow(&exp, &params.n);
            let session_key = hash_parts(&[&to_bytes(&s, params.byte_len)]);

            let a_pub = BigUint::parse_bytes(self.a_pub_hex.as_bytes(), 16)
                .ok_or(AuthError::InvalidCredentials)?;
            let m1 = compute_m1(params, identity, &salt, &a_pub, &b_pub, &session_key);
            let m2 = compute_m2(&a_pub, &m1, &session_key, params.byte_len);
            Ok((hex::encode(m1), hex::encode(m2)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::reference_client;
    use super::*;
    use axiam_core::models::srp::{SrpKdf, SrpKdfParams};

    fn key() -> [u8; 32] {
        [7u8; 32]
    }

    fn credential(group: SrpGroup, identity: &str, x: &[u8]) -> SrpCredential {
        SrpCredential {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            identity: identity.to_string(),
            group,
            kdf_params: SrpKdfParams::defaults_for(SrpKdf::Argon2id),
            salt: hex::encode([0xABu8; 32]),
            verifier: reference_client::verifier_hex(group, x),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // --- group constants -------------------------------------------------

    /// Miller-Rabin, deterministic enough at 40 rounds for a test.
    fn is_probable_prime(n: &BigUint) -> bool {
        use num_traits::One;
        let one = BigUint::one();
        let two = BigUint::from(2u32);
        if *n < two {
            return false;
        }
        let n_minus_1 = n - &one;
        let mut d = n_minus_1.clone();
        let mut r = 0u32;
        while (&d % &two).is_zero() {
            d /= &two;
            r += 1;
        }
        // Fixed small bases: for numbers this size a fixed base set is a
        // strong probabilistic check and keeps the test deterministic.
        for base in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
            let a = BigUint::from(base);
            let mut x = a.modpow(&d, n);
            if x == one || x == n_minus_1 {
                continue;
            }
            let mut passed = false;
            for _ in 0..r - 1 {
                x = x.modpow(&two, n);
                if x == n_minus_1 {
                    passed = true;
                    break;
                }
            }
            if !passed {
                return false;
            }
        }
        true
    }

    #[test]
    fn every_group_modulus_is_a_safe_prime_of_the_advertised_width() {
        // A transcription slip in these constants is a total, silent break:
        // client and server would still agree with each other while the
        // discrete-log hardness the whole protocol rests on quietly vanished.
        for group in [
            SrpGroup::Rfc5054_2048,
            SrpGroup::Rfc5054_3072,
            SrpGroup::Rfc5054_4096,
        ] {
            let params = group_params(group);
            assert_eq!(
                params.n.bits() as u32,
                group.bits(),
                "{group} modulus is the wrong width"
            );
            assert_eq!(params.byte_len, group.byte_len());
            assert!(is_probable_prime(&params.n), "{group} modulus is not prime");
            let q = (&params.n - BigUint::from(1u32)) / BigUint::from(2u32);
            assert!(is_probable_prime(&q), "{group} modulus is not a safe prime");
            // g generates the order-q subgroup iff g^q == N-1 for a safe prime.
            assert_eq!(
                params.g.modpow(&q, &params.n),
                &params.n - BigUint::from(1u32),
                "{group} generator does not generate the large subgroup"
            );
        }
    }

    // --- padding ---------------------------------------------------------

    #[test]
    fn pad_left_pads_to_the_group_width() {
        let small = BigUint::from(1u32);
        assert_eq!(to_bytes(&small, 4), vec![0, 0, 0, 1]);
        // Already wide enough: unchanged.
        assert_eq!(to_bytes(&BigUint::from(0x0102u32), 2), vec![1, 2]);
    }

    // --- happy path ------------------------------------------------------

    #[test]
    fn a_correct_password_completes_the_exchange_in_every_group() {
        for group in [
            SrpGroup::Rfc5054_2048,
            SrpGroup::Rfc5054_3072,
            SrpGroup::Rfc5054_4096,
        ] {
            let server = SrpServer::new(key());
            let x = [0x11u8; 32];
            let cred = credential(group, "alice", &x);
            let org_id = Uuid::new_v4();

            let client = reference_client::begin(group);
            let challenge = server
                .challenge(&cred, org_id, &client.a_pub_hex)
                .expect("challenge");

            assert_eq!(challenge.identity, "alice");
            assert_eq!(challenge.salt, cred.salt);
            assert_eq!(challenge.group, group.to_string());

            let (m1, expected_m2) = client
                .finish("alice", &challenge.salt, &challenge.b_pub, &x)
                .expect("client finish");

            let verified = server.verify(&challenge.srp_session, &m1).expect("verify");
            assert_eq!(verified.user_id, cred.user_id);
            assert_eq!(verified.tenant_id, cred.tenant_id);
            assert_eq!(verified.org_id, org_id);
            // Mutual auth: the client can check the server too.
            assert_eq!(verified.server_proof, expected_m2);
        }
    }

    #[test]
    fn b_pub_is_padded_to_the_full_group_width() {
        // Interop depends on this: an unpadded B would hash differently on a
        // client that pads, and would fail roughly one login in 256.
        let server = SrpServer::new(key());
        let cred = credential(SrpGroup::Rfc5054_2048, "alice", &[0x11u8; 32]);
        let client = reference_client::begin(SrpGroup::Rfc5054_2048);
        let challenge = server
            .challenge(&cred, Uuid::new_v4(), &client.a_pub_hex)
            .unwrap();
        assert_eq!(challenge.b_pub.len(), 256 * 2);
    }

    // --- failure modes ---------------------------------------------------

    #[test]
    fn a_wrong_password_is_rejected() {
        let server = SrpServer::new(key());
        let cred = credential(SrpGroup::Rfc5054_2048, "alice", &[0x11u8; 32]);
        let client = reference_client::begin(SrpGroup::Rfc5054_2048);
        let challenge = server
            .challenge(&cred, Uuid::new_v4(), &client.a_pub_hex)
            .unwrap();

        let (m1, _) = client
            .finish("alice", &challenge.salt, &challenge.b_pub, &[0x22u8; 32])
            .unwrap();
        assert!(matches!(
            server.verify(&challenge.srp_session, &m1),
            Err(AuthError::InvalidCredentials)
        ));
    }

    #[test]
    fn a_client_public_value_congruent_to_zero_is_refused() {
        // THE classic SRP break: A ≡ 0 (mod N) forces S = 0 server-side, so
        // an attacker could derive K and forge M1 with no password at all.
        let server = SrpServer::new(key());
        let cred = credential(SrpGroup::Rfc5054_2048, "alice", &[0x11u8; 32]);
        let params = group_params(SrpGroup::Rfc5054_2048);

        for a in [
            "00",
            &"0".repeat(512),
            &hex::encode(to_bytes(&params.n, 256)),
        ] {
            assert!(
                matches!(
                    server.challenge(&cred, Uuid::new_v4(), a),
                    Err(AuthError::InvalidCredentials)
                ),
                "A={a} should be refused"
            );
        }
        // 2N is also ≡ 0.
        let two_n = &params.n * BigUint::from(2u32);
        assert!(matches!(
            server.challenge(&cred, Uuid::new_v4(), &hex::encode(two_n.to_bytes_be())),
            Err(AuthError::InvalidCredentials)
        ));
    }

    #[test]
    fn a_malformed_client_public_value_is_refused() {
        let server = SrpServer::new(key());
        let cred = credential(SrpGroup::Rfc5054_2048, "alice", &[0x11u8; 32]);
        for a in ["", "zz", &"a".repeat(600)] {
            assert!(matches!(
                server.challenge(&cred, Uuid::new_v4(), a),
                Err(AuthError::InvalidCredentials)
            ));
        }
    }

    #[test]
    fn a_tampered_session_blob_is_refused() {
        let server = SrpServer::new(key());
        let cred = credential(SrpGroup::Rfc5054_2048, "alice", &[0x11u8; 32]);
        let client = reference_client::begin(SrpGroup::Rfc5054_2048);
        let challenge = server
            .challenge(&cred, Uuid::new_v4(), &client.a_pub_hex)
            .unwrap();
        let (m1, _) = client
            .finish("alice", &challenge.salt, &challenge.b_pub, &[0x11u8; 32])
            .unwrap();

        let mut tampered = challenge.srp_session.clone();
        // Flip one character in the AEAD ciphertext.
        let idx = tampered.len() / 2;
        let replacement = if tampered.as_bytes()[idx] == b'A' {
            'B'
        } else {
            'A'
        };
        tampered.replace_range(idx..idx + 1, &replacement.to_string());

        assert!(matches!(
            server.verify(&tampered, &m1),
            Err(AuthError::InvalidCredentials)
        ));
        assert!(matches!(
            server.verify("not-base64-$$$", &m1),
            Err(AuthError::InvalidCredentials)
        ));
    }

    #[test]
    fn a_session_sealed_by_a_different_key_is_refused() {
        let server_a = SrpServer::new([1u8; 32]);
        let server_b = SrpServer::new([2u8; 32]);
        let cred = credential(SrpGroup::Rfc5054_2048, "alice", &[0x11u8; 32]);
        let client = reference_client::begin(SrpGroup::Rfc5054_2048);
        let challenge = server_a
            .challenge(&cred, Uuid::new_v4(), &client.a_pub_hex)
            .unwrap();
        let (m1, _) = client
            .finish("alice", &challenge.salt, &challenge.b_pub, &[0x11u8; 32])
            .unwrap();

        assert!(matches!(
            server_b.verify(&challenge.srp_session, &m1),
            Err(AuthError::InvalidCredentials)
        ));
    }

    #[test]
    fn a_proof_of_the_wrong_length_is_refused_without_panicking() {
        let server = SrpServer::new(key());
        let cred = credential(SrpGroup::Rfc5054_2048, "alice", &[0x11u8; 32]);
        let client = reference_client::begin(SrpGroup::Rfc5054_2048);
        let challenge = server
            .challenge(&cred, Uuid::new_v4(), &client.a_pub_hex)
            .unwrap();

        for proof in ["", "ab", &"f".repeat(128), "zzzz"] {
            assert!(matches!(
                server.verify(&challenge.srp_session, proof),
                Err(AuthError::InvalidCredentials)
            ));
        }
    }

    // --- enumeration resistance -----------------------------------------

    #[test]
    fn a_simulated_challenge_is_shaped_exactly_like_a_real_one() {
        let server = SrpServer::new(key());
        let tenant_id = Uuid::new_v4();
        let group = SrpGroup::Rfc5054_2048;
        let client = reference_client::begin(group);

        let real = server
            .challenge(
                &credential(group, "alice", &[0x11u8; 32]),
                Uuid::new_v4(),
                &client.a_pub_hex,
            )
            .unwrap();
        let fake = server
            .simulated_challenge(
                group,
                SrpKdfParams::defaults_for(SrpKdf::Argon2id),
                "ghost",
                tenant_id,
                Uuid::new_v4(),
                &client.a_pub_hex,
            )
            .unwrap();

        assert_eq!(real.salt.len(), fake.salt.len());
        assert_eq!(real.b_pub.len(), fake.b_pub.len());
        assert_eq!(real.group, fake.group);
        assert_eq!(real.kdf, fake.kdf);
        assert_eq!(real.iterations, fake.iterations);
    }

    #[test]
    fn a_simulated_salt_is_stable_across_attempts() {
        // Two probes of the same unknown name must return the same salt; a
        // fresh random salt each time would announce "this account does not
        // exist" as loudly as a 404.
        let server = SrpServer::new(key());
        let tenant_id = Uuid::new_v4();
        let client = reference_client::begin(SrpGroup::Rfc5054_2048);

        let first = server
            .simulated_challenge(
                SrpGroup::Rfc5054_2048,
                SrpKdfParams::defaults_for(SrpKdf::Argon2id),
                "ghost",
                tenant_id,
                Uuid::new_v4(),
                &client.a_pub_hex,
            )
            .unwrap();
        let second = server
            .simulated_challenge(
                SrpGroup::Rfc5054_2048,
                SrpKdfParams::defaults_for(SrpKdf::Argon2id),
                "ghost",
                tenant_id,
                Uuid::new_v4(),
                &client.a_pub_hex,
            )
            .unwrap();
        assert_eq!(first.salt, second.salt);

        // ...but different per tenant and per identity, so one tenant cannot
        // fingerprint another's user list.
        let other_identity = server
            .simulated_challenge(
                SrpGroup::Rfc5054_2048,
                SrpKdfParams::defaults_for(SrpKdf::Argon2id),
                "phantom",
                tenant_id,
                Uuid::new_v4(),
                &client.a_pub_hex,
            )
            .unwrap();
        assert_ne!(first.salt, other_identity.salt);

        let other_tenant = server
            .simulated_challenge(
                SrpGroup::Rfc5054_2048,
                SrpKdfParams::defaults_for(SrpKdf::Argon2id),
                "ghost",
                Uuid::new_v4(),
                Uuid::new_v4(),
                &client.a_pub_hex,
            )
            .unwrap();
        assert_ne!(first.salt, other_tenant.salt);
    }

    #[test]
    fn a_simulated_exchange_can_never_authenticate_anyone() {
        let server = SrpServer::new(key());
        let client = reference_client::begin(SrpGroup::Rfc5054_2048);
        let challenge = server
            .simulated_challenge(
                SrpGroup::Rfc5054_2048,
                SrpKdfParams::defaults_for(SrpKdf::Argon2id),
                "ghost",
                Uuid::new_v4(),
                Uuid::new_v4(),
                &client.a_pub_hex,
            )
            .unwrap();

        // Even handed the correct M1 — which requires the fabricated verifier,
        // i.e. the server key — there is no user to return.
        let sealed = URL_SAFE_NO_PAD.decode(&challenge.srp_session).unwrap();
        let plaintext = aes256gcm_decrypt(
            &key(),
            &base64::engine::general_purpose::STANDARD.encode(&sealed),
        )
        .unwrap();
        let session: SealedSession = serde_json::from_slice(&plaintext).unwrap();
        assert!(session.user_id.is_none());

        assert!(matches!(
            server.verify(&challenge.srp_session, &session.expected_client_proof),
            Err(AuthError::InvalidCredentials)
        ));
    }

    // --- identity binding ------------------------------------------------

    #[test]
    fn a_verifier_is_bound_to_the_identity_it_was_enrolled_for() {
        // x is derived over `I ":" p` client-side, so a client that uses the
        // wrong identity string derives a different M1 and is rejected. This
        // is why the challenge response carries the canonical identity.
        let server = SrpServer::new(key());
        let x = [0x11u8; 32];
        let cred = credential(SrpGroup::Rfc5054_2048, "alice", &x);
        let client = reference_client::begin(SrpGroup::Rfc5054_2048);
        let challenge = server
            .challenge(&cred, Uuid::new_v4(), &client.a_pub_hex)
            .unwrap();

        let (m1, _) = client
            .finish("bob", &challenge.salt, &challenge.b_pub, &x)
            .unwrap();
        assert!(matches!(
            server.verify(&challenge.srp_session, &m1),
            Err(AuthError::InvalidCredentials)
        ));
    }

    #[test]
    fn two_exchanges_for_the_same_user_produce_different_sessions() {
        let server = SrpServer::new(key());
        let x = [0x11u8; 32];
        let cred = credential(SrpGroup::Rfc5054_2048, "alice", &x);

        let c1 = reference_client::begin(SrpGroup::Rfc5054_2048);
        let c2 = reference_client::begin(SrpGroup::Rfc5054_2048);
        let ch1 = server
            .challenge(&cred, Uuid::new_v4(), &c1.a_pub_hex)
            .unwrap();
        let ch2 = server
            .challenge(&cred, Uuid::new_v4(), &c2.a_pub_hex)
            .unwrap();

        assert_ne!(ch1.b_pub, ch2.b_pub, "B must be fresh per exchange");
        assert_ne!(ch1.srp_session, ch2.srp_session);

        // A proof from one exchange must not open the other.
        let (m1_for_1, _) = c1.finish("alice", &ch1.salt, &ch1.b_pub, &x).unwrap();
        assert!(matches!(
            server.verify(&ch2.srp_session, &m1_for_1),
            Err(AuthError::InvalidCredentials)
        ));
    }

    #[test]
    fn the_server_never_renders_its_session_key() {
        let server = SrpServer::new([0xAB; 32]);
        let rendered = format!("{server:?}");
        assert!(
            !rendered.contains("ab"),
            "Debug leaked key bytes: {rendered}"
        );
        assert!(!rendered.contains("171"));
    }
}
