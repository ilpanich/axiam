//! PKI configuration types.

/// PKI configuration — holds the AES-256-GCM key for encrypting CA private keys,
/// plus the FIDO MDS3 ingestion settings (D10, X3).
///
/// `encryption_key` is `Option` — absent means the operator has not configured
/// the key yet. Operations that encrypt private key material (CA generation,
/// PGP AuditSigning key generation) will return an error rather than silently
/// encrypting with a known-zero key (SEC-012).
///
/// MDS ingestion is opt-in and makes **no** outbound network calls unless
/// `mds_enabled` is explicitly set (D10): the master switch defaults to
/// `false`, so upgrading to a build that includes this feature changes no
/// deployment's runtime behavior until an operator turns it on.
#[derive(Clone)]
pub struct PkiConfig {
    pub encryption_key: Option<[u8; 32]>,

    // -----------------------------------------------------------------
    // FIDO MDS3 ingestion (D10)
    // -----------------------------------------------------------------
    /// Master switch. `false` (the default) means zero outbound calls —
    /// no background refresh job is spawned and the admin-triggered refresh
    /// endpoint refuses to run. Env: `AXIAM__PKI__MDS_ENABLED`.
    pub mds_enabled: bool,
    /// FIDO MDS3 BLOB fetch source. Env: `AXIAM__PKI__MDS_BLOB_URL`.
    pub mds_blob_url: String,
    /// Local BLOB file path for air-gapped deployments. When set, it wins
    /// over `mds_blob_url` and no network fetch happens at all.
    /// Env: `AXIAM__PKI__MDS_BLOB_PATH`.
    pub mds_blob_path: Option<std::path::PathBuf>,
    /// Background refresh interval, in seconds. `0` disables the background
    /// job (the admin-triggered endpoint still works). Default: 604800
    /// (weekly). Env: `AXIAM__PKI__MDS_REFRESH_INTERVAL_SECS`.
    pub mds_refresh_interval_secs: u64,
    /// Expected DNS SAN (or CN fallback) on the MDS BLOB's leaf signing
    /// certificate (D4 step 5) — configurable so a legitimate FIDO hostname
    /// change is an ops action, not a code release.
    /// Env: `AXIAM__PKI__MDS_LEAF_DNS`.
    pub mds_leaf_dns: String,
    /// T-153: refuse attested registration once the ingested MDS BLOB is more
    /// than this many days past its `nextUpdate`. `0` (the default) disables
    /// the check and keeps the fail-open behaviour described below.
    /// Env: `AXIAM__PKI__MDS_MAX_STALE_DAYS`.
    ///
    /// Staleness deliberately never hard-fails *ingestion*: a transient outage
    /// at the FIDO Alliance must not brick WebAuthn registration for everyone.
    /// The cost of that choice is T-153 — an authenticator model revoked since
    /// the last successful refresh keeps passing attestation policy, because
    /// the revocation is in a BLOB this deployment has not seen.
    ///
    /// This knob lets an operator put a bound on that window, and it is opt-in
    /// rather than defaulted to a value because the right bound is a property
    /// of the deployment: a high-assurance tenant may want days, an air-gapped
    /// one (`mds_blob_path`, no automatic refresh path at all) would be taken
    /// offline by anything short of months.
    ///
    /// Scope is attestation only. An unattested ceremony under
    /// `AttestationMode::None` consults no metadata, so stale metadata cannot
    /// have misled it and refusing it would deny a registration for a reason
    /// that does not apply to it.
    pub mds_max_stale_days: u32,
}

/// Default FIDO MDS3 BLOB fetch source (D10).
pub const DEFAULT_MDS_BLOB_URL: &str = "https://mds3.fidoalliance.org/";

/// Default background MDS refresh interval: weekly (D10).
pub const DEFAULT_MDS_REFRESH_INTERVAL_SECS: u64 = 604_800;

/// Default expected leaf DNS name on the MDS BLOB signing certificate (D4/D10).
pub const DEFAULT_MDS_LEAF_DNS: &str = "mds.fidoalliance.org";

impl Default for PkiConfig {
    /// Matches today's behavior byte-for-byte: no encryption key configured,
    /// and MDS ingestion fully disabled (no outbound calls).
    fn default() -> Self {
        Self {
            encryption_key: None,
            mds_enabled: false,
            mds_blob_url: DEFAULT_MDS_BLOB_URL.to_string(),
            mds_blob_path: None,
            mds_refresh_interval_secs: DEFAULT_MDS_REFRESH_INTERVAL_SECS,
            mds_leaf_dns: DEFAULT_MDS_LEAF_DNS.to_string(),
            mds_max_stale_days: 0,
        }
    }
}
