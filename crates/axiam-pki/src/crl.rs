//! Certificate revocation lists — one per issuing CA (RFC 5280 §5; #565,
//! T-102).
//!
//! Revoking a certificate sets the status on its row. Until this module that
//! status reached exactly the places that read the row — device sign-in, and
//! since the same change OAuth2 `tls_client_auth` — and nowhere else: a
//! relying party that validates AXIAM-issued certificates itself, a FreeRADIUS
//! server doing EAP-TLS or a VPN gateway, had no channel through which to learn
//! of a revocation, although every AXIAM CA carries the `cRLSign` bit.
//!
//! # What is published
//!
//! A complete, version 2 CRL per issuing CA, DER-encoded, at
//! `GET /pki/v1/{org_id}/ca/{ca_id}/crl` ([`crl_path`]), unauthenticated:
//!
//! - **signed with the CA's own key, fetched from the CA's own custodian** —
//!   the custodian the CA row names, through the same `load` the leaf path
//!   uses, so an RSA-4096 CA and an Ed25519 CA sign their lists exactly as they
//!   sign certificates;
//! - `thisUpdate` the start of the refresh epoch it was signed in, or the
//!   newest revocation on it if later (#608, below); `nextUpdate` a
//!   configurable interval later ([`DEFAULT_CRL_NEXT_UPDATE_SECS`]) and never
//!   past the CA's own `notAfter`;
//! - a CRL number and an authority key identifier equal to the CA's subject key
//!   identifier — the two extensions RFC 5280 §5.2 requires of every CRL;
//! - an entry for every certificate the CA signed and revoked that has not
//!   expired, or expired during the previous refresh epoch or this one (so it
//!   appears on a list issued after its expiry, as RFC 5280 §3.3 asks): its
//!   leaves in every tenant, and the subordinate CAs it signed, so
//!   an organization CA's list names a revoked tenant signing CA. Each entry
//!   carries the serial read out of the certificate and the date AXIAM recorded
//!   the revocation. No reason code: AXIAM does not record one, and RFC 5280
//!   §5.3.1 prefers an absent reason to `unspecified`.
//!
//! # Which CAs publish one
//!
//! A CA AXIAM can sign with, while it is active and in date. Three kinds
//! answer `404` instead, the same `404` as a CA that does not exist:
//!
//! - **a revoked or expired CA.** AXIAM signs nothing with one; its own status
//!   is on its parent's list;
//! - **an imported trust anchor with no key** (`external` custody): it cannot
//!   sign anything, a list included;
//! - **a CA whose key Vault's PKI engine holds** (`vault_pki`). Vault signs on
//!   AXIAM's behalf only certificate requests; it has no operation that signs a
//!   list AXIAM composed, and AXIAM never holds the key. Vault publishes that
//!   CA's list itself, and AXIAM revokes each leaf there too
//!   ([`crate::CertService::revoke`], T-470), so Vault's list names it. Leaves of
//!   such a CA carry no AXIAM distribution point — Vault issues them with its
//!   own profile, naming whatever the operator configured on the mount
//!   (`config/urls`) — so nothing points at a route that cannot answer, and
//!   relying parties read Vault's list (`/v1/<mount>/issuer/<issuer>/crl/der`).
//!
//! # Signing on request, and the cache in front of it
//!
//! A list is signed when it is first asked for and kept, per CA, until either
//! the set of revoked certificates changes or its refresh epoch ends; every
//! request still reads the set, so a revocation is in the next response.
//! Two things follow. A relying party revalidating with `If-None-Match` gets a
//! `304` until the list really changes, because an unchanged list is the same
//! bytes. And a flood of requests costs one database read each and no
//! signature, which matters on an unauthenticated route whose custodian may be
//! a Vault round trip away.
//!
//! That read is light (#607): each revoked certificate's fingerprint and the
//! date its entry states, never the certificate. The PEMs — what an entry's
//! serial is read from — are read only when the list is actually signed.
//!
//! Each CA is re-signed on its own (#607). One flight at a time re-signs a
//! given CA's list, through the custodian `load`, the crypto permit and the
//! signature; requests for the same CA's changed list wait for it, and nothing
//! else does. A cached list is answered without waiting on any re-sign, this
//! CA's or another's. The permit comes from the semaphore issuance and password
//! hashing share, and a flight waits for one at most
//! [`DEFAULT_CRL_PERMIT_WAIT`]; past that it fails with `503`.
//!
//! The flight's outcome is shared (#616). A request that finds one in flight
//! waits for it at most the same permit wait, then answers `503`, and is handed
//! what the flight ended with — its `503` included — instead of starting a
//! re-sign of its own behind it. So callers queued on a saturated gate all
//! answer within about one permit wait, not one wait each in turn, and an
//! unauthenticated caller is never queued without bound. A waiter that read a
//! later state than the flight signed (a revocation committed meanwhile)
//! starts the next flight rather than take a list without it. A flight runs as
//! a task of its own, so a caller hanging up does not abandon it: its list is
//! cached for the next request.
//!
//! # The same list from every replica (#608)
//!
//! Time is cut into **refresh epochs**, half the `nextUpdate` interval long and
//! aligned to the Unix epoch, so every replica cuts at the same instants. What
//! a list says is a function of the revocations in the store and of the epoch
//! alone — `thisUpdate` is the epoch's start or the newest revocation date on
//! the list, whichever is later, but never past the epoch's last second, and
//! the CRL number is that `thisUpdate`, in seconds, above the entry count. Both
//! CA key types sign deterministically (Ed25519, and RSA PKCS#1 v1.5), so two
//! replicas signing the same state in the same epoch produce the same bytes and
//! the same `ETag`, and a relying party behind a load balancer revalidates to
//! `304`s wherever its request lands. A list served at the end of its epoch
//! still has half its interval left.
//!
//! # When the number only grows (#615)
//!
//! RFC 5280 §5.2.3 asks for a CRL number that increases. The derivation gives
//! one — `list_identity` argues each step — on two conditions, and the
//! datastore's clock is not among them:
//!
//! - **The interval is unchanged.** Epochs are cut from it, so another
//!   `AXIAM__PKI__CRL_NEXT_UPDATE_SECS` cuts other epochs: raising it moves the
//!   current epoch's start back, and lowering it ends an expired entry's stay
//!   sooner, while `thisUpdate` may stay put. Either can step the number back
//!   once. A relying party that keeps its list until `nextUpdate` and refuses a
//!   lower number is offered a greater one when it fetches again at
//!   `nextUpdate` as long as the new interval is at most twice every interval
//!   its list may have been signed under: lowering is safe once every replica
//!   runs the new value, and raising goes in steps of at most a doubling, an
//!   old interval apart. The PKI guide (`docs/pki/README.md`) gives the
//!   operator the procedure.
//! - **The replicas' clocks agree within half an epoch.** A replica whose clock
//!   has passed a boundary serves the new epoch's list and one that has not
//!   still serves the old, so a relying party alternating between the two can
//!   see the previous epoch's number again for as long as the clocks disagree —
//!   never an older epoch's, and never at its own `nextUpdate`, by which time
//!   every such replica is past the boundary.
//!
//! A revocation date is written by the datastore's clock, which can be ahead of
//! the signing replica's and so lie past the end of the epoch. `thisUpdate` is
//! clamped to the epoch's last second and every entry's stated date to
//! `thisUpdate`, so no list states a time outside its epoch and the next
//! epoch's list, starting after every second of this one, has a greater number
//! whatever left it (#615). What remains is that `thisUpdate` can be ahead of
//! the replica's clock — and a strict relying party's — by as much as the
//! datastore's clock leads, never past the epoch's end.
//!
//! The route's `Cache-Control: max-age` runs to the end of the epoch — at most
//! half the interval — not to `nextUpdate`, so a shared cache revalidates with
//! the `ETag` at least that often instead of serving a list from before a
//! revocation until `nextUpdate`.
//!
//! # The distribution point
//!
//! [`CrlDistribution`] is the absolute URL of the route, built from the
//! deployment's public base URL. `CertService` and `CaService` write it into
//! every certificate they sign in-process from then on — leaves on both paths,
//! and subordinate CAs — so a relying party that follows distribution points
//! finds the list without being told. With no public base URL there is no
//! absolute URL to write, and the extension is omitted; the composition root
//! says so at boot.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex, PoisonError};

use axiam_core::ca_keys::CaKeyCustody;
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::certificate::{CaCertificate, CertificateStatus, RevokedCertificate};
use axiam_core::repository::{CaCertificateRepository, CertificateRepository};
use chrono::{DateTime, Duration, Utc};
use rcgen::{
    CertificateRevocationListParams, CrlDistributionPoint, Issuer, KeyIdMethod, KeyPair,
    RevokedCertParams, SerialNumber,
};
use sha2::{Digest, Sha256};
use tokio::sync::{Semaphore, watch};
use uuid::Uuid;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::Zeroize;

use crate::ca::CaService;
use crate::ca_key_store::CaKeyCustodians;

/// The media type a DER CRL is served as (RFC 5280 §4.2.1.13).
pub const CRL_MEDIA_TYPE: &str = "application/pkix-crl";

/// Default interval between a list's `thisUpdate` and its `nextUpdate`: one
/// day. Env: `AXIAM__PKI__CRL_NEXT_UPDATE_SECS`.
///
/// It bounds how long a relying party that caches a list honours a certificate
/// revoked after the list was fetched, which is the revocation window this
/// whole module exists to shorten. A day is the common choice for a CA whose
/// relying parties fetch on schedule; a deployment that needs a shorter window
/// sets a shorter interval and pays for it in fetches.
pub const DEFAULT_CRL_NEXT_UPDATE_SECS: u64 = 86_400;

/// Shortest accepted interval: five minutes. Below it a relying party would
/// spend more time fetching the list than trusting it.
pub const MIN_CRL_NEXT_UPDATE_SECS: u64 = 300;

/// Longest accepted interval: seven days. Past it the list stops being a
/// revocation channel anybody should rely on.
pub const MAX_CRL_NEXT_UPDATE_SECS: u64 = 604_800;

/// The route a CA's list is published at, relative to the deployment's public
/// base URL.
pub fn crl_path(organization_id: Uuid, ca_id: Uuid) -> String {
    format!("/pki/v1/{organization_id}/ca/{ca_id}/crl")
}

/// Check an operator's `nextUpdate` interval against
/// [`MIN_CRL_NEXT_UPDATE_SECS`] and [`MAX_CRL_NEXT_UPDATE_SECS`].
pub fn validate_next_update_secs(secs: u64) -> Result<u64, String> {
    if (MIN_CRL_NEXT_UPDATE_SECS..=MAX_CRL_NEXT_UPDATE_SECS).contains(&secs) {
        Ok(secs)
    } else {
        Err(format!(
            "the CRL nextUpdate interval must be between {MIN_CRL_NEXT_UPDATE_SECS} and \
             {MAX_CRL_NEXT_UPDATE_SECS} seconds, not {secs}"
        ))
    }
}

/// Where a relying party finds a CA's list: the absolute URL written into the
/// CRL distribution points extension of every certificate signed after it is
/// configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlDistribution {
    /// `scheme://host[:port][/path]`, with no trailing slash.
    base: String,
}

impl CrlDistribution {
    /// Validate a public base URL: absolute, `http` or `https`, with a host,
    /// no userinfo and no query or fragment.
    ///
    /// What is stored is the parser's own serialisation of what was validated
    /// (without the trailing slash), not the operator's text: the parser drops
    /// tabs and newlines, lowercases the host and percent-encodes what needs
    /// it, so the URI written into certificates is exactly the URL that passed
    /// these checks.
    ///
    /// `http` is accepted on purpose. A CRL is signed, so the transport adds no
    /// integrity, and RFC 5280 §4.2.1.13 expects distribution points that a
    /// relying party can fetch before it can validate anything — some cannot
    /// follow an `https` one without the chain they are trying to check.
    pub fn new(base_url: &str) -> Result<Self, String> {
        let trimmed = base_url.trim();
        let parsed = url::Url::parse(trimmed)
            .map_err(|e| format!("the CRL base URL is not an absolute URL: {e}"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(format!(
                "the CRL base URL must be http or https, not {}",
                parsed.scheme()
            ));
        }
        if parsed.host_str().is_none_or(str::is_empty) {
            return Err("the CRL base URL has no host".into());
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err("the CRL base URL must carry no query or fragment".into());
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err("the CRL base URL must carry no credentials (userinfo)".into());
        }
        Ok(Self {
            base: parsed.as_str().trim_end_matches('/').to_owned(),
        })
    }

    /// The distribution point configured explicitly, or else the one derived
    /// from the deployment's issuer URL — `None` when neither is an absolute
    /// `http(s)` URL.
    ///
    /// An explicit value that does not parse is an error rather than a
    /// fallback: an operator who set one meant it, and certificates naming the
    /// issuer instead would point somewhere they did not choose. An issuer that
    /// is not a URL (the JWT `iss` fallback is often a bare name) yields `None`.
    pub fn resolve(explicit: Option<&str>, issuer_url: &str) -> Result<Option<Self>, String> {
        match explicit.map(str::trim).filter(|v| !v.is_empty()) {
            Some(value) => Self::new(value).map(Some),
            None => Ok(Self::new(issuer_url).ok()),
        }
    }

    /// The absolute URL of a CA's list.
    pub fn uri_for(&self, organization_id: Uuid, ca_id: Uuid) -> String {
        format!("{}{}", self.base, crl_path(organization_id, ca_id))
    }

    /// The extension value for a certificate `issuer` signs.
    pub(crate) fn point_for(&self, issuer: &CaCertificate) -> CrlDistributionPoint {
        CrlDistributionPoint {
            uris: vec![self.uri_for(issuer.organization_id, issuer.id)],
        }
    }
}

/// A signed list, as the route serves it.
#[derive(Debug, Clone)]
pub struct PublishedCrl {
    /// The DER encoding.
    pub der: Arc<[u8]>,
    /// The list's `thisUpdate`.
    pub this_update: DateTime<Utc>,
    /// The list's `nextUpdate`.
    pub next_update: DateTime<Utc>,
    /// The list's CRL number.
    pub crl_number: u64,
    /// A strong entity tag over the DER, quoted.
    pub etag: String,
    /// When the origin re-signs the list even if nothing was revoked: the end
    /// of the refresh epoch it was signed in, half a `nextUpdate` interval at
    /// most after it was served (#608).
    pub refresh_at: DateTime<Utc>,
}

impl PublishedCrl {
    /// Seconds a shared cache may keep this list before revalidating it with
    /// its `ETag` (#608): until the origin's next scheduled re-sign, so at most
    /// half the `nextUpdate` interval and never past `nextUpdate`; never
    /// negative.
    ///
    /// Not until `nextUpdate`, which is what a relying party may trust the list
    /// for: an intermediary honouring that would serve the list from before a
    /// revocation for up to the whole interval, although the origin answers
    /// with the new one at once. Revalidating an unchanged list is a `304`.
    pub fn max_age_secs(&self, now: DateTime<Utc>) -> u64 {
        let until = self.refresh_at.min(self.next_update);
        u64::try_from((until - now).num_seconds().max(0)).unwrap_or(0)
    }

    /// Whether an `If-None-Match` header names this list (RFC 9110 §13.1.2):
    /// `*`, or any listed tag equal to [`Self::etag`], weak or strong.
    pub fn matches_if_none_match(&self, header: &str) -> bool {
        let wanted = self.etag.trim_start_matches("W/");
        header
            .split(',')
            .map(str::trim)
            .any(|candidate| candidate == "*" || candidate.trim_start_matches("W/") == wanted)
    }
}

/// What the cache keeps per CA.
struct CachedCrl {
    crl: PublishedCrl,
    /// Digest of the entries the list was signed over.
    entries_digest: [u8; 32],
    /// When the list is re-signed even if nothing was revoked: the end of its
    /// refresh epoch, so a cached response always has at least half the
    /// `nextUpdate` interval left.
    refresh_at: DateTime<Utc>,
}

/// One CA's place in the cache: its last list, and the re-sign of it in flight
/// (#607, #616).
///
/// Two locks, both `std` and neither held across an `await`, so that reading
/// never waits on signing. `published` is held only to look at or replace the
/// cached list; `flight` only to see whether a re-sign of this CA's list is in
/// flight, and to claim it when none is. A request for an unchanged list takes
/// only the first; a request for a changed list joins the flight already under
/// way for the same CA, and waits on nothing any other CA is doing.
#[derive(Default)]
struct CaSlot {
    published: StdMutex<Option<CachedCrl>>,
    /// The outcome of the re-sign in flight, if one is: `None` in the channel
    /// until it lands. Set only by [`Self::join_or_lead`] when unset, and
    /// cleared only by the flight's own [`Landing`], so while a flight runs the
    /// marker is that flight's.
    flight: StdMutex<Option<watch::Receiver<Option<FlightOutcome>>>>,
}

/// What a re-sign ends with, as every request waiting on it receives it.
type FlightOutcome = AxiamResult<PublishedCrl>;

/// A request's part in a CA's re-sign (#616).
enum Turn {
    /// Another request's flight is under way: wait for its outcome.
    Join(watch::Receiver<Option<FlightOutcome>>),
    /// None was: this request starts one, and lands it.
    Lead(Landing),
}

/// The claim on a CA's one flight, held by whatever runs it. Landing it hands
/// every waiter the outcome; dropping it unlanded — a cancelled or panicking
/// flight — clears the claim all the same, and the waiters, finding the channel
/// closed with nothing in it, look again.
struct Landing {
    slot: Arc<CaSlot>,
    outcome: watch::Sender<Option<FlightOutcome>>,
    landed: bool,
}

impl Landing {
    fn subscribe(&self) -> watch::Receiver<Option<FlightOutcome>> {
        self.outcome.subscribe()
    }

    /// End the flight with `outcome`. The claim is cleared before the outcome
    /// is sent: a request arriving in between finds no flight and the cache as
    /// the flight left it, and one already waiting receives the outcome.
    fn land(mut self, outcome: FlightOutcome) {
        self.slot.end_flight();
        self.landed = true;
        self.outcome.send_replace(Some(outcome));
    }
}

impl Drop for Landing {
    fn drop(&mut self) {
        // Not after `land`: by then another flight may hold the claim.
        if !self.landed {
            self.slot.end_flight();
        }
    }
}

impl CaSlot {
    /// The cached list, if it was signed over exactly `digest` and is not yet
    /// due for its refresh.
    fn fresh(&self, digest: &[u8; 32], now: DateTime<Utc>) -> Option<PublishedCrl> {
        let published = self
            .published
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        published
            .as_ref()
            .filter(|cached| cached.entries_digest == *digest && now < cached.refresh_at)
            .map(|cached| cached.crl.clone())
    }

    fn store(&self, cached: CachedCrl) {
        *self
            .published
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(cached);
    }

    /// Join the flight under way for this CA, or claim it.
    fn join_or_lead(self: &Arc<Self>) -> Turn {
        let mut flight = self.flight.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(outcome) = flight.as_ref() {
            return Turn::Join(outcome.clone());
        }
        let (outcome, waiting) = watch::channel(None);
        *flight = Some(waiting);
        Turn::Lead(Landing {
            slot: Arc::clone(self),
            outcome,
            landed: false,
        })
    }

    fn end_flight(&self) {
        self.flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }
}

/// How long a re-sign waits for a permit of the shared crypto semaphore before
/// the route answers `503` (#607): five seconds, the default wait of the
/// password-hash gate the semaphore also serves. It also bounds how long a
/// request waits on a re-sign of the same CA's list already in flight (#616).
///
/// The semaphore is shared with issuance and with every Argon2id hash and
/// verify. Without a bound a saturated gate would queue unauthenticated CRL
/// requests without limit; with it, a caller is told to come back, and a cached
/// list — which needs no permit — is served throughout.
pub const DEFAULT_CRL_PERMIT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Signs and caches each issuing CA's certificate revocation list.
#[derive(Clone)]
pub struct CrlService<CA, CR> {
    ca_repo: CA,
    cert_repo: CR,
    /// Shared bounding semaphore for CPU-bound crypto (CQ-B02).
    crypto_semaphore: Arc<Semaphore>,
    /// How long a re-sign waits for a crypto permit, and a request for a
    /// re-sign in flight ([`DEFAULT_CRL_PERMIT_WAIT`]).
    permit_wait: std::time::Duration,
    /// Who holds the CA signing keys. See [`crate::ca_key_store`].
    custodians: Arc<CaKeyCustodians>,
    next_update: Duration,
    /// One slot per CA that publishes a list. The map's lock is held only to
    /// find or insert a slot, and a slot is inserted only for a CA that exists
    /// and publishes one, so requests for made-up CA ids — the route is
    /// unauthenticated — add nothing to it; a CA found to publish no list
    /// (revoked or expired since) has its slot removed.
    slots: Arc<StdMutex<HashMap<Uuid, Arc<CaSlot>>>>,
}

impl<CA: CaCertificateRepository, CR: CertificateRepository> CrlService<CA, CR> {
    /// `next_update_secs` is the `thisUpdate` → `nextUpdate` interval; the
    /// composition root validates it with [`validate_next_update_secs`].
    pub fn new(
        ca_repo: CA,
        cert_repo: CR,
        crypto_semaphore: Arc<Semaphore>,
        custodians: Arc<CaKeyCustodians>,
        next_update_secs: u64,
    ) -> Self {
        Self {
            ca_repo,
            cert_repo,
            crypto_semaphore,
            permit_wait: DEFAULT_CRL_PERMIT_WAIT,
            custodians,
            next_update: Duration::seconds(i64::try_from(next_update_secs).unwrap_or(i64::MAX)),
            slots: Arc::default(),
        }
    }

    /// Replace [`DEFAULT_CRL_PERMIT_WAIT`].
    #[must_use]
    pub fn with_permit_wait(mut self, wait: std::time::Duration) -> Self {
        self.permit_wait = wait;
        self
    }

    /// The current list of CA `ca_id` of organization `organization_id`.
    ///
    /// `NotFound` for a CA that does not exist in that organization **and** for
    /// one that publishes no list (see the module docs): the route is
    /// unauthenticated, and which of the two it is — or which custodian holds a
    /// key — is not an outsider's business. The reason is logged.
    ///
    /// `ServiceUnavailable` when the list has to be signed and no crypto permit
    /// came free within the permit wait ([`Self::with_permit_wait`]).
    ///
    /// When the list has to be re-signed and a re-sign of the same CA's list is
    /// already in flight, the request waits for that one's outcome — at most the
    /// permit wait, then `ServiceUnavailable` — and receives it, a
    /// `ServiceUnavailable` included (#616).
    pub async fn current(&self, organization_id: Uuid, ca_id: Uuid) -> AxiamResult<PublishedCrl>
    where
        CA: Clone + 'static,
        CR: Clone + 'static,
    {
        self.current_at(organization_id, ca_id, Utc::now()).await
    }

    /// [`Self::current`], as of `now`.
    ///
    /// Everything the list says is a function of the revocations in the store
    /// and of the refresh epoch `now` falls in (#608), so two replicas — or two
    /// services in a test — asked at instants in the same epoch about the same
    /// store answer with the same bytes. Exposed so a test can name the instant
    /// rather than wait for an epoch to pass.
    pub async fn current_at(
        &self,
        organization_id: Uuid,
        ca_id: Uuid,
        now: DateTime<Utc>,
    ) -> AxiamResult<PublishedCrl>
    where
        CA: Clone + 'static,
        CR: Clone + 'static,
    {
        let not_published = || not_published(ca_id);

        // Organization-scoped, as every CA lookup is (T-98): a CA id under the
        // wrong organization is not found, not served.
        let ca = match self.ca_repo.get_by_id(organization_id, ca_id).await {
            Ok(ca) => ca,
            Err(AxiamError::NotFound { .. }) => return Err(not_published()),
            Err(e) => return Err(e),
        };
        if let Some(reason) = Self::why_unpublished(&ca, now) {
            tracing::debug!(%organization_id, %ca_id, reason, "no CRL is published for this CA");
            self.forget(ca.id);
            return Err(not_published());
        }
        let store = self.custodians.store_for(ca.key_custody)?;
        if store.signs_remotely() {
            tracing::debug!(
                %organization_id,
                %ca_id,
                "no CRL is published for this CA: its key is held by a custodian that signs \
                 certificate requests only (vault_pki), and publishes the CA's list itself"
            );
            self.forget(ca.id);
            return Err(not_published());
        }

        // Read on every request, and before any lock: a revocation is in the
        // very next response. Only fingerprints and dates (#607) — whether the
        // list changed is decided without reading a single certificate.
        let epoch = self.epoch_of(now);
        let mut stamps = self
            .cert_repo
            .list_revocation_stamps_by_issuer(ca.id, epoch.expiring_after)
            .await?;
        stamps.extend(
            self.ca_repo
                .list_revoked_children_stamps(ca.id, epoch.expiring_after)
                .await?,
        );
        stamps.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        let digest = entries_digest(stamps.iter().map(|s| {
            (
                s.fingerprint.as_str(),
                revocation_time(s.revoked_at, s.not_before),
            )
        }));

        let slot = self.slot(ca.id);
        if let Some(crl) = slot.fresh(&digest, now) {
            return Ok(crl);
        }
        self.resign(slot, ca, digest, now).await
    }

    /// The list of `ca` as of a state whose entries digest is `digest`, which
    /// the cache does not hold: from the re-sign of this CA's list already in
    /// flight, or from one this request starts (#607, #616).
    ///
    /// One re-sign per CA at a time, and its outcome is shared. A request that
    /// finds one in flight waits for it, at most the permit wait from when it
    /// began waiting, then answers `ServiceUnavailable`; it is handed the
    /// flight's failure, a `ServiceUnavailable` included, rather than starting
    /// a re-sign of its own behind it, so callers queued on a saturated gate all
    /// answer within about one permit wait instead of one each in turn. A
    /// flight that signed a list leaves it in the cache, and a waiter takes it
    /// from there only if it is of the state the waiter read; one that read a
    /// later state — a revocation committed while the flight ran — starts the
    /// next flight, so a revocation is still in the next response.
    ///
    /// The flight runs as a task of its own, so it ends — and its list is
    /// cached — even when the request that started it is gone (an
    /// unauthenticated caller can hang up at will). That request waits for it
    /// without the waiters' bound: the flight bounds its own wait for a crypto
    /// permit, and the custodian its own key read.
    async fn resign(
        &self,
        slot: Arc<CaSlot>,
        ca: CaCertificate,
        digest: [u8; 32],
        now: DateTime<Utc>,
    ) -> AxiamResult<PublishedCrl>
    where
        CA: Clone + 'static,
        CR: Clone + 'static,
    {
        let deadline = tokio::time::Instant::now() + self.permit_wait;
        loop {
            // Never earlier than the clock: a request that waited across an
            // epoch boundary takes, or signs, the new epoch's list, not one
            // older than the list a flight ahead of it may just have cached.
            let now = now.max(Utc::now());
            match slot.join_or_lead() {
                Turn::Lead(landing) => {
                    // A flight that landed between this request's look at the
                    // cache and its claim may have left exactly this list.
                    if let Some(crl) = slot.fresh(&digest, now) {
                        landing.land(Ok(crl.clone()));
                        return Ok(crl);
                    }
                    let mut outcome = landing.subscribe();
                    let flight = self.clone();
                    let flight_slot = Arc::clone(&slot);
                    tokio::spawn(async move {
                        let signed = flight.sign(&flight_slot, &ca, now).await;
                        landing.land(signed);
                    });
                    return match outcome.wait_for(Option::is_some).await {
                        Ok(landed) => landed.clone().unwrap_or_else(|| Err(interrupted())),
                        Err(_dropped) => Err(interrupted()),
                    };
                }
                Turn::Join(mut outcome) => {
                    let landed =
                        match tokio::time::timeout_at(deadline, outcome.wait_for(Option::is_some))
                            .await
                        {
                            Ok(Ok(landed)) => landed.clone(),
                            // The flight ended without an outcome: look again.
                            Ok(Err(_dropped)) => None,
                            Err(_elapsed) => {
                                tracing::debug!(
                                    organization_id = %ca.organization_id,
                                    ca_id = %ca.id,
                                    "the CRL re-sign in flight did not land within the permit wait"
                                );
                                return Err(busy());
                            }
                        };
                    if let Some(Err(failed)) = landed {
                        return Err(failed);
                    }
                    if let Some(crl) = slot.fresh(&digest, now.max(Utc::now())) {
                        return Ok(crl);
                    }
                    // Signed over another state than this request read: the
                    // next flight is this request's, or one it joins.
                }
            }
        }
    }

    /// Sign `ca`'s list as of the store now, and cache it — the body of one
    /// flight (#616).
    async fn sign(
        &self,
        slot: &CaSlot,
        ca: &CaCertificate,
        now: DateTime<Utc>,
    ) -> AxiamResult<PublishedCrl> {
        let (organization_id, ca_id) = (ca.organization_id, ca.id);
        let store = self.custodians.store_for(ca.key_custody)?;
        // The certificates, read only to sign — and read again rather than
        // trusted from the stamps, so the list is of the state as it is now.
        let epoch = self.epoch_of(now);
        let mut entries = self
            .cert_repo
            .list_revoked_by_issuer(ca.id, epoch.expiring_after)
            .await?;
        entries.extend(
            self.ca_repo
                .list_revoked_children(ca.id, epoch.expiring_after)
                .await?,
        );
        entries.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        let digest = entries_digest(entries.iter().map(|e| {
            (
                e.fingerprint.as_str(),
                revocation_time(e.revoked_at, e.not_before),
            )
        }));

        // Derived, not read off the clock (#608): see `list_identity`.
        let revocation_times: Vec<DateTime<Utc>> = entries
            .iter()
            .map(|e| revocation_time(e.revoked_at, e.not_before))
            .collect();
        // Never before the CA itself: a CA created mid-epoch states its own
        // notBefore, a constant of the CA, so the derivation stays the same on
        // every replica. Never past the epoch's last second (#615).
        let (this_update, crl_number) = list_identity(
            epoch.start.max(ca.not_before),
            epoch.last_second(),
            &revocation_times,
        );
        let next_update = (this_update + self.next_update).min(ca.not_after);
        if next_update <= this_update {
            tracing::debug!(%organization_id, %ca_id, "no CRL is published: the CA expires now");
            return Err(not_published(ca_id));
        }

        let key_ref = CaService::<CA>::key_ref(ca);
        let ca_key_pem = store
            .load(&key_ref, ca.encrypted_private_key.as_deref())
            .await?
            .to_string();
        let _permit = self.crypto_permit(organization_id, ca_id).await?;
        let ca_cert_pem = ca.public_cert_pem.clone();
        let der = tokio::task::spawn_blocking(move || {
            sign_crl(
                &ca_cert_pem,
                ca_key_pem,
                &entries,
                this_update,
                next_update,
                crl_number,
            )
        })
        .await
        .map_err(|e| AxiamError::Internal(format!("spawn_blocking join error: {e}")))??;

        let etag = format!("\"{}\"", hex::encode(&Sha256::digest(&der)[..16]));
        let crl = PublishedCrl {
            der: Arc::from(der),
            this_update,
            next_update,
            crl_number,
            etag,
            refresh_at: epoch.end,
        };
        slot.store(CachedCrl {
            crl: crl.clone(),
            entries_digest: digest,
            refresh_at: epoch.end,
        });
        Ok(crl)
    }

    /// The refresh epoch `now` falls in (#608).
    fn epoch_of(&self, now: DateTime<Utc>) -> RefreshEpoch {
        RefreshEpoch::of(self.next_update, now)
    }

    /// A permit of the shared crypto semaphore, or `ServiceUnavailable` once
    /// the permit wait has passed (#607).
    async fn crypto_permit(
        &self,
        organization_id: Uuid,
        ca_id: Uuid,
    ) -> AxiamResult<tokio::sync::SemaphorePermit<'_>> {
        match tokio::time::timeout(self.permit_wait, self.crypto_semaphore.acquire()).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_closed)) => Err(AxiamError::Internal("crypto semaphore closed".into())),
            Err(_elapsed) => {
                tracing::warn!(
                    %organization_id,
                    %ca_id,
                    wait_ms = u64::try_from(self.permit_wait.as_millis()).unwrap_or(u64::MAX),
                    "the CRL could not be re-signed: no crypto permit came free in time"
                );
                Err(busy())
            }
        }
    }

    /// The slot of a CA that publishes a list, inserted on first use.
    fn slot(&self, ca_id: Uuid) -> Arc<CaSlot> {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(slots.entry(ca_id).or_default())
    }

    /// Drop the slot of a CA that no longer publishes a list.
    fn forget(&self, ca_id: Uuid) {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&ca_id);
    }

    /// How many CAs the cache holds a slot for.
    #[doc(hidden)]
    pub fn cached_ca_count(&self) -> usize {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Why `ca` publishes no list, if it does not — the reasons that need no
    /// custodian to answer.
    fn why_unpublished(ca: &CaCertificate, now: DateTime<Utc>) -> Option<&'static str> {
        if ca.status != CertificateStatus::Active {
            return Some("the CA is not active; its own status is on its parent's list");
        }
        if now < ca.not_before || now >= ca.not_after {
            return Some("the CA is outside its validity window");
        }
        if ca.key_custody == CaKeyCustody::External {
            return Some("AXIAM holds no key for this CA: it was imported as a trust anchor");
        }
        None
    }
}

/// The `404` of a CA that publishes no list, alike for one that does not exist.
fn not_published(ca_id: Uuid) -> AxiamError {
    AxiamError::NotFound {
        entity: "certificate revocation list".into(),
        id: ca_id.to_string(),
    }
}

/// The route's `503`: the list has to be re-signed and was not, within the
/// permit wait.
fn busy() -> AxiamError {
    AxiamError::ServiceUnavailable(
        "the certificate revocation list cannot be signed right now; retry shortly".into(),
    )
}

/// A flight that ended without an outcome: its task was cancelled or panicked
/// (the runtime shutting down, say).
fn interrupted() -> AxiamError {
    AxiamError::Internal("the certificate revocation list re-sign was interrupted".into())
}

/// A digest that changes exactly when the list's entries would: over each
/// entry's fingerprint and stated date, in fingerprint order.
fn entries_digest<'a>(entries: impl Iterator<Item = (&'a str, DateTime<Utc>)>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for (fingerprint, revoked) in entries {
        hasher.update(fingerprint.as_bytes());
        hasher.update(b":");
        hasher.update(revoked.timestamp().to_be_bytes());
        hasher.update(b"\n");
    }
    hasher.finalize().into()
}

/// The date an entry states: when AXIAM recorded the revocation, or — for a
/// certificate revoked before the date was kept — its own `notBefore`, the
/// earliest moment anyone could have relied on it.
fn revocation_time(revoked_at: Option<DateTime<Utc>>, not_before: DateTime<Utc>) -> DateTime<Utc> {
    revoked_at.unwrap_or(not_before)
}

/// The date a list whose `thisUpdate` is `this_update` states for an entry
/// revoked at `revoked` (#615): never later than the list itself. Only a
/// revocation date past the epoch's end — written by a datastore clock ahead of
/// the replica's — is moved, to the epoch's last second, and it states its own
/// date again on the next epoch's list.
fn stated_revocation_time(revoked: DateTime<Utc>, this_update: DateTime<Utc>) -> DateTime<Utc> {
    revoked.min(this_update)
}

/// A slice of time half a `nextUpdate` interval long, aligned to the Unix
/// epoch, so that every replica cuts time at the same instants (#608).
struct RefreshEpoch {
    /// Its first second: the earliest `thisUpdate` a list signed in it states.
    start: DateTime<Utc>,
    /// The first second of the next one, when a cached list is re-signed.
    end: DateTime<Utc>,
    /// The start of the previous epoch. A list names every revoked certificate
    /// whose `notAfter` is later, so an entry stays until a list issued after
    /// its expiry has named it (RFC 5280 §3.3) and leaves only when the epoch
    /// moves on — never in the middle of one.
    expiring_after: DateTime<Utc>,
}

impl RefreshEpoch {
    /// Its last second: the latest `thisUpdate` a list signed in it states
    /// (#615), so that every list of the next epoch states a later one.
    fn last_second(&self) -> DateTime<Utc> {
        self.end - Duration::seconds(1)
    }

    /// The epoch `now` falls in, for lists valid for `next_update`.
    fn of(next_update: Duration, now: DateTime<Utc>) -> Self {
        let half = (next_update.num_seconds() / 2).max(1);
        let start = now.timestamp().div_euclid(half) * half;
        let at = |secs: i64| DateTime::from_timestamp(secs, 0).unwrap_or(now);
        Self {
            start: at(start),
            end: at(start.saturating_add(half)),
            expiring_after: at(start.saturating_sub(half)),
        }
    }
}

/// Bits of the CRL number below `thisUpdate`, holding the entry count.
const CRL_NUMBER_COUNT_BITS: u32 = 24;

/// The `thisUpdate` and CRL number of a list of entries with these revocation
/// dates, signed in the refresh epoch starting at `floor` — or, for a CA whose
/// own `notBefore` is later, starting at that — and ending after `ceiling`, its
/// last second (#608, #615).
///
/// Both are functions of the list's contents and its epoch alone, so every
/// replica signing the same state in the same epoch states the same ones — and,
/// with a deterministic signature (Ed25519; RSA PKCS#1 v1.5, the two key types
/// a CA can have), produces the same bytes and `ETag`:
///
/// - `thisUpdate` is the later of `floor` and the newest revocation date on
///   the list, in whole seconds — the moment the list's contents were last
///   made true, never before the epoch began nor before the CA existed — but
///   never later than `ceiling`. A revocation date is written by the
///   datastore's clock, which may be ahead of the replica's; one past the
///   epoch's end would otherwise carry `thisUpdate` out of its epoch, and the
///   next epoch's first list could then state the same `thisUpdate` with fewer
///   entries — a lower number (#615). [`sign_crl`] states no entry's date later
///   than `thisUpdate`;
/// - the CRL number is `thisUpdate` in seconds since the Unix epoch, shifted
///   left 24 bits, plus the number of entries.
///
/// Under one interval the number grows with every change of a CA's list,
/// whatever the datastore's clock says. Within an epoch the set of entries
/// only grows: a revocation is never undone, an expired entry stays until the
/// epoch ends (see [`RefreshEpoch::expiring_after`]), and the tenant purge
/// keeps a revoked row for longer than that. A new entry raises `thisUpdate`
/// or, when its date is not the newest (a revocation committed late, two in one
/// second) or `thisUpdate` is already at `ceiling`, the count. When the epoch
/// moves on, `thisUpdate` is at least the new epoch's start, later than
/// `ceiling` and so than every `thisUpdate` the old epoch stated — so even a
/// list that lost entries, because they expired, has a greater number. The
/// count saturates at 2^24 − 1 entries, past which two lists stating the same
/// `thisUpdate` would share a number. What the derivation cannot see — another
/// interval, another replica's clock — is in the module docs.
fn list_identity(
    floor: DateTime<Utc>,
    ceiling: DateTime<Utc>,
    revocation_times: &[DateTime<Utc>],
) -> (DateTime<Utc>, u64) {
    let secs = revocation_times
        .iter()
        .map(DateTime::timestamp)
        .fold(floor.timestamp(), i64::max)
        .min(ceiling.timestamp());
    let this_update = DateTime::from_timestamp(secs, 0).unwrap_or(floor);
    let count = u64::try_from(revocation_times.len())
        .unwrap_or(u64::MAX)
        .min((1 << CRL_NUMBER_COUNT_BITS) - 1);
    let number = (u64::try_from(secs).unwrap_or(0) << CRL_NUMBER_COUNT_BITS) | count;
    (this_update, number)
}

fn to_offset(t: DateTime<Utc>) -> AxiamResult<time::OffsetDateTime> {
    time::OffsetDateTime::from_unix_timestamp(t.timestamp())
        .map_err(|e| AxiamError::Internal(format!("CRL time out of range: {e}")))
}

/// Sign a CRL over `entries` with the CA's key. Pure and blocking — the caller
/// runs it under the crypto semaphore, off the async runtime.
///
/// A revoked certificate whose PEM does not parse fails the whole list rather
/// than being left off it: a list that silently omits a revocation is worse
/// than no list, because a relying party trusts what it says.
pub(crate) fn sign_crl(
    ca_cert_pem: &str,
    mut ca_key_pem: String,
    entries: &[RevokedCertificate],
    this_update: DateTime<Utc>,
    next_update: DateTime<Utc>,
    crl_number: u64,
) -> AxiamResult<Vec<u8>> {
    let key_pair = KeyPair::from_pem(&ca_key_pem)
        .map_err(|e| AxiamError::Certificate(format!("invalid CA private key: {e}")));
    // Scrubbed as soon as it is parsed, as on the leaf path.
    ca_key_pem.zeroize();
    let key_pair = key_pair?;

    // The authority key identifier must equal the CA certificate's subject key
    // identifier, whatever method produced it — an imported CA's is usually a
    // SHA-1 of its key, not rcgen's default — so it is read from the
    // certificate rather than derived again.
    let (_, ca_block) = x509_parser::pem::parse_x509_pem(ca_cert_pem.as_bytes())
        .map_err(|e| AxiamError::Certificate(format!("invalid CA certificate PEM: {e}")))?;
    let (_, ca_x509) = X509Certificate::from_der(&ca_block.contents)
        .map_err(|e| AxiamError::Certificate(format!("invalid CA certificate: {e}")))?;
    let key_identifier_method = ca_x509
        .extensions()
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(kid) => Some(kid.0.to_vec()),
            _ => None,
        })
        .map_or(KeyIdMethod::Sha256, KeyIdMethod::PreSpecified);

    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, key_pair)
        .map_err(|e| AxiamError::Certificate(format!("invalid CA certificate PEM: {e}")))?;

    let revoked_certs = entries
        .iter()
        .map(|entry| {
            let (_, block) = x509_parser::pem::parse_x509_pem(entry.public_cert_pem.as_bytes())
                .map_err(|e| {
                    AxiamError::Internal(format!(
                        "revoked certificate {} is not PEM: {e}",
                        entry.fingerprint
                    ))
                })?;
            let (_, cert) = X509Certificate::from_der(&block.contents).map_err(|e| {
                AxiamError::Internal(format!(
                    "revoked certificate {} does not parse: {e}",
                    entry.fingerprint
                ))
            })?;
            Ok(RevokedCertParams {
                serial_number: SerialNumber::from_slice(&cert.serial.to_bytes_be()),
                revocation_time: to_offset(stated_revocation_time(
                    revocation_time(entry.revoked_at, entry.not_before),
                    this_update,
                ))?,
                reason_code: None,
                invalidity_date: None,
            })
        })
        .collect::<AxiamResult<Vec<_>>>()?;

    let params = CertificateRevocationListParams {
        this_update: to_offset(this_update)?,
        next_update: to_offset(next_update)?,
        crl_number: SerialNumber::from(crl_number),
        // A complete list: every certificate this CA signed, leaves and CAs.
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method,
    };
    let crl = params
        .signed_by(&issuer)
        .map_err(|e| AxiamError::Certificate(format!("CRL signing failed: {e}")))?;
    Ok(crl.der().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_route_is_the_one_the_distribution_point_names() {
        let org = Uuid::new_v4();
        let ca = Uuid::new_v4();
        let distribution = CrlDistribution::new("https://id.example.com/").unwrap();
        assert_eq!(
            distribution.uri_for(org, ca),
            format!("https://id.example.com/pki/v1/{org}/ca/{ca}/crl")
        );
    }

    #[test]
    fn a_base_url_must_be_absolute_http_with_no_query() {
        for bad in [
            "id.example.com",
            "ftp://id.example.com",
            "https://id.example.com/?a=b",
            "https://id.example.com/#x",
            "",
        ] {
            assert!(
                CrlDistribution::new(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
        assert!(CrlDistribution::new("http://crl.internal:8080/axiam").is_ok());
    }

    #[test]
    fn the_stored_base_is_the_parsed_url_without_a_trailing_slash() {
        let org = Uuid::new_v4();
        let ca = Uuid::new_v4();
        for (given, base) in [
            ("https://id.example.com/", "https://id.example.com"),
            (
                "https://id.example.com/axiam/",
                "https://id.example.com/axiam",
            ),
            // The parser removes tabs and newlines anywhere in the input...
            (
                "https://id.exa\tmple.com/ax\niam",
                "https://id.example.com/axiam",
            ),
            (
                "  https://id.example.com/a\r\nb/  ",
                "https://id.example.com/ab",
            ),
            // ...lowercases the host and drops a default port...
            (
                "HTTPS://ID.Example.COM:443/axiam",
                "https://id.example.com/axiam",
            ),
            // ...and percent-encodes what a path may not carry verbatim.
            ("https://id.example.com/a b", "https://id.example.com/a%20b"),
            (
                "https://id.example.com/caf\u{e9}",
                "https://id.example.com/caf%C3%A9",
            ),
        ] {
            let distribution = CrlDistribution::new(given).unwrap();
            assert_eq!(distribution.base, base, "{given:?}");
            assert_eq!(
                distribution.uri_for(org, ca),
                format!("{base}/pki/v1/{org}/ca/{ca}/crl"),
                "{given:?}"
            );
        }
    }

    #[test]
    fn a_base_url_with_userinfo_is_refused() {
        for bad in [
            "https://user:pw@id.example.com/axiam",
            "https://user@id.example.com/axiam",
            "http://:pw@id.example.com",
        ] {
            assert!(
                CrlDistribution::new(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn resolve_prefers_the_explicit_value_and_never_falls_back_from_a_bad_one() {
        let issuer = "https://id.example.com";
        assert_eq!(
            CrlDistribution::resolve(None, issuer).unwrap(),
            Some(CrlDistribution::new(issuer).unwrap())
        );
        assert_eq!(
            CrlDistribution::resolve(Some("http://crl.internal"), issuer).unwrap(),
            Some(CrlDistribution::new("http://crl.internal").unwrap())
        );
        assert!(CrlDistribution::resolve(Some("not a url"), issuer).is_err());
        // The JWT issuer fallback is often a bare name: no distribution point.
        assert_eq!(CrlDistribution::resolve(None, "axiam").unwrap(), None);
        assert_eq!(CrlDistribution::resolve(Some("  "), "axiam").unwrap(), None);
    }

    #[test]
    fn the_interval_is_bounded() {
        assert!(validate_next_update_secs(DEFAULT_CRL_NEXT_UPDATE_SECS).is_ok());
        assert!(validate_next_update_secs(MIN_CRL_NEXT_UPDATE_SECS - 1).is_err());
        assert!(validate_next_update_secs(MAX_CRL_NEXT_UPDATE_SECS + 1).is_err());
    }

    #[test]
    fn if_none_match_accepts_star_lists_and_weak_tags() {
        let crl = PublishedCrl {
            der: Arc::from(vec![1u8, 2, 3]),
            this_update: Utc::now(),
            next_update: Utc::now(),
            crl_number: 1,
            etag: "\"abc\"".into(),
            refresh_at: Utc::now(),
        };
        assert!(crl.matches_if_none_match("\"abc\""));
        assert!(crl.matches_if_none_match("\"x\", W/\"abc\""));
        assert!(crl.matches_if_none_match("*"));
        assert!(!crl.matches_if_none_match("\"abd\""));
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    /// The last second of the one-day-interval epoch starting at `start`.
    fn last_of(start: DateTime<Utc>) -> DateTime<Utc> {
        start + Duration::seconds(43_199)
    }

    /// #608: `thisUpdate` is the later of the epoch's start and the newest
    /// revocation date; the number is `thisUpdate` above the entry count.
    #[test]
    fn this_update_and_the_number_are_derived_from_the_list_and_its_epoch() {
        let start = at(1_800_000_000);
        let last = last_of(start);
        assert_eq!(
            list_identity(start, last, &[]),
            (start, 1_800_000_000 << 24)
        );
        let older = at(1_799_999_000);
        assert_eq!(
            list_identity(start, last, &[older]),
            (start, (1_800_000_000 << 24) | 1),
            "an entry older than the epoch leaves thisUpdate at its start"
        );
        let newer = DateTime::from_timestamp(1_800_000_123, 900_000_000).unwrap();
        assert_eq!(
            list_identity(start, last, &[older, newer]),
            (at(1_800_000_123), (1_800_000_123 << 24) | 2),
            "the newest revocation, in whole seconds"
        );
    }

    /// #615: a revocation dated past the epoch's end — a datastore clock ahead
    /// of the replica's — leaves `thisUpdate` at the epoch's last second and is
    /// stated no later than it; the next epoch's list, which no longer names an
    /// entry that expired at the boundary, still has a greater number.
    #[test]
    fn a_revocation_dated_past_the_epoch_is_stated_at_its_last_second() {
        let start = at(1_800_000_000);
        let last = last_of(start);
        let ahead = last + Duration::seconds(11);
        let older = at(1_799_999_000);
        let (this_update, number) = list_identity(start, last, &[older, ahead]);
        assert_eq!(this_update, last, "thisUpdate stays in its epoch");
        assert_eq!(number, (u64::try_from(last.timestamp()).unwrap() << 24) | 2);
        assert_eq!(stated_revocation_time(ahead, this_update), last);
        assert_eq!(
            stated_revocation_time(older, this_update),
            older,
            "a date inside the list's time is stated as recorded"
        );
        // The next epoch: the older entry expired at the boundary and left, and
        // the one dated ahead now states its own date.
        let next = last + Duration::seconds(1);
        let (next_update, next_number) = list_identity(next, last_of(next), &[ahead]);
        assert_eq!(next_update, ahead);
        assert!(next_number > number, "fewer entries, a greater number");
        // Before #615 the first list stated `ahead` as its thisUpdate, and the
        // second — the same thisUpdate, one entry fewer — a lower number.
        let unclamped = (u64::try_from(ahead.timestamp()).unwrap() << 24) | 2;
        assert!(next_number < unclamped);
    }

    /// #608: every change a CA's list can undergo raises its number.
    #[test]
    fn the_number_grows_with_every_change_of_the_list() {
        let epoch = at(1_800_000_000);
        let last = last_of(epoch);
        let (_, empty) = list_identity(epoch, last, &[]);
        // A revocation, dated in the epoch.
        let first = at(1_800_000_100);
        let (_, one) = list_identity(epoch, last, &[first]);
        assert!(one > empty);
        // A second one in the same second: thisUpdate stays, the count grows.
        let (_, two) = list_identity(epoch, last, &[first, first]);
        assert!(two > one);
        // A revocation committed late, dated before the newest: the count.
        let (_, late) = list_identity(epoch, last, &[first, first, at(1_800_000_050)]);
        assert!(late > two);
        // One dated past the epoch's end (#615): thisUpdate stops at the last
        // second, and the next one dated past it raises the count.
        let ahead = last + Duration::seconds(30);
        let (_, clamped) = list_identity(epoch, last, &[first, first, first, ahead]);
        assert!(clamped > late);
        let (_, clamped_again) = list_identity(epoch, last, &[first, first, first, ahead, ahead]);
        assert!(clamped_again > clamped);
        // The next epoch, after both earlier entries expired and left: fewer
        // entries, a greater number, because thisUpdate is the new epoch's
        // start.
        let next = at(1_800_000_000 + 43_200);
        let (this_update, emptied) = list_identity(next, last_of(next), &[]);
        assert_eq!(this_update, next);
        assert!(emptied > clamped_again);
    }

    /// #608: epochs are half the interval long and aligned to the Unix epoch,
    /// so every replica cuts time at the same instants.
    #[test]
    fn epochs_are_half_the_interval_and_aligned_for_every_replica() {
        let now = DateTime::from_timestamp(1_800_012_345, 678).unwrap();
        let epoch = RefreshEpoch::of(Duration::seconds(86_400), now);
        assert_eq!(epoch.start, at(1_799_971_200));
        assert_eq!(epoch.end - epoch.start, Duration::seconds(43_200));
        assert_eq!(
            epoch.start - epoch.expiring_after,
            Duration::seconds(43_200)
        );
        assert!(epoch.start <= now && now < epoch.end);
        // Another instant in the same epoch is the same epoch.
        let later = RefreshEpoch::of(Duration::seconds(86_400), epoch.end - Duration::seconds(1));
        assert_eq!(later.start, epoch.start);
    }

    /// #608: a cache may keep the list until the origin's next re-sign — never
    /// until `nextUpdate`, and never past it.
    #[test]
    fn max_age_runs_to_the_refresh_not_to_next_update() {
        let now = at(1_800_000_000);
        let mut crl = PublishedCrl {
            der: Arc::from(vec![1u8]),
            this_update: now,
            next_update: now + Duration::seconds(86_400),
            crl_number: 1,
            etag: "\"x\"".into(),
            refresh_at: now + Duration::seconds(600),
        };
        assert_eq!(crl.max_age_secs(now), 600);
        assert_eq!(crl.max_age_secs(now + Duration::seconds(700)), 0);
        crl.next_update = now + Duration::seconds(300);
        assert_eq!(crl.max_age_secs(now), 300, "never past nextUpdate");
    }
}
