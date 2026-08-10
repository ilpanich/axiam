//! Reactor wire protocol (X1, SDK contract §16 — normative).
//!
//! Both directions are signed. The server signs the event with the tenant's
//! HKDF-derived AMQP subkey (§8); the reactor signs its reply with the same
//! key. That symmetry is the point: an unsigned reply is not a reply, it is an
//! unauthenticated instruction to change a token, and the whole reason
//! reactors are safe to expose is that the server never has to trust one.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

use axiam_core::models::reactor::{ReactorEventSpec, ReactorOutcome};

use crate::messages::{
    CURRENT_KEY_VERSION, MIN_ACCEPTED_KEY_VERSION, derive_tenant_key, is_fresh, sign_payload,
    verify_payload,
};

/// Topic exchange every reactor event is published to.
pub const REACTOR_EXCHANGE: &str = "axiam.reactor.events";

/// Routing key for an event: `<tenant_id>.<event>`.
pub fn routing_key(tenant_id: Uuid, event: &str) -> String {
    format!("{tenant_id}.{event}")
}

/// The durable per-reactor queue the server declares. Actors consume; they
/// never declare topology, so a compromised or buggy reactor cannot bind
/// itself to another tenant's routing key.
pub fn queue_name(tenant_id: Uuid, reactor_id: Uuid) -> String {
    format!("axiam.reactor.q.{tenant_id}.{reactor_id}")
}

// ---------------------------------------------------------------------------
// Event (server → reactor)
// ---------------------------------------------------------------------------

/// One hook firing, delivered to a reactor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactorEventMessage {
    pub tenant_id: Uuid,
    /// Registry event name, e.g. `token.pre_issue`.
    pub event: String,
    /// Correlates the reply. The dispatcher will not read a reply carrying any
    /// other value.
    pub correlation_id: Uuid,
    /// Event-specific body. Never carries a credential, a token, or a signing
    /// key — a reactor is told *what is being decided*, not handed the means
    /// to act on it elsewhere.
    pub payload: serde_json::Value,
    /// How long the server will wait. Sent so an actor can shed load rather
    /// than answer into a closed window.
    pub timeout_ms: u32,
    pub key_version: u8,
    pub nonce: Uuid,
    pub issued_at: DateTime<Utc>,
    /// HMAC over the body with this field cleared.
    pub hmac_signature: Option<String>,
}

// ---------------------------------------------------------------------------
// Reply (reactor → server)
// ---------------------------------------------------------------------------

/// What a reactor decided. `mutate` carries `patch`; every other decision
/// ignores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReplyDecision {
    Allow,
    Deny,
    Mutate,
}

/// A reactor's answer to one event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactorReply {
    pub correlation_id: Uuid,
    pub tenant_id: Uuid,
    pub event: String,
    pub decision: ReplyDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Flat field map. Validated against the event's allow-list; a single
    /// forbidden key rejects the **whole** reply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<BTreeMap<String, String>>,
    /// `login.post_auth` only: proceed, but demand step-up first.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub require_mfa: bool,
    pub key_version: u8,
    pub nonce: Uuid,
    pub issued_at: DateTime<Utc>,
    pub hmac_signature: Option<String>,
}

/// Why a reply was not usable. Every variant resolves to the registration's
/// `failure_policy`, and every variant is audited — a reactor that is silently
/// wrong is worse than one that is loudly absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyRejection {
    /// `correlation_id` does not match the event that was sent.
    WrongCorrelation,
    /// Reply is for a different tenant than the event. Never legitimate.
    TenantMismatch,
    /// Reply names a different event than the one that was sent.
    EventMismatch,
    /// `key_version` below the replay-protected floor.
    KeyVersionTooOld(u8),
    /// `issued_at` outside the freshness window.
    Stale,
    /// Missing or wrong signature.
    BadSignature,
    /// `decision: mutate` on a veto-only event.
    NotMutable,
    /// A patch key outside the event's allow-list. Carries the offending key
    /// so the audit record names it.
    ForbiddenPatchField(String),
    /// `decision: mutate` with no patch, or a patch on a non-mutate decision.
    MalformedMutation,
    /// `require_mfa` on an event that has no step-up notion.
    RequireMfaNotSupported,
}

impl std::fmt::Display for ReplyRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongCorrelation => write!(f, "reply correlation_id does not match the event"),
            Self::TenantMismatch => write!(f, "reply is for a different tenant"),
            Self::EventMismatch => write!(f, "reply is for a different event"),
            Self::KeyVersionTooOld(v) => {
                write!(f, "reply key_version {v} is below the accepted floor")
            }
            Self::Stale => write!(f, "reply issued_at is outside the freshness window"),
            Self::BadSignature => write!(f, "reply signature is missing or invalid"),
            Self::NotMutable => write!(f, "event is veto-only; a mutate reply is not accepted"),
            Self::ForbiddenPatchField(k) => {
                write!(f, "patch field '{k}' is outside the event's allow-list")
            }
            Self::MalformedMutation => write!(f, "mutate without a patch, or patch without mutate"),
            Self::RequireMfaNotSupported => {
                write!(f, "require_mfa is not supported for this event")
            }
        }
    }
}

/// Serialize a message with `hmac_signature` cleared — the exact bytes both
/// sides sign. Taking the value and clearing the field (rather than asking the
/// caller to remember) is what makes it impossible to sign over a body that
/// already contains a signature.
fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(value)
}

impl ReactorEventMessage {
    /// Build and sign an event.
    pub fn signed(
        master_key: &[u8],
        tenant_id: Uuid,
        event: &str,
        correlation_id: Uuid,
        payload: serde_json::Value,
        timeout_ms: u32,
        now: DateTime<Utc>,
    ) -> Result<Self, serde_json::Error> {
        let mut msg = Self {
            tenant_id,
            event: event.to_string(),
            correlation_id,
            payload,
            timeout_ms,
            key_version: CURRENT_KEY_VERSION,
            nonce: Uuid::new_v4(),
            issued_at: now,
            hmac_signature: None,
        };
        let key = derive_tenant_key(master_key, tenant_id, CURRENT_KEY_VERSION);
        let bytes = canonical_bytes(&msg)?;
        msg.hmac_signature = Some(sign_payload(&key, &bytes));
        Ok(msg)
    }

    /// Verify an event's signature — the check an SDK reactor runtime performs
    /// before acting on anything in the payload.
    pub fn verify(&self, master_key: &[u8]) -> bool {
        if self.key_version < MIN_ACCEPTED_KEY_VERSION {
            return false;
        }
        let Some(sig) = self.hmac_signature.as_deref() else {
            return false;
        };
        let mut unsigned = self.clone();
        unsigned.hmac_signature = None;
        let Ok(bytes) = canonical_bytes(&unsigned) else {
            return false;
        };
        let key = derive_tenant_key(master_key, self.tenant_id, self.key_version);
        verify_payload(&key, &bytes, sig)
    }
}

impl ReactorReply {
    /// Sign this reply in place.
    pub fn sign(&mut self, master_key: &[u8]) -> Result<(), serde_json::Error> {
        self.hmac_signature = None;
        self.key_version = CURRENT_KEY_VERSION;
        let key = derive_tenant_key(master_key, self.tenant_id, CURRENT_KEY_VERSION);
        let bytes = canonical_bytes(self)?;
        self.hmac_signature = Some(sign_payload(&key, &bytes));
        Ok(())
    }

    fn signature_valid(&self, master_key: &[u8]) -> bool {
        let Some(sig) = self.hmac_signature.as_deref() else {
            return false;
        };
        let mut unsigned = self.clone();
        unsigned.hmac_signature = None;
        let Ok(bytes) = canonical_bytes(&unsigned) else {
            return false;
        };
        let key = derive_tenant_key(master_key, self.tenant_id, self.key_version);
        verify_payload(&key, &bytes, sig)
    }

    /// Turn a raw reply into an outcome, or say exactly why it is not one.
    ///
    /// Order matters and is deliberate: **identity, then freshness, then
    /// signature, then semantics.** Checking the patch allow-list before the
    /// signature would mean spending allow-list logic on bytes nobody
    /// authenticated, and — worse — would let an unauthenticated party learn
    /// which fields are accepted by watching which rejections come back
    /// differently.
    pub fn into_outcome(
        self,
        master_key: &[u8],
        expected_correlation: Uuid,
        expected_tenant: Uuid,
        spec: &ReactorEventSpec,
        now: DateTime<Utc>,
        skew: chrono::Duration,
    ) -> Result<ReactorOutcome, ReplyRejection> {
        if self.correlation_id != expected_correlation {
            return Err(ReplyRejection::WrongCorrelation);
        }
        if self.tenant_id != expected_tenant {
            return Err(ReplyRejection::TenantMismatch);
        }
        if self.event != spec.name {
            return Err(ReplyRejection::EventMismatch);
        }
        if self.key_version < MIN_ACCEPTED_KEY_VERSION {
            return Err(ReplyRejection::KeyVersionTooOld(self.key_version));
        }
        if !is_fresh(self.issued_at, now, skew) {
            return Err(ReplyRejection::Stale);
        }
        if !self.signature_valid(master_key) {
            return Err(ReplyRejection::BadSignature);
        }

        // `require_mfa` is only meaningful where there is a session about to
        // be issued. Accepting it elsewhere would mean a token-enrichment
        // reactor could set a flag the token path has no way to honour, and
        // the operation would proceed as if it had.
        if self.require_mfa && spec.name != "login.post_auth" {
            return Err(ReplyRejection::RequireMfaNotSupported);
        }

        match self.decision {
            ReplyDecision::Deny => Ok(ReactorOutcome::Deny {
                reason: self.reason.unwrap_or_else(|| "denied by reactor".into()),
            }),
            ReplyDecision::Allow => {
                if self.patch.is_some() {
                    // A patch attached to an `allow` is a reply whose author
                    // and whose reader disagree about what will happen. That
                    // is exactly the ambiguity to refuse rather than resolve.
                    return Err(ReplyRejection::MalformedMutation);
                }
                if self.require_mfa {
                    Ok(ReactorOutcome::RequireMfa)
                } else {
                    Ok(ReactorOutcome::Allow)
                }
            }
            ReplyDecision::Mutate => {
                if !spec.mutable {
                    return Err(ReplyRejection::NotMutable);
                }
                let patch = self.patch.ok_or(ReplyRejection::MalformedMutation)?;
                if patch.is_empty() {
                    return Err(ReplyRejection::MalformedMutation);
                }
                // No partial application: one forbidden key rejects the whole
                // reply. Applying the acceptable half would leave the reactor
                // author believing a field was set when it was dropped.
                for key in patch.keys() {
                    if !spec.patch_field_allowed(key) {
                        return Err(ReplyRejection::ForbiddenPatchField(key.clone()));
                    }
                }
                Ok(ReactorOutcome::Mutate { patch })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::reactor::event_spec;

    const MASTER: &[u8] = b"master-key-for-reactor-protocol-tests";
    const SKEW: i64 = 300;

    fn skew() -> chrono::Duration {
        chrono::Duration::seconds(SKEW)
    }

    fn reply(
        tenant: Uuid,
        corr: Uuid,
        event: &str,
        decision: ReplyDecision,
        now: DateTime<Utc>,
    ) -> ReactorReply {
        let mut r = ReactorReply {
            correlation_id: corr,
            tenant_id: tenant,
            event: event.into(),
            decision,
            reason: None,
            patch: None,
            require_mfa: false,
            key_version: CURRENT_KEY_VERSION,
            nonce: Uuid::new_v4(),
            issued_at: now,
            hmac_signature: None,
        };
        r.sign(MASTER).unwrap();
        r
    }

    fn resolve(
        r: ReactorReply,
        corr: Uuid,
        tenant: Uuid,
        event: &str,
        now: DateTime<Utc>,
    ) -> Result<ReactorOutcome, ReplyRejection> {
        r.into_outcome(
            MASTER,
            corr,
            tenant,
            event_spec(event).unwrap(),
            now,
            skew(),
        )
    }

    #[test]
    fn routing_keys_and_queue_names_are_tenant_scoped() {
        let t = Uuid::new_v4();
        let r = Uuid::new_v4();
        assert_eq!(
            routing_key(t, "token.pre_issue"),
            format!("{t}.token.pre_issue")
        );
        assert_eq!(queue_name(t, r), format!("axiam.reactor.q.{t}.{r}"));
    }

    #[test]
    fn an_event_verifies_under_its_own_tenant_key_and_no_other() {
        let tenant = Uuid::new_v4();
        let other = Uuid::new_v4();
        let msg = ReactorEventMessage::signed(
            MASTER,
            tenant,
            "token.pre_issue",
            Uuid::new_v4(),
            serde_json::json!({"sub": "alice"}),
            500,
            Utc::now(),
        )
        .unwrap();

        assert!(msg.verify(MASTER));
        assert!(!msg.verify(b"a different master key"));

        // The per-tenant subkey is what stops a reactor in tenant A from
        // replaying a captured event into tenant B.
        let mut cross = msg.clone();
        cross.tenant_id = other;
        assert!(!cross.verify(MASTER));
    }

    #[test]
    fn tampering_with_the_payload_invalidates_the_event() {
        let msg = ReactorEventMessage::signed(
            MASTER,
            Uuid::new_v4(),
            "token.pre_issue",
            Uuid::new_v4(),
            serde_json::json!({"sub": "alice"}),
            500,
            Utc::now(),
        )
        .unwrap();

        let mut tampered = msg.clone();
        tampered.payload = serde_json::json!({"sub": "root"});
        assert!(!tampered.verify(MASTER));

        // Extending the window an actor thinks it has is also tampering.
        let mut stretched = msg;
        stretched.timeout_ms = 60_000;
        assert!(!stretched.verify(MASTER));
    }

    #[test]
    fn an_unsigned_reply_is_not_a_reply() {
        let (t, c, now) = (Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        let mut r = reply(t, c, "login.post_auth", ReplyDecision::Allow, now);
        r.hmac_signature = None;
        assert_eq!(
            resolve(r, c, t, "login.post_auth", now),
            Err(ReplyRejection::BadSignature)
        );
    }

    #[test]
    fn a_reply_signed_with_the_wrong_key_is_rejected() {
        let (t, c, now) = (Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        let mut r = reply(t, c, "login.post_auth", ReplyDecision::Deny, now);
        r.sign(b"attacker's key").unwrap();
        assert_eq!(
            resolve(r, c, t, "login.post_auth", now),
            Err(ReplyRejection::BadSignature)
        );
    }

    /// A correctly signed reply for a *different* request must not be
    /// accepted for this one — the classic cross-request replay.
    #[test]
    fn a_reply_for_another_correlation_or_tenant_or_event_is_rejected() {
        let (t, c, now) = (Uuid::new_v4(), Uuid::new_v4(), Utc::now());

        let r = reply(t, c, "login.post_auth", ReplyDecision::Allow, now);
        assert_eq!(
            resolve(r, Uuid::new_v4(), t, "login.post_auth", now),
            Err(ReplyRejection::WrongCorrelation)
        );

        let r = reply(t, c, "login.post_auth", ReplyDecision::Allow, now);
        assert_eq!(
            resolve(r, c, Uuid::new_v4(), "login.post_auth", now),
            Err(ReplyRejection::TenantMismatch)
        );

        let r = reply(t, c, "login.post_auth", ReplyDecision::Allow, now);
        assert_eq!(
            resolve(r, c, t, "token.pre_issue", now),
            Err(ReplyRejection::EventMismatch)
        );
    }

    #[test]
    fn a_stale_reply_is_rejected_in_both_directions() {
        let (t, c, now) = (Uuid::new_v4(), Uuid::new_v4(), Utc::now());

        let old = now - chrono::Duration::seconds(SKEW + 1);
        let r = reply(t, c, "login.post_auth", ReplyDecision::Allow, old);
        assert_eq!(
            resolve(r, c, t, "login.post_auth", now),
            Err(ReplyRejection::Stale)
        );

        // A future timestamp is not "extra fresh" — a clock far ahead is the
        // shape of a captured reply held for later use.
        let future = now + chrono::Duration::seconds(SKEW + 1);
        let r = reply(t, c, "login.post_auth", ReplyDecision::Allow, future);
        assert_eq!(
            resolve(r, c, t, "login.post_auth", now),
            Err(ReplyRejection::Stale)
        );
    }

    #[test]
    fn a_v1_reply_is_rejected_before_anything_else_is_considered() {
        let (t, c, now) = (Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        let mut r = reply(t, c, "login.post_auth", ReplyDecision::Allow, now);
        r.key_version = 1;
        assert_eq!(
            resolve(r, c, t, "login.post_auth", now),
            Err(ReplyRejection::KeyVersionTooOld(1))
        );
    }

    #[test]
    fn a_valid_allow_and_deny_resolve() {
        let (t, c, now) = (Uuid::new_v4(), Uuid::new_v4(), Utc::now());

        assert_eq!(
            resolve(
                reply(t, c, "login.post_auth", ReplyDecision::Allow, now),
                c,
                t,
                "login.post_auth",
                now
            ),
            Ok(ReactorOutcome::Allow)
        );

        let mut denied = reply(t, c, "login.post_auth", ReplyDecision::Deny, now);
        denied.reason = Some("embargoed region".into());
        denied.sign(MASTER).unwrap();
        assert_eq!(
            resolve(denied, c, t, "login.post_auth", now),
            Ok(ReactorOutcome::Deny {
                reason: "embargoed region".into()
            })
        );
    }

    /// A deny with no reason still denies. The reason is for the audit trail,
    /// not for the decision — a reactor that refuses without explaining has
    /// still refused.
    #[test]
    fn a_deny_without_a_reason_still_denies() {
        let (t, c, now) = (Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        let outcome = resolve(
            reply(t, c, "grant.pre_assign", ReplyDecision::Deny, now),
            c,
            t,
            "grant.pre_assign",
            now,
        )
        .unwrap();
        assert!(!outcome.permits());
    }

    #[test]
    fn a_patch_inside_the_allow_list_is_applied() {
        let (t, c, now) = (Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        let mut r = reply(t, c, "token.pre_issue", ReplyDecision::Mutate, now);
        r.patch = Some(BTreeMap::from([
            ("ext.department".to_string(), "eng".to_string()),
            ("ext.cost_center".to_string(), "42".to_string()),
        ]));
        r.sign(MASTER).unwrap();

        let outcome = resolve(r, c, t, "token.pre_issue", now).unwrap();
        match outcome {
            ReactorOutcome::Mutate { patch } => {
                assert_eq!(patch.len(), 2);
                assert_eq!(patch["ext.department"], "eng");
            }
            other => panic!("expected a mutation, got {other:?}"),
        }
    }

    /// The claim the allow-list exists to make, asserted through the reply
    /// path rather than against the spec helper — a reactor cannot rewrite a
    /// standard claim even with a perfectly valid signature.
    #[test]
    fn a_signed_reply_still_cannot_rewrite_a_standard_claim() {
        let (t, c, now) = (Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        for claim in ["sub", "aud", "exp", "scope", "iss"] {
            let mut r = reply(t, c, "token.pre_issue", ReplyDecision::Mutate, now);
            r.patch = Some(BTreeMap::from([(claim.to_string(), "root".to_string())]));
            r.sign(MASTER).unwrap();

            assert_eq!(
                resolve(r, c, t, "token.pre_issue", now),
                Err(ReplyRejection::ForbiddenPatchField(claim.to_string())),
                "a reactor must not be able to set '{claim}' even when correctly signed"
            );
        }
    }

    /// No partial application: one bad key rejects the whole patch, including
    /// the fields that would have been fine.
    #[test]
    fn one_forbidden_field_rejects_the_entire_patch() {
        let (t, c, now) = (Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        let mut r = reply(t, c, "token.pre_issue", ReplyDecision::Mutate, now);
        r.patch = Some(BTreeMap::from([
            ("ext.department".to_string(), "eng".to_string()),
            ("sub".to_string(), "root".to_string()),
        ]));
        r.sign(MASTER).unwrap();

        assert!(matches!(
            resolve(r, c, t, "token.pre_issue", now),
            Err(ReplyRejection::ForbiddenPatchField(_))
        ));
    }

    #[test]
    fn a_veto_only_event_refuses_a_mutation_outright() {
        let (t, c, now) = (Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        for event in ["login.post_auth", "grant.pre_assign"] {
            let mut r = reply(t, c, event, ReplyDecision::Mutate, now);
            r.patch = Some(BTreeMap::from([("anything".into(), "x".into())]));
            r.sign(MASTER).unwrap();

            assert_eq!(
                resolve(r, c, t, event, now),
                Err(ReplyRejection::NotMutable),
                "{event} is veto-only"
            );
        }
    }

    #[test]
    fn a_mutate_without_a_patch_and_an_allow_with_one_are_both_malformed() {
        let (t, c, now) = (Uuid::new_v4(), Uuid::new_v4(), Utc::now());

        let r = reply(t, c, "token.pre_issue", ReplyDecision::Mutate, now);
        assert_eq!(
            resolve(r, c, t, "token.pre_issue", now),
            Err(ReplyRejection::MalformedMutation)
        );

        let mut empty = reply(t, c, "token.pre_issue", ReplyDecision::Mutate, now);
        empty.patch = Some(BTreeMap::new());
        empty.sign(MASTER).unwrap();
        assert_eq!(
            resolve(empty, c, t, "token.pre_issue", now),
            Err(ReplyRejection::MalformedMutation)
        );

        let mut allow_with_patch = reply(t, c, "token.pre_issue", ReplyDecision::Allow, now);
        allow_with_patch.patch = Some(BTreeMap::from([("ext.a".into(), "b".into())]));
        allow_with_patch.sign(MASTER).unwrap();
        assert_eq!(
            resolve(allow_with_patch, c, t, "token.pre_issue", now),
            Err(ReplyRejection::MalformedMutation)
        );
    }

    #[test]
    fn require_mfa_works_on_login_and_nowhere_else() {
        let (t, c, now) = (Uuid::new_v4(), Uuid::new_v4(), Utc::now());

        let mut ok = reply(t, c, "login.post_auth", ReplyDecision::Allow, now);
        ok.require_mfa = true;
        ok.sign(MASTER).unwrap();
        assert_eq!(
            resolve(ok, c, t, "login.post_auth", now),
            Ok(ReactorOutcome::RequireMfa)
        );

        let mut wrong = reply(t, c, "token.pre_issue", ReplyDecision::Allow, now);
        wrong.require_mfa = true;
        wrong.sign(MASTER).unwrap();
        assert_eq!(
            resolve(wrong, c, t, "token.pre_issue", now),
            Err(ReplyRejection::RequireMfaNotSupported)
        );
    }

    /// Every field that changes the outcome must be covered by the signature.
    /// Flipping any of them after signing has to invalidate the reply — this
    /// is the test that catches a field being added to the struct and left
    /// out of the signed body.
    #[test]
    fn every_outcome_bearing_field_is_covered_by_the_signature() {
        let (t, c, now) = (Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        let signed = reply(t, c, "login.post_auth", ReplyDecision::Allow, now);

        type Tamper = Box<dyn Fn(&mut ReactorReply)>;
        let mutations: Vec<(&str, Tamper)> = vec![
            (
                "decision",
                Box::new(|r: &mut ReactorReply| r.decision = ReplyDecision::Deny),
            ),
            (
                "reason",
                Box::new(|r: &mut ReactorReply| r.reason = Some("injected".into())),
            ),
            (
                "require_mfa",
                Box::new(|r: &mut ReactorReply| r.require_mfa = true),
            ),
            (
                "nonce",
                Box::new(|r: &mut ReactorReply| r.nonce = Uuid::new_v4()),
            ),
            (
                "patch",
                Box::new(|r: &mut ReactorReply| {
                    r.patch = Some(BTreeMap::from([("ext.a".into(), "b".into())]))
                }),
            ),
        ];

        for (field, mutate) in mutations {
            let mut tampered = signed.clone();
            mutate(&mut tampered);
            assert!(
                !tampered.signature_valid(MASTER),
                "changing '{field}' after signing must invalidate the reply"
            );
        }
    }
}
