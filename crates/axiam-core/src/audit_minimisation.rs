//! Deployment-wide minimisation of what reaches the append-only audit log
//! (T-110).
//!
//! # The problem this answers
//!
//! The audit log is append-only by design, which is in direct tension with the
//! Art. 17 erasure path AXIAM also offers: personal data written into it cannot
//! later be removed, only aged out. T-119 bounded the *retention* side — a
//! default 730-day sweep, the table's only deletion path. The collection side
//! was never configurable at all, so a deployment whose lawful basis does not
//! support holding a full client IP address for two years had nothing to turn
//! off.
//!
//! # What it does, and what it deliberately does not
//!
//! With minimisation on, two fields are reduced **before** the write, because
//! after it there is no second chance by construction:
//!
//! - `ip_address` is truncated to its `/24` (IPv4) or `/48` (IPv6) prefix. That
//!   keeps the network an action came from — enough to see a pattern, to
//!   correlate a burst, to answer "was this the office" — and drops the part
//!   that identifies a subscriber line or a device.
//! - a `user_agent` member of `metadata`, where a producer sets one, is reduced
//!   to a coarse family. A full user-agent string is a fingerprint; the family
//!   is the part an investigation actually reads.
//!
//! **It does not strip the structured metadata domain producers write**, and
//! that limit is the design rather than an omission.
//! `oauth2.refresh_token_replayed` names the client, its profile and the
//! disposition (T-254); a sensitive-scope release names the claim by name
//! (T-241); a JIT provision names the provider and the external subject
//! (T-161). Those are accountability evidence that other threats' mitigations
//! depend on. Dropping them would weaken three controls to narrow one, and
//! none of them is request metadata: the request-audit middleware collects
//! `http_status` and `authenticated` and nothing else, which is pinned by its
//! own test rather than left to habit.
//!
//! # Why deployment-wide and not per tenant
//!
//! Audit is an accountability control the deployment relies on, **including
//! against a tenant administrator**. A per-tenant switch would let a tenant
//! weaken the evidence that would be used to investigate that tenant. It is
//! the same argument that makes `sensitive_scopes_enabled` disable-only for a
//! tenant under T-241, applied to a control where the tenant is a possible
//! subject rather than a possible victim.
//!
//! Off by default, because turning it on reduces forensic precision and that
//! is a lawful-basis judgement a deployment must make deliberately rather than
//! inherit.

use std::net::IpAddr;

use crate::models::audit::CreateAuditLogEntry;

/// Whether a deployment minimises what it collects into the audit log.
///
/// Built once at the composition root from `AXIAM__AUDIT__MINIMISE` and held
/// by the repository, so every producer passes through it — there are eighteen
/// of them, and only the repository is common to all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuditMinimisation {
    enabled: bool,
}

impl AuditMinimisation {
    /// `enabled = false` is today's behaviour and the default.
    #[must_use]
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Whether minimisation is in force. Logged at startup either way.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.enabled
    }

    /// Reduce an entry in place. A no-op when minimisation is off, which is
    /// what makes an unconfigured deployment byte-identical.
    pub fn apply(self, entry: &mut CreateAuditLogEntry) {
        if !self.enabled {
            return;
        }
        entry.ip_address = entry.ip_address.as_deref().and_then(truncate_ip);
        if let Some(serde_json::Value::Object(map)) = entry.metadata.as_mut()
            && let Some(agent) = map.get("user_agent").and_then(serde_json::Value::as_str)
        {
            let family = user_agent_family(agent).to_owned();
            map.insert("user_agent".into(), serde_json::Value::String(family));
        }
    }
}

/// Truncate an address to its `/24` (IPv4) or `/48` (IPv6) prefix.
///
/// Returns `None` for anything that does not parse as an address, and that is
/// the load-bearing case: a value which cannot be parsed cannot be shown to
/// have been minimised, and passing it through would be a silent hole in the
/// control. Dropping it costs one field on a row whose `action`, `actor_id`
/// and `outcome` are unaffected.
///
/// `realip_remote_addr` can hand back a `host:port` string, so a single
/// trailing `:port` on an IPv4 address is stripped first. An IPv6 address is
/// only accepted in its bracketed form when a port is present, because
/// `::1:8080` is a valid address in its own right and guessing would corrupt
/// it.
#[must_use]
pub fn truncate_ip(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let candidate = if let Some(rest) = trimmed.strip_prefix('[') {
        // `[2001:db8::1]:8080` or `[2001:db8::1]`
        rest.split(']').next()?
    } else if trimmed.matches(':').count() == 1 {
        // Exactly one colon can only be `v4:port` — an IPv6 address always has
        // at least two.
        trimmed.split(':').next()?
    } else {
        trimmed
    };

    match candidate.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            Some(format!("{a}.{b}.{c}.0/24"))
        }
        IpAddr::V6(v6) => {
            // A v4-mapped address is a v4 address wearing a hat; minimise it
            // as what it is, or the same client reaches the log at two
            // different granularities depending on the socket family.
            if let Some(v4) = v6.to_ipv4_mapped() {
                let [a, b, c, _] = v4.octets();
                return Some(format!("{a}.{b}.{c}.0/24"));
            }
            let s = v6.segments();
            Some(format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2]))
        }
    }
}

/// A coarse family for a user-agent string.
///
/// Total, dependency-free, and deliberately crude. A user-agent parsing
/// library exists to recover precision, which is the precise thing being
/// removed here — using one would be working against the control.
///
/// Order matters: every mainstream browser claims to be several others, so the
/// most specific claim is checked first.
#[must_use]
pub fn user_agent_family(raw: &str) -> &'static str {
    let ua = raw.to_ascii_lowercase();
    for (needle, family) in [
        ("edg/", "Edge"),
        ("opr/", "Opera"),
        ("firefox/", "Firefox"),
        ("chrome/", "Chrome"),
        ("safari/", "Safari"),
        ("curl/", "curl"),
        ("wget/", "Wget"),
        ("python-requests", "python-requests"),
        ("okhttp", "OkHttp"),
        ("go-http-client", "Go"),
        ("postmanruntime", "Postman"),
        ("axiam", "AXIAM SDK"),
    ] {
        if ua.contains(needle) {
            return family;
        }
    }
    "other"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::audit::{ActorType, AuditOutcome};
    use uuid::Uuid;

    fn entry(ip: Option<&str>, metadata: Option<serde_json::Value>) -> CreateAuditLogEntry {
        CreateAuditLogEntry {
            tenant_id: Uuid::new_v4(),
            actor_id: Uuid::new_v4(),
            actor_type: ActorType::User,
            action: "POST /api/v1/users".into(),
            resource_id: None,
            outcome: AuditOutcome::Success,
            ip_address: ip.map(str::to_owned),
            metadata,
        }
    }

    #[test]
    fn ipv4_keeps_the_network_and_drops_the_host() {
        assert_eq!(
            truncate_ip("203.0.113.42").as_deref(),
            Some("203.0.113.0/24")
        );
        assert_eq!(truncate_ip("  10.1.2.3  ").as_deref(), Some("10.1.2.0/24"));
    }

    /// `realip_remote_addr` hands back a `host:port` string on some
    /// configurations, and a value that failed to parse would be dropped
    /// rather than minimised — which is correct but loses a field nobody
    /// needed to lose.
    #[test]
    fn a_port_suffix_does_not_defeat_it() {
        assert_eq!(
            truncate_ip("203.0.113.42:54321").as_deref(),
            Some("203.0.113.0/24")
        );
        assert_eq!(
            truncate_ip("[2001:db8:1234:5678::1]:443").as_deref(),
            Some("2001:db8:1234::/48")
        );
        assert_eq!(
            truncate_ip("[2001:db8:1234:5678::1]").as_deref(),
            Some("2001:db8:1234::/48")
        );
    }

    #[test]
    fn ipv6_keeps_the_first_three_groups() {
        assert_eq!(
            truncate_ip("2001:db8:abcd:0012::1").as_deref(),
            Some("2001:db8:abcd::/48")
        );
        // An unbracketed v6 with two or more colons is taken whole — `::1` has
        // no port and guessing one would corrupt it.
        assert_eq!(truncate_ip("::1").as_deref(), Some("0:0:0::/48"));
    }

    /// A v4-mapped v6 address is a v4 address. Minimising it as a v6 one would
    /// give the same client two different granularities depending on the
    /// socket family the listener happened to accept it on.
    #[test]
    fn a_v4_mapped_address_is_minimised_as_v4() {
        assert_eq!(
            truncate_ip("::ffff:203.0.113.42").as_deref(),
            Some("203.0.113.0/24")
        );
    }

    /// The one that must fail closed: a value that cannot be parsed cannot be
    /// shown to have been minimised, so it is dropped rather than written
    /// through.
    #[test]
    fn an_unparseable_address_is_dropped_rather_than_passed_through() {
        for bad in ["not-an-ip", "", "   ", "203.0.113", "gibberish:1:2:3"] {
            assert_eq!(truncate_ip(bad), None, "{bad:?} must not pass through");
        }
    }

    #[test]
    fn user_agent_families_prefer_the_most_specific_claim() {
        // Edge and Opera both claim Chrome and Safari; Chrome claims Safari.
        assert_eq!(
            user_agent_family(
                "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120 Safari/537.36 Edg/120"
            ),
            "Edge"
        );
        assert_eq!(
            user_agent_family("Mozilla/5.0 AppleWebKit/537.36 Chrome/120 Safari/537.36"),
            "Chrome"
        );
        assert_eq!(user_agent_family("curl/8.5.0"), "curl");
        assert_eq!(user_agent_family("something nobody has seen"), "other");
    }

    #[test]
    fn minimisation_on_truncates_both_fields() {
        let mut e = entry(
            Some("203.0.113.42"),
            Some(serde_json::json!({
                "http_status": 200,
                "user_agent": "Mozilla/5.0 (X11; Linux) Firefox/128.0",
            })),
        );
        AuditMinimisation::new(true).apply(&mut e);
        assert_eq!(e.ip_address.as_deref(), Some("203.0.113.0/24"));
        assert_eq!(e.metadata.as_ref().unwrap()["user_agent"], "Firefox");
        // And leaves the structured accountability metadata exactly alone.
        assert_eq!(e.metadata.as_ref().unwrap()["http_status"], 200);
    }

    /// **I4 twin.** Off is the default, and off must be indistinguishable from
    /// the code that existed before this module.
    #[test]
    fn minimisation_off_changes_nothing() {
        let original = entry(
            Some("203.0.113.42"),
            Some(serde_json::json!({ "user_agent": "curl/8.5.0" })),
        );
        let mut e = original.clone();
        AuditMinimisation::default().apply(&mut e);
        assert_eq!(e.ip_address, original.ip_address);
        assert_eq!(e.metadata, original.metadata);
        assert!(!AuditMinimisation::default().is_enabled());
    }

    /// Accountability metadata other threats' mitigations depend on is not
    /// request metadata and is never touched — T-254's replay record, T-241's
    /// released claim names, T-161's federated subject.
    #[test]
    fn structured_accountability_metadata_survives_minimisation() {
        let mut e = entry(
            Some("203.0.113.42"),
            Some(serde_json::json!({
                "client_id": "oa_reporting",
                "profile": "fapi2",
                "disposition": "grace_accepted",
                "claims": ["email", "name"],
            })),
        );
        let before = e.metadata.clone();
        AuditMinimisation::new(true).apply(&mut e);
        assert_eq!(
            e.metadata, before,
            "minimisation must not strip a producer's structured metadata"
        );
    }
}
