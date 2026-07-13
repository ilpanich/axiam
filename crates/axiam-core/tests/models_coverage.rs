//! Coverage for pure domain-model logic: secret-redacting `Debug` impls,
//! enum string conversions, settings scope parsing, and tenant-override
//! validation branches. All pure — no external services.

use std::str::FromStr;

use axiam_core::models::certificate::{
    CaCertificate, CertificateStatus, GeneratedCaCertificate, KeyAlgorithm,
};
use axiam_core::models::settings::{
    SettingsScope, TenantSettingsOverride, settings_from_org_input, system_defaults,
    validate_tenant_override,
};
use axiam_core::models::webauthn_credential::WebauthnCredentialType;
use axiam_core::models::webhook::{CreateWebhook, RetryPolicy, UpdateWebhook, Webhook};
use chrono::Utc;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// webhook.rs
// ---------------------------------------------------------------------------

fn sample_webhook() -> Webhook {
    Webhook {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        url: "https://hooks.example.com/x".into(),
        events: vec!["user.created".into()],
        secret: "super-secret-hmac".into(),
        enabled: true,
        retry_policy: RetryPolicy::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn retry_policy_default_values() {
    let p = RetryPolicy::default();
    assert_eq!(p.max_retries, 5);
    assert_eq!(p.initial_delay_secs, 10);
    assert_eq!(p.backoff_multiplier, 2.0);
}

#[test]
fn webhook_debug_redacts_secret() {
    let wh = sample_webhook();
    let dbg = format!("{wh:?}");
    assert!(dbg.contains("[REDACTED]"));
    assert!(!dbg.contains("super-secret-hmac"));
    assert!(dbg.contains("hooks.example.com"));
}

#[test]
fn webhook_serialize_skips_secret() {
    let wh = sample_webhook();
    let json = serde_json::to_string(&wh).unwrap();
    assert!(!json.contains("super-secret-hmac"));
    assert!(json.contains("hooks.example.com"));
}

#[test]
fn create_webhook_debug_redacts_secret() {
    let cw = CreateWebhook {
        tenant_id: Uuid::new_v4(),
        url: "https://h/x".into(),
        events: vec!["a".into()],
        secret: "plaintext-secret".into(),
        retry_policy: None,
    };
    let dbg = format!("{cw:?}");
    assert!(dbg.contains("[REDACTED]"));
    assert!(!dbg.contains("plaintext-secret"));
}

#[test]
fn update_webhook_debug_redacts_secret_when_present_and_absent() {
    let with_secret = UpdateWebhook {
        secret: Some("rotated".into()),
        ..Default::default()
    };
    let d1 = format!("{with_secret:?}");
    assert!(d1.contains("[REDACTED]"));
    assert!(!d1.contains("rotated"));

    let without = UpdateWebhook::default();
    let d2 = format!("{without:?}");
    // secret: None => the map(|_| ...) yields None
    assert!(d2.contains("None"));
}

// ---------------------------------------------------------------------------
// webauthn_credential.rs
// ---------------------------------------------------------------------------

#[test]
fn webauthn_credential_type_as_str() {
    assert_eq!(WebauthnCredentialType::Passkey.as_str(), "Passkey");
    assert_eq!(WebauthnCredentialType::SecurityKey.as_str(), "SecurityKey");
}

#[test]
fn webauthn_credential_type_serde_roundtrip() {
    for v in [
        WebauthnCredentialType::Passkey,
        WebauthnCredentialType::SecurityKey,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: WebauthnCredentialType = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ---------------------------------------------------------------------------
// certificate.rs (redacting Debug impls)
// ---------------------------------------------------------------------------

fn sample_ca() -> CaCertificate {
    CaCertificate {
        id: Uuid::new_v4(),
        organization_id: Uuid::new_v4(),
        subject: "CN=Root".into(),
        public_cert_pem: "-----BEGIN CERTIFICATE-----".into(),
        fingerprint: "ab:cd".into(),
        key_algorithm: KeyAlgorithm::Ed25519,
        not_before: Utc::now(),
        not_after: Utc::now(),
        status: CertificateStatus::Active,
        encrypted_private_key: Some(vec![1, 2, 3, 4]),
        created_at: Utc::now(),
    }
}

#[test]
fn ca_certificate_debug_redacts_private_key() {
    let ca = sample_ca();
    let dbg = format!("{ca:?}");
    assert!(dbg.contains("[REDACTED]"));
    assert!(dbg.contains("CN=Root"));
    // The raw key bytes must not appear.
    assert!(!dbg.contains("[1, 2, 3, 4]"));
}

#[test]
fn ca_certificate_debug_none_private_key() {
    let mut ca = sample_ca();
    ca.encrypted_private_key = None;
    let dbg = format!("{ca:?}");
    assert!(dbg.contains("None"));
}

#[test]
fn generated_ca_certificate_debug_redacts_private_key_pem() {
    let generated = GeneratedCaCertificate {
        certificate: sample_ca(),
        private_key_pem: "-----BEGIN PRIVATE KEY-----SENSITIVE".into(),
    };
    let dbg = format!("{generated:?}");
    assert!(dbg.contains("[REDACTED]"));
    assert!(!dbg.contains("SENSITIVE"));
}

// ---------------------------------------------------------------------------
// settings.rs — SettingsScope Display / FromStr
// ---------------------------------------------------------------------------

#[test]
fn settings_scope_display() {
    assert_eq!(SettingsScope::Org.to_string(), "org");
    assert_eq!(SettingsScope::Tenant.to_string(), "tenant");
}

#[test]
fn settings_scope_from_str() {
    assert_eq!(SettingsScope::from_str("org").unwrap(), SettingsScope::Org);
    assert_eq!(
        SettingsScope::from_str("tenant").unwrap(),
        SettingsScope::Tenant
    );
    let err = SettingsScope::from_str("bogus").unwrap_err();
    assert!(err.contains("invalid settings scope"));
}

#[test]
fn tenant_override_is_empty() {
    assert!(TenantSettingsOverride::default().is_empty());
    let o = TenantSettingsOverride {
        min_length: Some(20),
        ..Default::default()
    };
    assert!(!o.is_empty());
}

// ---------------------------------------------------------------------------
// settings.rs — validate_tenant_override
// ---------------------------------------------------------------------------

fn org_baseline() -> axiam_core::models::settings::SecuritySettings {
    settings_from_org_input(Uuid::new_v4(), Uuid::new_v4(), &system_defaults())
}

#[test]
fn empty_override_passes_validation() {
    let org = org_baseline();
    assert!(validate_tenant_override(&org, &TenantSettingsOverride::default()).is_ok());
}

#[test]
fn many_less_restrictive_overrides_are_rejected() {
    let org = org_baseline();
    let overrides = TenantSettingsOverride {
        // check_min violations (below org baseline)
        min_length: Some(1),
        password_history_count: Some(0),
        lockout_duration_secs: Some(0),
        max_lockout_duration_secs: Some(0),
        lockout_backoff_multiplier: Some(0.0),
        // check_max violations (above org baseline)
        max_failed_login_attempts: Some(u32::MAX),
        access_token_lifetime_secs: Some(u64::MAX),
        refresh_token_lifetime_secs: Some(u64::MAX),
        mfa_challenge_lifetime_secs: Some(u64::MAX),
        default_cert_validity_days: Some(u32::MAX),
        max_cert_validity_days: Some(u32::MAX),
        email_verification_grace_period_hours: Some(u32::MAX),
        // enable-only violations (disable where org enabled)
        require_uppercase: Some(false),
        require_lowercase: Some(false),
        require_digits: Some(false),
        require_symbols: Some(false),
        mfa_enforced: Some(false),
        hibp_check_enabled: Some(false),
        email_verification_required: Some(false),
        admin_notifications_enabled: Some(false),
    };
    let err = validate_tenant_override(&org, &overrides)
        .unwrap_err()
        .to_string();
    assert!(err.contains("less restrictive") || err.contains("cannot disable"));
}

#[test]
fn override_producing_zero_lifetime_is_inconsistent() {
    let org = org_baseline();
    // 0 passes the "more restrictive" check_max (0 <= org) but yields an
    // unusable effective policy, tripping the cross-field invariant branch.
    let overrides = TenantSettingsOverride {
        access_token_lifetime_secs: Some(0),
        ..Default::default()
    };
    let err = validate_tenant_override(&org, &overrides)
        .unwrap_err()
        .to_string();
    assert!(err.contains("must be > 0") || err.contains("inconsistent"));
}
