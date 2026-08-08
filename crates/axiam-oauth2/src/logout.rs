//! OIDC RP-Initiated Logout 1.0 and Back-Channel Logout 1.0 — B5.
//!
//! # Why the two exist together
//!
//! A federation deployment is AXIAM plus N relying parties. Each half closes a
//! hole the other leaves:
//!
//! - Without RP-initiated logout, a user who logs out of an RP stays logged in
//!   at AXIAM, so the next "Login with AXIAM" silently re-authenticates them.
//!   From the user's point of view they did not log out.
//! - Without back-channel logout, a user who logs out **of AXIAM** stays
//!   logged in at every RP, indefinitely, because nothing tells the RPs. This
//!   is the one that matters: an admin revoking a compromised account leaves N
//!   live sessions behind.
//!
//! # Session precision
//!
//! Both halves operate on a **session**, not a user. A user with a phone and a
//! laptop who logs out on the laptop expects the phone to stay signed in, and
//! RP-Initiated Logout 1.0 §2 agrees. That is why the ID token carries `sid`
//! and why the logout token always names it.

use axiam_auth::config::AuthConfig;
use axiam_auth::error::AuthError;
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

/// The `events` member every logout token must carry (Back-Channel Logout 1.0
/// §2.4).
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// How long a logout token stays valid.
///
/// A logout token is delivered immediately or not at all, so its lifetime only
/// has to cover one HTTP request plus clock skew. A long-lived one is a
/// replayable session-termination command.
pub const LOGOUT_TOKEN_LIFETIME_SECS: i64 = 120;

/// Claims of an OIDC back-channel logout token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutTokenClaims {
    pub iss: String,
    /// The receiving client. One token per client, because `aud` names one.
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    /// Replay identifier the RP is required to track.
    pub jti: String,
    /// The session that ended. AXIAM always sends this — see the module docs.
    pub sid: String,
    pub sub: String,
    /// `{ "http://schemas.openid.net/event/backchannel-logout": {} }`.
    ///
    /// This member is what distinguishes a logout token from an ID token, and
    /// the receiving RP is required to check it.
    pub events: Map<String, Value>,
}

/// Build the `events` claim.
fn logout_events() -> Map<String, Value> {
    let mut events = Map::new();
    events.insert(
        BACKCHANNEL_LOGOUT_EVENT.to_string(),
        Value::Object(Map::new()),
    );
    events
}

/// Issue a signed back-channel logout token for one client.
///
/// Deliberately **not** given a `nonce` parameter. Back-Channel Logout 1.0 §2.4
/// forbids the claim, and its presence is the documented way an attacker
/// replays an ID token as a logout token. Making it un-passable is stronger
/// than remembering not to pass it.
pub fn issue_logout_token(
    issuer: &str,
    client_id: &str,
    session_id: Uuid,
    user_id: Uuid,
    config: &AuthConfig,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    let claims = LogoutTokenClaims {
        iss: issuer.to_string(),
        aud: client_id.to_string(),
        iat: now,
        exp: now + LOGOUT_TOKEN_LIFETIME_SECS,
        jti: Uuid::new_v4().to_string(),
        sid: session_id.to_string(),
        sub: user_id.to_string(),
        events: logout_events(),
    };

    let owned;
    let key: &EncodingKey = if let Some(ref cached) = config.jwt_encoding_key {
        cached.as_ref()
    } else {
        owned = EncodingKey::from_ed_pem(config.jwt_private_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;
        &owned
    };
    jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), &claims, key)
        .map_err(|e| AuthError::Crypto(format!("logout token encode: {e}")))
}

/// What the end-session endpoint decided to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogoutOutcome {
    /// Session ended; send the browser to this URI (with `state` appended when
    /// the RP supplied one).
    Redirect { uri: String, state: Option<String> },
    /// Session ended; render AXIAM's own logged-out page.
    ///
    /// This is **not** an error path. It is what happens when the RP supplied
    /// no `post_logout_redirect_uri`, or supplied one that is not on its
    /// allow-list. Refusing to log the user out because their RP sent a bad
    /// parameter would be the wrong failure: they asked to log out, and they
    /// are logged out.
    Rendered,
}

/// Resolve where to send the browser after a logout.
///
/// The allow-list check is **exact string equality** — no prefix matching, no
/// wildcards, no scheme or host normalisation — the same discipline
/// `redirect_uris` already uses. `post_logout_redirect_uri` is reachable
/// without authentication by design, so a loose match here is an open redirect
/// on an unauthenticated endpoint.
pub fn resolve_post_logout_redirect(
    requested: Option<&str>,
    allow_list: &[String],
    state: Option<&str>,
) -> LogoutOutcome {
    match requested {
        Some(uri) if allow_list.iter().any(|a| a == uri) => LogoutOutcome::Redirect {
            uri: uri.to_string(),
            state: state.map(str::to_owned),
        },
        // Includes both "no URI requested" and "URI not on the allow-list".
        // `state` is echoed only on a redirect that actually happens — there
        // is nowhere to echo it to otherwise, and it is never interpreted.
        _ => LogoutOutcome::Rendered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_auth::token::validate_access_token;
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};

    // Test-only Ed25519 keypair with no real-world value; the same fixed pair
    // the crate's other suites use, so no dev-dependency on a key generator.
    // nosemgrep
    const TEST_PRIVATE_KEY_PEM: &str = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n",
        "-----END PRIVATE KEY-----"
    ); // gitleaks:allow
    const TEST_PUBLIC_KEY_PEM: &str = concat!(
        "-----BEGIN PUBLIC KEY-----\n",
        "MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n",
        "-----END PUBLIC KEY-----"
    );

    fn test_config() -> AuthConfig {
        AuthConfig {
            jwt_private_key_pem: TEST_PRIVATE_KEY_PEM.into(),
            jwt_public_key_pem: TEST_PUBLIC_KEY_PEM.into(),
            jwt_issuer: "axiam-test".into(),
            oauth2_issuer_url: "https://id.test.example".into(),
            ..AuthConfig::default()
        }
    }

    fn decode(token: &str, config: &AuthConfig, aud: &str) -> LogoutTokenClaims {
        let key = DecodingKey::from_ed_pem(config.jwt_public_key_pem.as_bytes()).unwrap();
        let mut v = Validation::new(Algorithm::EdDSA);
        v.set_audience(&[aud]);
        v.set_issuer(&["https://id.test.example"]);
        jsonwebtoken::decode::<LogoutTokenClaims>(token, &key, &v)
            .unwrap()
            .claims
    }

    #[test]
    fn logout_token_carries_the_exact_events_member() {
        let cfg = test_config();
        let sid = Uuid::new_v4();
        let sub = Uuid::new_v4();
        let t = issue_logout_token("https://id.test.example", "rp-1", sid, sub, &cfg).unwrap();
        let c = decode(&t, &cfg, "rp-1");

        // The RP is required to check this; an empty or differently-keyed
        // events member makes the token indistinguishable from an ID token.
        assert_eq!(c.events.len(), 1);
        let member = c.events.get(BACKCHANNEL_LOGOUT_EVENT).expect("events key");
        assert_eq!(member, &Value::Object(Map::new()));
    }

    #[test]
    fn logout_token_has_no_nonce_claim() {
        // Back-Channel Logout 1.0 §2.4 forbids `nonce`; its presence is how an
        // ID token gets replayed as a logout token.
        let cfg = test_config();
        let t = issue_logout_token(
            "https://id.test.example",
            "rp-1",
            Uuid::new_v4(),
            Uuid::new_v4(),
            &cfg,
        )
        .unwrap();
        let payload = t.split('.').nth(1).unwrap();
        use base64::Engine;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap();
        let json: Value = serde_json::from_slice(&raw).unwrap();
        assert!(
            json.get("nonce").is_none(),
            "a logout token must not carry nonce, got {json}"
        );
    }

    #[test]
    fn logout_token_always_names_the_session() {
        let cfg = test_config();
        let sid = Uuid::new_v4();
        let t = issue_logout_token("https://id.test.example", "rp-1", sid, Uuid::new_v4(), &cfg)
            .unwrap();
        // `sub` alone would tell the RP to end every session it holds for the
        // user, which is not what happened.
        assert_eq!(decode(&t, &cfg, "rp-1").sid, sid.to_string());
    }

    #[test]
    fn logout_token_is_short_lived() {
        let cfg = test_config();
        let t = issue_logout_token(
            "https://id.test.example",
            "rp-1",
            Uuid::new_v4(),
            Uuid::new_v4(),
            &cfg,
        )
        .unwrap();
        let c = decode(&t, &cfg, "rp-1");
        assert_eq!(c.exp - c.iat, LOGOUT_TOKEN_LIFETIME_SECS);
        const {
            assert!(LOGOUT_TOKEN_LIFETIME_SECS <= 300);
        }
    }

    #[test]
    fn each_logout_token_has_its_own_jti() {
        let cfg = test_config();
        let sid = Uuid::new_v4();
        let sub = Uuid::new_v4();
        let a = issue_logout_token("https://id.test.example", "rp-1", sid, sub, &cfg).unwrap();
        let b = issue_logout_token("https://id.test.example", "rp-1", sid, sub, &cfg).unwrap();
        assert_ne!(decode(&a, &cfg, "rp-1").jti, decode(&b, &cfg, "rp-1").jti);
    }

    #[test]
    fn a_logout_token_is_not_accepted_as_an_access_token() {
        // The two are signed by the same key, so what must separate them is
        // the claim set. If this ever passes, a logout token has become a
        // bearer credential.
        let cfg = test_config();
        let t = issue_logout_token(
            "https://id.test.example",
            "rp-1",
            Uuid::new_v4(),
            Uuid::new_v4(),
            &cfg,
        )
        .unwrap();
        assert!(validate_access_token(&t, &cfg).is_err());
    }

    #[test]
    fn an_exact_allow_list_match_redirects_and_echoes_state() {
        let allow = vec!["https://rp.example/done".to_string()];
        assert_eq!(
            resolve_post_logout_redirect(Some("https://rp.example/done"), &allow, Some("xyz")),
            LogoutOutcome::Redirect {
                uri: "https://rp.example/done".into(),
                state: Some("xyz".into()),
            }
        );
    }

    #[test]
    fn a_prefix_match_does_not_count() {
        // The classic open-redirect shape: the attacker registers a prefix and
        // appends. Exact equality is the only match that is safe here.
        let allow = vec!["https://rp.example/done".to_string()];
        assert_eq!(
            resolve_post_logout_redirect(Some("https://rp.example/done/../../evil"), &allow, None),
            LogoutOutcome::Rendered
        );
        assert_eq!(
            resolve_post_logout_redirect(Some("https://rp.example/done2"), &allow, None),
            LogoutOutcome::Rendered
        );
    }

    #[test]
    fn a_scheme_downgrade_does_not_count() {
        let allow = vec!["https://rp.example/done".to_string()];
        assert_eq!(
            resolve_post_logout_redirect(Some("http://rp.example/done"), &allow, None),
            LogoutOutcome::Rendered
        );
    }

    #[test]
    fn an_empty_allow_list_never_redirects() {
        assert_eq!(
            resolve_post_logout_redirect(Some("https://rp.example/done"), &[], Some("xyz")),
            LogoutOutcome::Rendered
        );
    }

    #[test]
    fn state_is_not_echoed_when_there_is_no_redirect() {
        // There is nowhere to echo it to, and carrying it into the rendered
        // page would put an RP-controlled string in AXIAM's own response.
        let allow = vec!["https://rp.example/done".to_string()];
        let outcome =
            resolve_post_logout_redirect(Some("https://elsewhere.example"), &allow, Some("xyz"));
        assert_eq!(outcome, LogoutOutcome::Rendered);
    }
}
