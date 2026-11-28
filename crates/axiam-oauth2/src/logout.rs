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
use jsonwebtoken::Algorithm;
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

    // SA-03 — explicitly typed (`logout+jwt`), as Back-Channel Logout 1.0 §2.4
    // recommends, so no verifier of another AXIAM token kind can mistake it
    // for its own. #880 (contract 1.69) — and naming its JWKS `kid`, because a
    // relying party selects the verification key by it.
    axiam_auth::token::sign_logout_token(&claims, config)
}

/// The parts of an `id_token_hint` the end-session endpoint acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdTokenHint {
    /// The session to end. `None` when the token predates `sid` (B5).
    pub session_id: Option<Uuid>,
    /// The client the token was issued to — the allow-list to check the
    /// `post_logout_redirect_uri` against.
    pub client_id: String,
    pub subject_id: Option<Uuid>,
}

/// Decode an `id_token_hint`.
///
/// Two validation choices, both deliberate:
///
/// - **Expiry is not checked.** An ID token presented here has routinely
///   expired already: the user is logging out, which commonly happens long
///   after a 15-minute token was minted. Rejecting expired hints would make
///   the hint useless exactly when it is most needed.
/// - **The signature IS checked.** That is what makes the hint an
///   authenticated statement of which session and client this is about rather
///   than a suggestion. Without it, anyone could name any session.
///
/// The header `typ` must be an ID token's (`JWT`, or absent), and the claims
/// must carry no member an ID token never has (`jti`, `purpose`, `scope`,
/// `client_id`): an access token — including one minted before SA-03 with
/// `typ: JWT` — a purpose token or a logout token is not a hint. See
/// [`axiam_auth::token::decode_id_token_hint_claims`].
///
/// `aud` is read out rather than validated against — there is no expected
/// value to compare to, since the client's identity is what we are learning.
///
/// Anything unverifiable returns `None` and is treated by the caller as an
/// absent hint, per RP-Initiated Logout 1.0 §2 — not as an error.
pub fn decode_id_token_hint(token: &str, public_key_pem: &str) -> Option<IdTokenHint> {
    use jsonwebtoken::{DecodingKey, Validation};

    let key = DecodingKey::from_ed_pem(public_key_pem.as_bytes()).ok()?;
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_exp = false;
    validation.validate_aud = false;

    // Q-8 / S-10, SR2-2: only an ID token is a hint. An access token's claims
    // fit `IdTokenClaims` (and carry `sid`), so the header and the claim set
    // must refuse it.
    let claims = axiam_auth::token::decode_id_token_hint_claims(token, &key, &validation)?;
    Some(IdTokenHint {
        session_id: claims.sid.as_deref().and_then(|s| Uuid::parse_str(s).ok()),
        client_id: claims.aud,
        subject_id: Uuid::parse_str(&claims.sub).ok(),
    })
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
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};

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
    /// A second Ed25519 public key: the other half of a key rotation.
    const OTHER_PUBLIC_KEY_PEM: &str = concat!(
        "-----BEGIN PUBLIC KEY-----\n",
        "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n",
        "-----END PUBLIC KEY-----"
    );

    fn test_config() -> AuthConfig {
        AuthConfig {
            jwt_private_key_pem: TEST_PRIVATE_KEY_PEM.into(),
            jwt_public_key_pem: TEST_PUBLIC_KEY_PEM.into(),
            jwt_issuer: "axiam-test".into(),
            oauth2_issuer_url: "https://id.test.example".into(),
            sso_spa_origins: Vec::new(),
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

    /// SA-03: the logout token is explicitly typed (BCL 1.0 §2.4) and no
    /// access-token verifier admits it.
    #[test]
    fn logout_token_is_typed_and_is_not_an_access_token() {
        let cfg = test_config();
        let t = issue_logout_token(
            "https://id.test.example",
            "rp-1",
            Uuid::new_v4(),
            Uuid::new_v4(),
            &cfg,
        )
        .unwrap();
        let header = jsonwebtoken::decode_header(&t).unwrap();
        assert_eq!(header.typ.as_deref(), Some("logout+jwt"));
        assert!(axiam_auth::token::decode_access_token(&t, &cfg).is_err());
    }

    /// #880 (D-1, contract 1.69): the header names the JWKS key that signed
    /// the token, and is exactly the server shape an SDK's logout test
    /// fixture must reproduce — `alg`, `typ` and `kid`, nothing else.
    #[test]
    fn logout_token_header_names_its_jwks_key() {
        let cfg = test_config();
        let t = issue_logout_token(
            "https://id.test.example",
            "rp-1",
            Uuid::new_v4(),
            Uuid::new_v4(),
            &cfg,
        )
        .unwrap();
        let header = jsonwebtoken::decode_header(&t).unwrap();
        let published = crate::oidc::build_jwks(&cfg.jwt_public_key_pem).unwrap();
        assert_eq!(
            header.kid.as_deref(),
            Some(published.keys[0].kid.as_str()),
            "a logout token must name the kid /oauth2/jwks publishes for its key"
        );
        assert_eq!(header.typ.as_deref(), Some("logout+jwt"));
        assert_eq!(header.alg, Algorithm::EdDSA);

        use base64::Engine;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(t.split('.').next().unwrap())
            .unwrap();
        let members: Map<String, Value> = serde_json::from_slice(&raw).unwrap();
        let mut names: Vec<&str> = members.keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(names, ["alg", "kid", "typ"], "header {members:?}");
    }

    /// #880: verify the way a relying party does — read the JWKS as
    /// `/oauth2/jwks` serves it, during a rotation (two keys), select the key
    /// **by `kid`** and nothing else, then verify. Before contract 1.69 the
    /// token named no key, so a strictly-by-`kid` verifier found none.
    #[test]
    fn a_relying_party_selects_the_logout_key_by_kid() {
        let cfg = test_config();
        let sid = Uuid::new_v4();
        let t = issue_logout_token("https://id.test.example", "rp-1", sid, Uuid::new_v4(), &cfg)
            .unwrap();

        // What the endpoint serves, plus the next key of a rotation.
        let mut served =
            serde_json::to_value(crate::oidc::build_jwks(&cfg.jwt_public_key_pem).unwrap())
                .unwrap();
        let next = crate::oidc::build_jwks(OTHER_PUBLIC_KEY_PEM).unwrap();
        served["keys"]
            .as_array_mut()
            .unwrap()
            .insert(0, serde_json::to_value(&next.keys[0]).unwrap());
        let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(served).unwrap();
        assert_eq!(jwks.keys.len(), 2);

        let header = jsonwebtoken::decode_header(&t).unwrap();
        let kid = header.kid.expect("a logout token must carry a kid");
        let jwk = jwks.find(&kid).expect("the kid must name a published key");
        let key = DecodingKey::from_jwk(jwk).unwrap();
        let mut v = Validation::new(Algorithm::EdDSA);
        v.set_audience(&["rp-1"]);
        v.set_issuer(&["https://id.test.example"]);
        let claims = jsonwebtoken::decode::<LogoutTokenClaims>(&t, &key, &v)
            .expect("the key the kid names verifies the token")
            .claims;
        assert_eq!(claims.sid, sid.to_string());

        // The other key of the rotation does not.
        let other = jwks
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() != Some(kid.as_str()))
            .unwrap();
        let other = DecodingKey::from_jwk(other).unwrap();
        assert!(jsonwebtoken::decode::<LogoutTokenClaims>(&t, &other, &v).is_err());
    }

    /// #880 security argument, the claim half: with a `kid`, a logout token is
    /// a token a strictly-by-`kid` verifier finds a key for, so what must keep
    /// it from being an access token is not the key lookup. The header refuses
    /// it (`typ`), and so — independently — does its claim set, which lacks
    /// the `tenant_id` and `org_id` every access token carries. Re-signed as
    /// `at+jwt`, addressed to `axiam:user` and issued by the root issuer (so
    /// neither `typ`, `aud` nor `iss` can be what refuses it), it is still
    /// refused by both decoders, strict and relaxed.
    #[test]
    fn a_logout_token_is_refused_as_an_access_token_by_its_claims_alone() {
        let cfg = test_config();
        let mut relaxed = cfg.clone();
        relaxed.require_access_token_typ = false;
        let t = issue_logout_token(
            cfg.root_issuer(),
            axiam_auth::token::AUD_USER,
            Uuid::new_v4(),
            Uuid::new_v4(),
            &cfg,
        )
        .unwrap();
        for typ in [Some("at+jwt"), Some("JWT"), None] {
            let reshaped = resign_with_typ(&t, typ, &cfg);
            for c in [&cfg, &relaxed] {
                assert!(
                    axiam_auth::token::decode_access_token(&reshaped, c).is_err(),
                    "typ {typ:?}, relaxed {}",
                    !c.require_access_token_typ
                );
                assert!(
                    axiam_auth::token::decode_access_token_any_audience(&reshaped, c).is_err(),
                    "typ {typ:?}, relaxed {}",
                    !c.require_access_token_typ
                );
            }
        }
        // And as minted, kid and all: refused in both modes.
        for c in [&cfg, &relaxed] {
            assert!(axiam_auth::token::decode_access_token(&t, c).is_err());
            assert!(axiam_auth::token::decode_access_token_any_audience(&t, c).is_err());
        }
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

    /// Q-8 / S-10: an `at+jwt` access token is not an ID token. Its claims
    /// fit `IdTokenClaims` (`sub`, `aud`, `iss`, `iat`, `exp`, and `sid`), so
    /// only the header can refuse it; before SA-03 review it named the
    /// session and the client to the end-session endpoint and to
    /// `/oauth2/authorize`'s hint.
    #[test]
    fn an_access_token_is_not_an_id_token_hint() {
        let cfg = test_config();
        let sid = Uuid::new_v4();
        let access = axiam_auth::token::AccessTokenSpec::user(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            sid.to_string(),
        )
        .aud("rp-1")
        .session(Some(sid))
        .issue(&cfg)
        .unwrap();
        assert_eq!(
            jsonwebtoken::decode_header(&access).unwrap().typ.as_deref(),
            Some(axiam_auth::token::TYP_ACCESS_TOKEN)
        );
        let hint = decode_id_token_hint(&access, &cfg.jwt_public_key_pem);
        assert_eq!(
            hint, None,
            "an at+jwt access token was accepted as an id_token_hint"
        );

        // Every other AXIAM kind is refused too; an untyped token (every ID
        // token before SA-03 was `JWT`) and a real ID token are not.
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "iss": cfg.root_issuer(), "sub": Uuid::new_v4().to_string(),
            "aud": "rp-1", "iat": now, "exp": now + 300,
        });
        let key = EncodingKey::from_ed_pem(cfg.jwt_private_key_pem.as_bytes()).unwrap();
        for (typ, accepted) in [
            (Some(axiam_auth::token::TYP_WEBAUTHN_STATE), false),
            (Some(axiam_auth::token::TYP_MFA_CHALLENGE), false),
            (Some(axiam_auth::token::TYP_MFA_SETUP), false),
            (Some(axiam_auth::token::TYP_LOGOUT_TOKEN), false),
            (Some("JWT"), true),
            (None, true),
        ] {
            let mut header = Header::new(Algorithm::EdDSA);
            header.typ = typ.map(str::to_owned);
            let token = jsonwebtoken::encode(&header, &claims, &key).unwrap();
            assert_eq!(
                decode_id_token_hint(&token, &cfg.jwt_public_key_pem).is_some(),
                accepted,
                "typ {typ:?}"
            );
        }
        let id = axiam_auth::token::issue_id_token(
            Uuid::new_v4(),
            "rp-1",
            None,
            None,
            &[],
            &cfg,
            Some(sid),
            &axiam_auth::token::IdTokenEvidence::NONE,
        )
        .unwrap();
        assert!(decode_id_token_hint(&id, &cfg.jwt_public_key_pem).is_some());
    }

    /// Re-sign `token`'s payload, unchanged, under `typ`: what an access token
    /// minted before SA-03 (`Header::new(EdDSA)`, so `typ: "JWT"`) looks like.
    fn resign_with_typ(token: &str, typ: Option<&str>, cfg: &AuthConfig) -> String {
        use base64::Engine;
        let payload = token.split('.').nth(1).unwrap();
        let claims: Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .unwrap(),
        )
        .unwrap();
        let key = EncodingKey::from_ed_pem(cfg.jwt_private_key_pem.as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = typ.map(str::to_owned);
        jsonwebtoken::encode(&header, &claims, &key).unwrap()
    }

    /// SR2-2: an access token minted before SA-03 carries `typ: "JWT"` (or
    /// none) and claims that fit `IdTokenClaims`, `sid` included. The header
    /// cannot refuse it, and the decoder skips `exp`, so without a claims rule
    /// every such token would name a session to the end-session endpoint and
    /// a subject to `/oauth2/authorize` forever. `jti` (and `purpose`,
    /// `scope`, `client_id`) is what no ID token has ever carried.
    #[test]
    fn a_legacy_untyped_access_token_is_not_an_id_token_hint() {
        let cfg = test_config();
        let sid = Uuid::new_v4();
        let access = axiam_auth::token::AccessTokenSpec::user(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            sid.to_string(),
        )
        .aud("rp-1")
        .session(Some(sid))
        .issue(&cfg)
        .unwrap();
        for typ in [Some("JWT"), None] {
            let legacy = resign_with_typ(&access, typ, &cfg);
            assert_eq!(
                decode_id_token_hint(&legacy, &cfg.jwt_public_key_pem),
                None,
                "a legacy (typ {typ:?}) access token was accepted as an id_token_hint"
            );
        }

        // Each access-token-only member alone refuses an otherwise ID-shaped,
        // untyped token.
        let now = chrono::Utc::now().timestamp();
        let key = EncodingKey::from_ed_pem(cfg.jwt_private_key_pem.as_bytes()).unwrap();
        for (member, value) in [
            ("jti", serde_json::json!(Uuid::new_v4().to_string())),
            ("purpose", serde_json::json!("webauthn_authentication")),
            ("scope", serde_json::json!("openid")),
            ("client_id", serde_json::json!("rp-1")),
        ] {
            let mut claims = serde_json::json!({
                "iss": cfg.root_issuer(), "sub": Uuid::new_v4().to_string(),
                "aud": "rp-1", "iat": now, "exp": now + 300, "sid": sid.to_string(),
            });
            claims[member] = value;
            let token =
                jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), &claims, &key).unwrap();
            assert_eq!(
                decode_id_token_hint(&token, &cfg.jwt_public_key_pem),
                None,
                "an untyped token carrying `{member}` was accepted as an id_token_hint"
            );
        }

        // A real ID token as minted today, every optional claim populated,
        // still is a hint.
        let sub = Uuid::new_v4();
        let id = axiam_auth::token::issue_id_token(
            sub,
            "rp-1",
            Some("n-0S6_WzA2Mj"),
            Some("alice"),
            &["openid".to_owned(), "profile".to_owned()],
            &cfg,
            Some(sid),
            &axiam_auth::token::IdTokenEvidence {
                auth_time: Some(now - 60),
                acr: Some("urn:axiam:acr:mfa".into()),
                amr: vec!["pwd".into(), "otp".into()],
            },
        )
        .unwrap();
        let hint = decode_id_token_hint(&id, &cfg.jwt_public_key_pem).expect("a real ID token");
        assert_eq!(hint.session_id, Some(sid));
        assert_eq!(hint.client_id, "rp-1");
        assert_eq!(hint.subject_id, Some(sub));
    }

    #[test]
    fn an_expired_id_token_hint_is_still_decoded() {
        // The common case: the user logs out well after their 15-minute token
        // expired. Rejecting it would make the hint useless when it matters.
        let cfg = test_config();
        let sid = Uuid::new_v4();
        let sub = Uuid::new_v4();
        let mut expired_cfg = cfg.clone();
        expired_cfg.access_token_lifetime_secs = 1;
        let token = axiam_auth::token::issue_id_token(
            sub,
            "rp-1",
            None,
            None,
            &[],
            &expired_cfg,
            Some(sid),
            &axiam_auth::token::IdTokenEvidence::NONE,
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let hint = decode_id_token_hint(&token, &cfg.jwt_public_key_pem).expect("decodes");
        assert_eq!(hint.session_id, Some(sid));
        assert_eq!(hint.client_id, "rp-1");
        assert_eq!(hint.subject_id, Some(sub));
    }

    #[test]
    fn a_hint_signed_by_another_key_is_rejected() {
        // The signature is what makes the hint a statement rather than a
        // suggestion; without this check anyone could name any session.
        let cfg = test_config();
        let token = axiam_auth::token::issue_id_token(
            Uuid::new_v4(),
            "rp-1",
            None,
            None,
            &[],
            &cfg,
            Some(Uuid::new_v4()),
            &axiam_auth::token::IdTokenEvidence::NONE,
        )
        .unwrap();
        let other = concat!(
            "-----BEGIN PUBLIC KEY-----\n",
            "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n",
            "-----END PUBLIC KEY-----"
        );
        assert!(decode_id_token_hint(&token, other).is_none());
    }

    #[test]
    fn garbage_is_treated_as_an_absent_hint() {
        let cfg = test_config();
        assert!(decode_id_token_hint("not-a-jwt", &cfg.jwt_public_key_pem).is_none());
        assert!(decode_id_token_hint("", &cfg.jwt_public_key_pem).is_none());
    }
}
