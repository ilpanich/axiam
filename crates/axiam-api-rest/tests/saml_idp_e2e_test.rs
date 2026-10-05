//! **T23.2.7** — the SAML 2.0 IdP end to end, against a reference service
//! provider built from `samael`'s **SP-side API** (G-2).
//!
//! The reference SP is not hand-rolled XML. `samael::service_provider::
//! ServiceProvider` is configured from the IdP metadata document AXIAM serves
//! (`GET /saml/v2/{tenant}/metadata`), builds and signs the `AuthnRequest`
//! (`make_authentication_request`, `to_signed_xml`, `signed_redirect`), and
//! validates what comes back (`parse_xml_response`): the signature against the
//! certificate in the IdP metadata, the audience, `InResponseTo`, `Destination`,
//! `Recipient` and `NotOnOrAfter`. Everything on the AXIAM side is the production
//! route table, the real login endpoint, the real repositories, real RBAC for the
//! administrator routes, and an IdP signing credential **issued through the
//! administrator route** from a tenant signing CA.
//!
//! What each test pins, beyond what the per-route suites (`saml_idp_sso_test`,
//! `saml_idp_slo_test`, `saml_admin_test`) already pin with a synthetic SP:
//!
//! * SP-initiated login on the HTTP-POST binding (a signed request) and on the
//!   HTTP-Redirect binding (a signed query), the user signing in through the real
//!   login hop, and `samael` accepting the response — and refusing the *same*
//!   response under each wrong expectation, so its acceptance is not vacuous;
//! * IdP-initiated login, accepted by an SP that opted in and refused by `samael`
//!   configured as an SP that did not;
//! * the attribute mapping, and the pairwise `NameID` (stable for one SP, different
//!   for two SPs and for two users);
//! * single logout from a `samael`-built `LogoutRequest` on both bindings: the
//!   session is revoked, the revocation feed shows it, and the logout response's
//!   detached signature verifies under `samael`'s own URL verifier;
//! * a replayed `AuthnRequest` ID, an ACS URL outside the registry (and every
//!   near-miss spelling of a registered one) refused with nothing posted anywhere;
//! * the D-20 `404` on metadata, SSO and SLO for a tenant without the feature —
//!   and, in a build without `saml`, for every tenant.
//!
//! Keys and certificates are generated at runtime; no assertion or panic message
//! formats a cookie, a handle, a `SAMLResponse`, a `NameID`, a `SessionIndex` or a
//! document.

#[cfg(feature = "saml")]
mod saml_e2e_support;

#[cfg(feature = "saml")]
mod with_saml {
    use std::net::SocketAddr;
    use std::sync::OnceLock;

    use actix_web::http::Method;
    use actix_web::test;
    use axiam_core::models::settings::SetTenantOverride;
    use axiam_core::repository::SettingsRepository;
    use axiam_db::repository::SurrealSettingsRepository;
    use axiam_federation::saml_idp::request::{RedirectQuery, decode_redirect};
    use axiam_federation::saml_idp::test_support::{
        Material, deflate_base64, openssl, rsa_material, samael,
    };
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use chrono::Utc;
    use samael::crypto::{
        AllowedSignatureAlgorithm, CertificateDer, Crypto, CryptoProvider, UrlVerifier, sign_url,
    };
    use samael::metadata::{EntityDescriptor, HTTP_POST_BINDING, HTTP_REDIRECT_BINDING};
    use samael::schema::{Assertion, Issuer, LogoutRequest, LogoutResponse, NameID};
    use samael::service_provider::{Error as SpError, ServiceProvider, ServiceProviderBuilder};
    use samael::signature::{DigestAlgorithm, Signature};
    use samael::traits::ToXml;
    use uuid::Uuid;

    use crate::e2e_app;
    use crate::saml_e2e_support::*;

    // -----------------------------------------------------------------------
    // The reference service providers
    // -----------------------------------------------------------------------

    /// The request-signing key of SP `a`, `b` or a stranger — RSA-2048, minted
    /// once per binary.
    fn sp_key(which: &str) -> &'static Material {
        static A: OnceLock<Material> = OnceLock::new();
        static B: OnceLock<Material> = OnceLock::new();
        static STRANGER: OnceLock<Material> = OnceLock::new();
        match which {
            "a" => A.get_or_init(|| rsa_material(2048, "SP A request signing", 365)),
            "b" => B.get_or_init(|| rsa_material(2048, "SP B request signing", 365)),
            _ => STRANGER.get_or_init(|| rsa_material(2048, "Not an SP", 365)),
        }
    }

    fn entity(sp: &str) -> String {
        format!("https://sp-{sp}.example.test/metadata")
    }

    fn acs(sp: &str) -> String {
        format!("https://sp-{sp}.example.test/saml/acs")
    }

    fn slo(sp: &str) -> String {
        format!("https://sp-{sp}.example.test/saml/slo")
    }

    /// A `samael` service provider that trusts the IdP metadata document `idp_xml`.
    fn reference_sp(idp_xml: &str, sp: &str, allow_idp_initiated: bool) -> ServiceProvider {
        ServiceProviderBuilder::default()
            .entity_id(entity(sp))
            .acs_url(acs(sp))
            .slo_url(slo(sp))
            .idp_metadata(
                idp_xml
                    .parse::<EntityDescriptor>()
                    .expect("samael reads the IdP metadata AXIAM serves"),
            )
            .allow_idp_initiated(allow_idp_initiated)
            // No tolerance beyond the clock itself, and only the algorithm the
            // metadata's publisher uses.
            .max_clock_skew(chrono::Duration::zero())
            .allowed_signature_algorithms(vec![AllowedSignatureAlgorithm::RsaSha256])
            .build()
            .expect("a service provider")
    }

    /// What the administrator registers for SP `a`: it signs its requests, wants
    /// the full attribute set, and logs out over HTTP-Redirect.
    fn sp_a_body() -> serde_json::Value {
        serde_json::json!({
            "display_name": "SP A",
            "entity_id": entity("a"),
            "acs_urls": [{ "url": acs("a"), "binding": "http_post", "index": 0, "is_default": true }],
            "slo_url": slo("a"),
            "slo_binding": "http_redirect",
            "name_id_format": "persistent",
            "sign_responses": true,
            "sp_signing_cert_pem": sp_key("a").cert_pem,
            "want_authn_requests_signed": true,
            "allow_idp_initiated": false,
            "attribute_mappings": [
                { "saml_name": "mail", "source": "email" },
                { "saml_name": "uid", "source": "username" },
                { "saml_name": "displayName", "source": "display_name" },
                { "saml_name": "givenName", "source": "given_name" },
                { "saml_name": "sn", "source": "family_name" },
                { "saml_name": "groups", "source": "groups" },
            ],
        })
    }

    /// SP `b`: unsigned requests, IdP-initiated allowed, logout over HTTP-POST.
    fn sp_b_body() -> serde_json::Value {
        serde_json::json!({
            "display_name": "SP B",
            "entity_id": entity("b"),
            "acs_urls": [{ "url": acs("b"), "binding": "http_post", "index": 0, "is_default": true }],
            "slo_url": slo("b"),
            "slo_binding": "http_post",
            "name_id_format": "persistent",
            "sign_responses": false,
            "sp_signing_cert_pem": sp_key("b").cert_pem,
            "want_authn_requests_signed": false,
            "allow_idp_initiated": true,
            "attribute_mappings": [{ "saml_name": "mail", "source": "email" }],
        })
    }

    /// A world whose IdP credential is installed directly (sealed as D-21 seals
    /// it), and the IdP metadata the SP administrator would fetch.
    macro_rules! setup {
        () => {{
            let w = world().await;
            let app = e2e_app!(w);
            install_idp_credential(&w).await;
            let idp_xml = fetch_idp_metadata(&app, w.tenant_id).await;
            (w, app, idp_xml)
        }};
    }

    /// The same, with the credential issued through the **administrator route**
    /// from a tenant signing CA — the certificate AXIAM produces in production.
    macro_rules! setup_with_issued_credential {
        () => {{
            let w = world().await;
            let app = e2e_app!(w);
            issue_idp_credential(&app, &w).await;
            let idp_xml = fetch_idp_metadata(&app, w.tenant_id).await;
            (w, app, idp_xml)
        }};
    }

    // -----------------------------------------------------------------------
    // What an SP does
    // -----------------------------------------------------------------------

    /// The `AuthnRequest` `samael` builds for `sp`, signed by `signer` when given:
    /// an enveloped signature (SHA-256 digest, RSA-SHA256) for the POST binding.
    fn signed_post_request(sp: &ServiceProvider, signer: Option<&Material>) -> (String, String) {
        let destination = sp
            .sso_binding_location(HTTP_POST_BINDING)
            .expect("the IdP advertises an HTTP-POST SSO location");
        let mut authn = sp
            .make_authentication_request(&destination)
            .expect("an AuthnRequest");
        let id = authn.id.clone();
        let xml = match signer {
            None => authn.to_string().expect("serialised"),
            Some(signer) => {
                let cert = CertificateDer::from(signer.cert_der.clone());
                let mut signature = Signature::template(&authn.id, &cert);
                // `Signature::template` digests with SHA-1; a careful SP asks for
                // SHA-256, which is all an IdP of this posture accepts (D-23).
                signature.signed_info.reference[0].digest_method.algorithm =
                    DigestAlgorithm::Sha256;
                authn.signature = Some(signature);
                authn
                    .to_signed_xml(&signer.pkcs8_der)
                    .expect("samael signs its own request")
            }
        };
        (id, xml)
    }

    /// Deliver an SP's HTTP-POST request to the IdP the way a browser does.
    async fn post_request(
        app: &impl TestApp,
        browser: &mut Browser,
        sp: &ServiceProvider,
        xml: &str,
        relay: &str,
    ) -> actix_web::dev::ServiceResponse {
        let destination = sp.sso_binding_location(HTTP_POST_BINDING).unwrap();
        browser
            .post_form(
                app,
                &path_and_query(&destination),
                format!(
                    "SAMLRequest={}&RelayState={}",
                    enc(&STANDARD.encode(xml)),
                    enc(relay)
                ),
            )
            .await
    }

    /// One SP-initiated login on the POST binding: the request `samael` built, and
    /// the `(ACS URL, base64 SAMLResponse, RelayState)` the browser carries back.
    async fn sp_initiated_login(
        app: &impl TestApp,
        w: &World,
        browser: &mut Browser,
        sp: &ServiceProvider,
        signer: Option<&Material>,
        username: &str,
    ) -> (String, (String, String, Option<String>)) {
        let (id, xml) = signed_post_request(sp, signer);
        let first = post_request(app, browser, sp, &xml, "relay-1").await;
        let page = complete_login(app, w, browser, &first, username).await;
        (id, posted_response_b64(&page))
    }

    fn decode(response_b64: &str) -> String {
        String::from_utf8(STANDARD.decode(response_b64).unwrap()).unwrap()
    }

    fn attribute_values(assertion: &Assertion, name: &str) -> Vec<String> {
        assertion
            .attribute_statements
            .iter()
            .flatten()
            .flat_map(|s| s.attributes.iter())
            .filter(|a| a.name.as_deref() == Some(name))
            .flat_map(|a| a.values.iter().filter_map(|v| v.value.clone()))
            .collect()
    }

    fn name_id(assertion: &Assertion) -> (Option<String>, String) {
        let id = assertion
            .subject
            .as_ref()
            .and_then(|s| s.name_id.as_ref())
            .expect("a NameID");
        (id.format.clone(), id.value.clone())
    }

    fn session_index(assertion: &Assertion) -> String {
        assertion
            .authn_statements
            .iter()
            .flatten()
            .find_map(|s| s.session_index.clone())
            .expect("a SessionIndex")
    }

    // -----------------------------------------------------------------------
    // 1. SP-initiated, HTTP-POST, a signed request, end to end
    // -----------------------------------------------------------------------

    /// **Acceptance: SP-initiated login, validated by `samael` as an SP would.**
    /// The request is signed by the SP's own library; the user signs in through
    /// the login hop; the response arrives at the registered ACS; `samael` checks
    /// the signature against the IdP metadata's certificate, the audience,
    /// `InResponseTo`, `Destination`, `Recipient` and `NotOnOrAfter` — and refuses
    /// the very same response under each wrong expectation.
    #[actix_rt::test]
    async fn a_samael_sp_signs_in_over_post_and_validates_the_response_as_an_sp_would() {
        let (w, app, idp_xml) = setup_with_issued_credential!();
        register_sp(&app, &w, sp_a_body()).await;
        let sp = reference_sp(&idp_xml, "a", false);
        let mut browser = Browser::default();

        let (id, (action, response_b64, relay)) =
            sp_initiated_login(&app, &w, &mut browser, &sp, Some(sp_key("a")), "alice").await;
        assert_eq!(action, acs("a"), "posted to the registered ACS");
        assert_eq!(relay.as_deref(), Some("relay-1"), "RelayState is echoed");
        let xml = decode(&response_b64);

        // samael's own validation, with the expectations the SP holds.
        let assertion = sp
            .parse_xml_response(&xml, Some(&[id.as_str()]))
            .expect("samael accepts the response as the SP");
        let idp_entity = format!("{ROOT_ISSUER}/saml/v2/{}/metadata", w.tenant_id);
        assert_eq!(assertion.issuer.value.as_deref(), Some(idp_entity.as_str()));

        // What the assertion says.
        let (format, value) = name_id(&assertion);
        assert_eq!(format.as_deref(), Some(PERSISTENT));
        assert!(!value.is_empty());
        assert!(
            !value.contains("alice"),
            "the persistent NameID is pairwise, not the username"
        );
        let conditions = assertion.conditions.as_ref().expect("conditions");
        let audiences: Vec<String> = conditions
            .audience_restrictions
            .iter()
            .flatten()
            .flat_map(|r| r.audience.clone())
            .collect();
        assert_eq!(
            audiences,
            vec![entity("a")],
            "audience = the SP's entity id"
        );
        let not_on_or_after = conditions.not_on_or_after.expect("NotOnOrAfter");
        let window = not_on_or_after - Utc::now();
        assert!(
            window > chrono::Duration::minutes(4) && window <= chrono::Duration::minutes(5),
            "NotOnOrAfter is five minutes out"
        );
        let confirmation = assertion
            .subject
            .as_ref()
            .and_then(|s| s.subject_confirmations.as_ref())
            .and_then(|c| c.first())
            .and_then(|c| c.subject_confirmation_data.as_ref())
            .expect("bearer confirmation data");
        assert_eq!(confirmation.recipient.as_deref(), Some(acs("a").as_str()));
        assert_eq!(confirmation.in_response_to.as_deref(), Some(id.as_str()));

        // The attribute mapping.
        assert_eq!(attribute_values(&assertion, "mail"), vec![alice_email()]);
        assert_eq!(
            attribute_values(&assertion, "uid"),
            vec!["alice".to_string()]
        );
        assert_eq!(
            attribute_values(&assertion, "displayName"),
            vec!["Alice Example".to_string()]
        );
        assert_eq!(
            attribute_values(&assertion, "givenName"),
            vec!["Alice".to_string()]
        );
        assert_eq!(
            attribute_values(&assertion, "sn"),
            vec!["Example".to_string()]
        );
        assert_eq!(
            attribute_values(&assertion, "groups"),
            vec!["engineering".to_string()]
        );

        // The SessionIndex is per SP and random: it is not the AXIAM session id.
        let index = session_index(&assertion);
        assert!(index.len() >= 32);
        let session = participant_session(&w).await;
        assert!(
            !index.contains(&session.to_string()) && !xml.contains(&session.to_string()),
            "the AXIAM session id is nowhere in the response (T-312)"
        );

        // The same response under each wrong expectation: samael refuses it, by
        // the specific check, so the acceptance above is not vacuous.
        let mut wrong_acs = sp.clone();
        wrong_acs.acs_url = Some("https://sp-a.example.test/saml/other".into());
        assert!(
            matches!(
                wrong_acs.parse_xml_response(&xml, Some(&[id.as_str()])),
                Err(SpError::DestinationValidationError { .. })
            ),
            "Destination must equal the SP's ACS"
        );
        let mut wrong_audience = sp.clone();
        wrong_audience.entity_id = Some(entity("b"));
        assert!(
            matches!(
                wrong_audience.parse_xml_response(&xml, Some(&[id.as_str()])),
                Err(SpError::AssertionConditionAudienceRestrictionFailed { .. })
            ),
            "the audience must name the SP"
        );
        assert!(
            matches!(
                sp.parse_xml_response(&xml, Some(&["some-other-request"])),
                Err(SpError::ResponseInResponseToInvalid { .. })
            ),
            "InResponseTo must match an outstanding request"
        );
        assert!(
            matches!(
                sp.parse_xml_response(&xml, None),
                Err(SpError::ResponseInResponseToInvalid { .. })
            ),
            "and an SP with none outstanding refuses"
        );
        let mut wrong_idp = sp.clone();
        wrong_idp.idp_metadata.entity_id = Some("https://other-idp.example.test/".into());
        assert!(
            matches!(
                wrong_idp.parse_xml_response(&xml, Some(&[id.as_str()])),
                Err(SpError::ResponseIssuerMismatch { .. })
            ),
            "the issuer must be the IdP the SP trusts"
        );
        let mut wrong_cert = sp.clone();
        wrong_cert
            .idp_metadata
            .idp_sso_descriptors
            .as_mut()
            .unwrap()[0]
            .key_descriptors[0]
            .key_info
            .x509_data
            .as_mut()
            .unwrap()
            .certificates = vec![STANDARD.encode(&sp_key("stranger").cert_der)];
        assert!(
            matches!(
                wrong_cert.parse_xml_response(&xml, Some(&[id.as_str()])),
                Err(SpError::FailedToValidateSignature)
            ),
            "the signature must verify under the metadata's certificate"
        );
        let tampered = xml.replace(&alice_email(), "mallory@example.com");
        assert_ne!(tampered, xml);
        assert!(
            matches!(
                sp.parse_xml_response(&tampered, Some(&[id.as_str()])),
                Err(SpError::FailedToValidateSignature)
            ),
            "a changed attribute breaks the signature"
        );
    }

    // -----------------------------------------------------------------------
    // 2. SP-initiated, HTTP-Redirect, a signed query
    // -----------------------------------------------------------------------

    /// **Acceptance: the HTTP-Redirect binding with `samael`'s `signed_redirect`.**
    /// The signature is detached over the query octets the SP's library produced;
    /// AXIAM verifies it over exactly those octets, and an unsigned or foreign-key
    /// redirect is refused before the login hop.
    #[actix_rt::test]
    async fn a_samael_sp_signs_in_over_redirect_with_a_signed_query() {
        let (w, app, idp_xml) = setup!();
        register_sp(&app, &w, sp_a_body()).await;
        let sp = reference_sp(&idp_xml, "a", false);
        let destination = sp
            .sso_binding_location(HTTP_REDIRECT_BINDING)
            .expect("the IdP advertises an HTTP-Redirect SSO location");

        let pkey = |m: &Material| {
            openssl::pkey::PKey::private_key_from_pkcs8(&m.pkcs8_der).expect("a signing key")
        };
        let authn = sp.make_authentication_request(&destination).unwrap();

        // Signed by the SP's key: served.
        let url = authn
            .signed_redirect("redirect-relay", &pkey(sp_key("a")))
            .unwrap()
            .expect("a URL");
        let mut browser = Browser::default();
        let first = browser.get(&app, &path_and_query(url.as_str())).await;
        let page = complete_login(&app, &w, &mut browser, &first, "alice").await;
        let (action, response_b64, relay) = posted_response_b64(&page);
        assert_eq!(action, acs("a"));
        assert_eq!(relay.as_deref(), Some("redirect-relay"));
        sp.parse_xml_response(&decode(&response_b64), Some(&[authn.id.as_str()]))
            .expect("samael accepts the response to its Redirect-bound request");

        // Signed by somebody else's key: refused before the hop, nothing issued.
        let other = sp.make_authentication_request(&destination).unwrap();
        let forged = other
            .signed_redirect("", &pkey(sp_key("stranger")))
            .unwrap()
            .unwrap();
        let before = pending_rows(&w).await;
        let mut stranger = Browser::default();
        let resp = stranger.get(&app, &path_and_query(forged.as_str())).await;
        assert_eq!(resp.status().as_u16(), 400);
        assert!(!location(&resp).contains("/login"));
        let page = body_of(resp).await;
        assert!(!page.contains("SAMLResponse") && !page.contains("<form"));
        assert_eq!(pending_rows(&w).await, before, "nothing was stored");

        // Unsigned, for an SP that requires signed requests: refused too.
        let unsigned = sp.make_authentication_request(&destination).unwrap();
        let url = unsigned.redirect("").unwrap().unwrap();
        let resp = Browser::default()
            .get(&app, &path_and_query(url.as_str()))
            .await;
        assert_eq!(resp.status().as_u16(), 400);
        assert_eq!(pending_rows(&w).await, before);
    }

    // -----------------------------------------------------------------------
    // 3. IdP-initiated
    // -----------------------------------------------------------------------

    /// **Acceptance: IdP-initiated login.** For an SP that opted in, the signed
    /// response carries no `InResponseTo`; `samael` accepts it as an SP that
    /// allows unsolicited responses and refuses it as one that does not. An SP
    /// that has not opted in is refused at the trigger, before any hop.
    #[actix_rt::test]
    async fn idp_initiated_login_is_accepted_by_a_samael_sp_that_allows_it() {
        let (w, app, idp_xml) = setup!();
        register_sp(&app, &w, sp_a_body()).await;
        register_sp(&app, &w, sp_b_body()).await;
        let mut browser = Browser::default();
        browser.sign_in(&app, &w, "alice").await;

        let trigger = |sp: &str| {
            format!(
                "{}/idp-initiated?sp={}&RelayState=dashboard",
                sso_path(w.tenant_id),
                enc(&entity(sp))
            )
        };
        let first = browser
            .get_with(&app, &trigger("b"), &[("Sec-Fetch-Site", "same-origin")])
            .await;
        let page = complete_login(&app, &w, &mut browser, &first, "alice").await;
        let (action, response_b64, relay) = posted_response_b64(&page);
        assert_eq!(action, acs("b"), "the SP's default ACS");
        assert_eq!(relay.as_deref(), Some("dashboard"));
        let xml = decode(&response_b64);
        assert!(
            attr(&xml, "InResponseTo").is_none(),
            "an unsolicited response answers no request"
        );

        let accepting = reference_sp(&idp_xml, "b", true);
        let assertion = accepting
            .parse_xml_response(&xml, None)
            .expect("an SP that allows IdP-initiated sign-on accepts it");
        assert_eq!(attribute_values(&assertion, "mail"), vec![alice_email()]);
        let strict = reference_sp(&idp_xml, "b", false);
        assert!(
            matches!(
                strict.parse_xml_response(&xml, None),
                Err(SpError::ResponseInResponseToInvalid { .. }
                    | SpError::AssertionInResponseToInvalid { .. })
            ),
            "an SP that did not ask for it refuses an unsolicited response"
        );

        // SP A never opted in: refused at the trigger, no pending request.
        let before = pending_rows(&w).await;
        let refused = browser
            .get_with(&app, &trigger("a"), &[("Sec-Fetch-Site", "same-origin")])
            .await;
        assert_eq!(refused.status().as_u16(), 403);
        let page = body_of(refused).await;
        assert!(!page.contains("SAMLResponse"));
        assert_eq!(pending_rows(&w).await, before);
    }

    // -----------------------------------------------------------------------
    // 4. The pairwise NameID
    // -----------------------------------------------------------------------

    /// **Acceptance: the pairwise `NameID`.** Stable for one user at one SP across
    /// sessions, different at a second SP, different for a second user (D-22).
    #[actix_rt::test]
    async fn the_pairwise_name_id_is_stable_for_one_sp_and_differs_between_sps_and_users() {
        let (w, app, idp_xml) = setup!();
        register_sp(&app, &w, sp_a_body()).await;
        register_sp(&app, &w, sp_b_body()).await;
        let sp_a = reference_sp(&idp_xml, "a", false);
        let sp_b = reference_sp(&idp_xml, "b", false);

        let id_of = async |sp: &ServiceProvider, signer: Option<&Material>, user: &str| {
            let mut browser = Browser::default();
            let (id, (_, response_b64, _)) =
                sp_initiated_login(&app, &w, &mut browser, sp, signer, user).await;
            let assertion = sp
                .parse_xml_response(&decode(&response_b64), Some(&[id.as_str()]))
                .expect("samael accepts the response");
            name_id(&assertion).1
        };
        let alice_a_first = id_of(&sp_a, Some(sp_key("a")), "alice").await;
        let alice_a_second = id_of(&sp_a, Some(sp_key("a")), "alice").await;
        let alice_b = id_of(&sp_b, None, "alice").await;
        let bob_a = id_of(&sp_a, Some(sp_key("a")), "bob").await;

        assert!(
            alice_a_first == alice_a_second,
            "stable for one user at one SP, across two sign-ins"
        );
        assert!(alice_a_first != alice_b, "different at another SP");
        assert!(alice_a_first != bob_a, "different for another user");
        assert!(
            alice_b != bob_a,
            "and no collision between the remaining pairs"
        );
    }

    // -----------------------------------------------------------------------
    // 5. Single logout
    // -----------------------------------------------------------------------

    /// A `LogoutRequest` built with `samael`'s schema type, naming what the SP was
    /// given at sign-on.
    fn logout_request(
        w: &World,
        sp: &str,
        name_id: &str,
        session_index: &str,
        signer: Option<&Material>,
    ) -> (String, LogoutRequest) {
        let id = format!("_{}", Uuid::new_v4().simple());
        let signature = signer.map(|k| {
            let mut s = Signature::template(&id, &CertificateDer::from(k.cert_der.clone()));
            s.signed_info.reference[0].digest_method.algorithm = DigestAlgorithm::Sha256;
            s
        });
        (
            id.clone(),
            LogoutRequest {
                id: Some(id),
                version: Some("2.0".into()),
                issue_instant: Some(Utc::now()),
                destination: Some(format!("{ROOT_ISSUER}/saml/v2/{}/slo", w.tenant_id)),
                issuer: Some(Issuer {
                    format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:entity".into()),
                    value: Some(entity(sp)),
                    ..Issuer::default()
                }),
                signature,
                session_index: Some(session_index.to_owned()),
                name_id: Some(NameID {
                    format: Some(PERSISTENT.into()),
                    value: name_id.to_owned(),
                }),
            },
        )
    }

    /// The one AXIAM session the participant rows name.
    async fn participant_session(w: &World) -> Uuid {
        let mut result =
            w.db.query("SELECT session_id FROM saml_sp_session ORDER BY created_at ASC")
                .await
                .unwrap();
        let rows: Vec<serde_json::Value> = result.take(0).unwrap();
        assert!(!rows.is_empty(), "a participant row exists");
        Uuid::parse_str(rows[0]["session_id"].as_str().unwrap()).unwrap()
    }

    async fn feed(app: &impl TestApp) -> Vec<String> {
        let resp = test::call_service(
            app,
            test::TestRequest::get()
                .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
                .uri("/oauth2/revocations")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status().as_u16(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        body["revoked"]
            .as_array()
            .expect("an array")
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    }

    /// Log in at `sp`, send a `samael`-built signed `LogoutRequest` over `via`, and
    /// check the whole chain: a signed `Success` answer at the SP's registered
    /// endpoint, the session revoked, the access cookie refused and the revocation
    /// feed showing it.
    async fn logout_case(sp_name: &str, via: &str) {
        use axiam_core::revocation_feed::revocation_hash;

        let (w, app, idp_xml) = setup!();
        register_sp(&app, &w, sp_a_body()).await;
        register_sp(&app, &w, sp_b_body()).await;
        let sp = reference_sp(&idp_xml, sp_name, false);
        let signer = sp_key(sp_name);
        let mut browser = Browser::default();
        let (id, (_, response_b64, _)) = sp_initiated_login(
            &app,
            &w,
            &mut browser,
            &sp,
            (sp_name == "a").then_some(signer),
            "alice",
        )
        .await;
        let assertion = sp
            .parse_xml_response(&decode(&response_b64), Some(&[id.as_str()]))
            .expect("samael accepts the response");
        let (_, name_id) = name_id(&assertion);
        let index = session_index(&assertion);
        let session = participant_session(&w).await;
        assert_eq!(browser.me(&app).await, 200, "the session works before");
        assert!(!feed(&app).await.contains(&revocation_hash(session)));

        // An HTTP-Redirect document carries no enveloped signature (the signature is
        // the detached query one); an HTTP-POST document is signed in place.
        let (request_id, request) = logout_request(
            &w,
            sp_name,
            &name_id,
            &index,
            (via == "post").then_some(signer),
        );
        let slo_destination = request.destination.clone().unwrap();
        let mut anonymous = Browser::default();
        let resp = match via {
            "redirect" => {
                // The detached query signature is `samael`'s own `sign_url`.
                let xml = request.to_string().expect("serialised");
                let mut url: url::Url = slo_destination.parse().unwrap();
                url.query_pairs_mut()
                    .append_pair("SAMLRequest", &deflate_base64(xml.as_bytes()))
                    .append_pair("RelayState", "logout-relay");
                let pkey = openssl::pkey::PKey::private_key_from_pkcs8(&signer.pkcs8_der).unwrap();
                let signed = sign_url(url, &pkey).expect("samael signs the query");
                anonymous.get(&app, &path_and_query(signed.as_str())).await
            }
            _ => {
                let xml = Crypto::sign_xml(request.to_string().unwrap(), &signer.pkcs8_der)
                    .expect("samael signs the document");
                anonymous
                    .post_form(
                        &app,
                        &slo_path(w.tenant_id),
                        format!(
                            "SAMLRequest={}&RelayState=logout-relay",
                            enc(&STANDARD.encode(xml))
                        ),
                    )
                    .await
            }
        };

        // The answer: where the SP registered it, on its registered binding.
        let (destination, response_xml, relay, redirect_target) = match resp.status().as_u16() {
            302 => {
                let target = location(&resp);
                let (base, query) = target.split_once('?').expect("a message in the query");
                let parsed = RedirectQuery::parse_logout(query).expect("well-formed");
                (
                    base.to_owned(),
                    decode_redirect(&parsed.message()).expect("a document"),
                    parsed.relay_state(),
                    Some(target),
                )
            }
            200 => {
                let (action, xml, relay) = posted(&body_of(resp).await, "SAMLResponse");
                (action, xml, relay, None)
            }
            other => panic!("expected a logout answer, the status was {other}"),
        };
        assert_eq!(destination, slo(sp_name), "the SP's registered endpoint");
        assert_eq!(relay.as_deref(), Some("logout-relay"));
        let answer: LogoutResponse = response_xml.parse().expect("samael parses the response");
        assert_eq!(answer.in_response_to.as_deref(), Some(request_id.as_str()));
        assert_eq!(
            answer
                .status
                .as_ref()
                .and_then(|s| s.status_code.value.as_deref()),
            Some(SUCCESS)
        );
        let idp_cert = CertificateDer::from(idp_certificate_der(&idp_xml));
        match redirect_target {
            Some(target) => {
                // A Redirect-bound answer is signed detached: no ds:Signature in the
                // document, and `samael`'s URL verifier accepts it under the
                // metadata's certificate.
                assert!(!response_xml.contains("<ds:Signature"));
                let verifier = UrlVerifier::from_x509(&idp_cert).expect("a verifier");
                let url: url::Url = target.parse().expect("an absolute URL");
                assert!(
                    verifier
                        .verify_signed_response_url(&url)
                        .expect("samael checks the query signature"),
                    "the LogoutResponse's detached signature verifies under samael"
                );
            }
            None => {
                axiam_federation::saml_idp::request::verify_post_signature(
                    &response_xml,
                    idp_cert.der_data(),
                )
                .expect("the enveloped signature verifies under the metadata's certificate");
            }
        }

        // The session is gone and the feed says so.
        assert_eq!(browser.me(&app).await, 401, "the session is refused");
        assert!(
            feed(&app).await.contains(&revocation_hash(session)),
            "the revocation feed shows the revocation"
        );
        let mut result =
            w.db.query("SELECT count() AS n FROM saml_sp_session GROUP ALL")
                .await
                .unwrap();
        let rows: Vec<serde_json::Value> = result.take(0).unwrap();
        assert!(
            rows.first().and_then(|r| r["n"].as_u64()).unwrap_or(0) == 0,
            "the chain ended: no participant row is left"
        );
    }

    /// The signing certificate of the IdP metadata, DER, as an SP reads it.
    fn idp_certificate_der(idp_xml: &str) -> Vec<u8> {
        let parsed: EntityDescriptor = idp_xml.parse().unwrap();
        let b64 = parsed.idp_sso_descriptors.unwrap()[0].key_descriptors[0]
            .key_info
            .x509_data
            .as_ref()
            .unwrap()
            .certificates[0]
            .clone();
        STANDARD
            .decode(b64.split_whitespace().collect::<String>())
            .unwrap()
    }

    /// **Acceptance: SLO revokes the session and the feed shows it** — SP `a`
    /// registered HTTP-Redirect, the request sent on the Redirect binding with a
    /// detached query signature.
    #[actix_rt::test]
    async fn slo_from_a_samael_sp_over_redirect_revokes_the_session_and_the_feed_shows_it() {
        Box::pin(logout_case("a", "redirect")).await;
    }

    /// **Acceptance: the same, on the HTTP-POST binding** — SP `b` registered
    /// HTTP-POST, the request enveloped-signed by `samael`.
    #[actix_rt::test]
    async fn slo_from_a_samael_sp_over_post_revokes_the_session_and_the_feed_shows_it() {
        Box::pin(logout_case("b", "post")).await;
    }

    // -----------------------------------------------------------------------
    // 6. Replay
    // -----------------------------------------------------------------------

    /// **Acceptance: a replayed `InResponseTo` is refused.** The `AuthnRequest`
    /// `samael` built is delivered twice — by a second browser while the first is
    /// mid-login, and again after the first completed — and only the first is
    /// served. A response is also only good for the request it answers: `samael`
    /// refuses it for any other outstanding ID.
    #[actix_rt::test]
    async fn a_replayed_authn_request_id_is_refused() {
        let (w, app, idp_xml) = setup!();
        register_sp(&app, &w, sp_b_body()).await;
        let sp = reference_sp(&idp_xml, "b", false);
        let (id, xml) = signed_post_request(&sp, None);

        let mut first = Browser::default();
        let started = post_request(&app, &mut first, &sp, &xml, "r1").await;
        assert_eq!(
            started.status().as_u16(),
            303,
            "the first delivery is served"
        );
        let stored = pending_rows(&w).await;
        assert_eq!(stored, 1);

        let mut second = Browser::default();
        let replay = post_request(&app, &mut second, &sp, &xml, "r2").await;
        assert_eq!(replay.status().as_u16(), 400, "the replay is refused");
        assert!(location(&replay).is_empty(), "with no hop");
        let page = body_of(replay).await;
        assert!(!page.contains("SAMLResponse") && !page.contains("<form"));
        assert_eq!(pending_rows(&w).await, stored, "and nothing is stored");

        // The first browser completes; the request ID stays spent afterwards.
        let page = complete_login(&app, &w, &mut first, &started, "alice").await;
        let (_, response_b64, _) = posted_response_b64(&page);
        let response = decode(&response_b64);
        sp.parse_xml_response(&response, Some(&[id.as_str()]))
            .expect("the one served login validates");
        let mut third = Browser::default();
        let late = post_request(&app, &mut third, &sp, &xml, "r3").await;
        assert_eq!(
            late.status().as_u16(),
            400,
            "a completed request's ID is still refused"
        );
        assert!(
            !body_of(late).await.contains("SAMLResponse"),
            "nothing is issued for it"
        );

        // The SP's side of replay: the response answers one request only.
        let (other_id, _) = signed_post_request(&sp, None);
        assert!(
            sp.parse_xml_response(&response, Some(&[other_id.as_str()]))
                .is_err(),
            "a captured response does not satisfy another request"
        );
    }

    // -----------------------------------------------------------------------
    // 7. An ACS outside the registry
    // -----------------------------------------------------------------------

    /// **Acceptance: an ACS URL outside the registry is refused.** `samael` builds
    /// the request for an SP whose ACS the administrator never registered, and for
    /// every near-miss spelling of the registered one; each is refused before the
    /// hop with a page that posts nowhere, signed or not.
    #[actix_rt::test]
    async fn an_acs_url_outside_the_registry_is_refused_and_nothing_is_posted() {
        let (w, app, idp_xml) = setup!();
        register_sp(&app, &w, sp_b_body()).await;
        let registered = acs("b");
        let mut attempts = vec![
            "https://attacker.example.test/saml/acs".to_string(),
            format!("{registered}/"),
            format!("{registered}?next=1"),
            format!("{registered}#frag"),
            registered.replace("https://", "http://"),
            registered.replace("sp-b.", "sp-b.evil."),
            "https://sp-b.example.test/saml/*".to_string(),
        ];
        attempts.push(registered.to_uppercase());

        for attempt in attempts {
            let mut sp = reference_sp(&idp_xml, "b", false);
            sp.acs_url = Some(attempt.clone());
            let (_, xml) = signed_post_request(&sp, None);
            let mut browser = Browser::default();
            let resp = post_request(&app, &mut browser, &sp, &xml, "r").await;
            assert_eq!(
                resp.status().as_u16(),
                400,
                "an ACS URL outside the registry is refused"
            );
            assert!(
                !location(&resp).contains("/login") && !location(&resp).contains("/continue"),
                "no hop"
            );
            let page = body_of(resp).await;
            assert!(
                !page.contains("<form") && !page.contains("SAMLResponse"),
                "a page that posts nowhere"
            );
            assert!(!page.contains(&attempt), "the refused URL is not reflected");
            assert_eq!(pending_rows(&w).await, 0, "no pending request");
        }

        // The control: the registered ACS is served by the same code path.
        let sp = reference_sp(&idp_xml, "b", false);
        let (_, xml) = signed_post_request(&sp, None);
        let mut browser = Browser::default();
        let resp = post_request(&app, &mut browser, &sp, &xml, "r").await;
        assert_eq!(resp.status().as_u16(), 303);
    }

    async fn pending_rows(w: &World) -> usize {
        let mut result =
            w.db.query("SELECT count() AS n FROM saml_authn_request GROUP ALL")
                .await
                .unwrap();
        let rows: Vec<serde_json::Value> = result.take(0).unwrap();
        rows.first().and_then(|r| r["n"].as_u64()).unwrap_or(0) as usize
    }

    // -----------------------------------------------------------------------
    // 9. SP metadata samael cannot type (D-54)
    // -----------------------------------------------------------------------

    /// **D-54.** `samael` types `SPSSODescriptor/@cacheDuration` as an integer and
    /// requires an `AssertionConsumerService/@index`; real SP metadata (Shibboleth,
    /// SimpleSAMLphp) carries an ISO-8601 duration and often no index. AXIAM
    /// normalises both on the parsed tree before `samael` reads it: the duration is
    /// dropped and the missing index is defaulted, each with a warning in the draft.
    /// The draft registers, and the registered SP completes a sign-on that `samael`,
    /// as that SP, validates. (Keycloak 26.7.0's own export needs neither.)
    #[actix_rt::test]
    async fn sp_metadata_with_a_cache_duration_and_no_acs_index_registers_and_signs_in() {
        let (w, app, idp_xml) = setup!();
        let document = |sp_attrs: &str, acs: &str| {
            format!(
                r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{}"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"{sp_attrs}>{acs}</md:SPSSODescriptor></md:EntityDescriptor>"#,
                entity("c")
            )
        };
        let acs_element = |attrs: &str| {
            format!(
                r#"<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{}"{attrs}/>"#,
                acs("c")
            )
        };
        let parse = |doc: String| {
            let app = &app;
            let w = &w;
            async move {
                admin_call(
                    app,
                    w,
                    Method::POST,
                    "parse-sp-metadata",
                    Some(serde_json::json!({ "metadata_xml": doc })),
                )
                .await
            }
        };

        // The control: a document needing neither normalisation is not warned about.
        let (status, text) = parse(document("", &acs_element(r#" index="1""#))).await;
        assert_eq!(status, 200, "the control parses");
        assert!(
            json_of(&text)["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .all(|v| !v.as_str().unwrap_or_default().contains("cacheDuration")),
            "no spurious warning"
        );

        // The case: an ISO-8601 cacheDuration and an ACS with no index.
        let (status, text) = parse(document(
            r#" cacheDuration="PT1H""#,
            &acs_element(r#" isDefault="true""#),
        ))
        .await;
        assert_eq!(status, 200, "the document is read, with both normalised");
        let draft = json_of(&text);
        let warnings: Vec<String> = draft["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        assert!(
            warnings.iter().any(|w| w.contains("cacheDuration")),
            "the dropped duration is named"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains(&acs("c")) && w.contains("index 0")),
            "the defaulted index is named with its location"
        );
        assert_eq!(draft["service_provider"]["acs_urls"][0]["index"], 0);

        // The draft registers as it is, and the registered SP signs in.
        register_sp(&app, &w, draft["service_provider"].clone()).await;
        let sp = reference_sp(&idp_xml, "c", false);
        let mut browser = Browser::default();
        let (id, (action, response_b64, _)) =
            sp_initiated_login(&app, &w, &mut browser, &sp, None, "alice").await;
        assert_eq!(action, acs("c"));
        sp.parse_xml_response(&decode(&response_b64), Some(&[id.as_str()]))
            .expect("samael accepts the response for the SP registered from that metadata");

        // An index that is present but invalid is still refused, generically.
        let (status, text) = parse(document("", &acs_element(r#" index="abc""#))).await;
        assert_eq!(status, 400);
        assert_eq!(
            json_of(&text)["message"],
            "Validation error: not SAML service-provider metadata"
        );
    }

    // -----------------------------------------------------------------------
    // 8. The feature switch
    // -----------------------------------------------------------------------

    /// What an answer looks like, minus its date: status and header set.
    fn fingerprint(resp: &actix_web::dev::ServiceResponse) -> (u16, Vec<(String, String)>) {
        let mut headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .filter(|(k, _)| k.as_str() != "date")
            .map(|(k, v)| {
                (
                    k.as_str().to_owned(),
                    v.to_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        headers.sort();
        (resp.status().as_u16(), headers)
    }

    /// **Acceptance: a tenant without the feature answers `404` on metadata, SSO
    /// and SLO**, indistinguishably from a path nothing is mounted at — with the
    /// credential issued and a service provider registered, so the switch is the
    /// only difference (the control serves, and serves again when it is turned
    /// back on). The administrator routes keep working while it is off.
    #[actix_rt::test]
    async fn a_tenant_without_the_feature_answers_404_on_metadata_sso_and_slo() {
        let (w, app, idp_xml) = setup!();
        register_sp(&app, &w, sp_b_body()).await;
        let sp = reference_sp(&idp_xml, "b", false);
        let (_, authn_xml) = signed_post_request(&sp, None);
        let redirect_query = {
            let destination = sp.sso_binding_location(HTTP_REDIRECT_BINDING).unwrap();
            let authn = sp.make_authentication_request(&destination).unwrap();
            let url = authn.redirect("").unwrap().unwrap();
            url.query().unwrap().to_owned()
        };

        // Every request an SP could send to the three endpoints.
        let requests = |tenant: &str| -> Vec<(Method, String, Option<String>)> {
            vec![
                (Method::GET, format!("/saml/v2/{tenant}/metadata"), None),
                (Method::HEAD, format!("/saml/v2/{tenant}/metadata"), None),
                (
                    Method::GET,
                    format!("/saml/v2/{tenant}/sso?{redirect_query}"),
                    None,
                ),
                (
                    Method::POST,
                    format!("/saml/v2/{tenant}/sso"),
                    Some(format!("SAMLRequest={}", enc(&STANDARD.encode(&authn_xml)))),
                ),
                (
                    Method::GET,
                    format!(
                        "/saml/v2/{tenant}/sso/idp-initiated?sp={}",
                        enc(&entity("b"))
                    ),
                    None,
                ),
                (
                    Method::GET,
                    format!("/saml/v2/{tenant}/slo?SAMLRequest=x"),
                    None,
                ),
                (
                    Method::POST,
                    format!("/saml/v2/{tenant}/slo"),
                    Some("SAMLRequest=x".to_string()),
                ),
                (Method::GET, format!("/saml/v2/{tenant}/sso/logout"), None),
            ]
        };
        let call = |method: Method, uri: String, body: Option<String>| {
            let mut req = test::TestRequest::default()
                .method(method)
                .uri(&uri)
                .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap());
            if let Some(body) = body {
                req = req
                    .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
                    .set_payload(body);
            }
            req.to_request()
        };

        let unmounted = test::call_service(
            &app,
            call(Method::GET, "/saml/v3/nothing/here".into(), None),
        )
        .await;
        let expected = fingerprint(&unmounted);
        assert_eq!(expected.0, 404);
        assert!(test::read_body(unmounted).await.is_empty());

        // The control: the metadata serves while the switch is on.
        let served =
            test::call_service(&app, call(Method::GET, metadata_path(w.tenant_id), None)).await;
        assert_eq!(served.status().as_u16(), 200, "the control serves");

        // Switch the tenant's feature off: all three endpoints are the same 404.
        let settings = SurrealSettingsRepository::new(w.db.clone());
        settings
            .set_tenant_override(
                w.tenant_id,
                SetTenantOverride {
                    saml_idp_enabled: Some(false),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        for (method, uri, body) in requests(&w.tenant_id.to_string()) {
            let resp = test::call_service(&app, call(method.clone(), uri, body)).await;
            assert_eq!(
                fingerprint(&resp),
                expected,
                "{method} on a SAML route of a tenant with the feature off"
            );
            assert!(test::read_body(resp).await.is_empty());
        }

        // The administrator can still see and prepare the IdP (§29.3 rule 8).
        let (status, text) = admin_call(&app, &w, Method::GET, "idp", None).await;
        assert_eq!(status, 200);
        let info = json_of(&text);
        assert_eq!(info["saml_idp_enabled"], false);
        assert_eq!(info["metadata_served"], false);

        // An organization that never turned the feature on: the default is off.
        let default_tenant = {
            use axiam_core::models::organization::CreateOrganization;
            use axiam_core::models::tenant::{CreateTenant, TenantKind};
            use axiam_core::repository::{OrganizationRepository, TenantRepository};
            let org = axiam_db::repository::SurrealOrganizationRepository::new(w.db.clone())
                .create(CreateOrganization {
                    name: "Default org".into(),
                    slug: format!("default-{}", Uuid::new_v4().simple()),
                    metadata: None,
                })
                .await
                .unwrap();
            axiam_db::repository::SurrealTenantRepository::new(w.db.clone())
                .create(CreateTenant {
                    organization_id: org.id,
                    kind: TenantKind::Standard,
                    name: "Default tenant".into(),
                    slug: "default".into(),
                    metadata: None,
                })
                .await
                .unwrap()
                .id
        };
        for (method, uri, body) in requests(&default_tenant.to_string()) {
            let resp = test::call_service(&app, call(method.clone(), uri, body)).await;
            assert_eq!(
                fingerprint(&resp),
                expected,
                "{method}: a tenant of an organization with the default (off)"
            );
            assert!(test::read_body(resp).await.is_empty());
        }

        // The switch is the whole difference: clear the override and it serves again.
        settings.delete_tenant_override(w.tenant_id).await.unwrap();
        let again =
            test::call_service(&app, call(Method::GET, metadata_path(w.tenant_id), None)).await;
        assert_eq!(
            again.status().as_u16(),
            200,
            "the same tenant serves once its override is gone"
        );
    }
}

/// In a build without `saml` no SAML browser route is mounted at all: metadata,
/// SSO and SLO answer exactly what a path nothing is mounted at answers, for
/// every tenant and every method.
#[cfg(not(feature = "saml"))]
mod plain_build {
    use std::net::SocketAddr;
    use std::sync::{Arc, OnceLock};

    use actix_web::http::Method;
    use actix_web::{App, test, web};
    use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
    use axiam_api_rest::state::AppState;
    use axiam_api_rest::{RateLimitConfig, register_api_v1_routes};
    use axiam_auth::config::AuthConfig;
    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;
    use uuid::Uuid;

    type TestDb = surrealdb::engine::local::Db;

    fn jwt_pair() -> &'static (String, String) {
        static PAIR: OnceLock<(String, String)> = OnceLock::new();
        PAIR.get_or_init(|| {
            let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair");
            (pair.serialize_pem(), pair.public_key_pem())
        })
    }

    #[actix_rt::test]
    async fn without_saml_the_three_endpoints_are_not_mounted() {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        axiam_db::run_migrations(&db).await.unwrap();
        let (private_pem, public_pem) = jwt_pair().clone();
        let auth = AuthConfig {
            jwt_private_key_pem: private_pem,
            jwt_public_key_pem: public_pem,
            jwt_issuer: "axiam-test".into(),
            oauth2_issuer_url: "https://iam.example.com".into(),
            ..AuthConfig::default()
        };
        let state = AppState::for_test(db.clone(), auth.clone());
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(auth))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .app_data(web::Data::new(state))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await;

        let fingerprint = |resp: &actix_web::dev::ServiceResponse| {
            let mut headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .filter(|(k, _)| k.as_str() != "date")
                .map(|(k, v)| {
                    (
                        k.as_str().to_owned(),
                        v.to_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect();
            headers.sort();
            (resp.status().as_u16(), headers)
        };
        let call = |method: Method, uri: String| {
            test::TestRequest::default()
                .method(method)
                .uri(&uri)
                .peer_addr("127.0.0.1:12345".parse::<SocketAddr>().unwrap())
                .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
                .set_payload("SAMLRequest=x")
                .to_request()
        };
        let unmounted =
            test::call_service(&app, call(Method::GET, "/saml/v3/nothing/here".into())).await;
        let expected = fingerprint(&unmounted);
        assert_eq!(expected.0, 404);

        let tenant = Uuid::new_v4();
        for path in [
            format!("/saml/v2/{tenant}/metadata"),
            format!("/saml/v2/{tenant}/sso"),
            format!("/saml/v2/{tenant}/sso/idp-initiated?sp=x"),
            format!("/saml/v2/{tenant}/slo"),
            format!("/saml/v2/{tenant}/sso/logout"),
        ] {
            for method in [Method::GET, Method::HEAD, Method::POST] {
                let resp = test::call_service(&app, call(method.clone(), path.clone())).await;
                assert_eq!(
                    fingerprint(&resp),
                    expected,
                    "{method} {path}: not mounted in a build without saml"
                );
                assert!(test::read_body(resp).await.is_empty());
            }
        }
    }
}
