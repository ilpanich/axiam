//! **T23.2.7** — AXIAM as a SAML 2.0 identity provider, round-tripped with a real
//! **Keycloak** acting as the service provider (G-2).
//!
//! Keycloak is the SP in the only way it can be one: a realm with a SAML v2.0
//! *identity provider* (identity brokering) pointing at AXIAM. The test drives the
//! round trip the way a person's browser does and carries every message itself:
//!
//! 1. AXIAM's IdP metadata (`GET /saml/v2/{tenant}/metadata`, with a signing
//!    credential issued through the administrator route) is **imported into
//!    Keycloak** through its admin REST API (`identity-provider/import-config`),
//!    and the identity provider is created from what Keycloak made of it.
//! 2. Keycloak's **SP metadata** (the broker endpoint descriptor) is registered in
//!    AXIAM through `parse_sp_metadata` → `create_service_provider`.
//! 3. A cookie-jar HTTP client starts a broker login at Keycloak, carries the
//!    `AuthnRequest` to AXIAM's SSO endpoint, signs in through the real login hop,
//!    carries the `SAMLResponse` back to Keycloak's broker endpoint, and follows
//!    Keycloak to the end: an authorization code, exchanged for tokens whose
//!    claims come from the SAML attributes, and a federated identity whose id is
//!    the pairwise `NameID` AXIAM asserted.
//!
//! The test process carries every message, so **Keycloak never has to reach AXIAM
//! over the network** and AXIAM never reaches Keycloak. AXIAM's side is the
//! production route table in-process (the same posture as
//! `keycloak_cross_vendor_token_exchange_test.rs`); the only network peer is
//! Keycloak itself, over loopback, and nothing about AXIAM's production policy is
//! weakened to reach it.
//!
//! Both AuthnRequest bindings are exercised, each with a **signed** request
//! (Keycloak signs with its realm key; AXIAM verifies against the certificate in
//! Keycloak's exported metadata): HTTP-POST (an enveloped signature) and
//! HTTP-Redirect (a detached query signature, verified over the exact octets).
//!
//! # `#[ignore]`d: it needs a running Keycloak
//!
//! ```text
//! docker compose -f docker/docker-compose.e2e.yml up -d --wait keycloak
//! KEYCLOAK_URL=http://localhost:8180 \
//!   cargo test -p axiam-api-rest --test saml_idp_keycloak_roundtrip_test \
//!   -- --ignored --test-threads=1
//! ```
//!
//! `KEYCLOAK_URL` must be a loopback address reachable from where `cargo test`
//! runs. The admin credentials are the compose file's `E2E_KEYCLOAK_ADMIN` and
//! `E2E_KEYCLOAK_ADMIN_PASSWORD` environment variables, read from the environment
//! as `keycloak_cross_vendor_token_exchange_test.rs` reads them.
//!
//! No assertion or panic message formats a token, a cookie, a `SAMLResponse` or a
//! `NameID`.

#![cfg(feature = "saml")]

mod saml_e2e_support;

use std::collections::BTreeMap;

use actix_web::http::Method;
use axiam_federation::saml_idp::test_support::samael;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use samael::crypto::AllowedSignatureAlgorithm;
use samael::metadata::EntityDescriptor;
use samael::service_provider::ServiceProviderBuilder;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::saml_e2e_support::*;

const ALIAS: &str = "axiam";
const CLIENT_ID: &str = "axiam-saml-e2e-rp";
/// Nothing listens here. Keycloak redirects the browser to it with the
/// authorization code, and the test reads the `Location` instead of following it.
const RP_REDIRECT: &str = "http://127.0.0.1:1/callback";

fn keycloak_url() -> String {
    std::env::var("KEYCLOAK_URL").unwrap_or_else(|_| "http://localhost:8180".to_string())
}

/// A bootstrap-admin variable: the environment's value, else the default
/// `docker/docker-compose.e2e.yml` itself declares (`${NAME:-default}`), read from
/// that file at run time so this test carries no credential literal of its own.
fn compose_admin_setting(name: &str) -> String {
    if let Ok(value) = std::env::var(name) {
        return value;
    }
    let compose = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docker/docker-compose.e2e.yml"
    ))
    .expect("the e2e compose file");
    let marker = format!("${{{name}:-");
    let start = compose
        .find(&marker)
        .unwrap_or_else(|| panic!("the compose file declares a default for {name}"))
        + marker.len();
    let end = compose[start..].find('}').expect("a closing brace") + start;
    compose[start..end].to_owned()
}

fn keycloak_admin_user() -> String {
    compose_admin_setting("E2E_KEYCLOAK_ADMIN")
}

fn keycloak_admin_password() -> String {
    compose_admin_setting("E2E_KEYCLOAK_ADMIN_PASSWORD")
}

// ---------------------------------------------------------------------------
// A browser (a cookie jar over reqwest, no redirects followed) and Keycloak's
// admin REST API
// ---------------------------------------------------------------------------

struct Resp {
    status: u16,
    location: Option<String>,
    body: String,
}

struct KcBrowser {
    client: reqwest::Client,
    jar: BTreeMap<String, String>,
}

impl KcBrowser {
    fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("reqwest client"),
            jar: BTreeMap::new(),
        }
    }

    fn cookie_header(&self) -> Option<String> {
        (!self.jar.is_empty()).then(|| {
            self.jar
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ")
        })
    }

    async fn finish(&mut self, req: reqwest::RequestBuilder) -> Resp {
        let req = match self.cookie_header() {
            Some(cookies) => req.header("Cookie", cookies),
            None => req,
        };
        let resp = req.send().await.expect("Keycloak answers");
        for value in resp.headers().get_all("set-cookie") {
            let text = value.to_str().unwrap_or_default();
            let (pair, attrs) = text.split_once(';').unwrap_or((text, ""));
            if let Some((name, val)) = pair.split_once('=') {
                let expired = val.is_empty() || attrs.to_ascii_lowercase().contains("max-age=0");
                if expired {
                    self.jar.remove(name.trim());
                } else {
                    self.jar.insert(name.trim().to_owned(), val.to_owned());
                }
            }
        }
        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = resp.text().await.unwrap_or_default();
        Resp {
            status,
            location,
            body,
        }
    }

    async fn get(&mut self, url: &str) -> Resp {
        let req = self.client.get(url);
        self.finish(req).await
    }

    async fn post_form(&mut self, url: &str, fields: &[(String, String)]) -> Resp {
        let req = self.client.post(url).form(fields);
        self.finish(req).await
    }
}

struct KeycloakAdmin {
    base: String,
    client: reqwest::Client,
    token: String,
}

impl KeycloakAdmin {
    async fn login() -> Self {
        let base = keycloak_url();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client");
        let resp = client
            .post(format!(
                "{base}/realms/master/protocol/openid-connect/token"
            ))
            .form(&[
                ("grant_type", "password"),
                ("client_id", "admin-cli"),
                ("username", &keycloak_admin_user()),
                ("password", &keycloak_admin_password()),
            ])
            .send()
            .await
            .expect("reach Keycloak's master realm token endpoint");
        assert!(
            resp.status().is_success(),
            "Keycloak admin login failed: {}",
            resp.status()
        );
        let body: Value = resp.json().await.expect("admin token response is JSON");
        let token = body["access_token"]
            .as_str()
            .expect("an admin access token")
            .to_string();
        Self {
            base,
            client,
            token,
        }
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> (u16, String) {
        let resp = req
            .bearer_auth(&self.token)
            .send()
            .await
            .expect("Keycloak admin API answers");
        (
            resp.status().as_u16(),
            resp.text().await.unwrap_or_default(),
        )
    }

    async fn get(&self, path: &str) -> (u16, Value) {
        let (status, text) = self
            .send(self.client.get(format!("{}{path}", self.base)))
            .await;
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    async fn post(&self, path: &str, body: Value) -> (u16, Value) {
        let (status, text) = self
            .send(self.client.post(format!("{}{path}", self.base)).json(&body))
            .await;
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    async fn delete(&self, path: &str) -> u16 {
        self.send(self.client.delete(format!("{}{path}", self.base)))
            .await
            .0
    }

    /// Keycloak's own reading of an IdP metadata document: the SAML identity
    /// provider configuration it would build, via a hand-built
    /// `multipart/form-data` body (`import-config` takes the document as a file).
    async fn import_idp_config(&self, realm: &str, metadata_xml: &str) -> Value {
        let boundary = format!("----axiam{}", Uuid::new_v4().simple());
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"providerId\"\r\n\r\nsaml\r\n\
             --{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"idp.xml\"\r\n\
             Content-Type: application/xml\r\n\r\n{metadata_xml}\r\n--{boundary}--\r\n"
        );
        let (status, text) = self
            .send(
                self.client
                    .post(format!(
                        "{}/admin/realms/{realm}/identity-provider/import-config",
                        self.base
                    ))
                    .header(
                        "Content-Type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(body),
            )
            .await;
        assert_eq!(status, 200, "Keycloak reads AXIAM's IdP metadata");
        serde_json::from_str(&text).expect("an import-config answer")
    }
}

// ---------------------------------------------------------------------------
// HTML forms
// ---------------------------------------------------------------------------

fn unescape(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x3D;", "=")
        .replace("&#x2F;", "/")
        .replace("&#x2B;", "+")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// The value of attribute `name` in an HTML tag, case-insensitively, in either
/// quote style.
fn tag_attr(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(i) = lower[from..].find(name) {
        let start = from + i;
        let before_ok = start == 0 || !lower.as_bytes()[start - 1].is_ascii_alphanumeric();
        let rest = &lower[start + name.len()..];
        if before_ok && rest.trim_start().starts_with('=') {
            let after_eq = &tag[start + name.len()..];
            let after_eq = after_eq.trim_start().strip_prefix('=')?.trim_start();
            let quote = after_eq.chars().next()?;
            if quote == '"' || quote == '\'' {
                let inner = &after_eq[1..];
                let end = inner.find(quote)?;
                return Some(unescape(&inner[..end]));
            }
            let end = after_eq
                .find(|c: char| c.is_whitespace() || c == '>')
                .unwrap_or(after_eq.len());
            return Some(unescape(&after_eq[..end]));
        }
        from = start + name.len();
    }
    None
}

/// The first form of an HTML page: `(action, [(name, value)])`.
fn parse_form(html: &str) -> Option<(String, Vec<(String, String)>)> {
    let lower = html.to_ascii_lowercase();
    let form_start = lower.find("<form")?;
    let form_tag_end = lower[form_start..].find('>')? + form_start;
    let action = tag_attr(&html[form_start..=form_tag_end], "action")?;
    let form_end = lower[form_start..]
        .find("</form")
        .map_or(html.len(), |i| i + form_start);
    let mut fields = Vec::new();
    let mut at = form_start;
    while let Some(i) = lower[at..form_end].find("<input") {
        let start = at + i;
        let end = lower[start..].find('>')? + start;
        let tag = &html[start..=end];
        if let Some(name) = tag_attr(tag, "name") {
            fields.push((name, tag_attr(tag, "value").unwrap_or_default()));
        }
        at = end;
    }
    Some((action, fields))
}

fn field(fields: &[(String, String)], name: &str) -> Option<String> {
    fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
}

/// A page's `<title>` and the names of its form fields: what to say about a page
/// the test did not expect, never its values.
fn describe(resp: &Resp) -> String {
    let lower = resp.body.to_ascii_lowercase();
    let title = lower
        .find("<title>")
        .and_then(|i| {
            lower[i + 7..]
                .find("</title>")
                .map(|j| resp.body[i + 7..i + 7 + j].trim().to_owned())
        })
        .unwrap_or_default();
    let names: Vec<String> = parse_form(&resp.body)
        .map(|(_, f)| f.into_iter().map(|(k, _)| k).collect())
        .unwrap_or_default();
    format!(
        "status {}, title {title:?}, form fields {names:?}",
        resp.status
    )
}

/// Follow redirects from `resp` (cookies kept) until the next hop would go to a
/// URL beginning with `stop_at`, or the page is not a redirect.
async fn follow(browser: &mut KcBrowser, mut resp: Resp, stop_at: &[&str]) -> Resp {
    for _ in 0..16 {
        let Some(next) = resp.location.clone() else {
            return resp;
        };
        if !matches!(resp.status, 301 | 302 | 303 | 307 | 308)
            || stop_at.iter().any(|p| next.starts_with(p))
        {
            return resp;
        }
        resp = browser.get(&next).await;
    }
    panic!("Keycloak redirected more than sixteen times");
}

fn query_param(url: &str, name: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

// ---------------------------------------------------------------------------
// The round trip
// ---------------------------------------------------------------------------

/// What Keycloak exports as its SP metadata, and what AXIAM answers to it.
struct Exported {
    draft: Value,
}

/// Seed a realm that brokers to AXIAM's metadata, and register the Keycloak SP in
/// AXIAM from the SP metadata Keycloak exports.
///
/// `post_binding` picks the AuthnRequest binding Keycloak uses; the request is
/// signed either way.
async fn seed(
    kc: &KeycloakAdmin,
    realm: &str,
    idp_xml: &str,
    post_binding: bool,
) -> (String, String) {
    // A fixed realm name makes a failed run inspectable by hand; delete it first
    // so the run is repeatable against a Keycloak that already holds one.
    kc.delete(&format!("/admin/realms/{realm}")).await;
    let (status, _) = kc
        .post("/admin/realms", json!({ "realm": realm, "enabled": true }))
        .await;
    assert_eq!(status, 201, "the realm is created");

    let (status, _) = kc
        .post(
            &format!("/admin/realms/{realm}/clients"),
            json!({
                "clientId": CLIENT_ID,
                "enabled": true,
                "publicClient": true,
                "standardFlowEnabled": true,
                "directAccessGrantsEnabled": false,
                "redirectUris": [format!("{RP_REDIRECT}*")],
            }),
        )
        .await;
    assert_eq!(status, 201, "the relying-party client is created");

    // Keycloak reads AXIAM's IdP metadata itself.
    let mut config = kc.import_idp_config(realm, idp_xml).await;
    config["validateSignature"] = json!("true");
    config["wantAssertionsSigned"] = json!("true");
    config["wantAuthnRequestsSigned"] = json!("true");
    config["signatureAlgorithm"] = json!("RSA_SHA256");
    config["postBindingAuthnRequest"] = json!(post_binding.to_string());
    config["postBindingResponse"] = json!("true");
    let (status, _) = kc
        .post(
            &format!("/admin/realms/{realm}/identity-provider/instances"),
            json!({ "alias": ALIAS, "providerId": "saml", "enabled": true, "config": config.clone() }),
        )
        .await;
    assert_eq!(status, 201, "the SAML identity provider is created");

    // The SAML attributes AXIAM's registration will assert become the brokered
    // user's profile.
    for (name, mapper, mapper_config) in [
        (
            "username",
            "saml-username-idp-mapper",
            json!({ "syncMode": "INHERIT", "template": "${ATTRIBUTE.uid}", "target": "LOCAL" }),
        ),
        (
            "email",
            "saml-user-attribute-idp-mapper",
            json!({ "syncMode": "INHERIT", "attribute.name": "mail", "user.attribute": "email" }),
        ),
        (
            "first name",
            "saml-user-attribute-idp-mapper",
            json!({ "syncMode": "INHERIT", "attribute.name": "givenName", "user.attribute": "firstName" }),
        ),
        (
            "last name",
            "saml-user-attribute-idp-mapper",
            json!({ "syncMode": "INHERIT", "attribute.name": "sn", "user.attribute": "lastName" }),
        ),
    ] {
        let (status, _) = kc
            .post(
                &format!("/admin/realms/{realm}/identity-provider/instances/{ALIAS}/mappers"),
                json!({
                    "name": name,
                    "identityProviderAlias": ALIAS,
                    "identityProviderMapper": mapper,
                    "config": mapper_config,
                }),
            )
            .await;
        assert_eq!(status, 201, "the {name} mapper is created");
    }
    (
        config["singleSignOnServiceUrl"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        config["signingCertificate"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    )
}

/// Keycloak's exported SP metadata (the broker endpoint descriptor), run through
/// AXIAM's `parse_sp_metadata`.
async fn export_and_parse(app: &impl TestApp, w: &World, realm: &str) -> Exported {
    let descriptor = reqwest::Client::new()
        .get(format!(
            "{}/realms/{realm}/broker/{ALIAS}/endpoint/descriptor",
            keycloak_url()
        ))
        .send()
        .await
        .expect("Keycloak serves its SP descriptor")
        .text()
        .await
        .unwrap();
    assert!(
        descriptor.contains("SPSSODescriptor"),
        "Keycloak exports an SP descriptor"
    );
    let (status, text) = admin_call(
        app,
        w,
        Method::POST,
        "parse-sp-metadata",
        Some(json!({ "metadata_xml": descriptor })),
    )
    .await;
    assert_eq!(
        status,
        200,
        "AXIAM reads Keycloak's SP metadata (answer: {})",
        json_of(&text)["message"].as_str().unwrap_or("no message")
    );
    Exported {
        draft: json_of(&text),
    }
}

/// A broker login taken as far as AXIAM's answer: Keycloak's browser (cookies
/// and all) and the signed response AXIAM issued for Keycloak's request.
struct BrokerLeg {
    kc_browser: KcBrowser,
    action: String,
    response_b64: String,
    response_xml: String,
    relay: Option<String>,
    request_id: String,
}

impl BrokerLeg {
    /// Start a login at Keycloak, carry its `AuthnRequest` to AXIAM, sign `alice`
    /// in at AXIAM's login hop, and return AXIAM's answer — not yet delivered.
    async fn start(
        app: &impl TestApp,
        w: &World,
        realm: &str,
        post_binding: bool,
        idp_sso: &str,
        kc_acs: &str,
    ) -> Self {
        let mut kc_browser = KcBrowser::new();
        let auth_url = format!(
            "{}/realms/{realm}/protocol/openid-connect/auth?client_id={CLIENT_ID}\
             &response_type=code&scope=openid&redirect_uri={}&state=e2e-state&nonce=e2e-nonce\
             &kc_idp_hint={ALIAS}",
            keycloak_url(),
            enc(RP_REDIRECT)
        );
        let started = kc_browser.get(&auth_url).await;
        let at_idp = follow(&mut kc_browser, started, &[ROOT_ISSUER]).await;

        // The AuthnRequest Keycloak sends, on the binding it was told to use.
        let mut axiam_browser = Browser::default();
        let (first_leg, request_xml) = if post_binding {
            let (action, fields) = parse_form(&at_idp.body)
                .unwrap_or_else(|| panic!("a SAML POST form ({})", describe(&at_idp)));
            assert_eq!(action, idp_sso, "posted to AXIAM's SSO endpoint");
            let request = field(&fields, "SAMLRequest").expect("a SAMLRequest");
            let relay = field(&fields, "RelayState").unwrap_or_default();
            let xml = String::from_utf8(STANDARD.decode(&request).unwrap()).unwrap();
            let resp = axiam_browser
                .post_form(
                    app,
                    &path_and_query(&action),
                    format!("SAMLRequest={}&RelayState={}", enc(&request), enc(&relay)),
                )
                .await;
            (resp, xml)
        } else {
            let target = at_idp
                .location
                .clone()
                .unwrap_or_else(|| panic!("a redirect to the IdP ({})", describe(&at_idp)));
            assert!(target.starts_with(idp_sso), "redirected to AXIAM's SSO");
            let message = query_param(&target, "SAMLRequest").expect("a SAMLRequest");
            assert!(
                query_param(&target, "Signature").is_some()
                    && query_param(&target, "SigAlg").is_some(),
                "Keycloak signs its Redirect-bound request"
            );
            let xml = axiam_federation::saml_idp::request::decode_redirect(&message)
                .expect("an inflated AuthnRequest");
            let resp = axiam_browser.get(app, &path_and_query(&target)).await;
            (resp, xml)
        };
        let request_id = attr(&request_xml, "ID").expect("the request's ID");
        assert_eq!(
            first_leg.status().as_u16(),
            303,
            "AXIAM accepts Keycloak's signed request"
        );

        // The user signs in at AXIAM's real login hop; AXIAM answers with the
        // auto-post page for Keycloak's broker endpoint.
        let page = complete_login(app, w, &mut axiam_browser, &first_leg, "alice").await;
        let (action, response_b64, relay) = posted_response_b64(&page);
        assert_eq!(action, kc_acs, "posted to the ACS Keycloak registered");
        let response_xml = String::from_utf8(STANDARD.decode(&response_b64).unwrap()).unwrap();
        Self {
            kc_browser,
            action,
            response_b64,
            response_xml,
            relay,
            request_id,
        }
    }
}

/// Post a `SAMLResponse` to Keycloak's broker endpoint from `browser` and follow
/// Keycloak until it stops redirecting or sends the browser to the relying party.
async fn deliver(
    browser: &mut KcBrowser,
    action: &str,
    response_b64: &str,
    relay: Option<String>,
) -> Resp {
    let mut fields = vec![("SAMLResponse".to_owned(), response_b64.to_owned())];
    if let Some(relay) = relay {
        fields.push(("RelayState".to_owned(), relay));
    }
    let answered = browser.post_form(action, &fields).await;
    follow(browser, answered, &[RP_REDIRECT]).await
}

/// Whether the login ended at the relying party with an authorization code.
fn finished_with_code(resp: &Resp) -> bool {
    resp.location
        .as_deref()
        .is_some_and(|l| l.starts_with(RP_REDIRECT) && query_param(l, "code").is_some())
}

/// The whole round trip for one AuthnRequest binding.
async fn round_trip(post_binding: bool) {
    let realm = if post_binding {
        "axiam-saml-e2e-post"
    } else {
        "axiam-saml-e2e-redirect"
    };
    let w = world().await;
    let app = e2e_app!(w);
    issue_idp_credential(&app, &w).await;
    let idp_xml = fetch_idp_metadata(&app, w.tenant_id).await;
    let idp_sso = format!("{ROOT_ISSUER}/saml/v2/{}/sso", w.tenant_id);

    let kc = KeycloakAdmin::login().await;
    let (kc_sso, kc_signing_cert) = seed(&kc, realm, &idp_xml, post_binding).await;

    // Keycloak understood AXIAM's metadata: the SSO location, the entity id and
    // the certificate are the IdP's own.
    assert_eq!(kc_sso, idp_sso, "Keycloak took AXIAM's SSO location");
    let parsed: EntityDescriptor = idp_xml.parse().expect("samael reads the IdP metadata");
    let published = parsed.idp_sso_descriptors.as_ref().unwrap()[0].key_descriptors[0]
        .key_info
        .x509_data
        .as_ref()
        .unwrap()
        .certificates[0]
        .split_whitespace()
        .collect::<String>();
    assert!(
        kc_signing_cert.split_whitespace().collect::<String>() == published,
        "Keycloak took AXIAM's signing certificate"
    );

    // Keycloak's SP metadata, into AXIAM's registry.
    let exported = export_and_parse(&app, &w, realm).await;
    let kc_entity = format!("{}/realms/{realm}", keycloak_url());
    let kc_acs = format!("{}/realms/{realm}/broker/{ALIAS}/endpoint", keycloak_url());
    let mut sp = exported.draft["service_provider"].clone();
    assert_eq!(
        sp["entity_id"], kc_entity,
        "the draft names Keycloak's entity"
    );
    assert_eq!(
        sp["want_authn_requests_signed"], true,
        "Keycloak's metadata says it signs its requests"
    );
    assert!(
        sp["sp_signing_cert_pem"].is_string(),
        "the draft carries Keycloak's request-signing certificate"
    );
    assert!(
        sp["acs_urls"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["url"] == kc_acs && a["binding"] == "http_post"),
        "the draft carries the broker endpoint as an HTTP-POST ACS"
    );
    assert!(
        exported.draft["signing_certificate_fingerprint"].is_string(),
        "the draft carries the fingerprint of that certificate"
    );
    // The administrator's own choices: what AXIAM asserts about the user.
    sp["attribute_mappings"] = json!([
        { "saml_name": "uid", "source": "username" },
        { "saml_name": "mail", "source": "email" },
        { "saml_name": "givenName", "source": "given_name" },
        { "saml_name": "sn", "source": "family_name" },
    ]);
    register_sp(&app, &w, sp).await;

    // Three browsers each get as far as AXIAM's answer.
    let leg = |_: ()| BrokerLeg::start(&app, &w, realm, post_binding, &idp_sso, &kc_acs);
    let tampered_leg = leg(()).await;
    let crossed_leg = leg(()).await;
    let mut genuine = leg(()).await;

    // A response whose attribute was changed after AXIAM signed it: Keycloak
    // refuses it, and no user is made from it.
    let forged = tampered_leg
        .response_xml
        .replace(&alice_email(), "mallory@example.com");
    assert_ne!(forged, tampered_leg.response_xml);
    let mut tampered_browser = tampered_leg.kc_browser;
    let outcome = deliver(
        &mut tampered_browser,
        &tampered_leg.action,
        &STANDARD.encode(forged),
        tampered_leg.relay.clone(),
    )
    .await;
    assert!(
        !finished_with_code(&outcome),
        "Keycloak refuses a response whose signed content was changed"
    );
    let (_, mallory) = kc
        .get(&format!(
            "/admin/realms/{realm}/users?email=mallory@example.com&exact=true"
        ))
        .await;
    assert!(
        mallory.as_array().is_some_and(Vec::is_empty),
        "and no user was made from it"
    );

    // A genuine response, delivered into another browser's login: Keycloak
    // refuses it, because it answers a request that browser never made.
    let mut crossed_browser = crossed_leg.kc_browser;
    let outcome = deliver(
        &mut crossed_browser,
        &genuine.action,
        &genuine.response_b64,
        genuine.relay.clone(),
    )
    .await;
    assert!(
        !finished_with_code(&outcome),
        "Keycloak refuses a response that answers a different request"
    );

    // The same response as an independent SP library reads it, with Keycloak's
    // request id: whatever Keycloak concludes, `samael` as an SP agrees.
    let reference = ServiceProviderBuilder::default()
        .entity_id(kc_entity.clone())
        .acs_url(kc_acs.clone())
        .idp_metadata(parsed.clone())
        .max_clock_skew(chrono::Duration::zero())
        .allowed_signature_algorithms(vec![AllowedSignatureAlgorithm::RsaSha256])
        .build()
        .unwrap();
    let assertion = reference
        .parse_xml_response(&genuine.response_xml, Some(&[genuine.request_id.as_str()]))
        .expect("samael accepts the response to Keycloak's request");
    let name_id = assertion
        .subject
        .as_ref()
        .and_then(|s| s.name_id.as_ref())
        .map(|n| n.value.clone())
        .expect("a NameID");

    // The genuine one, into the browser that asked: accepted, to the end.
    let landed = deliver(
        &mut genuine.kc_browser,
        &genuine.action,
        &genuine.response_b64,
        genuine.relay.clone(),
    )
    .await;
    let callback = landed.location.clone().unwrap_or_else(|| {
        panic!(
            "Keycloak accepted the response and finished the login ({})",
            describe(&landed)
        )
    });
    assert!(
        callback.starts_with(RP_REDIRECT),
        "Keycloak sent the browser back to the relying party"
    );
    assert_eq!(
        query_param(&callback, "state").as_deref(),
        Some("e2e-state"),
        "with the relying party's state"
    );
    let code = query_param(&callback, "code").expect("an authorization code");

    // The tokens' claims are the SAML attributes AXIAM asserted.
    let tokens: Value = reqwest::Client::new()
        .post(format!(
            "{}/realms/{realm}/protocol/openid-connect/token",
            keycloak_url()
        ))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", CLIENT_ID),
            ("code", code.as_str()),
            ("redirect_uri", RP_REDIRECT),
        ])
        .send()
        .await
        .expect("Keycloak's token endpoint answers")
        .json()
        .await
        .expect("a token response");
    let id_token = tokens["id_token"].as_str().expect("an ID token");
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(id_token.split('.').nth(1).expect("a JWT payload"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["preferred_username"], "alice");
    assert_eq!(claims["email"], alice_email());
    assert_eq!(claims["given_name"], "Alice");
    assert_eq!(claims["family_name"], "Example");

    // And the brokered identity Keycloak linked is the pairwise NameID AXIAM
    // asserted — not the username, not the email.
    let (_, users) = kc
        .get(&format!(
            "/admin/realms/{realm}/users?username=alice&exact=true"
        ))
        .await;
    let user_id = users[0]["id"].as_str().expect("the brokered user");
    let (_, links) = kc
        .get(&format!(
            "/admin/realms/{realm}/users/{user_id}/federated-identity"
        ))
        .await;
    let link = &links[0];
    assert_eq!(link["identityProvider"], ALIAS);
    assert!(
        link["userId"].as_str() == Some(name_id.as_str()),
        "Keycloak's federated identity is AXIAM's pairwise NameID"
    );
    assert!(
        !name_id.contains("alice") && !name_id.contains('@'),
        "and that identifier reveals neither the username nor the email"
    );

    // Replaying the accepted response into the same browser is refused: the login
    // it answered is over.
    let replay = deliver(
        &mut genuine.kc_browser,
        &genuine.action,
        &genuine.response_b64,
        genuine.relay.clone(),
    )
    .await;
    assert!(
        !finished_with_code(&replay),
        "Keycloak refuses a replayed response"
    );

    kc.delete(&format!("/admin/realms/{realm}")).await;
}

/// **Acceptance: the Keycloak round trip, HTTP-POST AuthnRequest** (an enveloped
/// signature).
#[actix_rt::test]
#[ignore = "needs a running Keycloak (docker-compose.e2e.yml); see the module docs"]
async fn keycloak_brokers_to_axiam_over_http_post() {
    Box::pin(round_trip(true)).await;
}

/// **Acceptance: the Keycloak round trip, HTTP-Redirect AuthnRequest** (a detached
/// query signature, verified over the exact octets Keycloak sent).
#[actix_rt::test]
#[ignore = "needs a running Keycloak (docker-compose.e2e.yml); see the module docs"]
async fn keycloak_brokers_to_axiam_over_http_redirect() {
    Box::pin(round_trip(false)).await;
}
