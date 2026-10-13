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
//! # Single logout, from each side (P23W4-09)
//!
//! The same brokered session is then ended from either end, on either binding —
//! Keycloak's identity provider is told to log out over HTTP-POST or
//! HTTP-Redirect (`postBindingLogout`, front channel: `backchannelSupported` is
//! off), and AXIAM's registration of Keycloak's `SingleLogoutService` names the
//! same binding:
//!
//! * **Keycloak-initiated.** The relying party signs the user out at Keycloak
//!   (`/protocol/openid-connect/logout`); Keycloak sends its own signed
//!   `LogoutRequest` — its `NameID` and the `SessionIndex` AXIAM gave it — to
//!   AXIAM's `/slo`; AXIAM revokes the session and answers with a signed
//!   `LogoutResponse` at Keycloak's registered endpoint, which Keycloak verifies
//!   before it finishes the logout at the relying party's post-logout URI.
//! * **AXIAM-initiated.** The user signs out at AXIAM (`/sso/logout`); AXIAM
//!   revokes the session and sends Keycloak a signed `LogoutRequest`; Keycloak
//!   verifies it, ends its own session by the `SessionIndex`, and answers with
//!   its signed `LogoutResponse`, which AXIAM verifies and counts as a confirmed
//!   logout.
//!
//! Either way the AXIAM session is in `/oauth2/revocations`, its access token is
//! refused, no participant row is left, and Keycloak's admin API lists no session
//! for the brokered user. The browser is still the test: it carries every
//! logout message exactly as it carries the sign-on messages. The logout tests
//! install the IdP credential directly (`install_idp_credential`, RSA-4096 like
//! the administrator route's, sealed the same way) instead of minting one through
//! the PKI route, which the sign-on tests already prove and which costs about a
//! minute per world in a debug build.
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
use axiam_core::revocation_feed::revocation_hash;
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
/// Where Keycloak sends the browser once a logout the relying party started is
/// finished. Nothing listens here either.
const RP_LOGGED_OUT: &str = "http://127.0.0.1:1/logged-out";

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

/// What Keycloak made of AXIAM's IdP metadata.
struct Seeded {
    /// The SSO location it imported.
    sso: String,
    /// The single-logout location it imported, before `seed` set it.
    imported_slo: String,
    /// The signing certificate it imported.
    signing_cert: String,
}

/// Seed a realm that brokers to AXIAM's metadata, and register the Keycloak SP in
/// AXIAM from the SP metadata Keycloak exports.
///
/// `post_binding` picks the binding Keycloak uses for its AuthnRequest and for
/// its logout messages to AXIAM (front channel, `idp_slo`); both are signed
/// either way.
async fn seed(
    kc: &KeycloakAdmin,
    realm: &str,
    idp_xml: &str,
    idp_slo: &str,
    post_binding: bool,
) -> Seeded {
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
                "attributes": { "post.logout.redirect.uris": RP_LOGGED_OUT },
            }),
        )
        .await;
    assert_eq!(status, 201, "the relying-party client is created");

    // Keycloak reads AXIAM's IdP metadata itself.
    let mut config = kc.import_idp_config(realm, idp_xml).await;
    let imported_slo = config["singleLogoutServiceUrl"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    config["validateSignature"] = json!("true");
    config["wantAssertionsSigned"] = json!("true");
    config["wantAuthnRequestsSigned"] = json!("true");
    config["signatureAlgorithm"] = json!("RSA_SHA256");
    config["postBindingAuthnRequest"] = json!(post_binding.to_string());
    config["postBindingResponse"] = json!("true");
    // Single logout through the browser on the same binding as the AuthnRequest;
    // the logout messages Keycloak sends are signed because its AuthnRequests are
    // (`wantAuthnRequestsSigned`), and AXIAM's are verified (`validateSignature`).
    config["singleLogoutServiceUrl"] = json!(idp_slo);
    config["postBindingLogout"] = json!(post_binding.to_string());
    config["backchannelSupported"] = json!("false");
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
    Seeded {
        sso: config["singleSignOnServiceUrl"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        imported_slo,
        signing_cert: config["signingCertificate"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    }
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
    /// The same browser's AXIAM cookies: the OP cookie the login hop minted.
    axiam_browser: Browser,
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
            axiam_browser,
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

/// Route the server's log into the test's captured output. AXIAM logs why it
/// refuses a SAML message (`request_refused` and the other refusal pages) and
/// answers only a fixed page, so a failing leg says no more than its status; with
/// this, a failure prints the refusal reason with the panic.
fn capture_server_log() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::INFO)
        .with_test_writer()
        .with_ansi(false)
        .try_init();
}

/// A realm brokering to AXIAM, and Keycloak registered in AXIAM as an SP.
struct Prepared {
    kc: KeycloakAdmin,
    realm: &'static str,
    parsed: EntityDescriptor,
    idp_sso: String,
    idp_slo: String,
    kc_entity: String,
    /// Keycloak's broker endpoint: its ACS and its `SingleLogoutService` both.
    kc_acs: String,
}

/// Seed `realm` from AXIAM's metadata, check what Keycloak made of it, and
/// register Keycloak's exported SP metadata in AXIAM. The tenant's IdP credential
/// must already be active.
///
/// `post_binding` picks the binding of Keycloak's AuthnRequest and of its logout
/// messages, and the `SingleLogoutService` binding AXIAM registers for Keycloak.
async fn prepare(
    app: &impl TestApp,
    w: &World,
    realm: &'static str,
    post_binding: bool,
) -> Prepared {
    let idp_xml = fetch_idp_metadata(app, w.tenant_id).await;
    let idp_sso = format!("{ROOT_ISSUER}/saml/v2/{}/sso", w.tenant_id);
    let idp_slo = format!("{ROOT_ISSUER}/saml/v2/{}/slo", w.tenant_id);

    let kc = KeycloakAdmin::login().await;
    let seeded = seed(&kc, realm, &idp_xml, &idp_slo, post_binding).await;

    // Keycloak understood AXIAM's metadata: the SSO and SLO locations, the entity
    // id and the certificate are the IdP's own.
    assert_eq!(seeded.sso, idp_sso, "Keycloak took AXIAM's SSO location");
    assert_eq!(
        seeded.imported_slo, idp_slo,
        "Keycloak took AXIAM's single-logout location"
    );
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
        seeded.signing_cert.split_whitespace().collect::<String>() == published,
        "Keycloak took AXIAM's signing certificate"
    );

    // Keycloak's SP metadata, into AXIAM's registry.
    let exported = export_and_parse(app, w, realm).await;
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
    // Keycloak exports its broker endpoint as a SingleLogoutService on both
    // bindings; the import keeps one, HTTP-Redirect first.
    assert_eq!(
        sp["slo_url"], kc_acs,
        "the draft carries the broker endpoint as the SingleLogoutService"
    );
    assert_eq!(sp["slo_binding"], "http_redirect");
    // The administrator's own choices: what AXIAM asserts about the user, and the
    // binding AXIAM's logout messages take to Keycloak.
    sp["attribute_mappings"] = json!([
        { "saml_name": "uid", "source": "username" },
        { "saml_name": "mail", "source": "email" },
        { "saml_name": "givenName", "source": "given_name" },
        { "saml_name": "sn", "source": "family_name" },
    ]);
    if post_binding {
        sp["slo_binding"] = json!("http_post");
    }
    register_sp(app, w, sp).await;

    Prepared {
        kc,
        realm,
        parsed,
        idp_sso,
        idp_slo,
        kc_entity,
        kc_acs,
    }
}

/// Exchange an authorization code at Keycloak's token endpoint.
async fn exchange_code(realm: &str, code: &str) -> Value {
    reqwest::Client::new()
        .post(format!(
            "{}/realms/{realm}/protocol/openid-connect/token",
            keycloak_url()
        ))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", CLIENT_ID),
            ("code", code),
            ("redirect_uri", RP_REDIRECT),
        ])
        .send()
        .await
        .expect("Keycloak's token endpoint answers")
        .json()
        .await
        .expect("a token response")
}

/// The id of the user Keycloak brokered from AXIAM's `alice`.
async fn brokered_user_id(kc: &KeycloakAdmin, realm: &str) -> String {
    let (_, users) = kc
        .get(&format!(
            "/admin/realms/{realm}/users?username=alice&exact=true"
        ))
        .await;
    users[0]["id"]
        .as_str()
        .expect("the brokered user")
        .to_owned()
}

/// The whole round trip for one AuthnRequest binding.
async fn round_trip(post_binding: bool) {
    capture_server_log();
    let realm = if post_binding {
        "axiam-saml-e2e-post"
    } else {
        "axiam-saml-e2e-redirect"
    };
    let w = world().await;
    let app = e2e_app!(w);
    issue_idp_credential(&app, &w).await;
    let p = prepare(&app, &w, realm, post_binding).await;
    let kc = &p.kc;

    // Three browsers each get as far as AXIAM's answer.
    let leg = |_: ()| BrokerLeg::start(&app, &w, realm, post_binding, &p.idp_sso, &p.kc_acs);
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
    let assertion = reference_sp(&p)
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
    let tokens = exchange_code(realm, &code).await;
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
    let user_id = brokered_user_id(kc, realm).await;
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

/// `samael` as Keycloak's SP would be: Keycloak's entity and ACS, AXIAM's
/// metadata, no clock skew, RSA-SHA-256 only.
fn reference_sp(p: &Prepared) -> samael::service_provider::ServiceProvider {
    ServiceProviderBuilder::default()
        .entity_id(p.kc_entity.clone())
        .acs_url(p.kc_acs.clone())
        .idp_metadata(p.parsed.clone())
        .max_clock_skew(chrono::Duration::zero())
        .allowed_signature_algorithms(vec![AllowedSignatureAlgorithm::RsaSha256])
        .build()
        .unwrap()
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

// ---------------------------------------------------------------------------
// Single logout (P23W4-09)
// ---------------------------------------------------------------------------

/// A brokered session, live at both ends.
struct SignedOn {
    kc_browser: KcBrowser,
    axiam_browser: Browser,
    id_token: String,
    /// The pairwise `NameID` and the `SessionIndex` AXIAM asserted to Keycloak.
    name_id: String,
    session_index: String,
    kc_user_id: String,
    /// The AXIAM session the participant row names.
    axiam_session: Uuid,
}

/// One broker login, taken to the end: Keycloak's tokens for the relying party,
/// a Keycloak session for the brokered user, an AXIAM session behind it.
async fn sign_on(app: &impl TestApp, w: &World, p: &Prepared, post_binding: bool) -> SignedOn {
    let mut leg = BrokerLeg::start(app, w, p.realm, post_binding, &p.idp_sso, &p.kc_acs).await;
    let assertion = reference_sp(p)
        .parse_xml_response(&leg.response_xml, Some(&[leg.request_id.as_str()]))
        .expect("samael accepts the response to Keycloak's request");
    let name_id = assertion
        .subject
        .as_ref()
        .and_then(|s| s.name_id.as_ref())
        .map(|n| n.value.clone())
        .expect("a NameID");
    let session_index = assertion
        .authn_statements
        .iter()
        .flatten()
        .find_map(|s| s.session_index.clone())
        .expect("a SessionIndex");
    let landed = deliver(
        &mut leg.kc_browser,
        &leg.action,
        &leg.response_b64,
        leg.relay.clone(),
    )
    .await;
    assert!(
        finished_with_code(&landed),
        "Keycloak finished the login ({})",
        describe(&landed)
    );
    let code = query_param(landed.location.as_deref().unwrap(), "code").unwrap();
    let tokens = exchange_code(p.realm, &code).await;
    let id_token = tokens["id_token"].as_str().expect("an ID token").to_owned();

    let mut result =
        w.db.query("SELECT session_id FROM saml_sp_session")
            .await
            .unwrap();
    let rows: Vec<Value> = result.take(0).unwrap();
    assert_eq!(rows.len(), 1, "one participant row: Keycloak's");
    let axiam_session = Uuid::parse_str(rows[0]["session_id"].as_str().unwrap()).unwrap();

    SignedOn {
        kc_browser: leg.kc_browser,
        axiam_browser: leg.axiam_browser,
        id_token,
        name_id,
        session_index,
        kc_user_id: brokered_user_id(&p.kc, p.realm).await,
        axiam_session,
    }
}

/// The revocation feed's entries.
async fn revocation_feed(app: &impl TestApp) -> Vec<String> {
    let resp = actix_web::test::call_service(
        app,
        actix_web::test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<std::net::SocketAddr>().unwrap())
            .uri("/oauth2/revocations")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200, "the revocation feed answers");
    let body: Value = actix_web::test::read_body_json(resp).await;
    body["revoked"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

/// How many sessions Keycloak's admin API lists for the brokered user. A fresh
/// admin token each time: the master realm's tokens live a minute.
async fn keycloak_sessions(realm: &str, user_id: &str) -> usize {
    let kc = KeycloakAdmin::login().await;
    let (status, sessions) = kc
        .get(&format!("/admin/realms/{realm}/users/{user_id}/sessions"))
        .await;
    assert_eq!(status, 200, "Keycloak lists the user's sessions");
    sessions.as_array().map_or(0, Vec::len)
}

async fn participant_rows(w: &World) -> u64 {
    let mut result =
        w.db.query("SELECT count() AS n FROM saml_sp_session GROUP ALL")
            .await
            .unwrap();
    let rows: Vec<Value> = result.take(0).unwrap();
    rows.first().and_then(|r| r["n"].as_u64()).unwrap_or(0)
}

/// Both ends live: AXIAM's session works and is not in the feed; Keycloak holds
/// a session for the brokered user.
async fn assert_live(app: &impl TestApp, p: &Prepared, s: &SignedOn) {
    assert_eq!(s.axiam_browser.me(app).await, 200, "AXIAM's session works");
    assert!(
        !revocation_feed(app)
            .await
            .contains(&revocation_hash(s.axiam_session)),
        "and is not in the revocation feed"
    );
    assert_eq!(
        keycloak_sessions(p.realm, &s.kc_user_id).await,
        1,
        "Keycloak holds the brokered session"
    );
}

/// Both ends logged out: AXIAM's session is refused and in the feed, no
/// participant row is left, and Keycloak lists no session for the user.
async fn assert_logged_out(app: &impl TestApp, w: &World, p: &Prepared, s: &SignedOn) {
    assert_eq!(
        s.axiam_browser.me(app).await,
        401,
        "AXIAM's session is refused"
    );
    assert!(
        revocation_feed(app)
            .await
            .contains(&revocation_hash(s.axiam_session)),
        "the revocation feed shows the revocation"
    );
    assert_eq!(participant_rows(w).await, 0, "no participant row is left");
    assert_eq!(
        keycloak_sessions(p.realm, &s.kc_user_id).await,
        0,
        "Keycloak's session is gone"
    );
}

/// The `saml_idp.logout` row of the finished chain.
async fn completed_audit_row(w: &World) -> Value {
    let mut result =
        w.db.query("SELECT * FROM audit_log WHERE action = 'saml_idp.logout'")
            .await
            .unwrap();
    let rows: Vec<Value> = result.take(0).unwrap();
    rows.into_iter()
        .find(|r| r["metadata"]["phase"] == "completed")
        .expect("the chain's completed row")
}

/// A logout message on its way through the browser.
#[derive(Clone)]
struct Carried {
    /// The full URL of an HTTP-Redirect message; `None` on HTTP-POST.
    redirect: Option<String>,
    /// Where it goes: the URL without its query, or the form's action.
    endpoint: String,
    /// The form's fields, on HTTP-POST.
    fields: Vec<(String, String)>,
    /// The decoded document.
    xml: String,
    relay: Option<String>,
}

impl Carried {
    /// Read the message `field` from a redirect (`location`) or an auto-post page
    /// (`body`).
    fn read(status: u16, location: Option<&str>, body: &str, field: &str) -> Self {
        if matches!(status, 302 | 303) {
            let url = location.expect("a redirect carries a Location").to_owned();
            let endpoint = url
                .split_once('?')
                .map_or(url.as_str(), |(b, _)| b)
                .to_owned();
            let message = query_param(&url, field)
                .unwrap_or_else(|| panic!("a {field} in the redirect's query"));
            let xml = axiam_federation::saml_idp::request::decode_redirect(&message)
                .expect("an inflated message");
            assert!(
                query_param(&url, "Signature").is_some() && query_param(&url, "SigAlg").is_some(),
                "a Redirect-bound {field} carries its detached signature"
            );
            assert!(
                !xml.contains("SignatureValue"),
                "and no signature inside the document"
            );
            let relay = query_param(&url, "RelayState");
            return Self {
                redirect: Some(url),
                endpoint,
                fields: Vec::new(),
                xml,
                relay,
            };
        }
        assert_eq!(status, 200, "an auto-post page");
        let (endpoint, fields) = parse_form(body).expect("a SAML POST form");
        let value = field_value(&fields, field);
        let xml = String::from_utf8(STANDARD.decode(value).unwrap()).unwrap();
        assert!(
            xml.contains("SignatureValue"),
            "a POST-bound {field} is signed inside the document"
        );
        let relay = fields
            .iter()
            .find(|(k, _)| k == "RelayState")
            .map(|(_, v)| v.clone());
        Self {
            redirect: None,
            endpoint,
            fields,
            xml,
            relay,
        }
    }

    fn from_keycloak(resp: &Resp, field: &str) -> Self {
        Self::read(resp.status, resp.location.as_deref(), &resp.body, field)
    }

    async fn from_axiam(resp: actix_web::dev::ServiceResponse, field: &str) -> Self {
        let status = resp.status().as_u16();
        let loc = location(&resp);
        let body = body_of(resp).await;
        Self::read(
            status,
            Some(loc.as_str()).filter(|l| !l.is_empty()),
            &body,
            field,
        )
    }

    /// The same message with its signature broken and nothing else changed that
    /// a receiver acts on: on HTTP-Redirect one bit of the detached `Signature`
    /// flipped; on HTTP-POST the signed document's `IssueInstant` written with a
    /// fraction of a second (the same instant, other octets, so the digest no
    /// longer matches). For AXIAM's own messages, whose instants have no fraction.
    fn tampered(&self, field: &str) -> Self {
        let mut forged = self.clone();
        match &self.redirect {
            Some(url) => {
                let (head, tail) = url.split_once("&Signature=").expect("a Signature");
                let (signature, rest) = tail.split_once('&').unwrap_or((tail, ""));
                let raw = url::form_urlencoded::parse(format!("s={signature}").as_bytes())
                    .next()
                    .expect("a value")
                    .1
                    .into_owned();
                let mut bytes = STANDARD.decode(raw).expect("a base64 signature");
                let middle = bytes.len() / 2;
                bytes[middle] ^= 0x01;
                let mut url = format!("{head}&Signature={}", enc(&STANDARD.encode(bytes)));
                if !rest.is_empty() {
                    url.push('&');
                    url.push_str(rest);
                }
                forged.redirect = Some(url);
            }
            None => {
                let instant = attr(&self.xml, "IssueInstant").expect("an IssueInstant");
                assert!(instant.ends_with('Z') && !instant.contains('.'));
                let xml = self.xml.replacen(
                    &format!("IssueInstant=\"{instant}\""),
                    &format!("IssueInstant=\"{}.000Z\"", instant.trim_end_matches('Z')),
                    1,
                );
                assert_ne!(xml, self.xml);
                for (name, value) in &mut forged.fields {
                    if name == field {
                        *value = STANDARD.encode(&xml);
                    }
                }
                forged.xml = xml;
            }
        }
        forged
    }

    /// Carry it to AXIAM, from `browser`.
    async fn to_axiam(
        &self,
        app: &impl TestApp,
        browser: &mut Browser,
    ) -> actix_web::dev::ServiceResponse {
        match &self.redirect {
            Some(url) => browser.get(app, &path_and_query(url)).await,
            None => {
                let body = self
                    .fields
                    .iter()
                    .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
                    .collect::<Vec<_>>()
                    .join("&");
                browser
                    .post_form(app, &path_and_query(&self.endpoint), body)
                    .await
            }
        }
    }

    /// Carry it to Keycloak, from `browser`.
    async fn to_keycloak(&self, browser: &mut KcBrowser) -> Resp {
        match &self.redirect {
            Some(url) => browser.get(url).await,
            None => browser.post_form(&self.endpoint, &self.fields).await,
        }
    }
}

fn field_value(fields: &[(String, String)], name: &str) -> String {
    field(fields, name).unwrap_or_else(|| panic!("a {name} field"))
}

/// The text of the first element named `local` (any prefix) in `xml`.
fn element_text(xml: &str, local: &str) -> Option<String> {
    let mut from = 0;
    while let Some(i) = xml[from..].find(local) {
        let at = from + i;
        from = at + local.len();
        let Some(open) = xml[..at].rfind('<') else {
            continue;
        };
        let prefix = &xml[open + 1..at];
        let prefix_ok = prefix.is_empty()
            || prefix.strip_suffix(':').is_some_and(|p| {
                !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            });
        let next = xml[from..].chars().next();
        if prefix_ok && next.is_some_and(|c| c == '>' || c.is_whitespace()) {
            let start = xml[at..].find('>')? + at + 1;
            let end = xml[start..].find('<')? + start;
            return Some(xml[start..end].trim().to_owned());
        }
    }
    None
}

const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

/// A logout message's own checks: what it is, who it names, what it answers.
fn assert_logout_request(xml: &str, s: &SignedOn, from: &str) {
    assert!(
        element_text(xml, "NameID").as_deref() == Some(s.name_id.as_str()),
        "{from}'s LogoutRequest names the pairwise NameID AXIAM asserted"
    );
    assert!(
        element_text(xml, "SessionIndex").as_deref() == Some(s.session_index.as_str()),
        "{from}'s LogoutRequest names the SessionIndex AXIAM asserted"
    );
}

fn assert_success_response(xml: &str, in_response_to: &str, from: &str) {
    assert!(
        xml.contains("LogoutResponse"),
        "{from} answers with a LogoutResponse"
    );
    assert_eq!(
        attr(xml, "InResponseTo").as_deref(),
        Some(in_response_to),
        "{from}'s LogoutResponse answers the request it was sent"
    );
    assert!(
        xml.contains(STATUS_SUCCESS) && !xml.contains("PartialLogout"),
        "{from}'s LogoutResponse reports Success"
    );
}

fn slo_realm(initiator: &str, post_binding: bool) -> &'static str {
    match (initiator, post_binding) {
        ("keycloak", true) => "axiam-saml-slo-kc-post",
        ("keycloak", false) => "axiam-saml-slo-kc-redirect",
        (_, true) => "axiam-saml-slo-idp-post",
        (_, false) => "axiam-saml-slo-idp-redirect",
    }
}

/// **Keycloak-initiated single logout.** The relying party signs the user out at
/// Keycloak; Keycloak's signed `LogoutRequest` reaches AXIAM's `/slo`; AXIAM
/// revokes the session and answers with a signed `LogoutResponse`, which Keycloak
/// verifies before it finishes the logout.
async fn keycloak_initiated_logout(post_binding: bool) {
    capture_server_log();
    let realm = slo_realm("keycloak", post_binding);
    let w = world().await;
    let app = e2e_app!(w);
    install_idp_credential(&w).await;
    let p = prepare(&app, &w, realm, post_binding).await;
    let mut s = sign_on(&app, &w, &p, post_binding).await;
    assert_live(&app, &p, &s).await;

    // The relying party's logout at Keycloak (RP-initiated, with the ID token
    // hint, so no confirmation page). Keycloak sends the browser to AXIAM.
    let logout_url = format!(
        "{}/realms/{realm}/protocol/openid-connect/logout?client_id={CLIENT_ID}\
         &id_token_hint={}&post_logout_redirect_uri={}",
        keycloak_url(),
        enc(&s.id_token),
        enc(RP_LOGGED_OUT),
    );
    let started = s.kc_browser.get(&logout_url).await;
    let at_idp = follow(&mut s.kc_browser, started, &[ROOT_ISSUER]).await;

    // Keycloak's own LogoutRequest, on the binding it was told to use, signed.
    let request = Carried::from_keycloak(&at_idp, "SAMLRequest");
    assert_eq!(
        request.redirect.is_none(),
        post_binding,
        "Keycloak logs out on the binding it was told to use ({})",
        describe(&at_idp)
    );
    assert_eq!(request.endpoint, p.idp_slo, "sent to AXIAM's SLO endpoint");
    assert!(
        request.xml.contains("LogoutRequest"),
        "Keycloak sends a LogoutRequest"
    );
    assert_eq!(
        attr(&request.xml, "Destination").as_deref(),
        Some(p.idp_slo.as_str()),
        "addressed to AXIAM's SLO endpoint"
    );
    assert_logout_request(&request.xml, &s, "Keycloak");
    let request_id = attr(&request.xml, "ID").expect("the request's ID");
    let kc_relay = request.relay.clone().expect("Keycloak sends a RelayState");

    // AXIAM verifies it, revokes the session and answers at Keycloak's registered
    // SingleLogoutService on the registered binding.
    let answered = request.to_axiam(&app, &mut s.axiam_browser).await;
    let response = Carried::from_axiam(answered, "SAMLResponse").await;
    assert_eq!(
        response.redirect.is_none(),
        post_binding,
        "AXIAM answers on the binding registered for Keycloak"
    );
    assert_eq!(
        response.endpoint, p.kc_acs,
        "at Keycloak's registered SingleLogoutService"
    );
    assert_success_response(&response.xml, &request_id, "AXIAM");
    assert_eq!(
        response.relay.as_deref(),
        Some(kc_relay.as_str()),
        "with Keycloak's RelayState echoed"
    );
    // Revoked first: the session is gone before Keycloak hears back.
    assert_eq!(
        s.axiam_browser.me(&app).await,
        401,
        "AXIAM's session is refused"
    );

    // The same answer with its signature broken: Keycloak refuses it, and its
    // session is still there — Keycloak checks AXIAM's signature.
    let forged = response
        .tampered("SAMLResponse")
        .to_keycloak(&mut s.kc_browser)
        .await;
    let refused = follow(&mut s.kc_browser, forged, &[RP_LOGGED_OUT]).await;
    assert!(
        !refused
            .location
            .as_deref()
            .is_some_and(|l| l.starts_with(RP_LOGGED_OUT)),
        "Keycloak refuses a LogoutResponse whose signature does not verify"
    );
    assert_eq!(
        keycloak_sessions(p.realm, &s.kc_user_id).await,
        1,
        "and its session is not ended by it"
    );

    // Keycloak verifies AXIAM's signed answer and finishes the logout at the
    // relying party's post-logout URI.
    let delivered = response.to_keycloak(&mut s.kc_browser).await;
    let landed = follow(&mut s.kc_browser, delivered, &[RP_LOGGED_OUT]).await;
    assert!(
        landed
            .location
            .as_deref()
            .is_some_and(|l| l.starts_with(RP_LOGGED_OUT)),
        "Keycloak accepted AXIAM's LogoutResponse and finished the logout ({})",
        describe(&landed)
    );

    assert_logged_out(&app, &w, &p, &s).await;
    let completed = completed_audit_row(&w).await;
    assert_eq!(completed["metadata"]["initiator"], "sp");
    assert_eq!(completed["metadata"]["outcome"], "success");

    KeycloakAdmin::login()
        .await
        .delete(&format!("/admin/realms/{realm}"))
        .await;
}

/// **AXIAM-initiated single logout.** The user signs out at AXIAM; AXIAM revokes
/// the session and sends Keycloak a signed `LogoutRequest`; Keycloak verifies it,
/// ends its session by the `SessionIndex`, and answers with a signed
/// `LogoutResponse` that AXIAM verifies and counts as confirmed.
async fn axiam_initiated_logout(post_binding: bool) {
    capture_server_log();
    let realm = slo_realm("axiam", post_binding);
    let w = world().await;
    let app = e2e_app!(w);
    install_idp_credential(&w).await;
    let p = prepare(&app, &w, realm, post_binding).await;
    let mut s = sign_on(&app, &w, &p, post_binding).await;
    assert_live(&app, &p, &s).await;

    // The IdP-initiated trigger, from AXIAM's own pages, with the OP cookie.
    let triggered = s
        .axiam_browser
        .get_with(
            &app,
            &format!("/saml/v2/{}/sso/logout", w.tenant_id),
            &[("Sec-Fetch-Site", "same-origin")],
        )
        .await;
    // Revoked first: before Keycloak is told.
    assert_eq!(
        s.axiam_browser.me(&app).await,
        401,
        "AXIAM's session is refused"
    );
    assert!(
        revocation_feed(&app)
            .await
            .contains(&revocation_hash(s.axiam_session)),
        "and in the revocation feed before Keycloak is told"
    );

    // AXIAM's signed LogoutRequest, at Keycloak's registered SingleLogoutService.
    let request = Carried::from_axiam(triggered, "SAMLRequest").await;
    assert_eq!(
        request.redirect.is_none(),
        post_binding,
        "AXIAM sends on the binding registered for Keycloak"
    );
    assert_eq!(
        request.endpoint, p.kc_acs,
        "to Keycloak's registered SingleLogoutService"
    );
    assert!(request.xml.contains("LogoutRequest"));
    assert_logout_request(&request.xml, &s, "AXIAM");
    let request_id = attr(&request.xml, "ID").expect("the request's ID");

    // The same request with its signature broken: Keycloak refuses it, sends
    // nothing to AXIAM and keeps its session — Keycloak checks AXIAM's signature.
    let forged = request
        .tampered("SAMLRequest")
        .to_keycloak(&mut s.kc_browser)
        .await;
    let refused = follow(&mut s.kc_browser, forged, &[ROOT_ISSUER]).await;
    assert!(
        !refused
            .location
            .as_deref()
            .is_some_and(|l| l.starts_with(ROOT_ISSUER))
            && parse_form(&refused.body).is_none_or(|(action, _)| action != p.idp_slo),
        "Keycloak refuses a LogoutRequest whose signature does not verify ({})",
        describe(&refused)
    );
    assert_eq!(
        keycloak_sessions(p.realm, &s.kc_user_id).await,
        1,
        "and its session is not ended by it"
    );

    // Keycloak verifies it, ends the brokered session and answers at AXIAM's SLO.
    let delivered = request.to_keycloak(&mut s.kc_browser).await;
    let kc_answer = follow(&mut s.kc_browser, delivered, &[ROOT_ISSUER]).await;
    let response = Carried::from_keycloak(&kc_answer, "SAMLResponse");
    assert_eq!(
        response.redirect.is_none(),
        post_binding,
        "Keycloak answers on the binding it was told to use ({})",
        describe(&kc_answer)
    );
    assert_eq!(response.endpoint, p.idp_slo, "at AXIAM's SLO endpoint");
    assert_success_response(&response.xml, &request_id, "Keycloak");
    assert_eq!(
        keycloak_sessions(p.realm, &s.kc_user_id).await,
        0,
        "Keycloak ended the brokered session"
    );

    // AXIAM verifies Keycloak's signed answer; the chain ends on AXIAM's own
    // signed-out page, confirmed, not partial.
    let finished = response.to_axiam(&app, &mut s.axiam_browser).await;
    assert_eq!(
        finished.status().as_u16(),
        200,
        "AXIAM accepted Keycloak's LogoutResponse"
    );
    assert!(
        body_of(finished).await.contains("You are signed out"),
        "and ended the chain on its signed-out page"
    );
    let completed = completed_audit_row(&w).await;
    assert_eq!(completed["metadata"]["initiator"], "idp");
    assert_eq!(completed["metadata"]["sps_told"], 1);
    assert_eq!(
        completed["metadata"]["outcome"], "success",
        "a signed Success from Keycloak: the logout is confirmed, not partial"
    );

    assert_logged_out(&app, &w, &p, &s).await;

    KeycloakAdmin::login()
        .await
        .delete(&format!("/admin/realms/{realm}"))
        .await;
}

/// **Acceptance (#538): Keycloak-initiated single logout over HTTP-POST** —
/// Keycloak's enveloped-signed `LogoutRequest`, AXIAM's enveloped-signed
/// `LogoutResponse`.
#[actix_rt::test]
#[ignore = "needs a running Keycloak (docker-compose.e2e.yml); see the module docs"]
async fn keycloak_initiated_single_logout_over_http_post() {
    Box::pin(keycloak_initiated_logout(true)).await;
}

/// **Acceptance (#538): Keycloak-initiated single logout over HTTP-Redirect** —
/// both messages with detached query signatures.
#[actix_rt::test]
#[ignore = "needs a running Keycloak (docker-compose.e2e.yml); see the module docs"]
async fn keycloak_initiated_single_logout_over_http_redirect() {
    Box::pin(keycloak_initiated_logout(false)).await;
}

/// **Acceptance (#538): AXIAM-initiated single logout over HTTP-POST** — AXIAM's
/// `LogoutRequest` propagated to Keycloak's `SingleLogoutService`, Keycloak's
/// `LogoutResponse` consumed.
#[actix_rt::test]
#[ignore = "needs a running Keycloak (docker-compose.e2e.yml); see the module docs"]
async fn axiam_initiated_single_logout_over_http_post() {
    Box::pin(axiam_initiated_logout(true)).await;
}

/// **Acceptance (#538): AXIAM-initiated single logout over HTTP-Redirect.**
#[actix_rt::test]
#[ignore = "needs a running Keycloak (docker-compose.e2e.yml); see the module docs"]
async fn axiam_initiated_single_logout_over_http_redirect() {
    Box::pin(axiam_initiated_logout(false)).await;
}
