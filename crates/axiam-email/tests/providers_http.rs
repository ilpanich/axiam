//! Integration tests for the REST and SMTP email providers.
//!
//! The REST providers (SendGrid, Postmark, Resend, Brevo) are exercised
//! against a local `wiremock` server so the full request-building and
//! response-parsing paths are covered without hitting real APIs. The SMTP
//! provider is exercised for its construction and pre-connection error
//! paths (address parsing / empty body) which do not require a live relay.

use axiam_core::models::email::{ApiProviderConfig, SmtpConfig};
use axiam_email::message::EmailMessage;
use axiam_email::provider::EmailProvider;
use axiam_email::providers::brevo::BrevoProvider;
use axiam_email::providers::postmark::PostmarkProvider;
use axiam_email::providers::resend::ResendProvider;
use axiam_email::providers::sendgrid::SendGridProvider;
use axiam_email::providers::smtp::SmtpProvider;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn full_message() -> EmailMessage {
    EmailMessage {
        to: "recipient@example.com".to_string(),
        subject: "Hello".to_string(),
        html_body: Some("<h1>Hi</h1>".to_string()),
        text_body: Some("Hi".to_string()),
    }
}

fn api_config(url: &str) -> ApiProviderConfig {
    ApiProviderConfig {
        api_key: "secret-key".to_string(),
        api_url: Some(url.to_string()),
    }
}

// --- SendGrid ---

#[tokio::test]
async fn sendgrid_send_success_reads_message_id_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v3/mail/send"))
        .and(header("authorization", "Bearer secret-key"))
        .respond_with(ResponseTemplate::new(202).insert_header("x-message-id", "sg-123"))
        .mount(&server)
        .await;

    let url = format!("{}/v3/mail/send", server.uri());
    let provider = SendGridProvider::new(&api_config(&url)).unwrap();
    let result = provider
        .send(
            "AXIAM",
            "noreply@example.com",
            Some("reply@example.com"),
            &full_message(),
        )
        .await
        .unwrap();
    assert_eq!(result.message_id.as_deref(), Some("sg-123"));
    assert_eq!(provider.provider_name(), "sendgrid");
}

#[tokio::test]
async fn sendgrid_send_error_status_returns_delivery_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
        .mount(&server)
        .await;

    let provider = SendGridProvider::new(&api_config(&server.uri())).unwrap();
    let err = provider
        .send("AXIAM", "noreply@example.com", None, &full_message())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("SendGrid returned"), "got: {err}");
}

#[tokio::test]
async fn sendgrid_text_only_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;
    let provider = SendGridProvider::new(&api_config(&server.uri())).unwrap();
    let msg = EmailMessage {
        to: "r@example.com".into(),
        subject: "s".into(),
        html_body: None,
        text_body: Some("text only".into()),
    };
    let result = provider
        .send("AXIAM", "noreply@example.com", None, &msg)
        .await
        .unwrap();
    // No x-message-id header -> None.
    assert!(result.message_id.is_none());
}

// --- Postmark ---

#[tokio::test]
async fn postmark_send_success_parses_message_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("x-postmark-server-token", "secret-key"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"MessageID": "pm-9"})),
        )
        .mount(&server)
        .await;
    let provider = PostmarkProvider::new(&api_config(&server.uri())).unwrap();
    let result = provider
        .send(
            "AXIAM",
            "noreply@example.com",
            Some("reply@example.com"),
            &full_message(),
        )
        .await
        .unwrap();
    assert_eq!(result.message_id.as_deref(), Some("pm-9"));
    assert_eq!(provider.provider_name(), "postmark");
}

#[tokio::test]
async fn postmark_send_error_status() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(422).set_body_string("nope"))
        .mount(&server)
        .await;
    let provider = PostmarkProvider::new(&api_config(&server.uri())).unwrap();
    let err = provider
        .send("AXIAM", "noreply@example.com", None, &full_message())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("Postmark returned"), "got: {err}");
}

// --- Resend ---

#[tokio::test]
async fn resend_send_success_parses_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("authorization", "Bearer secret-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "re-77"})))
        .mount(&server)
        .await;
    let provider = ResendProvider::new(&api_config(&server.uri())).unwrap();
    let result = provider
        .send(
            "AXIAM",
            "noreply@example.com",
            Some("reply@example.com"),
            &full_message(),
        )
        .await
        .unwrap();
    assert_eq!(result.message_id.as_deref(), Some("re-77"));
    assert_eq!(provider.provider_name(), "resend");
}

#[tokio::test]
async fn resend_send_error_status() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;
    let provider = ResendProvider::new(&api_config(&server.uri())).unwrap();
    let err = provider
        .send("AXIAM", "noreply@example.com", None, &full_message())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("Resend returned"), "got: {err}");
}

// --- Brevo ---

#[tokio::test]
async fn brevo_send_success_parses_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("api-key", "secret-key"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(serde_json::json!({"messageId": "bv-5"})),
        )
        .mount(&server)
        .await;
    let provider = BrevoProvider::new(&api_config(&server.uri())).unwrap();
    let result = provider
        .send(
            "AXIAM",
            "noreply@example.com",
            Some("reply@example.com"),
            &full_message(),
        )
        .await
        .unwrap();
    assert_eq!(result.message_id.as_deref(), Some("bv-5"));
    assert_eq!(provider.provider_name(), "brevo");
}

#[tokio::test]
async fn brevo_send_error_status() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
        .mount(&server)
        .await;
    let provider = BrevoProvider::new(&api_config(&server.uri())).unwrap();
    let err = provider
        .send("AXIAM", "noreply@example.com", None, &full_message())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("Brevo returned"), "got: {err}");
}

// --- Network failure path (connection refused) ---

#[tokio::test]
async fn resend_request_failure_when_unreachable() {
    // Port 1 is not listening; reqwest returns a transport error, exercising
    // the `map_err(... request failed ...)` branch.
    let provider = ResendProvider::new(&api_config("http://127.0.0.1:1/emails")).unwrap();
    let err = provider
        .send("AXIAM", "noreply@example.com", None, &full_message())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("Resend request failed"), "got: {err}");
}

// --- SMTP construction and pre-connection error paths ---

fn smtp_config(starttls: bool) -> SmtpConfig {
    SmtpConfig {
        host: "smtp.example.com".to_string(),
        port: if starttls { 587 } else { 465 },
        username: "user".to_string(),
        password: "pass".to_string(),
        starttls,
    }
}

#[test]
fn smtp_new_starttls_and_implicit_tls_build() {
    let p1 = SmtpProvider::new(&smtp_config(true)).unwrap();
    assert_eq!(p1.provider_name(), "smtp");
    let p2 = SmtpProvider::new(&smtp_config(false)).unwrap();
    assert_eq!(p2.provider_name(), "smtp");
}

#[tokio::test]
async fn smtp_send_invalid_to_address_errors() {
    let provider = SmtpProvider::new(&smtp_config(true)).unwrap();
    let msg = EmailMessage {
        to: "not-an-email".to_string(),
        subject: "s".into(),
        html_body: None,
        text_body: Some("body".into()),
    };
    let err = provider
        .send("AXIAM", "noreply@example.com", None, &msg)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("invalid to address"), "got: {err}");
}

#[tokio::test]
async fn smtp_send_invalid_from_address_errors() {
    let provider = SmtpProvider::new(&smtp_config(false)).unwrap();
    let err = provider
        .send("AXIAM", "not a valid addr @@", None, &full_message())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("invalid from address"), "got: {err}");
}

#[tokio::test]
async fn smtp_send_invalid_reply_to_errors() {
    let provider = SmtpProvider::new(&smtp_config(true)).unwrap();
    let err = provider
        .send(
            "AXIAM",
            "noreply@example.com",
            Some("bad reply @@"),
            &full_message(),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("invalid reply-to address"), "got: {err}");
}

fn smtp_config_unreachable() -> SmtpConfig {
    // Loopback port 1 refuses connections immediately, so the transport
    // build succeeds and `send` fails fast at connect time — after the
    // message body has been assembled (covering the builder branches).
    SmtpConfig {
        host: "127.0.0.1".to_string(),
        port: 1,
        username: "user".to_string(),
        password: "pass".to_string(),
        starttls: false,
    }
}

#[tokio::test]
async fn smtp_send_multipart_build_then_connect_error() {
    let provider = SmtpProvider::new(&smtp_config_unreachable()).unwrap();
    // html + text -> multipart alternative branch.
    let err = provider
        .send(
            "AXIAM",
            "noreply@example.com",
            Some("reply@example.com"),
            &full_message(),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("SMTP send failed"), "got: {err}");
}

#[tokio::test]
async fn smtp_send_html_only_build_then_connect_error() {
    let provider = SmtpProvider::new(&smtp_config_unreachable()).unwrap();
    let msg = EmailMessage {
        to: "recipient@example.com".to_string(),
        subject: "s".into(),
        html_body: Some("<p>only html</p>".into()),
        text_body: None,
    };
    let err = provider
        .send("AXIAM", "noreply@example.com", None, &msg)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("SMTP send failed"), "got: {err}");
}

#[tokio::test]
async fn smtp_send_text_only_build_then_connect_error() {
    let provider = SmtpProvider::new(&smtp_config_unreachable()).unwrap();
    let msg = EmailMessage {
        to: "recipient@example.com".to_string(),
        subject: "s".into(),
        html_body: None,
        text_body: Some("only text".into()),
    };
    let err = provider
        .send("AXIAM", "noreply@example.com", None, &msg)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("SMTP send failed"), "got: {err}");
}

#[tokio::test]
async fn smtp_send_no_body_errors() {
    let provider = SmtpProvider::new(&smtp_config(true)).unwrap();
    let msg = EmailMessage {
        to: "recipient@example.com".to_string(),
        subject: "s".into(),
        html_body: None,
        text_body: None,
    };
    let err = provider
        .send("AXIAM", "noreply@example.com", None, &msg)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("email has no body"), "got: {err}");
}
