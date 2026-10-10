//! The email provider's outbound address policy (#529, P23W3-11, T-473).
//!
//! Each refused class, when a configuration is saved (`EmailEgress::check`) and
//! when a message is sent (the provider itself); a private relay inside the
//! operator's allow-list; DNS rebinding between the save and the send; and the
//! pinned address being the one dialled. The listeners here count what reaches
//! them, so "refused" means nothing was dialled, not just that an error came
//! back.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axiam_core::models::email::{ApiProviderConfig, ProviderConfig, SmtpConfig};
use axiam_email::egress::{
    AddressPolicy, EmailEgress, HOST_NOT_PERMITTED, PROVIDER_UNREACHABLE, ResolveFuture, Resolver,
    parse_allowed_networks,
};
use axiam_email::message::EmailMessage;
use axiam_email::provider::EmailProvider;
use axiam_email::providers::sendgrid::SendGridProvider;
use axiam_email::providers::smtp::SmtpProvider;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Answers one name from a script — the n-th question gets the n-th answer,
/// the last answer repeats — and counts the questions.
struct ScriptedResolver {
    host: &'static str,
    answers: Vec<Vec<IpAddr>>,
    asked: AtomicUsize,
}

impl ScriptedResolver {
    fn new(host: &'static str, answers: &[&[&str]]) -> Arc<Self> {
        Arc::new(Self {
            host,
            answers: answers
                .iter()
                .map(|ips| ips.iter().map(|ip| ip.parse().unwrap()).collect())
                .collect(),
            asked: AtomicUsize::new(0),
        })
    }

    fn questions(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }
}

impl Resolver for ScriptedResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
        let index = self.asked.fetch_add(1, Ordering::SeqCst);
        let answer = (host == self.host).then(|| {
            self.answers
                .get(index)
                .or_else(|| self.answers.last())
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect::<Vec<_>>()
        });
        Box::pin(async move {
            answer.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown"))
        })
    }
}

/// A TCP listener on loopback that counts connections and drops each one at
/// once, so a client's TLS handshake fails fast rather than waiting out a
/// timeout.
struct CountingListener {
    port: u16,
    connections: Arc<AtomicUsize>,
}

impl CountingListener {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&connections);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        Self { port, connections }
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

fn smtp(host: &str, port: u16) -> SmtpConfig {
    SmtpConfig {
        host: host.to_string(),
        port,
        username: "relay-user".to_string(),
        password: axiam_test_password(),
        starttls: false,
    }
}

/// A per-process value, never a literal in the source.
fn axiam_test_password() -> String {
    format!("pw-{}", std::process::id())
}

fn message() -> EmailMessage {
    EmailMessage {
        to: "recipient@example.com".to_string(),
        subject: "Hello".to_string(),
        html_body: None,
        text_body: Some("Hi".to_string()),
    }
}

async fn send_smtp(config: &SmtpConfig, egress: &EmailEgress) -> Result<(), String> {
    SmtpProvider::new(config, egress.clone())
        .unwrap()
        .send("AXIAM", "noreply@example.com", None, &message())
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// The refused classes, by IP literal: the address, and a word the specific
/// answer carries (a literal reveals nothing the administrator did not type).
const REFUSED_LITERALS: &[(&str, &str)] = &[
    ("127.0.0.1", "loopback"),
    ("::1", "loopback"),
    ("169.254.169.254", "link-local"),
    ("fe80::1", "link-local"),
    ("0.0.0.0", "unspecified"),
    ("224.0.0.1", "multicast"),
    ("192.0.2.10", "special-purpose"),
    ("10.1.2.3", "private"),
    ("fd00::1", "private"),
];

#[tokio::test]
async fn each_refused_class_is_refused_at_save_and_at_send_and_never_dialled() {
    let listener = CountingListener::start().await;
    let egress = EmailEgress::default();
    for (address, word) in REFUSED_LITERALS {
        // The listener's port on every address, so a dial of loopback would
        // be counted.
        let config = smtp(address, listener.port);
        let saved = egress
            .check(&ProviderConfig::Smtp(config.clone()))
            .await
            .expect_err(address);
        assert!(
            saved.public_message().contains(word),
            "{address}: a literal's refusal names the class: {}",
            saved.public_message()
        );
        let sent = send_smtp(&config, &egress).await.expect_err(address);
        assert!(sent.contains(word), "{address}: {sent}");
    }

    // The same classes reached through a name: one answer for all of them.
    for (address, _) in REFUSED_LITERALS {
        let resolver = ScriptedResolver::new("relay.example.test", &[&[address]]);
        let egress = EmailEgress::default().with_resolver(resolver.clone());
        let config = smtp("relay.example.test", listener.port);
        let saved = egress
            .check(&ProviderConfig::Smtp(config.clone()))
            .await
            .expect_err(address);
        assert_eq!(
            saved.public_message(),
            format!("smtp host: {HOST_NOT_PERMITTED}"),
            "{address}: a name's refusal says nothing about where it points"
        );
        let sent = send_smtp(&config, &egress).await.expect_err(address);
        assert!(sent.contains(HOST_NOT_PERMITTED), "{address}: {sent}");
        assert!(!sent.contains(address), "{address}: {sent}");
        assert_eq!(resolver.questions(), 2, "{address}: one question each time");
    }

    // A name that does not resolve reads the same as a refused one.
    let unknown = EmailEgress::default().with_resolver(ScriptedResolver::new("other.test", &[]));
    let sent = send_smtp(&smtp("nowhere.example.test", 587), &unknown)
        .await
        .unwrap_err();
    assert!(sent.contains(HOST_NOT_PERMITTED), "{sent}");

    assert_eq!(listener.connections(), 0, "no refused address was dialled");
}

#[tokio::test]
async fn axiams_own_listener_is_refused_at_save_and_at_send() {
    let listener = CountingListener::start().await;
    // The loopback seam admits 127.0.0.1, so what refuses it here is the
    // listener rule alone.
    let egress = EmailEgress::new(
        AddressPolicy::new()
            .admitting_loopback_for_tests()
            .with_listener_ports([listener.port]),
    );
    let config = smtp("127.0.0.1", listener.port);
    let saved = egress
        .check(&ProviderConfig::Smtp(config.clone()))
        .await
        .unwrap_err();
    assert_eq!(saved.rule, "address_guard.own_listener");
    let sent = send_smtp(&config, &egress).await.unwrap_err();
    assert!(sent.contains("AXIAM's own listeners"), "{sent}");
    assert_eq!(listener.connections(), 0);
}

#[tokio::test]
async fn a_private_relay_is_admitted_only_inside_the_operator_allow_list() {
    let resolver = ScriptedResolver::new("relay.corp.test", &[&["10.20.0.25"]]);
    let config = ProviderConfig::Smtp(smtp("relay.corp.test", 587));
    let strict = EmailEgress::default().with_resolver(resolver.clone());
    assert_eq!(
        strict.check(&config).await.unwrap_err().rule,
        "address_guard.private_not_allowed"
    );

    let (networks, rejected) = parse_allowed_networks("10.20.0.0/16");
    assert!(rejected.is_empty());
    let allowed = EmailEgress::new(AddressPolicy::new().with_allowed_private_networks(networks))
        .with_resolver(resolver.clone());
    allowed.check(&config).await.expect("inside the allow-list");
    let target = allowed.guard_smtp("relay.corp.test", 587).await.unwrap();
    assert_eq!(target.addresses, vec!["10.20.0.25:587".parse().unwrap()]);
    // Outside the listed network is still refused, and so is every
    // always-refused class, whatever the list says.
    assert_eq!(
        allowed
            .check(&ProviderConfig::Smtp(smtp("192.168.1.10", 587)))
            .await
            .unwrap_err()
            .rule,
        "address_guard.private_not_allowed"
    );
    let everything = EmailEgress::new(
        AddressPolicy::new().with_allowed_private_networks(vec!["0.0.0.0/0".parse().unwrap()]),
    );
    for (address, rule) in [
        ("127.0.0.1", "address_guard.loopback"),
        ("169.254.169.254", "address_guard.link_local"),
        ("100.100.100.200", "address_guard.metadata"),
    ] {
        assert_eq!(
            everything
                .check(&ProviderConfig::Smtp(smtp(address, 587)))
                .await
                .unwrap_err()
                .rule,
            rule,
            "{address}"
        );
    }
}

/// DNS rebinding: the name answers a public address when the configuration is
/// saved and loopback when the message is sent. The send-time guard refuses
/// it, and the loopback listener never hears from AXIAM.
#[tokio::test]
async fn dns_rebinding_between_save_and_send_never_reaches_loopback() {
    let listener = CountingListener::start().await;
    let resolver =
        ScriptedResolver::new("relay.rebind.test", &[&["93.184.216.34"], &["127.0.0.1"]]);
    let egress = EmailEgress::default().with_resolver(resolver.clone());
    let config = smtp("relay.rebind.test", listener.port);
    egress
        .check(&ProviderConfig::Smtp(config.clone()))
        .await
        .expect("the save sees a public address");
    let sent = send_smtp(&config, &egress).await.unwrap_err();
    assert!(sent.contains(HOST_NOT_PERMITTED), "{sent}");
    assert_eq!(
        resolver.questions(),
        2,
        "one answer for the save, one for the send"
    );
    assert_eq!(
        listener.connections(),
        0,
        "the rebound address was never dialled"
    );
}

/// Within one send the name is resolved once and the connection goes to the
/// address that was vetted: the resolver's first answer is the listener, its
/// second would be the metadata service, and the name exists nowhere but in
/// the script — so a second resolution, by the guard or by `lettre`, could
/// not have reached the listener.
#[tokio::test]
async fn the_send_dials_the_pinned_address_and_resolves_once() {
    let listener = CountingListener::start().await;
    let resolver = ScriptedResolver::new(
        "relay.pinned.invalid",
        &[&["127.0.0.1"], &["169.254.169.254"]],
    );
    // The loopback seam stands in for a public address the test cannot run a
    // server on; every other rule applies.
    let egress = EmailEgress::new(AddressPolicy::new().admitting_loopback_for_tests())
        .with_resolver(resolver.clone());
    let sent = send_smtp(&smtp("relay.pinned.invalid", listener.port), &egress)
        .await
        .unwrap_err();
    // The listener drops the connection, so the TLS handshake fails — and is
    // answered as the one "unreachable" sentence, never the socket's words.
    assert!(sent.contains(PROVIDER_UNREACHABLE), "{sent}");
    assert_eq!(resolver.questions(), 1, "resolved once per send");
    assert_eq!(listener.connections(), 1, "the pinned address was dialled");
}

fn api(url: &str) -> ApiProviderConfig {
    ApiProviderConfig {
        api_key: format!("key-{}", std::process::id()),
        api_url: Some(url.to_string()),
    }
}

#[tokio::test]
async fn an_http_providers_api_url_is_held_to_the_ssrf_rule_and_the_key_never_leaves() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;
    let port = server.address().port();
    let egress = EmailEgress::default();
    for (url, expect) in [
        // Plain http is refused for its own text.
        (server.uri(), "non-HTTPS"),
        (
            format!("https://127.0.0.1:{port}/v3/mail/send"),
            "SSRF blocked",
        ),
        ("https://169.254.169.254/latest".to_string(), "SSRF blocked"),
        ("https://0.0.0.0/send".to_string(), "SSRF blocked"),
        ("https://224.0.0.1/send".to_string(), "SSRF blocked"),
        ("https://10.1.2.3/send".to_string(), "SSRF blocked"),
        // A name that resolves to loopback: the one sentence.
        (format!("https://localhost:{port}/send"), HOST_NOT_PERMITTED),
    ] {
        let config = ProviderConfig::SendGrid(api(&url));
        let saved = egress.check(&config).await.expect_err(&url);
        assert!(
            saved.public_message().contains(expect),
            "{url}: {}",
            saved.public_message()
        );
        let sent = SendGridProvider::new(&api(&url), egress.clone())
            .unwrap()
            .send("AXIAM", "noreply@example.com", None, &message())
            .await
            .unwrap_err()
            .to_string();
        assert!(sent.contains(expect), "{url}: {sent}");
    }
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "no request, and so no API key, reached a refused address"
    );
    // The built-in provider URL is AXIAM's own constant and is not checked.
    egress
        .check(&ProviderConfig::SendGrid(ApiProviderConfig {
            api_key: "k".into(),
            api_url: None,
        }))
        .await
        .expect("no api_url, nothing to check");
}

#[tokio::test]
async fn an_http_provider_never_follows_a_redirect() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(307).insert_header("location", "http://169.254.169.254/steal"),
        )
        .mount(&server)
        .await;
    let provider = SendGridProvider::new(
        &api(&format!("{}/v3/mail/send", server.uri())),
        EmailEgress::default().allowing_private_http_for_tests(),
    )
    .unwrap();
    let err = provider
        .send("AXIAM", "noreply@example.com", None, &message())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("307"), "the redirect is the answer: {err}");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
