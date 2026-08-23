//! The Vault CA key store against a real HTTP server.
//!
//! The unit tests beside the implementation cover URL construction, which is
//! where a path bug hides. These cover what happens once a request is actually
//! made: the method, the header, the body shape, and — mostly — how each
//! status is read. A store that talked to Vault correctly and misread a 404 as
//! a transport failure would pass every unit test in the module.

use axiam_core::ca_keys::{CaKeyCustody, CaKeyRef, CaKeyStore, StoredCaKey};
use axiam_pki::{VaultCaKeyConfig, VaultCaKeyStore};
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{body_json_schema, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAw\n-----END PRIVATE KEY-----\n";
const TOKEN: &str = "hvs.test-only-not-a-real-token"; // gitleaks:allow
const PREFIX: &str = "axiam/ca-keys";

fn store_for(server: &MockServer) -> VaultCaKeyStore {
    VaultCaKeyStore::new(VaultCaKeyConfig {
        address: server.uri(),
        token: TOKEN.into(),
        mount: "secret".into(),
        prefix: PREFIX.into(),
        ca_cert_path: None,
    })
    .expect("no trust anchor configured, so the client builds")
}

fn key_ref(org: Uuid, ca: Uuid) -> CaKeyRef {
    CaKeyRef {
        organization_id: org,
        ca_id: ca,
        custody: CaKeyCustody::Vault,
        locator: format!("{PREFIX}/{org}/{ca}"),
    }
}

// ---------------------------------------------------------------------------
// store
// ---------------------------------------------------------------------------

#[tokio::test]
async fn store_writes_the_key_and_returns_a_locator_without_the_address() {
    let server = MockServer::start().await;
    let (org, ca) = (Uuid::new_v4(), Uuid::new_v4());

    Mock::given(method("POST"))
        .and(path(format!("/v1/secret/data/{PREFIX}/{org}/{ca}")))
        .and(header("X-Vault-Token", TOKEN))
        // `cas: 0` is what makes the write refuse to overwrite. A CA id is
        // freshly generated, so an existing secret there means an id collision
        // or a retried call that already succeeded — silently replacing would
        // destroy a live signing key.
        .and(body_json_schema::<serde_json::Value>)
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "version": 1 }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let stored = store_for(&server).store(org, ca, PEM).await.unwrap();

    match stored {
        StoredCaKey::Referenced(locator) => {
            assert_eq!(locator, format!("{PREFIX}/{org}/{ca}"));
            // Storing the address or the mount would strand every CA row the
            // day Vault moves or the engine is remounted.
            assert!(!locator.contains(&server.uri()));
            assert!(!locator.starts_with("secret"));
        }
        other => panic!("vault custody must reference, not inline: {other:?}"),
    }
}

#[tokio::test]
async fn store_sends_the_key_under_the_field_load_reads_back() {
    // The two halves have to agree on the field name, and nothing but a
    // round-trip proves it.
    let server = MockServer::start().await;
    let (org, ca) = (Uuid::new_v4(), Uuid::new_v4());

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {}})))
        .mount(&server)
        .await;

    let store = store_for(&server);
    store.store(org, ca, PEM).await.unwrap();

    let request = &server.received_requests().await.unwrap()[0];
    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["data"]["private_key_pem"], PEM);
    assert_eq!(
        body["options"]["cas"], 0,
        "the write must refuse to overwrite"
    );
}

#[tokio::test]
async fn a_refused_write_names_the_policy_rather_than_the_status_alone() {
    // The commonest real failure: a token whose policy grants read and not
    // create. An error saying only "403" sends an operator to the wrong place.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let err = store_for(&server)
        .store(Uuid::new_v4(), Uuid::new_v4(), PEM)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("403"), "{msg}");
    assert!(msg.contains("policy"), "{msg}");
    assert!(
        !msg.contains(TOKEN),
        "the token must never reach an error: {msg}"
    );
    assert!(!msg.contains(PEM), "nor the key: {msg}");
}

// ---------------------------------------------------------------------------
// load
// ---------------------------------------------------------------------------

#[tokio::test]
async fn load_reads_the_key_back_out_of_a_kv_v2_envelope() {
    let server = MockServer::start().await;
    let (org, ca) = (Uuid::new_v4(), Uuid::new_v4());

    Mock::given(method("GET"))
        .and(path(format!("/v1/secret/data/{PREFIX}/{org}/{ca}")))
        .and(header("X-Vault-Token", TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "private_key_pem": PEM }, "metadata": { "version": 1 } }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let loaded = store_for(&server)
        .load(&key_ref(org, ca), None)
        .await
        .unwrap();
    assert_eq!(&*loaded, PEM);
}

#[tokio::test]
async fn load_also_accepts_a_kv_v1_envelope() {
    // KV v1 does not nest under `data.data`. A deployment on the older engine
    // must not be told its key is absent — the same tolerance the startup
    // secret provider has.
    let server = MockServer::start().await;
    let (org, ca) = (Uuid::new_v4(), Uuid::new_v4());

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "private_key_pem": PEM }
        })))
        .mount(&server)
        .await;

    let loaded = store_for(&server)
        .load(&key_ref(org, ca), None)
        .await
        .unwrap();
    assert_eq!(&*loaded, PEM);
}

#[tokio::test]
async fn a_missing_secret_is_a_custody_problem_not_a_transport_one() {
    // These mean different things and a retry fixes only one of them. A CA row
    // pointing at a secret that is not there is something an operator has to
    // fix; the message says which of the two ways that happens.
    let server = MockServer::start().await;
    let (org, ca) = (Uuid::new_v4(), Uuid::new_v4());

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let err = store_for(&server)
        .load(&key_ref(org, ca), None)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("holds no key"), "{msg}");
    assert!(msg.contains("deleted") && msg.contains("mount"), "{msg}");
    assert!(msg.contains(&format!("{PREFIX}/{org}/{ca}")), "{msg}");
}

#[tokio::test]
async fn a_secret_without_the_expected_field_says_which_field() {
    // Someone wrote to the path by hand, or a prefix collides with another
    // system's secrets. "No key" would send an operator looking for the wrong
    // thing.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "some_other_field": "value" } }
        })))
        .mount(&server)
        .await;

    let err = store_for(&server)
        .load(&key_ref(Uuid::new_v4(), Uuid::new_v4()), None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("private_key_pem"), "{err}");
}

#[tokio::test]
async fn a_non_json_response_is_reported_as_such() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>a proxy</html>"))
        .mount(&server)
        .await;

    let err = store_for(&server)
        .load(&key_ref(Uuid::new_v4(), Uuid::new_v4()), None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("non-JSON"), "{err}");
}

#[tokio::test]
async fn load_ignores_the_rows_inline_ciphertext() {
    // Every custodian is handed it, and only the database one reads it. A vault
    // store that preferred it would open a stale key after a custody migration.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "private_key_pem": PEM } }
        })))
        .mount(&server)
        .await;

    let loaded = store_for(&server)
        .load(
            &key_ref(Uuid::new_v4(), Uuid::new_v4()),
            Some(b"stale ciphertext"),
        )
        .await
        .unwrap();
    assert_eq!(&*loaded, PEM);
}

// ---------------------------------------------------------------------------
// delete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_targets_the_metadata_path_so_every_version_goes() {
    // A KV v2 DELETE on the *data* path soft-deletes the latest version and
    // leaves it readable by version number. For a CA signing key that is not
    // deletion, and this is the assertion that keeps it that way.
    let server = MockServer::start().await;
    let (org, ca) = (Uuid::new_v4(), Uuid::new_v4());

    Mock::given(method("DELETE"))
        .and(path(format!("/v1/secret/metadata/{PREFIX}/{org}/{ca}")))
        .and(header("X-Vault-Token", TOKEN))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    store_for(&server).delete(&key_ref(org, ca)).await.unwrap();
}

#[tokio::test]
async fn deleting_a_key_that_is_already_gone_succeeds() {
    // Revocation calls this, and a second revocation must not fail because the
    // first one worked.
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    store_for(&server)
        .delete(&key_ref(Uuid::new_v4(), Uuid::new_v4()))
        .await
        .expect("already gone is success");
}

#[tokio::test]
async fn a_refused_delete_is_reported() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let err = store_for(&server)
        .delete(&key_ref(Uuid::new_v4(), Uuid::new_v4()))
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("403"), "{msg}");
    assert!(!msg.contains(TOKEN), "{msg}");
}

// ---------------------------------------------------------------------------
// transport
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unreachable_vault_names_the_operation_that_failed() {
    // Three operations reach Vault and they fail for different reasons at
    // different moments; an error saying only "request failed" would make the
    // log useless for telling them apart.
    //
    // Port 1 rather than a dropped `MockServer`: dropping one does not reliably
    // free its port, and the connection then succeeds and 404s — which is a
    // *different* branch, and the one the missing-secret test above covers.
    let store = VaultCaKeyStore::new(VaultCaKeyConfig {
        address: "http://127.0.0.1:1".into(),
        token: TOKEN.into(),
        mount: "secret".into(),
        prefix: PREFIX.into(),
        ca_cert_path: None,
    })
    .unwrap();

    let r = key_ref(Uuid::new_v4(), Uuid::new_v4());

    for (label, msg) in [
        (
            "store",
            store
                .store(r.organization_id, r.ca_id, PEM)
                .await
                .unwrap_err()
                .to_string(),
        ),
        ("load", store.load(&r, None).await.unwrap_err().to_string()),
        ("delete", store.delete(&r).await.unwrap_err().to_string()),
    ] {
        let expected = match label {
            "store" => "writing the CA key",
            "load" => "reading the CA key",
            _ => "deleting the CA key",
        };
        assert!(msg.contains(expected), "{label}: {msg}");
        assert!(!msg.contains(TOKEN), "{label} leaked the token: {msg}");
        assert!(!msg.contains(PEM), "{label} leaked the key: {msg}");
    }
}
