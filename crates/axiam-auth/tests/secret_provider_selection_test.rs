//! Choosing and building a `SecretProvider`, including the ways it refuses.
//!
//! `SecretProviderKind::build` is composition-root code: it runs once at
//! startup, and what it does on a bad input decides whether the process comes
//! up wrongly or not at all. The `vault` branch is the interesting one — when
//! the operator names a private CA bundle, failing to read or parse it is
//! deliberately fatal, because carrying on would silently fall back to the
//! default trust store and skip the very check the operator asked for.
//!
//! These cases need no Vault and no network: every one of them fails before
//! the first request.

use axiam_auth::secrets::{EnvSecretProvider, SecretProviderKind, VaultConfig};
use axiam_core::secrets::SecretProvider;

/// A scratch path under the system temp dir, unique per call.
fn scratch(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("axiam-secrets-{}-{name}", uuid::Uuid::new_v4()))
}

fn a_vault_kind(ca_cert_path: Option<std::path::PathBuf>) -> SecretProviderKind {
    SecretProviderKind::Vault(Box::new(VaultConfig {
        // Never contacted: every assertion below fails while reading the
        // bundle, which happens before the client is used.
        address: "https://vault.invalid".into(),
        token: "not-a-real-token".into(),
        mount: "secret".into(),
        path: "axiam".into(),
        ca_cert_path,
    }))
}

#[test]
fn a_logical_key_name_maps_to_the_documented_environment_variable() {
    // Operators set these by hand from the deployment docs, so the mapping is
    // a contract: lowercase logical name, uppercased under one fixed prefix.
    //
    // Asserted against a name the docs actually carry, rather than a plausible
    // invented one. `jwt_private_key_pem` is the lowercase field the secret
    // provider looks for on the configuration page, and
    // `AXIAM__AUTH__JWT_PRIVATE_KEY_PEM` is the variable listed beside it — so
    // this pins the real published pair, and `check-config-key-coverage.py`
    // sees a key it can find in the docs instead of one that exists nowhere.
    assert_eq!(
        EnvSecretProvider::var_name("jwt_private_key_pem"),
        "AXIAM__AUTH__JWT_PRIVATE_KEY_PEM"
    );
}

#[test]
fn an_absent_environment_variable_is_a_choice_rather_than_a_failure() {
    // The port's contract: absent means "not configured here", so the
    // composition root can try the next source. Returning an error instead
    // would turn every optional secret into a startup failure.
    let provider = EnvSecretProvider;
    let never_set = "key_that_no_deployment_sets_ce9f41";

    assert!(
        provider
            .get_key(never_set)
            .expect("an absent variable is not an error")
            .is_none()
    );
    assert!(
        provider
            .get_secret(never_set)
            .expect("an absent variable is not an error")
            .is_none()
    );
    assert_eq!(provider.describe(), "env");
}

#[tokio::test]
async fn the_env_and_file_kinds_build_the_provider_they_name() {
    // `describe()` is what startup diagnostics print, so a selector that built
    // the wrong provider would be invisible except in behaviour.
    let client = reqwest::Client::new();

    let env = SecretProviderKind::Env
        .build(&client, &[], &[])
        .await
        .expect("the env provider needs nothing to build");
    assert_eq!(env.describe(), "env");

    let file = SecretProviderKind::File {
        dir: scratch("dir"),
    }
    .build(&client, &[], &[])
    .await
    .expect("the file provider is built without touching the directory");
    assert_eq!(file.describe(), "file");
}

#[tokio::test]
async fn a_ca_bundle_that_cannot_be_read_stops_startup_and_names_the_path() {
    // Falling back to the default trust store here would silently drop the
    // operator's pinning. The path has to appear in the message: this runs at
    // startup, where a typo'd path is the likeliest cause.
    let missing = scratch("absent.pem");
    let client = reqwest::Client::new();

    // `Box<dyn SecretProvider>` is not `Debug`, so the error is taken by hand
    // rather than through `expect_err`.
    let message = match a_vault_kind(Some(missing.clone()))
        .build(&client, &[], &[])
        .await
    {
        Ok(_) => panic!("an unreadable CA bundle must be fatal"),
        Err(e) => e.to_string(),
    };
    assert!(
        message.contains("reading the CA bundle"),
        "the message must name the stage; got: {message}"
    );
    assert!(
        message.contains(&missing.display().to_string()),
        "the message must name the path; got: {message}"
    );
}

#[tokio::test]
async fn a_ca_bundle_that_parses_to_no_certificates_stops_startup() {
    // Distinct from the unreadable case on purpose: the file is there, so the
    // operator needs to be told the contents are wrong rather than the path.
    //
    // This is the case that used to slip through. `from_pem_bundle` answers
    // `Ok` with an empty list for a file containing no PEM blocks, so a
    // truncated or wrong-format bundle added zero roots and startup carried on
    // against the default trust store — the exact fallback the branch exists to
    // prevent, and silent.
    let not_pem = scratch("garbage.pem");
    std::fs::write(&not_pem, b"this is not a certificate bundle").expect("scratch write");
    let client = reqwest::Client::new();

    let message = match a_vault_kind(Some(not_pem.clone()))
        .build(&client, &[], &[])
        .await
    {
        Ok(_) => panic!("a malformed CA bundle must be fatal"),
        Err(e) => e.to_string(),
    };
    assert!(
        message.contains("contains no certificates")
            || message.contains("is not a PEM certificate bundle"),
        "the message must distinguish malformed contents from an unreadable \
         path, and must not be a downstream connection error; got: {message}"
    );
    assert!(
        !message.contains("error sending request"),
        "startup must fail while reading the bundle, not later against Vault; \
         got: {message}"
    );

    std::fs::remove_file(&not_pem).ok();
}
