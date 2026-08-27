//! Which custodian holds a CA's signing key, as a function of configuration.
//!
//! This is the decision the 1.0.0-beta01 report caught getting silently wrong:
//! a deployment with HashiCorp Vault wired up for the secret provider, and no
//! PKI-specific pair, fell through to `database` custody and sealed every
//! organization and tenant CA private key into a `ca_certificate` row — under a
//! startup log that said `provider=vault` on the line immediately above.
//!
//! `custodians_from` takes a lookup rather than reading the environment so
//! these rules can be asserted as a function of their inputs. Driving them
//! through the real environment would mean mutating process-global state from a
//! harness that runs tests on many threads at once, which is how a suite starts
//! passing or failing by run order.

use std::collections::HashMap;

use axiam_core::ca_keys::CaKeyCustody;
use axiam_core::error::AxiamResult;
use axiam_pki::ca_key_store::{
    AUTH_VAULT_ADDR_ENV, AUTH_VAULT_TOKEN_ENV, CA_KEY_STORE_ENV, CA_VAULT_ADDR_ENV,
    CA_VAULT_TOKEN_ENV, CaKeyCustodians, custodians_from,
};

/// Resolve custody against a frozen environment.
///
/// Values are placeholders — nothing here reaches Vault. The lookup is boxed
/// here rather than at each call site because `custodians_from` takes
/// `&dyn Fn`: one instantiation, so coverage instrumentation counts the
/// function's lines once rather than once per closure type.
fn custody(
    encryption_key: Option<[u8; 32]>,
    pairs: &[(&str, &str)],
) -> AxiamResult<CaKeyCustodians> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    custodians_from(encryption_key, &move |name: &str| map.get(name).cloned())
}

/// The defect itself, as a regression test.
///
/// The auth pair alone must resolve CA custody to Vault. Before the fix this
/// returned `Database`, which is how a beta shipped with its CA signing keys in
/// the database.
#[test]
fn the_auth_pair_alone_puts_ca_keys_in_vault_not_the_database() {
    let custodians = custody(
        Some([7u8; 32]),
        &[
            (AUTH_VAULT_ADDR_ENV, "https://vault:8200"),
            (AUTH_VAULT_TOKEN_ENV, "placeholder-auth-value"),
        ],
    )
    .unwrap();

    assert_eq!(custodians.default_custody(), Some(CaKeyCustody::Vault));
    assert!(
        custodians.vault_inherited(),
        "an operator who set no PKI variable must be able to read why their keys are in Vault"
    );
    assert!(!custodians.database_custody_despite_vault());
}

/// The PKI-specific pair still wins outright when both are set, and is not
/// reported as inherited — the startup line has to distinguish the two.
#[test]
fn the_pki_pair_wins_and_is_not_reported_as_inherited() {
    let custodians = custody(
        Some([7u8; 32]),
        &[
            (AUTH_VAULT_ADDR_ENV, "https://auth-vault:8200"),
            (AUTH_VAULT_TOKEN_ENV, "placeholder-auth-value"),
            (CA_VAULT_ADDR_ENV, "https://pki-vault:8200"),
            (CA_VAULT_TOKEN_ENV, "placeholder-pki-value"),
        ],
    )
    .unwrap();

    assert_eq!(custodians.default_custody(), Some(CaKeyCustody::Vault));
    assert!(!custodians.vault_inherited());
}

/// An explicit `database` beside a working Vault is the one remaining way to
/// put keys in a row. It is allowed — an operator may mean it — and it is
/// exactly what the startup warning exists to name.
#[test]
fn an_explicit_database_choice_beside_vault_is_allowed_and_flagged() {
    let custodians = custody(
        Some([7u8; 32]),
        &[
            (AUTH_VAULT_ADDR_ENV, "https://vault:8200"),
            (AUTH_VAULT_TOKEN_ENV, "placeholder-auth-value"),
            (CA_KEY_STORE_ENV, "database"),
        ],
    )
    .unwrap();

    assert_eq!(custodians.default_custody(), Some(CaKeyCustody::Database));
    assert!(custodians.database_custody_despite_vault());
}

/// `vault_pki` reaches the same Vault as `vault`, so naming it needs no second
/// address — which is the whole reason the two custodians share one pair.
#[test]
fn vault_pki_is_reachable_through_the_inherited_pair() {
    let custodians = custody(
        None,
        &[
            (AUTH_VAULT_ADDR_ENV, "https://vault:8200"),
            (AUTH_VAULT_TOKEN_ENV, "placeholder-auth-value"),
            (CA_KEY_STORE_ENV, "vault_pki"),
        ],
    )
    .unwrap();

    assert_eq!(custodians.default_custody(), Some(CaKeyCustody::VaultPki));
}

/// Naming a custodian that is not configured stops the process rather than
/// quietly substituting one that is — the failure mode this whole area is
/// about.
#[test]
fn naming_an_unconfigured_custodian_is_a_startup_failure() {
    let err = custody(Some([7u8; 32]), &[(CA_KEY_STORE_ENV, "vault")])
        .expect_err("vault named with no Vault configured must not start");
    assert!(
        format!("{err}").to_lowercase().contains("vault"),
        "the message must name the custodian: {err}"
    );
}

/// An unparseable value names the three that exist rather than falling back to
/// one of them.
#[test]
fn an_unknown_custodian_name_is_refused_with_the_valid_ones() {
    let err = custody(Some([7u8; 32]), &[(CA_KEY_STORE_ENV, "s3")])
        .expect_err("an unknown custodian must not start");
    let msg = format!("{err}");
    assert!(msg.contains("database"), "{msg}");
    assert!(msg.contains("vault_pki"), "{msg}");
}

/// A whitespace-only value is treated as unset, not as a name.
#[test]
fn a_blank_custodian_name_falls_through_to_the_default_rules() {
    let custodians = custody(
        Some([7u8; 32]),
        &[
            (AUTH_VAULT_ADDR_ENV, "https://vault:8200"),
            (AUTH_VAULT_TOKEN_ENV, "placeholder-auth-value"),
            (CA_KEY_STORE_ENV, "   "),
        ],
    )
    .unwrap();
    assert_eq!(custodians.default_custody(), Some(CaKeyCustody::Vault));
}

/// No Vault and an encryption key is database custody — the ordinary
/// single-node arrangement — and must not be warned about.
#[test]
fn an_encryption_key_alone_is_database_custody() {
    let custodians = custody(Some([7u8; 32]), &[]).unwrap();
    assert_eq!(custodians.default_custody(), Some(CaKeyCustody::Database));
    assert!(!custodians.database_custody_despite_vault());
}

/// Nothing configured at all still boots.
///
/// A deployment that issues no certificates has no reason to hold a PKI key,
/// and refusing to start would break it for a feature it never uses.
#[test]
fn nothing_configured_builds_with_no_default() {
    let custodians = custody(None, &[]).unwrap();
    assert_eq!(custodians.default_custody(), None);
}

/// The Vault mounts carry Vault's own conventional defaults, so adopting Vault
/// custody is an address and a token — not four variables.
#[test]
fn the_vault_mounts_default_rather_than_being_required() {
    custody(
        None,
        &[
            (AUTH_VAULT_ADDR_ENV, "https://vault:8200"),
            (AUTH_VAULT_TOKEN_ENV, "placeholder-auth-value"),
        ],
    )
    .expect("an address and a token are enough");
}

/// A half-configured pair is refused rather than ignored, and the message names
/// the pair the operator actually touched.
#[test]
fn a_half_configured_pair_is_refused_naming_the_pair_that_was_set() {
    let err = custody(None, &[(AUTH_VAULT_ADDR_ENV, "https://vault:8200")])
        .expect_err("an address with no token must not start");
    assert!(format!("{err}").contains(AUTH_VAULT_TOKEN_ENV), "{err}");

    let err = custody(None, &[(CA_VAULT_TOKEN_ENV, "placeholder-pki-value")])
        .expect_err("a token with no address must not start");
    assert!(format!("{err}").contains(CA_VAULT_ADDR_ENV), "{err}");
}
