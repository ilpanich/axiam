//! Environment variables that look like a secret's name and are read by nothing.
//!
//! Four variables were documented, set in two compose files and named in a
//! dozen error messages, and none of them ever reached the server
//! (DF-018/DF-022). `AXIAM__EMAIL_ENCRYPTION_KEY` and
//! `AXIAM__GDPR_PSEUDONYM_PEPPER` map to `AppConfig` fields that are
//! `#[serde(skip)]`; `AXIAM__PKI__ENCRYPTION_KEY` and
//! `AXIAM__FEDERATION_ENCRYPTION_KEY` have no `AppConfig` field at all. All
//! four are supplied by the secret provider instead, under the names
//! [`axiam_core::secrets::env_var_name`] resolves.
//!
//! The fix is the rename (decision D-1: one name per secret, no alias). This
//! module is the other half — the deployment that is already wrong learns so
//! at startup, in one line, naming both spellings.
//!
//! **The value is never read.** [`legacy_secret_env_warnings`] is handed a
//! predicate that answers *is this variable set*, not a lookup that returns
//! what it holds, so there is no path by which a key could reach a log line.

use axiam_core::secrets as keys;

/// A variable an operator may have set, and the logical secret it looks like.
///
/// Deliberately not a table of aliases: nothing here is ever read. `AXIAM`
/// resolves each logical key to exactly one variable, and this is the list of
/// spellings that were *documented* as that variable and were not.
///
/// `AXIAM__AMQP__SIGNING_KEY` is **not** in this list although it looks like a
/// sibling. It is a real, honoured variable — `load_config` deserialises it
/// into `AmqpConfig::signing_key`, and the provider's
/// `AXIAM__AUTH__AMQP_SIGNING_KEY` merely takes precedence when both are set.
/// Warning about it would tell an operator with a working deployment that it
/// is broken.
const LEGACY_SPELLINGS: &[(&str, &str)] = &[
    ("AXIAM__PKI__ENCRYPTION_KEY", keys::PKI_ENCRYPTION_KEY),
    ("AXIAM__EMAIL_ENCRYPTION_KEY", keys::EMAIL_ENCRYPTION_KEY),
    ("AXIAM__GDPR_PSEUDONYM_PEPPER", keys::GDPR_PSEUDONYM_PEPPER),
    (
        "AXIAM__FEDERATION_ENCRYPTION_KEY",
        keys::FEDERATION_ENCRYPTION_KEY,
    ),
];

/// One finding: a variable that is set and read by nothing, and the variable
/// that would have been read instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyEnvWarning {
    /// The spelling the operator set.
    pub legacy: &'static str,
    /// The variable the secret provider actually reads for the same secret.
    pub resolved: String,
}

/// Every legacy spelling that is set while the variable AXIAM reads is not.
///
/// `is_set` answers whether a variable is present in the environment. It is a
/// predicate rather than a lookup on purpose: a function that cannot obtain a
/// value cannot leak one.
///
/// Both-set is silent. That is the shape of a migration in progress — the
/// deployment already works, and the stale variable is about to go — and a
/// warning there would be noise on a correct configuration.
pub fn legacy_secret_env_warnings<F>(is_set: F) -> Vec<LegacyEnvWarning>
where
    F: Fn(&str) -> bool,
{
    LEGACY_SPELLINGS
        .iter()
        .filter_map(|(legacy, logical)| {
            let resolved = keys::env_var_name(logical);
            (is_set(legacy) && !is_set(&resolved)).then_some(LegacyEnvWarning { legacy, resolved })
        })
        .collect()
}

/// The variable the configuration layer reads the password pepper from
/// (`AppConfig::auth.pepper`): the one an operator sets, and the one the
/// deployment guide documents.
///
/// It is **not** the variable the `env` secret provider reads for the logical
/// key [`keys::AUTH_PEPPER`] — that is `AXIAM__AUTH__AUTH_PEPPER`, a spelling
/// nobody sets, because the logical key keeps its `auth_` prefix for the `file`
/// and `vault` providers (renaming it would move a mounted file and a Vault
/// field). The two paths both feed `config.auth.pepper`.
pub const PEPPER_CONFIG_VAR: &str = "AXIAM__AUTH__PEPPER";

/// Where the password pepper came from, for the boot log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PepperSource {
    /// The configured secret provider supplied it.
    SecretProvider,
    /// It was already in the configuration (`AXIAM__AUTH__PEPPER`).
    Configuration,
    /// Neither supplied one.
    Unset,
}

impl PepperSource {
    /// The provider's value wins over the configuration's, as in `main`.
    #[must_use]
    pub fn resolve(from_provider: bool, in_configuration: bool) -> Self {
        if from_provider {
            Self::SecretProvider
        } else if in_configuration {
            Self::Configuration
        } else {
            Self::Unset
        }
    }
}

/// The boot log line for an unset pepper. It names the variable an operator
/// sets, and the secret-provider spelling second, so it never names one nobody
/// reads (the previous line said `AXIAM__AUTH__PEPPER` was unset on a
/// deployment that had set it, because only the provider's spelling was
/// consulted).
#[must_use]
pub fn pepper_unset_message() -> String {
    format!(
        "no auth pepper configured: set {PEPPER_CONFIG_VAR} (or provide `{}` through the secret \
         provider; the env provider reads it from {}) — password hashing will proceed without a \
         pepper; client-secret hashing is mandatory-keyed and will fail closed in a release \
         build (OBS-1)",
        keys::AUTH_PEPPER,
        keys::env_var_name(keys::AUTH_PEPPER),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    fn env(vars: &[&str]) -> HashSet<String> {
        vars.iter().map(|v| (*v).to_string()).collect()
    }

    #[test]
    fn a_legacy_spelling_alone_is_reported_with_the_variable_that_is_read() {
        let set = env(&["AXIAM__PKI__ENCRYPTION_KEY"]);
        let found = legacy_secret_env_warnings(|v| set.contains(v));

        assert_eq!(
            found,
            vec![LegacyEnvWarning {
                legacy: "AXIAM__PKI__ENCRYPTION_KEY",
                resolved: "AXIAM__AUTH__PKI_ENCRYPTION_KEY".to_owned(),
            }]
        );
    }

    #[test]
    fn all_four_are_reported() {
        let set = env(&[
            "AXIAM__PKI__ENCRYPTION_KEY",
            "AXIAM__EMAIL_ENCRYPTION_KEY",
            "AXIAM__GDPR_PSEUDONYM_PEPPER",
            "AXIAM__FEDERATION_ENCRYPTION_KEY",
        ]);
        let found = legacy_secret_env_warnings(|v| set.contains(v));

        assert_eq!(found.len(), 4);
        // The message interpolates nothing. Both fields are variable *names*
        // and never values — `legacy_secret_env_warnings` takes an is-set
        // predicate, so no value is reachable from here — but a panic message
        // reaches stderr and a CI log that outlives the run, so a test is not
        // exempt from the rule this repository already settled once: don't
        // format something that reads as secret material into an assertion.
        // CodeQL reported exactly this shape (`rust/cleartext-logging`, high)
        // and is right about the construct even though nothing leaks. The four
        // inputs are the four literals directly above; a failure is
        // reproducible without them being printed back.
        assert!(
            found
                .iter()
                .all(|w| w.resolved.starts_with("AXIAM__AUTH__")),
            "every legacy spelling must resolve to an AXIAM__AUTH__ variable"
        );
    }

    /// The I4 twin: a deployment that set nothing, or set the right variable,
    /// says nothing at startup. A warning an operator cannot act on is one
    /// they learn to scroll past.
    #[test]
    fn a_correct_deployment_is_silent() {
        let nothing = env(&[]);
        assert!(legacy_secret_env_warnings(|v| nothing.contains(v)).is_empty());

        let correct = env(&[
            "AXIAM__AUTH__PKI_ENCRYPTION_KEY",
            "AXIAM__AUTH__EMAIL_ENCRYPTION_KEY",
            "AXIAM__AUTH__GDPR_PSEUDONYM_PEPPER",
            "AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY",
        ]);
        assert!(legacy_secret_env_warnings(|v| correct.contains(v)).is_empty());
    }

    /// A migration in progress is not a misconfiguration.
    #[test]
    fn both_spellings_set_is_silent() {
        let both = env(&[
            "AXIAM__PKI__ENCRYPTION_KEY",
            "AXIAM__AUTH__PKI_ENCRYPTION_KEY",
        ]);
        assert!(legacy_secret_env_warnings(|v| both.contains(v)).is_empty());
    }

    /// `AXIAM__AMQP__SIGNING_KEY` is honoured by `load_config`. Telling an
    /// operator who set it that it does nothing would be false.
    #[test]
    fn the_amqp_signing_key_is_not_treated_as_legacy() {
        let set = env(&["AXIAM__AMQP__SIGNING_KEY"]);
        assert!(legacy_secret_env_warnings(|v| set.contains(v)).is_empty());
    }

    /// The variable the unset-pepper line names is the one the configuration
    /// layer actually reads for `AppConfig::auth.pepper` — so an operator who
    /// sets it gets the pepper, and one who has set it is not told it is unset.
    /// Driven through the same `config` builder `load_config` uses, with the
    /// environment injected instead of `set_var`.
    #[test]
    fn the_variable_the_message_names_is_the_one_the_configuration_reads() {
        let source = HashMap::from([(
            PEPPER_CONFIG_VAR.to_owned(),
            "a-pepper-of-at-least-sixteen-bytes".to_owned(),
        )]);
        let built = config::Config::builder()
            .add_source(
                config::Environment::with_prefix("AXIAM")
                    .separator("__")
                    .source(Some(source)),
            )
            .build()
            .expect("build");
        let cfg: crate::boot::AppConfig = built.try_deserialize().expect("deserialize");
        assert!(
            cfg.auth.pepper.is_some(),
            "{PEPPER_CONFIG_VAR} must populate auth.pepper"
        );
        assert!(pepper_unset_message().starts_with(&format!(
            "no auth pepper configured: set {PEPPER_CONFIG_VAR} "
        )));
    }

    /// And the secret-provider spelling it also names is what the provider
    /// resolves, not a copy of it.
    #[test]
    fn the_provider_spelling_in_the_message_is_what_the_provider_resolves() {
        assert_eq!(
            keys::env_var_name(keys::AUTH_PEPPER),
            "AXIAM__AUTH__AUTH_PEPPER"
        );
        let message = pepper_unset_message();
        assert!(message.contains("AXIAM__AUTH__AUTH_PEPPER"), "{message}");
        assert!(message.contains(keys::AUTH_PEPPER), "{message}");
    }

    /// A deployment that set the pepper in the configuration is not told it is
    /// unset: only `Unset` produces the message.
    #[test]
    fn a_pepper_from_the_configuration_is_not_reported_as_unset() {
        assert_eq!(
            PepperSource::resolve(true, true),
            PepperSource::SecretProvider
        );
        assert_eq!(
            PepperSource::resolve(true, false),
            PepperSource::SecretProvider
        );
        assert_eq!(
            PepperSource::resolve(false, true),
            PepperSource::Configuration
        );
        assert_eq!(PepperSource::resolve(false, false), PepperSource::Unset);
    }
}
