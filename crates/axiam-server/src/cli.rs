//! The binary's subcommands, parsed as data rather than matched inline.
//!
//! `main.rs` cannot be linked from an integration test, so argv handling that
//! lives there is untestable by construction — which is how
//! `tests/healthcheck.rs` ended up re-implementing the probe it meant to test.
//! This module is the parse, as a pure function over the arguments, so the
//! table of what the binary answers to is checkable.
//!
//! Deliberately not `clap`. The binary answers to three subcommands and
//! otherwise serves; a dependency that renders help for an argument surface
//! this small would be more code than it replaces, and the one thing this has
//! to get right — `setup-token` never silently starting a server — is one
//! branch.

/// What the binary was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Run the server. The default, and what an unrecognised argument still
    /// means: a deployment that passes an extra flag keeps booting.
    Serve,
    /// `healthcheck` — probe `/health` and exit 0 on 2xx (D-09).
    Healthcheck,
    /// `--dump-openapi` — print the OpenAPI document and exit (FND-01).
    DumpOpenApi,
    /// `setup-token --remint` — replace the bootstrap setup token on a
    /// deployment nobody has bootstrapped yet (DF-019).
    RemintSetupToken,
    /// A subcommand that was recognised but not completed. Carries the line to
    /// print; the binary exits 2 rather than booting.
    Usage(&'static str),
}

/// Parse `args` — the whole of `std::env::args()`, program name included.
#[must_use]
pub fn parse(args: &[String]) -> Command {
    match args.get(1).map(String::as_str) {
        Some("healthcheck") => Command::Healthcheck,
        Some("--dump-openapi") => Command::DumpOpenApi,
        // `setup-token` alone must not fall through to `Serve`: an operator
        // who mistypes the flag would otherwise start a second server against
        // the production datastore and read it as the command having done
        // nothing.
        Some("setup-token") => match args.get(2).map(String::as_str) {
            Some("--remint") => Command::RemintSetupToken,
            _ => Command::Usage("usage: axiam-server setup-token --remint"),
        },
        _ => Command::Serve,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(rest: &[&str]) -> Vec<String> {
        std::iter::once("axiam-server")
            .chain(rest.iter().copied())
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn no_arguments_means_serve() {
        assert_eq!(parse(&argv(&[])), Command::Serve);
    }

    #[test]
    fn the_existing_two_subcommands_are_unchanged() {
        assert_eq!(parse(&argv(&["healthcheck"])), Command::Healthcheck);
        assert_eq!(parse(&argv(&["--dump-openapi"])), Command::DumpOpenApi);
    }

    #[test]
    fn setup_token_remint_is_recognised() {
        assert_eq!(
            parse(&argv(&["setup-token", "--remint"])),
            Command::RemintSetupToken
        );
    }

    /// The branch that matters: `setup-token` with the flag missing or
    /// mistyped must not boot a server.
    #[test]
    fn setup_token_without_the_flag_is_usage_not_serve() {
        for rest in [
            vec!["setup-token"],
            vec!["setup-token", "--print"],
            vec!["setup-token", "remint"],
            vec!["setup-token", "--remint=yes"],
        ] {
            assert!(
                matches!(parse(&argv(&rest)), Command::Usage(_)),
                "{rest:?} must not start a server"
            );
        }
    }

    /// The I4 twin: an argument the binary does not know still serves, which
    /// is what it did before this module existed.
    #[test]
    fn an_unrecognised_argument_still_serves() {
        assert_eq!(parse(&argv(&["--verbose"])), Command::Serve);
        assert_eq!(parse(&argv(&["serve"])), Command::Serve);
    }
}
