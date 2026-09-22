//! Where `axiam-server healthcheck` probes, and what it trusts (D-09, DF-016).
//!
//! The probe was `reqwest::blocking::get("http://127.0.0.1:8090/health")` with
//! `AXIAM_HEALTHCHECK_URL` as its only knob. On a deployment that terminates
//! TLS in the server process — `AXIAM__SERVER__TLS__ENABLED`, which is how the
//! shipped Kubernetes ConfigMap runs — that is a plaintext request to a TLS
//! listener, so the container healthcheck fails forever and the operator's only
//! recourse was an `AXIAM_HEALTHCHECK_URL` pointing at an `https://` address the
//! probe then could not verify.
//!
//! Two things were needed and one thing was not. The two: a default that
//! follows the listener, and a way to name the trust anchor. The one that was
//! not: an "insecure" switch. A probe that skips verification is a probe that
//! answers "healthy" to anything listening on the port, which is worse than no
//! probe, because a deployment stops looking.

use std::path::PathBuf;

/// The default REST port, matching `ServerConfig`'s own default.
const DEFAULT_PORT: u16 = 8090;

/// What to connect to, and what to trust when connecting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// The URL to request.
    pub url: String,
    /// A PEM bundle whose certificates are added as trust anchors.
    ///
    /// `None` means the platform trust store alone — right for a plaintext
    /// probe and for a publicly-issued certificate, and wrong for the private
    /// CA or self-signed certificate a direct-TLS deployment usually carries,
    /// which is what the resolution below supplies.
    pub trust_anchors: Option<PathBuf>,
}

/// Resolve the probe from the environment.
///
/// `var` reads an environment variable; a variable that is set but empty is
/// treated as unset, because that is what a Compose file writes when an
/// interpolated variable is missing.
///
/// - `AXIAM_HEALTHCHECK_URL` still wins outright, unchanged.
/// - Otherwise the scheme follows the listener: `https` when the server
///   terminates TLS itself, `http` when it does not.
/// - `AXIAM_HEALTHCHECK_CA_FILE` names the trust anchors.
/// - With no CA file and an `https` probe of a TLS-terminating server, the
///   anchors are the server's **own** `AXIAM__SERVER__TLS__CERT_PATH` chain:
///   a process verifying the certificate it is itself serving adds no trust it
///   does not already have.
#[must_use]
pub fn resolve<F>(var: F) -> Probe
where
    F: Fn(&str) -> Option<String>,
{
    let read = |name: &str| var(name).filter(|v| !v.trim().is_empty());

    // Both, not just the path. `docker-compose.prod.yml` sets
    // `AXIAM__SERVER__TLS__CERT_PATH` unconditionally and gates the listener on
    // `AXIAM__SERVER__TLS__ENABLED`, so reading the path alone would switch
    // every Compose deployment's probe to `https` against a plaintext listener
    // — the present defect, in the opposite direction.
    let cert_path = read("AXIAM__SERVER__TLS__CERT_PATH").map(PathBuf::from);
    let serving_tls =
        cert_path.is_some() && is_true(read("AXIAM__SERVER__TLS__ENABLED").as_deref());

    let url = read("AXIAM_HEALTHCHECK_URL").unwrap_or_else(|| {
        let port = read("AXIAM__SERVER__PORT")
            .and_then(|p| p.trim().parse::<u16>().ok())
            .unwrap_or(DEFAULT_PORT);
        let scheme = if serving_tls { "https" } else { "http" };
        format!("{scheme}://127.0.0.1:{port}/health")
    });

    let trust_anchors = match read("AXIAM_HEALTHCHECK_CA_FILE") {
        Some(path) => Some(PathBuf::from(path)),
        // Only for an `https` probe: adding anchors to a plaintext request is
        // meaningless, and doing it would hide a misconfigured CA file until
        // the day TLS was turned on.
        None if serving_tls && url.starts_with("https://") => cert_path,
        None => None,
    };

    Probe { url, trust_anchors }
}

/// The truthiness `config-rs` gives a boolean field, plus the spellings the
/// `AXIAM__PKI__MDS_*` variables already accept in `main.rs`.
fn is_true(value: Option<&str>) -> bool {
    matches!(
        value.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("true" | "1" | "yes" | "on")
    )
}

/// Run the probe. `true` iff the endpoint answered 2xx.
///
/// Every failure is `false` — unreachable, a TLS handshake that did not verify,
/// an unreadable or empty anchor bundle. A healthcheck reports health; it is
/// not the place to learn why a deployment is broken, and a probe that
/// distinguished "could not verify" from "not listening" by exiting differently
/// would make an orchestrator treat a misconfiguration as a healthy pod.
/// The reason goes to stderr, where `docker inspect` and `kubectl describe`
/// surface it.
#[must_use]
pub fn run(probe: &Probe) -> bool {
    let mut builder = reqwest::blocking::Client::builder();

    if let Some(path) = &probe.trust_anchors {
        let pem = match std::fs::read(path) {
            Ok(pem) => pem,
            Err(e) => {
                eprintln!("healthcheck: cannot read {}: {e}", path.display());
                return false;
            }
        };
        let anchors = match reqwest::Certificate::from_pem_bundle(&pem) {
            Ok(anchors) => anchors,
            Err(e) => {
                eprintln!("healthcheck: {} is not a PEM bundle: {e}", path.display());
                return false;
            }
        };
        // `from_pem_bundle` answers `Ok` with an empty list for a file that
        // holds no certificate, which would silently leave the probe on the
        // platform trust store — the pinning the operator asked for, absent,
        // with nothing to say so.
        if anchors.is_empty() {
            eprintln!("healthcheck: {} contains no certificates", path.display());
            return false;
        }
        for anchor in anchors {
            builder = builder.add_root_certificate(anchor);
        }
    }

    let client = match builder.build() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("healthcheck: could not build the HTTP client: {e}");
            return false;
        }
    };

    match client.get(&probe.url).send() {
        Ok(response) => response.status().is_success(),
        Err(e) => {
            eprintln!("healthcheck: {} did not answer: {e}", probe.url);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn resolve_with(pairs: &[(&str, &str)]) -> Probe {
        let map = env(pairs);
        resolve(|name| map.get(name).cloned())
    }

    /// The I4 twin: a plaintext deployment probes exactly what it probed
    /// before, with the platform trust store and nothing added.
    #[test]
    fn a_plaintext_deployment_is_unchanged() {
        assert_eq!(
            resolve_with(&[]),
            Probe {
                url: "http://127.0.0.1:8090/health".to_owned(),
                trust_anchors: None,
            }
        );
    }

    /// `docker-compose.prod.yml` sets the certificate path unconditionally and
    /// gates the listener on `ENABLED`. Reading the path alone would move every
    /// Compose deployment's probe to `https` against a plaintext listener.
    #[test]
    fn a_certificate_path_without_enabled_stays_plaintext() {
        assert_eq!(
            resolve_with(&[(
                "AXIAM__SERVER__TLS__CERT_PATH",
                "/etc/axiam/server-tls/fullchain.pem"
            )]),
            Probe {
                url: "http://127.0.0.1:8090/health".to_owned(),
                trust_anchors: None,
            }
        );
    }

    #[test]
    fn a_tls_deployment_probes_https_and_trusts_its_own_chain() {
        assert_eq!(
            resolve_with(&[
                ("AXIAM__SERVER__TLS__ENABLED", "true"),
                ("AXIAM__SERVER__TLS__CERT_PATH", "/etc/axiam/tls.crt"),
            ]),
            Probe {
                url: "https://127.0.0.1:8090/health".to_owned(),
                trust_anchors: Some(PathBuf::from("/etc/axiam/tls.crt")),
            }
        );
    }

    #[test]
    fn the_configured_port_is_honoured() {
        assert_eq!(
            resolve_with(&[("AXIAM__SERVER__PORT", "9443")]).url,
            "http://127.0.0.1:9443/health"
        );
        assert_eq!(
            resolve_with(&[
                ("AXIAM__SERVER__TLS__ENABLED", "true"),
                ("AXIAM__SERVER__TLS__CERT_PATH", "/etc/axiam/tls.crt"),
                ("AXIAM__SERVER__PORT", "9443"),
            ])
            .url,
            "https://127.0.0.1:9443/health"
        );
    }

    /// An unparseable port falls back rather than failing: a healthcheck is not
    /// where a configuration error should first be reported, and the server
    /// itself will refuse to start on the same value.
    #[test]
    fn an_unparseable_port_falls_back_to_the_default() {
        assert_eq!(
            resolve_with(&[("AXIAM__SERVER__PORT", "not-a-port")]).url,
            "http://127.0.0.1:8090/health"
        );
    }

    #[test]
    fn an_explicit_url_still_wins() {
        let p = resolve_with(&[
            (
                "AXIAM_HEALTHCHECK_URL",
                "https://axiam.internal:8443/health",
            ),
            ("AXIAM__SERVER__TLS__ENABLED", "true"),
            ("AXIAM__SERVER__TLS__CERT_PATH", "/etc/axiam/tls.crt"),
        ]);
        assert_eq!(p.url, "https://axiam.internal:8443/health");
        assert_eq!(p.trust_anchors, Some(PathBuf::from("/etc/axiam/tls.crt")));
    }

    #[test]
    fn the_ca_file_wins_over_the_servers_own_chain() {
        assert_eq!(
            resolve_with(&[
                ("AXIAM_HEALTHCHECK_CA_FILE", "/etc/axiam/probe-ca.pem"),
                ("AXIAM__SERVER__TLS__ENABLED", "true"),
                ("AXIAM__SERVER__TLS__CERT_PATH", "/etc/axiam/tls.crt"),
            ])
            .trust_anchors,
            Some(PathBuf::from("/etc/axiam/probe-ca.pem"))
        );
    }

    /// An operator who points the probe at a plaintext address on a
    /// TLS-terminating server gets no anchors: adding them would be
    /// meaningless, and doing it anyway would hide an unreadable bundle until
    /// the day the URL changed.
    #[test]
    fn a_plaintext_url_takes_no_anchors_from_the_listener() {
        assert_eq!(
            resolve_with(&[
                ("AXIAM_HEALTHCHECK_URL", "http://127.0.0.1:8090/health"),
                ("AXIAM__SERVER__TLS__ENABLED", "true"),
                ("AXIAM__SERVER__TLS__CERT_PATH", "/etc/axiam/tls.crt"),
            ])
            .trust_anchors,
            None
        );
    }

    /// Compose writes an empty string for an unset interpolation.
    #[test]
    fn empty_is_unset() {
        assert_eq!(
            resolve_with(&[
                ("AXIAM_HEALTHCHECK_URL", ""),
                ("AXIAM_HEALTHCHECK_CA_FILE", "   "),
                ("AXIAM__SERVER__TLS__ENABLED", "true"),
                ("AXIAM__SERVER__TLS__CERT_PATH", ""),
            ]),
            Probe {
                url: "http://127.0.0.1:8090/health".to_owned(),
                trust_anchors: None,
            }
        );
    }

    #[test]
    fn enabled_accepts_the_spellings_the_rest_of_the_binary_accepts() {
        for yes in ["true", "TRUE", "1", "yes", "on", " true "] {
            assert!(
                resolve_with(&[
                    ("AXIAM__SERVER__TLS__ENABLED", yes),
                    ("AXIAM__SERVER__TLS__CERT_PATH", "/etc/axiam/tls.crt"),
                ])
                .url
                .starts_with("https://"),
                "{yes:?} should enable TLS"
            );
        }
        for no in ["false", "0", "no", "off", ""] {
            assert!(
                resolve_with(&[
                    ("AXIAM__SERVER__TLS__ENABLED", no),
                    ("AXIAM__SERVER__TLS__CERT_PATH", "/etc/axiam/tls.crt"),
                ])
                .url
                .starts_with("http://"),
                "{no:?} should not enable TLS"
            );
        }
    }
}
