//! AMQP error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AmqpError {
    #[error("AMQP connection failed: {0}")]
    Connection(lapin::Error),

    #[error("AMQP channel creation failed: {0}")]
    Channel(lapin::Error),

    #[error("AMQP queue/exchange declaration failed: {0}")]
    Declaration(lapin::Error),

    #[error("AMQP publish failed: {0}")]
    Publish(String),

    #[error("AMQP connection failed after exhausting all retries: {0}")]
    MaxRetriesExhausted(#[source] lapin::Error),

    /// A6: the connection was refused before a socket was opened, because the
    /// configuration itself is unusable — an unrecognised URL scheme, half a
    /// client identity, an unreadable CA bundle, or plaintext in a release
    /// build without an explicit opt-in.
    ///
    /// Distinct from [`Self::Connection`] on purpose: this one is never
    /// retryable, and the retry loop must not spend `max_retries` attempts on
    /// a typo in a mount path.
    #[error("AMQP configuration is unusable: {0}")]
    Config(String),

    /// A6: a single connection attempt exceeded
    /// [`AmqpConfig::connect_timeout_ms`] and was abandoned.
    ///
    /// There is no underlying `lapin::Error` here, and that is the point:
    /// lapin has no connect timeout, so an attempt that never resolves
    /// produces no error at all. Everything downstream of it — the retry
    /// budget, the supervisor, the operator watching the log — is waiting on a
    /// future that will not complete. This variant is what makes that state
    /// observable.
    ///
    /// Retryable: unlike [`Self::Config`], a stalled broker may well answer on
    /// the next attempt.
    ///
    /// [`AmqpConfig::connect_timeout_ms`]: crate::AmqpConfig::connect_timeout_ms
    #[error(
        "AMQP connection attempt to {url} timed out after {timeout_ms}ms. The broker's port \
         accepted a socket but the connection never completed — check that an amqps:// listener \
         is actually bound there (`rabbitmq-diagnostics listeners`) and that its certificate \
         chains to the configured CA bundle."
    )]
    ConnectTimeout { url: String, timeout_ms: u64 },
}

impl AmqpError {
    /// Extract the underlying `lapin::Error` from connection-related variants.
    ///
    /// Only the variants that wrap one. [`Self::Config`] and
    /// [`Self::ConnectTimeout`] have no lapin error to extract — both are
    /// raised before or instead of one — and
    /// [`AmqpManager::connect_with_retry`] diverts them before reaching here.
    ///
    /// [`AmqpManager::connect_with_retry`]: crate::AmqpManager::connect_with_retry
    pub(crate) fn into_lapin_error(self) -> lapin::Error {
        match self {
            Self::Connection(e) | Self::Channel(e) | Self::Declaration(e) => e,
            _ => unreachable!("into_lapin_error called on non-lapin variant"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lapin_error() -> lapin::Error {
        lapin::ErrorKind::InvalidChannel(7).into()
    }

    #[test]
    fn each_variant_displays_its_own_sentence() {
        let wrapped = lapin_error().to_string();
        assert_eq!(
            AmqpError::Connection(lapin_error()).to_string(),
            format!("AMQP connection failed: {wrapped}")
        );
        assert_eq!(
            AmqpError::Channel(lapin_error()).to_string(),
            format!("AMQP channel creation failed: {wrapped}")
        );
        assert_eq!(
            AmqpError::Declaration(lapin_error()).to_string(),
            format!("AMQP queue/exchange declaration failed: {wrapped}")
        );
        assert_eq!(
            AmqpError::Publish("nack".into()).to_string(),
            "AMQP publish failed: nack"
        );
        assert_eq!(
            AmqpError::MaxRetriesExhausted(lapin_error()).to_string(),
            format!("AMQP connection failed after exhausting all retries: {wrapped}")
        );
        assert_eq!(
            AmqpError::Config("bad scheme".into()).to_string(),
            "AMQP configuration is unusable: bad scheme"
        );
        let timeout = AmqpError::ConnectTimeout {
            url: "amqps://broker:5671".into(),
            timeout_ms: 250,
        }
        .to_string();
        assert!(
            timeout.starts_with(
                "AMQP connection attempt to amqps://broker:5671 timed out after 250ms."
            ),
            "{timeout}"
        );
    }

    #[test]
    fn the_lapin_variants_give_their_error_back_and_the_others_do_not_have_one() {
        for error in [
            AmqpError::Connection(lapin_error()),
            AmqpError::Channel(lapin_error()),
            AmqpError::Declaration(lapin_error()),
        ] {
            assert_eq!(
                error.into_lapin_error().to_string(),
                lapin_error().to_string()
            );
        }
        let exhausted = AmqpError::MaxRetriesExhausted(lapin_error());
        let source = std::error::Error::source(&exhausted);
        assert!(
            source.is_some(),
            "the exhausted-retries error keeps its cause"
        );
    }

    #[test]
    #[should_panic(expected = "non-lapin variant")]
    fn a_variant_without_a_lapin_error_cannot_be_unwrapped_into_one() {
        let _ = AmqpError::Config("x".into()).into_lapin_error();
    }
}
