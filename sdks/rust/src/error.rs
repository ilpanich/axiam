//! `AxiamError` — the single, `?`-friendly error type for this SDK
//! (CONTRACT.md §2, D-06).
//!
//! Exactly three top-level variants exist: `Auth`, `Authz`, `Network`,
//! matching the CONTRACT.md §2 error taxonomy exactly. Mapping helpers
//! translate HTTP status codes and gRPC status codes into the correct
//! variant per the CONTRACT.md §2 tables.
//!
//! **Security note:** none of these variants may ever carry a raw token
//! value. The mapping helpers below accept a caller-controlled `message`;
//! callers MUST NOT pass token values into it.

use std::error::Error as StdError;
use std::fmt;

/// The unified error type returned by all fallible operations in this SDK.
#[derive(thiserror::Error, Debug)]
pub enum AxiamError {
    /// Authentication failure: wrong credentials, expired session, MFA
    /// failure, or a 401 on refresh (CONTRACT.md §2).
    #[error("authentication failed: {message}")]
    Auth {
        /// Human-readable description of the failure. MUST NOT contain a
        /// raw token value.
        message: String,
    },

    /// Authorization failure: the caller is authenticated but lacks
    /// permission for the requested operation (CONTRACT.md §2).
    #[error("authorization denied: {message}")]
    Authz {
        /// Human-readable description of the failure. MUST NOT contain a
        /// raw token value.
        message: String,
        /// The denied action, if known from the response body.
        action: Option<String>,
        /// The resource the action was denied against, if known.
        resource_id: Option<String>,
    },

    /// Transport-level failure: connection refused, timeout, TLS error, DNS
    /// failure, or a server-side 5xx (CONTRACT.md §2).
    #[error("network error: {message}")]
    Network {
        /// Human-readable description of the failure. MUST NOT contain a
        /// raw token value.
        message: String,
        /// The underlying transport error, if any. Boxed as a trait object
        /// so this variant compiles without any transport feature enabled;
        /// later plans may wrap concrete `reqwest`/`tonic`/`lapin` errors
        /// here via `From` impls.
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },
}

impl AxiamError {
    /// Map an HTTP status code to an [`AxiamError`] variant per CONTRACT.md
    /// §2's HTTP status table.
    ///
    /// | Status       | Variant  |
    /// |--------------|----------|
    /// | 400          | Network  |
    /// | 401          | Auth     |
    /// | 403          | Authz    |
    /// | 408, 429     | Network  |
    /// | 409          | Authz    |
    /// | 5xx          | Network  |
    /// | other        | Network  |
    ///
    /// `message` is caller-controlled and MUST NOT contain a raw token
    /// value.
    pub fn from_http_status(status: u16, message: impl Into<String>) -> AxiamError {
        let message = message.into();
        match status {
            401 => AxiamError::Auth { message },
            403 | 409 => AxiamError::Authz {
                message,
                action: None,
                resource_id: None,
            },
            _ => AxiamError::Network {
                message,
                source: None,
            },
        }
    }

    /// Map a gRPC status code (as its numeric `tonic::Code` value) to an
    /// [`AxiamError`] variant per CONTRACT.md §2's gRPC status table.
    ///
    /// | Code                      | Variant  |
    /// |---------------------------|----------|
    /// | 16 UNAUTHENTICATED        | Auth     |
    /// | 7 PERMISSION_DENIED       | Authz    |
    /// | 14 UNAVAILABLE            | Network  |
    /// | 4 DEADLINE_EXCEEDED       | Network  |
    /// | 13 INTERNAL               | Network  |
    /// | 8 RESOURCE_EXHAUSTED      | Network  |
    /// | other                     | Network  |
    ///
    /// `message` is caller-controlled and MUST NOT contain a raw token
    /// value.
    pub fn from_grpc_code(code: i32, message: impl Into<String>) -> AxiamError {
        let message = message.into();
        match code {
            16 => AxiamError::Auth { message },
            7 => AxiamError::Authz {
                message,
                action: None,
                resource_id: None,
            },
            _ => AxiamError::Network {
                message,
                source: None,
            },
        }
    }
}

// Manual Display impls are provided by `#[error(...)]` above via thiserror;
// this explicit re-statement documents the redaction invariant for readers
// browsing the source without expanding the derive macro.
#[allow(dead_code)]
fn _assert_no_token_in_display<T: fmt::Display>(_: &T) {}
