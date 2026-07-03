//! Actix-Web middleware (owned by 16-05): `FromRequest` extractor
//! `AxiamUser`.
//!
//! Satisfies CONTRACT.md §10's per-framework middleware/route-guard
//! requirement for Actix-Web: extract the session (cookie or Bearer),
//! verify it locally against the cached JWKS (no AXIAM-server round-trip),
//! inject the authenticated identity, and map `AuthError`/`AuthzError` to
//! HTTP 401/403 with a standardized JSON error body.
//!
//! Feature-gated behind `actix` so the core SDK does not pull `actix-web`
//! unconditionally (D-02 modularity).

pub mod actix;

pub use actix::AxiamUser;
