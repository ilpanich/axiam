//! AXIAM SCIM 2.0 provisioning (RFC 7643/7644), mounted under `/scim/v2`.
//!
//! R3.1 / improvement-after-run5-benchmark.md §B4. See
//! `docs/api/scim-provisioning.md` for the Okta/Entra setup walkthroughs and
//! `crate::auth` for how tenant scoping and the dedicated `scim:provision`
//! permission are enforced.
//!
//! ## Scope (verbatim from B4 — do not expand it here)
//!
//! `Users` and `Groups`: full CRUD, PATCH restricted to the RFC 7644 §3.5.2
//! op subset Okta/Entra actually send (add/replace/remove on standard
//! attribute paths — see [`patch`]); filtering subset `userName eq` and
//! `externalId eq`, plus paging (see [`filter`]); `/Schemas`,
//! `/ServiceProviderConfig`, `/ResourceTypes` (see [`schema`]). Maps onto
//! the EXISTING `UserRepository`/`GroupRepository` — no parallel storage.
//! Explicitly OUT of scope: bulk operations (`POST /Bulk` returns 501),
//! complex filters (anything but `<attr> eq "<value>"` returns 400
//! `invalidFilter`).

pub mod auth;
pub mod error;
pub mod filter;
pub mod groups;
pub mod patch;
pub mod routes;
pub mod schema;
pub mod scim_metadata;
pub mod users;

pub use routes::{scim_routes, scim_routes_with_rate_limits};
