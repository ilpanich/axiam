//! `GET /pki/v1/{org_id}/ca/{ca_id}/crl` — an issuing CA's certificate
//! revocation list (#565, T-102).
//!
//! Thin on purpose: what is published, which CAs publish one, how it is signed
//! and cached are `axiam_pki::crl`'s. This turns a [`PublishedCrl`] into HTTP —
//! the media type, the caching headers, and a `304` for a relying party that
//! already holds the current list.

use actix_web::http::header;
use actix_web::{HttpRequest, HttpResponse, web};
use axiam_pki::PublishedCrl;
use axiam_pki::crl::CRL_MEDIA_TYPE;
use chrono::Utc;
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::state::AppState;

/// The response body as the OpenAPI document names it: the DER bytes of an
/// RFC 5280 `CertificateList`.
#[derive(utoipa::ToSchema)]
#[schema(value_type = String, format = Binary)]
pub struct DerCrl(pub Vec<u8>);

/// The route's path parameters.
#[derive(Debug, Deserialize)]
pub struct CrlPath {
    org_id: Uuid,
    ca_id: Uuid,
}

/// `GET`/`HEAD /pki/v1/{org_id}/ca/{ca_id}/crl`
///
/// The CA's current CRL (RFC 5280 §5), DER, as `application/pkix-crl`:
/// signed with the CA's own key, `nextUpdate` a configured interval after
/// `thisUpdate` (`AXIAM__PKI__CRL_NEXT_UPDATE_SECS`, one day by default), with
/// a CRL number and an authority key identifier, and an entry for every
/// certificate the CA signed and revoked that has not expired. Every
/// certificate AXIAM signs names this URL in its CRL distribution points
/// extension when the deployment has a public base URL.
///
/// Unauthenticated, because a relying party fetches the list before it can
/// validate anything, and rate-limited per IP (`AXIAM__RATE_LIMIT__CRL_PER_MIN`).
/// `Cache-Control: public, max-age` runs to the list's `nextUpdate`, `ETag` is
/// the list's digest and `Last-Modified` its `thisUpdate`; a matching
/// `If-None-Match` answers `304`.
///
/// `404` for a CA that does not exist in that organization and, alike, for one
/// that publishes no list: a revoked or expired CA (its status is on its
/// parent's list), an imported trust anchor AXIAM holds no key for, and a CA
/// whose key Vault's PKI engine holds.
#[utoipa::path(
    get,
    path = "/pki/v1/{org_id}/ca/{ca_id}/crl",
    tag = "pki",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
        ("ca_id" = Uuid, Path, description = "Issuing CA certificate ID"),
    ),
    responses(
        (status = 200, description = "The CA's current certificate revocation list, DER \
             (RFC 5280 §5). `Cache-Control: public, max-age` until its nextUpdate, `ETag`, \
             `Last-Modified`", content_type = "application/pkix-crl", body = DerCrl),
        (status = 304, description = "The `If-None-Match` tag names the current list"),
        (status = 404, description = "No such CA in this organization, or a CA that \
             publishes no list (revoked, expired, keyless trust anchor, or a key held by \
             Vault's PKI engine)"),
        (status = 429, description = "Rate limit exceeded (`AXIAM__RATE_LIMIT__CRL_PER_MIN`)"),
    ),
)]
pub async fn get_crl<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    req: HttpRequest,
    path: web::Path<CrlPath>,
) -> Result<HttpResponse, AxiamApiError> {
    let crl = state
        .pki
        .crl_service
        .current(path.org_id, path.ca_id)
        .await?;
    Ok(respond(&req, &crl))
}

/// The response for `crl`, or a `304` when the caller already holds it.
fn respond(req: &HttpRequest, crl: &PublishedCrl) -> HttpResponse {
    let revalidated = req
        .headers()
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| crl.matches_if_none_match(v));
    let mut response = if revalidated {
        HttpResponse::NotModified()
    } else {
        HttpResponse::Ok()
    };
    response
        .insert_header((
            header::CACHE_CONTROL,
            format!("public, max-age={}", crl.max_age_secs(Utc::now())),
        ))
        .insert_header((header::ETAG, crl.etag.clone()))
        .insert_header((
            header::LAST_MODIFIED,
            crl.this_update
                .format("%a, %d %b %Y %H:%M:%S GMT")
                .to_string(),
        ));
    if revalidated {
        return response.finish();
    }
    response.content_type(CRL_MEDIA_TYPE).body(crl.der.to_vec())
}
