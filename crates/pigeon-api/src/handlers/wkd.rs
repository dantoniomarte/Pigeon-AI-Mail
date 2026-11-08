//! WKD publication endpoints.
//!
//! Two routes, both unauthenticated on purpose — a key directory is meant to be
//! read by anyone who wants to send you sealed mail:
//!
//! * `GET /.well-known/pigeon-pgp?email=<address>` — the simple endpoint Pigeon
//!   instances use between themselves. Returns the armored certificate.
//! * `GET /.well-known/openpgpkey/<domain>/hu/<hash>` — the advanced WKD path
//!   (draft-koch-openpgp-webkey-service): the same certificate in binary, keyed by
//!   `z-base-32(SHA-1(lowercased local part))`.
//!
//! Both are unauthenticated and therefore **rate limited per source address**
//! ([`crate::rate_limit::WKD_RATE_RPS`] sustained, a bounded burst): a key directory
//! is meant to be read, but not at whatever rate a stranger picks.
//!
//! Both answer **only for accounts of this instance**. A sender alias publishes
//! nothing: it has several owners, so "the key for sales@example.com" has no single
//! answer, and inventing one would hand the mail to an arbitrary person. This is
//! documented in `docs/e2ee-model.md` and `docs/API.md`.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use pigeon_core::EmailAddress;

use crate::handlers::{blocking, Params};
use crate::models::E2e;
use crate::problem::{internal, not_found, validation, FieldError, Problem, ProblemType};
use crate::rate_limit::client_bucket;
use crate::state::AppState;
use crate::wkd;

/// Content type of an armored OpenPGP certificate.
///
/// `application/pgp-keys` is what GnuPG and Proton serve; a client that only looks
/// at the body still gets the armor it expects.
const ARMOR_CONTENT_TYPE: &str = "application/pgp-keys";

/// Refuse a caller that is hammering an unauthenticated key directory.
///
/// `None` when the request may proceed. The bucket is keyed by source address
/// ([`client_bucket`]) and ignores the port, so reconnecting does not refresh the
/// budget. `429` carries `Retry-After`, exactly like the keyed API limit, so a well
/// behaved client backs off instead of retrying in a loop.
fn rate_limited(state: &AppState, peer: std::net::IpAddr) -> Option<Problem> {
    match state.wkd_limiter.check(client_bucket(peer)) {
        Ok(_) => None,
        Err(retry_after) => Some(
            Problem::new(
                StatusCode::TOO_MANY_REQUESTS,
                ProblemType::RateLimited,
                format!(
                    "sustained limit for key lookups is {} requests/second per address",
                    crate::rate_limit::WKD_RATE_RPS
                ),
            )
            .with_retry_after(retry_after),
        ),
    }
}

/// `GET /.well-known/pigeon-pgp?email=<address>`.
pub async fn pigeon_pgp(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(params): Query<Params>,
) -> Response {
    if let Some(problem) = rate_limited(&state, peer.ip()) {
        return problem.into_response();
    }
    let Some(raw) = params.get("email").map(|value| value.trim().to_string()) else {
        return validation(vec![FieldError::with_code(
            "email",
            "required",
            "email is required: this endpoint publishes the key for one address",
        )])
        .into_response();
    };
    let Ok(address) = EmailAddress::parse(&raw) else {
        return validation(vec![FieldError::with_code(
            "email",
            "invalid",
            "email is not a valid address",
        )])
        .into_response();
    };

    let published_for = address.clone();
    let result = blocking(move || {
        let store = &state.store;
        match wkd::publication_key(store, &state.master_key, &published_for) {
            Ok(Some(armored)) => Ok(Some(armored)),
            Ok(None) => Ok(None),
            Err(error) => Err(internal(format!(
                "cannot publish the key for {published_for}: {error}"
            ))),
        }
    })
    .await;

    match result {
        // A key directory's "no such address" is a plain 404: the sender falls back
        // to tls_only and the instance reveals nothing else.
        Ok(None) => not_found(format!("no OpenPGP key is published for {address}")).into_response(),
        Ok(Some(armored)) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, ARMOR_CONTENT_TYPE)],
            armored,
        )
            .into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `GET /.well-known/openpgpkey/<domain>/hu/<hash>` — advanced WKD.
pub async fn advanced_wkd(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path((domain, hash)): Path<(String, String)>,
) -> Response {
    if let Some(problem) = rate_limited(&state, peer.ip()) {
        return problem.into_response();
    }
    let result = blocking(move || {
        match wkd::publication_key_by_hash(&state.store, &state.master_key, &domain, &hash) {
            Ok(Some(binary)) => Ok(Some(binary)),
            Ok(None) => Ok(None),
            Err(error) => Err(internal(format!(
                "cannot publish the key for {domain}/hu/{hash}: {error}"
            ))),
        }
    })
    .await;

    match result {
        Ok(None) => not_found("no OpenPGP key is published for this address").into_response(),
        Ok(Some(binary)) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            binary,
        )
            .into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// The `e2e` value this deployment reports for mail that simply arrived over SMTP
/// from a foreign sender.
///
/// Inbound mail from a sender that did not seal to our published key is
/// `tls_only` by definition: the server received plaintext-or-TLS bytes and sealed
/// them at rest (layer 1). It is never reported as `sealed`, because no recipient
/// key was used.
pub const INBOUND_E2E: E2e = E2e::TlsOnly;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_mail_is_never_reported_as_sealed() {
        assert_eq!(INBOUND_E2E.as_str(), "tls_only");
        assert_eq!(INBOUND_E2E, E2e::TlsOnly);
    }
}
