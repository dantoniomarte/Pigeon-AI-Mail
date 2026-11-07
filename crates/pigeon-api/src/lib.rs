//! Pigeon Mail HTTP API: the axum router, its handlers, and the rules the
//! contract in `openapi.yaml` states in prose.
//!
//! # Shape
//!
//! [`router`] is the whole server. Routes are grouped by the authentication they
//! require and each group carries one middleware, so the requirement of an
//! endpoint is declared next to the endpoint and cannot be forgotten inside a
//! handler:
//!
//! * `send` / `read` / `full` accept an API key (or a session, which carries
//!   `full` authority);
//! * the session group (logout and every `/v1/account/2fa/*` route) accepts only
//!   the `pigeon_session` cookie;
//! * the probes and `POST /v1/auth/login` are unauthenticated.
//!
//! # Invariants this crate enforces
//!
//! * **Accepted is not delivered.** `POST /v1/emails` answers `202` with
//!   `{id, status, e2e}`; the queue owns the rest.
//! * **problem+json everywhere.** Every failure — including a malformed body — is
//!   an RFC 7807 document with a `type` from the contract's closed enum.
//! * **Bcc never leaves the server.** It is written to the envelope and never to
//!   the generated MIME nor to any response.
//! * **Plaintext needs `full`.** `?sealed=false` is refused for `read` keys, and
//!   the default read returns ciphertext plus metadata.
//! * **Sealed before stored.** A body is sealed with the reserved message id as
//!   AAD before `store` sees it, and `store` refuses anything that is not a
//!   versioned envelope.
//!
//! `unsafe` is forbidden in this crate.

#![forbid(unsafe_code)]

pub mod aad;
pub mod auth;
pub mod base32;
pub mod db;
pub mod dkim;
pub mod handlers;
pub mod ids;
pub mod keys;
pub mod mime;
pub mod models;
pub mod problem;
pub mod rate_limit;
pub mod session;
pub mod state;
pub mod templates;
pub mod time;

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::middleware::{from_fn_with_state, Next};
use axum::routing::{delete, get, patch, post, put};
use axum::Router;
use pigeon_core::ApiKeyScope;

pub use state::{ApiConfig, AppState};

use crate::handlers::{
    account, domains, drafts, health, messages, org, send, sessions, suppressions,
    templates as template_handlers, twofa, webhooks,
};

/// Build the application router.
pub fn router(state: AppState) -> Router {
    let send_group = Router::new()
        .route("/v1/emails", post(send::send_email))
        .route("/v1/emails/batch", post(send::send_batch))
        .route("/v1/emails/{id}", delete(send::cancel_email))
        // Mailbox mutations hold `send`, matching the cancel-email pattern:
        // `read` is the metadata tier, moving/deleting mail is a write.
        .route(
            "/v1/messages/{id}",
            patch(messages::patch_message).delete(messages::delete_message),
        )
        .route("/v1/messages/empty-trash", post(messages::empty_trash))
        // The retention purge, on demand (the server also runs it on a timer).
        .route("/v1/messages/purge-trash", post(messages::purge_trash))
        // Settings are a write here and a read below: changing the trash
        // retention is a mailbox write, exactly like moving a message.
        .route("/v1/account/settings", patch(account::patch_settings))
        .route("/v1/templates", post(template_handlers::create_template))
        .route(
            "/v1/templates/{id}",
            patch(template_handlers::update_template).delete(template_handlers::delete_template),
        )
        .route(
            "/v1/templates/{id}/test-send",
            post(template_handlers::test_send),
        )
        // Drafts are a write surface: saving one is preparation to send, and
        // sending one goes through the same accept path as `POST /v1/emails`.
        .route("/v1/drafts", post(drafts::create_draft))
        .route(
            "/v1/drafts/{id}",
            patch(drafts::update_draft).delete(drafts::delete_draft),
        )
        .route("/v1/drafts/{id}/send", post(drafts::send_draft));

    let read_group = Router::new()
        .route("/v1/emails", get(send::list_emails))
        .route("/v1/emails/{id}", get(send::get_email))
        .route("/v1/messages", get(messages::list_messages))
        .route("/v1/messages/{id}", get(messages::get_message))
        .route(
            "/v1/messages/{id}/attachments/{aid}",
            get(messages::get_attachment),
        )
        .route("/v1/templates", get(template_handlers::list_templates))
        .route("/v1/templates/{id}", get(template_handlers::get_template))
        .route("/v1/drafts", get(drafts::list_drafts))
        .route("/v1/drafts/{id}", get(drafts::get_draft))
        // The account's mailbox policy is metadata, so reading it is `read`.
        .route("/v1/account/settings", get(account::get_settings));

    let full_group = Router::new()
        .route(
            "/v1/account/keys",
            post(account::create_key).get(account::list_keys),
        )
        .route(
            "/v1/account/keys/{id}",
            patch(account::patch_key).delete(account::delete_key),
        )
        .route(
            "/v1/domains",
            get(domains::list_domains).post(domains::add_domain),
        )
        .route("/v1/domains/{id}", get(domains::get_domain))
        .route("/v1/domains/{id}/dns", get(domains::domain_dns))
        .route(
            "/v1/webhooks",
            get(webhooks::list_webhooks).post(webhooks::create_webhook),
        )
        .route(
            "/v1/webhooks/{id}",
            get(webhooks::get_webhook).delete(webhooks::delete_webhook),
        )
        .route(
            "/v1/suppressions",
            get(suppressions::list_suppressions).post(suppressions::add_suppressions),
        )
        .route(
            "/v1/suppressions/{address}",
            delete(suppressions::remove_suppression),
        )
        // Multi-tenant administration: organizations, their members and their
        // invitations. Every handler re-proves the caller is an `owner`/`admin`
        // *of that organization*; the scope gate here only says "this is an
        // account-administration surface", exactly like the key endpoints.
        .route("/v1/orgs", get(org::list_orgs).post(org::create_org))
        .route(
            "/v1/orgs/{id}/members",
            get(org::list_members).post(org::create_member),
        )
        .route(
            "/v1/orgs/{id}/members/{account_id}",
            patch(org::patch_member),
        )
        .route(
            "/v1/orgs/{id}/invitations",
            get(org::list_invitations).post(org::create_invitation),
        )
        .route(
            "/v1/orgs/{id}/invitations/{invitation_id}",
            delete(org::delete_invitation),
        )
        .route("/v1/invitations/accept", post(org::accept_invitation))
        // Catch-all routing for inbound mail: what happens to an unknown local
        // part of a managed domain (`route` into a mailbox, or `discard`).
        .route("/v1/catchall", get(org::list_catchalls))
        .route(
            "/v1/catchall/{domain}",
            put(org::put_catchall).delete(org::delete_catchall),
        );

    // The session realm: a live `pigeon_session` cookie and nothing else. API
    // keys cannot touch the second factor (see `auth::require_session`).
    let session_group = Router::new()
        .route("/v1/auth/logout", post(sessions::logout))
        .route("/v1/auth/check", get(sessions::check))
        .route("/v1/account/2fa/enroll", post(twofa::enroll))
        .route("/v1/account/2fa/activate", post(twofa::activate))
        .route("/v1/account/2fa/verify", post(twofa::verify))
        .route("/v1/account/2fa/disable", post(twofa::disable));

    Router::new()
        .merge(protected(send_group, &state, ApiKeyScope::Send))
        .merge(protected(read_group, &state, ApiKeyScope::Read))
        .merge(protected(full_group, &state, ApiKeyScope::Full))
        .merge(session_only(session_group, &state))
        // Unauthenticated surface: the probes and the login that mints a session.
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
        .route("/v1/auth/login", post(sessions::login))
        // The body cap is enforced by the `ProblemJson` extractor so that an
        // oversized body is a `problem+json` 413, not axum's plain-text one.
        .layer(DefaultBodyLimit::disable())
        .with_state(state)
}

/// Attach the session-only middleware to the session realm's routes.
///
/// `route_layer`, not `layer`: a plain `layer` also wraps the sub-router's
/// catch-all fallback, and merging such a router makes the session middleware
/// answer for *unknown* paths — a `404` would become a `401` for every typo in a
/// URL. `route_layer` limits the middleware to the routes declared above, which
/// is what the axum docs recommend for auth layers.
fn session_only(router: Router<AppState>, state: &AppState) -> Router<AppState> {
    router.route_layer(from_fn_with_state(
        state.clone(),
        |state: State<AppState>, request: Request, next: Next| async move {
            auth::require_session(state, request, next).await
        },
    ))
}

/// Attach the auth middleware for `scope` to a route group.
fn protected(router: Router<AppState>, state: &AppState, scope: ApiKeyScope) -> Router<AppState> {
    router.layer(from_fn_with_state(
        state.clone(),
        move |state: State<AppState>, request: Request, next: Next| async move {
            auth::authorize(state, request, next, scope).await
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pigeon_crypto::MasterKey;

    fn state() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pigeon.db");
        let state = AppState::open(
            &path,
            MasterKey::parse(&[9u8; 32]).expect("key"),
            ApiConfig::default(),
        )
        .expect("state");
        (dir, state)
    }

    #[test]
    fn every_group_builds_and_the_state_is_shared() {
        let (_dir, state) = state();
        // Building the router twice proves the route table has no overlapping
        // method/path pair (axum panics on those at build time).
        let _first = router(state.clone());
        let _second = router(state);
    }
}
