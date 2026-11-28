//! Health probes.
//!
//! Both endpoints are unauthenticated on purpose: an orchestrator cannot hold an
//! API key, and a probe that fails closed would keep a broken pod in rotation.
//!
//! * `/healthz` — liveness only. It answers `200` as long as the process can
//!   serve a request; it must not touch the database, because a slow disk should
//!   not make the orchestrator kill a working process.
//! * `/readyz` — readiness. It checks that the store answers `SELECT 1` and that
//!   the master key is loaded; otherwise `503` with a problem body naming the
//!   failed dependency.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::handlers::blocking;
use crate::problem::{internal, Problem, ProblemType};
use crate::state::AppState;

/// `GET /healthz` — always `200`.
pub async fn healthz() -> Response {
    (StatusCode::OK, "ok").into_response()
}

/// `GET /v1/instance` — public instance branding (issues #132 and #136).
///
/// Returns `{"display_name": "…" | null}`. The name resolves from the
/// request's `Host`: a `PIGEON_INSTANCE_NAMES` entry (parsed into
/// [`ApiConfig::instance_names`] at startup) wins, then the server-wide
/// `PIGEON_INSTANCE_NAME`. Unauthenticated on purpose: the webmail needs it
/// before login to render the header and tab title, and it carries no
/// secrets.
pub async fn instance(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    let display_name = state
        .config
        .display_name_for_host(host.as_deref())
        .map(|name| name.to_string());
    let body = serde_json::json!({ "display_name": display_name });
    (StatusCode::OK, axum::Json(body)).into_response()
}

/// `GET /readyz` — `200` when the store answers and the master key is loaded.
pub async fn readyz(State(state): State<AppState>) -> Response {
    let result = blocking(move || {
        if !state.master_key_loaded() {
            return Err(Problem::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ProblemType::Unavailable,
                "master key is not loaded",
            ));
        }
        state
            .db
            .ping()
            .map_err(|error| internal(format!("store is not reachable: {error}")))
    })
    .await;
    match result {
        Ok(()) => (StatusCode::OK, "ready").into_response(),
        Err(problem) => problem.into_response(),
    }
}
