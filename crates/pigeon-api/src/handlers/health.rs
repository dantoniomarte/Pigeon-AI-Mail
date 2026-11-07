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
