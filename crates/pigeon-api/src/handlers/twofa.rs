//! `/v1/account/2fa/*` — TOTP enrollment, activation, step-up verification and
//! disable.
//!
//! Every route here requires a **dashboard session** (`auth::require_session`)
//! and nothing else: an API key cannot enroll, verify or disable a second factor.
//! A machine credential that could turn 2FA off would make it decorative, and
//! enrollment is a human-at-a-browser flow (scan the QR, type the code).
//!
//! # Lifecycle
//!
//! 1. `enroll` — mint a 160-bit secret, seal it under the master key (AAD
//!    `totp:{account_id}`) and store it with `confirmed = 0`. Login still works
//!    without a code, because an enrollment that was never proven would otherwise
//!    lock the account out the moment the browser tab closed.
//! 2. `activate` — the first code from the authenticator app confirms the secret
//!    (`confirmed = 1`), stamps `enrolled_at`, seeds the replay counter and
//!    returns ten single-use recovery codes **once** (only Argon2id hashes are
//!    stored).
//! 3. `verify` — step-up check for a live session: the same TOTP/recovery
//!    verification and replay rejection the login uses.
//! 4. `disable` — requires a valid code, deletes the enrollment and revokes every
//!    other session of the account.
//!
//! # Why activation does not consume a TOTP step
//!
//! `activate` proves possession of the secret but leaves the replay counter at
//! zero, so the same code can still be used to log in inside the same 30-second
//! step. Refusing that would mean: activate, wait for the next step, then log in
//! — a real usability cost for no security gain, since the code came from the
//! owner's own authenticator in the session that is already authenticated.
//! Replay protection starts with the first authentication and is strict from
//! there on (every login, verify and disable consumes its step).

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use pigeon_crypto::Totp;
use store::Storage;

use crate::auth::{ClientIp, SessionContext, LOGIN_FAILURE_WINDOW};
use crate::handlers::sessions::rate_limited;
use crate::handlers::{blocking, ProblemJson};
use crate::models::{CodeVerified, RecoveryCodesIssued, TotpCodeRequest, TotpEnrollmentView};
use crate::problem::{internal, not_found, unauthorized, validation, FieldError, Problem};
use crate::session::{self, TOTP_WINDOW};
use crate::state::AppState;
use crate::time;

/// `POST /v1/account/2fa/enroll` — start (or restart) TOTP enrollment.
pub async fn enroll(
    State(state): State<AppState>,
    Extension(session): Extension<SessionContext>,
) -> Response {
    let result = blocking(move || {
        let secret = pigeon_crypto::generate_totp_secret();
        let wrapped = session::wrap_totp_secret(&state.master_key, session.account_id, &secret)
            .map_err(internal)?;
        let (_, email) = state
            .store
            .get_account(session.account_id)
            .map_err(Problem::from)?;
        // Stored before the response: a client that scanned the QR code must not
        // be holding a secret the server never saved.
        state
            .store
            .set_totp_enrollment(session.account_id, &wrapped)
            .map_err(Problem::from)?;
        if let Err(error) = state.store.audit(
            &format!("session:{}", session.session_id),
            "totp.enroll",
            "",
        ) {
            tracing::warn!(%error, "could not write audit row");
        }
        let secret_base32 = session::secret_base32(&secret);
        Ok(TotpEnrollmentView {
            otpauth_uri: session::otpauth_uri(&email.to_string(), &secret_base32),
            secret_base32,
        })
    })
    .await;
    match result {
        Ok(view) => Json(view).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `POST /v1/account/2fa/activate` — confirm the secret, issue recovery codes.
pub async fn activate(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Extension(session): Extension<SessionContext>,
    ProblemJson(request): ProblemJson<TotpCodeRequest>,
) -> Response {
    if state.auth.over_login_budget(ip) {
        return rate_limited();
    }
    let code = request.code.trim().to_string();
    let result = blocking(move || {
        let enrollment = state
            .store
            .get_totp_enrollment(session.account_id)
            .map_err(Problem::from)?
            .ok_or_else(|| {
                not_found(
                    "no TOTP enrollment is in progress for this account: POST /v1/account/2fa/enroll \
                     first",
                )
            })?;
        let secret = session::open_totp_secret(
            &state.master_key,
            session.account_id,
            &enrollment.secret_wrapped,
        )
        .map_err(internal)?;
        let totp = Totp::try_new(&secret).map_err(internal)?;
        let now = time::now_unix().max(0) as u64;
        if !totp.verify(&code, now, TOTP_WINDOW) {
            // A form-value rejection, not an authentication failure: the caller
            // is already authenticated, they typed the wrong code.
            return Err(validation(vec![FieldError::with_code(
                "code",
                "invalid",
                "the code does not match the enrolled secret (check the authenticator's clock)",
            )]));
        }
        let codes = session::new_recovery_codes();
        let hashes = codes
            .iter()
            .map(|code| session::hash_token(code))
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal)?;
        // Seeded with step 0: activation does not spend a step (see the module
        // docs), so the first login may use the very code that activated.
        state
            .store
            .confirm_totp(session.account_id, &hashes, 0)
            .map_err(Problem::from)?;
        if let Err(error) = state.store.audit(
            &format!("session:{}", session.session_id),
            "totp.activate",
            "",
        ) {
            tracing::warn!(%error, "could not write audit row");
        }
        Ok(RecoveryCodesIssued {
            recovery_codes: codes,
        })
    })
    .await;
    match result {
        Ok(issued) => Json(issued).into_response(),
        Err(problem) => {
            if problem.status == StatusCode::UNPROCESSABLE_ENTITY.as_u16() {
                state.auth.record_login_failure(ip);
            }
            problem.into_response()
        }
    }
}

/// `POST /v1/account/2fa/verify` — step-up check for the current session.
pub async fn verify(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Extension(session): Extension<SessionContext>,
    ProblemJson(request): ProblemJson<TotpCodeRequest>,
) -> Response {
    match consume(&state, &session, request.code.trim(), ip).await {
        Ok(()) => Json(CodeVerified { verified: true }).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `POST /v1/account/2fa/disable` — require a code, then tear 2FA down.
pub async fn disable(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Extension(session): Extension<SessionContext>,
    ProblemJson(request): ProblemJson<TotpCodeRequest>,
) -> Response {
    if let Err(problem) = consume(&state, &session, request.code.trim(), ip).await {
        return problem.into_response();
    }
    let result = blocking(move || {
        state
            .store
            .revoke_totp(session.account_id)
            .map_err(Problem::from)?;
        // Turning the second factor off must not leave the sessions it was
        // protecting alive: every session but this one goes.
        let revoked = state
            .store
            .revoke_all_account_sessions(session.account_id, Some(&session.session_id))
            .map_err(Problem::from)?;
        state.auth.invalidate_all();
        if let Err(error) = state.store.audit(
            &format!("session:{}", session.session_id),
            "totp.disable",
            &format!("revoked_sessions={revoked}"),
        ) {
            tracing::warn!(%error, "could not write audit row");
        }
        Ok(())
    })
    .await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// Verify and consume a code for `session`, sharing one failure budget with the
/// login path: a guessed code costs the same wherever it is guessed.
async fn consume(
    state: &AppState,
    session: &SessionContext,
    code: &str,
    ip: Option<std::net::IpAddr>,
) -> Result<(), Problem> {
    if state.auth.over_login_budget(ip) {
        return Err(Problem::new(
            StatusCode::TOO_MANY_REQUESTS,
            crate::problem::ProblemType::RateLimited,
            "too many failed second-factor attempts from this address",
        )
        .with_retry_after(LOGIN_FAILURE_WINDOW.as_secs()));
    }
    if code.is_empty() {
        return Err(validation(vec![FieldError::with_code(
            "code",
            "required",
            "code is required",
        )]));
    }
    let account_id = session.account_id;
    let code = code.to_string();
    let work = state.clone();
    let result = blocking(move || {
        let enrollment = work
            .store
            .get_totp_enrollment(account_id)
            .map_err(Problem::from)?
            .filter(|enrollment| enrollment.confirmed)
            .ok_or_else(|| {
                validation(vec![FieldError::with_code(
                    "code",
                    "not-enabled",
                    "two-factor authentication is not enabled for this account",
                )])
            })?;
        if session::consume_second_factor(&work, account_id, &enrollment, &code)? {
            return Ok(());
        }
        Err(unauthorized(
            "the code was not accepted (wrong code, expired step, or a replay of a code that was \
             already used)",
        ))
    })
    .await;
    if result.is_err() {
        state.auth.record_login_failure(ip);
    }
    result
}
