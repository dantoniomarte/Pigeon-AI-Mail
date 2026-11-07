//! `POST /v1/auth/login` and `POST /v1/auth/logout` — the session realm.
//!
//! # What v0.1 login actually proves (be honest about it)
//!
//! There is **no password realm yet**. `POST /v1/auth/login` identifies the
//! account by email and, depending on what the account has, requires a code:
//!
//! * **2FA enrolled** — the code is mandatory, single-use, and rate-limited, so
//!   the account cannot be entered with the address alone. A TOTP code and a
//!   recovery code are both accepted here.
//! * **no 2FA, code present** — the code is read as a **bootstrap/invitation
//!   token** (`POST /v1/orgs/{id}/members` returns one when an admin creates a
//!   member; `POST /v1/orgs/{id}/invitations` returns one for somebody who already
//!   has an account). A token that matches no pending invitation for this address
//!   is a failed login, not a silent success: a code the server does not accept
//!   must never be indistinguishable from a correct one. Redeeming the token burns
//!   it and attaches the account to the organization.
//! * **no 2FA, no code** — rejected with 403 mfa-required. The earlier
//!   email-only shortcut was a session-issuance hole (anyone who knew the
//!   address could log in); every login now requires a code — the
//!   bootstrap/invitation token for accounts that have not enrolled TOTP.
//!
//! Passwords land together with the installer's admin bootstrap (hashed with
//! the same Argon2id the API keys use); this handler is where they will be
//! checked, and the `password` member of the request body is already accepted so
//! clients written against `openapi.yaml` do not break then. Until that ships,
//! an operator who wants a real second gate should enroll TOTP.
//!
//! # Failure accounting
//!
//! Every failed step — unknown address, missing code, wrong code, replayed code,
//! burned recovery code, rejected bootstrap token — is one failure against the
//! client IP budget ([`MAX_LOGIN_FAILURES`] per [`LOGIN_FAILURE_WINDOW`]). Over
//! budget is `429` with `Retry-After`, checked *before* any database work or
//! Argon2id hashing. A successful login consumes nothing.

use axum::extract::{Extension, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use pigeon_core::EmailAddress;
use store::Storage;

use crate::auth::{ClientIp, SessionContext, LOGIN_FAILURE_WINDOW, MAX_LOGIN_FAILURES};
use crate::handlers::{blocking, ProblemJson};
use crate::models::{LoginRequest, SessionIssued};
use crate::problem::{internal, unauthorized, validation, FieldError, Problem, ProblemType};
use crate::session::{self, IssuedSession};
use crate::state::AppState;

/// `POST /v1/auth/login` — identify the account, check 2FA, issue a session.
pub async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ProblemJson(request): ProblemJson<LoginRequest>,
) -> Response {
    if state.auth.over_login_budget(ip) {
        return rate_limited();
    }
    let email = match EmailAddress::parse(request.email.trim()) {
        Ok(email) => email,
        Err(error) => {
            return validation(vec![FieldError::with_code(
                "email",
                "invalid",
                format!("email is not an address: {error}"),
            )])
            .into_response()
        }
    };
    let code = request
        .code
        .map(|code| code.trim().to_string())
        .filter(|code| !code.is_empty());

    let work = state.clone();
    let issued = blocking(move || login_blocking(&work, &email, code.as_deref())).await;
    match issued {
        Ok(session) => session_response(&session),
        Err(problem) => {
            // Count the failure before answering: the budget is what makes
            // guessing a 6-digit TOTP code (10^6 space) impractical.
            state.auth.record_login_failure(ip);
            problem.into_response()
        }
    }
}

/// Everything the login does that touches the database, off the async runtime.
fn login_blocking(
    state: &AppState,
    email: &EmailAddress,
    code: Option<&str>,
) -> Result<IssuedSession, Problem> {
    let Some(account_id) = state
        .store
        .get_account_by_email(&email.normalized())
        .map_err(Problem::from)?
    else {
        // The same problem document an existing account would produce for a bad
        // code: the login form must not become an account-existence oracle.
        return Err(unauthorized("no account matches that address and code"));
    };

    let enrollment = state
        .store
        .get_totp_enrollment(account_id)
        .map_err(Problem::from)?;
    match enrollment.filter(|enrollment| enrollment.confirmed) {
        Some(enrollment) => {
            let Some(code) = code else {
                return Err(Problem::new(
                    StatusCode::FORBIDDEN,
                    ProblemType::MfaRequired,
                    "this account requires a second factor: resend the TOTP code, a recovery \
                     code, or the invitation/bootstrap token in `code`",
                ));
            };
            if !session::consume_second_factor(state, account_id, &enrollment, code)? {
                return Err(unauthorized(
                    "the second factor was not accepted (wrong code, expired step, or a replay of a \
                     code that was already used)",
                ));
            }
        }
        None => {
            // No TOTP: a bootstrap/invitation token is REQUIRED — the email
            // alone must never issue a session (owner security review: the
            // email-only shortcut let anyone knowing the address log in).
            let Some(code) = code else {
                return Err(Problem::new(
                    StatusCode::FORBIDDEN,
                    ProblemType::MfaRequired,
                    "this account requires a second factor: resend the TOTP code, a recovery \
                     code, or the invitation/bootstrap token in `code`",
                ));
            };
            if !session::consume_bootstrap_token(state, account_id, &email.normalized(), code)? {
                return Err(unauthorized(
                    "no pending invitation or bootstrap token matches that code for this \
                     address",
                ));
            }
        }
    }

    session::issue(state, account_id)
}

/// `GET /v1/auth/check` — 204 when the session cookie is valid.
///
/// The cookie is HttpOnly, so the SPA cannot read it from JavaScript; this
/// endpoint is how the webmail learns a session still exists without paying
/// for a full data fetch.
pub async fn check(Extension(session): Extension<SessionContext>) -> Response {
    let _ = session;
    StatusCode::NO_CONTENT.into_response()
}

/// `POST /v1/auth/logout` — revoke the session the request came in with.
pub async fn logout(
    State(state): State<AppState>,
    Extension(session): Extension<SessionContext>,
) -> Response {
    let result = blocking(move || {
        state
            .store
            .revoke_session(&session.session_id)
            .map_err(Problem::from)?;
        // The verified-session cache would otherwise keep this cookie working
        // until the TTL expired.
        state.auth.invalidate_all();
        Ok(())
    })
    .await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// Attach the cookie and serialise the session the handler just minted.
fn session_response(session: &IssuedSession) -> Response {
    let body = SessionIssued {
        session_id: session.session_id.clone(),
        expires_at: session.expires_at.clone(),
    };
    let mut response = Json(body).into_response();
    // The cookie value is generated by this crate (base64url + `.`), so it is
    // always a valid header value; a failure here would be a bug worth a 500.
    match HeaderValue::from_str(&session.set_cookie()) {
        Ok(value) => {
            response.headers_mut().insert(header::SET_COOKIE, value);
            response
        }
        Err(error) => {
            internal(format!("could not build the session cookie: {error}")).into_response()
        }
    }
}

/// The `429` for a client that spent its second-factor budget.
///
/// `pub(crate)` because the 2FA handlers answer with the same problem: a guessed
/// code costs the same budget wherever it is guessed.
pub(crate) fn rate_limited() -> Response {
    Problem::new(
        StatusCode::TOO_MANY_REQUESTS,
        ProblemType::RateLimited,
        format!(
            "too many failed login attempts: at most {MAX_LOGIN_FAILURES} per {} minutes are \
             accepted from one address",
            LOGIN_FAILURE_WINDOW.as_secs() / 60
        ),
    )
    .with_retry_after(LOGIN_FAILURE_WINDOW.as_secs())
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_session_response_carries_the_cookie_and_the_body() {
        let session = IssuedSession {
            session_id: "sess_0000000000000001".to_string(),
            token: "sess_0000000000000001.abc".to_string(),
            expires_at: "2026-11-06T00:00:00Z".to_string(),
        };
        let body = SessionIssued {
            session_id: session.session_id.clone(),
            expires_at: session.expires_at.clone(),
        };
        let json = serde_json::to_string(&body).expect("serialize");
        assert!(json.contains("sess_0000000000000001"), "{json}");
        assert!(json.contains("2026-11-06T00:00:00Z"), "{json}");
        assert!(session.set_cookie().contains("HttpOnly"));
    }
}
