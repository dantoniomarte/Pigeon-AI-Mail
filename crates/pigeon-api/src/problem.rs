//! RFC 7807 problem details — the only error shape this API emits.
//!
//! Every failure is `application/problem+json` with a `type` drawn from the
//! closed enum in `openapi.yaml`, so a client can branch on the machine-readable
//! `type` instead of parsing prose. The [`Problem`] struct mirrors the contract
//! schema member for member (including the optional `id`, `quota` and `errors`),
//! and [`Problem::into_response`] sets the media type the spec requires.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::time::{iso_from_unix, next_utc_midnight, now_unix};

/// The closed set of problem types in `openapi.yaml` (`Problem.type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProblemType {
    /// Per-key request rate exceeded.
    RateLimited,
    /// Per-account daily send quota exceeded.
    QuotaExceeded,
    /// The idempotency key was already used; `id` carries the original email.
    IdempotentReplay,
    /// The email is no longer queued/scheduled, so it cannot be cancelled.
    NotCancellable,
    /// Request body failed validation; `errors` carries the field list.
    Validation,
    /// Missing or invalid credentials.
    Unauthorized,
    /// Authenticated, but the key does not hold the required scope.
    Forbidden,
    /// The resource does not exist for this account.
    NotFound,
    /// The write collides with an existing resource (e.g. duplicate name).
    Conflict,
    /// The request body exceeded the accepted size.
    PayloadTooLarge,
    /// The server cannot serve the request yet (unimplemented surface, storage
    /// failure). Never used for a client mistake.
    Unavailable,
    /// 2FA is enrolled and the login carried no valid code.
    MfaRequired,
    /// The change would leave an organization with no owner.
    LastOwner,
    /// The `from` address is neither the caller's own nor an alias assigned to it.
    FromNotAllowed,
}

impl ProblemType {
    /// Machine-readable type, as serialized.
    pub const fn as_str(self) -> &'static str {
        match self {
            ProblemType::RateLimited => "rate-limited",
            ProblemType::QuotaExceeded => "quota-exceeded",
            ProblemType::IdempotentReplay => "idempotent-replay",
            ProblemType::NotCancellable => "not-cancellable",
            ProblemType::Validation => "validation",
            ProblemType::Unauthorized => "unauthorized",
            ProblemType::Forbidden => "forbidden",
            ProblemType::NotFound => "not-found",
            ProblemType::Conflict => "conflict",
            ProblemType::PayloadTooLarge => "payload-too-large",
            ProblemType::Unavailable => "unavailable",
            ProblemType::MfaRequired => "mfa-required",
            ProblemType::LastOwner => "last-owner",
            ProblemType::FromNotAllowed => "from-not-allowed",
        }
    }

    /// Human-readable default title for the type.
    pub const fn title(self) -> &'static str {
        match self {
            ProblemType::RateLimited => "Rate limit exceeded",
            ProblemType::QuotaExceeded => "Daily send quota exceeded",
            ProblemType::IdempotentReplay => "Idempotency key already used",
            ProblemType::NotCancellable => "Email is not cancellable",
            ProblemType::Validation => "Validation failed",
            ProblemType::Unauthorized => "Unauthorized",
            ProblemType::Forbidden => "Forbidden",
            ProblemType::NotFound => "Not found",
            ProblemType::Conflict => "Conflict",
            ProblemType::PayloadTooLarge => "Payload too large",
            ProblemType::Unavailable => "Service unavailable",
            ProblemType::MfaRequired => "Two-factor authentication required",
            ProblemType::LastOwner => "The last owner cannot be removed",
            ProblemType::FromNotAllowed => "Sender address not allowed",
        }
    }
}

/// `Problem.quota` — only on `quota-exceeded`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Quota {
    pub limit: i64,
    pub used: i64,
    pub reset_at: String,
}

impl Quota {
    /// Quota snapshot for `used` of `limit`, resetting at the next UTC midnight.
    pub fn daily(limit: i64, used: i64) -> Self {
        Self {
            limit,
            used,
            reset_at: iso_from_unix(next_utc_midnight(now_unix())),
        }
    }
}

/// `Problem.errors[]` — one entry per rejected field (`422` only).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FieldError {
    pub field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub message: String,
}

impl FieldError {
    /// Field error without a machine-readable code.
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            code: None,
            message: message.into(),
        }
    }

    /// Field error with a machine-readable code (`required`, `invalid`, ...).
    pub fn with_code(
        field: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            field: field.into(),
            code: Some(code.into()),
            message: message.into(),
        }
    }
}

/// An RFC 7807 problem, serialized as `application/problem+json`.
///
/// The text members are boxed slices and the optional members are boxed so the
/// value stays small: it is carried in `Result::Err` through every handler, and
/// a fat error type makes every `Result` in the crate fat.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Problem {
    #[serde(rename = "type")]
    pub type_: &'static str,
    pub title: Box<str>,
    pub status: u16,
    pub detail: Box<str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Box<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota: Option<Box<Quota>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Box<Vec<FieldError>>>,
    /// Transport-level header value; never serialized into the body.
    #[serde(skip)]
    pub retry_after: Option<u64>,
}

impl Problem {
    /// Problem with the type's default title.
    pub fn new(status: StatusCode, type_: ProblemType, detail: impl Into<String>) -> Self {
        Self {
            type_: type_.as_str(),
            title: type_.title().into(),
            status: status.as_u16(),
            detail: detail.into().into_boxed_str(),
            id: None,
            quota: None,
            errors: None,
            retry_after: None,
        }
    }

    /// Replace the default title.
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into().into_boxed_str();
        self
    }

    /// Attach the original email id (`idempotent-replay`).
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into().into_boxed_str());
        self
    }

    /// Attach the quota snapshot (`quota-exceeded`).
    pub fn with_quota(mut self, quota: Quota) -> Self {
        self.quota = Some(Box::new(quota));
        self
    }

    /// Attach the field error list (`validation`).
    pub fn with_errors(mut self, errors: Vec<FieldError>) -> Self {
        self.errors = Some(Box::new(errors));
        self
    }

    /// Attach a `Retry-After` header (`429`).
    pub fn with_retry_after(mut self, seconds: u64) -> Self {
        self.retry_after = Some(seconds);
        self
    }

    /// HTTP status of this problem.
    pub fn status_code(&self) -> StatusCode {
        StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let retry_after = self.retry_after;
        // `serde_json` on a struct of owned scalars cannot fail; mapping the
        // error to a bare status keeps this infallible without `unwrap`.
        let body = serde_json::to_vec(&self).unwrap_or_else(|_| b"{}".to_vec());
        let mut response = (
            status,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/problem+json"),
            )],
            body,
        )
            .into_response();
        if let Some(seconds) = retry_after {
            if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }
        response
    }
}

/// Build a problem `Response` in one call. `title` overrides the type's default.
pub fn problem(
    status: StatusCode,
    type_: ProblemType,
    title: &str,
    detail: impl Into<String>,
) -> Response {
    Problem::new(status, type_, detail)
        .with_title(title)
        .into_response()
}

/// `401` for a missing/invalid API key.
pub fn unauthorized(detail: impl Into<String>) -> Problem {
    Problem::new(StatusCode::UNAUTHORIZED, ProblemType::Unauthorized, detail)
}

/// `403` for a scope mismatch.
pub fn forbidden(detail: impl Into<String>) -> Problem {
    Problem::new(StatusCode::FORBIDDEN, ProblemType::Forbidden, detail)
}

/// `403 from-not-allowed` for a `from` the caller may not send as.
///
/// Distinct from [`forbidden`] on purpose: a client has to tell "this key lacks a
/// scope" (fix by issuing another key) from "this identity is not yours" (fix by
/// asking an admin for the alias).
pub fn from_not_allowed(detail: impl Into<String>) -> Problem {
    Problem::new(StatusCode::FORBIDDEN, ProblemType::FromNotAllowed, detail)
}

/// `404` for a resource that is not visible to this account.
pub fn not_found(detail: impl Into<String>) -> Problem {
    Problem::new(StatusCode::NOT_FOUND, ProblemType::NotFound, detail)
}

/// `422` carrying field-level errors.
pub fn validation(errors: Vec<FieldError>) -> Problem {
    Problem::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        ProblemType::Validation,
        "one or more fields are invalid",
    )
    .with_errors(errors)
}

/// `500` for a storage/`SQLite` failure the client cannot fix.
pub fn internal(error: impl std::fmt::Display) -> Problem {
    Problem::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        ProblemType::Unavailable,
        format!("internal error: {error}"),
    )
}

/// Map a storage failure onto the contract: a missing row is `404`, a unique
/// collision is `409`, everything else is a `500` that never leaks SQL detail
/// beyond a one-line reason.
impl From<store::StoreError> for Problem {
    fn from(error: store::StoreError) -> Self {
        match error {
            store::StoreError::NotFound => not_found("resource not found"),
            store::StoreError::Conflict => Problem::new(
                StatusCode::CONFLICT,
                ProblemType::Conflict,
                "a resource with the same unique key already exists",
            ),
            // A `409` too, but with the actionable half: a duplicate account means
            // "pick another address", a shadowed alias means "delete the alias
            // first".
            store::StoreError::AliasShadow(address) => Problem::new(
                StatusCode::CONFLICT,
                ProblemType::Conflict,
                format!(
                    "{address} is a sender alias: an account cannot own that address. Delete the                      alias first, or use another address"
                ),
            ),
            other => internal(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).expect("problem body is JSON")
    }

    #[test]
    fn type_strings_match_the_contract_enum() {
        assert_eq!(ProblemType::RateLimited.as_str(), "rate-limited");
        assert_eq!(ProblemType::QuotaExceeded.as_str(), "quota-exceeded");
        assert_eq!(ProblemType::IdempotentReplay.as_str(), "idempotent-replay");
        assert_eq!(ProblemType::NotCancellable.as_str(), "not-cancellable");
        assert_eq!(ProblemType::PayloadTooLarge.as_str(), "payload-too-large");
        assert_eq!(ProblemType::MfaRequired.as_str(), "mfa-required");
        assert_eq!(ProblemType::LastOwner.as_str(), "last-owner");
        assert_eq!(ProblemType::FromNotAllowed.as_str(), "from-not-allowed");
        for type_ in [
            ProblemType::RateLimited,
            ProblemType::QuotaExceeded,
            ProblemType::IdempotentReplay,
            ProblemType::NotCancellable,
            ProblemType::Validation,
            ProblemType::Unauthorized,
            ProblemType::Forbidden,
            ProblemType::NotFound,
            ProblemType::Conflict,
            ProblemType::PayloadTooLarge,
            ProblemType::Unavailable,
            ProblemType::MfaRequired,
            ProblemType::LastOwner,
            ProblemType::FromNotAllowed,
        ] {
            assert!(!type_.title().is_empty());
        }
    }

    #[tokio::test]
    async fn problem_serializes_required_members_and_omits_empty_ones() {
        let response = Problem::new(
            StatusCode::NOT_FOUND,
            ProblemType::NotFound,
            "no such email",
        )
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/problem+json"
        );
        let body = body_json(response).await;
        assert_eq!(body["type"], "not-found");
        assert_eq!(body["status"], 404);
        assert_eq!(body["title"], "Not found");
        assert_eq!(body["detail"], "no such email");
        assert!(body.get("id").is_none());
        assert!(body.get("quota").is_none());
        assert!(body.get("errors").is_none());
        assert!(body.get("retry_after").is_none());
    }

    #[tokio::test]
    async fn quota_and_errors_and_id_are_serialized_when_present() {
        let problem = Problem::new(
            StatusCode::PAYMENT_REQUIRED,
            ProblemType::QuotaExceeded,
            "quota reached",
        )
        .with_quota(Quota::daily(50_000, 50_000));
        let body = body_json(problem.into_response()).await;
        assert_eq!(body["quota"]["limit"], 50_000);
        assert_eq!(body["quota"]["used"], 50_000);
        assert!(body["quota"]["reset_at"]
            .as_str()
            .expect("reset_at is a string")
            .ends_with('Z'));

        let problem = validation(vec![
            FieldError::with_code("from", "required", "from is required"),
            FieldError::new("to[0]", "to[0] is not an address"),
        ])
        .with_id("eml_9f2a44c1");
        let body = body_json(problem.into_response()).await;
        assert_eq!(body["id"], "eml_9f2a44c1");
        assert_eq!(body["errors"][0]["field"], "from");
        assert_eq!(body["errors"][0]["code"], "required");
        assert_eq!(body["errors"][1]["field"], "to[0]");
        assert!(body["errors"][1].get("code").is_none());
    }

    #[tokio::test]
    async fn retry_after_becomes_a_header_not_a_body_member() {
        let response = Problem::new(
            StatusCode::TOO_MANY_REQUESTS,
            ProblemType::RateLimited,
            "slow down",
        )
        .with_retry_after(7)
        .into_response();
        assert_eq!(response.headers()[header::RETRY_AFTER], "7");
        let body = body_json(response).await;
        assert!(body.get("retry_after").is_none());
    }

    #[test]
    fn store_errors_map_to_the_documented_statuses() {
        let not_found: Problem = store::StoreError::NotFound.into();
        assert_eq!(not_found.status, 404);
        let conflict: Problem = store::StoreError::Conflict.into();
        assert_eq!(conflict.status, 409);
        assert_eq!(conflict.type_, "conflict");
    }

    #[test]
    fn helper_constructors_use_the_right_status_and_type() {
        assert_eq!(unauthorized("x").status, 401);
        assert_eq!(forbidden("x").status, 403);
        assert_eq!(not_found("x").status, 404);
        assert_eq!(validation(Vec::new()).status, 422);
        let internal = internal("boom");
        assert_eq!(internal.status, 500);
        assert_eq!(internal.type_, "unavailable");
        assert!(internal.detail.contains("boom"));
    }
}
