//! HTTP handlers, one module per resource.
//!
//! Shared concerns live here:
//!
//! * [`ProblemJson`] — a JSON body extractor that rejects with `problem+json`
//!   (`413` / `422`) instead of axum's plain-text default, and whose field
//!   errors name the offending member.
//! * [`blocking`] — every handler's database work runs on a blocking thread, as
//!   the `store` crate documents: `rusqlite` is synchronous, and running it
//!   inline would stall the async runtime under load.
//! * Query helpers so a malformed `?limit=abc` is a `problem+json` `422` rather
//!   than a bare `400`.

pub mod account;
pub mod aliases;
pub mod domains;
pub mod drafts;
pub mod health;
pub mod messages;
pub mod org;
pub mod send;
pub mod sessions;
pub mod suppressions;
pub mod templates;
pub mod twofa;
pub mod webhooks;
pub mod wkd;

use std::collections::HashMap;

use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use serde::de::DeserializeOwned;

use crate::problem::{internal, validation, FieldError, Problem};

/// Largest request body accepted (attachments are base64: 25 MB decoded can
/// inflate to ~35 MB on the wire).
pub const MAX_BODY_BYTES: usize = 36 * 1024 * 1024;

/// Query string parameters, already decoded. Handlers parse them with the
/// helpers below so a bad value becomes a `422` problem.
pub type Params = HashMap<String, String>;

/// Run synchronous storage work off the async runtime's threads.
pub async fn blocking<T, F>(work: F) -> Result<T, Problem>
where
    F: FnOnce() -> Result<T, Problem> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(%error, "blocking handler task failed");
            Err(internal("worker task failed"))
        }
    }
}

/// A JSON request body that fails with `problem+json`.
pub struct ProblemJson<T>(pub T);

impl<T, S> FromRequest<S> for ProblemJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Problem;

    async fn from_request(request: Request, _state: &S) -> Result<Self, Self::Rejection> {
        // `to_bytes` enforces the cap, which is why the router disables axum's
        // own `DefaultBodyLimit`: this way the rejection is problem+json.
        let bytes = axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES)
            .await
            .map_err(|_| {
                Problem::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    crate::problem::ProblemType::PayloadTooLarge,
                    format!(
                        "request body exceeds the {} MB limit",
                        MAX_BODY_BYTES / (1024 * 1024)
                    ),
                )
            })?;
        if bytes.is_empty() {
            return Err(validation(vec![FieldError::with_code(
                "",
                "required",
                "a JSON body is required",
            )]));
        }
        serde_json::from_slice(&bytes)
            .map(ProblemJson)
            .map_err(|error| {
                validation(vec![FieldError::with_code(
                    field_from_serde_error(&error),
                    "invalid",
                    error.to_string(),
                )])
            })
    }
}

/// The `422` problem for a body that does not match its schema.
pub fn deserialization_problem(error: &serde_json::Error) -> Problem {
    validation(vec![FieldError::with_code(
        field_from_serde_error(error),
        "invalid",
        error.to_string(),
    )])
}

/// Pull the offending member name out of a `serde_json` message so the client
/// gets `field: "from"` instead of an unparsable sentence.
fn field_from_serde_error(error: &serde_json::Error) -> String {
    let message = error.to_string();
    for marker in ["missing field `", "unknown field `", "duplicate field `"] {
        if let Some(rest) = message.split(marker).nth(1) {
            if let Some(name) = rest.split('`').next() {
                return name.to_string();
            }
        }
    }
    String::new()
}

/// Read a bounded integer query parameter, rejecting out-of-range values with a
/// field-level `422`.
pub fn int_param(
    params: &Params,
    name: &str,
    default: i64,
    min: i64,
    max: i64,
) -> Result<i64, Problem> {
    let Some(raw) = opt_param(params, name) else {
        return Ok(default);
    };
    let value: i64 = raw.parse().map_err(|_| {
        validation(vec![FieldError::with_code(
            name,
            "invalid",
            format!("{name} must be an integer, got {raw:?}"),
        )])
    })?;
    if !(min..=max).contains(&value) {
        return Err(validation(vec![FieldError::with_code(
            name,
            "out-of-range",
            format!("{name} must be between {min} and {max}, got {value}"),
        )]));
    }
    Ok(value)
}

/// Read a boolean query parameter (`true`/`false`/`1`/`0`).
pub fn bool_param(params: &Params, name: &str, default: bool) -> Result<bool, Problem> {
    let Some(raw) = opt_param(params, name) else {
        return Ok(default);
    };
    match raw.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(validation(vec![FieldError::with_code(
            name,
            "invalid",
            format!("{name} must be true or false, got {raw:?}"),
        )])),
    }
}

/// Read an optional string query parameter; empty values count as absent.
pub fn opt_param<'a>(params: &'a Params, name: &str) -> Option<&'a str> {
    params
        .get(name)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// Reject a query value against a closed set, echoing the allowed values.
pub fn enum_param(
    params: &Params,
    name: &str,
    allowed: &[&str],
) -> Result<Option<String>, Problem> {
    let Some(raw) = opt_param(params, name) else {
        return Ok(None);
    };
    let lowered = raw.to_ascii_lowercase();
    if allowed.contains(&lowered.as_str()) {
        Ok(Some(lowered))
    } else {
        Err(validation(vec![FieldError::with_code(
            name,
            "invalid",
            format!("{name} must be one of {}", allowed.join("|")),
        )]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(pairs: &[(&str, &str)]) -> Params {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn integer_parameters_default_and_clamp_to_the_contract_range() {
        let empty = Params::new();
        assert_eq!(int_param(&empty, "limit", 50, 1, 100).unwrap(), 50);
        assert_eq!(
            int_param(&params(&[("limit", "100")]), "limit", 50, 1, 100).unwrap(),
            100
        );
        for bad in ["0", "101", "-1"] {
            let error = int_param(&params(&[("limit", bad)]), "limit", 50, 1, 100).unwrap_err();
            assert_eq!(error.status, 422);
            assert_eq!(error.errors.as_ref().unwrap()[0].field, "limit");
        }
        let error = int_param(&params(&[("limit", "abc")]), "limit", 50, 1, 100).unwrap_err();
        assert_eq!(error.status, 422);
    }

    #[test]
    fn boolean_parameters_accept_both_spellings() {
        assert!(bool_param(&params(&[("raw", "true")]), "raw", false).unwrap());
        assert!(bool_param(&params(&[("raw", "1")]), "raw", false).unwrap());
        assert!(!bool_param(&params(&[("raw", "false")]), "raw", true).unwrap());
        assert!(bool_param(&Params::new(), "raw", true).unwrap());
        assert!(bool_param(&params(&[("raw", "maybe")]), "raw", true).is_err());
    }

    #[test]
    fn empty_query_values_are_treated_as_absent() {
        assert_eq!(opt_param(&params(&[("status", "  ")]), "status"), None);
        assert_eq!(
            opt_param(&params(&[("status", "sent")]), "status"),
            Some("sent")
        );
        assert_eq!(opt_param(&Params::new(), "status"), None);
    }

    #[test]
    fn enum_parameters_reject_values_outside_the_contract() {
        let allowed = ["queued", "sent"];
        assert_eq!(
            enum_param(&params(&[("status", "SENT")]), "status", &allowed).unwrap(),
            Some("sent".to_string())
        );
        assert_eq!(
            enum_param(&Params::new(), "status", &allowed).unwrap(),
            None
        );
        let error = enum_param(&params(&[("status", "bogus")]), "status", &allowed).unwrap_err();
        assert_eq!(error.errors.as_ref().unwrap()[0].field, "status");
    }

    #[test]
    fn serde_errors_yield_a_field_name() {
        let error = serde_json::from_str::<std::collections::BTreeMap<String, String>>("[]")
            .expect_err("array is not a map");
        assert!(field_from_serde_error(&error).is_empty());

        #[derive(Debug, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Required {
            #[allow(dead_code)]
            from: String,
        }
        let error = serde_json::from_str::<Required>("{}").expect_err("missing from");
        assert_eq!(field_from_serde_error(&error), "from");

        let error = serde_json::from_str::<Required>(r#"{"from":"a","extra":1}"#)
            .expect_err("unknown field");
        assert_eq!(field_from_serde_error(&error), "extra");
    }
}
