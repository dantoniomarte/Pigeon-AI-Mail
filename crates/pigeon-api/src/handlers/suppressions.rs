//! Suppressions: the recipients this account must never mail again.
//!
//! The table is a *list of addresses plus why*, not a mail-sending feature: v0.1
//! stores and pages it, the delivery pipeline will consult it, and hard bounces
//! will add rows automatically. Manual adds are capped at 100 per call and
//! deduplicated case-insensitively (an address differing only in local-part case
//! is the same mailbox).

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use pigeon_core::EmailAddress;
use store::Storage;

use crate::auth::ApiKeyContext;
use crate::db::SuppressionRow;
use crate::handlers::{blocking, int_param, Params, ProblemJson};
use crate::models::{PageMeta, SuppressionCreate, SuppressionPage, SuppressionView};
use crate::problem::{not_found, validation, FieldError, Problem};
use crate::state::AppState;

/// Addresses accepted per call.
const MAX_ADDRESSES: usize = 100;
/// Reasons the contract defines.
const REASONS: [&str; 3] = ["manual", "bounce", "complaint"];

/// `GET /v1/suppressions` — page of suppressed recipients.
pub async fn list_suppressions(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Query(params): Query<Params>,
) -> Response {
    let result = blocking(move || {
        let limit = int_param(&params, "limit", 100, 1, 500)?;
        let offset = int_param(&params, "offset", 0, 0, i64::MAX)?;
        let (rows, total) = state
            .db
            .suppression_page(context.account_id, limit, offset)
            .map_err(Problem::from)?;
        let page = PageMeta::new(total, offset, rows.len() as i64);
        Ok(SuppressionPage {
            items: rows.iter().map(to_view).collect(),
            page,
        })
    })
    .await;
    match result {
        Ok(page) => Json(page).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `POST /v1/suppressions` — suppress up to 100 addresses.
pub async fn add_suppressions(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    ProblemJson(request): ProblemJson<SuppressionCreate>,
) -> Response {
    let result = blocking(move || {
        if request.addresses.is_empty() {
            return Err(validation(vec![FieldError::with_code(
                "addresses",
                "required",
                "at least one address is required",
            )]));
        }
        if request.addresses.len() > MAX_ADDRESSES {
            return Err(validation(vec![FieldError::with_code(
                "addresses",
                "too-many",
                format!(
                    "{} addresses supplied, above the {MAX_ADDRESSES} limit",
                    request.addresses.len()
                ),
            )]));
        }
        let mut errors = Vec::new();
        let mut addresses = Vec::with_capacity(request.addresses.len());
        for (index, raw) in request.addresses.iter().enumerate() {
            match EmailAddress::parse(raw.trim()) {
                Ok(address) => addresses.push(address),
                Err(error) => errors.push(FieldError::with_code(
                    format!("addresses[{index}]"),
                    "invalid",
                    error.to_string(),
                )),
            }
        }
        if !errors.is_empty() {
            return Err(validation(errors));
        }
        let reason = request.reason.as_deref().unwrap_or("manual");
        if !REASONS.contains(&reason) {
            return Err(validation(vec![FieldError::with_code(
                "reason",
                "invalid",
                format!("reason must be one of {}", REASONS.join("|")),
            )]));
        }
        let added = state
            .db
            .insert_suppressions(
                context.account_id,
                &addresses,
                reason,
                Some(&format!("key:{}", context.public_id)),
            )
            .map_err(Problem::from)?;
        if let Err(error) = state.store.audit(
            &format!("key:{}", context.public_id),
            "suppression.add",
            &format!("{added} addresses ({reason})"),
        ) {
            tracing::warn!(%error, "could not write audit row");
        }
        Ok(())
    })
    .await;
    match result {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// `DELETE /v1/suppressions/{address}` — remove one suppression explicitly.
pub async fn remove_suppression(
    State(state): State<AppState>,
    Extension(context): Extension<ApiKeyContext>,
    Path(address): Path<String>,
) -> Response {
    let result = blocking(move || {
        let parsed = EmailAddress::parse(address.trim()).map_err(|error| {
            validation(vec![FieldError::with_code(
                "address",
                "invalid",
                error.to_string(),
            )])
        })?;
        if !state
            .db
            .delete_suppression(context.account_id, &parsed.normalized())
            .map_err(Problem::from)?
        {
            return Err(not_found(format!("{address} is not suppressed")));
        }
        if let Err(error) = state.store.audit(
            &format!("key:{}", context.public_id),
            "suppression.remove",
            &parsed.normalized(),
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

fn to_view(row: &SuppressionRow) -> SuppressionView {
    SuppressionView {
        address: row.address.clone(),
        reason: row.reason.clone(),
        source: row.source.clone(),
        created_at: row.created_at.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_carry_the_reason_and_source() {
        let view = to_view(&SuppressionRow {
            address: "bounced@example.org".to_string(),
            reason: "bounce".to_string(),
            source: Some("eml_00000001".to_string()),
            created_at: "2026-11-06T00:00:00Z".to_string(),
        });
        let json = serde_json::to_string(&view).expect("serialize");
        assert!(json.contains("\"reason\":\"bounce\""));
        assert!(json.contains("eml_00000001"));
    }

    #[test]
    fn reasons_match_the_contract_enum() {
        assert_eq!(REASONS, ["manual", "bounce", "complaint"]);
    }

    #[test]
    fn addresses_are_normalized_for_deduplication() {
        let upper = EmailAddress::parse("Bounced@Example.ORG").expect("address");
        let lower = EmailAddress::parse("bounced@example.org").expect("address");
        assert_eq!(upper.normalized(), lower.normalized());
    }
}
