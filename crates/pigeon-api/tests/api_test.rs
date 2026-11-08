//! End-to-end tests through the real router.
//!
//! Every test drives `pigeon_api::router` with a real `AppState` on a real
//! tempdir database and a real (generated, Argon2id-hashed) API key — nothing is
//! stubbed. That matters here: the middleware chain, the sealed-body path, the
//! problem+json mapping and the SQL all have to agree, and only a full request
//! proves they do.

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use pigeon_api::wkd::KeyFetcher;
use pigeon_api::{ApiConfig, AppState};
use pigeon_core::{ApiKeyScope, Direction, EmailAddress, MessageFolder};
use pigeon_crypto::MasterKey;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use store::{NewMessage, Storage};
use tempfile::TempDir;
use tower::ServiceExt;

/// Master key for the whole suite: tests never inspect it, it only has to seal
/// and open.
const TEST_MASTER_KEY: [u8; 32] = [0x24; 32];
/// Server address used by the DNS-record test.
const TEST_PUBLIC_IP: &str = "203.0.113.10";

struct TestApp {
    // Dropping the tempdir deletes the database the two connections share.
    _dir: TempDir,
    /// Path of the database file, so a test can seed states the API cannot reach
    /// (a message that has been in the trash for 40 days).
    path: PathBuf,
    state: AppState,
    router: Router,
    full_key: String,
    account_id: i64,
}

impl TestApp {
    fn new() -> Self {
        Self::with_config(ApiConfig::default())
    }

    fn with_config(config: ApiConfig) -> Self {
        Self::with_state(config, Arc::new(NoKeys))
    }

    /// Build the app with an explicit key directory.
    ///
    /// Every test injects one: discovery is the only part of the send pipeline
    /// that talks to the network, and a suite that fetched `example.org` would be
    /// slow, flaky and dependent on somebody else's DNS.
    fn with_state(config: ApiConfig, fetcher: Arc<dyn KeyFetcher>) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pigeon.db");
        let state = AppState::open(
            &path,
            MasterKey::parse(&TEST_MASTER_KEY).expect("master key"),
            config,
        )
        .expect("state")
        .with_key_fetcher(fetcher);
        let account = EmailAddress::parse("owner@example.com").expect("address");
        let account_id = state.store.create_account(&account).expect("account");
        let (_, full_key) = pigeon_api::keys::issue(
            &state.store,
            &state.db,
            account_id,
            "full",
            &[ApiKeyScope::Full],
            false,
        )
        .expect("full key");
        let router = pigeon_api::router(state.clone());
        Self {
            _dir: dir,
            path,
            state,
            router,
            full_key,
            account_id,
        }
    }

    /// Issue an extra key with the given scopes.
    fn key_with(&self, scopes: &[ApiKeyScope], sandbox: bool) -> String {
        let (_, key) = pigeon_api::keys::issue(
            &self.state.store,
            &self.state.db,
            self.account_id,
            "scoped",
            scopes,
            sandbox,
        )
        .expect("scoped key");
        key
    }

    async fn call(&self, request: Request<Body>) -> Response {
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("router call");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024)
            .await
            .expect("read body");
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
        };
        Response {
            status,
            headers,
            body,
            raw: bytes.to_vec(),
        }
    }

    async fn get(&self, path: &str, key: Option<&str>) -> Response {
        self.call(build(Method::GET, path, key, None, &[])).await
    }

    async fn post(&self, path: &str, key: Option<&str>, body: Value) -> Response {
        self.call(build(Method::POST, path, key, Some(body), &[]))
            .await
    }

    async fn post_with_header(
        &self,
        path: &str,
        key: Option<&str>,
        body: Value,
        name: &'static str,
        value: &str,
    ) -> Response {
        self.call(build(Method::POST, path, key, Some(body), &[(name, value)]))
            .await
    }

    async fn patch(&self, path: &str, key: Option<&str>, body: Value) -> Response {
        self.call(build(Method::PATCH, path, key, Some(body), &[]))
            .await
    }

    async fn delete(&self, path: &str, key: Option<&str>) -> Response {
        self.call(build(Method::DELETE, path, key, None, &[])).await
    }

    /// Queue one email through the API and return its id.
    async fn send(&self, key: &str, body: Value) -> String {
        let response = self.post("/v1/emails", Some(key), body).await;
        assert_eq!(response.status, StatusCode::ACCEPTED, "{:?}", response.body);
        response.body["id"].as_str().expect("id").to_string()
    }
}

/// A key directory that publishes nothing: the default for tests that are not
/// about sealing.
#[derive(Debug)]
struct NoKeys;

impl KeyFetcher for NoKeys {
    fn fetch(&self, _url: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
}

/// A key directory that generates and serves one certificate per address.
///
/// It keeps the private halves so a test can play the recipient and prove the seal
/// really is only openable by the account key.
#[derive(Debug, Default)]
struct KeyDirectory {
    keys: Mutex<HashMap<String, (String, String)>>,
    /// When set, only these addresses publish a key (everything else 404s, like a
    /// domain that has no WKD entry for the address).
    only: Option<Vec<String>>,
}

impl KeyDirectory {
    /// A directory that publishes keys for exactly `addresses`.
    fn only(addresses: &[&str]) -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
            only: Some(addresses.iter().map(|a| a.to_lowercase()).collect()),
        }
    }

    fn key_for(&self, address: &str) -> (String, String) {
        let address = address.to_lowercase();
        let mut keys = self.keys.lock().expect("lock");
        keys.entry(address.clone())
            .or_insert_with(|| {
                let generated =
                    pigeon_crypto::generate_account_key(&address).expect("generated key");
                (generated.public_armored, generated.private_armored)
            })
            .clone()
    }

    fn private_for(&self, address: &str) -> String {
        self.key_for(address).1
    }
}

impl KeyFetcher for KeyDirectory {
    fn fetch(&self, url: &str) -> Result<Option<Vec<u8>>, String> {
        // Only the simple endpoint answers; the advanced paths are exercised by
        // their own tests.
        let Some((_, query)) = url.split_once("?email=") else {
            return Ok(None);
        };
        let address = query.replace("%40", "@").replace("%2E", ".");
        if let Some(only) = &self.only {
            if !only.contains(&address.to_lowercase()) {
                return Ok(None);
            }
        }
        Ok(Some(self.key_for(&address).0.into_bytes()))
    }
}

/// Pull the armored OpenPGP message out of a stored PGP/MIME body.
fn armored_payload(mime: &str) -> String {
    let start = mime
        .find("-----BEGIN PGP MESSAGE-----")
        .unwrap_or_else(|| panic!("no armored payload in {mime}"));
    let end = mime
        .find("-----END PGP MESSAGE-----")
        .map(|index| index + "-----END PGP MESSAGE-----".len())
        .unwrap_or_else(|| panic!("no armored payload end in {mime}"));
    mime[start..end].replace("\r\n", "\n")
}

struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
    /// Exactly what the handler wrote: `body` is the JSON reading of it, which
    /// cannot represent a binary key.
    raw: Vec<u8>,
}

impl Response {
    fn assert_problem(&self, status: StatusCode, type_: &str) {
        assert_eq!(self.status, status, "{:?}", self.body);
        assert_eq!(self.body["type"], type_, "{:?}", self.body);
        assert_eq!(self.body["status"], status.as_u16(), "{:?}", self.body);
        assert_eq!(
            self.headers[header::CONTENT_TYPE],
            "application/problem+json",
            "every error is a problem document"
        );
        assert!(
            self.body["detail"].as_str().is_some_and(|d| !d.is_empty()),
            "a problem always explains itself: {:?}",
            self.body
        );
    }
}

/// Source address every request reports.
///
/// The WKD endpoints are rate limited per source address, and they read the peer
/// from `ConnectInfo`, which `axum::serve` fills in from the socket. A router
/// driven directly (as here) has no socket, so the harness supplies the same
/// extension the server would.
const TEST_PEER: ([u8; 4], u16) = ([198, 51, 100, 9], 4242);

fn build(
    method: Method,
    path: &str,
    key: Option<&str>,
    body: Option<Value>,
    extra_headers: &[(&str, &str)],
) -> Request<Body> {
    build_from(method, path, key, body, extra_headers, TEST_PEER)
}

fn build_from(
    method: Method,
    path: &str,
    key: Option<&str>,
    body: Option<Value>,
    extra_headers: &[(&str, &str)],
    peer: ([u8; 4], u16),
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(key) = key {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {key}"));
    }
    for (name, value) in extra_headers {
        builder = builder.header(*name, *value);
    }
    let mut request = match body {
        Some(value) => builder
            .body(Body::from(value.to_string()))
            .expect("request"),
        None => builder.body(Body::empty()).expect("request"),
    };
    request
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from(peer)));
    request
}

fn valid_send() -> Value {
    json!({
        // The caller's own address: `from` is checked against the account and its
        // sender aliases (see `send_from_an_unassigned_alias_is_refused`).
        "from": "Dana <owner@example.com>",
        "to": ["carol@example.org"],
        "cc": ["dave@example.net"],
        "bcc": ["secret@example.org"],
        "subject": "Invoice #2041 paid",
        "text": "Thanks! Your renewal was processed.",
        "tags": ["billing"],
    })
}

// ---------------------------------------------------------------------------
// Send and lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_emails_queues_and_returns_a_lifecycle_view() {
    let app = TestApp::new();
    let response = app
        .post("/v1/emails", Some(&app.full_key), valid_send())
        .await;

    assert_eq!(response.status, StatusCode::ACCEPTED);
    let id = response.body["id"].as_str().expect("id").to_string();
    assert!(id.starts_with("eml_"), "{id}");
    assert_eq!(response.body["status"], "queued");
    assert_eq!(
        response.body["e2e"], "tls_only",
        "no recipient publishes a key in this app: transport TLS only, never a false `sealed`"
    );
    // Rate-limit headers ride on (successful) authenticated responses.
    assert_eq!(response.headers["x-ratelimit-limit"], "10");
    assert!(response.headers.contains_key("x-ratelimit-remaining"));
    assert!(response.headers.contains_key("x-ratelimit-reset"));

    let view = app
        .get(&format!("/v1/emails/{id}"), Some(&app.full_key))
        .await;
    assert_eq!(view.status, StatusCode::OK);
    assert_eq!(view.body["id"], id.as_str());
    assert_eq!(view.body["status"], "queued");
    assert_eq!(view.body["subject"], "Invoice #2041 paid");
    assert_eq!(view.body["from"], "owner@example.com");
    assert_eq!(view.body["to"][0], "carol@example.org");
    assert_eq!(view.body["tags"][0], "billing");
    assert_eq!(view.body["sandbox"], false);
    assert!(
        !view.body.to_string().contains("secret@example.org"),
        "bcc must never be echoed: {}",
        view.body
    );
}

#[tokio::test]
async fn scheduled_sends_report_scheduled_status() {
    let app = TestApp::new();
    let mut body = valid_send();
    body["scheduled_at"] = json!("2030-01-01T00:00:00Z");
    let response = app.post("/v1/emails", Some(&app.full_key), body).await;
    assert_eq!(response.status, StatusCode::ACCEPTED, "{:?}", response.body);
    assert_eq!(response.body["status"], "scheduled");

    let id = response.body["id"].as_str().expect("id");
    let view = app
        .get(&format!("/v1/emails/{id}"), Some(&app.full_key))
        .await;
    assert_eq!(view.body["status"], "scheduled");
}

#[tokio::test]
async fn the_daily_quota_is_a_402_problem() {
    let app = TestApp::with_config(ApiConfig {
        daily_send_quota: 1,
        ..ApiConfig::default()
    });
    app.send(&app.full_key, valid_send()).await;

    let refused = app
        .post("/v1/emails", Some(&app.full_key), valid_send())
        .await;
    refused.assert_problem(StatusCode::PAYMENT_REQUIRED, "quota-exceeded");
    assert_eq!(refused.body["quota"]["limit"], 1);
    assert_eq!(refused.body["quota"]["used"], 1);
    assert!(refused.body["quota"]["reset_at"]
        .as_str()
        .expect("reset_at")
        .ends_with('Z'));
}

#[tokio::test]
async fn a_body_without_from_is_a_validation_problem_with_field_errors() {
    let app = TestApp::new();
    let response = app
        .post(
            "/v1/emails",
            Some(&app.full_key),
            json!({"to": ["carol@example.org"], "subject": "hi", "text": "x"}),
        )
        .await;

    response.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");
    let errors = response.body["errors"].as_array().expect("errors array");
    assert!(!errors.is_empty());
    assert_eq!(errors[0]["field"], "from");
    assert!(errors[0]["message"].as_str().is_some());
}

#[tokio::test]
async fn unknown_request_fields_are_rejected_not_ignored() {
    let app = TestApp::new();
    let mut body = valid_send();
    body["subjct"] = json!("typo");
    let response = app.post("/v1/emails", Some(&app.full_key), body).await;
    response.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");
    assert_eq!(response.body["errors"][0]["field"], "subjct");
}

#[tokio::test]
async fn a_replayed_idempotency_key_returns_the_original_id() {
    let app = TestApp::new();
    let mut body = valid_send();
    body["idempotency_key"] = json!("invoice-2041-paid-v1");

    let first = app
        .post("/v1/emails", Some(&app.full_key), body.clone())
        .await;
    assert_eq!(first.status, StatusCode::ACCEPTED);
    let original = first.body["id"].as_str().expect("id").to_string();

    let second = app.post("/v1/emails", Some(&app.full_key), body).await;
    second.assert_problem(StatusCode::CONFLICT, "idempotent-replay");
    assert_eq!(second.body["id"], original.as_str());

    // The header form of the same key deduplicates too.
    let header_key_replay = app
        .post_with_header(
            "/v1/emails",
            Some(&app.full_key),
            valid_send(),
            "Idempotency-Key",
            "invoice-2041-paid-v1",
        )
        .await;
    header_key_replay.assert_problem(StatusCode::CONFLICT, "idempotent-replay");
    assert_eq!(header_key_replay.body["id"], original.as_str());
}

#[tokio::test]
async fn batch_send_reports_every_item_and_never_blocks_the_rest() {
    let app = TestApp::new();
    let response = app
        .post(
            "/v1/emails/batch",
            Some(&app.full_key),
            json!({
                "items": [
                    valid_send(),
                    {"to": ["nobody@example.org"], "subject": "no from", "text": "x"}
                ]
            }),
        )
        .await;

    assert_eq!(response.status, StatusCode::ACCEPTED, "{:?}", response.body);
    let results = response.body["results"].as_array().expect("results");
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["index"], 0);
    assert!(results[0]["id"].as_str().expect("id").starts_with("eml_"));
    assert_eq!(results[0]["status"], "queued");
    assert_eq!(results[1]["index"], 1);
    assert_eq!(results[1]["error"]["type"], "validation");
    assert!(results[1]["id"].is_null());
}

#[tokio::test]
async fn list_emails_pages_with_metadata() {
    let app = TestApp::new();
    for _ in 0..3 {
        app.send(&app.full_key, valid_send()).await;
    }

    let first = app.get("/v1/emails?limit=2", Some(&app.full_key)).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.body["items"].as_array().expect("items").len(), 2);
    assert_eq!(first.body["page"]["total"], 3);
    assert_eq!(first.body["page"]["has_more"], true);
    assert_eq!(first.body["page"]["next_offset"], 2);

    let second = app
        .get("/v1/emails?limit=2&offset=2", Some(&app.full_key))
        .await;
    assert_eq!(second.body["items"].as_array().expect("items").len(), 1);
    assert_eq!(second.body["page"]["has_more"], false);
    assert!(second.body["page"]["next_offset"].is_null());

    // Filters are applied server-side.
    let filtered = app.get("/v1/emails?status=sent", Some(&app.full_key)).await;
    assert_eq!(filtered.body["page"]["total"], 0);
    let tagged = app.get("/v1/emails?tag=billing", Some(&app.full_key)).await;
    assert_eq!(tagged.body["page"]["total"], 3);

    let bad = app.get("/v1/emails?limit=1000", Some(&app.full_key)).await;
    bad.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");
}

#[tokio::test]
async fn cancel_is_202_while_queued_and_409_once_sent() {
    let app = TestApp::new();
    let queued = app.send(&app.full_key, valid_send()).await;
    let cancelled = app
        .delete(&format!("/v1/emails/{queued}"), Some(&app.full_key))
        .await;
    assert_eq!(cancelled.status, StatusCode::ACCEPTED);
    let view = app
        .get(&format!("/v1/emails/{queued}"), Some(&app.full_key))
        .await;
    assert_eq!(view.body["status"], "cancelled");

    // A delivered email cannot be recalled: the worker already sent it.
    let sent = app.send(&app.full_key, valid_send()).await;
    app.state
        .db
        .set_email_status(app.account_id, &sent, "sent")
        .expect("mark sent");
    let refused = app
        .delete(&format!("/v1/emails/{sent}"), Some(&app.full_key))
        .await;
    refused.assert_problem(StatusCode::CONFLICT, "not-cancellable");
}

#[tokio::test]
async fn raw_mime_is_sandbox_only() {
    let app = TestApp::new();
    let sandbox_key = app.key_with(&[ApiKeyScope::Full], true);
    let sandbox_id = app.send(&sandbox_key, valid_send()).await;

    let raw = app
        .get(
            &format!("/v1/emails/{sandbox_id}?raw=true"),
            Some(&sandbox_key),
        )
        .await;
    assert_eq!(raw.status, StatusCode::OK, "{:?}", raw.body);
    let mime = raw.body["mime"].as_str().expect("mime");
    assert!(mime.contains("Subject: Invoice #2041 paid"));
    assert!(mime.contains("MIME-Version: 1.0"));
    assert!(
        !mime.contains("secret@example.org"),
        "bcc never reaches the generated MIME"
    );
    assert_eq!(raw.body["id"], sandbox_id.as_str());

    // A real (non-sandbox) message has no raw view.
    let real_id = app.send(&app.full_key, valid_send()).await;
    let refused = app
        .get(
            &format!("/v1/emails/{real_id}?raw=true"),
            Some(&app.full_key),
        )
        .await;
    refused.assert_problem(StatusCode::FORBIDDEN, "forbidden");
}

// ---------------------------------------------------------------------------
// Authentication and scopes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_missing_key_is_401_and_a_wrong_scope_is_403() {
    let app = TestApp::new();

    let anonymous = app.get("/v1/emails", None).await;
    anonymous.assert_problem(StatusCode::UNAUTHORIZED, "unauthorized");

    let malformed = app.get("/v1/emails", Some("pk_not-a-key")).await;
    malformed.assert_problem(StatusCode::UNAUTHORIZED, "unauthorized");

    // `send` may queue but not read.
    let send_only = app.key_with(&[ApiKeyScope::Send], false);
    let accepted = app.post("/v1/emails", Some(&send_only), valid_send()).await;
    assert_eq!(accepted.status, StatusCode::ACCEPTED);
    let wrong = app.get("/v1/emails", Some(&send_only)).await;
    wrong.assert_problem(StatusCode::FORBIDDEN, "forbidden");

    // `read` may read but not queue, and may not see admin surfaces.
    let read_only = app.key_with(&[ApiKeyScope::Read], false);
    let refused = app.post("/v1/emails", Some(&read_only), valid_send()).await;
    refused.assert_problem(StatusCode::FORBIDDEN, "forbidden");
    let admin = app.get("/v1/account/keys", Some(&read_only)).await;
    admin.assert_problem(StatusCode::FORBIDDEN, "forbidden");
    assert_eq!(
        app.get("/v1/emails", Some(&read_only)).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_revoked_key_stops_working_immediately() {
    let app = TestApp::new();
    let scoped = app.key_with(&[ApiKeyScope::Read], false);
    assert_eq!(
        app.get("/v1/emails", Some(&scoped)).await.status,
        StatusCode::OK
    );

    let listed = app.get("/v1/account/keys", Some(&app.full_key)).await;
    let keys = listed.body.as_array().expect("keys");
    assert_eq!(keys.len(), 2);
    let revoke_id = keys
        .iter()
        .find(|key| key["name"] == "scoped")
        .expect("scoped key")["id"]
        .as_str()
        .expect("id")
        .to_string();

    let patched = app
        .patch(
            &format!("/v1/account/keys/{revoke_id}"),
            Some(&app.full_key),
            json!({"revoked": true}),
        )
        .await;
    assert_eq!(patched.status, StatusCode::OK);
    assert_eq!(patched.body["revoked"], true);

    let refused = app.get("/v1/emails", Some(&scoped)).await;
    refused.assert_problem(StatusCode::UNAUTHORIZED, "unauthorized");
}

#[tokio::test]
async fn the_rate_limiter_answers_429_with_retry_after() {
    let app = TestApp::with_config(ApiConfig {
        rate_limit_rps: 1,
        rate_limit_burst: 1,
        ..ApiConfig::default()
    });
    let first = app.get("/v1/emails", Some(&app.full_key)).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.headers["x-ratelimit-remaining"], "0");

    let second = app.get("/v1/emails", Some(&app.full_key)).await;
    second.assert_problem(StatusCode::TOO_MANY_REQUESTS, "rate-limited");
    assert!(second.headers.contains_key(header::RETRY_AFTER));
}

// ---------------------------------------------------------------------------
// Account keys
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_keys_are_shown_once_and_listed_without_material() {
    let app = TestApp::new();
    let created = app
        .post(
            "/v1/account/keys",
            Some(&app.full_key),
            json!({"name": "ci", "scopes": ["send", "read"]}),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let id = created.body["id"].as_str().expect("id").to_string();
    let key = created.body["key"].as_str().expect("key").to_string();
    assert!(id.starts_with("key_"), "{id}");
    assert!(key.starts_with("pk_"), "{key}");
    assert_eq!(key.len(), 46);

    // The new key works and carries exactly the requested scopes.
    assert_eq!(
        app.get("/v1/emails", Some(&key)).await.status,
        StatusCode::OK
    );

    let listed = app.get("/v1/account/keys", Some(&app.full_key)).await;
    assert_eq!(listed.status, StatusCode::OK);
    let text = listed.body.to_string();
    assert!(!text.contains(&key), "listing must not echo key material");
    assert!(
        !text.contains("pk_"),
        "no key material in any listing: {text}"
    );
    let entry = listed
        .body
        .as_array()
        .expect("array")
        .iter()
        .find(|entry| entry["id"] == id.as_str())
        .expect("created key is listed");
    assert_eq!(entry["name"], "ci");
    assert_eq!(entry["scopes"], json!(["send", "read"]));
    assert_eq!(entry["revoked"], false);
    assert!(entry["last_used_at"].as_str().is_some(), "use was recorded");

    let deleted = app
        .delete(&format!("/v1/account/keys/{id}"), Some(&app.full_key))
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    let gone = app
        .delete(&format!("/v1/account/keys/{id}"), Some(&app.full_key))
        .await;
    gone.assert_problem(StatusCode::NOT_FOUND, "not-found");
}

// ---------------------------------------------------------------------------
// Templates, domains, webhooks, suppressions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn templates_create_render_and_refuse_duplicate_names() {
    let app = TestApp::new();
    let body = json!({
        "name": "welcome",
        "subject": "Welcome {{name}}",
        "html": "<p>Hi {{name}}</p>",
        "text": "Hi {{name}}",
    });
    let created = app
        .post("/v1/templates", Some(&app.full_key), body.clone())
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    assert!(created.body["id"].as_str().expect("id").starts_with("tpl_"));
    assert_eq!(created.body["name"], "welcome");

    let duplicate = app.post("/v1/templates", Some(&app.full_key), body).await;
    duplicate.assert_problem(StatusCode::CONFLICT, "conflict");

    let id = created.body["id"].as_str().expect("id").to_string();
    let fetched = app
        .get(&format!("/v1/templates/{id}"), Some(&app.full_key))
        .await;
    assert_eq!(fetched.status, StatusCode::OK);
    assert_eq!(fetched.body["subject"], "Welcome {{name}}");

    let test_send = app
        .post(
            &format!("/v1/templates/{id}/test-send"),
            Some(&app.full_key),
            json!({"to": ["carol@example.org"], "variables": {"name": "Carol"}}),
        )
        .await;
    assert_eq!(
        test_send.status,
        StatusCode::ACCEPTED,
        "{:?}",
        test_send.body
    );
    let email_id = test_send.body["id"].as_str().expect("id").to_string();
    let view = app
        .get(&format!("/v1/emails/{email_id}"), Some(&app.full_key))
        .await;
    assert_eq!(view.body["subject"], "Welcome Carol");

    let updated = app
        .patch(
            &format!("/v1/templates/{id}"),
            Some(&app.full_key),
            json!({"subject": "Hello {{name}}"}),
        )
        .await;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.body["subject"], "Hello {{name}}");

    let deleted = app
        .delete(&format!("/v1/templates/{id}"), Some(&app.full_key))
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    let gone = app
        .get(&format!("/v1/templates/{id}"), Some(&app.full_key))
        .await;
    gone.assert_problem(StatusCode::NOT_FOUND, "not-found");
}

#[tokio::test]
async fn templates_carry_a_description_and_have_no_cap() {
    let app = TestApp::new();
    // Twelve is above any plausible implicit cap: creation is unlimited.
    for index in 0..12 {
        let created = app
            .post(
                "/v1/templates",
                Some(&app.full_key),
                json!({
                    "name": format!("invoice-{index}"),
                    "description": format!("Template number {index}"),
                    "subject": format!("Invoice {index}"),
                    "text": "Hi there",
                }),
            )
            .await;
        assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
        assert_eq!(
            created.body["description"],
            format!("Template number {index}")
        );
    }

    let listed = app.get("/v1/templates", Some(&app.full_key)).await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
    let templates = listed.body.as_array().expect("array");
    assert_eq!(
        templates.len(),
        12,
        "creating templates must never hit a cap"
    );
    assert!(
        templates
            .iter()
            .all(|template| template["description"].is_string()),
        "every listed template carries its description: {:?}",
        templates
    );

    let id = templates[0]["id"].as_str().expect("id").to_string();
    let patched = app
        .patch(
            &format!("/v1/templates/{id}"),
            Some(&app.full_key),
            json!({"description": "Rewritten"}),
        )
        .await;
    assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.body);
    assert_eq!(patched.body["description"], "Rewritten");

    let fetched = app
        .get(&format!("/v1/templates/{id}"), Some(&app.full_key))
        .await;
    assert_eq!(fetched.body["description"], "Rewritten");
    assert_eq!(fetched.body["name"], "invoice-11");
}

// ---------------------------------------------------------------------------
// Drafts
// ---------------------------------------------------------------------------

fn draft_body() -> Value {
    json!({
        "from": "Dana <owner@example.com>",
        "to": ["carol@example.org"],
        "cc": ["dave@example.net"],
        "bcc": ["secret@example.org"],
        "subject": "Half written",
        "html": "<p>still writing</p>",
        "text": "still writing",
        "attachments": [{"filename": "notes.txt", "content": "aGVsbG8="}],
        "tags": ["billing"],
    })
}

#[tokio::test]
async fn drafts_save_continue_and_delete() {
    let app = TestApp::new();

    let created = app
        .post("/v1/drafts", Some(&app.full_key), draft_body())
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let draft_id = created.body["id"].as_str().expect("id").to_string();
    assert!(draft_id.starts_with("drf_"), "{draft_id}");

    let listed = app.get("/v1/drafts", Some(&app.full_key)).await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
    let items = listed.body["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "{:?}", listed.body);
    assert_eq!(items[0]["id"], draft_id.as_str());
    assert_eq!(items[0]["subject"], "Half written");
    assert_eq!(items[0]["to"][0], "carol@example.org");
    assert_eq!(listed.body["page"]["total"], 1);

    let patched = app
        .patch(
            &format!("/v1/drafts/{draft_id}"),
            Some(&app.full_key),
            json!({"subject": "Renamed", "to": ["erin@example.org"]}),
        )
        .await;
    assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.body);
    assert_eq!(patched.body["subject"], "Renamed");
    assert_eq!(patched.body["to"][0], "erin@example.org");
    assert_eq!(
        patched.body["cc"][0], "dave@example.net",
        "untouched fields stay"
    );
    assert!(patched.body["updated_at"].as_str().is_some());

    let fetched = app
        .get(&format!("/v1/drafts/{draft_id}"), Some(&app.full_key))
        .await;
    assert_eq!(fetched.status, StatusCode::OK, "{:?}", fetched.body);
    assert_eq!(fetched.body["html"], "<p>still writing</p>");
    assert_eq!(fetched.body["attachments"][0]["filename"], "notes.txt");

    // Continue the draft: it goes through the real send path and leaves `drafts`.
    let sent = app
        .post(
            &format!("/v1/drafts/{draft_id}/send"),
            Some(&app.full_key),
            json!({}),
        )
        .await;
    assert_eq!(sent.status, StatusCode::ACCEPTED, "{:?}", sent.body);
    let email_id = sent.body["id"].as_str().expect("email id").to_string();
    assert!(email_id.starts_with("eml_"), "{email_id}");
    let view = app
        .get(&format!("/v1/emails/{email_id}"), Some(&app.full_key))
        .await;
    assert_eq!(view.body["subject"], "Renamed");
    assert_eq!(view.body["to"][0], "erin@example.org");
    assert_eq!(view.body["tags"][0], "billing");

    let gone = app
        .get(&format!("/v1/drafts/{draft_id}"), Some(&app.full_key))
        .await;
    gone.assert_problem(StatusCode::NOT_FOUND, "not-found");
    let empty = app.get("/v1/drafts", Some(&app.full_key)).await;
    assert_eq!(empty.body["page"]["total"], 0);

    // A second draft can be deleted outright.
    let another = app
        .post("/v1/drafts", Some(&app.full_key), draft_body())
        .await;
    let another_id = another.body["id"].as_str().expect("id").to_string();
    let deleted = app
        .delete(&format!("/v1/drafts/{another_id}"), Some(&app.full_key))
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{:?}", deleted.body);
    let deleted_again = app
        .delete(&format!("/v1/drafts/{another_id}"), Some(&app.full_key))
        .await;
    deleted_again.assert_problem(StatusCode::NOT_FOUND, "not-found");
}

#[tokio::test]
async fn drafts_validate_fields_and_respect_scopes() {
    let app = TestApp::new();
    let read_key = app.key_with(&[ApiKeyScope::Read], false);
    let send_key = app.key_with(&[ApiKeyScope::Send], false);

    let bad_address = app
        .post(
            "/v1/drafts",
            Some(&app.full_key),
            json!({"to": ["not-an-address"]}),
        )
        .await;
    assert_eq!(
        bad_address.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{:?}",
        bad_address.body
    );
    assert_eq!(bad_address.body["errors"][0]["field"], "to[0]");

    let unknown_field = app
        .post(
            "/v1/drafts",
            Some(&app.full_key),
            json!({"subject": "x", "body": "typo"}),
        )
        .await;
    unknown_field.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");

    let read_only_write = app
        .post("/v1/drafts", Some(&read_key), json!({"subject": "x"}))
        .await;
    read_only_write.assert_problem(StatusCode::FORBIDDEN, "forbidden");

    // `send` writes but does not list: listing is the `read` tier.
    let created = app
        .post("/v1/drafts", Some(&send_key), json!({"subject": "scoped"}))
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let refused = app.get("/v1/drafts", Some(&send_key)).await;
    refused.assert_problem(StatusCode::FORBIDDEN, "forbidden");
    let listed = app.get("/v1/drafts", Some(&read_key)).await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
    assert_eq!(listed.body["page"]["total"], 1);

    let missing = app
        .get("/v1/drafts/drf_0000000000000000", Some(&app.full_key))
        .await;
    missing.assert_problem(StatusCode::NOT_FOUND, "not-found");
}

#[tokio::test]
async fn domains_expose_the_records_to_publish() {
    let app = TestApp::with_config(ApiConfig {
        public_ip: Some(TEST_PUBLIC_IP.to_string()),
        ..ApiConfig::default()
    });

    let listed = app.get("/v1/domains", Some(&app.full_key)).await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
    let domains = listed.body.as_array().expect("array");
    assert_eq!(domains.len(), 1, "the account domain is seeded");
    assert_eq!(domains[0]["name"], "example.com");
    assert_eq!(domains[0]["verified"], false);

    let added = app
        .post(
            "/v1/domains",
            Some(&app.full_key),
            json!({"name": "pigeonmail.dev"}),
        )
        .await;
    assert_eq!(added.status, StatusCode::CREATED, "{:?}", added.body);
    let id = added.body["id"].as_str().expect("id").to_string();

    let dns = app
        .get(&format!("/v1/domains/{id}/dns"), Some(&app.full_key))
        .await;
    assert_eq!(dns.status, StatusCode::OK, "{:?}", dns.body);
    let records = dns.body.as_array().expect("records");
    assert_eq!(records.len(), 5);
    assert_eq!(records[0]["type"], "A");
    assert_eq!(records[0]["value"], TEST_PUBLIC_IP);
    assert_eq!(records[1]["type"], "MX");
    assert_eq!(records[1]["priority"], 10);
    assert_eq!(records[2]["value"], "v=spf1 a mx -all");
    assert!(records[3]["value"]
        .as_str()
        .expect("dkim")
        .starts_with("v=DKIM1; k=rsa; p="));
    // The DKIM record is published under the selector, and its p= is the RSA
    // public key the worker signs with — not a placeholder.
    assert_eq!(records[3]["host"], "pigeon._domainkey.pigeonmail.dev");
    assert!(records[4]["value"]
        .as_str()
        .expect("dmarc")
        .starts_with("v=DMARC1;"));
    // The domain object itself stays small: records live on the sub-resource.
    assert!(added.body.get("dns_records").is_none());

    let verified = app
        .get(&format!("/v1/domains/{id}?verify=now"), Some(&app.full_key))
        .await;
    assert_eq!(verified.status, StatusCode::OK);
    assert_eq!(verified.body["verified"], false, "DNS checks land in v0.2");
}

/// The DKIM record served by `/dns` must be a real RSA key (not a placeholder),
/// and asking twice must return the *same* record: key generation happens once
/// per domain, so a second read cannot rotate a key operators already published.
#[tokio::test]
async fn the_dkim_record_is_a_real_rsa_key_and_stable_across_calls() {
    let app = TestApp::with_config(ApiConfig {
        public_ip: Some(TEST_PUBLIC_IP.to_string()),
        ..ApiConfig::default()
    });
    let added = app
        .post(
            "/v1/domains",
            Some(&app.full_key),
            json!({ "name": "stable.example" }),
        )
        .await;
    assert_eq!(added.status, StatusCode::CREATED, "{:?}", added.body);
    let id = added.body["id"].as_str().expect("id").to_string();

    let first = app
        .get(&format!("/v1/domains/{id}/dns"), Some(&app.full_key))
        .await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    let dkim = first.body.as_array().expect("records")[3].clone();
    assert_eq!(dkim["host"], "pigeon._domainkey.stable.example");
    let value = dkim["value"].as_str().expect("dkim value");

    let encoded = value
        .strip_prefix("v=DKIM1; k=rsa; p=")
        .expect("an RSA DKIM record");
    let der = STANDARD.decode(encoded).expect("p= is base64");
    // A 2048-bit RSA SubjectPublicKeyInfo is 294 bytes; anything much shorter is
    // a placeholder rather than a key that can sign.
    assert!(
        der.len() >= 290,
        "a 2048-bit RSA SPKI is ~294 bytes, got {}",
        der.len()
    );
    assert_eq!(der[0], 0x30, "SPKI DER starts with a SEQUENCE");

    let second = app
        .get(&format!("/v1/domains/{id}/dns"), Some(&app.full_key))
        .await;
    assert_eq!(
        second.body.as_array().expect("records")[3],
        dkim,
        "a second read must not rotate the published key"
    );
}

#[tokio::test]
async fn dns_records_are_refused_when_the_public_ip_is_unknown() {
    let app = TestApp::new();
    let listed = app.get("/v1/domains", Some(&app.full_key)).await;
    let id = listed.body[0]["id"].as_str().expect("id").to_string();
    let dns = app
        .get(&format!("/v1/domains/{id}/dns"), Some(&app.full_key))
        .await;
    dns.assert_problem(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
}

#[tokio::test]
async fn webhooks_show_the_secret_once() {
    let app = TestApp::new();
    let created = app
        .post(
            "/v1/webhooks",
            Some(&app.full_key),
            json!({"url": "https://example.com/hook", "events": ["email.sent", "email.bounced"]}),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let id = created.body["id"].as_str().expect("id").to_string();
    let secret = created.body["secret"].as_str().expect("secret").to_string();
    assert!(secret.starts_with("whsec_"), "{secret}");
    assert_eq!(secret.len(), 6 + 43);

    let listed = app.get("/v1/webhooks", Some(&app.full_key)).await;
    let text = listed.body.to_string();
    assert!(!text.contains(&secret), "list must not leak the secret");
    assert!(!text.contains("whsec_"), "{text}");
    assert_eq!(listed.body[0]["id"], id.as_str());

    let fetched = app
        .get(&format!("/v1/webhooks/{id}"), Some(&app.full_key))
        .await;
    assert_eq!(fetched.status, StatusCode::OK);
    assert!(fetched.body.get("secret").is_none());

    let deleted = app
        .delete(&format!("/v1/webhooks/{id}"), Some(&app.full_key))
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    let gone = app
        .get(&format!("/v1/webhooks/{id}"), Some(&app.full_key))
        .await;
    gone.assert_problem(StatusCode::NOT_FOUND, "not-found");
}

#[tokio::test]
async fn suppressions_page_add_and_remove() {
    let app = TestApp::new();
    let added = app
        .post(
            "/v1/suppressions",
            Some(&app.full_key),
            json!({"addresses": ["Bad@Example.org", "bad@example.org"], "reason": "manual"}),
        )
        .await;
    assert_eq!(added.status, StatusCode::CREATED, "{:?}", added.body);

    let page = app.get("/v1/suppressions", Some(&app.full_key)).await;
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(
        page.body["page"]["total"], 1,
        "case variants are one mailbox"
    );
    assert_eq!(page.body["items"][0]["address"], "Bad@example.org");
    assert_eq!(page.body["items"][0]["reason"], "manual");

    let removed = app
        .delete("/v1/suppressions/bad@example.org", Some(&app.full_key))
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let missing = app
        .delete("/v1/suppressions/bad@example.org", Some(&app.full_key))
        .await;
    missing.assert_problem(StatusCode::NOT_FOUND, "not-found");
}

// ---------------------------------------------------------------------------
// Receive surface and probes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn empty_inbox_pages_and_decryption_requires_the_full_scope() {
    let app = TestApp::new();
    let page = app
        .get("/v1/messages?folder=inbox", Some(&app.full_key))
        .await;
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(page.body["items"].as_array().expect("items").len(), 0);
    assert_eq!(page.body["page"]["total"], 0);
    assert_eq!(page.body["page"]["has_more"], false);

    let invalid = app
        .get("/v1/messages?folder=archive", Some(&app.full_key))
        .await;
    invalid.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");

    let read_only = app.key_with(&[ApiKeyScope::Read], false);
    let refused = app
        .get("/v1/messages/msg_00000001?sealed=false", Some(&read_only))
        .await;
    refused.assert_problem(StatusCode::FORBIDDEN, "forbidden");
}

#[tokio::test]
async fn mailbox_folders_read_state_and_trash_purge() {
    let app = TestApp::new();
    let read_key = app.key_with(&[ApiKeyScope::Read], false);

    // Accept a message through the send surface; the row lands in `inbox` (the
    // column default), which is what the listing below must show.
    let email_id = app.send(&app.full_key, valid_send()).await;

    let inbox = app
        .get("/v1/messages?folder=inbox", Some(&app.full_key))
        .await;
    assert_eq!(inbox.status, StatusCode::OK, "{:?}", inbox.body);
    let items = inbox.body["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "{:?}", inbox.body);
    let message_id = items[0]["id"].as_str().expect("id").to_string();
    assert!(
        message_id.starts_with("msg_"),
        "the mailbox surface speaks msg_ ids, got {message_id}"
    );
    assert_eq!(items[0]["from_addr"], "owner@example.com");
    assert_eq!(items[0]["folder"], "inbox");
    assert_eq!(items[0]["read"], false, "a new message is unread");
    assert_eq!(inbox.body["page"]["total"], 1);
    assert_eq!(inbox.body["counts"]["inbox"], 1, "{:?}", inbox.body);
    assert_eq!(inbox.body["counts"]["sent"], 0);
    assert_eq!(inbox.body["counts"]["spam"], 0);
    assert_eq!(inbox.body["counts"]["trash"], 0);

    // No `folder` at all means inbox.
    let defaulted = app.get("/v1/messages", Some(&app.full_key)).await;
    assert_eq!(defaulted.status, StatusCode::OK);
    assert_eq!(defaulted.body["items"][0]["id"], message_id.as_str());

    // Moving and deleting is a write: a read-only key is refused.
    let refused = app
        .patch(
            &format!("/v1/messages/{message_id}"),
            Some(&read_key),
            json!({ "read": true }),
        )
        .await;
    refused.assert_problem(StatusCode::FORBIDDEN, "forbidden");

    // Read state round-trips through the API and back into the listing.
    let patched = app
        .patch(
            &format!("/v1/messages/{message_id}"),
            Some(&app.full_key),
            json!({ "read": true }),
        )
        .await;
    assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.body);
    assert_eq!(patched.body["id"], message_id.as_str());
    assert_eq!(patched.body["read"], true);
    assert_eq!(patched.body["folder"], "inbox");
    let inbox = app
        .get("/v1/messages?folder=inbox", Some(&app.full_key))
        .await;
    assert_eq!(inbox.body["items"][0]["read"], true);

    // Move to spam: the inbox empties, the spam folder lists it, counts follow.
    let moved = app
        .patch(
            &format!("/v1/messages/{message_id}"),
            Some(&app.full_key),
            json!({ "folder": "spam" }),
        )
        .await;
    assert_eq!(moved.status, StatusCode::OK, "{:?}", moved.body);
    assert_eq!(moved.body["folder"], "spam");
    assert_eq!(moved.body["read"], true, "a move must not clear read state");
    let spam = app
        .get("/v1/messages?folder=spam", Some(&app.full_key))
        .await;
    assert_eq!(spam.status, StatusCode::OK);
    assert_eq!(spam.body["items"][0]["id"], message_id.as_str());
    assert_eq!(spam.body["counts"]["spam"], 1);
    assert_eq!(spam.body["counts"]["inbox"], 0, "{:?}", spam.body);
    let inbox = app
        .get("/v1/messages?folder=inbox", Some(&app.full_key))
        .await;
    assert_eq!(inbox.body["items"].as_array().expect("items").len(), 0);

    // Bad folder values and empty patches are validation problems, unknown ids
    // are 404s — never a silent no-op.
    for body in [json!({ "folder": "archive" }), json!({})] {
        let invalid = app
            .patch(
                &format!("/v1/messages/{message_id}"),
                Some(&app.full_key),
                body,
            )
            .await;
        invalid.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");
    }
    let unknown = app
        .patch(
            "/v1/messages/msg_00ffffff",
            Some(&app.full_key),
            json!({ "read": true }),
        )
        .await;
    unknown.assert_problem(StatusCode::NOT_FOUND, "not-found");

    // Delete is permanent: the row, its public id and its listing all go.
    let deleted = app
        .delete(&format!("/v1/messages/{message_id}"), Some(&app.full_key))
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{:?}", deleted.body);
    assert!(
        deleted.body.is_null(),
        "204 carries no body: {:?}",
        deleted.body
    );
    let gone = app
        .get(&format!("/v1/messages/{message_id}"), Some(&app.full_key))
        .await;
    gone.assert_problem(StatusCode::NOT_FOUND, "not-found");
    let spam = app
        .get("/v1/messages?folder=spam", Some(&app.full_key))
        .await;
    assert_eq!(spam.body["counts"]["spam"], 0);
    assert!(spam.body["items"].as_array().expect("items").is_empty());
    // The lifecycle row went with it: the send-side id no longer resolves.
    assert!(app
        .state
        .db
        .email_by_public_id(app.account_id, &email_id)
        .expect("lookup")
        .is_none());
    let twice = app
        .delete(&format!("/v1/messages/{message_id}"), Some(&app.full_key))
        .await;
    twice.assert_problem(StatusCode::NOT_FOUND, "not-found");

    // Empty-trash purges exactly the caller's trash and reports how many rows
    // it removed; other folders survive.
    let first = app.send(&app.full_key, valid_send()).await;
    let second = app.send(&app.full_key, valid_send()).await;
    assert_ne!(first, second);
    let trashed = app
        .get("/v1/messages?folder=inbox", Some(&app.full_key))
        .await;
    let trashed_ids: Vec<String> = trashed.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["id"].as_str().expect("id").to_string())
        .collect();
    assert_eq!(trashed_ids.len(), 2, "{:?}", trashed.body);
    for id in &trashed_ids {
        let moved = app
            .patch(
                &format!("/v1/messages/{id}"),
                Some(&app.full_key),
                json!({ "folder": "trash" }),
            )
            .await;
        assert_eq!(moved.status, StatusCode::OK, "{:?}", moved.body);
    }
    let trash = app
        .get("/v1/messages?folder=trash", Some(&app.full_key))
        .await;
    assert_eq!(trash.body["items"].as_array().expect("items").len(), 2);
    assert_eq!(trash.body["counts"]["trash"], 2);

    let emptied = app
        .post("/v1/messages/empty-trash", Some(&app.full_key), json!({}))
        .await;
    assert_eq!(emptied.status, StatusCode::OK, "{:?}", emptied.body);
    assert_eq!(emptied.body["deleted"], 2, "{:?}", emptied.body);
    let trash = app
        .get("/v1/messages?folder=trash", Some(&app.full_key))
        .await;
    assert!(trash.body["items"].as_array().expect("items").is_empty());
    assert_eq!(trash.body["counts"]["trash"], 0);

    // Emptying an already-empty trash is a zero, not an error.
    let emptied_again = app
        .post("/v1/messages/empty-trash", Some(&app.full_key), json!({}))
        .await;
    assert_eq!(emptied_again.status, StatusCode::OK);
    assert_eq!(emptied_again.body["deleted"], 0);

    // Empty-trash needs the write scope too.
    let refused = app
        .post("/v1/messages/empty-trash", Some(&read_key), json!({}))
        .await;
    refused.assert_problem(StatusCode::FORBIDDEN, "forbidden");
}

#[tokio::test]
async fn health_probes_answer_without_authentication() {
    let app = TestApp::new();
    assert_eq!(app.get("/healthz", None).await.status, StatusCode::OK);
    assert_eq!(app.get("/readyz", None).await.status, StatusCode::OK);
}

// ------------------------------------------------------- trash retention

/// Seed one stored message for `account_id` straight through the store (reserve
/// the id, seal with it as AAD, insert) and move it to `folder`.
///
/// The send path cannot produce a message that has been sitting in the trash for
/// weeks, so the retention tests build the row they need instead of waiting.
fn seed_stored_message(
    state: &AppState,
    account_id: i64,
    folder: MessageFolder,
    subject: &str,
) -> i64 {
    let reserved = state.store.reserve_message_id().expect("reserve id");
    let aad = format!("account:{account_id}:message:{reserved}");
    let sealed = pigeon_crypto::seal_content(
        &TEST_MASTER_KEY,
        b"Subject: seeded\r\n\r\nbody",
        aad.as_bytes(),
    )
    .expect("seal body");
    state
        .store
        .insert_message(
            NewMessage {
                account_id,
                direction: Direction::In,
                from_addr: EmailAddress::parse("sender@example.net").expect("sender"),
                to_addrs: vec![EmailAddress::parse("owner@example.com").expect("recipient")],
                subject: subject.to_string(),
                sealed_body: sealed,
                idempotency_key: None,
                delivered_for: None,
            },
            reserved,
        )
        .expect("insert message");
    state
        .store
        .set_message_folder(reserved, folder)
        .expect("move message");
    reserved
}

/// Rewrite `messages.trashed_at` to `now + offset` (`'-40 days'`) on the file the
/// API is using. The store only writes `datetime('now')`, so this is the only way
/// to reach the expired state the purge is supposed to act on.
fn craft_trashed_at(path: &Path, message_id: i64, offset: &str) {
    let conn = raw_connection(path);
    conn.execute(
        "UPDATE messages SET trashed_at = datetime('now', ?2) WHERE id = ?1",
        rusqlite::params![message_id, offset],
    )
    .expect("craft trashed_at");
}

fn stored_trashed_at(path: &Path, message_id: i64) -> Option<String> {
    let conn = raw_connection(path);
    conn.query_row(
        "SELECT trashed_at FROM messages WHERE id = ?1",
        [message_id],
        |row| row.get(0),
    )
    .expect("read trashed_at")
}

/// A second connection to the test database, with the same busy timeout the
/// store uses.
///
/// Without the timeout a statement that races the API's own writer fails
/// immediately with `SQLITE_BUSY` instead of waiting, which would make the
/// retention tests flaky rather than wrong.
fn raw_connection(path: &Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).expect("open raw connection");
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .expect("set busy timeout");
    conn
}

#[tokio::test]
async fn account_settings_read_and_update_the_trash_retention() {
    let app = TestApp::new();

    // The documented default: an account that never opened settings still has a
    // bounded trash.
    let current = app.get("/v1/account/settings", Some(&app.full_key)).await;
    assert_eq!(current.status, StatusCode::OK, "{:?}", current.body);
    assert_eq!(current.body["trash_retention_days"], 30);

    // A read key may see the policy; only a write credential may change it.
    let read_key = app.key_with(&[ApiKeyScope::Read], false);
    let seen = app.get("/v1/account/settings", Some(&read_key)).await;
    assert_eq!(seen.status, StatusCode::OK, "{:?}", seen.body);
    assert_eq!(seen.body["trash_retention_days"], 30);
    let refused = app
        .patch(
            "/v1/account/settings",
            Some(&read_key),
            json!({ "trash_retention_days": 7 }),
        )
        .await;
    refused.assert_problem(StatusCode::FORBIDDEN, "forbidden");

    // A valid patch answers with the updated settings and persists them.
    for days in [0_i64, 1, 90, 365] {
        let patched = app
            .patch(
                "/v1/account/settings",
                Some(&app.full_key),
                json!({ "trash_retention_days": days }),
            )
            .await;
        assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.body);
        assert_eq!(patched.body["trash_retention_days"], days);
        let reread = app.get("/v1/account/settings", Some(&app.full_key)).await;
        assert_eq!(reread.body["trash_retention_days"], days);
        assert_eq!(
            app.state
                .store
                .get_trash_retention(app.account_id)
                .expect("store read"),
            days,
            "the API writes through to the store, not to a copy"
        );
    }

    // Out of range is a validation problem, and the stored value is untouched:
    // a rejected patch must not be a partial write.
    for (body, expected) in [
        (json!({ "trash_retention_days": 366 }), 366),
        (json!({ "trash_retention_days": 400 }), 400),
        (json!({ "trash_retention_days": -1 }), -1),
    ] {
        let invalid = app
            .patch("/v1/account/settings", Some(&app.full_key), body)
            .await;
        invalid.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");
        assert_eq!(invalid.body["errors"][0]["field"], "trash_retention_days");
        assert!(
            invalid.body["errors"][0]["message"]
                .as_str()
                .is_some_and(|message| message.contains(&expected.to_string())),
            "the message names the offending value: {:?}",
            invalid.body
        );
        assert_eq!(
            app.state
                .store
                .get_trash_retention(app.account_id)
                .expect("store read"),
            365,
            "an invalid patch leaves the old policy in place"
        );
    }

    // An empty body and an unknown member are validation problems too.
    let empty = app
        .patch("/v1/account/settings", Some(&app.full_key), json!({}))
        .await;
    empty.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");
    let unknown = app
        .patch(
            "/v1/account/settings",
            Some(&app.full_key),
            json!({ "trash_retention_days": 7, "trash_days": 7 }),
        )
        .await;
    unknown.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");
}

#[tokio::test]
async fn purge_trash_deletes_only_the_callers_expired_trash() {
    let app = TestApp::new();
    // A second mailbox with its own policy and its own expired trash.
    let other_account = app
        .state
        .store
        .create_account(&EmailAddress::parse("other@example.com").expect("address"))
        .expect("second account");

    // Expired, fresh, and old-but-not-in-the-trash rows of the caller.
    let expired = seed_stored_message(&app.state, app.account_id, MessageFolder::Trash, "expired");
    craft_trashed_at(&app.path, expired, "-40 days");
    let fresh = seed_stored_message(&app.state, app.account_id, MessageFolder::Trash, "fresh");
    craft_trashed_at(&app.path, fresh, "-1 days");
    let inbox = seed_stored_message(&app.state, app.account_id, MessageFolder::Inbox, "inbox");
    craft_trashed_at(&app.path, inbox, "-400 days");
    let sent = seed_stored_message(&app.state, app.account_id, MessageFolder::Sent, "sent");
    craft_trashed_at(&app.path, sent, "-400 days");
    let spam = seed_stored_message(&app.state, app.account_id, MessageFolder::Spam, "spam");
    craft_trashed_at(&app.path, spam, "-400 days");

    // The other mailbox's expired trash is untouched by this caller's purge.
    let foreign = seed_stored_message(&app.state, other_account, MessageFolder::Trash, "foreign");
    craft_trashed_at(&app.path, foreign, "-400 days");
    let foreign_stamp = stored_trashed_at(&app.path, foreign).expect("foreign stamp");

    let purged = app
        .post("/v1/messages/purge-trash", Some(&app.full_key), json!({}))
        .await;
    assert_eq!(purged.status, StatusCode::OK, "{:?}", purged.body);
    assert_eq!(purged.body["deleted"], 1, "{:?}", purged.body);
    assert_eq!(purged.body["trash_remaining"], 1, "{:?}", purged.body);

    let trash = app
        .get("/v1/messages?folder=trash", Some(&app.full_key))
        .await;
    let remaining: Vec<&str> = trash.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["subject"].as_str().expect("subject"))
        .collect();
    assert_eq!(remaining, vec!["fresh"], "the fresh trash stays");
    assert_eq!(trash.body["counts"]["trash"], 1);

    // Every other folder survives, however old its stamp is.
    for folder in ["inbox", "sent", "spam"] {
        let listing = app
            .get(
                &format!("/v1/messages?folder={folder}"),
                Some(&app.full_key),
            )
            .await;
        assert_eq!(
            listing.body["items"].as_array().expect("items").len(),
            1,
            "{folder} must survive the purge: {:?}",
            listing.body
        );
    }
    assert_eq!(
        app.state.store.count_trash(other_account).expect("count"),
        1,
        "another account's trash is its own policy's business"
    );
    assert_eq!(
        stored_trashed_at(&app.path, foreign).as_deref(),
        Some(foreign_stamp.as_str()),
        "the foreign row keeps the stamp it had"
    );

    // The purge follows the account's own policy: `0` keeps everything.
    let set = app
        .patch(
            "/v1/account/settings",
            Some(&app.full_key),
            json!({ "trash_retention_days": 0 }),
        )
        .await;
    assert_eq!(set.status, StatusCode::OK, "{:?}", set.body);
    let kept = app
        .post("/v1/messages/purge-trash", Some(&app.full_key), json!({}))
        .await;
    assert_eq!(kept.status, StatusCode::OK, "{:?}", kept.body);
    assert_eq!(
        kept.body["deleted"], 0,
        "keep-forever deletes nothing: {:?}",
        kept.body
    );
    assert_eq!(kept.body["trash_remaining"], 1);

    // Purge is a write: a read key is refused.
    let read_key = app.key_with(&[ApiKeyScope::Read], false);
    let refused = app
        .post("/v1/messages/purge-trash", Some(&read_key), json!({}))
        .await;
    refused.assert_problem(StatusCode::FORBIDDEN, "forbidden");
}

// ------------------------------------------------------------ sessions / 2fa

/// Pull the session cookie out of a `Set-Cookie` header, asserting the
/// attributes the contract promises. A cookie that lost `HttpOnly` or
/// `SameSite=Strict` would still authenticate, so the test checks them here
/// once instead of trusting the handler.
fn session_cookie(response: &Response) -> String {
    let header = response
        .headers
        .get(header::SET_COOKIE)
        .expect("login sets the session cookie")
        .to_str()
        .expect("cookie header is ASCII")
        .to_string();
    for expected in ["HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=604800"] {
        assert!(
            header
                .to_ascii_lowercase()
                .contains(&expected.to_ascii_lowercase()),
            "cookie must carry {expected}: {header}"
        );
    }
    let (pair, _) = header.split_once(';').expect("attributes follow the pair");
    let (name, value) = pair.split_once('=').expect("name=value");
    assert_eq!(name, "pigeon_session");
    assert_eq!(value.len(), 65, "sess_ id, a dot, then 43 base64url chars");
    value.to_string()
}

/// The `secret_base32` from an enroll response, decoded for TOTP generation.
fn enrolled_secret(body: &Value) -> Vec<u8> {
    let encoded = body["secret_base32"].as_str().expect("secret_base32");
    assert!(
        !encoded.contains('='),
        "RFC 4648 base32 without padding: {encoded}"
    );
    pigeon_api::base32::decode(encoded).expect("enrolled secret decodes")
}

fn code_now(secret: &[u8]) -> String {
    let totp = pigeon_crypto::Totp::try_new(secret).expect("totp");
    totp.generate(pigeon_api::time::now_unix().max(0) as u64)
}

impl TestApp {
    async fn login(&self, body: Value) -> Response {
        self.post("/v1/auth/login", None, body).await
    }

    /// Creates a pending bootstrap invitation for the owner account and returns
    /// the one-time token (the login requires a code since the security fix).
    fn bootstrap_token(&self) -> String {
        // Create an org so the invitation has an owner context, then mint the
        // invitation for the owner's own address. The token is returned once.
        let org_id = self.state.store.create_org("test-org").expect("org");
        self.state
            .store
            .set_account_org(
                self.account_id,
                Some(org_id),
                pigeon_core::types::OrgRole::Owner,
            )
            .expect("org membership");
        let email = EmailAddress::parse("owner@example.com").expect("address");
        self.state
            .store
            .create_invitation(
                org_id,
                &email,
                pigeon_core::types::OrgRole::Admin,
                self.account_id,
            )
            .expect("invitation")
    }

    async fn get_with_session(&self, path: &str, cookie: &str) -> Response {
        let authorization = format!("pigeon_session={cookie}");
        self.call(build(
            Method::GET,
            path,
            None,
            None,
            &[(header::COOKIE.as_str(), authorization.as_str())],
        ))
        .await
    }

    async fn post_with_session(&self, path: &str, cookie: &str, body: Value) -> Response {
        let authorization = format!("pigeon_session={cookie}");
        self.call(build(
            Method::POST,
            path,
            None,
            Some(body),
            &[(header::COOKIE.as_str(), authorization.as_str())],
        ))
        .await
    }
}

#[tokio::test]
async fn login_issues_a_session_cookie_that_authenticates_full_scope_routes() {
    let app = TestApp::new();
    let token = app.bootstrap_token();
    let login = app
        .login(json!({"email": "owner@example.com", "code": token}))
        .await;

    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    let session_id = login.body["session_id"].as_str().expect("session_id");
    assert!(session_id.starts_with("sess_"), "{session_id}");
    assert!(login.body["expires_at"]
        .as_str()
        .expect("expires_at")
        .ends_with('Z'));
    let cookie = session_cookie(&login);
    assert!(
        cookie.starts_with(session_id),
        "the cookie names its own session: {cookie} vs {session_id}"
    );

    // A session satisfies the `full` scope: reads and writes both work.
    let keys = app.get_with_session("/v1/account/keys", &cookie).await;
    assert_eq!(keys.status, StatusCode::OK, "{:?}", keys.body);
    let created = app
        .post_with_session(
            "/v1/account/keys",
            &cookie,
            json!({"name": "dashboard", "scopes": ["send"]}),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    assert!(created.body["key"]
        .as_str()
        .expect("key")
        .starts_with("pk_"));

    // Logout revokes the session: the same cookie is dead immediately.
    let logout = app
        .post_with_session("/v1/auth/logout", &cookie, json!({}))
        .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT, "{:?}", logout.body);
    let after = app.get_with_session("/v1/account/keys", &cookie).await;
    after.assert_problem(StatusCode::UNAUTHORIZED, "unauthorized");

    // An unknown address and a malformed one are different problems.
    let unknown = app.login(json!({"email": "nobody@example.com"})).await;
    unknown.assert_problem(StatusCode::UNAUTHORIZED, "unauthorized");
    let malformed = app.login(json!({"email": "not-an-address"})).await;
    malformed.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");
    assert_eq!(malformed.body["errors"][0]["field"], "email");
}

#[tokio::test]
async fn repeated_login_failures_are_rate_limited() {
    let app = TestApp::new();
    for attempt in 0..5 {
        let failed = app.login(json!({"email": "nobody@example.com"})).await;
        assert_eq!(
            failed.status,
            StatusCode::UNAUTHORIZED,
            "attempt {attempt}: {:?}",
            failed.body
        );
    }
    let limited = app.login(json!({"email": "owner@example.com"})).await;
    limited.assert_problem(StatusCode::TOO_MANY_REQUESTS, "rate-limited");
    assert!(
        limited.headers.contains_key(header::RETRY_AFTER),
        "429 must tell the client when to retry"
    );
}

#[tokio::test]
async fn the_2fa_endpoints_are_session_realm_only() {
    let app = TestApp::new();
    let body = json!({"code": "123456"});
    for path in [
        "/v1/account/2fa/enroll",
        "/v1/account/2fa/activate",
        "/v1/account/2fa/verify",
        "/v1/account/2fa/disable",
    ] {
        let anonymous = app.post(path, None, body.clone()).await;
        anonymous.assert_problem(StatusCode::UNAUTHORIZED, "unauthorized");

        // A `full` API key is a machine credential: 2FA protects sessions, so
        // it must not be able to enroll or disable the second factor.
        let by_key = app.post(path, Some(&app.full_key), body.clone()).await;
        by_key.assert_problem(StatusCode::UNAUTHORIZED, "unauthorized");
    }

    let logout_anonymous = app.post("/v1/auth/logout", None, json!({})).await;
    logout_anonymous.assert_problem(StatusCode::UNAUTHORIZED, "unauthorized");
    let logout_by_key = app
        .post("/v1/auth/logout", Some(&app.full_key), json!({}))
        .await;
    logout_by_key.assert_problem(StatusCode::UNAUTHORIZED, "unauthorized");
}

#[tokio::test]
async fn totp_enroll_activate_and_login_with_a_code_rejects_replay() {
    let app = TestApp::new();
    let token = app.bootstrap_token();
    let login = app
        .login(json!({"email": "owner@example.com", "code": token}))
        .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    let cookie = session_cookie(&login);

    let enroll = app
        .post_with_session("/v1/account/2fa/enroll", &cookie, json!({}))
        .await;
    assert_eq!(enroll.status, StatusCode::OK, "{:?}", enroll.body);
    let secret = enrolled_secret(&enroll.body);
    let otpauth = enroll.body["otpauth_uri"].as_str().expect("otpauth_uri");
    assert!(otpauth.starts_with("otpauth://totp/"), "{otpauth}");
    assert!(otpauth.contains("secret="), "{otpauth}");
    assert_eq!(
        enroll.body["secret_base32"].as_str().expect("secret"),
        pigeon_api::base32::encode(&secret),
        "the returned secret is the stored one"
    );

    // Before activation the account is challenged (the security fix requires
    // a code on every login — no more email-only sessions).
    let without_code = app.login(json!({"email": "owner@example.com"})).await;
    without_code.assert_problem(StatusCode::FORBIDDEN, "mfa-required");

    let code = code_now(&secret);
    let activate = app
        .post_with_session("/v1/account/2fa/activate", &cookie, json!({"code": code}))
        .await;
    assert_eq!(activate.status, StatusCode::OK, "{:?}", activate.body);
    let recovery = activate.body["recovery_codes"]
        .as_array()
        .expect("recovery_codes")
        .clone();
    assert_eq!(recovery.len(), 10, "the contract issues ten codes");
    let unique: std::collections::HashSet<&str> =
        recovery.iter().filter_map(|value| value.as_str()).collect();
    assert_eq!(unique.len(), 10, "recovery codes never repeat");

    // 2FA is active: no code is a challenge, a wrong code is a rejection.
    let challenged = app.login(json!({"email": "owner@example.com"})).await;
    challenged.assert_problem(StatusCode::FORBIDDEN, "mfa-required");
    let wrong = app
        .login(json!({"email": "owner@example.com", "code": "000000"}))
        .await;
    wrong.assert_problem(StatusCode::UNAUTHORIZED, "unauthorized");

    // The same (still time-valid) code cannot be used twice.
    let accepted = app
        .login(json!({"email": "owner@example.com", "code": code.clone()}))
        .await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.body);
    let replay = app
        .login(json!({"email": "owner@example.com", "code": code}))
        .await;
    replay.assert_problem(StatusCode::UNAUTHORIZED, "unauthorized");
    assert!(replay.body["detail"]
        .as_str()
        .expect("detail")
        .contains("replay"));

    // The session issued by the coded login works, and disable tears 2FA down.
    let accepted_cookie = session_cookie(&accepted);
    let keys = app
        .get_with_session("/v1/account/keys", &accepted_cookie)
        .await;
    assert_eq!(keys.status, StatusCode::OK, "{:?}", keys.body);

    let disable = app
        .post_with_session(
            "/v1/account/2fa/disable",
            &accepted_cookie,
            json!({"code": recovery[0].as_str().expect("code")}),
        )
        .await;
    assert_eq!(disable.status, StatusCode::NO_CONTENT, "{:?}", disable.body);

    // Disabling revokes every other session but the one that disabled it.
    let stale = app.get_with_session("/v1/account/keys", &cookie).await;
    stale.assert_problem(StatusCode::UNAUTHORIZED, "unauthorized");
    let still_valid = app
        .get_with_session("/v1/account/keys", &accepted_cookie)
        .await;
    assert_eq!(still_valid.status, StatusCode::OK, "{:?}", still_valid.body);

    // And login works again with a fresh bootstrap token (the security fix
    // requires a code on every login; the first invitation was burned).
    let fresh_token = app.bootstrap_token();
    let no_second_factor = app
        .login(json!({"email": "owner@example.com", "code": fresh_token}))
        .await;
    assert_eq!(
        no_second_factor.status,
        StatusCode::OK,
        "{:?}",
        no_second_factor.body
    );
}

#[tokio::test]
async fn bootstrap_token_burns_on_login_and_replay_is_rejected() {
    let app = TestApp::new();
    let token = app.bootstrap_token();
    let first = app
        .login(json!({"email": "owner@example.com", "code": &token}))
        .await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    // The token is single-use: the same code is a failed login now.
    let replay = app
        .login(json!({"email": "owner@example.com", "code": &token}))
        .await;
    replay.assert_problem(StatusCode::UNAUTHORIZED, "unauthorized");
}

#[tokio::test]
async fn mfa_required_charges_the_login_budget() {
    // The 403 mfa-required path must count as a login failure (JD-A-009):
    // otherwise the enumeration challenge is free to hammer.
    let app = TestApp::new();
    for attempt in 1..=5 {
        let challenged = app.login(json!({"email": "owner@example.com"})).await;
        assert_eq!(
            challenged.status,
            StatusCode::FORBIDDEN,
            "attempt {attempt}: {:?}",
            challenged.body
        );
    }
    let limited = app.login(json!({"email": "owner@example.com"})).await;
    limited.assert_problem(StatusCode::TOO_MANY_REQUESTS, "rate-limited");
}

#[tokio::test]
async fn recovery_codes_log_in_once_and_step_up_verification_works() {
    let app = TestApp::new();
    let bootstrap = app.bootstrap_token();
    let login = app
        .login(json!({"email": "owner@example.com", "code": bootstrap}))
        .await;
    let cookie = session_cookie(&login);
    let enroll = app
        .post_with_session("/v1/account/2fa/enroll", &cookie, json!({}))
        .await;
    let secret = enrolled_secret(&enroll.body);
    let activate = app
        .post_with_session(
            "/v1/account/2fa/activate",
            &cookie,
            json!({"code": code_now(&secret)}),
        )
        .await;
    assert_eq!(activate.status, StatusCode::OK, "{:?}", activate.body);
    let codes: Vec<String> = activate.body["recovery_codes"]
        .as_array()
        .expect("recovery_codes")
        .iter()
        .map(|value| value.as_str().expect("code").to_string())
        .collect();

    // A recovery code is a login credential: it burns on use.
    let burned = app
        .login(json!({"email": "owner@example.com", "code": codes[0].clone()}))
        .await;
    assert_eq!(burned.status, StatusCode::OK, "{:?}", burned.body);
    let reused = app
        .login(json!({"email": "owner@example.com", "code": codes[0].clone()}))
        .await;
    reused.assert_problem(StatusCode::UNAUTHORIZED, "unauthorized");

    // Step-up verification accepts a different recovery code...
    let session = session_cookie(&burned);
    let verified = app
        .post_with_session(
            "/v1/account/2fa/verify",
            &session,
            json!({"code": codes[1]}),
        )
        .await;
    assert_eq!(verified.status, StatusCode::OK, "{:?}", verified.body);
    assert_eq!(verified.body["verified"], true);

    // ...and rejects a code that is neither TOTP nor unused recovery code.
    let refused = app
        .post_with_session(
            "/v1/account/2fa/verify",
            &session,
            json!({"code": codes[0]}),
        )
        .await;
    refused.assert_problem(StatusCode::UNAUTHORIZED, "unauthorized");

    // The used step-up code is burned too.
    let replay = app
        .post_with_session(
            "/v1/account/2fa/verify",
            &session,
            json!({"code": codes[1]}),
        )
        .await;
    replay.assert_problem(StatusCode::UNAUTHORIZED, "unauthorized");
}

#[tokio::test]
async fn activating_without_a_pending_enrollment_or_with_a_wrong_code_fails() {
    let app = TestApp::new();
    let bootstrap = app.bootstrap_token();
    let login = app
        .login(json!({"email": "owner@example.com", "code": bootstrap}))
        .await;
    let cookie = session_cookie(&login);

    // Nothing enrolled yet.
    let activate = app
        .post_with_session(
            "/v1/account/2fa/activate",
            &cookie,
            json!({"code": "123456"}),
        )
        .await;
    activate.assert_problem(StatusCode::NOT_FOUND, "not-found");

    let enroll = app
        .post_with_session("/v1/account/2fa/enroll", &cookie, json!({}))
        .await;
    let secret = enrolled_secret(&enroll.body);
    let wrong = app
        .post_with_session(
            "/v1/account/2fa/activate",
            &cookie,
            json!({"code": "000000"}),
        )
        .await;
    wrong.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");
    assert_eq!(wrong.body["errors"][0]["field"], "code");
    // The enrollment is still pending, so a good code activates it.
    let good = app
        .post_with_session(
            "/v1/account/2fa/activate",
            &cookie,
            json!({"code": code_now(&secret)}),
        )
        .await;
    assert_eq!(good.status, StatusCode::OK, "{:?}", good.body);
}

#[tokio::test]
async fn unknown_routes_are_not_served_as_success() {
    let app = TestApp::new();
    let response = app.get("/v1/nonsense", Some(&app.full_key)).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn two_apps_never_share_rows() {
    // Guards the fixture itself: a leak here would make every other assertion
    // silently order-dependent.
    let first = TestApp::new();
    let second = TestApp::new();
    first.send(&first.full_key, valid_send()).await;
    let page = second.get("/v1/emails", Some(&second.full_key)).await;
    assert_eq!(page.body["page"]["total"], 0);
}

// ---------------------------------------------------------------------------
// Multi-tenant: organizations, members, invitations and catch-all routing
// ---------------------------------------------------------------------------

impl TestApp {
    /// Issue a `full` key for an existing account.
    fn key_for_account(&self, account_id: i64) -> String {
        let (_, key) = pigeon_api::keys::issue(
            &self.state.store,
            &self.state.db,
            account_id,
            "full",
            &[ApiKeyScope::Full],
            false,
        )
        .expect("key");
        key
    }

    /// Create an account directly in the store and return a `full` key for it.
    ///
    /// Standing in for "this person already has a mailbox": the invitation flow
    /// links an existing account, and the installer/CLI is what creates it.
    fn account_with_key(&self, email: &str) -> (i64, String) {
        let address = EmailAddress::parse(email).expect("address");
        let account_id = self.state.store.create_account(&address).expect("account");
        (account_id, self.key_for_account(account_id))
    }

    /// `POST /v1/orgs` and return `(id, name)`.
    /// An organization with an owner and one plain `member`.
    ///
    /// A personal-workspace account is its own `owner`, so "this call needs an
    /// admin" can only be proven with somebody who is a `member` of somebody
    /// else's organization.
    async fn org_member(&self, owner_email: &str, member_email: &str) -> (i64, String) {
        let (_, owner_key) = self.account_with_key(owner_email);
        let org_id = self.create_org(&owner_key, "Team").await;
        let (member_id, member_key) = self.account_with_key(member_email);
        self.state
            .store
            .set_account_org(member_id, Some(org_id), pigeon_core::types::OrgRole::Member)
            .expect("member joins");
        (member_id, member_key)
    }

    async fn create_org(&self, key: &str, name: &str) -> i64 {
        let response = self
            .post("/v1/orgs", Some(key), json!({"name": name}))
            .await;
        assert_eq!(response.status, StatusCode::CREATED, "{:?}", response.body);
        assert_eq!(response.body["name"], name);
        assert_eq!(response.body["role"], "owner");
        response.body["id"].as_i64().expect("org id")
    }
}

#[tokio::test]
async fn an_organization_is_created_and_its_members_are_administered() {
    let app = TestApp::new();
    let org_id = app.create_org(&app.full_key, "Acme").await;

    // The creator is the owner and sees the organization in its own listing.
    let listing = app.get("/v1/orgs", Some(&app.full_key)).await;
    assert_eq!(listing.status, StatusCode::OK, "{:?}", listing.body);
    assert_eq!(listing.body.as_array().expect("array").len(), 1);
    assert_eq!(listing.body[0]["id"], org_id);
    assert_eq!(listing.body[0]["role"], "owner");

    // A member can be created directly, and the response carries the token once.
    let created = app
        .post(
            &format!("/v1/orgs/{org_id}/members"),
            Some(&app.full_key),
            json!({"email": "eli@acme.com", "display_name": "Eli", "role": "admin"}),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    assert_eq!(created.body["member"]["email"], "eli@acme.com");
    assert_eq!(created.body["member"]["display_name"], "Eli");
    assert_eq!(created.body["member"]["role"], "admin");
    let bootstrap = created.body["bootstrap_token"]
        .as_str()
        .expect("bootstrap token")
        .to_string();
    assert_eq!(bootstrap.len(), 43, "32 random bytes as unpadded base64url");

    // Display names and roles are patchable, and the change is visible.
    let eli_id = created.body["member"]["account_id"]
        .as_i64()
        .expect("account id");
    let patched = app
        .patch(
            &format!("/v1/orgs/{org_id}/members/{eli_id}"),
            Some(&app.full_key),
            json!({"display_name": "Eli Admin", "role": "member"}),
        )
        .await;
    assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.body);
    assert_eq!(patched.body["display_name"], "Eli Admin");
    assert_eq!(patched.body["role"], "member");

    // One account belongs to one organization: creating a second one is refused
    // rather than silently moving the mailbox out of the first.
    let second = app
        .post("/v1/orgs", Some(&app.full_key), json!({"name": "Second"}))
        .await;
    second.assert_problem(StatusCode::CONFLICT, "conflict");

    // The member list is the organization's, not the caller's.
    let members = app
        .get(&format!("/v1/orgs/{org_id}/members"), Some(&app.full_key))
        .await;
    assert_eq!(members.status, StatusCode::OK, "{:?}", members.body);
    let emails: Vec<&str> = members
        .body
        .as_array()
        .expect("array")
        .iter()
        .map(|member| member["email"].as_str().expect("email"))
        .collect();
    assert_eq!(emails, vec!["owner@example.com", "eli@acme.com"]);
}

#[tokio::test]
async fn an_invitation_is_returned_once_and_linking_an_account_burns_it() {
    let app = TestApp::new();
    let org_id = app.create_org(&app.full_key, "Acme").await;
    let (dana_id, dana_key) = app.account_with_key("dana@acme.com");

    let created = app
        .post(
            &format!("/v1/orgs/{org_id}/invitations"),
            Some(&app.full_key),
            json!({"email": "dana@acme.com", "role": "member"}),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let token = created.body["token"].as_str().expect("token").to_string();
    assert_eq!(token.len(), 43);
    assert_eq!(created.body["invitation"]["email"], "dana@acme.com");
    assert!(
        created.body["invitation"].get("token").is_none(),
        "the token lives beside the invitation, never inside it"
    );

    // The listing shows the invitation but not the token: it is available once.
    let listed = app
        .get(
            &format!("/v1/orgs/{org_id}/invitations"),
            Some(&app.full_key),
        )
        .await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
    assert_eq!(listed.body.as_array().expect("array").len(), 1);
    assert!(listed.body[0].get("token").is_none());
    assert!(listed.body[0].get("accepted_at").is_none());

    // Somebody else's token is refused rather than spent.
    let stolen = app
        .post(
            "/v1/invitations/accept",
            Some(&app.full_key),
            json!({"token": token}),
        )
        .await;
    stolen.assert_problem(StatusCode::FORBIDDEN, "forbidden");

    // Dana redeems it with her own credential.
    let accepted = app
        .post(
            "/v1/invitations/accept",
            Some(&dana_key),
            json!({"token": token}),
        )
        .await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.body);
    assert_eq!(accepted.body["id"], org_id);
    assert_eq!(accepted.body["role"], "member");
    assert_eq!(
        app.state
            .store
            .get_account_membership(dana_id)
            .expect("membership"),
        (Some(org_id), pigeon_core::types::OrgRole::Member)
    );

    // The token is burned: a replay is not found, and the row is still listed as
    // history with its acceptance stamp.
    let replay = app
        .post(
            "/v1/invitations/accept",
            Some(&dana_key),
            json!({"token": token}),
        )
        .await;
    replay.assert_problem(StatusCode::NOT_FOUND, "not-found");
    let listed = app
        .get(
            &format!("/v1/orgs/{org_id}/invitations"),
            Some(&app.full_key),
        )
        .await;
    assert!(listed.body[0]["accepted_at"].as_str().is_some());
}

#[tokio::test]
async fn a_bootstrap_token_logs_a_new_member_in_exactly_once() {
    let app = TestApp::new();
    let org_id = app.create_org(&app.full_key, "Acme").await;
    let created = app
        .post(
            &format!("/v1/orgs/{org_id}/members"),
            Some(&app.full_key),
            json!({"email": "eli@acme.com"}),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    assert_eq!(created.body["member"]["role"], "member");
    let bootstrap = created.body["bootstrap_token"]
        .as_str()
        .expect("bootstrap token")
        .to_string();

    // The token is the second factor slot: without it the member has no TOTP, so
    // with it the login succeeds and sets a session cookie.
    let login = app
        .login(json!({"email": "eli@acme.com", "code": bootstrap}))
        .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    let cookie = session_cookie(&login);
    assert!(!cookie.is_empty());
    let page = app.get_with_session("/v1/orgs", &cookie).await;
    assert_eq!(page.status, StatusCode::OK, "{:?}", page.body);
    assert_eq!(page.body[0]["role"], "member");

    // Burning is real: the same token is refused on the next attempt.
    let replay = app
        .login(json!({"email": "eli@acme.com", "code": bootstrap}))
        .await;
    replay.assert_problem(StatusCode::UNAUTHORIZED, "unauthorized");

    // A code that matches no invitation is a failed login, not a silent success.
    let wrong = app
        .login(json!({"email": "owner@example.com", "code": "not-a-real-token"}))
        .await;
    wrong.assert_problem(StatusCode::UNAUTHORIZED, "unauthorized");
}

#[tokio::test]
async fn the_last_owner_cannot_be_demoted_and_members_cannot_administrate() {
    let app = TestApp::new();
    let org_id = app.create_org(&app.full_key, "Acme").await;
    let added = app
        .post(
            &format!("/v1/orgs/{org_id}/members"),
            Some(&app.full_key),
            json!({"email": "eli@acme.com", "role": "admin"}),
        )
        .await;
    assert_eq!(added.status, StatusCode::CREATED, "{:?}", added.body);
    let eli_id = added.body["member"]["account_id"]
        .as_i64()
        .expect("member id");
    // A key for the new member's own account: the routes below must judge *its*
    // role, not its credential's scopes.
    let eli_key = app.key_for_account(eli_id);

    // The only owner cannot step down: the organization would be unadministered.
    let demote = app
        .patch(
            &format!("/v1/orgs/{org_id}/members/{}", app.account_id),
            Some(&app.full_key),
            json!({"role": "admin"}),
        )
        .await;
    demote.assert_problem(StatusCode::CONFLICT, "last-owner");

    // An admin cannot grant or take away ownership, even though it may edit
    // members.
    let promote_self = app
        .patch(
            &format!("/v1/orgs/{org_id}/members/{eli_id}"),
            Some(&eli_key),
            json!({"role": "owner"}),
        )
        .await;
    promote_self.assert_problem(StatusCode::FORBIDDEN, "forbidden");

    // Once the admin is demoted to member, every administration route is closed.
    let demote_admin = app
        .patch(
            &format!("/v1/orgs/{org_id}/members/{eli_id}"),
            Some(&app.full_key),
            json!({"role": "member"}),
        )
        .await;
    assert_eq!(
        demote_admin.status,
        StatusCode::OK,
        "{:?}",
        demote_admin.body
    );
    let forbidden = app
        .get(&format!("/v1/orgs/{org_id}/members"), Some(&eli_key))
        .await;
    forbidden.assert_problem(StatusCode::FORBIDDEN, "forbidden");
    let forbidden_invite = app
        .post(
            &format!("/v1/orgs/{org_id}/invitations"),
            Some(&eli_key),
            json!({"email": "someone@acme.com"}),
        )
        .await;
    forbidden_invite.assert_problem(StatusCode::FORBIDDEN, "forbidden");

    // A member of no organization cannot use the endpoints as an existence oracle:
    // a foreign organization id and a nonexistent one answer identically.
    let foreign = app
        .get(
            &format!("/v1/orgs/{}/members", org_id + 999),
            Some(&eli_key),
        )
        .await;
    foreign.assert_problem(StatusCode::FORBIDDEN, "forbidden");
}

/// A raw SMTP dialogue: enough to drive the inbound server from a test.
struct SmtpClient {
    reader: tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

impl SmtpClient {
    async fn connect(address: std::net::SocketAddr) -> Self {
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect to the inbound server");
        let (reader, writer) = stream.into_split();
        let mut client = Self {
            reader: tokio::io::BufReader::new(reader),
            writer,
        };
        assert_eq!(client.read_reply().await.0, 220, "banner");
        client
    }

    /// Read one reply, joining a multi-line reply into one string.
    async fn read_reply(&mut self) -> (u16, String) {
        let mut lines: Vec<String> = Vec::new();
        loop {
            use tokio::io::AsyncBufReadExt;
            let mut line = String::new();
            let read = self.reader.read_line(&mut line).await.expect("read reply");
            assert_ne!(read, 0, "the server closed during the dialogue");
            let line = line.trim_end_matches(['\r', '\n']).to_string();
            let code: u16 = line
                .get(..3)
                .and_then(|prefix| prefix.parse().ok())
                .unwrap_or_else(|| panic!("reply without a code: {line:?}"));
            let last = line.len() == 3 || line.as_bytes().get(3) == Some(&b' ');
            lines.push(line.get(4..).unwrap_or_default().to_string());
            if last {
                return (code, lines.join(" | "));
            }
        }
    }

    async fn command(&mut self, line: &str) -> (u16, String) {
        use tokio::io::AsyncWriteExt;
        self.writer
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .expect("write command");
        self.writer.flush().await.expect("flush");
        self.read_reply().await
    }

    /// Run `EHLO`/`MAIL`/`RCPT`/`DATA` and return the reply to the message data.
    async fn deliver(&mut self, from: &str, to: &str, body: &str) -> (u16, String) {
        assert_eq!(self.command("EHLO test.local").await.0, 250);
        assert_eq!(self.command(&format!("MAIL FROM:<{from}>")).await.0, 250);
        let (rcpt_code, _) = self.command(&format!("RCPT TO:<{to}>")).await;
        assert_eq!(
            rcpt_code, 250,
            "RCPT is accepted; resolution happens at DATA"
        );
        assert_eq!(self.command("DATA").await.0, 354);
        use tokio::io::AsyncWriteExt;
        self.writer
            .write_all(format!("{body}\r\n.\r\n").as_bytes())
            .await
            .expect("write data");
        self.writer.flush().await.expect("flush");
        self.read_reply().await
    }
}

/// Start the real inbound server against the app's own store and database.
async fn start_inbound(app: &TestApp) -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let server = std::sync::Arc::new(pigeon_smtp::InboundSmtpServer::new(
        std::sync::Arc::clone(&app.state.store),
        std::sync::Arc::clone(&app.state.db),
        std::sync::Arc::clone(&app.state.master_key),
        pigeon_smtp::ServerConfig::default(),
    ));
    let (listener, address) = server.bind("127.0.0.1:0").await.expect("bind");
    let (stop, stopped) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        server
            .serve_with_shutdown(listener, async {
                let _ = stopped.await;
            })
            .await;
    });
    (address, stop)
}

async fn inbox_subjects(app: &TestApp, account_id: i64) -> Vec<String> {
    app.state
        .store
        .list_folder(account_id, pigeon_core::MessageFolder::Inbox, 50, 0)
        .expect("inbox")
        .into_iter()
        .map(|row| row.subject)
        .collect()
}

/// `PUT /v1/catchall/{domain}` with an action, as the contract now shapes it.
async fn put_catchall(app: &TestApp, key: &str, domain: &str, action: &str) -> Response {
    app.call(build(
        Method::PUT,
        &format!("/v1/catchall/{domain}"),
        Some(key),
        Some(json!({ "action": action })),
        &[],
    ))
    .await
}

/// Assign one account to a domain's catch-all.
async fn assign_catchall(app: &TestApp, key: &str, domain: &str, account_id: i64) -> Response {
    app.call(build(
        Method::POST,
        &format!("/v1/catchall/{domain}/assign"),
        Some(key),
        Some(json!({ "account_id": account_id })),
        &[],
    ))
    .await
}

#[tokio::test]
async fn catchall_route_copies_the_mail_to_every_assignee() {
    let app = TestApp::new();
    let (second_id, _) = app.account_with_key("second@example.com");

    let rule = put_catchall(&app, &app.full_key, "example.com", "route").await;
    assert_eq!(rule.status, StatusCode::OK, "{:?}", rule.body);
    assert_eq!(rule.body["domain"], "example.com");
    assert_eq!(rule.body["action"], "route");

    // Two mailboxes hold the same catch-all; a third assignment is a conflict.
    for account_id in [app.account_id, second_id] {
        let assigned = assign_catchall(&app, &app.full_key, "example.com", account_id).await;
        assert_eq!(assigned.status, StatusCode::OK, "{:?}", assigned.body);
    }
    let assignees = app.get("/v1/catchall", Some(&app.full_key)).await;
    assert_eq!(assignees.status, StatusCode::OK, "{:?}", assignees.body);
    let assignments = assignees.body[0]["assignments"]
        .as_array()
        .expect("assignments");
    assert_eq!(assignments.len(), 2, "{:?}", assignees.body);
    assert!(assignments.iter().all(|row| row["paused"] == false));
    assert_eq!(assignments[0]["email"], "owner@example.com");

    let duplicate = assign_catchall(&app, &app.full_key, "example.com", second_id).await;
    duplicate.assert_problem(StatusCode::CONFLICT, "conflict");

    // A mailbox of another domain cannot hold this catch-all.
    let (elsewhere_id, _) = app.account_with_key("dana@other.example");
    let mismatched = assign_catchall(&app, &app.full_key, "example.com", elsewhere_id).await;
    mismatched.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");
    assert_eq!(mismatched.body["errors"][0]["field"], "account_id");
    let unknown = assign_catchall(&app, &app.full_key, "example.com", 9_999).await;
    unknown.assert_problem(StatusCode::NOT_FOUND, "not-found");

    let (address, stop) = start_inbound(&app).await;
    let mut client = SmtpClient::connect(address).await;
    let (code, text) = client
        .deliver(
            "dana@example.org",
            "nobody-here@example.com",
            "Subject: hello catch-all\r\nFrom: dana@example.org\r\n\r\nbody",
        )
        .await;
    assert_eq!(code, 250, "{text}");
    assert!(text.contains("queued as"), "{text}");

    // Every assignee gets its own copy, marked with the address it arrived for.
    for account_id in [app.account_id, second_id] {
        let rows = app
            .state
            .store
            .list_folder(account_id, pigeon_core::MessageFolder::Inbox, 10, 0)
            .expect("inbox");
        assert_eq!(rows.len(), 1, "account {account_id}: {rows:?}");
        assert_eq!(rows[0].subject, "hello catch-all");
        assert_eq!(
            rows[0].delivered_for.as_deref(),
            Some("nobody-here@example.com"),
            "the copy records the address it was delivered for"
        );
        assert_eq!(
            rows[0]
                .to_addrs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["nobody-here@example.com"]
        );
        let events = app.state.store.list_events(rows[0].id).expect("events");
        assert!(
            events[0].1.contains("via=catchall"),
            "the delivery event records why it arrived: {:?}",
            events[0]
        );
        assert!(
            events[0]
                .1
                .contains("delivered_for=nobody-here@example.com"),
            "{:?}",
            events[0]
        );
    }

    // A recipient of a domain without a rule still gets the ordinary 550.
    let mut client = SmtpClient::connect(address).await;
    let (code, _) = client
        .deliver(
            "dana@example.org",
            "nobody@unmanaged.example",
            "Subject: nope\r\n\r\nbody",
        )
        .await;
    assert_eq!(code, 550, "an unmanaged domain is still refused");
    let _ = stop.send(());
}

#[tokio::test]
async fn catchall_discard_accepts_and_stores_nothing() {
    let app = TestApp::new();
    let rule = put_catchall(&app, &app.full_key, "example.com", "discard").await;
    assert_eq!(rule.status, StatusCode::OK, "{:?}", rule.body);
    assert_eq!(rule.body["action"], "discard");
    assert!(
        rule.body.get("assignments").is_none(),
        "a discard rule names nobody: {:?}",
        rule.body
    );

    let (address, stop) = start_inbound(&app).await;
    let mut client = SmtpClient::connect(address).await;
    let (code, text) = client
        .deliver(
            "dana@example.org",
            "made-up@example.com",
            "Subject: discarded\r\n\r\nbody",
        )
        .await;
    // Accepted on purpose: a 550 here would tell the sender the address is
    // fictional, which is exactly what a catch-all exists to hide.
    assert_eq!(code, 250, "{text}");
    let _ = stop.send(());

    assert!(
        inbox_subjects(&app, app.account_id).await.is_empty(),
        "a discarded message is not stored anywhere"
    );

    // Removing the rule restores the 550 for the same address.
    let deleted = app
        .delete("/v1/catchall/example.com", Some(&app.full_key))
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{:?}", deleted.body);
    let missing = app
        .delete("/v1/catchall/example.com", Some(&app.full_key))
        .await;
    missing.assert_problem(StatusCode::NOT_FOUND, "not-found");
}

#[tokio::test]
async fn catchall_pause_is_per_member_and_an_admin_can_force_a_resume() {
    let app = TestApp::new();
    let (member_id, member_key) = app
        .org_member("team-lead@example.com", "eli@example.com")
        .await;
    put_catchall(&app, &app.full_key, "example.com", "route").await;

    // Pausing before holding anything is a conflict, not a silent no-op.
    let never_assigned = app
        .post("/v1/catchall/me/pause", Some(&member_key), json!({}))
        .await;
    never_assigned.assert_problem(StatusCode::CONFLICT, "conflict");

    assign_catchall(&app, &app.full_key, "example.com", app.account_id).await;
    let paused = app
        .post("/v1/catchall/me/pause", Some(&app.full_key), json!({}))
        .await;
    assert_eq!(paused.status, StatusCode::OK, "{:?}", paused.body);
    assert_eq!(paused.body["paused"], true);
    assert_eq!(paused.body["email"], "owner@example.com");

    // A paused copy is not delivered, and the message is still accepted.
    let (address, stop) = start_inbound(&app).await;
    let mut client = SmtpClient::connect(address).await;
    let (code, text) = client
        .deliver(
            "dana@example.org",
            "nobody-here@example.com",
            "Subject: while paused\r\n\r\nbody",
        )
        .await;
    assert_eq!(code, 250, "{text}");
    assert!(
        inbox_subjects(&app, app.account_id).await.is_empty(),
        "a paused assignee receives nothing"
    );

    let resumed = app
        .post("/v1/catchall/me/resume", Some(&app.full_key), json!({}))
        .await;
    assert_eq!(resumed.status, StatusCode::OK, "{:?}", resumed.body);
    assert_eq!(resumed.body["paused"], false);

    // The member holds nothing yet, so their listing is empty rather than a 403.
    let member_view = app.get("/v1/catchall", Some(&member_key)).await;
    assert_eq!(member_view.status, StatusCode::OK, "{:?}", member_view.body);
    assert_eq!(member_view.body.as_array().expect("array").len(), 0);

    // The admin force: assign the member, then pause and resume them.
    assign_catchall(&app, &app.full_key, "example.com", member_id).await;
    let forced = app
        .patch(
            &format!("/v1/catchall/example.com/assignments/{member_id}"),
            Some(&app.full_key),
            json!({"paused": true}),
        )
        .await;
    assert_eq!(forced.status, StatusCode::OK, "{:?}", forced.body);
    assert_eq!(forced.body["paused"], true);
    let forced_back = app
        .patch(
            &format!("/v1/catchall/example.com/assignments/{member_id}"),
            Some(&app.full_key),
            json!({"paused": false}),
        )
        .await;
    assert_eq!(forced_back.status, StatusCode::OK, "{:?}", forced_back.body);
    assert_eq!(forced_back.body["paused"], false);

    // The member now sees exactly their own row.
    let member_view = app.get("/v1/catchall", Some(&member_key)).await;
    assert_eq!(member_view.status, StatusCode::OK, "{:?}", member_view.body);
    let own = member_view.body.as_array().expect("array");
    assert_eq!(own.len(), 1);
    assert_eq!(own[0]["assignments"].as_array().expect("rows").len(), 1);
    assert_eq!(own[0]["assignments"][0]["account_id"], member_id);

    // Removing the assignment stops delivery and the self-service pause.
    let removed = app
        .delete(
            &format!("/v1/catchall/example.com/assign/{member_id}"),
            Some(&app.full_key),
        )
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT, "{:?}", removed.body);
    let gone = app
        .post("/v1/catchall/me/pause", Some(&member_key), json!({}))
        .await;
    gone.assert_problem(StatusCode::CONFLICT, "conflict");

    // And the message sent while the owner was paused is still the only one: the
    // resumed owner receives the next message, nobody receives the old one.
    let mut client = SmtpClient::connect(address).await;
    let (code, text) = client
        .deliver(
            "dana@example.org",
            "another-ghost@example.com",
            "Subject: after resume\r\n\r\nbody",
        )
        .await;
    assert_eq!(code, 250, "{text}");
    assert_eq!(
        inbox_subjects(&app, app.account_id).await,
        vec!["after resume".to_string()]
    );
    assert!(
        inbox_subjects(&app, member_id).await.is_empty(),
        "an unassigned mailbox receives nothing"
    );
    let _ = stop.send(());
}

#[tokio::test]
async fn catchall_rules_require_a_real_domain_and_an_admin() {
    let app = TestApp::new();

    let discard_with_target = app
        .call(build(
            Method::PUT,
            "/v1/catchall/example.com",
            Some(&app.full_key),
            Some(json!({"action": "discard", "target_account_id": app.account_id})),
            &[],
        ))
        .await;
    discard_with_target.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");

    // The domain itself is validated, and an unknown action is a 422.
    let bad_domain = put_catchall(&app, &app.full_key, "not-a-domain", "discard").await;
    bad_domain.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");
    let bad_action = put_catchall(&app, &app.full_key, "example.com", "bounce").await;
    bad_action.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");

    // A plain member may not change the domain decision, and may not assign.
    let (member_id, member_key) = app
        .org_member("lead@other.example", "eli@other.example")
        .await;
    let forbidden = put_catchall(&app, &member_key, "other.example", "discard").await;
    forbidden.assert_problem(StatusCode::FORBIDDEN, "forbidden");
    let forbidden_assign = assign_catchall(&app, &member_key, "other.example", member_id).await;
    forbidden_assign.assert_problem(StatusCode::FORBIDDEN, "forbidden");
}

// ---------------------------------------------------------------------------
// Sender aliases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sender_aliases_are_free_addresses_an_admin_shares() {
    let app = TestApp::new();

    // A free address on a served domain: created by the owner, `201`.
    let created = app
        .post(
            "/v1/aliases",
            Some(&app.full_key),
            json!({"address": "Sales@Example.com"}),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    assert_eq!(
        created.body["address"], "sales@example.com",
        "the stored alias is normalized"
    );
    assert_eq!(created.body["domain"], "example.com");
    let alias_id = created.body["id"].as_i64().expect("alias id");

    // Collisions and nonsense are refused with distinct answers.
    let duplicate = app
        .post(
            "/v1/aliases",
            Some(&app.full_key),
            json!({"address": "sales@example.com"}),
        )
        .await;
    duplicate.assert_problem(StatusCode::CONFLICT, "conflict");
    let owned_by_an_account = app
        .post(
            "/v1/aliases",
            Some(&app.full_key),
            json!({"address": "owner@example.com"}),
        )
        .await;
    owned_by_an_account.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");
    assert_eq!(owned_by_an_account.body["errors"][0]["field"], "address");
    let foreign_domain = app
        .post(
            "/v1/aliases",
            Some(&app.full_key),
            json!({"address": "sales@elsewhere.example"}),
        )
        .await;
    foreign_domain.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");
    let not_an_address = app
        .post(
            "/v1/aliases",
            Some(&app.full_key),
            json!({"address": "sales"}),
        )
        .await;
    not_an_address.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");

    // A member may read their own list and nothing else.
    let (member_id, member_key) = app
        .org_member("team-lead@example.com", "eli@example.com")
        .await;
    let member_create = app
        .post(
            "/v1/aliases",
            Some(&member_key),
            json!({"address": "soporte@example.com"}),
        )
        .await;
    member_create.assert_problem(StatusCode::FORBIDDEN, "forbidden");
    let member_list = app.get("/v1/aliases", Some(&member_key)).await;
    assert_eq!(member_list.status, StatusCode::OK, "{:?}", member_list.body);
    assert_eq!(member_list.body.as_array().expect("array").len(), 0);

    // Assigning shares the address; assigning twice is a conflict.
    let assigned = app
        .post(
            &format!("/v1/aliases/{alias_id}/assign"),
            Some(&app.full_key),
            json!({"account_id": member_id}),
        )
        .await;
    assert_eq!(assigned.status, StatusCode::OK, "{:?}", assigned.body);
    assert_eq!(assigned.body["assignments"][0]["account_id"], member_id);
    assert_eq!(assigned.body["assignments"][0]["email"], "eli@example.com");
    let again = app
        .post(
            &format!("/v1/aliases/{alias_id}/assign"),
            Some(&app.full_key),
            json!({"account_id": member_id}),
        )
        .await;
    again.assert_problem(StatusCode::CONFLICT, "conflict");

    // The member now sees it: this is the compose-box list.
    let mine = app.get("/v1/aliases?mine=1", Some(&member_key)).await;
    assert_eq!(mine.status, StatusCode::OK, "{:?}", mine.body);
    assert_eq!(mine.body.as_array().expect("array").len(), 1);
    assert_eq!(mine.body[0]["address"], "sales@example.com");

    // Unassigning stops it being theirs; deleting the alias removes it entirely.
    let unassigned = app
        .post(
            &format!("/v1/aliases/{alias_id}/unassign"),
            Some(&app.full_key),
            json!({"account_id": member_id}),
        )
        .await;
    assert_eq!(unassigned.status, StatusCode::OK, "{:?}", unassigned.body);
    assert!(unassigned.body["assignments"]
        .as_array()
        .expect("array")
        .is_empty());
    let unassigned_again = app
        .post(
            &format!("/v1/aliases/{alias_id}/unassign"),
            Some(&app.full_key),
            json!({"account_id": member_id}),
        )
        .await;
    unassigned_again.assert_problem(StatusCode::NOT_FOUND, "not-found");

    let deleted = app
        .delete(&format!("/v1/aliases/{alias_id}"), Some(&app.full_key))
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{:?}", deleted.body);
    let deleted_again = app
        .delete(&format!("/v1/aliases/{alias_id}"), Some(&app.full_key))
        .await;
    deleted_again.assert_problem(StatusCode::NOT_FOUND, "not-found");
}

#[tokio::test]
async fn a_member_account_cannot_take_a_sender_alias_address() {
    let app = TestApp::new();
    let org_id = app.create_org(&app.full_key, "Acme").await;
    let alias = app
        .post(
            "/v1/aliases",
            Some(&app.full_key),
            json!({"address": "sales@example.com"}),
        )
        .await;
    assert_eq!(alias.status, StatusCode::CREATED, "{:?}", alias.body);
    let alias_id = alias.body["id"].as_i64().expect("alias id");

    // The invariant: an address is either a mailbox or an alias, never both. A
    // mailbox on top of an alias would divert the shared address into one inbox.
    let refused = app
        .post(
            &format!("/v1/orgs/{org_id}/members"),
            Some(&app.full_key),
            json!({"email": "sales@example.com", "display_name": "Sales", "role": "member"}),
        )
        .await;
    refused.assert_problem(StatusCode::CONFLICT, "conflict");
    assert!(
        refused.body["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("sender alias")),
        "the detail has to say why: {:?}",
        refused.body
    );

    // Nothing was created, and the alias still owns the address.
    let members = app
        .get(&format!("/v1/orgs/{org_id}/members"), Some(&app.full_key))
        .await;
    assert_eq!(members.status, StatusCode::OK, "{:?}", members.body);
    let listed = members.body.as_array().expect("members");
    assert_eq!(listed.len(), 1, "only the owner exists: {listed:?}");
    assert!(
        listed
            .iter()
            .all(|member| member["email"] != "sales@example.com"),
        "{listed:?}"
    );
    assert!(
        app.state
            .store
            .get_account_by_email("sales@example.com")
            .expect("lookup")
            .is_none(),
        "no mailbox took the alias address"
    );

    // Delivery is not diverted: mail to the alias still goes to its holders, and
    // to nobody else.
    app.post(
        &format!("/v1/aliases/{alias_id}/assign"),
        Some(&app.full_key),
        json!({"account_id": app.account_id}),
    )
    .await;
    let (address, stop) = start_inbound(&app).await;
    let mut client = SmtpClient::connect(address).await;
    let (code, text) = client
        .deliver(
            "dana@example.org",
            "sales@example.com",
            "Subject: sigue siendo alias\r\n\r\nbody",
        )
        .await;
    assert_eq!(code, 250, "{text}");
    let _ = stop.send(());
    let inbox = app
        .state
        .store
        .list_folder(app.account_id, pigeon_core::MessageFolder::Inbox, 10, 0)
        .expect("inbox");
    assert_eq!(inbox.len(), 1, "{inbox:?}");
    assert_eq!(
        inbox[0].delivered_for.as_deref(),
        Some("sales@example.com")
    );

    // A genuine duplicate mailbox is still a `409`, with its own detail: the two
    // collisions are distinguishable for whoever has to fix them.
    let duplicate = app
        .post(
            &format!("/v1/orgs/{org_id}/members"),
            Some(&app.full_key),
            json!({"email": "owner@example.com", "role": "member"}),
        )
        .await;
    duplicate.assert_problem(StatusCode::CONFLICT, "conflict");
    assert!(
        duplicate.body["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("already has an account")),
        "{:?}",
        duplicate.body
    );
}

#[tokio::test]
async fn a_catchall_assignment_without_a_rule_is_a_404_and_changes_nothing() {
    let app = TestApp::new();

    // The rule is the domain decision; an assignment it can never apply to would
    // be a grant the listing shows and delivery ignores.
    let refused = assign_catchall(&app, &app.full_key, "example.com", app.account_id).await;
    refused.assert_problem(StatusCode::NOT_FOUND, "not-found");
    assert!(
        refused.body["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("no catch-all rule")),
        "{:?}",
        refused.body
    );

    // Nothing persisted: the refused call must not leave a row the next listing
    // would report.
    let listed = app.get("/v1/catchall", Some(&app.full_key)).await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
    assert!(
        listed.body.as_array().expect("array").is_empty(),
        "{:?}",
        listed.body
    );
    assert!(
        app.state
            .store
            .list_catchall_assignments()
            .expect("assignments")
            .is_empty(),
        "a refused assignment writes no row"
    );

    // With the rule in place the same call succeeds.
    let rule = put_catchall(&app, &app.full_key, "example.com", "route").await;
    assert_eq!(rule.status, StatusCode::OK, "{:?}", rule.body);
    let assigned = assign_catchall(&app, &app.full_key, "example.com", app.account_id).await;
    assert_eq!(assigned.status, StatusCode::OK, "{:?}", assigned.body);
    assert_eq!(
        assigned.body["assignments"][0]["account_id"],
        app.account_id
    );
}

#[tokio::test]
async fn the_alias_self_view_needs_send_scope_and_the_mutations_need_full() {
    let app = TestApp::new();
    let send_key = app.key_with(&[ApiKeyScope::Send], false);

    // The compose box asks with a `send` key: the self view must answer it.
    let mine = app.get("/v1/aliases?mine=1", Some(&send_key)).await;
    assert_eq!(mine.status, StatusCode::OK, "{:?}", mine.body);

    // Creating one is account administration, not a send.
    let refused = app
        .post(
            "/v1/aliases",
            Some(&send_key),
            json!({"address": "sales@example.com"}),
        )
        .await;
    refused.assert_problem(StatusCode::FORBIDDEN, "forbidden");

    // The member's own pause switch is `send` too (it changes where their mail
    // lands, but only their own): it answers 409 for a caller holding nothing,
    // which is proof the scope gate let it through.
    let pause = app
        .post("/v1/catchall/me/pause", Some(&send_key), json!({}))
        .await;
    pause.assert_problem(StatusCode::CONFLICT, "conflict");
}

#[tokio::test]
async fn a_sender_may_only_send_as_itself_or_an_assigned_alias() {
    let app = TestApp::new();
    let (member_id, member_key) = app
        .org_member("team-lead@example.com", "eli@example.com")
        .await;

    let alias = app
        .post(
            "/v1/aliases",
            Some(&app.full_key),
            json!({"address": "sales@example.com"}),
        )
        .await;
    let alias_id = alias.body["id"].as_i64().expect("alias id");

    // Not assigned yet: the member cannot send as it.
    let refused = app
        .post(
            "/v1/emails",
            Some(&member_key),
            json!({
                "from": "sales@example.com",
                "to": ["carol@example.org"],
                "subject": "hi",
                "text": "x",
            }),
        )
        .await;
    refused.assert_problem(StatusCode::FORBIDDEN, "from-not-allowed");

    app.post(
        &format!("/v1/aliases/{alias_id}/assign"),
        Some(&app.full_key),
        json!({"account_id": member_id}),
    )
    .await;

    // Assigned: sending as the alias is allowed, in any letter case.
    let accepted = app
        .post(
            "/v1/emails",
            Some(&member_key),
            json!({
                "from": "Sales <Sales@Example.com>",
                "to": ["carol@example.org"],
                "subject": "from the alias",
                "text": "x",
            }),
        )
        .await;
    assert_eq!(accepted.status, StatusCode::ACCEPTED, "{:?}", accepted.body);
    let id = accepted.body["id"].as_str().expect("id");
    let view = app
        .get(&format!("/v1/emails/{id}"), Some(&member_key))
        .await;
    // The local part keeps the case the caller wrote (SMTP may treat it as
    // significant); only the domain is folded, which is what the check compared.
    assert_eq!(view.body["from"], "Sales@example.com");

    // Somebody else's address is still refused, alias or not.
    let stranger = app
        .post(
            "/v1/emails",
            Some(&member_key),
            json!({
                "from": "owner@example.com",
                "to": ["carol@example.org"],
                "subject": "spoof",
                "text": "x",
            }),
        )
        .await;
    stranger.assert_problem(StatusCode::FORBIDDEN, "from-not-allowed");
}

#[tokio::test]
async fn mail_to_an_alias_reaches_every_assignee_and_files_under_its_address() {
    let app = TestApp::new();
    let (second_id, _) = app.account_with_key("second@example.com");
    let alias = app
        .post(
            "/v1/aliases",
            Some(&app.full_key),
            json!({"address": "sales@example.com"}),
        )
        .await;
    let alias_id = alias.body["id"].as_i64().expect("alias id");
    for account_id in [app.account_id, second_id] {
        app.post(
            &format!("/v1/aliases/{alias_id}/assign"),
            Some(&app.full_key),
            json!({"account_id": account_id}),
        )
        .await;
    }

    let (address, stop) = start_inbound(&app).await;
    let mut client = SmtpClient::connect(address).await;
    let (code, text) = client
        .deliver(
            "dana@example.org",
            "sales@example.com",
            "Subject: pedido nuevo\r\nFrom: dana@example.org\r\n\r\nbody",
        )
        .await;
    assert_eq!(code, 250, "{text}");

    for account_id in [app.account_id, second_id] {
        let rows = app
            .state
            .store
            .list_folder(account_id, pigeon_core::MessageFolder::Inbox, 10, 0)
            .expect("inbox");
        assert_eq!(rows.len(), 1, "account {account_id}: {rows:?}");
        assert_eq!(rows[0].subject, "pedido nuevo");
        assert_eq!(rows[0].delivered_for.as_deref(), Some("sales@example.com"));
        let events = app.state.store.list_events(rows[0].id).expect("events");
        assert!(events[0].1.contains("via=alias"), "{:?}", events[0]);
    }

    // The pseudo-folder listing narrows the inbox to that address, and carries a
    // count so the sidebar can render it without a second request.
    let filtered = app
        .get(
            "/v1/messages?folder=inbox&delivered_for=sales@example.com",
            Some(&app.full_key),
        )
        .await;
    assert_eq!(filtered.status, StatusCode::OK, "{:?}", filtered.body);
    assert_eq!(filtered.body["page"]["total"], 1);
    assert_eq!(
        filtered.body["items"][0]["delivered_for"],
        "sales@example.com"
    );
    assert_eq!(
        filtered.body["delivered_for_counts"][0]["address"],
        "sales@example.com"
    );
    assert_eq!(filtered.body["delivered_for_counts"][0]["count"], 1);

    let empty = app
        .get(
            "/v1/messages?delivered_for=nobody@example.com",
            Some(&app.full_key),
        )
        .await;
    assert_eq!(empty.body["page"]["total"], 0);
    let invalid = app
        .get(
            "/v1/messages?delivered_for=not-an-address",
            Some(&app.full_key),
        )
        .await;
    invalid.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");

    // Removing one holder stops that mailbox receiving the next one; the alias
    // itself keeps delivering to whoever is left.
    let removed = app
        .post(
            &format!("/v1/aliases/{alias_id}/unassign"),
            Some(&app.full_key),
            json!({"account_id": second_id}),
        )
        .await;
    assert_eq!(removed.status, StatusCode::OK, "{:?}", removed.body);
    let mut client = SmtpClient::connect(address).await;
    let (code, text) = client
        .deliver(
            "dana@example.org",
            "sales@example.com",
            "Subject: segunda orden\r\n\r\nbody",
        )
        .await;
    assert_eq!(code, 250, "{text}");
    assert_eq!(
        inbox_subjects(&app, app.account_id).await.len(),
        2,
        "the remaining holder keeps receiving"
    );
    assert_eq!(
        inbox_subjects(&app, second_id).await,
        vec!["pedido nuevo".to_string()],
        "the removed holder receives nothing new"
    );
    let _ = stop.send(());
}

// ---------------------------------------------------------------------------
// Layer 3 — WKD publication and honest e2e reporting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wkd_publishes_the_key_of_a_local_account_and_nothing_else() {
    let app = TestApp::new();

    let published = app
        .get("/.well-known/pigeon-pgp?email=owner%40example.com", None)
        .await;
    assert_eq!(published.status, StatusCode::OK, "{:?}", published.body);
    assert_eq!(
        published.headers[header::CONTENT_TYPE],
        "application/pgp-keys",
        "the published answer declares what it is"
    );
    let armor = published.body.as_str().expect("armored key");
    assert!(armor.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    assert!(
        !armor.contains("PRIVATE KEY"),
        "a key directory publishes public halves only"
    );

    // The published key really is the account's key: the store agrees.
    let (stored, fingerprint) = app
        .state
        .store
        .get_pgp_public_by_email("owner@example.com")
        .expect("lookup")
        .expect("published row");
    assert_eq!(stored, armor);
    assert_eq!(fingerprint.len(), 40);

    // Addresses this instance does not serve publish nothing.
    let foreign = app
        .get("/.well-known/pigeon-pgp?email=carol%40example.org", None)
        .await;
    foreign.assert_problem(StatusCode::NOT_FOUND, "not-found");

    // A malformed request explains itself instead of 404-ing silently.
    let missing = app.get("/.well-known/pigeon-pgp", None).await;
    missing.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");
    let invalid = app
        .get("/.well-known/pigeon-pgp?email=not-an-address", None)
        .await;
    invalid.assert_problem(StatusCode::UNPROCESSABLE_ENTITY, "validation");
}

#[tokio::test]
async fn advanced_wkd_serves_the_binary_key_under_its_zbase32_hash() {
    let app = TestApp::new();
    let hash = pigeon_api::wkd::zbase32_sha1("owner");
    let path = format!("/.well-known/openpgpkey/example.com/hu/{hash}");
    let response = app.get(&path, None).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    assert_eq!(
        response.headers[header::CONTENT_TYPE],
        "application/octet-stream"
    );

    // The body is the same certificate, in binary: parse it back and compare the
    // fingerprint with the one the simple endpoint publishes.
    let (cert, fingerprint) =
        pigeon_crypto::parse_cert_with_fingerprint(&response.raw).expect("served key parses");
    assert_eq!(fingerprint.len(), 40);
    let (stored, stored_fingerprint) = app
        .state
        .store
        .get_pgp_public_by_email("owner@example.com")
        .expect("lookup")
        .expect("published row");
    assert_eq!(fingerprint, stored_fingerprint);
    let stored_cert = pigeon_crypto::parse_cert(stored.as_bytes()).expect("stored cert");
    assert_eq!(
        cert.fingerprint(),
        stored_cert.fingerprint(),
        "both endpoints serve one identity"
    );
}

/// The simple endpoint gates on the **served domain** before it looks anything up,
/// exactly like the advanced path: a foreign domain and a non-existent address on a
/// served domain are indistinguishable, so the endpoint is not an enumeration
/// oracle.
#[tokio::test]
async fn the_simple_endpoint_answers_404_for_a_foreign_domain() {
    let app = TestApp::new();

    // A served domain with no such mailbox.
    let unknown_local = app
        .get("/.well-known/pigeon-pgp?email=nobody%40example.com", None)
        .await;
    unknown_local.assert_problem(StatusCode::NOT_FOUND, "not-found");

    // A domain this instance does not serve at all.
    let foreign = app
        .get(
            "/.well-known/pigeon-pgp?email=carol%40foreign.example",
            None,
        )
        .await;
    foreign.assert_problem(StatusCode::NOT_FOUND, "not-found");

    // Same status, same problem type, same shape: nothing tells the caller which
    // of the two it hit.
    assert_eq!(unknown_local.body["type"], foreign.body["type"]);
    assert_eq!(unknown_local.status, foreign.status);

    // And no key was created for the foreign address on the way.
    assert!(app
        .state
        .store
        .get_pgp_public_by_email("carol@foreign.example")
        .expect("lookup")
        .is_none());

    // The gate is "is this domain served", not "does this account exist": a second
    // account on the same domain still publishes after the first one answered.
    assert!(pigeon_api::wkd::served_domain(&app.state.store, "example.com").expect("served"));
    assert!(!pigeon_api::wkd::served_domain(&app.state.store, "foreign.example").expect("served"));
}

/// Both unauthenticated WKD routes share one per-address budget, and the refusal is
/// the contract's `429` with `Retry-After`.
#[tokio::test]
async fn the_wkd_endpoints_are_rate_limited_per_source_address() {
    let app = TestApp::new();
    // A fresh app has a full bucket; drain it from one address.
    let peer = ([203, 0, 113, 40], 5000);
    let mut limited = false;
    for _ in 0..(pigeon_api::rate_limit::WKD_RATE_BURST + 1) {
        let response = app
            .call(build_from(
                Method::GET,
                "/.well-known/pigeon-pgp?email=owner%40example.com",
                None,
                None,
                &[],
                peer,
            ))
            .await;
        if response.status == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            response.assert_problem(StatusCode::TOO_MANY_REQUESTS, "rate-limited");
            let retry_after = response.headers["retry-after"]
                .to_str()
                .expect("retry-after")
                .parse::<u64>()
                .expect("a number of seconds");
            assert!(retry_after >= 1, "the client is told when to come back");
            break;
        }
        assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    }
    assert!(
        limited,
        "a burst above WKD_RATE_BURST must be refused instead of served forever"
    );

    // The advanced route shares the budget: one directory, one limit.
    let advanced = app
        .call(build_from(
            Method::GET,
            &format!(
                "/.well-known/openpgpkey/example.com/hu/{}",
                pigeon_api::wkd::zbase32_sha1("owner")
            ),
            None,
            None,
            &[],
            peer,
        ))
        .await;
    advanced.assert_problem(StatusCode::TOO_MANY_REQUESTS, "rate-limited");

    // A different address is unaffected.
    let other = app
        .call(build_from(
            Method::GET,
            "/.well-known/pigeon-pgp?email=owner%40example.com",
            None,
            None,
            &[],
            ([203, 0, 113, 41], 5000),
        ))
        .await;
    assert_eq!(other.status, StatusCode::OK, "{:?}", other.body);
}

#[tokio::test]
async fn advanced_wkd_answers_404_for_a_wrong_hash_or_a_foreign_domain() {
    let app = TestApp::new();
    let wrong = app
        .get(
            "/.well-known/openpgpkey/example.com/hu/aaaaaaaaaaaaaaaa",
            None,
        )
        .await;
    wrong.assert_problem(StatusCode::NOT_FOUND, "not-found");
    let foreign = app
        .get(
            &format!(
                "/.well-known/openpgpkey/elsewhere.example/hu/{}",
                pigeon_api::wkd::zbase32_sha1("owner")
            ),
            None,
        )
        .await;
    foreign.assert_problem(StatusCode::NOT_FOUND, "not-found");
}

#[tokio::test]
async fn e2e_is_sealed_when_every_recipient_publishes_a_key() {
    let directory = Arc::new(KeyDirectory::default());
    let app = TestApp::with_state(ApiConfig::default(), directory.clone());
    let sandbox_key = app.key_with(&[ApiKeyScope::Full], true);

    let response = app
        .post(
            "/v1/emails",
            Some(&sandbox_key),
            json!({
                "from": "Dana <owner@example.com>",
                "to": ["carol@example.org"],
                "cc": ["dave@example.net"],
                "subject": "Sealed invoice",
                "text": "The renewal was processed.",
            }),
        )
        .await;
    assert_eq!(response.status, StatusCode::ACCEPTED, "{:?}", response.body);
    assert_eq!(
        response.body["e2e"], "sealed",
        "every recipient key was discovered: the payload must be sealed: {:?}",
        response.body
    );
    let id = response.body["id"].as_str().expect("id").to_string();

    // The lifecycle row carries the same honest value.
    let view = app
        .get(&format!("/v1/emails/{id}"), Some(&sandbox_key))
        .await;
    assert_eq!(view.body["e2e"], "sealed");

    // The stored MIME is a PGP/MIME message: headers in the clear, body sealed.
    let raw = app
        .get(&format!("/v1/emails/{id}?raw=true"), Some(&sandbox_key))
        .await;
    let mime = raw.body["mime"].as_str().expect("mime");
    assert!(
        mime.contains("Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\""),
        "{mime}"
    );
    assert!(mime.contains("Subject: Sealed invoice"), "{mime}");
    assert!(
        !mime.contains("The renewal was processed."),
        "the body must not survive in the clear: {mime}"
    );

    // Only the recipients' account keys open it — including the sender's own, so
    // the sent copy stays readable by the account that sent it.
    let payload = armored_payload(mime);
    let opened = pigeon_crypto::open_payload_with_key(
        directory.private_for("carol@example.org").as_bytes(),
        payload.as_bytes(),
    )
    .expect("the recipient's account key opens the seal");
    let opened = String::from_utf8(opened).expect("utf8");
    assert!(
        opened.contains("Content-Type: text/plain; charset=utf-8"),
        "{opened}"
    );
    assert!(
        opened.contains("VGhlIHJlbmV3YWwgd2FzIHByb2Nlc3NlZC4="),
        "the body part carries the original text (base64 per MIME): {opened}"
    );
    assert!(
        opened.contains("Content-Type:"),
        "the sealed entity is a MIME body part, headers included: {opened}"
    );
    assert!(
        pigeon_crypto::open_payload_with_key(
            directory.private_for("dave@example.net").as_bytes(),
            payload.as_bytes()
        )
        .is_ok(),
        "every recipient of the message can open it"
    );

    // The sender's own key opens the same payload (sent-folder readability).
    let own = pigeon_api::pgp::ensure_account_key(
        &app.state.store,
        &app.state.master_key,
        app.account_id,
        &EmailAddress::parse("owner@example.com").expect("address"),
    )
    .expect("own key");
    assert!(
        pigeon_crypto::open_payload_with_key(own.private_armored.as_bytes(), payload.as_bytes())
            .is_ok(),
        "the sending account must be able to read its own sent mail"
    );
}

#[tokio::test]
async fn a_recipient_without_a_key_makes_the_whole_message_tls_only() {
    // Only `carol` answers; `nokey.example` publishes nothing.
    let directory = Arc::new(KeyDirectory::only(&["carol@example.org"]));
    let app = TestApp::with_state(ApiConfig::default(), directory.clone());

    let response = app
        .post(
            "/v1/emails",
            Some(&app.full_key),
            json!({
                "from": "Dana <owner@example.com>",
                "to": ["carol@example.org", "stranger@nokey.example"],
                "subject": "Mixed",
                "text": "body",
            }),
        )
        .await;
    assert_eq!(response.status, StatusCode::ACCEPTED, "{:?}", response.body);
    assert_eq!(
        response.body["e2e"], "tls_only",
        "v1 is all-or-nothing: one unsealable recipient downgrades the whole message"
    );
}

#[tokio::test]
async fn a_local_recipient_keeps_the_message_tls_only() {
    // A second mailbox on this instance: delivery never leaves, layer 1 already
    // covers storage, and sealing would hide the mail from the webmail.
    let directory = Arc::new(KeyDirectory::default());
    let app = TestApp::with_state(ApiConfig::default(), directory);
    app.state
        .store
        .create_account(&EmailAddress::parse("mate@example.com").expect("address"))
        .expect("second account");

    let response = app
        .post(
            "/v1/emails",
            Some(&app.full_key),
            json!({
                "from": "Dana <owner@example.com>",
                "to": ["mate@example.com"],
                "subject": "Internal",
                "text": "body",
            }),
        )
        .await;
    assert_eq!(response.status, StatusCode::ACCEPTED, "{:?}", response.body);
    assert_eq!(response.body["e2e"], "tls_only");
}

#[tokio::test]
async fn an_explicit_plaintext_override_is_reported_and_never_seals() {
    let directory = Arc::new(KeyDirectory::default());
    let app = TestApp::with_state(
        ApiConfig {
            plaintext_override_domains: vec!["legacy.example".to_string()],
            ..ApiConfig::default()
        },
        directory.clone(),
    );
    let sandbox_key = app.key_with(&[ApiKeyScope::Full], true);

    let response = app
        .post(
            "/v1/emails",
            Some(&sandbox_key),
            json!({
                "from": "Dana <owner@example.com>",
                "to": ["archive@legacy.example"],
                "subject": "Overridden",
                "text": "readable on purpose",
            }),
        )
        .await;
    assert_eq!(response.status, StatusCode::ACCEPTED, "{:?}", response.body);
    assert_eq!(
        response.body["e2e"], "plaintext_override",
        "an operator opt-out is reported, never hidden behind tls_only"
    );

    // And the body really is in the clear: the override means what it says.
    let id = response.body["id"].as_str().expect("id");
    let raw = app
        .get(&format!("/v1/emails/{id}?raw=true"), Some(&sandbox_key))
        .await;
    let mime = raw.body["mime"].as_str().expect("mime");
    assert!(!mime.contains("multipart/encrypted"), "{mime}");
    assert!(
        mime.contains("cmVhZGFibGUgb24gcHVycG9zZQ=="),
        "the body is in the clear (base64 per MIME): {mime}"
    );
}

#[tokio::test]
async fn the_override_list_matches_case_insensitively() {
    let config = ApiConfig {
        plaintext_override_domains: vec!["Legacy.Example".to_string()],
        ..ApiConfig::default()
    };
    assert!(config.is_plaintext_override("legacy.example"));
    assert!(config.is_plaintext_override("LEGACY.EXAMPLE"));
    assert!(!config.is_plaintext_override("other.example"));
}
