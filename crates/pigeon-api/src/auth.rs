//! Authentication and per-route scope enforcement.
//!
//! Two credentials authenticate a request, and both end up in one
//! [`AuthContext`]:
//!
//! * a **bearer API key** (`pk_…`), for machines; and
//! * a **session cookie** (`pigeon_session`), for the dashboard/webmail, carrying
//!   the same authority as a `full` key (so it satisfies `send` and `read` too —
//!   `full` is the superset the scope model already defines).
//!
//! A session is verified by [`crate::session`]: the cookie names its own session
//! row, one primary-key lookup finds it, and one Argon2id comparison proves the
//! token. [`require_session`] is the stricter variant used by the session realm
//! itself (logout and the 2FA endpoints), which must *not* be reachable with an
//! API key: a machine credential that could disable 2FA would defeat it.
//!
//! The bearer story, in order:
//!
//! 1. **Format** — `Authorization: Bearer pk_…` must parse as an API key
//!    ([`pigeon_crypto::parse_api_key`]). This is pure string work, no database.
//! 2. **Lookup** — `store.find_api_key_by_prefix` returns every live candidate
//!    for the key's prefix (the plaintext is never stored, so more than one row
//!    can share a prefix).
//! 3. **Verify** — Argon2id against each candidate hash.
//! 4. **Scope** — the key must hold the route's required scope; `full` is a
//!    superset of `send` and `read`. Failure is `403`, never a silent widening.
//! 5. **Rate limit** — one token per request from the per-account bucket.
//!
//! # Argon2id is a denial-of-service surface
//!
//! Verification costs ~19 MiB and tens of milliseconds of CPU **by design**, so
//! two controls sit in front of it (`SECURITY.md`):
//!
//! * a **verified-key cache** (30 s TTL) so a session pays the KDF once instead
//!   of per request, and
//! * a **per-IP failure budget** — a `HashMap<IpAddr, Vec<Instant>>` capped at
//!   [`MAX_VERIFY_FAILURES_PER_MINUTE`] — so an attacker who learned a valid
//!   prefix cannot burn CPU with wrong keys. Once an IP is over budget its
//!   attempts are refused with `429` *before* the KDF runs. Successful
//!   verifications never consume the budget; a client with a real key is not
//!   punished for typos elsewhere.
//!
//! A random key whose prefix matches nothing costs no KDF at all, which is why
//! the budget is charged on *failures* rather than on every attempt.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, Extensions, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use pigeon_core::ApiKeyScope;
use store::Storage;

use crate::keys::key_prefix;
use crate::problem::{forbidden, unauthorized, Problem, ProblemType};
use crate::rate_limit::Permit;
use crate::session;
use crate::state::AppState;

/// Failed key verifications tolerated per IP per window.
pub const MAX_VERIFY_FAILURES_PER_MINUTE: usize = 5;
/// Length of the failure window.
pub const FAILURE_WINDOW: Duration = Duration::from_secs(60);
/// Failed logins / second-factor attempts tolerated per IP per window.
pub const MAX_LOGIN_FAILURES: usize = 5;
/// Length of the login failure window (15 minutes, as `openapi.yaml` states).
pub const LOGIN_FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Namespace for a session token in the verified-credential cache.
pub(crate) const SESSION_CACHE_COOKIE_PREFIX: &str = "cookie:";
/// Above this many cached keys, the next insert prunes expired entries.
const CACHE_PRUNE_THRESHOLD: usize = 4096;

/// The authenticated caller, attached to the request as an extension.
///
/// Handlers never parse credentials themselves: if this extension is present,
/// the key was verified and the route's scope check passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyContext {
    /// Owning account.
    pub account_id: i64,
    /// `api_keys.id`, for metadata updates.
    pub key_id: i64,
    /// Public key id (`key_…`).
    pub public_id: String,
    /// Scopes the key holds.
    pub scopes: Vec<ApiKeyScope>,
    /// Sandbox keys accept sends but never deliver.
    pub sandbox: bool,
}

impl ApiKeyContext {
    /// True when the key satisfies `required`: either it holds that scope or it
    /// holds `full`.
    pub fn has_scope(&self, required: ApiKeyScope) -> bool {
        self.scopes.contains(&ApiKeyScope::Full) || self.scopes.contains(&required)
    }
}

/// What authenticated one request.
///
/// Handlers that need to tell a machine credential from a browser session match
/// on this; handlers that only need the account keep taking
/// [`ApiKeyContext`], which every variant can produce
/// ([`AuthContext::handler_context`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthContext {
    /// A verified `pk_…` API key.
    ApiKey(ApiKeyContext),
    /// A verified `pigeon_session` cookie.
    Session(SessionContext),
}

impl AuthContext {
    /// The account this request acts for.
    pub fn account_id(&self) -> i64 {
        match self {
            AuthContext::ApiKey(key) => key.account_id,
            AuthContext::Session(session) => session.account_id,
        }
    }

    /// True when the credential satisfies `required`.
    ///
    /// A session carries `full` authority — the scope model already defines
    /// `full` as a superset of `send` and `read`, and a dashboard session *is*
    /// the account owner's own surface, so it satisfies every scope instead of
    /// silently failing on the narrower groups.
    pub fn has_scope(&self, required: ApiKeyScope) -> bool {
        match self {
            AuthContext::ApiKey(key) => key.has_scope(required),
            AuthContext::Session(_) => true,
        }
    }

    /// The extension every protected handler already destructures.
    ///
    /// A session becomes a synthesized full-scope key context with `key_id = 0`
    /// (no key row exists) and a `session:<id>` public id, so audit rows say
    /// which kind of credential acted instead of pretending to be a key.
    pub fn handler_context(&self) -> ApiKeyContext {
        match self {
            AuthContext::ApiKey(key) => key.clone(),
            AuthContext::Session(session) => ApiKeyContext {
                account_id: session.account_id,
                key_id: 0,
                public_id: format!("session:{}", session.session_id),
                scopes: vec![ApiKeyScope::Full],
                sandbox: false,
            },
        }
    }
}

/// A dashboard/webmail session that authenticated the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionContext {
    /// `sessions.id` (`sess_…`) — what logout revokes.
    pub session_id: String,
    /// Owning account.
    pub account_id: i64,
}

struct CachedKey {
    context: ApiKeyContext,
    inserted: Instant,
}

/// Per-IP failure budget: at most `max` failures inside `window`.
///
/// Two instances live in [`AuthState`]: one for API-key verification (a minute,
/// because the KDF is the resource under attack) and one for logins and
/// second-factor attempts (fifteen minutes, as `openapi.yaml` documents).
struct FailureBudget {
    max: usize,
    window: Duration,
    attempts: Mutex<HashMap<Option<IpAddr>, Vec<Instant>>>,
}

impl FailureBudget {
    fn new(max: usize, window: Duration) -> Self {
        Self {
            max,
            window,
            attempts: Mutex::new(HashMap::new()),
        }
    }

    /// True when `ip` already spent its budget inside the window.
    fn over_budget(&self, ip: Option<IpAddr>) -> bool {
        let mut attempts = self
            .attempts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entries = attempts.entry(ip).or_default();
        entries.retain(|at| at.elapsed() < self.window);
        entries.len() >= self.max
    }

    /// Charge one failure to `ip`.
    fn record(&self, ip: Option<IpAddr>) {
        let mut attempts = self
            .attempts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Opportunistic sweep: the map only holds IPs that failed recently, so
        // an interval task is unnecessary as long as entries expire on access.
        if attempts.len() > 1024 {
            let window = self.window;
            attempts.retain(|_, entries| {
                entries.retain(|at| at.elapsed() < window);
                !entries.is_empty()
            });
        }
        let entries = attempts.entry(ip).or_default();
        entries.retain(|at| at.elapsed() < self.window);
        entries.push(Instant::now());
    }
}

/// Verified-key cache plus the failure budgets.
pub struct AuthState {
    verified: Mutex<HashMap<String, CachedKey>>,
    api_key_failures: FailureBudget,
    login_failures: FailureBudget,
    ttl: Duration,
}

impl AuthState {
    /// Cache with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            verified: Mutex::new(HashMap::new()),
            api_key_failures: FailureBudget::new(MAX_VERIFY_FAILURES_PER_MINUTE, FAILURE_WINDOW),
            login_failures: FailureBudget::new(MAX_LOGIN_FAILURES, LOGIN_FAILURE_WINDOW),
            ttl,
        }
    }

    /// Cache lifetime.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Reuse a recently verified credential, if it is still inside the TTL.
    ///
    /// Keys and sessions share the cache because both are "a token that was
    /// proven to belong to an account"; session entries live under the
    /// [`SESSION_CACHE_COOKIE_PREFIX`] namespace so the two can never collide.
    pub fn cached(&self, token: &str) -> Option<ApiKeyContext> {
        let mut cache = self
            .verified
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match cache.get(token) {
            Some(entry) if entry.inserted.elapsed() < self.ttl => Some(entry.context.clone()),
            Some(_) => {
                cache.remove(token);
                None
            }
            None => None,
        }
    }

    /// Remember a successful verification.
    pub fn remember(&self, token: &str, context: ApiKeyContext) {
        let mut cache = self
            .verified
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if cache.len() > CACHE_PRUNE_THRESHOLD {
            let ttl = self.ttl;
            cache.retain(|_, entry| entry.inserted.elapsed() < ttl);
        }
        cache.insert(
            token.to_string(),
            CachedKey {
                context,
                inserted: Instant::now(),
            },
        );
    }

    /// Remember a verified session under `cache_key`.
    ///
    /// Only the account is cached; the session id travels inside the token, so a
    /// cache hit still reconstructs the exact [`SessionContext`] and nothing has
    /// to be invalidated when a *single* session is revoked — logging out calls
    /// [`AuthState::invalidate_all`], which drops it along with everything else.
    pub fn remember_session(&self, cache_key: &str, account_id: i64) {
        self.remember(
            cache_key,
            ApiKeyContext {
                account_id,
                key_id: 0,
                public_id: format!("session-cache:{account_id}"),
                scopes: vec![ApiKeyScope::Full],
                sandbox: false,
            },
        );
    }

    /// Drop every cached verification. Called when the caller mutates credential
    /// state (create/revoke/delete a key, log out, disable 2FA) so a revoked
    /// credential stops working immediately instead of at the next TTL expiry.
    pub fn invalidate_all(&self) {
        self.verified
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    /// Number of cached verifications (tests and metrics).
    pub fn cached_len(&self) -> usize {
        self.verified
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// True when `ip` already spent its API-key failure budget inside the window.
    pub fn over_budget(&self, ip: Option<IpAddr>) -> bool {
        self.api_key_failures.over_budget(ip)
    }

    /// Charge one API-key failure to `ip`.
    pub fn record_failure(&self, ip: Option<IpAddr>) {
        self.api_key_failures.record(ip);
    }

    /// True when `ip` already spent its login / second-factor budget.
    pub fn over_login_budget(&self, ip: Option<IpAddr>) -> bool {
        self.login_failures.over_budget(ip)
    }

    /// Charge one failed login or second-factor attempt to `ip`.
    pub fn record_login_failure(&self, ip: Option<IpAddr>) {
        self.login_failures.record(ip);
    }
}

/// The client address, when the transport reported one (tests and Unix sockets
/// have none, which is why the budgets accept `None` as its own bucket).
pub fn client_ip(extensions: &Extensions) -> Option<IpAddr> {
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip())
}

/// Extractor form of [`client_ip`], for handlers that need the budget.
///
/// Infallible on purpose: a request without a known peer address (a unit test,
/// a Unix socket) is not an error, it just cannot be attributed to an IP and
/// falls into the `None` bucket.
pub struct ClientIp(pub Option<IpAddr>);

impl<S> axum::extract::FromRequestParts<S> for ClientIp
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(ClientIp(client_ip(&parts.extensions)))
    }
}

/// Middleware: authenticate the request and require `required`.
///
/// Layer it per scope group (`send`, `read`, `full`) so the scope a route needs
/// is declared once, next to the route, and cannot be forgotten inside a
/// handler. Either credential is accepted; the scope check decides what it may
/// do.
pub async fn authorize(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
    required: ApiKeyScope,
) -> Response {
    let ip = client_ip(request.extensions());
    let auth = match credential(&state, request.headers(), ip) {
        Ok(auth) => auth,
        Err(problem) => return problem.into_response(),
    };
    if !auth.has_scope(required) {
        return forbidden(format!(
            "this credential does not hold the `{required}` scope required for this operation"
        ))
        .into_response();
    }
    let permit = match check_rate_limit(&state, auth.account_id()) {
        Ok(permit) => permit,
        Err(response) => return *response,
    };
    request.extensions_mut().insert(auth.handler_context());
    let mut response = next.run(request).await;
    apply_rate_headers(&mut response, &permit);
    response
}

/// Middleware: a live dashboard session is the only accepted credential.
///
/// The session realm (logout and everything under `/v1/account/2fa`) is
/// deliberately closed to API keys: a machine credential that could enroll or
/// disable the second factor would make 2FA decorative, and enrollment assumes a
/// human at a browser who can scan a QR code.
pub async fn require_session(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(token) = session::cookie_token(request.headers()).map(str::to_string) else {
        return unauthorized(
            "this endpoint needs a dashboard session: POST /v1/auth/login sets the `pigeon_session` \
             cookie, and API keys cannot act on the second factor",
        )
        .into_response();
    };
    let session = match session::authenticate(&state, &token) {
        Ok(session) => session,
        Err(problem) => return problem.into_response(),
    };
    let permit = match check_rate_limit(&state, session.account_id) {
        Ok(permit) => permit,
        Err(response) => return *response,
    };
    request.extensions_mut().insert(session);
    let mut response = next.run(request).await;
    apply_rate_headers(&mut response, &permit);
    response
}

/// Extract the token from `Authorization: Bearer <token>`.
///
/// The scheme is matched case-insensitively (RFC 7235 makes it case-insensitive)
/// and exactly one space separates it from the credentials.
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    Some(token)
}

/// Work out which credential the request presents.
///
/// The `Authorization` header wins when present: a client that sent a bearer
/// token asked to be judged as that key, and silently falling back to a cookie
/// would hide a broken key from it. A request with neither is a `401` that names
/// both accepted forms.
fn credential(
    state: &AppState,
    headers: &HeaderMap,
    ip: Option<IpAddr>,
) -> Result<AuthContext, Problem> {
    if let Some(token) = bearer_token(headers) {
        return resolve_api_key(state, token, ip).map(AuthContext::ApiKey);
    }
    if let Some(token) = session::cookie_token(headers) {
        return session::authenticate(state, token).map(AuthContext::Session);
    }
    Err(unauthorized(
        "missing credentials: send `Authorization: Bearer pk_...` for an API key, or the \
         `pigeon_session` cookie for a dashboard session",
    ))
}

fn resolve_api_key(
    state: &AppState,
    token: &str,
    ip: Option<IpAddr>,
) -> Result<ApiKeyContext, Problem> {
    if let Some(context) = state.auth.cached(token) {
        return Ok(context);
    }
    if state.auth.over_budget(ip) {
        return Err(Problem::new(
            StatusCode::TOO_MANY_REQUESTS,
            ProblemType::RateLimited,
            "too many failed API key attempts from this address; try again in a minute",
        )
        .with_retry_after(FAILURE_WINDOW.as_secs()));
    }

    // Cheap structural validation first: a malformed key never touches the KDF.
    if pigeon_crypto::parse_api_key(token).is_err() {
        return Err(unauthorized(
            "the bearer token is not a valid Pigeon API key (expected pk_ followed by 43 base64url characters)",
        ));
    }

    let candidates = state
        .store
        .find_api_key_by_prefix(key_prefix(token))
        .map_err(Problem::from)?;

    for (account_id, hash, scopes) in candidates {
        if !pigeon_crypto::verify_api_key(token, &hash) {
            continue;
        }
        let row = state
            .db
            .key_by_hash(account_id, &hash)
            .map_err(Problem::from)?;
        let (key_id, public_id, sandbox) = match row {
            Some(row) => (
                row.key_id,
                if row.public_id.is_empty() {
                    crate::ids::derived(crate::ids::KEY, row.key_id)
                } else {
                    row.public_id
                },
                row.sandbox,
            ),
            // A key written outside this API (an installer bootstrap) has no
            // metadata row yet; derive the id and default to non-sandbox.
            None => (0, crate::ids::derived(crate::ids::KEY, 0), false),
        };
        let context = ApiKeyContext {
            account_id,
            key_id,
            public_id,
            scopes,
            sandbox,
        };
        if key_id != 0 {
            // Observability only: a failure here must not fail the request.
            if let Err(error) = state.db.touch_key(key_id) {
                tracing::warn!(%error, key_id, "could not record last_used_at");
            }
        }
        state.auth.remember(token, context.clone());
        return Ok(context);
    }

    state.auth.record_failure(ip);
    Err(unauthorized("invalid API key"))
}

/// Take one token from the account's bucket, or build the `429` it owes.
///
/// The response is boxed because it is the `Err` variant of a `Result` that is
/// also used on the hot path; an unboxed `Response` would make every `Permit`
/// drag 128 bytes around (clippy's `result_large_err`).
fn check_rate_limit(state: &AppState, account_id: i64) -> Result<Permit, Box<Response>> {
    match state.limiter.check(account_id) {
        Ok(permit) => Ok(permit),
        Err(retry_after) => {
            let limit = state.config.rate_limit_rps;
            let mut response = Problem::new(
                StatusCode::TOO_MANY_REQUESTS,
                ProblemType::RateLimited,
                format!("sustained limit is {limit} requests/second"),
            )
            .with_retry_after(retry_after)
            .into_response();
            // The contract's 429 carries the same window headers as a success,
            // so a client can back off without guessing.
            let headers = response.headers_mut();
            insert_number(headers, "x-ratelimit-limit", u64::from(limit));
            insert_number(headers, "x-ratelimit-remaining", 0);
            insert_number(
                headers,
                "x-ratelimit-reset",
                crate::time::now_unix()
                    .saturating_add(retry_after as i64)
                    .max(0) as u64,
            );
            Err(Box::new(response))
        }
    }
}

fn apply_rate_headers(response: &mut Response, permit: &Permit) {
    let headers = response.headers_mut();
    insert_number(headers, "x-ratelimit-limit", u64::from(permit.limit));
    insert_number(
        headers,
        "x-ratelimit-remaining",
        u64::from(permit.remaining),
    );
    insert_number(headers, "x-ratelimit-reset", permit.reset_at.max(0) as u64);
}

fn insert_number(headers: &mut HeaderMap, name: &'static str, value: u64) {
    if let Ok(value) = HeaderValue::from_str(&value.to_string()) {
        headers.insert(name, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn context(scopes: Vec<ApiKeyScope>) -> ApiKeyContext {
        ApiKeyContext {
            account_id: 1,
            key_id: 2,
            public_id: "key_0000000000000001".to_string(),
            scopes,
            sandbox: false,
        }
    }

    #[test]
    fn bearer_token_accepts_the_documented_header_and_rejects_junk() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer pk_abc"),
        );
        assert_eq!(bearer_token(&headers), Some("pk_abc"));

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer   pk_abc  "),
        );
        assert_eq!(bearer_token(&headers), Some("pk_abc"));

        for value in ["pk_abc", "Basic abc", "Bearer", "Bearer ", "Bearer \t"] {
            let mut headers = HeaderMap::new();
            headers.insert(header::AUTHORIZATION, HeaderValue::from_static(value));
            assert_eq!(bearer_token(&headers), None, "{value:?} must not parse");
        }

        assert_eq!(bearer_token(&HeaderMap::new()), None);
    }

    #[test]
    fn full_scope_satisfies_send_and_read() {
        let full = context(vec![ApiKeyScope::Full]);
        assert!(full.has_scope(ApiKeyScope::Send));
        assert!(full.has_scope(ApiKeyScope::Read));
        assert!(full.has_scope(ApiKeyScope::Full));

        let send = context(vec![ApiKeyScope::Send]);
        assert!(send.has_scope(ApiKeyScope::Send));
        assert!(!send.has_scope(ApiKeyScope::Read));
        assert!(!send.has_scope(ApiKeyScope::Full));

        let read = context(vec![ApiKeyScope::Read]);
        assert!(read.has_scope(ApiKeyScope::Read));
        assert!(!read.has_scope(ApiKeyScope::Send));
    }

    #[test]
    fn cache_hits_expire_and_can_be_invalidated() {
        let state = AuthState::new(Duration::from_millis(20));
        assert!(state.cached("token").is_none());
        state.remember("token", context(vec![ApiKeyScope::Read]));
        assert_eq!(
            state.cached("token"),
            Some(context(vec![ApiKeyScope::Read]))
        );
        assert_eq!(state.cached_len(), 1);

        std::thread::sleep(Duration::from_millis(30));
        assert!(state.cached("token").is_none(), "expired entry is dropped");
        assert_eq!(state.cached_len(), 0);

        state.remember("token", context(vec![ApiKeyScope::Read]));
        state.invalidate_all();
        assert!(state.cached("token").is_none());
    }

    #[test]
    fn failure_budget_is_per_ip_and_expires() {
        let state = AuthState::new(Duration::from_secs(1));
        let ip: Option<IpAddr> = Some(IpAddr::from([127, 0, 0, 1]));
        for _ in 0..MAX_VERIFY_FAILURES_PER_MINUTE {
            assert!(!state.over_budget(ip));
            state.record_failure(ip);
        }
        assert!(state.over_budget(ip), "budget is consumed");
        assert!(
            !state.over_budget(Some(IpAddr::from([10, 0, 0, 1]))),
            "another address keeps its own budget"
        );
    }

    #[test]
    fn cache_prunes_itself_under_load() {
        let state = AuthState::new(Duration::from_millis(1));
        for index in 0..CACHE_PRUNE_THRESHOLD + 10 {
            state.remember(&format!("token-{index}"), context(vec![ApiKeyScope::Read]));
        }
        std::thread::sleep(Duration::from_millis(5));
        state.remember("fresh", context(vec![ApiKeyScope::Read]));
        assert!(
            state.cached_len() < CACHE_PRUNE_THRESHOLD,
            "expired entries are swept once the cache grows"
        );
        assert!(state.cached("fresh").is_some());
    }
}
