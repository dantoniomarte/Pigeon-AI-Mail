//! The dashboard session realm: cookie tokens, and the TOTP material that
//! protects them.
//!
//! # Token shape
//!
//! A session cookie is `<session_id>.<secret>` where `session_id` is the public
//! `sess_…` id and `secret` is 32 OS-random bytes as unpadded base64url. The
//! token therefore names its own row: verification is one primary-key lookup
//! followed by one hash comparison, with no table scan and no way for a bogus
//! cookie to make the server hash anything.
//!
//! # Hashing
//!
//! Only an Argon2id PHC hash of the token is stored, using the crate's existing
//! API-key hash (`pigeon_crypto::hash_api_key`) — the same "a database leak does
//! not hand out credentials" property. SHA-256 would be the textbook choice for
//! a 256-bit random token, but this crate's dependency set has no digest, and
//! Argon2id is strictly stronger; the cost is paid once per session per
//! [`AuthState`](crate::auth::AuthState) cache window, exactly like an API key.
//!
//! # Second factor
//!
//! `pigeon_crypto::Totp` verifies a code statelessly (RFC 6238, ±1 step). The
//! replay obligation is this layer's: the accepted step is persisted with
//! `Storage::set_totp_last_step`, which rejects any step that is not strictly
//! greater than the stored one. Recovery codes are single-use for the same
//! reason — the hash is removed from the list when it matches.

use axum::http::{header, HeaderMap};
use base64::Engine;
use pigeon_crypto::{MasterKey, Totp};

use crate::aad;
use crate::auth::{SessionContext, SESSION_CACHE_COOKIE_PREFIX};
use crate::base32;
use crate::ids;
use crate::problem::{internal, unauthorized, Problem};
use crate::state::AppState;
use crate::time;
use store::{Storage, TotpEnrollmentRow};

/// Name of the session cookie (`openapi.yaml` `sessionCookie`).
pub const SESSION_COOKIE: &str = "pigeon_session";
/// Session lifetime, in seconds (7 days). Matches the cookie's `Max-Age`.
pub const SESSION_TTL_SECS: u64 = 604_800;
/// Recovery codes issued on activation.
pub const RECOVERY_CODE_COUNT: usize = 10;
/// Random bytes behind one recovery code.
///
/// 15 bytes (120 bits) encode to exactly 20 base64url characters, which is the
/// length window the contract's `TotpCode` pattern allows
/// (`^[A-Za-z0-9-]{10,20}$`). 16 bytes would be 22 characters and no longer
/// schema-valid, so the extra byte would be unusable entropy.
pub const RECOVERY_CODE_BYTES: usize = 15;
/// TOTP steps of clock skew accepted in either direction.
pub const TOTP_WINDOW: u32 = 1;
/// Length of a TOTP step in seconds (RFC 6238 default, the authenticator
/// profile).
pub const TOTP_STEP_SECS: u64 = 30;

/// A freshly minted session, with the plaintext token that must now be set as a
/// cookie and never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedSession {
    /// Public session id (`sess_…`).
    pub session_id: String,
    /// The cookie value: session id, dot, secret.
    pub token: String,
    /// ISO 8601 expiry, ready for the response body.
    pub expires_at: String,
}

impl IssuedSession {
    /// The `Set-Cookie` header value for this session.
    ///
    /// `HttpOnly` keeps it away from page scripts, `SameSite=Strict` makes a
    /// cross-site form post unable to ride the cookie (CSRF), and `Path=/`
    /// scopes it to the whole dashboard. `Secure` is not set because a
    /// self-hosted v0.1 may serve plain HTTP on localhost; a deployment behind
    /// TLS terminates it at the proxy.
    pub fn set_cookie(&self) -> String {
        format!(
            "{SESSION_COOKIE}={}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL_SECS}",
            self.token
        )
    }
}

/// Mint a new session id: `sess_` plus 16 random hex characters.
pub fn new_session_id() -> String {
    ids::gen(ids::SESS)
}

/// Build the cookie token for `session_id`: `<id>.<32 random bytes b64url>`.
pub fn new_token(session_id: &str) -> String {
    let secret = pigeon_crypto::generate_content_key();
    format!(
        "{session_id}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret)
    )
}

/// The public session id carried by a token, or `None` when the value cannot be
/// a token at all (wrong shape, unknown prefix).
pub fn session_id_of(token: &str) -> Option<&str> {
    let (session_id, secret) = token.split_once('.')?;
    if !ids::is_well_formed(session_id, ids::SESS) || secret.len() != 43 {
        return None;
    }
    Some(session_id)
}

/// Hash a session token for storage.
pub fn hash_token(token: &str) -> Result<String, pigeon_crypto::CryptoError> {
    pigeon_crypto::hash_api_key(token)
}

/// Constant-work comparison of a presented token against its stored hash.
pub fn token_matches(token: &str, stored_hash: &str) -> bool {
    pigeon_crypto::verify_api_key(token, stored_hash)
}

/// The session cookie value from a request's `Cookie` header(s).
///
/// Multiple `Cookie` headers are legal (RFC 6265 §5.4) and a browser may send
/// one per origin path, so every header is searched. The last match wins, which
/// is what a cookie jar that overwrote an older value would have sent.
pub fn cookie_token(headers: &HeaderMap) -> Option<&str> {
    let mut found = None;
    for value in headers.get_all(header::COOKIE) {
        let Ok(value) = value.to_str() else { continue };
        for pair in value.split(';') {
            let Some((name, cookie)) = pair.trim().split_once('=') else {
                continue;
            };
            if name.trim() == SESSION_COOKIE && !cookie.trim().is_empty() {
                found = Some(cookie.trim());
            }
        }
    }
    found
}

/// Create and persist a session for `account_id`.
pub fn issue(state: &AppState, account_id: i64) -> Result<IssuedSession, Problem> {
    let session_id = new_session_id();
    let token = new_token(&session_id);
    let token_hash = hash_token(&token).map_err(internal)?;
    let expires_at = state
        .store
        .create_session(&session_id, account_id, &token_hash, SESSION_TTL_SECS)
        .map_err(Problem::from)?;
    Ok(IssuedSession {
        session_id,
        token,
        // The row stores SQLite's `YYYY-MM-DD HH:MM:SS`; the API speaks ISO 8601.
        expires_at: time::iso_from_sqlite(&expires_at),
    })
}

/// Redeem a bootstrap/invitation token for `account_id`, burning it.
///
/// This is the second-factor slot of the login for an account that has **no**
/// TOTP yet: `POST /v1/orgs/{id}/members` hands the new member a one-time token,
/// and presenting it in `code` proves the person logging in is the one the admin
/// created. Only an invitation addressed to this account's own address is
/// redeemable — anything else is `Ok(false)`, so a token for a colleague's mailbox
/// cannot be spent here.
///
/// `Ok(true)` means the token was pending, matched and is now spent: the store
/// burns it in the same transaction that attaches the account to the organization,
/// so a replay is `Ok(false)` and the login is refused.
pub fn consume_bootstrap_token(
    state: &AppState,
    account_id: i64,
    email_norm: &str,
    token: &str,
) -> Result<bool, Problem> {
    let Some(invitation) = state
        .store
        .get_invitation_by_token(token)
        .map_err(Problem::from)?
    else {
        return Ok(false);
    };
    if invitation.email != email_norm {
        // Right shape, wrong address: refuse rather than spend somebody else's
        // invitation (which would attach this account to a team it was never
        // invited to).
        return Ok(false);
    }
    state
        .store
        .accept_invitation(invitation.id, account_id)
        .map_err(Problem::from)?;
    Ok(true)
}

/// Verify a session token and return the authenticated session.
///
/// A cached verification short-circuits the KDF, exactly like the API-key path:
/// the Argon2id cost is paid once per cache window, not once per request.
///
/// A failed verification is deliberately *not* charged to the API-key failure
/// budget: the only way to make the server hash anything is to present an
/// existing session id (64 random bits) with the wrong secret, so there is no
/// guessing path that burns CPU, while charging every stale cookie would `429` a
/// browser that merely logged out in another tab.
pub fn authenticate(state: &AppState, token: &str) -> Result<SessionContext, Problem> {
    let Some(session_id) = session_id_of(token) else {
        return Err(unauthorized(
            "the session cookie is not a Pigeon session token (expected `sess_…` followed by `.` \
             and a 43-character base64url secret)",
        ));
    };
    if let Some(cached) = state.auth.cached(&cache_key(token)) {
        return Ok(SessionContext {
            session_id: session_id.to_string(),
            account_id: cached.account_id,
        });
    }
    let Some(row) = state
        .store
        .get_session_by_id(session_id)
        .map_err(Problem::from)?
    else {
        return Err(unauthorized("the session is unknown, expired or revoked"));
    };
    if !token_matches(token, &row.token_hash) {
        return Err(unauthorized(
            "the session cookie does not match its session",
        ));
    }
    // Cache the account under the full-token key: revoking, disabling 2FA or
    // logging out calls `AuthState::invalidate_all`, so a dead session cannot
    // keep working for the rest of the TTL.
    state
        .auth
        .remember_session(&cache_key(token), row.account_id);
    Ok(SessionContext {
        session_id: row.id,
        account_id: row.account_id,
    })
}

/// Cache key for a session token, namespaced so it can never collide with an
/// API key that happens to be the same string.
fn cache_key(token: &str) -> String {
    format!("{SESSION_CACHE_COOKIE_PREFIX}{token}")
}

/// Wrap a TOTP secret under the master key, bound to `totp:{account_id}`.
///
/// The wrapping primitive takes a 32-byte key and the TOTP secret is 20 bytes
/// (RFC 4226 recommendation), so the secret occupies the first 20 bytes and the
/// remaining 12 are zero. That tail adds no entropy and none is needed — the
/// secret itself carries 160 bits — while the AEAD still authenticates the whole
/// 32-byte value, so a tampered or transplanted secret fails to open.
pub fn wrap_totp_secret(
    master_key: &MasterKey,
    account_id: i64,
    secret: &[u8],
) -> Result<Vec<u8>, pigeon_crypto::CryptoError> {
    let mut key = [0u8; 32];
    let length = secret.len().min(key.len());
    key[..length].copy_from_slice(&secret[..length]);
    master_key.wrap_content_key(&key, aad::totp(account_id).as_bytes())
}

/// Open a wrapped TOTP secret, truncating the zero padding.
pub fn open_totp_secret(
    master_key: &MasterKey,
    account_id: i64,
    wrapped: &[u8],
) -> Result<Vec<u8>, pigeon_crypto::CryptoError> {
    let key = master_key.unwrap_content_key(wrapped, aad::totp(account_id).as_bytes())?;
    let length = pigeon_crypto::totp::RECOMMENDED_SECRET_LEN.min(key.len());
    Ok(key[..length].to_vec())
}

/// The `otpauth://` provisioning URI an authenticator app scans.
///
/// `SHA1`/6 digits/30 s is the interoperable default every app supports, and it
/// is exactly what [`Totp::try_new`] builds (SHA-1, 6 digits, 30-second step), so
/// the URI cannot drift from the verifier.
pub fn otpauth_uri(account_email: &str, secret_base32: &str) -> String {
    let issuer = "Pigeon";
    let label = format!("{issuer}:{account_email}");
    // Label and issuer are URL-encoded because an address can contain `+` or
    // `@`, which an authenticator would otherwise mis-parse.
    format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period={TOTP_STEP_SECS}",
        encode_component(&label),
        secret_base32,
        encode_component(issuer)
    )
}

/// Base32 encoding of a raw secret (no padding, uppercase).
pub fn secret_base32(secret: &[u8]) -> String {
    base32::encode(secret)
}

/// True when `code` has the shape of a TOTP code (6 or 8 digits). Anything else
/// is treated as a recovery code.
pub fn is_totp_code(code: &str) -> bool {
    let length = code.len();
    (length == 6 || length == 8) && code.bytes().all(|byte| byte.is_ascii_digit())
}

/// Ten fresh recovery codes, in issuance order.
pub fn new_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODE_COUNT)
        .map(|_| {
            let random = pigeon_crypto::generate_content_key();
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&random[..RECOVERY_CODE_BYTES])
        })
        .collect()
}

/// Verify a TOTP or recovery code against an account's enrollment.
///
/// Returns `Ok(true)` only when the code was accepted **and consumed**: the TOTP
/// step was advanced, or the recovery code was removed from the stored list. A
/// replayed code therefore returns `Ok(false)` on the second use.
pub fn consume_second_factor(
    state: &AppState,
    account_id: i64,
    enrollment: &TotpEnrollmentRow,
    code: &str,
) -> Result<bool, Problem> {
    if is_totp_code(code) {
        let secret = open_totp_secret(&state.master_key, account_id, &enrollment.secret_wrapped)
            .map_err(internal)?;
        let totp = Totp::try_new(&secret).map_err(internal)?;
        let now = time::now_unix().max(0) as u64;
        if !totp.verify(code, now, TOTP_WINDOW) {
            return Ok(false);
        }
        // Record *this* step: the code is spent for the whole window, including
        // the neighbour steps it might have matched, so a second presentation is
        // always a replay.
        let step = (now / TOTP_STEP_SECS) as i64;
        return state
            .store
            .set_totp_last_step(account_id, step)
            .map_err(Problem::from);
    }
    // Recovery code: compare against every unused hash (Argon2id, so this is
    // deliberately the slow path) and burn the one that matches.
    for (index, stored_hash) in enrollment.recovery_codes.iter().enumerate() {
        if token_matches(code, stored_hash) {
            return state
                .store
                .burn_recovery_code(account_id, index)
                .map_err(Problem::from);
        }
    }
    Ok(false)
}

/// Percent-encode a URI component (RFC 3986 unreserved characters pass through).
/// `url`-crate semantics for the tiny alphabet an `otpauth://` label needs.
fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_name_their_session_and_reject_junk() {
        let session_id = new_session_id();
        assert!(ids::is_well_formed(&session_id, ids::SESS));
        let token = new_token(&session_id);
        assert_eq!(session_id_of(&token), Some(session_id.as_str()));
        assert_eq!(token.len(), session_id.len() + 1 + 43);

        for junk in [
            "",
            "nonsense",
            "sess_0000000000000001",
            "sess_0000000000000001.",
            "sess_0000000000000001.short",
            "key_0000000000000001.dGhpcyBpcyBub3QgYSBzZXNzaW9uIHRva2VuISEhISEh",
        ] {
            assert_eq!(session_id_of(junk), None, "{junk:?} must not parse");
        }
    }

    #[test]
    fn every_minted_token_is_distinct() {
        let session_id = new_session_id();
        let first = new_token(&session_id);
        let second = new_token(&session_id);
        assert_ne!(first, second, "the secret half is fresh per session");
    }

    #[test]
    fn the_cookie_carries_the_security_attributes() {
        let session = IssuedSession {
            session_id: "sess_0000000000000001".to_string(),
            token: "sess_0000000000000001.secret".to_string(),
            expires_at: "2026-11-06T00:00:00Z".to_string(),
        };
        let cookie = session.set_cookie();
        assert!(cookie.starts_with(&format!("{SESSION_COOKIE}=")));
        for attribute in ["HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=604800"] {
            assert!(cookie.contains(attribute), "{attribute} missing: {cookie}");
        }
    }

    #[test]
    fn cookie_tokens_are_found_among_other_cookies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "theme=dark; pigeon_session=first; lang=es"
                .parse()
                .expect("cookie header"),
        );
        assert_eq!(cookie_token(&headers), Some("first"));

        headers.append(
            header::COOKIE,
            "pigeon_session=second".parse().expect("cookie header"),
        );
        assert_eq!(
            cookie_token(&headers),
            Some("second"),
            "the last cookie wins, as a browser jar would send it"
        );

        let mut empty = HeaderMap::new();
        empty.insert(header::COOKIE, "pigeon_session=".parse().expect("header"));
        assert_eq!(cookie_token(&empty), None);
        assert_eq!(cookie_token(&HeaderMap::new()), None);
    }

    #[test]
    fn totp_codes_are_told_apart_from_recovery_codes() {
        assert!(is_totp_code("123456"));
        assert!(is_totp_code("12345678"));
        assert!(!is_totp_code("12345"));
        assert!(!is_totp_code("1234567"));
        assert!(!is_totp_code("12345a"));
        let recovery = new_recovery_codes();
        for code in &recovery {
            assert!(!is_totp_code(code), "{code} is not a TOTP code");
        }
    }

    #[test]
    fn recovery_codes_are_twenty_unique_base64url_characters() {
        let codes = new_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        let unique: std::collections::HashSet<&String> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len(), "codes never repeat");
        for code in &codes {
            assert_eq!(code.len(), 20, "{code}");
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "base64url only: {code}"
            );
        }
    }

    #[test]
    fn the_otpauth_uri_is_scannable_and_pinned() {
        let secret = secret_base32(&[0x42u8; 20]);
        let uri = otpauth_uri("owner@example.com", &secret);
        assert_eq!(
            uri,
            format!(
                "otpauth://totp/Pigeon%3Aowner%40example.com?secret={secret}&issuer=Pigeon&algorithm=SHA1&digits=6&period=30"
            )
        );
        // A `+` in the address must not survive as a space in a QR decoder.
        assert!(otpauth_uri("a+b@example.com", &secret).contains("a%2Bb%40example.com"));
    }

    #[test]
    fn wrapped_secrets_are_bound_to_their_account() {
        let master = MasterKey::parse(&[3u8; 32]).expect("master key");
        let secret = pigeon_crypto::generate_totp_secret();
        let wrapped = wrap_totp_secret(&master, 7, &secret).expect("wrap");

        assert_eq!(
            open_totp_secret(&master, 7, &wrapped).expect("open"),
            secret,
            "the same account opens the same secret"
        );
        assert!(
            open_totp_secret(&master, 8, &wrapped).is_err(),
            "another account must not be able to open it"
        );
        let other_master = MasterKey::parse(&[4u8; 32]).expect("master key");
        assert!(open_totp_secret(&other_master, 7, &wrapped).is_err());
    }

    #[test]
    fn session_ids_and_cache_keys_do_not_collide_with_api_keys() {
        // A token and an API key are different strings; the cache separates them
        // by prefix so one can never authenticate as the other.
        let session_id = new_session_id();
        let token = new_token(&session_id);
        let api_key = pigeon_crypto::generate_api_key();
        assert_ne!(cache_key(&token), api_key);
        assert_eq!(session_id_of(&api_key), None);
    }
}
