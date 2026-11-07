//! TOTP second factor (RFC 6238 / RFC 4226), for dashboard & webmail accounts.
//!
//! Supports SHA-1 and SHA-256, 6 or 8 digits, 30-second steps (the Google
//! Authenticator profile), with a bounded configurable verification window and
//! constant-time comparison of every candidate (no timing oracle on the code
//! itself).
//!
//! # Secret handling
//!
//! The shared secret is kept in `Zeroizing` storage and the HMAC digest buffer
//! is wiped after truncation. Secrets must be at least 16 bytes
//! ([`Totp::try_new`], RFC 4226 §4 R6); `Totp::new` skips that check and is
//! test-only.
//!
//! # Replay obligation
//!
//! TOTP verification here is stateless: a code stays valid for its whole step
//! (and for `±window` steps when a window is used). The **service layer** is
//! therefore responsible for replay protection — it must persist the last
//! accepted counter per user (and per secret) and reject any code whose counter
//! is not strictly greater than the stored one. A stateful
//! `verify_and_consume` helper is planned for the storage layer; until it lands,
//! callers must implement that persistence themselves.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

pub const DEFAULT_STEP: u64 = 30;
pub const DEFAULT_DIGITS: u32 = 6;
/// RFC 4226 §4 R6: shared secrets are at least 128 bits.
pub const MIN_SECRET_LEN: usize = 16;
/// Recommended secret size in bytes (160 bits, RFC 4226 §4 R6 recommendation).
pub const RECOMMENDED_SECRET_LEN: usize = 20;
/// Largest accepted verification window (± steps). Bigger windows widen the
/// replay/brute-force surface far more than user clock skew justifies.
pub const MAX_WINDOW: u32 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TotpAlg {
    Sha1,
    Sha256,
}

/// A configured TOTP verifier. `secret` is the raw shared secret bytes
/// (what a base32 otpauth:// secret decodes to).
#[derive(Clone)]
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    alg: TotpAlg,
    digits: u32,
    step: u64,
}

impl Totp {
    /// Test-only: production callers must use [`Totp::try_new`], which enforces
    /// the RFC 4226 minimum of 16 bytes.
    #[cfg(test)]
    #[doc(hidden)]
    pub fn new(secret: &[u8]) -> Self {
        Self::unchecked(secret)
    }

    /// Construct without length validation — internal + test seam.
    fn unchecked(secret: &[u8]) -> Self {
        Totp {
            secret: Zeroizing::new(secret.to_vec()),
            alg: TotpAlg::Sha1,
            digits: DEFAULT_DIGITS,
            step: DEFAULT_STEP,
        }
    }

    /// Build a verifier, rejecting secrets shorter than 16 bytes
    /// (RFC 4226 §4 R6 — too little entropy to resist guessing).
    pub fn try_new(secret: &[u8]) -> Result<Self> {
        if secret.len() < MIN_SECRET_LEN {
            return Err(CryptoError::TotpConfig(format!(
                "secret must be at least {MIN_SECRET_LEN} bytes, got {}",
                secret.len()
            )));
        }
        Ok(Self::unchecked(secret))
    }

    pub fn alg(mut self, alg: TotpAlg) -> Self {
        self.alg = alg;
        self
    }

    pub fn digits(mut self, digits: u32) -> Result<Self> {
        if digits != 6 && digits != 8 {
            return Err(CryptoError::TotpConfig(format!(
                "digits must be 6 or 8, got {digits}"
            )));
        }
        self.digits = digits;
        Ok(self)
    }

    pub fn step(mut self, step: u64) -> Result<Self> {
        if step == 0 {
            return Err(CryptoError::TotpConfig("step must be > 0".into()));
        }
        self.step = step;
        Ok(self)
    }

    /// Current code for `unix_time` seconds.
    pub fn generate(&self, unix_time: u64) -> String {
        let counter = unix_time / self.step;
        self.hotp(counter)
    }

    /// Verify a user-supplied code, accepting `window` steps of drift in both
    /// directions (current, +1/-1 … ±window). Codes are compared in constant
    /// time.
    ///
    /// Every candidate inside the window is computed and compared — there is no
    /// early exit on the first match — so verification time does not reveal
    /// *which* step matched. A `window` above [`MAX_WINDOW`] is rejected
    /// outright (returns `false` without any HMAC work): accepting it would let
    /// a caller disable the anti-replay/brute-force property by accident.
    ///
    /// Replay protection is **not** provided here: see the module-level
    /// "Replay obligation" section.
    pub fn verify(&self, code: &str, unix_time: u64, window: u32) -> bool {
        if window > MAX_WINDOW {
            return false;
        }
        if code.len() != self.digits as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        let counter = unix_time / self.step;
        // Constant work: compute every candidate first (delta=0 exactly once),
        // then OR the comparisons — no short-circuit on match.
        let mut candidates: Vec<String> = Vec::with_capacity(2 * window as usize + 1);
        candidates.push(self.hotp(counter));
        for delta in 1..=window as u64 {
            if let Some(past) = counter.checked_sub(delta) {
                candidates.push(self.hotp(past));
            }
            if let Some(future) = counter.checked_add(delta) {
                candidates.push(self.hotp(future));
            }
        }
        let mut matched = false;
        for candidate in &candidates {
            matched |= constant_time_eq(candidate, code);
        }
        matched
    }

    /// RFC 4226 HOTP: HMAC → dynamic truncation → modulus 10^digits.
    fn hotp(&self, counter: u64) -> String {
        let msg = counter.to_be_bytes();
        // HMAC output length varies by algorithm (SHA-1: 20, SHA-256: 32) —
        // dynamic truncation MUST use the actual last byte (RFC 4226 §5.3).
        // The raw digest is MAC material, so it is wiped on scope exit.
        let digest: Zeroizing<Vec<u8>> = Zeroizing::new(match self.alg {
            TotpAlg::Sha1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(&self.secret)
                    .expect("HMAC accepts any key length");
                mac.update(&msg);
                mac.finalize().into_bytes().to_vec()
            }
            TotpAlg::Sha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
                    .expect("HMAC accepts any key length");
                mac.update(&msg);
                mac.finalize().into_bytes().to_vec()
            }
        });
        // Dynamic truncation (RFC 4226 §5.3): low 4 bits of the LAST byte select the offset.
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let bin = ((digest[offset] as u32 & 0x7f) << 24)
            | ((digest[offset + 1] as u32) << 16)
            | ((digest[offset + 2] as u32) << 8)
            | (digest[offset + 3] as u32);
        let modulus = 10u32.pow(self.digits);
        format!("{:0width$}", bin % modulus, width = self.digits as usize)
    }
}

/// Fresh 160-bit TOTP secret (20 random bytes), suitable for base32 encoding
/// into an `otpauth://` provisioning URI.
pub fn generate_totp_secret() -> Vec<u8> {
    crate::key::random_bytes(RECOMMENDED_SECRET_LEN).to_vec()
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}
