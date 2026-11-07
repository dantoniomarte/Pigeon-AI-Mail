//! DKIM key pairs and the DNS record operators publish (RFC 6376 §3.6).
//!
//! A DKIM key is a selector-scoped RSA key pair. The private half stays on the
//! sending server; the public half is published as a TXT record at
//! `<selector>._domainkey.<domain>` by [`DkimKeyPair::public_key_dns_record`].
//!
//! A key pair survives a round trip through storage: [`DkimKeyPair::to_pkcs8_der`]
//! exports the private half as PKCS#8 DER and [`DkimKeyPair::from_pkcs8_der`]
//! rebuilds the pair from those bytes (the caller seals them at rest —
//! `pigeon-api` wraps them under the master key). The `Debug` output is redacted
//! so keys cannot leak into a log line.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::rand_core::OsRng;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};

use crate::error::{DkimError, Result};

/// 2048-bit RSA: the size every DKIM verifier accepts, and the current
/// industry standard (RFC 8301 forbids less than 1024 bits).
pub const RSA_KEY_BITS: usize = 2048;

/// Smallest key [`DkimKeyPair::from_pkcs8_der`] accepts: RFC 8301 §3.2 requires
/// signers to use at least 1024 bits.
pub const MIN_RSA_KEY_BITS: usize = 1024;

/// The only signing algorithm this crate implements in v0.1.
pub const ALGORITHM: &str = "rsa-sha256";

/// Header/body canonicalization this crate implements: relaxed (RFC 6376
/// §3.4.2 / §3.4.4).
pub const CANONICALIZATION: &str = "relaxed/relaxed";

/// An RSA DKIM identity: one selector for one domain.
pub struct DkimKeyPair {
    private: RsaPrivateKey,
    selector: String,
    domain: String,
    /// DER-encoded `SubjectPublicKeyInfo`, computed once at generation time so
    /// building the DNS record cannot fail later.
    spki_der: Vec<u8>,
}

impl DkimKeyPair {
    /// Generate a fresh 2048-bit RSA key for `selector` at `domain`.
    pub fn generate(selector: impl Into<String>, domain: impl Into<String>) -> Result<Self> {
        let private = RsaPrivateKey::new(&mut OsRng, RSA_KEY_BITS)
            .map_err(|e| DkimError::KeyGen(e.to_string()))?;
        let spki_der = RsaPublicKey::from(&private)
            .to_public_key_der()
            .map_err(|e| DkimError::KeyGen(format!("cannot encode the public key: {e}")))?
            .as_bytes()
            .to_vec();

        Ok(Self {
            private,
            selector: selector.into(),
            domain: domain.into(),
            spki_der,
        })
    }

    /// The selector this key signs as.
    pub fn selector(&self) -> &str {
        &self.selector
    }

    /// The domain this key signs for.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The exact TXT record to publish at `<selector>._domainkey.<domain>`:
    /// `v=DKIM1; k=rsa; p=<base64(DER SubjectPublicKeyInfo)>`.
    ///
    /// The `p=` value of a 2048-bit key is longer than the 255-octet limit for
    /// a single DNS character-string, so most providers must split it into
    /// several quoted chunks; the resolver then hands us the concatenation.
    /// [`crate::verify`] ignores whitespace inside `p=` either way.
    pub fn public_key_dns_record(&self) -> String {
        format!("v=DKIM1; k=rsa; p={}", STANDARD.encode(&self.spki_der))
    }

    /// Sign `headers` and `body`, returning the complete `DKIM-Signature`
    /// header **value** (no `DKIM-Signature: ` prefix, no trailing CRLF).
    ///
    /// Each entry of `headers` is a raw `Name: value` field, folding included,
    /// in the order it appears in the message. The `h=` tag is built from those
    /// names in the same order, so the caller decides the signed set — use
    /// [`crate::sign::sign_message`] for the RFC 6376 §5.4 minimum set.
    pub fn sign(&self, headers: &[&str], body: &str) -> Result<String> {
        crate::sign::sign_with(self, headers, body)
    }

    /// Rebuild a key pair from PKCS#8 DER produced by
    /// [`DkimKeyPair::to_pkcs8_der`], signing as `selector` at `domain`.
    ///
    /// The selector and domain are **not** stored in the DER: they are nothing
    /// more than the DNS labels the key is published under, so the caller (the
    /// key store) supplies them and they must match the row the bytes came from.
    /// The public half — and therefore the DNS record — is recomputed from the
    /// private key, so a rebuilt pair publishes the exact record that verifies
    /// its signatures.
    ///
    /// Keys below 1024 bits are refused: RFC 8301 forbids them, and a stored
    /// short key would produce signatures that every verifier rejects, so failing
    /// at load time beats failing at delivery time.
    pub fn from_pkcs8_der(
        selector: impl Into<String>,
        domain: impl Into<String>,
        der: &[u8],
    ) -> Result<Self> {
        let private = RsaPrivateKey::from_pkcs8_der(der)
            .map_err(|e| DkimError::Parse(format!("cannot decode the PKCS#8 private key: {e}")))?;
        if private.n().bits() < MIN_RSA_KEY_BITS {
            return Err(DkimError::UnsupportedAlgorithm(format!(
                "RSA keys below {MIN_RSA_KEY_BITS} bits are not usable for DKIM (got {} bits)",
                private.n().bits()
            )));
        }
        let spki_der = RsaPublicKey::from(&private)
            .to_public_key_der()
            .map_err(|e| DkimError::Parse(format!("cannot encode the public key: {e}")))?
            .as_bytes()
            .to_vec();

        Ok(Self {
            private,
            selector: selector.into(),
            domain: domain.into(),
            spki_der,
        })
    }

    /// The private half as PKCS#8 DER, for a caller that seals it at rest.
    ///
    /// The bytes are key material: the returned buffer is plain `Vec<u8>` (this
    /// crate has no zeroizing dependency), so a caller that persists it owns the
    /// obligation to clear or encrypt it. Round-trip them with
    /// [`DkimKeyPair::from_pkcs8_der`] to sign again later.
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        self.private
            .to_pkcs8_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|e| DkimError::KeyGen(format!("cannot encode the PKCS#8 private key: {e}")))
    }

    /// The public half, for tests and for callers that want to inspect it.
    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey::from(&self.private)
    }

    /// The private key material. Crate-internal: signing goes through
    /// [`DkimKeyPair::sign`] so the canonicalization can never be bypassed.
    pub(crate) fn rsa_private(&self) -> &RsaPrivateKey {
        &self.private
    }
}

impl std::fmt::Debug for DkimKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DkimKeyPair")
            .field("selector", &self.selector)
            .field("domain", &self.domain)
            .field("private", &"<redacted>")
            .finish()
    }
}
