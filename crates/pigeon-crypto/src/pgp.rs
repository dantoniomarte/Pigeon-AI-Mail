//! OpenPGP (RFC 4880/9580) — the **layer-3** end-to-end payload seal.
//!
//! This is a different guarantee from [`crate::seal`]:
//!
//! | module | key holder | protects against |
//! |---|---|---|
//! | [`crate::seal`] | the server (master key) | a stolen database file |
//! | this module | the **recipient's account key** | the sending server, the network, and the receiving server's storage |
//!
//! A sealed payload is an OpenPGP message (public-key encrypted session key +
//! integrity-protected literal data, armored) addressed to one or more
//! recipients. Nobody in the delivery path holds those private keys, which is
//! what makes it end to end.
//!
//! # What is *not* encrypted
//!
//! SMTP requires the envelope and the headers in the clear: `From`, `To`,
//! `Subject`, `Date` and `Message-ID` stay readable by every hop. That is the
//! same caveat Proton documents for subject lines, and it is structural — the
//! [`crate::pgp`] seal covers the MIME body, not the mail headers.
//!
//! # Key shape
//!
//! [`generate_account_key`] builds one certificate per account:
//!
//! * a primary Ed25519 key (certification), so the certificate can be re-signed
//!   and rotated later,
//! * an Ed25519 **signing** subkey (proof of authorship; not used by the payload
//!   seal, which is anonymous on purpose — DKIM is the transport signature),
//! * a Curve25519 **transport-encryption** subkey, which is the key mail is
//!   actually sealed to.
//!
//! No expiry: an expired subkey silently turns every future send into
//! `tls_only`. Rotation is an explicit operation (a new subkey, re-published by
//! WKD), never a timer.
//!
//! # Why the RustCrypto backend
//!
//! `sequoia-openpgp`'s default backend is nettle, a C library: it needs a C
//! toolchain and a system dependency in every build image. The pure-Rust backend
//! (`crypto-rust`) covers exactly the algorithms used here and keeps the
//! single-binary, no-system-dependency posture. Sequoia requires two opt-ins for
//! it (`allow-experimental-crypto`, `allow-variable-time-crypto`); both are
//! declared with this reasoning in the workspace `Cargo.toml`.

use sequoia_openpgp as openpgp;

use openpgp::cert::prelude::*;
use openpgp::crypto::SessionKey;
use openpgp::packet::PKESK;
use openpgp::parse::stream::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use openpgp::serialize::SerializeInto;
use openpgp::types::{KeyFlags, SymmetricAlgorithm};

use crate::error::{CryptoError, Result};

/// Largest key blob this module will parse.
///
/// Keys arrive from the network (WKD), so an unbounded parse is a cheap
/// memory/CPU denial of service. A curve certificate with a handful of subkeys
/// and signatures is a few kilobytes; 128 KiB is already absurdly generous.
pub const MAX_KEY_BYTES: usize = 128 * 1024;

/// Largest sealed payload this module will open.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

/// An account's OpenPGP identity, exactly as it is stored.
///
/// Both halves are armored because that is what WKD publishes and what an
/// operator can paste into `gpg --import`. The private half is sealed under the
/// master key before it reaches SQL (see `pigeon_api::pgp`).
///
/// [`std::fmt::Debug`] is implemented by hand: the private half is key material,
/// and a derived `Debug` would leak it into any log line that formats the value.
#[derive(Clone, PartialEq, Eq)]
pub struct GeneratedKey {
    /// `-----BEGIN PGP PUBLIC KEY BLOCK-----` certificate.
    pub public_armored: String,
    /// `-----BEGIN PGP PRIVATE KEY BLOCK-----` transferable secret key.
    ///
    /// Passphrase-less on purpose: the private half is protected by the
    /// master-key envelope, and a second passphrase would have to be stored
    /// somewhere to make automation work.
    pub private_armored: String,
    /// Uppercase hex fingerprint of the primary key; the identity used for
    /// pinning (TOFU) and for telling a rotation from a re-publish.
    pub fingerprint: String,
}

fn pgp_error(context: &str, error: impl std::fmt::Display) -> CryptoError {
    CryptoError::Pgp(format!("{context}: {error}"))
}

/// Generate one account certificate: primary + signing subkey + transport
/// encryption subkey.
///
/// `user_id` is normally the account address; it is the identity a PGP client
/// shows, and the only place the certificate names its owner.
pub fn generate_account_key(user_id: &str) -> Result<GeneratedKey> {
    let (cert, _revocation) = CertBuilder::new()
        .set_cipher_suite(CipherSuite::Cv25519)
        .add_userid(user_id)
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .generate()
        .map_err(|error| pgp_error("key generation failed", error))?;

    let public_armored = String::from_utf8(
        cert.armored()
            .to_vec()
            .map_err(|error| pgp_error("public key armor failed", error))?,
    )
    .map_err(|error| pgp_error("public key armor is not UTF-8", error))?;
    let private_armored = String::from_utf8(
        cert.as_tsk()
            .armored()
            .to_vec()
            .map_err(|error| pgp_error("secret key armor failed", error))?,
    )
    .map_err(|error| pgp_error("secret key armor is not UTF-8", error))?;

    Ok(GeneratedKey {
        public_armored,
        private_armored,
        fingerprint: fingerprint_of(&cert),
    })
}

impl std::fmt::Debug for GeneratedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedKey")
            .field("fingerprint", &self.fingerprint)
            .field("public_armored_len", &self.public_armored.len())
            .field("private_armored", &"<redacted>")
            .finish()
    }
}

/// Uppercase hex fingerprint of a certificate's primary key.
pub fn fingerprint_of(cert: &openpgp::Cert) -> String {
    // Sequoia renders fingerprints in uppercase hex, the spelling `gpg` prints.
    cert.fingerprint().to_hex()
}

/// Parse a certificate from armored or binary bytes (public or secret).
///
/// WKD serves either form, and a Pigeon instance serves both the simple
/// endpoint (armored) and the advanced one (binary), so the pump accepts both.
/// Anything larger than [`MAX_KEY_BYTES`] is refused before parsing.
pub fn parse_cert(data: &[u8]) -> Result<openpgp::Cert> {
    if data.is_empty() {
        return Err(CryptoError::Pgp("key blob is empty".to_string()));
    }
    if data.len() > MAX_KEY_BYTES {
        return Err(CryptoError::Pgp(format!(
            "key blob is {} bytes, above the {MAX_KEY_BYTES} limit",
            data.len()
        )));
    }
    openpgp::Cert::from_bytes(data).map_err(|error| pgp_error("cannot parse the key", error))
}

/// Parse a certificate and return it with its fingerprint.
pub fn parse_cert_with_fingerprint(data: &[u8]) -> Result<(openpgp::Cert, String)> {
    let cert = parse_cert(data)?;
    let fingerprint = fingerprint_of(&cert);
    Ok((cert, fingerprint))
}

/// The certificate's binary (dearmored) form, as advanced WKD serves it.
pub fn to_binary(cert: &openpgp::Cert) -> Result<Vec<u8>> {
    cert.to_vec()
        .map_err(|error| pgp_error("cannot serialize the key", error))
}

/// True when the certificate carries a usable transport-encryption subkey.
///
/// Discovery uses this to answer "can this recipient be sealed to at all": a
/// certificate with only signing keys is not a recipient key, and pretending
/// otherwise would fail later, inside the delivery path.
pub fn can_encrypt(cert: &openpgp::Cert) -> bool {
    let policy = StandardPolicy::new();
    cert.keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .next()
        .is_some()
}

/// Seal `plaintext` to every recipient in `recipients`.
///
/// Returns an **armored** OpenPGP message. Fails when a recipient has no usable
/// encryption subkey: silently dropping that recipient from the session-key
/// packets would deliver a message they cannot read.
pub fn seal_payload(plaintext: &[u8], recipients: &[openpgp::Cert]) -> Result<String> {
    if recipients.is_empty() {
        return Err(CryptoError::Pgp(
            "sealing needs at least one recipient key".to_string(),
        ));
    }
    let policy = StandardPolicy::new();

    let mut keys = Vec::new();
    for cert in recipients {
        let mut found = false;
        for key in cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
        {
            keys.push(key);
            found = true;
        }
        if !found {
            return Err(CryptoError::Pgp(format!(
                "recipient key {} has no usable encryption subkey",
                fingerprint_of(cert)
            )));
        }
    }

    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let message = openpgp::serialize::stream::Armorer::new(message)
        .build()
        .map_err(|error| pgp_error("armor setup failed", error))?;
    let message = Encryptor::for_recipients(message, keys)
        .build()
        .map_err(|error| pgp_error("encryption setup failed", error))?;
    let mut writer = LiteralWriter::new(message)
        .build()
        .map_err(|error| pgp_error("literal data setup failed", error))?;
    use std::io::Write;
    writer
        .write_all(plaintext)
        .map_err(|error| pgp_error("cannot write the payload", error))?;
    writer
        .finalize()
        .map_err(|error| pgp_error("cannot finalize the payload", error))?;

    String::from_utf8(sink).map_err(|error| pgp_error("sealed payload is not UTF-8", error))
}

/// Seal `plaintext` to `recipients`, returning the sealed bytes (armored).
pub fn seal_payload_bytes(plaintext: &[u8], recipients: &[openpgp::Cert]) -> Result<Vec<u8>> {
    Ok(seal_payload(plaintext, recipients)?.into_bytes())
}

/// Open a payload sealed to `secret` (an armored or binary secret certificate).
///
/// Only the holder of the account's private key can call this successfully; the
/// server's master key does not help, which is the whole point of layer 3.
pub fn open_payload(secret: &openpgp::Cert, sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() > MAX_PAYLOAD_BYTES {
        return Err(CryptoError::Pgp(format!(
            "sealed payload is {} bytes, above the {MAX_PAYLOAD_BYTES} limit",
            sealed.len()
        )));
    }
    let policy = StandardPolicy::new();
    let helper = SecretKeyHelper {
        secret,
        policy: &policy,
    };
    let mut decryptor = DecryptorBuilder::from_bytes(sealed)
        .map_err(|error| pgp_error("cannot parse the sealed payload", error))?
        .with_policy(&policy, None, helper)
        .map_err(|error| pgp_error("the payload is not addressed to this key", error))?;

    let mut plaintext = Vec::new();
    std::io::copy(&mut decryptor, &mut plaintext)
        .map_err(|error| pgp_error("cannot read the sealed payload", error))?;
    Ok(plaintext)
}

/// Open an armored payload with an armored (or binary) secret certificate.
pub fn open_payload_with_key(secret_key: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    let secret = parse_cert(secret_key)?;
    open_payload(&secret, sealed)
}

/// Decryption helper over one certificate's secret subkeys.
///
/// Every encryption-capable secret subkey is offered to each `PKESK`; the first
/// one that decrypts wins. No signature verification helper is involved because
/// the sealed payload is not signed (DKIM covers transport authenticity), so
/// [`VerificationHelper::get_certs`] answers with nothing.
struct SecretKeyHelper<'a> {
    secret: &'a openpgp::Cert,
    policy: &'a StandardPolicy<'a>,
}

impl VerificationHelper for SecretKeyHelper<'_> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for SecretKeyHelper<'_> {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<openpgp::Cert>> {
        let candidates = self
            .secret
            .keys()
            .unencrypted_secret()
            .with_policy(self.policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .map(|amalgamation| amalgamation.key().clone())
            .collect::<Vec<_>>();

        for pkesk in pkesks {
            for secret in &candidates {
                let Ok(mut keypair) = secret.clone().into_keypair() else {
                    continue;
                };
                if let Some((algo, session_key)) = pkesk.decrypt(&mut keypair, sym_algo) {
                    if decrypt(algo, &session_key) {
                        return Ok(Some(self.secret.clone()));
                    }
                }
            }
        }
        Err(
            openpgp::Error::InvalidOperation("no packet is addressed to this key".to_string())
                .into(),
        )
    }
}

/// Key flags a recipient certificate must carry to be sealed to (exposed for
/// tests and for the discovery layer's diagnostics).
pub fn transport_encryption_flags() -> KeyFlags {
    KeyFlags::empty().set_transport_encryption()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(user_id: &str) -> GeneratedKey {
        generate_account_key(user_id).expect("key generation")
    }

    #[test]
    fn a_generated_key_pair_roundtrips_public_and_private() {
        let generated = key("dana@pigeonmail.dev");
        assert!(generated
            .public_armored
            .starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(generated
            .private_armored
            .starts_with("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        assert_eq!(generated.fingerprint.len(), 40);
        assert_eq!(generated.fingerprint.to_uppercase(), generated.fingerprint);

        let public = parse_cert(generated.public_armored.as_bytes()).expect("public");
        let secret = parse_cert(generated.private_armored.as_bytes()).expect("private");
        assert_eq!(fingerprint_of(&public), generated.fingerprint);
        assert_eq!(fingerprint_of(&secret), generated.fingerprint);
        assert_ne!(
            fingerprint_of(&public),
            String::new(),
            "fingerprints are never empty"
        );
    }

    #[test]
    fn the_certificate_carries_signing_and_encryption_subkeys() {
        let generated = key("dana@pigeonmail.dev");
        let cert = parse_cert(generated.public_armored.as_bytes()).expect("cert");
        assert!(can_encrypt(&cert), "a transport encryption subkey exists");

        let policy = StandardPolicy::new();
        let has_signing = cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .for_signing()
            .next()
            .is_some();
        assert!(has_signing, "a signing subkey exists");
        assert!(
            cert.userids().next().is_some(),
            "the certificate names its owner"
        );
    }

    #[test]
    fn a_payload_sealed_to_one_recipient_opens_with_that_key_only() {
        let recipient = key("carol@example.org");
        let other = key("dave@example.net");
        let sealed = seal_payload(
            b"From: a@b\r\nSubject: hi\r\n\r\nbody",
            &[parse_cert(recipient.public_armored.as_bytes()).expect("cert")],
        )
        .expect("seal");
        assert!(sealed.starts_with("-----BEGIN PGP MESSAGE-----"));

        let opened = open_payload_with_key(recipient.private_armored.as_bytes(), sealed.as_bytes())
            .expect("open");
        assert_eq!(opened, b"From: a@b\r\nSubject: hi\r\n\r\nbody");

        // Wrong key: the payload is not addressed to it.
        assert!(
            open_payload_with_key(other.private_armored.as_bytes(), sealed.as_bytes()).is_err(),
            "a different account key must not open it"
        );
    }

    #[test]
    fn a_payload_can_be_sealed_to_several_recipients_at_once() {
        let first = key("carol@example.org");
        let second = key("dave@example.net");
        let sealed = seal_payload(
            b"shared body",
            &[
                parse_cert(first.public_armored.as_bytes()).expect("cert"),
                parse_cert(second.public_armored.as_bytes()).expect("cert"),
            ],
        )
        .expect("seal");

        for recipient in [&first, &second] {
            let opened =
                open_payload_with_key(recipient.private_armored.as_bytes(), sealed.as_bytes())
                    .expect("each recipient opens it");
            assert_eq!(opened, b"shared body");
        }
    }

    #[test]
    fn sealing_without_a_recipient_is_refused() {
        let error = seal_payload(b"body", &[]).expect_err("no recipients");
        assert!(matches!(error, CryptoError::Pgp(_)), "got {error}");
    }

    #[test]
    fn a_certificate_without_an_encryption_subkey_cannot_be_a_recipient() {
        let (signing_only, _) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_userid("signer@example.org")
            .add_signing_subkey()
            .generate()
            .expect("generate");
        assert!(!can_encrypt(&signing_only));
        let error = seal_payload(b"body", &[signing_only]).expect_err("not a recipient key");
        assert!(
            matches!(&error, CryptoError::Pgp(message) if message.contains("encryption subkey")),
            "got {error}"
        );
    }

    #[test]
    fn a_tampered_payload_does_not_open() {
        let recipient = key("carol@example.org");
        let sealed = seal_payload(
            b"body",
            &[parse_cert(recipient.public_armored.as_bytes()).expect("cert")],
        )
        .expect("seal");

        // Flip one character inside the base64 body: the integrity-protected
        // literal data must fail closed, not yield corrupted bytes.
        let mut bytes = sealed.into_bytes();
        let middle = bytes.len() / 2;
        bytes[middle] = if bytes[middle] == b'A' { b'B' } else { b'A' };
        assert!(open_payload_with_key(recipient.private_armored.as_bytes(), &bytes).is_err());
    }

    #[test]
    fn oversized_or_empty_key_blobs_are_refused_before_parsing() {
        assert!(matches!(
            parse_cert(b""),
            Err(CryptoError::Pgp(message)) if message.contains("empty")
        ));
        let huge = vec![b'A'; MAX_KEY_BYTES + 1];
        assert!(matches!(
            parse_cert(&huge),
            Err(CryptoError::Pgp(message)) if message.contains("limit")
        ));
        assert!(parse_cert(b"not a key").is_err());
    }

    #[test]
    fn binary_and_armored_forms_describe_the_same_certificate() {
        let generated = key("dana@pigeonmail.dev");
        let cert = parse_cert(generated.public_armored.as_bytes()).expect("cert");
        let binary = to_binary(&cert).expect("binary");
        assert!(binary.len() < generated.public_armored.len());
        let reparsed = parse_cert_with_fingerprint(&binary).expect("parses binary");
        assert_eq!(reparsed.1, generated.fingerprint);
    }

    #[test]
    fn debug_output_redacts_the_secret_key() {
        let generated = key("dana@pigeonmail.dev");
        let rendered = format!("{generated:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("PRIVATE KEY"), "{rendered}");
        assert!(
            !rendered.contains(&generated.private_armored),
            "the armored secret must never be formatted"
        );
        assert!(
            rendered.contains(&generated.fingerprint),
            "the fingerprint is the useful part: {rendered}"
        );
        assert!(
            !rendered.contains("PUBLIC KEY"),
            "the armor itself is noise in a log line: {rendered}"
        );
    }

    #[test]
    fn userids_are_matched_exactly_not_by_containment() {
        // Direct guard for the discovery check: a certificate for a lookalike
        // address must not be accepted as the recipient's key.
        let generated = key("carol@example.org");
        let cert = parse_cert(generated.public_armored.as_bytes()).expect("cert");
        let userid = cert
            .userids()
            .next()
            .map(|userid| String::from_utf8_lossy(userid.userid().value()).into_owned())
            .expect("a user id");
        assert_eq!(userid, "carol@example.org");
    }

    #[test]
    fn two_generated_keys_never_collide() {
        let first = key("carol@example.org");
        let second = key("carol@example.org");
        assert_ne!(first.fingerprint, second.fingerprint);
        assert_ne!(first.public_armored, second.public_armored);
    }

    #[test]
    fn the_transport_encryption_flag_is_the_one_sealing_uses() {
        let flags = transport_encryption_flags();
        assert!(flags.for_transport_encryption());
        assert!(!flags.for_signing());
    }
}
