//! Per-account OpenPGP custody: the layer-3 identity and how it is stored.
//!
//! Mirrors [`crate::dkim`] one layer up, but keyed by **account** instead of
//! domain: an OpenPGP certificate is a mailbox identity, so sealing a message
//! "to this address" can only mean "to the holder of that account".
//!
//! # Storage envelope
//!
//! The transferable secret key is an armored blob sealed in the same two layers
//! every other secret in this service uses (ADR 0003):
//!
//! 1. a fresh 32-byte **content key** seals the armored secret
//!    ([`pigeon_crypto::seal_content`]),
//! 2. that content key is **wrapped** under the master key
//!    ([`pigeon_crypto::MasterKey::wrap_content_key`]).
//!
//! One SQL column holds both, length-prefixed:
//!
//! ```text
//! wrapped_len (4 bytes, big-endian) || wrapped content key || sealed secret
//! ```
//!
//! Both layers are bound to [`crate::aad::pgp_key`] — `pgp:{account_id}` — so a
//! blob cannot be replayed onto another account: unwrapping `account:1`'s key
//! while claiming `account:2` fails AEAD authentication instead of handing out a
//! private key.
//!
//! # Lazy generation (deliberate)
//!
//! A key is generated the **first time it is needed** — the first WKD
//! publication for the address, or the first sealed send — instead of at account
//! creation. Generating at creation would put an expensive key-generation step
//! inside every path that creates an account (keygen, invitations, organization
//! members, tests), and every existing deployment would still need a backfill
//! migration. Laziness has one observable consequence, documented in
//! `docs/e2ee-model.md`: an address that never sent and was never asked for has
//! no published key yet, and serves `404` until the first request, which then
//! creates it.
//!
//! # Concurrent first use converges on one identity
//!
//! Two requests can need the same new key at the same moment (the first WKD fetch
//! and the first sealed send, say). Both generate a candidate; exactly one wins the
//! insert and the loser **re-reads the winner's row** instead of overwriting it.
//! Overwriting would leave the published certificate and the stored secret key
//! describing different identities, and every message sealed in that window would
//! be unreadable by its own account.

use pigeon_core::EmailAddress;
use pigeon_crypto::{seal_content, CryptoError, MasterKey};
use store::{SqliteStorage, Storage};

use crate::aad;

/// Bytes of the big-endian length prefix in front of the wrapped content key.
const LEN_PREFIX: usize = 4;

/// An account's usable identity: the public half to seal to, the private half to
/// open with.
///
/// [`std::fmt::Debug`] is implemented by hand and **never prints the secret**: these
/// values end up in log lines and error contexts, and a derived `Debug` would put an
/// armored private key in the operator's log the first time somebody wrote `?key`.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountKey {
    /// Business-logic identifier of the owning account.
    pub account_id: i64,
    /// Armored public certificate (what WKD publishes).
    pub public_armored: String,
    /// Armored transferable secret key, opened from the master-key envelope.
    pub private_armored: String,
    /// Uppercase hex fingerprint of the primary key.
    pub fingerprint: String,
}

impl AccountKey {
    /// The public certificate, parsed and ready to be an encryption recipient.
    pub fn certificate(&self) -> Result<sequoia_openpgp::Cert, CryptoError> {
        pigeon_crypto::parse_cert(self.public_armored.as_bytes())
    }
}

impl std::fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Fingerprint and shapes only: enough to identify the key, nothing that
        // could be turned back into key material.
        f.debug_struct("AccountKey")
            .field("account_id", &self.account_id)
            .field("fingerprint", &self.fingerprint)
            .field("public_armored_len", &self.public_armored.len())
            .field("private_armored", &"<redacted>")
            .finish()
    }
}

fn seal_private_key(
    master_key: &MasterKey,
    account_id: i64,
    secret: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let aad = aad::pgp_key(account_id);
    let content_key = pigeon_crypto::generate_content_key();
    let sealed = seal_content(&content_key, secret, aad.as_bytes())?;
    let wrapped = master_key.wrap_content_key(&content_key, aad.as_bytes())?;

    let mut blob = Vec::with_capacity(LEN_PREFIX + wrapped.len() + sealed.len());
    let wrapped_len = u32::try_from(wrapped.len()).map_err(|_| CryptoError::Encrypt)?;
    blob.extend_from_slice(&wrapped_len.to_be_bytes());
    blob.extend_from_slice(&wrapped);
    blob.extend_from_slice(&sealed);
    Ok(blob)
}

fn open_private_key(
    master_key: &MasterKey,
    account_id: i64,
    blob: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if blob.len() <= LEN_PREFIX {
        return Err(CryptoError::Malformed(LEN_PREFIX + 1));
    }
    let (prefix, rest) = blob.split_at(LEN_PREFIX);
    let mut length_bytes = [0u8; LEN_PREFIX];
    length_bytes.copy_from_slice(prefix);
    let wrapped_len = u32::from_be_bytes(length_bytes) as usize;
    if rest.len() <= wrapped_len {
        return Err(CryptoError::Malformed(LEN_PREFIX + wrapped_len + 1));
    }
    let (wrapped, sealed) = rest.split_at(wrapped_len);

    let aad = aad::pgp_key(account_id);
    let content_key = master_key.unwrap_content_key(wrapped, aad.as_bytes())?;
    pigeon_crypto::open_content(&content_key, sealed, aad.as_bytes())
}

/// Load an account's key, generating and storing one on first use.
///
/// `address` only names the certificate's user id (the address a PGP client
/// shows); the account id is what the storage envelope is bound to.
pub fn ensure_account_key(
    store: &SqliteStorage,
    master_key: &MasterKey,
    account_id: i64,
    address: &EmailAddress,
) -> store::Result<AccountKey> {
    if let Some(row) = store.get_pgp_key(account_id)? {
        let secret = open_private_key(master_key, account_id, &row.private_sealed)?;
        return Ok(AccountKey {
            account_id,
            public_armored: row.public_armored,
            private_armored: String::from_utf8(secret)
                .map_err(|_| store::StoreError::Corrupt("PGP secret key is not UTF-8".into()))?,
            fingerprint: row.fingerprint,
        });
    }

    let generated = pigeon_crypto::generate_account_key(&address.to_string())?;
    let sealed = seal_private_key(master_key, account_id, generated.private_armored.as_bytes())?;

    // Insert-if-absent, never upsert: a concurrent first use that stored a key
    // first must win, otherwise the identity just published and the identity stored
    // here would disagree and mail sealed to one could not be opened by the other.
    if store.insert_pgp_key_if_absent(
        account_id,
        &generated.public_armored,
        &sealed,
        &generated.fingerprint,
    )? {
        tracing::info!(
            account_id,
            address = %address,
            fingerprint = %generated.fingerprint,
            "generated the account's OpenPGP identity"
        );
        return Ok(AccountKey {
            account_id,
            public_armored: generated.public_armored,
            private_armored: generated.private_armored,
            fingerprint: generated.fingerprint,
        });
    }

    // Lost the race: adopt the identity that is actually stored, so both callers
    // converge on it.
    let row = store.get_pgp_key(account_id)?.ok_or_else(|| {
        store::StoreError::Corrupt(
            "an OpenPGP key was in the way but is not readable afterwards".to_string(),
        )
    })?;
    let secret = open_private_key(master_key, account_id, &row.private_sealed)?;
    tracing::info!(
        account_id,
        address = %address,
        fingerprint = %row.fingerprint,
        "another request created the account's OpenPGP identity first: reusing it"
    );
    Ok(AccountKey {
        account_id,
        public_armored: row.public_armored,
        private_armored: String::from_utf8(secret)
            .map_err(|_| store::StoreError::Corrupt("PGP secret key is not UTF-8".into()))?,
        fingerprint: row.fingerprint,
    })
}

/// The published key for one address, generating it when the address is a local
/// account of this deployment.
///
/// Returns `Ok(None)` for anything this instance does not serve: a foreign
/// address, or a sender alias (which has several owners and no identity of its
/// own — sealing to one of them would be a lie).
pub fn published_key_for(
    store: &SqliteStorage,
    master_key: &MasterKey,
    address: &EmailAddress,
) -> store::Result<Option<AccountKey>> {
    let Some(account_id) = store.get_account_by_email(&address.normalized())? else {
        return Ok(None);
    };
    let (id, own) = store.get_account(account_id)?;
    Ok(Some(ensure_account_key(store, master_key, id, &own)?))
}

/// Seal one MIME body part to every recipient certificate plus the sender's own.
///
/// The sender's certificate is added on purpose: without it the sending account
/// could not read the copy it keeps in `sent`, and the only way back would be to
/// disable E2E. Proton documents the same choice ("sent mail is readable by the
/// sender").
pub fn seal_to_all(
    recipient_certificates: &[sequoia_openpgp::Cert],
    own_certificate: &sequoia_openpgp::Cert,
    plaintext: &[u8],
) -> Result<String, CryptoError> {
    let mut certificates = recipient_certificates.to_vec();
    if !certificates
        .iter()
        .any(|cert| cert.fingerprint() == own_certificate.fingerprint())
    {
        certificates.push(own_certificate.clone());
    }
    pigeon_crypto::seal_payload(plaintext, &certificates)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master() -> MasterKey {
        MasterKey::parse(&[0xA1; 32]).expect("master key")
    }

    fn fixture() -> (tempfile::TempDir, SqliteStorage, i64) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SqliteStorage::open(dir.path().join("pigeon.db")).expect("open");
        let address = EmailAddress::parse("carol@example.com").expect("address");
        let account_id = store.create_account(&address).expect("account");
        (dir, store, account_id)
    }

    #[test]
    fn a_sealed_private_key_opens_to_the_same_bytes() {
        let blob = seal_private_key(&master(), 1, b"secret-armor").expect("seal");
        assert_eq!(
            open_private_key(&master(), 1, &blob).expect("open"),
            b"secret-armor"
        );
    }

    #[test]
    fn a_sealed_private_key_does_not_open_for_another_account() {
        let blob = seal_private_key(&master(), 1, b"secret-armor").expect("seal");
        assert!(
            open_private_key(&master(), 2, &blob).is_err(),
            "the AAD binds the key to its account"
        );
    }

    #[test]
    fn a_sealed_private_key_does_not_open_under_another_master_key() {
        let blob = seal_private_key(&master(), 1, b"secret").expect("seal");
        let other = MasterKey::parse(&[0xA2; 32]).expect("other master");
        assert!(open_private_key(&other, 1, &blob).is_err());
    }

    #[test]
    fn truncated_blobs_fail_closed() {
        let blob = seal_private_key(&master(), 1, b"secret").expect("seal");
        for cut in 1..blob.len() {
            assert!(
                open_private_key(&master(), 1, &blob[..cut]).is_err(),
                "truncation at {cut} must fail"
            );
        }
    }

    #[test]
    fn a_rotation_still_replaces_the_identity_on_purpose() {
        let (_dir, store, account_id) = fixture();
        let address = EmailAddress::parse("carol@example.com").expect("address");
        let first = ensure_account_key(&store, &master(), account_id, &address).expect("key");

        // Rotation is an explicit operation and keeps working: `put_pgp_key` is the
        // primitive that replaces, `insert_pgp_key_if_absent` is the one that must
        // not.
        let rotated = pigeon_crypto::generate_account_key(&address.to_string()).expect("rotated");
        let sealed = seal_private_key(&master(), account_id, rotated.private_armored.as_bytes())
            .expect("seal");
        store
            .put_pgp_key(
                account_id,
                &rotated.public_armored,
                &sealed,
                &rotated.fingerprint,
            )
            .expect("rotate");

        let after = ensure_account_key(&store, &master(), account_id, &address).expect("key");
        assert_ne!(after.fingerprint, first.fingerprint);
        assert_eq!(after.fingerprint, rotated.fingerprint);
    }

    /// Two concurrent first uses must converge on ONE identity: otherwise the
    /// published certificate and the stored secret key describe different keys and
    /// the account cannot open its own sealed mail.
    #[test]
    fn concurrent_first_uses_converge_on_one_fingerprint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pigeon.db");
        let store = std::sync::Arc::new(SqliteStorage::open(&path).expect("open"));
        let address = EmailAddress::parse("carol@example.com").expect("address");
        let account_id = store.create_account(&address).expect("account");

        let mut handles = Vec::new();
        for _ in 0..4 {
            let store = std::sync::Arc::clone(&store);
            let address = address.clone();
            handles.push(std::thread::spawn(move || {
                let master = master();
                ensure_account_key(&store, &master, account_id, &address).expect("key")
            }));
        }
        let keys: Vec<AccountKey> = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread"))
            .collect();

        let first = &keys[0];
        for key in &keys {
            assert_eq!(
                key.fingerprint, first.fingerprint,
                "every concurrent caller adopts the same identity"
            );
        }
        let stored = store.get_pgp_key(account_id).expect("get").expect("row");
        assert_eq!(
            stored.fingerprint, first.fingerprint,
            "the stored identity is the one everybody got"
        );
        assert_eq!(stored.public_armored, first.public_armored);
    }

    #[test]
    fn debug_output_never_contains_the_secret_key() {
        let (_dir, store, account_id) = fixture();
        let address = EmailAddress::parse("carol@example.com").expect("address");
        let key = ensure_account_key(&store, &master(), account_id, &address).expect("key");
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("PRIVATE KEY"), "{rendered}");
        assert!(!rendered.contains(&key.private_armored), "{rendered}");
        assert!(
            rendered.contains(&key.fingerprint),
            "the fingerprint stays visible for debugging: {rendered}"
        );
    }

    #[test]
    fn the_first_use_generates_and_stores_one_key() {
        let (_dir, store, account_id) = fixture();
        let address = EmailAddress::parse("carol@example.com").expect("address");
        let key = ensure_account_key(&store, &master(), account_id, &address).expect("key");
        assert!(key
            .public_armored
            .starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(key
            .private_armored
            .starts_with("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        assert!(store.get_pgp_key(account_id).expect("get").is_some());

        // The second call reuses the stored key: identities never rotate by
        // accident.
        let again = ensure_account_key(&store, &master(), account_id, &address).expect("key");
        assert_eq!(again.fingerprint, key.fingerprint);
        assert_eq!(again.public_armored, key.public_armored);
    }

    #[test]
    fn a_key_sealed_under_another_master_key_is_an_error_not_a_new_identity() {
        let (_dir, store, account_id) = fixture();
        let address = EmailAddress::parse("carol@example.com").expect("address");
        ensure_account_key(&store, &master(), account_id, &address).expect("key");

        let other = MasterKey::parse(&[0xA3; 32]).expect("other master");
        let error = ensure_account_key(&store, &other, account_id, &address)
            .expect_err("a key we hold but cannot open must not be replaced");
        assert!(matches!(error, store::StoreError::Crypto(_)), "got {error}");
    }

    #[test]
    fn published_key_is_none_for_addresses_this_instance_does_not_own() {
        let (_dir, store, _account_id) = fixture();
        let foreign = EmailAddress::parse("someone@elsewhere.example").expect("address");
        assert!(published_key_for(&store, &master(), &foreign)
            .expect("lookup")
            .is_none());

        let local = EmailAddress::parse("Carol@Example.com").expect("address");
        let published = published_key_for(&store, &master(), &local)
            .expect("lookup")
            .expect("local account publishes a key");
        assert!(!published.public_armored.is_empty());
    }

    #[test]
    fn sealing_includes_the_senders_own_certificate() {
        let own = pigeon_crypto::generate_account_key("dana@pigeonmail.dev").expect("own key");
        let peer = pigeon_crypto::generate_account_key("carol@example.org").expect("peer key");
        let own_cert = pigeon_crypto::parse_cert(own.public_armored.as_bytes()).expect("cert");
        let peer_cert = pigeon_crypto::parse_cert(peer.public_armored.as_bytes()).expect("cert");

        let sealed = seal_to_all(&[peer_cert], &own_cert, b"body").expect("seal");
        // Both the recipient and the sender can open the sent copy.
        assert_eq!(
            pigeon_crypto::open_payload_with_key(
                peer.private_armored.as_bytes(),
                sealed.as_bytes()
            )
            .expect("peer opens"),
            b"body"
        );
        assert_eq!(
            pigeon_crypto::open_payload_with_key(own.private_armored.as_bytes(), sealed.as_bytes())
                .expect("sender opens its own sent copy"),
            b"body"
        );
    }

    #[test]
    fn the_senders_certificate_is_not_duplicated_when_it_is_a_recipient() {
        let own = pigeon_crypto::generate_account_key("dana@pigeonmail.dev").expect("key");
        let cert = pigeon_crypto::parse_cert(own.public_armored.as_bytes()).expect("cert");
        // Sealing to itself twice would still work; the point is that the helper
        // does not append a second copy of the same certificate.
        let sealed = seal_to_all(std::slice::from_ref(&cert), &cert, b"body").expect("seal");
        assert!(pigeon_crypto::open_payload_with_key(
            own.private_armored.as_bytes(),
            sealed.as_bytes()
        )
        .is_ok());
    }
}
