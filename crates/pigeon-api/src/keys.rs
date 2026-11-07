//! API key issuance.
//!
//! One code path creates keys, so the bootstrap (`pigeon keygen`) and the REST
//! endpoint cannot drift: generate `pk_…`, keep only the Argon2id hash in
//! `store`, and record the API-side metadata (`key_` public id, sandbox flag) in
//! the auxiliary table. The plaintext key is returned to the caller and never
//! stored anywhere.

use pigeon_core::ApiKeyScope;
use store::{SqliteStorage, Storage};

use crate::db::ApiDb;
use crate::ids;

/// Leading characters of a key used as its indexed lookup prefix.
///
/// 8 characters (`pk_` plus 5 random ones) keep the prefix selective enough that
/// almost every lookup has exactly one candidate, while the remaining 38
/// characters of entropy are what the Argon2id hash actually protects. A
/// collision is not a security problem: every candidate is verified.
pub const KEY_PREFIX_LEN: usize = 8;

/// The lookup prefix stored alongside the hash.
pub fn key_prefix(api_key: &str) -> &str {
    let end = api_key
        .char_indices()
        .nth(KEY_PREFIX_LEN)
        .map_or(api_key.len(), |(index, _)| index);
    &api_key[..end]
}

/// Issue a key for `account_id`. Returns `(public key id, pk_ key)`.
///
/// The `pk_` value is shown once and cannot be recovered: only its hash is
/// persisted.
pub fn issue(
    store: &SqliteStorage,
    db: &ApiDb,
    account_id: i64,
    name: &str,
    scopes: &[ApiKeyScope],
    sandbox: bool,
) -> store::Result<(String, String)> {
    let api_key = pigeon_crypto::generate_api_key();
    let hash = pigeon_crypto::hash_api_key(&api_key)?;
    let key_id = store.put_api_key(account_id, name, key_prefix(&api_key), &hash, scopes)?;
    let public_id = ids::gen(ids::KEY);
    db.create_key_meta(key_id, &public_id, sandbox)?;
    Ok((public_id, api_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    struct Fixture {
        _dir: TempDir,
        store: SqliteStorage,
        db: ApiDb,
        account_id: i64,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pigeon.db");
        let store = SqliteStorage::open(&path).expect("store");
        let db = ApiDb::open(&path).expect("api db");
        let account = pigeon_core::EmailAddress::parse("owner@example.com").expect("address");
        let account_id = store.create_account(&account).expect("account");
        Fixture {
            _dir: dir,
            store,
            db,
            account_id,
        }
    }

    #[test]
    fn prefix_is_eight_characters() {
        assert_eq!(key_prefix("pk_abcdefghij"), "pk_abcde");
        assert_eq!(key_prefix("short"), "short");
        assert_eq!(key_prefix(""), "");
    }

    #[test]
    fn issued_keys_are_verifiable_and_carry_metadata() {
        let fixture = fixture();
        let (public_id, key) = issue(
            &fixture.store,
            &fixture.db,
            fixture.account_id,
            "ci",
            &[ApiKeyScope::Send, ApiKeyScope::Read],
            true,
        )
        .expect("issue");

        assert!(key.starts_with("pk_"), "{key}");
        assert!(crate::ids::is_well_formed(&public_id, ids::KEY));
        assert_eq!(public_id.len(), 4 + 16);

        let candidates = fixture
            .store
            .find_api_key_by_prefix(key_prefix(&key))
            .expect("lookup");
        assert_eq!(candidates.len(), 1);
        assert!(pigeon_crypto::verify_api_key(&key, &candidates[0].1));

        let row = fixture
            .db
            .key_by_public_id(fixture.account_id, &public_id)
            .expect("row")
            .expect("exists");
        assert!(row.sandbox);
        assert!(!row.revoked);
        assert_eq!(row.scopes, vec![ApiKeyScope::Send, ApiKeyScope::Read]);
        assert!(row.last_used_at.is_none());
    }

    #[test]
    fn every_issued_key_is_distinct() {
        let fixture = fixture();
        let (_, first) = issue(
            &fixture.store,
            &fixture.db,
            fixture.account_id,
            "a",
            &[ApiKeyScope::Full],
            false,
        )
        .expect("first");
        let (_, second) = issue(
            &fixture.store,
            &fixture.db,
            fixture.account_id,
            "b",
            &[ApiKeyScope::Full],
            false,
        )
        .expect("second");
        assert_ne!(first, second);
        assert_eq!(
            fixture
                .db
                .list_keys(fixture.account_id)
                .expect("list")
                .len(),
            2
        );
    }
}
