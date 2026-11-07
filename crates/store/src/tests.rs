//! Storage contract tests: every one runs against a fresh database file in its
//! own tempdir, so ordering and leakage between tests are impossible.
//!
//! The sealed-body tests are the important ones: they document that the store
//! never sees plaintext, that the AAD binding really ties a blob to its account
//! and message id, and that a blob which is not an envelope never lands in the
//! database.

use std::collections::HashSet;
use std::path::PathBuf;

use pigeon_core::types::{CatchallAction, OrgRole};
use pigeon_core::{ApiKeyScope, Direction, EmailAddress, MessageFolder};
use pigeon_crypto::{
    generate_api_key, generate_content_key, hash_api_key, open_content, seal_content,
    verify_api_key, CryptoError, MasterKey, ENVELOPE_VERSION, MIN_BLOB_LEN,
};
use rusqlite::params;
use tempfile::TempDir;

use crate::storage::{list_folder_sql, QUEUE_CLAIM_SQL};
use crate::{
    DeadJob, NewDraft, NewMessage, SqliteStorage, Storage, StoreError, MAX_PAGE_LIMIT, MIGRATIONS,
};

/// One content key for the whole suite: the store never handles keys, so the
/// tests only need *a* key that seals and opens.
const TEST_KEY: [u8; 32] = [0x2a; 32];

struct Fixture {
    // Kept alive for the test's duration: dropping it removes the database.
    _dir: TempDir,
    path: PathBuf,
    storage: SqliteStorage,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("pigeon.db");
    let storage = SqliteStorage::open(&path).expect("open store");
    Fixture {
        _dir: dir,
        path,
        storage,
    }
}

fn addr(raw: &str) -> EmailAddress {
    EmailAddress::parse(raw).expect("test address parses")
}

fn new_account(storage: &SqliteStorage) -> i64 {
    storage
        .create_account(&addr("owner@example.com"))
        .expect("create account")
}

/// AAD the service is expected to seal with: account plus message id.
fn message_aad(account_id: i64, message_id: i64) -> String {
    format!("account:{account_id}:message:{message_id}")
}

fn sealed_body(account_id: i64, message_id: i64, plaintext: &[u8]) -> Vec<u8> {
    seal_content(
        &TEST_KEY,
        plaintext,
        message_aad(account_id, message_id).as_bytes(),
    )
    .expect("seal test body")
}

fn new_message(account_id: i64, reserved_id: i64, idempotency_key: Option<&str>) -> NewMessage {
    NewMessage {
        account_id,
        direction: Direction::Out,
        from_addr: addr("owner@example.com"),
        to_addrs: vec![addr("peer@example.net")],
        subject: "hello".to_string(),
        sealed_body: sealed_body(account_id, reserved_id, b"Subject: hi\r\n\r\nbody"),
        idempotency_key: idempotency_key.map(str::to_string),
        delivered_for: None,
    }
}

/// Reserve an id, seal a body with it and insert: the whole write sequence a
/// service performs.
fn insert(storage: &SqliteStorage, account_id: i64, key: Option<&str>) -> i64 {
    let reserved = storage.reserve_message_id().expect("reserve id");
    storage
        .insert_message(new_message(account_id, reserved, key), reserved)
        .expect("insert message")
}

fn seed_message(storage: &SqliteStorage, account_id: i64) -> i64 {
    insert(storage, account_id, None)
}

fn count(storage: &SqliteStorage, sql: &str) -> i64 {
    let conn = storage.raw_conn();
    conn.query_row(sql, [], |row| row.get(0)).expect(sql)
}

/// The same counter over a connection the test opened itself (upgrade tests).
fn count_raw(conn: &rusqlite::Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |row| row.get(0)).expect(sql)
}

// ------------------------------------------------------------- open / migrations

#[test]
fn migrations_are_idempotent_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pigeon.db");

    let storage = SqliteStorage::open(&path).unwrap();
    let account_id = new_account(&storage);
    assert_eq!(
        count(&storage, "SELECT COUNT(*) FROM _migrations"),
        MIGRATIONS.len() as i64
    );
    drop(storage);

    // Re-opening runs the migration pass again; it must neither fail nor
    // duplicate rows, and existing data must survive.
    let reopened = SqliteStorage::open(&path).unwrap();
    assert_eq!(
        count(&reopened, "SELECT COUNT(*) FROM _migrations"),
        MIGRATIONS.len() as i64
    );
    let (id, email) = reopened.get_account(account_id).unwrap();
    assert_eq!(id, account_id);
    assert_eq!(email, addr("owner@example.com"));
}

#[test]
fn simultaneous_open_of_a_fresh_file_succeeds() {
    const OPENERS: usize = 6;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fresh.db");

    // Every opener races the same cold file: the WAL switch, `_migrations`
    // creation and the migration pass itself. All of them must win or wait;
    // none may fail with "already exists" or "database is locked".
    let handles: Vec<_> = (0..OPENERS)
        .map(|opener| {
            let path = path.clone();
            std::thread::spawn(move || {
                SqliteStorage::open(&path).map(|storage| {
                    storage.create_account(&addr(&format!("racer{opener}@example.com")))
                })
            })
        })
        .collect();

    for handle in handles {
        let opened = handle.join().expect("opener thread must not panic");
        let created = opened.expect("every opener must get a usable store");
        assert!(created.expect("each opener inserts its own account") > 0);
    }

    let storage = SqliteStorage::open(&path).unwrap();
    assert_eq!(
        count(&storage, "SELECT COUNT(*) FROM _migrations"),
        MIGRATIONS.len() as i64,
        "the migration set must be recorded exactly once"
    );
    assert_eq!(
        count(&storage, "SELECT COUNT(*) FROM accounts"),
        OPENERS as i64
    );
}

#[test]
fn open_applies_the_durability_pragmas() {
    let fixture = fixture();
    let conn = fixture.storage.raw_conn();
    let journal: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(journal.to_ascii_lowercase(), "wal");
    let foreign_keys: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .unwrap();
    assert_eq!(foreign_keys, 1, "FK enforcement must be on");
    // synchronous: 0=OFF, 1=NORMAL, 2=FULL.
    let synchronous: i64 = conn
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .unwrap();
    assert_eq!(synchronous, 2, "queue durability needs synchronous=FULL");
}

#[test]
fn schema_carries_the_queue_retry_and_idempotency_columns() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let message_id = seed_message(&fixture.storage, account_id);

    let conn = fixture.storage.raw_conn();
    for (table, column) in [
        ("queue", "max_attempts"),
        ("queue", "status"),
        ("queue", "claimed_by"),
        ("messages", "idempotency_key"),
    ] {
        let exists: bool = conn
            .query_row(
                &format!(
                    "SELECT EXISTS(SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1)"
                ),
                [column],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "{table}.{column} must exist");
    }

    let indexes: Vec<String> = conn
        .prepare(
            "SELECT name FROM sqlite_master
              WHERE type = 'index' AND tbl_name = 'queue' AND name LIKE 'idx_%'",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        indexes.iter().any(|name| name == "idx_queue_claim"),
        "live claim index missing: {indexes:?}"
    );
    assert!(
        !indexes.iter().any(|name| name == "idx_queue_claimable"),
        "the superseded partial index must be gone: {indexes:?}"
    );

    // CHECKs must reject values the domain cannot represent.
    let bad_status = conn.execute(
        "UPDATE messages SET status = 'bogus' WHERE id = ?1",
        [message_id],
    );
    assert!(bad_status.is_err(), "messages.status CHECK must reject");
    let bad_direction = conn.execute(
        "UPDATE messages SET direction = 'sideways' WHERE id = ?1",
        [message_id],
    );
    assert!(
        bad_direction.is_err(),
        "messages.direction CHECK must reject"
    );
}

// --------------------------------------------------------------------- accounts

#[test]
fn duplicate_account_email_is_a_conflict() {
    let fixture = fixture();
    let first = new_account(&fixture.storage);
    assert!(first > 0);

    let err = fixture
        .storage
        .create_account(&addr("owner@example.com"))
        .unwrap_err();
    assert!(matches!(err, StoreError::Conflict), "got {err}");
    assert_eq!(count(&fixture.storage, "SELECT COUNT(*) FROM accounts"), 1);
}

#[test]
fn get_account_reports_missing_rows() {
    let fixture = fixture();
    let err = fixture.storage.get_account(404).unwrap_err();
    assert!(matches!(err, StoreError::NotFound), "got {err}");
}

// --------------------------------------------------------------------- api keys

#[test]
fn api_key_roundtrip_and_revoked_keys_are_skipped() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let api_key = generate_api_key();
    let prefix = "pk_roundtrip";
    let hash = hash_api_key(&api_key).unwrap();

    let key_id = fixture
        .storage
        .put_api_key(
            account_id,
            "ci",
            prefix,
            &hash,
            &[ApiKeyScope::Send, ApiKeyScope::Read],
        )
        .unwrap();
    assert!(key_id > 0);

    let candidates = fixture.storage.find_api_key_by_prefix(prefix).unwrap();
    assert_eq!(candidates.len(), 1);
    let (found_account, found_hash, scopes) = candidates.into_iter().next().unwrap();
    assert_eq!(found_account, account_id);
    assert_eq!(scopes, vec![ApiKeyScope::Send, ApiKeyScope::Read]);
    assert!(
        verify_api_key(&api_key, &found_hash),
        "stored hash must verify the issued key"
    );
    assert!(!verify_api_key("pk_wrong", &found_hash));

    assert!(fixture
        .storage
        .find_api_key_by_prefix("pk_missing")
        .unwrap()
        .is_empty());

    // v1 exposes no revoke endpoint yet; revoke through SQL and check lookup.
    fixture
        .storage
        .raw_conn()
        .execute(
            "UPDATE api_keys SET revoked_at = datetime('now') WHERE id = ?1",
            [key_id],
        )
        .unwrap();
    assert!(
        fixture
            .storage
            .find_api_key_by_prefix(prefix)
            .unwrap()
            .is_empty(),
        "revoked keys must not authenticate"
    );
}

#[test]
fn api_key_prefix_lookup_returns_every_live_candidate() {
    let fixture = fixture();
    let first = new_account(&fixture.storage);
    let second = fixture
        .storage
        .create_account(&addr("other@example.com"))
        .unwrap();
    // Prefixes are short and collision-prone by design; the plaintext key is
    // not stored, so the caller must be able to verify against all candidates.
    fixture
        .storage
        .put_api_key(first, "a", "pk_shared", "phc-one", &[ApiKeyScope::Send])
        .unwrap();
    fixture
        .storage
        .put_api_key(second, "b", "pk_shared", "phc-two", &[ApiKeyScope::Full])
        .unwrap();

    let candidates = fixture.storage.find_api_key_by_prefix("pk_shared").unwrap();
    assert_eq!(
        candidates.len(),
        2,
        "no LIMIT 1: both live keys are returned"
    );
    assert_eq!(candidates[0].0, second, "newest first");
    assert_eq!(candidates[1].0, first);

    // An unparsable scope is corrupt data, not a silently dropped permission.
    fixture
        .storage
        .raw_conn()
        .execute(
            "UPDATE api_keys SET scopes = 'admin' WHERE account_id = ?1",
            [first],
        )
        .unwrap();
    let err = fixture
        .storage
        .find_api_key_by_prefix("pk_shared")
        .unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)), "got {err}");
}

// --------------------------------------------------------------------- messages

#[test]
fn message_ids_are_reserved_before_insert() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);

    let first = fixture.storage.reserve_message_id().unwrap();
    assert_eq!(first, 1);
    assert_eq!(
        fixture
            .storage
            .insert_message(new_message(account_id, first, None), first)
            .unwrap(),
        first,
        "insert must use the reserved id"
    );

    let second = fixture.storage.reserve_message_id().unwrap();
    assert_eq!(second, 2);
    assert_eq!(
        fixture
            .storage
            .insert_message(new_message(account_id, second, None), second)
            .unwrap(),
        second
    );

    // A reservation that is never inserted burns the id: AUTOINCREMENT never
    // reissues it, which is what keeps a sealed blob bound to one id forever.
    let burned = fixture.storage.reserve_message_id().unwrap();
    assert_eq!(burned, 3);
    assert_eq!(fixture.storage.reserve_message_id().unwrap(), 4);
}

#[test]
fn heavy_concurrent_reservations_keep_ids_and_aad_aligned() {
    const THREADS: usize = 8;
    const PER_THREAD: usize = 8;

    let fixture = fixture();
    let account_id = new_account(&fixture.storage);

    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let path = fixture.path.clone();
            std::thread::spawn(move || {
                let storage = SqliteStorage::open(&path).expect("open worker connection");
                let mut ids = Vec::with_capacity(PER_THREAD);
                for _ in 0..PER_THREAD {
                    let reserved = storage.reserve_message_id().expect("reserve id");
                    let inserted = storage
                        .insert_message(new_message(account_id, reserved, None), reserved)
                        .expect("insert reserved id");
                    ids.push((reserved, inserted));
                }
                ids
            })
        })
        .collect();

    let mut ids = Vec::with_capacity(THREADS * PER_THREAD);
    for handle in handles {
        ids.extend(handle.join().expect("worker thread must not panic"));
    }
    assert_eq!(ids.len(), THREADS * PER_THREAD);
    for (reserved, inserted) in &ids {
        assert_eq!(
            reserved, inserted,
            "the row id must be the id the body was sealed with"
        );
    }
    let unique: HashSet<i64> = ids.iter().map(|(reserved, _)| *reserved).collect();
    assert_eq!(unique.len(), ids.len(), "no id may be handed out twice");

    // Every stored blob opens under the AAD derived from its own row, and only
    // that one.
    for id in &unique {
        let row = fixture.storage.get_message(*id).expect("row exists");
        let bound = message_aad(account_id, *id);
        assert_eq!(
            open_content(&TEST_KEY, &row.sealed_body, bound.as_bytes()).unwrap(),
            b"Subject: hi\r\n\r\nbody"
        );
        let other = message_aad(account_id, id + 1);
        assert!(
            open_content(&TEST_KEY, &row.sealed_body, other.as_bytes()).is_err(),
            "a blob must not open under another message id"
        );
    }
    assert_eq!(
        count(&fixture.storage, "SELECT COUNT(*) FROM messages"),
        ids.len() as i64
    );
}

#[test]
fn sealed_body_roundtrip_binds_to_account_and_message_id() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let content_key = generate_content_key();

    // The service seals first, with the reserved id as associated data.
    let message_id = fixture.storage.reserve_message_id().unwrap();
    let aad = message_aad(account_id, message_id);
    let sealed = seal_content(&content_key, b"Subject: hi\r\n\r\nbody", aad.as_bytes()).unwrap();
    assert_ne!(sealed, b"Subject: hi\r\n\r\nbody");

    let inserted = fixture
        .storage
        .insert_message(
            NewMessage {
                account_id,
                direction: Direction::Out,
                from_addr: addr("owner@example.com"),
                to_addrs: vec![addr("peer@example.net"), addr("cc@example.org")],
                subject: "hello".to_string(),
                sealed_body: sealed.clone(),
                idempotency_key: None,
                delivered_for: None,
            },
            message_id,
        )
        .unwrap();
    assert_eq!(inserted, message_id, "reserved id must survive the insert");

    let row = fixture.storage.get_message(message_id).unwrap();
    assert_eq!(row.id, message_id);
    assert_eq!(row.account_id, account_id);
    assert_eq!(row.direction, Direction::Out);
    assert_eq!(row.from_addr, addr("owner@example.com"));
    assert_eq!(
        row.to_addrs,
        vec![addr("peer@example.net"), addr("cc@example.org")]
    );
    assert_eq!(row.subject, "hello");
    assert_eq!(row.status, "stored");
    assert!(!row.created_at.is_empty());
    assert_eq!(
        row.sealed_body, sealed,
        "store returns the sealed blob as-is"
    );

    // The caller can only open it with the right key *and* the right context.
    let plain = open_content(&content_key, &row.sealed_body, aad.as_bytes()).unwrap();
    assert_eq!(plain, b"Subject: hi\r\n\r\nbody");
    let other_aad = message_aad(account_id, message_id + 1);
    assert!(
        open_content(&content_key, &row.sealed_body, other_aad.as_bytes()).is_err(),
        "a blob must not open under another message context"
    );
}

#[test]
fn insert_message_rejects_anything_that_is_not_a_sealed_envelope() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let valid = sealed_body(account_id, 1, b"body");
    let mut future = valid.clone();
    future[0] = ENVELOPE_VERSION.wrapping_add(1);
    let cases: [(&str, Vec<u8>); 4] = [
        ("empty", Vec::new()),
        ("plaintext", b"Subject: hi\r\n\r\nhello".to_vec()),
        ("truncated", valid[..MIN_BLOB_LEN - 1].to_vec()),
        ("unknown envelope version", future),
    ];

    for (label, body) in cases {
        let reserved = fixture.storage.reserve_message_id().unwrap();
        let message = NewMessage {
            sealed_body: body,
            ..new_message(account_id, reserved, None)
        };
        let err = fixture
            .storage
            .insert_message(message, reserved)
            .unwrap_err();
        assert!(
            matches!(err, StoreError::InvalidSealedBody(_)),
            "{label}: got {err}"
        );
    }
    assert_eq!(
        count(&fixture.storage, "SELECT COUNT(*) FROM messages"),
        0,
        "a rejected body must never be stored"
    );
}

#[test]
fn a_body_sealed_for_one_account_does_not_open_for_another() {
    let fixture = fixture();
    let alice = fixture
        .storage
        .create_account(&addr("alice@example.com"))
        .unwrap();
    let bob = fixture
        .storage
        .create_account(&addr("bob@example.com"))
        .unwrap();

    // Alice's message: sealed with Alice's account in the AAD.
    let alice_id = fixture.storage.reserve_message_id().unwrap();
    let body = sealed_body(alice, alice_id, b"Subject: secret\r\n\r\ntop");
    fixture
        .storage
        .insert_message(
            NewMessage {
                account_id: alice,
                sealed_body: body.clone(),
                ..new_message(alice, alice_id, None)
            },
            alice_id,
        )
        .unwrap();

    // Now transplant the same blob onto Bob's account. The store cannot detect
    // this — it has no key — but the AAD binding must make it unopenable there.
    let bob_id = fixture.storage.reserve_message_id().unwrap();
    let transplanted = fixture
        .storage
        .insert_message(
            NewMessage {
                account_id: bob,
                sealed_body: body,
                ..new_message(bob, bob_id, None)
            },
            bob_id,
        )
        .unwrap();
    let row = fixture.storage.get_message(transplanted).unwrap();
    let err = open_content(
        &TEST_KEY,
        &row.sealed_body,
        message_aad(bob, transplanted).as_bytes(),
    )
    .unwrap_err();
    assert!(matches!(err, CryptoError::Decrypt), "got {err}");

    // The original still opens under Alice's context.
    let original = fixture.storage.get_message(alice_id).unwrap();
    assert_eq!(
        open_content(
            &TEST_KEY,
            &original.sealed_body,
            message_aad(alice, alice_id).as_bytes()
        )
        .unwrap(),
        b"Subject: secret\r\n\r\ntop"
    );
}

#[test]
fn a_repeated_idempotency_key_returns_the_same_message() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);

    let first = insert(&fixture.storage, account_id, Some("submission-42"));
    let replay = insert(&fixture.storage, account_id, Some("submission-42"));
    assert_eq!(replay, first, "a replay must return the stored id");
    assert_eq!(
        count(&fixture.storage, "SELECT COUNT(*) FROM messages"),
        1,
        "a replay must not insert a second row"
    );

    // The key is scoped per account: another account may reuse the same string.
    let other = fixture
        .storage
        .create_account(&addr("other@example.com"))
        .unwrap();
    let other_id = insert(&fixture.storage, other, Some("submission-42"));
    assert_ne!(other_id, first);
    assert_eq!(count(&fixture.storage, "SELECT COUNT(*) FROM messages"), 2);

    // Messages without a key never deduplicate.
    let unkeyed_first = insert(&fixture.storage, account_id, None);
    let unkeyed_second = insert(&fixture.storage, account_id, None);
    assert_ne!(unkeyed_first, unkeyed_second);
}

#[test]
fn list_messages_pages_newest_first_without_bodies() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let other_account = fixture
        .storage
        .create_account(&addr("other@example.com"))
        .unwrap();
    let first = seed_message(&fixture.storage, account_id);
    let second = seed_message(&fixture.storage, account_id);
    seed_message(&fixture.storage, other_account);

    let all = fixture.storage.list_messages(account_id, 10, 0).unwrap();
    assert_eq!(all.len(), 2, "list is scoped to one account");
    assert_eq!(all[0].id, second, "newest first");
    assert_eq!(all[1].id, first);
    assert!(
        all.iter().all(|m| m.sealed_body.is_empty()),
        "listing must not load bodies"
    );
    assert_eq!(all[0].to_addrs, vec![addr("peer@example.net")]);
    assert_eq!(all[0].subject, "hello");

    let page = fixture.storage.list_messages(account_id, 1, 1).unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].id, first);
    assert!(fixture
        .storage
        .list_messages(account_id, 10, 99)
        .unwrap()
        .is_empty());
}

#[test]
fn list_messages_clamps_the_limit_into_the_page_bounds() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    for _ in 0..3 {
        seed_message(&fixture.storage, account_id);
    }

    // Below the bounds clamps up to one row instead of failing or returning an
    // empty page: an out-of-range page size must not hide the mailbox.
    for limit in [0, -1, i64::MIN] {
        let page = fixture.storage.list_messages(account_id, limit, 0).unwrap();
        assert_eq!(page.len(), 1, "limit {limit} must clamp to 1");
    }
    assert_eq!(
        fixture
            .storage
            .list_messages(account_id, 2, 0)
            .unwrap()
            .len(),
        2,
        "an in-range limit is honoured as-is"
    );

    // Above the bound clamps down to MAX_PAGE_LIMIT: no unbounded page.
    for limit in [MAX_PAGE_LIMIT + 1, i64::MAX] {
        let page = fixture.storage.list_messages(account_id, limit, 0).unwrap();
        assert_eq!(page.len(), 3, "limit {limit} clamps to {MAX_PAGE_LIMIT}");
    }
    assert_eq!(
        fixture
            .storage
            .list_messages(account_id, MAX_PAGE_LIMIT, 0)
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn corrupt_rows_degrade_in_listings_but_fail_single_reads() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let healthy = seed_message(&fixture.storage, account_id);
    let broken = seed_message(&fixture.storage, account_id);

    // The old comma-joined form is exactly what the JSON reader must reject.
    fixture
        .storage
        .raw_conn()
        .execute(
            "UPDATE messages SET to_addrs = 'peer@example.net,cc@example.org' WHERE id = ?1",
            [broken],
        )
        .unwrap();

    let listed = fixture.storage.list_messages(account_id, 10, 0).unwrap();
    assert_eq!(listed.len(), 2, "a corrupt row must not hide the page");
    assert_eq!(listed[0].id, broken);
    assert_eq!(listed[0].status, "corrupt_row");
    assert!(listed[0].to_addrs.is_empty());
    assert_eq!(listed[0].subject, "hello", "identity columns survive");
    assert_eq!(listed[1].id, healthy);
    assert_eq!(listed[1].status, "stored");

    let err = fixture.storage.get_message(broken).unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)), "got {err}");

    // An undecodable direction degrades the same way. The CHECK constraint
    // blocks this through normal SQL, so the test relaxes it for the statement
    // that simulates a hand-edited file (or a legacy row written before the
    // CHECK existed).
    {
        let conn = fixture.storage.raw_conn();
        conn.pragma_update(None, "ignore_check_constraints", "ON")
            .unwrap();
        conn.execute(
            "UPDATE messages SET direction = 'sideways' WHERE id = ?1",
            [broken],
        )
        .unwrap();
        conn.pragma_update(None, "ignore_check_constraints", "OFF")
            .unwrap();
    }
    let listed = fixture.storage.list_messages(account_id, 10, 0).unwrap();
    assert_eq!(listed[0].status, "corrupt_row");
    let err = fixture.storage.get_message(broken).unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)), "got {err}");
}

#[test]
fn get_message_reports_missing_rows() {
    let fixture = fixture();
    let err = fixture.storage.get_message(1234).unwrap_err();
    assert!(matches!(err, StoreError::NotFound), "got {err}");
}

// -------------------------------------------------------------------- folders

#[test]
fn the_folder_column_and_check_are_in_the_schema() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let message_id = seed_message(&fixture.storage, account_id);

    let conn = fixture.storage.raw_conn();
    for column in ["folder", "read_at"] {
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('messages') WHERE name = ?1)",
                [column],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "messages.{column} must exist");
    }

    // The CHECK keeps the column inside the closed set the domain can represent,
    // so an out-of-set value can only come from a hand-edited file.
    let bad_folder = conn.execute(
        "UPDATE messages SET folder = 'archive' WHERE id = ?1",
        [message_id],
    );
    assert!(bad_folder.is_err(), "messages.folder CHECK must reject");
}

#[test]
fn list_folder_uses_the_folder_index() {
    let fixture = fixture();
    let conn = fixture.storage.raw_conn();
    let mut stmt = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {}", list_folder_sql()))
        .unwrap();
    let plan: Vec<String> = stmt
        .query_map(params![1_i64, "inbox", 10_i64, 0_i64], |row| {
            row.get::<_, String>(3)
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        plan.iter().any(|step| step.contains("idx_messages_folder")),
        "the listing must use idx_messages_folder: {plan:?}"
    );
    assert!(
        !plan.iter().any(|step| step.contains("SCAN messages")),
        "the listing must not scan the messages table: {plan:?}"
    );
    assert!(
        !plan.iter().any(|step| step.contains("TEMP B-TREE")),
        "the index must supply the ORDER BY, not a sort: {plan:?}"
    );
}

#[test]
fn new_messages_start_in_the_inbox_unread() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let message_id = seed_message(&fixture.storage, account_id);

    let row = fixture.storage.get_message(message_id).unwrap();
    assert_eq!(
        row.folder,
        MessageFolder::Inbox,
        "the column default applies"
    );
    assert_eq!(row.read_at, None, "a fresh message is unread");

    // The listing agrees with the single read: both decode the same columns.
    let listed = fixture.storage.list_messages(account_id, 10, 0).unwrap();
    assert_eq!(listed[0].folder, MessageFolder::Inbox);
    assert_eq!(listed[0].read_at, None);
}

#[test]
fn set_message_folder_roundtrips_and_is_scoped_to_one_message() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let moved = seed_message(&fixture.storage, account_id);
    let untouched = seed_message(&fixture.storage, account_id);

    for folder in MessageFolder::all() {
        fixture.storage.set_message_folder(moved, *folder).unwrap();
        assert_eq!(
            fixture.storage.get_message(moved).unwrap().folder,
            *folder,
            "moving to {folder} must be readable back"
        );
    }

    assert_eq!(
        fixture.storage.get_message(untouched).unwrap().folder,
        MessageFolder::Inbox,
        "the other message must not move with it"
    );

    let err = fixture
        .storage
        .set_message_folder(999_999, MessageFolder::Spam)
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound), "got {err}");
}

#[test]
fn list_folder_filters_and_pages_per_folder() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let other_account = fixture
        .storage
        .create_account(&addr("other@example.com"))
        .unwrap();

    let inbox_first = seed_message(&fixture.storage, account_id);
    let inbox_second = seed_message(&fixture.storage, account_id);
    let spam = seed_message(&fixture.storage, account_id);
    fixture
        .storage
        .set_message_folder(spam, MessageFolder::Spam)
        .unwrap();
    let foreign = seed_message(&fixture.storage, other_account);

    let inbox = fixture
        .storage
        .list_folder(account_id, MessageFolder::Inbox, 10, 0)
        .unwrap();
    assert_eq!(
        inbox.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![inbox_second, inbox_first],
        "newest first, and only this account's inbox"
    );

    let spam_rows = fixture
        .storage
        .list_folder(account_id, MessageFolder::Spam, 10, 0)
        .unwrap();
    assert_eq!(spam_rows.len(), 1);
    assert_eq!(spam_rows[0].id, spam);
    assert_eq!(spam_rows[0].folder, MessageFolder::Spam);

    // Empty folders page to nothing instead of failing.
    for empty in [MessageFolder::Sent, MessageFolder::Trash] {
        assert!(fixture
            .storage
            .list_folder(account_id, empty, 10, 0)
            .unwrap()
            .is_empty());
    }

    // Paging works per folder, not per account.
    let page = fixture
        .storage
        .list_folder(account_id, MessageFolder::Inbox, 1, 1)
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].id, inbox_first);

    // The other account's message is invisible in both folders of this one.
    assert!(fixture
        .storage
        .list_folder(account_id, MessageFolder::Inbox, 10, 0)
        .unwrap()
        .iter()
        .all(|row| row.id != foreign));

    // `list_messages` still spans every folder (backward-compatible).
    assert_eq!(
        fixture
            .storage
            .list_messages(account_id, 10, 0)
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn count_folder_counts_one_account_and_folder() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let other_account = fixture
        .storage
        .create_account(&addr("other@example.com"))
        .unwrap();

    assert_eq!(
        fixture
            .storage
            .count_folder(account_id, MessageFolder::Inbox)
            .unwrap(),
        0,
        "an empty mailbox counts zero, not an error"
    );

    seed_message(&fixture.storage, account_id);
    let trashed = seed_message(&fixture.storage, account_id);
    fixture
        .storage
        .set_message_folder(trashed, MessageFolder::Trash)
        .unwrap();
    seed_message(&fixture.storage, other_account);

    assert_eq!(
        fixture
            .storage
            .count_folder(account_id, MessageFolder::Inbox)
            .unwrap(),
        1
    );
    assert_eq!(
        fixture
            .storage
            .count_folder(account_id, MessageFolder::Trash)
            .unwrap(),
        1
    );
    assert_eq!(
        fixture
            .storage
            .count_folder(account_id, MessageFolder::Spam)
            .unwrap(),
        0
    );
    assert_eq!(
        fixture
            .storage
            .count_folder(other_account, MessageFolder::Inbox)
            .unwrap(),
        1,
        "counts never leak across accounts"
    );
}

#[test]
fn set_message_read_stamps_and_clears_the_timestamp() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let message_id = seed_message(&fixture.storage, account_id);

    fixture.storage.set_message_read(message_id, true).unwrap();
    let read_at = fixture
        .storage
        .get_message(message_id)
        .unwrap()
        .read_at
        .expect("read marks a timestamp");
    assert!(!read_at.is_empty());

    // Idempotent: re-marking read keeps the first timestamp, so "when they read
    // it" stays truthful across repeated opens.
    fixture.storage.set_message_read(message_id, true).unwrap();
    assert_eq!(
        fixture.storage.get_message(message_id).unwrap().read_at,
        Some(read_at)
    );

    fixture.storage.set_message_read(message_id, false).unwrap();
    assert_eq!(
        fixture.storage.get_message(message_id).unwrap().read_at,
        None,
        "unread clears the timestamp"
    );

    let err = fixture.storage.set_message_read(999_999, true).unwrap_err();
    assert!(matches!(err, StoreError::NotFound), "got {err}");
}

#[test]
fn delete_message_removes_the_row_and_its_children() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let doomed = seed_message(&fixture.storage, account_id);
    let survivor = seed_message(&fixture.storage, account_id);
    fixture
        .storage
        .record_event(doomed, "received", "stored")
        .unwrap();
    fixture.storage.queue_enqueue(doomed, 0).unwrap();

    fixture.storage.delete_message(doomed).unwrap();
    assert!(matches!(
        fixture.storage.get_message(doomed).unwrap_err(),
        StoreError::NotFound
    ));
    assert_eq!(count(&fixture.storage, "SELECT COUNT(*) FROM messages"), 1);
    assert_eq!(
        count(&fixture.storage, "SELECT COUNT(*) FROM events"),
        0,
        "events cascade with the message"
    );
    assert_eq!(
        count(&fixture.storage, "SELECT COUNT(*) FROM queue"),
        0,
        "queue rows cascade with the message"
    );
    assert_eq!(fixture.storage.get_message(survivor).unwrap().id, survivor);

    let err = fixture.storage.delete_message(doomed).unwrap_err();
    assert!(matches!(err, StoreError::NotFound), "got {err}");
}

#[test]
fn empty_folder_returns_its_count_and_only_clears_that_folder_and_account() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let other_account = fixture
        .storage
        .create_account(&addr("other@example.com"))
        .unwrap();

    let first = seed_message(&fixture.storage, account_id);
    let second = seed_message(&fixture.storage, account_id);
    for id in [first, second] {
        fixture
            .storage
            .set_message_folder(id, MessageFolder::Trash)
            .unwrap();
    }
    let kept = seed_message(&fixture.storage, account_id);
    let foreign_trash = seed_message(&fixture.storage, other_account);
    fixture
        .storage
        .set_message_folder(foreign_trash, MessageFolder::Trash)
        .unwrap();

    assert_eq!(
        fixture
            .storage
            .empty_folder(account_id, MessageFolder::Trash)
            .unwrap(),
        2,
        "the count is the number of rows actually deleted"
    );
    assert_eq!(
        fixture
            .storage
            .count_folder(account_id, MessageFolder::Trash)
            .unwrap(),
        0
    );
    assert_eq!(
        fixture.storage.get_message(kept).unwrap().folder,
        MessageFolder::Inbox,
        "an inbox message survives emptying trash"
    );
    assert!(
        fixture.storage.get_message(foreign_trash).is_ok(),
        "another account's trash is untouched"
    );

    // Emptying an already-empty folder is a zero, not an error: the API answers
    // idempotently.
    assert_eq!(
        fixture
            .storage
            .empty_folder(account_id, MessageFolder::Trash)
            .unwrap(),
        0
    );
}

// ------------------------------------------------------- trash retention

/// Rewrite `messages.trashed_at` to `now + offset` (days), the state the purge
/// path is supposed to act on. The store only ever writes `datetime('now')`, so
/// a test that needs "41 days ago" has to craft it. `offset` is a SQLite
/// modifier such as `'-41 days'`.
fn craft_trashed_at(storage: &SqliteStorage, message_id: i64, offset: &str) -> String {
    let conn = storage.raw_conn();
    conn.execute(
        "UPDATE messages SET trashed_at = datetime('now', ?2) WHERE id = ?1",
        params![message_id, offset],
    )
    .expect("craft trashed_at");
    conn.query_row(
        "SELECT trashed_at FROM messages WHERE id = ?1",
        [message_id],
        |row| row.get(0),
    )
    .expect("read back trashed_at")
}

fn trashed_at(storage: &SqliteStorage, message_id: i64) -> Option<String> {
    storage
        .raw_conn()
        .query_row(
            "SELECT trashed_at FROM messages WHERE id = ?1",
            [message_id],
            |row| row.get(0),
        )
        .expect("read trashed_at")
}

#[test]
fn trash_retention_defaults_to_30_days_and_roundtrips() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);

    assert_eq!(
        fixture.storage.get_trash_retention(account_id).unwrap(),
        30,
        "an account that never opened settings still has a bounded trash"
    );

    for days in [0_i64, 1, 90, 365] {
        fixture
            .storage
            .set_trash_retention(account_id, days)
            .unwrap();
        assert_eq!(
            fixture.storage.get_trash_retention(account_id).unwrap(),
            days,
            "{days} must round-trip"
        );
    }

    // Out of range is refused, and the stored value is untouched: a rejected
    // write must not be a half-write.
    for bad in [-1_i64, 366, 100_000] {
        let error = fixture
            .storage
            .set_trash_retention(account_id, bad)
            .unwrap_err();
        assert!(
            matches!(error, StoreError::InvalidArgument(_)),
            "{bad} must be refused, got {error}"
        );
        assert_eq!(
            fixture.storage.get_trash_retention(account_id).unwrap(),
            365
        );
    }

    // An unknown account is `NotFound` in both directions, never a default.
    assert!(matches!(
        fixture.storage.get_trash_retention(999_999).unwrap_err(),
        StoreError::NotFound
    ));
    assert!(matches!(
        fixture.storage.set_trash_retention(999_999, 7).unwrap_err(),
        StoreError::NotFound
    ));
}

#[test]
fn moving_into_the_trash_stamps_the_clock_and_leaving_clears_it() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let message_id = seed_message(&fixture.storage, account_id);

    assert_eq!(
        trashed_at(&fixture.storage, message_id),
        None,
        "a message in the inbox has no trash clock"
    );

    fixture
        .storage
        .set_message_folder(message_id, MessageFolder::Trash)
        .unwrap();
    let stamp =
        trashed_at(&fixture.storage, message_id).expect("entering the trash stamps the clock");
    assert!(!stamp.is_empty());

    // Re-moving to the trash keeps the first arrival: a client cannot reset its
    // own countdown by re-patching `folder=trash`.
    fixture
        .storage
        .set_message_folder(message_id, MessageFolder::Trash)
        .unwrap();
    assert_eq!(trashed_at(&fixture.storage, message_id), Some(stamp));

    // Restoring the message stops the countdown.
    fixture
        .storage
        .set_message_folder(message_id, MessageFolder::Inbox)
        .unwrap();
    assert_eq!(
        trashed_at(&fixture.storage, message_id),
        None,
        "leaving the trash clears the clock"
    );

    // ... and a later trip to the trash starts a fresh one.
    fixture
        .storage
        .set_message_folder(message_id, MessageFolder::Trash)
        .unwrap();
    assert!(trashed_at(&fixture.storage, message_id).is_some());
}

#[test]
fn purge_expired_trash_deletes_only_expired_trash_of_one_account() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let other_account = fixture
        .storage
        .create_account(&addr("other@example.com"))
        .unwrap();
    fixture.storage.set_trash_retention(account_id, 30).unwrap();

    // Old trash of this account: expired.
    let expired = seed_message(&fixture.storage, account_id);
    fixture
        .storage
        .set_message_folder(expired, MessageFolder::Trash)
        .unwrap();
    craft_trashed_at(&fixture.storage, expired, "-41 days");

    // Fresh trash of this account: must survive.
    let fresh = seed_message(&fixture.storage, account_id);
    fixture
        .storage
        .set_message_folder(fresh, MessageFolder::Trash)
        .unwrap();
    craft_trashed_at(&fixture.storage, fresh, "-2 days");

    // Every other folder, however old, is out of scope for this path.
    let inbox = seed_message(&fixture.storage, account_id);
    craft_trashed_at(&fixture.storage, inbox, "-400 days");
    let sent = seed_message(&fixture.storage, account_id);
    fixture
        .storage
        .set_message_folder(sent, MessageFolder::Sent)
        .unwrap();
    craft_trashed_at(&fixture.storage, sent, "-400 days");
    let spam = seed_message(&fixture.storage, account_id);
    fixture
        .storage
        .set_message_folder(spam, MessageFolder::Spam)
        .unwrap();
    craft_trashed_at(&fixture.storage, spam, "-400 days");

    // Another account's expired trash belongs to that account's policy.
    let foreign = seed_message(&fixture.storage, other_account);
    fixture
        .storage
        .set_message_folder(foreign, MessageFolder::Trash)
        .unwrap();
    craft_trashed_at(&fixture.storage, foreign, "-400 days");

    assert_eq!(
        fixture.storage.purge_expired_trash(account_id).unwrap(),
        1,
        "exactly the expired trash row of this account goes"
    );
    assert!(matches!(
        fixture.storage.get_message(expired).unwrap_err(),
        StoreError::NotFound
    ));
    for survivor in [fresh, inbox, sent, spam, foreign] {
        assert!(
            fixture.storage.get_message(survivor).is_ok(),
            "message {survivor} must survive"
        );
    }
    assert_eq!(fixture.storage.count_trash(account_id).unwrap(), 1);

    // A second run is idempotent: nothing left to purge.
    assert_eq!(fixture.storage.purge_expired_trash(account_id).unwrap(), 0);
}

#[test]
fn purge_expired_trash_keeps_everything_when_retention_is_zero() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    fixture.storage.set_trash_retention(account_id, 0).unwrap();

    let ancient = seed_message(&fixture.storage, account_id);
    fixture
        .storage
        .set_message_folder(ancient, MessageFolder::Trash)
        .unwrap();
    craft_trashed_at(&fixture.storage, ancient, "-4000 days");

    assert_eq!(
        fixture.storage.purge_expired_trash(account_id).unwrap(),
        0,
        "0 means keep forever, not expire everything"
    );
    assert!(fixture.storage.get_message(ancient).is_ok());

    // The worker's work list agrees: this account opted out.
    assert!(!fixture
        .storage
        .accounts_with_trash_purge()
        .unwrap()
        .contains(&account_id));
}

#[test]
fn purge_skips_trash_whose_clock_never_started() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let legacy = seed_message(&fixture.storage, account_id);
    fixture
        .storage
        .set_message_folder(legacy, MessageFolder::Trash)
        .unwrap();
    // A row that predates migration 0012: in the trash, but never stamped.
    fixture
        .storage
        .raw_conn()
        .execute(
            "UPDATE messages SET trashed_at = NULL WHERE id = ?1",
            [legacy],
        )
        .unwrap();

    assert_eq!(
        fixture.storage.purge_expired_trash(account_id).unwrap(),
        0,
        "an upgrade must not delete mail whose countdown never started"
    );
    assert!(fixture.storage.get_message(legacy).is_ok());
}

#[test]
fn accounts_with_trash_purge_lists_only_enabled_accounts() {
    let fixture = fixture();
    let enabled = new_account(&fixture.storage);
    let disabled = fixture
        .storage
        .create_account(&addr("keep@example.com"))
        .unwrap();
    fixture.storage.set_trash_retention(disabled, 0).unwrap();

    assert_eq!(
        fixture.storage.accounts_with_trash_purge().unwrap(),
        vec![enabled],
        "a fresh account is enabled by default; `0` opts out"
    );
}

// ------------------------------------------------------------------------ queue

#[test]
fn queue_claim_returns_one_exclusive_job() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let message_id = seed_message(&fixture.storage, account_id);
    let job_id = fixture.storage.queue_enqueue(message_id, 0).unwrap();

    let claimed = fixture
        .storage
        .queue_claim("worker-a", 60)
        .unwrap()
        .expect("a due job must be claimable");
    assert_eq!(claimed.id, job_id);
    assert_eq!(claimed.message_id, message_id);
    assert_eq!(claimed.attempts, 1);
    assert_eq!(claimed.claimed_by, "worker-a");
    assert_eq!(claimed.claim_token.len(), 32, "hex of 16 random bytes");
    assert!(claimed.claim_token.chars().all(|c| c.is_ascii_hexdigit()));

    assert!(
        fixture
            .storage
            .queue_claim("worker-b", 60)
            .unwrap()
            .is_none(),
        "a claimed job must not be handed to a second worker"
    );
}

#[test]
fn queue_claim_uses_the_live_index() {
    let fixture = fixture();
    let conn = fixture.storage.raw_conn();
    let mut stmt = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {QUEUE_CLAIM_SQL}"))
        .unwrap();
    let plan: Vec<String> = stmt
        .query_map(params!["token", "worker-a", 60_i64], |row| {
            row.get::<_, String>(3)
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        plan.iter().any(|step| step.contains("idx_queue_claim")),
        "the claim must use idx_queue_claim: {plan:?}"
    );
    assert!(
        !plan.iter().any(|step| step.contains("SCAN queue")),
        "the claim must not scan the queue table: {plan:?}"
    );
}

#[test]
fn queue_respects_run_after() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let message_id = seed_message(&fixture.storage, account_id);
    let far_future = i64::from(u32::MAX) * 4;
    fixture
        .storage
        .queue_enqueue(message_id, far_future)
        .unwrap();

    assert!(fixture
        .storage
        .queue_claim("worker-a", 60)
        .unwrap()
        .is_none());
}

#[test]
fn queue_fail_backs_off_then_allows_reclaim() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let message_id = seed_message(&fixture.storage, account_id);
    let job_id = fixture.storage.queue_enqueue(message_id, 0).unwrap();

    let claimed = fixture
        .storage
        .queue_claim("worker-a", 60)
        .unwrap()
        .unwrap();
    fixture
        .storage
        .queue_fail(&claimed.claim_token, "421 try later", 3600)
        .unwrap();

    assert!(
        fixture
            .storage
            .queue_claim("worker-a", 60)
            .unwrap()
            .is_none(),
        "a failed job must stay unclaimable until its backoff elapses"
    );
    {
        let conn = fixture.storage.raw_conn();
        let (run_after, last_error, token, attempts, status): (
            i64,
            String,
            Option<String>,
            i64,
            String,
        ) = conn
            .query_row(
                "SELECT run_after, last_error, claim_token, attempts, status
                   FROM queue WHERE id = ?1",
                [job_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert!(run_after > 0, "backoff must move run_after forward");
        assert_eq!(last_error, "421 try later");
        assert_eq!(token, None, "fail must release the claim token");
        assert_eq!(attempts, 1);
        assert_eq!(status, "ready", "attempts remain, so the job is not dead");
    }

    // Simulate the backoff elapsing rather than sleeping in a test.
    fixture
        .storage
        .raw_conn()
        .execute("UPDATE queue SET run_after = 0 WHERE id = ?1", [job_id])
        .unwrap();
    let claimed_again = fixture
        .storage
        .queue_claim("worker-b", 60)
        .unwrap()
        .unwrap();
    assert_eq!(claimed_again.id, job_id);
    assert_eq!(claimed_again.attempts, 2);
    assert_eq!(
        claimed_again.claimed_by, "worker-b",
        "a new claim records its own worker"
    );
    assert_ne!(
        claimed_again.claim_token, claimed.claim_token,
        "every claim uses a fresh token"
    );
    // Claiming clears the error from the previous attempt.
    let cleared: Option<String> = fixture
        .storage
        .raw_conn()
        .query_row(
            "SELECT last_error FROM queue WHERE id = ?1",
            [job_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(cleared, None);
}

#[test]
fn queue_complete_removes_the_job() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let message_id = seed_message(&fixture.storage, account_id);
    fixture.storage.queue_enqueue(message_id, 0).unwrap();

    let claimed = fixture
        .storage
        .queue_claim("worker-a", 60)
        .unwrap()
        .unwrap();
    fixture
        .storage
        .queue_complete(&claimed.claim_token)
        .unwrap();
    assert_eq!(count(&fixture.storage, "SELECT COUNT(*) FROM queue"), 0);
    assert!(fixture
        .storage
        .queue_claim("worker-a", 60)
        .unwrap()
        .is_none());

    // A token that no longer owns a job is rejected, not silently ignored.
    let err = fixture
        .storage
        .queue_complete(&claimed.claim_token)
        .unwrap_err();
    assert!(matches!(err, StoreError::QueueClaim(_)), "got {err}");
}

#[test]
fn queue_stale_lease_can_be_reclaimed() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let message_id = seed_message(&fixture.storage, account_id);
    let job_id = fixture.storage.queue_enqueue(message_id, 0).unwrap();

    let claimed = fixture
        .storage
        .queue_claim("worker-a", 60)
        .unwrap()
        .unwrap();
    assert_eq!(claimed.id, job_id);

    // Simulate a worker that died mid-delivery: its claim is older than the
    // lease, so another worker must be able to take the job over.
    fixture
        .storage
        .raw_conn()
        .execute(
            "UPDATE queue SET claimed_at = claimed_at - 600 WHERE id = ?1",
            [job_id],
        )
        .unwrap();
    let recovered = fixture
        .storage
        .queue_claim("worker-b", 60)
        .unwrap()
        .expect("an expired lease must be reclaimable");
    assert_eq!(recovered.id, job_id);
    assert_eq!(recovered.attempts, 2);
    assert_eq!(recovered.claimed_by, "worker-b");
    assert_ne!(recovered.claim_token, claimed.claim_token);

    // The worker that lost the lease can no longer report on the job.
    let err = fixture
        .storage
        .queue_fail(&claimed.claim_token, "late failure", 0)
        .unwrap_err();
    assert!(matches!(err, StoreError::QueueClaim(_)), "got {err}");
}

#[test]
fn queue_dead_letters_a_job_after_max_attempts() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let message_id = seed_message(&fixture.storage, account_id);
    fixture.storage.queue_enqueue(message_id, 0).unwrap();
    let max_attempts: i64 = fixture
        .storage
        .raw_conn()
        .query_row("SELECT max_attempts FROM queue", [], |row| row.get(0))
        .unwrap();
    assert!(max_attempts > 1, "the default retry budget must be usable");

    for attempt in 1..=max_attempts {
        let claimed = fixture
            .storage
            .queue_claim("worker-a", 60)
            .unwrap()
            .unwrap_or_else(|| panic!("attempt {attempt} must be claimable"));
        assert_eq!(claimed.attempts, attempt);
        // Zero backoff: the job is due again as soon as it is released.
        fixture
            .storage
            .queue_fail(&claimed.claim_token, "451 greylisted", 0)
            .unwrap();
    }

    assert!(
        fixture
            .storage
            .queue_claim("worker-a", 60)
            .unwrap()
            .is_none(),
        "an exhausted job must never be claimed again"
    );
    assert_eq!(
        fixture.storage.list_dead(10).unwrap(),
        vec![DeadJob {
            message_id,
            last_error: "451 greylisted".to_string(),
            attempts: max_attempts,
        }],
        "the dead letter keeps the last error and the attempt count"
    );
    assert!(fixture.storage.list_dead(0).unwrap().len() <= 1);
}

// -------------------------------------------------------------- events / audit

#[test]
fn events_are_listed_in_insertion_order() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let message_id = seed_message(&fixture.storage, account_id);

    fixture
        .storage
        .record_event(message_id, "queued", "run_after=0")
        .unwrap();
    fixture
        .storage
        .record_event(message_id, "sent", "250 2.0.0 OK")
        .unwrap();
    fixture
        .storage
        .record_event(message_id, "delivered", "")
        .unwrap();

    let events = fixture.storage.list_events(message_id).unwrap();
    assert_eq!(events.len(), 3);
    let kinds: Vec<&str> = events.iter().map(|(kind, _, _)| kind.as_str()).collect();
    assert_eq!(kinds, vec!["queued", "sent", "delivered"]);
    assert_eq!(events[1].1, "250 2.0.0 OK");
    assert!(
        events.iter().all(|(_, _, at)| !at.is_empty()),
        "timestamps come from the database clock"
    );

    let other_message = seed_message(&fixture.storage, account_id);
    assert!(fixture
        .storage
        .list_events(other_message)
        .unwrap()
        .is_empty());

    // An empty event kind is not a representable event.
    let err = fixture
        .storage
        .record_event(message_id, "", "no kind")
        .unwrap_err();
    assert!(matches!(err, StoreError::Sqlite(_)), "got {err}");
}

#[test]
fn audit_appends_one_row_per_action() {
    let fixture = fixture();
    fixture
        .storage
        .audit("ops@example.com", "api_key.create", "name=ci")
        .unwrap();
    fixture
        .storage
        .audit("ops@example.com", "api_key.revoke", "id=1")
        .unwrap();
    assert_eq!(count(&fixture.storage, "SELECT COUNT(*) FROM audit"), 2);
}

// --------------------------------------------------------- totp / templates

#[test]
fn totp_secret_upserts_per_account() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    assert_eq!(fixture.storage.get_totp_secret(account_id).unwrap(), None);

    fixture
        .storage
        .set_totp_secret(account_id, b"wrapped-v1")
        .unwrap();
    assert_eq!(
        fixture.storage.get_totp_secret(account_id).unwrap(),
        Some(b"wrapped-v1".to_vec())
    );

    fixture
        .storage
        .set_totp_secret(account_id, b"wrapped-v2")
        .unwrap();
    assert_eq!(
        fixture.storage.get_totp_secret(account_id).unwrap(),
        Some(b"wrapped-v2".to_vec())
    );
    assert_eq!(
        count(&fixture.storage, "SELECT COUNT(*) FROM totp_secrets"),
        1,
        "one secret per account"
    );
}

#[test]
fn templates_are_unique_per_account_and_name() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let other_account = fixture
        .storage
        .create_account(&addr("other@example.com"))
        .unwrap();
    assert_eq!(
        fixture.storage.get_template(account_id, "welcome").unwrap(),
        None
    );

    fixture
        .storage
        .put_template(account_id, "welcome", "Hi {{name}}", "<p>Hi</p>", "Hi")
        .unwrap();
    fixture
        .storage
        .put_template(account_id, "welcome", "Hello {{name}}", "<p>Hey</p>", "Hey")
        .unwrap();
    let template = fixture
        .storage
        .get_template(account_id, "welcome")
        .unwrap()
        .expect("template exists");
    assert_eq!(template.account_id, account_id);
    assert_eq!(template.name, "welcome");
    assert_eq!(template.subject_tpl, "Hello {{name}}");
    assert_eq!(template.html_tpl, "<p>Hey</p>");
    assert_eq!(template.text_tpl, "Hey");
    assert!(!template.updated_at.is_empty());
    assert_eq!(
        count(&fixture.storage, "SELECT COUNT(*) FROM templates"),
        1,
        "re-putting the same name must update, not duplicate"
    );

    // Same name, different account: a separate row.
    fixture
        .storage
        .put_template(other_account, "welcome", "Other", "", "")
        .unwrap();
    assert_eq!(count(&fixture.storage, "SELECT COUNT(*) FROM templates"), 2);
    assert_eq!(
        fixture
            .storage
            .get_template(other_account, "welcome")
            .unwrap()
            .unwrap()
            .subject_tpl,
        "Other"
    );
}

#[test]
fn templates_store_a_description_and_stay_unlimited() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);

    for index in 0..40 {
        fixture
            .storage
            .put_template_with_description(
                account_id,
                &format!("template-{index}"),
                &format!("What template {index} is for"),
                "Hi {{name}}",
                "<p>Hi {{name}}</p>",
                "Hi {{name}}",
            )
            .unwrap();
    }
    let template = fixture
        .storage
        .get_template(account_id, "template-7")
        .unwrap()
        .expect("template exists");
    assert_eq!(template.description, "What template 7 is for");
    assert_eq!(
        count(
            &fixture.storage,
            &format!("SELECT COUNT(*) FROM templates WHERE account_id = {account_id}")
        ),
        40,
        "creating templates must never hit a cap"
    );

    // Re-putting the same name updates in place, description included.
    fixture
        .storage
        .put_template_with_description(account_id, "template-7", "Rewritten", "Hi", "", "")
        .unwrap();
    let updated = fixture
        .storage
        .get_template(account_id, "template-7")
        .unwrap()
        .expect("template exists");
    assert_eq!(updated.description, "Rewritten");
    assert_eq!(
        count(&fixture.storage, "SELECT COUNT(*) FROM templates"),
        40
    );

    // The description-less form still works and leaves an empty description.
    fixture
        .storage
        .put_template(account_id, "plain", "Hi", "", "")
        .unwrap();
    assert_eq!(
        fixture
            .storage
            .get_template(account_id, "plain")
            .unwrap()
            .expect("template exists")
            .description,
        ""
    );
}

// ---------------------------------------------------------------- drafts

fn new_draft(subject: &str) -> NewDraft {
    NewDraft {
        from_addr: "Dana <dana@example.com>".to_string(),
        to_addrs: vec!["carol@example.org".to_string()],
        cc_addrs: Vec::new(),
        bcc_addrs: vec!["secret@example.org".to_string()],
        subject: Some(subject.to_string()),
        body_html: Some("<p>still writing</p>".to_string()),
        body_text: Some("still writing".to_string()),
        attachments: vec![serde_json::json!({"filename": "notes.txt", "content": "aGVsbG8="})],
        tags: vec!["billing".to_string()],
    }
}

#[test]
fn drafts_are_created_updated_listed_and_deleted() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let other_account = fixture
        .storage
        .create_account(&addr("other@example.com"))
        .unwrap();

    assert_eq!(fixture.storage.count_drafts(account_id).unwrap(), 0);
    let draft_id = fixture
        .storage
        .create_draft(account_id, "drf_0000000000000001", &new_draft("First"))
        .unwrap();
    assert!(draft_id > 0);

    let stored = fixture
        .storage
        .get_draft("drf_0000000000000001", account_id)
        .unwrap()
        .expect("draft exists");
    assert_eq!(stored.public_id, "drf_0000000000000001");
    assert_eq!(stored.subject.as_deref(), Some("First"));
    assert_eq!(stored.body_html.as_deref(), Some("<p>still writing</p>"));
    assert_eq!(stored.to_addrs, vec!["carol@example.org".to_string()]);
    assert_eq!(stored.bcc_addrs, vec!["secret@example.org".to_string()]);
    assert_eq!(stored.tags, vec!["billing".to_string()]);
    assert_eq!(
        stored.attachments[0]["filename"], "notes.txt",
        "attachment JSON round-trips untouched"
    );
    assert!(!stored.updated_at.is_empty());

    // A draft is account-scoped: another account cannot read or replace it.
    assert!(fixture
        .storage
        .get_draft("drf_0000000000000001", other_account)
        .unwrap()
        .is_none());
    assert!(!fixture
        .storage
        .update_draft("drf_0000000000000001", other_account, &new_draft("Hijack"))
        .unwrap());
    assert!(!fixture
        .storage
        .delete_draft("drf_0000000000000001", other_account)
        .unwrap());

    // Updating replaces the contents and bumps `updated_at`.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let mut updated_draft = new_draft("Renamed");
    updated_draft.to_addrs = vec!["erin@example.org".to_string()];
    updated_draft.attachments = Vec::new();
    assert!(fixture
        .storage
        .update_draft("drf_0000000000000001", account_id, &updated_draft)
        .unwrap());
    let updated = fixture
        .storage
        .get_draft("drf_0000000000000001", account_id)
        .unwrap()
        .expect("draft exists");
    assert_eq!(updated.subject.as_deref(), Some("Renamed"));
    assert_eq!(updated.to_addrs, vec!["erin@example.org".to_string()]);
    assert!(
        updated.attachments.is_empty(),
        "an update replaces the list"
    );
    assert!(
        updated.updated_at > stored.updated_at,
        "{} must be newer than {}",
        updated.updated_at,
        stored.updated_at
    );

    // Listing is newest-save first and paginates.
    fixture
        .storage
        .create_draft(account_id, "drf_0000000000000002", &new_draft("Second"))
        .unwrap();
    let listed = fixture.storage.list_drafts(account_id, 10, 0).unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].public_id, "drf_0000000000000002");
    let page = fixture.storage.list_drafts(account_id, 1, 0).unwrap();
    assert_eq!(page.len(), 1, "limit is honoured");
    assert_eq!(page[0].public_id, "drf_0000000000000002");
    assert_eq!(
        fixture
            .storage
            .list_drafts(other_account, 10, 0)
            .unwrap()
            .len(),
        0,
        "another account sees nothing"
    );
    assert_eq!(fixture.storage.count_drafts(account_id).unwrap(), 2);

    assert!(fixture
        .storage
        .delete_draft("drf_0000000000000001", account_id)
        .unwrap());
    assert!(!fixture
        .storage
        .delete_draft("drf_0000000000000001", account_id)
        .unwrap());
    assert!(fixture
        .storage
        .get_draft("drf_0000000000000001", account_id)
        .unwrap()
        .is_none());
    assert_eq!(fixture.storage.count_drafts(account_id).unwrap(), 1);
}

/// The migrations really created what this feature needs.
#[test]
fn migration_0007_and_0008_created_the_drafts_table_and_the_description_column() {
    let fixture = fixture();
    assert_eq!(count(&fixture.storage, "SELECT COUNT(*) FROM drafts"), 0);
    assert!(
        MIGRATIONS
            .iter()
            .any(|m| m.contains("CREATE TABLE IF NOT EXISTS drafts")),
        "migration 0007 must create the drafts table"
    );
    assert!(
        MIGRATIONS
            .iter()
            .any(|m| m.contains("ALTER TABLE templates ADD COLUMN description")),
        "migration 0008 must add the description column"
    );
    // The column is queryable and defaults to an empty string, so a row written
    // without it (as an older build would) still reads back.
    let account_id = new_account(&fixture.storage);
    let conn = fixture.storage.raw_conn();
    conn.execute(
        "INSERT INTO templates (account_id, name, subject_tpl, html_tpl, text_tpl)
         VALUES (?1, 'legacy', '', '', '')",
        params![account_id],
    )
    .unwrap();
    let description: String = conn
        .query_row(
            "SELECT description FROM templates WHERE name = 'legacy'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(description, "");
}

// ------------------------------------------------------- sessions / 2fa enrollment

#[test]
fn accounts_are_found_by_normalized_email() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);

    assert_eq!(
        fixture
            .storage
            .get_account_by_email("owner@example.com")
            .unwrap(),
        Some(account_id)
    );
    assert_eq!(
        fixture
            .storage
            .get_account_by_email("nobody@example.com")
            .unwrap(),
        None
    );
}

#[test]
fn sessions_are_looked_up_live_and_die_on_expiry_or_revocation() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);

    let expires_at = fixture
        .storage
        .create_session("sess_0000000000000001", account_id, "phc$hash", 3600)
        .unwrap();
    assert!(!expires_at.is_empty(), "the row owns its expiry stamp");

    let row = fixture
        .storage
        .get_session_by_id("sess_0000000000000001")
        .unwrap()
        .expect("live session");
    assert_eq!(row.account_id, account_id);
    assert_eq!(row.token_hash, "phc$hash");
    assert_eq!(row.expires_at, expires_at);
    assert!(!row.created_at.is_empty());

    // Unknown ids are absent, not an error.
    assert_eq!(
        fixture
            .storage
            .get_session_by_id("sess_deadbeefdeadbeef")
            .unwrap(),
        None
    );

    // A session that has already expired is invisible to lookup, which is what
    // makes "no row" mean "not authenticated".
    fixture
        .storage
        .create_session("sess_0000000000000002", account_id, "phc$old", 0)
        .unwrap();
    assert_eq!(
        fixture
            .storage
            .get_session_by_id("sess_0000000000000002")
            .unwrap(),
        None,
        "an expired session must not authenticate"
    );

    fixture
        .storage
        .revoke_session("sess_0000000000000001")
        .unwrap();
    assert_eq!(
        fixture
            .storage
            .get_session_by_id("sess_0000000000000001")
            .unwrap(),
        None
    );
    assert!(matches!(
        fixture.storage.revoke_session("sess_0000000000000001"),
        Err(StoreError::NotFound)
    ));
    assert_eq!(
        count(&fixture.storage, "SELECT COUNT(*) FROM sessions"),
        2,
        "revocation marks the row, it does not delete it"
    );
}

#[test]
fn one_account_can_revoke_every_session_but_the_current_one() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    let other_account = fixture
        .storage
        .create_account(&addr("other@example.com"))
        .unwrap();
    for id in [
        "sess_0000000000000001",
        "sess_0000000000000002",
        "sess_0000000000000003",
    ] {
        fixture
            .storage
            .create_session(id, account_id, "phc$hash", 3600)
            .unwrap();
    }
    fixture
        .storage
        .create_session("sess_0000000000000009", other_account, "phc$hash", 3600)
        .unwrap();

    let revoked = fixture
        .storage
        .revoke_all_account_sessions(account_id, Some("sess_0000000000000001"))
        .unwrap();
    assert_eq!(revoked, 2);
    assert!(
        fixture
            .storage
            .get_session_by_id("sess_0000000000000001")
            .unwrap()
            .is_some(),
        "the session that asked to revoke the others keeps working"
    );
    assert_eq!(
        count(
            &fixture.storage,
            "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NOT NULL"
        ),
        2
    );
    assert!(
        fixture
            .storage
            .get_session_by_id("sess_0000000000000009")
            .unwrap()
            .is_some(),
        "another account's sessions are untouched"
    );

    // Without an exception every session of the account goes.
    assert_eq!(
        fixture
            .storage
            .revoke_all_account_sessions(account_id, None)
            .unwrap(),
        1
    );
    assert_eq!(
        fixture
            .storage
            .get_session_by_id("sess_0000000000000001")
            .unwrap(),
        None
    );
}

#[test]
fn totp_enrollment_upserts_and_only_confirms_with_codes() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    assert_eq!(
        fixture.storage.get_totp_enrollment(account_id).unwrap(),
        None
    );

    fixture
        .storage
        .set_totp_enrollment(account_id, b"wrapped-secret")
        .unwrap();
    let enrollment = fixture
        .storage
        .get_totp_enrollment(account_id)
        .unwrap()
        .expect("enrollment row");
    assert_eq!(enrollment.secret_wrapped, b"wrapped-secret".to_vec());
    assert!(
        !enrollment.confirmed,
        "a fresh enrollment is not active yet"
    );
    assert_eq!(enrollment.last_used_step, None);
    assert!(enrollment.recovery_codes.is_empty());
    assert_eq!(enrollment.enrolled_at, None);

    // Re-enrolling replaces the secret and drops any earlier confirmation.
    fixture
        .storage
        .set_totp_enrollment(account_id, b"wrapped-secret-v2")
        .unwrap();
    assert_eq!(
        fixture
            .storage
            .get_totp_enrollment(account_id)
            .unwrap()
            .unwrap()
            .secret_wrapped,
        b"wrapped-secret-v2".to_vec()
    );
    assert_eq!(
        count(&fixture.storage, "SELECT COUNT(*) FROM totp_enrollments"),
        1
    );

    fixture
        .storage
        .confirm_totp(
            account_id,
            &["phc$code1".to_string(), "phc$code2".to_string()],
            500,
        )
        .unwrap();
    let confirmed = fixture
        .storage
        .get_totp_enrollment(account_id)
        .unwrap()
        .expect("confirmed row");
    assert!(confirmed.confirmed);
    assert_eq!(confirmed.last_used_step, Some(500));
    assert_eq!(
        confirmed.recovery_codes,
        vec!["phc$code1".to_string(), "phc$code2".to_string()]
    );
    assert!(
        confirmed.enrolled_at.is_some(),
        "confirmation stamps the enrollment"
    );

    // Confirming without an enrollment in progress is a missing row, not a
    // silent success.
    let untouched = fixture
        .storage
        .create_account(&addr("other@example.com"))
        .unwrap();
    assert!(matches!(
        fixture.storage.confirm_totp(untouched, &[], 1),
        Err(StoreError::NotFound)
    ));
}

#[test]
fn last_used_step_rejects_replays_atomically() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    fixture
        .storage
        .set_totp_enrollment(account_id, b"wrapped-secret")
        .unwrap();
    fixture.storage.confirm_totp(account_id, &[], 100).unwrap();

    assert!(
        !fixture.storage.set_totp_last_step(account_id, 100).unwrap(),
        "the step already used must be refused"
    );
    assert!(!fixture.storage.set_totp_last_step(account_id, 99).unwrap());
    assert!(fixture.storage.set_totp_last_step(account_id, 101).unwrap());
    assert_eq!(
        fixture
            .storage
            .get_totp_enrollment(account_id)
            .unwrap()
            .unwrap()
            .last_used_step,
        Some(101)
    );
    assert!(!fixture.storage.set_totp_last_step(account_id, 101).unwrap());
    assert!(fixture.storage.set_totp_last_step(account_id, 102).unwrap());
}

#[test]
fn recovery_codes_burn_exactly_once() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    fixture
        .storage
        .set_totp_enrollment(account_id, b"wrapped-secret")
        .unwrap();
    fixture
        .storage
        .confirm_totp(
            account_id,
            &[
                "phc$one".to_string(),
                "phc$two".to_string(),
                "phc$three".to_string(),
            ],
            1,
        )
        .unwrap();

    assert!(fixture.storage.burn_recovery_code(account_id, 1).unwrap());
    assert_eq!(
        fixture
            .storage
            .get_totp_enrollment(account_id)
            .unwrap()
            .unwrap()
            .recovery_codes,
        vec!["phc$one".to_string(), "phc$three".to_string()],
        "only the used code is removed"
    );

    assert!(
        !fixture.storage.burn_recovery_code(account_id, 7).unwrap(),
        "an out-of-range index burns nothing"
    );
    // The array shrank, so the surviving codes keep burning by index until it
    // is empty; an empty list has nothing left to spend.
    assert!(fixture.storage.burn_recovery_code(account_id, 1).unwrap());
    assert!(fixture.storage.burn_recovery_code(account_id, 0).unwrap());
    assert!(
        !fixture.storage.burn_recovery_code(account_id, 0).unwrap(),
        "a burned-out list must reject rather than echo success"
    );
    assert_eq!(
        fixture
            .storage
            .get_totp_enrollment(account_id)
            .unwrap()
            .unwrap()
            .recovery_codes,
        Vec::<String>::new()
    );
    assert_eq!(
        count(&fixture.storage, "SELECT COUNT(*) FROM totp_enrollments"),
        1
    );
}

#[test]
fn revoking_totp_removes_the_enrollment() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);
    fixture
        .storage
        .set_totp_enrollment(account_id, b"wrapped-secret")
        .unwrap();
    fixture.storage.confirm_totp(account_id, &[], 1).unwrap();

    fixture.storage.revoke_totp(account_id).unwrap();
    assert_eq!(
        fixture.storage.get_totp_enrollment(account_id).unwrap(),
        None
    );
    assert_eq!(
        count(&fixture.storage, "SELECT COUNT(*) FROM totp_enrollments"),
        0
    );
    // Revoking nothing is a no-op, not an error: disable must be idempotent.
    fixture.storage.revoke_totp(account_id).unwrap();
}

// --------------------------------------------------------------- dkim keys

/// AAD the service uses for a domain's sealed private key: `pigeon-api`'s
/// `aad::dkim_key`. Pinned here as a literal on purpose — the store test must
/// not import the API crate, and the string is a wire format.
fn dkim_aad(domain: &str) -> String {
    format!("dkim:{domain}")
}

/// The store's job is narrow: hand back exactly the wrapped bytes it was given,
/// so the caller's seal/unseal roundtrip survives persistence. This seals a
/// PKCS#8 private key under the master key, stores it, reads it back and unseals
/// it — the whole path the worker runs on every send.
#[test]
fn dkim_key_roundtrips_sealed_under_the_master_key() {
    let fixture = fixture();
    let master = MasterKey::parse(&[3u8; 32]).expect("master key");
    let domain = "example.com";
    let aad = dkim_aad(domain);
    let pkcs8 = b"pretend-this-is-a-pkcs8-private-key";
    let dns = "v=DKIM1; k=rsa; p=QUJD";

    // Seal the private key with a fresh content key and wrap that key under the
    // master key: the store never sees plaintext key material.
    let content_key = generate_content_key();
    let sealed = seal_content(&content_key, pkcs8, aad.as_bytes()).expect("seal");
    let wrapped = master
        .wrap_content_key(&content_key, aad.as_bytes())
        .expect("wrap");

    fixture
        .storage
        .put_dkim_key(domain, "pigeon", &sealed, dns)
        .expect("put");

    let (selector, stored, stored_dns) = fixture
        .storage
        .get_dkim_key(domain)
        .expect("get")
        .expect("the row exists");
    assert_eq!(selector, "pigeon");
    assert_eq!(stored_dns, dns);
    assert_eq!(stored, sealed, "the store must not alter the wrapped blob");

    // Unseal: the bytes that come back out are the bytes that went in.
    let unwrapped_key = master
        .unwrap_content_key(&wrapped, aad.as_bytes())
        .expect("unwrap");
    let opened = open_content(&unwrapped_key, &stored, aad.as_bytes()).expect("open");
    assert_eq!(opened, pkcs8);
}

#[test]
fn dkim_key_for_an_unknown_domain_is_none_not_an_error() {
    let fixture = fixture();
    assert!(fixture
        .storage
        .get_dkim_key("nobody.example")
        .expect("lookup is not an error")
        .is_none());
    assert!(fixture.storage.list_dkim_keys().expect("list").is_empty());
}

/// Keys are domain-scoped: putting the same domain twice rotates the single row
/// (a second identity for one selector would make the public record flap).
#[test]
fn putting_the_same_domain_rotates_the_existing_row() {
    let fixture = fixture();
    fixture
        .storage
        .put_dkim_key("example.com", "pigeon", b"old", "v=DKIM1; p=OLD")
        .expect("first put");
    fixture
        .storage
        .put_dkim_key("example.com", "pigeon2", b"new", "v=DKIM1; p=NEW")
        .expect("second put");

    let (selector, wrapped, dns) = fixture
        .storage
        .get_dkim_key("example.com")
        .expect("get")
        .expect("row");
    assert_eq!(selector, "pigeon2", "the selector rotates with the key");
    assert_eq!(wrapped, b"new");
    assert_eq!(dns, "v=DKIM1; p=NEW");
    assert_eq!(
        fixture.storage.list_dkim_keys().expect("list").len(),
        1,
        "one row per domain, never two identities"
    );
}

#[test]
fn dkim_keys_are_isolated_per_domain_and_listed_oldest_first() {
    let fixture = fixture();
    for (domain, dns) in [("a.example", "v=DKIM1; p=A"), ("b.example", "v=DKIM1; p=B")] {
        fixture
            .storage
            .put_dkim_key(domain, "pigeon", domain.as_bytes(), dns)
            .expect("put");
    }

    assert_eq!(
        fixture
            .storage
            .get_dkim_key("a.example")
            .expect("get")
            .expect("row")
            .2,
        "v=DKIM1; p=A"
    );
    assert_eq!(
        fixture
            .storage
            .get_dkim_key("b.example")
            .expect("get")
            .expect("row")
            .2,
        "v=DKIM1; p=B"
    );

    let listed = fixture.storage.list_dkim_keys().expect("list");
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].0, "a.example");
    assert_eq!(listed[1].0, "b.example");
    // The listing carries no key material.
    assert_eq!(listed[0].1, "pigeon");
    assert_eq!(listed[0].2, "v=DKIM1; p=A");
}

/// The migration really created the table (a fresh file gets it, and reopening
/// does not re-run it).
#[test]
fn the_dkim_keys_table_and_its_unique_domain_exist() {
    let fixture = fixture();
    assert_eq!(count(&fixture.storage, "SELECT COUNT(*) FROM dkim_keys"), 0);
    assert!(
        MIGRATIONS
            .iter()
            .any(|m| m.contains("CREATE TABLE IF NOT EXISTS dkim_keys")),
        "migration 0006 must create the table"
    );
    let unique = count(
        &fixture.storage,
        "SELECT COUNT(*) FROM pragma_index_list('dkim_keys') WHERE \"unique\" = 1",
    );
    assert!(unique >= 1, "domain must be unique");
}

// ---------------------------------------------------------------------------
// Multi-tenant: organizations, roles, invitations and catch-all rules
// ---------------------------------------------------------------------------

#[test]
fn the_multi_tenant_migration_adds_orgs_invitations_and_catchall_rules() {
    let fixture = fixture();
    for table in ["orgs", "invitations", "catchall_rules"] {
        assert_eq!(
            count(&fixture.storage, &format!("SELECT COUNT(*) FROM {table}")),
            0,
            "{table} must exist and be empty on a fresh database"
        );
    }
    // The three columns `0009` adds to `accounts`, with the defaults that keep an
    // existing single account working: personal workspace (`org_id IS NULL`) and
    // role `owner`.
    let account_id = new_account(&fixture.storage);
    let row: (Option<i64>, String, String) = fixture
        .storage
        .raw_conn()
        .query_row(
            "SELECT org_id, role, display_name FROM accounts WHERE id = ?1",
            [account_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("account columns");
    assert_eq!(row, (None, "owner".to_string(), String::new()));
    assert!(MIGRATIONS
        .iter()
        .any(|m| m.contains("CREATE TABLE IF NOT EXISTS orgs")));
    assert!(MIGRATIONS
        .iter()
        .any(|m| m.contains("CREATE TABLE IF NOT EXISTS invitations")));
    assert!(MIGRATIONS
        .iter()
        .any(|m| m.contains("CREATE TABLE IF NOT EXISTS catchall_rules")));
}

#[test]
fn orgs_are_created_listed_renamed_and_deleted_only_when_empty() {
    let fixture = fixture();
    let account_id = new_account(&fixture.storage);

    let org_id = fixture
        .storage
        .create_org("Acme")
        .expect("create organization");
    assert_eq!(fixture.storage.get_org(org_id).expect("load").name, "Acme");
    assert_eq!(fixture.storage.list_orgs().expect("list").len(), 1);
    assert!(
        !fixture
            .storage
            .get_org(org_id)
            .expect("load")
            .created_at
            .is_empty(),
        "the database stamps the creation time"
    );

    fixture
        .storage
        .rename_org(org_id, "  Acme Corp  ")
        .expect("rename");
    assert_eq!(
        fixture.storage.get_org(org_id).expect("load").name,
        "Acme Corp",
        "names are trimmed"
    );

    // An empty name is refused, never repaired.
    assert!(matches!(
        fixture.storage.rename_org(org_id, "   "),
        Err(StoreError::InvalidArgument(_))
    ));
    assert!(matches!(
        fixture.storage.create_org(""),
        Err(StoreError::InvalidArgument(_))
    ));
    assert!(matches!(
        fixture.storage.get_org(org_id + 1),
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        fixture.storage.rename_org(org_id + 1, "Ghost"),
        Err(StoreError::NotFound)
    ));

    // Membership is what keeps the organization alive.
    fixture
        .storage
        .create_member_account(&addr("dana@example.com"), "Dana", org_id, OrgRole::Member)
        .expect("member");
    assert!(matches!(
        fixture.storage.delete_org(org_id),
        Err(StoreError::Conflict)
    ));

    // Move the only member out (a personal workspace) and the delete succeeds.
    fixture
        .storage
        .raw_conn()
        .execute(
            "UPDATE accounts SET org_id = NULL WHERE org_id = ?1",
            [org_id],
        )
        .expect("detach members");
    fixture
        .storage
        .delete_org(org_id)
        .expect("delete empty org");
    assert!(fixture.storage.list_orgs().expect("list").is_empty());
    assert!(matches!(
        fixture.storage.delete_org(org_id),
        Err(StoreError::NotFound)
    ));
    // The account itself survived: deleting a team never deletes mailboxes.
    let (_, email) = fixture.storage.get_account(account_id).expect("account");
    assert_eq!(email.to_string(), "owner@example.com");
}

#[test]
fn org_listings_are_scoped_to_the_caller_and_ordered() {
    let fixture = fixture();
    let owner = new_account(&fixture.storage);
    let other = fixture
        .storage
        .create_account(&addr("other@example.com"))
        .expect("account");

    let first = fixture.storage.create_org("First").expect("org");
    let second = fixture.storage.create_org("Second").expect("org");
    fixture
        .storage
        .raw_conn()
        .execute(
            "UPDATE accounts SET org_id = ?2 WHERE id = ?1",
            params![owner, second],
        )
        .expect("join second");

    assert_eq!(
        fixture
            .storage
            .list_orgs_for_account(owner)
            .expect("listing")
            .iter()
            .map(|org| org.id)
            .collect::<Vec<_>>(),
        vec![second]
    );
    assert!(
        fixture
            .storage
            .list_orgs_for_account(other)
            .expect("listing")
            .is_empty(),
        "an account with no organization belongs to none"
    );
    assert_eq!(
        fixture.storage.list_orgs().expect("all").len(),
        2,
        "the operator listing sees every organization, including the empty one"
    );
    assert_eq!(
        fixture
            .storage
            .get_account_membership(owner)
            .expect("membership"),
        (Some(second), OrgRole::Owner),
        "the migration's default role is owner"
    );
    assert_eq!(
        fixture
            .storage
            .get_account_membership(other)
            .expect("membership"),
        (None, OrgRole::Owner),
        "a personal workspace is owned by its only account"
    );
    assert!(matches!(
        fixture.storage.get_account_membership(owner + other + 100),
        Err(StoreError::NotFound)
    ));
    assert!(fixture.storage.get_org(first).is_ok());
}

#[test]
fn member_accounts_join_their_org_in_the_same_insert() {
    let fixture = fixture();
    let org_id = fixture.storage.create_org("Acme").expect("org");
    let member = fixture
        .storage
        .create_member_account(
            &addr("Dana@Example.com"),
            "  Dana  ",
            org_id,
            OrgRole::Admin,
        )
        .expect("member");

    let members = fixture.storage.list_org_accounts(org_id).expect("members");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].account_id, member);
    assert_eq!(members[0].org_id, Some(org_id));
    assert_eq!(members[0].role, OrgRole::Admin);
    assert_eq!(members[0].display_name, "Dana", "display names are trimmed");
    assert_eq!(
        members[0].email, "Dana@example.com",
        "the stored address keeps the local part's case and lowercases the domain"
    );

    // The address stays globally unique: one mailbox, one account.
    assert!(matches!(
        fixture.storage.create_member_account(
            &addr("dana@example.com"),
            "Duplicate",
            org_id,
            OrgRole::Member
        ),
        Err(StoreError::Conflict)
    ));
    assert!(matches!(
        fixture.storage.create_member_account(
            &addr("new@example.com"),
            "New",
            org_id + 100,
            OrgRole::Member
        ),
        Err(StoreError::NotFound)
    ));
}

#[test]
fn roles_change_but_the_last_owner_of_an_org_stays_owner() {
    let fixture = fixture();
    let org_id = fixture.storage.create_org("Acme").expect("org");
    let first = fixture
        .storage
        .create_member_account(&addr("one@example.com"), "One", org_id, OrgRole::Owner)
        .expect("owner");
    let second = fixture
        .storage
        .create_member_account(&addr("two@example.com"), "Two", org_id, OrgRole::Member)
        .expect("member");

    assert!(matches!(
        fixture.storage.set_account_role(first, OrgRole::Admin),
        Err(StoreError::Conflict)
    ));
    assert_eq!(
        fixture
            .storage
            .get_account_membership(first)
            .expect("role")
            .1,
        OrgRole::Owner,
        "the refused demotion changed nothing"
    );

    // Promoting a second owner makes the demotion legal.
    fixture
        .storage
        .set_account_role(second, OrgRole::Owner)
        .expect("promote");
    fixture
        .storage
        .set_account_role(first, OrgRole::Admin)
        .expect("demote the first owner now that another owner exists");
    assert_eq!(
        fixture
            .storage
            .get_account_membership(first)
            .expect("role")
            .1,
        OrgRole::Admin
    );

    // Setting the role an account already holds is a no-op success.
    fixture
        .storage
        .set_account_role(first, OrgRole::Admin)
        .expect("idempotent");

    // A personal workspace is not an organization, so there is no team to leave
    // without an owner: the guard only protects real organizations, which is what
    // makes "create a team and become its owner" a legal move.
    let solo = new_account(&fixture.storage);
    fixture
        .storage
        .set_account_role(solo, OrgRole::Member)
        .expect("a personal workspace has no owner to strand");
    assert!(matches!(
        fixture
            .storage
            .set_account_role(solo + second + 100, OrgRole::Member),
        Err(StoreError::NotFound)
    ));

    fixture
        .storage
        .set_account_display_name(first, "  First Owner  ")
        .expect("display name");
    assert_eq!(
        fixture.storage.list_org_accounts(org_id).expect("members")[0].display_name,
        "First Owner"
    );
    assert!(matches!(
        fixture
            .storage
            .set_account_display_name(solo + second + 100, "Ghost"),
        Err(StoreError::NotFound)
    ));
}

#[test]
fn invitations_are_created_with_a_one_time_token_and_burn_on_accept() {
    let fixture = fixture();
    let org_id = fixture.storage.create_org("Acme").expect("org");
    let inviter = fixture
        .storage
        .create_member_account(&addr("owner@acme.com"), "Owner", org_id, OrgRole::Owner)
        .expect("owner");
    let invited = addr("dana@acme.com");

    let token = fixture
        .storage
        .create_invitation(org_id, &invited, OrgRole::Member, inviter)
        .expect("invitation");
    assert_eq!(token.len(), 43, "32 random bytes as unpadded base64url");
    assert!(
        token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "base64url alphabet only: {token}"
    );

    // The hash, not the token, is what landed in the row.
    let stored: String = fixture
        .storage
        .raw_conn()
        .query_row("SELECT token_hash FROM invitations", [], |row| row.get(0))
        .expect("hash");
    assert_ne!(stored, token);
    assert!(stored.starts_with("$argon2"), "{stored}");

    let found = fixture
        .storage
        .get_invitation_by_token(&token)
        .expect("lookup")
        .expect("the pending invitation is found");
    assert_eq!(found.email, "dana@acme.com");
    assert_eq!(found.role, OrgRole::Member);
    assert_eq!(found.org_id, org_id);
    assert!(found.is_pending());
    assert!(
        fixture
            .storage
            .get_invitation_by_token("not-a-token")
            .expect("lookup")
            .is_none(),
        "an unknown token finds nothing"
    );
    assert!(fixture
        .storage
        .get_invitation_by_token("   ")
        .expect("lookup")
        .is_none());

    // Accepting burns the invitation and attaches the account.
    let account = fixture
        .storage
        .create_account(&invited)
        .expect("account exists before accepting");
    fixture
        .storage
        .accept_invitation(found.id, account)
        .expect("accept");
    assert_eq!(
        fixture
            .storage
            .get_account_membership(account)
            .expect("membership"),
        (Some(org_id), OrgRole::Member)
    );
    assert!(fixture
        .storage
        .get_invitation_by_token(&token)
        .expect("lookup")
        .is_none());
    assert!(matches!(
        fixture.storage.accept_invitation(found.id, account),
        Err(StoreError::Conflict)
    ));
    let listed = fixture.storage.list_invitations(org_id).expect("list");
    assert_eq!(listed.len(), 1);
    assert!(!listed[0].is_pending(), "the burned row keeps its history");
}

#[test]
fn expired_invitations_are_never_redeemable() {
    let fixture = fixture();
    let org_id = fixture.storage.create_org("Acme").expect("org");
    let inviter = fixture
        .storage
        .create_member_account(&addr("owner@acme.com"), "Owner", org_id, OrgRole::Owner)
        .expect("owner");
    let token = fixture
        .storage
        .create_invitation(org_id, &addr("late@acme.com"), OrgRole::Member, inviter)
        .expect("invitation");
    let invitation_id = fixture.storage.list_invitations(org_id).expect("list")[0].id;

    // Push the expiry into the past, exactly as a week of waiting would.
    fixture
        .storage
        .raw_conn()
        .execute(
            "UPDATE invitations SET expires_at = datetime('now', '-1 second') WHERE id = ?1",
            [invitation_id],
        )
        .expect("expire");

    assert!(fixture
        .storage
        .get_invitation_by_token(&token)
        .expect("lookup")
        .is_none());
    let account = fixture
        .storage
        .create_account(&addr("late@acme.com"))
        .expect("account");
    assert!(matches!(
        fixture.storage.accept_invitation(invitation_id, account),
        Err(StoreError::Conflict)
    ));
    assert_eq!(
        fixture
            .storage
            .get_account_membership(account)
            .expect("membership"),
        (None, OrgRole::Owner),
        "the account stayed in its personal workspace"
    );
}

#[test]
fn re_inventing_an_address_replaces_the_pending_token() {
    let fixture = fixture();
    let org_id = fixture.storage.create_org("Acme").expect("org");
    let inviter = fixture
        .storage
        .create_member_account(&addr("owner@acme.com"), "Owner", org_id, OrgRole::Owner)
        .expect("owner");

    let first = fixture
        .storage
        .create_invitation(org_id, &addr("dana@acme.com"), OrgRole::Member, inviter)
        .expect("first invitation");
    let second = fixture
        .storage
        .create_invitation(org_id, &addr("Dana@Acme.com"), OrgRole::Admin, inviter)
        .expect("second invitation");

    assert_ne!(first, second);
    assert_eq!(
        fixture
            .storage
            .list_invitations(org_id)
            .expect("list")
            .len(),
        1,
        "one pending invitation per address and organization"
    );
    assert!(fixture
        .storage
        .get_invitation_by_token(&first)
        .expect("lookup")
        .is_none());
    let current = fixture
        .storage
        .get_invitation_by_token(&second)
        .expect("lookup")
        .expect("the replacement is live");
    assert_eq!(current.role, OrgRole::Admin);

    // Deleting is scoped to the organization.
    assert!(!fixture
        .storage
        .delete_invitation(org_id + 1, current.id)
        .expect("scoped delete"));
    assert!(fixture
        .storage
        .delete_invitation(org_id, current.id)
        .expect("delete"));
    assert!(fixture
        .storage
        .list_invitations(org_id)
        .expect("list")
        .is_empty());
}

#[test]
fn invitations_never_grant_ownership_and_never_move_a_foreign_account() {
    let fixture = fixture();
    let org_id = fixture.storage.create_org("Acme").expect("org");
    let inviter = fixture
        .storage
        .create_member_account(&addr("owner@acme.com"), "Owner", org_id, OrgRole::Owner)
        .expect("owner");

    assert!(matches!(
        fixture
            .storage
            .create_invitation(org_id, &addr("boss@acme.com"), OrgRole::Owner, inviter),
        Err(StoreError::InvalidArgument(_))
    ));
    assert!(matches!(
        fixture.storage.create_invitation(
            org_id + 100,
            &addr("nobody@acme.com"),
            OrgRole::Member,
            inviter
        ),
        Err(StoreError::NotFound)
    ));

    // An account that already serves another team is not silently moved.
    let other_org = fixture.storage.create_org("Other").expect("org");
    let elsewhere = fixture
        .storage
        .create_member_account(&addr("dana@other.com"), "Dana", other_org, OrgRole::Member)
        .expect("member");
    let token = fixture
        .storage
        .create_invitation(org_id, &addr("dana@other.com"), OrgRole::Admin, inviter)
        .expect("invitation");
    let invitation = fixture
        .storage
        .get_invitation_by_token(&token)
        .expect("lookup")
        .expect("pending");
    assert!(matches!(
        fixture.storage.accept_invitation(invitation.id, elsewhere),
        Err(StoreError::Conflict)
    ));
}

#[test]
fn catchall_rules_upsert_by_domain() {
    let fixture = fixture();
    new_account(&fixture.storage);

    assert!(fixture
        .storage
        .get_catchall("Example.com")
        .expect("lookup")
        .is_none());
    fixture
        .storage
        .set_catchall("Example.COM", CatchallAction::Route)
        .expect("route rule");
    let rule = fixture
        .storage
        .get_catchall("example.com")
        .expect("lookup")
        .expect("the rule is found by lowercase domain");
    assert_eq!(rule.action, CatchallAction::Route);

    // Upsert: the domain is the identity.
    fixture
        .storage
        .set_catchall("example.com", CatchallAction::Discard)
        .expect("replace with discard");
    assert_eq!(fixture.storage.list_catchalls().expect("list").len(), 1);
    let rule = fixture
        .storage
        .get_catchall("example.com")
        .expect("lookup")
        .expect("still one rule");
    assert_eq!(rule.action, CatchallAction::Discard);

    assert!(matches!(
        fixture
            .storage
            .set_catchall("not a domain", CatchallAction::Discard),
        Err(StoreError::InvalidArgument(_))
    ));

    fixture
        .storage
        .delete_catchall("EXAMPLE.com")
        .expect("delete");
    assert!(matches!(
        fixture.storage.delete_catchall("example.com"),
        Err(StoreError::NotFound)
    ));
}

#[test]
fn catchall_assignments_are_multi_assignee_and_pausable() {
    let fixture = fixture();
    let first = new_account(&fixture.storage);
    let second = fixture
        .storage
        .create_account(&addr("second@example.com"))
        .expect("second account");
    fixture
        .storage
        .set_catchall("example.com", CatchallAction::Route)
        .expect("rule");

    fixture
        .storage
        .assign_catchall("Example.COM", first, first)
        .expect("first assignee");
    fixture
        .storage
        .assign_catchall("example.com", second, first)
        .expect("second assignee");
    // Assigning the same person twice is a conflict, not a second copy.
    assert!(matches!(
        fixture
            .storage
            .assign_catchall("example.com", second, first),
        Err(StoreError::Conflict)
    ));
    // An unknown account cannot hold a catch-all.
    assert!(matches!(
        fixture
            .storage
            .assign_catchall("example.com", second + 100, first),
        Err(StoreError::NotFound)
    ));

    let assignees = fixture
        .storage
        .catchall_assignees("example.com")
        .expect("assignees");
    assert_eq!(assignees.len(), 2, "both accounts hold the catch-all");
    assert!(assignees.iter().all(|row| !row.paused));
    assert_eq!(
        fixture
            .storage
            .catchall_assignments_for_account(second)
            .expect("own assignments")
            .len(),
        1
    );

    // One member pausing their copy leaves the other one receiving.
    fixture
        .storage
        .set_catchall_paused("example.com", second, true)
        .expect("pause");
    let assignees = fixture
        .storage
        .catchall_assignees("example.com")
        .expect("assignees");
    assert_eq!(
        assignees
            .iter()
            .filter(|row| !row.paused)
            .map(|row| row.account_id)
            .collect::<Vec<_>>(),
        vec![first],
        "a paused member must not appear among the live recipients"
    );
    assert!(
        fixture
            .storage
            .get_catchall_assignment("example.com", second)
            .expect("lookup")
            .expect("assigned")
            .paused,
        "the paused flag is what the inbound resolver reads"
    );

    // An admin force-resume is the same column, and pausing somebody who is not
    // assigned is a 404 rather than an invented row.
    fixture
        .storage
        .set_catchall_paused("example.com", second, false)
        .expect("resume");
    assert!(matches!(
        fixture
            .storage
            .set_catchall_paused("example.com", 9_999, true),
        Err(StoreError::NotFound)
    ));

    // Removing one assignment stops their delivery only.
    fixture
        .storage
        .unassign_catchall("example.com", first)
        .expect("unassign");
    assert_eq!(
        fixture
            .storage
            .catchall_assignees("example.com")
            .expect("assignees")
            .len(),
        1
    );
    assert!(matches!(
        fixture.storage.unassign_catchall("example.com", first),
        Err(StoreError::NotFound)
    ));

    // Deleting the rule takes its assignments with it: a grant that can never
    // fire would be a lie in the admin listing.
    fixture
        .storage
        .delete_catchall("example.com")
        .expect("delete rule");
    assert!(fixture
        .storage
        .list_catchall_assignments()
        .expect("list")
        .is_empty());
}

#[test]
fn sender_aliases_can_have_several_holders_and_never_shadow_a_mailbox() {
    let fixture = fixture();
    let sales = fixture
        .storage
        .create_account(&addr("sales@example.com"))
        .expect("sales account");
    let second = fixture
        .storage
        .create_account(&addr("second@example.com"))
        .expect("second account");

    let alias = fixture
        .storage
        .create_alias(&addr("sales@example.com"), sales)
        .expect("alias");
    let stored = fixture
        .storage
        .get_alias(alias)
        .expect("lookup")
        .expect("alias exists");
    assert_eq!(stored.address, "sales@example.com");
    assert_eq!(stored.domain, "example.com");
    assert_eq!(stored.created_by, sales);
    assert_eq!(fixture.storage.list_aliases().expect("list").len(), 1);
    assert_eq!(
        fixture
            .storage
            .get_alias_by_address("Sales@Example.COM")
            .expect("lookup")
            .expect("found by lowercase address")
            .id,
        alias
    );

    // Collisions: an existing alias, and an address that belongs to an account.
    assert!(matches!(
        fixture
            .storage
            .create_alias(&addr("sales@example.com"), sales),
        Err(StoreError::Conflict)
    ));
    assert!(matches!(
        fixture
            .storage
            .create_alias(&addr("sales@example.com"), sales),
        Err(StoreError::InvalidArgument(_))
    ));
    // An alias on a domain this deployment does not serve could never work.
    assert!(matches!(
        fixture
            .storage
            .create_alias(&addr("sales@elsewhere.example"), sales),
        Err(StoreError::InvalidArgument(_))
    ));
    assert!(fixture
        .storage
        .is_address_taken("sales@example.com")
        .expect("taken"));
    assert!(fixture
        .storage
        .is_address_taken("sales@example.com")
        .expect("taken"));
    assert!(!fixture
        .storage
        .is_address_taken("nobody@example.com")
        .expect("free"));

    // Several holders, each receiving a copy; assigning twice is a conflict.
    fixture
        .storage
        .assign_alias(alias, sales, sales)
        .expect("assign sales");
    fixture
        .storage
        .assign_alias(alias, second, sales)
        .expect("assign second");
    assert!(matches!(
        fixture.storage.assign_alias(alias, second, sales),
        Err(StoreError::Conflict)
    ));
    assert_eq!(
        fixture
            .storage
            .accounts_for_alias("sales@example.com")
            .expect("holders"),
        vec![sales, second]
    );
    assert_eq!(
        fixture
            .storage
            .aliases_for_account(second)
            .expect("own aliases")
            .iter()
            .map(|row| row.id)
            .collect::<Vec<_>>(),
        vec![alias]
    );
    assert_eq!(
        fixture
            .storage
            .alias_assignments(alias)
            .expect("assignments")
            .len(),
        2
    );

    // A user may hold several aliases.
    let marketing = fixture
        .storage
        .create_alias(&addr("marketing@example.com"), sales)
        .expect("second alias");
    fixture
        .storage
        .assign_alias(marketing, sales, sales)
        .expect("assign marketing");
    assert_eq!(
        fixture
            .storage
            .aliases_for_account(sales)
            .expect("own aliases")
            .len(),
        2
    );

    // Revoking one assignment stops future delivery only.
    fixture
        .storage
        .unassign_alias(alias, second)
        .expect("unassign");
    assert_eq!(
        fixture
            .storage
            .accounts_for_alias("sales@example.com")
            .expect("holders"),
        vec![sales]
    );
    assert!(matches!(
        fixture.storage.unassign_alias(alias, second),
        Err(StoreError::NotFound)
    ));

    fixture.storage.delete_alias(alias).expect("delete");
    assert!(fixture
        .storage
        .alias_assignments(alias)
        .expect("assignments")
        .is_empty());
    assert!(matches!(
        fixture.storage.delete_alias(alias),
        Err(StoreError::NotFound)
    ));
}

#[test]
fn an_account_can_never_take_a_sender_alias_address() {
    let fixture = fixture();
    let owner = new_account(&fixture.storage);
    fixture
        .storage
        .create_alias(&addr("sales@example.com"), owner)
        .expect("alias");
    let accounts_before = count(&fixture.storage, "SELECT COUNT(*) FROM accounts");

    // Both creation paths refuse it: a mailbox on a shared address would divert
    // that alias's mail into one inbox and stop delivering to every holder.
    assert!(matches!(
        fixture
            .storage
            .create_account(&addr("Sales@Example.com")),
        Err(StoreError::AliasShadow(address)) if address == "sales@example.com"
    ));
    let org_id = fixture.storage.create_org("Acme").expect("org");
    assert!(matches!(
        fixture.storage.create_member_account(
            &addr("sales@example.com"),
            "Sales",
            org_id,
            OrgRole::Member
        ),
        Err(StoreError::AliasShadow(_))
    ));
    assert_eq!(
        count(&fixture.storage, "SELECT COUNT(*) FROM accounts"),
        accounts_before,
        "a refused creation must not leave a half-made account"
    );
    assert!(
        fixture
            .storage
            .get_account_by_email("sales@example.com")
            .expect("lookup")
            .is_none(),
        "the alias address still belongs to no mailbox"
    );
    // The alias is untouched: its holder list is exactly what it was.
    assert!(fixture
        .storage
        .accounts_for_alias("sales@example.com")
        .expect("holders")
        .is_empty());
    assert!(fixture
        .storage
        .is_address_taken("sales@example.com")
        .expect("taken"));

    // The reverse direction still holds too: an existing mailbox cannot become an
    // alias (the pair of guards is what makes the collision impossible).
    assert!(matches!(
        fixture
            .storage
            .create_alias(&addr("owner@example.com"), owner),
        Err(StoreError::InvalidArgument(_))
    ));
}

#[test]
fn a_catchall_assignment_requires_an_existing_rule_and_persists_nothing_otherwise() {
    let fixture = fixture();
    let account = new_account(&fixture.storage);

    // No rule for the domain yet: the assignee could never receive anything, so
    // the call fails and — crucially — writes nothing.
    assert!(matches!(
        fixture
            .storage
            .assign_catchall("example.com", account, account),
        Err(StoreError::NotFound)
    ));
    assert_eq!(
        count(
            &fixture.storage,
            "SELECT COUNT(*) FROM catchall_assignments"
        ),
        0,
        "a refused assignment must not leave a row behind"
    );
    assert!(fixture
        .storage
        .catchall_assignees("example.com")
        .expect("assignees")
        .is_empty());
    assert!(fixture
        .storage
        .list_catchall_assignments()
        .expect("list")
        .is_empty());

    // With the rule in place the same call succeeds, which proves the check is
    // the rule and not some other rejection.
    fixture
        .storage
        .set_catchall("example.com", CatchallAction::Route)
        .expect("rule");
    fixture
        .storage
        .assign_catchall("example.com", account, account)
        .expect("assign");
    assert_eq!(
        count(
            &fixture.storage,
            "SELECT COUNT(*) FROM catchall_assignments"
        ),
        1
    );
}

#[test]
fn migration_0014_backfills_a_legacy_single_target_catchall() {
    // A database created by an earlier build: migrations `0001`-`0013` applied,
    // with a `catchall_rules` row that still carries `target_account_id`. The
    // upgrade has to move that target into `catchall_assignments`, or an
    // upgraded deployment would silently stop receiving its catch-all mail.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("legacy.db");
    let conn = rusqlite::Connection::open(&path).expect("open legacy db");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _migrations (
            id   INTEGER PRIMARY KEY,
            name TEXT UNIQUE NOT NULL
        )",
    )
    .expect("_migrations");
    // `MIGRATIONS[13]` is `0014`; everything before it is the pre-upgrade shape.
    for (index, sql) in MIGRATIONS.iter().enumerate().take(13) {
        conn.execute_batch(sql).expect("apply pre-0014 migration");
        conn.execute(
            "INSERT INTO _migrations (id, name) VALUES (?1, ?2)",
            params![(index + 1) as i64, format!("m{:04}", index + 1)],
        )
        .expect("record pre-0014 migration");
    }
    // Two mailboxes of the domain and the legacy single-target rule.
    conn.execute_batch(
        "INSERT INTO accounts (email, email_norm) VALUES ('ops@example.com', 'ops@example.com');
         INSERT INTO accounts (email, email_norm) VALUES ('lead@example.com', 'lead@example.com');",
    )
    .expect("legacy accounts");
    let ops_id: i64 = conn
        .query_row(
            "SELECT id FROM accounts WHERE email = 'ops@example.com'",
            [],
            |row| row.get(0),
        )
        .expect("ops id");
    conn.execute(
        "INSERT INTO catchall_rules (domain, action, target_account_id)
         VALUES ('example.com', 'route', ?1)",
        [ops_id],
    )
    .expect("legacy rule");

    // The upgrade itself: exactly the `0014` statement batch, recorded the way the
    // runner records it.
    conn.execute_batch(MIGRATIONS[13]).expect("apply 0014");
    conn.execute(
        "INSERT INTO _migrations (id, name) VALUES (14, 'm0014')",
        [],
    )
    .expect("record 0014");

    let backfilled: Vec<(String, i64, i64)> = {
        let mut statement = conn
            .prepare(
                "SELECT domain, account_id, paused FROM catchall_assignments ORDER BY account_id",
            )
            .expect("prepare");
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("query")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("rows")
    };
    assert_eq!(
        backfilled,
        vec![("example.com".to_string(), ops_id, 0)],
        "the legacy target becomes one unpaused assignment"
    );
    assert_eq!(
        count_raw(&conn, "SELECT COUNT(*) FROM catchall_assignments"),
        1,
        "a single-target rule backfills exactly one row"
    );

    // And the store opens the upgraded file without replaying anything, with the
    // backfilled assignment visible through the normal API.
    let storage = SqliteStorage::open(&path).expect("open upgraded db");
    let assignees = storage
        .catchall_assignees("example.com")
        .expect("assignees");
    assert_eq!(assignees.len(), 1);
    assert_eq!(assignees[0].account_id, ops_id);
    assert!(!assignees[0].paused);
    assert_eq!(storage.list_catchalls().expect("rules").len(), 1);
}

#[test]
fn the_alias_and_catchall_migrations_are_additive() {
    let fixture = fixture();
    for table in [
        "sender_aliases",
        "sender_alias_assignments",
        "catchall_assignments",
    ] {
        assert_eq!(
            count(&fixture.storage, &format!("SELECT COUNT(*) FROM {table}")),
            0,
            "{table} must exist and be empty on a fresh database"
        );
    }
    // An ordinary message carries no delivery marker: the column is NULL, and
    // that is what keeps the webmail grouping honest.
    let account_id = new_account(&fixture.storage);
    let message_id = fixture.storage.reserve_message_id().expect("reserve");
    fixture
        .storage
        .insert_message(new_message(account_id, message_id, None), message_id)
        .expect("insert");
    assert_eq!(
        fixture
            .storage
            .get_message(message_id)
            .expect("row")
            .delivered_for,
        None
    );
    // The marker is normalized on write, so the grouping key cannot fork on case.
    let marked_id = fixture.storage.reserve_message_id().expect("reserve");
    let mut marked = new_message(account_id, marked_id, None);
    marked.delivered_for = Some("Sales@Example.COM".to_string());
    fixture
        .storage
        .insert_message(marked, marked_id)
        .expect("insert marked");
    assert_eq!(
        fixture
            .storage
            .get_message(marked_id)
            .expect("row")
            .delivered_for
            .as_deref(),
        Some("sales@example.com")
    );
    assert!(MIGRATIONS
        .iter()
        .any(|m| m.contains("CREATE TABLE IF NOT EXISTS sender_aliases")));
    assert!(MIGRATIONS
        .iter()
        .any(|m| m.contains("CREATE TABLE IF NOT EXISTS catchall_assignments")));
}

#[test]
fn deactivating_a_member_revokes_sessions_and_api_keys_but_keeps_the_row() {
    let fixture = fixture();
    let org_id = fixture.storage.create_org("Acme").expect("org");
    let member = fixture
        .storage
        .create_member_account(&addr("dana@acme.com"), "Dana", org_id, OrgRole::Member)
        .expect("member");

    fixture
        .storage
        .create_session("sess_0000000000000001", member, "phc$hash", 3600)
        .expect("session");
    fixture
        .storage
        .put_api_key(
            member,
            "agent",
            "pk_prefix",
            "phc$hash",
            &[ApiKeyScope::Full],
        )
        .expect("api key");

    fixture
        .storage
        .deactivate_account(member)
        .expect("deactivate");

    assert!(
        fixture
            .storage
            .get_session_by_id("sess_0000000000000001")
            .expect("lookup")
            .is_none(),
        "every session is revoked"
    );
    assert!(
        fixture
            .storage
            .find_api_key_by_prefix("pk_prefix")
            .expect("lookup")
            .is_empty(),
        "every API key is revoked"
    );
    // The row survives so the mailbox, its addresses and its history do too.
    let (id, email) = fixture.storage.get_account(member).expect("account");
    assert_eq!(id, member);
    assert_eq!(email.to_string(), "dana@acme.com");
    assert_eq!(
        fixture
            .storage
            .list_org_accounts(org_id)
            .expect("members")
            .len(),
        1
    );

    // Re-running it changes nothing and unknown ids are reported.
    fixture
        .storage
        .deactivate_account(member)
        .expect("idempotent");
    assert!(matches!(
        fixture.storage.deactivate_account(member + 100),
        Err(StoreError::NotFound)
    ));
}
