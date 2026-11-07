//! Embedded schema migrations.
//!
//! The database is created and upgraded by the binary itself: each entry in
//! [`MIGRATIONS`] runs inside its own `IMMEDIATE` transaction and is recorded in
//! `_migrations`, so re-opening an existing file is a no-op. SQLite DDL is
//! transactional, which means a crash mid-migration leaves neither half a
//! schema nor a bogus migration row.
//!
//! Two properties make this safe when several processes open a fresh file at
//! the same time:
//!
//! * the transaction is `IMMEDIATE`, so the write lock is taken before anything
//!   is read — otherwise two openers could both see an empty `_migrations` and
//!   both try to create the same tables;
//! * `_migrations` is re-read *inside* that transaction, so the second opener
//!   observes the first one's committed row and skips the migration instead of
//!   replaying it.
//!
//! Every statement is idempotent (`IF NOT EXISTS`) as a second belt: a partially
//! migrated file from an older build converges instead of failing.

use rusqlite::{params, Connection, TransactionBehavior};

use crate::error::Result;

/// Ordered, append-only migration list. Never edit an entry once released;
/// add a new one instead.
///
/// Migration `0001` creates the schema from ADR 0002. `messages.id` is
/// `AUTOINCREMENT` on purpose: `reserve_message_id` bumps `sqlite_sequence` so a
/// body can be sealed (AAD `account:{account}:message:{id}`) *before* the row
/// exists, and AUTOINCREMENT guarantees the id handed out that way is never
/// reissued — the following INSERT either writes it or leaves a gap.
///
/// `0002` adds the indexes the hot paths need: queue claiming, message and
/// event listing, API-key prefix lookup.
///
/// `0003` adds the queue columns the claim/dead-letter path needs, per-account
/// idempotency keys, and the foreign-key indexes.
///
/// `0004` adds the mail-client basics the owner asked for: a folder per message
/// (`inbox`/`sent`/`spam`/`trash`) and a `read_at` timestamp that makes
/// read/unread a piece of state instead of a client-side guess.
///
/// `0005` adds the dashboard-auth tables (sessions, TOTP state) shipped with the
/// dashboard session PR.
///
/// `0006` adds `dkim_keys`: the per-domain RSA signing identity the outbound
/// worker signs with. Keys are **domain-scoped, not account-scoped** — a domain
/// has one DKIM identity that any account serving this domain signs with, which
/// is why the unique key is `domain` alone and not `(account_id, domain)`.
/// Two accounts sending as `example.com` must present the same public key, or
/// receivers would see the selector's rotation history flap.
///
/// `0005` adds the dashboard session realm: `sessions` (opaque token hash, not
/// the token) and `totp_enrollments` (wrapped TOTP secret, confirmation state,
/// the last consumed step for replay rejection, and the unused recovery-code
/// hashes). `totp_secrets` from `0001` stays as-is: it is the pre-session
/// placeholder and no longer written.
///
/// `0007` adds `drafts`: saved-but-not-sent emails. A draft is deliberately its
/// own table rather than a `messages` row with an extra flag — a draft carries
/// rich-text HTML, base64 attachments and recipient lists as **editable** data,
/// while `messages` is the sealed, append-only delivery record. Mixing the two
/// would either put plaintext mail in the sealed table or make every autosave a
/// delivery-pipeline artifact.
///
/// `0008` adds `templates.description` (plain text, default empty) so a template
/// list can explain itself without opening each template. Templates stay
/// unlimited: no count cap exists in the schema or the store, only the per-account
/// unique name.
///
/// `0009` adds the multi-tenant shape: `orgs` (a company/team) plus three
/// columns on `accounts` — `org_id` (NULL = the personal workspace every existing
/// account keeps), `role` (owner/admin/member, default `owner` so an account that
/// predates organizations stays in charge of what it already has) and
/// `display_name`. One account is still one mailbox: an organization groups
/// mailboxes, it does not merge them, and the unique key on `accounts.email`
/// therefore stays global — one address, one account, one agent connection.
///
/// `0010` adds `invitations`: a pending seat in an organization, addressed to an
/// email that may not have an account yet. The plaintext token is shown once and
/// never stored — `token_hash` is an Argon2id PHC hash — and `UNIQUE(org_id,
/// email)` makes "the invitation for this address in this organization" a single
/// row, re-inviting replaces it instead of piling up unaccepted tokens.
/// `accepted_at` is the burn marker: an accepted or expired row can never be
/// redeemed again, which is why login and `POST /v1/invitations/accept` both
/// check it rather than deleting the row (the history of who was invited stays
/// readable).
///
/// `0011` adds `catchall_rules`: what the inbound SMTP server does with mail for
/// an unknown local part of a managed domain. Keyed by `domain` alone for the
/// same reason `dkim_keys` is — the domain is the identity, a second rule for the
/// same domain could only contradict the first. `action = 'discard'` accepts and
/// drops (the anti-enumeration answer: the sender cannot tell a real address from
/// a made-up one); `action = 'route'` needs a `target_account_id`, and deleting
/// that account deletes the rule instead of leaving a rule that points nowhere.
///
/// `0012` adds trash retention: `accounts.trash_retention_days` (the policy,
/// default 30) and `messages.trashed_at` (the countdown clock). A retention of
/// `0` means "keep forever" and is a real setting, not a missing one, so the
/// purge path checks the value before deleting anything. `trashed_at` is written
/// by the folder move ([`crate::Storage::set_message_folder`]) and cleared when
/// the message leaves the trash, which is what makes "how long has this been in
/// the trash" answerable without a second history table. Rows already in the
/// trash when this migration runs keep `NULL` and are therefore never purged
/// until they are moved to the trash again: an upgrade must not delete mail whose
/// countdown never started.
///
/// `0013` adds sender aliases and the delivery marker.
///
/// A **sender alias** is a second address on a domain the deployment already
/// serves (`sales@example.com`): it owns no mailbox, so it can be handed
/// to several people at once. Two tables, not one, because the relationship is
/// many-to-many: `sender_aliases` holds the address, `sender_alias_assignments`
/// holds who may send as it and receive its mail. A single
/// `assigned_account_id` column could not express "everyone in sales gets a
/// copy", which is the whole point of the feature.
///
/// `messages.delivered_for` records *which* address a stored copy was delivered
/// for when that address is not the mailbox's own (an alias, or a catch-all
/// local part). The folder stays a real folder — `inbox` — because SQLite
/// `CHECK` constraints cannot express "any address", so a pseudo-folder invented
/// as a folder value would either be one fixed string or force a table rebuild
/// on every alias. The webmail groups the inbox by this column instead, which is
/// also why `folder` keeps its four-value contract and every existing client
/// keeps working.
///
/// `0014` makes a catch-all **multi-recipient and pausable**.
///
/// `catchall_rules` keeps the domain-level decision (`route` or `discard`);
/// `catchall_assignments` holds who receives a routed copy. `paused` is per
/// (domain, account) on purpose: one member going on holiday must not stop the
/// shared sales inbox, and the member — not an admin — is the one who knows.
/// The legacy `catchall_rules.target_account_id` column is left in place but is
/// no longer read or written (SQLite cannot drop it portably); the backfill below
/// moves any existing target into the assignment table so an upgraded deployment
/// keeps receiving its catch-all mail.
///
/// The schema is **unreleased**, so checks that SQLite cannot add later
/// (`CHECK` constraints, `AUTOINCREMENT` on `accounts.id`) are edited in place in
/// `0001` rather than shipped as a table rebuild.
pub const MIGRATIONS: &[&str] = &[
    // ---------------------------------------------------------------- 0001
    r#"
CREATE TABLE IF NOT EXISTS accounts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT UNIQUE NOT NULL,
    email_norm TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS api_keys (
    id         INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    hash       TEXT NOT NULL,
    scopes     TEXT NOT NULL,
    revoked_at TEXT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    direction   TEXT NOT NULL CHECK (direction IN ('out', 'in')),
    from_addr   TEXT NOT NULL,
    -- JSON array of addresses: an address cannot be split on a separator that
    -- also appears inside it, and corrupt content fails to decode loudly.
    to_addrs    TEXT NOT NULL,
    subject     TEXT NOT NULL DEFAULT '',
    sealed_body BLOB NOT NULL,
    status      TEXT NOT NULL DEFAULT 'stored'
                     CHECK (status IN ('stored', 'corrupt_row')),
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS attachments (
    id             INTEGER PRIMARY KEY,
    message_id     INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    filename       TEXT NOT NULL,
    size           INTEGER NOT NULL CHECK (size >= 0),
    sealed_content BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS queue (
    id          INTEGER PRIMARY KEY,
    message_id  INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    run_after   INTEGER NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    claimed_at  INTEGER NULL,
    claim_token TEXT NULL,
    last_error  TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY,
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind <> ''),
    detail     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS webhooks (
    id         INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    url        TEXT NOT NULL,
    secret     TEXT NOT NULL,
    events     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
    id         INTEGER PRIMARY KEY,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS totp_secrets (
    account_id     INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    wrapped_secret BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS templates (
    id          INTEGER PRIMARY KEY,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    subject_tpl TEXT NOT NULL,
    html_tpl    TEXT NOT NULL,
    text_tpl    TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (account_id, name)
);
"#,
    // ---------------------------------------------------------------- 0002
    r#"
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys (key_prefix) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_messages_account ON messages (account_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_events_message ON events (message_id, id);
-- One index serves both halves of a claim: `claim_token IS NULL` (a due job
-- nobody holds) and the expired-lease takeover, ordered by the columns the
-- claim query orders and compares on.
CREATE INDEX IF NOT EXISTS idx_queue_claim ON queue (claim_token, claimed_at, run_after);
"#,
    // ---------------------------------------------------------------- 0003
    r#"
-- Superseded by idx_queue_claim; drop it so a database created by an earlier
-- build of this unreleased schema loses the dead partial index.
DROP INDEX IF EXISTS idx_queue_claimable;

-- Retry policy and dead-letter state live on the row, not in worker memory: a
-- restarted worker must see how many attempts a job already spent.
ALTER TABLE queue ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 10;
ALTER TABLE queue ADD COLUMN status TEXT NOT NULL DEFAULT 'ready';
ALTER TABLE queue ADD COLUMN claimed_by TEXT;

-- Idempotent submission: a client-supplied key deduplicates retries.
ALTER TABLE messages ADD COLUMN idempotency_key TEXT NULL;

-- Per account, not global: a global index would let one account's key collide
-- with another account's, and the replay path would then hand back a foreign
-- message id. NULL keys never collide (partial index).
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_idempotency
    ON messages (account_id, idempotency_key)
 WHERE idempotency_key IS NOT NULL;

-- Foreign-key indexes. SQLite does not create them for a REFERENCES clause, and
-- without them `ON DELETE CASCADE` scans the child table on every account or
-- message delete.
CREATE INDEX IF NOT EXISTS idx_api_keys_account ON api_keys (account_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_account ON webhooks (account_id);
CREATE INDEX IF NOT EXISTS idx_queue_message ON queue (message_id);
CREATE INDEX IF NOT EXISTS idx_attachments_message ON attachments (message_id);
"#,
    // ---------------------------------------------------------------- 0004
    r#"
-- Folder per message. The default keeps every existing row in the inbox, so
-- this ALTER needs no backfill and is safe on a database created by an earlier
-- build. The CHECK is spelled exactly like `MessageFolder::as_str`.
ALTER TABLE messages ADD COLUMN folder TEXT NOT NULL DEFAULT 'inbox'
    CHECK (folder IN ('inbox', 'sent', 'spam', 'trash'));

-- Read state: NULL means unread, a timestamp means read. Storing *when* rather
-- than a boolean costs nothing and answers "when did they read it" later.
ALTER TABLE messages ADD COLUMN read_at TEXT NULL;

-- The two hot listings are "one folder of one account, newest first" and the
-- sidebar counts, which group by folder for one account. One composite index
-- serves both: equality on (account_id, folder), then id DESC for the page.
CREATE INDEX IF NOT EXISTS idx_messages_folder
    ON messages (account_id, folder, id DESC);
"#,
    // ---------------------------------------------------------------- 0005
    r#"
-- Dashboard/webmail sessions. The cookie carries an opaque token; only its
-- hash is stored, so a database leak does not hand out live sessions. Rows are
-- marked revoked rather than deleted, which keeps "this session existed and was
-- ended" auditable. Timestamps are SQLite `datetime('now')` strings so that the
-- expiry comparison is a plain string comparison in the same format.
CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    revoked_at TEXT NULL
);

-- Lookup is by primary key (the token names its own session id), so the only
-- index worth adding is the one that answers "every live session of this
-- account" for revoke-all.
CREATE INDEX IF NOT EXISTS idx_sessions_account ON sessions (account_id);

-- One TOTP enrollment per account. `confirmed = 0` is an enrollment in
-- progress: the secret exists but login does not require a code yet.
-- `last_used_step` is the anti-replay counter (RFC 6238 step, not time), and
-- `recovery_codes` holds a JSON array of Argon2id PHC hashes, never plaintext.
CREATE TABLE IF NOT EXISTS totp_enrollments (
    account_id       INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    secret_wrapped   BLOB NOT NULL,
    confirmed        INTEGER NOT NULL DEFAULT 0,
    last_used_step   INTEGER NULL,
    recovery_codes   TEXT NULL,
    enrolled_at      TEXT NULL
);
"#,
    // ---------------------------------------------------------------- 0006
    r#"
-- Per-domain DKIM signing identity (RFC 6376).
--
-- Keys are DOMAIN-SCOPED, NOT ACCOUNT-SCOPED: the unique constraint is on
-- `domain` alone, deliberately. A DKIM identity belongs to the sending domain,
-- so any account serving example.com signs with the same selector and key.
-- Scoping this per account would let two accounts publish different public keys
-- for one selector, and receivers would see the domain's key apparently rotate
-- on every message.
--
-- `private_key_wrapped` is the PKCS#8 RSA private key sealed under the master
-- key (domain-separated, AAD `dkim:{domain}`); the store never holds plaintext
-- key material. `public_dns` is the exact TXT record to publish at
-- `<selector>._domainkey.<domain>`, cached so the API can serve DNS guidance
-- without re-deriving it from the key.
CREATE TABLE IF NOT EXISTS dkim_keys (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    domain            TEXT UNIQUE NOT NULL,
    selector          TEXT NOT NULL DEFAULT 'pigeon',
    private_key_wrapped BLOB NOT NULL,
    public_dns        TEXT NOT NULL,
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
"#,
    // ---------------------------------------------------------------- 0007
    r#"
-- Saved-but-not-sent emails. Separate from `messages` on purpose: a draft holds
-- *editable* plaintext (rich-text HTML, base64 attachment JSON, recipient lists)
-- while `messages` is the sealed, append-only delivery record whose body must
-- arrive as a versioned envelope. A draft therefore has no `sealed_body` and no
-- queue row; sending one goes through the normal send path, which seals the MIME
-- and inserts the `messages` row, and only then deletes the draft.
--
-- Every list column is a JSON array, like `messages.to_addrs`: an address cannot
-- be split on a separator that also appears inside it, and corrupt content fails
-- to decode loudly instead of silently changing recipients.
CREATE TABLE IF NOT EXISTS drafts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    public_id   TEXT UNIQUE NOT NULL,
    from_addr   TEXT NOT NULL,
    to_addrs    TEXT NOT NULL DEFAULT '[]',
    cc_addrs    TEXT NOT NULL DEFAULT '[]',
    bcc_addrs   TEXT NOT NULL DEFAULT '[]',
    subject     TEXT,
    body_html   TEXT,
    body_text   TEXT,
    attachments TEXT NOT NULL DEFAULT '[]',
    tags        TEXT NOT NULL DEFAULT '[]',
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_drafts_account ON drafts(account_id);
"#,
    // ---------------------------------------------------------------- 0008
    r#"
-- A short human description of what a template is for. Plain text, default empty,
-- so this ALTER needs no backfill and is safe on a file created by an earlier
-- build. Templates have no count cap: a name is unique per account and that is
-- the only limit (see `Storage::put_template`).
ALTER TABLE templates ADD COLUMN description TEXT NOT NULL DEFAULT '';
"#,
    // ---------------------------------------------------------------- 0009
    r#"
-- An organization: the company/team that owns a set of accounts. One account is
-- one mailbox (the global UNIQUE on `accounts.email` is unchanged), so an
-- organization groups mailboxes rather than merging them — every member keeps
-- their own address, their own sealed mail and their own AI-agent connection.
CREATE TABLE IF NOT EXISTS orgs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- NULL org_id is the personal workspace: the account is a tenant of one, which is
-- exactly what every account created before this migration is. ON DELETE SET
-- NULL keeps the account and its mail if the organization row ever goes away,
-- instead of deleting a mailbox as a side effect.
ALTER TABLE accounts ADD COLUMN org_id INTEGER NULL REFERENCES orgs(id) ON DELETE SET NULL;

-- The role inside the organization. The default is `owner` on purpose: an account
-- that predates organizations must not be demoted by a migration, and a personal
-- workspace's single account really does own everything it has. The CHECK spells
-- exactly [`pigeon_core::types::OrgRole::as_str`].
ALTER TABLE accounts ADD COLUMN role TEXT NOT NULL DEFAULT 'owner'
    CHECK (role IN ('owner', 'admin', 'member'));

-- Human name shown in the member list; empty means "use the address".
ALTER TABLE accounts ADD COLUMN display_name TEXT NOT NULL DEFAULT '';

-- "Every member of this organization" is the hot administration query.
CREATE INDEX IF NOT EXISTS idx_accounts_org ON accounts (org_id);
"#,
    // ---------------------------------------------------------------- 0010
    r#"
-- A pending seat in an organization, addressed to an email that may not have an
-- account yet (accepting is what creates it). The plaintext token is handed to
-- the caller exactly once and never stored: `token_hash` is the Argon2id PHC
-- hash, the same discipline as `sessions.token_hash` and `api_keys.hash`.
--
-- `UNIQUE(org_id, email)` makes the invitation for one address in one
-- organization a single row: re-inviting replaces the pending token instead of
-- leaving two live invitations for the same seat.
--
-- `accepted_at` is the burn marker. Expired or accepted rows are never deleted on
-- use, so "who was invited and when did they join" stays readable; every
-- redemption path checks both columns.
CREATE TABLE IF NOT EXISTS invitations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id      INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
    token_hash  TEXT NOT NULL,
    invited_by  INTEGER NOT NULL REFERENCES accounts(id),
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT NOT NULL,
    accepted_at TEXT NULL,
    UNIQUE (org_id, email)
);

-- "The pending invitations of this organization", for the admin listing.
CREATE INDEX IF NOT EXISTS idx_invitations_org ON invitations (org_id);
"#,
    // ---------------------------------------------------------------- 0011
    r#"
-- What the inbound SMTP server does with mail addressed to an unknown local part
-- of a managed domain. Keyed by `domain` alone, like `dkim_keys`: the domain is
-- the identity, and a second rule for the same domain could only contradict the
-- first.
--
-- `discard` accepts the message (250) and drops it: the point of a catch-all is
-- that the sender cannot distinguish a real address from a made-up one. `route`
-- requires `target_account_id`, sealed into that account's mailbox with that
-- account's AAD; deleting that account deletes the rule (ON DELETE CASCADE)
-- rather than leaving a rule that resolves to nothing.
CREATE TABLE IF NOT EXISTS catchall_rules (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    domain            TEXT UNIQUE NOT NULL,
    action            TEXT NOT NULL CHECK (action IN ('route', 'discard')),
    target_account_id INTEGER NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
"#,
    // ---------------------------------------------------------------- 0012
    r#"
-- How long a message survives in the trash, in days. `0` is "keep forever", and
-- the API accepts 0..=365 (`Storage::set_trash_retention` refuses anything else
-- too, so a value the API would reject can never reach the column).
--
-- The default is 30 on purpose: a deployment whose owner never opens the settings
-- still has a bounded trash. Mailboxes that grow forever are a disk-full outage
-- with a long fuse.
ALTER TABLE accounts ADD COLUMN trash_retention_days INTEGER NOT NULL DEFAULT 30;

-- When the message entered the trash folder. NULL in every other folder, and
-- NULL on trash rows that predate this migration (see the note above MIGRATIONS:
-- an upgrade never starts a countdown retroactively).
ALTER TABLE messages ADD COLUMN trashed_at TEXT NULL;

-- "The expired trash of one account" is the purge query: equality on
-- (account_id, folder), then a range over the timestamp.
CREATE INDEX IF NOT EXISTS idx_messages_trash
    ON messages (account_id, folder, trashed_at);
"#,
    // ---------------------------------------------------------------- 0013
    r#"
-- A secondary address on a domain this deployment serves. It owns no mailbox:
-- mail to it is copied into every assignee's inbox, and every assignee may send
-- as it. The address is the unique key, so "this alias already exists" is a
-- constraint and not a race between two admins.
CREATE TABLE IF NOT EXISTS sender_aliases (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    address    TEXT UNIQUE NOT NULL,
    domain     TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES accounts(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Who holds the alias. Primary key on the pair: assigning the same person
-- twice is the same row, not a second copy of every message. Both sides cascade:
-- deleting the alias or the account removes the assignment instead of leaving a
-- grant that points nowhere.
CREATE TABLE IF NOT EXISTS sender_alias_assignments (
    alias_id    INTEGER NOT NULL REFERENCES sender_aliases(id) ON DELETE CASCADE,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    assigned_by INTEGER NOT NULL REFERENCES accounts(id),
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (alias_id, account_id)
);

-- "The aliases this account may send as" is the compose-box query.
CREATE INDEX IF NOT EXISTS idx_alias_assignments_account
    ON sender_alias_assignments (account_id);

-- The address a copy was delivered for, when it is not the mailbox's own: an
-- alias address, or the catch-all recipient. NULL is ordinary mail. The folder
-- stays `inbox`; this column is what the webmail groups by (see the note above
-- MIGRATIONS for why the folder CHECK is not extended).
ALTER TABLE messages ADD COLUMN delivered_for TEXT NULL;

-- "The inbox, grouped by delivered address" reads exactly this index shape.
CREATE INDEX IF NOT EXISTS idx_messages_delivered_for
    ON messages (account_id, delivered_for);
"#,
    // ---------------------------------------------------------------- 0014
    r#"
-- Who receives the catch-all mail of a domain. Several accounts may hold it: a
-- shared sales address has to land in more than one mailbox.
--
-- `paused` is per (domain, account), so one member can stop their own copy
-- without touching everybody else's. `UNIQUE(domain, account_id)` makes
-- "assign this person" idempotent.
CREATE TABLE IF NOT EXISTS catchall_assignments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT NOT NULL,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    assigned_by INTEGER NOT NULL REFERENCES accounts(id),
    paused      INTEGER NOT NULL DEFAULT 0 CHECK (paused IN (0, 1)),
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (domain, account_id)
);

-- "The live assignees of this domain" is the inbound resolution query.
CREATE INDEX IF NOT EXISTS idx_catchall_assignments_domain
    ON catchall_assignments (domain, paused);

-- "Which catch-alls does this account hold" serves the self-service pause and
-- the member view of `GET /v1/catchall`.
CREATE INDEX IF NOT EXISTS idx_catchall_assignments_account
    ON catchall_assignments (account_id);

-- Carry an existing single-target rule over to the new table, so an upgraded
-- deployment keeps receiving the mail it configured. `assigned_by` is the
-- target itself: the row predates per-admin attribution, and inventing an actor
-- would be a lie in the audit trail.
INSERT INTO catchall_assignments (domain, account_id, assigned_by, paused)
SELECT domain, target_account_id, target_account_id, 0
  FROM catchall_rules
 WHERE target_account_id IS NOT NULL
ON CONFLICT (domain, account_id) DO NOTHING;
"#,
];

/// Apply every migration that has not run yet. Safe to call on every open, from
/// several processes at once.
pub fn apply(conn: &mut Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _migrations (
            id   INTEGER PRIMARY KEY,
            name TEXT UNIQUE NOT NULL
        )",
    )?;

    for (index, sql) in MIGRATIONS.iter().enumerate() {
        let name = format!("m{:04}", index + 1);
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Re-read inside the transaction: the applied set captured before the
        // loop is stale the moment another process commits a migration.
        let already_applied: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM _migrations WHERE name = ?1)",
            [&name],
            |row| row.get(0),
        )?;
        if already_applied {
            tx.commit()?;
            continue;
        }
        tx.execute_batch(sql)?;
        tx.execute(
            "INSERT INTO _migrations (id, name) VALUES (?1, ?2)",
            params![(index + 1) as i64, &name],
        )?;
        tx.commit()?;
    }

    Ok(())
}
