//! Auxiliary SQL layer for the API surface the `store` crate does not expose
//! yet.
//!
//! # Why this module exists
//!
//! `store` owns the `Storage` trait (ADR 0002) and this PR's edit surface does
//! not include it. It covers what the send pipeline needs — accounts, API-key
//! creation/lookup, message insert, queue claims, events, templates by name —
//! but not the read/admin surface the REST contract exposes: listing and
//! patching API keys, cancelling a queue row, paginating emails and inbound
//! messages, attachments, domains, webhooks and suppressions.
//!
//! Rather than fake that state in memory (an API key that disappears on restart
//! is a production incident, not a v0.1 shortcut), [`ApiDb`] opens a **second
//! connection to the same SQLite file** and owns exactly those statements. It
//! reads the tables `store` migrated (`messages`, `queue`, `events`, `api_keys`,
//! `templates`, `attachments`) and adds its own `api_*` tables for state that
//! has no home in the current schema.
//!
//! **Follow-up (tracked in `docs/ROADMAP.md`):** every method here belongs on the
//! `Storage` trait; folding them in removes this module and restores the single
//! persistence seam for the whole server. Message bodies still never appear as
//! plaintext in this layer: reads return the sealed blob, and only the crypto
//! crate opens it.
//!
//! Concurrency: one connection behind a `Mutex`, WAL, and a busy timeout match
//! the store's own profile, so the two connections never deadlock on each other.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use pigeon_core::{ApiKeyScope, EmailAddress};
use rusqlite::types::Value;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Row};

use crate::models::{ApiKeyPatch, TemplatePatch};
use crate::time::iso_from_sqlite;

/// Tables and indexes this layer owns. Idempotent, applied on every open.
///
/// The `api_` prefix distinguishes these from the schema `store` migrates and
/// keeps the two migration lists independent: neither crate has to know the
/// other's order.
const API_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS api_messages (
    message_id  INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    account_id  INTEGER NOT NULL,
    public_id   TEXT NOT NULL UNIQUE,
    status      TEXT NOT NULL,
    to_addrs    TEXT NOT NULL DEFAULT '[]',
    cc_addrs    TEXT NOT NULL DEFAULT '[]',
    tags        TEXT NOT NULL DEFAULT '[]',
    sandbox     INTEGER NOT NULL DEFAULT 0,
    e2e         TEXT NOT NULL DEFAULT 'tls_only',
    wrapped_key BLOB NULL
);
CREATE INDEX IF NOT EXISTS idx_api_messages_account
    ON api_messages (account_id, message_id DESC);

CREATE TABLE IF NOT EXISTS api_key_meta (
    key_id       INTEGER PRIMARY KEY REFERENCES api_keys(id) ON DELETE CASCADE,
    public_id    TEXT NOT NULL UNIQUE,
    sandbox      INTEGER NOT NULL DEFAULT 0,
    last_used_at TEXT NULL
);

CREATE TABLE IF NOT EXISTS api_domains (
    public_id      TEXT PRIMARY KEY,
    account_id     INTEGER NOT NULL,
    name           TEXT NOT NULL,
    verified       INTEGER NOT NULL DEFAULT 0,
    checked_at     TEXT NULL,
    dkim_selector  TEXT NOT NULL,
    -- Retained for schema compatibility with files created before the DKIM
    -- reconciliation; both are written empty and never read. The signing
    -- identity (selector, sealed private key, published TXT record) lives in
    -- `dkim_keys`, which is domain-scoped so every account serving the domain
    -- shares one identity.
    dkim_public_key TEXT NOT NULL,
    dkim_private_key TEXT NOT NULL,
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (account_id, name)
);

CREATE TABLE IF NOT EXISTS api_webhooks (
    public_id  TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL,
    url        TEXT NOT NULL,
    secret     TEXT NOT NULL,
    events     TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_api_webhooks_account ON api_webhooks (account_id);

CREATE TABLE IF NOT EXISTS api_suppressions (
    id           INTEGER PRIMARY KEY,
    account_id   INTEGER NOT NULL,
    address      TEXT NOT NULL,
    address_norm TEXT NOT NULL,
    reason       TEXT NOT NULL,
    source       TEXT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (account_id, address_norm)
);
"#;

/// One outbound email, joined with its lifecycle and queue state.
#[derive(Debug, Clone)]
pub struct EmailRow {
    pub message_id: i64,
    pub public_id: String,
    pub status: String,
    pub from_addr: String,
    pub to_addrs: Vec<String>,
    pub cc_addrs: Vec<String>,
    pub subject: String,
    pub tags: Vec<String>,
    pub sandbox: bool,
    pub e2e: String,
    pub wrapped_key: Option<Vec<u8>>,
    pub created_at: String,
    pub queue_status: Option<String>,
    pub queue_attempts: i64,
    pub queue_run_after: Option<i64>,
    pub last_event: Option<String>,
}

/// Columns [`ApiDb::email_page`] and [`ApiDb::email_by_public_id`] select, in the
/// order [`ApiDb::map_email`] reads them. Kept in one place so the two queries
/// cannot drift apart.
const EMAIL_SELECT: &str = "\
SELECT m.id, a.public_id, a.status, m.from_addr, a.to_addrs, a.cc_addrs, m.subject, \
       a.tags, a.sandbox, a.e2e, a.wrapped_key, m.created_at, \
       q.status, COALESCE(q.attempts, 0), q.run_after, \
       (SELECT MAX(e.created_at) FROM events e WHERE e.message_id = m.id) \
  FROM messages m \
  JOIN api_messages a ON a.message_id = m.id \
  LEFT JOIN queue q ON q.message_id = m.id";

/// A stored message, sealed body included, resolved for one account.
#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub message_id: i64,
    pub public_id: String,
    pub direction: String,
    pub from_addr: String,
    pub to_addrs: Vec<String>,
    pub subject: String,
    pub sealed_body: Vec<u8>,
    pub created_at: String,
    pub wrapped_key: Option<Vec<u8>>,
    /// Address this copy was delivered for, when it is not the account's own (a
    /// sender alias or a catch-all local part). `None` on ordinary mail.
    pub delivered_for: Option<String>,
}

/// One attachment row.
#[derive(Debug, Clone)]
pub struct AttachmentRow {
    pub attachment_id: i64,
    pub public_id: String,
    pub filename: String,
    pub size: i64,
    /// 0-based position of the part in its message (the AAD binds it).
    pub ordinal: i64,
    pub sealed_content: Vec<u8>,
}

/// One template row.
#[derive(Debug, Clone)]
pub struct TemplateRow {
    pub template_id: i64,
    pub public_id: String,
    pub name: String,
    /// Short human description; empty when the template was stored without one.
    pub description: String,
    pub subject: String,
    pub html: String,
    pub text: String,
    pub updated_at: String,
}

/// One managed domain row.
#[derive(Debug, Clone)]
pub struct DomainRow {
    pub public_id: String,
    pub name: String,
    pub verified: bool,
    pub checked_at: Option<String>,
    pub dkim_selector: String,
}

/// One webhook row; the secret never leaves this struct except at creation.
#[derive(Debug, Clone)]
pub struct WebhookRow {
    pub public_id: String,
    pub url: String,
    pub events: Vec<String>,
    pub secret: String,
    pub created_at: String,
}

/// One suppression row.
#[derive(Debug, Clone)]
pub struct SuppressionRow {
    pub address: String,
    pub reason: String,
    pub source: Option<String>,
    pub created_at: String,
}

/// One API key, metadata only — the hash never leaves `store`.
#[derive(Debug, Clone)]
pub struct KeyRow {
    pub key_id: i64,
    pub public_id: String,
    pub name: String,
    pub scopes: Vec<ApiKeyScope>,
    pub revoked: bool,
    pub sandbox: bool,
    pub last_used_at: Option<String>,
    pub created_at: String,
}

/// The values written when an email is accepted.
#[derive(Debug, Clone)]
pub struct NewEmail {
    pub account_id: i64,
    pub message_id: i64,
    pub public_id: String,
    pub status: String,
    /// `To:` recipients only. The envelope in `messages.to_addrs` also carries
    /// cc and bcc, which must never be echoed back to a client.
    pub to_addrs: Vec<String>,
    pub cc_addrs: Vec<String>,
    pub tags: Vec<String>,
    pub sandbox: bool,
    pub e2e: String,
    pub wrapped_key: Vec<u8>,
}

/// Auxiliary SQL against the shared Pigeon database.
pub struct ApiDb {
    conn: Mutex<Connection>,
}

impl ApiDb {
    /// Open a second connection to the same file `store` uses and make sure the
    /// `api_*` tables exist.
    pub fn open(path: impl AsRef<Path>) -> store::Result<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(API_SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Lock the connection, recovering from a poisoned mutex: every statement is
    /// its own transaction, so the connection is still usable.
    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// `SELECT 1` — the readiness probe's storage check.
    pub fn ping(&self) -> store::Result<()> {
        let conn = self.lock();
        conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))?;
        Ok(())
    }

    /// Resolve an account by its normalized email address.
    pub fn account_id_by_email(&self, email_norm: &str) -> store::Result<Option<i64>> {
        let conn = self.lock();
        Ok(conn
            .query_row(
                "SELECT id FROM accounts WHERE email_norm = ?1",
                [email_norm],
                |row| row.get(0),
            )
            .optional()?)
    }

    // ---------------------------------------------------------------- emails

    /// Record the lifecycle side of a freshly inserted message.
    pub fn insert_email(&self, email: &NewEmail) -> store::Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO api_messages
                (message_id, account_id, public_id, status, to_addrs, cc_addrs,
                 tags, sandbox, e2e, wrapped_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                email.message_id,
                email.account_id,
                email.public_id,
                email.status,
                encode_list(&email.to_addrs),
                encode_list(&email.cc_addrs),
                encode_list(&email.tags),
                i64::from(email.sandbox),
                email.e2e,
                email.wrapped_key
            ],
        )?;
        Ok(())
    }

    /// Page outbound emails, newest first, optionally filtered by lifecycle
    /// status and tag. Returns `(rows, total_matching)`.
    pub fn email_page(
        &self,
        account_id: i64,
        limit: i64,
        offset: i64,
        status: Option<&str>,
        tag: Option<&str>,
    ) -> store::Result<(Vec<EmailRow>, i64)> {
        let mut filters = String::from(" WHERE m.account_id = ?1 AND m.direction = 'out'");
        let mut values = vec![Value::Integer(account_id)];
        if let Some(status) = status {
            values.push(Value::Text(status.to_string()));
            filters.push_str(&format!(" AND a.status = ?{}", values.len()));
        }
        if let Some(tag) = tag {
            values.push(Value::Text(tag.to_string()));
            filters.push_str(&format!(
                " AND EXISTS (SELECT 1 FROM json_each(a.tags) WHERE json_each.value = ?{})",
                values.len()
            ));
        }

        let conn = self.lock();
        let total: i64 = conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM messages m JOIN api_messages a \
                 ON a.message_id = m.id{filters}"
            ),
            params_from_iter(values.iter()),
            |row| row.get(0),
        )?;

        values.push(Value::Integer(limit));
        let limit_index = values.len();
        values.push(Value::Integer(offset));
        let offset_index = values.len();
        let sql = format!(
            "{EMAIL_SELECT}{filters} ORDER BY m.id DESC LIMIT ?{limit_index} OFFSET ?{offset_index}"
        );
        let mut statement = conn.prepare(&sql)?;
        let rows = statement
            .query_map(params_from_iter(values.iter()), map_email)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((rows, total))
    }

    /// Load one outbound email by its public id.
    pub fn email_by_public_id(
        &self,
        account_id: i64,
        public_id: &str,
    ) -> store::Result<Option<EmailRow>> {
        let conn = self.lock();
        Ok(conn
            .query_row(
                &format!("{EMAIL_SELECT} WHERE m.account_id = ?1 AND a.public_id = ?2"),
                params![account_id, public_id],
                map_email,
            )
            .optional()?)
    }

    /// Flip the lifecycle status of an email; `false` when no row matched.
    pub fn set_email_status(
        &self,
        account_id: i64,
        public_id: &str,
        status: &str,
    ) -> store::Result<bool> {
        let conn = self.lock();
        let updated = conn.execute(
            "UPDATE api_messages SET status = ?3 WHERE account_id = ?1 AND public_id = ?2",
            params![account_id, public_id, status],
        )?;
        Ok(updated > 0)
    }

    /// Number of outbound emails queued today (UTC), for the daily quota.
    pub fn daily_outbound_count(&self, account_id: i64) -> store::Result<i64> {
        let conn = self.lock();
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM messages
              WHERE account_id = ?1 AND direction = 'out'
                AND created_at >= datetime('now', 'start of day')",
            [account_id],
            |row| row.get(0),
        )?)
    }

    /// Public id already bound to an idempotency key, if any.
    pub fn email_id_by_idempotency(
        &self,
        account_id: i64,
        key: &str,
    ) -> store::Result<Option<String>> {
        let conn = self.lock();
        let found = conn
            .query_row(
                "SELECT a.public_id FROM messages m
                   JOIN api_messages a ON a.message_id = m.id
                  WHERE m.account_id = ?1 AND m.idempotency_key = ?2",
                params![account_id, key],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(found)
    }

    /// Public id of a message that already exists, preferring the stored id and
    /// falling back to the derived one (a replay can land between the winner's
    /// insert and its lifecycle row).
    pub fn public_id_for_message(&self, message_id: i64) -> store::Result<Option<String>> {
        let conn = self.lock();
        let stored = conn
            .query_row(
                "SELECT public_id FROM api_messages WHERE message_id = ?1",
                [message_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(stored.or_else(|| Some(crate::ids::derived(crate::ids::EML, message_id))))
    }

    /// Cancel: drop the queue row and mark the email cancelled.
    pub fn cancel_email(&self, account_id: i64, public_id: &str) -> store::Result<bool> {
        let conn = self.lock();
        let message_id: Option<i64> = conn
            .query_row(
                "SELECT message_id FROM api_messages WHERE account_id = ?1 AND public_id = ?2",
                params![account_id, public_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(message_id) = message_id else {
            return Ok(false);
        };
        conn.execute("DELETE FROM queue WHERE message_id = ?1", [message_id])?;
        conn.execute(
            "UPDATE api_messages SET status = 'cancelled'
              WHERE message_id = ?1",
            [message_id],
        )?;
        Ok(true)
    }

    // -------------------------------------------------------------- messages

    /// Resolve a public `msg_`/`eml_` id to the row id it points at, scoped to
    /// one account.
    ///
    /// Same resolution order as [`ApiDb::message_by_public_id`]: the id stored
    /// in `api_messages` wins, and a derived `<prefix><hex>` id is the fallback
    /// for rows the SMTP pipeline wrote without a lifecycle row. Folder and read
    /// state live in `messages` (the `store` crate's seam), so every mutation
    /// resolves the id here first and then hands the row id to `store`.
    ///
    /// The derived fallback is **account-checked** before it is returned: a
    /// derived id is `<prefix><row id>`, so without the check any account could
    /// name another account's row and mutate it. A missing row and a foreign row
    /// both resolve to `None`, which the handlers report as the same `404`.
    pub fn message_id_by_public_id(
        &self,
        account_id: i64,
        public_id: &str,
    ) -> store::Result<Option<i64>> {
        let conn = self.lock();
        let stored: Option<i64> = conn
            .query_row(
                "SELECT message_id FROM api_messages WHERE account_id = ?1 AND public_id = ?2",
                params![account_id, public_id],
                |row| row.get(0),
            )
            .optional()?;
        if stored.is_some() {
            return Ok(stored);
        }
        let Some(derived) = parse_derived(public_id, crate::ids::MSG) else {
            return Ok(None);
        };
        let owned: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE id = ?1 AND account_id = ?2)",
            params![derived, account_id],
            |row| row.get(0),
        )?;
        Ok(owned.then_some(derived))
    }

    /// Drop the lifecycle row of a hard-deleted message.
    ///
    /// The foreign key already cascades this delete, but the API removes the row
    /// explicitly so the operation does not depend on `PRAGMA foreign_keys`
    /// being on for whichever connection happens to run it. Returns how many
    /// rows were removed (zero when the cascade got there first).
    pub fn delete_api_message(&self, message_id: i64) -> store::Result<usize> {
        let conn = self.lock();
        Ok(conn.execute(
            "DELETE FROM api_messages WHERE message_id = ?1",
            [message_id],
        )?)
    }

    /// Load one message (either direction) by its public id, sealed body
    /// included.
    pub fn message_by_public_id(
        &self,
        account_id: i64,
        public_id: &str,
    ) -> store::Result<Option<StoredMessage>> {
        let conn = self.lock();
        let message_id: Option<i64> = conn
            .query_row(
                "SELECT message_id FROM api_messages WHERE account_id = ?1 AND public_id = ?2",
                params![account_id, public_id],
                |row| row.get(0),
            )
            .optional()?;
        let message_id = match message_id {
            Some(id) => id,
            None => match parse_derived(public_id, crate::ids::MSG) {
                Some(id) => id,
                None => return Ok(None),
            },
        };
        let message = conn
            .query_row(
                "SELECT m.id, m.direction, m.from_addr, m.to_addrs, m.subject,
                        m.sealed_body, m.created_at, a.wrapped_key, m.delivered_for
                   FROM messages m
                   LEFT JOIN api_messages a ON a.message_id = m.id
                  WHERE m.id = ?1 AND m.account_id = ?2",
                params![message_id, account_id],
                map_stored_message,
            )
            .optional()?;
        Ok(message.map(|mut message| {
            message.public_id = public_id.to_string();
            message
        }))
    }

    // ----------------------------------------------------------- attachments

    /// Store one sealed attachment blob; returns the row id.
    pub fn insert_attachment(
        &self,
        message_id: i64,
        filename: &str,
        size: i64,
        sealed_content: &[u8],
    ) -> store::Result<i64> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO attachments (message_id, filename, size, sealed_content)
             VALUES (?1, ?2, ?3, ?4)",
            params![message_id, filename, size, sealed_content],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Attachments of a message, metadata only (no blobs).
    pub fn attachments_for(&self, message_id: i64) -> store::Result<Vec<AttachmentRow>> {
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT a.id, a.filename, a.size,
                    (SELECT COUNT(*) FROM attachments b
                      WHERE b.message_id = a.message_id AND b.id < a.id)
               FROM attachments a WHERE a.message_id = ?1 ORDER BY a.id",
        )?;
        let rows = statement
            .query_map([message_id], |row| {
                let id: i64 = row.get(0)?;
                Ok(AttachmentRow {
                    attachment_id: id,
                    public_id: crate::ids::derived(crate::ids::ATC, id),
                    filename: row.get(1)?,
                    size: row.get(2)?,
                    ordinal: row.get(3)?,
                    sealed_content: Vec::new(),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// One attachment, blob included.
    pub fn attachment(
        &self,
        message_id: i64,
        attachment_id: i64,
    ) -> store::Result<Option<AttachmentRow>> {
        let conn = self.lock();
        Ok(conn
            .query_row(
                "SELECT a.id, a.filename, a.size, a.sealed_content,
                        (SELECT COUNT(*) FROM attachments b
                          WHERE b.message_id = a.message_id AND b.id < a.id)
                   FROM attachments a
                  WHERE a.message_id = ?1 AND a.id = ?2",
                params![message_id, attachment_id],
                |row| {
                    let id: i64 = row.get(0)?;
                    Ok(AttachmentRow {
                        attachment_id: id,
                        public_id: crate::ids::derived(crate::ids::ATC, id),
                        filename: row.get(1)?,
                        size: row.get(2)?,
                        sealed_content: row.get(3)?,
                        ordinal: row.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    // ------------------------------------------------------------- templates

    /// Insert a template; a duplicate `(account, name)` is `Conflict`.
    pub fn create_template(
        &self,
        account_id: i64,
        name: &str,
        description: &str,
        subject: &str,
        html: &str,
        text: &str,
    ) -> store::Result<i64> {
        let conn = self.lock();
        match conn.execute(
            "INSERT INTO templates (account_id, name, description, subject_tpl, html_tpl, text_tpl)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![account_id, name, description, subject, html, text],
        ) {
            Ok(_) => Ok(conn.last_insert_rowid()),
            Err(error) if is_unique_violation(&error) => Err(store::StoreError::Conflict),
            Err(error) => Err(error.into()),
        }
    }

    /// Every template of an account, newest first.
    pub fn list_templates(&self, account_id: i64) -> store::Result<Vec<TemplateRow>> {
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT id, name, description, subject_tpl, html_tpl, text_tpl, updated_at
               FROM templates WHERE account_id = ?1 ORDER BY id DESC",
        )?;
        let rows = statement
            .query_map([account_id], map_template)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Load one template by public id.
    pub fn template_by_public_id(
        &self,
        account_id: i64,
        public_id: &str,
    ) -> store::Result<Option<TemplateRow>> {
        let Some(template_id) = parse_derived(public_id, crate::ids::TPL) else {
            return Ok(None);
        };
        let conn = self.lock();
        Ok(conn
            .query_row(
                "SELECT id, name, description, subject_tpl, html_tpl, text_tpl, updated_at
                   FROM templates WHERE account_id = ?1 AND id = ?2",
                params![account_id, template_id],
                map_template,
            )
            .optional()?)
    }

    /// Apply a partial update; `None` when the template does not exist.
    pub fn update_template(
        &self,
        account_id: i64,
        template_id: i64,
        patch: &TemplatePatch,
    ) -> store::Result<Option<TemplateRow>> {
        let conn = self.lock();
        let existing = conn
            .query_row(
                "SELECT id, name, description, subject_tpl, html_tpl, text_tpl, updated_at
                   FROM templates WHERE account_id = ?1 AND id = ?2",
                params![account_id, template_id],
                map_template,
            )
            .optional()?;
        let Some(existing) = existing else {
            return Ok(None);
        };
        let name = patch.name.as_deref().unwrap_or(&existing.name);
        let description = patch
            .description
            .as_deref()
            .unwrap_or(&existing.description);
        let subject = patch.subject.as_deref().unwrap_or(&existing.subject);
        let html = patch.html.as_deref().unwrap_or(&existing.html);
        let text = patch.text.as_deref().unwrap_or(&existing.text);
        match conn.execute(
            "UPDATE templates
                SET name = ?3, description = ?4, subject_tpl = ?5, html_tpl = ?6,
                    text_tpl = ?7, updated_at = datetime('now')
              WHERE account_id = ?1 AND id = ?2",
            params![
                account_id,
                template_id,
                name,
                description,
                subject,
                html,
                text
            ],
        ) {
            Ok(_) => {}
            Err(error) if is_unique_violation(&error) => return Err(store::StoreError::Conflict),
            Err(error) => return Err(error.into()),
        }
        Ok(conn
            .query_row(
                "SELECT id, name, description, subject_tpl, html_tpl, text_tpl, updated_at
                   FROM templates WHERE account_id = ?1 AND id = ?2",
                params![account_id, template_id],
                map_template,
            )
            .optional()?)
    }

    /// Delete a template; `false` when it did not exist.
    pub fn delete_template(&self, account_id: i64, template_id: i64) -> store::Result<bool> {
        let conn = self.lock();
        let removed = conn.execute(
            "DELETE FROM templates WHERE account_id = ?1 AND id = ?2",
            params![account_id, template_id],
        )?;
        Ok(removed > 0)
    }

    // --------------------------------------------------------------- domains

    /// Insert a domain unless the account already has that name, then return the
    /// stored row.
    ///
    /// The DKIM keys this row used to carry are gone: only the selector is
    /// recorded here, and the key material lives in `dkim_keys` keyed by domain
    /// name (see migration `0006` in `store`). The two legacy key columns are
    /// still written — with empty strings — because files created by earlier
    /// builds declare them `NOT NULL`; nothing reads them.
    pub fn upsert_domain(
        &self,
        public_id: &str,
        account_id: i64,
        name: &str,
        selector: &str,
    ) -> store::Result<DomainRow> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO api_domains
                (public_id, account_id, name, verified, dkim_selector,
                 dkim_public_key, dkim_private_key)
             VALUES (?1, ?2, ?3, 0, ?4, '', '')
             ON CONFLICT (account_id, name) DO NOTHING",
            params![public_id, account_id, name, selector],
        )?;
        Ok(conn.query_row(
            "SELECT public_id, name, verified, checked_at, dkim_selector
               FROM api_domains WHERE account_id = ?1 AND name = ?2",
            params![account_id, name],
            map_domain,
        )?)
    }

    /// Domains of an account, oldest first.
    pub fn list_domains(&self, account_id: i64) -> store::Result<Vec<DomainRow>> {
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT public_id, name, verified, checked_at, dkim_selector
               FROM api_domains WHERE account_id = ?1 ORDER BY created_at, name",
        )?;
        let rows = statement
            .query_map([account_id], map_domain)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Load one domain by public id.
    pub fn domain_by_public_id(
        &self,
        account_id: i64,
        public_id: &str,
    ) -> store::Result<Option<DomainRow>> {
        let conn = self.lock();
        Ok(conn
            .query_row(
                "SELECT public_id, name, verified, checked_at, dkim_selector
                   FROM api_domains WHERE account_id = ?1 AND public_id = ?2",
                params![account_id, public_id],
                map_domain,
            )
            .optional()?)
    }

    /// Record a verification attempt. DNS checking itself is v0.2, so the
    /// verified flag is written as `false` until that lands.
    pub fn touch_domain_checked(&self, account_id: i64, public_id: &str) -> store::Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE api_domains SET checked_at = datetime('now')
              WHERE account_id = ?1 AND public_id = ?2",
            params![account_id, public_id],
        )?;
        Ok(())
    }

    // -------------------------------------------------------------- webhooks

    /// Insert a webhook.
    pub fn create_webhook(
        &self,
        account_id: i64,
        url: &str,
        events: &[String],
        secret: &str,
    ) -> store::Result<WebhookRow> {
        let public_id = crate::ids::gen(crate::ids::WHK);
        let conn = self.lock();
        conn.execute(
            "INSERT INTO api_webhooks (public_id, account_id, url, secret, events)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![public_id, account_id, url, secret, encode_list(events)],
        )?;
        Ok(conn.query_row(
            "SELECT public_id, url, events, secret, created_at
               FROM api_webhooks WHERE public_id = ?1",
            [&public_id],
            map_webhook,
        )?)
    }

    /// Webhooks of an account, oldest first.
    pub fn list_webhooks(&self, account_id: i64) -> store::Result<Vec<WebhookRow>> {
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT public_id, url, events, secret, created_at
               FROM api_webhooks WHERE account_id = ?1 ORDER BY created_at, public_id",
        )?;
        let rows = statement
            .query_map([account_id], map_webhook)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Load one webhook by public id.
    pub fn webhook_by_public_id(
        &self,
        account_id: i64,
        public_id: &str,
    ) -> store::Result<Option<WebhookRow>> {
        let conn = self.lock();
        Ok(conn
            .query_row(
                "SELECT public_id, url, events, secret, created_at
                   FROM api_webhooks WHERE account_id = ?1 AND public_id = ?2",
                params![account_id, public_id],
                map_webhook,
            )
            .optional()?)
    }

    /// Delete a webhook; `false` when it did not exist.
    pub fn delete_webhook(&self, account_id: i64, public_id: &str) -> store::Result<bool> {
        let conn = self.lock();
        let removed = conn.execute(
            "DELETE FROM api_webhooks WHERE account_id = ?1 AND public_id = ?2",
            params![account_id, public_id],
        )?;
        Ok(removed > 0)
    }

    // ---------------------------------------------------------- suppressions

    /// Insert suppressions, ignoring addresses already suppressed. Returns the
    /// number of new rows.
    pub fn insert_suppressions(
        &self,
        account_id: i64,
        addresses: &[EmailAddress],
        reason: &str,
        source: Option<&str>,
    ) -> store::Result<usize> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let mut inserted = 0;
        {
            let mut statement = tx.prepare(
                "INSERT INTO api_suppressions
                    (account_id, address, address_norm, reason, source)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (account_id, address_norm) DO NOTHING",
            )?;
            for address in addresses {
                inserted += statement.execute(params![
                    account_id,
                    address.to_string(),
                    address.normalized(),
                    reason,
                    source
                ])?;
            }
        }
        tx.commit()?;
        Ok(inserted)
    }

    /// Page suppressions, oldest first.
    pub fn suppression_page(
        &self,
        account_id: i64,
        limit: i64,
        offset: i64,
    ) -> store::Result<(Vec<SuppressionRow>, i64)> {
        let conn = self.lock();
        let total: i64 = conn.query_row(
            "SELECT COUNT(*) FROM api_suppressions WHERE account_id = ?1",
            [account_id],
            |row| row.get(0),
        )?;
        let mut statement = conn.prepare(
            "SELECT address, reason, source, created_at FROM api_suppressions
              WHERE account_id = ?1 ORDER BY id LIMIT ?2 OFFSET ?3",
        )?;
        let rows = statement
            .query_map(params![account_id, limit, offset], |row| {
                Ok(SuppressionRow {
                    address: row.get(0)?,
                    reason: row.get(1)?,
                    source: row.get(2)?,
                    created_at: iso_from_sqlite(&row.get::<_, String>(3)?),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((rows, total))
    }

    /// Remove one suppression by its normalized address.
    pub fn delete_suppression(&self, account_id: i64, address_norm: &str) -> store::Result<bool> {
        let conn = self.lock();
        let removed = conn.execute(
            "DELETE FROM api_suppressions WHERE account_id = ?1 AND address_norm = ?2",
            params![account_id, address_norm],
        )?;
        Ok(removed > 0)
    }

    // ------------------------------------------------------------- API keys

    /// Resolve a key by its stored Argon2id hash (auth path).
    pub fn key_by_hash(&self, account_id: i64, hash: &str) -> store::Result<Option<KeyRow>> {
        let conn = self.lock();
        Ok(conn
            .query_row(
                "SELECT k.id, COALESCE(m.public_id, ''), k.name, k.scopes,
                        k.revoked_at, COALESCE(m.sandbox, 0), m.last_used_at, k.created_at
                   FROM api_keys k
                   LEFT JOIN api_key_meta m ON m.key_id = k.id
                  WHERE k.account_id = ?1 AND k.hash = ?2
                  ORDER BY k.id DESC",
                params![account_id, hash],
                map_key,
            )
            .optional()?)
    }

    /// Record the metadata row for a key created through `store`.
    pub fn create_key_meta(
        &self,
        key_id: i64,
        public_id: &str,
        sandbox: bool,
    ) -> store::Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO api_key_meta (key_id, public_id, sandbox) VALUES (?1, ?2, ?3)",
            params![key_id, public_id, i64::from(sandbox)],
        )?;
        Ok(())
    }

    /// Keys of an account, newest first.
    pub fn list_keys(&self, account_id: i64) -> store::Result<Vec<KeyRow>> {
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT k.id, COALESCE(m.public_id, ''), k.name, k.scopes,
                    k.revoked_at, COALESCE(m.sandbox, 0), m.last_used_at, k.created_at
               FROM api_keys k
               LEFT JOIN api_key_meta m ON m.key_id = k.id
              WHERE k.account_id = ?1 ORDER BY k.id DESC",
        )?;
        let rows = statement
            .query_map([account_id], map_key)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Load one key by public id.
    pub fn key_by_public_id(
        &self,
        account_id: i64,
        public_id: &str,
    ) -> store::Result<Option<KeyRow>> {
        let conn = self.lock();
        Ok(conn
            .query_row(
                "SELECT k.id, COALESCE(m.public_id, ''), k.name, k.scopes,
                        k.revoked_at, COALESCE(m.sandbox, 0), m.last_used_at, k.created_at
                   FROM api_keys k
                   LEFT JOIN api_key_meta m ON m.key_id = k.id
                  WHERE k.account_id = ?1 AND m.public_id = ?2",
                params![account_id, public_id],
                map_key,
            )
            .optional()?)
    }

    /// Apply a partial key update; `None` when the key does not exist.
    pub fn patch_key(
        &self,
        account_id: i64,
        public_id: &str,
        patch: &ApiKeyPatch,
    ) -> store::Result<Option<KeyRow>> {
        let Some(existing) = self.key_by_public_id(account_id, public_id)? else {
            return Ok(None);
        };
        {
            // Scoped so the connection guard is released before the reload at
            // the end: `std::sync::Mutex` is not reentrant.
            let conn = self.lock();
            if let Some(name) = patch.name.as_deref() {
                conn.execute(
                    "UPDATE api_keys SET name = ?3 WHERE account_id = ?1 AND id = ?2",
                    params![account_id, existing.key_id, name],
                )?;
            }
            if let Some(revoked) = patch.revoked {
                if revoked {
                    conn.execute(
                        "UPDATE api_keys SET revoked_at = datetime('now')
                          WHERE account_id = ?1 AND id = ?2 AND revoked_at IS NULL",
                        params![account_id, existing.key_id],
                    )?;
                } else {
                    conn.execute(
                        "UPDATE api_keys SET revoked_at = NULL
                          WHERE account_id = ?1 AND id = ?2",
                        params![account_id, existing.key_id],
                    )?;
                }
            }
            if let Some(sandbox) = patch.sandbox {
                conn.execute(
                    "INSERT INTO api_key_meta (key_id, public_id, sandbox)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT (key_id) DO UPDATE SET sandbox = excluded.sandbox",
                    params![existing.key_id, existing.public_id, i64::from(sandbox)],
                )?;
            }
        }
        self.key_by_public_id(account_id, public_id)
    }

    /// Delete a key; returns its row id when one was removed.
    pub fn delete_key(&self, account_id: i64, public_id: &str) -> store::Result<Option<i64>> {
        let conn = self.lock();
        let key_id: Option<i64> = conn
            .query_row(
                "SELECT k.id FROM api_keys k
                   JOIN api_key_meta m ON m.key_id = k.id
                  WHERE k.account_id = ?1 AND m.public_id = ?2",
                params![account_id, public_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(key_id) = key_id else {
            return Ok(None);
        };
        conn.execute(
            "DELETE FROM api_keys WHERE account_id = ?1 AND id = ?2",
            params![account_id, key_id],
        )?;
        Ok(Some(key_id))
    }

    /// Record the last successful authentication for a key.
    pub fn touch_key(&self, key_id: i64) -> store::Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE api_key_meta SET last_used_at = datetime('now') WHERE key_id = ?1",
            [key_id],
        )?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Row mappers and helpers
// ---------------------------------------------------------------------------

fn map_email(row: &Row<'_>) -> rusqlite::Result<EmailRow> {
    Ok(EmailRow {
        message_id: row.get(0)?,
        public_id: row.get(1)?,
        status: row.get(2)?,
        from_addr: row.get(3)?,
        to_addrs: decode_list(&row.get::<_, String>(4)?),
        cc_addrs: decode_list(&row.get::<_, String>(5)?),
        subject: row.get(6)?,
        tags: decode_list(&row.get::<_, String>(7)?),
        sandbox: row.get::<_, i64>(8)? != 0,
        e2e: row.get(9)?,
        wrapped_key: row.get(10)?,
        created_at: iso_from_sqlite(&row.get::<_, String>(11)?),
        queue_status: row.get(12)?,
        queue_attempts: row.get(13)?,
        queue_run_after: row.get(14)?,
        last_event: row
            .get::<_, Option<String>>(15)?
            .map(|value| iso_from_sqlite(&value)),
    })
}

fn map_stored_message(row: &Row<'_>) -> rusqlite::Result<StoredMessage> {
    let message_id: i64 = row.get(0)?;
    Ok(StoredMessage {
        message_id,
        // Overwritten by the caller that knows which id was requested.
        public_id: crate::ids::derived(crate::ids::MSG, message_id),
        direction: row.get(1)?,
        from_addr: row.get(2)?,
        to_addrs: decode_list(&row.get::<_, String>(3)?),
        subject: row.get(4)?,
        sealed_body: row.get(5)?,
        created_at: iso_from_sqlite(&row.get::<_, String>(6)?),
        wrapped_key: row.get(7)?,
        delivered_for: row.get(8)?,
    })
}

fn map_template(row: &Row<'_>) -> rusqlite::Result<TemplateRow> {
    let template_id: i64 = row.get(0)?;
    Ok(TemplateRow {
        template_id,
        public_id: crate::ids::derived(crate::ids::TPL, template_id),
        name: row.get(1)?,
        description: row.get(2)?,
        subject: row.get(3)?,
        html: row.get(4)?,
        text: row.get(5)?,
        updated_at: iso_from_sqlite(&row.get::<_, String>(6)?),
    })
}

fn map_domain(row: &Row<'_>) -> rusqlite::Result<DomainRow> {
    Ok(DomainRow {
        public_id: row.get(0)?,
        name: row.get(1)?,
        verified: row.get::<_, i64>(2)? != 0,
        checked_at: row
            .get::<_, Option<String>>(3)?
            .map(|value| iso_from_sqlite(&value)),
        dkim_selector: row.get(4)?,
    })
}

fn map_webhook(row: &Row<'_>) -> rusqlite::Result<WebhookRow> {
    Ok(WebhookRow {
        public_id: row.get(0)?,
        url: row.get(1)?,
        events: decode_list(&row.get::<_, String>(2)?),
        secret: row.get(3)?,
        created_at: iso_from_sqlite(&row.get::<_, String>(4)?),
    })
}

fn map_key(row: &Row<'_>) -> rusqlite::Result<KeyRow> {
    let scopes: String = row.get(3)?;
    Ok(KeyRow {
        key_id: row.get(0)?,
        public_id: row.get(1)?,
        name: row.get(2)?,
        scopes: scopes
            .split(',')
            .filter(|scope| !scope.is_empty())
            // An unknown stored scope is dropped rather than failing the whole
            // listing: `store` already rejects such a key at auth time.
            .filter_map(|scope| ApiKeyScope::parse(scope).ok())
            .collect(),
        revoked: row.get::<_, Option<String>>(4)?.is_some(),
        sandbox: row.get::<_, i64>(5)? != 0,
        last_used_at: row
            .get::<_, Option<String>>(6)?
            .map(|value| iso_from_sqlite(&value)),
        created_at: iso_from_sqlite(&row.get::<_, String>(7)?),
    })
}

/// Encode a list as JSON — the same discipline `store` uses for `to_addrs`:
/// no separator to get wrong, corrupt content fails to decode.
fn encode_list(items: &[String]) -> String {
    serde_json::to_string(items).unwrap_or_else(|_| "[]".to_string())
}

/// Decode a JSON list, degrading to empty and logging when the column no longer
/// holds what this crate wrote.
fn decode_list(raw: &str) -> Vec<String> {
    match serde_json::from_str::<Vec<String>>(raw) {
        Ok(items) => items,
        Err(error) => {
            tracing::warn!(%error, "api_* column is not a JSON string array; treating as empty");
            Vec::new()
        }
    }
}

/// Parse a `<prefix><8 hex>` id back into its row id.
fn parse_derived(public_id: &str, prefix: &str) -> Option<i64> {
    let suffix = public_id.strip_prefix(prefix)?;
    i64::from_str_radix(suffix, 16).ok()
}

/// True only for a *unique* violation (`SQLITE_CONSTRAINT_UNIQUE` /
/// `SQLITE_CONSTRAINT_PRIMARYKEY`). Other constraint failures — a foreign key
/// pointing at a missing account, a NOT NULL — are real bugs and must surface as
/// server errors, not be reported to the client as a duplicate name.
fn is_unique_violation(error: &rusqlite::Error) -> bool {
    const SQLITE_CONSTRAINT_PRIMARYKEY: i32 = 1555;
    const SQLITE_CONSTRAINT_UNIQUE: i32 = 2067;
    matches!(
        error,
        rusqlite::Error::SqliteFailure(e, _)
            if e.code == rusqlite::ErrorCode::ConstraintViolation
                && (e.extended_code == SQLITE_CONSTRAINT_UNIQUE
                    || e.extended_code == SQLITE_CONSTRAINT_PRIMARYKEY)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use store::{SqliteStorage, Storage};
    use tempfile::TempDir;

    /// Temp database with the `store` schema and accounts 1..=3, which the
    /// foreign keys on `messages`/`templates` require.
    fn fixture() -> (TempDir, ApiDb) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("api.db");
        // The base schema (`templates`, `messages`, ...) belongs to `store`; open
        // it first, exactly as `AppState::open` does.
        let store = SqliteStorage::open(&path).expect("store migrations");
        for email in ["one@example.com", "two@example.com", "three@example.com"] {
            store
                .create_account(&EmailAddress::parse(email).expect("address"))
                .expect("account");
        }
        let db = ApiDb::open(&path).expect("open api db");
        (dir, db)
    }

    #[test]
    fn opening_twice_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("api.db");
        SqliteStorage::open(&path).expect("store migrations");
        let first = ApiDb::open(&path).expect("open");
        drop(first);
        let second = ApiDb::open(&path).expect("reopen");
        second.ping().expect("ping");
    }

    #[test]
    fn message_id_resolution_is_scoped_to_the_account() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("api.db");
        let store = SqliteStorage::open(&path).expect("store migrations");
        let owner = store
            .create_account(&EmailAddress::parse("owner@example.com").expect("address"))
            .expect("owner");
        let stranger = store
            .create_account(&EmailAddress::parse("stranger@example.com").expect("address"))
            .expect("stranger");
        let reserved = store.reserve_message_id().expect("reserve");
        let mut sealed = vec![0u8; pigeon_crypto::MIN_BLOB_LEN];
        sealed[0] = pigeon_crypto::ENVELOPE_VERSION;
        store
            .insert_message(
                store::NewMessage {
                    account_id: owner,
                    direction: pigeon_core::Direction::In,
                    from_addr: EmailAddress::parse("peer@example.net").expect("address"),
                    to_addrs: vec![EmailAddress::parse("owner@example.com").expect("address")],
                    subject: "hi".to_string(),
                    sealed_body: sealed,
                    idempotency_key: None,
                    delivered_for: None,
                },
                reserved,
            )
            .expect("insert");
        let db = ApiDb::open(&path).expect("open api db");

        let derived = crate::ids::derived(crate::ids::MSG, reserved);
        assert_eq!(
            db.message_id_by_public_id(owner, &derived)
                .expect("resolve"),
            Some(reserved)
        );
        assert_eq!(
            db.message_id_by_public_id(stranger, &derived)
                .expect("resolve other account"),
            None,
            "a derived id must never address another account's row"
        );
        assert_eq!(
            db.message_id_by_public_id(owner, "msg_00ffffff")
                .expect("resolve missing"),
            None
        );
        assert_eq!(
            db.message_id_by_public_id(owner, "not-an-id")
                .expect("resolve junk"),
            None
        );

        // A stored public id resolves through `api_messages`, and the lifecycle
        // row can be dropped explicitly once the message is gone.
        db.insert_email(&NewEmail {
            account_id: owner,
            message_id: reserved,
            public_id: "eml_0000beef".to_string(),
            status: "queued".to_string(),
            to_addrs: vec!["peer@example.net".to_string()],
            cc_addrs: Vec::new(),
            tags: Vec::new(),
            sandbox: false,
            e2e: "tls_only".to_string(),
            wrapped_key: vec![1, 2, 3],
        })
        .expect("insert lifecycle row");
        assert_eq!(
            db.message_id_by_public_id(owner, "eml_0000beef")
                .expect("resolve stored"),
            Some(reserved)
        );
        assert_eq!(
            db.delete_api_message(reserved).expect("delete lifecycle"),
            1
        );
        assert_eq!(
            db.delete_api_message(reserved).expect("delete twice"),
            0,
            "deleting an already-removed lifecycle row is not an error"
        );
        assert_eq!(
            db.message_id_by_public_id(owner, "eml_0000beef")
                .expect("resolve after delete"),
            None
        );
    }

    #[test]
    fn derived_ids_round_trip() {
        for prefix in [crate::ids::TPL, crate::ids::MSG, crate::ids::ATC] {
            for id in [1_i64, 7, 4096] {
                let public = crate::ids::derived(prefix, id);
                assert_eq!(parse_derived(&public, prefix), Some(id));
            }
        }
        assert_eq!(parse_derived("tpl_not-hex", crate::ids::TPL), None);
        assert_eq!(parse_derived("msg_00000001", crate::ids::TPL), None);
    }

    #[test]
    fn json_lists_round_trip_and_degrade() {
        let items = vec!["a@b.co".to_string(), "c@d.co".to_string()];
        assert_eq!(decode_list(&encode_list(&items)), items);
        assert!(decode_list("not json").is_empty());
        assert!(decode_list("{}").is_empty());
        assert!(decode_list("[]").is_empty());
    }

    #[test]
    fn templates_conflict_on_duplicate_name() {
        let (_dir, db) = fixture();
        db.create_template(1, "welcome", "First contact", "Hi", "<p>hi</p>", "hi")
            .expect("first insert");
        let error = db
            .create_template(1, "welcome", "First contact", "Hi", "<p>hi</p>", "hi")
            .expect_err("duplicate name");
        assert!(matches!(error, store::StoreError::Conflict));
        // A different account may reuse the name.
        db.create_template(2, "welcome", "First contact", "Hi", "<p>hi</p>", "hi")
            .expect("other account");
    }

    #[test]
    fn template_update_and_delete_are_scoped_to_the_account() {
        let (_dir, db) = fixture();
        let id = db
            .create_template(1, "welcome", "First contact", "Hi", "<p>hi</p>", "hi")
            .expect("insert");
        let patch = TemplatePatch {
            subject: Some("Hello".to_string()),
            ..TemplatePatch::default()
        };
        let updated = db
            .update_template(1, id, &patch)
            .expect("update")
            .expect("exists");
        assert_eq!(updated.subject, "Hello");
        assert_eq!(updated.name, "welcome");
        assert_eq!(updated.description, "First contact");
        assert!(db
            .update_template(2, id, &patch)
            .expect("update other account")
            .is_none());
        assert!(!db.delete_template(2, id).expect("delete other"));
        assert!(db.delete_template(1, id).expect("delete"));
        assert!(!db.delete_template(1, id).expect("delete twice"));
    }

    #[test]
    fn suppressions_deduplicate_per_account() {
        let (_dir, db) = fixture();
        let addresses = vec![
            EmailAddress::parse("A@Example.com").expect("address"),
            EmailAddress::parse("a@example.com").expect("address"),
        ];
        assert_eq!(
            db.insert_suppressions(1, &addresses, "manual", None)
                .expect("insert"),
            1,
            "the same address differing only in local-part case is one row"
        );
        assert_eq!(
            db.insert_suppressions(1, &addresses, "manual", None)
                .expect("reinsert"),
            0
        );
        let (rows, total) = db.suppression_page(1, 10, 0).expect("page");
        assert_eq!(total, 1);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].created_at.ends_with('Z'));
        assert!(db.delete_suppression(1, "a@example.com").expect("delete"));
        assert!(!db.delete_suppression(1, "a@example.com").expect("again"));
        assert_eq!(db.suppression_page(1, 10, 0).expect("page").1, 0);
    }

    #[test]
    fn domains_are_unique_per_account_and_keep_their_selector() {
        let (_dir, db) = fixture();
        let first = db
            .upsert_domain("dom_first", 1, "example.com", "pigeon")
            .expect("insert");
        let second = db
            .upsert_domain("dom_second", 1, "example.com", "pigeon")
            .expect("upsert is idempotent");
        assert_eq!(first.public_id, second.public_id);
        assert!(!second.verified);
        assert_eq!(second.dkim_selector, "pigeon");
        assert_eq!(db.list_domains(1).expect("list").len(), 1);
        assert!(db
            .domain_by_public_id(1, &first.public_id)
            .expect("get")
            .is_some());
        assert!(db
            .domain_by_public_id(2, &first.public_id)
            .expect("get")
            .is_none());
    }

    #[test]
    fn webhooks_round_trip_with_their_secret() {
        let (_dir, db) = fixture();
        let events = vec!["email.sent".to_string()];
        let created = db
            .create_webhook(1, "https://example.com/hook", &events, "whsec_x")
            .expect("create");
        assert_eq!(created.secret, "whsec_x");
        assert!(created.public_id.starts_with(crate::ids::WHK));
        let listed = db.list_webhooks(1).expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].events, events);
        assert!(db.delete_webhook(1, &created.public_id).expect("delete"));
        assert!(!db
            .delete_webhook(1, &created.public_id)
            .expect("delete again"));
    }
}
