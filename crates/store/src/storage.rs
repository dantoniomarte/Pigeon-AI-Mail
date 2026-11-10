//! The `Storage` seam (ADR 0002) and its first backend, SQLite.
//!
//! Business code depends on the [`Storage`] trait only; `store-pg`/`store-s3`
//! can land later without touching services. [`SqliteStorage`] is a blocking
//! `rusqlite` connection behind a `Mutex` — SQLite serializes writers anyway,
//! and the API/worker callers are async runtimes that wrap these calls in
//! `spawn_blocking`.
//!
//! **Sealed-body contract.** Nothing in this module ever sees plaintext mail.
//! The service reserves the id with [`Storage::reserve_message_id`], seals the
//! body with AEAD associated data `account:{account_id}:message:{message_id}`,
//! and only then inserts the ciphertext with [`Storage::insert_message`]. Reads
//! return the sealed blob, which the caller opens with the account key and the
//! same AAD. That binding means a blob cannot be replayed onto another account
//! or message id, and [`Storage::insert_message`] refuses anything that is not
//! a versioned sealed envelope.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use pigeon_core::types::{CatchallAction, OrgRole};
use pigeon_core::{ApiKeyScope, Direction, EmailAddress, MessageFolder};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::error::{Result, StoreError};
use crate::migrations;

/// Largest page [`Storage::list_messages`] will return in one call.
pub const MAX_PAGE_LIMIT: i64 = 500;

/// Longest lease [`Storage::queue_claim`] will honour (24 hours).
pub const MAX_LEASE_SECS: u64 = 86_400;

/// Longest session lifetime [`Storage::create_session`] will honour (30 days).
///
/// A caller that asks for more gets the clamp instead of an eternal cookie: the
/// bound is a backstop against a bug that would otherwise mint a session nobody
/// can revoke by expiry.
pub const MAX_SESSION_TTL_SECS: u64 = 30 * 86_400;

/// How long an invitation stays redeemable (7 days).
///
/// Long enough that an invited colleague can accept it after a weekend, short
/// enough that a leaked token is not a permanent key to the organization. The
/// expiry is computed by the database clock (`datetime('now', '+N seconds')`), so
/// it shares the time source of every other row.
pub const INVITATION_TTL_SECS: u64 = 7 * 86_400;

/// Most pending invitations [`Storage::get_invitation_by_token`] will hash.
///
/// A salted Argon2id hash cannot be looked up by equality, so redemption is a
/// verify against each live row. The cap is what keeps a pathological table (a
/// scripted invitation flood) from turning one login into an unbounded KDF sweep;
/// beyond it, older pending invitations are simply not redeemable until the
/// flood is cleaned up.
pub const MAX_INVITATION_SCAN: i64 = 256;

/// Longest trash retention [`Storage::set_trash_retention`] will accept, in days.
///
/// `0` is a valid value and means "keep forever"; the upper bound keeps a typo
/// (`3000` instead of `30`) from being a silent "never delete" and keeps the
/// comparison date SQLite computes well inside its range.
pub const MAX_TRASH_RETENTION_DAYS: i64 = 365;

/// Characters a base64url alphabet uses (RFC 4648 §5, no padding).
const B64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// `(account_id, phc_hash, scopes)` as returned by
/// [`Storage::find_api_key_by_prefix`].
pub type ApiKeyLookup = (i64, String, Vec<ApiKeyScope>);

/// `(kind, detail, created_at)` as returned by [`Storage::list_events`].
pub type EventEntry = (String, String, String);

/// Sentinel status of a listed row that no longer decodes (see
/// [`Storage::list_messages`]). It is never written by this crate.
const STATUS_CORRUPT_ROW: &str = "corrupt_row";

/// Address reported in place of one that no longer parses. `.invalid` is
/// reserved by RFC 2606, so it can never collide with a real mailbox.
const PLACEHOLDER_ADDRESS: &str = "corrupt@row.invalid";

/// One stored message. `sealed_body` is empty in [`Storage::list_messages`]
/// results (bodies are only loaded on demand).
///
/// `status` is `stored` for a row this crate wrote. A `corrupt_row` status is
/// the read-side sentinel described in [`Storage::list_messages`]: the id and
/// account are trustworthy, everything else is a placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRow {
    pub id: i64,
    pub account_id: i64,
    pub direction: Direction,
    pub from_addr: EmailAddress,
    pub to_addrs: Vec<EmailAddress>,
    pub subject: String,
    pub sealed_body: Vec<u8>,
    pub status: String,
    pub created_at: String,
    /// Mailbox folder. A stored value outside the closed set is read back as
    /// [`MessageFolder::Inbox`] (with a warning) instead of failing the page: a
    /// hand-edited folder must not make a mailbox unreadable.
    pub folder: MessageFolder,
    /// When the message was read; `None` is unread.
    pub read_at: Option<String>,
    /// The address this copy was delivered *for*, when it is not the mailbox's
    /// own: a sender alias (`sales@example.com`) or the catch-all local part the
    /// sender wrote. `None` is ordinary mail addressed to the account. The folder
    /// stays `inbox`; this column is what the webmail groups by.
    pub delivered_for: Option<String>,
}

/// A message waiting to be written, handed to [`Storage::insert_message`]
/// together with the id reserved for it.
///
/// The mailbox folder is not a field here: it follows [`Self::direction`], so
/// an outbound message is stored in `sent` and an inbound one in `inbox`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMessage {
    pub account_id: i64,
    pub direction: Direction,
    pub from_addr: EmailAddress,
    pub to_addrs: Vec<EmailAddress>,
    pub subject: String,
    /// Versioned sealed envelope (`0x01 || nonce || ciphertext || tag`) bound
    /// to the reserved id as AAD. Plaintext is rejected with
    /// [`StoreError::InvalidSealedBody`].
    pub sealed_body: Vec<u8>,
    /// Optional client-supplied deduplication key. It is unique **per
    /// account**: replaying the same key returns the id of the row already
    /// stored instead of inserting a second message.
    pub idempotency_key: Option<String>,
    /// Address this copy is delivered for, when it is not the account's own (an
    /// alias or a catch-all recipient). `None` is ordinary mail.
    pub delivered_for: Option<String>,
}

/// A queue row won by [`Storage::queue_claim`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedJob {
    pub id: i64,
    pub message_id: i64,
    /// Opaque ownership token: the only proof accepted by
    /// [`Storage::queue_complete`] and [`Storage::queue_fail`].
    pub claim_token: String,
    /// Delivery attempts so far, including this one.
    pub attempts: i64,
    /// Worker that took the claim ([`Storage::queue_claim`]'s `worker_id`),
    /// kept in the row for observability.
    pub claimed_by: String,
    /// Recipient domains an earlier attempt already delivered to (lowercased).
    ///
    /// Delivery is per recipient domain, so a retry must skip these: delivering
    /// again would put a duplicate copy in somebody's inbox. Empty on a first
    /// attempt and on every row that predates migration `0017`.
    pub delivered_domains: Vec<String>,
}

/// A job that exhausted its attempts and will not be claimed again, as
/// returned by [`Storage::list_dead`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadJob {
    pub message_id: i64,
    /// Last delivery error, empty when the failing worker reported none.
    pub last_error: String,
    pub attempts: i64,
}

/// A stored message template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateRow {
    pub id: i64,
    pub account_id: i64,
    pub name: String,
    /// Short human description, empty when the template was stored without one.
    pub description: String,
    pub subject_tpl: String,
    pub html_tpl: String,
    pub text_tpl: String,
    pub updated_at: String,
}

/// One saved-but-not-sent email draft, as returned by [`Storage::get_draft`]
/// and [`Storage::list_drafts`].
///
/// A draft is *editable* content, so unlike [`MessageRow`] it carries plaintext
/// bodies and a plain recipient list. Nothing here is sealed: drafts live in
/// their own table (migration `0007`), and the send path is what seals a body
/// and writes the delivery record.
#[derive(Debug, Clone, PartialEq)]
pub struct DraftRow {
    pub id: i64,
    pub account_id: i64,
    /// Public `drf_…` id the API handed out at creation.
    pub public_id: String,
    pub from_addr: String,
    pub to_addrs: Vec<String>,
    pub cc_addrs: Vec<String>,
    pub bcc_addrs: Vec<String>,
    pub subject: Option<String>,
    pub body_html: Option<String>,
    pub body_text: Option<String>,
    /// Attachment JSON exactly as the API received it (`filename`, base64
    /// `content`, optional `content_id`). Kept opaque here: `store` never
    /// interprets a draft body, and the send path revalidates the shape.
    pub attachments: Vec<serde_json::Value>,
    pub tags: Vec<String>,
    pub updated_at: String,
}

/// Draft contents to write, handed to [`Storage::create_draft`] and
/// [`Storage::update_draft`].
///
/// This is the *whole* editable state of a draft: an update replaces every
/// field, which is what "save what the compose box shows" means. The API
/// builds it from a partial patch by reading the existing row first.
#[derive(Debug, Clone, PartialEq)]
pub struct NewDraft {
    pub from_addr: String,
    pub to_addrs: Vec<String>,
    pub cc_addrs: Vec<String>,
    pub bcc_addrs: Vec<String>,
    pub subject: Option<String>,
    pub body_html: Option<String>,
    pub body_text: Option<String>,
    pub attachments: Vec<serde_json::Value>,
    pub tags: Vec<String>,
}

/// A live dashboard/webmail session, as returned by
/// [`Storage::get_session_by_id`].
///
/// `token_hash` is the Argon2id PHC hash of the cookie value; the token itself
/// is never stored. Rows that are revoked or past `expires_at` are not returned
/// at all, so "no row" is the single answer to "is this cookie live?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    pub id: String,
    pub account_id: i64,
    pub token_hash: String,
    pub created_at: String,
    /// SQLite `datetime('now')` form (`YYYY-MM-DD HH:MM:SS`), already
    /// normalized so expiry is a plain string comparison.
    pub expires_at: String,
}

/// The TOTP state of one account, as returned by
/// [`Storage::get_totp_enrollment`].
///
/// `confirmed == false` means an enrollment is in progress (the secret is
/// stored but login does not challenge for a code yet). `last_used_step` is the
/// anti-replay counter: the crypto crate verifies a code statelessly, and the
/// service must persist which RFC 6238 step it accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpEnrollmentRow {
    pub account_id: i64,
    /// TOTP secret sealed under the master key, AAD `totp:{account_id}`.
    pub secret_wrapped: Vec<u8>,
    pub confirmed: bool,
    /// Last accepted TOTP step (`unix_time / 30`); `None` before the first use.
    pub last_used_step: Option<i64>,
    /// Argon2id PHC hashes of the unused recovery codes, in issuance order.
    /// Plaintext codes never reach this layer.
    pub recovery_codes: Vec<String>,
    pub enrolled_at: Option<String>,
}

/// One organization (company/team) that owns a set of accounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgRow {
    pub id: i64,
    pub name: String,
    pub created_at: String,
}

/// One account as seen from its organization: the member list row.
///
/// `org_id == None` is the personal workspace (an account that belongs to no
/// organization), which is what every account created by the installer and every
/// account that predates migration `0009` keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgAccountRow {
    pub account_id: i64,
    pub org_id: Option<i64>,
    pub email: String,
    /// Human name; empty means "show the address".
    pub display_name: String,
    pub role: OrgRole,
    pub created_at: String,
}

/// One invitation to join an organization, as returned by
/// [`Storage::list_invitations`] and [`Storage::get_invitation_by_token`].
///
/// The token hash is deliberately **not** part of this row: nothing above the
/// store ever needs it, and a listing that carried it would be one `Debug` print
/// away from leaking hashes into a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationRow {
    pub id: i64,
    pub org_id: i64,
    /// Invited address, normalized (`local` folded, domain lowercase).
    pub email: String,
    /// Role granted on acceptance. Never `owner`: ownership moves by changing an
    /// existing member's role, not by invitation.
    pub role: OrgRole,
    pub invited_by: i64,
    pub created_at: String,
    /// SQLite `datetime('now')` form; past it the invitation is not redeemable.
    pub expires_at: String,
    /// Set when redeemed. A second redemption is refused, so this is the burn
    /// marker as much as it is history.
    pub accepted_at: Option<String>,
}

impl InvitationRow {
    /// True when the invitation can still be redeemed.
    pub fn is_pending(&self) -> bool {
        self.accepted_at.is_none()
    }
}

/// One catch-all rule for an inbound domain.
///
/// The rule is the **domain-level decision** only (`route` or `discard`). Who
/// receives a routed copy lives in [`CatchallAssignmentRow`], separately, because
/// several accounts may hold the same catch-all and each may pause its own copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchallRuleRow {
    pub id: i64,
    /// Lowercased domain the rule applies to.
    pub domain: String,
    pub action: CatchallAction,
    pub created_at: String,
}

/// One account holding the catch-all of a domain, with its own pause switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchallAssignmentRow {
    pub id: i64,
    /// Lowercased domain the catch-all belongs to.
    pub domain: String,
    pub account_id: i64,
    pub assigned_by: i64,
    /// `true` suspended this member's copy; the domain keeps routing to the
    /// others. Only the member may pause, and an admin may force a resume.
    pub paused: bool,
    pub created_at: String,
}

/// One sender alias: a secondary address on a served domain that owns no
/// mailbox of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderAliasRow {
    pub id: i64,
    /// Normalized address (`local` folded, domain lowercase).
    pub address: String,
    /// Lowercased domain half of [`Self::address`].
    pub domain: String,
    pub created_by: i64,
    pub created_at: String,
}

/// One account that may send as an alias and receives a copy of its mail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasAssignmentRow {
    pub alias_id: i64,
    pub account_id: i64,
    pub assigned_by: i64,
    pub created_at: String,
}

/// One account's OpenPGP identity (layer 3).
///
/// `private_sealed` is the transferable secret key **sealed under the master
/// key** (AAD `pgp:{account_id}`); this crate stores ciphertext and never sees
/// plaintext key material, exactly like `dkim_keys`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgpKeyRow {
    pub account_id: i64,
    /// Armored public certificate, as WKD publishes it.
    pub public_armored: String,
    /// Sealed transferable secret key.
    pub private_sealed: Vec<u8>,
    /// Uppercase hex fingerprint of the primary key.
    pub fingerprint: String,
    pub created_at: String,
}

/// A key discovered at another domain and **pinned** on first contact.
///
/// Deliberately only the public half plus the fingerprint: a peer's private key
/// never exists here, so `pgp_keys` is the only table with secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgpPeerKeyRow {
    /// Normalized address the pin belongs to.
    pub email_norm: String,
    pub fingerprint: String,
    pub public_armored: String,
    /// Where the key was found (`pigeon-pgp`, `wkd-advanced`, `local`), for the
    /// audit trail.
    pub source: String,
    pub first_seen_at: String,
    pub last_seen_at: String,
    /// Verdict of the last re-check against the live endpoint: `None` means
    /// pinned and not re-checked yet, `Some("match")` a confirmation, and
    /// `Some("mismatch:<fingerprint>")` the warning an operator must see.
    ///
    /// Separate from [`Self::last_checked_at`] on purpose: one answers "what
    /// happened", the other "when", and merging them made the timestamp
    /// unreadable.
    pub pin_status: Option<String>,
    /// When the endpoint was last re-read (SQLite `datetime('now')`), or `None`.
    pub last_checked_at: Option<String>,
}

/// Persistence contract used by services (ADR 0002 point 2).
pub trait Storage {
    /// Insert an account; duplicate email is [`StoreError::Conflict`].
    ///
    /// An address a **sender alias** already owns is
    /// [`StoreError::AliasShadow`], checked in the same transaction as the insert:
    /// the two unique indexes (`accounts.email_norm`, `sender_aliases.address`)
    /// cannot span each other, so without this guard a member mailbox could take
    /// an alias address and divert its mail.
    fn create_account(&self, account: &EmailAddress) -> Result<i64>;

    /// Load an account, or [`StoreError::NotFound`].
    fn get_account(&self, id: i64) -> Result<(i64, EmailAddress)>;

    /// Find an account id by its normalized address (`local@domain`, lowercased
    /// local part), the form `accounts.email_norm` stores.
    ///
    /// `None` for an unknown address, never an error: the login handler must be
    /// able to answer "no such account" with the same problem document it uses
    /// for a wrong code, without a storage failure leaking the distinction.
    fn get_account_by_email(&self, email_norm: &str) -> Result<Option<i64>>;

    /// Store an API key (PHC hash, never the key itself).
    fn put_api_key(
        &self,
        account_id: i64,
        name: &str,
        key_prefix: &str,
        phc_hash: &str,
        scopes: &[ApiKeyScope],
    ) -> Result<i64>;

    /// Load every live (non-revoked) key for `prefix`, newest first.
    ///
    /// All candidates are returned, not just one: the plaintext key is not
    /// stored, so the caller must verify the presented key against each stored
    /// hash. Collapsing to a single row would let a colliding prefix shadow the
    /// real key and would hide the duplicate from operators.
    fn find_api_key_by_prefix(&self, prefix: &str) -> Result<Vec<ApiKeyLookup>>;

    /// Reserve the next message id so the body can be sealed with it as AAD.
    ///
    /// The reservation is a write, not a read: it takes the `IMMEDIATE` write
    /// lock, bumps `sqlite_sequence` for `messages` and returns the bumped
    /// value. The following [`Storage::insert_message`] writes that exact id
    /// (`INSERT ... (id) VALUES (?1)`), so the id the caller sealed the body
    /// with and the id the row receives cannot diverge by construction: the row
    /// either carries the reserved id or does not exist. If the caller never
    /// inserts, the id is simply skipped — `AUTOINCREMENT` never reissues a
    /// value — so a sealed blob can never end up bound to a different message.
    fn reserve_message_id(&self) -> Result<i64>;

    /// Insert `message` under the id returned by
    /// [`Storage::reserve_message_id`]; returns the row id.
    ///
    /// The body must already be sealed. A blob that is shorter than
    /// [`pigeon_crypto::MIN_BLOB_LEN`] or whose version byte is not
    /// [`pigeon_crypto::ENVELOPE_VERSION`] is rejected with
    /// [`StoreError::InvalidSealedBody`], so plaintext cannot land in the
    /// database through this seam.
    ///
    /// When `message.idempotency_key` matches a row already stored for the same
    /// account, that existing id is returned and nothing is inserted.
    fn insert_message(&self, message: NewMessage, reserved_id: i64) -> Result<i64>;

    /// Load one message including its sealed body.
    ///
    /// Unlike [`Storage::list_messages`] this is strict: a row whose columns no
    /// longer decode is [`StoreError::Corrupt`], because a caller that asked
    /// for one message must learn it is unreadable.
    fn get_message(&self, id: i64) -> Result<MessageRow>;

    /// Page through an account's messages, newest first, without bodies.
    ///
    /// `limit` is clamped into `1..=MAX_PAGE_LIMIT`, so a caller cannot ask for
    /// an unbounded page by accident and an out-of-range value (`0`, a negative
    /// number, or something huge) degrades to the nearest bound instead of
    /// failing a mailbox listing.
    ///
    /// A single row that no longer decodes (hand-edited file, half-written
    /// legacy data) is reported as a `corrupt_row` placeholder with its id,
    /// account and creation time intact, instead of failing the whole page: one
    /// damaged row must not make an account's mailbox unreadable.
    ///
    /// Every folder is included; use [`Storage::list_folder`] for one folder.
    fn list_messages(&self, account_id: i64, limit: i64, offset: i64) -> Result<Vec<MessageRow>>;

    /// Page one folder of one account, newest first, without bodies.
    ///
    /// Same clamping and corruption discipline as [`Storage::list_messages`].
    /// This is what the mailbox UI lists: an inbox page must never be polluted
    /// by sent or trashed rows.
    fn list_folder(
        &self,
        account_id: i64,
        folder: MessageFolder,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<MessageRow>>;

    /// Move a message to a folder. Returns [`StoreError::NotFound`] when no such
    /// message exists, so a caller cannot silently "move" nothing.
    fn set_message_folder(&self, message_id: i64, folder: MessageFolder) -> Result<()>;

    /// Mark a message read (stamp `read_at`) or unread (clear it). Read state is
    /// idempotent: re-reading an already-read message keeps the original
    /// timestamp, so "when did they first read it" stays truthful.
    fn set_message_read(&self, message_id: i64, read: bool) -> Result<()>;

    /// Hard-delete one message row (attachments, events and queue rows follow
    /// through `ON DELETE CASCADE`). Only used for an explicit delete or a trash
    /// purge; ordinary removal from the inbox is a folder move.
    fn delete_message(&self, message_id: i64) -> Result<()>;

    /// Delete every message of `account_id` in `folder`; returns the number of
    /// rows removed. Only meaningful for `trash`, which is what the API exposes.
    fn empty_folder(&self, account_id: i64, folder: MessageFolder) -> Result<usize>;

    /// Number of messages of `account_id` in `folder`, for the sidebar badges.
    fn count_folder(&self, account_id: i64, folder: MessageFolder) -> Result<i64>;

    /// Total and unread count of `account_id`'s `folder`, as `(total, unread)`.
    ///
    /// The webmail shows one badge per folder: the folder's size and, separately,
    /// how much of it is still unread. Both halves come from the same query so a
    /// badge can never disagree with itself, and `unread` follows the same rule as
    /// [`Storage::set_message_read`]: a row is unread while `read_at` is `NULL`.
    ///
    /// Outbound copies live in `sent` and are never unread (the webmail never
    /// opens them), so callers reporting that folder use only the total.
    fn count_folder_with_unread(
        &self,
        account_id: i64,
        folder: MessageFolder,
    ) -> Result<(i64, i64)>;

    /// One page of the inbox that was delivered **for** `delivered_for` (an alias
    /// or a catch-all local part), newest first.
    ///
    /// This is the webmail's pseudo-folder listing. It is deliberately a filter on
    /// `inbox` and not a folder of its own: the message stays where the delivery
    /// put it, and revoking an alias never orphans mail in a synthetic folder.
    fn list_delivered_for(
        &self,
        account_id: i64,
        delivered_for: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<MessageRow>>;

    /// How many inbox messages were delivered for `delivered_for`.
    fn count_delivered_for(&self, account_id: i64, delivered_for: &str) -> Result<i64>;

    /// Every `delivered_for` marker the account holds, with its inbox count, so
    /// the webmail can render one pseudo-folder per shared address.
    fn delivered_for_counts(&self, account_id: i64) -> Result<Vec<(String, i64)>>;

    // ------------------------------------------------------- trash retention

    /// How long a trashed message survives, in days (`0` = keep forever).
    ///
    /// [`StoreError::NotFound`] for an unknown account: a settings read must not
    /// answer with the column default of an account that does not exist.
    fn get_trash_retention(&self, account_id: i64) -> Result<i64>;

    /// Set the trash retention window for `account_id`.
    ///
    /// `days` must be `0..=MAX_TRASH_RETENTION_DAYS`. The API validates the same
    /// range; the store refuses it as well ([`StoreError::InvalidArgument`]) so no
    /// caller can persist a value the API would have to reject on read.
    /// [`StoreError::NotFound`] for an unknown account.
    fn set_trash_retention(&self, account_id: i64, days: i64) -> Result<()>;

    /// Permanently delete the account's trash rows older than its retention
    /// window; returns how many rows were removed.
    ///
    /// "Older" is measured on `messages.trashed_at`, the stamp
    /// [`Storage::set_message_folder`] writes on entry to the trash, so the clock
    /// starts when the message was thrown away — not when it arrived. Only the
    /// `trash` folder is ever touched: an inbox, sent or spam row cannot be
    /// purged by this path even if it carries a stale stamp.
    ///
    /// A retention of `0` (keep forever) deletes nothing, and a row in the trash
    /// without a `trashed_at` (written before migration `0012`) is kept: no
    /// countdown ever started for it.
    fn purge_expired_trash(&self, account_id: i64) -> Result<usize>;

    /// Number of messages currently in the account's trash folder.
    fn count_trash(&self, account_id: i64) -> Result<i64> {
        self.count_folder(account_id, MessageFolder::Trash)
    }

    /// Every account whose trash retention is enabled (`> 0`), oldest first.
    ///
    /// The purge worker's work list: accounts that chose "keep forever" are not
    /// returned, so the worker never has to re-read a policy it would not act on.
    fn accounts_with_trash_purge(&self) -> Result<Vec<i64>>;

    /// Add a delivery job that becomes due at `run_after_unix`.
    fn queue_enqueue(&self, message_id: i64, run_after_unix: i64) -> Result<i64>;

    /// Atomically claim the next due job, if any.
    ///
    /// `worker_id` labels the claimant for observability and is stored in
    /// `claimed_by`; the returned opaque token — not the worker id — is what
    /// `complete`/`fail` verify, so a restarted worker can still finish a job it
    /// claimed before the restart.
    ///
    /// `lease_secs` is clamped to [`MAX_LEASE_SECS`]. Lease expiry is compared
    /// with a strict `<`: a claim taken at second `T` becomes reclaimable once
    /// `unixepoch() > T + lease_secs`, so the effective lease is the requested
    /// value rounded **up** to the next whole second (`+1s`). That bias is
    /// deliberate — a claim is never stolen one second early.
    ///
    /// Jobs with `attempts >= max_attempts` or `status = 'dead'` are never
    /// handed out again. A successful claim sets `claimed_at`, `claim_token`,
    /// `claimed_by`, increments `attempts` and clears `last_error`.
    fn queue_claim(&self, worker_id: &str, lease_secs: u64) -> Result<Option<ClaimedJob>>;

    /// Drop a finished job. A token that no longer owns a job is rejected with
    /// [`StoreError::QueueClaim`] rather than silently ignored.
    fn queue_complete(&self, claim_token: &str) -> Result<()>;

    /// Release a claimed job after a failed attempt.
    ///
    /// The error is recorded and the claim token cleared. If this attempt
    /// reached `max_attempts` the job becomes `dead` and stops being claimable;
    /// otherwise `run_after` is re-armed `backoff_secs` from now. A token that
    /// does not own a live job — a stale claim another worker already took over
    /// — is [`StoreError::QueueClaim`], never a silent no-op.
    fn queue_fail(&self, claim_token: &str, error: &str, backoff_secs: u64) -> Result<()>;

    /// Record that the live claim already delivered to `domains` (lowercased).
    ///
    /// Called once per attempt, as each recipient-domain group reaches a terminal
    /// verdict, so the next attempt only targets the domains still outstanding.
    /// Empty domain names (a smarthost delivery, which is not domain-scoped) are
    /// ignored: they must never make a retry look complete.
    ///
    /// A token that no longer owns a live claim is [`StoreError::QueueClaim`], so a
    /// worker that lost its lease cannot write to somebody else's job.
    fn queue_mark_domains_delivered(&self, claim_token: &str, domains: &[String]) -> Result<()>;

    /// Dead-lettered jobs, oldest first, for operators and bounce handling.
    fn list_dead(&self, limit: i64) -> Result<Vec<DeadJob>>;

    /// Append a delivery event.
    fn record_event(&self, message_id: i64, kind: &str, detail: &str) -> Result<()>;

    /// Events for a message, oldest first.
    fn list_events(&self, message_id: i64) -> Result<Vec<EventEntry>>;

    /// Append an audit entry (operator/API actions).
    fn audit(&self, actor: &str, action: &str, detail: &str) -> Result<()>;

    /// Store the wrapped TOTP secret (upsert, one per account).
    fn set_totp_secret(&self, account_id: i64, wrapped: &[u8]) -> Result<()>;

    /// Load the wrapped TOTP secret.
    fn get_totp_secret(&self, account_id: i64) -> Result<Option<Vec<u8>>>;

    // ------------------------------------------------------------ sessions

    /// Create a session that expires `ttl_secs` from now and return its stored
    /// expiry stamp (`YYYY-MM-DD HH:MM:SS`, computed by the database clock, so
    /// every row shares one time source).
    ///
    /// `ttl_secs` is clamped to [`MAX_SESSION_TTL_SECS`]. The `id` is the
    /// caller's public session id (it travels inside the cookie so a lookup
    /// needs no hash computation); a duplicate id is
    /// [`StoreError::Conflict`].
    fn create_session(
        &self,
        id: &str,
        account_id: i64,
        token_hash: &str,
        ttl_secs: u64,
    ) -> Result<String>;

    /// Load a session that is neither revoked nor expired.
    ///
    /// Revoked or expired rows are reported as `None` rather than as a row with
    /// a flag: a caller that forgets to check the flag would otherwise
    /// authenticate a dead cookie.
    fn get_session_by_id(&self, id: &str) -> Result<Option<SessionRow>>;

    /// Revoke one session. Revoking an already revoked or unknown session is
    /// [`StoreError::NotFound`], so a double logout is visible instead of a
    /// silent success.
    fn revoke_session(&self, id: &str) -> Result<()>;

    /// Revoke every live session of `account_id` except `except` (usually the
    /// caller's own); returns how many rows were revoked.
    fn revoke_all_account_sessions(&self, account_id: i64, except: Option<&str>) -> Result<usize>;

    // ----------------------------------------------------------- 2fa state

    /// Start (or restart) a TOTP enrollment: store the wrapped secret and reset
    /// confirmation, the replay counter and any recovery codes.
    ///
    /// Restarting is deliberate: re-enrolling must never inherit the
    /// confirmation of a secret that is no longer the stored one.
    fn set_totp_enrollment(&self, account_id: i64, secret_wrapped: &[u8]) -> Result<()>;

    /// Load the account's TOTP state, or `None` when nothing is enrolled.
    fn get_totp_enrollment(&self, account_id: i64) -> Result<Option<TotpEnrollmentRow>>;

    /// Activate an enrollment: mark it confirmed, stamp `enrolled_at`, store the
    /// recovery-code hashes and seed the replay counter with `step`.
    ///
    /// No enrollment row is [`StoreError::NotFound`]: confirming a secret that
    /// was never stored would leave the account unable to log in.
    fn confirm_totp(&self, account_id: i64, recovery_hashes: &[String], step: i64) -> Result<()>;

    /// Advance the anti-replay counter to `step`, atomically.
    ///
    /// Returns `true` when `step` is strictly greater than the stored one (and
    /// is now stored), `false` when it is not — i.e. the code was already spent.
    /// The comparison and the write are one statement, so two concurrent
    /// requests with the same code cannot both succeed.
    fn set_totp_last_step(&self, account_id: i64, step: i64) -> Result<bool>;

    /// Burn the recovery code at `index`, returning whether one was there.
    ///
    /// The list is re-written without that entry, so a code can be spent once
    /// even by two concurrent logins.
    fn burn_recovery_code(&self, account_id: i64, index: usize) -> Result<bool>;

    /// Delete the enrollment (the disable path). Idempotent: disabling an
    /// account that never enrolled does not fail.
    fn revoke_totp(&self, account_id: i64) -> Result<()>;

    /// Create or replace a named template for an account.
    ///
    /// Equivalent to [`Storage::put_template_with_description`] with an empty
    /// description; kept so callers that do not care about the description do
    /// not have to pass one. There is **no cap** on how many templates an
    /// account may hold — a name is unique per account and that is the only
    /// limit.
    fn put_template(
        &self,
        account_id: i64,
        name: &str,
        subject_tpl: &str,
        html_tpl: &str,
        text_tpl: &str,
    ) -> Result<()> {
        self.put_template_with_description(account_id, name, "", subject_tpl, html_tpl, text_tpl)
    }

    /// Create or replace a named template for an account, with a description.
    fn put_template_with_description(
        &self,
        account_id: i64,
        name: &str,
        description: &str,
        subject_tpl: &str,
        html_tpl: &str,
        text_tpl: &str,
    ) -> Result<()>;

    /// Load a template by account + name.
    fn get_template(&self, account_id: i64, name: &str) -> Result<Option<TemplateRow>>;

    /// Insert a draft and return its row id.
    ///
    /// `public_id` is the `drf_…` id the API already handed out; it is unique
    /// across the table, so two accounts can never collide.
    fn create_draft(&self, account_id: i64, public_id: &str, draft: &NewDraft) -> Result<i64>;

    /// Replace a draft's contents and bump `updated_at`.
    ///
    /// Returns `false` when the account has no draft with that public id, which
    /// the API answers with `404` — scoping the lookup by account is what keeps
    /// one account's id from reaching another's draft.
    fn update_draft(&self, public_id: &str, account_id: i64, draft: &NewDraft) -> Result<bool>;

    /// Load one draft, scoped to the account.
    fn get_draft(&self, public_id: &str, account_id: i64) -> Result<Option<DraftRow>>;

    /// One page of an account's drafts, newest first (`updated_at`, then id).
    fn list_drafts(&self, account_id: i64, limit: i64, offset: i64) -> Result<Vec<DraftRow>>;

    /// Total drafts of the account, for pagination metadata.
    fn count_drafts(&self, account_id: i64) -> Result<i64>;

    /// Delete a draft; `false` when the account has no draft with that id.
    fn delete_draft(&self, public_id: &str, account_id: i64) -> Result<bool>;

    /// Create or replace the DKIM signing identity for `domain` (upsert).
    ///
    /// Keys are domain-scoped, not account-scoped: one row per sending domain,
    /// shared by every account that sends as it (see migration `0006`). Re-putting
    /// a domain therefore rotates the existing row instead of creating a second
    /// identity for the same selector.
    ///
    /// `wrapped_private_key` arrives already sealed under the master key — this
    /// crate stores ciphertext and never sees plaintext key material. `public_dns`
    /// is the exact TXT record to publish.
    fn put_dkim_key(
        &self,
        domain: &str,
        selector: &str,
        wrapped_private_key: &[u8],
        public_dns: &str,
    ) -> Result<()>;

    /// Load a domain's DKIM identity as `(selector, wrapped_private_key, public_dns)`.
    ///
    /// `None` means the domain is not managed here. That is a normal state, not
    /// an error: outbound mail for a domain this server does not hold a key for
    /// is delivered unsigned.
    fn get_dkim_key(&self, domain: &str) -> Result<Option<(String, Vec<u8>, String)>>;

    /// Every managed DKIM identity as `(domain, selector, public_dns)`, oldest
    /// first, for the operator listing.
    ///
    /// The wrapped private key is deliberately **not** returned: a listing is for
    /// "which domains can I sign for", and there is no reason to move key
    /// material to answer it.
    fn list_dkim_keys(&self) -> Result<Vec<(String, String, String)>>;

    // -------------------------------------------------------------- orgs

    /// Insert an organization; returns its id. An empty name is
    /// [`StoreError::InvalidArgument`].
    fn create_org(&self, name: &str) -> Result<i64>;

    /// Load one organization, or [`StoreError::NotFound`].
    fn get_org(&self, id: i64) -> Result<OrgRow>;

    /// Every organization, oldest first. This is the operator/master-admin
    /// view; a tenant-facing listing uses [`Storage::list_orgs_for_account`].
    fn list_orgs(&self) -> Result<Vec<OrgRow>>;

    /// Organizations `account_id` is a member of, oldest first.
    fn list_orgs_for_account(&self, account_id: i64) -> Result<Vec<OrgRow>>;

    /// Rename an organization; [`StoreError::NotFound`] when it does not exist.
    fn rename_org(&self, id: i64, name: &str) -> Result<()>;

    /// Delete an organization that no account references.
    ///
    /// [`StoreError::Conflict`] while any account is still a member: deleting the
    /// row would otherwise silently orphan live mailboxes (the FK would set their
    /// `org_id` to NULL, which is a data change nobody asked for). Pending
    /// invitations are deleted with it (`ON DELETE CASCADE`) — they point at a
    /// team that no longer exists.
    fn delete_org(&self, id: i64) -> Result<()>;

    /// The organization an account belongs to and the role it holds there.
    ///
    /// `Ok((None, role))` is the personal workspace. [`StoreError::NotFound`] when
    /// the account does not exist, so an authorization check can never mistake a
    /// missing account for an unprivileged one.
    fn get_account_membership(&self, account_id: i64) -> Result<(Option<i64>, OrgRole)>;

    /// Every account of one organization, oldest first.
    fn list_org_accounts(&self, org_id: i64) -> Result<Vec<OrgAccountRow>>;

    /// Change an account's role inside its organization.
    ///
    /// The **last owner** cannot be demoted: [`StoreError::Conflict`] when no
    /// other owner remains, which is what stops an organization from ending up
    /// with nobody able to administer it. Setting the role an account already
    /// holds is a no-op success.
    fn set_account_role(&self, account_id: i64, role: OrgRole) -> Result<()>;

    /// Set (or clear, with an empty value) an account's display name.
    fn set_account_display_name(&self, account_id: i64, display_name: &str) -> Result<()>;

    /// Create an account that belongs to `org_id` from the start.
    ///
    /// Separate from [`Storage::create_account`] because a member is never a
    /// personal workspace: the organization and the role are part of the insert,
    /// so there is no window in which the account exists without them. Duplicate
    /// email is [`StoreError::Conflict`], unknown organization
    /// [`StoreError::NotFound`], and an address a sender alias already owns is
    /// [`StoreError::AliasShadow`] — the same rule [`Storage::create_account`]
    /// applies, so a member mailbox can never take a shared address.
    fn create_member_account(
        &self,
        email: &EmailAddress,
        display_name: &str,
        org_id: i64,
        role: OrgRole,
    ) -> Result<i64>;

    /// Take every credential of an account away without deleting the row.
    ///
    /// Revokes all its sessions and all its API keys; the account keeps its mail,
    /// its address and its history, so nothing an operator might need to read
    /// disappears. Re-running it revokes nothing further (the statements are
    /// scoped to live rows).
    fn deactivate_account(&self, account_id: i64) -> Result<()>;

    /// Move an account into `org_id` with `role` — the "create an organization and
    /// become its owner" path, and the same primitive a role change uses.
    ///
    /// `None` detaches the account back to a personal workspace. The last-owner
    /// guard applies here too: an owner cannot be moved out of, or demoted inside,
    /// the organization it solely owns ([`StoreError::Conflict`]), because that
    /// would leave a team nobody can administer. An unknown organization is
    /// [`StoreError::NotFound`].
    fn set_account_org(&self, account_id: i64, org_id: Option<i64>, role: OrgRole) -> Result<()>;

    // ------------------------------------------------------- invitations

    /// Create (or replace) the pending invitation for `email` in `org_id` and
    /// return the **plaintext** token — the only time it is available.
    ///
    /// `role` must be `admin` or `member`: ownership is never handed out by
    /// invitation (it is transferred by [`Storage::set_account_role`]), so
    /// `owner` is [`StoreError::InvalidArgument`]. Re-inviting the same address
    /// replaces the pending row in place (`UNIQUE(org_id, email)`), resetting the
    /// token, the expiry and the role, so two live tokens for one seat can never
    /// exist.
    ///
    /// Only the Argon2id hash of the token is stored.
    fn create_invitation(
        &self,
        org_id: i64,
        email: &EmailAddress,
        role: OrgRole,
        invited_by: i64,
    ) -> Result<String>;

    /// The pending, unexpired invitation a plaintext token belongs to.
    ///
    /// `None` for an unknown, expired or already-accepted token — the three cases
    /// are deliberately indistinguishable to the caller. The lookup is a
    /// `verify` against each pending row because a salted Argon2id hash cannot be
    /// searched by equality; the scan is bounded ([`MAX_INVITATION_SCAN`]) and a
    /// deployment has few pending invitations by construction.
    fn get_invitation_by_token(&self, token: &str) -> Result<Option<InvitationRow>>;

    /// Burn `invitation_id` and attach `account_id` to its organization with the
    /// invited role.
    ///
    /// One transaction: the burn and the membership change either both happen or
    /// neither does, so a crash cannot leave a spent token without a membership
    /// or a member without a spent token. An expired or already-accepted
    /// invitation is [`StoreError::Conflict`].
    fn accept_invitation(&self, invitation_id: i64, account_id: i64) -> Result<()>;

    /// Every invitation of an organization, newest first, accepted and expired
    /// ones included so the admin panel can show history instead of only the
    /// pending rows.
    fn list_invitations(&self, org_id: i64) -> Result<Vec<InvitationRow>>;

    /// Delete one invitation, scoped to its organization; `false` when the
    /// organization has no invitation with that id.
    fn delete_invitation(&self, org_id: i64, invitation_id: i64) -> Result<bool>;

    // --------------------------------------------------------- catch-all

    /// Create or replace the catch-all **rule** for `domain` (upsert).
    ///
    /// The domain is the identity, so re-putting replaces the action: two rules
    /// for one domain could only contradict each other. The recipients are
    /// separate rows ([`Storage::assign_catchall`]) and survive an action change:
    /// flipping a domain from `route` to `discard` must not silently forget who
    /// was receiving it. The domain is lowercased here so lookups cannot miss on
    /// case.
    fn set_catchall(&self, domain: &str, action: CatchallAction) -> Result<()>;

    /// The rule for `domain`, or `None` when the domain falls through to the
    /// ordinary `550`.
    fn get_catchall(&self, domain: &str) -> Result<Option<CatchallRuleRow>>;

    /// Every rule, oldest first, for the operator listing.
    fn list_catchalls(&self) -> Result<Vec<CatchallRuleRow>>;

    /// Delete the rule for `domain`; [`StoreError::NotFound`] when there is none,
    /// so a caller cannot believe it disabled a rule that was never there. The
    /// domain's assignments go with it (`ON DELETE` is not applicable here, so
    /// they are deleted in the same transaction): an assignment without a rule
    /// would be a grant that can never fire.
    fn delete_catchall(&self, domain: &str) -> Result<()>;

    /// Give `account_id` a copy of the catch-all mail of `domain`.
    ///
    /// [`StoreError::Conflict`] when the account already holds it (assigning
    /// twice is not two copies), [`StoreError::NotFound`] when the **domain has no
    /// rule** or the account does not exist. The rule check runs before the
    /// insert in the same transaction, so a refused call leaves no row behind: an
    /// assignment whose domain has no rule could never fire.
    fn assign_catchall(&self, domain: &str, account_id: i64, assigned_by: i64) -> Result<()>;

    /// Remove one account's catch-all assignment. Messages already delivered
    /// stay where they are; only future delivery stops.
    fn unassign_catchall(&self, domain: &str, account_id: i64) -> Result<()>;

    /// Set the per-member pause switch. [`StoreError::NotFound`] when the account
    /// does not hold that catch-all.
    fn set_catchall_paused(&self, domain: &str, account_id: i64, paused: bool) -> Result<()>;

    /// The account holding the catch-all of `domain`, or `None`.
    fn get_catchall_assignment(
        &self,
        domain: &str,
        account_id: i64,
    ) -> Result<Option<CatchallAssignmentRow>>;

    /// Every assignment of one domain, oldest first.
    fn catchall_assignees(&self, domain: &str) -> Result<Vec<CatchallAssignmentRow>>;

    /// Every assignment, oldest first (the admin listing).
    fn list_catchall_assignments(&self) -> Result<Vec<CatchallAssignmentRow>>;

    /// The catch-alls one account holds, for its own view and for the pause
    /// self-service.
    fn catchall_assignments_for_account(
        &self,
        account_id: i64,
    ) -> Result<Vec<CatchallAssignmentRow>>;

    // ----------------------------------------------------- sender aliases

    /// Create a sender alias for an address on a **served** domain.
    ///
    /// Refusals, all [`StoreError::InvalidArgument`] except the collision:
    ///
    /// * the address already belongs to an account — an alias must never shadow
    ///   a mailbox, or mail would be copied instead of delivered;
    /// * the address is another alias ([`StoreError::Conflict`]);
    /// * the domain is not served by this deployment (no account and no DKIM key
    ///   on it), because an alias on a foreign domain could never receive mail.
    fn create_alias(&self, address: &EmailAddress, created_by: i64) -> Result<i64>;

    /// Delete an alias and every assignment to it; [`StoreError::NotFound`] when
    /// there is none. Messages already delivered stay in their mailboxes.
    fn delete_alias(&self, alias_id: i64) -> Result<()>;

    /// Every alias, oldest first.
    fn list_aliases(&self) -> Result<Vec<SenderAliasRow>>;

    /// The alias with this address, if one exists (lowercase comparison).
    fn get_alias_by_address(&self, address: &str) -> Result<Option<SenderAliasRow>>;

    /// The alias with this id, if one exists.
    fn get_alias(&self, alias_id: i64) -> Result<Option<SenderAliasRow>>;

    /// Let `account_id` send as the alias and receive a copy of its mail.
    /// [`StoreError::Conflict`] when already assigned, [`StoreError::NotFound`]
    /// when the alias or the account does not exist.
    fn assign_alias(&self, alias_id: i64, account_id: i64, assigned_by: i64) -> Result<()>;

    /// Stop future delivery and sending for one account; delivered mail stays.
    fn unassign_alias(&self, alias_id: i64, account_id: i64) -> Result<()>;

    /// The aliases whose holder is `account_id` (the compose-box list).
    fn aliases_for_account(&self, account_id: i64) -> Result<Vec<SenderAliasRow>>;

    /// Every account holding the alias with this address.
    fn accounts_for_alias(&self, address: &str) -> Result<Vec<i64>>;

    /// The assignments of one alias, oldest first.
    fn alias_assignments(&self, alias_id: i64) -> Result<Vec<AliasAssignmentRow>>;

    /// True when the address belongs to an account **or** to an alias, which is
    /// the collision rule of both surfaces.
    fn is_address_taken(&self, address: &str) -> Result<bool>;

    /// Domains this deployment serves: the domains of its accounts, plus the ones
    /// it holds a DKIM identity for. An address on any other domain can neither
    /// receive nor send here.
    fn served_domains(&self) -> Result<Vec<String>>;

    // ------------------------------------------------- layer-3 OpenPGP keys

    /// Store an account's OpenPGP identity **only if it has none yet**.
    ///
    /// Returns `true` when this call created the row and `false` when a key was
    /// already there. That is the race-free first-use primitive: two concurrent
    /// first uses generate candidates, exactly one wins, and the loser re-reads the
    /// winner's row instead of overwriting it — so an account never ends up with
    /// two identities (one published, one stored, mail sealed to the wrong one).
    ///
    /// Rotation is a different operation and uses [`Storage::put_pgp_key`].
    fn insert_pgp_key_if_absent(
        &self,
        account_id: i64,
        public_armored: &str,
        private_sealed: &[u8],
        fingerprint: &str,
    ) -> Result<bool>;

    /// Create or replace an account's OpenPGP identity (upsert on `account_id`).
    ///
    /// `private_sealed` arrives already sealed under the master key; this crate
    /// never sees the plaintext secret key. Re-putting rotates the row in place,
    /// which is what a deliberate key rotation does — and why nothing else may
    /// write this table.
    fn put_pgp_key(
        &self,
        account_id: i64,
        public_armored: &str,
        private_sealed: &[u8],
        fingerprint: &str,
    ) -> Result<()>;

    /// Load an account's OpenPGP identity, or `None` when it has none yet.
    ///
    /// `None` is a normal state: keys are generated lazily on first use (first
    /// WKD publication or first sealed send), so an account that never sent or
    /// received sealed mail has no row.
    fn get_pgp_key(&self, account_id: i64) -> Result<Option<PgpKeyRow>>;

    /// The published key for one address, whoever asks.
    ///
    /// This is what WKD serves: `(public_armored, fingerprint)`. `None` when the
    /// address is not a local account here — a sender alias owns no key, because
    /// it has several owners and sealing to one of them would be a lie.
    fn get_pgp_public_by_email(&self, email_norm: &str) -> Result<Option<(String, String)>>;

    /// Pin a peer key, or refresh an existing pin.
    ///
    /// The first call for an address is the trust decision. Later calls **never**
    /// change the stored key: they only update `last_checked_at` with the result
    /// of the comparison (`match` or `mismatch:<fingerprint>`), so a replaced
    /// foreign key is reported instead of silently followed.
    fn pin_pgp_peer_key(
        &self,
        email_norm: &str,
        fingerprint: &str,
        public_armored: &str,
        source: &str,
    ) -> Result<()>;

    /// The current pin for an address, if any.
    fn get_pgp_peer_key(&self, email_norm: &str) -> Result<Option<PgpPeerKeyRow>>;

    /// Delete the pin for an address; `true` when a row was removed.
    ///
    /// The operator's recovery path (issue found in review): a peer that rotates
    /// its key keeps serving a pin this server will not follow, so sealed mail is
    /// produced that the recipient cannot open. Removing the pin re-runs trust on
    /// first use, which is exactly as safe as the first contact was — the caller
    /// takes responsibility for having verified the new key out of band.
    fn delete_pgp_peer_key(&self, email_norm: &str) -> Result<bool>;

    /// Every account whose address is on `domain`, as `(account_id, address)`.
    ///
    /// The advanced WKD lookup arrives with a domain and a hash instead of an
    /// address, so publication needs "who is on this domain" to find the row the
    /// hash names.
    fn accounts_on_domain(&self, domain: &str) -> Result<Vec<(i64, EmailAddress)>>;
}

/// Claim statement, kept in one place so the tests can `EXPLAIN QUERY PLAN` the
/// exact SQL that production runs.
///
/// Parameters: `?1` new claim token, `?2` worker id, `?3` lease in seconds.
///
/// `unixepoch()` (not `strftime('%s','now')`) keeps every queue timestamp in
/// integer seconds; string round-trips through `strftime` are how lease
/// comparisons drift.
///
/// The subquery and the `UPDATE` are one statement, so a claim is atomic across
/// every worker process sharing the file. The index chosen for it is asserted
/// by `queue_claim_uses_the_live_index`.
///
/// The candidate read is split into two `UNION ALL` branches on purpose. A
/// single `WHERE claim_token IS NULL OR claimed_at < ...` is an `OR` across two
/// different columns, which SQLite cannot turn into an index seek and answers by
/// scanning `queue` on every poll. Each branch instead has one constraint shape
/// that `idx_queue_claim (claim_token, claimed_at, run_after)` can seek:
///
/// * `claim_token IS NULL AND claimed_at IS NULL` pins the index prefix to
///   equality, so the `run_after` bound and the ordering come from the index;
/// * `claim_token > '' AND claimed_at < cutoff` is a range on the leading
///   column plus the lease column, which the index also searches. `> ''` is
///   the seekable spelling of `IS NOT NULL`: claim tokens come from
///   [`new_claim_token`] and are never empty.
///
/// The two branches are disjoint (a row either has a token or does not), so
/// `UNION ALL` adds no duplicate handling cost.
pub(crate) const QUEUE_CLAIM_SQL: &str = "\
UPDATE queue
   SET claim_token = ?1,
       claimed_at = unixepoch(),
       attempts = attempts + 1,
       claimed_by = ?2,
       last_error = NULL
 WHERE id = (
       SELECT id FROM (
            SELECT id, run_after FROM queue
             WHERE claim_token IS NULL
               AND claimed_at IS NULL
               AND run_after <= unixepoch()
               AND status <> 'dead'
               AND attempts < max_attempts
            UNION ALL
            SELECT id, run_after FROM queue
             WHERE claim_token > ''
               AND claimed_at < unixepoch() - ?3
               AND run_after <= unixepoch()
               AND status <> 'dead'
               AND attempts < max_attempts
       )
        ORDER BY run_after, id
        LIMIT 1)
RETURNING id, message_id, claim_token, attempts, claimed_by, delivered_domains";

/// SQLite-backed [`Storage`].
pub struct SqliteStorage {
    conn: Mutex<Connection>,
}

impl SqliteStorage {
    /// Open (or create) the database at `path`, apply PRAGMAs and migrations.
    ///
    /// Durability profile from ADR 0002: WAL for reader/writer concurrency,
    /// `synchronous=FULL` because a lost queue row is a lost email, and
    /// `foreign_keys=ON` so child rows cannot outlive their account/message.
    ///
    /// Safe to call from several processes at once: the busy timeout absorbs
    /// the migration write lock instead of failing with "database is locked".
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut conn = Connection::open(path)?;
        // Multi-process claims share the file; wait rather than fail on lock.
        conn.busy_timeout(Duration::from_secs(5))?;
        enable_wal(&conn)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        migrations::apply(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Lock the connection. A panic in another holder poisons the mutex; the
    /// SQLite connection itself is still usable (every statement is its own
    /// transaction), so recover instead of cascading the panic.
    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Raw connection access for tests that must simulate states the API
    /// cannot reach yet (e.g. revoking a key — v1 has no revoke method).
    #[cfg(test)]
    pub(crate) fn raw_conn(&self) -> MutexGuard<'_, Connection> {
        self.lock()
    }
}

/// Encode recipients as a JSON array for the `to_addrs` column.
///
/// JSON instead of a comma-joined string: the type has no separator character
/// to get wrong, an address containing a `,` or a `"` can never be re-split
/// into two addresses on read, and corrupt content fails loudly (`serde_json`
/// rejects it) instead of silently becoming a shorter recipient list.
fn encode_addrs(addrs: &[EmailAddress]) -> Result<String> {
    let raw: Vec<String> = addrs.iter().map(ToString::to_string).collect();
    serde_json::to_string(&raw).map_err(|error| {
        StoreError::InvalidArgument(format!("could not encode recipients as JSON: {error}"))
    })
}

/// Decode the JSON array written by [`encode_addrs`]. Anything else is
/// [`StoreError::Corrupt`]: the row exists but cannot be trusted.
fn decode_addrs(raw: &str) -> Result<Vec<EmailAddress>> {
    let raw: Vec<String> = serde_json::from_str(raw).map_err(|error| {
        StoreError::Corrupt(format!("messages.to_addrs is not a JSON array: {error}"))
    })?;
    raw.iter()
        .map(|addr| EmailAddress::parse(addr))
        .collect::<pigeon_core::Result<Vec<_>>>()
        .map_err(StoreError::from)
}

/// Columns [`SqliteStorage::get_draft`] and [`SqliteStorage::list_drafts`]
/// select, in the order [`map_draft`] reads them. Kept in one place so the two
/// queries cannot drift apart.
const DRAFT_SELECT: &str = "\
SELECT id, account_id, public_id, from_addr, to_addrs, cc_addrs, bcc_addrs, \
       subject, body_html, body_text, attachments, tags, updated_at \
  FROM drafts";

/// Columns [`DRAFT_SELECT`] selects, mapped by [`map_raw_draft`] before the
/// fallible JSON decoding of [`decode_draft`].
struct RawDraft {
    id: i64,
    account_id: i64,
    public_id: String,
    from_addr: String,
    to_addrs: String,
    cc_addrs: String,
    bcc_addrs: String,
    subject: Option<String>,
    body_html: Option<String>,
    body_text: Option<String>,
    attachments: String,
    tags: String,
    updated_at: String,
}

/// Map a [`DRAFT_SELECT`] row onto [`RawDraft`].
///
/// Only column typing happens here; the JSON columns are decoded afterwards, in
/// [`decode_draft`], because a `rusqlite::Result` mapper cannot report a
/// [`StoreError`].
fn map_raw_draft(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawDraft> {
    Ok(RawDraft {
        id: row.get(0)?,
        account_id: row.get(1)?,
        public_id: row.get(2)?,
        from_addr: row.get(3)?,
        to_addrs: row.get(4)?,
        cc_addrs: row.get(5)?,
        bcc_addrs: row.get(6)?,
        subject: row.get(7)?,
        body_html: row.get(8)?,
        body_text: row.get(9)?,
        attachments: row.get(10)?,
        tags: row.get(11)?,
        updated_at: row.get(12)?,
    })
}

/// Decode the JSON columns of a [`RawDraft`] into a [`DraftRow`].
fn decode_draft(raw: RawDraft) -> Result<DraftRow> {
    Ok(DraftRow {
        id: raw.id,
        account_id: raw.account_id,
        public_id: raw.public_id,
        from_addr: raw.from_addr,
        to_addrs: decode_string_list("drafts.to_addrs", &raw.to_addrs)?,
        cc_addrs: decode_string_list("drafts.cc_addrs", &raw.cc_addrs)?,
        bcc_addrs: decode_string_list("drafts.bcc_addrs", &raw.bcc_addrs)?,
        subject: raw.subject,
        body_html: raw.body_html,
        body_text: raw.body_text,
        attachments: decode_json_list("drafts.attachments", &raw.attachments)?,
        tags: decode_string_list("drafts.tags", &raw.tags)?,
        updated_at: raw.updated_at,
    })
}

/// Encode a `Vec<String>` column as a JSON array.
///
/// JSON for the same reason [`encode_addrs`] uses it: no separator to get wrong,
/// and corrupt content fails to decode instead of silently becoming a shorter
/// list.
fn encode_string_list(values: &[String]) -> Result<String> {
    serde_json::to_string(values).map_err(|error| {
        StoreError::InvalidArgument(format!("could not encode a draft list as JSON: {error}"))
    })
}

/// Decode a JSON array column that may be `NULL` — an older row, or "nothing yet".
fn decode_optional_string_list(column: &str, raw: Option<&str>) -> Result<Vec<String>> {
    match raw {
        Some(raw) => decode_string_list(column, raw),
        None => Ok(Vec::new()),
    }
}

/// Decode a JSON array of strings. Anything else is [`StoreError::Corrupt`].
fn decode_string_list(column: &str, raw: &str) -> Result<Vec<String>> {
    serde_json::from_str(raw).map_err(|error| {
        StoreError::Corrupt(format!("{column} is not a JSON array of strings: {error}"))
    })
}

/// Encode the opaque attachment JSON array of a draft.
fn encode_json_list(values: &[serde_json::Value]) -> Result<String> {
    serde_json::to_string(values).map_err(|error| {
        StoreError::InvalidArgument(format!("could not encode draft attachments: {error}"))
    })
}

/// Decode the attachment JSON array. The elements are kept as-is: `store` does
/// not interpret a draft's attachments, the send path does.
fn decode_json_list(column: &str, raw: &str) -> Result<Vec<serde_json::Value>> {
    serde_json::from_str(raw)
        .map_err(|error| StoreError::Corrupt(format!("{column} is not a JSON array: {error}")))
}

fn decode_direction(raw: &str) -> Result<Direction> {
    Direction::parse(raw).ok_or_else(|| {
        StoreError::Corrupt(format!("messages.direction holds an unknown value {raw:?}"))
    })
}

/// The address used by a `corrupt_row` placeholder. Parsed on use; the constant
/// is covered by `placeholder_address_is_a_valid_address`.
fn placeholder_address() -> EmailAddress {
    EmailAddress::parse(PLACEHOLDER_ADDRESS)
        .expect("PLACEHOLDER_ADDRESS is a valid address (covered by a unit test)")
}

fn is_constraint_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(e, _) if e.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

fn is_database_busy(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(e, _) if e.code == rusqlite::ErrorCode::DatabaseBusy
    )
}

/// Decode the `totp_enrollments.recovery_codes` column (a JSON array of PHC
/// hashes).
///
/// `NULL` means "no codes issued", which is an empty list, not an error. A
/// non-empty column that does not decode is [`StoreError::Corrupt`]: silently
/// treating it as empty would lock an account out of its own fallback path
/// without saying so.
fn decode_recovery_codes(raw: Option<&str>) -> Result<Vec<String>> {
    let Some(raw) = raw.filter(|value| !value.trim().is_empty()) else {
        return Ok(Vec::new());
    };
    serde_json::from_str(raw).map_err(|error| {
        StoreError::Corrupt(format!(
            "totp_enrollments.recovery_codes is not a JSON array of hashes: {error}"
        ))
    })
}

/// Switch the file to WAL mode, retrying while another opener holds the lock.
///
/// `PRAGMA journal_mode = WAL` needs exclusive access to the file, and unlike an
/// ordinary statement it fails with `SQLITE_BUSY` instead of going through the
/// busy handler: several processes opening the same cold file therefore race the
/// switch and lose. The retry is bounded (a few seconds, matching the busy
/// timeout) and the switch is idempotent — once any opener wins, the others see
/// `wal` and return immediately.
fn enable_wal(conn: &Connection) -> Result<()> {
    const ATTEMPTS: u32 = 60;
    let mut backoff = Duration::from_millis(5);
    for attempt in 1..=ATTEMPTS {
        match conn.query_row("PRAGMA journal_mode = WAL", [], |row| {
            row.get::<_, String>(0)
        }) {
            Ok(mode) if mode.eq_ignore_ascii_case("wal") => return Ok(()),
            Ok(mode) => {
                return Err(StoreError::InvalidArgument(format!(
                    "could not switch the database to WAL, journal_mode is {mode:?}"
                )))
            }
            Err(error) if is_database_busy(&error) && attempt < ATTEMPTS => {
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_millis(100));
            }
            Err(error) => return Err(error.into()),
        }
    }
    // The loop returns on the last attempt (`attempt < ATTEMPTS` is false), so
    // this is unreachable; keep it panic-free anyway.
    Err(StoreError::InvalidArgument(
        "could not switch the database to WAL: it stayed locked".to_string(),
    ))
}

/// 16 OS-random bytes, hex encoded, for queue claim ownership.
fn new_claim_token() -> String {
    // The crypto crate owns the OS RNG; reuse it instead of adding a second
    // randomness dependency to the storage layer.
    let random = pigeon_crypto::generate_content_key();
    hex::encode(&random[..16])
}

/// Unpadded base64url (RFC 4648 §5) of `bytes`.
///
/// A 20-line encoder instead of a dependency: `store` only needs this one
/// direction for invitation tokens, and the crate's dependency set is
/// deliberately small. Padding is omitted because a token is compared as text and
/// never concatenated with anything.
fn b64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map(u32::from);
        let b2 = chunk.get(2).copied().map(u32::from);
        let triple = (b0 << 16) | (b1.unwrap_or(0) << 8) | b2.unwrap_or(0);
        // 3 bytes -> 4 characters; 1 byte -> 2 characters (the rest is padding
        // that is dropped).
        let characters = chunk.len() + 1;
        for index in 0..characters {
            let sextet = (triple >> (18 - 6 * index)) & 0x3f;
            out.push(char::from(B64URL_ALPHABET[sextet as usize]));
        }
    }
    out
}

/// A fresh invitation token: 32 OS-random bytes, unpadded base64url (43 chars).
///
/// 256 bits of CSPRNG output, so the token cannot be guessed; the caller stores
/// only its Argon2id hash and hands this string out exactly once.
fn new_invitation_token() -> String {
    b64url(&pigeon_crypto::generate_content_key())
}

/// Normalize a domain for storage and lookup: trimmed and ASCII-lowercased.
///
/// DNS is case-insensitive and `catchall_rules.domain` is the identity of the
/// rule, so the stored form must be the form a lookup will use; otherwise
/// `Example.com` and `example.com` would be two rules for one name.
fn normalize_domain(raw: &str) -> Result<String> {
    let domain = raw.trim().to_ascii_lowercase();
    if domain.is_empty() {
        return Err(StoreError::InvalidArgument(
            "a catch-all rule needs a domain".to_string(),
        ));
    }
    // Reuse the address parser's domain rules (LDH labels, at least one dot, no
    // leading/trailing dot, bounded length) by validating a synthetic mailbox
    // with an empty-looking local part.
    EmailAddress::parse(&format!("postmaster@{domain}")).map_err(|error| {
        StoreError::InvalidArgument(format!("{domain:?} is not a domain: {error}"))
    })?;
    Ok(domain)
}

/// Decode `accounts.role`. The column has a `CHECK`, so an unknown value can only
/// come from a hand-edited file; it is reported instead of guessed.
fn decode_org_role(account_id: i64, raw: &str) -> Result<OrgRole> {
    OrgRole::parse(raw).ok_or_else(|| {
        StoreError::Corrupt(format!(
            "accounts.role of account {account_id} holds an unknown role {raw:?}"
        ))
    })
}

/// Decode `catchall_rules.action`.
fn decode_catchall_action(domain: &str, raw: &str) -> Result<CatchallAction> {
    CatchallAction::parse(raw).ok_or_else(|| {
        StoreError::Corrupt(format!(
            "catchall_rules.action of {domain:?} holds an unknown action {raw:?}"
        ))
    })
}

/// Reject anything that is not a versioned sealed envelope.
///
/// This is the storage-side half of the sealed-body contract: the service seals
/// with the reserved id as AAD, and the store refuses to persist a row whose
/// body could only be plaintext (or a future/unknown envelope generation it
/// would hand back unopenable).
fn validate_sealed_body(sealed_body: &[u8]) -> Result<()> {
    if sealed_body.len() < pigeon_crypto::MIN_BLOB_LEN {
        return Err(StoreError::InvalidSealedBody(format!(
            "blob is {} bytes, shorter than the {}-byte envelope minimum",
            sealed_body.len(),
            pigeon_crypto::MIN_BLOB_LEN
        )));
    }
    if sealed_body[0] != pigeon_crypto::ENVELOPE_VERSION {
        return Err(StoreError::InvalidSealedBody(format!(
            "envelope version is 0x{:02x}, expected 0x{:02x}",
            sealed_body[0],
            pigeon_crypto::ENVELOPE_VERSION
        )));
    }
    Ok(())
}

/// Raw columns of `messages`, shaped so the `rusqlite` closure can stay
/// infallible; parsing happens afterwards where domain errors can surface.
struct RawMessage {
    id: i64,
    account_id: i64,
    direction: String,
    from_addr: String,
    to_addrs: String,
    subject: String,
    sealed_body: Vec<u8>,
    status: String,
    created_at: String,
    folder: String,
    read_at: Option<String>,
    delivered_for: Option<String>,
}

/// Decode the `messages.folder` column. An unknown value is a corrupted column,
/// not a reason to hide the row from its owner: it degrades to the inbox with a
/// warning, the same discipline [`decode_listed_message`] uses for other
/// columns. Writes can never produce it — the column has a `CHECK`.
fn decode_folder(raw: &str) -> MessageFolder {
    MessageFolder::parse(raw).unwrap_or_else(|| {
        tracing::warn!(
            folder = raw,
            "messages.folder holds an unknown value; treating it as inbox"
        );
        MessageFolder::Inbox
    })
}

fn decode_message(raw: RawMessage) -> Result<MessageRow> {
    let direction = decode_direction(&raw.direction)?;
    let from_addr = EmailAddress::parse(&raw.from_addr)?;
    let to_addrs = decode_addrs(&raw.to_addrs)?;
    let folder = decode_folder(&raw.folder);
    Ok(MessageRow {
        id: raw.id,
        account_id: raw.account_id,
        direction,
        from_addr,
        to_addrs,
        subject: raw.subject,
        sealed_body: raw.sealed_body,
        status: raw.status,
        created_at: raw.created_at,
        folder,
        read_at: raw.read_at,
        delivered_for: raw.delivered_for,
    })
}

/// Decode one listed row, degrading a corrupt row instead of failing the page.
/// See [`Storage::list_messages`] for why a page must not fail here.
fn decode_listed_message(raw: RawMessage) -> MessageRow {
    let id = raw.id;
    let account_id = raw.account_id;
    let direction = Direction::parse(&raw.direction);
    let from_addr = EmailAddress::parse(&raw.from_addr);
    let to_addrs = decode_addrs(&raw.to_addrs);
    let folder = decode_folder(&raw.folder);
    let read_at = raw.read_at.clone();
    let RawMessage {
        subject,
        status,
        created_at,
        delivered_for,
        ..
    } = raw;

    match (direction, from_addr, to_addrs) {
        (Some(direction), Ok(from_addr), Ok(to_addrs)) => MessageRow {
            id,
            account_id,
            direction,
            from_addr,
            to_addrs,
            subject,
            // Listing never loads bodies, not even from a healthy row.
            sealed_body: Vec::new(),
            status,
            created_at,
            folder,
            read_at,
            delivered_for,
        },
        _ => {
            tracing::warn!(
                message_id = id,
                "message row no longer decodes; reporting it as corrupt_row"
            );
            MessageRow {
                id,
                account_id,
                direction: direction.unwrap_or(Direction::Out),
                from_addr: placeholder_address(),
                to_addrs: Vec::new(),
                subject,
                sealed_body: Vec::new(),
                status: STATUS_CORRUPT_ROW.to_string(),
                created_at,
                folder,
                read_at,
                delivered_for,
            }
        }
    }
}

/// Columns a listing needs, in the order [`listed_rows`] reads them.
///
/// Kept in one place so the account-wide listing, the folder listing and the
/// listing mapper cannot drift apart: a column added here without a matching
/// read in [`listed_rows`] fails every listing test at once.
const LISTED_COLUMNS: &str = "\
SELECT id, account_id, direction, from_addr, to_addrs, subject, \
       status, created_at, folder, read_at, delivered_for \
  FROM messages";

/// The folder listing, in one place so the test can `EXPLAIN QUERY PLAN` the
/// exact SQL production runs.
///
/// Parameters: `?1` account, `?2` folder, `?3` limit, `?4` offset.
/// `idx_messages_folder (account_id, folder, id DESC)` is built for this query:
/// equality on the two leading columns, ordering taken from the third.
pub(crate) fn list_folder_sql() -> String {
    format!(
        "{LISTED_COLUMNS} WHERE account_id = ?1 AND folder = ?2 \
         ORDER BY id DESC LIMIT ?3 OFFSET ?4"
    )
}

/// Run one listing query and decode its rows.
///
/// Bodies are never selected here: [`MessageRow::sealed_body`] stays empty and a
/// caller that needs one message asks [`Storage::get_message`].
fn listed_rows(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> Result<Vec<MessageRow>> {
    let rows = {
        let mut stmt = conn.prepare(sql)?;
        let mapped = stmt.query_map(params, |row| {
            Ok(RawMessage {
                id: row.get(0)?,
                account_id: row.get(1)?,
                direction: row.get(2)?,
                from_addr: row.get(3)?,
                to_addrs: row.get(4)?,
                subject: row.get(5)?,
                // Bodies stay on disk until a caller asks for one message.
                sealed_body: Vec::new(),
                status: row.get(6)?,
                created_at: row.get(7)?,
                folder: row.get(8)?,
                read_at: row.get(9)?,
                delivered_for: row.get(10)?,
            })
        })?;
        mapped.collect::<rusqlite::Result<Vec<_>>>()?
    };
    Ok(rows.into_iter().map(decode_listed_message).collect())
}

impl Storage for SqliteStorage {
    fn create_account(&self, account: &EmailAddress) -> Result<i64> {
        let mut conn = self.lock();
        // One transaction: the alias check and the insert must not be separable,
        // or an alias created in between would be shadowed by the account.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        guard_alias_shadow(&tx, account)?;
        match tx.execute(
            "INSERT INTO accounts (email, email_norm) VALUES (?1, ?2)",
            params![account.to_string(), account.normalized()],
        ) {
            Ok(_) => {
                let id = tx.last_insert_rowid();
                tx.commit()?;
                Ok(id)
            }
            Err(error) if is_constraint_violation(&error) => Err(StoreError::Conflict),
            Err(error) => Err(error.into()),
        }
    }

    fn get_account(&self, id: i64) -> Result<(i64, EmailAddress)> {
        let conn = self.lock();
        let email: String = conn
            .query_row("SELECT email FROM accounts WHERE id = ?1", [id], |row| {
                row.get(0)
            })
            .optional()?
            .ok_or(StoreError::NotFound)?;
        Ok((id, EmailAddress::parse(&email)?))
    }

    fn put_api_key(
        &self,
        account_id: i64,
        name: &str,
        key_prefix: &str,
        phc_hash: &str,
        scopes: &[ApiKeyScope],
    ) -> Result<i64> {
        let scopes: String = scopes
            .iter()
            .map(|scope| scope.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let conn = self.lock();
        conn.execute(
            "INSERT INTO api_keys (account_id, name, key_prefix, hash, scopes)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![account_id, name, key_prefix, phc_hash, scopes],
        )?;
        Ok(conn.last_insert_rowid())
    }

    fn find_api_key_by_prefix(&self, prefix: &str) -> Result<Vec<ApiKeyLookup>> {
        let conn = self.lock();
        let rows = {
            let mut stmt = conn.prepare(
                "SELECT account_id, hash, scopes FROM api_keys
                 WHERE key_prefix = ?1 AND revoked_at IS NULL
                 ORDER BY id DESC",
            )?;
            let mapped = stmt.query_map([prefix], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            mapped.collect::<rusqlite::Result<Vec<_>>>()?
        };

        rows.into_iter()
            .map(|(account_id, hash, scopes)| {
                let scopes = scopes
                    .split(',')
                    .filter(|scope| !scope.is_empty())
                    .map(|scope| {
                        ApiKeyScope::parse(scope).map_err(|error| {
                            StoreError::Corrupt(format!(
                                "api_keys.scopes of account {account_id} holds an unknown scope: {error}"
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok((account_id, hash, scopes))
            })
            .collect()
    }

    fn reserve_message_id(&self) -> Result<i64> {
        let mut conn = self.lock();
        // IMMEDIATE: take the write lock up front so two processes cannot read
        // the same counter value and both "reserve" it. A deferred transaction
        // would upgrade the lock lazily and surface SQLITE_BUSY instead.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // `AUTOINCREMENT` creates `sqlite_sequence` lazily: the row for
        // `messages` only exists after the first insert. Seed it from MAX(id)
        // (0 on an empty table) so the first reservation is 1, and so a
        // database whose sqlite_sequence was lost never hands out a live id.
        tx.execute(
            "INSERT INTO sqlite_sequence (name, seq)
             SELECT 'messages', COALESCE((SELECT MAX(id) FROM messages), 0)
              WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'messages')",
            [],
        )?;
        let reserved: i64 = tx.query_row(
            "UPDATE sqlite_sequence SET seq = seq + 1
              WHERE name = 'messages'
             RETURNING seq",
            [],
            |row| row.get(0),
        )?;
        tx.commit()?;
        Ok(reserved)
    }

    fn insert_message(&self, message: NewMessage, reserved_id: i64) -> Result<i64> {
        validate_sealed_body(&message.sealed_body)?;
        let to_addrs = encode_addrs(&message.to_addrs)?;
        // The delivery marker is an address or nothing: a hand-built string here
        // would end up in the inbox grouping and in the webmail's filter list.
        let delivered_for = match message.delivered_for.as_deref() {
            Some(raw) => Some(EmailAddress::parse(raw)?.normalized()),
            None => None,
        };
        // The folder follows the direction, and it is decided *here* rather than
        // by each caller: mail the account sent belongs in `sent`, mail that
        // arrived belongs in `inbox`. Leaving it to the column default is what
        // used to file every outbound copy in the inbox.
        //
        // `delivered_for` does not move a message out of the inbox: an alias or
        // catch-all copy is still received mail (direction `in`), and the marker
        // is a grouping key inside the inbox, not a folder.
        let folder = match message.direction {
            Direction::Out => MessageFolder::Sent,
            Direction::In => MessageFolder::Inbox,
        };
        let conn = self.lock();
        // The id is written explicitly, not left to AUTOINCREMENT: the caller
        // sealed the body with `reserved_id` as AAD, so the row must carry that
        // id or not exist. There is no code path in which SQLite picks a
        // different one.
        //
        // A replay of the same idempotency key is not an error: the conflict
        // target is the partial unique index on (account_id, idempotency_key),
        // so `DO NOTHING` swallows exactly the duplicate the caller is allowed
        // to repeat, and any other constraint violation still surfaces.
        let inserted = conn.execute(
            "INSERT INTO messages
                (id, account_id, direction, from_addr, to_addrs, subject,
                 sealed_body, idempotency_key, delivered_for, folder)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT (account_id, idempotency_key)
                 WHERE idempotency_key IS NOT NULL
             DO NOTHING",
            params![
                reserved_id,
                message.account_id,
                message.direction.as_str(),
                message.from_addr.to_string(),
                to_addrs,
                message.subject,
                message.sealed_body,
                message.idempotency_key,
                delivered_for,
                folder.as_str()
            ],
        )?;

        if inserted == 1 {
            return Ok(reserved_id);
        }

        // Nothing was written: this is the idempotent replay path. Return the
        // id of the row that already holds this key, so the caller sees the
        // same message instead of a duplicate. The reserved id is burned —
        // AUTOINCREMENT never reissues it — which is fine: ids are opaque.
        let key = message
            .idempotency_key
            .as_deref()
            .ok_or_else(|| StoreError::Conflict)?;
        conn.query_row(
            "SELECT id FROM messages WHERE account_id = ?1 AND idempotency_key = ?2",
            params![message.account_id, key],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(StoreError::Conflict)
    }

    fn get_message(&self, id: i64) -> Result<MessageRow> {
        let conn = self.lock();
        let raw = conn
            .query_row(
                "SELECT id, account_id, direction, from_addr, to_addrs, subject,
                        sealed_body, status, created_at, folder, read_at, delivered_for
                 FROM messages WHERE id = ?1",
                [id],
                |row| {
                    Ok(RawMessage {
                        id: row.get(0)?,
                        account_id: row.get(1)?,
                        direction: row.get(2)?,
                        from_addr: row.get(3)?,
                        to_addrs: row.get(4)?,
                        subject: row.get(5)?,
                        sealed_body: row.get(6)?,
                        status: row.get(7)?,
                        created_at: row.get(8)?,
                        folder: row.get(9)?,
                        read_at: row.get(10)?,
                        delivered_for: row.get(11)?,
                    })
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        decode_message(raw)
    }

    fn list_messages(&self, account_id: i64, limit: i64, offset: i64) -> Result<Vec<MessageRow>> {
        // Clamp rather than reject: the bound exists to protect the database
        // from an unbounded page, and a bad page size should not make the
        // mailbox unreadable to its owner.
        let limit = limit.clamp(1, MAX_PAGE_LIMIT);
        let conn = self.lock();
        listed_rows(
            &conn,
            &format!("{LISTED_COLUMNS} WHERE account_id = ?1 ORDER BY id DESC LIMIT ?2 OFFSET ?3"),
            params![account_id, limit, offset],
        )
    }

    fn list_folder(
        &self,
        account_id: i64,
        folder: MessageFolder,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<MessageRow>> {
        let limit = limit.clamp(1, MAX_PAGE_LIMIT);
        let conn = self.lock();
        listed_rows(
            &conn,
            &list_folder_sql(),
            params![account_id, folder.as_str(), limit, offset],
        )
    }

    fn set_message_folder(&self, message_id: i64, folder: MessageFolder) -> Result<()> {
        let conn = self.lock();
        // `trashed_at` is the retention clock and it moves with the folder:
        // entering the trash stamps it, leaving the trash clears it. A second
        // move *into* the trash keeps the first arrival (`COALESCE`), so a client
        // that re-patches `folder=trash` cannot reset its own countdown forever.
        let updated = conn.execute(
            "UPDATE messages
                SET folder = ?2,
                    trashed_at = CASE
                        WHEN ?2 = 'trash' THEN COALESCE(trashed_at, datetime('now'))
                        ELSE NULL
                    END
              WHERE id = ?1",
            params![message_id, folder.as_str()],
        )?;
        if updated == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    fn set_message_read(&self, message_id: i64, read: bool) -> Result<()> {
        let conn = self.lock();
        // Marking read is idempotent: `COALESCE` keeps the first timestamp, so a
        // client that re-opens a message does not rewrite "when they read it".
        let updated = conn.execute(
            "UPDATE messages
                SET read_at = CASE WHEN ?2 THEN COALESCE(read_at, datetime('now')) ELSE NULL END
              WHERE id = ?1",
            params![message_id, read],
        )?;
        if updated == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    fn delete_message(&self, message_id: i64) -> Result<()> {
        let conn = self.lock();
        let removed = conn.execute("DELETE FROM messages WHERE id = ?1", [message_id])?;
        if removed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    fn empty_folder(&self, account_id: i64, folder: MessageFolder) -> Result<usize> {
        let conn = self.lock();
        let removed = conn.execute(
            "DELETE FROM messages WHERE account_id = ?1 AND folder = ?2",
            params![account_id, folder.as_str()],
        )?;
        Ok(removed)
    }

    fn count_folder(&self, account_id: i64, folder: MessageFolder) -> Result<i64> {
        let conn = self.lock();
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE account_id = ?1 AND folder = ?2",
            params![account_id, folder.as_str()],
            |row| row.get(0),
        )?)
    }

    fn count_folder_with_unread(
        &self,
        account_id: i64,
        folder: MessageFolder,
    ) -> Result<(i64, i64)> {
        let conn = self.lock();
        // Both halves in one statement: `COALESCE` keeps an empty folder at 0
        // instead of `SUM` over no rows returning NULL, and the equality on
        // `(account_id, folder)` still walks `idx_messages_folder`.
        Ok(conn.query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(CASE WHEN read_at IS NULL THEN 1 ELSE 0 END), 0)
               FROM messages WHERE account_id = ?1 AND folder = ?2",
            params![account_id, folder.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?)
    }

    fn list_delivered_for(
        &self,
        account_id: i64,
        delivered_for: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<MessageRow>> {
        let limit = limit.clamp(1, MAX_PAGE_LIMIT);
        let marker = EmailAddress::parse(delivered_for)?.normalized();
        let conn = self.lock();
        listed_rows(
            &conn,
            &format!(
                "{LISTED_COLUMNS} WHERE account_id = ?1 AND folder = 'inbox' \
                 AND delivered_for = ?2 ORDER BY id DESC LIMIT ?3 OFFSET ?4"
            ),
            params![account_id, marker, limit, offset],
        )
    }

    fn count_delivered_for(&self, account_id: i64, delivered_for: &str) -> Result<i64> {
        let marker = EmailAddress::parse(delivered_for)?.normalized();
        let conn = self.lock();
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM messages
              WHERE account_id = ?1 AND folder = 'inbox' AND delivered_for = ?2",
            params![account_id, marker],
            |row| row.get(0),
        )?)
    }

    fn delivered_for_counts(&self, account_id: i64) -> Result<Vec<(String, i64)>> {
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT delivered_for, COUNT(*) FROM messages
              WHERE account_id = ?1 AND folder = 'inbox' AND delivered_for IS NOT NULL
              GROUP BY delivered_for ORDER BY delivered_for",
        )?;
        let rows = statement
            .query_map([account_id], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn get_trash_retention(&self, account_id: i64) -> Result<i64> {
        let conn = self.lock();
        conn.query_row(
            "SELECT trash_retention_days FROM accounts WHERE id = ?1",
            [account_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(StoreError::NotFound)
    }

    fn set_trash_retention(&self, account_id: i64, days: i64) -> Result<()> {
        if !(0..=MAX_TRASH_RETENTION_DAYS).contains(&days) {
            return Err(StoreError::InvalidArgument(format!(
                "trash retention must be 0..={MAX_TRASH_RETENTION_DAYS} days, got {days}"
            )));
        }
        let conn = self.lock();
        let updated = conn.execute(
            "UPDATE accounts SET trash_retention_days = ?2 WHERE id = ?1",
            params![account_id, days],
        )?;
        if updated == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    fn purge_expired_trash(&self, account_id: i64) -> Result<usize> {
        // The policy is read with its own lock, released before the delete: the
        // mutex is not reentrant, so nesting the two locks would deadlock.
        let days = self.get_trash_retention(account_id)?;
        if days <= 0 {
            return Ok(0);
        }
        let conn = self.lock();
        // The cutoff is computed by SQLite in the same textual form
        // `datetime('now')` writes into `trashed_at`, which is what makes the
        // comparison a plain string compare in one shared clock. `trashed_at IS
        // NOT NULL` keeps pre-migration trash and every non-trash row out.
        let removed = conn.execute(
            "DELETE FROM messages
              WHERE account_id = ?1
                AND folder = 'trash'
                AND trashed_at IS NOT NULL
                AND trashed_at < datetime('now', ?2)",
            params![account_id, format!("-{days} days")],
        )?;
        Ok(removed)
    }

    fn accounts_with_trash_purge(&self) -> Result<Vec<i64>> {
        let conn = self.lock();
        let mut stmt =
            conn.prepare("SELECT id FROM accounts WHERE trash_retention_days > 0 ORDER BY id")?;
        let ids = stmt
            .query_map([], |row| row.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(ids)
    }

    fn queue_enqueue(&self, message_id: i64, run_after_unix: i64) -> Result<i64> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO queue (message_id, run_after) VALUES (?1, ?2)",
            params![message_id, run_after_unix],
        )?;
        Ok(conn.last_insert_rowid())
    }

    fn queue_claim(&self, worker_id: &str, lease_secs: u64) -> Result<Option<ClaimedJob>> {
        let token = new_claim_token();
        // A lease longer than a day is a bug in the caller (a worker that
        // crashes then blocks the job for a day), so clamp instead of trusting.
        let lease = i64::try_from(lease_secs.min(MAX_LEASE_SECS)).unwrap_or(i64::MAX);
        let conn = self.lock();
        let job = conn
            .query_row(QUEUE_CLAIM_SQL, params![token, worker_id, lease], |row| {
                // The delivered-domain list is JSON, which rusqlite cannot decode:
                // read it raw here and decode below, so a corrupt row is a
                // `Corrupt` error instead of a driver error.
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })
            .optional()?;
        let job = match job {
            Some((id, message_id, claim_token, attempts, claimed_by, delivered)) => {
                Some(ClaimedJob {
                    id,
                    message_id,
                    claim_token,
                    attempts,
                    claimed_by,
                    delivered_domains: decode_optional_string_list(
                        "queue.delivered_domains",
                        delivered.as_deref(),
                    )?,
                })
            }
            None => None,
        };
        Ok(job)
    }

    fn queue_complete(&self, claim_token: &str) -> Result<()> {
        let conn = self.lock();
        let removed = conn.execute("DELETE FROM queue WHERE claim_token = ?1", [claim_token])?;
        if removed == 0 {
            return Err(StoreError::QueueClaim(
                "no live claim owns that token".to_string(),
            ));
        }
        Ok(())
    }

    fn queue_fail(&self, claim_token: &str, error: &str, backoff_secs: u64) -> Result<()> {
        let backoff = i64::try_from(backoff_secs).unwrap_or(86400).clamp(0, 86400);
        let conn = self.lock();
        // One statement so the "is this the last attempt?" decision cannot race
        // a concurrent claim. `claimed_at`/`claim_token` are cleared together:
        // an unclaimed job becomes due because `run_after` elapsed, never
        // because some lease quietly expired.
        //
        // A job that just spent its last attempt keeps its error and becomes
        // `dead`, which the claim query filters out for good; a job with
        // attempts left is re-armed for a retry.
        let released = conn.execute(
            "UPDATE queue
                SET claim_token = NULL,
                    claimed_at = NULL,
                    last_error = ?3,
                    status = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE status END,
                    run_after = CASE
                        WHEN attempts >= max_attempts THEN run_after
                        ELSE unixepoch() + ?2
                    END
              WHERE claim_token = ?1",
            params![claim_token, backoff, error],
        )?;
        if released == 0 {
            return Err(StoreError::QueueClaim(
                "no live claim owns that token".to_string(),
            ));
        }
        Ok(())
    }

    fn list_dead(&self, limit: i64) -> Result<Vec<DeadJob>> {
        let limit = limit.clamp(1, MAX_PAGE_LIMIT);
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT message_id, COALESCE(last_error, ''), attempts
               FROM queue WHERE status = 'dead' ORDER BY id LIMIT ?1",
        )?;
        let jobs = stmt
            .query_map([limit], |row| {
                Ok(DeadJob {
                    message_id: row.get(0)?,
                    last_error: row.get(1)?,
                    attempts: row.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(jobs)
    }

    fn record_event(&self, message_id: i64, kind: &str, detail: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO events (message_id, kind, detail) VALUES (?1, ?2, ?3)",
            params![message_id, kind, detail],
        )?;
        Ok(())
    }

    fn list_events(&self, message_id: i64) -> Result<Vec<EventEntry>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT kind, detail, created_at FROM events
             WHERE message_id = ?1 ORDER BY id",
        )?;
        let events = stmt
            .query_map([message_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(events)
    }

    fn audit(&self, actor: &str, action: &str, detail: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO audit (actor, action, detail) VALUES (?1, ?2, ?3)",
            params![actor, action, detail],
        )?;
        Ok(())
    }

    fn set_totp_secret(&self, account_id: i64, wrapped: &[u8]) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO totp_secrets (account_id, wrapped_secret) VALUES (?1, ?2)
             ON CONFLICT (account_id)
             DO UPDATE SET wrapped_secret = excluded.wrapped_secret",
            params![account_id, wrapped],
        )?;
        Ok(())
    }

    fn get_totp_secret(&self, account_id: i64) -> Result<Option<Vec<u8>>> {
        let conn = self.lock();
        let secret = conn
            .query_row(
                "SELECT wrapped_secret FROM totp_secrets WHERE account_id = ?1",
                [account_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(secret)
    }

    fn get_account_by_email(&self, email_norm: &str) -> Result<Option<i64>> {
        let conn = self.lock();
        let id = conn
            .query_row(
                "SELECT id FROM accounts WHERE email_norm = ?1",
                [email_norm],
                |row| row.get(0),
            )
            .optional()?;
        Ok(id)
    }

    fn create_session(
        &self,
        id: &str,
        account_id: i64,
        token_hash: &str,
        ttl_secs: u64,
    ) -> Result<String> {
        let ttl = i64::try_from(ttl_secs.min(MAX_SESSION_TTL_SECS)).unwrap_or(i64::MAX);
        let conn = self.lock();
        // The expiry is computed by SQLite, not by the caller: every row then
        // shares one clock and one textual format, which is what makes the
        // `expires_at > datetime('now')` comparison in `get_session_by_id`
        // correct without parsing dates.
        match conn.query_row(
            "INSERT INTO sessions (id, account_id, token_hash, expires_at)
             VALUES (?1, ?2, ?3, datetime('now', ?4))
             RETURNING expires_at",
            params![id, account_id, token_hash, format!("+{ttl} seconds")],
            |row| row.get(0),
        ) {
            Ok(expires_at) => Ok(expires_at),
            Err(error) if is_constraint_violation(&error) => Err(StoreError::Conflict),
            Err(error) => Err(error.into()),
        }
    }

    fn get_session_by_id(&self, id: &str) -> Result<Option<SessionRow>> {
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT id, account_id, token_hash, created_at, expires_at
                   FROM sessions
                  WHERE id = ?1
                    AND revoked_at IS NULL
                    AND expires_at > datetime('now')",
                [id],
                |row| {
                    Ok(SessionRow {
                        id: row.get(0)?,
                        account_id: row.get(1)?,
                        token_hash: row.get(2)?,
                        created_at: row.get(3)?,
                        expires_at: row.get(4)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    fn revoke_session(&self, id: &str) -> Result<()> {
        let conn = self.lock();
        // Only a live session can be revoked; a second logout (or an unknown id)
        // is `NotFound` so the caller sees that nothing was ended.
        let revoked = conn.execute(
            "UPDATE sessions SET revoked_at = datetime('now')
              WHERE id = ?1 AND revoked_at IS NULL",
            [id],
        )?;
        if revoked == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    fn revoke_all_account_sessions(&self, account_id: i64, except: Option<&str>) -> Result<usize> {
        let conn = self.lock();
        // `(?2 IS NULL OR id <> ?2)` keeps the caller's own session alive without
        // a second statement: revoking the session that is executing the revoke
        // would log the user out of the page they are using.
        let revoked = conn.execute(
            "UPDATE sessions SET revoked_at = datetime('now')
              WHERE account_id = ?1
                AND revoked_at IS NULL
                AND (?2 IS NULL OR id <> ?2)",
            params![account_id, except],
        )?;
        Ok(revoked)
    }

    fn set_totp_enrollment(&self, account_id: i64, secret_wrapped: &[u8]) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO totp_enrollments (account_id, secret_wrapped) VALUES (?1, ?2)
             ON CONFLICT (account_id)
             DO UPDATE SET
                secret_wrapped = excluded.secret_wrapped,
                confirmed = 0,
                last_used_step = NULL,
                recovery_codes = NULL,
                enrolled_at = NULL",
            params![account_id, secret_wrapped],
        )?;
        Ok(())
    }

    fn get_totp_enrollment(&self, account_id: i64) -> Result<Option<TotpEnrollmentRow>> {
        let conn = self.lock();
        let raw = conn
            .query_row(
                "SELECT account_id, secret_wrapped, confirmed, last_used_step,
                        recovery_codes, enrolled_at
                   FROM totp_enrollments WHERE account_id = ?1",
                [account_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((account_id, secret_wrapped, confirmed, last_used_step, codes, enrolled_at)) = raw
        else {
            return Ok(None);
        };
        Ok(Some(TotpEnrollmentRow {
            account_id,
            secret_wrapped,
            confirmed: confirmed != 0,
            last_used_step,
            recovery_codes: decode_recovery_codes(codes.as_deref())?,
            enrolled_at,
        }))
    }

    fn confirm_totp(&self, account_id: i64, recovery_hashes: &[String], step: i64) -> Result<()> {
        let codes = serde_json::to_string(recovery_hashes).map_err(|error| {
            StoreError::InvalidArgument(format!("could not encode recovery codes: {error}"))
        })?;
        let conn = self.lock();
        let updated = conn.execute(
            "UPDATE totp_enrollments
                SET confirmed = 1,
                    recovery_codes = ?2,
                    last_used_step = ?3,
                    enrolled_at = datetime('now')
              WHERE account_id = ?1",
            params![account_id, codes, step],
        )?;
        if updated == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    fn set_totp_last_step(&self, account_id: i64, step: i64) -> Result<bool> {
        let conn = self.lock();
        // One statement, so the "is this step new?" read cannot be raced by a
        // concurrent request replaying the same code.
        let updated = conn.execute(
            "UPDATE totp_enrollments SET last_used_step = ?2
              WHERE account_id = ?1
                AND (last_used_step IS NULL OR last_used_step < ?2)",
            params![account_id, step],
        )?;
        Ok(updated == 1)
    }

    fn burn_recovery_code(&self, account_id: i64, index: usize) -> Result<bool> {
        let mut conn = self.lock();
        // IMMEDIATE: read the list, drop one entry and write it back in one
        // transaction, so two concurrent logins cannot both spend the same code.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let raw: Option<String> = tx
            .query_row(
                "SELECT recovery_codes FROM totp_enrollments WHERE account_id = ?1",
                [account_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(raw) = raw else {
            return Ok(false);
        };
        let mut codes = decode_recovery_codes(Some(&raw))?;
        if index >= codes.len() {
            return Ok(false);
        }
        codes.remove(index);
        let encoded = serde_json::to_string(&codes).map_err(|error| {
            StoreError::InvalidArgument(format!("could not encode recovery codes: {error}"))
        })?;
        tx.execute(
            "UPDATE totp_enrollments SET recovery_codes = ?2 WHERE account_id = ?1",
            params![account_id, encoded],
        )?;
        tx.commit()?;
        Ok(true)
    }

    fn revoke_totp(&self, account_id: i64) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "DELETE FROM totp_enrollments WHERE account_id = ?1",
            [account_id],
        )?;
        Ok(())
    }

    fn put_template(
        &self,
        account_id: i64,
        name: &str,
        subject_tpl: &str,
        html_tpl: &str,
        text_tpl: &str,
    ) -> Result<()> {
        self.put_template_with_description(account_id, name, "", subject_tpl, html_tpl, text_tpl)
    }

    fn put_template_with_description(
        &self,
        account_id: i64,
        name: &str,
        description: &str,
        subject_tpl: &str,
        html_tpl: &str,
        text_tpl: &str,
    ) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO templates
                (account_id, name, description, subject_tpl, html_tpl, text_tpl)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (account_id, name)
             DO UPDATE SET
                description = excluded.description,
                subject_tpl = excluded.subject_tpl,
                html_tpl = excluded.html_tpl,
                text_tpl = excluded.text_tpl,
                updated_at = datetime('now')",
            params![
                account_id,
                name,
                description,
                subject_tpl,
                html_tpl,
                text_tpl
            ],
        )?;
        Ok(())
    }

    fn get_template(&self, account_id: i64, name: &str) -> Result<Option<TemplateRow>> {
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT id, account_id, name, description, subject_tpl, html_tpl, text_tpl,
                        updated_at
                 FROM templates WHERE account_id = ?1 AND name = ?2",
                params![account_id, name],
                |row| {
                    Ok(TemplateRow {
                        id: row.get(0)?,
                        account_id: row.get(1)?,
                        name: row.get(2)?,
                        description: row.get(3)?,
                        subject_tpl: row.get(4)?,
                        html_tpl: row.get(5)?,
                        text_tpl: row.get(6)?,
                        updated_at: row.get(7)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    // --------------------------------------------------------------- drafts

    fn create_draft(&self, account_id: i64, public_id: &str, draft: &NewDraft) -> Result<i64> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO drafts
                (account_id, public_id, from_addr, to_addrs, cc_addrs, bcc_addrs,
                 subject, body_html, body_text, attachments, tags)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                account_id,
                public_id,
                draft.from_addr,
                encode_string_list(&draft.to_addrs)?,
                encode_string_list(&draft.cc_addrs)?,
                encode_string_list(&draft.bcc_addrs)?,
                draft.subject,
                draft.body_html,
                draft.body_text,
                encode_json_list(&draft.attachments)?,
                encode_string_list(&draft.tags)?,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    fn update_draft(&self, public_id: &str, account_id: i64, draft: &NewDraft) -> Result<bool> {
        let conn = self.lock();
        let updated = conn.execute(
            "UPDATE drafts
                SET from_addr = ?3,
                    to_addrs = ?4,
                    cc_addrs = ?5,
                    bcc_addrs = ?6,
                    subject = ?7,
                    body_html = ?8,
                    body_text = ?9,
                    attachments = ?10,
                    tags = ?11,
                    updated_at = datetime('now')
              WHERE account_id = ?1 AND public_id = ?2",
            params![
                account_id,
                public_id,
                draft.from_addr,
                encode_string_list(&draft.to_addrs)?,
                encode_string_list(&draft.cc_addrs)?,
                encode_string_list(&draft.bcc_addrs)?,
                draft.subject,
                draft.body_html,
                draft.body_text,
                encode_json_list(&draft.attachments)?,
                encode_string_list(&draft.tags)?,
            ],
        )?;
        Ok(updated > 0)
    }

    fn get_draft(&self, public_id: &str, account_id: i64) -> Result<Option<DraftRow>> {
        let conn = self.lock();
        let row = conn
            .query_row(
                &format!("{DRAFT_SELECT} WHERE account_id = ?1 AND public_id = ?2"),
                params![account_id, public_id],
                map_raw_draft,
            )
            .optional()?;
        row.map(decode_draft).transpose()
    }

    fn list_drafts(&self, account_id: i64, limit: i64, offset: i64) -> Result<Vec<DraftRow>> {
        let conn = self.lock();
        let mut statement = conn.prepare(&format!(
            "{DRAFT_SELECT} WHERE account_id = ?1
             ORDER BY updated_at DESC, id DESC
             LIMIT ?2 OFFSET ?3"
        ))?;
        let rows = statement
            .query_map(params![account_id, limit, offset], map_raw_draft)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(decode_draft).collect()
    }

    fn count_drafts(&self, account_id: i64) -> Result<i64> {
        let conn = self.lock();
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM drafts WHERE account_id = ?1",
            [account_id],
            |row| row.get(0),
        )?)
    }

    fn delete_draft(&self, public_id: &str, account_id: i64) -> Result<bool> {
        let conn = self.lock();
        let removed = conn.execute(
            "DELETE FROM drafts WHERE account_id = ?1 AND public_id = ?2",
            params![account_id, public_id],
        )?;
        Ok(removed > 0)
    }

    // ----------------------------------------------------------- dkim keys

    fn put_dkim_key(
        &self,
        domain: &str,
        selector: &str,
        wrapped_private_key: &[u8],
        public_dns: &str,
    ) -> Result<()> {
        // A re-put must rotate the row in place: `domain` is the identity, so an
        // `ON CONFLICT` upsert keeps one row per sending domain and never leaves
        // a stale public record beside a new key.
        let conn = self.lock();
        conn.execute(
            "INSERT INTO dkim_keys (domain, selector, private_key_wrapped, public_dns)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (domain) DO UPDATE SET
                 selector = excluded.selector,
                 private_key_wrapped = excluded.private_key_wrapped,
                 public_dns = excluded.public_dns",
            params![domain, selector, wrapped_private_key, public_dns],
        )?;
        Ok(())
    }

    fn get_dkim_key(&self, domain: &str) -> Result<Option<(String, Vec<u8>, String)>> {
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT selector, private_key_wrapped, public_dns
                   FROM dkim_keys WHERE domain = ?1",
                [domain],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        Ok(row)
    }

    fn list_dkim_keys(&self) -> Result<Vec<(String, String, String)>> {
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT domain, selector, public_dns FROM dkim_keys ORDER BY created_at, domain",
        )?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ---------------------------------------------------------------- orgs

    fn create_org(&self, name: &str) -> Result<i64> {
        let name = require_name("organization", name)?;
        let conn = self.lock();
        conn.execute("INSERT INTO orgs (name) VALUES (?1)", [&name])?;
        Ok(conn.last_insert_rowid())
    }

    fn get_org(&self, id: i64) -> Result<OrgRow> {
        let conn = self.lock();
        let row = conn
            .query_row(&format!("{ORG_SELECT} WHERE id = ?1"), [id], map_org)
            .optional()?;
        row.ok_or(StoreError::NotFound)
    }

    fn list_orgs(&self) -> Result<Vec<OrgRow>> {
        let conn = self.lock();
        let mut statement = conn.prepare(&format!("{ORG_SELECT} ORDER BY id"))?;
        let rows = statement
            .query_map([], map_org)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn list_orgs_for_account(&self, account_id: i64) -> Result<Vec<OrgRow>> {
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT o.id, o.name, o.created_at
               FROM orgs o JOIN accounts a ON a.org_id = o.id
              WHERE a.id = ?1
              ORDER BY o.id",
        )?;
        let rows = statement
            .query_map([account_id], map_org)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn rename_org(&self, id: i64, name: &str) -> Result<()> {
        let name = require_name("organization", name)?;
        let conn = self.lock();
        let updated = conn.execute("UPDATE orgs SET name = ?2 WHERE id = ?1", params![id, name])?;
        if updated == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    fn delete_org(&self, id: i64) -> Result<()> {
        let mut conn = self.lock();
        // IMMEDIATE: "no member" and the delete are one decision. A concurrent
        // `create_member_account` between the check and the delete would
        // otherwise orphan a live mailbox.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM orgs WHERE id = ?1)",
            [id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(StoreError::NotFound);
        }
        let members: i64 = tx.query_row(
            "SELECT COUNT(*) FROM accounts WHERE org_id = ?1",
            [id],
            |row| row.get(0),
        )?;
        if members > 0 {
            return Err(StoreError::Conflict);
        }
        tx.execute("DELETE FROM orgs WHERE id = ?1", [id])?;
        tx.commit()?;
        Ok(())
    }

    fn get_account_membership(&self, account_id: i64) -> Result<(Option<i64>, OrgRole)> {
        let conn = self.lock();
        let raw: (Option<i64>, String) = conn
            .query_row(
                "SELECT org_id, role FROM accounts WHERE id = ?1",
                [account_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        Ok((raw.0, decode_org_role(account_id, &raw.1)?))
    }

    fn list_org_accounts(&self, org_id: i64) -> Result<Vec<OrgAccountRow>> {
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT id, org_id, email, display_name, role, created_at
               FROM accounts WHERE org_id = ?1 ORDER BY id",
        )?;
        let rows = statement
            .query_map([org_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(
                |(account_id, org_id, email, display_name, role, created_at)| {
                    Ok(OrgAccountRow {
                        account_id,
                        org_id,
                        email,
                        display_name,
                        role: decode_org_role(account_id, &role)?,
                        created_at,
                    })
                },
            )
            .collect()
    }

    fn set_account_role(&self, account_id: i64, role: OrgRole) -> Result<()> {
        let mut conn = self.lock();
        // IMMEDIATE: the "is another owner left?" count and the write are one
        // decision. Two concurrent demotions of an organization's two owners must
        // not both see one remaining owner and both proceed.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let raw: (Option<i64>, String) = tx
            .query_row(
                "SELECT org_id, role FROM accounts WHERE id = ?1",
                [account_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        let current = decode_org_role(account_id, &raw.1)?;
        if current == role {
            // A no-op rather than a conflict: a client that PATCHes the role it
            // sees must not have to special-case it.
            return Ok(());
        }
        guard_last_owner(&tx, account_id, raw.0, current, role, raw.0)?;
        tx.execute(
            "UPDATE accounts SET role = ?2 WHERE id = ?1",
            params![account_id, role.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn set_account_display_name(&self, account_id: i64, display_name: &str) -> Result<()> {
        let conn = self.lock();
        let updated = conn.execute(
            "UPDATE accounts SET display_name = ?2 WHERE id = ?1",
            params![account_id, display_name.trim()],
        )?;
        if updated == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    fn create_member_account(
        &self,
        email: &EmailAddress,
        display_name: &str,
        org_id: i64,
        role: OrgRole,
    ) -> Result<i64> {
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let org_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM orgs WHERE id = ?1)",
            [org_id],
            |row| row.get(0),
        )?;
        if !org_exists {
            return Err(StoreError::NotFound);
        }
        // Same rule as `create_account`: a member mailbox must never take an
        // address a sender alias already owns, or mail for the shared address
        // would be diverted into that one mailbox.
        guard_alias_shadow(&tx, email)?;
        match tx.execute(
            "INSERT INTO accounts (email, email_norm, org_id, role, display_name)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                email.to_string(),
                email.normalized(),
                org_id,
                role.as_str(),
                display_name.trim()
            ],
        ) {
            Ok(_) => {
                let id = tx.last_insert_rowid();
                tx.commit()?;
                Ok(id)
            }
            Err(error) if is_constraint_violation(&error) => Err(StoreError::Conflict),
            Err(error) => Err(error.into()),
        }
    }

    fn deactivate_account(&self, account_id: i64) -> Result<()> {
        let mut conn = self.lock();
        // One transaction for both revocations: a half-deactivated account whose
        // sessions are gone but whose API key still works is exactly the state
        // this call exists to prevent.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE id = ?1)",
            [account_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(StoreError::NotFound);
        }
        tx.execute(
            "UPDATE sessions SET revoked_at = datetime('now')
              WHERE account_id = ?1 AND revoked_at IS NULL",
            [account_id],
        )?;
        tx.execute(
            "UPDATE api_keys SET revoked_at = datetime('now')
              WHERE account_id = ?1 AND revoked_at IS NULL",
            [account_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn set_account_org(&self, account_id: i64, org_id: Option<i64>, role: OrgRole) -> Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let raw: (Option<i64>, String) = tx
            .query_row(
                "SELECT org_id, role FROM accounts WHERE id = ?1",
                [account_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        if let Some(target) = org_id {
            let org_exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM orgs WHERE id = ?1)",
                [target],
                |row| row.get(0),
            )?;
            if !org_exists {
                return Err(StoreError::NotFound);
            }
        }
        let current = decode_org_role(account_id, &raw.1)?;
        guard_last_owner(&tx, account_id, raw.0, current, role, org_id)?;
        tx.execute(
            "UPDATE accounts SET org_id = ?2, role = ?3 WHERE id = ?1",
            params![account_id, org_id, role.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }

    // --------------------------------------------------------- invitations

    fn create_invitation(
        &self,
        org_id: i64,
        email: &EmailAddress,
        role: OrgRole,
        invited_by: i64,
    ) -> Result<String> {
        if role == OrgRole::Owner {
            return Err(StoreError::InvalidArgument(
                "an invitation grants admin or member, never owner: ownership is transferred \
                 by changing an existing member's role"
                    .to_string(),
            ));
        }
        let token = new_invitation_token();
        let token_hash = pigeon_crypto::hash_api_key(&token).map_err(StoreError::from)?;
        let conn = self.lock();
        let org_exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM orgs WHERE id = ?1)",
            [org_id],
            |row| row.get(0),
        )?;
        if !org_exists {
            return Err(StoreError::NotFound);
        }
        // Re-inviting the same address replaces the pending row instead of
        // leaving two live tokens for one seat; `accepted_at` is cleared because
        // the row is a fresh invitation again.
        conn.execute(
            "INSERT INTO invitations (org_id, email, role, token_hash, invited_by, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, datetime('now', ?6))
             ON CONFLICT (org_id, email) DO UPDATE SET
                 role = excluded.role,
                 token_hash = excluded.token_hash,
                 invited_by = excluded.invited_by,
                 created_at = datetime('now'),
                 expires_at = excluded.expires_at,
                 accepted_at = NULL",
            params![
                org_id,
                email.normalized(),
                role.as_str(),
                token_hash,
                invited_by,
                format!("+{INVITATION_TTL_SECS} seconds")
            ],
        )?;
        Ok(token)
    }

    fn get_invitation_by_token(&self, token: &str) -> Result<Option<InvitationRow>> {
        let token = token.trim();
        if token.is_empty() {
            return Ok(None);
        }
        let conn = self.lock();
        let candidates = {
            let mut statement = conn.prepare(&format!(
                "{INVITATION_SELECT}
                  WHERE accepted_at IS NULL AND expires_at > datetime('now')
                  ORDER BY id DESC LIMIT ?1"
            ))?;
            let rows = statement
                .query_map([MAX_INVITATION_SCAN], map_raw_invitation)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        for candidate in candidates {
            if pigeon_crypto::verify_api_key(token, &candidate.token_hash) {
                return decode_invitation(candidate).map(Some);
            }
        }
        Ok(None)
    }

    fn accept_invitation(&self, invitation_id: i64, account_id: i64) -> Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // One statement decides "still redeemable?" and burns the row, so two
        // concurrent redemptions of one token cannot both succeed.
        let burnt: Option<(i64, String)> = tx
            .query_row(
                "UPDATE invitations SET accepted_at = datetime('now')
                  WHERE id = ?1
                    AND accepted_at IS NULL
                    AND expires_at > datetime('now')
                RETURNING org_id, role",
                [invitation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((org_id, role)) = burnt else {
            return Err(StoreError::Conflict);
        };
        let role = OrgRole::parse(&role).ok_or_else(|| {
            StoreError::Corrupt(format!(
                "invitations.role of invitation {invitation_id} is not a role: {role:?}"
            ))
        })?;
        if role == OrgRole::Owner {
            return Err(StoreError::Corrupt(format!(
                "invitation {invitation_id} grants ownership, which no invitation may do"
            )));
        }
        // An account belongs to one organization. Accepting an invitation to a
        // *different* organization is refused rather than silently moving the
        // mailbox out of the team it currently serves.
        let current: Option<i64> = tx
            .query_row(
                "SELECT org_id FROM accounts WHERE id = ?1",
                [account_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        if matches!(current, Some(existing) if existing != org_id) {
            return Err(StoreError::Conflict);
        }
        tx.execute(
            "UPDATE accounts SET org_id = ?2, role = ?3 WHERE id = ?1",
            params![account_id, org_id, role.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn list_invitations(&self, org_id: i64) -> Result<Vec<InvitationRow>> {
        let conn = self.lock();
        let mut statement = conn.prepare(&format!(
            "{INVITATION_SELECT} WHERE org_id = ?1 ORDER BY id DESC"
        ))?;
        let rows = statement
            .query_map([org_id], map_raw_invitation)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(decode_invitation).collect()
    }

    fn delete_invitation(&self, org_id: i64, invitation_id: i64) -> Result<bool> {
        let conn = self.lock();
        let removed = conn.execute(
            "DELETE FROM invitations WHERE id = ?1 AND org_id = ?2",
            params![invitation_id, org_id],
        )?;
        Ok(removed > 0)
    }

    // ----------------------------------------------------------- catch-all

    fn set_catchall(&self, domain: &str, action: CatchallAction) -> Result<()> {
        let domain = normalize_domain(domain)?;
        let conn = self.lock();
        conn.execute(
            "INSERT INTO catchall_rules (domain, action)
             VALUES (?1, ?2)
             ON CONFLICT (domain) DO UPDATE SET action = excluded.action",
            params![domain, action.as_str()],
        )?;
        Ok(())
    }

    fn get_catchall(&self, domain: &str) -> Result<Option<CatchallRuleRow>> {
        let domain = domain.trim().to_ascii_lowercase();
        let conn = self.lock();
        let raw = conn
            .query_row(
                &format!("{CATCHALL_SELECT} WHERE domain = ?1"),
                [&domain],
                map_raw_catchall,
            )
            .optional()?;
        raw.map(decode_catchall).transpose()
    }

    fn list_catchalls(&self) -> Result<Vec<CatchallRuleRow>> {
        let conn = self.lock();
        let mut statement = conn.prepare(&format!("{CATCHALL_SELECT} ORDER BY id"))?;
        let rows = statement
            .query_map([], map_raw_catchall)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(decode_catchall).collect()
    }

    fn delete_catchall(&self, domain: &str) -> Result<()> {
        let domain = domain.trim().to_ascii_lowercase();
        let mut conn = self.lock();
        // One transaction for both deletes: a rule that vanished while its
        // assignments survived would leave grants that can never fire.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let removed = tx.execute("DELETE FROM catchall_rules WHERE domain = ?1", [&domain])?;
        if removed == 0 {
            return Err(StoreError::NotFound);
        }
        tx.execute(
            "DELETE FROM catchall_assignments WHERE domain = ?1",
            [&domain],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn assign_catchall(&self, domain: &str, account_id: i64, assigned_by: i64) -> Result<()> {
        let domain = normalize_domain(domain)?;
        let mut conn = self.lock();
        // The rule check and the insert are one transaction: an assignment whose
        // domain has no rule can never fire, so it must not be left behind. The
        // check runs *first* — a failure has to write nothing, not roll back a
        // write the caller cannot see.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let rule_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM catchall_rules WHERE domain = ?1)",
            [&domain],
            |row| row.get(0),
        )?;
        if !rule_exists {
            return Err(StoreError::NotFound);
        }
        require_account_exists(&tx, account_id)?;
        require_account_exists(&tx, assigned_by)?;
        let inserted = tx.execute(
            "INSERT INTO catchall_assignments (domain, account_id, assigned_by)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (domain, account_id) DO NOTHING",
            params![domain, account_id, assigned_by],
        )?;
        if inserted == 0 {
            return Err(StoreError::Conflict);
        }
        tx.commit()?;
        Ok(())
    }

    fn unassign_catchall(&self, domain: &str, account_id: i64) -> Result<()> {
        let domain = domain.trim().to_ascii_lowercase();
        let conn = self.lock();
        let removed = conn.execute(
            "DELETE FROM catchall_assignments WHERE domain = ?1 AND account_id = ?2",
            params![domain, account_id],
        )?;
        if removed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    fn set_catchall_paused(&self, domain: &str, account_id: i64, paused: bool) -> Result<()> {
        let domain = domain.trim().to_ascii_lowercase();
        let conn = self.lock();
        let updated = conn.execute(
            "UPDATE catchall_assignments SET paused = ?3
              WHERE domain = ?1 AND account_id = ?2",
            params![domain, account_id, i64::from(paused)],
        )?;
        if updated == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    fn get_catchall_assignment(
        &self,
        domain: &str,
        account_id: i64,
    ) -> Result<Option<CatchallAssignmentRow>> {
        let domain = domain.trim().to_ascii_lowercase();
        let conn = self.lock();
        let raw = conn
            .query_row(
                &format!("{CATCHALL_ASSIGNMENT_SELECT} WHERE domain = ?1 AND account_id = ?2"),
                params![domain, account_id],
                map_raw_catchall_assignment,
            )
            .optional()?;
        raw.map(decode_catchall_assignment).transpose()
    }

    fn catchall_assignees(&self, domain: &str) -> Result<Vec<CatchallAssignmentRow>> {
        let domain = domain.trim().to_ascii_lowercase();
        let conn = self.lock();
        let mut statement = conn.prepare(&format!(
            "{CATCHALL_ASSIGNMENT_SELECT} WHERE domain = ?1 ORDER BY id"
        ))?;
        let rows = statement
            .query_map([domain], map_raw_catchall_assignment)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(decode_catchall_assignment).collect()
    }

    fn list_catchall_assignments(&self) -> Result<Vec<CatchallAssignmentRow>> {
        let conn = self.lock();
        let mut statement = conn.prepare(&format!("{CATCHALL_ASSIGNMENT_SELECT} ORDER BY id"))?;
        let rows = statement
            .query_map([], map_raw_catchall_assignment)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(decode_catchall_assignment).collect()
    }

    fn catchall_assignments_for_account(
        &self,
        account_id: i64,
    ) -> Result<Vec<CatchallAssignmentRow>> {
        let conn = self.lock();
        let mut statement = conn.prepare(&format!(
            "{CATCHALL_ASSIGNMENT_SELECT} WHERE account_id = ?1 ORDER BY id"
        ))?;
        let rows = statement
            .query_map([account_id], map_raw_catchall_assignment)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(decode_catchall_assignment).collect()
    }

    // ------------------------------------------------------- sender aliases

    fn create_alias(&self, address: &EmailAddress, created_by: i64) -> Result<i64> {
        let normalized = address.normalized();
        let domain = address.domain().to_ascii_lowercase();
        let conn = self.lock();
        require_account_exists(&conn, created_by)?;

        // An alias must never shadow a mailbox: mail to a real address is
        // delivered to that account's own inbox, and an alias with the same
        // spelling would silently turn one delivery into a copy for strangers.
        let account_holds: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE email_norm = ?1)",
            [&normalized],
            |row| row.get(0),
        )?;
        if account_holds {
            return Err(StoreError::InvalidArgument(format!(
                "{normalized} already belongs to an account: an alias is a free address, not a \
                 second name for a mailbox"
            )));
        }

        // An alias on a domain this deployment does not serve could never receive
        // mail nor send it: the SMTP server only accepts local parts of its own
        // domains, and DKIM has no key for a foreign one.
        let served: bool = conn.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM accounts
                  WHERE substr(email_norm, instr(email_norm, '@') + 1) = ?1
                 UNION ALL
                 SELECT 1 FROM dkim_keys WHERE domain = ?1
             )",
            [&domain],
            |row| row.get(0),
        )?;
        if !served {
            return Err(StoreError::InvalidArgument(format!(
                "{domain} is not a domain this deployment serves: an alias there could neither \
                 receive nor send mail"
            )));
        }

        let inserted = conn.execute(
            "INSERT INTO sender_aliases (address, domain, created_by) VALUES (?1, ?2, ?3)
             ON CONFLICT (address) DO NOTHING",
            params![normalized, domain, created_by],
        )?;
        if inserted == 0 {
            return Err(StoreError::Conflict);
        }
        Ok(conn.last_insert_rowid())
    }

    fn delete_alias(&self, alias_id: i64) -> Result<()> {
        let conn = self.lock();
        // The assignments cascade (foreign key with ON DELETE CASCADE), and
        // messages already delivered keep their `delivered_for` marker: history is
        // not rewritten because a grant was revoked.
        let removed = conn.execute("DELETE FROM sender_aliases WHERE id = ?1", [alias_id])?;
        if removed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    fn list_aliases(&self) -> Result<Vec<SenderAliasRow>> {
        let conn = self.lock();
        let mut statement = conn.prepare(&format!("{ALIAS_SELECT} ORDER BY id"))?;
        let rows = statement
            .query_map([], map_raw_alias)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(decode_alias).collect()
    }

    fn get_alias_by_address(&self, address: &str) -> Result<Option<SenderAliasRow>> {
        let normalized = EmailAddress::parse(address)?.normalized();
        let conn = self.lock();
        let raw = conn
            .query_row(
                &format!("{ALIAS_SELECT} WHERE address = ?1"),
                [&normalized],
                map_raw_alias,
            )
            .optional()?;
        raw.map(decode_alias).transpose()
    }

    fn get_alias(&self, alias_id: i64) -> Result<Option<SenderAliasRow>> {
        let conn = self.lock();
        let raw = conn
            .query_row(
                &format!("{ALIAS_SELECT} WHERE id = ?1"),
                [alias_id],
                map_raw_alias,
            )
            .optional()?;
        raw.map(decode_alias).transpose()
    }

    fn assign_alias(&self, alias_id: i64, account_id: i64, assigned_by: i64) -> Result<()> {
        let conn = self.lock();
        require_alias_exists(&conn, alias_id)?;
        require_account_exists(&conn, account_id)?;
        require_account_exists(&conn, assigned_by)?;
        let inserted = conn.execute(
            "INSERT INTO sender_alias_assignments (alias_id, account_id, assigned_by)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (alias_id, account_id) DO NOTHING",
            params![alias_id, account_id, assigned_by],
        )?;
        if inserted == 0 {
            return Err(StoreError::Conflict);
        }
        Ok(())
    }

    fn unassign_alias(&self, alias_id: i64, account_id: i64) -> Result<()> {
        let conn = self.lock();
        let removed = conn.execute(
            "DELETE FROM sender_alias_assignments WHERE alias_id = ?1 AND account_id = ?2",
            params![alias_id, account_id],
        )?;
        if removed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    fn aliases_for_account(&self, account_id: i64) -> Result<Vec<SenderAliasRow>> {
        let conn = self.lock();
        let mut statement = conn.prepare(&format!(
            "{ALIAS_SELECT} WHERE id IN (
                 SELECT alias_id FROM sender_alias_assignments WHERE account_id = ?1
             ) ORDER BY id"
        ))?;
        let rows = statement
            .query_map([account_id], map_raw_alias)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(decode_alias).collect()
    }

    fn accounts_for_alias(&self, address: &str) -> Result<Vec<i64>> {
        let normalized = EmailAddress::parse(address)?.normalized();
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT a.account_id FROM sender_alias_assignments a
               JOIN sender_aliases s ON s.id = a.alias_id
              WHERE s.address = ?1
              ORDER BY a.account_id",
        )?;
        let rows = statement
            .query_map([normalized], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<i64>>>()?;
        Ok(rows)
    }

    fn alias_assignments(&self, alias_id: i64) -> Result<Vec<AliasAssignmentRow>> {
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT alias_id, account_id, assigned_by, created_at
               FROM sender_alias_assignments WHERE alias_id = ?1 ORDER BY account_id",
        )?;
        let rows = statement
            .query_map([alias_id], |row| {
                Ok(AliasAssignmentRow {
                    alias_id: row.get(0)?,
                    account_id: row.get(1)?,
                    assigned_by: row.get(2)?,
                    created_at: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn is_address_taken(&self, address: &str) -> Result<bool> {
        let normalized = EmailAddress::parse(address)?.normalized();
        let conn = self.lock();
        let taken: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE email_norm = ?1)
                 OR EXISTS(SELECT 1 FROM sender_aliases WHERE address = ?1)",
            [&normalized],
            |row| row.get(0),
        )?;
        Ok(taken)
    }

    fn served_domains(&self) -> Result<Vec<String>> {
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT domain FROM (
                 SELECT substr(email_norm, instr(email_norm, '@') + 1) AS domain FROM accounts
                 UNION
                 SELECT domain FROM dkim_keys
             ) ORDER BY domain",
        )?;
        let rows = statement
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(rows)
    }

    fn put_pgp_key(
        &self,
        account_id: i64,
        public_armored: &str,
        private_sealed: &[u8],
        fingerprint: &str,
    ) -> Result<()> {
        self.check_pgp_key_args(account_id, public_armored, private_sealed, fingerprint)?;
        let conn = self.lock();
        conn.execute(
            "INSERT INTO pgp_keys (account_id, public_armored, private_sealed, fingerprint)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (account_id) DO UPDATE SET
                 public_armored = excluded.public_armored,
                 private_sealed = excluded.private_sealed,
                 fingerprint = excluded.fingerprint,
                 created_at = datetime('now')",
            params![account_id, public_armored, private_sealed, fingerprint],
        )?;
        Ok(())
    }

    fn insert_pgp_key_if_absent(
        &self,
        account_id: i64,
        public_armored: &str,
        private_sealed: &[u8],
        fingerprint: &str,
    ) -> Result<bool> {
        self.check_pgp_key_args(account_id, public_armored, private_sealed, fingerprint)?;
        let conn = self.lock();
        // `OR IGNORE`, not an upsert: a concurrent first use that already stored a
        // key must win, so the loser re-reads it instead of replacing an identity
        // some mail may already be sealed to.
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO pgp_keys
                 (account_id, public_armored, private_sealed, fingerprint)
             VALUES (?1, ?2, ?3, ?4)",
            params![account_id, public_armored, private_sealed, fingerprint],
        )?;
        Ok(inserted > 0)
    }

    fn get_pgp_key(&self, account_id: i64) -> Result<Option<PgpKeyRow>> {
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT account_id, public_armored, private_sealed, fingerprint, created_at
                   FROM pgp_keys WHERE account_id = ?1",
                [account_id],
                |row| {
                    Ok(PgpKeyRow {
                        account_id: row.get(0)?,
                        public_armored: row.get(1)?,
                        private_sealed: row.get(2)?,
                        fingerprint: row.get(3)?,
                        created_at: row.get(4)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    fn get_pgp_public_by_email(&self, email_norm: &str) -> Result<Option<(String, String)>> {
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT k.public_armored, k.fingerprint
                   FROM pgp_keys k
                   JOIN accounts a ON a.id = k.account_id
                  WHERE a.email_norm = ?1",
                [email_norm],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(row)
    }

    fn pin_pgp_peer_key(
        &self,
        email_norm: &str,
        fingerprint: &str,
        public_armored: &str,
        source: &str,
    ) -> Result<()> {
        if fingerprint.trim().is_empty() || public_armored.trim().is_empty() {
            return Err(StoreError::InvalidArgument(
                "a peer key pin needs a fingerprint and the certificate".to_string(),
            ));
        }
        let conn = self.lock();
        // `ON CONFLICT` deliberately touches only the audit columns: the key that
        // was pinned first stays the key this server seals to, whatever the
        // endpoint serves later.
        conn.execute(
            "INSERT INTO pgp_peer_keys (email_norm, fingerprint, public_armored, source)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (email_norm) DO UPDATE SET
                 last_seen_at = datetime('now'),
                 last_checked_at = datetime('now'),
                 pin_status = CASE
                     WHEN pgp_peer_keys.fingerprint = excluded.fingerprint THEN 'match'
                     ELSE 'mismatch:' || excluded.fingerprint
                 END",
            params![email_norm, fingerprint, public_armored, source],
        )?;
        Ok(())
    }

    fn accounts_on_domain(&self, domain: &str) -> Result<Vec<(i64, EmailAddress)>> {
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT id, email FROM accounts
              WHERE substr(email_norm, instr(email_norm, '@') + 1) = lower(?1)
              ORDER BY id",
        )?;
        let rows = statement.query_map([domain], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut accounts = Vec::new();
        for row in rows {
            let (id, raw) = row?;
            // A stored address that no longer parses is reported, not silently
            // skipped: publication answering "no key" for a broken row would hide
            // the corruption.
            accounts.push((id, EmailAddress::parse(&raw)?));
        }
        Ok(accounts)
    }

    fn get_pgp_peer_key(&self, email_norm: &str) -> Result<Option<PgpPeerKeyRow>> {
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT email_norm, fingerprint, public_armored, source,
                        first_seen_at, last_seen_at, pin_status, last_checked_at
                   FROM pgp_peer_keys WHERE email_norm = ?1",
                [email_norm],
                |row| {
                    Ok(PgpPeerKeyRow {
                        email_norm: row.get(0)?,
                        fingerprint: row.get(1)?,
                        public_armored: row.get(2)?,
                        source: row.get(3)?,
                        first_seen_at: row.get(4)?,
                        last_seen_at: row.get(5)?,
                        pin_status: row.get(6)?,
                        last_checked_at: row.get(7)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    fn delete_pgp_peer_key(&self, email_norm: &str) -> Result<bool> {
        let conn = self.lock();
        let removed = conn.execute(
            "DELETE FROM pgp_peer_keys WHERE email_norm = ?1",
            [email_norm],
        )?;
        Ok(removed > 0)
    }

    fn queue_mark_domains_delivered(&self, claim_token: &str, domains: &[String]) -> Result<()> {
        let fresh: Vec<String> = domains
            .iter()
            .map(|domain| domain.trim().to_ascii_lowercase())
            // A smarthost delivery is not domain-scoped: recording an empty name
            // would make the next attempt believe there is nothing left to do.
            .filter(|domain| !domain.is_empty())
            .collect();
        if fresh.is_empty() {
            return Ok(());
        }

        let conn = self.lock();
        // Read-modify-write inside one transaction, and only while this worker
        // still owns the row: a stale claim cannot write to somebody else's job.
        let tx = conn.unchecked_transaction()?;
        let current = tx
            .query_row(
                "SELECT delivered_domains FROM queue WHERE claim_token = ?1",
                [claim_token],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?;
        let Some(current) = current else {
            return Err(StoreError::QueueClaim(
                "no live claim owns that token".to_string(),
            ));
        };
        let mut merged =
            decode_optional_string_list("queue.delivered_domains", current.as_deref())?;
        for domain in fresh {
            if !merged.iter().any(|known| known == &domain) {
                merged.push(domain);
            }
        }
        let updated = tx.execute(
            "UPDATE queue SET delivered_domains = ?2 WHERE claim_token = ?1",
            params![claim_token, encode_string_list(&merged)?],
        )?;
        if updated == 0 {
            return Err(StoreError::QueueClaim(
                "no live claim owns that token".to_string(),
            ));
        }
        tx.commit()?;
        Ok(())
    }
}

impl SqliteStorage {
    /// Reject a PGP key row that could not be published or opened, and refuse an
    /// account that does not exist.
    fn check_pgp_key_args(
        &self,
        account_id: i64,
        public_armored: &str,
        private_sealed: &[u8],
        fingerprint: &str,
    ) -> Result<()> {
        if public_armored.trim().is_empty() || private_sealed.is_empty() {
            return Err(StoreError::InvalidArgument(
                "a PGP key needs both a public certificate and a sealed private key".to_string(),
            ));
        }
        if fingerprint.trim().is_empty() {
            return Err(StoreError::InvalidArgument(
                "a PGP key needs its fingerprint".to_string(),
            ));
        }
        // The account must exist: `account_id` is the primary key and a dangling
        // key would be published for an address that cannot receive mail.
        if self.get_account(account_id).is_err() {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}

/// Refuse an account address that a sender alias already owns.
///
/// The store-side half of [`Storage::is_address_taken`]: that predicate answers
/// "is this address used at all", and this guard is the half a `UNIQUE` index
/// cannot enforce — `accounts.email_norm` is unique, `sender_aliases.address` is
/// unique, but nothing in SQLite spans both tables. It must run inside the same
/// transaction as the insert, so an alias cannot appear between the check and the
/// write.
fn guard_alias_shadow(conn: &Connection, address: &EmailAddress) -> Result<()> {
    let normalized = address.normalized();
    let taken: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sender_aliases WHERE address = ?1)",
        [&normalized],
        |row| row.get(0),
    )?;
    if taken {
        return Err(StoreError::AliasShadow(normalized));
    }
    Ok(())
}

/// Refuse a write whose account does not exist, as [`StoreError::NotFound`].
fn require_account_exists(conn: &Connection, account_id: i64) -> Result<()> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM accounts WHERE id = ?1)",
        [account_id],
        |row| row.get(0),
    )?;
    if !exists {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

/// Refuse a write whose alias does not exist, as [`StoreError::NotFound`].
fn require_alias_exists(conn: &Connection, alias_id: i64) -> Result<()> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sender_aliases WHERE id = ?1)",
        [alias_id],
        |row| row.get(0),
    )?;
    if !exists {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

/// Columns [`Storage::get_org`] and its listings select, in [`map_org`] order.
const ORG_SELECT: &str = "SELECT id, name, created_at FROM orgs";

/// Columns the invitation queries select, in [`map_raw_invitation`] order.
///
/// `token_hash` is included because redemption has to verify against it; it never
/// reaches [`InvitationRow`].
const INVITATION_SELECT: &str = "\
SELECT id, org_id, email, role, invited_by, created_at, expires_at, accepted_at, token_hash \
  FROM invitations";

/// Columns the catch-all queries select, in [`map_raw_catchall`] order.
///
/// `target_account_id` is deliberately absent: the pre-`0014` single target is
/// migrated into `catchall_assignments` and nothing writes the column again.
const CATCHALL_SELECT: &str = "SELECT id, domain, action, created_at FROM catchall_rules";

/// Columns the catch-all assignment queries select, in
/// [`map_raw_catchall_assignment`] order.
const CATCHALL_ASSIGNMENT_SELECT: &str = "\
SELECT id, domain, account_id, assigned_by, paused, created_at FROM catchall_assignments";

/// Columns the sender-alias queries select, in [`map_raw_alias`] order.
const ALIAS_SELECT: &str = "SELECT id, address, domain, created_by, created_at FROM sender_aliases";

/// Refuse a change that would leave a real organization without an owner.
///
/// `current_org` is the account's organization *before* the change and
/// `next_org` the one it moves to. The guard applies only when the account
/// currently owns an organization (`current_org = Some(..)`) and would stop owning
/// *that* organization — because that organization would be left with nobody able
/// to administer it.
///
/// A personal workspace (`current_org = None`) is deliberately **not** guarded:
/// there is no organization row to strand, and creating a team from a personal
/// workspace moves an owner into a new organization without leaving anything
/// behind.
fn guard_last_owner(
    tx: &rusqlite::Transaction<'_>,
    account_id: i64,
    current_org: Option<i64>,
    current_role: OrgRole,
    next_role: OrgRole,
    next_org: Option<i64>,
) -> Result<()> {
    let Some(current_org) = current_org else {
        return Ok(());
    };
    let stops_owning = current_role == OrgRole::Owner
        && (next_role != OrgRole::Owner || next_org != Some(current_org));
    if !stops_owning {
        return Ok(());
    }
    let other_owners: i64 = tx.query_row(
        "SELECT COUNT(*) FROM accounts WHERE role = 'owner' AND id <> ?1 AND org_id = ?2",
        params![account_id, current_org],
        |row| row.get(0),
    )?;
    if other_owners == 0 {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

fn map_org(row: &rusqlite::Row<'_>) -> rusqlite::Result<OrgRow> {
    Ok(OrgRow {
        id: row.get(0)?,
        name: row.get(1)?,
        created_at: row.get(2)?,
    })
}

/// Raw invitation row: every column as stored, role and timestamps included,
/// before [`decode_invitation`] turns it into [`InvitationRow`].
struct RawInvitation {
    id: i64,
    org_id: i64,
    email: String,
    role: String,
    invited_by: i64,
    created_at: String,
    expires_at: String,
    accepted_at: Option<String>,
    token_hash: String,
}

fn map_raw_invitation(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawInvitation> {
    Ok(RawInvitation {
        id: row.get(0)?,
        org_id: row.get(1)?,
        email: row.get(2)?,
        role: row.get(3)?,
        invited_by: row.get(4)?,
        created_at: row.get(5)?,
        expires_at: row.get(6)?,
        accepted_at: row.get(7)?,
        token_hash: row.get(8)?,
    })
}

fn decode_invitation(raw: RawInvitation) -> Result<InvitationRow> {
    let role = OrgRole::parse(&raw.role).ok_or_else(|| {
        StoreError::Corrupt(format!(
            "invitations.role of invitation {} holds an unknown role {:?}",
            raw.id, raw.role
        ))
    })?;
    Ok(InvitationRow {
        id: raw.id,
        org_id: raw.org_id,
        email: raw.email,
        role,
        invited_by: raw.invited_by,
        created_at: raw.created_at,
        expires_at: raw.expires_at,
        accepted_at: raw.accepted_at,
    })
}

struct RawCatchall {
    id: i64,
    domain: String,
    action: String,
    created_at: String,
}

fn map_raw_catchall(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawCatchall> {
    Ok(RawCatchall {
        id: row.get(0)?,
        domain: row.get(1)?,
        action: row.get(2)?,
        created_at: row.get(3)?,
    })
}

fn decode_catchall(raw: RawCatchall) -> Result<CatchallRuleRow> {
    Ok(CatchallRuleRow {
        action: decode_catchall_action(&raw.domain, &raw.action)?,
        id: raw.id,
        domain: raw.domain,
        created_at: raw.created_at,
    })
}

struct RawCatchallAssignment {
    id: i64,
    domain: String,
    account_id: i64,
    assigned_by: i64,
    paused: i64,
    created_at: String,
}

fn map_raw_catchall_assignment(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawCatchallAssignment> {
    Ok(RawCatchallAssignment {
        id: row.get(0)?,
        domain: row.get(1)?,
        account_id: row.get(2)?,
        assigned_by: row.get(3)?,
        paused: row.get(4)?,
        created_at: row.get(5)?,
    })
}

fn decode_catchall_assignment(raw: RawCatchallAssignment) -> Result<CatchallAssignmentRow> {
    Ok(CatchallAssignmentRow {
        id: raw.id,
        domain: raw.domain,
        account_id: raw.account_id,
        assigned_by: raw.assigned_by,
        // Any non-zero value means paused; the column has a CHECK for 0/1, so this
        // only guards against a hand-edited row.
        paused: raw.paused != 0,
        created_at: raw.created_at,
    })
}

struct RawAlias {
    id: i64,
    address: String,
    domain: String,
    created_by: i64,
    created_at: String,
}

fn map_raw_alias(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawAlias> {
    Ok(RawAlias {
        id: row.get(0)?,
        address: row.get(1)?,
        domain: row.get(2)?,
        created_by: row.get(3)?,
        created_at: row.get(4)?,
    })
}

fn decode_alias(raw: RawAlias) -> Result<SenderAliasRow> {
    Ok(SenderAliasRow {
        id: raw.id,
        address: raw.address,
        domain: raw.domain,
        created_by: raw.created_by,
        created_at: raw.created_at,
    })
}

/// Trim a human name and refuse an empty one.
///
/// The store refuses rather than repairs: an organization with no name is not a
/// value the API is allowed to write, and silently substituting one here would
/// hide the bug above it.
fn require_name(what: &str, raw: &str) -> Result<String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(StoreError::InvalidArgument(format!("{what} needs a name")));
    }
    Ok(name.to_string())
}
