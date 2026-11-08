//! The outbound queue worker.
//!
//! Loop, every [`DEFAULT_POLL_INTERVAL`]:
//!
//! 1. `queue_claim` one due job (atomic, lease [`DEFAULT_LEASE_SECS`]),
//! 2. unseal the stored MIME with the master key,
//! 3. sign it with the `From:` domain's DKIM key, when this server holds one,
//! 4. hand the bytes to [`crate::client::OutboundSmtpClient`],
//! 5. record the verdict and settle the queue row:
//!
//! | verdict | queue | event |
//! |---|---|---|
//! | `Sent` | `queue_complete` | `email.sent` |
//! | `Deferred` | `queue_fail` + exponential backoff | `email.deferred` |
//! | `Bounced` (hard) | `queue_complete` + suppression | `email.bounced` |
//! | local failure | `queue_complete` | `email.failed` |
//!
//! # Why a bounce completes the job instead of failing it
//!
//! `Storage::queue_fail` re-arms a job until `max_attempts` is spent, because its
//! only terminal state is the dead-letter list. A `5xx` is permanent by
//! definition, so re-sending it would be wrong — and would delay the
//! `email.bounced` event by hours. The bounce is therefore recorded as the final
//! event and the queue row is dropped; surfacing bounced jobs in the dead-letter
//! listing needs a `status = 'bounced'` terminal state in `store` (tracked in
//! `docs/ROADMAP.md`).
//!
//! # Delivery is per recipient domain, and retries never duplicate a delivery
//!
//! [`crate::client::OutboundSmtpClient::deliver`] opens one SMTP transaction per
//! recipient domain, because MX records belong to the recipient's domain (issue
//! #70). The queue still holds **one row per message**, so the worker sees the
//! aggregate verdict: a message whose recipients span `example.org` (accepted)
//! and `example.net` (deferred) stays queued, and a `5xx` suppresses only the
//! addresses that actually bounced — never the whole recipient list.
//!
//! The dangerous half of that shape is the **retry**. Re-sending the whole message
//! would deliver a second copy to the domain that already accepted it, so every
//! domain that reached a terminal verdict in an attempt is recorded on the queue
//! row ([`store::Storage::queue_mark_domains_delivered`]) and the next attempt
//! filters them out before calling the client. A domain is terminal when it
//! answered `2xx`, `5xx` or a local refusal; only a deferral keeps it outstanding.
//! Once nothing is outstanding the job is settled, and a job whose every domain is
//! already delivered is completed without opening a connection at all.
//!
//! # DKIM keys
//!
//! Signing keys are **per sending domain**, so the worker looks one up for every
//! outbound message instead of holding a single configured key: [`DkimKeySource`]
//! is the seam, and [`StoreDkimKeys`] is the production implementation that reads
//! `store`'s `dkim_keys` row for the `From:` domain and unseals it under the
//! master key.
//!
//! Two outcomes are both normal:
//!
//! * **a key is found** — the message is signed with it and delivered;
//! * **no key is found** — the domain is not managed here (a relay, a customer
//!   domain this instance does not hold), so the message goes out unsigned and an
//!   `info` line records it. This is a configuration state, not a fault, which is
//!   why it is not a `warn`: a self-hosted instance with one account would
//!   otherwise log a warning on every single delivery.
//!
//! A key that exists but cannot be used — a wrapped blob sealed under another
//! master key, a truncated row — is **not** a silent downgrade: it fails the job
//! as a permanent error. Sending unsigned after a failed unseal would hide a
//! broken key behind plausible-looking mail, and DMARC would report the domain as
//! unsigned while the operator believes it is signed.
//!
//! # Rebuilding the key pair on every send
//!
//! [`pigeon_dkim::DkimKeyPair::from_pkcs8_der`] parses PKCS#8 on each delivery.
//! That is deliberate and cheap: RSA *parsing* is a DER decode (microseconds),
//! whereas RSA *generation* is the expensive operation and happens once, when the
//! domain is added. Caching parsed keys would buy almost nothing and would mean
//! holding private key material in memory for the life of the process.

use std::sync::Arc;
use std::time::Duration;

use pigeon_api::db::ApiDb;
use pigeon_api::dkim::open_private_key;
use pigeon_core::EmailAddress;
use pigeon_crypto::MasterKey;
use pigeon_dkim::DkimKeyPair;
use store::{ClaimedJob, SqliteStorage, Storage};

use crate::client::{DeliveryResult, DeliveryStatus, OutboundSmtpClient};
use crate::error::{Result, SmtpError};
use crate::server::parse_message;

/// How long to wait between polls when the queue is empty.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Claim lease: a worker that dies holding a job blocks it for at most this long.
pub const DEFAULT_LEASE_SECS: u64 = 300;

/// Retry schedule in seconds, indexed by attempts already spent:
/// 30s, 1m, 2m, 5m, 15m, 1h, 24h — the last entry repeats for every further
/// attempt, and `store` dead-letters the job once `max_attempts` is reached.
pub const BACKOFF_SCHEDULE_SECS: [u64; 7] = [30, 60, 120, 300, 900, 3600, 86_400];

/// Backoff before the retry that follows `attempts` spent attempts.
///
/// `attempts` is at least 1 for a claimed job (the claim increments it), so a
/// first failure waits [`BACKOFF_SCHEDULE_SECS`]`[0]`; zero or negative input is
/// clamped to the same first entry, and anything past the schedule is clamped to
/// the 24-hour ceiling.
pub fn backoff_secs(attempts: i64) -> u64 {
    let index = usize::try_from(attempts.max(1) - 1).unwrap_or(usize::MAX);
    BACKOFF_SCHEDULE_SECS[index.min(BACKOFF_SCHEDULE_SECS.len() - 1)]
}

/// Where [`QueueWorker`] gets the DKIM key for a sending domain.
///
/// The seam exists so the delivery loop never reaches into storage itself: a test
/// can serve a key from anywhere, and the production implementation is
/// [`StoreDkimKeys`].
///
/// `Ok(None)` means "this domain has no key here", which is a normal state and
/// produces unsigned mail. `Err` means a key exists but is unusable, which the
/// worker treats as permanent — see the module docs.
pub trait DkimKeySource: Send + Sync {
    /// The signing key for `domain`, or `None` when the domain is not managed.
    fn key_for(&self, domain: &str) -> Result<Option<DkimKeyPair>>;
}

/// The production [`DkimKeySource`]: `store`'s `dkim_keys` row, unsealed under
/// the master key.
///
/// Lookups are by domain name because that is what DKIM resolves: the selector
/// plus the `From:` domain is all a verifier needs, and the store enforces one
/// identity per domain.
pub struct StoreDkimKeys {
    store: Arc<SqliteStorage>,
    master_key: Arc<MasterKey>,
}

impl StoreDkimKeys {
    /// Build a source over the shared store and master key.
    pub fn new(store: Arc<SqliteStorage>, master_key: Arc<MasterKey>) -> Self {
        Self { store, master_key }
    }
}

impl DkimKeySource for StoreDkimKeys {
    fn key_for(&self, domain: &str) -> Result<Option<DkimKeyPair>> {
        let Some((selector, wrapped, _public_dns)) = self.store.get_dkim_key(domain)? else {
            return Ok(None);
        };
        let pkcs8_der = open_private_key(&self.master_key, domain, &wrapped)?;
        Ok(Some(DkimKeyPair::from_pkcs8_der(
            selector, domain, &pkcs8_der,
        )?))
    }
}

impl std::fmt::Debug for StoreDkimKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the master key or a decrypted key.
        f.debug_struct("StoreDkimKeys").finish_non_exhaustive()
    }
}

/// Worker tuning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerConfig {
    /// Label stored in `queue.claimed_by`, for observability.
    pub worker_id: String,
    /// Claim lease in seconds.
    pub lease_secs: u64,
    /// Idle poll interval.
    pub poll_interval: Duration,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            // Two servers sharing one database must not look like one worker in
            // the queue rows; the pid is enough to tell them apart in logs.
            worker_id: format!("pigeon-smtp-{}", std::process::id()),
            lease_secs: DEFAULT_LEASE_SECS,
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }
}

/// The delivery worker.
pub struct QueueWorker {
    store: Arc<SqliteStorage>,
    db: Arc<ApiDb>,
    master_key: Arc<MasterKey>,
    client: Arc<OutboundSmtpClient>,
    dkim: Arc<dyn DkimKeySource>,
    config: WorkerConfig,
}

impl QueueWorker {
    /// Build a worker.
    ///
    /// `dkim` supplies the signing key for each message's `From:` domain; the
    /// binary wires [`StoreDkimKeys`], and tests may inject any other source.
    pub fn new(
        store: Arc<SqliteStorage>,
        db: Arc<ApiDb>,
        master_key: Arc<MasterKey>,
        client: Arc<OutboundSmtpClient>,
        dkim: Arc<dyn DkimKeySource>,
        config: WorkerConfig,
    ) -> Self {
        Self {
            store,
            db,
            master_key,
            client,
            dkim,
            config,
        }
    }

    /// Poll until `shutdown` resolves.
    ///
    /// A claimed job is always finished before the loop looks at the shutdown
    /// signal again: dropping a claim mid-delivery would only block the message
    /// until the lease expires.
    pub async fn run<F>(self, shutdown: F)
    where
        F: std::future::Future<Output = ()> + Send,
    {
        tokio::pin!(shutdown);
        let mut idle = true;
        loop {
            if idle {
                tokio::select! {
                    () = &mut shutdown => {
                        tracing::info!("smtp queue worker shutting down");
                        return;
                    }
                    () = tokio::time::sleep(self.config.poll_interval) => {}
                }
            }

            let claimed = tokio::select! {
                () = &mut shutdown => {
                    tracing::info!("smtp queue worker shutting down");
                    return;
                }
                claimed = self.claim_one() => claimed,
            };

            match claimed {
                Ok(Some(job)) => {
                    idle = false;
                    if let Err(error) = self.process(job).await {
                        // The queue row is settled by `process`; an error here is
                        // only a bookkeeping failure worth a log line.
                        tracing::error!(%error, "queue job could not be settled");
                    }
                }
                Ok(None) => idle = true,
                Err(error) => {
                    tracing::error!(%error, "queue claim failed");
                    idle = true;
                }
            }
        }
    }

    /// Drain up to `max_jobs` due jobs. Returns how many were settled.
    ///
    /// This is the deterministic entry point for tests and for a one-shot
    /// `pigeon` invocation: no sleeping, no shutdown future.
    pub async fn drain(&self, max_jobs: usize) -> Result<usize> {
        let mut settled = 0;
        while settled < max_jobs {
            match self.claim_one().await? {
                Some(job) => {
                    self.process(job).await?;
                    settled += 1;
                }
                None => break,
            }
        }
        Ok(settled)
    }

    /// Claim at most one job without blocking the runtime.
    async fn claim_one(&self) -> Result<Option<ClaimedJob>> {
        let store = Arc::clone(&self.store);
        let worker_id = self.config.worker_id.clone();
        let lease_secs = self.config.lease_secs;
        let job = tokio::task::spawn_blocking(move || store.queue_claim(&worker_id, lease_secs))
            .await
            .map_err(|error| SmtpError::Protocol(format!("claim task failed: {error}")))??;
        Ok(job)
    }

    /// Unseal, sign, deliver and settle one job.
    async fn process(&self, job: ClaimedJob) -> Result<()> {
        let prepared = {
            let store = Arc::clone(&self.store);
            let db = Arc::clone(&self.db);
            let master_key = Arc::clone(&self.master_key);
            let dkim = Arc::clone(&self.dkim);
            let message_id = job.message_id;
            tokio::task::spawn_blocking(move || {
                prepare(&store, &db, &master_key, dkim.as_ref(), message_id)
            })
            .await
            .map_err(|error| SmtpError::Protocol(format!("prepare task failed: {error}")))?
        };

        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(PrepareError::Permanent(reason)) => {
                tracing::error!(message_id = job.message_id, %reason, "message cannot be delivered");
                self.record_event(job.message_id, "email.failed", &reason);
                return self.complete(&job, "undeliverable message");
            }
            Err(PrepareError::Transient(reason)) => {
                tracing::warn!(message_id = job.message_id, %reason, "message is not ready yet");
                self.record_event(job.message_id, "email.deferred", &reason);
                return self.fail(&job, &reason);
            }
        };

        // Retry safety: an earlier attempt may already have delivered to some of
        // these domains. Delivering to them again is duplicate mail, so they are
        // filtered out before the client ever opens a connection.
        let outstanding: Vec<EmailAddress> = prepared
            .recipients
            .iter()
            .filter(|recipient| {
                !job.delivered_domains
                    .iter()
                    .any(|delivered| delivered.eq_ignore_ascii_case(recipient.domain()))
            })
            .cloned()
            .collect();
        if outstanding.is_empty() {
            tracing::info!(
                message_id = job.message_id,
                delivered = ?job.delivered_domains,
                "every recipient domain was already delivered: settling without a connection"
            );
            self.settle_status(&prepared, "sent");
            self.record_event(
                job.message_id,
                "email.sent",
                "every recipient domain was delivered by an earlier attempt",
            );
            return self.complete(&job, "already delivered");
        }

        let result = self
            .client
            .deliver(&prepared.from, &outstanding, &prepared.mime)
            .await;

        let result = match result {
            Ok(result) => result,
            Err(error) => {
                // Resolution/transport problems are transient: retry.
                let reason = error.to_string();
                tracing::warn!(message_id = job.message_id, %reason, "delivery attempt failed");
                self.record_event(job.message_id, "email.deferred", &reason);
                return self.fail(&job, &reason);
            }
        };

        // Record what this attempt finished, *before* deciding what to do next: a
        // crash right after `queue_fail` must not lose the fact that some domains
        // already received the message.
        self.record_delivered_domains(&job, &result);

        let detail = format!(
            "mx={} code={} {}",
            result.mx_host, result.code, result.message
        );
        match result.status {
            DeliveryStatus::Sent => {
                tracing::info!(message_id = job.message_id, %detail, "email sent");
                self.record_event(job.message_id, "email.sent", &detail);
                self.settle_status(&prepared, "sent");
                self.complete(&job, "delivered")
            }
            DeliveryStatus::Deferred => {
                tracing::info!(message_id = job.message_id, %detail, "delivery deferred");
                self.record_event(job.message_id, "email.deferred", &detail);
                self.settle_status(&prepared, "deferred");
                self.fail(&job, &detail)
            }
            DeliveryStatus::Bounced => {
                tracing::warn!(message_id = job.message_id, %detail, "delivery bounced");
                self.record_event(job.message_id, "email.bounced", &detail);
                self.settle_status(&prepared, "bounced");
                // Only the domains that answered `5xx`: another recipient domain
                // of the same message may have accepted it.
                self.suppress(&prepared, &result, &detail);
                self.complete(&job, "bounced")
            }
            DeliveryStatus::Failed => {
                tracing::error!(message_id = job.message_id, %detail, "delivery refused locally");
                self.record_event(job.message_id, "email.failed", &detail);
                self.settle_status(&prepared, "failed");
                self.complete(&job, "local failure")
            }
        }
    }

    /// Persist the recipient domains this attempt finished for good.
    ///
    /// Only domains with a **terminal** verdict are recorded: `Deferred` means the
    /// domain is still owed the message, so it must stay outstanding. A relay
    /// delivery reports an empty domain name and is skipped by the store, because a
    /// smarthost is not domain-scoped — recording it would make the retry believe
    /// there is nothing left to send.
    fn record_delivered_domains(&self, job: &ClaimedJob, result: &DeliveryResult) {
        let domains: Vec<String> = result
            .groups
            .iter()
            .filter(|group| group.result.status != DeliveryStatus::Deferred)
            .map(|group| group.domain.clone())
            .filter(|domain| !domain.is_empty())
            .collect();
        if domains.is_empty() {
            return;
        }
        if let Err(error) = self
            .store
            .queue_mark_domains_delivered(&job.claim_token, &domains)
        {
            // Losing this write is not fatal for *this* attempt, but it is exactly
            // what causes duplicate mail on the next one, so it is an error line.
            tracing::error!(
                %error,
                message_id = job.message_id,
                domains = ?domains,
                "could not record the delivered domains; a retry may duplicate them"
            );
        }
    }

    /// Record an event, logging (never failing) when the write fails: the
    /// delivery verdict is more important than its audit trail.
    fn record_event(&self, message_id: i64, kind: &str, detail: &str) {
        if let Err(error) = self.store.record_event(message_id, kind, detail) {
            tracing::error!(%error, message_id, kind, "could not record delivery event");
        }
    }

    /// Mirror the verdict onto the API lifecycle row, when there is one.
    fn settle_status(&self, prepared: &Prepared, status: &str) {
        if let Err(error) =
            self.db
                .set_email_status(prepared.account_id, &prepared.public_id, status)
        {
            tracing::warn!(
                %error,
                public_id = %prepared.public_id,
                "could not update the email status"
            );
        }
    }

    /// Add hard-bounced recipients to the account's suppression list.
    ///
    /// Suppression is scoped to the sending account (the message owner), not to
    /// the domain: one account's bounce must not silence another account's mail.
    /// Recipients are taken from the domains the `5xx` actually came from, so a
    /// single bounced address never suppresses a sibling recipient that was
    /// delivered.
    fn suppress(&self, prepared: &Prepared, result: &DeliveryResult, detail: &str) {
        let bounced = result.recipients_with(DeliveryStatus::Bounced);
        if bounced.is_empty() {
            return;
        }
        if let Err(error) = self.db.insert_suppressions(
            prepared.account_id,
            &bounced,
            &format!("hard bounce: {detail}"),
            Some("smtp"),
        ) {
            tracing::warn!(%error, "could not record bounces as suppressions");
        }
    }

    fn complete(&self, job: &ClaimedJob, reason: &str) -> Result<()> {
        self.store
            .queue_complete(&job.claim_token)
            .map_err(|error| {
                tracing::error!(%error, message_id = job.message_id, reason, "queue_complete rejected");
                SmtpError::Store(error)
            })
    }

    fn fail(&self, job: &ClaimedJob, reason: &str) -> Result<()> {
        let backoff = backoff_secs(job.attempts);
        tracing::info!(
            message_id = job.message_id,
            attempts = job.attempts,
            backoff_secs = backoff,
            "re-queued for a later attempt"
        );
        self.store
            .queue_fail(&job.claim_token, reason, backoff)
            .map_err(|error| {
                tracing::error!(%error, message_id = job.message_id, "queue_fail rejected");
                SmtpError::Store(error)
            })
    }
}

impl std::fmt::Debug for QueueWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueueWorker")
            .field("config", &self.config)
            .field("dkim", &"injected source")
            .finish_non_exhaustive()
    }
}

/// A message ready to be put on the wire.
///
/// `recipients` is the **whole** envelope; [`QueueWorker::process`] filters out the
/// domains an earlier attempt already delivered to before handing it to the client.
struct Prepared {
    account_id: i64,
    public_id: String,
    from: EmailAddress,
    recipients: Vec<EmailAddress>,
    /// Unsealed MIME, carrying a `DKIM-Signature` when the `From:` domain has a
    /// key in the store.
    mime: Vec<u8>,
}

/// Why preparing a job failed, in terms of what the queue should do next.
enum PrepareError {
    /// Retrying cannot help (unreadable body, missing key material).
    Permanent(String),
    /// The database or a lock was unavailable; try again later.
    Transient(String),
}

impl From<store::StoreError> for PrepareError {
    fn from(error: store::StoreError) -> Self {
        match &error {
            // A row that no longer decodes is not going to start decoding.
            store::StoreError::Corrupt(_) | store::StoreError::NotFound => {
                PrepareError::Permanent(error.to_string())
            }
            _ => PrepareError::Transient(error.to_string()),
        }
    }
}

/// Load and open one stored message. Runs on the blocking pool.
fn prepare(
    store: &SqliteStorage,
    db: &ApiDb,
    master_key: &MasterKey,
    dkim: &dyn DkimKeySource,
    message_id: i64,
) -> std::result::Result<Prepared, PrepareError> {
    let row = store.get_message(message_id)?;
    let public_id = db
        .public_id_for_message(message_id)
        .map_err(PrepareError::from)?
        .ok_or_else(|| PrepareError::Permanent("message has no public id".to_string()))?;
    let stored = db
        .message_by_public_id(row.account_id, &public_id)
        .map_err(PrepareError::from)?
        .ok_or_else(|| PrepareError::Permanent(format!("message {public_id} disappeared")))?;
    let wrapped_key = stored.wrapped_key.ok_or_else(|| {
        PrepareError::Permanent(format!("message {public_id} has no wrapped content key"))
    })?;

    let message_aad = format!("account:{}:message:{message_id}", row.account_id);
    let content_key = master_key
        .unwrap_content_key(&wrapped_key, message_aad.as_bytes())
        .map_err(|error| {
            PrepareError::Permanent(format!("content key cannot be unwrapped: {error}"))
        })?;
    let mime = pigeon_crypto::open_content(&content_key, &row.sealed_body, message_aad.as_bytes())
        .map_err(|error| {
            PrepareError::Permanent(format!("sealed body cannot be opened: {error}"))
        })?;

    // Sign with the key for the *From:* domain — the domain a verifier will
    // resolve, and the only one whose key can legitimately sign this message.
    let from_domain = row.from_addr.domain().to_string();
    let mime = match dkim.key_for(&from_domain) {
        Ok(Some(key)) => sign_mime(&key, &mime)
            .map_err(|error| PrepareError::Permanent(format!("DKIM signing failed: {error}")))?,
        Ok(None) => {
            // Legitimate: this instance does not manage the domain, so there is
            // nothing to sign with. `info`, not `warn` — see the module docs.
            tracing::info!(
                message_id,
                from_domain,
                "no DKIM key for the sending domain; delivering unsigned"
            );
            mime
        }
        Err(error) => {
            // A key we hold but cannot use is a defect (wrong master key,
            // corrupt row). Failing loudly beats a silent unsigned downgrade.
            return Err(PrepareError::Permanent(format!(
                "DKIM key for {from_domain} is unusable: {error}"
            )));
        }
    };

    Ok(Prepared {
        account_id: row.account_id,
        public_id,
        from: row.from_addr,
        recipients: row.to_addrs,
        mime,
    })
}

/// Add a `DKIM-Signature` header to `mime`, signing exactly the headers
/// `pigeon-dkim` supports (`From`, `To`, `Subject`, `Date`, `Message-ID`).
pub(crate) fn sign_mime(key: &DkimKeyPair, mime: &[u8]) -> Result<Vec<u8>> {
    let parsed = parse_message(mime);
    // The signer needs the values it canonicalizes; a message without them is a
    // generator bug, not a recipient problem, so it fails loudly.
    let pick = |name: &str| {
        parsed
            .header(name)
            .map(str::to_string)
            .ok_or_else(|| SmtpError::Dkim(pigeon_dkim::DkimError::MissingHeader(name.to_string())))
    };
    let from = pick("From")?;
    let to = pick("To")?;
    let subject = pick("Subject")?;
    let date = pick("Date")?;
    let message_id = pick("Message-ID")?;
    let body = String::from_utf8_lossy(&parsed.body);
    let signature =
        pigeon_dkim::sign_message(key, &from, &to, &subject, &date, &message_id, &body)?;

    let mut out = Vec::with_capacity(mime.len() + signature.len() + 32);
    out.extend_from_slice(b"DKIM-Signature: ");
    out.extend_from_slice(signature.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(mime);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_follows_the_documented_schedule() {
        assert_eq!(backoff_secs(1), 30);
        assert_eq!(backoff_secs(2), 60);
        assert_eq!(backoff_secs(3), 120);
        assert_eq!(backoff_secs(4), 300);
        assert_eq!(backoff_secs(5), 900);
        assert_eq!(backoff_secs(6), 3600);
        assert_eq!(backoff_secs(7), 86_400);
    }

    #[test]
    fn backoff_is_clamped_at_both_ends() {
        assert_eq!(backoff_secs(0), 30, "a first failure waits the first step");
        assert_eq!(backoff_secs(-5), 30);
        assert_eq!(backoff_secs(8), 86_400);
        assert_eq!(backoff_secs(i64::MAX), 86_400);
    }

    #[test]
    fn dkim_signature_is_prepended_and_matches_the_signed_headers() {
        let key = DkimKeyPair::generate("mail", "example.com").expect("key");
        let mime = b"From: Dana <dana@example.com>\r\nTo: carol@example.net\r\nSubject: hi\r\nDate: Fri, 06 Nov 2026 00:00:00 +0000\r\nMessage-ID: <eml_1@example.com>\r\nMIME-Version: 1.0\r\n\r\nbody\r\n";
        let signed = sign_mime(&key, mime).expect("signs");
        let text = String::from_utf8(signed.clone()).expect("utf8");
        assert!(text.starts_with("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;"));
        assert!(text.contains("d=example.com; s=mail;"));
        assert!(text.contains("h=from:to:subject:date:message-id;"));
        assert!(text.contains("bh="));
        // The original bytes follow verbatim, so nothing the caller stored is
        // lost or reordered.
        assert!(text.contains("MIME-Version: 1.0\r\n\r\nbody\r\n"));
    }

    #[test]
    fn signing_a_message_without_the_signed_headers_is_an_error() {
        let key = DkimKeyPair::generate("mail", "example.com").expect("key");
        let error = sign_mime(&key, b"Subject: only\r\n\r\nbody").expect_err("missing From");
        assert!(matches!(
            error,
            SmtpError::Dkim(pigeon_dkim::DkimError::MissingHeader(name)) if name == "From"
        ));
    }

    #[test]
    fn worker_config_defaults_are_the_documented_ones() {
        let config = WorkerConfig::default();
        assert_eq!(config.lease_secs, 300);
        assert_eq!(config.poll_interval, Duration::from_secs(5));
        assert!(config.worker_id.starts_with("pigeon-smtp-"));
    }
}
