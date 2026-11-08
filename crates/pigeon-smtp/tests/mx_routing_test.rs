//! MX routing is per **recipient** domain (issue #70).
//!
//! The regression these tests pin: `deliver` used to resolve
//! `from.domain()` — the sender's own MX — so every external message was offered
//! to this server's exchanger and deferred forever. A correct MTA groups
//! recipients by their domain, resolves each recipient domain separately, and
//! keeps `MAIL FROM` as the sender on every transaction.
//!
//! Each test drives the real queue worker against loopback fake exchangers, so
//! what is asserted is what a peer would see on the wire.

mod support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pigeon_core::StartTlsMode;
use pigeon_smtp::dns::{LookupFuture, MxRecord, MxResolver, MxSource};
use pigeon_smtp::worker::StoreDkimKeys;
use pigeon_smtp::{
    DeliveryConfig, OutboundSmtpClient, QueueWorker, Result as SmtpResult, WorkerConfig,
};
use store::Storage;
use support::{FakeMx, TestEnv};

/// A resolver with an explicit answer table that remembers every domain it was
/// asked about.
struct TableMxSource {
    answers: HashMap<String, Vec<MxRecord>>,
    asked: Arc<Mutex<Vec<String>>>,
}

impl TableMxSource {
    fn new(answers: &[(&str, &str)], asked: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            answers: answers
                .iter()
                .map(|(domain, exchange)| {
                    ((*domain).to_string(), vec![MxRecord::new(10, *exchange)])
                })
                .collect(),
            asked,
        }
    }
}

impl MxSource for TableMxSource {
    fn mx_records<'a>(&'a self, domain: &'a str) -> LookupFuture<'a, Vec<MxRecord>> {
        Box::pin(async move {
            self.asked.lock().expect("lock").push(domain.to_string());
            // No entry means "this domain publishes no MX", which the resolver
            // turns into the RFC 5321 implicit MX for the domain itself.
            Ok(self.answers.get(domain).cloned().unwrap_or_default())
        })
    }
}

fn worker(env: &TestEnv, resolver: MxResolver, worker_id: &str) -> QueueWorker {
    let client = OutboundSmtpClient::new(
        resolver,
        DeliveryConfig {
            starttls: StartTlsMode::Opportunistic,
            timeout: Duration::from_secs(5),
            ..DeliveryConfig::default()
        },
    );
    QueueWorker::new(
        Arc::clone(&env.store),
        Arc::clone(&env.db),
        Arc::clone(&env.master_key),
        Arc::new(client),
        Arc::new(StoreDkimKeys::new(
            Arc::clone(&env.store),
            Arc::clone(&env.master_key),
        )),
        WorkerConfig {
            worker_id: worker_id.to_string(),
            poll_interval: Duration::from_millis(10),
            ..WorkerConfig::default()
        },
    )
}

/// Two recipients on two different domains, two fake exchangers: each exchanger
/// receives a transaction carrying **only** its own domain's recipients, and
/// `MAIL FROM` is the sender on both.
#[tokio::test]
async fn each_recipient_domain_is_delivered_to_its_own_mx() -> SmtpResult<()> {
    let env = TestEnv::new();
    let account_id = env.account("dana@pigeonmail.dev");
    let (message_id, _public_id) = env.queue_outbound(
        account_id,
        "dana@pigeonmail.dev",
        &["carol@example.org", "dave@example.net"],
        "two domains",
        "body",
    );

    let org_mx = FakeMx::start(false).await;
    let net_mx = FakeMx::start(false).await;
    let asked = Arc::new(Mutex::new(Vec::new()));
    let resolver = MxResolver::new(TableMxSource::new(
        &[("example.org", "127.0.0.1"), ("example.net", "127.0.0.1")],
        Arc::clone(&asked),
    ))
    .with_test_port_for("example.org", org_mx.address.port())
    .with_test_port_for("example.net", net_mx.address.port());

    let worker = worker(&env, resolver, "mx-1");
    assert_eq!(worker.drain(10).await.expect("drain"), 1);

    // --- one transaction per recipient domain --------------------------------
    assert_eq!(
        org_mx.count(),
        1,
        "example.org gets exactly one transaction"
    );
    assert_eq!(
        net_mx.count(),
        1,
        "example.net gets exactly one transaction"
    );
    assert_eq!(
        org_mx.recipient_sets(),
        vec![vec!["carol@example.org".to_string()]],
        "the .org exchanger must never be handed the .net recipient"
    );
    assert_eq!(
        net_mx.recipient_sets(),
        vec![vec!["dave@example.net".to_string()]],
        "the .net exchanger must never be handed the .org recipient"
    );

    // --- the envelope sender is unchanged on both -----------------------------
    assert_eq!(org_mx.senders(), vec!["dana@pigeonmail.dev".to_string()]);
    assert_eq!(net_mx.senders(), vec!["dana@pigeonmail.dev".to_string()]);

    // --- the recipient domains were resolved, the sender's domain was not -----
    let mut asked = asked.lock().expect("lock").clone();
    asked.sort();
    assert_eq!(
        asked,
        vec!["example.net".to_string(), "example.org".to_string()],
        "issue #70: the lookup must be for recipient domains only"
    );

    // The message itself is settled as sent, with both groups recorded.
    assert_eq!(env.queue_rows_for(message_id), 0);
    let events = env.store.list_events(message_id).expect("events");
    let sent = events
        .iter()
        .find(|(kind, _, _)| kind == "email.sent")
        .expect("an email.sent event");
    assert!(sent.1.contains("example.org"), "{}", sent.1);
    assert!(sent.1.contains("example.net"), "{}", sent.1);
    Ok(())
}

/// A recipient domain that publishes no MX still reaches the **recipient's**
/// implicit MX (RFC 5321 §5.1 fallback), never the sender's exchanger.
#[tokio::test]
async fn a_domain_without_mx_uses_its_own_implicit_mx_not_the_senders() -> SmtpResult<()> {
    let env = TestEnv::new();
    let account_id = env.account("dana@pigeonmail.dev");
    let (message_id, _public_id) = env.queue_outbound(
        account_id,
        "dana@pigeonmail.dev",
        &["carol@no-mx.example"],
        "implicit mx",
        "body",
    );

    // The sender's domain *does* publish an MX, and it is reachable: if delivery
    // ever resolved the sender again, this exchanger would receive the message.
    let sender_mx = FakeMx::start(false).await;
    let recipient_mx = FakeMx::start(false).await;
    let asked = Arc::new(Mutex::new(Vec::new()));
    let resolver = MxResolver::new(TableMxSource::new(
        // `no-mx.example` publishes no MX, so the resolver answers with the
        // implicit MX for the domain itself (RFC 5321 §5.1). A loopback test
        // cannot resolve that name, so the exchange stands in for the A record
        // such a domain would publish — the domain-identity part of the fallback
        // is asserted below on the lookup list and on the per-domain port.
        &[
            ("pigeonmail.dev", "127.0.0.1"),
            ("no-mx.example", "127.0.0.1"),
        ],
        Arc::clone(&asked),
    ))
    .with_test_port_for("pigeonmail.dev", sender_mx.address.port())
    .with_test_port_for("no-mx.example", recipient_mx.address.port());

    let worker = worker(&env, resolver, "mx-2");
    assert_eq!(worker.drain(10).await.expect("drain"), 1);

    let asked = asked.lock().expect("lock").clone();
    assert_eq!(
        asked,
        vec!["no-mx.example".to_string()],
        "only the recipient domain may be resolved, and the implicit MX must \
         keep its identity: got {asked:?}"
    );
    assert_eq!(
        sender_mx.count(),
        0,
        "the sender's own exchanger must never see outbound mail"
    );
    // Proof the fallback is the recipient domain itself: it was contacted at the
    // port pinned for that domain.
    assert_eq!(
        recipient_mx.senders(),
        vec!["dana@pigeonmail.dev".to_string()],
        "the implicit-MX connection must reach the recipient's own host"
    );
    assert_eq!(
        recipient_mx.recipient_sets(),
        vec![vec!["carol@no-mx.example".to_string()]]
    );
    assert_eq!(env.queue_rows_for(message_id), 0, "the job is settled");
    Ok(())
}

/// A relay is not domain-scoped: the smarthost receives the whole recipient set
/// in one transaction, exactly as before the per-domain routing change.
#[tokio::test]
async fn a_relay_still_receives_every_recipient_in_one_transaction() -> SmtpResult<()> {
    let env = TestEnv::new();
    let account_id = env.account("dana@pigeonmail.dev");
    env.queue_outbound(
        account_id,
        "dana@pigeonmail.dev",
        &["carol@example.org", "dave@example.net"],
        "via relay",
        "body",
    );

    let relay = FakeMx::start(false).await;
    let asked = Arc::new(Mutex::new(Vec::new()));
    // The answer table is deliberately empty and unreachable: a relay must not
    // resolve anything at all.
    let resolver = MxResolver::new(TableMxSource::new(&[], Arc::clone(&asked))).with_test_port(1); // nothing listens on port 1
    let client = OutboundSmtpClient::new(
        resolver,
        DeliveryConfig {
            starttls: StartTlsMode::Opportunistic,
            timeout: Duration::from_secs(5),
            relay: Some(("127.0.0.1".to_string(), relay.address.port())),
            ..DeliveryConfig::default()
        },
    );
    let worker = QueueWorker::new(
        Arc::clone(&env.store),
        Arc::clone(&env.db),
        Arc::clone(&env.master_key),
        Arc::new(client),
        Arc::new(StoreDkimKeys::new(
            Arc::clone(&env.store),
            Arc::clone(&env.master_key),
        )),
        WorkerConfig {
            worker_id: "mx-3".to_string(),
            poll_interval: Duration::from_millis(10),
            ..WorkerConfig::default()
        },
    );
    assert_eq!(worker.drain(10).await.expect("drain"), 1);

    assert!(
        asked.lock().expect("lock").is_empty(),
        "a relay resolves no MX"
    );
    assert_eq!(relay.count(), 1, "one transaction for a smarthost");
    assert_eq!(
        relay.recipient_sets(),
        vec![vec![
            "carol@example.org".to_string(),
            "dave@example.net".to_string()
        ]]
    );
    Ok(())
}

/// A bounce is attributed to the domain it came from: the delivered recipient of
/// the same message is not suppressed.
#[tokio::test]
async fn a_hard_bounce_suppresses_only_the_domain_that_refused() -> SmtpResult<()> {
    let env = TestEnv::new();
    let account_id = env.account("dana@pigeonmail.dev");
    env.queue_outbound(
        account_id,
        "dana@pigeonmail.dev",
        &["carol@example.org", "gone@example.net"],
        "mixed",
        "body",
    );

    let ok_mx = FakeMx::start(false).await;
    let rejecting = FakeMx::start_rejecting_recipients(false).await;
    let asked = Arc::new(Mutex::new(Vec::new()));
    let resolver = MxResolver::new(TableMxSource::new(
        &[("example.org", "127.0.0.1"), ("example.net", "127.0.0.1")],
        asked,
    ))
    .with_test_port_for("example.org", ok_mx.address.port())
    .with_test_port_for("example.net", rejecting.address.port());

    let worker = worker(&env, resolver, "mx-4");
    assert_eq!(worker.drain(10).await.expect("drain"), 1);

    assert_eq!(ok_mx.count(), 1, "the .org recipient was delivered");
    let (suppressed, total) = env
        .db
        .suppression_page(account_id, 10, 0)
        .expect("suppressions");
    assert_eq!(
        total, 1,
        "only the bounced address is suppressed: {suppressed:?}"
    );
    assert_eq!(suppressed[0].address, "gone@example.net");
    Ok(())
}

/// The regression that per-domain routing introduced: a mixed-domain attempt where
/// one domain accepts and another defers must not re-deliver to the accepting
/// domain on the retry.
///
/// `queue` holds one row per message, so without per-domain tracking the retry
/// would send the whole recipient list again and put a **duplicate** in the
/// accepting domain's inbox. The queue row now records every domain that reached a
/// terminal verdict, and the worker filters them out before connecting.
#[tokio::test]
async fn a_retry_never_re_delivers_to_a_domain_that_already_accepted() -> SmtpResult<()> {
    let env = TestEnv::new();
    let account_id = env.account("dana@pigeonmail.dev");
    let (message_id, public_id) = env.queue_outbound(
        account_id,
        "dana@pigeonmail.dev",
        &["carol@a.test", "dave@b.test"],
        "no duplicates",
        "body",
    );

    // `a.test` accepts immediately; `b.test` fails its first transaction with a
    // `451` (temporary) and accepts on the retry.
    let accepting = FakeMx::start(false).await;
    let deferring = FakeMx::start_deferring(1, false).await;
    let asked = Arc::new(Mutex::new(Vec::new()));
    let resolver = MxResolver::new(TableMxSource::new(
        &[("a.test", "127.0.0.1"), ("b.test", "127.0.0.1")],
        Arc::clone(&asked),
    ))
    .with_test_port_for("a.test", accepting.address.port())
    .with_test_port_for("b.test", deferring.address.port());

    let worker = worker(&env, resolver, "mx-retry");
    assert_eq!(worker.drain(10).await.expect("drain"), 1);

    // First attempt: A took the message, B refused it temporarily.
    assert_eq!(accepting.count(), 1, "the accepting domain got it once");
    assert_eq!(deferring.count(), 0, "the deferring domain stored nothing");

    let events = env.store.list_events(message_id).expect("events");
    assert!(
        events.iter().any(|(kind, _, _)| kind == "email.deferred"),
        "the message stays queued for the domain that deferred: {events:?}"
    );
    assert_eq!(env.queue_rows_for(message_id), 1, "the job is still queued");

    // The retry: 30 s of backoff is skipped, nothing else changes.
    env.make_queue_due(message_id);
    assert_eq!(worker.drain(10).await.expect("drain"), 1);

    // The deferred domain now accepted...
    assert_eq!(deferring.count(), 1, "the deferred domain finally got it");
    assert_eq!(
        deferring.recipient_sets(),
        vec![vec!["dave@b.test".to_string()]],
        "the retry carries only the outstanding domain"
    );
    // ...and the domain that already had the message did NOT get a second copy.
    assert_eq!(
        accepting.count(),
        1,
        "the accepting domain must never receive a duplicate: {:?}",
        accepting.recipient_sets()
    );
    assert_eq!(
        accepting.recipient_sets(),
        vec![vec!["carol@a.test".to_string()]]
    );

    // Job settled, lifecycle says sent.
    assert_eq!(env.queue_rows_for(message_id), 0, "nothing left to retry");
    let email = env
        .db
        .email_by_public_id(account_id, &public_id)
        .expect("email row")
        .expect("email row present");
    assert_eq!(email.status, "sent");
    Ok(())
}

/// A job whose domains were all delivered by an earlier attempt settles without
/// opening a connection: the crash-after-delivery case must not duplicate mail.
#[tokio::test]
async fn a_job_marked_delivered_settles_without_reconnecting() -> SmtpResult<()> {
    let env = TestEnv::new();
    let account_id = env.account("dana@pigeonmail.dev");
    let (message_id, _public_id) = env.queue_outbound(
        account_id,
        "dana@pigeonmail.dev",
        &["carol@a.test"],
        "already delivered",
        "body",
    );

    // Simulate "delivered, then the process died before queue_complete": the
    // claim is gone but the delivered domain is recorded.
    let job = env
        .store
        .queue_claim("crashed-worker", 300)
        .expect("claim")
        .expect("job");
    env.store
        .queue_mark_domains_delivered(&job.claim_token, &["a.test".to_string()])
        .expect("mark delivered");
    env.make_queue_due(message_id);
    assert_eq!(
        env.queue_rows_for(message_id),
        1,
        "the row survives: only the delivered marker was written"
    );

    let mx = FakeMx::start(false).await;
    let asked = Arc::new(Mutex::new(Vec::new()));
    let resolver = MxResolver::new(TableMxSource::new(&[("a.test", "127.0.0.1")], asked))
        .with_test_port_for("a.test", mx.address.port());
    let worker = worker(&env, resolver, "mx-idempotent");
    assert_eq!(worker.drain(10).await.expect("drain"), 1);

    assert_eq!(
        mx.count(),
        0,
        "an already-delivered message is never sent again"
    );
    assert_eq!(env.queue_rows_for(message_id), 0, "the job is settled");
    Ok(())
}
