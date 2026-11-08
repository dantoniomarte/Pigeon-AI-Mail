//! Outbound delivery: the worker claims a queued message, resolves the MX,
//! delivers to a fake MX server and settles the queue row.

mod support;

use std::sync::Arc;
use std::time::Duration;

use pigeon_core::StartTlsMode;
use pigeon_dkim::{verify_message, DkimKeyPair};
use pigeon_smtp::dns::{LookupFuture, MxRecord, MxResolver, MxSource};
use pigeon_smtp::worker::StoreDkimKeys;
use pigeon_smtp::{
    DeliveryConfig, OutboundSmtpClient, QueueWorker, Result as SmtpResult, WorkerConfig,
};
use store::Storage;
use support::{FakeMx, TestEnv};

/// A resolver that always answers with the same records, so no test needs DNS.
struct FixedMxSource {
    records: Vec<MxRecord>,
}

impl MxSource for FixedMxSource {
    fn mx_records<'a>(&'a self, _domain: &'a str) -> LookupFuture<'a, Vec<MxRecord>> {
        let records = self.records.clone();
        Box::pin(async move { Ok(records) })
    }
}

fn client_for(fake: &FakeMx, starttls: StartTlsMode) -> OutboundSmtpClient {
    let resolver = MxResolver::new(FixedMxSource {
        records: vec![MxRecord::new(10, "127.0.0.1")],
    })
    .with_test_port(fake.address.port());
    OutboundSmtpClient::new(
        resolver,
        DeliveryConfig {
            starttls,
            timeout: Duration::from_secs(5),
            ..DeliveryConfig::default()
        },
    )
}

fn worker(env: &TestEnv, client: OutboundSmtpClient, worker_id: &str) -> QueueWorker {
    QueueWorker::new(
        Arc::clone(&env.store),
        Arc::clone(&env.db),
        Arc::clone(&env.master_key),
        Arc::new(client),
        // The production source: this database has no `dkim_keys` rows in most
        // tests, so those messages go out unsigned exactly as they would in a
        // deployment that has not added a domain.
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

/// Split a delivered message into unfolded headers and its body, mirroring
/// `pigeon_smtp::server::parse_message` (which is crate-private) so the
/// verifier sees the same bytes the signer did.
fn split_message(raw: &str) -> (Vec<(String, String)>, String) {
    let (header_block, body) = raw
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("no header/body separator in {raw:?}"));
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in header_block.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, value)) = headers.last_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    (headers, body.to_string())
}

#[tokio::test]
async fn queued_message_is_delivered_and_recorded_as_sent() {
    let env = TestEnv::new();
    let account_id = env.account("dana@pigeonmail.dev");
    let (message_id, public_id) = env.queue_outbound(
        account_id,
        "dana@pigeonmail.dev",
        &["carol@example.org", "dave@example.net"],
        "Invoice #2041 paid",
        "Thanks for your business!",
    );
    let fake = FakeMx::start(false).await;
    let worker = worker(
        &env,
        client_for(&fake, StartTlsMode::Opportunistic),
        "test-1",
    );

    let settled = worker.drain(10).await.expect("drain");
    assert_eq!(settled, 1, "one job was due");

    // --- the peers received the exact stored MIME ---------------------------
    // Routing is per recipient domain (issue #70), so a message with two domains
    // reaches the fake MX in two transactions, each carrying one recipient.
    assert_eq!(fake.count(), 2, "one transaction per recipient domain");
    let delivered = fake.delivered();
    assert!(
        delivered.contains("Subject: Invoice #2041 paid"),
        "{delivered}"
    );
    assert!(
        delivered.contains("Thanks for your business!"),
        "{delivered}"
    );
    assert!(
        delivered.contains("From: dana@pigeonmail.dev"),
        "{delivered}"
    );
    let mut recipients = fake.recipient_sets();
    recipients.sort();
    assert_eq!(
        recipients,
        vec![
            vec!["carol@example.org".to_string()],
            vec!["dave@example.net".to_string()]
        ],
        "each transaction carries only its own domain's recipient"
    );

    // --- the queue row is gone, the lifecycle says sent ---------------------
    assert_eq!(
        env.queue_rows_for(message_id),
        0,
        "a delivered job is settled, not left behind its lease"
    );
    let email = env
        .db
        .email_by_public_id(account_id, &public_id)
        .expect("email row")
        .expect("email row present");
    assert_eq!(email.status, "sent");

    let events = env.store.list_events(message_id).expect("events");
    let sent = events
        .iter()
        .find(|(kind, _, _)| kind == "email.sent")
        .expect("an email.sent event");
    assert!(sent.1.contains("code=250"), "{}", sent.1);
    assert!(sent.1.contains("127.0.0.1"), "{}", sent.1);
}

#[tokio::test]
async fn required_starttls_fails_when_the_peer_does_not_offer_it() {
    let env = TestEnv::new();
    let account_id = env.account("dana@pigeonmail.dev");
    let (message_id, public_id) = env.queue_outbound(
        account_id,
        "dana@pigeonmail.dev",
        &["carol@example.org"],
        "needs TLS",
        "body",
    );
    // The peer advertises no STARTTLS: a `required` client must refuse to send.
    let fake = FakeMx::start(false).await;
    let worker = worker(&env, client_for(&fake, StartTlsMode::Required), "test-2");

    assert_eq!(worker.drain(10).await.expect("drain"), 1);
    assert_eq!(fake.count(), 0, "nothing may be sent in clear text");

    let events = env.store.list_events(message_id).expect("events");
    let failed = events
        .iter()
        .find(|(kind, _, _)| kind == "email.failed")
        .expect("an email.failed event");
    assert!(
        failed.1.contains("STARTTLS is required"),
        "the reason must name the policy: {}",
        failed.1
    );
    assert_eq!(
        env.queue_rows_for(message_id),
        0,
        "a refused send is settled"
    );
    let email = env
        .db
        .email_by_public_id(account_id, &public_id)
        .expect("email row")
        .expect("email row present");
    assert_eq!(email.status, "failed");
}

#[tokio::test]
async fn a_hard_bounce_suppresses_the_recipient_and_stops_retrying() {
    let env = TestEnv::new();
    let account_id = env.account("dana@pigeonmail.dev");
    let (message_id, public_id) = env.queue_outbound(
        account_id,
        "dana@pigeonmail.dev",
        &["gone@example.org"],
        "hello gone",
        "body",
    );
    let fake = FakeMx::start_rejecting_recipients(false).await;
    let worker = worker(
        &env,
        client_for(&fake, StartTlsMode::Opportunistic),
        "test-3",
    );

    assert_eq!(worker.drain(10).await.expect("drain"), 1);

    let events = env.store.list_events(message_id).expect("events");
    let bounced = events
        .iter()
        .find(|(kind, _, _)| kind == "email.bounced")
        .expect("an email.bounced event");
    assert!(bounced.1.contains("550"), "{}", bounced.1);

    let (suppressed, total) = env
        .db
        .suppression_page(account_id, 10, 0)
        .expect("suppressions");
    assert_eq!(
        total, 1,
        "the hard-bounced recipient is suppressed: {suppressed:?}"
    );
    assert_eq!(suppressed[0].address, "gone@example.org");
    assert!(suppressed[0].reason.contains("hard bounce"));

    // The job is finished, not re-queued: a 5xx is permanent.
    assert!(env
        .store
        .queue_claim("after", 300)
        .expect("claim")
        .is_none());
    let email = env
        .db
        .email_by_public_id(account_id, &public_id)
        .expect("email row")
        .expect("email row present");
    assert_eq!(email.status, "bounced");
}

#[tokio::test]
async fn a_deferred_delivery_is_requeued_with_backoff() {
    let env = TestEnv::new();
    let account_id = env.account("dana@pigeonmail.dev");
    let (message_id, _public_id) = env.queue_outbound(
        account_id,
        "dana@pigeonmail.dev",
        &["carol@example.org"],
        "try later",
        "body",
    );
    // Nothing is listening on the port the fake MX *would* use: the connect
    // fails, which is the transient case.
    let fake = FakeMx::start(false).await;
    let address = fake.address;
    drop(fake);
    let resolver = MxResolver::new(FixedMxSource {
        records: vec![MxRecord::new(10, "127.0.0.1")],
    })
    .with_test_port(address.port());
    let client = OutboundSmtpClient::new(
        resolver,
        DeliveryConfig {
            starttls: StartTlsMode::Opportunistic,
            timeout: Duration::from_millis(500),
            ..DeliveryConfig::default()
        },
    );
    let worker = worker(&env, client, "test-4");

    assert_eq!(worker.drain(10).await.expect("drain"), 1);

    let events = env.store.list_events(message_id).expect("events");
    assert!(
        events.iter().any(|(kind, _, _)| kind == "email.deferred"),
        "a connection failure defers: {events:?}"
    );
    // The row is still there, held back by the backoff it just received, so it is
    // not immediately claimable again.
    assert!(
        env.store
            .queue_claim("after", 300)
            .expect("claim")
            .is_none(),
        "the backoff must keep the job out of the next poll"
    );
}

#[tokio::test]
async fn a_message_without_a_wrapped_key_is_failed_permanently() {
    let env = TestEnv::new();
    let account_id = env.account("dana@pigeonmail.dev");
    // A message inserted straight into `store`, with no `api_messages` sibling:
    // its content key does not exist, so the body can never be opened.
    let message_id = env.store.reserve_message_id().expect("reserve");
    let aad = format!("account:{account_id}:message:{message_id}");
    let key = pigeon_crypto::generate_content_key();
    env.store
        .insert_message(
            store::NewMessage {
                account_id,
                direction: pigeon_core::Direction::Out,
                from_addr: pigeon_core::EmailAddress::parse("dana@pigeonmail.dev").expect("from"),
                to_addrs: vec![pigeon_core::EmailAddress::parse("carol@example.org").expect("to")],
                subject: "no key".to_string(),
                sealed_body: pigeon_crypto::seal_content(&key, b"body", aad.as_bytes())
                    .expect("seal"),
                idempotency_key: None,
                delivered_for: None,
            },
            message_id,
        )
        .expect("insert");
    env.store.queue_enqueue(message_id, 0).expect("queue");

    let fake = FakeMx::start(false).await;
    let worker = worker(
        &env,
        client_for(&fake, StartTlsMode::Opportunistic),
        "test-5",
    );
    assert_eq!(worker.drain(10).await.expect("drain"), 1);

    assert_eq!(fake.count(), 0, "nothing could be delivered");
    let events = env.store.list_events(message_id).expect("events");
    let failed = events
        .iter()
        .find(|(kind, _, _)| kind == "email.failed")
        .expect("an email.failed event");
    assert!(
        failed.1.contains("wrapped content key") || failed.1.contains("disappeared"),
        "{}",
        failed.1
    );
}

/// The signing path end to end: a key in the store for the `From:` domain is
/// unsealed, rebuilt and used, and the delivered message carries a signature that
/// **verifies** against the very TXT record the API hands the operator.
#[tokio::test]
async fn a_stored_domain_key_signs_the_delivered_message() -> SmtpResult<()> {
    let env = TestEnv::new();
    let account_id = env.account("dana@pigeonmail.dev");
    env.queue_outbound(
        account_id,
        "dana@pigeonmail.dev",
        &["carol@example.org"],
        "signed",
        "body",
    );

    // Seed the store exactly as `POST /v1/domains` does: generate, export
    // PKCS#8, seal under the master key, publish the DNS record.
    let key = DkimKeyPair::generate("pigeon", "pigeonmail.dev")?;
    let dns_record = key.public_key_dns_record();
    let pkcs8 = key.to_pkcs8_der()?;
    let wrapped = pigeon_api::dkim::seal_private_key(&env.master_key, "pigeonmail.dev", &pkcs8)
        .expect("seal the private key");
    env.store
        .put_dkim_key("pigeonmail.dev", key.selector(), &wrapped, &dns_record)
        .expect("store the dkim key");

    let fake = FakeMx::start(false).await;
    let worker = worker(
        &env,
        client_for(&fake, StartTlsMode::Opportunistic),
        "test-6",
    );
    assert_eq!(worker.drain(10).await.expect("drain"), 1);

    let delivered = fake.delivered();
    assert!(
        delivered.starts_with("DKIM-Signature: v=1; a=rsa-sha256"),
        "the signature must be the first header: {delivered}"
    );
    assert!(delivered.contains("d=pigeonmail.dev"), "{delivered}");
    assert!(delivered.contains("s=pigeon;"), "{delivered}");

    // The signature must actually verify against the published record — not just
    // look like one.
    let (headers, body) = split_message(&delivered);
    let signature = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("DKIM-Signature"))
        .map(|(_, value)| value.clone())
        .expect("a DKIM-Signature header");
    // Only the fields the signature covers; the signature itself is reconstructed
    // from the tag list, never taken from the message.
    let signed: Vec<(String, String)> = headers
        .into_iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("DKIM-Signature"))
        .collect();
    let result = verify_message(&signature, &signed, &body, |name| {
        (name == "pigeon._domainkey.pigeonmail.dev").then(|| dns_record.clone())
    })
    .expect("verification runs");
    assert!(result.passed, "reason: {:?}", result.reason);
    assert_eq!(result.domain, "pigeonmail.dev");
    assert_eq!(result.selector, "pigeon");
    Ok(())
}

/// A domain the server holds no key for is delivered **unsigned** and the job
/// still succeeds: signing is a policy, not a delivery prerequisite.
#[tokio::test]
async fn a_domain_without_a_stored_key_is_delivered_unsigned() -> SmtpResult<()> {
    let env = TestEnv::new();
    let account_id = env.account("dana@pigeonmail.dev");
    let (message_id, _) = env.queue_outbound(
        account_id,
        "dana@pigeonmail.dev",
        &["carol@example.org"],
        "unsigned",
        "body",
    );
    // A key for a *different* domain must not be used for this one.
    let other = DkimKeyPair::generate("pigeon", "somewhere-else.example")?;
    let pkcs8 = other.to_pkcs8_der()?;
    let wrapped =
        pigeon_api::dkim::seal_private_key(&env.master_key, "somewhere-else.example", &pkcs8)
            .expect("seal");
    env.store
        .put_dkim_key(
            "somewhere-else.example",
            other.selector(),
            &wrapped,
            &other.public_key_dns_record(),
        )
        .expect("store the other domain's key");

    let fake = FakeMx::start(false).await;
    let worker = worker(
        &env,
        client_for(&fake, StartTlsMode::Opportunistic),
        "test-7",
    );
    assert_eq!(worker.drain(10).await.expect("drain"), 1);

    let delivered = fake.delivered();
    assert!(delivered.starts_with("From: "), "{delivered}");
    assert!(
        !delivered.contains("DKIM-Signature"),
        "an unmanaged domain must not be signed with another domain's key: {delivered}"
    );
    // Delivery still succeeded.
    let events = env.store.list_events(message_id).expect("events");
    assert!(
        events.iter().any(|(kind, _, _)| kind == "email.sent"),
        "{events:?}"
    );
    Ok(())
}

/// A key that exists but cannot be unsealed is a permanent failure, never a
/// silent unsigned downgrade.
#[tokio::test]
async fn an_unusable_stored_key_fails_the_job_instead_of_sending_unsigned() -> SmtpResult<()> {
    let env = TestEnv::new();
    let account_id = env.account("dana@pigeonmail.dev");
    let (message_id, _) = env.queue_outbound(
        account_id,
        "dana@pigeonmail.dev",
        &["carol@example.org"],
        "broken key",
        "body",
    );
    // Sealed under a *different* master key: the domain looks managed but the
    // blob cannot be opened here.
    let other_master = pigeon_crypto::MasterKey::parse(&[0x11; 32]).expect("other master key");
    let key = DkimKeyPair::generate("pigeon", "pigeonmail.dev")?;
    let wrapped =
        pigeon_api::dkim::seal_private_key(&other_master, "pigeonmail.dev", &key.to_pkcs8_der()?)
            .expect("seal");
    env.store
        .put_dkim_key("pigeonmail.dev", key.selector(), &wrapped, "v=DKIM1")
        .expect("store");

    let fake = FakeMx::start(false).await;
    let worker = worker(
        &env,
        client_for(&fake, StartTlsMode::Opportunistic),
        "test-8",
    );
    assert_eq!(worker.drain(10).await.expect("drain"), 1);

    assert_eq!(fake.count(), 0, "nothing may be delivered unsigned");
    let events = env.store.list_events(message_id).expect("events");
    let failed = events
        .iter()
        .find(|(kind, _, _)| kind == "email.failed")
        .expect("an email.failed event");
    assert!(failed.1.contains("unusable"), "{}", failed.1);
    Ok(())
}
