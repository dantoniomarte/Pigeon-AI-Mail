//! The money test: a raw TCP client speaks ESMTP to the inbound server and the
//! message lands sealed in SQLite, openable with the master key.
//!
//! Nothing here uses the client in `pigeon-smtp`: the test drives the wire
//! format by hand, so a regression in the state machine cannot be hidden by a
//! matching regression in the client.

mod support;

use std::sync::Arc;

use pigeon_core::{Direction, EmailAddress};
use pigeon_crypto::{ENVELOPE_VERSION, MIN_BLOB_LEN};
use pigeon_smtp::{InboundSmtpServer, ServerConfig};
use store::Storage;
use support::{start_inbound, RawClient, TestEnv};

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test]
async fn inbound_message_is_stored_sealed_and_decryptable_with_the_master_key() {
    let env = TestEnv::new();
    let account_id = env.account("carol@example.com");
    let server = Arc::new(InboundSmtpServer::new(
        Arc::clone(&env.store),
        Arc::clone(&env.db),
        Arc::clone(&env.master_key),
        ServerConfig::default(),
    ));
    let (address, stop) = start_inbound(server).await;

    let mut client = RawClient::connect(address).await;
    let (code, banner) = client.read_reply().await;
    assert_eq!(code, 220, "{banner}");
    assert!(banner.contains("ESMTP"), "{banner}");

    let (code, capabilities) = client.ehlo("sender.example").await;
    assert_eq!(code, 250);
    assert!(capabilities.contains("SIZE 36700160"), "{capabilities}");
    assert!(capabilities.contains("8BITMIME"), "{capabilities}");
    assert!(capabilities.contains("STARTTLS"), "{capabilities}");

    assert_eq!(client.send("MAIL FROM:<dana@example.org>").await.0, 250);
    assert_eq!(client.send("RCPT TO:<carol@example.com>").await.0, 250);
    assert_eq!(client.send("DATA").await.0, 354);

    let message = concat!(
        "From: Dana <dana@example.org>\r\n",
        "To: carol@example.com\r\n",
        "Subject: Hello Pigeon\r\n",
        "Date: Fri, 06 Nov 2026 00:00:00 +0000\r\n",
        "Message-ID: <abc123@example.org>\r\n",
        "\r\n",
        "hello from the outside\r\n",
    );
    let (code, text) = client.data(message).await;
    assert_eq!(code, 250, "{text}");
    assert!(text.contains("queued as"), "{text}");
    assert_eq!(client.send("QUIT").await.0, 221);

    // --- stored, as an inbound message for the owning account ----------------
    let rows = env.store.list_messages(account_id, 10, 0).expect("listing");
    assert_eq!(rows.len(), 1, "exactly one inbound message: {rows:?}");
    let row = &rows[0];
    assert_eq!(row.direction, Direction::In);
    assert_eq!(row.from_addr.to_string(), "dana@example.org");
    assert_eq!(
        row.to_addrs,
        vec![EmailAddress::parse("carol@example.com").expect("address")]
    );
    assert_eq!(row.subject, "Hello Pigeon");

    // --- sealed, not plaintext ----------------------------------------------
    let stored = env.store.get_message(row.id).expect("message body");
    assert_eq!(
        stored.sealed_body[0], ENVELOPE_VERSION,
        "the stored body must be a versioned sealed envelope"
    );
    assert!(stored.sealed_body.len() > MIN_BLOB_LEN);
    assert!(
        !contains(&stored.sealed_body, b"hello from the outside"),
        "plaintext must never reach the database"
    );

    // --- decryptable with the master key ------------------------------------
    let body = env.open_body(account_id, row.id);
    assert!(
        body.contains("Hello Pigeon"),
        "opened body keeps the headers: {body}"
    );
    assert!(
        body.contains("hello from the outside"),
        "opened body keeps the payload: {body}"
    );
    assert!(
        body.starts_with(
            "Received: from sender.example ([127.0.0.1]) by pigeon.local with ESMTP id "
        ),
        "the stored copy carries our Received trace header: {body}"
    );

    // --- inbound event -------------------------------------------------------
    let events = env.store.list_events(row.id).expect("events");
    let received = events
        .iter()
        .find(|(kind, _, _)| kind == "email.received")
        .expect("an email.received event");
    assert!(received.1.contains("dana@example.org"), "{}", received.1);
    assert!(
        received.1.contains("dkim:none"),
        "v0.1 records the unevaluated verdicts honestly: {}",
        received.1
    );

    let _ = stop.send(());
}

#[tokio::test]
async fn a_message_for_an_unknown_mailbox_is_rejected_with_550() {
    let env = TestEnv::new();
    env.account("carol@example.com");
    let server = Arc::new(InboundSmtpServer::new(
        Arc::clone(&env.store),
        Arc::clone(&env.db),
        Arc::clone(&env.master_key),
        ServerConfig::default(),
    ));
    let (address, stop) = start_inbound(server).await;

    let mut client = RawClient::connect(address).await;
    assert_eq!(client.read_reply().await.0, 220);
    assert_eq!(client.ehlo("sender.example").await.0, 250);
    assert_eq!(client.send("MAIL FROM:<dana@example.org>").await.0, 250);
    assert_eq!(client.send("RCPT TO:<nobody@example.com>").await.0, 250);
    assert_eq!(client.send("DATA").await.0, 354);
    let (code, text) = client.data("Subject: x\r\n\r\nbody").await;
    assert_eq!(code, 550, "{text}");
    assert!(text.contains("no such mailbox"), "{text}");

    let _ = stop.send(());
}

#[tokio::test]
async fn starttls_is_advertised_and_refused_with_454() {
    let env = TestEnv::new();
    let server = Arc::new(InboundSmtpServer::new(
        Arc::clone(&env.store),
        Arc::clone(&env.db),
        Arc::clone(&env.master_key),
        ServerConfig::default(),
    ));
    let (address, stop) = start_inbound(server).await;

    let mut client = RawClient::connect(address).await;
    assert_eq!(client.read_reply().await.0, 220);
    assert_eq!(client.ehlo("sender.example").await.0, 250);
    let (code, text) = client.send("STARTTLS").await;
    assert_eq!(code, 454, "{text}");
    assert!(text.contains("TLS not available"), "{text}");
    // The session survives the refusal: a client that insists on TLS hangs up
    // itself, and one that accepts clear text can continue.
    assert_eq!(client.send("NOOP").await.0, 250);

    let _ = stop.send(());
}

#[tokio::test]
async fn one_message_for_two_local_accounts_is_stored_for_each_of_them() {
    let env = TestEnv::new();
    let carol = env.account("carol@example.com");
    let dave = env.account("dave@example.org");
    let server = Arc::new(InboundSmtpServer::new(
        Arc::clone(&env.store),
        Arc::clone(&env.db),
        Arc::clone(&env.master_key),
        ServerConfig::default(),
    ));
    let (address, stop) = start_inbound(server).await;

    let mut client = RawClient::connect(address).await;
    assert_eq!(client.read_reply().await.0, 220);
    assert_eq!(client.ehlo("sender.example").await.0, 250);
    assert_eq!(client.send("MAIL FROM:<dana@example.org>").await.0, 250);
    assert_eq!(client.send("RCPT TO:<carol@example.com>").await.0, 250);
    assert_eq!(client.send("RCPT TO:<dave@example.org>").await.0, 250);
    assert_eq!(client.send("DATA").await.0, 354);
    assert_eq!(
        client
            .data("Subject: both\r\nFrom: dana@example.org\r\n\r\nto both\r\n")
            .await
            .0,
        250
    );

    // Each account gets its own sealed copy, with only its own recipient in the
    // envelope: one account must not learn who else received the message.
    assert_eq!(
        env.store.list_messages(carol, 10, 0).expect("carol").len(),
        1
    );
    assert_eq!(env.store.list_messages(dave, 10, 0).expect("dave").len(), 1);
    let carol_row = &env.store.list_messages(carol, 10, 0).expect("carol")[0];
    assert_eq!(carol_row.to_addrs.len(), 1);
    assert!(env.open_body(carol, carol_row.id).contains("to both"));

    let _ = stop.send(());
}
