//! Inbound resolution: sender aliases and the multi-recipient catch-all.
//!
//! Every test drives the real inbound server over a raw TCP connection, exactly
//! like a sending MTA would, and then reads the resulting rows through `store`'s
//! public API. Nothing is stubbed: the alias and catch-all tables are the ones the
//! HTTP API and the MCP tools write.

mod support;

use std::sync::Arc;

use pigeon_core::types::CatchallAction;
use pigeon_core::{EmailAddress, MessageFolder};
use pigeon_smtp::{InboundSmtpServer, ServerConfig};
use store::Storage;
use support::{start_inbound, RawClient, TestEnv};

fn addr(raw: &str) -> EmailAddress {
    EmailAddress::parse(raw).expect("test address")
}

/// One `Subject` line, so a delivered copy is identifiable.
fn message(subject: &str) -> String {
    format!("Subject: {subject}\r\nFrom: dana@example.org\r\n\r\nbody\r\n")
}

fn inbox_subjects(env: &TestEnv, account_id: i64) -> Vec<String> {
    env.store
        .list_folder(account_id, MessageFolder::Inbox, 50, 0)
        .expect("inbox")
        .into_iter()
        .map(|row| row.subject)
        .collect()
}

/// Start the production inbound server over the test database.
async fn start(env: &TestEnv) -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let server = Arc::new(InboundSmtpServer::new(
        Arc::clone(&env.store),
        Arc::clone(&env.db),
        Arc::clone(&env.master_key),
        ServerConfig::default(),
    ));
    start_inbound(server).await
}

#[tokio::test]
async fn mail_to_an_alias_is_copied_to_every_assignee() {
    let env = TestEnv::new();
    let sales = env.account("sales@example.com");
    let second = env.account("second@example.com");
    let alias = env
        .store
        .create_alias(&addr("pedidos@example.com"), sales)
        .expect("alias");
    for account_id in [sales, second] {
        env.store
            .assign_alias(alias, account_id, sales)
            .expect("assign alias");
    }

    let (address, stop) = start(&env).await;
    let mut client = RawClient::connect(address).await;
    assert_eq!(client.read_reply().await.0, 220);
    assert_eq!(client.ehlo("sender.example").await.0, 250);
    assert_eq!(client.send("MAIL FROM:<dana@example.org>").await.0, 250);
    assert_eq!(client.send("RCPT TO:<pedidos@example.com>").await.0, 250);
    assert_eq!(client.send("DATA").await.0, 354);
    let (code, text) = client.data(&message("pedido")).await;
    assert_eq!(code, 250, "{text}");
    assert_eq!(client.send("QUIT").await.0, 221);

    // Both holders have one copy, marked with the address it arrived for, and the
    // body opens with each holder's own AAD.
    for account_id in [sales, second] {
        let rows = env
            .store
            .list_folder(account_id, MessageFolder::Inbox, 10, 0)
            .expect("inbox");
        assert_eq!(rows.len(), 1, "account {account_id}: {rows:?}");
        assert_eq!(rows[0].subject, "pedido");
        assert_eq!(
            rows[0].delivered_for.as_deref(),
            Some("pedidos@example.com")
        );
        let body = env.open_body(account_id, rows[0].id);
        assert!(body.contains("Subject: pedido"), "{body}");
        let events = env.store.list_events(rows[0].id).expect("events");
        assert!(
            events[0].1.contains("via=alias"),
            "the delivery event records the alias: {:?}",
            events[0]
        );
    }
    // The alias owns no mailbox: nothing landed in a made-up "alias account".
    assert!(env
        .store
        .get_account_by_email("pedidos@example.com")
        .expect("lookup")
        .is_none());
    let _ = stop.send(());
}

#[tokio::test]
async fn an_alias_wins_over_the_catchall_and_delivers_only_to_its_holders() {
    let env = TestEnv::new();
    let holder = env.account("holder@example.com");
    let other = env.account("other@example.com");
    // A catch-all that would otherwise take every unknown local part of the
    // domain, held by an account that must NOT receive alias mail as catch-all.
    env.store
        .set_catchall("example.com", CatchallAction::Route)
        .expect("rule");
    env.store
        .assign_catchall("example.com", other, other)
        .expect("assign catchall");
    let alias = env
        .store
        .create_alias(&addr("sales@example.com"), holder)
        .expect("alias");
    env.store
        .assign_alias(alias, holder, holder)
        .expect("assign alias");

    let (address, stop) = start(&env).await;
    let mut client = RawClient::connect(address).await;
    let _ = client.read_reply().await;
    assert_eq!(client.ehlo("sender.example").await.0, 250);
    assert_eq!(client.send("MAIL FROM:<dana@example.org>").await.0, 250);
    assert_eq!(client.send("RCPT TO:<sales@example.com>").await.0, 250);
    assert_eq!(client.send("DATA").await.0, 354);
    let (code, text) = client.data(&message("alias gana")).await;
    assert_eq!(code, 250, "{text}");

    assert_eq!(
        inbox_subjects(&env, holder),
        vec!["alias gana".to_string()],
        "the alias holder receives its copy"
    );
    assert!(
        inbox_subjects(&env, other).is_empty(),
        "an alias is not an unknown address: the catch-all must not also fire"
    );
    let _ = stop.send(());
}

#[tokio::test]
async fn the_catchall_copies_to_every_unpaused_assignee() {
    let env = TestEnv::new();
    let first = env.account("first@example.com");
    let paused = env.account("paused@example.com");
    env.store
        .set_catchall("example.com", CatchallAction::Route)
        .expect("rule");
    for account_id in [first, paused] {
        env.store
            .assign_catchall("example.com", account_id, first)
            .expect("assign");
    }
    env.store
        .set_catchall_paused("example.com", paused, true)
        .expect("pause");

    let (address, stop) = start(&env).await;
    let mut client = RawClient::connect(address).await;
    let _ = client.read_reply().await;
    assert_eq!(client.ehlo("sender.example").await.0, 250);
    assert_eq!(client.send("MAIL FROM:<dana@example.org>").await.0, 250);
    assert_eq!(client.send("RCPT TO:<ghost@example.com>").await.0, 250);
    assert_eq!(client.send("DATA").await.0, 354);
    let (code, text) = client.data(&message("catchall")).await;
    assert_eq!(code, 250, "{text}");

    let rows = env
        .store
        .list_folder(first, MessageFolder::Inbox, 10, 0)
        .expect("inbox");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].delivered_for.as_deref(), Some("ghost@example.com"));
    let events = env.store.list_events(rows[0].id).expect("events");
    assert!(events[0].1.contains("via=catchall"), "{:?}", events[0]);
    assert!(
        inbox_subjects(&env, paused).is_empty(),
        "a paused assignee receives nothing"
    );
    let _ = stop.send(());
}

#[tokio::test]
async fn a_route_rule_whose_assignees_all_paused_accepts_and_drops() {
    let env = TestEnv::new();
    let only = env.account("only@example.com");
    env.store
        .set_catchall("example.com", CatchallAction::Route)
        .expect("rule");
    env.store
        .assign_catchall("example.com", only, only)
        .expect("assign");
    env.store
        .set_catchall_paused("example.com", only, true)
        .expect("pause");

    let (address, stop) = start(&env).await;
    let mut client = RawClient::connect(address).await;
    let _ = client.read_reply().await;
    assert_eq!(client.ehlo("sender.example").await.0, 250);
    assert_eq!(client.send("MAIL FROM:<dana@example.org>").await.0, 250);
    assert_eq!(client.send("RCPT TO:<ghost@example.com>").await.0, 250);
    assert_eq!(client.send("DATA").await.0, 354);
    let (code, text) = client.data(&message("nadie")).await;
    // Accepted, not bounced: a configured catch-all never turns a member's pause
    // into a delivery failure for the sender.
    assert_eq!(code, 250, "{text}");
    assert!(inbox_subjects(&env, only).is_empty());
    let _ = stop.send(());
}
