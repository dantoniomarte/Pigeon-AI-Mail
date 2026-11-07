//! Limits and sequencing: the states that protect the server from a hostile (or
//! simply broken) client.
//!
//! Each test starts its own server with the limit under test lowered, so the
//! assertions stay fast and do not depend on the production constants.

mod support;

use std::sync::Arc;
use std::time::Duration;

use pigeon_smtp::{InboundSmtpServer, ServerConfig};
use support::{start_inbound, RawClient, TestEnv};

fn server_with(env: &TestEnv, config: ServerConfig) -> Arc<InboundSmtpServer> {
    Arc::new(InboundSmtpServer::new(
        Arc::clone(&env.store),
        Arc::clone(&env.db),
        Arc::clone(&env.master_key),
        config,
    ))
}

#[tokio::test]
async fn a_message_above_the_size_limit_is_refused_with_552() {
    let env = TestEnv::new();
    env.account("carol@example.com");
    let server = server_with(
        &env,
        ServerConfig {
            max_message_size: 1024,
            ..ServerConfig::default()
        },
    );
    let (address, stop) = start_inbound(server).await;

    let mut client = RawClient::connect(address).await;
    assert_eq!(client.read_reply().await.0, 220);
    assert_eq!(client.ehlo("sender.example").await.0, 250);
    assert_eq!(client.send("MAIL FROM:<dana@example.org>").await.0, 250);
    assert_eq!(client.send("RCPT TO:<carol@example.com>").await.0, 250);
    assert_eq!(client.send("DATA").await.0, 354);

    // ~2.5 KiB of body against a 1 KiB limit: the server must drain to the
    // terminator and then answer 552, so the next command is still in sync. The
    // lines stay under the 1000-byte line limit, so this exercises the size
    // limit and not the per-line one.
    let body = vec!["y".repeat(60); 40].join("\r\n");
    let (code, text) = client.data(&formatted(&body)).await;
    assert_eq!(code, 552, "{text}");
    assert!(text.contains("exceeds"), "{text}");

    // The session survives and the envelope was reset: a new transaction starts
    // from MAIL.
    assert_eq!(client.send("MAIL FROM:<dana@example.org>").await.0, 250);
    let _ = stop.send(());
}

#[tokio::test]
async fn a_declared_oversize_message_is_refused_before_the_data_phase() {
    let env = TestEnv::new();
    env.account("carol@example.com");
    let server = server_with(
        &env,
        ServerConfig {
            max_message_size: 1024,
            ..ServerConfig::default()
        },
    );
    let (address, stop) = start_inbound(server).await;

    let mut client = RawClient::connect(address).await;
    assert_eq!(client.read_reply().await.0, 220);
    assert_eq!(client.ehlo("sender.example").await.0, 250);
    let (code, text) = client
        .send("MAIL FROM:<dana@example.org> SIZE=1048576")
        .await;
    assert_eq!(code, 552, "{text}");
    assert!(text.contains("exceeds the 1024-byte limit"), "{text}");
    // No envelope was opened, so RCPT is a sequence error, not a queue entry.
    assert_eq!(client.send("RCPT TO:<carol@example.com>").await.0, 503);

    let _ = stop.send(());
}

#[tokio::test]
async fn too_many_recipients_is_refused_with_452() {
    let env = TestEnv::new();
    env.account("carol@example.com");
    let server = server_with(
        &env,
        ServerConfig {
            max_recipients: 3,
            ..ServerConfig::default()
        },
    );
    let (address, stop) = start_inbound(server).await;

    let mut client = RawClient::connect(address).await;
    assert_eq!(client.read_reply().await.0, 220);
    assert_eq!(client.ehlo("sender.example").await.0, 250);
    assert_eq!(client.send("MAIL FROM:<dana@example.org>").await.0, 250);
    for index in 0..3 {
        let (code, _) = client
            .send(&format!("RCPT TO:<carol+{index}@example.com>"))
            .await;
        assert_eq!(code, 250, "recipient {index} is within the limit");
    }
    let (code, text) = client.send("RCPT TO:<one-too-many@example.com>").await;
    assert_eq!(code, 452, "{text}");
    assert!(text.contains("too many recipients"), "{text}");

    let _ = stop.send(());
}

#[tokio::test]
async fn out_of_sequence_commands_are_refused_with_503() {
    let env = TestEnv::new();
    let server = server_with(&env, ServerConfig::default());
    let (address, stop) = start_inbound(server).await;

    let mut client = RawClient::connect(address).await;
    assert_eq!(client.read_reply().await.0, 220);

    // Before a greeting.
    assert_eq!(client.send("MAIL FROM:<dana@example.org>").await.0, 503);
    assert_eq!(client.send("RCPT TO:<carol@example.com>").await.0, 503);
    assert_eq!(client.send("DATA").await.0, 503);

    // After a greeting but before MAIL, and nested MAIL.
    assert_eq!(client.ehlo("sender.example").await.0, 250);
    assert_eq!(client.send("RCPT TO:<carol@example.com>").await.0, 503);
    assert_eq!(client.send("DATA").await.0, 503);
    assert_eq!(client.send("MAIL FROM:<dana@example.org>").await.0, 250);
    assert_eq!(client.send("MAIL FROM:<eve@example.net>").await.0, 503);
    assert_eq!(client.send("DATA").await.0, 503, "no recipient yet");

    // RSET clears the envelope, so DATA is a sequence error again.
    assert_eq!(client.send("RCPT TO:<carol@example.com>").await.0, 250);
    assert_eq!(client.send("RSET").await.0, 250);
    assert_eq!(client.send("DATA").await.0, 503);

    let _ = stop.send(());
}

#[tokio::test]
async fn a_silent_client_is_closed_with_421_after_the_timeout() {
    let env = TestEnv::new();
    let server = server_with(
        &env,
        ServerConfig {
            command_timeout: Duration::from_millis(200),
            ..ServerConfig::default()
        },
    );
    let (address, stop) = start_inbound(server).await;

    let mut client = RawClient::connect(address).await;
    assert_eq!(client.read_reply().await.0, 220);
    // Say nothing at all: the server must give up on its own.
    let (code, text) = tokio::time::timeout(Duration::from_secs(5), client.read_reply())
        .await
        .expect("the server closes the idle session");
    assert_eq!(code, 421, "{text}");
    assert!(text.contains("timeout"), "{text}");
    assert!(client.at_eof().await, "the connection is closed afterwards");

    let _ = stop.send(());
}

#[tokio::test]
async fn an_overlong_command_line_is_refused_with_500() {
    let env = TestEnv::new();
    let server = server_with(
        &env,
        ServerConfig {
            max_line_len: 128,
            ..ServerConfig::default()
        },
    );
    let (address, stop) = start_inbound(server).await;

    let mut client = RawClient::connect(address).await;
    assert_eq!(client.read_reply().await.0, 220);
    let (code, text) = client.send(&format!("NOOP {}", "a".repeat(512))).await;
    assert_eq!(code, 500, "{text}");
    assert!(text.contains("line too long"), "{text}");
    // The session is still usable: the oversized line was drained, not left to
    // corrupt the next command.
    assert_eq!(client.send("NOOP").await.0, 250);

    let _ = stop.send(());
}

#[tokio::test]
async fn the_command_budget_closes_the_session_with_421() {
    let env = TestEnv::new();
    let server = server_with(
        &env,
        ServerConfig {
            max_commands: 3,
            ..ServerConfig::default()
        },
    );
    let (address, stop) = start_inbound(server).await;

    let mut client = RawClient::connect(address).await;
    assert_eq!(client.read_reply().await.0, 220);
    // EHLO is command 1, the two NOOPs are 2 and 3, the fourth is over budget.
    assert_eq!(client.ehlo("sender.example").await.0, 250);
    assert_eq!(client.send("NOOP").await.0, 250);
    assert_eq!(client.send("NOOP").await.0, 250);
    let (code, text) = client.send("NOOP").await;
    assert_eq!(code, 421, "{text}");
    assert!(text.contains("too many commands"), "{text}");
    assert!(client.at_eof().await, "the connection is closed");

    let _ = stop.send(());
}

#[tokio::test]
async fn unknown_and_unimplemented_commands_get_500_and_502() {
    let env = TestEnv::new();
    let server = server_with(&env, ServerConfig::default());
    let (address, stop) = start_inbound(server).await;

    let mut client = RawClient::connect(address).await;
    assert_eq!(client.read_reply().await.0, 220);
    assert_eq!(client.ehlo("sender.example").await.0, 250);
    assert_eq!(client.send("FROBNICATE now").await.0, 500);
    assert_eq!(client.send("VRFY carol").await.0, 502);
    assert_eq!(client.send("EXPN list").await.0, 502);
    assert_eq!(client.send("AUTH PLAIN abcd").await.0, 502);
    assert_eq!(client.send("MAIL TO:<dana@example.org>").await.0, 501);

    let _ = stop.send(());
}

/// Build a `Subject: x` + body payload of exactly `body.len()` bytes.
fn formatted(body: &str) -> String {
    format!("Subject: big\r\nFrom: dana@example.org\r\n\r\n{body}")
}
