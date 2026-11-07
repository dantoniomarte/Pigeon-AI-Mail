//! Additional-authenticated-data bindings for sealed content.
//!
//! Every sealed blob is bound to its context, so a blob cannot be replayed onto
//! another account, message or attachment:
//!
//! * message body — `account:{account_id}:message:{message_id}`
//! * attachment — `account:{account_id}:message:{message_id}:attachment:{ordinal}:{filename}`
//! * domain DKIM private key — `dkim:{domain}`
//! * TOTP secret — `totp:{account_id}`
//!
//! The body form is the one `docs/e2ee-model.md` and the `store` crate document
//! (`insert_message` refuses to persist a body sealed under anything else). The
//! attachment form adds the part's ordinal and filename because attachments share
//! their message's content key: without them, two files in one message (even two
//! with the same name) would be interchangeable.
//!
//! These strings are a wire format. Changing one makes every existing blob
//! unreadable, so they live in one place with tests that pin the exact text.

/// AAD for a message body or its content key.
pub fn message(account_id: i64, message_id: i64) -> String {
    format!("account:{account_id}:message:{message_id}")
}

/// AAD for an attachment whose bytes are sealed under the message content key.
///
/// `ordinal` is the part's position in the message (0-based), which is how the
/// inbound parser will number the parts it seals.
pub fn attachment(account_id: i64, message_id: i64, ordinal: usize, filename: &str) -> String {
    format!(
        "{}{ATTACHMENT_SUFFIX}{ordinal}:{filename}",
        message(account_id, message_id)
    )
}

/// AAD for a domain's sealed RSA DKIM private key.
///
/// Keyed by the **domain name**, not by a dashboard row id: DKIM identities are
/// domain-scoped (`store`'s `dkim_keys` is unique on `domain`), so the binding
/// states which sending domain the key signs for. Two dashboard rows for the
/// same domain therefore share one key — which is the point, since receivers
/// resolve a key by domain and selector only.
pub fn dkim_key(domain: &str) -> String {
    format!("dkim:{domain}")
}

/// AAD for an account's wrapped TOTP secret.
///
/// One string per account, so a wrapped secret cannot be transplanted onto
/// another account even by someone who can write the database: opening it with
/// the wrong `account_id` fails authentication instead of handing over a
/// second factor that then protects the wrong login.
pub fn totp(account_id: i64) -> String {
    format!("totp:{account_id}")
}

const ATTACHMENT_SUFFIX: &str = ":attachment:";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_aad_is_pinned() {
        assert_eq!(message(1, 42), "account:1:message:42");
        assert_eq!(message(0, 0), "account:0:message:0");
    }

    #[test]
    fn attachment_aad_extends_the_message_aad() {
        assert_eq!(
            attachment(1, 42, 0, "receipt.pdf"),
            "account:1:message:42:attachment:0:receipt.pdf"
        );
        assert_ne!(
            attachment(1, 42, 0, "a.pdf"),
            attachment(1, 42, 1, "b.pdf"),
            "two attachments in one message must not share an AAD"
        );
        assert_ne!(
            attachment(1, 42, 0, "image.png"),
            attachment(1, 42, 1, "image.png"),
            "same-named parts stay distinguishable"
        );
        assert!(attachment(1, 42, 0, "a.pdf").starts_with(&message(1, 42)));
    }

    #[test]
    fn different_messages_and_accounts_never_collide() {
        assert_ne!(message(1, 2), message(2, 1));
        assert_ne!(message(1, 42), message(1, 43));
    }

    #[test]
    fn dkim_key_aad_is_pinned_and_per_domain() {
        assert_eq!(dkim_key("example.com"), "dkim:example.com");
        assert_eq!(dkim_key("mail.example.com"), "dkim:mail.example.com");
        assert_ne!(
            dkim_key("a.example"),
            dkim_key("b.example"),
            "two domains must never share a DKIM key binding"
        );
    }

    #[test]
    fn totp_aad_is_pinned_per_account() {
        assert_eq!(totp(1), "totp:1");
        assert_ne!(totp(1), totp(2));
        assert_ne!(totp(1), totp(11));
    }
}
