//! Value types shared across the server: email addresses, message ids,
//! direction and API-key scopes.

use std::fmt;

use crate::error::{CoreError, Result};

/// RFC 5321 limits the reverse-path to 254 characters in dotted form.
pub const MAX_ADDRESS_LEN: usize = 254;
/// RFC 5321 caps the local part at 64 characters.
pub const MAX_LOCAL_LEN: usize = 64;
/// DNS caps a single label at 63 characters.
pub const MAX_DOMAIN_LABEL_LEN: usize = 63;

/// Bytes that must never appear in an address: SMTP syntax (`<>()[]\;:`) and
/// header/list separators (`,`, quotes). Letting any of them through would turn
/// `Display` into an injection primitive when an address is written into a
/// command line or a header.
const FORBIDDEN_BYTES: &[u8] = b"<>()[]\x5C;:\x22,'";

/// A syntactically valid email address, split into its two halves.
///
/// The fields are private so an `EmailAddress` can only come from [`parse`]:
/// every value in the system has passed the byte, length and LDH checks.
///
/// v1 policy is **ASCII-only**: SMTPUTF8 is not supported, so any byte >= 0x80
/// is rejected instead of being smuggled into a 7-bit protocol.
///
/// The domain is stored lowercased (DNS is case-insensitive); the local part
/// keeps its original case because SMTP peers may treat it as significant.
/// [`normalized`] is the case-folded form used for account uniqueness.
///
/// [`parse`]: EmailAddress::parse
/// [`normalized`]: EmailAddress::normalized
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EmailAddress {
    local: String,
    domain: String,
}

impl EmailAddress {
    /// Parse `local@domain`.
    ///
    /// Rules (deliberately strict; they are the ones the server relies on):
    /// exactly one `@`; ASCII only; no byte `<= 0x20`, no DEL and none of
    /// [`FORBIDDEN_BYTES`]; local part 1-64 chars, no leading/trailing or
    /// doubled dot; domain made of LDH labels (letters, digits, hyphens), at
    /// least one dot, no empty label, no label longer than 63, no label
    /// starting or ending with a hyphen; total length at most
    /// [`MAX_ADDRESS_LEN`].
    ///
    /// Input is **not trimmed**: a leading/trailing space is a whitespace byte
    /// and gets rejected like any other.
    pub fn parse(input: &str) -> Result<Self> {
        if input.is_empty() {
            return Err(CoreError::InvalidAddress("address is empty".to_string()));
        }
        if input.len() > MAX_ADDRESS_LEN {
            return Err(CoreError::InvalidAddress(format!(
                "{input:?} is {} bytes, more than the {MAX_ADDRESS_LEN} limit",
                input.len()
            )));
        }
        for (index, byte) in input.bytes().enumerate() {
            if byte <= 0x20 || byte == 0x7f {
                return Err(CoreError::InvalidAddress(format!(
                    "{input:?} contains whitespace or control byte 0x{byte:02x} at offset {index}"
                )));
            }
            if byte >= 0x80 {
                return Err(CoreError::InvalidAddress(format!(
                    "{input:?} contains non-ASCII byte 0x{byte:02x} at offset {index} (SMTPUTF8 is not supported in v1)"
                )));
            }
            if FORBIDDEN_BYTES.contains(&byte) {
                return Err(CoreError::InvalidAddress(format!(
                    "{input:?} contains the forbidden byte 0x{byte:02x} ({}) at offset {index}",
                    char::from(byte)
                )));
            }
        }

        let mut parts = input.split('@');
        let local = parts.next().unwrap_or_default();
        let domain = parts
            .next()
            .ok_or_else(|| CoreError::InvalidAddress(format!("missing '@' in {input:?}")))?;
        if parts.next().is_some() {
            return Err(CoreError::InvalidAddress(format!(
                "more than one '@' in {input:?}"
            )));
        }

        if local.is_empty() {
            return Err(CoreError::InvalidAddress(format!(
                "empty local part in {input:?}"
            )));
        }
        if local.len() > MAX_LOCAL_LEN {
            return Err(CoreError::InvalidAddress(format!(
                "local part of {input:?} is {} bytes, more than the {MAX_LOCAL_LEN} limit",
                local.len()
            )));
        }
        if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
            return Err(CoreError::InvalidAddress(format!(
                "local part of {input:?} has an empty atom"
            )));
        }

        if domain.is_empty() {
            return Err(CoreError::InvalidAddress(format!(
                "empty domain in {input:?}"
            )));
        }
        if !domain.contains('.') {
            return Err(CoreError::InvalidAddress(format!(
                "domain {domain:?} has no dot (not a FQDN)"
            )));
        }
        if domain.starts_with('.') || domain.ends_with('.') {
            return Err(CoreError::InvalidAddress(format!(
                "domain {domain:?} starts or ends with a dot"
            )));
        }
        for label in domain.split('.') {
            if label.is_empty() {
                return Err(CoreError::InvalidAddress(format!(
                    "domain {domain:?} contains an empty label"
                )));
            }
            if label.len() > MAX_DOMAIN_LABEL_LEN {
                return Err(CoreError::InvalidAddress(format!(
                    "domain label {label:?} is {} bytes, more than the {MAX_DOMAIN_LABEL_LEN} limit",
                    label.len()
                )));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(CoreError::InvalidAddress(format!(
                    "domain label {label:?} starts or ends with a hyphen"
                )));
            }
            if !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(CoreError::InvalidAddress(format!(
                    "domain label {label:?} is not LDH (letters, digits, hyphens)"
                )));
            }
        }

        Ok(Self {
            local: local.to_string(),
            domain: domain.to_ascii_lowercase(),
        })
    }

    /// Local part, original case preserved.
    pub fn local(&self) -> &str {
        &self.local
    }

    /// Domain, always lowercase.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Case-insensitive comparison key: `local` ASCII-folded plus the already
    /// lowercase domain. Used for account uniqueness and lookups, never for
    /// delivery (the SMTP envelope keeps the original local part).
    pub fn normalized(&self) -> String {
        format!("{}@{}", self.local.to_ascii_lowercase(), self.domain)
    }
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

/// A message identifier, allocated before the body is sealed so the seal can be
/// bound to it as associated data (`account:{account}:message:{id}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId(pub u64);

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Which way a message travels through the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Submitted by an account and delivered to the outside world.
    Out,
    /// Received from the outside world for an account.
    In,
}

impl Direction {
    /// Wire/storage representation (matches the `messages.direction` CHECK).
    pub const fn as_str(self) -> &'static str {
        match self {
            Direction::Out => "out",
            Direction::In => "in",
        }
    }

    /// Decode a stored representation; `None` for anything else. Surrounding
    /// whitespace is trimmed and matching is ASCII-case-insensitive, the same
    /// discipline as the other enum parsers.
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "out" => Some(Direction::Out),
            "in" => Some(Direction::In),
            _ => None,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Mailbox folder a message lives in.
///
/// Deliberately a closed set: SQLite holds the same values behind a `CHECK`, so
/// an unknown value can only come from a hand-edited file and is reported as a
/// corrupt row rather than silently accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum MessageFolder {
    /// Received mail, the default for every row.
    #[default]
    Inbox,
    /// Mail this account sent.
    Sent,
    /// Suspected junk; the client moves it here, the server never guesses.
    Spam,
    /// Soft-deleted mail, purged with `empty_folder`.
    Trash,
}

/// Every folder, in the order the API documents them (and the order of the
/// sidebar badges).
const ALL_FOLDERS: [MessageFolder; 4] = [
    MessageFolder::Inbox,
    MessageFolder::Sent,
    MessageFolder::Spam,
    MessageFolder::Trash,
];

impl MessageFolder {
    /// Every folder, in documented order.
    pub fn all() -> &'static [MessageFolder] {
        &ALL_FOLDERS
    }

    /// Wire/storage representation (matches the `messages.folder` CHECK).
    pub const fn as_str(self) -> &'static str {
        match self {
            MessageFolder::Inbox => "inbox",
            MessageFolder::Sent => "sent",
            MessageFolder::Spam => "spam",
            MessageFolder::Trash => "trash",
        }
    }

    /// Decode a stored or client-supplied representation; `None` for anything
    /// else. Trimmed and ASCII-case-insensitive, like the other enum parsers.
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "inbox" => Some(MessageFolder::Inbox),
            "sent" => Some(MessageFolder::Sent),
            "spam" => Some(MessageFolder::Spam),
            "trash" => Some(MessageFolder::Trash),
            _ => None,
        }
    }
}

impl fmt::Display for MessageFolder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Permission scope carried by an API key (`send`, `read`, `full`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiKeyScope {
    /// May submit mail only.
    Send,
    /// May read messages, events and templates only.
    Read,
    /// Everything: send, read, manage keys and webhooks.
    Full,
}

const ALL_SCOPES: [ApiKeyScope; 3] = [ApiKeyScope::Send, ApiKeyScope::Read, ApiKeyScope::Full];

impl ApiKeyScope {
    /// Every scope, in the order the API documents them.
    pub fn all() -> &'static [ApiKeyScope] {
        &ALL_SCOPES
    }

    /// Canonical lowercase wire representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            ApiKeyScope::Send => "send",
            ApiKeyScope::Read => "read",
            ApiKeyScope::Full => "full",
        }
    }

    /// Parse one scope from its wire representation (trimmed,
    /// case-insensitive). The error echoes the raw input.
    pub fn parse(input: &str) -> Result<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "send" => Ok(ApiKeyScope::Send),
            "read" => Ok(ApiKeyScope::Read),
            "full" => Ok(ApiKeyScope::Full),
            _ => Err(CoreError::InvalidScope(input.to_string())),
        }
    }
}

impl fmt::Display for ApiKeyScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Role an account holds inside one organization.
///
/// Deliberately a closed set with a fixed ordering: `owner` outranks `admin`,
/// which outranks `member`, and the ordering is what the store's last-owner
/// guard and the API's "admin or better" check compare. SQLite holds the same
/// three values behind a `CHECK` on `accounts.role`, so an unknown value can
/// only come from a hand-edited file.
///
/// A `NULL` organization (a personal workspace) still carries `role = owner`: the
/// column states "this account owns what it has", the organization row is what
/// makes it a team.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OrgRole {
    /// Full control, including managing other admins. At least one per
    /// organization must remain.
    Owner,
    /// Manages members, invitations and display names; cannot touch owners.
    Admin,
    /// Ordinary member: their own mailbox, nothing else.
    Member,
}

const ALL_ORG_ROLES: [OrgRole; 3] = [OrgRole::Owner, OrgRole::Admin, OrgRole::Member];

impl OrgRole {
    /// Every role, most powerful first.
    pub fn all() -> &'static [OrgRole] {
        &ALL_ORG_ROLES
    }

    /// Wire/storage representation (matches the `accounts.role` CHECK).
    pub const fn as_str(self) -> &'static str {
        match self {
            OrgRole::Owner => "owner",
            OrgRole::Admin => "admin",
            OrgRole::Member => "member",
        }
    }

    /// Decode a stored or client-supplied representation; `None` for anything
    /// else. Trimmed and ASCII-case-insensitive, like the other enum parsers.
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "owner" => Some(OrgRole::Owner),
            "admin" => Some(OrgRole::Admin),
            "member" => Some(OrgRole::Member),
            _ => None,
        }
    }

    /// True when the role may perform organization administration (manage
    /// members, invitations and catch-all routing). Both `owner` and `admin`
    /// qualify; `member` does not.
    pub const fn is_admin(self) -> bool {
        matches!(self, OrgRole::Owner | OrgRole::Admin)
    }
}

impl fmt::Display for OrgRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the inbound server does with mail addressed to an unknown local part of
/// a managed domain.
///
/// A catch-all is opt-in per domain and never implicit: with no rule the server
/// keeps answering `550`, which is the only anti-enumeration answer that does not
/// lie. `Route` delivers into one mailbox, `Discard` accepts and drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CatchallAction {
    /// Deliver into `catchall_rules.target_account_id`'s mailbox.
    Route,
    /// Accept the message (`250`, so the sender cannot probe which addresses
    /// exist) and drop it, logging that it happened.
    Discard,
}

const ALL_CATCHALL_ACTIONS: [CatchallAction; 2] = [CatchallAction::Route, CatchallAction::Discard];

impl CatchallAction {
    /// Every action, as the API documents them.
    pub fn all() -> &'static [CatchallAction] {
        &ALL_CATCHALL_ACTIONS
    }

    /// Wire/storage representation (matches the `catchall_rules.action` CHECK).
    pub const fn as_str(self) -> &'static str {
        match self {
            CatchallAction::Route => "route",
            CatchallAction::Discard => "discard",
        }
    }

    /// Decode a stored or client-supplied representation; `None` for anything
    /// else. Trimmed and ASCII-case-insensitive, like the other enum parsers.
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "route" => Some(CatchallAction::Route),
            "discard" => Some(CatchallAction::Discard),
            _ => None,
        }
    }
}

impl fmt::Display for CatchallAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_parse_accepts_valid_addresses() {
        let cases = [
            "user@example.com",
            "a@b.co",
            "first.last+tag@mail.example.org",
            "ops@sub.domain.example.co.uk",
            "User@Example.COM",
            "x_y-z%1@example.io",
        ];
        for input in cases {
            let parsed = EmailAddress::parse(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(
                parsed.domain(),
                parsed.domain().to_ascii_lowercase(),
                "domain must be lowercased for {input}"
            );
        }
    }

    #[test]
    fn email_parse_reject_table() {
        let long_local = format!("{}@example.com", "a".repeat(MAX_LOCAL_LEN + 1));
        let long_label = format!("user@{}.com", "a".repeat(MAX_DOMAIN_LABEL_LEN + 1));
        let too_long = format!("{}@example.com", "a".repeat(MAX_ADDRESS_LEN));
        let cases: &[&str] = &[
            // Protocol injection: CRLF, bare LF, NUL, space, comma.
            "a@b.c\r\nDATA",
            "a@b.c\nX",
            "user@example.com\0",
            "a b@example.com",
            "user@exa mple.com",
            "a,b@example.com",
            "user\t@example.com",
            "user@example.com\u{7f}",
            // Non-ASCII (SMTPUTF8 not supported in v1).
            "user@exämple.com",
            "üser@example.com",
            // Local-part shape.
            ".lead@example.com",
            "trail.@example.com",
            "doub..le@example.com",
            "",
            "@example.com",
            "user@",
            // Domain shape.
            "user@-bad.com",
            "user@bad-.com",
            "user@exa..mple.com",
            "user@example",
            "user@.example.com",
            "user@example.com.",
            // Syntax.
            "user@@example.com",
            "a@b@example.com",
            "no-at-sign",
            "<user@example.com>",
            "user@example.com;",
            "user@example.com:25",
            "user@[127.0.0.1]",
            "user'x@example.com",
            "user\"x@example.com",
            "user\\x@example.com",
            "user(x)@example.com",
            long_local.as_str(),
            long_label.as_str(),
            too_long.as_str(),
        ];
        for input in cases {
            let err = EmailAddress::parse(input).unwrap_err();
            assert!(
                matches!(err, CoreError::InvalidAddress(_)),
                "{input:?} -> {err}"
            );
        }
    }

    #[test]
    fn email_parse_accepts_the_length_boundaries() {
        let domain = "example.com";
        let max_local = "a".repeat(MAX_LOCAL_LEN);
        assert!(EmailAddress::parse(&format!("{max_local}@{domain}")).is_ok());

        // A total-length boundary address needs a long *domain*: the local part
        // is capped at MAX_LOCAL_LEN, so `local@example.com` cannot reach
        // MAX_ADDRESS_LEN by growing the local half. Three legal LDH labels
        // fill the remaining 189 bytes (63 + '.' + 63 + '.' + 61).
        let local = "a".repeat(MAX_LOCAL_LEN);
        let long_domain = format!(
            "{}.{}.{}",
            "b".repeat(MAX_DOMAIN_LABEL_LEN),
            "c".repeat(MAX_DOMAIN_LABEL_LEN),
            "d".repeat(MAX_ADDRESS_LEN - MAX_LOCAL_LEN - 1 - 2 * MAX_DOMAIN_LABEL_LEN - 2)
        );
        let input = format!("{local}@{long_domain}");
        assert_eq!(input.len(), MAX_ADDRESS_LEN);
        assert!(EmailAddress::parse(&input).is_ok());

        // One byte more is over the limit, regardless of where it sits.
        let over = format!("{local}@{long_domain}a");
        assert_eq!(over.len(), MAX_ADDRESS_LEN + 1);
        assert!(EmailAddress::parse(&over).is_err());
    }

    #[test]
    fn email_fields_are_private_behind_accessors() {
        let parsed = EmailAddress::parse("MixedCase@Example.COM").unwrap();
        assert_eq!(parsed.local(), "MixedCase");
        assert_eq!(parsed.domain(), "example.com");
        assert_eq!(parsed.to_string(), "MixedCase@example.com");
    }

    #[test]
    fn normalized_folds_the_local_part_for_uniqueness() {
        let a = EmailAddress::parse("User@Example.COM").unwrap();
        let b = EmailAddress::parse("user@example.com").unwrap();
        assert_eq!(a.normalized(), "user@example.com");
        assert_eq!(a.normalized(), b.normalized());
        assert_ne!(a.to_string(), b.to_string(), "delivery address keeps case");
    }

    #[test]
    fn message_id_display_is_the_bare_number() {
        assert_eq!(MessageId(42).to_string(), "42");
        assert!(MessageId(2) < MessageId(10));
    }

    #[test]
    fn direction_roundtrips_and_parses_leniently() {
        for d in [Direction::Out, Direction::In] {
            assert_eq!(Direction::parse(d.as_str()), Some(d));
        }
        assert_eq!(Direction::parse(" OUT "), Some(Direction::Out));
        assert_eq!(Direction::parse("In"), Some(Direction::In));
        assert_eq!(Direction::parse("sideways"), None);
        assert_eq!(Direction::Out.to_string(), "out");
        assert_eq!(Direction::In.to_string(), "in");
    }

    #[test]
    fn folder_roundtrips_and_parses_leniently() {
        for folder in MessageFolder::all() {
            assert_eq!(MessageFolder::parse(folder.as_str()), Some(*folder));
            assert_eq!(folder.to_string(), folder.as_str());
        }
        assert_eq!(MessageFolder::parse(" SPAM "), Some(MessageFolder::Spam));
        assert_eq!(MessageFolder::parse("Trash"), Some(MessageFolder::Trash));
        assert_eq!(MessageFolder::parse("archive"), None);
        assert_eq!(MessageFolder::parse(""), None);
        assert_eq!(MessageFolder::default(), MessageFolder::Inbox);
        assert_eq!(
            MessageFolder::all(),
            &[
                MessageFolder::Inbox,
                MessageFolder::Sent,
                MessageFolder::Spam,
                MessageFolder::Trash
            ]
        );
    }

    #[test]
    fn scope_parse_accepts_the_documented_values() {
        assert_eq!(ApiKeyScope::parse("send").unwrap(), ApiKeyScope::Send);
        assert_eq!(ApiKeyScope::parse("read").unwrap(), ApiKeyScope::Read);
        assert_eq!(ApiKeyScope::parse("full").unwrap(), ApiKeyScope::Full);
        assert_eq!(ApiKeyScope::parse(" FULL ").unwrap(), ApiKeyScope::Full);
    }

    #[test]
    fn scope_parse_rejects_unknown_values_echoing_the_raw_input() {
        for input in ["", "admin", "send,read", "wRite"] {
            let err = ApiKeyScope::parse(input).unwrap_err();
            assert!(
                matches!(err, CoreError::InvalidScope(_)),
                "{input:?} -> {err}"
            );
            assert!(
                err.to_string().contains(&format!("{input:?}")),
                "error must echo the raw input {input:?}: {err}"
            );
        }
    }

    #[test]
    fn scope_all_lists_every_scope_in_documented_order() {
        assert_eq!(
            ApiKeyScope::all(),
            &[ApiKeyScope::Send, ApiKeyScope::Read, ApiKeyScope::Full]
        );
        for scope in ApiKeyScope::all() {
            assert_eq!(ApiKeyScope::parse(scope.as_str()).unwrap(), *scope);
            assert!(!scope.to_string().is_empty());
        }
    }

    #[test]
    fn org_roles_round_trip_and_rank_owner_above_admin_above_member() {
        assert_eq!(
            OrgRole::all(),
            &[OrgRole::Owner, OrgRole::Admin, OrgRole::Member]
        );
        for role in OrgRole::all() {
            assert_eq!(OrgRole::parse(role.as_str()), Some(*role));
            assert_eq!(OrgRole::parse(&role.as_str().to_uppercase()), Some(*role));
            assert_eq!(role.to_string(), role.as_str());
        }
        assert!(OrgRole::Owner < OrgRole::Admin);
        assert!(OrgRole::Admin < OrgRole::Member);
        assert!(OrgRole::Owner.is_admin());
        assert!(OrgRole::Admin.is_admin());
        assert!(!OrgRole::Member.is_admin());
        for junk in ["", "root", "owner,admin", "administrator"] {
            assert_eq!(OrgRole::parse(junk), None, "{junk:?} is not a role");
        }
    }

    #[test]
    fn catchall_actions_round_trip() {
        assert_eq!(
            CatchallAction::all(),
            &[CatchallAction::Route, CatchallAction::Discard]
        );
        for action in CatchallAction::all() {
            assert_eq!(CatchallAction::parse(action.as_str()), Some(*action));
            assert_eq!(action.to_string(), action.as_str());
        }
        for junk in ["", "bounce", "forward"] {
            assert_eq!(CatchallAction::parse(junk), None, "{junk:?}");
        }
    }
}
