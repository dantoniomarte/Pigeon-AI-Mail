//! Public identifier generation.
//!
//! Every resource the API exposes carries a prefixed id (`eml_`, `msg_`,
//! `tpl_`, `drf_`, `dom_`, `whk_`, `key_`, `atc_`, `sess_`) so a leaked id is self-describing in
//! logs and a client cannot confuse one resource kind with another. The suffix
//! is 16 lowercase hex characters from the OS CSPRNG — enough entropy that an
//! id is not guessable by enumeration, which matters for objects a client
//! reaches by id before any other check.
//!
//! Length and charset are pinned by `openapi.yaml` (`^eml_[a-z0-9]{8,32}$` and
//! friends); [`is_well_formed`] keeps the id a client can send back inside that
//! alphabet.

/// Prefix of an outbound email id.
pub const EML: &str = "eml_";
/// Prefix of an inbound message id.
pub const MSG: &str = "msg_";
/// Prefix of a template id.
pub const TPL: &str = "tpl_";
/// Prefix of a managed domain id.
pub const DOM: &str = "dom_";
/// Prefix of a webhook id.
pub const WHK: &str = "whk_";
/// Prefix of an API key id.
pub const KEY: &str = "key_";
/// Prefix of an attachment id.
pub const ATC: &str = "atc_";
/// Prefix of a dashboard session id.
pub const SESS: &str = "sess_";
/// Prefix of an email draft id.
pub const DRF: &str = "drf_";

/// Random suffix length in hex characters (16 → 64 bits of entropy).
const SUFFIX_HEX_LEN: usize = 16;

/// `prefix` + 16 lowercase hex characters.
pub fn gen(prefix: &str) -> String {
    let random = pigeon_crypto::generate_content_key();
    format!("{prefix}{}", hex::encode(&random[..SUFFIX_HEX_LEN / 2]))
}

/// True when `id` starts with `prefix` and the remainder is 8-32 characters of
/// `[a-z0-9]`, exactly as the contract patterns require.
pub fn is_well_formed(id: &str, prefix: &str) -> bool {
    let Some(suffix) = id.strip_prefix(prefix) else {
        return false;
    };
    (8..=32).contains(&suffix.len())
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

/// Stable public id for a row that has no stored id of its own (inbound
/// messages and attachments are written by the SMTP pipeline, which will not
/// have this API's id table). Deriving it from the row id keeps the value
/// stable across processes and restarts without a coordinated allocation.
pub fn derived(prefix: &str, row_id: i64) -> String {
    format!("{prefix}{:08x}", row_id.max(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generated_ids_match_the_contract_pattern() {
        for prefix in [EML, MSG, TPL, DOM, WHK, KEY, ATC, SESS, DRF] {
            for _ in 0..32 {
                let id = gen(prefix);
                assert!(is_well_formed(&id, prefix), "{id} must be well formed");
                assert_eq!(id.len(), prefix.len() + 16);
            }
        }
    }

    #[test]
    fn generated_ids_are_unique() {
        let ids: HashSet<String> = (0..256).map(|_| gen(EML)).collect();
        assert_eq!(ids.len(), 256, "ids must not repeat");
    }

    #[test]
    fn well_formed_checks_prefix_length_and_alphabet() {
        assert!(is_well_formed("eml_9f2a44c1", EML));
        assert!(is_well_formed("eml_9f2a44c19f2a44c1", EML));
        assert!(!is_well_formed("eml_short", EML));
        assert!(!is_well_formed("msg_9f2a44c1", EML));
        assert!(!is_well_formed("eml_9F2A44C1", EML));
        assert!(!is_well_formed("eml_9f2a44c1!", EML));
        assert!(!is_well_formed("eml_", EML));
        assert!(!is_well_formed(
            "eml_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            EML
        ));
    }

    #[test]
    fn derived_ids_are_stable_and_well_formed() {
        assert_eq!(derived(MSG, 1), "msg_00000001");
        assert_eq!(derived(MSG, 1), derived(MSG, 1));
        assert_eq!(derived(ATC, 255), "atc_000000ff");
        assert!(is_well_formed(&derived(MSG, 1), MSG));
        assert!(is_well_formed(&derived(MSG, 0), MSG));
        // A negative row id is impossible; clamping keeps the id well formed.
        assert!(is_well_formed(&derived(MSG, -5), MSG));
    }
}
