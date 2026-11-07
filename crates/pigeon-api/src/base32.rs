//! RFC 4648 base32, uppercased and unpadded.
//!
//! TOTP provisioning is base32 by convention: every authenticator app
//! (Google Authenticator, 1Password, Aegis, …) reads the `secret=` parameter of
//! an `otpauth://` URI as base32 with **no** padding, and the QR code encodes
//! that same string. The workspace has no base32 crate and the TOTP secret is
//! the only value that needs the encoding, so the alphabet and the two
//! transitions live here rather than in a dependency.
//!
//! [`decode`] is strict: an unknown character, or a final group whose trailing
//! bits are not zero, is rejected instead of being silently truncated. That
//! matters because the decoded bytes are the HMAC key — two spellings of the
//! same secret would be two different secrets, and a lenient decoder would make
//! "this code does not work" depend on how the string was typed.

/// RFC 4648 §6 alphabet (uppercase A–Z then 2–7).
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encode `bytes` as uppercase base32 with no `=` padding.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 0x1f) as usize]));
        }
    }
    if bits > 0 {
        // Left-align the remaining bits and pad the group with zero bits.
        out.push(char::from(
            ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize],
        ));
    }
    out
}

/// Decode unpadded base32. `None` for any input that is not a canonical
/// encoding of some byte string.
///
/// Lowercase letters are accepted (the alphabet is case-insensitive on input,
/// uppercase on output) and `=` padding is *not*: a TOTP secret is exchanged
/// unpadded, and accepting both spellings would give one secret two valid
/// encodings.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for character in text.chars() {
        let value = value_of(character)?;
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    // Spare bits must be zero, otherwise the text is one of several spellings
    // of the same bytes and re-encoding would not round-trip.
    if bits > 0 && (buffer & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

fn value_of(character: char) -> Option<u8> {
    match character {
        'A'..='Z' => Some(character as u8 - b'A'),
        'a'..='z' => Some(character as u8 - b'a'),
        '2'..='7' => Some(character as u8 - b'2' + 26),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_matches_the_rfc4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(encode(plain.as_bytes()), encoded, "encode {plain:?}");
            assert_eq!(
                decode(encoded).as_deref(),
                Some(plain.as_bytes()),
                "decode {encoded:?}"
            );
        }
    }

    #[test]
    fn roundtrip_is_exact_for_every_length() {
        // 0..=40 bytes covers every remainder class and the padding branch.
        for length in 0..=40 {
            let bytes: Vec<u8> = (0..length).map(|index| (index * 37 + 11) as u8).collect();
            let encoded = encode(&bytes);
            assert!(!encoded.contains('='), "no padding: {encoded}");
            assert_eq!(decode(&encoded), Some(bytes), "length {length}");
        }
    }

    #[test]
    fn decoding_rejects_junk_and_non_canonical_input() {
        assert_eq!(decode("MZXW6YTBOI="), None, "padding is not accepted");
        assert_eq!(decode("MZXW6YTBO1"), None, "8 is outside the alphabet");
        assert_eq!(decode("MZ XW"), None, "spaces are not skipped");
        assert_eq!(decode("MB"), None, "non-zero spare bits are not canonical");
        assert_eq!(decode("MY"), Some(vec![0x66]), "canonical 'f'");
    }

    #[test]
    fn a_twenty_byte_totp_secret_encodes_to_thirty_two_characters() {
        // The shape every authenticator app expects for a 160-bit secret.
        let secret = [0x42u8; 20];
        let encoded = encode(&secret);
        assert_eq!(encoded.len(), 32);
        assert!(encoded
            .chars()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)));
        assert_eq!(decode(&encoded), Some(secret.to_vec()));
    }
}
