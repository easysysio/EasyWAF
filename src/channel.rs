// =========================================================
// channel.rs — EasyWAF
// What the three signed channels — rule sets, IP lists and
// the country database — check the same way.
//
// Each channel has its own module, because what it mirrors
// and when it applies differ. These are the parts that do
// not: what a manifest may name, and how a file is compared
// with the digest the signed manifest gives for it.
// =========================================================

/// Whether an id from a manifest is a plain name: lowercase letters, digits and
/// dashes, at most 64 of them. Ids name files on disk, so nothing else is let
/// through.
pub fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Whether a manifest's file path may be appended to the channel URL.
///
/// The manifest is signed, so this is not the line of defence — but a signed
/// manifest naming `../../something` is still not something to follow.
pub fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.split('/').any(|part| part.is_empty() || part == "." || part == "..")
        && path.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(&b))
}

/// The SHA-256 of `data` as lowercase hex, the form a manifest gives it in.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// The first twelve characters of a digest, for a message a person reads.
pub fn short(digest: &str) -> &str {
    &digest[..12.min(digest.len())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_cannot_name_its_way_out_of_the_channel() {
        assert!(safe_relative("lists/drop.txt"));
        for bad in ["", "/etc/passwd", "../x", "lists/../../x", "lists//x", "./x", "a b"] {
            assert!(!safe_relative(bad), "{bad:?} was allowed");
        }
    }

    #[test]
    fn an_id_is_a_plain_name() {
        assert!(is_slug("spamhaus-drop"));
        for bad in ["", "Spamhaus", "a/b", "a.b", &"x".repeat(65)] {
            assert!(!is_slug(bad), "{bad:?} was allowed");
        }
    }

    #[test]
    fn digests_are_the_form_a_manifest_gives() {
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(short("e3b0c44298fc1c149afbf4c8"), "e3b0c44298fc");
        assert_eq!(short("abc"), "abc");
    }
}
