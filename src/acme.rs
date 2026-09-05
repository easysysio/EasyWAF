// =========================================================
// acme.rs — EasyWAF
// Certificate issuance and renewal over ACME (HTTP-01).
//
// EasyWAF answers the validation request itself rather than
// writing a file into a webroot: it already owns the port
// the challenge arrives on, so there is no directory to
// share with a backend and nothing to disagree about. See
// docs/design/acme.md.
//
// Scoped to HTTP-01. Wildcards need DNS-01, which needs
// provider credentials and an abstraction behind them.
// =========================================================

// The issuance flow that calls publish/withdraw lands in the next slice of
// 0.5.0; until then only the tests exercise them. Removed with that commit.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

/// Path prefix the CA fetches the token from. Fixed by RFC 8555.
pub const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// `token -> key authorization`, live only while an order is in flight.
///
/// In memory rather than in the database, deliberately. An interrupted order is
/// retried from the start, and a token that outlived the order it belonged to
/// is worse than no token at all — it answers a validation nobody is waiting
/// for.
type TokenMap = RwLock<HashMap<String, String>>;

static TOKENS: OnceLock<TokenMap> = OnceLock::new();

fn tokens() -> &'static TokenMap {
    TOKENS.get_or_init(|| RwLock::new(HashMap::new()))
}

// ─── Challenge store ─────────────────────────────────────

/// Publish a challenge answer for the CA to fetch.
pub fn publish(token: &str, key_authorization: &str) {
    if let Ok(mut m) = tokens().write() {
        m.insert(token.to_string(), key_authorization.to_string());
    }
}

/// Remove one, once its order has finished either way.
pub fn withdraw(token: &str) {
    if let Ok(mut m) = tokens().write() {
        m.remove(token);
    }
}

/// The answer for a token, if one is currently published.
pub fn answer(token: &str) -> Option<String> {
    tokens().read().ok()?.get(token).cloned()
}

/// How many answers are currently published — for the GUI and for tests.
pub fn pending() -> usize {
    tokens().read().map(|m| m.len()).unwrap_or(0)
}

/// A guard that withdraws its token when dropped.
///
/// Orders fail in several places — validation times out, finalisation is
/// rejected, the process is interrupted — and each early return would otherwise
/// have to remember to clean up. Leaving a stale token published is not
/// catastrophic but it is untidy in a way that accumulates.
pub struct PublishedToken(String);

impl PublishedToken {
    pub fn new(token: &str, key_authorization: &str) -> Self {
        publish(token, key_authorization);
        Self(token.to_string())
    }
}

impl Drop for PublishedToken {
    fn drop(&mut self) {
        withdraw(&self.0);
    }
}

// ─── Request matching ────────────────────────────────────

/// The token from an ACME challenge path, if the path is one.
///
/// Matched on the exact prefix and a non-empty remainder with no further path
/// separators — a token is a single opaque base64url segment, so anything
/// deeper is not a challenge and must not be treated as one.
pub fn token_from_path(path: &str) -> Option<&str> {
    let rest = path.strip_prefix(CHALLENGE_PREFIX)?;
    if rest.is_empty() || rest.contains('/') {
        return None;
    }
    Some(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_a_challenge_path() {
        assert_eq!(token_from_path("/.well-known/acme-challenge/abc123"), Some("abc123"));
    }

    #[test]
    fn rejects_paths_that_only_look_like_one() {
        // A deeper path is not a token, and must not be answered from the map.
        assert_eq!(token_from_path("/.well-known/acme-challenge/a/b"), None);
        assert_eq!(token_from_path("/.well-known/acme-challenge/"), None);
        assert_eq!(token_from_path("/.well-known/acme-challenge"), None);
        assert_eq!(token_from_path("/x/.well-known/acme-challenge/abc"), None);
        assert_eq!(token_from_path("/"), None);
    }

    #[test]
    fn publishes_and_withdraws() {
        publish("tok-a", "tok-a.keyauth");
        assert_eq!(answer("tok-a").as_deref(), Some("tok-a.keyauth"));
        withdraw("tok-a");
        assert_eq!(answer("tok-a"), None);
    }

    #[test]
    fn the_guard_withdraws_on_drop() {
        {
            let _g = PublishedToken::new("tok-b", "tok-b.keyauth");
            assert_eq!(answer("tok-b").as_deref(), Some("tok-b.keyauth"));
        }
        // Orders fail in several places; the guard is what stops each early
        // return having to remember to clean up.
        assert_eq!(answer("tok-b"), None);
    }

    #[test]
    fn an_unknown_token_is_not_answered() {
        assert_eq!(answer("never-published"), None);
    }
}
