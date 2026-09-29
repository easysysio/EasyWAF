// =========================================================
// challenge.rs — EasyWAF
// CAPTCHA challenge subsystem.
//
// When the WAF decides a request is suspicious-but-maybe-legit it issues a
// "challenge" instead of a hard block. The visitor is shown a self-hosted
// image CAPTCHA. On solving it they receive a short-lived, IP-bound,
// HMAC-signed "clearance" cookie and are redirected to where they were going.
// Subsequent requests with a valid clearance cookie skip the challenge.
//
// State for in-flight challenges is kept in memory (they live 3 minutes);
// the clearance cookie itself is stateless (verified by HMAC).
// =========================================================

use base64::Engine;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type HmacSha256 = Hmac<Sha256>;

/// Name of the clearance cookie set after a visitor solves a challenge.
pub const CLEARANCE_COOKIE: &str = "easywaf_clearance";

/// How long a solved clearance is valid.
const CLEARANCE_TTL_SECS: u64 = 1800; // 30 minutes

/// How long an unsolved challenge stays valid in the store.
const CHALLENGE_TTL: Duration = Duration::from_secs(180); // 3 minutes

/// How many unsolved challenges may wait at once. Each holds a few hundred
/// bytes, so this bounds the store at a few megabytes however many requests
/// cross a challenge threshold.
const MAX_PENDING: usize = 10_000;

/// Internal path prefix the proxy intercepts for challenge handling.
pub const VERIFY_PATH: &str = "/__easywaf/verify";

// ─── In-flight challenge store ───────────────────────────

/// A pending (unsolved) challenge.
struct Pending {
    answer:    String, // expected solution (uppercase)
    dest:      String, // path+query the visitor was trying to reach
    client_ip: String, // IP that requested the challenge
    expires:   Instant,
}

/// Shared, cloneable handle to the pending-challenge map.
#[derive(Clone)]
pub struct ChallengeStore {
    inner: Arc<Mutex<HashMap<String, Pending>>>,
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self { inner: Arc::new(Mutex::new(HashMap::new())) }
    }

    /// Create a new challenge for the given destination and client IP.
    /// Returns (challenge_id, captcha_png_data_uri), or `None` when
    /// [`MAX_PENDING`] challenges are already waiting — checked before the
    /// image is drawn, since drawing it is the expensive part.
    pub fn issue(&self, dest: &str, client_ip: &str) -> Option<(String, String)> {
        {
            let mut map = self.inner.lock().unwrap();
            if map.len() >= MAX_PENDING {
                let now = Instant::now();
                map.retain(|_, p| p.expires > now);
                if map.len() >= MAX_PENDING {
                    return None;
                }
            }
        }

        // `gen` is a reserved keyword in edition 2024 — call via raw identifier.
        let captcha = captcha::r#gen(captcha::Difficulty::Medium);
        let answer  = captcha.chars_as_string().to_uppercase();
        let png     = captcha.as_png().unwrap_or_default();
        let data_uri = format!(
            "data:image/png;base64,{}",
            base64::engine::general_purpose::STANDARD.encode(&png)
        );

        let id = random_id();

        let mut map = self.inner.lock().unwrap();
        map.insert(id.clone(), Pending {
            answer,
            dest: dest.to_string(),
            client_ip: client_ip.to_string(),
            expires: Instant::now() + CHALLENGE_TTL,
        });

        Some((id, data_uri))
    }

    /// Look up the intended destination for a challenge id without consuming
    /// it — used to re-challenge to the same place after a wrong answer.
    pub fn dest_of(&self, id: &str) -> Option<String> {
        let map = self.inner.lock().unwrap();
        map.get(id)
            .filter(|p| p.expires > Instant::now())
            .map(|p| p.dest.clone())
    }

    /// Verify a submitted answer. On success the challenge is consumed and the
    /// intended destination is returned. On failure returns None.
    pub fn verify(&self, id: &str, answer: &str, client_ip: &str) -> Option<String> {
        let mut map = self.inner.lock().unwrap();
        let pending = map.get(id)?;

        let ok = pending.expires > Instant::now()
            && pending.client_ip == client_ip
            && pending.answer == answer.trim().to_uppercase();

        if ok {
            let dest = pending.dest.clone();
            map.remove(id);
            Some(dest)
        } else {
            None
        }
    }
}

impl Default for ChallengeStore {
    fn default() -> Self { Self::new() }
}

// ─── Where a solved challenge returns to ─────────────────

/// Whether a path is safe to redirect to after a challenge: somewhere on this
/// site, and nowhere else.
///
/// A single leading slash is required. `//host/...` is a link to another site
/// that happens to start with a slash, and browsers read `/\host` the same way;
/// accepting either would let a crafted link send whoever solved the challenge
/// to a site of the attacker's choosing. Control characters are refused too,
/// since browsers drop them before reading the URL.
pub fn stays_on_site(dest: &str) -> bool {
    dest.starts_with('/')
        && !dest.starts_with("//")
        && !dest.starts_with("/\\")
        && !dest.chars().any(|c| c.is_control())
}

// ─── Clearance cookie (stateless, HMAC-signed) ───────────

/// Build the clearance cookie value: "<expiry_unix>.<hex_sig>".
/// The signature binds the cookie to the client IP and expiry.
pub fn make_clearance(secret: &str, client_ip: &str) -> String {
    let exp = now_unix() + CLEARANCE_TTL_SECS;
    let sig = sign(secret, client_ip, exp);
    format!("{}.{}", exp, sig)
}

/// Validate a clearance cookie value for the given client IP.
/// Returns true only if it is well-formed, unexpired, and correctly signed.
pub fn check_clearance(secret: &str, client_ip: &str, cookie_value: &str) -> bool {
    let (exp_str, sig) = match cookie_value.split_once('.') {
        Some(parts) => parts,
        None        => return false,
    };
    let exp: u64 = match exp_str.parse() {
        Ok(v)  => v,
        Err(_) => return false,
    };
    if exp < now_unix() {
        return false; // expired
    }
    let expected = sign(secret, client_ip, exp);
    constant_time_eq(sig.as_bytes(), expected.as_bytes())
}

/// HMAC-SHA256 over "<client_ip>|<exp>", hex-encoded.
fn sign(secret: &str, client_ip: &str, exp: u64) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(client_ip.as_bytes());
    mac.update(b"|");
    mac.update(exp.to_string().as_bytes());
    hex(&mac.finalize().into_bytes())
}

// ─── Challenge HTML page ─────────────────────────────────

/// Render the standalone CAPTCHA challenge page shown to visitors.
/// `error` is set after a wrong answer to prompt a retry.
pub fn challenge_page(id: &str, data_uri: &str, error: bool) -> String {
    let err_html = if error {
        r#"<p style="color:#dc2626;margin:0 0 12px">Incorrect — please try again.</p>"#
    } else {
        ""
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security check</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f172a;
         color:#f1f5f9; display:flex; min-height:100vh; margin:0; align-items:center;
         justify-content:center; }}
  .card {{ background:#111827; border:1px solid rgba(255,255,255,0.08); border-radius:14px;
           padding:32px 36px; max-width:380px; width:100%; box-shadow:0 8px 32px rgba(0,0,0,0.4);
           text-align:center; }}
  h1 {{ font-size:18px; margin:0 0 6px; }}
  p.sub {{ color:#94a3b8; font-size:13px; margin:0 0 20px; }}
  img {{ border-radius:8px; background:#fff; padding:6px; margin-bottom:14px; }}
  input[type=text] {{ width:100%; box-sizing:border-box; padding:11px 14px; font-size:16px;
           letter-spacing:3px; text-align:center; text-transform:uppercase;
           background:#0b1120; border:1px solid rgba(255,255,255,0.12); border-radius:8px;
           color:#f1f5f9; margin-bottom:14px; }}
  button {{ width:100%; padding:11px; font-size:15px; font-weight:600; border:none;
           border-radius:8px; background:linear-gradient(135deg,#0ea5e9,#0284c7); color:#fff;
           cursor:pointer; }}
  button:hover {{ filter:brightness(1.08); }}
  .foot {{ color:#64748b; font-size:11px; margin-top:16px; }}
</style>
</head>
<body>
  <div class="card">
    <h1>Verify you are human</h1>
    <p class="sub">This site is protected by EasyWAF. Enter the characters below to continue.</p>
    {err}
    <form method="post" action="{verify}">
      <img src="{img}" alt="CAPTCHA" width="220" height="120">
      <input type="hidden" name="id" value="{id}">
      <input type="text" name="answer" autocomplete="off" autocapitalize="characters"
             autofocus placeholder="Enter code" required>
      <button type="submit">Continue</button>
    </form>
    <div class="foot">Protected by EasyWAF</div>
  </div>
</body>
</html>"#,
        err = err_html,
        verify = VERIFY_PATH,
        img = data_uri,
        id = id,
    )
}

// ─── small helpers ───────────────────────────────────────

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn random_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill(&mut bytes);
    hex(&bytes)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Constant-time byte comparison to avoid timing leaks on the signature.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_solved_challenge_only_returns_to_this_site() {
        assert!(stays_on_site("/"));
        assert!(stays_on_site("/shop/cart?item=3"));
        for elsewhere in ["//evil.example/", "/\\evil.example", "https://evil.example/", "evil.example",
                          "/\t/evil.example", ""] {
            assert!(!stays_on_site(elsewhere), "{elsewhere:?} was allowed");
        }
    }

    #[test]
    fn the_store_stops_issuing_at_its_cap() {
        let store = ChallengeStore::new();
        {
            let mut map = store.inner.lock().unwrap();
            for i in 0..MAX_PENDING {
                map.insert(i.to_string(), Pending {
                    answer: "X".into(), dest: "/".into(), client_ip: "203.0.113.9".into(),
                    expires: Instant::now() + CHALLENGE_TTL,
                });
            }
        }
        assert!(store.issue("/", "203.0.113.9").is_none(), "a full store drew another image");

        // Expired ones make room again.
        store.inner.lock().unwrap().values_mut().for_each(|p| p.expires = Instant::now());
        assert!(store.issue("/", "203.0.113.9").is_some());
    }
}
