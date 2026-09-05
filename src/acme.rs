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

use crate::error::{AppError, Result};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, NewAccount, NewOrder, RetryPolicy,
};
use sqlx::SqlitePool;
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

// ─── Account ─────────────────────────────────────────────

/// Let's Encrypt's staging directory — untrusted certificates, generous limits.
pub const STAGING_DIRECTORY: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
/// Let's Encrypt's production directory.
pub const PRODUCTION_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// The stored ACME account: contact address and which directory it belongs to.
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub email: String,
    pub directory: String,
}

/// Read the configured account, if one has been set up.
pub async fn config(db: &SqlitePool) -> Result<Option<AcmeConfig>> {
    let row = sqlx::query!(
        r#"SELECT email as "email!", directory as "directory!"
           FROM acme_accounts ORDER BY id LIMIT 1"#
    )
    .fetch_optional(db)
    .await?;

    Ok(row.map(|r| AcmeConfig {
        email: r.email,
        directory: r.directory,
    }))
}

/// Load the ACME account, registering one on first use.
///
/// The credentials are stored rather than the account being re-registered each
/// time: an account is an identity at the CA that rate limits are counted
/// against, and creating a fresh one per issuance would both lose that history
/// and eventually run into the account-creation limit.
///
/// Changing the contact email or directory replaces the stored credentials,
/// because an account belongs to one directory — staging and production are
/// separate registries and an account from one is meaningless to the other.
async fn account(db: &SqlitePool, cfg: &AcmeConfig) -> Result<Account> {
    let stored = sqlx::query!(
        r#"SELECT private_key as "private_key!", directory as "directory!"
           FROM acme_accounts ORDER BY id LIMIT 1"#
    )
    .fetch_optional(db)
    .await?;

    if let Some(row) = stored
        && row.directory == cfg.directory
        && !row.private_key.trim().is_empty()
        && let Ok(creds) = serde_json::from_str::<AccountCredentials>(&row.private_key)
        && let Ok(acct) = Account::builder()
            .map_err(acme_err)?
            .from_credentials(creds)
            .await
    {
        return Ok(acct);
    }

    let contact = format!("mailto:{}", cfg.email);
    let (acct, creds) = Account::builder()
        .map_err(acme_err)?
        .create(
            &NewAccount {
                contact: &[&contact],
                // Registering an account *is* the agreement; there is no
                // separate step, so a checkbox in the GUI is what this
                // reflects rather than something decided here.
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            cfg.directory.clone(),
            None,
        )
        .await
        .map_err(acme_err)?;

    let serialised = serde_json::to_string(&creds)
        .map_err(|e| AppError::Internal(format!("ACME credentials: {e}")))?;

    sqlx::query!(
        "INSERT INTO acme_accounts (email, private_key, directory) VALUES (?, ?, ?)",
        cfg.email,
        serialised,
        cfg.directory
    )
    .execute(db)
    .await?;

    tracing::info!("Registered an ACME account with {}", cfg.directory);
    Ok(acct)
}

// ─── Issuance ────────────────────────────────────────────

/// Obtain a certificate for one domain, returning (cert chain PEM, key PEM).
///
/// The whole HTTP-01 exchange: order, publish the token where the proxy will
/// answer it, tell the CA to validate, wait, then finalise. The published
/// tokens are held in guards so every failure path withdraws them — and there
/// are many, since most of this is waiting on someone else's server.
pub async fn issue(db: &SqlitePool, domain: &str) -> Result<(String, String)> {
    let cfg = config(db)
        .await?
        .ok_or_else(|| AppError::Internal("ACME is not configured".into()))?;

    let account = account(db, &cfg).await?;
    let identifiers = [Identifier::Dns(domain.to_string())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(acme_err)?;

    // Held for the life of the order: dropping one withdraws its token.
    let mut published = Vec::new();

    {
        let mut auths = order.authorizations();
        while let Some(result) = auths.next().await {
            let mut authz = result.map_err(acme_err)?;

            // An authorization the CA already considers valid needs no challenge.
            // Re-answering one is harmless but pointless, and it is common on a
            // re-issue within the reuse window.
            if authz.status == instant_acme::AuthorizationStatus::Valid {
                continue;
            }

            let mut challenge = authz.challenge(ChallengeType::Http01).ok_or_else(|| {
                AppError::Internal(format!(
                    "{domain}: the CA offered no HTTP-01 challenge. Wildcards need DNS-01, \
                 which EasyWAF does not implement — upload that certificate instead."
                ))
            })?;

            let token = challenge.token.clone();
            let key_auth = challenge.key_authorization().as_str().to_string();

            // Published before telling the CA it is ready, never after: validation
            // can begin the instant set_ready returns.
            published.push(PublishedToken::new(&token, &key_auth));
            challenge.set_ready().await.map_err(acme_err)?;
        }
    } // ends the borrow of `order` taken by authorizations()

    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .map_err(acme_err)?;
    if status != instant_acme::OrderStatus::Ready {
        return Err(AppError::Internal(format!(
            "{domain}: validation did not succeed (order is {status:?}). Check that the \
             name resolves to this host and that port 80 is reachable from the internet."
        )));
    }

    // finalize generates the keypair and hands back its PEM; the CA never sees
    // the private key, only the CSR built from it.
    let key_pem = order.finalize().await.map_err(acme_err)?;
    let cert_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(acme_err)?;

    drop(published);
    tracing::info!(domain, "Issued a certificate over ACME");
    Ok((cert_pem, key_pem))
}

/// ACME failures are reported to an operator, so they keep the CA's own wording
/// — it is usually specific about what it could not verify.
fn acme_err(e: instant_acme::Error) -> AppError {
    AppError::Internal(format!("ACME: {e}"))
}

/// Store the ACME contact and directory.
///
/// Changing either clears the stored account credentials: an ACME account
/// belongs to one directory, so credentials from staging mean nothing to
/// production, and a changed contact should be registered rather than
/// silently kept. The next issuance registers afresh.
pub async fn set_config(db: &SqlitePool, email: &str, directory: &str) -> Result<()> {
    let directory = if directory.trim().is_empty() {
        STAGING_DIRECTORY
    } else {
        directory.trim()
    };

    let existing = sqlx::query!(
        r#"SELECT id as "id!", email as "email!", directory as "directory!"
           FROM acme_accounts ORDER BY id LIMIT 1"#
    )
    .fetch_optional(db)
    .await?;

    match existing {
        Some(r) if r.email == email && r.directory == directory => Ok(()),
        Some(r) => {
            sqlx::query!(
                "UPDATE acme_accounts SET email = ?, directory = ?, private_key = '' WHERE id = ?",
                email,
                directory,
                r.id
            )
            .execute(db)
            .await?;
            tracing::info!("ACME contact or directory changed — the account will be re-registered");
            Ok(())
        }
        None => {
            sqlx::query!(
                "INSERT INTO acme_accounts (email, private_key, directory) VALUES (?, '', ?)",
                email,
                directory
            )
            .execute(db)
            .await?;
            Ok(())
        }
    }
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
