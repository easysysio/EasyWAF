// =========================================================
// cert.rs — EasyWAF
// The management interface's TLS certificate.
//
// On first run EasyWAF generates a self-signed certificate
// named "easywaf" and stores it in the certs table, so the
// GUI is served over TLS from the very first start with
// nothing for an administrator to prepare. Later starts
// reuse the stored certificate — regenerating it on every
// boot would change the fingerprint each time, and an
// operator who has accepted a self-signed certificate should
// not be asked to accept a new one after a restart.
//
// It is a default, not a recommendation: browsers will warn,
// because nothing vouches for a self-signed certificate.
// Replacing it with a real one is the point of certificate
// management, and this exists so that the alternative is
// never plain HTTP.
// =========================================================

use crate::error::Result;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use sqlx::SqlitePool;
use time::{Duration, OffsetDateTime};

/// The name the default certificate is stored under.
pub const DEFAULT_CERT_NAME: &str = "easywaf";

/// How long the generated certificate is valid.
///
/// Ten years, deliberately. Nothing renews this certificate — ACME is for the
/// proxied sites, not for the management interface — so a shorter life would
/// mean the GUI stops serving one day for a reason nobody is watching for. It
/// is a placeholder to be replaced by a real certificate, and an expiry date
/// does not make a self-signed certificate any more trustworthy.
const VALID_YEARS: i64 = 10;

// ─── ensure_default ──────────────────────────────────────

/// Return the management certificate as (cert PEM, key PEM), generating and
/// storing it on first run.
///
/// The certificate covers the names the management interface is actually
/// reached by: `easywaf`, `localhost`, and the loopback addresses. A browser
/// will still warn — it is self-signed — but it will at least warn about
/// trust rather than about a name mismatch on top.
pub async fn ensure_default(db: &SqlitePool) -> Result<(String, String)> {
    if let Some(existing) = load(db).await? {
        return Ok(existing);
    }

    let (cert_pem, key_pem, not_before, not_after) = generate()?;

    sqlx::query!(
        "INSERT INTO certs (name, domain, not_before, not_after, cert_pem, key_pem)
         VALUES (?, ?, ?, ?, ?, ?)",
        DEFAULT_CERT_NAME,
        DEFAULT_CERT_NAME,
        not_before,
        not_after,
        cert_pem,
        key_pem,
    )
    .execute(db)
    .await?;

    tracing::info!(
        "Generated the default self-signed certificate '{}' for the management \
         interface — replace it with your own under Certificates",
        DEFAULT_CERT_NAME
    );

    Ok((cert_pem, key_pem))
}

// ─── load ────────────────────────────────────────────────

/// Fetch the stored default certificate, if it exists and is complete.
///
/// A row whose PEM columns are NULL is treated as absent rather than as an
/// error: those columns are nullable, and a half-written row should lead to a
/// fresh certificate rather than to a service that will not start.
async fn load(db: &SqlitePool) -> Result<Option<(String, String)>> {
    let row = sqlx::query!(
        "SELECT cert_pem, key_pem FROM certs WHERE name = ?",
        DEFAULT_CERT_NAME
    )
    .fetch_optional(db)
    .await?;

    Ok(match row {
        Some(r) => match (r.cert_pem, r.key_pem) {
            (Some(cert), Some(key)) if !cert.is_empty() && !key.is_empty() => Some((cert, key)),
            _ => None,
        },
        None => None,
    })
}

// ─── generate ────────────────────────────────────────────

/// Build a self-signed certificate, returning
/// (cert PEM, key PEM, not_before, not_after).
fn generate() -> Result<(String, String, String, String)> {
    let not_before = OffsetDateTime::now_utc();
    let not_after = not_before + Duration::days(365 * VALID_YEARS);

    let mut params = CertificateParams::default();

    // The names the management interface answers to. An IP literal has to be a
    // SanType::IpAddress rather than a DnsName, or a browser reaching the GUI
    // by address will reject the certificate for the wrong reason.
    params.subject_alt_names = vec![
        SanType::DnsName(DEFAULT_CERT_NAME.try_into().expect("valid DNS name")),
        SanType::DnsName("localhost".try_into().expect("valid DNS name")),
        SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])),
        SanType::IpAddress(std::net::IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])),
    ];

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, DEFAULT_CERT_NAME);
    dn.push(DnType::OrganizationName, "EasyWAF");
    params.distinguished_name = dn;

    params.not_before = not_before;
    params.not_after = not_after;

    let key_pair = KeyPair::generate()
        .map_err(|e| crate::error::AppError::Internal(format!("key generation failed: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| crate::error::AppError::Internal(format!("certificate generation failed: {e}")))?;

    Ok((
        cert.pem(),
        key_pair.serialize_pem(),
        not_before.date().to_string(),
        not_after.date().to_string(),
    ))
}
