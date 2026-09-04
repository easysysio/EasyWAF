// =========================================================
// tls.rs — EasyWAF
// TLS for proxied sites: SNI certificate selection and the
// appliance-wide TLS profile.
//
// Many sites can share one HTTPS port, each presenting its
// own certificate. rustls decides which to present from the
// server name in the ClientHello, so the mapping from name
// to certificate has to be resolvable synchronously and
// without touching the database — `ResolvesServerCert` is a
// blocking trait method on the handshake path. It is
// therefore an in-memory map, rebuilt by `reload` whenever a
// site or certificate changes.
//
// The TLS version and cipher suites are NOT per site. rustls
// fixes them on the listener when the port is bound, before
// any server name is known, so they are one appliance-wide
// setting rather than a per-site choice.
// =========================================================

use crate::error::Result;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

/// Server name (lower-cased) to the certificate that site presents.
type CertMap = RwLock<HashMap<String, Arc<CertifiedKey>>>;

static CERTS: OnceLock<CertMap> = OnceLock::new();

fn certs() -> &'static CertMap {
    CERTS.get_or_init(|| RwLock::new(HashMap::new()))
}

// ─── TlsProfile ──────────────────────────────────────────

/// Which TLS versions a listener accepts.
///
/// rustls implements no weak ciphers — there is no RC4, 3DES, CBC-SHA1, or
/// anything below TLS 1.2 to choose from — so the meaningful choice is the
/// version floor, not an OpenSSL-style cipher string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsProfile {
    /// TLS 1.2 and 1.3. The default: 1.3 where the client supports it, 1.2 for
    /// everything else.
    Compatible,
    /// TLS 1.3 only. Refuses 1.2 clients outright.
    Modern,
}

impl TlsProfile {
    /// Parse the stored setting, falling back to the safer-to-serve option.
    ///
    /// An unrecognised value becomes `Compatible` rather than `Modern`: a
    /// typo in a setting should not start refusing connections from clients
    /// that were working a moment ago.
    pub fn from_setting(value: &str) -> Self {
        match value.trim().to_lowercase().as_str() {
            "modern" => TlsProfile::Modern,
            _ => TlsProfile::Compatible,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TlsProfile::Modern => "modern",
            TlsProfile::Compatible => "compatible",
        }
    }
}

// ─── SniResolver ─────────────────────────────────────────

/// Chooses the certificate to present from the ClientHello's server name.
#[derive(Debug)]
pub struct SniResolver;

impl ResolvesServerCert for SniResolver {
    /// Returns None when the client sent no server name, or named a site with
    /// no certificate. rustls then fails the handshake, which is the correct
    /// outcome: presenting some other site's certificate would be worse than
    /// refusing.
    fn resolve(&self, hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name()?.to_lowercase();
        certs().read().ok()?.get(&name).cloned()
    }
}

// ─── server_config ───────────────────────────────────────

/// Build the TLS configuration a listener is bound with.
pub fn server_config(profile: TlsProfile) -> Arc<ServerConfig> {
    let builder = match profile {
        TlsProfile::Modern => {
            ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        }
        TlsProfile::Compatible => ServerConfig::builder(),
    };

    Arc::new(
        builder
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SniResolver)),
    )
}

// ─── reload ──────────────────────────────────────────────

/// Rebuild the server-name to certificate map from the database.
///
/// Called at startup and after any change to a site or a certificate. A site
/// whose certificate is missing or unparseable is left out with a warning
/// rather than aborting the rebuild — one bad certificate must not take TLS
/// down for every other site sharing the port.
pub async fn reload(db: &SqlitePool) -> Result<usize> {
    let rows = sqlx::query!(
        r#"SELECT s.server_name as "server_name!",
                  c.name        as "cert_name!",
                  c.cert_pem,
                  c.key_pem
           FROM   sites s
           JOIN   certs c ON c.id = s.cert_id
           WHERE  s.enabled = 1 AND s.tls_port IS NOT NULL"#
    )
    .fetch_all(db)
    .await?;

    let mut map: HashMap<String, Arc<CertifiedKey>> = HashMap::new();

    for r in rows {
        let (Some(cert_pem), Some(key_pem)) = (r.cert_pem, r.key_pem) else {
            tracing::warn!(
                site = %r.server_name,
                cert = %r.cert_name,
                "TLS: certificate has no PEM content — site will not serve HTTPS"
            );
            continue;
        };

        match certified_key(&cert_pem, &key_pem) {
            Ok(key) => {
                map.insert(r.server_name.to_lowercase(), Arc::new(key));
            }
            Err(e) => tracing::warn!(
                site = %r.server_name,
                cert = %r.cert_name,
                "TLS: certificate could not be loaded ({}) — site will not serve HTTPS",
                e
            ),
        }
    }

    let count = map.len();
    if let Ok(mut slot) = certs().write() {
        *slot = map;
    }
    tracing::info!(sites = count, "TLS: certificate map reloaded");
    Ok(count)
}

// ─── certified_key ───────────────────────────────────────

/// Parse a PEM certificate chain and private key into a rustls key.
fn certified_key(cert_pem: &str, key_pem: &str) -> std::result::Result<CertifiedKey, String> {
    let chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| format!("certificate PEM: {e}"))?;

    if chain.is_empty() {
        return Err("no certificate found in PEM".to_string());
    }

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| format!("private key PEM: {e}"))?
        .ok_or_else(|| "no private key found in PEM".to_string())?;

    let signing_key = any_supported_type(&key).map_err(|e| format!("unsupported key type: {e}"))?;

    Ok(CertifiedKey::new(chain, signing_key))
}

// ─── Tests ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// An unrecognised or empty profile must fall back to accepting more
    /// clients, not fewer — a bad setting should not refuse connections that
    /// were working.
    #[test]
    fn profile_falls_back_to_compatible() {
        assert_eq!(TlsProfile::from_setting("modern"), TlsProfile::Modern);
        assert_eq!(TlsProfile::from_setting("MODERN"), TlsProfile::Modern);
        assert_eq!(TlsProfile::from_setting("compatible"), TlsProfile::Compatible);
        assert_eq!(TlsProfile::from_setting(""), TlsProfile::Compatible);
        assert_eq!(TlsProfile::from_setting("banana"), TlsProfile::Compatible);
    }

    /// Garbage PEM must be reported, not panic — it arrives from a form.
    #[test]
    fn malformed_pem_is_an_error() {
        assert!(certified_key("not a certificate", "not a key").is_err());
        assert!(certified_key("", "").is_err());
    }
}
