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
use rustls::{ServerConfig, SupportedCipherSuite};
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
/// anything below TLS 1.2 to choose from — so this is a version floor rather
/// than an OpenSSL-style security level. Which of the strong suites are
/// offered is a separate setting; see `parse_suites`.
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

// ─── Cipher suites ───────────────────────────────────────

/// Every cipher suite this build can offer, in rustls's preference order.
///
/// Derived from the provider rather than hard-coded, so the list stays correct
/// if rustls adds or removes one. Note what is absent: there are **no CBC
/// suites at all**, and no TLS 1.2 suite without forward secrecy — every one
/// is ECDHE with AEAD. A policy that forbids CBC is therefore satisfied by
/// construction here, whatever is selected.
pub fn all_suites() -> Vec<SupportedCipherSuite> {
    rustls::crypto::ring::default_provider().cipher_suites
}

/// The IANA-style name of a suite, e.g. `TLS13_AES_128_GCM_SHA256`.
pub fn suite_name(suite: &SupportedCipherSuite) -> String {
    format!("{:?}", suite.suite())
}

/// Every suite name, space-separated — what an unset configuration means.
pub fn all_suite_names() -> String {
    all_suites()
        .iter()
        .map(suite_name)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Resolve a configured suite list into rustls suites.
///
/// Accepts names separated by spaces, commas or newlines, so a list can be
/// pasted from a policy document without reformatting. An empty configuration
/// means every supported suite.
///
/// Unknown names are an error rather than being skipped: a compliance policy
/// that names a suite this build cannot offer is a mismatch the operator has
/// to know about, and silently ignoring the name would leave them believing a
/// restriction is in force that is not.
pub fn parse_suites(configured: &str) -> std::result::Result<Vec<SupportedCipherSuite>, String> {
    let wanted: Vec<String> = configured
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(|t| t.trim().to_uppercase())
        .filter(|t| !t.is_empty())
        .collect();

    if wanted.is_empty() {
        return Ok(all_suites());
    }

    let available = all_suites();
    let mut chosen = Vec::new();
    let mut unknown = Vec::new();

    for name in &wanted {
        match available.iter().find(|s| suite_name(s).eq_ignore_ascii_case(name)) {
            // Preserve rustls's own preference order rather than the order the
            // operator happened to type: the server picks from its list, and
            // rustls orders by strength.
            Some(s) => {
                if !chosen.iter().any(|c| suite_name(c) == suite_name(s)) {
                    chosen.push(*s);
                }
            }
            None => unknown.push(name.clone()),
        }
    }

    if !unknown.is_empty() {
        return Err(format!(
            "not supported by this build: {}. Available: {}",
            unknown.join(", "),
            all_suite_names()
        ));
    }

    if chosen.is_empty() {
        return Err("no cipher suites selected — TLS could not be negotiated at all".to_string());
    }

    chosen.sort_by_key(|s| {
        available
            .iter()
            .position(|a| suite_name(a) == suite_name(s))
            .unwrap_or(usize::MAX)
    });
    Ok(chosen)
}

/// Whether a selection can actually negotiate under a version floor.
///
/// TLS 1.3 and 1.2 use disjoint suites, so "modern" with only 1.2 suites
/// selected would refuse every connection while looking configured.
pub fn suites_usable_with(profile: TlsProfile, suites: &[SupportedCipherSuite]) -> bool {
    let has_13 = suites.iter().any(|s| matches!(s, SupportedCipherSuite::Tls13(_)));
    match profile {
        TlsProfile::Modern => has_13,
        // Compatible negotiates 1.3 where it can and 1.2 otherwise, so either
        // family alone still serves someone.
        TlsProfile::Compatible => !suites.is_empty(),
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
pub fn server_config(profile: TlsProfile, suites: &[SupportedCipherSuite]) -> Arc<ServerConfig> {
    Arc::new(
        base_builder(profile, suites)
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SniResolver)),
    )
}

/// A TLS configuration presenting one fixed certificate — the management
/// interface, which serves a single name rather than resolving by SNI.
///
/// It honours the same profile and suite selection as the proxied sites: a
/// policy that restricts ciphers almost certainly means the administrative
/// interface too, and it would be strange for the appliance's own front door
/// to be the exception.
pub fn single_cert_config(
    profile: TlsProfile,
    suites: &[SupportedCipherSuite],
    cert_pem: &str,
    key_pem: &str,
) -> std::result::Result<Arc<ServerConfig>, String> {
    let (chain, key) = parse_pem(cert_pem, key_pem)?;
    base_builder(profile, suites)
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map(Arc::new)
        .map_err(|e| format!("TLS configuration: {e}"))
}

/// Shared construction of the builder, so both listener kinds get identical
/// version and cipher handling.
fn base_builder(
    profile: TlsProfile,
    suites: &[SupportedCipherSuite],
) -> rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier> {
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: suites.to_vec(),
        ..rustls::crypto::ring::default_provider()
    };

    let versions: &[&rustls::SupportedProtocolVersion] = match profile {
        TlsProfile::Modern => &[&rustls::version::TLS13],
        TlsProfile::Compatible => &[&rustls::version::TLS13, &rustls::version::TLS12],
    };

    ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        // Only fails when the provider offers nothing usable for the versions
        // asked for, which the settings form rejects before it can be stored.
        .expect("TLS provider supports the configured versions")
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
    let (chain, key) = parse_pem(cert_pem, key_pem)?;
    let signing_key = any_supported_type(&key).map_err(|e| format!("unsupported key type: {e}"))?;
    Ok(CertifiedKey::new(chain, signing_key))
}

/// Decode a stored certificate into the chain and key rustls wants.
///
/// Shared by both listener kinds: SNI needs a `CertifiedKey`, a single-name
/// listener needs the chain and key separately, and neither should differ in
/// what it accepts as a valid certificate.
fn parse_pem(
    cert_pem: &str,
    key_pem: &str,
) -> std::result::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| format!("certificate PEM: {e}"))?;

    if chain.is_empty() {
        return Err("no certificate found in PEM".to_string());
    }

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| format!("private key PEM: {e}"))?
        .ok_or_else(|| "no private key found in PEM".to_string())?;

    Ok((chain, key))
}

// ─── Tests ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #[test]
    fn the_restriction_reaches_the_listener_configuration() {
        // The setting is only worth anything if it survives into the config a
        // socket is actually bound with — assert on the built ServerConfig
        // rather than trusting that the builder honoured the provider.
        let chosen = parse_suites("TLS13_AES_256_GCM_SHA384").unwrap();
        let cfg = server_config(TlsProfile::Modern, &chosen);
        let offered: Vec<String> = cfg.crypto_provider().cipher_suites.iter().map(suite_name).collect();
        assert_eq!(offered, vec!["TLS13_AES_256_GCM_SHA384"]);
    }

    #[test]
    fn empty_configuration_means_every_suite() {
        assert_eq!(parse_suites("  ").unwrap().len(), all_suites().len());
    }

    #[test]
    fn unknown_suite_is_rejected_not_ignored() {
        // An operator pasting a policy that names a suite rustls does not have
        // must be told, not left believing the restriction took effect.
        let err = parse_suites("TLS_RSA_WITH_AES_128_CBC_SHA").unwrap_err();
        assert!(err.contains("not supported"), "{err}");
    }

    #[test]
    fn names_are_parsed_regardless_of_separator_or_case() {
        let a = parse_suites("TLS13_AES_128_GCM_SHA256, tls13_aes_256_gcm_sha384").unwrap();
        let b = parse_suites("TLS13_AES_256_GCM_SHA384 TLS13_AES_128_GCM_SHA256").unwrap();
        assert_eq!(a.len(), 2);
        // Both orderings normalise to rustls's own preference order.
        assert_eq!(
            a.iter().map(suite_name).collect::<Vec<_>>(),
            b.iter().map(suite_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn duplicates_collapse() {
        let s = parse_suites("TLS13_AES_128_GCM_SHA256 TLS13_AES_128_GCM_SHA256").unwrap();
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn modern_needs_a_tls13_suite() {
        // TLS 1.3 and 1.2 use disjoint suites, so a 1.2-only selection under
        // the TLS 1.3-only profile would refuse every connection.
        let only_12 = parse_suites("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256").unwrap();
        assert!(!suites_usable_with(TlsProfile::Modern, &only_12));
        assert!(suites_usable_with(TlsProfile::Compatible, &only_12));

        let with_13 = parse_suites("TLS13_AES_128_GCM_SHA256").unwrap();
        assert!(suites_usable_with(TlsProfile::Modern, &with_13));
    }

    #[test]
    fn no_cbc_or_legacy_suite_can_be_selected() {
        // The compliance claim made in the GUI, asserted rather than assumed:
        // there is nothing weak in the provider to select in the first place.
        for name in all_suites().iter().map(suite_name) {
            for banned in ["CBC", "RC4", "3DES", "NULL", "MD5"] {
                assert!(!name.contains(banned), "{name} contains {banned}");
            }
        }
    }

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
