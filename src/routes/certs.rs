// =========================================================
// routes/certs.rs — EasyWAF
// Certificate management.
// Cert and key PEM are stored directly in the database —
// no filesystem involvement.
// =========================================================

use crate::{auth::get_session, error::Result, AppState};
use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::{Deserialize, Serialize};
use tera::Context;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

// ─── Models ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct Cert {
    /// Sites currently serving this certificate. Shown in the list, and the
    /// reason deletion is refused.
    pub used_by: Vec<String>,
    /// True for the management interface's own certificate, which cannot be
    /// deleted.
    pub is_management: bool,
    pub id:         i64,
    pub name:       String,
    pub domain:     Option<String>,
    pub not_before: Option<String>,
    pub not_after:  Option<String>,
}

// ─── Forms ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CertForm {
    pub name:     String,
    pub cert_pem: String,
    pub key_pem:  String,
}

#[derive(Deserialize)]
pub struct FlashQuery {
    pub result: Option<String>,
    pub msg:    Option<String>,
}

// ─── get_certs ───────────────────────────────────────────

pub async fn get_certs(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(flash): Query<FlashQuery>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    let certs = fetch_certs(&state).await?;

    let mut ctx = Context::new();
    ctx.insert("username", &session.username);
    ctx.insert("title",    "Certificate Management");
    ctx.insert("url",      "/certs");
    ctx.insert("certs",    &certs);
    ctx.insert("result",   &flash.result.unwrap_or_default());
    ctx.insert("msg",      &flash.msg.unwrap_or_default());

    Ok((jar, Html(state.tera.render("certs.html", &ctx)?)).into_response())
}

// ─── get_cert_new ────────────────────────────────────────

pub async fn get_cert_new(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    let mut ctx = Context::new();
    ctx.insert("username", &session.username);
    ctx.insert("title",    "Upload Certificate");
    ctx.insert("url",      "/certs");

    Ok((jar, Html(state.tera.render("cert_create.html", &ctx)?)).into_response())
}

// ─── post_cert_create ────────────────────────────────────

pub async fn post_cert_create(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<CertForm>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let name = form.name.trim().to_string();
    if name.is_empty() {
        return flash_redirect("/certs", "failed", "Certificate name is required");
    }

    // Parse the certificate to extract metadata.
    let (domain, not_before, not_after) = parse_cert_pem(&form.cert_pem);

    sqlx::query!(
        "INSERT OR REPLACE INTO certs (name, domain, not_before, not_after, cert_pem, key_pem)
         VALUES (?, ?, ?, ?, ?, ?)",
        name, domain, not_before, not_after, form.cert_pem, form.key_pem,
    )
    .execute(&state.db)
    .await?;

    flash_redirect("/certs", "success", &format!("Certificate {} saved successfully", name))
}

// ─── post_cert_delete ────────────────────────────────────

pub async fn post_cert_delete(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    // The management interface is served with this one. Deleting it leaves the
    // GUI running on a certificate that no longer exists anywhere, and the next
    // start generates a replacement with a different fingerprint — so every
    // browser that had accepted the old one is met by a fresh warning, which is
    // indistinguishable from being locked out by anyone who does not know a
    // certificate was replaced underneath them.
    //
    // Refused rather than warned about: there is no reason to delete it, since
    // a start with it missing simply makes another.
    if name == crate::routes::settings::get_management_cert(&state.db).await {
        // Worded for which case it is. Telling someone who has already
        // uploaded their own certificate to "upload your own" reads as though
        // the page has not noticed what they did.
        let how = if name == crate::cert::DEFAULT_CERT_NAME {
            "To replace it, upload your own under Certificates and select it as the \
             Management Certificate under Settings — this one then becomes deletable."
        } else {
            "Select a different Management Certificate under Settings first; this one \
             becomes deletable once it is no longer in use."
        };
        return flash_redirect(
            "/certs",
            "failed",
            &format!("'{name}' is what the management interface is served with. {how}"),
        );
    }

    // `sites.cert_id` is ON DELETE SET NULL and sqlx enables foreign keys, so
    // deleting a certificate in use silently unsets it — and a site with an
    // HTTPS port but no certificate stops binding that port. The site keeps
    // working over plain HTTP, so nothing looks wrong until someone tries the
    // HTTPS one.
    let in_use: Vec<String> = sqlx::query_scalar!(
        r#"SELECT s.name as "name!" FROM sites s
           JOIN certs c ON c.id = s.cert_id
           WHERE c.name = ? ORDER BY s.name"#,
        name
    )
    .fetch_all(&state.db)
    .await?;

    if !in_use.is_empty() {
        return flash_redirect(
            "/certs",
            "failed",
            &format!(
                "'{}' is in use by {}: {}. Assign a different certificate there first — \
                 deleting it would stop {} serving HTTPS.",
                name,
                if in_use.len() == 1 { "one site" } else { "these sites" },
                in_use.join(", "),
                if in_use.len() == 1 { "it" } else { "them" },
            ),
        );
    }

    let deleted = sqlx::query!("DELETE FROM certs WHERE name = ?", name)
        .execute(&state.db)
        .await?
        .rows_affected();

    if deleted == 0 {
        return flash_redirect("/certs", "failed", &format!("No certificate named '{name}'"));
    }

    // The in-memory SNI map still holds it until rebuilt, which would keep a
    // deleted certificate being served for as long as the process lives.
    crate::tls::reload(&state.db).await?;

    flash_redirect("/certs", "success", &format!("Certificate {name} deleted"))
}

// ─── Helpers ─────────────────────────────────────────────

async fn fetch_certs(state: &AppState) -> Result<Vec<Cert>> {
    let rows = sqlx::query!(
        "SELECT id as \"id!\", name, domain, not_before, not_after
         FROM certs ORDER BY name"
    )
    .fetch_all(&state.db)
    .await?;

    let mgmt = crate::routes::settings::get_management_cert(&state.db).await;

    // One query for every certificate rather than one per row: the list is
    // small, but a per-row query in a loop is the shape that stops being small
    // without anyone noticing.
    let usage = sqlx::query!(
        r#"SELECT c.name as "cert_name!", s.name as "site_name!"
           FROM sites s JOIN certs c ON c.id = s.cert_id
           ORDER BY s.name"#
    )
    .fetch_all(&state.db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| Cert {
            used_by: usage
                .iter()
                .filter(|u| u.cert_name == r.name)
                .map(|u| u.site_name.clone())
                .collect(),
            is_management: r.name == mgmt,
            id:         r.id,
            name:       r.name,
            domain:     r.domain,
            not_before: r.not_before,
            not_after:  r.not_after,
        })
        .collect())
}

/// What the upload form stores: domain and validity, read from the certificate
/// itself so the list does not depend on what the operator typed.
fn parse_cert_pem(pem: &str) -> (Option<String>, Option<String>, Option<String>) {
    match inspect("", pem, false) {
        Ok(d) => (d.subject.common_name, Some(d.not_before), Some(d.not_after)),
        Err(_) => (None, None, None),
    }
}

// ─── get_cert_detail ─────────────────────────────────────

/// GET /certs/{name} — everything the stored certificate says about itself.
///
/// Read from the PEM on every load rather than from the `certs` columns. Those
/// are a snapshot taken at upload and hold only three fields; the certificate
/// is the authority on its own contents, and reading it cannot drift.
pub async fn get_cert_detail(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    let row = sqlx::query!(
        "SELECT name as \"name!\", cert_pem, key_pem FROM certs WHERE name = ?",
        name
    )
    .fetch_optional(&state.db)
    .await?;

    let row = match row {
        Some(r) => r,
        None => return flash_redirect("/certs", "failed", "No such certificate"),
    };

    let mut ctx = Context::new();
    ctx.insert("username", &session.username);
    ctx.insert("title",    &format!("Certificate: {}", row.name));
    ctx.insert("url",      "/certs");
    ctx.insert("name",     &row.name);

    match row.cert_pem.as_deref() {
        Some(pem) if !pem.trim().is_empty() => {
            match inspect(&row.name, pem, row.key_pem.is_some_and(|k| !k.trim().is_empty())) {
                Ok(detail) => ctx.insert("cert", &detail),
                // Shown rather than redirected away from: a certificate that
                // cannot be parsed is exactly the one an operator has come to
                // this page to understand.
                Err(e) => ctx.insert("parse_error", &e),
            }
        }
        _ => ctx.insert("parse_error", &"No certificate is stored under this name".to_string()),
    }

    Ok((jar, Html(state.tera.render("cert_detail.html", &ctx)?)).into_response())
}

// ─── Certificate inspection ──────────────────────────────

/// The distinguished-name fields worth showing an operator.
///
/// Every one is optional because every one genuinely is: a certificate need
/// carry nothing but a subject alternative name, and many modern ones carry
/// little else.
#[derive(Debug, Serialize)]
pub struct NameFields {
    pub common_name:         Option<String>,
    pub organization:        Option<String>,
    pub organizational_unit: Option<String>,
    pub locality:            Option<String>,
    pub state:               Option<String>,
    pub country:             Option<String>,
    pub email:               Option<String>,

    /// True when nothing at all was present, so the page can say so instead of
    /// rendering a table of empty rows.
    ///
    /// A stored field rather than a method: Tera reads the serialised struct
    /// and cannot call one, so a method here would silently evaluate as absent
    /// in the template and the branch would never be taken.
    pub is_empty: bool,
}

/// Everything the detail page shows about a stored certificate.
///
/// Note what is absent: nothing here is derived from the private key, and the
/// key is never read. The page reports only whether one is stored.
#[derive(Debug, Serialize)]
pub struct CertDetail {
    pub name:        String,
    pub subject:     NameFields,
    pub issuer:      NameFields,
    pub not_before:  String,
    pub not_after:   String,
    pub days_left:   i64,
    pub expired:     bool,
    pub not_yet_valid: bool,
    pub self_signed: bool,
    pub serial:      String,
    pub sig_alg:     String,
    pub key_type:    String,
    pub sans:        Vec<String>,
    pub fingerprint: String,
    pub chain_len:   usize,
    pub has_key:     bool,
}

/// Read the leaf certificate of a stored PEM chain.
///
/// Parsed in-process rather than by running `openssl`, which is what this
/// replaced. Shelling out made an undeclared external binary a requirement for
/// a certificate to display its own details, and failed silently to empty
/// fields when it was missing — the container image installs
/// `ca-certificates` with `--no-install-recommends`, so it is not safe to
/// assume the binary is there.
pub fn inspect(name: &str, cert_pem: &str, has_key: bool) -> std::result::Result<CertDetail, String> {
    let chain_len = cert_pem.matches("-----BEGIN CERTIFICATE-----").count();

    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| format!("not a PEM certificate: {e}"))?;
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| format!("certificate could not be parsed: {e}"))?;

    let validity  = cert.validity();
    let days_left = (validity.not_after.timestamp() - ::time::OffsetDateTime::now_utc().unix_timestamp())
        / 86_400;

    let mut sans = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for gn in &ext.value.general_names {
            match gn {
                GeneralName::DNSName(n)   => sans.push((*n).to_string()),
                GeneralName::IPAddress(b) => sans.push(render_ip(b)),
                GeneralName::RFC822Name(n) => sans.push(format!("email:{n}")),
                GeneralName::URI(u)       => sans.push(format!("URI:{u}")),
                _ => {}
            }
        }
    }

    Ok(CertDetail {
        name:          name.to_string(),
        subject:       name_fields(cert.subject()),
        issuer:        name_fields(cert.issuer()),
        not_before:    validity.not_before.to_string(),
        not_after:     validity.not_after.to_string(),
        days_left,
        expired:       !validity.is_valid() && days_left < 0,
        not_yet_valid: !validity.is_valid() && days_left >= 0,
        // Compared as issued-by-itself. A real check would verify the
        // signature against its own key; the name comparison is what an
        // operator is actually asking ("did this come from a CA?") and cannot
        // mislead in the direction that matters — a CA-issued certificate is
        // never reported as self-signed.
        self_signed:   cert.subject() == cert.issuer(),
        serial:        cert.raw_serial_as_string(),
        sig_alg:       algorithm_name(&cert.signature_algorithm.algorithm),
        key_type:      key_description(&cert),
        sans,
        fingerprint:   fingerprint(&pem.contents),
        chain_len,
        has_key,
    })
}

/// Pull the named attributes out of a distinguished name.
fn name_fields(n: &X509Name) -> NameFields {
    let first = |mut it: std::vec::IntoIter<&str>| it.next().map(|s| s.to_string());
    let collect = |vals: Vec<&str>| first(vals.into_iter());

    let mut f = NameFields {
        common_name:         collect(n.iter_common_name().filter_map(|a| a.as_str().ok()).collect()),
        organization:        collect(n.iter_organization().filter_map(|a| a.as_str().ok()).collect()),
        organizational_unit: collect(n.iter_organizational_unit().filter_map(|a| a.as_str().ok()).collect()),
        locality:            collect(n.iter_locality().filter_map(|a| a.as_str().ok()).collect()),
        state:               collect(n.iter_state_or_province().filter_map(|a| a.as_str().ok()).collect()),
        country:             collect(n.iter_country().filter_map(|a| a.as_str().ok()).collect()),
        email:               collect(n.iter_email().filter_map(|a| a.as_str().ok()).collect()),
        is_empty:            false,
    };

    f.is_empty = f.common_name.is_none()
        && f.organization.is_none()
        && f.organizational_unit.is_none()
        && f.locality.is_none()
        && f.state.is_none()
        && f.country.is_none()
        && f.email.is_none();
    f
}

/// Resolve an algorithm OID to its short name, e.g. `sha256WithRSAEncryption`.
///
/// Falls back to the dotted OID when the registry does not know it, which is
/// still more useful than nothing — it can be looked up.
fn algorithm_name(oid: &x509_parser::der_parser::Oid) -> String {
    x509_parser::oid_registry::format_oid(oid, oid_registry())
}

/// Algorithm and size, e.g. "RSA 2048-bit" — the part of a key that is public
/// information and worth seeing.
fn key_description(cert: &X509Certificate) -> String {
    match cert.public_key().parsed() {
        Ok(PublicKey::RSA(k))     => format!("RSA {}-bit", k.key_size()),
        Ok(PublicKey::EC(k))      => format!("EC {}-bit", k.key_size()),
        Ok(PublicKey::DSA(_))     => "DSA".to_string(),
        Ok(PublicKey::GostR3410(_)) | Ok(PublicKey::GostR3410_2012(_)) => "GOST".to_string(),
        Ok(PublicKey::Unknown(_)) | Err(_) => "unknown".to_string(),
    }
}

/// SHA-256 over the DER, colon-separated — the form every other tool prints,
/// so it can be compared by eye against a browser or `openssl`.
fn fingerprint(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Render a SAN IP address, which arrives as raw bytes.
fn render_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4  => format!("IP:{}", std::net::Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap())),
        16 => format!("IP:{}", std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap())),
        _  => "IP:<malformed>".to_string(),
    }
}

fn flash_redirect(path: &str, result: &str, msg: &str) -> Result<Response> {
    let msg_enc = urlencoding::encode(msg).into_owned();
    Ok(Redirect::to(&format!("{}?result={}&msg={}", path, result, msg_enc)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a certificate carrying every field the detail page shows, so the
    /// test asserts the mapping rather than a hand-pasted fixture that nobody
    /// can regenerate.
    fn sample() -> (String, String) {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "shop.example.com");
        dn.push(DnType::OrganizationName, "Example Ltd");
        dn.push(DnType::OrganizationalUnitName, "Web Operations");
        dn.push(DnType::LocalityName, "Tel Aviv");
        dn.push(DnType::StateOrProvinceName, "Tel Aviv District");
        dn.push(DnType::CountryName, "IL");
        params.distinguished_name = dn;
        params.subject_alt_names = vec![
            SanType::DnsName("shop.example.com".try_into().unwrap()),
            SanType::IpAddress(std::net::IpAddr::from([192, 0, 2, 10])),
        ];

        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn reads_every_distinguished_name_field() {
        let (pem, _) = sample();
        let d = inspect("shop", &pem, true).unwrap();

        assert_eq!(d.subject.common_name.as_deref(), Some("shop.example.com"));
        assert_eq!(d.subject.organization.as_deref(), Some("Example Ltd"));
        assert_eq!(d.subject.organizational_unit.as_deref(), Some("Web Operations"));
        assert_eq!(d.subject.locality.as_deref(), Some("Tel Aviv"));
        assert_eq!(d.subject.state.as_deref(), Some("Tel Aviv District"));
        assert_eq!(d.subject.country.as_deref(), Some("IL"));
        assert!(!d.subject.is_empty);
    }

    #[test]
    fn reads_names_dates_and_shape() {
        let (pem, _) = sample();
        let d = inspect("shop", &pem, true).unwrap();

        assert!(d.sans.contains(&"shop.example.com".to_string()));
        assert!(d.sans.contains(&"IP:192.0.2.10".to_string()));
        assert!(d.self_signed, "issued by itself");
        assert!(!d.expired && !d.not_yet_valid);
        assert!(d.days_left > 0);
        assert_eq!(d.chain_len, 1);
        assert!(d.has_key);
        // 32 bytes, colon-separated and upper-case, so it can be compared by
        // eye against a browser or openssl.
        assert_eq!(d.fingerprint.split(':').count(), 32);
        assert_eq!(d.fingerprint, d.fingerprint.to_uppercase());
    }

    #[test]
    fn a_certificate_with_no_subject_reports_it_as_a_serialised_field() {
        // Tera reads the serialised struct and cannot call a method, so
        // is_empty has to survive serialisation as a field with the right
        // value, or the template's "no subject name" branch never fires and
        // the page renders an empty table instead.
        use rcgen::{CertificateParams, DistinguishedName, KeyPair, SanType};

        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new(); // deliberately empty
        params.subject_alt_names =
            vec![SanType::DnsName("only.example.com".try_into().unwrap())];
        let key = KeyPair::generate().unwrap();
        let pem = params.self_signed(&key).unwrap().pem();

        let d = inspect("bare", &pem, false).unwrap();
        assert!(d.subject.is_empty, "no DN attributes were set");

        let v = serde_json::to_value(&d.subject).unwrap();
        assert_eq!(
            v.get("is_empty").and_then(|b| b.as_bool()),
            Some(true),
            "must serialise as a field Tera can read"
        );
    }

    #[test]
    fn garbage_is_an_error_rather_than_a_panic() {
        assert!(inspect("x", "not a certificate", false).is_err());
        assert!(inspect("x", "", false).is_err());
    }
}
