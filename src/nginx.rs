// =========================================================
// nginx.rs — EasyWAF
// Generates nginx virtual-host config files and triggers
// nginx reload via the configured shell command.
// =========================================================

use crate::config::NginxConfig;
use std::fs;
use std::process::Command;
use tracing::{error, info};

// ─── SiteParams ──────────────────────────────────────────

/// Parameters needed to render an nginx server block.
pub struct SiteParams<'a> {
    pub name: &'a str,
    pub server_name: &'a str,
    pub target: &'a str,
    pub port: i64,
    pub waf_policy: Option<&'a str>,
    pub hsts: bool,
    pub x_frame: bool,
    pub x_content_type: bool,
    pub xss_protection: bool,
}

// ─── write_site_config ───────────────────────────────────

/// Render and write the nginx .conf file for a site.
pub fn write_site_config(nginx: &NginxConfig, params: &SiteParams<'_>) -> std::io::Result<()> {
    let file = format!("{}/{}.conf", nginx.site_dir, params.name);
    let log = format!("{}/{}.log", nginx.log_dir, params.name);

    let mut content = format!(
        "#### {} ####\nserver {{\n   listen {};\n   server_name {};\n   access_log {};\n",
        params.name, params.port, params.server_name, log
    );

    if let Some(policy) = params.waf_policy {
        if policy != "None" && !policy.is_empty() {
            content.push_str(&format!(
                "   modsecurity on;\n   modsecurity_rules_file {}/{}.conf;\n",
                nginx.policy_dir, policy
            ));
        }
    }

    if params.hsts {
        content.push_str(
            "   add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n",
        );
    }
    if params.x_frame {
        content.push_str("   add_header X-Frame-Options DENY;\n");
    }
    if params.x_content_type {
        content.push_str("   add_header X-Content-Type-Options nosniff;\n");
    }
    if params.xss_protection {
        content.push_str("   add_header X-XSS-Protection \"1; mode=block\";\n");
    }

    content.push_str(&format!(
        "   location / {{\n     proxy_pass {};\n   }}\n}}\n",
        params.target
    ));

    fs::write(&file, content)?;
    info!("Wrote nginx config: {}", file);
    Ok(())
}

// ─── delete_site_config ──────────────────────────────────

/// Remove the nginx .conf file (and log) for a site.
pub fn delete_site_config(nginx: &NginxConfig, name: &str) {
    let conf = format!("{}/{}.conf", nginx.site_dir, name);
    let log = format!("{}/{}.log", nginx.log_dir, name);
    let _ = fs::remove_file(&conf);
    let _ = fs::remove_file(&log);
    info!("Deleted nginx config: {}", conf);
}

// ─── reload_nginx ────────────────────────────────────────

/// Run the configured reload command and return Ok/Err.
pub fn reload_nginx(reload_cmd: &str) -> Result<(), String> {
    let parts: Vec<&str> = reload_cmd.split_whitespace().collect();
    if parts.is_empty() {
        return Err("reload_cmd is empty".into());
    }
    let status = Command::new(parts[0])
        .args(&parts[1..])
        .status()
        .map_err(|e| format!("Failed to run '{}': {}", reload_cmd, e))?;

    if status.success() {
        info!("nginx reloaded successfully");
        Ok(())
    } else {
        let msg = format!("nginx reload exited with status: {}", status);
        error!("{}", msg);
        Err(msg)
    }
}

// ─── list_rules ──────────────────────────────────────────

/// Return sorted list of OWASP CRS rule file names (without .conf extension),
/// excluding initialisation/exclusion files that should not be toggled.
pub fn list_rules(rules_dir: &str) -> Vec<String> {
    let skip = [
        "REQUEST-901-INITIALIZATION",
        "RESPONSE-999-EXCLUSION-RULES-AFTER-CRS",
    ];
    let Ok(entries) = fs::read_dir(rules_dir) else {
        return Vec::new();
    };
    let mut rules: Vec<String> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            if name.ends_with(".conf") {
                let stem = name.trim_end_matches(".conf").to_string();
                if skip.contains(&stem.as_str()) {
                    None
                } else {
                    Some(stem)
                }
            } else {
                None
            }
        })
        .collect();
    rules.sort();
    rules
}

// ─── write_policy_config ─────────────────────────────────

/// Write a ModSecurity policy .conf file.
pub fn write_policy_config(
    nginx: &NginxConfig,
    name: &str,
    rule_engine: &str,
    enabled_rules: &[String],
) -> std::io::Result<()> {
    let file = format!("{}/{}.conf", nginx.policy_dir, name);
    let mut content = format!("#--------------- {} ---------------\n", name);
    content.push_str(&format!("SecRuleEngine {}\n", rule_engine));
    content.push_str("SecRequestBodyAccess On\n");
    content.push_str("SecRule REQUEST_HEADERS:Content-Type \"^(?:application(?:/soap\\+|/)|text/)xml\" ");
    content.push_str("\"id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML\"\n");
    content.push_str("SecRule REQUEST_HEADERS:Content-Type \"^application/json\" ");
    content.push_str("\"id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON\"\n");
    content.push_str("SecRequestBodyLimit 13107200\n");
    content.push_str("SecRequestBodyNoFilesLimit 131072\n");
    content.push_str("SecRequestBodyLimitAction Reject\n");
    content.push_str("SecRequestBodyJsonDepthLimit 512\n");
    content.push_str("SecArgumentsLimit 1000\n");

    for rule in enabled_rules {
        content.push_str(&format!("include {}/{}.conf\n", nginx.rules_dir, rule));
    }

    fs::write(&file, content)?;
    info!("Wrote policy config: {}", file);
    Ok(())
}

// ─── delete_policy_config ────────────────────────────────

/// Remove the ModSecurity policy .conf file.
pub fn delete_policy_config(nginx: &NginxConfig, name: &str) {
    let file = format!("{}/{}.conf", nginx.policy_dir, name);
    let _ = fs::remove_file(&file);
}

// ─── openssl_cert_info ───────────────────────────────────

/// Run openssl to extract domain, not-before and not-after from a cert file.
/// Returns (domain, not_before, not_after) strings, or empty strings on error.
pub fn openssl_cert_info(cert_path: &str) -> (String, String, String) {
    let domain = run_openssl(&[
        "x509", "-noout", "-subject", "-in", cert_path,
    ]);
    let not_before = run_openssl(&[
        "x509", "-noout", "-startdate", "-in", cert_path,
    ]);
    let not_after = run_openssl(&[
        "x509", "-noout", "-enddate", "-in", cert_path,
    ]);
    (domain, not_before, not_after)
}

/// Run openssl with given args, returning trimmed stdout or empty string.
fn run_openssl(args: &[&str]) -> String {
    Command::new("openssl")
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}
