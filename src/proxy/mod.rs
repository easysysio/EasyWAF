// =========================================================
// proxy/mod.rs — EasyWAF
// HTTP reverse proxy engine.
//
// On startup, reads all distinct listen_port values from
// enabled sites and binds one TCP listener per unique port.
// Incoming requests are routed to a backend site by matching
// the Host: header against sites.server_name in the database.
// Every request is passed through the module pipeline before
// being forwarded to the upstream.
//
// Note: adding a site with a new port or changing a site's
// port requires a proxy restart to take effect, because TCP
// listeners are bound once at startup.
// =========================================================

use crate::challenge::{
    self, ChallengeStore, CLEARANCE_COOKIE, VERIFY_PATH,
};
use crate::modules::{
    traffic::{log_event, TrafficRecord},
    Pipeline, PipelineVerdict, RequestContext,
};
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::Response,
    Router,
};
use reqwest::Client;
use sqlx::SqlitePool;
use std::{collections::{HashMap, HashSet}, net::SocketAddr, sync::Arc, time::Instant};
use tokio::{net::TcpListener, sync::mpsc};

// ─── Hop-by-hop headers ──────────────────────────────────

/// Headers that must not be forwarded between proxy and upstream.
/// These are connection-specific and are stripped before forwarding.
const HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

// ─── ProxyState ──────────────────────────────────────────

/// State shared across all proxy request handlers.
/// Cloned cheaply for each spawned listener / request.
#[derive(Clone)]
pub struct ProxyState {
    pub db:         SqlitePool,
    pub pipeline:   Arc<Pipeline>,
    pub client:     Client,
    /// Secret used to sign CAPTCHA clearance cookies.
    pub secret:     String,
    /// In-memory store of in-flight CAPTCHA challenges.
    pub challenges: ChallengeStore,
}

// ─── SiteRow ─────────────────────────────────────────────

/// Minimal site data fetched per request from the database.
struct SiteRow {
    id:             i64,
    name:           String,
    target:         String,
    hsts:           bool,
    x_frame:        bool,
    x_content_type: bool,
    xss_protection: bool,
}

// ─── start ───────────────────────────────────────────────

/// Bind all ports that exist in the DB now, then wait for new port numbers
/// sent over `port_rx` and bind those on the fly — no restart needed.
///
/// Already-bound ports are tracked in a local HashSet and silently ignored
/// when sent again (e.g. when a site's non-port fields are updated).
pub async fn start(state: ProxyState, mut port_rx: mpsc::Receiver<u16>) {
    // Track which ports we have already spawned a listener for.
    let mut bound: HashSet<u16> = HashSet::new();

    // Bind every port that is configured in the DB at startup.
    let initial_ports = get_listen_ports(&state.db).await;
    if initial_ports.is_empty() {
        tracing::warn!(
            "No enabled sites found at startup — proxy is not listening on any port. \
             Create a site in the GUI to begin proxying."
        );
    }
    for port in initial_ports {
        if bound.insert(port) {
            spawn_listener(state.clone(), port);
        }
    }

    // Wait for new ports sent by the GUI (site create / update).
    // The loop runs for the lifetime of the process because AppState holds
    // a Sender, so the channel is never closed until the process exits.
    while let Some(port) = port_rx.recv().await {
        if bound.insert(port) {
            tracing::info!(port, "Dynamically binding new proxy listener");
            spawn_listener(state.clone(), port);
        } else {
            tracing::debug!(port, "Port already bound — ignoring signal");
        }
    }
}

// ─── spawn_listener ──────────────────────────────────────

/// Spawn a background task that binds `port` and serves forever.
fn spawn_listener(state: ProxyState, port: u16) {
    tokio::spawn(async move {
        start_on_port(state, port).await;
    });
}

// ─── get_listen_ports ────────────────────────────────────

/// Query the database for the distinct set of listen_port values across
/// all enabled sites. Returns a sorted, deduplicated list of port numbers.
async fn get_listen_ports(db: &SqlitePool) -> Vec<u16> {
    let rows = sqlx::query!(
        "SELECT DISTINCT listen_port as \"listen_port!\" FROM sites WHERE enabled = 1"
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let mut ports: Vec<u16> = rows
        .into_iter()
        .filter_map(|r| {
            // Clamp to valid port range — values outside 1-65535 are ignored.
            if r.listen_port > 0 && r.listen_port <= 65535 {
                Some(r.listen_port as u16)
            } else {
                None
            }
        })
        .collect();

    ports.sort_unstable();
    ports.dedup();
    ports
}

// ─── start_on_port ───────────────────────────────────────

/// Bind a TCP listener on the given port and serve requests forever.
/// Each port gets its own Axum Router but shares the same ProxyState.
/// Logs an error and returns (rather than panicking) if the bind fails,
/// so a misconfigured port does not crash the whole process.
async fn start_on_port(state: ProxyState, port: u16) {
    let addr = format!("0.0.0.0:{}", port);

    let listener = match TcpListener::bind(&addr).await {
        Ok(l)  => l,
        Err(e) => {
            tracing::error!(port, "Failed to bind proxy port: {}", e);
            return;
        }
    };

    tracing::info!("Proxy listening on http://{}", addr);

    let app = Router::new()
        .fallback(handle_request)
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();

    axum::serve(listener, app)
        .await
        .expect("proxy server error");
}

// ─── handle_request ──────────────────────────────────────

/// Main proxy handler — called for every incoming request on every port.
/// Flow:
///   1. Extract and validate the Host: header.
///   2. Look up the matching enabled site in the database.
///   3. Buffer the request body (needed by WAF modules).
///   4. Run the module pipeline — block if any module returns Block.
///   5. Forward the request to the upstream via reqwest.
///   6. Inject security headers and stream the response back.
///   7. Log the completed request asynchronously.
async fn handle_request(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<ProxyState>,
    req: axum::extract::Request,
) -> Response<Body> {
    let started_at = Instant::now();

    // ── 1. Extract Host header ────────────────────────────
    // Strip the port suffix (e.g. "example.com:8081" → "example.com")
    // so routing works regardless of which port the client connected on.
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_lowercase();

    if host.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "Missing Host header");
    }

    // ── 2. Look up site ───────────────────────────────────
    let site = match lookup_site(&state.db, &host).await {
        Some(s) => s,
        None => {
            tracing::debug!(host = %host, "no site matched");
            return error_response(StatusCode::NOT_FOUND, "No site configured for this host");
        }
    };

    // ── 3. Decompose request ──────────────────────────────
    let (parts, body) = req.into_parts();
    let method    = parts.method.clone();
    let path      = parts.uri.path().to_string();
    let query     = parts.uri.query().map(str::to_string);
    let headers   = parts.headers.clone();
    let client_ip = peer.ip();

    // Buffer the full body (up to 32 MB) — WAF modules need to inspect it.
    let body_bytes = match axum::body::to_bytes(body, 32 * 1024 * 1024).await {
        Ok(b)  => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "Failed to read request body"),
    };

    // ── 3b. CAPTCHA verify submissions — handled before the WAF ──
    if method == Method::POST && path == VERIFY_PATH {
        return handle_verify(&state, &client_ip.to_string(), &body_bytes);
    }

    // Does the visitor already hold a valid challenge clearance cookie?
    let cleared = clearance_ok(&state, &headers, &client_ip.to_string());

    // ── 4. Build RequestContext and run pipeline ──────────
    let ctx = RequestContext {
        site_id:    site.id,
        site_name:  site.name.clone(),
        client_ip,
        method:     method.clone(),
        host:       host.clone(),
        path:       path.clone(),
        query:      query.clone(),
        headers:    headers.clone(),
        body:       body_bytes.clone(),
        started_at,
    };

    let verdict = state.pipeline.run(&ctx).await;

    if let PipelineVerdict::Block { reason, status, .. } = verdict {
        // Log the blocked request asynchronously so we don't delay the response.
        let elapsed    = started_at.elapsed().as_millis() as i64;
        let db         = state.db.clone();
        let method_str = method.to_string();
        let reason_log = reason.clone();
        tokio::spawn(async move {
            log_event(db, TrafficRecord {
                site_id:      site.id,
                client_ip:    client_ip.to_string(),
                method:       method_str,
                host:         host.clone(),
                path:         path.clone(),
                status_code:  status.as_u16() as i64,
                response_ms:  elapsed,
                blocked:      true,
                block_reason: Some(reason_log),
                waf_score:    None,
                country:      None,
            }).await;
        });
        return error_response(status, &reason);
    }

    // ── 4b. Challenge verdict: show CAPTCHA unless already cleared ──
    if let PipelineVerdict::Challenge { reason, .. } = &verdict {
        if !cleared {
            let dest = match &query {
                Some(q) => format!("{}?{}", path, q),
                None    => path.clone(),
            };
            let (id, data_uri) = state.challenges.issue(&dest, &client_ip.to_string());

            // Log the challenge asynchronously.
            let elapsed    = started_at.elapsed().as_millis() as i64;
            let db         = state.db.clone();
            let method_str = method.to_string();
            let reason_log = format!("challenge: {}", reason);
            let host_l     = host.clone();
            let path_l     = path.clone();
            let ip_l       = client_ip.to_string();
            tokio::spawn(async move {
                log_event(db, TrafficRecord {
                    site_id:      site.id,
                    client_ip:    ip_l,
                    method:       method_str,
                    host:         host_l,
                    path:         path_l,
                    status_code:  200,
                    response_ms:  elapsed,
                    blocked:      false,
                    block_reason: Some(reason_log),
                    waf_score:    None,
                    country:      None,
                }).await;
            });

            return challenge_response(&id, &data_uri, false);
        }
        // Cleared visitor — fall through and forward normally.
    }

    // ── 5. Forward to upstream ────────────────────────────
    let path_and_query = match &query {
        Some(q) => format!("{}?{}", path, q),
        None    => path.clone(),
    };
    let upstream_url = format!(
        "{}{}",
        site.target.trim_end_matches('/'),
        path_and_query
    );

    // Strip hop-by-hop headers before forwarding.
    let mut fwd_headers = headers.clone();
    for h in HOP_HEADERS {
        fwd_headers.remove(*h);
    }

    let upstream_result = state
        .client
        .request(to_reqwest_method(&method), &upstream_url)
        .headers(to_reqwest_headers(&fwd_headers))
        .body(body_bytes)
        .send()
        .await;

    match upstream_result {
        // ── Upstream unreachable ──────────────────────────
        Err(e) => {
            tracing::warn!(upstream = %upstream_url, error = %e, "upstream unreachable");
            let elapsed    = started_at.elapsed().as_millis() as i64;
            let db         = state.db.clone();
            let method_str = method.to_string();
            tokio::spawn(async move {
                log_event(db, TrafficRecord {
                    site_id:      site.id,
                    client_ip:    client_ip.to_string(),
                    method:       method_str,
                    host,
                    path,
                    status_code:  502,
                    response_ms:  elapsed,
                    blocked:      false,
                    block_reason: None,
                    waf_score:    None,
                    country:      None,
                }).await;
            });
            error_response(StatusCode::BAD_GATEWAY, "Upstream unreachable")
        }

        // ── Upstream responded — stream back to client ────
        Ok(upstream_resp) => {
            let status       = upstream_resp.status();
            let resp_headers = upstream_resp.headers().clone();
            let elapsed      = started_at.elapsed().as_millis() as i64;

            // Stream the response body back without buffering it.
            let body_stream = upstream_resp.bytes_stream();
            let body        = Body::from_stream(body_stream);

            // Copy upstream response headers (minus hop-by-hop).
            let mut resp = Response::builder().status(status);
            if let Some(headers_mut) = resp.headers_mut() {
                for (k, v) in &resp_headers {
                    if !HOP_HEADERS.contains(&k.as_str()) {
                        headers_mut.insert(k, v.clone());
                    }
                }
                // Inject any security headers configured for this site.
                inject_security_headers(headers_mut, &site);
            }

            // Log the completed request asynchronously.
            let db         = state.db.clone();
            let method_str = method.to_string();
            tokio::spawn(async move {
                log_event(db, TrafficRecord {
                    site_id:      site.id,
                    client_ip:    client_ip.to_string(),
                    method:       method_str,
                    host,
                    path,
                    status_code:  status.as_u16() as i64,
                    response_ms:  elapsed,
                    blocked:      false,
                    block_reason: None,
                    waf_score:    None,
                    country:      None,
                }).await;
            });

            resp.body(body).unwrap_or_else(|_| {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "Response build error")
            })
        }
    }
}

// ─── lookup_site ─────────────────────────────────────────

/// Find an enabled site by hostname (server_name column).
/// Returns None if no enabled site matches, so the proxy returns 404.
async fn lookup_site(db: &SqlitePool, host: &str) -> Option<SiteRow> {
    sqlx::query!(
        "SELECT id as \"id!\", name, target,
                hsts           as \"hsts!: bool\",
                x_frame        as \"x_frame!: bool\",
                x_content_type as \"x_content_type!: bool\",
                xss_protection as \"xss_protection!: bool\"
         FROM sites
         WHERE server_name = ? AND enabled = 1",
        host
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .map(|r| SiteRow {
        id:             r.id,
        name:           r.name,
        target:         r.target,
        hsts:           r.hsts,
        x_frame:        r.x_frame,
        x_content_type: r.x_content_type,
        xss_protection: r.xss_protection,
    })
}

// ─── inject_security_headers ─────────────────────────────

/// Append configured security response headers to the outgoing response.
/// Only headers that are enabled (set to true in the site row) are added.
fn inject_security_headers(headers: &mut HeaderMap, site: &SiteRow) {
    if site.hsts {
        headers.insert(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    if site.x_frame {
        headers.insert(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        );
    }
    if site.x_content_type {
        headers.insert(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        );
    }
    if site.xss_protection {
        headers.insert(
            HeaderName::from_static("x-xss-protection"),
            HeaderValue::from_static("1; mode=block"),
        );
    }
}

// ─── error_response ──────────────────────────────────────

/// Build a plain-text error response with the given status code and message.
fn error_response(status: StatusCode, msg: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Body::from(msg.to_string()))
        .unwrap()
}

// ─── CAPTCHA challenge helpers ───────────────────────────

/// Build the challenge-page response. Served with no-store so a cleared
/// visitor never gets a cached challenge.
fn challenge_response(id: &str, data_uri: &str, error: bool) -> Response<Body> {
    let html = challenge::challenge_page(id, data_uri, error);
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Body::from(html))
        .unwrap()
}

/// Handle a POST to the verify path: check the answer, set the clearance
/// cookie and redirect on success, or re-serve the challenge on failure.
fn handle_verify(state: &ProxyState, client_ip: &str, body: &[u8]) -> Response<Body> {
    let form = parse_form(body);
    let id     = form.get("id").map(String::as_str).unwrap_or("");
    let answer = form.get("answer").map(String::as_str).unwrap_or("");

    if let Some(dest) = state.challenges.verify(id, answer, client_ip) {
        let cookie = challenge::make_clearance(&state.secret, client_ip);
        let set_cookie = format!(
            "{}={}; Path=/; Max-Age=1800; HttpOnly; SameSite=Lax",
            CLEARANCE_COOKIE, cookie
        );
        // Only redirect to a same-site path, never an absolute URL.
        let location = if dest.starts_with('/') { dest } else { "/".to_string() };
        return Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header("location", location)
            .header("set-cookie", set_cookie)
            .header("cache-control", "no-store")
            .body(Body::empty())
            .unwrap();
    }

    // Wrong or expired answer — re-issue a challenge to the same destination.
    let dest = state.challenges.dest_of(id).unwrap_or_else(|| "/".to_string());
    let (new_id, data_uri) = state.challenges.issue(&dest, client_ip);
    challenge_response(&new_id, &data_uri, true)
}

/// True if the request carries a valid clearance cookie for this client IP.
fn clearance_ok(state: &ProxyState, headers: &HeaderMap, client_ip: &str) -> bool {
    match cookie_value(headers, CLEARANCE_COOKIE) {
        Some(v) => challenge::check_clearance(&state.secret, client_ip, &v),
        None    => false,
    }
}

/// Extract a single cookie value from the Cookie request header.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get("cookie")?.to_str().ok()?;
    for pair in raw.split(';') {
        if let Some((k, v)) = pair.trim().split_once('=') {
            if k == name {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Parse an application/x-www-form-urlencoded body into a map.
fn parse_form(body: &[u8]) -> HashMap<String, String> {
    let s = String::from_utf8_lossy(body);
    let mut map = HashMap::new();
    for pair in s.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = decode_component(it.next().unwrap_or(""));
        let v = decode_component(it.next().unwrap_or(""));
        if !k.is_empty() {
            map.insert(k, v);
        }
    }
    map
}

/// URL-decode one form component ('+' → space, then percent-decoding).
fn decode_component(s: &str) -> String {
    let plus = s.replace('+', " ");
    urlencoding::decode(&plus).map(|c| c.into_owned()).unwrap_or(plus)
}

// ─── Header conversion helpers ───────────────────────────

/// Convert an axum Method to a reqwest Method for the upstream request.
fn to_reqwest_method(m: &Method) -> reqwest::Method {
    reqwest::Method::from_bytes(m.as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET)
}

/// Copy axum HeaderMap into a reqwest HeaderMap, skipping any malformed values.
fn to_reqwest_headers(headers: &HeaderMap) -> reqwest::header::HeaderMap {
    let mut out = reqwest::header::HeaderMap::new();
    for (k, v) in headers {
        if let (Ok(name), Ok(val)) = (
            reqwest::header::HeaderName::from_bytes(k.as_ref()),
            reqwest::header::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            out.insert(name, val);
        }
    }
    out
}
