// =========================================================
// proxy/mod.rs — EasyWAF
// HTTP reverse proxy engine.
//
// On startup, reads all distinct listen_port values from
// enabled sites and binds one TCP listener per unique port.
// Incoming requests are routed to a backend site by matching
// the Host: header against sites.server_name — or one of the
// site's aliases — in the database.
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
use std::{collections::{HashMap, HashSet}, net::SocketAddr, sync::Arc, sync::OnceLock, sync::RwLock, time::Instant};
use axum_server::tls_rustls::RustlsConfig;
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

// ─── BindRequest ─────────────────────────────────────────

/// A port the GUI has asked the proxy to start listening on.
///
/// Carries the kind because a site can have both: `listen_port` serving plain
/// HTTP and `tls_port` serving HTTPS, bound independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BindRequest {
    pub port: u16,
    pub tls:  bool,
}

/// The port HTTP-01 validation always arrives on. Fixed by RFC 8555: a CA
/// will not be redirected to another port for the first request, so a
/// certificate cannot be obtained without something answering here.
pub const ACME_PORT: u16 = 80;

/// Ports with a listener that actually came up, as opposed to one that was
/// asked for.
///
/// A bind can fail after the request — the port is already in use, or the
/// process lacks CAP_NET_BIND_SERVICE for a privileged one — and the two are
/// indistinguishable from the request side. The difference is the whole
/// explanation when a certificate validation never arrives, so it is recorded
/// where the bind succeeds rather than where it is wished for.
static LISTENING: OnceLock<RwLock<HashSet<BindRequest>>> = OnceLock::new();

fn listening() -> &'static RwLock<HashSet<BindRequest>> {
    LISTENING.get_or_init(Default::default)
}

/// Whether a plain-HTTP listener is up on `port`.
pub fn is_listening_plain(port: u16) -> bool {
    listening()
        .read()
        .map(|l| l.contains(&BindRequest { port, tls: false }))
        .unwrap_or(false)
}

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
    /// True for the HTTPS listeners. The handler is shared between both kinds,
    /// and needs to know which it is on to avoid redirecting an HTTPS request
    /// to itself forever.
    pub is_tls:     bool,
    /// Flow lines to the collector. Cloned per request into the spawned
    /// logging task, never awaited on the request path.
    pub logger:     crate::logging::Logger,
}

// ─── SiteRow ─────────────────────────────────────────────

/// Minimal site data fetched per request from the database.
struct SiteRow {
    id:             i64,
    name:           String,
    target:         String,
    tls_port:       Option<i64>,
    tls_redirect:   bool,
    hsts:           bool,
    x_frame:        bool,
    x_frame_value:  String,
    x_content_type: bool,
    xss_protection: bool,
}

// ─── start ───────────────────────────────────────────────

/// Bind all ports that exist in the DB now, then wait for new port numbers
/// sent over `port_rx` and bind those on the fly — no restart needed.
///
/// Already-bound ports are tracked in a local HashSet and silently ignored
/// when sent again (e.g. when a site's non-port fields are updated).
pub async fn start(state: ProxyState, mut port_rx: mpsc::Receiver<BindRequest>) {
    // Track which ports we have already spawned a listener for. A plain and a
    // TLS listener on the same number would be a configuration mistake, but
    // they are tracked separately so the set never silently swallows one.
    let mut bound: HashSet<BindRequest> = HashSet::new();

    // Bind every port that is configured in the DB at startup.
    let mut initial = get_listen_ports(&state.db).await;
    if initial.is_empty() {
        tracing::warn!(
            "No enabled sites found at startup — no site is being proxied yet. \
             Create a site in the GUI to begin proxying."
        );
    }

    // Port 80 is bound whether or not a site asks for it, because HTTP-01
    // validation always arrives there and a certificate cannot be obtained
    // without an answer. Binding it only when a site happened to use it meant
    // a certificate could be requested for a name nothing on this host would
    // ever answer for, and the only symptom was the CA timing out.
    //
    // A request to it for a hostname no site claims is answered exactly as it
    // would be on any other port: 404, or the maintenance page for a site that
    // is switched off. The listener adds an ACME responder, not a new way in.
    let acme_bind = BindRequest { port: ACME_PORT, tls: false };
    if !initial.contains(&acme_bind) {
        initial.push(acme_bind);
    }

    for req in initial {
        if bound.insert(req) {
            spawn_listener(state.clone(), req);
        }
    }

    // Wait for new ports sent by the GUI (site create / update).
    // The loop runs for the lifetime of the process because AppState holds
    // a Sender, so the channel is never closed until the process exits.
    while let Some(req) = port_rx.recv().await {
        if bound.insert(req) {
            tracing::info!(port = req.port, tls = req.tls, "Dynamically binding new proxy listener");
            spawn_listener(state.clone(), req);
        } else {
            tracing::debug!(port = req.port, tls = req.tls, "Port already bound — ignoring signal");
        }
    }
}

// ─── spawn_listener ──────────────────────────────────────

/// Spawn a background task that binds the port and serves forever.
fn spawn_listener(state: ProxyState, req: BindRequest) {
    tokio::spawn(async move {
        if req.tls {
            start_tls_on_port(state, req.port).await;
        } else {
            start_on_port(state, req.port).await;
        }
    });
}

// ─── get_listen_ports ────────────────────────────────────

/// Query the database for the distinct set of listen_port values across
/// all enabled sites. Returns a sorted, deduplicated list of port numbers.
async fn get_listen_ports(db: &SqlitePool) -> Vec<BindRequest> {
    let mut out: Vec<BindRequest> = Vec::new();

    let plain = sqlx::query!(
        "SELECT DISTINCT listen_port as \"listen_port!\" FROM sites WHERE enabled = 1"
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    for r in plain {
        if let Some(port) = valid_port(r.listen_port) {
            out.push(BindRequest { port, tls: false });
        }
    }

    // Only sites that actually have a certificate: binding a TLS port with
    // nothing to present would fail every handshake, which is worse than not
    // listening at all and much harder to diagnose.
    let secure = sqlx::query!(
        "SELECT DISTINCT tls_port as \"tls_port!\"
         FROM sites
         WHERE enabled = 1 AND tls_port IS NOT NULL AND cert_id IS NOT NULL"
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    for r in secure {
        if let Some(port) = valid_port(r.tls_port) {
            out.push(BindRequest { port, tls: true });
        }
    }

    // Extra ports, beyond the primary pair. A TLS one is bound only when the
    // site has a certificate, for the reason above — binding with nothing to
    // present fails every handshake, which is harder to diagnose than a port
    // that is simply not there.
    let extra = sqlx::query!(
        r#"SELECT DISTINCT sp.port as "port!", sp.tls as "tls!: bool"
           FROM   site_ports sp
           JOIN   sites s ON s.id = sp.site_id
           WHERE  s.enabled = 1 AND (sp.tls = 0 OR s.cert_id IS NOT NULL)"#
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    for r in extra {
        if let Some(port) = valid_port(r.port) {
            out.push(BindRequest { port, tls: r.tls });
        }
    }

    out.sort_unstable_by_key(|r| (r.port, r.tls));
    out.dedup();
    out
}

/// Accept a port number only if it is in range — a value outside 1-65535 is
/// ignored rather than wrapped into some other port.
fn valid_port(port: i64) -> Option<u16> {
    if port > 0 && port <= 65535 {
        Some(port as u16)
    } else {
        None
    }
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
            // Port 80 is bound for everyone now, so failing to get it is a
            // normal thing to hit — something else already has it, or the
            // process lacks CAP_NET_BIND_SERVICE. Worth saying what stops
            // working, because the consequence shows up much later and looks
            // like a certificate problem rather than a bind one.
            if port == ACME_PORT {
                tracing::error!(
                    port,
                    "Failed to bind port {port}: {e}. Let's Encrypt validation always \
                     arrives on port {port}, so certificates cannot be issued or renewed \
                     until whatever holds it is stopped, or port {port} is forwarded to a \
                     port EasyWAF does listen on. Sites on other ports are unaffected."
                );
            } else {
                tracing::error!(port, "Failed to bind proxy port: {}", e);
            }
            return;
        }
    };

    if let Ok(mut l) = listening().write() {
        l.insert(BindRequest { port, tls: false });
    }
    tracing::info!("Proxy listening on http://{}", addr);

    let app = Router::new()
        .fallback(handle_request)
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();

    axum::serve(listener, app)
        .await
        .expect("proxy server error");
}

// ─── start_tls_on_port ───────────────────────────────────

/// Bind an HTTPS listener and serve requests forever.
///
/// Certificates are chosen per connection by SNI, so one port serves every
/// site configured to use it, each presenting its own certificate. The TLS
/// version and cipher profile is appliance-wide — rustls fixes it when the
/// listener is bound, before any server name is known.
///
/// Logs and returns rather than panicking if the bind fails, so one
/// misconfigured port cannot take the whole proxy down.
async fn start_tls_on_port(state: ProxyState, port: u16) {
    let state = ProxyState { is_tls: true, ..state };
    let addr: SocketAddr = match format!("0.0.0.0:{}", port).parse() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(port, "Invalid TLS listen address: {}", e);
            return;
        }
    };

    let profile = crate::routes::settings::get_tls_profile(&state.db).await;
    let suites  = crate::routes::settings::get_tls_ciphers(&state.db).await;
    let config  = RustlsConfig::from_config(crate::tls::server_config(profile, &suites));

    // Bound before announcing, for the same reason as the management port:
    // bind_rustls defers the bind into serve(), so logging first would claim a
    // listener that may never exist.
    let listener = match crate::tls::bind_listener(addr) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(port, "Failed to bind TLS proxy port: {}", e);
            return;
        }
    };

    if let Ok(mut l) = listening().write() {
        l.insert(BindRequest { port, tls: true });
    }
    tracing::info!(profile = profile.as_str(), "Proxy listening on https://{}", addr);

    let app = Router::new()
        .fallback(handle_request)
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();

    // 0.8 made this fallible rather than panicking on a listener it cannot
    // adopt. Reported and returned from, since this task owns one port and
    // the other listeners are unaffected.
    let server = match axum_server::from_tcp_rustls(listener, config) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(port, "Cannot serve TLS on the bound port: {}", e);
            return;
        }
    };

    if let Err(e) = server.serve(app).await {
        tracing::error!(port, "TLS proxy server error: {}", e);
    }
}

/// Copy the upstream's response headers, dropping hop-by-hop ones.
///
/// `append`, not `insert`. A `HeaderMap` yields one pair per value, so
/// inserting in a loop keeps only the last of any repeated header — and the
/// header applications repeat most is `Set-Cookie`. A login that sets a session
/// cookie alongside others would reach the browser with one of them, the
/// session would not exist, and the user would be returned to the login page
/// with nothing logged anywhere to say why.
fn copy_response_headers(dst: &mut HeaderMap, src: &HeaderMap) {
    for (k, v) in src {
        if !HOP_HEADERS.contains(&k.as_str()) {
            dst.append(k, v.clone());
        }
    }
}

// ─── Forwarding headers ──────────────────────────────────

/// Tell the upstream what the original request looked like.
///
/// Without these an application behind EasyWAF cannot know it is behind
/// anything: it sees a plain HTTP request from a local address, so it builds
/// `http://` URLs, redirects to them, and marks session cookies as not needing
/// a secure connection. Applications that generate absolute URLs — Nextcloud
/// is the usual example — fail to log in for exactly that reason, while an
/// API-driven front end on the same proxy works fine and makes it look like
/// the application's fault.
fn apply_forwarded_headers(
    headers: &mut HeaderMap,
    peer: std::net::IpAddr,
    client: std::net::IpAddr,
    original_host: Option<&HeaderValue>,
    is_tls: bool,
) {
    // `client` differs from `peer` only when the peer is a proxy we trust and
    // its X-Forwarded-For was honoured. In that case the chain it sent is
    // worth passing on, with this hop appended.
    //
    // Otherwise the header is replaced outright rather than appended to. A
    // client that sends its own X-Forwarded-For is claiming an address, and
    // forwarding that claim would hand the upstream a forgery this proxy
    // already decided not to believe.
    let xff = match headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        Some(existing) if client != peer => format!("{existing}, {peer}"),
        _ => client.to_string(),
    };

    let set = |h: &mut HeaderMap, name: &'static str, value: String| {
        if let Ok(v) = HeaderValue::from_str(&value) {
            h.insert(HeaderName::from_static(name), v);
        }
    };

    set(headers, "x-forwarded-for", xff);
    set(headers, "x-real-ip", client.to_string());

    // The scheme the *client* used, which is what an application needs to build
    // links back to itself — not the scheme of this hop to the upstream.
    set(headers, "x-forwarded-proto", if is_tls { "https".into() } else { "http".into() });

    // Forwarded verbatim, port included: an application on a non-standard port
    // needs it to build a URL that works.
    if let Some(h) = original_host
        && let Ok(v) = h.to_str()
    {
        set(headers, "x-forwarded-host", v.to_string());
    }
}

// ─── WebSocket / protocol upgrades ───────────────────────

/// Whether this request is asking to leave HTTP behind.
///
/// Both headers are required: `Upgrade` names the protocol, and `Connection`
/// must list `upgrade` for it to mean anything. A request carrying only one is
/// not an upgrade and must not be treated as one.
pub fn is_upgrade(headers: &HeaderMap) -> bool {
    let connection_says_upgrade = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));

    connection_says_upgrade && headers.contains_key("upgrade")
}

/// Proxy an upgrade request, tunnelling the connection if the upstream accepts.
///
/// This is the one path that does not go through reqwest, which has no way to
/// take over a connection after the response. It opens its own connection,
/// speaks HTTP/1.1 by hand, and if the upstream answers `101 Switching
/// Protocols` it stops being an HTTP proxy: both sides are handed to
/// `copy_bidirectional` and the bytes are relayed until one end closes.
///
/// **The tunnel is not inspected.** The handshake is a normal request and goes
/// through the pipeline like any other, but once it is upgraded EasyWAF is
/// relaying opaque frames. That is inherent to proxying WebSockets rather than
/// a shortcut — the payload is no longer HTTP, so there is nothing for HTTP
/// rules to match.
async fn proxy_upgrade(
    upstream: &str,
    method: &Method,
    headers: &HeaderMap,
    on_upgrade: hyper::upgrade::OnUpgrade,
) -> std::result::Result<Response<Body>, String> {
    let url = upstream.parse::<hyper::Uri>().map_err(|e| format!("upstream URL: {e}"))?;
    let host = url.host().ok_or("upstream URL has no host")?;
    let port = url.port_u16().unwrap_or(match url.scheme_str() {
        Some("https") => 443,
        _             => 80,
    });

    if url.scheme_str() == Some("https") {
        // Tunnelling to a TLS upstream needs a TLS client on this path too.
        // Refused rather than attempted, so the failure names itself instead of
        // arriving as a protocol error.
        return Err("upgrades to an https:// upstream are not supported yet".into());
    }

    let stream = tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(|e| format!("connecting to {host}:{port}: {e}"))?;

    let (mut sender, conn) = hyper::client::conn::http1::handshake(
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .map_err(|e| format!("upstream handshake: {e}"))?;

    // The connection must keep being driven, and `with_upgrades` is what lets
    // it hand back the raw stream once the upstream switches protocols.
    let conn_task = tokio::spawn(conn.with_upgrades());

    let path = url.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let mut builder = hyper::Request::builder().method(method).uri(path);

    if let Some(hs) = builder.headers_mut() {
        // Forwarded whole, including Connection and Upgrade. They are
        // hop-by-hop and stripped for every other request, which is correct —
        // and is exactly why an upgrade never reached the upstream before.
        for (k, v) in headers {
            hs.insert(k, v.clone());
        }
        if let Ok(h) = hyper::header::HeaderValue::from_str(&format!("{host}:{port}")) {
            hs.insert(hyper::header::HOST, h);
        }
    }

    let req = builder
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .map_err(|e| format!("building upstream request: {e}"))?;

    let upstream_resp = sender
        .send_request(req)
        .await
        .map_err(|e| format!("upstream request: {e}"))?;

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    if status != StatusCode::SWITCHING_PROTOCOLS {
        // The upstream declined to upgrade. Pass its answer back unchanged;
        // it is a normal response and the client will deal with it.
        conn_task.abort();
        let mut resp = Response::builder().status(status);
        if let Some(hs) = resp.headers_mut() {
            for (k, v) in &resp_headers {
                if !HOP_HEADERS.contains(&k.as_str()) {
                    hs.insert(k, v.clone());
                }
            }
        }
        return resp
            .body(Body::empty())
            .map_err(|e| format!("response: {e}"));
    }

    // Both sides agreed. Wait for each end to hand over its raw stream, then
    // relay until one closes.
    tokio::spawn(async move {
        let upstream_io = match hyper::upgrade::on(upstream_resp).await {
            Ok(io) => io,
            Err(e) => {
                tracing::warn!("upstream upgrade failed: {}", e);
                return;
            }
        };
        let client_io = match on_upgrade.await {
            Ok(io) => io,
            Err(e) => {
                tracing::warn!("client upgrade failed: {}", e);
                return;
            }
        };

        let mut a = hyper_util::rt::TokioIo::new(client_io);
        let mut b = hyper_util::rt::TokioIo::new(upstream_io);

        match tokio::io::copy_bidirectional(&mut a, &mut b).await {
            Ok((from_client, from_upstream)) => tracing::debug!(
                from_client, from_upstream, "upgraded connection closed"
            ),
            // Both halves closing abruptly is ordinary for a tunnel that a
            // browser tab simply went away from, so this is not an error.
            Err(e) => tracing::debug!("upgraded connection ended: {}", e),
        }
    });

    // 101 back to the client with the upstream's own handshake headers —
    // Sec-WebSocket-Accept among them, which the client verifies. These are
    // hop-by-hop and must NOT be stripped here.
    let mut resp = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    if let Some(hs) = resp.headers_mut() {
        for (k, v) in &resp_headers {
            hs.insert(k, v.clone());
        }
    }
    resp.body(Body::empty()).map_err(|e| format!("response: {e}"))
}

// ─── handle_request ──────────────────────────────────────

/// Spread an allowed request's detection into the four columns that store it.
///
/// A tuple rather than four `Option`s threaded separately: they are only ever
/// set together, and a request that matched nothing must not record a score of
/// zero — that would be indistinguishable from one that matched a rule scoring
/// nothing, and would make "clean" a value rather than an absence.
fn split_detection(
    found: Option<(i64, Option<String>, String, String)>,
) -> (Option<i64>, Option<String>, Option<String>, Option<String>) {
    match found {
        Some((score, hits, detection, why)) => (
            Some(score),
            hits,
            Some(detection),
            if why.is_empty() { None } else { Some(why) },
        ),
        None => (None, None, None, None),
    }
}

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

    // ── 1b. ACME HTTP-01 challenge ────────────────────────
    // Answered before everything else, and on purpose.
    //
    // Before the site lookup, so it works for a site that is disabled or not
    // configured yet. Before the HTTPS redirect, because the CA follows
    // redirects and a site with a broken certificate would bounce the
    // validator into a connection it cannot complete — the exact situation
    // someone is trying to fix. Before the pipeline, because a token is opaque
    // base64url and nothing should be able to score or block one: a renewal
    // that failed because a scanner rule matched its challenge token would be
    // a genuinely awful outage to diagnose.
    //
    // Only on the plain-HTTP listener: HTTP-01 validation always arrives on
    // port 80, so answering on the TLS one would serve a token to something
    // that is not the CA.
    //
    // A challenge path with no answer published falls through to be handled as
    // any other request would be, rather than confirming the path exists.
    if !state.is_tls
        && let Some(token) = crate::acme::token_from_path(req.uri().path())
        && let Some(answer) = crate::acme::answer(token)
    {
        tracing::info!(host = %host, "Answered an ACME HTTP-01 challenge");
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(Body::from(answer))
            .unwrap_or_else(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "response"));
    }

    // ── 2. Look up site ───────────────────────────────────
    let site = match lookup_site(&state.db, &host).await {
        Some(s) => s,
        None => {
            // A site that exists but is switched off is a different situation
            // from a hostname nobody configured: the first is the operator
            // taking it down on purpose, and its visitors deserve to be told
            // that rather than being shown a 404 that reads like a mistake.
            if site_is_disabled(&state.db, &host).await {
                let message = crate::routes::settings::get_maintenance_message(&state.db).await;
                tracing::debug!(host = %host, "site is disabled — serving maintenance page");
                return maintenance_response(&message);
            }
            tracing::debug!(host = %host, "no site matched");
            return error_response(StatusCode::NOT_FOUND, "No site configured for this host");
        }
    };

    // ── 2b. Redirect to HTTPS when the site asks for it ───
    // Only from a plain listener, and only when there is somewhere to send
    // them: redirecting to a TLS port that is not bound would take the site
    // off the air instead of securing it. Done before any inspection, since
    // the request is not being served here either way.
    if !state.is_tls && site.tls_redirect {
        if let Some(tls_port) = site.tls_port {
            let target = if tls_port == 443 {
                format!("https://{}{}", host, req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/"))
            } else {
                format!(
                    "https://{}:{}{}",
                    host,
                    tls_port,
                    req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/")
                )
            };
            return Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header("location", target)
                .body(Body::empty())
                .unwrap_or_else(|_| {
                    error_response(StatusCode::INTERNAL_SERVER_ERROR, "Redirect build error")
                });
        }
    }

    // ── 3. Decompose request ──────────────────────────────
    // Taken before the request is torn apart: the handle that lets this
    // connection be upgraded lives in its extensions and goes with them.
    let mut req = req;
    let on_upgrade = req.extensions_mut().remove::<hyper::upgrade::OnUpgrade>();

    let (parts, body) = req.into_parts();
    let method    = parts.method.clone();
    let path      = parts.uri.path().to_string();
    let query     = parts.uri.query().map(str::to_string);
    let headers   = parts.headers.clone();
    // The connection's peer unless it came from a configured proxy, in which
    // case the client address that proxy reported. Resolved here, once, so
    // everything downstream — country rules, CAPTCHA clearance, the traffic
    // log — agrees on who the client is.
    let client_ip = crate::forwarded::client_ip(peer.ip(), &headers);
    // Resolved once and reused: the traffic log records it, and the country
    // rules in the pipeline read it from the same lookup.
    let country   = crate::geo::country_of(client_ip);

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

    if let PipelineVerdict::Block { reason, status, findings, .. } = verdict {
        // Log the blocked request asynchronously so we don't delay the response.
        let elapsed    = started_at.elapsed().as_millis() as i64;
        let db         = state.db.clone();
            let logger     = state.logger.clone();
        let method_str = method.to_string();
        let reason_log = reason.clone();
        tokio::spawn(async move {
            log_event(db, logger, TrafficRecord {
                site_id:      site.id,
                client_ip:    client_ip.to_string(),
                method:       method_str,
                host:         host.clone(),
                path:         path.clone(),
                query:        query.clone(),
                status_code:  status.as_u16() as i64,
                response_ms:  elapsed,
                blocked:      true,
                block_reason: Some(reason_log),
                waf_score:    Some(findings.score),
                matched_rules: findings.hits_json(),
                country:      country.clone(),
                // The request was refused; `blocked` says so. `detection` is
                // for what would have happened and did not.
                detection:    None,
            }).await;
        });
        return error_response(status, &reason);
    }

    // ── 4b. Challenge verdict: show CAPTCHA unless already cleared ──
    if let PipelineVerdict::Challenge { reason, findings, .. } = &verdict {
        if !cleared {
            let dest = match &query {
                Some(q) => format!("{}?{}", path, q),
                None    => path.clone(),
            };
            let (id, data_uri) = state.challenges.issue(&dest, &client_ip.to_string());

            // Log the challenge asynchronously.
            let elapsed    = started_at.elapsed().as_millis() as i64;
            let db         = state.db.clone();
            let logger     = state.logger.clone();
            let method_str = method.to_string();
            let reason_log = format!("challenge: {}", reason);
            // Copied out before the spawn: the verdict is borrowed here, and a
            // challenged request is worth attributing for the same reason a
            // blocked one is.
            let score      = findings.score;
            let hits       = findings.hits_json();
            let host_l     = host.clone();
            let path_l     = path.clone();
            let ip_l       = client_ip.to_string();
            tokio::spawn(async move {
                log_event(db, logger, TrafficRecord {
                    site_id:      site.id,
                    client_ip:    ip_l,
                    method:       method_str,
                    host:         host_l,
                    path:         path_l,
                    query:        query.clone(),
                    status_code:  200,
                    response_ms:  elapsed,
                    blocked:      false,
                    block_reason: Some(reason_log),
                    waf_score:    Some(score),
                    matched_rules: hits,
                    country:      country.clone(),
                    detection:    None,   // it was challenged, not merely detected
                }).await;
            });

            return challenge_response(&id, &data_uri, false);
        }
        // Cleared visitor — fall through and forward normally.
    }

    // What the WAF found on a request it is about to allow.
    //
    // Until 0.6.11 this was dropped: every allowed request logged a clean
    // record, whether nothing had matched or a DetectionOnly policy had just
    // decided it would have blocked. That made DetectionOnly report nothing,
    // and hid every near-miss in enforcing mode too.
    //
    // Computed once here because three paths below forward a request —
    // WebSocket upgrade, cleared challenge, and the ordinary response.
    let detected: Option<(i64, Option<String>, String, String)> = match &verdict {
        PipelineVerdict::Allow { findings, alerts } => findings.detection.map(|d| {
            let why = alerts
                .iter()
                .map(|a| a.reason.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            (findings.score, findings.hits_json(), d.as_str().to_string(), why)
        }),
        // A cleared challenge falls through to here. It was challenged, and
        // the visitor answered; that is not a detection to report again.
        _ => None,
    };

    // ── 5. Forward to upstream ────────────────────────────
    // Kept because `query` is consumed below and the flow line still needs it:
    // a query string is where most of what a WAF matches actually lives.
    let qs = query.clone();

    let path_and_query = match &query {
        Some(q) => format!("{}?{}", path, q),
        None    => path.clone(),
    };
    let upstream_url = format!(
        "{}{}",
        site.target.trim_end_matches('/'),
        path_and_query
    );

    // An accepted upgrade leaves HTTP behind, so it cannot go through reqwest,
    // which has no way to take over a connection after the response. It happens
    // here rather than earlier so the handshake is inspected like any other
    // request — it is a normal GET with headers, and the pipeline has already
    // had its say by this point.
    if is_upgrade(&headers)
        && let Some(on_upgrade) = on_upgrade
    {
        tracing::debug!(host = %host, path = %path, "proxying a protocol upgrade");
        let resp = match proxy_upgrade(&upstream_url, &method, &headers, on_upgrade).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!(upstream = %upstream_url, "upgrade failed: {}", e);
                error_response(StatusCode::BAD_GATEWAY, "Upgrade failed")
            }
        };

        // Logged like any other request. The tunnel that follows cannot be,
        // but the handshake is the only record that the connection happened at
        // all — without it a WebSocket application is invisible in Traffic
        // Monitor, which is worse than useless when someone is trying to work
        // out whether their traffic is reaching the site.
        let db         = state.db.clone();
            let logger     = state.logger.clone();
        let method_str = method.to_string();
        let status     = resp.status().as_u16() as i64;
        let elapsed    = started_at.elapsed().as_millis() as i64;
        let (h, pth, c) = (host.clone(), path.clone(), country.clone());
        let site_id    = site.id;
        let ip         = client_ip.to_string();
        let found      = detected.clone();
        tokio::spawn(async move {
            let (score, hits, detection, why) = split_detection(found);
            log_event(db, logger, TrafficRecord {
                site_id,
                client_ip:    ip,
                method:       method_str,
                host:         h,
                path:         pth,
                query:        query.clone(),
                status_code:  status,
                response_ms:  elapsed,
                blocked:      false,
                block_reason: why,
                waf_score:    score,
                matched_rules: hits,
                country:      c,
                detection,
            }).await;
        });

        return resp;
    }

    // Strip hop-by-hop headers before forwarding.
    let mut fwd_headers = headers.clone();
    for h in HOP_HEADERS {
        fwd_headers.remove(*h);
    }

    apply_forwarded_headers(
        &mut fwd_headers,
        peer.ip(),
        client_ip,
        headers.get(axum::http::header::HOST),
        state.is_tls,
    );

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
            let logger     = state.logger.clone();
            let method_str = method.to_string();
            let found      = detected.clone();
            tokio::spawn(async move {
                let (score, hits, detection, why) = split_detection(found);
                log_event(db, logger, TrafficRecord {
                    site_id:      site.id,
                    client_ip:    client_ip.to_string(),
                    method:       method_str,
                    host,
                    path,
                    query:        qs.clone(),
                    status_code:  502,
                    response_ms:  elapsed,
                    blocked:      false,
                    block_reason: why,
                    waf_score:    score,
                    matched_rules: hits,
                    country:      country.clone(),
                    detection,
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
            //
            // `append`, not `insert`. A HeaderMap yields one pair per value, so
            // inserting in a loop keeps only the last of any repeated header —
            // and the header applications repeat most is Set-Cookie. A login
            // that sets a session cookie and a passphrase cookie together would
            // arrive with one of them, and the browser would come back
            // unauthenticated to the login page with nothing logged anywhere.
            let mut resp = Response::builder().status(status);
            if let Some(headers_mut) = resp.headers_mut() {
                copy_response_headers(headers_mut, &resp_headers);
                // Inject any security headers configured for this site.
                inject_security_headers(headers_mut, &site);
            }

            // Log the completed request asynchronously.
            let db         = state.db.clone();
            let logger     = state.logger.clone();
            let method_str = method.to_string();
            let found      = detected.clone();
            tokio::spawn(async move {
                let (score, hits, detection, why) = split_detection(found);
                log_event(db, logger, TrafficRecord {
                    site_id:      site.id,
                    client_ip:    client_ip.to_string(),
                    method:       method_str,
                    host,
                    path,
                    query:        qs.clone(),
                    status_code:  status.as_u16() as i64,
                    response_ms:  elapsed,
                    blocked:      false,
                    block_reason: why,
                    waf_score:    score,
                    matched_rules: hits,
                    country:      country.clone(),
                    detection,
                }).await;
            });

            resp.body(body).unwrap_or_else(|_| {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "Response build error")
            })
        }
    }
}

// ─── lookup_site ─────────────────────────────────────────

/// Find an enabled site by hostname — its `server_name`, or any of its
/// aliases.
/// Returns None if no enabled site matches, so the proxy returns 404.
async fn lookup_site(db: &SqlitePool, host: &str) -> Option<SiteRow> {
    sqlx::query!(
        "SELECT id as \"id!\", name, target,
                tls_port,
                tls_redirect   as \"tls_redirect!: bool\",
                hsts           as \"hsts!: bool\",
                x_frame        as \"x_frame!: bool\",
                x_frame_value  as \"x_frame_value!\",
                x_content_type as \"x_content_type!: bool\",
                xss_protection as \"xss_protection!: bool\"
         FROM sites
         WHERE enabled = 1
           AND (server_name = ?1
                OR EXISTS (SELECT 1 FROM site_aliases a
                           WHERE a.site_id = sites.id AND a.name = ?1))
         LIMIT 1",
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
        tls_port:       r.tls_port,
        tls_redirect:   r.tls_redirect,
        hsts:           r.hsts,
        x_frame:        r.x_frame,
        x_frame_value:  r.x_frame_value,
        x_content_type: r.x_content_type,
        xss_protection: r.xss_protection,
    })
}

// ─── site_is_disabled ────────────────────────────────────

/// True when a site exists for this hostname but is switched off.
///
/// Only reached when `lookup_site` found nothing, so this runs on the miss path
/// and never on a served request.
async fn site_is_disabled(db: &SqlitePool, host: &str) -> bool {
    sqlx::query_scalar!(
        "SELECT COUNT(*) FROM sites
         WHERE enabled = 0
           AND (server_name = ?1
                OR EXISTS (SELECT 1 FROM site_aliases a
                           WHERE a.site_id = sites.id AND a.name = ?1))",
        host
    )
    .fetch_one(db)
    .await
    .map(|n| n > 0)
    .unwrap_or(false)
}

// ─── maintenance_response ────────────────────────────────

/// Build the page shown for a disabled site.
///
/// 503 rather than 404 or 200: the hostname is configured and expected back, so
/// this is "unavailable right now", which is also what a crawler should take
/// from it. Retry-After gives that a concrete meaning without committing to a
/// return time the operator has not promised.
///
/// The page is self-contained — no CSS or images fetched from anywhere — since
/// it is served to the public while the site behind it is deliberately down.
fn maintenance_response(message: &str) -> Response<Body> {
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Temporarily unavailable</title>
<style>
  body {{ margin:0; min-height:100vh; display:flex; align-items:center;
         justify-content:center; background:#0f172a; color:#e2e8f0;
         font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }}
  .card {{ max-width:32rem; padding:2.5rem; text-align:center; }}
  h1 {{ font-size:1.4rem; font-weight:600; margin:0 0 .75rem; }}
  p  {{ margin:0; line-height:1.6; color:#94a3b8; }}
</style>
</head>
<body>
  <div class="card">
    <h1>Temporarily unavailable</h1>
    <p>{}</p>
  </div>
</body>
</html>"#,
        escape_html(message)
    );

    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .header("retry-after", "3600")
        .body(Body::from(html))
        .unwrap()
}

/// Escape the five characters that would otherwise let the configured text
/// break out of the page. The text comes from an authenticated administrator
/// rather than from a request, but it is still data being placed into markup.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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
        // The configured value wins over anything the application sent, so
        // what the setting says is what is served. DENY forbids framing by
        // *anything*, self included, which quietly breaks applications that
        // frame their own pages — Nextcloud is one, and reports the header as
        // misconfigured when it sees it.
        let v = match site.x_frame_value.trim().to_uppercase().as_str() {
            "DENY" => "DENY",
            _      => "SAMEORIGIN",
        };
        if let Ok(hv) = HeaderValue::from_str(v) {
            headers.insert(HeaderName::from_static("x-frame-options"), hv);
        }
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
            // `append` for the same reason as the response side: a repeated
            // header must survive the crossing, not collapse to its last value.
            out.append(name, val);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn fwd(peer: &str, client: &str, host: Option<&str>, tls: bool) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(v) = host {
            h.insert(axum::http::header::HOST, HeaderValue::from_str(v).unwrap());
        }
        apply_forwarded_headers(
            &mut h, peer.parse().unwrap(), client.parse().unwrap(),
            host.map(|v| HeaderValue::from_str(v).unwrap()).as_ref(), tls,
        );
        h
    }

    fn got<'a>(h: &'a HeaderMap, k: &str) -> &'a str {
        h.get(k).and_then(|v| v.to_str().ok()).unwrap_or("")
    }

    #[test]
    fn tells_the_upstream_what_the_client_asked_for() {
        let h = fwd("203.0.113.9", "203.0.113.9", Some("cloud.example.com"), true);
        assert_eq!(got(&h, "x-forwarded-for"), "203.0.113.9");
        assert_eq!(got(&h, "x-real-ip"), "203.0.113.9");
        // The scheme the client used, not the scheme of the hop to the
        // upstream — this is what an application builds its own links from.
        assert_eq!(got(&h, "x-forwarded-proto"), "https");
        assert_eq!(got(&h, "x-forwarded-host"), "cloud.example.com");

        let h = fwd("203.0.113.9", "203.0.113.9", Some("cloud.example.com"), false);
        assert_eq!(got(&h, "x-forwarded-proto"), "http");
    }

    #[test]
    fn a_clients_own_forwarded_for_is_replaced_not_extended() {
        // The peer is the client, so any chain it sent is a claim this proxy
        // already declined to believe; passing it on would hand the upstream a
        // forgery.
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4, 5.6.7.8"));
        apply_forwarded_headers(
            &mut h, "203.0.113.9".parse().unwrap(), "203.0.113.9".parse().unwrap(), None, false,
        );
        assert_eq!(got(&h, "x-forwarded-for"), "203.0.113.9");
    }

    #[test]
    fn a_trusted_proxys_chain_is_preserved_and_extended() {
        // client != peer means the peer is trusted and its header was
        // honoured, so the upstream should see the whole path.
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.9"));
        apply_forwarded_headers(
            &mut h, "10.0.0.1".parse().unwrap(), "203.0.113.9".parse().unwrap(), None, true,
        );
        assert_eq!(got(&h, "x-forwarded-for"), "203.0.113.9, 10.0.0.1");
        assert_eq!(got(&h, "x-real-ip"), "203.0.113.9");
    }

    #[test]
    fn the_host_keeps_its_port() {
        // An application on a non-standard port needs it to build a working URL.
        let h = fwd("203.0.113.9", "203.0.113.9", Some("cloud.example.com:8443"), true);
        assert_eq!(got(&h, "x-forwarded-host"), "cloud.example.com:8443");
    }

    #[test]
    fn every_set_cookie_survives_the_crossing() {
        // The bug this exists to prevent: insert() in a copy loop keeps only
        // the last value of a repeated header. Nextcloud sets four cookies on
        // login, three were discarded, and the session never existed.
        let mut src = HeaderMap::new();
        for c in ["a=1", "b=2", "c=3", "d=4"] {
            src.append("set-cookie", HeaderValue::from_str(c).unwrap());
        }
        let mut dst = HeaderMap::new();
        copy_response_headers(&mut dst, &src);
        assert_eq!(dst.get_all("set-cookie").iter().count(), 4);
    }

    #[test]
    fn hop_by_hop_headers_are_still_dropped() {
        let mut src = HeaderMap::new();
        src.insert("connection", HeaderValue::from_static("keep-alive"));
        src.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        src.insert("content-type", HeaderValue::from_static("text/html"));
        let mut dst = HeaderMap::new();
        copy_response_headers(&mut dst, &src);
        assert!(dst.get("connection").is_none());
        assert!(dst.get("transfer-encoding").is_none());
        assert_eq!(got(&dst, "content-type"), "text/html");
    }

    #[test]
    fn repeated_request_headers_reach_the_upstream() {
        // The same mistake in the other direction: a client may send Cookie
        // more than once, and collapsing them loses part of the session.
        let mut h = HeaderMap::new();
        h.append("cookie", HeaderValue::from_static("a=1"));
        h.append("cookie", HeaderValue::from_static("b=2"));
        let out = to_reqwest_headers(&h);
        assert_eq!(out.get_all("cookie").iter().count(), 2);
    }

    #[test]
    fn recognises_a_websocket_upgrade() {
        assert!(is_upgrade(&hm(&[("connection", "Upgrade"), ("upgrade", "websocket")])));
        // Real clients send this with keep-alive alongside, and case varies.
        assert!(is_upgrade(&hm(&[
            ("connection", "keep-alive, Upgrade"), ("upgrade", "websocket"),
        ])));
        assert!(is_upgrade(&hm(&[("Connection", "upgrade"), ("Upgrade", "WebSocket")])));
        // Some send Connection as repeated headers rather than one list.
        assert!(is_upgrade(&hm(&[
            ("connection", "keep-alive"), ("connection", "Upgrade"), ("upgrade", "websocket"),
        ])));
    }

    #[test]
    fn one_header_alone_is_not_an_upgrade() {
        // Either half on its own is meaningless, and treating it as an upgrade
        // would divert an ordinary request into the tunnelling path.
        assert!(!is_upgrade(&hm(&[("upgrade", "websocket")])));
        assert!(!is_upgrade(&hm(&[("connection", "Upgrade")])));
        assert!(!is_upgrade(&hm(&[("connection", "keep-alive"), ("upgrade", "websocket")])));
        assert!(!is_upgrade(&HeaderMap::new()));
    }

    #[test]
    fn upgrade_is_not_matched_inside_another_token() {
        // Browsers send "upgrade-insecure-requests"; a substring match would
        // divert those requests into a tunnel they never asked for.
        assert!(!is_upgrade(&hm(&[
            ("connection", "upgrade-insecure-requests"), ("upgrade", "websocket"),
        ])));
    }
}
