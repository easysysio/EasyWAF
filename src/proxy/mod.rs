// =========================================================
// proxy/mod.rs — EasyWAF
// HTTP reverse proxy engine.
//
// Binds one listener per port the enabled sites use, at
// startup and again whenever a site is saved with a new one.
// A port no site uses any more stays bound until the next
// restart.
//
// Incoming requests are routed to a site by matching the
// Host: header against its server_name or one of its
// aliases, in a table of every site held in memory and
// reloaded when the configuration changes. Every request
// goes through the module pipeline before it is forwarded.
// =========================================================

use crate::challenge::{
    self, ChallengeStore, CLEARANCE_COOKIE, VERIFY_PATH,
};
use crate::modules::{
    traffic::{TrafficRecord, TrafficWriter},
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
use tokio::sync::mpsc;

// ─── Timeouts and limits ─────────────────────────────────

/// How long to wait for an upstream to accept a connection.
pub const UPSTREAM_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long an upstream connection may sit with nothing arriving before it is
/// abandoned. Idle, not total: it resets on every successful read.
///
/// Not a total timeout: a total one covers the whole response body, so it cuts
/// off every download and media stream that takes longer — after the
/// upstream's 200 has been sent, leaving the client a truncated file and a
/// success status. Ten minutes of silence is what Immich's documentation asks
/// of a reverse proxy, and an idle timeout only ever fires on a connection that
/// has actually stopped moving.
pub const UPSTREAM_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// How long the start of a request body — the part the rules inspect — may go
/// without another byte arriving. A client that sends its headers and then
/// stops holds a connection just as one that never finishes its headers does
/// (see `slow_clients`), so it is given the same time.
///
/// A limit on stalling, not on the whole read: how much is inspected is a
/// setting that can be megabytes, and a slow link sending steadily is not a
/// stalled one. The rest of a long upload streams with no such limit.
pub const BODY_STALL_TIMEOUT: std::time::Duration = crate::slow_clients::HEADER_READ_TIMEOUT;

/// How long a backend has to answer an upgrade handshake.
const UPGRADE_ANSWER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How much of a backend's refusal of an upgrade is relayed.
const UPGRADE_REFUSAL_BODY: usize = 64 * 1024;

/// How much of a request body the rules see unless Settings says otherwise.
/// Everything past it is forwarded to the upstream as it arrives, uninspected.
pub const DEFAULT_INSPECTION_LIMIT: usize = 128 * 1024;

/// The limit in force, set at startup from Settings and again on every save.
///
/// An atomic rather than a setting read per request: the point of the engine
/// release is that the request path stops reading the database.
static INSPECTION_LIMIT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_INSPECTION_LIMIT);

/// Change how many bytes of each request body the rules inspect. Never zero:
/// a limit of nothing would forward every body uninspected, which is not a
/// setting anybody means to choose.
pub fn set_inspection_limit(bytes: usize) {
    INSPECTION_LIMIT.store(bytes.max(1), std::sync::atomic::Ordering::Relaxed);
}

pub fn inspection_limit() -> usize {
    INSPECTION_LIMIT.load(std::sync::atomic::Ordering::Relaxed)
}

/// The start of a request body, read far enough to inspect, and whatever of the
/// body is still to come.
pub(crate) struct Prefix<S> {
    /// Every byte read so far: at least the limit, unless the body ended first.
    /// It can run past the limit by part of a chunk — those bytes are
    /// forwarded like the rest, just not inspected.
    pub head:     bytes::Bytes,
    /// Whether the body ended within what was read.
    pub complete: bool,
    /// The unread remainder, streamed on after `head`.
    pub rest:     S,
}

/// Why the start of a body could not be read.
#[derive(Debug)]
pub(crate) enum PrefixError<E> {
    /// The body itself failed: the client went away, or sent something invalid.
    Read(E),
    /// Nothing arrived for as long as a body may stall.
    Stalled,
}

/// Read a body until at least `limit` bytes are in hand or it ends, giving up
/// if it goes `stall` without a chunk arriving.
///
/// Reads whole chunks and never splits one, so `head` followed by `rest` is
/// always the body exactly as it arrived — nothing is dropped, duplicated or
/// reordered on its way to the upstream.
pub(crate) async fn read_prefix<S, E>(
    mut body: S,
    limit: usize,
    stall: std::time::Duration,
) -> Result<Prefix<S>, PrefixError<E>>
where
    S: futures::Stream<Item = Result<bytes::Bytes, E>> + Unpin,
{
    use futures::StreamExt;
    let mut head = bytes::BytesMut::new();
    while head.len() < limit {
        match tokio::time::timeout(stall, body.next()).await {
            Ok(Some(Ok(chunk))) => head.extend_from_slice(&chunk),
            Ok(Some(Err(e)))    => return Err(PrefixError::Read(e)),
            Ok(None)            => return Ok(Prefix { head: head.freeze(), complete: true, rest: body }),
            Err(_)              => return Err(PrefixError::Stalled),
        }
    }
    Ok(Prefix { head: head.freeze(), complete: false, rest: body })
}

/// Headers that describe one connection rather than the request, so they are
/// not passed from one side of the proxy to the other.
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
    /// The same client without certificate verification, for a site whose
    /// HTTPS backend has a certificate of its own and whose operator has said
    /// to reach it anyway.
    pub client_unverified: Client,
    /// Secret used to sign CAPTCHA clearance cookies.
    pub secret:     String,
    /// In-memory store of in-flight CAPTCHA challenges.
    pub challenges: ChallengeStore,
    /// True for the HTTPS listeners. The handler is shared between both kinds,
    /// and needs to know which it is on to avoid redirecting an HTTPS request
    /// to itself forever.
    pub is_tls:     bool,
    /// Where each request's traffic row is queued. Never awaited on the
    /// request path.
    pub traffic:    TrafficWriter,
    /// Where sign-ins to a site are recorded, with the management interface's
    /// own: they are authentication events, and belong in one trail.
    pub logger:     crate::logging::Logger,
}

// ─── SiteRow ─────────────────────────────────────────────

/// What the proxy needs of a site to serve a request, as the site table holds it.
struct SiteRow {
    id:             i64,
    name:           String,
    /// Every upstream this site can be served from, already parsed. One for
    /// almost every site, and then the choice below is that one.
    upstreams:      Vec<crate::upstream::Upstream>,
    tls_port:       Option<i64>,
    /// Whether the site has a certificate it can complete a handshake with.
    /// An HTTPS port without one refuses every client, so it is never a
    /// place to redirect anybody to.
    has_cert:       bool,
    tls_redirect:   bool,
    hsts:           bool,
    x_frame:        bool,
    x_frame_value:  String,
    x_content_type: bool,
    xss_protection: bool,
    /// Whether a client is pinned to the backend that first served it.
    affinity:       bool,
    /// The site's policy and its mode, which decide whether its IP lists apply.
    policy_id:      Option<i64>,
    rule_engine:    Option<String>,
    /// Whether the site's policy has Smart Protect switched on.
    smart_protect:  bool,
    /// Whether an HTTPS backend's certificate goes unverified.
    backend_tls_insecure: bool,
    /// What the site asks of its visitors, when it asks them to sign in.
    auth:           Option<crate::gateway::SiteAuth>,
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

    let listener = match addr.parse::<SocketAddr>().map_err(std::io::Error::other).and_then(crate::tls::bind_listener) {
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

    let server = match axum_server::from_tcp(listener) {
        Ok(s) => crate::slow_clients::limit(s),
        Err(e) => {
            tracing::error!(port, "Cannot serve on the bound port: {}", e);
            return;
        }
    };

    if let Err(e) = server.serve(app).await {
        tracing::error!(port, "Proxy server error: {}", e);
    }
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
        Ok(s) => crate::slow_clients::limit(s),
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

/// Headers by which a request describes its own origin, removed unless a
/// trusted proxy sent them. See `apply_forwarded_headers`.
const CLIENT_CLAIMS: &[&str] = &[
    "forwarded",
    "x-forwarded-port",
    "x-forwarded-scheme",
    "x-forwarded-ssl",
    "x-client-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "x-original-url",
    "x-rewrite-url",
];

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
    https: bool,
) {
    // The other ways of saying who the client is or what it asked for, which
    // some application or framework reads in preference to the headers set
    // below. From a trusted proxy they are that proxy's report. From anyone
    // else they are a client describing itself — or, with X-Original-URL,
    // asking the application for a different path than the one the rules
    // read — and are not passed on.
    if !crate::forwarded::is_trusted_proxy(peer) {
        for claim in CLIENT_CLAIMS {
            headers.remove(*claim);
        }
    }

    // `client` differs from `peer` only when the peer is a proxy we trust and
    // its X-Forwarded-For was honoured. In that case the chain it sent is
    // worth passing on, with this hop appended.
    //
    // Otherwise the header is replaced outright rather than appended to. A
    // client that sends its own X-Forwarded-For is claiming an address, and
    // forwarding that claim would hand the upstream a forgery this proxy
    // already decided not to believe.
    let xff = match crate::forwarded::forwarded_for(headers) {
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
    set(headers, "x-forwarded-proto", if https { "https".into() } else { "http".into() });

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

/// The headers an upgrade handshake is sent upstream with.
///
/// What every other request gets — the client's headers without the hop-by-hop
/// ones, and the forwarding headers that say who the client is — except that
/// `Connection` and `Upgrade` are kept, because they are the request. The
/// browser's `Host` goes too: an application that compares `Origin` with `Host`
/// refuses a handshake whose `Host` names the backend.
fn upgrade_headers(
    headers: &HeaderMap,
    peer: std::net::IpAddr,
    client: std::net::IpAddr,
    https: bool,
) -> HeaderMap {
    let mut out = headers.clone();
    for h in HOP_HEADERS {
        if *h != "connection" && *h != "upgrade" {
            out.remove(*h);
        }
    }
    apply_forwarded_headers(&mut out, peer, client, headers.get(axum::http::header::HOST), https);
    out
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

    let stream = tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, tokio::net::TcpStream::connect((host, port)))
        .await
        .map_err(|_| format!("connecting to {host}:{port}: timed out"))?
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
        // Prepared by `upgrade_headers`: the client's own, with the forwarding
        // headers every request gets and the two hop-by-hop headers an upgrade
        // needs. `append`, so a repeated header keeps every value.
        for (k, v) in headers {
            hs.append(k, v.clone());
        }
        // The client's Host, as every other request carries. Only a request
        // that came without one is given the upstream's.
        if !hs.contains_key(hyper::header::HOST)
            && let Ok(h) = hyper::header::HeaderValue::from_str(&format!("{host}:{port}"))
        {
            hs.insert(hyper::header::HOST, h);
        }
    }

    let req = builder
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .map_err(|e| format!("building upstream request: {e}"))?;

    // A handshake is answered at once or not at all, so it is given the time
    // a connection is, not the time a slow page is.
    let upstream_resp = tokio::time::timeout(UPGRADE_ANSWER_TIMEOUT, sender.send_request(req))
        .await
        .map_err(|_| "upstream request: no answer to the handshake".to_string())?
        .map_err(|e| format!("upstream request: {e}"))?;

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    if status != StatusCode::SWITCHING_PROTOCOLS {
        // The upstream declined to upgrade. Pass its answer back, body and
        // all: it is a normal response — usually a 401 or 403 saying why — and
        // the client will deal with it. The body is read before the connection
        // is let go, and only so much of it: a refusal is a line or two.
        let body = http_body_util::BodyExt::collect(
            http_body_util::Limited::new(upstream_resp.into_body(), UPGRADE_REFUSAL_BODY),
        )
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
        conn_task.abort();
        let mut resp = Response::builder().status(status);
        if let Some(hs) = resp.headers_mut() {
            copy_response_headers(hs, &resp_headers);
            // The length is set from what is sent. The upstream's own would
            // promise bytes this response may not carry.
            hs.remove(axum::http::header::CONTENT_LENGTH);
        }
        return resp
            .body(Body::from(body))
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
            hs.append(k, v.clone());
        }
    }
    resp.body(Body::empty()).map_err(|e| format!("response: {e}"))
}

// ─── Traffic rows ────────────────────────────────────────

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

/// What every traffic row for one request shares. Each way a request can end
/// records this plus an `Outcome`, so the rows cannot disagree about the
/// request itself.
struct Visit {
    site_id:    i64,
    site_name:  String,
    client_ip:  String,
    method:     String,
    host:       String,
    path:       String,
    query:      Option<String>,
    country:    Option<String>,
    started_at: Instant,
    /// Who the sign-in gateway found the visitor to be, once it has.
    user:       Option<String>,
}

/// How a request ended, which is the rest of its row. `Default` is an allowed
/// request that matched nothing and reached no backend; each path sets what
/// differs.
#[derive(Default)]
struct Outcome {
    status:    i64,
    blocked:   bool,
    reason:    Option<String>,
    score:     Option<i64>,
    hits:      Option<String>,
    detection: Option<String>,
    upstream:  Option<String>,
}

impl Outcome {
    /// A request the rules let through and EasyWAF then answered itself — the
    /// sign-in page, a redirect after signing in — with whatever the WAF found
    /// on it. `why` is the row's reason, and begins `sign-in:`.
    fn answered_here(
        found: &Option<(i64, Option<String>, String, String)>,
        status: i64,
        why: &str,
    ) -> Self {
        let (score, hits, detection, _) = split_detection(found.clone());
        Outcome { status, reason: Some(why.to_string()), score, hits, detection, ..Outcome::default() }
    }

    /// A request let through to a backend, with whatever the WAF found on it.
    fn forwarded(
        found: &Option<(i64, Option<String>, String, String)>,
        status: i64,
        upstream: &str,
    ) -> Self {
        let (score, hits, detection, reason) = split_detection(found.clone());
        Outcome { status, reason, score, hits, detection, upstream: Some(upstream.to_string()), ..Outcome::default() }
    }
}

impl Visit {
    /// Queue this request's row. Timed now, so call it once the outcome is
    /// known — before the body streams, which is how it has always been timed.
    fn record(&self, traffic: &TrafficWriter, o: Outcome) {
        traffic.record(TrafficRecord {
            site_id:       self.site_id,
            site_name:     self.site_name.clone(),
            client_ip:     self.client_ip.clone(),
            method:        self.method.clone(),
            host:          self.host.clone(),
            path:          self.path.clone(),
            query:         self.query.clone(),
            status_code:   o.status,
            response_ms:   self.started_at.elapsed().as_millis() as i64,
            blocked:       o.blocked,
            block_reason:  o.reason,
            waf_score:     o.score,
            matched_rules: o.hits,
            country:       self.country.clone(),
            detection:     o.detection,
            upstream:      o.upstream,
            user:          self.user.clone(),
        });
    }
}

// ─── handle_request ──────────────────────────────────────

/// Main proxy handler — called for every incoming request on every port.
///
/// Reads as the list of what happens to a request, in order. Each step is a
/// function below, and the first one that answers ends the request:
///
///   1. `request_host`     — the Host header.
///   2. `acme_answer`      — a Let's Encrypt validation, before anything else.
///   3. `find_site`        — the site, from the site table.
///   4. `https_redirect`   — the redirect to HTTPS, when the site asks for one.
///   5. `Incoming::take`   — the request taken apart, and who the client is.
///   6. `refused_by_lists` — the site's IP lists, then
///      `refused_by_smart_protect` — an address its rules keep refusing.
///   7. `read_body_start`  — as much of the body as the rules inspect.
///   8. `handle_verify`    — a CAPTCHA answer, handled before the rules.
///   9. `judge`            — the module pipeline, and what the lists add to it.
///  10. `challenge`        — a CAPTCHA, unless the visitor has answered one.
///  11. `forward`          — the upstream, and its response streamed back.
///
/// Whichever step answers, the site's security headers are added (from step 3
/// on) and the request's traffic row is queued (from step 6 on).
async fn handle_request(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<ProxyState>,
    req: axum::extract::Request,
) -> Response<Body> {
    let started_at = Instant::now();

    let Some(host) = request_host(&req) else {
        return error_response(StatusCode::BAD_REQUEST, "Missing Host header");
    };
    if let Some(answer) = acme_answer(&state, &host, &req) {
        return answer;
    }
    let site = match find_site(&state, &host).await {
        Ok(site)  => site,
        Err(page) => return page,
    };

    // Everything from here is this site's response, whichever step produces it
    // — the upstream's, a block, a challenge, a gateway error — and carries the
    // headers the site asked for: a visitor whose first response is one of
    // EasyWAF's own pages must still receive the HSTS the site promises.
    // The scheme the client used, which is this listener's unless a trusted
    // proxy in front terminated TLS and said so.
    let https = crate::forwarded::client_used_https(peer.ip(), req.headers(), state.is_tls);
    let security = SecurityHeaders::of(&site, https);
    let mut response = serve_site(&state, peer, &site, host, req, started_at, https).await;
    security.apply(response.headers_mut());
    response
}

/// Steps 4 to 11, for a request whose site is known.
async fn serve_site(
    state:      &ProxyState,
    peer:       SocketAddr,
    site:       &SiteRow,
    host:       String,
    req:        axum::extract::Request,
    started_at: Instant,
    https:      bool,
) -> Response<Body> {
    if let Some(redirect) = https_redirect(site, &host, &req, https) {
        return redirect;
    }

    let (mut incoming, body, on_upgrade) = Incoming::take(req, peer, https);
    let mut visit = Visit::of(site, &incoming, host, started_at);

    let lists = ListCheck::of(state, site, incoming.client_ip).await;
    if let Some(refusal) = refused_by_lists(state, &visit, &lists) {
        return refusal;
    }

    let watch = Watch::of(site, &lists, incoming.client_ip);
    if let Some(refusal) = refused_by_smart_protect(state, &visit, &watch) {
        return refusal;
    }

    let body = match read_body_start(body).await {
        Ok(body)  => body,
        Err(resp) => return resp,
    };

    // A CAPTCHA answer. Always a tiny form this server rendered, so it is
    // answered only when it arrived whole: a submission larger than the
    // inspection limit is not one this server sent.
    if incoming.method == Method::POST && incoming.path == VERIFY_PATH {
        if !body.start.complete {
            return error_response(StatusCode::PAYLOAD_TOO_LARGE, "Verification submission too large");
        }
        return handle_verify(state, &incoming.client_ip.to_string(), &body.start.head, incoming.https);
    }

    // The session a visitor already holds, on a site that asks for a sign-in.
    // Read before the rules run because it bears on them: somebody who has
    // signed in has proved more than a CAPTCHA asks.
    let session = site.auth.as_ref().and_then(|ask| signed_in(state, site, ask, &incoming));

    // Whether the visitor already holds a valid challenge clearance cookie.
    let cleared = session.is_some()
        || clearance_ok(state, &incoming.headers, &incoming.client_ip.to_string());

    // A sign-in is posted as a password, and a password is exactly what an
    // injection rule matches: quotes, semicolons, backslashes. A false positive
    // there would not block a request, it would lock every user out — and the
    // person who could fix it could not sign in to do so. The form's body is
    // the one thing the rules are not shown; its path and headers still are.
    let signing_in = site.auth.is_some()
        && incoming.method == Method::POST
        && incoming.path == crate::gateway::LOGIN_PATH;
    let inspected = if signing_in { bytes::Bytes::new() } else { body.inspected.clone() };

    let verdict = judge(state, site, &incoming, inspected, &lists, &watch, cleared).await;

    let findings = match verdict {
        PipelineVerdict::Block { reason, status, findings } => {
            if findings.offence {
                watch.count(incoming.client_ip, &reason);
            }
            // The request was refused; `blocked` says so. `detection` is for
            // what would have happened and did not.
            visit.record(&state.traffic, Outcome {
                status:  status.as_u16() as i64,
                blocked: true,
                reason:  Some(reason),
                score:   Some(findings.score),
                hits:    findings.hits_json(),
                ..Outcome::default()
            });
            return blocked_response(status, &visit.client_ip, Refusal::Rules);
        }
        PipelineVerdict::Challenge { reason, findings } if !cleared => {
            return challenge(state, &visit, &incoming, &reason, &findings);
        }
        // A visitor who has answered a challenge is forwarded. It was
        // challenged, and they answered; that is not a detection to report
        // again.
        PipelineVerdict::Challenge { .. } => None,
        PipelineVerdict::Allow { alerts, findings } => {
            // What a DetectionOnly policy would have refused counts as well, so
            // Smart Protect can be trialled with the policy.
            if findings.offence {
                watch.count(incoming.client_ip, alerts.first().map_or("", |a| a.reason.as_str()));
            }
            detection_of(&alerts, &findings)
        }
    };

    // The gateway, last: after the rules, so an attack on a protected site is
    // recorded as what it was and not as "sent to a sign-in page", and
    // immediately before the application, which is what it guards.
    let mut renewed = None;
    if let Some(ask) = &site.auth {
        // What was posted, when all of it has arrived — which a sign-in form
        // always has.
        let posted = body.start.complete.then_some(&body.start.head);
        match gate(state, site, ask, &mut incoming, &mut visit, session, posted, &findings).await {
            Gate::Answered(response) => return response,
            Gate::Through(cookie)    => renewed = cookie,
        }
    }

    let mut response = forward(state, site, &incoming, &visit, &findings, body.start, on_upgrade).await;
    // A session in use is given a fresh cookie now and then, which is how its
    // idle timeout slides without anything being written down.
    if let Some(cookie) = renewed.and_then(|c| HeaderValue::from_str(&c).ok()) {
        response.headers_mut().append(axum::http::header::SET_COOKIE, cookie);
    }
    response
}

// ─── Steps 1 to 4 ────────────────────────────────────────

/// Step 1. The hostname the request is for, lowercase and without its port —
/// "example.com:8081" routes as "example.com", whichever port the client
/// connected on. `None` when there is no Host header to route by.
fn request_host(req: &axum::extract::Request) -> Option<String> {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        // "example.com." is the same name written in full, and a site is
        // stored without the dot.
        .trim_end_matches('.')
        .to_lowercase();
    (!host.is_empty()).then_some(host)
}

/// Step 2. The answer to a Let's Encrypt HTTP-01 validation, if this is one.
///
/// Answered before everything else, and on purpose. Before the site lookup, so
/// it works for a site that is disabled or not configured yet. Before the HTTPS
/// redirect, because the CA follows redirects and a site with a broken
/// certificate would bounce the validator into a connection it cannot complete
/// — the exact situation someone is trying to fix. Before the pipeline, because
/// a token is opaque base64url and nothing should be able to score or block
/// one: a renewal that failed because a scanner rule matched its challenge
/// token would be a genuinely awful outage to diagnose.
///
/// Only on the plain-HTTP listener: HTTP-01 validation always arrives on port
/// 80, so answering on the TLS one would serve a token to something that is not
/// the CA. A challenge path with no answer published falls through to be
/// handled as any other request would be, rather than confirming the path
/// exists.
fn acme_answer(state: &ProxyState, host: &str, req: &axum::extract::Request) -> Option<Response<Body>> {
    if state.is_tls {
        return None;
    }
    let token = crate::acme::token_from_path(req.uri().path())?;
    let answer = crate::acme::answer(token)?;
    tracing::info!(host = %host, "Answered an ACME HTTP-01 challenge");
    Some(
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(Body::from(answer))
            .unwrap_or_else(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "response")),
    )
}

/// Step 3. The enabled site this hostname belongs to, or the page to answer
/// with instead.
///
/// A site that exists but is switched off is a different situation from a
/// hostname nobody configured: the first is the operator taking it down on
/// purpose, and its visitors deserve to be told that rather than being shown a
/// 404 that reads like a mistake.
async fn find_site(state: &ProxyState, host: &str) -> Result<Arc<SiteRow>, Response<Body>> {
    let table = site_table(&state.db).await;
    if let Some(site) = table.enabled.get(host) {
        return Ok(site.clone());
    }
    if table.disabled.contains(host) {
        let message = crate::routes::settings::get_maintenance_message(&state.db).await;
        tracing::debug!(host = %host, "site is disabled — serving maintenance page");
        return Err(maintenance_response(&message));
    }
    tracing::debug!(host = %host, "no site matched");
    Err(error_response(StatusCode::NOT_FOUND, "No site configured for this host"))
}

/// Step 4. The redirect to HTTPS, when the site asks for one and it can work.
///
/// Only for a client that came over plain HTTP — which one behind a proxy that
/// terminates TLS did not, though it arrives on a plain listener, and
/// redirecting it would loop — and only when there is somewhere to send them:
/// redirecting to a TLS port that is not bound would take the site off the air
/// instead of securing it. Done before any inspection, since the request is not
/// being served here either way.
///
/// "Somewhere" includes a certificate. An HTTPS port with none refuses every
/// handshake, so a redirect to it would make the whole site unreachable. The
/// form refuses to save a site that way, but one can still arrive there — a
/// certificate requested from Let's Encrypt while creating the site, and
/// refused — and serving plain HTTP is never worse than sending visitors to a
/// port that cannot answer.
fn https_redirect(
    site:  &SiteRow,
    host:  &str,
    req:   &axum::extract::Request,
    https: bool,
) -> Option<Response<Body>> {
    if https || !site.tls_redirect || !site.has_cert {
        return None;
    }
    let tls_port = site.tls_port?;
    let path = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let target = if tls_port == 443 {
        format!("https://{host}{path}")
    } else {
        format!("https://{host}:{tls_port}{path}")
    };
    Some(
        Response::builder()
            .status(StatusCode::TEMPORARY_REDIRECT)
            .header("location", target)
            .body(Body::empty())
            .unwrap_or_else(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "Redirect build error")),
    )
}

// ─── Step 5: the request, taken apart ────────────────────

/// What the later steps read about a request, taken once.
struct Incoming {
    /// The address the connection came from.
    peer:      std::net::IpAddr,
    /// The client: the peer, unless it is a trusted proxy, in which case the
    /// client that proxy reported. Resolved once, so everything downstream —
    /// country rules, CAPTCHA clearance, the traffic log — agrees on who the
    /// client is.
    client_ip: std::net::IpAddr,
    method:    Method,
    path:      String,
    query:     Option<String>,
    headers:   HeaderMap,
    /// Whether the client used HTTPS, on this listener or at a trusted proxy
    /// in front of it. What the backend is told, and whether cookies set here
    /// are marked Secure.
    https:     bool,
}

/// The request body, before any of it is read.
type BodyStream = std::pin::Pin<Box<axum::body::BodyDataStream>>;

impl Incoming {
    /// Step 5. Take the request apart: what later steps read, the body still
    /// to be read, and the handle that lets the connection be upgraded — taken
    /// first, because it lives in the request's extensions and goes with them.
    fn take(
        mut req: axum::extract::Request,
        peer: SocketAddr,
        https: bool,
    ) -> (Self, BodyStream, Option<hyper::upgrade::OnUpgrade>) {
        let on_upgrade = req.extensions_mut().remove::<hyper::upgrade::OnUpgrade>();
        let (parts, body) = req.into_parts();
        let client_ip = crate::forwarded::client_ip(peer.ip(), &parts.headers);
        let incoming = Incoming {
            peer: peer.ip(),
            client_ip,
            method: parts.method,
            path: parts.uri.path().to_string(),
            query: parts.uri.query().map(str::to_string),
            headers: parts.headers,
            https,
        };
        (incoming, Box::pin(body.into_data_stream()), on_upgrade)
    }

    /// The path with its query string, as the request line had them.
    fn path_and_query(&self) -> String {
        match &self.query {
            Some(q) => format!("{}?{}", self.path, q),
            None    => self.path.clone(),
        }
    }
}

impl Visit {
    /// What every traffic row for this request shares. Whichever way it ends —
    /// refused by a list, blocked, challenged, or forwarded — its row is this
    /// plus how it ended.
    fn of(site: &SiteRow, incoming: &Incoming, host: String, started_at: Instant) -> Self {
        Visit {
            site_id:    site.id,
            site_name:  site.name.clone(),
            client_ip:  incoming.client_ip.to_string(),
            method:     incoming.method.to_string(),
            host,
            path:       incoming.path.clone(),
            query:      incoming.query.clone(),
            // Looked up once: the traffic row records it, and the country
            // rules in the pipeline read the same lookup.
            country:    crate::geo::country_of(incoming.client_ip),
            started_at,
            user:       None,
        }
    }
}

// ─── Step 6: the IP lists ────────────────────────────────

/// What the site's IP lists say about this client.
struct ListCheck {
    listed:         Option<crate::iplist::Listed>,
    /// The site's policy records what its lists would do rather than doing it.
    detection_only: bool,
}

impl ListCheck {
    /// Look the client up in the site's policy's lists.
    ///
    /// The lists are the policy's, and follow its mode: Off ignores them with
    /// the rest of the policy, DetectionOnly records what they would have done,
    /// and anything else enforces them. A site with no policy has none.
    async fn of(state: &ProxyState, site: &SiteRow, client_ip: std::net::IpAddr) -> Self {
        let listed = match (site.policy_id, site.rule_engine.as_deref()) {
            (Some(policy), Some(mode)) if mode != "Off" => {
                crate::iplist::check(&state.db, policy, client_ip).await
            }
            _ => None,
        };
        ListCheck {
            listed,
            detection_only: site.rule_engine.as_deref() == Some("DetectionOnly"),
        }
    }
}

/// Step 6. The refusal, when a list the policy enforces blocks this client.
///
/// Before the body is read, so a refused address costs no reads at all. Before
/// the pipeline, and that is the whole design rather than an optimisation: a
/// site with no policy runs no pipeline at all, and "refuse this client" has to
/// work there too. A published list that blocks is refused here as well, and
/// the row names the list: a refusal nobody can explain is the one people
/// switch the whole feature off over.
fn refused_by_lists(state: &ProxyState, visit: &Visit, lists: &ListCheck) -> Option<Response<Body>> {
    let reason = match list_verdict(&lists.listed) {
        Some((why, crate::modules::Detection::WouldBlock)) if !lists.detection_only => why,
        _ => return None,
    };
    // No rule fired and no score accumulated: the address was refused for
    // being itself. Recording a score of zero would read as a WAF decision
    // that never happened.
    visit.record(&state.traffic, Outcome {
        status:  403,
        blocked: true,
        reason:  Some(reason),
        ..Outcome::default()
    });
    Some(blocked_response(StatusCode::FORBIDDEN, &visit.client_ip, Refusal::Rules))
}

// ─── Smart Protect ───────────────────────────────────────

/// What Smart Protect has to do with this request.
struct Watch {
    /// The policy whose refusals are being counted, when Smart Protect applies
    /// to this request at all.
    policy:         Option<i64>,
    /// The block in force on this client, if there is one.
    block:          Option<crate::smart_protect::Block>,
    /// The policy records what it would do rather than doing it.
    detection_only: bool,
}

impl Watch {
    /// Whether Smart Protect applies to this request, and the block on its
    /// client if so.
    ///
    /// It follows the policy: switched on there, and not while the policy is
    /// Off. Two clients are never counted or blocked whatever they do:
    ///
    ///   * one on the policy's allow list — otherwise the first thing Smart
    ///     Protect does in an incident is refuse the monitoring, the office,
    ///     and whoever is trying to fix it;
    ///   * a trusted proxy — if forwarded headers are misconfigured, every
    ///     request appears to come from its address, and blocking that would
    ///     refuse every client behind it at once.
    fn of(site: &SiteRow, lists: &ListCheck, client_ip: std::net::IpAddr) -> Self {
        let applies = site.smart_protect
            && site.rule_engine.as_deref().is_some_and(|mode| mode != "Off")
            && lists.listed != Some(crate::iplist::Listed::Allowed)
            && !crate::forwarded::is_trusted_proxy(client_ip);
        let policy = site.policy_id.filter(|_| applies);
        Watch {
            policy,
            block: policy.and_then(|p| crate::smart_protect::blocked(p, client_ip)),
            detection_only: lists.detection_only,
        }
    }

    /// Why this request would be refused, when the policy is only watching.
    fn would_refuse(&self) -> Option<String> {
        self.block.as_ref().filter(|_| self.detection_only).map(|b| b.refusal())
    }

    /// Count a refusal by the rules against this client. One made while the
    /// client is already blocked is not counted, so a block lasts as long as it
    /// says and no longer.
    fn count(&self, client_ip: std::net::IpAddr, reason: &str) {
        let Some(policy) = self.policy else { return };
        if self.block.is_some() {
            return;
        }
        if let Some(b) = crate::smart_protect::offence(policy, client_ip, reason) {
            tracing::info!(
                client = %crate::smart_protect::unit_label(b.unit),
                policy,
                "Smart Protect: blocked for {} after {} refusals within {}",
                crate::smart_protect::span(b.until.saturating_duration_since(std::time::Instant::now())),
                b.refusals,
                crate::smart_protect::span(b.window),
            );
        }
    }
}

/// The refusal, when Smart Protect has this client blocked and the policy
/// enforces. Before the body is read, like a list refusal, so a blocked
/// address costs no reads.
fn refused_by_smart_protect(state: &ProxyState, visit: &Visit, watch: &Watch) -> Option<Response<Body>> {
    let block = watch.block.as_ref().filter(|_| !watch.detection_only)?;
    visit.record(&state.traffic, Outcome {
        status:  403,
        blocked: true,
        reason:  Some(block.refusal()),
        ..Outcome::default()
    });
    Some(blocked_response(StatusCode::FORBIDDEN, &visit.client_ip, Refusal::Repeated))
}

// ─── Step 7: the start of the body ───────────────────────

/// The start of the body, and the part of it the rules see.
struct BodyStart {
    /// What has been read, and the rest still to come.
    start:     Prefix<BodyStream>,
    /// The first `inspection_limit()` bytes of it: `start.head` can run past
    /// the limit by part of a chunk, and those bytes are forwarded but not
    /// inspected.
    inspected: bytes::Bytes,
}

/// Step 7. Read as much of the body as the rules inspect.
///
/// Only the first `inspection_limit()` bytes are read before the verdict, never
/// the whole body: the rules decode a body several ways, so holding an upload
/// whole costs several times its size, and a few concurrent ones would exhaust
/// memory. Attacks sit at the start of a body — the tail of a video does not
/// contain SQL injection. The rest streams to the upstream as it arrives, so an
/// upload of any size costs about the limit rather than its own size. The
/// trade-off is
/// stated in Settings, where the limit is set: bytes past it are forwarded
/// uninspected, so a payload padded past it is not seen.
async fn read_body_start(body: BodyStream) -> Result<BodyStart, Response<Body>> {
    let limit = inspection_limit();
    let start = match read_prefix(body, limit, BODY_STALL_TIMEOUT).await {
        Ok(start) => start,
        Err(PrefixError::Read(_)) =>
            return Err(error_response(StatusCode::BAD_REQUEST, "Failed to read request body")),
        Err(PrefixError::Stalled) =>
            return Err(error_response(StatusCode::REQUEST_TIMEOUT, "The request body stopped arriving")),
    };
    let inspected = if start.head.len() > limit {
        start.head.slice(..limit)
    } else {
        start.head.clone()
    };
    Ok(BodyStart { start, inspected })
}

// ─── Steps 9 and 10: the verdict ─────────────────────────

/// Step 9. What the modules decide, and what the IP lists add to it.
async fn judge(
    state:     &ProxyState,
    site:      &SiteRow,
    incoming:  &Incoming,
    inspected: bytes::Bytes,
    lists:     &ListCheck,
    watch:     &Watch,
    cleared:   bool,
) -> PipelineVerdict {
    // An allowed address skips the pipeline rather than being waved through
    // it. An allowed address has to skip GeoIP, the WAF and the challenge
    // alike, and making that a verdict every module must remember to honour
    // would be one forgotten check away from being false. Never entering the
    // pipeline is true regardless of which modules exist now or are added
    // later.
    let verdict = if lists.listed == Some(crate::iplist::Listed::Allowed) {
        PipelineVerdict::Allow {
            alerts:   Vec::new(),
            findings: crate::modules::Findings::default(),
        }
    } else {
        state.pipeline.run(&RequestContext {
            site_id:   site.id,
            site_name: site.name.clone(),
            client_ip: incoming.client_ip,
            path:      incoming.path.clone(),
            query:     incoming.query.clone(),
            headers:   incoming.headers.clone(),
            body:      inspected,
        }).await
    };

    // A published list whose response is a challenge. Applied to what the
    // pipeline decided rather than before it, so a request the rules would
    // block is still blocked and one they would challenge is challenged once.
    //
    // Not for a visitor who has already answered a challenge: they have shown
    // what the list was asking, and turning their request into a challenge
    // they skip would also drop what a DetectionOnly policy found on it.
    let verdict = match (verdict, &lists.listed) {
        (PipelineVerdict::Allow { findings, .. }, Some(crate::iplist::Listed::Published(hit)))
            if hit.response == crate::iplist::Response::Challenge && !cleared && !lists.detection_only =>
        {
            PipelineVerdict::Challenge {
                reason: format!("Client address is on the published list \"{}\"", hit.name),
                findings,
            }
        }
        (verdict, _) => verdict,
    };

    // In DetectionOnly a list refuses and challenges nobody. It records what it
    // would have done, beside whatever the rules found, the way the rules
    // record theirs — so a policy can be trialled with its lists as well.
    let verdict = match (verdict, list_verdict(&lists.listed).filter(|_| lists.detection_only)) {
        (PipelineVerdict::Allow { mut alerts, mut findings }, Some((why, would))) => {
            findings.detection = Some(stronger(findings.detection, would));
            alerts.push(crate::modules::Alert { reason: why });
            PipelineVerdict::Allow { alerts, findings }
        }
        (verdict, _) => verdict,
    };

    // The same for a Smart Protect block the policy is only watching: the
    // request is served, and its row says it would have been refused.
    match (verdict, watch.would_refuse()) {
        (PipelineVerdict::Allow { mut alerts, mut findings }, Some(why)) => {
            findings.detection =
                Some(stronger(findings.detection, crate::modules::Detection::WouldBlock));
            alerts.push(crate::modules::Alert { reason: why });
            PipelineVerdict::Allow { alerts, findings }
        }
        (verdict, _) => verdict,
    }
}

/// Step 10. Show a CAPTCHA, and remember where the visitor was going.
fn challenge(
    state:    &ProxyState,
    visit:    &Visit,
    incoming: &Incoming,
    reason:   &str,
    findings: &crate::modules::Findings,
) -> Response<Body> {
    let issued = state.challenges.issue(&incoming.path_and_query(), &incoming.client_ip.to_string());

    // Attributed like a block: a challenged request is worth knowing the rules
    // of for the same reason. Not a detection — it was challenged, not merely
    // detected.
    visit.record(&state.traffic, Outcome {
        status: if issued.is_some() { 200 } else { 429 },
        reason: Some(format!("challenge: {}", reason)),
        score:  Some(findings.score),
        hits:   findings.hits_json(),
        ..Outcome::default()
    });
    match issued {
        Some((id, data_uri)) => challenge_response(&id, &data_uri, false),
        None                 => too_many_challenges(),
    }
}

/// What the rules found on a request that is being let through, for its
/// traffic row: score, rules, detection and the alerts' reasons.
///
/// Recorded, not dropped: it is what DetectionOnly exists to report, and in an
/// enforcing policy it is every near-miss.
fn detection_of(
    alerts:   &[crate::modules::Alert],
    findings: &crate::modules::Findings,
) -> Option<(i64, Option<String>, String, String)> {
    findings.detection.map(|d| {
        let why = alerts.iter().map(|a| a.reason.as_str()).collect::<Vec<_>>().join("; ");
        (findings.score, findings.hits_json(), d.as_str().to_string(), why)
    })
}

// ─── The sign-in gateway ─────────────────────────────────

/// The session this request carries, if the site would still honour it.
///
/// Over HTTPS only. The cookie is marked Secure and a browser will not send it
/// in the clear, so one arriving that way was put there by hand.
fn signed_in(
    state:    &ProxyState,
    site:     &SiteRow,
    ask:      &crate::gateway::SiteAuth,
    incoming: &Incoming,
) -> Option<crate::gateway::Session> {
    if !incoming.https {
        return None;
    }
    let cookie = cookie_value(&incoming.headers, crate::gateway::SESSION_COOKIE)?;
    crate::gateway::read(&state.secret, site.id, &ask.realm, &cookie, chrono::Utc::now().timestamp())
}

/// What the gateway did with a request.
enum Gate {
    /// It answered: the sign-in page, a redirect after signing in or out, a
    /// refusal.
    Answered(Response<Body>),
    /// The request goes on to the application. Holds a renewed session cookie
    /// when the visitor is due one.
    Through(Option<String>),
}

/// The gateway's part in a request the rules have let through.
///
/// In order: signing out and signing in, which are the gateway's own paths;
/// then, for everything else, the headers a client must not be able to send
/// are removed; then a path that needs a sign-in is let through for a visitor
/// who has one, or who sends a good Basic credential where that is allowed —
/// and anybody else is shown the form.
#[allow(clippy::too_many_arguments)]
async fn gate(
    state:    &ProxyState,
    site:     &SiteRow,
    ask:      &crate::gateway::SiteAuth,
    incoming: &mut Incoming,
    visit:    &mut Visit,
    session:  Option<crate::gateway::Session>,
    posted:   Option<&bytes::Bytes>,
    detected: &Option<(i64, Option<String>, String, String)>,
) -> Gate {
    use crate::gateway::{self, Notice};

    let answered = |visit: &Visit, status: StatusCode, why: &str, response: Response<Body>| {
        visit.record(&state.traffic, Outcome::answered_here(detected, status.as_u16() as i64, why));
        Gate::Answered(response)
    };

    if incoming.path == gateway::LOGOUT_PATH {
        if let Some(s) = &session {
            visit.user = Some(s.who.subject.clone());
            gateway_audit(state, site, ask, &s.who.subject, incoming.client_ip, "signed-out");
        }
        let page = sign_in_page(&visit.host, "/", Notice::SignedOut, StatusCode::OK, Some(gateway::clear_cookie()));
        return answered(visit, StatusCode::OK, "sign-in: signed out", page);
    }

    if incoming.path == gateway::LOGIN_PATH {
        if incoming.method == Method::POST {
            return sign_in(state, site, ask, incoming, visit, posted, detected).await;
        }
        // Somebody opened the form's address directly. Signed in already, they
        // are sent to the site; otherwise it is the form.
        let response = match &session {
            Some(_) => redirect_to("/", None),
            None    => sign_in_page(&visit.host, "/", Notice::None, StatusCode::OK, None),
        };
        return answered(visit, response.status(), "sign-in: form", response);
    }

    // From here the request may reach the application, so what only the
    // gateway may say is taken off it first — on every path of the site, asked
    // or not.
    ask.strip(&mut incoming.headers);

    // Somebody signed in is named to the application wherever on the site
    // they are, which lets a page that needs no sign-in still greet them.
    if let Some(s) = session {
        ask.announce(&mut incoming.headers, &s.who);
        visit.user = Some(s.who.subject.clone());
        let renewed = s.refresh.then(|| {
            let now = chrono::Utc::now().timestamp();
            gateway::set_cookie(
                &gateway::mint(&state.secret, site.id, &ask.realm, &s.who, s.user_epoch, s.issued, now),
                &ask.realm,
            )
        });
        return Gate::Through(renewed);
    }

    if !ask.needs_sign_in(&incoming.path) {
        return Gate::Through(None);
    }

    // A name and password are never asked for, or accepted, in the clear.
    if !incoming.https {
        let response = match (site.tls_port, site.has_cert) {
            (Some(port), true) => {
                let host = if port == 443 { visit.host.clone() } else { format!("{}:{port}", visit.host) };
                redirect_to(&format!("https://{host}{}", incoming.path_and_query()), None)
            }
            _ => error_response(
                StatusCode::FORBIDDEN,
                "This page asks visitors to sign in, which is only done over HTTPS.",
            ),
        };
        return answered(visit, response.status(), "sign-in: needs HTTPS", response);
    }

    // HTTP Basic, for the clients that cannot fill in a form.
    if ask.basic
        && let Some((user, pass)) = gateway::basic_credentials(&incoming.headers)
    {
        if gateway::throttled(ask.realm.id, &user, incoming.client_ip) {
            gateway_audit(state, site, ask, &user, incoming.client_ip, "throttled");
            return answered(visit, StatusCode::TOO_MANY_REQUESTS, "sign-in: too many attempts",
                            error_response(StatusCode::TOO_MANY_REQUESTS, "Too many attempts. Try again in a few minutes."));
        }
        let (who, trouble) = gateway::check_basic(&state.secret, &ask.realm, &user, &pass).await;
        if let Some(e) = trouble {
            tracing::warn!(site = %site.name, realm = %ask.realm.name, "Sign-in could not be checked: {e}");
        }
        return match who {
            Some(who) => {
                gateway::note_success(incoming.client_ip);
                // The credential was the gateway's. The application is told
                // who it was, not handed the password.
                incoming.headers.remove(axum::http::header::AUTHORIZATION);
                ask.announce(&mut incoming.headers, &who);
                visit.user = Some(who.subject);
                Gate::Through(None)
            }
            None => {
                gateway::note_failure(ask.realm.id, &user, incoming.client_ip);
                gateway_audit(state, site, ask, &user, incoming.client_ip, "refused");
                answered(visit, StatusCode::UNAUTHORIZED, "sign-in: refused", basic_challenge(&ask.realm.name))
            }
        };
    }

    // Nobody we can name. A browser is shown the form; a client that did not
    // ask for a page is told, in the way it understands, that it may send a
    // credential — where the site accepts one that way.
    let wants_page = incoming.headers.get(axum::http::header::ACCEPT)
        .is_none_or(|v| String::from_utf8_lossy(v.as_bytes()).contains("text/html"));
    let response = if ask.basic && !wants_page {
        basic_challenge(&ask.realm.name)
    } else {
        sign_in_page(&visit.host, &incoming.path_and_query(), Notice::None, StatusCode::UNAUTHORIZED, None)
    };
    answered(visit, StatusCode::UNAUTHORIZED, "sign-in: required", response)
}

/// The sign-in form, posted.
async fn sign_in(
    state:    &ProxyState,
    site:     &SiteRow,
    ask:      &crate::gateway::SiteAuth,
    incoming: &Incoming,
    visit:    &mut Visit,
    posted:   Option<&bytes::Bytes>,
    detected: &Option<(i64, Option<String>, String, String)>,
) -> Gate {
    use crate::gateway::{self, Notice};

    let answered = |visit: &Visit, status: StatusCode, why: &str, response: Response<Body>| {
        visit.record(&state.traffic, Outcome::answered_here(detected, status.as_u16() as i64, why));
        Gate::Answered(response)
    };

    if !incoming.https {
        return answered(visit, StatusCode::FORBIDDEN, "sign-in: needs HTTPS",
                        error_response(StatusCode::FORBIDDEN, "Signing in is only done over HTTPS."));
    }
    // The form is this server's and is small. One that did not arrive whole,
    // or was posted from another site's page, is not it.
    let Some(posted) = posted else {
        return answered(visit, StatusCode::PAYLOAD_TOO_LARGE, "sign-in: refused",
                        error_response(StatusCode::PAYLOAD_TOO_LARGE, "Sign-in submission too large"));
    };
    if posted_from_elsewhere(&incoming.headers) {
        return answered(visit, StatusCode::FORBIDDEN, "sign-in: refused",
                        error_response(StatusCode::FORBIDDEN, "This sign-in was sent from another site's page."));
    }

    let form = parse_form(posted);
    let user = form.get("user").map(|s| s.trim().to_string()).unwrap_or_default();
    let pass = form.get("pass").cloned().unwrap_or_default();
    let dest = form.get("dest").map(String::as_str).filter(|d| lands_on_the_site(d)).unwrap_or("/").to_string();

    if gateway::throttled(ask.realm.id, &user, incoming.client_ip) {
        gateway_audit(state, site, ask, &user, incoming.client_ip, "throttled");
        let page = sign_in_page(&visit.host, &dest, Notice::Throttled, StatusCode::TOO_MANY_REQUESTS, None);
        return answered(visit, StatusCode::TOO_MANY_REQUESTS, "sign-in: too many attempts", page);
    }

    let (checked, trouble) = gateway::check_password(&ask.realm, &user, &pass).await;
    if let Some(e) = trouble {
        tracing::warn!(site = %site.name, realm = %ask.realm.name, "Sign-in could not be checked: {e}");
    }
    let Some((who, user_epoch)) = checked else {
        gateway::note_failure(ask.realm.id, &user, incoming.client_ip);
        gateway_audit(state, site, ask, &user, incoming.client_ip, "refused");
        let page = sign_in_page(&visit.host, &dest, Notice::Refused, StatusCode::UNAUTHORIZED, None);
        return answered(visit, StatusCode::UNAUTHORIZED, "sign-in: refused", page);
    };

    gateway::note_success(incoming.client_ip);
    gateway_audit(state, site, ask, &who.subject, incoming.client_ip, "signed-in");
    if ask.realm.kind == gateway::Kind::Local {
        // For the account list. Not waited for: a sign-in does not depend on it.
        let (db, realm, name) = (state.db.clone(), ask.realm.id, who.subject.clone());
        tokio::spawn(async move {
            let _ = sqlx::query!(
                "UPDATE auth_users SET last_login = datetime('now') WHERE realm_id = ? AND username = ?",
                realm, name
            )
            .execute(&db)
            .await;
        });
    }

    let now = chrono::Utc::now().timestamp();
    let cookie = gateway::set_cookie(
        &gateway::mint(&state.secret, site.id, &ask.realm, &who, user_epoch, now, now),
        &ask.realm,
    );
    visit.user = Some(who.subject);
    answered(visit, StatusCode::SEE_OTHER, "sign-in: signed in", redirect_to(&dest, Some(cookie)))
}

/// Whether a path is somewhere to send a visitor who has just signed in: on
/// this site, and not one of the gateway's own addresses, which would bring
/// them straight back to a form or sign them out again.
fn lands_on_the_site(dest: &str) -> bool {
    challenge::stays_on_site(dest)
        && !dest.starts_with(crate::gateway::LOGIN_PATH)
        && !dest.starts_with(crate::gateway::LOGOUT_PATH)
}

/// Whether a form was posted from a page on another host. A browser says
/// where a POST came from; a request that does not say is not refused for it.
fn posted_from_elsewhere(headers: &HeaderMap) -> bool {
    let text = |name: &str| headers.get(name).map(|v| String::from_utf8_lossy(v.as_bytes()).to_ascii_lowercase());
    let (Some(origin), Some(host)) = (text("origin"), text("host")) else { return false };
    origin.split_once("://").map_or(origin.as_str(), |(_, rest)| rest) != host
}

/// The sign-in page as a response, never cached, with a cookie when it sets
/// or clears one.
fn sign_in_page(
    host:   &str,
    dest:   &str,
    notice: crate::gateway::Notice,
    status: StatusCode,
    cookie: Option<String>,
) -> Response<Body> {
    let mut response = Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store");
    if let Some(c) = cookie {
        response = response.header("set-cookie", c);
    }
    response
        .body(Body::from(crate::gateway::login_page(host, dest, notice)))
        .unwrap_or_else(|_| error_response(status, "Sign in"))
}

/// A redirect that is never cached, with a cookie when it sets one.
fn redirect_to(location: &str, cookie: Option<String>) -> Response<Body> {
    let mut response = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("location", location)
        .header("cache-control", "no-store");
    if let Some(c) = cookie {
        response = response.header("set-cookie", c);
    }
    response
        .body(Body::empty())
        .unwrap_or_else(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "Redirect build error"))
}

/// The answer that asks a client for a Basic credential.
fn basic_challenge(realm: &str) -> Response<Body> {
    // The realm is shown by clients. Quotes and control characters cannot be
    // put in a quoted string, and a realm's name does not need them.
    let shown: String = realm.chars().filter(|c| !c.is_control() && *c != '"' && *c != '\\').collect();
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("www-authenticate", format!("Basic realm=\"{shown}\", charset=\"UTF-8\""))
        .header("content-type", "text/plain; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Body::from("Sign-in required."))
        .unwrap_or_else(|_| error_response(StatusCode::UNAUTHORIZED, "Sign-in required."))
}

/// One line in the audit trail for a sign-in to a site: who, to what, from
/// where, and how it went. Never the password.
fn gateway_audit(
    state:  &ProxyState,
    site:   &SiteRow,
    ask:    &crate::gateway::SiteAuth,
    user:   &str,
    client: std::net::IpAddr,
    result: &str,
) {
    use crate::logging::{clip, field};
    state.logger.audit(format!(
        "ts={} event=site-sign-in site={} realm={} user={} client={} result={}",
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
        field(&site.name),
        field(&ask.realm.name),
        field(&clip(user, 128)),
        client,
        result,
    ));
}

// ─── Step 11: forwarding ─────────────────────────────────

/// Step 11. Send the request to one of the site's backends and stream the
/// answer back — or hand the connection over, for an upgrade.
async fn forward(
    state:      &ProxyState,
    site:       &SiteRow,
    incoming:   &Incoming,
    visit:      &Visit,
    detected:   &Option<(i64, Option<String>, String, String)>,
    body:       Prefix<BodyStream>,
    on_upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> Response<Body> {
    // Which backend serves this request. With one upstream it is that one,
    // every time, as it was before a site could have more. With affinity on,
    // the cookie the client sends back decides — as long as the backend it
    // names is still in this site's pool and still answering.
    let pinned = if site.affinity {
        cookie_value(&incoming.headers, crate::upstream::AFFINITY_COOKIE)
            .and_then(|v| crate::upstream::read_pin(&state.secret, &v))
    } else {
        None
    };
    let Some(chosen) = crate::upstream::choose_pinned(site.id, &site.upstreams, pinned) else {
        // A site with no upstream at all: nothing to forward to, and saying so
        // beats a generic gateway error nobody can act on.
        tracing::warn!(site = %site.name, "no upstream is configured for this site");
        return error_response(StatusCode::BAD_GATEWAY, "No upstream is configured for this site");
    };

    // An accepted upgrade leaves HTTP behind, so it cannot go through reqwest,
    // which has no way to take over a connection after the response. It happens
    // here rather than earlier so the handshake is inspected like any other
    // request — it is a normal GET with headers, and the pipeline has already
    // had its say by this point.
    if is_upgrade(&incoming.headers)
        && let Some(on_upgrade) = on_upgrade
    {
        return forward_upgrade(state, incoming, visit, detected, &chosen.upstream.url, on_upgrade).await;
    }

    // A cookie is set when the site pins and this request did not arrive with
    // the right one — first request, or a re-pin because the old backend has
    // gone. Sending it every time would be a header on every response for
    // nothing.
    let result = send_upstream(state, site, incoming, chosen.upstream, body).await;
    let repin = site.affinity && pinned != Some(result.upstream.id);

    match result.response {
        Ok(upstream_resp) => {
            visit.record(&state.traffic,
                         Outcome::forwarded(detected, upstream_resp.status().as_u16() as i64, &result.upstream.url));
            stream_back(state, upstream_resp, result.upstream.id, repin, incoming.https)
        }
        // The client stopped sending its body. Not the backend's failure and
        // not a gateway error: the request never finished arriving.
        Err(e) if result.client_gave_up => {
            tracing::debug!(upstream = %result.upstream.url, error = %error_chain(&e),
                            "the client stopped sending its request body");
            visit.record(&state.traffic, Outcome::forwarded(detected, 400, &result.upstream.url));
            error_response(StatusCode::BAD_REQUEST, "The request body did not finish arriving")
        }
        Err(e) => {
            tracing::warn!(upstream = %result.upstream.url, error = %error_chain(&e), "upstream unreachable");
            visit.record(&state.traffic, Outcome::forwarded(detected, 502, &result.upstream.url));
            // Two different problems with two different next steps, so they
            // are not given the same sentence: one backend is unreachable, or
            // every backend of this site is.
            if chosen.all_out || result.tried > 1 {
                error_response(StatusCode::BAD_GATEWAY, "All upstreams for this site are down")
            } else {
                error_response(StatusCode::BAD_GATEWAY, "Upstream unreachable")
            }
        }
    }
}

/// Proxy an upgrade handshake and, if the backend accepts, the connection.
async fn forward_upgrade(
    state:      &ProxyState,
    incoming:   &Incoming,
    visit:      &Visit,
    detected:   &Option<(i64, Option<String>, String, String)>,
    upstream:   &str,
    on_upgrade: hyper::upgrade::OnUpgrade,
) -> Response<Body> {
    let url = format!("{}{}", upstream.trim_end_matches('/'), incoming.path_and_query());
    tracing::debug!(path = %incoming.path, "proxying a protocol upgrade");
    let headers = upgrade_headers(&incoming.headers, incoming.peer, incoming.client_ip, incoming.https);
    let resp = match proxy_upgrade(&url, &incoming.method, &headers, on_upgrade).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!(upstream = %url, "upgrade failed: {}", e);
            error_response(StatusCode::BAD_GATEWAY, "Upgrade failed")
        }
    };

    // Logged like any other request. The tunnel that follows cannot be, but
    // the handshake is the only record that the connection happened at all —
    // without it a WebSocket application is invisible in Traffic Monitor, which
    // is worse than useless when someone is trying to work out whether their
    // traffic is reaching the site.
    visit.record(&state.traffic, Outcome::forwarded(detected, resp.status().as_u16() as i64, upstream));
    resp
}

/// How sending a request upstream went.
struct Sent<'a> {
    /// The upstream's response, or the last error trying to reach one.
    response: Result<reqwest::Response, reqwest::Error>,
    /// The backend that answered, or the last one tried.
    upstream: &'a crate::upstream::Upstream,
    /// How many backends were tried.
    tried:    usize,
    /// The request failed because the client stopped sending its body, which
    /// says nothing about the backend.
    client_gave_up: bool,
}

/// Send the request to `first`, and to another backend if that is safe.
///
/// Two things have to hold for a second attempt.
///
/// The body can be sent again. One that ended within the inspected start is
/// held whole. One that is still arriving cannot be replayed: it is a stream,
/// the first attempt consumes it, and there is nothing left. So a large upload
/// gets one attempt and an honest 502, rather than a retry that would send
/// half a body. It is sent with the client's own Content-Length, which still
/// matches, since not one byte is altered.
///
/// And sending it again cannot do the thing twice — see `may_send_again`.
///
/// A failure is counted against the backend unless it was the client's: a
/// client that abandons an upload breaks the request just as a dead backend
/// does, and three cancelled uploads must not take a working backend out of
/// the rotation.
async fn send_upstream<'a>(
    state:    &ProxyState,
    site:     &'a SiteRow,
    incoming: &Incoming,
    first:    &'a crate::upstream::Upstream,
    body:     Prefix<BodyStream>,
) -> Sent<'a> {
    // At most three backends: a pool large enough for a fourth attempt is a
    // pool where the client has waited long enough to be told.
    const ATTEMPTS: usize = 3;

    let mut headers = incoming.headers.clone();
    for h in HOP_HEADERS {
        headers.remove(*h);
    }
    apply_forwarded_headers(
        &mut headers,
        incoming.peer,
        incoming.client_ip,
        incoming.headers.get(axum::http::header::HOST),
        incoming.https,
    );
    let headers = to_reqwest_headers(&headers);

    let replayable = body.complete;
    let head = body.head.clone();
    // Set when the rest of the client's body fails to arrive, so the error
    // that follows can be told from one that is the backend's.
    let client_failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut streamed = if body.complete {
        None
    } else {
        let first_chunk = futures::stream::once(std::future::ready(
            Ok::<bytes::Bytes, axum::Error>(body.head),
        ));
        let failed = client_failed.clone();
        let rest = futures::TryStreamExt::inspect_err(body.rest, move |_| {
            failed.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        Some(reqwest::Body::wrap_stream(futures::StreamExt::chain(first_chunk, rest)))
    };

    let path_and_query = incoming.path_and_query();
    let mut upstream = first;
    let mut tried: Vec<i64> = Vec::new();
    loop {
        let url = format!("{}{}", upstream.url.trim_end_matches('/'), path_and_query);
        let request_body = match streamed.take() {
            Some(b) => b,
            None    => reqwest::Body::from(head.clone()),
        };
        let client = if site.backend_tls_insecure { &state.client_unverified } else { &state.client };
        let response = client
            .request(to_reqwest_method(&incoming.method), &url)
            .headers(headers.clone())
            .body(request_body)
            .send()
            .await;

        let Err(e) = &response else {
            return Sent { response, upstream, tried: tried.len() + 1, client_gave_up: false };
        };

        if client_failed.load(std::sync::atomic::Ordering::Relaxed) {
            return Sent { response, upstream, tried: tried.len() + 1, client_gave_up: true };
        }

        // Could not be reached: that is the backend's fault, whatever the
        // application would have said.
        crate::upstream::failed(upstream.id);
        tried.push(upstream.id);
        if !replayable || !may_send_again(&incoming.method, e) || tried.len() >= ATTEMPTS {
            return Sent { response, upstream, tried: tried.len(), client_gave_up: false };
        }
        let Some(next) = crate::upstream::choose_except(site.id, &site.upstreams, &tried) else {
            return Sent { response, upstream, tried: tried.len(), client_gave_up: false };
        };
        tracing::warn!(upstream = %url, error = %error_chain(e), next = %next.upstream.url,
                       "upstream unreachable, trying another backend");
        upstream = next.upstream;
    }
}

/// Whether a request that failed on one backend may be sent to another without
/// risking that it is carried out twice.
///
/// A connection that was never made sent nothing, so anything may be tried
/// elsewhere. After that the request may have arrived: a backend that received
/// an order and died before answering has still taken the order. Then only a
/// request that is safe to repeat is repeated — the methods HTTP defines as
/// idempotent — and a POST gets the 502 it would get from a single backend.
fn may_send_again(method: &Method, error: &reqwest::Error) -> bool {
    error.is_connect() || is_idempotent(method)
}

/// The methods RFC 9110 defines as idempotent: repeating one leaves the server
/// as one request would have.
fn is_idempotent(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE | Method::PUT | Method::DELETE)
}

/// An error with every cause behind it, joined by colons.
///
/// reqwest's own message stops at "error sending request": whether the backend
/// refused the connection, timed out or presented a certificate that did not
/// verify is in the causes, and that is the part an operator needs.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut cause = e.source();
    while let Some(c) = cause {
        let text = c.to_string();
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        cause = c.source();
    }
    out
}

/// Turn the upstream's response into the client's, streaming the body without
/// buffering it. `served` is the backend that answered; `repin` says the client
/// needs a new affinity cookie naming it.
fn stream_back(
    state:         &ProxyState,
    upstream_resp: reqwest::Response,
    served:        i64,
    repin:         bool,
    secure:        bool,
) -> Response<Body> {
    let status = upstream_resp.status();
    // A 5xx is the backend saying it cannot answer, and counts against it. A
    // 404 is the application answering, and does not: taking a working backend
    // out of rotation because somebody asked for a missing page would be a
    // worse fault than the one being guarded against.
    if status.is_server_error() {
        crate::upstream::failed(served);
    } else {
        crate::upstream::succeeded(served);
    }
    let resp_headers = upstream_resp.headers().clone();
    let body = Body::from_stream(upstream_resp.bytes_stream());

    let mut resp = Response::builder().status(status);
    if let Some(headers) = resp.headers_mut() {
        copy_response_headers(headers, &resp_headers);

        // Pin the client to the backend that served it. A session cookie:
        // affinity that outlives the browser session would hold a client to a
        // backend long after anything it was keeping in memory had gone.
        // HttpOnly because no page has any business reading it, and Secure for
        // a client on HTTPS so it is not sent back in clear.
        if repin
            && let Ok(v) = axum::http::HeaderValue::from_str(&format!(
                "{}={}; Path=/; HttpOnly; SameSite=Lax{}",
                crate::upstream::AFFINITY_COOKIE,
                crate::upstream::make_pin(&state.secret, served),
                if secure { "; Secure" } else { "" }))
        {
            headers.append(axum::http::header::SET_COOKIE, v);
        }
    }
    resp.body(body)
        .unwrap_or_else(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "Response build error"))
}

// ─── IP list verdicts ────────────────────────────────────

/// What a list says about a request: the reason a traffic row gives, and what
/// enforcing it means. `None` for an address on no list, or on the allowlist,
/// which is not a verdict but a pass.
fn list_verdict(
    listed: &Option<crate::iplist::Listed>,
) -> Option<(String, crate::modules::Detection)> {
    use crate::iplist::{Listed, Response};
    use crate::modules::Detection;
    match listed {
        Some(Listed::Blocked) => Some((
            "Client address is on the block list".to_string(),
            Detection::WouldBlock,
        )),
        Some(Listed::Published(hit)) => Some((
            format!("Client address is on the published list \"{}\"", hit.name),
            match hit.response {
                Response::Block     => Detection::WouldBlock,
                Response::Challenge => Detection::WouldChallenge,
            },
        )),
        _ => None,
    }
}

/// The more serious of two detections: a list that would block outranks rules
/// that would only have challenged, and the other way round.
fn stronger(
    have: Option<crate::modules::Detection>,
    list: crate::modules::Detection,
) -> crate::modules::Detection {
    use crate::modules::Detection;
    let rank = |d: Detection| match d {
        Detection::Observed       => 0,
        Detection::WouldChallenge => 1,
        Detection::WouldBlock     => 2,
    };
    match have {
        Some(h) if rank(h) >= rank(list) => h,
        _ => list,
    }
}

// ─── The site table ──────────────────────────────────────

/// Every site, by each hostname it answers for.
///
/// Held in memory because a query per request would be most of what a request
/// costs. Sites change when an administrator saves something, so they are read
/// once and read again when the configuration generation moves — the
/// invalidation the rule caches rely on, which the database's own triggers
/// drive (migrations 025 and 035), so no handler can forget it. A change
/// reaches the proxy within [`crate::modules::generation::MAX_AGE`].
///
/// Held whole rather than filled per hostname, so a hostname nobody configured
/// costs nothing to refuse, and scanners sending made-up `Host` headers cannot
/// grow it.
struct SiteTable {
    generation: u64,
    /// Enabled sites, under their `server_name` and every alias.
    enabled:    HashMap<String, Arc<SiteRow>>,
    /// Hostnames of sites that are switched off, which get the maintenance page.
    disabled:   HashSet<String>,
}

static SITES: OnceLock<RwLock<Option<Arc<SiteTable>>>> = OnceLock::new();

fn sites() -> &'static RwLock<Option<Arc<SiteTable>>> {
    SITES.get_or_init(|| RwLock::new(None))
}

/// The site table for the current generation, reloading it if that moved.
///
/// If the reload fails, the table already held goes on being used: the sites as
/// they were a moment ago beat refusing every request until the database
/// answers. With nothing held yet, an empty table is returned and not kept, so
/// the next request tries again.
async fn site_table(db: &SqlitePool) -> Arc<SiteTable> {
    let generation = crate::modules::generation::current(db).await;
    let held = sites().read().ok().and_then(|t| t.clone());
    if let Some(t) = &held
        && t.generation == generation
    {
        return t.clone();
    }

    let loaded = match load_sites(db, generation).await {
        Ok(t) => Arc::new(t),
        Err(e) => {
            tracing::warn!("Could not load the sites: {e}");
            return held.unwrap_or_else(|| Arc::new(SiteTable {
                generation: 0,
                enabled:    HashMap::new(),
                disabled:   HashSet::new(),
            }));
        }
    };

    // Two requests can reload at once. The table read at the newer generation
    // is the one kept, so a slow read cannot put back sites a faster one had
    // already seen changed.
    if let Ok(mut t) = sites().write()
        && t.as_ref().is_none_or(|t| t.generation <= generation)
    {
        *t = Some(loaded.clone());
    }
    loaded
}

/// Read every site and its aliases.
async fn load_sites(db: &SqlitePool, generation: u64) -> Result<SiteTable, sqlx::Error> {
    let rows = sqlx::query!(
        // A URL holds neither a space nor a newline, so `url weight` per line
        // needs no escaping.
        "SELECT id as \"id!\", name, server_name, enabled as \"enabled!: bool\",
                (SELECT group_concat(id || ' ' || url || ' ' || weight, char(10))
                   FROM upstreams
                  WHERE site_id = sites.id AND enabled = 1) as \"pool?: String\",
                tls_port,
                EXISTS (SELECT 1 FROM certs c WHERE c.id = sites.cert_id
                          AND trim(COALESCE(c.cert_pem, '')) <> ''
                          AND trim(COALESCE(c.key_pem, '')) <> '')
                               as \"has_cert!: bool\",
                tls_redirect   as \"tls_redirect!: bool\",
                hsts           as \"hsts!: bool\",
                x_frame        as \"x_frame!: bool\",
                x_frame_value  as \"x_frame_value!\",
                x_content_type as \"x_content_type!: bool\",
                xss_protection as \"xss_protection!: bool\",
                affinity       as \"affinity!: bool\",
                waf_policy_id,
                (SELECT rule_engine FROM policies p WHERE p.id = sites.waf_policy_id)
                               as \"rule_engine?: String\",
                (SELECT smart_protect FROM policies p WHERE p.id = sites.waf_policy_id)
                               as \"smart_protect?: bool\",
                backend_tls_insecure as \"backend_tls_insecure!: bool\"
         FROM sites
         ORDER BY id"
    )
    .fetch_all(db)
    .await?;

    let mut aliases: HashMap<i64, Vec<String>> = HashMap::new();
    for a in sqlx::query!("SELECT site_id, name FROM site_aliases ORDER BY id")
        .fetch_all(db)
        .await?
    {
        aliases.entry(a.site_id).or_default().push(a.name);
    }

    let mut asks = load_site_auth(db).await?;

    let mut table = SiteTable { generation, enabled: HashMap::new(), disabled: HashSet::new() };
    for r in rows {
        let mut names = vec![r.server_name];
        names.extend(aliases.remove(&r.id).unwrap_or_default());

        if !r.enabled {
            table.disabled.extend(names);
            continue;
        }
        let site = Arc::new(SiteRow {
            id:             r.id,
            name:           r.name,
            upstreams:      crate::upstream::parse_pool(r.pool.as_deref().unwrap_or("")),
            tls_port:       r.tls_port,
            has_cert:       r.has_cert,
            tls_redirect:   r.tls_redirect,
            hsts:           r.hsts,
            x_frame:        r.x_frame,
            x_frame_value:  r.x_frame_value,
            x_content_type: r.x_content_type,
            xss_protection: r.xss_protection,
            affinity:       r.affinity,
            policy_id:      r.waf_policy_id,
            rule_engine:    r.rule_engine,
            smart_protect:  r.smart_protect.unwrap_or(false),
            backend_tls_insecure: r.backend_tls_insecure,
            auth:           asks.remove(&r.id),
        });
        // The oldest site keeps a name two of them claim. The forms refuse
        // that, so it is a tiebreak for a database edited by hand.
        for name in names {
            table.enabled.entry(name).or_insert_with(|| site.clone());
        }
    }
    // A name an enabled site answers for is served, even if a disabled site
    // also lists it.
    table.disabled.retain(|n| !table.enabled.contains_key(n));
    Ok(table)
}

/// What each site asks of its visitors, by site: its realm with that realm's
/// accounts, the paths, and the headers.
///
/// Read with the sites and held with them, so a request that carries a session
/// is checked against memory. Accounts are few — these are the people let into
/// an admin panel, not a site's customers — and a realm is shared by reference
/// between the sites that use it.
async fn load_site_auth(db: &SqlitePool) -> Result<HashMap<i64, crate::gateway::SiteAuth>, sqlx::Error> {
    use crate::gateway::{Kind, LdapConfig, LocalUser, Realm, SiteAuth};
    use std::time::Duration;

    let sites = sqlx::query!(
        r#"SELECT site_id as "site_id!", realm_id as "realm_id!", paths as "paths!", bypass as "bypass!",
                  basic as "basic!: bool", user_header as "user_header!", groups_header as "groups_header!"
           FROM site_auth"#
    )
    .fetch_all(db)
    .await?;
    if sites.is_empty() {
        return Ok(HashMap::new());
    }

    let mut users: HashMap<i64, HashMap<String, LocalUser>> = HashMap::new();
    for u in sqlx::query!(
        r#"SELECT realm_id as "realm_id!", username as "username!", password_hash as "password_hash!",
                  enabled as "enabled!: bool", epoch as "epoch!"
           FROM auth_users"#
    )
    .fetch_all(db)
    .await?
    {
        users.entry(u.realm_id).or_default().insert(
            u.username,
            LocalUser { password_hash: u.password_hash, enabled: u.enabled, epoch: u.epoch },
        );
    }

    let mut realms: HashMap<i64, Arc<Realm>> = HashMap::new();
    for r in sqlx::query!(
        r#"SELECT id as "id!", name as "name!", kind as "kind!", session_minutes as "session_minutes!",
                  idle_minutes as "idle_minutes!", epoch as "epoch!", config as "config!"
           FROM auth_realms"#
    )
    .fetch_all(db)
    .await?
    {
        let kind = if r.kind == "ldap" {
            // A directory whose settings do not read is one nobody can sign in
            // through, which fails closed: the site still asks.
            Kind::Ldap(serde_json::from_str::<LdapConfig>(&r.config).unwrap_or_default())
        } else {
            Kind::Local
        };
        realms.insert(r.id, Arc::new(Realm {
            id:      r.id,
            name:    r.name,
            kind,
            session: Duration::from_secs(r.session_minutes.max(1) as u64 * 60),
            idle:    Duration::from_secs(r.idle_minutes.max(1) as u64 * 60),
            epoch:   r.epoch,
            users:   users.remove(&r.id).unwrap_or_default(),
        }));
    }

    let header = |name: &str, default: &'static str| {
        HeaderName::from_bytes(name.trim().to_ascii_lowercase().as_bytes())
            .unwrap_or(HeaderName::from_static(default))
    };
    let mut out = HashMap::new();
    for s in sites {
        let Some(realm) = realms.get(&s.realm_id) else { continue };
        out.insert(s.site_id, SiteAuth {
            realm:         realm.clone(),
            protect:       crate::gateway::parse_prefixes(&s.paths).0,
            bypass:        crate::gateway::parse_prefixes(&s.bypass).0,
            basic:         s.basic,
            user_header:   header(&s.user_header, "x-forwarded-user"),
            groups_header: header(&s.groups_header, "x-forwarded-groups"),
        });
    }
    Ok(out)
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

// ─── Security headers ────────────────────────────────────

/// The response headers a site has switched on, taken from its row before the
/// request is handled, so they can be applied to whatever the handling
/// produces.
struct SecurityHeaders {
    hsts:           bool,
    x_frame:        Option<&'static str>,
    x_content_type: bool,
    xss_protection: bool,
}

impl SecurityHeaders {
    fn of(site: &SiteRow, tls: bool) -> Self {
        SecurityHeaders {
            // Over HTTPS only. RFC 6797 says a server must not send HSTS over
            // plain HTTP — a browser ignores it there, and an attacker in the
            // middle could otherwise strip or forge it.
            hsts: site.hsts && tls,
            // The configured value wins over anything the application sent,
            // so what the setting says is what is served. DENY forbids
            // framing by *anything*, self included, which quietly breaks
            // applications that frame their own pages — Nextcloud is one, and
            // reports the header as misconfigured when it sees it.
            x_frame: site.x_frame.then(|| {
                match site.x_frame_value.trim().to_uppercase().as_str() {
                    "DENY" => "DENY",
                    _      => "SAMEORIGIN",
                }
            }),
            x_content_type: site.x_content_type,
            xss_protection: site.xss_protection,
        }
    }

    fn apply(&self, headers: &mut HeaderMap) {
        if self.hsts {
            headers.insert(
                HeaderName::from_static("strict-transport-security"),
                HeaderValue::from_static("max-age=31536000; includeSubDomains"),
            );
        }
        if let Some(v) = self.x_frame {
            headers.insert(HeaderName::from_static("x-frame-options"), HeaderValue::from_static(v));
        }
        if self.x_content_type {
            headers.insert(
                HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            );
        }
        if self.xss_protection {
            headers.insert(
                HeaderName::from_static("x-xss-protection"),
                HeaderValue::from_static("1; mode=block"),
            );
        }
    }
}

// ─── blocked_response ────────────────────────────────────

/// What a refused visitor is told, which is not why.
enum Refusal {
    /// The site's rules, a country rule or an IP list refused the request.
    Rules,
    /// Smart Protect has the address blocked for a while.
    Repeated,
}

/// The page a refused request is answered with.
///
/// It says the request was blocked and gives a reference — the time and the
/// visitor's address — and nothing else. Which rule matched, the score and the
/// threshold are in Traffic Monitor for the operator; told to the visitor, they
/// are instructions for getting under the threshold next time. The reference is
/// enough to find the row: a visitor wrongly blocked can quote it.
///
/// Self-contained, like the maintenance page: nothing fetched from anywhere.
fn blocked_response(status: StatusCode, client_ip: &str, refusal: Refusal) -> Response<Body> {
    let (title, message) = match refusal {
        Refusal::Rules => (
            "Request blocked",
            "This request was blocked by the site's security rules.",
        ),
        Refusal::Repeated => (
            "Temporarily blocked",
            "Too many of your recent requests were blocked, so requests from your \
             address are being refused for a while. Try again later.",
        ),
    };
    let when = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  body {{ margin:0; min-height:100vh; display:flex; align-items:center;
         justify-content:center; background:#0f172a; color:#e2e8f0;
         font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }}
  .card {{ max-width:34rem; padding:2.5rem; text-align:center; }}
  h1 {{ font-size:1.4rem; font-weight:600; margin:0 0 .75rem; }}
  p  {{ margin:0 0 1rem; line-height:1.6; color:#94a3b8; }}
  code {{ color:#e2e8f0; }}
</style>
</head>
<body>
  <div class="card">
    <h1>{title}</h1>
    <p>{message}</p>
    <p>If you think this is a mistake, give the site's administrator this
       reference: <code>{when} — {ip}</code></p>
  </div>
</body>
</html>"#,
        ip = escape_html(client_ip),
    );
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Body::from(html))
        .unwrap_or_else(|_| error_response(status, title))
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
fn handle_verify(state: &ProxyState, client_ip: &str, body: &[u8], secure: bool) -> Response<Body> {
    let form = parse_form(body);
    let id     = form.get("id").map(String::as_str).unwrap_or("");
    let answer = form.get("answer").map(String::as_str).unwrap_or("");

    let outcome = state.challenges.verify(id, answer, client_ip);
    if let challenge::Answer::Right(dest) = outcome {
        let cookie = challenge::make_clearance(&state.secret, client_ip);
        // Secure over HTTPS, like the affinity cookie: a clearance sent back
        // in clear on a plain port could be lifted and replayed.
        let set_cookie = format!(
            "{}={}; Path=/; Max-Age=1800; HttpOnly; SameSite=Lax{}",
            CLEARANCE_COOKIE, cookie, if secure { "; Secure" } else { "" }
        );
        let location = if challenge::stays_on_site(&dest) { dest } else { "/".to_string() };
        return Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header("location", location)
            .header("set-cookie", set_cookie)
            .header("cache-control", "no-store")
            .body(Body::empty())
            .unwrap();
    }

    // Wrong or expired — a new challenge, to the same place when the old one
    // said where. The old one is gone: an image is answered once.
    let dest = match outcome {
        challenge::Answer::Wrong(dest) => dest,
        _ => "/".to_string(),
    };
    match state.challenges.issue(&dest, client_ip) {
        Some((new_id, data_uri)) => challenge_response(&new_id, &data_uri, true),
        None                     => too_many_challenges(),
    }
}

/// The answer when as many challenges are waiting as the store will hold.
///
/// Every challenge draws an image and is kept for three minutes, so without a
/// cap a flood of requests that each cross the challenge threshold would cost
/// memory and CPU without limit. Past the cap a visitor is asked to come back
/// instead, before any image is drawn.
fn too_many_challenges() -> Response<Body> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "text/plain; charset=utf-8")
        .header("retry-after", "60")
        .header("cache-control", "no-store")
        .body(Body::from("Too many visitors are being checked right now. Please try again in a minute."))
        .unwrap()
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
    // Read whatever bytes it holds: applications do set cookies that are not
    // ASCII, and one of those beside ours must not hide ours.
    let raw = String::from_utf8_lossy(headers.get("cookie")?.as_bytes()).into_owned();
    for pair in raw.split(';') {
        if let Some((k, v)) = pair.trim().split_once('=')
            && k == name
        {
            return Some(v.to_string());
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

    /// A refused visitor is told that, and given a reference — the rule, the
    /// score and the threshold stay in Traffic Monitor.
    #[tokio::test]
    async fn a_block_page_says_blocked_and_not_why() {
        for (refusal, title) in [(Refusal::Rules, "Request blocked"), (Refusal::Repeated, "Temporarily blocked")] {
            let resp = blocked_response(StatusCode::FORBIDDEN, "203.0.113.9", refusal);
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            assert_eq!(resp.headers()["cache-control"], "no-store");
            let body = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
            let body = String::from_utf8(body.to_vec()).unwrap();
            assert!(body.contains(title), "{title}");
            assert!(body.contains("203.0.113.9"), "the reference names the address");
            for word in ["score", "threshold", "rule matched", "WAF", "EasyWAF"] {
                assert!(!body.contains(word), "the page gives away {word:?}");
            }
        }
    }

    #[test]
    fn an_upgrade_is_forwarded_with_the_headers_every_request_gets() {
        let mut h = HeaderMap::new();
        h.insert("host", "chat.example".parse().unwrap());
        h.insert("connection", "Upgrade".parse().unwrap());
        h.insert("upgrade", "websocket".parse().unwrap());
        h.insert("x-forwarded-for", "6.6.6.6".parse().unwrap());
        h.insert("te", "trailers".parse().unwrap());
        h.append("sec-websocket-protocol", "chat".parse().unwrap());
        h.append("sec-websocket-protocol", "superchat".parse().unwrap());
        let peer: std::net::IpAddr = "198.51.100.4".parse().unwrap();

        let out = upgrade_headers(&h, peer, peer, true);
        assert_eq!(out["x-forwarded-for"], "198.51.100.4", "the client's own claim went through");
        assert_eq!(out["x-real-ip"], "198.51.100.4");
        assert_eq!(out["x-forwarded-proto"], "https");
        assert_eq!(out["host"], "chat.example", "the Host the browser sent must reach the app");
        assert_eq!(out["connection"], "Upgrade");
        assert_eq!(out["upgrade"], "websocket");
        assert!(!out.contains_key("te"), "other hop-by-hop headers are not forwarded");
        assert_eq!(out.get_all("sec-websocket-protocol").iter().count(), 2, "a repeated header lost a value");
    }

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

    /// A client describing its own origin, or asking the application for a
    /// path other than the one the rules read, is not passed on.
    #[test]
    fn a_clients_claims_about_itself_are_not_forwarded() {
        let mut h = HeaderMap::new();
        for (name, value) in [
            ("forwarded", "for=10.0.0.1;proto=https"),
            ("x-original-url", "/admin"),
            ("x-rewrite-url", "/admin"),
            ("x-client-ip", "10.0.0.1"),
            ("true-client-ip", "10.0.0.1"),
            ("cf-connecting-ip", "10.0.0.1"),
            ("x-forwarded-ssl", "on"),
            ("x-forwarded-proto", "https"),
            ("accept", "text/html"),
        ] {
            h.insert(HeaderName::from_static(name), HeaderValue::from_static(value));
        }
        let peer: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        apply_forwarded_headers(&mut h, peer, peer, None, false);

        for claim in CLIENT_CLAIMS {
            assert!(!h.contains_key(*claim), "{claim} reached the backend");
        }
        assert_eq!(got(&h, "x-forwarded-proto"), "http", "the client's own word for the scheme was kept");
        assert_eq!(got(&h, "accept"), "text/html");
    }

    #[test]
    fn a_sign_in_posted_from_another_sites_page_is_told_apart() {
        let from = |origin: Option<&'static str>| {
            let mut h = HeaderMap::new();
            h.insert("host", HeaderValue::from_static("shop.example.com"));
            if let Some(o) = origin {
                h.insert("origin", HeaderValue::from_static(o));
            }
            posted_from_elsewhere(&h)
        };
        assert!(!from(Some("https://shop.example.com")));
        assert!(!from(Some("https://SHOP.example.com")));
        assert!(from(Some("https://evil.example")));
        assert!(from(Some("https://shop.example.com.evil.example")));
        assert!(from(Some("null")), "a sandboxed page is not this site's page");
        // A client that does not say where it posts from is not a browser, and
        // is not refused for that.
        assert!(!from(None));
    }

    #[test]
    fn after_signing_in_a_visitor_lands_on_the_site_and_not_back_at_the_form() {
        for dest in ["/", "/admin/users?page=2", "/a/b"] {
            assert!(lands_on_the_site(dest), "{dest}");
        }
        for dest in ["//evil.example/", "/\\evil.example", "https://evil.example/", "",
                     "/__easywaf/login", "/__easywaf/logout", "/__easywaf/login?x=1"] {
            assert!(!lands_on_the_site(dest), "{dest:?}");
        }
    }

    #[test]
    fn only_requests_that_are_safe_to_repeat_are_repeated() {
        for m in [Method::GET, Method::HEAD, Method::OPTIONS, Method::PUT, Method::DELETE] {
            assert!(is_idempotent(&m), "{m}");
        }
        for m in [Method::POST, Method::PATCH, Method::CONNECT] {
            assert!(!is_idempotent(&m), "{m} would be sent twice");
        }
    }

    #[test]
    fn a_hostname_written_in_full_is_the_same_hostname() {
        let host = |v: &'static str| {
            let req = axum::http::Request::builder().header("host", v).body(Body::empty()).unwrap();
            request_host(&req)
        };
        assert_eq!(host("Example.com.").as_deref(), Some("example.com"));
        assert_eq!(host("example.com.:8080").as_deref(), Some("example.com"));
        assert_eq!(host("example.com").as_deref(), Some("example.com"));
        assert_eq!(host("."), None);
    }

    /// Applications set cookies that are not ASCII. One of those beside ours
    /// must not hide ours, or a visitor could never get past a challenge.
    #[test]
    fn our_cookie_is_found_beside_one_that_is_not_ascii() {
        let mut h = HeaderMap::new();
        h.insert("cookie", HeaderValue::from_bytes("name=caf\u{e9}; easywaf_clearance=123.abc; x=1".as_bytes()).unwrap());
        assert_eq!(cookie_value(&h, "easywaf_clearance").as_deref(), Some("123.abc"));
        let mut h = HeaderMap::new();
        h.insert("cookie", HeaderValue::from_bytes(b"name=\xff\xfe; easywaf_clearance=123.abc").unwrap());
        assert_eq!(cookie_value(&h, "easywaf_clearance").as_deref(), Some("123.abc"));
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

#[cfg(test)]
mod list_verdict_tests {
    use super::*;
    use crate::iplist::{FeedHit, Listed, Response};
    use crate::modules::Detection;

    fn hit(response: Response) -> Option<Listed> {
        Some(Listed::Published(FeedHit { id: "x".into(), name: "X".into(), response }))
    }

    #[test]
    fn each_list_state_maps_to_what_enforcing_it_means() {
        assert_eq!(list_verdict(&Some(Listed::Blocked)).unwrap().1, Detection::WouldBlock);
        assert_eq!(list_verdict(&hit(Response::Block)).unwrap().1, Detection::WouldBlock);
        assert_eq!(list_verdict(&hit(Response::Challenge)).unwrap().1, Detection::WouldChallenge);
        assert!(list_verdict(&Some(Listed::Allowed)).is_none(), "allowing is a pass, not a verdict");
        assert!(list_verdict(&None).is_none());
        assert!(list_verdict(&hit(Response::Block)).unwrap().0.contains("\"X\""),
                "the reason names the list");
    }

    #[test]
    fn the_stronger_detection_is_kept() {
        use Detection::*;
        assert_eq!(stronger(None, WouldChallenge), WouldChallenge);
        assert_eq!(stronger(Some(Observed), WouldChallenge), WouldChallenge);
        assert_eq!(stronger(Some(WouldBlock), WouldChallenge), WouldBlock,
                   "a list must not soften what the rules found");
        assert_eq!(stronger(Some(WouldChallenge), WouldBlock), WouldBlock);
    }
}

#[cfg(test)]
mod prefix_tests {
    use super::{read_prefix, PrefixError};
    use std::time::Duration;
    use bytes::Bytes;
    use futures::{stream, StreamExt};

    type Chunk = Result<Bytes, std::io::Error>;

    /// Longer than any test here takes: these bodies do not stall.
    const PATIENT: Duration = Duration::from_secs(30);

    fn body(chunks: &[&'static [u8]]) -> impl futures::Stream<Item = Chunk> + Unpin {
        stream::iter(chunks.iter().map(|c| Ok(Bytes::from_static(c))).collect::<Vec<_>>())
    }

    async fn drain<S: futures::Stream<Item = Chunk> + Unpin>(mut s: S) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(c) = s.next().await {
            out.extend_from_slice(&c.unwrap());
        }
        out
    }

    #[tokio::test]
    async fn a_body_under_the_limit_is_read_whole() {
        let p = read_prefix(body(&[b"small", b" form"]), 1024, PATIENT).await.unwrap();
        assert!(p.complete, "a body that ends within the limit is complete");
        assert_eq!(&p.head[..], b"small form");
        assert!(drain(p.rest).await.is_empty());
    }

    #[tokio::test]
    async fn a_body_over_the_limit_stops_reading_and_keeps_the_rest() {
        // Chunks are never split, so the head may run past the limit by part
        // of one; reading stops as soon as the limit is reached.
        let p = read_prefix(body(&[b"aaaa", b"bbbb", b"cccc", b"dddd"]), 6, PATIENT).await.unwrap();
        assert!(!p.complete);
        assert_eq!(&p.head[..], b"aaaabbbb");
        assert_eq!(drain(p.rest).await, b"ccccdddd");
    }

    #[tokio::test]
    async fn nothing_is_lost_duplicated_or_reordered_at_any_limit() {
        // The property the upstream depends on: head then rest is the body.
        let chunks: &[&'static [u8]] = &[b"GET", b" the ", b"whole", b" body", b" back"];
        let whole: Vec<u8> = chunks.concat();
        for limit in 1..=whole.len() + 2 {
            let p = read_prefix(body(chunks), limit, PATIENT).await.unwrap();
            let mut got = p.head.to_vec();
            got.extend(drain(p.rest).await);
            assert_eq!(got, whole, "limit {limit} changed the body");
            assert!(p.head.len() >= limit.min(whole.len()), "limit {limit} read too little");
        }
    }

    #[tokio::test]
    async fn a_read_error_is_returned_rather_than_swallowed() {
        // A client that disconnects mid-body must not be forwarded as a body
        // that simply ended early.
        let broken = stream::iter(vec![
            Ok(Bytes::from_static(b"partial")),
            Err(std::io::Error::other("client went away")),
        ]);
        assert!(matches!(read_prefix(broken, 1024, PATIENT).await, Err(PrefixError::Read(_))));
    }

    /// One chunk and then nothing, with the body still open.
    fn stalls_after(first: &'static [u8]) -> impl futures::Stream<Item = Chunk> + Unpin {
        Box::pin(stream::iter(vec![Ok(Bytes::from_static(first))]).chain(stream::pending()))
    }

    #[tokio::test]
    async fn a_body_that_stops_arriving_is_given_up_on() {
        let stalled = read_prefix(stalls_after(b"partial"), 1024, Duration::from_millis(40)).await;
        assert!(matches!(stalled, Err(PrefixError::Stalled)));
    }

    /// The limit is on stalling, not on how long the whole start takes: a slow
    /// link sending steadily takes far longer than one stall allows in total.
    #[tokio::test]
    async fn a_slow_body_that_keeps_arriving_is_read_however_long_it_takes() {
        let stall = Duration::from_millis(80);
        let slow = Box::pin(stream::unfold(0u8, |sent| async move {
            if sent == 8 {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
            Some((Ok::<_, std::io::Error>(Bytes::from_static(b"chunk")), sent + 1))
        }));
        let started = std::time::Instant::now();
        let p = read_prefix(slow, 1024, stall).await.expect("a steady body was given up on");
        assert!(started.elapsed() > stall, "the test did not outlast one stall");
        assert_eq!(p.head.len(), 40);
        assert!(p.complete);
    }

    #[tokio::test]
    async fn an_empty_body_is_complete_and_empty() {
        let p = read_prefix(body(&[]), 1024, PATIENT).await.unwrap();
        assert!(p.complete);
        assert!(p.head.is_empty());
    }
}

#[cfg(test)]
mod site_table_tests {
    use super::*;

    async fn db() -> (SqlitePool, std::path::PathBuf) {
        let path = std::env::temp_dir()
            .join(format!("easywaf-sites-{}-{}.db", std::process::id(), rand::random::<u32>()));
        let db = crate::db::init(&format!("sqlite://{}", path.display())).await;
        sqlx::raw_sql(
            "INSERT INTO sites (name, server_name, enabled) VALUES ('shop', 'shop.example', 1);
             INSERT INTO site_aliases (site_id, name) VALUES (1, 'www.shop.example');
             INSERT INTO upstreams (site_id, url, weight, enabled) VALUES (1, 'http://10.0.0.1:8080', 1, 1);
             INSERT INTO sites (name, server_name, enabled) VALUES ('old', 'old.example', 0);
             INSERT INTO site_aliases (site_id, name) VALUES (2, 'www.old.example');",
        )
        .execute(&db)
        .await
        .unwrap();
        (db, path)
    }

    #[tokio::test]
    async fn every_name_of_a_site_finds_it_and_a_disabled_one_is_told_apart() {
        let (db, path) = db().await;
        let t = load_sites(&db, 1).await.unwrap();

        let shop = t.enabled.get("shop.example").expect("server_name");
        let www = t.enabled.get("www.shop.example").expect("alias");
        assert!(Arc::ptr_eq(shop, www), "an alias is the same site, not a copy");
        assert_eq!(shop.upstreams.len(), 1);

        // Switched off, under both names: the maintenance page rather than 404.
        assert!(t.disabled.contains("old.example") && t.disabled.contains("www.old.example"));
        assert!(!t.enabled.contains_key("old.example"));
        // A name nobody configured is neither.
        assert!(!t.enabled.contains_key("nobody.example") && !t.disabled.contains("nobody.example"));

        db.close().await;
        for sfx in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{}{sfx}", path.display())); }
    }

    #[tokio::test]
    async fn a_new_backend_is_seen_once_the_generation_moves() {
        // The table is the only thing between a saved change and the proxy,
        // so a write that did not move the generation would never be served.
        let (db, path) = db().await;
        let before = load_sites(&db, 1).await.unwrap();
        let generation = || async {
            sqlx::query_scalar::<_, i64>("SELECT value FROM config_generation WHERE id = 1")
                .fetch_one(&db).await.unwrap()
        };
        let g0 = generation().await;
        sqlx::raw_sql("INSERT INTO upstreams (site_id, url, weight, enabled) VALUES (1, 'http://10.0.0.2:8080', 1, 1)")
            .execute(&db).await.unwrap();
        assert!(generation().await > g0, "adding a backend did not move the generation");

        let after = load_sites(&db, generation().await as u64).await.unwrap();
        assert_eq!(before.enabled["shop.example"].upstreams.len(), 1);
        assert_eq!(after.enabled["shop.example"].upstreams.len(), 2);

        db.close().await;
        for sfx in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{}{sfx}", path.display())); }
    }
}
