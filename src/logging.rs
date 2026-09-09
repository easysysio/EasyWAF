// =========================================================
// logging.rs — EasyWAF
// Flow logs and the audit trail.
//
// Flow lines go to syslog, for a collector. The audit trail
// goes to a local file. There is no local flow file: every
// request is already in traffic_events and shown in Traffic
// Monitor with its verdict, score and rules, so syslog's job
// is to get that stream off the box rather than duplicate it
// beside the database.
//
// One rule governs both: the request path never waits for a
// log. Lines are handed to a bounded channel with try_send
// and a full channel drops them, counting what was lost. A
// proxy that stalls because a disk is slow or a collector is
// gone has turned its logging into an outage.
//
// Operational chatter is not here. That stays on stdout for
// the journal, which is what a systemd service should do.
// =========================================================

use crate::config::LoggingConfig;
use chrono::{DateTime, Utc};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// How many lines may be waiting before new ones are dropped.
///
/// Large enough to absorb a burst — a scanner walking a site produces lines
/// far faster than a disk flush — and small enough that a permanently stuck
/// sink costs bounded memory rather than growing until the process dies.
const QUEUE: usize = 4096;

/// One line, and which file it belongs in.
#[derive(Debug)]
enum Line {
    Flow(String),
    Audit(String),
}

// ─── Logger ──────────────────────────────────────────────

/// The handle held by the rest of the program.
///
/// Cloneable and cheap: it is a channel sender and two counters. Everything
/// that can block — opening files, rotating them, resolving a collector —-
/// happens in the task behind it.
#[derive(Clone)]
pub struct Logger {
    tx:      Option<mpsc::Sender<Line>>,
    dropped: Arc<AtomicU64>,
}

impl Logger {
    /// A logger that discards everything, for tests and for a configuration
    /// with every sink switched off.
    pub fn disabled() -> Self {
        Self { tx: None, dropped: Arc::new(AtomicU64::new(0)) }
    }

    /// Record one proxied request.
    pub fn flow(&self, line: String) {
        self.send(Line::Flow(line));
    }

    /// Record one state-changing action on the management interface.
    pub fn audit(&self, line: String) {
        self.send(Line::Audit(line));
    }

    fn send(&self, line: Line) {
        let Some(tx) = &self.tx else { return };
        // try_send, never send: awaiting here would put the log queue on the
        // request path, which is the one thing this must not do.
        if tx.try_send(line).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ─── init ────────────────────────────────────────────────

/// Start the writer task and return a handle.
///
/// Returns a disabled logger when nothing is switched on, so callers need no
/// conditional and the cost of logging-off is a null check.
///
/// A directory that cannot be created is a warning, not a failure to start: a
/// source build running unprivileged should not refuse to boot because
/// `/var/log/easywaf` is root-owned.
pub fn init(cfg: &LoggingConfig) -> Logger {
    let want_syslog = cfg.syslog.enabled && !cfg.syslog.host.is_empty();
    // The audit log has no switch: an appliance that cannot say who changed it
    // is not one to run, and it is a local file whose only cost is disk.
    let dir = PathBuf::from(&cfg.dir);

    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!(
            dir = %dir.display(),
            "Cannot create the log directory, so flow and audit lines will not be written: {e}"
        );
        return Logger::disabled();
    }

    if cfg.syslog.enabled && cfg.syslog.host.is_empty() {
        tracing::warn!("logging.syslog.enabled is on but logging.syslog.host is empty — not sending");
    }
    if cfg.syslog.enabled && cfg.syslog.protocol != "udp" {
        tracing::warn!(
            protocol = %cfg.syslog.protocol,
            "Only \"udp\" is supported today; syslog will not be sent"
        );
    }

    let (tx, rx) = mpsc::channel(QUEUE);
    let dropped  = Arc::new(AtomicU64::new(0));

    tokio::spawn(writer(
        rx,
        dir,
        cfg.keep_days,
        want_syslog && cfg.syslog.protocol == "udp",
        format!("{}:{}", cfg.syslog.host, cfg.syslog.port),
        dropped.clone(),
    ));

    tracing::info!(
        dir = %cfg.dir, flow_syslog = want_syslog, keep_days = cfg.keep_days,
        "Logging started"
    );
    Logger { tx: Some(tx), dropped }
}

// ─── The writer task ─────────────────────────────────────

/// Owns every file handle and the socket, so nothing else can block on them.
async fn writer(
    mut rx: mpsc::Receiver<Line>,
    dir: PathBuf,
    keep_days: u32,
    to_syslog: bool,
    collector: String,
    dropped: Arc<AtomicU64>,
) {
    let socket = if to_syslog {
        match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::error!("Cannot open a socket for syslog, so nothing will be sent: {e}");
                None
            }
        }
    } else {
        None
    };

    let mut audit = DailyFile::new(dir, "audit", keep_days);

    // Reported rather than left silent: dropped lines are the failure mode of
    // this whole design, so they have to be visible without reading code.
    let mut report = tokio::time::interval(std::time::Duration::from_secs(300));
    report.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_reported = 0u64;

    loop {
        tokio::select! {
            line = rx.recv() => {
                let Some(line) = line else { break };
                match line {
                    Line::Flow(text) => {
                        if let Some(sock) = &socket {
                            send_syslog(sock, &collector, &text).await;
                        }
                    }
                    Line::Audit(text) => audit.write(&text),
                }
            }
            _ = report.tick() => {
                let n = dropped.load(Ordering::Relaxed);
                if n > last_reported {
                    tracing::warn!(
                        total = n, since_last = n - last_reported,
                        "Dropped log lines: a sink is not keeping up"
                    );
                    last_reported = n;
                }
                audit.prune();
            }
        }
    }
}

/// One datagram per line, prefixed with an RFC 3164 priority and timestamp.
///
/// Failures are counted, not logged per line: a collector that has gone away
/// would otherwise produce one error per request, which is its own outage.
async fn send_syslog(sock: &tokio::net::UdpSocket, collector: &str, text: &str) {
    // local0.info — the facility a collector is most likely to be listening on
    // for an appliance, and the severity of a thing that merely happened.
    const PRI: u8 = 16 * 8 + 6;
    let host = hostname();
    let stamp = Utc::now().format("%b %e %H:%M:%S");
    let datagram = format!("<{PRI}>{stamp} {host} easywaf: {text}");
    let _ = sock.send_to(datagram.as_bytes(), collector).await;
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "easywaf".to_string())
}

// ─── DailyFile ───────────────────────────────────────────

/// A file per day, named `<stem>-YYYY-MM-DD.log`, with `<stem>.log` as a
/// symlink to today's.
///
/// Rotation by name rather than by renaming: a reader tailing `flow.log`
/// follows the symlink, and nothing has to move a file another process may
/// have open.
struct DailyFile {
    dir:       PathBuf,
    stem:      String,
    keep_days: u32,
    today:     String,
    handle:    Option<std::fs::File>,
    /// So a permission problem is reported once rather than per line.
    warned:    bool,
}

impl DailyFile {
    fn new(dir: PathBuf, stem: &str, keep_days: u32) -> Self {
        Self {
            dir, stem: stem.to_string(), keep_days,
            today: String::new(), handle: None, warned: false,
        }
    }

    fn write(&mut self, line: &str) {
        let day = Utc::now().format("%Y-%m-%d").to_string();
        if day != self.today || self.handle.is_none() {
            self.open(&day);
            self.today = day;
        }
        if let Some(f) = &mut self.handle
            && writeln!(f, "{line}").is_err()
            && !self.warned
        {
            tracing::warn!(file = %self.path(&self.today).display(), "Cannot write the log file");
            self.warned = true;
        }
    }

    fn path(&self, day: &str) -> PathBuf {
        self.dir.join(format!("{}-{}.log", self.stem, day))
    }

    fn open(&mut self, day: &str) {
        let path = self.path(day);
        match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            Ok(f) => {
                self.handle = Some(f);
                self.warned = false;
                // Point <stem>.log at today, so "tail -F flow.log" keeps working
                // across a rotation without knowing the date.
                let link = self.dir.join(format!("{}.log", self.stem));
                let _ = std::fs::remove_file(&link);
                #[cfg(unix)]
                let _ = std::os::unix::fs::symlink(path.file_name().unwrap_or_default(), &link);
            }
            Err(e) => {
                if !self.warned {
                    tracing::warn!(file = %path.display(), "Cannot open the log file: {e}");
                    self.warned = true;
                }
                self.handle = None;
            }
        }
    }

    /// Delete files older than `keep_days`, so there is nothing to configure in
    /// logrotate. `keep_days = 0` keeps everything.
    fn prune(&self) {
        if self.keep_days == 0 {
            return;
        }
        let cutoff = Utc::now() - chrono::Duration::days(self.keep_days as i64);
        let Ok(entries) = std::fs::read_dir(&self.dir) else { return };
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(day) = name
                .strip_prefix(&format!("{}-", self.stem))
                .and_then(|r| r.strip_suffix(".log"))
            else { continue };
            if let Ok(d) = DateTime::parse_from_str(&format!("{day} 00:00:00 +0000"),
                                                    "%Y-%m-%d %H:%M:%S %z")
                && d.with_timezone(&Utc) < cutoff
            {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// Escape a value for a `key=value` line: quote it only when it contains
/// something that would otherwise split a field, so ordinary lines stay
/// readable by eye.
pub fn field(value: &str) -> String {
    let dirty = value.is_empty()
        || value.contains(|c: char| c.is_whitespace() || c == '"' || c == '=');
    if dirty {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        value.to_string()
    }
}

/// Trim a value that has no business being long, so one enormous URL cannot
/// push a datagram past what a collector will accept.
pub fn clip(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut out: String = value.chars().take(max).collect();
    out.push('…');
    out
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_value_is_left_alone() {
        // Lines are read by eye during an incident as often as by a parser.
        for v in ["GET", "203.0.113.9", "/index.html", "blocked", "913015"] {
            assert_eq!(field(v), v, "{v} should not have been quoted");
        }
    }

    #[test]
    fn anything_that_would_split_a_field_is_quoted() {
        assert_eq!(field("/a b"), "\"/a b\"");
        assert_eq!(field("a=b"),  "\"a=b\"");
        assert_eq!(field(""),     "\"\"");
    }

    #[test]
    fn a_quote_cannot_end_a_field_early() {
        // A path or user agent is attacker-controlled. Without escaping, one
        // containing a quote could forge extra fields in the log — a line that
        // lies is worse than a line that is missing.
        assert_eq!(field(r#"a"b"#),  r#""a\"b""#);
        assert_eq!(field(r#"a\"b"#), r#""a\\\"b""#);
    }

    #[test]
    fn a_long_value_is_clipped_with_a_marker() {
        let long = "x".repeat(300);
        let out  = clip(&long, 64);
        assert_eq!(out.chars().count(), 65, "64 characters plus the marker");
        assert!(out.ends_with('…'), "clipping must be visible, not silent");
    }

    #[test]
    fn clipping_counts_characters_not_bytes() {
        // A URL full of multi-byte characters must not be cut mid-character.
        let s = "é".repeat(100);
        let out = clip(&s, 10);
        assert_eq!(out.chars().count(), 11);
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }

    #[test]
    fn a_disabled_logger_accepts_and_discards() {
        // Callers have no conditional, so this must be safe to call always.
        let l = Logger::disabled();
        l.flow("anything".into());
        l.audit("anything".into());
        assert_eq!(l.dropped.load(Ordering::Relaxed), 0,
                   "a disabled logger is not a dropping logger");
    }

    #[tokio::test]
    async fn a_full_queue_drops_rather_than_waits() {
        // The property the request path depends on: sending must never block,
        // however far behind the writer is.
        let (tx, _rx) = mpsc::channel(1);
        let l = Logger { tx: Some(tx), dropped: Arc::new(AtomicU64::new(0)) };
        for _ in 0..50 {
            l.flow("line".into());
        }
        let dropped = l.dropped.load(Ordering::Relaxed);
        assert!(dropped >= 48, "expected most of 50 to be dropped, got {dropped}");
    }
}
