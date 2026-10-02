// =========================================================
// slow_clients.rs — EasyWAF
// A limit on how long a connection may take to send a
// request.
//
// A connection that never finishes its headers — or never
// sends anything at all — is otherwise held open for ever,
// and each one holds a file descriptor. A thousand of them, a
// "slow loris", and every site and the management interface
// stop answering. Every listener EasyWAF opens goes through
// `limit`, so none is left without it.
//
// Two timers cover it. hyper's header timeout runs once a
// request has begun to arrive, and again while a kept-alive
// connection waits for its next request. Nothing covers a
// connection that has sent no bytes yet — the server reads the
// first few to tell HTTP/1 from HTTP/2 before any timer
// starts — so each accepted connection is wrapped to give its
// first read the same deadline. That holds after a TLS
// handshake too: the wrapper is around the decrypted stream.
//
// Neither timer exists for HTTP/2, and the server would speak
// it to any client that opened with its preface — advertised
// or not — and then wait on that connection for ever. EasyWAF
// serves HTTP/1.1 only, so the same wrapper ends a connection
// that opens that way.
//
// The timers bound how long one connection can be held, not
// how many. So one address may hold only so many connections
// at once: without that, a single machine opening them faster
// than they time out reaches the descriptor limit anyway.
// =========================================================

use axum_server::accept::Accept;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// How long a client has to send a request's headers, to send anything at all
/// on a new connection, and how long a kept-alive connection may sit idle
/// before its next request. Thirty seconds is far longer than any client needs.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How many connections one address may hold open at once, across every
/// listener. An IPv6 client is counted by its /64, as Smart Protect counts it:
/// one address there costs nothing, so a limit on one limits nobody.
///
/// A browser opens about six to a site, so this is far above one person, an
/// office behind one address, or a busy API client — and far below the 65,536
/// descriptors the service is given, so no single address can use them up. A
/// trusted proxy is exempt: every client behind it arrives from its address.
pub const MAX_CONNECTIONS_PER_ADDRESS: u32 = 1024;

/// Apply the limits to a listener.
pub fn limit<A, Acc>(mut server: axum_server::Server<A, Acc>) -> axum_server::Server<A, Guard<Acc>>
where
    A: axum_server::Address,
{
    server
        .http_builder()
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    server.map(|inner| Guard { inner })
}

/// An acceptor that gives every connection it accepts a deadline for its first
/// read.
#[derive(Clone)]
pub struct Guard<A> {
    inner: A,
}

impl<A, S> Accept<TcpStream, S> for Guard<A>
where
    A: Accept<TcpStream, S>,
    A::Future: Send + 'static,
    A::Stream: Send,
    A::Service: Send,
{
    type Stream = FirstRead<A::Stream>;
    type Service = A::Service;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        // Counted before anything else is done for the connection — a TLS
        // handshake included — and released when the connection is dropped.
        let slot = stream.peer_addr().ok().map(|peer| Slot::take(peer.ip()));
        let accepting = self.inner.accept(stream, service);
        Box::pin(async move {
            let slot = match slot {
                Some(Some(slot)) => Some(slot),
                Some(None) => return Err(io::Error::other("too many connections from this address")),
                // No peer address to count against: not refused for that.
                None => None,
            };
            let (stream, service) = accepting.await?;
            Ok((FirstRead::new(stream, HEADER_READ_TIMEOUT, slot), service))
        })
    }
}

// ─── Connections per address ─────────────────────────────

fn open_connections() -> &'static Mutex<HashMap<IpAddr, u32>> {
    static OPEN: OnceLock<Mutex<HashMap<IpAddr, u32>>> = OnceLock::new();
    OPEN.get_or_init(|| Mutex::new(HashMap::new()))
}

/// One of an address's connections. Dropping it gives the place back.
pub struct Slot {
    /// What the connection is counted against: the address, or its /64.
    /// `None` for an address that is not counted.
    counted: Option<IpAddr>,
}

impl Slot {
    /// Take a place for a connection from `address`, or `None` if it already
    /// holds as many as it may.
    fn take(address: IpAddr) -> Option<Slot> {
        Self::take_within(address, MAX_CONNECTIONS_PER_ADDRESS)
    }

    fn take_within(address: IpAddr, limit: u32) -> Option<Slot> {
        // A v4 address written as v6 is the v4 address it is, for the trusted
        // list as much as for the count.
        let address = match address {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
            v4 => v4,
        };
        if crate::forwarded::is_trusted_proxy(address) {
            return Some(Slot { counted: None });
        }
        let unit = crate::smart_protect::unit(address);
        let mut open = open_connections().lock().unwrap_or_else(|p| p.into_inner());
        let held = open.entry(unit).or_insert(0);
        if *held >= limit {
            drop(open);
            refused(unit);
            return None;
        }
        *held += 1;
        Some(Slot { counted: Some(unit) })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let Some(unit) = self.counted else { return };
        let mut open = open_connections().lock().unwrap_or_else(|p| p.into_inner());
        if let Some(held) = open.get_mut(&unit) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                open.remove(&unit);
            }
        }
    }
}

/// Say that an address was refused a connection — at most once a minute, since
/// the address doing it is by definition doing it a great deal.
fn refused(unit: IpAddr) {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let last = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(last) >= 60
        && LAST.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_ok()
    {
        tracing::warn!(
            address = %crate::smart_protect::unit_label(unit),
            "Refusing connections: this address already holds {MAX_CONNECTIONS_PER_ADDRESS}, the most one address may"
        );
    }
}

/// How every HTTP/2 connection begins (RFC 9113, section 3.4). No HTTP/1
/// request can: `PRI` is a method reserved so that it never will.
const HTTP2_OPENING: &[u8; 4] = b"PRI ";

/// A connection whose first read must complete before a deadline, and which
/// must not open as HTTP/2. After that it is the connection it wraps, and
/// hyper's own timer takes over.
pub struct FirstRead<S> {
    inner:    S,
    /// Present until the first read completes.
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    /// The connection's first bytes, kept until there are enough to tell
    /// whether it opened as HTTP/2 — they need not arrive in one read.
    opening:  Option<Vec<u8>>,
    /// The connection's place among its address's connections, held for as
    /// long as the connection lives.
    _slot:    Option<Slot>,
}

impl<S> FirstRead<S> {
    fn new(inner: S, within: Duration, slot: Option<Slot>) -> Self {
        Self {
            inner,
            deadline: Some(Box::pin(tokio::time::sleep(within))),
            opening:  Some(Vec::with_capacity(HTTP2_OPENING.len())),
            _slot:    slot,
        }
    }

    /// Look at bytes just read. `false` once the connection is known to have
    /// opened as HTTP/2; `true` while that is undecided or ruled out.
    fn may_continue(&mut self, read: &[u8]) -> bool {
        let Some(seen) = self.opening.as_mut() else { return true };
        let wanted = HTTP2_OPENING.len() - seen.len();
        seen.extend_from_slice(&read[..read.len().min(wanted)]);

        if !HTTP2_OPENING.starts_with(seen) {
            // Ruled out: nothing more to watch for on this connection.
            self.opening = None;
            return true;
        }
        seen.len() < HTTP2_OPENING.len()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FirstRead<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(read) => {
                this.deadline = None;
                if read.is_ok() && this.opening.is_some() && !this.may_continue(&buf.filled()[before..]) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the connection opened as HTTP/2, which is not served",
                    )));
                }
                Poll::Ready(read)
            }
            Poll::Pending => {
                // Still waiting for the first bytes: has the deadline passed?
                if let Some(deadline) = this.deadline.as_mut()
                    && deadline.as_mut().poll(cx).is_ready()
                {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "nothing was sent on the connection in time",
                    )));
                }
                Poll::Pending
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FirstRead<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn a_connection_that_sends_nothing_is_ended_at_the_deadline() {
        let (client, server) = tokio::io::duplex(64);
        let mut guarded = FirstRead::new(server, Duration::from_millis(50), None);
        let mut buf = [0u8; 8];
        let err = guarded.read(&mut buf).await.expect_err("a silent connection was left waiting");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        drop(client);
    }

    #[tokio::test]
    async fn once_something_arrives_the_deadline_is_gone() {
        let (mut client, server) = tokio::io::duplex(64);
        let mut guarded = FirstRead::new(server, Duration::from_millis(50), None);
        client.write_all(b"GET").await.unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(guarded.read(&mut buf).await.unwrap(), 3);

        // Long past the deadline, the connection is still simply waiting: what
        // limits it from here is hyper's own timer, not this one.
        tokio::time::sleep(Duration::from_millis(120)).await;
        client.write_all(b" /").await.unwrap();
        assert_eq!(guarded.read(&mut buf).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn a_connection_that_opens_as_http2_is_ended() {
        let (mut client, server) = tokio::io::duplex(64);
        let mut guarded = FirstRead::new(server, Duration::from_secs(5), None);
        client.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.unwrap();
        let mut buf = [0u8; 64];
        let err = guarded.read(&mut buf).await.expect_err("an HTTP/2 connection was served");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// The opening need not arrive in one piece, and a client that wanted to
    /// get past a check on the first read would see to it that it did not.
    #[tokio::test]
    async fn an_http2_opening_sent_a_byte_at_a_time_is_still_ended() {
        let (mut client, server) = tokio::io::duplex(64);
        let mut guarded = FirstRead::new(server, Duration::from_secs(5), None);
        let mut buf = [0u8; 1];
        for (i, byte) in b"PRI ".iter().enumerate() {
            client.write_all(&[*byte]).await.unwrap();
            let read = guarded.read(&mut buf).await;
            if i < 3 {
                assert_eq!(read.unwrap(), 1, "byte {i} was refused before the opening was complete");
            } else {
                assert_eq!(read.expect_err("served").kind(), io::ErrorKind::InvalidData);
            }
        }
    }

    #[tokio::test]
    async fn http1_requests_are_read_untouched_whatever_they_start_with() {
        for request in [&b"GET / HTTP/1.1\r\n"[..], b"POST /x HTTP/1.1\r\n", b"PATCH /p HTTP/1.1\r\n",
                        b"PROPFIND / HTTP/1.1\r\n", b"PRI", b"P"] {
            let (mut client, server) = tokio::io::duplex(64);
            let mut guarded = FirstRead::new(server, Duration::from_secs(5), None);
            client.write_all(request).await.unwrap();
            drop(client);
            let mut got = Vec::new();
            guarded.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, request, "{:?}", String::from_utf8_lossy(request));
        }
    }

    #[test]
    fn an_ipv6_client_is_counted_by_its_64() {
        let one:   IpAddr = "2001:db8:61:1::1".parse().unwrap();
        let other: IpAddr = "2001:db8:61:1:ffff::2".parse().unwrap();
        let away:  IpAddr = "2001:db8:61:2::1".parse().unwrap();
        let _held: Vec<Slot> = (0..2).map(|_| Slot::take_within(one, 2).expect("under the limit")).collect();
        assert!(Slot::take_within(other, 2).is_none(), "another address in the same /64 got a place");
        assert!(Slot::take_within(away, 2).is_some(), "a different /64 was refused with it");
    }

    #[test]
    fn an_address_holds_only_so_many_connections_and_gets_them_back() {
        let a: IpAddr = "198.51.100.61".parse().unwrap();
        let b: IpAddr = "198.51.100.62".parse().unwrap();
        let held: Vec<Slot> = (0..3).map(|_| Slot::take_within(a, 3).expect("under the limit")).collect();
        assert!(Slot::take_within(a, 3).is_none(), "a fourth connection was accepted");
        assert!(Slot::take_within(b, 3).is_some(), "another address was refused with it");

        // Closing one makes room for one.
        drop(held.into_iter().next());
        // (the iterator dropped the rest too: all three places are back)
        let again: Vec<Option<Slot>> = (0..3).map(|_| Slot::take_within(a, 3)).collect();
        assert!(again.iter().all(Option::is_some), "places were not given back");
        assert!(Slot::take_within(a, 3).is_none());
    }
}
