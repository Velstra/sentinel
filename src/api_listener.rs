//! The management listener's connection budget (CTRL-05).
//!
//! The API used to serve every TCP connection it accepted for as long as the
//! client cared to keep it: hyper's header-read timeout needs a timer, and none
//! was configured, so a client trickling one header line a second held its
//! connection indefinitely. The unit ran with the default 1024 descriptors, and
//! about a thousand such connections from one unauthenticated source took the
//! console, sign-in, commit-confirm and HA config-sync receive dark together.
//!
//! Three bounds now apply before any request is read:
//! - **a header-read deadline** — a request head must arrive whole within
//!   [`Limits::header_read_timeout`], however slowly it trickles;
//! - **per-source and total connection caps** — a connection over either is
//!   closed as soon as it is accepted, before TLS, so one source cannot hold
//!   more than its share and all sources together cannot exhaust descriptors;
//! - **a descriptor limit** on the unit well above the total cap (`flake.nix`).
//!
//! A source is an IPv4 address or an IPv6 /64, the same unit the sign-in
//! budgets count ([`crate::api_throttle::source`]).

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum_server::accept::{Accept, DefaultAcceptor};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// How many connections the listener holds open, and how long a request head
/// may take to arrive.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub per_source: usize,
    pub per_network: usize,
    pub total: usize,
    pub header_read_timeout: Duration,
}

/// The appliance's limits. A console opens a handful of connections, a stack
/// view and config-sync peer a few more; 32 per source leaves room for a busy
/// operator workstation behind NAT. A network (IPv4 /24, IPv6 /48 — what one
/// party typically holds) gets 256, so filling the 4096 total takes sixteen
/// unrelated networks, and 4096 stays far below the unit's descriptor limit.
pub(crate) const LIMITS: Limits = Limits {
    per_source: 32,
    per_network: 256,
    total: 4096,
    header_read_timeout: Duration::from_secs(10),
};

/// How long a request body may take to arrive once its head has. hyper's
/// header deadline ends when the head is complete; a body trickled a byte at a
/// time would otherwise hold its connection for as long as the client liked.
pub(crate) const BODY_DEADLINE: Duration = Duration::from_secs(30);

/// How long a body may take, and the most of it that is buffered.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BodyBound {
    pub deadline: Duration,
    pub limit: usize,
}

/// For authenticated routes: above every route's own limit (2 MiB by
/// default), which the handler still enforces on the buffered body. Applied
/// after authentication, so an anonymous client cannot make the server buffer
/// it.
pub(crate) const AUTHENTICATED_BODY: BodyBound = BodyBound {
    deadline: BODY_DEADLINE,
    limit: 4 * 1024 * 1024,
};

/// For the sign-in form, the one body an anonymous client may send.
pub(crate) const SIGN_IN_BODY: BodyBound = BodyBound {
    deadline: BODY_DEADLINE,
    limit: 64 * 1024,
};

/// How often an HTTP/2 connection is pinged, and how long a ping may go
/// unanswered before the connection is closed: a vanished peer must not hold
/// its slot forever either.
const H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Default)]
struct Counts {
    total: usize,
    per_source: HashMap<IpAddr, usize>,
    per_network: HashMap<IpAddr, usize>,
}

/// The network a source belongs to: its IPv4 /24 or IPv6 /48.
fn network(source: IpAddr) -> IpAddr {
    match source {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            IpAddr::from([a, b, c, 0])
        }
        IpAddr::V6(v6) => {
            let mut bytes = v6.octets();
            bytes[6..].fill(0);
            IpAddr::from(bytes)
        }
    }
}

fn release(map: &mut HashMap<IpAddr, usize>, key: &IpAddr) {
    if let Some(held) = map.get_mut(key) {
        *held = held.saturating_sub(1);
        if *held == 0 {
            map.remove(key);
        }
    }
}

/// The open-connection counts every accepted connection is charged to.
pub(crate) struct Slots {
    counts: Mutex<Counts>,
    limits: Limits,
}

impl Slots {
    pub(crate) fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            counts: Mutex::default(),
            limits,
        })
    }

    fn counts(&self) -> std::sync::MutexGuard<'_, Counts> {
        self.counts.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Charge one connection from `peer`, or `None` when it is over a cap.
    fn acquire(self: &Arc<Self>, peer: IpAddr) -> Option<Slot> {
        let source = crate::api_throttle::source(peer);
        let network = network(source);
        let mut counts = self.counts();
        let held = counts.per_source.get(&source).copied().unwrap_or(0);
        let in_network = counts.per_network.get(&network).copied().unwrap_or(0);
        if counts.total >= self.limits.total
            || held >= self.limits.per_source
            || in_network >= self.limits.per_network
        {
            return None;
        }
        counts.total += 1;
        counts.per_source.insert(source, held + 1);
        counts.per_network.insert(network, in_network + 1);
        Some(Slot {
            slots: Arc::clone(self),
            source,
        })
    }
}

/// One open connection's charge, released when the connection is dropped.
pub(crate) struct Slot {
    slots: Arc<Slots>,
    source: IpAddr,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut counts = self.slots.counts();
        counts.total = counts.total.saturating_sub(1);
        release(&mut counts.per_source, &self.source);
        release(&mut counts.per_network, &network(self.source));
    }
}

/// A stream that carries its connection's [`Slot`].
pub(crate) struct Held<S> {
    inner: S,
    _slot: Slot,
}

impl<S: AsyncRead + Unpin> AsyncRead for Held<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Held<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// An acceptor that charges each connection to its source before handing it
/// to `inner` (TLS, or nothing), and closes it when a cap is reached.
#[derive(Clone)]
pub(crate) struct Limited<A> {
    inner: A,
    slots: Arc<Slots>,
}

impl<A> Limited<A> {
    pub(crate) fn new(inner: A, slots: Arc<Slots>) -> Self {
        Self { inner, slots }
    }
}

type Accepting<T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send>>;

impl<A, S> Accept<TcpStream, S> for Limited<A>
where
    A: Accept<Held<TcpStream>, S>,
    A::Future: Send + 'static,
    A::Stream: Send + 'static,
    A::Service: Send + 'static,
{
    type Stream = A::Stream;
    type Service = A::Service;
    type Future = Accepting<(A::Stream, A::Service)>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let slot = stream
            .peer_addr()
            .ok()
            .and_then(|peer| self.slots.acquire(peer.ip()));
        match slot {
            Some(slot) => Box::pin(self.inner.accept(
                Held {
                    inner: stream,
                    _slot: slot,
                },
                service,
            )),
            // Dropping the stream closes it; the error tells axum-server not to
            // serve it. Nothing is logged per refusal: a flood would fill the
            // journal as quickly as it fills the table.
            None => Box::pin(std::future::ready(Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "management connection limit reached",
            )))),
        }
    }
}

/// Where to listen: an address to bind (production — tokio sets
/// `SO_REUSEADDR`, so a restart rebinds past TIME_WAIT), or a bound listener
/// (tests, which need port 0).
pub(crate) enum Listen {
    Bind(SocketAddr),
    #[cfg_attr(not(test), allow(dead_code))]
    Bound(std::net::TcpListener),
}

/// Serve `app` on `listen`, over TLS when `tls` is set, inside `limits`.
pub(crate) async fn serve(
    listen: Listen,
    app: Router,
    tls: Option<axum_server::tls_rustls::RustlsConfig>,
    limits: Limits,
) -> io::Result<()> {
    let slots = Slots::new(limits);
    let server = match listen {
        Listen::Bind(addr) => axum_server::bind(addr),
        Listen::Bound(listener) => {
            listener.set_nonblocking(true)?;
            axum_server::from_tcp(listener)
        }
    };
    // `SocketAddr` connect info so the sign-in and bearer budgets see the peer
    // address; without it every request would look like it came from nowhere.
    let make = app.into_make_service_with_connect_info::<SocketAddr>();
    match tls {
        Some(tls) => {
            let acceptor = axum_server::tls_rustls::RustlsAcceptor::new(tls);
            let mut server = server.acceptor(Limited::new(acceptor, slots));
            bound_requests(server.http_builder(), limits);
            server.serve(make).await
        }
        None => {
            let mut server = server.acceptor(Limited::new(DefaultAcceptor::new(), slots));
            bound_requests(server.http_builder(), limits);
            server.serve(make).await
        }
    }
}

/// Read a request's body within `deadline` of its head, or answer 408.
///
/// Bodies are buffered (up to the bound's limit, else 413) before the handler
/// runs; every handler reads its whole body anyway, and the per-route body
/// limits still apply to the buffered body. Requests that carry no body by
/// method are passed straight through, so the telemetry stream is untouched.
pub(crate) async fn bounded_body(
    axum::extract::State(bound): axum::extract::State<BodyBound>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::{Method, StatusCode};
    use axum::response::IntoResponse;
    if matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    match tokio::time::timeout(bound.deadline, axum::body::to_bytes(body, bound.limit)).await {
        Ok(Ok(bytes)) => {
            next.run(axum::extract::Request::from_parts(
                parts,
                axum::body::Body::from(bytes),
            ))
            .await
        }
        Ok(Err(_)) => (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response(),
        Err(_) => (
            StatusCode::REQUEST_TIMEOUT,
            "request body arrived too slowly",
        )
            .into_response(),
    }
}

/// hyper enforces its header-read timeout and HTTP/2 keep-alive only with a
/// timer, and axum-server configures none.
fn bound_requests(
    builder: &mut hyper_util::server::conn::auto::Builder<hyper_util::rt::TokioExecutor>,
    limits: Limits,
) {
    builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout);
    builder
        .http2()
        .timer(hyper_util::rt::TokioTimer::new())
        .keep_alive_interval(H2_KEEPALIVE_INTERVAL)
        .keep_alive_timeout(H2_KEEPALIVE_TIMEOUT);
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn app() -> Router {
        Router::new().route("/api/v1/health", get(|| async { "ok" }))
    }

    /// A real listener on 127.0.0.1:0, served in the background.
    async fn start(limits: Limits) -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(Listen::Bound(listener), app(), None, limits));
        addr
    }

    async fn connect_from(local: &str, addr: SocketAddr) -> TcpStream {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind(format!("{local}:0").parse().unwrap()).unwrap();
        socket.connect(addr).await.unwrap()
    }

    /// Whether the server closed `stream` within `within`.
    async fn closed_within(stream: &mut TcpStream, within: Duration) -> bool {
        let mut buf = [0u8; 512];
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            match tokio::time::timeout(left, stream.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => return true,
                Ok(Ok(_)) => continue,
                Err(_) => return false,
            }
        }
    }

    async fn health(stream: &mut TcpStream) -> String {
        stream
            .write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = String::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_string(&mut out))
            .await
            .unwrap()
            .unwrap();
        out
    }

    /// CTRL-05, the audit's own probe: a request head trickled one line at a
    /// time. Before the fix it stayed open for as long as it trickled.
    #[tokio::test]
    async fn a_trickled_request_head_is_cut_off_at_the_deadline() {
        let limits = Limits {
            per_source: 8,
            per_network: 8,
            total: 8,
            header_read_timeout: Duration::from_millis(800),
        };
        let addr = start(limits).await;
        let mut slow = TcpStream::connect(addr).await.unwrap();
        slow.write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: t\r\n")
            .await
            .unwrap();
        let started = Instant::now();
        let mut cut = false;
        while started.elapsed() < Duration::from_secs(6) {
            tokio::time::sleep(Duration::from_millis(200)).await;
            if slow.write_all(b"X-Trickle: 1\r\n").await.is_err() {
                cut = true;
                break;
            }
            if closed_within(&mut slow, Duration::from_millis(50)).await {
                cut = true;
                break;
            }
        }
        assert!(
            cut,
            "a trickled head was still open after {:?}",
            started.elapsed()
        );
        assert!(started.elapsed() < Duration::from_secs(4));
        // A prompt client is still served.
        let mut prompt = TcpStream::connect(addr).await.unwrap();
        assert!(health(&mut prompt).await.starts_with("HTTP/1.1 200"));
    }

    /// One source cannot hold more than its share; another source still gets
    /// in, and a released slot is reusable.
    #[tokio::test]
    async fn one_source_is_capped_and_others_are_still_served() {
        let limits = Limits {
            per_source: 3,
            per_network: 16,
            total: 16,
            header_read_timeout: Duration::from_secs(30),
        };
        let addr = start(limits).await;
        let mut held = Vec::new();
        for _ in 0..3 {
            held.push(connect_from("127.0.0.1", addr).await);
        }
        // Give the server a moment to have accepted the three.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut over = connect_from("127.0.0.1", addr).await;
        assert!(
            closed_within(&mut over, Duration::from_secs(2)).await,
            "a fourth connection from one source was kept"
        );
        let mut other = connect_from("127.0.0.2", addr).await;
        assert!(health(&mut other).await.starts_with("HTTP/1.1 200"));
        drop(held.pop());
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut again = connect_from("127.0.0.1", addr).await;
        assert!(health(&mut again).await.starts_with("HTTP/1.1 200"));
    }

    /// Many sources of one network cannot take more than the network's share;
    /// another network still gets in.
    #[tokio::test]
    async fn one_network_is_capped_across_its_sources() {
        let limits = Limits {
            per_source: 8,
            per_network: 3,
            total: 64,
            header_read_timeout: Duration::from_secs(30),
        };
        let addr = start(limits).await;
        let mut held = Vec::new();
        for n in 1..=3 {
            held.push(connect_from(&format!("127.0.0.{n}"), addr).await);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut over = connect_from("127.0.0.4", addr).await;
        assert!(
            closed_within(&mut over, Duration::from_secs(2)).await,
            "a fourth source of one /24 got a connection past the network cap"
        );
        let mut elsewhere = connect_from("127.0.1.1", addr).await;
        assert!(health(&mut elsewhere).await.starts_with("HTTP/1.1 200"));
    }

    /// A body trickled after a prompt head is cut off at the body deadline
    /// with 408; a prompt body is served.
    #[tokio::test]
    async fn a_trickled_request_body_is_cut_off() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route(
                "/echo",
                axum::routing::post(|body: String| async move { body }),
            )
            .layer(axum::middleware::from_fn_with_state(
                BodyBound {
                    deadline: Duration::from_millis(600),
                    limit: 1024,
                },
                bounded_body,
            ));
        tokio::spawn(serve(Listen::Bound(listener), app, None, LIMITS));
        let mut slow = TcpStream::connect(addr).await.unwrap();
        slow.write_all(b"POST /echo HTTP/1.1\r\nHost: t\r\nContent-Length: 100\r\n\r\nx")
            .await
            .unwrap();
        let started = Instant::now();
        let mut answer = Vec::new();
        let mut buf = [0u8; 256];
        while started.elapsed() < Duration::from_secs(5) {
            let _ = slow.write_all(b"x").await;
            match tokio::time::timeout(Duration::from_millis(200), slow.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => break,
                Ok(Ok(n)) => {
                    answer.extend_from_slice(&buf[..n]);
                    break;
                }
                Err(_) => {}
            }
        }
        let answer = String::from_utf8_lossy(&answer);
        assert!(
            answer.starts_with("HTTP/1.1 408"),
            "{answer:?} after {:?}",
            started.elapsed()
        );
        assert!(started.elapsed() < Duration::from_secs(3));
        let mut prompt = TcpStream::connect(addr).await.unwrap();
        prompt
            .write_all(b"POST /echo HTTP/1.1\r\nHost: t\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        let mut out = String::new();
        prompt.read_to_string(&mut out).await.unwrap();
        assert!(
            out.starts_with("HTTP/1.1 200") && out.ends_with("ok"),
            "{out}"
        );
    }

    /// All sources together cannot exceed the total either.
    #[tokio::test]
    async fn the_total_is_capped_across_sources() {
        let limits = Limits {
            per_source: 8,
            per_network: 8,
            total: 4,
            header_read_timeout: Duration::from_secs(30),
        };
        let addr = start(limits).await;
        let mut held = Vec::new();
        for n in 1..=4 {
            held.push(connect_from(&format!("127.0.0.{n}"), addr).await);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut over = connect_from("127.0.0.9", addr).await;
        assert!(closed_within(&mut over, Duration::from_secs(2)).await);
        drop(held);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut again = connect_from("127.0.0.9", addr).await;
        assert!(health(&mut again).await.starts_with("HTTP/1.1 200"));
    }
}
