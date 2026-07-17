//! The proxy accept loop and per-connection handling.
//!
//! A forward proxy for Android's Global HTTP Proxy sees two request shapes:
//!
//!   * `CONNECT host:port`  — an HTTPS/TLS tunnel. We log `host:port` and the
//!     resolved destination IP, then relay the opaque byte stream in both
//!     directions. We never decrypt — the domain (from the CONNECT line) and
//!     the IP are all we want.
//!   * absolute-form HTTP   — cleartext. We can see and log the full URL, then
//!     forward the request (request-line rewritten to origin-form) and relay
//!     the rest of the stream.
//!
//! Every established relay is bounded by an idle timeout so a stalled peer
//! cannot pin sockets and connection permits indefinitely.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};

use crate::blocklist::BlockList;
use crate::config::Config;
use crate::http::{self, RequestHead, Target};
use crate::logger::{HttpRecord, Logger};

/// Hard cap on the request head we buffer before giving up. Real heads are a
/// few KB; anything larger is abuse or a non-HTTP client.
const MAX_HEAD: usize = 64 * 1024;

/// Chunk size for reading and pre-allocating the request head.
const HEAD_CHUNK: usize = 8 * 1024;

/// Relay copy-buffer size per direction. 64 KiB measured ~20% higher loopback
/// throughput than 16/32 KiB (fewer read/write syscalls per MB) while keeping
/// worst-case relay memory bounded: `RELAY_BUF * 2 * max_conns`, i.e. 128 MiB at
/// the default `max_conns = 1024`. Raise `max_conns` with that multiplier in mind.
const RELAY_BUF: usize = 64 * 1024;

/// Monotonic per-connection id, used to correlate open/close/error log lines.
static CONN_ID: AtomicU64 = AtomicU64::new(1);

/// Per-connection context threaded through the handlers, so they don't each
/// carry `id`/`peer`/`cfg`/`logger` as separate parameters.
struct Conn<'a> {
    id: u64,
    peer: SocketAddr,
    cfg: &'a Config,
    logger: &'a Logger,
    blocklist: &'a BlockList,
}

impl Conn<'_> {
    /// The download byte cap for `host`: `Some(block_cap)` if the destination is
    /// soft-blocked, else `None` (relay uncapped).
    fn download_cap(&self, host: &str) -> Option<u64> {
        self.blocklist
            .is_blocked(host)
            .then_some(self.cfg.block_cap)
    }
}

/// Bind, then accept connections until the shutdown signal fires.
pub async fn run(cfg: Config, logger: Logger) -> io::Result<()> {
    // Soft-blocking is gated by the `blocking` switch: when off, the configured
    // list is ignored entirely (and its file isn't even read). Build it up front
    // so a bad file fails fast, before binding.
    let blocklist = if cfg.blocking {
        BlockList::build(&cfg.block, &cfg.blocklist_files)?
    } else {
        BlockList::default()
    };

    let listener = TcpListener::bind(&cfg.listen).await?;
    let local = listener.local_addr()?;
    logger.info(format!(
        "LISTEN {local} (max_conns={}, connect_timeout={}s, idle_timeout={}s)",
        cfg.max_conns,
        cfg.connect_timeout.as_secs(),
        cfg.idle_timeout.as_secs(),
    ));
    let list_configured = !cfg.block.is_empty() || !cfg.blocklist_files.is_empty();
    if !blocklist.is_empty() {
        logger.info(format!(
            "blocking: on — {} domain(s), soft-block cap={}B",
            blocklist.len(),
            cfg.block_cap
        ));
    } else if cfg.blocking && list_configured {
        logger.info("blocking: on, but the block list is empty — nothing will be blocked");
    } else if list_configured {
        logger.info("blocking: off (a block list is configured; set `blocking = on` to enable)");
    }

    let sem = Arc::new(Semaphore::new(cfg.max_conns));
    let cfg = Arc::new(cfg);
    let blocklist = Arc::new(blocklist);

    // Graceful shutdown on Ctrl-C (SIGINT). One future, reused across the loop.
    // If the signal can't be registered — as happens in some containers — this
    // never fires and the proxy simply runs until it's killed (`docker stop`
    // sends SIGTERM), rather than mistaking the *failure* to register for a
    // shutdown request (which would exit immediately in a restart loop).
    let shutdown = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    tokio::pin!(shutdown);

    loop {
        // Back-pressure: block accepting new sockets while at the connection
        // cap. Race against shutdown so ctrl_c stays responsive even when every
        // permit is held (otherwise the loop would park here, deaf to signals).
        let permit = tokio::select! {
            p = sem.clone().acquire_owned() => p.expect("semaphore never closed"),
            () = &mut shutdown => {
                logger.info("SHUTDOWN signal received, stopping accept loop");
                return Ok(());
            }
        };

        let accepted = tokio::select! {
            res = listener.accept() => res,
            () = &mut shutdown => {
                logger.info("SHUTDOWN signal received, stopping accept loop");
                return Ok(());
            }
        };

        let (client, peer) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                logger.info(format!("ACCEPT-ERR {e}"));
                drop(permit); // return the permit; keep serving
                continue;
            }
        };

        let logger = logger.clone();
        let cfg = cfg.clone();
        let blocklist = blocklist.clone();
        tokio::spawn(async move {
            let _permit = permit; // released on task completion
            let id = CONN_ID.fetch_add(1, Ordering::Relaxed);
            let conn = Conn {
                id,
                peer,
                cfg: cfg.as_ref(),
                logger: &logger,
                blocklist: blocklist.as_ref(),
            };
            if let Err(e) = handle(&conn, client).await {
                // Most errors here are benign (client hung up, reset, timeout).
                logger.info(format!("[#{id}] CONN-ERR {peer} {e}"));
            }
        });
    }
}

/// Read the request head, decide CONNECT vs HTTP, dispatch.
async fn handle(conn: &Conn<'_>, mut client: TcpStream) -> io::Result<()> {
    client.set_nodelay(true).ok();

    let mut buf = Vec::with_capacity(HEAD_CHUNK);
    let head_end = timeout(conn.cfg.head_timeout, read_head(&mut client, &mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request head read timeout"))??;

    let head = RequestHead::parse(&buf[..head_end])
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unparseable request head"))?;

    // Bytes the client already sent past the head (a pipelined request body,
    // or — rarely — early TLS bytes after CONNECT). Must be forwarded first.
    let leftover = &buf[head_end..];

    match &head.target {
        Target::Connect { host, port } => handle_connect(conn, client, host, *port, leftover).await,
        Target::Http { .. } => handle_http(conn, client, &head, &buf[..head_end], leftover).await,
    }
}

/// Establish a TLS tunnel and relay bytes without inspecting them.
async fn handle_connect(
    conn: &Conn<'_>,
    mut client: TcpStream,
    host: &str,
    port: u16,
    leftover: &[u8],
) -> io::Result<()> {
    let started = Instant::now();
    let target = format!("{host}:{port}");
    let cap = conn.download_cap(host);

    let mut upstream = match dial(host, port, conn.cfg).await {
        Ok(s) => s,
        Err(reply) => {
            conn.logger
                .failed(conn.id, "CONNECT", &target, conn.peer, &reply.why);
            let _ = write_with_timeout(&mut client, reply.status, conn.cfg.connect_timeout).await;
            return Ok(());
        }
    };
    let ip = peer_ip(&upstream);

    conn.logger
        .connect(conn.id, host, port, &ip, conn.peer, cap.is_some());

    write_with_timeout(
        &mut client,
        b"HTTP/1.1 200 Connection Established\r\n\r\n",
        conn.cfg.connect_timeout,
    )
    .await?;

    // Bytes we hand to upstream directly (before relay) still count as sent.
    let mut pre_sent = 0u64;
    if !leftover.is_empty() {
        write_with_timeout(&mut upstream, leftover, conn.cfg.connect_timeout).await?;
        pre_sent += leftover.len() as u64;
    }

    let (sent, recv) = relay(&mut client, &mut upstream, idle(conn.cfg), cap).await;

    conn.logger.close(
        conn.id,
        &target,
        sent + pre_sent,
        recv,
        started.elapsed().as_millis(),
    );
    Ok(())
}

/// Forward a cleartext HTTP request and relay the rest of the connection.
async fn handle_http(
    conn: &Conn<'_>,
    mut client: TcpStream,
    head: &RequestHead,
    whole_head: &[u8],
    leftover: &[u8],
) -> io::Result<()> {
    // `head` is dispatched here only for the HTTP variant; extract its fields.
    let Target::Http { host, port, url } = &head.target else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "handle_http called with a non-HTTP target",
        ));
    };
    let port = *port;
    let cap = conn.download_cap(host);
    let started = Instant::now();

    let mut upstream = match dial(host, port, conn.cfg).await {
        Ok(s) => s,
        Err(reply) => {
            conn.logger
                .failed(conn.id, &head.method, url, conn.peer, &reply.why);
            let _ = write_with_timeout(&mut client, reply.status, conn.cfg.connect_timeout).await;
            return Ok(());
        }
    };
    let ip = peer_ip(&upstream);

    let host_header = if conn.cfg.verbose {
        head.host_header.as_deref()
    } else {
        None
    };
    conn.logger.http(HttpRecord {
        id: conn.id,
        method: &head.method,
        url,
        host,
        port,
        ip: &ip,
        peer: conn.peer,
        host_header,
        blocked: cap.is_some(),
    });

    // Rewrite the absolute-form request-line to origin-form for the origin
    // server; the raw target bytes and all header bytes are preserved.
    let forward_head = http::rewrite_request_line(whole_head)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed head on rewrite"))?;
    write_with_timeout(&mut upstream, &forward_head, conn.cfg.connect_timeout).await?;
    let mut pre_sent = forward_head.len() as u64;
    if !leftover.is_empty() {
        write_with_timeout(&mut upstream, leftover, conn.cfg.connect_timeout).await?;
        pre_sent += leftover.len() as u64;
    }

    let (sent, recv) = relay(&mut client, &mut upstream, idle(conn.cfg), cap).await;

    conn.logger.close(
        conn.id,
        url,
        sent + pre_sent,
        recv,
        started.elapsed().as_millis(),
    );
    Ok(())
}

/// A canned HTTP error response for the client plus a short reason for the log.
struct DialError {
    status: &'static [u8],
    why: String,
}

/// Connect upstream with a timeout, mapping failures to a client-facing status.
async fn dial(host: &str, port: u16, cfg: &Config) -> Result<TcpStream, DialError> {
    match timeout(cfg.connect_timeout, TcpStream::connect((host, port))).await {
        Ok(Ok(stream)) => {
            stream.set_nodelay(true).ok();
            Ok(stream)
        }
        Ok(Err(e)) => Err(DialError {
            status: b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n",
            why: e.to_string(),
        }),
        Err(_) => Err(DialError {
            status: b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n",
            why: "connect timeout".to_string(),
        }),
    }
}

fn peer_ip(stream: &TcpStream) -> String {
    stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "?".to_string())
}

/// Config idle timeout as an `Option` (0 = disabled).
fn idle(cfg: &Config) -> Option<Duration> {
    if cfg.idle_timeout.is_zero() {
        None
    } else {
        Some(cfg.idle_timeout)
    }
}

/// `write_all` bounded by a timeout, so a peer that stops reading can't hang the
/// task on a full socket buffer.
async fn write_with_timeout(stream: &mut TcpStream, data: &[u8], dur: Duration) -> io::Result<()> {
    match timeout(dur, stream.write_all(data)).await {
        Ok(res) => res,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "write timeout")),
    }
}

/// Relay bytes between `client` and `upstream` until both sides close, an I/O
/// error occurs, or `idle` elapses with no traffic in *either* direction.
///
/// The two directions are copied concurrently (like `copy_bidirectional`) so a
/// blocked write in one direction never starves the other — avoiding the
/// classic proxy deadlock. An independent watchdog enforces the idle deadline
/// even while a write is blocked. Byte totals are accumulated as data moves, so
/// they stay accurate on a reset or idle-timeout termination, not just a clean
/// close. Returns `(client -> upstream, upstream -> client)`.
///
/// `download_cap` soft-blocks a destination: the upstream -> client direction is
/// capped at that many bytes, and the whole connection is dropped as soon as the
/// cap is reached (or the site closes first) — so a blocked page loads partially
/// then dies.
async fn relay(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    idle: Option<Duration>,
    download_cap: Option<u64>,
) -> (u64, u64) {
    let (mut cr, mut cw) = client.split();
    let (mut ur, mut uw) = upstream.split();
    let sent = AtomicU64::new(0); // client -> upstream
    let recv = AtomicU64::new(0); // upstream -> client
    let last = AtomicU64::new(0); // millis since t0 of the most recent activity
    let t0 = Instant::now();

    // client -> upstream is never capped (the request/TLS handshake must flow);
    // upstream -> client carries the download cap for soft-blocked destinations.
    let up = copy_dir(&mut cr, &mut uw, &sent, &last, t0, None);
    let down = copy_dir(&mut ur, &mut cw, &recv, &last, t0, download_cap);

    let watchdog = async {
        match idle.map(|d| d.as_millis() as u64) {
            None => std::future::pending::<()>().await,
            Some(d_ms) => loop {
                let idle_ms =
                    (t0.elapsed().as_millis() as u64).saturating_sub(last.load(Ordering::Relaxed));
                if idle_ms >= d_ms {
                    return; // no traffic either way for the whole window
                }
                sleep(Duration::from_millis(d_ms - idle_ms)).await;
            },
        }
    };

    if download_cap.is_some() {
        // Soft-blocked: this connection is being broken anyway, so end the
        // instant ANY side finishes — the capped download completing (cap hit,
        // upstream EOF/error), OR the client going away — instead of lingering
        // on a half-dead connection to an unresponsive upstream. Both futures
        // are still driven concurrently, so the request/handshake flows.
        tokio::select! {
            _ = down => {}
            _ = up => {}
            _ = watchdog => {}
        }
    } else {
        // Normal: relay until both directions close, bounded by idle.
        let both = async {
            tokio::join!(up, down);
        };
        tokio::select! {
            _ = both => {}
            _ = watchdog => {}
        }
    }

    (sent.load(Ordering::Relaxed), recv.load(Ordering::Relaxed))
}

/// Copy one direction, recording bytes and stamping `last` on each chunk so the
/// relay watchdog can measure whole-connection idleness. Half-closes the write
/// side on EOF. When `cap` is set, stops after that many bytes (never reading
/// past it).
async fn copy_dir<R, W>(
    r: &mut R,
    w: &mut W,
    counter: &AtomicU64,
    last: &AtomicU64,
    t0: Instant,
    cap: Option<u64>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; RELAY_BUF];
    loop {
        // For a capped direction, never read past the remaining budget.
        let want = match cap {
            Some(limit) => {
                let remaining = limit.saturating_sub(counter.load(Ordering::Relaxed));
                if remaining == 0 {
                    break;
                }
                remaining.min(RELAY_BUF as u64) as usize
            }
            None => RELAY_BUF,
        };
        match r.read(&mut buf[..want]).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                last.store(t0.elapsed().as_millis() as u64, Ordering::Relaxed);
                if w.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
    }
    let _ = w.shutdown().await; // signal EOF to the peer's read side
}

/// Read from `stream` into `buf` until a full request head is present; returns
/// the index just past the terminating blank line.
async fn read_head(stream: &mut TcpStream, buf: &mut Vec<u8>) -> io::Result<usize> {
    let mut tmp = [0u8; HEAD_CHUNK];
    // How far the buffer has already been searched. Scanning only the new tail
    // (plus a 3-byte overlap, since the 4-byte terminator can straddle reads)
    // keeps head detection O(n) instead of O(n^2) when a client trickles the
    // head one byte at a time.
    let mut scanned = 0usize;
    loop {
        let from = scanned.saturating_sub(3);
        if let Some(end) = http::find_head_end(&buf[from..]) {
            return Ok(from + end);
        }
        scanned = buf.len();
        if buf.len() >= MAX_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request head exceeds limit",
            ));
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before end of request head",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}
