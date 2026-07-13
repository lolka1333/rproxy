//! A tiny asynchronous, structured logger.
//!
//! Per-connection tasks call one typed method (`connect`, `http`, `close`,
//! `failed`, `info`); the method formats a single line — either human-readable
//! text (default) or JSON Lines (`json = true`) — and pushes it onto a **bounded**
//! channel. A dedicated writer thread owns the sinks (stdout and an optional
//! append-only file) and flushes after every line so a human watching the
//! output sees events live and lines never interleave.
//!
//! The channel is bounded so a stalled sink (a paused pager, a slow disk)
//! cannot grow memory without limit: on overflow the line is dropped and a
//! counter is incremented, and the next successful line is preceded by a
//! `dropped N` notice. Producers therefore never block the proxy hot path.
//!
//! In text mode, attacker-controlled fields (URLs, hostnames, the `Host`
//! header) are passed through [`tsafe`], which renders control bytes as `\xNN`
//! so a crafted request cannot inject ANSI/terminal escapes into the operator's
//! terminal or log file. JSON mode escapes them via [`jstr`].
//!
//! Timestamps are UTC RFC 3339 produced with std only (no date crate); the
//! civil-date conversion is Howard Hinnant's well-known algorithm.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc::{self, Sender, error::TrySendError};

/// Upper bound on queued (not-yet-written) log lines.
const CHANNEL_CAPACITY: usize = 8192;

#[derive(Clone, Copy)]
pub enum Format {
    Text,
    Json,
}

#[derive(Clone)]
pub struct Logger {
    tx: Sender<String>,
    dropped: Arc<AtomicU64>,
    format: Format,
}

/// Fields of a forwarded cleartext-HTTP request, passed to [`Logger::http`].
/// Bundled into a record so the logging call stays readable instead of a long
/// positional argument list.
pub struct HttpRecord<'a> {
    pub id: u64,
    pub method: &'a str,
    pub url: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub ip: &'a str,
    pub peer: SocketAddr,
    pub host_header: Option<&'a str>,
    /// Soft-blocked destination whose download is capped.
    pub blocked: bool,
}

impl Logger {
    /// Create a logger writing to stdout and, optionally, appending to a file.
    ///
    /// Returns the [`Logger`] plus the sink thread's [`JoinHandle`]. At shutdown,
    /// drop every `Logger` (and any clones held by tasks) then `join()` the
    /// handle so the queued tail — the `SHUTDOWN` line and the last `CLOSE`
    /// records — is flushed before the process exits.
    pub fn new(file: Option<&Path>, format: Format) -> io::Result<(Logger, JoinHandle<()>)> {
        let mut file_writer = match file {
            Some(path) => Some(io::BufWriter::new(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?,
            )),
            None => None,
        };

        let (tx, mut rx) = mpsc::channel::<String>(CHANNEL_CAPACITY);

        // Dedicated blocking sink thread: writes are small, and a plain thread
        // keeps synchronous file I/O off the async runtime.
        let handle = std::thread::spawn(move || {
            let stdout = io::stdout();
            while let Some(line) = rx.blocking_recv() {
                let mut out = stdout.lock();
                let _ = writeln!(out, "{line}");
                let _ = out.flush();
                if let Some(w) = file_writer.as_mut() {
                    let _ = writeln!(w, "{line}");
                    let _ = w.flush();
                }
            }
        });

        let logger = Logger {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
            format,
        };
        Ok((logger, handle))
    }

    /// Enqueue a formatted line without ever blocking. If the queue is full the
    /// line is dropped and counted; the count surfaces on the next line that
    /// does fit.
    fn send(&self, line: String) {
        // Atomically *take* the pending drop count so concurrent producers can't
        // both announce (and both subtract) the same value — a load-then-sub
        // race would underflow the u64 and corrupt every later line.
        let dropped = self.dropped.swap(0, Ordering::Relaxed);
        if dropped > 0 && self.tx.try_send(self.drop_notice(dropped)).is_err() {
            // Notice didn't fit; fold the count back so it isn't lost.
            self.dropped.fetch_add(dropped, Ordering::Relaxed);
        }
        if let Err(TrySendError::Full(_)) = self.tx.try_send(line) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn drop_notice(&self, n: u64) -> String {
        let ts = now_rfc3339();
        match self.format {
            Format::Text => format!("{ts} WARN dropped {n} log line(s) (sink stalled)"),
            Format::Json => format!(r#"{{"ts":"{ts}","ev":"warn","dropped":{n}}}"#),
        }
    }

    /// A free-form informational line (startup, shutdown, accept errors).
    pub fn info(&self, msg: impl AsRef<str>) {
        let ts = now_rfc3339();
        let msg = msg.as_ref();
        let line = match self.format {
            Format::Text => format!("{ts} {}", tsafe(msg)),
            Format::Json => format!(r#"{{"ts":"{ts}","ev":"info","msg":{}}}"#, jstr(msg)),
        };
        self.send(line);
    }

    /// A `CONNECT` tunnel was established. `blocked` marks a soft-blocked
    /// destination whose download is capped.
    pub fn connect(
        &self,
        id: u64,
        host: &str,
        port: u16,
        ip: &str,
        peer: SocketAddr,
        blocked: bool,
    ) {
        let ts = now_rfc3339();
        let line = match self.format {
            Format::Text => {
                let mark = if blocked { " BLOCKED" } else { "" };
                format!(
                    "{ts} [#{id}] CONNECT {}:{port} ip={ip} <- {peer}{mark}",
                    tsafe(host)
                )
            }
            Format::Json => {
                let b = if blocked { r#","blocked":true"# } else { "" };
                format!(
                    r#"{{"ts":"{ts}","id":{id},"ev":"connect","host":{},"port":{port},"ip":{},"peer":{}{b}}}"#,
                    jstr(host),
                    jstr(ip),
                    jstr(&peer.to_string())
                )
            }
        };
        self.send(line);
    }

    /// A cleartext HTTP request was forwarded.
    pub fn http(&self, record: HttpRecord<'_>) {
        let HttpRecord {
            id,
            method,
            url,
            host,
            port,
            ip,
            peer,
            host_header,
            blocked,
        } = record;
        let ts = now_rfc3339();
        let line = match self.format {
            Format::Text => {
                let extra = host_header
                    .map(|h| format!(" host={}", tsafe(h)))
                    .unwrap_or_default();
                let mark = if blocked { " BLOCKED" } else { "" };
                format!(
                    "{ts} [#{id}] {} {} ip={ip} <- {peer}{extra}{mark}",
                    tsafe(method),
                    tsafe(url)
                )
            }
            Format::Json => {
                let hh = match host_header {
                    Some(h) => format!(r#","host_header":{}"#, jstr(h)),
                    None => String::new(),
                };
                let b = if blocked { r#","blocked":true"# } else { "" };
                format!(
                    r#"{{"ts":"{ts}","id":{id},"ev":"http","method":{},"url":{},"host":{},"port":{port},"ip":{},"peer":{}{hh}{b}}}"#,
                    jstr(method),
                    jstr(url),
                    jstr(host),
                    jstr(ip),
                    jstr(&peer.to_string())
                )
            }
        };
        self.send(line);
    }

    /// A connection closed; report relayed byte counts and duration.
    pub fn close(&self, id: u64, target: &str, sent: u64, recv: u64, dur_ms: u128) {
        let ts = now_rfc3339();
        let line = match self.format {
            Format::Text => format!(
                "{ts} [#{id}] CLOSE {} sent={sent} recv={recv} dur={dur_ms}ms",
                tsafe(target)
            ),
            Format::Json => format!(
                r#"{{"ts":"{ts}","id":{id},"ev":"close","target":{},"c2u":{sent},"u2c":{recv},"dur_ms":{dur_ms}}}"#,
                jstr(target)
            ),
        };
        self.send(line);
    }

    /// An upstream dial failed.
    pub fn failed(&self, id: u64, phase: &str, target: &str, peer: SocketAddr, why: &str) {
        let ts = now_rfc3339();
        let line = match self.format {
            Format::Text => format!(
                "{ts} [#{id}] {} {} <- {peer} FAILED ({})",
                tsafe(phase),
                tsafe(target),
                tsafe(why)
            ),
            Format::Json => format!(
                r#"{{"ts":"{ts}","id":{id},"ev":"error","phase":{},"target":{},"peer":{},"msg":{}}}"#,
                jstr(phase),
                jstr(target),
                jstr(&peer.to_string()),
                jstr(why)
            ),
        };
        self.send(line);
    }
}

/// True for control codepoints that a terminal may act on: C0 (`< 0x20`), DEL
/// (`0x7f`), and C1 (`0x80..=0x9f`, e.g. U+009B = CSI, U+0085 = NEL). C1 chars
/// encode as multi-byte UTF-8 whose bytes are all `>= 0x20`, so a byte-level
/// check would miss them — the check must be per-codepoint.
fn is_control(n: u32) -> bool {
    n < 0x20 || (0x7f..=0x9f).contains(&n)
}

/// Render control codepoints as `\xNN` so untrusted text cannot inject
/// terminal/ANSI escapes into text-mode output. Printable UTF-8 (including
/// non-ASCII) is passed through unchanged.
fn tsafe(s: &str) -> Cow<'_, str> {
    if !s.chars().any(|c| is_control(c as u32)) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        let n = c as u32;
        if is_control(n) {
            let _ = write!(out, "\\x{n:02x}");
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// Escape a string as a JSON string literal (including surrounding quotes).
fn jstr(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // C0, DEL and C1 controls -> \uXXXX (valid JSON, and neutralized if
            // the JSONL is tailed in a terminal).
            c if is_control(c as u32) => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
fn now_rfc3339() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let millis = now.subsec_millis();

    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (hour, min, sec) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (year, month, day) = civil_from_days(days);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

/// Convert days since the Unix epoch (1970-01-01) to a civil (year, month, day)
/// in the proleptic Gregorian calendar.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::{civil_from_days, jstr, tsafe};

    #[test]
    fn epoch_is_1970() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn known_dates() {
        assert_eq!(civil_from_days(18_993), (2022, 1, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29)); // leap day
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn json_escaping() {
        assert_eq!(jstr("a\"b\\c"), r#""a\"b\\c""#);
        assert_eq!(jstr("line\nbreak"), r#""line\nbreak""#);
        assert_eq!(jstr("plain"), r#""plain""#);
    }

    #[test]
    fn tsafe_neutralizes_control_bytes() {
        // ESC and CR become visible escapes; printable text is untouched.
        assert_eq!(tsafe("plain/path"), "plain/path");
        assert_eq!(tsafe("a\x1b[2Kb"), "a\\x1b[2Kb");
        assert_eq!(tsafe("x\x7fy"), "x\\x7fy");
        // Non-ASCII UTF-8 passes through.
        assert_eq!(tsafe("café"), "café");
    }

    #[test]
    fn tsafe_neutralizes_c1_controls() {
        // C1 CSI (U+009B) and NEL (U+0085) are multi-byte UTF-8 but must escape.
        assert_eq!(tsafe("a\u{009b}2Kb"), "a\\x9b2Kb");
        assert_eq!(tsafe("line\u{0085}break"), "line\\x85break");
    }

    #[test]
    fn jstr_escapes_c1_and_del() {
        assert_eq!(jstr("a\u{009b}b"), r#""a\u009bb""#);
        assert_eq!(jstr("a\x7fb"), r#""a\u007fb""#);
    }
}
