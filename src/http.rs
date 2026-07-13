//! Minimal, allocation-light parsing of the HTTP request head that a client
//! sends to a *forward proxy*.
//!
//! We only ever need to understand the first line and (for logging) the `Host`
//! header. There are exactly two request shapes a proxy receives:
//!
//! * `CONNECT host:port HTTP/1.1`            — used for HTTPS / TLS tunnels.
//! * `GET http://host/path HTTP/1.1`         — "absolute-form" cleartext HTTP
//!   (RFC 9112 §3.2.2). Any method can appear here, not just `GET`.
//!
//! We deliberately do NOT implement a full HTTP stack: for cleartext HTTP we
//! parse and log the first request, rewrite its request-line to origin-form
//! (from the *raw bytes*, so the exact target is preserved), then relay the
//! rest of the byte stream verbatim.

/// The end-of-head marker: a blank line (CRLF CRLF).
const HEAD_TERMINATOR: &[u8] = b"\r\n\r\n";

/// Returns the index *just past* the `\r\n\r\n` that terminates the request
/// head, if the buffer already contains a complete head.
pub fn find_head_end(buf: &[u8]) -> Option<usize> {
    find_subslice(buf, HEAD_TERMINATOR).map(|p| p + HEAD_TERMINATOR.len())
}

/// What kind of request the client made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// `CONNECT` tunnel to `host:port` (typically TLS/HTTPS).
    Connect { host: String, port: u16 },
    /// Absolute-form cleartext HTTP request.
    Http {
        /// Destination host (from the absolute URI).
        host: String,
        /// Destination port (defaults to 80).
        port: u16,
        /// The full absolute URL, for logging. The bytes forwarded upstream are
        /// derived separately by [`rewrite_request_line`] to preserve fidelity.
        url: String,
    },
}

/// A parsed request head.
#[derive(Debug, Clone)]
pub struct RequestHead {
    pub method: String,
    pub target: Target,
    /// Value of the `Host` header, if present (informational / logging).
    pub host_header: Option<String>,
}

impl RequestHead {
    /// Parse the bytes of a request head (everything up to and including the
    /// terminating blank line). Returns `None` if the head is malformed or the
    /// request-line target is not something a forward proxy can service.
    pub fn parse(head: &[u8]) -> Option<RequestHead> {
        // Heads are ASCII structure; lossy conversion is fine — we only inspect
        // that structure here. The bytes forwarded upstream come from the
        // original slice (see `rewrite_request_line`), never from this string.
        let text = String::from_utf8_lossy(head);
        let mut lines = text.split("\r\n");

        let request_line = lines.next()?;
        let mut parts = request_line.split(' ');
        let method = parts.next()?.to_string();
        let raw_target = parts.next()?;
        let version = parts.next()?; // validated for presence; bytes reused from head
        if method.is_empty() || raw_target.is_empty() || version.is_empty() {
            return None;
        }

        // Collect the Host header (case-insensitive name) for logging.
        let mut host_header = None;
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.trim().eq_ignore_ascii_case("host")
            {
                host_header = Some(value.trim().to_string());
            }
        }

        let target = if method.eq_ignore_ascii_case("CONNECT") {
            let (host, port) = split_host_port(raw_target, 443)?;
            Target::Connect { host, port }
        } else {
            parse_absolute_uri(raw_target, host_header.as_deref())?
        };

        Some(RequestHead {
            method,
            target,
            host_header,
        })
    }
}

/// Parse an absolute-form request target such as
/// `http://user@host:8080/path?q` into its destination + logged URL.
fn parse_absolute_uri(raw: &str, host_header: Option<&str>) -> Option<Target> {
    // Only `http://` absolute-form reaches a proxy in cleartext; `https://`
    // arrives via CONNECT, never as a plain request-line.
    let rest = raw
        .strip_prefix("http://")
        .or_else(|| raw.strip_prefix("HTTP://"))?;

    // The authority ends at the first '/', '?' or '#' (RFC 3986 §3.2). Anything
    // after is the path/query/fragment; normalise it to an origin-form path.
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    let tail = &rest[auth_end..];
    let path = if tail.is_empty() {
        "/".to_string()
    } else if tail.starts_with('/') {
        tail.to_string()
    } else {
        // tail begins with '?' or '#'
        format!("/{tail}")
    };

    // Strip optional userinfo (`user:pass@`).
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);

    let (host, port) = if authority.is_empty() {
        // Degenerate `http:///path` — fall back to the Host header.
        split_host_port(host_header?, 80)?
    } else {
        split_host_port(authority, 80)?
    };

    let url = format!("http://{host}:{port}{path}");
    Some(Target::Http { host, port, url })
}

/// Split a `host:port` authority, honouring bracketed IPv6 literals
/// (`[::1]:443`). Falls back to `default_port` when no port is present.
fn split_host_port(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if authority.is_empty() {
        return None;
    }

    // Bracketed IPv6 literal.
    if let Some(after_bracket) = authority.strip_prefix('[') {
        let (host, remainder) = after_bracket.split_once(']')?;
        let port = match remainder.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default_port,
        };
        return Some((host.to_string(), port));
    }

    match authority.rsplit_once(':') {
        // Ambiguous: bare IPv6 without brackets has many ':'; if more than one
        // colon and no brackets, treat the whole thing as a host.
        Some((host, port)) if !host.contains(':') => {
            let port = port.parse().ok()?;
            Some((host.to_string(), port))
        }
        _ => Some((authority.to_string(), default_port)),
    }
}

/// Rewrite an absolute-form request head to origin-form, operating on the raw
/// bytes so the exact target (including any non-UTF-8 or query/fragment bytes)
/// and every following header byte are preserved verbatim.
///
/// `GET http://host/a?b HTTP/1.1\r\n...` -> `GET /a?b HTTP/1.1\r\n...`
pub fn rewrite_request_line(head: &[u8]) -> Option<Vec<u8>> {
    let first_crlf = find_subslice(head, b"\r\n")?;
    let line = &head[..first_crlf];

    let sp1 = line.iter().position(|&b| b == b' ')?;
    let method = &line[..sp1];
    let after_method = &line[sp1 + 1..];
    let sp2 = after_method.iter().position(|&b| b == b' ')?;
    let raw_target = &after_method[..sp2];
    let version = &after_method[sp2 + 1..];

    let path = origin_form_path(raw_target);

    let mut out = Vec::with_capacity(head.len());
    out.extend_from_slice(method);
    out.push(b' ');
    out.extend_from_slice(&path);
    out.push(b' ');
    out.extend_from_slice(version);
    out.extend_from_slice(&head[first_crlf..]); // "\r\n" + headers + "\r\n\r\n"
    Some(out)
}

/// Extract the origin-form path bytes from an absolute-form target:
/// `http://host:8080/a?b#c` -> `/a?b#c`; `http://host` -> `/`.
fn origin_form_path(target: &[u8]) -> Vec<u8> {
    let after_scheme = match find_subslice(target, b"://") {
        Some(i) => &target[i + 3..],
        None => target,
    };
    match after_scheme
        .iter()
        .position(|&b| matches!(b, b'/' | b'?' | b'#'))
    {
        Some(i) => {
            let t = &after_scheme[i..];
            if t.first() == Some(&b'/') {
                t.to_vec()
            } else {
                // begins with '?' or '#': origin-form still needs a leading '/'
                let mut v = Vec::with_capacity(t.len() + 1);
                v.push(b'/');
                v.extend_from_slice(t);
                v
            }
        }
        None => b"/".to_vec(),
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_head_end() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\n"), Some(18));
        assert_eq!(
            find_head_end(b"GET / HTTP/1.1\r\nHost: x\r\n\r\nBODY"),
            Some(27)
        );
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn parses_connect() {
        let head = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let r = RequestHead::parse(head).unwrap();
        assert_eq!(r.method, "CONNECT");
        assert_eq!(
            r.target,
            Target::Connect {
                host: "example.com".into(),
                port: 443
            }
        );
    }

    #[test]
    fn parses_connect_default_port() {
        let head = b"CONNECT example.com HTTP/1.1\r\n\r\n";
        let r = RequestHead::parse(head).unwrap();
        assert_eq!(
            r.target,
            Target::Connect {
                host: "example.com".into(),
                port: 443
            }
        );
    }

    #[test]
    fn parses_connect_ipv6() {
        let head = b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n";
        let r = RequestHead::parse(head).unwrap();
        assert_eq!(
            r.target,
            Target::Connect {
                host: "2001:db8::1".into(),
                port: 8443
            }
        );
    }

    #[test]
    fn parses_absolute_http() {
        let head = b"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let r = RequestHead::parse(head).unwrap();
        assert_eq!(r.method, "GET");
        match r.target {
            Target::Http { host, port, url } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 80);
                assert_eq!(url, "http://example.com:80/path?q=1");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parses_absolute_http_with_port_and_userinfo() {
        let head = b"POST http://user:pass@example.com:8080/api HTTP/1.1\r\n\r\n";
        let r = RequestHead::parse(head).unwrap();
        match r.target {
            Target::Http { host, port, url } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 8080);
                assert_eq!(url, "http://example.com:8080/api");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn absolute_http_without_path() {
        let head = b"GET http://example.com HTTP/1.1\r\n\r\n";
        let r = RequestHead::parse(head).unwrap();
        match r.target {
            Target::Http { url, .. } => assert_eq!(url, "http://example.com:80/"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn absolute_http_query_but_no_path() {
        // Regression: '?' must terminate the authority, not fold into the host.
        let head = b"GET http://example.com?q=1 HTTP/1.1\r\n\r\n";
        let r = RequestHead::parse(head).unwrap();
        match r.target {
            Target::Http { host, port, url } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 80);
                assert_eq!(url, "http://example.com:80/?q=1");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(RequestHead::parse(b"not a request\r\n\r\n").is_none());
        assert!(RequestHead::parse(b"\r\n\r\n").is_none());
    }

    #[test]
    fn rewrites_to_origin_form() {
        let head = b"GET http://example.com/a?b=c HTTP/1.1\r\nHost: example.com\r\nX: 1\r\n\r\n";
        let out = rewrite_request_line(head).unwrap();
        assert_eq!(
            out,
            b"GET /a?b=c HTTP/1.1\r\nHost: example.com\r\nX: 1\r\n\r\n"
        );
    }

    #[test]
    fn rewrite_query_without_path_gets_slash() {
        let head = b"GET http://example.com?q=1 HTTP/1.1\r\nHost: h\r\n\r\n";
        let out = rewrite_request_line(head).unwrap();
        assert_eq!(out, b"GET /?q=1 HTTP/1.1\r\nHost: h\r\n\r\n");
    }

    #[test]
    fn rewrite_preserves_non_utf8_target_bytes() {
        // A raw 0xFF in the path must survive verbatim, not become U+FFFD.
        let head = b"GET http://example.com/\xff HTTP/1.1\r\nHost: h\r\n\r\n";
        let out = rewrite_request_line(head).unwrap();
        assert_eq!(out, b"GET /\xff HTTP/1.1\r\nHost: h\r\n\r\n");
    }

    #[test]
    fn rewrite_no_path_becomes_slash() {
        let head = b"GET http://example.com HTTP/1.1\r\n\r\n";
        let out = rewrite_request_line(head).unwrap();
        assert_eq!(out, b"GET / HTTP/1.1\r\n\r\n");
    }
}
