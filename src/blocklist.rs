//! Domain blocklist with subdomain-aware matching.
//!
//! Blocked destinations are NOT hard-failed. The proxy still connects and
//! relays, but caps the bytes delivered to the client (the download cap in
//! `proxy`), so a blocked site loads partially and the connection is then
//! dropped mid-load — a "soft block" that is harder to detect/circumvent than
//! an outright connection failure.

use std::collections::HashSet;
use std::io;
use std::path::Path;

/// A set of blocked domains. A host matches if it equals a listed domain or is
/// a subdomain of one: `example.com` blocks `example.com` and any
/// `*.example.com`.
#[derive(Debug, Default, Clone)]
pub struct BlockList {
    domains: HashSet<String>,
}

impl BlockList {
    /// Build from inline `block` entries plus an optional `blocklist` file of
    /// one-domain-per-line; blank lines and `#` comments are ignored.
    pub fn build(inline: &[String], file: Option<&Path>) -> io::Result<BlockList> {
        let mut domains = HashSet::new();
        for entry in inline {
            if let Some(d) = normalize(entry) {
                domains.insert(d);
            }
        }
        if let Some(path) = file {
            let text = std::fs::read_to_string(path)?;
            for line in text.lines() {
                if let Some(d) = normalize(line) {
                    domains.insert(d);
                }
            }
        }
        Ok(BlockList { domains })
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    pub fn len(&self) -> usize {
        self.domains.len()
    }

    /// Is `host` blocked (exact match or a subdomain of a listed domain)?
    pub fn is_blocked(&self, host: &str) -> bool {
        if self.domains.is_empty() {
            return false;
        }
        // Walk the host and each parent suffix: a.b.example.com -> b.example.com
        // -> example.com -> com, matching against the normalized domain set.
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let mut suffix = host.as_str();
        loop {
            if self.domains.contains(suffix) {
                return true;
            }
            match suffix.split_once('.') {
                Some((_, rest)) => suffix = rest,
                None => return false,
            }
        }
    }
}

/// Normalize a blocklist entry: strip a leading UTF-8 BOM (Notepad / PowerShell
/// `-Encoding utf8` prepend one to the first line), drop a `#` comment (whole
/// line or trailing — a domain never contains `#`), strip a leading `*.` or `.`
/// and any trailing `.`, trim, and lowercase. Returns `None` for non-entries.
fn normalize(raw: &str) -> Option<String> {
    let s = raw.trim_start_matches('\u{feff}');
    let s = s.split('#').next().unwrap_or("").trim();
    if s.is_empty() {
        return None;
    }
    let s = s
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.');
    if s.is_empty() {
        return None;
    }
    Some(s.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &[&str]) -> BlockList {
        BlockList::build(
            &entries.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn empty_blocks_nothing() {
        let bl = BlockList::default();
        assert!(bl.is_empty());
        assert!(!bl.is_blocked("example.com"));
    }

    #[test]
    fn exact_and_subdomain_match() {
        let bl = list(&["example.com"]);
        assert!(bl.is_blocked("example.com"));
        assert!(bl.is_blocked("www.example.com"));
        assert!(bl.is_blocked("a.b.example.com"));
        assert!(bl.is_blocked("EXAMPLE.COM")); // case-insensitive
        assert!(bl.is_blocked("example.com.")); // trailing dot
    }

    #[test]
    fn non_matches() {
        let bl = list(&["example.com"]);
        assert!(!bl.is_blocked("example.org"));
        assert!(!bl.is_blocked("notexample.com")); // not a subdomain label
        assert!(!bl.is_blocked("example.com.evil.com"));
    }

    #[test]
    fn normalizes_entries() {
        let bl = list(&["*.Blocked.NET", ".foo.com", "bar.com.", "   ", "# comment"]);
        assert_eq!(bl.len(), 3);
        assert!(bl.is_blocked("x.blocked.net"));
        assert!(bl.is_blocked("foo.com"));
        assert!(bl.is_blocked("bar.com"));
    }

    #[test]
    fn strips_utf8_bom() {
        // A file saved UTF-8-with-BOM on Windows prepends U+FEFF to line 1; the
        // first entry must still be enforced.
        let bl = list(&["\u{feff}ads.example", "tracker.net"]);
        assert!(bl.is_blocked("ads.example"));
        assert!(bl.is_blocked("www.ads.example"));
        assert!(bl.is_blocked("tracker.net"));
    }

    #[test]
    fn shipped_blocklist_parses() {
        // Guarantees the committed blocked.txt loads and matches as expected.
        let entries: Vec<String> = include_str!("../blocked.txt")
            .lines()
            .map(String::from)
            .collect();
        let bl = BlockList::build(&entries, None).unwrap();
        assert!(!bl.is_empty());
        assert!(bl.is_blocked("doubleclick.net"));
        assert!(bl.is_blocked("stats.g.doubleclick.net")); // subdomain
        assert!(bl.is_blocked("connect.facebook.net"));
    }
}
