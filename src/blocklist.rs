//! Domain blocklist with subdomain-aware matching.
//!
//! Blocked destinations are NOT hard-failed. The proxy still connects and
//! relays, but caps the bytes delivered to the client (the download cap in
//! `proxy`), so a blocked site loads partially and the connection is then
//! dropped mid-load — a "soft block" that is harder to detect/circumvent than
//! an outright connection failure.

use std::collections::HashSet;
use std::io;
use std::path::PathBuf;

/// A set of blocked domains. A host matches if it equals a listed domain or is
/// a subdomain of one: `example.com` blocks `example.com` and any
/// `*.example.com`.
#[derive(Debug, Default, Clone)]
pub struct BlockList {
    domains: HashSet<String>,
}

impl BlockList {
    /// Build from inline `block` entries plus any number of `blocklist` files of
    /// one-domain-per-line; blank lines and `#` comments are ignored. Entries
    /// from every source merge into one set, so duplicates collapse and order is
    /// irrelevant. A file that cannot be read is a hard error (named), so a
    /// mistyped path fails fast at startup rather than silently disabling blocks.
    pub fn build(inline: &[String], files: &[PathBuf]) -> io::Result<BlockList> {
        let mut domains = HashSet::new();
        for entry in inline {
            if let Some(d) = normalize(entry) {
                domains.insert(d);
            }
        }
        for path in files {
            let text = std::fs::read_to_string(path).map_err(|e| {
                io::Error::new(e.kind(), format!("blocklist {}: {e}", path.display()))
            })?;
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
            &[],
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
        let bl = BlockList::build(&entries, &[]).unwrap();
        assert!(!bl.is_empty());
        assert!(bl.is_blocked("doubleclick.net"));
        assert!(bl.is_blocked("stats.g.doubleclick.net")); // subdomain
        assert!(bl.is_blocked("connect.facebook.net"));
    }

    #[test]
    fn merges_multiple_files() {
        // Several `blocklist` files load into one set; duplicates across files
        // collapse, and inline `block` entries merge in too.
        let dir = std::env::temp_dir().join(format!("rproxy_blm_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let (a, b) = (dir.join("a.txt"), dir.join("b.txt"));
        std::fs::write(&a, "ads.example\n# a comment\n").unwrap();
        std::fs::write(&b, "tracker.net\nads.example\n").unwrap(); // ads.example repeats
        let bl = BlockList::build(&["inline.dom".to_string()], &[a, b]).unwrap();
        assert_eq!(bl.len(), 3); // ads.example, tracker.net, inline.dom
        assert!(bl.is_blocked("x.ads.example"));
        assert!(bl.is_blocked("tracker.net"));
        assert!(bl.is_blocked("inline.dom"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_is_a_named_error() {
        let err = BlockList::build(&[], &[PathBuf::from("no_such_blocklist_xyz.txt")]).unwrap_err();
        assert!(err.to_string().contains("no_such_blocklist_xyz.txt"));
    }
}
