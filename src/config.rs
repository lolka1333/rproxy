//! Configuration parsing. Hand-rolled to keep the dependency footprint at
//! exactly one crate (tokio), which matters for on-device / Termux builds.
//!
//! rproxy is config-file driven: every setting lives in a `key = value` file.
//! This module turns a located config file (via `--config`) into a [`Config`].
//! Resolving the data directory (`--dir` / `$RPROXY_DIR`) and seeding the
//! default file on first run live in [`crate::startup`].

use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_LISTEN: &str = "0.0.0.0:20487";
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_HEAD_TIMEOUT_SECS: u64 = 30;
/// Idle (no traffic in either direction) timeout for an established relay.
/// Generous by default so long-poll / WebSocket heartbeats survive, but bounded
/// so stalled connections can't pin sockets and permits forever. 0 disables it.
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;
const DEFAULT_MAX_CONNS: usize = 1024;
/// Sane ceiling for `max-conns`: generous (far above any real deployment) yet
/// well below tokio's `Semaphore` permit limit, so a huge value is rejected
/// with a clear error instead of panicking or truncating on a 32-bit target.
const MAX_CONNS_LIMIT: usize = 1 << 20;
/// Bytes a blocked destination is allowed to deliver to the client before the
/// connection is dropped mid-load (a "soft block"). 13 KiB.
const DEFAULT_BLOCK_CAP: u64 = 13 * 1024;

#[derive(Debug, Clone)]
pub struct Config {
    /// Address to listen on (e.g. `0.0.0.0:20487`).
    pub listen: String,
    /// Optional append-only log file (in addition to stdout).
    pub log_file: Option<PathBuf>,
    /// Timeout for establishing the upstream connection.
    pub connect_timeout: Duration,
    /// Timeout for reading a full request head from the client.
    pub head_timeout: Duration,
    /// Idle timeout for an established relay (0 = disabled).
    pub idle_timeout: Duration,
    /// Maximum number of simultaneous client connections.
    pub max_conns: usize,
    /// Emit the `Host` header alongside each request when present.
    pub verbose: bool,
    /// Emit JSON Lines instead of human-readable text.
    pub json: bool,
    /// Master switch for soft-blocking; when false `block` / `blocklist` are
    /// ignored (the list can stay configured but inactive).
    pub blocking: bool,
    /// Inline blocked domains (`block`), matched with subdomains.
    pub block: Vec<String>,
    /// Files of blocked domains, one per line (`blocklist`, repeatable — every
    /// listed file is loaded and merged; duplicates across files collapse).
    pub blocklist_files: Vec<PathBuf>,
    /// Bytes a blocked destination may deliver before the connection is dropped.
    pub block_cap: u64,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            listen: DEFAULT_LISTEN.to_string(),
            log_file: None,
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
            head_timeout: Duration::from_secs(DEFAULT_HEAD_TIMEOUT_SECS),
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
            max_conns: DEFAULT_MAX_CONNS,
            verbose: false,
            json: false,
            blocking: false,
            block: Vec::new(),
            blocklist_files: Vec::new(),
            block_cap: DEFAULT_BLOCK_CAP,
        }
    }
}

pub enum Parsed {
    Run(Config),
    Help,
}

impl Config {
    /// Parse arguments into a `Config`. The CLI only says *where* the config is
    /// (`--config` / `--dir`); every actual setting lives in the config file.
    /// Pure: no data-directory resolution or file creation — see
    /// [`crate::startup::load`] for those.
    pub fn from_args<I, S>(args: I) -> Result<Parsed, String>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let args: Vec<String> = args.into_iter().map(Into::into).collect();

        // Help short-circuits regardless of position.
        if args.iter().any(|a| a == "-h" || a == "--help") {
            return Ok(Parsed::Help);
        }
        validate_args(&args)?;

        let mut cfg = Config::default();
        if let Some(path) = flag_value(&args, &["--config", "-c"])? {
            load_file(&path, &mut cfg)?;
        }
        Ok(Parsed::Run(cfg))
    }
}

/// Reject anything other than the config-locating flags: settings live in the
/// config file, not on the command line.
pub(crate) fn validate_args(args: &[String]) -> Result<(), String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {}
            "-c" | "--config" | "--dir" => {
                it.next().ok_or_else(|| format!("{a} requires a value"))?;
            }
            other => {
                return Err(format!(
                    "unexpected argument: {other}\n(settings go in the config file — see `rproxy --help`)"
                ));
            }
        }
    }
    Ok(())
}

/// Return the value following the first of `names` in `args`.
pub(crate) fn flag_value(args: &[String], names: &[&str]) -> Result<Option<PathBuf>, String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if names.contains(&a.as_str()) {
            let v = it.next().ok_or_else(|| format!("{a} requires a value"))?;
            return Ok(Some(PathBuf::from(v)));
        }
    }
    Ok(None)
}

/// Read and apply a config file over `cfg`. Relative `log` / `blocklist` paths
/// resolve against the file's own directory.
fn load_file(path: &Path, cfg: &mut Config) -> Result<(), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read config file {}: {e}", path.display()))?;
    parse_config(&text, cfg)?;
    if let Some(base) = path.parent().filter(|b| !b.as_os_str().is_empty()) {
        rebase(&mut cfg.log_file, base);
        for p in &mut cfg.blocklist_files {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        }
    }
    Ok(())
}

/// Anchor a relative path to `base` (absolute paths are left as-is).
fn rebase(path: &mut Option<PathBuf>, base: &Path) {
    if let Some(p) = path.take() {
        *path = Some(if p.is_relative() { base.join(p) } else { p });
    }
}

/// Strip a `#` comment, but only when `#` starts the line or follows
/// whitespace — so a value (e.g. a filesystem path) may contain a literal `#`.
fn strip_comment(raw: &str) -> &str {
    match raw
        .char_indices()
        .find(|&(i, c)| c == '#' && (i == 0 || raw[..i].ends_with(char::is_whitespace)))
    {
        Some((i, _)) => &raw[..i],
        None => raw,
    }
}

/// Parse the `key = value` config text over `cfg`. `#` starts a comment (whole
/// line, or trailing when preceded by whitespace); blank lines are ignored.
fn parse_config(text: &str, cfg: &mut Config) -> Result<(), String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text); // tolerate a BOM
    for (n, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let (key, val) = line
            .split_once('=')
            .ok_or_else(|| format!("config line {}: expected `key = value`", n + 1))?;
        let key = key.trim();
        if key == "config" {
            return Err(format!(
                "config line {}: `config` is not allowed here",
                n + 1
            ));
        }
        set(cfg, key, val.trim()).map_err(|e| format!("config line {}: {e}", n + 1))?;
    }
    Ok(())
}

/// Apply a single `key = value` setting from the config file to `cfg`.
fn set(cfg: &mut Config, key: &str, value: &str) -> Result<(), String> {
    match key {
        "listen" => cfg.listen = req(value, key)?.to_string(),
        "log" => cfg.log_file = Some(PathBuf::from(req(value, key)?)),
        "connect-timeout" => cfg.connect_timeout = Duration::from_secs(num(value, key)?),
        "head-timeout" => cfg.head_timeout = Duration::from_secs(num(value, key)?),
        "idle-timeout" => cfg.idle_timeout = Duration::from_secs(num(value, key)?),
        "max-conns" => {
            // Range-check with a fallible conversion (never a truncating `as`),
            // so 0 and out-of-range values are rejected on every target.
            let n = usize::try_from(num(value, key)?).unwrap_or(usize::MAX);
            if !(1..=MAX_CONNS_LIMIT).contains(&n) {
                return Err(format!("max-conns must be between 1 and {MAX_CONNS_LIMIT}"));
            }
            cfg.max_conns = n;
        }
        "blocking" => cfg.blocking = boolean(value, key)?,
        "block" => cfg.block.push(req(value, key)?.to_string()),
        "blocklist" => cfg.blocklist_files.push(PathBuf::from(req(value, key)?)),
        "block-cap" => cfg.block_cap = num(value, key)?,
        "verbose" => cfg.verbose = boolean(value, key)?,
        "json" => cfg.json = boolean(value, key)?,
        _ => return Err(format!("unknown setting: {key}")),
    }
    Ok(())
}

/// A value that must be non-empty.
fn req<'a>(value: &'a str, key: &str) -> Result<&'a str, String> {
    if value.is_empty() {
        return Err(format!("{key} requires a value"));
    }
    Ok(value)
}

/// A non-negative integer value.
fn num(value: &str, key: &str) -> Result<u64, String> {
    req(value, key)?
        .parse::<u64>()
        .map_err(|_| format!("{key} expects a non-negative integer"))
}

/// A boolean value (`true`/`false` and friends).
fn boolean(value: &str, key: &str) -> Result<bool, String> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        _ => Err(format!("{key} expects true or false, got `{value}`")),
    }
}

pub const HELP: &str = "\
rproxy — logging-only HTTP forward proxy for Android's Global HTTP Proxy

USAGE:
    rproxy [--dir <DIR>] [--config <FILE>]

rproxy is configured entirely through a config file — the command line only
says WHERE that file is:

    --dir <DIR>       Data directory for the config files [default: next to exe]
    -c, --config <FILE>   Load a specific config file
    -h, --help        Print this help

On first run, rproxy creates `rproxy.conf` and `blocked.txt` in the data
directory (the `--dir` value, else $RPROXY_DIR, else the folder next to the
executable) and loads `rproxy.conf` automatically. Edit them and restart.

Every setting — listen address, timeouts, logging, verbose/json output, and the
soft-block list — lives in `rproxy.conf` as `key = value` lines. See the
annotated template in rproxy.conf (or the one just created for you).

EXAMPLES:
    rproxy                    First run writes rproxy.conf next to the exe; edit it
    rproxy --dir ./conf       Keep the config in ./conf instead
    rproxy --config my.conf   Load a specific file

Point Android at it (the default config listens on 0.0.0.0:20487):
    adb shell settings put global http_proxy <PROXY_IP>:20487
    adb shell settings delete global http_proxy      # to clear
";

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Config {
        match Config::from_args(args.iter().copied()).unwrap() {
            Parsed::Run(c) => c,
            Parsed::Help => panic!("unexpected help"),
        }
    }

    fn parsed(text: &str) -> Config {
        let mut cfg = Config::default();
        parse_config(text, &mut cfg).unwrap();
        cfg
    }

    #[test]
    fn defaults() {
        let c = run(&[]);
        assert_eq!(c.listen, "0.0.0.0:20487");
        assert!(c.log_file.is_none());
        assert_eq!(c.max_conns, 1024);
    }

    #[test]
    fn cli_rejects_settings() {
        // Settings live in the config file, not on the command line.
        assert!(Config::from_args(["--listen", "0.0.0.0:1"]).is_err());
        assert!(Config::from_args(["-v"]).is_err());
        assert!(Config::from_args(["--block", "x"]).is_err());
        assert!(Config::from_args(["127.0.0.1:9000"]).is_err()); // no positional
    }

    #[test]
    fn help_flag() {
        assert!(matches!(
            Config::from_args(["--help"]).unwrap(),
            Parsed::Help
        ));
    }

    #[test]
    fn rejects_unknown() {
        assert!(Config::from_args(["--nope"]).is_err());
    }

    #[test]
    fn config_text_parses() {
        let c = parsed(
            "\
            # a comment\n\
            listen = 1.2.3.4:9999   # inline comment\n\
            verbose = true\n\
            json = off\n\
            idle-timeout = 60\n\
            max-conns = 256\n\
            block = ads.example\n\
            block = tracker.net\n\
            block-cap = 4096\n",
        );
        assert_eq!(c.listen, "1.2.3.4:9999");
        assert!(c.verbose);
        assert!(!c.json);
        assert_eq!(c.idle_timeout, Duration::from_secs(60));
        assert_eq!(c.max_conns, 256);
        assert_eq!(
            c.block,
            vec!["ads.example".to_string(), "tracker.net".to_string()]
        );
        assert_eq!(c.block_cap, 4096);
    }

    #[test]
    fn blocking_switch() {
        assert!(!Config::default().blocking); // off by default
        assert!(parsed("blocking = on\n").blocking);
        assert!(!parsed("blocking = off\n").blocking);
        assert!(parsed("blocking = true\n").blocking);
    }

    #[test]
    fn config_rejects_bad_lines() {
        let mut cfg = Config::default();
        assert!(parse_config("listen 1.2.3.4:80\n", &mut cfg).is_err()); // no '='
        assert!(parse_config("bogus = x\n", &mut cfg).is_err()); // unknown key
        assert!(parse_config("verbose = maybe\n", &mut cfg).is_err()); // bad bool
        assert!(parse_config("config = other.conf\n", &mut cfg).is_err()); // no recursion
    }

    #[test]
    fn config_tolerates_bom() {
        let c = parsed("\u{feff}listen = 5.6.7.8:80\n");
        assert_eq!(c.listen, "5.6.7.8:80");
    }

    #[test]
    fn config_rejects_bad_max_conns() {
        // 0 / out-of-range would panic tokio's Semaphore or truncate on 32-bit.
        let mut cfg = Config::default();
        assert!(parse_config("max-conns = 0\n", &mut cfg).is_err());
        assert!(parse_config("max-conns = 2000000\n", &mut cfg).is_err());
        assert!(parse_config("max-conns = 18446744073709551615\n", &mut cfg).is_err());
        assert_eq!(parsed("max-conns = 4096\n").max_conns, 4096); // sane value ok
    }

    #[test]
    fn config_value_may_contain_hash() {
        // A '#' not preceded by whitespace is a literal value char, not a comment.
        let c = parsed("log = /var/log/proxy#1.log\n");
        assert_eq!(
            c.log_file.unwrap().to_str().unwrap(),
            "/var/log/proxy#1.log"
        );
        // A space-preceded trailing '# comment' is still stripped.
        assert_eq!(
            parsed("listen = 1.2.3.4:80   # note\n").listen,
            "1.2.3.4:80"
        );
    }

    #[test]
    fn explicit_config_is_loaded() {
        let path = std::env::temp_dir().join(format!("rproxy_cfg_{}.conf", std::process::id()));
        std::fs::write(&path, "listen = 9.9.9.9:1\nverbose = true\nmax-conns = 7\n").unwrap();
        let c = match Config::from_args(["--config", path.to_str().unwrap()]).unwrap() {
            Parsed::Run(c) => c,
            Parsed::Help => panic!("unexpected help"),
        };
        let _ = std::fs::remove_file(&path);
        assert_eq!(c.listen, "9.9.9.9:1");
        assert!(c.verbose);
        assert_eq!(c.max_conns, 7);
    }

    #[test]
    fn config_file_relative_paths_rebase_to_its_dir() {
        let dir = std::env::temp_dir().join(format!("rproxy_rb_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("rproxy.conf");
        std::fs::write(&cfg_path, "blocklist = blocked.txt\nlog = out.log\n").unwrap();
        let mut cfg = Config::default();
        load_file(&cfg_path, &mut cfg).unwrap();
        assert_eq!(cfg.blocklist_files, vec![dir.join("blocked.txt")]);
        assert_eq!(cfg.log_file.unwrap(), dir.join("out.log"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn blocklist_is_repeatable() {
        // Several `blocklist =` lines accumulate (like `block =`) instead of the
        // last one overwriting the rest.
        let c = parsed("blocklist = ads.txt\nblocklist = music.txt\nblocklist = vk.txt\n");
        assert_eq!(
            c.blocklist_files,
            vec![
                PathBuf::from("ads.txt"),
                PathBuf::from("music.txt"),
                PathBuf::from("vk.txt"),
            ]
        );
    }
}
