//! Application startup: resolve the data directory, seed the default config
//! files on first run, then hand off to the (pure) config parser in
//! [`crate::config`].
//!
//! Keeping the filesystem side of startup here lets `config` stay a plain
//! args/text → [`Config`] parser that is trivial to unit-test.

use std::path::{Path, PathBuf};

use crate::config::{self, Config, Parsed};

/// Environment variable naming the data directory (set by the container image).
const DATA_DIR_ENV: &str = "RPROXY_DIR";
/// Files created in the data directory on first run.
const CONFIG_FILENAME: &str = "rproxy.conf";
const BLOCKLIST_FILENAME: &str = "blocked.txt";

/// Templates written on first run — the committed `rproxy.conf` / `blocked.txt`
/// are their single source of truth.
const CONFIG_TEMPLATE: &str = include_str!("../rproxy.conf");
const BLOCKLIST_TEMPLATE: &str = include_str!("../blocked.txt");

/// Resolve the data directory, create the default `rproxy.conf` / `blocked.txt`
/// there on first run, then parse the config. This is the entry point `main`
/// uses; [`Config::from_args`] stays pure (no filesystem access) for tests.
pub fn load<I, S>(args: I) -> Result<Parsed, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args: Vec<String> = args.into_iter().map(Into::into).collect();

    if args.iter().any(|a| a == "-h" || a == "--help") {
        return Ok(Parsed::Help);
    }
    // Reject bad args before touching the filesystem, so a mistyped command
    // never creates files as a side effect.
    config::validate_args(&args)?;

    // An explicit --config means the user manages their own file; leave the data
    // directory untouched. Otherwise seed and load the default config.
    let has_config = args.iter().any(|a| a == "--config" || a == "-c");
    if !has_config {
        let dir = resolve_data_dir(&args)?;
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("cannot create data dir {}: {e}", dir.display()))?;

        // Seed the starter files on first run (best-effort; a read-only dir just
        // means we fall back to built-in defaults).
        let config_file = dir.join(CONFIG_FILENAME);
        create_if_missing(&config_file, CONFIG_TEMPLATE);
        create_if_missing(&dir.join(BLOCKLIST_FILENAME), BLOCKLIST_TEMPLATE);

        if config_file.is_file() {
            args.push("--config".into());
            args.push(config_file.to_string_lossy().into_owned());
        } else if config_file.exists() {
            // Exists but isn't a regular file (e.g. a Docker bind-mount that
            // created it as a directory) — say so instead of silently using
            // defaults.
            eprintln!(
                "rproxy: {} is not a regular file; using built-in defaults",
                config_file.display()
            );
        }
    }

    Config::from_args(args)
}

/// Resolve the data directory: `--dir`, then `$RPROXY_DIR`, then the
/// executable's own directory (portable / next-to-exe), then the cwd.
fn resolve_data_dir(args: &[String]) -> Result<PathBuf, String> {
    if let Some(dir) = config::flag_value(args, &["--dir"])? {
        if dir.as_os_str().is_empty() {
            return Err("--dir requires a non-empty value".into());
        }
        return Ok(dir);
    }
    if let Ok(dir) = std::env::var(DATA_DIR_ENV)
        && !dir.is_empty()
    {
        return Ok(PathBuf::from(dir));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        return Ok(parent.to_path_buf());
    }
    std::env::current_dir().map_err(|e| format!("cannot determine data directory: {e}"))
}

/// Write `template` to `path` if it does not exist yet (best-effort).
fn create_if_missing(path: &Path, template: &str) {
    if path.exists() {
        return;
    }
    match std::fs::write(path, template) {
        Ok(()) => eprintln!("rproxy: created {}", path.display()),
        Err(e) => eprintln!("rproxy: could not create {}: {e}", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_flag_wins_for_data_dir() {
        let dir = resolve_data_dir(&["--dir".into(), "/tmp/rproxy-x".into()]).unwrap();
        assert_eq!(dir, PathBuf::from("/tmp/rproxy-x"));
    }

    #[test]
    fn empty_dir_is_rejected() {
        // An empty --dir (e.g. an unset launch-script variable) must not silently
        // target the cwd.
        assert!(resolve_data_dir(&["--dir".into(), String::new()]).is_err());
    }

    #[test]
    fn seeds_and_loads_defaults() {
        // Also proves the embedded CONFIG_TEMPLATE parses (listen == default).
        let dir = std::env::temp_dir().join(format!("rproxy_bs_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dir_s = dir.to_str().unwrap().to_string();
        let c = match load(["--dir", &dir_s]).unwrap() {
            Parsed::Run(c) => c,
            Parsed::Help => panic!("unexpected help"),
        };
        assert!(dir.join("rproxy.conf").is_file());
        assert!(dir.join("blocked.txt").is_file());
        assert_eq!(c.listen, "0.0.0.0:20487");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn blocklist_template_is_nonempty() {
        assert!(!BLOCKLIST_TEMPLATE.trim().is_empty());
    }
}
