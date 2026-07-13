//! rproxy — a logging-only HTTP forward proxy.
//!
//! Intended target: an Android 16 device configured with a **Global HTTP
//! Proxy** pointing at this server. The proxy records the destinations of
//! proxy-aware TCP traffic — full URLs for cleartext HTTP, and host/domain +
//! resolved IP for HTTPS (via the `CONNECT` request-line) — without any TLS
//! decryption or certificate installation.
//!
//! See README.md for deployment (Termux on-device vs. PC-on-LAN), the adb
//! commands to set/clear the proxy, and the important QUIC/HTTP-3 caveat.

mod blocklist;
mod config;
mod http;
mod logger;
mod proxy;
mod startup;

use std::process::ExitCode;

use config::Parsed;
use logger::{Format, Logger};

fn main() -> ExitCode {
    let parsed = match startup::load(std::env::args().skip(1)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("rproxy: {e}\n\nRun `rproxy --help` for usage.");
            return ExitCode::FAILURE;
        }
    };

    let cfg = match parsed {
        Parsed::Help => {
            print!("{}", config::HELP);
            return ExitCode::SUCCESS;
        }
        Parsed::Run(cfg) => cfg,
    };

    let format = if cfg.json { Format::Json } else { Format::Text };
    let logger = match Logger::new(cfg.log_file.as_deref(), format) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("rproxy: cannot open log file: {e}");
            return ExitCode::FAILURE;
        }
    };

    // A multi-threaded runtime so many concurrent tunnels relay in parallel.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("rproxy: cannot start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(proxy::run(cfg, logger)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rproxy: fatal: {e}");
            ExitCode::FAILURE
        }
    }
}
