# rproxy

A small, dependency-light (**tokio only**) HTTP **forward proxy** written in
Rust 2024 edition, built for one job: sit behind an Android **Global HTTP
Proxy** and **log where traffic goes** — full URLs for cleartext HTTP, and the
domain + resolved IP for HTTPS.

It does **not** decrypt TLS. There is no MITM, no root CA to install on the
device. As requested, seeing URLs / domains / IPs is enough.

It can also **soft-block** a list of domains: instead of failing them outright,
it lets ~13 KB load and then drops the connection (see
[Blocking sites](#blocking-sites-soft-block)).

---

## What it can and cannot see

An app that honours the system proxy opens a TCP connection to rproxy and sends
one of two request shapes. That is all a forward proxy ever receives:

| Client traffic | What rproxy receives | What it logs |
| --- | --- | --- |
| **Cleartext HTTP** | `GET http://host/path HTTP/1.1` (absolute-form) | **Full URL**, method, host, resolved IP |
| **HTTPS / any TLS** | `CONNECT host:443 HTTP/1.1` then opaque TLS | **host:port** (domain), **resolved IP**, timing, byte counts |

For HTTPS the domain comes from the `CONNECT` line and the IP from the upstream
socket — the payload stays encrypted and is relayed untouched.

### Important coverage limits (not bugs — inherent to a proxy-only setup)

- **QUIC / HTTP-3 (UDP 443) bypasses the proxy entirely.** Chrome, most Google
  apps, YouTube and anything using Cronet negotiate HTTP-3 by default and go
  direct — you will not see them. To force them through the proxy, disable QUIC
  in the client under test, or block outbound UDP/443 at the network so clients
  fall back to TCP+TLS.
- **The global proxy is a hint, not enforcement.** Apps with their own network
  stack can ignore it. Only an OS-level VPN or `root`+iptables enforces routing.
- **No SNI, no URL for HTTPS.** Only host (from `CONNECT`) + IP.
- **Keep-alive blind spot.** Only the *first* request on a reused TCP connection
  is parsed/logged; the rest is blind-relayed. Fine for a destination logger.

If you need to capture *everything* (including QUIC and non-proxy-aware apps),
that requires a VPN-based capture (Android `VpnService`) — a different tool.

---

## Build

Built and pinned to **Rust 1.96.1** (edition 2024) via
[rust-toolchain.toml](rust-toolchain.toml); rustup will select it automatically.

```sh
cargo build --release
# binary at target/release/rproxy(.exe)
```

Run the tests:

```sh
cargo test
```

## Docker

A multi-stage build produces a small (~25 MB) image on `distroless/cc`
(glibc for reliable DNS, no shell, runs as a non-root user). Its data directory
is **`/data`** (`RPROXY_DIR=/data`): on first run rproxy writes `rproxy.conf` and
`blocked.txt` there and loads them.

```sh
docker build -t rproxy .

# run it; point the Android device at <docker-host-ip>:20487
docker run --rm -p 20487:20487 rproxy

# keep + edit the config on the host: mount a folder over /data (first run
# populates it), then edit ./data/rproxy.conf and ./data/blocked.txt and restart
docker run --rm -p 20487:20487 -v "$PWD/data:/data" rproxy
```

Logs go to stdout — view with `docker logs <container>`. Or `docker compose up`
(see [docker-compose.yml](docker-compose.yml)).

> The mounted `/data` folder must be writable by the container user (uid
> 65532), otherwise rproxy can't create/edit its config and falls back to
> built-in defaults.

> **Caveat — client IP in logs:** with published ports (`-p`), Docker NATs the
> connection, so the `peer` field shows the Docker gateway (e.g. `172.17.0.1`),
> not the phone's real LAN IP. On Linux, run with `--network host` to see the
> real client address (host networking is limited on Docker Desktop for
> Windows/macOS).

## Usage

rproxy is **configured entirely through a config file**; the command line only
says *where* that file is:

```
rproxy                  # first run creates + loads the config, then serves
rproxy --dir ./conf     # keep the config in ./conf
rproxy --config my.conf # load a specific file
rproxy --help
```

Everything else is a `key = value` line in the config file (see
[Configuration file](#configuration-file)):

| key | default | meaning |
| --- | --- | --- |
| `listen` | `0.0.0.0:20487` | address to listen on |
| `log` | *(stdout only)* | also append log lines to this file |
| `verbose` | `false` | include the `Host` header on HTTP log lines |
| `json` | `false` | emit JSON Lines instead of text |
| `connect-timeout` | `10` | upstream connect timeout (seconds) |
| `head-timeout` | `30` | request-head read timeout (seconds) |
| `idle-timeout` | `300` | relay idle timeout (seconds), `0` = off |
| `max-conns` | `1024` | max concurrent connections |
| `blocking` | `off` | master switch — soft-blocking is applied only when `on` |
| `block` | — | soft-block a domain (+subdomains); repeatable |
| `blocklist` | — | soft-block domains from a file |
| `block-cap` | `13312` | bytes a blocked site may load before the drop |

Established tunnels are reclaimed after `idle-timeout` seconds with no traffic
in either direction (so a stalled client can't pin sockets/permits forever); the
default of 300 s is generous enough for WebSocket/long-poll heartbeats. In text
mode, control bytes in logged URLs/hosts are rendered as `\xNN` so a crafted
request can't inject terminal escapes into your log.

Text output (default):

```
2026-07-13T10:10:45.962Z [#1] GET http://example.com:80/ ip=172.66.147.243 <- 127.0.0.1:63850 host=example.com
2026-07-13T10:10:46.330Z [#2] CONNECT example.com:443 ip=172.66.147.243 <- 127.0.0.1:63852
2026-07-13T10:10:46.878Z [#2] CLOSE example.com:443 sent=659 recv=5745 dur=573ms
```

JSON Lines (`json = true`), one object per event (`connect` / `http` / `close` /
`error` / `info`), easy to `jq`:

```json
{"ts":"2026-07-13T10:11:29.348Z","id":1,"ev":"connect","host":"example.com","port":443,"ip":"172.66.147.243","peer":"127.0.0.1:50933"}
{"ts":"2026-07-13T10:11:29.497Z","id":1,"ev":"close","target":"example.com:443","c2u":659,"u2c":5745,"dur_ms":197}
```

The `#id` / `id` field correlates the open event with its `close`.

## Configuration file

**On first run, rproxy creates `rproxy.conf` and `blocked.txt` in its data
directory and loads `rproxy.conf` automatically** — no flags needed. Edit them
and restart. The data directory is resolved in this order:

1. `--dir <DIR>` if given,
2. the `RPROXY_DIR` environment variable (the Docker image sets it to `/data`),
3. otherwise **the folder next to the executable** (so on Windows the config
   sits right beside `rproxy.exe`).

The format is plain `key = value` (keys are listed in [Usage](#usage) above).
`#` starts a comment (whole-line, or trailing after a space — so a value may
contain a literal `#`), blank lines are ignored, and `block =` may be repeated.
Relative `log` / `blocklist` paths resolve against the config file's own
directory.

```ini
# rproxy.conf
listen  = 0.0.0.0:20487
verbose = true
idle-timeout = 300

block-cap = 13312
block = ads.example.com
block = tracker.example.net
# blocklist = blocked.txt
```

The committed [rproxy.conf](rproxy.conf) is a fully annotated template of every
option (with the defaults) — it's exactly what gets written on first run. Just
edit it and restart; there are no per-setting command-line flags to remember.

---

## Blocking sites (soft block)

A blocklisted destination is **not** hard-failed. The proxy still connects and
relays, but caps the bytes delivered to the client at `block-cap` (default
**13312 B = 13 KiB**) and then drops the connection — so the page starts
loading and dies mid-load. A partial/broken load is harder to diagnose and work
around than an instant "connection refused", and it works for HTTPS too (the
first ~13 KB of the TLS stream flows, then the tunnel is cut).

Blocking is **off by default** and turned on with one line in `rproxy.conf` —
the list stays configured either way, so you can toggle it without deleting
anything:

```ini
blocking = on            # ← the master switch (off = list ignored)

# a whole file, one domain per line...
blocklist = blocked.txt
# ...and/or a few inline domains (repeatable; matches subdomains too)
block = ads.example.com
block = adserver.net

# tune how much loads before the drop (e.g. 4 KiB)
block-cap = 4096
```

The shipped [rproxy.conf](rproxy.conf) already wires `blocklist = blocked.txt`
with `blocking = off`, so enabling the block list is just `blocking = on`. The
repo ships [blocked.txt](blocked.txt) — a ready-to-use, grouped starter list of
common ad / tracker / telemetry domains (63 entries), created in your data
directory on first run. Curate it for your needs.

- **Matching is subdomain-aware and case-insensitive:** `example.com` blocks
  `example.com`, `www.example.com`, `a.b.example.com` — but not `example.org`
  or `notexample.com`. A leading `*.` or `.` and case/trailing-dot are
  normalized away.
- **Works for both** cleartext HTTP (host from the URL) and HTTPS (host from the
  `CONNECT` line).
- Blocked events are marked in the log (` BLOCKED` in text, `"blocked":true` in
  JSON); the `CLOSE` line's `recv`/`u2c` shows the capped byte count.
- Caveat: the same coverage limits apply — a site reached over **QUIC/HTTP-3**
  or by an app that ignores the system proxy won't pass through here and so
  can't be blocked by it.

```
2026-07-13T11:31:18Z [#1] GET http://ads.example.com/x ip=93.184.216.34 <- 127.0.0.1:59736 BLOCKED
2026-07-13T11:31:20Z [#1] CLOSE http://ads.example.com/x sent=112 recv=13312 dur=2044ms
```

---

## Deploying for an Android 16 device

Pick one of two models. In both, `adb` sets the Global HTTP Proxy (it holds the
`WRITE_SECURE_SETTINGS` permission — **no root required**).

### Model A — run rproxy *on the phone* via Termux (simplest, most robust)

The phone proxies itself over loopback. Works on Wi-Fi and cellular, and the
address (`127.0.0.1`) never changes.

```sh
# in Termux
pkg update && pkg upgrade
pkg install rust
git clone <this repo> && cd rproxy   # or copy the sources over
cargo build --release

termux-wake-lock                       # keep it alive; also disable battery
                                       # optimization for Termux
./target/release/rproxy --dir ~/.rproxy
# first run writes ~/.rproxy/rproxy.conf — set `listen = 127.0.0.1:20487`
# (and `log = proxy.log`) there, then re-run
```

Point the device at it (non-root can't bind ports < 1024, so use 20487 or any
high port):

```sh
adb shell settings put global http_proxy 127.0.0.1:20487
```

### Model B — run rproxy on a PC on the same LAN

The default config already binds all interfaces (`0.0.0.0:20487`), reachable
from the phone; just run it and point the phone at the PC's LAN IP.

```sh
# on the PC — creates rproxy.conf next to the binary on first run
rproxy
```

- Find the PC IPv4: `ipconfig` (Windows) / `ip addr` (Linux). Give it a static
  IP or a DHCP reservation so it doesn't move.
- **Windows firewall** (admin) — allow inbound TCP 20487:
  ```
  netsh advfirewall firewall add rule name="rproxy 20487" dir=in action=allow protocol=TCP localport=20487
  ```
- Point the device at the PC:
  ```sh
  adb shell settings put global http_proxy 192.168.1.50:20487   # your PC LAN IP
  ```

> ⚠️ `0.0.0.0` makes this an **open proxy** on your LAN — anyone on the network
> can route through it. Only do this on a network you trust, and clear the rule
> when done.

### Cross-compiling for the device (Model B, push a binary instead of Termux)

Prefer `cargo-ndk` (avoids a linker version-script bug on Windows):

```sh
rustup target add aarch64-linux-android
cargo install cargo-ndk
# ANDROID_NDK_HOME must point at your NDK
cargo ndk -t arm64-v8a -p 30 build --release
adb push target/aarch64-linux-android/release/rproxy /data/local/tmp/
adb shell chmod +x /data/local/tmp/rproxy
adb shell /data/local/tmp/rproxy   # writes rproxy.conf into /data/local/tmp
```

### Managing the proxy setting with adb

```sh
# set
adb shell settings put global http_proxy 127.0.0.1:20487     # or PC_LAN_IP:20487
# verify
adb shell settings get global http_proxy
# CLEAR when done  (the value persists across reboots — a stale proxy is the
# usual cause of "phone has no internet" later)
adb shell settings put global http_proxy :0
```

You can also set it manually on the device: **Settings → Network & internet →
Wi-Fi → (your network) → Proxy → Manual**. Note that the Wi-Fi GUI proxy is
per-network; `adb ... global http_proxy` is the true global setting.

---

## How it works

```
src/
  main.rs      wire modules -> load config -> start multi-thread tokio runtime
  startup.rs   resolve the data dir, seed rproxy.conf/blocked.txt on first run
  config.rs    parse the config file into a Config (hand-rolled, no clap)
  http.rs      find CRLFCRLF, parse the request-line, IPv6-safe host:port split
  blocklist.rs subdomain-aware domain matching for the soft-block feature
  proxy.rs     accept loop (Semaphore backpressure, ctrl-c shutdown) + per-conn
               CONNECT tunnel / HTTP forwarding + concurrent idle-bounded relay
  logger.rs    std-only RFC3339 timestamps, async single-writer sink, text/JSON
```

- **CONNECT**: parse `host:port`, dial upstream (with timeout), reply
  `200 Connection Established`, flush any early client bytes, then
  `copy_bidirectional` relays the opaque stream. Logged: domain, IP, bytes.
- **Cleartext HTTP**: parse the absolute URL, dial upstream, rewrite the
  request-line to origin-form (headers preserved verbatim), forward, relay.
  Logged: full URL, IP, bytes.
- One `tokio::spawn` per connection; a `Semaphore` caps concurrency; a single
  writer thread keeps log lines from interleaving. Errors on one connection
  never take down the accept loop.

## License

MIT OR Apache-2.0
