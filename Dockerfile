# syntax=docker/dockerfile:1

# ---- build stage -----------------------------------------------------------
# Pinned to Rust 1.96.1 (matches rust-toolchain.toml) on bookworm, so the
# produced glibc binary matches the debian12 runtime.
FROM rust:1.96.1-slim-bookworm AS build
WORKDIR /src

# rproxy.conf / blocked.txt are embedded (include_str!) as the first-run
# templates, so they must be present at build time.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY rproxy.conf blocked.txt ./

# Build the real binary. `--locked` enforces the committed Cargo.lock.
# (No dependency-caching stub trick — under Docker its stale mtime could make
# cargo skip the real compile and ship an empty `fn main(){}` binary.)
RUN cargo build --release --locked

# Seed the data dir with the default config so `docker run` works out of the box
# even without a mounted volume (and even if /data ends up read-only): the files
# are already present, so nothing needs to be written at runtime.
RUN mkdir -p /data && cp rproxy.conf blocked.txt /data/

# ---- runtime stage ---------------------------------------------------------
# distroless/cc: glibc + CA certs, no shell/package manager (small attack
# surface), and runs as a non-root user (uid 65532) by default.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/rproxy /usr/local/bin/rproxy
COPY --from=build --chown=65532:65532 /data /data

# rproxy writes/reads its config here on first run; mount a host dir over it to
# edit rproxy.conf / blocked.txt from outside (must be writable by uid 65532).
ENV RPROXY_DIR=/data
VOLUME ["/data"]

EXPOSE 20487
ENTRYPOINT ["/usr/local/bin/rproxy"]
# No default flags: the seeded /data/rproxy.conf governs (listen 0.0.0.0:20487).
# Append flags after the image name to override, e.g. `docker run rproxy --dir /x`.
CMD []
