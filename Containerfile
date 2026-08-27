# hecate-warden — L2 hecate-om service: the deceptive threshold guard.
#
# Runs as a sidecar to macula-station on the PUBLIC boxes. Storeless (no
# reckon-db), so the runtime is lean, but it still depends on hecate_om, which
# brings the macula mesh SDK and its Rust QUIC NIF — so the builder carries the
# Rust toolchain and builds that NIF from source (never a fetched artifact), the
# same as every macula-linked image.
#
# Pushed to ghcr.io/hecate-services/hecate-warden:latest + :semver.

#----------------------------------------------------------------------
# Stage 1 — builder: Erlang + Rust + rebar3 + deps + release
#----------------------------------------------------------------------
FROM docker.io/erlang:27-alpine AS builder
WORKDIR /build

# hecate_om 0.15.0 made barrel_docdb (RocksDB-backed) a hard dependency.
# erocksdb's CMake build:
#   - openssl-dev: does find_package(OpenSSL) and fails outright without the
#     dev headers.
#   - zstd-dev: without it, falls back to building zstd from a
#     bundled/vendored copy the hex package doesn't actually ship (a
#     git-submodule path never populated by `rebar3 get-deps`), failing
#     with "No download info given for 'zstd'".
#   - snappy-dev, lz4-dev: unlike zstd, a missing system snappy/lz4 does NOT
#     fail the CMake configure — it silently disables that compression
#     backend and the build succeeds. The break only shows up at RUNTIME:
#     confirmed live 2026-08-27, barrel_docdb's db_open failed with
#     "Invalid argument: The specified blob compression type Snappy is not
#     available" the moment a real database was opened. A clean build is
#     not proof this is fixed — only starting the release and opening a
#     store is.
RUN apk add --no-cache git curl bash build-base cmake perl linux-headers openssl-dev zstd-dev snappy-dev lz4-dev
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"
ENV RUSTFLAGS="-C target-feature=-crt-static"
ENV MACULA_FORCE_SOURCE_BUILD=1
# rebar3 runs the macula NIF build hook in a subprocess whose PATH lacks
# /root/.cargo/bin, so symlink the rustup proxies onto the default PATH.
RUN ln -sf /root/.cargo/bin/rustup /usr/local/bin/cargo \
    && ln -sf /root/.cargo/bin/rustup /usr/local/bin/rustc \
    && ln -sf /root/.cargo/bin/rustup /usr/local/bin/rustup \
    && cargo --version && rustc --version

RUN curl -fsSL https://s3.amazonaws.com/rebar3/rebar3 -o /usr/local/bin/rebar3 \
    && chmod +x /usr/local/bin/rebar3

# Deps first (cacheable until rebar.config changes). No rebar.lock in git.
COPY rebar.config ./
RUN rebar3 get-deps

COPY config ./config
COPY apps ./apps
RUN rebar3 as prod release

#----------------------------------------------------------------------
# Stage 2 — runtime: bare Alpine + the assembled release
#----------------------------------------------------------------------
FROM docker.io/alpine:3.22
# zstd-libs, snappy, lz4-libs: the *runtime* shared libraries matching the
# builder stage's zstd-dev/snappy-dev/lz4-dev. Confirmed live 2026-08-27
# these are genuinely separate packages on Alpine (dev vs runtime, same
# split as openssl/openssl-dev) -- erocksdb's NIF linked against
# liblz4.so.1 at build time, then failed to LOAD it at boot with "Error
# loading shared library liblz4.so.1: No such file or directory", crash-
# looping the whole release. A clean build proves nothing here either.
RUN apk add --no-cache ncurses-libs libstdc++ libgcc openssl ca-certificates curl zstd-libs snappy lz4-libs
WORKDIR /app
COPY --from=builder /build/_build/prod/rel/hecate_warden ./
RUN mkdir -p /var/lib/hecate-warden

ENV HOME=/app
# Substitute ${VAR} in vm.args/sys.config from the container env at boot.
ENV RELX_REPLACE_OS_VARS=true

# Per-node defaults; every ${VAR} in sys.config/vm.args must resolve or the term
# is malformed. The deploy overrides realm, node name/host/cookie, and ports.
ENV HECATE_NODE_NAME=hecate_warden
ENV HECATE_NODE_HOST=127.0.0.1
ENV HECATE_COOKIE=hecate_warden
ENV HECATE_HEALTH_PORT=8460
# Decoy ports the tarpit binds — NOT the box's real sshd. An Erlang list literal
# (textual substitution). Override per box.
ENV HECATE_WARDEN_TARPIT_PORTS="[2222,2323,23]"
ENV HECATE_WARDEN_MAX_CONNS=65536
# The host auth log, mounted read-only. The sensor tails it for real attacks on
# the box's real sshd; it never writes and never touches sshd.
ENV HECATE_WARDEN_AUTH_LOG=/host/log/auth.log
# A human name for this warden ("helsinki"). Travels on every fact it publishes.
ENV HECATE_WARDEN_LABEL=unknown

# Realm service-principal cert mounts here; station socket under /run/macula.
VOLUME ["/etc/hecate/secrets", "/var/lib/hecate-warden"]

# Health is loopback-only (in-container check). The tarpit's decoy ports are
# bound directly on the host under --network host, so they are not EXPOSEd here.
EXPOSE 8460
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${HECATE_HEALTH_PORT}/health" || exit 1

ENTRYPOINT ["/app/bin/hecate_warden"]
CMD ["foreground"]
