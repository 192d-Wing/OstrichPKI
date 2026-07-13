# OstrichPKI Web UI Service Dockerfile
#
# COMPLIANCE MAPPING:
# - NIST 800-53: CM-2 (Baseline Configuration)
# - NIST 800-53: CM-6 (Configuration Settings)
# - NIST 800-53: SA-10 (Developer Configuration Management)
# - NIST 800-53: SC-18 (Mobile Code) - CSP nonces prevent unauthorized scripts
#
# Build stages:
# 1. web-builder: Builds the React (AWS Cloudscape) console with pnpm
# 2. server-builder: Builds the Axum server
# 3. runtime: Final minimal image with both components

# ==============================================================================
# Stage 1: Web Builder (React + AWS Cloudscape console)
# ==============================================================================
# The React console is the primary app (served at /). The Vite build only needs
# services/web-ui/web — no Rust workspace — so this is a small Node-only stage.
# corepack pins pnpm from web/package.json's "packageManager".
FROM node:20-bookworm-slim AS web-builder
WORKDIR /app/web
COPY services/web-ui/web/ ./
RUN corepack enable \
    && pnpm install --frozen-lockfile \
    && pnpm build

# ==============================================================================
# Stage 2a: Server Chef base — toolchain, FIPS build deps, and cargo-chef
# ==============================================================================
# cargo-chef caches dependency compilation (the expensive aws-lc-fips C/asm
# build) separately from the workspace source, so a routine source edit no
# longer rebuilds the whole crypto stack. Mirrors the root Dockerfile.
FROM rust:1.97-bookworm AS server-chef

# Install build dependencies. The server binary's dependency graph pulls in the
# FIPS crypto module (aws-lc-fips-sys, via rustls / ostrich-crypto), which builds
# from source with cmake and additionally needs clang/libclang (bindgen) plus
# golang + perl (aws-lc/cmake/go.cmake code/asm generation). Without these the
# aws-lc cmake build panics. Mirrors the root Dockerfile's builder stage.
RUN apt-get update && apt-get install -y \
    clang \
    libclang-dev \
    cmake \
    golang-go \
    perl \
    pkg-config \
    libssl-dev \
    libpq-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-chef --locked
WORKDIR /app

# ==============================================================================
# Stage 2b: Server Planner — capture the dependency recipe
# ==============================================================================
FROM server-chef AS server-planner
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY services/ ./services/
COPY tools/ ./tools/
COPY benches/ ./benches/
COPY tests/ ./tests/
COPY migrations/ ./migrations/
COPY config/ ./config/
COPY proto/ ./proto/
RUN cargo chef prepare --recipe-path recipe.json

# ==============================================================================
# Stage 2c: Server Builder — cook web-ui deps (cached), then build the binary
# ==============================================================================
FROM server-chef AS server-builder

# Build scripts can run during `cook`: ostrich-protocol's build.rs compiles the
# gRPC definitions in proto/, and ostrich-common include_str!s JSON schemas under
# config/. Provide both before cooking so the dependency build never fails.
COPY proto/ ./proto/
COPY config/ ./config/

# Cook only the web-ui binary's dependency graph (cached until a dep changes).
COPY --from=server-planner /app/recipe.json recipe.json
RUN cargo chef cook --release -p ostrich-web-ui --recipe-path recipe.json

# Now the real source; only the workspace crates recompile.
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY services/ ./services/
COPY tools/ ./tools/
COPY benches/ ./benches/
COPY tests/ ./tests/
COPY migrations/ ./migrations/

# Build only the web-ui server binary
RUN cargo build --release -p ostrich-web-ui

# ==============================================================================
# Stage 3: Runtime Image — Iron Bank UBI 10 (multi-arch: amd64 + arm64)
# ==============================================================================
# Hardened DoD Iron Bank Red Hat UBI base (replaces debian:bookworm-slim).
FROM registry1.dso.mil/ironbank/redhat/ubi/ubi10:10.2 AS runtime

# Install runtime dependencies (RHEL/UBI package names).
# NIST 800-53: CM-6 - Minimal software installation
#   - ca-certificates : trust store
#   - openssl-libs    : libcrypto/libssl (the web-ui binary links openssl via reqwest)
#   - libpq           : PostgreSQL client library
# curl for the HEALTHCHECK is already present in the UBI base image.
RUN dnf install -y --setopt=install_weak_deps=0 \
        ca-certificates \
        openssl-libs \
        libpq \
    && dnf clean all \
    && useradd -r -u 1000 -s /sbin/nologin ostrich

# Create application directories
# NIST 800-53: AC-6 - Least Privilege
RUN mkdir -p /app/static /app/config \
    && chown -R ostrich:ostrich /app

WORKDIR /app

# Labels
LABEL org.opencontainers.image.title="OstrichPKI Web UI"
LABEL org.opencontainers.image.description="Web administration interface for OstrichPKI"
LABEL org.opencontainers.image.vendor="OstrichPKI"

# Copy server binary
COPY --from=server-builder /app/target/release/ostrich-web-ui /usr/local/bin/

# React console: the Vite build (index.html + hashed /static/assets/* + any
# public assets) is the entire static tree. index.html is read by the server for
# per-request nonce + runtime-config injection (see server/template.rs); the
# hashed assets are served under the CSP 'self' source at /static/assets/*.
COPY --from=web-builder /app/web/dist/ /app/static/

# Health check
# NIST 800-53: SI-17 - Fail-Safe Procedures
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run as non-root user
USER ostrich

# Expose HTTP port
EXPOSE 8080

# Environment variables with secure defaults
# NIST 800-53: CM-6 - Configuration Settings
ENV RUST_LOG=info
ENV WEBUI_LISTEN_ADDRESS=0.0.0.0:8080
ENV STATIC_FILES_DIRECTORY=/app/static
ENV STATIC_FILES_URL_PREFIX=/static

# Default command
ENTRYPOINT ["ostrich-web-ui"]
CMD ["--config", "/app/config/web-ui.json"]
