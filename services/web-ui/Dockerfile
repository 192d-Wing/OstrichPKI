# OstrichPKI Web UI Service Dockerfile
#
# COMPLIANCE MAPPING:
# - NIST 800-53: CM-2 (Baseline Configuration)
# - NIST 800-53: CM-6 (Configuration Settings)
# - NIST 800-53: SA-10 (Developer Configuration Management)
# - NIST 800-53: SC-18 (Mobile Code) - CSP nonces prevent unauthorized scripts
#
# Build stages:
# 1. wasm-builder: Builds the Yew WASM client with Trunk
# 2. server-builder: Builds the Axum server
# 3. runtime: Final minimal image with both components

# ==============================================================================
# Stage 1: WASM Builder (Yew client)
# ==============================================================================
FROM rust:1.96-bookworm AS wasm-builder

# Install wasm target and trunk. Do NOT `cargo install wasm-bindgen-cli`: that
# compiles the CLI from source (slow, and a freshly published version can fail
# to build on the runner — wasm-bindgen-cli 0.2.125 broke the arm64 build).
# Trunk downloads the prebuilt wasm-bindgen binary that exactly matches the
# project's wasm-bindgen dependency, so the explicit install is both unnecessary
# and a version-mismatch risk.
RUN rustup target add wasm32-unknown-unknown \
    && cargo install trunk

# Install Node.js for Tailwind CSS. Pin Tailwind to v3 to match the project's
# package.json (^3.4.19): the styles use v3 syntax (@tailwind directives, JS
# tailwind.config.js, @apply). Tailwind v4 moved the CLI to @tailwindcss/cli, so
# an unpinned `npm install -g tailwindcss` installs v4 and `npx tailwindcss`
# fails with "could not determine executable to run".
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && npm install -g tailwindcss@^3.4.19

WORKDIR /app

# Copy the full workspace. Even though the wasm32 client only compiles its own
# (yew/wasm-bindgen) dependency set, Cargo must be able to LOAD every workspace
# member's manifest to resolve the workspace at all, so all member directories
# must be present. config/ + proto/ mirror the server build context.
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY services/ ./services/
COPY tools/ ./tools/
COPY benches/ ./benches/
COPY tests/ ./tests/
COPY migrations/ ./migrations/
COPY config/ ./config/
COPY proto/ ./proto/

# Build the WASM client
WORKDIR /app/services/web-ui

# Generate Tailwind CSS
RUN npx tailwindcss -i ./input.css -o ./output.css --minify

# Build WASM with trunk
RUN trunk build --release

# Build the React (preview) SPA with pnpm. corepack ships with Node 20 and pins
# the version from web/package.json's "packageManager". Served at /next during
# the Yew→React migration (P1); the Yew bundle above remains the app at /.
WORKDIR /app/services/web-ui/web
RUN corepack enable \
    && pnpm install --frozen-lockfile \
    && pnpm build
WORKDIR /app/services/web-ui

# ==============================================================================
# Stage 2a: Server Chef base — toolchain, FIPS build deps, and cargo-chef
# ==============================================================================
# cargo-chef caches dependency compilation (the expensive aws-lc-fips C/asm
# build) separately from the workspace source, so a routine source edit no
# longer rebuilds the whole crypto stack. Mirrors the root Dockerfile.
FROM rust:1.96-bookworm AS server-chef

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
# Stage 3: Runtime Image
# ==============================================================================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
# NIST 800-53: CM-6 - Minimal software installation
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
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

# Copy WASM build artifacts (static files)
COPY --from=wasm-builder /app/services/web-ui/dist/ /app/static/

# Copy index.html template for server-side nonce injection
COPY --from=wasm-builder /app/services/web-ui/index.html /app/templates/index.html

# React (preview) SPA: hashed assets join the static tree (served at
# /static/assets/* under the CSP 'self' source); its index.html is read by the
# server at /next for nonce + config injection (see server/template.rs).
COPY --from=wasm-builder /app/services/web-ui/web/dist/assets/ /app/static/assets/
COPY --from=wasm-builder /app/services/web-ui/web/dist/index.html /app/static/next-index.html

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
