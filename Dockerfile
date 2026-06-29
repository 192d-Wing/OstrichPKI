# OstrichPKI Multi-Service Dockerfile
#
# COMPLIANCE MAPPING:
# - NIST 800-53: CM-2 (Baseline Configuration)
# - NIST 800-53: CM-6 (Configuration Settings)
# - NIST 800-53: SA-10 (Developer Configuration Management)
# - NIST 800-53: SI-7 (Software/Firmware Integrity)
#
# This Dockerfile builds all OstrichPKI services using a multi-stage build
# to minimize the final image size and attack surface.

# ==============================================================================
# Stage 1a: Chef base — toolchain, FIPS build deps, and cargo-chef
# ==============================================================================
# cargo-chef splits dependency compilation (the expensive aws-lc-fips C/asm
# build) from workspace-source compilation. The dependency layer is keyed on the
# dependency set (recipe.json), so it stays cached across builds until a
# dependency actually changes — a routine source edit no longer rebuilds the
# whole crypto stack from scratch.
FROM rust:1.96-bookworm AS chef

# Install build dependencies for the FIPS crypto module (aws-lc-fips-sys):
#   - clang + libclang-dev: bindgen
#   - cmake: drives the aws-lc build
#   - golang + perl: the FIPS module is built from source and uses Go for code
#     generation and Perl for assembly generation (aws-lc/cmake/go.cmake)
# Without these the ostrich-crypto build fails.
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
# Stage 1b: Planner — capture the dependency recipe from the workspace
# ==============================================================================
FROM chef AS planner
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
# Stage 1c: Builder — cook dependencies (cached), then build the workspace
# ==============================================================================
FROM chef AS builder

# Build scripts can run during `cook`: ostrich-protocol's build.rs compiles the
# gRPC definitions in proto/, and several crates include_str! JSON schemas under
# config/. Provide both before cooking so the dependency build never fails on a
# missing path.
COPY proto/ ./proto/
COPY config/ ./config/

# Cook ONLY the dependency graph. This layer is keyed on recipe.json (the
# dependency set), so it is reused across builds until a dependency changes —
# the expensive aws-lc-fips compile is paid once, not on every source edit.
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Now the real workspace source. With dependencies already compiled above, only
# the workspace crates recompile.
# NIST 800-53: SA-10 - Developer Configuration Management
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY services/ ./services/
COPY tools/ ./tools/
COPY benches/ ./benches/
COPY tests/ ./tests/
COPY migrations/ ./migrations/
RUN cargo build --release --workspace

# ==============================================================================
# Stage 2: Runtime Base Image
# ==============================================================================
FROM debian:bookworm-slim AS runtime-base

# Install runtime dependencies
# NIST 800-53: CM-6 - Minimal software installation
# softhsm2 provides a PKCS#11 token for development; production deployments
# mount a real HSM's PKCS#11 module instead (NIAP PP-CA FCS_STG_EXT.1).
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libpq5 \
    curl \
    softhsm2 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 1000 -s /sbin/nologin ostrich

# Create necessary directories with proper permissions
# NIST 800-53: AC-6 - Least Privilege
# /app/tokens holds the SoftHSM token store (shared volume between the
# one-shot ca-init container and ca-service).
RUN mkdir -p /app/config /app/certs /app/data /app/tokens \
    && chown -R ostrich:ostrich /app

# Point SoftHSM at the shared token directory
COPY docker/softhsm2.conf /app/config/softhsm2.conf
ENV SOFTHSM2_CONF=/app/config/softhsm2.conf

WORKDIR /app

# ==============================================================================
# Stage 3: CA Service
# ==============================================================================
FROM runtime-base AS ca-service

# NIST 800-53: SC-17 - PKI Certificates (this IS the CA service)
LABEL org.opencontainers.image.title="OstrichPKI CA Service"
LABEL org.opencontainers.image.description="Certificate Authority core service"
LABEL org.opencontainers.image.vendor="OstrichPKI"

# Copy the CA service binary
COPY --from=builder /app/target/release/ostrich-ca-server /usr/local/bin/

# Copy migrations for database setup
COPY --from=builder /app/migrations /app/migrations

# Health check endpoint
# NIST 800-53: SI-17 - Fail-Safe Procedures
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run as non-root user
USER ostrich

# Expose gRPC and REST ports
EXPOSE 50051 8080

# Environment variables with secure defaults
# NIST 800-53: CM-6 - Configuration Settings
ENV RUST_LOG=info
ENV CA_BIND_ADDRESS=0.0.0.0:50051
ENV CA_REST_ADDRESS=0.0.0.0:8080

ENTRYPOINT ["ostrich-ca-server"]

# ==============================================================================
# Stage 4: ACME Service
# ==============================================================================
FROM runtime-base AS acme-service

LABEL org.opencontainers.image.title="OstrichPKI ACME Service"
LABEL org.opencontainers.image.description="RFC 8555 ACME protocol service"
LABEL org.opencontainers.image.vendor="OstrichPKI"

COPY --from=builder /app/target/release/ostrich-acme-server /usr/local/bin/

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

USER ostrich
EXPOSE 8080

ENV RUST_LOG=info
ENV ACME_BIND_ADDRESS=0.0.0.0:8080

ENTRYPOINT ["ostrich-acme-server"]

# ==============================================================================
# Stage 5: EST Service
# ==============================================================================
FROM runtime-base AS est-service

LABEL org.opencontainers.image.title="OstrichPKI EST Service"
LABEL org.opencontainers.image.description="RFC 7030 EST enrollment service"
LABEL org.opencontainers.image.vendor="OstrichPKI"

COPY --from=builder /app/target/release/ostrich-est-server /usr/local/bin/

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8443/health || exit 1

USER ostrich
EXPOSE 8443

ENV RUST_LOG=info
ENV EST_BIND_ADDRESS=0.0.0.0:8443

ENTRYPOINT ["ostrich-est-server"]

# ==============================================================================
# Stage 6: OCSP Service
# ==============================================================================
FROM runtime-base AS ocsp-service

LABEL org.opencontainers.image.title="OstrichPKI OCSP Responder"
LABEL org.opencontainers.image.description="RFC 6960 OCSP responder service"
LABEL org.opencontainers.image.vendor="OstrichPKI"

COPY --from=builder /app/target/release/ostrich-ocsp-server /usr/local/bin/

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/health || exit 1

USER ostrich
EXPOSE 8081

ENV RUST_LOG=info
ENV OCSP_BIND_ADDRESS=0.0.0.0:8081

ENTRYPOINT ["ostrich-ocsp-server"]

# ==============================================================================
# Stage 7: SCMS Service
# ==============================================================================
FROM runtime-base AS scms-service

LABEL org.opencontainers.image.title="OstrichPKI SCMS Service"
LABEL org.opencontainers.image.description="Smartcard Management System service"
LABEL org.opencontainers.image.vendor="OstrichPKI"

COPY --from=builder /app/target/release/ostrich-scms-server /usr/local/bin/

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8082/health || exit 1

USER ostrich
EXPOSE 8082

ENV RUST_LOG=info
ENV SCMS_BIND_ADDRESS=0.0.0.0:8082

ENTRYPOINT ["ostrich-scms-server"]

# ==============================================================================
# Stage 8: KRA Service
# ==============================================================================
FROM runtime-base AS kra-service

LABEL org.opencontainers.image.title="OstrichPKI KRA Service"
LABEL org.opencontainers.image.description="Key Recovery Authority service"
LABEL org.opencontainers.image.vendor="OstrichPKI"

COPY --from=builder /app/target/release/ostrich-kra-server /usr/local/bin/

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8083/health || exit 1

USER ostrich
EXPOSE 8083

ENV RUST_LOG=info
ENV KRA_BIND_ADDRESS=0.0.0.0:8083

ENTRYPOINT ["ostrich-kra-server"]

# ==============================================================================
# Stage 9: CLI Tools
# ==============================================================================
FROM runtime-base AS cli

LABEL org.opencontainers.image.title="OstrichPKI CLI"
LABEL org.opencontainers.image.description="OstrichPKI command-line tools"
LABEL org.opencontainers.image.vendor="OstrichPKI"

COPY --from=builder /app/target/release/ostrich-cli /usr/local/bin/
COPY --from=builder /app/target/release/ostrich-init /usr/local/bin/

# One-shot CA bootstrap script (SoftHSM token init + root CA registration)
# used by the ca-init compose service. NIAP PP-CA: FCS_CKM.1
COPY --chmod=755 docker/ca-init.sh /usr/local/bin/ca-init.sh

USER ostrich

ENTRYPOINT ["ostrich-cli"]

# ==============================================================================
# Stage 10: NPE Portal Web Builder (React/Vite SPA)
# ==============================================================================
# The NPE portal binary serves a static SPA from ./dist; build it here so the
# runtime image carries only the compiled assets (no node toolchain).
FROM node:22-bookworm-slim AS npe-portal-web-builder
WORKDIR /web

# Install dependencies first so this layer is cached until package.json changes.
# No lockfile is committed for the SPA (matches services/web-ui/web), so `npm
# install` resolves fresh — pinned, audited dependency upgrades happen in PRs.
COPY services/npe-portal/web/package.json ./
RUN npm install --no-audit --no-fund

# Build the SPA. `npm run build` runs `tsc --noEmit && vite build` -> /web/dist.
COPY services/npe-portal/web/ ./
RUN npm run build

# ==============================================================================
# Stage 11: NPE Portal (mTLS BFF + React SPA)
# ==============================================================================
# A standalone Non-Person Entity enrollment portal: an Axum BFF authenticated by
# mTLS client certificate (OID->role), serving the SPA and proxying an
# allowlisted set of CA/EST routes.
FROM runtime-base AS npe-portal

# NIST 800-53: IA-2 (mTLS identification), AC-3 (OID->role + proxy allowlist)
LABEL org.opencontainers.image.title="OstrichPKI NPE Portal"
LABEL org.opencontainers.image.description="Non-Person Entity PKI enrollment portal (mTLS, OID-to-role)"
LABEL org.opencontainers.image.vendor="OstrichPKI"

# The BFF binary, the compiled SPA (served from the configured staticFiles
# directory, /app/static, under the /static prefix matching Vite's base), and a
# baseline config (production overrides by mounting config/npe-portal.json).
COPY --from=builder /app/target/release/ostrich-npe-portal /usr/local/bin/
COPY --from=npe-portal-web-builder /web/dist /app/static
COPY --from=builder /app/config/npe-portal.example.json /app/config/npe-portal.json

# The portal requires mTLS, so an HTTP health check cannot complete the TLS
# handshake without a client certificate; check that the listener accepts a TCP
# connection instead (SI-17 — liveness without weakening the auth posture).
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/8443' || exit 1

USER ostrich

# mTLS HTTPS listener.
EXPOSE 8443

# NIST 800-53: CM-6 - secure defaults. The portal fails closed without mTLS
# material unless NPE_ALLOW_INSECURE is set (development only).
ENV RUST_LOG=info
ENV NPE_BIND_ADDRESS=0.0.0.0:8443

ENTRYPOINT ["ostrich-npe-portal"]
