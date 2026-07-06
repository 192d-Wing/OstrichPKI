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
# Stage 2a: SoftHSM provider
# ==============================================================================
# SoftHSM2 provides a PKCS#11 token for development (production mounts a real
# HSM's module — NIAP PP-CA FCS_STG_EXT.1). It is not in the Iron Bank UBI repos
# (upstream ships it in EPEL), and SoftHSM 2.6.1 does not build against UBI's
# OpenSSL 3 (it uses the removed ENGINE rdrand API). So take Debian's already
# OpenSSL-3-patched package: OpenSSL 3.x is ABI-stable (libcrypto.so.3), so the
# module + util load cleanly against UBI's openssl-libs/sqlite-libs/libstdc++.
FROM debian:bookworm-slim AS softhsm-provider
RUN apt-get update && apt-get install -y softhsm2 && rm -rf /var/lib/apt/lists/*

# ==============================================================================
# Stage 2b: Runtime Base Image — Iron Bank UBI 10 (multi-arch: amd64 + arm64)
# ==============================================================================
# Hardened DoD Iron Bank Red Hat UBI base (replaces debian:bookworm-slim).
# Package management is dnf/RHEL, not apt/Debian.
FROM registry1.dso.mil/ironbank/redhat/ubi/ubi10:10.2 AS runtime-base
ARG TARGETARCH

# Install runtime dependencies (RHEL/UBI package names).
# NIST 800-53: CM-6 - Minimal software installation
#   - ca-certificates : trust store
#   - openssl-libs    : libcrypto/libssl for the SoftHSM module + any dynamic TLS
#   - sqlite-libs     : SoftHSM's token store backend
#   - libpq           : PostgreSQL client library
#   - libstdc++       : C++ runtime for softhsm2-util
# curl for the HEALTHCHECKs is already present in the UBI base image.
RUN dnf install -y --setopt=install_weak_deps=0 \
        ca-certificates \
        openssl-libs \
        sqlite-libs \
        libpq \
        libstdc++ \
    && dnf clean all \
    && useradd -r -u 1000 -s /sbin/nologin ostrich

# SoftHSM2 (module + CLI) from the Debian provider. The module lands at the stable
# path the deployment's PKCS11_MODULE_PATH uses (/usr/lib/softhsm/libsofthsm2.so),
# and a per-arch symlink satisfies softhsm2-util's compiled-in default module path
# (Debian multiarch dir), so `softhsm2-util` in docker/ca-init.sh works unchanged.
COPY --from=softhsm-provider /usr/lib/*/softhsm/libsofthsm2.so /usr/lib/softhsm/libsofthsm2.so
COPY --from=softhsm-provider /usr/bin/softhsm2-util /usr/local/bin/softhsm2-util
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) triplet=x86_64-linux-gnu ;; \
      arm64) triplet=aarch64-linux-gnu ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    mkdir -p "/usr/lib/${triplet}/softhsm"; \
    ln -sf /usr/lib/softhsm/libsofthsm2.so "/usr/lib/${triplet}/softhsm/libsofthsm2.so"

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
# Stage: Notify Service (certificate-expiry notifications; NATS -> SMTP)
# ==============================================================================
FROM runtime-base AS notify-service

LABEL org.opencontainers.image.title="OstrichPKI Notify Service"
LABEL org.opencontainers.image.description="Certificate-expiry notification service (NATS JetStream -> SMTP)"
LABEL org.opencontainers.image.vendor="OstrichPKI"

COPY --from=builder /app/target/release/ostrich-notify-server /usr/local/bin/

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8090/health || exit 1

USER ostrich
EXPOSE 8090

ENV RUST_LOG=info
ENV NOTIFY_HEALTH_ADDRESS=0.0.0.0:8090

ENTRYPOINT ["ostrich-notify-server"]

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
FROM node:26-bookworm-slim AS npe-portal-web-builder
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
