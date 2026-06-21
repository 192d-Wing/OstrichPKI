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
# Stage 1: Build Environment
# ==============================================================================
FROM rust:1.96-bookworm AS builder

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

# Create a new directory for the application
WORKDIR /app

# Copy the Cargo workspace files first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY services/ ./services/
COPY tools/ ./tools/
COPY benches/ ./benches/
COPY tests/ ./tests/
COPY migrations/ ./migrations/

# Build all workspace members in release mode
# NIST 800-53: SA-10 - Developer Configuration Management
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
