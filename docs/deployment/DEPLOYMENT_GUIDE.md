# OstrichPKI Deployment Guide

This document provides comprehensive deployment procedures for OstrichPKI in production environments.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Architecture Overview](#architecture-overview)
3. [Deployment Options](#deployment-options)
4. [Configuration](#configuration)
5. [Database Setup](#database-setup)
6. [HSM Integration](#hsm-integration)
7. [Service Deployment](#service-deployment)
8. [Health Checks](#health-checks)
9. [Monitoring](#monitoring)
10. [Backup & Recovery](#backup--recovery)

---

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16+ GB |
| Storage | 100 GB SSD | 500+ GB NVMe |
| Network | 1 Gbps | 10 Gbps |

### Software Dependencies

- **Rust**: 1.92+ (for building from source)
- **PostgreSQL**: 15+
- **Redis**: 7+ (optional, for session caching)
- **Docker**: 24+ (for containerized deployment)
- **HSM**: PKCS#11 compatible (SoftHSM2 for development)

### COMPLIANCE MAPPING
- NIST 800-53: CM-2 (Baseline Configuration)
- NIST 800-53: CM-6 (Configuration Settings)

---

## Architecture Overview

```
                                    ┌─────────────────┐
                                    │   Load Balancer │
                                    │   (TLS Term)    │
                                    └────────┬────────┘
                                             │
              ┌──────────────────────────────┼──────────────────────────────┐
              │                              │                              │
      ┌───────▼───────┐            ┌─────────▼─────────┐          ┌────────▼────────┐
      │   ACME API    │            │     EST API       │          │   OCSP API      │
      │   (8080)      │            │     (8443)        │          │   (8081)        │
      └───────┬───────┘            └─────────┬─────────┘          └────────┬────────┘
              │                              │                              │
              └──────────────────────────────┼──────────────────────────────┘
                                             │
                                    ┌────────▼────────┐
                                    │   CA Service    │
                                    │   (gRPC 50051)  │
                                    └────────┬────────┘
                                             │
              ┌──────────────────────────────┼──────────────────────────────┐
              │                              │                              │
      ┌───────▼───────┐            ┌─────────▼─────────┐          ┌────────▼────────┐
      │   PostgreSQL  │            │      HSM         │          │  Audit Logger   │
      │   (5432)      │            │   (PKCS#11)      │          │                 │
      └───────────────┘            └───────────────────┘          └─────────────────┘
```

---

## Deployment Options

### Option 1: Docker Compose (Development/Testing)

```bash
# Clone repository
git clone https://github.com/yourorg/ostrich-pki.git
cd ostrich-pki

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Start all services
docker-compose up -d

# Verify services
docker-compose ps
```

### Option 2: Kubernetes (Production)

See [kubernetes/](../kubernetes/) for Helm charts and manifests.

```bash
# Add Helm repository
helm repo add ostrich-pki https://charts.ostrich-pki.io

# Install with custom values
helm install ostrich-pki ostrich-pki/ostrich-pki \
  --namespace pki \
  --create-namespace \
  -f values-production.yaml
```

### Option 3: Bare Metal

```bash
# Build release binaries
cargo build --release

# Install binaries
sudo install -m 755 target/release/ostrich-* /usr/local/bin/

# Create service user
sudo useradd -r -s /sbin/nologin ostrich

# Create directories
sudo mkdir -p /etc/ostrich-pki /var/lib/ostrich-pki /var/log/ostrich-pki
sudo chown ostrich:ostrich /var/lib/ostrich-pki /var/log/ostrich-pki

# Install systemd units
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
```

---

## Configuration

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://ostrich:password@localhost:5432/ostrich_pki

# HSM Configuration
HSM_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so
HSM_SLOT=0
HSM_PIN=secure-pin-here

# TLS Configuration
TLS_CERT_PATH=/etc/ostrich-pki/tls/server.crt
TLS_KEY_PATH=/etc/ostrich-pki/tls/server.key
TLS_CA_PATH=/etc/ostrich-pki/tls/ca.crt

# Service Ports
ACME_PORT=8080
EST_PORT=8443
OCSP_PORT=8081
CA_GRPC_PORT=50051

# Logging
RUST_LOG=info
LOG_FORMAT=json

# Audit
AUDIT_LOG_PATH=/var/log/ostrich-pki/audit.log
```

### COMPLIANCE MAPPING
- NIST 800-53: CM-6 (Configuration Settings)
- NIST 800-53: AC-17 (Remote Access) - mTLS configuration

### Configuration File (`/etc/ostrich-pki/config.toml`)

```toml
[database]
url = "postgresql://ostrich:password@localhost:5432/ostrich_pki"
max_connections = 20
min_connections = 5
connection_timeout_secs = 30

[hsm]
module_path = "/usr/lib/softhsm/libsofthsm2.so"
slot = 0
# PIN should be provided via environment variable HSM_PIN

[ca]
name = "OstrichPKI Root CA"
validity_days = 3650
crl_validity_hours = 24
ocsp_responder_url = "http://ocsp.example.com"
crl_distribution_point = "http://crl.example.com/root.crl"

[acme]
directory_url = "https://acme.example.com/directory"
terms_of_service_url = "https://example.com/tos"
max_names_per_cert = 100
challenge_timeout_secs = 300

[est]
enable_mtls = true
client_ca_path = "/etc/ostrich-pki/tls/client-ca.crt"

[audit]
enabled = true
log_path = "/var/log/ostrich-pki/audit.log"
retention_days = 365
sign_entries = true
```

---

## Database Setup

### PostgreSQL Installation

```bash
# Install PostgreSQL 15
sudo apt install postgresql-15

# Create database and user
sudo -u postgres psql <<EOF
CREATE USER ostrich WITH PASSWORD 'secure-password';
CREATE DATABASE ostrich_pki OWNER ostrich;
GRANT ALL PRIVILEGES ON DATABASE ostrich_pki TO ostrich;
EOF
```

### Run Migrations

```bash
# Using sqlx-cli
cargo install sqlx-cli
sqlx database create
sqlx migrate run

# Or using the initialization tool
ostrich-init database --migrate
```

### COMPLIANCE MAPPING
- NIST 800-53: CP-9 (System Backup)
- NIST 800-53: SC-28 (Protection of Information at Rest)

---

## HSM Integration

### SoftHSM2 (Development)

```bash
# Install SoftHSM2
sudo apt install softhsm2

# Initialize token
softhsm2-util --init-token --slot 0 --label "OstrichPKI" \
  --pin 1234 --so-pin 5678

# Verify
softhsm2-util --show-slots
```

### Hardware HSM (Production)

See vendor-specific documentation for:
- Thales Luna Network HSM
- AWS CloudHSM
- Azure Dedicated HSM
- Google Cloud HSM

### COMPLIANCE MAPPING
- NIST 800-53: SC-12 (Cryptographic Key Management)
- NIST 800-53: SC-13 (Cryptographic Protection)
- NIAP PP-CA: FCS_CKM.1 (Cryptographic Key Generation)

---

## Service Deployment

### Systemd Service Files

**CA Service** (`/etc/systemd/system/ostrich-ca.service`):
```ini
[Unit]
Description=OstrichPKI Certificate Authority Service
After=network.target postgresql.service

[Service]
Type=simple
User=ostrich
Group=ostrich
EnvironmentFile=/etc/ostrich-pki/env
ExecStart=/usr/local/bin/ostrich-ca --config /etc/ostrich-pki/config.toml
Restart=always
RestartSec=5
LimitNOFILE=65535

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/ostrich-pki /var/log/ostrich-pki

[Install]
WantedBy=multi-user.target
```

**ACME Service** (`/etc/systemd/system/ostrich-acme.service`):
```ini
[Unit]
Description=OstrichPKI ACME Service
After=network.target ostrich-ca.service

[Service]
Type=simple
User=ostrich
Group=ostrich
EnvironmentFile=/etc/ostrich-pki/env
ExecStart=/usr/local/bin/ostrich-acme --config /etc/ostrich-pki/config.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Start Services

```bash
sudo systemctl enable ostrich-ca ostrich-acme ostrich-est ostrich-ocsp
sudo systemctl start ostrich-ca ostrich-acme ostrich-est ostrich-ocsp

# Check status
sudo systemctl status ostrich-*
```

---

## Health Checks

### Endpoint Health Checks

```bash
# ACME Directory
curl -s http://localhost:8080/directory | jq .

# OCSP Health
curl -s http://localhost:8081/health

# EST Health (requires mTLS)
curl -s --cert client.crt --key client.key \
  https://localhost:8443/.well-known/est/cacerts

# CA gRPC Health
grpcurl -plaintext localhost:50051 grpc.health.v1.Health/Check
```

### Database Health

```bash
# Check connection pool
psql -U ostrich -d ostrich_pki -c "SELECT count(*) FROM pg_stat_activity WHERE datname='ostrich_pki';"
```

### HSM Health

```bash
# Check PKCS#11 token status
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --show-info
```

---

## Monitoring

### Prometheus Metrics

All services expose Prometheus metrics at `/metrics`:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'ostrich-pki'
    static_configs:
      - targets:
        - 'localhost:8080'  # ACME
        - 'localhost:8443'  # EST
        - 'localhost:8081'  # OCSP
```

### Key Metrics

| Metric | Description |
|--------|-------------|
| `ostrich_certificates_issued_total` | Total certificates issued |
| `ostrich_certificates_revoked_total` | Total certificates revoked |
| `ostrich_acme_orders_total` | ACME orders by status |
| `ostrich_ocsp_requests_total` | OCSP requests by response |
| `ostrich_hsm_operations_total` | HSM operations by type |
| `ostrich_audit_events_total` | Audit events by type |

### Alerting Rules

See [monitoring/alerts.yaml](../monitoring/alerts.yaml) for recommended alerting rules.

### COMPLIANCE MAPPING
- NIST 800-53: AU-6 (Audit Review, Analysis, and Reporting)
- NIST 800-53: SI-4 (Information System Monitoring)

---

## Backup & Recovery

### Database Backup

```bash
# Full backup
pg_dump -U ostrich ostrich_pki | gzip > backup_$(date +%Y%m%d).sql.gz

# Point-in-time recovery setup
# Enable WAL archiving in postgresql.conf:
# archive_mode = on
# archive_command = 'cp %p /backup/wal/%f'
```

### HSM Key Backup

See [HSM_KEY_BACKUP.md](./HSM_KEY_BACKUP.md) for HSM-specific key backup procedures.

### Recovery Procedures

1. **Database Recovery**:
   ```bash
   gunzip < backup_YYYYMMDD.sql.gz | psql -U ostrich ostrich_pki
   ```

2. **Service Recovery**:
   ```bash
   sudo systemctl restart ostrich-*
   ```

### COMPLIANCE MAPPING
- NIST 800-53: CP-9 (System Backup)
- NIST 800-53: CP-10 (System Recovery and Reconstitution)

---

## Security Hardening

### Firewall Rules

```bash
# Allow only necessary ports
sudo ufw allow 8080/tcp  # ACME (external)
sudo ufw allow 8443/tcp  # EST (external, mTLS)
sudo ufw allow 8081/tcp  # OCSP (external)
sudo ufw deny 50051/tcp  # CA gRPC (internal only)
```

### TLS Configuration

- Minimum TLS version: 1.3
- Cipher suites: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
- Certificate rotation: 90 days
- OCSP stapling: enabled

### COMPLIANCE MAPPING
- NIST 800-53: SC-8 (Transmission Confidentiality and Integrity)
- NIST 800-53: SC-23 (Session Authenticity)

---

## Troubleshooting

### Common Issues

1. **HSM Connection Failure**
   ```bash
   # Check PKCS#11 module
   pkcs11-tool --module $HSM_MODULE_PATH --show-info

   # Verify permissions
   ls -la $HSM_MODULE_PATH
   ```

2. **Database Connection Issues**
   ```bash
   # Test connection
   psql -U ostrich -h localhost -d ostrich_pki -c "SELECT 1;"

   # Check pg_hba.conf for authentication rules
   ```

3. **Service Won't Start**
   ```bash
   # Check logs
   journalctl -u ostrich-ca -f

   # Verify configuration
   ostrich-ca --config /etc/ostrich-pki/config.toml --check
   ```

---

## Next Steps

- [RUNBOOK.md](./RUNBOOK.md) - Operational runbook for day-to-day operations
- [INCIDENT_RESPONSE.md](./INCIDENT_RESPONSE.md) - Incident response procedures
- [HSM_KEY_BACKUP.md](./HSM_KEY_BACKUP.md) - HSM key backup and recovery
