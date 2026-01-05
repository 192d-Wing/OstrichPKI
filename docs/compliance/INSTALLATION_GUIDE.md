# OstrichPKI Installation Guide

**Document Version:** 1.1
**Last Updated:** January 2026
**OstrichPKI Version:** 0.15.0
**NIAP Reference:** AGD_PRE.1 - Preparative Procedures
**Audience:** System Administrators, Security Engineers

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Secure Delivery Verification](#3-secure-delivery-verification)
4. [Installation Methods](#4-installation-methods)
5. [Initial Configuration](#5-initial-configuration)
6. [HSM Setup](#6-hsm-setup)
7. [Database Setup](#7-database-setup)
8. [TLS Certificate Configuration](#8-tls-certificate-configuration)
9. [CA Initialization](#9-ca-initialization)
10. [Post-Installation Verification](#10-post-installation-verification)
11. [Security Hardening](#11-security-hardening)

---

## 1. Overview

### 1.1 Purpose

This document provides secure installation procedures for OstrichPKI in compliance with NIAP PP-CA v2.1 preparative procedures (AGD_PRE.1).

### 1.2 Security Considerations

**Warning:** OstrichPKI is a security-critical system. Installation must be performed by trained personnel in a controlled environment.

- All installation steps are auditable
- HSM must be physically secured
- Network isolation recommended during initial setup
- Two-person integrity (TPI) recommended for CA key generation

### 1.3 Component Overview

| Component | Description | Port |
|-----------|-------------|------|
| CA Service | Certificate Authority core | 8443 |
| ACME Service | Automated certificate management | 443 |
| EST Service | Enrollment over Secure Transport | 8444 |
| OCSP Service | Certificate status | 80, 443 |
| Audit Service | Security event logging | Internal |
| KRA Service | Key Recovery Agent | Internal |
| SCMS Service | Token/Smartcard management | 8445 |

---

## 2. Prerequisites

### 2.1 Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16+ GB |
| Storage | 100 GB SSD | 500 GB+ NVMe |
| HSM | FIPS 140-2 Level 2 | FIPS 140-2 Level 3 |

### 2.2 Software Requirements

| Software | Version | Purpose |
|----------|---------|---------|
| Operating System | RHEL 8/9, Ubuntu 22.04+ | Base OS |
| PostgreSQL | 14+ | Certificate database |
| Docker | 24+ | Container runtime (optional) |
| Kubernetes | 1.28+ | Orchestration (optional) |

### 2.3 Network Requirements

| Port | Protocol | Purpose | Source |
|------|----------|---------|--------|
| 443 | HTTPS | ACME, OCSP | Internet |
| 8443 | HTTPS | CA Admin API | Internal |
| 8444 | HTTPS | EST | Internal |
| 8445 | HTTPS | SCMS | Internal |
| 5432 | TCP | PostgreSQL | Localhost |
| 123 | UDP | NTP | NTP servers |

### 2.4 HSM Requirements

Supported HSMs:

- Thales Luna Network HSM 7 (FIPS 140-2 Level 3)
- AWS CloudHSM (FIPS 140-2 Level 3)
- Azure Dedicated HSM (FIPS 140-2 Level 3)
- SoftHSM 2.x (Development only - NOT for production)

**Production Requirement:** FIPS 140-2 Level 2 or higher validated HSM

---

## 3. Secure Delivery Verification

### 3.1 Download Verification

**Warning:** Always verify the integrity and authenticity of downloaded packages.

```bash
# Download release package
wget https://releases.ostrich-pki.io/v1.0.0/ostrich-pki-v1.0.0-linux-amd64.tar.gz

# Download signature and checksums
wget https://releases.ostrich-pki.io/v1.0.0/ostrich-pki-v1.0.0-linux-amd64.tar.gz.sig
wget https://releases.ostrich-pki.io/v1.0.0/SHA256SUMS
wget https://releases.ostrich-pki.io/v1.0.0/SHA256SUMS.sig
```

### 3.2 Verify Checksum

```bash
# Verify SHA-256 checksum
sha256sum -c SHA256SUMS 2>&1 | grep ostrich-pki-v1.0.0-linux-amd64.tar.gz

# Expected output:
# ostrich-pki-v1.0.0-linux-amd64.tar.gz: OK
```

### 3.3 Verify Signature

```bash
# Import OstrichPKI release signing key
gpg --keyserver keys.openpgp.org --recv-keys 0xABCD1234EFGH5678

# Verify key fingerprint matches published fingerprint
gpg --fingerprint 0xABCD1234EFGH5678

# Verify package signature
gpg --verify ostrich-pki-v1.0.0-linux-amd64.tar.gz.sig

# Expected output should include:
# Good signature from "OstrichPKI Release Signing Key <release@ostrich-pki.io>"
```

### 3.4 SBOM Verification

```bash
# Download Software Bill of Materials
wget https://releases.ostrich-pki.io/v1.0.0/sbom.json

# Verify SBOM signature
gpg --verify sbom.json.sig

# Review SBOM for known vulnerabilities
# Use tools like Grype or Syft
grype sbom:sbom.json
```

---

## 4. Installation Methods

### 4.1 Binary Installation (Recommended for Production)

```bash
# Extract package
tar -xzf ostrich-pki-v1.0.0-linux-amd64.tar.gz
cd ostrich-pki-v1.0.0

# Install binaries
sudo ./install.sh

# Installed components:
# /usr/local/bin/ostrich-ca
# /usr/local/bin/ostrich-acme
# /usr/local/bin/ostrich-est
# /usr/local/bin/ostrich-ocsp
# /usr/local/bin/ostrich-admin
# /etc/ostrich-pki/ (configuration)
# /var/lib/ostrich-pki/ (data)
# /var/log/ostrich-pki/ (logs)

# Install systemd services
sudo cp systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### 4.2 Docker Installation (Development/Testing)

**See Also:** [Docker Deployment Guide](../DOCKER_GUIDE.md) for comprehensive documentation

```bash
# Pull official images (v0.15.0)
docker pull ghcr.io/ostrich-pki/ca-service:0.15.0
docker pull ghcr.io/ostrich-pki/acme-service:0.15.0
docker pull ghcr.io/ostrich-pki/est-service:0.15.0
docker pull ghcr.io/ostrich-pki/ocsp-service:0.15.0
docker pull ghcr.io/ostrich-pki/scms-service:0.15.0
docker pull ghcr.io/ostrich-pki/kra-service:0.15.0

# Verify image signatures
docker trust inspect ghcr.io/ostrich-pki/ca-service:0.15.0

# Quick start with docker-compose
git clone https://github.com/ostrich-pki/ostrich-pki.git
cd ostrich-pki

# Set environment variables
export POSTGRES_PASSWORD=strongpassword
export RUST_LOG=info

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f ca-service

# Check status
docker-compose ps

# Access services
curl http://localhost:8080/health      # CA service
curl http://localhost:8081/acme/directory  # ACME directory
curl http://localhost:8082/health      # OCSP service
```

**⚠️ Docker Deployment Notes:**

- **Development Only**: Docker setup uses SoftHSM (not FIPS 140-2 validated)
- **Production**: Use Kubernetes with real HSM for NIAP compliance
- **HSM Requirement**: Set `REQUIRE_HSM=true` and mount real HSM in production
- **Architecture**: 7 services (CA, ACME, EST, OCSP, SCMS, KRA, PostgreSQL)
- **Networks**: Internal (service-to-service) and external (public-facing)
- **Volumes**: Persistent storage for database, certificates, and configurations
- **Health Checks**: All services include health monitoring
- **Security**: Non-root containers (UID 1000), minimal images (~52-55MB)

**Docker Compose Architecture:**

```
External Network: ACME (:8081), EST (:8443), OCSP (:8082), CA REST (:8080)
        ↓
Internal Network: CA gRPC (:50051), SCMS (:8083), KRA (:8084), PostgreSQL (:5432)
```

### 4.3 Kubernetes Installation (Helm)

```bash
# Add Helm repository
helm repo add ostrich-pki https://charts.ostrich-pki.io
helm repo update

# Install with custom values
helm install ostrich-pki ostrich-pki/ostrich-pki \
  --namespace ostrich-pki \
  --create-namespace \
  --values values.yaml

# Verify deployment
kubectl get pods -n ostrich-pki
```

---

## 5. Initial Configuration

### 5.1 Create Configuration Directory

```bash
sudo mkdir -p /etc/ostrich-pki/{tls,profiles}
sudo mkdir -p /var/lib/ostrich-pki
sudo mkdir -p /var/log/ostrich-pki/audit

# Set permissions
sudo chown -R ostrich:ostrich /etc/ostrich-pki
sudo chown -R ostrich:ostrich /var/lib/ostrich-pki
sudo chown -R ostrich:ostrich /var/log/ostrich-pki
sudo chmod 700 /etc/ostrich-pki
sudo chmod 700 /var/lib/ostrich-pki
sudo chmod 700 /var/log/ostrich-pki
```

### 5.2 Create Main Configuration

```bash
sudo cat > /etc/ostrich-pki/config.yaml << 'EOF'
# OstrichPKI Configuration
# Version: 1.0

service:
  name: "OstrichPKI Production CA"
  environment: production
  log_level: info

# Database - configure after PostgreSQL setup
database:
  host: localhost
  port: 5432
  name: ostrich_pki
  username: ostrich_app
  # Password from environment: OSTRICH_DB_PASSWORD
  ssl_mode: require
  max_connections: 50

# HSM - configure after HSM setup
hsm:
  provider: pkcs11
  library_path: /usr/lib/softhsm/libsofthsm2.so
  slot: 0
  # PIN from environment: OSTRICH_HSM_PIN

# TLS - configure after certificate setup
tls:
  min_version: "1.3"
  cert_path: /etc/ostrich-pki/tls/server.crt
  key_path: /etc/ostrich-pki/tls/server.key
  client_ca_path: /etc/ostrich-pki/tls/client-ca.crt
  require_client_cert: true

# Audit configuration
audit:
  enabled: true
  storage_path: /var/log/ostrich-pki/audit
  max_size_gb: 100
  retention_days: 365
  hash_algorithm: sha256
  alert_threshold_percent: 80

# Time synchronization
time:
  ntp_servers:
    - time.nist.gov
    - time.windows.com
  max_drift_seconds: 5
  sync_interval_minutes: 60

# Self-test configuration
self_test:
  run_on_startup: true
  periodic_interval_hours: 24
  fail_action: halt
EOF

sudo chmod 600 /etc/ostrich-pki/config.yaml
```

### 5.3 Create Environment File

```bash
sudo cat > /etc/ostrich-pki/environment << 'EOF'
# OstrichPKI Environment Variables
# WARNING: Contains sensitive credentials

# Database password
OSTRICH_DB_PASSWORD=<generate_strong_password>

# HSM PIN
OSTRICH_HSM_PIN=<hsm_user_pin>

# Configuration path
OSTRICH_CONFIG_PATH=/etc/ostrich-pki/config.yaml

# Log level
OSTRICH_LOG_LEVEL=info
EOF

sudo chmod 600 /etc/ostrich-pki/environment
sudo chown ostrich:ostrich /etc/ostrich-pki/environment
```

---

## 6. HSM Setup

### 6.1 SoftHSM Setup (Development Only)

**Warning:** SoftHSM is for development and testing only. Use hardware HSM for production.

```bash
# Install SoftHSM
sudo apt-get install softhsm2

# Initialize token
softhsm2-util --init-token --slot 0 --label "OstrichPKI" \
  --so-pin <security_officer_pin> --pin <user_pin>

# Verify token
softhsm2-util --show-slots

# Configure library path in config.yaml
# library_path: /usr/lib/softhsm/libsofthsm2.so
```

### 6.2 Thales Luna HSM Setup

```bash
# Install Luna client
sudo ./install.sh

# Register HSM partition
vtl addServer -n <hsm_hostname> -c <cert_path>

# Create network trust link
vtl createCert -n <client_hostname>

# Register partition
vtl addSlot -p <partition_password> -n <partition_name>

# Verify connection
cmu list

# Configure library path
# library_path: /usr/safenet/lunaclient/lib/libCryptoki2_64.so
```

### 6.3 AWS CloudHSM Setup

```bash
# Install CloudHSM client
wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-client-latest.el7.x86_64.rpm
sudo yum install ./cloudhsm-client-latest.el7.x86_64.rpm

# Configure cluster
sudo /opt/cloudhsm/bin/configure -a <hsm_ip>

# Activate crypto user
/opt/cloudhsm/bin/cloudhsm_mgmt_util /opt/cloudhsm/etc/cloudhsm_mgmt_util.cfg
# createUser CU ostrich_pki <password>

# Configure library path
# library_path: /opt/cloudhsm/lib/libcloudhsm_pkcs11.so
```

### 6.4 Verify HSM Connection

```bash
# Test HSM connection
ostrich-admin hsm test

# Expected output:
# HSM Connection: OK
# Provider: PKCS#11
# Slot: 0
# Token: OstrichPKI
# Mechanisms: RSA, ECDSA, AES, SHA-256, ...
```

---

## 7. Database Setup

### 7.1 Install PostgreSQL

```bash
# Install PostgreSQL 15
sudo apt-get install postgresql-15

# Enable and start service
sudo systemctl enable postgresql
sudo systemctl start postgresql
```

### 7.2 Create Database and User

```bash
# Switch to postgres user
sudo -u postgres psql

-- Create database
CREATE DATABASE ostrich_pki;

-- Create application user
CREATE USER ostrich_app WITH ENCRYPTED PASSWORD '<strong_password>';

-- Grant permissions
GRANT CONNECT ON DATABASE ostrich_pki TO ostrich_app;
GRANT USAGE ON SCHEMA public TO ostrich_app;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ostrich_app;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ostrich_app;

-- Create audit user (read-only for audit exports)
CREATE USER ostrich_audit WITH ENCRYPTED PASSWORD '<audit_password>';
GRANT CONNECT ON DATABASE ostrich_pki TO ostrich_audit;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ostrich_audit;

\q
```

### 7.3 Configure SSL for PostgreSQL

```bash
# Generate server certificate
openssl req -new -x509 -days 3650 -nodes \
  -out /var/lib/postgresql/15/main/server.crt \
  -keyout /var/lib/postgresql/15/main/server.key \
  -subj "/CN=postgres.local"

# Set permissions
sudo chown postgres:postgres /var/lib/postgresql/15/main/server.{crt,key}
sudo chmod 600 /var/lib/postgresql/15/main/server.key

# Configure postgresql.conf
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'

# Configure pg_hba.conf
hostssl ostrich_pki ostrich_app 127.0.0.1/32 scram-sha-256
hostssl ostrich_pki ostrich_audit 127.0.0.1/32 scram-sha-256

# Restart PostgreSQL
sudo systemctl restart postgresql
```

### 7.4 Initialize Database Schema

```bash
# Run database migrations
ostrich-admin db migrate

# Verify schema
ostrich-admin db status

# Expected output:
# Database: ostrich_pki
# Schema version: 1.0.0
# Tables: certificates, revocations, audit_events, ...
# Connection: OK
```

---

## 8. TLS Certificate Configuration

### 8.1 Generate Server Certificates

For production, obtain certificates from a trusted CA. For initial setup:

```bash
# Generate CA for internal TLS (temporary - replace with production CA)
openssl genrsa -out /etc/ostrich-pki/tls/internal-ca.key 4096
openssl req -new -x509 -days 3650 -key /etc/ostrich-pki/tls/internal-ca.key \
  -out /etc/ostrich-pki/tls/internal-ca.crt \
  -subj "/CN=OstrichPKI Internal CA/O=OstrichPKI"

# Generate server certificate
openssl genrsa -out /etc/ostrich-pki/tls/server.key 2048
openssl req -new -key /etc/ostrich-pki/tls/server.key \
  -out /etc/ostrich-pki/tls/server.csr \
  -subj "/CN=ca.example.com/O=Example Org" \
  -addext "subjectAltName=DNS:ca.example.com,DNS:localhost"

openssl x509 -req -days 365 \
  -in /etc/ostrich-pki/tls/server.csr \
  -CA /etc/ostrich-pki/tls/internal-ca.crt \
  -CAkey /etc/ostrich-pki/tls/internal-ca.key \
  -CAcreateserial \
  -out /etc/ostrich-pki/tls/server.crt \
  -extfile <(echo "subjectAltName=DNS:ca.example.com,DNS:localhost")

# Set permissions
sudo chmod 600 /etc/ostrich-pki/tls/*.key
sudo chmod 644 /etc/ostrich-pki/tls/*.crt
```

### 8.2 Configure Client CA (for mTLS)

```bash
# Copy client CA certificate (used to verify admin certificates)
sudo cp /path/to/client-ca.crt /etc/ostrich-pki/tls/client-ca.crt

# For testing, use the internal CA
sudo cp /etc/ostrich-pki/tls/internal-ca.crt /etc/ostrich-pki/tls/client-ca.crt
```

---

## 9. CA Initialization

### 9.1 Generate CA Signing Key

**Warning:** This step should be performed with two-person integrity (TPI).

```bash
# Generate CA key in HSM
ostrich-admin ca init \
  --algorithm ecdsa-p384 \
  --label "Root-CA-2026" \
  --validity-years 20

# For post-quantum hybrid:
ostrich-admin ca init \
  --algorithm hybrid-ecdsa-mldsa65 \
  --label "Root-CA-PQ-2026" \
  --validity-years 20

# Output:
# CA Key Generated
# Key ID: <uuid>
# Algorithm: ECDSA P-384
# Label: Root-CA-2026
# HSM Slot: 0
# IMPORTANT: Record this Key ID securely
```

### 9.2 Generate CA Certificate

```bash
# Generate self-signed root CA certificate
ostrich-admin ca generate-cert \
  --key-id <key_id_from_previous_step> \
  --subject "CN=Example Root CA,O=Example Organization,C=US" \
  --validity-years 20 \
  --output /etc/ostrich-pki/ca.crt

# View CA certificate
openssl x509 -in /etc/ostrich-pki/ca.crt -text -noout
```

### 9.3 Create Initial Administrator

```bash
# Create first administrator account
ostrich-admin user create \
  --username admin \
  --email admin@example.com \
  --full-name "System Administrator" \
  --role administrator

# Generate enrollment invitation
ostrich-admin user enroll --username admin

# Output:
# Enrollment URL: https://ca.example.com/enroll/<token>
# One-time code: XXXX-XXXX-XXXX
# Valid for: 24 hours
```

---

## 10. Post-Installation Verification

### 10.1 Run Self-Tests

```bash
# Execute all self-tests
ostrich-admin self-test run

# Expected output:
# ============================================
# OstrichPKI Self-Test Results
# ============================================
# Cryptographic KAT (RSA-2048): PASS
# Cryptographic KAT (ECDSA-P256): PASS
# Cryptographic KAT (ECDSA-P384): PASS
# Cryptographic KAT (SHA-256): PASS
# Cryptographic KAT (AES-256): PASS
# DRBG Health Test: PASS
# HSM Connectivity: PASS
# Database Connectivity: PASS
# Time Source Verification: PASS
# Audit System: PASS
# ============================================
# Overall Result: PASS
# ============================================
```

### 10.2 Verify Service Health

```bash
# Start services
sudo systemctl start ostrich-ca
sudo systemctl start ostrich-acme
sudo systemctl start ostrich-est
sudo systemctl start ostrich-ocsp

# Check status
sudo systemctl status ostrich-ca

# Run health check
ostrich-admin health

# Expected output:
# Service Status: HEALTHY
# Components:
#   CA Service: Running
#   ACME Service: Running
#   EST Service: Running
#   OCSP Service: Running
#   HSM: Connected
#   Database: Connected
#   Time Sync: OK (drift: 0.2s)
#   Audit Storage: OK (0.1%)
```

### 10.3 Verify Audit Logging

```bash
# Check that installation events were logged
ostrich-admin audit list --limit 10

# Expected events:
# - ServiceStartup
# - SelfTestCompleted
# - CaKeyGenerated
# - CaCertificateGenerated
# - UserCreated
```

### 10.4 Test Certificate Issuance

```bash
# Generate test CSR
openssl req -new -newkey rsa:2048 -nodes \
  -keyout test.key -out test.csr \
  -subj "/CN=test.example.com"

# Issue test certificate
ostrich-admin cert issue \
  --csr test.csr \
  --profile tls-server \
  --validity-days 30 \
  --output test.crt

# Verify certificate
openssl verify -CAfile /etc/ostrich-pki/ca.crt test.crt

# Clean up test files
rm test.key test.csr test.crt
```

---

## 11. Security Hardening

### 11.1 File Permissions

```bash
# Verify critical file permissions
ls -la /etc/ostrich-pki/

# Required permissions:
# config.yaml: 600 (rw-------)
# environment: 600 (rw-------)
# tls/*.key: 600 (rw-------)
# tls/*.crt: 644 (rw-r--r--)

# Fix if necessary
sudo chmod 600 /etc/ostrich-pki/config.yaml
sudo chmod 600 /etc/ostrich-pki/environment
sudo chmod 600 /etc/ostrich-pki/tls/*.key
```

### 11.2 Network Hardening

```bash
# Configure firewall (example for UFW)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 443/tcp    # ACME, OCSP
sudo ufw allow 8443/tcp from 10.0.0.0/8  # CA Admin (internal only)
sudo ufw allow 8444/tcp from 10.0.0.0/8  # EST (internal only)
sudo ufw enable

# Verify
sudo ufw status verbose
```

### 11.3 SELinux/AppArmor

```bash
# For SELinux (RHEL/CentOS)
sudo semanage fcontext -a -t bin_t "/usr/local/bin/ostrich-*"
sudo restorecon -Rv /usr/local/bin/ostrich-*

# For AppArmor (Ubuntu)
sudo cp /etc/ostrich-pki/apparmor/ostrich-ca /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/ostrich-ca
```

### 11.4 Secure Boot Verification

```bash
# Verify Secure Boot is enabled (if applicable)
mokutil --sb-state

# Verify kernel is signed
dmesg | grep -i secure

# Verify OstrichPKI binaries are signed
# (If using signed release builds)
```

### 11.5 Final Checklist

Before putting the system into production, verify:

- [ ] All self-tests pass
- [ ] HSM is FIPS 140-2 Level 2+ validated (production)
- [ ] Database SSL is enabled
- [ ] TLS 1.3 minimum is enforced
- [ ] File permissions are correct
- [ ] Firewall rules are configured
- [ ] Time synchronization is working
- [ ] Audit logging is operational
- [ ] Backup procedures are tested
- [ ] Administrator can authenticate and perform operations
- [ ] Certificate issuance works correctly

---

## Appendix A: Troubleshooting Installation

### A.1 HSM Connection Issues

```bash
# Check HSM library
ls -la /usr/lib/softhsm/libsofthsm2.so

# Check slot configuration
softhsm2-util --show-slots

# Test PKCS#11 directly
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -L
```

### A.2 Database Connection Issues

```bash
# Test PostgreSQL connection
psql -h localhost -U ostrich_app -d ostrich_pki -c "SELECT 1"

# Check PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-15-main.log

# Verify SSL
psql "host=localhost dbname=ostrich_pki user=ostrich_app sslmode=require"
```

### A.3 Service Start Failures

```bash
# Check service logs
sudo journalctl -u ostrich-ca -f

# Check for port conflicts
sudo netstat -tlnp | grep 8443

# Verify configuration
ostrich-admin config validate
```

---

## Appendix B: Uninstallation

```bash
# Stop services
sudo systemctl stop ostrich-ca ostrich-acme ostrich-est ostrich-ocsp

# Disable services
sudo systemctl disable ostrich-ca ostrich-acme ostrich-est ostrich-ocsp

# Remove binaries
sudo rm /usr/local/bin/ostrich-*

# Remove configuration (backup first!)
sudo tar -czf /backup/ostrich-pki-config-backup.tar.gz /etc/ostrich-pki
sudo rm -rf /etc/ostrich-pki

# Remove data (backup first!)
sudo tar -czf /backup/ostrich-pki-data-backup.tar.gz /var/lib/ostrich-pki
sudo rm -rf /var/lib/ostrich-pki

# Remove logs (backup first!)
sudo tar -czf /backup/ostrich-pki-logs-backup.tar.gz /var/log/ostrich-pki
sudo rm -rf /var/log/ostrich-pki

# Remove systemd services
sudo rm /etc/systemd/system/ostrich-*.service
sudo systemctl daemon-reload
```

---

**Document History:**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | January 2026 | OstrichPKI Team | Initial release |
