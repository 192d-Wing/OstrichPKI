# OstrichPKI Administrative Guidance

**Document Version:** 1.0
**Last Updated:** January 2026
**NIAP Reference:** AGD_OPE.1 - Operational User Guidance
**Audience:** CA Administrators, Operations Staff, Security Officers

---

## Table of Contents

1. [Overview](#1-overview)
2. [Security Roles and Responsibilities](#2-security-roles-and-responsibilities)
3. [System Configuration](#3-system-configuration)
4. [Certificate Lifecycle Operations](#4-certificate-lifecycle-operations)
5. [Key Management](#5-key-management)
6. [Audit Log Management](#6-audit-log-management)
7. [User Management](#7-user-management)
8. [Security Monitoring](#8-security-monitoring)
9. [Backup and Recovery](#9-backup-and-recovery)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Overview

### 1.1 Purpose

This document provides operational guidance for administrators and operators of OstrichPKI. It covers secure configuration, daily operations, and security management procedures required for NIAP PP-CA v2.1 compliance.

### 1.2 Scope

This guide covers:
- Role-based access control configuration
- Certificate Authority operations
- Key management procedures
- Audit log review and management
- Security monitoring and incident response
- Backup and disaster recovery

### 1.3 Prerequisites

Before using this guide, ensure:
- OstrichPKI is installed per [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md)
- HSM is initialized and configured
- Database is operational
- TLS certificates are deployed
- Initial administrator account is created

### 1.4 Document Conventions

| Convention | Meaning |
|------------|---------|
| `command` | Command to execute |
| `<variable>` | Replace with actual value |
| **Warning** | Security-critical information |
| **Note** | Additional information |

---

## 2. Security Roles and Responsibilities

### 2.1 Role Definitions

OstrichPKI implements five security roles per NIAP PP-CA v2.1:

| Role | Description | Primary Responsibilities |
|------|-------------|-------------------------|
| **Administrator** | System configuration and user management | Install, configure, maintain system; manage users; backup keys |
| **Operations Staff** | Certificate lifecycle operations | Issue, revoke, renew certificates; generate CRLs |
| **Auditor** | Security monitoring and log review | Review audit logs; generate compliance reports |
| **RA Staff** | Registration authority functions | Verify identity; approve certificate requests |
| **AOR** | Policy authority | Define certificate policies; approve policy changes |

### 2.2 Separation of Duties

**Critical Requirement:** The following role combinations are prohibited:

| Prohibited Combination | Reason |
|-----------------------|--------|
| Administrator + Operations Staff | Prevents single person from configuring system and issuing certificates |
| Auditor + Operations Staff | Prevents hiding certificate operations from audit |
| AOR + Operations Staff | Prevents policy maker from executing operations |

### 2.3 Role Assignment

**Administrator Only:** Role assignment requires Administrator privileges.

```bash
# Assign role to user
ostrich-admin user add-role --user <username> --role <role>

# Available roles: administrator, operations, auditor, ra_staff, aor

# List user roles
ostrich-admin user list-roles --user <username>

# Remove role from user
ostrich-admin user remove-role --user <username> --role <role>
```

### 2.4 Role Permissions Matrix

| Operation | Admin | Ops | Auditor | RA | AOR |
|-----------|-------|-----|---------|----|----|
| Issue Certificate | - | Yes | - | - | - |
| Revoke Certificate | - | Yes | - | - | - |
| Generate CRL | - | Yes | - | - | - |
| View Audit Logs | Yes | - | Yes | - | Yes |
| Export Audit Logs | - | - | Yes | - | - |
| Modify Configuration | Yes | - | - | - | - |
| Manage Users | Yes | - | - | - | - |
| Backup CA Key | Yes | - | - | - | - |
| Approve Requests | - | - | - | Yes | - |
| Modify Policy | - | - | - | - | Yes |

---

## 3. System Configuration

### 3.1 Configuration Files

| File | Purpose | Access |
|------|---------|--------|
| `/etc/ostrich-pki/config.yaml` | Main configuration | Administrator |
| `/etc/ostrich-pki/ca-policy.yaml` | Certificate policies | AOR |
| `/etc/ostrich-pki/profiles/*.yaml` | Certificate profiles | Administrator |
| `/etc/ostrich-pki/hsm.yaml` | HSM configuration | Administrator |

### 3.2 Main Configuration

```yaml
# /etc/ostrich-pki/config.yaml

# Service configuration
service:
  name: "OstrichPKI CA"
  environment: production
  log_level: info

# Database configuration
database:
  host: localhost
  port: 5432
  name: ostrich_pki
  ssl_mode: require
  max_connections: 50

# HSM configuration
hsm:
  provider: pkcs11
  library_path: /usr/lib/softhsm/libsofthsm2.so
  slot: 0
  # PIN stored in environment variable OSTRICH_HSM_PIN

# TLS configuration
tls:
  min_version: "1.3"
  cert_path: /etc/ostrich-pki/tls/server.crt
  key_path: /etc/ostrich-pki/tls/server.key
  client_ca_path: /etc/ostrich-pki/tls/client-ca.crt
  require_client_cert: true

# Audit configuration
audit:
  storage_path: /var/log/ostrich-pki/audit
  max_size_gb: 100
  retention_days: 365
  alert_threshold_percent: 80

# Time synchronization
time:
  ntp_servers:
    - ntp1.example.com
    - ntp2.example.com
  max_drift_seconds: 5
```

### 3.3 Modifying Configuration

**Warning:** Configuration changes require service restart and are audited.

```bash
# Validate configuration before applying
ostrich-admin config validate --file /etc/ostrich-pki/config.yaml

# Apply configuration (requires restart)
sudo systemctl restart ostrich-ca

# View current configuration
ostrich-admin config show

# View configuration history
ostrich-admin config history
```

### 3.4 Certificate Profiles

Certificate profiles define the content and constraints for issued certificates.

```yaml
# /etc/ostrich-pki/profiles/tls-server.yaml

name: TLS Server Certificate
description: Standard TLS server certificate for web servers

# Validity
validity:
  max_days: 398  # Per CA/B Forum baseline requirements
  default_days: 365

# Key constraints
key_constraints:
  algorithms:
    - rsa:2048
    - rsa:3072
    - rsa:4096
    - ecdsa:p256
    - ecdsa:p384
  min_rsa_bits: 2048
  min_ec_bits: 256

# Extensions
extensions:
  key_usage:
    critical: true
    values:
      - digitalSignature
      - keyEncipherment

  extended_key_usage:
    critical: false
    values:
      - serverAuth

  basic_constraints:
    critical: true
    ca: false

  subject_alt_name:
    required: true
    allowed_types:
      - dnsName
      - ipAddress

# Subject DN requirements
subject:
  required_fields:
    - commonName
  optional_fields:
    - organizationName
    - countryName
  max_cn_length: 64
```

### 3.5 Secure Defaults

**Warning:** The following settings must not be modified to maintain security compliance:

| Setting | Required Value | Reason |
|---------|---------------|--------|
| `tls.min_version` | "1.3" | NIAP PP-CA requirement |
| `tls.require_client_cert` | true | mTLS required for admin access |
| `key_constraints.min_rsa_bits` | 2048 | NIST minimum |
| `audit.retention_days` | >= 365 | Compliance requirement |

---

## 4. Certificate Lifecycle Operations

### 4.1 Certificate Issuance

**Role Required:** Operations Staff

#### Via ACME (Automated)

```bash
# ACME clients automatically obtain certificates
# No manual intervention required

# View pending ACME orders
ostrich-admin acme orders list --status pending

# View issued certificates
ostrich-admin acme orders list --status valid
```

#### Via EST (Enrollment over Secure Transport)

```bash
# EST enrollment requires mTLS client certificate
# Clients submit CSR via EST protocol

# View pending EST enrollments
ostrich-admin est enrollments list --status pending
```

#### Manual Issuance (CA CLI)

```bash
# Issue certificate from CSR file
ostrich-admin cert issue \
  --csr /path/to/request.csr \
  --profile tls-server \
  --validity-days 365 \
  --output /path/to/certificate.pem

# Issue certificate with SAN
ostrich-admin cert issue \
  --csr /path/to/request.csr \
  --profile tls-server \
  --san "DNS:www.example.com,DNS:example.com" \
  --output /path/to/certificate.pem
```

### 4.2 Certificate Revocation

**Role Required:** Operations Staff

```bash
# Revoke by serial number
ostrich-admin cert revoke \
  --serial <serial_number> \
  --reason keyCompromise \
  --comment "Private key compromised"

# Revoke by certificate file
ostrich-admin cert revoke \
  --cert /path/to/certificate.pem \
  --reason superseded

# Available revocation reasons:
# - unspecified
# - keyCompromise
# - cACompromise
# - affiliationChanged
# - superseded
# - cessationOfOperation
# - certificateHold
```

### 4.3 CRL Generation

**Role Required:** Operations Staff

```bash
# Generate new CRL
ostrich-admin crl generate

# View CRL information
ostrich-admin crl info

# List revoked certificates in current CRL
ostrich-admin crl list

# CRL is automatically published to distribution points
```

### 4.4 Certificate Search and Export

```bash
# Search certificates by subject
ostrich-admin cert search --subject "CN=example.com"

# Search by serial number
ostrich-admin cert search --serial <serial_number>

# Export certificate
ostrich-admin cert export --serial <serial_number> --format pem

# List all active certificates
ostrich-admin cert list --status valid
```

---

## 5. Key Management

### 5.1 CA Key Operations

**Role Required:** Administrator

**Warning:** CA key operations are security-critical and fully audited.

#### View CA Key Information

```bash
# List CA keys
ostrich-admin key list

# View key details (public key only)
ostrich-admin key info --key-id <key_id>

# Key information includes:
# - Algorithm (RSA, ECDSA, EdDSA, ML-DSA)
# - Key size
# - Creation date
# - Usage statistics
```

#### Generate New CA Key

```bash
# Generate new CA signing key (stored in HSM)
ostrich-admin key generate \
  --algorithm ecdsa-p384 \
  --label "CA-Signing-Key-2026" \
  --usage sign

# For post-quantum:
ostrich-admin key generate \
  --algorithm ml-dsa-65 \
  --label "CA-Signing-Key-PQ-2026" \
  --usage sign
```

#### Key Backup (KRA Integration)

```bash
# Initiate key backup (escrow)
# Requires M-of-N key recovery agents
ostrich-admin key backup \
  --key-id <key_id> \
  --agents agent1,agent2,agent3 \
  --threshold 2

# Key is split using Shamir Secret Sharing
# Each agent receives one share
```

#### Key Recovery

```bash
# Initiate key recovery request
ostrich-admin key recover \
  --key-id <key_id> \
  --reason "HSM failure"

# Agents submit their shares
ostrich-admin key recover-submit \
  --request-id <request_id> \
  --agent <agent_name> \
  --share <share_data>

# After threshold shares submitted, key is recovered
```

### 5.2 HSM Operations

```bash
# Check HSM status
ostrich-admin hsm status

# List objects in HSM
ostrich-admin hsm list-objects

# HSM session information
ostrich-admin hsm session-info
```

---

## 6. Audit Log Management

### 6.1 Audit Log Access

**Role Required:** Auditor or Administrator

```bash
# View recent audit events
ostrich-admin audit list --limit 100

# Filter by event type
ostrich-admin audit list --type CertificateIssued

# Filter by actor
ostrich-admin audit list --actor "admin@example.com"

# Filter by time range
ostrich-admin audit list \
  --from "2026-01-01T00:00:00Z" \
  --to "2026-01-31T23:59:59Z"

# Filter by outcome
ostrich-admin audit list --outcome failure
```

### 6.2 Audit Event Types

| Event Type | Description |
|------------|-------------|
| `ServiceStartup` | Service started |
| `ServiceShutdown` | Service stopped |
| `AuthenticationSuccess` | Successful authentication |
| `AuthenticationFailure` | Failed authentication attempt |
| `CertificateIssued` | Certificate was issued |
| `CertificateRevoked` | Certificate was revoked |
| `CrlGenerated` | CRL was generated |
| `KeyGenerated` | CA key was generated |
| `KeyBackupInitiated` | Key backup started |
| `KeyRecovered` | Key was recovered |
| `ConfigurationChanged` | Configuration modified |
| `UserCreated` | User account created |
| `UserDeleted` | User account deleted |
| `RoleAssigned` | Role assigned to user |
| `RoleRemoved` | Role removed from user |
| `SelfTestCompleted` | Self-test executed |
| `SelfTestFailed` | Self-test failed |

### 6.3 Audit Log Export

**Role Required:** Auditor

```bash
# Export audit logs to file
ostrich-admin audit export \
  --from "2026-01-01T00:00:00Z" \
  --to "2026-01-31T23:59:59Z" \
  --format json \
  --output /path/to/audit-export.json

# Export with signature for integrity verification
ostrich-admin audit export \
  --from "2026-01-01T00:00:00Z" \
  --to "2026-01-31T23:59:59Z" \
  --format json \
  --sign \
  --output /path/to/audit-export.json
```

### 6.4 Audit Log Integrity Verification

```bash
# Verify audit log hash chain integrity
ostrich-admin audit verify

# Output:
# Audit log integrity: VERIFIED
# Records checked: 15,234
# Hash chain valid: Yes
# First record: 2026-01-01T00:00:00Z
# Last record: 2026-01-04T15:30:00Z
```

### 6.5 Audit Storage Management

```bash
# Check audit storage usage
ostrich-admin audit storage

# Output:
# Storage used: 45.2 GB / 100 GB (45.2%)
# Records: 1,234,567
# Oldest record: 2025-01-15T00:00:00Z
# Alert threshold: 80%

# Archive old audit logs (preserves integrity)
ostrich-admin audit archive \
  --before "2025-12-31T23:59:59Z" \
  --destination /archive/audit/
```

---

## 7. User Management

### 7.1 User Account Operations

**Role Required:** Administrator

```bash
# Create new user
ostrich-admin user create \
  --username jsmith \
  --email jsmith@example.com \
  --full-name "John Smith"

# User receives enrollment invitation via email
# Must complete mTLS certificate enrollment

# List all users
ostrich-admin user list

# View user details
ostrich-admin user info --username jsmith

# Disable user account
ostrich-admin user disable --username jsmith

# Enable user account
ostrich-admin user enable --username jsmith

# Delete user account
ostrich-admin user delete --username jsmith
```

### 7.2 User Certificate Enrollment

```bash
# Generate enrollment invitation
ostrich-admin user enroll --username jsmith

# User receives:
# - Enrollment URL
# - One-time enrollment code
# - Instructions for certificate request

# Check enrollment status
ostrich-admin user enrollment-status --username jsmith
```

### 7.3 Account Lockout

```bash
# View locked accounts
ostrich-admin user list --locked

# Unlock account (after failed authentication lockout)
ostrich-admin user unlock --username jsmith

# Lockout settings are in configuration:
# max_failures: 5
# lockout_duration: 15m
```

---

## 8. Security Monitoring

### 8.1 Health Checks

```bash
# Check overall system health
ostrich-admin health

# Output:
# Service Status: HEALTHY
# HSM: Connected
# Database: Connected
# Time Sync: OK (drift: 0.3s)
# Audit Storage: OK (45.2%)
# Self-Tests: PASS
```

### 8.2 Self-Tests

**Role Required:** Administrator

```bash
# Run self-tests on demand
ostrich-admin self-test run

# Output:
# Cryptographic KAT (RSA): PASS
# Cryptographic KAT (ECDSA): PASS
# Cryptographic KAT (SHA-256): PASS
# DRBG Health Test: PASS
# HSM Connectivity: PASS
# Database Connectivity: PASS
# Time Source Verification: PASS
# Overall: PASS

# View self-test history
ostrich-admin self-test history
```

### 8.3 Security Alerts

```bash
# View active security alerts
ostrich-admin alerts list

# Alert types:
# - HIGH: Self-test failure, HSM disconnection
# - MEDIUM: Authentication failures, certificate expiration
# - LOW: Configuration changes, high audit storage

# Acknowledge alert
ostrich-admin alerts acknowledge --id <alert_id>
```

### 8.4 Metrics and Monitoring

```bash
# Prometheus metrics endpoint
curl https://ca.example.com:9090/metrics

# Key metrics:
# ostrich_certificates_issued_total
# ostrich_certificates_revoked_total
# ostrich_authentication_failures_total
# ostrich_hsm_operations_total
# ostrich_audit_storage_bytes
# ostrich_self_test_last_result
```

---

## 9. Backup and Recovery

### 9.1 Database Backup

**Role Required:** Administrator

```bash
# Create database backup
ostrich-admin backup create \
  --type database \
  --destination /backup/ostrich-pki/

# Backup includes:
# - Certificate database
# - Revocation information
# - User accounts and roles
# - Configuration (encrypted)
# - Audit log references

# List available backups
ostrich-admin backup list

# Verify backup integrity
ostrich-admin backup verify --backup-id <backup_id>
```

### 9.2 CA Key Backup

See [Section 5.1 - Key Backup](#key-backup-kra-integration)

**Warning:** CA private keys are backed up through the KRA service using Shamir Secret Sharing. Direct key export is not supported.

### 9.3 Disaster Recovery

```bash
# Recovery procedure:
# 1. Install OstrichPKI on new system
# 2. Restore database backup
ostrich-admin backup restore \
  --backup-id <backup_id> \
  --type database

# 3. Initialize HSM on new system
# 4. Recover CA key using KRA shares
ostrich-admin key recover --key-id <key_id>

# 5. Verify system health
ostrich-admin health

# 6. Run self-tests
ostrich-admin self-test run
```

### 9.4 Backup Schedule

| Backup Type | Frequency | Retention |
|-------------|-----------|-----------|
| Database (full) | Daily | 30 days |
| Database (incremental) | Hourly | 7 days |
| Configuration | On change | 90 days |
| Audit logs | Monthly archive | 7 years |

---

## 10. Troubleshooting

### 10.1 Common Issues

#### HSM Connection Failed

```bash
# Check HSM status
ostrich-admin hsm status

# Common causes:
# - HSM library path incorrect
# - HSM slot not initialized
# - PIN incorrect (check OSTRICH_HSM_PIN env var)
# - HSM hardware failure

# Restart HSM service
sudo systemctl restart softhsm2
```

#### Database Connection Failed

```bash
# Check database connectivity
ostrich-admin db status

# Common causes:
# - PostgreSQL not running
# - Network connectivity
# - SSL certificate issues
# - Connection pool exhausted

# Check PostgreSQL logs
sudo journalctl -u postgresql
```

#### Time Synchronization Failed

```bash
# Check time sync status
ostrich-admin time status

# Common causes:
# - NTP servers unreachable
# - Time drift exceeds threshold
# - Firewall blocking NTP

# Force time sync
sudo ntpdate -u ntp1.example.com
```

#### Self-Test Failure

```bash
# View self-test results
ostrich-admin self-test history --limit 10

# If cryptographic KAT fails:
# - HSM may be in error state
# - Restart HSM and retry
# - Contact vendor if persists

# Service will not start if self-tests fail
```

### 10.2 Log Files

| Log File | Purpose |
|----------|---------|
| `/var/log/ostrich-pki/ca.log` | CA service logs |
| `/var/log/ostrich-pki/acme.log` | ACME service logs |
| `/var/log/ostrich-pki/est.log` | EST service logs |
| `/var/log/ostrich-pki/ocsp.log` | OCSP service logs |
| `/var/log/ostrich-pki/audit/` | Audit logs |

```bash
# View recent CA logs
sudo journalctl -u ostrich-ca -f

# Search logs for errors
grep -i error /var/log/ostrich-pki/ca.log
```

### 10.3 Support

For issues not covered in this guide:

1. Check documentation at https://docs.ostrich-pki.io
2. Search issues at https://github.com/ostrich-pki/issues
3. Contact support with:
   - OstrichPKI version (`ostrich-admin version`)
   - Error messages and logs
   - Steps to reproduce

---

## Appendix A: Quick Reference

### Common Commands

```bash
# Certificate operations
ostrich-admin cert issue --csr <file> --profile <profile>
ostrich-admin cert revoke --serial <serial> --reason <reason>
ostrich-admin cert search --subject <subject>

# CRL operations
ostrich-admin crl generate
ostrich-admin crl info

# User operations
ostrich-admin user create --username <user>
ostrich-admin user add-role --user <user> --role <role>
ostrich-admin user list

# Audit operations
ostrich-admin audit list --limit 100
ostrich-admin audit export --from <date> --to <date>
ostrich-admin audit verify

# System operations
ostrich-admin health
ostrich-admin self-test run
ostrich-admin backup create
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OSTRICH_HSM_PIN` | HSM user PIN |
| `OSTRICH_DB_PASSWORD` | Database password |
| `OSTRICH_CONFIG_PATH` | Configuration file path |
| `OSTRICH_LOG_LEVEL` | Logging level (debug, info, warn, error) |

---

**Document History:**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | January 2026 | OstrichPKI Team | Initial release |
