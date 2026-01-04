# OstrichPKI Operations Runbook

This runbook provides standard operating procedures for managing OstrichPKI in production.

## Table of Contents

1. [Daily Operations](#daily-operations)
2. [Certificate Management](#certificate-management)
3. [CRL Management](#crl-management)
4. [Key Management](#key-management)
5. [Incident Response](#incident-response)
6. [Maintenance Procedures](#maintenance-procedures)

---

## Daily Operations

### Morning Health Check

```bash
#!/bin/bash
# daily_health_check.sh

echo "=== OstrichPKI Daily Health Check ==="
echo "Date: $(date)"
echo ""

# Check service status
echo "--- Service Status ---"
for svc in ostrich-ca ostrich-acme ostrich-est ostrich-ocsp; do
    status=$(systemctl is-active $svc)
    echo "$svc: $status"
done

# Check database connectivity
echo ""
echo "--- Database Status ---"
psql -U ostrich -d ostrich_pki -c "SELECT 1;" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Database: OK"

    # Check certificate counts
    echo "Active certificates: $(psql -U ostrich -d ostrich_pki -tAc "SELECT COUNT(*) FROM certificates WHERE status = 'valid'")"
    echo "Revoked certificates: $(psql -U ostrich -d ostrich_pki -tAc "SELECT COUNT(*) FROM certificates WHERE status = 'revoked'")"
else
    echo "Database: FAILED"
fi

# Check HSM status
echo ""
echo "--- HSM Status ---"
pkcs11-tool --module $HSM_MODULE_PATH --show-info > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "HSM: OK"
else
    echo "HSM: FAILED"
fi

# Check disk space
echo ""
echo "--- Disk Usage ---"
df -h /var/lib/ostrich-pki /var/log/ostrich-pki

# Check recent errors
echo ""
echo "--- Recent Errors (last hour) ---"
journalctl -u 'ostrich-*' --since "1 hour ago" -p err --no-pager | tail -10
```

### COMPLIANCE MAPPING

- NIST 800-53: CA-7 (Continuous Monitoring)
- NIST 800-53: AU-6 (Audit Review)

---

## Certificate Management

### Issue a Certificate (Manual)

For emergency certificate issuance outside of ACME/EST:

```bash
# 1. Generate CSR (if not provided)
openssl req -new -newkey rsa:2048 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=server.example.com/O=Example Inc"

# 2. Issue certificate via CLI
ostrich-cli cert issue \
  --csr server.csr \
  --profile server \
  --validity-days 365 \
  --output server.crt

# 3. Verify certificate
openssl x509 -in server.crt -text -noout
```

### Revoke a Certificate

```bash
# Revoke by serial number
ostrich-cli cert revoke \
  --serial 0x1234567890ABCDEF \
  --reason keyCompromise \
  --comment "Key compromise reported via ticket #12345"

# Revoke by certificate file
ostrich-cli cert revoke \
  --cert compromised.crt \
  --reason keyCompromise

# Verify revocation
ostrich-cli cert status --serial 0x1234567890ABCDEF
```

### Revocation Reasons (RFC 5280)

| Code | Reason | When to Use |
|------|--------|-------------|
| 0 | unspecified | No specific reason |
| 1 | keyCompromise | Private key disclosed |
| 2 | cACompromise | CA key compromised |
| 3 | affiliationChanged | Subject info changed |
| 4 | superseded | Replaced by new cert |
| 5 | cessationOfOperation | No longer needed |
| 6 | certificateHold | Temporary suspension |
| 9 | privilegeWithdrawn | Authorization revoked |

### COMPLIANCE MAPPING

- NIST 800-53: SC-17 (PKI Certificates)
- RFC 5280 §5.3.1 (CRL Reason Codes)

### List Certificates

```bash
# List all active certificates
ostrich-cli cert list --status valid

# List expiring soon (next 30 days)
ostrich-cli cert list --expiring-within 30d

# Search by subject
ostrich-cli cert list --subject "example.com"

# Export certificate details
ostrich-cli cert show --serial 0x1234567890ABCDEF --format json
```

---

## CRL Management

### Generate CRL Manually

```bash
# Force CRL regeneration
ostrich-cli crl generate --force

# Verify CRL
openssl crl -in /var/lib/ostrich-pki/crl/root.crl -text -noout

# Check CRL validity
ostrich-cli crl status
```

### CRL Distribution

```bash
# Copy CRL to distribution point
scp /var/lib/ostrich-pki/crl/root.crl cdn-server:/var/www/crl/

# Verify distribution
curl -s http://crl.example.com/root.crl | openssl crl -inform DER -text -noout
```

### CRL Schedule

| CA Level | Update Frequency | Validity Period |
|----------|------------------|-----------------|
| Root CA | Weekly | 30 days |
| Issuing CA | Daily | 7 days |
| Emergency | Immediate | 24 hours |

### COMPLIANCE MAPPING

- NIST 800-53: SC-17 (PKI Certificates)
- RFC 5280 §5 (CRL Profile)

---

## Key Management

### CA Key Rotation

**WARNING: CA key rotation is a critical operation. Follow change management procedures.**

```bash
# 1. Generate new CA key in HSM
ostrich-cli hsm generate-key \
  --label "CA-2025" \
  --algorithm RSA-4096 \
  --slot 0

# 2. Generate new CA certificate
ostrich-cli ca rotate \
  --new-key-label "CA-2025" \
  --validity-years 10 \
  --cross-sign  # Sign with old key for chain continuity

# 3. Distribute new CA certificate
cp /var/lib/ostrich-pki/ca/new-ca.crt /var/www/pki/

# 4. Update configuration
# Edit /etc/ostrich-pki/config.toml with new key label

# 5. Restart services
sudo systemctl restart ostrich-ca
```

### HSM Key Backup

See [HSM_KEY_BACKUP.md](./HSM_KEY_BACKUP.md) for detailed procedures.

```bash
# Export wrapped keys (requires security officer presence)
ostrich-cli hsm backup \
  --output /secure/backup/keys_$(date +%Y%m%d).bin \
  --wrap-key-id 0x0001
```

### COMPLIANCE MAPPING

- NIST 800-53: SC-12 (Cryptographic Key Management)
- NIAP PP-CA: FCS_CKM.4 (Cryptographic Key Destruction)

---

## Incident Response

### Certificate Compromise Response

**Severity: CRITICAL**

1. **Immediate Actions (< 15 minutes)**

   ```bash
   # Revoke compromised certificate immediately
   ostrich-cli cert revoke \
     --serial $SERIAL \
     --reason keyCompromise \
     --comment "INCIDENT-$TICKET_ID"

   # Force CRL regeneration
   ostrich-cli crl generate --force

   # Notify OCSP responders
   ostrich-cli ocsp refresh
   ```

2. **Investigation (< 1 hour)**
   - Identify scope of compromise
   - Review audit logs for unauthorized access
   - Identify all certificates signed with compromised key

3. **Remediation (< 24 hours)**
   - Revoke all affected certificates
   - Issue replacement certificates
   - Update CRL distribution points
   - Notify affected parties

4. **Post-Incident**
   - Document incident timeline
   - Update procedures as needed
   - Conduct root cause analysis

### CA Key Compromise Response

**Severity: CRITICAL - EMERGENCY**

This is the most severe incident. Follow the CA Key Compromise Procedure:

1. **Immediate Actions**
   - Shut down all CA services
   - Revoke CA certificate (requires offline root)
   - Notify all relying parties
   - Engage incident response team

2. **See**: [INCIDENT_RESPONSE.md](./INCIDENT_RESPONSE.md) for full procedure

### COMPLIANCE MAPPING

- NIST 800-53: IR-4 (Incident Handling)
- NIST 800-53: IR-6 (Incident Reporting)

---

## Maintenance Procedures

### Database Maintenance

```bash
# Weekly: Vacuum and analyze
psql -U ostrich -d ostrich_pki -c "VACUUM ANALYZE;"

# Monthly: Check table sizes
psql -U ostrich -d ostrich_pki -c "
SELECT relname, pg_size_pretty(pg_total_relation_size(relid))
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC;"

# Archive old audit logs (> 1 year)
ostrich-cli audit archive --older-than 365d --output /archive/
```

### Log Rotation

Configured in `/etc/logrotate.d/ostrich-pki`:

```
/var/log/ostrich-pki/*.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0640 ostrich ostrich
    postrotate
        systemctl reload ostrich-ca ostrich-acme ostrich-est ostrich-ocsp 2>/dev/null || true
    endscript
}
```

### Service Updates

```bash
# 1. Download new release
wget https://releases.ostrich-pki.io/v0.14.0/ostrich-pki-linux-amd64.tar.gz

# 2. Verify signature
gpg --verify ostrich-pki-linux-amd64.tar.gz.sig

# 3. Stop services (schedule maintenance window)
sudo systemctl stop ostrich-acme ostrich-est ostrich-ocsp
sudo systemctl stop ostrich-ca

# 4. Backup current binaries
sudo cp /usr/local/bin/ostrich-* /backup/bin/

# 5. Install new binaries
sudo tar -xzf ostrich-pki-linux-amd64.tar.gz -C /usr/local/bin/

# 6. Run database migrations
ostrich-init database --migrate

# 7. Start services
sudo systemctl start ostrich-ca
sudo systemctl start ostrich-acme ostrich-est ostrich-ocsp

# 8. Verify health
./daily_health_check.sh
```

### COMPLIANCE MAPPING

- NIST 800-53: CM-3 (Configuration Change Control)
- NIST 800-53: SI-7 (Software, Firmware, and Information Integrity)

---

## Monitoring Alerts Response

### Alert: Certificate Expiry Warning

**Trigger**: Certificate expires in < 30 days

```bash
# List expiring certificates
ostrich-cli cert list --expiring-within 30d

# Notify certificate owners
ostrich-cli notify expiry --within 30d

# For internal certificates, auto-renew if configured
ostrich-cli cert renew --auto
```

### Alert: CRL Generation Failed

**Trigger**: CRL not updated within expected window

```bash
# Check CA service status
systemctl status ostrich-ca
journalctl -u ostrich-ca --since "1 hour ago"

# Check HSM connectivity
pkcs11-tool --module $HSM_MODULE_PATH --show-info

# Manual CRL generation
ostrich-cli crl generate --force --debug
```

### Alert: OCSP Responder Unavailable

**Trigger**: OCSP endpoint returns errors

```bash
# Check OCSP service
systemctl status ostrich-ocsp

# Test OCSP response
openssl ocsp -issuer ca.crt -cert server.crt \
  -url http://localhost:8081 -resp_text

# Restart if needed
sudo systemctl restart ostrich-ocsp
```

### Alert: Database Connection Pool Exhausted

**Trigger**: Connection pool utilization > 90%

```bash
# Check current connections
psql -U ostrich -d ostrich_pki -c "
SELECT count(*), state FROM pg_stat_activity
WHERE datname='ostrich_pki' GROUP BY state;"

# Identify long-running queries
psql -U ostrich -d ostrich_pki -c "
SELECT pid, now() - pg_stat_activity.query_start AS duration, query
FROM pg_stat_activity
WHERE state != 'idle' AND now() - pg_stat_activity.query_start > interval '5 minutes';"

# Increase pool size if needed (requires config change and restart)
```

---

## Emergency Contacts

| Role | Contact | Escalation Time |
|------|---------|-----------------|
| On-Call Engineer | pki-oncall@example.com | Immediate |
| Security Team | security@example.com | 15 minutes |
| CA Administrator | ca-admin@example.com | 30 minutes |
| HSM Security Officer | hsm-so@example.com | For key operations |

---

## Appendix: Common Commands Reference

```bash
# Service management
sudo systemctl {start|stop|restart|status} ostrich-{ca|acme|est|ocsp}

# Certificate operations
ostrich-cli cert {list|show|issue|revoke|renew}

# CRL operations
ostrich-cli crl {generate|status|verify}

# HSM operations
ostrich-cli hsm {status|generate-key|backup|list-keys}

# Audit operations
ostrich-cli audit {search|export|archive}

# Configuration validation
ostrich-cli config validate --config /etc/ostrich-pki/config.toml
```
