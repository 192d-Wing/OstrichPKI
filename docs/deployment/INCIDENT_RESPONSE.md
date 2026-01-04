# OstrichPKI Incident Response Procedures

This document defines incident response procedures for security events affecting OstrichPKI.

## Incident Classification

### Severity Levels

| Level | Description | Response Time | Examples |
|-------|-------------|---------------|----------|
| SEV-1 | Critical - CA compromise | Immediate | CA key compromise, unauthorized cert issuance |
| SEV-2 | High - Service compromise | < 1 hour | Database breach, HSM failure |
| SEV-3 | Medium - Certificate issue | < 4 hours | Single cert compromise, revocation needed |
| SEV-4 | Low - Operational issue | < 24 hours | Service degradation, monitoring alert |

---

## SEV-1: CA Key Compromise

**This is the most severe incident type. Immediate action required.**

### COMPLIANCE MAPPING
- NIST 800-53: IR-4 (Incident Handling)
- NIST 800-53: IR-5 (Incident Monitoring)
- NIST 800-53: IR-6 (Incident Reporting)
- NIAP PP-CA: FMT_MTD.1 (Management of TSF Data)

### Detection Indicators

- Unauthorized certificate issuance detected
- HSM audit log anomalies
- Unexpected CA key usage patterns
- External report of forged certificates
- Physical security breach at HSM location

### Immediate Response (< 15 minutes)

```bash
#!/bin/bash
# EMERGENCY: CA Key Compromise Response
# Run with root privileges

echo "=== CA KEY COMPROMISE RESPONSE ==="
echo "Time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Operator: $USER"

# 1. STOP ALL CA SERVICES IMMEDIATELY
echo "[CRITICAL] Stopping all CA services..."
systemctl stop ostrich-ca ostrich-acme ostrich-est ostrich-ocsp

# 2. Preserve evidence - DO NOT MODIFY
echo "[FORENSICS] Preserving evidence..."
mkdir -p /evidence/$(date +%Y%m%d_%H%M%S)
cp -a /var/log/ostrich-pki/* /evidence/$(date +%Y%m%d_%H%M%S)/
cp -a /var/lib/ostrich-pki/* /evidence/$(date +%Y%m%d_%H%M%S)/

# 3. Block network access to HSM
echo "[NETWORK] Isolating HSM..."
iptables -A OUTPUT -d $HSM_IP -j DROP

# 4. Notify security team
echo "[NOTIFY] Sending emergency notification..."
# Implement your notification mechanism

echo "=== SERVICES STOPPED - AWAIT SECURITY TEAM ==="
```

### Escalation Chain

1. **Immediate**: CA Administrator + Security Team
2. **15 minutes**: CISO / Security Director
3. **1 hour**: Executive leadership
4. **2 hours**: Legal / Compliance / External parties

### Investigation Phase (Security Team Lead)

1. **Secure the HSM**
   - Physical access control
   - Disable remote management
   - Preserve HSM audit logs

2. **Forensic Analysis**
   ```bash
   # Export all audit logs
   ostrich-cli audit export --all --output /forensics/audit.json

   # Identify unauthorized certificates
   ostrich-cli cert list --issued-after "compromise_time" --format json > /forensics/certs.json

   # Check database for anomalies
   pg_dump ostrich_pki > /forensics/database.sql
   ```

3. **Scope Determination**
   - What keys were compromised?
   - What certificates were issued?
   - What systems are affected?

### Revocation Phase

1. **Revoke Compromised CA**
   ```bash
   # This requires offline root CA access
   # Must be performed with Security Officer present

   # Generate emergency CRL
   ostrich-cli crl generate \
     --revoke-ca \
     --reason cACompromise \
     --output /emergency/emergency.crl

   # Sign with offline root (air-gapped system)
   ```

2. **Distribute Revocation**
   - Push emergency CRL to all distribution points
   - Contact browser vendors for inclusion in their blocklists
   - Contact major relying parties directly

3. **Notify Certificate Holders**
   ```bash
   # Generate list of affected certificates
   ostrich-cli cert list --issuer $COMPROMISED_CA --format csv > affected.csv

   # Send notifications
   ostrich-cli notify emergency --list affected.csv
   ```

### Recovery Phase

1. **Generate New CA Key**
   - Perform key ceremony with multiple Security Officers
   - Document in key ceremony log
   - Store in new HSM slot

2. **Issue New CA Certificate**
   - Cross-sign with root (if root not compromised)
   - Distribute new CA certificate

3. **Re-issue Certificates**
   - Contact all certificate holders
   - Re-validate identities
   - Issue new certificates

### Post-Incident

1. **Incident Report**
   - Timeline of events
   - Root cause analysis
   - Actions taken
   - Lessons learned

2. **Process Improvements**
   - Update procedures
   - Enhance monitoring
   - Additional controls

---

## SEV-2: Certificate Database Compromise

### Detection Indicators

- Unauthorized database access
- SQL injection detected
- Data exfiltration alerts
- Database integrity check failure

### Response Procedure

```bash
# 1. Isolate database
systemctl stop postgresql

# 2. Preserve evidence
pg_dump ostrich_pki > /evidence/db_$(date +%Y%m%d).sql

# 3. Analyze access logs
grep -E "(ostrich_pki|suspicious_ip)" /var/log/postgresql/*.log

# 4. Check for unauthorized certificates
# Compare recent issuances against legitimate requests

# 5. Reset credentials
# Rotate all database passwords and API keys
```

### COMPLIANCE MAPPING
- NIST 800-53: IR-4 (Incident Handling)
- NIST 800-53: AU-9 (Protection of Audit Information)

---

## SEV-3: Single Certificate Compromise

### Detection Indicators

- Certificate holder reports key compromise
- Unauthorized usage detected
- Certificate found in the wild

### Response Procedure

```bash
# 1. Verify the report
ostrich-cli cert show --serial $SERIAL

# 2. Revoke immediately
ostrich-cli cert revoke \
  --serial $SERIAL \
  --reason keyCompromise \
  --comment "Incident ticket: $TICKET_ID"

# 3. Regenerate CRL
ostrich-cli crl generate

# 4. Notify OCSP
ostrich-cli ocsp refresh

# 5. Issue replacement (if requested)
ostrich-cli cert issue \
  --csr replacement.csr \
  --profile $(original_profile) \
  --validity-days $(original_validity)
```

### COMPLIANCE MAPPING
- NIST 800-53: SC-17 (PKI Certificates)
- RFC 5280 §5.3.1 (Reason Codes)

---

## SEV-4: Service Degradation

### Detection Indicators

- Monitoring alerts
- Increased error rates
- Performance degradation

### Response Procedure

1. **Identify Affected Service**
   ```bash
   # Check all services
   for svc in ostrich-ca ostrich-acme ostrich-est ostrich-ocsp; do
       echo "=== $svc ==="
       systemctl status $svc
       journalctl -u $svc --since "10 minutes ago" | tail -20
   done
   ```

2. **Common Fixes**
   ```bash
   # Restart service
   sudo systemctl restart ostrich-$SERVICE

   # Clear connection pool
   psql -U ostrich -d ostrich_pki -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='ostrich_pki' AND state='idle' AND query_start < now() - interval '1 hour';"

   # Check disk space
   df -h /var/lib/ostrich-pki
   ```

3. **Escalate if Unresolved**
   - Engage development team
   - Check for known issues
   - Consider rollback

---

## Communication Templates

### Internal Notification (SEV-1)

```
SUBJECT: [CRITICAL] PKI Security Incident - Immediate Action Required

Priority: CRITICAL
Time: [UTC timestamp]
Incident ID: [ID]

SUMMARY:
A potential compromise of the Certificate Authority has been detected.
All CA services have been stopped pending investigation.

IMMEDIATE ACTIONS REQUIRED:
1. Do not attempt to restart CA services
2. Preserve all evidence
3. Join emergency bridge: [call details]

AFFECTED SYSTEMS:
- Certificate Authority
- ACME service
- EST service
- OCSP service

NEXT UPDATE: [time]

This is a confidential security incident. Do not discuss externally.
```

### External Notification (Certificate Holders)

```
SUBJECT: Important Security Notice - Certificate Revocation Required

Dear Certificate Holder,

We are writing to inform you that due to a security incident,
your certificate with serial number [SERIAL] has been revoked.

ACTION REQUIRED:
1. Stop using the affected certificate immediately
2. Generate a new key pair
3. Submit a new certificate request
4. Install the replacement certificate

We apologize for any inconvenience. If you have questions,
please contact: security@example.com

Certificate Details:
- Serial: [SERIAL]
- Subject: [SUBJECT]
- Revocation Time: [TIME UTC]
- Revocation Reason: Key Compromise

Sincerely,
OstrichPKI Security Team
```

---

## Evidence Preservation

### What to Preserve

- All log files (`/var/log/ostrich-pki/`)
- Database dumps
- HSM audit logs
- Network traffic captures
- Configuration files
- Binary hashes

### Chain of Custody

```
Evidence Log
============
Item: [description]
Location: [path]
Collected by: [name]
Collection time: [UTC timestamp]
Hash (SHA-256): [hash]
Storage location: [secure location]
```

### COMPLIANCE MAPPING
- NIST 800-53: AU-9 (Protection of Audit Information)
- NIST 800-53: IR-4 (Incident Handling)

---

## Post-Incident Review

### Review Meeting Agenda

1. Incident timeline review
2. Detection effectiveness
3. Response effectiveness
4. What went well
5. What could be improved
6. Action items

### Documentation Requirements

- Incident report (within 72 hours)
- Root cause analysis (within 2 weeks)
- Remediation plan (within 2 weeks)
- Lessons learned document
- Updated runbooks (if applicable)

---

## Contacts and Escalation

### Internal Contacts

| Role | Name | Phone | Email |
|------|------|-------|-------|
| CA Administrator | | | ca-admin@example.com |
| Security Team | | | security@example.com |
| On-Call Engineer | | | pki-oncall@example.com |
| CISO | | | ciso@example.com |

### External Contacts

| Organization | Purpose | Contact |
|--------------|---------|---------|
| HSM Vendor | HSM support | |
| Browser Vendors | Revocation | |
| CA/Browser Forum | Incident disclosure | |
| Legal Counsel | Legal guidance | |

---

## Appendix: Quick Reference

### Revocation Reasons

| Code | Reason | Use Case |
|------|--------|----------|
| 1 | keyCompromise | Private key exposed |
| 2 | cACompromise | CA key exposed |
| 3 | affiliationChanged | Organization changed |
| 4 | superseded | Replaced |
| 5 | cessationOfOperation | No longer needed |

### Critical Commands

```bash
# Emergency stop
sudo systemctl stop ostrich-ca ostrich-acme ostrich-est ostrich-ocsp

# Evidence preservation
tar -czf /evidence/ostrich_$(date +%Y%m%d_%H%M%S).tar.gz /var/log/ostrich-pki /var/lib/ostrich-pki

# Emergency CRL
ostrich-cli crl generate --force

# Revoke certificate
ostrich-cli cert revoke --serial $SERIAL --reason keyCompromise
```
