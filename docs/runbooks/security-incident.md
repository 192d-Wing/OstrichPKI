# Runbook: Security Incident Response

## Overview

This runbook covers security incident response procedures for OstrichPKI infrastructure.

**NIST 800-53 Controls:** IR-4, IR-5, IR-6, IR-8, AU-6

## Incident Classification

### Severity Levels

| Level | Description | Response Time | Examples |
|-------|-------------|---------------|----------|
| **P1 - Critical** | CA key compromise, active breach | Immediate | Key exposure, unauthorized cert issuance |
| **P2 - High** | Potential compromise, service impact | < 1 hour | Unusual issuance patterns, auth failures |
| **P3 - Medium** | Security policy violation | < 4 hours | Configuration drift, expired certs |
| **P4 - Low** | Minor security issue | < 24 hours | Failed login attempts, audit log gaps |

## Incident Response Procedures

### Phase 1: Detection and Initial Response

#### Immediate Actions (First 15 minutes)

1. **Acknowledge the alert**
```bash
# Document initial observations
echo "$(date): Incident detected - $(description)" >> /tmp/incident-log.txt
```

2. **Assess scope and severity**
```bash
# Check for active threats
kubectl logs -n ostrich-pki -l app.kubernetes.io/name=ostrich-pki --since=1h | \
  grep -i "error\|unauthorized\|denied\|failed"

# Check recent certificate issuance
curl "http://localhost:8080/api/v1/certificates?issued_after=$(date -d '1 hour ago' -Iseconds)"
```

3. **Notify incident response team**
   - Security: security@example.com
   - On-call: +1-555-0100
   - Management: pkiadmin@example.com

### Phase 2: Containment

#### CA Key Compromise

**CRITICAL: This is the most severe incident type**

1. **Immediately revoke compromised CA certificate:**
```bash
# Stop all CA operations
kubectl scale deployment ostrich-pki-ca -n ostrich-pki --replicas=0

# Mark CA as compromised in database
kubectl exec -n ostrich-pki ostrich-pki-postgresql-0 -- \
  psql -U ostrich ostrich_pki -c \
  "UPDATE ca_certificates SET status='COMPROMISED', compromise_date=NOW() WHERE id='<ca-id>';"
```

2. **Generate emergency CRL:**
```bash
# Start CA in emergency mode (CRL generation only)
kubectl set env deployment/ostrich-pki-ca EMERGENCY_MODE=true -n ostrich-pki
kubectl scale deployment ostrich-pki-ca -n ostrich-pki --replicas=1

# Generate CRL with CA compromise
curl -X POST http://localhost:8080/api/v1/crl/emergency-generate
```

3. **Notify relying parties:**
   - Publish CA compromise notice
   - Update trust stores (remove compromised CA)
   - Activate backup/disaster recovery CA if available

#### Unauthorized Certificate Issuance

1. **Identify unauthorized certificates:**
```bash
# Review recent issuance
curl "http://localhost:8080/api/v1/certificates?status=valid" | \
  jq '.certificates[] | select(.issued_at > "2024-01-15T00:00:00Z")'
```

2. **Revoke suspicious certificates:**
```bash
# Revoke with key_compromise reason
curl -X POST http://localhost:8080/api/v1/certificates/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "serial_numbers": ["serial1", "serial2", "serial3"],
    "reason": "key_compromise",
    "comment": "Unauthorized issuance - incident #INC-12345"
  }'
```

3. **Block the attack vector:**
```bash
# Rotate compromised credentials
kubectl delete secret ostrich-pki-admin-creds -n ostrich-pki
kubectl create secret generic ostrich-pki-admin-creds \
  --from-literal=password=$(openssl rand -base64 32) -n ostrich-pki

# Restart services to pick up new credentials
kubectl rollout restart deployment -n ostrich-pki
```

#### Authentication Bypass

1. **Disable affected authentication method:**
```bash
kubectl set env deployment/ostrich-pki-ca \
  MTLS_REQUIRED=true \
  BASIC_AUTH_ENABLED=false \
  -n ostrich-pki
```

2. **Review all recent authentications:**
```bash
# Query audit logs
curl "http://localhost:8080/api/v1/audit?event_type=authentication&since=24h" | \
  jq '.events[] | select(.outcome == "success")'
```

3. **Revoke all sessions:**
```bash
kubectl exec -n ostrich-pki ostrich-pki-postgresql-0 -- \
  psql -U ostrich ostrich_pki -c "TRUNCATE sessions;"
```

### Phase 3: Eradication

1. **Remove malicious artifacts:**
```bash
# Check for unauthorized changes
kubectl diff -f deploy/kubernetes/

# Restore known-good configuration
kubectl apply -f deploy/kubernetes/
```

2. **Patch vulnerabilities:**
```bash
# Update to patched version
helm upgrade ostrich-pki deploy/helm/ostrich-pki \
  --set image.tag=v0.13.1-security-patch \
  -n ostrich-pki
```

3. **Harden configuration:**
```bash
# Apply security hardening
kubectl apply -f deploy/kubernetes/networkpolicy-strict.yaml
kubectl apply -f deploy/kubernetes/podsecuritypolicy.yaml
```

### Phase 4: Recovery

1. **Restore normal operations:**
```bash
# Scale services back to normal
kubectl scale deployment ostrich-pki-ca -n ostrich-pki --replicas=1
kubectl scale deployment ostrich-pki-acme -n ostrich-pki --replicas=2
```

2. **Verify system integrity:**
```bash
# Run integrity checks
kubectl exec -n ostrich-pki ostrich-pki-ca-xxxx -- \
  ostrich-cli verify-integrity

# Verify certificate chains
curl http://localhost:8080/api/v1/ca/verify-chain
```

3. **Resume monitoring:**
```bash
# Check all alerts cleared
kubectl get prometheusrule -n ostrich-pki -o yaml | grep "alertname"
```

### Phase 5: Post-Incident

1. **Document the incident:**
   - Timeline of events
   - Actions taken
   - Root cause analysis
   - Lessons learned

2. **Preserve evidence:**
```bash
# Export audit logs
curl "http://localhost:8080/api/v1/audit/export?incident=INC-12345" > incident-audit.json

# Save pod logs
kubectl logs -n ostrich-pki -l app.kubernetes.io/name=ostrich-pki --since=24h > incident-logs.txt
```

3. **Update procedures:**
   - Revise runbooks based on lessons learned
   - Update detection rules
   - Improve preventive controls

## Incident Communication

### Internal Notification Template

```
Subject: [SECURITY INCIDENT] OstrichPKI - Severity P{1-4}

Time Detected: YYYY-MM-DD HH:MM UTC
Incident ID: INC-XXXXX
Severity: P{1-4}

Summary:
[Brief description of the incident]

Impact:
[Services affected, scope of impact]

Current Status:
[Contained / Investigating / Resolved]

Actions Taken:
1. [Action 1]
2. [Action 2]

Next Steps:
1. [Next step 1]
2. [Next step 2]

Contact:
[Incident commander contact info]
```

### External Notification (if required)

For CA compromise or large-scale certificate revocation:

1. Notify certificate subscribers
2. Update public-facing status page
3. Coordinate with browser vendors if applicable
4. File regulatory notifications as required

## Emergency Contacts

| Role | Name | Phone | Email |
|------|------|-------|-------|
| Incident Commander | [Name] | +1-555-0100 | ic@example.com |
| Security Lead | [Name] | +1-555-0101 | security@example.com |
| PKI Admin | [Name] | +1-555-0102 | pkiadmin@example.com |
| Legal/Compliance | [Name] | +1-555-0103 | legal@example.com |
| Executive Sponsor | [Name] | +1-555-0104 | exec@example.com |

## Evidence Preservation Checklist

- [ ] System logs exported
- [ ] Database state captured
- [ ] Network traffic captured (if applicable)
- [ ] Memory dumps (if applicable)
- [ ] Configuration snapshots
- [ ] Access logs
- [ ] Audit trail exported
- [ ] Timeline documented
- [ ] Screenshots of dashboards
- [ ] Affected certificate list
