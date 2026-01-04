# Runbook: Certificate Operations

## Overview

This runbook covers operational procedures for certificate management in OstrichPKI.

**NIST 800-53 Controls:** SC-17, SC-12, CM-3

## Certificate Issuance

### Manual Certificate Issuance (Admin)

```bash
# Connect to CA service
kubectl port-forward svc/ostrich-pki-ca-rest 8080:8080 -n ostrich-pki

# Issue certificate via REST API
curl -X POST http://localhost:8080/api/v1/certificates \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {
      "common_name": "example.com",
      "organization": "Example Inc"
    },
    "validity_days": 365,
    "key_type": "ecdsa-p256",
    "san": ["www.example.com", "api.example.com"]
  }'
```

### ACME Certificate Issuance

For automated issuance via ACME:

```bash
# Using certbot
certbot certonly \
  --server https://acme.example.com/directory \
  --standalone \
  -d example.com
```

## Certificate Revocation

### Emergency Revocation

**Use Case:** Compromised private key, security incident

```bash
# Revoke by serial number
curl -X POST http://localhost:8080/api/v1/certificates/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "serial_number": "01:23:45:67:89:AB:CD:EF",
    "reason": "key_compromise",
    "revocation_date": "2024-01-15T12:00:00Z"
  }'

# Force CRL regeneration
curl -X POST http://localhost:8080/api/v1/crl/generate
```

### Batch Revocation

For revoking multiple certificates (e.g., employee termination):

```bash
# Revoke all certificates for a subject
curl -X POST http://localhost:8080/api/v1/certificates/revoke-by-subject \
  -H "Content-Type: application/json" \
  -d '{
    "subject_dn": "CN=John Doe,O=Example Inc",
    "reason": "cessation_of_operation"
  }'
```

### Revocation Reasons (RFC 5280)

| Code | Reason | Use Case |
|------|--------|----------|
| 0 | unspecified | No specific reason |
| 1 | keyCompromise | Private key exposed |
| 2 | cACompromise | CA key compromised |
| 3 | affiliationChanged | Subject's org changed |
| 4 | superseded | Replaced by new cert |
| 5 | cessationOfOperation | Subject no longer valid |
| 6 | certificateHold | Temporary suspension |

## CRL Management

### Manual CRL Generation

```bash
# Generate new CRL
curl -X POST http://localhost:8080/api/v1/crl/generate

# Download CRL
curl -o crl.der http://localhost:8080/crl/ostrich-ca.crl
```

### Verify CRL

```bash
# View CRL contents
openssl crl -in crl.der -inform DER -text -noout

# Check specific certificate against CRL
openssl verify -crl_check -CAfile ca-chain.pem -CRLfile crl.pem cert.pem
```

## OCSP Operations

### Check OCSP Status

```bash
# Query OCSP responder
openssl ocsp \
  -issuer issuer.pem \
  -cert cert.pem \
  -url http://localhost:8081 \
  -text
```

### OCSP Responder Health

```bash
# Check OCSP health
curl http://localhost:8081/health

# View OCSP metrics
curl http://localhost:8081/metrics
```

## Key Rotation

### CA Key Rotation

**Warning:** This is a critical operation requiring careful planning.

1. **Pre-Rotation Checklist:**
   - [ ] All current certificates inventoried
   - [ ] New key pair generated in HSM
   - [ ] Cross-signing plan prepared
   - [ ] Rollback plan documented
   - [ ] Stakeholders notified

2. **Rotation Steps:**

```bash
# Generate new CA key pair (in HSM)
# This is typically done via HSM management tools

# Create new CA certificate
curl -X POST http://localhost:8080/api/v1/ca/rotate \
  -H "Content-Type: application/json" \
  -d '{
    "new_key_label": "ca-key-2024",
    "cross_sign": true,
    "transition_period_days": 180
  }'

# Update configuration
kubectl set env deployment/ostrich-pki-ca \
  CA_KEY_LABEL=ca-key-2024 \
  -n ostrich-pki
```

1. **Post-Rotation:**
   - [ ] Verify new CA certificate published
   - [ ] Cross-signed certificate distributed
   - [ ] OCSP responder updated
   - [ ] Monitoring updated for new certificate

### OCSP Signing Key Rotation

```bash
# Generate new OCSP signing certificate
curl -X POST http://localhost:8080/api/v1/ocsp/rotate-signing-key

# Update OCSP responder
kubectl rollout restart deployment/ostrich-pki-ocsp -n ostrich-pki
```

## Certificate Inventory

### List All Certificates

```bash
# Get certificate inventory
curl "http://localhost:8080/api/v1/certificates?limit=100&offset=0"

# Filter by status
curl "http://localhost:8080/api/v1/certificates?status=valid"

# Filter by expiration
curl "http://localhost:8080/api/v1/certificates?expires_before=2024-06-01"
```

### Export Certificate Report

```bash
# Export to CSV
curl -H "Accept: text/csv" \
  "http://localhost:8080/api/v1/certificates/report" > cert-inventory.csv
```

## Expiration Management

### Check Expiring Certificates

```bash
# Find certificates expiring in next 30 days
curl "http://localhost:8080/api/v1/certificates?expires_within=30d"
```

### Renewal Notifications

The system automatically sends expiration notifications at:

- 60 days before expiry (informational)
- 30 days before expiry (warning)
- 7 days before expiry (critical)

### Manual Renewal

```bash
# Renew certificate
curl -X POST http://localhost:8080/api/v1/certificates/{serial}/renew
```

## Audit Trail

### View Certificate Operations

```bash
# View audit log for certificate
curl "http://localhost:8080/api/v1/audit?resource_type=certificate&resource_id={serial}"
```

### Export Audit Report

```bash
# Export audit events for compliance
curl "http://localhost:8080/api/v1/audit/export?start=2024-01-01&end=2024-12-31" \
  > audit-report.json
```
