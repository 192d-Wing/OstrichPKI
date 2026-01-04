# Runbook: Database Recovery

## Overview

This runbook covers database backup, recovery, and disaster recovery procedures for OstrichPKI.

**NIST 800-53 Controls:** CP-9, CP-10, SC-28

## Backup Procedures

### Automated Backups

OstrichPKI uses PostgreSQL with automated backups. Verify backup configuration:

```bash
# Check backup CronJob
kubectl get cronjob -n ostrich-pki

# View last backup job
kubectl get jobs -n ostrich-pki -l app=ostrich-pki-backup
```

### Manual Backup

#### Full Database Backup

```bash
# Create backup from PostgreSQL pod
kubectl exec -n ostrich-pki ostrich-pki-postgresql-0 -- \
  pg_dump -U ostrich ostrich_pki | gzip > backup-$(date +%Y%m%d-%H%M%S).sql.gz
```

#### Backup Specific Tables

```bash
# Backup certificates table only
kubectl exec -n ostrich-pki ostrich-pki-postgresql-0 -- \
  pg_dump -U ostrich -t certificates ostrich_pki > certificates-backup.sql

# Backup audit logs
kubectl exec -n ostrich-pki ostrich-pki-postgresql-0 -- \
  pg_dump -U ostrich -t audit_events ostrich_pki > audit-backup.sql
```

#### Backup with Encryption

```bash
# Backup with GPG encryption (NIST 800-53: SC-28)
kubectl exec -n ostrich-pki ostrich-pki-postgresql-0 -- \
  pg_dump -U ostrich ostrich_pki | \
  gpg --encrypt --recipient backup@example.com | \
  aws s3 cp - s3://ostrich-pki-backups/backup-$(date +%Y%m%d).sql.gpg
```

### Verify Backup Integrity

```bash
# Download and verify backup
gunzip -t backup-20240115.sql.gz
# Should complete without errors

# Check backup contents
gunzip -c backup-20240115.sql.gz | head -100
```

## Recovery Procedures

### Point-in-Time Recovery

#### From Latest Backup

```bash
# Stop all OstrichPKI services
kubectl scale deployment --all -n ostrich-pki --replicas=0

# Restore database
cat backup.sql | kubectl exec -i -n ostrich-pki ostrich-pki-postgresql-0 -- \
  psql -U ostrich ostrich_pki

# Restart services
kubectl scale deployment ostrich-pki-ca -n ostrich-pki --replicas=1
kubectl scale deployment ostrich-pki-acme -n ostrich-pki --replicas=2
# ... repeat for other services
```

#### From Specific Point in Time

If using PostgreSQL WAL archiving:

```bash
# Create recovery.conf
cat << EOF > /tmp/recovery.conf
restore_command = 'aws s3 cp s3://ostrich-pki-wal/%f %p'
recovery_target_time = '2024-01-15 12:00:00 UTC'
EOF

# Copy to PostgreSQL pod and restart
kubectl cp /tmp/recovery.conf ostrich-pki/ostrich-pki-postgresql-0:/var/lib/postgresql/data/
kubectl delete pod ostrich-pki-postgresql-0 -n ostrich-pki
```

### Disaster Recovery

#### Complete Cluster Loss

1. **Provision new infrastructure:**

```bash
# Apply Terraform/CloudFormation for infrastructure
terraform apply

# Install OstrichPKI
helm install ostrich-pki deploy/helm/ostrich-pki -n ostrich-pki
```

1. **Restore database:**

```bash
# Wait for PostgreSQL to be ready
kubectl wait --for=condition=ready pod/ostrich-pki-postgresql-0 -n ostrich-pki --timeout=300s

# Restore from backup
aws s3 cp s3://ostrich-pki-backups/latest.sql.gz - | gunzip | \
  kubectl exec -i -n ostrich-pki ostrich-pki-postgresql-0 -- \
  psql -U ostrich ostrich_pki
```

1. **Restore CA keys from HSM backup:**

```bash
# This depends on your HSM vendor
# Typically involves importing PKCS#11 backup
```

1. **Verify recovery:**

```bash
# Check certificate count
kubectl exec -n ostrich-pki ostrich-pki-postgresql-0 -- \
  psql -U ostrich ostrich_pki -c "SELECT count(*) FROM certificates;"

# Verify CA can sign
curl http://localhost:8080/health
```

#### Database Corruption Recovery

1. **Detect corruption:**

```bash
# Run PostgreSQL consistency check
kubectl exec -n ostrich-pki ostrich-pki-postgresql-0 -- \
  pg_dumpall -U postgres > /dev/null
# If this fails, database is corrupt
```

1. **Recover from corruption:**

```bash
# Option 1: Restore from backup (preferred)
# See "From Latest Backup" above

# Option 2: Attempt repair (last resort)
kubectl exec -n ostrich-pki ostrich-pki-postgresql-0 -- \
  pg_resetwal -f /var/lib/postgresql/data
```

## Data Validation

### Post-Recovery Validation

```bash
# Check table row counts
kubectl exec -n ostrich-pki ostrich-pki-postgresql-0 -- psql -U ostrich ostrich_pki << EOF
SELECT 'certificates' as table_name, count(*) FROM certificates
UNION ALL
SELECT 'revocations', count(*) FROM revocations
UNION ALL
SELECT 'audit_events', count(*) FROM audit_events
UNION ALL
SELECT 'acme_accounts', count(*) FROM acme_accounts;
EOF

# Verify foreign key integrity
kubectl exec -n ostrich-pki ostrich-pki-postgresql-0 -- psql -U ostrich ostrich_pki << EOF
SELECT conname, conrelid::regclass, confrelid::regclass
FROM pg_constraint
WHERE contype = 'f'
AND NOT EXISTS (
  SELECT 1 FROM pg_depend
  WHERE objid = conrelid
);
EOF
```

### Certificate Chain Validation

```bash
# Verify certificate chains are intact
kubectl exec -n ostrich-pki ostrich-pki-ca-xxxx -- \
  ostrich-cli validate-chains
```

## Backup Retention Policy

| Backup Type | Retention | Storage Location |
|-------------|-----------|------------------|
| Hourly WAL | 24 hours | S3/NFS |
| Daily Full | 30 days | S3 (Standard) |
| Weekly Full | 1 year | S3 (Glacier) |
| Monthly Full | 7 years | S3 (Glacier Deep) |

## Emergency Contacts

| Role | Contact | When to Escalate |
|------|---------|------------------|
| Database Admin | dba@example.com | Corruption, failed recovery |
| Security Team | security@example.com | Any PKI key recovery |
| On-Call Engineer | +1-555-0100 | After-hours incidents |

## Recovery Time Objectives

| Scenario | RTO | RPO |
|----------|-----|-----|
| Single pod failure | 5 minutes | 0 (HA) |
| Database restart | 15 minutes | 0 |
| Full backup restore | 4 hours | Last backup |
| Disaster recovery | 8 hours | Last backup |
