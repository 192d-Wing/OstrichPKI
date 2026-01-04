# Runbook: OstrichPKI Service Down

## Overview

**Alert Name:** `OstrichPKIServiceDown`
**Severity:** Critical
**NIST 800-53 Controls:** SI-4, CP-10, IR-4

This runbook covers troubleshooting and recovery procedures when an OstrichPKI service becomes unavailable.

## Impact Assessment

| Service | Impact if Down |
|---------|---------------|
| CA | Cannot issue new certificates; existing certificates remain valid |
| OCSP | Certificate validation may fail; clients may fallback to CRL |
| ACME | Automated certificate issuance blocked |
| EST | Device enrollment blocked |
| SCMS | Smartcard operations blocked |
| KRA | Key recovery operations blocked |

## Diagnostic Steps

### 1. Verify Alert Accuracy

```bash
# Check if pods are running
kubectl get pods -n ostrich-pki -l app.kubernetes.io/component=<component>

# Check pod status details
kubectl describe pod -n ostrich-pki <pod-name>

# Check service endpoints
kubectl get endpoints -n ostrich-pki
```

### 2. Check Pod Logs

```bash
# View recent logs
kubectl logs -n ostrich-pki <pod-name> --tail=100

# Stream logs for live debugging
kubectl logs -n ostrich-pki <pod-name> -f

# View previous container logs (if restarting)
kubectl logs -n ostrich-pki <pod-name> --previous
```

### 3. Check Resource Utilization

```bash
# Check pod resource usage
kubectl top pods -n ostrich-pki

# Check node resources
kubectl top nodes
```

### 4. Verify Database Connectivity

```bash
# Test database connection from pod
kubectl exec -n ostrich-pki <pod-name> -- nc -zv ostrich-pki-postgresql 5432

# Check database pod status
kubectl get pods -n ostrich-pki -l app.kubernetes.io/name=postgresql
```

## Common Issues and Resolutions

### Issue: Pod CrashLoopBackOff

**Symptoms:**

- Pod status shows `CrashLoopBackOff`
- Logs show application startup failures

**Resolution:**

1. Check for configuration errors:

```bash
kubectl describe pod -n ostrich-pki <pod-name> | grep -A5 "Environment"
```

1. Verify secrets are mounted:

```bash
kubectl get secret -n ostrich-pki ostrich-pki-db -o yaml
```

1. Check for missing dependencies:

```bash
kubectl logs -n ostrich-pki <pod-name> --previous | grep -i "error\|panic\|fatal"
```

### Issue: Database Connection Failed

**Symptoms:**

- Logs show `database connection refused` or `connection timeout`
- Pod stuck in initialization

**Resolution:**

1. Verify PostgreSQL is running:

```bash
kubectl get pods -n ostrich-pki -l app.kubernetes.io/name=postgresql
```

1. Check database credentials:

```bash
kubectl get secret -n ostrich-pki ostrich-pki-db -o jsonpath='{.data.password}' | base64 -d
```

1. Test connectivity:

```bash
kubectl run -n ostrich-pki psql-test --rm -it --image=postgres:16 -- psql "postgresql://ostrich:<password>@ostrich-pki-postgresql:5432/ostrich_pki"
```

### Issue: Out of Memory (OOMKilled)

**Symptoms:**

- Pod terminated with reason `OOMKilled`
- `kubectl describe pod` shows memory limit exceeded

**Resolution:**

1. Increase memory limits in deployment:

```yaml
resources:
  limits:
    memory: 1Gi  # Increase from default 512Mi
```

1. Apply changes:

```bash
kubectl apply -f deploy/kubernetes/ca-deployment.yaml
```

### Issue: Certificate/TLS Errors

**Symptoms:**

- Logs show TLS handshake failures
- Certificate validation errors

**Resolution:**

1. Check certificate secrets:

```bash
kubectl get secret -n ostrich-pki ostrich-pki-ca-certs -o yaml
```

1. Verify certificate validity:

```bash
kubectl get secret -n ostrich-pki ostrich-pki-ca-certs -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -text -noout
```

1. Regenerate certificates if expired (see certificate rotation runbook)

## Recovery Procedures

### Restart Single Service

```bash
# Trigger rolling restart
kubectl rollout restart deployment/ostrich-pki-<component> -n ostrich-pki

# Monitor restart progress
kubectl rollout status deployment/ostrich-pki-<component> -n ostrich-pki
```

### Scale Up Replicas

```bash
# Increase replicas for high availability
kubectl scale deployment/ostrich-pki-<component> -n ostrich-pki --replicas=3

# Verify new pods are healthy
kubectl get pods -n ostrich-pki -l app.kubernetes.io/component=<component>
```

### Full Service Recovery

If a service cannot be recovered through restarts:

1. Check persistent data:

```bash
kubectl get pvc -n ostrich-pki
```

1. Verify database integrity:

```bash
# Connect to database pod
kubectl exec -n ostrich-pki ostrich-pki-postgresql-0 -- psql -U ostrich ostrich_pki -c "SELECT count(*) FROM certificates;"
```

1. Redeploy if necessary:

```bash
helm upgrade --install ostrich-pki deploy/helm/ostrich-pki -n ostrich-pki
```

## Escalation

If the issue cannot be resolved within 30 minutes:

1. Notify the security team (PKI operations may be impacted)
2. Enable maintenance page / status notification
3. Engage on-call senior engineer
4. Document all troubleshooting steps taken

## Post-Incident Actions

After service recovery:

1. [ ] Verify all health checks passing
2. [ ] Review audit logs for any failed operations during outage
3. [ ] Check for backlog of pending operations (ACME orders, etc.)
4. [ ] Create incident report
5. [ ] Update runbook if new issues discovered
