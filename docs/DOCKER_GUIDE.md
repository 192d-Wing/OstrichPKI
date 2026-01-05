# OstrichPKI Docker Deployment Guide

**Document Version:** 1.0
**Last Updated:** January 2026
**OstrichPKI Version:** 0.15.0
**Audience:** DevOps Engineers, System Administrators

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Docker Images](#docker-images)
4. [Docker Compose](#docker-compose)
5. [Configuration](#configuration)
6. [Volumes and Persistence](#volumes-and-persistence)
7. [Networking](#networking)
8. [Security Considerations](#security-considerations)
9. [Production Deployment](#production-deployment)
10. [Troubleshooting](#troubleshooting)

---

## Overview

OstrichPKI provides multi-stage Docker images for all services, built with security and minimal attack surface in mind.

### Key Features

- **Multi-stage builds** - Minimal runtime images (~50MB base)
- **Non-root execution** - All services run as `ostrich` user (UID 1000)
- **Health checks** - Built-in health monitoring
- **Compliance** - NIST 800-53 CM-2, CM-6, AC-6 compliant
- **SBOM included** - Software Bill of Materials for vulnerability scanning

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     External Network                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │   ACME   │  │   EST    │  │   OCSP   │  │    CA    │  │
│  │  :8081   │  │  :8443   │  │  :8082   │  │  :8080   │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
└───────┼────────────┼────────────┼────────────┼────────────┘
        │            │            │            │
┌───────┼────────────┼────────────┼────────────┼────────────┐
│       │     Internal Network (ostrich_internal)           │
│  ┌────▼─────┐  ┌──▼──────┐  ┌─▼───────┐  ┌──▼──────┐    │
│  │    CA    │  │  SCMS   │  │   KRA   │  │ Postgres│    │
│  │ :50051   │  │  :8083  │  │  :8084  │  │  :5432  │    │
│  │  (gRPC)  │  └─────────┘  └─────────┘  └─────────┘    │
│  └──────────┘                                             │
└───────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Docker 24+ (or Docker Desktop)
- Docker Compose 2.0+
- 4GB RAM minimum
- 20GB disk space

### Start All Services

```bash
# Clone repository
git clone https://github.com/ostrich-pki/ostrich-pki.git
cd ostrich-pki

# Set environment variables (optional)
export POSTGRES_PASSWORD=strongpassword
export RUST_LOG=info

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f ca-service

# Check status
docker-compose ps
```

### Verify Deployment

```bash
# Check CA service health
curl http://localhost:8080/health

# Check ACME directory
curl http://localhost:8081/acme/directory

# Check OCSP responder
curl http://localhost:8082/health

# View PostgreSQL logs
docker-compose logs postgres
```

### Stop Services

```bash
# Stop all services (preserves data)
docker-compose down

# Stop and remove volumes (⚠️ destroys data)
docker-compose down -v
```

---

## Docker Images

### Available Images

All images are available from GitHub Container Registry:

| Image | Description | Size | Ports |
|-------|-------------|------|-------|
| `ghcr.io/ostrich-pki/ca-service:0.15.0` | CA core service | ~55MB | 50051 (gRPC), 8080 (REST) |
| `ghcr.io/ostrich-pki/acme-service:0.15.0` | ACME responder | ~52MB | 8080 |
| `ghcr.io/ostrich-pki/est-service:0.15.0` | EST enrollment | ~52MB | 8443 |
| `ghcr.io/ostrich-pki/ocsp-service:0.15.0` | OCSP responder | ~52MB | 8081 |
| `ghcr.io/ostrich-pki/scms-service:0.15.0` | Smartcard management | ~52MB | 8082 |
| `ghcr.io/ostrich-pki/kra-service:0.15.0` | Key recovery | ~52MB | 8083 |
| `ghcr.io/ostrich-pki/cli:0.15.0` | CLI tools | ~52MB | - |

### Pull Images

```bash
# Pull all images
docker-compose pull

# Pull specific image
docker pull ghcr.io/ostrich-pki/ca-service:0.15.0

# Verify image signature (when available)
docker trust inspect ghcr.io/ostrich-pki/ca-service:0.15.0
```

### Build from Source

```bash
# Build all services
docker-compose build

# Build specific service
docker build --target ca-service -t ostrich-ca:dev .

# Build with specific Rust version
docker build --build-arg RUST_VERSION=1.83 -t ostrich-ca:dev .
```

### Image Security

All images:
- ✅ Run as non-root user (`ostrich`, UID 1000)
- ✅ Based on `debian:bookworm-slim` (security patches)
- ✅ Minimal runtime dependencies
- ✅ No shell in runtime images
- ✅ Health checks included
- ✅ Compliance annotations (NIST 800-53)

---

## Docker Compose

### Configuration File

The `docker-compose.yaml` provides:

- **7 services**: postgres, ca-service, acme-service, est-service, ocsp-service, scms-service, kra-service
- **2 networks**: `ostrich_internal` (private), `ostrich_external` (public)
- **11 volumes**: Persistent storage for each service

### Environment Variables

Create a `.env` file in the project root:

```bash
# Database Configuration
POSTGRES_PASSWORD=changeme_in_production
POSTGRES_DB=ostrich_pki
POSTGRES_USER=ostrich

# Logging
RUST_LOG=info  # Options: trace, debug, info, warn, error

# HSM Configuration (Development - SoftHSM)
PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so
PKCS11_SLOT=0
PKCS11_PIN=1234
REQUIRE_HSM=false  # Set to true for production with real HSM

# CA Service
CA_BIND_ADDRESS=0.0.0.0:50051
CA_REST_ADDRESS=0.0.0.0:8080

# ACME Service
ACME_BIND_ADDRESS=0.0.0.0:8080

# EST Service
EST_BIND_ADDRESS=0.0.0.0:8443
```

### Service Dependencies

```yaml
# Service startup order
postgres → ca-service → (acme, est, ocsp, scms, kra)
```

Health checks ensure services wait for dependencies before starting.

---

## Configuration

### Volume Mounts

Each service uses dedicated volumes:

```yaml
# Example: CA Service volumes
volumes:
  - ca_config:/app/config      # Configuration files
  - ca_certs:/app/certs        # TLS certificates
  - ca_data:/app/data          # Runtime data
```

### Runtime Configuration

Configuration files can be mounted at runtime:

```bash
# Create custom config
cat > ca-config.yaml << EOF
service:
  name: "Custom CA"
  environment: production
database:
  url: postgresql://ostrich:pass@postgres:5432/ostrich_pki
EOF

# Mount config file
docker run -v $(pwd)/ca-config.yaml:/app/config/config.yaml \
  ghcr.io/ostrich-pki/ca-service:0.15.0
```

### Database Initialization

The PostgreSQL container automatically runs migrations on first start:

```yaml
volumes:
  - ./migrations:/docker-entrypoint-initdb.d:ro
```

Migration files are executed in order (00001, 00002, etc.).

---

## Volumes and Persistence

### Volume Types

| Volume | Purpose | Backup Required | Size Estimate |
|--------|---------|-----------------|---------------|
| `postgres_data` | Database storage | ✅ Critical | 10GB+ |
| `ca_data` | CA runtime data | ✅ Critical | 1GB |
| `ca_certs` | TLS certificates | ✅ Important | 100MB |
| `kra_data` | Escrowed keys | ✅ Critical | 5GB |
| `*_config` | Service configs | ✅ Important | <10MB |

### Backup Strategy

```bash
# Backup PostgreSQL database
docker exec ostrich-postgres pg_dump -U ostrich ostrich_pki > backup.sql

# Backup all volumes
docker run --rm -v postgres_data:/data -v $(pwd):/backup \
  alpine tar czf /backup/postgres_data.tar.gz /data

# Restore from backup
docker run --rm -v postgres_data:/data -v $(pwd):/backup \
  alpine tar xzf /backup/postgres_data.tar.gz -C /
```

### Volume Management

```bash
# List volumes
docker volume ls | grep ostrich

# Inspect volume
docker volume inspect postgres_data

# Remove unused volumes
docker volume prune

# Backup volume to tar
docker run --rm -v ca_data:/source -v $(pwd):/backup \
  busybox tar czf /backup/ca_data.tar.gz -C /source .
```

---

## Networking

### Network Configuration

```yaml
networks:
  # Internal network - service-to-service communication
  ostrich_internal:
    driver: bridge
    internal: false  # Set to true in production

  # External network - public-facing services
  ostrich_external:
    driver: bridge
```

### Port Mapping

| Service | Internal Port | External Port | Protocol | Public |
|---------|---------------|---------------|----------|--------|
| CA (gRPC) | 50051 | 50051 | HTTP/2 | No |
| CA (REST) | 8080 | 8080 | HTTP | No |
| ACME | 8080 | 8081 | HTTPS | Yes |
| EST | 8443 | 8443 | HTTPS | Yes |
| OCSP | 8081 | 8082 | HTTP | Yes |
| SCMS | 8082 | 8083 | HTTPS | No |
| KRA | 8083 | 8084 | HTTPS | No |
| PostgreSQL | 5432 | 5432 | TCP | No |

### Firewall Rules

```bash
# Allow ACME (Let's Encrypt clients)
sudo ufw allow 8081/tcp comment "ACME Service"

# Allow EST (enrollment clients)
sudo ufw allow 8443/tcp comment "EST Service"

# Allow OCSP (certificate validation)
sudo ufw allow 8082/tcp comment "OCSP Responder"

# Block direct database access
sudo ufw deny 5432/tcp comment "PostgreSQL"
```

---

## Security Considerations

### Development vs Production

| Feature | Development | Production |
|---------|-------------|------------|
| HSM | SoftHSM | FIPS 140-2 Level 2+ |
| TLS | Self-signed | Valid certificates |
| Passwords | Default | Strong, rotated |
| Networks | Exposed | Isolated |
| Audit Logs | File | SIEM integration |
| `REQUIRE_HSM` | false | true |

### HSM Integration

**Development (SoftHSM):**

```yaml
environment:
  PKCS11_LIBRARY: /usr/lib/softhsm/libsofthsm2.so
  PKCS11_SLOT: 0
  PKCS11_PIN: 1234
  REQUIRE_HSM: false  # Allow software keys
```

**Production (Real HSM):**

```yaml
environment:
  PKCS11_LIBRARY: /opt/luna/libs/64/libCryptoki2_64.so
  PKCS11_SLOT: 0
  PKCS11_PIN: ${PKCS11_PIN}  # From secrets manager
  REQUIRE_HSM: true  # Enforce HSM storage
volumes:
  - /opt/luna:/opt/luna:ro  # Mount HSM client libraries
devices:
  - /dev/luna0:/dev/luna0  # HSM device access
```

### Secrets Management

**⚠️ DO NOT hardcode secrets in docker-compose.yaml**

Use Docker secrets or environment variables from secure sources:

```bash
# Use Docker secrets (Swarm mode)
echo "strongpassword" | docker secret create postgres_password -

# Use environment file
docker-compose --env-file .env.production up -d

# Use external secrets manager (AWS Secrets Manager, Vault)
export POSTGRES_PASSWORD=$(aws secretsmanager get-secret-value \
  --secret-id ostrich/postgres/password --query SecretString --output text)
```

### Network Isolation

For production, isolate internal network:

```yaml
networks:
  ostrich_internal:
    driver: bridge
    internal: true  # No external access
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

---

## Production Deployment

### Prerequisites

1. **FIPS 140-2 validated HSM**
   - Thales Luna Network HSM 7
   - AWS CloudHSM
   - Azure Dedicated HSM

2. **Valid TLS certificates**
   - From trusted CA
   - Wildcard or SAN for all services

3. **Hardened OS**
   - RHEL 8/9 or Ubuntu 22.04+ LTS
   - SELinux/AppArmor enabled
   - Security patches applied

### Production Compose Override

Create `docker-compose.prod.yaml`:

```yaml
version: '3.8'

services:
  ca-service:
    environment:
      REQUIRE_HSM: "true"
      RUST_LOG: warn
    volumes:
      - /opt/luna:/opt/luna:ro
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G

  postgres:
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/postgres_password
    secrets:
      - postgres_password
    volumes:
      - /encrypted/postgres_data:/var/lib/postgresql/data

secrets:
  postgres_password:
    external: true
```

Start with production overrides:

```bash
docker-compose -f docker-compose.yaml -f docker-compose.prod.yaml up -d
```

### Kubernetes Migration

For production scale, migrate to Kubernetes:

```bash
# Install Helm chart
helm install ostrich-pki ostrich-pki/ostrich-pki \
  --namespace ostrich-pki \
  --create-namespace \
  --values production-values.yaml

# Example values.yaml
cat > production-values.yaml << EOF
global:
  requireHsm: true
  hsm:
    type: luna
    library: /opt/luna/libs/64/libCryptoki2_64.so

database:
  type: postgresql
  host: postgres.database.svc.cluster.local
  credentials:
    existingSecret: postgres-credentials

ingress:
  enabled: true
  className: nginx
  tls:
    enabled: true
    secretName: ostrich-tls

resources:
  ca:
    limits:
      cpu: 2000m
      memory: 4Gi
    requests:
      cpu: 1000m
      memory: 2Gi
EOF
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check service logs
docker-compose logs ca-service

# Check service health
docker inspect ostrich-ca --format='{{.State.Health.Status}}'

# Enter container for debugging
docker exec -it ostrich-ca /bin/sh
```

### Database Connection Errors

```bash
# Verify PostgreSQL is ready
docker-compose logs postgres | grep "ready to accept connections"

# Test connection from CA service
docker exec ostrich-ca curl postgres:5432

# Check database credentials
docker exec ostrich-postgres psql -U ostrich -d ostrich_pki -c "SELECT 1;"
```

### HSM Not Detected

```bash
# Check PKCS#11 library
docker exec ostrich-ca ls -la ${PKCS11_LIBRARY}

# Verify HSM device access
docker exec ostrich-ca pkcs11-tool --module ${PKCS11_LIBRARY} --list-slots

# Check HSM environment variables
docker exec ostrich-ca env | grep PKCS11
```

### Port Conflicts

```bash
# Check port usage
sudo netstat -tulpn | grep 8080

# Change port mapping in docker-compose.yaml
ports:
  - "9080:8080"  # Map to different host port
```

### Volume Permission Issues

```bash
# Fix volume ownership
docker run --rm -v ca_data:/data alpine chown -R 1000:1000 /data

# Check volume permissions
docker run --rm -v ca_data:/data alpine ls -la /data
```

### Performance Issues

```bash
# Check resource usage
docker stats

# Increase memory limits
docker-compose -f docker-compose.yaml \
  -f <(cat <<EOF
services:
  ca-service:
    deploy:
      resources:
        limits:
          memory: 8G
EOF
) up -d
```

---

## Additional Resources

- [Dockerfile Reference](../Dockerfile)
- [Docker Compose Reference](../docker-compose.yaml)
- [Installation Guide](compliance/INSTALLATION_GUIDE.md)
- [Admin Guide](compliance/ADMIN_GUIDE.md)
- [Kubernetes Helm Charts](https://github.com/ostrich-pki/helm-charts)

---

**SECURITY NOTICE:**
- Development Docker setup uses SoftHSM - **NOT for production use**
- Production deployments **MUST** use FIPS 140-2 Level 2+ validated HSMs
- Always use strong, randomly generated passwords
- Enable TLS for all external communications
- Regularly scan images for vulnerabilities: `grype ghcr.io/ostrich-pki/ca-service:0.15.0`
