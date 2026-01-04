# Health Check Endpoints

All OstrichPKI services expose standardized health and readiness check endpoints for Kubernetes orchestration.

## COMPLIANCE MAPPING

- **NIST 800-53: SI-17** - Fail-safe response
- **Kubernetes**: Liveness and readiness probes

## Endpoints

### Liveness Probe: `/health`

**Purpose**: Determine if the service process is running and responsive.

**Response**: Always returns 200 OK if the service can handle the request.

**Use Case**: Kubernetes uses this to restart pods that become unresponsive.

**Example Response**:
```json
{
  "status": "healthy",
  "service": "ostrich-ca",
  "version": "0.13.0"
}
```

### Readiness Probe: `/ready`

**Purpose**: Determine if the service is ready to handle traffic.

**Response**:
- **200 OK**: Service is ready (all dependencies accessible)
- **503 SERVICE_UNAVAILABLE**: Service is not ready (dependencies unavailable)

**Use Case**: Kubernetes uses this to control traffic routing.

**Example Response (Ready)**:
```json
{
  "status": "ready",
  "service": "ostrich-acme",
  "version": "0.13.0",
  "checks": {
    "database": true,
    "crypto_provider": true
  }
}
```

**Example Response (Not Ready)**:
```json
{
  "status": "not_ready",
  "service": "ostrich-acme",
  "checks": {
    "database": false
  }
}
```

## Service Status

| Service | `/health` | `/ready` | Database Check | Notes |
|---------|-----------|----------|----------------|-------|
| **ostrich-ca** | ✅ | ✅ | ⏳ TODO | Checks CA initialization |
| **ostrich-acme** | ✅ | ✅ | ✅ | Checks PostgreSQL connectivity |
| **ostrich-est** | ⏳ TODO | ⏳ TODO | ⏳ TODO | Needs implementation |
| **ostrich-ocsp** | ⏳ TODO | ⏳ TODO | ⏳ TODO | Needs implementation |
| **ostrich-kra** | ⏳ TODO | ⏳ TODO | ⏳ TODO | Needs implementation |
| **ostrich-scms** | ⏳ TODO | ⏳ TODO | ⏳ TODO | Needs implementation |

## Implementation

### Using the Helper Module

All services use `ostrich-common::health` for standardized responses:

```rust
use ostrich_common::health;

// Liveness probe - simple health check
async fn health_check() -> impl IntoResponse {
    health::health_response("ostrich-acme")
}

// Readiness probe - with database check
async fn readiness_check(State(state): State<AcmeState>) -> impl IntoResponse {
    health::readiness_response_with_db("ostrich-acme", &state.db_pool).await
}

// Readiness probe - without database
async fn readiness_check() -> impl IntoResponse {
    health::readiness_response_simple("ostrich-service")
}
```

### Adding to Router

```rust
Router::new()
    .route("/health", get(health_check))
    .route("/ready", get(readiness_check))
    // ... other routes
```

## Kubernetes Configuration

### Liveness Probe

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
```

### Readiness Probe

```yaml
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 3
```

## Testing

```bash
# Test liveness probe
curl http://localhost:8080/health

# Test readiness probe
curl http://localhost:8080/ready

# Expected 200 OK when healthy/ready
# Expected 503 when not ready
```

## Monitoring

Health check endpoints can be monitored for:

- **Response time**: Should be <100ms
- **Availability**: Should be >99.9%
- **Error rate**: Should be 0% for `/health`, <1% for `/ready`

Alert if:
- `/health` returns non-200 (service crashed)
- `/ready` returns 503 for >5 minutes (prolonged degradation)
- Response time >1s (performance issue)
