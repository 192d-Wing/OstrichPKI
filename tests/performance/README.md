# OstrichPKI Performance Tests

Load and performance testing for OstrichPKI services using [k6](https://k6.io/).

## Prerequisites

Install k6:

```bash
# macOS
brew install k6

# Linux (Debian/Ubuntu)
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6

# Docker
docker pull grafana/k6
```

## Test Files

| Test | Service | Description | Target TPS |
|------|---------|-------------|------------|
| `acme-load-test.js` | ACME | Directory, nonce, health endpoints | 50-100 |
| `ocsp-load-test.js` | OCSP | Certificate status queries | 1000+ |
| `ca-load-test.js` | CA | Health and readiness checks | 50-100 |

## Running Tests

### Quick Test

```bash
# Test ACME service
k6 run tests/performance/acme-load-test.js

# Test OCSP service
k6 run tests/performance/ocsp-load-test.js

# Test CA service
k6 run tests/performance/ca-load-test.js
```

### Custom Configuration

```bash
# Override VUs and duration
k6 run --vus 100 --duration 5m tests/performance/acme-load-test.js

# Override service URL
ACME_BASE_URL=http://acme.example.com:8080 k6 run tests/performance/acme-load-test.js
```

### Docker

```bash
# Run with Docker
docker run --rm -v $(pwd)/tests/performance:/tests \
  -e ACME_BASE_URL=http://host.docker.internal:8080 \
  grafana/k6 run /tests/acme-load-test.js
```

## Performance Targets

Based on ROADMAP.md requirements:

| Metric | Target | Acceptable | Service |
|--------|--------|------------|---------|
| OCSP response | <100ms (p99) | <200ms | OCSP |
| OCSP TPS | 1000 TPS | 500 TPS | OCSP |
| ACME directory | <200ms (p95) | <500ms | ACME |
| ACME account creation | <500ms | <1s | ACME |
| Certificate signing (HSM) | <50ms | <100ms | CA |
| Health check | <50ms (p95) | <100ms | All |
| Database queries | <10ms (p99) | <50ms | All |

## Test Scenarios

### ACME Load Test

1. **Ramp-up**: 0 → 10 → 50 → 100 VUs over 5 minutes
2. **Steady state**: 100 VUs for 2 minutes
3. **Ramp-down**: 100 → 0 VUs over 30 seconds

Tests:

- `GET /health` - Health check
- `GET /directory` - ACME directory (RFC 8555 §7.1.1)
- `HEAD {newNonce}` - Nonce generation (RFC 8555 §7.2)

### OCSP Load Test

1. **Constant rate**: 1000 requests/second for 2 minutes
2. **Spike test**: 100 → 500 → 2000 → 500 → 100 requests/second

Tests:

- `GET /health` - Health check
- `GET /{base64-request}` - OCSP GET (RFC 6960 Appendix A.1)
- `POST /` - OCSP POST (RFC 6960 Appendix A.1)

### CA Load Test

1. **Ramp-up**: 0 → 10 → 25 → 50 VUs over 5 minutes
2. **Steady state**: 50 VUs for 2 minutes
3. **Ramp-down**: 50 → 0 VUs over 30 seconds

Tests:

- `GET /health` - Health check
- `GET /ready` - Readiness check (includes HSM connectivity)

## Results

Test results are saved to `tests/performance/results/`:

- `acme-load-test-summary.json` - ACME test results
- `ocsp-load-test-summary.json` - OCSP test results
- `ca-load-test-summary.json` - CA test results

## CI Integration

Add to GitLab CI:

```yaml
performance-test:
  stage: test
  image: grafana/k6:latest
  services:
    - name: postgres:16
      alias: db
  script:
    - k6 run tests/performance/acme-load-test.js --out json=results.json
  artifacts:
    paths:
      - results.json
    when: always
```

## Grafana Dashboard

For real-time monitoring, use k6 with Grafana:

```bash
# Run with InfluxDB output
k6 run --out influxdb=http://localhost:8086/k6 tests/performance/acme-load-test.js
```

Then import the k6 dashboard in Grafana (ID: 2587).

## Compliance

NIST 800-53 Controls:

- **SA-11**: Developer Security Testing
- **SC-5**: Denial of Service Protection

RFC Compliance:

- **RFC 8555**: ACME protocol endpoints
- **RFC 6960**: OCSP response timing
