# OstrichPKI Penetration Testing Guide

## Overview

This document outlines the penetration testing requirements and procedures for OstrichPKI to ensure security before production deployment.

**NIST 800-53 Controls**: CA-2 (Security Assessments), CA-8 (Penetration Testing), SA-11 (Developer Security Testing)

## Scope

### In-Scope Systems

| Service | Endpoints | Priority |
|---------|-----------|----------|
| ACME | `/directory`, `/new-nonce`, `/new-account`, `/new-order`, `/authz/*`, `/challenge/*`, `/finalize/*`, `/certificate/*` | HIGH |
| EST | `/cacerts`, `/simpleenroll`, `/simplereenroll`, `/csrattrs` | HIGH |
| OCSP | `/` (POST), `/{base64-request}` (GET) | HIGH |
| CA | gRPC endpoints, `/health`, `/ready` | HIGH |
| KRA | `/escrow`, `/recover`, `/agents` | MEDIUM |
| SCMS | `/tokens/*`, `/keys/*`, `/events` | MEDIUM |
| Audit | `/events`, `/search` | LOW |

### Out of Scope

- Third-party dependencies (covered by `cargo audit`)
- Operating system vulnerabilities
- Network infrastructure

## Test Categories

### 1. Authentication & Authorization

#### ACME JWS Validation (RFC 8555)

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| AUTH-01 | Submit request without JWS signature | HTTP 400, `urn:ietf:params:acme:error:malformed` |
| AUTH-02 | Submit request with invalid JWS signature | HTTP 403, `urn:ietf:params:acme:error:unauthorized` |
| AUTH-03 | Submit request with expired nonce | HTTP 400, `urn:ietf:params:acme:error:badNonce` |
| AUTH-04 | Replay previously used nonce | HTTP 400, `urn:ietf:params:acme:error:badNonce` |
| AUTH-05 | Use different account's key for order | HTTP 403, `urn:ietf:params:acme:error:unauthorized` |
| AUTH-06 | Access order without account ownership | HTTP 403 |
| AUTH-07 | Modify JWS protected header after signing | HTTP 400 |

#### EST mTLS Authentication (RFC 7030)

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| AUTH-10 | Request without client certificate | TLS handshake failure |
| AUTH-11 | Request with expired client certificate | HTTP 403 |
| AUTH-12 | Request with revoked client certificate | HTTP 403 |
| AUTH-13 | Request with untrusted CA | TLS handshake failure |
| AUTH-14 | Request with valid cert, unauthorized CN | HTTP 403 |

#### PIN/Password Security (SCMS)

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| AUTH-20 | Brute force PIN attempts | Account lockout after 5 attempts |
| AUTH-21 | Timing attack on PIN verification | Constant-time comparison |
| AUTH-22 | PIN in clear text in logs | PIN must be redacted |
| AUTH-23 | PIN stored in plaintext | PIN must be hashed (Argon2) |

### 2. Input Validation

#### CSR Validation

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| INP-01 | Malformed CSR (invalid ASN.1) | HTTP 400, parsing error |
| INP-02 | CSR with invalid signature | HTTP 400, signature verification failed |
| INP-03 | CSR requesting unauthorized SAN | HTTP 403 or HTTP 400 |
| INP-04 | CSR with excessively long CN (>64 chars) | HTTP 400, validation error |
| INP-05 | CSR with null bytes in DN | HTTP 400 |
| INP-06 | CSR requesting wildcard for non-domain-validated | HTTP 403 |

#### OCSP Request Validation

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| INP-10 | Malformed OCSP request | HTTP 400 |
| INP-11 | OCSP request for unknown issuer | OCSP response with `unknown` status |
| INP-12 | Oversized OCSP request (>64KB) | HTTP 400 or 413 |
| INP-13 | OCSP request with invalid hash algorithm | HTTP 400 |

#### API Input Validation

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| INP-20 | SQL injection in query parameters | No SQL error, parameterized query protection |
| INP-21 | Command injection in identifiers | No command execution |
| INP-22 | Path traversal in resource IDs | HTTP 400 or 404 |
| INP-23 | JSON with deeply nested objects | HTTP 400 or graceful handling |
| INP-24 | Extremely large JSON payload | HTTP 413 or timeout |

### 3. Protocol Security

#### ACME Protocol (RFC 8555)

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| PROT-01 | HTTP-01 challenge manipulation | Challenge marked invalid |
| PROT-02 | DNS-01 with incorrect TXT record | Challenge marked invalid |
| PROT-03 | TLS-ALPN-01 with wrong certificate | Challenge marked invalid |
| PROT-04 | Order state manipulation (skip validation) | State machine enforcement |
| PROT-05 | Request certificate before authorization complete | HTTP 403 |
| PROT-06 | Finalize with modified identifiers | HTTP 400 |

#### EST Protocol (RFC 7030)

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| PROT-10 | Simple enroll without prior auth | mTLS required |
| PROT-11 | Re-enroll with different subject | HTTP 400 or 403 |
| PROT-12 | Request CA certs over HTTP (not HTTPS) | Connection refused |

#### OCSP Protocol (RFC 6960)

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| PROT-20 | Nonce replay attack | Different response or nonce mismatch |
| PROT-21 | Response with future producedAt | Validation failure |
| PROT-22 | Response with past nextUpdate | Stale response detection |

### 4. Cryptographic Security

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| CRYPTO-01 | Weak key detection (RSA <2048, EC <P-256) | HTTP 400, key too weak |
| CRYPTO-02 | Deprecated algorithm (SHA-1, MD5) | HTTP 400, algorithm not supported |
| CRYPTO-03 | Timing attack on signature verification | Constant-time operations |
| CRYPTO-04 | Key material in error messages | No key exposure |
| CRYPTO-05 | Private key in logs | Key material never logged |
| CRYPTO-06 | HSM bypass attempt | Operations require HSM |

### 5. Denial of Service

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| DOS-01 | Rapid nonce generation | Rate limiting applied |
| DOS-02 | Mass account creation | Rate limiting, max accounts |
| DOS-03 | Large number of pending orders | Order limits enforced |
| DOS-04 | OCSP flood | Rate limiting, caching |
| DOS-05 | Slow loris attack | Connection timeout |
| DOS-06 | Large CSR/certificate requests | Size limits enforced |

### 6. TLS Configuration

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| TLS-01 | SSLv3 connection | Connection refused |
| TLS-02 | TLS 1.0 connection | Connection refused |
| TLS-03 | TLS 1.1 connection | Connection refused |
| TLS-04 | TLS 1.2 connection | Allowed (with strong ciphers) |
| TLS-05 | TLS 1.3 connection | Allowed (preferred) |
| TLS-06 | Weak cipher suite (DES, RC4, export) | Cipher not offered |
| TLS-07 | Certificate chain validation | Proper chain returned |

## Testing Tools

### Recommended Tools

| Tool | Purpose | Usage |
|------|---------|-------|
| **Burp Suite** | HTTP/HTTPS interception and testing | ACME, EST API testing |
| **OWASP ZAP** | Automated security scanning | API endpoint scanning |
| **testssl.sh** | TLS configuration testing | `testssl.sh https://acme.example.com` |
| **openssl** | Certificate and crypto testing | CSR generation, validation |
| **certbot** | ACME client testing | End-to-end ACME workflow |
| **curl** | Manual API testing | Request crafting |
| **ghz** | gRPC load testing | CA gRPC endpoints |
| **step-ca** | EST client testing | EST enrollment testing |

### Custom Test Scripts

```bash
# Test ACME JWS validation
curl -X POST https://acme.example.com/new-account \
  -H "Content-Type: application/jose+json" \
  -d '{"invalid": "payload"}' \
  # Expected: 400 Bad Request

# Test EST without mTLS
curl https://est.example.com/.well-known/est/simpleenroll \
  -X POST -d @csr.pem \
  # Expected: TLS handshake failure

# Test OCSP malformed request
curl https://ocsp.example.com/ \
  -X POST \
  -H "Content-Type: application/ocsp-request" \
  -d "invalid-data" \
  # Expected: 400 Bad Request
```

## Test Execution

### Pre-Test Checklist

- [ ] Test environment isolated from production
- [ ] All services running with production-like configuration
- [ ] HSM/SoftHSM configured for CA operations
- [ ] Database populated with test certificates
- [ ] Monitoring and logging enabled
- [ ] Backup of test environment taken

### Test Phases

1. **Reconnaissance** (1 day)
   - Map all endpoints and parameters
   - Identify authentication mechanisms
   - Document API schemas

2. **Automated Scanning** (1 day)
   - OWASP ZAP active scan
   - testssl.sh TLS analysis
   - cargo audit dependency check

3. **Manual Testing** (3-5 days)
   - Authentication bypass attempts
   - Input validation testing
   - Protocol manipulation
   - Business logic flaws

4. **Exploitation** (1-2 days)
   - Attempt to chain vulnerabilities
   - Privilege escalation testing
   - Data exfiltration attempts

5. **Reporting** (1 day)
   - Document all findings
   - Assign severity ratings
   - Provide remediation guidance

### Severity Ratings

| Severity | Description | SLA |
|----------|-------------|-----|
| **Critical** | CA key compromise, auth bypass, RCE | Fix immediately |
| **High** | Certificate issuance bypass, data exposure | Fix within 7 days |
| **Medium** | Information disclosure, DoS | Fix within 30 days |
| **Low** | Best practice violations | Fix within 90 days |
| **Info** | Observations, hardening suggestions | No SLA |

## Reporting

### Finding Template

```markdown
## Finding: [Title]

**Severity**: Critical / High / Medium / Low / Info
**CVSS Score**: X.X
**CWE**: CWE-XXX

### Description
[Detailed description of the vulnerability]

### Affected Component
- Service: [ACME/EST/OCSP/CA/KRA/SCMS]
- Endpoint: [/path/to/endpoint]
- Parameter: [affected parameter]

### Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

### Evidence
[Screenshots, request/response logs, POC code]

### Impact
[Business impact and potential consequences]

### Remediation
[Specific fix recommendations]

### References
- [Relevant RFC section]
- [OWASP reference]
- [CVE if applicable]
```

### Report Structure

1. Executive Summary
2. Scope and Methodology
3. Risk Summary (by severity)
4. Detailed Findings
5. Remediation Roadmap
6. Appendices (raw scan results, test logs)

## Compliance Evidence

### NIST 800-53 Mapping

| Control | Requirement | Evidence |
|---------|-------------|----------|
| CA-2 | Security assessments | Penetration test report |
| CA-8 | Penetration testing | Test execution logs, findings |
| SA-11 | Developer security testing | Integration with CI/CD |

### ATO Artifacts

- [ ] Penetration test report (PDF)
- [ ] Remediation tracking document
- [ ] Re-test verification report
- [ ] Risk acceptance for residual findings

## Schedule

| Activity | Duration | Dependencies |
|----------|----------|--------------|
| Test planning | 2 days | - |
| Environment setup | 1 day | Test planning |
| Automated scanning | 1 day | Environment setup |
| Manual testing | 5 days | Environment setup |
| Report writing | 2 days | Manual testing |
| Remediation | 5-10 days | Report |
| Re-testing | 2 days | Remediation |
| Final report | 1 day | Re-testing |

**Total Duration**: 2-3 weeks

## Contact

- **Security Team**: security@example.com
- **PKI Admin**: pkiadmin@example.com
- **Penetration Testing Vendor**: [TBD]
