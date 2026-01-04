# OstrichPKI User Guide

**Document Version:** 1.0
**Last Updated:** January 2026
**NIAP Reference:** AGD_USR.1 - User Operational Guidance
**Audience:** Certificate Subscribers, Application Developers, DevOps Engineers

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Getting Certificates via ACME](#2-getting-certificates-via-acme)
3. [Getting Certificates via EST](#3-getting-certificates-via-est)
4. [Certificate Lifecycle](#4-certificate-lifecycle)
5. [Checking Certificate Status](#5-checking-certificate-status)
6. [Troubleshooting](#6-troubleshooting)
7. [Security Best Practices](#7-security-best-practices)

---

## 1. Introduction

### 1.1 Purpose

This guide provides operational instructions for end-users (certificate subscribers) who need to obtain, use, and manage certificates from OstrichPKI. It covers the automated ACME protocol and the enterprise EST protocol.

### 1.2 What is OstrichPKI?

OstrichPKI is a Certificate Authority (CA) that issues X.509 digital certificates. These certificates are used to:

- Secure websites with HTTPS (TLS/SSL certificates)
- Authenticate servers and clients
- Sign code and software packages
- Encrypt email communications

### 1.3 Certificate Types Available

| Certificate Type | Use Case | Validity |
|-----------------|----------|----------|
| TLS Server | Web server HTTPS | Up to 398 days |
| TLS Client | Client authentication | Up to 398 days |
| Code Signing | Software signing | Up to 39 months |
| Email (S/MIME) | Email encryption | Up to 398 days |

### 1.4 Prerequisites

Before requesting a certificate, you need:

- A valid domain name (for TLS certificates)
- Control of the domain (proven via ACME challenges)
- A Certificate Signing Request (CSR) or the ability to generate one

---

## 2. Getting Certificates via ACME

### 2.1 What is ACME?

ACME (Automatic Certificate Management Environment) is a protocol that automates certificate issuance. It's the same protocol used by Let's Encrypt.

### 2.2 Supported ACME Clients

| Client | Platform | Installation |
|--------|----------|-------------|
| certbot | Linux/macOS/Windows | `apt install certbot` or `brew install certbot` |
| acme.sh | Unix/Linux | `curl https://get.acme.sh \| sh` |
| Caddy | Any | Built-in ACME client |
| Traefik | Any | Built-in ACME client |
| win-acme | Windows | Download from GitHub |

### 2.3 Configuring Your ACME Client

Configure your client to use the OstrichPKI ACME server:

```bash
# ACME Directory URL
https://acme.example.com/directory

# For certbot
certbot certonly \
  --server https://acme.example.com/directory \
  --agree-tos \
  --email your-email@example.com \
  -d your-domain.com

# For acme.sh
acme.sh --issue \
  --server https://acme.example.com/directory \
  -d your-domain.com \
  --webroot /var/www/html
```

### 2.4 Challenge Types

ACME verifies domain ownership using challenges:

| Challenge | Method | Port Required |
|-----------|--------|---------------|
| HTTP-01 | Place file on web server | 80 |
| DNS-01 | Add DNS TXT record | None |
| TLS-ALPN-01 | TLS extension | 443 |

**Recommended:** Use DNS-01 for wildcard certificates or when port 80 is not available.

### 2.5 Requesting a Certificate

#### Using Certbot (HTTP-01)

```bash
# Standalone mode (certbot runs its own web server)
sudo certbot certonly \
  --standalone \
  --server https://acme.example.com/directory \
  -d example.com -d www.example.com

# Webroot mode (use existing web server)
sudo certbot certonly \
  --webroot \
  --webroot-path /var/www/html \
  --server https://acme.example.com/directory \
  -d example.com
```

#### Using Certbot (DNS-01 for Wildcards)

```bash
sudo certbot certonly \
  --manual \
  --preferred-challenges dns \
  --server https://acme.example.com/directory \
  -d "*.example.com" -d example.com
```

#### Using acme.sh

```bash
# HTTP mode
acme.sh --issue \
  --server https://acme.example.com/directory \
  -d example.com \
  -w /var/www/html

# DNS mode with Cloudflare
export CF_Token="your-cloudflare-api-token"
acme.sh --issue \
  --server https://acme.example.com/directory \
  --dns dns_cf \
  -d "*.example.com"
```

### 2.6 Certificate Files

After successful issuance, you'll receive:

| File | Description | Usage |
|------|-------------|-------|
| `cert.pem` | Your certificate | Configure in web server |
| `privkey.pem` | Private key | Keep secure! |
| `chain.pem` | Intermediate CA certificate | May be needed by some servers |
| `fullchain.pem` | Certificate + chain | Most common configuration |

### 2.7 Automatic Renewal

Set up automatic renewal to avoid certificate expiration:

```bash
# Certbot automatic renewal (usually set up automatically)
sudo certbot renew --dry-run

# Add to crontab for regular renewal checks
0 0,12 * * * certbot renew --quiet

# acme.sh (installed automatically)
acme.sh --install-cronjob
```

---

## 3. Getting Certificates via EST

### 3.1 What is EST?

EST (Enrollment over Secure Transport) is an enterprise protocol for certificate enrollment, typically used in controlled environments with client certificates.

### 3.2 Prerequisites for EST

- A client certificate for mTLS authentication
- Access to the EST server endpoint
- A CSR (Certificate Signing Request)

### 3.3 EST Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/.well-known/est/cacerts` | Get CA certificates |
| `/.well-known/est/simpleenroll` | Enroll new certificate |
| `/.well-known/est/simplereenroll` | Renew certificate |
| `/.well-known/est/serverkeygen` | Server-side key generation |

### 3.4 Using curl for EST

```bash
# Get CA certificates
curl https://est.example.com/.well-known/est/cacerts \
  --cert client.crt --key client.key \
  -o cacerts.p7

# Generate a CSR
openssl req -new -newkey rsa:2048 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=server.example.com"

# Enroll certificate
curl https://est.example.com/.well-known/est/simpleenroll \
  --cert client.crt --key client.key \
  --data-binary @server.csr \
  -H "Content-Type: application/pkcs10" \
  -o server.p7

# Convert PKCS#7 to PEM
openssl pkcs7 -in server.p7 -print_certs -out server.crt
```

### 3.5 Using libest (C Library)

```c
#include <est.h>

// Initialize EST client
EST_CTX *ctx = est_client_init(
    ca_chain, ca_chain_len,
    EST_CERT_FORMAT_PEM,
    NULL);

// Set server address
est_client_set_server(ctx, "est.example.com", 443, NULL);

// Set authentication
est_client_set_auth(ctx, "user", "password", client_cert, client_key);

// Enroll
int rv = est_client_enroll(ctx, "CN=myserver", &pkcs7_len, &pkcs7);
```

---

## 4. Certificate Lifecycle

### 4.1 Certificate Validity

| Certificate Type | Maximum Validity | Recommended Renewal |
|-----------------|------------------|---------------------|
| TLS Server | 398 days | 30 days before expiry |
| TLS Client | 398 days | 30 days before expiry |
| Code Signing | 39 months | 60 days before expiry |

### 4.2 Renewing Certificates

**ACME Renewal:**

```bash
# Check certificate expiration
certbot certificates

# Renew if needed
certbot renew

# Force renewal (even if not expiring)
certbot renew --force-renewal
```

**EST Renewal:**

```bash
curl https://est.example.com/.well-known/est/simplereenroll \
  --cert current.crt --key current.key \
  --data-binary @new.csr \
  -H "Content-Type: application/pkcs10" \
  -o renewed.p7
```

### 4.3 Revoking Certificates

If your private key is compromised, revoke the certificate immediately:

**ACME Revocation:**

```bash
certbot revoke --cert-path /etc/letsencrypt/live/example.com/cert.pem
```

**Contact Administrator:**

If you cannot revoke via ACME, contact your CA administrator with:
- Certificate serial number
- Reason for revocation
- Proof of ownership

### 4.4 Key Compromise Procedures

If you suspect your private key is compromised:

1. **Revoke immediately** using the methods above
2. **Generate new key pair** - never reuse the compromised key
3. **Request new certificate** with the new key
4. **Update all systems** using the certificate
5. **Investigate** how the compromise occurred
6. **Report** to your security team

---

## 5. Checking Certificate Status

### 5.1 Using OCSP

Check if a certificate is revoked using OCSP:

```bash
# Extract OCSP responder URL from certificate
openssl x509 -in cert.pem -noout -ocsp_uri

# Query OCSP responder
openssl ocsp \
  -issuer chain.pem \
  -cert cert.pem \
  -url https://ocsp.example.com \
  -resp_text
```

### 5.2 Using CRL

Download and check the Certificate Revocation List:

```bash
# Download CRL
curl -O https://ca.example.com/crl/ca.crl

# View CRL contents
openssl crl -in ca.crl -text -noout

# Check if specific serial is revoked
openssl crl -in ca.crl -text | grep <serial_number>
```

### 5.3 Verifying Certificate Chain

```bash
# Verify certificate chain
openssl verify -CAfile ca-chain.pem cert.pem

# Verify with OCSP checking
openssl verify -CAfile ca-chain.pem -crl_check cert.pem
```

---

## 6. Troubleshooting

### 6.1 ACME Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `unauthorized` | Domain validation failed | Check DNS, ensure port 80/443 accessible |
| `badCSR` | Invalid CSR format | Regenerate CSR with correct format |
| `rateLimited` | Too many requests | Wait and retry (see rate limits) |
| `serverInternal` | CA server error | Contact administrator |
| `connection refused` | Network issue | Check firewall, DNS resolution |

**HTTP-01 Challenge Failures:**

```bash
# Verify challenge file is accessible
curl http://your-domain.com/.well-known/acme-challenge/test

# Check for redirects (must be HTTP, not HTTPS)
curl -I http://your-domain.com/.well-known/acme-challenge/test
```

**DNS-01 Challenge Failures:**

```bash
# Verify TXT record
dig TXT _acme-challenge.your-domain.com

# Check propagation (allow 5-10 minutes)
dig @8.8.8.8 TXT _acme-challenge.your-domain.com
```

### 6.2 EST Errors

| HTTP Status | Meaning | Solution |
|-------------|---------|----------|
| 401 | Authentication failed | Check client certificate |
| 400 | Bad CSR | Verify CSR format (PKCS#10) |
| 403 | Not authorized | Contact administrator |
| 500 | Server error | Contact administrator |

### 6.3 Certificate Verification Failures

| Error | Cause | Solution |
|-------|-------|----------|
| `certificate has expired` | Validity period passed | Renew certificate |
| `unable to get local issuer certificate` | Missing CA chain | Install CA certificates |
| `certificate revoked` | Certificate was revoked | Request new certificate |
| `hostname mismatch` | Wrong domain in cert | Request cert with correct SAN |

### 6.4 Getting Help

1. Check the FAQ at https://docs.ostrich-pki.io/faq
2. Search issues at https://github.com/ostrich-pki/issues
3. Contact your IT administrator for enterprise support

---

## 7. Security Best Practices

### 7.1 Private Key Security

- **Never share** your private key with anyone
- **Store securely** with proper file permissions (`chmod 600`)
- **Use hardware security** (HSM, TPM, Yubikey) for high-value keys
- **Rotate regularly** even if not compromised
- **Delete old keys** securely after rotation

```bash
# Secure private key permissions
chmod 600 privkey.pem
chown root:root privkey.pem
```

### 7.2 Certificate Monitoring

- **Monitor expiration** dates proactively
- **Set up alerts** at 30, 14, and 7 days before expiry
- **Test renewal** process before it's needed
- **Keep inventory** of all certificates

### 7.3 CSR Best Practices

- **Use strong keys**: RSA 2048+ or ECDSA P-256+
- **Include all SANs**: List all domains/hostnames
- **Avoid wildcards** unless necessary
- **Don't reuse keys**: Generate new key for each certificate

```bash
# Generate secure CSR
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -nodes -keyout server.key -out server.csr \
  -subj "/CN=server.example.com/O=Example Corp/C=US" \
  -addext "subjectAltName=DNS:server.example.com,DNS:www.example.com"
```

### 7.4 TLS Configuration

Configure your web server with modern TLS settings:

```nginx
# Nginx example
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_stapling on;
ssl_stapling_verify on;
```

### 7.5 Regular Audits

- Review certificate inventory quarterly
- Verify certificate purposes match usage
- Check for weak algorithms (SHA-1, RSA-1024)
- Ensure proper chain configuration

---

## Appendix A: Certificate Formats

| Format | Extension | Description |
|--------|-----------|-------------|
| PEM | `.pem`, `.crt` | Base64 encoded, human readable |
| DER | `.der`, `.cer` | Binary format |
| PKCS#7 | `.p7b`, `.p7c` | Certificate chain format |
| PKCS#12 | `.p12`, `.pfx` | Certificate + private key bundle |

**Converting Formats:**

```bash
# PEM to DER
openssl x509 -in cert.pem -outform DER -out cert.der

# DER to PEM
openssl x509 -in cert.der -inform DER -out cert.pem

# PEM to PKCS#12
openssl pkcs12 -export -out cert.p12 -inkey key.pem -in cert.pem -certfile chain.pem
```

---

## Appendix B: Rate Limits

To protect the CA infrastructure, rate limits apply:

| Limit | Value | Window |
|-------|-------|--------|
| Certificates per domain | 50 | 7 days |
| Failed validations | 5 | 1 hour |
| Pending orders | 300 | Total |
| New accounts | 10 | 3 hours |

If rate limited, wait for the window to expire or contact your administrator for an exception.

---

**Document History:**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | January 2026 | OstrichPKI Team | Initial user guide |
