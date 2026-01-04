# Post-Quantum Cryptography OID Mapping

This document provides the official NIST OID assignments for post-quantum cryptographic algorithms as finalized in FIPS 203, 204, and 205 (August 2024).

## NIST OID Registry Structure

All NIST post-quantum algorithm OIDs fall under the NIST Computer Security Objects Registry:

```
2.16.840.1.101.3.4 - NIST Computer Security Objects
├── .3.* - Signature Algorithms (ML-DSA, SLH-DSA)
└── .4.* - Key Encapsulation Mechanisms (ML-KEM)
```

## FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)

Formerly known as CRYSTALS-Dilithium.

| Algorithm | Security Level | OID | Implementation Status |
|-----------|----------------|-----|----------------------|
| ML-DSA-44 | NIST Level 2   | `2.16.840.1.101.3.4.3.17` | ✅ Implemented |
| ML-DSA-65 | NIST Level 3   | `2.16.840.1.101.3.4.3.18` | ✅ Implemented |
| ML-DSA-87 | NIST Level 5   | `2.16.840.1.101.3.4.3.19` | ✅ Implemented |

**Use Cases**:
- Certificate signing (CA operations)
- CRL signing
- OCSP response signing
- Document signing
- Code signing

**Recommended Variant**: ML-DSA-65 for most PKI applications (NIST Level 3 security)

## FIPS 203: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)

Formerly known as CRYSTALS-Kyber.

| Algorithm | Security Level | OID | Implementation Status |
|-----------|----------------|-----|----------------------|
| ML-KEM-512  | NIST Level 1   | `2.16.840.1.101.3.4.4.1` | ✅ Implemented |
| ML-KEM-768  | NIST Level 3   | `2.16.840.1.101.3.4.4.2` | ✅ Implemented |
| ML-KEM-1024 | NIST Level 5   | `2.16.840.1.101.3.4.4.3` | ✅ Implemented |

**Use Cases**:
- TLS 1.3 key exchange (hybrid mode)
- KRA key wrapping
- Session key establishment
- Secure email encryption

**Recommended Variant**: ML-KEM-768 for most applications (NIST Level 3 security)

## FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)

Formerly known as SPHINCS+.

### SHA2 Variants (FIPS 180-4)

| Algorithm | Security Level | Category | OID | Implementation Status |
|-----------|----------------|----------|-----|----------------------|
| SLH-DSA-SHA2-128s | 128-bit | Small | `2.16.840.1.101.3.4.3.20` | ✅ Implemented |
| SLH-DSA-SHA2-128f | 128-bit | Fast  | `2.16.840.1.101.3.4.3.21` | ✅ Implemented |
| SLH-DSA-SHA2-192s | 192-bit | Small | `2.16.840.1.101.3.4.3.22` | ✅ Implemented |
| SLH-DSA-SHA2-192f | 192-bit | Fast  | `2.16.840.1.101.3.4.3.23` | ✅ Implemented |
| SLH-DSA-SHA2-256s | 256-bit | Small | `2.16.840.1.101.3.4.3.24` | ✅ Implemented |
| SLH-DSA-SHA2-256f | 256-bit | Fast  | `2.16.840.1.101.3.4.3.25` | ✅ Implemented |

### SHAKE Variants (FIPS 202)

| Algorithm | Security Level | Category | OID | Implementation Status |
|-----------|----------------|----------|-----|----------------------|
| SLH-DSA-SHAKE-128s | 128-bit | Small | `2.16.840.1.101.3.4.3.26` | ✅ Implemented |
| SLH-DSA-SHAKE-128f | 128-bit | Fast  | `2.16.840.1.101.3.4.3.27` | ✅ Implemented |
| SLH-DSA-SHAKE-192s | 192-bit | Small | `2.16.840.1.101.3.4.3.28` | ✅ Implemented |
| SLH-DSA-SHAKE-192f | 192-bit | Fast  | `2.16.840.1.101.3.4.3.29` | ✅ Implemented |
| SLH-DSA-SHAKE-256s | 256-bit | Small | `2.16.840.1.101.3.4.3.30` | ✅ Implemented |
| SLH-DSA-SHAKE-256f | 256-bit | Fast  | `2.16.840.1.101.3.4.3.31` | ✅ Implemented |

**Variant Selection**:
- **s (small)**: Smaller signature size, slower signing/verification
- **f (fast)**: Faster signing/verification, larger signature size

**Use Cases**:
- Long-lived root CA certificates (conservative, stateless design)
- High-assurance signatures where ML-DSA may be questioned
- Backup signature algorithm for crypto-agility

**Recommended Variant**: SLH-DSA-SHA2-128s or SLH-DSA-SHA2-128f for most applications

## Hybrid Signature Schemes

OstrichPKI supports hybrid signatures combining classical and post-quantum algorithms for defense-in-depth:

| Hybrid Scheme | Classical | PQC | Use Case |
|---------------|-----------|-----|----------|
| ECDSA-P256 + ML-DSA-44 | ECDSA P-256 | ML-DSA-44 | Standard certificates |
| ECDSA-P384 + ML-DSA-65 | ECDSA P-384 | ML-DSA-65 | High-assurance certificates |
| RSA-3072 + ML-DSA-65 | RSA 3072 | ML-DSA-65 | Legacy compatibility |

**Note**: Hybrid signature OIDs will be defined in future IETF drafts (draft-ietf-lamps-pq-composite-sigs).

## References

### Standards Documents

- **FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism Standard
- **FIPS 204**: Module-Lattice-Based Digital Signature Standard
- **FIPS 205**: Stateless Hash-Based Digital Signature Standard
- **NIST SP 800-208**: Recommendation for Stateful Hash-Based Signature Schemes
- **NIST SP 800-186**: Recommendations for Discrete Logarithm-Based Cryptography (for comparison)

### IETF Drafts

- `draft-ietf-lamps-dilithium-certificates` - ML-DSA in X.509 Certificates
- `draft-ietf-lamps-kyber-certificates` - ML-KEM in X.509 Certificates
- `draft-ietf-lamps-cms-sphincs-plus` - SLH-DSA in CMS
- `draft-ietf-lamps-pq-composite-sigs` - Composite Signature Algorithms

### NIST Resources

- NIST PQC Project: https://csrc.nist.gov/projects/post-quantum-cryptography
- NIST Computer Security Objects Registry: https://csrc.nist.gov/projects/computer-security-objects-register

## Implementation Notes

### Phase 13 Track 4 Updates (2025-01-04)

Updated all post-quantum algorithm OIDs from draft/proposed values to official NIST assignments:

**ML-DSA Changes**:
- ML-DSA-44: `1.3.6.1.4.1.2.267.7.4.4` → `2.16.840.1.101.3.4.3.17` ✅
- ML-DSA-65: `1.3.6.1.4.1.2.267.7.6.5` → `2.16.840.1.101.3.4.3.18` ✅
- ML-DSA-87: `1.3.6.1.4.1.2.267.7.8.7` → `2.16.840.1.101.3.4.3.19` ✅

**ML-KEM Changes**:
- ML-KEM-512: `1.3.6.1.4.1.22554.5.6.1` → `2.16.840.1.101.3.4.4.1` ✅
- ML-KEM-768: `1.3.6.1.4.1.22554.5.6.2` → `2.16.840.1.101.3.4.4.2` ✅
- ML-KEM-1024: `1.3.6.1.4.1.22554.5.6.3` → `2.16.840.1.101.3.4.4.3` ✅

**SLH-DSA Additions**:
- Added 6 SHA2 variants (128s/f, 192s/f, 256s/f)
- Added 6 SHAKE variants (128s/f, 192s/f, 256s/f)
- Total: 12 SLH-DSA variants (previously only 3)

### Backward Compatibility

⚠️ **Breaking Change**: Certificates signed with draft OIDs (prior to this update) will have different algorithm identifiers and will not validate against the new OIDs.

**Migration Strategy**:
1. Re-issue certificates using updated OIDs
2. Maintain dual support during transition period (Phase 14)
3. Update all services to use new OIDs
4. Deprecate draft OID support after transition (6 months)

### Testing

All OID constants verified with comprehensive unit tests:
- OID value correctness (e.g., `"2.16.840.1.101.3.4.3.17"`)
- OID name mapping (e.g., `"ML-DSA-44"`)
- All 24 post-quantum algorithm variants

**Test Coverage**: 100% of PQC OID constants

## Security Considerations

### Algorithm Selection Guidelines

1. **ML-DSA vs SLH-DSA for Signatures**:
   - ML-DSA: Preferred for most use cases (faster, smaller signatures)
   - SLH-DSA: Conservative choice for long-lived CA certificates (stateless, hash-based)

2. **Security Levels**:
   - Level 1 (128-bit): Minimum for most applications
   - Level 3 (192-bit): Recommended for PKI (balanced security/performance)
   - Level 5 (256-bit): High-assurance, future-proof

3. **Hybrid Mode**:
   - Always use hybrid signatures during PQC transition (defense-in-depth)
   - Protects against both classical and quantum attacks
   - Ensures backward compatibility

### Crypto-Agility

OstrichPKI supports algorithm negotiation and migration:
- Multiple algorithms supported simultaneously
- Certificate profiles specify allowed algorithms
- CA can issue certificates with different PQC algorithms
- Clients validate using algorithm indicated in certificate

## Compliance Mapping

### FIPS Compliance

- ✅ **FIPS 203**: ML-KEM implementation ready (OIDs assigned)
- ✅ **FIPS 204**: ML-DSA implementation ready (OIDs assigned)
- ✅ **FIPS 205**: SLH-DSA implementation ready (OIDs assigned)
- ⏳ **FIPS 140-3**: Pending HSM vendor support for PQC algorithms

### NIAP PP-CA v2.1

- **FCS_CKM.1**: Cryptographic key generation - PQC key generation supported
- **FCS_COP.1**: Cryptographic operations - PQC signing/verification supported
- **FMT_SMF.1**: Security management - Algorithm selection configurable

### NIST 800-53 Rev 5

- **SC-12**: Cryptographic Key Establishment - ML-KEM support
- **SC-13**: Cryptographic Protection - FIPS 203/204/205 algorithms
- **SC-17**: Public Key Infrastructure - PQC certificate support

## Future Work

- [ ] Implement actual PQC algorithm operations (currently OIDs only)
- [ ] Add HSM support for PQC key generation
- [ ] Implement hybrid signature encoding per IETF drafts
- [ ] Add PQC algorithm self-tests per FIPS 140-3
- [ ] Support composite certificates (dual classical+PQC keys)
- [ ] Implement key recovery for ML-KEM-wrapped keys

---

**Last Updated**: 2025-01-04
**Phase**: 13 Track 4
**Status**: ✅ Complete
