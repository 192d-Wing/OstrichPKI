# PKCS#11 Integration Tests

This directory contains integration tests for the PKCS#11 HSM provider using SoftHSM.

## Overview

The integration tests validate the PKCS#11 provider implementation against a real PKCS#11 cryptographic token (SoftHSM). These tests ensure that the OstrichPKI cryptographic operations work correctly with FIPS 140-3 compliant hardware security modules.

## Prerequisites

### Install SoftHSM

**macOS:**
```bash
brew install softhsm
```

**Ubuntu/Debian:**
```bash
sudo apt-get install softhsm2
```

**RHEL/CentOS/Fedora:**
```bash
sudo yum install softhsm    # RHEL/CentOS
sudo dnf install softhsm    # Fedora
```

## Setup

### Automated Setup (Recommended)

Run the setup script to automatically configure SoftHSM:

```bash
./tests/setup_softhsm.sh
```

This script will:
- Detect your operating system
- Locate the SoftHSM library
- Create SoftHSM configuration file
- Initialize a test token named "OstrichPKI-Test"
- Display environment variables to set

After running the script, add the environment variables to your shell profile:

```bash
# Add to ~/.bashrc, ~/.zshrc, or similar
export PKCS11_MODULE_PATH=/usr/local/lib/softhsm/libsofthsm2.so  # Path from script
export SOFTHSM2_CONF=$HOME/.config/softhsm2/softhsm2.conf
```

### Manual Setup

If you prefer manual setup:

1. **Create SoftHSM configuration directory:**
   ```bash
   mkdir -p ~/.config/softhsm2/tokens
   ```

2. **Create SoftHSM configuration file** (`~/.config/softhsm2/softhsm2.conf`):
   ```
   directories.tokendir = /Users/youruser/.config/softhsm2/tokens
   objectstore.backend = file
   log.level = INFO
   slots.removable = false
   ```

3. **Set environment variable:**
   ```bash
   export SOFTHSM2_CONF=$HOME/.config/softhsm2/softhsm2.conf
   ```

4. **Initialize test token:**
   ```bash
   softhsm2-util --init-token --slot 0 --label "OstrichPKI-Test" \
     --so-pin 12345678 --pin 1234
   ```

5. **Set PKCS11_MODULE_PATH:**
   ```bash
   # macOS (Homebrew Intel)
   export PKCS11_MODULE_PATH=/usr/local/lib/softhsm/libsofthsm2.so

   # macOS (Homebrew Apple Silicon)
   export PKCS11_MODULE_PATH=/opt/homebrew/lib/softhsm/libsofthsm2.so

   # Linux (Ubuntu/Debian)
   export PKCS11_MODULE_PATH=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so

   # Linux (RHEL/CentOS)
   export PKCS11_MODULE_PATH=/usr/lib64/pkcs11/libsofthsm2.so
   ```

## Running Tests

### Run All Tests

```bash
cargo test --test pkcs11_integration_test -- --test-threads=1
```

**Important:** Tests must run with `--test-threads=1` to prevent PKCS#11 session conflicts when multiple tests access the HSM simultaneously.

### Run Specific Test

```bash
cargo test --test pkcs11_integration_test test_rsa2048_key_generation -- --test-threads=1
```

### Run with Verbose Output

```bash
cargo test --test pkcs11_integration_test -- --test-threads=1 --nocapture
```

## Test Coverage

The integration test suite covers:

### Key Generation (FIPS 186-5)
- ✓ RSA-2048 key pair generation
- ✓ RSA-3072 key pair generation
- ✓ RSA-4096 key pair generation
- ✓ ECDSA P-256 key pair generation
- ✓ ECDSA P-384 key pair generation
- ✓ ECDSA P-521 key pair generation

### Digital Signatures (FIPS 186-5)
- ✓ RSA-PSS with SHA-256 signing and verification
- ✓ RSA PKCS#1 v1.5 with SHA-256/384/512 signing and verification
- ✓ ECDSA P-256 with SHA-256 signing and verification
- ✓ ECDSA P-384 with SHA-384 signing and verification
- ✓ ECDSA P-521 with SHA-512 signing and verification
- ✓ Signature verification failure with tampered data
- ✓ Non-deterministic RSA-PSS signatures (random salt)

### Public Key Export
- ✓ RSA public key export in DER format
- ✓ EC public key export in DER format
- ✓ Private keys remain non-exportable (NIST 800-53: SC-12)

### Key Wrapping (NIST SP 800-38F)
- ⚠️ Key wrapping with AES-KW (requires KEK generation)
- ⚠️ Key unwrapping and recovery (requires KEK generation)

### Concurrency and Thread Safety
- ✓ Multiple concurrent key generation operations
- ✓ Multiple keys coexisting in same HSM slot
- ✓ Thread-safe session management

### Error Handling
- ✓ Signature verification with wrong algorithm fails gracefully
- ✓ Algorithm mismatch detection (RSA key with ECDSA algorithm)

## Compliance Validation

These tests validate compliance with:

- **NIST 800-53 Rev 5:**
  - SC-12: Cryptographic key establishment and management
  - SC-13: Cryptographic protection using FIPS-approved algorithms
  - IA-7: Cryptographic module authentication
  - AU-3: Audit content (security-relevant events)
  - CA-8: Penetration testing (cryptographic module validation)

- **FIPS 186-5:** Digital Signature Standard
  - RSA signature generation and verification
  - ECDSA signature generation and verification

- **FIPS 140-3:** Cryptographic Module Validation
  - Through SoftHSM or real HSM in production

- **NIAP PP-CA v2.1:** Protection Profile for Certificate Authority
  - FCS_CKM.4: Cryptographic key destruction (key escrow)

## Troubleshooting

### "SoftHSM library not found"

Ensure PKCS11_MODULE_PATH is set correctly:
```bash
# Find SoftHSM library
find /usr -name "libsofthsm2.so" 2>/dev/null

# Set environment variable
export PKCS11_MODULE_PATH=/path/to/libsofthsm2.so
```

### "Token not found" or "Slot not found"

Verify token is initialized:
```bash
softhsm2-util --show-slots
```

You should see:
```
Slot 0
    Slot info:
        Description:      SoftHSM slot 0
        Token present:    yes
    Token info:
        Label:            OstrichPKI-Test
        ...
```

If not, run the setup script again.

### "CKR_PIN_INCORRECT"

The test uses PIN `1234`. If you initialized the token with a different PIN, either:
1. Re-initialize the token with PIN `1234`
2. Modify the `init_test_provider()` function in the test file

### Tests hang or timeout

This usually indicates a session leak. Ensure you're running with `--test-threads=1`.

### "CKR_SESSION_COUNT" or "CKR_SESSION_EXISTS"

Too many open sessions. Restart SoftHSM:
```bash
# Delete and reinitialize token
softhsm2-util --delete-token --token "OstrichPKI-Test"
./tests/setup_softhsm.sh
```

## Using Real HSM

To test with a real FIPS 140-3 validated HSM instead of SoftHSM:

1. Install HSM vendor's PKCS#11 library
2. Initialize HSM token with appropriate SO-PIN and user PIN
3. Set PKCS11_MODULE_PATH to vendor library:
   ```bash
   export PKCS11_MODULE_PATH=/path/to/vendor/pkcs11.so
   ```
4. Update `init_test_provider()` in test file with correct slot ID and PIN
5. Run tests

Example HSM vendors:
- **Thales Luna HSM:** `/usr/lib/libCryptoki2.so`
- **Utimaco CryptoServer:** `/opt/utimaco/lib/libcs_pkcs11.so`
- **YubiHSM 2:** `/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so`
- **AWS CloudHSM:** `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so`

## Continuous Integration

For CI/CD pipelines, add SoftHSM setup to your workflow:

### GitHub Actions
```yaml
- name: Install SoftHSM
  run: |
    sudo apt-get update
    sudo apt-get install -y softhsm2

- name: Setup SoftHSM
  run: |
    ./crates/ostrich-crypto/tests/setup_softhsm.sh
    echo "PKCS11_MODULE_PATH=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so" >> $GITHUB_ENV

- name: Run PKCS#11 Tests
  run: cargo test --test pkcs11_integration_test -- --test-threads=1
```

### GitLab CI
```yaml
test:pkcs11:
  before_script:
    - apt-get update && apt-get install -y softhsm2
    - ./crates/ostrich-crypto/tests/setup_softhsm.sh
    - export PKCS11_MODULE_PATH=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
  script:
    - cargo test --test pkcs11_integration_test -- --test-threads=1
```

## Security Considerations

- **Test PINs:** The test token uses weak PINs (`1234`). Never use these in production.
- **Test Keys:** All keys generated during tests are for testing only and have no cryptographic strength guarantees.
- **Token Isolation:** Tests should run in isolated environments (containers, VMs) to prevent cross-contamination with production keys.
- **Key Cleanup:** Tests generate many keys in the HSM. Periodically reinitialize the test token to clean up:
  ```bash
  ./tests/setup_softhsm.sh
  ```

## References

- [SoftHSM Project](https://www.opendnssec.org/softhsm/)
- [PKCS#11 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
- [NIST FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final)
- [NIST FIPS 186-5 (DSS)](https://csrc.nist.gov/publications/detail/fips/186/5/final)
- [NIST SP 800-38F (Key Wrap)](https://csrc.nist.gov/publications/detail/sp/800-38f/final)
