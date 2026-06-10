#!/bin/sh
# One-shot CA bootstrap for the OstrichPKI dev environment.
#
# 1. Initializes a SoftHSM token (idempotent - skipped if it exists)
# 2. Runs ostrich-init to generate the CA key on the token, self-sign the
#    root certificate, and register both in the database (idempotent via
#    --if-exists-ok)
#
# COMPLIANCE MAPPING:
# - NIST 800-53: CM-2 - convergent baseline configuration (safe to re-run)
# - NIAP PP-CA: FCS_CKM.1 / FCS_STG_EXT.1 - HSM-backed CA key generation
set -eu

TOKEN_LABEL="${SOFTHSM_TOKEN_LABEL:-ostrich-dev}"
PIN="${PKCS11_PIN:?PKCS11_PIN must be set}"
SO_PIN="${PKCS11_SO_PIN:-$PIN}"
MODULE="${PKCS11_MODULE_PATH:?PKCS11_MODULE_PATH must be set}"
KEY_LABEL="${CA_KEY_LABEL:-ostrich-root-ca}"

# Initialize the token once. SoftHSM assigns a random slot id at init time,
# so the slot is discovered (not assumed) below.
if ! softhsm2-util --show-slots | grep -q "Label:[[:space:]]*${TOKEN_LABEL}\$"; then
    echo "Initializing SoftHSM token '${TOKEN_LABEL}'"
    softhsm2-util --init-token --free --label "${TOKEN_LABEL}" \
        --pin "${PIN}" --so-pin "${SO_PIN}"
else
    echo "SoftHSM token '${TOKEN_LABEL}' already initialized"
fi

# Discover the slot id that carries our token label
SLOT="$(softhsm2-util --show-slots | awk -v label="${TOKEN_LABEL}" '
    /^Slot / { slot = $2 }
    $1 == "Label:" && $2 == label { print slot; exit }
')"
if [ -z "${SLOT}" ]; then
    echo "ERROR: could not find SoftHSM slot for token '${TOKEN_LABEL}'" >&2
    exit 1
fi
echo "Using SoftHSM slot ${SLOT}"

# Generate + register the root CA (no-op if the key label already exists).
# ostrich-init records the slot id on the ca_keys row; ca-server reads the
# slot from there, so the random SoftHSM slot id is handled automatically.
exec ostrich-init \
    --key-label "${KEY_LABEL}" \
    --pkcs11-module "${MODULE}" \
    --pkcs11-slot "${SLOT}" \
    --pkcs11-pin "${PIN}" \
    --if-exists-ok
