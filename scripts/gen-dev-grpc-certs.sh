#!/usr/bin/env bash
#
# OstrichPKI - DEV ONLY CA gRPC mTLS certificate generator
#
# Creates a throwaway PKI for the ca-server gRPC listener and its gRPC clients
# so that `docker compose up` (and the env-gated live integration tests) run the
# CA gRPC channel over TLS 1.3 mutual authentication, exactly like production.
# There is no plaintext fallback in release builds (CA_GRPC_INSECURE_DEV_PLAINTEXT
# is refused), so every compose stack needs these files.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SC-8 (Transmission Confidentiality), AC-17 (mTLS between services)
# - NIST 800-53: IA-3 / IA-5(2) (PKI-based service authentication), SC-12 (key handling)
# - NIST 800-53: CM-6 (no keys committed: output is gitignored, generated locally)
# - NIAP PP-CA: FTP_ITC.1 (inter-TSF trusted channel), FIA_X509_EXT.1
# - FIPS 186-5: ECDSA P-384 keys, SHA-384 signatures
# - RFC 5280 §4.2.1.9 basicConstraints, §4.2.1.3 keyUsage, §4.2.1.12 extKeyUsage,
#   §4.2.1.6 subjectAltName
#
# Output (default: <repo>/.dev-grpc-certs, override with the first positional
# arg). The default is deliberately OUTSIDE ./certs: docker-compose.yml mounts
# ./certs wholesale into ca, est and ocsp, so material under ./certs would be
# readable by every one of them (AC-6, SC-12). Keep it out of ./certs.
#   ca.crt                         dev gRPC CA (client-CA for the server, trust
#                                  anchor for the clients); valid one day
#                                  longer than the leaves so no leaf outlives it
#   ca-service.crt / .key          server, CN=ca-service, EKU serverAuth,
#                                  SAN DNS:ca-service,DNS:ca,DNS:localhost,IP:127.0.0.1
#   acme-server.crt / .key         client, CN=acme-server, EKU clientAuth
#   est-server.crt / .key          client, CN=est-server, EKU clientAuth
#   integration-tests.crt / .key   client, CN=integration-tests, EKU clientAuth
#                                  (ACME namespace in the dev/test compose files)
#   integration-admin.crt / .key   client, CN=integration-admin, EKU clientAuth
#                                  (admin role: Revoke/GenerateCrl/
#                                  CheckRevocationStatus in dev/test compose)
#   integration-tests.env          host-side CA_GRPC_* env for `cargo test`
#                                  (issuer client + CA_GRPC_ADMIN_CLIENT_*)
#
# Per-service subdirectories (copies of the files above, laid out like the
# Kubernetes secrets) so a container can mount ONLY its own key material
# (docker-compose.yml does this; SC-12 / AC-6 least privilege):
#   ca-server/   tls.crt, tls.key (CN=ca-service), client-ca.crt (= ca.crt)
#   acme-server/ tls.crt, tls.key (CN=acme-server), ca.crt
#   est-server/  tls.crt, tls.key (CN=est-server),  ca.crt
# The integration-tests / integration-admin identities are host-side only (used
# by `cargo test`), so they get no container subdirectory.
#
# The dev CA is a DEDICATED service-identity CA: it issues only these gRPC
# certificates and nothing else, which is what ca-server requires of
# CA_GRPC_TLS_CLIENT_CA_FILE (it refuses to start if that file holds its own
# subscriber-issuing CA certificate). client-ca.crt holds exactly this one
# trust anchor, which ca-server also requires whenever the admin list
# (CA_GRPC_ADMIN_CLIENT_SUBJECTS) is non-empty.
#
# The dev CA private key is generated in a temporary directory and DELETED once
# the leaves are signed: it is never written to the output directory, so no CA
# key ends up bind-mounted into a container. Re-running regenerates the whole
# set (all leaves must come from the same CA).
#
# Usage:
#   scripts/gen-dev-grpc-certs.sh [--force] [--san <SAN>]... [outdir]
#   make dev-grpc-certs                       # same, default outdir
#
#   --force       regenerate even if a complete, unexpired set already exists
#   --san <SAN>   extra server subjectAltName entry (repeatable), e.g.
#                 --san DNS:ostrich-pki-ca for a Helm release named "ostrich"
#                 (the Helm CA gRPC URL host is "<fullname>-ca")
#
# Idempotent: when every file exists and no certificate expires within 24 h the
# script exits 0 without touching anything. Otherwise (or with --force) the full
# set is regenerated.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Git Bash: stop MSYS from rewriting "/CN=..." subjects into Windows paths.
export MSYS_NO_PATHCONV=1

VALIDITY_DAYS=30
# The CA outlives every leaf by a day (leaves are signed seconds after the CA,
# so equal -days would make each leaf's notAfter fall after the CA's).
CA_VALIDITY_DAYS=$((VALIDITY_DAYS + 1))
CURVE="P-384"
DIGEST="sha384"
CA_SUBJECT="/CN=OstrichPKI Dev gRPC CA"
SERVER_NAME="ca-service"
SERVER_SANS="DNS:ca-service,DNS:ca,DNS:localhost,IP:127.0.0.1"
CLIENT_NAMES="acme-server est-server integration-tests integration-admin"
# Per-service mount directories: "<subdir>:<leaf name>:<trust anchor file name>".
SERVICE_DIRS="ca-server:${SERVER_NAME}:client-ca.crt acme-server:acme-server:ca.crt est-server:est-server:ca.crt"

usage() {
    sed -n '/^# Usage:/,/^# Idempotent:/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d'
}

FORCE=0
OUTDIR=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --force)
            FORCE=1
            ;;
        --san)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                echo "error: --san needs a value (e.g. DNS:ostrich-pki-ca)" >&2
                exit 2
            fi
            case "$2" in
                DNS:*|IP:*) ;;
                *)
                    echo "error: --san value must start with DNS: or IP: (got '$2')" >&2
                    exit 2
                    ;;
            esac
            # Reject characters that would break the openssl extension syntax.
            case "$2" in
                *,*|*\ *|*\"*|*\'*|*\\*)
                    echo "error: --san value must not contain commas, spaces, quotes or backslashes" >&2
                    exit 2
                    ;;
            esac
            SERVER_SANS="${SERVER_SANS},$2"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "error: unknown option '$1'" >&2
            usage >&2
            exit 2
            ;;
        *)
            if [ -n "$OUTDIR" ]; then
                echo "error: only one output directory may be given" >&2
                exit 2
            fi
            OUTDIR="$1"
            ;;
    esac
    shift
done
OUTDIR="${OUTDIR:-$PROJECT_ROOT/.dev-grpc-certs}"

if ! command -v openssl >/dev/null 2>&1; then
    echo "error: openssl not found in PATH" >&2
    exit 1
fi

banner() {
    echo "=============================================================================="
    echo " DEV ONLY - OstrichPKI CA gRPC mTLS test certificates"
    echo " Throwaway ${VALIDITY_DAYS}-day ECDSA ${CURVE} PKI with world-readable keys."
    echo " NEVER use these in a shared, staging or production environment."
    echo " Production: issue from a real CA - see docs/runbooks/ca-grpc-mtls.md"
    echo "=============================================================================="
}

banner

EXPECTED_CERTS="ca.crt ${SERVER_NAME}.crt"
EXPECTED_KEYS="${SERVER_NAME}.key"
for name in $CLIENT_NAMES; do
    EXPECTED_CERTS="$EXPECTED_CERTS ${name}.crt"
    EXPECTED_KEYS="$EXPECTED_KEYS ${name}.key"
done

EXPECTED_SUBDIR_FILES=""
for entry in $SERVICE_DIRS; do
    dir="${entry%%:*}"
    anchor="${entry##*:}"
    EXPECTED_SUBDIR_FILES="$EXPECTED_SUBDIR_FILES ${dir}/tls.crt ${dir}/tls.key ${dir}/${anchor}"
done

# Returns 0 when a complete set exists and nothing expires within 24 h.
existing_set_is_usable() {
    local f
    for f in $EXPECTED_CERTS $EXPECTED_KEYS integration-tests.env $EXPECTED_SUBDIR_FILES; do
        [ -s "$OUTDIR/$f" ] || return 1
    done
    # Sets generated before the admin identity existed lack these variables.
    grep -q '^CA_GRPC_ADMIN_CLIENT_CERT_FILE=' "$OUTDIR/integration-tests.env" || return 1
    for f in $EXPECTED_CERTS; do
        openssl x509 -in "$OUTDIR/$f" -noout -checkend 86400 >/dev/null 2>&1 || return 1
    done
    return 0
}

if [ "$FORCE" -eq 0 ] && existing_set_is_usable; then
    echo "Complete, unexpired set already present in $OUTDIR - nothing to do."
    echo "(use --force to regenerate, e.g. after adding --san entries)"
    exit 0
fi

mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)"
if [ "$OUTDIR" = "/" ]; then
    echo "error: refusing to write into /" >&2
    exit 1
fi
# ./certs is bind-mounted wholesale into ca, est and ocsp (docker-compose.yml):
# every key written below it is readable by all three (AC-6, SC-12).
case "$OUTDIR/" in
    "$PROJECT_ROOT/certs/"*)
        echo "warning: $OUTDIR is under ./certs, which docker-compose.yml mounts into" >&2
        echo "         ca, est and ocsp; every service would see every dev gRPC key." >&2
        echo "         Prefer the default ($PROJECT_ROOT/.dev-grpc-certs)." >&2
        ;;
esac

# Private working area (0700). Holds the dev CA key; removed on every exit path.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ostrich-grpc-certs.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
trap 'exit 130' INT TERM
umask 077

# Random positive serial, 128 bits (RFC 5280 §4.1.2.2: positive, <= 20 octets).
serial() {
    echo "0x$(openssl rand -hex 16)"
}

genkey() {
    openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${CURVE}" \
        -pkeyopt ec_param_enc:named_curve -out "$1" 2>/dev/null
}

cat > "$WORK/ext.cnf" <<EOF
[ca_ext]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[server_ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = ${SERVER_SANS}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

# --- Dev CA ------------------------------------------------------------------
genkey "$WORK/ca.key"
openssl req -new -key "$WORK/ca.key" -subj "$CA_SUBJECT" -out "$WORK/ca.csr"
openssl x509 -req -in "$WORK/ca.csr" -signkey "$WORK/ca.key" \
    -days "$CA_VALIDITY_DAYS" -"$DIGEST" -set_serial "$(serial)" \
    -extfile "$WORK/ext.cnf" -extensions ca_ext \
    -out "$WORK/ca.crt" 2>/dev/null

# sign_leaf <name> <extensions-section>
sign_leaf() {
    local name="$1" section="$2"
    genkey "$WORK/${name}.key"
    openssl req -new -key "$WORK/${name}.key" -subj "/CN=${name}" -out "$WORK/${name}.csr"
    openssl x509 -req -in "$WORK/${name}.csr" \
        -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" \
        -days "$VALIDITY_DAYS" -"$DIGEST" -set_serial "$(serial)" \
        -extfile "$WORK/ext.cnf" -extensions "$section" \
        -out "$WORK/${name}.crt" 2>/dev/null
    openssl verify -CAfile "$WORK/ca.crt" "$WORK/${name}.crt" >/dev/null
}

# --- Server ------------------------------------------------------------------
sign_leaf "$SERVER_NAME" server_ext

# --- Clients (subjects must be in a CA_GRPC_{ACME,EST,ADMIN}_CLIENT_SUBJECTS list)
for name in $CLIENT_NAMES; do
    cat >> "$WORK/ext.cnf" <<EOF

[client_${name}]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = DNS:${name}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
    sign_leaf "$name" "client_${name}"
done

# Host-side env for the env-gated live integration tests (cargo test runs on
# the host and dials the compose CA on localhost:50051).
cat > "$WORK/integration-tests.env" <<EOF
# DEV ONLY - generated by scripts/gen-dev-grpc-certs.sh; do not commit.
# Usage: set -a; . "${OUTDIR}/integration-tests.env"; set +a
CA_GRPC_URL="https://localhost:50051"
CA_GRPC_CLIENT_CERT_FILE="${OUTDIR}/integration-tests.crt"
CA_GRPC_CLIENT_KEY_FILE="${OUTDIR}/integration-tests.key"
CA_GRPC_CA_CERT_FILE="${OUTDIR}/ca.crt"
# Admin-role client (CN=integration-admin, in CA_GRPC_ADMIN_CLIENT_SUBJECTS in
# the dev/test compose files) for the Revoke/GenerateCrl/CheckRevocationStatus
# tests. Issuer identities are denied those RPCs.
CA_GRPC_ADMIN_CLIENT_CERT_FILE="${OUTDIR}/integration-admin.crt"
CA_GRPC_ADMIN_CLIENT_KEY_FILE="${OUTDIR}/integration-admin.key"
EOF

# --- Install -----------------------------------------------------------------
# Certificates 0644. Keys are ALSO 0644 on purpose: the service containers run
# as uid 1000, which usually differs from the host uid that owns these bind-
# mounted files, so a 0600 key would be unreadable inside the container. This
# is acceptable ONLY because the material is a disposable dev PKI. Production
# keys come from Kubernetes secrets / a secrets manager, never from this script.
for f in $EXPECTED_CERTS $EXPECTED_KEYS integration-tests.env; do
    cp "$WORK/$f" "$OUTDIR/$f.tmp"
    chmod 0644 "$OUTDIR/$f.tmp"
    mv -f "$OUTDIR/$f.tmp" "$OUTDIR/$f"
done
chmod 0755 "$OUTDIR"

# Per-service subdirectories (same files, Kubernetes-secret names). Each
# container in docker-compose.yml mounts only its own subdirectory.
# install_file <src> <dest> (atomic replace, 0644 - see note above)
install_file() {
    cp "$1" "$2.tmp"
    chmod 0644 "$2.tmp"
    mv -f "$2.tmp" "$2"
}
for entry in $SERVICE_DIRS; do
    dir="${entry%%:*}"
    rest="${entry#*:}"
    leaf="${rest%%:*}"
    anchor="${rest#*:}"
    mkdir -p "$OUTDIR/$dir"
    chmod 0755 "$OUTDIR/$dir"
    install_file "$WORK/${leaf}.crt" "$OUTDIR/$dir/tls.crt"
    install_file "$WORK/${leaf}.key" "$OUTDIR/$dir/tls.key"
    install_file "$WORK/ca.crt" "$OUTDIR/$dir/$anchor"
done

echo
echo "Wrote dev gRPC mTLS material to $OUTDIR (CA key discarded):"
for f in $EXPECTED_CERTS; do
    subject="$(openssl x509 -in "$OUTDIR/$f" -noout -subject | sed 's/^subject= *//')"
    enddate="$(openssl x509 -in "$OUTDIR/$f" -noout -enddate | sed 's/^notAfter=//')"
    printf '  %-24s %-34s expires %s\n' "$f" "$subject" "$enddate"
done
echo "Per-service mount directories: ca-server/ acme-server/ est-server/"
echo
echo "ca-server per-role client lists for these clients (dev/test compose):"
echo "  CA_GRPC_ACME_CLIENT_SUBJECTS=CN=acme-server;CN=integration-tests"
echo "  CA_GRPC_EST_CLIENT_SUBJECTS=CN=est-server"
echo "  CA_GRPC_ADMIN_CLIENT_SUBJECTS=CN=integration-admin"
echo "  CA_GRPC_ACME_ALLOWED_PROFILES=acme-default;tls_client"
echo "  CA_GRPC_EST_ALLOWED_PROFILES=tls_client;tls_server;tls_server_client;efs"
echo "Restart running ca/acme/est containers to pick up regenerated files."
