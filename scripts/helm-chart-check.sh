#!/usr/bin/env bash
#
# OstrichPKI - Helm chart validation (lint, template, fail-closed guards)
#
# Lints and renders deploy/helm/ostrich-pki with the default values and with
# values-est-issuer-ci.yaml, then renders a set of misconfigurations that the
# chart's guards MUST refuse. A negative case passes only when helm fails AND
# its output contains the expected guard message, so an unrelated error (or a
# guard that silently stopped firing) is caught.
#
# Usage: scripts/helm-chart-check.sh [CHART_DIR]   (default deploy/helm/ostrich-pki)
#   HELM=/path/to/helm   helm binary (default: helm on PATH)
# Needs the chart dependencies vendored first (`helm dependency build`); this
# script never fetches anything.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: CM-2 / CM-6 (baseline renders; secure defaults refuse to
#   render without mTLS secrets), CM-3, AC-3 / AC-6 / AC-5 (role lists and
#   issuer profile allowlists fail closed), SA-11 (developer testing)
# - NIAP PP-CA: FMT_SMR.2 (role separation between issuer and admin lists),
#   FTP_ITC.1 (mTLS secrets required)

set -euo pipefail

HELM="${HELM:-helm}"
CHART="${1:-deploy/helm/ostrich-pki}"

if [[ ! -f "$CHART/Chart.yaml" ]]; then
  echo "error: $CHART is not a Helm chart directory" >&2
  exit 2
fi
if [[ ! -d "$CHART/charts" ]] || ! compgen -G "$CHART/charts/*.tgz" >/dev/null; then
  echo "error: $CHART/charts is missing; run: $HELM dependency build $CHART" >&2
  exit 2
fi

echo "--- helm version"
"$HELM" version

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Names of the mTLS secrets the default values require (no secret material:
# the chart only references them by name).
SECRETS=(
  --set ca.grpc.tls.existingSecret=ci-ca-grpc-tls
  --set acme.caGrpc.clientTls.existingSecret=ci-acme-grpc
  --set est.caGrpc.clientTls.existingSecret=ci-est-grpc
)

pass=0
fail=0

ok() { echo "PASS $1"; pass=$((pass + 1)); }
ko() { echo "FAIL $1"; fail=$((fail + 1)); }

# positive <id> <helm args...>: helm must succeed.
positive() {
  local id="$1"
  shift
  local out="$work/$id.out"
  if "$HELM" "$@" >"$out" 2>&1; then
    ok "$id: helm $*"
  else
    ko "$id: helm $* (exit $?)"
    sed 's/^/    /' "$out"
  fi
}

# negative <id> <expected substring> <values yaml|-> [extra helm args...]:
# `helm template` must fail with output containing the substring. "-" = no
# values file.
negative() {
  local id="$1" expect="$2" yaml="$3"
  shift 3
  local args=(template t "$CHART" "$@")
  if [[ "$yaml" != "-" ]]; then
    printf '%s\n' "$yaml" >"$work/$id.yaml"
    args+=(-f "$work/$id.yaml")
  fi
  local out="$work/$id.out" rc=0
  "$HELM" "${args[@]}" >"$out" 2>&1 || rc=$?
  if [[ "$rc" -eq 0 ]]; then
    ko "$id: rendered, expected refusal: $expect"
  elif grep -Fq -- "$expect" "$out"; then
    ok "$id: refused ($expect)"
  else
    ko "$id: failed (exit $rc) without the expected message: $expect"
    sed 's/^/    /' "$out"
  fi
}

echo "--- positive cases"
positive P1 lint --strict "$CHART" "${SECRETS[@]}"
positive P2 template t "$CHART" "${SECRETS[@]}"
positive P3 lint --strict "$CHART" -f "$CHART/values-est-issuer-ci.yaml"
positive P4 template t "$CHART" -f "$CHART/values-est-issuer-ci.yaml"

echo "--- negative cases (must be refused)"
# N0a-c: each mTLS secret guard on its own (the other two names set), so a
# removed guard cannot hide behind another one's identical message tail.
negative N0a 'ca.grpc.tls.existingSecret is required: the CA gRPC API' - \
  --set acme.caGrpc.clientTls.existingSecret=ci-acme-grpc \
  --set est.caGrpc.clientTls.existingSecret=ci-est-grpc
negative N0b 'acme.caGrpc.clientTls.existingSecret is required: the CA gRPC API' - \
  --set ca.grpc.tls.existingSecret=ci-ca-grpc-tls \
  --set est.caGrpc.clientTls.existingSecret=ci-est-grpc
negative N0c 'est.caGrpc.clientTls.existingSecret is required: the CA gRPC API' - \
  --set ca.grpc.tls.existingSecret=ci-ca-grpc-tls \
  --set acme.caGrpc.clientTls.existingSecret=ci-acme-grpc
negative N1 'ca.grpc.allowedClientSubjects was removed' '
ca:
  grpc:
    allowedClientSubjects:
      - "CN=x"' "${SECRETS[@]}"
negative N2 'ca.grpc.acmeAllowedProfiles must not list "intermediate_ca"' '
ca:
  grpc:
    acmeAllowedProfiles:
      - intermediate_ca' "${SECRETS[@]}"
negative N3 'ca.grpc.estAllowedProfiles must not list "intermediate_ca"' '
ca:
  grpc:
    estAllowedProfiles:
      - intermediate_ca' "${SECRETS[@]}"
negative N4 'ca.grpc.acmeClientSubjects and ca.grpc.estClientSubjects are both empty' '
ca:
  grpc:
    acmeClientSubjects: []
    estClientSubjects: []' "${SECRETS[@]}"
negative N5 'ca.grpc.acmeClientSubjects is set but ca.grpc.acmeAllowedProfiles is empty' '
ca:
  grpc:
    acmeAllowedProfiles: []' "${SECRETS[@]}"
negative N6 'is listed in both ca.grpc.acmeClientSubjects and ca.grpc.adminClientSubjects' '
ca:
  grpc:
    adminClientSubjects:
      - "CN=acme-server"' "${SECRETS[@]}"
negative N7 'is listed in both ca.grpc.acmeClientSubjects and ca.grpc.estClientSubjects' '
ca:
  grpc:
    estClientSubjects:
      - "CN=acme-server"' "${SECRETS[@]}"
negative N8 "ca.grpc.acmeClientSubjects entry \"CN=a;CN=b\" is empty or contains ';'" '
ca:
  grpc:
    acmeClientSubjects:
      - "CN=a;CN=b"' "${SECRETS[@]}"

echo "--- result: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
