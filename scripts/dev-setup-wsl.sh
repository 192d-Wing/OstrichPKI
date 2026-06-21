#!/usr/bin/env bash
#
# One-time WSL dev environment setup for OstrichPKI.
#
# Takes a fresh WSL Ubuntu (with rustup already installed) to the point where
# `scripts/build-wsl.sh test ...` -- including the DB-backed integration tests --
# runs green. Installs the native build toolchain (clang/cmake for aws-lc),
# protoc (tonic/prost codegen), openssl + pkg-config (transitive -sys crates),
# and a local dev Postgres with the ostrich role/database provisioned.
#
# Usage (run from inside WSL, at the repo root on /mnt/c/...):
#   scripts/dev-setup-wsl.sh
#
# Dev Postgres parameters (overridable via env):
#   PGUSER_OSTRICH (ostrich)  PGPASS_OSTRICH (changeme)  PGDB_OSTRICH (ostrich_pki)
#
# Day-to-day building/testing lives in scripts/build-wsl.sh.
set -euo pipefail

pg_user="${PGUSER_OSTRICH:-ostrich}"
pg_pass="${PGPASS_OSTRICH:-changeme}"
pg_db="${PGDB_OSTRICH:-ostrich_pki}"

echo "dev-setup: installing apt packages (needs sudo)..."
sudo apt-get update -qq
sudo apt-get install -y \
  build-essential clang libclang-dev cmake pkg-config \
  libssl-dev protobuf-compiler \
  postgresql postgresql-contrib

echo "dev-setup: starting Postgres..."
sudo service postgresql start

echo "dev-setup: provisioning role '$pg_user' and database '$pg_db' (idempotent)..."
# Role: create only if absent, then (re)apply the password. Identifiers/literals
# are quoted via format() %I/%L; the password is never written into SQL text.
sudo -u postgres psql -v ON_ERROR_STOP=1 \
  -v user="$pg_user" -v pass="$pg_pass" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN', :'user')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'user') \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'user', :'pass') \gexec
SQL
# Database: CREATE DATABASE cannot run inside the block above.
if ! sudo -u postgres psql -tAc \
      "SELECT 1 FROM pg_database WHERE datname='$pg_db'" | grep -q 1; then
  sudo -u postgres createdb -O "$pg_user" "$pg_db"
fi

url="postgresql://${pg_user}:${pg_pass}@127.0.0.1:5432/${pg_db}?sslmode=disable"
echo
echo "dev-setup: complete."
echo "  Rust:     $(cargo --version 2>/dev/null || echo 'not found -- install rustup')"
echo "  protoc:   $(protoc --version 2>/dev/null || echo 'missing')"
echo "  Postgres: reachable at 127.0.0.1:5432 (db '$pg_db', role '$pg_user')"
echo
echo "  Build/check the workspace:"
echo "    scripts/build-wsl.sh"
echo
echo "  Run the DB-backed integration tests:"
echo "    export DATABASE_URL='$url'"
echo "    scripts/build-wsl.sh test -p ostrich-integration-tests --test session_store_e2e -- --test-threads=1"
