#!/usr/bin/env bash
#
# Build / test OstrichPKI from WSL (Linux toolchain).
#
# Why this exists: the FIPS crypto stack does not build cleanly with the Windows
# native toolchain in this repo's dev setup -- `aws-lc-fips-sys` needs libclang
# for bindgen and `aws-lc-sys` needs an MSVC C build that fails locally. The
# Linux toolchain (clang + cmake + make) builds all of it without fuss, so we
# edit on Windows and build/test in WSL.
#
# First-time setup (installs deps + dev Postgres) lives in a separate script:
#   scripts/dev-setup-wsl.sh
#
# Usage (run from inside WSL, at the repo root on /mnt/c/...):
#   scripts/build-wsl.sh                       # default: check all but the wasm UI
#   scripts/build-wsl.sh test -p ostrich-common
#   scripts/build-wsl.sh test -p ostrich-integration-tests --test session_store_e2e -- --test-threads=1
#   scripts/build-wsl.sh build -p ostrich-ca-server --release
#
# All arguments are passed straight through to `cargo`.
set -euo pipefail

# --- Linux-native target dir -------------------------------------------------
# Keep build artifacts off the Windows `target/`: mixing ELF and PE objects in
# one directory corrupts both Windows and WSL builds, and building under /mnt/c
# is slow over the 9P bridge. Guard against Windows env interop leaking a
# non-Linux $HOME (it can arrive mangled, e.g. "C:Users...").
case "${HOME:-}" in
  /home/*|/root) cache_base="$HOME/.cache" ;;
  *)             cache_base="/tmp" ;;
esac
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$cache_base/ostrich-pki-target}"

# --- protoc (lightweight guard) ----------------------------------------------
# Required by ostrich-protocol (tonic/prost code generation). Full provisioning
# lives in scripts/dev-setup-wsl.sh; this just keeps an ad-hoc build on a fresh
# box from failing on a missing protoc.
if ! command -v protoc >/dev/null 2>&1; then
  echo "build-wsl: protoc not found; installing protobuf-compiler (needs sudo)..." >&2
  echo "build-wsl: (run 'scripts/dev-setup-wsl.sh' once for the full dev setup)" >&2
  sudo apt-get update -qq && sudo apt-get install -y protobuf-compiler
fi

# --- default action ----------------------------------------------------------
# `ostrich-web-ui` is a wasm32 (Yew) crate and is built separately for the
# wasm32-unknown-unknown target; exclude it from host-target builds so the
# default action does not fail on it.
if [ "$#" -eq 0 ]; then
  set -- check --workspace --exclude ostrich-web-ui
fi

echo "build-wsl: CARGO_TARGET_DIR=$CARGO_TARGET_DIR"
echo "build-wsl: cargo $*"
exec cargo "$@"
