#!/usr/bin/env bash
# Regenerates the Go package in nachalo/ from the nachalo-uniffi library. CI fails if the
# committed code differs from what this produces.
set -euo pipefail

# The generator release the uniffi crate is pinned to (bindings/uniffi/Cargo.toml).
TAG="v0.7.1+v0.31.0"
if ! uniffi-bindgen-go --version 2>/dev/null | grep -qF "${TAG#v}"; then
  echo "needs uniffi-bindgen-go $TAG:" >&2
  echo "  cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag $TAG --locked" >&2
  exit 1
fi
# The output is formatted with gofmt, so the committed code matches CI's.
command -v gofmt >/dev/null || { echo "needs Go (gofmt) on PATH" >&2; exit 1; }

cd "$(dirname "$0")/../.."
cargo build -p nachalo-uniffi --lib
for lib in target/debug/{libnachalo_uniffi.so,libnachalo_uniffi.dylib,nachalo_uniffi.dll}; do
  [ -f "$lib" ] && break
done
uniffi-bindgen-go --no-format --out-dir bindings/go "$lib"
gofmt -w bindings/go/nachalo
