#!/bin/sh -e

# Native SQLCipher writes, the wasm build reads and writes back, native reads the result.
cd "$(dirname "$0")"
FIXTURES="$(pwd)/fixtures"
# This checkout's sources, never the release sqlite-wasm-rs depends on, unless CI points SQLCIPHER_DIR at the packaged crate.
SOURCE_DIR=${SQLCIPHER_DIR:-$(cargo metadata --format-version 1 --manifest-path web/Cargo.toml |
    jq -r '.packages[] | select(.name == "sqlcipher-src" and .source == null) | .manifest_path' | xargs dirname)/sqlcipher}
[ -f "$SOURCE_DIR/sqlcipher.c" ] || { echo "no SQLCipher sources in $SOURCE_DIR" >&2; exit 1; }
rm -rf "$FIXTURES" && mkdir -p "$FIXTURES"
cargo run --release --manifest-path native/Cargo.toml -- write "$FIXTURES"
(cd web && SQLITE_WASM_RS_SOURCE_DIR="$SOURCE_DIR" wasm-pack test --node --release)
cargo run --release --manifest-path native/Cargo.toml -- read "$FIXTURES"
(cd web && SQLITE_WASM_RS_SOURCE_DIR="$SOURCE_DIR" WASM_BINDGEN_USE_BROWSER=1 \
    nice wasm-pack test --headless --chrome --release \
    --test encryption --test broken_crypto --test broken_crypto_plain --test sahpool --test bindings)
(cd web && SQLITE_WASM_RS_SOURCE_DIR="$SOURCE_DIR" WASM_BINDGEN_USE_BROWSER=1 \
    nice wasm-pack test --headless --firefox --release \
    --test encryption --test broken_crypto --test broken_crypto_plain --test sahpool --test bindings)
