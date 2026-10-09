#!/bin/sh -e

# Native SQLCipher writes, the wasm build reads and writes back, native reads the result.
cd "$(dirname "$0")"
FIXTURES="$(pwd)/fixtures"
# This checkout's sources, never the release sqlite-wasm-rs depends on, unless CI points SQLCIPHER_DIR at the packaged crate.
SOURCE_DIR=${SQLCIPHER_DIR:-$(cargo metadata --format-version 1 --manifest-path web/Cargo.toml |
    jq -r '.packages[] | select(.name == "sqlcipher-src" and .source == null) | .manifest_path' | xargs dirname)/sqlcipher}
[ -f "$SOURCE_DIR/sqlcipher.c" ] || { echo "no SQLCipher sources in $SOURCE_DIR" >&2; exit 1; }

# A leg's switches reach every wasm unit through cc-rs.
if [ -n "${SQLCIPHER_LEG_FLAGS:-}" ]; then
    export CFLAGS_wasm32_unknown_unknown="$SQLCIPHER_LEG_FLAGS"
fi

# NATIVE_SQLCIPHER_DIR builds the native side from those sources in place of rusqlite's bundled SQLCipher,
# so a leg's own defaults cross both ways.
NATIVE="$(pwd)/native"
NATIVE_FEATURES=""
if [ -n "${NATIVE_SQLCIPHER_DIR:-}" ]; then
    WORK=$(mktemp -d)
    trap 'rm -rf "$WORK"' EXIT
    sys=$(cargo metadata --format-version 1 --manifest-path native/Cargo.toml |
        jq -r '.packages[] | select(.name == "libsqlite3-sys") | .manifest_path' | xargs dirname)
    cp -R "$sys" "$WORK/libsqlite3-sys"
    chmod -R u+w "$WORK/libsqlite3-sys"
    cp "$NATIVE_SQLCIPHER_DIR/sqlcipher.c" "$WORK/libsqlite3-sys/sqlcipher/sqlite3.c"
    cp "$NATIVE_SQLCIPHER_DIR/sqlite3.h" "$NATIVE_SQLCIPHER_DIR/sqlite3ext.h" "$WORK/libsqlite3-sys/sqlcipher/"
    mkdir "$WORK/native"
    cp -R native/Cargo.toml native/Cargo.lock native/src "$WORK/native/"
    printf '\n[patch.crates-io]\nlibsqlite3-sys = { path = "%s" }\n' "$WORK/libsqlite3-sys" >> "$WORK/native/Cargo.toml"
    NATIVE="$WORK/native"
    # 5.x's OpenSSL provider needs a newer OpenSSL than ubuntu-latest carries.
    NATIVE_FEATURES="--features rusqlite/bundled-sqlcipher-vendored-openssl"
    # 5.x refuses to build with direct overflow reads, which 4.x only uses as a shortcut.
    [ -n "${LIBSQLITE3_FLAGS:-}" ] || export LIBSQLITE3_FLAGS="-DSQLITE_DIRECT_OVERFLOW_READ=0"
fi

rm -rf "$FIXTURES" && mkdir -p "$FIXTURES"
# shellcheck disable=SC2086 # NATIVE_FEATURES is empty or two words.
cargo run --release --manifest-path "$NATIVE/Cargo.toml" $NATIVE_FEATURES -- write "$FIXTURES"
# The tests that exchange files with the native side come first, so a failure elsewhere cannot hide the exchange.
(cd web && SQLITE_WASM_RS_SOURCE_DIR="$SOURCE_DIR" wasm-pack test --node --release --test interop --test rusqlite --test settings)
# shellcheck disable=SC2086 # NATIVE_FEATURES is empty or two words.
cargo run --release --manifest-path "$NATIVE/Cargo.toml" $NATIVE_FEATURES -- read "$FIXTURES"
# The rest exchange no files with the native side, so one run of them per source directory suffices.
[ -z "${NATIVE_SQLCIPHER_DIR:-}" ] || exit 0
(cd web && SQLITE_WASM_RS_SOURCE_DIR="$SOURCE_DIR" wasm-pack test --node --release \
    --test encryption --test broken_crypto --test broken_crypto_plain --test sahpool --test bindings)
(cd web && SQLITE_WASM_RS_SOURCE_DIR="$SOURCE_DIR" WASM_BINDGEN_USE_BROWSER=1 \
    nice wasm-pack test --headless --chrome --release \
    --test encryption --test broken_crypto --test broken_crypto_plain --test sahpool --test bindings)
(cd web && SQLITE_WASM_RS_SOURCE_DIR="$SOURCE_DIR" WASM_BINDGEN_USE_BROWSER=1 \
    nice wasm-pack test --headless --firefox --release \
    --test encryption --test broken_crypto --test broken_crypto_plain --test sahpool --test bindings)
