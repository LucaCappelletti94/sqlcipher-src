#!/bin/sh -e
# Writes what fuzz/build.sh needs into $1: the sqlite-wasm-rs wrapper, a static OpenSSL, the testkey databases, and the
# beta (signed pre-release tag) and prerelease (unsigned branch tip) amalgamations with the COMMIT each came from.

mkdir -p "$1/shim" "$1/release"
OUT=$(cd "$1" && pwd)
cd "$(dirname "$0")/.."
ROOT=$(pwd)
# shellcheck source=tools/releases.sh
. "$ROOT/tools/releases.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

SHIM=$(wasm_shim)
cp "$SHIM/sqlcipher-wasm.c" "$SHIM/sqlcipher-entropy.c" "$SHIM/sqlcipher-ltc.h" "$OUT/shim/"

trust_keys "$WORK"
fetch_sqlcipher "$WORK"
cp "$WORK"/sqlcipher/sqlcipher-resources/sqlcipher-*-testkey.db "$OUT/release/"

# SQLCipher 5.x needs OpenSSL's KBKDF parameters from 3.1 on, kept here across runs while the version holds.
OPENSSL_VERSION=3.5.8
OPENSSL_SHA256=a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2
if [ "$(cat "$OUT/openssl/VERSION" 2>/dev/null)" != "$OPENSSL_VERSION" ]; then
    rm -rf "$OUT/openssl"
    curl -sSfL -o "$WORK/openssl.tar.gz" \
        "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz"
    echo "$OPENSSL_SHA256  $WORK/openssl.tar.gz" | sha256sum -c --quiet -
    tar -xzf "$WORK/openssl.tar.gz" -C "$WORK"
    (cd "$WORK/openssl-$OPENSSL_VERSION" &&
        CFLAGS=-O2 ./Configure linux-x86_64 no-shared no-tests no-docs --prefix="$OUT/openssl" --libdir=lib > configure.log &&
        make -j"$(nproc)" build_libs > make.log && make install_dev > install.log)
    echo "$OPENSSL_VERSION" > "$OUT/openssl/VERSION"
fi

# $1 is an unpacked SQLCipher tree, $2 the line, $3 the commit it came from.
amalgamate() {
    (cd "$1" && ./configure > configure.log && make sqlite3.c > make.log)
    mkdir -p "$OUT/$2"
    cp "$1/sqlite3.c" "$OUT/$2/sqlcipher.c"
    cp "$1"/sqlcipher-resources/sqlcipher-*-testkey.db "$OUT/$2/"
    echo "$3" > "$OUT/$2/COMMIT"
}

mkdir "$WORK/beta"
fetch_sqlcipher_tag "$WORK/beta" "$SQLCIPHER_NEXT_VERSION" "$SQLCIPHER_NEXT_COMMIT"
amalgamate "$WORK/beta/sqlcipher" beta "$SQLCIPHER_NEXT_COMMIT"

mkdir -p "$WORK/prerelease/sqlcipher"
git init --quiet "$WORK/prerelease/sqlcipher.git"
git -C "$WORK/prerelease/sqlcipher.git" fetch --quiet --depth 1 https://github.com/sqlcipher/sqlcipher.git prerelease
commit=$(git -C "$WORK/prerelease/sqlcipher.git" rev-parse FETCH_HEAD)
git -C "$WORK/prerelease/sqlcipher.git" archive "$commit" | tar x -C "$WORK/prerelease/sqlcipher"
amalgamate "$WORK/prerelease/sqlcipher" prerelease "$commit"
