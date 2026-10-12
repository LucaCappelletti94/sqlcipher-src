#!/bin/sh -e
# Writes what the fuzz build needs beside this checkout into $1: the sqlite-wasm-rs SQLCipher wrapper in $1/shim, the
# testkey databases hostile_file seeds from in $1/<line>, and for the beta and prerelease lines their generated
# amalgamation as $1/<line>/sqlcipher.c with the commit it came from in $1/<line>/COMMIT. beta is the signed pre-release
# tag tools/releases.sh pins, prerelease the tip of the branch SQLCipher bases patches on, which no signature covers.

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
