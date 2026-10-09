#!/bin/sh -e
# Writes what the fuzz build needs beside this checkout into $1: the sqlite-wasm-rs SQLCipher wrapper in $1/shim, and
# the testkey databases of the pinned release, which hostile_file seeds from, in $1/release.

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
