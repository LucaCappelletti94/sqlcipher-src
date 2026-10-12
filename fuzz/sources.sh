#!/bin/sh -e
# Copies the sqlite-wasm-rs SQLCipher wrapper the fuzz build compiles into $1/shim.

mkdir -p "$1/shim"
OUT=$(cd "$1" && pwd)
cd "$(dirname "$0")/.."
ROOT=$(pwd)
# shellcheck source=tools/releases.sh
. "$ROOT/tools/releases.sh"

SHIM=$(wasm_shim)
cp "$SHIM/sqlcipher-wasm.c" "$SHIM/sqlcipher-entropy.c" "$SHIM/sqlcipher-ltc.h" "$OUT/shim/"
