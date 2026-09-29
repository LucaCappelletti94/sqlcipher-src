#!/bin/sh -e

cd "$(dirname "$0")"
ROOT=$(pwd)
# shellcheck source=tools/releases.sh
. "$ROOT/tools/releases.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

trust_keys "$WORK"
fetch_sqlcipher "$WORK"
fetch_libtomcrypt "$WORK"
generate_sources "$WORK" "$ROOT/sqlcipher"
python3 "$ROOT/tools/checksums.py" "$ROOT/sqlcipher"
