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
(cd "$WORK/sqlcipher" && ./configure > configure.log && make sqlite3.c > make.log)

python3 "$ROOT/tools/assemble.py" "$WORK/sqlcipher" "$WORK/libtomcrypt" "$ROOT/sqlcipher"
python3 "$ROOT/tools/checksums.py" "$ROOT/sqlcipher"
