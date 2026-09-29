#!/bin/sh -e
# Builds rusqlite's bundled SQLCipher from the sqlcipher.c in SQLCIPHER_DIR, the shipped sources unless set, and runs rusqlite's own tests on it.
# The rusqlite revision is the one interop/web pins, which Dependabot cannot move.

cd "$(dirname "$0")/.."
ROOT=$(pwd)
SOURCES=${SQLCIPHER_DIR:-$ROOT/sqlcipher}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

rev=$(sed -nE 's/^rusqlite = \{ git = "https:\/\/github.com\/rusqlite\/rusqlite", rev = "([0-9a-f]{40})" \}$/\1/p' interop/web/Cargo.toml)
[ -n "$rev" ] || { echo "no rusqlite revision in interop/web/Cargo.toml" >&2; exit 1; }
git init -q "$WORK/rusqlite"
git -C "$WORK/rusqlite" fetch -q --depth 1 https://github.com/rusqlite/rusqlite.git "$rev"
git -C "$WORK/rusqlite" checkout -q FETCH_HEAD
cp "$SOURCES/sqlcipher.c" "$WORK/rusqlite/libsqlite3-sys/sqlcipher/sqlite3.c"
cp "$SOURCES/sqlite3.h" "$SOURCES/sqlite3ext.h" "$WORK/rusqlite/libsqlite3-sys/sqlcipher/"
cd "$WORK/rusqlite"
cargo test --features "backup blob chrono functions limits load_extension serde_json trace vtab bundled-sqlcipher-vendored-openssl"
