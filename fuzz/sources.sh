#!/bin/sh -e
# Generates the SQLCipher amalgamations the fetched fuzz targets build, into $1/<variant>/sqlcipher.c: the signed beta
# tag, and the tip of prerelease, the branch SQLCipher bases patches on, which no signature covers.

mkdir -p "$1"
OUT=$(cd "$1" && pwd)
cd "$(dirname "$0")/.."
ROOT=$(pwd)
# shellcheck source=tools/releases.sh
. "$ROOT/tools/releases.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# $1 is an unpacked tree, $2 the variant, $3 the commit it came from.
amalgamate() {
    (cd "$1" && ./configure > configure.log && make sqlite3.c > make.log)
    mkdir -p "$OUT/$2"
    cp "$1/sqlite3.c" "$OUT/$2/sqlcipher.c"
    echo "$3" > "$OUT/$2/COMMIT"
}

trust_keys "$WORK"
mkdir "$WORK/beta"
fetch_sqlcipher_tag "$WORK/beta" "$SQLCIPHER_NEXT_VERSION" "$SQLCIPHER_NEXT_COMMIT"
amalgamate "$WORK/beta/sqlcipher" beta "$SQLCIPHER_NEXT_COMMIT"

mkdir -p "$WORK/prerelease/sqlcipher"
git init --quiet "$WORK/prerelease/sqlcipher.git"
git -C "$WORK/prerelease/sqlcipher.git" fetch --quiet --depth 1 https://github.com/sqlcipher/sqlcipher.git prerelease
commit=$(git -C "$WORK/prerelease/sqlcipher.git" rev-parse FETCH_HEAD)
git -C "$WORK/prerelease/sqlcipher.git" archive "$commit" | tar x -C "$WORK/prerelease/sqlcipher"
amalgamate "$WORK/prerelease/sqlcipher" prerelease "$commit"
echo "prerelease at $commit"
