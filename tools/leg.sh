#!/bin/sh -e
# Generates the sources of a SQLCipher line other than the shipped release into OUT, for CI to test and nothing to ship.
# LEG is next, the signed pre-release pinned in tools/releases.sh, or prerelease or beta, the unsigned head of that branch.
# OUT/sqlcipher is the SQLCipher tree, OUT/sources the generated sources, and OUT/leg.env names the leg's commit and version.

LEG=${1:?usage: tools/leg.sh LEG OUT}
OUT=${2:?usage: tools/leg.sh LEG OUT}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
cd "$(dirname "$0")/.."
ROOT=$(pwd)
# shellcheck source=tools/releases.sh
. "$ROOT/tools/releases.sh"

trust_keys "$OUT"
case "$LEG" in
next)
    fetch_sqlcipher_tag "$OUT" "$SQLCIPHER_NEXT_VERSION" "$SQLCIPHER_NEXT_COMMIT"
    commit=$SQLCIPHER_NEXT_COMMIT
    ;;
prerelease | beta)
    git init --quiet "$OUT/sqlcipher.git"
    git -C "$OUT/sqlcipher.git" fetch --quiet --depth 1 https://github.com/sqlcipher/sqlcipher.git "refs/heads/$LEG"
    commit=$(git -C "$OUT/sqlcipher.git" rev-parse FETCH_HEAD)
    mkdir "$OUT/sqlcipher"
    git -C "$OUT/sqlcipher.git" archive "$commit" | tar x -C "$OUT/sqlcipher"
    ;;
*)
    echo "unknown leg $LEG, expected next, prerelease or beta" >&2
    exit 1
    ;;
esac
fetch_libtomcrypt "$OUT"

# 5.x refuses to build without URI filenames or with direct overflow reads, and encrypts with AES-GCM keyed through OMAC.
# 4.x accepts all four, so every leg takes them and the shipped wrapper keeps what the release needs.
mkdir "$OUT/sources"
{
    printf '%s\n' '#define SQLITE_USE_URI 1' '#define SQLITE_DIRECT_OVERFLOW_READ 0' '#define LTC_GCM_MODE' '#define LTC_OMAC'
    cat "$ROOT/sqlcipher/sqlite3.c"
} > "$OUT/sources/sqlite3.c"
generate_sources "$OUT" "$OUT/sources"

version=$(sed -nE 's/^#define CIPHER_VERSION_NUMBER ([^ ]+)$/\1/p' "$OUT/sources/sqlcipher.c")
[ -n "$version" ] || { echo "no CIPHER_VERSION_NUMBER in the generated sqlcipher.c" >&2; exit 1; }
[ "$LEG" != next ] || [ "$version" = "$SQLCIPHER_NEXT_VERSION" ] ||
    { echo "SQLCipher v$SQLCIPHER_NEXT_VERSION calls itself $version" >&2; exit 1; }
printf 'SQLCIPHER_LEG=%s\nSQLCIPHER_LEG_COMMIT=%s\nSQLCIPHER_LEG_VERSION=%s\n' "$LEG" "$commit" "$version" > "$OUT/leg.env"
rm -rf "$OUT/sqlcipher.git" "$OUT/target" "$OUT/gnupg" "$OUT/libtomcrypt" "$OUT"/libtomcrypt.tar.xz*
echo "SQLCipher $LEG leg at $commit, version $version"
