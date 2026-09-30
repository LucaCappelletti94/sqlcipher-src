#!/bin/sh -e

# Moves the generated sources to SQLCipher release VERSION. Only an annotated tag is taken, and
# upgrade.sh then accepts it only with a valid signature from the pinned key in tools/releases.sh.
VERSION=${1:?usage: bump.sh VERSION}
echo "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "not a release version: $VERSION" >&2; exit 1; }

cd "$(dirname "$0")"
COMMIT=$(git ls-remote https://github.com/sqlcipher/sqlcipher.git "refs/tags/v${VERSION}^{}" | cut -f1)
[ -n "$COMMIT" ] || { echo "SQLCipher has no annotated tag v${VERSION}" >&2; exit 1; }

sed -i -E \
    -e "s/^SQLCIPHER_VERSION=\".*\"$/SQLCIPHER_VERSION=\"${VERSION}\"/" \
    -e "s/^SQLCIPHER_COMMIT=\".*\"$/SQLCIPHER_COMMIT=\"${COMMIT}\"/" \
    tools/releases.sh
./upgrade.sh

SQLITE_VERSION=$(sed -nE 's/^#define SQLITE_VERSION +"([0-9.]+)"$/\1/p' sqlcipher/sqlite3.h)
LIBTOMCRYPT_VERSION=$(sed -nE 's/^LIBTOMCRYPT_VERSION="(.*)"$/\1/p' tools/releases.sh)
[ -n "$SQLITE_VERSION" ] || { echo "no SQLite version in sqlcipher/sqlite3.h" >&2; exit 1; }

# The crate version encodes the release, so SQLCipher X.Y.Z becomes (100X+Y).Z.0.
MAJOR=${VERSION%%.*}
REST=${VERSION#*.}
MINOR=${REST%%.*}
PATCH=${REST#*.}
CRATE_VERSION="$((MAJOR * 100 + MINOR)).${PATCH}.0+sqlcipher-${VERSION}-sqlite-${SQLITE_VERSION}-libtomcrypt-${LIBTOMCRYPT_VERSION}"

sed -i -E \
    -e "s/^(pub const SQLCIPHER_VERSION: &str = )\".*\";$/\1\"${VERSION}\";/" \
    -e "s/^(pub const SQLITE_VERSION: &str = )\".*\";$/\1\"${SQLITE_VERSION}\";/" \
    src/lib.rs
sed -i -E "0,/^version = \".*\"$/s//version = \"${CRATE_VERSION}\"/" Cargo.toml
cargo update --quiet -p sqlcipher-src
# interop/web also locks the sqlcipher-src release sqlite-wasm-rs depends on, so only the path copy is named.
cargo update --quiet --manifest-path interop/web/Cargo.toml -p "path+file://$(pwd)#sqlcipher-src"

echo "Pinned SQLCipher ${VERSION} on SQLite ${SQLITE_VERSION} as ${CRATE_VERSION}"
