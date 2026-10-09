# shellcheck shell=sh
# Pinned upstream releases and their verified fetch, sourced by upgrade.sh, suite/run.sh and fuzz/sources.sh with ROOT set.

SQLCIPHER_VERSION="4.19.0"
# A signed tag moved to another commit still fails.
SQLCIPHER_COMMIT="c4b275a47932888216bade83aff2bbc73df0ff85"
# Stephen Lombardo's key from keys.openpgp.org, in keys/sqlcipher.asc.
SQLCIPHER_SIGNER="D92204901CD8BFDF63A2D9F952E8883F1591F4CE"
LIBTOMCRYPT_VERSION="1.18.2"
LIBTOMCRYPT_SHA256="96ad4c3b8336050993c5bc2cf6c057484f2b0f9f763448151567fbab5e767b84"
# Steffen Jaeckel's key from keyserver.ubuntu.com, in keys/libtomcrypt.asc.
LIBTOMCRYPT_SIGNER="C4386A237ED43A475541B9427B2CD0DD4BCFF59B"

# Only the committed keys count, never the machine's keyring.
trust_keys() {
    GNUPGHOME="$1/gnupg"
    export GNUPGHOME
    mkdir -m 700 "$GNUPGHOME"
    gpg --quiet --import "$ROOT"/keys/*.asc
}

# Accepts a valid signature by primary key $1 even from an expired key, as libtomcrypt 1.18.2's is, never a revoked one.
signed_by() {
    awk -v fpr="$1" '$1 == "[GNUPG:]" && $2 == "VALIDSIG" && $NF == fpr { ok = 1 }
        $1 == "[GNUPG:]" && $2 == "REVKEYSIG" { revoked = 1 }
        END { exit !(ok && !revoked) }'
}

# Writes the SQLCipher tree at the verified tag's commit to $1/sqlcipher.
fetch_sqlcipher() {
    git init --quiet "$1/sqlcipher.git"
    git -C "$1/sqlcipher.git" fetch --quiet --depth 1 https://github.com/sqlcipher/sqlcipher.git \
        "refs/tags/v${SQLCIPHER_VERSION}:refs/tags/v${SQLCIPHER_VERSION}"
    git -C "$1/sqlcipher.git" verify-tag --raw "v${SQLCIPHER_VERSION}" 2>&1 | signed_by "$SQLCIPHER_SIGNER" ||
        { echo "SQLCipher v${SQLCIPHER_VERSION} carries no valid signature from ${SQLCIPHER_SIGNER}" >&2; exit 1; }
    tagged=$(git -C "$1/sqlcipher.git" rev-parse "v${SQLCIPHER_VERSION}^{commit}")
    [ "$tagged" = "$SQLCIPHER_COMMIT" ] ||
        { echo "SQLCipher v${SQLCIPHER_VERSION} points at ${tagged}, not ${SQLCIPHER_COMMIT}" >&2; exit 1; }
    mkdir "$1/sqlcipher"
    git -C "$1/sqlcipher.git" archive "$SQLCIPHER_COMMIT" | tar x -C "$1/sqlcipher"
}

# Writes the verified libtomcrypt release tree to $1/libtomcrypt.
fetch_libtomcrypt() {
    release="https://github.com/libtom/libtomcrypt/releases/download/v${LIBTOMCRYPT_VERSION}/crypt-${LIBTOMCRYPT_VERSION}.tar.xz"
    curl -sfL -o "$1/libtomcrypt.tar.xz" "$release"
    curl -sfL -o "$1/libtomcrypt.tar.xz.asc" "$release.asc"
    gpg --status-fd 1 --verify "$1/libtomcrypt.tar.xz.asc" "$1/libtomcrypt.tar.xz" 2>/dev/null | signed_by "$LIBTOMCRYPT_SIGNER" ||
        { echo "libtomcrypt ${LIBTOMCRYPT_VERSION} carries no valid signature from ${LIBTOMCRYPT_SIGNER}" >&2; exit 1; }
    echo "$LIBTOMCRYPT_SHA256  $1/libtomcrypt.tar.xz" | shasum -a 256 -c -
    mkdir "$1/libtomcrypt"
    tar xJf "$1/libtomcrypt.tar.xz" --strip-components=1 -C "$1/libtomcrypt"
}

# Prints the directory of sqlite-wasm-rs's SQLCipher wrapper at the revision interop/web pins, as cargo resolves it.
wasm_shim() {
    shim=$(cargo metadata --locked --format-version 1 --manifest-path "$ROOT/interop/web/Cargo.toml" |
        jq -r '.packages[] | select(.name == "sqlite-wasm-rs" and (.source | startswith("git+"))) | .manifest_path' |
        xargs dirname)/shim
    for unit in sqlcipher-wasm.c sqlcipher-entropy.c sqlcipher-ltc.h; do
        [ -f "$shim/$unit" ] || { echo "no sqlite-wasm-rs $unit in $shim" >&2; exit 1; }
    done
    echo "$shim"
}

