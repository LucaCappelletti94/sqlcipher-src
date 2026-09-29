# shellcheck shell=sh
# Pinned upstream releases, their verified fetch and the sources generated from them, sourced with ROOT set.

SQLCIPHER_VERSION="4.19.0"
# A signed tag moved to another commit still fails.
SQLCIPHER_COMMIT="c4b275a47932888216bade83aff2bbc73df0ff85"
# The newest signed pre-release tag of the next major line, which sqlcipher-release.yml moves and CI tests but nothing ships.
# shellcheck disable=SC2034 # tools/leg.sh reads both.
SQLCIPHER_NEXT_VERSION="5.0.0-beta"
# shellcheck disable=SC2034
SQLCIPHER_NEXT_COMMIT="02051d3d35b1e8d084670a7566c92f037e21399e"
# Stephen Lombardo's key from keys.openpgp.org, in keys/sqlcipher.asc.
SQLCIPHER_SIGNER="D92204901CD8BFDF63A2D9F952E8883F1591F4CE"
LIBTOMCRYPT_VERSION="1.18.2"
LIBTOMCRYPT_SHA256="96ad4c3b8336050993c5bc2cf6c057484f2b0f9f763448151567fbab5e767b84"
# Steffen Jaeckel's key from keyserver.ubuntu.com, in keys/libtomcrypt.asc.
LIBTOMCRYPT_SIGNER="C4386A237ED43A475541B9427B2CD0DD4BCFF59B"
# bindgen output depends on the libclang it loads, and ubuntu-latest carries several.
LLVM_MAJOR="18"

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

# Writes the SQLCipher tree at signed tag v$2, which must point at commit $3, to $1/sqlcipher.
fetch_sqlcipher_tag() {
    git init --quiet "$1/sqlcipher.git"
    git -C "$1/sqlcipher.git" fetch --quiet --depth 1 https://github.com/sqlcipher/sqlcipher.git \
        "refs/tags/v$2:refs/tags/v$2"
    git -C "$1/sqlcipher.git" verify-tag --raw "v$2" 2>&1 | signed_by "$SQLCIPHER_SIGNER" ||
        { echo "SQLCipher v$2 carries no valid signature from ${SQLCIPHER_SIGNER}" >&2; exit 1; }
    tagged=$(git -C "$1/sqlcipher.git" rev-parse "v$2^{commit}")
    [ "$tagged" = "$3" ] || { echo "SQLCipher v$2 points at ${tagged}, not $3" >&2; exit 1; }
    mkdir "$1/sqlcipher"
    git -C "$1/sqlcipher.git" archive "$3" | tar x -C "$1/sqlcipher"
}

# Writes the SQLCipher tree of the pinned release to $1/sqlcipher.
fetch_sqlcipher() {
    fetch_sqlcipher_tag "$1" "$SQLCIPHER_VERSION" "$SQLCIPHER_COMMIT"
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

# Points bindgen at the pinned libclang, which CI installs as libclang-<major>-dev.
use_libclang() {
    LIBCLANG_PATH="/usr/lib/llvm-${LLVM_MAJOR}/lib"
    export LIBCLANG_PATH
    [ -f "$LIBCLANG_PATH/libclang-${LLVM_MAJOR}.so" ] ||
        { echo "libclang ${LLVM_MAJOR} not found, install libclang-${LLVM_MAJOR}-dev" >&2; exit 1; }
}

# Makes the amalgamation in $1/sqlcipher and writes the sources and bindings generated from it and $1/libtomcrypt
# to $2, which must already hold the wrapper sqlite3.c.
generate_sources() {
    (cd "$1/sqlcipher" && ./configure > configure.log && make sqlite3.c > make.log)
    python3 "$ROOT/tools/assemble.py" "$1/sqlcipher" "$1/libtomcrypt" "$2"
    # sqlite-wasm-rs's own bindgen setup, plus the define SQLCipher's header puts sqlite3_key behind.
    use_libclang
    out=$(BINDGEN_EXTRA_CLANG_ARGS=-DSQLITE_HAS_CODEC SQLITE_WASM_RS_SOURCE_DIR="$2" CARGO_TARGET_DIR="$1/target" \
        cargo build --quiet --locked --manifest-path "$ROOT/interop/web/Cargo.toml" --lib \
        --target wasm32-unknown-unknown --features sqlite-wasm-rs/bindgen --message-format json |
        jq -r 'select(.reason == "build-script-executed" and (.package_id | test("sqlite-wasm-rs"))) | .out_dir')
    [ -f "$out/bindgen.rs" ] || { echo "sqlite-wasm-rs produced no bindings" >&2; exit 1; }
    cp "$out/bindgen.rs" "$2/sqlcipher_bindgen.rs"
}
