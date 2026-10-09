#!/bin/bash
# Builds the fuzz targets into $OUT, from CC, CFLAGS and LIB_FUZZING_ENGINE as OSS-Fuzz's compile sets them.
# OSS-Fuzz runs this through bash, which ignores the shebang, so the options are set here.
set -euo pipefail

# Runs from the repository root, which the Dockerfile makes the working directory.
cd fuzz
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# sqlite-wasm-rs's FULL_FEATURED flags from its build.rs, so the harness compiles what Wasm consumers run.
SQLITE_FLAGS=(
    -DSQLITE_OS_OTHER
    -DSQLITE_USE_URI
    -DSQLITE_THREADSAFE=0
    -DSQLITE_TEMP_STORE=2
    -DSQLITE_DEFAULT_CACHE_SIZE=-16384
    -DSQLITE_DEFAULT_PAGE_SIZE=8192
    -DSQLITE_OMIT_DEPRECATED
    -DSQLITE_OMIT_LOAD_EXTENSION
    -DSQLITE_OMIT_SHARED_CACHE
    -DSQLITE_ENABLE_UNLOCK_NOTIFY
    -DSQLITE_ENABLE_API_ARMOR
    -DSQLITE_ENABLE_BYTECODE_VTAB
    -DSQLITE_ENABLE_DBPAGE_VTAB
    -DSQLITE_ENABLE_DBSTAT_VTAB
    -DSQLITE_ENABLE_FTS5
    -DSQLITE_ENABLE_MATH_FUNCTIONS
    -DSQLITE_ENABLE_OFFSET_SQL_FUNC
    -DSQLITE_ENABLE_PREUPDATE_HOOK
    -DSQLITE_ENABLE_RTREE
    -DSQLITE_ENABLE_SESSION
    -DSQLITE_ENABLE_STMTVTAB
    -DSQLITE_ENABLE_UNKNOWN_SQL_FUNCTION
    -DSQLITE_ENABLE_COLUMN_METADATA
)

CRYPTO_CFLAGS=$(pkg-config --cflags libcrypto)
read -ra CRYPTO_FLAGS <<< "$CRYPTO_CFLAGS"
LIBCRYPTO=$(pkg-config --variable=libdir libcrypto)/libcrypto.a
SOURCES=${FUZZ_SQLCIPHER_SOURCES:?set FUZZ_SQLCIPHER_SOURCES to the directory fuzz/sources.sh wrote}
SHIM=$SOURCES/shim
LTC=../sqlcipher/libtomcrypt
WRAPPER=(-I"$SHIM" -iquote ../sqlcipher -I"$LTC/headers")

# libtomcrypt one file per unit as sqlite-wasm-rs compiles it, shared by both heaps since the heap switch only reaches SQLCipher.
mkdir "$WORK/ltc"
# shellcheck disable=SC2016 # The inner sh expands them.
sed -n 's/^ *"\(libtomcrypt\/.*\.c\)",$/\1/p' ../src/libtomcrypt_sources.rs |
    CC=$CC CFLAGS=$CFLAGS SHIM=$SHIM LTC=$LTC WORK=$WORK xargs -P "$(nproc)" -I {} sh -c \
        'o="$WORK/ltc/$(echo "$1" | tr / _).o"; $CC $CFLAGS -w -include "$SHIM/sqlcipher-ltc.h" -DLTC_SOURCE -I"$LTC/headers" -c "../sqlcipher/$1" -o "$o"' _ {}
[ "$(find "$WORK/ltc" -name '*.o' | wc -l)" -eq "$(grep -c '"libtomcrypt/' ../src/libtomcrypt_sources.rs)" ] ||
    { echo "not every libtomcrypt source compiled" >&2; exit 1; }
# shellcheck disable=SC2086
$CC $CFLAGS -include "$SHIM/sqlcipher-ltc.h" -DLTC_SOURCE "${WRAPPER[@]}" -c entropy.c -o "$WORK/ltc/entropy.o"
ld -r -o "$WORK/libtomcrypt.o" "$WORK"/ltc/*.o

# Builds provider $2 of variant $1 from unit $3 and objects $4, prefixing every global but the API table so two SQLCipher
# copies link into one binary. Localizing fails instead, since the sanitizers' per-global COMDAT groups keep the names.
# The steps are chained because spawn runs this where set -e does not apply.
library() {
    local variant=$1 provider=$2 unit=$3 objects=$4
    shift 4
    local table="fuzz_sqlite_${variant}_${provider}" object="$WORK/${variant}_${provider}.o"
    # shellcheck disable=SC2086
    $CC $CFLAGS "${SQLITE_FLAGS[@]}" "${CRYPTO_FLAGS[@]}" "$@" -DFUZZ_LIBRARY="$table" -w -c "$unit" -o "$object.unit" &&
        ld -r -o "$object" "$object.unit" $objects &&
        nm -g -P --defined-only "$object" | awk -v keep="$table" -v prefix="fuzz_${variant}_${provider}_" \
            '$1 != keep { print $1, prefix $1 }' > "$object.symbols" &&
        objcopy --redefine-syms="$object.symbols" "$object"
}

# Runs library in the background, one job per core, since each compile takes minutes and none depends on another.
spawn() {
    while [ "$(jobs -rp | wc -l)" -ge "$(nproc)" ]; do wait -n || true; done
    { library "$@" || touch "$WORK/failed"; } &
}

# $1 names the target source, $2 the binary, and the rest are its compiler flags.
target() {
    local source=$1 binary=$2
    shift 2
    # shellcheck disable=SC2086
    $CC $CFLAGS -Wall -Wextra -Werror "$@" -c "$source.c" -o "$WORK/$binary.o"
}

for source in app known libstate memvfs pagemut plaindiff random rawfile script tamper; do
    # shellcheck disable=SC2086
    $CC $CFLAGS -Wall -Wextra -Werror -c "$source.c" -o "$WORK/$source.o"
done
# Every target links libstate, whose per-input reset clears each oracle's record.
state_units=("$WORK/libstate.o" "$WORK/memvfs.o" "$WORK/known.o" "$WORK/random.o" "$WORK/tamper.o")
script_units=("$WORK/script.o" "${state_units[@]}")
file_units=("$WORK/app.o" "$WORK/rawfile.o" "${state_units[@]}")

# The system heap lets AddressSanitizer see overflows that SQLCipher's private heap arena hides.
spawn release libtomcrypt libtomcrypt.c "$WORK/libtomcrypt.o" "${WRAPPER[@]}"
spawn release libtomcrypt_system_heap libtomcrypt.c "$WORK/libtomcrypt.o" "${WRAPPER[@]}" -DSQLCIPHER_OMIT_MALLOC
spawn release openssl openssl.c "" -iquote ../sqlcipher
# Plain SQLite from the same amalgamation, the reference keyed_file compares SQLCipher against.
spawn release plain plain.c "" -iquote ../sqlcipher
wait
[ ! -e "$WORK/failed" ] || { echo "a SQLCipher library failed to compile" >&2; exit 1; }

libtomcrypt=fuzz_sqlite_release_libtomcrypt
for heap in "" _system_heap; do
    target codec "codec$heap" -DFUZZ_LIBTOMCRYPT="$libtomcrypt$heap"
    # shellcheck disable=SC2086
    $CXX $CXXFLAGS "$WORK/codec$heap.o" "${script_units[@]}" "$WORK/release_libtomcrypt$heap.o" \
        $LIB_FUZZING_ENGINE -o "$OUT/codec$heap"
    cp codec.dict "$OUT/codec$heap.dict"
    table="$libtomcrypt$heap" binary="hostile_file$heap" keyed="keyed_file$heap"
    target hostile_file "$binary" -DFUZZ_LIBRARY_TABLE="$table"
    target seedgen "seedgen$heap" -DFUZZ_LIBRARY_TABLE="$table"
    target keyed_file "$keyed" -DFUZZ_LIBRARY_TABLE="$table" -DFUZZ_PLAIN_TABLE=fuzz_sqlite_release_plain
    # shellcheck disable=SC2086
    $CXX $CXXFLAGS "$WORK/$binary.o" "${file_units[@]}" "$WORK/release_libtomcrypt$heap.o" \
        $LIB_FUZZING_ENGINE -o "$OUT/$binary"
    # shellcheck disable=SC2086
    $CXX $CXXFLAGS "$WORK/$keyed.o" "$WORK/pagemut.o" "$WORK/plaindiff.o" "${file_units[@]}" \
        "$WORK/release_libtomcrypt$heap.o" "$WORK/release_plain.o" $LIB_FUZZING_ENGINE -o "$OUT/$keyed"
    # shellcheck disable=SC2086
    $CXX $CXXFLAGS "$WORK/seedgen$heap.o" "${file_units[@]}" "$WORK/release_libtomcrypt$heap.o" -o "$WORK/seedgen$heap"
    # Each heap seeds from databases its own library wrote, and keyed_file reads the same file images.
    mkdir -p "$WORK/seeds/$binary"
    LLVM_PROFILE_FILE="$WORK/seedgen.profraw" "$WORK/seedgen$heap" "$WORK/seeds/$binary" "$SOURCES/release"
    (cd "$WORK/seeds/$binary" && zip -q -r "$OUT/${binary}_seed_corpus.zip" .)
    cp "$OUT/${binary}_seed_corpus.zip" "$OUT/${keyed}_seed_corpus.zip"
    printf '[libfuzzer]\nmax_len = 200000\n' | tee "$OUT/$binary.options" > "$OUT/$keyed.options"
done
# OpenSSL links statically, since the runner image that executes the targets has no libcrypto.
target differential differential -DFUZZ_LIBTOMCRYPT="$libtomcrypt" -DFUZZ_OPENSSL=fuzz_sqlite_release_openssl
# shellcheck disable=SC2086
$CXX $CXXFLAGS "$WORK/differential.o" "${script_units[@]}" "$WORK/release_libtomcrypt.o" "$WORK/release_openssl.o" \
    "$LIBCRYPTO" -ldl -pthread $LIB_FUZZING_ENGINE -o "$OUT/differential"
