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
# shellcheck source=tools/releases.sh
. ../tools/releases.sh
read -ra LEG_FLAGS <<< "$SQLCIPHER_LEG_FLAGS"

# Compiles libtomcrypt one file per unit as sqlite-wasm-rs does, plus the entropy unit, into $1 with flags $2. Both
# heaps share it, since the heap switch only reaches SQLCipher.
libtomcrypt_objects() {
    local dir
    dir="$WORK/ltc$(basename "$1" .o)"
    mkdir "$dir"
    # shellcheck disable=SC2016 # The inner sh expands them.
    sed -n 's/^ *"\(libtomcrypt\/.*\.c\)",$/\1/p' ../src/libtomcrypt_sources.rs |
        CC=$CC CFLAGS="$CFLAGS $2" SHIM=$SHIM LTC=$LTC DIR=$dir xargs -P "$(nproc)" -I {} sh -c \
            'o="$DIR/$(echo "$1" | tr / _).o"; $CC $CFLAGS -w -include "$SHIM/sqlcipher-ltc.h" -DLTC_SOURCE -I"$LTC/headers" -c "../sqlcipher/$1" -o "$o"' _ {}
    [ "$(find "$dir" -name '*.o' | wc -l)" -eq "$(grep -c '"libtomcrypt/' ../src/libtomcrypt_sources.rs)" ] ||
        { echo "not every libtomcrypt source compiled" >&2; exit 1; }
    # shellcheck disable=SC2086
    $CC $CFLAGS $2 -include "$SHIM/sqlcipher-ltc.h" -DLTC_SOURCE "${WRAPPER[@]}" -c entropy.c -o "$dir/entropy.o"
    ld -r -o "$1" "$dir"/*.o
}
libtomcrypt_objects "$WORK/libtomcrypt.o" ""

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

for source in app confidentiality fault known libstate memvfs model pagemut plaindiff random rawfile script tamper uniqueness; do
    # shellcheck disable=SC2086
    $CC $CFLAGS -Wall -Wextra -Werror -c "$source.c" -o "$WORK/$source.o"
done
# Every target links libstate, whose per-input reset clears each oracle's record.
state_units=("$WORK/libstate.o" "$WORK/memvfs.o" "$WORK/known.o" "$WORK/random.o" "$WORK/tamper.o" "$WORK/confidentiality.o"
    "$WORK/uniqueness.o" "$WORK/model.o" "$WORK/fault.o")
script_units=("$WORK/script.o" "${state_units[@]}")
file_units=("$WORK/app.o" "$WORK/rawfile.o" "${state_units[@]}")

# MSan needs every linked object instrumented, and the static libcrypto is not, so a memory build leaves out the OpenSSL
# provider and the differential target. It also leaves out the private heap, which fills its arena with random bytes
# up front, so MSan would see every allocation from it as initialised. It builds only the release, since ASan and UBSan
# batch fuzzing already cover the beta and prerelease lines.
msan=0
[ "${SANITIZER:-}" != memory ] || msan=1
heaps=("" _system_heap)
plain_heap=""
if [ "$msan" = 1 ]; then
    heaps=(_system_heap)
    plain_heap=_system_heap
fi
# PR fuzzing sets CFL_EXTRA_FUZZ_RELEASE_ONLY for its short budget, since a beta or prerelease crash needs an upstream fix
# however fast a PR run finds it, and batch fuzzing covers both lines.
lines=(release)
if [ "$msan" = 0 ] && [ -z "${CFL_EXTRA_FUZZ_RELEASE_ONLY:-}" ]; then
    lines+=(beta prerelease)
    libtomcrypt_objects "$WORK/libtomcrypt_next.o" "$SQLCIPHER_LEG_FLAGS"
fi

# The system heap lets AddressSanitizer see overflows that SQLCipher's private heap arena hides.
for line in "${lines[@]}"; do
    objects="$WORK/libtomcrypt.o" unit_flags=("${WRAPPER[@]}") openssl_flags=(-iquote ../sqlcipher)
    if [ "$line" != release ]; then
        objects="$WORK/libtomcrypt_next.o"
        unit_flags=(-I"$SHIM" -iquote "$SOURCES/$line" -I"$LTC/headers" "${LEG_FLAGS[@]}")
        openssl_flags=(-iquote "$SOURCES/$line" "${LEG_FLAGS[@]}")
    fi
    for heap in "${heaps[@]}"; do
        heap_flags=()
        [ -z "$heap" ] || heap_flags=(-DSQLCIPHER_OMIT_MALLOC)
        spawn "$line" "libtomcrypt$heap" libtomcrypt.c "$objects" "${unit_flags[@]}" "${heap_flags[@]}"
    done
    [ "$msan" = 1 ] || spawn "$line" openssl openssl.c "" "${openssl_flags[@]}"
done
# Plain SQLite from the release amalgamation, the reference keyed_file and differential_plain compare SQLCipher against.
spawn release plain plain.c "" -iquote ../sqlcipher
wait
[ ! -e "$WORK/failed" ] || { echo "a SQLCipher library failed to compile" >&2; exit 1; }

# Builds every target of line $1 into binaries named with suffix $2.
targets() {
    local line=$1 suffix=$2
    local libtomcrypt="fuzz_sqlite_${line}_libtomcrypt"
    for heap in "${heaps[@]}"; do
        target codec "codec$suffix$heap" -DFUZZ_LIBTOMCRYPT="$libtomcrypt$heap"
        # shellcheck disable=SC2086
        $CXX $CXXFLAGS "$WORK/codec$suffix$heap.o" "${script_units[@]}" "$WORK/${line}_libtomcrypt$heap.o" \
            $LIB_FUZZING_ENGINE -o "$OUT/codec$suffix$heap"
        cp codec.dict "$OUT/codec$suffix$heap.dict"
        local table="$libtomcrypt$heap" binary="hostile_file$suffix$heap" keyed="keyed_file$suffix$heap"
        target hostile_file "$binary" -DFUZZ_LIBRARY_TABLE="$table"
        target seedgen "seedgen$suffix$heap" -DFUZZ_LIBRARY_TABLE="$table"
        target keyed_file "$keyed" -DFUZZ_LIBRARY_TABLE="$table" -DFUZZ_PLAIN_TABLE=fuzz_sqlite_release_plain
        # shellcheck disable=SC2086
        $CXX $CXXFLAGS "$WORK/$binary.o" "${file_units[@]}" "$WORK/${line}_libtomcrypt$heap.o" \
            $LIB_FUZZING_ENGINE -o "$OUT/$binary"
        # shellcheck disable=SC2086
        $CXX $CXXFLAGS "$WORK/$keyed.o" "$WORK/pagemut.o" "$WORK/plaindiff.o" "${file_units[@]}" \
            "$WORK/${line}_libtomcrypt$heap.o" "$WORK/release_plain.o" $LIB_FUZZING_ENGINE -o "$OUT/$keyed"
        # shellcheck disable=SC2086
        $CXX $CXXFLAGS "$WORK/seedgen$suffix$heap.o" "${file_units[@]}" "$WORK/${line}_libtomcrypt$heap.o" \
            -o "$WORK/seedgen$suffix$heap"
        # Each library seeds from databases it wrote itself, and keyed_file reads the same file images.
        mkdir -p "$WORK/seeds/$binary"
        LLVM_PROFILE_FILE="$WORK/seedgen.profraw" "$WORK/seedgen$suffix$heap" "$WORK/seeds/$binary" "$SOURCES/$line"
        (cd "$WORK/seeds/$binary" && zip -q -r "$OUT/${binary}_seed_corpus.zip" .)
        cp "$OUT/${binary}_seed_corpus.zip" "$OUT/${keyed}_seed_corpus.zip"
        printf '[libfuzzer]\nmax_len = 200000\n' | tee "$OUT/$binary.options" > "$OUT/$keyed.options"
    done
    if [ "$msan" = 0 ]; then
        # OpenSSL links statically, since the runner image that executes the targets has no libcrypto.
        target differential "differential$suffix" -DFUZZ_LIBTOMCRYPT="$libtomcrypt" \
            -DFUZZ_OPENSSL="fuzz_sqlite_${line}_openssl"
        # shellcheck disable=SC2086
        $CXX $CXXFLAGS "$WORK/differential$suffix.o" "${script_units[@]}" "$WORK/${line}_libtomcrypt.o" \
            "$WORK/${line}_openssl.o" "$LIBCRYPTO" -ldl -pthread $LIB_FUZZING_ENGINE -o "$OUT/differential$suffix"
    fi
    target differential_plain "differential_plain$suffix" -DFUZZ_LIBTOMCRYPT="$libtomcrypt$plain_heap" \
        -DFUZZ_PLAIN=fuzz_sqlite_release_plain
    # shellcheck disable=SC2086
    $CXX $CXXFLAGS "$WORK/differential_plain$suffix.o" "${script_units[@]}" "$WORK/${line}_libtomcrypt$plain_heap.o" \
        "$WORK/release_plain.o" $LIB_FUZZING_ENGINE -o "$OUT/differential_plain$suffix"
    cp codec.dict "$OUT/differential_plain$suffix.dict"
}

targets release ""
for line in "${lines[@]:1}"; do
    targets "$line" "_$line"
done
