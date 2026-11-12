#!/bin/bash
# Builds the libFuzzer targets into $1 under SANITIZER (address, undefined or memory), with OSS-Fuzz's CC, CFLAGS and
# LIB_FUZZING_ENGINE overriding the defaults. FUZZ_RELEASE_ONLY skips the beta and prerelease lines.
set -euo pipefail

mkdir -p "${1:?usage: fuzz/build.sh <output directory>}"
OUT=$(cd "$1" && pwd -P)
cd "$(dirname "$0")"
# The targets' outputs share names with sources here, such as codec.dict.
[ "$OUT" != "$(pwd -P)" ] || { echo "the output directory must not be fuzz/ itself" >&2; exit 1; }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

SANITIZER=${SANITIZER:-address}
case $SANITIZER in
address) SANITIZER_FLAGS="-fsanitize=address" ;;
undefined) SANITIZER_FLAGS="-fsanitize=undefined -fno-sanitize-recover=undefined" ;;
memory) SANITIZER_FLAGS="-fsanitize=memory -fsanitize-memory-track-origins" ;;
*) echo "SANITIZER must be address, undefined or memory" >&2; exit 1 ;;
esac
CC=${CC:-clang}
CXX=${CXX:-clang++}
CFLAGS=${CFLAGS:-"-O1 -g -fno-omit-frame-pointer $SANITIZER_FLAGS -fsanitize=fuzzer-no-link"}
CXXFLAGS=${CXXFLAGS:-$CFLAGS}
LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}

# Another sanitizer or line set leaves targets this build would not replace.
for suffix in "" _beta _prerelease; do
    rm -rf "$OUT/differential$suffix" "$OUT/differential_plain$suffix" "$OUT/differential_plain$suffix.dict"
    for heap in "" _system_heap; do
        name=$suffix$heap
        rm -rf "$OUT/codec$name" "$OUT/codec$name.dict" "$OUT/hostile_file$name" "$OUT/hostile_file${name}_seeds" \
            "$OUT/keyed_file$name" "$OUT/keyed_file${name}_seeds"
    done
done

SOURCES=$OUT/sources
./sources.sh "$SOURCES"

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

CRYPTO_FLAGS=(-I"$SOURCES/openssl/include")
LIBCRYPTO=$SOURCES/openssl/lib/libcrypto.a
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
    { library "$@" || touch "$WORK/failed_$1"; } &
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

# MSan needs every object instrumented, so a memory build leaves out the uninstrumented libcrypto, the private heap whose
# random arena would read as initialised, and the beta and prerelease lines.
msan=0
[ "${SANITIZER:-}" != memory ] || msan=1
heaps=("" _system_heap)
plain_heap=""
if [ "$msan" = 1 ]; then
    heaps=(_system_heap)
    plain_heap=_system_heap
fi
# A beta or prerelease crash needs an upstream fix, so short runs can skip those lines.
lines=(release)
if [ "$msan" = 0 ] && [ -z "${FUZZ_RELEASE_ONLY:-}" ]; then
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
# The release and plain libraries must compile. A beta or prerelease line that does not is an upstream defect, so it
# leaves this build with a warning and never stops the release from being fuzzed.
[ ! -e "$WORK/failed_release" ] || { echo "a SQLCipher release library failed to compile" >&2; exit 1; }
built=()
for line in "${lines[@]}"; do
    if [ -e "$WORK/failed_$line" ]; then
        echo "::warning::SQLCipher $line at $(cat "$SOURCES/$line/COMMIT") failed to compile, so its targets are left out"
    else
        built+=("$line")
    fi
done
lines=("${built[@]}")

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
        mkdir "$OUT/${binary}_seeds"
        LLVM_PROFILE_FILE="$WORK/seedgen.profraw" "$WORK/seedgen$suffix$heap" "$OUT/${binary}_seeds" "$SOURCES/$line"
        cp -r "$OUT/${binary}_seeds" "$OUT/${keyed}_seeds"
    done
    if [ "$msan" = 0 ]; then
        # OpenSSL links statically, so the machine running the targets needs no OpenSSL 3.
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
