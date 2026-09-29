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
echo "prerelease at $(cat "$SOURCES/prerelease/COMMIT")"

# Compiles translation unit $3 as provider $2 of variant $1, with any further arguments as compiler flags. Every global
# except the API table gets a per-build prefix, so two SQLCipher copies link into one binary. Localizing instead fails,
# since the sanitizers' per-global COMDAT groups keep the shared names. The steps are chained because spawn runs this
# in a context where set -e does not apply.
library() {
    local variant=$1 provider=$2 unit=$3
    shift 3
    local table="fuzz_sqlite_${variant}_${provider}" object="$WORK/${variant}_${provider}.o"
    # shellcheck disable=SC2086
    $CC $CFLAGS "${SQLITE_FLAGS[@]}" "${CRYPTO_FLAGS[@]}" "$@" -DFUZZ_LIBRARY="$table" -w -c "$unit" -o "$object" &&
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

# Links variant $1's targets, named with suffix $2.
targets() {
    local variant=$1 suffix=$2
    local libtomcrypt="fuzz_sqlite_${variant}_libtomcrypt" openssl="fuzz_sqlite_${variant}_openssl"
    target codec "codec$suffix" -DFUZZ_LIBTOMCRYPT="$libtomcrypt"
    target codec "codec${suffix}_system_heap" -DFUZZ_LIBTOMCRYPT="${libtomcrypt}_system_heap"
    target differential "differential$suffix" -DFUZZ_LIBTOMCRYPT="$libtomcrypt" -DFUZZ_OPENSSL="$openssl"
    for heap in "" _system_heap; do
        # shellcheck disable=SC2086
        $CXX $CXXFLAGS "$WORK/codec$suffix$heap.o" "$WORK/script.o" "$WORK/libstate.o" "$WORK/memvfs.o" "$WORK/known.o" "$WORK/random.o" \
            "$WORK/${variant}_libtomcrypt$heap.o" $LIB_FUZZING_ENGINE -o "$OUT/codec$suffix$heap"
        cp codec.dict "$OUT/codec$suffix$heap.dict"
    done
    for heap in "" _system_heap; do
        local table="${libtomcrypt}$heap" binary="hostile_file$suffix$heap"
        target hostile_file "$binary" -DFUZZ_LIBRARY_TABLE="$table"
        target seedgen "seedgen$suffix$heap" -DFUZZ_LIBRARY_TABLE="$table"
        # shellcheck disable=SC2086
        $CXX $CXXFLAGS "$WORK/$binary.o" "${file_units[@]}" "$WORK/${variant}_libtomcrypt$heap.o" \
            $LIB_FUZZING_ENGINE -o "$OUT/$binary"
        # shellcheck disable=SC2086
        $CXX $CXXFLAGS "$WORK/seedgen$suffix$heap.o" "${file_units[@]}" "$WORK/${variant}_libtomcrypt$heap.o" \
            -o "$WORK/seedgen$suffix$heap"
        # The seeds are built with the same library, so every variant starts from databases it wrote itself.
        mkdir -p "$WORK/seeds/$binary"
        LLVM_PROFILE_FILE="$WORK/seedgen.profraw" "$WORK/seedgen$suffix$heap" "$WORK/seeds/$binary" "$SOURCES/prerelease"
        (cd "$WORK/seeds/$binary" && zip -q -r "$OUT/${binary}_seed_corpus.zip" .)
        # keyed_file reads the same file images, so it starts from the same seeds.
        local keyed="keyed_file$suffix$heap"
        target keyed_file "$keyed" -DFUZZ_LIBRARY_TABLE="$table" -DFUZZ_PLAIN_TABLE=fuzz_sqlite_release_plain
        # shellcheck disable=SC2086
        $CXX $CXXFLAGS "$WORK/$keyed.o" "$WORK/pagemut.o" "$WORK/plaindiff.o" "${file_units[@]}" \
            "$WORK/${variant}_libtomcrypt$heap.o" "$WORK/release_plain.o" $LIB_FUZZING_ENGINE -o "$OUT/$keyed"
        cp "$OUT/${binary}_seed_corpus.zip" "$OUT/${keyed}_seed_corpus.zip"
        printf '[libfuzzer]\nmax_len = 200000\n' | tee "$OUT/$binary.options" > "$OUT/$keyed.options"
    done
    # OpenSSL links statically, since the runner image that executes the targets has no libcrypto.
    # shellcheck disable=SC2086
    $CXX $CXXFLAGS "$WORK/differential$suffix.o" "$WORK/script.o" "$WORK/libstate.o" "$WORK/memvfs.o" "$WORK/known.o" "$WORK/random.o" "$WORK/${variant}_libtomcrypt.o" \
        "$WORK/${variant}_openssl.o" "$LIBCRYPTO" -ldl -pthread $LIB_FUZZING_ENGINE -o "$OUT/differential$suffix"
}

for source in app known libstate memvfs pagemut plaindiff random rawfile script; do
    # shellcheck disable=SC2086
    $CC $CFLAGS -Wall -Wextra -Werror -c "$source.c" -o "$WORK/$source.o"
done

# SQLCipher's private heap keeps its buffers inside one arena, where AddressSanitizer only sees an overflow once it
# corrupts a block header. Each variant also builds on the system heap, which reports the faulting access itself.
system_heap=(-DSQLCIPHER_OMIT_MALLOC)

# The shipped release, whose libtomcrypt build is sqlcipher/sqlite3.c itself.
spawn release libtomcrypt libtomcrypt.c
spawn release libtomcrypt_system_heap libtomcrypt.c "${system_heap[@]}"
spawn release openssl openssl.c -iquote ../sqlcipher
# Plain SQLite from the same amalgamation, the reference keyed_file compares every line against.
spawn release plain plain.c -iquote ../sqlcipher

# The fetched lines, which 5.x only builds with SQLITE_DIRECT_OVERFLOW_READ off.
for variant in beta prerelease; do
    fetched=(-iquote "$SOURCES/$variant" -I ../sqlcipher -DSQLITE_DIRECT_OVERFLOW_READ=0)
    spawn "$variant" libtomcrypt fetched_libtomcrypt.c "${fetched[@]}"
    spawn "$variant" libtomcrypt_system_heap fetched_libtomcrypt.c "${fetched[@]}" "${system_heap[@]}"
    spawn "$variant" openssl openssl.c "${fetched[@]}"
done
wait
[ ! -e "$WORK/failed" ] || { echo "a SQLCipher library failed to compile" >&2; exit 1; }

# The units every file-image binary links besides its target and its library.
file_units=("$WORK/app.o" "$WORK/rawfile.o" "$WORK/libstate.o" "$WORK/memvfs.o" "$WORK/known.o" "$WORK/random.o")

targets release ""
targets beta _beta
targets prerelease _prerelease
