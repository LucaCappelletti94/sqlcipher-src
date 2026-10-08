#!/bin/sh -e
# Runs SQLCipher's own test suite against the shipped sources built as sqlite-wasm-rs builds them, so its libtomcrypt switch set meets SQLCipher's expectations.

cd "$(dirname "$0")/.."
ROOT=$(pwd)
# shellcheck source=tools/releases.sh
. "$ROOT/tools/releases.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# sqlcipher-template holds no tests, and sqlcipher-threads races under the shipped SQLITE_MUTEX_NOOP.
SKIP_FILES="sqlcipher-template sqlcipher-threads"
# verify-memory-security-log-path needs a cipher_log destination, which the shipped SQLCIPHER_OMIT_LOG removes.
EXPECTED_FAILURES="verify-memory-security-log-path"

# SANITIZE=1 builds under clang with AddressSanitizer and UBSan, where any report ends the file without a summary.
CC=cc
OPT="-O2"
if [ -n "${SANITIZE:-}" ]; then
    CC=clang
    OPT="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all"
    ASAN_OPTIONS="detect_leaks=1:abort_on_error=1"
    UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
    export ASAN_OPTIONS UBSAN_OPTIONS
fi

# The wrapper at the revision interop/web pins, as cargo resolves it.
SHIM=$(cargo metadata --locked --format-version 1 --manifest-path "$ROOT/interop/web/Cargo.toml" |
    jq -r '.packages[] | select(.name == "sqlite-wasm-rs" and (.source | startswith("git+"))) | .manifest_path' |
    xargs dirname)/shim
for unit in sqlcipher-wasm.c sqlcipher-entropy.c sqlcipher-ltc.h; do
    [ -f "$SHIM/$unit" ] || { echo "no sqlite-wasm-rs $unit in $SHIM" >&2; exit 1; }
done
LTC="$ROOT/sqlcipher/libtomcrypt"

trust_keys "$WORK"
fetch_sqlcipher "$WORK"
cd "$WORK/sqlcipher"
# TCL_LIB names the tclConfig.sh directory when configure cannot find it.
CC="$CC" ./configure ${TCL_LIB:+--with-tcl="$TCL_LIB"} > configure.log
make sqlite3.c > make.log
# SQLCipher needs SQLITE_TEMP_STORE=2, which sqlite-wasm-rs sets on its own command line.
printf '#define SQLITE_TEMP_STORE 2\n#include "%s"\n' "$SHIM/sqlcipher-wasm.c" > sqlite3.c
# libtomcrypt one file per unit under the wrapper's switch set, then the entropy hook, as sqlite-wasm-rs links them.
mkdir ltc
# shellcheck disable=SC2016 # The inner sh expands them.
sed -n 's/^ *"\(libtomcrypt\/.*\.c\)",$/\1/p' "$ROOT/src/libtomcrypt_sources.rs" |
    OPT="$OPT" CC="$CC" SHIM="$SHIM" LTC="$LTC" ROOT="$ROOT" xargs -P "$(nproc)" -I {} sh -c \
        'o="ltc/$(echo "$1" | tr / _).o"; $CC $OPT -include "$SHIM/sqlcipher-ltc.h" -DLTC_SOURCE -I"$LTC/headers" -c "$ROOT/sqlcipher/$1" -o "$o"' _ {}
[ "$(find ltc -name '*.o' | wc -l)" -eq "$(grep -c '"libtomcrypt/' "$ROOT/src/libtomcrypt_sources.rs")" ] ||
    { echo "not every libtomcrypt source compiled" >&2; exit 1; }
# shellcheck disable=SC2086 # OPT holds several flags.
$CC $OPT -I"$LTC/headers" -c "$SHIM/sqlcipher-entropy.c" -o ltc/entropy.o
# SQLITE_HAS_CODEC stops every file skipping itself, SQLCIPHER_TEST enables the error pragmas, FTS5 is used by export tests.
# main.mk links with CFLAGS and never reads LDFLAGS, so the sanitizer flags in OPT reach the link from here.
# LDFLAGS.configure is the one variable main.mk appends to the testfixture link.
make testfixture CC="$CC" CFLAGS="$OPT -I$ROOT/sqlcipher -I$LTC/headers -DSQLITE_HAS_CODEC=1 -DSQLCIPHER_TEST=1 -DSQLITE_ENABLE_FTS5=1" \
    LDFLAGS.configure="$(echo "$PWD"/ltc/*.o)" > testfixture.log 2>&1

for symbol in sqlcipher_wasm_extra_init fortuna_start; do
    nm testfixture | grep -q "$symbol" ||
        { echo "testfixture lacks $symbol, so it was not built from $SHIM" >&2; exit 1; }
done
# A clean sanitizer run only counts if the binary is really instrumented.
[ -z "${SANITIZE:-}" ] || { nm testfixture | grep -q __asan_report_load && nm testfixture | grep -q __ubsan_handle; } ||
    { echo "testfixture is not instrumented" >&2; exit 1; }
printf 'sqlite3 db :memory:\ndb eval {PRAGMA key = %s}\nputs "[db eval {PRAGMA cipher_version}] [db eval {PRAGMA cipher_provider}]"\n' "'probe'" > probe.tcl
echo "Testing SQLCipher $(./testfixture probe.tcl)"

failed_files=""
for test in test/sqlcipher-*.test; do
    name=$(basename "$test" .test)
    case " $SKIP_FILES " in *" $name "*) echo "skip  $name"; continue ;; esac
    ./testfixture "$test" > "$name.log" 2>&1 || true
    # The summary line, not the exit status, proves the file ran to its end.
    summary=$(grep -E '^[0-9]+ errors out of [1-9][0-9]* tests' "$name.log" | tail -n 1)
    listed=0
    unexpected=""
    failures=$(sed -n 's/^!Failures on these tests: //p' "$name.log")
    for case_name in $failures; do
        listed=$((listed + 1))
        case " $EXPECTED_FAILURES " in *" $case_name "*) ;; *) unexpected="$unexpected $case_name" ;; esac
    done
    # LeakSanitizer reports at exit, after the summary, so the log itself is checked too.
    sanitizer=$(grep -m 1 -E '^==[0-9]+==(ERROR|WARNING): |runtime error: ' "$name.log" || true)
    # Every error must be a named failure, and every named failure an expected one.
    if [ -n "$summary" ] && [ "${summary%% errors*}" -eq "$listed" ] && [ -z "$unexpected" ] && [ -z "$sanitizer" ]; then
        echo "pass  $name  ${summary%% tests*} tests"
    else
        echo "FAIL  $name  ${summary:-no summary line}${unexpected:+, unexpected failures:$unexpected}${sanitizer:+, $sanitizer}"
        grep -E '^!|^==[0-9]+==|^SUMMARY: |runtime error: ' "$name.log" | head -n 20
        failed_files="$failed_files $name"
    fi
done

[ -z "$failed_files" ] || { echo "Failed:$failed_files" >&2; exit 1; }
