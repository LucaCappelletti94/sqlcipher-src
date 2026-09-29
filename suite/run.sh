#!/bin/sh -e
# Runs SQLCipher's own test suite against the shipped wrapper, so our libtomcrypt switch set meets SQLCipher's expectations.
# A leg of tools/leg.sh sets SQLCIPHER_TREE to its SQLCipher tree and SQLCIPHER_DIR to its generated sources.

cd "$(dirname "$0")/.."
ROOT=$(pwd)
# shellcheck source=tools/releases.sh
. "$ROOT/tools/releases.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
SOURCES=${SQLCIPHER_DIR:-$ROOT/sqlcipher}

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

if [ -n "${SQLCIPHER_TREE:-}" ]; then
    cp -R "$SQLCIPHER_TREE" "$WORK/sqlcipher"
else
    trust_keys "$WORK"
    fetch_sqlcipher "$WORK"
fi
cd "$WORK/sqlcipher"
# TCL_LIB names the tclConfig.sh directory when configure cannot find it.
CC="$CC" ./configure ${TCL_LIB:+--with-tcl="$TCL_LIB"} > configure.log
make sqlite3.c > make.log
# SQLCipher needs SQLITE_TEMP_STORE=2, which sqlite-wasm-rs sets on its own command line.
printf '#define SQLITE_TEMP_STORE 2\n#include "%s/sqlite3.c"\n' "$SOURCES" > sqlite3.c
# SQLITE_HAS_CODEC stops every file skipping itself, SQLCIPHER_TEST enables the error pragmas, FTS5 is used by export tests.
make testfixture CC="$CC" CFLAGS="$OPT -DSQLITE_HAS_CODEC=1 -DSQLCIPHER_TEST=1 -DSQLITE_ENABLE_FTS5=1" \
    LDFLAGS="${SANITIZE:+$OPT}" > testfixture.log 2>&1

nm testfixture | grep -q sqlcipher_wasm_extra_init ||
    { echo "testfixture was not built from $SOURCES/sqlite3.c" >&2; exit 1; }
# A clean sanitizer run only counts if the binary is really instrumented.
[ -z "${SANITIZE:-}" ] || { nm testfixture | grep -q __asan_report_load && nm testfixture | grep -q __ubsan_handle; } ||
    { echo "testfixture is not instrumented" >&2; exit 1; }
# 5.x refuses a key on :memory:, so the probe keys a file.
printf 'sqlite3 db probe.db\ndb eval {PRAGMA key = %s}\nputs "[db eval {PRAGMA cipher_version}] [db eval {PRAGMA cipher_provider}]"\n' "'probe'" > probe.tcl
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
