"""Builds the vendored directory from an unpacked SQLCipher tree (with sqlite3.c made) and libtomcrypt release."""

import glob
import os
import re
import shutil
import sys

sqlcipher, libtomcrypt, out = sys.argv[1:4]
os.makedirs(out, exist_ok=True)
# A file an upstream release drops must leave the crate.
for name in os.listdir(out):
    os.remove(os.path.join(out, name))

# wasm32 cannot hold a .fini_array section, and SQLCipher offers no switch to skip it until sqlcipher/sqlcipher#622 ships.
FINI_BEFORE = '#else\nstatic void (*const sqlcipher_fini_func)(void) __attribute__((used, section(".fini_array"))) = sqlcipher_fini;\n#endif\n'
FINI_AFTER = '#elif !defined(__wasm__)\nstatic void (*const sqlcipher_fini_func)(void) __attribute__((used, section(".fini_array"))) = sqlcipher_fini;\n#endif\n'


def read(path):
    with open(path, encoding="latin-1") as f:
        return f.read()


def write(path, text):
    with open(path, "w", encoding="latin-1") as f:
        f.write(text)


amalgamation = read(os.path.join(sqlcipher, "sqlite3.c"))
if amalgamation.count(FINI_BEFORE) != 1:
    sys.exit("SQLCipher's .fini_array registration moved, so the wasm guard needs updating")
write(os.path.join(out, "sqlcipher.c"), amalgamation.replace(FINI_BEFORE, FINI_AFTER))
for name in ("sqlite3.h", "sqlite3ext.h"):
    shutil.copy(os.path.join(sqlcipher, name), os.path.join(out, name))
shutil.copy(os.path.join(sqlcipher, "LICENSE.md"), os.path.join(out, "LICENSE-sqlcipher"))

src = os.path.join(libtomcrypt, "src")
for header in glob.glob(os.path.join(src, "headers", "*.h")):
    shutil.copy(header, os.path.join(out, os.path.basename(header)))
shutil.copy(os.path.join(libtomcrypt, "LICENSE"), os.path.join(out, "LICENSE-libtomcrypt"))

sources = sorted(glob.glob(os.path.join(src, "**", "*.c"), recursive=True))
tables = set()
for path in sources:
    for name in re.findall(r'#include\s+"([^"]+\.c)"', read(path)):
        tables.add(os.path.normpath(os.path.join(os.path.dirname(path), name)))
for table in tables:
    shutil.copy(table, os.path.join(out, os.path.basename(table)))

parts = ["/* libtomcrypt, every src/ file in path order, unmodified apart from flattened includes. Generated. */\n"]
for path in sources:
    if path in tables:
        continue
    rel = os.path.relpath(path, src)
    body = re.sub(r'#include\s+"([^"]+\.c)"', lambda m: '#include "' + os.path.basename(m.group(1)) + '"', read(path))
    parts.append(f'\n/* ===== {rel} ===== */\n#line 1 "{rel}"\n{body}\n')
write(os.path.join(out, "libtomcrypt.c"), "".join(parts))
