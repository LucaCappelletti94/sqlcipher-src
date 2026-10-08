"""Writes SHA256SUMS for every generated file under the given directory, by path relative to it."""

import hashlib
import os
import sys

out = sys.argv[1]
paths = []
for root, _, names in os.walk(out):
    paths.extend(os.path.relpath(os.path.join(root, name), out).replace(os.sep, "/") for name in names)
with open(os.path.join(out, "SHA256SUMS"), "w") as sums:
    for path in sorted(paths):
        if path == "SHA256SUMS":
            continue
        with open(os.path.join(out, path), "rb") as f:
            sums.write(f"{hashlib.sha256(f.read()).hexdigest()}  {path}\n")
