"""Writes SHA256SUMS for every generated file in the given directory."""

import hashlib
import os
import sys

out = sys.argv[1]
with open(os.path.join(out, "SHA256SUMS"), "w") as sums:
    for name in sorted(os.listdir(out)):
        if name == "SHA256SUMS":
            continue
        with open(os.path.join(out, name), "rb") as f:
            sums.write(f"{hashlib.sha256(f.read()).hexdigest()}  {name}\n")
