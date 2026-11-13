#!/usr/bin/env python3
"""List everything inside an app bundle that must be signed, deepest first.

Prints NUL-separated paths. A path is either a nested bundle directory (.app, .framework,
.xpc, .appex, .plugin, .bundle) or a loose Mach-O file (executable, dylib, .so). The top
app itself is not listed: sign.sh signs it last.

Order is deepest path first, so a bundle's contents are always signed before the bundle.
Symbolic links are never followed or listed (frameworks keep Versions/Current as a link),
so nothing is listed twice.

Usage:  python3 scripts/list_signables.py <App.app>
"""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

BUNDLE_SUFFIXES = (".app", ".framework", ".xpc", ".appex", ".plugin", ".bundle")
THIN_MAGICS = {0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE}
FAT_MAGICS = {0xCAFEBABE, 0xBEBAFECA}


def is_macho(path: Path) -> bool:
    """True when the file starts like a Mach-O binary or a universal (fat) binary."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(8)
    except OSError:
        return False
    if len(head) < 8:
        return False
    magic = struct.unpack(">I", head[:4])[0]
    if magic in THIN_MAGICS:
        return True
    if magic in FAT_MAGICS:
        # A Java class file shares the fat magic; a real fat binary has a small architecture count.
        count = struct.unpack(">I", head[4:8])[0]
        if magic == 0xBEBAFECA:
            count = struct.unpack("<I", head[4:8])[0]
        return 1 <= count <= 20
    return False


def signables(app: Path) -> list:
    app = Path(app)
    found = []
    for root, dirs, files in os.walk(app, followlinks=False):
        root_path = Path(root)
        for name in dirs:
            path = root_path / name
            if path.is_symlink():
                continue
            if name.endswith(BUNDLE_SUFFIXES):
                found.append(path)
        for name in files:
            path = root_path / name
            if path.is_symlink() or not path.is_file():
                continue
            if is_macho(path):
                found.append(path)
    found.sort(key=lambda p: (-len(p.relative_to(app).parts), str(p)))
    return found


def main(argv) -> int:
    if len(argv) != 2:
        print("usage: list_signables.py <App.app>", file=sys.stderr)
        return 2
    app = Path(argv[1])
    if not app.is_dir():
        print(f"list_signables.py: {app} is not a directory", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(b"".join(os.fsencode(str(p)) + b"\0" for p in signables(app)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
